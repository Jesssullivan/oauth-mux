// Test harness only: no browser automation belongs to the product runtime.
// Uses Chromium's CDP pipe, with no npm packages, listening port or provider IO.
import { spawn } from "node:child_process";
import { readFile, rename } from "node:fs/promises";
import { createHash } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import { setTimeout as delay } from "node:timers/promises";

const [chromium, extension, profile, journal] = process.argv.slice(2);
const require = (condition) => { if (!condition) throw new Error("fixture_boundary"); };
require(process.argv.length === 6 && [chromium, extension, profile, journal].every(value => value?.startsWith("/")));
const manifest = JSON.parse(await readFile(`${extension}/manifest.json`, "utf8"));
const identity = [...createHash("sha256").update(Buffer.from(manifest.key, "base64")).digest("hex").slice(0, 32)]
  .map(value => String.fromCharCode(97 + parseInt(value, 16))).join("");
const sourceId = "installed-chromium-synthetic-context";
const syntheticSource = { adapter: "github", storeId: "installed-chromium-synthetic-store", sourceId };
const registration = `${profile}/NativeMessagingHosts/ai.xoxd.omux.dev.json`;
const storageKeys = ["omuxSourceMetadataV1", "omuxSourceStatesV1", "omuxSourceRequestsV1"];
let phase = "chromium-startup";
let browser;
let sequence = 0;
const pending = new Map();
let bytes = Buffer.alloc(0);

function failPending() {
  for (const { reject, timer } of pending.values()) { clearTimeout(timer); reject(new Error("cdp_unavailable")); }
  pending.clear();
}

function call(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error("cdp_deadline")); }, 12000);
    pending.set(id, { resolve, reject, timer });
    const request = { id, method, params };
    if (sessionId) request.sessionId = sessionId;
    browser.stdio[3].write(JSON.stringify(request) + "\0", error => {
      if (error && pending.has(id)) { clearTimeout(timer); pending.delete(id); reject(error); }
    });
  });
}

async function launch() {
  bytes = Buffer.alloc(0);
  browser = spawn(chromium, ["--headless=new", "--remote-debugging-pipe", `--user-data-dir=${profile}`,
    `--load-extension=${extension}`, `--disable-extensions-except=${extension}`, "--no-first-run",
    "--no-default-browser-check", "--disable-background-networking", "--disable-component-update",
    "--disable-sync", "--disable-domain-reliability", "--metrics-recording-only", "--disable-gpu",
    "--host-resolver-rules=MAP * ~NOTFOUND", "--proxy-server=http://127.0.0.1:9",
    "--proxy-bypass-list=<-loopback>", "about:blank"],
    { stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"], detached: false });
  browser.on("error", failPending);
  browser.on("exit", failPending);
  browser.stdio[4].on("data", chunk => {
    bytes = Buffer.concat([bytes, chunk]);
    if (bytes.length > 1024 * 1024) { failPending(); browser.kill("SIGTERM"); return; }
    let end;
    while ((end = bytes.indexOf(0)) >= 0) {
      const message = bytes.subarray(0, end);
      bytes = bytes.subarray(end + 1);
      let value;
      try { value = JSON.parse(message.toString("utf8")); } catch { failPending(); browser.kill("SIGTERM"); return; }
      const waiting = pending.get(value.id);
      if (!waiting) continue;
      pending.delete(value.id);
      clearTimeout(waiting.timer);
      if (value.error) waiting.reject(new Error("cdp_rejected")); else waiting.resolve(value.result);
    }
  });
  const version = await call("Browser.getVersion");
  require(typeof version.product === "string" && /(?:Chrome|Chromium)\/147\.0\.7727\.116$/.test(version.product));
  const deadline = performance.now() + 12000;
  let worker;
  while (performance.now() < deadline) {
    const { targetInfos } = await call("Target.getTargets");
    worker = targetInfos.find(target => target.type === "service_worker"
      && target.url === `chrome-extension://${identity}/shared/background.mjs`);
    if (worker) break;
    await delay(50);
  }
  require(worker);
  // MV3 service workers do not support dynamic import(). Use an actual shipped
  // extension page for module inspection, after proving its worker is loaded.
  const { targetId } = await call("Target.createTarget", { url: `chrome-extension://${identity}/shared/popup.html` });
  const { sessionId } = await call("Target.attachToTarget", { targetId, flatten: true });
  await call("Runtime.enable", {}, sessionId);
  const pageDeadline = performance.now() + 12000;
  let ready = false;
  while (performance.now() < pageDeadline) {
    const state = await call("Runtime.evaluate", { expression: "globalThis.chrome?.runtime?.id", returnByValue: true }, sessionId);
    if (state.result?.value === identity) { ready = true; break; }
    await delay(25);
  }
  require(ready);
  return { sessionId, version: version.product };
}

async function evaluate(sessionId, expression) {
  const reply = await call("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true }, sessionId);
  require(!reply.exceptionDetails && Object.hasOwn(reply.result, "value"));
  return reply.result.value;
}

async function health(sessionId, id) {
  const value = await evaluate(sessionId, `(async () => {
    const {requestNativeHealth}=await import(chrome.runtime.getURL('shared/native.mjs'));
    const {CHANNEL}=await import(chrome.runtime.getURL('shared/channel.mjs'));
    return {identity:chrome.runtime.id,channel:CHANNEL,health:await requestNativeHealth(chrome,'chromium',${JSON.stringify(id)})};
  })()`);
  require(value.identity === identity && value.channel === "development"
    && value.health.protocolVersion === 1 && value.health.channel === value.channel
    && value.health.status === "ready" && value.health.custody_available === true && value.health.provider_access === false
    && value.health.capabilities.source_connection === true && value.health.capabilities.production_export === false);
}

async function observedMutations() {
  const payload = await readFile(journal, "utf8");
  require(Buffer.byteLength(payload) <= 16384);
  const rows = payload.trim() ? payload.trim().split("\n").map(value => JSON.parse(value)) : [];
  require(rows.length <= 64 && rows.every(row => Object.keys(row).sort().join(",") === "id,method,sourceId"));
  return rows.filter(row => row.method !== "browser.health");
}

async function permissionsAbsent(sessionId) {
  const permissions = await evaluate(sessionId, "chrome.permissions.getAll()");
  require(Array.isArray(permissions.permissions) && !permissions.permissions.includes("cookies")
    && Array.isArray(permissions.origins) && permissions.origins.length === 0);
}

async function close() {
  if (!browser) return;
  const owned = browser;
  if (owned.exitCode === null) {
    try { await call("Browser.close"); } catch { /* Browser closes its pipe before acknowledging on some versions. */ }
    const deadline = performance.now() + 4000;
    while (owned.exitCode === null && owned.signalCode === null && performance.now() < deadline) await delay(25);
    if (owned.exitCode === null && owned.signalCode === null) owned.kill("SIGTERM");
    await delay(100);
    if (owned.exitCode === null && owned.signalCode === null) owned.kill("SIGKILL");
  }
  failPending();
  for (const fd of [3, 4]) owned.stdio[fd].destroy();
  browser = undefined;
  // The outer fixture session owns and cleans all descendants, including hosts.
}

try {
  const first = await launch();
  phase = "chromium-native-health";
  await health(first.sessionId, "chromium-health-first");
  phase = "chromium-extension-tab-boundary";
  // CDP opened an extension TAB, not the toolbar popup. The actual background
  // must reject this sender, preserving the shipped custody boundary.
  for (const command of [{ command: "status", adapter: "github" }, { command: "health" }]) {
    const refusal = await evaluate(first.sessionId, `chrome.runtime.sendMessage(${JSON.stringify(command)})`);
    require(isDeepStrictEqual(refusal, { ok: false, code: "request_failed" }));
  }
  require(await evaluate(first.sessionId,
    "!document.querySelector('#consent').checked && document.querySelector('button[data-command=connect]').disabled"));
  await permissionsAbsent(first.sessionId);
  phase = "chromium-service-permission-refusal";
  const beforeDenied = await evaluate(first.sessionId, "chrome.storage.local.get(null)");
  const beforeMutations = await observedMutations();
  require(beforeMutations.length === 0);
  const denied = await evaluate(first.sessionId, `(async () => {
    const {BrowserService,publicError}=await import(chrome.runtime.getURL('shared/service.mjs'));
    const {ADAPTERS,getAdapter}=await import(chrome.runtime.getURL('shared/adapters.mjs'));
    const ids=['chromium-service-health','chromium-recovery-connect','chromium-service-health'];
    // Unchanged shipped class, real Chrome APIs, no fixture adapter or permission
    // mock. This driver instance does not represent a toolbar consent gesture.
    const service=new BrowserService({api:chrome,browserKind:'chromium',randomId:()=>{
      if (!ids.length) throw new Error('fixture_id_budget');
      return ids.shift();
    }});
    globalThis.omuxInstalledServiceProof={service,adapter:getAdapter('github'),publicError};
    const health=await service.health();
    const replies=[];
    for(const command of ['connect','reconcile']) {
      try { replies.push(await service.command({command,adapter:'github'})); }
      catch(error) { replies.push(publicError(error)); }
    }
    return {health,replies,exportsBlocked:Object.values(ADAPTERS).every(adapter=>
      adapter.grantExport==='blocked_pending_schema_proof' && !adapter.cookies.length && !adapter.storageKeys.length),
      status:await service.command({command:'status',adapter:'github'})};
  })()`);
  require(denied.exportsBlocked && denied.health.ok && denied.health.provider_access === false
    && denied.health.capabilities.production_export === false
    && denied.replies.length === 2 && denied.replies.every(reply => reply.ok === false && reply.code === "provider_permission_required")
    && isDeepStrictEqual(denied.status, { ok: true, connection: "disconnected", identity: "unverified",
      grant: "unproven", capability: "unproven", sources: [] }));
  require(isDeepStrictEqual(await evaluate(first.sessionId, "chrome.storage.local.get(null)"), beforeDenied));
  require(isDeepStrictEqual(await observedMutations(), beforeMutations));
  phase = "chromium-uncertain-source-seed";
  // Synthetic source/store metadata substitutes only for prior enrollment. No
  // real store selection, provider permission, consent or capture is established.
  await evaluate(first.sessionId, `chrome.storage.local.set({
    omuxSourceMetadataV1:[${JSON.stringify(syntheticSource)}],
    omuxSourceStatesV1:{${JSON.stringify(sourceId)}:'pending_connection'},omuxSourceRequestsV1:{}}).then(()=>true)`);
  phase = "chromium-uncertain-host-disabled";
  await rename(registration, `${registration}.inactive`);
  let uncertain;
  try {
    phase = "chromium-uncertain-native-dispatch";
    uncertain = await evaluate(first.sessionId, `(async()=>{
      const {service,adapter,publicError}=globalThis.omuxInstalledServiceProof;
      let result;
      try {result=await service.reconcileSource(${JSON.stringify(syntheticSource)},adapter,'browser.connect');}
      catch(error){result=publicError(error);}
      return {result,status:await service.status(),saved:await chrome.storage.local.get(${JSON.stringify(storageKeys)})};
    })()`);
  } finally { await rename(`${registration}.inactive`, registration); }
  phase = "chromium-uncertain-service-outcome";
  require(isDeepStrictEqual(uncertain.result, { ok: false, code: "native_host_unavailable" }));
  // Browser storage may reorder record properties. Deep strict comparison
  // preserves exact key sets, types, values and array order without treating
  // JSON object insertion order as additional custody authority.
  phase = "chromium-uncertain-source-metadata";
  require(Object.keys(uncertain.saved).sort().join(",") === [...storageKeys].sort().join(",")
    && isDeepStrictEqual(uncertain.saved.omuxSourceMetadataV1, [syntheticSource]));
  phase = "chromium-uncertain-source-state";
  require(isDeepStrictEqual(uncertain.saved.omuxSourceStatesV1, { [sourceId]: "completion_unknown" }));
  phase = "chromium-uncertain-request-identity";
  require(isDeepStrictEqual(uncertain.saved.omuxSourceRequestsV1, {
    [sourceId]: { id: "chromium-recovery-connect", method: "browser.connect" },
  }));
  phase = "chromium-uncertain-redacted-status";
  require(isDeepStrictEqual(uncertain.status, { ok: true, connection: "select_source_context", identity: "unverified",
    grant: "unproven", capability: "unproven", sources: [{ ...syntheticSource, status: "completion_unknown" }] }));
  phase = "chromium-uncertain-no-mutations";
  require((await observedMutations()).length === 0);
  phase = "chromium-uncertain-permissions";
  await permissionsAbsent(first.sessionId);
  phase = "chromium-restart";
  await close();
  const second = await launch();
  require(second.version === first.version);
  await health(second.sessionId, "chromium-health-restart");
  phase = "chromium-shipped-worker-recovery";
  // No driver service is recreated. The unchanged background startup observes
  // missing permission, resolves its retained connect, then disconnects source.
  const recoveryDeadline = performance.now() + 12000;
  let recovered = false;
  while (performance.now() < recoveryDeadline) {
    const saved = await evaluate(second.sessionId, `chrome.storage.local.get(${JSON.stringify(storageKeys)})`);
    if (Array.isArray(saved.omuxSourceMetadataV1) && saved.omuxSourceMetadataV1.length === 0
      && JSON.stringify(saved.omuxSourceStatesV1) === "{}" && JSON.stringify(saved.omuxSourceRequestsV1) === "{}") {
      recovered = true;
      break;
    }
    await delay(25);
  }
  require(recovered);
  const mutations = await observedMutations();
  require(mutations.length === 2 && isDeepStrictEqual(mutations[0], {
    id: "chromium-recovery-connect", method: "browser.connect", sourceId,
  }) && mutations[1].method === "browser.disconnect" && mutations[1].sourceId === sourceId
    && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(mutations[1].id)
    && mutations[1].id !== mutations[0].id);
  await permissionsAbsent(second.sessionId);
  console.log(JSON.stringify({scope:"installed-chromium-synthetic-browser-service-recovery",browserVersion:second.version,
    extensionId:identity,channel:"development",providerAccess:false,grantExport:false,restarted:true,
    permissionGranted:false,toolbarConsentProved:false,retainedConnectId:true,distinctDisconnectId:true}));
} catch {
  console.error(`installed Chromium transport failed at ${phase}`);
  process.exitCode = 1;
} finally { await close(); }
