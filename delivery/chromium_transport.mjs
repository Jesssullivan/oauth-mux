// Test harness only: no browser automation belongs to the product runtime.
// Uses Chromium's CDP pipe, with no npm packages, listening port or provider IO.
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
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
const operationId = "chromium-original-operation";
const newOperationId = "chromium-new-operation";
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
    && value.health.capabilities.source_connection === true && value.health.capabilities.production_export === false
    && value.health.capabilities.connect_recovery === true);
}

async function native(sessionId, method, requestId, extra) {
  return evaluate(sessionId, `(async()=>{
    const {sendNativeRequest}=await import(chrome.runtime.getURL('shared/native.mjs'));
    const {makeEnvelope,makeHealthEnvelope}=await import(chrome.runtime.getURL('shared/protocol.mjs'));
    const {getAdapter}=await import(chrome.runtime.getURL('shared/adapters.mjs'));
    const envelope=makeEnvelope({requestId:${JSON.stringify(requestId)},sourceId:${JSON.stringify(sourceId)},
      adapter:getAdapter('github'),method:${JSON.stringify(method)},extra:{...${JSON.stringify(extra)},
      provenance:{browser:'chromium',extensionId:chrome.runtime.id}}});
    try { return await sendNativeRequest(chrome,envelope,{healthEnvelope:makeHealthEnvelope(crypto.randomUUID(),
      {browser:'chromium',extensionId:chrome.runtime.id})}); }
    catch(error) { return {transportLost:error.code==='native_host_unavailable'}; }
  })()`);
}

async function outcome(sessionId, requestId, intent, expectedRevision) {
  const response = await native(sessionId, "browser.connectOutcome", requestId,
    { operationId: intent, ...(expectedRevision === undefined ? {} : { expectedRevision }) });
  return evaluate(sessionId, `(async()=>{
    const {validateConnectOutcome}=await import(chrome.runtime.getURL('shared/protocol.mjs'));
    return validateConnectOutcome(${JSON.stringify(response)},${JSON.stringify(requestId)},${JSON.stringify(sourceId)},${JSON.stringify(intent)});
  })()`);
}

async function observedRequests() {
  const payload = await readFile(journal, "utf8");
  require(Buffer.byteLength(payload) <= 16384);
  const rows = payload.trim() ? payload.trim().split("\n").map(value => JSON.parse(value)) : [];
  const common = ["id", "method", "sourceId"];
  require(rows.length <= 64 && rows.every(row => common.every(key => Object.hasOwn(row, key))
    && Object.keys(row).every(key => [...common, "operationId", "expectedRevision", "expectedGeneration"].includes(key))));
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
  const beforeMutations = await observedRequests();
  require(beforeMutations.length === 0);
  const denied = await evaluate(first.sessionId, `(async () => {
    const {BrowserService,publicError}=await import(chrome.runtime.getURL('shared/service.mjs'));
    const {ADAPTERS,getAdapter}=await import(chrome.runtime.getURL('shared/adapters.mjs'));
    const ids=['chromium-service-health'];
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
  require(isDeepStrictEqual(await observedRequests(), beforeMutations));
  phase = "chromium-v4-outcome-preflight";
  const before = await outcome(first.sessionId, "chromium-outcome-before", operationId);
  require(before.outcome === "unknown" && before.current_generation === null
    && before.source_status === "absent" && before.authorized === false);
  const intent = { operationId, expectedRevision: before.current_revision };
  phase = "chromium-v4-pending-source-seed";
  // Only the durable descriptor is seeded. No real browser context, provider
  // permission, captured fields, identity, grant or consent is established.
  const pendingConnect = { id: "chromium-lost-connect", method: "browser.connect", ...intent };
  await evaluate(first.sessionId, `chrome.storage.local.set({
    omuxSourceMetadataV1:[${JSON.stringify(syntheticSource)}],
    omuxSourceStatesV1:{${JSON.stringify(sourceId)}:'pending_connection'},
    omuxSourceRequestsV1:{${JSON.stringify(sourceId)}:${JSON.stringify(pendingConnect)}}}).then(()=>true)`);
  // This explicit synthetic setup request is not a toolbar gesture or the
  // service's fresh permission admission. Only real daemon source metadata is
  // committed; the recorder drops its accepted reply, never its execution.
  phase = "chromium-v4-committed-reply-loss";
  require(isDeepStrictEqual(await native(first.sessionId, "browser.connect", "chromium-lost-connect", intent),
    { transportLost: true }));
  await evaluate(first.sessionId, `chrome.storage.local.set({
    omuxSourceStatesV1:{${JSON.stringify(sourceId)}:'completion_unknown'}}).then(()=>true)`);
  const committed = await outcome(first.sessionId, "chromium-outcome-committed", operationId, intent.expectedRevision);
  require(committed.outcome === "committed" && committed.current_generation === committed.connect_generation
    && committed.source_status === "connected" && committed.authorized === true
    && BigInt(committed.connect_revision) === BigInt(intent.expectedRevision) + 1n);
  phase = "chromium-v4-exact-retry";
  const original = await native(first.sessionId, "browser.connect", "chromium-exact-retry", intent);
  require(isDeepStrictEqual(original.result, { accepted: true, source_id: sourceId, operation_id: operationId,
    generation: committed.connect_generation, revision: committed.connect_revision }));
  phase = "chromium-v4-changed-intent-refusal";
  const changed = await native(first.sessionId, "browser.connect", "chromium-changed-intent",
    { ...intent, expectedRevision: committed.current_revision });
  require(changed.error?.code === "OperationIdConflict");
  phase = "chromium-v4-stale-generation-refusal";
  const stale = await native(first.sessionId, "browser.disconnect", "chromium-stale-removal", {
    operationId: "chromium-stale-removal-operation", expectedRevision: committed.current_revision,
    expectedGeneration: (BigInt(committed.current_generation) + 1n).toString(),
  });
  require(stale.error?.code === "GenerationConflict");
  require(isDeepStrictEqual(await outcome(first.sessionId, "chromium-outcome-unchanged", operationId,
    intent.expectedRevision), committed));
  await permissionsAbsent(first.sessionId);
  const beforeRestart = await observedRequests();
  phase = "chromium-restart";
  await close();
  const second = await launch();
  require(second.version === first.version);
  await health(second.sessionId, "chromium-health-restart");
  phase = "chromium-shipped-worker-recovery";
  // The unchanged shipped worker sees missing permission and reads the exact
  // original receipt before fenced removal. It never issues another Connect.
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
  const afterRestart = await observedRequests();
  require(isDeepStrictEqual(afterRestart.slice(0, beforeRestart.length), beforeRestart));
  const worker = afterRestart.slice(beforeRestart.length);
  require(worker.length === 2 && worker[0].method === "browser.connectOutcome"
    && worker[0].operationId === operationId && worker[0].expectedRevision === intent.expectedRevision
    && worker[1].method === "browser.disconnect" && worker[1].sourceId === sourceId
    && worker[1].expectedRevision === committed.current_revision
    && worker[1].expectedGeneration === committed.connect_generation
    && worker[1].operationId !== operationId && worker[1].operationId !== worker[1].id);
  phase = "chromium-v4-current-removal-readback";
  const removed = await outcome(second.sessionId, "chromium-outcome-removed", operationId, intent.expectedRevision);
  require(removed.outcome === "committed" && removed.connect_generation === committed.connect_generation
    && BigInt(removed.current_generation) === BigInt(committed.connect_generation) + 1n
    && removed.source_status === "disconnected" && removed.authorized === false);
  phase = "chromium-v4-old-ack-new-generation";
  const newIntent = { operationId: newOperationId, expectedRevision: removed.current_revision };
  const newer = await native(second.sessionId, "browser.connect", "chromium-new-connect", newIntent);
  require(newer.result?.accepted === true && newer.result.operation_id === newOperationId
    && BigInt(newer.result.generation) === BigInt(removed.current_generation) + 1n);
  const newBefore = await outcome(second.sessionId, "chromium-outcome-new", newOperationId, newIntent.expectedRevision);
  require(newBefore.authorized === true && newBefore.source_status === "connected"
    && newBefore.current_generation === newer.result.generation);
  const repeatedRemoval = await native(second.sessionId, "browser.disconnect", "chromium-removal-retry", {
    operationId: worker[1].operationId, expectedRevision: worker[1].expectedRevision,
    expectedGeneration: worker[1].expectedGeneration,
  });
  require(isDeepStrictEqual(repeatedRemoval.result, { accepted: true, source_id: sourceId,
    operation_id: worker[1].operationId, generation: removed.current_generation, revision: removed.current_revision }));
  // The old ACK is historical. This actual current readback must still show
  // the newer connected generation; cached removal cannot remove it again.
  require(isDeepStrictEqual(await outcome(second.sessionId, "chromium-outcome-after-replay", newOperationId,
    newIntent.expectedRevision), newBefore));
  phase = "chromium-v4-final-explicit-removal";
  const finalRemoval = await native(second.sessionId, "browser.disconnect", "chromium-final-removal", {
    operationId: "chromium-final-removal-operation", expectedRevision: newBefore.current_revision,
    expectedGeneration: newBefore.current_generation,
  });
  require(finalRemoval.result?.accepted === true
    && BigInt(finalRemoval.result.generation) === BigInt(newBefore.current_generation) + 1n);
  const final = await outcome(second.sessionId, "chromium-outcome-final", newOperationId, newIntent.expectedRevision);
  require(final.source_status === "disconnected" && final.authorized === false
    && final.current_generation === finalRemoval.result.generation);
  phase = "chromium-historical-pending-seed";
  // A historical descriptor has no authoritative operation receipt. Keep it
  // uncertain even though this synthetic source has other known operations.
  const historical = { id: "chromium-recovery-connect", method: "browser.connect" };
  await evaluate(second.sessionId, `chrome.storage.local.set({
    omuxSourceMetadataV1:[${JSON.stringify(syntheticSource)}],
    omuxSourceStatesV1:{${JSON.stringify(sourceId)}:'completion_unknown'},
    omuxSourceRequestsV1:{${JSON.stringify(sourceId)}:${JSON.stringify(historical)}}}).then(()=>true)`);
  const beforeHistorical = await observedRequests();
  await close();
  const third = await launch();
  require(third.version === first.version);
  await health(third.sessionId, "chromium-health-historical");
  phase = "chromium-historical-pending-retained";
  const historicalDeadline = performance.now() + 12000;
  let held;
  while (performance.now() < historicalDeadline) {
    held = await evaluate(third.sessionId, `chrome.storage.local.get(${JSON.stringify(storageKeys)})`);
    if (held.omuxSourceStatesV1?.[sourceId] === "pending_disconnect") break;
    await delay(25);
  }
  require(isDeepStrictEqual(held, { omuxSourceMetadataV1: [syntheticSource],
    omuxSourceStatesV1: { [sourceId]: "pending_disconnect" }, omuxSourceRequestsV1: { [sourceId]: historical } }));
  require(isDeepStrictEqual(await observedRequests(), beforeHistorical));
  await permissionsAbsent(third.sessionId);
  console.log(JSON.stringify({scope:"installed-chromium-synthetic-browser-outcome-v4",browserVersion:third.version,
    extensionId:identity,channel:"development",providerAccess:false,grantExport:false,restarted:true,
    permissionGranted:false,toolbarConsentProved:false,committedReplyLost:true,exactRetryImmutable:true,
    changedIntentRefused:true,staleGenerationRefused:true,startupConnectReplay:false,
    fencedRemoval:true,oldAckCurrentAuthority:false,historicalOutcomeHeld:true}));
} catch {
  console.error(`installed Chromium transport failed at ${phase}`);
  process.exitCode = 1;
} finally { await close(); }
