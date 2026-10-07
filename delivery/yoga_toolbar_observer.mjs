// Test-only passive observer. All user interaction belongs to the operator.
import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { isDeepStrictEqual } from "node:util";
import { setTimeout as delay } from "node:timers/promises";
import { pathToFileURL } from "node:url";

const [configuration] = process.argv.slice(2);
let phase = "arguments";
let browser;
let sequence = 0;
let buffer = Buffer.alloc(0);
const pending = new Map();
let deadline = 0;
const require = condition => { if (!condition) throw new Error("observer_boundary"); };
const report = (caseName, stage) => console.log(JSON.stringify({scope:"yoga-toolbar-progress",case:caseName,phase:stage}));

// A finite command allowlist is enforced at the transport, not just by callers.
const methods = new Set(["Browser.getVersion", "Browser.close", "Target.getTargets", "Target.attachToTarget", "Runtime.evaluate"]);
const permissionsExpression = "chrome.permissions.getAll()";
const storageExpression = "chrome.storage.local.get(['omuxSourceMetadataV1','omuxSourceStatesV1','omuxSourceRequestsV1'])";
const uiExpression = `(() => {
 const text=id=>document.querySelector('#'+id)?.textContent;
 return {adapter:document.querySelector('#adapter')?.value,
 consent:document.querySelector('#consent')?.checked,
 disabled:document.querySelector('button[data-command=connect]')?.disabled,
 status:text('status'),connection:text('connection'),identity:text('identity'),grant:text('grant'),
 health:text('health'),custody:text('custody'),bridge:text('bridge'),provider:text('provider-access'),capability:text('capability')};
})()`;
const expressions = new Set([permissionsExpression, storageExpression, uiExpression]);

function rejectPending() {
 for (const item of pending.values()) { clearTimeout(item.timer); item.reject(new Error("observer_transport")); }
 pending.clear();
}

function call(method, params = {}, sessionId) {
 require(methods.has(method) && performance.now() < deadline);
 if (method === "Runtime.evaluate") require(expressions.has(params.expression) && params.userGesture === false);
 return new Promise((resolve,reject) => {
  const id=++sequence;
  const timer=setTimeout(()=>{pending.delete(id);reject(new Error("observer_deadline"));},Math.min(8000,deadline-performance.now()));
  pending.set(id,{resolve,reject,timer});
  const request={id,method,params}; if(sessionId) request.sessionId=sessionId;
  browser.stdio[3].write(JSON.stringify(request)+"\0",error=>{
   if(error && pending.has(id)) {clearTimeout(timer);pending.delete(id);reject(new Error("observer_transport"));}
  });
 });
}

async function evaluate(sessionId, expression) {
 const value=await call("Runtime.evaluate",{expression,awaitPromise:true,returnByValue:true,userGesture:false},sessionId);
 require(!value.exceptionDetails && Object.hasOwn(value.result,"value"));
 return value.result.value;
}

async function targets(identity) {
 const {targetInfos}=await call("Target.getTargets");
 require(Array.isArray(targetInfos) && targetInfos.length <= 32);
 const prefix=`chrome-extension://${identity}/`;
 require(targetInfos.every(target => target.type !== "page" || target.url === "about:blank"
  || target.url === `${prefix}shared/popup.html`));
 return targetInfos;
}

function permissionState(value, approved) {
 require(value && Array.isArray(value.permissions) && Array.isArray(value.origins));
 const expected=["activeTab","nativeMessaging","storage",...(approved?["cookies"]:[])].sort();
 require(isDeepStrictEqual([...value.permissions].sort(),expected)
  && isDeepStrictEqual([...value.origins].sort(),approved?["https://github.com/*"]:[]));
}

function emptyStorage(value) {
 require(value && Object.keys(value).every(key=>["omuxSourceMetadataV1","omuxSourceStatesV1","omuxSourceRequestsV1"].includes(key)));
 for(const [key,item] of Object.entries(value)) require(isDeepStrictEqual(item,key==="omuxSourceMetadataV1"?[]:{}));
}

function readiness(ui) {
 require(ui.connection === "Disconnected" && ui.identity === "Not verified" && ui.grant === "Not established"
  && ui.capability === "Not established" && ui.health === "Ready (development)" && ui.custody === "Available"
  && ui.bridge === "Supported" && ui.provider === "Unavailable");
}

async function close() {
 if(!browser) return;
 const owned=browser;
 try { if(owned.exitCode===null && owned.signalCode===null) await call("Browser.close"); } catch { /* outer owned group remains cleanup authority */ }
 const until=performance.now()+3000;
 while(owned.exitCode===null && owned.signalCode===null && performance.now()<until) await delay(25);
 if(owned.exitCode===null && owned.signalCode===null) owned.kill("SIGTERM");
 await delay(100);
 if(owned.exitCode===null && owned.signalCode===null) owned.kill("SIGKILL");
 rejectPending();
 for(const fd of [3,4]) owned.stdio[fd]?.destroy();
 browser=undefined;
}

try {
 require(process.argv.length===3 && configuration?.startsWith("/"));
 const payload=await readFile(configuration,"utf8"); require(Buffer.byteLength(payload)<=4096);
 const config=JSON.parse(payload);
 require(Object.keys(config).sort().join(",")==="case,chromium,deadlineMonotonicNs,extension,extensionId,ozone,profile"
  && ["denial","approval","reload"].includes(config.case) && config.ozone==="wayland"
  && /^[a-p]{32}$/.test(config.extensionId)
  && [config.chromium,config.extension,config.profile].every(item=>typeof item==="string"&&item.startsWith("/")));
 const remaining=Number(BigInt(config.deadlineMonotonicNs)-process.hrtime.bigint())/1e6;
 require(remaining>0 && remaining<=300000); deadline=performance.now()+remaining;
 const {ADAPTERS}=await import(pathToFileURL(`${config.extension}/shared/adapters.mjs`));
 require(Object.keys(ADAPTERS).sort().join(",")==="claude,codex,github" && Object.values(ADAPTERS).every(adapter=>
  adapter.grantExport==="blocked_pending_schema_proof" && adapter.cookies.length===0 && adapter.storageKeys.length===0));
 phase="startup";
 browser=spawn(config.chromium,["--remote-debugging-pipe",`--ozone-platform=${config.ozone}`,`--user-data-dir=${config.profile}`,
  `--load-extension=${config.extension}`,`--disable-extensions-except=${config.extension}`,"--no-first-run",
  "--no-default-browser-check","--disable-background-networking","--disable-component-update","--disable-sync",
  "--disable-domain-reliability","--metrics-recording-only","--host-resolver-rules=MAP * ~NOTFOUND",
  "--proxy-server=http://127.0.0.1:9","--proxy-bypass-list=<-loopback>","about:blank"],
  {stdio:["ignore","ignore","ignore","pipe","pipe"]});
 browser.on("error",rejectPending); browser.on("exit",rejectPending);
 browser.stdio[4].on("data",chunk=>{
  buffer=Buffer.concat([buffer,chunk]);
  if(buffer.length>1024*1024){rejectPending();browser.kill("SIGTERM");return;}
  let end; while((end=buffer.indexOf(0))>=0){
   let value; try{value=JSON.parse(buffer.subarray(0,end).toString("utf8"));}catch{rejectPending();browser.kill("SIGTERM");return;}
   buffer=buffer.subarray(end+1); const item=pending.get(value.id); if(!item) continue;
   pending.delete(value.id);clearTimeout(item.timer);
   if(value.error)item.reject(new Error("observer_rejected"));else item.resolve(value.result);
  }
 });
 const version=await call("Browser.getVersion");
 require(/^(?:Chrome|Chromium)\/147\.0\.7727\.116$/.test(version.product));
 phase="worker";
 let workerSession;
 while(performance.now()<deadline){
  const worker=(await targets(config.extensionId)).find(item=>item.type==="service_worker"
   &&item.url===`chrome-extension://${config.extensionId}/shared/background.mjs`);
  if(worker){workerSession=(await call("Target.attachToTarget",{targetId:worker.targetId,flatten:true})).sessionId;break;}
  await delay(100);
 }
 require(workerSession);
 permissionState(await evaluate(workerSession,permissionsExpression),config.case==="reload");
 emptyStorage(await evaluate(workerSession,storageExpression));
 phase="await-toolbar"; report(config.case,phase);
 let popupSession;
 let outcome=false;
 let gate=false;
 while(performance.now()<deadline){
  const popup=(await targets(config.extensionId)).find(item=>item.url===`chrome-extension://${config.extensionId}/shared/popup.html`);
  if(popup && !popupSession) popupSession=(await call("Target.attachToTarget",{targetId:popup.targetId,flatten:true})).sessionId;
  if(popupSession){
   const ui=await evaluate(popupSession,uiExpression);
   if(!gate && ui.adapter==="github" && ui.consent===false && ui.disabled===true && ui.health==="Ready (development)"){
    readiness(ui);gate=true;phase="await-human-decision";report(config.case,phase);
   }
   if(gate){
    readiness(ui);
    const expected={denial:"Allow access to this provider to connect its browser context.",
     approval:"Open this provider's account tab in a regular browser window, then try again."}[config.case];
    if(config.case==="reload" || (ui.adapter==="github" && ui.consent===true && ui.disabled===false && ui.status===expected)){
     permissionState(await evaluate(workerSession,permissionsExpression),config.case!=="denial");
     emptyStorage(await evaluate(workerSession,storageExpression));outcome=true;break;
    }
   }
  }
  await delay(100);
 }
 require(outcome);
 phase="observed";
 console.log(JSON.stringify({scope:"yoga-toolbar-observed-case",case:config.case,browserVersion:version.product,
  initialGateObserved:true,optionalPermissionApproved:config.case!=="denial",emptyBrowserMetadata:true,
  outcome:config.case==="denial"?"permission_denied":config.case==="approval"?"open_provider_tab":"reload_gate_reset",
  driverInteraction:false,humanAttestationRequired:true}));
} catch {
 console.error(JSON.stringify({scope:"yoga-toolbar-observer-refusal",phase})); process.exitCode=1;
} finally { await close(); }
