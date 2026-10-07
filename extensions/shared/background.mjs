import { BrowserService, publicError } from "./service.mjs";

// Current supported Chrome and Firefox API methods return promises.
const api = globalThis.browser ?? globalThis.chrome;
const browserKind = globalThis.browser ? "firefox" : "chromium";
const service = new BrowserService({ api, browserKind, randomId: () => crypto.randomUUID() });
const popupUrl = api.runtime.getURL("shared/popup.html");
const showBridgeFailure = () => { api.action.setBadgeText({ text: "!" }); };
let cookieListenerInstalled = false;
const onCookieChanged = change => { service.cookieChanged(change).catch(showBridgeFailure); };

api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Only our popup may initiate custody operations; page/content scripts cannot.
  if (sender.id !== api.runtime.id || sender.url !== popupUrl || sender.tab) {
    sendResponse({ ok: false, code: "request_failed" });
    return false;
  }
  service.command(message).then(result => {
    api.action.setBadgeText({ text: "" });
    sendResponse(result);
  }, error => sendResponse(publicError(error)));
  return true;
});

api.permissions.onRemoved.addListener(permissions => {
  // No error/cookie/native response is logged or retained.
  if (permissions.permissions?.includes("cookies")) {
    api.cookies?.onChanged?.removeListener(onCookieChanged);
    cookieListenerInstalled = false;
  }
  service.permissionsRemoved(permissions).catch(showBridgeFailure);
});

function observeCookies() {
  // Optional API namespaces can become available only after consent is granted.
  if (api.cookies?.onChanged && !cookieListenerInstalled) {
    api.cookies.onChanged.addListener(onCookieChanged);
    cookieListenerInstalled = true;
  }
}
observeCookies();
api.permissions.onAdded.addListener(() => {
  observeCookies();
  reconcileSources();
});

// A failed revocation retains metadata, and a later worker startup retries it.
// A failed revoked-context cleanup must not suppress still-authorized contexts.
// The service skips pending-disconnect sources during valid-source reconciliation.
function reconcileSources() {
  service.reconcilePermissions().catch(showBridgeFailure)
    .then(() => service.reconcileSources()).catch(showBridgeFailure);
}
reconcileSources();
