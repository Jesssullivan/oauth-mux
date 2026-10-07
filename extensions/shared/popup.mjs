import { getAdapter, hostPermission } from "./adapters.mjs";

const api = globalThis.browser ?? globalThis.chrome;
const status = document.querySelector("#status");
const selector = document.querySelector("#adapter");
const consent = document.querySelector("#consent");
const buttons = [...document.querySelectorAll("button[data-command]")];
let busy = false;
let snapshotRevision = 0;
const messages = {
  connected_schema_unproven: "Browser context connected. Account import is not yet available for this provider.",
  grant_submitted: "Account access submitted to Omux for identity verification.",
  disconnected: "Selected browser context disconnected. Access from other sources is preserved.",
  provider_permission_required: "Allow access to this provider to connect its browser context.",
  open_provider_tab: "Open this provider's account tab in a regular browser window, then try again.",
  cookie_store_unavailable: "This browser context is unavailable. Reopen the provider tab and try again.",
  source_not_connected: "Connect this provider's current browser context first.",
  native_host_unavailable: "Omux is unavailable. Open the Omux app to check installation and activation.",
  incompatible_native_host: "The browser bridge and Omux are incompatible. Update them together in Omux setup.",
  daemon_rejected_request: "Omux rejected this request. Check source status in the Omux app.",
  operation_in_progress: "A source update is already running.",
  source_limit_reached: "The source limit has been reached. Manage connected sources in Omux.",
  select_source_context: "Open the connected provider context you want to manage, then try again.",
  disconnect_pending: "Disconnection is pending. Keep Omux available and retry to complete it.",
};
const labels = {
  connection: { connected: "Connected", disconnected: "Disconnected", pending: "Pending", unavailable: "Unavailable", select_source_context: "Select provider context", pending_connection: "Connection pending", connected_schema_unproven: "Connected", grant_submitted: "Connected", completion_unknown: "Confirmation pending", pending_disconnect: "Disconnect pending" },
  identity: { verified: "Verified", pending: "Verification pending", unverified: "Not verified", unavailable: "Not available" },
  grant: { usable: "Ready", unavailable: "Not available", unproven: "Not established", pending: "Verification pending", expired: "Expired", browser_required: "Browser required", blocked_pending_schema_proof: "Import not available" },
};
const setField = (field, value, fallback) => { document.querySelector(`#${field}`).textContent = labels[field]?.[value] ?? fallback; };
function updateButtons() {
  for (const button of buttons) button.disabled = busy || (button.dataset.command === "connect" && !consent.checked);
}
function renderUnavailable() {
  setField("connection", "unavailable", "Unavailable");
  setField("identity", "unavailable", "Not available");
  setField("grant", "unavailable", "Not available");
}
async function refreshReadiness() {
  const revision = ++snapshotRevision;
  const adapter = getAdapter(selector.value);
  document.querySelector("#availability").textContent = adapter.grantExport === "enabled"
    ? "Connecting a source and verifying an identity are separate from usable account access."
    : "Account import is not yet available for this provider. Connecting a source does not make account access ready.";
  const [contextResult, healthResult] = await Promise.allSettled([
    api.runtime.sendMessage({ command: "status", adapter: adapter.id }),
    api.runtime.sendMessage({ command: "health" }),
  ]);
  if (revision !== snapshotRevision) return;
  const context = contextResult.status === "fulfilled" ? contextResult.value : null;
  if (context?.ok) {
    setField("connection", context.connection, "Unknown");
    setField("identity", context.identity, "Not verified");
    setField("grant", context.grant, "Not available");
  } else {
    renderUnavailable();
    if (!busy) status.textContent = messages[context?.code] ?? "Selected context status is unavailable. Check the Omux app.";
  }
  const health = healthResult.status === "fulfilled" ? healthResult.value : null;
  const compatibleHealth = health?.ok && health.protocolVersion === 1;
  document.querySelector("#health").textContent = compatibleHealth
    ? health.status === "repair_required" ? "Repair required" : health.status === "ready" ? health.channel === "development" ? "Ready (development)" : "Ready" : "Unknown"
    : health?.code === "incompatible_native_host" ? "Update required" : "Unavailable";
  document.querySelector("#custody").textContent = compatibleHealth
    ? health.custody_available === true ? "Available" : "Unavailable" : "Unknown";
  document.querySelector("#bridge").textContent = compatibleHealth && health.capabilities?.source_connection === true ? "Supported" : "Unavailable";
  document.querySelector("#provider-access").textContent = compatibleHealth && health.provider_access === false ? "Unavailable" : "Not established";
  if (compatibleHealth && health.capabilities?.production_export === false) {
    document.querySelector("#availability").textContent = "Account import is not yet available. A connected browser context does not provide usable account access.";
  }
  // Browser bridge capabilities never establish native application continuity.
  document.querySelector("#capability").textContent = "Not established";
  if (!busy && context?.ok) status.textContent = health?.status === "repair_required"
    ? "Omux secure storage needs attention. Open the Omux app to repair setup."
    : "Selected context status updated.";
}

for (const button of buttons) button.addEventListener("click", async () => {
  const adapter = getAdapter(selector.value);
  if (busy || (button.dataset.command === "connect" && !consent.checked)) return;
  busy = true;
  selector.disabled = true;
  consent.disabled = true;
  updateButtons();
  status.textContent = "Updating selected context…";
  let resultMessage;
  try {
    // Optional provider access is requested directly inside the consent gesture.
    if (button.dataset.command === "connect" && !await api.permissions.request({ permissions: ["cookies"], origins: [hostPermission(adapter)] })) {
      resultMessage = messages.provider_permission_required;
    } else {
      const response = await api.runtime.sendMessage({ command: button.dataset.command, adapter: adapter.id });
      resultMessage = messages[response?.status] ?? messages[response?.code] ?? "Source update failed. Check the Omux app.";
    }
  } catch { resultMessage = "Source update failed. Check the Omux app."; }
  finally {
    await refreshReadiness();
    status.textContent = resultMessage;
    busy = false;
    selector.disabled = false;
    consent.disabled = false;
    updateButtons();
  }
});
selector.addEventListener("change", () => {
  consent.checked = false;
  renderUnavailable();
  updateButtons();
  void refreshReadiness();
});
consent.addEventListener("change", updateButtons);
api.storage.onChanged.addListener((changes, area) => {
  if (!busy && area === "local" && (Object.hasOwn(changes, "omuxSourceMetadataV1") || Object.hasOwn(changes, "omuxSourceStatesV1"))) void refreshReadiness();
});
updateButtons();
void refreshReadiness();
