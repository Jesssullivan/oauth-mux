import { getAdapter, hostPermission } from "./adapters.mjs";

const api = globalThis.browser ?? globalThis.chrome;
const status = document.querySelector("#status");
const selector = document.querySelector("#adapter");
const consent = document.querySelector("#consent");
const storedContext = document.querySelector("#stored-context");
const removalNote = document.querySelector("#removal-note");
const buttons = [...document.querySelectorAll("button[data-command]")];
let busy = false;
let snapshotRevision = 0;
let selectionGeneration = 0;
let storedSources = [];
const messages = {
  connected_schema_unproven: "Browser context connected. Account import is not yet available for this provider.",
  grant_submitted: "Account access submitted to Omux for identity verification.",
  disconnected: "Disconnect acknowledged for the selected context. This does not prove a later authorization in Omux is absent. Access from other sources is preserved.",
  provider_permission_required: "Allow access to this provider to connect its browser context.",
  open_provider_tab: "Open this provider's account tab in a regular browser window, then try again.",
  cookie_store_unavailable: "This browser context is unavailable. Reopen the provider tab and try again.",
  source_not_connected: "This context is not connected. Refresh the saved list or select another context; connecting creates new acquisition authority.",
  native_host_unavailable: "Omux is unavailable. Open the Omux app to check installation and activation.",
  incompatible_native_host: "The browser bridge and Omux are incompatible. Update them together in Omux setup.",
  daemon_rejected_request: "Omux rejected this request. Check source status in the Omux app.",
  operation_in_progress: "A source update is already running.",
  source_limit_reached: "The source limit has been reached. Manage connected sources in Omux.",
  select_source_context: "Open the connected provider context you want to manage, then try again.",
  disconnect_pending: "Removal is pending. Select its saved context to inspect the unresolved operation before retrying Disconnect.",
  connect_outcome_unknown: "The original Connect outcome is unknown. Removal remains pending. Omux can check a retained operation on a recovery-capable host; historical requests cannot be recovered this way. Retrying does not cancel a delayed Connect. Connect would authorize acquisition again.",
  source_authority_changed: "The original Connect completed, but its authority is no longer current. Removal remains pending. Check this source in Omux; recovery cannot renew or remove a different authorization generation.",
  uncertain_operation: "A previous operation has not been confirmed. Omux has kept its identity; retrying a different operation cannot establish its original outcome.",
};
const labels = {
  connection: { connected: "Connected", disconnected: "Disconnected", pending: "Pending", unavailable: "Unavailable", select_source_context: "Select provider context", pending_connection: "Connection pending", connected_schema_unproven: "Connected", grant_submitted: "Connected", completion_unknown: "Confirmation pending", pending_disconnect: "Disconnect pending" },
  identity: { verified: "Verified", pending: "Verification pending", unverified: "Not verified", unavailable: "Not available" },
  grant: { usable: "Ready", unavailable: "Not available", unproven: "Not established", pending: "Verification pending", expired: "Expired", browser_required: "Browser required", blocked_pending_schema_proof: "Import not available" },
};
const setField = (field, value, fallback) => { document.querySelector(`#${field}`).textContent = labels[field]?.[value] ?? fallback; };
function updateButtons() {
  for (const button of buttons) button.disabled = busy || (button.dataset.command === "connect" && !consent.checked) || (button.hasAttribute("data-stored-context") && !storedContext.value);
  storedContext.disabled = busy || !storedSources.length;
}
function showRemovalNote() {
  const selected = storedSources.find(source => source.sourceId === storedContext.value);
  removalNote.textContent = selected?.pendingOutcome === "stale" ? messages.source_authority_changed
    : selected?.pendingOutcome === "committed" ? "The original Connect completed. Removal remains pending; retry Disconnect to check its current generation in Omux. This does not reconnect."
    : selected?.pendingOperation === "connect" ? messages.connect_outcome_unknown
    : selected?.pendingOperation === "disconnect" ? "The previous Disconnect reply was not confirmed. Keep Omux available and retry Disconnect for this saved context. This sends removal only; it does not reconnect."
    : selected?.pendingOperation ? "A previous source operation is unresolved. Removal may remain pending; check source status in Omux. No credential capsule is replayed."
    : "Choose a saved connection to disconnect without provider read access. These local records are not verified accounts.";
}
function renderStoredSources(sources) {
  const previous = storedContext.value;
  storedSources = sources;
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = sources.length ? "Select a saved context" : "No saved contexts for this provider";
  const options = sources.map((source, index) => {
    const option = document.createElement("option");
    option.value = source.sourceId;
    option.textContent = `Saved context ${index + 1} (${source.storeId}) — ${labels.connection[source.status] ?? "Unknown"}`;
    return option;
  });
  storedContext.replaceChildren(placeholder, ...options);
  storedContext.value = sources.some(source => source.sourceId === previous) ? previous : "";
  if (previous && storedContext.value !== previous) consent.checked = false;
  showRemovalNote();
  updateButtons();
}
function renderUnavailable() {
  setField("connection", "unavailable", "Unavailable");
  setField("identity", "unavailable", "Not available");
  setField("grant", "unavailable", "Not available");
}
async function refreshReadiness() {
  const revision = ++snapshotRevision;
  const generation = selectionGeneration;
  const adapter = getAdapter(selector.value);
  document.querySelector("#stored-context-label").textContent = `Saved ${adapter.label} context to disconnect`;
  document.querySelector("#availability").textContent = adapter.grantExport === "enabled"
    ? "Connecting a source and verifying an identity are separate from usable account access."
    : "Account import is not yet available for this provider. Connecting a source does not make account access ready.";
  const [contextResult, healthResult] = await Promise.allSettled([
    api.runtime.sendMessage({ command: "status", adapter: adapter.id }),
    api.runtime.sendMessage({ command: "health" }),
  ]);
  if (revision !== snapshotRevision || generation !== selectionGeneration) return;
  const context = contextResult.status === "fulfilled" ? contextResult.value : null;
  if (context?.ok) {
    renderStoredSources(context.sources);
    setField("connection", context.connection, "Unknown");
    setField("identity", context.identity, "Not verified");
    setField("grant", context.grant, "Not available");
  } else {
    renderStoredSources([]);
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
  if (busy || (button.dataset.command === "connect" && !consent.checked) || (button.hasAttribute("data-stored-context") && !storedContext.value)) return;
  const generation = selectionGeneration;
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
      const command = { command: button.dataset.command, adapter: adapter.id };
      if (button.hasAttribute("data-stored-context")) command.sourceId = storedContext.value;
      const response = await api.runtime.sendMessage(command);
      resultMessage = messages[response?.status] ?? messages[response?.code] ?? "Source update failed. Check the Omux app.";
    }
  } catch { resultMessage = "Source update failed. Check the Omux app."; }
  finally {
    await refreshReadiness();
    if (generation === selectionGeneration) status.textContent = resultMessage;
    busy = false;
    selector.disabled = false;
    consent.disabled = false;
    updateButtons();
  }
});
selector.addEventListener("change", () => {
  selectionGeneration++;
  status.textContent = "Checking selected context…";
  consent.checked = false;
  storedContext.value = "";
  renderStoredSources([]);
  renderUnavailable();
  updateButtons();
  void refreshReadiness();
});
consent.addEventListener("change", updateButtons);
storedContext.addEventListener("change", () => { selectionGeneration++; consent.checked = false; status.textContent = "Saved context selected. Its local state does not confirm Omux authority."; showRemovalNote(); updateButtons(); if (!busy) void refreshReadiness(); });
api.storage.onChanged.addListener((changes, area) => {
  if (!busy && area === "local" && (Object.hasOwn(changes, "omuxSourceMetadataV1") || Object.hasOwn(changes, "omuxSourceStatesV1") || Object.hasOwn(changes, "omuxSourceRequestsV1"))) void refreshReadiness();
});
updateButtons();
void refreshReadiness();
