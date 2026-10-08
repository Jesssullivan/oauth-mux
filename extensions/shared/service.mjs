import { getAdapter, hostPermission } from "./adapters.mjs";
import { acquireGrant, projectCookieChange } from "./acquisition.mjs";
import { AcquisitionError, makeEnvelope, makeHealthEnvelope, validateResponse } from "./protocol.mjs";
import { sendNativeRequest, requestNativeHealth } from "./native.mjs";

const STORAGE_KEY = "omuxSourceMetadataV1";
const STATE_KEY = "omuxSourceStatesV1";
const REQUEST_KEY = "omuxSourceRequestsV1";
const STATES = new Set(["pending_connection", "connected_schema_unproven", "grant_submitted", "completion_unknown", "pending_disconnect"]);
const COMMANDS = new Set(["connect", "reconcile", "disconnect", "status"]);
const REQUEST_ID = /^[A-Za-z0-9._:-]{1,64}$/;

function validPendingRequest(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || typeof value.id !== "string" || !REQUEST_ID.test(value.id) || !["browser.connect", "browser.disconnect", "browser.reconcile", "browser.importGrant"].includes(value.method)) return false;
  const keys = Object.keys(value).sort().join(",");
  if (keys === "id,method") return true;
  if (keys !== "id,method,superseded" || value.method !== "browser.disconnect") return false;
  const previous = value.superseded;
  return previous !== null && typeof previous === "object" && !Array.isArray(previous) &&
    Object.keys(previous).sort().join(",") === "id,method" &&
    typeof previous.id === "string" && REQUEST_ID.test(previous.id) &&
    previous.id !== value.id && previous.method === "browser.importGrant";
}

export class BrowserService {
  constructor({ api, browserKind, randomId, now = () => Date.now() / 1000, monotonicNow = () => performance.now(), readStorage = async () => { throw new AcquisitionError("storage_reader_unproven"); }, allowFixture = false, nativeOptions }) {
    this.api = api;
    this.browserKind = browserKind;
    this.randomId = randomId;
    this.now = now;
    this.monotonicNow = monotonicNow;
    this.startupBudget = null;
    this.activeBudget = null;
    this.reconcileCursor = 0;
    this.readStorage = readStorage;
    this.allowFixture = allowFixture;
    this.nativeOptions = nativeOptions;
    this.inflight = new Set();
    this.queue = Promise.resolve();
    this.pendingCookieWork = new Map();
  }

  serialized(operation) {
    const result = this.queue.then(operation);
    // Preserve a usable queue after failure, while returning failure to caller.
    this.queue = result.then(() => {}, () => {});
    return result;
  }

  async metadata() {
    const saved = await this.api.storage.local.get(STORAGE_KEY);
    const entries = saved[STORAGE_KEY] ?? [];
    // Treat browser storage as untrusted input; no credentials ever enter it.
    if (!Array.isArray(entries) || entries.length > 64 || entries.some(entry => !entry || Object.keys(entry).sort().join(",") !== "adapter,sourceId,storeId" || typeof entry.sourceId !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(entry.sourceId) || typeof entry.storeId !== "string" || !entry.storeId || entry.storeId.length > 128)) throw new AcquisitionError("invalid_source_metadata");
    if (new Set(entries.map(entry => entry.sourceId)).size !== entries.length || new Set(entries.map(entry => JSON.stringify([entry.adapter, entry.storeId]))).size !== entries.length) throw new AcquisitionError("invalid_source_metadata");
    for (const entry of entries) getAdapter(entry.adapter, { allowFixture: this.allowFixture });
    return entries;
  }

  async saveMetadata(entries) { await this.api.storage.local.set({ [STORAGE_KEY]: entries }); }

  async states() {
    const saved = (await this.api.storage.local.get(STATE_KEY))[STATE_KEY] ?? {};
    if (!saved || typeof saved !== "object" || Array.isArray(saved) || Object.keys(saved).length > 64 || Object.entries(saved).some(([id, state]) => !/^[A-Za-z0-9._:-]{1,128}$/.test(id) || !STATES.has(state))) throw new AcquisitionError("invalid_source_metadata");
    return saved;
  }

  async setState(source, state) {
    const entries = await this.metadata();
    const states = await this.states();
    for (const id of Object.keys(states)) if (!entries.some(entry => entry.sourceId === id)) delete states[id];
    states[source.sourceId] = state;
    await this.api.storage.local.set({ [STATE_KEY]: states });
  }

  async status(adapterId) {
    const entries = await this.metadata();
    const states = await this.states();
    const sources = entries.filter(source => !adapterId || source.adapter === adapterId);
    let connection = sources.length ? "select_source_context" : "disconnected";
    if (adapterId) {
      const adapter = getAdapter(adapterId, { allowFixture: this.allowFixture });
      const [tab] = await this.api.tabs.query({ active: true, currentWindow: true });
      let origin;
      try { origin = new URL(tab?.url).origin; } catch {}
      if (tab && !tab.incognito && origin === adapter.origin) {
        const stores = tab.cookieStoreId ? [] : await this.api.cookies?.getAllCookieStores?.() ?? [];
        const storeId = tab.cookieStoreId ?? stores.find(candidate => candidate.tabIds?.includes(tab.id))?.id;
        const source = sources.find(source => source.storeId === storeId);
        connection = source ? states[source.sourceId] ?? "pending_connection" : "disconnected";
      } else if (!tab && sources.length === 1) connection = states[sources[0].sourceId] ?? "pending_connection";
    }
    // UI readback exposes only categorical local state, never native response data.
    return { ok: true, connection, identity: "unverified", grant: "unproven", capability: "unproven", sources: sources.map(source => ({ ...source, status: states[source.sourceId] ?? "pending_connection" })) };
  }

  async health() { return { ok: true, ...await requestNativeHealth(this.api, this.browserKind, this.randomId(), this.nativeOptions) }; }

  async disconnectSource(source, adapter) {
    await this.setState(source, "pending_disconnect");
    await this.send(source, adapter, "browser.disconnect");
    await this.saveMetadata((await this.metadata()).filter(entry => entry.sourceId !== source.sourceId));
    const states = await this.states();
    delete states[source.sourceId];
    await this.api.storage.local.set({ [STATE_KEY]: states });
  }

  async reconcileSource(source, adapter, method = "browser.reconcile") {
    try {
      await this.send(source, adapter, method, method === "browser.connect" ? { provenance: { browser: this.browserKind, extensionId: this.api.runtime.id } } : {});
      await this.capture(source, adapter);
      const status = adapter.grantExport === "enabled" ? "grant_submitted" : "connected_schema_unproven";
      await this.setState(source, status);
      return { ok: true, status };
    } catch (error) {
      await this.setState(source, "completion_unknown");
      throw error;
    }
  }

  async send(source, adapter, method, extra = {}) {
    const budget = this.activeBudget;
    const remaining = budget ? Math.floor(budget.deadline - this.monotonicNow()) : 10000;
    if (budget && (remaining < 1 || budget.items >= 8)) throw new AcquisitionError("startup_budget_exhausted");
    const requests = (await this.api.storage.local.get(REQUEST_KEY))[REQUEST_KEY] ?? {};
    if (!requests || typeof requests !== "object" || Array.isArray(requests) || Object.keys(requests).length > 64 || Object.entries(requests).some(([id, value]) => !/^[A-Za-z0-9._:-]{1,128}$/.test(id) || !validPendingRequest(value))) throw new AcquisitionError("invalid_source_metadata");
    const entries = await this.metadata();
    for (const id of Object.keys(requests)) if (!entries.some(entry => entry.sourceId === id)) delete requests[id];
    const pending = requests[source.sourceId];
    if (["browser.connect", "browser.reconcile"].includes(pending?.method) && method === "browser.disconnect") {
      // Disconnect intent is already durable. Resolve only the original metadata
      // operation with its retained ID before admitting a new disconnect. This
      // does not acquire provider data, renew consent or run grant capture.
      await this.send(source, adapter, pending.method);
      return this.send(source, adapter, method, extra);
    }
    // Explicit removal supersedes an unknown import without replaying its
    // credential capsule. Keep its opaque unresolved identity until removal ACK.
    const supersedesImport = pending?.method === "browser.importGrant" && method === "browser.disconnect";
    if (pending && (pending.method !== method || method === "browser.importGrant") && !supersedesImport) throw new AcquisitionError("uncertain_operation");
    const requestId = supersedesImport ? this.randomId() : pending?.id ?? this.randomId();
    if (supersedesImport && requestId === pending.id) throw new AcquisitionError("invalid_source_metadata");
    const envelope = makeEnvelope({ requestId, sourceId: source.sourceId, adapter, method, extra: { ...extra, provenance: { browser: this.browserKind, extensionId: this.api.runtime.id } } }, { allowFixture: this.allowFixture });
    const superseded = supersedesImport ? { id: pending.id, method: pending.method } : pending?.superseded;
    requests[source.sourceId] = { id: requestId, method, ...(superseded ? { superseded } : {}) };
    await this.api.storage.local.set({ [REQUEST_KEY]: requests });
    if (budget && this.monotonicNow() >= budget.deadline) throw new AcquisitionError("startup_budget_exhausted");
    if (budget) budget.items++;
    let response;
    try { response = await sendNativeRequest(this.api, envelope, { ...this.nativeOptions, healthEnvelope: makeHealthEnvelope(this.randomId(), { browser: this.browserKind, extensionId: this.api.runtime.id }), timeoutMs: Math.min(this.nativeOptions?.timeoutMs ?? 10000, Math.max(1, Math.floor(budget ? budget.deadline - this.monotonicNow() : 10000))) }); }
    catch (error) {
      if (error instanceof AcquisitionError && error.code === "incompatible_native_host") throw error;
      throw new AcquisitionError("native_host_unavailable");
    }
    validateResponse(response, envelope.id);
    // A correlated envelope alone cannot settle mutation authority. Keep the
    // original pending request on malformed or non-accepted completion.
    if (response.result?.accepted !== true) throw new AcquisitionError("invalid_native_response");
    delete requests[source.sourceId];
    await this.api.storage.local.set({ [REQUEST_KEY]: requests });
  }

  async context(adapter) {
    if (!await this.api.permissions.contains({ permissions: ["cookies"], origins: [hostPermission(adapter)] })) throw new AcquisitionError("provider_permission_required");
    const tabs = await this.api.tabs.query({ active: true, currentWindow: true });
    const tab = tabs[0];
    let origin;
    try { origin = new URL(tab?.url).origin; } catch { throw new AcquisitionError("open_provider_tab"); }
    if (origin !== adapter.origin || !Number.isInteger(tab.id) || tab.incognito) throw new AcquisitionError("open_provider_tab");
    const stores = await this.api.cookies.getAllCookieStores();
    const store = stores.find(candidate => candidate.tabIds?.includes(tab.id) && (!tab.cookieStoreId || candidate.id === tab.cookieStoreId));
    if (!store || typeof store.id !== "string") throw new AcquisitionError("cookie_store_unavailable");
    return { storeId: store.id };
  }

  command(command) {
    return this.serialized(() => this.performCommand(command));
  }

  async performCommand(command) {
    if (command && typeof command === "object" && !Array.isArray(command) && Object.keys(command).join(",") === "command" && command.command === "health") return this.health();
    if (!command || typeof command !== "object" || Array.isArray(command) || Object.keys(command).sort().join(",") !== "adapter,command" || !COMMANDS.has(command.command)) throw new AcquisitionError("invalid_command");
    let adapter;
    try { adapter = getAdapter(command.adapter, { allowFixture: this.allowFixture }); } catch { throw new AcquisitionError("unsupported_adapter"); }
    if (command.command === "status") return this.status(adapter.id);
    if (this.inflight.has(adapter.id)) throw new AcquisitionError("operation_in_progress");
    this.inflight.add(adapter.id);
    try {
      const entries = await this.metadata();
      if (command.command === "disconnect") {
        const sources = entries.filter(entry => entry.adapter === adapter.id);
        // Resolve the selected context without reading provider data or requiring
        // acquisition permission. With no tab, a sole source remains removable.
        const tabs = await this.api.tabs.query({ active: true, currentWindow: true });
        const tab = tabs[0];
        let selected;
        if (tab) {
          if (tab.incognito) throw new AcquisitionError("select_source_context");
          let origin;
          try { origin = new URL(tab.url).origin; } catch {}
          if (origin === adapter.origin) {
            const stores = tab.cookieStoreId ? [] : await this.api.cookies?.getAllCookieStores?.() ?? [];
            const storeId = tab.cookieStoreId ?? stores.find(candidate => candidate.tabIds?.includes(tab.id))?.id;
            selected = sources.find(source => source.storeId === storeId);
            if (!selected) throw new AcquisitionError("source_not_connected");
          } else throw new AcquisitionError("select_source_context");
        }
        if (!selected && sources.length === 1) selected = sources[0];
        if (!selected) throw new AcquisitionError(sources.length ? "select_source_context" : "source_not_connected");
        await this.disconnectSource(selected, adapter);
        const remaining = await this.metadata();
        if (!remaining.some(entry => entry.adapter === adapter.id)) {
          const permissions = { origins: [hostPermission(adapter)] };
          if (!remaining.length) permissions.permissions = ["cookies"];
          await this.api.permissions.remove(permissions);
        }
        return { ok: true, status: "disconnected" };
      }
      const { storeId } = await this.context(adapter);
      let source = entries.find(entry => entry.adapter === adapter.id && entry.storeId === storeId);
      if (command.command === "connect") {
        if (!source) {
          if (entries.length >= 64) throw new AcquisitionError("source_limit_reached");
          source = { adapter: adapter.id, storeId, sourceId: this.randomId() };
          // Persist only source metadata before dispatch, keeping retries idempotent.
          entries.push(source);
          await this.saveMetadata(entries);
          await this.setState(source, "pending_connection");
        }
        return await this.reconcileSource(source, adapter, "browser.connect");
      }
      if (!source) throw new AcquisitionError("source_not_connected");
      if (command.command === "reconcile") {
        if ((await this.states())[source.sourceId] === "pending_disconnect") throw new AcquisitionError("disconnect_pending");
        return await this.reconcileSource(source, adapter);
      }
      throw new AcquisitionError("invalid_command");
    } finally { this.inflight.delete(adapter.id); }
  }

  async capture(source, adapter) {
    if (adapter.grantExport !== "enabled") return;
    const capsule = await acquireGrant({ adapter, storeId: source.storeId, cookies: this.api.cookies, readStorage: this.readStorage, now: this.now, browserKind: this.browserKind });
    // Provider identity is verified by the daemon, not inferred from source IDs.
    await this.send(source, adapter, "browser.importGrant", { capsule });
  }

  permissionsRemoved(permissions) {
    return this.serialized(() => this.removePermissions(permissions));
  }

  async removePermissions(permissions) {
    const origins = permissions.origins ?? [];
    const cookiesRemoved = permissions.permissions?.includes("cookies") ?? false;
    const entries = await this.metadata();
    let failure;
    for (const entry of entries) {
      const adapter = getAdapter(entry.adapter, { allowFixture: this.allowFixture });
      if (cookiesRemoved || origins.includes(hostPermission(adapter))) {
        try { await this.disconnectSource(entry, adapter); } catch (error) { failure ??= error; }
      }
    }
    if (failure) throw failure;
  }

  reconcilePermissions() {
    return this.serialized(async () => {
      this.startupBudget = { deadline: this.monotonicNow() + 10000, items: 0 };
      this.activeBudget = this.startupBudget;
      try {
      const entries = await this.metadata();
      const states = await this.states();
      let failure;
      for (const entry of entries) {
        if (this.monotonicNow() >= this.activeBudget.deadline || this.activeBudget.items >= 8) break;
        const adapter = getAdapter(entry.adapter, { allowFixture: this.allowFixture });
        if (states[entry.sourceId] === "pending_disconnect" || !await this.api.permissions.contains({ permissions: ["cookies"], origins: [hostPermission(adapter)] })) {
          try { await this.disconnectSource(entry, adapter); } catch (error) { failure ??= error; }
        }
      }
      if (failure) throw failure;
      } finally { this.activeBudget = null; }
    });
  }

  reconcileSources() {
    return this.serialized(async () => {
      this.activeBudget = this.startupBudget ?? { deadline: this.monotonicNow() + 10000, items: 0 };
      try {
      const entries = await this.metadata(); // Validated and capped at 64.
      const states = await this.states();
      let failure;
      const offset = entries.length ? this.reconcileCursor % entries.length : 0;
      const ordered = [...entries.slice(offset), ...entries.slice(0, offset)];
      for (const source of ordered) {
        if (this.monotonicNow() >= this.activeBudget.deadline || this.activeBudget.items >= 8) break;
        this.reconcileCursor = entries.length ? (entries.indexOf(source) + 1) % entries.length : 0;
        if (["pending_disconnect", "completion_unknown", "pending_connection"].includes(states[source.sourceId])) continue;
        const adapter = getAdapter(source.adapter, { allowFixture: this.allowFixture });
        if (!await this.api.permissions.contains({ permissions: ["cookies"], origins: [hostPermission(adapter)] })) continue;
        try { await this.reconcileSource(source, adapter); } catch (error) { failure ??= error; }
      }
      if (failure) throw failure;
      return this.status();
      } finally { this.activeBudget = null; this.startupBudget = null; }
    });
  }

  cookieChanged(changeInfo) {
    const scope = projectCookieChange(changeInfo, { allowFixture: this.allowFixture });
    return this.cookieScopeChanged(scope);
  }

  cookieScopeChanged(scope) {
    if (!scope) return Promise.resolve();
    const key = `${scope.adapter}:${scope.storeId}`;
    const existing = this.pendingCookieWork.get(key);
    if (existing) {
      existing.scope = scope;
      return existing.promise;
    }
    // One queued scope per registered-context candidate, with a hard global cap.
    // No raw change event or credential is retained in the serialized queue.
    if (this.pendingCookieWork.size >= 64) return Promise.resolve();
    const work = { scope, promise: null };
    this.pendingCookieWork.set(key, work);
    work.promise = this.serialized(async () => {
      const projected = work.scope;
      this.pendingCookieWork.delete(key);
      const entries = await this.metadata();
      const states = await this.states();
      for (const source of entries) {
        const adapter = getAdapter(source.adapter, { allowFixture: this.allowFixture });
        if (source.adapter !== projected.adapter || source.storeId !== projected.storeId) continue;
        if (states[source.sourceId] === "pending_disconnect") continue;
        if (!await this.api.permissions.contains({ permissions: ["cookies"], origins: [hostPermission(adapter)] })) continue;
        // Re-read the declared source, never trust/persist a credential in an event.
        if (projected.removed) await this.send(source, adapter, "browser.reconcile");
        else await this.capture(source, adapter);
      }
    });
    return work.promise;
  }
}

export function publicError(error) {
    const allowed = new Set(["provider_permission_required", "open_provider_tab", "cookie_store_unavailable", "source_not_connected", "select_source_context", "disconnect_pending", "uncertain_operation", "startup_budget_exhausted", "operation_in_progress", "source_limit_reached", "native_host_unavailable", "incompatible_native_host", "daemon_rejected_request", "grant_export_unproven", "storage_reader_unproven"]);
  return { ok: false, code: error instanceof AcquisitionError && allowed.has(error.code) ? error.code : "request_failed" };
}
