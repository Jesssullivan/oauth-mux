import { getAdapter, hostPermission } from "./adapters.mjs";
import { acquireGrant, projectCookieChange } from "./acquisition.mjs";
import { AcquisitionError, makeEnvelope, makeHealthEnvelope, validateResponse, validateConnectOutcome, authorityNumber } from "./protocol.mjs";
import { sendNativeRequest, requestNativeHealth } from "./native.mjs";

const STORAGE_KEY = "omuxSourceMetadataV1";
const STATE_KEY = "omuxSourceStatesV1";
const REQUEST_KEY = "omuxSourceRequestsV1";
const CLEANUP_CURSOR_KEY = "omuxSourceCleanupCursorV1";
const RECOVERY_CURSOR_KEY = "omuxConnectRecoveryCursorV1";
const STATES = new Set(["pending_connection", "connected_schema_unproven", "grant_submitted", "completion_unknown", "pending_disconnect"]);
const COMMANDS = new Set(["connect", "reconcile", "disconnect", "status"]);
const REQUEST_ID = /^[A-Za-z0-9._:-]{1,64}$/;

function validPendingRequest(value) {
  if (!value || typeof value !== "object" || Array.isArray(value) || typeof value.id !== "string" || !REQUEST_ID.test(value.id) || !["browser.connect", "browser.disconnect", "browser.reconcile", "browser.importGrant"].includes(value.method)) return false;
  const keys = Object.keys(value).sort().join(",");
  if (keys === "id,method") return true;
  if (value.method === "browser.connect" && ["expectedRevision,id,method,operationId", "expectedRevision,id,knownOutcome,method,operationId"].includes(keys)) {
    try { authorityNumber(value.expectedRevision); } catch { return false; }
    return typeof value.operationId === "string" && REQUEST_ID.test(value.operationId) && value.operationId !== value.id && (!Object.hasOwn(value, "knownOutcome") || ["committed", "stale"].includes(value.knownOutcome));
  }
  if (value.method === "browser.disconnect" && keys === "expectedGeneration,expectedRevision,id,method,operationId,resolvedConnect") {
    const original = value.resolvedConnect;
    if (!original || typeof original !== "object" || Array.isArray(original) || Object.keys(original).sort().join(",") !== "expectedRevision,generation,id,operationId") return false;
    try { authorityNumber(value.expectedGeneration, true); authorityNumber(value.expectedRevision); authorityNumber(original.generation, true); authorityNumber(original.expectedRevision); } catch { return false; }
    return value.expectedGeneration === original.generation && typeof value.operationId === "string" && REQUEST_ID.test(value.operationId) && value.operationId !== value.id && value.operationId !== original.operationId && typeof original.id === "string" && REQUEST_ID.test(original.id) && original.id !== value.id && typeof original.operationId === "string" && REQUEST_ID.test(original.operationId) && original.operationId !== original.id;
  }
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

  async requests() {
    const requests = (await this.api.storage.local.get(REQUEST_KEY))[REQUEST_KEY] ?? {};
    if (!requests || typeof requests !== "object" || Array.isArray(requests) || Object.keys(requests).length > 64 || Object.entries(requests).some(([id, value]) => !/^[A-Za-z0-9._:-]{1,128}$/.test(id) || !validPendingRequest(value))) throw new AcquisitionError("invalid_source_metadata");
    return requests;
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
    const requests = await this.requests();
    const sources = entries.filter(source => !adapterId || source.adapter === adapterId);
    let connection = sources.length ? "select_source_context" : "disconnected";
    if (adapterId) {
      const adapter = getAdapter(adapterId, { allowFixture: this.allowFixture });
      // Missing browser read access must not hide the saved removal choices.
      // A failed active-context lookup establishes no selected-context status.
      try {
        const [tab] = await this.api.tabs.query({ active: true, currentWindow: true });
        let origin;
        try { origin = new URL(tab?.url).origin; } catch {}
        if (tab && !tab.incognito && origin === adapter.origin) {
          const stores = tab.cookieStoreId ? [] : await this.api.cookies?.getAllCookieStores?.() ?? [];
          const storeId = tab.cookieStoreId ?? stores.find(candidate => candidate.tabIds?.includes(tab.id))?.id;
          const source = sources.find(source => source.storeId === storeId);
          connection = source ? states[source.sourceId] ?? "pending_connection" : "disconnected";
        } else if (!tab && sources.length === 1) connection = states[sources[0].sourceId] ?? "pending_connection";
      } catch { connection = sources.length ? "select_source_context" : "disconnected"; }
    }
    // UI readback exposes only categorical local state, never native response data.
    const pendingOperations = { "browser.connect": "connect", "browser.disconnect": "disconnect", "browser.reconcile": "reconcile", "browser.importGrant": "import" };
    return { ok: true, connection, identity: "unverified", grant: "unproven", capability: "unproven", sources: sources.map(source => ({ ...source, status: states[source.sourceId] ?? "pending_connection", pendingOperation: pendingOperations[requests[source.sourceId]?.method] ?? null, pendingOutcome: requests[source.sourceId]?.knownOutcome ?? null })) };
  }

  async health() { return { ok: true, ...await requestNativeHealth(this.api, this.browserKind, this.randomId(), this.nativeOptions) }; }

  async disconnectSource(source, adapter) {
    await this.setState(source, "pending_disconnect");
    await this.send(source, adapter, "browser.disconnect");
    const entries = await this.metadata();
    if (!entries.some(entry => entry.sourceId === source.sourceId && entry.adapter === source.adapter && entry.storeId === source.storeId)) throw new AcquisitionError("source_not_connected");
    const states = await this.states();
    delete states[source.sourceId];
    // Retain the exact removal descriptor throughout local retirement. Even a
    // partial/interrupted metadata/state write cannot fall back to a fresh,
    // unfenced Disconnect: only source metadata drives startup cleanup.
    await this.api.storage.local.set({ [STORAGE_KEY]: entries.filter(entry => entry.sourceId !== source.sourceId), [STATE_KEY]: states });
    if ((await this.metadata()).some(entry => entry.sourceId === source.sourceId)) throw new AcquisitionError("uncertain_operation");
    const requests = await this.requests();
    delete requests[source.sourceId];
    await this.api.storage.local.set({ [REQUEST_KEY]: requests });
  }

  async reconcileSource(source, adapter, method = "browser.reconcile") {
    try {
      const recovered = await this.send(source, adapter, method, method === "browser.connect" ? { provenance: { browser: this.browserKind, extensionId: this.api.runtime.id } } : {});
      // Outcome recovery is source metadata only; never replay/capture a capsule.
      if (!recovered) await this.capture(source, adapter);
      const status = !recovered && adapter.grantExport === "enabled" ? "grant_submitted" : "connected_schema_unproven";
      await this.setState(source, status);
      return { ok: true, status };
    } catch (error) {
      if ((await this.states())[source.sourceId] !== "pending_disconnect") await this.setState(source, "completion_unknown");
      throw error;
    }
  }

  async connectOutcome(source, adapter, operationId, expectedRevision) {
    const budget = this.activeBudget;
    if (budget && (budget.items >= 8 || this.monotonicNow() >= budget.deadline)) throw new AcquisitionError("startup_budget_exhausted");
    const request = makeEnvelope({ requestId: this.randomId(), sourceId: source.sourceId, adapter, method: "browser.connectOutcome", extra: { operationId, ...(expectedRevision === undefined ? {} : { expectedRevision }), provenance: { browser: this.browserKind, extensionId: this.api.runtime.id } } }, { allowFixture: this.allowFixture });
    if (budget) budget.items++;
    const response = await sendNativeRequest(this.api, request, { ...this.nativeOptions, healthEnvelope: makeHealthEnvelope(this.randomId(), { browser: this.browserKind, extensionId: this.api.runtime.id }), timeoutMs: Math.min(this.nativeOptions?.timeoutMs ?? 10000, Math.max(1, Math.floor(budget ? budget.deadline - this.monotonicNow() : 10000))) });
    const outcome = validateConnectOutcome(response, request.id, source.sourceId, operationId);
    if (outcome.outcome === "committed" && expectedRevision !== undefined && BigInt(outcome.connect_revision) !== BigInt(expectedRevision) + 1n) throw new AcquisitionError("invalid_native_response");
    return outcome;
  }

  async recoverConnect(source, adapter, pending, forRemoval = false) {
    if (!pending?.operationId) throw new AcquisitionError("connect_outcome_unknown");
    const outcome = await this.connectOutcome(source, adapter, pending.operationId, pending.expectedRevision);
    if (outcome.outcome !== "committed") throw new AcquisitionError("connect_outcome_unknown");
    if (!(await this.metadata()).some(entry => entry.sourceId === source.sourceId && entry.adapter === source.adapter && entry.storeId === source.storeId)) throw new AcquisitionError("source_not_connected");
    const requests = await this.requests();
    if (JSON.stringify(requests[source.sourceId]) !== JSON.stringify(pending)) throw new AcquisitionError("uncertain_operation");
    const current = outcome.current_generation === outcome.connect_generation;
    requests[source.sourceId] = { ...pending, knownOutcome: current ? "committed" : "stale" };
    await this.api.storage.local.set({ [REQUEST_KEY]: requests });
    if (!current || (!forRemoval && !outcome.authorized)) throw new AcquisitionError("source_authority_changed");
    if (forRemoval) return { id: pending.id, operationId: pending.operationId, expectedRevision: pending.expectedRevision, generation: outcome.connect_generation, removalRevision: outcome.current_revision };
    const states = await this.states();
    if (states[source.sourceId] === "pending_disconnect" || !await this.api.permissions.contains({ permissions: ["cookies"], origins: [hostPermission(adapter)] })) {
      await this.setState(source, "pending_disconnect");
      throw new AcquisitionError("disconnect_pending");
    }
    delete requests[source.sourceId];
    states[source.sourceId] = "connected_schema_unproven";
    // One local write preserves recovered state across an interrupted popup.
    await this.api.storage.local.set({ [REQUEST_KEY]: requests, [STATE_KEY]: states });
    return true;
  }

  async send(source, adapter, method, extra = {}) {
    const budget = this.activeBudget;
    const remaining = budget ? Math.floor(budget.deadline - this.monotonicNow()) : 10000;
    if (budget && (remaining < 1 || budget.items >= 8)) throw new AcquisitionError("startup_budget_exhausted");
    let requests = await this.requests();
    const entries = await this.metadata();
    for (const id of Object.keys(requests)) if (!entries.some(entry => entry.sourceId === id)) delete requests[id];
    let pending = requests[source.sourceId];
    let resolvedConnect;
    if (pending?.method === "browser.connect" && method === "browser.disconnect") {
      // Only a durable original-operation receipt can resolve this uncertainty.
      // Historical requests still have no such authority. Never replay Connect.
      resolvedConnect = await this.recoverConnect(source, adapter, pending, true);
      requests = await this.requests();
      pending = requests[source.sourceId];
    } else if (pending?.method === "browser.connect" && pending.operationId && ["browser.connect", "browser.reconcile"].includes(method)) {
      return this.recoverConnect(source, adapter, pending);
    }
    if (pending?.method === "browser.reconcile" && method === "browser.disconnect") {
      // Reconcile observes current authority without reconnecting or extending
      // it. Resolve only that retained read-only operation before removal.
      await this.send(source, adapter, pending.method);
      return this.send(source, adapter, method, extra);
    }
    // Explicit removal supersedes an unknown import without replaying its
    // credential capsule. Keep its opaque unresolved identity until removal ACK.
    const supersedesImport = pending?.method === "browser.importGrant" && method === "browser.disconnect";
    if (budget && (budget.items >= 8 || this.monotonicNow() >= budget.deadline)) throw new AcquisitionError("startup_budget_exhausted");
    if (pending && (pending.method !== method || method === "browser.importGrant") && !supersedesImport && !resolvedConnect) throw new AcquisitionError("uncertain_operation");
    const requestId = supersedesImport || resolvedConnect ? this.randomId() : pending?.id ?? this.randomId();
    if (supersedesImport && requestId === pending.id) throw new AcquisitionError("invalid_source_metadata");
    if (resolvedConnect && requestId === pending.id) throw new AcquisitionError("invalid_source_metadata");
    let connectIntent;
    let removalIntent;
    if (method === "browser.connect" && !pending) {
      const health = await requestNativeHealth(this.api, this.browserKind, this.randomId(), this.nativeOptions);
      if (health.capabilities.connect_recovery === true) {
        if (!health.custody_available) throw new AcquisitionError("daemon_rejected_request");
        const operationId = this.randomId();
        if (operationId === requestId) throw new AcquisitionError("invalid_source_metadata");
        const before = await this.connectOutcome(source, adapter, operationId);
        if (before.outcome !== "unknown") throw new AcquisitionError("uncertain_operation");
        connectIntent = { operationId, expectedRevision: before.current_revision };
      }
    }
    // The read-only capability/outcome preflight may outlive browser consent.
    // Refuse a fresh authorization if permission disappeared before dispatch.
    if (method === "browser.connect" && !pending && !await this.api.permissions.contains({ permissions: ["cookies"], origins: [hostPermission(adapter)] })) throw new AcquisitionError("provider_permission_required");
    if (resolvedConnect) {
      removalIntent = { operationId: this.randomId(), expectedRevision: resolvedConnect.removalRevision };
      if (removalIntent.operationId === requestId || removalIntent.operationId === resolvedConnect.operationId) throw new AcquisitionError("invalid_source_metadata");
    } else if (pending?.resolvedConnect) removalIntent = { operationId: pending.operationId, expectedRevision: pending.expectedRevision };
    const retainedConnect = resolvedConnect ? { id: resolvedConnect.id, operationId: resolvedConnect.operationId, expectedRevision: resolvedConnect.expectedRevision, generation: resolvedConnect.generation } : pending?.resolvedConnect;
    const generationFence = retainedConnect ? { expectedGeneration: retainedConnect.generation } : {};
    const envelope = makeEnvelope({ requestId, sourceId: source.sourceId, adapter, method, extra: { ...extra, ...connectIntent, ...removalIntent, ...generationFence, provenance: { browser: this.browserKind, extensionId: this.api.runtime.id } } }, { allowFixture: this.allowFixture });
    const superseded = supersedesImport ? { id: pending.id, method: pending.method } : pending?.superseded;
    requests[source.sourceId] = { id: requestId, method, ...connectIntent, ...removalIntent, ...(retainedConnect ? { ...generationFence, resolvedConnect: retainedConnect } : {}), ...(superseded ? { superseded } : {}) };
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
    const operationIntent = connectIntent ?? removalIntent;
    if (operationIntent) {
      const result = response.result;
      if (Object.keys(result).sort().join(",") !== "accepted,generation,operation_id,revision,source_id" || result.operation_id !== operationIntent.operationId || result.source_id !== source.sourceId) throw new AcquisitionError("invalid_native_response");
      authorityNumber(result.generation, true); authorityNumber(result.revision, true);
      if (BigInt(result.revision) !== BigInt(operationIntent.expectedRevision) + 1n || (retainedConnect && BigInt(result.generation) !== BigInt(retainedConnect.generation) + 1n)) throw new AcquisitionError("invalid_native_response");
      if (connectIntent) {
        await this.recoverConnect(source, adapter, requests[source.sourceId]);
        // This initial gesture received the original mutation ACK. Preserve
        // its one fresh fixture capture; later recovery never captures/replays.
        return false;
      }
    }
    // Disconnect's immutable identity stays durable until disconnectSource
    // has retired the corresponding metadata and observed its absence.
    if (method === "browser.disconnect") return;
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
    if (!command || typeof command !== "object" || Array.isArray(command) || !COMMANDS.has(command.command)) throw new AcquisitionError("invalid_command");
    const fields = Object.keys(command).sort().join(",");
    const storedRemoval = fields === "adapter,command,sourceId" && command.command === "disconnect";
    if (fields !== "adapter,command" && !storedRemoval) throw new AcquisitionError("invalid_command");
    if (storedRemoval && (typeof command.sourceId !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(command.sourceId))) throw new AcquisitionError("invalid_command");
    let adapter;
    try { adapter = getAdapter(command.adapter, { allowFixture: this.allowFixture }); } catch { throw new AcquisitionError("unsupported_adapter"); }
    if (command.command === "status") return this.status(adapter.id);
    if (this.inflight.has(adapter.id)) throw new AcquisitionError("operation_in_progress");
    this.inflight.add(adapter.id);
    try {
      const entries = await this.metadata();
      if (command.command === "disconnect") {
        const sources = entries.filter(entry => entry.adapter === adapter.id);
        let selected;
        if (storedRemoval) {
          // Explicit popup selection is removal intent only. Recheck membership
          // and provider now; a stale selection cannot target a replacement.
          selected = sources.find(source => source.sourceId === command.sourceId);
          if (!selected) throw new AcquisitionError("source_not_connected");
        } else {
          // Resolve the active context without reading provider data or requiring
          // acquisition permission. With no tab, a sole source remains removable.
          const tabs = await this.api.tabs.query({ active: true, currentWindow: true });
          const tab = tabs[0];
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
        }
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
        if (source && (await this.states())[source.sourceId] === "pending_disconnect") throw new AcquisitionError("disconnect_pending");
        if (!source) {
          if (entries.length >= 64) throw new AcquisitionError("source_limit_reached");
          source = { adapter: adapter.id, storeId, sourceId: this.randomId() };
          // Persist only metadata before dispatch to retain the same source ID.
          // Legacy correlation IDs alone still cannot settle an outcome.
          // Recovery-capable hosts receive a separate durable operation intent.
          entries.push(source);
          await this.saveMetadata(entries);
          await this.setState(source, "pending_connection");
        }
        return await this.reconcileSource(source, adapter, "browser.connect");
      }
      if (!source) throw new AcquisitionError("source_not_connected");
      if (command.command === "reconcile") {
        if ((await this.states())[source.sourceId] === "pending_disconnect") {
          const pending = (await this.requests())[source.sourceId];
          if (pending?.method === "browser.connect") {
            if (pending.operationId) await this.recoverConnect(source, adapter, pending, true);
            throw new AcquisitionError(pending.operationId ? "disconnect_pending" : "connect_outcome_unknown");
          }
          throw new AcquisitionError("disconnect_pending");
        }
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
      const requests = await this.requests();
      const cursor = (await this.api.storage.local.get(CLEANUP_CURSOR_KEY))[CLEANUP_CURSOR_KEY];
      if (cursor !== undefined && (typeof cursor !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(cursor))) throw new AcquisitionError("invalid_source_metadata");
      const offset = Math.max(0, entries.findIndex(entry => entry.sourceId === cursor));
      const ordered = [...entries.slice(offset), ...entries.slice(0, offset)];
      let failure;
      for (const [index, entry] of ordered.entries()) {
        if (this.monotonicNow() >= this.activeBudget.deadline || this.activeBudget.items >= 8) break;
        // Persist only the next opaque source ID before work. A worker restart
        // must not strand later removals behind repeatedly failing contexts.
        // This hint confers no source, permission or mutation authority.
        await this.api.storage.local.set({ [CLEANUP_CURSOR_KEY]: ordered[(index + 1) % ordered.length].sourceId });
        if (this.monotonicNow() >= this.activeBudget.deadline) break;
        const adapter = getAdapter(entry.adapter, { allowFixture: this.allowFixture });
        // A retained, validated Disconnect is removal intent even when an
        // interrupted retirement removed state before source metadata.
        if (states[entry.sourceId] === "pending_disconnect" || requests[entry.sourceId]?.method === "browser.disconnect" || !await this.api.permissions.contains({ permissions: ["cookies"], origins: [hostPermission(adapter)] })) {
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
      const requests = await this.requests();
      let failure;
      const cursor = (await this.api.storage.local.get(RECOVERY_CURSOR_KEY))[RECOVERY_CURSOR_KEY];
      if (cursor !== undefined && (typeof cursor !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/.test(cursor))) throw new AcquisitionError("invalid_source_metadata");
      const offset = entries.length ? (cursor === undefined ? this.reconcileCursor % entries.length : Math.max(0, entries.findIndex(entry => entry.sourceId === cursor))) : 0;
      const ordered = [...entries.slice(offset), ...entries.slice(0, offset)];
      for (const source of ordered) {
        if (this.monotonicNow() >= this.activeBudget.deadline || this.activeBudget.items >= 8) break;
        this.reconcileCursor = entries.length ? (entries.indexOf(source) + 1) % entries.length : 0;
        if (states[source.sourceId] === "pending_disconnect") continue;
        const adapter = getAdapter(source.adapter, { allowFixture: this.allowFixture });
        if (!await this.api.permissions.contains({ permissions: ["cookies"], origins: [hostPermission(adapter)] })) continue;
        if (["completion_unknown", "pending_connection"].includes(states[source.sourceId])) {
          if (requests[source.sourceId]?.method !== "browser.connect" || !requests[source.sourceId].operationId) continue;
          await this.api.storage.local.set({ [RECOVERY_CURSOR_KEY]: ordered[(ordered.indexOf(source) + 1) % ordered.length].sourceId });
          try { await this.recoverConnect(source, adapter, requests[source.sourceId]); } catch (error) { failure ??= error; }
          continue;
        }
        await this.api.storage.local.set({ [RECOVERY_CURSOR_KEY]: ordered[(ordered.indexOf(source) + 1) % ordered.length].sourceId });
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
    const allowed = new Set(["provider_permission_required", "open_provider_tab", "cookie_store_unavailable", "source_not_connected", "select_source_context", "disconnect_pending", "connect_outcome_unknown", "source_authority_changed", "uncertain_operation", "startup_budget_exhausted", "operation_in_progress", "source_limit_reached", "native_host_unavailable", "incompatible_native_host", "daemon_rejected_request", "grant_export_unproven", "storage_reader_unproven"]);
  return { ok: false, code: error instanceof AcquisitionError && allowed.has(error.code) ? error.code : "request_failed" };
}
