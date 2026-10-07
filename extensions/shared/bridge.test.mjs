import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { inflateRawSync } from "node:zlib";
import { ADAPTERS, getAdapter, hostPermission } from "./adapters.mjs";
import { AcquisitionError, makeEnvelope, validateEnvelope, validateCapsule, validateResponse, MAX_SECRET_BYTES } from "./protocol.mjs";
import { acquireGrant, projectCookieChange } from "./acquisition.mjs";
import { BrowserService, publicError } from "./service.mjs";
import { sendNativeRequest } from "./native.mjs";

const adapter = getAdapter("fixture", { allowFixture: true });
const fakeValue = "synthetic-test-value";
const cookie = (overrides = {}) => ({ name: "omux_fixture_session", value: fakeValue, domain: "fixture.invalid", path: "/", secure: true, httpOnly: true, hostOnly: true, session: false, sameSite: "lax", storeId: "container-4", expirationDate: 1200.75, ...overrides });
const capsule = (overrides = {}) => ({ kind: "browser_session", purpose: "identity_observation", renewalAuthority: "external", browserBound: false, capturedAt: 1000, expiresAt: 1200, cookies: [cookie()], storage: [], ...overrides });
const envelope = (method, extra = {}, overrides = {}) => ({ version: 1, id: "request-1", method, params: { sourceId: "source-1", adapter: "fixture", origin: adapter.origin, provenance: { browser: "firefox", extensionId: "browser-sources@omux.xoxd.ai", channel: "release" }, ...extra }, ...overrides });
const fixtureOptions = { allowFixture: true };
const fails = (code) => error => error instanceof AcquisitionError && error.code === code;

function event() {
  const listeners = new Set();
  return { addListener(listener) { listeners.add(listener); }, removeListener(listener) { listeners.delete(listener); }, emit(...values) { for (const listener of [...listeners]) listener(...values); }, get size() { return listeners.size; } };
}

function nativePort({ messages = [], healthMessages = [], channel = "release", nativeFailure = false, reply = true, mutationReply } = {}) {
  const port = { onMessage: event(), onDisconnect: event(), disconnected: false, postMessage(message) {
    (message.method === "browser.health" ? healthMessages : messages).push(structuredClone(message));
    queueMicrotask(() => {
      if (port.disconnected) return;
      if (nativeFailure && message.method !== "browser.health") port.onDisconnect.emit();
      else if (reply) port.onMessage.emit(message.method !== "browser.health" && mutationReply ? mutationReply(message) : { version: 1, id: message.id, result: message.method === "browser.health" ? { status: "ready", custody_available: true, provider_access: false, protocolVersion: 1, channel, capabilities: { source_connection: true, production_export: false } } : { accepted: true } });
    });
  }, disconnect() { port.disconnected = true; port.onDisconnect.emit(); } };
  return port;
}

function browserMock({ selectedAdapter = "fixture", storeId = "container-4", nativeFailure = false, grantCookies = [cookie()], permission = true } = {}) {
  const persisted = {};
  const messages = [];
  const cookieQueries = [];
  const removedPermissions = [];
  const selected = getAdapter(selectedAdapter, fixtureOptions);
  let idCounter = 0;
  const api = {
    runtime: { id: "browser-sources@omux.xoxd.ai", connectNative(host) {
      assert.equal(host, "ai.xoxd.omux");
      return nativePort({ messages, nativeFailure });
    } },
    storage: { local: { async get(key) { return structuredClone({ [key]: persisted[key] }); }, async set(value) { Object.assign(persisted, structuredClone(value)); } } },
    permissions: { async contains(value) { assert.deepEqual(value, { permissions: ["cookies"], origins: [hostPermission(selected)] }); return permission; }, async remove(value) { removedPermissions.push(value); return true; } },
    tabs: { async query() { return [{ id: 7, url: `${selected.origin}/settings`, cookieStoreId: storeId, incognito: false }]; } },
    cookies: { async getAllCookieStores() { return [{ id: "other-container", tabIds: [8] }, { id: storeId, tabIds: [7] }]; }, async getAll(query) {
      cookieQueries.push(query);
      assert.equal(Object.hasOwn(query, "firstPartyDomain"), true, "Firefox FPI queries must declare their exact context");
      return structuredClone(grantCookies.filter(value => (value.firstPartyDomain ?? "") === query.firstPartyDomain && (value.partitionKey ? value.partitionKey.topLevelSite === query.partitionKey?.topLevelSite : !query.partitionKey)));
    } },
  };
  const service = new BrowserService({ api, browserKind: "firefox", randomId: () => `opaque-${++idCounter}`, now: () => 1000, allowFixture: true, readStorage: async (origin, keys, context) => {
    assert.equal(origin, adapter.origin);
    assert.deepEqual(keys, ["omux_fixture_state"]);
    assert.equal(context.storeId, storeId);
    assert.equal(context.browserKind, "firefox");
    assert.deepEqual(context.browserContext, adapter.browserContext);
    return [{ origin, key: "omux_fixture_state", value: "synthetic-storage-value" }];
  } });
  return { service, api, persisted, messages, cookieQueries, removedPermissions };
}

test("production adapters request only fixed provider origins and export no grants", async () => {
  assert.deepEqual(Object.keys(ADAPTERS), ["codex", "claude", "github"]);
  for (const descriptor of Object.values(ADAPTERS)) {
    assert.equal(descriptor.grantExport, "blocked_pending_schema_proof");
    assert.deepEqual(descriptor.cookies, []);
    assert.deepEqual(descriptor.storageKeys, []);
    let queried = false;
    await assert.rejects(acquireGrant({ adapter: descriptor, cookies: { getAll: async () => { queried = true; } } }), fails("grant_export_unproven"));
    assert.equal(queried, false);
  }
  assert.throws(() => getAdapter("fixture"));
  assert.throws(() => getAdapter("__proto__"));
});

test("protocol rejects general control methods, arbitrary origins and extra fields", () => {
  const connect = envelope("browser.connect", { provenance: { browser: "firefox", extensionId: "browser-sources@omux.xoxd.ai", channel: "release" } });
  assert.equal(validateEnvelope(connect, fixtureOptions), connect);
  assert.throws(() => validateEnvelope({ ...connect, method: "accounts.forget" }, fixtureOptions), fails("unsupported_protocol"));
  assert.throws(() => validateEnvelope({ ...connect, version: 2 }, fixtureOptions), fails("unsupported_protocol"));
  assert.throws(() => validateEnvelope({ ...connect, params: { ...connect.params, origin: "https://fixture.invalid/" } }, fixtureOptions), fails("invalid_origin"));
  assert.throws(() => validateEnvelope({ ...connect, params: { ...connect.params, origin: "https://another.invalid" } }, fixtureOptions), fails("wrong_adapter_origin"));
  assert.throws(() => validateEnvelope({ ...connect, params: { ...connect.params, identity: "assumed-from-browser" } }, fixtureOptions), fails("invalid_fields"));
  assert.throws(() => validateEnvelope({ ...connect, params: { ...connect.params, provenance: { ...connect.params.provenance, token: fakeValue } } }, fixtureOptions), fails("invalid_fields"));
  assert.throws(() => validateEnvelope(envelope("browser.disconnect", { capsule: capsule() }), fixtureOptions), fails("invalid_fields"));
  assert.throws(() => validateEnvelope(connect), fails("unsupported_adapter"));
});

test("grant authority stays external and purpose-limited, with bounded provider validity", () => {
  assert.equal(validateCapsule(capsule(), adapter).expiresAt, 1200);
  for (const value of [capsule({ purpose: "terminal_api" }), capsule({ renewalAuthority: "omux" }), capsule({ browserBound: true })]) assert.throws(() => validateCapsule(value, adapter), fails("invalid_grant_authority"));
  assert.throws(() => validateCapsule(capsule({ expiresAt: 1201 }), adapter), fails("invalid_grant_expiry"));
  assert.throws(() => validateCapsule(capsule({ expiresAt: 1000 }), adapter), fails("expired_grant"));
  assert.throws(() => validateCapsule(capsule({ capturedAt: 0.5 }), adapter), fails("invalid_time"));
  assert.throws(() => validateCapsule(capsule({ cookies: [], storage: [] }), adapter), fails("empty_grant"));
  assert.throws(() => validateCapsule(capsule({ rawHtml: fakeValue }), adapter), fails("invalid_fields"));
  assert.throws(() => validateCapsule(capsule(), ADAPTERS.codex), fails("grant_export_unproven"));
});

test("cookies and storage retain declared scope and reject source mixing", () => {
  const partitioned = cookie({ partitionKey: { topLevelSite: adapter.origin, hasCrossSiteAncestor: false }, firstPartyDomain: "fixture.invalid" });
  assert.deepEqual(validateCapsule(capsule({ cookies: [partitioned] }), adapter).cookies[0], partitioned);
  assert.throws(() => validateCapsule(capsule({ cookies: [cookie({ storeId: "a" }), cookie({ storeId: "b" })] }), adapter), fails("mixed_cookie_stores"));
  assert.throws(() => validateCapsule(capsule({ cookies: [cookie(), cookie()] }), adapter), fails("duplicate_cookie"));
  assert.throws(() => validateCapsule(capsule({ cookies: [partitioned, cookie({ partitionKey: { hasCrossSiteAncestor: false, topLevelSite: adapter.origin }, firstPartyDomain: "fixture.invalid" })] }), adapter), fails("duplicate_cookie"));
  assert.throws(() => validateCapsule(capsule({ cookies: [cookie({ partitionKey: { topLevelSite: "https://other.invalid" } })] }), adapter), fails("wrong_cookie_partition"));
  assert.throws(() => validateCapsule(capsule({ cookies: [cookie({ firstPartyDomain: "other.invalid" })] }), adapter), fails("wrong_cookie_partition"));
  assert.throws(() => validateCapsule(capsule({ cookies: [cookie({ path: "/private" })] }), adapter), fails("undeclared_cookie"));
  assert.throws(() => validateCapsule(capsule({ cookies: [cookie({ secure: false })] }), adapter), fails("invalid_cookie"));
  assert.throws(() => validateCapsule(capsule({ cookies: [cookie({ value: "unexpected;cookie" })] }), adapter), fails("invalid_cookie_value"));
  assert.throws(() => validateCapsule(capsule({ cookies: [cookie({ value: "unexpected cookie" })] }), adapter), fails("invalid_cookie_value"));
  assert.throws(() => validateCapsule(capsule({ cookies: [cookie({ value: "" })] }), adapter), fails("invalid_cookie_value"));
  for (const value of ['unexpected,cookie', 'unexpected"cookie', 'unexpected\\cookie']) assert.throws(() => validateCapsule(capsule({ cookies: [cookie({ value })] }), adapter), fails("invalid_cookie_value"));
  assert.throws(() => validateCapsule(capsule({ cookies: [cookie(), partitioned] }), adapter), fails("mixed_cookie_partitions"));
  assert.throws(() => validateCapsule(capsule({ storage: [{ origin: adapter.origin, key: "all-local-storage", value: fakeValue }] }), adapter), fails("undeclared_storage"));
  assert.throws(() => validateCapsule(capsule({ storage: [{ origin: "https://other.invalid", key: "omux_fixture_state", value: fakeValue }] }), adapter), fails("undeclared_storage"));
});

test("secret payload limits count UTF-8 bytes rather than characters", () => {
  validateCapsule(capsule({ storage: [{ origin: adapter.origin, key: "omux_fixture_state", value: "é".repeat(MAX_SECRET_BYTES / 2) }] }), adapter);
  assert.throws(() => validateCapsule(capsule({ storage: [{ origin: adapter.origin, key: "omux_fixture_state", value: "é".repeat(MAX_SECRET_BYTES / 2 + 1) }] }), adapter), fails("invalid_string"));
  assert.throws(() => validateCapsule(capsule({ cookies: [cookie({ value: "x".repeat(MAX_SECRET_BYTES + 1) })] }), adapter), fails("invalid_string"));
});

test("unpartitioned acquisition queries only declared cookies and filters unrelated contexts", async () => {
  const good = cookie();
  const values = [good, cookie({ name: "other" }), cookie({ storeId: "other-container" }), cookie({ path: "/private" }), cookie({ expirationDate: 999 }), cookie({ partitionKey: { topLevelSite: "https://other.invalid" } }), cookie({ firstPartyDomain: "other.invalid" })];
  const queries = [];
  const captured = await acquireGrant({ adapter, storeId: "container-4", now: () => 1000.4, cookies: { async getAll(query) { queries.push(query); return values; } }, readStorage: async () => [{ origin: adapter.origin, key: "omux_fixture_state", value: "fixture" }] });
  assert.deepEqual(queries, [{ url: "https://fixture.invalid/", name: "omux_fixture_session", storeId: "container-4" }]);
  assert.deepEqual(captured.cookies, [good]);
  assert.equal(captured.capturedAt, 1000);
  assert.equal(captured.expiresAt, 1200);
  assert.equal(captured.renewalAuthority, "external");
});

test("partitioned Firefox acquisition explicitly supplies adapter-declared partition and FPI context", async () => {
  const partitionedAdapter = { ...adapter, browserContext: { partition: "origin", firefoxFirstPartyDomain: "fixture.invalid" } };
  const good = cookie({ partitionKey: { topLevelSite: adapter.origin, hasCrossSiteAncestor: false }, firstPartyDomain: "fixture.invalid" });
  let queried = false;
  const captured = await acquireGrant({ adapter: partitionedAdapter, storeId: "container-4", browserKind: "firefox", now: () => 1000, readStorage: async () => [], cookies: { async getAll(query) {
    assert.deepEqual(query, { url: "https://fixture.invalid/", name: "omux_fixture_session", storeId: "container-4", partitionKey: { topLevelSite: adapter.origin }, firstPartyDomain: "fixture.invalid" });
    queried = true;
    return query.partitionKey?.topLevelSite === good.partitionKey.topLevelSite && query.firstPartyDomain === good.firstPartyDomain ? [good] : [];
  } } });
  assert.equal(queried, true);
  assert.deepEqual(captured.cookies, [good]);
});

test("session cookies preserve unknown expiry without fabricating validity", async () => {
  const sessionCookie = cookie({ session: true });
  delete sessionCookie.expirationDate;
  const captured = await acquireGrant({ adapter, storeId: "container-4", now: () => 1000, cookies: { async getAll() { return [sessionCookie]; } }, readStorage: async () => [] });
  assert.equal(Object.hasOwn(captured, "expiresAt"), false);
  assert.equal(captured.cookies[0].session, true);
  assert.throws(() => validateCapsule(capsule({ cookies: [cookie({ session: true })] }), adapter), fails("invalid_cookie_expiry"));
});

test("observations use typed finite capacity without credential additions", () => {
  const observation = { resource: "fixture.calls", unit: "calls", value: 4, limit: 10, observedAt: 1000, expiresAt: 1100 };
  validateEnvelope(envelope("browser.observation", { observation }), fixtureOptions);
  for (const bad of [{ ...observation, value: NaN }, { ...observation, limit: 3 }, { ...observation, unit: "credits_and_time" }, { ...observation, expiresAt: 1000 }, { ...observation, credential: fakeValue }]) assert.throws(() => validateEnvelope(envelope("browser.observation", { observation: bad }), fixtureOptions));
});

test("native response validates identity and never propagates arbitrary error content", () => {
  assert.equal(validateResponse({ version: 1, id: "request-1", result: { arbitrary: fakeValue } }, "request-1"), true);
  assert.throws(() => validateResponse({ version: 1, id: "another-request", result: {} }, "request-1"), fails("invalid_native_response"));
  assert.throws(() => validateResponse({ version: 1, id: "request-1", error: { code: "rejected", message: fakeValue } }, "request-1"), fails("daemon_rejected_request"));
  assert.deepEqual(publicError(new Error(fakeValue)), { ok: false, code: "request_failed" });
  assert.deepEqual(publicError(new AcquisitionError("native_host_unavailable")), { ok: false, code: "native_host_unavailable" });
});

test("native port deadlines close transport and remove handlers without exposing platform errors", async () => {
  const port = nativePort({ reply: false });
  let deadline;
  let cleared = false;
  const api = { runtime: { connectNative: () => port, lastError: { message: fakeValue } } };
  const request = sendNativeRequest(api, envelope("browser.reconcile"), { setTimer(callback, milliseconds) { assert.equal(milliseconds, 10000); deadline = callback; return 1; }, clearTimer(handle) { assert.equal(handle, 1); cleared = true; } });
  const rejected = assert.rejects(request, fails("native_host_unavailable"));
  deadline();
  await rejected;
  assert.equal(port.disconnected, true);
  assert.equal(port.onMessage.size, 0);
  assert.equal(port.onDisconnect.size, 0);
  assert.equal(cleared, true);
  // Late native delivery cannot resurrect a failed source operation.
  port.onMessage.emit({ version: 1, id: "request-1", result: {} });
});

test("native successful replies close the one-request transport and cancel its deadline", async () => {
  const port = nativePort();
  let cleared = false;
  const api = { runtime: { connectNative: () => port } };
  const response = await sendNativeRequest(api, envelope("browser.reconcile"), { setTimer() { return 1; }, clearTimer() { cleared = true; } });
  assert.equal(response.id, "request-1");
  assert.equal(port.disconnected, true);
  assert.equal(cleared, true);
  assert.equal(port.onMessage.size, 0);
  assert.equal(port.onDisconnect.size, 0);
});

test("connect and reconcile persist opaque provenance only and reuse source after restart", async () => {
  const mock = browserMock();
  assert.deepEqual(await mock.service.command({ command: "connect", adapter: "fixture" }), { ok: true, status: "grant_submitted" });
  assert.deepEqual(mock.messages.map(message => message.method), ["browser.connect", "browser.importGrant"]);
  const firstSourceId = mock.messages[0].params.sourceId;
  assert.deepEqual(mock.persisted.omuxSourceMetadataV1, [{ adapter: "fixture", storeId: "container-4", sourceId: firstSourceId }]);
  assert.equal(JSON.stringify(mock.persisted).includes(fakeValue), false);
  assert.equal(mock.messages[0].params.provenance.extensionId, mock.api.runtime.id);
  assert.equal(mock.messages.every(message => message.params.provenance.channel === "release"), true);
  assert.equal(mock.messages[1].params.capsule.renewalAuthority, "external");
  const nextService = new BrowserService({ api: mock.api, browserKind: "firefox", randomId: () => "after-restart", now: () => 1000, allowFixture: true, readStorage: async () => [] });
  await nextService.command({ command: "reconcile", adapter: "fixture" });
  assert.deepEqual(mock.messages.slice(2).map(message => message.method), ["browser.reconcile", "browser.importGrant"]);
  assert.equal(mock.messages.slice(2).every(message => message.params.provenance.channel === "release"), true);
  assert.equal(mock.messages[2].params.sourceId, firstSourceId);
});

test("production connections communicate provenance without reading/exporting credentials", async () => {
  const mock = browserMock({ selectedAdapter: "codex" });
  const result = await mock.service.command({ command: "connect", adapter: "codex" });
  assert.deepEqual(result, { ok: true, status: "connected_schema_unproven" });
  assert.deepEqual(mock.messages.map(message => message.method), ["browser.connect"]);
  assert.deepEqual(mock.cookieQueries, []);
  await mock.service.command({ command: "reconcile", adapter: "codex" });
  assert.equal(mock.messages.at(-1).method, "browser.reconcile");
  await mock.service.cookieChanged({ removed: false, cookie: cookie() });
  assert.equal(mock.messages.length, 2);
});

test("raw source provenance requires its declared release or development channel", () => {
  for (const method of ["browser.connect", "browser.reconcile", "browser.disconnect"]) {
    const request = envelope(method);
    const missing = structuredClone(request);
    delete missing.params.provenance.channel;
    assert.throws(() => validateEnvelope(missing, fixtureOptions), fails("invalid_fields"));
    assert.equal(validateEnvelope(request, fixtureOptions).params.provenance.channel, "release");
    const wrongChannel = structuredClone(request);
    wrongChannel.params.provenance.channel = "development";
    assert.throws(() => validateEnvelope(wrongChannel, fixtureOptions), fails("incompatible_native_host"));
    const unknownChannel = structuredClone(request);
    unknownChannel.params.provenance.channel = "unknown";
    assert.throws(() => validateEnvelope(unknownChannel, fixtureOptions), fails("invalid_provenance"));
  }
});

test("declared cookie rotation reimports a fresh externally owned capsule without persisting event data", async () => {
  const mock = browserMock();
  await mock.service.command({ command: "connect", adapter: "fixture" });
  await mock.service.cookieChanged({ removed: false, cookie: cookie({ name: "unrelated" }) });
  await mock.service.cookieChanged({ removed: false, cookie: cookie({ storeId: "other-container" }) });
  await mock.service.cookieChanged({ removed: false, cookie: cookie({ partitionKey: { topLevelSite: "https://other.invalid" } }) });
  assert.equal(mock.messages.length, 2);
  mock.api.cookies.getAll = async () => [cookie({ value: "synthetic-rotated-value", expirationDate: 1300 })];
  await mock.service.cookieChanged({ removed: false, cookie: cookie({ value: "untrusted-event-value" }) });
  assert.equal(mock.messages.length, 3);
  const grant = mock.messages.at(-1).params.capsule;
  assert.equal(grant.cookies[0].value, "synthetic-rotated-value");
  assert.equal(grant.expiresAt, 1300);
  assert.equal(grant.renewalAuthority, "external");
  assert.equal(JSON.stringify(mock.persisted).includes("synthetic-rotated-value"), false);
  assert.equal(JSON.stringify(mock.persisted).includes("untrusted-event-value"), false);
  await mock.service.cookieChanged({ removed: true, cookie: cookie() });
  assert.equal(mock.messages.at(-1).method, "browser.reconcile");
  assert.equal(Object.hasOwn(mock.messages.at(-1).params, "capsule"), false);
  assert.equal(mock.persisted.omuxSourceMetadataV1.length, 1);
});

test("cookie event projection never reads the secret value, including blocked production adapters", async () => {
  const eventCookie = cookie();
  Object.defineProperty(eventCookie, "value", { get() { throw new Error("cookie event secret must not be read"); } });
  assert.deepEqual(projectCookieChange({ removed: false, cookie: eventCookie }, fixtureOptions), { adapter: "fixture", storeId: "container-4", removed: false });
  assert.equal(projectCookieChange({ removed: false, cookie: eventCookie }), null);
  const mock = browserMock();
  await mock.service.command({ command: "connect", adapter: "fixture" });
  await mock.service.cookieChanged({ removed: false, cookie: eventCookie });
  assert.equal(mock.messages.length, 3);
});

test("cookie event bursts coalesce one scope per store and cap total queued work during a native stall", async () => {
  const mock = browserMock();
  await mock.service.command({ command: "connect", adapter: "fixture" });
  let unblock;
  const blocked = mock.service.serialized(() => new Promise(resolve => { unblock = resolve; }));
  await Promise.resolve();
  const eventCookie = cookie();
  Object.defineProperty(eventCookie, "value", { get() { throw new Error("queued cookie event must not retain/read credentials"); } });
  const promises = [];
  for (let index = 0; index < 1000; index++) promises.push(mock.service.cookieChanged({ removed: false, cookie: eventCookie }));
  assert.equal(mock.service.pendingCookieWork.size, 1);
  assert.equal(new Set(promises).size, 1);
  for (let index = 0; index < 1000; index++) promises.push(mock.service.cookieChanged({ removed: false, cookie: { ...cookie(), storeId: `unregistered-${index}` } }));
  assert.equal(mock.service.pendingCookieWork.size, 64);
  for (const work of mock.service.pendingCookieWork.values()) assert.deepEqual(Object.keys(work.scope).sort(), ["adapter", "removed", "storeId"]);
  unblock();
  await blocked;
  await Promise.all(promises);
  assert.equal(mock.service.pendingCookieWork.size, 0);
  assert.equal(mock.messages.length, 3, "one registered store imports once; unregistered store events never call the provider");
});

test("disconnect retains metadata on bridge failure, then removes source and permission on success", async () => {
  const mock = browserMock({ selectedAdapter: "codex" });
  await mock.service.command({ command: "connect", adapter: "codex" });
  const originalNative = mock.api.runtime.connectNative;
  mock.api.runtime.connectNative = () => { throw new Error(fakeValue); };
  await assert.rejects(mock.service.command({ command: "disconnect", adapter: "codex" }), fails("native_host_unavailable"));
  assert.equal(mock.persisted.omuxSourceMetadataV1.length, 1);
  assert.deepEqual(mock.removedPermissions, []);
  mock.api.runtime.connectNative = originalNative;
  await mock.service.command({ command: "disconnect", adapter: "codex" });
  assert.equal(mock.messages.at(-1).method, "browser.disconnect");
  assert.deepEqual(mock.persisted.omuxSourceMetadataV1, []);
  assert.deepEqual(mock.removedPermissions, [{ origins: ["https://chatgpt.com/*"], permissions: ["cookies"] }]);
});

test("permissions revocation disconnects the daemon source and retains no grants", async () => {
  const mock = browserMock({ selectedAdapter: "claude" });
  await mock.service.command({ command: "connect", adapter: "claude" });
  await mock.service.permissionsRemoved({ origins: ["https://claude.ai/*"] });
  assert.equal(mock.messages.at(-1).method, "browser.disconnect");
  assert.deepEqual(mock.persisted.omuxSourceMetadataV1, []);
});

test("provider permission removal isolates other providers; cookie permission removal detaches all remaining sources", async () => {
  const mock = browserMock({ selectedAdapter: "codex" });
  mock.api.permissions.contains = async () => true;
  await mock.service.command({ command: "connect", adapter: "codex" });
  mock.api.tabs.query = async () => [{ id: 7, url: "https://github.com/settings", cookieStoreId: "container-4", incognito: false }];
  await mock.service.command({ command: "connect", adapter: "github" });
  await mock.service.permissionsRemoved({ origins: ["https://chatgpt.com/*"] });
  assert.deepEqual(mock.persisted.omuxSourceMetadataV1.map(source => source.adapter), ["github"]);
  assert.equal(mock.messages.at(-1).params.adapter, "codex");
  await mock.service.permissionsRemoved({ permissions: ["cookies"] });
  assert.deepEqual(mock.persisted.omuxSourceMetadataV1, []);
  assert.equal(mock.messages.at(-1).method, "browser.disconnect");
  assert.equal(mock.messages.at(-1).params.adapter, "github");
});

test("disconnect works after closing provider tabs and losing provider access", async () => {
  const mock = browserMock({ selectedAdapter: "github" });
  await mock.service.command({ command: "connect", adapter: "github" });
  mock.api.tabs.query = async () => [];
  mock.api.permissions.contains = async () => false;
  const result = await mock.service.command({ command: "disconnect", adapter: "github" });
  assert.deepEqual(result, { ok: true, status: "disconnected" });
  assert.equal(mock.messages.at(-1).method, "browser.disconnect");
  assert.deepEqual(mock.persisted.omuxSourceMetadataV1, []);
});

test("disconnect resolves a selected Firefox context after the optional cookies API disappears", async () => {
  const mock = browserMock({ selectedAdapter: "github" });
  await mock.service.command({ command: "connect", adapter: "github" });
  mock.api.cookies = undefined;
  mock.api.permissions.contains = async () => false;
  assert.equal((await mock.service.command({ command: "status", adapter: "github" })).connection, "connected_schema_unproven");
  assert.deepEqual(await mock.service.command({ command: "disconnect", adapter: "github" }), { ok: true, status: "disconnected" });
  assert.deepEqual(mock.persisted.omuxSourceMetadataV1, []);
});

test("disconnect refuses unrelated and private active tabs rather than guessing a sole source", async () => {
  const mock = browserMock({ selectedAdapter: "codex" });
  await mock.service.command({ command: "connect", adapter: "codex" });
  for (const tab of [{ id: 7, url: "https://github.com", cookieStoreId: "container-4" }, { id: 7, url: "https://chatgpt.com", cookieStoreId: "container-4", incognito: true }]) {
    mock.api.tabs.query = async () => [tab];
    await assert.rejects(mock.service.command({ command: "disconnect", adapter: "codex" }), fails("select_source_context"));
  }
  assert.equal(mock.persisted.omuxSourceMetadataV1.length, 1);
  assert.equal(mock.messages.some(message => message.method === "browser.disconnect"), false);
});

test("incompatible native channel remains an explicit redacted setup diagnostic", () => {
  assert.deepEqual(publicError(new AcquisitionError("incompatible_native_host")), { ok: false, code: "incompatible_native_host" });
});

test("wrong-channel native health prevents source mutation on the same transport", async () => {
  const mock = browserMock({ selectedAdapter: "codex" });
  const healthMessages = [];
  mock.api.runtime.connectNative = () => nativePort({ messages: mock.messages, healthMessages, channel: "development" });
  await assert.rejects(mock.service.command({ command: "connect", adapter: "codex" }), fails("incompatible_native_host"));
  assert.equal(healthMessages.length, 1);
  assert.equal(healthMessages[0].params.provenance.channel, "release");
  assert.deepEqual(mock.messages, []);
  assert.deepEqual(mock.cookieQueries, []);
  assert.equal(mock.persisted.omuxSourceMetadataV1.length, 1);
  assert.equal((await mock.service.command({ command: "status", adapter: "codex" })).connection, "completion_unknown");
});

test("permission revocation retries after a bridge outage on the next worker start", async () => {
  const mock = browserMock({ selectedAdapter: "codex" });
  await mock.service.command({ command: "connect", adapter: "codex" });
  const originalNative = mock.api.runtime.connectNative;
  mock.api.runtime.connectNative = () => { throw new Error(fakeValue); };
  await assert.rejects(mock.service.permissionsRemoved({ origins: ["https://chatgpt.com/*"] }), fails("native_host_unavailable"));
  assert.equal(mock.persisted.omuxSourceMetadataV1.length, 1);
  mock.api.runtime.connectNative = originalNative;
  mock.api.permissions.contains = async () => false;
  await mock.service.reconcilePermissions();
  assert.equal(mock.messages.at(-1).method, "browser.disconnect");
  assert.deepEqual(mock.persisted.omuxSourceMetadataV1, []);
});

test("parallel source operations do not overwrite account source metadata", async () => {
  const mock = browserMock({ selectedAdapter: "codex" });
  let selectedStore = 0;
  mock.api.tabs.query = async () => [{ id: 7, url: "https://chatgpt.com", cookieStoreId: `store-${++selectedStore}`, incognito: false }];
  mock.api.cookies.getAllCookieStores = async () => [{ id: `store-${selectedStore}`, tabIds: [7] }];
  await Promise.all([mock.service.command({ command: "connect", adapter: "codex" }), mock.service.command({ command: "connect", adapter: "codex" })]);
  assert.equal(mock.persisted.omuxSourceMetadataV1.length, 2);
  assert.equal(new Set(mock.persisted.omuxSourceMetadataV1.map(entry => entry.sourceId)).size, 2);
  mock.api.tabs.query = async () => [{ id: 7, url: "https://chatgpt.com", cookieStoreId: "store-2", incognito: false }];
  mock.api.cookies.getAllCookieStores = async () => [{ id: "store-2", tabIds: [7] }];
  await mock.service.command({ command: "disconnect", adapter: "codex" });
  assert.equal(mock.persisted.omuxSourceMetadataV1.length, 1);
  assert.equal(mock.persisted.omuxSourceMetadataV1[0].storeId, "store-1");
  assert.equal(mock.messages.filter(message => message.method === "browser.disconnect").length, 1);
  assert.deepEqual(mock.removedPermissions, []);
});

test("unknown native completion survives restart with redacted state and stable retry source", async () => {
  const mock = browserMock({ selectedAdapter: "codex", nativeFailure: true });
  await assert.rejects(mock.service.command({ command: "connect", adapter: "codex" }), fails("native_host_unavailable"));
  const sourceId = mock.persisted.omuxSourceMetadataV1[0].sourceId;
  assert.equal((await mock.service.command({ command: "status", adapter: "codex" })).connection, "completion_unknown");
  mock.api.runtime.connectNative = () => nativePort({ messages: mock.messages });
  const restarted = new BrowserService({ api: mock.api, browserKind: "firefox", randomId: () => "restart-request", allowFixture: true });
  await restarted.reconcileSources();
  assert.equal(mock.messages.length, 1, "startup never replays uncertain mutations");
  await restarted.command({ command: "connect", adapter: "codex" });
  assert.equal(mock.messages.at(-1).params.sourceId, sourceId);
  assert.equal(mock.messages.at(-1).id, mock.messages[0].id, "explicit retry retains its original request ID");
  assert.equal((await restarted.command({ command: "status", adapter: "codex" })).connection, "connected_schema_unproven");
  assert.equal(JSON.stringify(mock.persisted).includes(fakeValue), false);
  assert.deepEqual(mock.cookieQueries, []);
});

test("revoked permission resolves an unknown connect before disconnect across restart without touching another provider", async () => {
  const mock = browserMock({ selectedAdapter: "codex" });
  const selectedTabs = mock.api.tabs.query;
  mock.api.permissions.contains = async () => true;
  mock.api.tabs.query = async () => [{ id: 7, url: "https://github.com/settings", cookieStoreId: "github-store", incognito: false }];
  mock.api.cookies.getAllCookieStores = async () => [{ id: "github-store", tabIds: [7] }];
  await mock.service.command({ command: "connect", adapter: "github" });
  const independent = structuredClone(mock.persisted.omuxSourceMetadataV1[0]);
  const independentState = mock.persisted.omuxSourceStatesV1[independent.sourceId];
  mock.api.tabs.query = selectedTabs;
  mock.api.cookies.getAllCookieStores = async () => [{ id: "container-4", tabIds: [7] }];
  mock.api.runtime.connectNative = () => nativePort({ messages: mock.messages, nativeFailure: true });
  await assert.rejects(mock.service.command({ command: "connect", adapter: "codex" }), fails("native_host_unavailable"));
  const original = structuredClone(mock.messages.at(-1));
  const pending = structuredClone(mock.persisted.omuxSourceRequestsV1[original.params.sourceId]);
  mock.api.permissions.contains = async value => value.origins[0] === "https://github.com/*";
  mock.api.cookies = undefined;
  mock.api.tabs.query = async () => { throw new Error("revocation must not reopen a provider context"); };
  await assert.rejects(mock.service.permissionsRemoved({ origins: ["https://chatgpt.com/*"] }), fails("native_host_unavailable"));
  assert.deepEqual(mock.messages.at(-1), original);
  assert.deepEqual(mock.persisted.omuxSourceRequestsV1[original.params.sourceId], pending);
  assert.equal(mock.persisted.omuxSourceStatesV1[original.params.sourceId], "pending_disconnect");
  const restartMessages = [];
  mock.api.runtime.connectNative = () => nativePort({ messages: restartMessages });
  let nextId = 0;
  const restarted = new BrowserService({ api: mock.api, browserKind: "firefox", randomId: () => `revoked-restart-${++nextId}`, readStorage: async () => { throw new Error("revocation must not capture grants"); } });
  await restarted.reconcilePermissions();
  assert.deepEqual(restartMessages[0], original);
  assert.equal(restartMessages[1].method, "browser.disconnect");
  assert.deepEqual(restartMessages[1].params, original.params);
  assert.notEqual(restartMessages[1].id, original.id);
  assert.equal(restartMessages.length, 2);
  assert.deepEqual(mock.persisted.omuxSourceMetadataV1, [independent]);
  assert.deepEqual(mock.persisted.omuxSourceStatesV1, { [independent.sourceId]: independentState });
  assert.deepEqual(mock.persisted.omuxSourceRequestsV1, {});
  assert.deepEqual(mock.cookieQueries, []);
  assert.deepEqual(mock.removedPermissions, []);
});

test("selected disconnect resolves only its unknown connect without new read permission", async () => {
  const mock = browserMock({ selectedAdapter: "codex" });
  await mock.service.command({ command: "connect", adapter: "codex" });
  const independent = structuredClone(mock.persisted.omuxSourceMetadataV1[0]);
  const independentState = mock.persisted.omuxSourceStatesV1[independent.sourceId];
  mock.api.tabs.query = async () => [{ id: 7, url: "https://chatgpt.com/settings", cookieStoreId: "second-store", incognito: false }];
  mock.api.cookies.getAllCookieStores = async () => [{ id: "second-store", tabIds: [7] }];
  mock.api.runtime.connectNative = () => nativePort({ messages: mock.messages, nativeFailure: true });
  await assert.rejects(mock.service.command({ command: "connect", adapter: "codex" }), fails("native_host_unavailable"));
  const original = structuredClone(mock.messages.at(-1));
  mock.api.permissions.contains = async () => { throw new Error("disconnect must not request browser read authority"); };
  mock.api.cookies = undefined;
  mock.api.runtime.connectNative = () => nativePort({ messages: mock.messages });
  const before = mock.messages.length;
  assert.deepEqual(await mock.service.command({ command: "disconnect", adapter: "codex" }), { ok: true, status: "disconnected" });
  assert.deepEqual(mock.messages[before], original);
  assert.equal(mock.messages[before + 1].method, "browser.disconnect");
  assert.deepEqual(mock.messages[before + 1].params, original.params);
  assert.notEqual(mock.messages[before + 1].id, original.id);
  assert.equal(mock.messages.length, before + 2);
  assert.deepEqual(mock.persisted.omuxSourceMetadataV1, [independent]);
  assert.deepEqual(mock.persisted.omuxSourceStatesV1, { [independent.sourceId]: independentState });
  assert.deepEqual(mock.persisted.omuxSourceRequestsV1, {});
  assert.deepEqual(mock.removedPermissions, []);
  assert.deepEqual(mock.cookieQueries, []);
});

test("unknown connect resolution refuses malformed or unresolved replies and preserves disconnect intent for restart", async () => {
  const cases = [
    { name: "wrong request", code: "invalid_native_response", mutationReply: message => ({ version: 1, id: `${message.id}-wrong`, result: { accepted: true } }) },
    { name: "missing acceptance", code: "invalid_native_response", mutationReply: message => ({ version: 1, id: message.id, result: {} }) },
    { name: "false acceptance", code: "invalid_native_response", mutationReply: message => ({ version: 1, id: message.id, result: { accepted: false } }) },
    { name: "nonboolean acceptance", code: "invalid_native_response", mutationReply: message => ({ version: 1, id: message.id, result: { accepted: "true" } }) },
    { name: "daemon refusal", code: "daemon_rejected_request", mutationReply: message => ({ version: 1, id: message.id, error: { code: "ServiceBusy", message: fakeValue } }) },
    { name: "unresolved transport", code: "native_host_unavailable", nativeFailure: true },
    { name: "unqualified channel", code: "incompatible_native_host", channel: "development" },
  ];
  for (const scenario of cases) {
    const mock = browserMock({ selectedAdapter: "codex", nativeFailure: true });
    await assert.rejects(mock.service.command({ command: "connect", adapter: "codex" }), fails("native_host_unavailable"));
    const original = structuredClone(mock.messages[0]);
    const metadata = structuredClone(mock.persisted.omuxSourceMetadataV1);
    const requests = structuredClone(mock.persisted.omuxSourceRequestsV1);
    mock.api.cookies = undefined;
    const attempts = [];
    mock.api.runtime.connectNative = () => nativePort({ messages: attempts, ...scenario });
    await assert.rejects(mock.service.permissionsRemoved({ origins: ["https://chatgpt.com/*"] }), fails(scenario.code), scenario.name);
    assert.deepEqual(attempts, scenario.channel ? [] : [original], scenario.name);
    assert.deepEqual(mock.persisted.omuxSourceMetadataV1, metadata, scenario.name);
    assert.deepEqual(mock.persisted.omuxSourceRequestsV1, requests, scenario.name);
    assert.equal(mock.persisted.omuxSourceStatesV1[original.params.sourceId], "pending_disconnect", scenario.name);
    const recovered = [];
    mock.api.runtime.connectNative = () => nativePort({ messages: recovered });
    // Durable disconnect intent suffices even if permission readback is absent.
    mock.api.permissions.contains = async () => { throw new Error("pending disconnect must not depend on read permission"); };
    let nextId = 0;
    const restarted = new BrowserService({ api: mock.api, browserKind: "firefox", randomId: () => `resolution-restart-${++nextId}` });
    await restarted.reconcilePermissions();
    assert.deepEqual(recovered[0], original, scenario.name);
    assert.equal(recovered[1].method, "browser.disconnect", scenario.name);
    assert.notEqual(recovered[1].id, original.id, scenario.name);
    assert.equal(recovered.length, 2, scenario.name);
    assert.deepEqual(mock.persisted.omuxSourceMetadataV1, [], scenario.name);
    assert.deepEqual(mock.persisted.omuxSourceRequestsV1, {}, scenario.name);
    assert.deepEqual(mock.cookieQueries, [], scenario.name);
  }
});

test("lost disconnect after resolved connect retains only the new disconnect identity across restart", async () => {
  const mock = browserMock({ selectedAdapter: "codex", nativeFailure: true });
  await assert.rejects(mock.service.command({ command: "connect", adapter: "codex" }), fails("native_host_unavailable"));
  const original = structuredClone(mock.messages[0]);
  let transports = 0;
  mock.api.runtime.connectNative = () => nativePort({ messages: mock.messages, nativeFailure: ++transports === 2 });
  await assert.rejects(mock.service.permissionsRemoved({ origins: ["https://chatgpt.com/*"] }), fails("native_host_unavailable"));
  assert.deepEqual(mock.messages[1], original);
  const disconnect = structuredClone(mock.messages[2]);
  assert.equal(disconnect.method, "browser.disconnect");
  assert.notEqual(disconnect.id, original.id);
  assert.deepEqual(mock.persisted.omuxSourceRequestsV1[original.params.sourceId], { id: disconnect.id, method: "browser.disconnect" });
  assert.equal(mock.persisted.omuxSourceStatesV1[original.params.sourceId], "pending_disconnect");
  const recovered = [];
  mock.api.runtime.connectNative = () => nativePort({ messages: recovered });
  mock.api.permissions.contains = async () => false;
  const restarted = new BrowserService({ api: mock.api, browserKind: "firefox", randomId: () => "disconnect-restart" });
  await restarted.reconcilePermissions();
  assert.deepEqual(recovered, [disconnect]);
  assert.deepEqual(mock.persisted.omuxSourceMetadataV1, []);
  assert.deepEqual(mock.persisted.omuxSourceRequestsV1, {});
});

test("disconnect never erases malformed pending authority or substitutes another pending mutation", async () => {
  for (const [pending, code] of [
    [{ id: "pending-original", method: "browser.connect", extra: true }, "invalid_source_metadata"],
    [{ id: "pending-original", method: "browser.importGrant" }, "uncertain_operation"],
  ]) {
    const mock = browserMock({ selectedAdapter: "codex", nativeFailure: true });
    await assert.rejects(mock.service.command({ command: "connect", adapter: "codex" }), fails("native_host_unavailable"));
    const sourceId = mock.persisted.omuxSourceMetadataV1[0].sourceId;
    mock.persisted.omuxSourceRequestsV1[sourceId] = structuredClone(pending);
    const before = mock.messages.length;
    mock.api.runtime.connectNative = () => nativePort({ messages: mock.messages });
    await assert.rejects(mock.service.permissionsRemoved({ origins: ["https://chatgpt.com/*"] }), fails(code));
    assert.equal(mock.messages.length, before);
    assert.deepEqual(mock.persisted.omuxSourceRequestsV1[sourceId], pending);
    assert.equal(mock.persisted.omuxSourceStatesV1[sourceId], "pending_disconnect");
    assert.equal(mock.persisted.omuxSourceMetadataV1.length, 1);
  }
});

test("startup unknown-connect resolution and disconnect share the existing eight-mutation budget", async () => {
  const mock = browserMock({ selectedAdapter: "codex" });
  const entries = Array.from({ length: 5 }, (_, index) => ({ adapter: "codex", storeId: `store-${index}`, sourceId: `source-${index}` }));
  mock.persisted.omuxSourceMetadataV1 = structuredClone(entries);
  mock.persisted.omuxSourceStatesV1 = Object.fromEntries(entries.map(entry => [entry.sourceId, "completion_unknown"]));
  mock.persisted.omuxSourceRequestsV1 = Object.fromEntries(entries.map((entry, index) => [entry.sourceId, { id: `original-connect-${index}`, method: "browser.connect" }]));
  mock.api.permissions.contains = async () => false;
  mock.api.cookies = undefined;
  let nextId = 0;
  const restarted = new BrowserService({ api: mock.api, browserKind: "firefox", randomId: () => `budget-resolution-${++nextId}`, monotonicNow: () => 0 });
  await restarted.reconcilePermissions();
  assert.equal(mock.messages.length, 8);
  for (let index = 0; index < 4; index++) {
    assert.equal(mock.messages[index * 2].method, "browser.connect");
    assert.equal(mock.messages[index * 2].id, `original-connect-${index}`);
    assert.equal(mock.messages[index * 2 + 1].method, "browser.disconnect");
    assert.equal(mock.messages[index * 2 + 1].params.sourceId, entries[index].sourceId);
  }
  assert.deepEqual(mock.persisted.omuxSourceMetadataV1, [entries[4]]);
  assert.deepEqual(mock.persisted.omuxSourceRequestsV1, { "source-4": { id: "original-connect-4", method: "browser.connect" } });
  assert.deepEqual(mock.persisted.omuxSourceStatesV1, { "source-4": "completion_unknown" });
  assert.equal(restarted.activeBudget, null);
  await restarted.reconcilePermissions();
  assert.equal(mock.messages.length, 10);
  assert.equal(mock.messages[8].id, "original-connect-4");
  assert.equal(mock.messages[9].method, "browser.disconnect");
  assert.deepEqual(mock.persisted.omuxSourceMetadataV1, []);
  assert.deepEqual(mock.persisted.omuxSourceRequestsV1, {});
  assert.deepEqual(mock.cookieQueries, []);
});

test("startup shares a monotonic aggregate deadline across permission and source reconciliation", async () => {
  const mock = browserMock({ selectedAdapter: "codex" });
  await mock.service.command({ command: "connect", adapter: "codex" });
  const entries = Array.from({ length: 12 }, (_, index) => ({ adapter: "codex", storeId: `store-${index}`, sourceId: `source-${index}` }));
  mock.persisted.omuxSourceMetadataV1 = entries;
  mock.persisted.omuxSourceStatesV1 = Object.fromEntries(entries.map(entry => [entry.sourceId, "connected_schema_unproven"]));
  let clock = 0;
  const timeouts = [];
  let requestIndex = 0;
  mock.api.runtime.connectNative = () => {
    const port = nativePort({ messages: mock.messages });
    const post = port.postMessage;
    port.postMessage = message => { if (message.method !== "browser.health") clock += 4000; post(message); };
    return port;
  };
  const service = new BrowserService({ api: mock.api, browserKind: "firefox", randomId: () => `budget-${++requestIndex}`, monotonicNow: () => clock, nativeOptions: { setTimer(callback, timeout) { timeouts.push(timeout); return 1; }, clearTimer() {} } });
  await service.reconcilePermissions();
  await service.reconcileSources();
  assert.deepEqual(timeouts, [10000, 6000, 2000]);
  assert.equal(mock.messages.length, 4);
  assert.equal(mock.persisted.omuxSourceMetadataV1.length, 12);
  assert.equal(service.activeBudget, null);
});

test("startup caps item count and leaves remaining sources for an explicit subsequent event", async () => {
  const mock = browserMock({ selectedAdapter: "codex" });
  const entries = Array.from({ length: 12 }, (_, index) => ({ adapter: "codex", storeId: `store-${index}`, sourceId: `source-${index}` }));
  mock.persisted.omuxSourceMetadataV1 = entries;
  mock.persisted.omuxSourceStatesV1 = Object.fromEntries(entries.map(entry => [entry.sourceId, "connected_schema_unproven"]));
  let requestIndex = 0;
  const service = new BrowserService({ api: mock.api, browserKind: "firefox", randomId: () => `item-${++requestIndex}`, monotonicNow: () => 0 });
  await service.reconcileSources();
  assert.equal(mock.messages.length, 8);
  assert.equal(mock.messages.every(message => message.method === "browser.reconcile"), true);
  assert.equal(mock.persisted.omuxSourceMetadataV1.length, 12);
  await Promise.resolve();
  assert.equal(mock.messages.length, 8, "there is no automatic continuation loop");
  await service.reconcileSources();
  assert.equal(mock.messages[8].params.sourceId, "source-8", "the next explicit event starts with deferred sources");
});

test("ambiguous disconnected-tab selection cannot disconnect multiple authorized contexts", async () => {
  const mock = browserMock({ selectedAdapter: "codex" });
  await mock.service.command({ command: "connect", adapter: "codex" });
  mock.api.tabs.query = async () => [{ id: 7, url: "https://chatgpt.com", cookieStoreId: "second-store" }];
  mock.api.cookies.getAllCookieStores = async () => [{ id: "second-store", tabIds: [7] }];
  await mock.service.command({ command: "connect", adapter: "codex" });
  mock.api.tabs.query = async () => [];
  await assert.rejects(mock.service.command({ command: "disconnect", adapter: "codex" }), fails("select_source_context"));
  assert.equal(mock.persisted.omuxSourceMetadataV1.length, 2);
  assert.equal(mock.messages.some(message => message.method === "browser.disconnect"), false);
});

test("pending disconnect is retried at startup even when browser permission remains", async () => {
  const mock = browserMock({ selectedAdapter: "codex" });
  await mock.service.command({ command: "connect", adapter: "codex" });
  const original = mock.api.runtime.connectNative;
  mock.api.runtime.connectNative = () => { throw new Error(fakeValue); };
  await assert.rejects(mock.service.command({ command: "disconnect", adapter: "codex" }), fails("native_host_unavailable"));
  assert.equal((await mock.service.command({ command: "status", adapter: "codex" })).connection, "pending_disconnect");
  mock.api.runtime.connectNative = original;
  await mock.service.reconcileSources();
  assert.equal(mock.messages.length, 1);
  await mock.service.reconcilePermissions();
  assert.equal(mock.messages.at(-1).method, "browser.disconnect");
  assert.deepEqual(mock.persisted.omuxSourceMetadataV1, []);
});

test("source context requires consent, correct active origin and matching cookie store", async () => {
  const denied = browserMock({ permission: false });
  await assert.rejects(denied.service.command({ command: "connect", adapter: "fixture" }), fails("provider_permission_required"));
  assert.deepEqual(denied.messages, []);
  const wrongOrigin = browserMock();
  wrongOrigin.api.tabs.query = async () => [{ id: 7, url: "https://other.invalid", cookieStoreId: "container-4" }];
  await assert.rejects(wrongOrigin.service.command({ command: "connect", adapter: "fixture" }), fails("open_provider_tab"));
  const privateWindow = browserMock();
  privateWindow.api.tabs.query = async () => [{ id: 7, url: adapter.origin, cookieStoreId: "container-4", incognito: true }];
  await assert.rejects(privateWindow.service.command({ command: "connect", adapter: "fixture" }), fails("open_provider_tab"));
  const missingStore = browserMock();
  missingStore.api.cookies.getAllCookieStores = async () => [{ id: "container-4", tabIds: [8] }];
  await assert.rejects(missingStore.service.command({ command: "connect", adapter: "fixture" }), fails("cookie_store_unavailable"));
});

test("popup commands cannot provide capsules, arbitrary fetches, or raw native methods", async () => {
  const mock = browserMock();
  for (const command of [{ command: "importGrant", adapter: "fixture" }, { command: "connect", adapter: "fixture", capsule: capsule() }, { command: "connect", adapter: "fixture", url: "https://other.invalid" }]) await assert.rejects(mock.service.command(command), fails("invalid_command"));
  assert.deepEqual(mock.messages, []);
});

test("background source operations accept only this extension's trusted popup sender", async () => {
  const mock = browserMock({ selectedAdapter: "codex" });
  const popupUrl = "moz-extension://test-installation/shared/popup.html";
  mock.api.runtime.getURL = path => `moz-extension://test-installation/${path}`;
  mock.api.runtime.onMessage = event();
  mock.api.permissions.onRemoved = event();
  mock.api.permissions.onAdded = event();
  mock.api.cookies.onChanged = event();
  mock.api.action = { async setBadgeText() {} };
  const previous = Object.getOwnPropertyDescriptor(globalThis, "browser");
  Object.defineProperty(globalThis, "browser", { configurable: true, value: mock.api });
  try {
    await import("./background.mjs?sender-security-test");
    const request = sender => new Promise(resolve => mock.api.runtime.onMessage.emit({ command: "connect", adapter: "codex" }, sender, resolve));
    for (const sender of [{ id: "another-extension", url: popupUrl }, { id: mock.api.runtime.id, url: "https://github.com" }, { id: mock.api.runtime.id, url: popupUrl, tab: { id: 7 } }]) assert.deepEqual(await request(sender), { ok: false, code: "request_failed" });
    assert.deepEqual(mock.messages, []);
    assert.deepEqual(await request({ id: mock.api.runtime.id, url: popupUrl }), { ok: true, status: "connected_schema_unproven" });
    assert.equal(mock.messages.length, 1);
    assert.equal(mock.messages[0].method, "browser.connect");
  } finally {
    if (previous) Object.defineProperty(globalThis, "browser", previous);
    else delete globalThis.browser;
  }
});

test("generated manifests grant no blanket sites, page scripts, browser debugging, or fixture origin", async () => {
  const origins = Object.values(ADAPTERS).map(hostPermission);
  for (const kind of ["chromium", "firefox"]) {
    const manifest = JSON.parse(await readFile(new URL(`../${kind}/manifest.json`, import.meta.url), "utf8"));
    assert.equal(manifest.manifest_version, 3);
    assert.deepEqual(manifest.optional_host_permissions, origins);
    assert.deepEqual(manifest.optional_permissions, ["cookies"]);
    assert.equal(manifest.permissions.includes("cookies"), false);
    assert.equal(Object.hasOwn(manifest, "host_permissions"), false);
    assert.equal(Object.hasOwn(manifest, "content_scripts"), false);
    assert.equal(Object.hasOwn(manifest, "externally_connectable"), false);
    assert.equal(manifest.permissions.includes("debugger"), false);
    assert.equal(manifest.permissions.includes("scripting"), false);
    assert.equal(manifest.permissions.includes("webRequest"), false);
    assert.equal(manifest.background.type, "module");
    assert.equal(manifest.action.default_popup, "shared/popup.html");
    assert.equal(JSON.stringify(manifest).includes("fixture.invalid"), false);
    assert.match(manifest.content_security_policy.extension_pages, /connect-src 'none'/);
  }
});

test("Bazel extension archives contain complete root manifests and local module dependencies", async () => {
  for (const kind of ["chromium", "firefox"]) {
    const argument = process.argv.find(value => value.startsWith(`--${kind}Archive=`));
    assert.ok(argument, "Bazel must supply the packaged browser artifact");
    const bytes = await readFile(argument.slice(argument.indexOf("=") + 1));
    const entries = new Map();
    let offset = 0;
    while (bytes.readUInt32LE(offset) === 0x04034b50) {
      const flags = bytes.readUInt16LE(offset + 6);
      assert.equal(flags & 8, 0, "archive entries must have known sizes");
      const method = bytes.readUInt16LE(offset + 8);
      const size = bytes.readUInt32LE(offset + 18);
      const nameLength = bytes.readUInt16LE(offset + 26);
      const extraLength = bytes.readUInt16LE(offset + 28);
      const name = bytes.subarray(offset + 30, offset + 30 + nameLength).toString("utf8");
      assert.equal(name.startsWith("/"), false);
      assert.equal(name.split("/").includes(".."), false);
      assert.equal(entries.has(name), false);
      const start = offset + 30 + nameLength + extraLength;
      const compressed = bytes.subarray(start, start + size);
      assert.ok(method === 0 || method === 8);
      entries.set(name, method === 8 ? inflateRawSync(compressed) : compressed);
      offset = start + size;
    }
    assert.equal(bytes.readUInt32LE(offset), 0x02014b50, "archive must contain a central directory");
    const manifest = JSON.parse(entries.get("manifest.json").toString("utf8"));
    for (const resource of [manifest.action.default_popup, manifest.background.service_worker, ...(manifest.background.scripts ?? [])].filter(Boolean)) assert.ok(entries.has(resource), `missing extension resource ${resource}`);
    for (const name of ["shared/service.mjs", "shared/protocol.mjs", "shared/adapters.mjs", "shared/acquisition.mjs", "shared/native.mjs", "shared/popup.mjs", "shared/popup.css"]) assert.ok(entries.has(name));
    assert.equal([...entries.keys()].some(name => name.endsWith(".test.mjs")), false);
    assert.equal(entries.has(`${kind}/manifest.json`), false);
  }
});
