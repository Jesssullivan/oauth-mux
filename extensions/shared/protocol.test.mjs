import test from "node:test";
import assert from "node:assert/strict";
import { AcquisitionError, makeEnvelope, makeHealthEnvelope, validateEnvelope, validateHealthResponse, validateConnectOutcome } from "./protocol.mjs";
import { getAdapter } from "./adapters.mjs";
import { sendNativeRequest } from "./native.mjs";

const provenance = { browser: "chromium", extensionId: "a".repeat(32), channel: "release" };
const failCode = code => error => error instanceof AcquisitionError && error.code === code;
const response = (result = {}) => ({ version: 1, id: "health-1", result: { status: "ready", custody_available: true, provider_access: false, protocolVersion: 1, channel: "release", capabilities: { source_connection: true, production_export: false }, ...result } });

test("provider-free health uses strict provenance and never accepts source fields", () => {
  const envelope = makeHealthEnvelope("health-1", provenance);
  assert.equal(envelope.method, "browser.health");
  assert.deepEqual(Object.keys(envelope.params), ["provenance"]);
  assert.throws(() => validateEnvelope({ ...envelope, params: { ...envelope.params, sourceId: "source-1" } }), failCode("invalid_fields"));
  assert.throws(() => makeHealthEnvelope("health-1", { ...provenance, browser: "unknown" }), failCode("invalid_provenance"));
  assert.throws(() => makeHealthEnvelope("health-1", { ...provenance, extensionId: "x".repeat(129) }), failCode("invalid_provenance"));
  assert.throws(() => validateEnvelope({ ...envelope, params: { provenance: { browser: provenance.browser, extensionId: provenance.extensionId } } }), failCode("invalid_fields"));
  assert.throws(() => validateEnvelope({ ...envelope, params: { provenance: { ...provenance, channel: "unknown" } } }), failCode("invalid_provenance"));
  assert.throws(() => validateEnvelope({ ...envelope, params: { provenance: { ...provenance, channel: "development" } } }), failCode("incompatible_native_host"));
  assert.throws(() => makeHealthEnvelope("health-1", { ...provenance, channel: "development" }), failCode("incompatible_native_host"));
});

test("health result is a bounded capability projection with exact protocol and channel", () => {
  assert.deepEqual(validateHealthResponse(response(), "health-1").capabilities, { source_connection: true, production_export: false });
  assert.equal(validateHealthResponse(response({ status: "repair_required", custody_available: false }), "health-1").custody_available, false);
  assert.throws(() => validateHealthResponse(response({ channel: "development" }), "health-1"), failCode("incompatible_native_host"));
  assert.throws(() => validateHealthResponse(response({ protocolVersion: 2 }), "health-1"), failCode("incompatible_native_host"));
  assert.throws(() => validateHealthResponse(response({ capabilities: ["browser.connect"] }), "health-1"), failCode("invalid_fields"));
  assert.throws(() => validateHealthResponse(response({ capabilities: { source_connection: true, production_export: true } }), "health-1"), failCode("invalid_native_response"));
  assert.throws(() => validateHealthResponse(response({ provider_access: true }), "health-1"), failCode("invalid_native_response"));
  assert.throws(() => validateHealthResponse(response({ status: "repair_required", custody_available: true }), "health-1"), failCode("invalid_native_response"));
  assert.throws(() => validateHealthResponse(response({ privatePayload: "synthetic-private-data" }), "health-1"), failCode("invalid_fields"));
  assert.throws(() => validateHealthResponse({ version: 1, id: "health-1", error: { code: "internal", message: "synthetic-private-data" } }, "health-1"), failCode("daemon_rejected_request"));
});

test("source mutations require principal provenance before transport", () => {
  for (const method of ["browser.reconcile", "browser.disconnect"]) {
    const envelope = { version: 1, id: "mutation-1", method, params: { sourceId: "source-1", adapter: "fixture", origin: "https://fixture.invalid" } };
    assert.throws(() => validateEnvelope(envelope, { allowFixture: true }), failCode("invalid_fields"));
    assert.equal(validateEnvelope({ ...envelope, params: { ...envelope.params, provenance } }, { allowFixture: true }).method, method);
    assert.throws(() => validateEnvelope({ ...envelope, params: { ...envelope.params, provenance: { ...provenance, channel: "development" } } }, { allowFixture: true }), failCode("incompatible_native_host"));
  }
});

test("envelope makers derive channel intent from the packaged configuration", () => {
  const principal = { browser: provenance.browser, extensionId: provenance.extensionId };
  assert.equal(makeHealthEnvelope("health-1", principal).params.provenance.channel, "release");
  const adapter = getAdapter("fixture", { allowFixture: true });
  const args = { requestId: "mutation-1", sourceId: "source-1", adapter, method: "browser.reconcile", extra: { provenance: principal } };
  assert.equal(makeEnvelope(args, { allowFixture: true }).params.provenance.channel, "release");
  assert.throws(() => makeEnvelope({ ...args, extra: { provenance: { ...principal, channel: "development" } } }, { allowFixture: true }), failCode("incompatible_native_host"));
});

test("Connect outcome wire has separate operation intent and exact u64 authority bounds", () => {
  const adapter = getAdapter("codex");
  const query = makeEnvelope({ requestId: "correlation", sourceId: "source", adapter, method: "browser.connectOutcome", extra: { operationId: "operation", expectedRevision: "18446744073709551615", provenance } });
  assert.notEqual(query.id, query.params.operationId);
  assert.equal(query.params.expectedRevision, "18446744073709551615");
  for (const value of [1, "01", "-1", "18446744073709551616", "1.0", ""]) assert.throws(() => validateEnvelope({ ...query, params: { ...query.params, expectedRevision: value } }));
  for (const extra of [{ capsule: {} }, { expectedGeneration: "1" }, { identity: "inferred" }]) assert.throws(() => validateEnvelope({ ...query, params: { ...query.params, ...extra } }), failCode("invalid_fields"));
  assert.throws(() => validateEnvelope({ ...query, params: { ...query.params, provenance: { ...provenance, channel: "development" } } }), failCode("incompatible_native_host"));
  const connect = { ...query, method: "browser.connect" };
  assert.throws(() => validateEnvelope({ ...connect, params: { sourceId: "source", adapter: "codex", origin: adapter.origin, provenance, operationId: "operation" } }), failCode("invalid_fields"));
  const remove = { ...query, method: "browser.disconnect" };
  assert.throws(() => validateEnvelope(remove), failCode("invalid_fields"));
  assert.equal(validateEnvelope({ ...remove, params: { ...remove.params, expectedGeneration: "1" } }).params.expectedGeneration, "1");
  assert.throws(() => validateEnvelope({ ...remove, params: { ...remove.params, expectedGeneration: "0" } }));
});

test("Connect outcome rejects wrong operation, context and malformed authority while retaining disabled export", () => {
  const result = { outcome: "committed", source_id: "source", operation_id: "operation", connect_generation: "1", connect_revision: "2", current_generation: "1", current_revision: "3", source_status: "connected", authorized: true };
  const outcome = value => ({ version: 1, id: "query", result: { ...result, ...value } });
  assert.equal(validateConnectOutcome(outcome({}), "query", "source", "operation").authorized, true);
  for (const value of [{ source_id: "other" }, { operation_id: "other" }, { connect_revision: "4" }, { current_generation: 1 }, { source_status: "disconnected" }, { outcome: "unknown" }, { capsule: {} }, { current_revision: "03" }]) assert.throws(() => validateConnectOutcome(outcome(value), "query", "source", "operation"));
  assert.equal(validateConnectOutcome(outcome({ outcome: "unknown", connect_generation: null, connect_revision: null }), "query", "source", "operation").outcome, "unknown");
  const health = validateHealthResponse(response({ capabilities: { source_connection: true, production_export: false, connect_recovery: true } }), "health-1");
  assert.equal(health.capabilities.connect_recovery, true);
  assert.equal(health.capabilities.production_export, false);
  assert.equal(validateHealthResponse(response(), "health-1").capabilities.connect_recovery, undefined);
  assert.throws(() => validateHealthResponse(response({ capabilities: { source_connection: true, production_export: false, connect_recovery: "true" } }), "health-1"));
});

test("invalid transport deadline refuses without opening a native port", async () => {
  let opened = false;
  const api = { runtime: { connectNative() { opened = true; } } };
  await assert.rejects(sendNativeRequest(api, makeHealthEnvelope("health-1", provenance), { timeoutMs: Infinity }), failCode("invalid_native_timeout"));
  assert.equal(opened, false);
});

function portFixture(healthResult) {
  const sent = [];
  const event = () => {
    const listeners = new Set();
    return { addListener: listener => listeners.add(listener), removeListener: listener => listeners.delete(listener), emit: value => { for (const listener of [...listeners]) listener(value); } };
  };
  const port = { onMessage: event(), onDisconnect: event(), disconnected: false,
    postMessage(envelope) {
      sent.push(envelope);
      queueMicrotask(() => port.onMessage.emit(envelope.method === "browser.health"
        ? { ...healthResult, id: envelope.id }
        : { version: 1, id: envelope.id, result: { accepted: true } }));
    }, disconnect() { this.disconnected = true; } };
  let opened = 0;
  return { sent, port, api: { runtime: { connectNative() { opened++; return port; } } }, opened: () => opened };
}

test("same-port health fences wrong channel and invalid response before posting mutation", async () => {
  const mutation = { version: 1, id: "mutation-1", method: "browser.disconnect", params: { sourceId: "source-1", adapter: "fixture", origin: "https://fixture.invalid", provenance } };
  for (const [health, code] of [[response({ channel: "development" }), "incompatible_native_host"], [response({ provider_access: true }), "invalid_native_response"], [response({ capabilities: [] }), "invalid_fields"]]) {
    const fixture = portFixture(health);
    await assert.rejects(sendNativeRequest(fixture.api, mutation, { healthEnvelope: makeHealthEnvelope("health-1", provenance) }), failCode(code));
    assert.equal(fixture.opened(), 1);
    assert.deepEqual(fixture.sent.map(envelope => envelope.method), ["browser.health"]);
    assert.equal(fixture.port.disconnected, true);
  }
});

test("valid health posts the original stable mutation ID on its existing port", async () => {
  const mutation = { version: 1, id: "mutation-stable", method: "browser.disconnect", params: { sourceId: "source-1", adapter: "fixture", origin: "https://fixture.invalid", provenance } };
  const fixture = portFixture(response());
  const result = await sendNativeRequest(fixture.api, mutation, { healthEnvelope: makeHealthEnvelope("health-1", provenance) });
  assert.equal(fixture.opened(), 1);
  assert.deepEqual(fixture.sent.map(envelope => envelope.method), ["browser.health", "browser.disconnect"]);
  assert.equal(fixture.sent[1], mutation);
  assert.equal(result.id, "mutation-stable");
  assert.equal(fixture.port.disconnected, true);
});
