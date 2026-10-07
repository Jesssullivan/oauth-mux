import { getAdapter } from "./adapters.mjs";
import { CHANNEL, NATIVE_HOST } from "./channel.mjs";

export const PROTOCOL_VERSION = 1;
export { NATIVE_HOST };
export const MAX_MESSAGE_BYTES = 262144;
export const MAX_SECRET_BYTES = 8192;
export const MAX_CAPSULE_BYTES = 131072;
export const SOURCE_METHODS = Object.freeze(["browser.connect", "browser.importGrant", "browser.observation", "browser.reconcile", "browser.disconnect"]);
const METHODS = new Set([...SOURCE_METHODS, "browser.health"]);
const TEXT_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const SAME_SITES = new Set(["no_restriction", "lax", "strict", "unspecified"]);
const UNITS = new Set(["calls", "bytes", "seconds", "count", "bytes_per_second"]);

export class AcquisitionError extends Error {
  constructor(code) { super(code); this.name = "AcquisitionError"; this.code = code; }
}

function fail(code) { throw new AcquisitionError(code); }
function record(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function fields(value, allowed, required = []) {
  if (!record(value) || Object.keys(value).some(key => !allowed.includes(key)) || required.some(key => !Object.hasOwn(value, key))) fail("invalid_fields");
}
function string(value, max = 4096) { if (typeof value !== "string" || value.length > max || value.includes("\0")) fail("invalid_string"); }
function secret(value) { string(value, MAX_SECRET_BYTES); if (new TextEncoder().encode(value).length > MAX_SECRET_BYTES) fail("invalid_string"); }
function id(value, max = 128) { if (typeof value !== "string" || value.length > max || !TEXT_ID.test(value)) fail("invalid_id"); }
function seconds(value) { if (!Number.isSafeInteger(value) || value < 0) fail("invalid_time"); }
function number(value) { if (typeof value !== "number" || !Number.isFinite(value) || value < 0) fail("invalid_number"); }
function optional(value, key, check) { if (Object.hasOwn(value, key)) check(value[key]); }
function boolean(value) { if (typeof value !== "boolean") fail("invalid_boolean"); }

function validateProvenance(provenance) {
  fields(provenance, ["browser", "extensionId", "channel"], ["browser", "extensionId", "channel"]);
  if (!["chromium", "firefox"].includes(provenance.browser)) fail("invalid_provenance");
  if (typeof provenance.extensionId !== "string" || !/^[A-Za-z0-9._@{}:-]{1,128}$/.test(provenance.extensionId)) fail("invalid_provenance");
  if (!["release", "development"].includes(provenance.channel)) fail("invalid_provenance");
  if (provenance.channel !== CHANNEL) fail("incompatible_native_host");
}

export function exactOrigin(origin) {
  string(origin, 256);
  let parsed;
  try { parsed = new URL(origin); } catch { fail("invalid_origin"); }
  if (parsed.protocol !== "https:" || parsed.origin !== origin) fail("invalid_origin");
  return origin;
}

function validateCookie(cookie, adapter) {
  fields(cookie, ["name", "value", "domain", "path", "secure", "httpOnly", "hostOnly", "session", "sameSite", "storeId", "expirationDate", "partitionKey", "firstPartyDomain"],
    ["name", "value", "domain", "path", "secure", "httpOnly", "hostOnly", "session", "sameSite", "storeId"]);
  for (const key of ["name", "domain", "path", "storeId"]) string(cookie[key]);
  secret(cookie.value);
  if (!/^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]+$/.test(cookie.value)) fail("invalid_cookie_value");
  for (const key of ["secure", "httpOnly", "hostOnly", "session"]) boolean(cookie[key]);
  if (!SAME_SITES.has(cookie.sameSite) || !cookie.secure || !cookie.storeId) fail("invalid_cookie");
  if (!adapter.cookies.some(rule => rule.name === cookie.name && rule.domain === cookie.domain && rule.path === cookie.path)) fail("undeclared_cookie");
  optional(cookie, "expirationDate", number);
  if (cookie.session === Object.hasOwn(cookie, "expirationDate")) fail("invalid_cookie_expiry");
  optional(cookie, "firstPartyDomain", value => {
    string(value, 256);
    if (value !== "" && value !== new URL(adapter.origin).hostname) fail("wrong_cookie_partition");
  });
  if (Object.hasOwn(cookie, "partitionKey")) {
    fields(cookie.partitionKey, ["topLevelSite", "hasCrossSiteAncestor"], ["topLevelSite"]);
    if (exactOrigin(cookie.partitionKey.topLevelSite) !== adapter.origin) fail("wrong_cookie_partition");
    optional(cookie.partitionKey, "hasCrossSiteAncestor", boolean);
  }
}

export function validateCapsule(capsule, adapter) {
  fields(capsule, ["kind", "purpose", "renewalAuthority", "browserBound", "capturedAt", "expiresAt", "cookies", "storage"],
    ["kind", "purpose", "renewalAuthority", "browserBound", "capturedAt", "cookies", "storage"]);
  if (adapter.grantExport !== "enabled") fail("grant_export_unproven");
  if (capsule.kind !== "browser_session" || capsule.purpose !== "identity_observation" || capsule.renewalAuthority !== "external") fail("invalid_grant_authority");
  boolean(capsule.browserBound);
  if (capsule.browserBound !== adapter.browserBound) fail("invalid_grant_authority");
  seconds(capsule.capturedAt);
  optional(capsule, "expiresAt", seconds);
  if (Object.hasOwn(capsule, "expiresAt") && capsule.expiresAt <= capsule.capturedAt) fail("expired_grant");
  if (!Array.isArray(capsule.cookies) || !Array.isArray(capsule.storage) || capsule.cookies.length > 32 || capsule.storage.length > 16) fail("invalid_capsule");
  if (capsule.cookies.length + capsule.storage.length === 0) fail("empty_grant");
  const cookieKeys = new Set();
  const storeIds = new Set();
  const partitionKeys = new Set();
  for (const cookie of capsule.cookies) {
    validateCookie(cookie, adapter);
    if (cookie.expirationDate <= capsule.capturedAt) fail("expired_grant");
    if (Object.hasOwn(cookie, "expirationDate") && (!Object.hasOwn(capsule, "expiresAt") || capsule.expiresAt > Math.floor(cookie.expirationDate))) fail("invalid_grant_expiry");
    storeIds.add(cookie.storeId);
    partitionKeys.add(JSON.stringify([cookie.partitionKey?.topLevelSite ?? null, cookie.partitionKey?.hasCrossSiteAncestor ?? null, cookie.firstPartyDomain ?? null]));
    const key = JSON.stringify([cookie.name, cookie.domain, cookie.path, cookie.storeId, cookie.partitionKey?.topLevelSite ?? null, cookie.partitionKey?.hasCrossSiteAncestor ?? null, cookie.firstPartyDomain ?? null]);
    if (cookieKeys.has(key)) fail("duplicate_cookie");
    cookieKeys.add(key);
  }
  if (storeIds.size > 1) fail("mixed_cookie_stores");
  if (partitionKeys.size > 1) fail("mixed_cookie_partitions");
  const storageKeys = new Set();
  for (const entry of capsule.storage) {
    fields(entry, ["origin", "key", "value"], ["origin", "key", "value"]);
    if (entry.origin !== adapter.origin || !adapter.storageKeys.includes(entry.key)) fail("undeclared_storage");
    secret(entry.value);
    if (storageKeys.has(entry.key)) fail("duplicate_storage");
    storageKeys.add(entry.key);
  }
  if (new TextEncoder().encode(JSON.stringify(capsule)).length > MAX_CAPSULE_BYTES) fail("capsule_too_large");
  return capsule;
}

export function validateEnvelope(envelope, { allowFixture = false } = {}) {
  fields(envelope, ["version", "id", "method", "params"], ["version", "id", "method", "params"]);
  if (envelope.version !== PROTOCOL_VERSION || !METHODS.has(envelope.method)) fail("unsupported_protocol");
  id(envelope.id, 64);
  if (envelope.method === "browser.health") {
    fields(envelope.params, ["provenance"], ["provenance"]);
    validateProvenance(envelope.params.provenance);
    if (new TextEncoder().encode(JSON.stringify(envelope)).length > MAX_MESSAGE_BYTES) fail("message_too_large");
    return envelope;
  }
  const extra = envelope.method === "browser.importGrant" ? ["capsule"] : envelope.method === "browser.observation" ? ["observation"] : [];
  fields(envelope.params, ["sourceId", "adapter", "origin", "provenance", ...extra], ["sourceId", "adapter", "origin", "provenance", ...extra]);
  id(envelope.params.sourceId);
  let adapter;
  try { adapter = getAdapter(envelope.params.adapter, { allowFixture }); } catch { fail("unsupported_adapter"); }
  if (exactOrigin(envelope.params.origin) !== adapter.origin) fail("wrong_adapter_origin");
  // Every mutation carries the browser principal bound to its source context.
  // It authenticates a source, never a provider identity.
  validateProvenance(envelope.params.provenance);
  if (envelope.method === "browser.importGrant") validateCapsule(envelope.params.capsule, adapter);
  if (envelope.method === "browser.observation") {
    const observation = envelope.params.observation;
    fields(observation, ["resource", "unit", "value", "limit", "observedAt", "expiresAt"], ["resource", "unit", "value", "observedAt"]);
    id(observation.resource);
    if (!UNITS.has(observation.unit)) fail("invalid_unit");
    number(observation.value);
    seconds(observation.observedAt);
    optional(observation, "limit", number);
    optional(observation, "expiresAt", seconds);
    if (observation.limit < observation.value || observation.expiresAt <= observation.observedAt) fail("invalid_observation");
  }
  if (new TextEncoder().encode(JSON.stringify(envelope)).length > MAX_MESSAGE_BYTES) fail("message_too_large");
  return envelope;
}

export function makeEnvelope({ requestId, sourceId, adapter, method, extra = {} }, options) {
  return validateEnvelope({ version: PROTOCOL_VERSION, id: requestId, method, params: { sourceId, adapter: adapter.id, origin: adapter.origin, ...extra, provenance: { channel: CHANNEL, ...extra.provenance } } }, options);
}

export function validateResponse(response, requestId) {
  if (new TextEncoder().encode(JSON.stringify(response)).length > MAX_MESSAGE_BYTES) fail("invalid_native_response");
  if (!record(response) || response.version !== PROTOCOL_VERSION || response.id !== requestId) fail("invalid_native_response");
  if (Object.hasOwn(response, "error")) {
    fields(response, ["version", "id", "error"], ["version", "id", "error"]);
    fields(response.error, ["code", "message"], ["code", "message"]);
    // Do not copy native error messages into UI/logs: they may contain provider data.
    fail("daemon_rejected_request");
  }
  fields(response, ["version", "id", "result"], ["version", "id", "result"]);
  // Native results are deliberately not returned to extension UI or persisted.
  return true;
}

export function makeHealthEnvelope(requestId, provenance) {
  return validateEnvelope({ version: PROTOCOL_VERSION, id: requestId, method: "browser.health", params: { provenance: { channel: CHANNEL, ...provenance } } });
}

export function validateHealthResponse(response, requestId, expectedChannel = CHANNEL) {
  // Browser health schema v1 is exactly the daemon's six-field, provider-free
  // readiness result. Source connection is a bridge capability; disabled export
  // and provider access cannot establish usable grants or native continuity.
  validateResponse(response, requestId);
  const result = response.result;
  fields(result, ["status", "custody_available", "provider_access", "protocolVersion", "channel", "capabilities"], ["status", "custody_available", "provider_access", "protocolVersion", "channel", "capabilities"]);
  if (result.protocolVersion !== PROTOCOL_VERSION || result.channel !== expectedChannel) fail("incompatible_native_host");
  fields(result.capabilities, ["source_connection", "production_export"], ["source_connection", "production_export"]);
  if (!["ready", "repair_required"].includes(result.status) || typeof result.custody_available !== "boolean" || result.custody_available !== (result.status === "ready") || result.provider_access !== false || result.capabilities.source_connection !== true || result.capabilities.production_export !== false) fail("invalid_native_response");
  return { status: result.status, custody_available: result.custody_available, provider_access: false, protocolVersion: result.protocolVersion, channel: result.channel, capabilities: { source_connection: true, production_export: false } };
}
