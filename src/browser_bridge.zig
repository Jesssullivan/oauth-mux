//! Restricted WebExtension/native-messaging boundary. Browser provenance is
//! never an account identity, and imported browser grants retain external
//! renewal ownership. Production exports remain disabled until adapter proof.
const std = @import("std");
const builtin = @import("builtin");

pub const max_message_bytes = 256 * 1024;
pub const max_cookies = 32;
pub const max_storage_entries = 16;
pub const max_secret_bytes = 8 * 1024;
pub const max_capsule_bytes = 128 * 1024;
pub const max_json_depth = 32;

pub const Method = enum { health, connect, import_grant, observation, reconcile, disconnect };
pub const Channel = enum { release, development };
pub const Provenance = struct {
    browser: []const u8,
    extension_id: []const u8,
    channel: Channel,

    pub fn eql(a: Provenance, b: Provenance) bool {
        return a.channel == b.channel and std.mem.eql(u8, a.browser, b.browser) and std.mem.eql(u8, a.extension_id, b.extension_id);
    }
};
pub const Adapter = enum { codex, claude, github, fixture };
pub const ExportCapability = enum { needs_provider_adapter_proof, fixture_only };
pub const Policy = struct {
    adapter: Adapter,
    origin: []const u8,
    identity_endpoint: []const u8,
    export_capability: ExportCapability,
};

/// Fixed endpoints are a declaration, never caller-supplied fetch authority.
/// Private identity/session schemas are deliberately not claimed as proved.
pub fn policy(adapter: Adapter) Policy {
    return switch (adapter) {
        .codex => .{ .adapter = adapter, .origin = "https://chatgpt.com", .identity_endpoint = "", .export_capability = .needs_provider_adapter_proof },
        .claude => .{ .adapter = adapter, .origin = "https://claude.ai", .identity_endpoint = "", .export_capability = .needs_provider_adapter_proof },
        .github => .{ .adapter = adapter, .origin = "https://github.com", .identity_endpoint = "https://api.github.com/user", .export_capability = .needs_provider_adapter_proof },
        .fixture => .{ .adapter = adapter, .origin = "https://fixture.invalid", .identity_endpoint = "https://fixture.invalid/account", .export_capability = .fixture_only },
    };
}

pub const Validated = struct {
    id: []const u8,
    method: Method,
    adapter: Adapter = .fixture,
    source_id: []const u8 = "",
    origin: []const u8 = "",
    provenance: Provenance,
    capsule: ?std.json.Value = null,
    observation: ?std.json.Value = null,
    browser_bound: bool = false,
    expires_at: ?i64 = null,
    cookie_count: usize = 0,
    storage_count: usize = 0,
};

pub const Error = error{
    InvalidRequest,
    InvalidVersion,
    InvalidChannel,
    BrowserChannelMismatch,
    InvalidIdentifier,
    UnsupportedMethod,
    UnknownAdapter,
    OriginMismatch,
    FixtureDisabled,
    NeedsProviderAdapterProof,
    InvalidCapsule,
    InvalidCookieScope,
    InvalidStorageScope,
    InvalidObservation,
    Expired,
    MessageTooLarge,
    IncompleteFrame,
    TrailingFrame,
};

fn fields(value: std.json.Value, required: []const []const u8, optional: []const []const u8) Error!void {
    if (value != .object) return error.InvalidRequest;
    for (required) |key| if (!value.object.contains(key)) return error.InvalidRequest;
    var it = value.object.iterator();
    while (it.next()) |entry| {
        var found = false;
        for (required) |key| if (std.mem.eql(u8, key, entry.key_ptr.*)) {
            found = true;
            break;
        };
        if (!found) for (optional) |key| if (std.mem.eql(u8, key, entry.key_ptr.*)) {
            found = true;
            break;
        };
        if (!found) return error.InvalidRequest;
    }
}

fn member(value: std.json.Value, key: []const u8) Error!std.json.Value {
    if (value != .object) return error.InvalidRequest;
    return value.object.get(key) orelse error.InvalidRequest;
}

fn string(value: std.json.Value) Error![]const u8 {
    if (value != .string) return error.InvalidRequest;
    return value.string;
}

fn boolean(value: std.json.Value) Error!bool {
    if (value != .bool) return error.InvalidRequest;
    return value.bool;
}

fn integer(value: std.json.Value) Error!i64 {
    if (value != .integer) return error.InvalidRequest;
    return value.integer;
}

fn identifier(value: std.json.Value, max_len: usize) Error![]const u8 {
    const s = try string(value);
    if (s.len == 0 or s.len > max_len) return error.InvalidIdentifier;
    for (s) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '-' and c != ':' and c != '.') return error.InvalidIdentifier;
    return s;
}

fn parseMethod(s: []const u8) Error!Method {
    const names = [_][]const u8{ "browser.health", "browser.connect", "browser.importGrant", "browser.observation", "browser.reconcile", "browser.disconnect" };
    const methods = [_]Method{ .health, .connect, .import_grant, .observation, .reconcile, .disconnect };
    for (names, methods) |name, method| if (std.mem.eql(u8, s, name)) return method;
    return error.UnsupportedMethod;
}

/// Claims are syntax checked, not authenticated browser/profile identity.
/// Same-user transport trust never upgrades them into verified identity.
fn validateProvenance(value: std.json.Value) Error!Provenance {
    try fields(value, &.{ "browser", "extensionId", "channel" }, &.{});
    const browser = try string(try member(value, "browser"));
    if (!std.mem.eql(u8, browser, "chromium") and !std.mem.eql(u8, browser, "firefox")) return error.InvalidRequest;
    const extension_id = try string(try member(value, "extensionId"));
    if (extension_id.len == 0 or extension_id.len > 128) return error.InvalidIdentifier;
    for (extension_id) |c| if (!std.ascii.isAlphanumeric(c) and std.mem.indexOfScalar(u8, "._@{}:-", c) == null) return error.InvalidIdentifier;
    const channel = std.meta.stringToEnum(Channel, try string(try member(value, "channel"))) orelse return error.InvalidChannel;
    return .{ .browser = browser, .extension_id = extension_id, .channel = channel };
}

fn parseAdapter(s: []const u8) Error!Adapter {
    return std.meta.stringToEnum(Adapter, s) orelse error.UnknownAdapter;
}

fn timestamp(value: std.json.Value) Error!i64 {
    const result = try integer(value);
    if (result < 0) return error.InvalidRequest;
    return result;
}

fn finiteNumber(value: std.json.Value) Error!f64 {
    const n: f64 = switch (value) {
        .integer => @floatFromInt(value.integer),
        .float => value.float,
        else => return error.InvalidRequest,
    };
    if (!std.math.isFinite(n) or n < 0) return error.InvalidRequest;
    return n;
}

fn verifyCookie(cookie: std.json.Value, origin: []const u8, now_unix: i64) Error!void {
    try fields(cookie, &.{ "name", "value", "domain", "path", "secure", "httpOnly", "hostOnly", "session", "sameSite", "storeId" }, &.{ "expirationDate", "partitionKey", "firstPartyDomain" });
    if (!std.mem.eql(u8, try string(try member(cookie, "name")), "omux_fixture_session")) return error.InvalidCookieScope;
    const secret = try string(try member(cookie, "value"));
    if (secret.len == 0 or secret.len > max_secret_bytes) return error.InvalidCapsule;
    for (secret) |c| if (c < 0x21 or c == ';' or c == ',' or c == '\\' or c == '"' or c > 0x7e) return error.InvalidCapsule;
    const domain = try string(try member(cookie, "domain"));
    const host_only = try boolean(try member(cookie, "hostOnly"));
    if (!std.mem.eql(u8, domain, "fixture.invalid") and !(std.mem.eql(u8, domain, ".fixture.invalid") and !host_only)) return error.InvalidCookieScope;
    if (!std.mem.eql(u8, try string(try member(cookie, "path")), "/")) return error.InvalidCookieScope;
    if (!try boolean(try member(cookie, "secure"))) return error.InvalidCookieScope;
    _ = try boolean(try member(cookie, "httpOnly"));
    const session = try boolean(try member(cookie, "session"));
    _ = try identifier(try member(cookie, "storeId"), 128);
    const same_site = try string(try member(cookie, "sameSite"));
    var valid_same_site = false;
    for ([_][]const u8{ "no_restriction", "lax", "strict", "unspecified" }) |name| if (std.mem.eql(u8, name, same_site)) {
        valid_same_site = true;
        break;
    };
    if (!valid_same_site) return error.InvalidCookieScope;
    if (cookie.object.get("expirationDate")) |v| {
        if (session) return error.InvalidCookieScope;
        const expiry = try finiteNumber(v);
        if (expiry <= @as(f64, @floatFromInt(now_unix))) return error.Expired;
    } else if (!session) return error.InvalidCookieScope;
    if (cookie.object.get("partitionKey")) |partition| {
        try fields(partition, &.{"topLevelSite"}, &.{"hasCrossSiteAncestor"});
        if (!std.mem.eql(u8, try string(try member(partition, "topLevelSite")), origin)) return error.InvalidCookieScope;
        if (partition.object.get("hasCrossSiteAncestor")) |v| _ = try boolean(v);
    }
    if (cookie.object.get("firstPartyDomain")) |v| {
        const first_party = try string(v);
        if (first_party.len != 0 and !std.mem.eql(u8, first_party, "fixture.invalid")) return error.InvalidCookieScope;
    }
}

fn verifyStorage(storage: std.json.Value, origin: []const u8) Error!void {
    try fields(storage, &.{ "origin", "key", "value" }, &.{});
    if (!std.mem.eql(u8, try string(try member(storage, "origin")), origin)) return error.InvalidStorageScope;
    if (!std.mem.eql(u8, try string(try member(storage, "key")), "omux_fixture_state")) return error.InvalidStorageScope;
    const secret = try string(try member(storage, "value"));
    if (secret.len == 0 or secret.len > max_secret_bytes) return error.InvalidCapsule;
}

/// Validation establishes message/scope integrity only. The daemon still must
/// authorize the source, check tombstones, and verify identity before admission.
/// Strict envelope/routing metadata only; capsule admission is separate. This
/// allows host and daemon to fence instance intent before provider refusal
/// accounting or any source mutation. Channel intent is not profile identity.
pub fn validateIngress(value: std.json.Value, allow_fixture: bool) Error!Validated {
    try fields(value, &.{ "version", "id", "method", "params" }, &.{});
    if (try integer(try member(value, "version")) != 1) return error.InvalidVersion;
    const id = try identifier(try member(value, "id"), 64);
    const method = try parseMethod(try string(try member(value, "method")));
    const params = try member(value, "params");
    if (method == .health) {
        try fields(params, &.{"provenance"}, &.{});
        return .{ .id = id, .method = .health, .provenance = try validateProvenance(try member(params, "provenance")) };
    }
    const extras: []const []const u8 = switch (method) {
        .health => unreachable,
        .connect => &.{},
        .import_grant => &.{"capsule"},
        .observation => &.{"observation"},
        .reconcile, .disconnect => &.{},
    };
    try fields(params, &.{ "sourceId", "adapter", "origin", "provenance" }, extras);
    // Method-specific extras are required, not merely permitted.
    for (extras) |extra| _ = try member(params, extra);
    const source_id = try identifier(try member(params, "sourceId"), 128);
    const adapter = try parseAdapter(try string(try member(params, "adapter")));
    if (adapter == .fixture and (!allow_fixture or !builtin.is_test)) return error.FixtureDisabled;
    const origin = try string(try member(params, "origin"));
    if (!std.mem.eql(u8, origin, policy(adapter).origin)) return error.OriginMismatch;
    return .{ .id = id, .method = method, .adapter = adapter, .source_id = source_id, .origin = origin, .provenance = try validateProvenance(try member(params, "provenance")) };
}

pub fn validateRequest(value: std.json.Value, allow_fixture: bool, now_unix: i64) Error!Validated {
    var validated = try validateIngress(value, allow_fixture);
    if (validated.method == .health) return validated;
    const method = validated.method;
    const adapter = validated.adapter;
    const origin = validated.origin;
    const params = try member(value, "params");
    switch (method) {
        .health => unreachable,
        .connect => {},
        .import_grant => {
            if (policy(adapter).export_capability == .needs_provider_adapter_proof) return error.NeedsProviderAdapterProof;
            const capsule = try member(params, "capsule");
            try fields(capsule, &.{ "kind", "purpose", "renewalAuthority", "browserBound", "capturedAt", "cookies", "storage" }, &.{"expiresAt"});
            if (!std.mem.eql(u8, try string(try member(capsule, "kind")), "browser_session") or !std.mem.eql(u8, try string(try member(capsule, "purpose")), "identity_observation") or !std.mem.eql(u8, try string(try member(capsule, "renewalAuthority")), "external")) return error.InvalidCapsule;
            validated.browser_bound = try boolean(try member(capsule, "browserBound"));
            const captured_at = try timestamp(try member(capsule, "capturedAt"));
            if (now_unix < 0 or captured_at > now_unix +| 300) return error.InvalidCapsule;
            if (capsule.object.get("expiresAt")) |expiry| {
                validated.expires_at = try timestamp(expiry);
                if (validated.expires_at.? <= now_unix or validated.expires_at.? <= captured_at) return error.Expired;
            }
            const cookies = try member(capsule, "cookies");
            const storage = try member(capsule, "storage");
            if (cookies != .array or storage != .array or cookies.array.items.len > max_cookies or storage.array.items.len > max_storage_entries) return error.InvalidCapsule;
            if (cookies.array.items.len == 0 and storage.array.items.len == 0) return error.InvalidCapsule;
            var capsule_bytes: usize = 0;
            for (cookies.array.items) |cookie| {
                try verifyCookie(cookie, origin, now_unix);
                capsule_bytes += (try string(try member(cookie, "value"))).len;
                if (cookie.object.get("expirationDate")) |expiry| {
                    if (validated.expires_at == null or @as(f64, @floatFromInt(validated.expires_at.?)) > try finiteNumber(expiry)) return error.InvalidCapsule;
                }
            }
            for (storage.array.items) |entry| {
                try verifyStorage(entry, origin);
                capsule_bytes += (try string(try member(entry, "value"))).len;
            }
            if (capsule_bytes > max_capsule_bytes) return error.InvalidCapsule;
            for (cookies.array.items, 0..) |cookie, index| for (cookies.array.items[0..index]) |previous| {
                if (std.mem.eql(u8, try string(try member(cookie, "name")), try string(try member(previous, "name"))) and
                    std.mem.eql(u8, try string(try member(cookie, "domain")), try string(try member(previous, "domain"))) and
                    std.mem.eql(u8, try string(try member(cookie, "path")), try string(try member(previous, "path")))) return error.InvalidCookieScope;
            };
            for (storage.array.items, 0..) |entry, index| for (storage.array.items[0..index]) |previous| {
                if (std.mem.eql(u8, try string(try member(entry, "key")), try string(try member(previous, "key")))) return error.InvalidStorageScope;
            };
            // An export capsule is one isolated browser context. Mixed stores or
            // partitions must be split, never flattened into one Cookie header.
            if (cookies.array.items.len > 1) {
                const first = cookies.array.items[0];
                for (cookies.array.items[1..]) |cookie| {
                    if (!std.mem.eql(u8, try string(try member(first, "storeId")), try string(try member(cookie, "storeId")))) return error.InvalidCookieScope;
                    const first_partition = first.object.get("partitionKey");
                    const next_partition = cookie.object.get("partitionKey");
                    if ((first_partition == null) != (next_partition == null)) return error.InvalidCookieScope;
                    const first_party = first.object.get("firstPartyDomain");
                    const next_party = cookie.object.get("firstPartyDomain");
                    if ((first_party == null) != (next_party == null)) return error.InvalidCookieScope;
                    if (first_party != null and !std.mem.eql(u8, try string(first_party.?), try string(next_party.?))) return error.InvalidCookieScope;
                    if (first_partition != null) {
                        const first_ancestor = first_partition.?.object.get("hasCrossSiteAncestor");
                        const next_ancestor = next_partition.?.object.get("hasCrossSiteAncestor");
                        if ((first_ancestor == null) != (next_ancestor == null)) return error.InvalidCookieScope;
                        if (first_ancestor != null and (try boolean(first_ancestor.?)) != (try boolean(next_ancestor.?))) return error.InvalidCookieScope;
                    }
                }
            }
            validated.cookie_count = cookies.array.items.len;
            validated.storage_count = storage.array.items.len;
            validated.capsule = capsule;
        },
        .observation => {
            // Private usage readers require separately promoted adapter proof.
            if (adapter != .fixture) return error.NeedsProviderAdapterProof;
            const observation = try member(params, "observation");
            try fields(observation, &.{ "resource", "unit", "value", "observedAt" }, &.{ "limit", "expiresAt" });
            _ = try identifier(try member(observation, "resource"), 256);
            const unit = try string(try member(observation, "unit"));
            var valid_unit = false;
            for ([_][]const u8{ "calls", "bytes", "seconds", "count", "bytes_per_second" }) |candidate| if (std.mem.eql(u8, unit, candidate)) {
                valid_unit = true;
                break;
            };
            if (!valid_unit) return error.InvalidObservation;
            const current = try finiteNumber(try member(observation, "value"));
            if (observation.object.get("limit")) |limit| if (try finiteNumber(limit) < current) return error.InvalidObservation;
            const observed_at = try timestamp(try member(observation, "observedAt"));
            if (now_unix < 0 or observed_at > now_unix +| 300) return error.InvalidObservation;
            if (observation.object.get("expiresAt")) |expiry| {
                const expires_at = try timestamp(expiry);
                if (expires_at <= observed_at or expires_at <= now_unix) return error.Expired;
            }
            validated.observation = observation;
        },
        .reconcile, .disconnect => {},
    }
    return validated;
}

pub const Parsed = struct {
    allocator: std.mem.Allocator,
    payload: []u8,
    parsed: std.json.Parsed(std.json.Value),
    validated: Validated,

    /// Invalidates all borrowed strings immediately, without releasing memory.
    /// Useful once a custody transaction has consumed its candidate capsule.
    pub fn eraseSensitive(self: *Parsed) void {
        eraseJsonStrings(self.parsed.value);
        std.crypto.secureZero(u8, self.payload);
    }

    pub fn deinit(self: *Parsed) void {
        self.eraseSensitive();
        self.parsed.deinit();
        self.allocator.free(self.payload);
        self.* = undefined;
    }
};

fn eraseJsonStrings(value: std.json.Value) void {
    switch (value) {
        .string, .number_string => |s| std.crypto.secureZero(u8, @constCast(s)),
        .array => |a| for (a.items) |item| eraseJsonStrings(item),
        .object => |o| {
            var it = o.iterator();
            while (it.next()) |entry| eraseJsonStrings(entry.value_ptr.*);
        },
        else => {},
    }
}

/// Takes a private copy so all grant-bearing JSON can be erased on completion.
pub fn decodeRequest(allocator: std.mem.Allocator, payload: []const u8, allow_fixture: bool, now_unix: i64) !Parsed {
    return decode(allocator, payload, allow_fixture, now_unix, false);
}

pub fn decodeIngress(allocator: std.mem.Allocator, payload: []const u8, allow_fixture: bool) !Parsed {
    return decode(allocator, payload, allow_fixture, 0, true);
}

fn decode(allocator: std.mem.Allocator, payload: []const u8, allow_fixture: bool, now_unix: i64, ingress_only: bool) !Parsed {
    if (payload.len == 0 or payload.len > max_message_bytes) return error.MessageTooLarge;
    try checkJsonDepth(payload);
    const owned = try allocator.dupe(u8, payload);
    errdefer {
        std.crypto.secureZero(u8, owned);
        allocator.free(owned);
    }
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, owned, .{ .duplicate_field_behavior = .@"error", .max_value_len = max_message_bytes });
    errdefer {
        eraseJsonStrings(parsed.value);
        parsed.deinit();
    }
    const validated = if (ingress_only) try validateIngress(parsed.value, allow_fixture) else try validateRequest(parsed.value, allow_fixture, now_unix);
    return .{ .allocator = allocator, .payload = owned, .parsed = parsed, .validated = validated };
}

fn checkJsonDepth(payload: []const u8) Error!void {
    var depth: usize = 0;
    var in_string = false;
    var escaped = false;
    for (payload) |byte| {
        if (in_string) {
            if (escaped) escaped = false else if (byte == '\\') escaped = true else if (byte == '"') in_string = false;
            continue;
        }
        switch (byte) {
            '"' => in_string = true,
            '{', '[' => {
                depth += 1;
                if (depth > max_json_depth) return error.InvalidRequest;
            },
            '}', ']' => {
                if (depth == 0) return error.InvalidRequest;
                depth -= 1;
            },
            else => {},
        }
    }
    // The JSON parser handles quote validity and matching delimiter types.
}

pub fn frameLength(header: [4]u8) Error!usize {
    const length = @as(u32, header[0]) | (@as(u32, header[1]) << 8) | (@as(u32, header[2]) << 16) | (@as(u32, header[3]) << 24);
    if (length == 0 or length > max_message_bytes) return error.MessageTooLarge;
    return @intCast(length);
}

pub fn decodeFrame(frame: []const u8) Error![]const u8 {
    if (frame.len < 4) return error.IncompleteFrame;
    const length = try frameLength(frame[0..4].*);
    if (frame.len < length + 4) return error.IncompleteFrame;
    if (frame.len != length + 4) return error.TrailingFrame;
    return frame[4..];
}

pub fn encodeFrame(allocator: std.mem.Allocator, payload: []const u8) ![]u8 {
    if (payload.len == 0 or payload.len > max_message_bytes) return error.MessageTooLarge;
    const frame = try allocator.alloc(u8, payload.len + 4);
    const length: u32 = @intCast(payload.len);
    inline for (0..4) |i| frame[i] = @truncate(length >> (i * 8));
    @memcpy(frame[4..], payload);
    return frame;
}

const fixture_connect =
    \\{"version":1,"id":"r1","method":"browser.connect","params":{"sourceId":"source-1","adapter":"fixture","origin":"https://fixture.invalid","provenance":{"channel":"release","browser":"firefox","extensionId":"omux@xoxd.ai"}}}
;
const fixture_import =
    \\{"version":1,"id":"r2","method":"browser.importGrant","params":{"provenance":{"channel":"release","browser":"firefox","extensionId":"omux@xoxd.ai"},"sourceId":"source-1","adapter":"fixture","origin":"https://fixture.invalid","capsule":{"kind":"browser_session","purpose":"identity_observation","renewalAuthority":"external","browserBound":false,"capturedAt":1000,"expiresAt":2000,"cookies":[{"name":"omux_fixture_session","value":"fake-fixture-value","domain":"fixture.invalid","path":"/","secure":true,"httpOnly":true,"hostOnly":true,"session":false,"sameSite":"strict","storeId":"firefox-container-1","expirationDate":2000,"partitionKey":{"topLevelSite":"https://fixture.invalid","hasCrossSiteAncestor":false},"firstPartyDomain":"fixture.invalid"}],"storage":[]}}}
;

test "native messaging frame rejects truncation, trailing data, oversized lengths" {
    const allocator = std.testing.allocator;
    const frame = try encodeFrame(allocator, fixture_connect);
    defer allocator.free(frame);
    try std.testing.expectEqualStrings(fixture_connect, try decodeFrame(frame));
    try std.testing.expectError(error.IncompleteFrame, decodeFrame(frame[0..3]));
    try std.testing.expectError(error.IncompleteFrame, decodeFrame(frame[0 .. frame.len - 1]));
    try std.testing.expectError(error.MessageTooLarge, frameLength(.{ 255, 255, 255, 255 }));
    var extra = try allocator.alloc(u8, frame.len + 1);
    defer allocator.free(extra);
    @memcpy(extra[0..frame.len], frame);
    extra[frame.len] = 0;
    try std.testing.expectError(error.TrailingFrame, decodeFrame(extra));
}

test "nested hostile JSON is bounded before parsing or recursive erasure" {
    var nested: [max_json_depth + 1]u8 = @splat('[');
    try std.testing.expectError(error.InvalidRequest, decodeRequest(std.testing.allocator, &nested, false, 1500));
    try checkJsonDepth("{\"quoted\":\"[[[\\\"{{{\"}");
}

test "fixture cannot be enabled without test-only explicit permission" {
    try std.testing.expectError(error.FixtureDisabled, decodeRequest(std.testing.allocator, fixture_connect, false, 1500));
    var parsed = try decodeRequest(std.testing.allocator, fixture_connect, true, 1500);
    defer parsed.deinit();
    try std.testing.expectEqual(Method.connect, parsed.validated.method);
    try std.testing.expectEqualStrings("source-1", parsed.validated.source_id);
}

test "capsules retain isolated cookie metadata and external renewal authority" {
    var parsed = try decodeRequest(std.testing.allocator, fixture_import, true, 1500);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.validated.cookie_count);
    try std.testing.expectEqual(@as(?i64, 2000), parsed.validated.expires_at);
    try std.testing.expect(!parsed.validated.browser_bound);
    const cookies = parsed.validated.capsule.?.object.get("cookies").?.array.items;
    try std.testing.expectEqualStrings("firefox-container-1", cookies[0].object.get("storeId").?.string);
    try std.testing.expectEqualStrings("fixture.invalid", cookies[0].object.get("firstPartyDomain").?.string);
    try std.testing.expectError(error.Expired, decodeRequest(std.testing.allocator, fixture_import, true, 2000));
}

test "origin, caller identity, arbitrary methods, duplicate fields and unknown fields are rejected" {
    const requests = [_][]const u8{
        "{\"version\":1,\"id\":\"r1\",\"method\":\"browser.exec\",\"params\":{}}",
        "{\"version\":1,\"id\":\"r1\",\"method\":\"browser.reconcile\",\"params\":{\"provenance\":{\"channel\":\"release\",\"browser\":\"firefox\",\"extensionId\":\"omux@xoxd.ai\"},\"sourceId\":\"s\",\"adapter\":\"github\",\"origin\":\"https://evil.invalid\"}}",
        "{\"version\":1,\"id\":\"r1\",\"method\":\"browser.reconcile\",\"params\":{\"provenance\":{\"channel\":\"release\",\"browser\":\"firefox\",\"extensionId\":\"omux@xoxd.ai\"},\"sourceId\":\"s\",\"adapter\":\"github\",\"origin\":\"https://github.com\",\"identity\":\"forged\"}}",
        "{\"version\":1,\"id\":\"r1\",\"method\":\"browser.reconcile\",\"params\":{\"provenance\":{\"channel\":\"release\",\"browser\":\"firefox\",\"extensionId\":\"omux@xoxd.ai\"},\"sourceId\":\"../source\",\"adapter\":\"github\",\"origin\":\"https://github.com\"}}",
    };
    const expected = [_]Error{ error.UnsupportedMethod, error.OriginMismatch, error.InvalidRequest, error.InvalidIdentifier };
    for (requests, expected) |request, err| try std.testing.expectError(err, decodeRequest(std.testing.allocator, request, false, 1500));
    try std.testing.expectError(error.DuplicateField, decodeRequest(std.testing.allocator, "{\"version\":1,\"version\":1}", false, 1500));
}

test "production export and usage schemas require provider proof" {
    const production = "{\"version\":1,\"id\":\"r\",\"method\":\"browser.importGrant\",\"params\":{\"provenance\":{\"channel\":\"release\",\"browser\":\"firefox\",\"extensionId\":\"omux@xoxd.ai\"},\"sourceId\":\"s\",\"adapter\":\"claude\",\"origin\":\"https://claude.ai\",\"capsule\":{}}}";
    try std.testing.expectError(error.NeedsProviderAdapterProof, decodeRequest(std.testing.allocator, production, false, 1500));
    const observation = "{\"version\":1,\"id\":\"r\",\"method\":\"browser.observation\",\"params\":{\"provenance\":{\"channel\":\"release\",\"browser\":\"firefox\",\"extensionId\":\"omux@xoxd.ai\"},\"sourceId\":\"s\",\"adapter\":\"github\",\"origin\":\"https://github.com\",\"observation\":{}}}";
    try std.testing.expectError(error.NeedsProviderAdapterProof, decodeRequest(std.testing.allocator, observation, false, 1500));
}

fn alteredImportError(needle: []const u8, replacement: []const u8, expected: anyerror) !void {
    const allocator = std.testing.allocator;
    const start = std.mem.indexOf(u8, fixture_import, needle) orelse return error.TestUnexpectedResult;
    const altered = try std.fmt.allocPrint(allocator, "{s}{s}{s}", .{ fixture_import[0..start], replacement, fixture_import[start + needle.len ..] });
    defer allocator.free(altered);
    try std.testing.expectError(expected, decodeRequest(allocator, altered, true, 1500));
}

test "capsule cannot expand cookie, partition, storage or renewal authority" {
    try alteredImportError("\"renewalAuthority\":\"external\"", "\"renewalAuthority\":\"omux\"", error.InvalidCapsule);
    try alteredImportError("\"domain\":\"fixture.invalid\"", "\"domain\":\"evil.invalid\"", error.InvalidCookieScope);
    try alteredImportError("\"path\":\"/\"", "\"path\":\"/admin\"", error.InvalidCookieScope);
    try alteredImportError("\"secure\":true", "\"secure\":false", error.InvalidCookieScope);
    try alteredImportError("\"name\":\"omux_fixture_session\"", "\"name\":\"unrelated_cookie\"", error.InvalidCookieScope);
    try alteredImportError("\"topLevelSite\":\"https://fixture.invalid\"", "\"topLevelSite\":\"https://evil.invalid\"", error.InvalidCookieScope);
    try alteredImportError("\"firstPartyDomain\":\"fixture.invalid\"", "\"firstPartyDomain\":\"evil.invalid\"", error.InvalidCookieScope);
    try alteredImportError("\"storage\":[]", "\"storage\":[{\"origin\":\"https://fixture.invalid\",\"key\":\"private_unrelated_key\",\"value\":\"fake\"}]", error.InvalidStorageScope);
    try alteredImportError("\"storage\":[]", "\"storage\":[],\"verifiedIdentity\":\"forged\"", error.InvalidRequest);
    try alteredImportError("\"capturedAt\":1000", "\"capturedAt\":1900", error.InvalidCapsule);
    try alteredImportError("\"expirationDate\":2000", "\"expirationDate\":1700", error.InvalidCapsule);
}

test "browser-bound imports never become portable bearer or renewal grants" {
    const allocator = std.testing.allocator;
    const needle = "\"browserBound\":false";
    const start = std.mem.indexOf(u8, fixture_import, needle).?;
    const altered = try std.fmt.allocPrint(allocator, "{s}\"browserBound\":true{s}", .{ fixture_import[0..start], fixture_import[start + needle.len ..] });
    defer allocator.free(altered);
    var parsed = try decodeRequest(allocator, altered, true, 1500);
    defer parsed.deinit();
    try std.testing.expect(parsed.validated.browser_bound);
    try std.testing.expectEqualStrings("identity_observation", parsed.validated.capsule.?.object.get("purpose").?.string);
    try std.testing.expectEqualStrings("external", parsed.validated.capsule.?.object.get("renewalAuthority").?.string);
}

test "generic observations have bounded units, finite values and freshness" {
    const accepted = "{\"version\":1,\"id\":\"r\",\"method\":\"browser.observation\",\"params\":{\"provenance\":{\"channel\":\"release\",\"browser\":\"firefox\",\"extensionId\":\"omux@xoxd.ai\"},\"sourceId\":\"s\",\"adapter\":\"fixture\",\"origin\":\"https://fixture.invalid\",\"observation\":{\"resource\":\"uploads\",\"unit\":\"bytes\",\"value\":100,\"limit\":200,\"observedAt\":1000,\"expiresAt\":2000}}}";
    var parsed = try decodeRequest(std.testing.allocator, accepted, true, 1500);
    defer parsed.deinit();
    try std.testing.expectEqual(Method.observation, parsed.validated.method);
    try std.testing.expectError(error.Expired, decodeRequest(std.testing.allocator, accepted, true, 2000));
    const invalid = "{\"version\":1,\"id\":\"r\",\"method\":\"browser.observation\",\"params\":{\"provenance\":{\"channel\":\"release\",\"browser\":\"firefox\",\"extensionId\":\"omux@xoxd.ai\"},\"sourceId\":\"s\",\"adapter\":\"fixture\",\"origin\":\"https://fixture.invalid\",\"observation\":{\"resource\":\"uploads\",\"unit\":\"bytes\",\"value\":201,\"limit\":200,\"observedAt\":1000}}}";
    try std.testing.expectError(error.InvalidObservation, decodeRequest(std.testing.allocator, invalid, true, 1500));
}

test "completion erases input copies and separately unescaped credential values" {
    const escaped = "{\"version\":1,\"id\":\"r\",\"method\":\"browser.importGrant\",\"params\":{\"provenance\":{\"channel\":\"release\",\"browser\":\"firefox\",\"extensionId\":\"omux@xoxd.ai\"},\"sourceId\":\"s\",\"adapter\":\"fixture\",\"origin\":\"https://fixture.invalid\",\"capsule\":{\"kind\":\"browser_session\",\"purpose\":\"identity_observation\",\"renewalAuthority\":\"external\",\"browserBound\":false,\"capturedAt\":1000,\"cookies\":[],\"storage\":[{\"origin\":\"https://fixture.invalid\",\"key\":\"omux_fixture_state\",\"value\":\"fake\\u002dfixture\\u002dsecret\"}]}}}";
    var backing: [32768]u8 = @splat(0);
    var fixed = std.heap.FixedBufferAllocator.init(&backing);
    var parsed = try decodeRequest(fixed.allocator(), escaped, true, 1500);
    const owned_input = parsed.payload;
    const secret = parsed.validated.capsule.?.object.get("storage").?.array.items[0].object.get("value").?.string;
    try std.testing.expectEqualStrings("fake-fixture-secret", secret);
    // Inspect while allocations are alive. Debug Allocator.free deliberately
    // poisons released memory, so examining it after deinit would be invalid.
    parsed.eraseSensitive();
    defer parsed.deinit();
    for (owned_input) |byte| try std.testing.expectEqual(@as(u8, 0), byte);
    try std.testing.expect(std.mem.indexOf(u8, &backing, "fake-fixture-secret") == null);
}

test "health is provider-free and retains only bounded provenance" {
    const request =
        \\{"version":1,"id":"health-1","method":"browser.health","params":{"provenance":{"channel":"release","browser":"chromium","extensionId":"abcdefghijklmnopabcdefghijklmnop"}}}
    ;
    var parsed = try decodeRequest(std.testing.allocator, request, false, 0);
    defer parsed.deinit();
    try std.testing.expectEqual(Method.health, parsed.validated.method);
    try std.testing.expectEqualStrings("chromium", parsed.validated.provenance.browser);
    try std.testing.expectEqual(@as(usize, 0), parsed.validated.source_id.len);
    const with_provider =
        \\{"version":1,"id":"health-1","method":"browser.health","params":{"adapter":"codex","provenance":{"channel":"release","browser":"chromium","extensionId":"id"}}}
    ;
    try std.testing.expectError(error.InvalidRequest, decodeRequest(std.testing.allocator, with_provider, false, 0));
    const invalid_extension =
        \\{"version":1,"id":"health-1","method":"browser.health","params":{"provenance":{"channel":"release","browser":"chromium","extensionId":"bad/id"}}}
    ;
    try std.testing.expectError(error.InvalidIdentifier, decodeRequest(std.testing.allocator, invalid_extension, false, 0));
}

test "every source mutation carries syntax-checked provenance" {
    const missing =
        \\{"version":1,"id":"r","method":"browser.disconnect","params":{"sourceId":"context-1","adapter":"github","origin":"https://github.com"}}
    ;
    try std.testing.expectError(error.InvalidRequest, decodeRequest(std.testing.allocator, missing, false, 0));
    const request =
        \\{"version":1,"id":"r","method":"browser.disconnect","params":{"sourceId":"context-1","adapter":"github","origin":"https://github.com","provenance":{"channel":"release","browser":"firefox","extensionId":"omux@xoxd.ai"}}}
    ;
    var parsed = try decodeRequest(std.testing.allocator, request, false, 0);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("context-1", parsed.validated.source_id);
    try std.testing.expect(parsed.validated.provenance.eql(.{ .browser = "firefox", .extension_id = "omux@xoxd.ai", .channel = .release }));
    try std.testing.expect(!parsed.validated.provenance.eql(.{ .browser = "chromium", .extension_id = "omux@xoxd.ai", .channel = .release }));
    try std.testing.expect(!parsed.validated.provenance.eql(.{ .browser = "firefox", .extension_id = "omux@xoxd.ai", .channel = .development }));
}

test "required typed channel intent precedes production provider proof" {
    const missing =
        \\{"version":1,"id":"r","method":"browser.importGrant","params":{"sourceId":"context","adapter":"github","origin":"https://github.com","provenance":{"browser":"chromium","extensionId":"id"},"capsule":{}}}
    ;
    const unknown =
        \\{"version":1,"id":"r","method":"browser.importGrant","params":{"sourceId":"context","adapter":"github","origin":"https://github.com","provenance":{"browser":"chromium","extensionId":"id","channel":"unknown"},"capsule":{}}}
    ;
    const accepted =
        \\{"version":1,"id":"r","method":"browser.importGrant","params":{"sourceId":"context","adapter":"github","origin":"https://github.com","provenance":{"browser":"chromium","extensionId":"id","channel":"development"},"capsule":{}}}
    ;
    try std.testing.expectError(error.InvalidRequest, decodeRequest(std.testing.allocator, missing, false, 0));
    try std.testing.expectError(error.InvalidChannel, decodeRequest(std.testing.allocator, unknown, false, 0));
    var ingress = try decodeIngress(std.testing.allocator, accepted, false);
    defer ingress.deinit();
    try std.testing.expectEqual(Channel.development, ingress.validated.provenance.channel);
    try std.testing.expectEqual(Method.import_grant, ingress.validated.method);
    try std.testing.expectError(error.NeedsProviderAdapterProof, decodeRequest(std.testing.allocator, accepted, false, 0));
}
