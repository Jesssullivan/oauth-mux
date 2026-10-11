//! Versioned, credential-free control contract. Browser acquisition and native
//! materialization use separate authenticated channels, not public methods.
const std = @import("std");

pub const protocol_version = 2;
pub const max_message = 1024 * 1024;
pub const Channel = enum { control, browser, adapter };
pub const Method = struct { name: []const u8, summary: []const u8, channel: Channel = .control };
pub const methods = [_]Method{
    .{ .name = "system.handshake", .summary = "Negotiate the implemented local protocol and capabilities." },
    .{ .name = "setup.readiness", .summary = "Inspect independent installation and account readiness without provider access." },
    .{ .name = "setup.applicationReadiness", .summary = "Read selected application and caller-declared demand diagnostics with independent source, identity, authority, renewal and capacity facts; ordinary launch remains unknown." },
    .{ .name = "setup.refresh", .summary = "Refresh bounded readiness diagnostics; optional operation_id and expected_revision record verification completion, not installation or continuity." },
    .{ .name = "setup.evidence", .summary = "Read cached bounded installation probes, diagnostic failures and freshness without provider access." },
    .{ .name = "setup.plan", .summary = "Read ownership-aware setup actions without altering managed files." },
    .{ .name = "system.health", .summary = "Read local health without initiating provider access." },
    .{ .name = "custody.reopen", .summary = "Explicitly retry locked startup custody after normal platform unlock; no source enrollment or provider request." },
    .{ .name = "reliability.lifecycle", .summary = "Read retained terminal counts and explicit setup-verification facts; timing and coverage remain partial, with no achieved SLO." },
    .{ .name = "reliability.export", .summary = "Export redacted diagnostic counters and typed timing bounds; no achieved reliability claim." },
    .{ .name = "sources.catalog", .summary = "Read supported source purposes and acquisition constraints." },
    .{ .name = "operation.status", .summary = "Resolve a mutation outcome by its stable operation identifier." },
    .{ .name = "state.snapshot", .summary = "Read a revisioned snapshot without credential payloads." },
    .{ .name = "events.watch", .summary = "Read current state after a revision; reconnect with a fresh snapshot." },
    .{ .name = "accounts.list", .summary = "List opaque accounts and independent lifecycle states." },
    .{ .name = "sources.list", .summary = "List authorized sources and their attachment state." },
    .{ .name = "usage.summary", .summary = "Group observed capacity by provider, resource, units and window." },
    .{ .name = "source.connect", .summary = "Authorize a labeled source; identity verification precedes admission." },
    .{ .name = "source.reconcile", .summary = "Request reconciliation of an authorized source." },
    .{ .name = "source.disconnect", .summary = "End source authorization, invalidate its grants and delete their retained secrets." },
    .{ .name = "account.pause", .summary = "Stop selecting an account for new requests." },
    .{ .name = "account.resume", .summary = "Make a paused account eligible again." },
    .{ .name = "account.drain", .summary = "Stop new leases while accepted requests finish." },
    .{ .name = "account.forget", .summary = "Remove retained authorization and prevent automatic re-enrollment." },
    .{ .name = "enrollment.start", .summary = "Reconcile the selected authorized source; this method does not start provider sign-in." },
    .{ .name = "repair.start", .summary = "Reconcile an account's authorized sources and report readiness without restoring spent credentials." },
    .{ .name = "operation.cancel", .summary = "Cancel an unissued enrollment or repair job." },
    .{ .name = "integrations.status", .summary = "Inspect implemented and unproven native integration capabilities." },
    .{ .name = "integrations.discover", .summary = "Inspect bounded authenticated native owner inventory in the selected integration context; hook compatibility is experimental and native support remains false." },
    .{ .name = "integrations.nativeRequestAudit", .summary = "Read at most six retained request fences for one exact native owner attachment and thread, with opaque account handles and pending-state facts; no replay or continuity claim." },
    .{ .name = "integrations.install", .summary = "Install a reversible integration after proving its prerequisites." },
    .{ .name = "integrations.remove", .summary = "Restore owned settings; Codex retains custody until reachable native threads detach safely." },
    .{ .name = "integrations.attach", .summary = "Attach a compatible native Codex hook to selected or discovered loaded threads." },
    .{ .name = "integrations.detach", .summary = "Require idle portable native context before returning threads to unmanaged routing." },
    .{ .name = "policy.get", .summary = "Read default sticky routing and alternative warming policy." },
    .{ .name = "policy.set", .summary = "Set explicitly supported routing policy." },
    .{ .name = "credential.import", .summary = "Verify and retain a purpose-scoped grant through an authorized acquisition channel.", .channel = .adapter },
    .{ .name = "adapter.owner.register", .summary = "Register socket-verified native owner custody before authorization or thread readiness.", .channel = .adapter },
    .{ .name = "adapter.acquire", .summary = "Acquire a request-scoped route lease for a trusted native adapter.", .channel = .adapter },
    .{ .name = "adapter.materialize", .summary = "Materialize only the access credential authorized by an unexpired lease.", .channel = .adapter },
    .{ .name = "adapter.report", .summary = "Report acceptance, safe rejection or completion at the native boundary.", .channel = .adapter },
    .{ .name = "adapter.metadata", .summary = "Inspect a native binding's redacted account and lease authority.", .channel = .adapter },
    .{ .name = "adapter.releaseBinding", .summary = "Retire a native binding after its in-flight leases finish.", .channel = .adapter },
    .{ .name = "adapter.gitGet", .summary = "Materialize a credential for a declared HTTPS Git context.", .channel = .adapter },
    .{ .name = "adapter.gitErase", .summary = "Reject the current Git context lease without deleting the account.", .channel = .adapter },
};

pub const Request = struct {
    parsed: std.json.Parsed(std.json.Value),
    id: std.json.Value,
    method: []const u8,
    params: std.json.Value,

    pub fn deinit(self: *Request) void {
        wipeJson(self.parsed.value);
        self.parsed.deinit();
    }
};

pub fn parse(allocator: std.mem.Allocator, payload: []const u8) !Request {
    if (payload.len == 0 or payload.len > max_message) return error.MessageTooLarge;
    try checkDepth(payload);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error" });
    errdefer {
        wipeJson(parsed.value);
        parsed.deinit();
    }
    if (parsed.value != .object) return error.InvalidRequest;
    const version = parsed.value.object.get("jsonrpc") orelse return error.InvalidRequest;
    if (version != .string or !std.mem.eql(u8, version.string, "2.0")) return error.InvalidRequest;
    const method = parsed.value.object.get("method") orelse return error.InvalidRequest;
    if (method != .string or method.string.len == 0 or method.string.len > 64) return error.InvalidRequest;
    const id = parsed.value.object.get("id") orelse return error.InvalidRequest;
    switch (id) {
        .integer => {},
        .string => |value| {
            if (value.len == 0 or value.len > 64) return error.InvalidRequest;
            for (value) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return error.InvalidRequest;
        },
        else => return error.InvalidRequest,
    }
    const params = parsed.value.object.get("params") orelse .null;
    if (params != .object and params != .null) return error.InvalidParams;
    return .{ .parsed = parsed, .id = id, .method = method.string, .params = params };
}

pub fn checkDepth(payload: []const u8) !void {
    var depth: usize = 0;
    var quoted = false;
    var escaped = false;
    for (payload) |byte| {
        if (quoted) {
            if (escaped) escaped = false else if (byte == '\\') escaped = true else if (byte == '"') quoted = false;
            continue;
        }
        switch (byte) {
            '"' => quoted = true,
            '[', '{' => {
                depth += 1;
                if (depth > 32) return error.InvalidRequest;
            },
            ']', '}' => {
                if (depth == 0) return error.InvalidRequest;
                depth -= 1;
            },
            else => {},
        }
    }
    if (quoted or depth != 0) return error.InvalidRequest;
}

/// Erase owned parsed strings, including escaped copies of private grants.
/// Call only on values parsed with .alloc_always, or from writable plaintext.
pub fn wipeJson(value: std.json.Value) void {
    switch (value) {
        .string, .number_string => |s| std.crypto.secureZero(u8, @constCast(s)),
        .array => |a| for (a.items) |item| wipeJson(item),
        .object => |o| {
            var iterator = o.iterator();
            while (iterator.next()) |entry| {
                std.crypto.secureZero(u8, @constCast(entry.key_ptr.*));
                wipeJson(entry.value_ptr.*);
            }
        },
        else => {},
    }
}

test "rejections use the JSON-RPC error field" {
    const encoded = try failure(std.testing.allocator, .null, -32600, "InvalidRequest");
    defer std.testing.allocator.free(encoded);
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, encoded, .{});
    defer parsed.deinit();
    try std.testing.expect(parsed.value.object.contains("error"));
    try std.testing.expect(!parsed.value.object.contains("err"));
}

pub fn success(allocator: std.mem.Allocator, id: std.json.Value, result: anytype) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = id, .result = result }, .{});
}

pub fn failure(allocator: std.mem.Allocator, id: std.json.Value, code: i32, name: []const u8) ![]u8 {
    // Error names come from our error set, never provider bodies or SQL errors.
    return std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = id, .@"error" = .{ .code = code, .message = name } }, .{});
}

pub fn get(params: std.json.Value, key: []const u8) ?std.json.Value {
    return if (params == .object) params.object.get(key) else null;
}

pub fn string(params: std.json.Value, key: []const u8) ![]const u8 {
    const value = get(params, key) orelse return error.InvalidParams;
    if (value != .string or value.string.len == 0 or value.string.len > 4096) return error.InvalidParams;
    for (value.string) |byte| if (byte < 0x20 or byte == 0x7f) return error.InvalidParams;
    return value.string;
}

pub fn optionalString(params: std.json.Value, key: []const u8) !?[]const u8 {
    const value = get(params, key) orelse return null;
    if (value == .null) return null;
    return try string(params, key);
}

pub fn identifier(params: std.json.Value, key: []const u8) ![]const u8 {
    const value = try string(params, key);
    if (value.len > 64) return error.InvalidParams;
    for (value) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return error.InvalidParams;
    return value;
}

pub fn operationId(params: std.json.Value) ![]const u8 {
    return identifier(params, "operation_id");
}

pub fn requestId(params: std.json.Value) ![]const u8 {
    return identifier(params, "request_id");
}

pub fn expectedRevision(params: std.json.Value) !u64 {
    const value = get(params, "expected_revision") orelse return error.InvalidParams;
    if (value != .integer or value.integer < 0) return error.InvalidParams;
    return @intCast(value.integer);
}

pub fn isMutation(method: []const u8) bool {
    const names = [_][]const u8{ "source.connect", "source.reconcile", "source.disconnect", "account.pause", "account.resume", "account.drain", "account.forget", "enrollment.start", "repair.start", "operation.cancel", "integrations.install", "integrations.remove", "integrations.attach", "integrations.detach", "policy.set" };
    for (names) |name| if (std.mem.eql(u8, method, name)) return true;
    return false;
}

/// setup.refresh remains available as a diagnostic without durable authority.
/// Any nonempty object selects its identified mode; exact field/type admission
/// belongs to the daemon, and must not become a static mutation classification.
pub fn hasOperationAuthority(method: []const u8, params: std.json.Value) bool {
    return isMutation(method) or (std.mem.eql(u8, method, "setup.refresh") and params == .object and params.object.count() != 0);
}

test "refresh authority depends on parameters and never changes its legacy classification" {
    try std.testing.expect(!isMutation("setup.refresh"));
    try std.testing.expect(!hasOperationAuthority("setup.refresh", .null));
    try std.testing.expect(!hasOperationAuthority("setup.refresh", .{ .object = .empty }));
    var identified = try parse(std.testing.allocator, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"setup.refresh\",\"params\":{\"operation_id\":\"verification-1\",\"expected_revision\":7}}");
    defer identified.deinit();
    try std.testing.expect(hasOperationAuthority(identified.method, identified.params));
    try std.testing.expectEqualStrings("verification-1", try operationId(identified.params));
    try std.testing.expectEqual(@as(u64, 7), try expectedRevision(identified.params));
    try std.testing.expect(!hasOperationAuthority("setup.evidence", identified.params));
    try std.testing.expect(hasOperationAuthority("account.pause", .null));
}

pub fn boolean(params: std.json.Value, key: []const u8, default: bool) !bool {
    const value = get(params, key) orelse return default;
    if (value != .bool) return error.InvalidParams;
    return value.bool;
}

test "public control decoding is bounded and rejects malformed framing and IDs" {
    var valid = try parse(std.testing.allocator, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"state.snapshot\"}");
    defer valid.deinit();
    try std.testing.expectEqualStrings("state.snapshot", valid.method);
    try std.testing.expectError(error.InvalidRequest, parse(std.testing.allocator, "[]"));
    try std.testing.expectError(error.InvalidRequest, parse(std.testing.allocator, "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"state.snapshot\"}"));
    try std.testing.expectError(error.InvalidRequest, parse(std.testing.allocator, "{\"jsonrpc\":\"2.0\",\"id\":\"a/b\",\"method\":\"state.snapshot\"}"));
}

test "mutation and adapter authority identifiers are explicit and distinct from correlation" {
    var admitted = try parse(std.testing.allocator, "{\"jsonrpc\":\"2.0\",\"id\":\"correlation\",\"method\":\"account.pause\",\"params\":{\"operation_id\":\"stable-action\",\"expected_revision\":7}}");
    defer admitted.deinit();
    try std.testing.expectEqualStrings("stable-action", try operationId(admitted.params));
    try std.testing.expectEqual(@as(u64, 7), try expectedRevision(admitted.params));
    try std.testing.expectError(error.InvalidParams, requestId(admitted.params));
    var missing = try parse(std.testing.allocator, "{\"jsonrpc\":\"2.0\",\"id\":\"correlation\",\"method\":\"adapter.acquire\",\"params\":{\"request_id\":\"unsafe/path\",\"expected_revision\":-1}}");
    defer missing.deinit();
    try std.testing.expectError(error.InvalidParams, operationId(missing.params));
    try std.testing.expectError(error.InvalidParams, requestId(missing.params));
    try std.testing.expectError(error.InvalidParams, expectedRevision(missing.params));
}
