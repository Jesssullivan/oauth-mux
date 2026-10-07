//! Native Codex broker contract, deliberately independent of account/login.
//! Stock account RPCs mutate shared auth and are never a substitute for this
//! per-thread hook. No auth.json, CODEX_HOME, transcript, or history mutation.
const std = @import("std");
const paths = @import("../paths.zig");

/// R-N13: a supplied config selects its actual parent, never a discovered socket.
/// A retained installation fixes both the config and its native home.
pub fn selectedHome(allocator: std.mem.Allocator, home: []const u8, codex_home: ?[]const u8, codex_home_explicit: bool, config_path: ?[]const u8, retained_config: ?[]const u8) ![]u8 {
    if (retained_config) |retained| {
        try paths.validateAbsolute(retained);
        if (config_path) |requested| {
            try paths.validateAbsolute(requested);
            if (!std.mem.eql(u8, requested, retained)) return error.IntegrationPathConflict;
        }
        const parent = std.fs.path.dirname(retained) orelse return error.InvalidHome;
        try paths.validateAbsolute(parent);
        if (codex_home_explicit) {
            const requested = codex_home orelse return error.InvalidHome;
            try paths.validateAbsolute(requested);
            if (!std.mem.eql(u8, requested, parent)) return error.IntegrationPathConflict;
        }
        return allocator.dupe(u8, parent);
    }
    if (config_path) |config| {
        try paths.validateAbsolute(config);
        const parent = std.fs.path.dirname(config) orelse return error.InvalidHome;
        try paths.validateAbsolute(parent);
        if (codex_home_explicit) {
            const requested = codex_home orelse return error.InvalidHome;
            try paths.validateAbsolute(requested);
            if (!std.mem.eql(u8, requested, parent)) return error.IntegrationPathConflict;
        }
        return allocator.dupe(u8, parent);
    }
    if (codex_home) |selected| {
        try paths.validateAbsolute(selected);
        return allocator.dupe(u8, selected);
    }
    if (codex_home_explicit) return error.InvalidHome;
    try paths.validateAbsolute(home);
    return std.fmt.allocPrint(allocator, "{s}/.codex", .{home});
}

test "R-N13 config context is selected before discovery and retained installation rejects rebinding" {
    const a = std.testing.allocator;
    const custom = try selectedHome(a, "/fixture/user", "/fixture/fallback", false, "/fixture/selected/custom.toml", null);
    defer a.free(custom);
    try std.testing.expectEqualStrings("/fixture/selected", custom);
    const retained = try selectedHome(a, "/fixture/user", "/fixture/changed-environment", false, null, "/fixture/selected/custom.toml");
    defer a.free(retained);
    try std.testing.expectEqualStrings("/fixture/selected", retained);
    const matching = try selectedHome(a, "/fixture/user", "/fixture/selected", true, "/fixture/selected/custom.toml", "/fixture/selected/custom.toml");
    defer a.free(matching);
    try std.testing.expectEqualStrings("/fixture/selected", matching);
    try std.testing.expectError(error.IntegrationPathConflict, selectedHome(a, "/fixture/user", "/fixture/other", true, "/fixture/selected/custom.toml", null));
    try std.testing.expectError(error.IntegrationPathConflict, selectedHome(a, "/fixture/user", "/fixture/other", true, null, "/fixture/selected/custom.toml"));
    try std.testing.expectError(error.IntegrationPathConflict, selectedHome(a, "/fixture/user", null, false, "/fixture/other/custom.toml", "/fixture/selected/custom.toml"));
    try std.testing.expectError(error.IntegrationPathConflict, selectedHome(a, "/fixture/user", null, false, "/fixture/selected/config.toml", "/fixture/selected/custom.toml"));
    try std.testing.expectError(error.UnsafePath, selectedHome(a, "/fixture/user", null, false, "/fixture/selected/../other/config.toml", null));
    try std.testing.expectError(error.InvalidHome, selectedHome(a, "/fixture/user", null, true, null, null));
}

pub const protocol_version: u32 = 1;
pub const Support = enum { native_unsupported, compatible_hook };
pub const HookCapabilities = struct {
    protocol_version: u32,
    late_thread_binding: bool = false,
    per_request_auth: bool = false,
    exclusive_refresh_owner: bool = false,
    preacceptance_failure: bool = false,
    account_transport_invalidation: bool = false,
    native_context_reconstruction: bool = false,
};
pub const NativeInfo = struct {
    native_version: []u8,
    native_discovery: bool,
    support: Support,

    pub fn deinit(self: NativeInfo, allocator: std.mem.Allocator) void {
        allocator.free(self.native_version);
    }
};

pub fn support(capabilities: ?HookCapabilities) Support {
    const hook = capabilities orelse return .native_unsupported;
    if (hook.protocol_version != protocol_version or !hook.late_thread_binding or !hook.per_request_auth or !hook.exclusive_refresh_owner or !hook.preacceptance_failure or !hook.account_transport_invalidation or !hook.native_context_reconstruction) return .native_unsupported;
    return .compatible_hook;
}

/// Native metadata is bounded before recursively parsing an external reply.
pub fn parseNativeReply(allocator: std.mem.Allocator, encoded: []const u8) !std.json.Parsed(std.json.Value) {
    if (encoded.len > 1024 * 1024) return error.MessageTooLarge;
    var depth: usize = 0;
    var quoted = false;
    var escaped = false;
    for (encoded) |byte| {
        if (quoted) {
            if (escaped) escaped = false else if (byte == '\\') escaped = true else if (byte == '"') quoted = false;
            continue;
        }
        switch (byte) {
            '"' => quoted = true,
            '[', '{' => {
                depth += 1;
                if (depth > 32) return error.InvalidHandshake;
            },
            ']', '}' => {
                if (depth == 0) return error.InvalidHandshake;
                depth -= 1;
            },
            else => {},
        }
    }
    if (quoted or depth != 0) return error.InvalidHandshake;
    return std.json.parseFromSlice(std.json.Value, allocator, encoded, .{ .duplicate_field_behavior = .@"error" });
}

/// Native app-server replies omit a JSON-RPC version field. A
/// matching request ID alone never makes a server request or an ambiguous
/// success/error envelope an acknowledgment of local custody changes.
pub fn validateResponseEnvelope(root: std.json.Value) !void {
    if (root != .object or root.object.contains("method") or root.object.contains("params")) return error.InvalidHandshake;
    const has_result = root.object.contains("result");
    const has_error = root.object.contains("error");
    if (has_result == has_error) return error.InvalidHandshake;
    if (root.object.get("error")) |failure| {
        if (failure != .object) return error.InvalidHandshake;
        const code = failure.object.get("code") orelse return error.InvalidHandshake;
        const message = failure.object.get("message") orelse return error.InvalidHandshake;
        if (code != .integer or message != .string) return error.InvalidHandshake;
    }
}

/// The initialize result's optional Omux capability is an explicit extension.
/// Unknown stock capabilities remain observational and cannot enable routing.
pub fn parseHandshake(allocator: std.mem.Allocator, encoded: []const u8) !NativeInfo {
    const parsed = try parseNativeReply(allocator, encoded);
    defer parsed.deinit();
    const root = parsed.value;
    try validateResponseEnvelope(root);
    if (root.object.contains("error")) return error.InvalidHandshake;
    const result = root.object.get("result") orelse return error.InvalidHandshake;
    if (result != .object) return error.InvalidHandshake;
    var version: []const u8 = "unknown";
    if (result.object.get("serverInfo")) |server| {
        if (server == .object) if (server.object.get("version")) |value| {
            if (value == .string) version = value.string;
        };
    }
    if (std.mem.eql(u8, version, "unknown")) {
        if (result.object.get("userAgent")) |agent| {
            if (agent == .string) version = agent.string;
        }
    }
    var compatible: Support = .native_unsupported;
    if (result.object.get("capabilities")) |caps| {
        if (caps == .object) if (caps.object.get("omuxBroker")) |broker| {
            if (broker != .object) return error.InvalidHandshake;
            const v = broker.object.get("protocol_version") orelse return error.InvalidHandshake;
            if (v != .integer or v.integer < 0 or v.integer > std.math.maxInt(u32)) return error.InvalidHandshake;
            compatible = support(.{
                .protocol_version = @intCast(v.integer),
                .late_thread_binding = try boolean(broker, "late_thread_binding"),
                .per_request_auth = try boolean(broker, "per_request_auth"),
                .exclusive_refresh_owner = try boolean(broker, "exclusive_refresh_owner"),
                .preacceptance_failure = try boolean(broker, "preacceptance_failure"),
                .account_transport_invalidation = try boolean(broker, "account_transport_invalidation"),
                .native_context_reconstruction = try boolean(broker, "native_context_reconstruction"),
            });
        };
    }
    return .{ .native_version = try allocator.dupe(u8, version), .native_discovery = true, .support = compatible };
}

fn boolean(object: std.json.Value, name: []const u8) !bool {
    const value = object.object.get(name) orelse return false;
    if (value != .bool) return error.InvalidHandshake;
    return value.bool;
}

pub fn parseCapabilities(allocator: std.mem.Allocator, encoded: []const u8) !Support {
    const parsed = try parseNativeReply(allocator, encoded);
    defer parsed.deinit();
    try validateResponseEnvelope(parsed.value);
    if (parsed.value.object.contains("error")) return .native_unsupported;
    const result = parsed.value.object.get("result") orelse return error.InvalidHandshake;
    if (result != .object) return error.InvalidHandshake;
    const version = result.object.get("protocolVersion") orelse return .native_unsupported;
    if (version != .integer or version.integer < 0 or version.integer > std.math.maxInt(u32)) return error.InvalidHandshake;
    const caps = result.object.get("capabilities") orelse return .native_unsupported;
    if (caps != .object) return error.InvalidHandshake;
    const nested_version = caps.object.get("protocol_version") orelse return .native_unsupported;
    if (nested_version != .integer or nested_version.integer < 0 or nested_version.integer > std.math.maxInt(u32)) return error.InvalidHandshake;
    if (nested_version.integer != version.integer) return .native_unsupported;
    return support(.{
        .protocol_version = @intCast(version.integer),
        .late_thread_binding = try boolean(caps, "late_thread_binding"),
        .per_request_auth = try boolean(caps, "per_request_auth"),
        .exclusive_refresh_owner = try boolean(caps, "exclusive_refresh_owner"),
        .preacceptance_failure = try boolean(caps, "preacceptance_failure"),
        .account_transport_invalidation = try boolean(caps, "account_transport_invalidation"),
        .native_context_reconstruction = try boolean(caps, "native_context_reconstruction"),
    });
}

pub fn advertisedSocket(allocator: std.mem.Allocator, codex_home: []const u8) ![]u8 {
    if (codex_home.len == 0 or codex_home[0] != '/' or std.mem.indexOfScalar(u8, codex_home, 0) != null) return error.InvalidHome;
    return std.fmt.allocPrint(allocator, "{s}{s}app-server-control/app-server-control.sock", .{ codex_home, if (codex_home[codex_home.len - 1] == '/') "" else "/" });
}

/// This JSON is carried in WebSocket-over-UDS text frames, never raw JSONL on
/// Codex's advertised socket. Transport adapters must verify the peer first.
pub fn initializeRequest(allocator: std.mem.Allocator, request_id: u64, version: []const u8) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, .{
        .id = request_id,
        .method = "initialize",
        .params = .{ .clientInfo = .{ .name = "omux", .title = "Omux account continuity", .version = version }, .capabilities = .{ .experimentalApi = true } },
    }, .{});
}

pub const BrokerConfig = struct { broker_socket: []const u8, capability_path: []const u8 };
const begin_marker = "# BEGIN OMUX CODEX INTEGRATION v1\n";
const end_marker = "# END OMUX CODEX INTEGRATION v1\n";

fn validateLocalPath(path: []const u8) !void {
    if (path.len == 0 or path[0] != '/' or path.len > 4096) return error.InvalidPath;
    for (path) |c| if (c < 0x20 or c == 0x7f) return error.InvalidPath;
}

/// Native upstream hook configuration. A stock binary will not gain routing
/// from this declaration. Installer must verify hook support before activation.
pub fn installConfig(allocator: std.mem.Allocator, original: []const u8, config: BrokerConfig) ![]u8 {
    try validateLocalPath(config.broker_socket);
    try validateLocalPath(config.capability_path);
    // Reserve the name conservatively rather than risk duplicate TOML tables,
    // dotted keys or inline tables under alternate valid TOML spellings.
    if (std.mem.indexOf(u8, original, begin_marker) != null or std.mem.indexOf(u8, original, end_marker) != null or std.mem.indexOf(u8, original, "omux_broker") != null) return error.AlreadyConfigured;
    const socket = try std.json.Stringify.valueAlloc(allocator, config.broker_socket, .{});
    defer allocator.free(socket);
    const capability_path = try std.json.Stringify.valueAlloc(allocator, config.capability_path, .{});
    defer allocator.free(capability_path);
    return std.fmt.allocPrint(allocator, "{s}{s}{s}[omux_broker]\nbroker_socket = {s}\ncapability_path = {s}\n{s}", .{ original, if (original.len == 0 or original[original.len - 1] == '\n') "" else "\n", begin_marker, socket, capability_path, end_marker });
}

pub fn removeConfig(allocator: std.mem.Allocator, current: []const u8, installed: []const u8, original: []const u8) ![]u8 {
    if (std.mem.eql(u8, current, installed)) return allocator.dupe(u8, original);
    const start = std.mem.indexOf(u8, current, begin_marker) orelse return error.NotInstalled;
    const finish = std.mem.indexOfPos(u8, current, start, end_marker) orelse return error.IntegrationModified;
    const end = finish + end_marker.len;
    if (std.mem.indexOfPos(u8, current, start + begin_marker.len, begin_marker) != null or std.mem.indexOfPos(u8, current, end, end_marker) != null) return error.IntegrationModified;
    const installed_start = std.mem.indexOf(u8, installed, begin_marker) orelse return error.IntegrationModified;
    if (!std.mem.eql(u8, current[start..end], installed[installed_start..])) return error.IntegrationModified;
    var suffix_lines = std.mem.splitScalar(u8, current[end..], '\n');
    while (suffix_lines.next()) |line| {
        const text = std.mem.trim(u8, line, " \t\r");
        if (text.len == 0 or text[0] == '#') continue;
        if (text[0] != '[') return error.IntegrationModified;
        break;
    }
    return std.mem.concat(allocator, u8, &.{ current[0..start], current[end..] });
}

pub fn registrationRequest(allocator: std.mem.Allocator, request_id: u64, thread_id: []const u8, binding_id: []const u8, config: BrokerConfig) ![]u8 {
    try validateLocalPath(config.broker_socket);
    try validateLocalPath(config.capability_path);
    if (thread_id.len == 0 or binding_id.len == 0 or thread_id.len > 256 or binding_id.len > 256) return error.InvalidBinding;
    return std.json.Stringify.valueAlloc(allocator, .{
        .id = request_id,
        .method = "omux/broker/register",
        .params = .{ .threadId = thread_id, .bindingId = binding_id, .brokerSocket = config.broker_socket, .capabilityPath = config.capability_path, .protocolVersion = protocol_version },
    }, .{});
}

pub const Lease = struct {
    lease_id: []const u8,
    account_handle: []const u8,
    route_generation: u64,
    expires_at: i64,
};
pub const Acceptance = enum { not_accepted, accepted, unknown };
pub const FailureKind = enum { auth, quota, rate, tier, transport, other };
pub const Failure = struct { kind: FailureKind, acceptance: Acceptance };
pub const State = enum { ready, requesting, accepted, completed, blocked };
pub const RouteChange = struct {
    invalidate_account_connections: bool,
    clear_incremental_references: bool,
    rebuild_from_native_context: bool,
    rerun_tools: bool = false,
};

/// One instance per native thread. IDs and strings are borrowed from the
/// binding owner. Native transcript authority stays in Codex throughout.
pub const Binding = struct {
    binding_id: []const u8,
    thread_id: []const u8,
    hook: HookCapabilities,
    refresh_ownership_acknowledged: bool,
    native_context_reconstructable: bool = false,
    state: State = .ready,
    request_id: ?[]const u8 = null,
    current_lease: ?Lease = null,
    alternate_used: bool = false,
    accepted_events: u64 = 0,

    pub fn begin(self: *Binding, request_id: []const u8, lease: Lease, now: i64) !RouteChange {
        if (support(self.hook) != .compatible_hook) return error.NativeUnsupported;
        if (!self.refresh_ownership_acknowledged) return error.RefreshOwnershipUnproven;
        if (self.state == .requesting or self.state == .accepted) return error.RequestInProgress;
        if (self.request_id) |prior| if (std.mem.eql(u8, prior, request_id)) return error.DuplicateRequest;
        if (request_id.len == 0 or lease.lease_id.len == 0 or lease.account_handle.len == 0) return error.InvalidLease;
        if (lease.expires_at <= now) return error.LeaseExpired;
        const account_changed = if (self.current_lease) |current| !std.mem.eql(u8, current.account_handle, lease.account_handle) else true;
        const generation_changed = if (self.current_lease) |current| current.route_generation != lease.route_generation else true;
        if (account_changed and !self.native_context_reconstructable) return error.NativeContextOpaque;
        self.state = .requesting;
        self.request_id = request_id;
        self.current_lease = lease;
        self.alternate_used = false;
        self.accepted_events = 0;
        return .{ .invalidate_account_connections = account_changed or generation_changed, .clear_incremental_references = account_changed, .rebuild_from_native_context = account_changed };
    }

    pub fn accepted(self: *Binding, request_id: []const u8) !void {
        try self.checkRequest(request_id);
        if (self.state != .requesting and self.state != .accepted) return error.InvalidTransition;
        self.state = .accepted;
        self.accepted_events +|= 1;
    }

    pub fn handoff(self: *Binding, request_id: []const u8, failure: Failure, alternate: Lease, now: i64) !RouteChange {
        try self.checkRequest(request_id);
        if (self.state != .requesting or self.accepted_events > 0 or failure.acceptance != .not_accepted) return error.UnsafeReplay;
        if (self.alternate_used) return error.AlternateExhausted;
        switch (failure.kind) {
            .auth, .quota, .rate, .tier => {},
            .transport, .other => return error.UnprovenHandoff,
        }
        const current = self.current_lease orelse return error.InvalidTransition;
        if (!self.native_context_reconstructable) return error.NativeContextOpaque;
        if (alternate.lease_id.len == 0 or alternate.account_handle.len == 0) return error.InvalidAlternate;
        if (alternate.expires_at <= now) return error.LeaseExpired;
        if (std.mem.eql(u8, current.lease_id, alternate.lease_id) or std.mem.eql(u8, current.account_handle, alternate.account_handle) or alternate.route_generation <= current.route_generation) return error.InvalidAlternate;
        self.current_lease = alternate;
        self.alternate_used = true;
        return .{ .invalidate_account_connections = true, .clear_incremental_references = true, .rebuild_from_native_context = true };
    }

    pub fn complete(self: *Binding, request_id: []const u8) !void {
        try self.checkRequest(request_id);
        if (self.state != .requesting and self.state != .accepted) return error.InvalidTransition;
        self.state = .completed;
    }

    fn checkRequest(self: Binding, request_id: []const u8) !void {
        if (self.request_id == null or !std.mem.eql(u8, self.request_id.?, request_id)) return error.RequestMismatch;
    }
};

const fixture_hook: HookCapabilities = .{ .protocol_version = 1, .late_thread_binding = true, .per_request_auth = true, .exclusive_refresh_owner = true, .preacceptance_failure = true, .account_transport_invalidation = true, .native_context_reconstruction = true };
fn fixtureLease(id: []const u8, account: []const u8, generation: u64) Lease {
    return .{ .lease_id = id, .account_handle = account, .route_generation = generation, .expires_at = 1000 };
}

test "stock and malformed native handshakes fail closed" {
    try std.testing.expectError(error.InvalidHandshake, parseNativeReply(std.testing.allocator, "[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"));
    try std.testing.expectError(error.DuplicateField, parseHandshake(std.testing.allocator, "{\"result\":{\"userAgent\":\"first\",\"userAgent\":\"second\"}}"));
    try std.testing.expectEqual(Support.native_unsupported, try parseCapabilities(std.testing.allocator, "{\"result\":{\"protocolVersion\":1,\"capabilities\":{\"protocol_version\":2,\"late_thread_binding\":true,\"per_request_auth\":true,\"exclusive_refresh_owner\":true,\"preacceptance_failure\":true,\"account_transport_invalidation\":true,\"native_context_reconstruction\":true}}}"));
    const allocator = std.testing.allocator;
    const stock = try parseHandshake(allocator, "{\"id\":1,\"result\":{\"capabilities\":{}}}");
    defer allocator.free(stock.native_version);
    try std.testing.expectEqual(Support.native_unsupported, stock.support);
    try std.testing.expectEqual(Support.native_unsupported, support(.{ .protocol_version = 1 }));
    var future = fixture_hook;
    future.protocol_version = 2;
    try std.testing.expectEqual(Support.native_unsupported, support(future));
}

test "native acknowledgments reject ambiguous success and server request envelopes" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{
        "{\"result\":{},\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}",
        "{\"method\":\"account/read\",\"result\":{}}",
        "{\"params\":{},\"result\":{}}",
        "{}",
        "{\"error\":null}",
        "{\"error\":{\"code\":\"wrong\",\"message\":\"invalid\"}}",
        "{\"error\":{\"code\":-32601}}",
    }) |encoded| {
        try std.testing.expectError(error.InvalidHandshake, parseHandshake(allocator, encoded));
        try std.testing.expectError(error.InvalidHandshake, parseCapabilities(allocator, encoded));
    }
    try std.testing.expectEqual(Support.native_unsupported, try parseCapabilities(allocator, "{\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}"));
}

test "fixture preserves thread and retries one proven preacceptance rejection" {
    var binding: Binding = .{ .binding_id = "binding", .thread_id = "native-thread", .hook = fixture_hook, .refresh_ownership_acknowledged = true, .native_context_reconstructable = true };
    const first = try binding.begin("request", fixtureLease("first", "work", 1), 0);
    try std.testing.expect(first.clear_incremental_references);
    const second = try binding.handoff("request", .{ .kind = .quota, .acceptance = .not_accepted }, fixtureLease("second", "research", 2), 0);
    try std.testing.expect(second.invalidate_account_connections and second.rebuild_from_native_context and !second.rerun_tools);
    try std.testing.expectEqualStrings("native-thread", binding.thread_id);
    try std.testing.expectError(error.AlternateExhausted, binding.handoff("request", .{ .kind = .quota, .acceptance = .not_accepted }, fixtureLease("third", "home", 3), 0));
    try binding.accepted("request");
    try std.testing.expectError(error.UnsafeReplay, binding.handoff("request", .{ .kind = .quota, .acceptance = .not_accepted }, fixtureLease("third", "home", 3), 0));
    try binding.complete("request");
}

test "concurrent bindings do not mutate one another or borrow renewal authority" {
    var left: Binding = .{ .binding_id = "left", .thread_id = "work-thread", .hook = fixture_hook, .refresh_ownership_acknowledged = true, .native_context_reconstructable = true };
    var right: Binding = .{ .binding_id = "right", .thread_id = "home-thread", .hook = fixture_hook, .refresh_ownership_acknowledged = false, .native_context_reconstructable = true };
    _ = try left.begin("left-request", fixtureLease("left-lease", "work", 1), 0);
    try std.testing.expectError(error.RefreshOwnershipUnproven, right.begin("right-request", fixtureLease("right-lease", "home", 1), 0));
    right.refresh_ownership_acknowledged = true;
    _ = try right.begin("right-request", fixtureLease("right-lease", "home", 1), 0);
    try std.testing.expectEqualStrings("work", left.current_lease.?.account_handle);
    try std.testing.expectEqualStrings("home", right.current_lease.?.account_handle);
    try std.testing.expectError(error.RequestMismatch, left.accepted("right-request"));
    try std.testing.expectError(error.UnsafeReplay, right.handoff("right-request", .{ .kind = .auth, .acceptance = .unknown }, fixtureLease("alternate", "research", 2), 0));
}

test "opaque native context blocks attachment and reversible configuration preserves history paths" {
    const allocator = std.testing.allocator;
    var binding: Binding = .{ .binding_id = "opaque", .thread_id = "native", .hook = fixture_hook, .refresh_ownership_acknowledged = true };
    try std.testing.expectError(error.NativeContextOpaque, binding.begin("request", fixtureLease("lease", "work", 1), 0));
    const original = "model = \"reference\"\n";
    const installed = try installConfig(allocator, original, .{ .broker_socket = "/home/user/Omux State/adapter.sock", .capability_path = "/home/user/Omux State/integrations/codex.capability" });
    defer allocator.free(installed);
    const restored = try removeConfig(allocator, installed, installed, original);
    defer allocator.free(restored);
    try std.testing.expectEqualStrings(original, restored);
    try std.testing.expect(std.mem.indexOf(u8, installed, "CODEX_HOME") == null);
    try std.testing.expect(std.mem.indexOf(u8, installed, "auth.json") == null);
}
