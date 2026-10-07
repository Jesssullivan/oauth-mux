//! Actual actor/SQLite adapter admission and report recovery under whole-envelope
//! saturation. Synthetic identities and credentials are generated per fixture;
//! no provider, personal vault, installed application or live continuity proof.
//! R-N13: scoped October 4 snapshot sprint acceptance gates.
const std = @import("std");
const builtin = @import("builtin");
const paths = @import("paths.zig");
const file_metadata = @import("platform/file_metadata.zig");
const engine_module = @import("engine.zig");
const control = @import("control.zig");
const domain = @import("domain.zig");
const envelope = @import("envelope.zig");
const owner_fixture = @import("native_owner_fixture.zig");
const native_owner = @import("native_owner.zig");

const allocator = std.testing.allocator;
const io = std.testing.io;
const model: domain.Resource = .{ .kind = "model", .target = "synthetic-envelope-model", .unit = .tokens };

const PrivateDirectory = struct {
    dir: std.Io.Dir,
    path: [:0]u8,

    fn cleanup(self: *PrivateDirectory) void {
        // Refuse cleanup if the original exclusive root was renamed/replaced,
        // or if any path component became an alias. Never sweep other roots.
        const current_fd = paths.openPrivateRoot(allocator, self.path, false) catch @panic("Fixture root custody changed");
        defer _ = std.c.close(current_fd);
        const original = file_metadata.statFd(self.dir.handle) catch @panic("Fixture root identity unavailable");
        const current = file_metadata.statFd(current_fd) catch @panic("Fixture root identity unavailable");
        if (original.dev != current.dev or original.ino != current.ino) @panic("Fixture root identity changed");
        std.Io.Dir.cwd().deleteTree(io, self.path) catch @panic("Fixture root cleanup failed");
        self.dir.close(io);
        allocator.free(self.path);
        self.* = undefined;
    }
};

fn privateDirectory() !PrivateDirectory {
    var nonce: [12]u8 = undefined;
    try io.randomSecure(&nonce);
    const root = try std.fmt.allocPrintSentinel(allocator, "{s}/omux-accept-{s}", .{ if (builtin.os.tag == .macos) "/private/tmp" else "/tmp", std.fmt.bytesToHex(nonce, .lower) }, 0);
    errdefer allocator.free(root);
    if (std.c.mkdir(root.ptr, 0o700) != 0) return error.FixtureDirectoryCreationFailed;
    errdefer _ = std.c.rmdir(root.ptr);
    const fd = try paths.openPrivateRoot(allocator, root, false);
    // Native registration also constructs the real broker socket path. A short
    // state root satisfies its unchanged AF_UNIX bound under long Bazel paths.
    return .{ .dir = .{ .handle = fd }, .path = root };
}

const Reply = struct {
    bytes: []u8,
    parsed: std.json.Parsed(std.json.Value),

    fn deinit(self: *Reply) void {
        control.wipeJson(self.parsed.value);
        self.parsed.deinit();
        std.crypto.secureZero(u8, self.bytes);
        allocator.free(self.bytes);
    }

    fn result(self: *const Reply) !std.json.Value {
        return control.get(self.parsed.value, "result") orelse error.ExpectedRpcSuccess;
    }

    fn expectError(self: *const Reply, expected: []const u8) !void {
        try std.testing.expect(control.get(self.parsed.value, "result") == null);
        const failure = control.get(self.parsed.value, "error") orelse return error.ExpectedRpcFailure;
        try std.testing.expectEqualStrings(expected, try control.string(failure, "message"));
    }
};

const Fixture = struct {
    directory: PrivateDirectory,
    path: [:0]u8,
    key: envelope.Key,
    engine: ?*engine_module.Engine,
    native: *owner_fixture.Fixture,
    native_ref: ?native_owner.NativeRef = null,
    next_rpc_id: u64 = 1,

    fn init() !Fixture {
        var directory = try privateDirectory();
        errdefer directory.cleanup();
        const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
        errdefer allocator.free(path);
        var key: envelope.Key = undefined;
        try io.randomSecure(&key);
        defer std.crypto.secureZero(u8, &key);
        const engine = try engine_module.Engine.openWithKey(io, allocator, path, key);
        errdefer engine.deinit();
        return .{ .directory = directory, .path = path, .key = key, .engine = engine, .native = try owner_fixture.Fixture.create(io, allocator) };
    }

    fn deinit(self: *Fixture) void {
        if (self.engine) |engine| engine.deinit();
        self.engine = null;
        self.native.destroy();
        std.crypto.secureZero(u8, &self.key);
        allocator.free(self.path);
        self.directory.cleanup();
    }

    fn restart(self: *Fixture) !void {
        const engine = self.engine orelse return error.FixtureEngineUnavailable;
        self.engine = null;
        engine.deinit();
        self.engine = try engine_module.Engine.openWithKey(io, allocator, self.path, self.key);
    }

    fn rpc(self: *Fixture, channel: engine_module.Channel, method: []const u8, params: anytype) !Reply {
        var arena: std.heap.ArenaAllocator = .init(allocator);
        defer arena.deinit();
        const a = arena.allocator();
        const normalized = if (comptime @TypeOf(params) == @TypeOf(.{})) @as(?u8, null) else params;
        const encoded_params = try std.json.Stringify.valueAlloc(a, normalized, .{});
        defer std.crypto.secureZero(u8, encoded_params);
        var parsed_params = try std.json.parseFromSlice(std.json.Value, a, encoded_params, .{ .allocate = .alloc_always });
        defer control.wipeJson(parsed_params.value);
        if (channel == .adapter and parsed_params.value == .object) {
            const application = control.get(parsed_params.value, "application");
            if (application != null and application.? == .string and std.mem.eql(u8, application.?.string, "codex")) {
                const reference = self.native_ref orelse return error.FixtureOwnerNotRegistered;
                try parsed_params.value.object.put(a, try a.dupe(u8, "native_ref"), try owner_fixture.referenceValue(a, reference));
            }
        }
        const request = try std.json.Stringify.valueAlloc(allocator, .{
            .jsonrpc = "2.0",
            .id = self.next_rpc_id,
            .method = method,
            .params = parsed_params.value,
        }, .{});
        defer {
            std.crypto.secureZero(u8, request);
            allocator.free(request);
        }
        self.next_rpc_id += 1;
        const bytes = if (channel == .adapter) try self.native.dispatch(self.engine.?, allocator, request, channel) else try self.engine.?.dispatch(allocator, request, channel);
        errdefer {
            std.crypto.secureZero(u8, bytes);
            allocator.free(bytes);
        }
        return .{ .bytes = bytes, .parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .allocate = .alloc_always }) };
    }

    fn connect(self: *Fixture) ![]u8 {
        var before = try self.rpc(.control, "state.snapshot", .{});
        defer before.deinit();
        const revision = control.get(try before.result(), "revision") orelse return error.MissingRevision;
        const operation = try std.fmt.allocPrint(allocator, "snapshot-source-authorization-{d}", .{self.next_rpc_id});
        defer allocator.free(operation);
        var connected = try self.rpc(.control, "source.connect", .{
            .operation_id = operation,
            .expected_revision = revision,
            .kind = "explicit",
            .provider = "codex",
            .label = "synthetic authorized source",
        });
        defer connected.deinit();
        return allocator.dupe(u8, try control.string(try connected.result(), "source_id"));
    }

    fn enroll(self: *Fixture, source: []const u8) !void {
        var random: [32]u8 = undefined;
        try io.randomSecure(&random);
        defer std.crypto.secureZero(u8, &random);
        var token = std.fmt.bytesToHex(random, .lower);
        defer std.crypto.secureZero(u8, &token);
        try io.randomSecure(&random);
        var subject = std.fmt.bytesToHex(random, .lower);
        defer std.crypto.secureZero(u8, &subject);
        var capability = try self.engine.?.capabilityForTest("enrollment");
        defer std.crypto.secureZero(u8, &capability);
        var reply = try self.rpc(.adapter, "fixture.enroll", .{
            .application = "enrollment",
            .capability = capability[0..],
            .source_id = source,
            .provider = "codex",
            .subject = subject[0..],
            .access_token = token[0..],
            .label = "synthetic verified account",
            .audience = "https://chatgpt.com",
        });
        defer reply.deinit();
        try std.testing.expectEqualStrings("enrolled", try control.string(try reply.result(), "status"));
    }

    fn acquire(self: *Fixture, session: []const u8, request_id: []const u8) !Reply {
        if (self.native_ref == null) try self.prepareOwner(session);
        var capability = try self.engine.?.capabilityForTest("codex");
        defer std.crypto.secureZero(u8, &capability);
        return self.rpc(.adapter, "adapter.acquire", .{
            .application = "codex",
            .capability = capability[0..],
            .session_id = session,
            .request_id = request_id,
            .demand = .{ .provider = "codex", .audience = "https://chatgpt.com", .resource = model },
        });
    }

    fn prepareOwner(self: *Fixture, session: []const u8) !void {
        if (self.native_ref != null) return error.FixtureOwnerAlreadyRegistered;
        self.native_ref = try self.native.register(self.engine.?, session);
    }

    fn report(self: *Fixture, handle: []const u8, event: []const u8) !Reply {
        var capability = try self.engine.?.capabilityForTest("codex");
        defer std.crypto.secureZero(u8, &capability);
        return self.rpc(.adapter, "adapter.report", .{
            .application = "codex",
            .capability = capability[0..],
            .lease_handle = handle,
            .event = event,
        });
    }

    fn reject(self: *Fixture, handle: []const u8) !Reply {
        var capability = try self.engine.?.capabilityForTest("codex");
        defer std.crypto.secureZero(u8, &capability);
        return self.rpc(.adapter, "adapter.report", .{
            .application = "codex",
            .capability = capability[0..],
            .lease_handle = handle,
            .event = "rejected",
            .pre_acceptance = true,
            .response_started = false,
            .status = 429,
        });
    }

    fn budget(self: *Fixture) !Budget {
        var capability = try self.engine.?.capabilityForTest("enrollment");
        defer std.crypto.secureZero(u8, &capability);
        var reply = try self.rpc(.adapter, "fixture.snapshotBudget", .{ .application = "enrollment", .capability = capability[0..] });
        defer reply.deinit();
        const value = try reply.result();
        return .{
            .exact = try integer(value, "exact_snapshot_bytes"),
            .reserved = try integer(value, "reserved_bytes"),
            .credits = try integer(value, "credits_bytes"),
            .remaining = try integer(value, "remaining_bytes"),
            .credit_count = try integer(value, "credit_count"),
        };
    }

    fn saturate(self: *Fixture) !void {
        var capability = try self.engine.?.capabilityForTest("enrollment");
        defer std.crypto.secureZero(u8, &capability);
        var reply = try self.rpc(.adapter, "fixture.snapshotSaturate", .{
            .application = "enrollment",
            .capability = capability[0..],
            .spare_bytes = 0,
        });
        defer reply.deinit();
        _ = try reply.result();
        const measured = try self.budget();
        try measured.expectBounded();
        // Prove actual whole-envelope pressure, beyond either authority partition.
        try std.testing.expect(measured.reserved > 15 * 1024 * 1024);
        try std.testing.expect(measured.remaining <= 64);
    }

    fn remainingRequests(self: *Fixture) !usize {
        var health = try self.rpc(.control, "system.health", .{});
        defer health.deinit();
        const value = try health.result();
        try std.testing.expect(control.get(value, "custody_available").?.bool);
        return integer(control.get(value, "request_authority").?, "remaining");
    }
};

const Budget = struct {
    exact: usize,
    reserved: usize,
    credits: usize,
    remaining: usize,
    credit_count: usize,

    fn expectBounded(self: Budget) !void {
        try std.testing.expect(self.exact <= 16 * 1024 * 1024);
        try std.testing.expect(self.reserved <= 16 * 1024 * 1024);
        try std.testing.expect(self.exact <= self.reserved);
        try std.testing.expect(self.credits <= self.reserved);
    }
};

fn integer(value: std.json.Value, name: []const u8) !usize {
    const field = control.get(value, name) orelse return error.MissingBudgetField;
    if (field != .integer or field.integer < 0) return error.InvalidBudgetField;
    return @intCast(field.integer);
}

fn leaseHandle(reply: *const Reply) ![]u8 {
    return allocator.dupe(u8, try control.string(try reply.result(), "lease_handle"));
}

fn expectSameState(before: *const Reply, after: *const Reply) !void {
    const a = try before.result();
    const b = try after.result();
    try std.testing.expectEqual(try integer(a, "revision"), try integer(b, "revision"));
    for ([_][]const u8{ "bindings", "leases" }) |field| {
        const first = try std.json.Stringify.valueAlloc(allocator, control.get(a, field).?, .{});
        defer allocator.free(first);
        const second = try std.json.Stringify.valueAlloc(allocator, control.get(b, field).?, .{});
        defer allocator.free(second);
        // Opaque handles must not appear in assertion diagnostics.
        try std.testing.expect(std.mem.eql(u8, first, second));
    }
}

test "whole-envelope saturation refuses adapter acquisition before route lease or request authority changes" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const source = try fixture.connect();
    defer allocator.free(source);
    try fixture.enroll(source);
    try fixture.prepareOwner("saturated-native-session");
    try fixture.saturate();
    for (0..2) |round| {
        if (round != 0) try fixture.restart();
        var before = try fixture.rpc(.control, "state.snapshot", .{});
        defer before.deinit();
        const budget_before = try fixture.budget();
        const authority_before = try fixture.remainingRequests();
        var refused = try fixture.acquire("saturated-native-session", "never-issued-request");
        defer refused.deinit();
        try refused.expectError(if (round == 0) "SnapshotTooLarge" else "NativeRemovalPending");
        var after = try fixture.rpc(.control, "state.snapshot", .{});
        defer after.deinit();
        try expectSameState(&before, &after);
        try std.testing.expectEqual(authority_before, try fixture.remainingRequests());
        const budget_after = try fixture.budget();
        try std.testing.expectEqual(budget_before.credit_count, budget_after.credit_count);
        try std.testing.expectEqual(budget_before.credits, budget_after.credits);
        try budget_after.expectBounded();
    }
}

test "accepted and uncertain adapter reports use held envelope capacity through saturation and SQLite restart" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const source = try fixture.connect();
    defer allocator.free(source);
    try fixture.enroll(source);
    var first = try fixture.acquire("preserved-native-session", "accepted-work");
    defer first.deinit();
    const accepted_handle = try leaseHandle(&first);
    defer allocator.free(accepted_handle);
    var accepted = try fixture.report(accepted_handle, "accepted");
    defer accepted.deinit();
    _ = try accepted.result();
    var second = try fixture.acquire("preserved-native-session", "accepted-restart-work");
    defer second.deinit();
    const ongoing_handle = try leaseHandle(&second);
    defer allocator.free(ongoing_handle);
    var ongoing_accepted = try fixture.report(ongoing_handle, "accepted");
    defer ongoing_accepted.deinit();
    _ = try ongoing_accepted.result();
    var third = try fixture.acquire("preserved-native-session", "unreported-work");
    defer third.deinit();
    const uncertain_handle = try leaseHandle(&third);
    defer allocator.free(uncertain_handle);
    const promised = try fixture.budget();
    try std.testing.expect(promised.credit_count >= 3);
    try std.testing.expect(promised.credits > 0);
    try fixture.saturate();
    const saturated = try fixture.budget();
    try std.testing.expectEqual(promised.credit_count, saturated.credit_count);
    try std.testing.expectEqual(promised.credits, saturated.credits);
    var refused = try fixture.acquire("preserved-native-session", "unrelated-saturated-work");
    defer refused.deinit();
    try refused.expectError("SnapshotTooLarge");
    const requests_before = try fixture.remainingRequests();
    var completed = try fixture.report(accepted_handle, "completed");
    defer completed.deinit();
    _ = try completed.result();
    const terminated = try fixture.budget();
    try std.testing.expectEqual(saturated.credit_count - 1, terminated.credit_count);
    try std.testing.expect(terminated.credits < saturated.credits);
    try std.testing.expectEqual(requests_before, try fixture.remainingRequests());
    try terminated.expectBounded();
    try fixture.restart();
    const recovered = try fixture.budget();
    try std.testing.expectEqual(terminated.credit_count, recovered.credit_count);
    try std.testing.expectEqual(terminated.credits, recovered.credits);
    for ([_][]const u8{ "accepted-work", "accepted-restart-work", "unreported-work" }) |request_id| {
        var replay = try fixture.acquire("preserved-native-session", request_id);
        defer replay.deinit();
        try replay.expectError("NativeRemovalPending");
    }
    // Acceptance already recorded before the crash remains terminal-reportable;
    // a new process cannot substitute another acquisition for that held work.
    var recovered_completion = try fixture.report(ongoing_handle, "completed");
    defer recovered_completion.deinit();
    _ = try recovered_completion.result();
    const completed_after_restart = try fixture.budget();
    try std.testing.expectEqual(recovered.credit_count - 1, completed_after_restart.credit_count);
    try std.testing.expect(completed_after_restart.credits < recovered.credits);
    // Lost acceptance cannot be converted into a safe preacceptance retry.
    var unsafe = try fixture.reject(uncertain_handle);
    defer unsafe.deinit();
    try unsafe.expectError("UnsafeReplay");
    var unaccepted_completion = try fixture.report(uncertain_handle, "completed");
    defer unaccepted_completion.deinit();
    try unaccepted_completion.expectError("InvalidTransition");
    try std.testing.expectEqual(completed_after_restart.credit_count, (try fixture.budget()).credit_count);
    var abandoned = try fixture.report(uncertain_handle, "abandoned");
    defer abandoned.deinit();
    _ = try abandoned.result();
    try std.testing.expectEqual(completed_after_restart.credit_count - 1, (try fixture.budget()).credit_count);
    // Duplicate acknowledgments remain usable; none issues another request.
    for ([_][]const u8{ "accepted", "completed" }) |event| {
        var duplicate = try fixture.report(accepted_handle, event);
        defer duplicate.deinit();
        _ = try duplicate.result();
    }
    try fixture.restart();
    for ([_][]const u8{ "accepted-work", "accepted-restart-work", "unreported-work" }) |request_id| {
        var replay = try fixture.acquire("preserved-native-session", request_id);
        defer replay.deinit();
        try replay.expectError("NativeRemovalPending");
    }
    try std.testing.expectEqual(requests_before, try fixture.remainingRequests());
}

test "saturated preacceptance rejection and two restarts never replenish the two-attempt budget" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    const source = try fixture.connect();
    defer allocator.free(source);
    for (0..3) |_| try fixture.enroll(source);
    var first = try fixture.acquire("two-attempt-native-session", "bounded-provider-request");
    defer first.deinit();
    const first_handle = try leaseHandle(&first);
    defer allocator.free(first_handle);
    const first_account = try allocator.dupe(u8, try control.string(try first.result(), "account_id"));
    defer allocator.free(first_account);
    var first_rejected = try fixture.reject(first_handle);
    defer first_rejected.deinit();
    _ = try first_rejected.result();
    try (try fixture.budget()).expectBounded();
    var alternate = try fixture.acquire("two-attempt-native-session", "bounded-provider-request");
    defer alternate.deinit();
    const alternate_handle = try leaseHandle(&alternate);
    defer allocator.free(alternate_handle);
    try std.testing.expect(!std.mem.eql(u8, first_account, try control.string(try alternate.result(), "account_id")));
    try fixture.saturate();
    var alternate_rejected = try fixture.reject(alternate_handle);
    defer alternate_rejected.deinit();
    _ = try alternate_rejected.result();
    try (try fixture.budget()).expectBounded();
    var exhausted = try fixture.acquire("two-attempt-native-session", "bounded-provider-request");
    defer exhausted.deinit();
    try exhausted.expectError("AttemptBudgetExhausted");
    const requests_before = try fixture.remainingRequests();
    const budget_before = try fixture.budget();
    for (0..2) |_| {
        try fixture.restart();
        var third = try fixture.acquire("two-attempt-native-session", "bounded-provider-request");
        defer third.deinit();
        try third.expectError("NativeRemovalPending");
        var duplicate = try fixture.reject(alternate_handle);
        defer duplicate.deinit();
        _ = try duplicate.result();
        try std.testing.expectEqual(requests_before, try fixture.remainingRequests());
        const budget_after = try fixture.budget();
        try std.testing.expectEqual(budget_before.credit_count, budget_after.credit_count);
        try std.testing.expectEqual(budget_before.credits, budget_after.credits);
    }
}
