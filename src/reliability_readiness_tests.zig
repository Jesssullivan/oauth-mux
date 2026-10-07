//! Joint readiness is a projection of each original verification result, never
//! a cross-attempt union of prerequisites or an installation-success baseline.
const std = @import("std");
const builtin = @import("builtin");
const verification = @import("setup_verification.zig");
const mutation = @import("mutation_authority.zig");
const engine_module = @import("engine.zig");
const control = @import("control.zig");
const paths = @import("paths.zig");

const allocator = std.testing.allocator;
const io = std.testing.io;

fn readyFact(id: []const u8, observed_at: i64) verification.Result {
    return .{ .operation_id = id, .generation = 1, .observed_at = observed_at, .outcome = .verification_completed, .phases = @splat(.{ .outcome = .verified_ready, .reason = .ready }) };
}
fn complete(ledger: *mutation.Ledger, fact: verification.Result) !void {
    const slot = (try ledger.begin(fact.operation_id, verification.method, @splat(7), 0, 0, .external)).execute;
    const encoded = try verification.serialize(allocator, fact);
    defer allocator.free(encoded);
    try ledger.complete(slot, encoded);
}

test "marginal ready phases from different attempts cannot manufacture one all-ready attempt" {
    var ledger = try mutation.Ledger.init(allocator, 3);
    defer ledger.deinit();
    var missing_service = readyFact("missing-service", 100);
    missing_service.phases[1] = .{ .outcome = .action_required, .reason = .missing };
    var missing_native = readyFact("missing-native", 100);
    missing_native.phases[6] = .{ .outcome = .action_required, .reason = .native_unsupported };
    try complete(&ledger, missing_service);
    try complete(&ledger, missing_native);
    const mixed = try verification.summarize(allocator, ledger.snapshot(), 100);
    for (mixed.phases) |phase| try std.testing.expect(phase.verified_ready > 0);
    try std.testing.expectEqual(@as(u64, 0), mixed.joint_readiness.all_ready);
    try std.testing.expectEqual(@as(u64, 2), mixed.joint_readiness.action_required);
    try complete(&ledger, readyFact("all-prerequisites", 100));
    const observed = try verification.summarize(allocator, ledger.snapshot(), 100);
    try std.testing.expectEqual(@as(u64, 1), observed.joint_readiness.all_ready);
    try std.testing.expectEqual(observed.verification_completed, observed.joint_readiness.all_ready + observed.joint_readiness.action_required + observed.joint_readiness.unknown);
    try std.testing.expect(!observed.installation_success_measured and !observed.complete_user_demand_denominator and !observed.achieved_slo and !observed.end_to_end_latency_measured);
}

test "known action precedence preserves raw unknown phase presence" {
    var ledger = try mutation.Ledger.init(allocator, 2);
    defer ledger.deinit();
    var mixed = readyFact("mixed-uncertainty", 100);
    mixed.phases[1] = .{ .outcome = .action_required, .reason = .missing };
    mixed.phases[6] = .{ .outcome = .unknown, .reason = .native_evidence_missing };
    var unknown = readyFact("only-uncertainty", 100);
    unknown.phases[5] = .{ .outcome = .unknown, .reason = .observation_unknown };
    try complete(&ledger, mixed);
    try complete(&ledger, unknown);
    const summary = try verification.summarize(allocator, ledger.snapshot(), 100);
    try std.testing.expectEqualDeep(verification.JointReadiness{ .action_required = 1, .unknown = 1, .unknown_phase_present = 2 }, summary.joint_readiness);
    try std.testing.expectEqual(@as(u64, 1), summary.phases[6].unknown);
    try std.testing.expectEqual(@as(u64, 1), summary.phases[5].unknown);
}

test "refused unresolved old and future verifications never enter joint readiness" {
    const now = 30 * 86_400;
    var ledger = try mutation.Ledger.init(allocator, 5);
    defer ledger.deinit();
    try complete(&ledger, try verification.makeRefusal("refused", 0, now, .installation_selection_required));
    try complete(&ledger, readyFact("expired-window", 0));
    try complete(&ledger, readyFact("future-clock", now + 1));
    _ = try ledger.begin("started", verification.method, @splat(7), 0, 0, .external);
    const uncertain = (try ledger.begin("indeterminate", verification.method, @splat(7), 0, 0, .external)).execute;
    try ledger.markIndeterminate(uncertain);
    const summary = try verification.summarize(allocator, ledger.snapshot(), now);
    try std.testing.expectEqualDeep(verification.JointReadiness{}, summary.joint_readiness);
    try std.testing.expectEqual(@as(u64, 1), summary.safe_refusals);
    try std.testing.expectEqual(@as(u64, 1), summary.old_window_records);
    try std.testing.expectEqual(@as(u64, 1), summary.future_clock_records);
    try std.testing.expectEqual(@as(u64, 1), summary.unresolved_started);
    try std.testing.expectEqual(@as(u64, 1), summary.unresolved_indeterminate);
}

test "replay and restored original authority project each readiness attempt once" {
    var ledger = try mutation.Ledger.init(allocator, 2);
    defer ledger.deinit();
    const fact = readyFact("one-original-attempt", 100);
    try complete(&ledger, fact);
    _ = (try ledger.begin(fact.operation_id, verification.method, @splat(7), 0, 1, .external)).replay;
    const before = try verification.summarize(allocator, ledger.snapshot(), 100);
    const bytes = try std.json.Stringify.valueAlloc(allocator, ledger.snapshot(), .{});
    defer allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(mutation.Snapshot, allocator, bytes, .{});
    defer parsed.deinit();
    var restored = try mutation.Ledger.fromSnapshot(allocator, parsed.value);
    defer restored.deinit();
    restored.recoverAfterRestart();
    _ = (try restored.begin(fact.operation_id, verification.method, @splat(7), 0, 2, .external)).replay;
    const after = try verification.summarize(allocator, restored.snapshot(), 100);
    try std.testing.expectEqualDeep(before.joint_readiness, after.joint_readiness);
    try std.testing.expectEqual(@as(u64, 1), after.joint_readiness.all_ready);
    var duplicated = [_]mutation.Record{ restored.snapshot().records[0], restored.snapshot().records[0] };
    try std.testing.expectError(error.InvalidSetupVerificationSnapshot, verification.summarize(allocator, .{ .capacity = 2, .count = 2, .records = &duplicated }, 100));
}

test "malformed completed phase authority cannot default to all-ready" {
    var ledger = try mutation.Ledger.init(allocator, 1);
    defer ledger.deinit();
    var forged = readyFact("invalid-phase-pair", 100);
    forged.phases[0].reason = .missing;
    const bytes = try std.json.Stringify.valueAlloc(allocator, forged, .{});
    defer allocator.free(bytes);
    const slot = (try ledger.begin(forged.operation_id, verification.method, @splat(7), 0, 0, .external)).execute;
    try ledger.complete(slot, bytes);
    try std.testing.expectError(error.InvalidSetupVerificationResult, verification.summarize(allocator, ledger.snapshot(), 100));
}

extern "c" fn setenv(name: [*:0]const u8, value: [*:0]const u8, overwrite: c_int) c_int;
extern "c" fn unsetenv(name: [*:0]const u8) c_int;
const LaunchEnvironment = struct {
    previous_prefix: ?[:0]u8,
    previous_receipt: ?[:0]u8,

    fn init(prefix: [:0]const u8, receipt: [:0]const u8) !LaunchEnvironment {
        const previous_prefix = if (std.c.getenv("OMUX_INSTALL_PREFIX")) |value| try allocator.dupeSentinel(u8, std.mem.span(value), 0) else null;
        errdefer if (previous_prefix) |value| allocator.free(value);
        const previous_receipt = if (std.c.getenv("OMUX_INSTALL_RECORD")) |value| try allocator.dupeSentinel(u8, std.mem.span(value), 0) else null;
        errdefer if (previous_receipt) |value| allocator.free(value);
        if (setenv("OMUX_INSTALL_PREFIX", prefix.ptr, 1) != 0) return error.TestEnvironmentFailed;
        if (setenv("OMUX_INSTALL_RECORD", receipt.ptr, 1) != 0) {
            restore("OMUX_INSTALL_PREFIX", previous_prefix);
            return error.TestEnvironmentFailed;
        }
        return .{ .previous_prefix = previous_prefix, .previous_receipt = previous_receipt };
    }
    fn restore(name: [*:0]const u8, previous: ?[:0]const u8) void {
        const result = if (previous) |value| setenv(name, value.ptr, 1) else unsetenv(name);
        if (result != 0) @panic("Test environment restoration failed");
    }
    fn deinit(self: LaunchEnvironment) void {
        // All Engine-owned workers must have joined before this runs.
        restore("OMUX_INSTALL_PREFIX", self.previous_prefix);
        restore("OMUX_INSTALL_RECORD", self.previous_receipt);
        if (self.previous_prefix) |value| allocator.free(value);
        if (self.previous_receipt) |value| allocator.free(value);
    }
};
const Reply = struct {
    bytes: []u8,
    parsed: std.json.Parsed(std.json.Value),
    fn deinit(self: *Reply) void {
        self.parsed.deinit();
        allocator.free(self.bytes);
    }
    fn result(self: *const Reply) !std.json.Value {
        return control.get(self.parsed.value, "result") orelse error.UnexpectedRpcFailure;
    }
};
fn rpc(engine: *engine_module.Engine, method: []const u8, params: anytype) anyerror!Reply {
    const request = try std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = 1, .method = method, .params = params }, .{});
    defer allocator.free(request);
    const bytes = try engine.dispatch(allocator, request, .control);
    errdefer allocator.free(bytes);
    return .{ .bytes = bytes, .parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) };
}
fn exportedVerification(engine: *engine_module.Engine) !verification.Summary {
    var reply = try rpc(engine, "reliability.lifecycle", @as(?u8, null));
    defer reply.deinit();
    const summary = control.get(try reply.result(), "setup_verification") orelse return error.InvalidReply;
    const encoded = try std.json.Stringify.valueAlloc(allocator, summary, .{});
    defer allocator.free(encoded);
    const parsed = try std.json.parseFromSlice(verification.Summary, allocator, encoded, .{});
    defer parsed.deinit();
    return parsed.value;
}
fn revision(engine: *engine_module.Engine) !u64 {
    var health = try rpc(engine, "system.health", @as(?u8, null));
    defer health.deinit();
    const value = control.get(try health.result(), "revision") orelse return error.InvalidReply;
    if (value != .integer or value.integer < 0) return error.InvalidReply;
    return @intCast(value.integer);
}

test "actual identified setup collection replay and SQLite restart preserve joint readiness without claiming installation success" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const temporary = std.mem.span(std.c.getenv("TEST_TMPDIR") orelse return error.MissingTestTempDirectory);
    try paths.validateAbsolute(temporary);
    var nonce: [12]u8 = undefined;
    try io.randomSecure(&nonce);
    const prefix = try std.fmt.allocPrintSentinel(allocator, "{s}/readiness-{s}", .{ temporary, std.fmt.bytesToHex(nonce, .lower) }, 0);
    defer allocator.free(prefix);
    if (std.c.mkdir(prefix.ptr, 0o700) != 0) return error.TestDirectoryCreationFailed;
    defer std.Io.Dir.cwd().deleteTree(io, prefix) catch @panic("Test directory cleanup failed");
    const receipt = try std.fmt.allocPrintSentinel(allocator, "{s}/absent-owned-receipt.json", .{prefix}, 0);
    defer allocator.free(receipt);
    const environment = try LaunchEnvironment.init(prefix, receipt);
    defer environment.deinit();
    var engine: ?*engine_module.Engine = try engine_module.Engine.openWithKey(io, allocator, prefix, @splat(79));
    defer if (engine) |current| current.deinit();
    const params = .{ .operation_id = "original-readiness-attempt", .expected_revision = try revision(engine.?) };
    var pending = try rpc(engine.?, "setup.refresh", params);
    defer pending.deinit();
    _ = try pending.result();
    const deadline = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(5000) });
    var measured: verification.Summary = undefined;
    while (true) {
        measured = try exportedVerification(engine.?);
        if (measured.verification_completed == 1) break;
        if (deadline.durationFromNow(io).raw.toMilliseconds() <= 0) return error.SetupVerificationDidNotComplete;
        try io.sleep(.fromMilliseconds(10), .awake);
    }
    try std.testing.expectEqual(@as(u64, 0), measured.joint_readiness.all_ready);
    try std.testing.expectEqual(@as(u64, 1), measured.joint_readiness.action_required);
    try std.testing.expectEqual(@as(u64, 1), measured.joint_readiness.unknown_phase_present);
    try std.testing.expect(!measured.installation_success_measured and !measured.complete_user_demand_denominator and !measured.achieved_slo and !measured.end_to_end_latency_measured);
    const before_reads = try revision(engine.?);
    var replay = try rpc(engine.?, "setup.refresh", params);
    defer replay.deinit();
    const fact = try replay.result();
    try std.testing.expectEqualStrings("verification_completed", try control.string(fact, "outcome"));
    try std.testing.expectEqualDeep(measured.joint_readiness, (try exportedVerification(engine.?)).joint_readiness);
    try std.testing.expectEqual(before_reads, try revision(engine.?));
    engine.?.deinit();
    engine = null;
    engine = try engine_module.Engine.openWithKey(io, allocator, prefix, @splat(79));
    const restored = try exportedVerification(engine.?);
    try std.testing.expectEqualDeep(measured.joint_readiness, restored.joint_readiness);
    try std.testing.expectEqual(@as(u64, 1), restored.verification_completed);
    var reopened_replay = try rpc(engine.?, "setup.refresh", params);
    defer reopened_replay.deinit();
    try std.testing.expectEqualStrings("verification_completed", try control.string(try reopened_replay.result(), "outcome"));
    try std.testing.expectEqualDeep(restored.joint_readiness, (try exportedVerification(engine.?)).joint_readiness);
}
