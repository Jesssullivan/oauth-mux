const std = @import("std");
const mutation = @import("mutation_authority.zig");
const removal = @import("terminal_removal.zig");
const engine = @import("engine.zig");
const control = @import("control.zig");
const native_fixture = @import("native_owner_fixture.zig");
const builtin = @import("builtin");
const allocator = std.testing.allocator;

fn complete(ledger: *mutation.Ledger, id: []const u8, method: []const u8, kind: mutation.Kind, result: []const u8) !usize {
    const slot = (try ledger.begin(id, method, @splat(1), 0, 0, kind)).execute;
    try ledger.complete(slot, result);
    return slot;
}

test "cached terminal forget and removal replay recover without recounting or exposing paths" {
    var ledger = try mutation.Ledger.init(allocator, 8);
    defer ledger.deinit();
    _ = try complete(&ledger, "forget-1", "account.forget", .local_atomic, "{\"forgotten\":true}");
    _ = try complete(&ledger, "remove-1", "integrations.remove", .external, "{\"removed\":true,\"adapter\":\"git\",\"config_path\":\"opaque-private-fixture-path\",\"changed\":false}");
    const replay = try ledger.begin("forget-1", "account.forget", @splat(1), 0, 1, .local_atomic);
    try std.testing.expect(replay == .replay);
    const bytes = try std.json.Stringify.valueAlloc(allocator, ledger.snapshot(), .{});
    defer allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(mutation.Snapshot, allocator, bytes, .{});
    defer parsed.deinit();
    var restored = try mutation.Ledger.fromSnapshot(allocator, parsed.value);
    defer restored.deinit();
    const summary = try removal.summarize(allocator, restored.snapshot());
    try std.testing.expectEqual(@as(u64, 1), summary.identity_forget_completed);
    try std.testing.expectEqual(@as(u64, 1), summary.adapter_removal_completed.git);
    try std.testing.expectEqual(@as(u64, 2), summary.retained_relevant_records);
    try std.testing.expect(!summary.complete_user_demand_denominator);
    try std.testing.expect(!summary.achieved_slo);
    const redacted = try std.json.Stringify.valueAlloc(allocator, summary, .{});
    defer allocator.free(redacted);
    inline for (.{ "config_path", "opaque-private-fixture-path", "forget-1", "remove-1", "account_id" }) |forbidden| try std.testing.expect(std.mem.indexOf(u8, redacted, forbidden) == null);
}

test "native safe pending reply and unresolved external effects are never successful removal" {
    var ledger = try mutation.Ledger.init(allocator, 8);
    defer ledger.deinit();
    _ = try complete(&ledger, "pending-reply", "integrations.remove", .external, "{\"removed\":false,\"adapter\":\"codex\",\"installed\":true,\"pending_safe_detach\":true,\"reason\":\"NativeRequestsPending\"}");
    _ = try ledger.begin("effect-started", "integrations.remove", @splat(1), 0, 0, .external);
    const unknown = (try ledger.begin("effect-unknown", "integrations.remove", @splat(1), 0, 0, .external)).execute;
    try ledger.markIndeterminate(unknown);
    const summary = try removal.summarize(allocator, ledger.snapshot());
    try std.testing.expectEqual(@as(u64, 0), summary.adapter_removal_completed.codex);
    try std.testing.expectEqual(@as(u64, 1), summary.adapter_removal_pending_safe.native_requests_pending);
    try std.testing.expectEqual(@as(u64, 1), summary.unresolved_started.adapter_removal);
    try std.testing.expectEqual(@as(u64, 1), summary.unresolved_indeterminate.adapter_removal);
    ledger.recoverAfterRestart();
    const after = try removal.summarize(allocator, ledger.snapshot());
    try std.testing.expectEqual(@as(u64, 0), after.adapter_removal_completed.codex);
    try std.testing.expectEqual(@as(u64, 2), after.unresolved_indeterminate.adapter_removal);
}

test "strict current result shapes and mutation kinds reject optimistic or misattributed completion" {
    const invalid = [_][]const u8{
        "{\"removed\":false,\"adapter\":\"git\",\"config_path\":\"opaque\",\"changed\":true}",
        "{\"removed\":true,\"adapter\":\"git\",\"changed\":true}",
        "{\"removed\":true,\"adapter\":\"unknown\",\"config_path\":\"opaque\",\"changed\":true}",
        "{\"removed\":true,\"removed\":false,\"adapter\":\"git\",\"config_path\":\"opaque\",\"changed\":true}",
        "{\"removed\":false,\"adapter\":\"codex\",\"installed\":true,\"pending_safe_detach\":true,\"reason\":\"UnverifiedReason\"}",
    };
    for (invalid) |bytes| {
        var ledger = try mutation.Ledger.init(allocator, 1);
        defer ledger.deinit();
        const slot = try complete(&ledger, "remove-1", "integrations.remove", .external, bytes);
        try std.testing.expectError(error.InvalidTerminalRemovalResult, removal.classifyCompleted(allocator, ledger.data.records[slot]));
    }
    var ledger = try mutation.Ledger.init(allocator, 2);
    defer ledger.deinit();
    const bad_kind = try complete(&ledger, "wrong-kind", "account.forget", .external, "{\"forgotten\":true}");
    try std.testing.expectError(error.InvalidTerminalRemovalRecord, removal.classifyCompleted(allocator, ledger.data.records[bad_kind]));
    const false_forget = try complete(&ledger, "not-forgotten", "account.forget", .local_atomic, "{\"forgotten\":false}");
    try std.testing.expectError(error.InvalidTerminalRemovalResult, removal.classifyCompleted(allocator, ledger.data.records[false_forget]));
}

test "duplicate authority cannot manufacture an extra completed outcome" {
    var ledger = try mutation.Ledger.init(allocator, 1);
    defer ledger.deinit();
    _ = try complete(&ledger, "forget-1", "account.forget", .local_atomic, "{\"forgotten\":true}");
    const rows = [_]mutation.Record{ ledger.data.records[0], ledger.data.records[0] };
    try std.testing.expectError(error.InvalidTerminalRemovalSnapshot, removal.summarize(allocator, .{ .capacity = 2, .count = 2, .records = &rows }));
    try std.testing.expectError(error.InvalidTerminalRemovalSnapshot, removal.summarize(allocator, .{ .capacity = mutation.max_records + 1 }));
}

test "stable snapshot IDs remain distinct across intervening rows before a duplicate" {
    var ledger = try mutation.Ledger.init(allocator, 8);
    defer ledger.deinit();
    for ([_][]const u8{ "first", "second", "third", "fourth", "fifth" }) |id| _ = try complete(&ledger, id, "account.forget", .local_atomic, "{\"forgotten\":true}");
    try std.testing.expectEqual(@as(u64, 5), (try removal.summarize(allocator, ledger.snapshot())).identity_forget_completed);
    const rows = [_]mutation.Record{ ledger.data.records[0], ledger.data.records[1], ledger.data.records[2], ledger.data.records[3], ledger.data.records[4], ledger.data.records[1] };
    try std.testing.expectError(error.InvalidTerminalRemovalSnapshot, removal.summarize(allocator, .{ .capacity = 8, .count = rows.len, .records = &rows }));
}

const Reply = struct {
    bytes: []u8,
    parsed: std.json.Parsed(std.json.Value),
    method: []const u8,
    fn deinit(self: *Reply) void {
        control.wipeJson(self.parsed.value);
        self.parsed.deinit();
        std.crypto.secureZero(u8, self.bytes);
        allocator.free(self.bytes);
    }
    fn result(self: *const Reply) !std.json.Value {
        if (control.get(self.parsed.value, "result")) |value| return value;
        if (control.get(self.parsed.value, "error")) |failure| {
            const category = control.string(failure, "message") catch "InvalidRpcError";
            var canonical = category.len > 0 and category.len <= 64;
            for (category) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_') {
                canonical = false;
            };
            // Method names are static callsite labels; only a bounded category
            // escapes. Never print params, paths, token bytes or error bodies.
            std.debug.print("terminal removal RPC {s}: {s}\n", .{ self.method, if (canonical) category else "NoncanonicalRpcError" });
        }
        return error.UnexpectedRpcFailure;
    }
};
fn rpc(actor: *engine.Engine, channel: engine.Channel, method: []const u8, params: anytype) !Reply {
    const payload = try std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = 1, .method = method, .params = params }, .{});
    defer {
        std.crypto.secureZero(u8, payload);
        allocator.free(payload);
    }
    const bytes = try actor.dispatch(allocator, payload, channel);
    errdefer allocator.free(bytes);
    return .{ .bytes = bytes, .parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .allocate = .alloc_always }), .method = method };
}
fn exported(actor: *engine.Engine) !removal.Summary {
    var reply = try rpc(actor, .control, "reliability.lifecycle", @as(?u8, null));
    defer reply.deinit();
    const value = control.get(try reply.result(), "terminal_removal") orelse return error.MissingRemovalSummary;
    const bytes = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(removal.Summary, allocator, bytes, .{});
    defer parsed.deinit();
    try std.testing.expect(!parsed.value.achieved_slo and !parsed.value.end_to_end_latency_measured);
    return parsed.value;
}
fn enroll(actor: *engine.Engine) ![]u8 {
    var connected = try rpc(actor, .control, "source.connect", .{ .operation_id = "removal-source", .expected_revision = actor.revision, .kind = "explicit", .provider = "codex", .label = "synthetic removal source" });
    defer connected.deinit();
    const source = try control.string(try connected.result(), "source_id");
    var random: [32]u8 = undefined;
    try std.testing.io.randomSecure(&random);
    var token = std.fmt.bytesToHex(random, .lower);
    defer std.crypto.secureZero(u8, &token);
    defer std.crypto.secureZero(u8, &random);
    var capability = try actor.capabilityForTest("enrollment");
    defer std.crypto.secureZero(u8, &capability);
    var enrolled = try rpc(actor, .adapter, "fixture.enroll", .{ .application = "enrollment", .capability = &capability, .source_id = source, .provider = "codex", .subject = &token, .access_token = &token, .audience = "https://chatgpt.com" });
    defer enrolled.deinit();
    return allocator.dupe(u8, try control.string(try enrolled.result(), "account_id"));
}

test "actual actor forget cached authority survives replay restart and denied SQLite commit" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const producer = try native_fixture.Fixture.create(std.testing.io, allocator);
    defer producer.destroy();
    const actor = try native_fixture.ActorFixture.create(std.testing.io, allocator, producer);
    defer actor.destroy();
    const account = try enroll(actor.engine.?);
    defer allocator.free(account);
    const intent = .{ .operation_id = "forget-durable", .expected_revision = actor.engine.?.revision, .account_id = account };
    var forgotten = try rpc(actor.engine.?, .control, "account.forget", intent);
    defer forgotten.deinit();
    try std.testing.expect(try control.boolean(try forgotten.result(), "forgotten", false));
    const cached = try allocator.dupe(u8, (try actor.engine.?.mutations.lookup("forget-durable")).?.result);
    defer allocator.free(cached);
    var replay = try rpc(actor.engine.?, .control, "account.forget", intent);
    defer replay.deinit();
    _ = try replay.result();
    try actor.restart();
    var restored = try rpc(actor.engine.?, .control, "account.forget", intent);
    defer restored.deinit();
    _ = try restored.result();
    try std.testing.expectEqual(@as(u64, 1), (try exported(actor.engine.?)).identity_forget_completed);
    try std.testing.expect(std.mem.eql(u8, cached, (try actor.engine.?.mutations.lookup("forget-durable")).?.result));
    var capability = try actor.engine.?.capabilityForTest("enrollment");
    defer std.crypto.secureZero(u8, &capability);
    var fault = try rpc(actor.engine.?, .adapter, "fixture.storageReadOnly", .{ .application = "enrollment", .capability = &capability });
    defer fault.deinit();
    _ = try fault.result();
    // Even an already-forgotten identity needs a new durable terminal row.
    var failed = try rpc(actor.engine.?, .control, "account.forget", .{ .operation_id = "forget-storage-denied", .expected_revision = actor.engine.?.revision, .account_id = account });
    defer failed.deinit();
    try std.testing.expect(control.get(failed.parsed.value, "error") != null);
    try actor.restart();
    try std.testing.expect((try actor.engine.?.mutations.lookup("forget-storage-denied")) == null);
    try std.testing.expectEqual(@as(u64, 1), (try exported(actor.engine.?)).identity_forget_completed);
}

test "actual native removal success is counted once across replay and restart" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const producer = try native_fixture.Fixture.create(std.testing.io, allocator);
    defer producer.destroy();
    const actor = try native_fixture.ActorFixture.create(std.testing.io, allocator, producer);
    defer actor.destroy();
    try actor.install();
    _ = try producer.register(actor.engine.?, "synthetic-removal-thread");
    // Native operation authority requires a canonical 64-byte lowercase hex
    // identity, in addition to the generic mutation ledger ID grammar.
    const intent = .{ .operation_id = "1111111111111111111111111111111111111111111111111111111111111111", .expected_revision = actor.engine.?.revision, .adapter = "codex", .config_path = actor.config };
    var removed = try rpc(actor.engine.?, .control, "integrations.remove", intent);
    defer removed.deinit();
    try std.testing.expect(try control.boolean(try removed.result(), "removed", false));
    var replay = try rpc(actor.engine.?, .control, "integrations.remove", intent);
    defer replay.deinit();
    _ = try replay.result();
    try actor.restart();
    var restored = try rpc(actor.engine.?, .control, "integrations.remove", intent);
    defer restored.deinit();
    _ = try restored.result();
    try std.testing.expectEqual(@as(usize, 1), producer.methodCount(.unregister));
    try std.testing.expectEqual(@as(u64, 1), (try exported(actor.engine.?)).adapter_removal_completed.codex);
}

test "actual lost detach reply and cached pending custody never count as completed removal" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const producer = try native_fixture.Fixture.create(std.testing.io, allocator);
    defer producer.destroy();
    const actor = try native_fixture.ActorFixture.create(std.testing.io, allocator, producer);
    defer actor.destroy();
    try actor.install();
    _ = try producer.register(actor.engine.?, "synthetic-pending-thread");
    producer.setMethodMode(.unregister, .drop_reply);
    var failed = try rpc(actor.engine.?, .control, "integrations.remove", .{ .operation_id = "2222222222222222222222222222222222222222222222222222222222222222", .expected_revision = actor.engine.?.revision, .adapter = "codex", .config_path = actor.config });
    defer failed.deinit();
    try std.testing.expect(control.get(failed.parsed.value, "error") != null);
    try actor.restart();
    const pending_intent = .{ .operation_id = "3333333333333333333333333333333333333333333333333333333333333333", .expected_revision = actor.engine.?.revision, .adapter = "codex", .config_path = actor.config };
    var pending = try rpc(actor.engine.?, .control, "integrations.remove", pending_intent);
    defer pending.deinit();
    try std.testing.expect(try control.boolean(try pending.result(), "pending_safe_detach", false));
    try std.testing.expect(!try control.boolean(try pending.result(), "removed", true));
    var retry = try rpc(actor.engine.?, .control, "integrations.remove", pending_intent);
    defer retry.deinit();
    _ = try retry.result();
    try actor.restart();
    const summary = try exported(actor.engine.?);
    try std.testing.expectEqual(@as(u64, 0), summary.adapter_removal_completed.codex);
    try std.testing.expectEqual(@as(u64, 1), summary.adapter_removal_pending_safe.native_custody_pending);
    try std.testing.expectEqual(@as(u64, 1), summary.unresolved_indeterminate.adapter_removal);
    try std.testing.expectEqual(@as(usize, 1), producer.methodCount(.unregister));
}
