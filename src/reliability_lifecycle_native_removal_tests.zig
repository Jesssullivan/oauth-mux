//! Actual local actor/storage predicates; no live application or SLO baseline.
const std = @import("std");
const builtin = @import("builtin");
const engine = @import("engine.zig");
const control = @import("control.zig");
const native_fixture = @import("native_owner_fixture.zig");
const mutation = @import("mutation_authority.zig");
const removal = @import("terminal_removal.zig");
const timing_module = @import("reliability_lifecycle_native_removal.zig");
const witness = @import("reliability_lifecycle_native_removal_witness.zig");
const allocator = std.testing.allocator;
const storage = @import("storage.zig");
const recovery = @import("recovery.zig");
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

fn stopActor(actor: *native_fixture.ActorFixture) void {
    actor.producer.pause();
    if (actor.engine) |current| current.deinit();
    actor.engine = null;
}
fn openStore(actor: *native_fixture.ActorFixture) !storage.Store {
    const path = try std.fmt.allocPrintSentinel(allocator, "{s}/state.sqlite", .{actor.state}, 0);
    defer allocator.free(path);
    const root = try storage.Store.readRootId(allocator, path);
    defer allocator.free(root);
    return storage.Store.openRoot(std.testing.io, allocator, path, root, actor.key);
}
test "actual authenticated snapshot startup refuses omitted witness facts and future outcome revisions before recovery publication" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const producer = try native_fixture.Fixture.create(std.testing.io, allocator);
    defer producer.destroy();
    const actor = try native_fixture.ActorFixture.create(std.testing.io, allocator, producer);
    defer actor.destroy();
    try actor.install();
    const id = "6666666666666666666666666666666666666666666666666666666666666666";
    var removed = try rpc(actor.engine.?, .control, "integrations.remove", .{ .adapter = "codex", .config_path = actor.config, .operation_id = id, .expected_revision = actor.engine.?.revision });
    defer removed.deinit();
    _ = try removed.result();
    stopActor(actor);
    const original = blk: {
        var store = try openStore(actor);
        defer store.close();
        var saved = try store.readSnapshot();
        defer saved.deinit();
        break :blk try allocator.dupe(u8, saved.json);
    };
    defer allocator.free(original);
    for ([_]bool{ false, true }) |future_revision| {
        var checkpoint: recovery.Checkpoint = undefined;
        var sealed_json: []u8 = undefined;
        {
            var store = try openStore(actor);
            defer store.close();
            var saved = try store.readSnapshot();
            defer saved.deinit();
            const raw = try std.json.parseFromSlice(std.json.Value, allocator, original, .{ .allocate = .alloc_always });
            defer raw.deinit();
            const records = control.get(control.get(raw.value, "mutation_authority").?, "records").?.array.items;
            var found = false;
            for (records) |*row| {
                // Fixed record arrays may serialize as strings or byte arrays.
                // A source completion is uniquely identified here by its one
                // nonnull timing witness, not by assumed byte-array encoding.
                const fact = row.object.getPtr("native_removal_witness") orelse continue;
                if (fact.* == .null) continue;
                found = true;
                if (future_revision) {
                    fact.object.getPtr("outcome_revision").?.* = .{ .integer = @intCast(saved.revision + 2) };
                } else {
                    try std.testing.expect(fact.object.getPtr("local_work").?.object.swapRemove("missing"));
                }
            }
            try std.testing.expect(found);
            sealed_json = try std.json.Stringify.valueAlloc(allocator, raw.value, .{});
            _ = try store.commit(saved.revision, sealed_json, &.{});
            checkpoint = store.checkpoint;
        }
        defer allocator.free(sealed_json);
        try std.testing.expectError(if (future_revision) error.LifecycleAuthorityMismatch else error.InvalidLifecycleWitness, engine.Engine.openWithKey(std.testing.io, allocator, actor.state, actor.key));
        {
            var store = try openStore(actor);
            defer store.close();
            var saved = try store.readSnapshot();
            defer saved.deinit();
            try std.testing.expect(checkpoint.eql(store.checkpoint));
            try std.testing.expect(checkpoint.eql(try store.authority.?.read()));
            try std.testing.expect(std.mem.eql(u8, sealed_json, saved.json));
            try std.testing.expectEqual(checkpoint.snapshot_revision, saved.revision);
            _ = try store.commit(saved.revision, original, &.{});
        }
    }
    try actor.restart();
    const summary = try timingSummary(actor.engine.?);
    try std.testing.expectEqual(@as(u64, 1), summary.completed);
    try std.testing.expectEqual(@as(u64, 1), summary.elapsed_measured);
    try std.testing.expectEqual(@as(usize, 0), producer.methodCount(.unregister));
}

fn timingSummary(actor: *engine.Engine) !timing_module.Summary {
    var reply = try rpc(actor, .control, "reliability.lifecycle", @as(?u8, null));
    defer reply.deinit();
    const value = control.get(try reply.result(), "native_removal_timing") orelse return error.MissingTiming;
    const bytes = try std.json.Stringify.valueAlloc(allocator, value, .{});
    defer allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(timing_module.Summary, allocator, bytes, .{});
    defer parsed.deinit();
    return parsed.value;
}

fn peerRpc(actor: *engine.Engine, producer: *native_fixture.Fixture, method: []const u8, params: anytype) !Reply {
    const payload = try std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = 1, .method = method, .params = params }, .{});
    defer {
        std.crypto.secureZero(u8, payload);
        allocator.free(payload);
    }
    const bytes = try producer.dispatch(actor, allocator, payload, .adapter);
    errdefer allocator.free(bytes);
    return .{ .bytes = bytes, .parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .allocate = .alloc_always }), .method = method };
}

fn pressureDiagnostic(actor: *engine.Engine, producer: *native_fixture.Fixture, operation_id: []const u8, before_revision: u64, spare_bytes: usize, stage: []const u8, reply: *const Reply) !void {
    const row = try actor.mutations.lookup(operation_id);
    const fence = actor.native_owners.applicationRemoval("codex", actor.adapter_epochs[0]) orelse actor.native_owners.applicationRemoval("codex", actor.adapter_epochs[0] -| 1);
    const failure = control.get(reply.parsed.value, "error");
    const category = if (failure) |value| control.string(value, "message") catch "InvalidRpcError" else "success";
    var canonical = category.len > 0 and category.len <= 64;
    for (category) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_') {
        canonical = false;
    };
    // Only fixed phase/category names, sizes, counters and booleans. Never
    // print operation IDs, configuration paths, cached results or request data.
    std.debug.print("native pressure stage={s} spare={d} category={s} revision_delta={d} state={s} reserved={any} measured={any} fence={s} unregister={d} poisoned={any}\n", .{
        stage,                                                  spare_bytes,                                                         if (canonical) category else "NoncanonicalRpcError",                actor.revision -| before_revision,
        if (row) |record| @tagName(record.state) else "absent", if (row) |record| record.native_removal_witness_reserved else false, if (row) |record| record.native_removal_witness != null else false, if (fence) |value| @tagName(value.phase) else "absent",
        producer.methodCount(.unregister),                      actor.poisoned,
    });
}

test "accepted native work produces a timed pending acknowledgment without removal or repeated detach" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const producer = try native_fixture.Fixture.create(std.testing.io, allocator);
    defer producer.destroy();
    const actor = try native_fixture.ActorFixture.create(std.testing.io, allocator, producer);
    defer actor.destroy();
    try actor.install();
    const account = try enroll(actor.engine.?);
    defer allocator.free(account);
    const ref = try producer.register(actor.engine.?, "same-native-thread");
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const owner = std.fmt.bytesToHex(ref.owner_id, .lower);
    const wire = .{ .owner_id = owner[0..], .adapter_epoch = try std.fmt.allocPrint(a, "{d}", .{ref.adapter_epoch}), .endpoint_generation = try std.fmt.allocPrint(a, "{d}", .{ref.endpoint_generation}), .thread_instance_generation = try std.fmt.allocPrint(a, "{d}", .{ref.thread_instance_generation}), .attachment_generation = try std.fmt.allocPrint(a, "{d}", .{ref.attachment_generation}) };
    var capability = try actor.engine.?.capabilityForTest("codex");
    defer std.crypto.secureZero(u8, &capability);
    var acquired = try peerRpc(actor.engine.?, producer, "adapter.acquire", .{ .application = "codex", .capability = &capability, .native_ref = wire, .session_id = "same-native-thread", .request_id = "accepted-removal-work", .demand = .{ .provider = "codex", .audience = "https://chatgpt.com", .purpose = "request", .required = 1, .resource = .{ .kind = "model", .target = "fixture-model", .unit = "tokens" } } });
    defer acquired.deinit();
    const handle = try control.string(try acquired.result(), "lease_handle");
    var accepted = try peerRpc(actor.engine.?, producer, "adapter.report", .{ .application = "codex", .capability = &capability, .native_ref = wire, .lease_handle = handle, .event = "accepted", .pre_acceptance = false, .response_started = true, .status = @as(u16, 0) });
    defer accepted.deinit();
    _ = try accepted.result();
    const params = .{ .operation_id = "5555555555555555555555555555555555555555555555555555555555555555", .expected_revision = actor.engine.?.revision, .adapter = "codex", .config_path = actor.config };
    var pending = try rpc(actor.engine.?, .control, "integrations.remove", params);
    defer pending.deinit();
    try std.testing.expectEqualStrings("NativeRequestsPending", try control.string(try pending.result(), "reason"));
    const before = try timingSummary(actor.engine.?);
    try std.testing.expectEqual(@as(u64, 0), before.removed);
    try std.testing.expectEqual(@as(u64, 1), before.pending_requests);
    try std.testing.expectEqual(@as(u64, 1), before.elapsed_measured);
    try std.testing.expectEqual(@as(usize, 0), producer.methodCount(.unregister));
    var completed = try peerRpc(actor.engine.?, producer, "adapter.report", .{ .application = "codex", .capability = &capability, .native_ref = wire, .lease_handle = handle, .event = "completed", .pre_acceptance = false, .response_started = true, .status = @as(u16, 0) });
    defer completed.deinit();
    _ = try completed.result();
    try actor.restart();
    var replay = try rpc(actor.engine.?, .control, "integrations.remove", params);
    defer replay.deinit();
    try std.testing.expect(std.mem.eql(u8, pending.bytes, replay.bytes));
    try std.testing.expectEqualDeep(before, try timingSummary(actor.engine.?));
    try std.testing.expectEqual(@as(usize, 0), producer.methodCount(.unregister));
}

test "native original result survives optional preparation and actual SQLite second commit denial without backfill" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    for ([_][]const u8{ "preparation", "sqlite_commit" }) |mode| {
        const producer = try native_fixture.Fixture.create(std.testing.io, allocator);
        defer producer.destroy();
        const actor = try native_fixture.ActorFixture.create(std.testing.io, allocator, producer);
        defer actor.destroy();
        try actor.install();
        _ = try producer.register(actor.engine.?, "synthetic-fault-thread");
        var armed = try rpc(actor.engine.?, .control, "fixture.lifecycleMeasurementFault", .{ .mode = mode });
        defer armed.deinit();
        _ = try armed.result();
        const params = .{ .operation_id = "4444444444444444444444444444444444444444444444444444444444444444", .expected_revision = actor.engine.?.revision, .adapter = "codex", .config_path = actor.config };
        var removed = try rpc(actor.engine.?, .control, "integrations.remove", params);
        defer removed.deinit();
        try std.testing.expect(try control.boolean(try removed.result(), "removed", false));
        if (std.mem.eql(u8, mode, "sqlite_commit")) {
            try std.testing.expect(actor.engine.?.poisoned);
            try std.testing.expect(!(try timingSummary(actor.engine.?)).authority_available);
        }
        try actor.restart();
        const revision = actor.engine.?.revision;
        var replay = try rpc(actor.engine.?, .control, "integrations.remove", params);
        defer replay.deinit();
        try std.testing.expect(std.mem.eql(u8, removed.bytes, replay.bytes));
        try std.testing.expectEqual(revision, actor.engine.?.revision);
        const summary = try timingSummary(actor.engine.?);
        try std.testing.expectEqual(@as(u64, 1), summary.removed);
        try std.testing.expectEqual(@as(u64, 1), summary.elapsed_missing);
        try std.testing.expectEqual(@as(u64, 0), summary.elapsed_measured);
        try std.testing.expectEqual(@as(usize, 1), producer.methodCount(.unregister));
    }
}

test "actual envelope pressure preserves mandatory native removal with optional timing absent" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const producer = try native_fixture.Fixture.create(std.testing.io, allocator);
    defer producer.destroy();
    const actor = try native_fixture.ActorFixture.create(std.testing.io, allocator, producer);
    defer actor.destroy();
    try actor.install();
    var capability = try actor.engine.?.capabilityForTest("enrollment");
    defer std.crypto.secureZero(u8, &capability);
    var pressure = try rpc(actor.engine.?, .adapter, "fixture.snapshotSaturate", .{ .application = "enrollment", .capability = &capability, .spare_bytes = 9500 });
    defer pressure.deinit();
    _ = try pressure.result();
    const params = .{ .operation_id = "7777777777777777777777777777777777777777777777777777777777777777", .expected_revision = actor.engine.?.revision, .adapter = "codex", .config_path = actor.config };
    var removed = try rpc(actor.engine.?, .control, "integrations.remove", params);
    defer removed.deinit();
    try pressureDiagnostic(actor.engine.?, producer, params.operation_id, params.expected_revision, 9500, "zero_owner_terminal", &removed);
    try std.testing.expect(try control.boolean(try removed.result(), "removed", false));
    const summary = try timingSummary(actor.engine.?);
    try std.testing.expectEqual(@as(u64, 1), summary.removed);
    try std.testing.expectEqual(@as(u64, 1), summary.elapsed_missing);
    try std.testing.expectEqual(@as(u64, 0), summary.elapsed_measured);
    try actor.restart();
    var replay = try rpc(actor.engine.?, .control, "integrations.remove", params);
    defer replay.deinit();
    try std.testing.expect(std.mem.eql(u8, removed.bytes, replay.bytes));
    try std.testing.expectEqualDeep(summary, try timingSummary(actor.engine.?));
}

test "registered owner optional measurement allocation failure preserves exactly once removal" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    // A deterministic real failure of optional post-terminal allocation.
    // This is not physical envelope-pressure coverage: its earlier sweep
    // receipts stay failed/unproved, and native/outer deadlines stay unchanged.
    const producer = try native_fixture.Fixture.create(std.testing.io, allocator);
    defer producer.destroy();
    const actor = try native_fixture.ActorFixture.create(std.testing.io, allocator, producer);
    defer actor.destroy();
    const original = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, actor.config, allocator, .limited(1024 * 1024));
    defer allocator.free(original);
    try actor.install();
    const reference = try producer.register(actor.engine.?, "allocation-native-thread");
    var armed = try rpc(actor.engine.?, .control, "fixture.lifecycleMeasurementFault", .{ .mode = "native_preparation_allocation" });
    defer armed.deinit();
    _ = try armed.result();
    const params = .{ .operation_id = "8888888888888888888888888888888888888888888888888888888888888888", .expected_revision = actor.engine.?.revision, .adapter = "codex", .config_path = actor.config };
    var removed = try rpc(actor.engine.?, .control, "integrations.remove", params);
    defer removed.deinit();
    try std.testing.expect(try control.boolean(try removed.result(), "removed", false));
    try std.testing.expect(actor.engine.?.fixture_native_allocation_failed);
    try std.testing.expect(!actor.engine.?.poisoned);
    const row = (try actor.engine.?.mutations.lookup(params.operation_id)).?;
    try std.testing.expectEqual(mutation.State.completed, row.state);
    try std.testing.expect(!row.native_removal_witness_reserved and row.native_removal_witness == null);
    try std.testing.expectEqual(@as(usize, 1), producer.methodCount(.unregister));
    const attachment = actor.engine.?.native_owners.lookupAttachment(reference) orelse return error.MissingAttachment;
    try std.testing.expect(attachment.phase == .retired and attachment.retirement == .verified_detach);
    const restored_config = try std.Io.Dir.cwd().readFileAlloc(std.testing.io, actor.config, allocator, .limited(1024 * 1024));
    defer allocator.free(restored_config);
    try std.testing.expect(std.mem.eql(u8, original, restored_config));
    const summary = try timingSummary(actor.engine.?);
    try std.testing.expect(summary.authority_available);
    try std.testing.expectEqual(@as(u64, 1), summary.removed);
    try std.testing.expectEqual(@as(u64, 1), summary.elapsed_missing);
    try std.testing.expectEqual(@as(u64, 0), summary.elapsed_measured);
    const revision = actor.engine.?.revision;
    var replay = try rpc(actor.engine.?, .control, "integrations.remove", params);
    defer replay.deinit();
    try std.testing.expect(std.mem.eql(u8, removed.bytes, replay.bytes));
    try std.testing.expectEqual(revision, actor.engine.?.revision);
    try std.testing.expectEqualDeep(summary, try timingSummary(actor.engine.?));
    try actor.restart();
    const restarted_revision = actor.engine.?.revision;
    var restarted = try rpc(actor.engine.?, .control, "integrations.remove", params);
    defer restarted.deinit();
    try std.testing.expect(std.mem.eql(u8, removed.bytes, restarted.bytes));
    try std.testing.expectEqual(restarted_revision, actor.engine.?.revision);
    try std.testing.expectEqualDeep(summary, try timingSummary(actor.engine.?));
    const restored_row = (try actor.engine.?.mutations.lookup(params.operation_id)).?;
    try std.testing.expectEqual(mutation.State.completed, restored_row.state);
    try std.testing.expect(!restored_row.native_removal_witness_reserved and restored_row.native_removal_witness == null);
    try std.testing.expectEqual(@as(usize, 1), producer.methodCount(.unregister));
}

test "native cached outcome strictness and original revision bind the outer operation" {
    for ([_][]const u8{
        "{\"removed\":true,\"adapter\":\"codex\",\"config_path\":\"opaque\",\"changed\":false}",
        "{\"removed\":false,\"adapter\":\"codex\",\"installed\":true,\"pending_safe_detach\":true,\"reason\":\"NativeRequestsPending\"}",
        "{\"removed\":false,\"adapter\":\"codex\",\"installed\":true,\"pending_safe_detach\":true,\"reason\":\"NativeCustodyPending\"}",
    }, 0..) |result, index| {
        var ledger = try mutation.Ledger.init(allocator, 1);
        defer ledger.deinit();
        const slot = (try ledger.begin("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", witness.method, @splat(8), 7, 7, .external)).execute;
        try std.testing.expect(try ledger.tryReserveNativeRemovalWitness(slot));
        var session = try witness.Session.begin(std.testing.io, ledger.data.records[slot], .{});
        try ledger.complete(slot, result);
        const fact = try session.afterCommitted(std.testing.io, allocator, ledger.data.records[slot], 9);
        try std.testing.expectEqual(@as(witness.Outcome, switch (index) {
            0 => .removed,
            1 => .pending_requests,
            else => .pending_custody,
        }), fact.outcome);
        try ledger.setNativeRemovalWitnessOnce(slot, fact, 9);
        try std.testing.expectError(error.LifecycleMeasurementAlreadyCaptured, ledger.abandonNativeRemovalWitness(slot));
        const encoded = try std.json.Stringify.valueAlloc(allocator, fact, .{});
        defer allocator.free(encoded);
        var parsed = try witness.read(allocator, encoded);
        defer parsed.deinit();
        try parsed.value.validateForRecord(allocator, ledger.data.records[slot], 10);
        try std.testing.expectError(error.LifecycleAuthorityMismatch, parsed.value.validateForRecord(allocator, ledger.data.records[slot], 8));
        try std.testing.expect(encoded.len <= try witness.maximumSerializedBytes());
        const saved = try std.json.Stringify.valueAlloc(allocator, ledger.snapshot(), .{});
        defer allocator.free(saved);
        try std.testing.expect(saved.len <= ledger.reservedSnapshotBytes());
    }
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
    const timing = try timingSummary(actor.engine.?);
    try std.testing.expectEqual(@as(u64, 1), timing.removed);
    try std.testing.expectEqual(@as(u64, 1), timing.elapsed_measured);
    const row = (try actor.engine.?.mutations.lookup(intent.operation_id)).?;
    try std.testing.expect(row.native_removal_witness.?.outcome_revision < actor.engine.?.revision);
    try std.testing.expectError(error.LifecycleRevisionRequired, mutation.Ledger.fromSnapshot(allocator, actor.engine.?.mutations.snapshot()));
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
    const timing = try timingSummary(actor.engine.?);
    try std.testing.expectEqual(@as(u64, 0), timing.removed);
    try std.testing.expectEqual(@as(u64, 1), timing.pending_custody);
    try std.testing.expectEqual(@as(u64, 1), timing.elapsed_measured);
    try std.testing.expectEqual(@as(u64, 1), timing.indeterminate);
}
