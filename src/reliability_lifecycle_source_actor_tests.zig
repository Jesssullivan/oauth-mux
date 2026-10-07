//! Actual actor/SQLite source removal timing. Synthetic private custody proves
//! these boundaries only, never native handoff, provider access or user latency.
const std = @import("std");
const builtin = @import("builtin");
const engine = @import("engine.zig");
const control = @import("control.zig");
const storage = @import("storage.zig");
const recovery = @import("recovery.zig");
const mutation = @import("mutation_authority.zig");
const witness = @import("reliability_lifecycle_witness.zig");
const projection = @import("reliability_lifecycle_source.zig");
const fixture = @import("native_owner_fixture.zig");
const allocator = std.testing.allocator;
const io = std.testing.io;

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
        return control.get(self.parsed.value, "result") orelse error.UnexpectedRpcFailure;
    }
    fn refused(self: *const Reply, expected: []const u8) !void {
        try std.testing.expect(control.get(self.parsed.value, "result") == null);
        const failure = control.get(self.parsed.value, "error") orelse return error.ExpectedRpcFailure;
        try std.testing.expectEqualStrings(expected, try control.string(failure, "message"));
    }
};
fn rpc(actor: *engine.Engine, channel: engine.Channel, method: []const u8, params: anytype) anyerror!Reply {
    const bytes = try std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = 1, .method = method, .params = params }, .{});
    defer allocator.free(bytes);
    const reply = try actor.dispatch(allocator, bytes, channel);
    errdefer allocator.free(reply);
    return .{ .bytes = reply, .parsed = try std.json.parseFromSlice(std.json.Value, allocator, reply, .{ .allocate = .alloc_always }) };
}
fn revision(actor: *engine.Engine) !u64 {
    var health = try rpc(actor, .control, "system.health", @as(?u8, null));
    defer health.deinit();
    const value = control.get(try health.result(), "revision") orelse return error.MissingRevision;
    if (value != .integer or value.integer < 0) return error.InvalidRevision;
    return @intCast(value.integer);
}
fn operation() ![64]u8 {
    var random: [32]u8 = undefined;
    try io.randomSecure(&random);
    return std.fmt.bytesToHex(random, .lower);
}
fn exported(actor: *engine.Engine) !projection.Summary {
    var reply = try rpc(actor, .control, "reliability.lifecycle", @as(?u8, null));
    defer reply.deinit();
    const value = control.get(try reply.result(), "source_disconnect_timing") orelse return error.MissingTimingSummary;
    const parsed = try std.json.parseFromValue(projection.Summary, allocator, value, .{});
    defer parsed.deinit();
    return parsed.value;
}
fn connect(actor: *engine.Engine) ![]u8 {
    const id = try operation();
    var reply = try rpc(actor, .control, "source.connect", .{ .operation_id = id[0..], .expected_revision = try revision(actor), .provider = "github", .kind = "native_store" });
    defer reply.deinit();
    return allocator.dupe(u8, try control.string(try reply.result(), "source_id"));
}
fn noEffects(actor: *engine.Engine, producer: *fixture.Fixture) !void {
    var capability = try actor.capabilityForTest("enrollment");
    defer std.crypto.secureZero(u8, &capability);
    var submissions = try rpc(actor, .adapter, "fixture.providerSubmissions", .{ .application = "enrollment", .capability = &capability });
    defer submissions.deinit();
    const value = try submissions.result();
    try std.testing.expectEqual(@as(i64, 0), control.get(value, "identity_submissions").?.integer);
    try std.testing.expectEqual(@as(i64, 0), control.get(value, "observation_submissions").?.integer);
    try std.testing.expectEqual(@as(usize, 0), producer.methodCount(.register));
    try std.testing.expectEqual(@as(usize, 0), producer.methodCount(.unregister));
}
fn stop(actor: *fixture.ActorFixture) void {
    actor.producer.pause();
    if (actor.engine) |current| current.deinit();
    actor.engine = null;
}
fn openStore(actor: *fixture.ActorFixture) !storage.Store {
    const path = try std.fmt.allocPrintSentinel(allocator, "{s}/state.sqlite", .{actor.state}, 0);
    defer allocator.free(path);
    const root = try storage.Store.readRootId(allocator, path);
    defer allocator.free(root);
    return storage.Store.openRoot(io, allocator, path, root, actor.key);
}
const StoredSnapshot = struct { mutation_authority: mutation.Snapshot };
const Saved = struct {
    snapshot: storage.Snapshot,
    parsed: std.json.Parsed(StoredSnapshot),
    fn capture(store: *storage.Store) !Saved {
        var snapshot = try store.readSnapshot();
        errdefer snapshot.deinit();
        return .{ .snapshot = snapshot, .parsed = try std.json.parseFromSlice(StoredSnapshot, allocator, snapshot.json, .{ .allocate = .alloc_always, .ignore_unknown_fields = true }) };
    }
    fn deinit(self: *Saved) void {
        self.parsed.deinit();
        self.snapshot.deinit();
    }
    fn record(self: *const Saved, id: []const u8) !mutation.Record {
        for (self.parsed.value.mutation_authority.records) |row| if (std.mem.eql(u8, row.id[0..row.id_len], id)) return row;
        return error.MissingOriginalOperation;
    }
};

test "actual committed source removal measurement advances metadata revision while immutable replay and restart never repeat effects" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const producer = try fixture.Fixture.create(io, allocator);
    defer producer.destroy();
    const actor = try fixture.ActorFixture.create(io, allocator, producer);
    defer actor.destroy();
    const source = try connect(actor.engine.?);
    defer allocator.free(source);
    const id = try operation();
    const params = .{ .source_id = source, .operation_id = id[0..], .expected_revision = try revision(actor.engine.?) };
    var removed = try rpc(actor.engine.?, .control, witness.method, params);
    defer removed.deinit();
    try std.testing.expect(try control.boolean(try removed.result(), "disconnected", false));
    const current = try revision(actor.engine.?);
    const summary = try exported(actor.engine.?);
    try std.testing.expectEqual(@as(u64, 1), summary.completed);
    try std.testing.expectEqual(@as(u64, 1), summary.elapsed_measured);
    try std.testing.expectEqual(@as(u64, 0), summary.elapsed_missing);
    try std.testing.expect(summary.elapsed_total_ns != null and summary.elapsed_min_ns != null and summary.elapsed_max_ns != null);
    try std.testing.expect(!summary.achieved_slo and !summary.complete_user_demand_denominator and !summary.user_end_to_end_measured);
    var replay = try rpc(actor.engine.?, .control, witness.method, params);
    defer replay.deinit();
    try std.testing.expect(std.mem.eql(u8, removed.bytes, replay.bytes));
    try std.testing.expectEqual(current, try revision(actor.engine.?));
    try noEffects(actor.engine.?, producer);
    stop(actor);
    var original: witness.Witness = undefined;
    {
        var store = try openStore(actor);
        defer store.close();
        var saved = try Saved.capture(&store);
        defer saved.deinit();
        const row = try saved.record(&id);
        original = row.lifecycle_witness orelse return error.MissingCommittedWitness;
        try original.validateForRecord(allocator, row, saved.snapshot.revision);
        try std.testing.expectEqual(current, original.outcome_revision + 1);
        try std.testing.expectEqual(mutation.State.completed, row.state);
        try std.testing.expect(!row.lifecycle_witness_reserved);
        try std.testing.expectError(error.LifecycleRevisionRequired, mutation.Ledger.fromSnapshot(allocator, saved.parsed.value.mutation_authority));
    }
    try actor.restart();
    var restarted = try rpc(actor.engine.?, .control, witness.method, params);
    defer restarted.deinit();
    try std.testing.expect(std.mem.eql(u8, removed.bytes, restarted.bytes));
    try std.testing.expectEqualDeep(summary, try exported(actor.engine.?));
    try noEffects(actor.engine.?, producer);
    stop(actor);
    {
        var store = try openStore(actor);
        defer store.close();
        var saved = try Saved.capture(&store);
        defer saved.deinit();
        try std.testing.expectEqualDeep(original, (try saved.record(&id)).lifecycle_witness.?);
    }
}

test "actual authenticated snapshot startup refuses omitted witness facts and future outcome revisions before recovery publication" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const producer = try fixture.Fixture.create(io, allocator);
    defer producer.destroy();
    const actor = try fixture.ActorFixture.create(io, allocator, producer);
    defer actor.destroy();
    const source = try connect(actor.engine.?);
    defer allocator.free(source);
    const id = try operation();
    var removed = try rpc(actor.engine.?, .control, witness.method, .{ .source_id = source, .operation_id = id[0..], .expected_revision = try revision(actor.engine.?) });
    defer removed.deinit();
    _ = try removed.result();
    stop(actor);
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
                const fact = row.object.getPtr("lifecycle_witness") orelse continue;
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
        try std.testing.expectError(if (future_revision) error.LifecycleAuthorityMismatch else error.InvalidLifecycleWitness, engine.Engine.openWithKey(io, allocator, actor.state, actor.key));
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
    const summary = try exported(actor.engine.?);
    try std.testing.expectEqual(@as(u64, 1), summary.completed);
    try std.testing.expectEqual(@as(u64, 1), summary.elapsed_measured);
    try noEffects(actor.engine.?, producer);
}

test "optional measurement preparation refusal preserves completed removal and never backfills time after replay or restart" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const producer = try fixture.Fixture.create(io, allocator);
    defer producer.destroy();
    const actor = try fixture.ActorFixture.create(io, allocator, producer);
    defer actor.destroy();
    const source = try connect(actor.engine.?);
    defer allocator.free(source);
    var armed = try rpc(actor.engine.?, .control, "fixture.lifecycleMeasurementFault", .{ .mode = "preparation" });
    defer armed.deinit();
    _ = try armed.result();
    const id = try operation();
    const params = .{ .source_id = source, .operation_id = id[0..], .expected_revision = try revision(actor.engine.?) };
    var removed = try rpc(actor.engine.?, .control, witness.method, params);
    defer removed.deinit();
    try std.testing.expect(try control.boolean(try removed.result(), "disconnected", false));
    const summary = try exported(actor.engine.?);
    try std.testing.expectEqual(@as(u64, 1), summary.completed);
    try std.testing.expectEqual(@as(u64, 1), summary.elapsed_missing);
    try std.testing.expectEqual(@as(u64, 0), summary.elapsed_measured);
    const before = try revision(actor.engine.?);
    var replay = try rpc(actor.engine.?, .control, witness.method, params);
    defer replay.deinit();
    try std.testing.expect(std.mem.eql(u8, removed.bytes, replay.bytes));
    try std.testing.expectEqual(before, try revision(actor.engine.?));
    try actor.restart();
    var restarted = try rpc(actor.engine.?, .control, witness.method, params);
    defer restarted.deinit();
    try std.testing.expect(std.mem.eql(u8, removed.bytes, restarted.bytes));
    try std.testing.expectEqualDeep(summary, try exported(actor.engine.?));
    try noEffects(actor.engine.?, producer);
    stop(actor);
    var store = try openStore(actor);
    defer store.close();
    var saved = try Saved.capture(&store);
    defer saved.deinit();
    const row = try saved.record(&id);
    try std.testing.expectEqual(mutation.State.completed, row.state);
    try std.testing.expect(row.lifecycle_witness == null and !row.lifecycle_witness_reserved);
}

test "actual whole snapshot telemetry headroom refusal does not prevent security sensitive source disconnection" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const producer = try fixture.Fixture.create(io, allocator);
    defer producer.destroy();
    const actor = try fixture.ActorFixture.create(io, allocator, producer);
    defer actor.destroy();
    const source = try connect(actor.engine.?);
    defer allocator.free(source);
    var capability = try actor.engine.?.capabilityForTest("enrollment");
    defer std.crypto.secureZero(u8, &capability);
    // Real bounded metadata pressure, not a reduced fixture-only ceiling. This
    // headroom admits the original replay/result/effect promise but omits the
    // additional optional timing and legacy aggregate promises.
    var saturated = try rpc(actor.engine.?, .adapter, "fixture.snapshotSaturate", .{ .application = "enrollment", .capability = &capability, .spare_bytes = 9500 });
    defer saturated.deinit();
    _ = try saturated.result();
    const id = try operation();
    const params = .{ .source_id = source, .operation_id = id[0..], .expected_revision = try revision(actor.engine.?) };
    var removed = try rpc(actor.engine.?, .control, witness.method, params);
    defer removed.deinit();
    try std.testing.expect(try control.boolean(try removed.result(), "disconnected", false));
    const summary = try exported(actor.engine.?);
    try std.testing.expectEqual(@as(u64, 1), summary.completed);
    try std.testing.expectEqual(@as(u64, 1), summary.elapsed_missing);
    try std.testing.expectEqual(@as(u64, 0), summary.elapsed_measured);
    const before = try revision(actor.engine.?);
    var replay = try rpc(actor.engine.?, .control, witness.method, params);
    defer replay.deinit();
    try std.testing.expect(std.mem.eql(u8, removed.bytes, replay.bytes));
    try std.testing.expectEqual(before, try revision(actor.engine.?));
    try actor.restart();
    try std.testing.expectEqualDeep(summary, try exported(actor.engine.?));
    try noEffects(actor.engine.?, producer);
}

test "actual post-outcome SQLite measurement commit failure retains original success poisons custody and restart acknowledges without retry" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const producer = try fixture.Fixture.create(io, allocator);
    defer producer.destroy();
    const actor = try fixture.ActorFixture.create(io, allocator, producer);
    defer actor.destroy();
    const source = try connect(actor.engine.?);
    defer allocator.free(source);
    var armed = try rpc(actor.engine.?, .control, "fixture.lifecycleMeasurementFault", .{ .mode = "sqlite_commit" });
    defer armed.deinit();
    _ = try armed.result();
    const id = try operation();
    const params = .{ .source_id = source, .operation_id = id[0..], .expected_revision = try revision(actor.engine.?) };
    var removed = try rpc(actor.engine.?, .control, witness.method, params);
    defer removed.deinit();
    try std.testing.expect(try control.boolean(try removed.result(), "disconnected", false));
    var health = try rpc(actor.engine.?, .control, "system.health", @as(?u8, null));
    defer health.deinit();
    try std.testing.expect(!try control.boolean(try health.result(), "custody_available", true));
    try std.testing.expect(!(try exported(actor.engine.?)).authority_available);
    var blocked = try rpc(actor.engine.?, .control, witness.method, params);
    defer blocked.deinit();
    try blocked.refused("CustodyUnavailable");
    stop(actor);
    {
        var store = try openStore(actor);
        defer store.close();
        var saved = try Saved.capture(&store);
        defer saved.deinit();
        const row = try saved.record(&id);
        try std.testing.expectEqual(mutation.State.completed, row.state);
        try std.testing.expect(row.lifecycle_witness == null);
        try witness.requireTerminal(allocator, row);
    }
    try actor.restart();
    const before = try revision(actor.engine.?);
    var replay = try rpc(actor.engine.?, .control, witness.method, params);
    defer replay.deinit();
    try std.testing.expect(std.mem.eql(u8, removed.bytes, replay.bytes));
    try std.testing.expectEqual(before, try revision(actor.engine.?));
    const summary = try exported(actor.engine.?);
    try std.testing.expectEqual(@as(u64, 1), summary.completed);
    try std.testing.expectEqual(@as(u64, 1), summary.elapsed_missing);
    try std.testing.expectEqual(@as(u64, 0), summary.elapsed_measured);
    try noEffects(actor.engine.?, producer);
}
