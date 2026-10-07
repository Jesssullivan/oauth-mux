//! Real SQLite/actor crash recovery with a private, durable external effect.
//! No vault, provider, service or native account store is accessed. Child
//! processes use fresh IO/allocators and never inherit an open actor/database.
const std = @import("std");
const c = @import("c");
const engine_module = @import("engine.zig");
const storage = @import("storage.zig");
const owner_fixture = @import("native_owner_fixture.zig");
const control = @import("control.zig");

extern "c" fn waitpid(pid: c.pid_t, status: *c_int, options: c_int) c.pid_t;
extern "c" fn kill(pid: c.pid_t, signal: c_int) c_int;

const allocator = std.testing.allocator;
const io = std.testing.io;
const test_key = @as([32]u8, @splat(71));
const operation_id = "snapshot-crash-external";

const Reply = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,
    parsed: std.json.Parsed(std.json.Value),

    fn deinit(self: *Reply) void {
        self.parsed.deinit();
        self.allocator.free(self.bytes);
    }

    fn result(self: *const Reply) !std.json.Value {
        return control.get(self.parsed.value, "result") orelse error.MissingResult;
    }

    fn expectError(self: *const Reply, expected: []const u8) !void {
        if (control.get(self.parsed.value, "result") != null) return error.UnexpectedSuccess;
        const failure = control.get(self.parsed.value, "error") orelse return error.MissingFailure;
        if (!std.mem.eql(u8, expected, try control.string(failure, "message"))) return error.UnexpectedFailure;
    }
};

fn rpc(engine: *engine_module.Engine, target_allocator: std.mem.Allocator, method: []const u8, params: anytype, channel: engine_module.Channel) !Reply {
    const normalized = if (comptime @TypeOf(params) == @TypeOf(.{})) @as(?u8, null) else params;
    const payload = try std.json.Stringify.valueAlloc(target_allocator, .{ .jsonrpc = "2.0", .id = 1, .method = method, .params = normalized }, .{});
    defer target_allocator.free(payload);
    const bytes = if (channel == .adapter) blk: {
        // This suite's adapter method is the enrollment-authorized budget
        // query. Receive its actual packet before dispatching peer evidence;
        // it does not require or manufacture a Codex owner registration.
        const native = try owner_fixture.Fixture.create(engine.io, target_allocator);
        defer native.destroy();
        break :blk try native.dispatch(engine, target_allocator, payload, channel);
    } else try engine.dispatch(target_allocator, payload, channel);
    errdefer target_allocator.free(bytes);
    return .{ .allocator = target_allocator, .bytes = bytes, .parsed = try std.json.parseFromSlice(std.json.Value, target_allocator, bytes, .{}) };
}

fn revision(engine: *engine_module.Engine, target_allocator: std.mem.Allocator) !u64 {
    var reply = try rpc(engine, target_allocator, "system.health", .{}, .control);
    defer reply.deinit();
    const value = control.get(try reply.result(), "revision") orelse return error.MissingRevision;
    if (value != .integer or value.integer < 0) return error.InvalidRevision;
    return @intCast(value.integer);
}

fn unsignedField(value: std.json.Value, name: []const u8) !usize {
    const number = control.get(value, name) orelse return error.MissingBudgetField;
    if (number != .integer or number.integer < 0) return error.InvalidBudgetField;
    return @intCast(number.integer);
}

fn expectBudget(engine: *engine_module.Engine, target_allocator: std.mem.Allocator, credit_count: usize, credit_bytes: ?usize) !void {
    const capability = try engine.capabilityForTest("enrollment");
    var reply = try rpc(engine, target_allocator, "fixture.snapshotBudget", .{ .application = "enrollment", .capability = capability[0..] }, .adapter);
    defer reply.deinit();
    const value = try reply.result();
    if (try unsignedField(value, "credit_count") != credit_count) return error.UnexpectedCreditCount;
    const bytes = try unsignedField(value, "credits_bytes");
    if (credit_bytes) |expected| if (bytes != expected) return error.UnexpectedCreditBytes;
    if (credit_count == 0 and bytes != 0) return error.UnexpectedCreditBytes;
    const exact = try unsignedField(value, "exact_snapshot_bytes");
    const reserved = try unsignedField(value, "reserved_bytes");
    if (exact > reserved or reserved > storage.maximum_snapshot_bytes) return error.InvalidBudgetEnvelope;
    if (try unsignedField(value, "remaining_bytes") != storage.maximum_snapshot_bytes - reserved) return error.InvalidBudgetEnvelope;
}

fn waitForChild(pid: c.pid_t) !void {
    const started = std.Io.Clock.awake.now(io);
    var status: c_int = undefined;
    while (true) {
        const observed = waitpid(pid, &status, 1); // POSIX WNOHANG on Linux/macOS.
        if (observed == pid) {
            if (status != 0) return error.FixtureChildFailed;
            return;
        }
        if (observed < 0 and std.c.errno(observed) != .INTR) return error.ChildWaitFailed;
        if (started.durationTo(std.Io.Clock.awake.now(io)).toMilliseconds() >= 60_000) {
            _ = kill(pid, 9); // Only this test's child; POSIX SIGKILL.
            while (waitpid(pid, &status, 0) < 0) {
                if (std.c.errno(-1) != .INTR) break;
            }
            return error.FixtureChildDeadline;
        }
        try io.sleep(.fromMilliseconds(10), .awake);
    }
}

fn childFailure(failure: anyerror, status: c_int) noreturn {
    // Error-set names only, via unbuffered writes: no inherited test-runner
    // diagnostic mutex, private paths, effect contents or credential values.
    const prefix: []const u8 = "snapshot restart child rejected: ";
    const name = @errorName(failure);
    _ = c.write(2, prefix.ptr, prefix.len);
    _ = c.write(2, name.ptr, name.len);
    _ = c.write(2, "\n", 1);
    c._exit(status);
}

fn crashAfterEffect(state_path: []const u8) !void {
    const child_allocator = std.heap.page_allocator;
    var threaded: std.Io.Threaded = .init(child_allocator, .{ .async_limit = .limited(2), .concurrent_limit = .limited(8) });
    defer threaded.deinit();
    const engine = try engine_module.Engine.openWithKey(threaded.io(), child_allocator, state_path, test_key);
    defer engine.deinit();
    var reply = try rpc(engine, child_allocator, "fixture.externalEffect", .{ .operation_id = operation_id, .expected_revision = try revision(engine, child_allocator), .crash_after_effect = true }, .control);
    defer reply.deinit();
    // The actor must exit after the durable effect, before completing its
    // mutation. Returning normally would not exercise abrupt SQLite recovery.
    return error.CrashFixtureReturned;
}

fn duplicateProbe(state_path: []const u8, original_revision: u64, credit_bytes: usize) !void {
    const child_allocator = std.heap.page_allocator;
    var threaded: std.Io.Threaded = .init(child_allocator, .{ .async_limit = .limited(2), .concurrent_limit = .limited(8) });
    defer threaded.deinit();
    const engine = try engine_module.Engine.openWithKey(threaded.io(), child_allocator, state_path, test_key);
    defer engine.deinit();
    try expectBudget(engine, child_allocator, 1, credit_bytes);
    var status = try rpc(engine, child_allocator, "operation.status", .{ .operation_id = operation_id }, .control);
    defer status.deinit();
    if (!std.mem.eql(u8, "indeterminate", try control.string(try status.result(), "status"))) return error.RecoveryDidNotFenceEffect;
    var duplicate = try rpc(engine, child_allocator, "fixture.externalEffect", .{ .operation_id = operation_id, .expected_revision = original_revision, .crash_after_effect = true }, .control);
    defer duplicate.deinit();
    try duplicate.expectError("OperationIndeterminate");
    try expectBudget(engine, child_allocator, 1, credit_bytes);
    const marker = try std.fmt.allocPrint(child_allocator, "{s}/verified-indeterminate", .{state_path});
    defer child_allocator.free(marker);
    try std.Io.Dir.cwd().writeFile(threaded.io(), .{ .sub_path = marker, .data = "verified" });
}

fn persistedOperationRevision(store: *storage.Store, expected_state: []const u8) !u64 {
    var saved = try store.readSnapshot();
    defer saved.deinit();
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, saved.json, .{});
    defer parsed.deinit();
    const authority = control.get(parsed.value, "mutation_authority") orelse return error.MissingMutationAuthority;
    const records = control.get(authority, "records") orelse return error.MissingMutationRecords;
    if (records != .array or records.array.items.len != 1) return error.UnexpectedMutationCount;
    const record = records.array.items[0];
    if (!std.mem.eql(u8, expected_state, try control.string(record, "state"))) return error.UnexpectedDurableMutationState;
    const held_revision = control.get(record, "expected_revision") orelse return error.MissingRevision;
    if (held_revision != .integer or held_revision.integer < 0) return error.InvalidRevision;
    return @intCast(held_revision.integer);
}

const DurableCredit = struct {
    key_json: []u8,
    bytes: usize,

    fn deinit(self: *DurableCredit) void {
        allocator.free(self.key_json);
    }
};

fn persistedCredit(store: *storage.Store, expected_state: []const u8) !DurableCredit {
    var saved = try store.readSnapshot();
    defer saved.deinit();
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, saved.json, .{});
    defer parsed.deinit();
    const admission = control.get(parsed.value, "snapshot_admission") orelse return error.MissingSnapshotAdmission;
    const credits = control.get(admission, "credits") orelse return error.MissingSnapshotCredits;
    if (credits != .array or credits.array.items.len != 1) return error.UnexpectedCreditCount;
    const credit = credits.array.items[0];
    if (!std.mem.eql(u8, expected_state, try control.string(credit, "state"))) return error.UnexpectedDurableCreditState;
    const key = control.get(credit, "key") orelse return error.MissingSnapshotCreditKey;
    if (!std.mem.eql(u8, "mutation", try control.string(key, "kind"))) return error.UnexpectedSnapshotCreditKind;
    const bytes = try unsignedField(credit, "bytes");
    if (bytes == 0) return error.UnexpectedCreditBytes;
    return .{ .key_json = try std.json.Stringify.valueAlloc(allocator, key, .{}), .bytes = bytes };
}

test "durable external effect crash survives SQLite restart without duplicate execution" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    if (std.c.fchmodat(directory.dir.handle, ".", 0o700, 0) != 0) return error.FixtureModeFailed;
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const database = try std.fmt.allocPrintSentinel(allocator, "{s}/state.sqlite", .{path}, 0);
    defer allocator.free(database);

    const first = c.fork();
    if (first < 0) return error.FixtureForkFailed;
    if (first == 0) {
        crashAfterEffect(path) catch |failure| childFailure(failure, 91);
        c._exit(92);
    }
    try waitForChild(first);
    const effect = try directory.dir.readFileAlloc(io, "fixture-effect.log", allocator, .limited(4096));
    defer allocator.free(effect);
    try std.testing.expect(effect.len > 0);
    var retained_credit: DurableCredit = undefined;
    const original_revision = blk: {
        var store = try storage.Store.open(io, allocator, database, test_key);
        defer store.close();
        const held_revision = try persistedOperationRevision(&store, "started");
        retained_credit = try persistedCredit(&store, "reserved");
        break :blk held_revision;
    };
    defer retained_credit.deinit();

    // Probe in another child: if dedup regresses, the crash fixture could exit
    // zero again. The parent additionally requires the post-refusal marker and
    // unchanged effect bytes, so that false success cannot satisfy this test.
    const second = c.fork();
    if (second < 0) return error.FixtureForkFailed;
    if (second == 0) {
        duplicateProbe(path, original_revision, retained_credit.bytes) catch |failure| childFailure(failure, 93);
        c._exit(0);
    }
    try waitForChild(second);
    const marker = try directory.dir.readFileAlloc(io, "verified-indeterminate", allocator, .limited(32));
    defer allocator.free(marker);
    try std.testing.expectEqualStrings("verified", marker);
    const after = try directory.dir.readFileAlloc(io, "fixture-effect.log", allocator, .limited(4096));
    defer allocator.free(after);
    try std.testing.expectEqualSlices(u8, effect, after);
    var recovered = try storage.Store.open(io, allocator, database, test_key);
    defer recovered.close();
    try std.testing.expectEqual(original_revision, try persistedOperationRevision(&recovered, "indeterminate"));
    var recovered_credit = try persistedCredit(&recovered, "indeterminate");
    defer recovered_credit.deinit();
    try std.testing.expectEqual(retained_credit.bytes, recovered_credit.bytes);
    try std.testing.expectEqualStrings(retained_credit.key_json, recovered_credit.key_json);
}

test "completed external effect acknowledgment replays from SQLite without another effect" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    if (std.c.fchmodat(directory.dir.handle, ".", 0o700, 0) != 0) return error.FixtureModeFailed;
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const database = try std.fmt.allocPrintSentinel(allocator, "{s}/state.sqlite", .{path}, 0);
    defer allocator.free(database);
    var expected_revision: u64 = 0;
    const acknowledgment = blk: {
        const engine = try engine_module.Engine.openWithKey(io, allocator, path, test_key);
        defer engine.deinit();
        expected_revision = try revision(engine, allocator);
        var reply = try rpc(engine, allocator, "fixture.externalEffect", .{ .operation_id = operation_id, .expected_revision = expected_revision, .crash_after_effect = false }, .control);
        defer reply.deinit();
        try expectBudget(engine, allocator, 0, 0);
        break :blk try std.json.Stringify.valueAlloc(allocator, try reply.result(), .{});
    };
    defer allocator.free(acknowledgment);
    const effect = try directory.dir.readFileAlloc(io, "fixture-effect.log", allocator, .limited(4096));
    defer allocator.free(effect);
    try std.testing.expect(effect.len > 0);
    {
        var store = try storage.Store.open(io, allocator, database, test_key);
        defer store.close();
        try std.testing.expectEqual(expected_revision, try persistedOperationRevision(&store, "completed"));
    }
    {
        const engine = try engine_module.Engine.openWithKey(io, allocator, path, test_key);
        defer engine.deinit();
        try expectBudget(engine, allocator, 0, 0);
        const before_revision = try revision(engine, allocator);
        var replay = try rpc(engine, allocator, "fixture.externalEffect", .{ .operation_id = operation_id, .expected_revision = expected_revision, .crash_after_effect = false }, .control);
        defer replay.deinit();
        const encoded = try std.json.Stringify.valueAlloc(allocator, try replay.result(), .{});
        defer allocator.free(encoded);
        try std.testing.expectEqualStrings(acknowledgment, encoded);
        try std.testing.expectEqual(before_revision, try revision(engine, allocator));
        try expectBudget(engine, allocator, 0, 0);
    }
    const after = try directory.dir.readFileAlloc(io, "fixture-effect.log", allocator, .limited(4096));
    defer allocator.free(after);
    try std.testing.expectEqualSlices(u8, effect, after);
}
