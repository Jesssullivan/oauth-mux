//! R-N13: actual actor startup rejects unsafe stored admission before recovery.
//! Fixtures use private SQLite, generated synthetic credentials and test keys.
//! No provider, installed service or OS vault is contacted.
const std = @import("std");
const c = @import("c");
const engine_module = @import("engine.zig");
const control = @import("control.zig");
const domain = @import("domain.zig");
const envelope = @import("envelope.zig");
const storage = @import("storage.zig");
const admission = @import("snapshot_admission.zig");

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
        return control.get(self.parsed.value, "result") orelse error.FixtureRpcFailed;
    }
};

const Disk = struct {
    database: []u8,
    authority: []u8,

    fn capture(fixture: *const Fixture) !Disk {
        const database = try fixture.directory.dir.readFileAlloc(io, "state.sqlite", allocator, .limited(64 * 1024 * 1024));
        errdefer allocator.free(database);
        return .{ .database = database, .authority = try fixture.directory.dir.readFileAlloc(io, "state.sqlite.authority", allocator, .limited(4096)) };
    }

    fn deinit(self: *Disk) void {
        allocator.free(self.database);
        allocator.free(self.authority);
    }

    fn expectUnchanged(self: *const Disk, fixture: *const Fixture) !void {
        var after = try capture(fixture);
        defer after.deinit();
        // Boolean comparisons avoid dumping ciphertext/metadata on a failure.
        try std.testing.expect(std.mem.eql(u8, self.database, after.database));
        try std.testing.expect(std.mem.eql(u8, self.authority, after.authority));
    }
};

const Fixture = struct {
    directory: std.testing.TmpDir,
    // R-N13: retain the sentinel allocation extent returned by realPathFileAlloc.
    path: [:0]u8,
    key: envelope.Key,
    engine: ?*engine_module.Engine,
    source: []u8 = &.{},
    account: []u8 = &.{},
    grant: []u8 = &.{},
    forgotten: []u8 = &.{},
    work_id: ?[]u8 = null,
    request_number: u64 = 1,

    fn init(hold_import: bool) !Fixture {
        var directory = std.testing.tmpDir(.{});
        var owned_by_fixture = false;
        errdefer if (!owned_by_fixture) directory.cleanup();
        if (std.c.fchmodat(directory.dir.handle, ".", 0o700, 0) != 0) return error.FixturePermissionFailed;
        const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
        errdefer if (!owned_by_fixture) allocator.free(path);
        var key: envelope.Key = undefined;
        try io.randomSecure(&key);
        defer std.crypto.secureZero(u8, &key);
        var fixture: Fixture = .{ .directory = directory, .path = path, .key = key, .engine = try engine_module.Engine.openWithKey(io, allocator, path, key) };
        owned_by_fixture = true;
        errdefer fixture.deinit();
        var connected = try fixture.rpc(.control, "source.connect", .{ .kind = "explicit", .provider = "github", .label = "synthetic migration source" });
        defer connected.deinit();
        fixture.source = try allocator.dupe(u8, try control.string(try connected.result(), "source_id"));
        const retained = try fixture.enroll();
        fixture.account = retained.account;
        fixture.grant = retained.grant;
        const removed = try fixture.enroll();
        fixture.forgotten = removed.account;
        allocator.free(removed.grant);
        var forgotten = try fixture.rpc(.control, "account.forget", .{ .account_id = fixture.forgotten });
        defer forgotten.deinit();
        _ = try forgotten.result();
        if (hold_import) {
            var random: [32]u8 = undefined;
            try io.randomSecure(&random);
            defer std.crypto.secureZero(u8, &random);
            var token = std.fmt.bytesToHex(random, .lower);
            defer std.crypto.secureZero(u8, &token);
            var capability = try fixture.engine.?.capabilityForTest("enrollment");
            defer std.crypto.secureZero(u8, &capability);
            var held = try fixture.rpc(.adapter, "fixture.importStart", .{ .application = "enrollment", .capability = capability[0..], .source_id = fixture.source, .provider = "github", .access_token = token[0..] });
            defer held.deinit();
            fixture.work_id = try allocator.dupe(u8, try control.string(try held.result(), "operation_id"));
        }
        fixture.close();
        return fixture;
    }

    fn close(self: *Fixture) void {
        if (self.engine) |engine| engine.deinit();
        self.engine = null;
    }

    fn deinit(self: *Fixture) void {
        self.close();
        if (self.work_id) |value| allocator.free(value);
        for ([_][]u8{ self.source, self.account, self.grant, self.forgotten }) |value| if (value.len != 0) allocator.free(value);
        allocator.free(self.path);
        self.directory.cleanup();
        std.crypto.secureZero(u8, &self.key);
    }

    fn rpc(self: *Fixture, channel: engine_module.Channel, method: []const u8, params: anytype) !Reply {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const scratch = arena.allocator();
        // R-N13: Zig's empty tuple serializes as an array; control accepts
        // omitted/null or object params, including for revision reads.
        var value = try jsonValue(scratch, .{ .jsonrpc = "2.0", .id = self.request_number, .method = method, .params = if (comptime @TypeOf(params) == @TypeOf(.{})) @as(?u8, null) else params });
        defer control.wipeJson(value);
        self.request_number += 1;
        if (channel == .control and engine_module.mutationKind(method) != null) {
            var health = try self.rpc(.control, "system.health", .{});
            defer health.deinit();
            const revision = control.get(try health.result(), "revision") orelse return error.MissingFixtureRevision;
            const object = &value.object.getPtr("params").?.object;
            // R-N13: wipeJson recursively scrubs keys as well as values;
            // ObjectMap borrows them, so inserted strings must be arena-owned.
            try object.put(scratch, try scratch.dupe(u8, "expected_revision"), revision);
            const operation = try std.fmt.allocPrint(scratch, "synthetic-migration-work-{d}", .{self.request_number});
            try object.put(scratch, try scratch.dupe(u8, "operation_id"), .{ .string = try scratch.dupe(u8, operation) });
        }
        const request = try std.json.Stringify.valueAlloc(allocator, value, .{});
        defer {
            std.crypto.secureZero(u8, request);
            allocator.free(request);
        }
        const bytes = try self.engine.?.dispatch(allocator, request, channel);
        errdefer allocator.free(bytes);
        return .{ .bytes = bytes, .parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .allocate = .alloc_always }) };
    }

    fn enroll(self: *Fixture) !struct { account: []u8, grant: []u8 } {
        var random: [32]u8 = undefined;
        try io.randomSecure(&random);
        defer std.crypto.secureZero(u8, &random);
        var token = std.fmt.bytesToHex(random, .lower);
        defer std.crypto.secureZero(u8, &token);
        try io.randomSecure(&random);
        const subject = try std.fmt.allocPrint(allocator, "synthetic-{s}", .{std.fmt.bytesToHex(random, .lower)});
        defer allocator.free(subject);
        var capability = try self.engine.?.capabilityForTest("enrollment");
        defer std.crypto.secureZero(u8, &capability);
        var reply = try self.rpc(.adapter, "fixture.enroll", .{ .application = "enrollment", .capability = capability[0..], .source_id = self.source, .provider = "github", .audience = "https://github.com", .subject = subject, .access_token = token[0..], .label = "synthetic migration account" });
        defer reply.deinit();
        const result = try reply.result();
        const account = try allocator.dupe(u8, try control.string(result, "account_id"));
        errdefer allocator.free(account);
        return .{ .account = account, .grant = try allocator.dupe(u8, try control.string(result, "grant_id")) };
    }

    fn openStore(self: *const Fixture) !storage.Store {
        try std.testing.expect(self.engine == null);
        const path = try std.fmt.allocPrintSentinel(allocator, "{s}/state.sqlite", .{self.path}, 0);
        defer allocator.free(path);
        const root = try storage.Store.readRootId(allocator, path);
        defer allocator.free(root);
        return storage.Store.openRoot(io, allocator, path, root, self.key);
    }

    fn original(self: *const Fixture) !storage.Snapshot {
        var store = try self.openStore();
        defer store.close();
        try std.testing.expect(try store.isTombstoned(self.forgotten));
        try std.testing.expect((try store.readGrantStatus(self.account, self.grant)) != null);
        return store.readSnapshot();
    }

    fn write(self: *const Fixture, value: std.json.Value) !void {
        const encoded = try std.json.Stringify.valueAlloc(allocator, value, .{});
        defer allocator.free(encoded);
        var store = try self.openStore();
        defer store.close();
        var before = try store.readSnapshot();
        defer before.deinit();
        _ = try store.commit(before.revision, encoded, &.{});
    }

    fn reject(self: *const Fixture, expected: anyerror) !void {
        var before = try Disk.capture(self);
        defer before.deinit();
        // Repeating startup cannot consume a promise, repair metadata, create
        // a replay key, quarantine a lineage or reserve a recovery checkpoint.
        for (0..2) |_| {
            try std.testing.expectError(expected, engine_module.Engine.openWithKey(io, allocator, self.path, self.key));
            try before.expectUnchanged(self);
        }
    }
};

fn jsonValue(scratch: std.mem.Allocator, value: anytype) !std.json.Value {
    const encoded = try std.json.Stringify.valueAlloc(scratch, value, .{});
    // Every parsed string is copied below; discard the temporary request copy
    // with the same scrub discipline as the eventual structured request.
    defer std.crypto.secureZero(u8, encoded);
    return std.json.parseFromSliceLeaky(std.json.Value, scratch, encoded, .{ .allocate = .alloc_always });
}

fn decode(scratch: std.mem.Allocator, json: []const u8) !std.json.Value {
    return std.json.parseFromSliceLeaky(std.json.Value, scratch, json, .{ .allocate = .alloc_always });
}

fn legacy(value: *std.json.Value, scratch: std.mem.Allocator) !void {
    try value.object.put(scratch, "schema_version", .{ .integer = 1 });
    try value.object.put(scratch, "snapshot_admission", try jsonValue(scratch, admission.Snapshot{}));
    _ = value.object.swapRemove("outcome_intents");
    // A legacy record has no reviewed typed maintenance promise to inherit.
    _ = value.object.swapRemove("maintenance_growth_bytes");
}

test "R-N13 overcommitted quiescent legacy actor snapshot refuses without custody migration" {
    var fixture = try Fixture.init(false);
    defer fixture.deinit();
    var original = try fixture.original();
    defer original.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();
    var value = try decode(scratch, original.json);
    const maintenance = value.object.get("maintenance_growth_bytes") orelse return error.MissingFixtureMaintenance;
    if (maintenance != .integer or maintenance.integer <= 0) return error.InvalidFixtureMaintenance;
    const old_state_json = try std.json.Stringify.valueAlloc(scratch, value.object.get("state").?, .{});
    const saved = try std.json.parseFromSliceLeaky(domain.Snapshot, scratch, old_state_json, .{});
    var state = try domain.State.fromSnapshot(allocator, saved);
    defer state.deinit();
    const escaped: [domain.max_text_bytes]u8 = @splat(1);
    const identity: domain.Identity = .{ .provider = "github", .issuer = &escaped, .subject = &escaped, .tenant = &escaped };
    const candidate: [64]u8 = @splat('a');
    const row: domain.QuarantinedImport = .{ .source_id = fixture.source, .candidate_id = &candidate, .identity = identity, .reason = .unverified_identity };
    const stride = (try admission.countJson(row, storage.maximum_snapshot_bytes)) + 1;
    try std.testing.expect(@as(usize, @intCast(maintenance.integer)) > stride * 2);
    const target = storage.maximum_snapshot_bytes - @as(usize, @intCast(maintenance.integer)) / 2;
    var count = try admission.countJson(value, storage.maximum_snapshot_bytes);
    var index: usize = 0;
    while (count + stride < target) : (index += 1) {
        var id: [64]u8 = @splat('a');
        std.mem.writeInt(u64, id[0..8], @intCast(index), .little);
        // Domain IDs forbid NUL; an opaque hex candidate is constant-width.
        const hex = std.fmt.bytesToHex(id[0..32].*, .lower);
        _ = try state.enroll(.{ .account_id = &hex, .source_id = fixture.source, .identity = identity }, std.Io.Clock.real.now(io).toSeconds());
        count += stride;
    }
    try std.testing.expect(index > 0 and index < domain.max_records);
    try value.object.put(scratch, "state", try jsonValue(scratch, state.snapshot()));
    try legacy(&value, scratch);
    try std.testing.expect((try admission.countJson(value, storage.maximum_snapshot_bytes)) < storage.maximum_snapshot_bytes);
    try fixture.write(value);
    try fixture.reject(error.SnapshotAdmissionMigrationRequired);
}

fn readonlyText(fixture: *const Fixture, sql: [:0]const u8, id: []const u8) ![]u8 {
    const path = try std.fmt.allocPrintSentinel(allocator, "{s}/state.sqlite", .{fixture.path}, 0);
    defer allocator.free(path);
    var database: ?*c.sqlite3 = null;
    if (c.sqlite3_open_v2(path.ptr, &database, c.SQLITE_OPEN_READONLY | c.SQLITE_OPEN_FULLMUTEX | c.SQLITE_OPEN_NOFOLLOW, null) != c.SQLITE_OK) {
        if (database) |db| _ = c.sqlite3_close(db);
        return error.FixtureSqlFailed;
    }
    defer _ = c.sqlite3_close(database.?);
    var statement: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(database.?, sql.ptr, -1, &statement, null) != c.SQLITE_OK) return error.FixtureSqlFailed;
    defer _ = c.sqlite3_finalize(statement.?);
    if (c.sqlite3_bind_text(statement.?, 1, id.ptr, @intCast(id.len), null) != c.SQLITE_OK or c.sqlite3_step(statement.?) != c.SQLITE_ROW or c.sqlite3_column_type(statement.?, 0) != c.SQLITE_TEXT) return error.FixtureSqlFailed;
    const length = c.sqlite3_column_bytes(statement.?, 0);
    if (length <= 0 or length > 4096) return error.InvalidFixtureSqlText;
    const pointer: [*]const u8 = @ptrCast(c.sqlite3_column_text(statement.?, 0) orelse return error.InvalidFixtureSqlText);
    return allocator.dupe(u8, pointer[0..@intCast(length)]);
}

test "R-N13 unresolved legacy startup rejects before actual pending rotation recovery" {
    var fixture = try Fixture.init(true);
    defer fixture.deinit();
    var original = try fixture.original();
    defer original.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const scratch = arena.allocator();
    var value = try decode(scratch, original.json);
    try legacy(&value, scratch);
    const grants = &value.object.getPtr("state").?.object.getPtr("grants").?.array;
    try std.testing.expectEqual(@as(usize, 1), grants.items.len);
    try grants.items[0].object.put(scratch, "ownership", .{ .string = "omux" });
    try grants.items[0].object.put(scratch, "generation", .{ .integer = 2 });
    try grants.items[0].object.put(scratch, "status", .{ .string = "refreshing" });
    const encoded = try std.json.Stringify.valueAlloc(scratch, value, .{});
    const operation = "synthetic-rotation-before-actor-admission";
    {
        var store = try fixture.openStore();
        defer store.close();
        var snapshot = try store.readSnapshot();
        defer snapshot.deinit();
        var random: [32]u8 = undefined;
        try io.randomSecure(&random);
        defer std.crypto.secureZero(u8, &random);
        var token = std.fmt.bytesToHex(random, .lower);
        defer std.crypto.secureZero(u8, &token);
        const context: envelope.Context = .{ .key_id = store.key_id, .account_id = fixture.account, .grant_id = fixture.grant, .generation = 2, .purpose = "request", .scope = "https://github.com" };
        _ = try store.commit(snapshot.revision, encoded, &.{.{ .put = .{ .context = context, .plaintext = &token, .renewal_owner = .omux } }});
        const begun = try store.beginRotation(context, operation);
        try std.testing.expect(begun.may_issue and begun.status == .started);
        try std.testing.expect(try store.isTombstoned(fixture.forgotten));
        const raw = try fixture.directory.dir.readFileAlloc(io, "state.sqlite-wal", allocator, .limited(64 * 1024 * 1024));
        defer allocator.free(raw);
        try std.testing.expect(std.mem.indexOf(u8, raw, &token) == null);
    }
    try fixture.reject(error.SnapshotAdmissionMigrationRequired);
    const phase = try readonlyText(&fixture, "SELECT state FROM operations WHERE operation_id=?1;", operation);
    defer allocator.free(phase);
    try std.testing.expectEqualStrings("started", phase);
    const grant_state = try readonlyText(&fixture, "SELECT state FROM grants WHERE grant_id=?1;", fixture.grant);
    defer allocator.free(grant_state);
    try std.testing.expectEqualStrings("refreshing", grant_state);
}

fn pendingRotation(fixture: *const Fixture, json: []const u8, operation: []const u8) !void {
    var store = try fixture.openStore();
    defer store.close();
    var snapshot = try store.readSnapshot();
    defer snapshot.deinit();
    var random: [32]u8 = undefined;
    try io.randomSecure(&random);
    defer std.crypto.secureZero(u8, &random);
    var token = std.fmt.bytesToHex(random, .lower);
    defer std.crypto.secureZero(u8, &token);
    const context: envelope.Context = .{ .key_id = store.key_id, .account_id = fixture.account, .grant_id = fixture.grant, .generation = 2, .purpose = "request", .scope = "https://github.com" };
    _ = try store.commit(snapshot.revision, json, &.{.{ .put = .{ .context = context, .plaintext = &token, .renewal_owner = .omux } }});
    const begun = try store.beginRotation(context, operation);
    try std.testing.expect(begun.may_issue and begun.status == .started);
    try std.testing.expect(try store.isTombstoned(fixture.forgotten));
    const raw = try fixture.directory.dir.readFileAlloc(io, "state.sqlite-wal", allocator, .limited(64 * 1024 * 1024));
    defer allocator.free(raw);
    try std.testing.expect(std.mem.indexOf(u8, raw, &token) == null);
}

test "R-N13 legacy empty or apparently quiescent metadata cannot hide durable SQL rotation" {
    // A real newly initialized Store can survive the actor's first-commit gap.
    // Revision zero plus empty history is sufficient; existing custody is not.
    {
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        if (std.c.fchmodat(directory.dir.handle, ".", 0o700, 0) != 0) return error.FixturePermissionFailed;
        const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
        defer allocator.free(path);
        const database = try std.fmt.allocPrintSentinel(allocator, "{s}/state.sqlite", .{path}, 0);
        defer allocator.free(database);
        var key: envelope.Key = undefined;
        try io.randomSecure(&key);
        defer std.crypto.secureZero(u8, &key);
        {
            var store = try storage.Store.openRoot(io, allocator, database, envelope.default_key_id, key);
            defer store.close();
            var snapshot = try store.readSnapshot();
            defer snapshot.deinit();
            try std.testing.expectEqual(@as(u64, 0), snapshot.revision);
            try std.testing.expectEqualStrings("{}", snapshot.json);
        }
        const fresh = try engine_module.Engine.openWithKey(io, allocator, path, key);
        fresh.deinit();
    }

    for ([_]bool{ true, false }) |empty_metadata| {
        var fixture = try Fixture.init(false);
        defer fixture.deinit();
        var original = try fixture.original();
        defer original.deinit();
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const scratch = arena.allocator();
        var value = try decode(scratch, original.json);
        try legacy(&value, scratch);
        const grants = &value.object.getPtr("state").?.object.getPtr("grants").?.array;
        try std.testing.expectEqual(@as(usize, 1), grants.items.len);
        try grants.items[0].object.put(scratch, "ownership", .{ .string = "omux" });
        try grants.items[0].object.put(scratch, "generation", .{ .integer = 2 });
        // No running actor job, lease or external mutation exists in this v1
        // metadata. The SQL operation still owns a real unresolved lineage.
        const json = if (empty_metadata) "{}" else try std.json.Stringify.valueAlloc(scratch, value, .{});
        const operation = "synthetic-hidden-sql-rotation";
        try pendingRotation(&fixture, json, operation);
        try fixture.reject(error.SnapshotAdmissionMigrationRequired);
        const phase = try readonlyText(&fixture, "SELECT state FROM operations WHERE operation_id=?1;", operation);
        defer allocator.free(phase);
        try std.testing.expectEqualStrings("started", phase);
        const grant_state = try readonlyText(&fixture, "SELECT state FROM grants WHERE grant_id=?1;", fixture.grant);
        defer allocator.free(grant_state);
        try std.testing.expectEqualStrings("refreshing", grant_state);
    }
}

const Corruption = enum { orphan_credit, undersized_credit, undersized_counts, mismatched_generation, mismatched_owner, missing_intent };

test "R-N13 v2 credits must belong to exact adequately reserved actor outcome intents" {
    var fixture = try Fixture.init(true);
    defer fixture.deinit();
    var original = try fixture.original();
    defer original.deinit();
    for (std.enums.values(Corruption)) |corruption| {
        var arena = std.heap.ArenaAllocator.init(allocator);
        defer arena.deinit();
        const scratch = arena.allocator();
        var value = try decode(scratch, original.json);
        const credits = &value.object.getPtr("snapshot_admission").?.object.getPtr("credits").?.array;
        const intents = &value.object.getPtr("outcome_intents").?.array;
        try std.testing.expectEqual(@as(usize, 1), credits.items.len);
        try std.testing.expectEqual(@as(usize, 1), intents.items.len);
        switch (corruption) {
            .orphan_credit => try credits.append(try jsonValue(scratch, admission.Credit{ .key = .{ .kind = .request, .id = @splat(71), .generation = 7 }, .bytes = 1 })),
            .undersized_credit => {
                // Internal equality remains valid; the accepted provider plan
                // itself must establish a larger minimum before recovery.
                try credits.items[0].object.put(scratch, "bytes", .{ .integer = 1 });
                try intents.items[0].object.put(scratch, "plan_bytes", .{ .integer = 1 });
            },
            .undersized_counts => {
                try credits.items[0].object.put(scratch, "counts", try jsonValue(scratch, admission.Counts{}));
                try intents.items[0].object.put(scratch, "plan_counts", try jsonValue(scratch, admission.Counts{}));
            },
            .mismatched_generation => credits.items[0].object.getPtr("key").?.object.getPtr("generation").?.integer += 1,
            .mismatched_owner => try intents.items[0].object.put(scratch, "owner_id", .{ .string = "synthetic-unrelated-work" }),
            .missing_intent => intents.clearRetainingCapacity(),
        }
        try fixture.write(value);
        try fixture.reject(error.InvalidSnapshotCreditAuthority);
    }
    // The actual original owner/plan remains sufficient. Restoring its test
    // metadata explicitly permits ordinary startup without inventing a promise.
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    try fixture.write(try decode(arena.allocator(), original.json));
    const engine = try engine_module.Engine.openWithKey(io, allocator, fixture.path, fixture.key);
    defer engine.deinit();
}
