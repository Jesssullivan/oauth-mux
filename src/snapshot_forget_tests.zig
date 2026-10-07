//! R-N13: scoped snapshot-forget proof owned by the journey workstream.
//! Actual actor mutations and encrypted SQLite custody with generated inputs.
//! Offline fixture seeding occurs only after the actor closes its writer.
//! No provider, personal vault, native application or live-continuity proof.
const std = @import("std");
const c = @import("c");
const Engine = @import("engine.zig").Engine;
const engine_module = @import("engine.zig");
const control = @import("control.zig");
const domain = @import("domain.zig");
const storage = @import("storage.zig");
const envelope = @import("envelope.zig");
const snapshot_admission = @import("snapshot_admission.zig");
const mutation_authority = @import("mutation_authority.zig");

const allocator = std.testing.allocator;
const io = std.testing.io;
const audience = "https://chatgpt.com";
const old_subject_prefix = "synthetic-forgotten-";

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
        return control.get(self.parsed.value, "result") orelse error.FixtureRpcRejected;
    }

    fn expectError(self: *const Reply, name: []const u8) !void {
        try std.testing.expect(control.get(self.parsed.value, "result") == null);
        const failure = control.get(self.parsed.value, "error") orelse return error.MissingRpcError;
        try std.testing.expectEqualStrings(name, try control.string(failure, "message"));
    }
};

fn generatedValue() ![]u8 {
    var random: [32]u8 = undefined;
    try io.randomSecure(&random);
    defer std.crypto.secureZero(u8, &random);
    const hex = std.fmt.bytesToHex(random, .lower);
    return allocator.dupe(u8, &hex);
}

fn rpc(engine: *Engine, channel: engine_module.Channel, method: []const u8, params: anytype) !Reply {
    const normalized = if (comptime @TypeOf(params) == @TypeOf(.{})) @as(?u8, null) else params;
    const initial = try std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = 1, .method = method, .params = normalized }, .{});
    defer {
        std.crypto.secureZero(u8, initial);
        allocator.free(initial);
    }
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, initial, .{ .allocate = .alloc_always });
    defer {
        control.wipeJson(parsed.value);
        parsed.deinit();
    }
    if (channel == .control and engine_module.mutationKind(method) != null) {
        const target = parsed.value.object.getPtr("params").?;
        if (target.* == .null) target.* = .{ .object = .empty };
        if (!target.object.contains("operation_id")) {
            const identifier = try generatedValue();
            defer allocator.free(identifier);
            try target.object.put(parsed.arena.allocator(), try parsed.arena.allocator().dupe(u8, "operation_id"), .{ .string = try parsed.arena.allocator().dupe(u8, identifier) });
        }
        if (!target.object.contains("expected_revision")) {
            var snapshot = try rpc(engine, .control, "state.snapshot", .{});
            defer snapshot.deinit();
            try target.object.put(parsed.arena.allocator(), try parsed.arena.allocator().dupe(u8, "expected_revision"), .{ .integer = @intCast(try revision(&snapshot)) });
        }
    }
    const request = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
    defer {
        std.crypto.secureZero(u8, request);
        allocator.free(request);
    }
    const bytes = try engine.dispatch(allocator, request, channel);
    errdefer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    return .{ .bytes = bytes, .parsed = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .allocate = .alloc_always }) };
}

fn revision(reply: *const Reply) !u64 {
    const value = control.get(try reply.result(), "revision") orelse return error.InvalidRevision;
    if (value != .integer or value.integer < 0) return error.InvalidRevision;
    return @intCast(value.integer);
}

const Grant = struct {
    account_id: []u8,
    grant_id: []u8,

    fn deinit(self: *Grant) void {
        allocator.free(self.account_id);
        allocator.free(self.grant_id);
    }
};

fn connect(engine: *Engine) ![]u8 {
    return connectProvider(engine, "codex");
}

fn connectProvider(engine: *Engine, provider: []const u8) ![]u8 {
    var reply = try rpc(engine, .control, "source.connect", .{ .kind = "explicit", .provider = provider, .label = "synthetic source" });
    defer reply.deinit();
    return allocator.dupe(u8, try control.string(try reply.result(), "source_id"));
}

fn enrollment(engine: *Engine, source_id: []const u8, subject: []const u8, token: []const u8) !Reply {
    var capability = try engine.capabilityForTest("enrollment");
    defer std.crypto.secureZero(u8, &capability);
    return rpc(engine, .adapter, "fixture.enroll", .{
        .application = "enrollment",
        .capability = capability[0..],
        .source_id = source_id,
        .provider = "codex",
        .subject = subject,
        .label = "synthetic account",
        .access_token = token,
        .audience = audience,
    });
}

fn enroll(engine: *Engine, source_id: []const u8, subject: []const u8, token: []const u8) !Grant {
    var reply = try enrollment(engine, source_id, subject, token);
    defer reply.deinit();
    const result = try reply.result();
    const account_id = try allocator.dupe(u8, try control.string(result, "account_id"));
    errdefer allocator.free(account_id);
    return .{ .account_id = account_id, .grant_id = try allocator.dupe(u8, try control.string(result, "grant_id")) };
}

fn openStore(path: []const u8, key: envelope.Key) !storage.Store {
    const database = try std.fmt.allocPrintSentinel(allocator, "{s}/state.sqlite", .{path}, 0);
    defer allocator.free(database);
    const root_id = try storage.Store.readRootId(allocator, database);
    defer allocator.free(root_id);
    return storage.Store.openRoot(io, allocator, database, root_id, key);
}

/// Offline preparation preserves all non-domain persisted sections. It uses
/// the real Store commit and recovery fence; no live actor state is poked.
fn seedTombstones(path: []const u8, key: envelope.Key, source_id: []const u8, old_account_id: []const u8, count: usize) !void {
    var store = try openStore(path, key);
    defer store.close();
    var saved = try store.readSnapshot();
    defer saved.deinit();
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, saved.json, .{ .allocate = .alloc_always });
    defer parsed.deinit();
    const scratch = parsed.arena.allocator();
    const old = try scratch.alloc(domain.Tombstone, count);
    const changes = try scratch.alloc(storage.GrantChange, count + 1);
    changes[0] = .{ .tombstone_account = old_account_id };
    for (old, 0..) |*item, index| item.* = .{
        .source_id = source_id,
        .identity = .{
            .provider = "codex",
            .issuer = audience,
            .subject = try std.fmt.allocPrint(scratch, "{s}{d}", .{ old_subject_prefix, index }),
            .verified = true,
        },
    };
    for (0..count) |index| {
        const input = try std.fmt.allocPrint(scratch, "synthetic-retained-custody/{s}/{d}", .{ old_account_id, index });
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(input, &digest, .{});
        const identifier = std.fmt.bytesToHex(digest, .lower);
        changes[index + 1] = .{ .tombstone_account = try scratch.dupe(u8, &identifier) };
    }
    const encoded = try std.json.Stringify.valueAlloc(scratch, old, .{});
    var tombstones = try std.json.parseFromSlice(std.json.Value, allocator, encoded, .{ .allocate = .alloc_always });
    defer tombstones.deinit();
    const state = parsed.value.object.getPtr("state") orelse return error.InvalidFixtureSnapshot;
    try state.object.put(scratch, "tombstones", tombstones.value);
    const metadata = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
    defer allocator.free(metadata);
    _ = try store.commit(saved.revision, metadata, changes);
}

/// Ciphertext is compared as bytes without logging plaintext or identifiers.
/// Inputs stay alive until statement finalization, so SQLITE_STATIC is safe.
fn readCiphertext(store: *storage.Store, grant: Grant) !?[]u8 {
    var statement: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(store.db, "SELECT ciphertext FROM grants WHERE account_id=?1 AND grant_id=?2;", -1, &statement, null) != c.SQLITE_OK) return error.FixtureSqlFailed;
    defer _ = c.sqlite3_finalize(statement.?);
    if (c.sqlite3_bind_text(statement.?, 1, grant.account_id.ptr, @intCast(grant.account_id.len), null) != c.SQLITE_OK or
        c.sqlite3_bind_text(statement.?, 2, grant.grant_id.ptr, @intCast(grant.grant_id.len), null) != c.SQLITE_OK) return error.FixtureSqlFailed;
    switch (c.sqlite3_step(statement.?)) {
        c.SQLITE_DONE => return null,
        c.SQLITE_ROW => {},
        else => return error.FixtureSqlFailed,
    }
    if (c.sqlite3_column_type(statement.?, 0) != c.SQLITE_BLOB) return error.InvalidFixtureCiphertext;
    const length = c.sqlite3_column_bytes(statement.?, 0);
    if (length <= 0 or length > envelope.maximum_plaintext + 48) return error.InvalidFixtureCiphertext;
    const pointer: [*]const u8 = @ptrCast(c.sqlite3_column_blob(statement.?, 0) orelse return error.InvalidFixtureCiphertext);
    return try allocator.dupe(u8, pointer[0..@intCast(length)]);
}

const Disk = struct {
    snapshot: storage.Snapshot,
    ciphertext: [2]?[]u8,
    old_tombstone: bool,
    target_tombstone: bool,
    old_tombstone_rows: usize = 0,
    old_tombstone_digest: [32]u8 = @splat(0),

    fn deinit(self: *Disk) void {
        self.snapshot.deinit();
        for (self.ciphertext) |value| if (value) |bytes| allocator.free(bytes);
    }
};

/// Excluding only the target account permits the old set to be compared before
/// and after successful insertion without assuming SQLite row order or count.
fn priorSqlTombstones(store: *storage.Store, target_account: []const u8) !struct { count: usize, digest: [32]u8 } {
    var statement: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(store.db, "SELECT account_id FROM tombstones WHERE account_id!=?1 ORDER BY account_id;", -1, &statement, null) != c.SQLITE_OK) return error.FixtureSqlFailed;
    defer _ = c.sqlite3_finalize(statement.?);
    if (c.sqlite3_bind_text(statement.?, 1, target_account.ptr, @intCast(target_account.len), null) != c.SQLITE_OK) return error.FixtureSqlFailed;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var count: usize = 0;
    while (true) switch (c.sqlite3_step(statement.?)) {
        c.SQLITE_DONE => break,
        c.SQLITE_ROW => {
            if (c.sqlite3_column_type(statement.?, 0) != c.SQLITE_TEXT) return error.InvalidFixtureTombstone;
            const length = c.sqlite3_column_bytes(statement.?, 0);
            if (length <= 0 or length > domain.max_text_bytes) return error.InvalidFixtureTombstone;
            const pointer: [*]const u8 = @ptrCast(c.sqlite3_column_text(statement.?, 0) orelse return error.InvalidFixtureTombstone);
            var framed: [8]u8 = undefined;
            std.mem.writeInt(u64, &framed, @intCast(length), .little);
            hash.update(&framed);
            hash.update(pointer[0..@intCast(length)]);
            count += 1;
        },
        else => return error.FixtureSqlFailed,
    };
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return .{ .count = count, .digest = digest };
}

/// A second writer opens only after the actor has joined and closed SQLite.
fn diskState(path: []const u8, key: envelope.Key, grants: [2]Grant, tokens: [2][]u8, old_account_id: []const u8, retained: bool) !Disk {
    var store = try openStore(path, key);
    defer store.close();
    var result: Disk = .{
        .snapshot = try store.readSnapshot(),
        .ciphertext = .{ null, null },
        .old_tombstone = false,
        .target_tombstone = false,
    };
    errdefer result.deinit();
    result.old_tombstone = try store.isTombstoned(old_account_id);
    result.target_tombstone = try store.isTombstoned(grants[0].account_id);
    const prior = try priorSqlTombstones(&store, grants[0].account_id);
    result.old_tombstone_rows = prior.count;
    result.old_tombstone_digest = prior.digest;
    for (grants, 0..) |grant, index| {
        result.ciphertext[index] = try readCiphertext(&store, grant);
        const status = try store.readGrantStatus(grant.account_id, grant.grant_id);
        try std.testing.expectEqual(@as(u64, 2), try store.nextGeneration(grant.account_id, grant.grant_id));
        const context: envelope.Context = .{
            .key_id = store.key_id,
            .account_id = grant.account_id,
            .grant_id = grant.grant_id,
            .generation = 1,
            .purpose = "request",
            .scope = audience,
        };
        if (retained) {
            try std.testing.expect(result.ciphertext[index] != null and status != null);
            try std.testing.expect(status.?.state == .ready);
            var secret = try store.loadGrant(context);
            defer secret.deinit();
            var parsed = try std.json.parseFromSlice(std.json.Value, allocator, secret.bytes, .{ .allocate = .alloc_always });
            defer {
                control.wipeJson(parsed.value);
                parsed.deinit();
            }
            try std.testing.expect(std.mem.eql(u8, tokens[index], try control.string(parsed.value, "access_token")));
        } else {
            try std.testing.expect(result.ciphertext[index] == null and status == null);
            try std.testing.expectError(error.GrantUnavailable, store.loadGrant(context));
        }
    }
    return result;
}

fn expectTombstones(saved: Disk, sources: [2][]u8, subject: []const u8, old_count: usize, forgotten: bool) !void {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, saved.snapshot.json, .{});
    defer parsed.deinit();
    const state = control.get(parsed.value, "state") orelse return error.InvalidFixtureSnapshot;
    const tombstones = control.get(state, "tombstones") orelse return error.InvalidFixtureSnapshot;
    try std.testing.expect(tombstones == .array);
    try std.testing.expectEqual(old_count + @as(usize, if (forgotten) 2 else 0), tombstones.array.items.len);
    var old = std.bit_set.Static(domain.max_records).empty;
    var target_sources: u2 = 0;
    for (tombstones.array.items) |item| {
        const identity = control.get(item, "identity") orelse return error.InvalidFixtureSnapshot;
        try std.testing.expect(try control.boolean(identity, "verified", false));
        try std.testing.expect(std.mem.eql(u8, "codex", try control.string(identity, "provider")));
        try std.testing.expect(std.mem.eql(u8, audience, try control.string(identity, "issuer")));
        const tenant = control.get(identity, "tenant") orelse return error.InvalidFixtureSnapshot;
        try std.testing.expect(tenant == .string and tenant.string.len == 0);
        const retained_subject = try control.string(identity, "subject");
        const source_id = try control.string(item, "source_id");
        if (std.mem.eql(u8, retained_subject, subject)) {
            try std.testing.expect(forgotten);
            const source: u2 = if (std.mem.eql(u8, sources[0], source_id)) 1 else if (std.mem.eql(u8, sources[1], source_id)) 2 else return error.InvalidFixtureTombstone;
            try std.testing.expect(target_sources & source == 0);
            target_sources |= source;
        } else {
            try std.testing.expect(std.mem.startsWith(u8, retained_subject, old_subject_prefix));
            const index = try std.fmt.parseInt(usize, retained_subject[old_subject_prefix.len..], 10);
            try std.testing.expect(index < old_count and !old.isSet(index));
            try std.testing.expect(std.mem.eql(u8, source_id, sources[0]));
            old.set(index);
        }
    }
    try std.testing.expectEqual(old_count, old.count());
    try std.testing.expectEqual(@as(u2, if (forgotten) 3 else 0), target_sources);
    try std.testing.expect(saved.old_tombstone);
    try std.testing.expectEqual(old_count + 1, saved.old_tombstone_rows);
    try std.testing.expectEqual(forgotten, saved.target_tombstone);
}

fn expectVisible(engine: *Engine, sources: [2][]u8, expected_grants: [2]Grant, retained: bool) !u64 {
    var snapshot = try rpc(engine, .control, "state.snapshot", .{});
    defer snapshot.deinit();
    const result = try snapshot.result();
    try std.testing.expect(try control.boolean(result, "custody_available", false));
    const accounts = control.get(result, "accounts") orelse return error.InvalidFixtureSnapshot;
    const grants = control.get(result, "grants") orelse return error.InvalidFixtureSnapshot;
    try std.testing.expect(accounts == .array and grants == .array);
    try std.testing.expectEqual(@as(usize, if (retained) 1 else 0), accounts.array.items.len);
    try std.testing.expectEqual(@as(usize, if (retained) 2 else 0), grants.array.items.len);
    if (retained) {
        const account = accounts.array.items[0];
        try std.testing.expect(std.mem.eql(u8, expected_grants[0].account_id, try control.string(account, "id")));
        const links = control.get(account, "source_ids") orelse return error.InvalidFixtureSnapshot;
        try std.testing.expect(links == .array and links.array.items.len == 2);
        var linked: u2 = 0;
        for (links.array.items) |item| {
            try std.testing.expect(item == .string);
            const bit: u2 = if (std.mem.eql(u8, item.string, sources[0])) 1 else if (std.mem.eql(u8, item.string, sources[1])) 2 else return error.InvalidFixtureSourceLink;
            try std.testing.expect(linked & bit == 0);
            linked |= bit;
        }
        try std.testing.expectEqual(@as(u2, 3), linked);
        var retained_grants: u2 = 0;
        for (grants.array.items) |item| {
            const identifier = try control.string(item, "id");
            const index: usize = if (std.mem.eql(u8, identifier, expected_grants[0].grant_id)) 0 else if (std.mem.eql(u8, identifier, expected_grants[1].grant_id)) 1 else return error.InvalidFixtureGrant;
            const bit: u2 = if (index == 0) 1 else 2;
            try std.testing.expect(retained_grants & bit == 0);
            retained_grants |= bit;
            try std.testing.expect(std.mem.eql(u8, expected_grants[index].account_id, try control.string(item, "account_id")));
            try std.testing.expect(std.mem.eql(u8, sources[index], try control.string(item, "source_id")));
            try std.testing.expectEqualStrings("ready", try control.string(item, "status"));
        }
        try std.testing.expectEqual(@as(u2, 3), retained_grants);
    }
    return revision(&snapshot);
}

fn exerciseRecordBoundary(old_count: usize, admitted: bool) !void {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    if (std.c.fchmodat(directory.dir.handle, ".", 0o700, 0) != 0) return error.FixturePermissionsFailed;
    const path: [:0]u8 = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    var key: envelope.Key = undefined;
    try io.randomSecure(&key);
    defer std.crypto.secureZero(u8, &key);
    const subject = try generatedValue();
    defer allocator.free(subject);
    const operation_id = try generatedValue();
    defer allocator.free(operation_id);
    const old_account_id = try generatedValue();
    defer allocator.free(old_account_id);
    var engine = try Engine.openWithKey(io, allocator, path, key);
    var engine_open = true;
    defer if (engine_open) engine.deinit();
    var sources: [2][]u8 = undefined;
    var source_count: usize = 0;
    defer for (sources[0..source_count]) |source| allocator.free(source);
    var tokens: [2][]u8 = undefined;
    var token_count: usize = 0;
    defer for (tokens[0..token_count]) |token| {
        std.crypto.secureZero(u8, token);
        allocator.free(token);
    };
    var grants: [2]Grant = undefined;
    var grant_count: usize = 0;
    defer for (grants[0..grant_count]) |*grant| grant.deinit();
    for (0..2) |index| {
        sources[index] = try connect(engine);
        source_count += 1;
        tokens[index] = try generatedValue();
        token_count += 1;
        grants[index] = try enroll(engine, sources[index], subject, tokens[index]);
        grant_count += 1;
    }
    try std.testing.expect(std.mem.eql(u8, grants[0].account_id, grants[1].account_id));
    engine.deinit();
    engine_open = false;
    try seedTombstones(path, key, sources[0], old_account_id, old_count);
    var before = try diskState(path, key, grants, tokens, old_account_id, true);
    defer before.deinit();
    try expectTombstones(before, sources, subject, old_count, false);
    engine = try Engine.openWithKey(io, allocator, path, key);
    engine_open = true;
    const submitted_revision = try expectVisible(engine, sources, grants, true);
    // Opening may commit a recovery checkpoint. Compare the mutation against
    // its immediate pre-request revision, not an earlier offline checkpoint.
    try std.testing.expect(submitted_revision >= before.snapshot.revision);
    const intent = .{ .operation_id = operation_id, .expected_revision = submitted_revision, .account_id = grants[0].account_id };
    var forgotten = try rpc(engine, .control, "account.forget", intent);
    defer forgotten.deinit();
    if (admitted) {
        try std.testing.expect(try control.boolean(try forgotten.result(), "forgotten", false));
        try std.testing.expectEqual(submitted_revision + 1, try expectVisible(engine, sources, grants, false));
    } else {
        try forgotten.expectError("TooManyRecords");
        try std.testing.expectEqual(submitted_revision, try expectVisible(engine, sources, grants, true));
    }
    engine.deinit();
    engine_open = false;
    var after = try diskState(path, key, grants, tokens, old_account_id, !admitted);
    defer after.deinit();
    try expectTombstones(after, sources, subject, old_count, admitted);
    try std.testing.expect(std.mem.eql(u8, &before.old_tombstone_digest, &after.old_tombstone_digest));
    if (admitted) {
        try std.testing.expectEqual(submitted_revision + 1, after.snapshot.revision);
    } else {
        try std.testing.expectEqual(submitted_revision, after.snapshot.revision);
        try std.testing.expect(std.mem.eql(u8, before.snapshot.json, after.snapshot.json));
        for (0..2) |index| try std.testing.expect(std.mem.eql(u8, before.ciphertext[index].?, after.ciphertext[index].?));
    }
    engine = try Engine.openWithKey(io, allocator, path, key);
    engine_open = true;
    const restarted_revision = try expectVisible(engine, sources, grants, !admitted);
    try std.testing.expect(restarted_revision >= after.snapshot.revision);
    var status = try rpc(engine, .control, "operation.status", .{ .operation_id = operation_id });
    defer status.deinit();
    if (admitted) {
        const completion = try status.result();
        try std.testing.expectEqualStrings("completed", try control.string(completion, "status"));
        try std.testing.expect(try control.boolean(control.get(completion, "result").?, "forgotten", false));
        var replay = try rpc(engine, .control, "account.forget", intent);
        defer replay.deinit();
        try std.testing.expect(try control.boolean(try replay.result(), "forgotten", false));
        for (0..2) |index| {
            var discovery = try enrollment(engine, sources[index], subject, tokens[index]);
            defer discovery.deinit();
            try std.testing.expectEqualStrings("tombstoned", try control.string(try discovery.result(), "status"));
        }
        try std.testing.expectEqual(restarted_revision, try expectVisible(engine, sources, grants, false));
    } else try status.expectError("UnknownOperation");
    engine.deinit();
    engine_open = false;
    var restarted = try diskState(path, key, grants, tokens, old_account_id, !admitted);
    defer restarted.deinit();
    try expectTombstones(restarted, sources, subject, old_count, admitted);
    try std.testing.expect(std.mem.eql(u8, &after.old_tombstone_digest, &restarted.old_tombstone_digest));
    try std.testing.expectEqual(restarted_revision, restarted.snapshot.revision);
    try std.testing.expect(std.mem.eql(u8, after.snapshot.json, restarted.snapshot.json));
}

test "snapshot forget refuses multi-source tombstone saturation without changing custody or old tombstones" {
    try exerciseRecordBoundary(domain.max_records - 1, false);
}

test "snapshot forget admits exact multi-source tombstone boundary atomically and persists completion across restart" {
    try exerciseRecordBoundary(domain.max_records - 2, true);
}

const Budget = struct {
    exact_snapshot_bytes: usize,
    reserved_bytes: usize,
    credits_bytes: usize,
    remaining_bytes: usize,
    credit_count: usize,
};

fn budget(engine: *Engine) !Budget {
    var capability = try engine.capabilityForTest("enrollment");
    defer std.crypto.secureZero(u8, &capability);
    var reply = try rpc(engine, .adapter, "fixture.snapshotBudget", .{ .application = "enrollment", .capability = capability[0..] });
    defer reply.deinit();
    const result = try reply.result();
    var value: Budget = undefined;
    inline for (@typeInfo(Budget).@"struct".field_names) |name| {
        const encoded = control.get(result, name) orelse return error.MissingBudgetField;
        if (encoded != .integer or encoded.integer < 0) return error.InvalidBudgetField;
        @field(value, name) = @intCast(encoded.integer);
    }
    try std.testing.expect(value.exact_snapshot_bytes <= value.reserved_bytes);
    try std.testing.expectEqual(snapshot_admission.maximum_snapshot_bytes, value.reserved_bytes + value.remaining_bytes);
    return value;
}

/// The actor reads its own SQLite connection. Equality of these SHA-256
/// fingerprints proves saved bytes stayed identical without exporting private
/// metadata or racing a second writer while the pending import is alive.
const Stored = struct {
    revision: u64,
    snapshot_bytes: usize,
    snapshot_sha256: [64]u8,
    ciphertext_sha256: [2][64]u8,
    tombstone_count: usize,
    tombstone_sha256: [64]u8,
};

fn stored(engine: *Engine, grants: [2]Grant, excluded: []const u8) !Stored {
    var capability = try engine.capabilityForTest("enrollment");
    defer std.crypto.secureZero(u8, &capability);
    var reply = try rpc(engine, .adapter, "fixture.snapshotStored", .{
        .application = "enrollment",
        .capability = capability[0..],
        .grants = .{
            .{ .account_id = grants[0].account_id, .grant_id = grants[0].grant_id },
            .{ .account_id = grants[1].account_id, .grant_id = grants[1].grant_id },
        },
        .exclude_account_id = excluded,
    });
    defer reply.deinit();
    const result = try reply.result();
    var value: Stored = undefined;
    inline for (.{ "revision", "snapshot_bytes", "tombstone_count" }) |name| {
        const encoded = control.get(result, name) orelse return error.MissingStoredField;
        if (encoded != .integer or encoded.integer < 0) return error.InvalidStoredField;
        @field(value, name) = @intCast(encoded.integer);
    }
    inline for (.{ "snapshot_sha256", "tombstone_sha256" }) |name| {
        const encoded = try control.string(result, name);
        if (encoded.len != 64) return error.InvalidStoredField;
        @memcpy(&@field(value, name), encoded);
    }
    const ciphertexts = control.get(result, "ciphertext_sha256") orelse return error.MissingStoredField;
    if (ciphertexts != .array or ciphertexts.array.items.len != 2) return error.InvalidStoredField;
    for (ciphertexts.array.items, &value.ciphertext_sha256) |encoded, *digest| {
        if (encoded != .string or encoded.string.len != 64) return error.InvalidStoredField;
        @memcpy(digest, encoded.string);
    }
    return value;
}

const HeldImport = struct {
    generation: i64,
    operation_id: []u8,

    fn deinit(self: *HeldImport) void {
        allocator.free(self.operation_id);
    }
};

fn holdImport(engine: *Engine, source_id: []const u8, token: []const u8) !HeldImport {
    var capability = try engine.capabilityForTest("enrollment");
    defer std.crypto.secureZero(u8, &capability);
    var reply = try rpc(engine, .adapter, "fixture.importStart", .{
        .application = "enrollment",
        .capability = capability[0..],
        .source_id = source_id,
        .provider = "github",
        .access_token = token,
        // This captures the forget epoch. A refused forget must not supersede
        // independently admitted explicit re-enrollment authority.
        .allow_reenrollment = true,
    });
    defer reply.deinit();
    const result = try reply.result();
    return .{ .generation = control.get(result, "generation").?.integer, .operation_id = try allocator.dupe(u8, try control.string(result, "operation_id")) };
}

fn completeHeldImport(engine: *Engine, source_id: []const u8, held: HeldImport) !void {
    var random: [8]u8 = undefined;
    try io.randomSecure(&random);
    defer std.crypto.secureZero(u8, &random);
    const login = try generatedValue();
    defer allocator.free(login);
    const response = try std.json.Stringify.valueAlloc(allocator, .{ .id = std.mem.readInt(u64, &random, .little) | 1, .login = login, .type = "User" }, .{});
    defer {
        std.crypto.secureZero(u8, response);
        allocator.free(response);
    }
    var capability = try engine.capabilityForTest("enrollment");
    defer std.crypto.secureZero(u8, &capability);
    var reply = try rpc(engine, .adapter, "fixture.importComplete", .{
        .application = "enrollment",
        .capability = capability[0..],
        .source_id = source_id,
        .generation = held.generation,
        .response = response,
    });
    defer reply.deinit();
    try std.testing.expect(try control.boolean(try reply.result(), "admitted", false));
}

/// Local atomic mutations persist only their completed record together with the
/// domain candidate. Measure that record through its production ledger, using
/// the exact intent/result and a worst-width escaped fingerprint.
fn completedForgetReservation(operation_id: []const u8, expected_revision: u64) !usize {
    var ledger = try mutation_authority.Ledger.init(allocator, 1);
    defer ledger.deinit();
    const empty = ledger.reservedSnapshotBytes();
    const admitted = try ledger.begin(operation_id, "account.forget", @splat(0), expected_revision, expected_revision, .local_atomic);
    const slot = switch (admitted) {
        .execute => |index| index,
        else => return error.InvalidFixtureMutation,
    };
    const cached = try std.json.Stringify.valueAlloc(allocator, .{ .forgotten = true }, .{});
    defer allocator.free(cached);
    try ledger.complete(slot, cached);
    return ledger.reservedSnapshotBytes() - empty;
}

test "snapshot forget refuses actual whole-envelope byte growth atomically and preserves held import authority" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    if (std.c.fchmodat(directory.dir.handle, ".", 0o700, 0) != 0) return error.FixturePermissionsFailed;
    const path: [:0]u8 = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    var key: envelope.Key = undefined;
    try io.randomSecure(&key);
    defer std.crypto.secureZero(u8, &key);
    const generated_subject = try generatedValue();
    defer allocator.free(generated_subject);
    var subject: [domain.max_text_bytes]u8 = @splat('\\');
    @memcpy(subject[0..generated_subject.len], generated_subject);
    const operation_id = try generatedValue();
    defer allocator.free(operation_id);
    const old_account_id = try generatedValue();
    defer allocator.free(old_account_id);
    var engine = try Engine.openWithKey(io, allocator, path, key);
    var engine_open = true;
    defer if (engine_open) engine.deinit();
    var sources: [2][]u8 = undefined;
    var source_count: usize = 0;
    defer for (sources[0..source_count]) |source| allocator.free(source);
    var tokens: [2][]u8 = undefined;
    var token_count: usize = 0;
    defer for (tokens[0..token_count]) |token| {
        std.crypto.secureZero(u8, token);
        allocator.free(token);
    };
    var grants: [2]Grant = undefined;
    var grant_count: usize = 0;
    defer for (grants[0..grant_count]) |*grant| grant.deinit();
    for (0..2) |index| {
        sources[index] = try connect(engine);
        source_count += 1;
        tokens[index] = try generatedValue();
        token_count += 1;
        grants[index] = try enroll(engine, sources[index], &subject, tokens[index]);
        grant_count += 1;
    }
    try std.testing.expect(std.mem.eql(u8, grants[0].account_id, grants[1].account_id));
    engine.deinit();
    engine_open = false;
    const old_count = 3;
    try seedTombstones(path, key, sources[0], old_account_id, old_count);
    var initial = try diskState(path, key, grants, tokens, old_account_id, true);
    defer initial.deinit();
    try expectTombstones(initial, sources, &subject, old_count, false);
    const InitialState = struct { state: domain.Snapshot };
    var initial_state = try std.json.parseFromSlice(InitialState, allocator, initial.snapshot.json, .{ .ignore_unknown_fields = true });
    defer initial_state.deinit();
    var domain_state = try domain.State.fromSnapshot(allocator, initial_state.value.state);
    defer domain_state.deinit();
    const forget_growth = try domain_state.forgetGrowth(grants[0].account_id);
    try std.testing.expectEqual(@as(usize, 2), forget_growth.tombstones);
    const original_domain_bytes = try snapshot_admission.countJson(domain_state.snapshot(), storage.maximum_snapshot_bytes);
    try domain_state.forget(grants[0].account_id);
    const forgotten_domain_bytes = try snapshot_admission.countJson(domain_state.snapshot(), storage.maximum_snapshot_bytes);
    try std.testing.expect(forgotten_domain_bytes > original_domain_bytes);
    const net_domain_growth = forgotten_domain_bytes - original_domain_bytes;

    engine = try Engine.openWithKey(io, allocator, path, key);
    engine_open = true;
    const import_source = try connectProvider(engine, "github");
    defer allocator.free(import_source);
    const import_token = try generatedValue();
    defer {
        std.crypto.secureZero(u8, import_token);
        allocator.free(import_token);
    }
    var held = try holdImport(engine, import_source, import_token);
    defer held.deinit();
    const promised = try budget(engine);
    try std.testing.expect(promised.credit_count > 0 and promised.credits_bytes > 0);
    const spare_bytes = 4096;
    var capability = try engine.capabilityForTest("enrollment");
    defer std.crypto.secureZero(u8, &capability);
    var saturated = try rpc(engine, .adapter, "fixture.snapshotSaturate", .{ .application = "enrollment", .capability = capability[0..], .spare_bytes = spare_bytes });
    defer saturated.deinit();
    _ = try saturated.result();
    const full = try budget(engine);
    // The whole envelope includes prepaid scalar-maintenance space for absent
    // slots. Three f64 spans per 1024 slots alone reserve over 1 MiB, so the
    // physical JSON need not approach 15 MiB to reach this production boundary.
    try std.testing.expect(full.reserved_bytes > 15 * 1024 * 1024);
    try std.testing.expect(full.remaining_bytes >= spare_bytes and full.remaining_bytes <= spare_bytes + 64);
    try std.testing.expect(net_domain_growth > full.remaining_bytes);
    try std.testing.expectEqual(promised.credits_bytes, full.credits_bytes);
    try std.testing.expectEqual(promised.credit_count, full.credit_count);
    // The actual domain expansion plus a worst-case mutation record fits the old
    // physical-only 16 MiB limit. Refusal therefore protects outstanding
    // completion reservations, rather than merely retesting that old limit.
    try std.testing.expect(full.exact_snapshot_bytes + net_domain_growth + 20 + mutation_authority.maximum_record_snapshot_bytes <= storage.maximum_snapshot_bytes);
    const before = try stored(engine, grants, grants[0].account_id);
    try std.testing.expectEqual(full.exact_snapshot_bytes, before.snapshot_bytes);
    try std.testing.expectEqual(old_count + 1, before.tombstone_count);
    const prior_tombstone_hex = std.fmt.bytesToHex(initial.old_tombstone_digest, .lower);
    try std.testing.expect(std.mem.eql(u8, &prior_tombstone_hex, &before.tombstone_sha256));
    for (0..2) |index| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(initial.ciphertext[index].?, &digest, .{});
        const hexadecimal = std.fmt.bytesToHex(digest, .lower);
        try std.testing.expect(std.mem.eql(u8, &hexadecimal, &before.ciphertext_sha256[index]));
    }
    const submitted_revision = try expectVisible(engine, sources, grants, true);
    try std.testing.expectEqual(before.revision, submitted_revision);
    const completion_reservation = try completedForgetReservation(operation_id, submitted_revision);
    try std.testing.expect(completion_reservation < full.remaining_bytes);
    var forgotten = try rpc(engine, .control, "account.forget", .{ .operation_id = operation_id, .expected_revision = submitted_revision, .account_id = grants[0].account_id });
    defer forgotten.deinit();
    try forgotten.expectError("SnapshotTooLarge");
    try std.testing.expectEqual(submitted_revision, try expectVisible(engine, sources, grants, true));
    try std.testing.expectEqualDeep(before, try stored(engine, grants, grants[0].account_id));
    try std.testing.expectEqualDeep(full, try budget(engine));
    var status = try rpc(engine, .control, "operation.status", .{ .operation_id = operation_id });
    defer status.deinit();
    try status.expectError("UnknownOperation");

    // Completion uses its previously reserved space and original forget epoch.
    // Refusal cannot cancel or silently supersede this already held authority.
    try completeHeldImport(engine, import_source, held);
    const completed = try budget(engine);
    try std.testing.expect(completed.credit_count < full.credit_count);
    engine.deinit();
    engine_open = false;
    var after = try diskState(path, key, grants, tokens, old_account_id, true);
    defer after.deinit();
    try expectTombstones(after, sources, &subject, old_count, false);
    try std.testing.expect(std.mem.eql(u8, &initial.old_tombstone_digest, &after.old_tombstone_digest));
    for (0..2) |index| try std.testing.expect(std.mem.eql(u8, initial.ciphertext[index].?, after.ciphertext[index].?));
}
