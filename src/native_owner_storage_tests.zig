//! Actual private SQLite/independent-authority predicates for retained owner
//! provenance. These prove exact snapshot integrity, not live native identity.
const std = @import("std");
const c = @import("c");
const storage = @import("storage.zig");
const envelope = @import("envelope.zig");
extern "c" fn waitpid(pid: c.pid_t, status: *c_int, options: c_int) c.pid_t;
extern "c" fn kill(pid: c.pid_t, signal: c_int) c_int;

const allocator = std.testing.allocator;
const io = std.testing.io;
const key: envelope.Key = @splat(81);
const context: envelope.Context = .{ .account_id = "fixture-account", .grant_id = "fixture-grant", .generation = 1, .purpose = "request", .scope = "read" };
const original = "{\"state\":{},\"owners\":[{\"owner_id\":\"fixture-owner-a\",\"attachment_generation\":1,\"native_nonce\":\"fixture-incarnation-a\",\"operation_id\":\"fixture-operation-a\",\"phase\":\"pending_registration\"}],\"requests\":[{\"request_id\":\"fixture-work-a\",\"owner_id\":\"fixture-owner-a\",\"attempts\":1}],\"credits\":[{\"operation_id\":\"fixture-operation-a\",\"bytes\":4096}]}";
const substituted = "{\"state\":{},\"owners\":[{\"owner_id\":\"fixture-owner-b\",\"attachment_generation\":2,\"native_nonce\":\"fixture-incarnation-b\",\"operation_id\":\"fixture-operation-b\",\"phase\":\"attached\"}],\"requests\":[{\"request_id\":\"fixture-work-b\",\"owner_id\":\"fixture-owner-b\",\"attempts\":0}],\"credits\":[]}";

fn privatePath(tmp: std.testing.TmpDir) ![:0]u8 {
    const directory_path = try std.fmt.allocPrintSentinel(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer allocator.free(directory_path);
    const fd = std.c.open(directory_path.ptr, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (fd < 0) return error.FixtureDirectoryUnavailable;
    defer _ = std.c.close(fd);
    if (std.c.fchmod(fd, 0o700) != 0) return error.FixtureModeFailed;
    return std.fmt.allocPrintSentinel(allocator, ".zig-cache/tmp/{s}/custody.sqlite3", .{tmp.sub_path}, 0);
}

fn exec(db: *c.sqlite3, sql: [:0]const u8) !void {
    if (c.sqlite3_exec(db, sql.ptr, null, null, null) != c.SQLITE_OK) return error.FixtureSqlFailed;
}

fn replaceMetadata(db: *c.sqlite3, bytes: []const u8) !void {
    var statement: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(db, "UPDATE snapshot SET metadata_json=?1;", -1, &statement, null) != c.SQLITE_OK) return error.FixtureSqlFailed;
    defer _ = c.sqlite3_finalize(statement.?);
    // Input remains owned until finalization; no translated C macro needed.
    if (c.sqlite3_bind_text(statement.?, 1, bytes.ptr, @intCast(bytes.len), null) != c.SQLITE_OK or c.sqlite3_step(statement.?) != c.SQLITE_DONE) return error.FixtureSqlFailed;
}

fn rejectTypedRecovery(_: std.mem.Allocator, _: []const u8, _: u64) anyerror!void {
    return error.TypedRecoveryUnexpectedlyReached;
}

fn seed(path: [:0]const u8, rotation: bool) !void {
    var store = try storage.Store.open(io, allocator, path, key);
    defer store.close();
    _ = try store.commit(0, original, &.{.{ .put = .{ .context = context, .plaintext = "private-custody-fixture", .renewal_owner = if (rotation) .omux else .external } }});
    if (rotation) try std.testing.expect((try store.beginRotation(context, "fixture-sql-rotation")).may_issue);
}

fn expectPreservedRefusal(tmp: std.testing.TmpDir, path: [:0]const u8, failure: anyerror) !void {
    const db_before = try tmp.dir.readFileAlloc(io, "custody.sqlite3", allocator, .limited(2 * 1024 * 1024));
    defer allocator.free(db_before);
    const authority_before = try tmp.dir.readFileAlloc(io, "custody.sqlite3.authority", allocator, .limited(1024));
    defer allocator.free(authority_before);
    for (0..2) |_| {
        try std.testing.expectError(failure, storage.Store.openRootWithSnapshotValidator(io, allocator, path, envelope.default_key_id, key, rejectTypedRecovery));
        const db_after = try tmp.dir.readFileAlloc(io, "custody.sqlite3", allocator, .limited(2 * 1024 * 1024));
        defer allocator.free(db_after);
        const authority_after = try tmp.dir.readFileAlloc(io, "custody.sqlite3.authority", allocator, .limited(1024));
        defer allocator.free(authority_after);
        try std.testing.expectEqualSlices(u8, db_before, db_after);
        try std.testing.expectEqualSlices(u8, authority_before, authority_after);
    }
}

test "fresh snapshot seal commits exact initial bytes and retains encrypted custody on reopen" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try privatePath(tmp);
    defer allocator.free(path);
    {
        var store = try storage.Store.open(io, allocator, path, key);
        defer store.close();
        var snapshot = try store.readSnapshot();
        defer snapshot.deinit();
        try std.testing.expectEqualStrings("{}", snapshot.json);
        try std.testing.expectEqual(@as(u64, 0), store.checkpoint.snapshot_revision);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(snapshot.json, &digest, .{});
        try std.testing.expectEqualSlices(u8, &digest, &store.checkpoint.snapshot_digest);
        try std.testing.expect(store.checkpoint.eql(try store.authority.?.read()));
        _ = try store.commit(0, original, &.{.{ .put = .{ .context = context, .plaintext = "private-custody-fixture", .renewal_owner = .external } }});
    }
    var reopened = try storage.Store.open(io, allocator, path, key);
    defer reopened.close();
    var snapshot = try reopened.readSnapshot();
    defer snapshot.deinit();
    try std.testing.expectEqualStrings(original, snapshot.json);
    try std.testing.expectEqual(snapshot.revision, reopened.checkpoint.snapshot_revision);
    var payload = try reopened.loadGrant(context);
    defer payload.deinit();
    try std.testing.expectEqualStrings("private-custody-fixture", payload.bytes);
}

test "self-consistent owner work and credit substitution cannot create recovered authority" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try privatePath(tmp);
    defer allocator.free(path);
    {
        var store = try storage.Store.open(io, allocator, path, key);
        defer store.close();
        _ = try store.commit(0, original, &.{.{ .put = .{ .context = context, .plaintext = "private-custody-fixture", .renewal_owner = .omux } }});
        try std.testing.expect((try store.beginRotation(context, "tampered-pending-rotation")).may_issue);
        // A coordinated valid-JSON rewrite must refuse before automatic SQL
        // quarantine can publish another checkpoint over the changed bytes.
        try replaceMetadata(store.db, substituted);
        try std.testing.expectError(error.SnapshotAuthenticationFailed, store.readSnapshot());
    }
    try expectPreservedRefusal(tmp, path, error.SnapshotAuthenticationFailed);
}

test "semantically equal whitespace and revision rewrites fail exact snapshot binding" {
    inline for (.{ true, false }) |whitespace| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const path = try privatePath(tmp);
        defer allocator.free(path);
        try seed(path, false);
        {
            var store = try storage.Store.open(io, allocator, path, key);
            defer store.close();
            if (whitespace) {
                const changed = try std.fmt.allocPrint(allocator, " {s} ", .{original});
                defer allocator.free(changed);
                try replaceMetadata(store.db, changed);
            } else try exec(store.db, "UPDATE snapshot SET revision=revision+1;");
        }
        try expectPreservedRefusal(tmp, path, error.SnapshotAuthenticationFailed);
    }
}

test "copying a replacement commitment into SQLite cannot authenticate changed metadata" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try privatePath(tmp);
    defer allocator.free(path);
    try seed(path, false);
    {
        var store = try storage.Store.open(io, allocator, path, key);
        defer store.close();
        try replaceMetadata(store.db, substituted);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(substituted, &digest, .{});
        const sql = try std.fmt.allocPrintSentinel(allocator, "UPDATE recovery_checkpoint SET snapshot_digest=X'{s}';", .{std.fmt.bytesToHex(digest, .lower)}, 0);
        defer allocator.free(sql);
        try exec(store.db, sql);
    }
    try expectPreservedRefusal(tmp, path, error.RecoveryCheckpointMismatch);
}

test "DELETE-mode wrong-key and bad-seal refusal preserve the database journal contract" {
    inline for (.{ false, true }) |tampered| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const path = try privatePath(tmp);
        defer allocator.free(path);
        try seed(path, false);
        var raw: ?*c.sqlite3 = null;
        if (c.sqlite3_open_v2(path.ptr, &raw, c.SQLITE_OPEN_READWRITE | c.SQLITE_OPEN_NOFOLLOW, null) != c.SQLITE_OK) return error.FixtureSqlFailed;
        {
            defer _ = c.sqlite3_close(raw.?);
            try exec(raw.?, "PRAGMA journal_mode=DELETE;");
            if (tampered) try replaceMetadata(raw.?, substituted);
        }
        if (tampered) {
            try expectPreservedRefusal(tmp, path, error.SnapshotAuthenticationFailed);
        } else {
            const before = try tmp.dir.readFileAlloc(io, "custody.sqlite3", allocator, .limited(2 * 1024 * 1024));
            defer allocator.free(before);
            const authority_before = try tmp.dir.readFileAlloc(io, "custody.sqlite3.authority", allocator, .limited(1024));
            defer allocator.free(authority_before);
            for (0..2) |_| {
                try std.testing.expectError(error.WrongKey, storage.Store.openRootWithSnapshotValidator(io, allocator, path, envelope.default_key_id, @splat(82), rejectTypedRecovery));
                const after = try tmp.dir.readFileAlloc(io, "custody.sqlite3", allocator, .limited(2 * 1024 * 1024));
                defer allocator.free(after);
                const authority_after = try tmp.dir.readFileAlloc(io, "custody.sqlite3.authority", allocator, .limited(1024));
                defer allocator.free(authority_after);
                try std.testing.expectEqualSlices(u8, before, after);
                try std.testing.expectEqualSlices(u8, authority_before, authority_after);
            }
        }
    }
}

fn legacyRecord(checkpoint: anytype) [112]u8 {
    // Exact former public record layout/domain, with fixture wrapping-key
    // custody. A valid former MAC must not be mistaken for a metadata seal.
    var bytes: [112]u8 = undefined;
    @memcpy(bytes[0..8], "OMUXR001");
    @memcpy(bytes[8..40], &checkpoint.installation);
    std.mem.writeInt(u64, bytes[40..48], checkpoint.sequence, .little);
    @memcpy(bytes[48..80], &checkpoint.nonce);
    var mac = std.crypto.auth.hmac.sha2.HmacSha256.init(&key);
    mac.update("omux recovery authority v1\x00");
    mac.update(envelope.default_key_id);
    mac.update("\x00");
    mac.update(bytes[0..80]);
    const tag: *[32]u8 = bytes[80..112];
    mac.final(tag);
    return bytes;
}

test "valid legacy authority never signs retained metadata or recovers pending SQL custody" {
    inline for (.{ false, true }) |legacy_sql| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const path = try privatePath(tmp);
        defer allocator.free(path);
        var store = try storage.Store.open(io, allocator, path, key);
        _ = try store.commit(0, original, &.{.{ .put = .{ .context = context, .plaintext = "private-custody-fixture", .renewal_owner = .omux } }});
        try std.testing.expect((try store.beginRotation(context, "legacy-pending-rotation")).may_issue);
        const legacy = legacyRecord(store.checkpoint);
        if (legacy_sql) try exec(store.db, "PRAGMA user_version=2;");
        store.close();
        try tmp.dir.writeFile(io, .{ .sub_path = "custody.sqlite3.authority", .data = &legacy });
        try expectPreservedRefusal(tmp, path, error.RecoveryMigrationRequired);
        try std.testing.expectError(error.WrongKey, storage.Store.openRootWithSnapshotValidator(io, allocator, path, envelope.default_key_id, @splat(82), rejectTypedRecovery));
    }
}

fn crashAfterReserve(path: [:0]const u8) !void {
    const child_allocator = std.heap.page_allocator;
    var threaded: std.Io.Threaded = .init(child_allocator, .{ .async_limit = .limited(2), .concurrent_limit = .limited(8) });
    const child_io = threaded.io();
    // Intentionally no close/rollback/deinit: the child exits at the durable
    // independent reservation with an actual uncommitted SQLite transaction.
    var store = try storage.Store.open(child_io, child_allocator, path, key);
    // Publish the baseline after legitimate opening and checkpointing, before
    // the crash transaction. Comparison must not confuse earlier committed WAL
    // flushing with a refused recovery mutation.
    var checkpoint_stmt: ?*c.sqlite3_stmt = null;
    if (c.sqlite3_prepare_v2(store.db, "PRAGMA wal_checkpoint(TRUNCATE);", -1, &checkpoint_stmt, null) != c.SQLITE_OK) return error.FixtureSqlFailed;
    if (c.sqlite3_step(checkpoint_stmt.?) != c.SQLITE_ROW or c.sqlite3_column_int(checkpoint_stmt.?, 0) != 0 or c.sqlite3_column_int(checkpoint_stmt.?, 1) != 0 or c.sqlite3_column_int(checkpoint_stmt.?, 2) != 0) {
        _ = c.sqlite3_finalize(checkpoint_stmt.?);
        return error.FixtureCheckpointFailed;
    }
    _ = c.sqlite3_finalize(checkpoint_stmt.?);
    var admitted = try store.readSnapshot();
    if (!std.mem.eql(u8, admitted.json, original)) return error.FixtureOriginalMetadataChanged;
    admitted.deinit();
    var retained = try store.loadGrant(context);
    if (!std.mem.eql(u8, retained.bytes, "private-custody-fixture")) return error.FixtureCiphertextChanged;
    retained.deinit();
    const baseline = try std.Io.Dir.cwd().readFileAlloc(child_io, path, child_allocator, .limited(2 * 1024 * 1024));
    const baseline_path = try std.fmt.allocPrint(child_allocator, "{s}.before-reserve", .{path});
    try std.Io.Dir.cwd().writeFile(child_io, .{ .sub_path = baseline_path, .data = baseline, .flags = .{ .permissions = .fromMode(0o600) } });
    try exec(store.db, "BEGIN IMMEDIATE; UPDATE snapshot SET revision=revision+1,metadata_json='{\"state\":{},\"phase\":\"pending_detach\"}';");
    const changed = "{\"state\":{},\"phase\":\"pending_detach\"}";
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(changed, &digest, .{});
    const next = try store.checkpoint.successor(child_io, store.checkpoint.snapshot_revision + 1, digest);
    const sql = try std.fmt.allocPrintSentinel(child_allocator, "UPDATE recovery_checkpoint SET sequence={d},nonce=X'{s}',snapshot_revision={d},snapshot_digest=X'{s}';", .{ next.sequence, std.fmt.bytesToHex(next.nonce, .lower), next.snapshot_revision, std.fmt.bytesToHex(next.snapshot_digest, .lower) }, 0);
    try exec(store.db, sql);
    try store.authority.?.reserve(store.checkpoint, next);
    c._exit(0);
}

fn waitForChild(pid: c.pid_t) !void {
    const started = std.Io.Clock.awake.now(io);
    var status: c_int = undefined;
    while (true) {
        const observed = waitpid(pid, &status, 1);
        if (observed == pid) {
            if (status != 0) return error.FixtureChildFailed;
            return;
        }
        if (observed < 0 and std.c.errno(observed) != .INTR) return error.ChildWaitFailed;
        if (started.durationTo(std.Io.Clock.awake.now(io)).toMilliseconds() >= 60_000) {
            _ = kill(pid, 9); // This test's child only.
            while (waitpid(pid, &status, 0) < 0) {
                if (std.c.errno(-1) != .INTR) break;
            }
            return error.FixtureChildDeadline;
        }
        try io.sleep(.fromMilliseconds(10), .awake);
    }
}

test "real process loss after independent reservation cannot resume the older SQL snapshot" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try privatePath(tmp);
    defer allocator.free(path);
    try seed(path, false);
    const child = c.fork();
    if (child < 0) return error.FixtureForkFailed;
    if (child == 0) {
        crashAfterReserve(path) catch |failure| {
            const name = @errorName(failure);
            _ = c.write(2, name.ptr, name.len);
            _ = c.write(2, "\n", 1);
            c._exit(1);
        };
        c._exit(2);
    }
    try waitForChild(child);
    const admitted = try tmp.dir.readFileAlloc(io, "custody.sqlite3.before-reserve", allocator, .limited(2 * 1024 * 1024));
    defer allocator.free(admitted);
    const after_crash = try tmp.dir.readFileAlloc(io, "custody.sqlite3", allocator, .limited(2 * 1024 * 1024));
    defer allocator.free(after_crash);
    try std.testing.expectEqualSlices(u8, admitted, after_crash);
    try expectPreservedRefusal(tmp, path, error.RecoveryRollbackDetected);
}
