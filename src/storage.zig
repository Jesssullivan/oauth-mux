//! SQLite belongs to one daemon writer thread. Network requests occur outside
//! these transactions. Only encrypted grant payloads reach SQLite or its WAL.
const std = @import("std");
const c = @import("c");
const envelope = @import("envelope.zig");
const recovery = @import("recovery.zig");

pub const RenewalOwner = enum { none, external, omux };
pub const GrantPut = struct {
    context: envelope.Context,
    plaintext: []const u8,
    renewal_owner: RenewalOwner = .none,
};
pub const GrantChange = union(enum) {
    put: GrantPut,
    delete: struct { account_id: []const u8, grant_id: []const u8 },
    tombstone_account: []const u8,
    /// Only explicit user re-enrollment may lift a forgotten-account tombstone.
    reenroll_account: []const u8,
};
pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    revision: u64,
    json: []u8,

    pub fn deinit(self: *Snapshot) void {
        self.allocator.free(self.json);
        self.* = undefined;
    }
};
pub const RotationStatus = enum { started, completed, quarantined };
pub const RotationBegin = struct {
    status: RotationStatus,
    /// Only the call which created durable intent may contact the issuer.
    /// An existing started operation is ambiguous and must not be reissued.
    may_issue: bool,
};
pub const Operation = struct {
    status: RotationStatus,
    generation: u64,
    committed_revision: ?u64,
};
pub const GrantState = enum { ready, refreshing, quarantined };
pub const GrantStatus = struct {
    generation: u64,
    state: GrantState,
    renewal_owner: RenewalOwner,
};

/// Exact serialized metadata ceiling. Whole-snapshot admission must reserve
/// every persisted section against this bound before external effects; grant
/// ciphertext has its separate envelope limit and never consumes this JSON.
pub const maximum_snapshot_bytes = 16 * 1024 * 1024;
/// The actor's typed whole-envelope/obligation gate. It must perform no effects;
/// returning an error prevents storage from adopting any recovered mutation.
pub const SnapshotValidator = *const fn (std.mem.Allocator, []const u8, u64) anyerror!void;
const key_check_context: envelope.Context = .{
    .account_id = "omux-installation",
    .grant_id = "wrapping-key-check",
    .generation = 1,
    .purpose = "key-check",
    .scope = "database-v1",
};
const key_check_plaintext = "omux database wrapping key version 1";

pub const Store = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    db: *c.sqlite3,
    key: envelope.Key,
    key_id: []u8,
    owner_thread: std.Thread.Id,
    poisoned: bool = false,
    authority: ?recovery.FileAuthority = null,
    checkpoint: recovery.Checkpoint = undefined,

    /// The supplied key must come from the OS vault. This API never creates a
    /// replacement key, and a missing/corrupted key check is an opening error.
    /// Call only on the dedicated SQLite writer thread and retain that owner.
    pub fn open(io: std.Io, allocator: std.mem.Allocator, path: [:0]const u8, key: envelope.Key) !Store {
        return openRoot(io, allocator, path, envelope.default_key_id, key);
    }

    pub fn openRoot(io: std.Io, allocator: std.mem.Allocator, path: [:0]const u8, key_id: []const u8, key: envelope.Key) !Store {
        return openRootValidated(io, allocator, path, key_id, key, null);
    }

    /// Validate an existing actor snapshot before rotation recovery can reserve
    /// independent authority or update SQLite. Fresh databases still begin with
    /// '{}'; the actor commits its new typed schema during initial bootstrap.
    pub fn openRootWithSnapshotValidator(io: std.Io, allocator: std.mem.Allocator, path: [:0]const u8, key_id: []const u8, key: envelope.Key, validator: SnapshotValidator) !Store {
        return openRootValidated(io, allocator, path, key_id, key, validator);
    }

    fn openRootValidated(io: std.Io, allocator: std.mem.Allocator, path: [:0]const u8, key_id: []const u8, key: envelope.Key, validator: ?SnapshotValidator) !Store {
        if (key_id.len == 0 or key_id.len > 128) return error.InvalidKeyIdentity;
        const existed = if (std.Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false })) |_| true else |err| switch (err) {
            error.FileNotFound => false,
            else => return err,
        };
        var db: ?*c.sqlite3 = null;
        const result = c.sqlite3_open_v2(path.ptr, &db, c.SQLITE_OPEN_READWRITE | c.SQLITE_OPEN_CREATE | c.SQLITE_OPEN_FULLMUTEX | c.SQLITE_OPEN_NOFOLLOW, null);
        if (result != c.SQLITE_OK) {
            if (db) |handle| _ = c.sqlite3_close(handle);
            try check(result);
            unreachable;
        }
        const owned_key_id = allocator.dupe(u8, key_id) catch |err| {
            _ = c.sqlite3_close(db.?);
            return err;
        };
        var self: Store = .{ .allocator = allocator, .io = io, .db = db.?, .key = key, .key_id = owned_key_id, .owner_thread = std.Thread.getCurrentId() };
        errdefer self.close();
        // Legacy refusal precedes journal-mode changes as well as schema or
        // authority writes, including a retained database in DELETE mode.
        const opening_version = try self.scalar("PRAGMA user_version;");
        if (opening_version == 2) {
            try self.verifyKey(false);
            return error.RecoveryMigrationRequired;
        }
        if (opening_version == 1 or (opening_version == 0 and existed)) return error.RecoveryMigrationRequired;
        if (opening_version != 0 and opening_version != 3) return error.UnsupportedSchema;
        if (opening_version == 3) {
            // Refusal must preserve even an existing DELETE-mode database.
            // Authenticate before journal-mode configuration, then repeat the
            // checks inside the exclusive transaction before typed recovery.
            if (try self.scalar("SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN ('custody','snapshot','tombstones','grants','operations','grant_generations','recovery_checkpoint');") != 7) return error.MissingSchema;
            try self.verifyKey(false);
            self.authority = try recovery.FileAuthority.open(io, allocator, path, key_id, key);
            const independent = try self.authority.?.read();
            self.checkpoint = try self.readCheckpoint();
            try independent.verify(self.checkpoint);
            if (try self.scalar("SELECT count(*) FROM snapshot WHERE id=1;") != 1) return error.MissingSnapshot;
            const stmt = try self.prepare("SELECT revision,metadata_json FROM snapshot WHERE id=1;");
            defer finalize(stmt);
            try expectRow(stmt);
            const json = try textColumn(stmt, 1);
            try validateMetadata(allocator, json);
            const revision = try integerColumn(stmt, 0);
            try self.verifySnapshot(revision, json);
            if (validator) |validate| {
                try self.validateActorRecovery(allocator, json, revision);
                try validate(allocator, json, revision);
            }
        }
        try self.exec("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; PRAGMA secure_delete=ON; PRAGMA busy_timeout=0; PRAGMA locking_mode=EXCLUSIVE;");
        try self.exec("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;");
        {
            const stmt = try self.prepare("PRAGMA journal_mode;");
            defer finalize(stmt);
            try expectRow(stmt);
            const mode = try textColumn(stmt, 0);
            if (!std.mem.eql(u8, mode, "wal") and !(std.mem.eql(u8, path, ":memory:") and std.mem.eql(u8, mode, "memory"))) return error.WalUnavailable;
        }
        try self.exec("BEGIN EXCLUSIVE;");
        errdefer self.rollback();
        const version = try self.scalar("PRAGMA user_version;");
        // A v1 backup has no independent authority. Automatically migrating it
        // would bless whatever forgotten/rotated state that backup contains.
        if (version == 1 or (version == 0 and existed)) return error.RecoveryMigrationRequired;
        if (version != 0 and version != 2 and version != 3) return error.UnsupportedSchema;
        // The former independent lineage never authenticated metadata. Check
        // the supplied vault key first, then hold migration without DDL,
        // authority publication, typed defaults or SQL rotation recovery.
        if (version == 2) {
            try self.verifyKey(false);
            return error.RecoveryMigrationRequired;
        }
        if (version == 3 and try self.scalar("SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN ('custody','snapshot','tombstones','grants','operations','grant_generations','recovery_checkpoint');") != 7) return error.MissingSchema;
        if (version == 0) try self.exec(
            "CREATE TABLE IF NOT EXISTS custody (id INTEGER PRIMARY KEY CHECK(id=1),key_id TEXT NOT NULL,key_check BLOB NOT NULL);" ++
                "CREATE TABLE IF NOT EXISTS snapshot (id INTEGER PRIMARY KEY CHECK(id=1),revision INTEGER NOT NULL CHECK(revision>=0),metadata_json TEXT NOT NULL);" ++
                "CREATE TABLE IF NOT EXISTS tombstones (account_id TEXT PRIMARY KEY NOT NULL);" ++
                "CREATE TABLE IF NOT EXISTS grants (account_id TEXT NOT NULL,grant_id TEXT NOT NULL,generation INTEGER NOT NULL CHECK(generation>0),purpose TEXT NOT NULL,scope TEXT NOT NULL,renewal_owner TEXT NOT NULL CHECK(renewal_owner IN ('none','external','omux')),state TEXT NOT NULL CHECK(state IN ('ready','refreshing','quarantined')),ciphertext BLOB NOT NULL,PRIMARY KEY(account_id,grant_id));" ++
                "CREATE TABLE IF NOT EXISTS operations (operation_id TEXT PRIMARY KEY NOT NULL,account_id TEXT NOT NULL,grant_id TEXT NOT NULL,generation INTEGER NOT NULL CHECK(generation>0),state TEXT NOT NULL CHECK(state IN ('started','completed','quarantined')),committed_revision INTEGER);" ++
                "CREATE TABLE IF NOT EXISTS grant_generations (account_id TEXT NOT NULL,grant_id TEXT NOT NULL,generation INTEGER NOT NULL CHECK(generation>0),PRIMARY KEY(account_id,grant_id));" ++
                "CREATE TABLE IF NOT EXISTS recovery_checkpoint (id INTEGER PRIMARY KEY CHECK(id=1),installation BLOB NOT NULL CHECK(length(installation)=32),sequence INTEGER NOT NULL CHECK(sequence>=0),nonce BLOB NOT NULL CHECK(length(nonce)=32),snapshot_revision INTEGER NOT NULL CHECK(snapshot_revision>=0),snapshot_digest BLOB NOT NULL CHECK(length(snapshot_digest)=32));",
        );
        try self.verifyKey(version == 0);
        if (version == 3 and try self.scalar("SELECT count(*) FROM snapshot WHERE id=1;") != 1) return error.MissingSnapshot;
        if (version == 3) {
            // Reject malformed/over-limit stored metadata before either
            // pending rotation recovery or a new recovery-authority reserve.
            const stmt = try self.prepare("SELECT revision,metadata_json FROM snapshot WHERE id=1;");
            defer finalize(stmt);
            try expectRow(stmt);
            const revision = try integerColumn(stmt, 0);
            const json = try textColumn(stmt, 1);
            try validateMetadata(allocator, json);
            // Read independent format before interpreting the SQL tuple: even
            // a schema3 label cannot promote a legacy unsealed authority.
            const authority_checkpoint = try self.authority.?.read();
            self.checkpoint = try self.readCheckpoint();
            try authority_checkpoint.verify(self.checkpoint);
            try self.verifySnapshot(revision, json);
            if (validator) |validate| {
                try self.validateActorRecovery(allocator, json, revision);
                try validate(allocator, json, revision);
            }
        }
        if (version == 0) {
            try self.exec("INSERT INTO snapshot(id,revision,metadata_json) VALUES(1,0,'{}');");
            const initial = try self.snapshotCommitment();
            self.checkpoint = try recovery.Checkpoint.fresh(io, initial.revision, initial.digest);
            try self.writeCheckpoint(self.checkpoint);
            self.authority = try recovery.FileAuthority.open(io, allocator, path, key_id, key);
            // Reserve before SQLite commits, including first initialization.
            // An interrupted initialization is never silently reseeded.
            try self.authority.?.initialize(self.checkpoint);
        }
        if (version == 0) try self.exec("PRAGMA user_version=3;");
        try self.exec("COMMIT;");
        _ = try self.reconcilePendingRotations();
        return self;
    }

    fn validateActorRecovery(self: *Store, allocator: std.mem.Allocator, json: []const u8, revision: u64) !void {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, json, .{});
        defer parsed.deinit();
        // Only a genuine interrupted first initialization may use the empty
        // metadata object. Typed actor defaults cannot erase retained grants,
        // tombstones, generation history or work authority from an existing DB.
        if (parsed.value.object.count() == 0) {
            if (revision != 0 or try self.scalar("SELECT (SELECT count(*) FROM grants)+(SELECT count(*) FROM operations)+(SELECT count(*) FROM tombstones)+(SELECT count(*) FROM grant_generations);") != 0 or (try self.readCheckpoint()).sequence != 0) return error.SnapshotAdmissionMigrationRequired;
        } else if (!parsed.value.object.contains("state")) return error.SnapshotAdmissionMigrationRequired;

        // Current actors import externally owned grants and issue no SQL
        // renewal rotations. A metadata-only callback cannot correlate or
        // simulate SQL-only unresolved custody, even when JSON names schema2.
        // A future renewal adapter needs a typed SQL obligation/simulation gate
        // before automatic reconciliation can be enabled for actor startup.
        // Generic Store.open/openRoot retain their independent quarantine API.
        if (try self.scalar("SELECT (SELECT count(*) FROM operations WHERE state='started')+(SELECT count(*) FROM grants WHERE state='refreshing');") != 0) return error.SnapshotAdmissionMigrationRequired;
    }

    /// Read public wrapping-key identity before requesting the corresponding
    /// OS-vault root. No key is guessed or created for an existing database.
    /// The caller owns the returned sentinel buffer and must free it.
    pub fn readRootId(allocator: std.mem.Allocator, path: [:0]const u8) ![:0]u8 {
        var db: ?*c.sqlite3 = null;
        const result = c.sqlite3_open_v2(path.ptr, &db, c.SQLITE_OPEN_READONLY | c.SQLITE_OPEN_FULLMUTEX | c.SQLITE_OPEN_NOFOLLOW, null);
        defer {
            if (db) |handle| _ = c.sqlite3_close(handle);
        }
        try check(result);
        var stmt: ?*c.sqlite3_stmt = null;
        try check(c.sqlite3_prepare_v2(db.?, "SELECT key_id FROM custody WHERE id=1;", -1, &stmt, null));
        defer finalize(stmt.?);
        try expectRow(stmt.?);
        const key_id = try textColumn(stmt.?, 0);
        if (key_id.len == 0 or key_id.len > 128) return error.InvalidKeyIdentity;
        return allocator.dupeSentinel(u8, key_id, 0);
    }

    pub fn close(self: *Store) void {
        // No child statements escape this object; close cannot be SQLITE_BUSY.
        const result = c.sqlite3_close(self.db);
        std.debug.assert(result == c.SQLITE_OK);
        std.crypto.secureZero(u8, &self.key);
        if (self.authority) |*authority| authority.deinit();
        self.allocator.free(self.key_id);
        self.* = undefined;
    }

    fn assertOwner(self: *Store) !void {
        if (self.owner_thread != std.Thread.getCurrentId()) return error.WrongOwnerThread;
        if (self.poisoned) return error.DatabasePoisoned;
    }

    fn prepare(self: *Store, sql: [:0]const u8) !*c.sqlite3_stmt {
        var stmt: ?*c.sqlite3_stmt = null;
        try check(c.sqlite3_prepare_v2(self.db, sql.ptr, -1, &stmt, null));
        return stmt orelse error.DatabaseFailure;
    }

    fn exec(self: *Store, sql: [:0]const u8) !void {
        // Never expose SQLite diagnostics: even malformed imported data must
        // not make an error string or a SQL trace into a credential channel.
        try check(c.sqlite3_exec(self.db, sql.ptr, null, null, null));
    }

    fn scalar(self: *Store, sql: [:0]const u8) !u64 {
        const stmt = try self.prepare(sql);
        defer finalize(stmt);
        try expectRow(stmt);
        return integerColumn(stmt, 0);
    }

    fn rollback(self: *Store) void {
        // Keep the triggering error, but prevent subsequent use if SQLite
        // could not establish that the transaction was rolled back.
        self.exec("ROLLBACK;") catch {
            self.poisoned = true;
        };
    }

    fn readCheckpoint(self: *Store) !recovery.Checkpoint {
        const stmt = try self.prepare("SELECT installation,sequence,nonce,snapshot_revision,snapshot_digest FROM recovery_checkpoint WHERE id=1;");
        defer finalize(stmt);
        try expectRow(stmt);
        const installation = try blobColumn(stmt, 0);
        const nonce = try blobColumn(stmt, 2);
        const digest = try blobColumn(stmt, 4);
        if (installation.len != 32 or nonce.len != 32 or digest.len != 32) return error.InvalidRecoveryCheckpoint;
        return .{ .installation = installation[0..32].*, .sequence = try integerColumn(stmt, 1), .nonce = nonce[0..32].*, .snapshot_revision = try integerColumn(stmt, 3), .snapshot_digest = digest[0..32].* };
    }

    fn writeCheckpoint(self: *Store, checkpoint: recovery.Checkpoint) !void {
        const stmt = try self.prepare("INSERT INTO recovery_checkpoint(id,installation,sequence,nonce,snapshot_revision,snapshot_digest) VALUES(1,?1,?2,?3,?4,?5) ON CONFLICT(id) DO UPDATE SET installation=excluded.installation,sequence=excluded.sequence,nonce=excluded.nonce,snapshot_revision=excluded.snapshot_revision,snapshot_digest=excluded.snapshot_digest;");
        defer finalize(stmt);
        try bindBlob(stmt, 1, &checkpoint.installation);
        try bindInteger(stmt, 2, checkpoint.sequence);
        try bindBlob(stmt, 3, &checkpoint.nonce);
        try bindInteger(stmt, 4, checkpoint.snapshot_revision);
        try bindBlob(stmt, 5, &checkpoint.snapshot_digest);
        try expectDone(stmt);
    }

    const SnapshotCommitment = struct { revision: u64, digest: [32]u8 };

    /// Hash exact transaction-visible bytes without allocating a second copy.
    fn snapshotCommitment(self: *Store) !SnapshotCommitment {
        const stmt = try self.prepare("SELECT revision,metadata_json FROM snapshot WHERE id=1;");
        defer finalize(stmt);
        try expectRow(stmt);
        const json = try textColumn(stmt, 1);
        if (json.len > maximum_snapshot_bytes) return error.SnapshotTooLarge;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(json, &digest, .{});
        return .{ .revision = try integerColumn(stmt, 0), .digest = digest };
    }

    fn verifySnapshot(self: *Store, revision: u64, json: []const u8) !void {
        if (json.len > maximum_snapshot_bytes) return error.SnapshotTooLarge;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(json, &digest, .{});
        if (revision != self.checkpoint.snapshot_revision or !std.crypto.timing_safe.eql([32]u8, digest, self.checkpoint.snapshot_digest)) return error.SnapshotAuthenticationFailed;
    }

    /// Every authorization mutation crosses this fence. After reserving, even
    /// an unsuccessful/ambiguous SQLite COMMIT prevents further use. The older
    /// DB cannot be admitted on restart, or used to repeat issuer contact.
    fn finishMutation(self: *Store) !void {
        const snapshot = try self.snapshotCommitment();
        const next = try self.checkpoint.successor(self.io, snapshot.revision, snapshot.digest);
        if (next.sequence > std.math.maxInt(i64)) return error.RecoverySequenceExhausted;
        try self.writeCheckpoint(next);
        self.authority.?.reserve(self.checkpoint, next) catch |err| {
            self.poisoned = true;
            return err;
        };
        self.exec("COMMIT;") catch |err| {
            self.poisoned = true;
            return err;
        };
        self.checkpoint = next;
    }

    fn verifyKey(self: *Store, allow_initialization: bool) !void {
        var context = key_check_context;
        context.key_id = self.key_id;
        const stmt = try self.prepare("SELECT key_id,key_check FROM custody WHERE id=1;");
        defer finalize(stmt);
        switch (c.sqlite3_step(stmt)) {
            c.SQLITE_ROW => {
                if (!std.mem.eql(u8, self.key_id, try textColumn(stmt, 0))) return error.WrongKeyIdentity;
                var secret = envelope.open(self.allocator, self.key, context, try blobColumn(stmt, 1)) catch |err| switch (err) {
                    error.OutOfMemory => return err,
                    else => return error.WrongKey,
                };
                defer secret.deinit();
                if (!std.mem.eql(u8, secret.bytes, key_check_plaintext)) return error.WrongKey;
            },
            c.SQLITE_DONE => {
                if (!allow_initialization or try self.scalar("SELECT (SELECT count(*) FROM snapshot)+(SELECT count(*) FROM grants)+(SELECT count(*) FROM operations)+(SELECT count(*) FROM tombstones)+(SELECT count(*) FROM grant_generations);") != 0) return error.MissingKeyCheck;
                const ciphertext = try envelope.seal(self.io, self.allocator, self.key, context, key_check_plaintext);
                defer self.allocator.free(ciphertext);
                const insert = try self.prepare("INSERT INTO custody(id,key_id,key_check) VALUES(1,?1,?2);");
                defer finalize(insert);
                try bindText(insert, 1, self.key_id);
                try bindBlob(insert, 2, ciphertext);
                try expectDone(insert);
            },
            else => |result| try check(result),
        }
    }

    pub fn readSnapshot(self: *Store) !Snapshot {
        try self.assertOwner();
        const stmt = try self.prepare("SELECT revision,metadata_json FROM snapshot WHERE id=1;");
        defer finalize(stmt);
        try expectRow(stmt);
        const revision = try integerColumn(stmt, 0);
        const json = try textColumn(stmt, 1);
        // Stored snapshots have the same contract as new commits. In
        // particular, do not allocate an unbounded owned copy on restart.
        try validateMetadata(self.allocator, json);
        try self.verifySnapshot(revision, json);
        return .{ .allocator = self.allocator, .revision = revision, .json = try self.allocator.dupe(u8, json) };
    }

    /// Snapshot JSON is metadata only. Secret-bearing fields are rejected as
    /// defense in depth; provider adapters import payloads via GrantChange.put.
    /// Caller-owned input secrets are never copied into the metadata snapshot.
    pub fn commit(self: *Store, expected_revision: u64, snapshot_json: []const u8, changes: []const GrantChange) !u64 {
        try self.assertOwner();
        try validateMetadata(self.allocator, snapshot_json);
        const sealed = try self.allocator.alloc(?[]u8, changes.len);
        @memset(sealed, null);
        defer {
            for (sealed) |ciphertext| if (ciphertext) |bytes| self.allocator.free(bytes);
            self.allocator.free(sealed);
        }
        // Encryption and entropy acquisition happen before taking the writer
        // transaction; SQLite never sees the source plaintext.
        for (changes, 0..) |change, index| switch (change) {
            .put => |grant_put| {
                if (!std.mem.eql(u8, self.key_id, grant_put.context.key_id)) return error.WrongKeyIdentity;
                sealed[index] = try envelope.seal(self.io, self.allocator, self.key, grant_put.context, grant_put.plaintext);
            },
            .delete, .tombstone_account, .reenroll_account => {},
        };
        try self.exec("BEGIN IMMEDIATE;");
        errdefer self.rollback();
        const next_revision = try self.checkRevision(expected_revision);
        for (changes, 0..) |change, index| switch (change) {
            .put => |grant_put| try self.put(grant_put, sealed[index].?),
            .delete => |remove| try self.deleteGrant(remove.account_id, remove.grant_id),
            .tombstone_account => |account_id| try self.tombstoneAccount(account_id),
            .reenroll_account => |account_id| {
                if (account_id.len == 0) return error.InvalidContext;
                const stmt = try self.prepare("DELETE FROM tombstones WHERE account_id=?1;");
                defer finalize(stmt);
                try bindText(stmt, 1, account_id);
                try expectDone(stmt);
            },
        };
        try self.updateSnapshot(next_revision, snapshot_json);
        try self.finishMutation();
        return next_revision;
    }

    fn checkRevision(self: *Store, expected: u64) !u64 {
        if (try self.scalar("SELECT revision FROM snapshot WHERE id=1;") != expected) return error.RevisionConflict;
        if (expected >= std.math.maxInt(i64)) return error.RevisionExhausted;
        return expected + 1;
    }

    fn bumpRevision(self: *Store) !void {
        const revision = try self.scalar("SELECT revision FROM snapshot WHERE id=1;");
        if (revision >= std.math.maxInt(i64)) return error.RevisionExhausted;
        try self.exec("UPDATE snapshot SET revision=revision+1 WHERE id=1;");
    }

    fn updateSnapshot(self: *Store, revision: u64, json: []const u8) !void {
        const stmt = try self.prepare("UPDATE snapshot SET revision=?1,metadata_json=?2 WHERE id=1;");
        defer finalize(stmt);
        try bindInteger(stmt, 1, revision);
        try bindText(stmt, 2, json);
        try expectDone(stmt);
    }

    fn put(self: *Store, grant: GrantPut, ciphertext: []const u8) !void {
        if (try self.isTombstoned(grant.context.account_id)) return error.AccountForgotten;
        if (grant.context.generation != try self.nextGeneration(grant.context.account_id, grant.context.grant_id)) return error.StaleGeneration;
        const lookup = try self.prepare("SELECT generation,state FROM grants WHERE account_id=?1 AND grant_id=?2;");
        defer finalize(lookup);
        try bindText(lookup, 1, grant.context.account_id);
        try bindText(lookup, 2, grant.context.grant_id);
        switch (c.sqlite3_step(lookup)) {
            c.SQLITE_ROW => {
                const old_generation = try integerColumn(lookup, 0);
                if (old_generation == std.math.maxInt(i64) or grant.context.generation != old_generation + 1) return error.StaleGeneration;
                if (std.mem.eql(u8, try textColumn(lookup, 1), "refreshing")) return error.RotationInProgress;
            },
            c.SQLITE_DONE => {},
            else => |result| try check(result),
        }
        const stmt = try self.prepare("INSERT INTO grants(account_id,grant_id,generation,purpose,scope,renewal_owner,state,ciphertext) VALUES(?1,?2,?3,?4,?5,?6,'ready',?7) ON CONFLICT(account_id,grant_id) DO UPDATE SET generation=excluded.generation,purpose=excluded.purpose,scope=excluded.scope,renewal_owner=excluded.renewal_owner,state='ready',ciphertext=excluded.ciphertext;");
        defer finalize(stmt);
        try bindContext(stmt, grant.context);
        try bindText(stmt, 6, @tagName(grant.renewal_owner));
        try bindBlob(stmt, 7, ciphertext);
        try expectDone(stmt);
        try self.recordGeneration(grant.context);
    }

    /// Deletion retains the generation watermark so a re-enrollment cannot
    /// revive a lease referring to an older grant with the same opaque IDs.
    pub fn nextGeneration(self: *Store, account_id: []const u8, grant_id: []const u8) !u64 {
        try self.assertOwner();
        const stmt = try self.prepare("SELECT generation FROM grant_generations WHERE account_id=?1 AND grant_id=?2;");
        defer finalize(stmt);
        try bindText(stmt, 1, account_id);
        try bindText(stmt, 2, grant_id);
        switch (c.sqlite3_step(stmt)) {
            c.SQLITE_DONE => return 1,
            c.SQLITE_ROW => {
                const generation = try integerColumn(stmt, 0);
                if (generation >= std.math.maxInt(i64)) return error.GenerationExhausted;
                return generation + 1;
            },
            else => |result| {
                try check(result);
                return error.DatabaseFailure;
            },
        }
    }

    fn recordGeneration(self: *Store, context: envelope.Context) !void {
        const stmt = try self.prepare("INSERT INTO grant_generations(account_id,grant_id,generation) VALUES(?1,?2,?3) ON CONFLICT(account_id,grant_id) DO UPDATE SET generation=excluded.generation;");
        defer finalize(stmt);
        try bindText(stmt, 1, context.account_id);
        try bindText(stmt, 2, context.grant_id);
        try bindInteger(stmt, 3, context.generation);
        try expectDone(stmt);
    }

    pub fn isTombstoned(self: *Store, account_id: []const u8) !bool {
        try self.assertOwner();
        const stmt = try self.prepare("SELECT 1 FROM tombstones WHERE account_id=?1;");
        defer finalize(stmt);
        try bindText(stmt, 1, account_id);
        return switch (c.sqlite3_step(stmt)) {
            c.SQLITE_ROW => true,
            c.SQLITE_DONE => false,
            else => |result| blk: {
                try check(result);
                break :blk false;
            },
        };
    }

    fn deleteGrant(self: *Store, account_id: []const u8, grant_id: []const u8) !void {
        const stmt = try self.prepare("DELETE FROM grants WHERE account_id=?1 AND grant_id=?2;");
        defer finalize(stmt);
        try bindText(stmt, 1, account_id);
        try bindText(stmt, 2, grant_id);
        try expectDone(stmt);
        const pending = try self.prepare("UPDATE operations SET state='quarantined' WHERE account_id=?1 AND grant_id=?2 AND state='started';");
        defer finalize(pending);
        try bindText(pending, 1, account_id);
        try bindText(pending, 2, grant_id);
        try expectDone(pending);
    }

    fn tombstoneAccount(self: *Store, account_id: []const u8) !void {
        if (account_id.len == 0) return error.InvalidContext;
        const tombstone = try self.prepare("INSERT OR IGNORE INTO tombstones(account_id) VALUES(?1);");
        defer finalize(tombstone);
        try bindText(tombstone, 1, account_id);
        try expectDone(tombstone);
        const remove = try self.prepare("DELETE FROM grants WHERE account_id=?1;");
        defer finalize(remove);
        try bindText(remove, 1, account_id);
        try expectDone(remove);
        const pending = try self.prepare("UPDATE operations SET state='quarantined' WHERE account_id=?1 AND state='started';");
        defer finalize(pending);
        try bindText(pending, 1, account_id);
        try expectDone(pending);
    }

    pub fn loadGrant(self: *Store, context: envelope.Context) !envelope.Secret {
        try self.assertOwner();
        try context.validate();
        if (!std.mem.eql(u8, self.key_id, context.key_id)) return error.WrongKeyIdentity;
        const stmt = try self.prepare("SELECT generation,state,ciphertext FROM grants WHERE account_id=?1 AND grant_id=?2;");
        defer finalize(stmt);
        try bindText(stmt, 1, context.account_id);
        try bindText(stmt, 2, context.grant_id);
        switch (c.sqlite3_step(stmt)) {
            c.SQLITE_ROW => {},
            c.SQLITE_DONE => return error.GrantUnavailable,
            else => |result| {
                try check(result);
                return error.DatabaseFailure;
            },
        }
        if (try integerColumn(stmt, 0) != context.generation) return error.StaleGeneration;
        const state = try textColumn(stmt, 1);
        if (std.mem.eql(u8, state, "refreshing")) return error.RotationInProgress;
        if (!std.mem.eql(u8, state, "ready")) return error.GrantQuarantined;
        return envelope.open(self.allocator, self.key, context, try blobColumn(stmt, 2));
    }

    /// Credential readiness comes from custody state, not a provider metadata
    /// snapshot. Control views and route admission must include this overlay.
    pub fn readGrantStatus(self: *Store, account_id: []const u8, grant_id: []const u8) !?GrantStatus {
        try self.assertOwner();
        const stmt = try self.prepare("SELECT generation,state,renewal_owner FROM grants WHERE account_id=?1 AND grant_id=?2;");
        defer finalize(stmt);
        try bindText(stmt, 1, account_id);
        try bindText(stmt, 2, grant_id);
        switch (c.sqlite3_step(stmt)) {
            c.SQLITE_DONE => return null,
            c.SQLITE_ROW => return .{
                .generation = try integerColumn(stmt, 0),
                .state = std.meta.stringToEnum(GrantState, try textColumn(stmt, 1)) orelse return error.DatabaseCorrupt,
                .renewal_owner = std.meta.stringToEnum(RenewalOwner, try textColumn(stmt, 2)) orelse return error.DatabaseCorrupt,
            },
            else => |result| {
                try check(result);
                return error.DatabaseFailure;
            },
        }
    }

    /// Commit intent before contacting a rotating-token issuer. Only adopted
    /// Omux grants are eligible; external browser/native lineages are excluded.
    /// Reusing an operation ID returns its durable status without issuing again.
    pub fn beginRotation(self: *Store, context: envelope.Context, operation_id: []const u8) !RotationBegin {
        try self.assertOwner();
        try context.validate();
        if (operation_id.len == 0 or operation_id.len > 4096) return error.InvalidOperation;
        try self.exec("BEGIN IMMEDIATE;");
        errdefer self.rollback();
        const previous = try self.prepare("SELECT account_id,grant_id,generation,state FROM operations WHERE operation_id=?1;");
        defer finalize(previous);
        try bindText(previous, 1, operation_id);
        switch (c.sqlite3_step(previous)) {
            c.SQLITE_ROW => {
                if (!std.mem.eql(u8, try textColumn(previous, 0), context.account_id) or !std.mem.eql(u8, try textColumn(previous, 1), context.grant_id) or try integerColumn(previous, 2) != context.generation) return error.OperationConflict;
                const status = try parseRotationStatus(try textColumn(previous, 3));
                try self.exec("COMMIT;");
                return .{ .status = status, .may_issue = false };
            },
            c.SQLITE_DONE => {},
            else => |result| try check(result),
        }
        var old_secret = try self.loadGrant(context);
        old_secret.deinit();
        const update = try self.prepare("UPDATE grants SET state='refreshing' WHERE account_id=?1 AND grant_id=?2 AND generation=?3 AND renewal_owner='omux' AND state='ready';");
        defer finalize(update);
        try bindText(update, 1, context.account_id);
        try bindText(update, 2, context.grant_id);
        try bindInteger(update, 3, context.generation);
        try expectDone(update);
        if (c.sqlite3_changes(self.db) != 1) return error.RenewalNotOwned;
        const insert = try self.prepare("INSERT INTO operations(operation_id,account_id,grant_id,generation,state) VALUES(?1,?2,?3,?4,'started');");
        defer finalize(insert);
        try bindText(insert, 1, operation_id);
        try bindText(insert, 2, context.account_id);
        try bindText(insert, 3, context.grant_id);
        try bindInteger(insert, 4, context.generation);
        try expectDone(insert);
        try self.bumpRevision();
        try self.finishMutation();
        return .{ .status = .started, .may_issue = true };
    }

    /// Atomically install the successor generation and snapshot after the
    /// provider responds. Never restore a previous rotating refresh token.
    pub fn completeRotation(self: *Store, operation_id: []const u8, expected_revision: u64, snapshot_json: []const u8, successor: envelope.Context, plaintext: []const u8) !u64 {
        try self.assertOwner();
        try validateMetadata(self.allocator, snapshot_json);
        if (!std.mem.eql(u8, self.key_id, successor.key_id)) return error.WrongKeyIdentity;
        const ciphertext = try envelope.seal(self.io, self.allocator, self.key, successor, plaintext);
        defer self.allocator.free(ciphertext);
        try self.exec("BEGIN IMMEDIATE;");
        errdefer self.rollback();
        const operation = try self.prepare("SELECT account_id,grant_id,generation,state,committed_revision FROM operations WHERE operation_id=?1;");
        defer finalize(operation);
        try bindText(operation, 1, operation_id);
        try expectRow(operation);
        const previous_generation = try integerColumn(operation, 2);
        if (!std.mem.eql(u8, try textColumn(operation, 0), successor.account_id) or !std.mem.eql(u8, try textColumn(operation, 1), successor.grant_id) or previous_generation == std.math.maxInt(i64) or successor.generation != previous_generation + 1) return error.OperationConflict;
        switch (try parseRotationStatus(try textColumn(operation, 3))) {
            .completed => {
                const revision = try integerColumn(operation, 4);
                try self.exec("COMMIT;");
                return revision;
            },
            .quarantined => return error.GrantQuarantined,
            .started => {},
        }
        const revision = try self.checkRevision(expected_revision);
        const update = try self.prepare("UPDATE grants SET generation=?3,purpose=?4,scope=?5,ciphertext=?6,state='ready' WHERE account_id=?1 AND grant_id=?2 AND generation=?7 AND state='refreshing' AND renewal_owner='omux';");
        defer finalize(update);
        try bindContext(update, successor);
        try bindBlob(update, 6, ciphertext);
        try bindInteger(update, 7, previous_generation);
        try expectDone(update);
        if (c.sqlite3_changes(self.db) != 1) return error.RotationConflict;
        try self.recordGeneration(successor);
        const finish = try self.prepare("UPDATE operations SET state='completed',committed_revision=?2 WHERE operation_id=?1 AND state='started';");
        defer finalize(finish);
        try bindText(finish, 1, operation_id);
        try bindInteger(finish, 2, revision);
        try expectDone(finish);
        try self.updateSnapshot(revision, snapshot_json);
        try self.finishMutation();
        return revision;
    }

    pub fn readOperation(self: *Store, operation_id: []const u8) !?Operation {
        try self.assertOwner();
        const stmt = try self.prepare("SELECT state,generation,committed_revision FROM operations WHERE operation_id=?1;");
        defer finalize(stmt);
        try bindText(stmt, 1, operation_id);
        switch (c.sqlite3_step(stmt)) {
            c.SQLITE_DONE => return null,
            c.SQLITE_ROW => return .{
                .status = try parseRotationStatus(try textColumn(stmt, 0)),
                .generation = try integerColumn(stmt, 1),
                .committed_revision = if (c.sqlite3_column_type(stmt, 2) == c.SQLITE_NULL) null else try integerColumn(stmt, 2),
            },
            else => |result| {
                try check(result);
                return error.DatabaseFailure;
            },
        }
    }

    /// Fail-closed resolution of a transport timeout/ambiguous issuer reply
    /// while the daemon remains alive. Other grant rotations remain untouched.
    pub fn quarantineRotation(self: *Store, operation_id: []const u8) !void {
        try self.assertOwner();
        try self.exec("BEGIN IMMEDIATE;");
        errdefer self.rollback();
        const stmt = try self.prepare("UPDATE grants SET state='quarantined' WHERE state='refreshing' AND EXISTS(SELECT 1 FROM operations WHERE operation_id=?1 AND state='started' AND operations.account_id=grants.account_id AND operations.grant_id=grants.grant_id AND operations.generation=grants.generation);");
        defer finalize(stmt);
        try bindText(stmt, 1, operation_id);
        try expectDone(stmt);
        const changed_grant = c.sqlite3_changes(self.db) != 0;
        const operation = try self.prepare("UPDATE operations SET state='quarantined' WHERE operation_id=?1 AND state='started';");
        defer finalize(operation);
        try bindText(operation, 1, operation_id);
        try expectDone(operation);
        if (changed_grant or c.sqlite3_changes(self.db) != 0) {
            try self.bumpRevision();
            try self.finishMutation();
        } else try self.exec("COMMIT;");
    }

    /// Called automatically on open. A crash between issuance and commit
    /// leaves an ambiguous lineage, not permission to retry the old token.
    pub fn reconcilePendingRotations(self: *Store) !u64 {
        try self.assertOwner();
        try self.exec("BEGIN IMMEDIATE;");
        errdefer self.rollback();
        const count = try self.scalar("SELECT count(*) FROM operations WHERE state='started';");
        try self.exec("UPDATE grants SET state='quarantined' WHERE state='refreshing';");
        const changed_grant = c.sqlite3_changes(self.db) != 0;
        try self.exec("UPDATE operations SET state='quarantined' WHERE state='started';");
        if (changed_grant or count != 0) {
            try self.bumpRevision();
            try self.finishMutation();
        } else try self.exec("COMMIT;");
        return count;
    }
};

fn check(result: c_int) !void {
    switch (result & 0xff) {
        c.SQLITE_OK, c.SQLITE_ROW, c.SQLITE_DONE => {},
        c.SQLITE_BUSY, c.SQLITE_LOCKED => return error.StoreBusy,
        c.SQLITE_NOMEM => return error.OutOfMemory,
        c.SQLITE_READONLY, c.SQLITE_PERM, c.SQLITE_AUTH => return error.DatabaseDenied,
        c.SQLITE_CORRUPT, c.SQLITE_NOTADB => return error.DatabaseCorrupt,
        c.SQLITE_FULL, c.SQLITE_IOERR, c.SQLITE_CANTOPEN => return error.DatabaseIo,
        c.SQLITE_CONSTRAINT => return error.ConstraintViolation,
        else => return error.DatabaseFailure,
    }
}

fn finalize(stmt: *c.sqlite3_stmt) void {
    // sqlite3_finalize repeats a prior step error. The original step is checked
    // by the caller; finalization still releases the statement in that case.
    _ = c.sqlite3_finalize(stmt);
}

fn expectRow(stmt: *c.sqlite3_stmt) !void {
    const result = c.sqlite3_step(stmt);
    if (result == c.SQLITE_ROW) return;
    try check(result);
    return error.RecordMissing;
}

fn expectDone(stmt: *c.sqlite3_stmt) !void {
    const result = c.sqlite3_step(stmt);
    if (result == c.SQLITE_DONE) return;
    try check(result);
    return error.DatabaseFailure;
}

fn bindText(stmt: *c.sqlite3_stmt, index: c_int, value: []const u8) !void {
    if (value.len > std.math.maxInt(c_int)) return error.ValueTooLarge;
    // SQLITE_STATIC is safe: every statement is finalized before its input
    // buffers leave scope. No SQL string interpolation occurs anywhere.
    try check(c.sqlite3_bind_text(stmt, index, value.ptr, @intCast(value.len), null));
}

fn bindBlob(stmt: *c.sqlite3_stmt, index: c_int, value: []const u8) !void {
    if (value.len > std.math.maxInt(c_int)) return error.ValueTooLarge;
    try check(c.sqlite3_bind_blob(stmt, index, value.ptr, @intCast(value.len), null));
}

fn bindInteger(stmt: *c.sqlite3_stmt, index: c_int, value: u64) !void {
    if (value > std.math.maxInt(i64)) return error.ValueTooLarge;
    try check(c.sqlite3_bind_int64(stmt, index, @intCast(value)));
}

fn bindContext(stmt: *c.sqlite3_stmt, context: envelope.Context) !void {
    try bindText(stmt, 1, context.account_id);
    try bindText(stmt, 2, context.grant_id);
    try bindInteger(stmt, 3, context.generation);
    try bindText(stmt, 4, context.purpose);
    try bindText(stmt, 5, context.scope);
}

fn integerColumn(stmt: *c.sqlite3_stmt, column: c_int) !u64 {
    if (c.sqlite3_column_type(stmt, column) != c.SQLITE_INTEGER) return error.DatabaseCorrupt;
    const value = c.sqlite3_column_int64(stmt, column);
    if (value < 0) return error.DatabaseCorrupt;
    return @intCast(value);
}

fn textColumn(stmt: *c.sqlite3_stmt, column: c_int) ![]const u8 {
    if (c.sqlite3_column_type(stmt, column) != c.SQLITE_TEXT) return error.DatabaseCorrupt;
    const pointer = c.sqlite3_column_text(stmt, column);
    const length = c.sqlite3_column_bytes(stmt, column);
    if (length < 0 or pointer == null) return error.DatabaseCorrupt;
    return pointer[0..@intCast(length)];
}

fn blobColumn(stmt: *c.sqlite3_stmt, column: c_int) ![]const u8 {
    if (c.sqlite3_column_type(stmt, column) != c.SQLITE_BLOB) return error.DatabaseCorrupt;
    const pointer = c.sqlite3_column_blob(stmt, column) orelse return error.DatabaseCorrupt;
    const length = c.sqlite3_column_bytes(stmt, column);
    if (length < 0) return error.DatabaseCorrupt;
    const bytes: [*]const u8 = @ptrCast(pointer);
    return bytes[0..@intCast(length)];
}

fn parseRotationStatus(value: []const u8) !RotationStatus {
    return std.meta.stringToEnum(RotationStatus, value) orelse error.DatabaseCorrupt;
}

fn validateMetadata(allocator: std.mem.Allocator, json: []const u8) !void {
    if (json.len > maximum_snapshot_bytes) return error.SnapshotTooLarge;
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, json, .{}) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.InvalidSnapshot,
    };
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidSnapshot;
    try validateValue(parsed.value, 0);
}

fn validateValue(value: std.json.Value, depth: usize) error{ InvalidSnapshot, SecretInSnapshot }!void {
    if (depth > 64) return error.InvalidSnapshot;
    switch (value) {
        .object => |object| {
            var iterator = object.iterator();
            while (iterator.next()) |entry| {
                for ([_][]const u8{ "access_token", "refresh_token", "id_token", "api_key", "OPENAI_API_KEY", "password", "cookie", "cookies", "secret", "secrets", "plaintext", "grant_blob", "credential_payload" }) |forbidden| {
                    if (std.ascii.eqlIgnoreCase(entry.key_ptr.*, forbidden)) return error.SecretInSnapshot;
                }
                try validateValue(entry.value_ptr.*, depth + 1);
            }
        },
        .array => |array| for (array.items) |item| try validateValue(item, depth + 1),
        .null, .bool, .integer, .float, .number_string, .string => {},
    }
}

const test_context: envelope.Context = .{ .account_id = "account-1", .grant_id = "grant-1", .generation = 1, .purpose = "request", .scope = "read" };

test "lifecycle terminal fact and mutation replay fence share authenticated commit" {
    const reliability = @import("reliability.zig");
    const lifecycle_commit = @import("reliability_commit.zig");
    const mutation = @import("mutation_authority.zig");
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testPath(allocator, tmp);
    defer allocator.free(path);
    const Saved = struct {
        mutation_authority: mutation.Snapshot = .{},
        lifecycle_measurements: ?*const reliability.LifecycleRecorder = null,
    };
    var ledger = try mutation.Ledger.init(allocator, 4);
    defer ledger.deinit();
    const admission = try ledger.begin("remove-1", "account.forget", @splat(7), 0, 0, .local_atomic);
    const slot = admission.execute;
    const previous = ledger.data.records[slot];
    try ledger.complete(slot, "{\"forgotten\":true}");
    const current = try reliability.LifecycleRecorder.create(allocator, 0, .{});
    defer allocator.destroy(current);
    const prepared = try lifecycle_commit.terminalTransition(allocator, current, previous, ledger.data.records[slot], 0, .{ .operation_correlation = 1, .phase = .remove, .outcome = .success });
    defer allocator.destroy(prepared.recorder);
    const bytes = try std.json.Stringify.valueAlloc(allocator, Saved{ .mutation_authority = ledger.snapshot(), .lifecycle_measurements = prepared.recorder }, .{});
    defer allocator.free(bytes);
    {
        var store = try Store.open(std.testing.io, allocator, path, @splat(30));
        defer store.close();
        _ = try store.commit(0, bytes, &.{});
        // Rejected writes cannot move either the metric or replay authority.
        try std.testing.expectError(error.RevisionConflict, store.commit(0, "{}", &.{}));
    }
    var reopened = try Store.open(std.testing.io, allocator, path, @splat(30));
    defer reopened.close();
    var snapshot = try reopened.readSnapshot();
    defer snapshot.deinit();
    const decoded = try std.json.parseFromSlice(Saved, allocator, snapshot.json, .{});
    defer decoded.deinit();
    var restored = try mutation.Ledger.fromSnapshot(allocator, decoded.value.mutation_authority);
    defer restored.deinit();
    const retry = try restored.begin("remove-1", "account.forget", @splat(7), 0, snapshot.revision, .local_atomic);
    try std.testing.expect(retry == .replay);
    const measurements = try decoded.value.lifecycle_measurements.?.clone(allocator);
    defer allocator.destroy(measurements);
    try std.testing.expectEqual(@as(u64, 1), (try measurements.window(0))[@backingInt(reliability.Phase.remove)][0].count);
}

fn testPath(allocator: std.mem.Allocator, tmp: std.testing.TmpDir) ![:0]u8 {
    const directory_path = try std.fmt.allocPrintSentinel(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer allocator.free(directory_path);
    const directory = std.c.open(directory_path.ptr, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (directory < 0) return error.FixtureOpenFailed;
    defer _ = std.c.close(directory);
    if (std.c.fchmod(directory, 0o700) != 0) return error.FixtureModeFailed;
    return std.fmt.allocPrintSentinel(allocator, ".zig-cache/tmp/{s}/custody.sqlite3", .{tmp.sub_path}, 0);
}

/// Use SQLite's consistent backup view; the independent authority is never
/// exported. Fixture restore below replaces only SQLite, after closing it.
fn backupBytes(store: *Store) ![]u8 {
    var backup_db: ?*c.sqlite3 = null;
    try check(c.sqlite3_open(":memory:", &backup_db));
    defer _ = c.sqlite3_close(backup_db.?);
    const backup = c.sqlite3_backup_init(backup_db.?, "main", store.db, "main") orelse return error.DatabaseFailure;
    const step_result = c.sqlite3_backup_step(backup, -1);
    const finish_result = c.sqlite3_backup_finish(backup);
    if (step_result != c.SQLITE_DONE) try check(step_result);
    try check(finish_result);
    var length: c.sqlite3_int64 = 0;
    const serialized = c.sqlite3_serialize(backup_db.?, "main", &length, 0);
    if (serialized == null or length <= 0) return error.DatabaseFailure;
    defer c.sqlite3_free(serialized);
    return store.allocator.dupe(u8, serialized[0..@intCast(length)]);
}

test "SQLite-only restore cannot resurrect forget authority or explicit reenrollment predecessors" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testPath(allocator, tmp);
    defer allocator.free(path);
    const key: envelope.Key = @splat(61);
    var store = try Store.open(std.testing.io, allocator, path, key);
    _ = try store.commit(0, "{}", &.{.{ .put = .{ .context = test_context, .plaintext = "fixture-predecessor" } }});
    const before_forget = try backupBytes(&store);
    defer allocator.free(before_forget);
    _ = try store.commit(1, "{}", &.{.{ .tombstone_account = test_context.account_id }});
    const forgotten = try backupBytes(&store);
    defer allocator.free(forgotten);
    var next = test_context;
    next.generation = 2;
    _ = try store.commit(2, "{}", &.{ .{ .reenroll_account = test_context.account_id }, .{ .put = .{ .context = next, .plaintext = "fixture-reenrollment" } } });
    store.close();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "custody.sqlite3", .data = before_forget });
    try std.testing.expectError(error.RecoveryRollbackDetected, Store.open(std.testing.io, allocator, path, key));
    // Failed admission must not reseed the authority from this older backup.
    try std.testing.expectError(error.RecoveryRollbackDetected, Store.open(std.testing.io, allocator, path, key));
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "custody.sqlite3", .data = forgotten });
    try std.testing.expectError(error.RecoveryRollbackDetected, Store.open(std.testing.io, allocator, path, key));
}

test "pre-intent and pre-successor SQLite backups cannot reissue a rotating predecessor" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testPath(allocator, tmp);
    defer allocator.free(path);
    const key: envelope.Key = @splat(62);
    var store = try Store.open(std.testing.io, allocator, path, key);
    _ = try store.commit(0, "{}", &.{.{ .put = .{ .context = test_context, .plaintext = "fixture-refresh", .renewal_owner = .omux } }});
    const ready_backup = try backupBytes(&store);
    defer allocator.free(ready_backup);
    try std.testing.expect((try store.beginRotation(test_context, "fixture-rotation")).may_issue);
    const pending_backup = try backupBytes(&store);
    defer allocator.free(pending_backup);
    var successor = test_context;
    successor.generation = 2;
    _ = try store.completeRotation("fixture-rotation", 2, "{}", successor, "fixture-successor");
    const completed_backup = try backupBytes(&store);
    defer allocator.free(completed_backup);
    store.close();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "custody.sqlite3", .data = ready_backup });
    try std.testing.expectError(error.RecoveryRollbackDetected, Store.open(std.testing.io, allocator, path, key));
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "custody.sqlite3", .data = pending_backup });
    try std.testing.expectError(error.RecoveryRollbackDetected, Store.open(std.testing.io, allocator, path, key));
    // A committed result survives a lost response without another issuer call.
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "custody.sqlite3", .data = completed_backup });
    var reopened = try Store.open(std.testing.io, allocator, path, key);
    defer reopened.close();
    const operation = try reopened.beginRotation(test_context, "fixture-rotation");
    try std.testing.expectEqual(RotationStatus.completed, operation.status);
    try std.testing.expect(!operation.may_issue);
    try std.testing.expectError(error.StaleGeneration, reopened.loadGrant(test_context));
}

test "reserve before SQLite commit interruption fences the old database and never reseeds" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testPath(allocator, tmp);
    defer allocator.free(path);
    const key: envelope.Key = @splat(63);
    var store = try Store.open(std.testing.io, allocator, path, key);
    _ = try store.commit(0, "{}", &.{.{ .put = .{ .context = test_context, .plaintext = "fixture" } }});
    const reserved = try store.checkpoint.successor(std.testing.io, store.checkpoint.snapshot_revision, store.checkpoint.snapshot_digest);
    try store.exec("BEGIN IMMEDIATE;");
    try store.writeCheckpoint(reserved);
    try store.authority.?.reserve(store.checkpoint, reserved);
    // Crash point: durable reservation, SQLite transaction not committed.
    store.rollback();
    store.poisoned = true;
    try std.testing.expectError(error.DatabasePoisoned, store.loadGrant(test_context));
    store.close();
    try std.testing.expectError(error.RecoveryRollbackDetected, Store.open(std.testing.io, allocator, path, key));
    try std.testing.expectError(error.RecoveryRollbackDetected, Store.open(std.testing.io, allocator, path, key));
}

test "a failed SQLite COMMIT after durable reservation poisons the live writer" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testPath(allocator, tmp);
    defer allocator.free(path);
    const key: envelope.Key = @splat(66);
    var store = try Store.open(std.testing.io, allocator, path, key);
    _ = try store.commit(0, "{}", &.{.{ .put = .{ .context = test_context, .plaintext = "fixture" } }});
    // An actual SQLite deferred-constraint failure at COMMIT, after authority
    // publication, exercises the production fence rather than a synthetic flag.
    try store.exec("CREATE TABLE fixture_parent(id INTEGER PRIMARY KEY); CREATE TABLE fixture_child(parent INTEGER REFERENCES fixture_parent(id) DEFERRABLE INITIALLY DEFERRED);");
    try store.exec("BEGIN IMMEDIATE; INSERT INTO fixture_child VALUES(1);");
    try std.testing.expectError(error.ConstraintViolation, store.finishMutation());
    try std.testing.expectError(error.DatabasePoisoned, store.loadGrant(test_context));
    store.rollback();
    store.close();
    try std.testing.expectError(error.RecoveryRollbackDetected, Store.open(std.testing.io, allocator, path, key));
}

test "missing authority and pre-checkpoint schema require explicit recovery without regeneration" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testPath(allocator, tmp);
    defer allocator.free(path);
    const key: envelope.Key = @splat(64);
    {
        var store = try Store.open(std.testing.io, allocator, path, key);
        store.close();
    }
    try tmp.dir.deleteFile(std.testing.io, "custody.sqlite3.authority");
    try std.testing.expectError(error.MissingRecoveryAuthority, Store.open(std.testing.io, allocator, path, key));
    try std.testing.expectError(error.MissingRecoveryAuthority, Store.open(std.testing.io, allocator, path, key));
    var legacy = std.testing.tmpDir(.{});
    defer legacy.cleanup();
    const legacy_path = try testPath(allocator, legacy);
    defer allocator.free(legacy_path);
    {
        var store = try Store.open(std.testing.io, allocator, legacy_path, key);
        try store.exec("PRAGMA user_version=1;");
        store.close();
    }
    try std.testing.expectError(error.RecoveryMigrationRequired, Store.open(std.testing.io, allocator, legacy_path, key));
}

test "same root does not authorize another installation or a divergent commit nonce" {
    const allocator = std.testing.allocator;
    var first = std.testing.tmpDir(.{});
    defer first.cleanup();
    var second = std.testing.tmpDir(.{});
    defer second.cleanup();
    const first_path = try testPath(allocator, first);
    defer allocator.free(first_path);
    const second_path = try testPath(allocator, second);
    defer allocator.free(second_path);
    const key: envelope.Key = @splat(65);
    var first_store = try Store.open(std.testing.io, allocator, first_path, key);
    const copied = try backupBytes(&first_store);
    defer allocator.free(copied);
    first_store.close();
    {
        var second_store = try Store.open(std.testing.io, allocator, second_path, key);
        second_store.close();
    }
    try second.dir.writeFile(std.testing.io, .{ .sub_path = "custody.sqlite3", .data = copied });
    try std.testing.expectError(error.WrongRecoveryInstallation, Store.open(std.testing.io, allocator, second_path, key));
    {
        var store = try Store.open(std.testing.io, allocator, first_path, key);
        var divergent = store.checkpoint;
        divergent.nonce[0] ^= 1;
        try store.writeCheckpoint(divergent);
        store.close();
    }
    try std.testing.expectError(error.RecoveryCheckpointMismatch, Store.open(std.testing.io, allocator, first_path, key));
}

test "durable metadata and encrypted grants never expose tokens in database WAL or backup" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testPath(allocator, tmp);
    defer allocator.free(path);
    const key: envelope.Key = @splat(29);
    var store = try Store.open(std.testing.io, allocator, path, key);
    defer store.close();
    const token = "plaintext-refresh-token-must-never-be-in-the-wal-72d7c";
    try std.testing.expectEqual(@as(u64, 1), try store.commit(0, "{\"accounts\":[{\"id\":\"account-1\"}]}", &.{.{ .put = .{ .context = test_context, .plaintext = token, .renewal_owner = .omux } }}));
    var secret = try store.loadGrant(test_context);
    defer secret.deinit();
    try std.testing.expectEqualStrings(token, secret.bytes);
    const wal = try tmp.dir.readFileAlloc(std.testing.io, "custody.sqlite3-wal", allocator, .limited(4 * 1024 * 1024));
    defer allocator.free(wal);
    try std.testing.expect(std.mem.indexOf(u8, wal, token) == null);
    try store.exec("PRAGMA wal_checkpoint(FULL);");
    const database = try tmp.dir.readFileAlloc(std.testing.io, "custody.sqlite3", allocator, .limited(4 * 1024 * 1024));
    defer allocator.free(database);
    try std.testing.expect(std.mem.indexOf(u8, database, token) == null);
    // SQLite's backup API must copy ciphertext, just like a file backup.
    var backup_db: ?*c.sqlite3 = null;
    try check(c.sqlite3_open(":memory:", &backup_db));
    defer _ = c.sqlite3_close(backup_db.?);
    const backup = c.sqlite3_backup_init(backup_db.?, "main", store.db, "main") orelse return error.DatabaseFailure;
    try std.testing.expectEqual(c.SQLITE_DONE, c.sqlite3_backup_step(backup, -1));
    try check(c.sqlite3_backup_finish(backup));
    var serialized_length: c.sqlite3_int64 = 0;
    const serialized = c.sqlite3_serialize(backup_db.?, "main", &serialized_length, 0);
    if (serialized == null) return error.DatabaseFailure;
    defer c.sqlite3_free(serialized);
    try std.testing.expect(std.mem.indexOf(u8, serialized[0..@intCast(serialized_length)], token) == null);
    var snapshot = try store.readSnapshot();
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(u64, 1), snapshot.revision);
}

test "atomic revision conflicts roll back every grant change and reject stale generations" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testPath(allocator, tmp);
    defer allocator.free(path);
    var store = try Store.open(std.testing.io, allocator, path, @splat(30));
    defer store.close();
    _ = try store.commit(0, "{}", &.{.{ .put = .{ .context = test_context, .plaintext = "first" } }});
    var next = test_context;
    next.generation = 2;
    try std.testing.expectError(error.RevisionConflict, store.commit(0, "{}", &.{.{ .put = .{ .context = next, .plaintext = "second" } }}));
    try std.testing.expectError(error.StaleGeneration, store.commit(1, "{}", &.{.{ .put = .{ .context = test_context, .plaintext = "stale" } }}));
    var bad = test_context;
    bad.grant_id = "nonexistent";
    bad.generation = 5;
    try std.testing.expectError(error.StaleGeneration, store.commit(1, "{}", &.{ .{ .put = .{ .context = next, .plaintext = "second" } }, .{ .put = .{ .context = bad, .plaintext = "invalid" } } }));
    var secret = try store.loadGrant(test_context);
    defer secret.deinit();
    try std.testing.expectEqualStrings("first", secret.bytes);
    var snapshot = try store.readSnapshot();
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(u64, 1), snapshot.revision);
    const checkpoint_before = store.checkpoint;
    try std.testing.expectError(error.SecretInSnapshot, store.commit(1, "{\"nested\":{\"refresh_token\":\"forbidden\"}}", &.{}));
    try std.testing.expectError(error.SecretInSnapshot, store.commit(1, "{\"nested\":[{\"api_key\":\"forbidden\"}]}", &.{}));
    try std.testing.expectError(error.SecretInSnapshot, store.commit(1, "{\"nested\":[{\"OPENAI_API_KEY\":\"forbidden\"}]}", &.{}));
    var after_rejection = try store.readSnapshot();
    defer after_rejection.deinit();
    try std.testing.expectEqual(snapshot.revision, after_rejection.revision);
    try std.testing.expectEqualStrings(snapshot.json, after_rejection.json);
    try std.testing.expect(checkpoint_before.eql(store.checkpoint));
}

test "stored snapshot validation rejects corrupt metadata before rotation recovery" {
    const allocator = std.testing.allocator;
    const cases = .{
        .{ "UPDATE snapshot SET metadata_json='[]';", error.InvalidSnapshot },
        .{ "UPDATE snapshot SET metadata_json='{';", error.InvalidSnapshot },
        .{ "UPDATE snapshot SET metadata_json='{\"nested\":{\"access_token\":\"rejected\"}}';", error.SecretInSnapshot },
        .{ "UPDATE snapshot SET metadata_json='{\"nested\":[{\"api_key\":\"rejected\"}]}';", error.SecretInSnapshot },
        .{ "UPDATE snapshot SET metadata_json='{\"nested\":[{\"OPENAI_API_KEY\":\"rejected\"}]}';", error.SecretInSnapshot },
        .{ "UPDATE snapshot SET metadata_json=CAST(zeroblob(16777217) AS TEXT);", error.SnapshotTooLarge },
    };
    inline for (cases) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const path = try testPath(allocator, tmp);
        defer allocator.free(path);
        const key: envelope.Key = @splat(53);
        {
            var store = try Store.open(std.testing.io, allocator, path, key);
            defer store.close();
            _ = try store.commit(0, "{}", &.{.{ .put = .{ .context = test_context, .plaintext = "rotation-fixture", .renewal_owner = .omux } }});
            try std.testing.expect((try store.beginRotation(test_context, "pending-before-invalid-snapshot")).may_issue);
            try store.exec(case[0]);
            try std.testing.expectError(case[1], store.readSnapshot());
        }
        const before = try tmp.dir.readFileAlloc(std.testing.io, "custody.sqlite3.authority", allocator, .limited(1024));
        defer allocator.free(before);
        try std.testing.expectError(case[1], Store.open(std.testing.io, allocator, path, key));
        const after = try tmp.dir.readFileAlloc(std.testing.io, "custody.sqlite3.authority", allocator, .limited(1024));
        defer allocator.free(after);
        // Invalid snapshot startup must not reserve a new checkpoint to
        // quarantine rotations, or bless the damaged metadata as a new epoch.
        try std.testing.expectEqualSlices(u8, before, after);
    }
}

fn denyRecoveredSnapshot(_: std.mem.Allocator, _: []const u8, _: u64) anyerror!void {
    return error.ActorSnapshotValidatorRejected;
}

fn acceptRecoveredSnapshot(_: std.mem.Allocator, _: []const u8, _: u64) anyerror!void {}

test "actor snapshot validator runs for explicit quiescent state before authority adoption" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testPath(allocator, tmp);
    defer allocator.free(path);
    const key: envelope.Key = @splat(54);
    const sequence = blk: {
        // A genuinely new store has no legacy snapshot to adopt. Its initial
        // '{}' is deliberately committed by the actor, not passed as schema2.
        var store = try Store.openRootWithSnapshotValidator(std.testing.io, allocator, path, envelope.default_key_id, key, denyRecoveredSnapshot);
        defer store.close();
        _ = try store.commit(0, "{\"state\":{}}", &.{.{ .put = .{ .context = test_context, .plaintext = "quiescent-fixture" } }});
        break :blk store.checkpoint.sequence;
    };
    const before = try tmp.dir.readFileAlloc(std.testing.io, "custody.sqlite3.authority", allocator, .limited(1024));
    defer allocator.free(before);
    try std.testing.expectError(error.WrongKey, Store.openRootWithSnapshotValidator(std.testing.io, allocator, path, envelope.default_key_id, @splat(55), denyRecoveredSnapshot));
    try std.testing.expectError(error.ActorSnapshotValidatorRejected, Store.openRootWithSnapshotValidator(std.testing.io, allocator, path, envelope.default_key_id, key, denyRecoveredSnapshot));
    const after = try tmp.dir.readFileAlloc(std.testing.io, "custody.sqlite3.authority", allocator, .limited(1024));
    defer allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    var admitted = try Store.open(std.testing.io, allocator, path, key);
    defer admitted.close();
    try std.testing.expectEqual(sequence, admitted.checkpoint.sequence);
    var secret = try admitted.loadGrant(test_context);
    defer secret.deinit();
    try std.testing.expectEqualStrings("quiescent-fixture", secret.bytes);
}

test "actor initial empty metadata is admitted only before any history" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testPath(allocator, tmp);
    defer allocator.free(path);
    const key: envelope.Key = @splat(56);
    {
        var store = try Store.open(std.testing.io, allocator, path, key);
        defer store.close();
        // Exact initial bytes are sealed; an out-of-band whitespace rewrite
        // is covered by native_owner_storage_tests and cannot be blessed here.
    }
    try std.testing.expectError(error.ActorSnapshotValidatorRejected, Store.openRootWithSnapshotValidator(std.testing.io, allocator, path, envelope.default_key_id, key, denyRecoveredSnapshot));
    {
        var initial = try Store.openRootWithSnapshotValidator(std.testing.io, allocator, path, envelope.default_key_id, key, acceptRecoveredSnapshot);
        defer initial.close();
        try std.testing.expectEqual(@as(u64, 0), initial.checkpoint.sequence);
        _ = try initial.commit(0, "{}", &.{});
    }
    // Even a metadata-only committed history is no longer initialization.
    try std.testing.expectError(error.SnapshotAdmissionMigrationRequired, Store.openRootWithSnapshotValidator(std.testing.io, allocator, path, envelope.default_key_id, key, acceptRecoveredSnapshot));
}

test "actor hidden SQL rotation is rejected before recovery for every metadata schema" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{ " {} ", "{\"schema_version\":1}", "{\"schema_version\":1,\"state\":{}}", "{\"schema_version\":2,\"state\":{}}" }) |json| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const path = try testPath(allocator, tmp);
        defer allocator.free(path);
        const key: envelope.Key = @splat(57);
        const sequence = blk: {
            var store = try Store.open(std.testing.io, allocator, path, key);
            defer store.close();
            _ = try store.commit(0, json, &.{.{ .put = .{ .context = test_context, .plaintext = "rotation-fixture", .renewal_owner = .omux } }});
            try std.testing.expect((try store.beginRotation(test_context, "pending-before-actor-validator")).may_issue);
            break :blk store.checkpoint.sequence;
        };
        const before = try tmp.dir.readFileAlloc(std.testing.io, "custody.sqlite3.authority", allocator, .limited(1024));
        defer allocator.free(before);
        try std.testing.expectError(error.SnapshotAdmissionMigrationRequired, Store.openRootWithSnapshotValidator(std.testing.io, allocator, path, envelope.default_key_id, key, denyRecoveredSnapshot));
        const after = try tmp.dir.readFileAlloc(std.testing.io, "custody.sqlite3.authority", allocator, .limited(1024));
        defer allocator.free(after);
        try std.testing.expectEqualSlices(u8, before, after);
        // Generic storage retains its independently proved SQL quarantine API;
        // actor admission cannot silently invent a corresponding owner credit.
        var admitted = try Store.open(std.testing.io, allocator, path, key);
        defer admitted.close();
        try std.testing.expectEqual(sequence + 1, admitted.checkpoint.sequence);
        try std.testing.expectEqual(RotationStatus.quarantined, (try admitted.readOperation("pending-before-actor-validator")).?.status);
        try std.testing.expectError(error.GrantQuarantined, admitted.loadGrant(test_context));
    }
}

test "one writer owns the database and a forgotten account cannot be rediscovered" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testPath(allocator, tmp);
    defer allocator.free(path);
    const key: envelope.Key = @splat(31);
    var store = try Store.open(std.testing.io, allocator, path, key);
    defer store.close();
    try std.testing.expectError(error.StoreBusy, Store.open(std.testing.io, allocator, path, key));
    _ = try store.commit(0, "{}", &.{.{ .put = .{ .context = test_context, .plaintext = "first" } }});
    _ = try store.commit(1, "{}", &.{.{ .tombstone_account = test_context.account_id }});
    try std.testing.expect(try store.isTombstoned(test_context.account_id));
    try std.testing.expectError(error.GrantUnavailable, store.loadGrant(test_context));
    try std.testing.expectError(error.AccountForgotten, store.commit(2, "{}", &.{.{ .put = .{ .context = test_context, .plaintext = "rediscovered" } }}));
    var replacement = test_context;
    replacement.generation = try store.nextGeneration(replacement.account_id, replacement.grant_id);
    _ = try store.commit(2, "{}", &.{ .{ .reenroll_account = test_context.account_id }, .{ .put = .{ .context = replacement, .plaintext = "explicitly-reenrolled" } } });
    try std.testing.expect(!try store.isTombstoned(test_context.account_id));
    try std.testing.expectError(error.StaleGeneration, store.loadGrant(test_context));
    var reenrolled = try store.loadGrant(replacement);
    defer reenrolled.deinit();
    try std.testing.expectEqualStrings("explicitly-reenrolled", reenrolled.bytes);
}

test "rotation is owned idempotent and atomically advances ciphertext with metadata" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testPath(allocator, tmp);
    defer allocator.free(path);
    var store = try Store.open(std.testing.io, allocator, path, @splat(32));
    defer store.close();
    _ = try store.commit(0, "{}", &.{.{ .put = .{ .context = test_context, .plaintext = "first", .renewal_owner = .omux } }});
    const begin = try store.beginRotation(test_context, "rotation-1");
    try std.testing.expectEqual(RotationStatus.started, begin.status);
    try std.testing.expect(begin.may_issue);
    const replay = try store.beginRotation(test_context, "rotation-1");
    try std.testing.expectEqual(RotationStatus.started, replay.status);
    try std.testing.expect(!replay.may_issue);
    try std.testing.expectError(error.RotationInProgress, store.beginRotation(test_context, "rotation-2"));
    var next = test_context;
    next.generation = 2;
    try std.testing.expectError(error.RevisionConflict, store.completeRotation("rotation-1", 0, "{}", next, "second"));
    try std.testing.expectError(error.RotationInProgress, store.loadGrant(test_context));
    try std.testing.expectEqual(@as(u64, 3), try store.completeRotation("rotation-1", 2, "{\"generation\":2}", next, "second"));
    try std.testing.expectEqual(@as(u64, 3), try store.completeRotation("rotation-1", 2, "{}", next, "second"));
    try std.testing.expectEqual(RotationStatus.completed, (try store.readOperation("rotation-1")).?.status);
    try std.testing.expectError(error.StaleGeneration, store.loadGrant(test_context));
    var secret = try store.loadGrant(next);
    defer secret.deinit();
    try std.testing.expectEqualStrings("second", secret.bytes);
}

test "oversized rotation completion retains durable issuance and quarantines after restart" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testPath(allocator, tmp);
    defer allocator.free(path);
    const key: envelope.Key = @splat(67);
    const oversized = try allocator.alloc(u8, maximum_snapshot_bytes + 1);
    defer allocator.free(oversized);
    // A valid metadata-only JSON object, exactly one byte above the complete
    // storage envelope limit. No provider request or live rotation occurs here.
    @memset(oversized, 'x');
    const prefix = "{\"padding\":\"";
    @memcpy(oversized[0..prefix.len], prefix);
    @memcpy(oversized[oversized.len - 2 ..], "\"}");
    var successor = test_context;
    successor.generation = 2;
    var pending_checkpoint: recovery.Checkpoint = undefined;
    {
        var store = try Store.open(std.testing.io, allocator, path, key);
        defer store.close();
        _ = try store.commit(0, "{\"phase\":\"before_rotation\"}", &.{.{ .put = .{ .context = test_context, .plaintext = "fixture-predecessor", .renewal_owner = .omux } }});
        const begin = try store.beginRotation(test_context, "oversized-completion");
        try std.testing.expectEqual(RotationStatus.started, begin.status);
        try std.testing.expect(begin.may_issue);
        pending_checkpoint = store.checkpoint;
        try std.testing.expectError(error.SnapshotTooLarge, store.completeRotation("oversized-completion", 2, oversized, successor, "fixture-successor"));
        try std.testing.expect(pending_checkpoint.eql(store.checkpoint));
        try std.testing.expect(pending_checkpoint.eql(try store.authority.?.read()));
        const pending = (try store.readOperation("oversized-completion")).?;
        try std.testing.expectEqual(RotationStatus.started, pending.status);
        try std.testing.expectEqual(test_context.generation, pending.generation);
        try std.testing.expect(pending.committed_revision == null);
        const grant = (try store.readGrantStatus(test_context.account_id, test_context.grant_id)).?;
        try std.testing.expectEqual(GrantState.refreshing, grant.state);
        try std.testing.expectEqual(test_context.generation, grant.generation);
        try std.testing.expectEqual(@as(u64, 2), try store.nextGeneration(test_context.account_id, test_context.grant_id));
        try std.testing.expectError(error.RotationInProgress, store.loadGrant(test_context));
        try std.testing.expectError(error.StaleGeneration, store.loadGrant(successor));
        var snapshot = try store.readSnapshot();
        defer snapshot.deinit();
        try std.testing.expectEqual(@as(u64, 2), snapshot.revision);
        try std.testing.expectEqualStrings("{\"phase\":\"before_rotation\"}", snapshot.json);
        const retry = try store.beginRotation(test_context, "oversized-completion");
        try std.testing.expectEqual(RotationStatus.started, retry.status);
        try std.testing.expect(!retry.may_issue);
        try std.testing.expectError(error.RotationInProgress, store.beginRotation(test_context, "second-writer"));
        try std.testing.expectError(error.StoreBusy, Store.open(std.testing.io, allocator, path, key));
    }
    {
        var reopened = try Store.open(std.testing.io, allocator, path, key);
        defer reopened.close();
        try std.testing.expectEqual(pending_checkpoint.sequence + 1, reopened.checkpoint.sequence);
        const operation = (try reopened.readOperation("oversized-completion")).?;
        try std.testing.expectEqual(RotationStatus.quarantined, operation.status);
        try std.testing.expectEqual(test_context.generation, operation.generation);
        try std.testing.expect(operation.committed_revision == null);
        const grant = (try reopened.readGrantStatus(test_context.account_id, test_context.grant_id)).?;
        try std.testing.expectEqual(GrantState.quarantined, grant.state);
        try std.testing.expectEqual(test_context.generation, grant.generation);
        try std.testing.expectError(error.GrantQuarantined, reopened.loadGrant(test_context));
        try std.testing.expectError(error.StaleGeneration, reopened.loadGrant(successor));
        const retry = try reopened.beginRotation(test_context, "oversized-completion");
        try std.testing.expectEqual(RotationStatus.quarantined, retry.status);
        try std.testing.expect(!retry.may_issue);
        try std.testing.expectError(error.GrantQuarantined, reopened.beginRotation(test_context, "second-writer"));
        try std.testing.expect((try reopened.readOperation("second-writer")) == null);
        try std.testing.expectError(error.GrantQuarantined, reopened.completeRotation("oversized-completion", 3, "{}", successor, "fixture-successor"));
        try std.testing.expectError(error.StoreBusy, Store.open(std.testing.io, allocator, path, key));
    }
}

test "crashed rotations quarantine instead of restoring or retrying old refresh tokens" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testPath(allocator, tmp);
    defer allocator.free(path);
    const key: envelope.Key = @splat(33);
    var pending_sequence: u64 = 0;
    {
        var store = try Store.open(std.testing.io, allocator, path, key);
        defer store.close();
        _ = try store.commit(0, "{}", &.{.{ .put = .{ .context = test_context, .plaintext = "old-lineage", .renewal_owner = .omux } }});
        _ = try store.beginRotation(test_context, "ambiguous-issuance");
        pending_sequence = store.checkpoint.sequence;
    }
    {
        var store = try Store.open(std.testing.io, allocator, path, key);
        defer store.close();
        try std.testing.expectEqual(pending_sequence + 1, store.checkpoint.sequence);
        try std.testing.expectEqual(RotationStatus.quarantined, (try store.readOperation("ambiguous-issuance")).?.status);
        try std.testing.expectError(error.GrantQuarantined, store.loadGrant(test_context));
        const replay = try store.beginRotation(test_context, "ambiguous-issuance");
        try std.testing.expectEqual(RotationStatus.quarantined, replay.status);
        try std.testing.expect(!replay.may_issue);
    }
    try std.testing.expectError(error.WrongKey, Store.open(std.testing.io, allocator, path, @splat(34)));
    var store = try Store.open(std.testing.io, allocator, path, key);
    defer store.close();
    try std.testing.expectError(error.GrantQuarantined, store.loadGrant(test_context));
}

test "external renewal authority is never adopted implicitly" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testPath(allocator, tmp);
    defer allocator.free(path);
    var store = try Store.open(std.testing.io, allocator, path, @splat(35));
    defer store.close();
    _ = try store.commit(0, "{}", &.{.{ .put = .{ .context = test_context, .plaintext = "browser-owned", .renewal_owner = .external } }});
    try std.testing.expectError(error.RenewalNotOwned, store.beginRotation(test_context, "forbidden-rotation"));
    var secret = try store.loadGrant(test_context);
    defer secret.deinit();
    try std.testing.expectEqualStrings("browser-owned", secret.bytes);
}

test "missing initialized custody records fail closed and are never recreated" {
    const allocator = std.testing.allocator;
    const key: envelope.Key = @splat(36);
    var missing_key = std.testing.tmpDir(.{});
    defer missing_key.cleanup();
    const key_path = try testPath(allocator, missing_key);
    defer allocator.free(key_path);
    {
        var store = try Store.open(std.testing.io, allocator, key_path, key);
        defer store.close();
        try store.exec("DELETE FROM custody; DELETE FROM snapshot;");
    }
    try std.testing.expectError(error.MissingKeyCheck, Store.open(std.testing.io, allocator, key_path, key));
    // Retrying must still fail; opening did not commit a replacement check.
    try std.testing.expectError(error.MissingKeyCheck, Store.open(std.testing.io, allocator, key_path, key));
    var missing_snapshot = std.testing.tmpDir(.{});
    defer missing_snapshot.cleanup();
    const snapshot_path = try testPath(allocator, missing_snapshot);
    defer allocator.free(snapshot_path);
    {
        var store = try Store.open(std.testing.io, allocator, snapshot_path, key);
        defer store.close();
        try store.exec("DELETE FROM snapshot;");
    }
    try std.testing.expectError(error.MissingSnapshot, Store.open(std.testing.io, allocator, snapshot_path, key));
    var missing_generations = std.testing.tmpDir(.{});
    defer missing_generations.cleanup();
    const generation_path = try testPath(allocator, missing_generations);
    defer allocator.free(generation_path);
    {
        var store = try Store.open(std.testing.io, allocator, generation_path, key);
        defer store.close();
        try store.exec("DROP TABLE grant_generations;");
    }
    try std.testing.expectError(error.MissingSchema, Store.open(std.testing.io, allocator, generation_path, key));
}

test "targeted ambiguity quarantine publishes a new revision and does not reissue" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testPath(allocator, tmp);
    defer allocator.free(path);
    var store = try Store.open(std.testing.io, allocator, path, @splat(37));
    defer store.close();
    _ = try store.commit(0, "{}", &.{.{ .put = .{ .context = test_context, .plaintext = "lineage", .renewal_owner = .omux } }});
    _ = try store.beginRotation(test_context, "timeout");
    try std.testing.expectEqual(GrantState.refreshing, (try store.readGrantStatus(test_context.account_id, test_context.grant_id)).?.state);
    try store.quarantineRotation("timeout");
    try std.testing.expectEqual(GrantState.quarantined, (try store.readGrantStatus(test_context.account_id, test_context.grant_id)).?.state);
    try std.testing.expectEqual(RotationStatus.quarantined, (try store.readOperation("timeout")).?.status);
    try std.testing.expectError(error.GrantQuarantined, store.loadGrant(test_context));
    var snapshot = try store.readSnapshot();
    defer snapshot.deinit();
    try std.testing.expectEqual(@as(u64, 3), snapshot.revision);
    try store.quarantineRotation("timeout");
    var replayed_snapshot = try store.readSnapshot();
    defer replayed_snapshot.deinit();
    try std.testing.expectEqual(snapshot.revision, replayed_snapshot.revision);
    const replay = try store.beginRotation(test_context, "timeout");
    try std.testing.expect(!replay.may_issue);
}

test "grant deletion retains generation across daemon reopen" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testPath(allocator, tmp);
    defer allocator.free(path);
    const key: envelope.Key = @splat(38);
    {
        var store = try Store.open(std.testing.io, allocator, path, key);
        defer store.close();
        _ = try store.commit(0, "{}", &.{.{ .put = .{ .context = test_context, .plaintext = "old" } }});
        _ = try store.commit(1, "{}", &.{.{ .delete = .{ .account_id = test_context.account_id, .grant_id = test_context.grant_id } }});
    }
    var store = try Store.open(std.testing.io, allocator, path, key);
    defer store.close();
    try std.testing.expectEqual(@as(u64, 2), try store.nextGeneration(test_context.account_id, test_context.grant_id));
    try std.testing.expectError(error.StaleGeneration, store.commit(2, "{}", &.{.{ .put = .{ .context = test_context, .plaintext = "replacement" } }}));
    var successor = test_context;
    successor.generation = 2;
    _ = try store.commit(2, "{}", &.{.{ .put = .{ .context = successor, .plaintext = "replacement" } }});
    try std.testing.expectError(error.StaleGeneration, store.loadGrant(test_context));
}

test "database row swaps and ciphertext damage fail authentication" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testPath(allocator, tmp);
    defer allocator.free(path);
    var store = try Store.open(std.testing.io, allocator, path, @splat(39));
    defer store.close();
    var other = test_context;
    other.account_id = "account-2";
    _ = try store.commit(0, "{}", &.{ .{ .put = .{ .context = test_context, .plaintext = "first" } }, .{ .put = .{ .context = other, .plaintext = "second" } } });
    try store.exec("UPDATE grants SET ciphertext=(SELECT ciphertext FROM grants WHERE account_id='account-2') WHERE account_id='account-1';");
    try std.testing.expectError(error.AuthenticationFailed, store.loadGrant(test_context));
    try store.exec("UPDATE grants SET ciphertext=zeroblob(length(ciphertext)) WHERE account_id='account-2';");
    try std.testing.expectError(error.InvalidEnvelope, store.loadGrant(other));
}

fn wrongOwnerThread(store: *Store, rejected: *bool) void {
    var snapshot = store.readSnapshot() catch |err| {
        rejected.* = err == error.WrongOwnerThread;
        return;
    };
    snapshot.deinit();
    rejected.* = false;
}

test "SQLite ownership cannot silently move to an IPC worker thread" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testPath(allocator, tmp);
    defer allocator.free(path);
    var store = try Store.open(std.testing.io, allocator, path, @splat(40));
    defer store.close();
    var rejected = false;
    const thread = try std.Thread.spawn(.{}, wrongOwnerThread, .{ &store, &rejected });
    thread.join();
    try std.testing.expect(rejected);
}

test "database records the exact vault root and rejects identity fallback" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testPath(allocator, tmp);
    defer allocator.free(path);
    const key: envelope.Key = @splat(41);
    var custom_context = test_context;
    custom_context.key_id = "installation-v2";
    {
        var store = try Store.openRoot(std.testing.io, allocator, path, custom_context.key_id, key);
        defer store.close();
        _ = try store.commit(0, "{}", &.{.{ .put = .{ .context = custom_context, .plaintext = "custom-root" } }});
        try std.testing.expectError(error.WrongKeyIdentity, store.loadGrant(test_context));
    }
    const key_id = try Store.readRootId(allocator, path);
    defer allocator.free(key_id);
    try std.testing.expectEqualStrings(custom_context.key_id, key_id);
    try std.testing.expectError(error.WrongKeyIdentity, Store.open(std.testing.io, allocator, path, key));
    var store = try Store.openRoot(std.testing.io, allocator, path, key_id, key);
    defer store.close();
    var secret = try store.loadGrant(custom_context);
    defer secret.deinit();
    try std.testing.expectEqualStrings("custom-root", secret.bytes);
}
