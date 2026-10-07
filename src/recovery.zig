//! Independent rollback fence for SQLite-only backup restoration. The private
//! authority file is not part of SQLite backup exports. Its trusted durable
//! state binds installation lineage and exact snapshot bytes/revision, and must
//! survive restore. It does not authenticate every SQL table or peer liveness.
//! Rolling back this file together with SQLite,
//! or a compromised OS user/vault/daemon, is outside this boundary.
const std = @import("std");
const c = std.c;
const metadata = @import("platform/file_metadata.zig");
const envelope = @import("envelope.zig");
extern "c" fn flock(fd: c.fd_t, operation: c_int) c_int;

pub const Checkpoint = struct {
    installation: [32]u8,
    sequence: u64,
    nonce: [32]u8,
    snapshot_revision: u64,
    snapshot_digest: [32]u8,

    pub fn fresh(io: std.Io, snapshot_revision: u64, snapshot_digest: [32]u8) !Checkpoint {
        if (snapshot_revision != 0) return error.InvalidRecoveryTransition;
        var result: Checkpoint = .{ .installation = undefined, .sequence = 0, .nonce = undefined, .snapshot_revision = snapshot_revision, .snapshot_digest = snapshot_digest };
        try io.randomSecure(&result.installation);
        try io.randomSecure(&result.nonce);
        return result;
    }

    pub fn successor(self: Checkpoint, io: std.Io, snapshot_revision: u64, snapshot_digest: [32]u8) !Checkpoint {
        if (snapshot_revision < self.snapshot_revision or snapshot_revision > std.math.maxInt(i64)) return error.InvalidRecoveryTransition;
        var result = self;
        result.sequence = std.math.add(u64, self.sequence, 1) catch return error.RecoverySequenceExhausted;
        try io.randomSecure(&result.nonce);
        result.snapshot_revision = snapshot_revision;
        result.snapshot_digest = snapshot_digest;
        return result;
    }

    pub fn eql(self: Checkpoint, other: Checkpoint) bool {
        return self.sequence == other.sequence and self.snapshot_revision == other.snapshot_revision and std.mem.eql(u8, &self.installation, &other.installation) and std.mem.eql(u8, &self.nonce, &other.nonce) and std.mem.eql(u8, &self.snapshot_digest, &other.snapshot_digest);
    }

    pub fn verify(self: Checkpoint, database: Checkpoint) !void {
        if (!std.mem.eql(u8, &self.installation, &database.installation)) return error.WrongRecoveryInstallation;
        if (database.sequence < self.sequence) return error.RecoveryRollbackDetected;
        if (!self.eql(database)) return error.RecoveryCheckpointMismatch;
    }
};

const magic = "OMUXR002";
const legacy_magic = "OMUXR001";
const legacy_record_size = 112;
const payload_size = magic.len + 32 + 8 + 32 + 8 + 32;
const record_size = payload_size + 32;
const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;

/// Owns a descriptor lock independent of the replaceable authority inode. All
/// reads/writes are bounded and descriptor relative. No credential bytes or
/// OS error diagnostics leave this API. An uncertain write fences its caller.
pub const FileAuthority = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    directory: c.fd_t,
    lock: c.fd_t,
    name: [:0]u8,
    key_id: []u8,
    key: envelope.Key,
    poisoned: bool = false,

    pub fn open(io: std.Io, allocator: std.mem.Allocator, database_path: []const u8, key_id: []const u8, key: envelope.Key) !FileAuthority {
        if (key_id.len == 0 or key_id.len > 128) return error.InvalidKeyIdentity;
        if (std.mem.eql(u8, database_path, ":memory:")) return error.RecoveryRequiresDurableDatabase;
        const parent = try allocator.dupeSentinel(u8, std.fs.path.dirname(database_path) orelse ".", 0);
        defer allocator.free(parent);
        const directory = c.open(parent.ptr, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
        if (directory < 0) return error.RecoveryDirectoryUnavailable;
        errdefer _ = c.close(directory);
        const dir_stat = try metadata.statFd(directory);
        if (dir_stat.uid != c.getuid() or dir_stat.mode & 0o777 != 0o700) return error.UnsafeRecoveryDirectory;
        const name = try std.fmt.allocPrintSentinel(allocator, "{s}.authority", .{std.fs.path.basename(database_path)}, 0);
        errdefer allocator.free(name);
        const lock_name = try std.fmt.allocPrintSentinel(allocator, "{s}.lock", .{name}, 0);
        defer allocator.free(lock_name);
        const lock = c.openat(directory, lock_name.ptr, .{ .ACCMODE = .RDWR, .CREAT = true, .NOFOLLOW = true, .CLOEXEC = true }, @as(c.mode_t, 0o600));
        if (lock < 0) return error.RecoveryLockUnavailable;
        errdefer _ = c.close(lock);
        try privateFile(lock);
        if (flock(lock, c.LOCK.EX | c.LOCK.NB) != 0) return error.RecoveryAuthorityBusy;
        const owned_key_id = try allocator.dupe(u8, key_id);
        return .{ .allocator = allocator, .io = io, .directory = directory, .lock = lock, .name = name, .key_id = owned_key_id, .key = key };
    }

    pub fn deinit(self: *FileAuthority) void {
        std.crypto.secureZero(u8, &self.key);
        _ = c.close(self.lock);
        _ = c.close(self.directory);
        self.allocator.free(self.name);
        self.allocator.free(self.key_id);
        self.* = undefined;
    }

    pub fn read(self: *FileAuthority) !Checkpoint {
        if (self.poisoned) return error.RecoveryAuthorityPoisoned;
        const fd = c.openat(self.directory, self.name.ptr, .{ .NOFOLLOW = true, .CLOEXEC = true });
        if (fd < 0) return switch (c.errno(fd)) {
            .NOENT => error.MissingRecoveryAuthority,
            else => error.RecoveryAuthorityUnavailable,
        };
        defer _ = c.close(fd);
        try privateFile(fd);
        const status = try metadata.statFd(fd);
        if (status.size != record_size and status.size != legacy_record_size) return error.InvalidRecoveryAuthority;
        var bytes: [record_size]u8 = undefined;
        const length: usize = @intCast(status.size);
        var offset: usize = 0;
        while (offset < length) {
            const count = c.read(fd, bytes[offset..].ptr, length - offset);
            if (count < 0) {
                if (c.errno(count) == .INTR) continue;
                return error.RecoveryReadFailed;
            }
            if (count == 0) return error.InvalidRecoveryAuthority;
            offset += @intCast(count);
        }
        // Former lineage authentication did not bind any metadata bytes. It
        // must never be promoted to recovered owner authority or re-signed.
        if (length == legacy_record_size and std.mem.eql(u8, bytes[0..legacy_magic.len], legacy_magic)) return error.RecoveryMigrationRequired;
        if (length != record_size) return error.InvalidRecoveryAuthority;
        if (!std.mem.eql(u8, bytes[0..magic.len], magic)) return error.InvalidRecoveryAuthority;
        const expected = self.authenticate(bytes[0..payload_size]);
        if (!std.crypto.timing_safe.eql([32]u8, expected, bytes[payload_size..].*)) return error.RecoveryAuthenticationFailed;
        const revision = std.mem.readInt(u64, bytes[80..88], .little);
        if (revision > std.math.maxInt(i64)) return error.InvalidRecoveryAuthority;
        return .{ .installation = bytes[8..40].*, .sequence = std.mem.readInt(u64, bytes[40..48], .little), .nonce = bytes[48..80].*, .snapshot_revision = revision, .snapshot_digest = bytes[88..120].* };
    }

    /// Fresh installations only. Existing/missing initialized authority cannot
    /// be inferred from a database backup. No repair/reseed operation is exposed.
    pub fn initialize(self: *FileAuthority, checkpoint: Checkpoint) !void {
        if (checkpoint.sequence != 0 or checkpoint.snapshot_revision != 0) return error.InvalidRecoveryTransition;
        _ = self.read() catch |err| switch (err) {
            error.MissingRecoveryAuthority => return self.publish(checkpoint),
            else => return err,
        };
        return error.RecoveryAuthorityAlreadyInitialized;
    }

    /// The reservation is durable before the database commit/issuer admission.
    /// A crash before SQLite commit deliberately requires recovery intervention.
    pub fn reserve(self: *FileAuthority, expected: Checkpoint, next: Checkpoint) !void {
        try (try self.read()).verify(expected);
        if (!std.mem.eql(u8, &expected.installation, &next.installation) or expected.sequence == std.math.maxInt(u64) or next.sequence != expected.sequence + 1 or std.mem.eql(u8, &expected.nonce, &next.nonce) or next.snapshot_revision < expected.snapshot_revision or next.snapshot_revision > std.math.maxInt(i64)) return error.InvalidRecoveryTransition;
        try self.publish(next);
    }

    fn authenticate(self: *const FileAuthority, payload: []const u8) [32]u8 {
        var mac = Hmac.init(&self.key);
        mac.update("omux recovery authority v2\x00");
        var key_id_length: [4]u8 = undefined;
        std.mem.writeInt(u32, &key_id_length, @intCast(self.key_id.len), .little);
        mac.update(&key_id_length);
        mac.update(self.key_id);
        mac.update(payload);
        var result: [32]u8 = undefined;
        mac.final(&result);
        return result;
    }

    fn publish(self: *FileAuthority, checkpoint: Checkpoint) !void {
        if (self.poisoned) return error.RecoveryAuthorityPoisoned;
        // Any failure after publication starts may leave a durable reservation.
        errdefer self.poisoned = true;
        var bytes: [record_size]u8 = undefined;
        @memcpy(bytes[0..8], magic);
        @memcpy(bytes[8..40], &checkpoint.installation);
        std.mem.writeInt(u64, bytes[40..48], checkpoint.sequence, .little);
        @memcpy(bytes[48..80], &checkpoint.nonce);
        std.mem.writeInt(u64, bytes[80..88], checkpoint.snapshot_revision, .little);
        @memcpy(bytes[88..120], &checkpoint.snapshot_digest);
        @memcpy(bytes[payload_size..], &self.authenticate(bytes[0..payload_size]));
        var random: [16]u8 = undefined;
        try self.io.randomSecure(&random);
        const temporary = try std.fmt.allocPrintSentinel(self.allocator, ".omux-recovery-{s}.tmp", .{std.fmt.bytesToHex(random, .lower)}, 0);
        defer self.allocator.free(temporary);
        const fd = c.openat(self.directory, temporary.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true }, @as(c.mode_t, 0o600));
        if (fd < 0) return error.RecoveryWriteFailed;
        defer _ = c.close(fd);
        defer _ = c.unlinkat(self.directory, temporary.ptr, 0);
        try privateFile(fd);
        var offset: usize = 0;
        while (offset < bytes.len) {
            const count = c.write(fd, bytes[offset..].ptr, bytes.len - offset);
            if (count < 0) {
                if (c.errno(count) == .INTR) continue;
                return error.RecoveryWriteFailed;
            }
            if (count == 0) return error.RecoveryWriteFailed;
            offset += @intCast(count);
        }
        if (c.fsync(fd) != 0) return error.RecoverySyncFailed;
        if (c.renameat(self.directory, temporary.ptr, self.directory, self.name.ptr) != 0) return error.RecoveryWriteFailed;
        if (c.fsync(self.directory) != 0) return error.RecoverySyncFailed;
    }
};

fn privateFile(fd: c.fd_t) !void {
    const status = try metadata.statFd(fd);
    if (status.mode & c.S.IFMT != c.S.IFREG or status.uid != c.getuid() or status.mode & 0o777 != 0o600 or status.nlink != 1) return error.UnsafeRecoveryFile;
}

test "independent authenticated authority fences rollback and divergent same sequence" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const allocator = std.testing.allocator;
    const directory_path = try std.fmt.allocPrintSentinel(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer allocator.free(directory_path);
    const directory = c.open(directory_path.ptr, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (directory < 0) return error.FixtureOpenFailed;
    defer _ = c.close(directory);
    if (c.fchmod(directory, 0o700) != 0) return error.FixtureModeFailed;
    const path = try std.fmt.allocPrint(allocator, ".zig-cache/tmp/{s}/fixture.sqlite", .{tmp.sub_path});
    defer allocator.free(path);
    var authority = try FileAuthority.open(std.testing.io, allocator, path, "fixture-root", @splat(14));
    defer authority.deinit();
    try std.testing.expectError(error.MissingRecoveryAuthority, authority.read());
    const first = try Checkpoint.fresh(std.testing.io, 0, @splat(1));
    try authority.initialize(first);
    try std.testing.expectError(error.RecoveryAuthorityAlreadyInitialized, authority.initialize(first));
    const next = try first.successor(std.testing.io, 1, @splat(2));
    try authority.reserve(first, next);
    try std.testing.expectError(error.RecoveryRollbackDetected, (try authority.read()).verify(first));
    var divergent = next;
    divergent.nonce[0] ^= 1;
    try std.testing.expectError(error.RecoveryCheckpointMismatch, (try authority.read()).verify(divergent));
    divergent = next;
    divergent.snapshot_revision += 1;
    try std.testing.expectError(error.RecoveryCheckpointMismatch, (try authority.read()).verify(divergent));
    divergent = next;
    divergent.snapshot_digest[0] ^= 1;
    try std.testing.expectError(error.RecoveryCheckpointMismatch, (try authority.read()).verify(divergent));
    try std.testing.expectError(error.RecoveryAuthorityBusy, FileAuthority.open(std.testing.io, allocator, path, "fixture-root", @splat(14)));
    try std.testing.expectError(error.RecoveryRollbackDetected, authority.reserve(first, next));
}

test "authority authentication and private file custody fail closed without reseeding" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const allocator = std.testing.allocator;
    const directory_path = try std.fmt.allocPrintSentinel(allocator, ".zig-cache/tmp/{s}", .{tmp.sub_path}, 0);
    defer allocator.free(directory_path);
    const directory = c.open(directory_path.ptr, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (directory < 0) return error.FixtureOpenFailed;
    defer _ = c.close(directory);
    if (c.fchmod(directory, 0o700) != 0) return error.FixtureModeFailed;
    const path = try std.fmt.allocPrint(allocator, "{s}/fixture.sqlite", .{directory_path});
    defer allocator.free(path);
    const key: envelope.Key = @splat(15);
    const initial = try Checkpoint.fresh(std.testing.io, 0, @splat(1));
    {
        var authority = try FileAuthority.open(std.testing.io, allocator, path, "fixture-root", key);
        defer authority.deinit();
        try authority.initialize(initial);
    }
    {
        var wrong_root = try FileAuthority.open(std.testing.io, allocator, path, "other-root", key);
        defer wrong_root.deinit();
        try std.testing.expectError(error.RecoveryAuthenticationFailed, wrong_root.read());
        try std.testing.expectError(error.RecoveryAuthenticationFailed, wrong_root.initialize(initial));
    }
    {
        var wrong_key = try FileAuthority.open(std.testing.io, allocator, path, "fixture-root", @splat(16));
        defer wrong_key.deinit();
        try std.testing.expectError(error.RecoveryAuthenticationFailed, wrong_key.read());
    }
    var authority = try FileAuthority.open(std.testing.io, allocator, path, "fixture-root", key);
    defer authority.deinit();
    const bytes = try tmp.dir.readFileAlloc(std.testing.io, "fixture.sqlite.authority", allocator, .limited(record_size + 1));
    defer allocator.free(bytes);
    try std.testing.expectEqual(record_size, bytes.len);
    bytes[48] ^= 1;
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "fixture.sqlite.authority", .data = bytes });
    try std.testing.expectError(error.RecoveryAuthenticationFailed, authority.read());
    try std.testing.expectError(error.RecoveryAuthenticationFailed, authority.initialize(initial));
    const anchor = c.openat(directory, "fixture.sqlite.authority", .{ .NOFOLLOW = true, .CLOEXEC = true });
    if (anchor < 0) return error.FixtureOpenFailed;
    defer _ = c.close(anchor);
    if (c.fchmod(anchor, 0o644) != 0) return error.FixtureModeFailed;
    try std.testing.expectError(error.UnsafeRecoveryFile, authority.read());
    try tmp.dir.deleteFile(std.testing.io, "fixture.sqlite.authority");
    if (c.symlinkat("fixture.sqlite.authority.lock", directory, "fixture.sqlite.authority") != 0) return error.FixtureSymlinkFailed;
    try std.testing.expectError(error.RecoveryAuthorityUnavailable, authority.read());
    try std.testing.expectError(error.RecoveryAuthorityUnavailable, authority.initialize(initial));
}
