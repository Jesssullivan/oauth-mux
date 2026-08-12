//! Exact process-incarnation custody for persisted broker leases.
//!
//! A PID is never liveness authority. Each managed sidecar holds one mode-0600
//! flock whose name includes a random incarnation and generation. Peers probe
//! that exact inode non-blockingly: contention proves the exact owner is alive;
//! a safely acquired flock proves it is dead; missing or invalid custody stays
//! unknown and therefore cannot authorize stale-owner cleanup.

const std = @import("std");
const builtin = @import("builtin");
const lease_state = @import("lease_state.zig");
const lease_store = @import("lease_store.zig");
const lock_wait = @import("../lock_wait.zig");

const owner_dir_name = "lease-owners-v1";
const registry_lock_name = ".registry.lock";
const owner_file_mode = 0o600;
const owner_dir_mode = 0o700;
const max_owner_file_name = 96;

/// Request/teardown-owned cumulative deadline. The registry never owns a
/// second timeout; it only consumes the caller's remaining budget.
pub const Budget = struct {
    ctx: *anyopaque,
    remaining_ns: *const fn (ctx: *anyopaque) anyerror!u64,

    fn remaining(self: Budget) !u64 {
        return self.remaining_ns(self.ctx);
    }
};

const FileIdentity = struct {
    device: u64,
    inode: u64,
    uid: u64,
    mode: u32,

    fn eql(a: FileIdentity, b: FileIdentity) bool {
        return a.device == b.device and
            a.inode == b.inode and
            a.uid == b.uid and
            a.mode == b.mode;
    }
};

pub const Registry = struct {
    dir: std.fs.Dir,
    control: std.fs.File,
    control_identity: FileIdentity,
    owner_uid: u64,

    pub fn init(absolute_broker_root: []const u8) !Registry {
        if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
            return error.UnsupportedLeaseOwnerPlatform;
        }
        if (!std.fs.path.isAbsolute(absolute_broker_root)) return error.InvalidRuntimeRoot;

        var root = try std.fs.openDirAbsolute(absolute_broker_root, .{ .no_follow = true });
        defer root.close();
        const root_stat = try std.posix.fstat(root.fd);
        if ((root_stat.mode & std.posix.S.IFMT) != std.posix.S.IFDIR) {
            return error.NonDirectoryLeaseOwnerRoot;
        }
        // The lease store permits an operator-owned 0755 runtime parent; exact
        // owner custody lives in the hardened 0700 child below. Group/world
        // write on the parent is still a hard refusal.
        if ((root_stat.mode & 0o022) != 0) return error.InsecureLeaseOwnerCustody;

        root.makeDir(owner_dir_name) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        var dir = try root.openDir(owner_dir_name, .{ .iterate = true, .no_follow = true });
        errdefer dir.close();
        const stat = try std.posix.fstat(dir.fd);
        if ((stat.mode & std.posix.S.IFMT) != std.posix.S.IFDIR) {
            return error.NonDirectoryLeaseOwnerRoot;
        }
        if (@as(u64, @intCast(stat.uid)) != @as(u64, @intCast(root_stat.uid))) {
            return error.InsecureLeaseOwnerCustody;
        }
        try std.posix.fchmod(dir.fd, owner_dir_mode);
        const hardened = try std.posix.fstat(dir.fd);
        if ((hardened.mode & 0o777) != owner_dir_mode) {
            return error.InsecureLeaseOwnerCustody;
        }
        const control_fd = try std.posix.openat(dir.fd, registry_lock_name, .{
            .ACCMODE = .RDWR,
            .CREAT = true,
            .NOFOLLOW = true,
            .CLOEXEC = true,
        }, owner_file_mode);
        var control = std.fs.File{ .handle = control_fd };
        errdefer control.close();
        try std.posix.fchmod(control.handle, owner_file_mode);
        const control_identity = try validateCustodyStat(
            try std.posix.fstat(control.handle),
            @intCast(hardened.uid),
        );
        return .{
            .dir = dir,
            .control = control,
            .control_identity = control_identity,
            .owner_uid = @intCast(hardened.uid),
        };
    }

    pub fn deinit(self: *Registry) void {
        self.control.close();
        self.dir.close();
        self.* = undefined;
    }

    pub fn livenessSource(self: *const Registry) lease_store.LivenessSource {
        return .{ .ctx = @ptrCast(self), .resolve = resolveLiveness };
    }

    pub fn status(self: *const Registry, owner: lease_store.OwnerIdentity) lease_store.OwnerLiveness {
        if (!owner.isValid()) return .unknown;
        var name_buf: [max_owner_file_name]u8 = undefined;
        const name = ownerFileName(&name_buf, owner) catch return .unknown;
        const file = self.openOwnerFile(name, false) catch return .unknown;
        defer file.close();
        const identity = self.validateOwnerFile(file) catch return .unknown;
        self.verifyCanonical(name, identity) catch return .unknown;
        const acquired = lock_wait.tryLockFile(file) catch return .unknown;
        if (!acquired) return .alive;
        file.unlock();
        return .dead;
    }

    pub fn acquireRandom(self: *Registry) !Guard {
        var attempts: usize = 0;
        while (attempts < 16) : (attempts += 1) {
            const owner = lease_store.OwnerIdentity{
                .pid = currentPid(),
                .incarnation = randomGeneration(),
                .generation = randomGeneration(),
            };
            if (try self.acquireExact(owner)) |guard| return guard;
        }
        return error.OwnerIdentityCollision;
    }

    pub fn acquireExactForTest(self: *Registry, owner: lease_store.OwnerIdentity) !Guard {
        if (!builtin.is_test) return error.TestOnlyLeaseOwnerIdentity;
        return (try self.acquireExact(owner)) orelse error.OwnerAlreadyAlive;
    }

    fn acquireExact(self: *Registry, owner: lease_store.OwnerIdentity) !?Guard {
        if (!owner.isValid()) return error.InvalidOwnerIdentity;
        try self.verifyControlCanonical();
        try self.control.lock(.exclusive);
        defer self.control.unlock();
        try self.verifyControlCanonical();
        var name_buf: [max_owner_file_name]u8 = undefined;
        const name = try ownerFileName(&name_buf, owner);
        const file = try self.openOwnerFile(name, true);
        errdefer file.close();
        const identity = try self.validateOwnerFile(file);
        try self.verifyCanonical(name, identity);
        if (!(try lock_wait.tryLockFile(file))) return null;
        return .{ .identity = owner, .file = file };
    }

    /// Removes a gracefully released owner's custody path while its lifetime
    /// flock is still held. The one registry flock serializes this unlink with
    /// owner creation, so a new incarnation can never be detached mid-startup.
    pub fn retireGuard(self: *Registry, guard: *Guard) !void {
        try self.verifyControlCanonical();
        try self.control.lock(.exclusive);
        defer self.control.unlock();
        try self.verifyControlCanonical();
        try self.retireGuardLocked(guard);
    }

    pub fn retireGuardBounded(
        self: *Registry,
        guard: *Guard,
        wait: lock_wait.WaitOptions,
        budget: Budget,
    ) !void {
        try self.lockControlBounded(wait, budget);
        defer self.control.unlock();
        try self.retireGuardLocked(guard);
        _ = try budget.remaining();
    }

    fn retireGuardLocked(self: *Registry, guard: *Guard) !void {
        var name_buf: [max_owner_file_name]u8 = undefined;
        const name = try ownerFileName(&name_buf, guard.identity);
        const identity = try self.validateOwnerFile(guard.file);
        try self.verifyCanonical(name, identity);
        try self.dir.deleteFile(name);
    }

    /// Retires crash residue only after the store has durably removed every
    /// lease reported for this exact owner incarnation.
    pub fn retireDead(self: *Registry, owner: lease_store.OwnerIdentity) !bool {
        if (!owner.isValid()) return false;
        try self.verifyControlCanonical();
        try self.control.lock(.exclusive);
        defer self.control.unlock();
        try self.verifyControlCanonical();
        return self.retireDeadLocked(owner);
    }

    fn retireDeadLocked(self: *Registry, owner: lease_store.OwnerIdentity) !bool {
        if (!owner.isValid()) return false;
        var name_buf: [max_owner_file_name]u8 = undefined;
        const name = try ownerFileName(&name_buf, owner);
        const file = self.openOwnerFile(name, false) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
        defer file.close();
        const identity = try self.validateOwnerFile(file);
        try self.verifyCanonical(name, identity);
        if (!(try lock_wait.tryLockFile(file))) return false;
        defer file.unlock();
        try self.verifyCanonical(name, identity);
        try self.dir.deleteFile(name);
        return true;
    }

    /// Reconsiders custody files whose leases were removed by an earlier
    /// transaction. Exact-owner flocks remain the only deletion authority.
    /// Owners removed in the current transaction are excluded so their direct
    /// `retireDead` result remains observable and independently testable.
    pub fn retireOrphanedDead(
        self: *Registry,
        excluded: []const lease_store.OwnerIdentity,
    ) !usize {
        var retired: usize = 0;
        var iterator = self.dir.iterate();
        while (try iterator.next()) |entry| {
            const owner = parseOwnerFileName(entry.name) catch continue;
            var skip = false;
            for (excluded) |excluded_owner| {
                if (owner.eql(excluded_owner)) {
                    skip = true;
                    break;
                }
            }
            if (!skip and try self.retireDead(owner)) retired += 1;
        }
        return retired;
    }

    /// Retires the owners removed from the canonical lease snapshot and then
    /// any older orphan custody files under one bounded registry flock. This
    /// prevents a 256-owner scan from multiplying the request deadline.
    pub fn retireDeadAndOrphanedBounded(
        self: *Registry,
        removed: []const lease_store.OwnerIdentity,
        wait: lock_wait.WaitOptions,
        budget: Budget,
    ) !usize {
        try self.lockControlBounded(wait, budget);
        defer self.control.unlock();

        var retired: usize = 0;
        for (removed) |owner| {
            _ = try budget.remaining();
            if (try self.retireDeadLocked(owner)) retired += 1;
            _ = try budget.remaining();
        }

        var iterator = self.dir.iterate();
        while (try iterator.next()) |entry| {
            _ = try budget.remaining();
            const owner = parseOwnerFileName(entry.name) catch continue;
            var skip = false;
            for (removed) |removed_owner| {
                if (owner.eql(removed_owner)) {
                    skip = true;
                    break;
                }
            }
            if (!skip and try self.retireDeadLocked(owner)) retired += 1;
            _ = try budget.remaining();
        }
        return retired;
    }

    fn lockControlBounded(
        self: *Registry,
        wait: lock_wait.WaitOptions,
        budget: Budget,
    ) !void {
        try self.verifyControlCanonical();
        if (try lock_wait.tryLockFile(self.control)) {
            self.verifyControlCanonical() catch |err| {
                self.control.unlock();
                return err;
            };
            _ = budget.remaining() catch |err| {
                self.control.unlock();
                return err;
            };
            return;
        }

        const initial_remaining = try budget.remaining();
        const timeout_ns = @min(wait.timeout_ns, initial_remaining);
        if (timeout_ns == 0 or wait.poll_interval_ns == 0) {
            return error.LockWaitTimeout;
        }
        var timer = std.time.Timer.start() catch return error.MonotonicClockUnavailable;
        while (timer.read() < timeout_ns) {
            const remaining = try budget.remaining();
            const elapsed = timer.read();
            if (remaining == 0 or elapsed >= timeout_ns) return error.LockWaitTimeout;
            const local_remaining = timeout_ns - elapsed;
            std.Thread.sleep(@min(wait.poll_interval_ns, @min(remaining, local_remaining)));
            if (try lock_wait.tryLockFile(self.control)) {
                self.verifyControlCanonical() catch |err| {
                    self.control.unlock();
                    return err;
                };
                _ = budget.remaining() catch |err| {
                    self.control.unlock();
                    return err;
                };
                return;
            }
        }
        return error.LockWaitTimeout;
    }

    fn openOwnerFile(self: *const Registry, name: []const u8, create: bool) !std.fs.File {
        if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
            return error.UnsupportedLeaseOwnerPlatform;
        }
        const fd = try std.posix.openat(self.dir.fd, name, .{
            .ACCMODE = .RDWR,
            .CREAT = create,
            .NONBLOCK = true,
            .NOFOLLOW = true,
            .CLOEXEC = true,
        }, owner_file_mode);
        return .{ .handle = fd };
    }

    fn validateOwnerFile(self: *const Registry, file: std.fs.File) !FileIdentity {
        if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
            return error.UnsupportedLeaseOwnerPlatform;
        }
        return validateCustodyStat(try std.posix.fstat(file.handle), self.owner_uid);
    }

    fn verifyCanonical(self: *const Registry, name: []const u8, expected: FileIdentity) !void {
        if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
            return error.UnsupportedLeaseOwnerPlatform;
        }
        const stat = try std.posix.fstatat(self.dir.fd, name, std.posix.AT.SYMLINK_NOFOLLOW);
        const actual = try validateCustodyStat(stat, self.owner_uid);
        if (!actual.eql(expected)) return error.LeaseOwnerPathChanged;
    }

    fn verifyControlCanonical(self: *const Registry) !void {
        if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
            return error.UnsupportedLeaseOwnerPlatform;
        }
        const stat = try std.posix.fstatat(
            self.dir.fd,
            registry_lock_name,
            std.posix.AT.SYMLINK_NOFOLLOW,
        );
        const actual = try validateCustodyStat(stat, self.owner_uid);
        if (!actual.eql(self.control_identity)) return error.LeaseOwnerRegistryPathChanged;
    }
};

fn validateCustodyStat(stat: std.posix.Stat, owner_uid: u64) !FileIdentity {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.UnsupportedLeaseOwnerPlatform;
    }
    if ((stat.mode & std.posix.S.IFMT) != std.posix.S.IFREG) {
        return error.NonRegularLeaseOwnerFile;
    }
    if ((stat.mode & 0o777) != owner_file_mode or
        @as(u64, @intCast(stat.uid)) != owner_uid)
    {
        return error.InsecureLeaseOwnerCustody;
    }
    return .{
        .device = @intCast(stat.dev),
        .inode = @intCast(stat.ino),
        .uid = @intCast(stat.uid),
        .mode = @intCast(stat.mode & 0o777),
    };
}

pub const Guard = struct {
    identity: lease_store.OwnerIdentity,
    file: std.fs.File,

    pub fn deinit(self: *Guard) void {
        self.file.close();
        self.* = undefined;
    }
};

fn resolveLiveness(ctx: *const anyopaque, owner: lease_store.OwnerIdentity) lease_store.OwnerLiveness {
    const registry: *const Registry = @ptrCast(@alignCast(ctx));
    return registry.status(owner);
}

fn ownerFileName(buffer: []u8, owner: lease_store.OwnerIdentity) ![]const u8 {
    return std.fmt.bufPrint(
        buffer,
        "owner-{d}-{x}-{x}.lock",
        .{ owner.pid, owner.incarnation, owner.generation },
    );
}

fn parseOwnerFileName(name: []const u8) !lease_store.OwnerIdentity {
    const prefix = "owner-";
    const suffix = ".lock";
    if (!std.mem.startsWith(u8, name, prefix) or
        !std.mem.endsWith(u8, name, suffix) or
        name.len <= prefix.len + suffix.len)
    {
        return error.InvalidLeaseOwnerFileName;
    }
    const body = name[prefix.len .. name.len - suffix.len];
    var parts = std.mem.splitScalar(u8, body, '-');
    const pid_text = parts.next() orelse return error.InvalidLeaseOwnerFileName;
    const incarnation_text = parts.next() orelse return error.InvalidLeaseOwnerFileName;
    const generation_text = parts.next() orelse return error.InvalidLeaseOwnerFileName;
    if (parts.next() != null) return error.InvalidLeaseOwnerFileName;
    const owner = lease_store.OwnerIdentity{
        .pid = try std.fmt.parseUnsigned(lease_state.OwnerPid, pid_text, 10),
        .incarnation = try std.fmt.parseUnsigned(u64, incarnation_text, 16),
        .generation = try std.fmt.parseUnsigned(u64, generation_text, 16),
    };
    if (!owner.isValid()) return error.InvalidLeaseOwnerFileName;
    return owner;
}

pub const testing = if (builtin.is_test) struct {
    const FixedBudget = struct {
        remaining: u64 = 500 * std.time.ns_per_ms,

        fn read(raw: *anyopaque) anyerror!u64 {
            const self: *FixedBudget = @ptrCast(@alignCast(raw));
            return self.remaining;
        }

        fn budget(self: *FixedBudget) Budget {
            return .{ .ctx = @ptrCast(self), .remaining_ns = read };
        }
    };

    pub fn ownerPathExists(registry: *const Registry, owner: lease_store.OwnerIdentity) !bool {
        var name_buf: [max_owner_file_name]u8 = undefined;
        const name = try ownerFileName(&name_buf, owner);
        _ = std.posix.fstatat(
            registry.dir.fd,
            name,
            std.posix.AT.SYMLINK_NOFOLLOW,
        ) catch |err| switch (err) {
            error.FileNotFound => return false,
            else => return err,
        };
        return true;
    }

    /// Two registries opened across an unlink/recreate hold independently
    /// lockable descriptors. Canonical dev/inode custody must reject the stale
    /// registry before it can mistake that split inode for serialization.
    pub fn runControlCustodyDiagnostics(parent_root: []const u8) !bool {
        if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) return true;
        const root = try std.fs.path.join(
            std.testing.allocator,
            &.{ parent_root, "owner-control-custody" },
        );
        defer std.testing.allocator.free(root);
        try std.fs.makeDirAbsolute(root);

        var first = try Registry.init(root);
        defer first.deinit();
        try first.dir.deleteFile(registry_lock_name);
        {
            const replacement = try first.dir.createFile(registry_lock_name, .{
                .read = true,
                .truncate = false,
                .mode = owner_file_mode,
            });
            replacement.close();
        }
        var second = try Registry.init(root);
        defer second.deinit();
        try std.testing.expect(!first.control_identity.eql(second.control_identity));
        {
            try std.testing.expect(try lock_wait.tryLockFile(first.control));
            defer first.control.unlock();
            try std.testing.expect(try lock_wait.tryLockFile(second.control));
            defer second.control.unlock();
        }

        var second_budget = FixedBudget{};
        try std.testing.expectEqual(
            @as(usize, 0),
            try second.retireDeadAndOrphanedBounded(&.{}, .{
                .poll_interval_ns = 0,
                .heartbeat_ns = std.time.ns_per_hour,
                .timeout_ns = 0,
            }, second_budget.budget()),
        );

        var first_budget = FixedBudget{};
        try std.testing.expectError(
            error.LeaseOwnerRegistryPathChanged,
            first.retireDeadAndOrphanedBounded(&.{}, .{
                .poll_interval_ns = 0,
                .heartbeat_ns = std.time.ns_per_hour,
                .timeout_ns = 0,
            }, first_budget.budget()),
        );
        return true;
    }
} else struct {};

fn currentPid() lease_state.OwnerPid {
    return switch (builtin.os.tag) {
        .linux => @intCast(std.os.linux.getpid()),
        .macos, .ios, .watchos, .tvos, .visionos, .freebsd, .netbsd, .openbsd, .dragonfly => @intCast(std.c.getpid()),
        else => 0,
    };
}

fn randomGeneration() u64 {
    const maximum: u64 = @intCast(lease_state.max_timestamp_ms);
    return (std.crypto.random.int(u64) % maximum) + 1;
}

fn testRoot(tmp: *std.testing.TmpDir) ![]u8 {
    return tmp.dir.realpathAlloc(std.testing.allocator, ".");
}

test "exact owner flock distinguishes alive dead missing and reused pid" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SkipZigTest;
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(&tmp);
    defer std.testing.allocator.free(root);

    var registry = try Registry.init(root);
    defer registry.deinit();
    const owner = lease_store.OwnerIdentity{ .pid = currentPid(), .incarnation = 11, .generation = 7 };
    var guard = try registry.acquireExactForTest(owner);
    try std.testing.expectEqual(lease_store.OwnerLiveness.alive, registry.status(owner));

    const reused = lease_store.OwnerIdentity{ .pid = owner.pid, .incarnation = 12, .generation = 7 };
    try std.testing.expectEqual(lease_store.OwnerLiveness.unknown, registry.status(reused));

    guard.deinit();
    try std.testing.expectEqual(lease_store.OwnerLiveness.dead, registry.status(owner));
}

test "invalid owner-file custody remains unknown" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SkipZigTest;
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(&tmp);
    defer std.testing.allocator.free(root);
    var registry = try Registry.init(root);
    defer registry.deinit();
    const owner = lease_store.OwnerIdentity{ .pid = currentPid(), .incarnation = 21, .generation = 9 };
    var name_buf: [max_owner_file_name]u8 = undefined;
    const name = try ownerFileName(&name_buf, owner);
    const file = try registry.dir.createFile(name, .{ .mode = 0o644 });
    file.close();
    try std.testing.expectEqual(lease_store.OwnerLiveness.unknown, registry.status(owner));
}

test "graceful retirement removes per-session owner custody" {
    if (comptime builtin.os.tag == .windows or builtin.os.tag == .wasi) {
        return error.SkipZigTest;
    }
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try testRoot(&tmp);
    defer std.testing.allocator.free(root);
    var registry = try Registry.init(root);
    defer registry.deinit();
    const owner = lease_store.OwnerIdentity{ .pid = currentPid(), .incarnation = 31, .generation = 11 };
    var guard = try registry.acquireExactForTest(owner);
    try registry.retireGuard(&guard);
    guard.deinit();
    try std.testing.expectEqual(lease_store.OwnerLiveness.unknown, registry.status(owner));

    var iterator = registry.dir.iterate();
    while (try iterator.next()) |entry| {
        try std.testing.expect(!std.mem.startsWith(u8, entry.name, "owner-"));
    }
}
