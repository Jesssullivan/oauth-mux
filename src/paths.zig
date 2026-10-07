//! Per-user state locations and descriptor-based private-directory custody.
const std = @import("std");
const builtin = @import("builtin");
const c = std.c;
const metadata = @import("platform/file_metadata.zig");
const instance = @import("instance.zig");
extern "c" fn flock(fd: c.fd_t, operation: c_int) c_int;

pub const Locations = struct {
    instance: instance.Selection = .default,
    state: []const u8,
    run: []const u8,
    control: []const u8,
    browser: []const u8,
    adapter: []const u8,
    /// Present only for environment-selected Linux runtime placement. This
    /// directory must already exist; Omux creates only its private child.
    runtime_parent: ?[]const u8 = null,

    pub fn init(allocator: std.mem.Allocator, state: []const u8) !Locations {
        try validateAbsolute(state);
        const run = try std.fmt.allocPrint(allocator, "{s}/run", .{state});
        errdefer allocator.free(run);
        return fromRun(allocator, state, run, null);
    }

    /// Production selection: an absent Linux XDG_RUNTIME_DIR uses state/run.
    /// An explicitly supplied empty/unsafe/missing directory fails closed.
    /// No other candidate is tried after an explicit runtime selection fails.
    pub fn fromEnvironment(allocator: std.mem.Allocator, state: []const u8, env: *const std.process.Environ.Map) !Locations {
        return fromRuntime(allocator, state, if (builtin.os.tag == .linux) env.get("XDG_RUNTIME_DIR") else null);
    }

    /// Selection is captured once by the launcher and propagated to custody.
    /// An explicit state override stays exact; vault namespace validation must
    /// reject a database belonging to another instance before opening custody.
    pub fn fromEnvironmentForInstance(allocator: std.mem.Allocator, state: []const u8, env: *const std.process.Environ.Map, selection: instance.Selection) !Locations {
        var result = try fromEnvironment(allocator, state, env);
        result.instance = selection;
        return result;
    }

    pub fn fromRuntime(allocator: std.mem.Allocator, state: []const u8, runtime: ?[]const u8) !Locations {
        try validateAbsolute(state);
        const base = runtime orelse return init(allocator, state);
        const fd = try openPrivateRoot(allocator, base, false);
        closeFd(fd);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(state, &digest, .{});
        const run = try std.fmt.allocPrint(allocator, "{s}/omux-{s}", .{ base, std.fmt.bytesToHex(digest[0..16].*, .lower) });
        errdefer allocator.free(run);
        return fromRun(allocator, state, run, base);
    }

    fn fromRun(allocator: std.mem.Allocator, state: []const u8, run: []const u8, runtime: ?[]const u8) !Locations {
        // AF_UNIX requires space for the trailing NUL on both supported OSes.
        const limit: usize = if (builtin.os.tag == .macos) 103 else 107;
        if (run.len + "/control.sock".len > limit) return error.SocketPathTooLong;
        const state_copy = try allocator.dupe(u8, state);
        errdefer allocator.free(state_copy);
        const control = try std.fmt.allocPrint(allocator, "{s}/control.sock", .{run});
        errdefer allocator.free(control);
        const browser = try std.fmt.allocPrint(allocator, "{s}/browser.sock", .{run});
        errdefer allocator.free(browser);
        const adapter = try std.fmt.allocPrint(allocator, "{s}/adapter.sock", .{run});
        errdefer allocator.free(adapter);
        return .{
            .state = state_copy,
            .run = run,
            .control = control,
            .browser = browser,
            .adapter = adapter,
            .runtime_parent = if (runtime) |base| try allocator.dupe(u8, base) else null,
        };
    }
};

pub fn defaultState(allocator: std.mem.Allocator, env: *const std.process.Environ.Map) ![]u8 {
    return defaultStateForInstance(allocator, env, .default);
}

pub fn defaultStateForInstance(allocator: std.mem.Allocator, env: *const std.process.Environ.Map, selection: instance.Selection) ![]u8 {
    const home = env.get("HOME") orelse return error.MissingHome;
    try validateAbsolute(home);
    return switch (builtin.os.tag) {
        .macos => std.fmt.allocPrint(allocator, "{s}/Library/Application Support/Omux{s}", .{ home, if (selection == .dev) "-dev" else "" }),
        .linux => if (env.get("XDG_STATE_HOME")) |base| blk: {
            try validateAbsolute(base);
            break :blk std.fmt.allocPrint(allocator, "{s}/omux{s}", .{ base, if (selection == .dev) "-dev" else "" });
        } else std.fmt.allocPrint(allocator, "{s}/.local/state/omux{s}", .{ home, if (selection == .dev) "-dev" else "" }),
        else => error.UnsupportedPlatform,
    };
}

pub fn validateAbsolute(path: []const u8) !void {
    if (path.len < 2 or path[0] != '/' or path[path.len - 1] == '/' or std.mem.indexOfScalar(u8, path, 0) != null) return error.UnsafePath;
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.UnsafePath;
    }
}

fn closeFd(fd: c.fd_t) void {
    _ = c.close(fd);
}

fn statFd(fd: c.fd_t) !metadata.Metadata {
    return metadata.statFd(fd);
}

fn validateAncestor(stat: metadata.Metadata) !void {
    if (stat.mode & c.S.IFMT != c.S.IFDIR) return error.UnsafePath;
    if (stat.uid != c.getuid() and stat.uid != 0) return error.UnsafePathOwner;
    // Root-owned sticky temporary directories cannot have an existing entry
    // renamed by another user. Every existing component is opened NOFOLLOW.
    if (stat.mode & 0o022 != 0 and !(stat.uid == 0 and stat.mode & 0o1000 != 0)) return error.UnsafePathPermissions;
}

pub fn verifyPrivateFd(fd: c.fd_t, kind: c.mode_t, mode: c.mode_t) !void {
    const stat = try statFd(fd);
    if (stat.mode & c.S.IFMT != kind or stat.uid != c.getuid() or stat.mode & 0o777 != mode) return error.UnsafePrivatePath;
}

/// Walk every component relative to an already-open directory. Existing
/// symlinks, ownership mismatches and permissive private roots fail closed.
pub fn openPrivateRoot(allocator: std.mem.Allocator, path: []const u8, create: bool) !c.fd_t {
    try validateAbsolute(path);
    var fd = c.open("/", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (fd < 0) return error.PathOpenFailed;
    errdefer closeFd(fd);
    var parts = std.mem.splitScalar(u8, path[1..], '/');
    while (parts.next()) |part| {
        try validateAncestor(try statFd(fd));
        const name = try allocator.dupeSentinel(u8, part, 0);
        defer allocator.free(name);
        var next = c.openat(fd, name.ptr, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
        if (next < 0 and create and std.posix.errno(next) == .NOENT) {
            if (c.mkdirat(fd, name.ptr, 0o700) != 0 and std.posix.errno(-1) != .EXIST) return error.PathCreateFailed;
            next = c.openat(fd, name.ptr, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
        }
        if (next < 0) return error.PathOpenFailed;
        closeFd(fd);
        fd = next;
    }
    try verifyPrivateFd(fd, c.S.IFDIR, 0o700);
    return fd;
}

pub const Custody = struct {
    state_fd: c.fd_t,
    run_fd: c.fd_t,
    lock_fd: c.fd_t,
    legacy_lock_fd: ?c.fd_t = null,

    pub fn acquire(allocator: std.mem.Allocator, locations: Locations) !Custody {
        const state_fd = try openPrivateRoot(allocator, locations.state, true);
        errdefer closeFd(state_fd);
        // Persistent state owns singleton authority. An ephemeral runtime path
        // or differing process environment cannot establish a second writer.
        const lock_fd = c.openat(state_fd, "daemon.lock", .{ .ACCMODE = .RDWR, .CREAT = true, .NOFOLLOW = true, .CLOEXEC = true }, @as(c.mode_t, 0o600));
        if (lock_fd < 0) return error.LockOpenFailed;
        errdefer closeFd(lock_fd);
        try verifyPrivateFd(lock_fd, c.S.IFREG, 0o600);
        if ((try statFd(lock_fd)).nlink != 1) return error.UnsafePrivatePath;
        if (flock(lock_fd, c.LOCK.EX | c.LOCK.NB) != 0) return switch (std.posix.errno(-1)) {
            .AGAIN => error.DaemonAlreadyRunning,
            else => error.LockAcquireFailed,
        };
        const legacy_lock_fd = try acquireLegacyLock(state_fd);
        errdefer if (legacy_lock_fd) |fd| closeFd(fd);
        const parent_fd = if (locations.runtime_parent) |base| try openPrivateRoot(allocator, base, false) else state_fd;
        defer if (locations.runtime_parent != null) closeFd(parent_fd);
        const run_name = try allocator.dupeSentinel(u8, std.fs.path.basename(locations.run), 0);
        defer allocator.free(run_name);
        if (c.mkdirat(parent_fd, run_name.ptr, 0o700) != 0 and std.posix.errno(-1) != .EXIST) return error.PathCreateFailed;
        const run_fd = c.openat(parent_fd, run_name.ptr, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
        if (run_fd < 0) return error.PathOpenFailed;
        errdefer closeFd(run_fd);
        try verifyPrivateFd(run_fd, c.S.IFDIR, 0o700);
        return .{ .state_fd = state_fd, .run_fd = run_fd, .lock_fd = lock_fd, .legacy_lock_fd = legacy_lock_fd };
    }

    pub fn deinit(self: *Custody) void {
        if (self.legacy_lock_fd) |fd| closeFd(fd);
        closeFd(self.lock_fd);
        closeFd(self.run_fd);
        closeFd(self.state_fd);
        self.* = undefined;
    }

    /// Never unlink a foreign file, symlink, directory or active daemon socket.
    /// Caller holds the per-installation exclusive lock before stale removal.
    pub fn removeSocket(self: Custody, name: [:0]const u8) !void {
        const stat = metadata.statAt(self.run_fd, name.ptr, c.AT.SYMLINK_NOFOLLOW) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        if (stat.mode & c.S.IFMT != c.S.IFSOCK or stat.uid != c.getuid() or stat.mode & 0o777 != 0o600) return error.UnsafeSocketPath;
        if (c.unlinkat(self.run_fd, name.ptr, 0) != 0) return error.SocketRemoveFailed;
    }
};

/// A pre-change experimental daemon used state/run/daemon.lock. Probe only
/// existing entries, fail closed on unsafe custody, and retain an acquired old
/// lock until shutdown. Never create a legacy directory or legacy lock.
fn acquireLegacyLock(state_fd: c.fd_t) !?c.fd_t {
    const directory = c.openat(state_fd, "run", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (directory < 0) return switch (std.posix.errno(directory)) {
        .NOENT => null,
        else => error.PathOpenFailed,
    };
    defer closeFd(directory);
    try verifyPrivateFd(directory, c.S.IFDIR, 0o700);
    const fd = c.openat(directory, "daemon.lock", .{ .ACCMODE = .RDWR, .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true });
    if (fd < 0) return switch (std.posix.errno(fd)) {
        .NOENT => null,
        else => error.LockOpenFailed,
    };
    errdefer closeFd(fd);
    try verifyPrivateFd(fd, c.S.IFREG, 0o600);
    if ((try statFd(fd)).nlink != 1) return error.UnsafePrivatePath;
    if (flock(fd, c.LOCK.EX | c.LOCK.NB) != 0) return switch (std.posix.errno(-1)) {
        .AGAIN => error.DaemonAlreadyRunning,
        else => error.LockAcquireFailed,
    };
    return fd;
}

pub fn readCapability(allocator: std.mem.Allocator, state: []const u8, application: []const u8) ![]u8 {
    const capability_name: [:0]const u8 = if (std.mem.eql(u8, application, "git")) "git.capability" else if (std.mem.eql(u8, application, "enrollment")) "enrollment.capability" else return error.UnsupportedAdapter;
    const state_fd = try openPrivateRoot(allocator, state, false);
    defer closeFd(state_fd);
    const dir_fd = c.openat(state_fd, "integrations", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (dir_fd < 0) return error.AdapterNotInstalled;
    defer closeFd(dir_fd);
    try verifyPrivateFd(dir_fd, c.S.IFDIR, 0o700);
    const fd = c.openat(dir_fd, capability_name.ptr, .{ .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true });
    if (fd < 0) return error.AdapterNotInstalled;
    defer closeFd(fd);
    try verifyPrivateFd(fd, c.S.IFREG, 0o600);
    var buffer: [129]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    const n = c.read(fd, &buffer, buffer.len);
    if (n != 64) return error.InvalidAdapterCapability;
    for (buffer[0..64]) |byte| if (!std.ascii.isHex(byte)) return error.InvalidAdapterCapability;
    return allocator.dupe(u8, buffer[0..64]);
}

pub fn verifySocketPath(allocator: std.mem.Allocator, path: []const u8) !void {
    try validateAbsolute(path);
    const run = std.fs.path.dirname(path) orelse return error.UnsafeSocketPath;
    const fd = try openPrivateRoot(allocator, run, false);
    defer closeFd(fd);
    const name = try allocator.dupeSentinel(u8, std.fs.path.basename(path), 0);
    defer allocator.free(name);
    const stat = metadata.statAt(fd, name.ptr, c.AT.SYMLINK_NOFOLLOW) catch |err| switch (err) {
        error.FileNotFound => return error.DaemonUnavailable,
        else => return err,
    };
    if (stat.mode & c.S.IFMT != c.S.IFSOCK or stat.uid != c.getuid() or stat.mode & 0o777 != 0o600) return error.UnsafeSocketPath;
}

test "private roots reject traversal and symlink components" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.UnsafePath, validateAbsolute("/tmp/../root"));
    try std.testing.expectError(error.UnsafePath, validateAbsolute("relative"));
    const io = std.testing.io;
    const base = try freshTestPath(allocator);
    defer allocator.free(base);
    defer std.Io.Dir.cwd().deleteTree(io, base) catch |err| std.log.err("test path cleanup failed: {s}", .{@errorName(err)});
    const root = try openPrivateRoot(allocator, base, true);
    defer closeFd(root);
    if (c.symlinkat(".", root, "alias") != 0) return error.SymlinkFailed;
    const alias = try std.fmt.allocPrint(allocator, "{s}/alias", .{base});
    defer allocator.free(alias);
    try std.testing.expectError(error.PathOpenFailed, openPrivateRoot(allocator, alias, false));
}

test "custody is exclusive and refuses permissive private roots" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const path = try freshTestPath(a);
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, path) catch |err| std.log.err("test path cleanup failed: {s}", .{@errorName(err)});
    const locations = try Locations.init(a, path);
    var first = try Custody.acquire(a, locations);
    defer first.deinit();
    try std.testing.expectError(error.DaemonAlreadyRunning, Custody.acquire(a, locations));
    if (c.fchmod(first.state_fd, 0o755) != 0) return error.PermissionChangeFailed;
    try std.testing.expectError(error.UnsafePrivatePath, openPrivateRoot(a, path, false));
}

test "runtime selection uses absent fallback and rejects explicit unsafe input" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const base = try freshTestPath(a);
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, base) catch |err| std.log.err("test path cleanup failed: {s}", .{@errorName(err)});
    const fd = try openPrivateRoot(a, base, true);
    defer closeFd(fd);
    const state = try std.fmt.allocPrint(a, "{s}/state", .{base});
    const fallback = try Locations.fromRuntime(a, state, null);
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(a, "{s}/run", .{state}), fallback.run);
    try std.testing.expectError(error.UnsafePath, Locations.fromRuntime(a, state, ""));
    try std.testing.expectError(error.UnsafePath, Locations.fromRuntime(a, state, "relative"));
    try std.testing.expectError(error.UnsafePath, Locations.fromRuntime(a, state, "/tmp/../runtime"));
    const missing = try std.fmt.allocPrint(a, "{s}/missing", .{base});
    try std.testing.expectError(error.PathOpenFailed, Locations.fromRuntime(a, state, missing));
    try std.testing.expectError(error.FileNotFound, metadata.statAt(fd, "missing", c.AT.SYMLINK_NOFOLLOW));
    if (c.fchmod(fd, 0o755) != 0) return error.PermissionChangeFailed;
    try std.testing.expectError(error.UnsafePrivatePath, Locations.fromRuntime(a, state, base));
}

test "runtime roots reject symlink aliases and writable ancestors" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const base = try freshTestPath(a);
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, base) catch |err| std.log.err("test path cleanup failed: {s}", .{@errorName(err)});
    const fd = try openPrivateRoot(a, base, true);
    defer closeFd(fd);
    if (c.symlinkat(".", fd, "alias") != 0) return error.SymlinkFailed;
    const alias = try std.fmt.allocPrint(a, "{s}/alias", .{base});
    try std.testing.expectError(error.PathOpenFailed, Locations.fromRuntime(a, "/state", alias));
    if (c.mkdirat(fd, "runtime", 0o700) != 0) return error.PathCreateFailed;
    const runtime = try std.fmt.allocPrint(a, "{s}/runtime", .{base});
    if (c.fchmod(fd, 0o777) != 0) return error.PermissionChangeFailed;
    try std.testing.expectError(error.UnsafePathPermissions, Locations.fromRuntime(a, "/state", runtime));
}

test "production environment preserves strict runtime presence and state precedence" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var env = std.process.Environ.Map.init(a);
    defer env.deinit();
    try env.put("HOME", "/fixture-home");
    try env.put("XDG_STATE_HOME", "/fixture-state");
    const state = try defaultState(a, &env);
    const expected = if (builtin.os.tag == .linux) "/fixture-state/omux" else "/fixture-home/Library/Application Support/Omux";
    try std.testing.expectEqualStrings(expected, state);
    const fallback = try Locations.fromEnvironment(a, state, &env);
    try std.testing.expectEqualStrings(try std.fmt.allocPrint(a, "{s}/run", .{state}), fallback.run);
    try env.put("XDG_RUNTIME_DIR", "");
    if (builtin.os.tag == .linux) {
        try std.testing.expectError(error.UnsafePath, Locations.fromEnvironment(a, state, &env));
    } else {
        const unchanged = try Locations.fromEnvironment(a, state, &env);
        try std.testing.expectEqualStrings(fallback.run, unchanged.run);
    }
}

test "distinct state installations share runtime root without socket collision" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const base = try freshTestPath(a);
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, base) catch |err| std.log.err("test path cleanup failed: {s}", .{@errorName(err)});
    const fd = try openPrivateRoot(a, base, true);
    defer closeFd(fd);
    const first_state = try std.fmt.allocPrint(a, "{s}/first", .{base});
    const second_state = try std.fmt.allocPrint(a, "{s}/second", .{base});
    const first = try Locations.fromRuntime(a, first_state, base);
    const same = try Locations.fromRuntime(a, first_state, base);
    const second = try Locations.fromRuntime(a, second_state, base);
    try std.testing.expectEqualStrings(first.run, same.run);
    try std.testing.expect(!std.mem.eql(u8, first.run, second.run));
    try std.testing.expectEqual(@as(usize, "omux-".len + 32), std.fs.path.basename(first.run).len);
    var one = try Custody.acquire(a, first);
    defer one.deinit();
    var two = try Custody.acquire(a, second);
    defer two.deinit();
    try std.testing.expectEqual(@as(u32, 0o700), (try statFd(one.run_fd)).mode & 0o777);
    try std.testing.expectEqual(@as(u32, 0o600), (try metadata.statAt(one.state_fd, "daemon.lock", c.AT.SYMLINK_NOFOLLOW)).mode & 0o777);
    try std.testing.expectError(error.FileNotFound, metadata.statAt(one.run_fd, "daemon.lock", c.AT.SYMLINK_NOFOLLOW));
}

test "state singleton fences a second daemon with a different runtime selection" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const base = try freshTestPath(a);
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, base) catch |err| std.log.err("test path cleanup failed: {s}", .{@errorName(err)});
    const fd = try openPrivateRoot(a, base, true);
    defer closeFd(fd);
    const state = try std.fmt.allocPrint(a, "{s}/state", .{base});
    var first = try Custody.acquire(a, try Locations.init(a, state));
    defer first.deinit();
    const alternative = try Locations.fromRuntime(a, state, base);
    try std.testing.expectError(error.DaemonAlreadyRunning, Custody.acquire(a, alternative));
    try std.testing.expectError(error.FileNotFound, metadata.statAt(fd, (try a.dupeSentinel(u8, std.fs.path.basename(alternative.run), 0)).ptr, c.AT.SYMLINK_NOFOLLOW));
}

test "socket paths reject lengths that would truncate the native address" {
    const limit: usize = if (builtin.os.tag == .macos) 103 else 107;
    var state: [108]u8 = @splat('a');
    state[0] = '/';
    // state + /run + /control.sock must fit including its NUL terminator.
    const allowed = limit - "/run/control.sock".len;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const locations = try Locations.init(a, state[0..allowed]);
    try std.testing.expectEqual(limit, locations.control.len);
    try std.testing.expectError(error.SocketPathTooLong, Locations.init(a, state[0 .. allowed + 1]));
}

test "existing legacy daemon lock blocks upgrade and remains fenced until shutdown" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const base = try freshTestPath(a);
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, base) catch |err| std.log.err("test path cleanup failed: {s}", .{@errorName(err)});
    const locations = try Locations.init(a, base);
    const run_fd = try openPrivateRoot(a, locations.run, true);
    defer closeFd(run_fd);
    const legacy = c.openat(run_fd, "daemon.lock", .{ .ACCMODE = .RDWR, .CREAT = true, .NOFOLLOW = true, .CLOEXEC = true }, @as(c.mode_t, 0o600));
    if (legacy < 0) return error.LockOpenFailed;
    defer closeFd(legacy);
    if (flock(legacy, c.LOCK.EX | c.LOCK.NB) != 0) return error.LockAcquireFailed;
    try std.testing.expectError(error.DaemonAlreadyRunning, Custody.acquire(a, locations));
    if (flock(legacy, c.LOCK.UN) != 0) return error.LockAcquireFailed;
    var current = try Custody.acquire(a, locations);
    var current_open = true;
    defer if (current_open) current.deinit();
    try std.testing.expect(current.legacy_lock_fd != null);
    const result = flock(legacy, c.LOCK.EX | c.LOCK.NB);
    try std.testing.expect(result != 0);
    try std.testing.expectEqual(std.posix.E.AGAIN, std.posix.errno(result));
    current.deinit();
    current_open = false;
    if (flock(legacy, c.LOCK.EX | c.LOCK.NB) != 0) return error.LockAcquireFailed;
}

test "legacy compatibility probe rejects symlink and unsafe lock metadata" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const base = try freshTestPath(a);
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, base) catch |err| std.log.err("test path cleanup failed: {s}", .{@errorName(err)});
    const locations = try Locations.init(a, base);
    const state_fd = try openPrivateRoot(a, locations.state, true);
    defer closeFd(state_fd);
    if (c.symlinkat(".", state_fd, "run") != 0) return error.SymlinkFailed;
    try std.testing.expectError(error.PathOpenFailed, Custody.acquire(a, locations));
    if (c.unlinkat(state_fd, "run", 0) != 0) return error.PathDeleteFailed;
    const run_fd = try openPrivateRoot(a, locations.run, true);
    defer closeFd(run_fd);
    if (c.symlinkat("missing", run_fd, "daemon.lock") != 0) return error.SymlinkFailed;
    try std.testing.expectError(error.LockOpenFailed, Custody.acquire(a, locations));
    if (c.unlinkat(run_fd, "daemon.lock", 0) != 0) return error.PathDeleteFailed;
    const legacy = c.openat(run_fd, "daemon.lock", .{ .ACCMODE = .RDWR, .CREAT = true, .NOFOLLOW = true, .CLOEXEC = true }, @as(c.mode_t, 0o600));
    if (legacy < 0) return error.LockOpenFailed;
    defer closeFd(legacy);
    if (c.fchmod(legacy, 0o644) != 0) return error.PermissionChangeFailed;
    try std.testing.expectError(error.UnsafePrivatePath, Custody.acquire(a, locations));
    if (c.fchmod(legacy, 0o600) != 0) return error.PermissionChangeFailed;
    if (c.linkat(run_fd, "daemon.lock", run_fd, "alias.lock", 0) != 0) return error.PathCreateFailed;
    try std.testing.expectError(error.UnsafePrivatePath, Custody.acquire(a, locations));
}

fn freshTestPath(allocator: std.mem.Allocator) ![]u8 {
    var nonce: [8]u8 = undefined;
    std.testing.io.random(&nonce);
    return std.fmt.allocPrint(allocator, "{s}/omux-paths-{s}", .{ if (builtin.os.tag == .macos) "/private/tmp" else "/tmp", std.fmt.bytesToHex(nonce, .lower) });
}
