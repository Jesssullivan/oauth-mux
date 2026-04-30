const std = @import("std");
const health_mod = @import("health.zig");
const paths = @import("paths.zig");
const log = @import("log.zig");
const builtin = @import("builtin");

const Pid = if (builtin.os.tag == .windows) u32 else std.posix.pid_t;

pub const DaemonError = error{
    AlreadyRunning,
    SocketError,
    ForkFailed,
    ConfigError,
    OutOfMemory,
};

pub fn run(allocator: std.mem.Allocator) DaemonError!void {
    if (comptime builtin.os.tag == .windows) {
        log.err("daemon: foreground socket transport is not implemented on windows", .{});
        return error.SocketError;
    }

    const sock_path = paths.socketPath(allocator) catch return error.OutOfMemory;
    defer allocator.free(sock_path);

    const pid_path = pidPath(allocator) catch return error.OutOfMemory;
    defer allocator.free(pid_path);

    if (isRunning(allocator)) {
        log.err("daemon: already running", .{});
        return error.AlreadyRunning;
    }

    ensureRuntimeDir(sock_path) catch return error.SocketError;

    writePidFile(pid_path, currentPid()) catch return error.SocketError;
    defer std.fs.deleteFileAbsolute(pid_path) catch {};

    runLoop(allocator, sock_path) catch return error.SocketError;
}

pub fn start(allocator: std.mem.Allocator) DaemonError!void {
    if (comptime builtin.os.tag == .windows) {
        log.err("daemon: unsupported on windows", .{});
        return error.SocketError;
    }

    const sock_path = paths.socketPath(allocator) catch return error.OutOfMemory;
    defer allocator.free(sock_path);

    const pid_path = pidPath(allocator) catch return error.OutOfMemory;
    defer allocator.free(pid_path);

    // Check if already running
    if (isRunning(allocator)) {
        log.err("daemon: already running", .{});
        return error.AlreadyRunning;
    }

    ensureRuntimeDir(sock_path) catch return error.SocketError;

    // Fork into background
    if (comptime builtin.os.tag == .linux or builtin.os.tag == .macos) {
        const pid = std.posix.fork() catch return error.ForkFailed;
        if (pid != 0) {
            // Parent: write PID file and exit
            writePidFile(pid_path, pid) catch {};
            log.info("daemon: started (pid {d})", .{pid});
            return;
        }
        // Child: continue to event loop
    }

    // Child continues after fork — parent already returned

    // Run the daemon event loop
    runLoop(allocator, sock_path) catch |e| {
        log.err("daemon: loop error: {s}", .{@errorName(e)});
    };

    // Cleanup
    std.fs.deleteFileAbsolute(sock_path) catch {};
    std.fs.deleteFileAbsolute(pid_path) catch {};
}

fn ensureRuntimeDir(sock_path: []const u8) !void {
    if (std.fs.path.dirname(sock_path)) |dir| {
        std.fs.makeDirAbsolute(dir) catch |e| switch (e) {
            error.PathAlreadyExists => {},
            else => return e,
        };
    }
}

pub fn stop(allocator: std.mem.Allocator) !void {
    if (comptime builtin.os.tag == .windows) {
        log.err("daemon: unsupported on windows", .{});
        return;
    }

    const pid_path = try pidPath(allocator);
    defer allocator.free(pid_path);

    const pid = readPidFile(allocator, pid_path) catch {
        log.err("daemon: not running (no pid file)", .{});
        return;
    };

    // Send SIGTERM
    std.posix.kill(pid, std.posix.SIG.TERM) catch {
        log.err("daemon: failed to signal pid {d}", .{pid});
        std.fs.deleteFileAbsolute(pid_path) catch {};
        return;
    };

    log.info("daemon: stopped (pid {d})", .{pid});
    std.fs.deleteFileAbsolute(pid_path) catch {};
}

pub fn status(allocator: std.mem.Allocator, writer: anytype) !void {
    const pid_path = try pidPath(allocator);
    defer allocator.free(pid_path);

    if (isRunning(allocator)) {
        const pid = readPidFile(allocator, pid_path) catch 0;
        const sock = try paths.socketPath(allocator);
        defer allocator.free(sock);
        try writer.print("daemon: running (pid {d}, socket {s})\n", .{ pid, sock });
    } else {
        try writer.writeAll("daemon: not running\n");
    }
}

fn isRunning(allocator: std.mem.Allocator) bool {
    if (comptime builtin.os.tag == .windows) {
        return false;
    }

    const pid_path = pidPath(allocator) catch return false;
    defer allocator.free(pid_path);

    const pid = readPidFile(allocator, pid_path) catch return false;

    // Check if process is alive
    std.posix.kill(pid, 0) catch return false;
    return true;
}

fn runLoop(allocator: std.mem.Allocator, sock_path: []const u8) !void {
    if (comptime builtin.os.tag == .windows) {
        return error.Unsupported;
    }

    // Remove stale socket
    std.fs.deleteFileAbsolute(sock_path) catch {};

    const addr = std.net.Address.initUnix(sock_path) catch return error.Unexpected;
    var server = addr.listen(.{ .reuse_address = true }) catch return error.Unexpected;
    defer server.deinit();

    log.info("daemon: listening on {s}", .{sock_path});

    // Main loop: accept connections and handle commands
    while (true) {
        if (server.accept()) |conn| {
            defer conn.stream.close();
            handleConnection(allocator, conn.stream) catch |e| {
                log.debug("daemon: connection error: {s}", .{@errorName(e)});
            };
        } else |_| {
            break;
        }
    }
}

fn handleConnection(allocator: std.mem.Allocator, stream: std.net.Stream) !void {
    var buf: [1024]u8 = undefined;
    const n = stream.read(&buf) catch return;
    if (n == 0) return;

    const cmd = std.mem.trim(u8, buf[0..n], " \t\n\r");

    if (std.mem.eql(u8, cmd, "status")) {
        var store = health_mod.HealthStore.load(allocator, .{});
        defer store.deinit();

        var resp = std.ArrayList(u8).init(allocator);
        defer resp.deinit();
        const writer = resp.writer();

        try writer.writeAll("{\"status\":\"running\",\"accounts\":{");
        var first = true;
        var it = store.accounts.iterator();
        while (it.next()) |entry| {
            if (!first) try writer.writeByte(',');
            first = false;
            try writer.print("\"{s}\":{{\"score\":{d},\"circuit\":\"{s}\"}}", .{
                entry.key_ptr.*,
                entry.value_ptr.score.score,
                switch (entry.value_ptr.circuit) {
                    .closed => "closed",
                    .open => "open",
                    .half_open => "half_open",
                },
            });
        }
        try writer.writeAll("}}\n");
        _ = stream.write(resp.items) catch {};
    } else if (std.mem.eql(u8, cmd, "stop")) {
        _ = stream.write("stopping\n") catch {};
        std.process.exit(0);
    } else if (std.mem.startsWith(u8, cmd, "refresh ")) {
        _ = stream.write("refresh unsupported; use oauth-mux repair-plan\n") catch {};
    } else {
        _ = stream.write("unknown command\n") catch {};
    }
}

fn pidPath(allocator: std.mem.Allocator) ![]const u8 {
    const dir = paths.runtimeDir(allocator) catch return error.OutOfMemory;
    defer allocator.free(dir);
    return std.fs.path.join(allocator, &.{ dir, "daemon.pid" });
}

fn currentPid() Pid {
    return switch (builtin.os.tag) {
        .linux => std.os.linux.getpid(),
        .macos => std.c.getpid(),
        else => 0,
    };
}

fn writePidFile(path: []const u8, pid: Pid) !void {
    if (std.fs.path.dirname(path)) |dir| {
        std.fs.makeDirAbsolute(dir) catch |e| switch (e) {
            error.PathAlreadyExists => {},
            else => return e,
        };
    }
    const file = try std.fs.createFileAbsolute(path, .{ .mode = 0o600 });
    defer file.close();
    try file.writer().print("{d}", .{pid});
}

fn readPidFile(allocator: std.mem.Allocator, path: []const u8) !Pid {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    var buf: [32]u8 = undefined;
    const n = try file.readAll(&buf);
    const pid_str = std.mem.trim(u8, buf[0..n], " \t\n\r");
    _ = allocator;
    return std.fmt.parseInt(Pid, pid_str, 10) catch return error.InvalidCharacter;
}

test "isRunning returns false when no daemon" {
    try std.testing.expect(!isRunning(std.testing.allocator));
}
