const std = @import("std");
const env = @import("env.zig");
const health_mod = @import("health.zig");
const paths = @import("paths.zig");
const log = @import("log.zig");
const repair_state = @import("repair_state.zig");
const builtin = @import("builtin");

const Pid = if (builtin.os.tag == .windows) u32 else std.posix.pid_t;
const stay_afloat_snapshot_stale_after_s: i64 = 300;

pub const DaemonError = error{
    AlreadyRunning,
    SocketError,
    ForkFailed,
    ConfigError,
    OutOfMemory,
};

pub const RunGuard = struct {
    allocator: std.mem.Allocator,
    pid_path: []const u8,
    metadata_path: []const u8,

    pub fn release(self: *RunGuard) void {
        std.fs.deleteFileAbsolute(self.pid_path) catch {};
        std.fs.deleteFileAbsolute(self.metadata_path) catch {};
        self.allocator.free(self.pid_path);
        self.allocator.free(self.metadata_path);
    }
};

pub const StayAfloatRunMetadata = struct {
    profile: ?[]const u8 = null,
    provider: ?[]const u8 = null,
    account: ?[]const u8 = null,
    capability: ?[]const u8 = null,
    once: bool = true,
    iterations: u32 = 1,
    interval_ms: u64 = 60_000,
    execute: bool = true,
};

const SnapshotFreshness = struct {
    present: bool,
    parseable: bool,
    last_tick_at: ?i64 = null,
    age_seconds: ?i64 = null,
    loop_started_at: ?i64 = null,
    current_loop_observed: ?bool = null,
    stale_after_seconds: i64 = stay_afloat_snapshot_stale_after_s,
    stale: bool = true,
    reason: []const u8,
};

const StatusLoopInfo = struct {
    started_at: ?i64 = null,
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

pub fn acquireStayAfloatRunGuard(allocator: std.mem.Allocator, metadata: StayAfloatRunMetadata) DaemonError!RunGuard {
    if (comptime builtin.os.tag == .windows) {
        log.err("daemon: foreground stay-afloat loop is not implemented on windows", .{});
        return error.SocketError;
    }

    const pid_path = pidPath(allocator) catch return error.OutOfMemory;
    errdefer allocator.free(pid_path);

    const metadata_path = metadataPath(allocator) catch return error.OutOfMemory;
    errdefer allocator.free(metadata_path);

    if (isRunning(allocator)) {
        log.err("daemon: already running", .{});
        return error.AlreadyRunning;
    }

    ensureParentDir(pid_path) catch return error.SocketError;
    writePidFile(pid_path, currentPid()) catch return error.SocketError;
    errdefer std.fs.deleteFileAbsolute(pid_path) catch {};

    writeStayAfloatMetadata(metadata_path, metadata) catch return error.SocketError;
    return .{
        .allocator = allocator,
        .pid_path = pid_path,
        .metadata_path = metadata_path,
    };
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
        // The macOS runtime dir lives under ~/Library/Application Support and
        // is more than one level deep (TIN-2041); create the full path.
        try std.fs.cwd().makePath(dir);
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

    const metadata_path = metadataPath(allocator) catch null;
    defer if (metadata_path) |path| allocator.free(path);

    log.info("daemon: stopped (pid {d})", .{pid});
    std.fs.deleteFileAbsolute(pid_path) catch {};
    if (metadata_path) |path| std.fs.deleteFileAbsolute(path) catch {};
}

pub fn status(allocator: std.mem.Allocator, writer: anytype, json: bool) !void {
    const pid_path = try pidPath(allocator);
    defer allocator.free(pid_path);

    const running = isRunning(allocator);
    const loop_hosted = if (running) hasStayAfloatMetadata(allocator) else false;

    if (running) {
        const pid = readPidFile(allocator, pid_path) catch 0;
        const sock = try paths.socketPath(allocator);
        defer allocator.free(sock);
        if (json) {
            try writer.writeAll("{\"status\":\"running\"");
            try writeStatusContractJson(writer, loop_hosted);
            const loop_info = try writeStatusLoopJson(allocator, writer, loop_hosted);
            try writeStatusSnapshotJson(allocator, writer, loop_info.started_at);
            try writer.print(",\"pid\":{d},\"transport\":", .{pid});
            try std.json.stringify(if (loop_hosted) "foreground_tick_loop" else "unix_socket", .{}, writer);
            try writer.writeAll(",\"socket\":");
            if (loop_hosted) try writer.writeAll("null") else try std.json.stringify(sock, .{}, writer);
            try writer.writeAll("}\n");
        } else {
            if (loop_hosted) {
                try writer.print("daemon: running foreground stay-afloat tick loop (pid {d})\n", .{pid});
            } else {
                try writer.print("daemon: running (pid {d}, socket {s})\n", .{ pid, sock });
            }
            try writer.writeAll("daemon: experimental; stay-afloat contract is the foreground tick engine\n");
        }
    } else {
        if (json) {
            try writer.writeAll("{\"status\":\"not_running\"");
            try writeStatusContractJson(writer, false);
            const loop_info = try writeStatusLoopJson(allocator, writer, false);
            try writeStatusSnapshotJson(allocator, writer, loop_info.started_at);
            try writer.writeAll("}\n");
        } else {
            try writer.writeAll("daemon: not running\n");
            try writer.writeAll("daemon: experimental; stay-afloat contract is the foreground tick engine\n");
        }
    }
}

fn writeStatusContractJson(writer: anytype, loop_hosted: bool) !void {
    try writer.writeAll(",\"contract\":");
    try std.json.stringify(if (loop_hosted) "experimental_foreground_tick_loop" else "experimental_socket_stub", .{}, writer);
    try writer.writeAll(",\"production_supported\":false");
    try writer.writeAll(",\"hosts_stay_afloat\":false");
    try writer.writeAll(",\"wrapper_contract\":\"foreground_tick\"");
    try writer.writeAll(",\"socket_transport_supported\":");
    try writer.writeAll(if (builtin.os.tag == .windows) "false" else "true");
}

fn writeStatusLoopJson(allocator: std.mem.Allocator, writer: anytype, loop_hosted: bool) !StatusLoopInfo {
    try writer.writeAll(",\"stay_afloat_loop\":");
    if (loop_hosted) {
        const metadata = try readMetadataAlloc(allocator);
        if (metadata) |bytes| {
            defer allocator.free(bytes);
            const trimmed = std.mem.trim(u8, bytes, " \t\r\n");
            if (trimmed.len != 0 and trimmed[0] == '{') {
                try writer.writeAll(trimmed);
                return .{ .started_at = jsonObjectI64(allocator, trimmed, "started_at") };
            }
        }
    }
    try writer.writeAll("{\"hosted\":false,\"production_supported\":false}");
    return .{};
}

fn writeStatusSnapshotJson(allocator: std.mem.Allocator, writer: anytype, loop_started_at: ?i64) !void {
    try writer.writeAll(",\"stay_afloat\":");
    const now = std.time.timestamp();
    const snapshot = try repair_state.readDaemonSnapshotAlloc(allocator);
    const freshness = if (snapshot) |bytes| blk: {
        defer allocator.free(bytes);
        const trimmed = std.mem.trim(u8, bytes, " \t\r\n");
        const classified = snapshotFreshnessFromBytes(allocator, trimmed, now, loop_started_at);
        if (trimmed.len != 0 and classified.parseable) {
            try writer.writeAll(trimmed);
        } else {
            try writer.writeAll("null");
        }
        break :blk classified;
    } else blk: {
        try writer.writeAll("null");
        break :blk missingSnapshotFreshness();
    };

    try writer.writeAll(",\"stay_afloat_snapshot\":");
    try writeSnapshotFreshnessJson(writer, freshness);
}

fn snapshotFreshnessFromBytes(
    allocator: std.mem.Allocator,
    trimmed: []const u8,
    now: i64,
    loop_started_at: ?i64,
) SnapshotFreshness {
    if (trimmed.len == 0) return .{
        .present = false,
        .parseable = false,
        .loop_started_at = loop_started_at,
        .current_loop_observed = if (loop_started_at == null) null else false,
        .reason = "empty",
    };

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, trimmed, .{}) catch {
        return .{
            .present = true,
            .parseable = false,
            .loop_started_at = loop_started_at,
            .current_loop_observed = if (loop_started_at == null) null else false,
            .reason = "malformed",
        };
    };
    defer parsed.deinit();

    const obj = switch (parsed.value) {
        .object => |obj| obj,
        else => return .{
            .present = true,
            .parseable = true,
            .loop_started_at = loop_started_at,
            .current_loop_observed = if (loop_started_at == null) null else false,
            .reason = "missing_last_tick_at",
        },
    };

    const last_tick_at = switch (obj.get("last_tick_at") orelse return .{
        .present = true,
        .parseable = true,
        .loop_started_at = loop_started_at,
        .current_loop_observed = if (loop_started_at == null) null else false,
        .reason = "missing_last_tick_at",
    }) {
        .integer => |value| value,
        else => return .{
            .present = true,
            .parseable = true,
            .loop_started_at = loop_started_at,
            .current_loop_observed = if (loop_started_at == null) null else false,
            .reason = "invalid_last_tick_at",
        },
    };

    const age = if (last_tick_at > now) 0 else now - last_tick_at;
    const stale = age > stay_afloat_snapshot_stale_after_s;
    const current_loop_observed = if (loop_started_at) |started_at| last_tick_at >= started_at else null;
    return .{
        .present = true,
        .parseable = true,
        .last_tick_at = last_tick_at,
        .age_seconds = age,
        .loop_started_at = loop_started_at,
        .current_loop_observed = current_loop_observed,
        .stale = stale,
        .reason = if (stale) "stale" else if (current_loop_observed == false) "before_current_loop" else "fresh",
    };
}

fn missingSnapshotFreshness() SnapshotFreshness {
    return .{
        .present = false,
        .parseable = false,
        .reason = "missing",
    };
}

fn writeSnapshotFreshnessJson(writer: anytype, freshness: SnapshotFreshness) !void {
    try writer.writeAll("{\"present\":");
    try writer.writeAll(if (freshness.present) "true" else "false");
    try writer.writeAll(",\"parseable\":");
    try writer.writeAll(if (freshness.parseable) "true" else "false");
    try writer.writeAll(",\"last_tick_at\":");
    if (freshness.last_tick_at) |last_tick_at| try writer.print("{d}", .{last_tick_at}) else try writer.writeAll("null");
    try writer.writeAll(",\"age_seconds\":");
    if (freshness.age_seconds) |age_seconds| try writer.print("{d}", .{age_seconds}) else try writer.writeAll("null");
    try writer.writeAll(",\"loop_started_at\":");
    if (freshness.loop_started_at) |started_at| try writer.print("{d}", .{started_at}) else try writer.writeAll("null");
    try writer.writeAll(",\"current_loop_observed\":");
    if (freshness.current_loop_observed) |observed| try writer.writeAll(if (observed) "true" else "false") else try writer.writeAll("null");
    try writer.writeAll(",\"stale_after_seconds\":");
    try writer.print("{d}", .{freshness.stale_after_seconds});
    try writer.writeAll(",\"stale\":");
    try writer.writeAll(if (freshness.stale) "true" else "false");
    try writer.writeAll(",\"reason\":");
    try std.json.stringify(freshness.reason, .{}, writer);
    try writer.writeAll("}");
}

fn jsonObjectI64(allocator: std.mem.Allocator, bytes: []const u8, field: []const u8) ?i64 {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch return null;
    defer parsed.deinit();
    const obj = switch (parsed.value) {
        .object => |obj| obj,
        else => return null,
    };
    return switch (obj.get(field) orelse return null) {
        .integer => |value| value,
        else => null,
    };
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
    try ensureParentDir(path);
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

fn metadataPath(allocator: std.mem.Allocator) ![]const u8 {
    const dir = paths.runtimeDir(allocator) catch return error.OutOfMemory;
    defer allocator.free(dir);
    return std.fs.path.join(allocator, &.{ dir, "daemon-metadata.json" });
}

fn writeStayAfloatMetadata(path: []const u8, metadata: StayAfloatRunMetadata) !void {
    try ensureParentDir(path);
    const file = try std.fs.createFileAbsolute(path, .{ .truncate = true, .mode = 0o600 });
    defer file.close();
    try writeStayAfloatMetadataJson(file.writer(), metadata);
}

fn writeStayAfloatMetadataJson(writer: anytype, metadata: StayAfloatRunMetadata) !void {
    try writer.writeAll("{\"hosted\":true");
    try writer.writeAll(",\"mode\":\"stay_afloat_tick_loop\"");
    try writer.writeAll(",\"contract\":\"beta_foreground_tick_host\"");
    try writer.writeAll(",\"production_supported\":false");
    try writer.writeAll(",\"selector\":{");
    try writer.writeAll("\"profile\":");
    if (metadata.profile) |profile| try std.json.stringify(profile, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"provider\":");
    if (metadata.provider) |provider| try std.json.stringify(provider, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"account\":");
    if (metadata.account) |account| try std.json.stringify(account, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"capability\":");
    if (metadata.capability) |capability| try std.json.stringify(capability, .{}, writer) else try writer.writeAll("null");
    try writer.writeByte('}');
    try writer.writeAll(",\"once\":");
    try writer.writeAll(if (metadata.once) "true" else "false");
    try writer.writeAll(",\"iterations\":");
    try writer.print("{d}", .{metadata.iterations});
    try writer.writeAll(",\"interval_ms\":");
    try writer.print("{d}", .{metadata.interval_ms});
    try writer.writeAll(",\"execution_mode\":");
    try std.json.stringify(if (metadata.execute) "execute" else "plan", .{}, writer);
    try writer.writeAll(",\"started_at\":");
    try writer.print("{d}", .{std.time.timestamp()});
    try writer.writeAll("}\n");
}

fn readMetadataAlloc(allocator: std.mem.Allocator) !?[]const u8 {
    const path = try metadataPath(allocator);
    defer allocator.free(path);
    const file = std.fs.openFileAbsolute(path, .{}) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return e,
    };
    defer file.close();
    return try file.readToEndAlloc(allocator, 16 * 1024);
}

fn hasStayAfloatMetadata(allocator: std.mem.Allocator) bool {
    const metadata = readMetadataAlloc(allocator) catch return false;
    if (metadata) |bytes| {
        defer allocator.free(bytes);
        return std.mem.indexOf(u8, bytes, "\"hosted\":true") != null and
            (std.mem.indexOf(u8, bytes, "\"mode\":\"stay_afloat_tick_loop\"") != null or
                std.mem.indexOf(u8, bytes, "\"mode\":\"stay_afloat_supervisor\"") != null);
    }
    return false;
}

fn ensureParentDir(path: []const u8) !void {
    if (std.fs.path.dirname(path)) |dir| {
        // The macOS runtime dir lives under ~/Library/Application Support and
        // is more than one level deep (TIN-2041); create the full path.
        try std.fs.cwd().makePath(dir);
    }
}

/// Test helper: point the runtime and state dirs at a per-test tmp dir via
/// the OMUX_RUNTIME_DIR / OMUX_STATE_DIR seams so daemon tests assert a
/// synthetic state instead of the developer's real machine state.
const TestDaemonDirScope = struct {
    tmp: std.testing.TmpDir,
    root: []const u8,
    overrides: std.process.EnvMap,

    fn init(allocator: std.mem.Allocator) !TestDaemonDirScope {
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        const root = try tmp.dir.realpathAlloc(allocator, ".");
        errdefer allocator.free(root);
        var overrides = std.process.EnvMap.init(allocator);
        errdefer overrides.deinit();
        try overrides.put("OMUX_RUNTIME_DIR", root);
        try overrides.put("OMUX_STATE_DIR", root);
        return .{ .tmp = tmp, .root = root, .overrides = overrides };
    }

    fn activate(self: *TestDaemonDirScope) void {
        env.test_overrides = &self.overrides;
    }

    fn deinit(self: *TestDaemonDirScope, allocator: std.mem.Allocator) void {
        env.test_overrides = null;
        self.overrides.deinit();
        allocator.free(self.root);
        self.tmp.cleanup();
    }
};

test "isRunning returns false when no daemon" {
    var scope = try TestDaemonDirScope.init(std.testing.allocator);
    defer scope.deinit(std.testing.allocator);
    scope.activate();

    try std.testing.expect(!isRunning(std.testing.allocator));
}

test "isRunning returns true for a live pid in the runtime pid file" {
    if (comptime builtin.os.tag == .windows) return error.SkipZigTest;
    const a = std.testing.allocator;
    var scope = try TestDaemonDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    // Synthetic pid file carrying this test process's own (live) pid.
    const pid_path = try pidPath(a);
    defer a.free(pid_path);
    try writePidFile(pid_path, currentPid());

    try std.testing.expect(isRunning(a));
}

test "status json exposes socket daemon contract" {
    var scope = try TestDaemonDirScope.init(std.testing.allocator);
    defer scope.deinit(std.testing.allocator);
    scope.activate();

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try status(std.testing.allocator, buf.writer(), true);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"status\":\"not_running\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"contract\":\"experimental_socket_stub\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"production_supported\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"hosts_stay_afloat\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"wrapper_contract\":\"foreground_tick\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"stay_afloat_loop\":{\"hosted\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"stay_afloat\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"stay_afloat_snapshot\":") != null);
}

test "stay-afloat snapshot freshness reports fresh and stale snapshots" {
    const fresh = snapshotFreshnessFromBytes(std.testing.allocator, "{\"last_tick_at\":1000}", 1100, null);
    try std.testing.expect(fresh.present);
    try std.testing.expect(fresh.parseable);
    try std.testing.expectEqual(@as(?i64, 1000), fresh.last_tick_at);
    try std.testing.expectEqual(@as(?i64, 100), fresh.age_seconds);
    try std.testing.expect(!fresh.stale);
    try std.testing.expectEqualStrings("fresh", fresh.reason);

    const stale = snapshotFreshnessFromBytes(std.testing.allocator, "{\"last_tick_at\":1000}", 1301, null);
    try std.testing.expect(stale.present);
    try std.testing.expect(stale.parseable);
    try std.testing.expectEqual(@as(?i64, 301), stale.age_seconds);
    try std.testing.expect(stale.stale);
    try std.testing.expectEqualStrings("stale", stale.reason);

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try writeSnapshotFreshnessJson(buf.writer(), fresh);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"present\":true,\"parseable\":true,\"last_tick_at\":1000") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"age_seconds\":100") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"loop_started_at\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"current_loop_observed\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"stale_after_seconds\":300") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"stale\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"reason\":\"fresh\"") != null);
}

test "stay-afloat snapshot freshness reports missing and malformed snapshots" {
    const missing = missingSnapshotFreshness();
    try std.testing.expect(!missing.present);
    try std.testing.expect(!missing.parseable);
    try std.testing.expect(missing.stale);
    try std.testing.expectEqualStrings("missing", missing.reason);

    const empty = snapshotFreshnessFromBytes(std.testing.allocator, "", 1100, null);
    try std.testing.expect(!empty.present);
    try std.testing.expect(!empty.parseable);
    try std.testing.expect(empty.stale);
    try std.testing.expectEqualStrings("empty", empty.reason);

    const malformed = snapshotFreshnessFromBytes(std.testing.allocator, "{\"last_tick_at\":", 1100, null);
    try std.testing.expect(malformed.present);
    try std.testing.expect(!malformed.parseable);
    try std.testing.expect(malformed.stale);
    try std.testing.expectEqualStrings("malformed", malformed.reason);

    const missing_tick = snapshotFreshnessFromBytes(std.testing.allocator, "{\"version\":\"test\"}", 1100, null);
    try std.testing.expect(missing_tick.present);
    try std.testing.expect(missing_tick.parseable);
    try std.testing.expect(missing_tick.stale);
    try std.testing.expectEqualStrings("missing_last_tick_at", missing_tick.reason);
}

test "stay-afloat snapshot freshness identifies snapshots before active loop" {
    const before_loop = snapshotFreshnessFromBytes(std.testing.allocator, "{\"last_tick_at\":1000}", 1100, 1050);
    try std.testing.expect(before_loop.present);
    try std.testing.expect(before_loop.parseable);
    try std.testing.expectEqual(@as(?i64, 1050), before_loop.loop_started_at);
    try std.testing.expectEqual(@as(?bool, false), before_loop.current_loop_observed);
    try std.testing.expect(!before_loop.stale);
    try std.testing.expectEqualStrings("before_current_loop", before_loop.reason);

    const current_loop = snapshotFreshnessFromBytes(std.testing.allocator, "{\"last_tick_at\":1100}", 1100, 1050);
    try std.testing.expectEqual(@as(?i64, 1050), current_loop.loop_started_at);
    try std.testing.expectEqual(@as(?bool, true), current_loop.current_loop_observed);
    try std.testing.expect(!current_loop.stale);
    try std.testing.expectEqualStrings("fresh", current_loop.reason);
}

test "stay-afloat metadata json exposes selector and cadence" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeStayAfloatMetadataJson(buf.writer(), .{
        .profile = "codex-max",
        .capability = "codex-max",
        .once = false,
        .iterations = 200,
        .interval_ms = 50,
        .execute = true,
    });

    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"hosted\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"selector\":{\"profile\":\"codex-max\",\"provider\":null,\"account\":null,\"capability\":\"codex-max\"}") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"once\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"iterations\":200") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"interval_ms\":50") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "\"execution_mode\":\"execute\"") != null);
}
