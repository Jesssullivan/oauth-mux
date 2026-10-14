//! Resident per-user broker. Socket reads never hold the lifecycle writer lock.
//! A fixed worker pool and bounded queue isolate slow/malformed local clients.
const std = @import("std");
const builtin = @import("builtin");
const c = std.c;
const paths = @import("paths.zig");
const native_peer = @import("platform/peer.zig");
const metadata = @import("platform/file_metadata.zig");
const engine_module = @import("engine.zig");
const Engine = engine_module.Engine;
pub const Channel = engine_module.Channel;

pub const max_frame_bytes = 1024 * 1024;
pub const worker_count = 16;
pub const queue_capacity = 8;
// Lower-priority UI/browser clients cannot occupy every native-adapter worker.
const channel_workers = [_]usize{ 4, 4, 8 };
const control_connection_capacity = queue_capacity + channel_workers[0];
const control_slice_ms: i64 = 100;
pub const request_timeout_ms: i64 = 15_000;
pub const ConnectionError = error{ Timeout, PeerRejected, SocketFailed, FrameTooLarge, TrailingFrame, IncompleteFrame, EmptyFrame, ConnectionClosed };

extern "c" fn socket(domain: c_int, kind: c_int, protocol: c_int) c.fd_t;
extern "c" fn socketpair(domain: c_int, kind: c_int, protocol: c_int, pair: *[2]c.fd_t) c_int;
extern "c" fn getpeereid(fd: c.fd_t, uid: *c.uid_t, gid: *c.gid_t) c_int;
extern "c" fn signal(sig: c_int, handler: ?*const fn (c_int) callconv(.c) void) ?*const fn (c_int) callconv(.c) void;

var stopping: std.atomic.Value(bool) = .init(false);
fn stopSignal(_: c_int) callconv(.c) void {
    stopping.store(true, .release);
}

fn nonblocking(fd: c.fd_t) !void {
    const flags = c.fcntl(fd, c.F.GETFL);
    if (flags < 0 or c.fcntl(fd, c.F.SETFL, flags | @as(c_int, @bitCast(c.O{ .NONBLOCK = true }))) != 0) return error.SocketFailed;
    if (c.fcntl(fd, c.F.SETFD, @as(c_int, c.FD_CLOEXEC)) != 0) return error.SocketFailed;
    if (builtin.os.tag == .macos) {
        const enabled: c_int = 1;
        if (c.setsockopt(fd, c.SOL.SOCKET, c.SO.NOSIGPIPE, &enabled, @sizeOf(c_int)) != 0) return error.SocketFailed;
    }
}

/// Threaded's accept implementation assumes blocking listeners. A readiness
/// indication can race with peer closure, so handle EAGAIN at this boundary.
fn acceptReady(io: std.Io, listener: c.fd_t) !?std.Io.net.Stream {
    try io.checkCancel();
    const fd = if (builtin.os.tag == .linux)
        c.accept4(listener, null, null, c.SOCK.CLOEXEC | c.SOCK.NONBLOCK)
    else
        c.accept(listener, null, null);
    if (fd < 0) return switch (std.posix.errno(fd)) {
        .AGAIN, .INTR, .CONNABORTED => null,
        else => error.SocketFailed,
    };
    errdefer _ = c.close(fd);
    try nonblocking(fd);
    return .{ .socket = .{ .handle = fd, .address = .{ .ip4 = .loopback(0) } } };
}

/// Configure writer evidence before bind/listen, so even a peer's first queued
/// bytes carry ancillary authority. Unsupported platforms keep a private socket
/// whose protected requests refuse at capture, leaving control/status usable.
fn listenAdapter(io: std.Io, path: []const u8, custody: paths.Custody) !std.Io.net.Server {
    try io.checkCancel();
    if (path.len >= @as(c.sockaddr.un, undefined).path.len) return error.SocketPathTooLong;
    const fd = socket(c.AF.UNIX, c.SOCK.STREAM, 0);
    if (fd < 0) return error.SocketFailed;
    errdefer _ = c.close(fd);
    try nonblocking(fd);
    native_peer.Context.enable(fd) catch |err| switch (err) {
        error.UnsupportedPeerProfile => {},
        else => return err,
    };
    var addr: c.sockaddr.un = .{ .path = @splat(0) };
    @memcpy(addr.path[0..path.len], path);
    addr.path[path.len] = 0;
    const addr_len: c.socklen_t = @intCast(@offsetOf(c.sockaddr.un, "path") + path.len + 1);
    if (builtin.os.tag == .macos) addr.len = @intCast(addr_len);
    if (c.bind(fd, @ptrCast(&addr), addr_len) != 0) return error.SocketFailed;
    if (c.fchmodat(custody.run_fd, "adapter.sock", 0o600, 0) != 0) return error.SocketPermissionFailed;
    const bound = try metadata.statAt(custody.run_fd, "adapter.sock", c.AT.SYMLINK_NOFOLLOW);
    errdefer {
        const current = metadata.statAt(custody.run_fd, "adapter.sock", c.AT.SYMLINK_NOFOLLOW) catch null;
        if (current) |present| {
            if (present.dev == bound.dev and present.ino == bound.ino) custody.removeSocket("adapter.sock") catch |err| {
                std.log.err("owned adapter socket cleanup failed: {s}", .{@errorName(err)});
            };
        }
    }
    if (c.listen(fd, queue_capacity) != 0) return error.SocketFailed;
    return .{
        .socket = .{ .handle = fd, .address = .{ .ip4 = .loopback(0) } },
        .options = if (std.Io.net.Server.AcceptOptions != void) .{ .mode = .stream, .protocol = null },
    };
}

/// Authenticate both directions. A socket pathname is not server identity.
pub fn verifyPeer(fd: c.fd_t) !void {
    const uid = c.getuid();
    switch (builtin.os.tag) {
        .linux => {
            const Credentials = extern struct { pid: c.pid_t, uid: c.uid_t, gid: c.gid_t };
            var peer: Credentials = undefined;
            var len: c.socklen_t = @sizeOf(Credentials);
            if (c.getsockopt(fd, c.SOL.SOCKET, c.SO.PEERCRED, &peer, &len) != 0 or len != @sizeOf(Credentials) or peer.uid != uid) return error.PeerRejected;
        },
        .macos => {
            var peer_uid: c.uid_t = undefined;
            var peer_gid: c.gid_t = undefined;
            if (getpeereid(fd, &peer_uid, &peer_gid) != 0 or peer_uid != uid) return error.PeerRejected;
        },
        else => return error.PeerRejected,
    }
}

fn deadline(io: std.Io) std.Io.Clock.Timestamp {
    return deadlineAfter(io, request_timeout_ms);
}

fn channelDeadline(io: std.Io, channel: Channel) std.Io.Clock.Timestamp {
    return deadlineAfter(io, if (channel == .browser) 8_000 else request_timeout_ms);
}

fn deadlineAfter(io: std.Io, timeout_ms: i64) std.Io.Clock.Timestamp {
    return .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(timeout_ms) });
}

fn waitReady(io: std.Io, fd: c.fd_t, events: i16, until: std.Io.Clock.Timestamp) !void {
    var fds = [_]c.pollfd{.{ .fd = fd, .events = events, .revents = 0 }};
    while (true) {
        try io.checkCancel();
        const remaining = until.durationFromNow(io).raw.toMilliseconds();
        if (remaining <= 0) return error.Timeout;
        const rc = c.poll(&fds, 1, @intCast(@min(remaining, 200)));
        if (rc < 0) {
            if (std.posix.errno(rc) == .INTR) continue;
            return error.SocketFailed;
        }
        if (rc == 0) continue;
        if (fds[0].revents & events != 0) return;
        if (fds[0].revents & (c.POLL.ERR | c.POLL.HUP | c.POLL.NVAL) != 0) return error.ConnectionClosed;
    }
}

pub const Frame = struct {
    bytes: std.ArrayList(u8) = .empty,
    complete: bool = false,

    pub fn deinit(self: *Frame, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, self.bytes.items);
        self.bytes.deinit(allocator);
    }

    pub fn feed(self: *Frame, allocator: std.mem.Allocator, data: []const u8) !void {
        if (self.complete) return error.TrailingFrame;
        if (std.mem.indexOfScalar(u8, data, '\n')) |end| {
            if (end + 1 != data.len) return error.TrailingFrame;
            if (self.bytes.items.len + end > max_frame_bytes) return error.FrameTooLarge;
            try self.bytes.appendSlice(allocator, data[0..end]);
            if (self.bytes.items.len == 0) return error.EmptyFrame;
            self.complete = true;
        } else {
            if (self.bytes.items.len + data.len > max_frame_bytes) return error.FrameTooLarge;
            try self.bytes.appendSlice(allocator, data);
        }
    }
};

pub fn readFrame(io: std.Io, allocator: std.mem.Allocator, fd: c.fd_t, until: std.Io.Clock.Timestamp) ![]u8 {
    var frame: Frame = .{};
    errdefer frame.deinit(allocator);
    var buffer: [8192]u8 = undefined;
    defer std.crypto.secureZero(u8, &buffer);
    while (!frame.complete) {
        try waitReady(io, fd, c.POLL.IN, until);
        const n = c.recv(fd, &buffer, buffer.len, 0);
        if (n < 0) {
            switch (std.posix.errno(n)) {
                .INTR, .AGAIN => continue,
                else => return error.SocketFailed,
            }
        }
        if (n == 0) return error.IncompleteFrame;
        try frame.feed(allocator, buffer[0..@intCast(n)]);
    }
    return frame.bytes.toOwnedSlice(allocator);
}

/// Persistent control clients may send several complete NDJSON requests in
/// one kernel read. Keep only one bounded frame plus a small read-ahead buffer.
pub const ConnectionReader = struct {
    buffer: [8192]u8 = undefined,
    start: usize = 0,
    end: usize = 0,

    const Slice = union(enum) { pending, closed, frame: []u8 };

    pub fn next(self: *ConnectionReader, io: std.Io, allocator: std.mem.Allocator, fd: c.fd_t, until: std.Io.Clock.Timestamp) !?[]u8 {
        return self.nextWithPeer(io, allocator, fd, until, null);
    }

    /// Adapter framing returns bytes only after authenticating every received
    /// segment. Authentication failure discards the entire partial frame.
    pub fn nextWithPeer(self: *ConnectionReader, io: std.Io, allocator: std.mem.Allocator, fd: c.fd_t, until: std.Io.Clock.Timestamp, peer: ?*native_peer.Context) !?[]u8 {
        var bytes: std.ArrayList(u8) = .empty;
        defer {
            std.crypto.secureZero(u8, bytes.items);
            bytes.deinit(allocator);
        }
        return switch (try self.nextSliceWithPeer(io, allocator, fd, &bytes, until, until, peer)) {
            .frame => |frame| frame,
            .closed => null,
            .pending => error.Timeout,
        };
    }

    // A fairness slice may end with a partial frame. Its owner retains both
    // accumulated bytes and read-ahead without extending the request deadline.
    fn nextSlice(self: *ConnectionReader, io: std.Io, allocator: std.mem.Allocator, fd: c.fd_t, bytes: *std.ArrayList(u8), until: std.Io.Clock.Timestamp, slice_until: std.Io.Clock.Timestamp) !Slice {
        return self.nextSliceWithPeer(io, allocator, fd, bytes, until, slice_until, null);
    }

    fn nextSliceWithPeer(self: *ConnectionReader, io: std.Io, allocator: std.mem.Allocator, fd: c.fd_t, bytes: *std.ArrayList(u8), until: std.Io.Clock.Timestamp, slice_until: std.Io.Clock.Timestamp, peer: ?*native_peer.Context) !Slice {
        while (true) {
            try io.checkCancel();
            if (until.durationFromNow(io).raw.toMilliseconds() <= 0) return error.Timeout;
            if (self.start != self.end) {
                const pending = self.buffer[self.start..self.end];
                const newline = std.mem.indexOfScalar(u8, pending, '\n');
                const n = newline orelse pending.len;
                if (bytes.items.len + n > max_frame_bytes) return error.FrameTooLarge;
                try bytes.appendSlice(allocator, pending[0..n]);
                self.start += n;
                if (newline != null) {
                    self.start += 1;
                    if (bytes.items.len == 0) return error.EmptyFrame;
                    return .{ .frame = try bytes.toOwnedSlice(allocator) };
                }
            }
            waitReady(io, fd, c.POLL.IN, slice_until) catch |err| {
                if (err == error.Timeout and until.durationFromNow(io).raw.toMilliseconds() > 0) return .pending;
                return err;
            };
            const n: isize = if (peer) |verified| @intCast(verified.receiveSegment(&self.buffer) catch |err| switch (err) {
                error.WouldBlock, error.Interrupted => continue,
                else => {
                    std.crypto.secureZero(u8, &self.buffer);
                    self.start = 0;
                    self.end = 0;
                    return err;
                },
            }) else c.recv(fd, &self.buffer, self.buffer.len, 0);
            if (n < 0) {
                switch (std.posix.errno(n)) {
                    .INTR, .AGAIN => continue,
                    else => return error.SocketFailed,
                }
            }
            if (n == 0) {
                if (bytes.items.len != 0) return error.IncompleteFrame;
                return .closed;
            }
            self.start = 0;
            self.end = @intCast(n);
        }
    }
};

fn writeBytes(io: std.Io, fd: c.fd_t, bytes: []const u8, until: std.Io.Clock.Timestamp) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        try waitReady(io, fd, c.POLL.OUT, until);
        const n = c.send(fd, bytes[offset..].ptr, bytes.len - offset, if (builtin.os.tag == .linux) c.MSG.NOSIGNAL else 0);
        if (n < 0) {
            switch (std.posix.errno(n)) {
                .INTR, .AGAIN => continue,
                else => return error.SocketFailed,
            }
        }
        if (n == 0) return error.ConnectionClosed;
        offset += @intCast(n);
    }
}

pub fn writeFrame(io: std.Io, fd: c.fd_t, bytes: []const u8, until: std.Io.Clock.Timestamp) !void {
    if (bytes.len > max_frame_bytes or std.mem.indexOfScalar(u8, bytes, '\n') != null) return error.FrameTooLarge;
    try writeBytes(io, fd, bytes, until);
    try writeBytes(io, fd, "\n", until);
}

fn connect(io: std.Io, path: []const u8, until: std.Io.Clock.Timestamp) !c.fd_t {
    if (path.len >= @as(c.sockaddr.un, undefined).path.len) return error.SocketPathTooLong;
    const fd = socket(c.AF.UNIX, c.SOCK.STREAM, 0);
    if (fd < 0) return error.SocketFailed;
    errdefer _ = c.close(fd);
    try nonblocking(fd);
    var addr: c.sockaddr.un = .{ .path = @splat(0) };
    @memcpy(addr.path[0..path.len], path);
    addr.path[path.len] = 0;
    const addr_len: c.socklen_t = @intCast(@offsetOf(c.sockaddr.un, "path") + path.len + 1);
    if (builtin.os.tag == .macos) addr.len = @intCast(addr_len);
    if (c.connect(fd, @ptrCast(&addr), addr_len) != 0) {
        switch (std.posix.errno(-1)) {
            .INPROGRESS, .AGAIN => {},
            .NOENT, .CONNREFUSED => return error.DaemonUnavailable,
            else => return error.SocketFailed,
        }
        try waitReady(io, fd, c.POLL.OUT, until);
        var connect_error: c_int = 0;
        var len: c.socklen_t = @sizeOf(c_int);
        if (c.getsockopt(fd, c.SOL.SOCKET, c.SO.ERROR, &connect_error, &len) != 0 or connect_error != 0) return error.DaemonUnavailable;
    }
    try verifyPeer(fd);
    return fd;
}

pub fn exchange(io: std.Io, allocator: std.mem.Allocator, socket_path: []const u8, payload: []const u8) ![]u8 {
    return exchangeWithTimeout(io, allocator, socket_path, payload, request_timeout_ms);
}

pub fn exchangeWithTimeout(io: std.Io, allocator: std.mem.Allocator, socket_path: []const u8, payload: []const u8, timeout_ms: i64) ![]u8 {
    if (timeout_ms < 1 or timeout_ms > request_timeout_ms) return error.InvalidDeadline;
    return exchangeUntil(io, allocator, socket_path, payload, deadlineAfter(io, timeout_ms));
}

/// Bound every transport phase by the original caller deadline. Preserve the
/// existing per-exchange 15s ceiling even when the caller has more time.
pub fn exchangeUntil(io: std.Io, allocator: std.mem.Allocator, socket_path: []const u8, payload: []const u8, original: std.Io.Clock.Timestamp) ![]u8 {
    const remaining = original.durationFromNow(io).raw.toMilliseconds();
    if (remaining <= 0) return error.Timeout;
    const capped = deadline(io);
    const until = if (original.raw.durationTo(capped.raw).toNanoseconds() > 0) original else capped;
    paths.verifySocketPath(allocator, socket_path) catch |err| switch (err) {
        error.PathOpenFailed => return error.DaemonUnavailable,
        else => return err,
    };
    if (until.durationFromNow(io).raw.toMilliseconds() <= 0) return error.Timeout;
    const fd = try connect(io, socket_path, until);
    defer _ = c.close(fd);
    try writeFrame(io, fd, payload, until);
    return readFrame(io, allocator, fd, until);
}

test "expired original client deadline refuses before socket metadata or IO" {
    const original = std.Io.Clock.Timestamp.fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromMilliseconds(-1) });
    try std.testing.expectError(error.Timeout, exchangeUntil(std.testing.io, std.testing.allocator, "/not-an-authorized-socket", "never-issued", original));
}

const ControlConnection = struct {
    reader: ConnectionReader = .{},
    partial: std.ArrayList(u8) = .empty,
    until: std.Io.Clock.Timestamp,
};
const Job = struct { stream: std.Io.net.Stream, channel: Channel, until: std.Io.Clock.Timestamp, control: ?*ControlConnection = null };
const Pool = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    engine: *Engine,
    queue: std.Io.Queue(Job),
    failures: std.atomic.Value(u64) = .init(0),
    control_connections: std.atomic.Value(usize) = .init(0),
};

fn closeJob(pool: *Pool, job: Job) void {
    job.stream.close(pool.io);
    if (job.control) |connection| {
        std.crypto.secureZero(u8, connection.partial.items);
        connection.partial.deinit(pool.allocator);
        std.crypto.secureZero(u8, &connection.reader.buffer);
        pool.allocator.destroy(connection);
        _ = pool.control_connections.fetchSub(1, .monotonic);
    }
}

/// Only control connections yield. Native/browser workers retain their existing
/// channel budgets and behavior. Every admitted control connection has a queue
/// slot even while active, so yielding cannot discard a request or block.
fn handleControlSlice(pool: *Pool, job: Job) !bool {
    const connection = job.control.?;
    const fd = job.stream.socket.handle;
    try verifyPeer(fd);
    const remaining = connection.until.durationFromNow(pool.io).raw.toMilliseconds();
    if (remaining <= 0) return error.Timeout;
    const slice_until = deadlineAfter(pool.io, @min(remaining, control_slice_ms));
    const payload = switch (try connection.reader.nextSlice(pool.io, pool.allocator, fd, &connection.partial, connection.until, slice_until)) {
        .pending => return true,
        .closed => return false,
        .frame => |bytes| bytes,
    };
    defer {
        std.crypto.secureZero(u8, payload);
        pool.allocator.free(payload);
    }
    var arena: std.heap.ArenaAllocator = .init(pool.allocator);
    defer arena.deinit();
    const reply = try pool.engine.dispatchUntil(arena.allocator(), payload, .control, connection.until);
    defer std.crypto.secureZero(u8, reply);
    try writeFrame(pool.io, fd, reply, connection.until);
    connection.until = channelDeadline(pool.io, .control);
    return true;
}

fn handle(pool: *Pool, job: Job) !void {
    const fd = job.stream.socket.handle;
    defer job.stream.close(pool.io);
    try verifyPeer(fd);
    try nonblocking(fd);
    if (job.channel == .adapter) try native_peer.Context.enable(fd);
    var peer: ?native_peer.Context = if (job.channel == .adapter)
        try native_peer.Context.capture(fd, c.getuid())
    else
        null;
    defer if (peer) |*verified| verified.deinit();
    var reader: ConnectionReader = .{};
    defer std.crypto.secureZero(u8, &reader.buffer);
    var until = job.until;
    while (true) {
        var arena: std.heap.ArenaAllocator = .init(pool.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        const payload = (try reader.nextWithPeer(pool.io, allocator, fd, until, if (peer) |*verified| verified else null)) orelse return;
        defer std.crypto.secureZero(u8, payload);
        const reply = if (peer) |*verified|
            try pool.engine.dispatchUntilWithPeer(allocator, payload, job.channel, until, verified)
        else
            try pool.engine.dispatchUntil(allocator, payload, job.channel, until);
        defer std.crypto.secureZero(u8, reply);
        try writeFrame(pool.io, fd, reply, until);
        until = channelDeadline(pool.io, job.channel);
    }
}

fn handleNonControl(pool: *Pool, job: Job) !bool {
    try handle(pool, job);
    return false;
}

fn worker(pool: *Pool) std.Io.Cancelable!void {
    while (true) {
        const job = pool.queue.getOne(pool.io) catch |err| switch (err) {
            error.Closed => return,
            error.Canceled => return error.Canceled,
        };
        const yielded = if (job.control != null) handleControlSlice(pool, job) else handleNonControl(pool, job);
        const keep = yielded catch |err| {
            if (job.control != null) closeJob(pool, job);
            if (err == error.Canceled) return error.Canceled;
            if (err == error.ConnectionClosed) continue;
            // Connection faults are accounted without recording request bytes.
            _ = pool.failures.fetchAdd(1, .monotonic);
            std.log.warn("local {s} request failed: {s}", .{ @tagName(job.channel), @errorName(err) });
            continue;
        };
        if (job.control == null) continue;
        if (!keep) {
            closeJob(pool, job);
            continue;
        }
        const queued = pool.queue.put(pool.io, &.{job}, 0) catch |err| {
            closeJob(pool, job);
            return switch (err) {
                error.Closed => {},
                error.Canceled => error.Canceled,
            };
        };
        // Admission reserves a slot for this active connection. A full queue
        // here violates that invariant; fail closed without executing it again.
        if (queued == 0) {
            closeJob(pool, job);
            _ = pool.failures.fetchAdd(1, .monotonic);
        }
    }
}

pub fn run(io: std.Io, allocator: std.mem.Allocator, locations: paths.Locations) !void {
    return runConfigured(io, allocator, locations, null);
}

pub fn runWithDeployment(io: std.Io, allocator: std.mem.Allocator, locations: paths.Locations, deployment: Engine.NativeDeploymentSelection) !void {
    return runConfigured(io, allocator, locations, deployment);
}

fn runConfigured(io: std.Io, allocator: std.mem.Allocator, locations: paths.Locations, deployment: ?Engine.NativeDeploymentSelection) !void {
    var custody = try paths.Custody.acquire(allocator, locations);
    defer custody.deinit();
    const engine = if (deployment) |configured|
        try Engine.openForInstanceWithDeployment(io, allocator, locations.state, locations.instance, configured)
    else
        try Engine.openForInstance(io, allocator, locations.state, locations.instance);
    defer engine.deinit();
    try serve(io, allocator, locations, custody, engine);
}

/// Exercise the production socket/worker path with an explicitly synthetic
/// engine. This entry point never acquires a personal vault key.
pub fn serveWithEngineForTest(io: std.Io, allocator: std.mem.Allocator, locations: paths.Locations, engine: *Engine) !void {
    if (!builtin.is_test) return error.TestOnly;
    var custody = try paths.Custody.acquire(allocator, locations);
    defer custody.deinit();
    try serve(io, allocator, locations, custody, engine);
}

pub fn stopForTest() !void {
    if (!builtin.is_test) return error.TestOnly;
    stopping.store(true, .release);
}

fn serve(io: std.Io, allocator: std.mem.Allocator, locations: paths.Locations, custody: paths.Custody, engine: *Engine) !void {
    const socket_names = [_][:0]const u8{ "control.sock", "browser.sock", "adapter.sock" };
    const socket_paths = [_][]const u8{ locations.control, locations.browser, locations.adapter };
    const channels = [_]Channel{ .control, .browser, .adapter };
    var servers: [3]std.Io.net.Server = undefined;
    var initialized: usize = 0;
    defer for (0..initialized) |i| {
        servers[i].deinit(io);
        custody.removeSocket(socket_names[i]) catch |err| {
            std.log.err("private socket cleanup failed: {s}", .{@errorName(err)});
        };
    };
    for (socket_paths, 0..) |path, i| {
        try custody.removeSocket(socket_names[i]);
        const address = try std.Io.net.UnixAddress.init(path);
        servers[i] = if (channels[i] == .adapter)
            try listenAdapter(io, path, custody)
        else
            try address.listen(io, .{ .kernel_backlog = queue_capacity });
        initialized += 1;
        if (c.fchmodat(custody.run_fd, socket_names[i].ptr, 0o600, 0) != 0) return error.SocketPermissionFailed;
        try nonblocking(servers[i].socket.handle);
    }
    var jobs: [3][control_connection_capacity]Job = undefined;
    var pools: [3]Pool = undefined;
    for (&pools, 0..) |*pool, i| pool.* = .{ .io = io, .allocator = allocator, .engine = engine, .queue = .init(jobs[i][0..if (i == 0) control_connection_capacity else queue_capacity]) };
    var workers: std.Io.Group = .init;
    defer {
        for (&pools) |*pool| pool.queue.close(io);
        workers.cancel(io);
        for (&pools) |*pool| {
            var leftovers: [1]Job = undefined;
            while (true) {
                const n = pool.queue.getUncancelable(io, &leftovers, 0) catch break;
                if (n == 0) break;
                closeJob(pool, leftovers[0]);
            }
        }
    }
    for (&pools, 0..) |*pool, i| for (0..channel_workers[i]) |_| try workers.concurrent(io, worker, .{pool});
    stopping.store(false, .release);
    const old_term = signal(@backingInt(c.SIG.TERM), stopSignal);
    const old_int = signal(@backingInt(c.SIG.INT), stopSignal);
    defer {
        _ = signal(@backingInt(c.SIG.TERM), old_term);
        _ = signal(@backingInt(c.SIG.INT), old_int);
    }
    var pollfds: [3]c.pollfd = undefined;
    while (!stopping.load(.acquire)) {
        try io.checkCancel();
        for (&pollfds, 0..) |*entry, i| entry.* = .{ .fd = servers[i].socket.handle, .events = c.POLL.IN, .revents = 0 };
        const rc = c.poll(&pollfds, pollfds.len, 200);
        if (rc < 0) {
            if (std.posix.errno(rc) == .INTR) continue;
            return error.SocketFailed;
        }
        for (pollfds, 0..) |entry, i| {
            if (entry.revents & c.POLL.IN == 0) continue;
            const stream = (try acceptReady(io, servers[i].socket.handle)) orelse continue;
            var job: Job = .{ .stream = stream, .channel = channels[i], .until = channelDeadline(io, channels[i]) };
            if (channels[i] == .control) {
                if (pools[i].control_connections.fetchAdd(1, .monotonic) >= control_connection_capacity) {
                    _ = pools[i].control_connections.fetchSub(1, .monotonic);
                    stream.close(io);
                    continue;
                }
                const connection = allocator.create(ControlConnection) catch |err| {
                    _ = pools[i].control_connections.fetchSub(1, .monotonic);
                    stream.close(io);
                    return err;
                };
                connection.* = .{ .until = job.until };
                job.control = connection;
            }
            const queued = pools[i].queue.put(io, &.{job}, 0) catch |err| {
                closeJob(&pools[i], job);
                return err;
            };
            if (queued == 0) closeJob(&pools[i], job);
        }
    }
}

test "NDJSON framing rejects oversized and pipelined input" {
    const allocator = std.testing.allocator;
    var frame: Frame = .{};
    defer frame.deinit(allocator);
    try frame.feed(allocator, "{\"jsonrpc\":");
    try frame.feed(allocator, "\"2.0\"}\n");
    try std.testing.expect(frame.complete);
    try std.testing.expectEqualStrings("{\"jsonrpc\":\"2.0\"}", frame.bytes.items);
    try std.testing.expectError(error.TrailingFrame, frame.feed(allocator, "{}\n"));
    var pipelined: Frame = .{};
    defer pipelined.deinit(allocator);
    try std.testing.expectError(error.TrailingFrame, pipelined.feed(allocator, "{}\n{}\n"));
    var oversized: Frame = .{};
    defer oversized.deinit(allocator);
    const huge = try allocator.alloc(u8, max_frame_bytes + 1);
    defer allocator.free(huge);
    @memset(huge, 'x');
    try std.testing.expectError(error.FrameTooLarge, oversized.feed(allocator, huge));
}

test "local socket framing verifies peer and bounds incomplete reads" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    var pair: [2]c.fd_t = undefined;
    if (socketpair(c.AF.UNIX, c.SOCK.STREAM, 0, &pair) != 0) return error.SocketFailed;
    defer _ = c.close(pair[0]);
    defer _ = c.close(pair[1]);
    try nonblocking(pair[0]);
    try nonblocking(pair[1]);
    try verifyPeer(pair[0]);
    try verifyPeer(pair[1]);
    const io = std.testing.io;
    try writeFrame(io, pair[0], "{\"jsonrpc\":\"2.0\"}", deadline(io));
    const payload = try readFrame(io, std.testing.allocator, pair[1], deadline(io));
    defer std.testing.allocator.free(payload);
    try std.testing.expectEqualStrings("{\"jsonrpc\":\"2.0\"}", payload);
    const expired = std.Io.Clock.Timestamp.now(io, .awake);
    try std.testing.expectError(error.Timeout, readFrame(io, std.testing.allocator, pair[1], expired));
    const partial_until = std.Io.Clock.Timestamp.fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(5) });
    try writeBytes(io, pair[0], "{", deadline(io));
    try std.testing.expectError(error.Timeout, readFrame(io, std.testing.allocator, pair[1], partial_until));
}

test "persistent connection reader preserves coalesced requests" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    var pair: [2]c.fd_t = undefined;
    if (socketpair(c.AF.UNIX, c.SOCK.STREAM, 0, &pair) != 0) return error.SocketFailed;
    defer _ = c.close(pair[0]);
    defer _ = c.close(pair[1]);
    try nonblocking(pair[0]);
    try nonblocking(pair[1]);
    const io = std.testing.io;
    try writeBytes(io, pair[0], "{\"id\":1}\n{\"id\":2}\n", deadline(io));
    var reader: ConnectionReader = .{};
    const first = (try reader.next(io, std.testing.allocator, pair[1], deadline(io))).?;
    defer std.testing.allocator.free(first);
    const second = (try reader.next(io, std.testing.allocator, pair[1], deadline(io))).?;
    defer std.testing.allocator.free(second);
    try std.testing.expectEqualStrings("{\"id\":1}", first);
    try std.testing.expectEqualStrings("{\"id\":2}", second);
}

test "control reader yields partial frames without renewing their absolute deadline" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    var pair: [2]c.fd_t = undefined;
    if (socketpair(c.AF.UNIX, c.SOCK.STREAM, 0, &pair) != 0) return error.SocketFailed;
    defer _ = c.close(pair[0]);
    defer _ = c.close(pair[1]);
    try nonblocking(pair[0]);
    try nonblocking(pair[1]);
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var reader: ConnectionReader = .{};
    var partial: std.ArrayList(u8) = .empty;
    defer partial.deinit(allocator);
    const until = deadline(io);
    try writeBytes(io, pair[0], "{\"id\":", until);
    const yielded = try reader.nextSlice(io, allocator, pair[1], &partial, until, deadlineAfter(io, 5));
    try std.testing.expect(yielded == .pending);
    try std.testing.expectEqualStrings("{\"id\":", partial.items);
    // Expiry also applies to bytes already buffered at an earlier slice.
    try std.testing.expectError(error.Timeout, reader.nextSlice(io, allocator, pair[1], &partial, .now(io, .awake), until));
    try writeBytes(io, pair[0], "1}\n{\"id\":2}\n", until);
    const first = (try reader.nextSlice(io, allocator, pair[1], &partial, until, until)).frame;
    defer allocator.free(first);
    const second = (try reader.nextSlice(io, allocator, pair[1], &partial, until, until)).frame;
    defer allocator.free(second);
    try std.testing.expectEqualStrings("{\"id\":1}", first);
    try std.testing.expectEqualStrings("{\"id\":2}", second);
}

test "fifth control client progresses while four persistent clients remain connected" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    const io = std.testing.io;
    const allocator = std.heap.page_allocator;
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var nonce: [8]u8 = undefined;
    try io.randomSecure(&nonce);
    const root = try std.fmt.allocPrint(a, "{s}/omux-fair-{s}", .{ if (builtin.os.tag == .macos) "/private/tmp" else "/tmp", std.fmt.bytesToHex(nonce, .lower) });
    const root_fd = try paths.openPrivateRoot(a, root, true);
    _ = c.close(root_fd);
    defer std.Io.Dir.cwd().deleteTree(io, root) catch |err| std.log.err("fixture cleanup failed: {s}", .{@errorName(err)});
    const locations = try paths.Locations.init(a, root);
    const engine = try Engine.openWithKey(io, allocator, root, @splat(47));
    defer engine.deinit();
    const Server = struct {
        locations: paths.Locations,
        engine: *Engine,
        failure: ?anyerror = null,
        fn run(self: *@This()) void {
            serveWithEngineForTest(std.testing.io, std.heap.page_allocator, self.locations, self.engine) catch |err| {
                self.failure = err;
            };
        }
    };
    var server: Server = .{ .locations = locations, .engine = engine };
    const thread = try std.Thread.spawn(.{}, Server.run, .{&server});
    defer {
        stopForTest() catch unreachable;
        thread.join();
        std.testing.expect(server.failure == null) catch @panic("fairness fixture daemon failed");
    }
    const health = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system.health\"}";
    var ready = false;
    for (0..100) |_| {
        const response = exchangeWithTimeout(io, a, locations.control, health, 100) catch {
            try io.sleep(.fromMilliseconds(10), .awake);
            continue;
        };
        const parsed = try std.json.parseFromSlice(std.json.Value, a, response, .{});
        defer parsed.deinit();
        try std.testing.expect(parsed.value.object.contains("result"));
        ready = true;
        break;
    }
    try std.testing.expect(ready);
    var clients: [4]c.fd_t = undefined;
    var connected: usize = 0;
    defer for (clients[0..connected]) |fd| {
        _ = c.close(fd);
    };
    for (&clients) |*fd| {
        fd.* = try connect(io, locations.control, deadline(io));
        connected += 1;
        try writeFrame(io, fd.*, health, deadline(io));
        const reply = try readFrame(io, a, fd.*, deadlineAfter(io, 2_000));
        const parsed = try std.json.parseFromSlice(std.json.Value, a, reply, .{});
        defer parsed.deinit();
        try std.testing.expect(parsed.value.object.contains("result"));
    }
    const fifth = try exchangeWithTimeout(io, a, locations.control, "{\"jsonrpc\":\"2.0\",\"id\":5,\"method\":\"state.snapshot\"}", 2_000);
    const parsed_fifth = try std.json.parseFromSlice(std.json.Value, a, fifth, .{});
    defer parsed_fifth.deinit();
    try std.testing.expectEqual(@as(i64, 5), parsed_fifth.value.object.get("id").?.integer);
    try std.testing.expect(parsed_fifth.value.object.contains("result"));
    // Existing controls retain their streams and partial/coalesced requests
    // across yields; no reconnect or replay is required to complete them.
    try writeBytes(io, clients[0], "{\"jsonrpc\":\"2.0\",\"id\":6,", deadline(io));
    try io.sleep(.fromMilliseconds(250), .awake);
    try writeBytes(io, clients[0], "\"method\":\"state.snapshot\"}\n{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"system.health\"}\n", deadline(io));
    var reader: ConnectionReader = .{};
    for ([_]i64{ 6, 7 }) |expected| {
        const reply = (try reader.next(io, a, clients[0], deadlineAfter(io, 2_000))).?;
        const parsed = try std.json.parseFromSlice(std.json.Value, a, reply, .{});
        defer parsed.deinit();
        try std.testing.expectEqual(expected, parsed.value.object.get("id").?.integer);
        try std.testing.expect(parsed.value.object.contains("result"));
    }
    for (clients[1..]) |fd| {
        try writeFrame(io, fd, health, deadline(io));
        const reply = try readFrame(io, a, fd, deadlineAfter(io, 2_000));
        const parsed = try std.json.parseFromSlice(std.json.Value, a, reply, .{});
        defer parsed.deinit();
        try std.testing.expect(parsed.value.object.contains("result"));
    }
}

test "private Unix endpoint roundtrip rejects symlink socket aliases" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var nonce: [8]u8 = undefined;
    io.random(&nonce);
    const root = try std.fmt.allocPrint(a, "{s}/omux-ipc-{s}", .{ if (builtin.os.tag == .macos) "/private/tmp" else "/tmp", std.fmt.bytesToHex(nonce, .lower) });
    defer std.Io.Dir.cwd().deleteTree(io, root) catch |err| std.log.err("test directory cleanup failed: {s}", .{@errorName(err)});
    const locations = try paths.Locations.init(a, root);
    var custody = try paths.Custody.acquire(a, locations);
    defer custody.deinit();
    const address = try std.Io.net.UnixAddress.init(locations.control);
    var server = try address.listen(io, .{});
    defer server.deinit(io);
    try nonblocking(server.socket.handle);
    if (c.fchmodat(custody.run_fd, "control.sock", 0o600, 0) != 0) return error.SocketPermissionFailed;
    try std.testing.expect((try acceptReady(io, server.socket.handle)) == null);
    const client = try connect(io, locations.control, deadline(io));
    defer _ = c.close(client);
    const accepted = (try acceptReady(io, server.socket.handle)) orelse return error.NoQueuedConnection;
    defer accepted.close(io);
    try nonblocking(accepted.socket.handle);
    try verifyPeer(accepted.socket.handle);
    try paths.verifySocketPath(a, locations.control);
    try writeFrame(io, client, "{\"id\":1}", deadline(io));
    const payload = try readFrame(io, a, accepted.socket.handle, deadline(io));
    try std.testing.expectEqualStrings("{\"id\":1}", payload);
    try writeFrame(io, accepted.socket.handle, "{\"id\":1,\"result\":{}}", deadline(io));
    const reply = try readFrame(io, a, client, deadline(io));
    try std.testing.expectEqualStrings("{\"id\":1,\"result\":{}}", reply);
    if (c.symlinkat("control.sock", custody.run_fd, "alias.sock") != 0) return error.SymlinkFailed;
    const alias = try std.fmt.allocPrint(a, "{s}/alias.sock", .{locations.run});
    try std.testing.expectError(error.UnsafeSocketPath, paths.verifySocketPath(a, alias));
}
