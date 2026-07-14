const std = @import("std");

const max_request_head_bytes = 64 * 1024;
const max_response_headers = 25;
const script_exhausted_body = "fake upstream response script exhausted";

pub const Header = std.http.Header;

pub const ScriptedResponse = struct {
    status: std.http.Status,
    body: []const u8 = "",
    headers: []const Header = &.{},
};

/// A coherent counter pair. Attempts count accepted non-shutdown TCP
/// connections; calls count requests dispatched to a script index, including
/// indexes beyond the configured script that receive the synthetic 500.
pub const Snapshot = struct {
    attempt_count: usize = 0,
    call_count: usize = 0,

    pub const zero: Snapshot = .{};

    pub fn isZero(self: Snapshot) bool {
        return self.attempt_count == 0 and self.call_count == 0;
    }
};

/// Test-only deterministic HTTP upstream. It has no environment lookup or
/// production registration path: callers must construct it explicitly and use
/// the returned loopback URL in their test seam.
pub const FakeUpstream = struct {
    allocator: std.mem.Allocator,
    shared: ?*Shared,
    thread: ?std.Thread,
    base_url: ?[]u8,

    pub fn start(
        allocator: std.mem.Allocator,
        script: []const ScriptedResponse,
    ) !FakeUpstream {
        const responses = try cloneScript(allocator, script);
        errdefer deinitScript(allocator, responses);

        const loopback = try std.net.Address.parseIp("127.0.0.1", 0);
        var server = try loopback.listen(.{ .reuse_address = true });
        errdefer server.deinit();

        const shared = try allocator.create(Shared);
        errdefer allocator.destroy(shared);
        shared.* = .{
            .server = server,
            .responses = responses,
            .stopping = std.atomic.Value(bool).init(false),
            .stopped = std.atomic.Value(bool).init(false),
            .response_write_in_progress = std.atomic.Value(bool).init(false),
        };

        const base_url = try std.fmt.allocPrint(
            allocator,
            "http://127.0.0.1:{d}",
            .{server.listen_address.getPort()},
        );
        errdefer allocator.free(base_url);

        const thread = try std.Thread.spawn(.{}, run, .{shared});
        return .{
            .allocator = allocator,
            .shared = shared,
            .thread = thread,
            .base_url = base_url,
        };
    }

    pub fn baseUrl(self: *const FakeUpstream) []const u8 {
        return self.base_url.?;
    }

    pub fn address(self: *const FakeUpstream) std.net.Address {
        return self.shared.?.server.listen_address;
    }

    pub fn snapshot(self: *FakeUpstream) Snapshot {
        return self.shared.?.counters.snapshot();
    }

    pub fn deinit(self: *FakeUpstream) void {
        const shared = self.shared orelse return;
        self.requestStop();

        if (self.thread) |thread| thread.join();
        shared.server.deinit();
        deinitScript(self.allocator, shared.responses);
        self.allocator.destroy(shared);
        self.allocator.free(self.base_url.?);

        self.shared = null;
        self.thread = null;
        self.base_url = null;
    }

    fn requestStop(self: *FakeUpstream) void {
        const shared = self.shared orelse return;
        shared.stopping.store(true, .release);
        shared.active.interrupt();
    }

    fn isStopped(self: *FakeUpstream) bool {
        const shared = self.shared orelse return true;
        return shared.stopped.load(.acquire);
    }

    fn responseWriteInProgress(self: *FakeUpstream) bool {
        const shared = self.shared orelse return false;
        return shared.response_write_in_progress.load(.acquire);
    }
};

const Counters = struct {
    mutex: std.Thread.Mutex = .{},
    attempt_count: usize = 0,
    call_count: usize = 0,

    fn recordAttempt(self: *Counters) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.attempt_count +|= 1;
    }

    fn recordCall(self: *Counters) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        const script_index = self.call_count;
        self.call_count +|= 1;
        return script_index;
    }

    fn snapshot(self: *Counters) Snapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        return .{
            .attempt_count = self.attempt_count,
            .call_count = self.call_count,
        };
    }
};

const Shared = struct {
    server: std.net.Server,
    responses: []OwnedResponse,
    stopping: std.atomic.Value(bool),
    stopped: std.atomic.Value(bool),
    response_write_in_progress: std.atomic.Value(bool),
    counters: Counters = .{},
    active: ActiveConnection = .{},
};

const ActiveConnection = struct {
    mutex: std.Thread.Mutex = .{},
    handle: ?std.posix.socket_t = null,

    fn begin(
        self: *ActiveConnection,
        handle: std.posix.socket_t,
        stopping: *std.atomic.Value(bool),
    ) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (stopping.load(.acquire)) return false;
        std.debug.assert(self.handle == null);
        self.handle = handle;
        return true;
    }

    fn end(self: *ActiveConnection, handle: std.posix.socket_t) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.handle == handle) self.handle = null;
    }

    fn interrupt(self: *ActiveConnection) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.handle) |handle| {
            std.posix.shutdown(handle, .both) catch {};
        }
    }
};

const OwnedResponse = struct {
    status: std.http.Status,
    body: []u8,
    headers: []Header,

    fn clone(allocator: std.mem.Allocator, response: ScriptedResponse) !OwnedResponse {
        const status_code = @intFromEnum(response.status);
        if (status_code < 200 or status_code > 599) return error.InvalidStatus;
        if (responseHasNoBody(response.status) and response.body.len != 0) {
            return error.ResponseBodyNotAllowed;
        }
        if (response.headers.len > max_response_headers) return error.TooManyHeaders;

        const body = try allocator.dupe(u8, response.body);
        errdefer allocator.free(body);
        const headers = try allocator.alloc(Header, response.headers.len);
        errdefer allocator.free(headers);

        var initialized: usize = 0;
        errdefer {
            for (headers[0..initialized]) |header| {
                allocator.free(header.name);
                allocator.free(header.value);
            }
        }
        for (response.headers, 0..) |header, index| {
            headers[index] = try cloneHeader(allocator, header);
            initialized += 1;
        }
        return .{
            .status = response.status,
            .body = body,
            .headers = headers,
        };
    }

    fn deinit(self: *OwnedResponse, allocator: std.mem.Allocator) void {
        for (self.headers) |header| {
            allocator.free(header.name);
            allocator.free(header.value);
        }
        allocator.free(self.headers);
        allocator.free(self.body);
    }
};

fn cloneHeader(allocator: std.mem.Allocator, header: Header) !Header {
    try validateHeader(header);
    const name = try allocator.dupe(u8, header.name);
    errdefer allocator.free(name);
    const value = try allocator.dupe(u8, header.value);
    return .{ .name = name, .value = value };
}

fn validateHeader(header: Header) !void {
    if (header.name.len == 0) return error.InvalidHeader;
    for (header.name) |byte| {
        const valid = std.ascii.isAlphanumeric(byte) or switch (byte) {
            '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', 0x60, '|', '~' => true,
            else => false,
        };
        if (!valid) return error.InvalidHeader;
    }
    for (header.value) |byte| {
        if (byte == '\r' or byte == '\n' or byte == 0 or byte == 0x7f) {
            return error.InvalidHeader;
        }
        if (byte < 0x20 and byte != '\t') return error.InvalidHeader;
    }
    if (std.ascii.eqlIgnoreCase(header.name, "content-length") or
        std.ascii.eqlIgnoreCase(header.name, "transfer-encoding") or
        std.ascii.eqlIgnoreCase(header.name, "connection"))
    {
        return error.ReservedHeader;
    }
}

fn cloneScript(
    allocator: std.mem.Allocator,
    script: []const ScriptedResponse,
) ![]OwnedResponse {
    const responses = try allocator.alloc(OwnedResponse, script.len);
    errdefer allocator.free(responses);
    var initialized: usize = 0;
    errdefer {
        for (responses[0..initialized]) |*response| response.deinit(allocator);
    }
    for (script, 0..) |response, index| {
        responses[index] = try OwnedResponse.clone(allocator, response);
        initialized += 1;
    }
    return responses;
}

fn deinitScript(allocator: std.mem.Allocator, script: []OwnedResponse) void {
    for (script) |*response| response.deinit(allocator);
    allocator.free(script);
}

fn responseHasNoBody(status: std.http.Status) bool {
    return switch (@intFromEnum(status)) {
        204, 205, 304 => true,
        else => false,
    };
}

fn run(shared: *Shared) void {
    defer shared.stopped.store(true, .release);
    while (!shared.stopping.load(.acquire)) {
        var fds = [_]std.posix.pollfd{.{
            .fd = shared.server.stream.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = std.posix.poll(&fds, 50) catch return;
        if (ready == 0) continue;
        if (fds[0].revents & std.posix.POLL.IN == 0) {
            if (shared.stopping.load(.acquire)) return;
            continue;
        }
        const connection = shared.server.accept() catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return,
        };
        if (!shared.active.begin(connection.stream.handle, &shared.stopping)) {
            connection.stream.close();
            return;
        }
        shared.counters.recordAttempt();
        serveOne(shared, connection);
        shared.active.end(connection.stream.handle);
        connection.stream.close();
    }
}

fn serveOne(shared: *Shared, connection: std.net.Server.Connection) void {
    var read_buffer: [max_request_head_bytes]u8 = undefined;
    var server = std.http.Server.init(connection, &read_buffer);
    var request = server.receiveHead() catch return;
    if (request.head.expect != null) {
        request.respond("", .{
            .status = .expectation_failed,
            .keep_alive = false,
        }) catch {};
        return;
    }
    const script_index = shared.counters.recordCall();

    if (script_index < shared.responses.len) {
        const response = &shared.responses[script_index];
        shared.response_write_in_progress.store(true, .release);
        defer shared.response_write_in_progress.store(false, .release);
        if (responseHasNoBody(response.status)) {
            request.respond("", .{
                .status = response.status,
                .keep_alive = false,
                .extra_headers = response.headers,
                .transfer_encoding = .none,
            }) catch {};
        } else {
            request.respond(response.body, .{
                .status = response.status,
                .keep_alive = false,
                .extra_headers = response.headers,
            }) catch {};
        }
        return;
    }

    request.respond(script_exhausted_body, .{
        .status = .internal_server_error,
        .keep_alive = false,
    }) catch {};
}

fn requestAlloc(
    allocator: std.mem.Allocator,
    address: std.net.Address,
) ![]u8 {
    return requestRawAlloc(
        allocator,
        address,
        "GET /v1/messages HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Connection: close\r\n\r\n",
    );
}

fn requestRawAlloc(
    allocator: std.mem.Allocator,
    address: std.net.Address,
    bytes: []const u8,
) ![]u8 {
    var stream = try std.net.tcpConnectToAddress(address);
    defer stream.close();
    try stream.writeAll(bytes);

    var response = std.ArrayList(u8).init(allocator);
    errdefer response.deinit();
    var buffer: [1024]u8 = undefined;
    while (true) {
        const count = try stream.read(&buffer);
        if (count == 0) break;
        try response.appendSlice(buffer[0..count]);
    }
    return response.toOwnedSlice();
}

fn waitForSnapshot(
    upstream: *FakeUpstream,
    attempt_count: usize,
    call_count: usize,
) !void {
    var timer = try std.time.Timer.start();
    while (true) {
        const current = upstream.snapshot();
        if (current.attempt_count >= attempt_count and current.call_count >= call_count) return;
        if (timer.read() > std.time.ns_per_s) return error.TestTimeout;
        std.Thread.yield() catch {};
    }
}

fn waitForResponseWrite(upstream: *FakeUpstream) void {
    var timer = std.time.Timer.start() catch @panic("test timer unavailable");
    while (!upstream.responseWriteInProgress()) {
        if (timer.read() > 2 * std.time.ns_per_s) {
            @panic("fake upstream never entered response write");
        }
        std.Thread.yield() catch {};
    }
}

fn waitForStopped(upstream: *FakeUpstream) void {
    var timer = std.time.Timer.start() catch @panic("test timer unavailable");
    while (!upstream.isStopped()) {
        if (timer.read() > 2 * std.time.ns_per_s) {
            @panic("fake upstream did not stop within deadline");
        }
        std.Thread.yield() catch {};
    }
}

fn requestNoAlloc(address: std.net.Address) !void {
    var stream = try std.net.tcpConnectToAddress(address);
    defer stream.close();
    try stream.writeAll(
        "GET /v1/messages HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Connection: close\r\n\r\n",
    );
    var buffer: [1024]u8 = undefined;
    while (try stream.read(&buffer) != 0) {}
}

test "fake upstream starts with a concrete zero-call snapshot" {
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{});
    defer upstream.deinit();

    try std.testing.expect(std.mem.startsWith(u8, upstream.baseUrl(), "http://127.0.0.1:"));
    try std.testing.expect(upstream.snapshot().isZero());
    try std.testing.expectEqualDeep(Snapshot.zero, upstream.snapshot());
}

test "fake upstream owns and serves scripted status body and headers in order" {
    var first_body = [_]u8{ 'l', 'i', 'm', 'i', 't' };
    var first_header_name = [_]u8{ 'R', 'e', 't', 'r', 'y', '-', 'A', 'f', 't', 'e', 'r' };
    var first_header_value = [_]u8{'7'};
    const first_headers = [_]Header{.{
        .name = &first_header_name,
        .value = &first_header_value,
    }};
    const script = [_]ScriptedResponse{
        .{
            .status = .too_many_requests,
            .body = &first_body,
            .headers = &first_headers,
        },
        .{
            .status = .ok,
            .body = "accepted",
            .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
        },
    };
    var upstream = try FakeUpstream.start(std.testing.allocator, &script);
    defer upstream.deinit();

    first_body[0] = 'X';
    first_header_name[0] = 'X';
    first_header_value[0] = '9';

    const first = try requestAlloc(std.testing.allocator, upstream.address());
    defer std.testing.allocator.free(first);
    try std.testing.expect(std.mem.startsWith(u8, first, "HTTP/1.1 429 Too Many Requests\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, first, "Retry-After: 7\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, first, "\r\n\r\nlimit"));

    const second = try requestAlloc(std.testing.allocator, upstream.address());
    defer std.testing.allocator.free(second);
    try std.testing.expect(std.mem.startsWith(u8, second, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, second, "Content-Type: application/json\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, second, "\r\n\r\naccepted"));

    try std.testing.expectEqualDeep(
        Snapshot{ .attempt_count = 2, .call_count = 2 },
        upstream.snapshot(),
    );
}

test "fake upstream counters remain coherent under concurrent calls" {
    const call_count = 8;
    const script = [_]ScriptedResponse{.{ .status = .ok }} ** call_count;
    var upstream = try FakeUpstream.start(std.testing.allocator, &script);
    defer upstream.deinit();

    const Call = struct {
        address: std.net.Address,
        failure: ?anyerror = null,

        fn run(self: *@This()) void {
            requestNoAlloc(self.address) catch |err| {
                self.failure = err;
            };
        }
    };
    var calls: [call_count]Call = undefined;
    var threads: [call_count]std.Thread = undefined;
    var started: usize = 0;
    errdefer for (threads[0..started]) |thread| thread.join();
    for (&calls, 0..) |*call, index| {
        call.* = .{ .address = upstream.address() };
        threads[index] = try std.Thread.spawn(.{}, Call.run, .{call});
        started += 1;
    }
    for (threads) |thread| thread.join();

    for (calls) |call| try std.testing.expectEqual(@as(?anyerror, null), call.failure);
    try std.testing.expectEqualDeep(
        Snapshot{ .attempt_count = call_count, .call_count = call_count },
        upstream.snapshot(),
    );
}

test "expect continue is rejected without consuming the response script" {
    const script = [_]ScriptedResponse{.{ .status = .ok, .body = "first" }};
    var upstream = try FakeUpstream.start(std.testing.allocator, &script);
    defer upstream.deinit();

    const rejected = try requestRawAlloc(
        std.testing.allocator,
        upstream.address(),
        "POST /v1/messages HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Content-Length: 1\r\n" ++
            "Expect: 100-continue\r\n" ++
            "Connection: close\r\n\r\n",
    );
    defer std.testing.allocator.free(rejected);
    try std.testing.expect(std.mem.startsWith(
        u8,
        rejected,
        "HTTP/1.1 417 Expectation Failed\r\n",
    ));

    const first = try requestAlloc(std.testing.allocator, upstream.address());
    defer std.testing.allocator.free(first);
    try std.testing.expect(std.mem.startsWith(u8, first, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.endsWith(u8, first, "\r\n\r\nfirst"));
    try std.testing.expectEqualDeep(
        Snapshot{ .attempt_count = 2, .call_count = 1 },
        upstream.snapshot(),
    );
}

test "bodyless response uses bodyless framing" {
    const script = [_]ScriptedResponse{.{ .status = .no_content }};
    var upstream = try FakeUpstream.start(std.testing.allocator, &script);
    defer upstream.deinit();

    const response = try requestAlloc(std.testing.allocator, upstream.address());
    defer std.testing.allocator.free(response);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 204 No Content\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, response, "content-length:") == null);
    try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\n"));
}

test "deinit interrupts an accepted partial request" {
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{});
    defer upstream.deinit();

    var stream = try std.net.tcpConnectToAddress(upstream.address());
    defer stream.close();
    try stream.writeAll(
        "GET /v1/messages HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n",
    );
    try waitForSnapshot(&upstream, 1, 0);

    upstream.requestStop();
    waitForStopped(&upstream);
    upstream.deinit();
}

test "deinit interrupts a blocked response writer" {
    const body = try std.testing.allocator.alloc(u8, 4 * 1024 * 1024);
    defer std.testing.allocator.free(body);
    @memset(body, 'x');
    var upstream = try FakeUpstream.start(
        std.testing.allocator,
        &.{.{ .status = .ok, .body = body }},
    );
    defer upstream.deinit();

    var stream = try std.net.tcpConnectToAddress(upstream.address());
    defer stream.close();
    try stream.writeAll(
        "GET /v1/messages HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Connection: close\r\n\r\n",
    );
    try waitForSnapshot(&upstream, 1, 1);
    waitForResponseWrite(&upstream);

    upstream.requestStop();
    waitForStopped(&upstream);
    upstream.deinit();
}

test "fake upstream rejects unsafe scripted response framing" {
    try std.testing.expectError(
        error.InvalidStatus,
        FakeUpstream.start(std.testing.allocator, &.{.{
            .status = .@"continue",
        }}),
    );
    try std.testing.expectError(
        error.ReservedHeader,
        FakeUpstream.start(std.testing.allocator, &.{.{
            .status = .ok,
            .headers = &.{.{ .name = "Content-Length", .value = "99" }},
        }}),
    );
    try std.testing.expectError(
        error.InvalidHeader,
        FakeUpstream.start(std.testing.allocator, &.{.{
            .status = .ok,
            .headers = &.{.{ .name = "X-Test", .value = "bad\r\nInjected: true" }},
        }}),
    );
    try std.testing.expectError(
        error.ResponseBodyNotAllowed,
        FakeUpstream.start(std.testing.allocator, &.{.{
            .status = .no_content,
            .body = "not allowed",
        }}),
    );
    try std.testing.expectError(
        error.ResponseBodyNotAllowed,
        FakeUpstream.start(std.testing.allocator, &.{.{
            .status = .not_modified,
            .body = "not allowed",
        }}),
    );
}
