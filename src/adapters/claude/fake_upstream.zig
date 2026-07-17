const std = @import("std");

const max_request_head_bytes = 64 * 1024;
const max_response_headers = 25;
const max_captured_request_bytes = 64 * 1024;
const max_captured_auth_bytes = 512;
const script_exhausted_body = "fake upstream response script exhausted";

pub const Header = std.http.Header;

pub const ScriptedResponse = struct {
    status: std.http.Status,
    body: []const u8 = "",
    headers: []const Header = &.{},
    /// Frame the body with chunked transfer-encoding instead of a fixed
    /// content-length. Used to script SSE-shaped streaming responses; the
    /// client decodes the framing, so the proxy still observes byte-identical
    /// body bytes. Ignored for bodyless statuses.
    chunked: bool = false,
    /// Test-only deterministic streaming gate. When set, the fake flushes this
    /// many body bytes, records that the prefix is visible, and waits for
    /// `releasePausedResponse` before writing the remainder.
    pause_after_bytes: ?usize = null,
    /// Test-only malformed-response seam. Flush this many body bytes, then
    /// close without completing the declared content length or chunk stream.
    truncate_after_bytes: ?usize = null,
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

pub const connection_nominated_canary = "x-private-hop";

/// Fixed-name, value-free request-header observations. Flags are sticky for
/// the fake's lifetime so a later clean request cannot erase an earlier leak.
/// The fake never retains a credential, arbitrary header name, or value.
pub const RequestHeaderPresence = struct {
    authorization: bool = false,
    x_api_key: bool = false,
    cookie: bool = false,
    forwarded: bool = false,
    x_forwarded_for: bool = false,
    x_forwarded_host: bool = false,
    x_forwarded_port: bool = false,
    x_forwarded_proto: bool = false,
    x_real_ip: bool = false,
    keep_alive: bool = false,
    proxy_authenticate: bool = false,
    proxy_authorization: bool = false,
    proxy_connection: bool = false,
    x_private_hop_canary: bool = false,
    te: bool = false,
    trailer: bool = false,
    trailers: bool = false,
    upgrade: bool = false,
    expect: bool = false,
    accept_encoding: bool = false,
    anthropic_version: bool = false,
};

pub const RequestCaptureSnapshot = struct {
    captured_len: usize = 0,
    total_len: usize = 0,
    truncated: bool = false,
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

    /// Copies the most recent received request body into `out`, returning the
    /// number of bytes copied. Lets a test assert byte-for-byte request-body
    /// pass-through.
    pub fn capturedRequestBody(self: *FakeUpstream, out: []u8) usize {
        const shared = self.shared orelse return 0;
        shared.request_capture.mutex.lock();
        defer shared.request_capture.mutex.unlock();
        const n = @min(out.len, shared.request_capture.len);
        @memcpy(out[0..n], shared.request_capture.buf[0..n]);
        return n;
    }

    /// Copies the most recent received `Authorization` header value into `out`,
    /// returning the number of bytes copied. Lets a test prove which synthetic
    /// route credential the proxy injected on the attempt this upstream served.
    /// The value is a synthetic test-only bearer; no real credential material
    /// ever reaches the fake because tests construct the routes themselves.
    pub fn capturedAuthorization(self: *FakeUpstream, out: []u8) usize {
        const shared = self.shared orelse return 0;
        shared.auth_capture.mutex.lock();
        defer shared.auth_capture.mutex.unlock();
        const n = @min(out.len, shared.auth_capture.len);
        @memcpy(out[0..n], shared.auth_capture.buf[0..n]);
        return n;
    }

    pub fn requestCaptureSnapshot(self: *FakeUpstream) RequestCaptureSnapshot {
        const shared = self.shared orelse return .{};
        return shared.request_capture.snapshot();
    }

    pub fn requestHeaderPresenceSnapshot(self: *FakeUpstream) RequestHeaderPresence {
        const shared = self.shared orelse return .{};
        return shared.request_capture.headerPresence();
    }

    pub fn responsePrefixWritten(self: *FakeUpstream) bool {
        const shared = self.shared orelse return false;
        return shared.response_prefix_written.load(.acquire);
    }

    pub fn releasePausedResponse(self: *FakeUpstream) void {
        const shared = self.shared orelse return;
        shared.release_paused_response.store(true, .release);
    }

    pub fn deinit(self: *FakeUpstream) void {
        const shared = self.shared orelse return;
        self.requestStop();

        if (self.thread) |thread| thread.join();
        shared.server.deinit();
        deinitScript(self.allocator, shared.responses);
        shared.request_capture.deinit();
        shared.auth_capture.deinit();
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
    response_prefix_written: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    release_paused_response: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    counters: Counters = .{},
    active: ActiveConnection = .{},
    request_capture: RequestCapture = .{},
    auth_capture: AuthCapture = .{},
};

/// Records the `Authorization` header of the most recent request the upstream
/// served, so a test can prove the proxy injected the expected synthetic route
/// credential. Test-only bearers only; the proxy never forwards the downstream
/// capability, so no live credential is ever observable here.
const AuthCapture = struct {
    mutex: std.Thread.Mutex = .{},
    buf: [max_captured_auth_bytes]u8 = undefined,
    len: usize = 0,

    fn record(self: *AuthCapture, value: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        std.crypto.secureZero(u8, self.buf[0..self.len]);
        const n = @min(value.len, self.buf.len);
        @memcpy(self.buf[0..n], value[0..n]);
        self.len = n;
    }

    fn reset(self: *AuthCapture) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        std.crypto.secureZero(u8, self.buf[0..self.len]);
        self.len = 0;
    }

    fn deinit(self: *AuthCapture) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        std.crypto.secureZero(u8, &self.buf);
        self.len = 0;
    }
};

/// Records the most recent request body the upstream received, so a test can
/// prove the proxy forwarded it byte-for-byte. Bounded and truncation-aware;
/// it holds no credential material because the proxy strips those upstream.
const RequestCapture = struct {
    mutex: std.Thread.Mutex = .{},
    buf: [max_captured_request_bytes]u8 = undefined,
    len: usize = 0,
    total_len: usize = 0,
    truncated: bool = false,
    headers: RequestHeaderPresence = .{},

    fn resetBody(self: *RequestCapture) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        std.crypto.secureZero(u8, self.buf[0..self.len]);
        self.len = 0;
        self.total_len = 0;
        self.truncated = false;
    }

    fn recordHeader(self: *RequestCapture, name: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (std.ascii.eqlIgnoreCase(name, "authorization")) {
            self.headers.authorization = true;
        } else if (std.ascii.eqlIgnoreCase(name, "x-api-key")) {
            self.headers.x_api_key = true;
        } else if (std.ascii.eqlIgnoreCase(name, "cookie")) {
            self.headers.cookie = true;
        } else if (std.ascii.eqlIgnoreCase(name, "forwarded")) {
            self.headers.forwarded = true;
        } else if (std.ascii.eqlIgnoreCase(name, "x-forwarded-for")) {
            self.headers.x_forwarded_for = true;
        } else if (std.ascii.eqlIgnoreCase(name, "x-forwarded-host")) {
            self.headers.x_forwarded_host = true;
        } else if (std.ascii.eqlIgnoreCase(name, "x-forwarded-port")) {
            self.headers.x_forwarded_port = true;
        } else if (std.ascii.eqlIgnoreCase(name, "x-forwarded-proto")) {
            self.headers.x_forwarded_proto = true;
        } else if (std.ascii.eqlIgnoreCase(name, "x-real-ip")) {
            self.headers.x_real_ip = true;
        } else if (std.ascii.eqlIgnoreCase(name, "keep-alive")) {
            self.headers.keep_alive = true;
        } else if (std.ascii.eqlIgnoreCase(name, "proxy-authenticate")) {
            self.headers.proxy_authenticate = true;
        } else if (std.ascii.eqlIgnoreCase(name, "proxy-authorization")) {
            self.headers.proxy_authorization = true;
        } else if (std.ascii.eqlIgnoreCase(name, "proxy-connection")) {
            self.headers.proxy_connection = true;
        } else if (std.ascii.eqlIgnoreCase(name, connection_nominated_canary)) {
            self.headers.x_private_hop_canary = true;
        } else if (std.ascii.eqlIgnoreCase(name, "te")) {
            self.headers.te = true;
        } else if (std.ascii.eqlIgnoreCase(name, "trailer")) {
            self.headers.trailer = true;
        } else if (std.ascii.eqlIgnoreCase(name, "trailers")) {
            self.headers.trailers = true;
        } else if (std.ascii.eqlIgnoreCase(name, "upgrade")) {
            self.headers.upgrade = true;
        } else if (std.ascii.eqlIgnoreCase(name, "expect")) {
            self.headers.expect = true;
        } else if (std.ascii.eqlIgnoreCase(name, "accept-encoding")) {
            self.headers.accept_encoding = true;
        } else if (std.ascii.eqlIgnoreCase(name, "anthropic-version")) {
            self.headers.anthropic_version = true;
        }
    }

    fn append(self: *RequestCapture, body: []const u8) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.total_len +|= body.len;
        const available = self.buf.len - self.len;
        const n = @min(body.len, available);
        @memcpy(self.buf[self.len..][0..n], body[0..n]);
        self.len += n;
        self.truncated = self.truncated or n != body.len;
    }

    fn snapshot(self: *RequestCapture) RequestCaptureSnapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        return .{
            .captured_len = self.len,
            .total_len = self.total_len,
            .truncated = self.truncated,
        };
    }

    fn headerPresence(self: *RequestCapture) RequestHeaderPresence {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.headers;
    }

    fn deinit(self: *RequestCapture) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        std.crypto.secureZero(u8, &self.buf);
        self.len = 0;
        self.total_len = 0;
        self.truncated = false;
        self.headers = .{};
    }
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
    chunked: bool,
    pause_after_bytes: ?usize,
    truncate_after_bytes: ?usize,

    fn clone(allocator: std.mem.Allocator, response: ScriptedResponse) !OwnedResponse {
        const status_code = @intFromEnum(response.status);
        if (status_code < 200 or status_code > 599) return error.InvalidStatus;
        if (responseHasNoBody(response.status) and response.body.len != 0) {
            return error.ResponseBodyNotAllowed;
        }
        if (response.chunked and responseHasNoBody(response.status)) {
            return error.ResponseBodyNotAllowed;
        }
        if (response.pause_after_bytes) |split| {
            if (responseHasNoBody(response.status) or split == 0 or split >= response.body.len) {
                return error.InvalidPauseBoundary;
            }
        }
        if (response.truncate_after_bytes) |split| {
            if (responseHasNoBody(response.status) or split == 0 or split >= response.body.len) {
                return error.InvalidTruncationBoundary;
            }
        }
        if (response.pause_after_bytes != null and response.truncate_after_bytes != null) {
            return error.ConflictingResponseControls;
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
            .chunked = response.chunked,
            .pause_after_bytes = response.pause_after_bytes,
            .truncate_after_bytes = response.truncate_after_bytes,
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
    shared.request_capture.resetBody();
    var headers = request.iterateHeaders();
    while (headers.next()) |header| {
        shared.request_capture.recordHeader(header.name);
    }
    if (request.head.expect != null) {
        request.respond("", .{
            .status = .expectation_failed,
            .keep_alive = false,
        }) catch {};
        return;
    }
    captureAuthorization(shared, &request);
    captureRequestBody(shared, &request);
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
        } else if (response.pause_after_bytes) |split| {
            shared.response_prefix_written.store(false, .release);
            shared.release_paused_response.store(false, .release);
            var send_buffer: [max_request_head_bytes]u8 = undefined;
            defer std.crypto.secureZero(u8, &send_buffer);
            var streamed = request.respondStreaming(.{
                .send_buffer = &send_buffer,
                .content_length = if (response.chunked) null else response.body.len,
                .respond_options = .{
                    .status = response.status,
                    .keep_alive = false,
                    .extra_headers = response.headers,
                },
            });
            streamed.writeAll(response.body[0..split]) catch return;
            streamed.flush() catch return;
            shared.response_prefix_written.store(true, .release);
            defer shared.response_prefix_written.store(false, .release);
            while (!shared.release_paused_response.load(.acquire)) {
                if (shared.stopping.load(.acquire)) return;
                std.Thread.yield() catch {};
            }
            streamed.writeAll(response.body[split..]) catch return;
            streamed.end() catch {};
        } else if (response.truncate_after_bytes) |split| {
            var send_buffer: [max_request_head_bytes]u8 = undefined;
            defer std.crypto.secureZero(u8, &send_buffer);
            var streamed = request.respondStreaming(.{
                .send_buffer = &send_buffer,
                .content_length = if (response.chunked) null else response.body.len,
                .respond_options = .{
                    .status = response.status,
                    .keep_alive = false,
                    .extra_headers = response.headers,
                },
            });
            streamed.writeAll(response.body[0..split]) catch return;
            streamed.flush() catch return;
            // Intentionally omit `end`: connection close is the malformed
            // truncation that the proxy must classify as interrupted.
            return;
        } else {
            request.respond(response.body, .{
                .status = response.status,
                .keep_alive = false,
                .extra_headers = response.headers,
                .transfer_encoding = if (response.chunked) .chunked else null,
            }) catch {};
        }
        return;
    }

    request.respond(script_exhausted_body, .{
        .status = .internal_server_error,
        .keep_alive = false,
    }) catch {};
}

fn captureAuthorization(shared: *Shared, request: *std.http.Server.Request) void {
    shared.auth_capture.reset();
    var iterator = request.iterateHeaders();
    while (iterator.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "authorization")) {
            shared.auth_capture.record(header.value);
            return;
        }
    }
}

fn captureRequestBody(shared: *Shared, request: *std.http.Server.Request) void {
    const reader = request.reader() catch return;
    var buf: [16 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &buf);
    while (true) {
        const n = reader.read(&buf) catch return;
        if (n == 0) return;
        shared.request_capture.append(buf[0..n]);
    }
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

test "request header presence is case-insensitive and sticky across requests" {
    const script = [_]ScriptedResponse{.{ .status = .no_content }} ** 3;
    var upstream = try FakeUpstream.start(std.testing.allocator, &script);
    defer upstream.deinit();

    const ordinary = try requestRawAlloc(
        std.testing.allocator,
        upstream.address(),
        "GET /v1/messages HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "Authorization2: ignored\r\n" ++
            "Cookie2: ignored\r\n" ++
            "X-Forwarded-Format: ignored\r\n" ++
            "Connection: close\r\n\r\n",
    );
    defer std.testing.allocator.free(ordinary);
    try std.testing.expect(std.mem.startsWith(u8, ordinary, "HTTP/1.1 204 No Content\r\n"));
    try std.testing.expectEqualDeep(
        RequestHeaderPresence{},
        upstream.requestHeaderPresenceSnapshot(),
    );

    const audited = try std.fmt.allocPrint(
        std.testing.allocator,
        "GET /v1/messages HTTP/1.1\r\n" ++
            "Host: 127.0.0.1\r\n" ++
            "aUtHoRiZaTiOn: Bearer test-only\r\n" ++
            "X-Api-Key: test-only\r\n" ++
            "cOoKiE: test-only\r\n" ++
            "Forwarded: test-only\r\n" ++
            "X-Forwarded-For: test-only\r\n" ++
            "X-Forwarded-Host: test-only\r\n" ++
            "X-Forwarded-Port: test-only\r\n" ++
            "X-Forwarded-Proto: test-only\r\n" ++
            "X-Real-IP: test-only\r\n" ++
            "Keep-Alive: test-only\r\n" ++
            "Proxy-Authenticate: test-only\r\n" ++
            "Proxy-Authorization: test-only\r\n" ++
            "Proxy-Connection: test-only\r\n" ++
            "{s}: test-only\r\n" ++
            "TE: test-only\r\n" ++
            "Trailer: test-only\r\n" ++
            "Trailers: test-only\r\n" ++
            "Upgrade: test-only\r\n" ++
            "Accept-Encoding: identity\r\n" ++
            "Anthropic-Version: 2023-06-01\r\n" ++
            "Connection: close\r\n\r\n",
        .{connection_nominated_canary},
    );
    defer std.testing.allocator.free(audited);
    const detected = try requestRawAlloc(std.testing.allocator, upstream.address(), audited);
    defer std.testing.allocator.free(detected);
    try std.testing.expect(std.mem.startsWith(u8, detected, "HTTP/1.1 204 No Content\r\n"));
    try std.testing.expectEqualDeep(
        RequestHeaderPresence{
            .authorization = true,
            .x_api_key = true,
            .cookie = true,
            .forwarded = true,
            .x_forwarded_for = true,
            .x_forwarded_host = true,
            .x_forwarded_port = true,
            .x_forwarded_proto = true,
            .x_real_ip = true,
            .keep_alive = true,
            .proxy_authenticate = true,
            .proxy_authorization = true,
            .proxy_connection = true,
            .x_private_hop_canary = true,
            .te = true,
            .trailer = true,
            .trailers = true,
            .upgrade = true,
            .accept_encoding = true,
            .anthropic_version = true,
        },
        upstream.requestHeaderPresenceSnapshot(),
    );

    const second = try requestAlloc(std.testing.allocator, upstream.address());
    defer std.testing.allocator.free(second);
    try std.testing.expect(std.mem.startsWith(u8, second, "HTTP/1.1 204 No Content\r\n"));
    try std.testing.expectEqualDeep(
        RequestHeaderPresence{
            .authorization = true,
            .x_api_key = true,
            .cookie = true,
            .forwarded = true,
            .x_forwarded_for = true,
            .x_forwarded_host = true,
            .x_forwarded_port = true,
            .x_forwarded_proto = true,
            .x_real_ip = true,
            .keep_alive = true,
            .proxy_authenticate = true,
            .proxy_authorization = true,
            .proxy_connection = true,
            .x_private_hop_canary = true,
            .te = true,
            .trailer = true,
            .trailers = true,
            .upgrade = true,
            .accept_encoding = true,
            .anthropic_version = true,
        },
        upstream.requestHeaderPresenceSnapshot(),
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
            "Authorization: Bearer test-only\r\n" ++
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
    try std.testing.expectEqualDeep(
        RequestHeaderPresence{
            .authorization = true,
            .expect = true,
        },
        upstream.requestHeaderPresenceSnapshot(),
    );

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

test "chunked scripted body is framed chunked and decodes to the same bytes" {
    const sse = "event: ping\ndata: {\"n\":1}\n\nevent: done\ndata: {}\n\n";
    const script = [_]ScriptedResponse{.{
        .status = .ok,
        .body = sse,
        .headers = &.{.{ .name = "Content-Type", .value = "text/event-stream" }},
        .chunked = true,
    }};
    var upstream = try FakeUpstream.start(std.testing.allocator, &script);
    defer upstream.deinit();

    const response = try requestAlloc(std.testing.allocator, upstream.address());
    defer std.testing.allocator.free(response);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, response, "transfer-encoding: chunked\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, "content-length:") == null);
    // Chunked framing carries the exact SSE payload as its terminal chunk data.
    try std.testing.expect(std.mem.indexOf(u8, response, sse) != null);
}

test "chunked framing is rejected for a bodyless status" {
    try std.testing.expectError(
        error.ResponseBodyNotAllowed,
        FakeUpstream.start(std.testing.allocator, &.{.{
            .status = .no_content,
            .chunked = true,
        }}),
    );
}

test "received request body is captured for byte-for-byte assertions" {
    const script = [_]ScriptedResponse{.{ .status = .ok, .body = "ack" }};
    var upstream = try FakeUpstream.start(std.testing.allocator, &script);
    defer upstream.deinit();

    const payload = "{\"model\":\"claude-opus-4-20250514\",\"messages\":[]}";
    const request = try std.fmt.allocPrint(
        std.testing.allocator,
        "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n" ++
            "Content-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ payload.len, payload },
    );
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(std.testing.allocator, upstream.address(), request);
    defer std.testing.allocator.free(response);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200 OK\r\n"));

    var captured: [128]u8 = undefined;
    const n = upstream.capturedRequestBody(&captured);
    try std.testing.expectEqualStrings(payload, captured[0..n]);
    try std.testing.expectEqualDeep(
        RequestCaptureSnapshot{
            .captured_len = payload.len,
            .total_len = payload.len,
            .truncated = false,
        },
        upstream.requestCaptureSnapshot(),
    );
}

test "request capture drains the body and reports bounded truncation" {
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok }});
    defer upstream.deinit();

    const payload = try std.testing.allocator.alloc(u8, max_captured_request_bytes + 257);
    defer std.testing.allocator.free(payload);
    @memset(payload, 'p');
    const head = try std.fmt.allocPrint(
        std.testing.allocator,
        "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1\r\n" ++
            "Content-Length: {d}\r\nConnection: close\r\n\r\n",
        .{payload.len},
    );
    defer std.testing.allocator.free(head);
    const request = try std.mem.concat(std.testing.allocator, u8, &.{ head, payload });
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(std.testing.allocator, upstream.address(), request);
    defer std.testing.allocator.free(response);
    try std.testing.expect(std.mem.startsWith(u8, response, "HTTP/1.1 200 OK\r\n"));

    try std.testing.expectEqualDeep(
        RequestCaptureSnapshot{
            .captured_len = max_captured_request_bytes,
            .total_len = payload.len,
            .truncated = true,
        },
        upstream.requestCaptureSnapshot(),
    );
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
