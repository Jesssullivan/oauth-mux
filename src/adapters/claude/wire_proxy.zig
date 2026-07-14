//! Authenticated loopback ingress for the unshipped managed Claude broker.
//!
//! This slice only establishes the local HTTP boundary. It does not read or
//! inject provider credentials, select routes, retry requests, or spawn Claude.

const std = @import("std");
const capability_mod = @import("session_capability.zig");
const fake_upstream_mod = @import("fake_upstream.zig");

const SessionCapability = capability_mod.SessionCapability;
const FakeUpstream = fake_upstream_mod.FakeUpstream;

pub const production_origin = "https://api.anthropic.com";
pub const production_forwarding_enabled = false;
const max_request_head_bytes = 64 * 1024;
const max_request_body_bytes = 32 * 1024 * 1024;
const max_response_head_bytes = 64 * 1024;
const max_response_body_bytes = 32 * 1024 * 1024;
const max_forwarded_response_headers = 25;

const Upstream = union(enum) {
    production,
    fake: *FakeUpstream,
};

const State = struct {
    allocator: std.mem.Allocator,
    capability: *SessionCapability,
    server: std.net.Server,
    upstream: Upstream,
    event_writer: std.io.AnyWriter,
    thread: ?std.Thread = null,
    stopping: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    active: ActiveConnection = .{},
};

/// One authenticated HTTP/1.1 listener bound to an ephemeral IPv4 loopback
/// port. The concrete state is opaque so callers cannot inject an upstream.
pub const Listener = opaque {
    /// Starts the production listener. Its upstream authority is compile-fixed;
    /// no client input or environment variable participates in selection.
    /// Production forwarding remains fail-closed until credential injection is
    /// implemented. The capability and event writer must outlive the listener.
    pub fn start(
        allocator: std.mem.Allocator,
        capability: *SessionCapability,
        event_writer: std.io.AnyWriter,
    ) !*Listener {
        return startWithUpstream(allocator, capability, event_writer, .production);
    }

    pub fn address(self: *const Listener) std.net.Address {
        return statePtrConst(self).server.listen_address;
    }

    pub fn port(self: *const Listener) u16 {
        return self.address().getPort();
    }

    /// Interrupts an accepted inbound connection, joins the listener thread,
    /// and only then releases the socket and listener state.
    pub fn deinit(self: *Listener) void {
        const state = statePtr(self);
        state.stopping.store(true, .release);
        state.active.interrupt();
        if (state.thread) |thread| thread.join();
        state.server.deinit();
        const allocator = state.allocator;
        allocator.destroy(state);
    }
};

fn statePtr(listener: *Listener) *State {
    return @ptrCast(@alignCast(listener));
}

fn statePtrConst(listener: *const Listener) *const State {
    return @ptrCast(@alignCast(listener));
}

fn startWithUpstream(
    allocator: std.mem.Allocator,
    capability: *SessionCapability,
    event_writer: std.io.AnyWriter,
    upstream: Upstream,
) !*Listener {
    const loopback = try std.net.Address.parseIp("127.0.0.1", 0);
    var server = try loopback.listen(.{ .reuse_address = true });
    errdefer server.deinit();

    const state = try allocator.create(State);
    errdefer allocator.destroy(state);
    state.* = .{
        .allocator = allocator,
        .capability = capability,
        .server = server,
        .upstream = upstream,
        .event_writer = event_writer,
    };
    state.thread = try std.Thread.spawn(.{}, run, .{state});
    return @ptrCast(state);
}

/// This file-private seam can only target the repository's deterministic fake.
fn startForTest(
    allocator: std.mem.Allocator,
    capability: *SessionCapability,
    upstream: *FakeUpstream,
) !*Listener {
    return startWithUpstream(
        allocator,
        capability,
        std.io.null_writer.any(),
        .{ .fake = upstream },
    );
}

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
        if (self.handle) |handle| std.posix.shutdown(handle, .both) catch {};
    }

    fn isSet(self: *ActiveConnection) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.handle != null;
    }
};

fn run(state: *State) void {
    while (!state.stopping.load(.acquire)) {
        var fds = [_]std.posix.pollfd{.{
            .fd = state.server.stream.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        const ready = std.posix.poll(&fds, 50) catch return;
        if (ready == 0) continue;
        if (fds[0].revents & std.posix.POLL.IN == 0) continue;

        const connection = state.server.accept() catch |err| switch (err) {
            error.WouldBlock => continue,
            else => return,
        };
        if (!state.active.begin(connection.stream.handle, &state.stopping)) {
            connection.stream.close();
            return;
        }
        serveConnection(state, connection);
        state.active.end(connection.stream.handle);
        connection.stream.close();
    }
}

fn serveConnection(state: *State, connection: std.net.Server.Connection) void {
    var read_buffer: [max_request_head_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &read_buffer);
    var server = std.http.Server.init(connection, &read_buffer);
    var request = server.receiveHead() catch |err| {
        writeHeadError(connection.stream, err) catch {};
        return;
    };
    handleRequest(state, &request) catch {
        request.respond("upstream unavailable", .{
            .status = .bad_gateway,
            .keep_alive = false,
        }) catch {};
    };
}

fn writeHeadError(stream: std.net.Stream, err: anyerror) !void {
    if (err == error.HttpConnectionClosing or err == error.HttpRequestTruncated) return;
    if (err == error.HttpHeadersOversize) {
        try stream.writeAll(
            "HTTP/1.1 431 Request Header Fields Too Large\r\n" ++
                "Content-Length: 0\r\nConnection: close\r\n\r\n",
        );
        return;
    }
    try stream.writeAll(
        "HTTP/1.1 400 Bad Request\r\n" ++
            "Content-Length: 0\r\nConnection: close\r\n\r\n",
    );
}

fn handleRequest(state: *State, request: *std.http.Server.Request) !void {
    var arena = std.heap.ArenaAllocator.init(state.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var inbound = std.ArrayListUnmanaged(std.http.Header){};
    var iterator = request.iterateHeaders();
    while (iterator.next()) |header| try inbound.append(allocator, header);

    if (!validCapability(state.capability, inbound.items)) {
        emitEvent(state, "claude_proxy_capability_rejected");
        try request.respond("unauthorized", .{
            .status = .unauthorized,
            .keep_alive = false,
        });
        return;
    }

    if (!validRequestOrigin(request, inbound.items, state.server.listen_address.getPort())) {
        try request.respond("bad request", .{
            .status = .bad_request,
            .keep_alive = false,
        });
        return;
    }

    if (request.head.expect != null) {
        try request.respond("expectation failed", .{
            .status = .expectation_failed,
            .keep_alive = false,
        });
        return;
    }

    var forwarded_headers = std.ArrayListUnmanaged(std.http.Header){};
    try appendForwardingHeaders(allocator, inbound.items, &forwarded_headers);

    const body_reader = try request.reader();
    var body = readAllSensitiveAlloc(allocator, body_reader, max_request_body_bytes) catch |err| {
        if (err == error.StreamTooLong) {
            try request.respond("request too large", .{
                .status = .payload_too_large,
                .keep_alive = false,
            });
            return;
        }
        return err;
    };
    defer body.deinit();

    try forwardOnce(state, request, allocator, forwarded_headers.items, body.slice());
}

const SensitiveBytes = struct {
    allocator: std.mem.Allocator,
    storage: []u8 = &.{},
    len: usize = 0,

    fn slice(self: *const SensitiveBytes) []const u8 {
        return self.storage[0..self.len];
    }

    fn grow(self: *SensitiveBytes, max_bytes: usize) !void {
        if (self.storage.len >= max_bytes) return error.StreamTooLong;
        const next_capacity = if (self.storage.len == 0)
            @min(max_bytes, 16 * 1024)
        else
            @min(max_bytes, self.storage.len * 2);
        const replacement = try self.allocator.alloc(u8, next_capacity);
        @memcpy(replacement[0..self.len], self.storage[0..self.len]);
        if (self.storage.len != 0) {
            std.crypto.secureZero(u8, self.storage);
            self.allocator.free(self.storage);
        }
        self.storage = replacement;
    }

    fn deinit(self: *SensitiveBytes) void {
        if (self.storage.len != 0) {
            std.crypto.secureZero(u8, self.storage);
            self.allocator.free(self.storage);
        }
        self.* = .{ .allocator = self.allocator };
    }
};

fn readAllSensitiveAlloc(
    allocator: std.mem.Allocator,
    reader: anytype,
    max_bytes: usize,
) !SensitiveBytes {
    var bytes = SensitiveBytes{ .allocator = allocator };
    errdefer bytes.deinit();
    while (true) {
        if (bytes.len == bytes.storage.len) {
            if (bytes.len == max_bytes) {
                var overflow_probe: [1]u8 = undefined;
                defer std.crypto.secureZero(u8, &overflow_probe);
                if (try reader.read(&overflow_probe) != 0) return error.StreamTooLong;
                break;
            }
            try bytes.grow(max_bytes);
        }
        const count = try reader.read(bytes.storage[bytes.len..]);
        if (count == 0) break;
        bytes.len += count;
    }
    return bytes;
}

fn emitEvent(state: *State, kind: []const u8) void {
    state.event_writer.print("{{\"kind\":\"{s}\"}}\n", .{kind}) catch {};
}

fn validCapability(capability: *SessionCapability, headers: []const std.http.Header) bool {
    var authorization: ?[]const u8 = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "authorization")) continue;
        if (authorization != null) return false;
        authorization = header.value;
    }
    const value = authorization orelse return false;
    const prefix = "Bearer ";
    if (value.len != prefix.len + capability_mod.carrier_len) return false;
    if (!std.ascii.eqlIgnoreCase(value[0 .. prefix.len - 1], "Bearer")) return false;
    if (value[prefix.len - 1] != ' ') return false;
    return capability.validate(value[prefix.len..]);
}

fn validRequestOrigin(
    request: *const std.http.Server.Request,
    headers: []const std.http.Header,
    port: u16,
) bool {
    if (request.head.version != .@"HTTP/1.1") return false;
    if (request.head.method == .CONNECT) return false;
    if (request.head.target.len == 0 or request.head.target[0] != '/') return false;
    if (std.mem.indexOfScalar(u8, request.head.target, '#') != null) return false;

    var host: ?[]const u8 = null;
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "host")) continue;
        if (host != null) return false;
        host = header.value;
    }
    const actual = host orelse return false;
    var expected_buffer: [32]u8 = undefined;
    const expected = std.fmt.bufPrint(&expected_buffer, "127.0.0.1:{d}", .{port}) catch return false;
    return std.mem.eql(u8, actual, expected);
}

fn appendForwardingHeaders(
    allocator: std.mem.Allocator,
    inbound: []const std.http.Header,
    outbound: *std.ArrayListUnmanaged(std.http.Header),
) !void {
    for (inbound) |header| {
        if (stripRequestHeader(header.name, inbound)) continue;
        try outbound.append(allocator, header);
    }
}

fn stripRequestHeader(name: []const u8, headers: []const std.http.Header) bool {
    const fixed = [_][]const u8{
        "authorization",
        "x-api-key",
        "cookie",
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-port",
        "x-forwarded-proto",
        "x-real-ip",
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "trailers",
        "upgrade",
        "expect",
    };
    for (fixed) |blocked| {
        if (std.ascii.eqlIgnoreCase(name, blocked)) return true;
    }
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "connection")) continue;
        if (commaSeparatedTokenContains(header.value, name)) return true;
    }
    return false;
}

fn commaSeparatedTokenContains(value: []const u8, wanted: []const u8) bool {
    var tokens = std.mem.splitScalar(u8, value, ',');
    while (tokens.next()) |raw| {
        const token = std.mem.trim(u8, raw, " \t");
        if (std.ascii.eqlIgnoreCase(token, wanted)) return true;
    }
    return false;
}

fn forwardOnce(
    state: *State,
    downstream: *std.http.Server.Request,
    allocator: std.mem.Allocator,
    headers: []const std.http.Header,
    body: []const u8,
) !void {
    const origin = switch (state.upstream) {
        .production => return error.ProductionCredentialInjectionNotImplemented,
        .fake => |upstream| upstream.baseUrl(),
    };
    const url = try std.fmt.allocPrint(allocator, "{s}{s}", .{ origin, downstream.head.target });
    defer std.crypto.secureZero(u8, url);
    const uri = try std.Uri.parse(url);

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();
    var response_head_buffer: [max_response_head_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &response_head_buffer);
    var upstream_request = try client.open(downstream.head.method, uri, .{
        .server_header_buffer = &response_head_buffer,
        .keep_alive = false,
        .redirect_behavior = .unhandled,
        .headers = .{
            .authorization = .omit,
            .connection = .{ .override = "close" },
        },
        .extra_headers = headers,
    });
    defer upstream_request.deinit();

    if (body.len != 0) upstream_request.transfer_encoding = .{ .content_length = body.len };
    try upstream_request.send();
    if (body.len != 0) {
        try upstream_request.writeAll(body);
        try upstream_request.finish();
    }
    try upstream_request.wait();

    var upstream_body = try readAllSensitiveAlloc(
        allocator,
        upstream_request.reader(),
        max_response_body_bytes,
    );
    defer upstream_body.deinit();
    if (upstream_request.response.status.class() == .redirect) {
        try downstream.respond("upstream redirect rejected", .{
            .status = .bad_gateway,
            .keep_alive = false,
        });
        return;
    }

    var all_response_headers = std.ArrayListUnmanaged(std.http.Header){};
    var response_iterator = upstream_request.response.iterateHeaders();
    while (response_iterator.next()) |header| {
        try all_response_headers.append(allocator, header);
    }

    var response_headers: [max_forwarded_response_headers]std.http.Header = undefined;
    var response_header_count: usize = 0;
    for (all_response_headers.items) |header| {
        if (stripResponseHeader(header.name, all_response_headers.items)) continue;
        if (response_header_count == response_headers.len) return error.ResponseHeadersOverflow;
        response_headers[response_header_count] = header;
        response_header_count += 1;
    }
    try downstream.respond(upstream_body.slice(), .{
        .status = upstream_request.response.status,
        .keep_alive = false,
        .extra_headers = response_headers[0..response_header_count],
    });
}

fn stripResponseHeader(name: []const u8, headers: []const std.http.Header) bool {
    const blocked = [_][]const u8{
        "connection",
        "content-length",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "trailers",
        "transfer-encoding",
        "upgrade",
    };
    for (blocked) |candidate| {
        if (std.ascii.eqlIgnoreCase(name, candidate)) return true;
    }
    for (headers) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "connection")) continue;
        if (commaSeparatedTokenContains(header.value, name)) return true;
    }
    return false;
}

fn copyCarrier(capability: *SessionCapability) ![capability_mod.carrier_len]u8 {
    var carrier: [capability_mod.carrier_len]u8 = undefined;
    try capability.copyCarrier(&carrier);
    return carrier;
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

fn expectStatus(response: []const u8, status_line: []const u8) !void {
    try std.testing.expect(std.mem.startsWith(u8, response, status_line));
}

test "sensitive reader grows without realloc and rejects overflow" {
    var payload: [20 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &payload);
    for (&payload, 0..) |*byte, index| byte.* = @intCast(index % 251);
    var payload_stream = std.io.fixedBufferStream(&payload);
    var bytes = try readAllSensitiveAlloc(
        std.testing.allocator,
        payload_stream.reader(),
        32 * 1024,
    );
    defer bytes.deinit();
    try std.testing.expectEqualSlices(u8, &payload, bytes.slice());

    var overflow_stream = std.io.fixedBufferStream(&payload);
    try std.testing.expectError(
        error.StreamTooLong,
        readAllSensitiveAlloc(std.testing.allocator, overflow_stream.reader(), 16 * 1024),
    );
}

test "valid capability reaches only the fake upstream" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = "accepted",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    }});
    defer upstream.deinit();
    const listener = try startForTest(std.testing.allocator, capability, &upstream);
    defer listener.deinit();

    const request = try std.fmt.allocPrint(
        std.testing.allocator,
        "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n",
        .{ listener.port(), carrier },
    );
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
    defer std.testing.allocator.free(response);

    try expectStatus(response, "HTTP/1.1 200 OK\r\n");
    try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\naccepted"));
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);
}

test "missing malformed and wrong capabilities return 401 with zero upstream calls" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var wrong = [_]u8{'A'} ** capability_mod.carrier_len;
    defer std.crypto.secureZero(u8, &wrong);
    if (std.mem.eql(u8, &wrong, &carrier)) wrong[0] = 'B';
    var malformed = carrier;
    defer std.crypto.secureZero(u8, &malformed);
    malformed[0] = '=';
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{});
    defer upstream.deinit();
    var event_buffer: [1024]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try startWithUpstream(
        std.testing.allocator,
        capability,
        event_stream.writer().any(),
        .{ .fake = &upstream },
    );
    defer listener.deinit();

    const auth_values = [_]?[]const u8{ null, "", "short", malformed[0..], wrong[0..] };
    for (auth_values) |auth_value| {
        const auth_line = if (auth_value) |value|
            try std.fmt.allocPrint(std.testing.allocator, "Authorization: Bearer {s}\r\n", .{value})
        else
            try std.testing.allocator.dupe(u8, "");
        defer std.testing.allocator.free(auth_line);
        const request = try std.fmt.allocPrint(
            std.testing.allocator,
            "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\n{s}Connection: close\r\n\r\n",
            .{ listener.port(), auth_line },
        );
        defer std.testing.allocator.free(request);
        const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
        defer std.testing.allocator.free(response);
        try expectStatus(response, "HTTP/1.1 401 Unauthorized\r\n");
    }

    const duplicate_request = try std.fmt.allocPrint(
        std.testing.allocator,
        "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n",
        .{ listener.port(), carrier, carrier },
    );
    defer std.testing.allocator.free(duplicate_request);
    const duplicate_response = try requestRawAlloc(
        std.testing.allocator,
        listener.address(),
        duplicate_request,
    );
    defer std.testing.allocator.free(duplicate_response);
    try expectStatus(duplicate_response, "HTTP/1.1 401 Unauthorized\r\n");

    try std.testing.expect(upstream.snapshot().isZero());
    const expected_event = "{\"kind\":\"claude_proxy_capability_rejected\"}\n";
    try std.testing.expectEqual(
        auth_values.len + 1,
        std.mem.count(u8, event_stream.getWritten(), expected_event),
    );
    try std.testing.expect(std.mem.indexOf(u8, event_stream.getWritten(), &carrier) == null);
}

test "production listener is fixed-origin and fail-closed before credential wiring" {
    try std.testing.expectEqualStrings("https://api.anthropic.com", production_origin);
    try std.testing.expect(!production_forwarding_enabled);

    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    const listener = try Listener.start(
        std.testing.allocator,
        capability,
        std.io.null_writer.any(),
    );
    defer listener.deinit();

    const request = try std.fmt.allocPrint(
        std.testing.allocator,
        "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n",
        .{ listener.port(), carrier },
    );
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
    defer std.testing.allocator.free(response);
    try expectStatus(response, "HTTP/1.1 502 Bad Gateway\r\n");
}

test "origin form Host CONNECT and absolute form fail before upstream" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{});
    defer upstream.deinit();
    const listener = try startForTest(std.testing.allocator, capability, &upstream);
    defer listener.deinit();

    const requests = [_][]u8{
        try std.fmt.allocPrint(std.testing.allocator, "GET /v1/messages HTTP/1.1\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{carrier}),
        try std.fmt.allocPrint(std.testing.allocator, "GET /v1/messages HTTP/1.1\r\nHost: api.anthropic.com\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{carrier}),
        try std.fmt.allocPrint(std.testing.allocator, "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{ listener.port(), listener.port(), carrier }),
        try std.fmt.allocPrint(std.testing.allocator, "CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{ listener.port(), carrier }),
        try std.fmt.allocPrint(std.testing.allocator, "GET https://api.anthropic.com/v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{ listener.port(), carrier }),
        try std.fmt.allocPrint(std.testing.allocator, "OPTIONS * HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n", .{ listener.port(), carrier }),
    };
    defer for (requests) |request| std.testing.allocator.free(request);
    for (requests) |request| {
        const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
        defer std.testing.allocator.free(response);
        try expectStatus(response, "HTTP/1.1 400 Bad Request\r\n");
    }
    try std.testing.expect(upstream.snapshot().isZero());
}

test "forwarded headers strip credentials framing and connection tokens" {
    const inbound = [_]std.http.Header{
        .{ .name = "Authorization", .value = "Bearer local-capability" },
        .{ .name = "X-Api-Key", .value = "caller-key" },
        .{ .name = "Cookie", .value = "caller-cookie" },
        .{ .name = "Forwarded", .value = "host=caller.invalid" },
        .{ .name = "X-Forwarded-Host", .value = "caller.invalid" },
        .{ .name = "Proxy-Authenticate", .value = "Basic local" },
        .{ .name = "Proxy-Authorization", .value = "Basic caller" },
        .{ .name = "Proxy-Connection", .value = "keep-alive" },
        .{ .name = "Host", .value = "127.0.0.1:1" },
        .{ .name = "Content-Length", .value = "4" },
        .{ .name = "Transfer-Encoding", .value = "chunked" },
        .{ .name = "Connection", .value = "X-Private-Hop, keep-alive" },
        .{ .name = "X-Private-Hop", .value = "remove-me" },
        .{ .name = "TE", .value = "trailers" },
        .{ .name = "Upgrade", .value = "websocket" },
        .{ .name = "Anthropic-Version", .value = "2023-06-01" },
    };
    var outbound = std.ArrayListUnmanaged(std.http.Header){};
    defer outbound.deinit(std.testing.allocator);
    try appendForwardingHeaders(std.testing.allocator, &inbound, &outbound);

    try std.testing.expectEqual(@as(usize, 1), outbound.items.len);
    try std.testing.expectEqualStrings("Anthropic-Version", outbound.items[0].name);
    try std.testing.expectEqualStrings("2023-06-01", outbound.items[0].value);
}

test "response headers strip fixed and connection-nominated hop headers" {
    const headers = [_]std.http.Header{
        .{ .name = "Connection", .value = "X-Upstream-Hop, close" },
        .{ .name = "X-Upstream-Hop", .value = "remove-me" },
        .{ .name = "Transfer-Encoding", .value = "chunked" },
        .{ .name = "TE", .value = "trailers" },
        .{ .name = "Trailer", .value = "X-Trailer" },
        .{ .name = "Proxy-Authorization", .value = "Basic upstream" },
        .{ .name = "Proxy-Connection", .value = "keep-alive" },
        .{ .name = "Anthropic-RateLimit-Unified-Status", .value = "allowed" },
    };
    try std.testing.expect(stripResponseHeader(headers[0].name, &headers));
    try std.testing.expect(stripResponseHeader(headers[1].name, &headers));
    try std.testing.expect(stripResponseHeader(headers[2].name, &headers));
    try std.testing.expect(stripResponseHeader(headers[3].name, &headers));
    try std.testing.expect(stripResponseHeader(headers[4].name, &headers));
    try std.testing.expect(stripResponseHeader(headers[5].name, &headers));
    try std.testing.expect(stripResponseHeader(headers[6].name, &headers));
    try std.testing.expect(!stripResponseHeader(headers[7].name, &headers));
}

test "accepted request with stripped headers still reaches fake upstream" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .no_content }});
    defer upstream.deinit();
    const listener = try startForTest(std.testing.allocator, capability, &upstream);
    defer listener.deinit();

    const request = try std.fmt.allocPrint(
        std.testing.allocator,
        "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nX-Api-Key: caller-key\r\nProxy-Authorization: Basic caller\r\nConnection: X-Private-Hop, close\r\nX-Private-Hop: remove\r\nTE: trailers\r\n\r\n",
        .{ listener.port(), carrier },
    );
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
    defer std.testing.allocator.free(response);
    try expectStatus(response, "HTTP/1.1 204 No Content\r\n");
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);
}

test "upstream redirect is rejected without a second call" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .found,
        .headers = &.{.{ .name = "Location", .value = "https://example.com/steal" }},
    }});
    defer upstream.deinit();
    const listener = try startForTest(std.testing.allocator, capability, &upstream);
    defer listener.deinit();

    const request = try std.fmt.allocPrint(
        std.testing.allocator,
        "GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\nConnection: close\r\n\r\n",
        .{ listener.port(), carrier },
    );
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
    defer std.testing.allocator.free(response);
    try expectStatus(response, "HTTP/1.1 502 Bad Gateway\r\n");
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);
}

test "shutdown interrupts a partial request within a fixed deadline" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{});
    defer upstream.deinit();
    const listener = try startForTest(std.testing.allocator, capability, &upstream);
    var listener_live = true;
    defer if (listener_live) listener.deinit();

    var stream = try std.net.tcpConnectToAddress(listener.address());
    defer stream.close();
    try stream.writeAll("GET /v1/messages HTTP/1.1\r\nHost: 127.0.0.1");

    var active_timer = try std.time.Timer.start();
    while (!statePtr(listener).active.isSet()) {
        if (active_timer.read() > std.time.ns_per_s) return error.TestTimeout;
        std.Thread.yield() catch {};
    }
    var shutdown_timer = try std.time.Timer.start();
    listener.deinit();
    listener_live = false;
    try std.testing.expect(shutdown_timer.read() < std.time.ns_per_s);
    try std.testing.expect(upstream.snapshot().isZero());
}
