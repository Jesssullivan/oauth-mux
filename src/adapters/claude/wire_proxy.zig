//! Authenticated loopback ingress for the unshipped managed Claude broker.
//!
//! This slice only establishes the local HTTP boundary. It does not read or
//! inject provider credentials, select routes, retry requests, or spawn Claude.

const std = @import("std");
const builtin = @import("builtin");
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
// Exact-model admission (program §2.2, ladder §8.2). The request body is already
// bounded by `max_request_body_bytes`, so the complete document is validated.
// This rejects duplicate model keys and trailing JSON before any upstream call.
const max_model_len = 128;

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
    upstream_active: ActiveConnection = .{},
    observation_mutex: std.Thread.Mutex = .{},
    observation: RequestObservation = .{},
};

/// FIRST-ATTEMPT ADMISSION ONLY. Records what model was admitted for the one
/// upstream attempt of the last request. It is exposed to tests through the same
/// snapshot pattern the fake upstream uses. The model bytes are the public model
/// identifier only; no credential or body payload is retained.
///
/// It deliberately makes NO result-side claim. Ladder §8.2 step 3 (the
/// harness-visible successful result reporting the same public model through a
/// trusted local observation) is NOT established here: this slice never inspects
/// the response body for a model, so result-side model evidence does not exist
/// yet. `admittedModel()` describes only what was admitted for the attempt,
/// never what the upstream result reported.
const RequestObservation = struct {
    had_body: bool = false,
    /// A top-level request model was present and admitted for the attempt.
    model_present: bool = false,
    admitted_model_buf: [max_model_len]u8 = undefined,
    admitted_model_len: usize = 0,
    upstream_attempted: bool = false,
    upstream_status: u16 = 0,
    model_admission_rejected: bool = false,

    fn admittedModel(self: *const RequestObservation) []const u8 {
        return self.admitted_model_buf[0..self.admitted_model_len];
    }
};

const ModelObservationInput = struct {
    had_body: bool = false,
    model_present: bool = false,
    admitted_model: ?[]const u8 = null,
    upstream_attempted: bool = false,
    upstream_status: u16 = 0,
    model_admission_rejected: bool = false,
};

fn recordModelObservation(state: *State, input: ModelObservationInput) void {
    state.observation_mutex.lock();
    defer state.observation_mutex.unlock();
    var obs = RequestObservation{
        .had_body = input.had_body,
        .model_present = input.model_present,
        .upstream_attempted = input.upstream_attempted,
        .upstream_status = input.upstream_status,
        .model_admission_rejected = input.model_admission_rejected,
    };
    if (input.admitted_model) |m| {
        const n = @min(m.len, max_model_len);
        @memcpy(obs.admitted_model_buf[0..n], m[0..n]);
        obs.admitted_model_len = n;
    }
    state.observation = obs;
}

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
        state.upstream_active.interrupt();
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

/// File-private: capture the last request's exact-model accounting.
fn observationSnapshot(listener: *Listener) RequestObservation {
    const state = statePtr(listener);
    state.observation_mutex.lock();
    defer state.observation_mutex.unlock();
    return state.observation;
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

pub const testing = if (builtin.is_test) struct {
    /// Test-only composition seam. The caller supplies the repository's
    /// deterministic fake explicitly; production upstream selection remains
    /// compile-fixed and unavailable through this API.
    pub fn startWithFake(
        allocator: std.mem.Allocator,
        capability: *SessionCapability,
        upstream: *FakeUpstream,
        event_writer: std.io.AnyWriter,
    ) !*Listener {
        return startWithUpstream(
            allocator,
            capability,
            event_writer,
            .{ .fake = upstream },
        );
    }
} else struct {};

/// This file-private seam can only target the repository's deterministic fake.
fn startForTest(
    allocator: std.mem.Allocator,
    capability: *SessionCapability,
    upstream: *FakeUpstream,
) !*Listener {
    return testing.startWithFake(
        allocator,
        capability,
        upstream,
        std.io.null_writer.any(),
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

    const captured_model = peekTopLevelModel(allocator, body.slice()) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => {
            recordModelObservation(state, .{
                .had_body = body.slice().len != 0,
                .model_admission_rejected = true,
            });
            emitEvent(state, "claude_proxy_model_admission_rejected");
            try request.respond("model admission rejected", .{
                .status = .bad_request,
                .keep_alive = false,
            });
            return;
        },
    };

    try forwardOnce(state, request, allocator, forwarded_headers.items, body.slice(), captured_model);
}

const ModelPeekError = error{
    ModelPeekUnparseable,
    ModelPeekMissing,
    ModelPeekDuplicate,
    ModelPeekNotString,
    ModelPeekTooLong,
    OutOfMemory,
};

fn scanNext(scanner: *std.json.Scanner, alloc: std.mem.Allocator) ModelPeekError!std.json.Token {
    // The scanner is built over the complete request body, already bounded by
    // `max_request_body_bytes`; malformed or truncated input refuses locally.
    return scanner.nextAlloc(alloc, .alloc_if_needed) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.ModelPeekUnparseable,
    };
}

fn skipJsonValue(scanner: *std.json.Scanner, alloc: std.mem.Allocator) ModelPeekError!void {
    var depth: usize = 0;
    while (true) {
        switch (try scanNext(scanner, alloc)) {
            .object_begin, .array_begin => depth += 1,
            .object_end, .array_end => {
                if (depth == 0) return error.ModelPeekUnparseable;
                depth -= 1;
            },
            .end_of_document => return error.ModelPeekUnparseable,
            else => {},
        }
        if (depth == 0) return;
    }
}

/// Validates the complete bounded JSON document and returns its unique top-level
/// `model` string (program §2.2, ladder §8.2). Returns null for a bodyless
/// request. No family inference, alias, or substitution is performed.
fn peekTopLevelModel(alloc: std.mem.Allocator, body: []const u8) ModelPeekError!?[]const u8 {
    if (body.len == 0) return null;
    var scanner = std.json.Scanner.initCompleteInput(alloc, body);
    defer scanner.deinit();

    switch (try scanNext(&scanner, alloc)) {
        .object_begin => {},
        else => return error.ModelPeekUnparseable,
    }
    var model: ?[]const u8 = null;
    while (true) {
        const key: []const u8 = switch (try scanNext(&scanner, alloc)) {
            .object_end => {
                switch (try scanNext(&scanner, alloc)) {
                    .end_of_document => return model orelse error.ModelPeekMissing,
                    else => return error.ModelPeekUnparseable,
                }
            },
            .string => |s| s,
            .allocated_string => |s| s,
            else => return error.ModelPeekUnparseable,
        };
        if (std.mem.eql(u8, key, "model")) {
            if (model != null) return error.ModelPeekDuplicate;
            const value: []const u8 = switch (try scanNext(&scanner, alloc)) {
                .string => |s| s,
                .allocated_string => |s| s,
                else => return error.ModelPeekNotString,
            };
            if (value.len == 0) return error.ModelPeekNotString;
            if (value.len > max_model_len) return error.ModelPeekTooLong;
            model = try alloc.dupe(u8, value);
            continue;
        }
        try skipJsonValue(&scanner, alloc);
    }
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
        "accept-encoding",
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
    captured_model: ?[]const u8,
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
            .accept_encoding = .{ .override = "identity" },
            .connection = .{ .override = "close" },
        },
        .extra_headers = headers,
    });
    defer upstream_request.deinit();

    const upstream_connection = upstream_request.connection orelse return error.UpstreamConnectionMissing;
    const upstream_handle = upstream_connection.stream.handle;
    if (!state.upstream_active.begin(upstream_handle, &state.stopping)) {
        return error.ListenerStopping;
    }
    defer state.upstream_active.end(upstream_handle);

    if (body.len != 0) upstream_request.transfer_encoding = .{ .content_length = body.len };
    try upstream_request.send();
    if (body.len != 0) {
        try upstream_request.writeAll(body);
        try upstream_request.finish();
    }
    try upstream_request.wait();
    const upstream_status = upstream_request.response.status;
    recordModelObservation(state, .{
        .had_body = body.len != 0,
        .model_present = captured_model != null,
        .admitted_model = captured_model,
        .upstream_attempted = true,
        .upstream_status = @intFromEnum(upstream_status),
    });

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

    if (upstream_status.class() == .redirect) {
        try downstream.respond("upstream redirect rejected", .{
            .status = .bad_gateway,
            .keep_alive = false,
        });
        return;
    }

    // Error responses remain buffered because 401/403/429 are future
    // pre-response decision points. Provider 5xx passes through unchanged to
    // Claude Code's native retry and never authorizes another account attempt.
    if (upstream_status.class() == .client_error or upstream_status.class() == .server_error) {
        var upstream_body = try readAllSensitiveAlloc(
            allocator,
            upstream_request.reader(),
            max_response_body_bytes,
        );
        defer upstream_body.deinit();
        if (upstream_status.class() == .server_error) {
            emitEvent(state, "claude_proxy_upstream_server_error");
        }
        try downstream.respond(upstream_body.slice(), .{
            .status = upstream_status,
            .keep_alive = false,
            .extra_headers = response_headers[0..response_header_count],
        });
        return;
    }

    if (responseHasNoBody(downstream, upstream_status)) {
        downstream.respond("", .{
            .status = upstream_status,
            .keep_alive = false,
            .extra_headers = response_headers[0..response_header_count],
            .transfer_encoding = .none,
        }) catch {
            emitEvent(state, "claude_proxy_client_disconnected");
        };
        return;
    }

    streamUpstreamResponse(
        state,
        downstream,
        &upstream_request,
        response_headers[0..response_header_count],
    );
}

fn responseHasNoBody(request: *const std.http.Server.Request, status: std.http.Status) bool {
    return request.head.method == .HEAD or switch (@intFromEnum(status)) {
        100...199, 204, 205, 304 => true,
        else => false,
    };
}

fn streamUpstreamResponse(
    state: *State,
    downstream: *std.http.Server.Request,
    upstream: *std.http.Client.Request,
    headers: []const std.http.Header,
) void {
    var send_buffer: [max_response_head_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &send_buffer);
    var response = downstream.respondStreaming(.{
        .send_buffer = &send_buffer,
        .content_length = upstream.response.content_length,
        .respond_options = .{
            .status = upstream.response.status,
            .keep_alive = false,
            .extra_headers = headers,
        },
    });
    response.flush() catch {
        emitEvent(state, "claude_proxy_client_disconnected");
        return;
    };

    var body_buffer: [64 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &body_buffer);
    var body_reader = upstream.reader();
    var streamed: u64 = 0;
    while (true) {
        const count = body_reader.read(&body_buffer) catch |err| {
            if (err == error.EndOfStream and
                upstream.response.transfer_encoding == .none and
                upstream.response.content_length == null)
            {
                // Close-delimited upstream framing cannot distinguish a clean
                // EOF from truncation. The fixed Anthropic path requests
                // identity encoding and normally receives length or chunked
                // framing; retain this protocol-compatible fallback without
                // promoting it as completeness evidence.
                response.end() catch {
                    emitEvent(state, "claude_proxy_client_disconnected");
                };
                return;
            }
            emitEvent(state, "claude_proxy_upstream_interrupted");
            return;
        };
        if (count == 0) {
            // Zig 0.14.1 normalizes premature EOF while parsing chunked bodies
            // to a zero-byte read, but leaves the parser in its unfinished
            // chunk state. Only `.finished` proves the terminal chunk/trailers.
            if (upstream.response.transfer_encoding == .chunked and
                upstream.response.parser.state != .finished)
            {
                emitEvent(state, "claude_proxy_upstream_interrupted");
                return;
            }
            if (upstream.response.content_length) |expected| {
                if (streamed != expected) {
                    emitEvent(state, "claude_proxy_upstream_interrupted");
                    return;
                }
            }
            response.end() catch {
                emitEvent(state, "claude_proxy_client_disconnected");
                return;
            };
            return;
        }
        response.writeAll(body_buffer[0..count]) catch {
            emitEvent(state, "claude_proxy_client_disconnected");
            return;
        };
        response.flush() catch {
            emitEvent(state, "claude_proxy_client_disconnected");
            return;
        };
        streamed += count;
    }
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
        .{ .name = "Accept-Encoding", .value = "gzip, deflate" },
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
    const obs = observationSnapshot(listener);
    try std.testing.expect(obs.upstream_attempted);
    try std.testing.expectEqual(@as(u16, 302), obs.upstream_status);
}

fn postRequestAlloc(
    allocator: std.mem.Allocator,
    port: u16,
    carrier: []const u8,
    body: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "POST /v1/messages HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nAuthorization: Bearer {s}\r\n" ++
            "Content-Type: application/json\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ port, carrier, body.len, body },
    );
}

fn waitForResponsePrefix(upstream: *FakeUpstream) !void {
    var timer = try std.time.Timer.start();
    while (!upstream.responsePrefixWritten()) {
        if (timer.read() > 5 * std.time.ns_per_s) return error.TestTimeout;
        std.Thread.yield() catch {};
    }
}

fn waitForListenerIdle(listener: *Listener) !void {
    var timer = try std.time.Timer.start();
    while (statePtr(listener).active.isSet()) {
        if (timer.read() > 5 * std.time.ns_per_s) return error.TestTimeout;
        std.Thread.yield() catch {};
    }
}

fn readUntilContains(
    stream: *std.net.Stream,
    response: *std.ArrayList(u8),
    needle: []const u8,
) !void {
    var timer = try std.time.Timer.start();
    var buffer: [1024]u8 = undefined;
    while (std.mem.indexOf(u8, response.items, needle) == null) {
        if (timer.read() > 5 * std.time.ns_per_s) return error.TestTimeout;
        var fds = [_]std.posix.pollfd{.{
            .fd = stream.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        if (try std.posix.poll(&fds, 10) == 0) continue;
        const count = try stream.read(&buffer);
        if (count == 0) return error.EndOfStream;
        try response.appendSlice(buffer[0..count]);
    }
}

fn readResponseRemainder(stream: *std.net.Stream, response: *std.ArrayList(u8)) !void {
    var timer = try std.time.Timer.start();
    var buffer: [1024]u8 = undefined;
    while (true) {
        if (timer.read() > 5 * std.time.ns_per_s) return error.TestTimeout;
        var fds = [_]std.posix.pollfd{.{
            .fd = stream.handle,
            .events = std.posix.POLL.IN,
            .revents = 0,
        }};
        if (try std.posix.poll(&fds, 10) == 0) continue;
        const count = try stream.read(&buffer);
        if (count == 0) return;
        try response.appendSlice(buffer[0..count]);
    }
}

/// Decodes the chunked transfer-encoded body of a raw HTTP response into its
/// plain bytes, so a test can assert byte-for-byte stream equality.
fn decodeChunkedBody(alloc: std.mem.Allocator, response: []const u8) ![]u8 {
    const head_end = std.mem.indexOf(u8, response, "\r\n\r\n") orelse return error.NoHead;
    var body = response[head_end + 4 ..];
    var out = std.ArrayList(u8).init(alloc);
    errdefer out.deinit();
    while (true) {
        const line_end = std.mem.indexOf(u8, body, "\r\n") orelse return error.BadChunk;
        var len_field = body[0..line_end];
        if (std.mem.indexOfScalar(u8, len_field, ';')) |semi| len_field = len_field[0..semi];
        const chunk_len = try std.fmt.parseInt(usize, std.mem.trim(u8, len_field, " \t"), 16);
        body = body[line_end + 2 ..];
        if (chunk_len == 0) break;
        if (body.len < chunk_len + 2) return error.BadChunk;
        try out.appendSlice(body[0..chunk_len]);
        body = body[chunk_len + 2 ..];
    }
    return out.toOwnedSlice();
}

test "exact model is captured and forwarded byte-identically to the fake upstream" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = "{\"ok\":true}",
        .headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    }});
    defer upstream.deinit();
    const listener = try startForTest(std.testing.allocator, capability, &upstream);
    defer listener.deinit();

    const model = "claude-opus-4-20250514";
    const json = "{\"model\":\"" ++ model ++ "\",\"max_tokens\":16," ++
        "\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}";
    const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, json);
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
    defer std.testing.allocator.free(response);

    try expectStatus(response, "HTTP/1.1 200 OK\r\n");
    try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\n{\"ok\":true}"));
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);

    const obs = observationSnapshot(listener);
    try std.testing.expect(obs.model_present);
    try std.testing.expect(obs.upstream_attempted);
    try std.testing.expectEqual(@as(u16, 200), obs.upstream_status);
    try std.testing.expectEqualStrings(model, obs.admittedModel());

    var captured: [256]u8 = undefined;
    const captured_len = upstream.capturedRequestBody(&captured);
    try std.testing.expectEqualStrings(json, captured[0..captured_len]);
    try std.testing.expectEqualDeep(
        fake_upstream_mod.RequestCaptureSnapshot{
            .captured_len = json.len,
            .total_len = json.len,
            .truncated = false,
        },
        upstream.requestCaptureSnapshot(),
    );
}

test "SSE response prefix reaches the client before the upstream completes" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const first = "event: message_start\ndata: {\"type\":\"message_start\"}\n\n";
    const rest =
        "event: content_block_delta\ndata: {\"delta\":{\"text\":\"hi\"}}\n\n" ++
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
    const sse = first ++ rest;
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = sse,
        .headers = &.{.{ .name = "Content-Type", .value = "text/event-stream" }},
        .chunked = true,
        .pause_after_bytes = first.len,
    }});
    defer upstream.deinit();
    const listener = try startForTest(std.testing.allocator, capability, &upstream);
    defer listener.deinit();

    const json = "{\"model\":\"claude-sonnet-4-20250514\",\"stream\":true}";
    const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, json);
    defer std.testing.allocator.free(request);

    var stream = try std.net.tcpConnectToAddress(listener.address());
    defer stream.close();
    try stream.writeAll(request);
    try waitForResponsePrefix(&upstream);
    var response = std.ArrayList(u8).init(std.testing.allocator);
    defer response.deinit();
    try readUntilContains(&stream, &response, first);

    try expectStatus(response.items, "HTTP/1.1 200 OK\r\n");
    try std.testing.expect(std.mem.indexOf(u8, response.items, "Content-Type: text/event-stream\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.items, "transfer-encoding: chunked\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.items, rest) == null);

    upstream.releasePausedResponse();
    try readResponseRemainder(&stream, &response);
    // Strict byte-for-byte reassembly: the decoded chunked body must equal the
    // whole dripped stream exactly, not merely contain its segments.
    const decoded = try decodeChunkedBody(std.testing.allocator, response.items);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualStrings(sse, decoded);
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);
}

test "truncated chunked upstream remains detectably incomplete downstream" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const first = "event: content_block_delta\ndata: {\"delta\":{\"text\":\"partial\"}}\n\n";
    const rest = "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = first ++ rest,
        .headers = &.{.{ .name = "Content-Type", .value = "text/event-stream" }},
        .chunked = true,
        .truncate_after_bytes = first.len,
    }});
    defer upstream.deinit();
    var event_buffer: [512]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try startWithUpstream(
        std.testing.allocator,
        capability,
        event_stream.writer().any(),
        .{ .fake = &upstream },
    );
    defer listener.deinit();

    const json = "{\"model\":\"claude-sonnet-4-20250514\",\"stream\":true}";
    const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, json);
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
    defer std.testing.allocator.free(response);

    try expectStatus(response, "HTTP/1.1 200 OK\r\n");
    try std.testing.expect(std.mem.indexOf(u8, response, "transfer-encoding: chunked\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, response, first) != null);
    try std.testing.expect(std.mem.indexOf(u8, response, rest) == null);
    try std.testing.expect(!std.mem.endsWith(u8, response, "0\r\n\r\n"));
    try std.testing.expect(std.mem.indexOf(
        u8,
        event_stream.getWritten(),
        "claude_proxy_upstream_interrupted",
    ) != null);
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);
}

test "truncated content-length upstream remains shorter than its downstream declaration" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const first = "partial-body";
    const rest = "-must-not-arrive";
    const body = first ++ rest;
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = body,
        .truncate_after_bytes = first.len,
    }});
    defer upstream.deinit();
    var event_buffer: [512]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try startWithUpstream(
        std.testing.allocator,
        capability,
        event_stream.writer().any(),
        .{ .fake = &upstream },
    );
    defer listener.deinit();

    const json = "{\"model\":\"claude-opus-4-20250514\"}";
    const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, json);
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
    defer std.testing.allocator.free(response);
    const expected_length = try std.fmt.allocPrint(
        std.testing.allocator,
        "content-length: {d}\r\n",
        .{body.len},
    );
    defer std.testing.allocator.free(expected_length);

    try expectStatus(response, "HTTP/1.1 200 OK\r\n");
    try std.testing.expect(std.mem.indexOf(u8, response, expected_length) != null);
    try std.testing.expect(std.mem.indexOf(u8, response, first) != null);
    try std.testing.expect(std.mem.indexOf(u8, response, rest) == null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        event_stream.getWritten(),
        "claude_proxy_upstream_interrupted",
    ) != null);
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);
}

test "listener shutdown interrupts a stalled started upstream response" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const response_body = "first chunksecond chunk";
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = response_body,
        .pause_after_bytes = "first chunk".len,
    }});
    defer upstream.deinit();
    const listener = try startForTest(std.testing.allocator, capability, &upstream);
    var listener_live = true;
    defer if (listener_live) listener.deinit();

    const json = "{\"model\":\"claude-opus-4-20250514\"}";
    const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, json);
    defer std.testing.allocator.free(request);

    var stream = try std.net.tcpConnectToAddress(listener.address());
    defer stream.close();
    try stream.writeAll(request);
    try waitForResponsePrefix(&upstream);
    var response = std.ArrayList(u8).init(std.testing.allocator);
    defer response.deinit();
    try readUntilContains(&stream, &response, "first chunk");

    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().attempt_count);

    // The fake remains paused with the upstream response open. Teardown must
    // interrupt both the downstream socket and the blocked upstream read.
    var shutdown_timer = try std.time.Timer.start();
    listener.deinit();
    listener_live = false;
    try std.testing.expect(shutdown_timer.read() < std.time.ns_per_s);
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);
}

test "client disconnect after a streamed prefix ends the single upstream attempt" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const response_body = try std.testing.allocator.alloc(u8, 4 * 1024 * 1024);
    defer std.testing.allocator.free(response_body);
    @memset(response_body, 'y');
    const prefix = "streamed-prefix";
    @memcpy(response_body[0..prefix.len], prefix);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = response_body,
        .pause_after_bytes = prefix.len,
    }});
    defer upstream.deinit();
    var event_buffer: [512]u8 = undefined;
    var event_stream = std.io.fixedBufferStream(&event_buffer);
    const listener = try startWithUpstream(
        std.testing.allocator,
        capability,
        event_stream.writer().any(),
        .{ .fake = &upstream },
    );
    defer listener.deinit();

    const json = "{\"model\":\"claude-opus-4-20250514\",\"stream\":true}";
    const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, json);
    defer std.testing.allocator.free(request);
    var stream = try std.net.tcpConnectToAddress(listener.address());
    var stream_live = true;
    defer if (stream_live) stream.close();
    try stream.writeAll(request);
    try waitForResponsePrefix(&upstream);
    var response = std.ArrayList(u8).init(std.testing.allocator);
    defer response.deinit();
    try readUntilContains(&stream, &response, prefix);

    std.posix.shutdown(stream.handle, .both) catch {};
    stream.close();
    stream_live = false;
    upstream.releasePausedResponse();
    try waitForListenerIdle(listener);

    try std.testing.expect(std.mem.indexOf(
        u8,
        event_stream.getWritten(),
        "claude_proxy_client_disconnected",
    ) != null);
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().attempt_count);
}

test "provider 5xx passes through unchanged as a single classified attempt" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);

    const Case = struct { status: std.http.Status, line: []const u8 };
    const cases = [_]Case{
        .{ .status = .internal_server_error, .line = "HTTP/1.1 500 Internal Server Error\r\n" },
        .{ .status = @enumFromInt(529), .line = "HTTP/1.1 529 " },
    };
    for (cases) |case| {
        var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
            .status = case.status,
            .body = "upstream boom",
            .headers = &.{.{ .name = "X-Trace", .value = "abc123" }},
        }});
        defer upstream.deinit();
        var event_buffer: [512]u8 = undefined;
        var event_stream = std.io.fixedBufferStream(&event_buffer);
        const listener = try startWithUpstream(
            std.testing.allocator,
            capability,
            event_stream.writer().any(),
            .{ .fake = &upstream },
        );
        defer listener.deinit();

        const json = "{\"model\":\"claude-opus-4-20250514\"}";
        const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, json);
        defer std.testing.allocator.free(request);
        const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
        defer std.testing.allocator.free(response);

        try expectStatus(response, case.line);
        try std.testing.expect(std.mem.indexOf(u8, response, "X-Trace: abc123\r\n") != null);
        try std.testing.expect(std.mem.endsWith(u8, response, "\r\n\r\nupstream boom"));
        try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);
        try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().attempt_count);
        try std.testing.expect(std.mem.indexOf(
            u8,
            event_stream.getWritten(),
            "claude_proxy_upstream_server_error",
        ) != null);

        const obs = observationSnapshot(listener);
        try std.testing.expect(obs.upstream_attempted);
        try std.testing.expectEqual(@as(u16, @intFromEnum(case.status)), obs.upstream_status);
    }
}

test "model after the former peek window is admitted from the complete bounded body" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{
        .status = .ok,
        .body = "accepted",
    }});
    defer upstream.deinit();
    const listener = try startForTest(std.testing.allocator, capability, &upstream);
    defer listener.deinit();

    const model = "claude-opus-4-20250514";
    const pad = try std.testing.allocator.alloc(u8, 64 * 1024 + 64);
    defer std.testing.allocator.free(pad);
    @memset(pad, 'a');
    const json = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"pad\":\"{s}\",\"model\":\"{s}\"}}",
        .{ pad, model },
    );
    defer std.testing.allocator.free(json);
    const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, json);
    defer std.testing.allocator.free(request);
    const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
    defer std.testing.allocator.free(response);

    try expectStatus(response, "HTTP/1.1 200 OK\r\n");
    try std.testing.expectEqual(@as(usize, 1), upstream.snapshot().call_count);

    const obs = observationSnapshot(listener);
    try std.testing.expect(obs.model_present);
    try std.testing.expect(obs.upstream_attempted);
    try std.testing.expectEqualStrings(model, obs.admittedModel());
    const capture = upstream.requestCaptureSnapshot();
    try std.testing.expectEqual(json.len, capture.total_len);
    try std.testing.expect(capture.truncated);
    try std.testing.expect(capture.captured_len < capture.total_len);
}

test "malformed ambiguous and missing model bodies refuse locally with zero upstream calls" {
    const capability = try SessionCapability.generate(std.testing.allocator);
    defer capability.deinit();
    var carrier = try copyCarrier(capability);
    defer std.crypto.secureZero(u8, &carrier);
    var upstream = try FakeUpstream.start(std.testing.allocator, &.{.{ .status = .ok, .body = "nope" }});
    defer upstream.deinit();
    const listener = try startForTest(std.testing.allocator, capability, &upstream);
    defer listener.deinit();

    // Full-document admission (program §2.2, ladder §8.2): the whole buffered
    // body must be one complete JSON object with exactly one top-level `model`
    // string, no trailing non-whitespace, and a model within the length bound.
    const overlong_model = "{\"model\":\"" ++ ("x" ** (max_model_len + 1)) ++ "\"}";
    const bodies = [_][]const u8{
        "not json at all",
        "{\"messages\":[]}",
        "{\"model\":5}",
        "{\"model\":\"\"}",
        "[]",
        overlong_model, // model exceeds the length bound
        "{\"model\":\"claude-opus-4-20250514\",\"model\":\"claude-haiku-4-20250514\"}",
        "{\"model\":\"claude-opus-4-20250514\",\"model\":\"claude-opus-4-20250514\"}",
        "{\"model\":\"claude-opus-4-20250514\"} trailing",
        "{\"model\":\"claude-opus-4-20250514\"}{\"model\":\"claude-haiku-4-20250514\"}",
    };
    for (bodies) |body| {
        const request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, body);
        defer std.testing.allocator.free(request);
        const response = try requestRawAlloc(std.testing.allocator, listener.address(), request);
        defer std.testing.allocator.free(response);
        try expectStatus(response, "HTTP/1.1 400 Bad Request\r\n");
    }

    try std.testing.expect(upstream.snapshot().isZero());
    const obs = observationSnapshot(listener);
    try std.testing.expect(obs.model_admission_rejected);
    try std.testing.expect(!obs.upstream_attempted);

    // Trailing whitespace after a complete single-model document is tolerated,
    // so a legitimate body with a trailing newline still admits and forwards.
    const trailing_ws = "{\"model\":\"claude-opus-4-20250514\"}\n\n  \t";
    const accept_request = try postRequestAlloc(std.testing.allocator, listener.port(), &carrier, trailing_ws);
    defer std.testing.allocator.free(accept_request);
    const accept_response = try requestRawAlloc(std.testing.allocator, listener.address(), accept_request);
    defer std.testing.allocator.free(accept_response);
    try expectStatus(accept_response, "HTTP/1.1 200 OK\r\n");
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
