//! Owned bounded loopback OAuth callback receiver. Never a browser/control
//! credential import route. A genuine opaque registration profile is required
//! before socket IO; the current production profile constructor is absent.
const std = @import("std");
const builtin = @import("builtin");
const c = @import("c");
const authority = @import("oauth_issue_authority.zig");
const enrollment = @import("oauth_enrollment.zig");
const envelope = @import("envelope.zig");
pub const max_receivers = 4;
pub const max_frame = 16 * 1024;
const max_rejections = 4;
pub const Captured = struct {
    binding: enrollment.Binding,
    state: [32]u8,
    code: envelope.Secret,
    client_id: envelope.Secret,
    denied: bool = false,
    pub fn deinit(self: *Captured) void {
        self.code.deinit();
        self.client_id.deinit();
        std.crypto.secureZero(u8, &self.state);
        self.* = undefined;
    }
};
const Data = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    profile: *authority.EnrollmentProfile,
    attempt: enrollment.Attempt,
    listener: c_int,
    peer: c_int = -1,
    frame: [max_frame]u8 = @splat(0),
    length: usize = 0,
    rejected: usize = 0,
    captured: bool = false,
    host: [64]u8 = @splat(0),
    host_len: usize,
};
pub const Acknowledgment = enum { recorded, refused };
const ReservationData = struct { allocator: std.mem.Allocator, io: std.Io, until: std.Io.Clock.Timestamp, fd: c_int, port: u16 };
pub const ListenerReservation = opaque {
    pub fn port(self: *ListenerReservation) u16 {
        return reserved(self).port;
    }
    pub fn deinit(self: *ListenerReservation) void {
        const data = reserved(self);
        if (data.fd >= 0) _ = c.close(data.fd);
        data.allocator.destroy(data);
    }
    pub fn take(self: *ListenerReservation, profile: *authority.EnrollmentProfile, attempt: enrollment.Attempt) !*Receiver {
        const data = reserved(self);
        try profile.requireAvailable();
        if (data.fd < 0 or !std.meta.eql(data.until, attempt.until) or try authority.loopbackPort(profile.view().exact_redirect_uri) != data.port or !std.meta.eql(attempt.binding.registration_profile_sha256, @as(?[32]u8, profile.view().sha256))) return error.CallbackAuthorityChanged;
        var actual = std.mem.zeroes(c.struct_sockaddr_in);
        var length: c.socklen_t = @sizeOf(c.struct_sockaddr_in);
        if (c.getsockname(data.fd, @ptrCast(&actual), &length) != 0 or length != @sizeOf(c.struct_sockaddr_in) or actual.sin_family != c.AF_INET or actual.sin_addr.s_addr != c.htonl(0x7f000001) or c.ntohs(actual.sin_port) != data.port) return error.CallbackAuthorityChanged;
        const owner = try data.allocator.create(Data);
        owner.* = .{ .allocator = data.allocator, .io = data.io, .profile = profile, .attempt = attempt, .listener = data.fd, .host_len = 0 };
        errdefer {
            owner.attempt.deinit();
            data.allocator.destroy(owner);
        }
        const host = try std.fmt.allocPrint(data.allocator, "127.0.0.1:{d}", .{data.port});
        defer data.allocator.free(host);
        owner.* = .{ .allocator = data.allocator, .io = data.io, .profile = profile, .attempt = attempt, .listener = data.fd, .host_len = host.len };
        @memcpy(owner.host[0..host.len], host);
        try check(owner);
        profile.retain();
        data.fd = -1;
        return @ptrCast(owner);
    }
};
fn reserved(self: *ListenerReservation) *ReservationData {
    return @ptrCast(@alignCast(self));
}
/// Called only after actor-owned explicit SIWC consent, wrapping-key and
/// capacity admission. Kernel-selected loopback port remains continuously held
/// until take(); no free-port probing, name substitution or fallback is used.
pub fn reserveDocumentedLoopback(io: std.Io, a: std.mem.Allocator, until: std.Io.Clock.Timestamp) !*ListenerReservation {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.UnsupportedPlatform;
    if (until.clock != .awake or until.durationFromNow(io).raw.toNanoseconds() <= 0 or until.durationFromNow(io).raw.toNanoseconds() > 3_600_000_000_000) return error.CallbackExpired;
    const fd = c.socket(c.AF_INET, c.SOCK_STREAM, 0);
    if (fd < 0) return error.CallbackSocket;
    errdefer _ = c.close(fd);
    try nonblocking(fd);
    var address = std.mem.zeroes(c.struct_sockaddr_in);
    address.sin_family = c.AF_INET;
    address.sin_addr.s_addr = c.htonl(0x7f000001);
    if (@hasField(c.struct_sockaddr_in, "sin_len")) address.sin_len = @sizeOf(c.struct_sockaddr_in);
    if (c.bind(fd, @ptrCast(&address), @sizeOf(c.struct_sockaddr_in)) != 0 or c.listen(fd, 1) != 0) return error.CallbackSocket;
    var length: c.socklen_t = @sizeOf(c.struct_sockaddr_in);
    if (c.getsockname(fd, @ptrCast(&address), &length) != 0 or length != @sizeOf(c.struct_sockaddr_in) or address.sin_addr.s_addr != c.htonl(0x7f000001) or c.ntohs(address.sin_port) == 0) return error.CallbackSocket;
    if (until.durationFromNow(io).raw.toNanoseconds() <= 0) return error.CallbackExpired;
    const data = try a.create(ReservationData);
    data.* = .{ .allocator = a, .io = io, .until = until, .fd = fd, .port = c.ntohs(address.sin_port) };
    return @ptrCast(data);
}
pub const Receiver = opaque {
    /// One nonblocking accept/read per actor poll; no worker holds the SQLite
    /// lock while waiting for a browser. Four receivers and four rejections per
    /// original cutoff bound all sockets, buffers and read work.
    pub fn poll(self: *Receiver) !?Captured {
        const data = get(self);
        try check(data);
        if (data.captured) return null;
        if (data.rejected >= max_rejections) return error.CallbackBudgetExhausted;
        if (data.peer < 0) {
            var peer_address = std.mem.zeroes(c.struct_sockaddr_in);
            var length: c.socklen_t = @sizeOf(c.struct_sockaddr_in);
            const fd = c.accept(data.listener, @ptrCast(&peer_address), &length);
            if (fd < 0) return switch (std.posix.errno(fd)) {
                .AGAIN, .INTR => null,
                else => error.CallbackSocket,
            };
            errdefer _ = c.close(fd);
            if (length != @sizeOf(c.struct_sockaddr_in) or peer_address.sin_family != c.AF_INET or peer_address.sin_addr.s_addr != c.htonl(0x7f000001)) return error.CallbackPeer;
            try nonblocking(fd);
            data.peer = fd;
        }
        const received = c.recv(data.peer, data.frame[data.length..].ptr, data.frame.len - data.length, 0);
        if (received < 0) return switch (std.posix.errno(received)) {
            .AGAIN, .INTR => null,
            else => error.CallbackSocket,
        };
        if (received == 0) {
            refuse(data);
            return null;
        }
        data.length += @intCast(received);
        const end = std.mem.indexOf(u8, data.frame[0..data.length], "\r\n\r\n") orelse {
            if (data.length == data.frame.len) refuse(data);
            return null;
        };
        try check(data);
        if (end + 4 != data.length) {
            refuse(data);
            return null;
        }
        var captured = decode(data) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => {
                refuse(data);
                return null;
            },
        };
        errdefer captured.deinit();
        try check(data);
        data.captured = true;
        // Peer remains owned until actor durable callback commit determines its
        // static redacted reply. Captured raw input is wiped immediately.
        std.crypto.secureZero(u8, &data.frame);
        data.length = 0;
        return captured;
    }
    pub fn acknowledge(self: *Receiver, disposition: Acknowledgment) void {
        const data = get(self);
        if (data.peer >= 0) {
            const response = if (disposition == .recorded) "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n" else "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\nCache-Control: no-store\r\n\r\n";
            _ = c.send(data.peer, response.ptr, response.len, if (@hasDecl(c, "MSG_NOSIGNAL")) c.MSG_NOSIGNAL else 0);
            _ = c.close(data.peer);
            data.peer = -1;
        }
    }
    pub fn deinit(self: *Receiver) void {
        const data = get(self);
        if (data.peer >= 0) _ = c.close(data.peer);
        _ = c.close(data.listener);
        data.profile.deinit();
        data.attempt.deinit();
        std.crypto.secureZero(u8, &data.frame);
        data.allocator.destroy(data);
    }
};
fn get(self: *Receiver) *Data {
    return @ptrCast(@alignCast(self));
}
/// No native-home fallback, arbitrary URL, wildcard binding or port retry.
/// A missing/unqualified profile refuses BEFORE allocating/opening a socket.
pub fn open(io: std.Io, a: std.mem.Allocator, profile: ?*authority.EnrollmentProfile, attempt: enrollment.Attempt) !*Receiver {
    const qualified = profile orelse return error.RegistrationProfileUnavailable;
    try qualified.requireAvailable();
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.UnsupportedCallbackPlatform;
    enrollment.checkFlow(io, attempt) catch return error.CallbackExpired;
    if (std.Io.Clock.real.now(io).toSeconds() >= attempt.binding.consent_expires_at) return error.CallbackExpired;
    const uri = qualified.view().exact_redirect_uri;
    const prefix = "http://127.0.0.1:";
    if (!std.mem.startsWith(u8, uri, prefix)) return error.UnsupportedCallbackRedirect;
    const path_at = std.mem.indexOfScalarPos(u8, uri, prefix.len, '/') orelse return error.UnsupportedCallbackRedirect;
    const port_text = uri[prefix.len..path_at];
    const port = std.fmt.parseInt(u16, port_text, 10) catch return error.UnsupportedCallbackRedirect;
    if (port == 0 or port_text.len == 0 or port_text[0] == '0' or !std.mem.eql(u8, uri[path_at..], "/auth/callback")) return error.UnsupportedCallbackRedirect;
    if (!std.mem.eql(u8, attempt.binding.redirect(), uri) or attempt.binding.registration_profile_sha256 == null or !std.crypto.timing_safe.eql([32]u8, attempt.binding.registration_profile_sha256.?, qualified.view().sha256)) return error.CallbackAuthorityChanged;
    const fd = c.socket(c.AF_INET, c.SOCK_STREAM, 0);
    if (fd < 0) return error.CallbackSocket;
    errdefer _ = c.close(fd);
    try nonblocking(fd);
    var address = std.mem.zeroes(c.struct_sockaddr_in);
    address.sin_family = c.AF_INET;
    address.sin_addr.s_addr = c.htonl(0x7f000001);
    address.sin_port = c.htons(port);
    if (@hasField(c.struct_sockaddr_in, "sin_len")) address.sin_len = @sizeOf(c.struct_sockaddr_in);
    if (c.bind(fd, @ptrCast(&address), @sizeOf(c.struct_sockaddr_in)) != 0 or c.listen(fd, 1) != 0) return error.CallbackSocket;
    const data = try a.create(Data);
    errdefer a.destroy(data);
    const host = uri["http://".len..path_at];
    if (host.len > 64) return error.UnsupportedCallbackRedirect;
    data.* = .{ .allocator = a, .io = io, .profile = qualified, .attempt = attempt, .listener = fd, .host_len = host.len };
    @memcpy(data.host[0..host.len], host);
    errdefer std.crypto.secureZero(u8, &data.attempt.callback_state);
    try check(data);
    qualified.retain();
    return @ptrCast(data);
}
fn nonblocking(fd: c_int) !void {
    const flags = c.fcntl(fd, c.F_GETFL);
    if (flags < 0 or c.fcntl(fd, c.F_SETFL, flags | c.O_NONBLOCK) != 0 or c.fcntl(fd, c.F_SETFD, c.FD_CLOEXEC) != 0) return error.CallbackSocket;
    if (@hasDecl(c, "SO_NOSIGPIPE")) {
        const enabled: c_int = 1;
        if (c.setsockopt(fd, c.SOL_SOCKET, c.SO_NOSIGPIPE, &enabled, @sizeOf(c_int)) != 0) return error.CallbackSocket;
    }
}
fn check(data: *Data) !void {
    enrollment.checkFlow(data.io, data.attempt) catch return error.CallbackExpired;
    if (std.Io.Clock.real.now(data.io).toSeconds() >= data.attempt.binding.consent_expires_at) return error.CallbackExpired;
}
fn refuse(data: *Data) void {
    if (data.peer >= 0) _ = c.close(data.peer);
    data.peer = -1;
    std.crypto.secureZero(u8, &data.frame);
    data.length = 0;
    data.rejected += 1;
}
fn decode(data: *Data) !Captured {
    var lines = std.mem.splitSequence(u8, data.frame[0..data.length], "\r\n");
    const request = lines.next() orelse return error.InvalidCallbackFrame;
    if (!std.mem.startsWith(u8, request, "GET ") or !std.mem.endsWith(u8, request, " HTTP/1.1")) return error.InvalidCallbackFrame;
    const target = request[4 .. request.len - " HTTP/1.1".len];
    const prefix = "/auth/callback?";
    if (!std.mem.startsWith(u8, target, prefix)) return error.InvalidCallbackFrame;
    var host_seen = false;
    var headers: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) break;
        headers += 1;
        if (headers > 16 or line.len > 512 or line[0] == ' ' or line[0] == '\t') return error.InvalidCallbackFrame;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.InvalidCallbackFrame;
        if (colon == 0) return error.InvalidCallbackFrame;
        const name = line[0..colon];
        for (name) |byte| if (!std.ascii.isAlphabetic(byte) and byte != '-') return error.InvalidCallbackFrame;
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        for (value) |byte| if (byte < 0x20 or byte > 0x7e) return error.InvalidCallbackFrame;
        if (std.ascii.eqlIgnoreCase(name, "Host")) {
            if (host_seen or !std.mem.eql(u8, value, data.host[0..data.host_len])) return error.InvalidCallbackFrame;
            host_seen = true;
        } else if (std.ascii.eqlIgnoreCase(name, "Transfer-Encoding") or std.ascii.eqlIgnoreCase(name, "Authorization") or std.ascii.eqlIgnoreCase(name, "Cookie")) return error.InvalidCallbackFrame else if (std.ascii.eqlIgnoreCase(name, "Content-Length") and !std.mem.eql(u8, value, "0")) return error.InvalidCallbackFrame;
    }
    if (!host_seen) return error.InvalidCallbackFrame;
    var state_text: ?[]const u8 = null;
    var code_text: ?[]const u8 = null;
    var client_text: ?[]const u8 = null;
    var scope_text: ?[]const u8 = null;
    var error_text: ?[]const u8 = null;
    var fields = std.mem.splitScalar(u8, target[prefix.len..], '&');
    while (fields.next()) |field| {
        const equals = std.mem.indexOfScalar(u8, field, '=') orelse return error.InvalidCallbackFrame;
        const name = field[0..equals];
        const value = field[equals + 1 ..];
        if (std.mem.eql(u8, name, "state")) {
            if (state_text != null) return error.InvalidCallbackFrame;
            state_text = value;
        } else if (std.mem.eql(u8, name, "code")) {
            if (code_text != null) return error.InvalidCallbackFrame;
            code_text = value;
        } else if (std.mem.eql(u8, name, "client_id")) {
            if (client_text != null) return error.InvalidCallbackFrame;
            client_text = value;
        } else if (std.mem.eql(u8, name, "scope")) {
            if (scope_text != null) return error.InvalidCallbackFrame;
            scope_text = value;
        } else if (std.mem.eql(u8, name, "error")) {
            if (error_text != null) return error.InvalidCallbackFrame;
            error_text = value;
        } else return error.InvalidCallbackFrame;
    }
    const state = state_text orelse return error.InvalidCallbackFrame;
    if (state.len != 43) return error.InvalidCallbackFrame;
    var decoded_state: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &decoded_state);
    std.base64.url_safe_no_pad.Decoder.decode(&decoded_state, state) catch return error.InvalidCallbackFrame;
    var canonical: [43]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&canonical, &decoded_state);
    if (!std.mem.eql(u8, &canonical, state) or !std.crypto.timing_safe.eql([32]u8, decoded_state, data.attempt.callback_state)) return error.InvalidCallbackFrame;
    if (error_text) |denied| {
        if (!std.mem.eql(u8, denied, "access_denied") or code_text != null or client_text != null or scope_text != null) return error.InvalidCallbackFrame;
        return .{ .binding = data.attempt.binding, .state = decoded_state, .code = .{ .allocator = data.allocator, .bytes = &.{} }, .client_id = .{ .allocator = data.allocator, .bytes = &.{} }, .denied = true };
    }
    var client: [256]u8 = undefined;
    defer std.crypto.secureZero(u8, &client);
    const client_len = try decodeQuery(client_text orelse return error.InvalidCallbackFrame, &client, false);
    if (!enrollment.validIssuedClient(client[0..client_len])) return error.InvalidCallbackFrame;
    if (scope_text) |scope| {
        // Callback scope is bounded diagnostic input, never a granted-scope
        // predicate. Only verified token evidence can establish permissions.
        var decoded_scope: [2048]u8 = undefined;
        defer std.crypto.secureZero(u8, &decoded_scope);
        _ = try decodeQuery(scope, &decoded_scope, true);
    }
    const encoded_code = code_text orelse return error.InvalidCallbackFrame;
    var code: [enrollment.max_code_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &code);
    const count = try decodeQuery(encoded_code, &code, false);
    const owned_code = try data.allocator.dupe(u8, code[0..count]);
    errdefer {
        std.crypto.secureZero(u8, owned_code);
        data.allocator.free(owned_code);
    }
    return .{ .binding = data.attempt.binding, .state = decoded_state, .code = .{ .allocator = data.allocator, .bytes = owned_code }, .client_id = .{ .allocator = data.allocator, .bytes = try data.allocator.dupe(u8, client[0..client_len]) } };
}
fn decodeQuery(encoded_code: []const u8, code: []u8, allow_space: bool) !usize {
    var count: usize = 0;
    var index: usize = 0;
    while (index < encoded_code.len) {
        if (count == code.len) return error.InvalidCallbackFrame;
        const byte = encoded_code[index];
        if (byte == '%') {
            if (encoded_code.len - index < 3) return error.InvalidCallbackFrame;
            const hi = hex(encoded_code[index + 1]) catch return error.InvalidCallbackFrame;
            const lo = hex(encoded_code[index + 2]) catch return error.InvalidCallbackFrame;
            code[count] = (hi << 4) | lo;
            index += 3;
        } else {
            code[count] = if (byte == '+') ' ' else byte;
            index += 1;
        }
        if (code[count] < (if (allow_space) @as(u8, 0x20) else 0x21) or code[count] > 0x7e) return error.InvalidCallbackFrame;
        count += 1;
    }
    if (count == 0) return error.InvalidCallbackFrame;
    return count;
}

fn hex(byte: u8) !u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => error.InvalidCallbackFrame,
    };
}

const Model = struct {
    allocator: std.mem.Allocator,
    receiver: *Receiver,
    ledger: enrollment.Ledger,
    profile: *authority.EnrollmentProfile,
    port: u16,
    state: [43]u8,
    fn create(a: std.mem.Allocator) !Model {
        // Hold the actual reservation socket throughout fixture construction;
        // no close/rebind free-port race is treated as owned binding.
        const fd = c.socket(c.AF_INET, c.SOCK_STREAM, 0);
        if (fd < 0) return error.CallbackSocket;
        errdefer _ = c.close(fd);
        try nonblocking(fd);
        var address = std.mem.zeroes(c.struct_sockaddr_in);
        address.sin_family = c.AF_INET;
        address.sin_addr.s_addr = c.htonl(0x7f000001);
        address.sin_port = 0;
        if (@hasField(c.struct_sockaddr_in, "sin_len")) address.sin_len = @sizeOf(c.struct_sockaddr_in);
        if (c.bind(fd, @ptrCast(&address), @sizeOf(c.struct_sockaddr_in)) != 0 or c.listen(fd, 1) != 0) return error.CallbackSocket;
        var length: c.socklen_t = @sizeOf(c.struct_sockaddr_in);
        if (c.getsockname(fd, @ptrCast(&address), &length) != 0 or length != @sizeOf(c.struct_sockaddr_in) or address.sin_addr.s_addr != c.htonl(0x7f000001)) return error.CallbackSocket;
        const port = c.ntohs(address.sin_port);
        const uri = try std.fmt.allocPrint(a, "http://127.0.0.1:{d}/auth/callback", .{port});
        defer a.free(uri);
        const profile = try authority.testing.profile(a, port, uri);
        errdefer profile.deinit();
        var ledger: enrollment.Ledger = .{};
        errdefer ledger.deinit(a);
        const key: envelope.Key = @splat(0x39);
        var original = try ledger.prepare(std.testing.io, a, key, "fixture-callback-root", 0, std.Io.Clock.real.now(std.testing.io).toSeconds(), 60, .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(5) }));
        defer original.deinit();
        var bound = try ledger.bindForIssue(std.testing.io, a, key, "fixture-callback-root", original, "fixture-callback-operation", profile.view().sha256, uri, profile.view().host_id);
        defer bound.deinit();
        var encoded_state: [43]u8 = undefined;
        _ = std.base64.url_safe_no_pad.Encoder.encode(&encoded_state, &bound.callback_state);
        const data = try a.create(Data);
        errdefer a.destroy(data);
        const host = try std.fmt.allocPrint(a, "127.0.0.1:{d}", .{port});
        defer a.free(host);
        data.* = .{ .allocator = a, .io = std.testing.io, .profile = profile, .attempt = bound, .listener = fd, .host_len = host.len };
        @memcpy(data.host[0..host.len], host);
        profile.retain();
        return .{ .allocator = a, .receiver = @ptrCast(data), .ledger = ledger, .profile = profile, .port = port, .state = encoded_state };
    }
    fn connect(self: *Model, payload: []const u8) !c_int {
        const fd = c.socket(c.AF_INET, c.SOCK_STREAM, 0);
        if (fd < 0) return error.CallbackSocket;
        errdefer _ = c.close(fd);
        var address = std.mem.zeroes(c.struct_sockaddr_in);
        address.sin_family = c.AF_INET;
        address.sin_addr.s_addr = c.htonl(0x7f000001);
        address.sin_port = c.htons(self.port);
        if (@hasField(c.struct_sockaddr_in, "sin_len")) address.sin_len = @sizeOf(c.struct_sockaddr_in);
        if (c.connect(fd, @ptrCast(&address), @sizeOf(c.struct_sockaddr_in)) != 0) return error.CallbackSocket;
        if (c.send(fd, payload.ptr, payload.len, if (@hasDecl(c, "MSG_NOSIGNAL")) c.MSG_NOSIGNAL else 0) != payload.len) return error.CallbackSocket;
        return fd;
    }
    fn deinit(self: *Model) void {
        self.receiver.deinit();
        self.profile.deinit();
        self.ledger.deinit(self.allocator);
        std.crypto.secureZero(u8, &self.state);
    }
};

test "real owned loopback callback captures once and waits for durable actor disposition" {
    const a = std.testing.allocator;
    var model = try Model.create(a);
    defer model.deinit();
    const request = try std.fmt.allocPrint(a, "GET /auth/callback?state={s}&code=synthetic-callback-code&client_id=omux-fixture-client HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\n\r\n", .{ model.state, model.port });
    defer wipe(a, request);
    const client = try model.connect(request);
    defer _ = c.close(client);
    var captured: ?Captured = null;
    const until: std.Io.Clock.Timestamp = .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) });
    while (captured == null and until.durationFromNow(std.testing.io).raw.toNanoseconds() > 0) {
        captured = try model.receiver.poll();
        if (captured == null) try std.testing.io.sleep(.fromMilliseconds(1), .awake);
    }
    var callback = captured orelse return error.CallbackModelTimeout;
    defer callback.deinit();
    try std.testing.expectEqualSlices(u8, "synthetic-callback-code", callback.code.bytes);
    try std.testing.expectEqual(enrollment.Phase.prepared, model.ledger.records.items[0].phase);
    var readiness: c.struct_pollfd = .{ .fd = client, .events = c.POLLIN, .revents = 0 };
    try std.testing.expectEqual(@as(c_int, 0), c.poll(&readiness, 1, 0));
    try std.testing.expect((try model.receiver.poll()) == null);
    model.receiver.acknowledge(.recorded);
    try std.testing.expect(c.poll(&readiness, 1, 100) > 0);
}

test "wrong host duplicate state and expired consent cannot yield a callback" {
    const a = std.testing.allocator;
    var model = try Model.create(a);
    defer model.deinit();
    const foreign = try std.fmt.allocPrint(a, "GET /auth/callback?state={s}&code=synthetic&client_id=synthetic-issued-client HTTP/1.1\r\nHost: foreign.invalid\r\n\r\n", .{model.state});
    defer wipe(a, foreign);
    const duplicate = try std.fmt.allocPrint(a, "GET /auth/callback?state={s}&state={s}&code=synthetic&client_id=synthetic-issued-client HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\n\r\n", .{ model.state, model.state, model.port });
    defer wipe(a, duplicate);
    var wrong_state = model.state;
    wrong_state[0] = if (wrong_state[0] == 'A') 'B' else 'A';
    const wrong = try std.fmt.allocPrint(a, "GET /auth/callback?state={s}&code=synthetic&client_id=synthetic-issued-client HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\n\r\n", .{ wrong_state, model.port });
    defer wipe(a, wrong);
    const missing_client = try std.fmt.allocPrint(a, "GET /auth/callback?state={s}&code=synthetic HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\n\r\n", .{ model.state, model.port });
    defer wipe(a, missing_client);
    const requests = [_][]const u8{ foreign, duplicate, wrong, missing_client };
    for (requests) |request| {
        const client = try model.connect(request);
        defer _ = c.close(client);
        const before = get(model.receiver).rejected;
        const until: std.Io.Clock.Timestamp = .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) });
        while (get(model.receiver).rejected == before and until.durationFromNow(std.testing.io).raw.toNanoseconds() > 0) {
            try std.testing.expect((try model.receiver.poll()) == null);
            try std.testing.io.sleep(.fromMilliseconds(1), .awake);
        }
        try std.testing.expectEqual(before + 1, get(model.receiver).rejected);
    }
    get(model.receiver).attempt.binding.consent_expires_at = std.Io.Clock.real.now(std.testing.io).toSeconds();
    try std.testing.expectError(error.CallbackExpired, model.receiver.poll());
    try std.testing.expectEqual(enrollment.Phase.prepared, model.ledger.records.items[0].phase);
    try std.testing.expectEqual(@as(usize, 0), model.ledger.records.items[0].callback_capsule.len);
}
fn wipe(a: std.mem.Allocator, bytes: []u8) void {
    std.crypto.secureZero(u8, bytes);
    a.free(bytes);
}
