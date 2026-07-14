const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");
const log = @import("log.zig");

pub const RefreshError = error{
    NetworkError,
    InvalidResponse,
    RefreshDenied,
    OutOfMemory,
};

pub const RefreshResult = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8 = null,
    expires_in: ?i64 = null,
};

const RefreshFailureClass = enum {
    transient_lock,
    transient_network,
    transient_store,
    transient_endpoint,
    invalid_rotating_lineage,
};

// Intentionally module-private until the flock-held refresh path can derive
// this proof from immutable attempt evidence. No caller may assert a hard
// rotating-lineage failure from endpoint bytes alone.
const RefreshLineageProof = enum {
    unproven,
    /// While holding the per-account flock, the canonical fingerprint matched
    /// the submitted refresh token and remained unchanged after the failure.
    current_rotating,
};

const RefreshEndpointFailure = struct {
    status_code: ?u16,
    response_body: []const u8,
    lineage_proof: RefreshLineageProof,
};

const RefreshFailureInput = union(enum) {
    transient_lock,
    transient_network,
    transient_store,
    endpoint: RefreshEndpointFailure,
};

const OAuthErrorResponse = struct {
    @"error": ?[]const u8 = null,
};

const max_refresh_error_body_bytes = 16 * 1024;
const max_refresh_error_value_bytes = 256;
const refresh_error_parse_scratch_bytes = 512;

/// Pure reducer for a failed refresh attempt. Endpoint bytes are parsed in
/// bounded scratch memory and the returned classification retains no response
/// data.
fn classifyRefreshFailure(input: RefreshFailureInput) RefreshFailureClass {
    return switch (input) {
        .transient_lock => .transient_lock,
        .transient_network => .transient_network,
        .transient_store => .transient_store,
        .endpoint => |failure| classifyRefreshEndpointFailure(failure),
    };
}

fn classifyRefreshEndpointFailure(failure: RefreshEndpointFailure) RefreshFailureClass {
    if (failure.status_code != 400 or failure.lineage_proof != .current_rotating) {
        return .transient_endpoint;
    }
    return if (isInvalidGrantOAuthError(failure.response_body))
        .invalid_rotating_lineage
    else
        .transient_endpoint;
}

fn isInvalidGrantOAuthError(response_body: []const u8) bool {
    if (response_body.len > max_refresh_error_body_bytes) return false;

    var scratch: [refresh_error_parse_scratch_bytes]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&scratch);
    const parsed = std.json.parseFromSliceLeaky(
        OAuthErrorResponse,
        fixed.allocator(),
        response_body,
        .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_if_needed,
            .max_value_len = max_refresh_error_value_bytes,
        },
    ) catch return false;

    const error_code = parsed.@"error" orelse return false;
    return std.mem.eql(u8, error_code, "invalid_grant");
}

// Best-effort SO_RCVTIMEO/SO_SNDTIMEO on a connected socket. winsock takes
// a DWORD of milliseconds; posix takes a timeval. Both platforms get a
// real bound; any failure is swallowed (a missing timeout must never fail
// the refresh).
fn setSocketTimeout(handle: std.posix.socket_t, seconds: u32) void {
    if (comptime builtin.os.tag == .windows) {
        const millis: u32 = seconds * 1000;
        _ = std.os.windows.ws2_32.setsockopt(handle, std.os.windows.ws2_32.SOL.SOCKET, std.os.windows.ws2_32.SO.RCVTIMEO, std.mem.asBytes(&millis), @sizeOf(u32));
        _ = std.os.windows.ws2_32.setsockopt(handle, std.os.windows.ws2_32.SOL.SOCKET, std.os.windows.ws2_32.SO.SNDTIMEO, std.mem.asBytes(&millis), @sizeOf(u32));
    } else {
        const timeout = std.posix.timeval{ .sec = @intCast(seconds), .usec = 0 };
        std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&timeout)) catch {};
        std.posix.setsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&timeout)) catch {};
    }
}

pub fn refreshToken(
    allocator: std.mem.Allocator,
    token_url: []const u8,
    refresh_token: []const u8,
    client_id: ?[]const u8,
) RefreshError!RefreshResult {
    var body_buf = std.ArrayList(u8).init(allocator);
    defer body_buf.deinit();
    const writer = body_buf.writer();
    writer.writeAll("grant_type=refresh_token&refresh_token=") catch return error.OutOfMemory;
    writeUrlEncoded(writer, refresh_token) catch return error.OutOfMemory;
    if (client_id) |cid| {
        writer.writeAll("&client_id=") catch return error.OutOfMemory;
        writeUrlEncoded(writer, cid) catch return error.OutOfMemory;
    }

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const uri = std.Uri.parse(token_url) catch return error.NetworkError;

    var header_buf: [4096]u8 = undefined;
    var req = client.open(.POST, uri, .{
        .server_header_buffer = &header_buf,
        .extra_headers = &.{
            .{ .name = "Content-Type", .value = "application/x-www-form-urlencoded" },
            .{ .name = "Accept", .value = "application/json" },
        },
    }) catch return error.NetworkError;
    defer req.deinit();

    // TIN-2074: bound the send/recv legs so a stalled connection cannot
    // wedge the caller — attemptRefresh holds the per-account repair flock
    // across this call, and the flock's blocking acquirers (adapter session
    // start, broker) have no timeout of their own. Socket-level deadlines
    // turn a post-connect stall into a NetworkError within ~30s per leg.
    // DNS/TCP-connect/TLS-handshake are bounded only by the OS TCP timeout.
    // Best-effort: a setsockopt failure must never fail the refresh.
    if (req.connection) |conn| {
        setSocketTimeout(conn.stream.handle, 30);
    }

    req.transfer_encoding = .{ .content_length = body_buf.items.len };
    req.send() catch return error.NetworkError;
    req.writeAll(body_buf.items) catch return error.NetworkError;
    req.finish() catch return error.NetworkError;
    req.wait() catch return error.NetworkError;

    if (req.response.status != .ok) {
        log.debug("oauth: refresh returned {d}", .{@intFromEnum(req.response.status)});
        return error.RefreshDenied;
    }

    var resp_buf: [16384]u8 = undefined;
    const resp_len = req.readAll(&resp_buf) catch return error.NetworkError;
    const resp_body = resp_buf[0..resp_len];

    const parsed = std.json.parseFromSlice(TokenResponse, allocator, resp_body, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.InvalidResponse;
    defer parsed.deinit();

    return .{
        .access_token = allocator.dupe(u8, parsed.value.access_token) catch return error.OutOfMemory,
        .refresh_token = if (parsed.value.refresh_token) |rt|
            (allocator.dupe(u8, rt) catch return error.OutOfMemory)
        else
            null,
        .expires_in = parsed.value.expires_in,
    };
}

const TokenResponse = struct {
    access_token: []const u8,
    token_type: ?[]const u8 = null,
    expires_in: ?i64 = null,
    refresh_token: ?[]const u8 = null,
    scope: ?[]const u8 = null,
};

// ── PKCE (RFC 7636) ──

pub const PkceChallenge = struct {
    verifier: [43]u8,
    challenge: [43]u8,
};

pub fn generatePkce() PkceChallenge {
    var verifier_bytes: [32]u8 = undefined;
    std.crypto.random.bytes(&verifier_bytes);

    var verifier: [43]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&verifier, &verifier_bytes);

    var challenge_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&verifier, &challenge_hash, .{});

    var challenge: [43]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&challenge, &challenge_hash);

    return .{ .verifier = verifier, .challenge = challenge };
}

// ── Provider-specific refresh URLs ──

pub fn refreshUrl(kind: types.ProviderKind) ?[]const u8 {
    return switch (kind) {
        .claude => "https://console.anthropic.com/v1/oauth/token",
        .codex => "https://auth.openai.com/oauth/token",
        .gemini => "https://oauth2.googleapis.com/token",
        .vercel => null, // discovered via OIDC metadata
        .github => null, // tokens don't expire
        .mcp => null, // per-server
    };
}

fn writeUrlEncoded(writer: anytype, s: []const u8) !void {
    for (s) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~') {
            try writer.writeByte(c);
        } else {
            try writer.print("%{X:0>2}", .{c});
        }
    }
}

// ── Tests ──

test "refresh failure classifier covers every class" {
    const cases = [_]struct {
        input: RefreshFailureInput,
        expected: RefreshFailureClass,
    }{
        .{ .input = .transient_lock, .expected = .transient_lock },
        .{ .input = .transient_network, .expected = .transient_network },
        .{ .input = .transient_store, .expected = .transient_store },
        .{
            .input = .{ .endpoint = .{
                .status_code = 503,
                .response_body = "Service Unavailable",
                .lineage_proof = .unproven,
            } },
            .expected = .transient_endpoint,
        },
        .{
            .input = .{ .endpoint = .{
                .status_code = 400,
                .response_body = "{\"error\":\"invalid_\\u0067rant\",\"error_description\":\"expired\",\"extension\":{\"ignored\":true}}",
                .lineage_proof = .current_rotating,
            } },
            .expected = .invalid_rotating_lineage,
        },
    };

    for (cases) |case| {
        try std.testing.expectEqual(case.expected, classifyRefreshFailure(case.input));
    }
}

test "refresh failure classifier identifies only proven invalid grant lineage" {
    const cases = [_]RefreshEndpointFailure{
        // Body substring and status text are not structured OAuth errors.
        .{ .status_code = 400, .response_body = "400 Bad Request: invalid_grant", .lineage_proof = .current_rotating },
        .{ .status_code = 400, .response_body = "{\"error_description\":\"invalid_grant\"}", .lineage_proof = .current_rotating },
        // Malformed and unknown endpoint responses remain transient.
        .{ .status_code = 400, .response_body = "{\"error\":\"invalid_grant\"", .lineage_proof = .current_rotating },
        .{ .status_code = 400, .response_body = "{\"error\":\"temporarily_unavailable\"}", .lineage_proof = .current_rotating },
        .{ .status_code = 400, .response_body = "{\"error\":{\"code\":\"invalid_grant\"}}", .lineage_proof = .current_rotating },
        // Exact invalid_grant is insufficient without both remaining proofs.
        .{ .status_code = 401, .response_body = "{\"error\":\"invalid_grant\"}", .lineage_proof = .current_rotating },
        .{ .status_code = 500, .response_body = "{\"error\":\"invalid_grant\"}", .lineage_proof = .current_rotating },
        .{ .status_code = null, .response_body = "{\"error\":\"invalid_grant\"}", .lineage_proof = .current_rotating },
        .{ .status_code = 400, .response_body = "{\"error\":\"invalid_grant\"}", .lineage_proof = .unproven },
    };

    for (cases) |case| {
        try std.testing.expectEqual(
            RefreshFailureClass.transient_endpoint,
            classifyRefreshFailure(.{ .endpoint = case }),
        );
    }
}

test "refresh failure classifier bounds endpoint parsing" {
    var oversized: [max_refresh_error_body_bytes + 1]u8 = undefined;
    @memset(&oversized, ' ');
    const prefix = "{\"error\":\"invalid_grant\"}";
    @memcpy(oversized[0..prefix.len], prefix);

    try std.testing.expectEqual(
        RefreshFailureClass.transient_endpoint,
        classifyRefreshFailure(.{ .endpoint = .{
            .status_code = 400,
            .response_body = &oversized,
            .lineage_proof = .current_rotating,
        } }),
    );
}

test "generatePkce produces valid challenge" {
    const pkce = generatePkce();
    try std.testing.expectEqual(@as(usize, 43), pkce.verifier.len);
    try std.testing.expectEqual(@as(usize, 43), pkce.challenge.len);

    // Verify S256: challenge = base64url(sha256(verifier))
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&pkce.verifier, &hash, .{});
    var expected: [43]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&expected, &hash);
    try std.testing.expectEqualSlices(u8, &expected, &pkce.challenge);
}

test "writeUrlEncoded" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeUrlEncoded(fbs.writer(), "hello world&foo=bar");
    try std.testing.expectEqualStrings("hello%20world%26foo%3Dbar", fbs.getWritten());
}

test "refreshUrl returns expected endpoints" {
    try std.testing.expectEqualStrings(
        "https://console.anthropic.com/v1/oauth/token",
        refreshUrl(.claude).?,
    );
    try std.testing.expectEqualStrings(
        "https://auth.openai.com/oauth/token",
        refreshUrl(.codex).?,
    );
    try std.testing.expect(refreshUrl(.github) == null);
}

test "refreshUrl(.claude) stays consistent with claude_def token endpoint" {
    // TIN-1817: both constants must point at the same verified endpoint so the
    // schema and the refresh path can never drift apart. Constants only — no
    // live HTTP.
    const provider_schema = @import("provider_schema.zig");
    try std.testing.expectEqualStrings(
        provider_schema.claude_def.auth.token_endpoint.?,
        refreshUrl(.claude).?,
    );
}
