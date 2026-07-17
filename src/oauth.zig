const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");
const log = @import("log.zig");

pub const RefreshError = error{
    NetworkError,
    InvalidResponse,
    RefreshDenied,
    BoundaryPersistenceFailed,
    OutOfMemory,
};

pub const RefreshResult = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8 = null,
    expires_in: ?i64 = null,
};

/// Redacted, provisional evidence from a non-2xx token endpoint response.
/// Neither tag is authoritative lineage proof. In particular,
/// `structured_invalid_grant` must be combined with flock ownership and a
/// locked canonical-store recheck by the pipeline before it can become
/// `RefreshOutcome.hard_lineage_invalidated`.
pub const RefreshEndpointFailure = enum {
    unproven,
    structured_invalid_grant,
    indeterminate_success,
};

pub const RefreshAttempt = union(enum) {
    refreshed: RefreshResult,
    endpoint_failure: RefreshEndpointFailure,
};

pub const RefreshBoundary = struct {
    ctx: *anyopaque,
    before_send: *const fn (ctx: *anyopaque) RefreshError!void,
};

const OAuthErrorResponse = struct {
    @"error": ?[]const u8 = null,
};

const max_refresh_error_body_bytes = 16 * 1024;
const max_refresh_error_value_bytes = 256;
const refresh_error_parse_scratch_bytes = 512;

/// Classify bounded endpoint bytes into provisional evidence. A buffer filled
/// to the read limit is conservatively treated as oversized/truncated because
/// no byte beyond the existing 16 KiB cap is read to disambiguate it.
fn classifyRefreshEndpointFailure(
    status_code: u16,
    response_body: []const u8,
    body_limit_reached: bool,
) RefreshEndpointFailure {
    if (status_code != 400 or body_limit_reached) return .unproven;
    return if (isInvalidGrantOAuthError(response_body))
        .structured_invalid_grant
    else
        .unproven;
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
) RefreshError!RefreshAttempt {
    return refreshTokenWithBoundary(
        allocator,
        token_url,
        refresh_token,
        client_id,
        null,
    );
}

/// Execute a token refresh with an optional durable boundary hook. The hook is
/// invoked after URI/connection setup but immediately before request bytes can
/// be sent. Callers use it to persist redacted indeterminate-lineage state; a
/// hook failure aborts before the endpoint request.
pub fn refreshTokenWithBoundary(
    allocator: std.mem.Allocator,
    token_url: []const u8,
    refresh_token: []const u8,
    client_id: ?[]const u8,
    boundary: ?RefreshBoundary,
) RefreshError!RefreshAttempt {
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

    if (boundary) |b| try b.before_send(b.ctx);

    req.transfer_encoding = .{ .content_length = body_buf.items.len };
    req.send() catch return error.NetworkError;
    req.writeAll(body_buf.items) catch return error.NetworkError;
    req.finish() catch return error.NetworkError;
    req.wait() catch return error.NetworkError;

    var resp_buf: [max_refresh_error_body_bytes]u8 = undefined;
    const resp_len = req.readAll(&resp_buf) catch return error.NetworkError;
    const resp_body = resp_buf[0..resp_len];
    const status_code: u16 = @intCast(@intFromEnum(req.response.status));

    return parseRefreshResponse(
        allocator,
        status_code,
        resp_body,
        resp_len == resp_buf.len,
    );
}

fn parseRefreshResponse(
    allocator: std.mem.Allocator,
    status_code: u16,
    resp_body: []const u8,
    body_limit_reached: bool,
) RefreshError!RefreshAttempt {
    // The 16 KiB cap applies to every response, including HTTP 200. A valid
    // JSON prefix in a full buffer is not proof that the unread suffix is
    // absent, so it must never mint or rotate credentials.
    if (body_limit_reached) {
        return .{ .endpoint_failure = if (status_code == 200)
            .indeterminate_success
        else
            .unproven };
    }
    if (status_code != 200) {
        log.debug("oauth: refresh returned {d}", .{status_code});
        return .{ .endpoint_failure = classifyRefreshEndpointFailure(
            status_code,
            resp_body,
            false,
        ) };
    }

    const parsed = std.json.parseFromSlice(TokenResponse, allocator, resp_body, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    }) catch return error.InvalidResponse;
    defer parsed.deinit();

    const access_token = allocator.dupe(u8, parsed.value.access_token) catch return error.OutOfMemory;
    errdefer allocator.free(access_token);
    const rotated_refresh_token = if (parsed.value.refresh_token) |rt|
        (allocator.dupe(u8, rt) catch return error.OutOfMemory)
    else
        null;

    return .{ .refreshed = .{
        .access_token = access_token,
        .refresh_token = rotated_refresh_token,
        .expires_in = parsed.value.expires_in,
    } };
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

test "refresh endpoint classifier covers every provisional tag" {
    const cases = [_]struct {
        status: u16,
        body: []const u8,
        limit_reached: bool = false,
        expected: RefreshEndpointFailure,
    }{
        .{
            .status = 503,
            .body = "Service Unavailable",
            .expected = .unproven,
        },
        .{
            .status = 400,
            .body = "{\"error\":\"invalid_\\u0067rant\",\"error_description\":\"expired\",\"extension\":{\"ignored\":true}}",
            .expected = .structured_invalid_grant,
        },
    };

    for (cases) |case| {
        try std.testing.expectEqual(
            case.expected,
            classifyRefreshEndpointFailure(case.status, case.body, case.limit_reached),
        );
    }
}

test "refresh endpoint bytes alone never establish hard lineage" {
    const cases = [_]struct {
        status: u16,
        body: []const u8,
    }{
        // Body substring and status text are not structured OAuth errors.
        .{ .status = 400, .body = "400 Bad Request: invalid_grant" },
        .{ .status = 400, .body = "{\"error_description\":\"invalid_grant\"}" },
        // Malformed and unknown endpoint responses remain transient.
        .{ .status = 400, .body = "{\"error\":\"invalid_grant\"" },
        .{ .status = 400, .body = "{\"error\":\"temporarily_unavailable\"}" },
        .{ .status = 400, .body = "{\"error\":{\"code\":\"invalid_grant\"}}" },
        // Exact invalid_grant on 429/5xx remains unproven.
        .{ .status = 429, .body = "{\"error\":\"invalid_grant\"}" },
        .{ .status = 500, .body = "{\"error\":\"invalid_grant\"}" },
    };

    for (cases) |case| {
        try std.testing.expectEqual(
            RefreshEndpointFailure.unproven,
            classifyRefreshEndpointFailure(case.status, case.body, false),
        );
    }
}

test "refresh endpoint classifier treats the 16 KiB read boundary as unproven" {
    var oversized: [max_refresh_error_body_bytes + 1]u8 = undefined;
    @memset(&oversized, ' ');
    const prefix = "{\"error\":\"invalid_grant\"}";
    @memcpy(oversized[0..prefix.len], prefix);

    try std.testing.expectEqual(
        RefreshEndpointFailure.unproven,
        classifyRefreshEndpointFailure(400, oversized[0..max_refresh_error_body_bytes], true),
    );
    try std.testing.expectEqual(
        RefreshEndpointFailure.unproven,
        classifyRefreshEndpointFailure(400, &oversized, false),
    );
}

test "oversized HTTP 200 with a valid JSON prefix is indeterminate success" {
    var truncated: [max_refresh_error_body_bytes]u8 = undefined;
    @memset(&truncated, ' ');
    const valid_prefix = "{\"access_token\":\"must-not-be-adopted\"}";
    @memcpy(truncated[0..valid_prefix.len], valid_prefix);

    const attempt = try parseRefreshResponse(
        std.testing.allocator,
        200,
        &truncated,
        true,
    );
    try std.testing.expectEqual(
        RefreshEndpointFailure.indeterminate_success,
        attempt.endpoint_failure,
    );
}

test "short HTTP 200 response still returns refreshed credentials" {
    const attempt = try parseRefreshResponse(
        std.testing.allocator,
        200,
        "{\"access_token\":\"at\",\"refresh_token\":\"rt\",\"expires_in\":60}",
        false,
    );
    const result = attempt.refreshed;
    defer std.testing.allocator.free(result.access_token);
    defer if (result.refresh_token) |refresh_token| {
        std.testing.allocator.free(refresh_token);
    };
    try std.testing.expectEqualStrings("at", result.access_token);
    try std.testing.expectEqualStrings("rt", result.refresh_token.?);
    try std.testing.expectEqual(@as(?i64, 60), result.expires_in);
}

test "successful OAuth response may omit a refresh token" {
    const attempt = try parseRefreshResponse(
        std.testing.allocator,
        200,
        "{\"access_token\":\"at\",\"expires_in\":60}",
        false,
    );
    const result = attempt.refreshed;
    defer std.testing.allocator.free(result.access_token);
    try std.testing.expectEqualStrings("at", result.access_token);
    try std.testing.expect(result.refresh_token == null);
    try std.testing.expectEqual(@as(?i64, 60), result.expires_in);
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
