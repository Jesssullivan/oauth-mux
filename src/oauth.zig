const std = @import("std");
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
        .claude => "https://claude.ai/api/auth/oauth/token",
        .codex => "https://auth0.openai.com/oauth/token",
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
        "https://claude.ai/api/auth/oauth/token",
        refreshUrl(.claude).?,
    );
    try std.testing.expectEqualStrings(
        "https://auth0.openai.com/oauth/token",
        refreshUrl(.codex).?,
    );
    try std.testing.expect(refreshUrl(.github) == null);
}
