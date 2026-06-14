//! Unit tests for the Claude reauth adapter (pure builders/parsers + the
//! adapter over a fake HTTP seam). No real network.
//!
//!     zig test src/enroll/claude_reauth_tests.zig
//!
//! All allocations go through `std.testing.allocator`, so any leak fails.

const std = @import("std");
const cr = @import("claude_reauth.zig");

test {
    std.testing.refAllDeclsRecursive(cr);
}

// ── Fixtures ───────────────────────────────────────────────────────────────

const token_response_json =
    \\{"access_token":"sk-ant-oat01-AAA","refresh_token":"sk-ant-ort01-BBB","expires_in":3600,"scope":"user:inference user:profile","token_type":"Bearer"}
;
const credential_json =
    \\{"claudeAiOauth":{"accessToken":"sk-ant-oat01-CCC","refreshToken":"sk-ant-ort01-DDD","expiresAt":1748276587173,"scopes":["user:inference","user:profile"],"subscriptionType":"max"}}
;

const verifier: [43]u8 = .{0xCD} ** 43;

// ── Fake HTTP seam ─────────────────────────────────────────────────────────

const Recorder = struct {
    response: []const u8 = "{}",
    fail: bool = false,
    url_buf: [256]u8 = undefined,
    url_len: usize = 0,
    body_buf: [512]u8 = undefined,
    body_len: usize = 0,
    ct_buf: [64]u8 = undefined,
    ct_len: usize = 0,

    fn postFn(
        allocator: std.mem.Allocator,
        ctx: *anyopaque,
        url: []const u8,
        body: []const u8,
        content_type: []const u8,
    ) cr.HttpError![]u8 {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        self.url_len = @min(url.len, self.url_buf.len);
        @memcpy(self.url_buf[0..self.url_len], url[0..self.url_len]);
        self.body_len = @min(body.len, self.body_buf.len);
        @memcpy(self.body_buf[0..self.body_len], body[0..self.body_len]);
        self.ct_len = @min(content_type.len, self.ct_buf.len);
        @memcpy(self.ct_buf[0..self.ct_len], content_type[0..self.ct_len]);
        if (self.fail) return error.HttpFailed;
        return allocator.dupe(u8, self.response);
    }

    fn seenUrl(self: *Recorder) []const u8 {
        return self.url_buf[0..self.url_len];
    }
    fn seenBody(self: *Recorder) []const u8 {
        return self.body_buf[0..self.body_len];
    }
    fn seenContentType(self: *Recorder) []const u8 {
        return self.ct_buf[0..self.ct_len];
    }
    fn adapter(self: *Recorder) cr.ClaudeReauthAdapter {
        return .{ .http_post = postFn, .http_ctx = self };
    }
};

fn contains(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

// ── Request builders ───────────────────────────────────────────────────────

test "buildAuthorizeUrl uses the verified Claude endpoint + client_id + S256" {
    const challenge = cr.deriveChallenge(verifier);
    const url = try cr.buildAuthorizeUrl(
        std.testing.allocator,
        cr.default_client_id,
        cr.default_scopes,
        "http://127.0.0.1:8123/callback",
        challenge,
        "state-xyz",
    );
    defer std.testing.allocator.free(url);
    try std.testing.expect(std.mem.startsWith(u8, url, "https://console.anthropic.com/oauth/authorize?response_type=code"));
    try std.testing.expect(contains(url, "client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e"));
    try std.testing.expect(contains(url, "code_challenge_method=S256"));
    try std.testing.expect(contains(url, "redirect_uri=http%3A%2F%2F127.0.0.1%3A8123%2Fcallback"));
    try std.testing.expect(contains(url, "scope=user%3Ainference%20user%3Aprofile"));
    try std.testing.expect(contains(url, "state=state-xyz"));
    try std.testing.expect(contains(url, challenge[0..]));
}

test "buildTokenExchangeBody is a valid authorization_code grant" {
    const body = try cr.buildTokenExchangeBody(
        std.testing.allocator,
        cr.default_client_id,
        "the-code",
        verifier,
        "http://127.0.0.1:8123/callback",
    );
    defer std.testing.allocator.free(body);
    try std.testing.expect(contains(body, "grant_type=authorization_code"));
    try std.testing.expect(contains(body, "code=the-code"));
    try std.testing.expect(contains(body, "client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e"));
    try std.testing.expect(contains(body, "redirect_uri=http%3A%2F%2F127.0.0.1%3A8123%2Fcallback"));
    try std.testing.expect(contains(body, "code_verifier="));
}

test "buildRefreshBody is a valid refresh_token grant" {
    const body = try cr.buildRefreshBody(std.testing.allocator, cr.default_client_id, "sk-ant-ort01-RRR");
    defer std.testing.allocator.free(body);
    try std.testing.expect(contains(body, "grant_type=refresh_token"));
    try std.testing.expect(contains(body, "refresh_token=sk-ant-ort01-RRR"));
    try std.testing.expect(contains(body, "client_id=9d1c250a-e61b-44d9-88ed-5944d1962f5e"));
}

// ── Token endpoint response parsing ────────────────────────────────────────

test "parseTokenEndpointResponse normalizes expires_in -> absolute ms" {
    const t = try cr.parseTokenEndpointResponse(std.testing.allocator, token_response_json, 1000);
    defer cr.freeTokens(std.testing.allocator, t);
    try std.testing.expectEqualStrings("sk-ant-oat01-AAA", t.access_token);
    try std.testing.expectEqualStrings("sk-ant-ort01-BBB", t.refresh_token);
    // 1000 ms + 3600 s * 1000 = 3_601_000 ms
    try std.testing.expectEqual(@as(i64, 3_601_000), t.expires_at_ms);
    try std.testing.expectEqualStrings("user:inference user:profile", t.scopes.?);
}

test "parseTokenEndpointResponse rejects missing access_token" {
    try std.testing.expectError(error.ParseFailed, cr.parseTokenEndpointResponse(std.testing.allocator, "{\"refresh_token\":\"x\"}", 0));
}

test "parseTokenEndpointResponse rejects invalid JSON" {
    try std.testing.expectError(error.ParseFailed, cr.parseTokenEndpointResponse(std.testing.allocator, "not json", 0));
}

test "parseTokenEndpointResponse rejects an overflowing/negative expires_in (no panic)" {
    // A hostile/proxied token endpoint returning a huge expires_in must reject,
    // not overflow-panic on now_ms + expires_in*1000.
    try std.testing.expectError(error.ParseFailed, cr.parseTokenEndpointResponse(
        std.testing.allocator,
        "{\"access_token\":\"sk-ant-oat01-X\",\"expires_in\":9223372036854775}",
        1000,
    ));
    // a negative relative TTL is nonsensical.
    try std.testing.expectError(error.ParseFailed, cr.parseTokenEndpointResponse(
        std.testing.allocator,
        "{\"access_token\":\"sk-ant-oat01-X\",\"expires_in\":-1}",
        1000,
    ));
}

// ── Credential file (claudeAiOauth) build + parse ──────────────────────────

test "buildCredentialJson emits the verified claudeAiOauth shape" {
    const t = cr.ClaudeTokens{
        .access_token = "sk-ant-oat01-CCC",
        .refresh_token = "sk-ant-ort01-DDD",
        .expires_at_ms = 1748276587173,
        .scopes = "user:inference user:profile",
        .subscription_type = "max",
    };
    const json = try cr.buildCredentialJson(std.testing.allocator, t);
    defer std.testing.allocator.free(json);
    try std.testing.expect(contains(json, "\"claudeAiOauth\":{"));
    try std.testing.expect(contains(json, "\"accessToken\":\"sk-ant-oat01-CCC\""));
    try std.testing.expect(contains(json, "\"refreshToken\":\"sk-ant-ort01-DDD\""));
    try std.testing.expect(contains(json, "\"expiresAt\":1748276587173"));
    try std.testing.expect(contains(json, "\"scopes\":[\"user:inference\",\"user:profile\"]"));
    try std.testing.expect(contains(json, "\"subscriptionType\":\"max\""));
}

test "buildCredentialJson escapes JSON metacharacters — no key injection" {
    // Fields carrying `"` / `\` must be escaped, not allowed to inject a sibling
    // key or break the document. Round-trip preserving the EXACT values is the
    // proof: an unescaped write would truncate subscriptionType to "max" and leak
    // an "injected" key (parseCredentialJson ignores unknown fields).
    const t = cr.ClaudeTokens{
        .access_token = "a\"x",
        .refresh_token = "b\\y",
        .expires_at_ms = 1,
        .scopes = null,
        .subscription_type = "max\",\"injected\":\"1",
    };
    const json = try cr.buildCredentialJson(std.testing.allocator, t);
    defer std.testing.allocator.free(json);
    const back = try cr.parseCredentialJson(std.testing.allocator, json);
    defer cr.freeTokens(std.testing.allocator, back);
    try std.testing.expectEqualStrings("a\"x", back.access_token);
    try std.testing.expectEqualStrings("b\\y", back.refresh_token);
    try std.testing.expectEqualStrings("max\",\"injected\":\"1", back.subscription_type.?);
}

test "parseCredentialJson reads absolute ms expiresAt + subscriptionType" {
    const t = try cr.parseCredentialJson(std.testing.allocator, credential_json);
    defer cr.freeTokens(std.testing.allocator, t);
    try std.testing.expectEqualStrings("sk-ant-oat01-CCC", t.access_token);
    try std.testing.expectEqualStrings("sk-ant-ort01-DDD", t.refresh_token);
    try std.testing.expectEqual(@as(i64, 1748276587173), t.expires_at_ms);
    try std.testing.expectEqualStrings("max", t.subscription_type.?);
}

test "credential build -> parse round-trip" {
    const orig = cr.ClaudeTokens{
        .access_token = "sk-ant-oat01-RT",
        .refresh_token = "sk-ant-ort01-RT",
        .expires_at_ms = 1700000000000,
        .scopes = "user:inference",
        .subscription_type = "pro",
    };
    const json = try cr.buildCredentialJson(std.testing.allocator, orig);
    defer std.testing.allocator.free(json);
    const back = try cr.parseCredentialJson(std.testing.allocator, json);
    defer cr.freeTokens(std.testing.allocator, back);
    try std.testing.expectEqualStrings(orig.access_token, back.access_token);
    try std.testing.expectEqualStrings(orig.refresh_token, back.refresh_token);
    try std.testing.expectEqual(orig.expires_at_ms, back.expires_at_ms);
    try std.testing.expectEqualStrings("pro", back.subscription_type.?);
}

// ── Predicates ─────────────────────────────────────────────────────────────

test "isAccessTokenExpired honors skew" {
    const t = cr.ClaudeTokens{ .access_token = "a", .refresh_token = "r", .expires_at_ms = 10_000 };
    try std.testing.expect(!cr.isAccessTokenExpired(t, 5_000, 0));
    try std.testing.expect(cr.isAccessTokenExpired(t, 10_000, 0)); // at expiry
    try std.testing.expect(cr.isAccessTokenExpired(t, 9_500, 1_000)); // within skew
    try std.testing.expect(!cr.isAccessTokenExpired(t, 8_000, 1_000));
}

test "token prefix recognizers" {
    try std.testing.expect(cr.looksLikeAccessToken("sk-ant-oat01-xyz"));
    try std.testing.expect(!cr.looksLikeAccessToken("sk-ant-ort01-xyz"));
    try std.testing.expect(cr.looksLikeRefreshToken("sk-ant-ort01-xyz"));
    try std.testing.expect(!cr.looksLikeRefreshToken("nope"));
}

test "deriveChallenge matches RFC 7636 Appendix B vector" {
    const rfc_verifier: [43]u8 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".*;
    const got = cr.deriveChallenge(rfc_verifier);
    try std.testing.expectEqualStrings("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", got[0..]);
}

test "percentEncode encodes reserved, passes unreserved" {
    const e = try cr.percentEncode(std.testing.allocator, "a:b/c d");
    defer std.testing.allocator.free(e);
    try std.testing.expectEqualStrings("a%3Ab%2Fc%20d", e);
}

// ── Adapter over the fake HTTP seam ────────────────────────────────────────

test "adapter.exchangeCode posts an auth-code grant to the token endpoint and parses tokens" {
    var rec = Recorder{ .response = token_response_json };
    const adapter = rec.adapter();
    const t = try adapter.exchangeCode(std.testing.allocator, "the-code", verifier, "http://127.0.0.1:9/callback", 1000);
    defer cr.freeTokens(std.testing.allocator, t);

    try std.testing.expectEqualStrings("https://console.anthropic.com/v1/oauth/token", rec.seenUrl());
    try std.testing.expectEqualStrings("application/x-www-form-urlencoded", rec.seenContentType());
    try std.testing.expect(contains(rec.seenBody(), "grant_type=authorization_code"));
    try std.testing.expectEqualStrings("sk-ant-oat01-AAA", t.access_token);
    try std.testing.expectEqual(@as(i64, 3_601_000), t.expires_at_ms);
}

test "adapter.refresh posts a refresh grant and parses tokens" {
    var rec = Recorder{ .response = token_response_json };
    const adapter = rec.adapter();
    const t = try adapter.refresh(std.testing.allocator, "sk-ant-ort01-OLD", 2000);
    defer cr.freeTokens(std.testing.allocator, t);
    try std.testing.expect(contains(rec.seenBody(), "grant_type=refresh_token"));
    try std.testing.expect(contains(rec.seenBody(), "refresh_token=sk-ant-ort01-OLD"));
    try std.testing.expectEqual(@as(i64, 3_602_000), t.expires_at_ms);
}

test "adapter.exchangeCode maps HTTP failure -> ExchangeFailed" {
    var rec = Recorder{ .fail = true };
    const adapter = rec.adapter();
    try std.testing.expectError(error.ExchangeFailed, adapter.exchangeCode(std.testing.allocator, "c", verifier, "http://127.0.0.1:9/callback", 0));
}

test "adapter.refresh maps HTTP failure -> RefreshFailed" {
    var rec = Recorder{ .fail = true };
    const adapter = rec.adapter();
    try std.testing.expectError(error.RefreshFailed, adapter.refresh(std.testing.allocator, "rt", 0));
}

test "adapter.exchangeCode maps unparseable response -> ExchangeFailed" {
    var rec = Recorder{ .response = "garbage" };
    const adapter = rec.adapter();
    try std.testing.expectError(error.ExchangeFailed, adapter.exchangeCode(std.testing.allocator, "c", verifier, "http://127.0.0.1:9/callback", 0));
}

test "adapter.materialize writes a parseable credential file" {
    var rec = Recorder{};
    const adapter = rec.adapter();
    const t = cr.ClaudeTokens{
        .access_token = "sk-ant-oat01-M",
        .refresh_token = "sk-ant-ort01-M",
        .expires_at_ms = 1700000000000,
        .scopes = "user:inference user:profile",
        .subscription_type = "max",
    };
    const json = try adapter.materialize(std.testing.allocator, t);
    defer std.testing.allocator.free(json);
    const back = try cr.parseCredentialJson(std.testing.allocator, json);
    defer cr.freeTokens(std.testing.allocator, back);
    try std.testing.expectEqualStrings("sk-ant-oat01-M", back.access_token);
    try std.testing.expectEqual(@as(i64, 1700000000000), back.expires_at_ms);
}
