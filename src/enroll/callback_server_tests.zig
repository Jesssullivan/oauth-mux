//! Unit tests for the loopback PKCE callback server (pure core + pure helpers).
//!
//! Run standalone, zero build wiring:
//!     zig test src/enroll/callback_server_tests.zig
//!
//! Everything here exercises the PURE CORE (`handleCallbackRequest`) and the
//! pure parse/validate helpers via injected fake seams — no real socket is
//! opened. `refAllDeclsRecursive` forces the whole module (including the
//! untested-by-design listener wrapper) to compile. All allocations go through
//! `std.testing.allocator`, so any leak fails the test.

const std = @import("std");
const cb = @import("callback_server.zig");

test {
    std.testing.refAllDeclsRecursive(cb);
}

// ── Fake seams ─────────────────────────────────────────────────────────────

const Recorder = struct {
    now: i64 = 1_000_000,

    exchange_fail: bool = false,
    exchange_oom: bool = false,
    access_token: []const u8 = "at-xyz",
    refresh_token: ?[]const u8 = "rt-xyz",
    id_token: ?[]const u8 = "jwt-xyz",
    expires_in: ?i64 = 3600,

    identity_fail: bool = false,
    identity_oom: bool = false,
    email: []const u8 = "user@work.example",
    account_id: []const u8 = "acc-work",

    fn clockFn(ctx: *anyopaque) i64 {
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        return self.now;
    }

    fn exchangeFn(
        allocator: std.mem.Allocator,
        ctx: *anyopaque,
        token_uri: []const u8,
        code: []const u8,
        code_verifier: [43]u8,
        client_id: []const u8,
        client_secret: []const u8,
        redirect_uri: []const u8,
    ) cb.ExchangeError!cb.TokenEndpointResponse {
        _ = token_uri;
        _ = code;
        _ = code_verifier;
        _ = client_id;
        _ = client_secret;
        _ = redirect_uri;
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        if (self.exchange_oom) return error.OutOfMemory;
        if (self.exchange_fail) return error.ExchangeFailed;
        return .{
            .access_token = try allocator.dupe(u8, self.access_token),
            .refresh_token = if (self.refresh_token) |rt| try allocator.dupe(u8, rt) else null,
            .id_token = if (self.id_token) |it| try allocator.dupe(u8, it) else null,
            .expires_in = self.expires_in,
        };
    }

    fn identityFn(
        allocator: std.mem.Allocator,
        ctx: *anyopaque,
        id_token: ?[]const u8,
        access_token: []const u8,
    ) cb.IdentityError!cb.IdentityInfo {
        _ = id_token;
        _ = access_token;
        const self: *Recorder = @ptrCast(@alignCast(ctx));
        if (self.identity_oom) return error.OutOfMemory;
        if (self.identity_fail) return error.ExtractFailed;
        return .{
            .email = try allocator.dupe(u8, self.email),
            .account_id = try allocator.dupe(u8, self.account_id),
        };
    }

    fn seams(self: *Recorder) cb.CallbackServerSeams {
        return .{
            .clock = clockFn,
            .exchange_code = exchangeFn,
            .extract_identity = identityFn,
            .clock_ctx = self,
            .exchange_code_ctx = self,
            .extract_identity_ctx = self,
        };
    }
};

// ── Fixtures ───────────────────────────────────────────────────────────────

const nonce: [16]u8 = .{ 0xAB, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0xFF };
const other_nonce: [16]u8 = .{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x00, 0x10 };
const verifier: [43]u8 = .{0xCD} ** 43;

const loopback_host = "127.0.0.1:54321";
const redirect = "http://127.0.0.1:54321/callback";
const far_future: i64 = 9_999_999_999;

/// Build "/callback?code=<code>&state=<base64url(nonce)>" into `buf`.
fn successTarget(buf: []u8, code: []const u8, n: [16]u8) []const u8 {
    const enc = cb.encodeState(n);
    return std.fmt.bufPrint(buf, "/callback?code={s}&state={s}", .{ code, enc[0..] }) catch unreachable;
}

/// Drive the pure core with the standard fixtures, overriding only `target`,
/// `host`, `expected_state`, `expected_account`, and `deadline`.
fn call(
    rec: *Recorder,
    target: []const u8,
    host: []const u8,
    expected_state: [16]u8,
    expected_account: ?[]const u8,
    deadline: i64,
) cb.CallbackServerError!cb.CallbackData {
    return cb.handleCallbackRequest(
        std.testing.allocator,
        rec.seams(),
        "GET",
        target,
        host,
        expected_state,
        verifier,
        expected_account,
        "https://token.example/oauth/token",
        "client-id",
        "client-secret",
        redirect,
        deadline,
    );
}

// ── Happy path ─────────────────────────────────────────────────────────────

test "happy path: valid code + state -> CallbackData with moved identity" {
    var rec = Recorder{};
    var buf: [256]u8 = undefined;
    const target = successTarget(&buf, "auth-code-1", nonce);

    const data = try call(&rec, target, loopback_host, nonce, "acc-work", far_future);
    defer cb.freeCallbackData(std.testing.allocator, data);

    try std.testing.expectEqualStrings("auth-code-1", data.code);
    try std.testing.expectEqualStrings("at-xyz", data.access_token);
    try std.testing.expectEqualStrings("user@work.example", data.email);
    try std.testing.expectEqualStrings("acc-work", data.account_id);
    try std.testing.expect(data.refresh_token != null);
    try std.testing.expectEqualStrings("rt-xyz", data.refresh_token.?);
    try std.testing.expectEqual(@as(?i64, 3600), data.expires_in);
    try std.testing.expectEqualSlices(u8, nonce[0..], data.state[0..]);
}

test "happy path: expected_account null skips identity match" {
    var rec = Recorder{ .account_id = "whatever-account" };
    var buf: [256]u8 = undefined;
    const target = successTarget(&buf, "auth-code-2", nonce);

    const data = try call(&rec, target, "localhost", nonce, null, far_future);
    defer cb.freeCallbackData(std.testing.allocator, data);
    try std.testing.expectEqualStrings("whatever-account", data.account_id);
}

test "happy path: refresh token absent" {
    var rec = Recorder{ .refresh_token = null };
    var buf: [256]u8 = undefined;
    const target = successTarget(&buf, "auth-code-3", nonce);

    const data = try call(&rec, target, loopback_host, nonce, "acc-work", far_future);
    defer cb.freeCallbackData(std.testing.allocator, data);
    try std.testing.expect(data.refresh_token == null);
}

// ── Missing / malformed params ─────────────────────────────────────────────

test "missing state -> MissingCodeOrState" {
    var rec = Recorder{};
    try std.testing.expectError(error.MissingCodeOrState, call(&rec, "/callback?code=xyz", loopback_host, nonce, "acc-work", far_future));
}

test "empty state -> MissingCodeOrState" {
    var rec = Recorder{};
    try std.testing.expectError(error.MissingCodeOrState, call(&rec, "/callback?code=xyz&state=", loopback_host, nonce, "acc-work", far_future));
}

test "missing code (valid state, no error) -> MissingCodeOrState" {
    var rec = Recorder{};
    const enc = cb.encodeState(nonce);
    var buf: [128]u8 = undefined;
    const target = std.fmt.bufPrint(&buf, "/callback?state={s}", .{enc[0..]}) catch unreachable;
    try std.testing.expectError(error.MissingCodeOrState, call(&rec, target, loopback_host, nonce, "acc-work", far_future));
}

test "empty code (valid state) -> MissingCodeOrState" {
    var rec = Recorder{};
    const enc = cb.encodeState(nonce);
    var buf: [128]u8 = undefined;
    const target = std.fmt.bufPrint(&buf, "/callback?code=&state={s}", .{enc[0..]}) catch unreachable;
    try std.testing.expectError(error.MissingCodeOrState, call(&rec, target, loopback_host, nonce, "acc-work", far_future));
}

// ── Host header (anti-DNS-rebinding) ───────────────────────────────────────

test "DNS-rebind suffix host -> HostHeaderRejected" {
    var rec = Recorder{};
    var buf: [256]u8 = undefined;
    const target = successTarget(&buf, "c", nonce);
    try std.testing.expectError(error.HostHeaderRejected, call(&rec, target, "127.0.0.1.evil.com", nonce, "acc-work", far_future));
}

test "non-loopback host -> HostHeaderRejected" {
    var rec = Recorder{};
    var buf: [256]u8 = undefined;
    const target = successTarget(&buf, "c", nonce);
    try std.testing.expectError(error.HostHeaderRejected, call(&rec, target, "example.com", nonce, "acc-work", far_future));
}

test "missing host -> HostHeaderRejected" {
    var rec = Recorder{};
    var buf: [256]u8 = undefined;
    const target = successTarget(&buf, "c", nonce);
    try std.testing.expectError(error.HostHeaderRejected, call(&rec, target, "", nonce, "acc-work", far_future));
}

// ── State / CSRF ───────────────────────────────────────────────────────────

test "state mismatch (different nonce, same length) -> StateMismatch" {
    var rec = Recorder{};
    var buf: [256]u8 = undefined;
    const target = successTarget(&buf, "c", other_nonce); // received encodes other_nonce
    try std.testing.expectError(error.StateMismatch, call(&rec, target, loopback_host, nonce, "acc-work", far_future));
}

test "state garbage (wrong length) -> StateMismatch" {
    var rec = Recorder{};
    try std.testing.expectError(error.StateMismatch, call(&rec, "/callback?code=c&state=abc", loopback_host, nonce, "acc-work", far_future));
}

test "CSRF is checked BEFORE the error branch: bad state + error= -> StateMismatch" {
    var rec = Recorder{};
    var buf: [256]u8 = undefined;
    const enc = cb.encodeState(other_nonce); // wrong state
    const target = std.fmt.bufPrint(&buf, "/callback?error=access_denied&state={s}", .{enc[0..]}) catch unreachable;
    // Must be StateMismatch (not ErrorRedirect) — forged error callbacks are rejected.
    try std.testing.expectError(error.StateMismatch, call(&rec, target, loopback_host, nonce, "acc-work", far_future));
}

// ── Provider error redirect ────────────────────────────────────────────────

test "valid-state provider error redirect -> ErrorRedirect" {
    var rec = Recorder{};
    var buf: [256]u8 = undefined;
    const enc = cb.encodeState(nonce);
    const target = std.fmt.bufPrint(&buf, "/callback?error=access_denied&state={s}", .{enc[0..]}) catch unreachable;
    try std.testing.expectError(error.ErrorRedirect, call(&rec, target, loopback_host, nonce, "acc-work", far_future));
}

// ── Deadline / timeout ─────────────────────────────────────────────────────

test "deadline passed -> Timeout" {
    var rec = Recorder{ .now = 2_000_000 };
    var buf: [256]u8 = undefined;
    const target = successTarget(&buf, "c", nonce);
    // clock (2_000_000) >= deadline (2_000_000) -> Timeout, before any exchange.
    try std.testing.expectError(error.Timeout, call(&rec, target, loopback_host, nonce, "acc-work", 2_000_000));
}

// ── Seam failures ──────────────────────────────────────────────────────────

test "exchange seam failure -> CodeExchangeFailed" {
    var rec = Recorder{ .exchange_fail = true };
    var buf: [256]u8 = undefined;
    const target = successTarget(&buf, "c", nonce);
    try std.testing.expectError(error.CodeExchangeFailed, call(&rec, target, loopback_host, nonce, "acc-work", far_future));
}

test "exchange seam OOM -> OutOfMemory" {
    var rec = Recorder{ .exchange_oom = true };
    var buf: [256]u8 = undefined;
    const target = successTarget(&buf, "c", nonce);
    try std.testing.expectError(error.OutOfMemory, call(&rec, target, loopback_host, nonce, "acc-work", far_future));
}

test "identity seam failure -> IdentityExtractFailed (no leak of token_resp)" {
    var rec = Recorder{ .identity_fail = true };
    var buf: [256]u8 = undefined;
    const target = successTarget(&buf, "c", nonce);
    try std.testing.expectError(error.IdentityExtractFailed, call(&rec, target, loopback_host, nonce, "acc-work", far_future));
}

test "identity seam OOM -> OutOfMemory" {
    var rec = Recorder{ .identity_oom = true };
    var buf: [256]u8 = undefined;
    const target = successTarget(&buf, "c", nonce);
    try std.testing.expectError(error.OutOfMemory, call(&rec, target, loopback_host, nonce, "acc-work", far_future));
}

// ── Identity / clone guard ─────────────────────────────────────────────────

test "identity mismatch (clone guard) -> IdentityMismatch (identity freed)" {
    var rec = Recorder{ .account_id = "acc-personal" }; // exchanged a DIFFERENT account
    var buf: [256]u8 = undefined;
    const target = successTarget(&buf, "c", nonce);
    // Expected acc-work, got acc-personal -> reject, and the identity must be
    // freed (testing.allocator would flag a leak otherwise).
    try std.testing.expectError(error.IdentityMismatch, call(&rec, target, loopback_host, nonce, "acc-work", far_future));
}

// ── Pure helpers ───────────────────────────────────────────────────────────

test "validateLoopbackHost accepts loopback forms" {
    try cb.validateLoopbackHost("127.0.0.1");
    try cb.validateLoopbackHost("127.0.0.1:65535");
    try cb.validateLoopbackHost("localhost");
    try cb.validateLoopbackHost("localhost:8080");
}

test "validateLoopbackHost rejects suffix + foreign hosts" {
    try std.testing.expectError(error.HostHeaderRejected, cb.validateLoopbackHost("127.0.0.1.evil.com"));
    try std.testing.expectError(error.HostHeaderRejected, cb.validateLoopbackHost("localhost.evil.com"));
    try std.testing.expectError(error.HostHeaderRejected, cb.validateLoopbackHost("github.com"));
    try std.testing.expectError(error.HostHeaderRejected, cb.validateLoopbackHost(""));
}

test "queryParam extracts and reports missing keys" {
    const q = "code=abc&state=xyz&error=";
    try std.testing.expectEqualStrings("abc", cb.queryParam(q, "code").?);
    try std.testing.expectEqualStrings("xyz", cb.queryParam(q, "state").?);
    try std.testing.expectEqualStrings("", cb.queryParam(q, "error").?);
    try std.testing.expect(cb.queryParam(q, "missing") == null);
}

test "encodeState/validateState round-trip" {
    const enc = cb.encodeState(nonce);
    try cb.validateState(enc[0..], nonce);
    try std.testing.expectError(error.StateMismatch, cb.validateState(enc[0..], other_nonce));
}

test "deriveChallenge matches RFC 7636 Appendix B vector" {
    // RFC 7636 B.1: verifier -> S256 challenge.
    const rfc_verifier: [43]u8 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk".*;
    const expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    const got = cb.deriveChallenge(rfc_verifier);
    try std.testing.expectEqualStrings(expected_challenge, got[0..]);
}

test "generatePkceAndState is internally consistent" {
    const ps = cb.generatePkceAndState();
    try std.testing.expectEqual(@as(usize, 43), ps.verifier.len);
    const ch = cb.deriveChallenge(ps.verifier);
    try std.testing.expectEqualSlices(u8, ch[0..], ps.challenge[0..]);
}

// ── Authorize URL (emitted, consent boundary) ──────────────────────────────

test "percentEncode encodes reserved chars, passes unreserved" {
    const e = try cb.percentEncode(std.testing.allocator, "http://127.0.0.1:8080/callback");
    defer std.testing.allocator.free(e);
    try std.testing.expectEqualStrings("http%3A%2F%2F127.0.0.1%3A8080%2Fcallback", e);
    const f = try cb.percentEncode(std.testing.allocator, "openid email");
    defer std.testing.allocator.free(f);
    try std.testing.expectEqualStrings("openid%20email", f);
}

test "buildAuthorizeUrl assembles an S256 PKCE request with encoded values" {
    const ps = cb.generatePkceAndState();
    const enc_state = cb.encodeState(ps.state_nonce);
    const url = try cb.buildAuthorizeUrl(std.testing.allocator, .{
        .authorize_endpoint = "https://auth.example/authorize",
        .client_id = "cid-1",
        .redirect_uri = "http://127.0.0.1:8080/callback",
        .scope = "openid email",
        .challenge = ps.challenge,
        .state = enc_state,
    });
    defer std.testing.allocator.free(url);
    try std.testing.expect(std.mem.startsWith(u8, url, "https://auth.example/authorize?response_type=code"));
    try std.testing.expect(std.mem.indexOf(u8, url, "code_challenge_method=S256") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "redirect_uri=http%3A%2F%2F127.0.0.1%3A8080%2Fcallback") != null);
    try std.testing.expect(std.mem.indexOf(u8, url, "scope=openid%20email") != null);
    // The challenge appears verbatim (already URL-safe base64url).
    try std.testing.expect(std.mem.indexOf(u8, url, ps.challenge[0..]) != null);
}

// ── Redaction (success page leaks nothing) ─────────────────────────────────

test "success response echoes no request data" {
    const resp = try cb.renderSuccessResponse(std.testing.allocator);
    defer std.testing.allocator.free(resp);
    try std.testing.expect(std.mem.indexOf(u8, resp, "200 OK") != null);
    // No code / token / verifier / state value can appear in a static page.
    try std.testing.expect(std.mem.indexOf(u8, resp, "auth-code") == null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "at-xyz") == null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "rt-xyz") == null);
    try std.testing.expect(std.mem.indexOf(u8, resp, "jwt-xyz") == null);
}

// ── Listener HTTP parse helpers (pure parts of the untested wrapper) ────────

test "parseRequestLine extracts method + target" {
    const raw = "GET /callback?code=x&state=y HTTP/1.1\r\nHost: 127.0.0.1:8080\r\n\r\n";
    const line = cb.parseRequestLine(raw).?;
    try std.testing.expectEqualStrings("GET", line.method);
    try std.testing.expectEqualStrings("/callback?code=x&state=y", line.target);
}

test "parseRequestLine rejects empty input" {
    try std.testing.expect(cb.parseRequestLine("") == null);
}

test "parseHostHeader is case-insensitive and trims" {
    const raw = "GET /callback HTTP/1.1\r\nhost:  127.0.0.1:8080  \r\nAccept: */*\r\n\r\n";
    try std.testing.expectEqualStrings("127.0.0.1:8080", cb.parseHostHeader(raw).?);
}

test "parseHostHeader returns null when absent" {
    const raw = "GET /callback HTTP/1.1\r\nAccept: */*\r\n\r\n";
    try std.testing.expect(cb.parseHostHeader(raw) == null);
}
