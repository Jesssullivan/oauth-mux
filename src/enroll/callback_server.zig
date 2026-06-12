//! Loopback PKCE callback server for cookieless reauth (greenfield increment 3).
//!
//! This is the `redirect_loopback` half of the reauth backend: a one-shot,
//! ephemeral `127.0.0.1` listener that captures the OAuth authorization-code
//! redirect (`?code=…&state=…`), validates CSRF + the loopback Host, drives the
//! PKCE S256 code exchange through an injected seam, confirms the returned
//! identity matches the account being re-authed (clone / wrong-identity guard),
//! and hands back a `CallbackData`. It is the real backing for the operator web
//! UI's `GET /callback` route stub.
//!
//! Same proven shape as the engine (`reauth.zig`) and web UI (`web_ui.zig`):
//!   * a PURE CORE (`handleCallbackRequest`) that takes the parsed request as
//!     plain strings + injected seams and touches NO socket, clock, or disk —
//!     fully unit-testable with `std.testing.allocator` leak-checking;
//!   * a thin, untested-by-design listener wrapper (`CallbackServerListener`)
//!     that owns the real `std.net` socket and delegates every decision to the
//!     pure core.
//!
//! Self-contained: `std` only. No `@import` of existing `src/`, no
//! `build_options`, so `zig test src/enroll/callback_server_tests.zig` runs with
//! zero build wiring. The inline `deriveChallenge` mirrors
//! `src/oauth.zig:generatePkce` (S256) byte-for-byte; production wiring should
//! call the real `oauth.generatePkce` instead of the local convenience helper.
//!
//! Security model (RFC 8252 loopback, RFC 7636 PKCE, OAuth 2.1 state):
//!   * bind 127.0.0.1 ONLY, ephemeral port (never 0.0.0.0 / a hostname);
//!   * reject any inbound Host that is not EXACTLY 127.0.0.1/localhost
//!     (optional :port) — suffix bypass (127.0.0.1.evil.com) is anti-DNS-rebinding;
//!   * state is 16 random bytes (128-bit), single-use, constant-time compared,
//!     and validated BEFORE the error-redirect branch (a forged ?error= callback
//!     is still CSRF-checked);
//!   * the PKCE code_verifier is ephemeral in-process, passed only to the
//!     exchange seam, and NEVER returned in CallbackData, logged, or rendered;
//!   * the static success page echoes NO request data (no code/state/token);
//!   * after exchange the returned account_id MUST match the expected account.

const std = @import("std");

// ── Public data types ──────────────────────────────────────────────────────

/// The validated, exchanged result of a single loopback callback. The caller
/// owns every slice and frees them with `freeCallbackData`. Note: there is no
/// `verifier` field — the PKCE verifier is ephemeral and never escapes here.
pub const CallbackData = struct {
    /// Authorization code that was exchanged (kept for audit only).
    code: []const u8,
    /// The CSRF nonce this callback was validated against (fixed array, not a
    /// slice: it is the raw 16 bytes, never the encoded query value).
    state: [16]u8,
    access_token: []const u8,
    refresh_token: ?[]const u8 = null,
    expires_in: ?i64 = null,
    /// Identity the tokens belong to (for operator display + confirmation).
    email: []const u8,
    account_id: []const u8,
};

/// Token endpoint (`POST /token`) response, produced by the exchange seam.
pub const TokenEndpointResponse = struct {
    access_token: []const u8,
    token_type: []const u8 = "Bearer",
    expires_in: ?i64 = null,
    refresh_token: ?[]const u8 = null,
    /// JWT used by the identity seam to derive email + account_id.
    id_token: ?[]const u8 = null,
};

/// Identity extracted from the exchanged tokens.
pub const IdentityInfo = struct {
    email: []const u8,
    account_id: []const u8,
};

/// Errors the pure core can surface. `OutOfMemory` is propagated distinctly so
/// the caller can retry; everything else is a terminal validation failure.
pub const CallbackServerError = error{
    /// Required `state` (or, post-validation, `code`) absent or empty.
    MissingCodeOrState,
    /// Received state did not match the expected nonce (CSRF / replay).
    StateMismatch,
    /// Host header is missing or not exactly loopback (anti-DNS-rebinding).
    HostHeaderRejected,
    /// Provider sent `?error=…` (e.g. access_denied) after a valid-state callback.
    ErrorRedirect,
    /// The token exchange seam failed.
    CodeExchangeFailed,
    /// The identity-extraction seam failed.
    IdentityExtractFailed,
    /// Exchanged identity's account_id != the account being re-authed.
    IdentityMismatch,
    /// Deadline passed before a usable callback arrived.
    Timeout,
    OutOfMemory,
};

// ── Injected seams ─────────────────────────────────────────────────────────
//
// Each seam is a bare fn pointer plus an opaque ctx, exactly like the engine's
// device_code seams, so the pure core needs no network, clock, or disk and the
// tests inject deterministic fakes.

/// Wall-clock seconds (Unix epoch). Injected so the deadline is virtual in tests.
pub const ClockFn = *const fn (ctx: *anyopaque) i64;

/// Errors the exchange seam may surface (small, exhaustive — no `else` prong).
pub const ExchangeError = error{ OutOfMemory, ExchangeFailed };

/// `POST` the authorization code + PKCE verifier to the token endpoint.
/// Returns freshly-allocated slices the core frees after use.
pub const ExchangeCodeFn = *const fn (
    allocator: std.mem.Allocator,
    ctx: *anyopaque,
    token_uri: []const u8,
    code: []const u8,
    code_verifier: [43]u8,
    client_id: []const u8,
    client_secret: []const u8,
    redirect_uri: []const u8,
) ExchangeError!TokenEndpointResponse;

/// Errors the identity seam may surface.
pub const IdentityError = error{ OutOfMemory, ExtractFailed };

/// Derive (email, account_id) from the exchanged tokens (JWT or userinfo).
/// Returns freshly-allocated slices; ownership transfers to the core, which
/// either moves them into `CallbackData` or frees them on mismatch/failure.
pub const ExtractIdentityFn = *const fn (
    allocator: std.mem.Allocator,
    ctx: *anyopaque,
    id_token: ?[]const u8,
    access_token: []const u8,
) IdentityError!IdentityInfo;

/// Bundle of every external coupling the core needs. Three seams cover all I/O.
pub const CallbackServerSeams = struct {
    clock: ClockFn,
    exchange_code: ExchangeCodeFn,
    extract_identity: ExtractIdentityFn,
    clock_ctx: *anyopaque,
    exchange_code_ctx: *anyopaque,
    extract_identity_ctx: *anyopaque,
};

// ── Pure core ──────────────────────────────────────────────────────────────

/// Parse + validate a single loopback callback request and, if it is a valid
/// success redirect, exchange the code and confirm identity. NO socket/clock/FS
/// access of its own — every side effect is an injected seam.
///
/// Validation order is security-significant:
///   1. Host must be exactly loopback (before anything else is trusted).
///   2. `state` must be present and CSRF-valid — checked BEFORE the error
///      branch so a forged `?error=…&state=WRONG` is rejected as StateMismatch,
///      not silently accepted as a provider error.
///   3. only then: distinguish a provider error redirect from a real code,
///      check the deadline, exchange, and confirm identity.
pub fn handleCallbackRequest(
    allocator: std.mem.Allocator,
    seams: CallbackServerSeams,
    method: []const u8,
    target: []const u8,
    host_header: []const u8,
    expected_state: [16]u8,
    pkce_verifier: [43]u8,
    expected_account_id: ?[]const u8,
    token_uri: []const u8,
    client_id: []const u8,
    client_secret: []const u8,
    redirect_uri: []const u8,
    deadline_s: i64,
) CallbackServerError!CallbackData {
    _ = method; // GET-only is enforced by the listener; the core is method-agnostic.

    // 1. Anti-DNS-rebinding: loopback Host only (RFC 8252 §7.3).
    try validateLoopbackHost(host_header);

    // 2. Extract query params.
    const query = splitQuery(target);
    const state_str = queryParam(query, "state") orelse return error.MissingCodeOrState;
    if (state_str.len == 0) return error.MissingCodeOrState;

    // 3. CSRF FIRST: reject any callback whose state does not match, regardless
    //    of whether it carries a code or an error (defense-in-depth).
    try validateState(state_str, expected_state);

    // 4. Provider error redirect (?error=access_denied&state=…) — state already
    //    proven valid, so this is a genuine provider-side denial, not a forgery.
    if (queryParam(query, "error") != null) return error.ErrorRedirect;

    // 5. Success path requires a non-empty code.
    const code = queryParam(query, "code") orelse return error.MissingCodeOrState;
    if (code.len == 0) return error.MissingCodeOrState;

    // 6. Deadline guard before the (network) exchange.
    if (seams.clock(seams.clock_ctx) >= deadline_s) return error.Timeout;

    // 7. Exchange the code + PKCE verifier for tokens.
    const token_resp = seams.exchange_code(
        allocator,
        seams.exchange_code_ctx,
        token_uri,
        code,
        pkce_verifier,
        client_id,
        client_secret,
        redirect_uri,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ExchangeFailed => return error.CodeExchangeFailed,
    };
    defer {
        allocator.free(token_resp.access_token);
        if (token_resp.refresh_token) |rt| allocator.free(rt);
        if (token_resp.id_token) |it| allocator.free(it);
    }

    // 8. Derive identity (email + account_id) from the tokens.
    const identity = seams.extract_identity(
        allocator,
        seams.extract_identity_ctx,
        token_resp.id_token,
        token_resp.access_token,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ExtractFailed => return error.IdentityExtractFailed,
    };

    // 9. Clone / wrong-identity guard: the exchanged account must match the one
    //    being re-authed. Free the identity (it would otherwise leak) and abort.
    if (expected_account_id) |expected| {
        if (!std.mem.eql(u8, identity.account_id, expected)) {
            allocator.free(identity.account_id);
            allocator.free(identity.email);
            return error.IdentityMismatch;
        }
    }

    // 10. Assemble the result. The identity slices are MOVED into CallbackData;
    //     errdefer frees them only if a subsequent dupe fails (leak-safety).
    errdefer allocator.free(identity.email);
    errdefer allocator.free(identity.account_id);

    const code_owned = try allocator.dupe(u8, code);
    errdefer allocator.free(code_owned);
    const access_owned = try allocator.dupe(u8, token_resp.access_token);
    errdefer allocator.free(access_owned);
    const refresh_owned = if (token_resp.refresh_token) |rt|
        try allocator.dupe(u8, rt)
    else
        null;

    return .{
        .code = code_owned,
        .state = expected_state,
        .access_token = access_owned,
        .refresh_token = refresh_owned,
        .expires_in = token_resp.expires_in,
        .email = identity.email,
        .account_id = identity.account_id,
    };
}

/// Free a `CallbackData` produced by `handleCallbackRequest`.
pub fn freeCallbackData(allocator: std.mem.Allocator, data: CallbackData) void {
    allocator.free(data.code);
    allocator.free(data.access_token);
    if (data.refresh_token) |rt| allocator.free(rt);
    allocator.free(data.email);
    allocator.free(data.account_id);
}

// ── Validation + parsing helpers (pure) ────────────────────────────────────

/// Accept only an exact loopback Host (optional :port). Splitting on the first
/// ':' and requiring an exact string match defeats the suffix bypass
/// (`127.0.0.1.evil.com`, `localhost.attacker`) that `startsWith` would allow.
pub fn validateLoopbackHost(host_header: []const u8) CallbackServerError!void {
    if (host_header.len == 0) return error.HostHeaderRejected;
    const host = if (std.mem.indexOfScalar(u8, host_header, ':')) |colon|
        host_header[0..colon]
    else
        host_header;
    if (std.mem.eql(u8, host, "127.0.0.1")) return;
    if (std.mem.eql(u8, host, "localhost")) return;
    return error.HostHeaderRejected;
}

/// Return the query portion of a request target (`/callback?a=b` -> `a=b`).
fn splitQuery(target: []const u8) []const u8 {
    return if (std.mem.indexOfScalar(u8, target, '?')) |q| target[q + 1 ..] else "";
}

/// First value for `key` in an `&`-separated query string, or null. Values are
/// returned raw (no percent-decoding); base64url state and OAuth codes are
/// URL-safe so this is sufficient for validation + exchange.
pub fn queryParam(query: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (std.mem.eql(u8, pair[0..eq], key)) return pair[eq + 1 ..];
    }
    return null;
}

/// Constant-time validation of the received (base64url) state against the
/// expected 16-byte nonce. Any decode failure or length mismatch is a plain
/// StateMismatch (no oracle); the byte compare never early-exits.
pub fn validateState(received_str: []const u8, expected: [16]u8) CallbackServerError!void {
    const decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = decoder.calcSizeForSlice(received_str) catch return error.StateMismatch;
    if (decoded_len != expected.len) return error.StateMismatch;
    var decoded: [16]u8 = undefined;
    decoder.decode(decoded[0..], received_str) catch return error.StateMismatch;
    var diff: u8 = 0;
    for (expected, decoded) |a, b| diff |= a ^ b;
    if (diff != 0) return error.StateMismatch;
}

/// Encode a 16-byte state nonce to its base64url (no-pad) query form. The
/// listener puts this in the `state` parameter of the authorize URL.
pub fn encodeState(nonce: [16]u8) [22]u8 {
    var out: [22]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(out[0..], nonce[0..]);
    return out;
}

/// Derive the PKCE S256 challenge for a verifier — base64url(SHA256(verifier)).
/// Mirrors `src/oauth.zig:generatePkce` so the local convenience helper matches
/// production exactly.
pub fn deriveChallenge(verifier: [43]u8) [43]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(verifier[0..], &hash, .{});
    var challenge: [43]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(challenge[0..], hash[0..]);
    return challenge;
}

/// A fresh PKCE verifier + challenge + state nonce for one loopback attempt.
pub const PkceState = struct {
    verifier: [43]u8,
    challenge: [43]u8,
    state_nonce: [16]u8,
};

/// Convenience: generate a verifier + challenge + state nonce. Uses
/// `std.crypto.random` directly (like `oauth.generatePkce`); not unit-tested
/// for randomness — the deterministic math is covered via `deriveChallenge`.
/// Production wiring should prefer the real `oauth.generatePkce` for the PKCE
/// pair and only borrow the state-nonce generation here.
pub fn generatePkceAndState() PkceState {
    var verifier_bytes: [32]u8 = undefined;
    std.crypto.random.bytes(&verifier_bytes);
    var verifier: [43]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(verifier[0..], verifier_bytes[0..]);

    var state_nonce: [16]u8 = undefined;
    std.crypto.random.bytes(&state_nonce);

    return .{
        .verifier = verifier,
        .challenge = deriveChallenge(verifier),
        .state_nonce = state_nonce,
    };
}

// ── Authorize URL (emitted, never auto-opened — consent boundary) ──────────

fn isUnreserved(c: u8) bool {
    return (c >= 'A' and c <= 'Z') or
        (c >= 'a' and c <= 'z') or
        (c >= '0' and c <= '9') or
        c == '-' or c == '_' or c == '.' or c == '~';
}

/// Percent-encode per RFC 3986 (unreserved set passes through). Used for the
/// `redirect_uri` / `scope` / `client_id` values placed in the authorize URL.
pub fn percentEncode(allocator: std.mem.Allocator, s: []const u8) ![]u8 {
    const hex = "0123456789ABCDEF";
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    for (s) |c| {
        if (isUnreserved(c)) {
            try out.append(c);
        } else {
            try out.append('%');
            try out.append(hex[c >> 4]);
            try out.append(hex[c & 0x0F]);
        }
    }
    return out.toOwnedSlice();
}

/// Inputs for the authorization-code + PKCE authorize URL.
pub const AuthorizeParams = struct {
    authorize_endpoint: []const u8,
    client_id: []const u8,
    redirect_uri: []const u8,
    scope: []const u8,
    challenge: [43]u8, // PKCE S256 challenge (base64url, URL-safe as-is)
    state: [22]u8, // base64url(nonce) (URL-safe as-is)
};

/// Build the `redirect_loopback` authorize URL. This is EMITTED to the operator
/// (printed / shown as a UI link) and deliberately NOT auto-opened: the operator
/// chooses the isolated/private browser context, which is what guarantees the
/// right identity for multi-account users. Caller owns the returned slice.
pub fn buildAuthorizeUrl(allocator: std.mem.Allocator, p: AuthorizeParams) ![]u8 {
    const enc_client = try percentEncode(allocator, p.client_id);
    defer allocator.free(enc_client);
    const enc_redirect = try percentEncode(allocator, p.redirect_uri);
    defer allocator.free(enc_redirect);
    const enc_scope = try percentEncode(allocator, p.scope);
    defer allocator.free(enc_scope);
    return std.fmt.allocPrint(
        allocator,
        "{s}?response_type=code&client_id={s}&redirect_uri={s}" ++
            "&scope={s}&state={s}&code_challenge={s}&code_challenge_method=S256",
        .{ p.authorize_endpoint, enc_client, enc_redirect, enc_scope, p.state[0..], p.challenge[0..] },
    );
}

// ── Success page (static, secret-free) ─────────────────────────────────────

/// The HTML shown to the browser after a successful capture. It is a constant
/// with NO interpolation of any request data, so no code/state/token can leak
/// into rendered output. Closes the tab automatically after a short delay.
pub const success_page_html: []const u8 =
    "<!doctype html><html><head><meta charset=\"utf-8\">" ++
    "<title>Re-authentication complete</title></head><body>" ++
    "<h1>Re-authentication complete</h1>" ++
    "<p>You may close this window and return to your terminal.</p>" ++
    "<script>setTimeout(function(){window.close();},1500);</script>" ++
    "</body></html>";

/// Minimal HTTP/1.1 response bytes for the success page.
pub fn renderSuccessResponse(allocator: std.mem.Allocator) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n" ++
            "Content-Length: {d}\r\nConnection: close\r\n\r\n{s}",
        .{ success_page_html.len, success_page_html },
    );
}

// ── Listener wrapper (thin, untested by design) ────────────────────────────
//
// This is the ONLY code that touches a real socket. It mirrors the repo's
// existing loopback idiom (src/adapters/codex/wire_proxy.zig: parseIp →
// listen(.reuse_address) → listen_address → accept → conn.stream). All
// decisions are delegated to the pure core above, which is exhaustively tested.

/// One-shot loopback callback listener. `listenOnce` binds an ephemeral
/// 127.0.0.1 port, reports it (for building redirect_uri), accepts exactly one
/// connection, and runs the pure core over the parsed request.
pub const CallbackServerListener = struct {
    allocator: std.mem.Allocator,
    seams: CallbackServerSeams,
    token_uri: []const u8,
    client_id: []const u8,
    client_secret: []const u8,
    expected_account_id: ?[]const u8 = null,
    timeout_s: i64 = 300,

    pub const Captured = struct {
        port: u16,
        callback: CallbackData,
    };

    /// Bind 127.0.0.1:0, accept one callback, validate + exchange, respond.
    /// Untested by design (real socket I/O); the logic lives in the pure core.
    pub fn listenOnce(
        self: *const CallbackServerListener,
        pkce_verifier: [43]u8,
        state_nonce: [16]u8,
    ) !Captured {
        const loopback = try std.net.Address.parseIp("127.0.0.1", 0);
        var server = try loopback.listen(.{ .reuse_address = true });
        defer server.deinit();

        const port = server.listen_address.getPort();
        const redirect_uri = try std.fmt.allocPrint(
            self.allocator,
            "http://127.0.0.1:{d}/callback",
            .{port},
        );
        defer self.allocator.free(redirect_uri);

        const start = self.seams.clock(self.seams.clock_ctx);
        const deadline = start + self.timeout_s;

        var conn = try server.accept();
        defer conn.stream.close();

        var buf: [16 * 1024]u8 = undefined;
        const n = try conn.stream.read(&buf);
        const raw = buf[0..n];

        const line = parseRequestLine(raw) orelse return error.MissingCodeOrState;
        const host_header = parseHostHeader(raw) orelse "";

        const callback = try handleCallbackRequest(
            self.allocator,
            self.seams,
            line.method,
            line.target,
            host_header,
            state_nonce,
            pkce_verifier,
            self.expected_account_id,
            self.token_uri,
            self.client_id,
            self.client_secret,
            redirect_uri,
            deadline,
        );

        const resp = try renderSuccessResponse(self.allocator);
        defer self.allocator.free(resp);
        conn.stream.writeAll(resp) catch {};

        return .{ .port = port, .callback = callback };
    }
};

const RequestLine = struct { method: []const u8, target: []const u8 };

/// Parse "GET /callback?… HTTP/1.1" from the first line. Pure helper.
pub fn parseRequestLine(raw: []const u8) ?RequestLine {
    const eol = std.mem.indexOfScalar(u8, raw, '\r') orelse raw.len;
    var parts = std.mem.splitScalar(u8, raw[0..eol], ' ');
    const method = parts.next() orelse return null;
    const target = parts.next() orelse return null;
    if (method.len == 0 or target.len == 0) return null;
    return .{ .method = method, .target = target };
}

/// Extract the (case-insensitive) `Host` header value. Pure helper.
pub fn parseHostHeader(raw: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, raw, "\r\n");
    _ = lines.next(); // request line
    while (lines.next()) |line| {
        if (line.len == 0) break; // end of headers
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = line[0..colon];
        if (std.ascii.eqlIgnoreCase(name, "Host")) {
            return std.mem.trim(u8, line[colon + 1 ..], " \t");
        }
    }
    return null;
}
