//! Claude (Claude Code) reauth adapter — greenfield, provider-specific OAuth.
//!
//! The first NON-Codex adapter: the Claude-specific pieces of a re-login flow,
//! plugging into the flow-agnostic reauth engine (#344) and the loopback PKCE
//! callback server (#349). Claude Code authenticates with **OAuth 2.1 loopback
//! PKCE (S256)** — the SAME shape #349 already captures — so this module owns
//! only what is Claude-specific: the verified endpoints + public client id, the
//! authorize-URL / token-exchange / refresh request builders, parsing the token
//! endpoint response, and materializing the `~/.claude/.credentials.json`
//! (`claudeAiOauth`) credential shape.
//!
//! Verified 2026-06-01 (code.claude.com/docs/en/authentication, cedws
//! ANTHROPIC_AUTH gist, querymt/anthropic-auth, anthropics/claude-code #39445):
//!   * authorize  https://console.anthropic.com/oauth/authorize
//!   * token      https://console.anthropic.com/v1/oauth/token   (exchange + refresh)
//!   * client_id  9d1c250a-e61b-44d9-88ed-5944d1962f5e           (Claude Code public client)
//!   * loopback PKCE S256, ephemeral 127.0.0.1/localhost callback (NOT device_code)
//!   * credential ~/.claude/.credentials.json (0600):
//!       {"claudeAiOauth":{"accessToken":"sk-ant-oat01-…","refreshToken":"sk-ant-ort01-…",
//!        "expiresAt":<unix MILLISECONDS>,"scopes":[…],"subscriptionType":"max"}}
//! NOTE: the declarative `claude_def` (src/provider_schema.zig) and `oauth.zig`
//! now carry the correct `console.anthropic.com/v1/oauth/token` endpoint and a
//! matching client_id — verified consistent with the constants below. On
//! integration the duplicated constants here should collapse to that single
//! source of truth (de-dup of the PKCE/percent-encode helpers with #349 too).
//!
//! Shape mirrors the engine/web-UI/callback siblings: a PURE provider core (the
//! builders/parsers) plus a thin `ClaudeReauthAdapter` over an INJECTED HTTP
//! seam, so the whole module is unit-testable with `std.testing.allocator`
//! (leak-checked) and no real network. Self-contained: `std` only, no `@import`
//! of existing `src`. The `percentEncode`/`deriveChallenge` helpers intentionally
//! mirror callback_server.zig (#349); they de-dup into a shared oauth/http util
//! on integration.

const std = @import("std");

// ── Verified Claude OAuth constants ────────────────────────────────────────

pub const authorize_endpoint = "https://console.anthropic.com/oauth/authorize";
pub const token_endpoint = "https://console.anthropic.com/v1/oauth/token";
pub const default_client_id = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";
/// Scopes confirmed in the credential `scopes` array; `org:create_api_key` may
/// also be requested by Claude Code — verify against a live account if needed.
pub const default_scopes = "user:inference user:profile";
pub const form_content_type = "application/x-www-form-urlencoded";

pub const access_token_prefix = "sk-ant-oat01-";
pub const refresh_token_prefix = "sk-ant-ort01-";

// ── Token model ────────────────────────────────────────────────────────────

/// Claude tokens in the broker's normalized form. `expires_at_ms` is an ABSOLUTE
/// Unix-millisecond instant (the token endpoint returns relative `expires_in`
/// seconds; the credential file stores absolute `expiresAt` ms — both normalize
/// here). Caller owns every slice; free with `freeTokens`.
pub const ClaudeTokens = struct {
    access_token: []const u8,
    refresh_token: []const u8,
    expires_at_ms: i64,
    /// Space-joined scope string (as the OAuth `scope` field), or null.
    scopes: ?[]const u8 = null,
    subscription_type: ?[]const u8 = null,
};

pub fn freeTokens(allocator: std.mem.Allocator, t: ClaudeTokens) void {
    allocator.free(t.access_token);
    allocator.free(t.refresh_token);
    if (t.scopes) |s| allocator.free(s);
    if (t.subscription_type) |s| allocator.free(s);
}

pub const ParseError = error{ OutOfMemory, ParseFailed };

/// True if the access token is at/after expiry (with `skew_ms` early margin) —
/// the predicate a keepalive scheduler uses to decide a proactive refresh.
pub fn isAccessTokenExpired(t: ClaudeTokens, now_ms: i64, skew_ms: i64) bool {
    return now_ms + skew_ms >= t.expires_at_ms;
}

pub fn looksLikeAccessToken(s: []const u8) bool {
    return std.mem.startsWith(u8, s, access_token_prefix);
}
pub fn looksLikeRefreshToken(s: []const u8) bool {
    return std.mem.startsWith(u8, s, refresh_token_prefix);
}

// ── Pure request builders ──────────────────────────────────────────────────

/// Claude authorize URL (EMITTED to the operator, never auto-opened — the
/// operator picks the isolated/private browser, guaranteeing the right identity
/// for multi-account users). `challenge` is the PKCE S256 challenge; `state` is
/// the caller's CSRF value (e.g. base64url(nonce)).
pub fn buildAuthorizeUrl(
    allocator: std.mem.Allocator,
    client_id: []const u8,
    scopes: []const u8,
    redirect_uri: []const u8,
    challenge: [43]u8,
    state: []const u8,
) ![]u8 {
    const enc_cid = try percentEncode(allocator, client_id);
    defer allocator.free(enc_cid);
    const enc_redirect = try percentEncode(allocator, redirect_uri);
    defer allocator.free(enc_redirect);
    const enc_scope = try percentEncode(allocator, scopes);
    defer allocator.free(enc_scope);
    const enc_state = try percentEncode(allocator, state);
    defer allocator.free(enc_state);
    return std.fmt.allocPrint(
        allocator,
        "{s}?response_type=code&client_id={s}&redirect_uri={s}" ++
            "&scope={s}&state={s}&code_challenge={s}&code_challenge_method=S256",
        .{ authorize_endpoint, enc_cid, enc_redirect, enc_scope, enc_state, challenge[0..] },
    );
}

/// Form body for the authorization-code → token exchange POST. The PKCE verifier
/// is base64url (URL-safe) so it is emitted verbatim; it is never logged here.
pub fn buildTokenExchangeBody(
    allocator: std.mem.Allocator,
    client_id: []const u8,
    code: []const u8,
    code_verifier: [43]u8,
    redirect_uri: []const u8,
) ![]u8 {
    const enc_code = try percentEncode(allocator, code);
    defer allocator.free(enc_code);
    const enc_redirect = try percentEncode(allocator, redirect_uri);
    defer allocator.free(enc_redirect);
    const enc_cid = try percentEncode(allocator, client_id);
    defer allocator.free(enc_cid);
    return std.fmt.allocPrint(
        allocator,
        "grant_type=authorization_code&code={s}&redirect_uri={s}&client_id={s}&code_verifier={s}",
        .{ enc_code, enc_redirect, enc_cid, code_verifier[0..] },
    );
}

/// Form body for the refresh-token grant POST.
pub fn buildRefreshBody(
    allocator: std.mem.Allocator,
    client_id: []const u8,
    refresh_token: []const u8,
) ![]u8 {
    const enc_rt = try percentEncode(allocator, refresh_token);
    defer allocator.free(enc_rt);
    const enc_cid = try percentEncode(allocator, client_id);
    defer allocator.free(enc_cid);
    return std.fmt.allocPrint(
        allocator,
        "grant_type=refresh_token&refresh_token={s}&client_id={s}",
        .{ enc_rt, enc_cid },
    );
}

// ── Pure parsers ───────────────────────────────────────────────────────────

const TokenWire = struct {
    access_token: []const u8,
    refresh_token: []const u8 = "",
    expires_in: i64 = 0,
    scope: []const u8 = "",
    token_type: []const u8 = "",
};

/// Parse the OAuth token-endpoint JSON response. `expires_in` (relative seconds)
/// is normalized to an absolute `expires_at_ms` using the injected `now_ms`.
pub fn parseTokenEndpointResponse(
    allocator: std.mem.Allocator,
    json: []const u8,
    now_ms: i64,
) ParseError!ClaudeTokens {
    var parsed = std.json.parseFromSlice(TokenWire, allocator, json, .{ .ignore_unknown_fields = true }) catch |e| {
        return if (e == error.OutOfMemory) error.OutOfMemory else error.ParseFailed;
    };
    defer parsed.deinit();
    const w = parsed.value;
    if (w.access_token.len == 0) return error.ParseFailed;
    if (w.expires_in < 0) return error.ParseFailed; // nonsensical relative TTL

    // Seconds→ms with CHECKED arithmetic (computed before any alloc so an error
    // can't leak): a hostile or proxied token endpoint can return an `expires_in`
    // large enough that `now_ms + expires_in*1000` would overflow i64 and PANIC
    // the process in Debug/ReleaseSafe — the parser must reject, not crash.
    const delta_ms = std.math.mul(i64, w.expires_in, std.time.ms_per_s) catch return error.ParseFailed;
    const expires_at_ms = std.math.add(i64, now_ms, delta_ms) catch return error.ParseFailed;

    const access = try allocator.dupe(u8, w.access_token);
    errdefer allocator.free(access);
    const refresh = try allocator.dupe(u8, w.refresh_token);
    errdefer allocator.free(refresh);
    const scopes = if (w.scope.len > 0) try allocator.dupe(u8, w.scope) else null;

    return .{
        .access_token = access,
        .refresh_token = refresh,
        .expires_at_ms = expires_at_ms,
        .scopes = scopes,
        .subscription_type = null,
    };
}

const CredInner = struct {
    accessToken: []const u8,
    refreshToken: []const u8 = "",
    expiresAt: i64 = 0,
    subscriptionType: []const u8 = "",
};
const CredOuter = struct { claudeAiOauth: CredInner };

/// Parse an existing `~/.claude/.credentials.json` (`claudeAiOauth`) file.
/// `expiresAt` is already absolute Unix ms. (scopes array is ignored on read.)
pub fn parseCredentialJson(allocator: std.mem.Allocator, json: []const u8) ParseError!ClaudeTokens {
    var parsed = std.json.parseFromSlice(CredOuter, allocator, json, .{ .ignore_unknown_fields = true }) catch |e| {
        return if (e == error.OutOfMemory) error.OutOfMemory else error.ParseFailed;
    };
    defer parsed.deinit();
    const c = parsed.value.claudeAiOauth;
    if (c.accessToken.len == 0) return error.ParseFailed;

    const access = try allocator.dupe(u8, c.accessToken);
    errdefer allocator.free(access);
    const refresh = try allocator.dupe(u8, c.refreshToken);
    errdefer allocator.free(refresh);
    const sub = if (c.subscriptionType.len > 0) try allocator.dupe(u8, c.subscriptionType) else null;

    return .{
        .access_token = access,
        .refresh_token = refresh,
        .expires_at_ms = c.expiresAt,
        .scopes = null,
        .subscription_type = sub,
    };
}

/// Serialize tokens to the Claude credential file shape (`claudeAiOauth`).
/// Emitted via `std.json.stringify`, so every string field is correctly JSON-
/// escaped — a `"` or `\` in a token/scope/subscriptionType can never inject a
/// sibling key or produce invalid JSON, regardless of where the value came from.
pub fn buildCredentialJson(allocator: std.mem.Allocator, t: ClaudeTokens) ![]u8 {
    // Space-separated scopes → a JSON array of strings.
    var scope_list = std.ArrayList([]const u8).init(allocator);
    defer scope_list.deinit();
    if (t.scopes) |sc| {
        var it = std.mem.splitScalar(u8, sc, ' ');
        while (it.next()) |s| {
            if (s.len != 0) try scope_list.append(s);
        }
    }

    const Out = struct {
        claudeAiOauth: struct {
            accessToken: []const u8,
            refreshToken: []const u8,
            expiresAt: i64,
            scopes: []const []const u8,
            subscriptionType: []const u8,
        },
    };
    const out = Out{ .claudeAiOauth = .{
        .accessToken = t.access_token,
        .refreshToken = t.refresh_token,
        .expiresAt = t.expires_at_ms,
        .scopes = scope_list.items,
        .subscriptionType = t.subscription_type orelse "",
    } };

    var buf = std.ArrayList(u8).init(allocator);
    errdefer buf.deinit();
    try std.json.stringify(out, .{}, buf.writer());
    return buf.toOwnedSlice();
}

// ── Adapter over an injected HTTP seam ─────────────────────────────────────

pub const HttpError = error{ OutOfMemory, HttpFailed };

/// POST `body` to `url` and return the freshly-allocated response body.
pub const HttpPostFn = *const fn (
    allocator: std.mem.Allocator,
    ctx: *anyopaque,
    url: []const u8,
    body: []const u8,
    content_type: []const u8,
) HttpError![]u8;

pub const ClaudeReauthError = error{ OutOfMemory, ExchangeFailed, RefreshFailed };

/// The Claude reauth adapter: provider config + an injected HTTP seam. Composes
/// with the engine (#344) + callback server (#349): the engine emits
/// `authorizeUrl`, #349 captures the loopback callback, then `exchangeCode`
/// turns the code into tokens and `materialize` writes the credential file.
pub const ClaudeReauthAdapter = struct {
    http_post: HttpPostFn,
    http_ctx: *anyopaque,
    client_id: []const u8 = default_client_id,
    scopes: []const u8 = default_scopes,

    pub fn authorizeUrl(
        self: *const ClaudeReauthAdapter,
        allocator: std.mem.Allocator,
        redirect_uri: []const u8,
        challenge: [43]u8,
        state: []const u8,
    ) ![]u8 {
        return buildAuthorizeUrl(allocator, self.client_id, self.scopes, redirect_uri, challenge, state);
    }

    pub fn exchangeCode(
        self: *const ClaudeReauthAdapter,
        allocator: std.mem.Allocator,
        code: []const u8,
        code_verifier: [43]u8,
        redirect_uri: []const u8,
        now_ms: i64,
    ) ClaudeReauthError!ClaudeTokens {
        const body = buildTokenExchangeBody(allocator, self.client_id, code, code_verifier, redirect_uri) catch
            return error.OutOfMemory;
        defer allocator.free(body);
        return self.post(allocator, body, now_ms, error.ExchangeFailed);
    }

    pub fn refresh(
        self: *const ClaudeReauthAdapter,
        allocator: std.mem.Allocator,
        refresh_token: []const u8,
        now_ms: i64,
    ) ClaudeReauthError!ClaudeTokens {
        const body = buildRefreshBody(allocator, self.client_id, refresh_token) catch
            return error.OutOfMemory;
        defer allocator.free(body);
        return self.post(allocator, body, now_ms, error.RefreshFailed);
    }

    fn post(
        self: *const ClaudeReauthAdapter,
        allocator: std.mem.Allocator,
        body: []const u8,
        now_ms: i64,
        fail: ClaudeReauthError,
    ) ClaudeReauthError!ClaudeTokens {
        const resp = self.http_post(allocator, self.http_ctx, token_endpoint, body, form_content_type) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.HttpFailed => return fail,
        };
        defer allocator.free(resp);
        return parseTokenEndpointResponse(allocator, resp, now_ms) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.ParseFailed => return fail,
        };
    }

    /// Serialize the exchanged/refreshed tokens to the credential file content.
    pub fn materialize(self: *const ClaudeReauthAdapter, allocator: std.mem.Allocator, t: ClaudeTokens) ![]u8 {
        _ = self;
        return buildCredentialJson(allocator, t);
    }
};

// ── Small shared helpers (mirror callback_server.zig #349) ─────────────────

fn isUnreserved(c: u8) bool {
    return (c >= 'A' and c <= 'Z') or
        (c >= 'a' and c <= 'z') or
        (c >= '0' and c <= '9') or
        c == '-' or c == '_' or c == '.' or c == '~';
}

/// RFC 3986 percent-encoding (unreserved set passes through).
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

/// PKCE S256 challenge for a verifier — base64url(SHA256(verifier)). Mirrors
/// `oauth.generatePkce` / callback_server.zig.
pub fn deriveChallenge(verifier: [43]u8) [43]u8 {
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(verifier[0..], &hash, .{});
    var challenge: [43]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(challenge[0..], hash[0..]);
    return challenge;
}
