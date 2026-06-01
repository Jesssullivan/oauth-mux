const std = @import("std");
const web_ui = @import("web_ui.zig");

const test_gpa = std.testing.allocator;

// Ensure every declaration in web_ui.zig is analyzed/compiled by the test run.
test {
    std.testing.refAllDeclsRecursive(web_ui);
}

// ════════════════════════════════════════════════════════════════════════════
// FAKE SEAMS FOR TESTING
//
// A fake token/secret is seeded into the account data so tests can assert it
// NEVER appears in any rendered output (HTML or JSON). The masked email hint is
// the ONLY identity-ish field allowed in output.
// ════════════════════════════════════════════════════════════════════════════

/// A secret that must never leak into UI/JSON output. Tests assert its absence.
const SEEDED_SECRET = "sk-live-DEADBEEFsecrettoken0xFEEDFACE";
/// A raw account id that must never leak into UI/JSON output either.
const SEEDED_ACCOUNT_ID = "raw-account-id-9f3c2b-DO-NOT-LEAK";

var test_accounts_data: [3]web_ui.AccountHealth = undefined;
var test_accounts_len: usize = 0;

fn fakeListAccounts(allocator: std.mem.Allocator) ![]web_ui.AccountHealth {
    const result = try allocator.alloc(web_ui.AccountHealth, test_accounts_len);
    @memcpy(result, test_accounts_data[0..test_accounts_len]);
    return result;
}

var fake_reauth_state: web_ui.ReauthState = .pending;
// Records the (provider, account) the most recent enqueue/poll was driven with,
// so index-selector resolution can be asserted.
var last_enqueue_provider: []const u8 = "";
var last_enqueue_account: []const u8 = "";

fn fakeEnqueueReauth(allocator: std.mem.Allocator, provider: []const u8, account: []const u8) !web_ui.ReauthJobHandle {
    last_enqueue_provider = provider;
    last_enqueue_account = account;
    const job_id = try allocator.dupe(u8, "job-test-123");
    // The handoff is operator-facing and intentionally carries NO secret token.
    const handoff = try allocator.dupe(u8, "device code ABC-123 -> https://verify.example.com");
    fake_reauth_state = .awaiting_device_code;
    return .{ .job_id = job_id, .handoff = handoff };
}

fn fakePollReauth(allocator: std.mem.Allocator, provider: []const u8, account: []const u8) !web_ui.ReauthState {
    _ = allocator;
    last_enqueue_provider = provider;
    last_enqueue_account = account;
    return fake_reauth_state;
}

fn fakeNow() i64 {
    return 1234567890;
}

fn makeTestSeams() web_ui.Seams {
    return .{
        .listAccounts = &fakeListAccounts,
        .enqueueReauth = &fakeEnqueueReauth,
        .pollReauth = &fakePollReauth,
        .now = &fakeNow,
    };
}

/// Assert neither the seeded secret nor the raw account id appears in `body`.
fn assertNoSecretLeak(body: []const u8) !void {
    try std.testing.expect(std.mem.indexOf(u8, body, SEEDED_SECRET) == null);
    try std.testing.expect(std.mem.indexOf(u8, body, SEEDED_ACCOUNT_ID) == null);
}

// ════════════════════════════════════════════════════════════════════════════
// ROUTING + RENDERING TESTS
// ════════════════════════════════════════════════════════════════════════════

test "GET / renders HTML dashboard" {
    test_accounts_data[0] = .{
        .provider = "claude",
        .account = SEEDED_ACCOUNT_ID,
        .route_state = "available",
        .email_hint_masked = "c***@example.com",
        .reauth_in_progress = false,
    };
    test_accounts_len = 1;

    const response = try web_ui.routeRequest(test_gpa, .GET, "/", "127.0.0.1:8080", makeTestSeams());
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "<html") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "oauth-mux") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "claude") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "c***@example.com") != null);
    try assertNoSecretLeak(response.body);
}

test "GET /api/accounts returns JSON with provider and state" {
    test_accounts_data[0] = .{
        .provider = "codex",
        .account = SEEDED_ACCOUNT_ID,
        .route_state = "credential_unavailable",
        .email_hint_masked = "s***@internal.com",
        .reauth_in_progress = true,
    };
    test_accounts_len = 1;

    const response = try web_ui.routeRequest(test_gpa, .GET, "/api/accounts", "localhost:8080", makeTestSeams());
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"provider\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"credential_unavailable\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"reauth_in_progress\":true") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "codex") != null);
    // REDACTION: no "account" field key, no raw account id, no token.
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"account\"") == null);
    try assertNoSecretLeak(response.body);
}

test "REDACTION: seeded token never appears in HTML or JSON" {
    // Stuff the secret into every plausible carrier field to prove the render
    // path emits only the allow-list. email_hint_masked is intentionally the
    // only identity field; we still keep it masked.
    test_accounts_data[0] = .{
        .provider = "claude",
        .account = SEEDED_ACCOUNT_ID,
        .route_state = "auth_permanently_failed",
        .email_hint_masked = "w***@company.com",
        .reauth_in_progress = false,
    };
    test_accounts_len = 1;

    const html = try web_ui.routeRequest(test_gpa, .GET, "/", "127.0.0.1", makeTestSeams());
    defer html.deinit();
    try assertNoSecretLeak(html.body);

    const json = try web_ui.routeRequest(test_gpa, .GET, "/api/accounts", "127.0.0.1", makeTestSeams());
    defer json.deinit();
    try assertNoSecretLeak(json.body);
    // The masked hint is allowed; the raw account id key is not.
    try std.testing.expect(std.mem.indexOf(u8, json.body, "w***@company.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, json.body, "\"account\"") == null);
}

// ════════════════════════════════════════════════════════════════════════════
// SECURITY: ANTI-DNS-REBINDING (HARD INVARIANT)
// ════════════════════════════════════════════════════════════════════════════

test "403 Forbidden for non-loopback Host header" {
    test_accounts_len = 0;
    const response = try web_ui.routeRequest(test_gpa, .GET, "/", "evil.example.com:8080", makeTestSeams());
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 403), response.status);
}

test "403 for DNS-rebinding suffix-bypass attempts" {
    test_accounts_len = 0;
    // These would all pass a naive startsWith() check but must be rejected.
    const hostile = [_][]const u8{
        "127.0.0.1.evil.com",
        "127.0.0.1.evil.com:8080",
        "localhost.evil.com",
        "localhost.evil.com:8080",
        "127.0.0.1x",
        "localhostx",
        "10.0.0.5",
        "0.0.0.0",
        "",
        "example.com",
    };
    for (hostile) |h| {
        const response = try web_ui.routeRequest(test_gpa, .GET, "/", h, makeTestSeams());
        defer response.deinit();
        try std.testing.expectEqual(@as(u16, 403), response.status);
    }
}

test "loopback hosts accepted with and without port" {
    test_accounts_len = 0;
    const ok = [_][]const u8{ "127.0.0.1", "127.0.0.1:8080", "localhost", "localhost:3000" };
    for (ok) |h| {
        const response = try web_ui.routeRequest(test_gpa, .GET, "/healthz", h, makeTestSeams());
        defer response.deinit();
        try std.testing.expectEqual(@as(u16, 200), response.status);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// REAUTH (single-flight enqueue, poll, index-selector resolution)
// ════════════════════════════════════════════════════════════════════════════

test "POST /reauth/{provider}/{account} enqueues job" {
    // Literal-account selector form (documented follow-up route).
    test_accounts_len = 0;
    const response = try web_ui.routeRequest(test_gpa, .POST, "/reauth/claude/user-123", "127.0.0.1:8080", makeTestSeams());
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"job_id\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "job-test-123") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"handoff\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"state\":\"pending\"") != null);
    try std.testing.expectEqualStrings("claude", last_enqueue_provider);
    try std.testing.expectEqualStrings("user-123", last_enqueue_account);
}

test "POST /reauth index selector resolves to real account server-side" {
    // The board emits a numeric index; the handler resolves it to the raw
    // account via the seam list. The raw account id is what the seam receives,
    // but it never appears in any rendered output (asserted elsewhere).
    test_accounts_data[0] = .{
        .provider = "claude",
        .account = SEEDED_ACCOUNT_ID,
        .route_state = "rate_limited",
        .email_hint_masked = "c***@example.com",
        .reauth_in_progress = false,
    };
    test_accounts_len = 1;

    const response = try web_ui.routeRequest(test_gpa, .POST, "/reauth/claude/0", "127.0.0.1:8080", makeTestSeams());
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expectEqualStrings("claude", last_enqueue_provider);
    try std.testing.expectEqualStrings(SEEDED_ACCOUNT_ID, last_enqueue_account);
    // The response handed to the operator carries no secret/account leak.
    try assertNoSecretLeak(response.body);
}

test "POST /reauth index out of range returns 404" {
    test_accounts_len = 0;
    const response = try web_ui.routeRequest(test_gpa, .POST, "/reauth/claude/7", "127.0.0.1:8080", makeTestSeams());
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 404), response.status);
}

test "POST /reauth index provider mismatch returns 404" {
    test_accounts_data[0] = .{
        .provider = "claude",
        .account = SEEDED_ACCOUNT_ID,
        .route_state = "rate_limited",
        .email_hint_masked = "c***@example.com",
        .reauth_in_progress = false,
    };
    test_accounts_len = 1;
    // index 0 exists, but its provider is "claude", not "codex".
    const response = try web_ui.routeRequest(test_gpa, .POST, "/reauth/codex/0", "127.0.0.1:8080", makeTestSeams());
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 404), response.status);
}

test "POST /reauth malformed path returns 400" {
    test_accounts_len = 0;
    const bad = [_][]const u8{ "/reauth/", "/reauth/claude", "/reauth/claude/", "/reauth//x" };
    for (bad) |p| {
        const response = try web_ui.routeRequest(test_gpa, .POST, p, "127.0.0.1:8080", makeTestSeams());
        defer response.deinit();
        try std.testing.expectEqual(@as(u16, 400), response.status);
    }
}

test "GET /reauth/{provider}/{account} polls job state" {
    test_accounts_len = 0;
    fake_reauth_state = .in_progress;
    const response = try web_ui.routeRequest(test_gpa, .GET, "/reauth/claude/user-123", "127.0.0.1:8080", makeTestSeams());
    defer response.deinit();

    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"in_progress\"") != null);
}

test "reauth state transitions rendered in poll responses" {
    test_accounts_len = 0;
    const states = [_]web_ui.ReauthState{
        .pending,
        .awaiting_device_code,
        .awaiting_user_confirmation,
        .in_progress,
        .success,
        .failed,
    };
    for (states) |state| {
        fake_reauth_state = state;
        const response = try web_ui.routeRequest(test_gpa, .GET, "/reauth/test/literal-acct", "127.0.0.1:8080", makeTestSeams());
        defer response.deinit();
        try std.testing.expectEqual(@as(u16, 200), response.status);
        try std.testing.expect(std.mem.indexOf(u8, response.body, state.toString()) != null);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// CALLBACK
// ════════════════════════════════════════════════════════════════════════════

test "GET /callback with code+state returns 200" {
    test_accounts_len = 0;
    const response = try web_ui.routeRequest(test_gpa, .GET, "/callback?code=abc123&state=xyz789", "127.0.0.1:8080", makeTestSeams());
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status);
}

test "GET /callback missing code or state returns 400" {
    test_accounts_len = 0;
    const bad = [_][]const u8{
        "/callback",
        "/callback?code=abc123",
        "/callback?state=xyz789",
        "/callback?code=&state=xyz789",
        "/callback?code=abc123&state=",
    };
    for (bad) |target| {
        const response = try web_ui.routeRequest(test_gpa, .GET, target, "127.0.0.1:8080", makeTestSeams());
        defer response.deinit();
        try std.testing.expectEqual(@as(u16, 400), response.status);
    }
}

// ════════════════════════════════════════════════════════════════════════════
// LIVENESS + ROUTING EDGES
// ════════════════════════════════════════════════════════════════════════════

test "GET /healthz returns 200 OK" {
    test_accounts_len = 0;
    const response = try web_ui.routeRequest(test_gpa, .GET, "/healthz", "127.0.0.1:8080", makeTestSeams());
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expect(std.mem.eql(u8, response.body, "OK"));
}

test "GET /nonexistent returns 404" {
    test_accounts_len = 0;
    const response = try web_ui.routeRequest(test_gpa, .GET, "/nonexistent", "127.0.0.1:8080", makeTestSeams());
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 404), response.status);
}

test "POST to GET-only route falls through to 404" {
    test_accounts_len = 0;
    const response = try web_ui.routeRequest(test_gpa, .POST, "/healthz", "127.0.0.1:8080", makeTestSeams());
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 404), response.status);
}

// ════════════════════════════════════════════════════════════════════════════
// BOARD CONTENT
// ════════════════════════════════════════════════════════════════════════════

test "multiple accounts return provider and route_state" {
    test_accounts_data[0] = .{
        .provider = "claude",
        .account = "account-1",
        .route_state = "available",
        .email_hint_masked = "c***@example.com",
        .reauth_in_progress = false,
    };
    test_accounts_data[1] = .{
        .provider = "codex",
        .account = "account-2",
        .route_state = "credential_unavailable",
        .email_hint_masked = "d***@example.com",
        .reauth_in_progress = true,
    };
    test_accounts_len = 2;

    const response = try web_ui.routeRequest(test_gpa, .GET, "/api/accounts", "127.0.0.1:8080", makeTestSeams());
    defer response.deinit();

    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"claude\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"codex\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"available\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "\"credential_unavailable\"") != null);
}

test "HTML shows re-login + identity reminder only for accounts needing reauth" {
    test_accounts_data[0] = .{
        .provider = "claude",
        .account = "good-user",
        .route_state = "available",
        .email_hint_masked = "g***@example.com",
        .reauth_in_progress = false,
    };
    test_accounts_data[1] = .{
        .provider = "codex",
        .account = "bad-user",
        .route_state = "auth_permanently_failed",
        .email_hint_masked = "b***@example.com",
        .reauth_in_progress = false,
    };
    test_accounts_len = 2;

    const response = try web_ui.routeRequest(test_gpa, .GET, "/", "127.0.0.1:8080", makeTestSeams());
    defer response.deinit();
    const body = response.body;

    try std.testing.expect(std.mem.indexOf(u8, body, "g***@example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "b***@example.com") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "claude") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "codex") != null);
    // Exactly one Re-login button: only the failed account gets one.
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, body, ">Re-login</button>"));
    // The cookieless private-window reminder is server-rendered.
    try std.testing.expect(std.mem.indexOf(u8, body, "PRIVATE / INCOGNITO") != null);
}

test "HTML shows in-progress spinner when a job holds the account" {
    test_accounts_data[0] = .{
        .provider = "claude",
        .account = "busy-user",
        .route_state = "revalidation_needed",
        .email_hint_masked = "b***@example.com",
        .reauth_in_progress = true,
    };
    test_accounts_len = 1;

    const response = try web_ui.routeRequest(test_gpa, .GET, "/", "127.0.0.1:8080", makeTestSeams());
    defer response.deinit();
    const body = response.body;

    try std.testing.expect(std.mem.indexOf(u8, body, "spinner") != null);
    try std.testing.expect(std.mem.indexOf(u8, body, "data-reauth=\"in_progress\"") != null);
    // No re-login button while a job already holds the account.
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, body, ">Re-login</button>"));
}

test "empty account list renders empty-state board" {
    test_accounts_len = 0;
    const response = try web_ui.routeRequest(test_gpa, .GET, "/", "127.0.0.1:8080", makeTestSeams());
    defer response.deinit();
    try std.testing.expectEqual(@as(u16, 200), response.status);
    try std.testing.expect(std.mem.indexOf(u8, response.body, "No accounts configured") != null);
}

test "empty account list returns empty JSON array" {
    test_accounts_len = 0;
    const response = try web_ui.routeRequest(test_gpa, .GET, "/api/accounts", "127.0.0.1:8080", makeTestSeams());
    defer response.deinit();
    try std.testing.expectEqualStrings("[]", response.body);
}

test "HttpMethod.fromString parses GET/POST and rejects others" {
    try std.testing.expectEqual(web_ui.HttpMethod.GET, web_ui.HttpMethod.fromString("GET").?);
    try std.testing.expectEqual(web_ui.HttpMethod.POST, web_ui.HttpMethod.fromString("POST").?);
    try std.testing.expect(web_ui.HttpMethod.fromString("DELETE") == null);
    try std.testing.expect(web_ui.HttpMethod.fromString("get") == null);
}

// ════════════════════════════════════════════════════════════════════════════
// LISTENER HELPERS (pure parts of the thin wrapper; serve() itself is untested)
// ════════════════════════════════════════════════════════════════════════════

test "parseRequest extracts method, target, and Host header" {
    const raw = "GET /api/accounts HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nAccept: */*\r\n\r\n";
    const parsed = web_ui.parseRequest(raw).?;
    try std.testing.expectEqual(web_ui.HttpMethod.GET, parsed.method);
    try std.testing.expectEqualStrings("/api/accounts", parsed.target);
    try std.testing.expectEqualStrings("127.0.0.1:8080", parsed.host);
}

test "parseRequest is case-insensitive for the Host header name" {
    const raw = "POST /reauth/claude/0 HTTP/1.1\r\nhOsT: localhost\r\n\r\n";
    const parsed = web_ui.parseRequest(raw).?;
    try std.testing.expectEqual(web_ui.HttpMethod.POST, parsed.method);
    try std.testing.expectEqualStrings("localhost", parsed.host);
}

test "parseRequest rejects unsupported methods and junk" {
    try std.testing.expect(web_ui.parseRequest("DELETE / HTTP/1.1\r\n\r\n") == null);
    try std.testing.expect(web_ui.parseRequest("garbage") == null);
}

test "serializeResponse emits an HTTP/1.1 message with content-length" {
    const resp = web_ui.Response{
        .status = 404,
        .content_type = "text/plain",
        .body = try test_gpa.dupe(u8, "nope"),
        .allocator = test_gpa,
    };
    defer resp.deinit();
    const wire = try web_ui.serializeResponse(test_gpa, resp);
    defer test_gpa.free(wire);
    try std.testing.expect(std.mem.startsWith(u8, wire, "HTTP/1.1 404 Not Found\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, wire, "Content-Length: 4\r\n") != null);
    try std.testing.expect(std.mem.endsWith(u8, wire, "\r\n\r\nnope"));
}
