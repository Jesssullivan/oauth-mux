const std = @import("std");

// ────────────────────────────────────────────────────────────────────────────
// MINIMAL SEAM INTERFACES FOR WEB UI
// These are defined locally and SELF-CONTAINED. Integration with real
// reauth engine (src/enroll/reauth.zig) is a coordinated follow-up (PR #344).
// ────────────────────────────────────────────────────────────────────────────

/// Per-account health row data (already redacted by the seam provider).
/// Only fields safe for UI/JSON output (no raw tokens, no raw account_id).
pub const AccountHealth = struct {
    provider: []const u8,
    account: []const u8,
    /// Route-state label: "available", "rate_limited", "quota_exhausted",
    /// "tier_insufficient", "auth_permanently_failed", "credential_unavailable",
    /// "revalidation_needed"
    route_state: []const u8,
    /// Masked email hint (e.g. "j***@example.com"), or null if unavailable.
    email_hint_masked: ?[]const u8 = null,
    /// Whether a reauth job is currently in-flight for this account.
    reauth_in_progress: bool = false,
};

/// Reauth state machine label.
pub const ReauthState = enum {
    pending,
    awaiting_device_code,
    awaiting_user_confirmation,
    in_progress,
    success,
    failed,

    pub fn toString(self: ReauthState) []const u8 {
        return switch (self) {
            .pending => "pending",
            .awaiting_device_code => "awaiting_device_code",
            .awaiting_user_confirmation => "awaiting_user_confirmation",
            .in_progress => "in_progress",
            .success => "success",
            .failed => "failed",
        };
    }
};

/// Job handle returned by enqueueReauth.
pub const ReauthJobHandle = struct {
    job_id: []const u8,
    handoff: []const u8, // device code+URL or authorize URL
};

/// Seam interface: pure function pointers injected at runtime.
pub const Seams = struct {
    /// List all accounts with their health (no-spend, already redacted).
    listAccounts: *const fn (allocator: std.mem.Allocator) std.mem.Allocator.Error![]AccountHealth,

    /// Enqueue or join a reauth job for provider:account.
    enqueueReauth: *const fn (allocator: std.mem.Allocator, provider: []const u8, account: []const u8) std.mem.Allocator.Error!ReauthJobHandle,

    /// Poll reauth state for provider:account.
    pollReauth: *const fn (allocator: std.mem.Allocator, provider: []const u8, account: []const u8) std.mem.Allocator.Error!ReauthState,

    /// Current unix timestamp (seconds).
    now: *const fn () i64,
};

// ────────────────────────────────────────────────────────────────────────────
// HTTP REQUEST/RESPONSE TYPES
// ────────────────────────────────────────────────────────────────────────────

pub const HttpMethod = enum {
    GET,
    POST,
    pub fn fromString(s: []const u8) ?HttpMethod {
        if (std.mem.eql(u8, s, "GET")) return .GET;
        if (std.mem.eql(u8, s, "POST")) return .POST;
        return null;
    }
};

pub const Response = struct {
    status: u16,
    content_type: []const u8,
    body: []const u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: Response) void {
        self.allocator.free(self.body);
    }
};

// ────────────────────────────────────────────────────────────────────────────
// HTML / JSON RENDERING
// ────────────────────────────────────────────────────────────────────────────

fn renderAccountHealthHtml(allocator: std.mem.Allocator, accounts: []const AccountHealth) std.mem.Allocator.Error![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    try buf.appendSlice(
        \\<!DOCTYPE html>
        \\<html lang="en">
        \\<head>
        \\  <meta charset="UTF-8">
        \\  <meta name="viewport" content="width=device-width, initial-scale=1.0">
        \\  <title>oauth-mux Operator Console</title>
        \\  <style>
        \\    * { margin: 0; padding: 0; box-sizing: border-box; }
        \\    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f5f5f5; padding: 20px; }
        \\    .container { max-width: 1200px; margin: 0 auto; background: white; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); padding: 40px; }
        \\    h1 { color: #333; margin-bottom: 30px; }
        \\    .account-grid { display: grid; gap: 20px; }
        \\    .account-card { border: 1px solid #e0e0e0; border-radius: 6px; padding: 20px; transition: all 0.2s; }
        \\    .account-card:hover { box-shadow: 0 4px 12px rgba(0,0,0,0.08); }
        \\    .account-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        \\    .account-title { font-size: 18px; font-weight: 600; color: #1a1a1a; }
        \\    .account-subtitle { color: #666; font-size: 14px; margin-top: 4px; }
        \\    .route-state { display: inline-block; padding: 4px 12px; border-radius: 4px; font-size: 12px; font-weight: 600; }
        \\    .route-state.available { background: #c8e6c9; color: #2e7d32; }
        \\    .route-state.rate_limited { background: #fff3cd; color: #856404; }
        \\    .route-state.quota_exhausted { background: #fff3cd; color: #856404; }
        \\    .route-state.revalidation_needed { background: #fff3cd; color: #856404; }
        \\    .route-state.tier_insufficient { background: #ffccbc; color: #d84315; }
        \\    .route-state.auth_permanently_failed { background: #ffcdd2; color: #c62828; }
        \\    .route-state.credential_unavailable { background: #ffcdd2; color: #c62828; }
        \\    .account-actions { margin-top: 15px; display: flex; gap: 10px; }
        \\    button { padding: 8px 16px; border: none; border-radius: 4px; font-size: 14px; cursor: pointer; font-weight: 500; transition: all 0.2s; }
        \\    .btn-primary { background: #1976d2; color: white; }
        \\    .btn-primary:hover { background: #1565c0; }
        \\    .btn-primary:disabled { background: #ccc; cursor: not-allowed; }
        \\    .spinner { display: inline-block; width: 14px; height: 14px; border: 2px solid #ccc; border-top: 2px solid #1976d2; border-radius: 50%; animation: spin 0.6s linear infinite; }
        \\    @keyframes spin { to { transform: rotate(360deg); } }
        \\    .status-badge { display: inline-block; margin-left: 8px; }
        \\    .reauth-hint { color: #856404; font-size: 13px; margin-left: 8px; }
        \\    .empty-state { text-align: center; color: #999; padding: 40px 20px; }
        \\  </style>
        \\</head>
        \\<body>
        \\  <div class="container">
        \\    <h1>oauth-mux Operator Console</h1>
        \\    <div class="account-grid">
    );

    // REDACTION: the rendered board emits ONLY allow-listed fields:
    //   - provider (label)
    //   - email_hint_masked (masked hint)
    //   - route_state (label)
    //   - reauth_in_progress (boolean-derived UI state)
    // The raw account_id (acc.account) is NEVER rendered as visible text. The
    // re-login action targets the row's *index* (a non-identifying selector);
    // the POST handler resolves index -> account server-side via the seam list.
    for (accounts, 0..) |acc, idx| {
        try buf.writer().print(
            \\      <div class="account-card">
            \\        <div class="account-header">
            \\          <div>
            \\            <div class="account-title">{s}</div>
            \\            <div class="account-subtitle">{s}</div>
            \\          </div>
            \\          <span class="route-state {s}">{s}</span>
            \\        </div>
            , .{
                acc.provider,
                if (acc.email_hint_masked) |hint| hint else "(email unavailable)",
                acc.route_state,
                acc.route_state,
            }
        );

        if (acc.reauth_in_progress) {
            try buf.appendSlice(
                \\        <div class="status-badge" data-reauth="in_progress">
                \\          <span class="spinner"></span> Re-login in progress &mdash; complete it in a PRIVATE / INCOGNITO window.
                \\        </div>
            );
        } else if (!std.mem.eql(u8, acc.route_state, "available")) {
            // Confirm-identity reminder is server-rendered so the operator sees
            // the intended provider + masked identity before driving re-login,
            // and is reminded to use a private/incognito window (cookieless).
            try buf.writer().print(
                \\        <div class="account-actions">
                \\          <button class="btn-primary" onclick="startReauth('{s}', {d})">Re-login</button>
                \\          <span class="reauth-hint">Confirm identity <strong>{s}:{s}</strong> and use a PRIVATE / INCOGNITO window.</span>
                \\        </div>
                , .{
                    acc.provider,
                    idx,
                    acc.provider,
                    if (acc.email_hint_masked) |hint| hint else "(email unavailable)",
                }
            );
        }

        try buf.appendSlice("      </div>\n");
    }

    if (accounts.len == 0) {
        try buf.appendSlice(
            \\      <div class="empty-state">
            \\        <p>No accounts configured.</p>
            \\      </div>
        );
    }

    try buf.appendSlice(
        \\    </div>
        \\  </div>
        \\  <script>
        \\    // The "selector" is a non-identifying row index; the server resolves
        \\    // it back to the real account. The raw account id never reaches the DOM.
        \\    async function startReauth(provider, selector) {
        \\      try {
        \\        const response = await fetch(`/reauth/${provider}/${selector}`, { method: 'POST' });
        \\        const data = await response.json();
        \\        if (data.job_id && data.handoff) {
        \\          alert(`Use a PRIVATE / INCOGNITO window for ${provider}.\n\n${data.handoff}`);
        \\          pollReauth(provider, selector);
        \\        }
        \\      } catch (e) {
        \\        console.error('Reauth failed:', e);
        \\      }
        \\    }
        \\    function pollReauth(provider, selector) {
        \\      const interval = setInterval(async () => {
        \\        try {
        \\          const response = await fetch(`/reauth/${provider}/${selector}`);
        \\          const data = await response.json();
        \\          if (data.state === 'success' || data.state === 'failed') {
        \\            clearInterval(interval);
        \\            location.reload();
        \\          }
        \\        } catch (e) {
        \\          console.error('Poll failed:', e);
        \\        }
        \\      }, 2000);
        \\    }
        \\    // ~2s board-level health poll on the single status endpoint.
        \\    let lastBoard = null;
        \\    setInterval(async () => {
        \\      try {
        \\        const response = await fetch('/api/accounts');
        \\        const text = await response.text();
        \\        if (lastBoard !== null && lastBoard !== text) location.reload();
        \\        lastBoard = text;
        \\      } catch (e) {
        \\        console.error('Board poll failed:', e);
        \\      }
        \\    }, 2000);
        \\  </script>
        \\</body>
        \\</html>
    );

    return try buf.toOwnedSlice();
}

fn renderAccountsJson(allocator: std.mem.Allocator, accounts: []const AccountHealth) std.mem.Allocator.Error![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();

    try buf.appendSlice("[");
    for (accounts, 0..) |acc, idx| {
        if (idx > 0) try buf.appendSlice(",");
        try buf.appendSlice("{\"provider\":");
        try std.json.stringify(acc.provider, .{}, buf.writer());
        try buf.appendSlice(",\"route_state\":");
        try std.json.stringify(acc.route_state, .{}, buf.writer());
        try buf.appendSlice(",\"email_hint_masked\":");
        if (acc.email_hint_masked) |hint| {
            try std.json.stringify(hint, .{}, buf.writer());
        } else {
            try buf.appendSlice("null");
        }
        try buf.appendSlice(",\"reauth_in_progress\":");
        try buf.appendSlice(if (acc.reauth_in_progress) "true" else "false");
        try buf.appendSlice("}");
    }
    try buf.appendSlice("]");

    return try buf.toOwnedSlice();
}
// ────────────────────────────────────────────────────────────────────────────
// ROUTE HANDLERS
// ────────────────────────────────────────────────────────────────────────────

/// Check if Host header is loopback-only.
///
/// ANTI-DNS-REBINDING: the host portion (everything before an optional ":port")
/// must be EXACTLY "127.0.0.1" or "localhost". A prefix match is deliberately
/// NOT used, because "127.0.0.1.evil.com" / "localhost.evil.com" would slip
/// past a startsWith() check and resolve to an attacker-controlled address.
fn isLoopbackHost(host_header: []const u8) bool {
    if (host_header.len == 0) return false;

    // Split off an optional ":port" suffix. IPv6 literals are intentionally
    // unsupported here: this surface binds the IPv4 loopback only.
    const host = if (std.mem.indexOfScalar(u8, host_header, ':')) |colon|
        host_header[0..colon]
    else
        host_header;

    if (std.mem.eql(u8, host, "127.0.0.1")) return true;
    if (std.mem.eql(u8, host, "localhost")) return true;
    return false;
}

/// Handle GET / (account health board).
fn handleGetRoot(allocator: std.mem.Allocator, seams: Seams) std.mem.Allocator.Error!Response {
    const accounts = try seams.listAccounts(allocator);
    defer allocator.free(accounts);

    const html = try renderAccountHealthHtml(allocator, accounts);

    return Response{
        .status = 200,
        .content_type = "text/html; charset=utf-8",
        .body = html,
        .allocator = allocator,
    };
}

/// Handle GET /api/accounts (JSON account list).
fn handleGetApiAccounts(allocator: std.mem.Allocator, seams: Seams) std.mem.Allocator.Error!Response {
    const accounts = try seams.listAccounts(allocator);
    defer allocator.free(accounts);

    const json = try renderAccountsJson(allocator, accounts);

    return Response{
        .status = 200,
        .content_type = "application/json",
        .body = json,
        .allocator = allocator,
    };
}

/// A parsed /reauth/{provider}/{selector} path. `selector` is either a numeric
/// row index (from the board) or a literal account token (documented route for
/// the coordinated follow-up). `selector_is_index` records which form was seen.
const ReauthTarget = struct {
    provider: []const u8,
    selector: []const u8,
    selector_is_index: bool,
};

fn jsonError(allocator: std.mem.Allocator, status: u16, comptime err: []const u8) std.mem.Allocator.Error!Response {
    return Response{
        .status = status,
        .content_type = "application/json",
        .body = try allocator.dupe(u8, "{\"error\":\"" ++ err ++ "\"}"),
        .allocator = allocator,
    };
}

/// Parse /reauth/{provider}/{selector}. Returns null on malformed input.
fn parseReauthPath(path: []const u8) ?ReauthTarget {
    const prefix = "/reauth/";
    if (!std.mem.startsWith(u8, path, prefix)) return null;

    const remaining = path[prefix.len..];
    const slash = std.mem.indexOfScalar(u8, remaining, '/') orelse return null;

    const provider = remaining[0..slash];
    const selector = remaining[slash + 1 ..];
    if (provider.len == 0 or selector.len == 0) return null;
    // A selector that still contains a slash is not a single path segment.
    if (std.mem.indexOfScalar(u8, selector, '/') != null) return null;

    const is_index = blk: {
        _ = std.fmt.parseInt(usize, selector, 10) catch break :blk false;
        break :blk true;
    };

    return .{ .provider = provider, .selector = selector, .selector_is_index = is_index };
}

/// Resolve a parsed target to the (provider, account) pair the seams expect.
/// When the selector is a numeric index, it is looked up against the seam
/// account list so the raw account id never needs to traverse the UI/DOM.
/// The returned account is owned by `account_list` (do not free separately).
fn resolveReauthTarget(
    target: ReauthTarget,
    account_list: []const AccountHealth,
) ?[]const u8 {
    if (!target.selector_is_index) return target.selector;

    const idx = std.fmt.parseInt(usize, target.selector, 10) catch return null;
    if (idx >= account_list.len) return null;
    const row = account_list[idx];
    if (!std.mem.eql(u8, row.provider, target.provider)) return null;
    return row.account;
}

/// Handle POST /reauth/{provider}/{selector} (enqueue/join reauth, single-flight).
fn handlePostReauth(
    allocator: std.mem.Allocator,
    path: []const u8,
    seams: Seams,
) std.mem.Allocator.Error!Response {
    const target = parseReauthPath(path) orelse
        return jsonError(allocator, 400, "invalid_path");

    const accounts = try seams.listAccounts(allocator);
    defer allocator.free(accounts);

    const account = resolveReauthTarget(target, accounts) orelse
        return jsonError(allocator, 404, "unknown_account");

    const handle = try seams.enqueueReauth(allocator, target.provider, account);
    defer allocator.free(handle.job_id);
    defer allocator.free(handle.handoff);

    var json_buf = std.ArrayList(u8).init(allocator);
    defer json_buf.deinit();

    try json_buf.appendSlice("{\"job_id\":");
    try std.json.stringify(handle.job_id, .{}, json_buf.writer());
    try json_buf.appendSlice(",\"state\":\"pending\",\"handoff\":");
    try std.json.stringify(handle.handoff, .{}, json_buf.writer());
    try json_buf.appendSlice("}");

    return Response{
        .status = 200,
        .content_type = "application/json",
        .body = try json_buf.toOwnedSlice(),
        .allocator = allocator,
    };
}

/// Handle GET /reauth/{provider}/{selector} (poll job state).
fn handleGetReauth(
    allocator: std.mem.Allocator,
    path: []const u8,
    seams: Seams,
) std.mem.Allocator.Error!Response {
    const target = parseReauthPath(path) orelse
        return jsonError(allocator, 400, "invalid_path");

    const accounts = try seams.listAccounts(allocator);
    defer allocator.free(accounts);

    const account = resolveReauthTarget(target, accounts) orelse
        return jsonError(allocator, 404, "unknown_account");

    const state = try seams.pollReauth(allocator, target.provider, account);

    var json_buf = std.ArrayList(u8).init(allocator);
    defer json_buf.deinit();

    try json_buf.writer().print(
        "{{\"state\":\"{s}\"}}",
        .{state.toString()},
    );

    return Response{
        .status = 200,
        .content_type = "application/json",
        .body = try json_buf.toOwnedSlice(),
        .allocator = allocator,
    };
}

/// Return the value of `key` in a url-encoded query string, or null if absent.
/// (No percent-decoding here; presence/shape validation only. The injected
/// reauth controller is responsible for decoding + verifying the values.)
fn queryParam(query: []const u8, key: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (std.mem.eql(u8, pair[0..eq], key)) return pair[eq + 1 ..];
    }
    return null;
}

/// Handle GET /callback?code=...&state=... (loopback OAuth redirect target).
///
/// Validates PRESENCE of both `code` and `state` (anti-CSRF/state-binding is
/// the injected reauth controller's job; this surface only gates malformed
/// callbacks). On success it hands off to the controller — which is a
/// coordinated follow-up — so for now a validated callback returns 200 and a
/// missing param returns 400.
fn handleGetCallback(allocator: std.mem.Allocator, query: []const u8) std.mem.Allocator.Error!Response {
    const code = queryParam(query, "code");
    const state = queryParam(query, "state");

    if (code == null or state == null or code.?.len == 0 or state.?.len == 0) {
        return jsonError(allocator, 400, "missing_code_or_state");
    }

    // Follow-up: seams.handleCallback(code, state) -> drive reauth controller.
    const body = try allocator.dupe(u8, "OK");
    return Response{
        .status = 200,
        .content_type = "text/plain",
        .body = body,
        .allocator = allocator,
    };
}

/// Handle GET /healthz (liveness).
fn handleGetHealthz(allocator: std.mem.Allocator) std.mem.Allocator.Error!Response {
    const body = try allocator.dupe(u8, "OK");
    return Response{
        .status = 200,
        .content_type = "text/plain",
        .body = body,
        .allocator = allocator,
    };
}

// ────────────────────────────────────────────────────────────────────────────
// MAIN REQUEST ROUTER
// ────────────────────────────────────────────────────────────────────────────

/// Route an HTTP request and return a response.
/// Pure function; no real socket I/O. Host header is checked for loopback-only.
///
/// `raw_target` is the request-line target: a path with an optional
/// "?query" suffix (e.g. "/callback?code=x&state=y"). Routing matches on the
/// path portion; the query is handed to handlers that need it.
pub fn routeRequest(
    allocator: std.mem.Allocator,
    method: HttpMethod,
    raw_target: []const u8,
    host_header: []const u8,
    seams: Seams,
) std.mem.Allocator.Error!Response {
    // SECURITY: Loopback-only check (anti-DNS-rebinding). Checked FIRST so a
    // non-loopback Host never reaches any account-bearing handler.
    if (!isLoopbackHost(host_header)) {
        const body = try allocator.dupe(u8, "");
        return Response{
            .status = 403,
            .content_type = "text/plain",
            .body = body,
            .allocator = allocator,
        };
    }

    // Split path from query.
    const path, const query = blk: {
        if (std.mem.indexOfScalar(u8, raw_target, '?')) |q|
            break :blk .{ raw_target[0..q], raw_target[q + 1 ..] };
        break :blk .{ raw_target, "" };
    };

    // Route matching.
    if (std.mem.eql(u8, path, "/")) {
        if (method == .GET) return try handleGetRoot(allocator, seams);
    }

    if (std.mem.eql(u8, path, "/api/accounts")) {
        if (method == .GET) return try handleGetApiAccounts(allocator, seams);
    }

    if (std.mem.startsWith(u8, path, "/reauth/")) {
        if (method == .POST) return try handlePostReauth(allocator, path, seams);
        if (method == .GET) return try handleGetReauth(allocator, path, seams);
    }

    if (std.mem.eql(u8, path, "/callback")) {
        if (method == .GET) return try handleGetCallback(allocator, query);
    }

    if (std.mem.eql(u8, path, "/healthz")) {
        if (method == .GET) return try handleGetHealthz(allocator);
    }

    // 404.
    const body = try allocator.dupe(u8, "");
    return Response{
        .status = 404,
        .content_type = "text/plain",
        .body = body,
        .allocator = allocator,
    };
}

// ────────────────────────────────────────────────────────────────────────────
// THIN HTTP LISTENER (injected wrapper around routeRequest)
//
// This is the only part that touches a real socket. It is intentionally thin
// and is NOT exercised by the unit tests (those drive routeRequest directly
// with synthetic requests + fake seams). Binding the real account/reauth seams
// and wiring this into the daemon are coordinated follow-ups.
// ────────────────────────────────────────────────────────────────────────────

/// Minimal parse of an HTTP/1.x request: method, target, and Host header.
/// Returns null if the request line is malformed or the method is unsupported.
pub const ParsedRequest = struct {
    method: HttpMethod,
    target: []const u8,
    host: []const u8,
};

pub fn parseRequest(raw: []const u8) ?ParsedRequest {
    var lines = std.mem.splitSequence(u8, raw, "\r\n");
    const request_line = lines.next() orelse return null;

    var parts = std.mem.splitScalar(u8, request_line, ' ');
    const method_str = parts.next() orelse return null;
    const target = parts.next() orelse return null;
    const method = HttpMethod.fromString(method_str) orelse return null;

    var host: []const u8 = "";
    while (lines.next()) |line| {
        if (line.len == 0) break; // end of headers
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        if (std.ascii.eqlIgnoreCase(name, "host")) {
            host = std.mem.trim(u8, line[colon + 1 ..], " \t");
        }
    }

    return .{ .method = method, .target = target, .host = host };
}

fn statusText(status: u16) []const u8 {
    return switch (status) {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        else => "OK",
    };
}

/// Serialize a Response into an HTTP/1.1 wire message. Caller owns the result.
pub fn serializeResponse(allocator: std.mem.Allocator, resp: Response) std.mem.Allocator.Error![]const u8 {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    try buf.writer().print(
        "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
        .{ resp.status, statusText(resp.status), resp.content_type, resp.body.len },
    );
    try buf.appendSlice(resp.body);
    return buf.toOwnedSlice();
}

/// Bind 127.0.0.1:port (loopback ONLY — never a non-loopback address) and serve
/// requests by delegating each one to routeRequest. Blocking, one connection at
/// a time; the operator console is single-user and low-traffic by design.
///
/// NOTE: not covered by unit tests (real socket I/O). Kept here so the listener
/// seam is explicit; the daemon wiring + real seams are a coordinated follow-up.
pub fn serve(allocator: std.mem.Allocator, port: u16, seams: Seams) !void {
    const loopback = try std.net.Address.parseIp4("127.0.0.1", port);
    var server = try loopback.listen(.{ .reuse_address = true });
    defer server.deinit();

    var read_buf: [16 * 1024]u8 = undefined;
    while (true) {
        const conn = try server.accept();
        defer conn.stream.close();

        const n = conn.stream.read(&read_buf) catch continue;
        const parsed = parseRequest(read_buf[0..n]) orelse continue;

        const resp = routeRequest(allocator, parsed.method, parsed.target, parsed.host, seams) catch continue;
        defer resp.deinit();

        const wire = serializeResponse(allocator, resp) catch continue;
        defer allocator.free(wire);
        _ = conn.stream.writeAll(wire) catch continue;
    }
}
