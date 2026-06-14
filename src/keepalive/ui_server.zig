//! Keepalive operator status UI — greenfield (TIN-1827 / ide-keepalive epic).
//!
//! A `127.0.0.1`-only status board that makes the warm-loop scheduler (B.1,
//! `warm_scheduler.zig`) observable: per account, its masked label, health
//! state, last-refresh instant, and next-refresh ETA. No actions, no spend, no
//! secrets — a read-only window onto the keepalive pool.
//!
//! Same proven shape as the reauth web UI (#347) + callback server (#349):
//!   * a PURE `routeRequest(method, target, host, seam) -> Response` core that
//!     touches no socket — fully unit-testable with `std.testing.allocator`;
//!   * a thin, untested-by-design listener wrapper.
//!
//! Security / privacy, by construction:
//!   * Anti-DNS-rebinding: pool-bearing routes require the Host header to be
//!     EXACTLY 127.0.0.1/localhost (optional :port); suffix bypass → 403.
//!   * Structural redaction: the view type `AccountStatus` has NO token / no raw
//!     account_id field, so no credential can reach the rendered output — the
//!     seam supplies only an already-masked, non-identifying `label`. Rendered
//!     values are HTML/JSON-escaped.
//!
//! Self-contained: `std` only, no `@import` of existing `src`. Feeding real
//! scheduler state into the pool seam + wiring the listener into the daemon are
//! coordinated follow-ups (shared files).

const std = @import("std");

/// Sentinel "never due" instant (matches `warm_scheduler.never`): a dead account.
pub const never: i64 = std.math.maxInt(i64);

/// Health of one account in the keepalive pool (display vocabulary).
pub const HealthState = enum {
    warm, // token fresh, not yet due
    refreshing, // a refresh is in flight
    backoff, // last refresh failed, waiting to retry
    expired, // past expiry, needs refresh now
    dead, // gave up (failure budget) — skipped, awaiting re-login
    unknown,

    pub fn name(self: HealthState) []const u8 {
        return switch (self) {
            .warm => "warm",
            .refreshing => "refreshing",
            .backoff => "backoff",
            .expired => "expired",
            .dead => "dead",
            .unknown => "unknown",
        };
    }
};

/// A single, redaction-safe pool row. NOTE: deliberately no token / account_id
/// field — the seam masks identity into `label` before it ever reaches here.
pub const AccountStatus = struct {
    label: []const u8, // already-masked, non-identifying (e.g. "claude · max · ****@work")
    state: HealthState,
    last_refresh_ms: i64,
    next_due_ms: i64, // effective due instant, or `never` for dead
    failures: u32,
};

/// Read-only snapshot seam onto the keepalive pool. `list` returns rows borrowed
/// from the seam's storage (valid for the duration of the request).
pub const PoolSeam = struct {
    ctx: *anyopaque,
    list: *const fn (ctx: *anyopaque) []const AccountStatus,
    now: *const fn (ctx: *anyopaque) i64,
};

/// An HTTP response. `body` is always allocator-owned (static bodies are duped)
/// so `freeResponse` is uniform.
pub const Response = struct {
    status: u16,
    content_type: []const u8,
    body: []const u8,
};

pub fn freeResponse(allocator: std.mem.Allocator, r: Response) void {
    allocator.free(r.body);
}

// ── Pure router ────────────────────────────────────────────────────────────

/// Route one request. Pure: no socket, no clock of its own (the seam provides
/// `now`). Returns an allocator-owned Response.
pub fn routeRequest(
    allocator: std.mem.Allocator,
    method: []const u8,
    target: []const u8,
    host_header: []const u8,
    seam: PoolSeam,
) !Response {
    const path = splitPath(target);

    // Liveness needs no data and no host gate.
    if (std.mem.eql(u8, path, "/healthz")) return staticResponse(allocator, 200, "text/plain", "ok");

    // Everything else is pool-bearing: enforce loopback Host first.
    if (!isLoopbackHost(host_header)) return staticResponse(allocator, 403, "text/plain", "forbidden");
    if (!std.mem.eql(u8, method, "GET")) return staticResponse(allocator, 405, "text/plain", "method not allowed");

    if (std.mem.eql(u8, path, "/")) {
        const rows = seam.list(seam.ctx);
        const body = try renderStatusHtml(allocator, rows, seam.now(seam.ctx));
        return .{ .status = 200, .content_type = "text/html; charset=utf-8", .body = body };
    }
    if (std.mem.eql(u8, path, "/status") or std.mem.eql(u8, path, "/api/pool")) {
        const rows = seam.list(seam.ctx);
        const body = try renderStatusJson(allocator, rows, seam.now(seam.ctx));
        return .{ .status = 200, .content_type = "application/json", .body = body };
    }
    return staticResponse(allocator, 404, "text/plain", "not found");
}

fn staticResponse(allocator: std.mem.Allocator, status: u16, ct: []const u8, body: []const u8) !Response {
    return .{ .status = status, .content_type = ct, .body = try allocator.dupe(u8, body) };
}

/// Path portion of a request target (drops any query string).
pub fn splitPath(target: []const u8) []const u8 {
    return if (std.mem.indexOfScalar(u8, target, '?')) |q| target[0..q] else target;
}

/// Exact loopback Host (optional :port). Defeats the suffix bypass
/// (127.0.0.1.evil.com) that `startsWith` would allow.
pub fn isLoopbackHost(host_header: []const u8) bool {
    if (host_header.len == 0) return false;
    const host = if (std.mem.indexOfScalar(u8, host_header, ':')) |c| host_header[0..c] else host_header;
    return std.mem.eql(u8, host, "127.0.0.1") or std.mem.eql(u8, host, "localhost");
}

// ── Renderers ──────────────────────────────────────────────────────────────

/// JSON array of pool rows. Allow-listed keys only: label, state, lastRefreshMs,
/// nextDueMs, etaMs, failures. No token/account_id can appear (no such field).
pub fn renderStatusJson(allocator: std.mem.Allocator, rows: []const AccountStatus, now_ms: i64) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    const w = out.writer();
    try w.writeByte('[');
    for (rows, 0..) |row, i| {
        if (i != 0) try w.writeByte(',');
        try w.writeAll("{\"label\":\"");
        try writeJsonEscaped(w, row.label);
        try w.print("\",\"state\":\"{s}\",\"lastRefreshMs\":{d},", .{ row.state.name(), row.last_refresh_ms });
        if (row.next_due_ms == never) {
            try w.writeAll("\"nextDueMs\":null,\"etaMs\":null,");
        } else {
            const eta: i64 = if (row.next_due_ms > now_ms) row.next_due_ms -| now_ms else 0;
            try w.print("\"nextDueMs\":{d},\"etaMs\":{d},", .{ row.next_due_ms, eta });
        }
        try w.print("\"failures\":{d}}}", .{row.failures});
    }
    try w.writeByte(']');
    return out.toOwnedSlice();
}

/// Human status board (self-refreshing every 2s, no JS build).
pub fn renderStatusHtml(allocator: std.mem.Allocator, rows: []const AccountStatus, now_ms: i64) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    const w = out.writer();
    try w.writeAll(
        "<!doctype html><html><head><meta charset=\"utf-8\">" ++
        "<meta http-equiv=\"refresh\" content=\"2\">" ++
        "<title>oauth-mux keepalive</title>" ++
        "<style>body{font:14px system-ui;margin:2rem}table{border-collapse:collapse}" ++
        "th,td{border:1px solid #ccc;padding:.3rem .6rem;text-align:left}" ++
        ".dead{color:#b00}.backoff,.expired{color:#b60}.warm{color:#070}</style>" ++
        "</head><body><h1>Keepalive pool</h1><table>" ++
        "<tr><th>account</th><th>state</th><th>last refresh (ms)</th><th>next refresh ETA</th><th>failures</th></tr>",
    );
    for (rows) |row| {
        try w.print("<tr><td>", .{});
        try writeHtmlEscaped(w, row.label);
        try w.print("</td><td class=\"{s}\">{s}</td><td>{d}</td><td>", .{ row.state.name(), row.state.name(), row.last_refresh_ms });
        if (row.next_due_ms == never) {
            try w.writeAll("—");
        } else {
            const eta: i64 = if (row.next_due_ms > now_ms) row.next_due_ms -| now_ms else 0;
            try w.print("{d} ms", .{eta});
        }
        try w.print("</td><td>{d}</td></tr>", .{row.failures});
    }
    try w.writeAll("</table></body></html>");
    return out.toOwnedSlice();
}

fn writeJsonEscaped(w: anytype, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            else => if (c < 0x20) try w.print("\\u{x:0>4}", .{c}) else try w.writeByte(c),
        }
    }
}

fn writeHtmlEscaped(w: anytype, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '&' => try w.writeAll("&amp;"),
            '<' => try w.writeAll("&lt;"),
            '>' => try w.writeAll("&gt;"),
            '"' => try w.writeAll("&quot;"),
            '\'' => try w.writeAll("&#39;"),
            else => try w.writeByte(c),
        }
    }
}

// ── Listener wrapper (thin, untested by design) ────────────────────────────
//
// The only code that touches a real socket. Mirrors the repo's loopback idiom
// (wire_proxy.zig: parseIp → listen(.reuse_address) → accept → conn.stream) and
// delegates every decision to the pure router. Serves a long-lived status loop.

pub const UiListener = struct {
    allocator: std.mem.Allocator,
    seam: PoolSeam,

    /// Bind 127.0.0.1:0 and return the assigned port (for the daemon to advertise).
    pub fn bind(self: *const UiListener) !std.net.Server {
        _ = self;
        const loopback = try std.net.Address.parseIp("127.0.0.1", 0);
        return loopback.listen(.{ .reuse_address = true });
    }

    /// Handle exactly one accepted connection (untested by design).
    pub fn serveConn(self: *const UiListener, conn: std.net.Server.Connection) void {
        defer conn.stream.close();
        var buf: [8 * 1024]u8 = undefined;
        const n = conn.stream.read(&buf) catch return;
        const raw = buf[0..n];
        const line = parseRequestLine(raw) orelse return;
        const host = parseHostHeader(raw) orelse "";
        const resp = routeRequest(self.allocator, line.method, line.target, host, self.seam) catch return;
        defer freeResponse(self.allocator, resp);
        writeResponse(conn.stream, resp) catch {};
    }

    /// Serve forever (until `should_stop` flips). Untested by design.
    pub fn serve(self: *const UiListener, server: *std.net.Server, should_stop: *const std.atomic.Value(bool)) void {
        while (!should_stop.load(.acquire)) {
            const conn = server.accept() catch continue;
            self.serveConn(conn);
        }
    }
};

const RequestLine = struct { method: []const u8, target: []const u8 };

pub fn parseRequestLine(raw: []const u8) ?RequestLine {
    const eol = std.mem.indexOfScalar(u8, raw, '\r') orelse raw.len;
    var parts = std.mem.splitScalar(u8, raw[0..eol], ' ');
    const method = parts.next() orelse return null;
    const target = parts.next() orelse return null;
    if (method.len == 0 or target.len == 0) return null;
    return .{ .method = method, .target = target };
}

pub fn parseHostHeader(raw: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, raw, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        if (line.len == 0) break;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(line[0..colon], "Host")) {
            return std.mem.trim(u8, line[colon + 1 ..], " \t");
        }
    }
    return null;
}

fn writeResponse(stream: std.net.Stream, resp: Response) !void {
    var hdr: [256]u8 = undefined;
    const head = try std.fmt.bufPrint(
        &hdr,
        "HTTP/1.1 {d} {s}\r\nContent-Type: {s}\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n",
        .{ resp.status, statusText(resp.status), resp.content_type, resp.body.len },
    );
    try stream.writeAll(head);
    try stream.writeAll(resp.body);
}

fn statusText(status: u16) []const u8 {
    return switch (status) {
        200 => "OK",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        else => "OK",
    };
}
