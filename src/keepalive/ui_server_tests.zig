//! Unit tests for the keepalive status UI (pure router + renderers). No socket.
//!
//!     zig test src/keepalive/ui_server_tests.zig

const std = @import("std");
const ui = @import("ui_server.zig");

test {
    std.testing.refAllDeclsRecursive(ui);
}

const rows = [_]ui.AccountStatus{
    .{ .label = "claude · max · ****@work", .state = .warm, .last_refresh_ms = 1000, .next_due_ms = 2000, .failures = 0 },
    .{ .label = "codex:max-1", .state = .backoff, .last_refresh_ms = 500, .next_due_ms = 1500, .failures = 2 },
    .{ .label = "codex:max-2", .state = .dead, .last_refresh_ms = 0, .next_due_ms = ui.never, .failures = 8 },
};

const FakePool = struct {
    rows: []const ui.AccountStatus = &rows,
    now_ms: i64 = 1000,

    fn listFn(ctx: *anyopaque) []const ui.AccountStatus {
        const self: *FakePool = @ptrCast(@alignCast(ctx));
        return self.rows;
    }
    fn nowFn(ctx: *anyopaque) i64 {
        const self: *FakePool = @ptrCast(@alignCast(ctx));
        return self.now_ms;
    }
    fn seam(self: *FakePool) ui.PoolSeam {
        return .{ .ctx = self, .list = listFn, .now = nowFn };
    }
};

fn contains(haystack: []const u8, needle: []const u8) bool {
    return std.mem.indexOf(u8, haystack, needle) != null;
}

fn route(method: []const u8, target: []const u8, host: []const u8) !ui.Response {
    var pool = FakePool{};
    return ui.routeRequest(std.testing.allocator, method, target, host, pool.seam());
}

// ── Routing + security ─────────────────────────────────────────────────────

test "GET /healthz is 200 ok without a host gate" {
    const r = try route("GET", "/healthz", "");
    defer ui.freeResponse(std.testing.allocator, r);
    try std.testing.expectEqual(@as(u16, 200), r.status);
    try std.testing.expectEqualStrings("ok", r.body);
}

test "GET / on loopback renders the HTML board" {
    const r = try route("GET", "/", "127.0.0.1:7777");
    defer ui.freeResponse(std.testing.allocator, r);
    try std.testing.expectEqual(@as(u16, 200), r.status);
    try std.testing.expectEqualStrings("text/html; charset=utf-8", r.content_type);
    try std.testing.expect(contains(r.body, "Keepalive pool"));
    try std.testing.expect(contains(r.body, "codex:max-1"));
    try std.testing.expect(contains(r.body, "warm"));
}

test "GET /status on loopback returns JSON" {
    const r = try route("GET", "/status", "localhost");
    defer ui.freeResponse(std.testing.allocator, r);
    try std.testing.expectEqual(@as(u16, 200), r.status);
    try std.testing.expectEqualStrings("application/json", r.content_type);
    try std.testing.expect(contains(r.body, "\"label\":\"claude · max · ****@work\""));
    try std.testing.expect(contains(r.body, "\"state\":\"backoff\""));
}

test "GET /status ignores the query string (splitPath)" {
    const r = try route("GET", "/status?foo=bar", "127.0.0.1");
    defer ui.freeResponse(std.testing.allocator, r);
    try std.testing.expectEqual(@as(u16, 200), r.status);
}

test "DNS-rebind suffix host -> 403" {
    const r = try route("GET", "/", "127.0.0.1.evil.com");
    defer ui.freeResponse(std.testing.allocator, r);
    try std.testing.expectEqual(@as(u16, 403), r.status);
}

test "missing host -> 403 on a pool route" {
    const r = try route("GET", "/status", "");
    defer ui.freeResponse(std.testing.allocator, r);
    try std.testing.expectEqual(@as(u16, 403), r.status);
}

test "non-GET -> 405" {
    const r = try route("POST", "/", "127.0.0.1");
    defer ui.freeResponse(std.testing.allocator, r);
    try std.testing.expectEqual(@as(u16, 405), r.status);
}

test "unknown path -> 404" {
    const r = try route("GET", "/nope", "127.0.0.1");
    defer ui.freeResponse(std.testing.allocator, r);
    try std.testing.expectEqual(@as(u16, 404), r.status);
}

// ── Rendering correctness ──────────────────────────────────────────────────

test "JSON: a warm account reports etaMs = next_due - now" {
    const r = try route("GET", "/status", "127.0.0.1");
    defer ui.freeResponse(std.testing.allocator, r);
    // warm row: next_due 2000, now 1000 -> eta 1000
    try std.testing.expect(contains(r.body, "\"etaMs\":1000"));
}

test "JSON: a dead account reports null nextDueMs + etaMs" {
    const r = try route("GET", "/status", "127.0.0.1");
    defer ui.freeResponse(std.testing.allocator, r);
    try std.testing.expect(contains(r.body, "\"state\":\"dead\",\"lastRefreshMs\":0,\"nextDueMs\":null,\"etaMs\":null,\"failures\":8"));
}

test "HTML escapes a hostile label" {
    var pool = FakePool{ .rows = &[_]ui.AccountStatus{
        .{ .label = "<script>alert(1)</script>", .state = .warm, .last_refresh_ms = 0, .next_due_ms = 1, .failures = 0 },
    } };
    const r = try ui.routeRequest(std.testing.allocator, "GET", "/", "127.0.0.1", pool.seam());
    defer ui.freeResponse(std.testing.allocator, r);
    try std.testing.expect(contains(r.body, "&lt;script&gt;"));
    try std.testing.expect(!contains(r.body, "<script>alert"));
}

test "JSON escapes a quote in a label" {
    var pool = FakePool{ .rows = &[_]ui.AccountStatus{
        .{ .label = "a\"b", .state = .warm, .last_refresh_ms = 0, .next_due_ms = 1, .failures = 0 },
    } };
    const r = try ui.routeRequest(std.testing.allocator, "GET", "/status", "127.0.0.1", pool.seam());
    defer ui.freeResponse(std.testing.allocator, r);
    try std.testing.expect(contains(r.body, "\"label\":\"a\\\"b\""));
}

// ── Redaction allow-list ───────────────────────────────────────────────────

test "JSON exposes only allow-listed keys (no token/secret leakage possible)" {
    const r = try route("GET", "/status", "127.0.0.1");
    defer ui.freeResponse(std.testing.allocator, r);
    for ([_][]const u8{ "label", "state", "lastRefreshMs", "nextDueMs", "etaMs", "failures" }) |k| {
        try std.testing.expect(contains(r.body, k));
    }
    for ([_][]const u8{ "token", "access", "refresh", "secret", "sk-ant", "auth.json" }) |bad| {
        try std.testing.expect(!contains(r.body, bad));
    }
}

// ── Host predicate ─────────────────────────────────────────────────────────

test "isLoopbackHost: accepts loopback, rejects suffix/foreign/empty" {
    try std.testing.expect(ui.isLoopbackHost("127.0.0.1"));
    try std.testing.expect(ui.isLoopbackHost("127.0.0.1:8080"));
    try std.testing.expect(ui.isLoopbackHost("localhost"));
    try std.testing.expect(!ui.isLoopbackHost("127.0.0.1.evil.com"));
    try std.testing.expect(!ui.isLoopbackHost("example.com"));
    try std.testing.expect(!ui.isLoopbackHost(""));
}
