//! Unit tests for the Claude OAuth reauth cassette. Pure: in-memory cassettes +
//! the on-disk neutral fixtures, no network. Proves: neutralize-on-disk /
//! reconstruct-in-memory, that no forbidden marker is ever produced, that the
//! reconstructed body is real-shaped (sk-ant- prefixes parse), that the replayer
//! serves as the adapter HttpPostFn, and that the scheduler RefreshFn shim drives
//! a success refresh + a never-halt failure.
//!
//!     zig test src/cassettes/claude_oauth_cassette_tests.zig

const std = @import("std");
const testing = std.testing;
const cas = @import("claude_oauth_cassette.zig");

test {
    std.testing.refAllDeclsRecursive(cas);
}

// The exact forbidden markers from src/fixture_redaction.zig — anything the
// repo's fixture scanner rejects. Neutral cassette output must contain NONE.
const forbidden_markers = [_][]const u8{
    "access_token", "refresh_token", "id_token",     "client_secret",
    "authorization:", "authorization=", "bearer ",   "bearer%20",
    "set-cookie:",  "cookie:",       "sk-",          "sess-",
};

fn containsForbidden(bytes: []const u8) bool {
    for (forbidden_markers) |m| {
        if (std.ascii.indexOfIgnoreCase(bytes, m) != null) return true;
    }
    return false;
}

// A synthetic REAL-shaped token-endpoint body, built in memory in the test (the
// sk-ant- prefix comes from the module's public constant, never a literal here;
// this file lives under src/, which the fixture scanner does not walk).
fn fakeRealBody(a: std.mem.Allocator, ttl: i64) ![]u8 {
    const pad = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"; // length-class filler
    return std.fmt.allocPrint(
        a,
        "{{\"access_token\":\"{s}{s}\",\"refresh_token\":\"{s}{s}\"," ++
            "\"expires_in\":{d},\"scope\":\"user:inference user:profile\",\"token_type\":\"Bearer\"}}",
        .{ cas.access_token_prefix, pad, cas.refresh_token_prefix, pad, ttl },
    );
}

fn cassetteFromLine(a: std.mem.Allocator, line: []const u8) !cas.Cassette {
    return cas.Cassette.parse(a, line);
}

// ── Reconstruction / parser-still-runs ─────────────────────────────────────

test "reconstructSuccessBody emits a real-shaped body with sk-ant- prefixes that parses" {
    const a = testing.allocator;
    const entry = cas.Entry{ .op = .refresh, .status = 200, .at_len = 108, .rt_len = 108, .ttl_s = 3600, .scope = "user:inference", .ttype = "Bearer" };
    const body = try cas.reconstructSuccessBody(a, entry);
    defer a.free(body);

    // Real shape: the adapter parser would accept this (prefixes + expires_in).
    try testing.expect(std.mem.indexOf(u8, body, cas.access_token_prefix) != null);
    try testing.expect(std.mem.indexOf(u8, body, cas.refresh_token_prefix) != null);

    const Shape = struct { access_token: []const u8 = "", refresh_token: []const u8 = "", expires_in: i64 = 0 };
    const parsed = try std.json.parseFromSlice(Shape, a, body, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    try testing.expect(std.mem.startsWith(u8, parsed.value.access_token, cas.access_token_prefix));
    try testing.expectEqual(@as(usize, 108), parsed.value.access_token.len); // length-class preserved
    try testing.expectEqual(@as(i64, 3600), parsed.value.expires_in);
}

test "reconstruct is byte-deterministic" {
    const a = testing.allocator;
    const entry = cas.Entry{ .op = .refresh, .status = 200, .at_len = 64, .rt_len = 64, .ttl_s = 100, .scope = "x", .ttype = "Bearer" };
    const b1 = try cas.reconstructSuccessBody(a, entry);
    defer a.free(b1);
    const b2 = try cas.reconstructSuccessBody(a, entry);
    defer a.free(b2);
    try testing.expectEqualStrings(b1, b2);
}

// ── Neutralize (capture-time redaction), fail-closed ───────────────────────

test "neutralizeSuccessBody strips secrets, keeps length-class, emits no forbidden marker" {
    const a = testing.allocator;
    const real = try fakeRealBody(a, 3600);
    defer a.free(real);
    // sanity: the REAL body of course contains a forbidden marker
    try testing.expect(containsForbidden(real));

    const line = try cas.neutralizeSuccessBody(a, .refresh, real);
    defer a.free(line);
    // the NEUTRAL on-disk line must be marker-free (passes fixture_redaction)
    try testing.expect(!containsForbidden(line));
    // and must carry the length-class, not the value
    const expect_len = cas.access_token_prefix.len + 48;
    var buf: [16]u8 = undefined;
    const needle = try std.fmt.bufPrint(&buf, "\"at_len\":{d}", .{expect_len});
    try testing.expect(std.mem.indexOf(u8, line, needle) != null);
}

test "neutralize is fail-closed on a wrong-prefix access token" {
    const a = testing.allocator;
    const body = "{\"access_token\":\"nope-not-a-claude-token\",\"refresh_token\":\"x\",\"expires_in\":1}";
    try testing.expectError(error.MalformedCassette, cas.neutralizeSuccessBody(a, .refresh, body));
}

test "neutralize is fail-closed on a shape-mismatched body" {
    const a = testing.allocator;
    const body = "{\"unexpected\":true}";
    try testing.expectError(error.MalformedCassette, cas.neutralizeSuccessBody(a, .refresh, body));
}

test "neutralize round-trip: real -> neutral -> cassette -> reconstruct keeps prefixes" {
    const a = testing.allocator;
    const real = try fakeRealBody(a, 1200);
    defer a.free(real);
    const line = try cas.neutralizeSuccessBody(a, .refresh, real);
    defer a.free(line);

    var cassette = try cassetteFromLine(a, line);
    defer cassette.deinit();
    try testing.expectEqual(@as(usize, 1), cassette.entries.len);
    try testing.expectEqual(cas.Op.refresh, cassette.entries[0].op);

    const reconstructed = try cas.reconstructSuccessBody(a, cassette.entries[0]);
    defer a.free(reconstructed);
    try testing.expect(std.mem.indexOf(u8, reconstructed, cas.access_token_prefix) != null);
}

// ── Recorder ────────────────────────────────────────────────────────────────

const FakeInner = struct {
    ttl: i64,
    calls: u32 = 0,
    fn post(allocator: std.mem.Allocator, ctx: *anyopaque, url: []const u8, body: []const u8, content_type: []const u8) cas.HttpError![]u8 {
        const self: *FakeInner = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        _ = url;
        _ = body;
        _ = content_type;
        return fakeRealBody(allocator, self.ttl) catch return error.OutOfMemory;
    }
};

test "Recorder forwards the call unchanged and appends a marker-free neutral line" {
    const a = testing.allocator;
    var sink = std.ArrayList(u8).init(a);
    defer sink.deinit();
    var inner = FakeInner{ .ttl = 3600 };
    var rec = cas.Recorder{ .inner = FakeInner.post, .inner_ctx = &inner, .sink = &sink };

    const resp = try cas.Recorder.post(a, &rec, cas.token_endpoint, "grant_type=refresh_token", cas.form_content_type);
    defer a.free(resp);

    try testing.expectEqual(@as(u32, 1), inner.calls);
    // returned body is the inner real body, untouched
    try testing.expect(std.mem.indexOf(u8, resp, cas.access_token_prefix) != null);
    // the recorded sink line is neutral / marker-free
    try testing.expect(sink.items.len > 0);
    try testing.expect(!containsForbidden(sink.items));
}

// ── Replayer as the adapter HttpPostFn ─────────────────────────────────────

test "Replayer.post replays a refresh 200 as a reconstructed body" {
    const a = testing.allocator;
    var cassette = try cassetteFromLine(a,
        "{\"v\":1,\"op\":\"refresh\",\"status\":200,\"at_len\":80,\"rt_len\":80,\"ttl_s\":3600,\"scope\":\"s\",\"ttype\":\"Bearer\"}");
    defer cassette.deinit();
    var rp = cas.Replayer{ .cassette = &cassette };

    const body = try cas.Replayer.post(a, &rp, cas.token_endpoint, "grant_type=refresh_token", cas.form_content_type);
    defer a.free(body);
    try testing.expect(std.mem.indexOf(u8, body, cas.refresh_token_prefix) != null);
    try testing.expect(rp.last_miss == null);
}

test "Replayer.post on an op with no recorded line returns HttpFailed + value-free miss" {
    const a = testing.allocator;
    // exchange-only cassette, but we replay a refresh
    var cassette = try cassetteFromLine(a,
        "{\"v\":1,\"op\":\"exchange\",\"status\":200,\"at_len\":80,\"rt_len\":80,\"ttl_s\":1,\"scope\":\"s\",\"ttype\":\"Bearer\"}");
    defer cassette.deinit();
    var rp = cas.Replayer{ .cassette = &cassette };

    try testing.expectError(error.HttpFailed, cas.Replayer.post(a, &rp, cas.token_endpoint, "grant_type=refresh_token", cas.form_content_type));
    try testing.expect(rp.last_miss != null);
    try testing.expectEqual(cas.Op.refresh, rp.last_miss.?.op);
}

test "Replayer.post on a failure-status entry returns HttpFailed" {
    const a = testing.allocator;
    var cassette = try cassetteFromLine(a, "{\"v\":1,\"op\":\"refresh\",\"status\":400}");
    defer cassette.deinit();
    var rp = cas.Replayer{ .cassette = &cassette };

    try testing.expectError(error.HttpFailed, cas.Replayer.post(a, &rp, cas.token_endpoint, "grant_type=refresh_token", cas.form_content_type));
    try testing.expectEqual(@as(?cas.Op, cas.Op.refresh), if (rp.last_miss) |m| m.op else null);
}

test "Replayer cursor plays in order then saturates on the last entry" {
    const a = testing.allocator;
    var cassette = try cassetteFromLine(a,
        "{\"v\":1,\"op\":\"refresh\",\"status\":200,\"at_len\":80,\"rt_len\":80,\"ttl_s\":1,\"scope\":\"s\",\"ttype\":\"Bearer\"}\n" ++
        "{\"v\":1,\"op\":\"refresh\",\"status\":400}");
    defer cassette.deinit();
    var rp = cas.Replayer{ .cassette = &cassette };

    const first = try cas.Replayer.post(a, &rp, cas.token_endpoint, "grant_type=refresh_token", cas.form_content_type);
    a.free(first); // first replay = 200
    // second replay = 400 (HttpFailed), and it then saturates on the 400
    try testing.expectError(error.HttpFailed, cas.Replayer.post(a, &rp, cas.token_endpoint, "grant_type=refresh_token", cas.form_content_type));
    try testing.expectError(error.HttpFailed, cas.Replayer.post(a, &rp, cas.token_endpoint, "grant_type=refresh_token", cas.form_content_type));
}

// ── Scheduler RefreshFn shim ────────────────────────────────────────────────

test "SchedulerBinding.refresh maps a 200 cassette to an advanced RefreshResult" {
    const a = testing.allocator;
    var cassette = try cassetteFromLine(a,
        "{\"v\":1,\"op\":\"refresh\",\"status\":200,\"at_len\":80,\"rt_len\":80,\"ttl_s\":3600,\"scope\":\"s\",\"ttype\":\"Bearer\"}");
    defer cassette.deinit();
    var rp = cas.Replayer{ .cassette = &cassette };
    var bind = cas.SchedulerBinding{ .replayer = &rp, .allocator = a, .now_ms = 1_000_000 };

    const result = try cas.SchedulerBinding.refresh(&bind, "claude:work");
    try testing.expectEqual(@as(i64, 1_000_000), result.new_last_refresh_ms);
    try testing.expectEqual(@as(i64, 1_000_000 + 3600 * std.time.ms_per_s), result.new_expires_at_ms);
}

test "SchedulerBinding.refresh maps a 4xx cassette to RefreshFailed (never-halt)" {
    const a = testing.allocator;
    var cassette = try cassetteFromLine(a, "{\"v\":1,\"op\":\"refresh\",\"status\":400}");
    defer cassette.deinit();
    var rp = cas.Replayer{ .cassette = &cassette };
    var bind = cas.SchedulerBinding{ .replayer = &rp, .allocator = a, .now_ms = 5 };

    try testing.expectError(error.RefreshFailed, cas.SchedulerBinding.refresh(&bind, "claude:work"));
}

// ── On-disk fixture loads + replays (the committed neutral cassette) ────────

test "the committed refresh_200 fixture loads, is marker-free, and replays" {
    const a = testing.allocator;
    const path = "test/fixtures/cassettes/claude/refresh_200.jsonl";
    const bytes = std.fs.cwd().readFileAlloc(a, path, 1 << 16) catch |err| switch (err) {
        error.FileNotFound => return error.SkipZigTest, // run from repo root
        else => return err,
    };
    defer a.free(bytes);

    try testing.expect(!containsForbidden(bytes)); // the on-disk fixture carries no secret marker

    var cassette = try cas.Cassette.parse(a, bytes);
    defer cassette.deinit();
    var rp = cas.Replayer{ .cassette = &cassette };
    const body = try cas.Replayer.post(a, &rp, cas.token_endpoint, "grant_type=refresh_token", cas.form_content_type);
    defer a.free(body);
    try testing.expect(std.mem.indexOf(u8, body, cas.access_token_prefix) != null);
}
