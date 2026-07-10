//! Keepalive → desktop-notification glue (TIN-2061 MVP).
//!
//! Binds the pure scheduler's opaque notification seam
//! (`warm_scheduler.NotifySeam`) to the general delivery module (`notify.zig`):
//! it decodes the `<provider>:<account>` key, builds a `notify.NotifyEvent`,
//! applies the opt-in + per-target dedupe `Policy`, and posts. This is the live
//! glue layer — it may import `src` — but it stays effect-injectable so it can
//! be unit-tested without spawning a real `osascript`/`notify-send`.
//!
//! NEVER a spam channel: `shouldNotify` gates every post on the operator's
//! `min_interval_ms`, keyed per (reason, account). On the tick path, a class
//! sitting in repeated refusal fires at most one notification per interval.

const std = @import("std");
const ws = @import("warm_scheduler.zig");
const wb = @import("warm_binding.zig");
const notify = @import("../notify.zig");
const log = @import("../log.zig");

/// A generic reason string carried in the `refresh_failed` body. Deliberately
/// vague and FIXED: the raw pipeline/provider error is NEVER interpolated (it
/// could echo a token), and the operator's own log already carries the detail.
const refresh_failed_reason = "proactive refresh was refused or failed";

/// Injectable post seam (so tests can record instead of spawning a subprocess).
/// Production is `defaultPost`, a thin `notify.post` wrapper.
pub const PostFn = *const fn (ctx: *anyopaque, allocator: std.mem.Allocator, title: []const u8, body: []const u8) notify.NotifyError!void;

fn defaultPost(ctx: *anyopaque, allocator: std.mem.Allocator, title: []const u8, body: []const u8) notify.NotifyError!void {
    _ = ctx;
    return notify.post(allocator, title, body);
}

/// Injectable clock seam (so tests can drive dedupe timing deterministically).
fn realNow(ctx: *anyopaque) i64 {
    _ = ctx;
    return std.time.milliTimestamp();
}

pub const NotifyAdapter = struct {
    allocator: std.mem.Allocator,
    policy: notify.Policy,
    post_fn: PostFn = defaultPost,
    post_ctx: *anyopaque = undefined,
    now_fn: *const fn (ctx: *anyopaque) i64 = realNow,
    now_ctx: *anyopaque = undefined,
    /// Per-target "last delivered at" (Unix ms), keyed "<reason>\x00<key>".
    /// Keys are duped once into `arena` on first delivery and reused.
    last_sent: std.StringHashMap(i64),
    arena: std.heap.ArenaAllocator,

    pub fn init(allocator: std.mem.Allocator, policy: notify.Policy) NotifyAdapter {
        return .{
            .allocator = allocator,
            .policy = policy,
            .last_sent = std.StringHashMap(i64).init(allocator),
            .arena = std.heap.ArenaAllocator.init(allocator),
        };
    }

    pub fn deinit(self: *NotifyAdapter) void {
        self.last_sent.deinit();
        self.arena.deinit();
    }

    /// Bind onto `ws.Scheduler.notify`.
    pub fn seam(self: *NotifyAdapter) ws.NotifySeam {
        return .{ .func = onEvent, .ctx = self };
    }

    /// Matches `ws.NotifyFn`. Never fails outward (the scheduler must not care):
    /// a delivery error is logged (exit code / error name only) and dropped.
    fn onEvent(ctx: *anyopaque, reason: ws.NotifyReason, account_key: []const u8) void {
        const self: *NotifyAdapter = @ptrCast(@alignCast(ctx));
        self.dispatch(reason, account_key) catch |e| {
            log.warn("notify: delivery dropped: {s}", .{@errorName(e)});
        };
    }

    fn dispatch(self: *NotifyAdapter, reason: ws.NotifyReason, account_key: []const u8) !void {
        const dk = wb.decodeKey(account_key) orelse return; // malformed key → no wrong-account notify
        const event: notify.NotifyEvent = switch (reason) {
            .refresh_failed => .{ .refresh_failed = .{
                .provider = dk.provider,
                .account = dk.account,
                .reason = refresh_failed_reason,
            } },
            .credential_dead => .{ .credential_dead = .{
                .provider = dk.provider,
                .account = dk.account,
            } },
        };

        const now = self.now_fn(self.now_ctx);

        // Dedupe key built on the stack; only duped into the arena when we
        // actually record a send, so the arena grows by distinct targets only.
        var kbuf: [320]u8 = undefined;
        const dkey = std.fmt.bufPrint(&kbuf, "{s}\x00{s}", .{ @tagName(reason), account_key }) catch account_key;

        if (!notify.shouldNotify(self.policy, event, self.last_sent.get(dkey), now)) return;

        const rendered = notify.renderNotification(event);
        try self.post_fn(self.post_ctx, self.allocator, rendered.title(), rendered.body());

        // Delivered — record the send instant so the interval dedupe holds.
        if (self.last_sent.getEntry(dkey)) |ent| {
            ent.value_ptr.* = now;
        } else {
            const owned = self.arena.allocator().dupe(u8, dkey) catch return; // best effort
            self.last_sent.put(owned, now) catch {};
        }
    }
};

// ── Tests ────────────────────────────────────────────────────────────────────

const forbidden_markers = [_][]const u8{
    "access_token", "refresh_token", "id_token",   "client_secret",
    "authorization:", "bearer ",      "set-cookie:", "cookie:",
    "sk-",          "sess-",
};

const RecordingPost = struct {
    posts: u32 = 0,
    last_title: [96]u8 = undefined,
    last_title_len: usize = 0,
    last_body: [400]u8 = undefined,
    last_body_len: usize = 0,

    fn post(ctx: *anyopaque, allocator: std.mem.Allocator, title: []const u8, body: []const u8) notify.NotifyError!void {
        _ = allocator;
        const self: *RecordingPost = @ptrCast(@alignCast(ctx));
        self.posts += 1;
        self.last_title_len = @min(title.len, self.last_title.len);
        @memcpy(self.last_title[0..self.last_title_len], title[0..self.last_title_len]);
        self.last_body_len = @min(body.len, self.last_body.len);
        @memcpy(self.last_body[0..self.last_body_len], body[0..self.last_body_len]);
    }
    fn bodyStr(self: *RecordingPost) []const u8 {
        return self.last_body[0..self.last_body_len];
    }
};

const TestClock = struct {
    now: i64,
    fn read(ctx: *anyopaque) i64 {
        const self: *TestClock = @ptrCast(@alignCast(ctx));
        return self.now;
    }
};

fn wire(adapter: *NotifyAdapter, rec: *RecordingPost, clk: *TestClock) void {
    adapter.post_fn = RecordingPost.post;
    adapter.post_ctx = rec;
    adapter.now_fn = TestClock.read;
    adapter.now_ctx = clk;
}

test "NotifyAdapter: disabled adapter posts nothing" {
    var rec = RecordingPost{};
    var clk = TestClock{ .now = 1_000 };
    var adapter = NotifyAdapter.init(std.testing.allocator, .{ .enabled = false });
    defer adapter.deinit();
    wire(&adapter, &rec, &clk);

    const s = adapter.seam();
    s.func(s.ctx, .refresh_failed, "claude:work");
    s.func(s.ctx, .credential_dead, "claude:work");
    try std.testing.expectEqual(@as(u32, 0), rec.posts);
}

test "NotifyAdapter: enabled posts once then dedupes within the interval" {
    var rec = RecordingPost{};
    var clk = TestClock{ .now = 1_000 };
    var adapter = NotifyAdapter.init(std.testing.allocator, .{ .enabled = true, .min_interval_ms = 60_000 });
    defer adapter.deinit();
    wire(&adapter, &rec, &clk);
    const s = adapter.seam();

    s.func(s.ctx, .refresh_failed, "claude:work");
    try std.testing.expectEqual(@as(u32, 1), rec.posts);

    // 1s later → still within the 60s dedupe window → suppressed.
    clk.now += 1_000;
    s.func(s.ctx, .refresh_failed, "claude:work");
    try std.testing.expectEqual(@as(u32, 1), rec.posts);

    // Past the interval → fires again.
    clk.now += 60_000;
    s.func(s.ctx, .refresh_failed, "claude:work");
    try std.testing.expectEqual(@as(u32, 2), rec.posts);
}

test "NotifyAdapter: distinct reason/account keep independent dedupe state" {
    var rec = RecordingPost{};
    var clk = TestClock{ .now = 1_000 };
    var adapter = NotifyAdapter.init(std.testing.allocator, .{ .enabled = true, .min_interval_ms = 60_000 });
    defer adapter.deinit();
    wire(&adapter, &rec, &clk);
    const s = adapter.seam();

    s.func(s.ctx, .refresh_failed, "claude:work"); // 1
    s.func(s.ctx, .credential_dead, "claude:work"); // 2 — different reason
    s.func(s.ctx, .refresh_failed, "codex:home"); // 3 — different account
    try std.testing.expectEqual(@as(u32, 3), rec.posts);
}

test "NotifyAdapter: malformed key is skipped — no post, no crash" {
    var rec = RecordingPost{};
    var clk = TestClock{ .now = 1_000 };
    var adapter = NotifyAdapter.init(std.testing.allocator, .{ .enabled = true });
    defer adapter.deinit();
    wire(&adapter, &rec, &clk);
    const s = adapter.seam();

    s.func(s.ctx, .refresh_failed, "no-separator");
    s.func(s.ctx, .refresh_failed, ":emptyprovider");
    try std.testing.expectEqual(@as(u32, 0), rec.posts);
}

test "NotifyAdapter: delivered body carries the account label but no token markers" {
    var rec = RecordingPost{};
    var clk = TestClock{ .now = 1_000 };
    var adapter = NotifyAdapter.init(std.testing.allocator, .{ .enabled = true });
    defer adapter.deinit();
    wire(&adapter, &rec, &clk);
    const s = adapter.seam();

    s.func(s.ctx, .refresh_failed, "claude:work-account");
    try std.testing.expectEqual(@as(u32, 1), rec.posts);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(rec.bodyStr(), "claude") != null);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(rec.bodyStr(), "work-account") != null);
    for (forbidden_markers) |m| {
        try std.testing.expect(std.ascii.indexOfIgnoreCase(rec.bodyStr(), m) == null);
    }
}

test "NotifyAdapter: a failing post does not record — it retries next event" {
    const FailingPost = struct {
        calls: u32 = 0,
        fn post(ctx: *anyopaque, allocator: std.mem.Allocator, title: []const u8, body: []const u8) notify.NotifyError!void {
            _ = allocator;
            _ = title;
            _ = body;
            const self: *@This() = @ptrCast(@alignCast(ctx));
            self.calls += 1;
            return error.NotifyUnavailable;
        }
    };
    var fp = FailingPost{};
    var clk = TestClock{ .now = 1_000 };
    var adapter = NotifyAdapter.init(std.testing.allocator, .{ .enabled = true, .min_interval_ms = 60_000 });
    defer adapter.deinit();
    adapter.post_fn = FailingPost.post;
    adapter.post_ctx = &fp;
    adapter.now_fn = TestClock.read;
    adapter.now_ctx = &clk;
    const s = adapter.seam();

    // Two events, same target, same instant: because the first post FAILED, its
    // send was not recorded, so the second still attempts (no false dedupe).
    s.func(s.ctx, .refresh_failed, "claude:work");
    s.func(s.ctx, .refresh_failed, "claude:work");
    try std.testing.expectEqual(@as(u32, 2), fp.calls);
}
