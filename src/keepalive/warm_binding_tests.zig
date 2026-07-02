//! Unit tests for the keepalive warm-loop binding. Pure: a fake clock, fake
//! refresh seam, and fake wait seam drive the loop deterministically with no I/O.
//!
//!     zig test src/keepalive/warm_binding_tests.zig

const std = @import("std");
const testing = std.testing;
const ws = @import("warm_scheduler.zig");
const bind = @import("warm_binding.zig");

test {
    testing.refAllDeclsRecursive(bind);
}

// ── Fakes ────────────────────────────────────────────────────────────────────

const FakeEnv = struct {
    now: i64,
    refresh_mode: enum { ok, fail, oom } = .ok,
    new_ttl_ms: i64 = 1_000_000,
    refresh_calls: u32 = 0,
    last_provider: [64]u8 = undefined,
    last_provider_len: usize = 0,
    last_account: [64]u8 = undefined,
    last_account_len: usize = 0,
    waits: u32 = 0,
    max_waits: u32 = 1000,

    fn clock(ctx: *anyopaque) i64 {
        const self: *FakeEnv = @ptrCast(@alignCast(ctx));
        return self.now;
    }

    fn doRefresh(ctx: *anyopaque, provider: []const u8, account: []const u8) ws.RefreshError!ws.RefreshResult {
        const self: *FakeEnv = @ptrCast(@alignCast(ctx));
        self.refresh_calls += 1;
        self.last_provider_len = @min(provider.len, self.last_provider.len);
        @memcpy(self.last_provider[0..self.last_provider_len], provider[0..self.last_provider_len]);
        self.last_account_len = @min(account.len, self.last_account.len);
        @memcpy(self.last_account[0..self.last_account_len], account[0..self.last_account_len]);
        return switch (self.refresh_mode) {
            .ok => .{ .new_last_refresh_ms = self.now, .new_expires_at_ms = self.now + self.new_ttl_ms },
            .fail => ws.RefreshError.RefreshFailed,
            .oom => ws.RefreshError.OutOfMemory,
        };
    }

    /// Advances the fake clock to the scheduled wake instant, then continues until
    /// the wait cap is hit (simulating a daemon stop).
    fn wait(ctx: *anyopaque, wake_at_ms: i64) bool {
        const self: *FakeEnv = @ptrCast(@alignCast(ctx));
        self.waits += 1;
        self.now = wake_at_ms;
        return self.waits < self.max_waits;
    }

    /// A FAITHFUL timed wait: it only advances the clock when the wake is strictly
    /// in the FUTURE — a real timed wait returns immediately from a past/now
    /// deadline without sleeping. Used to detect a busy-spin (clock never advances).
    fn faithfulWait(ctx: *anyopaque, wake_at_ms: i64) bool {
        const self: *FakeEnv = @ptrCast(@alignCast(ctx));
        self.waits += 1;
        if (wake_at_ms > self.now) self.now = wake_at_ms;
        return self.waits < self.max_waits;
    }

    fn lastProvider(self: *FakeEnv) []const u8 {
        return self.last_provider[0..self.last_provider_len];
    }
    fn lastAccount(self: *FakeEnv) []const u8 {
        return self.last_account[0..self.last_account_len];
    }

    fn scheduler(self: *FakeEnv, binding: *bind.RefreshBinding, policy: ws.Policy) ws.Scheduler {
        return .{
            .policy = policy,
            .clock = FakeEnv.clock,
            .clock_ctx = self,
            .refresh = bind.RefreshBinding.refresh,
            .refresh_ctx = binding,
        };
    }
};

const due_policy = ws.Policy{ .refresh_percent = 75, .min_lead_ms = 0 };

// ── Account key codec ────────────────────────────────────────────────────────

test "encodeKey/decodeKey round-trips, splitting on the first colon" {
    var buf: [64]u8 = undefined;
    const key = try bind.encodeKey(&buf, "codex", "max-1");
    try testing.expectEqualStrings("codex:max-1", key);
    const dk = bind.decodeKey(key).?;
    try testing.expectEqualStrings("codex", dk.provider);
    try testing.expectEqualStrings("max-1", dk.account);
}

test "decodeKey keeps an account that itself contains a colon (split-first)" {
    const dk = bind.decodeKey("claude:org:acct").?;
    try testing.expectEqualStrings("claude", dk.provider);
    try testing.expectEqualStrings("org:acct", dk.account);
}

test "decodeKey refuses malformed keys (no/empty provider/empty account)" {
    try testing.expect(bind.decodeKey("nocolon") == null);
    try testing.expect(bind.decodeKey(":acct") == null); // empty provider
    try testing.expect(bind.decodeKey("prov:") == null); // empty account
    try testing.expect(bind.decodeKey("") == null);
}

test "encodeKey rejects empty components (symmetric with decodeKey)" {
    var buf: [64]u8 = undefined;
    try testing.expectError(error.EmptyKeyComponent, bind.encodeKey(&buf, "", "acct"));
    try testing.expectError(error.EmptyKeyComponent, bind.encodeKey(&buf, "codex", ""));
    try testing.expectError(error.EmptyKeyComponent, bind.encodeKey(&buf, "", ""));
}

// ── Pool construction ────────────────────────────────────────────────────────

test "buildPool seeds last_refresh near now and preserves expiry per account" {
    const a = testing.allocator;
    const observed = [_]bind.Observed{
        .{ .key = "claude:work", .expires_at_ms = 5_000_000 },
        .{ .key = "codex:max-1", .expires_at_ms = 9_000_000 },
    };
    const pool = try bind.buildPool(a, &observed, 1_000_000);
    defer a.free(pool);
    try testing.expectEqual(@as(usize, 2), pool.len);
    try testing.expectEqualStrings("claude:work", pool[0].key);
    try testing.expect(pool[0].last_refresh_ms <= 1_000_000);
    try testing.expect(pool[0].last_refresh_ms >= 1_000_000 - 60 * std.time.ms_per_min);
    try testing.expectEqual(@as(i64, 5_000_000), pool[0].expires_at_ms);
    try testing.expectEqual(@as(i64, 9_000_000), pool[1].expires_at_ms);
    try testing.expectEqual(@as(u32, 0), pool[0].failures);
}

test "buildPool deterministically staggers a fresh pool instead of one due cohort" {
    const a = testing.allocator;
    const observed = [_]bind.Observed{
        .{ .key = "claude:work", .expires_at_ms = 24 * std.time.ms_per_hour },
        .{ .key = "claude:personal", .expires_at_ms = 24 * std.time.ms_per_hour },
        .{ .key = "codex:work", .expires_at_ms = 24 * std.time.ms_per_hour },
        .{ .key = "codex:personal", .expires_at_ms = 24 * std.time.ms_per_hour },
    };
    const pool1 = try bind.buildPool(a, &observed, 1_000_000);
    defer a.free(pool1);
    const pool2 = try bind.buildPool(a, &observed, 1_000_000);
    defer a.free(pool2);

    var all_same = true;
    for (pool1, pool2) |p1, p2| {
        try testing.expectEqual(p1.last_refresh_ms, p2.last_refresh_ms);
        try testing.expect(p1.last_refresh_ms <= 1_000_000);
        if (p1.last_refresh_ms != pool1[0].last_refresh_ms) all_same = false;
    }
    try testing.expect(!all_same);
}

test "buildPool stagger only pulls first due times earlier, never later" {
    const a = testing.allocator;
    const now: i64 = 1_000_000;
    const expires = now + 24 * std.time.ms_per_hour;
    const observed = [_]bind.Observed{
        .{ .key = "claude:work", .expires_at_ms = expires },
        .{ .key = "claude:personal", .expires_at_ms = expires },
        .{ .key = "codex:work", .expires_at_ms = expires },
        .{ .key = "codex:personal", .expires_at_ms = expires },
    };
    const pool = try bind.buildPool(a, &observed, now);
    defer a.free(pool);

    const policy = ws.Policy{ .refresh_percent = 75, .min_lead_ms = 0 };
    const unstaggered = ws.Account{ .key = "baseline", .last_refresh_ms = now, .expires_at_ms = expires };
    const baseline_due = ws.refreshDueAtMs(unstaggered, policy);
    var pulled_earlier = false;
    for (pool) |account| {
        const due = ws.refreshDueAtMs(account, policy);
        try testing.expect(due <= baseline_due);
        try testing.expect(due >= baseline_due - 60 * std.time.ms_per_min);
        if (due < baseline_due) pulled_earlier = true;
    }
    try testing.expect(pulled_earlier);
}

// ── Refresh binding ──────────────────────────────────────────────────────────

test "RefreshBinding decodes the key and dispatches to (provider, account)" {
    var env = FakeEnv{ .now = 0, .new_ttl_ms = 500 };
    var binding = bind.RefreshBinding{ .do_refresh = FakeEnv.doRefresh, .do_refresh_ctx = &env };
    const res = try bind.RefreshBinding.refresh(&binding, "codex:max-1");
    try testing.expectEqual(@as(i64, 500), res.new_expires_at_ms); // now(0) + ttl(500)
    try testing.expectEqualStrings("codex", env.lastProvider());
    try testing.expectEqualStrings("max-1", env.lastAccount());
}

test "RefreshBinding turns an undecodable key into RefreshFailed (never a wrong-account refresh)" {
    var env = FakeEnv{ .now = 0 };
    var binding = bind.RefreshBinding{ .do_refresh = FakeEnv.doRefresh, .do_refresh_ctx = &env };
    try testing.expectError(ws.RefreshError.RefreshFailed, bind.RefreshBinding.refresh(&binding, "nocolon"));
    try testing.expectEqual(@as(u32, 0), env.refresh_calls); // never dispatched
}

// ── Loop driver ──────────────────────────────────────────────────────────────

test "runLoop refreshes a due account each tick until the daemon stops" {
    var env = FakeEnv{ .now = 1_000_000, .refresh_mode = .ok, .new_ttl_ms = 1_000_000, .max_waits = 3 };
    var binding = bind.RefreshBinding{ .do_refresh = FakeEnv.doRefresh, .do_refresh_ctx = &env };
    const sched = env.scheduler(&binding, due_policy);
    var accounts = [_]ws.Account{
        .{ .key = "claude:work", .last_refresh_ms = 0, .expires_at_ms = 1_000_000 }, // due at 750k <= now
    };
    const report = bind.runLoop(&sched, &accounts, FakeEnv.wait, &env);
    // 3 ticks then the 3rd wait stops; the account was due-then-refreshed each time.
    try testing.expectEqual(@as(u32, 3), report.ticks);
    try testing.expectEqual(@as(u32, 3), report.refreshed);
    try testing.expectEqual(@as(u32, 3), env.refresh_calls);
    try testing.expect(!report.drained); // stopped by the daemon, not by draining
    try testing.expectEqualStrings("claude", env.lastProvider());
    try testing.expectEqualStrings("work", env.lastAccount());
}

test "runLoop drains: a persistently failing account backs off, dies, ends the loop" {
    var env = FakeEnv{ .now = 1_000_000, .refresh_mode = .fail, .max_waits = 1000 };
    var binding = bind.RefreshBinding{ .do_refresh = FakeEnv.doRefresh, .do_refresh_ctx = &env };
    const policy = ws.Policy{ .refresh_percent = 75, .min_lead_ms = 0, .max_failures = 3 };
    const sched = env.scheduler(&binding, policy);
    var accounts = [_]ws.Account{
        .{ .key = "x:y", .last_refresh_ms = 0, .expires_at_ms = 1_000_000 }, // due
    };
    const report = bind.runLoop(&sched, &accounts, FakeEnv.wait, &env);
    try testing.expect(report.drained); // every account dead → nothing left to schedule
    try testing.expectEqual(@as(u32, 1), report.died);
    try testing.expectEqual(@as(u32, 2), report.failed); // failures 1,2 = failed; 3rd = died
    try testing.expect(accounts[0].dead);
}

test "runLoop NEVER-HALT: a dead peer never blocks the live account, never drains" {
    var env = FakeEnv{ .now = 1_000_000, .refresh_mode = .ok, .new_ttl_ms = 1_000_000, .max_waits = 2 };
    var binding = bind.RefreshBinding{ .do_refresh = FakeEnv.doRefresh, .do_refresh_ctx = &env };
    const sched = env.scheduler(&binding, due_policy);
    var accounts = [_]ws.Account{
        .{ .key = "dead:acct", .last_refresh_ms = 0, .expires_at_ms = 1000, .dead = true },
        .{ .key = "live:acct", .last_refresh_ms = 0, .expires_at_ms = 1_000_000 }, // due
    };
    const report = bind.runLoop(&sched, &accounts, FakeEnv.wait, &env);
    try testing.expect(!report.drained); // the live account keeps the loop afloat
    try testing.expectEqual(@as(u32, 2), report.refreshed);
    // only the live account was ever refreshed; the dead peer was skipped.
    try testing.expectEqualStrings("live", env.lastProvider());
    try testing.expect(!accounts[1].dead);
}

test "runLoop floors a past/now wake so a short-TTL token can't busy-spin the seam" {
    // A refreshed token whose TTL (30s) is shorter than min_lead_ms (60s) makes
    // refreshDueAtMs clamp the due instant up to `now`, so nextWakeMs returns a
    // past/now value every tick. A FAITHFUL timed wait returns immediately from a
    // past deadline WITHOUT advancing time — so without the forward-progress floor
    // the loop would spin, refreshing with zero real delay (the fake clock would
    // never advance). The floor pushes the wake to now+backoff_base, so the wait
    // genuinely sleeps and time marches forward.
    var env = FakeEnv{ .now = 1_000_000, .refresh_mode = .ok, .new_ttl_ms = 30_000, .max_waits = 5 };
    var binding = bind.RefreshBinding{ .do_refresh = FakeEnv.doRefresh, .do_refresh_ctx = &env };
    const policy = ws.Policy{ .refresh_percent = 75, .min_lead_ms = 60_000, .backoff_base_ms = 5_000 };
    const sched = env.scheduler(&binding, policy);
    var accounts = [_]ws.Account{
        .{ .key = "claude:work", .last_refresh_ms = 0, .expires_at_ms = 1_000_000 },
    };
    const report = bind.runLoop(&sched, &accounts, FakeEnv.faithfulWait, &env);
    // The wait actually slept each pass (clock advanced by ~max_waits*backoff_base).
    // With the busy-spin bug the faithful wait would never advance → env.now stays
    // at the start and this fails.
    try testing.expect(env.now >= 1_000_000 + @as(i64, 5) * 5_000);
    try testing.expectEqual(@as(u32, 5), env.waits);
    try testing.expect(!report.drained);
}

test "runLoop: a sticky OOM is transient — never counts toward death, loop is wait-bounded" {
    var env = FakeEnv{ .now = 1_000_000, .refresh_mode = .oom, .max_waits = 4 };
    var binding = bind.RefreshBinding{ .do_refresh = FakeEnv.doRefresh, .do_refresh_ctx = &env };
    const sched = env.scheduler(&binding, due_policy);
    var accounts = [_]ws.Account{
        .{ .key = "x:y", .last_refresh_ms = 0, .expires_at_ms = 1_000_000 },
    };
    const report = bind.runLoop(&sched, &accounts, FakeEnv.wait, &env);
    // OOM never marks the account dead, so the loop only ends on the wait cap.
    try testing.expect(!report.drained);
    try testing.expectEqual(@as(u32, 0), report.died);
    try testing.expect(!accounts[0].dead);
    try testing.expectEqual(@as(u32, 0), accounts[0].failures); // OOM not charged
}
