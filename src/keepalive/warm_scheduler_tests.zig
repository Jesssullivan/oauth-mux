//! Unit tests for the keepalive warm-loop scheduler. Pure core: fake clock +
//! fake refresh seam, no I/O. The core never allocates.
//!
//!     zig test src/keepalive/warm_scheduler_tests.zig

const std = @import("std");
const ws = @import("warm_scheduler.zig");

test {
    std.testing.refAllDeclsRecursive(ws);
}

// ── Fakes ──────────────────────────────────────────────────────────────────

const FakeClock = struct {
    now: i64,
    fn read(ctx: *anyopaque) i64 {
        const self: *FakeClock = @ptrCast(@alignCast(ctx));
        return self.now;
    }
};

const FakeRefresher = struct {
    fail: bool = false,
    oom: bool = false,
    new_last: i64 = 0,
    new_expires: i64 = 0,
    calls: u32 = 0,
    last_key: [64]u8 = undefined,
    last_key_len: usize = 0,

    fn refresh(ctx: *anyopaque, key: []const u8) ws.RefreshError!ws.RefreshResult {
        const self: *FakeRefresher = @ptrCast(@alignCast(ctx));
        self.calls += 1;
        self.last_key_len = @min(key.len, self.last_key.len);
        @memcpy(self.last_key[0..self.last_key_len], key[0..self.last_key_len]);
        if (self.oom) return error.OutOfMemory;
        if (self.fail) return error.RefreshFailed;
        return .{ .new_last_refresh_ms = self.new_last, .new_expires_at_ms = self.new_expires };
    }
    fn keyStr(self: *FakeRefresher) []const u8 {
        return self.last_key[0..self.last_key_len];
    }
};

fn scheduler(clk: *FakeClock, ref: *FakeRefresher, policy: ws.Policy) ws.Scheduler {
    return .{
        .policy = policy,
        .clock = FakeClock.read,
        .clock_ctx = clk,
        .refresh = FakeRefresher.refresh,
        .refresh_ctx = ref,
    };
}

// ── Pure scheduling math ───────────────────────────────────────────────────

test "refreshDueAtMs: 75% of lifetime" {
    const a = ws.Account{ .key = "k", .last_refresh_ms = 0, .expires_at_ms = 1_000_000 };
    try std.testing.expectEqual(@as(i64, 750_000), ws.refreshDueAtMs(a, .{ .refresh_percent = 75, .min_lead_ms = 0 }));
}

test "refreshDueAtMs: min_lead clamps the due time before expiry" {
    const a = ws.Account{ .key = "k", .last_refresh_ms = 0, .expires_at_ms = 1000 };
    // 99% -> 990, but min_lead 200 caps the latest refresh to expires-200 = 800.
    try std.testing.expectEqual(@as(i64, 800), ws.refreshDueAtMs(a, .{ .refresh_percent = 99, .min_lead_ms = 200 }));
}

test "refreshDueAtMs: already-expired lifetime is due immediately" {
    const a = ws.Account{ .key = "k", .last_refresh_ms = 1000, .expires_at_ms = 500 };
    try std.testing.expectEqual(@as(i64, 1000), ws.refreshDueAtMs(a, .{}));
}

test "effectiveDueMs: backoff gate overrides the due time" {
    const a = ws.Account{ .key = "k", .last_refresh_ms = 0, .expires_at_ms = 1_000_000, .next_attempt_ms = 900_000 };
    try std.testing.expectEqual(@as(i64, 900_000), ws.effectiveDueMs(a, .{ .refresh_percent = 75, .min_lead_ms = 0 }));
}

test "effectiveDueMs: dead account is never due" {
    const a = ws.Account{ .key = "k", .last_refresh_ms = 0, .expires_at_ms = 1000, .dead = true };
    try std.testing.expectEqual(ws.never, ws.effectiveDueMs(a, .{}));
}

test "isDue honors now, backoff, and dead" {
    const policy = ws.Policy{ .refresh_percent = 75, .min_lead_ms = 0 };
    const a = ws.Account{ .key = "k", .last_refresh_ms = 0, .expires_at_ms = 1_000_000 }; // due at 750_000
    try std.testing.expect(!ws.isDue(a, policy, 749_999));
    try std.testing.expect(ws.isDue(a, policy, 750_000));
    var dead = a;
    dead.dead = true;
    try std.testing.expect(!ws.isDue(dead, policy, 999_999_999));
}

test "nextWakeMs: earliest live due, null if all dead" {
    const policy = ws.Policy{ .refresh_percent = 75, .min_lead_ms = 0 };
    var accounts = [_]ws.Account{
        .{ .key = "a", .last_refresh_ms = 0, .expires_at_ms = 1_000_000 }, // due 750_000
        .{ .key = "b", .last_refresh_ms = 0, .expires_at_ms = 400_000 }, // due 300_000
        .{ .key = "c", .last_refresh_ms = 0, .expires_at_ms = 1000, .dead = true },
    };
    try std.testing.expectEqual(@as(?i64, 300_000), ws.nextWakeMs(&accounts, policy));
    for (&accounts) |*a| a.dead = true;
    try std.testing.expectEqual(@as(?i64, null), ws.nextWakeMs(&accounts, policy));
}

test "backoffDelayMs: exponential with cap" {
    const policy = ws.Policy{ .backoff_base_ms = 5_000, .backoff_factor = 2, .backoff_max_ms = 600_000 };
    try std.testing.expectEqual(@as(i64, 0), ws.backoffDelayMs(0, policy));
    try std.testing.expectEqual(@as(i64, 5_000), ws.backoffDelayMs(1, policy));
    try std.testing.expectEqual(@as(i64, 10_000), ws.backoffDelayMs(2, policy));
    try std.testing.expectEqual(@as(i64, 20_000), ws.backoffDelayMs(3, policy));
    try std.testing.expectEqual(@as(i64, 600_000), ws.backoffDelayMs(99, policy)); // capped, no overflow
}

// ── tick() ─────────────────────────────────────────────────────────────────

const due_policy = ws.Policy{ .refresh_percent = 75, .min_lead_ms = 0 };

test "tick: a due account is refreshed and its state is reset" {
    var clk = FakeClock{ .now = 1_000_000 };
    var ref = FakeRefresher{ .new_last = 1_000_000, .new_expires = 5_000_000 };
    const sched = scheduler(&clk, &ref, due_policy);
    var accounts = [_]ws.Account{
        .{ .key = "claude:org:acct", .last_refresh_ms = 0, .expires_at_ms = 1_000_000, .failures = 3, .next_attempt_ms = 0 },
    };
    const r = sched.tick(&accounts);
    try std.testing.expectEqual(@as(u32, 1), r.refreshed);
    try std.testing.expectEqual(@as(u32, 1), ref.calls);
    try std.testing.expectEqualStrings("claude:org:acct", ref.keyStr());
    try std.testing.expectEqual(@as(i64, 1_000_000), accounts[0].last_refresh_ms);
    try std.testing.expectEqual(@as(i64, 5_000_000), accounts[0].expires_at_ms);
    try std.testing.expectEqual(@as(u32, 0), accounts[0].failures);
}

test "tick: a not-due account is skipped without calling refresh" {
    var clk = FakeClock{ .now = 1_000_000 };
    var ref = FakeRefresher{};
    const sched = scheduler(&clk, &ref, due_policy);
    var accounts = [_]ws.Account{
        .{ .key = "k", .last_refresh_ms = 0, .expires_at_ms = 10_000_000 }, // due 7.5M > now
    };
    const r = sched.tick(&accounts);
    try std.testing.expectEqual(@as(u32, 1), r.not_due);
    try std.testing.expectEqual(@as(u32, 0), ref.calls);
}

test "tick: a failed refresh increments failures and arms backoff" {
    var clk = FakeClock{ .now = 1_000_000 };
    var ref = FakeRefresher{ .fail = true };
    const sched = scheduler(&clk, &ref, due_policy);
    var accounts = [_]ws.Account{
        .{ .key = "k", .last_refresh_ms = 0, .expires_at_ms = 1_000_000 },
    };
    const r = sched.tick(&accounts);
    try std.testing.expectEqual(@as(u32, 1), r.failed);
    try std.testing.expectEqual(@as(u32, 1), accounts[0].failures);
    try std.testing.expect(!accounts[0].dead);
    try std.testing.expectEqual(@as(i64, 1_005_000), accounts[0].next_attempt_ms); // now + base
}

test "tick: failures past the budget mark the account dead" {
    var clk = FakeClock{ .now = 1_000_000 };
    var ref = FakeRefresher{ .fail = true };
    const policy = ws.Policy{ .refresh_percent = 75, .min_lead_ms = 0, .max_failures = 2 };
    const sched = scheduler(&clk, &ref, policy);
    var accounts = [_]ws.Account{
        .{ .key = "k", .last_refresh_ms = 0, .expires_at_ms = 1_000_000, .failures = 1, .next_attempt_ms = 0 },
    };
    const r = sched.tick(&accounts);
    try std.testing.expectEqual(@as(u32, 1), r.died);
    try std.testing.expect(accounts[0].dead);
}

test "tick: an OOM is transient (no death charge) but arms the backoff gate" {
    var clk = FakeClock{ .now = 1_000_000 };
    var ref = FakeRefresher{ .oom = true };
    const sched = scheduler(&clk, &ref, due_policy);
    var accounts = [_]ws.Account{
        .{ .key = "k", .last_refresh_ms = 0, .expires_at_ms = 1_000_000, .failures = 0 },
    };
    const r = sched.tick(&accounts);
    try std.testing.expectEqual(@as(u32, 1), r.transient);
    try std.testing.expectEqual(@as(u32, 0), accounts[0].failures); // not charged toward death
    // gate armed at now + backoffDelayMs(failures+1 = 1) = now + base, so a sticky
    // OOM can't re-attempt every tick.
    try std.testing.expectEqual(@as(i64, 1_005_000), accounts[0].next_attempt_ms);
}

test "tick: NEVER-HALT — a dead peer does not block a live account" {
    var clk = FakeClock{ .now = 1_000_000 };
    var ref = FakeRefresher{ .new_last = 1_000_000, .new_expires = 9_000_000 };
    const sched = scheduler(&clk, &ref, due_policy);
    var accounts = [_]ws.Account{
        .{ .key = "dead", .last_refresh_ms = 0, .expires_at_ms = 1000, .dead = true },
        .{ .key = "live-due", .last_refresh_ms = 0, .expires_at_ms = 1_000_000 }, // due 750k <= now
        .{ .key = "live-future", .last_refresh_ms = 0, .expires_at_ms = 100_000_000 }, // not due
    };
    const r = sched.tick(&accounts);
    // The live, due account was refreshed despite the dead peer.
    try std.testing.expectEqual(@as(u32, 1), r.refreshed);
    try std.testing.expectEqual(@as(u32, 1), r.skipped_dead);
    try std.testing.expectEqual(@as(u32, 1), r.not_due);
    try std.testing.expectEqual(@as(i64, 9_000_000), accounts[1].expires_at_ms); // got refreshed
    try std.testing.expectEqualStrings("live-due", ref.keyStr());
}

// ── Adversarial-review regression tests (TIN-2053 unpark) ────────────────────

test "refreshDueAtMs: pathological i64-extreme inputs never overflow-panic" {
    // expires at the `never` sentinel with a negative last_refresh would overflow a
    // plain `expires - last_refresh`; the saturating ops must stay panic-free and
    // yield a well-defined far-future instant (this test crashes if any op wraps).
    const a = ws.Account{ .key = "k", .last_refresh_ms = -1, .expires_at_ms = ws.never };
    try std.testing.expect(ws.refreshDueAtMs(a, .{ .refresh_percent = 75, .min_lead_ms = 60_000 }) > 0);
    // an absurd min_lead must not overflow `expires - min_lead`.
    const b = ws.Account{ .key = "k", .last_refresh_ms = 0, .expires_at_ms = 1000 };
    _ = ws.refreshDueAtMs(b, .{ .refresh_percent = 100, .min_lead_ms = std.math.minInt(i64) });
    // an extreme positive last_refresh near i64-max must not overflow the `+`.
    const c = ws.Account{ .key = "k", .last_refresh_ms = std.math.maxInt(i64) - 10, .expires_at_ms = ws.never };
    _ = ws.refreshDueAtMs(c, .{});
    // and isDue/effectiveDueMs over the same extremes stay panic-free.
    try std.testing.expect(!ws.isDue(c, .{}, 0));
}

test "tick: a degenerate success (expiry <= issue) is escalated, not committed" {
    var clk = FakeClock{ .now = 1_000_000 };
    // "success" but new_expires == new_last → adopting it would be perpetually due.
    var ref = FakeRefresher{ .new_last = 2_000_000, .new_expires = 2_000_000 };
    const sched = scheduler(&clk, &ref, due_policy);
    var accounts = [_]ws.Account{
        .{ .key = "k", .last_refresh_ms = 0, .expires_at_ms = 1_000_000 },
    };
    const r = sched.tick(&accounts);
    try std.testing.expectEqual(@as(u32, 0), r.refreshed); // NOT adopted
    try std.testing.expectEqual(@as(u32, 1), r.failed); // escalated like a failure
    try std.testing.expectEqual(@as(u32, 1), accounts[0].failures);
    try std.testing.expectEqual(@as(i64, 0), accounts[0].last_refresh_ms); // bad instants not committed
    try std.testing.expect(accounts[0].next_attempt_ms > clk.now); // backoff gate armed → no busy-loop
}

test "tick: a sticky OOM is rate-limited by the backoff gate across ticks" {
    var clk = FakeClock{ .now = 1_000_000 };
    var ref = FakeRefresher{ .oom = true };
    const sched = scheduler(&clk, &ref, due_policy);
    var accounts = [_]ws.Account{
        .{ .key = "k", .last_refresh_ms = 0, .expires_at_ms = 1_000_000 },
    };
    _ = sched.tick(&accounts); // due → OOM → arms next_attempt at now+base
    try std.testing.expectEqual(@as(u32, 1), ref.calls);
    // tick again at the SAME clock: the gate makes it not-due → no second call (no hammer).
    const r2 = sched.tick(&accounts);
    try std.testing.expectEqual(@as(u32, 1), ref.calls);
    try std.testing.expectEqual(@as(u32, 1), r2.not_due);
    // advancing past the gate re-attempts.
    clk.now = accounts[0].next_attempt_ms;
    _ = sched.tick(&accounts);
    try std.testing.expectEqual(@as(u32, 2), ref.calls);
}

test "tick: OOM with saturated failure count still backs off without overflow" {
    var clk = FakeClock{ .now = 1_000_000 };
    var ref = FakeRefresher{ .oom = true };
    const sched = scheduler(&clk, &ref, due_policy);
    var accounts = [_]ws.Account{
        .{ .key = "k", .last_refresh_ms = 0, .expires_at_ms = 1_000_000, .failures = std.math.maxInt(u32) },
    };
    const r = sched.tick(&accounts);
    try std.testing.expectEqual(@as(u32, 1), r.transient);
    try std.testing.expectEqual(std.math.maxInt(u32), accounts[0].failures);
    try std.testing.expect(accounts[0].next_attempt_ms > clk.now);
}

test "tick: death is counted once, then the account is skipped on later ticks" {
    var clk = FakeClock{ .now = 1_000_000 };
    var ref = FakeRefresher{ .fail = true };
    const policy = ws.Policy{ .refresh_percent = 75, .min_lead_ms = 0, .max_failures = 1 };
    const sched = scheduler(&clk, &ref, policy);
    var accounts = [_]ws.Account{
        .{ .key = "k", .last_refresh_ms = 0, .expires_at_ms = 1_000_000 },
    };
    const r1 = sched.tick(&accounts); // first failure hits max_failures=1 → dead
    try std.testing.expectEqual(@as(u32, 1), r1.died);
    try std.testing.expect(accounts[0].dead);
    try std.testing.expectEqual(@as(u32, 1), ref.calls);
    const r2 = sched.tick(&accounts); // dead → skipped, not re-counted, no refresh call
    try std.testing.expectEqual(@as(u32, 0), r2.died);
    try std.testing.expectEqual(@as(u32, 1), r2.skipped_dead);
    try std.testing.expectEqual(@as(u32, 1), ref.calls);
}

test "nextWakeMs: a live account's backoff gate is reflected; dead peer ignored" {
    const policy = ws.Policy{ .refresh_percent = 75, .min_lead_ms = 0 };
    var accounts = [_]ws.Account{
        .{ .key = "dead", .last_refresh_ms = 0, .expires_at_ms = 500_000, .dead = true }, // ignored
        // due at 750k, but the backoff gate pushes the effective wake to 900k.
        .{ .key = "gated", .last_refresh_ms = 0, .expires_at_ms = 1_000_000, .next_attempt_ms = 900_000 },
    };
    try std.testing.expectEqual(@as(?i64, 900_000), ws.nextWakeMs(&accounts, policy));
}
