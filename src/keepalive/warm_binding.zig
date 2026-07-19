//! Keepalive warm-loop BINDING — greenfield glue between the pure scheduler
//! decision core (`warm_scheduler.zig`, B.1) and the live daemon (B.2). It is
//! itself still pure and seam-based: the actual refresh, the clock, and the wait
//! are INJECTED, so the binding logic — account-key round-trip, pool construction
//! from observed credential expiry, and the tick → next-wake → wait → repeat
//! driver — is fully unit-testable with NO I/O.
//!
//! The daemon wires the real seams (`pipeline.attemptRefresh`,
//! `std.time.milliTimestamp`, a timed wait on the stop condition, config account
//! enumeration); that thin layer is untested-by-design.
//!
//! NORTH STAR (never-halt, inherited from the scheduler): a dead/exhausted
//! account never blocks the loop; the loop ends only when EVERY account is dead
//! (nothing left to schedule) or the daemon signals stop.
//!
//! Self-contained: `std`, the shared closed outcome type, and
//! `warm_scheduler.zig`. Live pipeline/secret/config code still reaches the loop
//! exclusively through injected seams.

const std = @import("std");
const ws = @import("warm_scheduler.zig");
const types = @import("../types.zig");

// ── Account key: a stable opaque "<provider>:<account>" the scheduler acts on ──

pub const EncodeKeyError = error{ EmptyKeyComponent, NoSpaceLeft };

/// Encode (provider, account) into `buf` as "<provider>:<account>". Provider keys
/// are identifiers (no `:`); account names MAY contain `:`, which round-trips
/// because `decodeKey` splits on the FIRST `:` only. An empty provider or account
/// is rejected here (symmetric with `decodeKey`) so a bad key is caught at
/// construction, not as a refusal 8 failed refreshes later.
pub fn encodeKey(buf: []u8, provider: []const u8, account: []const u8) EncodeKeyError![]const u8 {
    if (provider.len == 0 or account.len == 0) return error.EmptyKeyComponent;
    return std.fmt.bufPrint(buf, "{s}:{s}", .{ provider, account });
}

pub const DecodedKey = struct {
    provider: []const u8,
    account: []const u8,
};

/// Split "<provider>:<account>" on the FIRST `:`. Returns null if there is no
/// separator, an empty provider, or an empty account — so a malformed key is a
/// refusal, never a silent mis-target.
pub fn decodeKey(key: []const u8) ?DecodedKey {
    const colon = std.mem.indexOfScalar(u8, key, ':') orelse return null;
    if (colon == 0 or colon + 1 >= key.len) return null;
    return .{ .provider = key[0..colon], .account = key[colon + 1 ..] };
}

// ── Pool construction ────────────────────────────────────────────────────────

/// One account's observed credential state, as the daemon reads it from the
/// store at tick time. `key` is borrowed and MUST outlive the built Account.
pub const Observed = struct {
    key: []const u8,
    /// Absolute expiry instant (Unix ms): claude's stored `expiresAt`, or codex's
    /// JWT-derived expiry (TIN-2087), normalized to ms by the daemon's reader.
    /// Persisted hard quarantines use 0 because they are dead before scheduling.
    expires_at_ms: i64,
    /// Persisted closed outcome, used to seed hard quarantine across restarts.
    refresh_outcome: ?types.RefreshOutcome = null,
    /// Private disposition for an in-flight/indeterminate rotating lineage.
    quarantined: bool = false,
};

const max_initial_stagger_ms: i64 = 60 * std.time.ms_per_min;

fn initialStaggerMs(key: []const u8, now_ms: i64, expires_at_ms: i64) i64 {
    const remaining = expires_at_ms -| now_ms;
    if (remaining <= 0) return 0;
    const window = @min(max_initial_stagger_ms, @divTrunc(remaining, 2));
    if (window <= 0) return 0;
    const hash = std.hash.Wyhash.hash(0x6f6d75785f776172, key);
    return @intCast(hash % @as(u64, @intCast(window + 1)));
}

/// Build the scheduler's mutable Account list from observed credential/refresh
/// state at `now_ms`. The credential store does NOT persist an issue instant, so
/// `last_refresh_ms` is seeded near `now_ms`: the scheduler then refreshes at
/// `refresh_percent` of the OBSERVED-REMAINING lifetime (i.e. "refresh once
/// refresh_percent of the life left at first observation has elapsed"), which is
/// a safe, slightly-earlier trigger than 75%-of-total. A deterministic,
/// key-derived backward stagger prevents a fresh loop from aligning every
/// account into one due cohort; it can only make first refreshes earlier, never
/// later than the no-stagger schedule. Caller owns the slice.
pub fn buildPool(allocator: std.mem.Allocator, observed: []const Observed, now_ms: i64) std.mem.Allocator.Error![]ws.Account {
    const accounts = try allocator.alloc(ws.Account, observed.len);
    for (observed, accounts) |o, *a| {
        const stagger = initialStaggerMs(o.key, now_ms, o.expires_at_ms);
        const quarantined = o.quarantined or
            o.refresh_outcome == .hard_lineage_invalidated;
        a.* = .{
            .key = o.key,
            .last_refresh_ms = now_ms -| stagger,
            .expires_at_ms = o.expires_at_ms,
            .dead = quarantined,
            .quarantined = quarantined,
            .last_refresh_outcome = o.refresh_outcome,
        };
    }
    return accounts;
}

// ── Refresh seam: bind the scheduler's RefreshFn to a (provider, account) op ───

/// The live refresh the daemon binds to `pipeline.attemptRefresh`: perform ONE
/// locked refresh for a decoded (provider, account) and report the new issue +
/// expiry instants. Errors map onto the scheduler's `RefreshError`
/// (`RefreshFailed` for a real failure, `OutOfMemory` for a transient).
pub const DoRefreshFn = *const fn (ctx: *anyopaque, provider: []const u8, account: []const u8) ws.RefreshError!ws.RefreshResult;
pub const DoRefreshOutcomeFn = *const fn (ctx: *anyopaque) ?types.RefreshOutcome;
pub const DoRefreshQuarantinedFn = *const fn (ctx: *anyopaque) bool;

/// Adapter that satisfies the scheduler's opaque `RefreshFn` by decoding the
/// account key and dispatching to an injected `DoRefreshFn`. A key that fails to
/// decode is a `RefreshFailed` (never a wrong-account refresh).
pub const RefreshBinding = struct {
    do_refresh: DoRefreshFn,
    do_refresh_ctx: *anyopaque,
    do_refresh_outcome: ?DoRefreshOutcomeFn = null,
    do_refresh_quarantined: ?DoRefreshQuarantinedFn = null,
    last_refresh_outcome: ?types.RefreshOutcome = null,
    last_refresh_quarantined: bool = false,

    /// Matches `ws.RefreshFn`. Bind via `.refresh = RefreshBinding.refresh,
    /// .refresh_ctx = &binding` on the Scheduler.
    pub fn refresh(ctx: *anyopaque, account_key: []const u8) ws.RefreshError!ws.RefreshResult {
        const self: *RefreshBinding = @ptrCast(@alignCast(ctx));
        self.last_refresh_outcome = null;
        self.last_refresh_quarantined = false;
        const dk = decodeKey(account_key) orelse {
            self.last_refresh_outcome = .transient_store;
            return ws.RefreshError.RefreshFailed;
        };
        const result = self.do_refresh(self.do_refresh_ctx, dk.provider, dk.account) catch |e| {
            self.last_refresh_outcome = if (self.do_refresh_outcome) |outcome_fn|
                outcome_fn(self.do_refresh_ctx)
            else switch (e) {
                error.OutOfMemory => .transient_store,
                error.RefreshFailed => .transient_endpoint,
            };
            self.last_refresh_quarantined = if (self.do_refresh_quarantined) |quarantined_fn|
                quarantined_fn(self.do_refresh_ctx)
            else
                false;
            return e;
        };
        const reported = if (self.do_refresh_outcome) |outcome_fn|
            outcome_fn(self.do_refresh_ctx)
        else
            null;
        self.last_refresh_outcome = reported orelse .refreshed;
        self.last_refresh_quarantined = if (self.do_refresh_quarantined) |quarantined_fn|
            quarantined_fn(self.do_refresh_ctx)
        else
            false;
        if (reported) |outcome| {
            if (outcome != .refreshed) return ws.RefreshError.RefreshFailed;
        }
        return result;
    }

    /// Matches `ws.RefreshOutcomeFn`; the scheduler reads this only after the
    /// corresponding refresh call returns.
    pub fn refreshOutcome(ctx: *anyopaque, account_key: []const u8) ?types.RefreshOutcome {
        _ = account_key;
        const self: *RefreshBinding = @ptrCast(@alignCast(ctx));
        return self.last_refresh_outcome;
    }

    pub fn refreshQuarantined(ctx: *anyopaque, account_key: []const u8) bool {
        _ = account_key;
        const self: *RefreshBinding = @ptrCast(@alignCast(ctx));
        return self.last_refresh_quarantined;
    }
};

// ── Loop driver ──────────────────────────────────────────────────────────────

/// Injected wait seam: block until the absolute instant `wake_at_ms` OR until the
/// daemon signals stop. Returns `true` to continue the loop, `false` to stop. The
/// daemon implements this as a real timed wait on its stop condition; tests use a
/// fake that advances a fake clock and bounds the iteration count.
pub const WaitFn = *const fn (ctx: *anyopaque, wake_at_ms: i64) bool;

/// Per-loop outcome counters for logging / the operator UI.
pub const LoopReport = struct {
    ticks: u32 = 0,
    refreshed: u32 = 0,
    failed: u32 = 0,
    died: u32 = 0,
    transient: u32 = 0,
    /// Current quarantined accounts: seeded from persisted startup state and
    /// incremented for quarantine transitions observed by this loop.
    quarantined: u32 = 0,
    /// True when the loop ended because every account is dead (nothing left to
    /// schedule), as opposed to a daemon stop.
    drained: bool = false,
};

/// Run the warm loop: tick the scheduler, accumulate the report, compute the next
/// wake via `nextWakeMs`, wait (injected), repeat — until `wait` returns false
/// (daemon stop) or `nextWakeMs` returns null (all accounts dead → drained).
/// Saturating counter adds so a pathological run can never overflow-panic.
pub fn runLoop(
    sched: *const ws.Scheduler,
    accounts: []ws.Account,
    wait: WaitFn,
    wait_ctx: *anyopaque,
) LoopReport {
    var report = LoopReport{};
    for (accounts) |account| {
        if (account.quarantined) report.quarantined +|= 1;
    }
    while (true) {
        const tr = sched.tick(accounts);
        report.ticks +|= 1;
        report.refreshed +|= tr.refreshed;
        report.failed +|= tr.failed;
        report.died +|= tr.died;
        report.transient +|= tr.transient;
        report.quarantined +|= tr.quarantined;
        const wake = ws.nextWakeMs(accounts, sched.policy) orelse {
            report.drained = true;
            break;
        };
        // Forward-progress floor: never wait on a past/now instant. A due-now
        // account — e.g. a token whose refreshed TTL is shorter than
        // `min_lead_ms`, so `refreshDueAtMs` clamps the due instant up to `now` —
        // makes `nextWakeMs` return a past/now value; a real timed wait would
        // return from that immediately, busy-spinning the refresh seam with zero
        // delay. Flooring to `now + backoff_base_ms` rate-limits such an account
        // to one pass per backoff interval regardless of the injected WaitFn.
        const now = sched.clock(sched.clock_ctx);
        const safe_wake = if (wake <= now) now +| sched.policy.backoff_base_ms else wake;
        if (!wait(wait_ctx, safe_wake)) break; // daemon signalled stop
    }
    return report;
}

test "run loop reports quarantine restored from persisted startup state" {
    const Fake = struct {
        fn clock(ctx: *anyopaque) i64 {
            _ = ctx;
            return 10_000;
        }

        fn refresh(ctx: *anyopaque, key: []const u8) ws.RefreshError!ws.RefreshResult {
            _ = ctx;
            _ = key;
            return error.RefreshFailed;
        }

        fn wait(ctx: *anyopaque, wake_at_ms: i64) bool {
            _ = ctx;
            _ = wake_at_ms;
            return false;
        }
    };
    var dummy: u8 = 0;
    const scheduler = ws.Scheduler{
        .clock = Fake.clock,
        .clock_ctx = &dummy,
        .refresh = Fake.refresh,
        .refresh_ctx = &dummy,
    };
    var accounts = [_]ws.Account{.{
        .key = "toy:quarantined",
        .last_refresh_ms = 0,
        .expires_at_ms = 0,
        .dead = true,
        .quarantined = true,
        .last_refresh_outcome = .transient_store,
    }};

    const report = runLoop(
        &scheduler,
        &accounts,
        Fake.wait,
        &dummy,
    );
    try std.testing.expectEqual(@as(u32, 1), report.quarantined);
    try std.testing.expectEqual(@as(u32, 0), report.transient);
    try std.testing.expect(report.drained);
}

test "refresh binding preserves the runner's closed failure outcome" {
    const Fake = struct {
        next_outcome: types.RefreshOutcome,

        fn refresh(
            ctx: *anyopaque,
            provider: []const u8,
            account: []const u8,
        ) ws.RefreshError!ws.RefreshResult {
            _ = ctx;
            _ = provider;
            _ = account;
            return error.RefreshFailed;
        }

        fn reportedOutcome(ctx: *anyopaque) ?types.RefreshOutcome {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            return self.next_outcome;
        }
    };

    var fake = Fake{ .next_outcome = .hard_lineage_invalidated };
    var binding = RefreshBinding{
        .do_refresh = Fake.refresh,
        .do_refresh_ctx = &fake,
        .do_refresh_outcome = Fake.reportedOutcome,
    };
    try std.testing.expectError(error.RefreshFailed, RefreshBinding.refresh(&binding, "toy:lineage"));
    try std.testing.expectEqual(
        types.RefreshOutcome.hard_lineage_invalidated,
        RefreshBinding.refreshOutcome(&binding, "toy:lineage").?,
    );

    try std.testing.expectError(error.RefreshFailed, RefreshBinding.refresh(&binding, "malformed"));
    try std.testing.expectEqual(
        types.RefreshOutcome.transient_store,
        RefreshBinding.refreshOutcome(&binding, "malformed").?,
    );
}

test "refresh binding converts successful typed transient into scheduler failure" {
    const Fake = struct {
        fn refresh(
            ctx: *anyopaque,
            provider: []const u8,
            account: []const u8,
        ) ws.RefreshError!ws.RefreshResult {
            _ = ctx;
            _ = provider;
            _ = account;
            return .{
                .new_last_refresh_ms = 10,
                .new_expires_at_ms = 20,
            };
        }

        fn reportedOutcome(ctx: *anyopaque) ?types.RefreshOutcome {
            _ = ctx;
            return .transient_lock;
        }
    };

    var fake: u8 = 0;
    var binding = RefreshBinding{
        .do_refresh = Fake.refresh,
        .do_refresh_ctx = &fake,
        .do_refresh_outcome = Fake.reportedOutcome,
    };
    try std.testing.expectError(
        error.RefreshFailed,
        RefreshBinding.refresh(&binding, "toy:lineage"),
    );
    try std.testing.expectEqual(
        types.RefreshOutcome.transient_lock,
        binding.last_refresh_outcome.?,
    );
}
