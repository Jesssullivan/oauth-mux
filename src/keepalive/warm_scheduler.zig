//! Keepalive warm-loop scheduler — greenfield, the pure core of the professional
//! keepalive daemon (TIN-1825 / ide-keepalive epic).
//!
//! The daemon's job is to keep every enrolled account's token WARM so the IDE /
//! agent never sees a dead token: refresh each account proactively at ~75% of
//! its lifetime (well before expiry), under the broker's per-account flock. This
//! module is the *decision* core — WHEN to refresh, and WHAT to do on failure —
//! with the clock and the actual refresh injected as seams. It performs NO I/O,
//! NO allocation, and NO clock reads of its own, so it is fully deterministic
//! and unit-testable; the surrounding daemon loop (tick → sleep → repeat) is the
//! thin untested-by-design wrapper.
//!
//! North star (resilience-never-halt): a dead/exhausted account must NEVER block
//! work. A refresh that fails repeatedly is marked `dead` and SKIPPED — the other
//! accounts keep being warmed. One live account keeps the fleet afloat.
//!
//! Self-contained: `std` only, no `@import` of existing `src`. The daemon wiring
//! that calls `tick` and the binding of the refresh seam to the broker's
//! `credential/refresh` (B.2) are coordinated follow-ups (shared files).

const std = @import("std");

/// Per-account state the scheduler reads and updates in place. `key` is an
/// opaque, borrowed identifier (e.g. "claude:org:acct") the refresh seam acts on;
/// the scheduler never owns or frees it.
pub const Account = struct {
    key: []const u8,
    /// When the current token was issued / last refreshed (absolute Unix ms).
    last_refresh_ms: i64,
    /// Absolute token expiry (Unix ms).
    expires_at_ms: i64,
    /// Consecutive refresh failures (reset to 0 on success).
    failures: u32 = 0,
    /// Backoff gate: earliest next refresh attempt (Unix ms). 0 = no gate.
    next_attempt_ms: i64 = 0,
    /// Gave up after `max_failures` — skipped by the scheduler so it never blocks
    /// the live accounts. Cleared externally on operator re-login.
    dead: bool = false,
};

/// Tunable scheduling policy. Integer-only (no float) so timing is deterministic.
pub const Policy = struct {
    /// Refresh when this percent of the token lifetime has elapsed (75% → refresh
    /// with 25% of life remaining).
    refresh_percent: u8 = 75,
    /// Always refresh at least this long before expiry, regardless of percent.
    min_lead_ms: i64 = 60_000, // 1 min
    /// Exponential backoff on failure: base, factor, cap.
    backoff_base_ms: i64 = 5_000, // 5 s
    backoff_factor: u32 = 2,
    backoff_max_ms: i64 = 600_000, // 10 min
    /// After this many consecutive failures, mark the account dead.
    max_failures: u32 = 8,
};

/// Sentinel "never due" instant for dead accounts.
pub const never: i64 = std.math.maxInt(i64);

// ── Pure scheduling math ───────────────────────────────────────────────────

/// The instant a healthy token should be proactively refreshed: `refresh_percent`
/// of the way through its lifetime, but never later than `min_lead_ms` before
/// expiry, and never before it was issued. Ignores backoff/dead state.
pub fn refreshDueAtMs(account: Account, policy: Policy) i64 {
    const lifetime = account.expires_at_ms - account.last_refresh_ms;
    if (lifetime <= 0) return account.last_refresh_ms; // already expired/odd → due now
    // last_refresh + lifetime * percent/100. Saturating multiply (`*|`) so a
    // pathological expires_at_ms near i64-max (e.g. a "never expires" sentinel —
    // cf. `never` above) can never overflow-panic the daemon; it just yields a
    // far-future due instant, which the never-halt loop tolerates fine.
    const elapsed_target = @divTrunc(lifetime *| @as(i64, policy.refresh_percent), 100);
    var due = account.last_refresh_ms + elapsed_target;
    const latest = account.expires_at_ms - policy.min_lead_ms;
    if (due > latest) due = latest;
    if (due < account.last_refresh_ms) due = account.last_refresh_ms;
    return due;
}

/// The effective due instant including the backoff gate. Dead → `never`.
pub fn effectiveDueMs(account: Account, policy: Policy) i64 {
    if (account.dead) return never;
    const due = refreshDueAtMs(account, policy);
    return if (account.next_attempt_ms > due) account.next_attempt_ms else due;
}

/// Is this account due for a refresh at `now_ms`? (false if dead.)
pub fn isDue(account: Account, policy: Policy, now_ms: i64) bool {
    if (account.dead) return false;
    return now_ms >= effectiveDueMs(account, policy);
}

/// The earliest instant the daemon should next wake to act, across all accounts,
/// or null if every account is dead (nothing left to schedule). A value <= now
/// means at least one account is already due.
pub fn nextWakeMs(accounts: []const Account, policy: Policy) ?i64 {
    var best: ?i64 = null;
    for (accounts) |a| {
        if (a.dead) continue;
        const due = effectiveDueMs(a, policy);
        if (best == null or due < best.?) best = due;
    }
    return best;
}

/// Exponential backoff delay for the Nth consecutive failure (1-based), capped.
/// Saturating multiply avoids overflow at large failure counts.
pub fn backoffDelayMs(failures: u32, policy: Policy) i64 {
    if (failures == 0) return 0;
    var delay: i64 = policy.backoff_base_ms;
    var i: u32 = 1;
    while (i < failures) : (i += 1) {
        delay = delay *| @as(i64, policy.backoff_factor);
        if (delay >= policy.backoff_max_ms) return policy.backoff_max_ms;
    }
    return @min(delay, policy.backoff_max_ms);
}

// ── Injected seams ─────────────────────────────────────────────────────────

pub const ClockFn = *const fn (ctx: *anyopaque) i64;

pub const RefreshError = error{ OutOfMemory, RefreshFailed };

/// Outcome of a successful refresh: the new issue + expiry instants the broker
/// wrote. (The credential itself is materialized by the broker/adapter, not here.)
///
/// Seam contract: `new_expires_at_ms` MUST be strictly greater than
/// `new_last_refresh_ms`. A degenerate result (expiry <= issue) leaves the
/// account perpetually `isDue`, so the daemon loop would re-refresh it every
/// tick — the binding (B.2 follow-up) is responsible for rejecting/flooring a
/// provider response that violates this, not the pure core here.
pub const RefreshResult = struct {
    new_last_refresh_ms: i64,
    new_expires_at_ms: i64,
};

/// Perform one account's refresh (broker `credential/refresh` under the flock).
pub const RefreshFn = *const fn (ctx: *anyopaque, account_key: []const u8) RefreshError!RefreshResult;

/// Per-tick outcome counters (for logging / the operator UI).
pub const TickReport = struct {
    refreshed: u32 = 0,
    failed: u32 = 0,
    died: u32 = 0,
    not_due: u32 = 0,
    skipped_dead: u32 = 0,
    /// Transient errors (e.g. OOM) — retried next tick, no state change.
    transient: u32 = 0,
};

// ── The scheduler ──────────────────────────────────────────────────────────

pub const Scheduler = struct {
    policy: Policy = .{},
    clock: ClockFn,
    clock_ctx: *anyopaque,
    refresh: RefreshFn,
    refresh_ctx: *anyopaque,

    /// Run one scheduling tick: refresh every account due now (updating its state
    /// in place), apply backoff on failure, and mark accounts dead past the
    /// failure budget. Dead accounts are skipped so they never block the live
    /// ones (never-halt). No allocation, no blocking. Returns the outcome counts.
    pub fn tick(self: *const Scheduler, accounts: []Account) TickReport {
        const now = self.clock(self.clock_ctx);
        var report = TickReport{};
        for (accounts) |*a| {
            if (a.dead) {
                report.skipped_dead += 1;
                continue;
            }
            if (!isDue(a.*, self.policy, now)) {
                report.not_due += 1;
                continue;
            }
            const result = self.refresh(self.refresh_ctx, a.key) catch |err| {
                switch (err) {
                    error.OutOfMemory => {
                        // Transient: leave state untouched, retry next tick.
                        report.transient += 1;
                    },
                    error.RefreshFailed => {
                        a.failures += 1;
                        if (a.failures >= self.policy.max_failures) {
                            a.dead = true;
                            report.died += 1;
                        } else {
                            a.next_attempt_ms = now + backoffDelayMs(a.failures, self.policy);
                            report.failed += 1;
                        }
                    },
                }
                continue;
            };
            a.last_refresh_ms = result.new_last_refresh_ms;
            a.expires_at_ms = result.new_expires_at_ms;
            a.failures = 0;
            a.next_attempt_ms = 0;
            report.refreshed += 1;
        }
        return report;
    }
};
