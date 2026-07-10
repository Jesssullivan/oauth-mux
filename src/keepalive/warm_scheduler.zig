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
    const lifetime = account.expires_at_ms -| account.last_refresh_ms;
    if (lifetime <= 0) return account.last_refresh_ms; // already expired/odd → due now
    // last_refresh + lifetime * percent/100. EVERY arithmetic op here is
    // saturating (`-|`/`*|`/`+|`) so even a pathological account — expires_at_ms
    // at the `never` sentinel (i64-max), a negative or extreme last_refresh_ms,
    // or an absurd min_lead_ms — can NEVER overflow-panic the daemon (the maximal
    // never-halt violation: one bad account would abort warming for the fleet).
    // The worst case degrades to a far-future (or due-now) instant, tolerated fine.
    const elapsed_target = @divTrunc(lifetime *| @as(i64, policy.refresh_percent), 100);
    var due = account.last_refresh_ms +| elapsed_target;
    const latest = account.expires_at_ms -| policy.min_lead_ms;
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
/// Seam contract: `new_expires_at_ms` SHOULD be strictly greater than
/// `new_last_refresh_ms`. A degenerate result (expiry <= issue) would leave the
/// account perpetually `isDue` → a per-tick busy-loop against the broker. The
/// pure core defends itself in depth: `tick` treats such a result as a refresh
/// failure (rate-limited via backoff, escalates to `dead`) rather than committing
/// the bad instants. The B.2 seam binding should still reject such a provider
/// response upstream — this guard is the last line, not the first.
pub const RefreshResult = struct {
    new_last_refresh_ms: i64,
    new_expires_at_ms: i64,
};

/// Perform one account's refresh (broker `credential/refresh` under the flock).
pub const RefreshFn = *const fn (ctx: *anyopaque, account_key: []const u8) RefreshError!RefreshResult;

// ── Notification seam (TIN-2061) ─────────────────────────────────────────────

/// The two operator-relevant transitions the scheduler REPORTS (it never
/// delivers): a single proactive refresh failed, or an account exhausted its
/// failure budget and was marked dead. The live glue
/// (`keepalive/notify_adapter.zig`) turns these into a desktop notification
/// under the opt-in + dedupe policy. Keeping the seam opaque (`account_key` +
/// this enum, no `notify.zig` import) preserves the pure core's std-only,
/// I/O-free contract.
pub const NotifyReason = enum { refresh_failed, credential_dead };

/// Injected notification callback. Called at most once per transition, from the
/// tick's failure path only — never on a successful refresh, never on a skipped
/// dead account, never on a transient (OOM). `account_key` is borrowed.
pub const NotifyFn = *const fn (ctx: *anyopaque, reason: NotifyReason, account_key: []const u8) void;

pub const NotifySeam = struct { func: NotifyFn, ctx: *anyopaque };

/// Per-tick outcome counters (for logging / the operator UI).
pub const TickReport = struct {
    refreshed: u32 = 0,
    failed: u32 = 0,
    died: u32 = 0,
    not_due: u32 = 0,
    skipped_dead: u32 = 0,
    /// Transient errors (e.g. OOM) — not counted toward the death budget, but the
    /// backoff gate IS armed so a sticky transient can't hammer the broker.
    transient: u32 = 0,
};

// ── The scheduler ──────────────────────────────────────────────────────────

pub const Scheduler = struct {
    policy: Policy = .{},
    clock: ClockFn,
    clock_ctx: *anyopaque,
    refresh: RefreshFn,
    refresh_ctx: *anyopaque,
    /// Optional desktop-notification seam (TIN-2061). null (default) = today's
    /// behavior byte-for-byte: no notifications, and the pure core stays fully
    /// deterministic (the seam is the only effect, and it is injected).
    notify: ?NotifySeam = null,

    /// Record a refresh failure on `a`: increment the failure count, arm the
    /// backoff gate, and mark the account `dead` exactly once when it exhausts the
    /// failure budget. Shared by the hard-failure path and the degenerate-success
    /// guard so both escalate identically. `now +| backoff` is saturating so a
    /// huge clock value can't overflow the gate instant.
    fn recordFailure(self: *const Scheduler, a: *Account, now: i64, report: *TickReport) void {
        a.failures +|= 1;
        if (a.failures >= self.policy.max_failures) {
            a.dead = true;
            report.died += 1;
            // Fires exactly once: the next tick skips the now-dead account, so
            // this death transition is reported to the operator a single time.
            if (self.notify) |n| n.func(n.ctx, .credential_dead, a.key);
        } else {
            a.next_attempt_ms = now +| backoffDelayMs(a.failures, self.policy);
            report.failed += 1;
            if (self.notify) |n| n.func(n.ctx, .refresh_failed, a.key);
        }
    }

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
                        // Transient (host-wide pressure, not account-specific): do
                        // NOT count toward the death budget, but arm the backoff
                        // gate so a sticky OOM can't re-attempt every tick.
                        // failures is untouched, so backoffDelayMs(failures+1)
                        // floors at one backoff_base even on the first OOM.
                        a.next_attempt_ms = now +| backoffDelayMs(a.failures +| 1, self.policy);
                        report.transient += 1;
                    },
                    error.RefreshFailed => self.recordFailure(a, now, &report),
                }
                continue;
            };
            // Defend the pure core against a degenerate "success" (expiry <= issue):
            // adopting it would make the account perpetually `isDue` → a per-tick
            // busy-loop against the broker. Escalate it like a failure instead of
            // committing the bad instants (see RefreshResult's seam contract).
            if (result.new_expires_at_ms <= result.new_last_refresh_ms) {
                self.recordFailure(a, now, &report);
                continue;
            }
            a.last_refresh_ms = result.new_last_refresh_ms;
            a.expires_at_ms = result.new_expires_at_ms;
            a.failures = 0;
            a.next_attempt_ms = 0;
            report.refreshed += 1;
        }
        return report;
    }
};
