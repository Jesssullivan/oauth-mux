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
//! The scheduler imports only `std` plus the shared closed `RefreshOutcome`;
//! credential I/O remains outside this pure core.

const std = @import("std");
const types = @import("../types.zig");

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
    /// Hard rotating-lineage death, distinct from a legacy retry-budget death.
    quarantined: bool = false,
    /// Last closed refresh result observed for this account.
    last_refresh_outcome: ?types.RefreshOutcome = null,
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
/// pure core defends itself in depth: `tick` treats such a result as a typed
/// endpoint transient (rate-limited via backoff, never charged to the credential
/// death budget) rather than committing the bad instants. The B.2 seam binding
/// should still reject such a provider response upstream — this guard is the
/// last line, not the first.
pub const RefreshResult = struct {
    new_last_refresh_ms: i64,
    new_expires_at_ms: i64,
};

/// Perform one account's refresh (broker `credential/refresh` under the flock).
pub const RefreshFn = *const fn (ctx: *anyopaque, account_key: []const u8) RefreshError!RefreshResult;
pub const RefreshOutcomeFn = *const fn (ctx: *anyopaque, account_key: []const u8) ?types.RefreshOutcome;
pub const RefreshQuarantinedFn = *const fn (ctx: *anyopaque, account_key: []const u8) bool;

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
/// dead account, never on a typed transient. `account_key` is borrowed.
pub const NotifyFn = *const fn (ctx: *anyopaque, reason: NotifyReason, account_key: []const u8) void;

pub const NotifySeam = struct { func: NotifyFn, ctx: *anyopaque };

/// Per-tick outcome counters (for logging / the operator UI).
pub const TickReport = struct {
    refreshed: u32 = 0,
    failed: u32 = 0,
    died: u32 = 0,
    not_due: u32 = 0,
    skipped_dead: u32 = 0,
    /// Typed transient errors — not counted toward the death budget, but the
    /// backoff gate IS armed so a sticky transient can't hammer the broker.
    transient: u32 = 0,
    quarantined: u32 = 0,
};

// ── The scheduler ──────────────────────────────────────────────────────────

pub const Scheduler = struct {
    policy: Policy = .{},
    clock: ClockFn,
    clock_ctx: *anyopaque,
    refresh: RefreshFn,
    refresh_ctx: *anyopaque,
    /// Optional typed outcome side channel. Legacy injected seams can omit it
    /// and retain their existing generic RefreshFailed retry-budget behavior.
    refresh_outcome: ?RefreshOutcomeFn = null,
    /// Internal disposition side channel. Indeterminate rotating lineage is
    /// quarantined even though its persisted public outcome remains transient.
    refresh_quarantined: ?RefreshQuarantinedFn = null,
    /// Optional desktop-notification seam (TIN-2061). null (default) = today's
    /// behavior byte-for-byte: no notifications, and the pure core stays fully
    /// deterministic (the seam is the only effect, and it is injected).
    notify: ?NotifySeam = null,

    /// Record a refresh failure on `a`: increment the failure count, arm the
    /// backoff gate, and mark the account `dead` exactly once when it exhausts the
    /// failure budget. `now +| backoff` is saturating so a huge clock value can't
    /// overflow the gate instant.
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

    fn recordTransient(self: *const Scheduler, a: *Account, now: i64, report: *TickReport) void {
        a.next_attempt_ms = now +| backoffDelayMs(a.failures +| 1, self.policy);
        report.transient += 1;
    }

    fn recordTypedTransient(self: *const Scheduler, a: *Account, now: i64, report: *TickReport) void {
        self.recordTransient(a, now, report);
    }

    fn quarantine(self: *const Scheduler, a: *Account, report: *TickReport) void {
        a.dead = true;
        a.quarantined = true;
        a.next_attempt_ms = 0;
        report.died += 1;
        report.quarantined += 1;
        if (self.notify) |n| n.func(n.ctx, .credential_dead, a.key);
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
                        a.last_refresh_outcome = .transient_store;
                        self.recordTransient(a, now, &report);
                    },
                    error.RefreshFailed => {
                        const typed = if (self.refresh_outcome) |outcome_fn|
                            outcome_fn(self.refresh_ctx, a.key)
                        else
                            null;
                        if (typed) |outcome| {
                            a.last_refresh_outcome = outcome;
                            const quarantined = if (self.refresh_quarantined) |quarantined_fn|
                                quarantined_fn(self.refresh_ctx, a.key)
                            else
                                false;
                            if (quarantined or outcome == .hard_lineage_invalidated) {
                                self.quarantine(a, &report);
                            } else switch (outcome) {
                                .transient_lock,
                                .transient_network,
                                .transient_store,
                                .transient_endpoint,
                                => self.recordTypedTransient(a, now, &report),
                                .hard_lineage_invalidated => unreachable,
                                // A seam reporting success through an error is
                                // inconsistent; preserve the legacy fail-closed
                                // retry-budget behavior.
                                .refreshed => self.recordFailure(a, now, &report),
                            }
                        } else {
                            self.recordFailure(a, now, &report);
                        }
                    },
                }
                continue;
            };
            // Defend the pure core against a degenerate "success" (expiry <= issue):
            // adopting it would make the account perpetually `isDue` → a per-tick
            // busy-loop against the broker. Escalate it like a failure instead of
            // committing the bad instants (see RefreshResult's seam contract).
            if (result.new_expires_at_ms <= result.new_last_refresh_ms) {
                a.last_refresh_outcome = .transient_endpoint;
                self.recordTypedTransient(a, now, &report);
                continue;
            }
            a.last_refresh_ms = result.new_last_refresh_ms;
            a.expires_at_ms = result.new_expires_at_ms;
            a.failures = 0;
            a.next_attempt_ms = 0;
            a.last_refresh_outcome = .refreshed;
            report.refreshed += 1;
        }
        return report;
    }
};

test "typed keepalive outcomes back off transients and quarantine only hard lineage" {
    const Fake = struct {
        outcome: types.RefreshOutcome,

        fn clock(ctx: *anyopaque) i64 {
            _ = ctx;
            return 10_000;
        }

        fn refresh(ctx: *anyopaque, key: []const u8) RefreshError!RefreshResult {
            _ = ctx;
            _ = key;
            return error.RefreshFailed;
        }

        fn refreshOutcome(ctx: *anyopaque, key: []const u8) ?types.RefreshOutcome {
            _ = key;
            const self: *@This() = @ptrCast(@alignCast(ctx));
            return self.outcome;
        }
    };

    inline for (std.meta.fields(types.RefreshOutcome)) |field| {
        const outcome: types.RefreshOutcome = @enumFromInt(field.value);
        var fake = Fake{ .outcome = outcome };
        const scheduler = Scheduler{
            .clock = Fake.clock,
            .clock_ctx = &fake,
            .refresh = Fake.refresh,
            .refresh_ctx = &fake,
            .refresh_outcome = Fake.refreshOutcome,
        };
        var accounts = [_]Account{.{
            .key = "toy:lineage",
            .last_refresh_ms = 0,
            .expires_at_ms = 1,
        }};
        const report = scheduler.tick(&accounts);
        try std.testing.expectEqual(outcome, accounts[0].last_refresh_outcome.?);
        switch (outcome) {
            .transient_lock, .transient_network, .transient_store, .transient_endpoint => {
                try std.testing.expectEqual(@as(u32, 1), report.transient);
                try std.testing.expect(!accounts[0].dead);
                try std.testing.expectEqual(@as(u32, 0), report.failed);
                try std.testing.expectEqual(@as(u32, 0), accounts[0].failures);
                try std.testing.expect(accounts[0].next_attempt_ms > 10_000);
            },
            .hard_lineage_invalidated => {
                try std.testing.expect(accounts[0].dead);
                try std.testing.expect(accounts[0].quarantined);
                try std.testing.expectEqual(@as(u32, 1), report.quarantined);
                try std.testing.expectEqual(@as(u32, 1), report.died);
            },
            .refreshed => {
                // Success reported through an error is inconsistent and keeps
                // the legacy fail-closed retry-budget behavior.
                try std.testing.expectEqual(@as(u32, 1), report.failed);
                try std.testing.expectEqual(@as(u32, 1), accounts[0].failures);
            },
        }
    }
}

test "private indeterminate disposition quarantines a transient persisted outcome" {
    const Fake = struct {
        fn clock(ctx: *anyopaque) i64 {
            _ = ctx;
            return 10_000;
        }

        fn refresh(ctx: *anyopaque, key: []const u8) RefreshError!RefreshResult {
            _ = ctx;
            _ = key;
            return error.RefreshFailed;
        }

        fn refreshOutcome(ctx: *anyopaque, key: []const u8) ?types.RefreshOutcome {
            _ = ctx;
            _ = key;
            return .transient_store;
        }

        fn refreshQuarantined(ctx: *anyopaque, key: []const u8) bool {
            _ = ctx;
            _ = key;
            return true;
        }
    };
    var dummy_ctx: u8 = 0;
    const scheduler = Scheduler{
        .clock = Fake.clock,
        .clock_ctx = &dummy_ctx,
        .refresh = Fake.refresh,
        .refresh_ctx = &dummy_ctx,
        .refresh_outcome = Fake.refreshOutcome,
        .refresh_quarantined = Fake.refreshQuarantined,
    };
    var accounts = [_]Account{.{
        .key = "toy:indeterminate",
        .last_refresh_ms = 0,
        .expires_at_ms = 1,
    }};
    const report = scheduler.tick(&accounts);
    try std.testing.expect(accounts[0].dead);
    try std.testing.expect(accounts[0].quarantined);
    try std.testing.expectEqual(
        types.RefreshOutcome.transient_store,
        accounts[0].last_refresh_outcome.?,
    );
    try std.testing.expectEqual(@as(u32, 1), report.quarantined);
    try std.testing.expectEqual(@as(u32, 0), report.transient);
}

test "typed transients never consume the legacy death budget after repeated retries" {
    const Fake = struct {
        outcome: types.RefreshOutcome,
        now: i64 = 10_000,
        refresh_failed_notifications: u32 = 0,
        credential_dead_notifications: u32 = 0,

        fn clock(ctx: *anyopaque) i64 {
            const self: *@This() = @ptrCast(@alignCast(ctx));
            return self.now;
        }

        fn refresh(ctx: *anyopaque, key: []const u8) RefreshError!RefreshResult {
            _ = ctx;
            _ = key;
            return error.RefreshFailed;
        }

        fn refreshOutcome(ctx: *anyopaque, key: []const u8) ?types.RefreshOutcome {
            _ = key;
            const self: *@This() = @ptrCast(@alignCast(ctx));
            return self.outcome;
        }

        fn notify(ctx: *anyopaque, reason: NotifyReason, key: []const u8) void {
            _ = key;
            const self: *@This() = @ptrCast(@alignCast(ctx));
            switch (reason) {
                .refresh_failed => self.refresh_failed_notifications += 1,
                .credential_dead => self.credential_dead_notifications += 1,
            }
        }
    };

    const transients = [_]types.RefreshOutcome{
        .transient_lock,
        .transient_network,
        .transient_store,
        .transient_endpoint,
    };
    for (transients) |outcome| {
        var fake = Fake{ .outcome = outcome };
        const scheduler = Scheduler{
            .policy = .{ .max_failures = 8 },
            .clock = Fake.clock,
            .clock_ctx = &fake,
            .refresh = Fake.refresh,
            .refresh_ctx = &fake,
            .refresh_outcome = Fake.refreshOutcome,
            .notify = .{ .func = Fake.notify, .ctx = &fake },
        };
        var accounts = [_]Account{.{
            .key = "toy:transient",
            .last_refresh_ms = 0,
            .expires_at_ms = 1,
            .failures = 7,
        }};

        var attempts: usize = 0;
        while (attempts < 16) : (attempts += 1) {
            accounts[0].next_attempt_ms = 0;
            const report = scheduler.tick(&accounts);
            try std.testing.expectEqual(@as(u32, 1), report.transient);
            try std.testing.expectEqual(@as(u32, 0), report.failed);
            try std.testing.expectEqual(@as(u32, 0), report.died);
            try std.testing.expect(!accounts[0].dead);
            try std.testing.expectEqual(@as(u32, 7), accounts[0].failures);
            fake.now += 1;
        }
        try std.testing.expectEqual(
            @as(u32, 0),
            fake.refresh_failed_notifications,
        );
        try std.testing.expectEqual(
            @as(u32, 0),
            fake.credential_dead_notifications,
        );
    }
}
