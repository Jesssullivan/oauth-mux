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
//! Self-contained: `std` + `warm_scheduler.zig` only. No `@import` of the live
//! `src` (pipeline/secret/config) — those reach the loop exclusively through the
//! injected `DoRefreshFn`/`WaitFn` seams.

const std = @import("std");
const ws = @import("warm_scheduler.zig");

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
    expires_at_ms: i64,
};

/// Build the scheduler's mutable Account list from observed credential state at
/// `now_ms`. The credential store does NOT persist an issue instant, so
/// `last_refresh_ms` is seeded to `now_ms`: the scheduler then refreshes at
/// `refresh_percent` of the OBSERVED-REMAINING lifetime (i.e. "refresh once
/// refresh_percent of the life left at first observation has elapsed"), which is
/// a safe, slightly-earlier trigger than 75%-of-total. Caller owns the slice.
pub fn buildPool(allocator: std.mem.Allocator, observed: []const Observed, now_ms: i64) std.mem.Allocator.Error![]ws.Account {
    const accounts = try allocator.alloc(ws.Account, observed.len);
    for (observed, accounts) |o, *a| {
        a.* = .{
            .key = o.key,
            .last_refresh_ms = now_ms,
            .expires_at_ms = o.expires_at_ms,
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

/// Adapter that satisfies the scheduler's opaque `RefreshFn` by decoding the
/// account key and dispatching to an injected `DoRefreshFn`. A key that fails to
/// decode is a `RefreshFailed` (never a wrong-account refresh).
pub const RefreshBinding = struct {
    do_refresh: DoRefreshFn,
    do_refresh_ctx: *anyopaque,

    /// Matches `ws.RefreshFn`. Bind via `.refresh = RefreshBinding.refresh,
    /// .refresh_ctx = &binding` on the Scheduler.
    pub fn refresh(ctx: *anyopaque, account_key: []const u8) ws.RefreshError!ws.RefreshResult {
        const self: *RefreshBinding = @ptrCast(@alignCast(ctx));
        const dk = decodeKey(account_key) orelse return ws.RefreshError.RefreshFailed;
        return self.do_refresh(self.do_refresh_ctx, dk.provider, dk.account);
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
    while (true) {
        const tr = sched.tick(accounts);
        report.ticks +|= 1;
        report.refreshed +|= tr.refreshed;
        report.failed +|= tr.failed;
        report.died +|= tr.died;
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
