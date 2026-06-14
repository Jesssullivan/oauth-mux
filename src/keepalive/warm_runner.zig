//! Keepalive warm-loop RUNNER — the live glue (B.2) that binds the pure binding
//! (`warm_binding.zig`) to the real system: it builds the scheduler's account
//! pool from live config + credential expiry, and satisfies the binding's
//! injected `DoRefreshFn`/`ClockFn` from `pipeline.refreshAccount` and the wall
//! clock. Unlike `warm_binding`/`warm_scheduler` (pure), this layer DOES import
//! `src` — it is the seam-binding glue, not the decision core.
//!
//! SAFE-BY-GATE: `pipeline.refreshAccount` refuses any account whose
//! `proactive_refresh` grant + operator opt-in are not both admitted (the
//! writeback gate) BEFORE any network/store mutation, returning a typed failure.
//! So a warm loop over builtins (which declare no grant) only records refusals;
//! the scheduler backs each off and marks it dead, the loop drains harmlessly.
//! Nothing is rotated until the grant flip + live proof (TIN-2054).
//!
//! The actual timed wait + the CLI/daemon command that calls `bind.runLoop` are
//! the thin, untested-by-design wrapper (a real wait blocks on the daemon stop
//! condition); this file's pool-build + refresh adapter are unit-tested.

const std = @import("std");
const ws = @import("warm_scheduler.zig");
const bind = @import("warm_binding.zig");
const pipeline = @import("../pipeline.zig");
const config_mod = @import("../config.zig");
const health_mod = @import("../health.zig");

/// Context the binding's `DoRefreshFn`/`ClockFn` are bound to. Borrows the config
/// and health store for the loop's lifetime.
pub const WarmRunner = struct {
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    health: *health_mod.HealthStore,

    /// `ws.ClockFn`: real wall clock in Unix ms.
    pub fn clock(ctx: *anyopaque) i64 {
        _ = ctx;
        return std.time.milliTimestamp();
    }

    /// `bind.DoRefreshFn`: proactively refresh one (provider, account) via
    /// `pipeline.refreshAccount`, building a fresh Context per call (deinit'd
    /// each call — no cross-tick state leak). Maps the pipeline outcome onto the
    /// scheduler's `RefreshError`: `OutOfMemory` → transient (host pressure, not
    /// the account's fault, not charged toward death); any other failure
    /// (incl. the grant-gate refusal and a network/endpoint failure) →
    /// `RefreshFailed`. On success the new expiry comes from the POST-rotation
    /// `ctx.token` (seconds → ms, saturating), so the scheduler re-arms honestly.
    pub fn doRefresh(ctx: *anyopaque, provider: []const u8, account: []const u8) ws.RefreshError!ws.RefreshResult {
        const self: *WarmRunner = @ptrCast(@alignCast(ctx));
        var pctx = pipeline.Context.init(self.allocator, self.cfg, self.health);
        defer pctx.deinit();
        pctx.provider_name = provider;
        pctx.account_name = account;
        pipeline.refreshAccount(&pctx) catch |e| return switch (e) {
            error.OutOfMemory => ws.RefreshError.OutOfMemory,
            else => ws.RefreshError.RefreshFailed,
        };
        const tok = pctx.token orelse return ws.RefreshError.RefreshFailed;
        const exp_s = tok.expires_at orelse return ws.RefreshError.RefreshFailed;
        return .{
            .new_last_refresh_ms = std.time.milliTimestamp(),
            .new_expires_at_ms = exp_s *| std.time.ms_per_s,
        };
    }
};

/// The warm pool built from live config: the scheduler's `Observed` rows plus an
/// arena owning the "<provider>:<account>" key strings the rows (and the built
/// Accounts) borrow. `deinit` frees everything; it must outlive any
/// `warm_binding.buildPool` / scheduler run over `observed`.
pub const Pool = struct {
    observed: []const bind.Observed,
    arena: std.heap.ArenaAllocator,

    pub fn deinit(self: *Pool) void {
        self.arena.deinit();
    }
};

/// Enumerate every configured (provider, account) with a READABLE expiry into a
/// warm pool. Accounts whose credential is unreadable or carries no expiry are
/// skipped (logged) — a dead/unprofiled account never blocks the loop. Keys are
/// "<provider>:<account>", arena-owned. Caller frees via `Pool.deinit`.
pub fn enumeratePool(
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    health: *health_mod.HealthStore,
) std.mem.Allocator.Error!Pool {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    var list = std.ArrayList(bind.Observed).init(a);
    var prov_it = cfg.providers.map.iterator();
    while (prov_it.next()) |pe| {
        const prov = pe.key_ptr.*;
        var acct_it = pe.value_ptr.accounts.map.iterator();
        while (acct_it.next()) |ae| {
            const acct = ae.key_ptr.*;
            // Read this account's expiry with a throwaway Context (transient
            // allocations freed by its deinit). A read failure / no-expiry skips
            // the account rather than poisoning the pool.
            var pctx = pipeline.Context.init(allocator, cfg, health);
            defer pctx.deinit();
            pctx.provider_name = prov;
            pctx.account_name = acct;
            const maybe_exp = pipeline.readAccountExpiryMs(&pctx) catch null;
            const exp = maybe_exp orelse continue;
            const key = try std.fmt.allocPrint(a, "{s}:{s}", .{ prov, acct });
            try list.append(.{ .key = key, .expires_at_ms = exp });
        }
    }
    return .{ .observed = try list.toOwnedSlice(), .arena = arena };
}
