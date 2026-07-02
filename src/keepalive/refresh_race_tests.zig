//! TIN-2059 engineered race: a warm-scheduler tick and a same-process
//! live-path writer (broker materializer / managed-session refresh) contend
//! for ONE provider:account credential chain. Deterministic — no network, no
//! real credential store. The FakeChain models the two invariants the real
//! paths must preserve:
//!   - exactly one RT spend per rotation window (single-use RT family:
//!     presenting a superseded RT revokes the whole chain), and
//!   - no stale writeback over a newer credential.
//! The actor protocols mirror the production callers exactly:
//!   - warm tick  = pipeline.attemptRefresh: pre-lock RT snapshot →
//!     NONBLOCKING per-account lock with the typed RepairInProgress deferred
//!     arm (pipeline.zig:755) → under-lock revalidate (TIN-2073
//!     lock-then-revalidate) → spend → writeback;
//!   - live path  = broker_loader.refreshCodexAccountAuthFile: BLOCKING
//!     per-account lock (broker_loader.zig:368) → under-lock freshness
//!     re-read (.not_needed when a peer already rotated) → spend → writeback.
//! Cross-PROCESS this contention is pinned by the exactly-once smoke
//! (PR #427); these tests pin the in-PROCESS leg the flock cannot see.

const std = @import("std");
const testing = std.testing;
const repair_state = @import("../repair_state.zig");

/// One single-use refresh-token chain plus its credential store, with race
/// evidence recorders. Generations are monotonically increasing integers:
/// gen N's RT is superseded the moment gen N+1 is minted.
const FakeChain = struct {
    mutex: std.Thread.Mutex = .{},
    /// Credential store content: the generation of the stored RT.
    store_rt: u32 = 1,
    /// Provider-side truth: the most recently issued RT of the chain.
    last_issued: u32 = 1,
    /// Total refresh-endpoint spends.
    spends: u32 = 0,
    /// A spend presented an RT that was no longer current — with a
    /// single-use chain this is the family-revocation catastrophe.
    revoked_spend: bool = false,
    /// A writeback regressed the store to an older generation.
    stale_overwrite: bool = false,

    fn readStore(self: *FakeChain) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.store_rt;
    }

    /// POST /token presenting `presented`: single-use RT semantics.
    fn spend(self: *FakeChain, presented: u32) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.spends += 1;
        if (presented != self.last_issued) self.revoked_spend = true;
        self.last_issued += 1;
        return self.last_issued;
    }

    fn writeback(self: *FakeChain, rt: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (rt < self.store_rt) self.stale_overwrite = true;
        self.store_rt = rt;
    }
};

const WarmTickOutcome = enum { rotated, deferred_lock_busy, adopted_peer_rotation };

/// Mirrors pipeline.attemptRefresh: `pre_lock_rt` is the RT snapshot the
/// pipeline hands in from BEFORE the flock; the lock is nonblocking with the
/// typed deferred arm; the store is revalidated UNDER the lock and a peer
/// rotation is adopted instead of re-spent.
fn warmTickRefresh(
    chain: *FakeChain,
    provider: []const u8,
    account: []const u8,
    pre_lock_rt: u32,
) WarmTickOutcome {
    var lock = repair_state.acquireRepairLock(testing.allocator, provider, account) catch |e| switch (e) {
        error.RepairInProgress => return .deferred_lock_busy,
        else => std.debug.panic("warm tick lock: {s}", .{@errorName(e)}),
    };
    defer lock.release();
    const reread = chain.readStore();
    if (reread != pre_lock_rt) return .adopted_peer_rotation;
    const minted = chain.spend(reread);
    chain.writeback(minted);
    return .rotated;
}

const LivePathOutcome = enum { rotated, not_needed };

/// Mirrors broker_loader.refreshCodexAccountAuthFile: blocking per-account
/// lock, then the under-lock freshness re-read that no-ops when a peer
/// already rotated past the state that triggered this refresh.
fn livePathRefresh(
    chain: *FakeChain,
    provider: []const u8,
    account: []const u8,
    trigger_rt: u32,
) LivePathOutcome {
    var lock = repair_state.acquireRepairLockBlocking(testing.allocator, provider, account) catch |e|
        std.debug.panic("live path lock: {s}", .{@errorName(e)});
    defer lock.release();
    const reread = chain.readStore();
    if (reread != trigger_rt) return .not_needed;
    const minted = chain.spend(reread);
    chain.writeback(minted);
    return .rotated;
}

test "warm tick firing during a live-path refresh: exactly one RT spend, warm defers typed (TIN-2059)" {
    // Forced interleaving (event-sequenced, deterministic):
    //   live path acquires (blocking) and reads gen1 under the lock;
    //   warm tick snapshots gen1 pre-lock, then attempts its nonblocking
    //   acquire WHILE the live path provably holds (the attempt completes
    //   before the live path releases);
    //   live path then spends gen1 → gen2 and writes back; releases.
    // Actor gate present → the warm attempt gets RepairInProgress → typed
    // deferred: 1 spend, no revoked spend, store ends at gen2.
    //
    // FAILS-against-old proof: with the gate reverted to the pre-TIN-2059
    // unconditional `entry.count += 1` join, the warm tick JOINED the held
    // lock, revalidated against its own gen1 snapshot (match → proceeded),
    // spent gen1 and wrote gen2 — so the live path's subsequent under-lock
    // read saw a store mutated behind its exclusively-held lock (expect
    // below), its own gen1 spend became a revoked-RT double-spend, and
    // spends reached 2. Verified 2026-07-02 by reverting the gate locally,
    // observing this test fail, then restoring the gate.
    const a = testing.allocator;
    var scope = try repair_state.TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    var chain = FakeChain{};
    var live_holds = std.Thread.ResetEvent{};
    var warm_done = std.Thread.ResetEvent{};
    var warm_outcome: WarmTickOutcome = .rotated;

    const Warm = struct {
        fn run(
            c: *FakeChain,
            holds: *std.Thread.ResetEvent,
            done: *std.Thread.ResetEvent,
            outcome: *WarmTickOutcome,
        ) void {
            const snapshot = c.readStore(); // pre-lock read: gen1
            holds.wait(); // the live path provably holds the lock from here on
            outcome.* = warmTickRefresh(c, "codex", "tin2059-race-warm-vs-live", snapshot);
            done.set();
        }
    };

    // Live path: acquire and read the trigger state under the lock.
    var live_lock = try repair_state.acquireRepairLockBlocking(a, "codex", "tin2059-race-warm-vs-live");
    const trigger = chain.readStore();
    try testing.expectEqual(@as(u32, 1), trigger);

    const warm_thread = try std.Thread.spawn(.{}, Warm.run, .{ &chain, &live_holds, &warm_done, &warm_outcome });
    live_holds.set();
    warm_done.wait(); // warm's attempt fully resolved while we STILL hold

    // Nobody may have rotated behind our exclusively-held lock.
    try testing.expectEqual(trigger, chain.readStore());
    const minted = chain.spend(trigger);
    chain.writeback(minted);
    live_lock.release();
    warm_thread.join();

    try testing.expectEqual(WarmTickOutcome.deferred_lock_busy, warm_outcome);
    try testing.expectEqual(@as(u32, 1), chain.spends);
    try testing.expect(!chain.revoked_spend);
    try testing.expect(!chain.stale_overwrite);
    try testing.expectEqual(@as(u32, 2), chain.store_rt);
}

test "live-path refresh arriving during a warm tick serializes behind it: not_needed, one spend (TIN-2059)" {
    // Reverse arrival order: the warm tick holds (nonblocking short-hold);
    // the live path's BLOCKING acquire must wait for FULL release — never
    // cooperative-join a nonblocking hold — after which its under-lock
    // freshness re-read finds gen2 and returns .not_needed: one spend total,
    // no stale overwrite. Deterministic under the gate (the blocking acquire
    // cannot return before the warm hold is fully released). Against the old
    // unconditional join this leg raced rather than failing deterministically
    // — the deterministic old-behavior witness is the test above.
    const a = testing.allocator;
    var scope = try repair_state.TestRuntimeDirScope.init(a);
    defer scope.deinit(a);
    scope.activate();

    var chain = FakeChain{};
    var live_outcome: LivePathOutcome = .rotated;

    const snapshot = chain.readStore(); // warm pre-lock read: gen1
    var warm_lock = try repair_state.acquireRepairLock(a, "codex", "tin2059-race-live-vs-warm");

    const Live = struct {
        fn run(c: *FakeChain, outcome: *LivePathOutcome) void {
            // Triggered off gen1 (stale by the time the lock is granted).
            outcome.* = livePathRefresh(c, "codex", "tin2059-race-live-vs-warm", 1);
        }
    };
    const live_thread = try std.Thread.spawn(.{}, Live.run, .{ &chain, &live_outcome });

    // Give an (incorrect) instant join a scheduling window before we rotate.
    var i: usize = 0;
    while (i < 200) : (i += 1) std.Thread.yield() catch {};

    // Warm tick rotates under its hold: revalidate, spend gen1, write gen2.
    const reread = chain.readStore();
    try testing.expectEqual(snapshot, reread);
    const minted = chain.spend(reread);
    chain.writeback(minted);
    warm_lock.release();
    live_thread.join();

    try testing.expectEqual(LivePathOutcome.not_needed, live_outcome);
    try testing.expectEqual(@as(u32, 1), chain.spends);
    try testing.expect(!chain.revoked_spend);
    try testing.expect(!chain.stale_overwrite);
    try testing.expectEqual(@as(u32, 2), chain.store_rt);
}
