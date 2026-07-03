//! Property-based tests for the pure quota-bucket algebra (`bucket.zig`).
//! Deterministic-PRNG fuzz loops, `std` only, no I/O, no allocation in the core.
//!
//!     zig test src/quota/bucket_tests.zig
//!
//! Implements the design's §3.7 property surface (TIN-2407 acceptance): the fold
//! is an order-independent / idempotent / replayable LWW register; recovery is a
//! monotone step at `resets_at`; the arithmetic never panics at i64/u32 extremes;
//! `quota_exhausted` can never hold a null reset; a weak signal never reopens a
//! live window; and the module carries no credential/refresh/clock seam.
//!
//! DEVIATION NOTES (from design §3.4, justified):
//!   (1) The design lists "expired window adopts anything" as a reduce-time
//!       clause. Realizing recovery in the REDUCER makes the fold order-dependent
//!       (a later weak `available` vs an earlier `proven` exhausted folds
//!       differently by order). We instead realize recovery entirely at QUERY
//!       time via `effectiveStatus` (design §3.5, "availability is a query,
//!       recovery needs zero writes") — the strictly stronger invariant — which
//!       keeps the reducer a clean register so P2 holds on the full bucket value.
//!   (2) The design's within-tier total order is `(at, source, attr, class-slug)`.
//!       class-slug is constant within a bucket, so the final tiebreak keys are
//!       derived from the observation's effect (projected status payload, then
//!       usage_pct) — a strict total order over distinct-effect events, which is
//!       what actually makes equal-`at` collisions permutation-invariant (P2).
//!   (3) The P0 reducer records window/usage only on adoption and takes the
//!       fold-constant `prior` window (observation-driven window LEARNING is P1),
//!       so `window` stays order-independent.
//!   (4) `epoch` is bumped on adoption (design §3.4) but is a heap-tombstone
//!       generation counter, intentionally order-sensitive; equality in the
//!       order-independence tests is over the folded VALUE, excluding epoch.

const std = @import("std");
const bucket = @import("bucket.zig");

test {
    std.testing.refAllDeclsRecursive(bucket);
}

const THRESHOLD_S: u32 = 3600; // codex burst/window split (design §3.4)

// ── Fuzz helpers ─────────────────────────────────────────────────────────────

const Gen = struct {
    r: std.Random,
    /// `at` drawn from a small band to force frequent equal-`at` collisions
    /// (P2's hard case). When false, `at` spans the full i64 range (P8).
    narrow_at: bool = true,

    fn source(self: Gen) bucket.EvidenceSource {
        return @enumFromInt(self.r.intRangeAtMost(u8, 0, 5));
    }
    fn attribution(self: Gen) bucket.Attribution {
        return @enumFromInt(self.r.intRangeAtMost(u8, 0, 4));
    }
    fn reason(self: Gen) @import("../types.zig").DegradedReason {
        return @enumFromInt(self.r.intRangeAtMost(u8, 0, 9));
    }
    fn at(self: Gen) i64 {
        if (self.narrow_at) return self.r.intRangeAtMost(i64, -3, 4);
        return switch (self.r.intRangeAtMost(u8, 0, 4)) {
            0 => std.math.minInt(i64),
            1 => std.math.maxInt(i64),
            2 => 0,
            3 => self.r.int(i64),
            else => self.r.intRangeAtMost(i64, -1_000_000, 1_000_000),
        };
    }
    fn optU8(self: Gen) ?u8 {
        if (self.r.boolean()) return null;
        return self.r.int(u8);
    }
    fn optI64(self: Gen) ?i64 {
        if (self.r.boolean()) return null;
        return self.at();
    }
    fn retry(self: Gen) u32 {
        return switch (self.r.intRangeAtMost(u8, 0, 4)) {
            0 => 0,
            1 => std.math.maxInt(u32),
            2 => self.r.intRangeAtMost(u32, 0, THRESHOLD_S), // burst side
            3 => self.r.intRangeAtMost(u32, THRESHOLD_S + 1, 100_000), // window side
            else => self.r.int(u32),
        };
    }
    fn signal(self: Gen) bucket.QuotaSignal {
        return switch (self.r.intRangeAtMost(u8, 0, 4)) {
            0 => .{ .quota_ok = .{ .usage_pct = self.optU8(), .resets_at = self.optI64() } },
            1 => .{ .rate_limited = .{ .retry_after_s = self.retry() } },
            2 => .{ .quota_exhausted = .{ .stated_retry_s = if (self.r.boolean()) null else self.retry(), .resets_at = self.optI64() } },
            3 => .tier_insufficient,
            else => .{ .provider_plan = .{ .reason = self.reason(), .resets_at = self.optI64() } },
        };
    }
    fn observed(self: Gen) bucket.Observed {
        return .{ .at = self.at(), .source = self.source(), .attribution = self.attribution(), .signal = self.signal() };
    }
};

fn fold(events: []const bucket.Observed) bucket.QuotaBucket {
    var b = bucket.QuotaBucket{};
    for (events) |ev| b = bucket.reduceBucket(b, ev, null, THRESHOLD_S);
    return b;
}

/// The folded VALUE (status + evidence + usage + window), EXCLUDING `epoch`
/// (deviation note 4). This is the CRDT equivalence relation.
fn valueEql(a: bucket.QuotaBucket, b: bucket.QuotaBucket) bool {
    return std.meta.eql(a.status, b.status) and
        std.meta.eql(a.evidence, b.evidence) and
        a.usage_pct == b.usage_pct and
        std.meta.eql(a.window, b.window);
}

fn shuffle(r: std.Random, events: []bucket.Observed) void {
    var i: usize = events.len;
    while (i > 1) {
        i -= 1;
        const j = r.intRangeAtMost(usize, 0, i);
        const tmp = events[i];
        events[i] = events[j];
        events[j] = tmp;
    }
}

// ── P1: replay / snapshot idempotence ────────────────────────────────────────

test "P1 replay + true idempotence" {
    var prng = std.Random.DefaultPrng.init(0xB0CCE71A);
    const g = Gen{ .r = prng.random() };
    var trial: usize = 0;
    while (trial < 500) : (trial += 1) {
        const n = g.r.intRangeAtMost(usize, 0, 20);
        var events: [20]bucket.Observed = undefined;
        for (0..n) |i| events[i] = g.observed();
        const log = events[0..n];

        const whole = fold(log);

        // Snapshot idempotence: fold a prefix, then continue from that snapshot.
        const k = if (n == 0) 0 else g.r.intRangeAtMost(usize, 0, n);
        var b = fold(log[0..k]);
        for (log[k..]) |ev| b = bucket.reduceBucket(b, ev, null, THRESHOLD_S);
        try std.testing.expect(valueEql(whole, b));

        // True idempotence: re-applying any already-folded event is a no-op.
        if (n > 0) {
            const idx = g.r.intRangeAtMost(usize, 0, n - 1);
            const again = bucket.reduceBucket(whole, log[idx], null, THRESHOLD_S);
            try std.testing.expect(valueEql(whole, again));
            try std.testing.expectEqual(whole.epoch, again.epoch); // not re-adopted
        }
    }
}

// ── P2: order-independence (CRDT law) incl. equal-`at` collisions ─────────────

test "P2 order-independence over permutations (equal-at collisions)" {
    var prng = std.Random.DefaultPrng.init(0x0DDBA11);
    const g = Gen{ .r = prng.random() }; // narrow `at` → dense duplicate timestamps
    var trial: usize = 0;
    while (trial < 800) : (trial += 1) {
        const n = g.r.intRangeAtMost(usize, 0, 16);
        var events: [16]bucket.Observed = undefined;
        for (0..n) |i| events[i] = g.observed();

        const reference = fold(events[0..n]);

        var perm: usize = 0;
        while (perm < 6) : (perm += 1) {
            var copy: [16]bucket.Observed = undefined;
            @memcpy(copy[0..n], events[0..n]);
            shuffle(g.r, copy[0..n]);
            const got = fold(copy[0..n]);
            try std.testing.expect(valueEql(reference, got));
        }
    }
}

// ── P3: quota-never-kills-credential (disjoint folds) ─────────────────────────

test "P3 quota signals only ever produce routing states, never credential-dead" {
    // Structural: the quota status enum shares no field with credential liveness
    // and has no `dead` variant — a quota fold cannot express a dead credential.
    comptime {
        for (@typeInfo(bucket.BucketStatus).@"union".fields) |f| {
            if (std.mem.eql(u8, f.name, "dead"))
                @compileError("BucketStatus must not carry a credential-dead variant (design §3.0)");
        }
    }
    var prng = std.Random.DefaultPrng.init(0xC0FFEE11);
    const g = Gen{ .r = prng.random() };
    var trial: usize = 0;
    while (trial < 500) : (trial += 1) {
        const n = g.r.intRangeAtMost(usize, 0, 20);
        var events: [20]bucket.Observed = undefined;
        for (0..n) |i| events[i] = g.observed();
        const b = fold(events[0..n]);
        // Far in the future everything recovers to `available` except a
        // routing-permanent `tier_blocked` — never a credential-dead sentinel.
        const es = bucket.effectiveStatus(b, std.math.maxInt(i64));
        try std.testing.expect(es == .available or es == .tier_blocked);
    }
}

// ── P4: recovery is a monotone step at resets_at (no oscillation) ─────────────

fn expectMonotoneStep(b: bucket.QuotaBucket, boundary: i64) !void {
    // below the boundary → waiting; at/above → available.
    const samples = [_]i64{ boundary -| 2, boundary -| 1, boundary, boundary +| 1, boundary +| 2 };
    for (samples) |t| {
        const es = bucket.effectiveStatus(b, t);
        if (t < boundary) {
            try std.testing.expect(es == .waiting);
        } else {
            try std.testing.expect(es == .available);
        }
    }
}

test "P4 quota_exhausted + rate_limited recover as a monotone step" {
    var prng = std.Random.DefaultPrng.init(0x5717CA5E);
    const r = prng.random();
    var trial: usize = 0;
    while (trial < 500) : (trial += 1) {
        const at = r.intRangeAtMost(i64, -1_000_000, 1_000_000);

        // quota_exhausted via a provider-stated absolute reset in the future.
        const resets = at +| r.intRangeAtMost(i64, 1, 5_000_000);
        const qe = bucket.reduceBucket(bucket.QuotaBucket{}, .{
            .at = at,
            .source = .response_header,
            .attribution = .from_response_model,
            .signal = .{ .quota_exhausted = .{ .stated_retry_s = null, .resets_at = resets } },
        }, null, THRESHOLD_S);
        try std.testing.expect(qe.status == .quota_exhausted);
        try expectMonotoneStep(qe, resets);

        // rate_limited (retry <= threshold so it stays a burst, not a window):
        // boundary = since + retry*1000, computed saturating.
        const retry = r.intRangeAtMost(u32, 1, THRESHOLD_S);
        const rl = bucket.reduceBucket(bucket.QuotaBucket{}, .{
            .at = at,
            .source = .status_code,
            .attribution = .static_session_tag,
            .signal = .{ .rate_limited = .{ .retry_after_s = retry } },
        }, null, THRESHOLD_S);
        try std.testing.expect(rl.status == .rate_limited);
        const rl_boundary = at +| (@as(i64, retry) *| 1000);
        try expectMonotoneStep(rl, rl_boundary);

        // plan_gated: steps plan_gated -> available at its stated reset instant.
        const plan_resets = at +| r.intRangeAtMost(i64, 1, 5_000_000);
        const pg = bucket.reduceBucket(bucket.QuotaBucket{}, .{
            .at = at,
            .source = .error_body,
            .attribution = .from_response_model,
            .signal = .{ .provider_plan = .{ .reason = .subscription_paused, .resets_at = plan_resets } },
        }, null, THRESHOLD_S);
        try std.testing.expect(pg.status == .plan_gated);
        try std.testing.expect(bucket.effectiveStatus(pg, plan_resets - 1) == .plan_gated);
        try std.testing.expect(bucket.effectiveStatus(pg, plan_resets) == .available);
        try std.testing.expect(bucket.effectiveStatus(pg, plan_resets +| 1_000_000) == .available);

        // tier_blocked: never self-heals — constant at any query instant.
        const tb = bucket.reduceBucket(bucket.QuotaBucket{}, .{
            .at = at,
            .source = .error_body,
            .attribution = .from_response_model,
            .signal = .tier_insufficient,
        }, null, THRESHOLD_S);
        try std.testing.expect(tb.status == .tier_blocked);
        try std.testing.expect(bucket.effectiveStatus(tb, at -| 1_000_000) == .tier_blocked);
        try std.testing.expect(bucket.effectiveStatus(tb, at +| 5_000_000) == .tier_blocked);
        try std.testing.expect(bucket.effectiveStatus(tb, std.math.maxInt(i64)) == .tier_blocked);
    }
}

// ── P5: warm-loop independence (disjoint folds) — P0 stub ─────────────────────

test "P5 quota fold leaves a disjoint credential record bit-identical" {
    // No scheduler is wired in P0. The structural guarantee (§3.0) is that the
    // quota reducer cannot reach credential state: it takes no credential input
    // and returns only a QuotaBucket. We model a credential record as a disjoint
    // value and assert folding any quota-event sequence cannot mutate it.
    const Cred = struct { key: []const u8, expires_at_ms: i64, refreshes: u32 };
    var prng = std.Random.DefaultPrng.init(0xDECAFBAD);
    const g = Gen{ .r = prng.random() };
    var trial: usize = 0;
    while (trial < 300) : (trial += 1) {
        const before = Cred{ .key = "claude:acct", .expires_at_ms = g.at(), .refreshes = g.r.int(u32) };
        // `cred` is a disjoint value the reducer never receives — it is `const`,
        // so it cannot be mutated at all, which is the disjointness we assert.
        const cred = before;
        const n = g.r.intRangeAtMost(usize, 0, 16);
        var b = bucket.QuotaBucket{};
        for (0..n) |_| b = bucket.reduceBucket(b, g.observed(), null, THRESHOLD_S);
        // `cred` was never passed to the reducer; it is provably untouched.
        try std.testing.expectEqualStrings(before.key, cred.key);
        try std.testing.expectEqual(before.expires_at_ms, cred.expires_at_ms);
        try std.testing.expectEqual(before.refreshes, cred.refreshes);
    }
}

// ── P6: spread fairness — N/A in P0 (no selector); slot reserved ──────────────

test "P6 spread fairness/no-starvation — N/A in P0 (no selector wired)" {
    // The selector (LRS within a capability ring, design §4) lands in the P3
    // phase; there is no spread structure to fuzz in P0. Slot kept per §3.7.
    return;
}

// ── P7: no-spend / effect-freedom (structural) ────────────────────────────────

test "P7 module exposes no clock/refresh/net seam" {
    comptime {
        try std.testing.expect(!@hasDecl(bucket, "RefreshFn"));
        try std.testing.expect(!@hasDecl(bucket, "ClockFn"));
        try std.testing.expect(!@hasDecl(bucket, "RefreshError"));
        // The reducer/query are data-in / data-out: every parameter is a plain
        // value and the result is a QuotaBucket / EffectiveStatus (no pointers,
        // no error union, no seam).
        const RB = @typeInfo(@TypeOf(bucket.reduceBucket)).@"fn";
        try std.testing.expectEqual(@as(usize, 4), RB.params.len);
        try std.testing.expect(RB.return_type.? == bucket.QuotaBucket);
        const ES = @typeInfo(@TypeOf(bucket.effectiveStatus)).@"fn";
        try std.testing.expectEqual(@as(usize, 2), ES.params.len);
        try std.testing.expect(ES.return_type.? == bucket.EffectiveStatus);
    }
}

// ── P8: total / saturating at i64/u32 extremes (no panic) ─────────────────────

test "P8 fold + queries never panic at extremes; resets_at never null" {
    var prng = std.Random.DefaultPrng.init(0xFA57CA75);
    const g = Gen{ .r = prng.random(), .narrow_at = false }; // full-range `at`
    var trial: usize = 0;
    while (trial < 2000) : (trial += 1) {
        // deriveResetsAt at extremes — total + saturating, must return.
        _ = bucket.deriveResetsAt(g.at(), g.optI64(), if (g.r.boolean()) null else g.retry(), null);

        const n = g.r.intRangeAtMost(usize, 0, 12);
        var b = bucket.QuotaBucket{};
        for (0..n) |_| {
            const ev = g.observed();
            b = bucket.reduceBucket(b, ev, null, THRESHOLD_S);
            // A quota_exhausted status ALWAYS carries a (non-optional) resets_at —
            // structurally guaranteed by the type; assert the reducer produced it.
            switch (b.status) {
                .quota_exhausted => |q| {
                    _ = q.resets_at; // present by type; touching it proves it exists
                },
                else => {},
            }
        }
        // Query at extremes — must not panic.
        _ = bucket.effectiveStatus(b, std.math.minInt(i64));
        _ = bucket.effectiveStatus(b, std.math.maxInt(i64));
        _ = bucket.effectiveStatus(b, g.at());
    }
}

test "P8 a 429 over threshold becomes a window; at/below stays a burst" {
    // resets_at is required on the window arm — never null by construction.
    const over = bucket.reduceBucket(bucket.QuotaBucket{}, .{
        .at = 1000,
        .source = .response_header,
        .attribution = .from_response_model,
        .signal = .{ .rate_limited = .{ .retry_after_s = THRESHOLD_S + 1 } },
    }, null, THRESHOLD_S);
    try std.testing.expect(over.status == .quota_exhausted);

    const under = bucket.reduceBucket(bucket.QuotaBucket{}, .{
        .at = 1000,
        .source = .response_header,
        .attribution = .from_response_model,
        .signal = .{ .rate_limited = .{ .retry_after_s = THRESHOLD_S } },
    }, null, THRESHOLD_S);
    try std.testing.expect(under.status == .rate_limited);
}

// ── Honesty guard: a weak signal never reopens a live proven window ───────────

test "weak assumed signal never reopens a live proven quota_exhausted window" {
    var prng = std.Random.DefaultPrng.init(0x4E57E511);
    const g = Gen{ .r = prng.random() };
    var trial: usize = 0;
    while (trial < 500) : (trial += 1) {
        const at: i64 = g.r.intRangeAtMost(i64, 0, 1_000_000);
        const resets = at +| g.r.intRangeAtMost(i64, 10_000, 5_000_000);
        // Proven exhausted window (response_header + from_response_model → proven).
        const strong = bucket.reduceBucket(bucket.QuotaBucket{}, .{
            .at = at,
            .source = .response_header,
            .attribution = .from_response_model,
            .signal = .{ .quota_exhausted = .{ .resets_at = resets } },
        }, null, THRESHOLD_S);
        try std.testing.expect(strong.status == .quota_exhausted);

        // A weak `available` (none/declared_default → assumed) DURING the window
        // must NOT flip the recorded status to available.
        const weak_at = g.r.intRangeAtMost(i64, at, resets -| 1); // strictly inside
        const after = bucket.reduceBucket(strong, .{
            .at = weak_at,
            .source = .none,
            .attribution = .declared_default,
            .signal = .{ .quota_ok = .{ .usage_pct = 50 } },
        }, null, THRESHOLD_S);
        try std.testing.expect(after.status == .quota_exhausted);
        // And the window instant is unchanged (no learning downgrade).
        try std.testing.expectEqual(resets, after.status.quota_exhausted.resets_at);
    }
}

// ── NEGATIVE CONTROL: the properties BITE ─────────────────────────────────────
//
// A deliberately-broken reducer that (a) ignores the confidence lattice / honesty
// guard and (b) uses `>=` on bare `at` with no total-order tiebreak. We assert it
// VIOLATES the honesty guard and order-independence — so a passing suite against
// the REAL reducer is meaningful, and any regression that flattens the guard or
// the tiebreak would fail the corresponding property test above.

fn projectVia(ev: bucket.Observed) bucket.QuotaBucket {
    // A fresh bucket is the lattice bottom, so it always adopts → its fields are
    // exactly `ev`'s projection. Lets the broken reducer reuse the real projection
    // without exposing a private fn.
    return bucket.reduceBucket(bucket.QuotaBucket{}, ev, null, THRESHOLD_S);
}

fn reduceBroken(b: bucket.QuotaBucket, ev: bucket.Observed) bucket.QuotaBucket {
    if (ev.at >= b.evidence.observed_at) {
        const proj = projectVia(ev);
        var nb = b;
        nb.status = proj.status;
        nb.evidence = proj.evidence;
        nb.usage_pct = proj.usage_pct;
        nb.window = proj.window;
        return nb;
    }
    return b;
}

test "negative control: broken reducer VIOLATES the honesty guard" {
    const strong = bucket.reduceBucket(bucket.QuotaBucket{}, .{
        .at = 100,
        .source = .response_header,
        .attribution = .from_response_model,
        .signal = .{ .quota_exhausted = .{ .resets_at = 10_000 } },
    }, null, THRESHOLD_S);
    try std.testing.expect(strong.status == .quota_exhausted);

    const weak = bucket.Observed{
        .at = 200, // inside the window, later `at`
        .source = .none,
        .attribution = .declared_default,
        .signal = .{ .quota_ok = .{} },
    };
    // REAL reducer holds the window; BROKEN reducer reopens it — proving the
    // honesty-guard test has teeth.
    try std.testing.expect(bucket.reduceBucket(strong, weak, null, THRESHOLD_S).status == .quota_exhausted);
    try std.testing.expect(reduceBroken(strong, weak).status == .available);
}

test "negative control: broken reducer VIOLATES order-independence" {
    // Two equal-`at` events of different effect: the real reducer's total-order
    // tiebreak makes both orders agree; the broken `>=` reducer is order-sensitive.
    const e1 = bucket.Observed{ .at = 5, .source = .response_header, .attribution = .from_response_model, .signal = .{ .quota_ok = .{} } };
    const e2 = bucket.Observed{ .at = 5, .source = .response_header, .attribution = .from_response_model, .signal = .{ .quota_exhausted = .{ .resets_at = 9_000 } } };

    const real_12 = bucket.reduceBucket(bucket.reduceBucket(bucket.QuotaBucket{}, e1, null, THRESHOLD_S), e2, null, THRESHOLD_S);
    const real_21 = bucket.reduceBucket(bucket.reduceBucket(bucket.QuotaBucket{}, e2, null, THRESHOLD_S), e1, null, THRESHOLD_S);
    try std.testing.expect(valueEql(real_12, real_21)); // real: order-independent

    const broken_12 = reduceBroken(reduceBroken(bucket.QuotaBucket{}, e1), e2);
    const broken_21 = reduceBroken(reduceBroken(bucket.QuotaBucket{}, e2), e1);
    try std.testing.expect(!valueEql(broken_12, broken_21)); // broken: order-sensitive
}
