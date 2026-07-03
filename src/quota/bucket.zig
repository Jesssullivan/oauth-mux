//! Pure quota-bucket algebra — the spine of the model-class quota-granularity
//! design (TIN-2400) and its P0 enabler (TIN-2407). Design of record:
//! `docs/spec/model-quota-granularity-2026-07-03.md` (§3.2 types, §3.4 reducer,
//! §3.5 effectiveStatus, `deriveResetsAt`, §3.7 property surface).
//!
//! This module is a *pure library*: a total reducer that folds one observation
//! into a per-`(identity × model-class × window)` `QuotaBucket`, plus two pure
//! queries (`effectiveStatus`, `deriveResetsAt`). It performs **NO I/O, NO
//! allocation, and NO clock reads of its own** — every instant is passed in as a
//! plain `i64` parameter, exactly like `keepalive/warm_scheduler.zig`. That makes
//! the fold deterministic, replayable, and property-testable.
//!
//! STATUS: tested-but-not-yet-consumed by production — the same posture
//! `warm_scheduler.zig` held before its binding landed. P1 wires it to the
//! classification path; P0 only extracts and proves the algebra. Nothing here
//! changes a produced route decision or refresh timing.
//!
//! North star (honesty boundary, design §3.0): credential-alive and
//! model-quota-alive are two disjoint folds over one log. This module folds only
//! quota observations; it has no credential/liveness concept and cannot emit a
//! refresh — the type system makes the boundary unrepresentable to violate.
//!
//! Time unit: **all instants (`at`, `now`, `resets_at`, `since`) are Unix
//! milliseconds**, consistent with `WindowSpec.length_ms` and `DEFAULT_WINDOW_MS`
//! (and `warm_scheduler`'s `_ms` convention). The P1 boundary converts the health
//! path's seconds → ms when it wires events; the pure algebra never mixes units.
//!
//! Arithmetic: every time computation is **saturating** (`+|`, `*|`) so that even
//! pathological `i64`/`u32` extremes (min/max sentinels) can never overflow-panic
//! the fold (§3.7 P8) — the same never-halt discipline as `warm_scheduler`.

const std = @import("std");
const types = @import("../types.zig");

/// Conservative reset floor when nothing better is known (design §3.4: "codex
/// 7d"). Milliseconds. Flagged low-confidence upstream so a real signal re-probes
/// sooner; here it only guarantees `quota_exhausted` can never hold a null.
pub const DEFAULT_WINDOW_MS: i64 = 7 * 24 * 60 * 60 * 1000; // 604_800_000

// ── §3.1 boundary scaffolding — interning types the hot path uses; the pure
//    algebra below never touches them. Provided for shape-compatibility so the
//    P1 boundary (interning + persist) drops in without reshaping the value. ──

pub const IdentityIdx = u16;
pub const ClassIdx = u16;

/// Interned identity of a bucket (design §3.1). POD `u64`; not consumed by the
/// reducer/queries in P0 (bucket identity is implied by the fold target).
pub const BucketId = packed struct(u64) {
    provider: u8 = 0,
    identity: IdentityIdx = 0,
    class: ClassIdx = 0,
    window: u8 = 0,
    _pad: u16 = 0,
};

/// Borrowed slices; the algebra never owns/frees them (warm_scheduler discipline).
/// Scaffolding only in P0 — rendering/persist is a boundary concern (P1).
pub const RouteKey = struct {
    provider: []const u8 = "",
    account: []const u8 = "",
    model: []const u8 = "",
};

// ── §3.2 observation taxonomy + first-class evidence provenance ──

pub const EvidenceSource = enum { response_header, error_body, status_code, response_model, local_probe, none };

/// A lattice: `assumed < inferred < proven`. Declaration order IS the lattice
/// order — `@intFromEnum` gives the join rank.
pub const Confidence = enum { assumed, inferred, proven };

pub const Attribution = enum { from_response_model, from_request_model, static_session_tag, declared_default, unknown };

pub const DiscoverySource = enum { builtin_prior, observed_traffic, config_declared };

pub const Evidence = struct {
    observed_at: i64,
    source: EvidenceSource,
    confidence: Confidence,
    attribution: Attribution,
};

/// The evidence a never-observed (`.fresh`) bucket carries: the lattice bottom at
/// the earliest possible instant, so any real observation strictly dominates it
/// and populates the bucket on first sight (design §3.3 self-population).
pub const fresh_evidence: Evidence = .{
    .observed_at = std.math.minInt(i64),
    .source = .none,
    .confidence = .assumed,
    .attribution = .unknown,
};

pub const WindowSpec = struct {
    length_ms: i64,
    cadence: enum { rolling, fixed_daily, fixed_weekly, plan_cycle, unknown } = .unknown,
    provenance: DiscoverySource = .builtin_prior,
};

/// A total sum type — illegal states unrepresentable (design §3.2). Crucially,
/// `quota_exhausted`/`plan_gated` carry a **non-optional** `resets_at` (supplied
/// at reduce time by `deriveResetsAt`), so "exhausted but no idea when it
/// recovers" — the `types.Availability.QuotaInfo.window_resets_at == null` hazard
/// — cannot occur here.
pub const BucketStatus = union(enum) {
    fresh,
    available: struct { since: i64 },
    rate_limited: struct { since: i64, retry_after_s: u32 },
    quota_exhausted: struct { since: i64, resets_at: i64 },
    tier_blocked: struct { since: i64 },
    plan_gated: struct { since: i64, resets_at: i64, reason: types.DegradedReason },
};

/// One (identity × model-class × window) bucket. POD: no owned slices, so it is
/// snapshot-friendly and property-testable. `id`/`last_selected_at`/`epoch` are
/// P1+ machinery (interning / fairness fold / heap-tombstone generation) carried
/// for shape-compatibility; the P0 reducer only writes `status`/`evidence`/
/// `usage_pct`/`window` (+ bumps `epoch`).
pub const QuotaBucket = struct {
    id: BucketId = .{},
    status: BucketStatus = .fresh,
    evidence: Evidence = fresh_evidence,
    /// ONLY ever the last observed headroom value (design §3.2) — never a
    /// decremented budget. Cleared to null when a non-`quota_ok` status is adopted.
    usage_pct: ?u8 = null,
    window: ?WindowSpec = null,
    last_selected_at: i64 = 0,
    /// Generation counter for the P2 lazy-deletion heap (§3.7). Bumped on every
    /// adoption; intentionally order-sensitive, so it is NOT part of the folded
    /// *value* (order-independence, P2, is asserted over status/evidence/usage/
    /// window, excluding epoch).
    epoch: u32 = 0,
};

// ── §3.4 events + signals ──

/// Mirror of `provider_schema.classifyHttp`'s quota-relevant arms.
pub const QuotaSignal = union(enum) {
    quota_ok: struct { usage_pct: ?u8 = null, resets_at: ?i64 = null },
    rate_limited: struct { retry_after_s: u32 }, // ≤ threshold → burst; > threshold → window
    quota_exhausted: struct { stated_retry_s: ?u32 = null, resets_at: ?i64 = null },
    tier_insufficient,
    provider_plan: struct { reason: types.DegradedReason, resets_at: ?i64 = null },
};

/// A single quota observation. The pure algebra needs only `(at, source,
/// attribution, signal)`; `route` is boundary scaffolding (the bucket identity is
/// the fold target, so the design's total-order `class-slug` key is *constant*
/// within a bucket and unneeded here — see `strictlyLater`).
pub const Observed = struct {
    at: i64,
    source: EvidenceSource,
    attribution: Attribution,
    signal: QuotaSignal,
    route: ?RouteKey = null,
};

// Disjoint-fold scaffolding (design §3.0). The quota reducer consumes ONLY
// `Observed`; `Refreshed` feeds the credential fold and `Selected` the fairness
// fold — both out of P0 scope. Present so the log's `Event` type has its shape.
pub const Refreshed = struct { at: i64 };
pub const Selected = struct { at: i64 };
pub const Event = union(enum) { observed: Observed, refreshed: Refreshed, selected: Selected };

// ── deriveResetsAt (design §3.4) ──

/// Supplies the REQUIRED reset instant so `quota_exhausted` can never hold a null.
/// Precedence: provider-stated absolute `resets_at` > stated `retry_after` >
/// learned/declared `WindowSpec` > `DEFAULT_WINDOW_MS` floor. Total + saturating.
pub fn deriveResetsAt(at: i64, stated: ?i64, retry_s: ?u32, prior: ?WindowSpec) i64 {
    if (stated) |t| return t; // provider-authoritative absolute (clock-skew-safe)
    if (retry_s) |s| return at +| (@as(i64, s) *| 1000);
    if (prior) |w| return at +| w.length_ms;
    return at +| DEFAULT_WINDOW_MS;
}

// ── confidence lattice + attribution cap ──

fn confidenceOf(source: EvidenceSource) Confidence {
    return switch (source) {
        // Provider-stated header / served-model echo are directly authoritative.
        .response_header, .response_model => .proven,
        // Parsed from a body / status code / our own probe — inferred, not stated.
        .error_body, .status_code, .local_probe => .inferred,
        .none => .assumed,
    };
}

/// Attribution caps how far we may trust a source: seeing the *request* model (or
/// a static session tag) is weaker than seeing the *served* model echoed back.
fn attributionCeiling(attr: Attribution) Confidence {
    return switch (attr) {
        .from_response_model => .proven,
        .from_request_model, .static_session_tag => .inferred,
        .declared_default, .unknown => .assumed,
    };
}

fn capBy(conf: Confidence, attr: Attribution) Confidence {
    const ceil = attributionCeiling(attr);
    return @enumFromInt(@min(@intFromEnum(conf), @intFromEnum(ceil)));
}

/// The confidence an observation carries after the attribution cap. Exposed for
/// the boundary + tests.
pub fn observationConfidence(ev: Observed) Confidence {
    return capBy(confidenceOf(ev.source), ev.attribution);
}

// ── projection: the status an observation would produce ──

fn projectStatus(ev: Observed, prior: ?WindowSpec, threshold_s: u32) BucketStatus {
    return switch (ev.signal) {
        .quota_ok => .{ .available = .{ .since = ev.at } },
        // A 429 whose wait exceeds the burst threshold is a spent WINDOW; at or
        // below it is a burst throttle. Under-claim on ambiguity (design §3.4).
        .rate_limited => |r| if (r.retry_after_s > threshold_s)
            .{ .quota_exhausted = .{ .since = ev.at, .resets_at = deriveResetsAt(ev.at, null, r.retry_after_s, prior) } }
        else
            .{ .rate_limited = .{ .since = ev.at, .retry_after_s = r.retry_after_s } },
        .quota_exhausted => |q| .{ .quota_exhausted = .{ .since = ev.at, .resets_at = deriveResetsAt(ev.at, q.resets_at, q.stated_retry_s, prior) } },
        .tier_insufficient => .{ .tier_blocked = .{ .since = ev.at } },
        .provider_plan => |p| .{ .plan_gated = .{ .since = ev.at, .resets_at = deriveResetsAt(ev.at, p.resets_at, null, prior), .reason = p.reason } },
    };
}

// ── total order for the within-tier tiebreak (design §3.4) ──
//
// The design's total order is `(at, sourceRank, attributionRank, class-slug)`.
// Because the reducer folds an `Observed` into its *already-selected* bucket, the
// class-slug is constant within one bucket and cannot break a within-bucket tie.
// To make the within-bucket LWW a genuine STRICT total order — required so that
// equal-`at` collisions fold to the same result under any permutation (P2) — the
// final tiebreak keys are derived from the observation's *effect* (its projected
// status payload, then `usage_pct`). Two events tie here only if they produce a
// byte-identical bucket, so the fold is exactly "adopt the total-order maximum
// event" = an order-independent LWW register.

const StatusKey = struct { rank: u8, k1: i64, k2: i64, k3: i64 };

fn statusKey(s: BucketStatus) StatusKey {
    return switch (s) {
        .fresh => .{ .rank = 0, .k1 = 0, .k2 = 0, .k3 = 0 },
        .available => |a| .{ .rank = 1, .k1 = a.since, .k2 = 0, .k3 = 0 },
        .rate_limited => |r| .{ .rank = 2, .k1 = @as(i64, r.retry_after_s), .k2 = r.since, .k3 = 0 },
        .plan_gated => |p| .{ .rank = 3, .k1 = p.resets_at, .k2 = p.since, .k3 = @intFromEnum(p.reason) },
        .tier_blocked => |t| .{ .rank = 4, .k1 = t.since, .k2 = 0, .k3 = 0 },
        // Highest rank: on a genuine all-keys tie, the conservative (exhausted)
        // status wins rather than a co-timed `available` — never strand-then-drop.
        .quota_exhausted => |q| .{ .rank = 5, .k1 = q.resets_at, .k2 = q.since, .k3 = 0 },
    };
}

fn orderStatus(a: BucketStatus, b: BucketStatus) std.math.Order {
    const ka = statusKey(a);
    const kb = statusKey(b);
    if (ka.rank != kb.rank) return std.math.order(ka.rank, kb.rank);
    if (ka.k1 != kb.k1) return std.math.order(ka.k1, kb.k1);
    if (ka.k2 != kb.k2) return std.math.order(ka.k2, kb.k2);
    return std.math.order(ka.k3, kb.k3);
}

fn usageKey(u: ?u8) i64 {
    return if (u) |v| @as(i64, v) else -1;
}

fn eventUsage(ev: Observed) i64 {
    return switch (ev.signal) {
        .quota_ok => |o| usageKey(o.usage_pct),
        else => -1,
    };
}

/// Is `ev` (projecting to `proposed`) strictly later than the bucket's current
/// winner, in the total order `(at, source, attribution, statusKey, usage)`?
/// Consulted only when confidence is EQUAL (cross-tier moves are decided by the
/// lattice in `reduceBucket`).
fn strictlyLater(ev: Observed, proposed: BucketStatus, b: QuotaBucket) bool {
    if (ev.at != b.evidence.observed_at) return ev.at > b.evidence.observed_at;
    const es = @intFromEnum(ev.source);
    const bs = @intFromEnum(b.evidence.source);
    if (es != bs) return es > bs;
    const ea = @intFromEnum(ev.attribution);
    const ba = @intFromEnum(b.evidence.attribution);
    if (ea != ba) return ea > ba;
    switch (orderStatus(proposed, b.status)) {
        .gt => return true,
        .lt => return false,
        .eq => {},
    }
    const pu = eventUsage(ev);
    const bu = usageKey(b.usage_pct);
    if (pu != bu) return pu > bu;
    return false; // fully equal → not strictly later → keep current (idempotent)
}

// ── the reducer (design §3.4) ──

/// PURE. Total. No clock read (the event carries `at`), no alloc, no I/O.
/// `state' = reduceBucket(state, event)`.
///
/// Confidence-lattice LWW join, structured so the fold is a genuine
/// order-independent / associative / idempotent merge (an LWW register whose key
/// is `(confidence, at, source, attribution, statusKey, usage)`):
///
///   * strictly-higher confidence  → adopt (the honesty guard, in force: a
///     strictly-WEAKER signal is NEVER adopted, so it can never downgrade a
///     stronger recorded status — e.g. a stray `assumed` 200 cannot reopen a
///     `proven`-exhausted route);
///   * equal confidence            → adopt iff strictly-later in the total order;
///   * strictly-lower confidence   → keep current (absorb-noop).
///
/// Recovery ("a route reopens the instant its window elapses") is realized at
/// QUERY time by `effectiveStatus` (design §3.5), NOT by a reduce-time
/// expired-window branch — see the deviation note in `bucket_tests.zig`. This
/// keeps the fold a clean register (full order-independence, P2) while giving the
/// strictly stronger §3.5 invariant: zero scheduled writes for recovery.
pub fn reduceBucket(b: QuotaBucket, ev: Observed, prior: ?WindowSpec, threshold_s: u32) QuotaBucket {
    const inc = observationConfidence(ev);
    const cur = b.evidence.confidence;
    const proposed = projectStatus(ev, prior, threshold_s);

    const adopt = if (@intFromEnum(inc) > @intFromEnum(cur))
        true
    else if (@intFromEnum(inc) < @intFromEnum(cur))
        false // generalized honesty guard: weaker never overwrites stronger
    else
        strictlyLater(ev, proposed, b);

    if (!adopt) return b; // absorb-noop: P0 records nothing for a non-adopted obs

    var nb = b;
    nb.status = proposed;
    nb.evidence = .{ .observed_at = ev.at, .source = ev.source, .confidence = inc, .attribution = ev.attribution };
    // `usage_pct` is ONLY ever the last observed headroom; a non-ok status clears
    // it (we never retain stale headroom across a state change).
    nb.usage_pct = switch (ev.signal) {
        .quota_ok => |o| o.usage_pct,
        else => null,
    };
    // P0 window is the fold-constant declared/prior spec (observation-driven
    // window LEARNING is P1; deferring it keeps the fold a clean register).
    nb.window = prior;
    nb.epoch +%= 1; // heap-tombstone generation; excluded from the folded value
    return nb;
}

// ── §3.5 availability is a QUERY, not a stored field ──

pub const EffectiveStatus = enum { available, waiting, tier_blocked, plan_gated };

fn ms(s: u32) i64 {
    return @as(i64, s) *| 1000;
}

/// Pure `(bucket, now) → status`. Referentially transparent — the ONLY thing
/// routing consults. A route returns to `available` the instant `now` crosses its
/// reset, with no event, no timer, no write (design §3.5): a monotone step, no
/// oscillation.
pub fn effectiveStatus(b: QuotaBucket, now: i64) EffectiveStatus {
    return switch (b.status) {
        .fresh, .available => .available, // optimistic out-of-box
        .rate_limited => |rl| if (now >= rl.since +| ms(rl.retry_after_s)) .available else .waiting,
        .quota_exhausted => |q| if (now >= q.resets_at) .available else .waiting,
        .plan_gated => |p| if (now >= p.resets_at) .available else .plan_gated,
        .tier_blocked => .tier_blocked, // routing-permanent; never credential-dead
    };
}
