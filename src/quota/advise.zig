//! Pure valet advisor core (TIN-2719 M0 PR1) — the first production consumer of
//! the quota-bucket algebra (`bucket.zig`). Design of record:
//! `docs/spec/stay-afloat-valet-and-browser-evidence-2026-07-09.md`
//! (§Pure Core, §Ranking, §Required Properties).
//!
//! This module answers one question honestly: given the per-`(provider ×
//! account × model-class)` liveness rows the HealthStore already persists, which
//! account should carry the next unit of work for a declared model demand — and
//! with what provenance. It is a **pure deterministic data transform**: NO I/O,
//! NO clock read (every instant is a passed-in `i64`), NO allocation (the caller
//! supplies the `ClassSummary` output buffer). It imports only `std` and
//! `bucket.zig` — no net, clock, refresh, secret, or pipeline seam is reachable.
//!
//! Honesty boundary (design §Required Properties 1, 2, 7):
//!   * Credential keepalive and model-quota are DISJOINT folds. A `ClassSummary`
//!     status is the *quota* availability query over a bucket; a row's credential
//!     liveness (`state`) is a separate dimension that gates only whether an
//!     account may be *suggested*, never the quota status we report.
//!   * We never claim provenance above what the row proves. A persisted liveness
//!     row is a classified observation → `.inferred`, not a provider-stated
//!     header (`.proven`). A model-class with NO row is `.unobserved` — the
//!     honest name for "we have never looked", distinct from `.assumed`.
//!
//! Time unit: **milliseconds** (bucket.zig convention). The HealthStore liveness
//! rows carry Unix *seconds* (`std.time.timestamp()`); `bucketFromHealthRow`
//! converts second-granularity fields to ms at this boundary — exactly the
//! "P1 boundary converts the health path's seconds → ms" note in `bucket.zig`.
//! `now` passed to `advise` is therefore Unix *milliseconds*.
//!
//! Ranking is the valet spec §Ranking **truncated to the data one liveness row
//! proves**: criteria (5) longest usable horizon, (6) switch cost / bleed risk,
//! and (7) least-recently-selected are NOT derivable from a single HealthStore
//! row (no per-class selection history, no switch-cost model) and land in later
//! increments. What survives here: (1) exact class parity, (2) credential-ready,
//! (3) not a duplicate identity (via a caller-supplied exclusion list — this
//! module does NOT re-derive identity graphs; `provider_schema`/`identity` own
//! that), (4) higher quota-evidence confidence, (5) a deterministic lexicographic
//! tiebreak on the route key.

const std = @import("std");
const bucket = @import("bucket.zig");

/// Codex burst/window 429 split (design §3.4 of the quota spec). Only affects
/// whether a `rate_limited` row is modeled as a burst throttle vs a spent window;
/// both recover at `limited_at + retry_after_s`, so the boundary is timing-neutral
/// here — it exists only so the reused `bucket.reduceBucket` projection is total.
const BURST_THRESHOLD_S: u32 = 3600;

// ── inputs ───────────────────────────────────────────────────────────────────

/// One pre-parsed HealthStore liveness row. Mirrors the persisted
/// `HealthStore.LivenessEntry` (src/health.zig ~:563) plus its route key. Kept as
/// a plain struct so `advise.zig` need not import `health.zig` (and drag its net /
/// keychain / daemon deps into this pure core). All borrowed slices; never owned.
///
/// Timestamp fields are Unix **seconds** (health convention); the boundary
/// converts them to ms.
pub const Row = struct {
    provider: []const u8,
    /// Identity-hash-or-label. Borrowed; compared only by bytes (no identity
    /// graph is derived here — duplicate collapse is the caller's exclusion list).
    account: []const u8,
    /// Model-class capability slug (e.g. "opus", "fable", "sonnet", "haiku").
    class: []const u8,

    /// Credential-liveness state: "live" | "degraded" | "dead" (health §611).
    /// Gates suggestion eligibility ONLY — never the reported quota status.
    state: []const u8 = "live",
    /// Availability sub-state of a *live* credential: null/"available" |
    /// "rate_limited" | "quota_exhausted" | "cooldown".
    availability: ?[]const u8 = null,

    since: ?i64 = null,
    retry_after_s: ?u32 = null,
    limited_at: ?i64 = null,
    window_resets_at: ?i64 = null,
    usage_pct: ?u8 = null,
    exhausted_at: ?i64 = null,
    cooldown_until: ?i64 = null,
};

/// A model-class the provider schema DECLARES exists for a provider. Passed in so
/// this module never hardcodes a Claude class list — `provider_schema` owns the
/// declarations (design: "provider_schema owns declarations; pass them in").
pub const DeclaredClass = struct {
    provider: []const u8,
    class: []const u8,
};

/// The work the operator needs served. A null field is "unconstrained".
pub const Demand = struct {
    provider: ?[]const u8 = null,
    class: ?[]const u8 = null,
};

// ── outputs ──────────────────────────────────────────────────────────────────

/// Evidence strength carried into every summary and suggestion (design §7,
/// "confidence is visible"). A refinement of `bucket.Confidence`:
/// `unobserved` sits strictly below `assumed` — it is the honest name for a
/// model-class we have never observed a row for (`bucket.status == .fresh`).
/// Declaration order IS the rank: `unobserved < assumed < inferred < proven`.
pub const Provenance = enum { unobserved, assumed, inferred, proven };

pub const ClassSummary = struct {
    provider: []const u8,
    class: []const u8,
    /// The QUOTA availability query (`bucket.effectiveStatus`) of the best
    /// representative row for this class — NOT a credential-liveness verdict.
    status: bucket.EffectiveStatus,
    usage_pct: ?u8,
    /// The instant (ms) this class recovers, when known (waiting/gated only).
    resets_at: ?i64,
    provenance: Provenance,
};

pub const Suggestion = struct {
    provider: []const u8,
    account: []const u8,
    class: []const u8,
    /// Static string only (no allocation, no borrowed row data).
    reason: []const u8,
    provenance: Provenance,
};

pub const Advice = struct {
    /// Borrows the caller-supplied `out_classes` buffer.
    classes: []const ClassSummary,
    /// null when no account can be honestly recommended for the demand.
    suggestion: ?Suggestion,
    /// When `suggestion == null` because every demand candidate is waiting: the
    /// earliest `resets_at` (ms) among them. null when nothing is recoverable
    /// (no candidates, or all permanently blocked with no reset instant).
    wait_until: ?i64,
};

// ── boundary: one liveness row → one quota bucket ─────────────────────────────

fn secToMs(s: i64) i64 {
    return s *| 1000; // saturating: pathological second values can never panic
}

/// Adapt one parsed HealthStore liveness row into a `bucket.QuotaBucket` with
/// HONEST evidence. A persisted row is a *classified observation*, not a
/// provider-stated header, so its confidence is `.inferred` (source `.status_code`,
/// attribution `.static_session_tag`, both of which cap at `inferred`). The quota
/// status is derived ONLY from the availability sub-state — the credential
/// dimension (`row.state`) is disjoint and handled in `advise`. Reuses
/// `bucket.reduceBucket` from a fresh bucket so the status projection,
/// `deriveResetsAt`, and the never-null-reset guarantee come from the algebra.
pub fn bucketFromHealthRow(row: Row) bucket.QuotaBucket {
    const avail = row.availability orelse "available";

    const signal: bucket.QuotaSignal = if (std.mem.eql(u8, avail, "rate_limited"))
        .{ .rate_limited = .{ .retry_after_s = row.retry_after_s orelse 0 } }
    else if (std.mem.eql(u8, avail, "quota_exhausted"))
        .{ .quota_exhausted = .{ .stated_retry_s = null, .resets_at = if (row.window_resets_at) |r| secToMs(r) else null } }
    else if (std.mem.eql(u8, avail, "cooldown"))
        // A timed cooldown is a wait until an absolute instant — modeled as a spent
        // window recovering at `cooldown_until` (the only bucket arm with an
        // absolute reset). Yields `.waiting` until then, `.available` after.
        .{ .quota_exhausted = .{ .stated_retry_s = null, .resets_at = if (row.cooldown_until) |c| secToMs(c) else null } }
    else
        // "available", null, or any unrecognized string → optimistic ok, matching
        // the bucket's own out-of-box posture (an existing row still lifts
        // provenance to `.inferred`, distinguishing it from an unobserved class).
        .{ .quota_ok = .{ .usage_pct = row.usage_pct } };

    const observed_at = secToMs(row.since orelse row.limited_at orelse row.exhausted_at orelse 0);

    return bucket.reduceBucket(bucket.QuotaBucket{}, .{
        .at = observed_at,
        .source = .status_code, // parsed from a persisted classification, not a header
        .attribution = .static_session_tag, // a persisted tag, not an echoed served-model
        .signal = signal,
    }, null, BURST_THRESHOLD_S);
}

// ── bucket → summary projections ──────────────────────────────────────────────

fn provenanceOf(b: bucket.QuotaBucket) Provenance {
    return switch (b.status) {
        .fresh => .unobserved, // no observation folded in → never looked
        else => switch (b.evidence.confidence) {
            .assumed => .assumed,
            .inferred => .inferred,
            .proven => .proven,
        },
    };
}

fn provenanceRank(p: Provenance) u8 {
    return @intFromEnum(p); // declaration order is the rank
}

/// The provenance one liveness row contributes — exposed for the boundary + tests
/// (mirrors `bucket.observationConfidence`). A persisted row is a classified
/// observation, so this is `.inferred` today; never `.proven`.
pub fn rowProvenance(row: Row) Provenance {
    return provenanceOf(bucketFromHealthRow(row));
}

fn resetsAtOf(b: bucket.QuotaBucket) ?i64 {
    return switch (b.status) {
        .quota_exhausted => |q| q.resets_at,
        .plan_gated => |p| p.resets_at,
        .rate_limited => |r| r.since +| (@as(i64, r.retry_after_s) *| 1000),
        .fresh, .available, .tier_blocked => null,
    };
}

// ── deterministic tiebreak (design §Ranking step 5) ───────────────────────────
//
// The primary tiebreak is the route key, compared field-wise in
// `health.capabilityKey`'s "provider → account → class" lexicographic order (we
// replicate the ordering inline rather than import `health.zig` and drag its I/O
// deps into this pure core). To make it a genuine STRICT total order — so that
// two distinct rows sharing one route key can never fold order-dependently (the
// same hazard `bucket.zig` closes by keying its LWW on the observation's effect)
// — the order is extended over the remaining row fields. In production a route
// key is unique per row, so only the leading key components ever bite.

fn optStrOrder(a: ?[]const u8, b: ?[]const u8) std.math.Order {
    if (a == null and b == null) return .eq;
    if (a == null) return .lt;
    if (b == null) return .gt;
    return std.mem.order(u8, a.?, b.?);
}

fn optOrder(comptime T: type, a: ?T, b: ?T) std.math.Order {
    if (a == null and b == null) return .eq;
    if (a == null) return .lt;
    if (b == null) return .gt;
    return std.math.order(a.?, b.?);
}

fn rowOrder(a: Row, b: Row) std.math.Order {
    const seq = [_]std.math.Order{
        std.mem.order(u8, a.provider, b.provider),
        std.mem.order(u8, a.account, b.account),
        std.mem.order(u8, a.class, b.class),
        std.mem.order(u8, a.state, b.state),
        optStrOrder(a.availability, b.availability),
        optOrder(i64, a.since, b.since),
        optOrder(u32, a.retry_after_s, b.retry_after_s),
        optOrder(i64, a.limited_at, b.limited_at),
        optOrder(i64, a.window_resets_at, b.window_resets_at),
        optOrder(u8, a.usage_pct, b.usage_pct),
        optOrder(i64, a.exhausted_at, b.exhausted_at),
        optOrder(i64, a.cooldown_until, b.cooldown_until),
    };
    for (seq) |o| {
        if (o != .eq) return o;
    }
    return .eq;
}

fn keyLess(a: Row, b: Row) bool {
    return rowOrder(a, b) == .lt;
}

// ── class summary (pure quota view, per declared class) ───────────────────────

fn classMatches(row: Row, provider: []const u8, class: []const u8) bool {
    return std.mem.eql(u8, row.provider, provider) and std.mem.eql(u8, row.class, class);
}

fn summarizeClass(rows: []const Row, provider: []const u8, class: []const u8, now: i64) ClassSummary {
    var best_available: ?Row = null; // among quota-available rows, by (conf desc, key asc)
    var best_waiting: ?Row = null; // among the rest, by (resets asc, conf desc, key asc)

    for (rows) |row| {
        if (!classMatches(row, provider, class)) continue;
        const b = bucketFromHealthRow(row);
        const es = bucket.effectiveStatus(b, now);
        if (es == .available) {
            if (best_available) |cur| {
                if (availableBetter(row, cur)) best_available = row;
            } else best_available = row;
        } else {
            if (best_waiting) |cur| {
                if (waitingBetter(row, cur)) best_waiting = row;
            } else best_waiting = row;
        }
    }

    const rep: ?Row = best_available orelse best_waiting;
    if (rep) |row| {
        const b = bucketFromHealthRow(row);
        return .{
            .provider = provider,
            .class = class,
            .status = bucket.effectiveStatus(b, now),
            .usage_pct = b.usage_pct,
            .resets_at = resetsAtOf(b),
            .provenance = provenanceOf(b),
        };
    }

    // No row for this declared class → optimistic-available (bucket out-of-box
    // posture) but provenance `.unobserved`: we have never looked.
    const fresh = bucket.QuotaBucket{};
    return .{
        .provider = provider,
        .class = class,
        .status = bucket.effectiveStatus(fresh, now),
        .usage_pct = null,
        .resets_at = null,
        .provenance = .unobserved,
    };
}

fn availableBetter(cand: Row, cur: Row) bool {
    const pc = provenanceRank(provenanceOf(bucketFromHealthRow(cand)));
    const pr = provenanceRank(provenanceOf(bucketFromHealthRow(cur)));
    if (pc != pr) return pc > pr; // higher confidence wins
    return keyLess(cand, cur); // deterministic lexicographic tiebreak
}

fn waitingBetter(cand: Row, cur: Row) bool {
    const rc = resetsAtOf(bucketFromHealthRow(cand));
    const rr = resetsAtOf(bucketFromHealthRow(cur));
    // Soonest recovery first; a known reset beats an unknown (null) one.
    if (rc) |c| {
        if (rr) |r| {
            if (c != r) return c < r;
        } else return true;
    } else if (rr != null) return false;
    const pc = provenanceRank(provenanceOf(bucketFromHealthRow(cand)));
    const pr = provenanceRank(provenanceOf(bucketFromHealthRow(cur)));
    if (pc != pr) return pc > pr;
    return keyLess(cand, cur);
}

// ── suggestion (combined: quota + credential + parity + exclusion) ────────────

fn credentialAlive(row: Row) bool {
    // A live credential is the ONLY thing that proves the account is refreshable
    // (health §611: "live" wraps availability; "degraded"/"dead" are non-live).
    return std.mem.eql(u8, row.state, "live");
}

fn isExcluded(account: []const u8, excluded: []const []const u8) bool {
    for (excluded) |e| {
        if (std.mem.eql(u8, account, e)) return true;
    }
    return false;
}

fn matchesDemand(row: Row, demand: Demand) bool {
    if (demand.provider) |p| {
        if (!std.mem.eql(u8, row.provider, p)) return false;
    }
    if (demand.class) |c| {
        if (!std.mem.eql(u8, row.class, c)) return false;
    }
    return true;
}

fn parityScore(row: Row, demand: Demand) u8 {
    // 0 = exact declared-class parity for the demand (ranks first).
    if (demand.class) |c| {
        return if (std.mem.eql(u8, row.class, c)) 0 else 1;
    }
    return 0;
}

/// Is `cand` a strictly better suggestion than `cur`? Encodes ranking criteria
/// (1) parity, (4) confidence, (5) lexicographic key. (2) credential-ready and
/// (3) not-excluded are hard eligibility gates applied before this comparator,
/// so they never need to break a tie here.
fn suggestionBetter(cand: Row, cur: Row, demand: Demand) bool {
    const psc = parityScore(cand, demand);
    const psr = parityScore(cur, demand);
    if (psc != psr) return psc < psr; // lower parity score wins

    const pc = provenanceRank(provenanceOf(bucketFromHealthRow(cand)));
    const pr = provenanceRank(provenanceOf(bucketFromHealthRow(cur)));
    if (pc != pr) return pc > pr; // higher confidence wins

    return keyLess(cand, cur); // deterministic tiebreak
}

// ── the advisor ───────────────────────────────────────────────────────────────

/// PURE. No clock read, no allocation. Writes one `ClassSummary` per declared
/// class into the caller-supplied `out_classes` buffer (truncating if the buffer
/// is smaller than `declared.len`; never overflows) and returns `Advice`
/// borrowing that buffer.
///
/// `now` is Unix **milliseconds** (bucket convention; see the module header).
pub fn advise(
    rows: []const Row,
    declared: []const DeclaredClass,
    demand: Demand,
    excluded_accounts: []const []const u8,
    now: i64,
    out_classes: []ClassSummary,
) Advice {
    // 1) Per-declared-class quota summary (pure quota view; credential-independent).
    const n = @min(declared.len, out_classes.len);
    for (declared[0..n], 0..) |dc, i| {
        out_classes[i] = summarizeClass(rows, dc.provider, dc.class, now);
    }
    const classes = out_classes[0..n];

    // 2) Suggestion over demand candidates. Eligibility gates (design §Ranking
    //    criteria 2 & 3, applied as hard filters):
    //      - credential-alive (refreshable),
    //      - not in the caller's exclusion list (duplicate-identity collapse),
    //      - quota effectiveStatus == .available.
    var best: ?Row = null;
    var wait_until: ?i64 = null;
    for (rows) |row| {
        if (!matchesDemand(row, demand)) continue;

        const b = bucketFromHealthRow(row);
        const es = bucket.effectiveStatus(b, now);

        const eligible = credentialAlive(row) and
            !isExcluded(row.account, excluded_accounts) and
            es == .available;

        if (eligible) {
            if (best) |cur| {
                if (suggestionBetter(row, cur, demand)) best = row;
            } else best = row;
        } else if (es == .waiting or es == .plan_gated) {
            // A demand candidate that will recover: fold its reset into wait_until.
            if (resetsAtOf(b)) |r| {
                wait_until = if (wait_until) |w| @min(w, r) else r;
            }
        }
    }

    if (best) |row| {
        const b = bucketFromHealthRow(row);
        const reason: []const u8 = if (demand.class != null)
            "credential-ready and quota-available with exact class parity"
        else
            "credential-ready and quota-available";
        return .{
            .classes = classes,
            .suggestion = .{
                .provider = row.provider,
                .account = row.account,
                .class = row.class,
                .reason = reason,
                .provenance = provenanceOf(b),
            },
            .wait_until = null, // a live suggestion means no wait is required
        };
    }

    // No eligible account: all-waiting → surface the earliest recovery instant.
    return .{ .classes = classes, .suggestion = null, .wait_until = wait_until };
}
