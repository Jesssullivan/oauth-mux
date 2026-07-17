//! Pure advisory-usage reader core (TIN-2400 — the advisory half of exact-model
//! readiness). Authorities of record:
//!   * `docs/runbooks/omux-v0.2-evaluation-ladder-2026-07-14.md` §8.8
//!     (advisory usage and refresh);
//!   * `docs/plans/oauth-mux-v0.2-full-broker-foss-program-2026-07-11.md` §2.3
//!     (usage and health truth);
//!   * Prompt 79 ratified contract, the default-on advisory reader bullet.
//!
//! This module models the §8.8 default-on Claude usage reader as a **pure
//! data-in / data-out core**, exactly the way `bucket.zig` models quota: a
//! deterministic transform over injected observations, with the clock inverted.
//! It performs **NO I/O, NO network, NO provider call, NO credential read, and
//! NO clock read of its own** — every instant is passed in as a plain `now_s`
//! (Unix *seconds*, matching the provider `-reset` epoch grammar in
//! `provider_schema.zig`). The actual `GET /api/oauth/usage` fetch, the per-account
//! flock, refresh, and resident-service wiring all live elsewhere in later
//! increments; this file is only the pure reducer they will fold observations
//! through. It imports only `std` and the sibling `advise.zig` (for the shared
//! provenance vocabulary) — no net/clock/refresh/secret/pipeline seam is
//! reachable.
//!
//! ── SYNTHETIC SCHEMA DISCLAIMER (READ BEFORE WIRING TO A REAL ENDPOINT) ──
//!
//! The wire shape parsed by `parseUsage` is **SYNTHETIC and UNVERIFIED** against
//! the real Anthropic `GET /api/oauth/usage` response. It was invented for
//! Stage-1 local deterministic fixtures only (evaluation ladder §9 Stage 1). It
//! MUST NOT be treated as the confirmed provider contract. Before any real
//! endpoint is read, `SUPPORTED_SCHEMA_VERSION` and every field name/shape here
//! must be reconciled against a live no-spend capture, behind the kill switch
//! this module already implements — an unknown top-level shape or unsupported
//! version trips the per-account kill switch and the reader degrades to reactive
//! request-path evidence rather than guessing. The synthetic shape is:
//!
//!     {
//!       "schema_version": 1,
//!       "usage": [
//!         { "scope": "model",  "model": "claude-opus-4",
//!           "window": "5h", "utilization": 0.42, "resets_at": 1783652400 },
//!         { "scope": "model",  "model": "claude-opus-4",
//!           "window": "7d", "remaining": 1200,     "resets_at": 1783879200 },
//!         { "scope": "account",
//!           "window": "5h", "utilization": 0.10, "resets_at": 1783652400 }
//!       ]
//!     }
//!
//! Per §8.8 each row REQUIRES: `scope` ("account" | "model"), `window`
//! ("5h" | "7d"), one bounded usage-or-remaining value (`utilization` in 0..1
//! OR `remaining` >= 0), an absolute `resets_at` (epoch seconds > 0), and — for
//! model-scoped rows only — an exact `model`. Unknown fields are tolerated;
//! invalid rows are excluded with a typed reason and NEVER fabricated.
//!
//! ── No-raw-persistence, enforced by construction ──
//!
//! `Row` and `AdvisoryCache` carry NO `[]const u8` raw-response field: the exact
//! model is copied into a fixed `[MAX_MODEL_LEN]u8` inline buffer, every other
//! field is a scalar/enum. There is therefore no representable way to retain raw
//! response bytes in the cache — the §8.8 "no raw response persistence" rule is a
//! type-level invariant, not a runtime discipline.

const std = @import("std");
const advise = @import("advise.zig");

// ── §8.8 tunables ─────────────────────────────────────────────────────────────

/// Normalized-observation freshness window (seconds). A populated cache is fresh
/// while `now_s - observed_at_s < FRESHNESS_WINDOW_S`; it is STALE at exactly the
/// boundary (`>=`). "Five-minute normalized freshness window."
pub const FRESHNESS_WINDOW_S: i64 = 5 * 60; // 300

/// Negative cache for a valid-but-empty result (seconds). Same boundary rule.
/// "Five-minute negative cache for a valid empty result."
pub const NEGATIVE_CACHE_S: i64 = 5 * 60; // 300

/// The only advisory schema version this synthetic reader admits. Anything else
/// (or a missing version) trips the kill switch — see the disclaimer above.
pub const SUPPORTED_SCHEMA_VERSION: i64 = 1;

/// Exact-model identifiers are short; a longer value is excluded by construction
/// (`model_identifier_too_long`) so the inline buffer can never truncate a model.
pub const MAX_MODEL_LEN: usize = 64;

/// Cap on normalized rows retained per account. Bounds the cache footprint and
/// the parse output; excess synthetic rows are dropped (documented, never
/// silently merged).
pub const MAX_ROWS: usize = 16;

// Provenance is REUSED from the sibling valet advisor rather than redeclared:
// `advise.zig` is in this same `quota/` pure-core family and is NOT owned by any
// in-flight lane (the untouchable files are `adapters/claude/{main,wire_proxy,
// fake_upstream}.zig`), so importing it is conflict-free and keeps one provenance
// lattice across the quota cores. `unobserved < assumed < inferred < proven`.
pub const Provenance = advise.Provenance;

// ── normalized observation row (§8.8) ─────────────────────────────────────────

pub const Scope = enum { account, model };
pub const Window = enum { five_hour, seven_day };

/// The bounded usage-or-remaining value a row carries. `utilization` is a 0..1
/// fraction of the window consumed; `remaining` is a non-negative headroom count.
/// Both are bounded at parse time — an out-of-range value excludes the row.
pub const Usage = union(enum) {
    utilization: f64,
    remaining: u64,
};

/// One normalized advisory-usage row. POD, self-contained (no borrowed slices),
/// so it is snapshot-friendly, commutatively mergeable, and — crucially — cannot
/// hold raw response bytes. The model identifier is an inline fixed buffer.
pub const Row = struct {
    scope: Scope,
    window: Window,
    usage: Usage,
    /// Absolute reset instant, epoch **seconds**, always > 0 (parse-guaranteed).
    resets_at_s: i64,
    /// Exact model identifier for a model-scoped row; `model_len == 0` for an
    /// account-scoped row. Backed by an inline buffer — never a borrowed slice.
    model_buf: [MAX_MODEL_LEN]u8 = [_]u8{0} ** MAX_MODEL_LEN,
    model_len: u8 = 0,

    /// The exact model slice (empty for account scope). Borrows `self`.
    pub fn model(self: *const Row) []const u8 {
        return self.model_buf[0..self.model_len];
    }
};

/// The immediate readiness a row asserts, IGNORING its reset instant (that is a
/// query-time concern in `projectReadiness`). A valid row is only ever
/// `available` or `exhausted` — never `unknown`.
pub const Readiness = enum { available, exhausted, unknown };

/// The raw readiness a valid row asserts: a spent window (utilization at/above
/// 1.0, or zero remaining) is `exhausted`; anything else `available`.
pub fn rowReadiness(row: Row) Readiness {
    return switch (row.usage) {
        .utilization => |u| if (u >= 1.0) .exhausted else .available,
        .remaining => |r| if (r == 0) .exhausted else .available,
    };
}

// ── typed per-row exclusion reasons (§8.8 "invalid-row exclusion") ─────────────

/// Why a synthetic `usage[]` element was excluded. Each maps to one missing or
/// out-of-contract required field. An excluded row is NEVER fabricated into a
/// default — it simply does not enter the normalized set.
pub const ExclusionReason = enum {
    missing_scope,
    unknown_scope,
    missing_window,
    unknown_window,
    missing_usage_value,
    usage_value_out_of_range,
    missing_reset,
    non_absolute_reset,
    missing_model_for_model_scope,
    model_identifier_too_long,
};

// ── kill switch (§8.8) ────────────────────────────────────────────────────────

/// The structural class of a top-level failure that trips the per-account
/// process-lifetime kill switch. Low-cardinality and value-free.
pub const KillKind = enum {
    unparseable, // bytes are not JSON at all → "missing top-level structure"
    not_object, // top-level JSON is not an object
    missing_usage_array, // no `usage` array present
    unsupported_schema_version, // absent or != SUPPORTED_SCHEMA_VERSION
};

/// A shape-derived, low-cardinality kill fingerprint. It carries NO payload
/// values — only the structural `kind` and a 64-bit hash folded from that kind
/// plus the (schema-structural, not data) version tag. Two top-level failures
/// with the same shape share a fingerprint, so exactly one redacted event is
/// emitted per distinct shape.
pub const Fingerprint = struct {
    kind: KillKind,
    hash: u64,

    pub fn eql(a: Fingerprint, b: Fingerprint) bool {
        return a.hash == b.hash;
    }
};

/// FNV-1a over (kind, version-tag). The version integer is a SCHEMA identifier
/// (which contract we were handed), not a usage payload value, so including it
/// keeps the fingerprint value-free while still distinguishing "version 2" from
/// "version 3" for the one-event-per-fingerprint rule.
fn fingerprintFor(kind: KillKind, version_tag: i64) Fingerprint {
    var h: u64 = 0xcbf29ce484222325;
    const mix = struct {
        fn go(hash: *u64, byte: u8) void {
            hash.* ^= byte;
            hash.* *%= 0x100000001b3;
        }
    };
    mix.go(&h, @intFromEnum(kind));
    const vt: u64 = @bitCast(version_tag);
    var i: u6 = 0;
    while (i < 8) : (i += 1) mix.go(&h, @truncate(vt >> (@as(u6, i) * 8)));
    return .{ .kind = kind, .hash = h };
}

/// The only thing a kill emits: a redacted, value-free event. Contains the
/// structural kind and the fingerprint hash — nothing derived from the payload.
pub const RedactedEvent = struct {
    kind: KillKind,
    fingerprint: u64,
};

/// Per-account kill state: a process-lifetime latch plus the set of fingerprints
/// already reported, so `recordKill` emits at most one event per shape. Pure: it
/// records and dedupes, it does not perform I/O (the caller logs the event).
pub const KillRegistry = struct {
    killed: bool = false,
    seen: [MAX_KILL_FINGERPRINTS]u64 = [_]u64{0} ** MAX_KILL_FINGERPRINTS,
    seen_len: usize = 0,

    pub const MAX_KILL_FINGERPRINTS: usize = 8;

    /// Latch the kill (process-lifetime — never cleared here) and return a
    /// redacted event ONLY the first time this fingerprint is seen. A repeat of a
    /// known fingerprint latches (idempotently) but emits nothing.
    pub fn recordKill(self: *KillRegistry, fp: Fingerprint) ?RedactedEvent {
        self.killed = true;
        for (self.seen[0..self.seen_len]) |h| {
            if (h == fp.hash) return null; // already emitted for this shape
        }
        if (self.seen_len < self.seen.len) {
            self.seen[self.seen_len] = fp.hash;
            self.seen_len += 1;
        }
        return .{ .kind = fp.kind, .fingerprint = fp.hash };
    }
};

// ── parse: synthetic JSON bytes → normalized rows + typed exclusions ───────────

/// The outcome of parsing one `GET /api/oauth/usage` body. On a top-level
/// failure `killed` is set and `fingerprint` names the shape (the caller feeds it
/// to `KillRegistry.recordKill`); no rows are produced. Otherwise `rows` borrows
/// the caller's `out_rows` buffer (valid, normalized rows) and `exclusions`
/// borrows `out_excl` (one typed reason per rejected element).
pub const Parsed = struct {
    killed: bool = false,
    fingerprint: ?Fingerprint = null,
    rows: []const Row = &.{},
    exclusions: []const ExclusionReason = &.{},
    /// Count of `usage[]` elements seen (valid + excluded), before buffer caps.
    total_elements: usize = 0,
};

/// PURE (aside from the transient JSON DOM alloc, freed before return). Parses
/// SYNTHETIC advisory bytes into normalized rows. Tolerant of unknown fields;
/// strict on the required ones. Never panics on malformed input — unparseable
/// bytes are a kill (missing top-level structure), a bad element is a typed
/// exclusion. `now_s` is not needed here (parsing is time-independent); freshness
/// is applied later by `AdvisoryCache`.
///
/// The `allocator` backs only the throwaway `std.json.Value` DOM; every retained
/// value is copied into `out_rows` (POD), so nothing borrows freed memory.
pub fn parseUsage(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    out_rows: []Row,
    out_excl: []ExclusionReason,
) Parsed {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch {
        // Not JSON at all → missing top-level structure → kill.
        return .{ .killed = true, .fingerprint = fingerprintFor(.unparseable, 0) };
    };
    defer parsed.deinit();

    const root = parsed.value;
    if (root != .object) {
        return .{ .killed = true, .fingerprint = fingerprintFor(.not_object, 0) };
    }
    const obj = root.object;

    // Unsupported / missing schema version → kill (fingerprint keyed on version).
    const version: ?i64 = if (obj.get("schema_version")) |v| jsonInt(v) else null;
    if (version == null or version.? != SUPPORTED_SCHEMA_VERSION) {
        return .{
            .killed = true,
            .fingerprint = fingerprintFor(.unsupported_schema_version, version orelse -1),
        };
    }

    // Missing top-level structure: no `usage` array.
    const usage_val = obj.get("usage") orelse {
        return .{ .killed = true, .fingerprint = fingerprintFor(.missing_usage_array, version.?) };
    };
    if (usage_val != .array) {
        return .{ .killed = true, .fingerprint = fingerprintFor(.missing_usage_array, version.?) };
    }

    var n_rows: usize = 0;
    var n_excl: usize = 0;
    var total: usize = 0;
    for (usage_val.array.items) |elem| {
        total += 1;
        switch (parseElement(elem)) {
            .row => |r| {
                if (n_rows < out_rows.len) {
                    out_rows[n_rows] = r;
                    n_rows += 1;
                }
            },
            .excluded => |reason| {
                if (n_excl < out_excl.len) {
                    out_excl[n_excl] = reason;
                    n_excl += 1;
                }
            },
        }
    }

    return .{
        .killed = false,
        .fingerprint = null,
        .rows = out_rows[0..n_rows],
        .exclusions = out_excl[0..n_excl],
        .total_elements = total,
    };
}

const ElementResult = union(enum) {
    row: Row,
    excluded: ExclusionReason,
};

/// One `usage[]` element → a valid row or a typed exclusion. Required-field order
/// is deterministic so a fixture can target one reason at a time.
fn parseElement(elem: std.json.Value) ElementResult {
    if (elem != .object) return .{ .excluded = .missing_scope };
    const o = elem.object;

    // scope
    const scope_str = jsonStr(o.get("scope")) orelse return .{ .excluded = .missing_scope };
    const scope: Scope = if (std.mem.eql(u8, scope_str, "account"))
        .account
    else if (std.mem.eql(u8, scope_str, "model"))
        .model
    else
        return .{ .excluded = .unknown_scope };

    // window
    const window_str = jsonStr(o.get("window")) orelse return .{ .excluded = .missing_window };
    const window: Window = if (std.mem.eql(u8, window_str, "5h"))
        .five_hour
    else if (std.mem.eql(u8, window_str, "7d"))
        .seven_day
    else
        return .{ .excluded = .unknown_window };

    // bounded usage-or-remaining value: `utilization` (0..1) preferred, else
    // `remaining` (>= 0). Presence of the key decides; a present-but-bad value is
    // out-of-range, not missing.
    const usage: Usage = blk: {
        if (o.get("utilization")) |uv| {
            const f = jsonFloat(uv) orelse return .{ .excluded = .usage_value_out_of_range };
            if (!std.math.isFinite(f) or f < 0.0 or f > 1.0) return .{ .excluded = .usage_value_out_of_range };
            break :blk .{ .utilization = f };
        }
        if (o.get("remaining")) |rv| {
            const i = jsonInt(rv) orelse return .{ .excluded = .usage_value_out_of_range };
            if (i < 0) return .{ .excluded = .usage_value_out_of_range };
            break :blk .{ .remaining = @intCast(i) };
        }
        return .{ .excluded = .missing_usage_value };
    };

    // absolute reset (epoch seconds > 0)
    const reset_val = o.get("resets_at") orelse return .{ .excluded = .missing_reset };
    const reset = jsonInt(reset_val) orelse return .{ .excluded = .non_absolute_reset };
    if (reset <= 0) return .{ .excluded = .non_absolute_reset };

    var row = Row{
        .scope = scope,
        .window = window,
        .usage = usage,
        .resets_at_s = reset,
    };

    // exact model, required for model-scoped rows only
    if (scope == .model) {
        const m = jsonStr(o.get("model")) orelse return .{ .excluded = .missing_model_for_model_scope };
        if (m.len == 0) return .{ .excluded = .missing_model_for_model_scope };
        if (m.len > MAX_MODEL_LEN) return .{ .excluded = .model_identifier_too_long };
        @memcpy(row.model_buf[0..m.len], m);
        row.model_len = @intCast(m.len);
    }

    return .{ .row = row };
}

// tolerant JSON scalar readers — absence/type-mismatch is data (→ null), never a
// panic. Integers may arrive as `.integer` or an out-of-i64 `.number_string`.
fn jsonStr(v: ?std.json.Value) ?[]const u8 {
    const val = v orelse return null;
    return switch (val) {
        .string => |s| s,
        else => null,
    };
}

fn jsonInt(v: std.json.Value) ?i64 {
    return switch (v) {
        .integer => |i| i,
        .number_string => |s| std.fmt.parseInt(i64, s, 10) catch null,
        else => null,
    };
}

fn jsonFloat(v: std.json.Value) ?f64 {
    return switch (v) {
        .float => |f| f,
        .integer => |i| @floatFromInt(i),
        .number_string => |s| std.fmt.parseFloat(f64, s) catch null,
        else => null,
    };
}

// ── commutative row merge (§CRDT/order-independence spirit) ────────────────────

/// Do two rows address the same advisory slot? Same scope + window, and — for
/// model scope — the same exact model. Merge is only meaningful for same-key rows.
pub fn rowKeyEqual(a: Row, b: Row) bool {
    if (a.scope != b.scope or a.window != b.window) return false;
    if (a.scope == .model) return std.mem.eql(u8, a.model(), b.model());
    return true;
}

// A conservatism scalar for the final commutative tiebreak: higher = "more
// spent" (closer to exhausted). Utilization scales into the same axis as a
// negated remaining count so the max is order-independent.
fn conservatism(row: Row) i128 {
    return switch (row.usage) {
        .utilization => |u| @as(i128, @intFromFloat(u * 1_000_000_000.0)),
        .remaining => |r| -@as(i128, r),
    };
}

/// Commutative, associative, idempotent merge of two SAME-KEY rows (precondition:
/// `rowKeyEqual(a, b)`). Resolution, in order, all symmetric in `(a, b)`:
///   1. disagreeing readiness → the conservative (`exhausted`) row wins;
///   2. else the later window horizon (`resets_at_s`) wins;
///   3. else the more-spent (`conservatism`) row wins;
///   4. else the rows are equivalent → return `a` (== `b`).
/// This is the §CRDT/order-independence spirit `bucket.zig` folds by: merging
/// observations of one account must not depend on arrival order.
pub fn mergeSameKey(a: Row, b: Row) Row {
    const ra = rowReadiness(a);
    const rb = rowReadiness(b);
    if (ra != rb) return if (ra == .exhausted) a else b;
    if (a.resets_at_s != b.resets_at_s) return if (a.resets_at_s > b.resets_at_s) a else b;
    const ca = conservatism(a);
    const cb = conservatism(b);
    if (ca != cb) return if (ca > cb) a else b;
    return a;
}

// ── freshness / negative cache / coalesced in-flight (§8.8 state machine) ──────

pub const Phase = enum { never, populated, negative, killed };

pub const Freshness = enum {
    never, // no observation ever folded
    populated_fresh, // rows within the freshness window
    populated_stale, // rows, but the window elapsed
    negative_active, // valid-empty result, negative cache live
    negative_expired, // valid-empty result, negative cache elapsed
    killed, // kill switch latched for this account
};

/// Per-account advisory cache: the §8.8 freshness / negative-cache / coalesced-
/// in-flight state as pure transitions over `now_s`. Holds only NORMALIZED rows
/// (POD, no raw bytes) plus timing metadata and an in-flight flag. Once `.killed`
/// it stays killed (process-lifetime).
pub const AdvisoryCache = struct {
    phase: Phase = .never,
    observed_at_s: i64 = 0,
    inflight: bool = false,
    rows: [MAX_ROWS]Row = undefined,
    row_len: usize = 0,

    pub const AcquireResult = enum { acquired, coalesced };

    /// Fold a parse outcome into the cache at `now_s`. A killed parse latches the
    /// kill phase (and drops any rows); a valid-empty result arms the negative
    /// cache; rows populate the cache. A latched kill absorbs further ingests.
    pub fn ingest(self: *AdvisoryCache, parsed: Parsed, now_s: i64) void {
        if (self.phase == .killed) return; // process-lifetime latch
        if (parsed.killed) {
            self.phase = .killed;
            self.row_len = 0;
            self.observed_at_s = now_s;
            return;
        }
        self.observed_at_s = now_s;
        if (parsed.rows.len == 0) {
            self.phase = .negative;
            self.row_len = 0;
            return;
        }
        const n = @min(parsed.rows.len, self.rows.len);
        for (parsed.rows[0..n], 0..) |r, i| self.rows[i] = r;
        self.row_len = n;
        self.phase = .populated;
    }

    /// The freshness classification at `now_s`. The window is closed at the exact
    /// boundary: fresh while `age < WINDOW`, stale/expired at `age >= WINDOW`.
    pub fn freshness(self: *const AdvisoryCache, now_s: i64) Freshness {
        return switch (self.phase) {
            .never => .never,
            .killed => .killed,
            .populated => if (now_s - self.observed_at_s < FRESHNESS_WINDOW_S)
                .populated_fresh
            else
                .populated_stale,
            .negative => if (now_s - self.observed_at_s < NEGATIVE_CACHE_S)
                .negative_active
            else
                .negative_expired,
        };
    }

    /// The fresh normalized rows, or an empty slice when not fresh/populated.
    /// Killed, stale, negative, and never-observed all yield no advisory rows —
    /// the caller then falls back to reactive evidence.
    pub fn freshRows(self: *const AdvisoryCache, now_s: i64) []const Row {
        return if (self.freshness(now_s) == .populated_fresh)
            self.rows[0..self.row_len]
        else
            &.{};
    }

    /// Coalesce reads: the first acquire wins the single in-flight slot; further
    /// acquires are coalesced onto it until `releaseInflight`. Models "one
    /// coalesced in-flight read per account" — the real read happens elsewhere.
    pub fn acquireInflight(self: *AdvisoryCache) AcquireResult {
        if (self.inflight) return .coalesced;
        self.inflight = true;
        return .acquired;
    }

    pub fn releaseInflight(self: *AdvisoryCache) void {
        self.inflight = false;
    }
};

// ── precedence election: advisory vs reactive (§8.8 last bullet, §2.3) ─────────

/// A summarized advisory signal for one model (folded from fresh rows). `null` at
/// call sites means the advisory state is stale/missing/killed/contradictory/
/// resident-unavailable — all of which degrade to reactive evidence.
pub const Advisory = struct {
    readiness: Readiness,
    resets_at_s: i64,
};

/// A direct request-path observation: the reactive evidence that OUTRANKS
/// advisory state. `resets_at_s` is the instant an exhaustion frees, or an
/// availability deadline after which the observation is no longer trusted.
pub const Reactive = struct {
    readiness: Readiness,
    resets_at_s: i64,
};

pub const Election = struct {
    readiness: Readiness,
    provenance: Provenance,
    /// The reset/free instant when `readiness == .exhausted`; else null.
    resets_at_s: ?i64,
};

/// Project a timed readiness at `now_s`, honoring the §8.8 temporal rules:
///   * observed exhaustion is trusted THROUGH its reset — `exhausted` while
///     `now_s < resets_at_s`, then `unknown` (we do NOT invent `available`);
///   * availability EXPIRES at its deadline — `available` while
///     `now_s < resets_at_s`, then `unknown`.
/// `unknown` in → `unknown` out. `unknown` out means "no readiness here",
/// which lets the election fall through to the next-lower evidence tier.
pub fn projectReadiness(readiness: Readiness, resets_at_s: i64, now_s: i64) Readiness {
    return switch (readiness) {
        .exhausted => if (now_s >= resets_at_s) .unknown else .exhausted,
        .available => if (now_s >= resets_at_s) .unknown else .available,
        .unknown => .unknown,
    };
}

/// Elect readiness for a route from reactive and advisory evidence at `now_s`.
///
/// Precedence (§8.8 last bullet, program §2.3):
///   * DIRECT request-path (reactive) evidence OUTRANKS advisory state: a
///     projected reactive readiness is returned `.proven` before advisory is
///     consulted;
///   * a reactive observation that has expired (projects to `unknown`) falls
///     through to advisory;
///   * fresh, valid, non-contradictory advisory state is `.inferred` (a
///     classified usage read, never `.proven`);
///   * stale / missing / killed / contradictory / resident-unavailable advisory
///     state is passed as `null` here and degrades to reactive — and when both
///     are absent the result is `.unobserved`/`unknown`, NEVER an invented
///     route/model readiness.
pub fn elect(advisory: ?Advisory, reactive: ?Reactive, now_s: i64) Election {
    if (reactive) |rx| {
        const r = projectReadiness(rx.readiness, rx.resets_at_s, now_s);
        switch (r) {
            .exhausted => return .{ .readiness = .exhausted, .provenance = .proven, .resets_at_s = rx.resets_at_s },
            .available => return .{ .readiness = .available, .provenance = .proven, .resets_at_s = null },
            .unknown => {}, // expired reactive evidence → consult advisory
        }
    }
    if (advisory) |a| {
        const r = projectReadiness(a.readiness, a.resets_at_s, now_s);
        switch (r) {
            .exhausted => return .{ .readiness = .exhausted, .provenance = .inferred, .resets_at_s = a.resets_at_s },
            .available => return .{ .readiness = .available, .provenance = .inferred, .resets_at_s = null },
            .unknown => {},
        }
    }
    // Nothing usable: honest "we have never looked / it expired", no invention.
    return .{ .readiness = .unknown, .provenance = .unobserved, .resets_at_s = null };
}

// ── advisory summary over fresh rows (contradiction detection) ─────────────────

/// The outcome of folding fresh rows into an advisory signal for one model.
pub const Summary = union(enum) {
    /// No fresh row applies to the model (falls back to reactive/unobserved).
    none,
    /// Two same-key rows disagree on readiness — the advisory state is
    /// contradictory and must degrade to reactive (§8.8).
    contradiction,
    /// A coherent advisory signal for the model.
    advisory: Advisory,
};

fn rowAppliesToModel(row: Row, model_id: []const u8) bool {
    return switch (row.scope) {
        .account => true, // account-wide rows apply to every model
        .model => std.mem.eql(u8, row.model(), model_id),
    };
}

/// Fold the fresh rows applicable to `model_id` into one advisory signal.
/// Contradiction = two SAME-KEY rows with disagreeing readiness. Otherwise the
/// signal is conservative: exhausted if ANY applicable window is spent (freeing
/// at the latest such reset); else available (deadline = the earliest horizon).
pub fn summarizeModel(rows: []const Row, model_id: []const u8, now_s: i64) Summary {
    _ = now_s; // freshness is applied by the caller (freshRows); kept for symmetry
    // Same-key contradiction (O(n^2); n <= MAX_ROWS).
    for (rows, 0..) |ri, i| {
        if (!rowAppliesToModel(ri, model_id)) continue;
        for (rows[i + 1 ..]) |rj| {
            if (!rowAppliesToModel(rj, model_id)) continue;
            if (rowKeyEqual(ri, rj) and rowReadiness(ri) != rowReadiness(rj)) {
                return .contradiction;
            }
        }
    }

    var applicable = false;
    var exhausted = false;
    var exhaust_reset: i64 = std.math.minInt(i64);
    var earliest_avail: i64 = std.math.maxInt(i64);
    for (rows) |row| {
        if (!rowAppliesToModel(row, model_id)) continue;
        applicable = true;
        switch (rowReadiness(row)) {
            .exhausted => {
                exhausted = true;
                if (row.resets_at_s > exhaust_reset) exhaust_reset = row.resets_at_s;
            },
            .available => {
                if (row.resets_at_s < earliest_avail) earliest_avail = row.resets_at_s;
            },
            .unknown => {},
        }
    }

    if (!applicable) return .none;
    if (exhausted) return .{ .advisory = .{ .readiness = .exhausted, .resets_at_s = exhaust_reset } };
    return .{ .advisory = .{ .readiness = .available, .resets_at_s = earliest_avail } };
}

// ════════════════════════════════════════════════════════════════════════════
//  Tests — in-file, `std` only, deterministic fixtures (§8.8 predicate surface).
//  Run: nix develop -c zig build test
// ════════════════════════════════════════════════════════════════════════════

test {
    std.testing.refAllDeclsRecursive(@This());
}

const testing = std.testing;

// Small fixed scratch for parse output in tests.
fn parse(bytes: []const u8, rows: []Row, excl: []ExclusionReason) Parsed {
    return parseUsage(testing.allocator, bytes, rows, excl);
}

test "happy path: valid synthetic body yields normalized rows" {
    var rows: [MAX_ROWS]Row = undefined;
    var excl: [MAX_ROWS]ExclusionReason = undefined;
    const body =
        \\{ "schema_version": 1, "usage": [
        \\  { "scope": "model", "model": "claude-opus-4", "window": "5h", "utilization": 0.42, "resets_at": 1783652400 },
        \\  { "scope": "model", "model": "claude-opus-4", "window": "7d", "remaining": 1200, "resets_at": 1783879200 },
        \\  { "scope": "account", "window": "5h", "utilization": 0.10, "resets_at": 1783652400 }
        \\] }
    ;
    const p = parse(body, &rows, &excl);
    try testing.expect(!p.killed);
    try testing.expectEqual(@as(usize, 3), p.rows.len);
    try testing.expectEqual(@as(usize, 0), p.exclusions.len);

    try testing.expectEqual(Scope.model, p.rows[0].scope);
    try testing.expectEqual(Window.five_hour, p.rows[0].window);
    try testing.expectEqualStrings("claude-opus-4", p.rows[0].model());
    try testing.expectEqual(@as(f64, 0.42), p.rows[0].usage.utilization);
    try testing.expectEqual(@as(i64, 1783652400), p.rows[0].resets_at_s);

    try testing.expectEqual(@as(u64, 1200), p.rows[1].usage.remaining);
    try testing.expectEqual(Scope.account, p.rows[2].scope);
    try testing.expectEqual(@as(u8, 0), p.rows[2].model_len);
}

test "unknown fields are tolerated" {
    var rows: [MAX_ROWS]Row = undefined;
    var excl: [MAX_ROWS]ExclusionReason = undefined;
    const body =
        \\{ "schema_version": 1, "generated_at": "whenever", "extra": {"a":1},
        \\  "usage": [
        \\   { "scope": "model", "model": "claude-sonnet-4", "window": "7d",
        \\     "utilization": 0.5, "resets_at": 1783879200,
        \\     "future_field": true, "nested": {"x":[1,2,3]} } ] }
    ;
    const p = parse(body, &rows, &excl);
    try testing.expect(!p.killed);
    try testing.expectEqual(@as(usize, 1), p.rows.len);
    try testing.expectEqualStrings("claude-sonnet-4", p.rows[0].model());
}

test "each exclusion reason is reported, row never fabricated" {
    const Case = struct { body: []const u8, want: ExclusionReason };
    const cases = [_]Case{
        .{ .body =
        \\{"schema_version":1,"usage":[{"window":"5h","utilization":0.1,"resets_at":10}]}
        , .want = .missing_scope },
        .{ .body =
        \\{"schema_version":1,"usage":[{"scope":"team","window":"5h","utilization":0.1,"resets_at":10}]}
        , .want = .unknown_scope },
        .{ .body =
        \\{"schema_version":1,"usage":[{"scope":"account","utilization":0.1,"resets_at":10}]}
        , .want = .missing_window },
        .{ .body =
        \\{"schema_version":1,"usage":[{"scope":"account","window":"90m","utilization":0.1,"resets_at":10}]}
        , .want = .unknown_window },
        .{ .body =
        \\{"schema_version":1,"usage":[{"scope":"account","window":"5h","resets_at":10}]}
        , .want = .missing_usage_value },
        .{ .body =
        \\{"schema_version":1,"usage":[{"scope":"account","window":"5h","utilization":1.7,"resets_at":10}]}
        , .want = .usage_value_out_of_range },
        .{ .body =
        \\{"schema_version":1,"usage":[{"scope":"account","window":"5h","utilization":0.1}]}
        , .want = .missing_reset },
        .{ .body =
        \\{"schema_version":1,"usage":[{"scope":"account","window":"5h","utilization":0.1,"resets_at":-5}]}
        , .want = .non_absolute_reset },
        .{ .body =
        \\{"schema_version":1,"usage":[{"scope":"model","window":"5h","utilization":0.1,"resets_at":10}]}
        , .want = .missing_model_for_model_scope },
        .{ .body =
        \\{"schema_version":1,"usage":[{"scope":"model","model":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","window":"5h","utilization":0.1,"resets_at":10}]}
        , .want = .model_identifier_too_long },
    };
    for (cases) |c| {
        var rows: [MAX_ROWS]Row = undefined;
        var excl: [MAX_ROWS]ExclusionReason = undefined;
        const p = parse(c.body, &rows, &excl);
        try testing.expect(!p.killed);
        try testing.expectEqual(@as(usize, 0), p.rows.len); // never fabricated
        try testing.expectEqual(@as(usize, 1), p.exclusions.len);
        try testing.expectEqual(c.want, p.exclusions[0]);
    }
}

test "kill switch: missing top-level structure and unsupported version trip a kill" {
    var rows: [MAX_ROWS]Row = undefined;
    var excl: [MAX_ROWS]ExclusionReason = undefined;

    const not_json = parse("this is not json", &rows, &excl);
    try testing.expect(not_json.killed);
    try testing.expectEqual(KillKind.unparseable, not_json.fingerprint.?.kind);

    const not_obj = parse("[1,2,3]", &rows, &excl);
    try testing.expect(not_obj.killed);
    try testing.expectEqual(KillKind.not_object, not_obj.fingerprint.?.kind);

    const no_usage = parse("{\"schema_version\":1}", &rows, &excl);
    try testing.expect(no_usage.killed);
    try testing.expectEqual(KillKind.missing_usage_array, no_usage.fingerprint.?.kind);

    const bad_ver = parse("{\"schema_version\":9,\"usage\":[]}", &rows, &excl);
    try testing.expect(bad_ver.killed);
    try testing.expectEqual(KillKind.unsupported_schema_version, bad_ver.fingerprint.?.kind);
}

test "kill switch: one redacted event per schema fingerprint, reactive still available" {
    var reg = KillRegistry{};

    const fp_v2 = fingerprintFor(.unsupported_schema_version, 2);
    const fp_v3 = fingerprintFor(.unsupported_schema_version, 3);

    // First sight of v2 emits; repeat of v2 does not.
    try testing.expect(reg.recordKill(fp_v2) != null);
    try testing.expect(reg.recordKill(fp_v2) == null);
    try testing.expect(reg.killed);

    // A DIFFERENT shape emits its own single event.
    try testing.expect(reg.recordKill(fp_v3) != null);
    try testing.expect(reg.recordKill(fp_v3) == null);

    // Killed advisory (passed as null) never blocks reactive evidence.
    const el = elect(null, .{ .readiness = .available, .resets_at_s = 10_000 }, 0);
    try testing.expectEqual(Readiness.available, el.readiness);
    try testing.expectEqual(Provenance.proven, el.provenance);
}

test "freshness expiry at exactly the 300s boundary" {
    var cache = AdvisoryCache{};
    var rows: [MAX_ROWS]Row = undefined;
    var excl: [MAX_ROWS]ExclusionReason = undefined;
    const p = parse(
        \\{"schema_version":1,"usage":[{"scope":"account","window":"5h","utilization":0.1,"resets_at":9999999999}]}
    , &rows, &excl);
    cache.ingest(p, 1000);

    try testing.expectEqual(Freshness.populated_fresh, cache.freshness(1000 + 299));
    // Exactly at the 300s boundary the window is CLOSED → stale.
    try testing.expectEqual(Freshness.populated_stale, cache.freshness(1000 + 300));
    try testing.expectEqual(@as(usize, 1), cache.freshRows(1000 + 299).len);
    try testing.expectEqual(@as(usize, 0), cache.freshRows(1000 + 300).len);
}

test "negative cache: hit then expiry at the boundary" {
    var cache = AdvisoryCache{};
    var rows: [MAX_ROWS]Row = undefined;
    var excl: [MAX_ROWS]ExclusionReason = undefined;
    const empty = parse("{\"schema_version\":1,\"usage\":[]}", &rows, &excl);
    try testing.expect(!empty.killed);
    try testing.expectEqual(@as(usize, 0), empty.rows.len);

    cache.ingest(empty, 500);
    try testing.expectEqual(Freshness.negative_active, cache.freshness(500 + 299));
    try testing.expectEqual(Freshness.negative_expired, cache.freshness(500 + 300));
}

test "coalesced in-flight: one acquire wins, rest coalesce until release" {
    var cache = AdvisoryCache{};
    try testing.expectEqual(AdvisoryCache.AcquireResult.acquired, cache.acquireInflight());
    try testing.expectEqual(AdvisoryCache.AcquireResult.coalesced, cache.acquireInflight());
    try testing.expectEqual(AdvisoryCache.AcquireResult.coalesced, cache.acquireInflight());
    cache.releaseInflight();
    try testing.expectEqual(AdvisoryCache.AcquireResult.acquired, cache.acquireInflight());
}

test "cache kill is a process-lifetime latch that absorbs later ingests" {
    var cache = AdvisoryCache{};
    var rows: [MAX_ROWS]Row = undefined;
    var excl: [MAX_ROWS]ExclusionReason = undefined;

    const killed = parse("garbage", &rows, &excl);
    cache.ingest(killed, 100);
    try testing.expectEqual(Freshness.killed, cache.freshness(100));

    // A later VALID ingest cannot revive a killed account.
    const good = parse(
        \\{"schema_version":1,"usage":[{"scope":"account","window":"5h","utilization":0.1,"resets_at":9999999999}]}
    , &rows, &excl);
    cache.ingest(good, 200);
    try testing.expectEqual(Freshness.killed, cache.freshness(200));
    try testing.expectEqual(@as(usize, 0), cache.freshRows(200).len);
}

test "precedence: reactive-newer outranks fresh advisory" {
    // Advisory says exhausted; a direct request-path success says available.
    const adv = Advisory{ .readiness = .exhausted, .resets_at_s = 100_000 };
    const rx = Reactive{ .readiness = .available, .resets_at_s = 100_000 };
    const el = elect(adv, rx, 0);
    try testing.expectEqual(Readiness.available, el.readiness);
    try testing.expectEqual(Provenance.proven, el.provenance);
}

test "precedence: observed exhaustion trusted through reset, then no invention" {
    const rx = Reactive{ .readiness = .exhausted, .resets_at_s = 1000 };
    // Before reset: exhausted, trusted, proven.
    const before = elect(null, rx, 999);
    try testing.expectEqual(Readiness.exhausted, before.readiness);
    try testing.expectEqual(Provenance.proven, before.provenance);
    try testing.expectEqual(@as(?i64, 1000), before.resets_at_s);
    // At/after reset: no longer trusted as exhausted, and NOT invented available.
    const at = elect(null, rx, 1000);
    try testing.expectEqual(Readiness.unknown, at.readiness);
    try testing.expectEqual(Provenance.unobserved, at.provenance);
}

test "precedence: availability expires at its deadline" {
    const rx = Reactive{ .readiness = .available, .resets_at_s = 2000 };
    try testing.expectEqual(Readiness.available, elect(null, rx, 1999).readiness);
    // Deadline reached: reactive available no longer trusted → falls through.
    const expired = elect(null, rx, 2000);
    try testing.expectEqual(Readiness.unknown, expired.readiness);
    try testing.expectEqual(Provenance.unobserved, expired.provenance);
}

test "precedence: expired reactive falls through to fresh advisory" {
    const adv = Advisory{ .readiness = .available, .resets_at_s = 5000 };
    const rx = Reactive{ .readiness = .available, .resets_at_s = 1000 }; // already expired at now=1500
    const el = elect(adv, rx, 1500);
    try testing.expectEqual(Readiness.available, el.readiness);
    try testing.expectEqual(Provenance.inferred, el.provenance); // advisory tier
}

test "precedence: contradictory advisory degrades to reactive" {
    // Two same-key rows disagree → summarize reports contradiction → caller passes
    // null advisory to elect → reactive evidence carries the decision.
    var rows = [_]Row{
        makeRow(.model, "claude-opus-4", .five_hour, .{ .utilization = 0.1 }, 1000),
        makeRow(.model, "claude-opus-4", .five_hour, .{ .utilization = 1.0 }, 1000),
    };
    const summary = summarizeModel(&rows, "claude-opus-4", 0);
    try testing.expectEqual(Summary.contradiction, summary);

    const advisory: ?Advisory = switch (summary) {
        .advisory => |a| a,
        else => null, // contradiction / none → degrade
    };
    const el = elect(advisory, .{ .readiness = .available, .resets_at_s = 9999 }, 0);
    try testing.expectEqual(Readiness.available, el.readiness);
    try testing.expectEqual(Provenance.proven, el.provenance);
}

test "summarizeModel: conservative fold across windows, account rows apply" {
    var rows = [_]Row{
        makeRow(.model, "claude-opus-4", .five_hour, .{ .utilization = 0.2 }, 1000),
        makeRow(.model, "claude-opus-4", .seven_day, .{ .remaining = 0 }, 5000), // exhausted
        makeRow(.account, "", .five_hour, .{ .utilization = 0.3 }, 1200),
    };
    const s = summarizeModel(&rows, "claude-opus-4", 0);
    switch (s) {
        .advisory => |a| {
            try testing.expectEqual(Readiness.exhausted, a.readiness); // any spent window → exhausted
            try testing.expectEqual(@as(i64, 5000), a.resets_at_s); // frees at latest exhausted reset
        },
        else => return error.TestUnexpectedResult,
    }

    // A model with no applicable model-scoped row still sees account-wide rows.
    const other = summarizeModel(&rows, "claude-haiku-4", 0);
    switch (other) {
        .advisory => |a| try testing.expectEqual(Readiness.available, a.readiness),
        else => return error.TestUnexpectedResult,
    }
}

test "mergeSameKey is commutative and idempotent (CRDT spirit)" {
    const a = makeRow(.model, "claude-opus-4", .five_hour, .{ .utilization = 0.2 }, 1000);
    const b = makeRow(.model, "claude-opus-4", .five_hour, .{ .utilization = 1.0 }, 900);
    try testing.expect(rowKeyEqual(a, b));

    const ab = mergeSameKey(a, b);
    const ba = mergeSameKey(b, a);
    try testing.expectEqual(rowReadiness(ab), rowReadiness(ba));
    try testing.expectEqual(ab.resets_at_s, ba.resets_at_s);
    try testing.expectEqual(ab.usage.utilization, ba.usage.utilization);
    // Disagreeing readiness → conservative (exhausted) wins, regardless of order.
    try testing.expectEqual(Readiness.exhausted, rowReadiness(ab));

    // Idempotent.
    try testing.expectEqual(rowReadiness(a), rowReadiness(mergeSameKey(a, a)));
    try testing.expectEqual(a.resets_at_s, mergeSameKey(a, a).resets_at_s);

    // Same readiness → later horizon wins, still commutative.
    const c = makeRow(.account, "", .five_hour, .{ .utilization = 0.1 }, 3000);
    const d = makeRow(.account, "", .five_hour, .{ .utilization = 0.4 }, 5000);
    try testing.expectEqual(mergeSameKey(c, d).resets_at_s, mergeSameKey(d, c).resets_at_s);
    try testing.expectEqual(@as(i64, 5000), mergeSameKey(c, d).resets_at_s);
}

test "property fuzz: malformed JSON never crashes, always a typed refusal" {
    var prng = std.Random.DefaultPrng.init(0xA5A5_1234_2400);
    const rand = prng.random();
    const alphabet = "{}[]\":,abc0123 \tnulltrue.-e/\\";
    var buf: [128]u8 = undefined;
    var rows: [MAX_ROWS]Row = undefined;
    var excl: [MAX_ROWS]ExclusionReason = undefined;

    var iter: usize = 0;
    while (iter < 4000) : (iter += 1) {
        const len = rand.intRangeAtMost(usize, 0, buf.len);
        for (buf[0..len]) |*ch| ch.* = alphabet[rand.intRangeLessThan(usize, 0, alphabet.len)];
        const p = parse(buf[0..len], &rows, &excl);
        // The only guarantees: no crash, and a typed outcome. Either a kill with a
        // fingerprint, or a normal parse whose rows are all well-formed.
        if (p.killed) {
            try testing.expect(p.fingerprint != null);
        } else {
            for (p.rows) |r| {
                try testing.expect(r.resets_at_s > 0);
                if (r.scope == .model) try testing.expect(r.model_len > 0);
                switch (r.usage) {
                    .utilization => |u| try testing.expect(u >= 0.0 and u <= 1.0),
                    .remaining => {},
                }
            }
        }
    }
}

// Test helper: build a normalized Row directly (bypassing the parser) for the
// fold/precedence tests. Not part of the public surface.
fn makeRow(scope: Scope, model_id: []const u8, window: Window, usage: Usage, resets_at_s: i64) Row {
    var r = Row{ .scope = scope, .window = window, .usage = usage, .resets_at_s = resets_at_s };
    if (model_id.len > 0) {
        @memcpy(r.model_buf[0..model_id.len], model_id);
        r.model_len = @intCast(model_id.len);
    }
    return r;
}
