# Model-Class Quota-Granularity Keepalive across n accounts × m model-classes

> **SUPERSEDED 2026-07-11; DO NOT EXECUTE.** This file is historical input,
> not active design authority. Binding invariants moved to
> `docs/plans/oauth-mux-v0.2-full-broker-foss-program-2026-07-11.md` and
> `docs/security/omux-v0.2-threat-model-2026-07-11.md`. It is pending deletion
> under the v0.2 deletion ledger; Git is the archive. Preserve cited immutable
> evidence and shipped release history.
## TIN-2400 — synthesized architecture (judge + synthesizer output)

> **Status: design of record — NOT YET IMPLEMENTED.** Tracking: Linear TIN-2400 (parent) ·
> TIN-2407 (P0 enabler, July-safe) · GitHub issue #436. This is the working theory and
> phased plan; no code from it has landed. Credential keepalive (shipped) ≠ model-quota
> keepalive (this design). Provenance: 4-lens architecture workflow (algebraic-FP /
> complexity / zero-interaction / observation-TOS) → judge synthesis → adversarial verify
> (SOUND_WITH_FIXES), session 9925b2e2, 2026-07-03. Do not cite any part of this as
> implemented until a phase PR lands with committed evidence.

*Spine: Lens A (pure QuotaBucket algebra + event-log fold). Grafts: Lens B (data structures + defended Big-O), Lens C (autodiscovery + zero-config defaults), Lens D (observation taxonomy + honesty boundary). All repo citations at `origin/main @ 1767391`. This is a **design artifact** — no implementation is proposed for July; see §6.*

---

## 1. Honest answer to the operator's question

**"Do we have the granularity and algorithmic ability to keep alive model specifics across n accounts?"**

**Partly — the granularity substrate exists; the algorithm, the Claude evidence, and the scheduling are not built; and one framing in the question is a category error.** The route/health key is already `provider:account#capability` (`health.zig:87` `capabilityKey`, split by `parseHealthKey` health.zig:94) — an **open string**, so `#capability` already *is* the model-class dimension, and the durable `HealthStore` JSON (**version 2**, health.zig:534) already persists a per-`#capability` `window_resets_at`/`usage_pct`/`exhausted_at` row (`LivenessEntry`, health.zig:563-577, fields at 572-574) with **zero schema change needed**. For **Codex** this granularity is live: `codex-max` and `codex-mini` are declared capabilities each with their own quota clock, fed by the managed wire proxy → `classifyHttp` (pure) → durable per-capability rows, and consumed by the merged TIN-1811/1812 selector (`muxDecision`, health.zig:947). **What is missing:** (a) **Claude has no model capabilities** — `claude_capabilities` declares exactly one, `#auth-status` (provider_schema.zig:328), and `claude_failure_rules` has **no Claude-specific 429/quota/tier rule** (provider_schema.zig:306). *(Precision: `classifyHttp`'s generic 429/403 arms — provider_schema.zig:1032-1060 — are provider-agnostic and **would** classify a Claude 429→quota/rate-limited and 403→tier_insufficient today; the gap is therefore not the classification logic but the missing evidence SOURCE feeding it and the unvalidated Codex-derived 3600s threshold + header names, per (b).)* (b) **Claude has no quota-evidence source** — there is no Claude wire proxy, and the `x-ratelimit-*` header names in `claude_def.rate_limits` (provider_schema.zig:806-807) are almost certainly wrong for Anthropic and have **never been exercised**; (c) **scheduling is quota-blind** — the warm loop (`warm_scheduler.zig`) refreshes on credential expiry only (`refreshDueAtMs` reads only `expires_at_ms`/`last_refresh_ms`/`refresh_percent`/`min_lead_ms`), with no quota/window/capability term; (d) **selection is capability-blind** — `elect` (account_pool.zig:229) discards its `capability` argument (`_ = capability;`, account_pool.zig:236) and never reads the health store, so there is no spread policy at all (prompt 41: "a genuine gap"). **The category error:** *there is no such thing as per-model token refresh.* A credential (OAuth token) is per **account/identity** — one refresh warms every model class that account can serve; there is no per-model credential. Quota windows reset on the **provider's own clock** regardless of anything we do. So "keep model specifics alive" can only ever mean **per-model *routing readiness*** — re-observe eligibility and route at the instant a window resets — never per-model credential keepalive and never manufacturing capacity. **Credential keepalive ≠ model-quota keepalive**, and this design keeps that boundary structural, not merely documented (§3.5, §6).

---

## 2. Layered truth table — what exists vs. gap, by layer × provider

| Layer | Codex | Claude |
|---|---|---|
| **1. Token / credential refresh** (per **account**, spend-free) | ✅ EXISTS — warm loop `refreshDueAtMs`/`nextWakeMs`/`tick` (`warm_scheduler.zig`), key `provider:account`, ~75% lifetime. Account-scoped, **correctly not per-model**. | ✅ EXISTS — same warm loop; Claude creds in keychain, per-account. Account-scoped. *(This is the layer that actually works today and must never be blocked by anything below.)* |
| **2. Route / health data model** (per **model-class**) | ✅ EXISTS — `#capability` open string; `codex-max`/`codex-mini` declared (provider_schema.zig codex_capabilities); persisted per-capability `LivenessEntry` v2 (health.zig:563-577). | ⚠️ PARTIAL — key *accepts* `#opus`/`#fable`/`#sonnet` with zero type change, but **only `#auth-status` is declared** (provider_schema.zig:328). GAP = declare model capabilities. |
| **3. Quota observation** (passive, no-spend) | ✅ EXISTS (with one refinement gap) — managed wire proxy classifies 200/401/429/5xx → `classifyHttp` (3600s split, pure) → durable rows → `quota/observe` RPC (methods.zig:410, dispatch :51). **Refinement gap:** capability is a **static per-session field** (`capability: ?[]const u8`, wire_proxy.zig:354, "Borrowed from managed launch options"), consumed as `capability orelse self.capability` when writing durable route state (wire_proxy.zig:948, :962); the request `model` is **not parsed** anywhere in the proxy (grep for a request-body `model` field in wire_proxy.zig returns nothing → per-request model→class attribution absent). *(The `"codex-mini"` at wire_proxy.zig:2806 is test scaffolding, not a production hardcode — it stands in for the launch-option tag.)* | ❌ GAP (the real one) — **no wire proxy, no 429/quota rule** (provider_schema.zig:306). Placeholder `x-ratelimit-*` headers (provider_schema.zig:806-807) never exercised. Only zero-spend channels *possible*: response rate-limit headers on the operator's own traffic, 429/403 bodies, served-model echo on 200s. All **net-new adapter work**, unproven until a committed evidence fixture. |
| **4. Quota-aware scheduling** (routing-readiness wake, not refresh) | ❌ GAP — warm scheduler has no quota term; selector waits (TIN-1812) but **nothing schedules a re-observe at `window_resets_at`**. | ❌ GAP — same; and no signal to schedule against yet. |
| **5. Spread / balance selection** (per model-class) | ❌ GAP — `elect` discards `capability` (account_pool.zig:236; :235 discards `profile`), first-fit in insertion order over `self.accounts.items`, reads only the pre-computed `a.availability`/`a.selectable` summary fields, never `HealthStore`. No spread of any kind. | ❌ GAP — same `elect`; additionally capability-blind because Claude has no capabilities declared. |

**Reading of the table:** the model-class dimension is *real and persisted* at layer 2 and *live* at layer 3 for Codex. Everything from layer 3-Claude down, and all of layers 4-5, is the TIN-2400 surface. The two-clock separation (layer 1 per-account vs. layers 2-5 per-model) is the spine of the whole design.

---

## 3. The chosen architecture

**Spine (Lens A):** the domain is one **pure algebra** — an append-only **event log**, a **total reducer** that folds it into per-`(identity × model-class)` **quota buckets**, and two pure queries over those buckets: a **schedule** (`now → next wake`) and a **selection** (`request → route`). The only effects are *observe-in* (world → event) and *act-out* (refresh a credential / hand a route to the harness / persist a snapshot). Between them: no clock read, no allocation, no network, no global mutation. This makes the honesty boundary **unrepresentable to violate** — credential-alive and model-quota-alive are two **disjoint folds over one log** that share no field.

### 3.0 The two-clock invariant (the spine's spine)

Every account carries two independent clocks; conflating them is the bug TIN-2400 exists to prevent.

| Clock | Granularity | Drives | Effect it authorizes | Fed by |
|---|---|---|---|---|
| **Credential-expiry** | `provider:account` | warm loop (`warm_scheduler.zig`, unchanged) | token refresh (spend-free, account-level) | `Refreshed` events |
| **Quota-window** | `provider:account#model` | routing / wait / degrade | **nothing** — routing readiness only | `Observed` events |

The credential fold reads only `Refreshed`; the quota fold reads only `Observed`. They never cross. This *is* TIN-2400 acceptance #3 ("warm loop keeps refreshing while model-quota health only affects routing") and #5 (the honesty boundary), expressed structurally: the warm scheduler's input type has no quota field, and the pure module that computes quota wakes cannot emit a refresh. A property test (§3.7 P5) fuzzes any quota-event sequence and asserts credential wake times are bit-identical.

### 3.1 Keys, identity canonicalization, and interning (Lens A key + Lens B interning)

The bucket key **is** the existing route key. Two semantic choices:

1. **`account` canonicalizes to the stable identity hash** (`sha256_12hex` of Claude `accountUuid` / Codex identity — the project's existing TIN-1822 dedupe key), **never a config label**. Load-bearing for *correctness*: two aliases of one subscription share **one real quota pool**; folding them into two buckets double-counts headroom and drains a single account thinking it has two. Canonicalizing collapses aliases to **one bucket**.
2. **`#capability` is the model class** (`opus`/`fable`/`sonnet`/`haiku`; `codex-max`/`codex-mini`) — an open string, discovered not declared (§3.3).

For the hot path we **intern** the string key once, at the effect boundary, into a packed `u64` (Lens B) so `observe`/`select`/`next-wake` touch only integers — string hashing/comparison is paid once per identity/class, never per event.

```zig
// ── Interned identity of a bucket. Total order == (identity, class) lexicographic. ──
const IdentityIdx = u16;              // dense index into interned identities[]
const ClassIdx    = u16;              // dense index into per-provider class table[]
pub const BucketId = packed struct(u64) {
    provider: u8,      // small enum: claude=0, codex=1, …
    identity: IdentityIdx,
    class:    ClassIdx,
    window:   u8 = 0,  // 0 = the class's primary window; >0 = secondary (weekly cap) — Claude publishes 2
    _pad:     u16 = 0,
};

/// Borrowed slices; the engine never owns/frees them (warm_scheduler discipline).
pub const RouteKey = struct {
    provider: []const u8,   // "claude" | "codex"
    account:  []const u8,   // CANONICAL sha256_12hex identity, NOT the alias
    model:    []const u8,   // the #capability slug
    /// Renders "provider:account#model" — byte-identical to health.capabilityKey,
    /// so persisted HealthStore v2 rows and the log agree with zero translation.
    pub fn render(self: RouteKey) health.KeyBuf { return health.capabilityKey(self.provider, self.account, self.model); }
    /// Strip #model → the credential axis. The JOIN to the warm loop.
    pub fn accountKey(self: RouteKey) health.KeyBuf { return health.accountKey(self.provider, self.account); }
};
```

### 3.2 The bucket value — a total sum type + first-class evidence provenance (Lens A + Lens D)

Lens A's crux: make illegal states unrepresentable. The repo's `Availability.QuotaInfo.window_resets_at` is **nullable** — a "exhausted but no idea when it recovers" hazard. The algebra forbids it: the `quota_exhausted` arm carries a **non-optional** `resets_at`, supplied at reduce time by `deriveResetsAt`. Lens D's contribution: every bucket carries **provenance** (`source`, `confidence`, `attribution`) so the honesty boundary is a *field*, not a footnote, and so the fold's join order is well-defined.

```zig
// ── Observation taxonomy (Lens D): exactly the classes TIN-2400 names, each a routing state. ──
pub const BucketStatus = union(enum) {
    fresh,                                          // never observed → optimistic available (zero-config)
    available:       struct { since: i64 },
    rate_limited:    struct { since: i64, retry_after_s: u32 },        // burst throttle (retry_after ≤ 3600s)
    quota_exhausted: struct { since: i64, resets_at: i64 },            // usage window spent; resets_at REQUIRED
    tier_blocked:    struct { since: i64 },                            // class not on plan — ROUTING-permanent, never credential-dead
    plan_gated:      struct { since: i64, resets_at: i64, reason: types.DegradedReason }, // plan-cycle gate (weekly cap)
};

pub const EvidenceSource = enum { response_header, error_body, status_code, response_model, local_probe, none };
pub const Confidence     = enum { assumed, inferred, proven };        // a lattice: assumed < inferred < proven
pub const Attribution    = enum { from_response_model, from_request_model, static_session_tag, declared_default, unknown };
pub const DiscoverySource = enum { builtin_prior, observed_traffic, config_declared };

pub const Evidence = struct { observed_at: i64, source: EvidenceSource, confidence: Confidence, attribution: Attribution };

pub const WindowSpec = struct {
    length_ms: i64,                                 // Opus 5h rolling; Fable different; codex per-route
    cadence:   enum { rolling, fixed_daily, fixed_weekly, plan_cycle, unknown } = .unknown,
    provenance: DiscoverySource = .builtin_prior,
};

/// One (identity × model-class × window) bucket. POD: no owned slices → snapshot-friendly,
/// property-testable, stored contiguously in a flat table (Lens B, ~64 B / one cache line).
pub const QuotaBucket = struct {
    id:     BucketId,
    route:  RouteKey,                               // borrowed strings for rendering/persist
    status: BucketStatus = .fresh,
    evidence: Evidence,                             // provenance of `status`
    usage_pct: ?u8 = null,                          // headroom, ONLY when a header proved it (never a decremented counter)
    window: ?WindowSpec = null,                     // learned or declared prior
    last_selected_at: i64 = 0,                      // fairness fold (§4); replayable from Selected events
    epoch: u32 = 0,                                 // generation counter for lazy heap deletion (Lens B)
};
```

Design note (Lens D honesty): `usage_pct` is **only ever the last observed value**, never a running `remaining--` budget. Inventing a decrementing budget the provider never handed us is both a fabrication and a step toward limit-modeling that reads as evasion. `unobserved`/`fresh` ≠ `available`-with-headroom — the selector treats a never-seen route as *eligible but unweighted* (§4).

### 3.3 Autodiscovery — buckets self-populate, classes discovered not declared (Lens C)

A model class exists in the surface because it was **observed on the wire**, not because someone enumerated it. `normalizeModelClass` is pure and total: a tiny shipped prior table coalesces known aliases and pretty-labels them; **an unknown model string still yields a bucket** via deterministic slug derivation — so `fable` self-populates the first time it is seen, with `confidence=assumed`, `window=unknown`.

```zig
/// Pure. Prior table is DATA (courtesy labels + known windows), never a gate. Unknowns bypass it.
pub fn normalizeModelClass(provider: []const u8, raw: []const u8) struct {
    slug: []const u8, label: []const u8, window_kind: WindowSpec, matched_prior: bool,
} { … }   // prefix-match a fixed tiny table; else discoveredSlug(raw) (lowercased, version suffix trimmed)

/// Bounded per-provider set with LRU/TTL aging — pure reducers. Cap guards adversarial churn (Lens B/C).
pub const Catalog = struct {
    classes: [MAX]ModelClass = undefined, len: usize = 0, pub const MAX = 64;
    pub fn observe(self: Catalog, id, src: DiscoverySource, now: i64) Catalog { … } // insert / bump last_seen / upgrade source precedence
    pub fn age(self: Catalog, now: i64, ttl_ms: i64) Catalog { … }                  // reap unseen classes; truth persists in HealthStore, revives on re-observe
};
```

Precedence for coalescing / the honesty SRC column: `config_declared` > `observed_traffic` > `builtin_prior`. Observation **upgrades a prior in place** (same slug); it never forks a second bucket. Config (`CapabilityDefinition.quota`, optional) can only make the surface *nicer/more precise* — never the thing that makes keepalive *work*.

### 3.4 The reducer — a confidence-lattice LWW fold (Lens A CRDT + Lens D provenance)

The per-route status is the **join** of observations, structured as a **two-tier lattice** so the fold is a genuine (order-independent, associative, idempotent) merge:

- **Across confidence tiers** the higher tier wins unconditionally *while the current window is live* — `proven` > `inferred` > `assumed` — so a weak guess can never downgrade a live proven window. Tier-max is commutative → order-independent.
- **Within one confidence tier** adopt by a **total order** `(at, sourceRank, attributionRank, class-slug)`, not `at` alone. The extra keys are the deterministic tiebreaker that makes two observations sharing an identical `at` fold to the same result under any permutation (bare `at` is only a *partial* order and would break property P2).
- **When the current window has already expired** (`ev.at ≥ resets_at`) any observation — including a weak `available` — is adopted; that is exactly how a route reopens at its reset instant (§3.5).

Net rule: **adopt iff strictly-higher confidence (window live), OR equal confidence and strictly-later in the total order, OR the current window has already expired.** The critical honesty direction is the first clause read backwards: while a window is LIVE, a *strictly-weaker* signal — regardless of how recent — may contribute window learning but may **not** flip the status to `available`. This is what stops a stray `assumed`-confidence 200 from reopening a `proven`-exhausted route before its `resets_at`.

```zig
// ── PURE. Total. No clock read (event carries `at`), no alloc, no I/O. state' = reduce(state, event). ──
pub const Event = union(enum) { observed: Observed, refreshed: Refreshed, selected: Selected };
pub const Observed = struct { route: RouteKey, at: i64, source: EvidenceSource, attribution: Attribution, signal: QuotaSignal };
pub const QuotaSignal = union(enum) {                 // mirror of classifyHttp's quota-relevant arms
    quota_ok:        struct { usage_pct: ?u8 = null, resets_at: ?i64 = null },
    rate_limited:    struct { retry_after_s: u32 },   // ≤ threshold → burst
    quota_exhausted: struct { stated_retry_s: ?u32 = null, resets_at: ?i64 = null }, // > threshold → window
    tier_insufficient,
    provider_plan:   struct { reason: types.DegradedReason, resets_at: ?i64 = null },
};

/// Supplies the REQUIRED reset instant so quota_exhausted can never hold a null.
/// Precedence: provider-stated absolute resets_at > stated retry_after > learned window > declared prior > default floor.
pub fn deriveResetsAt(at: i64, stated: ?i64, retry_s: ?u32, prior: ?WindowSpec) i64 {
    if (stated) |t| return t;                         // provider-authoritative absolute (preferred; clock-skew-safe)
    if (retry_s) |s| return at +| (@as(i64, s) *| 1000);
    if (prior) |w| return at +| w.length_ms;
    return at +| DEFAULT_WINDOW_MS;                    // conservative floor (codex 7d), flagged low-confidence → re-probe sooner
}

pub fn reduceBucket(b: QuotaBucket, ev: Observed, prior: ?WindowSpec, threshold_s: u32) QuotaBucket {
    const inc = capBy(confidenceOf(ev.source), ev.attribution); // proven/inferred/assumed after attribution cap
    const live = isWindowLive(b, ev.at);              // ev.at < current resets_at (window still spent)?
    // (1) Honesty guard — window live AND incoming strictly weaker ⇒ NEVER downgrade to available,
    //     regardless of recency. Absorb any window learning, keep the stronger live status.
    if (live and @intFromEnum(inc) < @intFromEnum(b.evidence.confidence))
        return absorbWindowLearningOnly(b, ev);
    // (2) Same-tier determinism — adopt only if strictly-later in the TOTAL order
    //     (at, sourceRank, attributionRank, class-slug); else keep current. Guarantees
    //     fold(π(log)) is permutation-invariant even when two events share `at`. (Cross-tier
    //     upward moves — inc > current — fall straight through to the overwrite below.)
    if (@intFromEnum(inc) == @intFromEnum(b.evidence.confidence) and !laterInTotalOrder(ev, b))
        return absorbWindowLearningOnly(b, ev);
    var nb = b; nb.epoch +%= 1;
    nb.evidence = .{ .observed_at = ev.at, .source = ev.source, .confidence = capBy(inc, ev.attribution), .attribution = ev.attribution };
    switch (ev.signal) {
        .quota_ok => |o| { nb.status = .{ .available = .{ .since = ev.at } }; nb.usage_pct = o.usage_pct; nb.window = learn(b, ev, prior); },
        .rate_limited => |r| nb.status = if (r.retry_after_s > threshold_s)   // codex 3600s split, validated per-provider (Lens D)
            .{ .quota_exhausted = .{ .since = ev.at, .resets_at = deriveResetsAt(ev.at, null, r.retry_after_s, learnedOr(b, prior)) } }
            else .{ .rate_limited = .{ .since = ev.at, .retry_after_s = r.retry_after_s } },
        .quota_exhausted => |q| nb.status = .{ .quota_exhausted = .{ .since = ev.at, .resets_at = deriveResetsAt(ev.at, q.resets_at, q.stated_retry_s, learnedOr(b, prior)) } },
        .tier_insufficient => nb.status = .{ .tier_blocked = .{ .since = ev.at } },
        .provider_plan => |p| nb.status = .{ .plan_gated = .{ .since = ev.at, .resets_at = deriveResetsAt(ev.at, p.resets_at, null, learnedOr(b, prior)), .reason = p.reason } },
    }
    return nb;
}
```

Design note (Lens D taxonomy discipline): a 429 with an unparseable body classifies to `rate_limited` (the **weaker, safer** class), never upgraded to `quota_exhausted` on a guess. Under-claiming costs a short cooldown; over-claiming strands a route for hours. The classifier reuses the repo's pure `classifyHttp` (provider_schema.zig) and its `quota_threshold_seconds` (default 3600) split — but the threshold must be **Claude-validated by fixture**, not assumed from Codex.

### 3.5 Availability is a *query*, not a stored field — recovery needs zero scheduled writes (Lens A)

The single most important result. Generalizing the repo's existing `recoverExpiredTransientHealth(health, now)` (health.zig:182, which mutates only in-memory liveness, nothing durable): **a route comes back online purely because `now ≥ resets_at`, with no event, no timer, no write.**

```zig
pub const EffectiveStatus = enum { available, waiting, tier_blocked, plan_gated };
/// Pure (bucket, now) → status. Referentially transparent. The ONLY thing routing consults.
pub fn effectiveStatus(b: QuotaBucket, now: i64) EffectiveStatus {
    return switch (b.status) {
        .fresh, .available => .available,                                    // optimistic out-of-box
        .rate_limited => |rl| if (now >= rl.since +| ms(rl.retry_after_s)) .available else .waiting,
        .quota_exhausted => |q| if (now >= q.resets_at) .available else .waiting,   // monotone step, no oscillation
        .plan_gated => |p| if (now >= p.resets_at) .available else .plan_gated,
        .tier_blocked => .tier_blocked,                                      // won't self-heal; route away
    };
}
```

Consequence: **the quota-revalidation schedule (§3.6) is not required for correctness** — it exists only to proactively re-observe and to emit an operator-visible "route back online" event. This is the honest realization of "keep model specifics alive": you don't *bring* a route back — it *is* back the instant `now` crosses `resets_at`, everywhere the function is evaluated.

**Index vs. truth — the one subtlety that keeps "missed wake harmless" true.** `effectiveStatus` is the *truth* and is a pure query. The spread ring (§4) is a derived *index*, and §4 removes a bucket from its ring when an observation exhausts it. For the "a missed quota wake cannot cause wrong routing" property to actually hold, `elect` must not treat ring-absence as authority: when a capability ring is empty or every member is `waiting`, `elect` falls back to the deadline-heap min for that capability and re-evaluates `effectiveStatus(min_bucket, now)`. A bucket whose `resets_at` has already passed then presents an in-the-past deadline and is **lazily re-admitted at query time** — no wake required. So the wake is a pure optimization (proactive re-probe + operator event); its absence only delays the re-probe, never strands an available route. This lazy-readmit path is O(log N) (one heap peek + one ring insert), preserving the §3.7 bounds.

### 3.6 Scheduling — two disjoint deadline producers, one heap (Lens A separation + Lens B heap)

The credential schedule is **`warm_scheduler.zig`, unchanged** (the exemplar pure core; its `nextWakeMs` is today an O(n) linear scan over accounts, warm_scheduler.zig:97). We add a **parallel, disjoint** quota-revalidation schedule and combine at the daemon wake by `min`. The quota side gets its own new **4-ary min-heap with epoch-tombstone lazy deletion** (Lens B) over *buckets*, so the quota next-wake is O(1) peek and an update is O(log N). Note this heap is **additive** — it is a new structure over new bucket state; it does **not** replace the existing credential account scan, which stays O(n) until separately heap-upgraded (§3.7). The daemon's combined next-wake is therefore `min(O(n) credential scan, O(1) quota peek)` = O(n) today, dominated by the still-linear credential term — but the quota layer alone is event-driven (wake at the exact bucket deadline, not on a poll).

```zig
/// PURE. Earliest instant any WAITING route crosses reset — a RE-OBSERVE wake, never a refresh, never a spend.
pub fn nextQuotaWakeMs(buckets: []const QuotaBucket, now: i64) ?i64 { … }   // O(1) via heap root; O(log N) to maintain

/// The daemon's next wake. Two disjoint terms; the ACTIONS differ by kind.
pub fn nextWakeMs(accts: []const warm.Account, buckets: []const QuotaBucket, pol: warm.Policy, now: i64) ?i64 {
    const cred  = warm.nextWakeMs(accts, pol);      // → RefreshFn  (credential, spend-free, account-level)
    const quota = nextQuotaWakeMs(buckets, now);    // → pure recompute + optional zero-spend re-observe; NEVER RefreshFn
    return minOpt(cred, quota);
}
```

The honesty boundary is enforced by **which seam a wake dispatches to**: a credential wake calls `RefreshFn`; a quota wake calls the pure recompute (flip eligibility, re-render status) — it can never reach `RefreshFn`. We deliberately keep the credential timer **per-account** (not lifted to `#capability`): one token warms all of an account's model classes, so the warm loop stays **O(n)** and only the quota fold is O(n·m). That separation is a direct dividend of §3.0.

Thundering-herd guard (Lens B): shared reset boundaries (e.g. all weekly caps at 00:00 UTC) get a deterministic per-bucket `stagger(id)` added to the reset wake — the same technique as this branch's TIN-1825 warm-pool stagger — spreading the N re-observations across a small span. Pure and reproducible.

### 3.7 Big-O of every hot operation (defended; no hidden O(n²))

State size: **N = n·m·w** buckets (w = windows/class, tiny; for a per-operator daemon N is tens, capped ~256). The hot **numeric** table holds one `BucketId` (u64) + timestamps + `epoch` per bucket (~32 B, cache-friendly); the borrowed `RouteKey` strings and `WindowSpec`/`Evidence` live in a side table indexed by `BucketId` and are touched only at render/persist time, not on the hot path. (The full `QuotaBucket` struct in §3.2 — which embeds three `[]const u8` slices plus the status/evidence/window fields — is ~144 B if stored inline; splitting the numeric hot fields from the string side-table is what keeps the hot row within a cache line.) Three views over the numeric table: deadline heap, per-capability spread heaps, interned index.

| Hot operation | Structure | Complexity | Note |
|---|---|---|---|
| **observe** (fold one event) | intern lookup O(key-len), amortized O(1) in N + reducer O(1) + heap re-push O(log N) + ring reposition O(log r) | **O(log N)** | one bucket touched; never rescan |
| **next-wake (quota term)** | 4-ary min-heap root | **O(1)** peek, **O(log N)** update | new additive heap over buckets; the credential term stays the O(n) `warm.nextWakeMs` account scan (next row) |
| **select under spread** | per-capability spread heap | **O(log r)**, r ≤ n live in that ring | replaces O(n) capability-blind first-fit |
| effectiveStatus (recovery) | pure fn | **O(1)** | query-time; zero scheduled writes |
| credential wake | `warm.nextWakeMs` | **O(n)** today | orthogonal; heap-upgradeable identically |
| cold build at start | fold HealthStore rows, Floyd heapify | **O(N)** build; one-time | dominated by the one HealthStore parse |
| snapshot / truncate log | fold prefix → HealthStore v2 | **O(k)** truncated, amortized | resumable fold ⇒ lossless |

**No cross-bucket computation anywhere in the hot path** ⇒ no O(n²). The one all-pairs temptation (recompute global spread per observation) is avoided by making the spread key **event-driven** (§4): it changes only on selection/observation of *that* bucket. The lazy-deletion heap uses `epoch` tombstones (bump `bucket.epoch`, push a fresh entry; skip stale entries on pop) capped by a "compact when `len > 2N`" invariant → O(N) space, amortized O(1) push. Steady-state memory ≈ 12 KB at N≈64 (numeric hot table + string side-table + three heap views); ~64 KB ceiling at N=256 — still trivially small, and **zero allocation in the steady hot path**.

### 3.8 Seam map — what is pure, where the two effects live

```
   ┌────────────────────── EFFECT: observe-in (passive, no-spend) ──────────────────────┐
   │ codex wire_proxy (+per-req model attribution) │ claude passive header/body reader │ (budgeted zero-spend probe, OFF by default) │
   └───────────────┬───────────────────────────────┬───────────────────────────────────┘
                   │  classifyHttp / normalizeModelClass (PURE, existing/new)
                   ▼
        append Event{observed|refreshed|selected} ──► IMMUTABLE LOG ──► snapshot ⇄ HealthStore v2 (EFFECT: file)
                   │
   ╔═══════════════▼═══════════════ PURE CORE (no clock, no alloc, no net) ═══════════════╗
   ║ reduceBucket (lattice+LWW fold) │ effectiveStatus(b,now) │ deriveResetsAt │ Catalog  ║
   ║ nextQuotaWakeMs(buckets,now)    │ selectRoute (§4)       │ warm.* (unchanged, disjoint) ║
   ╚═══════════════╤════════════════════════════════╤════════════════════════════════════╝
                   │ Decision.route                    │ credential wake
                   ▼                                   ▼
            hand to harness (EFFECT: act-out)      RefreshFn (EFFECT: credential refresh — spend-free, account-level)
```

**The impurity to invert first (REPO TRUTH §6):** the classification path reads `std.time.timestamp()` *internally* at two sites — `recordHttpClassification` (health.zig:862) and the `quota/observe` RPC handler `quotaObserve` (methods.zig:410, clock read at methods.zig:429); the selector `muxDecision` (health.zig:949) reads it too. TIN-2400's first structural increment makes events carry `at` and queries take `now` — turning those impure islands into the pure reducer above, exactly as `warm_scheduler` already models.

### Property-based test surface (std-only fuzzable — the invariants that must hold over ANY event sequence)

1. **Replay/snapshot idempotence:** `fold(log) == fold(snapshot(fold(log[0..k])) ++ log[k..])`.
2. **Order-independence (CRDT law):** `fold(log) == fold(π(log))` for any permutation π — including logs with **duplicate timestamps**, which is why the within-tier tiebreaker is the full total order `(at, sourceRank, attributionRank, class-slug)` (§3.4) and not `at` alone. Fuzz must include equal-`at` collisions.
3. **Quota-never-kills-credential:** no `QuotaSignal` sequence yields `CredentialLiveness.dead` (disjoint folds).
4. **Recovery is a monotone step, no oscillation:** `effectiveStatus` is `waiting` ∀ t<resets_at, `available` ∀ t≥resets_at.
5. **Warm-loop independence:** injecting any quota-event sequence leaves every credential wake bit-identical (encodes acceptance #3).
6. **Spread fairness + no starvation:** selection counts converge to fair share; every eligible route served within one round.
7. **No-spend/effect-freedom:** the pure modules import no `RefreshFn`/net/clock seam (compile-time structural + fuzz assertion).
8. **Total/saturating:** fuzz `at`/`now`/`resets_at`/`retry_after` at i64/u32 extremes → no panic, no overflow.

---

## 4. The spread / balance algorithm — recommended first increment

**Recommendation: least-recently-selected (LRS) *within a capability ring*, keyed by `last_selected_at` — a pure fold, dressed as an O(log r) heap.**

Given the three candidates (round-robin-by-cursor / **LRS** / remaining-window-weighted), LRS is the right *first* increment for four reasons that dominate under the operator's binding constraints:

1. **It is a pure fold (constraint 1, FP).** `last_selected_at` is fully derivable by replaying `Selected` events — referentially transparent, replayable, property-testable. Round-robin-by-cursor needs mutable cursor state (less FP-clean); LRS keeps the "fairness is a fold, not a side effect" property of the spine.
2. **It needs zero signal (constraint 3, zero-config) and works for Claude on day one.** Remaining-window-weighted requires a **proven** `usage_pct` headroom signal that **does not exist for Claude** and would ship at `confidence=assumed` — a fabrication (Lens D forbids it). LRS spreads correctly with no observation at all: pick the eligible route in this capability least recently handed out. When no headroom is known, that *is* the honest spread.
3. **It is honest by construction (constraint 5, TOS).** LRS's only effect is reducing mid-session swap disruption by rotating the operator's own authorized routes — it never sums allowances, never pools, never maximizes throughput. There is no data structure representing combined capacity.
4. **It is the minimal seam that upgrades cleanly.** LRS is exactly round-robin when all weights are equal, and generalizes to remaining-window-weighted by swapping the heap key from `last_selected_at` to a virtual-finish/stride value once a *proven* headroom signal exists — no structural change.

**Mechanism & complexity.** Partition live routes into one min-heap per `(provider, capability)` ring, keyed by `last_selected_at`. Selection is split into a **pure query** and a **boundary apply**, so the "selection is a pure query" claim of the spine holds literally:

- `selectRoute` is a **pure read** over an immutable ring *view*: it filters to `effectiveStatus(b, now) == available` AND credential-not-dead (join to the credential fold) AND model matches (or an allowed TIN-1811 downgrade class), peeks the min `last_selected_at`, and returns both the `Decision` **and** the `Selected{route, at}` event to append. It mutates nothing.
- The **boundary** then applies the returned event: append `Selected` to the log and reposition that one key in its ring — **O(log r)**, r ≤ n.

Exhausted/tier-blocked routes are absent from the ring (removed on the observation that exhausted them); a route whose window has since reset is **lazily re-admitted at query time** via the §3.5 deadline-heap fallback, so `elect` neither scans dead candidates nor depends on a wake having fired. If all eligible routes are `waiting`, `selectRoute` returns `Decision.wait_until{earliest_reset}` (TIN-1812 wait-and-continue) — **never halt, never mark dead**. This replaces `elect`'s first-fit, capability-discarding O(n) scan (account_pool.zig:229-236) and joins it to `HealthStore` for the first time. TIN-1822 identity-dedupe rank + insertion order are the deterministic tiebreakers.

```zig
pub const Decision  = union(enum) { route: RouteKey, wait_until: i64, no_route };
pub const Selection = struct { decision: Decision, emit: ?Selected };  // `emit` applied at the boundary
/// PURE QUERY over an immutable view: reads only, returns the choice + the event to append.
/// Eligible = effectiveStatus(b,now)==available AND model matches AND credential not dead.
/// Among eligible: min last_selected_at (LRS). Ties: (dedupe rank, insertion order) → total order.
pub fn selectRoute(rings: SpreadView, cred: CredView, req: Request, now: i64) Selection { … }  // O(log r) read
```

**Follow-ups (noted, not first):** (a) **remaining-window-weighted** via smooth-WRR / stride scheduling (Lens A/B) — weight = observed headroom (`100 − usage_pct`), virtual-finish min-heap, proportional-fair within ±1 quantum — the moment a *proven* headroom signal exists (Codex `usage_pct` already qualifies; Claude only after the evidence dir). (b) **power-of-two-choices** as an O(1) escape hatch if N ever grows large (charter parks hosted/multi-tenant, so not now). Both are drop-in key swaps on the same ring.

---

## 5. Phased roadmap mapped to TIN-2400 acceptance criteria

TIN-2400's acceptance (per the scout): **#1** model families as capabilities with independent health/quota/reset; **#2** passive/no-spend classification into `quota_exhausted | rate_limited | tier_insufficient | provider_plan`; **#3** warm loop stays quota-blind, quota only affects routing/wait/degrade; **#4** the reset-window model (TIN-1824) + usage export (TIN-2062) gain the capability/model bucket field; **#5** honesty boundary — credential keepalive ≠ model-quota keepalive.

| Phase | Scope | Maps to | Honest evidence bar |
|---|---|---|---|
| **P0 — pure-core inversion** *(enabler, no behavior change)* | Invert the embedded `std.time.timestamp()` in `recordHttpClassification` (health.zig:862) and `quotaObserve` (methods.zig:429) → events carry `at`, queries take `now`. Extract `reduceBucket`/`effectiveStatus`/`deriveResetsAt` into `src/quota/bucket.zig` (pure). | Unlocks #1–#5 (makes the fold testable) | Unit-green **and** the 8 property tests (§3.7) pass. No production wire yet. |
| **P1 — minimal first PR: two Claude capabilities + passive classification + the proof fixture** | Declare `#opus`/`#sonnet`/`#haiku` `CapabilityDefinition`s (append-only, open string). Add the Claude passive-header/body classifier (`ProbeDefinition` → `recordCapabilityHttpStatusForProvider` → `classifyHttp`, no proxy). **Ship a redacted fixture proving two capabilities on one account carrying *different reset state* simultaneously** (e.g. `#fable` exhausted with resets_at=T, `#opus` available). Buckets self-populate (§3.3). | **#1**, **#2** | The fixture is the bar: a committed `test/evidence/quota-observation/` capture showing (a) real Anthropic rate-limit header names / 429 body, (b) two distinct `#capability` rows on one identity with divergent `window_resets_at`, (c) attribution from request/response `model`. Until it exists, classifiers ship at `confidence=assumed`, dashboard shows `unobserved`, claims stay "credential keepalive." |
| **P2 — quota-aware scheduling** | Add `nextQuotaWakeMs` as a disjoint term next to the untouched warm schedule; combine by `min` at the daemon wake (§3.6). Quota wake flips eligibility + re-observes; **never** calls `RefreshFn`. Add the 4-ary lazy-deletion min-heap; replace the O(n) `nextWakeMs` scan. | **#3** (structurally: two producers, disjoint effects) | Property test P5 (warm wakes bit-identical under any quota-event sequence). A soak showing a `#capability` returns to routing at its observed `resets_at` with no refresh and no spend. |
| **P3 — spread policy** | Join `elect` → capability rings; LRS selection (§4); stop discarding `capability` (account_pool.zig:236). First for **Codex** (signal exists), then Claude once P1 lands. | **#1** consumption; closes the acknowledged election gap (prompt 41) | Property tests P6 (fairness/no-starvation) + a replay showing spread across ≥2 live routes for one capability; TOS-framed as disruption reduction, not maximization. |
| **P4 — schema extension + export** | Add the capability/model bucket field to the TIN-1824 reset-window model and the TIN-2062 `oauth-mux.usage.v1` export (identity-keyed → identity+capability-keyed). Optional `CapabilityDefinition.quota` prior. | **#4** | TIN-1824 fixtures predict per-capability reset windows; TIN-2062 export round-trips the new key dimension; coye.ai consumer unaffected. |

**Minimal first PR = P1 (built on P0).** It is the smallest change that makes a *model-specific* claim honest: it proves — with a committed, redacted fixture — that one account holds two model-class buckets with independent reset state, classified from passive/no-spend evidence, with zero credential-path change.

---

## 6. Sequencing vs. org direction & tonight's dogfood

**This is an August (adapter-maturation, target 2026-08-31) design, not a July deliverable — and it does NOT block tonight's credential-keepalive dogfood.** Grounding (ledger item 12 + prompts 39/41):

- **July critical path is credential-keepalive *evidence*, not model-quota.** July live successors are TIN-2057 (warm-loop → golden soak), TIN-1813 (never-halt cross-cap drill, codex), TIN-1823/GH#176 (cassettes), GH#212=TIN-1824 (reset-window permutation residue). TIN-2400's two hard dependencies — TIN-1824 (reset model, Backlog) and TIN-2062 (export schema, Todo) — are both **cold**, and its Claude passive signal **does not exist today** (Claude = auth-status-only, synthetic-smoke harness). Creating that signal is net-new adapter work gated behind the parked Claude adapter maturation (TIN-1818/2078/1819, all Backlog), **not** behind the July soak.
- **TIN-2077 is explicitly not a July gate; reauth is queued behind July; ffi/federation are parked.** Nothing here changes that. This design is *adjacent to* GH#212/TIN-1824, not on the Level-3 July line.
- **Does not block the dogfood, by construction.** With nothing observed, every bucket is `fresh → available`, `nextQuotaWakeMs` returns `null`, and `nextWakeMs == warm.nextWakeMs` — the daemon is **byte-for-byte today's behavior**. The quota layer is purely additive and observation-gated; a fresh download watching credential keepalive sees zero interruption whether or not any quota channel ever lights up.

**Recommendation — split by signal dependency:**

- **July-parallelizable (low-risk, no new provider signal, de-risks the soak):** **P0 only** — the pure-core clock inversion + `src/quota/bucket.zig` extraction. It is a no-behavior-change refactor that makes the classification reducer property-testable and ensures the July credential-keepalive code is built with the `#capability` route-key, `Evidence`/`confidence`, and event-`at` shapes that won't need rework when model-buckets arrive. This is the "land the design's *shapes* now" move the scout recommends, and it is safe to land during July because it touches no routing behavior and no provider wire. (Optionally P3-for-Codex, since Codex's signal already exists — but that is genuinely new routing behavior and should not compete with the July soak for CI/attention; default it to August.)
- **Parked to August (adapter-maturation):** **P1–P4.** The Claude model-class capabilities, the passive Claude quota signal + evidence dir, quota-aware scheduling, spread policy, and the schema/export extension. All gated behind a committed evidence fixture proving the Anthropic channel.
- **Public-claim posture until the evidence dir exists:** **"credential keepalive, not model-quota keepalive."** The status surface renders `CRED` (proven) physically separate from per-model `STATE` (observed/best-effort), and Claude `STATE` reads `unobserved (no signal)` — the honesty boundary is *rendered*, not just documented.

**One-line landing plan:** land TIN-2400 as **doc + comment now**; land **P0** in July as a shape-only enabler; hold **P1–P4** for August behind the evidence fixture; keep the honest public claim at credential keepalive throughout.

---

## 7. Draft comment for TIN-2400 (returned as text — NOT posted)

> **Synthesized design — model-class quota-granularity across n accounts (design note, not an implementation commit).**
>
> **Answer to the posit:** the *granularity substrate* already exists — the route/health key is `provider:account#capability` (an open string; `capabilityKey` health.zig:87), and HealthStore v2 persists a per-`#capability` `window_resets_at`/`usage_pct`/`exhausted_at` row (`LivenessEntry` health.zig:563-577) with zero schema change. For **Codex** this is live (codex-max/codex-mini, per-route quota clocks via the managed wire → `classifyHttp` → durable rows → TIN-1811/1812 selector). **What's missing:** Claude has only `#auth-status` (provider_schema.zig:328) and **no Claude-specific 429/quota/tier failure rule** (provider_schema.zig:306) — though note `classifyHttp`'s generic 429/403 arms (provider_schema.zig:1032-1060) are provider-agnostic and *would* classify a Claude 429/403 today, so the true gap is the missing evidence SOURCE, not the classifier; there is **no Claude quota-evidence source** (no wire proxy; the `x-ratelimit-*` header names at provider_schema.zig:806-807 are placeholders never exercised, and the 3600s threshold is Codex-derived); scheduling is **quota-blind** (warm loop is credential-expiry-only); and `elect` is **capability-blind** (discards `capability`, account_pool.zig:236). **Category error to flag:** there is no per-model token refresh — a credential is per-account/identity (one refresh warms every model class); only *routing* is per-model. "Keep model specifics alive" can only mean re-observe eligibility and route at the provider's reset instant — **credential keepalive ≠ model-quota keepalive** (acceptance #5).
>
> **Proposed shape (pure algebra + event-log fold):** an append-only log; a total reducer folding it into per-`(identity × model-class × window)` `QuotaBucket`s; two pure queries — `nextQuotaWakeMs(buckets, now)` (schedule) and `selectRoute` (selection). Buckets self-populate (`normalizeModelClass`: model classes **discovered, not declared**; unknowns still get a bucket). Every bucket carries **evidence provenance** `{source, confidence (assumed<inferred<proven), attribution}`; the fold is a confidence-lattice LWW join (order-independent, replayable). `quota_exhausted` carries a **non-optional** `resets_at` (via `deriveResetsAt`) — "exhausted forever" is unrepresentable. Availability is a **query** (`effectiveStatus(b, now)`), not a stored field, so a route returns to routing the instant `now ≥ resets_at` with no timer and no write — the honest realization of the ask. Classification taxonomy = exactly the four TIN-2400 classes (`quota_exhausted`/`rate_limited`/`tier_insufficient`/`provider_plan`), each defined by its evidence + reset + routing effect; under-claim on ambiguous bodies.
>
> **Acceptance #3 enforced structurally:** credential and quota are **two disjoint folds over one log** sharing no field. The scheduler gains one additive term whose effect is *flip routing eligibility / re-observe*, never refresh, never spend; the credential timer stays per-account (one token warms all classes). Property test: any quota-event sequence leaves every credential wake bit-identical.
>
> **Big-O (defended, no hidden O(n²)):** observe **O(log N)** (one bucket, then a 4-ary lazy-deletion min-heap + capability ring), quota next-wake **O(1)** peek / **O(log N)** update (a *new additive* heap over buckets — the credential term stays the existing O(n) `warm.nextWakeMs` account scan until separately heap-upgraded), select **O(log r)** (replaces capability-blind first-fit). N = n·m ≈ tens; ~12 KB steady, zero steady-state allocation.
>
> **Spread — recommended first increment:** **least-recently-selected within a capability ring** (pure fold on `last_selected_at`, O(log r)). It needs **zero** signal so it works for Claude day one, is honest (disruption reduction, never pooling/maximization), and upgrades cleanly to remaining-window-weighted (smooth-WRR) once a *proven* headroom signal exists. Follow-ups: WRR/stride, power-of-two-choices.
>
> **The gate (acceptance #2/#5):** before any model-quota claim, a committed redacted `test/evidence/quota-observation/` must prove (1) real Anthropic rate-limit header names + whether any carries a model dimension, (2) window-cap vs burst 429 bodies (validate the 3600s split for Claude, don't assume it from Codex), (3) tier vs plan bodies, (4) a request→served `model` round-trip incl. a downgrade case, (5) a no-spend proof (observation rode existing traffic), (6) an `auth-status` capture annotated "no quota signal." Until then classifiers ship at `confidence=assumed`, the dashboard shows `unobserved`, and public claims stay "credential keepalive, not model-quota keepalive." No pooling, no capacity-summing, no synthetic-spend probing, no anti-detection — per-operator scheduling of the operator's own authorized accounts' own documented windows, full stop.
>
> **Sequencing:** August adapter-maturation design. Land as doc+comment now; the only July-safe piece is the **pure-core clock inversion** (invert the embedded `std.time.timestamp()` at health.zig:862 [`recordHttpClassification`] and methods.zig:429 [`quotaObserve`] → events carry `at`, queries take `now`; extract `src/quota/bucket.zig`) — a no-behavior-change enabler so July credential-keepalive work adopts the `#capability`/`Evidence` shapes without rework. Everything else (Claude capabilities, passive signal, quota-aware scheduling, spread, schema/export extending TIN-1824/TIN-2062) is August, behind the evidence fixture. **Does not block tonight's credential-keepalive dogfood** — with nothing observed, `nextWakeMs == warm.nextWakeMs`, byte-for-byte today's behavior.

---

### Files grounding this synthesis (all `origin/main @ 17673914`, read-only)
`src/health.zig` (`capabilityKey`:87, `parseHealthKey`:94, v2 row:534, `LivenessEntry`:563-577 [fields `window_resets_at`:572 / `usage_pct`:573 / `exhausted_at`:574], `recoverExpiredTransientHealth`:182, `recordHttpClassification` inline-clock impurity: fn:855 clock:862, `muxDecision`:947 [clock:949]), `src/keepalive/warm_scheduler.zig` (`refreshDueAtMs`:64 reads `expires_at_ms`/`last_refresh_ms`/`refresh_percent`/`min_lead_ms`, `nextWakeMs`:97 [O(n) account scan], `tick`:185 — pure clock-injected core, no `std.time` read), `src/broker/account_pool.zig` (`elect`:229 discards `capability` at :236 [:235 discards `profile`], reads only `a.availability`/`a.selectable`; `refreshTimeBased`:191), `src/provider_schema.zig` (`CapabilityDefinition`:200, `ProbeDefinition`:208, `RateLimitConfig.quota_threshold_seconds` 3600s :262, `claude_capabilities` auth-status-only:328-346, `claude_failure_rules`:306-326, `claude_def` header placeholders:806-807, `codex_capabilities`:679 [codex-max:681, codex-mini:708], `classifyHttp`:1019 [generic 429/403 arms:1032-1060]), `src/types.zig` (`Availability`:193 / `QuotaInfo`:205-209 [`window_resets_at` nullable:206], `DegradedReason`:224, `HttpClassification`:369), `src/broker/types.zig` (`QuotaKind`:47, `SwapReason`:64), `src/broker/methods.zig` (`quota/observe` dispatch:51 → `quotaObserve`:410 [clock:429]), `src/adapters/codex/wire_proxy.zig` (static `capability` field:354, consumed `capability orelse self.capability`:948/:962, test tag `"codex-mini"`:2806, `retryAfterSeconds`:1151). Proposed new home: `src/quota/bucket.zig` (pure algebra) + `src/quota/select.zig` (pure LRS selector).
