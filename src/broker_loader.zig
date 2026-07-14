//! Bridge between the existing oauth-mux Config and the broker
//! AccountPool + CredentialMaterializer. Lives at the same level as
//! main.zig so it can import both `config.zig` and `broker/mod.zig`
//! without leaking either side across module boundaries.
//!
//! Anchor: docs/spec/broker-mcp-contract-2026-05-03.md §2.2 / §2.3.
//! Adapter consumer: src/broker/account_pool.zig + Server.materializer.

const std = @import("std");
const config_mod = @import("config.zig");
const broker = @import("broker/mod.zig");
const broker_types = @import("broker/types.zig");
const env = @import("env.zig");
const health_mod = @import("health.zig");
const oauth = @import("oauth.zig");
const paths = @import("paths.zig");
const repair_state = @import("repair_state.zig");
const trace = @import("trace.zig");
const provider_schema = @import("provider_schema.zig");
const identity_hash = @import("identity_hash.zig");
const types = @import("types.zig");
const pipeline = @import("pipeline.zig");
const claude_identity_source = @import("identity/claude_identity_source.zig");
const ig = @import("identity/identity_graph.zig");
const log = @import("log.zig");

/// Populate `pool` with one entry per `<provider>:<account>` defined in
/// the active Config. Liveness is `.unknown` and availability is
/// `.available`; Phase 2 wires real health correlation.
///
/// `profile_name` (optional) restricts visible accounts to those listed
/// in the named profile. Profile entries may be `provider:account` or
/// `provider:account#capability`; we match the `provider:account`
/// prefix. Out-of-profile accounts stay in the pool but are marked
/// non-selectable so callers can introspect why they're hidden.
pub fn populatePool(
    pool: *broker.AccountPool,
    cfg: config_mod.Config,
    profile_name: ?[]const u8,
) !void {
    var prov_it = cfg.providers.map.iterator();
    while (prov_it.next()) |prov_entry| {
        const provider_name = prov_entry.key_ptr.*;
        const provider_cfg = prov_entry.value_ptr.*;
        var acc_it = provider_cfg.accounts.map.iterator();
        while (acc_it.next()) |acc_entry| {
            const account_name = acc_entry.key_ptr.*;
            const id_buf = try std.fmt.allocPrint(
                pool.allocator,
                "{s}:{s}",
                .{ provider_name, account_name },
            );
            defer pool.allocator.free(id_buf);
            try pool.add(.{
                .id = id_buf,
                .selectable = true,
                .liveness = .unknown,
                .availability = .available,
            });
        }
    }

    if (profile_name) |pname| {
        if (cfg.profiles.map.get(pname)) |profile| {
            // Build a slice-of-slices into the original profile entries,
            // each trimmed to the `provider:account` prefix. No
            // allocation; restrictToAllowList only reads.
            var allow_buf = std.ArrayListUnmanaged([]const u8){};
            defer allow_buf.deinit(pool.allocator);
            for (profile.providers) |entry| {
                const head = if (std.mem.indexOfScalar(u8, entry, '#')) |idx| entry[0..idx] else entry;
                try allow_buf.append(pool.allocator, head);
            }
            pool.restrictToAllowList(allow_buf.items);
        }
    }
}

/// Populate and then apply the same durable route/account health gate used by
/// `broker-session-plan`: account-level dead/quota/rate state dominates, then
/// the profile route's capability health is considered. Missing health leaves
/// the route non-selectable so managed adapter launch cannot silently bypass
/// route repair evidence.
pub fn populatePoolFromRouteHealth(
    pool: *broker.AccountPool,
    cfg: config_mod.Config,
    profile_name: ?[]const u8,
    store: *health_mod.HealthStore,
) !void {
    try populatePoolFromRouteHealthScoped(pool, cfg, profile_name, null, store);
}

pub fn populatePoolFromRouteHealthScoped(
    pool: *broker.AccountPool,
    cfg: config_mod.Config,
    profile_name: ?[]const u8,
    capability_name: ?[]const u8,
    store: *health_mod.HealthStore,
) !void {
    try populatePool(pool, cfg, profile_name);
    applyRouteHealth(pool, cfg, profile_name, capability_name, store);
    try applyIdentityDedupe(pool, cfg, store);
}

const RouteHealthMatch = struct {
    health: health_mod.AccountHealth,
    capability: ?[]const u8 = null,
};

pub const ManagedClaudeIdentityError = error{
    ManagedClaudeRouteMissing,
    ManagedClaudeIdentityClarityRequired,
};

/// Fail-closed admission gate for the managed Claude sidecar. The shared pool
/// deliberately keeps unknown identities opaque for legacy introspection; a
/// managed session must call this after identity dedupe and before election.
/// Known duplicate hashes are already collapsed to one keeper and remain clear.
pub fn requireManagedClaudeIdentityClarity(
    pool: *const broker.AccountPool,
    cfg: config_mod.Config,
    profile_name: []const u8,
) ManagedClaudeIdentityError!void {
    const profile = cfg.profiles.map.get(profile_name) orelse
        return error.ManagedClaudeRouteMissing;

    var saw_claude = false;
    for (profile.providers) |route| {
        const route_id = if (std.mem.indexOfScalar(u8, route, '#')) |idx| route[0..idx] else route;
        const colon = std.mem.indexOfScalar(u8, route_id, ':') orelse continue;
        const provider_name = route_id[0..colon];
        const kind = config_mod.resolveProviderKind(cfg, provider_name) orelse continue;
        if (kind != .claude) continue;
        saw_claude = true;

        var found = false;
        for (pool.accounts.items) |entry| {
            if (!std.mem.eql(u8, entry.id, route_id)) continue;
            found = true;
            if (entry.account_id_hash == null) {
                return error.ManagedClaudeIdentityClarityRequired;
            }
            break;
        }
        if (!found) return error.ManagedClaudeIdentityClarityRequired;
    }
    if (!saw_claude) return error.ManagedClaudeRouteMissing;
}

// ── identity dedupe before election (TIN-1822 / GH #338) ─────────────
//
// Two config slots enrolled on ONE upstream OAuth identity (the live
// max-1 == max-2 shape, account_id_hash 38079d6acec6 in GH #338) must
// never present to `AccountPool.elect` as independent routes: a
// duplicate is not failover capacity, and a stale live-looking duplicate
// of a dead identity is a lie. This mirrors the landed TIN-2113
// warm-pool pattern (src/keepalive/warm_runner.zig enumeratePool):
// identity hashes come from the same producer
// (pipeline.readAccountIdentityHash → identity_hash.sha256_12hex) and
// grouping is the same landed graph primitive
// (identity_graph.duplicateCollisions) — NOT re-implemented here.
//
// Resolution per collision group, in pool (= config) order:
//   * Death arbitration: slots in one group are one upstream account, so
//     account-death evidence on any sibling is evidence about the shared
//     identity. The identity is treated dead unless some live sibling's
//     evidence is STRICTLY newer than every death observation (the
//     re-auth repair shape — authMaterialRepairHealth stamps the auth
//     material mtime). Unverifiable evidence never launders in EITHER
//     direction: liveness with no timestamp cannot outrank death (the
//     #338 stale-live trap), and death with no timestamp cannot be
//     outranked by any liveness (it cannot be ordered, so fail closed).
//   * Dead identity → every slot in the group is demoted dead (one dead
//     identity, not N routes), stamped `duplicate_of` the sibling whose
//     death evidence won.
//   * Live identity → exactly ONE slot stays electable: the keeper is
//     the most RECOVERABLE, freshest-evidenced sibling (keeperOutranks:
//     never a dead slot — dead is sticky and would bury the identity's
//     recovery clock forever; then a slot that can return via elect or
//     refreshTimeBased over one that cannot; then the newest
//     health_observed_at — a fresh quota_exhausted with its reset clock
//     outranks a stale "available" probe; ties prefer the slot usable
//     now, then pool order). The keeper keeps its `next_eligible_at` so
//     a quota-exhausted identity still recovers via refreshTimeBased,
//     counted ONCE per TIN-1812. Every other slot is demoted:
//     selectable=false, next_eligible_at=null, and `duplicate_of` set to
//     the keeper so refreshTimeBased (and any later broker-MCP mark) can
//     never resurrect a duplicate as second capacity.
//
// A slot whose identity cannot be read (missing credential or a missing /
// unusable Claude `.claude.json`) keeps a null hash; the graph keys it
// opaquely and never coalesces two unknowns. Grouping is hash-only (like
// the warm pool): hashes live in one shared sha256_12hex space, and a
// cross-provider 48-bit collision is negligible.
fn applyIdentityDedupe(
    pool: *broker.AccountPool,
    cfg: config_mod.Config,
    store: *health_mod.HealthStore,
) !void {
    // Pass 1: resolve every entry's stable identity hash, even in a one-account
    // pool. Credential-backed providers use their declared identity claim;
    // Claude reads only its account-scoped `.claude.json` profile. Failures
    // leave the hash null (opaque key, no grouping).
    for (pool.accounts.items) |*entry| {
        if (entry.account_id_hash != null) continue;
        const colon = std.mem.indexOfScalar(u8, entry.id, ':') orelse continue;
        const provider_name = entry.id[0..colon];
        const account_name = entry.id[colon + 1 ..];
        if (config_mod.resolveProviderKind(cfg, provider_name)) |kind| {
            if (kind == .claude) {
                // Claude's canonical account UUID is profile metadata, not a
                // credential claim. Resolve it before the generic credential
                // path so pool admission never reads or prompts for a secret.
                const provider_cfg = cfg.providers.map.get(provider_name) orelse continue;
                const account_cfg = provider_cfg.accounts.map.get(account_name) orelse continue;
                entry.account_id_hash = try claude_identity_source.readAccountIdentityHash(
                    pool.allocator,
                    account_cfg.config_dir,
                );
                continue;
            }
        }

        const def = config_mod.resolveProviderDefinition(cfg, provider_name);
        if (def.credential.identity_claim_path == null) continue;
        var pctx = pipeline.Context.init(pool.allocator, cfg, store);
        defer pctx.deinit();
        pctx.provider_name = provider_name;
        pctx.account_name = account_name;
        if (pipeline.readAccountIdentityHash(&pctx) catch null) |hash| {
            // Owned by pool.allocator already; pool.deinit frees it.
            entry.account_id_hash = hash;
        }
    }

    // Identity admission is useful for one-account introspection; only actual
    // duplicate resolution needs at least two slots.
    if (pool.accounts.items.len < 2) return;

    // Pass 2: group by identity via the landed graph primitive. Slot
    // account = pool id ("provider:account") so collisions name routes
    // unambiguously.
    var arena = std.heap.ArenaAllocator.init(pool.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var slots = std.ArrayList(ig.AccountSlot).init(a);
    for (pool.accounts.items) |entry| {
        const colon = std.mem.indexOfScalar(u8, entry.id, ':') orelse continue;
        try slots.append(.{
            .account = entry.id,
            .provider = entry.id[0..colon],
            .capability = "election",
            .account_id_hash = entry.account_id_hash,
            .liveness = igLivenessForPoolEntry(entry),
        });
    }
    const collisions = try ig.duplicateCollisions(a, slots.items);
    // Collision slices are arena-owned; freed with the arena.

    // Pass 3: resolve each duplicate-identity group.
    for (collisions) |collision| try resolveDuplicateIdentityGroup(pool, collision);
}

fn igLivenessForPoolEntry(entry: broker.account_pool_mod.AccountSummary) ig.Liveness {
    return switch (entry.liveness) {
        .dead => .dead,
        .degraded => .degraded,
        .unknown => .unknown,
        .live => switch (entry.availability) {
            .available => .live,
            .rate_limited => .rate_limited,
            .quota_exhausted => .quota_exhausted,
            .cooldown => .cooldown,
            .unknown => .unknown,
        },
    };
}

fn collisionHasAccount(collision: ig.Collision, id: []const u8) bool {
    for (collision.accounts) |name| {
        if (std.mem.eql(u8, name, id)) return true;
    }
    return false;
}

fn resolveDuplicateIdentityGroup(pool: *broker.AccountPool, collision: ig.Collision) !void {
    // Death arbitration (see the module comment above applyIdentityDedupe).
    var any_dead = false;
    var untimestamped_dead = false;
    var newest_dead_ts: i64 = 0;
    var newest_dead_id: ?[]const u8 = null;
    var newest_live_ts: ?i64 = null;
    for (pool.accounts.items) |entry| {
        if (!collisionHasAccount(collision, entry.id)) continue;
        switch (entry.liveness) {
            .dead => {
                any_dead = true;
                if (entry.health_observed_at) |ts| {
                    if (newest_dead_id == null or ts > newest_dead_ts) {
                        newest_dead_ts = ts;
                        newest_dead_id = entry.id;
                    }
                } else {
                    // Untimestamped death evidence cannot be ordered, so no
                    // liveness can be proven strictly newer than it — fail
                    // closed rather than let stale liveness launder it.
                    untimestamped_dead = true;
                    if (newest_dead_id == null) newest_dead_id = entry.id;
                }
            },
            .live => {
                if (entry.health_observed_at) |ts| {
                    if (newest_live_ts == null or ts > newest_live_ts.?) newest_live_ts = ts;
                }
            },
            .degraded, .unknown => {},
        }
    }
    const identity_dead = any_dead and
        (untimestamped_dead or newest_live_ts == null or newest_live_ts.? <= newest_dead_ts);

    if (identity_dead) {
        for (pool.accounts.items) |*entry| {
            if (!collisionHasAccount(collision, entry.id)) continue;
            if (entry.liveness != .dead) {
                log.warn(
                    "broker: route {s} shares one OAuth identity with a slot carrying newer auth-death evidence — one dead identity, not {d} routes (GH #338 / TIN-1822); resolve the duplicate config slot",
                    .{ entry.id, collision.accounts.len },
                );
                // Durable operator evidence: name the sibling whose death
                // evidence demoted this live-looking route.
                if (newest_dead_id) |source| try setPoolEntryDuplicateOf(pool, entry, source);
            }
            entry.liveness = .dead;
            entry.availability = .unknown;
            entry.selectable = false;
            entry.next_eligible_at = null;
        }
        return;
    }

    // Live (or transiently unavailable) identity: keep exactly ONE slot —
    // the most recoverable, freshest-evidenced sibling (keeperOutranks).
    var kept: ?*broker.account_pool_mod.AccountSummary = null;
    for (pool.accounts.items) |*entry| {
        if (!collisionHasAccount(collision, entry.id)) continue;
        if (kept == null or keeperOutranks(entry, kept.?)) kept = entry;
    }
    const kept_entry = kept orelse return;

    for (pool.accounts.items) |*entry| {
        if (!collisionHasAccount(collision, entry.id)) continue;
        if (entry == kept_entry) continue;
        if (entry.selectable or entry.next_eligible_at != null) {
            log.warn(
                "broker: route {s} shares one OAuth identity with {s} — a duplicate enrollment is not failover capacity (GH #338 / TIN-1822); demoting the duplicate; resolve the duplicate config slot to re-enable",
                .{ entry.id, kept_entry.id },
            );
        }
        entry.selectable = false;
        // Clear the recovery clock so refreshTimeBased never resurrects a
        // duplicate as apparent second capacity; the keeper carries the
        // identity's recovery window (TIN-1812 wait-and-continue, once).
        entry.next_eligible_at = null;
        // Durable demotion marker: refreshTimeBased skips slots carrying
        // duplicate_of, so no later broker-MCP mark (account/swap,
        // quota/observe) can resurrect the duplicate either; accounts/list
        // exposes it so operators can see WHY this route is never used.
        try setPoolEntryDuplicateOf(pool, entry, kept_entry.id);
    }
}

/// Strict "candidate outranks incumbent" ordering for choosing the ONE kept
/// slot of a live duplicate-identity group (TIN-1822). Pool (= config) order
/// breaks exact ties because the scan only replaces the incumbent on a
/// strictly better candidate.
fn keeperOutranks(
    candidate: *const broker.account_pool_mod.AccountSummary,
    incumbent: *const broker.account_pool_mod.AccountSummary,
) bool {
    // 1. Never keep a dead slot while a non-dead sibling exists: dead is
    //    sticky (refreshTimeBased cannot restore it), so a dead keeper buries
    //    the identity's recovery clock and makes a live, quota-waiting
    //    identity permanently invisible.
    const candidate_dead = candidate.liveness == .dead;
    const incumbent_dead = incumbent.liveness == .dead;
    if (candidate_dead != incumbent_dead) return !candidate_dead;
    // 2. Recoverable beats unrecoverable: a slot that is selectable now or
    //    carries a recovery clock can return via elect/refreshTimeBased; an
    //    unselectable slot with no clock (out-of-profile, missing route
    //    health) cannot.
    const candidate_recoverable = candidate.selectable or candidate.next_eligible_at != null;
    const incumbent_recoverable = incumbent.selectable or incumbent.next_eligible_at != null;
    if (candidate_recoverable != incumbent_recoverable) return candidate_recoverable;
    // 3. Evidence freshness: the slots are ONE upstream account, so the
    //    newest observation is the identity's truth — a fresh quota_exhausted
    //    (with its reset clock) outranks a stale "available" probe, and
    //    timestamped evidence outranks unverifiable evidence.
    const candidate_ts = candidate.health_observed_at;
    const incumbent_ts = incumbent.health_observed_at;
    if ((candidate_ts != null) != (incumbent_ts != null)) return candidate_ts != null;
    if (candidate_ts != null and candidate_ts.? != incumbent_ts.?) return candidate_ts.? > incumbent_ts.?;
    // 4. Same-freshness tie: prefer the slot usable right now.
    const candidate_available = candidate.selectable and candidate.availability == .available;
    const incumbent_available = incumbent.selectable and incumbent.availability == .available;
    if (candidate_available != incumbent_available) return candidate_available;
    if (candidate.selectable != incumbent.selectable) return candidate.selectable;
    return false;
}

fn setPoolEntryDuplicateOf(
    pool: *broker.AccountPool,
    entry: *broker.account_pool_mod.AccountSummary,
    keeper_id: []const u8,
) !void {
    if (entry.duplicate_of) |old| {
        pool.allocator.free(old);
        entry.duplicate_of = null;
    }
    entry.duplicate_of = try pool.allocator.dupe(u8, keeper_id);
}

fn applyRouteHealth(
    pool: *broker.AccountPool,
    cfg: config_mod.Config,
    profile_name: ?[]const u8,
    capability_name: ?[]const u8,
    store: *health_mod.HealthStore,
) void {
    for (pool.accounts.items) |*entry| {
        if (!entry.selectable) continue;
        const route_health = routeHealthForPoolAccount(pool.allocator, cfg, profile_name, capability_name, entry.id, store) orelse {
            entry.selectable = false;
            entry.liveness = .unknown;
            entry.availability = .unknown;
            setPoolEntryCapability(pool, entry, null) catch {};
            continue;
        };
        setPoolEntryCapability(pool, entry, route_health.capability) catch {
            entry.selectable = false;
            entry.liveness = .unknown;
            entry.availability = .unknown;
            continue;
        };
        applyHealthToPoolEntry(entry, route_health.health);
    }
}

fn routeHealthForPoolAccount(
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    profile_name: ?[]const u8,
    requested_capability: ?[]const u8,
    account_id: []const u8,
    store: *health_mod.HealthStore,
) ?RouteHealthMatch {
    const now = std.time.timestamp();
    const colon = std.mem.indexOfScalar(u8, account_id, ':') orelse return null;
    const provider = account_id[0..colon];
    const account = account_id[colon + 1 ..];
    const account_key = health_mod.accountKey(provider, account);
    if (store.accounts.get(account_key.slice())) |account_health| {
        const effective = health_mod.effectiveHealthForRouteSelection(account_health, now);
        tracePoolHealthNormalization(allocator, provider, account, null, "account", account_health.liveness, effective.liveness);
        if (accountLivenessBlocksRoute(effective.liveness)) {
            if (authMaterialRepairHealth(allocator, cfg, provider, account, account_health)) |repaired| return .{ .health = repaired };
            return .{ .health = effective };
        }
    }

    if (profile_name) |name| {
        if (cfg.profiles.map.get(name)) |profile| {
            if (requested_capability) |want| {
                if (profileHasAccountCapability(profile, account_id, want)) {
                    if (capabilityHealthForPoolAccount(allocator, cfg, provider, account, want, store, now)) |requested| {
                        if (!accountLivenessBlocksRoute(requested.health.liveness)) return requested;
                        if (fallbackCapabilityHealthForPoolAccount(allocator, cfg, profile, account_id, provider, account, want, store, now)) |fallback| return fallback;
                        return requested;
                    }
                    if (fallbackCapabilityHealthForPoolAccount(allocator, cfg, profile, account_id, provider, account, want, store, now)) |fallback| return fallback;
                    return null;
                }
                if (fallbackCapabilityHealthForPoolAccount(allocator, cfg, profile, account_id, provider, account, want, store, now)) |fallback| return fallback;
            }

            for (profile.providers) |profile_entry| {
                const hash = std.mem.indexOfScalar(u8, profile_entry, '#') orelse continue;
                const head = profile_entry[0..hash];
                if (!std.mem.eql(u8, head, account_id)) continue;
                const capability = profile_entry[hash + 1 ..];
                if (capabilityHealthForPoolAccount(allocator, cfg, provider, account, capability, store, now)) |match| return match;
            }
        }
    }

    if (requested_capability) |capability| {
        if (capabilityHealthForPoolAccount(allocator, cfg, provider, account, capability, store, now)) |match| return match;
    }

    if (store.accounts.get(account_key.slice())) |account_health| {
        const effective = health_mod.effectiveHealthForRouteSelection(account_health, now);
        tracePoolHealthNormalization(allocator, provider, account, null, "account", account_health.liveness, effective.liveness);
        if (accountLivenessBlocksRoute(effective.liveness)) {
            if (authMaterialRepairHealth(allocator, cfg, provider, account, account_health)) |repaired| return .{ .health = repaired };
        }
        return .{ .health = effective };
    }
    return null;
}

fn profileHasAccountCapability(profile: config_mod.ProfileConfig, account_id: []const u8, capability: []const u8) bool {
    for (profile.providers) |profile_entry| {
        const hash = std.mem.indexOfScalar(u8, profile_entry, '#') orelse continue;
        if (!std.mem.eql(u8, profile_entry[0..hash], account_id)) continue;
        if (std.mem.eql(u8, profile_entry[hash + 1 ..], capability)) return true;
    }
    return false;
}

fn capabilityHealthForPoolAccount(
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    provider: []const u8,
    account: []const u8,
    capability: []const u8,
    store: *health_mod.HealthStore,
    now: i64,
) ?RouteHealthMatch {
    const capability_key = health_mod.capabilityKey(provider, account, capability);
    const capability_health = store.accounts.get(capability_key.slice()) orelse return null;
    const effective = health_mod.effectiveHealthForRouteSelection(capability_health, now);
    tracePoolHealthNormalization(allocator, provider, account, capability, "capability", capability_health.liveness, effective.liveness);
    if (accountLivenessBlocksRoute(effective.liveness)) {
        if (authMaterialRepairHealth(allocator, cfg, provider, account, capability_health)) |repaired| {
            return .{ .health = repaired, .capability = capability };
        }
    }
    return .{ .health = effective, .capability = capability };
}

fn fallbackCapabilityHealthForPoolAccount(
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    profile: config_mod.ProfileConfig,
    account_id: []const u8,
    provider: []const u8,
    account: []const u8,
    requested_capability: []const u8,
    store: *health_mod.HealthStore,
    now: i64,
) ?RouteHealthMatch {
    const chain = profile.capability_degradation_chain orelse return null;
    for (chain) |fallback_capability| {
        if (std.mem.eql(u8, requested_capability, fallback_capability)) continue;
        if (!profileHasAccountCapability(profile, account_id, fallback_capability)) continue;
        const fallback = capabilityHealthForPoolAccount(allocator, cfg, provider, account, fallback_capability, store, now) orelse continue;
        if (!accountLivenessBlocksRoute(fallback.health.liveness)) return fallback;
    }
    return null;
}

fn setPoolEntryCapability(
    pool: *broker.AccountPool,
    entry: *broker.account_pool_mod.AccountSummary,
    capability: ?[]const u8,
) !void {
    if (entry.capability) |old| {
        pool.allocator.free(old);
        entry.capability = null;
    }
    if (capability) |cap| {
        entry.capability = try pool.allocator.dupe(u8, cap);
    }
}

fn tracePoolHealthNormalization(
    allocator: std.mem.Allocator,
    provider_name: []const u8,
    account_label: []const u8,
    capability: ?[]const u8,
    source_scope: []const u8,
    before: types.CredentialLiveness,
    after: types.CredentialLiveness,
) void {
    var before_buf: [128]u8 = undefined;
    var after_buf: [128]u8 = undefined;
    const before_summary = livenessSummaryIntoBuffer(before, &before_buf);
    const after_summary = livenessSummaryIntoBuffer(after, &after_buf);
    if (std.mem.eql(u8, before_summary, after_summary)) return;

    trace.append(allocator, "health.normalize", .info, &.{
        trace.string("provider", provider_name),
        trace.string("account_label", account_label),
        trace.string("capability", capability orelse "none"),
        trace.string("source_scope", source_scope),
        trace.string("before_liveness", before_summary),
        trace.string("after_liveness", after_summary),
        trace.boolean("token_material_printed", false),
        trace.boolean("path_printed", false),
    });
}

fn livenessSummaryIntoBuffer(liveness: types.CredentialLiveness, buf: []u8) []const u8 {
    var stream = std.io.fixedBufferStream(buf);
    health_mod.writeLivenessSummary(stream.writer(), liveness) catch return "unavailable";
    return stream.getWritten();
}

fn accountLivenessBlocksRoute(liveness: types.CredentialLiveness) bool {
    return switch (liveness) {
        .dead, .degraded => true,
        .live => |live| switch (live.availability) {
            .available => false,
            .rate_limited, .quota_exhausted, .cooldown => true,
        },
    };
}

fn authMaterialRepairHealth(
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    provider: []const u8,
    account: []const u8,
    health: health_mod.AccountHealth,
) ?health_mod.AccountHealth {
    const observed_at = health.last_probe_observed_at orelse return null;
    const auth_mtime_ns = accountAuthMaterialMtimeNs(allocator, cfg, provider, account) orelse return null;
    const observed_ns = @as(i128, observed_at) * std.time.ns_per_s;
    if (auth_mtime_ns <= observed_ns) return null;

    return .{
        .liveness = .{ .live = .{ .availability = .available } },
        .last_probe_source = .credential_validation,
        .last_probe_observed_at = @intCast(@divFloor(auth_mtime_ns, std.time.ns_per_s)),
        .last_probe_hint_class = .none,
        .last_probe_decision = .use_this,
    };
}

fn accountAuthMaterialMtimeNs(
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    provider: []const u8,
    account: []const u8,
) ?i128 {
    const provider_cfg = cfg.providers.map.get(provider) orelse return null;
    const acct_cfg = provider_cfg.accounts.map.get(account) orelse return null;

    const auth_path = accountAuthMaterialPath(allocator, acct_cfg) catch return null;
    defer allocator.free(auth_path);

    const file = if (std.fs.path.isAbsolute(auth_path))
        std.fs.openFileAbsolute(auth_path, .{}) catch return null
    else
        std.fs.cwd().openFile(auth_path, .{}) catch return null;
    defer file.close();
    const stat = file.stat() catch return null;
    return stat.mtime;
}

fn accountAuthMaterialPath(
    allocator: std.mem.Allocator,
    acct_cfg: config_mod.AccountConfig,
) ![]const u8 {
    if (std.mem.eql(u8, acct_cfg.secret.backend, "file")) {
        if (acct_cfg.secret.path) |path| return try paths.expandTilde(allocator, path);
    }
    if (acct_cfg.config_dir) |dir_raw| {
        const dir = try paths.expandTilde(allocator, dir_raw);
        defer allocator.free(dir);
        return try std.fs.path.join(allocator, &.{ dir, "auth.json" });
    }
    return error.FileNotFound;
}

fn refreshCodexAccountAuthFile(
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    provider: []const u8,
    account: []const u8,
    acct_cfg: config_mod.AccountConfig,
) !void {
    const path = try accountAuthMaterialPath(allocator, acct_cfg);
    defer allocator.free(path);

    var lock = try repair_state.acquireRepairLockBlocking(allocator, provider, account);
    defer lock.release();

    const bytes = try readFileAlloc(allocator, path);
    defer allocator.free(bytes);

    switch (refreshCodexAuthState(allocator, bytes)) {
        .not_needed => return,
        .unavailable => return error.NoRefreshToken,
        .needed => {},
    }

    const def = config_mod.resolveProviderDefinition(cfg, provider);

    // TIN-2043: defer if a live session of the same UPSTREAM IDENTITY holds
    // the identity flock — even under a different config account (the
    // max-1 == max-4 shape). The per-account blocking lock above does not
    // cover a sibling config account sharing one single-use RT chain. Key
    // it exactly as the managed session does; nonblocking, defer-on-held
    // (background refresh is never urgent — the session holder rotates its
    // own chain).
    var identity_lock: ?repair_state.RepairLock = null;
    defer if (identity_lock) |*l| l.release();
    if (def.credential.identity_claim_path != null) {
        const account_id = (provider_schema.identityClaimFromCredential(def, bytes, allocator) catch null) orelse
            // Defensive: a store that reached here already parsed an
            // account_id via refreshCodexAuthState above (a store without
            // one bails as .not_needed before this point), so this refuse is
            // belt-and-suspenders against future changes to that gate — never
            // dodge the duplicate-identity guard on an unresolved id.
            return error.NoIdentityClaim;
        defer allocator.free(account_id);
        const id_hash = try identity_hash.sha256_12hex(allocator, account_id);
        defer allocator.free(id_hash);
        const identity_domain = try std.fmt.allocPrint(allocator, "{s}-identity", .{provider});
        defer allocator.free(identity_domain);
        identity_lock = repair_state.acquireRepairLock(allocator, identity_domain, id_hash) catch |e| switch (e) {
            error.RepairInProgress => return, // a live session owns the chain; skip this background refresh
            else => return e,
        };
    }

    var material = try parseCodexAuthRefreshMaterial(allocator, bytes);
    defer material.deinit(allocator);
    const refresh_token = material.refresh_token orelse return error.NoRefreshToken;

    const token_url = def.auth.token_endpoint orelse oauth.refreshUrl(.codex) orelse return error.NoTokenEndpoint;
    const result = try oauth.refreshToken(allocator, token_url, refresh_token, def.auth.client_id);
    defer allocator.free(result.access_token);
    defer if (result.refresh_token) |rt| allocator.free(rt);

    const refreshed = try buildRefreshedCodexAuthJson(allocator, material, result);
    defer allocator.free(refreshed);
    try writeFileReplace(path, refreshed, allocator);
}

const CodexAuthRefreshState = enum {
    not_needed,
    needed,
    unavailable,
};

fn refreshCodexAuthState(allocator: std.mem.Allocator, bytes: []const u8) CodexAuthRefreshState {
    var material = parseCodexAuthRefreshMaterial(allocator, bytes) catch return .not_needed;
    defer material.deinit(allocator);
    const exp = jwtExpiresAt(allocator, material.access_token) catch return .not_needed;
    if (exp > std.time.timestamp() + 300) return .not_needed;
    return if (material.refresh_token != null) .needed else .unavailable;
}

fn refreshCodexAuthBeforeMaterialize(
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    provider: []const u8,
    account: []const u8,
    acct_cfg: config_mod.AccountConfig,
    bytes: []const u8,
) broker_types.BrokerError!bool {
    if (!std.mem.eql(u8, provider, "codex")) return false;
    if (acct_cfg.config_dir == null) return false;
    switch (refreshCodexAuthState(allocator, bytes)) {
        .not_needed => return false,
        .unavailable => return broker_types.BrokerError.SecretUnavailable,
        .needed => {},
    }
    refreshCodexAccountAuthFile(allocator, cfg, provider, account, acct_cfg) catch
        return broker_types.BrokerError.SecretUnavailable;
    return true;
}

fn codexAuthShouldRefresh(allocator: std.mem.Allocator, bytes: []const u8) bool {
    return refreshCodexAuthState(allocator, bytes) == .needed;
}

const CodexAuthRefreshMaterial = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8 = null,
    account_id: []const u8,
    id_token: ?[]const u8 = null,
    auth_mode: ?[]const u8 = null,

    fn deinit(self: *CodexAuthRefreshMaterial, allocator: std.mem.Allocator) void {
        allocator.free(self.access_token);
        if (self.refresh_token) |value| allocator.free(value);
        allocator.free(self.account_id);
        if (self.id_token) |value| allocator.free(value);
        if (self.auth_mode) |value| allocator.free(value);
    }
};

fn parseCodexAuthRefreshMaterial(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) broker_types.BrokerError!CodexAuthRefreshMaterial {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch
        return broker_types.BrokerError.ParseError;
    defer parsed.deinit();

    if (parsed.value != .object) return broker_types.BrokerError.InvalidShape;
    const tokens_v = parsed.value.object.get("tokens") orelse return broker_types.BrokerError.InvalidShape;
    if (tokens_v != .object) return broker_types.BrokerError.InvalidShape;

    const access_v = tokens_v.object.get("access_token") orelse return broker_types.BrokerError.InvalidShape;
    if (access_v != .string) return broker_types.BrokerError.InvalidShape;
    const account_v = tokens_v.object.get("account_id") orelse return broker_types.BrokerError.InvalidShape;
    if (account_v != .string) return broker_types.BrokerError.InvalidShape;

    const access_token = allocator.dupe(u8, access_v.string) catch return broker_types.BrokerError.OutOfMemory;
    const account_id = allocator.dupe(u8, account_v.string) catch {
        allocator.free(access_token);
        return broker_types.BrokerError.OutOfMemory;
    };
    var material = CodexAuthRefreshMaterial{
        .access_token = access_token,
        .account_id = account_id,
    };
    errdefer material.deinit(allocator);

    if (tokens_v.object.get("refresh_token")) |refresh_v| {
        if (refresh_v == .string) {
            material.refresh_token = allocator.dupe(u8, refresh_v.string) catch return broker_types.BrokerError.OutOfMemory;
        }
    }
    if (tokens_v.object.get("id_token")) |id_v| {
        if (id_v == .string) {
            material.id_token = allocator.dupe(u8, id_v.string) catch return broker_types.BrokerError.OutOfMemory;
        }
    }
    if (parsed.value.object.get("auth_mode")) |mode_v| {
        if (mode_v == .string) {
            material.auth_mode = allocator.dupe(u8, mode_v.string) catch return broker_types.BrokerError.OutOfMemory;
        }
    }
    return material;
}

fn buildRefreshedCodexAuthJson(
    allocator: std.mem.Allocator,
    material: CodexAuthRefreshMaterial,
    result: oauth.RefreshResult,
) ![]const u8 {
    var out = std.ArrayListUnmanaged(u8){};
    errdefer out.deinit(allocator);
    const w = out.writer(allocator);

    try w.writeAll("{\"OPENAI_API_KEY\":null,\"tokens\":{");
    var first = true;
    if (material.id_token) |id_token| {
        try writeJsonField(w, &first, "id_token", id_token);
    }
    try writeJsonField(w, &first, "access_token", result.access_token);
    try writeJsonField(w, &first, "refresh_token", result.refresh_token orelse material.refresh_token.?);
    try writeJsonField(w, &first, "account_id", material.account_id);
    try w.writeAll("},\"auth_mode\":");
    try std.json.stringify(material.auth_mode orelse "Chatgpt", .{}, w);
    try w.writeAll("}\n");
    return try out.toOwnedSlice(allocator);
}

fn writeJsonField(writer: anytype, first: *bool, name: []const u8, value: []const u8) !void {
    if (!first.*) try writer.writeByte(',');
    first.* = false;
    try std.json.stringify(name, .{}, writer);
    try writer.writeByte(':');
    try std.json.stringify(value, .{}, writer);
}

fn jwtExpiresAt(allocator: std.mem.Allocator, jwt: []const u8) !i64 {
    const dot1 = std.mem.indexOfScalar(u8, jwt, '.') orelse return error.BadJwt;
    const after_header = jwt[dot1 + 1 ..];
    const dot2 = std.mem.indexOfScalar(u8, after_header, '.') orelse return error.BadJwt;
    const payload_b64 = after_header[0..dot2];

    const decoder = std.base64.url_safe_no_pad.Decoder;
    const payload_len = try decoder.calcSizeForSlice(payload_b64);
    const payload_buf = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload_buf);
    try decoder.decode(payload_buf, payload_b64);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_buf, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.BadJwt;
    const exp_v = parsed.value.object.get("exp") orelse return error.BadJwt;
    if (exp_v != .integer) return error.BadJwt;
    return exp_v.integer;
}

fn readFileAlloc(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const file = if (std.fs.path.isAbsolute(path))
        try std.fs.openFileAbsolute(path, .{})
    else
        try std.fs.cwd().openFile(path, .{});
    defer file.close();
    return try file.readToEndAlloc(allocator, 1 << 20);
}

fn writeFileReplace(path: []const u8, bytes: []const u8, allocator: std.mem.Allocator) !void {
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.tmp-{x}", .{ path, std.crypto.random.int(u64) });
    defer allocator.free(tmp_path);

    const is_absolute = std.fs.path.isAbsolute(path);
    const file = if (is_absolute)
        try std.fs.createFileAbsolute(tmp_path, .{ .exclusive = true, .mode = 0o600 })
    else
        try std.fs.cwd().createFile(tmp_path, .{ .exclusive = true, .mode = 0o600 });
    errdefer {
        if (is_absolute) {
            std.fs.deleteFileAbsolute(tmp_path) catch {};
        } else {
            std.fs.cwd().deleteFile(tmp_path) catch {};
        }
    }

    {
        defer file.close();
        try file.writeAll(bytes);
        try file.sync();
    }

    if (is_absolute) {
        try std.fs.renameAbsolute(tmp_path, path);
    } else {
        try std.fs.cwd().rename(tmp_path, path);
    }
}

fn applyHealthToPoolEntry(entry: *broker.account_pool_mod.AccountSummary, health: health_mod.AccountHealth) void {
    entry.selectable = types.selectable(health.liveness, .ready);
    entry.health_observed_at = health.last_probe_observed_at;
    switch (health.liveness) {
        .dead => {
            entry.liveness = .dead;
            entry.availability = .unknown;
        },
        .degraded => {
            entry.liveness = .degraded;
            entry.availability = .unknown;
        },
        .live => |live| {
            entry.liveness = .live;
            entry.availability = switch (live.availability) {
                .available => .available,
                .rate_limited => .rate_limited,
                .quota_exhausted => .quota_exhausted,
                .cooldown => .cooldown,
            };
            switch (live.availability) {
                .rate_limited => |rl| entry.next_eligible_at = rl.limited_at + @as(i64, rl.retry_after_s),
                .quota_exhausted => |quota| entry.next_eligible_at = quota.window_resets_at,
                .cooldown => |cooldown| entry.next_eligible_at = cooldown.until,
                .available => entry.next_eligible_at = null,
            }
        },
    }
}

// ── credential materializer ──────────────────────────────────────────

/// Holds a borrowed reference to a loaded Config so the broker's
/// CredentialMaterializer vtable can find an account's configured
/// secret store. Lifetime: must outlive the broker server.
pub const ChatgptMaterializerCtx = struct {
    cfg: *const config_mod.Config,

    /// Cast to/from the broker's opaque ctx pointer.
    pub fn vtable(self: *ChatgptMaterializerCtx) broker_types.CredentialMaterializer {
        return .{
            .ctx = @as(*anyopaque, @ptrCast(self)),
            .materialize_chatgpt = chatgptThunk,
        };
    }
};

fn chatgptThunk(
    raw: *anyopaque,
    allocator: std.mem.Allocator,
    account_id: []const u8,
) broker_types.BrokerError!broker_types.ChatgptAuthTokens {
    const self: *ChatgptMaterializerCtx = @ptrCast(@alignCast(raw));
    return materializeChatgpt(self.cfg.*, allocator, account_id);
}

/// Resolve a `provider:account` to a chatgpt_auth_tokens tuple by
/// reading the account's configured secret store. Phase 1 supports the
/// `backend: "file"` shape, which is what oauth-mux uses for managed
/// codex accounts under ~/.config/oauth-mux/codex/<account>/auth.json.
pub fn materializeChatgpt(
    cfg: config_mod.Config,
    allocator: std.mem.Allocator,
    account_id: []const u8,
) broker_types.BrokerError!broker_types.ChatgptAuthTokens {
    const colon = std.mem.indexOfScalar(u8, account_id, ':') orelse
        return broker_types.BrokerError.InvalidParams;
    const provider = account_id[0..colon];
    const account = account_id[colon + 1 ..];

    const provider_cfg = cfg.providers.map.get(provider) orelse
        return broker_types.BrokerError.AccountNotFound;
    if (!std.mem.eql(u8, provider, "codex") and !std.mem.eql(u8, provider_cfg.kind, "codex")) {
        // chatgpt_auth_tokens is a Codex app-server credential shape. Refuse
        // providers that are neither the built-in Codex key nor Codex-kind
        // before touching their account stores.
        return broker_types.BrokerError.UnsupportedShape;
    }
    const acct_cfg = provider_cfg.accounts.map.get(account) orelse
        return broker_types.BrokerError.AccountNotFound;

    if (!std.mem.eql(u8, acct_cfg.secret.backend, "file")) {
        // Phase 1: only file-backend is wired. Other backends
        // (keychain, sops/age, command, env, stdin) need their own
        // secret/*.zig invocations, follow-up.
        return broker_types.BrokerError.SecretUnavailable;
    }
    const path_raw = acct_cfg.secret.path orelse
        return broker_types.BrokerError.SecretUnavailable;

    // Tilde-expand a leading ~ for ergonomics; otherwise use the path
    // as-is.
    const path = if (std.mem.startsWith(u8, path_raw, "~/")) blk: {
        const home = std.process.getEnvVarOwned(allocator, "HOME") catch
            return broker_types.BrokerError.SecretUnavailable;
        defer allocator.free(home);
        break :blk std.fmt.allocPrint(allocator, "{s}{s}", .{ home, path_raw[1..] }) catch
            return broker_types.BrokerError.OutOfMemory;
    } else allocator.dupe(u8, path_raw) catch
        return broker_types.BrokerError.OutOfMemory;
    defer allocator.free(path);

    var bytes = readFileAlloc(allocator, path) catch
        return broker_types.BrokerError.SecretUnavailable;
    defer allocator.free(bytes);

    if (try refreshCodexAuthBeforeMaterialize(allocator, cfg, provider, account, acct_cfg, bytes)) {
        const refreshed_bytes = readFileAlloc(allocator, path) catch
            return broker_types.BrokerError.SecretUnavailable;
        allocator.free(bytes);
        bytes = refreshed_bytes;
    }

    return parseAuthJson(allocator, bytes);
}

test "materializeChatgpt rejects non-Codex providers before reading secrets" {
    const json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "claude": {
        \\      "kind": "claude",
        \\      "accounts": {
        \\        "work": {
        \\          "priority": 10,
        \\          "secret": {
        \\            "backend": "file",
        \\            "path": "/tmp/omux-this-file-must-not-be-read"
        \\          }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "claude": { "providers": ["claude:work#auth-status"] }
        \\  }
        \\}
    ;
    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    try std.testing.expectError(
        broker_types.BrokerError.UnsupportedShape,
        materializeChatgpt(parsed.value, std.testing.allocator, "claude:work"),
    );
}

/// Parse a codex-shaped auth.json into ChatgptAuthTokens. Schema
/// reference: codex-rs/login/src/auth/storage.rs (AuthDotJson).
fn parseAuthJson(
    allocator: std.mem.Allocator,
    bytes: []const u8,
) broker_types.BrokerError!broker_types.ChatgptAuthTokens {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, bytes, .{}) catch
        return broker_types.BrokerError.ParseError;
    defer parsed.deinit();

    if (parsed.value != .object) return broker_types.BrokerError.InvalidShape;
    const tokens_v = parsed.value.object.get("tokens") orelse return broker_types.BrokerError.InvalidShape;
    if (tokens_v != .object) return broker_types.BrokerError.InvalidShape;

    const access_v = tokens_v.object.get("access_token") orelse return broker_types.BrokerError.InvalidShape;
    if (access_v != .string) return broker_types.BrokerError.InvalidShape;
    const account_v = tokens_v.object.get("account_id") orelse return broker_types.BrokerError.InvalidShape;
    if (account_v != .string) return broker_types.BrokerError.InvalidShape;

    const access_token = allocator.dupe(u8, access_v.string) catch return broker_types.BrokerError.OutOfMemory;
    errdefer allocator.free(access_token);
    const acct_id = allocator.dupe(u8, account_v.string) catch return broker_types.BrokerError.OutOfMemory;
    errdefer allocator.free(acct_id);

    // Best-effort: extract chatgpt_plan_type and chatgpt_account_is_fedramp
    // from the id_token JWT's "https://api.openai.com/auth" claim. JWT
    // body is the second base64url-encoded segment; we decode it and
    // look up the nested field. Failure is non-fatal: plan_type stays
    // null, fedramp stays false.
    var plan_type: ?[]const u8 = null;
    var fedramp = false;
    if (tokens_v.object.get("id_token")) |id_v| {
        if (id_v == .string) {
            extractIdTokenClaims(allocator, id_v.string, &plan_type, &fedramp) catch {};
        }
    }

    return broker_types.ChatgptAuthTokens{
        .access_token = access_token,
        .account_id = acct_id,
        .plan_type = plan_type,
        .fedramp = fedramp,
    };
}

fn extractIdTokenClaims(
    allocator: std.mem.Allocator,
    jwt: []const u8,
    out_plan_type: *?[]const u8,
    out_fedramp: *bool,
) !void {
    // JWT shape: header.payload.signature, all base64url-no-padding.
    const dot1 = std.mem.indexOfScalar(u8, jwt, '.') orelse return error.BadJwt;
    const after_header = jwt[dot1 + 1 ..];
    const dot2 = std.mem.indexOfScalar(u8, after_header, '.') orelse return error.BadJwt;
    const payload_b64 = after_header[0..dot2];

    const decoder = std.base64.url_safe_no_pad.Decoder;
    const payload_len = try decoder.calcSizeForSlice(payload_b64);
    const payload_buf = try allocator.alloc(u8, payload_len);
    defer allocator.free(payload_buf);
    try decoder.decode(payload_buf, payload_b64);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload_buf, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return;

    const auth_claim = parsed.value.object.get("https://api.openai.com/auth") orelse return;
    if (auth_claim != .object) return;

    if (auth_claim.object.get("chatgpt_plan_type")) |pt| {
        if (pt == .string) {
            out_plan_type.* = try allocator.dupe(u8, pt.string);
        }
    }
    if (auth_claim.object.get("chatgpt_account_is_fedramp")) |f| {
        if (f == .bool) out_fedramp.* = f.bool;
    }
}

test "parseAuthJson minimal shape" {
    const bytes =
        \\{
        \\  "OPENAI_API_KEY": null,
        \\  "tokens": {
        \\    "id_token": "ignored.eyJ9.x",
        \\    "access_token": "AT-1234",
        \\    "refresh_token": "RT-5678",
        \\    "account_id": "acc-abc"
        \\  },
        \\  "last_refresh": "now",
        \\  "auth_mode": "Chatgpt"
        \\}
    ;
    var tokens = try parseAuthJson(std.testing.allocator, bytes);
    defer tokens.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("AT-1234", tokens.access_token);
    try std.testing.expectEqualStrings("acc-abc", tokens.account_id);
    try std.testing.expect(tokens.plan_type == null);
    try std.testing.expect(!tokens.fedramp);
}

test "parseAuthJson rejects missing tokens key" {
    const bytes = "{\"OPENAI_API_KEY\":null,\"auth_mode\":\"Chatgpt\"}";
    const result = parseAuthJson(std.testing.allocator, bytes);
    try std.testing.expectError(broker_types.BrokerError.InvalidShape, result);
}

test "parseAuthJson tolerates malformed id_token (silent fallback)" {
    // Single dot instead of two — JWT extractor returns BadJwt, but we
    // swallow it and keep plan_type/fedramp at defaults.
    const bytes =
        \\{"tokens":{"access_token":"AT","account_id":"AID","id_token":"only-one-dot"}}
    ;
    var tokens = try parseAuthJson(std.testing.allocator, bytes);
    defer tokens.deinit(std.testing.allocator);
    try std.testing.expect(tokens.plan_type == null);
    try std.testing.expect(!tokens.fedramp);
    try std.testing.expectEqualStrings("AT", tokens.access_token);
}

test "parseAuthJson with plan_type from id_token" {
    // id_token payload: {"https://api.openai.com/auth":{"chatgpt_plan_type":"pro","chatgpt_account_is_fedramp":true}}
    // base64url-no-pad encoded:
    const id_token = "h.eyJodHRwczovL2FwaS5vcGVuYWkuY29tL2F1dGgiOnsiY2hhdGdwdF9wbGFuX3R5cGUiOiJwcm8iLCJjaGF0Z3B0X2FjY291bnRfaXNfZmVkcmFtcCI6dHJ1ZX19.s";
    const bytes = try std.fmt.allocPrint(std.testing.allocator,
        \\{{"tokens":{{"access_token":"a","account_id":"b","id_token":"{s}"}}}}
    , .{id_token});
    defer std.testing.allocator.free(bytes);

    var tokens = try parseAuthJson(std.testing.allocator, bytes);
    defer tokens.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("pro", tokens.plan_type.?);
    try std.testing.expect(tokens.fedramp);
}

test "codex auth refresh detection uses access token exp" {
    const expired_auth =
        \\{"tokens":{"access_token":"h.eyJleHAiOjF9.s","refresh_token":"rt","account_id":"acc"}}
    ;
    try std.testing.expect(codexAuthShouldRefresh(std.testing.allocator, expired_auth));
    try std.testing.expectEqual(
        CodexAuthRefreshState.unavailable,
        refreshCodexAuthState(std.testing.allocator,
            \\{"tokens":{"access_token":"h.eyJleHAiOjF9.s","account_id":"acc"}}
        ),
    );

    const future_exp = std.time.timestamp() + 3600;
    var payload_buf: [64]u8 = undefined;
    const payload = try std.fmt.bufPrint(&payload_buf, "{{\"exp\":{d}}}", .{future_exp});
    var encoded_buf: [128]u8 = undefined;
    const encoded = std.base64.url_safe_no_pad.Encoder.encode(&encoded_buf, payload);
    const fresh_auth = try std.fmt.allocPrint(std.testing.allocator,
        \\{{"tokens":{{"access_token":"h.{s}.s","refresh_token":"rt","account_id":"acc"}}}}
    , .{encoded});
    defer std.testing.allocator.free(fresh_auth);
    try std.testing.expect(!codexAuthShouldRefresh(std.testing.allocator, fresh_auth));
}

fn testCodexAccessTokenWithExp(allocator: std.mem.Allocator, exp: i64) ![]const u8 {
    var payload_buf: [96]u8 = undefined;
    const payload = try std.fmt.bufPrint(&payload_buf, "{{\"exp\":{d}}}", .{exp});
    var encoded_buf: [160]u8 = undefined;
    const encoded = std.base64.url_safe_no_pad.Encoder.encode(&encoded_buf, payload);
    return try std.fmt.allocPrint(allocator, "h.{s}.s", .{encoded});
}

fn testCodexAuthJsonWithExp(
    allocator: std.mem.Allocator,
    exp: i64,
    refresh_token: []const u8,
    account_id: []const u8,
) ![]const u8 {
    const access_token = try testCodexAccessTokenWithExp(allocator, exp);
    defer allocator.free(access_token);
    return try std.fmt.allocPrint(
        allocator,
        \\{{"tokens":{{"access_token":"{s}","refresh_token":"{s}","account_id":"{s}"}}}}
    ,
        .{ access_token, refresh_token, account_id },
    );
}

test "codex refresh rechecks auth file before spending refresh token" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const fresh_auth = try testCodexAuthJsonWithExp(
        std.testing.allocator,
        std.time.timestamp() + 3600,
        "rt-peer-refreshed",
        "acc",
    );
    defer std.testing.allocator.free(fresh_auth);

    const auth_file = try tmp.dir.createFile("auth.json", .{ .mode = 0o600 });
    try auth_file.writeAll(fresh_auth);
    auth_file.close();

    const auth_path = try tmp.dir.realpathAlloc(std.testing.allocator, "auth.json");
    defer std.testing.allocator.free(auth_path);
    const config_dir = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(config_dir);

    // refreshCodexAccountAuthFile takes a real BLOCKING repair lock; scope the
    // lock file to this test's tmp dir instead of the user's real runtime dir.
    var overrides = std.process.EnvMap.init(std.testing.allocator);
    defer overrides.deinit();
    try overrides.put("OMUX_RUNTIME_DIR", config_dir);
    env.test_overrides = &overrides;
    defer env.test_overrides = null;

    const cfg_json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "codex-test": {{
        \\      "name": "codex-test",
        \\      "auth": {{
        \\        "token_endpoint": "://invalid",
        \\        "client_id": "client"
        \\      }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "codex": {{
        \\      "kind": "codex-test",
        \\      "accounts": {{
        \\        "refresh-skip": {{
        \\          "config_dir": "{s}",
        \\          "secret": {{ "backend": "file", "path": "{s}" }}
        \\        }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ,
        .{ config_dir, auth_path },
    );
    defer std.testing.allocator.free(cfg_json);

    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    const acct_cfg = parsed.value.providers.map.get("codex").?.accounts.map.get("refresh-skip").?;
    try refreshCodexAccountAuthFile(std.testing.allocator, parsed.value, "codex", "refresh-skip", acct_cfg);

    const bytes = try readFileAlloc(std.testing.allocator, auth_path);
    defer std.testing.allocator.free(bytes);
    try std.testing.expect(!codexAuthShouldRefresh(std.testing.allocator, bytes));
}

test "materializeChatgpt refuses expired codex token when refresh is unavailable" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const auth_file = try tmp.dir.createFile("auth.json", .{ .mode = 0o600 });
    try auth_file.writeAll(
        \\{"tokens":{"access_token":"h.eyJleHAiOjF9.s","account_id":"acc"}}
    );
    auth_file.close();

    const auth_path = try tmp.dir.realpathAlloc(std.testing.allocator, "auth.json");
    defer std.testing.allocator.free(auth_path);
    const config_dir = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(config_dir);

    const cfg_json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "providers": {{
        \\    "codex": {{
        \\      "kind": "codex",
        \\      "accounts": {{
        \\        "max-1": {{
        \\          "config_dir": "{s}",
        \\          "secret": {{ "backend": "file", "path": "{s}" }}
        \\        }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ,
        .{ config_dir, auth_path },
    );
    defer std.testing.allocator.free(cfg_json);

    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    try std.testing.expectError(
        broker_types.BrokerError.SecretUnavailable,
        materializeChatgpt(parsed.value, std.testing.allocator, "codex:max-1"),
    );
}

test "materializeChatgpt refuses stale codex token when refresh fails" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const auth_file = try tmp.dir.createFile("auth.json", .{ .mode = 0o600 });
    try auth_file.writeAll(
        \\{"tokens":{"access_token":"h.eyJleHAiOjF9.s","refresh_token":"rt","account_id":"acc"}}
    );
    auth_file.close();

    const auth_path = try tmp.dir.realpathAlloc(std.testing.allocator, "auth.json");
    defer std.testing.allocator.free(auth_path);
    const config_dir = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(config_dir);

    // The stale-token path calls refreshCodexAccountAuthFile, which takes a
    // real BLOCKING repair lock for codex:max-1 — the same lock name a live
    // operator session uses. Scope it to this test's tmp dir.
    var overrides = std.process.EnvMap.init(std.testing.allocator);
    defer overrides.deinit();
    try overrides.put("OMUX_RUNTIME_DIR", config_dir);
    env.test_overrides = &overrides;
    defer env.test_overrides = null;

    const cfg_json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "codex-test": {{
        \\      "name": "codex-test",
        \\      "auth": {{
        \\        "token_endpoint": "://invalid",
        \\        "client_id": "client"
        \\      }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "codex": {{
        \\      "kind": "codex-test",
        \\      "accounts": {{
        \\        "max-1": {{
        \\          "config_dir": "{s}",
        \\          "secret": {{ "backend": "file", "path": "{s}" }}
        \\        }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ,
        .{ config_dir, auth_path },
    );
    defer std.testing.allocator.free(cfg_json);

    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    try std.testing.expectError(
        broker_types.BrokerError.SecretUnavailable,
        materializeChatgpt(parsed.value, std.testing.allocator, "codex:max-1"),
    );
}

test "buildRefreshedCodexAuthJson preserves account id and retained refresh token" {
    const material = CodexAuthRefreshMaterial{
        .access_token = "old-access",
        .refresh_token = "old-refresh",
        .account_id = "acc-1",
        .id_token = "id-token",
        .auth_mode = "Chatgpt",
    };
    const refreshed = try buildRefreshedCodexAuthJson(std.testing.allocator, material, .{
        .access_token = "new-access",
        .refresh_token = null,
        .expires_in = 3600,
    });
    defer std.testing.allocator.free(refreshed);

    var parsed = try parseAuthJson(std.testing.allocator, refreshed);
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("new-access", parsed.access_token);
    try std.testing.expectEqualStrings("acc-1", parsed.account_id);

    var raw = try parseCodexAuthRefreshMaterial(std.testing.allocator, refreshed);
    defer raw.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("old-refresh", raw.refresh_token.?);
    try std.testing.expectEqualStrings("id-token", raw.id_token.?);
}

// ── pool population (above) ──────────────────────────────────────────

test "populatePool from JSON config" {
    const cfg_json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": { "priority": 30, "secret": { "backend": "file", "path": "/tmp/a" } },
        \\        "max-2": { "priority": 20, "secret": { "backend": "file", "path": "/tmp/b" } }
        \\      }
        \\    },
        \\    "claude": {
        \\      "kind": "claude-command",
        \\      "accounts": {
        \\        "personal": { "priority": 10, "secret": { "backend": "command", "command": ["true"] } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": { "providers": ["codex:max-1#codex-max", "codex:max-2#codex-max"] }
        \\  }
        \\}
    ;
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePool(&pool, parsed.value, null);

    try std.testing.expectEqual(@as(usize, 3), pool.accounts.items.len);
}

test "populatePool with profile filter narrows selectable" {
    const cfg_json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": { "priority": 30, "secret": { "backend": "file", "path": "/tmp/a" } },
        \\        "max-2": { "priority": 20, "secret": { "backend": "file", "path": "/tmp/b" } }
        \\      }
        \\    },
        \\    "claude": {
        \\      "kind": "claude-command",
        \\      "accounts": {
        \\        "personal": { "priority": 10, "secret": { "backend": "command", "command": ["true"] } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": { "providers": ["codex:max-1#codex-max", "codex:max-2#codex-max"] }
        \\  }
        \\}
    ;
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePool(&pool, parsed.value, "codex-max");

    try std.testing.expectEqual(@as(usize, 3), pool.accounts.items.len);

    const elected = try pool.elect(null, null, &.{});
    try std.testing.expect(std.mem.eql(u8, elected.id, "codex:max-1") or std.mem.eql(u8, elected.id, "codex:max-2"));

    var claude_present_and_blocked = false;
    for (pool.accounts.items) |a| {
        if (std.mem.eql(u8, a.id, "claude:personal")) {
            try std.testing.expect(!a.selectable);
            claude_present_and_blocked = true;
        }
    }
    try std.testing.expect(claude_present_and_blocked);
}

test "populatePoolFromRouteHealth mirrors broker-session-plan route health" {
    const cfg_json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": { "priority": 30, "secret": { "backend": "file", "path": "/tmp/a" } },
        \\        "max-2": { "priority": 20, "secret": { "backend": "file", "path": "/tmp/b" } },
        \\        "max-3": { "priority": 10, "secret": { "backend": "file", "path": "/tmp/c" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": { "providers": ["codex:max-1#codex-max", "codex:max-2#codex-max", "codex:max-3#codex-max"] }
        \\  }
        \\}
    ;
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    store.recordCapabilityHttpStatus("codex", "max-1", "codex-max", 429, 7200);
    _ = try store.getOrCreate("codex:max-2#codex-max");
    // max-3 has no route health and must not be silently admitted.

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealth(&pool, parsed.value, "codex-max", &store);

    const elected = try pool.elect(null, null, &.{});
    try std.testing.expectEqualStrings("codex:max-2", elected.id);

    for (pool.accounts.items) |entry| {
        if (std.mem.eql(u8, entry.id, "codex:max-1")) {
            try std.testing.expect(!entry.selectable);
            try std.testing.expectEqual(broker.account_pool_mod.Availability.quota_exhausted, entry.availability);
        }
        if (std.mem.eql(u8, entry.id, "codex:max-3")) {
            try std.testing.expect(!entry.selectable);
            try std.testing.expectEqual(broker.account_pool_mod.Availability.unknown, entry.availability);
        }
    }
}

test "populatePoolFromRouteHealthScoped keeps mixed-profile capabilities isolated" {
    const cfg_json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": { "priority": 30, "secret": { "backend": "file", "path": "/tmp/a" } },
        \\        "max-2": { "priority": 20, "secret": { "backend": "file", "path": "/tmp/b" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "mixed": { "providers": ["codex:max-1#codex-mini", "codex:max-1#codex-max", "codex:max-2#codex-max"] }
        \\  }
        \\}
    ;
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    store.recordCapabilityHttpStatus("codex", "max-1", "codex-max", 429, 7200);
    const mini = try store.getOrCreate("codex:max-1#codex-mini");
    mini.liveness = .{ .live = .{ .availability = .available } };
    mini.last_probe_hint_class = .none;
    mini.last_probe_decision = .use_this;
    const max2 = try store.getOrCreate("codex:max-2#codex-max");
    max2.liveness = .{ .live = .{ .availability = .available } };
    max2.last_probe_hint_class = .none;
    max2.last_probe_decision = .use_this;

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealthScoped(&pool, parsed.value, "mixed", "codex-max", &store);

    const elected = try pool.elect("mixed", "codex-max", &.{});
    try std.testing.expectEqualStrings("codex:max-2", elected.id);
    for (pool.accounts.items) |entry| {
        if (std.mem.eql(u8, entry.id, "codex:max-1")) {
            try std.testing.expect(!entry.selectable);
            try std.testing.expectEqual(broker.account_pool_mod.Availability.quota_exhausted, entry.availability);
        }
    }
}

test "populatePoolFromRouteHealthScoped degrades to fallback capability when requested route is blocked" {
    const cfg_json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": { "priority": 30, "secret": { "backend": "file", "path": "/tmp/a" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": {
        \\      "providers": ["codex:max-1#codex-max", "codex:max-1#codex-mini"],
        \\      "capability_degradation_chain": ["codex-mini"]
        \\    }
        \\  }
        \\}
    ;
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    store.recordCapabilityHttpStatus("codex", "max-1", "codex-max", 429, 7200);
    const mini = try store.getOrCreate("codex:max-1#codex-mini");
    mini.liveness = .{ .live = .{ .availability = .available } };
    mini.last_probe_hint_class = .none;
    mini.last_probe_decision = .use_this;

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealthScoped(&pool, parsed.value, "codex-max", "codex-max", &store);

    const elected = try pool.elect("codex-max", "codex-max", &.{});
    try std.testing.expectEqualStrings("codex:max-1", elected.id);
    try std.testing.expectEqualStrings("codex-mini", elected.capability.?);
    try std.testing.expect(elected.selectable);
    try std.testing.expectEqual(broker.account_pool_mod.Availability.available, elected.availability);
}

test "populatePoolFromRouteHealthScoped does not degrade around account-dead auth health" {
    const cfg_json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": { "priority": 30, "secret": { "backend": "file", "path": "/tmp/a" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": {
        \\      "providers": ["codex:max-1#codex-max", "codex:max-1#codex-mini"],
        \\      "capability_degradation_chain": ["codex-mini"]
        \\    }
        \\  }
        \\}
    ;
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    const account_health = try store.getOrCreate("codex:max-1");
    account_health.liveness = .{ .dead = .{
        .reason = .token_revoked,
        .since = std.time.timestamp() - 120,
    } };
    account_health.last_probe_hint_class = .auth_dead;
    account_health.last_probe_decision = .try_next_account;
    const mini = try store.getOrCreate("codex:max-1#codex-mini");
    mini.liveness = .{ .live = .{ .availability = .available } };
    mini.last_probe_hint_class = .none;
    mini.last_probe_decision = .use_this;

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealthScoped(&pool, parsed.value, "codex-max", "codex-max", &store);

    try std.testing.expectError(broker_types.BrokerError.NoAccountSelectable, pool.elect("codex-max", "codex-max", &.{}));
    try std.testing.expectEqual(broker.account_pool_mod.Liveness.dead, pool.accounts.items[0].liveness);
    try std.testing.expect(pool.accounts.items[0].capability == null);
}

test "populatePoolFromRouteHealth lets expired provider degradation yield to capability health" {
    const cfg_json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": { "priority": 30, "secret": { "backend": "file", "path": "/tmp/a" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": { "providers": ["codex:max-1#codex-max"] }
        \\  }
        \\}
    ;
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    const now = std.time.timestamp();
    const account_health = try store.getOrCreate("codex:max-1");
    account_health.liveness = .{ .degraded = .{
        .reason = .provider_degraded,
        .since = now - 120,
        .retry_at = now - 1,
    } };
    account_health.last_probe_hint_class = .provider_degraded;
    account_health.last_probe_decision = .try_next_provider;
    const capability_health = try store.getOrCreate("codex:max-1#codex-max");
    capability_health.liveness = .{ .live = .{ .availability = .available } };
    capability_health.last_probe_hint_class = .none;
    capability_health.last_probe_decision = .use_this;

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealth(&pool, parsed.value, "codex-max", &store);

    const elected = try pool.elect(null, null, &.{});
    try std.testing.expectEqualStrings("codex:max-1", elected.id);
    try std.testing.expectEqual(broker.account_pool_mod.Availability.available, elected.availability);
}

test "populatePoolFromRouteHealth lets expired account rate limit yield to capability health" {
    const cfg_json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": { "priority": 30, "secret": { "backend": "file", "path": "/tmp/a" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": { "providers": ["codex:max-1#codex-max"] }
        \\  }
        \\}
    ;
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    const now = std.time.timestamp();
    const account_health = try store.getOrCreate("codex:max-1");
    account_health.liveness = .{ .live = .{ .availability = .{ .rate_limited = .{
        .retry_after_s = 60,
        .limited_at = now - 120,
        .window = .unknown,
    } } } };
    account_health.last_probe_hint_class = .rate_limit;
    account_health.last_probe_decision = .wait_and_retry;
    const capability_health = try store.getOrCreate("codex:max-1#codex-max");
    capability_health.liveness = .{ .live = .{ .availability = .available } };
    capability_health.last_probe_hint_class = .none;
    capability_health.last_probe_decision = .use_this;

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealth(&pool, parsed.value, "codex-max", &store);

    const elected = try pool.elect(null, null, &.{});
    try std.testing.expectEqualStrings("codex:max-1", elected.id);
    try std.testing.expectEqual(broker.account_pool_mod.Availability.available, elected.availability);
}

test "populatePoolFromRouteHealth keeps auth-dead account health global" {
    const cfg_json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": { "priority": 30, "secret": { "backend": "file", "path": "/tmp/a" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": { "providers": ["codex:max-1#codex-max"] }
        \\  }
        \\}
    ;
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    const now = std.time.timestamp();
    const account_health = try store.getOrCreate("codex:max-1");
    account_health.liveness = .{ .dead = .{
        .reason = .token_revoked,
        .since = now - 120,
    } };
    account_health.last_probe_hint_class = .auth_dead;
    account_health.last_probe_decision = .try_next_account;
    const capability_health = try store.getOrCreate("codex:max-1#codex-max");
    capability_health.liveness = .{ .live = .{ .availability = .available } };
    capability_health.last_probe_hint_class = .none;
    capability_health.last_probe_decision = .use_this;

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealth(&pool, parsed.value, "codex-max", &store);

    try std.testing.expectError(broker_types.BrokerError.NoAccountSelectable, pool.elect(null, null, &.{}));
    try std.testing.expectEqual(broker.account_pool_mod.Liveness.dead, pool.accounts.items[0].liveness);
}

test "populatePoolFromRouteHealth treats newer auth material as route repair evidence" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const auth_file = try tmp.dir.createFile("auth.json", .{ .mode = 0o600 });
    try auth_file.writeAll(
        \\{"tokens":{"access_token":"AT","account_id":"AID"}}
    );
    auth_file.close();

    const auth_path = try tmp.dir.realpathAlloc(std.testing.allocator, "auth.json");
    defer std.testing.allocator.free(auth_path);
    const cfg_json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "providers": {{
        \\    "codex": {{
        \\      "kind": "codex",
        \\      "accounts": {{
        \\        "default": {{ "priority": 10, "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}}
        \\}}
    ,
        .{auth_path},
    );
    defer std.testing.allocator.free(cfg_json);
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    const health = try store.getOrCreate("codex:default");
    health.liveness = .{ .live = .{ .availability = .{ .quota_exhausted = .{
        .window_resets_at = 1_800_000_000,
        .exhausted_at = 1,
    } } } };
    health.last_probe_observed_at = 1;
    health.last_probe_source = .broker_run_live;
    health.last_probe_hint_class = .quota_exhausted;
    health.last_probe_decision = .try_next_account;

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealth(&pool, parsed.value, null, &store);

    const elected = try pool.elect(null, null, &.{});
    try std.testing.expectEqualStrings("codex:default", elected.id);
    try std.testing.expectEqual(broker.account_pool_mod.Availability.available, elected.availability);
}

// ── identity dedupe before election: tests (TIN-1822 / GH #338) ──────

fn writeTestCodexAuthFile(dir: std.fs.Dir, name: []const u8, account_id: []const u8) !void {
    const file = try dir.createFile(name, .{ .mode = 0o600 });
    defer file.close();
    var buf: [256]u8 = undefined;
    const bytes = try std.fmt.bufPrint(
        &buf,
        "{{\"tokens\":{{\"access_token\":\"AT\",\"refresh_token\":\"RT\",\"account_id\":\"{s}\"}}}}",
        .{account_id},
    );
    try file.writeAll(bytes);
}

/// Three-account codex-max fixture config: max-1 and max-4 are the GH #338
/// duplicate pair (same upstream identity), max-2 is the genuinely distinct
/// route enrolled only for the degraded codex-mini capability (TIN-1811 chain).
fn testDedupeConfigJson(
    allocator: std.mem.Allocator,
    max1_path: []const u8,
    max4_path: []const u8,
    max2_path: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        \\{{
        \\  "version": 1,
        \\  "providers": {{
        \\    "codex": {{
        \\      "kind": "codex",
        \\      "accounts": {{
        \\        "max-1": {{ "priority": 30, "secret": {{ "backend": "file", "path": "{s}" }} }},
        \\        "max-4": {{ "priority": 20, "secret": {{ "backend": "file", "path": "{s}" }} }},
        \\        "max-2": {{ "priority": 10, "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{
        \\    "codex-max": {{
        \\      "providers": ["codex:max-1#codex-max", "codex:max-4#codex-max", "codex:max-2#codex-mini"],
        \\      "capability_degradation_chain": ["codex-mini"]
        \\    }}
        \\  }}
        \\}}
    ,
        .{ max1_path, max4_path, max2_path },
    );
}

fn markTestCapabilityLive(store: *health_mod.HealthStore, key: []const u8, observed_at: ?i64) !void {
    const health = try store.getOrCreate(key);
    health.liveness = .{ .live = .{ .availability = .available } };
    health.last_probe_hint_class = .none;
    health.last_probe_decision = .use_this;
    health.last_probe_observed_at = observed_at;
}

fn writeTestClaudeIdentityProfile(dir: std.fs.Dir, account_uuid: []const u8) !void {
    var buf: [256]u8 = undefined;
    const bytes = try std.fmt.bufPrint(
        &buf,
        "{{\"oauthAccount\":{{\"accountUuid\":\"{s}\"}}}}",
        .{account_uuid},
    );
    try writeTestClaudeRawProfile(dir, bytes);
}

fn writeTestClaudeRawProfile(dir: std.fs.Dir, bytes: []const u8) !void {
    const file = try dir.createFile(".claude.json", .{ .mode = 0o600, .truncate = true });
    defer file.close();
    try file.writeAll(bytes);
}

fn testClaudeSingleConfigJson(allocator: std.mem.Allocator, config_dir: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        \\{{
        \\  "version": 1,
        \\  "providers": {{
        \\    "claude": {{
        \\      "kind": "claude",
        \\      "accounts": {{
        \\        "a": {{
        \\          "priority": 20,
        \\          "secret": {{ "backend": "env", "variable": "OMUX_TEST_CLAUDE_SECRET_A" }},
        \\          "config_dir": "{s}"
        \\        }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{
        \\    "claude-managed": {{ "providers": ["claude:a#claude-managed"] }}
        \\  }}
        \\}}
    ,
        .{config_dir},
    );
}

fn testClaudePairConfigJson(
    allocator: std.mem.Allocator,
    config_dir_a: []const u8,
    config_dir_b: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        \\{{
        \\  "version": 1,
        \\  "providers": {{
        \\    "claude": {{
        \\      "kind": "claude",
        \\      "accounts": {{
        \\        "a": {{
        \\          "priority": 20,
        \\          "secret": {{ "backend": "env", "variable": "OMUX_TEST_CLAUDE_SECRET_A" }},
        \\          "config_dir": "{s}"
        \\        }},
        \\        "b": {{
        \\          "priority": 10,
        \\          "secret": {{ "backend": "env", "variable": "OMUX_TEST_CLAUDE_SECRET_B" }},
        \\          "config_dir": "{s}"
        \\        }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{
        \\    "claude-managed": {{
        \\      "providers": ["claude:a#claude-managed", "claude:b#claude-managed"]
        \\    }}
        \\  }}
        \\}}
    ,
        .{ config_dir_a, config_dir_b },
    );
}

fn expectManagedClaudeIdentityClarityError(
    raw_a: ?[]const u8,
    raw_b: ?[]const u8,
) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir("a");
    try tmp.dir.makeDir("b");
    var profile_dir_a = try tmp.dir.openDir("a", .{});
    defer profile_dir_a.close();
    var profile_dir_b = try tmp.dir.openDir("b", .{});
    defer profile_dir_b.close();
    if (raw_a) |raw| try writeTestClaudeRawProfile(profile_dir_a, raw);
    if (raw_b) |raw| try writeTestClaudeRawProfile(profile_dir_b, raw);
    const dir_a = try tmp.dir.realpathAlloc(std.testing.allocator, "a");
    defer std.testing.allocator.free(dir_a);
    const dir_b = try tmp.dir.realpathAlloc(std.testing.allocator, "b");
    defer std.testing.allocator.free(dir_b);

    const cfg_json = try testClaudePairConfigJson(std.testing.allocator, dir_a, dir_b);
    defer std.testing.allocator.free(cfg_json);
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    try markTestCapabilityLive(&store, "claude:a#claude-managed", null);
    try markTestCapabilityLive(&store, "claude:b#claude-managed", null);

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealthScoped(
        &pool,
        parsed.value,
        "claude-managed",
        "claude-managed",
        &store,
    );
    try std.testing.expectError(
        error.ManagedClaudeIdentityClarityRequired,
        requireManagedClaudeIdentityClarity(&pool, parsed.value, "claude-managed"),
    );
}

test "identity dedupe: duplicate slot is never failover capacity (GH #338 / TIN-1822)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    // max-1 == max-4: one upstream identity enrolled twice. The shared
    // account-id claim is the repo golden input so this test also pins the
    // pool path into the shared sha256_12hex identity space.
    try writeTestCodexAuthFile(tmp.dir, "max-1.json", "acct-test");
    try writeTestCodexAuthFile(tmp.dir, "max-4.json", "acct-test");
    try writeTestCodexAuthFile(tmp.dir, "max-2.json", "acct-distinct-338");

    const p1 = try tmp.dir.realpathAlloc(std.testing.allocator, "max-1.json");
    defer std.testing.allocator.free(p1);
    const p4 = try tmp.dir.realpathAlloc(std.testing.allocator, "max-4.json");
    defer std.testing.allocator.free(p4);
    const p2 = try tmp.dir.realpathAlloc(std.testing.allocator, "max-2.json");
    defer std.testing.allocator.free(p2);
    const cfg_json = try testDedupeConfigJson(std.testing.allocator, p1, p4, p2);
    defer std.testing.allocator.free(cfg_json);
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    try markTestCapabilityLive(&store, "codex:max-1#codex-max", null);
    try markTestCapabilityLive(&store, "codex:max-4#codex-max", null);
    try markTestCapabilityLive(&store, "codex:max-2#codex-mini", null);

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealthScoped(&pool, parsed.value, "codex-max", "codex-max", &store);

    // Pool path golden: identity keys come from identity_hash.sha256_12hex
    // (same space as the codex inventory and the claude labeler).
    var max1_hash: ?[]const u8 = null;
    var max4_hash: ?[]const u8 = null;
    var max2_hash: ?[]const u8 = null;
    for (pool.accounts.items) |entry| {
        if (std.mem.eql(u8, entry.id, "codex:max-1")) max1_hash = entry.account_id_hash;
        if (std.mem.eql(u8, entry.id, "codex:max-4")) max4_hash = entry.account_id_hash;
        if (std.mem.eql(u8, entry.id, "codex:max-2")) max2_hash = entry.account_id_hash;
    }
    try std.testing.expectEqualStrings("660d25a9d7ee", max1_hash.?);
    try std.testing.expectEqualStrings("660d25a9d7ee", max4_hash.?);
    try std.testing.expect(!std.mem.eql(u8, max2_hash.?, max1_hash.?));

    // The keeper (first available slot of the identity) is still electable.
    const first = try pool.elect("codex-max", "codex-max", &.{});
    try std.testing.expectEqualStrings("codex:max-1", first.id);

    // The duplicate must NOT be the failover: excluding the keeper elects the
    // genuinely distinct degraded route, not the same account under another
    // name. Pre-dedupe election returned codex:max-4 here (proved by
    // disabling the applyIdentityDedupe call and observing this fail).
    const fallback = try pool.elect("codex-max", "codex-max", &.{"codex:max-1"});
    try std.testing.expectEqualStrings("codex:max-2", fallback.id);
    try std.testing.expectEqualStrings("codex-mini", fallback.capability.?);

    // The demoted duplicate keeps its health evidence but can never be
    // resurrected by the time-based recovery walk.
    for (pool.accounts.items) |entry| {
        if (std.mem.eql(u8, entry.id, "codex:max-4")) {
            try std.testing.expect(!entry.selectable);
            try std.testing.expectEqual(broker.account_pool_mod.Liveness.live, entry.liveness);
            try std.testing.expect(entry.next_eligible_at == null);
        }
    }
}

test "identity dedupe: stale live duplicate of a dead identity is demoted dead (GH #338)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTestCodexAuthFile(tmp.dir, "max-1.json", "acct-shared-338");
    try writeTestCodexAuthFile(tmp.dir, "max-4.json", "acct-shared-338");
    try writeTestCodexAuthFile(tmp.dir, "max-2.json", "acct-distinct-338");

    const p1 = try tmp.dir.realpathAlloc(std.testing.allocator, "max-1.json");
    defer std.testing.allocator.free(p1);
    const p4 = try tmp.dir.realpathAlloc(std.testing.allocator, "max-4.json");
    defer std.testing.allocator.free(p4);
    const p2 = try tmp.dir.realpathAlloc(std.testing.allocator, "max-2.json");
    defer std.testing.allocator.free(p2);
    const cfg_json = try testDedupeConfigJson(std.testing.allocator, p1, p4, p2);
    defer std.testing.allocator.free(cfg_json);
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    const now = std.time.timestamp();
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    // Fresh account-level death on max-1 (the AAS-locked / auth-failed shape).
    // The observation is stamped slightly in the future so the auth fixture
    // files written moments ago cannot trip the newer-auth-material repair
    // path (which has its own tests) and so the death evidence is strictly
    // newer than the duplicate's stale liveness.
    const dead = try store.getOrCreate("codex:max-1");
    dead.liveness = .{ .dead = .{ .reason = .token_revoked, .since = now - 120 } };
    dead.last_probe_hint_class = .auth_dead;
    dead.last_probe_decision = .try_next_account;
    dead.last_probe_observed_at = now + 60;
    // Stale live capability probe on the duplicate: pre-dedupe this presented
    // the SAME dead account as a live route.
    try markTestCapabilityLive(&store, "codex:max-4#codex-max", now - 7200);
    try markTestCapabilityLive(&store, "codex:max-2#codex-mini", null);

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealthScoped(&pool, parsed.value, "codex-max", "codex-max", &store);

    // Honest outcome: one dead identity — not one dead route plus one "live"
    // duplicate — and the genuinely distinct degraded route is elected.
    // Pre-dedupe election returned codex:max-4 here (proved by disabling the
    // applyIdentityDedupe call and observing this fail).
    const elected = try pool.elect("codex-max", "codex-max", &.{});
    try std.testing.expectEqualStrings("codex:max-2", elected.id);
    try std.testing.expectEqualStrings("codex-mini", elected.capability.?);

    for (pool.accounts.items) |entry| {
        if (std.mem.eql(u8, entry.id, "codex:max-4")) {
            try std.testing.expect(!entry.selectable);
            try std.testing.expectEqual(broker.account_pool_mod.Liveness.dead, entry.liveness);
        }
    }

    // Graph-level view of the same trap (identity_graph is the analysis the
    // dedupe consumes): the pair collides, the AAS lockout marks it
    // un-reauthable, and the capability keeps ONE distinct live identity.
    const slots = [_]ig.AccountSlot{
        .{ .account = "max-1", .provider = "codex", .capability = "codex-max", .account_id_hash = "38079d6acec6", .liveness = .dead, .reauthable = false },
        .{ .account = "max-4", .provider = "codex", .capability = "codex-max", .account_id_hash = "38079d6acec6", .liveness = .dead, .reauthable = false },
        .{ .account = "max-2", .provider = "codex", .capability = "codex-mini", .account_id_hash = "aaaaaaaaaaaa", .liveness = .live },
    };
    const collisions = try ig.duplicateCollisions(std.testing.allocator, &slots);
    defer ig.freeCollisions(std.testing.allocator, collisions);
    try std.testing.expectEqual(@as(usize, 1), collisions.len);
    try std.testing.expectEqual(@as(usize, 2), collisions[0].accounts.len);
    try std.testing.expect(collisions[0].any_unreauthable);
    try std.testing.expectEqual(@as(usize, 0), ig.distinctLiveIdentities(&slots, "codex", "codex-max"));
    try std.testing.expectEqual(@as(usize, 1), ig.distinctLiveIdentities(&slots, "codex", "codex-mini"));
}

test "identity dedupe: quota-exhausted duplicate identity waits once, not twice (TIN-1812)" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTestCodexAuthFile(tmp.dir, "max-1.json", "acct-shared-338");
    try writeTestCodexAuthFile(tmp.dir, "max-4.json", "acct-shared-338");

    const p1 = try tmp.dir.realpathAlloc(std.testing.allocator, "max-1.json");
    defer std.testing.allocator.free(p1);
    const p4 = try tmp.dir.realpathAlloc(std.testing.allocator, "max-4.json");
    defer std.testing.allocator.free(p4);
    const cfg_json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "providers": {{
        \\    "codex": {{
        \\      "kind": "codex",
        \\      "accounts": {{
        \\        "max-1": {{ "priority": 30, "secret": {{ "backend": "file", "path": "{s}" }} }},
        \\        "max-4": {{ "priority": 20, "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{
        \\    "codex-max": {{ "providers": ["codex:max-1#codex-max", "codex:max-4#codex-max"] }}
        \\  }}
        \\}}
    ,
        .{ p1, p4 },
    );
    defer std.testing.allocator.free(cfg_json);
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    const now = std.time.timestamp();
    const resets_at = now + 7200;
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    for ([_][]const u8{ "codex:max-1#codex-max", "codex:max-4#codex-max" }) |key| {
        const health = try store.getOrCreate(key);
        health.liveness = .{ .live = .{ .availability = .{ .quota_exhausted = .{
            .window_resets_at = resets_at,
            .exhausted_at = now - 60,
        } } } };
        health.last_probe_hint_class = .quota_exhausted;
        health.last_probe_decision = .try_next_account;
    }

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealthScoped(&pool, parsed.value, "codex-max", "codex-max", &store);

    // Quota is wait-and-continue (TIN-1812), never counted twice: nothing is
    // electable now, the keeper carries the identity's single reset window,
    // and the duplicate's recovery clock is cleared.
    try std.testing.expectError(broker_types.BrokerError.NoAccountSelectable, pool.elect("codex-max", "codex-max", &.{}));
    for (pool.accounts.items) |entry| {
        if (std.mem.eql(u8, entry.id, "codex:max-1")) {
            try std.testing.expectEqual(resets_at, entry.next_eligible_at.?);
        }
        if (std.mem.eql(u8, entry.id, "codex:max-4")) {
            try std.testing.expect(!entry.selectable);
            try std.testing.expect(entry.next_eligible_at == null);
        }
    }

    // After the window passes exactly ONE route of the identity returns.
    // Pre-dedupe, elect(exclude=keeper) returned codex:max-4 here — the same
    // exhausted account resurrected as apparent second capacity (proved by
    // disabling the applyIdentityDedupe call and observing this fail).
    pool.refreshTimeBased(resets_at + 1);
    const recovered = try pool.elect("codex-max", "codex-max", &.{});
    try std.testing.expectEqualStrings("codex:max-1", recovered.id);
    try std.testing.expectError(
        broker_types.BrokerError.NoAccountSelectable,
        pool.elect("codex-max", "codex-max", &.{"codex:max-1"}),
    );
}

/// Two-slot fixture config for the keeper-ranking tests: max-1 declared
/// first (pool order), max-4 second, both on the codex-max capability.
fn testDedupePairConfigJson(
    allocator: std.mem.Allocator,
    max1_path: []const u8,
    max4_path: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        \\{{
        \\  "version": 1,
        \\  "providers": {{
        \\    "codex": {{
        \\      "kind": "codex",
        \\      "accounts": {{
        \\        "max-1": {{ "priority": 30, "secret": {{ "backend": "file", "path": "{s}" }} }},
        \\        "max-4": {{ "priority": 20, "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{
        \\    "codex-max": {{ "providers": ["codex:max-1#codex-max", "codex:max-4#codex-max"] }}
        \\  }}
        \\}}
    ,
        .{ max1_path, max4_path },
    );
}

test "identity dedupe: dead duplicate never buries the identity's recovery clock (TIN-1822)" {
    // Review-blocker shape: max-1 (pool-order first) is DEAD with older
    // evidence; max-4 — the SAME identity — is quota-exhausted with FRESH
    // evidence and a reset clock. Death arbitration correctly concludes the
    // identity is alive (live evidence strictly newer), but the keeper must
    // then be the recoverable max-4, not the sticky-dead max-1: keeping the
    // dead slot would null max-4's clock and make the identity permanently
    // invisible to refreshTimeBased/elect for the life of the pool.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTestCodexAuthFile(tmp.dir, "max-1.json", "acct-shared-338");
    try writeTestCodexAuthFile(tmp.dir, "max-4.json", "acct-shared-338");

    const p1 = try tmp.dir.realpathAlloc(std.testing.allocator, "max-1.json");
    defer std.testing.allocator.free(p1);
    const p4 = try tmp.dir.realpathAlloc(std.testing.allocator, "max-4.json");
    defer std.testing.allocator.free(p4);
    const cfg_json = try testDedupePairConfigJson(std.testing.allocator, p1, p4);
    defer std.testing.allocator.free(cfg_json);
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    const now = std.time.timestamp();
    const resets_at = now + 7200;
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    // Death observed at T0 (stamped past the fixture files' mtime so the
    // newer-auth-material repair path stays out of this test's way).
    const dead = try store.getOrCreate("codex:max-1");
    dead.liveness = .{ .dead = .{ .reason = .token_revoked, .since = now - 120 } };
    dead.last_probe_hint_class = .auth_dead;
    dead.last_probe_decision = .try_next_account;
    dead.last_probe_observed_at = now + 60;
    // Quota exhaustion on the duplicate observed at T1 > T0, carrying the
    // identity's one reset window.
    const quota = try store.getOrCreate("codex:max-4#codex-max");
    quota.liveness = .{ .live = .{ .availability = .{ .quota_exhausted = .{
        .window_resets_at = resets_at,
        .exhausted_at = now - 60,
    } } } };
    quota.last_probe_hint_class = .quota_exhausted;
    quota.last_probe_decision = .try_next_account;
    quota.last_probe_observed_at = now + 120;

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealthScoped(&pool, parsed.value, "codex-max", "codex-max", &store);

    // Nothing electable during the wait window...
    try std.testing.expectError(broker_types.BrokerError.NoAccountSelectable, pool.elect("codex-max", "codex-max", &.{}));
    for (pool.accounts.items) |entry| {
        if (std.mem.eql(u8, entry.id, "codex:max-1")) {
            // The dead slot is the demoted duplicate, with durable evidence.
            try std.testing.expectEqual(broker.account_pool_mod.Liveness.dead, entry.liveness);
            try std.testing.expect(!entry.selectable);
            try std.testing.expectEqualStrings("codex:max-4", entry.duplicate_of.?);
        }
        if (std.mem.eql(u8, entry.id, "codex:max-4")) {
            // The keeper carries the identity's recovery clock.
            try std.testing.expectEqual(resets_at, entry.next_eligible_at.?);
            try std.testing.expect(entry.duplicate_of == null);
        }
    }

    // ...and after the window the identity comes BACK, exactly once. On the
    // pre-fix keeper (first-in-pool-order = the dead max-1) this returned
    // NoAccountSelectable forever: the dead keeper has no clock and the
    // demoted duplicate's clock was destroyed.
    pool.refreshTimeBased(resets_at + 1);
    const recovered = try pool.elect("codex-max", "codex-max", &.{});
    try std.testing.expectEqualStrings("codex:max-4", recovered.id);
    try std.testing.expectError(
        broker_types.BrokerError.NoAccountSelectable,
        pool.elect("codex-max", "codex-max", &.{"codex:max-4"}),
    );
}

test "identity dedupe: fresh quota evidence outranks a stale available duplicate (TIN-1822)" {
    // Same root cause as the dead-keeper blocker, softer consequence: a
    // STALE "available" probe on the pool-order-first duplicate must not
    // beat a FRESH quota_exhausted observation on its sibling — the slots
    // are one upstream account, so electing the stale-available slot is one
    // blind doomed attempt and the known reset clock is discarded.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTestCodexAuthFile(tmp.dir, "max-1.json", "acct-shared-338");
    try writeTestCodexAuthFile(tmp.dir, "max-4.json", "acct-shared-338");

    const p1 = try tmp.dir.realpathAlloc(std.testing.allocator, "max-1.json");
    defer std.testing.allocator.free(p1);
    const p4 = try tmp.dir.realpathAlloc(std.testing.allocator, "max-4.json");
    defer std.testing.allocator.free(p4);
    const cfg_json = try testDedupePairConfigJson(std.testing.allocator, p1, p4);
    defer std.testing.allocator.free(cfg_json);
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    const now = std.time.timestamp();
    const resets_at = now + 7200;
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    // Stale available probe on the first slot.
    try markTestCapabilityLive(&store, "codex:max-1#codex-max", now - 7200);
    // Fresh quota exhaustion on the duplicate (stamped past file mtime so
    // the auth-material repair path stays inert).
    const quota = try store.getOrCreate("codex:max-4#codex-max");
    quota.liveness = .{ .live = .{ .availability = .{ .quota_exhausted = .{
        .window_resets_at = resets_at,
        .exhausted_at = now - 60,
    } } } };
    quota.last_probe_hint_class = .quota_exhausted;
    quota.last_probe_decision = .try_next_account;
    quota.last_probe_observed_at = now + 60;

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealthScoped(&pool, parsed.value, "codex-max", "codex-max", &store);

    // Honest outcome: the identity WAITS from the known clock (pre-fix the
    // stale-available max-1 was kept and elected — an exhausted identity
    // presented as available).
    try std.testing.expectError(broker_types.BrokerError.NoAccountSelectable, pool.elect("codex-max", "codex-max", &.{}));
    for (pool.accounts.items) |entry| {
        if (std.mem.eql(u8, entry.id, "codex:max-1")) {
            try std.testing.expect(!entry.selectable);
            try std.testing.expectEqualStrings("codex:max-4", entry.duplicate_of.?);
        }
        if (std.mem.eql(u8, entry.id, "codex:max-4")) {
            try std.testing.expectEqual(resets_at, entry.next_eligible_at.?);
        }
    }

    pool.refreshTimeBased(resets_at + 1);
    const recovered = try pool.elect("codex-max", "codex-max", &.{});
    try std.testing.expectEqualStrings("codex:max-4", recovered.id);
}

test "identity dedupe: untimestamped death evidence is never laundered by stale liveness (TIN-1822)" {
    // Symmetric arbitration: unverifiable evidence launders in NEITHER
    // direction. A death observation with no timestamp cannot be ordered, so
    // no liveness can be proven strictly newer than it — the identity fails
    // closed as dead. Pre-fix, null death timestamps counted as epoch 0 and
    // ANY timestamped live duplicate (here 2h stale) kept the identity
    // electable.
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try writeTestCodexAuthFile(tmp.dir, "max-1.json", "acct-shared-338");
    try writeTestCodexAuthFile(tmp.dir, "max-4.json", "acct-shared-338");

    const p1 = try tmp.dir.realpathAlloc(std.testing.allocator, "max-1.json");
    defer std.testing.allocator.free(p1);
    const p4 = try tmp.dir.realpathAlloc(std.testing.allocator, "max-4.json");
    defer std.testing.allocator.free(p4);
    const cfg_json = try testDedupePairConfigJson(std.testing.allocator, p1, p4);
    defer std.testing.allocator.free(cfg_json);
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();

    const now = std.time.timestamp();
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    // Death with NO observation timestamp (the repair path needs a timestamp
    // to fire, so the fresh fixture file mtime cannot resurrect it).
    const dead = try store.getOrCreate("codex:max-1");
    dead.liveness = .{ .dead = .{ .reason = .token_revoked, .since = now - 120 } };
    dead.last_probe_hint_class = .auth_dead;
    dead.last_probe_decision = .try_next_account;
    dead.last_probe_observed_at = null;
    // Timestamped but stale live probe on the duplicate.
    try markTestCapabilityLive(&store, "codex:max-4#codex-max", now - 7200);

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealthScoped(&pool, parsed.value, "codex-max", "codex-max", &store);

    try std.testing.expectError(broker_types.BrokerError.NoAccountSelectable, pool.elect("codex-max", "codex-max", &.{}));
    for (pool.accounts.items) |entry| {
        if (std.mem.eql(u8, entry.id, "codex:max-4")) {
            try std.testing.expectEqual(broker.account_pool_mod.Liveness.dead, entry.liveness);
            try std.testing.expect(!entry.selectable);
            try std.testing.expectEqualStrings("codex:max-1", entry.duplicate_of.?);
        }
    }
}

test "Claude identity admission hashes a one-account managed pool" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir("a");
    var profile_dir = try tmp.dir.openDir("a", .{});
    defer profile_dir.close();
    try writeTestClaudeIdentityProfile(profile_dir, "acct-test");
    const dir_a = try tmp.dir.realpathAlloc(std.testing.allocator, "a");
    defer std.testing.allocator.free(dir_a);

    const cfg_json = try testClaudeSingleConfigJson(std.testing.allocator, dir_a);
    defer std.testing.allocator.free(cfg_json);
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    try markTestCapabilityLive(&store, "claude:a#claude-managed", null);

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealthScoped(
        &pool,
        parsed.value,
        "claude-managed",
        "claude-managed",
        &store,
    );

    try std.testing.expectEqual(@as(usize, 1), pool.accounts.items.len);
    const admitted = pool.accounts.items[0];
    try std.testing.expectEqualStrings("claude:a", admitted.id);
    try std.testing.expectEqualStrings("660d25a9d7ee", admitted.account_id_hash.?);
    try std.testing.expect(admitted.selectable);
    try std.testing.expect(admitted.duplicate_of == null);
    try requireManagedClaudeIdentityClarity(&pool, parsed.value, "claude-managed");
}

test "Claude identity dedupe keeps one alias for duplicate config dirs" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir("a");
    try tmp.dir.makeDir("b");
    var profile_dir_a = try tmp.dir.openDir("a", .{});
    defer profile_dir_a.close();
    var profile_dir_b = try tmp.dir.openDir("b", .{});
    defer profile_dir_b.close();
    try writeTestClaudeIdentityProfile(profile_dir_a, "same-claude-account");
    try writeTestClaudeIdentityProfile(profile_dir_b, "same-claude-account");
    const dir_a = try tmp.dir.realpathAlloc(std.testing.allocator, "a");
    defer std.testing.allocator.free(dir_a);
    const dir_b = try tmp.dir.realpathAlloc(std.testing.allocator, "b");
    defer std.testing.allocator.free(dir_b);

    const cfg_json = try testClaudePairConfigJson(std.testing.allocator, dir_a, dir_b);
    defer std.testing.allocator.free(cfg_json);
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    try markTestCapabilityLive(&store, "claude:a#claude-managed", null);
    try markTestCapabilityLive(&store, "claude:b#claude-managed", null);

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealthScoped(
        &pool,
        parsed.value,
        "claude-managed",
        "claude-managed",
        &store,
    );

    var keeper_id: ?[]const u8 = null;
    var alias_of: ?[]const u8 = null;
    var selectable_count: usize = 0;
    var alias_count: usize = 0;
    var shared_hash: ?[]const u8 = null;
    for (pool.accounts.items) |entry| {
        const hash = entry.account_id_hash.?;
        if (shared_hash) |expected| {
            try std.testing.expectEqualStrings(expected, hash);
        } else {
            shared_hash = hash;
        }
        if (entry.selectable) {
            selectable_count += 1;
            keeper_id = entry.id;
        }
        if (entry.duplicate_of) |keeper| {
            alias_count += 1;
            alias_of = keeper;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), selectable_count);
    try std.testing.expectEqual(@as(usize, 1), alias_count);
    try std.testing.expectEqualStrings(keeper_id.?, alias_of.?);

    const elected = try pool.elect("claude-managed", "claude-managed", &.{});
    try std.testing.expectEqualStrings(keeper_id.?, elected.id);
    const exclude = [_][]const u8{keeper_id.?};
    try std.testing.expectError(
        broker_types.BrokerError.NoAccountSelectable,
        pool.elect("claude-managed", "claude-managed", &exclude),
    );
    try requireManagedClaudeIdentityClarity(&pool, parsed.value, "claude-managed");
}

test "Claude identity dedupe preserves distinct config-dir identities" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makeDir("a");
    try tmp.dir.makeDir("b");
    var profile_dir_a = try tmp.dir.openDir("a", .{});
    defer profile_dir_a.close();
    var profile_dir_b = try tmp.dir.openDir("b", .{});
    defer profile_dir_b.close();
    try writeTestClaudeIdentityProfile(profile_dir_a, "claude-account-a");
    try writeTestClaudeIdentityProfile(profile_dir_b, "claude-account-b");
    const dir_a = try tmp.dir.realpathAlloc(std.testing.allocator, "a");
    defer std.testing.allocator.free(dir_a);
    const dir_b = try tmp.dir.realpathAlloc(std.testing.allocator, "b");
    defer std.testing.allocator.free(dir_b);

    const cfg_json = try testClaudePairConfigJson(std.testing.allocator, dir_a, dir_b);
    defer std.testing.allocator.free(cfg_json);
    var parsed = try config_mod.loadFromBytes(std.testing.allocator, cfg_json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    try markTestCapabilityLive(&store, "claude:a#claude-managed", null);
    try markTestCapabilityLive(&store, "claude:b#claude-managed", null);

    var pool = broker.AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try populatePoolFromRouteHealthScoped(
        &pool,
        parsed.value,
        "claude-managed",
        "claude-managed",
        &store,
    );

    var hash_a: ?[]const u8 = null;
    var hash_b: ?[]const u8 = null;
    var selectable_count: usize = 0;
    for (pool.accounts.items) |entry| {
        if (std.mem.eql(u8, entry.id, "claude:a")) hash_a = entry.account_id_hash;
        if (std.mem.eql(u8, entry.id, "claude:b")) hash_b = entry.account_id_hash;
        if (entry.selectable) selectable_count += 1;
        try std.testing.expect(entry.duplicate_of == null);
    }
    try std.testing.expectEqual(@as(usize, 2), selectable_count);
    try std.testing.expect(!std.mem.eql(u8, hash_a.?, hash_b.?));

    const first = try pool.elect("claude-managed", "claude-managed", &.{});
    const exclude = [_][]const u8{first.id};
    const second = try pool.elect("claude-managed", "claude-managed", &exclude);
    try std.testing.expect(!std.mem.eql(u8, first.id, second.id));
    try requireManagedClaudeIdentityClarity(&pool, parsed.value, "claude-managed");
}

test "managed Claude identity admission rejects hashless profile routes" {
    const valid =
        \\{"oauthAccount":{"accountUuid":"known-account"}}
    ;
    try expectManagedClaudeIdentityClarityError(valid, "{");
    try expectManagedClaudeIdentityClarityError("{", "{}");
    try expectManagedClaudeIdentityClarityError(null, null);
}

test "identity golden: codex claim and claude accountUuid hash into one sha256_12hex space (TIN-1822)" {
    const a = std.testing.allocator;
    const claude_identity = @import("identity/claude_identity.zig");

    // Codex producer: the tokens.account_id claim, hashed by the shared
    // module. Pins the repo golden through the provider-schema extractor.
    const codex_auth =
        \\{"tokens":{"access_token":"AT","account_id":"acct-test"}}
    ;
    const claim = (try provider_schema.identityClaimFromCredential(provider_schema.codex_def, codex_auth, a)).?;
    defer a.free(claim);
    const codex_hash = try identity_hash.sha256_12hex(a, claim);
    defer a.free(codex_hash);
    try std.testing.expectEqualStrings("660d25a9d7ee", codex_hash);

    // Claude producer: oauthAccount.accountUuid must land in the byte-identical
    // hash space (claude_identity re-derives sha256_12hex locally).
    const claude_same = try claude_identity.parseClaudeIdentity(a,
        \\{"oauthAccount":{"accountUuid":"acct-test"}}
    );
    defer claude_same.deinit(a);
    try std.testing.expect(claude_same.present);
    try std.testing.expectEqualStrings("660d25a9d7ee", claude_same.account_id_hash.?);

    // Second pinned vector (uuid-shaped, the real claude input class) so a
    // refactor cannot change the key derivation while preserving the single
    // legacy golden. sha256("0f7a2b1c-9e4d-4a3b-8c6f-2d5e7a9b1c3d")[0..6].
    const uuid = "0f7a2b1c-9e4d-4a3b-8c6f-2d5e7a9b1c3d";
    const codex_uuid_hash = try identity_hash.sha256_12hex(a, uuid);
    defer a.free(codex_uuid_hash);
    try std.testing.expectEqualStrings("7b29dfead5c3", codex_uuid_hash);
    const claude_uuid = try claude_identity.parseClaudeIdentity(a,
        \\{"oauthAccount":{"accountUuid":"0f7a2b1c-9e4d-4a3b-8c6f-2d5e7a9b1c3d"}}
    );
    defer claude_uuid.deinit(a);
    try std.testing.expectEqualStrings("7b29dfead5c3", claude_uuid.account_id_hash.?);
}
