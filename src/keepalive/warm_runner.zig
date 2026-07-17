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
//! The claude/codex providers declare the grant (TIN-2057), but admission still
//! requires the account to opt in (`allow_proactive_refresh: true`, defaults
//! false), so a warm loop over accounts that haven't opted in only records
//! refusals; the scheduler backs each off and marks it dead, the loop drains
//! harmlessly. Live-proven 2026-06-14 (TIN-2057).
//!
//! The actual timed wait + the CLI/daemon command that calls `bind.runLoop` are
//! the thin, untested-by-design wrapper (a real wait blocks on the daemon stop
//! condition); this file's pool-build + refresh adapter are unit-tested.

const std = @import("std");
const ws = @import("warm_scheduler.zig");
const bind = @import("warm_binding.zig");
const ig = @import("../identity/identity_graph.zig");
const claude_identity_source = @import("../identity/claude_identity_source.zig");
const pipeline = @import("../pipeline.zig");
const config_mod = @import("../config.zig");
const health_mod = @import("../health.zig");
const log = @import("../log.zig");
const repair_state = @import("../repair_state.zig");
const types = @import("../types.zig");

/// Context the binding's `DoRefreshFn`/`ClockFn` are bound to. Borrows the config
/// and health store for the loop's lifetime.
pub const WarmRunner = struct {
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    health: *health_mod.HealthStore,
    last_refresh_outcome: ?types.RefreshOutcome = null,
    last_refresh_quarantined: bool = false,

    /// `ws.ClockFn`: real wall clock in Unix ms.
    pub fn clock(ctx: *anyopaque) i64 {
        _ = ctx;
        return std.time.milliTimestamp();
    }

    /// `bind.DoRefreshFn`: proactively refresh one (provider, account) via
    /// `pipeline.refreshAccount`, building a fresh Context per call (deinit'd
    /// each call — no cross-tick state leak). Maps the pipeline outcome onto the
    /// scheduler's `RefreshError`: `OutOfMemory` → transient host pressure; any
    /// other failure → `RefreshFailed`, with the closed side channel preserving
    /// whether it is a typed transient or hard quarantine. On success the new
    /// expiry comes from the POST-rotation `ctx.token` (seconds → ms, saturating),
    /// so the scheduler re-arms honestly.
    pub fn doRefresh(ctx: *anyopaque, provider: []const u8, account: []const u8) ws.RefreshError!ws.RefreshResult {
        const self: *WarmRunner = @ptrCast(@alignCast(ctx));
        self.last_refresh_outcome = null;
        self.last_refresh_quarantined = false;
        var pctx = pipeline.Context.init(self.allocator, self.cfg, self.health);
        defer pctx.deinit();
        pctx.provider_name = provider;
        pctx.account_name = account;
        pipeline.refreshAccount(&pctx) catch |e| {
            self.last_refresh_outcome = pctx.last_refresh_outcome orelse switch (e) {
                error.OutOfMemory => .transient_store,
                else => .transient_endpoint,
            };
            self.last_refresh_quarantined = pctx.last_refresh_quarantined;
            return switch (e) {
                error.OutOfMemory => ws.RefreshError.OutOfMemory,
                else => ws.RefreshError.RefreshFailed,
            };
        };
        self.last_refresh_outcome = pctx.last_refresh_outcome;
        self.last_refresh_quarantined = pctx.last_refresh_quarantined;
        const tok = pctx.token orelse {
            if (self.last_refresh_outcome == null) {
                self.last_refresh_outcome = .transient_store;
            }
            return ws.RefreshError.RefreshFailed;
        };
        const exp_s = tok.expires_at orelse {
            if (self.last_refresh_outcome == null) {
                self.last_refresh_outcome = .transient_endpoint;
            }
            return ws.RefreshError.RefreshFailed;
        };
        if (self.last_refresh_outcome == null) {
            self.last_refresh_outcome = .refreshed;
        }
        return .{
            .new_last_refresh_ms = std.time.milliTimestamp(),
            .new_expires_at_ms = exp_s *| std.time.ms_per_s,
        };
    }

    pub fn refreshOutcome(ctx: *anyopaque) ?types.RefreshOutcome {
        const self: *WarmRunner = @ptrCast(@alignCast(ctx));
        return self.last_refresh_outcome;
    }

    pub fn refreshQuarantined(ctx: *anyopaque) bool {
        const self: *WarmRunner = @ptrCast(@alignCast(ctx));
        return self.last_refresh_quarantined;
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

/// Enumerate every configured (provider, account) with a readable expiry, plus
/// persisted hard quarantines, into a warm pool. A quarantined account is
/// admitted as already dead without reading its credential. Other accounts
/// whose credential is unreadable or carries no expiry are skipped. Keys are
/// "<provider>:<account>", arena-owned. Caller frees via `Pool.deinit`.
pub fn enumeratePool(
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    health: *health_mod.HealthStore,
) std.mem.Allocator.Error!Pool {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    // Pass 1: every account with a readable expiry, plus hard quarantines, becomes
    // a candidate carrying its key, expiry, closed refresh state, and stable
    // identity hash. Hard quarantine is checked before credential I/O. File-
    // scoped providers such as codex read the hash from the credential claim;
    // Claude reads it from `.claude.json`. A read failure/no-expiry skips a
    // non-quarantined account; an unreadable identity leaves the slot opaque.
    const Candidate = struct {
        key: []const u8,
        expires_at_ms: i64,
        id_hash: ?[]const u8,
        refresh_outcome: ?types.RefreshOutcome,
        quarantined: bool,
    };
    var candidates = std.ArrayList(Candidate).init(a);
    var prov_it = cfg.providers.map.iterator();
    while (prov_it.next()) |pe| {
        const prov = pe.key_ptr.*;
        var acct_it = pe.value_ptr.accounts.map.iterator();
        while (acct_it.next()) |ae| {
            const acct = ae.key_ptr.*;
            const key = try std.fmt.allocPrint(a, "{s}:{s}", .{ prov, acct });
            const refresh_quarantine = repair_state.effectiveRefreshQuarantineForRoute(
                allocator,
                prov,
                acct,
            ) catch {
                try candidates.append(.{
                    .key = key,
                    .expires_at_ms = 0,
                    .id_hash = null,
                    .refresh_outcome = .transient_store,
                    .quarantined = false,
                });
                continue;
            };
            if (refresh_quarantine) |state| {
                try candidates.append(.{
                    .key = key,
                    .expires_at_ms = 0,
                    .id_hash = null,
                    .refresh_outcome = switch (state) {
                        .hard_lineage_invalidated => .hard_lineage_invalidated,
                        .indeterminate_lineage => .transient_store,
                    },
                    .quarantined = true,
                });
                continue;
            }
            const refresh_outcome = repair_state.refreshOutcomeForRoute(
                allocator,
                prov,
                acct,
            ) catch {
                try candidates.append(.{
                    .key = key,
                    .expires_at_ms = 0,
                    .id_hash = null,
                    .refresh_outcome = .transient_store,
                    .quarantined = false,
                });
                continue;
            };
            var pctx = pipeline.Context.init(allocator, cfg, health);
            defer pctx.deinit();
            pctx.provider_name = prov;
            pctx.account_name = acct;
            const exp = (pipeline.readAccountExpiryMs(&pctx) catch null) orelse continue;
            var id_hash: ?[]const u8 = null;
            if (pipeline.readAccountIdentityHash(&pctx) catch null) |h| {
                defer allocator.free(h); // WE own `h` (ctx.allocator); free it after duping (incl. on the dupe's OOM)
                id_hash = try a.dupe(u8, h);
            } else if (config_mod.resolveProviderKind(cfg, prov)) |kind| {
                if (kind == .claude) {
                    id_hash = try claude_identity_source.readAccountIdentityHash(a, ae.value_ptr.config_dir);
                }
            }
            try candidates.append(.{
                .key = key,
                .expires_at_ms = exp,
                .id_hash = id_hash,
                .refresh_outcome = refresh_outcome,
                .quarantined = false,
            });
        }
    }

    // Pass 2 (TIN-2113): two accounts with the same identity hash share ONE
    // single-use refresh-token family — rotating either risks provider
    // family-revocation of the other (outside the per-host lock domain). So
    // EXCLUDE every colliding account from the warm pool. The identity graph's
    // duplicateCollisions does the grouping; the slot's `account` is the full key
    // so collisions report unambiguous "<provider>:<account>" names.
    var slots = std.ArrayList(ig.AccountSlot).init(a);
    for (candidates.items) |c| {
        try slots.append(.{ .account = c.key, .provider = "keepalive", .capability = "keepalive", .account_id_hash = c.id_hash, .liveness = .live });
    }
    const collisions = try ig.duplicateCollisions(a, slots.items); // arena-owned; freed with the arena
    var excluded = std.StringHashMap(void).init(a);
    for (collisions) |col| {
        for (col.accounts) |k| try excluded.put(k, {});
    }

    // Pass 3: build the pool, excluding colliding accounts (logged so the operator
    // sees why an account is not being warmed).
    var list = std.ArrayList(bind.Observed).init(a);
    for (candidates.items) |c| {
        if (excluded.contains(c.key)) {
            log.warn("keepalive: refusing to warm {s} — shares an OAuth identity with another enrolled account (single-use refresh-token family; family-revocation risk, TIN-2113); resolve the duplicate to enable", .{c.key});
            continue;
        }
        try list.append(.{
            .key = c.key,
            .expires_at_ms = c.expires_at_ms,
            .refresh_outcome = c.refresh_outcome,
            .quarantined = c.quarantined,
        });
    }
    return .{ .observed = try list.toOwnedSlice(), .arena = arena };
}

test "enumeratePool seeds persisted hard quarantine without reading the credential" {
    const allocator = std.testing.allocator;
    var scope = try repair_state.TestRuntimeDirScope.init(allocator);
    defer scope.deinit(allocator);
    scope.activate();

    const credential_path = try std.fs.path.join(
        allocator,
        &.{ scope.root, "lineage.json" },
    );
    defer allocator.free(credential_path);
    {
        const credential = try std.fs.createFileAbsolute(credential_path, .{
            .mode = 0o600,
        });
        defer credential.close();
        try credential.writeAll(
            "{\"access_token\":\"at\",\"refresh_token\":\"rt\",\"expires_at\":9000000000,\"account_id\":\"identity\"}",
        );
    }
    const config_json = try std.fmt.allocPrint(
        allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "repair": {{ "owner": "oauth_mux_refresh", "proactive_refresh": "oauth_refresh_token" }},
        \\      "credential": {{
        \\        "access_token_path": "access_token",
        \\        "refresh_token_path": "refresh_token",
        \\        "expires_at_path": "expires_at",
        \\        "identity_claim_path": "account_id"
        \\      }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{ "kind": "toy", "accounts": {{
        \\      "lineage": {{ "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\    }} }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ,
        .{credential_path},
    );
    defer allocator.free(config_json);
    const parsed = try config_mod.loadFromBytes(allocator, config_json);
    defer parsed.deinit();
    const acct_cfg = parsed.value.providers.map.get("toy").?.accounts.map.get("lineage").?;
    try repair_state.establishHardRefreshQuarantineForTest(
        allocator,
        "toy",
        "lineage",
        try config_mod.resolveSecretBackend(acct_cfg.secret),
        config_mod.resolveProviderDefinition(parsed.value, "toy"),
    );
    try std.fs.deleteFileAbsolute(credential_path);

    var health = health_mod.HealthStore.init(allocator, .{});
    defer health.deinit();
    var pool = try enumeratePool(allocator, parsed.value, &health);
    defer pool.deinit();
    try std.testing.expectEqual(@as(usize, 1), pool.observed.len);
    try std.testing.expectEqual(
        types.RefreshOutcome.hard_lineage_invalidated,
        pool.observed[0].refresh_outcome.?,
    );

    const accounts = try bind.buildPool(allocator, pool.observed, 10_000);
    defer allocator.free(accounts);
    try std.testing.expect(accounts[0].dead);
    try std.testing.expect(accounts[0].quarantined);
}
