const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");
const config_mod = @import("config.zig");
const secret = @import("secret.zig");
const provider = @import("provider.zig");
const provider_schema = @import("provider_schema.zig");
const health_mod = @import("health.zig");
const shell_mod = @import("shell.zig");
const paths = @import("paths.zig");
const log = @import("log.zig");
const oauth = @import("oauth.zig");
const probe = @import("probe.zig");
const env = @import("env.zig");
const repair_state = @import("repair_state.zig");
const runtime = @import("runtime.zig");
const identity_hash = @import("identity_hash.zig");

pub const Context = struct {
    allocator: std.mem.Allocator,
    cfg: config_mod.Config,
    profile_name: ?[]const u8 = null,
    provider_name: ?[]const u8 = null,
    provider_kind: ?types.ProviderKind = null,
    account_name: ?[]const u8 = null,
    capability_name: ?[]const u8 = null,
    token: ?provider.TokenFields = null,
    health: *health_mod.HealthStore,
    env_pairs: std.ArrayList([2][]const u8),
    allocated_values: std.ArrayList([]const u8),
    target_argv: []const []const u8 = &.{},
    shell: types.ShellKind = .posix,
    probe_only: bool = false,
    probe_recheck_blocked: bool = false,
    last_probe_executed: bool = false,
    last_probe_status: ?u16 = null,
    last_probe_decision: ?types.MuxDecision = null,
    // TIN-2039: set when a command-transport probe of a real account store
    // was skipped because the per-account lock was held by a live session —
    // the probe did NOT touch the store (codex could otherwise rewrite
    // auth.json under the live session). Surfaced as "lock_busy" in JSON.
    last_probe_lock_busy: bool = false,
    // TIN-2073: probe-budget callers (the daemon tick's probe phase) set
    // this false — they must never rotate tokens; rotation belongs to the
    // repair phase under admission + the per-account repair lock.
    allow_refresh_mutation: bool = true,
    // Diagnostics: the most recent closed refresh outcome plus a local-only
    // compatibility reason. Persisted/status surfaces receive only the enum.
    last_refresh_outcome: ?types.RefreshOutcome = null,
    last_refresh_reason: ?[]const u8 = null,
    last_refresh_quarantined: bool = false,

    pub fn init(allocator: std.mem.Allocator, cfg: config_mod.Config, store: *health_mod.HealthStore) Context {
        return .{
            .allocator = allocator,
            .cfg = cfg,
            .health = store,
            .env_pairs = std.ArrayList([2][]const u8).init(allocator),
            .allocated_values = std.ArrayList([]const u8).init(allocator),
        };
    }

    pub fn deinit(self: *Context) void {
        if (self.token) |tok| {
            self.allocator.free(tok.access_token);
            if (tok.refresh_token) |rt| self.allocator.free(rt);
        }
        for (self.allocated_values.items) |v| self.allocator.free(v);
        self.allocated_values.deinit();
        self.env_pairs.deinit();
    }

    fn addEnvOwned(self: *Context, key: []const u8, owned_value: []const u8) !void {
        self.allocated_values.append(owned_value) catch {
            self.allocator.free(owned_value);
            return error.OutOfMemory;
        };
        self.env_pairs.append(.{ key, owned_value }) catch return error.OutOfMemory;
    }
};

pub const PipelineError = types.PipelineError;

/// Full pipeline with retry-across-accounts.
/// For each candidate account: read → validate → if ok, inject.
/// On recoverable failure: mark account, try next.
/// On exhaustion of all accounts: return AllAccountsExhausted.
pub fn runExec(ctx: *Context) PipelineError!void {
    try resolveProvider(ctx);
    try selectWithFallback(ctx);
    try injectEnv(ctx);
}

pub fn runEnv(ctx: *Context) PipelineError!void {
    try resolveProvider(ctx);
    try selectWithFallback(ctx);
    try injectEnv(ctx);
}

pub fn runProbe(ctx: *Context) PipelineError!void {
    try resolveProvider(ctx);
    ctx.probe_only = true;
    defer ctx.probe_only = false;
    try selectWithFallback(ctx);
}

/// Proactively refresh ONE account's credential — the live seam the keepalive
/// warm loop binds to (TIN-1825 B.2). Resolves the provider kind from the
/// already-set `ctx.provider_name`, reads the account's refresh token from the
/// store, and rotates it via `attemptRefresh` — serialized under the per-account
/// and per-identity flock and field-preserving (TIN-2073/2074).
///
/// SAFE-BY-GATE: `attemptRefresh` calls `refreshWritebackBackend` FIRST, which
/// returns the typed `error.RefreshTransientStore` disposition for any account whose
/// provider `proactive_refresh` grant and operator `allow_proactive_refresh` are
/// not both admitted — BEFORE any network call or store write. So a warm loop
/// over builtins (which declare no grant) only records refusals; nothing is
/// rotated. On success `ctx.token` carries the new (access, refresh, expires_at).
///
/// Requires `ctx.provider_name` + `ctx.account_name`. Leak-safe: the snapshot set
/// into `ctx.token` is freed by `attemptRefresh` on the success/adopt paths and
/// by `Context.deinit` on the refusal/error paths.
pub fn refreshAccount(ctx: *Context) PipelineError!void {
    resolveProvider(ctx) catch |e| {
        ctx.last_refresh_outcome = .transient_store;
        ctx.last_refresh_reason = "refresh_route_unresolved";
        return e;
    };
    const prov = ctx.provider_name orelse {
        ctx.last_refresh_outcome = .transient_store;
        ctx.last_refresh_reason = "refresh_provider_missing";
        return error.ProviderNotFound;
    };
    const acct = ctx.account_name orelse {
        ctx.last_refresh_outcome = .transient_store;
        ctx.last_refresh_reason = "refresh_account_missing";
        return error.AccountNotFound;
    };
    if (try applyPersistedRefreshQuarantine(ctx, prov, acct)) {
        return error.TokenRefreshFailed;
    }
    ctx.token = readTokenSnapshot(ctx) catch |e| {
        ctx.last_refresh_outcome = .transient_store;
        ctx.last_refresh_reason = "refresh_store_unreadable";
        return e;
    };
    const rt = ctx.token.?.refresh_token orelse {
        ctx.last_refresh_outcome = .transient_store;
        ctx.last_refresh_reason = "refresh_token_missing";
        return error.RefreshTransientStore;
    };
    try attemptRefresh(ctx, rt);
}

/// Read one account's current credential expiry as absolute Unix MILLISECONDS for
/// the warm-loop pool (`warm_binding.Observed`), without mutating anything.
/// `TokenFields.expires_at` is normalized to seconds by the parser (claude's ms
/// `expiresAt` is divided down per `expires_at_unit`), so this scales seconds →
/// ms with a saturating multiply. Returns null when the credential carries no
/// expiry. Requires `ctx.provider_name` + `ctx.account_name`.
pub fn readAccountExpiryMs(ctx: *Context) PipelineError!?i64 {
    try resolveProvider(ctx);
    const snap = try readTokenSnapshot(ctx);
    defer freeTokenFields(ctx.allocator, snap);
    if (snap.expires_at) |exp_s| return exp_s *| std.time.ms_per_s;
    return null;
}

/// Read one account's stable identity as `sha256_12hex(account-id claim)`, for the
/// keepalive shared-identity guard (TIN-2113): two accounts with the same hash
/// share one single-use refresh-token family, so the warm loop must not rotate
/// either (provider family-revocation is outside the per-host lock domain).
/// Returns null when the provider declares no `identity_claim_path` (claude — its
/// identity lives in .claude.json, not the credential) or the claim is absent.
/// Caller OWNS the returned hash. Requires `ctx.provider_name` + `ctx.account_name`.
pub fn readAccountIdentityHash(ctx: *Context) PipelineError!?[]u8 {
    try resolveProvider(ctx);
    const prov = ctx.provider_name orelse return error.ProviderNotFound;
    const def = config_mod.resolveProviderDefinition(ctx.cfg, prov);
    const raw = try readSecretRaw(ctx);
    defer ctx.allocator.free(raw);
    const account_id = (provider_schema.identityClaimFromCredential(def, raw, ctx.allocator) catch null) orelse return null;
    defer ctx.allocator.free(account_id);
    return identity_hash.sha256_12hex(ctx.allocator, account_id) catch return error.OutOfMemory;
}

/// The retry loop: try each candidate account in priority order.
/// On failure, record the typed failure and move to the next candidate.
fn selectWithFallback(ctx: *Context) PipelineError!void {
    const candidates = gatherCandidates(ctx);
    if (candidates.len == 0) return error.AllAccountsExhausted;

    var last_err: PipelineError = error.AllAccountsExhausted;
    var skipped_providers: [32][]const u8 = undefined;
    var skipped_provider_count: usize = 0;

    for (candidates) |candidate| {
        if (providerWasSkipped(skipped_providers[0..skipped_provider_count], candidate.provider)) {
            log.debug("pipeline: skip {s}:{s} (provider already skipped)", .{ candidate.provider, candidate.account });
            continue;
        }

        const key = health_mod.accountKey(candidate.provider, candidate.account);
        ctx.provider_name = candidate.provider;
        ctx.account_name = candidate.account;
        ctx.capability_name = candidate.capability;
        ctx.provider_kind = config_mod.resolveProviderKind(ctx.cfg, candidate.provider);
        const route_quarantined = applyPersistedRefreshQuarantine(
            ctx,
            candidate.provider,
            candidate.account,
        ) catch |e| {
            last_err = e;
            log.warn("pipeline: skip {s}:{s} (refresh quarantine unreadable)", .{
                candidate.provider,
                candidate.account,
            });
            continue;
        };
        if (route_quarantined) {
            last_err = error.TokenRefreshFailed;
            log.warn("pipeline: skip {s}:{s} (refresh lineage quarantined)", .{
                candidate.provider,
                candidate.account,
            });
            continue;
        }
        const decision = ctx.health.muxDecisionFor(candidate.provider, candidate.account, candidate.capability);
        const bypass_health_gate = ctx.probe_only and ctx.probe_recheck_blocked;

        if (!bypass_health_gate) {
            switch (decision) {
                .try_next_account => {
                    log.debug("pipeline: skip {s}:{s} (health: try_next)", .{ candidate.provider, candidate.account });
                    continue;
                },
                .try_next_provider => {
                    if (skipped_provider_count < skipped_providers.len) {
                        skipped_providers[skipped_provider_count] = candidate.provider;
                        skipped_provider_count += 1;
                    }
                    log.debug("pipeline: skip {s}:{s} (health: try_next_provider)", .{ candidate.provider, candidate.account });
                    continue;
                },
                .give_up => {
                    log.debug("pipeline: skip {s}:{s} (health: give_up)", .{ candidate.provider, candidate.account });
                    continue;
                },
                .wait_and_retry => {
                    // Could wait, but for now try next account
                    log.debug("pipeline: skip {s}:{s} (health: rate limited)", .{ candidate.provider, candidate.account });
                    continue;
                },
                .use_this => {},
            }
        }

        if (ctx.probe_only and probePlanUsesNoCredential(ctx)) {
            const post_probe_decision = probeCapability(ctx) catch |e| {
                recordCandidateFailure(ctx, key.slice(), e);
                last_err = e;
                freeCurrentToken(ctx);
                continue;
            };
            switch (post_probe_decision) {
                .use_this => {},
                .try_next_provider => {
                    if (skipped_provider_count < skipped_providers.len) {
                        skipped_providers[skipped_provider_count] = candidate.provider;
                        skipped_provider_count += 1;
                    }
                    freeCurrentToken(ctx);
                    continue;
                },
                .try_next_account, .wait_and_retry, .give_up => {
                    freeCurrentToken(ctx);
                    continue;
                },
            }

            log.info("pipeline: using {s}:{s}", .{ candidate.provider, candidate.account });
            return;
        }

        // Try the read → validate path
        readSecret(ctx) catch |e| {
            recordCandidateFailure(ctx, key.slice(), e);
            last_err = e;
            freeCurrentToken(ctx);
            continue;
        };

        validateToken(ctx) catch |e| {
            recordCandidateFailure(ctx, key.slice(), e);
            last_err = e;
            freeCurrentToken(ctx);
            continue;
        };

        const post_probe_decision = probeCapability(ctx) catch |e| {
            recordCandidateFailure(ctx, key.slice(), e);
            last_err = e;
            freeCurrentToken(ctx);
            continue;
        };
        switch (post_probe_decision) {
            .use_this => {},
            .try_next_provider => {
                if (skipped_provider_count < skipped_providers.len) {
                    skipped_providers[skipped_provider_count] = candidate.provider;
                    skipped_provider_count += 1;
                }
                freeCurrentToken(ctx);
                continue;
            },
            .try_next_account, .wait_and_retry, .give_up => {
                freeCurrentToken(ctx);
                continue;
            },
        }

        // Success — this account works
        log.info("pipeline: using {s}:{s}", .{ candidate.provider, candidate.account });
        return;
    }

    return last_err;
}

fn providerWasSkipped(skipped_providers: []const []const u8, provider_name: []const u8) bool {
    for (skipped_providers) |skipped| {
        if (std.mem.eql(u8, skipped, provider_name)) return true;
    }
    return false;
}

fn freeCurrentToken(ctx: *Context) void {
    if (ctx.token) |tok| {
        ctx.allocator.free(tok.access_token);
        if (tok.refresh_token) |rt| ctx.allocator.free(rt);
    }
    ctx.token = null;
}

fn applyPersistedRefreshQuarantine(
    ctx: *Context,
    provider_name: []const u8,
    account_name: []const u8,
) PipelineError!bool {
    const quarantine = repair_state.effectiveRefreshQuarantineForRoute(
        ctx.allocator,
        provider_name,
        account_name,
    ) catch {
        ctx.last_refresh_outcome = .transient_store;
        ctx.last_refresh_reason = "refresh_quarantine_read_failed";
        ctx.last_refresh_quarantined = false;
        return error.RefreshTransientStore;
    };
    const state = quarantine orelse return false;
    if (state == .indeterminate_lineage) {
        ctx.last_refresh_outcome = .transient_store;
        ctx.last_refresh_reason = "refresh_lineage_indeterminate";
        ctx.last_refresh_quarantined = true;
        return error.RefreshLineageIndeterminate;
    }

    ctx.last_refresh_outcome = .hard_lineage_invalidated;
    ctx.last_refresh_reason = "refresh_lineage_quarantined";
    ctx.last_refresh_quarantined = true;
    const key = health_mod.accountKey(provider_name, account_name);
    ctx.health.recordFailure(key.slice(), .auth_failure);
    return true;
}

fn probePlanUsesNoCredential(ctx: *Context) bool {
    const capability = ctx.capability_name orelse return false;
    const prov = ctx.provider_name orelse return false;
    const def = config_mod.resolveProviderDefinition(ctx.cfg, prov);
    const plan = provider_schema.probePlanForCapability(def, capability) orelse return false;
    return plan.auth == .none;
}

fn recordCandidateFailure(ctx: *Context, key: []const u8, err: PipelineError) void {
    switch (err) {
        error.SecretReadFailed,
        error.SecretDecryptFailed,
        error.TokenParseFailed,
        error.TokenExpired,
        error.TokenRefreshFailed,
        error.RefreshQuarantinePersistenceFailed,
        error.TokenRevoked,
        => ctx.health.recordFailure(key, .auth_failure),
        error.RefreshTransientLock,
        error.RefreshTransientNetwork,
        error.RefreshTransientStore,
        error.RefreshTransientEndpoint,
        error.RefreshLineageIndeterminate,
        => {},
        error.RateLimited => ctx.health.recordFailure(key, .rate_limited),
        error.NetworkError => ctx.health.recordFailure(key, .timeout),
        error.ConfigNotFound,
        error.ConfigParseError,
        error.ConfigValidationError,
        error.RuntimeNotReady,
        => {},
        else => ctx.health.recordFailure(key, .error_response),
    }
}

const Candidate = struct {
    provider: []const u8,
    account: []const u8,
    capability: ?[]const u8 = null,
    priority: i32,
};

fn gatherCandidates(ctx: *Context) []const Candidate {
    // Static buffer — up to 32 candidates
    const S = struct {
        var buf: [32]Candidate = undefined;
    };
    var count: usize = 0;

    // If profile specified, use its provider:account list
    if (ctx.profile_name) |pname| {
        if (ctx.cfg.profiles.map.get(pname)) |profile| {
            for (profile.providers) |spec| {
                if (splitProviderAccount(spec)) |pa| {
                    // If provider filter set, skip non-matching
                    if (ctx.provider_name) |filter| {
                        if (!std.mem.eql(u8, pa.provider, filter)) continue;
                    }
                    if (ctx.account_name) |account_filter| {
                        if (!std.mem.eql(u8, pa.account, account_filter)) continue;
                    }
                    if (count < S.buf.len) {
                        const prov_cfg = ctx.cfg.providers.map.get(pa.provider) orelse continue;
                        const acct_cfg = prov_cfg.accounts.map.get(pa.account) orelse continue;
                        S.buf[count] = .{
                            .provider = pa.provider,
                            .account = pa.account,
                            .capability = pa.capability orelse ctx.capability_name,
                            .priority = acct_cfg.priority,
                        };
                        count += 1;
                    }
                }
            }
        }
    }

    // If no profile or profile yielded nothing, gather from provider config
    if (count == 0) {
        const prov_name = ctx.provider_name orelse ctx.cfg.defaults.provider orelse return S.buf[0..0];
        const prov_cfg = ctx.cfg.providers.map.get(prov_name) orelse return S.buf[0..0];

        if (ctx.account_name) |account_filter| {
            if (prov_cfg.accounts.map.get(account_filter)) |acct_cfg| {
                if (count < S.buf.len) {
                    S.buf[count] = .{
                        .provider = prov_name,
                        .account = account_filter,
                        .capability = ctx.capability_name,
                        .priority = acct_cfg.priority,
                    };
                    count += 1;
                }
            }
        } else {
            var it = prov_cfg.accounts.map.iterator();
            while (it.next()) |entry| {
                if (count < S.buf.len) {
                    S.buf[count] = .{
                        .provider = prov_name,
                        .account = entry.key_ptr.*,
                        .capability = ctx.capability_name,
                        .priority = entry.value_ptr.priority,
                    };
                    count += 1;
                }
            }
        }
    }

    // Sort by priority descending (insertion sort, small N)
    var i: usize = 1;
    while (i < count) : (i += 1) {
        var j = i;
        while (j > 0 and S.buf[j].priority > S.buf[j - 1].priority) {
            const tmp = S.buf[j];
            S.buf[j] = S.buf[j - 1];
            S.buf[j - 1] = tmp;
            j -= 1;
        }
    }

    return S.buf[0..count];
}

fn resolveProvider(ctx: *Context) PipelineError!void {
    // If provider already set (from CLI flag), use it
    if (ctx.provider_name != null) {
        if (ctx.provider_name) |name| {
            ctx.provider_kind = config_mod.resolveProviderKind(ctx.cfg, name);
        }
        return;
    }

    // Try auto-detecting from target command
    if (ctx.target_argv.len > 0) {
        if (provider.detectProvider(ctx.target_argv)) |kind| {
            ctx.provider_kind = kind;
            ctx.provider_name = @tagName(kind);
            log.debug("pipeline: auto-detected provider {s}", .{kind.displayName()});
            return;
        }
    }

    // A profile supplies an ordered mux lane. Leave provider_name unset here so
    // gatherCandidates can fan out across every provider listed in the profile.
    // Explicit --provider and target-command detection are handled above and
    // still act as provider filters.
    if (ctx.profile_name) |pname| {
        if (ctx.cfg.profiles.map.get(pname)) |profile| {
            if (profile.providers.len > 0) return;
        }
    }

    // Fall back to config default
    if (ctx.cfg.defaults.provider) |def| {
        ctx.provider_name = def;
        ctx.provider_kind = config_mod.resolveProviderKind(ctx.cfg, def);
        return;
    }

    return error.ProviderNotFound;
}

fn readSecret(ctx: *Context) PipelineError!void {
    ctx.token = try readTokenSnapshot(ctx);
}

// Reads + parses the account's credential store WITHOUT touching ctx.token.
// Used both for the initial load (readSecret) and the under-lock
// revalidation in attemptRefresh (TIN-2073), where the pre-lock ctx.token
// must stay live while the fresh snapshot is examined.
fn readTokenSnapshot(ctx: *Context) PipelineError!provider.TokenFields {
    const raw = try readSecretRaw(ctx);
    defer ctx.allocator.free(raw);
    return parseRawToken(ctx, raw);
}

fn readSecretRaw(ctx: *Context) PipelineError![]const u8 {
    const prov_name = ctx.provider_name orelse return error.ProviderNotFound;
    const acct_name = ctx.account_name orelse return error.AccountNotFound;

    const prov_cfg = ctx.cfg.providers.map.get(prov_name) orelse return error.ProviderNotFound;
    const acct_cfg = prov_cfg.accounts.map.get(acct_name) orelse return error.AccountNotFound;

    const backend = config_mod.resolveSecretBackend(acct_cfg.secret) catch return error.ConfigParseError;

    return secret.read(backend, ctx.allocator) catch |e| {
        log.err("secret: {s}:{s}: {s}", .{ prov_name, acct_name, @errorName(e) });
        return error.SecretReadFailed;
    };
}

fn parseRawToken(ctx: *Context, raw: []const u8) PipelineError!provider.TokenFields {
    const prov_name = ctx.provider_name orelse return error.ProviderNotFound;
    const acct_name = ctx.account_name orelse return error.AccountNotFound;
    const def = config_mod.resolveProviderDefinition(ctx.cfg, prov_name);
    const generic = provider_schema.parseTokenGeneric(def, raw, ctx.allocator) catch {
        log.debug("token: schema parse failed for {s}:{s}, trying legacy parser", .{ prov_name, acct_name });
        const kind = ctx.provider_kind orelse return error.ProviderNotFound;
        return provider.parseToken(kind, raw, ctx.allocator) catch {
            log.err("token: parse failed for {s}:{s}", .{ prov_name, acct_name });
            return error.TokenParseFailed;
        };
    };
    return .{
        .access_token = generic.access_token,
        .refresh_token = generic.refresh_token,
        .token_type = generic.token_type,
        .expires_at = generic.expires_at,
    };
}

fn freeTokenFields(allocator: std.mem.Allocator, tok: provider.TokenFields) void {
    allocator.free(tok.access_token);
    if (tok.refresh_token) |token_rt| allocator.free(token_rt);
}

fn validateToken(ctx: *Context) PipelineError!void {
    const tok = ctx.token orelse return error.TokenParseFailed;
    const prov = ctx.provider_name orelse return error.ProviderNotFound;
    const acct = ctx.account_name orelse return error.AccountNotFound;

    // API keys don't expire
    if (tok.token_type == .api_key) {
        const key = health_mod.accountKey(prov, acct);
        ctx.health.recordSuccess(key.slice());
        ctx.health.recordProbeEvidence(key.slice(), .credential_validation, null, .none, .use_this);
        return;
    }

    // Check expiry (with 30s skew to refresh before actual expiry)
    if (tok.expires_at) |exp| {
        const now = std.time.timestamp();
        if (now >= exp - 30) {
            if (tok.refresh_token) |rt| {
                if (!ctx.allow_refresh_mutation) {
                    // TIN-2073: a probe-budget caller must not rotate
                    // tokens. Record the typed deferral; a token that is
                    // merely inside the skew window stays usable, an
                    // actually-expired one fails closed for the repair
                    // phase to handle under admission + lock.
                    log.info("token: refresh needed for {s}:{s} but caller budget is non-mutating; deferring", .{ prov, acct });
                    const def = config_mod.resolveProviderDefinition(ctx.cfg, prov);
                    if (refreshWritebackBackend(ctx, def)) |writeback| {
                        recordTypedRefreshEvent(ctx, writeback.plan, .transient_store, "refresh_requires_mutating_budget", false, false);
                    } else |_| {}
                    if (now >= exp) return error.TokenExpired;
                } else {
                    log.info("token: expired for {s}:{s}, attempting refresh", .{ prov, acct });
                    try attemptRefresh(ctx, rt);
                }
            } else {
                return error.TokenExpired;
            }
        }
    }

    const key = health_mod.accountKey(prov, acct);
    ctx.health.recordSuccess(key.slice());
    ctx.health.recordProbeEvidence(key.slice(), .credential_validation, null, .none, .use_this);
}

fn probeCapability(ctx: *Context) PipelineError!types.MuxDecision {
    const capability = ctx.capability_name orelse return .use_this;
    const prov = ctx.provider_name orelse return error.ProviderNotFound;
    const acct = ctx.account_name orelse return error.AccountNotFound;
    const def = config_mod.resolveProviderDefinition(ctx.cfg, prov);
    const plan = provider_schema.probePlanForCapability(def, capability) orelse return .use_this;
    const access_token = if (ctx.token) |tok|
        tok.access_token
    else switch (plan.auth) {
        .none => "",
        else => return error.TokenParseFailed,
    };

    // TIN-2039: a command-transport probe spawns the native CLI (codex exec)
    // INSIDE the account's real store when the account has a config_dir, and
    // the CLI may refresh + rewrite auth.json mid-probe. ACQUIRE the
    // per-account lock and HOLD it across the probe so it never races a live
    // managed session of the same account in another process (the lock is
    // the same key the session/refresh paths use → cross-process). Acquired
    // BEFORE the readiness check so a held lock is reported authoritatively
    // as lock_busy (not the advisory repair_in_progress, which is a
    // check-then-release with a TOCTOU window). Held → skip entirely: no
    // store access, no health poison. HTTP-transport probes touch no store
    // and are unaffected.
    var probe_store_lock: ?repair_state.RepairLock = null;
    defer if (probe_store_lock) |*l| l.release();
    if (plan.transport == .command) {
        const store_guarded = probeTargetsRealAccountStore(ctx, prov, acct, def);
        if (store_guarded) {
            probe_store_lock = repair_state.acquireRepairLock(ctx.allocator, prov, acct) catch |e| switch (e) {
                error.RepairInProgress => {
                    log.warn("probe: {s}:{s} store lock held by a live session; skipping store probe (lock_busy)", .{ prov, acct });
                    ctx.last_probe_executed = false;
                    ctx.last_probe_lock_busy = true;
                    // No store access, no new evidence — preserve the
                    // account's existing recorded decision rather than poison
                    // health on a benign "busy" outcome.
                    const decision = ctx.health.muxDecisionFor(prov, acct, capability);
                    ctx.last_probe_decision = decision;
                    return decision;
                },
                else => return error.RuntimeNotReady,
            };
        }
        // Readiness check: skip the advisory repair-lock probe when we
        // already hold the lock (it would falsely conflict with ourselves).
        const route_ref = runtime.RouteRef{ .provider = prov, .account = acct, .capability = capability };
        const readiness = (if (store_guarded)
            runtime.routeReadinessHoldingLock(ctx.allocator, ctx.cfg, route_ref, def)
        else
            runtime.routeReadiness(ctx.allocator, ctx.cfg, route_ref, def)) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.RuntimeNotReady,
        };
        if (!readiness.isReady()) return error.RuntimeNotReady;
    }

    var probe_env = buildProbeEnv(ctx, prov, acct, def, plan) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.ConfigValidationError,
    };
    defer probe_env.deinit();

    const result = probe.execute(ctx.allocator, plan, access_token, probe_env.pairs.items) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        error.UnsupportedMethod, error.UnsupportedTransport => return error.ConfigValidationError,
        error.NetworkError => return error.NetworkError,
    };
    defer result.deinit(ctx.allocator);

    const classification = probe.classifyResult(ctx.allocator, def, plan, result);
    ctx.last_probe_executed = true;
    ctx.last_probe_status = result.status;
    var evidence_key: health_mod.KeyBuf = undefined;
    // Effect boundary (TIN-2407 P0): one clock read for this probe result, threaded
    // into whichever arm records the classification.
    const now_s = std.time.timestamp();
    switch (classification) {
        .dead => {
            const key = health_mod.accountKey(prov, acct);
            ctx.health.recordHttpClassification(key.slice(), result.status, classification, now_s);
            evidence_key = key;
        },
        else => {
            const key = health_mod.capabilityKey(prov, acct, capability);
            ctx.health.recordHttpClassification(key.slice(), result.status, classification, now_s);
            evidence_key = key;
        },
    }

    const decision = ctx.health.muxDecisionFor(prov, acct, capability);
    ctx.last_probe_decision = decision;
    ctx.health.recordProbeEvidence(
        evidence_key.slice(),
        .capability_probe,
        result.retry_after_s orelse health_mod.retryAfterFromClassification(classification),
        health_mod.hintClassFromClassification(classification),
        decision,
    );
    return decision;
}

const ProbeEnv = struct {
    allocator: std.mem.Allocator,
    pairs: std.ArrayList([2][]const u8),
    allocated_values: std.ArrayList([]const u8),

    fn init(allocator: std.mem.Allocator) ProbeEnv {
        return .{
            .allocator = allocator,
            .pairs = std.ArrayList([2][]const u8).init(allocator),
            .allocated_values = std.ArrayList([]const u8).init(allocator),
        };
    }

    fn deinit(self: *ProbeEnv) void {
        for (self.allocated_values.items) |value| self.allocator.free(value);
        self.allocated_values.deinit();
        self.pairs.deinit();
    }

    fn addOwned(self: *ProbeEnv, key: []const u8, owned_value: []const u8) !void {
        self.allocated_values.append(owned_value) catch {
            self.allocator.free(owned_value);
            return error.OutOfMemory;
        };
        self.pairs.append(.{ key, owned_value }) catch return error.OutOfMemory;
    }

    fn addBorrowed(self: *ProbeEnv, key: []const u8, value: []const u8) !void {
        self.pairs.append(.{ key, value }) catch return error.OutOfMemory;
    }
};

// TIN-2039: true when a command-transport probe will run the native CLI in
// the account's real store (config_dir set + a config-dir env to point it
// there) — i.e. the CLI can mutate that store's auth.json mid-probe and must
// be serialized against a live session. Mirrors buildProbeEnv's config-dir
// gate so the lock is taken exactly when the store would be touched.
fn probeTargetsRealAccountStore(ctx: *Context, prov: []const u8, acct: []const u8, def: provider_schema.ProviderDefinition) bool {
    const prov_cfg = ctx.cfg.providers.map.get(prov) orelse return false;
    const acct_cfg = prov_cfg.accounts.map.get(acct) orelse return false;
    if (acct_cfg.config_dir == null) return false;
    return providerConfigDirEnv(prov_cfg, def, ctx.provider_kind) != null;
}

fn buildProbeEnv(
    ctx: *Context,
    prov: []const u8,
    acct: []const u8,
    def: provider_schema.ProviderDefinition,
    plan: provider_schema.ProbePlan,
) !ProbeEnv {
    var probe_env = ProbeEnv.init(ctx.allocator);
    errdefer probe_env.deinit();

    if (plan.transport != .command) return probe_env;

    const prov_cfg = ctx.cfg.providers.map.get(prov) orelse return error.ProviderNotFound;
    const acct_cfg = prov_cfg.accounts.map.get(acct) orelse return error.AccountNotFound;
    const config_dir_env = providerConfigDirEnv(prov_cfg, def, ctx.provider_kind);

    if (acct_cfg.config_dir) |dir| {
        if (config_dir_env) |env_var| {
            const expanded = paths.expandTilde(ctx.allocator, dir) catch return error.OutOfMemory;
            try probe_env.addOwned(env_var, expanded);
        }
    }

    try probe_env.addBorrowed("OMUX_ACTIVE_PROVIDER", prov);
    try probe_env.addBorrowed("OMUX_ACTIVE_ACCOUNT", acct);
    try probe_env.addBorrowed("OMUX_ACTIVE_CAPABILITY", plan.capability);
    if (ctx.profile_name) |profile| try probe_env.addBorrowed("OMUX_ACTIVE_PROFILE", profile);
    try addProbeReauthEnv(ctx, &probe_env, prov, acct);

    return probe_env;
}

fn addProbeReauthEnv(ctx: *Context, probe_env: *ProbeEnv, prov: []const u8, acct: []const u8) !void {
    const job = try repair_state.reauthJobAlloc(ctx.allocator, prov, acct);
    try probe_env.addOwned("OMUX_REAUTH_JOB", job);
    const lock_dir = try repair_state.reauthLocksDir(ctx.allocator);
    try probe_env.addOwned("OMUX_REAUTH_LOCK_DIR", lock_dir);
    const ui_url = (try env.get(ctx.allocator, "OMUX_REAUTH_UI_URL")) orelse try ctx.allocator.dupe(u8, "");
    try probe_env.addOwned("OMUX_REAUTH_UI_URL", ui_url);
}

pub const FlockRefreshFailure = repair_state.LockedRefreshFailure;
pub const FlockRefreshAttempt = repair_state.LockedRefreshAttempt;
pub const FlockRefreshError = repair_state.LockedRefreshError;

/// Perform one refresh while the current actor owns the account flock. Hard
/// lineage can only emerge from repair_state's proof-complete operation, which
/// binds the configured canonical store, exact before/after identity and refresh
/// token values, account + identity flock ownership, endpoint evidence, and the
/// durable quarantine commit. No proof primitive crosses this boundary.
pub fn refreshTokenHoldingFlock(
    ctx: *Context,
    token_url: []const u8,
    submitted_refresh_token: []const u8,
    client_id: ?[]const u8,
    metadata: repair_state.HardRefreshEventMetadata,
) FlockRefreshError!FlockRefreshAttempt {
    const prov = ctx.provider_name orelse return .{ .failed = .{
        .outcome = .transient_store,
        .endpoint_executed = false,
    } };
    const acct = ctx.account_name orelse return .{ .failed = .{
        .outcome = .transient_store,
        .endpoint_executed = false,
    } };
    const prov_cfg = ctx.cfg.providers.map.get(prov) orelse return .{ .failed = .{
        .outcome = .transient_store,
        .endpoint_executed = false,
    } };
    const acct_cfg = prov_cfg.accounts.map.get(acct) orelse return .{ .failed = .{
        .outcome = .transient_store,
        .endpoint_executed = false,
    } };
    const backend = config_mod.resolveSecretBackend(acct_cfg.secret) catch
        return .{ .failed = .{
            .outcome = .transient_store,
            .endpoint_executed = false,
        } };
    const def = config_mod.resolveProviderDefinition(ctx.cfg, prov);
    return repair_state.refreshTokenWithLockedLineage(
        ctx.allocator,
        prov,
        acct,
        backend,
        def,
        token_url,
        submitted_refresh_token,
        client_id,
        .{
            .profile = ctx.profile_name,
            .capability = ctx.capability_name,
            .writeback_capability = metadata.writeback_capability,
            .automatic_refresh_admitted = metadata.automatic_refresh_admitted,
        },
    );
}

fn adoptFailClosedHardRefreshOutcome(
    ctx: *Context,
    reason: []const u8,
) void {
    ctx.last_refresh_outcome = .hard_lineage_invalidated;
    ctx.last_refresh_reason = reason;
    ctx.last_refresh_quarantined = true;
    if (ctx.provider_name) |prov| {
        if (ctx.account_name) |acct| {
            const key = health_mod.accountKey(prov, acct);
            ctx.health.recordFailure(key.slice(), .auth_failure);
        }
    }
}

fn refreshPipelineError(
    outcome: types.RefreshOutcome,
    quarantined: bool,
) PipelineError {
    if (quarantined and outcome != .hard_lineage_invalidated) {
        return error.RefreshLineageIndeterminate;
    }
    return switch (outcome) {
        .refreshed => unreachable,
        .transient_lock => error.RefreshTransientLock,
        .transient_network => error.RefreshTransientNetwork,
        .transient_store => error.RefreshTransientStore,
        .transient_endpoint => error.RefreshTransientEndpoint,
        .hard_lineage_invalidated => error.TokenRefreshFailed,
    };
}

fn refreshMetadata(plan: secret.WritebackPlan) repair_state.HardRefreshEventMetadata {
    return .{
        .writeback_capability = @tagName(plan.capability),
        .automatic_refresh_admitted = plan.automatic_refresh_admitted,
    };
}

fn attemptRefresh(ctx: *Context, rt: []const u8) PipelineError!void {
    const prov = ctx.provider_name orelse return error.ProviderNotFound;
    const acct = ctx.account_name orelse return error.AccountNotFound;
    const def = config_mod.resolveProviderDefinition(ctx.cfg, prov);
    const writeback = try refreshWritebackBackend(ctx, def);

    // TIN-2073: serialize against every other mux-owned writer to this
    // account's credential store (repair run, daemon repair, broker, and
    // adapter session flows take the same per-(provider,account) flock).
    // Upstream CLI logins (e.g. `oauth-mux codex login` wrapping the vendor
    // CLI) are user-mediated writes outside this lock domain — lock-aware
    // readiness for those is the TIN-1806 lane. Nonblocking: a held lock
    // means another rotation is in flight — racing it is the refresh-token
    // self-revocation failure mode, so defer typed instead.
    var refresh_lock = repair_state.acquireRepairLock(ctx.allocator, prov, acct) catch |e| switch (e) {
        error.RepairInProgress => {
            log.warn("token: refresh deferred for {s}:{s}: repair lock held", .{ prov, acct });
            recordTypedRefreshEvent(ctx, writeback.plan, .transient_lock, "refresh_lock_held", false, false);
            // Inside the 30s skew the current token is still provider-valid:
            // keep serving it so a benign in-flight peer rotation does not
            // poison route health as an auth failure. Only an actually
            // expired token fails closed.
            if (ctx.token) |tok| {
                if (tok.expires_at) |exp| {
                    if (std.time.timestamp() < exp) return;
                }
            }
            return refreshPipelineError(.transient_lock, false);
        },
        else => {
            recordTypedRefreshEvent(ctx, writeback.plan, .transient_lock, @errorName(e), false, false);
            return refreshPipelineError(.transient_lock, false);
        },
    };
    defer refresh_lock.release();

    // TIN-2073 (review): revalidate under the lock — the broker's
    // lock-then-revalidate pattern. The rt argument was read BEFORE the
    // flock; a peer's rotation may have completed inside that window. If the
    // re-read RT DIFFERS from the pre-lock rt (a peer actually rotated) — or its
    // expiry advanced past ours — adopt it and skip the endpoint; otherwise
    // (same RT, still-our-token) rotate with the re-read refresh token, never the
    // pre-lock snapshot. Keying on RT-change (not mere freshness) is what lets the
    // proactive keepalive loop rotate a still-valid same-RT token (TIN-1825).
    const existing_raw: ?[]const u8 = readSecretRaw(ctx) catch null;
    defer if (existing_raw) |r| ctx.allocator.free(r);
    const fresh_snapshot: ?provider.TokenFields = if (existing_raw) |r| (parseRawToken(ctx, r) catch null) else null;
    var fresh_adopted = false;
    defer if (fresh_snapshot) |f| {
        if (!fresh_adopted) freeTokenFields(ctx.allocator, f);
    };
    // TIN-2073 (revised for TIN-1825 proactive keepalive): adopt-and-skip ONLY
    // when a PEER ACTUALLY ROTATED, witnessed by the under-lock re-read RT
    // DIFFERING from the pre-lock `rt` we were handed (or, belt-and-suspenders,
    // its expiry advancing past ours). The OLD predicate keyed on freshness alone
    // (now < exp-30), which is ALWAYS true for the warm loop's proactive call
    // (token hours from expiry) → it skipped EVERY proactive refresh. Keying on
    // RT-change lets a still-valid SAME-RT token fall through to a real rotation
    // (proactive 75% keepalive), while a genuine peer rotation still
    // short-circuits (no double-rotation of one single-use chain). Sound because
    // Claude/Codex are single-use-RT and rewrite the stored RT on every rotation;
    // the `expiry_advanced` arm covers a hypothetical non-RT-rotating provider's
    // expiry-only peer refresh. effective_rt (below) already prefers the re-read
    // RT, so the fall-through rotation never replays the pre-lock snapshot.
    if (fresh_snapshot) |f| {
        // A null re-read RT is `false` (not a peer rotation): unreachable for the
        // single-use-RT providers this guards, and a fall-through then rotates
        // under the grant + identity + field-preserving guards — never a replay.
        const peer_rotated = if (f.refresh_token) |frt| !std.mem.eql(u8, frt, rt) else false;
        const expiry_advanced = blk: {
            const pre = (ctx.token orelse break :blk false).expires_at orelse break :blk false;
            const reread = f.expires_at orelse break :blk false;
            break :blk reread > pre;
        };
        if (peer_rotated or expiry_advanced) {
            if (ctx.token) |old| freeTokenFields(ctx.allocator, old);
            ctx.token = f;
            fresh_adopted = true;
            log.info("token: concurrent rotation detected for {s}:{s}; adopted fresh credential", .{ prov, acct });
            recordTypedRefreshEvent(ctx, writeback.plan, .refreshed, "concurrent_rotation_detected", true, false);
            return;
        }
    }
    const effective_rt = if (fresh_snapshot) |f| (f.refresh_token orelse rt) else rt;

    // TIN-2074: the field-preserving writeback needs the existing store to
    // merge into. If the under-lock re-read failed, refuse BEFORE spending
    // a refresh-token rotation we could only persist by clobbering the
    // canonical store the CLI reads with a lossy template. The refresh path
    // always has a pre-existing credential (the refresh token came from
    // it), so a null here is a transient store-read failure, not bootstrap.
    const raw_for_merge = existing_raw orelse {
        log.err("token: refusing refresh for {s}: credential store unreadable under lock", .{prov});
        recordTypedRefreshEvent(ctx, writeback.plan, .transient_store, "store_unreadable_refusing_lossy_write", false, false);
        return refreshPipelineError(.transient_store, false);
    };

    // TIN-2043: serialize against any LIVE SESSION (or background refresh)
    // of the same UPSTREAM IDENTITY, even when it is enrolled under a
    // different config account (the live max-1 == max-4 Apple-ID shape). The
    // per-account flock above does not cover that — two config accounts map
    // to two different account locks but one shared single-use RT chain. Key
    // the identity flock exactly as the managed session does
    // (`("<provider>-identity", sha256_12(account_id))`), nonblocking: a held
    // lock means a live session owns the chain's rotation, so defer typed —
    // a warm refresh is never urgent. Lock order matches the adapter:
    // per-account (held) then identity, no inversion. Released by defer.
    var identity_lock: ?repair_state.RepairLock = null;
    defer if (identity_lock) |*l| l.release();
    if (def.credential.identity_claim_path != null) {
        const account_id = (provider_schema.identityClaimFromCredential(def, raw_for_merge, ctx.allocator) catch null) orelse {
            // Declared an identity path but the store carries no id: refuse
            // rather than skip the duplicate-identity guard (the managed
            // session refuses launch on a missing id; match that posture so
            // a malformed store cannot dodge the guard). claude declares no
            // path and is unaffected.
            log.err("token: refusing refresh for {s}:{s}: identity claim unresolved", .{ prov, acct });
            recordTypedRefreshEvent(ctx, writeback.plan, .transient_store, "identity_unresolved_refusing_refresh", false, false);
            return refreshPipelineError(.transient_store, false);
        };
        defer ctx.allocator.free(account_id);
        const id_hash = identity_hash.sha256_12hex(ctx.allocator, account_id) catch return error.OutOfMemory;
        defer ctx.allocator.free(id_hash);
        const identity_domain = std.fmt.allocPrint(ctx.allocator, "{s}-identity", .{prov}) catch return error.OutOfMemory;
        defer ctx.allocator.free(identity_domain);
        identity_lock = repair_state.acquireRepairLock(ctx.allocator, identity_domain, id_hash) catch |e| switch (e) {
            error.RepairInProgress => {
                log.warn("token: refresh deferred for {s}:{s}: identity lock held by a live session", .{ prov, acct });
                recordTypedRefreshEvent(ctx, writeback.plan, .transient_lock, "identity_lock_held", false, false);
                // Token still valid inside the skew → keep serving it.
                if (ctx.token) |tok| {
                    if (tok.expires_at) |exp| {
                        if (std.time.timestamp() < exp) return;
                    }
                }
                return refreshPipelineError(.transient_lock, false);
            },
            else => {
                recordTypedRefreshEvent(ctx, writeback.plan, .transient_lock, @errorName(e), false, false);
                return refreshPipelineError(.transient_lock, false);
            },
        };
    }

    const url = def.auth.token_endpoint orelse fallbackRefreshUrl(ctx) orelse {
        log.warn("token: no refresh URL for {s}", .{prov});
        recordTypedRefreshEvent(ctx, writeback.plan, .transient_endpoint, "token_endpoint_missing", false, false);
        return refreshPipelineError(.transient_endpoint, false);
    };

    // oauth.refreshToken bounds the post-connect send/recv legs with a
    // 30s socket deadline (TIN-2074, posix only), so the dominant hang
    // mode — server accepts then stalls — can no longer wedge the held
    // flock indefinitely. Residual: DNS/TCP-connect/TLS-handshake are
    // bounded only by the OS TCP timeout, and Windows has no deadline
    // (winsock SO_RCVTIMEO takes DWORD ms, gated off). Acceptable while
    // builtin grants stay off; revisit if a connect-phase stall proves
    // material before the flip.
    const attempt = refreshTokenHoldingFlock(
        ctx,
        url,
        effective_rt,
        def.auth.client_id,
        refreshMetadata(writeback.plan),
    ) catch |e| {
        log.err("token: refresh failed: {s}", .{@errorName(e)});
        if (e == error.RefreshQuarantinePersistenceFailed) {
            adoptFailClosedHardRefreshOutcome(
                ctx,
                "refresh_quarantine_persistence_failed",
            );
            return error.RefreshQuarantinePersistenceFailed;
        }
        const outcome: types.RefreshOutcome = switch (e) {
            error.OutOfMemory => .transient_store,
            error.RefreshQuarantinePersistenceFailed => unreachable,
        };
        recordTypedRefreshEvent(ctx, writeback.plan, outcome, @errorName(e), false, false);
        return refreshPipelineError(outcome, false);
    };
    var success = switch (attempt) {
        .refreshed => |refreshed| refreshed,
        .failed => |failure| {
            if (failure.outcome == .hard_lineage_invalidated) {
                adoptFailClosedHardRefreshOutcome(
                    ctx,
                    "refresh_lineage_invalidated",
                );
            } else {
                recordTypedRefreshEvent(
                    ctx,
                    writeback.plan,
                    failure.outcome,
                    "token_endpoint_rejected",
                    false,
                    failure.endpoint_executed,
                );
                ctx.last_refresh_quarantined = failure.lineage_quarantined;
            }
            return refreshPipelineError(
                failure.outcome,
                failure.lineage_quarantined,
            );
        },
    };
    defer success.releaseStoreLock();
    const result = success.result;
    errdefer ctx.allocator.free(result.access_token);
    errdefer if (result.refresh_token) |new_rt| ctx.allocator.free(new_rt);

    const expires_at = if (result.expires_in) |ei| std.time.timestamp() + ei else null;
    const retained_refresh_token = switch (success.refresh_token_disposition) {
        .endpoint_rotated => result.refresh_token.?,
        .submitted_reused => ctx.allocator.dupe(u8, effective_rt) catch
            return error.OutOfMemory,
    };
    errdefer if (success.refresh_token_disposition == .submitted_reused) {
        ctx.allocator.free(retained_refresh_token);
    };

    // TIN-2074: field-preserving writeback. Merge the refreshed token
    // fields into the existing credential so store fields the token
    // response does not own (claude scopes/subscriptionType/rateLimitTier,
    // codex tokens.id_token/last_refresh) survive the rotation.
    //
    // FAIL CLOSED, never lossy: if the merge cannot apply (non-object /
    // unexpected-shape store — e.g. a flat claude store where a wrapper is
    // declared), falling back to the bootstrap template would overwrite the
    // canonical store the CLI reads with a blob missing every preserved
    // field — the exact corruption TIN-2074 exists to prevent. Refuse and
    // keep the store intact and leave lineage quarantined.
    // (buildCredentialGeneric remains the legitimate writer only for first-time
    // injection of a fresh tmpdir credential, in injectEnv — a different path
    // with no existing store.)
    const schema_token = provider_schema.TokenFields{
        .access_token = result.access_token,
        // Omission under an explicitly reusable-token policy means the token
        // endpoint did not own this field. Let the merge preserve the
        // under-lock canonical value rather than rewriting it from a response
        // that did not contain it.
        .refresh_token = switch (success.refresh_token_disposition) {
            .endpoint_rotated => retained_refresh_token,
            .submitted_reused => null,
        },
        .expires_at = expires_at,
    };
    const credential = provider_schema.mergeCredentialGeneric(def, raw_for_merge, schema_token, ctx.allocator) catch |e| {
        log.err("token: refusing lossy writeback for {s}: merge failed ({s})", .{ prov, @errorName(e) });
        recordQuarantinedRefreshEvent(ctx, writeback.plan, .transient_store, "merge_failed_refusing_lossy_write", false, true);
        return refreshPipelineError(.transient_store, true);
    };
    defer ctx.allocator.free(credential);

    secret.writeReplace(writeback.backend, credential, ctx.allocator) catch |e| {
        log.err("token: refresh writeback failed for {s}: {s}", .{ prov, @errorName(e) });
        recordQuarantinedRefreshEvent(ctx, writeback.plan, .transient_store, @errorName(e), false, true);
        return refreshPipelineError(.transient_store, true);
    };
    success.credentialPersisted(ctx.allocator) catch |e| {
        log.err("token: refresh quarantine clear failed for {s}: {s}", .{ prov, @errorName(e) });
        recordQuarantinedRefreshEvent(ctx, writeback.plan, .transient_store, "refresh_quarantine_clear_failed", false, true);
        return refreshPipelineError(.transient_store, true);
    };

    // Update the token in context
    if (ctx.token) |old| {
        ctx.allocator.free(old.access_token);
        if (old.refresh_token) |old_rt| ctx.allocator.free(old_rt);
    }
    ctx.token = .{
        .access_token = result.access_token,
        .refresh_token = retained_refresh_token,
        .expires_at = expires_at,
    };

    recordTypedRefreshEvent(ctx, writeback.plan, .refreshed, writeback.plan.reason, true, true);
    log.info("token: refreshed successfully", .{});
}

const RefreshWriteback = struct {
    backend: types.SecretBackend,
    plan: secret.WritebackPlan,
};

fn refreshWritebackBackend(
    ctx: *Context,
    def: provider_schema.ProviderDefinition,
) PipelineError!RefreshWriteback {
    const prov = ctx.provider_name orelse return error.ProviderNotFound;
    const acct = ctx.account_name orelse return error.AccountNotFound;
    const prov_cfg = ctx.cfg.providers.map.get(prov) orelse return error.ProviderNotFound;
    const acct_cfg = prov_cfg.accounts.map.get(acct) orelse return error.AccountNotFound;
    const backend = config_mod.resolveSecretBackend(acct_cfg.secret) catch return error.ConfigValidationError;

    // TIN-2054 (criterion #2): NEVER rotate the canonical/shared Claude
    // keychain item. The unsuffixed `Claude Code-credentials` service is what
    // bare Claude Code uses when CLAUDE_CONFIG_DIR is unset — i.e. the user's
    // own credential outside oauth-mux. A managed account configured with that
    // exact service (e.g. a pre-TIN-2070 `omux init` starter) would, on a
    // proactive refresh, rotate the user's bare-Claude refresh token — the
    // dual-writer self-revocation hazard against a credential oauth-mux does
    // not own. Refuse: the account must point at a per-config-dir SUFFIXED
    // service (the enroll/derivation path produces one). Defense in depth —
    // it holds even if the grant and consent gates are ever misconfigured.
    if (backend == .keychain and std.mem.eql(u8, backend.keychain.service, provider_schema.claude_keychain_service_base)) {
        const plan = secret.WritebackPlan{
            .capability = secret.writeCapability(backend),
            .automatic_refresh_admitted = false,
            .reason = "writeback_refused_canonical_keychain_item",
        };
        log.err("token: refusing refresh writeback for {s}:{s}: targets the canonical shared keychain item '{s}' (the bare-Claude credential) — use a per-config-dir suffixed service", .{ prov, acct, provider_schema.claude_keychain_service_base });
        recordRefreshEvent(ctx, plan, "not_admitted", plan.reason, false, false);
        return error.TokenRefreshFailed;
    }

    const plan = secret.writebackPlan(backend, def.repair.owner, .{
        .provider_supports_refresh = def.repair.proactive_refresh != .unsupported,
        .account_opted_in = acct_cfg.allow_proactive_refresh,
    });
    if (!plan.automatic_refresh_admitted) {
        log.warn("token: refresh writeback not admitted for {s}:{s}: {s}", .{ prov, acct, plan.reason });
        recordTypedRefreshEvent(ctx, plan, .transient_store, plan.reason, false, false);
        return error.RefreshTransientStore;
    }
    return .{
        .backend = backend,
        .plan = plan,
    };
}

fn recordRefreshEvent(
    ctx: *Context,
    plan: secret.WritebackPlan,
    outcome: []const u8,
    reason: ?[]const u8,
    ok: bool,
    executed: bool,
) void {
    std.debug.assert(std.mem.eql(u8, outcome, "not_admitted"));
    std.debug.assert(!ok and !executed);
    ctx.last_refresh_outcome = null;
    ctx.last_refresh_reason = reason;
    ctx.last_refresh_quarantined = false;
    persistCanonicalKeychainRefusalEvent(ctx, plan, outcome, reason);
}

fn recordTypedRefreshEvent(
    ctx: *Context,
    plan: secret.WritebackPlan,
    outcome: types.RefreshOutcome,
    reason: ?[]const u8,
    ok: bool,
    executed: bool,
) void {
    std.debug.assert(outcome != .hard_lineage_invalidated);
    ctx.last_refresh_outcome = outcome;
    ctx.last_refresh_reason = reason;
    ctx.last_refresh_quarantined = false;
    persistRefreshEvent(ctx, plan, outcome, ok, executed);
}

fn persistCanonicalKeychainRefusalEvent(
    ctx: *Context,
    plan: secret.WritebackPlan,
    outcome: []const u8,
    reason: ?[]const u8,
) void {
    repair_state.appendEvent(ctx.allocator, .{
        .kind = "token_refresh",
        .profile = ctx.profile_name,
        .provider = ctx.provider_name,
        .account = ctx.account_name,
        .capability = ctx.capability_name,
        .action = "refresh",
        .writeback_capability = @tagName(plan.capability),
        .automatic_refresh_admitted = plan.automatic_refresh_admitted,
        .outcome = outcome,
        .reason = reason,
        .ok = false,
        .executed = false,
        .interactive = false,
        .mutating = false,
    }) catch {};
}

fn recordQuarantinedRefreshEvent(
    ctx: *Context,
    plan: secret.WritebackPlan,
    outcome: types.RefreshOutcome,
    reason: ?[]const u8,
    ok: bool,
    executed: bool,
) void {
    std.debug.assert(outcome != .hard_lineage_invalidated);
    ctx.last_refresh_outcome = outcome;
    ctx.last_refresh_reason = reason;
    ctx.last_refresh_quarantined = true;
    persistRefreshEvent(ctx, plan, outcome, ok, executed);
}

fn persistRefreshEvent(
    ctx: *Context,
    plan: secret.WritebackPlan,
    outcome: types.RefreshOutcome,
    ok: bool,
    executed: bool,
) void {
    if (comptime builtin.is_test) return;
    const provider_name = ctx.provider_name orelse return;
    const account_name = ctx.account_name orelse return;
    repair_state.appendEvent(ctx.allocator, repair_state.refreshEvent(.{
        .profile = ctx.profile_name,
        .provider = provider_name,
        .account = account_name,
        .capability = ctx.capability_name,
        .writeback_capability = @tagName(plan.capability),
        .automatic_refresh_admitted = plan.automatic_refresh_admitted,
        .outcome = outcome,
        .ok = ok,
        .executed = executed,
        .mutating = executed,
    })) catch {};
}

fn fallbackRefreshUrl(ctx: *Context) ?[]const u8 {
    const kind = ctx.provider_kind orelse return null;
    return oauth.refreshUrl(kind);
}

fn injectEnv(ctx: *Context) PipelineError!void {
    const tok = ctx.token orelse return error.TokenParseFailed;
    const prov_name = ctx.provider_name orelse return error.ProviderNotFound;
    const acct_name = ctx.account_name orelse return error.AccountNotFound;
    const def = config_mod.resolveProviderDefinition(ctx.cfg, prov_name);

    // Check for persistent config_dir on the account
    const prov_cfg = ctx.cfg.providers.map.get(prov_name) orelse return error.ProviderNotFound;
    const acct_cfg = prov_cfg.accounts.map.get(acct_name) orelse return error.AccountNotFound;
    const config_dir_env = providerConfigDirEnv(prov_cfg, def, ctx.provider_kind);

    if (acct_cfg.config_dir) |dir| {
        // Persistent config dir mode
        if (config_dir_env) |env_var| {
            const expanded = paths.expandTilde(ctx.allocator, dir) catch return error.OutOfMemory;
            ctx.addEnvOwned(env_var, expanded) catch return error.OutOfMemory;
        }
    } else if (config_dir_env) |env_var| {
        // TIN-2054: Claude's credentials live in the macOS login keychain
        // keyed off CLAUDE_CONFIG_DIR (TIN-2060) — it never reads an injected
        // .credentials.json. Routing it through tmpdir mode writes a dead
        // credential file AND points CLAUDE_CONFIG_DIR at an ephemeral dir, so
        // the keychain service hash resolves to a fresh EMPTY slot → a
        // guaranteed 401, plus an orphaned /tmp dir. This is also the exact
        // temp-home shape that poisoned the canonical Codex store for 3 weeks
        // (the TIN-1851 Model B guards live only in the codex adapter, not
        // here). Refuse: a Claude account must declare a persistent config_dir
        // (the `oauth-mux enroll claude` flow creates one). All platforms —
        // an ephemeral Claude config dir can't persist credentials anywhere.
        //
        // Key on the HAZARD SIGNAL, not just the enum kind: the danger is that
        // the config-dir env is CLAUDE_CONFIG_DIR (whose value is the keychain
        // service-hash input), so a custom provider_definitions entry with a
        // non-enum kind string but CLAUDE_CONFIG_DIR — which yields a null
        // provider_kind and is reachable because runEnv/runProbe skip
        // config.validate — is caught too. (Derive the kind from the name as a
        // secondary signal so a bare kind:"claude" is covered even if
        // provider_kind was never pre-resolved.)
        const inject_kind = ctx.provider_kind orelse config_mod.resolveProviderKind(ctx.cfg, prov_name);
        if (inject_kind == .claude or std.mem.eql(u8, env_var, "CLAUDE_CONFIG_DIR")) {
            log.err("inject: claude account {s} has no config_dir; tmpdir credential injection cannot reach the keychain-backed CLI — set a persistent config_dir (e.g. via `oauth-mux enroll claude`)", .{acct_name});
            return error.ProviderNeedsConfigDir;
        }

        // Tmpdir mode: write credential file to temp dir
        const schema_token = schemaTokenFromProviderToken(tok);
        const cred_content = provider_schema.buildCredentialGeneric(def, schema_token, ctx.allocator) catch return error.OutOfMemory;
        defer ctx.allocator.free(cred_content);

        const tmp_dir = createTmpCredDir(ctx.allocator, def.injection.credential_filename, cred_content) catch return error.OutOfMemory;
        ctx.addEnvOwned(env_var, tmp_dir) catch return error.OutOfMemory;
    }

    if (def.injection.direct_env) |direct_env| {
        for (direct_env) |mapping| {
            if (tokenFieldValue(tok, mapping[1])) |value| {
                ctx.env_pairs.append(.{ mapping[0], value }) catch return error.OutOfMemory;
            }
        }
    }

    // Breadcrumb env vars
    ctx.env_pairs.append(.{ "OMUX_ACTIVE_PROVIDER", prov_name }) catch return error.OutOfMemory;
    ctx.env_pairs.append(.{ "OMUX_ACTIVE_ACCOUNT", acct_name }) catch return error.OutOfMemory;
    if (ctx.profile_name) |pn| {
        ctx.env_pairs.append(.{ "OMUX_ACTIVE_PROFILE", pn }) catch return error.OutOfMemory;
    }
    if (ctx.capability_name) |capability| {
        ctx.env_pairs.append(.{ "OMUX_ACTIVE_CAPABILITY", capability }) catch return error.OutOfMemory;
    }
    try addReauthEnv(ctx, prov_name, acct_name);
}

fn addReauthEnv(ctx: *Context, prov_name: []const u8, acct_name: []const u8) PipelineError!void {
    const job = repair_state.reauthJobAlloc(ctx.allocator, prov_name, acct_name) catch return error.OutOfMemory;
    ctx.addEnvOwned("OMUX_REAUTH_JOB", job) catch return error.OutOfMemory;
    const lock_dir = repair_state.reauthLocksDir(ctx.allocator) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.RuntimeNotReady,
    };
    ctx.addEnvOwned("OMUX_REAUTH_LOCK_DIR", lock_dir) catch return error.OutOfMemory;
    const ui_url = (env.get(ctx.allocator, "OMUX_REAUTH_UI_URL") catch return error.OutOfMemory) orelse
        (ctx.allocator.dupe(u8, "") catch return error.OutOfMemory);
    ctx.addEnvOwned("OMUX_REAUTH_UI_URL", ui_url) catch return error.OutOfMemory;
}

fn providerConfigDirEnv(
    prov_cfg: config_mod.ProviderConfig,
    def: provider_schema.ProviderDefinition,
    kind: ?types.ProviderKind,
) ?[]const u8 {
    if (prov_cfg.config_dir_env) |env_var| return env_var;
    if (def.injection.config_dir_env) |env_var| return env_var;
    if (kind) |k| return k.configDirEnv();
    return null;
}

fn schemaTokenFromProviderToken(tok: provider.TokenFields) provider_schema.TokenFields {
    return .{
        .access_token = tok.access_token,
        .refresh_token = tok.refresh_token,
        .token_type = tok.token_type,
        .expires_at = tok.expires_at,
    };
}

fn tokenFieldValue(tok: provider.TokenFields, field: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, field, "access_token")) return tok.access_token;
    if (std.mem.eql(u8, field, "refresh_token")) return tok.refresh_token;
    return null;
}

fn createTmpCredDir(allocator: std.mem.Allocator, fname: []const u8, content: []const u8) ![]const u8 {
    const tmp_base = (try env.get(allocator, "TMPDIR")) orelse try allocator.dupe(u8, "/tmp");
    defer allocator.free(tmp_base);
    const dir_path = std.fmt.allocPrint(allocator, "{s}/oauth-mux-{d}", .{ tmp_base, std.time.timestamp() }) catch return error.OutOfMemory;

    std.fs.makeDirAbsolute(dir_path) catch |e| switch (e) {
        error.PathAlreadyExists => {},
        else => return error.OutOfMemory,
    };

    const file_path = std.fs.path.join(allocator, &.{ dir_path, fname }) catch return error.OutOfMemory;
    defer allocator.free(file_path);

    const file = std.fs.createFileAbsolute(file_path, .{ .mode = 0o600 }) catch return error.OutOfMemory;
    defer file.close();
    file.writeAll(content) catch return error.OutOfMemory;

    return dir_path;
}

const ProviderAccount = struct {
    provider: []const u8,
    account: []const u8,
    capability: ?[]const u8 = null,
};

fn splitProviderAccount(spec: []const u8) ?ProviderAccount {
    const parsed = health_mod.parseHealthKey(spec) orelse return null;
    return .{
        .provider = parsed.provider,
        .account = parsed.account,
        .capability = parsed.capability,
    };
}

test "splitProviderAccount" {
    const pa = splitProviderAccount("claude:work").?;
    try std.testing.expectEqualStrings("claude", pa.provider);
    try std.testing.expectEqualStrings("work", pa.account);
    try std.testing.expect(pa.capability == null);

    const route = splitProviderAccount("codex:max-1#codex-max").?;
    try std.testing.expectEqualStrings("codex", route.provider);
    try std.testing.expectEqualStrings("max-1", route.account);
    try std.testing.expectEqualStrings("codex-max", route.capability.?);

    try std.testing.expect(splitProviderAccount("nocolon") == null);
}

test "runEnv uses configured provider definition" {
    var rt_scope = try repair_state.TestRuntimeDirScope.init(std.testing.allocator);
    defer rt_scope.deinit(std.testing.allocator);
    rt_scope.activate();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const auth_file = try tmp.dir.createFile("toy-auth.json", .{});
    defer auth_file.close();
    try auth_file.writeAll(
        \\{"tokens":{"access":"toy-at","refresh":"toy-rt"}}
    );

    const auth_path = try tmp.dir.realpathAlloc(std.testing.allocator, "toy-auth.json");
    defer std.testing.allocator.free(auth_path);

    const json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "defaults": {{ "provider": "toy" }},
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "credential": {{
        \\        "access_token_path": "tokens.access",
        \\        "refresh_token_path": "tokens.refresh"
        \\      }},
        \\      "injection": {{
        \\        "direct_env": [["TOY_TOKEN", "access_token"]]
        \\      }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{
        \\      "kind": "toy",
        \\      "accounts": {{
        \\        "default": {{
        \\          "secret": {{ "backend": "file", "path": "{s}" }}
        \\        }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ,
        .{auth_path},
    );
    defer std.testing.allocator.free(json);

    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();

    try runEnv(&ctx);

    try std.testing.expectEqualStrings("toy", ctx.provider_name.?);
    try std.testing.expect(ctx.provider_kind == null);
    try expectEnvPair(ctx.env_pairs.items, "TOY_TOKEN", "toy-at");
    try expectEnvPair(ctx.env_pairs.items, "OMUX_ACTIVE_PROVIDER", "toy");
    try expectEnvPair(ctx.env_pairs.items, "OMUX_ACTIVE_ACCOUNT", "default");
    try expectEnvPair(ctx.env_pairs.items, "OMUX_REAUTH_JOB", "toy:default");
    try expectEnvKey(ctx.env_pairs.items, "OMUX_REAUTH_LOCK_DIR");
    try expectEnvPair(ctx.env_pairs.items, "OMUX_REAUTH_UI_URL", "");
}

test "refreshWritebackBackend admits only oauth-mux owned file writeback" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/auth.json", .{root_path});
    defer std.testing.allocator.free(auth_path);

    const admitted_json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "repair": {{ "owner": "oauth_mux_refresh" }},
        \\      "auth": {{ "token_endpoint": "https://example.invalid/token" }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{
        \\      "kind": "toy",
        \\      "accounts": {{
        \\        "default": {{ "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ,
        .{auth_path},
    );
    defer std.testing.allocator.free(admitted_json);

    const admitted = try config_mod.loadFromBytes(std.testing.allocator, admitted_json);
    defer admitted.deinit();
    var admitted_store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer admitted_store.deinit();
    var admitted_ctx = Context.init(std.testing.allocator, admitted.value, &admitted_store);
    defer admitted_ctx.deinit();
    admitted_ctx.provider_name = "toy";
    admitted_ctx.account_name = "default";
    const admitted_writeback = try refreshWritebackBackend(&admitted_ctx, config_mod.resolveProviderDefinition(admitted.value, "toy"));
    try std.testing.expect(admitted_writeback.plan.automatic_refresh_admitted);
    switch (admitted_writeback.backend) {
        .file => |ref| try std.testing.expectEqualStrings(auth_path, ref.path),
        else => return error.TestUnexpectedResult,
    }

    const upstream_json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "repair": {{ "owner": "upstream_cli_login" }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{
        \\      "kind": "toy",
        \\      "accounts": {{
        \\        "default": {{ "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ,
        .{auth_path},
    );
    defer std.testing.allocator.free(upstream_json);

    const upstream = try config_mod.loadFromBytes(std.testing.allocator, upstream_json);
    defer upstream.deinit();
    var upstream_store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer upstream_store.deinit();
    var upstream_ctx = Context.init(std.testing.allocator, upstream.value, &upstream_store);
    defer upstream_ctx.deinit();
    upstream_ctx.provider_name = "toy";
    upstream_ctx.account_name = "default";
    try std.testing.expectError(
        error.RefreshTransientStore,
        refreshWritebackBackend(&upstream_ctx, config_mod.resolveProviderDefinition(upstream.value, "toy")),
    );

    const readonly_json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "repair": { "owner": "oauth_mux_refresh" }
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": { "secret": { "backend": "env", "variable": "TOY_AUTH" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const readonly = try config_mod.loadFromBytes(std.testing.allocator, readonly_json);
    defer readonly.deinit();
    var readonly_store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer readonly_store.deinit();
    var readonly_ctx = Context.init(std.testing.allocator, readonly.value, &readonly_store);
    defer readonly_ctx.deinit();
    readonly_ctx.provider_name = "toy";
    readonly_ctx.account_name = "default";
    try std.testing.expectError(
        error.RefreshTransientStore,
        refreshWritebackBackend(&readonly_ctx, config_mod.resolveProviderDefinition(readonly.value, "toy")),
    );
}

test "runEnv honors capability route health from profile" {
    var rt_scope = try repair_state.TestRuntimeDirScope.init(std.testing.allocator);
    defer rt_scope.deinit(std.testing.allocator);
    rt_scope.activate();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const codex1 = try tmp.dir.createFile("codex-1.json", .{});
    defer codex1.close();
    try codex1.writeAll(
        \\{"auth_mode":"chatgpt","tokens":{"access_token":"codex-one","refresh_token":"codex-rt"}}
    );

    const codex2 = try tmp.dir.createFile("codex-2.json", .{});
    defer codex2.close();
    try codex2.writeAll(
        \\{"auth_mode":"chatgpt","tokens":{"access_token":"codex-two","refresh_token":"codex-rt"}}
    );

    const codex1_path = try tmp.dir.realpathAlloc(std.testing.allocator, "codex-1.json");
    defer std.testing.allocator.free(codex1_path);
    const codex2_path = try tmp.dir.realpathAlloc(std.testing.allocator, "codex-2.json");
    defer std.testing.allocator.free(codex2_path);

    const json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "defaults": {{ "provider": "codex" }},
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "credential": {{
        \\        "access_token_path": "tokens.access_token",
        \\        "refresh_token_path": "tokens.refresh_token"
        \\      }},
        \\      "injection": {{ "direct_env": [["TOY_TOKEN", "access_token"]] }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "codex": {{
        \\      "kind": "toy",
        \\      "accounts": {{
        \\        "max-1": {{ "priority": 30, "secret": {{ "backend": "file", "path": "{s}" }} }},
        \\        "max-2": {{ "priority": 20, "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{
        \\    "mux": {{ "providers": ["codex:max-1#codex-route", "codex:max-2#codex-route"] }}
        \\  }},
        \\  "strategies": {{}}
        \\}}
    ,
        .{ codex1_path, codex2_path },
    );
    defer std.testing.allocator.free(json);

    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    store.recordCapabilityHttpStatus("codex", "max-1", "codex-route", 429, 7200);

    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.profile_name = "mux";

    try runEnv(&ctx);

    try std.testing.expectEqualStrings("codex", ctx.provider_name.?);
    try std.testing.expectEqualStrings("max-2", ctx.account_name.?);
    try std.testing.expectEqualStrings("codex-route", ctx.capability_name.?);
    try expectEnvPair(ctx.env_pairs.items, "OMUX_ACTIVE_ACCOUNT", "max-2");
    try expectEnvPair(ctx.env_pairs.items, "OMUX_ACTIVE_CAPABILITY", "codex-route");
}

test "runEnv routes around degraded capability without poisoning account" {
    var rt_scope = try repair_state.TestRuntimeDirScope.init(std.testing.allocator);
    defer rt_scope.deinit(std.testing.allocator);
    rt_scope.activate();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const codex1 = try tmp.dir.createFile("codex-1.json", .{});
    defer codex1.close();
    try codex1.writeAll(
        \\{"auth_mode":"chatgpt","tokens":{"access_token":"codex-one","refresh_token":"codex-rt"}}
    );

    const codex2 = try tmp.dir.createFile("codex-2.json", .{});
    defer codex2.close();
    try codex2.writeAll(
        \\{"auth_mode":"chatgpt","tokens":{"access_token":"codex-two","refresh_token":"codex-rt"}}
    );

    const codex1_path = try tmp.dir.realpathAlloc(std.testing.allocator, "codex-1.json");
    defer std.testing.allocator.free(codex1_path);
    const codex2_path = try tmp.dir.realpathAlloc(std.testing.allocator, "codex-2.json");
    defer std.testing.allocator.free(codex2_path);

    const json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "codex": {{
        \\      "name": "codex",
        \\      "display_name": "Synthetic Codex",
        \\      "credential": {{
        \\        "access_token_path": "tokens.access_token",
        \\        "refresh_token_path": "tokens.refresh_token"
        \\      }},
        \\      "injection": {{
        \\        "direct_env": [["OPENAI_API_KEY", "access_token"]]
        \\      }}
        \\    }}
        \\  }},
        \\  "defaults": {{ "provider": "codex" }},
        \\  "providers": {{
        \\    "codex": {{
        \\      "kind": "codex",
        \\      "accounts": {{
        \\        "max-1": {{ "priority": 30, "secret": {{ "backend": "file", "path": "{s}" }} }},
        \\        "max-2": {{ "priority": 20, "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{
        \\    "max": {{ "providers": ["codex:max-1#codex-max", "codex:max-2#codex-max"] }},
        \\    "mini": {{ "providers": ["codex:max-1#codex-mini", "codex:max-2#codex-mini"] }}
        \\  }},
        \\  "strategies": {{}}
        \\}}
    ,
        .{ codex1_path, codex2_path },
    );
    defer std.testing.allocator.free(json);

    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    const degraded_route = health_mod.capabilityKey("codex", "max-1", "codex-max");
    store.recordHttpClassification(
        degraded_route.slice(),
        403,
        .{ .degraded = .tier_insufficient },
        std.time.timestamp(),
    );

    var max_ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer max_ctx.deinit();
    max_ctx.profile_name = "max";

    try runEnv(&max_ctx);

    try std.testing.expectEqualStrings("max-2", max_ctx.account_name.?);
    try std.testing.expectEqualStrings("codex-max", max_ctx.capability_name.?);
    try expectEnvPair(max_ctx.env_pairs.items, "OMUX_ACTIVE_ACCOUNT", "max-2");
    try expectEnvPair(max_ctx.env_pairs.items, "OMUX_ACTIVE_CAPABILITY", "codex-max");

    var mini_ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer mini_ctx.deinit();
    mini_ctx.profile_name = "mini";

    try runEnv(&mini_ctx);

    try std.testing.expectEqualStrings("max-1", mini_ctx.account_name.?);
    try std.testing.expectEqualStrings("codex-mini", mini_ctx.capability_name.?);
    try expectEnvPair(mini_ctx.env_pairs.items, "OMUX_ACTIVE_ACCOUNT", "max-1");
    try expectEnvPair(mini_ctx.env_pairs.items, "OMUX_ACTIVE_CAPABILITY", "codex-mini");
}

test "runProbe honors explicit account filter without a configured probe plan" {
    var rt_scope = try repair_state.TestRuntimeDirScope.init(std.testing.allocator);
    defer rt_scope.deinit(std.testing.allocator);
    rt_scope.activate();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const codex1 = try tmp.dir.createFile("codex-1.json", .{});
    defer codex1.close();
    try codex1.writeAll(
        \\{"auth_mode":"chatgpt","tokens":{"access_token":"codex-one","refresh_token":"codex-rt"}}
    );

    const codex2 = try tmp.dir.createFile("codex-2.json", .{});
    defer codex2.close();
    try codex2.writeAll(
        \\{"auth_mode":"chatgpt","tokens":{"access_token":"codex-two","refresh_token":"codex-rt"}}
    );

    const codex1_path = try tmp.dir.realpathAlloc(std.testing.allocator, "codex-1.json");
    defer std.testing.allocator.free(codex1_path);
    const codex2_path = try tmp.dir.realpathAlloc(std.testing.allocator, "codex-2.json");
    defer std.testing.allocator.free(codex2_path);

    const json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "defaults": {{ "provider": "codex" }},
        \\  "providers": {{
        \\    "codex": {{
        \\      "kind": "codex",
        \\      "accounts": {{
        \\        "max-1": {{ "priority": 30, "secret": {{ "backend": "file", "path": "{s}" }} }},
        \\        "max-2": {{ "priority": 20, "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ,
        .{ codex1_path, codex2_path },
    );
    defer std.testing.allocator.free(json);

    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.provider_name = "codex";
    ctx.account_name = "max-2";
    ctx.capability_name = "codex-route";

    try runProbe(&ctx);

    try std.testing.expectEqualStrings("codex", ctx.provider_name.?);
    try std.testing.expectEqualStrings("max-2", ctx.account_name.?);
    try std.testing.expectEqualStrings("codex-route", ctx.capability_name.?);
    try std.testing.expect(!ctx.last_probe_executed);
    try std.testing.expect(store.accounts.get("codex:max-2") != null);
    try std.testing.expect(store.accounts.get("codex:max-1") == null);
}

test "runProbe executes auth none command probe without reading missing secret" {
    var rt_scope = try repair_state.TestRuntimeDirScope.init(std.testing.allocator);
    defer rt_scope.deinit(std.testing.allocator);
    rt_scope.activate();
    const json =
        \\{
        \\  "version": 1,
        \\  "defaults": { "provider": "toy" },
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "credential": { "access_token_path": "access" },
        \\      "capabilities": [
        \\        {
        \\          "name": "status",
        \\          "probe": {
        \\            "transport": "command",
        \\            "auth": "none",
        \\            "command": ["sh", "-c", "test \"$OMUX_REAUTH_JOB\" = \"toy:default\" && test -n \"$OMUX_REAUTH_LOCK_DIR\" && test \"$OMUX_REAUTH_UI_URL\" = \"\" && printf '{\"loggedIn\":true}'"],
        \\            "budget": "free_command"
        \\          }
        \\        }
        \\      ],
        \\      "failure_rules": [
        \\        {
        \\          "status": 400,
        \\          "hint_contains": "\"loggedIn\":false",
        \\          "class": { "dead": "token_revoked" }
        \\        }
        \\      ]
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "OMUX_TEST_SECRET_THAT_IS_NOT_SET" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "toy": { "providers": ["toy:default#status"] }
        \\  },
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.profile_name = "toy";
    ctx.capability_name = "status";

    try runProbe(&ctx);

    try std.testing.expect(ctx.last_probe_executed);
    try std.testing.expect(ctx.token == null);
    try std.testing.expectEqual(@as(?u16, 200), ctx.last_probe_status);
    try std.testing.expectEqual(types.MuxDecision.use_this, ctx.last_probe_decision.?);
    try std.testing.expect(store.accounts.get("toy:default#status") != null);
}

test "runProbe with explicit account rechecks previously degraded command route" {
    var rt_scope = try repair_state.TestRuntimeDirScope.init(std.testing.allocator);
    defer rt_scope.deinit(std.testing.allocator);
    rt_scope.activate();
    const json =
        \\{
        \\  "version": 1,
        \\  "defaults": { "provider": "toy" },
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "credential": { "access_token_path": "access" },
        \\      "capabilities": [
        \\        {
        \\          "name": "status",
        \\          "probe": {
        \\            "transport": "command",
        \\            "auth": "none",
        \\            "command": ["sh", "-c", "printf '{\"type\":\"turn.completed\"}'"],
        \\            "budget": "free_command"
        \\          }
        \\        }
        \\      ]
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "OMUX_TEST_SECRET_THAT_IS_NOT_SET" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    store.recordHttpClassification("toy:default#status", 400, .{ .degraded = .unknown_4xx }, std.time.timestamp());

    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.provider_name = "toy";
    ctx.account_name = "default";
    ctx.capability_name = "status";
    ctx.probe_recheck_blocked = true;

    try runProbe(&ctx);

    try std.testing.expect(ctx.last_probe_executed);
    try std.testing.expectEqual(@as(?u16, 200), ctx.last_probe_status);
    try std.testing.expectEqual(types.MuxDecision.use_this, ctx.last_probe_decision.?);
    const health = store.accounts.get("toy:default#status").?;
    switch (health.liveness) {
        .live => |live| try std.testing.expect(live.availability == .available),
        else => return error.TestUnexpectedResult,
    }
}

test "runProbe does not poison liveness when command probe binary is missing" {
    var rt_scope = try repair_state.TestRuntimeDirScope.init(std.testing.allocator);
    defer rt_scope.deinit(std.testing.allocator);
    rt_scope.activate();
    const missing_binary = "omux-definitely-missing-probe-runtime";
    const json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "defaults": {{ "provider": "toy" }},
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "capabilities": [
        \\        {{
        \\          "name": "status",
        \\          "probe": {{
        \\            "transport": "command",
        \\            "auth": "none",
        \\            "command": ["{s}", "status"],
        \\            "budget": "free_command"
        \\          }}
        \\        }}
        \\      ],
        \\      "failure_rules": [
        \\        {{ "status_min": 500, "status_max": 599, "class": {{ "provider_degraded": {{}} }} }}
        \\      ]
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{
        \\      "kind": "toy",
        \\      "accounts": {{
        \\        "default": {{
        \\          "secret": {{ "backend": "env", "variable": "OMUX_TEST_SECRET_THAT_IS_NOT_SET" }}
        \\        }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{
        \\    "toy": {{ "providers": ["toy:default#status"] }}
        \\  }},
        \\  "strategies": {{}}
        \\}}
    ,
        .{missing_binary},
    );
    defer std.testing.allocator.free(json);

    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.profile_name = "toy";
    ctx.capability_name = "status";

    try std.testing.expectError(error.RuntimeNotReady, runProbe(&ctx));
    try std.testing.expect(!ctx.last_probe_executed);
    try expectUnpoisonedRuntimeHealth(store.accounts.get("toy:default").?);
    try expectUnpoisonedRuntimeHealth(store.accounts.get("toy:default#status").?);
}

test "runProbe does not poison liveness when command account runtime is unavailable" {
    var rt_scope = try repair_state.TestRuntimeDirScope.init(std.testing.allocator);
    defer rt_scope.deinit(std.testing.allocator);
    rt_scope.activate();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const missing_config_dir = try std.fs.path.join(std.testing.allocator, &.{ root, "missing-store" });
    defer std.testing.allocator.free(missing_config_dir);

    const json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "defaults": {{ "provider": "toy" }},
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "injection": {{ "config_dir_env": "TOY_HOME" }},
        \\      "runtime": {{
        \\        "env_vars": ["TOY_HOME"],
        \\        "writable_paths": ["TOY_HOME"],
        \\        "session_paths": ["TOY_HOME/session.json"]
        \\      }},
        \\      "capabilities": [
        \\        {{
        \\          "name": "status",
        \\          "probe": {{
        \\            "transport": "command",
        \\            "auth": "none",
        \\            "command": ["sh", "-c", "printf '{{\"loggedIn\":true}}'"],
        \\            "budget": "free_command"
        \\          }}
        \\        }}
        \\      ],
        \\      "failure_rules": [
        \\        {{ "status_min": 500, "status_max": 599, "class": {{ "provider_degraded": {{}} }} }}
        \\      ]
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{
        \\      "kind": "toy",
        \\      "accounts": {{
        \\        "default": {{
        \\          "config_dir": "{s}",
        \\          "secret": {{ "backend": "env", "variable": "OMUX_TEST_SECRET_THAT_IS_NOT_SET" }}
        \\        }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{
        \\    "toy": {{ "providers": ["toy:default#status"] }}
        \\  }},
        \\  "strategies": {{}}
        \\}}
    ,
        .{missing_config_dir},
    );
    defer std.testing.allocator.free(json);

    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.profile_name = "toy";
    ctx.capability_name = "status";

    try std.testing.expectError(error.RuntimeNotReady, runProbe(&ctx));
    try std.testing.expect(!ctx.last_probe_executed);
    try expectUnpoisonedRuntimeHealth(store.accounts.get("toy:default").?);
    try expectUnpoisonedRuntimeHealth(store.accounts.get("toy:default#status").?);
}

fn expectUnpoisonedRuntimeHealth(health: health_mod.AccountHealth) !void {
    switch (health.liveness) {
        .live => |live| switch (live.availability) {
            .available => {},
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expect(health.last_http_status == null);
    try std.testing.expect(health.last_probe_source == null);
}

test "runEnv skips remaining accounts for degraded provider" {
    var rt_scope = try repair_state.TestRuntimeDirScope.init(std.testing.allocator);
    defer rt_scope.deinit(std.testing.allocator);
    rt_scope.activate();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const codex1 = try tmp.dir.createFile("codex-1.json", .{});
    defer codex1.close();
    try codex1.writeAll(
        \\{"auth_mode":"chatgpt","tokens":{"access_token":"codex-one","refresh_token":"codex-rt"}}
    );

    const codex2 = try tmp.dir.createFile("codex-2.json", .{});
    defer codex2.close();
    try codex2.writeAll(
        \\{"auth_mode":"chatgpt","tokens":{"access_token":"codex-two","refresh_token":"codex-rt"}}
    );

    const toy_file = try tmp.dir.createFile("toy.json", .{});
    defer toy_file.close();
    try toy_file.writeAll(
        \\{"tokens":{"access":"toy-at"}}
    );

    const codex1_path = try tmp.dir.realpathAlloc(std.testing.allocator, "codex-1.json");
    defer std.testing.allocator.free(codex1_path);
    const codex2_path = try tmp.dir.realpathAlloc(std.testing.allocator, "codex-2.json");
    defer std.testing.allocator.free(codex2_path);
    const toy_path = try tmp.dir.realpathAlloc(std.testing.allocator, "toy.json");
    defer std.testing.allocator.free(toy_path);

    const json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "defaults": {{ "provider": "codex" }},
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "credential": {{ "access_token_path": "tokens.access" }},
        \\      "injection": {{ "direct_env": [["TOY_TOKEN", "access_token"]] }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "codex": {{
        \\      "kind": "codex",
        \\      "accounts": {{
        \\        "max-1": {{ "priority": 30, "secret": {{ "backend": "file", "path": "{s}" }} }},
        \\        "max-2": {{ "priority": 20, "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }},
        \\    "toy": {{
        \\      "kind": "toy",
        \\      "accounts": {{
        \\        "default": {{ "priority": 10, "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{
        \\    "mux": {{ "providers": ["codex:max-1", "codex:max-2", "toy:default"] }}
        \\  }},
        \\  "strategies": {{}}
        \\}}
    ,
        .{ codex1_path, codex2_path, toy_path },
    );
    defer std.testing.allocator.free(json);

    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    store.recordHttpClassification("codex:max-1", 500, .provider_degraded, std.time.timestamp());

    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.profile_name = "mux";

    try runEnv(&ctx);

    try std.testing.expectEqualStrings("toy", ctx.provider_name.?);
    try std.testing.expectEqualStrings("default", ctx.account_name.?);
    try expectEnvPair(ctx.env_pairs.items, "TOY_TOKEN", "toy-at");
    try expectMissingEnvValue(ctx.env_pairs.items, "OMUX_ACTIVE_ACCOUNT", "max-2");
}

fn expectEnvPair(pairs: []const [2][]const u8, key: []const u8, value: []const u8) !void {
    for (pairs) |pair| {
        if (std.mem.eql(u8, pair[0], key)) {
            try std.testing.expectEqualStrings(value, pair[1]);
            return;
        }
    }
    return error.TestUnexpectedResult;
}

fn expectEnvKey(pairs: []const [2][]const u8, key: []const u8) !void {
    for (pairs) |pair| {
        if (std.mem.eql(u8, pair[0], key)) return;
    }
    return error.TestUnexpectedResult;
}

fn expectMissingEnvValue(pairs: []const [2][]const u8, key: []const u8, value: []const u8) !void {
    for (pairs) |pair| {
        if (std.mem.eql(u8, pair[0], key) and std.mem.eql(u8, pair[1], value)) {
            return error.TestUnexpectedResult;
        }
    }
}

test "refreshWritebackBackend admits opted-in proactive refresh under upstream login ownership" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/auth.json", .{root_path});
    defer std.testing.allocator.free(auth_path);

    // Provider declares the refresh grant; login stays upstream-owned.
    // Account consent is the only difference between the two configs.
    const config_fmt =
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "repair": {{ "owner": "upstream_cli_login", "proactive_refresh": "oauth_refresh_token" }},
        \\      "auth": {{ "token_endpoint": "https://example.invalid/token" }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{
        \\      "kind": "toy",
        \\      "accounts": {{
        \\        "default": {{ "secret": {{ "backend": "file", "path": "{s}" }}{s} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ;

    const opted_json = try std.fmt.allocPrint(std.testing.allocator, config_fmt, .{ auth_path, ", \"allow_proactive_refresh\": true" });
    defer std.testing.allocator.free(opted_json);

    const opted = try config_mod.loadFromBytes(std.testing.allocator, opted_json);
    defer opted.deinit();
    var opted_store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer opted_store.deinit();
    var opted_ctx = Context.init(std.testing.allocator, opted.value, &opted_store);
    defer opted_ctx.deinit();
    opted_ctx.provider_name = "toy";
    opted_ctx.account_name = "default";
    const opted_writeback = try refreshWritebackBackend(&opted_ctx, config_mod.resolveProviderDefinition(opted.value, "toy"));
    try std.testing.expect(opted_writeback.plan.automatic_refresh_admitted);
    try std.testing.expectEqualStrings("proactive_refresh_opted_in", opted_writeback.plan.reason);

    // Default mode (no consent): the same provider definition still refuses.
    const default_json = try std.fmt.allocPrint(std.testing.allocator, config_fmt, .{ auth_path, "" });
    defer std.testing.allocator.free(default_json);

    const defaulted = try config_mod.loadFromBytes(std.testing.allocator, default_json);
    defer defaulted.deinit();
    var default_store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer default_store.deinit();
    var default_ctx = Context.init(std.testing.allocator, defaulted.value, &default_store);
    defer default_ctx.deinit();
    default_ctx.provider_name = "toy";
    default_ctx.account_name = "default";
    try std.testing.expectError(
        error.RefreshTransientStore,
        refreshWritebackBackend(&default_ctx, config_mod.resolveProviderDefinition(defaulted.value, "toy")),
    );
}

test "validateToken defers refresh under a non-mutating budget (TIN-2073)" {
    var rt_scope = try repair_state.TestRuntimeDirScope.init(std.testing.allocator);
    defer rt_scope.deinit(std.testing.allocator);
    rt_scope.activate();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/auth.json", .{root_path});
    defer std.testing.allocator.free(auth_path);

    const json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "repair": {{ "owner": "oauth_mux_refresh" }},
        \\      "auth": {{ "token_endpoint": "http://127.0.0.1:9/token" }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{
        \\      "kind": "toy",
        \\      "accounts": {{
        \\        "default": {{ "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ,
        .{auth_path},
    );
    defer std.testing.allocator.free(json);

    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.provider_name = "toy";
    ctx.account_name = "default";
    ctx.allow_refresh_mutation = false;

    const now = std.time.timestamp();
    ctx.token = .{
        .access_token = try std.testing.allocator.dupe(u8, "at-skew"),
        .refresh_token = try std.testing.allocator.dupe(u8, "rt-skew"),
        .expires_at = now + 10,
    };

    // Inside the 30s skew but not expired: the token stays usable, the
    // refresh is deferred typed, and the endpoint is never contacted
    // (attemptRefresh is never entered).
    try validateToken(&ctx);
    try std.testing.expectEqual(types.RefreshOutcome.transient_store, ctx.last_refresh_outcome.?);
    try std.testing.expectEqualStrings("refresh_requires_mutating_budget", ctx.last_refresh_reason.?);

    // Actually expired: fails closed for the repair phase, still no rotation.
    ctx.token.?.expires_at = now - 10;
    ctx.last_refresh_outcome = null;
    ctx.last_refresh_reason = null;
    try std.testing.expectError(error.TokenExpired, validateToken(&ctx));
    try std.testing.expectEqual(types.RefreshOutcome.transient_store, ctx.last_refresh_outcome.?);
    try std.testing.expectEqualStrings("refresh_requires_mutating_budget", ctx.last_refresh_reason.?);
}

test "attemptRefresh defers typed when the repair flock is held by another process (TIN-2073)" {
    var rt_scope = try repair_state.TestRuntimeDirScope.init(std.testing.allocator);
    defer rt_scope.deinit(std.testing.allocator);
    rt_scope.activate();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/auth.json", .{root_path});
    defer std.testing.allocator.free(auth_path);

    const json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "repair": {{ "owner": "oauth_mux_refresh" }},
        \\      "auth": {{ "token_endpoint": "http://127.0.0.1:9/token" }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{
        \\      "kind": "toy",
        \\      "accounts": {{
        \\        "tin2073-lock": {{ "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ,
        .{auth_path},
    );
    defer std.testing.allocator.free(json);

    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.provider_name = "toy";
    ctx.account_name = "tin2073-lock";

    ctx.token = .{
        .access_token = try std.testing.allocator.dupe(u8, "at-lock"),
        .refresh_token = try std.testing.allocator.dupe(u8, "rt-lock"),
        .expires_at = std.time.timestamp() - 10,
    };

    // Simulate a FOREIGN process holding the account's repair flock: take
    // the raw kernel flock on the lock file without this process's
    // re-entrancy registry (the same technique as repair_state's own tests).
    const lock_path = try repair_state.lockPath(std.testing.allocator, "toy", "tin2073-lock");
    defer std.testing.allocator.free(lock_path);
    if (std.fs.path.dirname(lock_path)) |dir| try std.fs.cwd().makePath(dir);
    const holder = try std.fs.createFileAbsolute(lock_path, .{
        .truncate = false,
        .mode = 0o600,
        .lock = .exclusive,
        .lock_nonblocking = true,
    });

    {
        defer holder.close();
        try std.testing.expectError(error.RefreshTransientLock, validateToken(&ctx));
        try std.testing.expectEqual(types.RefreshOutcome.transient_lock, ctx.last_refresh_outcome.?);
        try std.testing.expectEqualStrings("refresh_lock_held", ctx.last_refresh_reason.?);

        // Within the skew window (expiring but not expired) a held lock
        // defers WITHOUT failing the candidate: the token is still valid
        // and health must not be poisoned by a benign peer rotation.
        ctx.token.?.expires_at = std.time.timestamp() + 10;
        ctx.last_refresh_outcome = null;
        ctx.last_refresh_reason = null;
        try validateToken(&ctx);
        try std.testing.expectEqual(types.RefreshOutcome.transient_lock, ctx.last_refresh_outcome.?);
        try std.testing.expectEqualStrings("refresh_lock_held", ctx.last_refresh_reason.?);
        ctx.token.?.expires_at = std.time.timestamp() - 10;
    }

    // Holder released: the refresh proceeds past the lock and the
    // under-lock store re-read to the token endpoint (a closed local port),
    // proving the deferral above came from the flock and not the endpoint.
    // A real on-disk store is required so the TIN-2074 unreadable-store
    // refusal does not short-circuit before the endpoint.
    {
        const f = try std.fs.createFileAbsolute(auth_path, .{});
        defer f.close();
        try f.writeAll(
            \\{"access_token":"at-lock","refresh_token":"rt-lock","expires_at":1700000000}
        );
    }
    ctx.last_refresh_outcome = null;
    ctx.last_refresh_reason = null;
    try std.testing.expectError(error.RefreshTransientNetwork, validateToken(&ctx));
    try std.testing.expectEqual(types.RefreshOutcome.transient_network, ctx.last_refresh_outcome.?);
}

test "attemptRefresh adopts a concurrent peer rotation under the lock (TIN-2073 TOCTOU)" {
    var rt_scope = try repair_state.TestRuntimeDirScope.init(std.testing.allocator);
    defer rt_scope.deinit(std.testing.allocator);
    rt_scope.activate();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/auth.json", .{root_path});
    defer std.testing.allocator.free(auth_path);

    const json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "repair": {{ "owner": "oauth_mux_refresh" }},
        \\      "auth": {{ "token_endpoint": "http://127.0.0.1:9/token" }},
        \\      "credential": {{
        \\        "access_token_path": "access_token",
        \\        "refresh_token_path": "refresh_token",
        \\        "expires_at_path": "expires_at"
        \\      }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{
        \\      "kind": "toy",
        \\      "accounts": {{
        \\        "tin2073-toctou": {{ "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ,
        .{auth_path},
    );
    defer std.testing.allocator.free(json);

    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.provider_name = "toy";
    ctx.account_name = "tin2073-toctou";

    // The store already holds a FRESH credential — a peer completed its
    // rotation between this context's pre-lock read (simulated by the stale
    // ctx.token below) and the lock acquisition.
    const now = std.time.timestamp();
    const fresh_credential = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{\"access_token\":\"at-peer-fresh\",\"refresh_token\":\"rt-peer-fresh\",\"expires_at\":{d}}}",
        .{now + 3600},
    );
    defer std.testing.allocator.free(fresh_credential);
    {
        const f = try std.fs.createFileAbsolute(auth_path, .{});
        defer f.close();
        try f.writeAll(fresh_credential);
    }

    ctx.token = .{
        .access_token = try std.testing.allocator.dupe(u8, "at-stale"),
        .refresh_token = try std.testing.allocator.dupe(u8, "rt-stale"),
        .expires_at = now - 10,
    };

    // Succeeds WITHOUT contacting the (dead) token endpoint: the under-lock
    // revalidation adopts the peer's rotation instead of re-rotating with
    // the superseded refresh token.
    try validateToken(&ctx);
    try std.testing.expectEqual(types.RefreshOutcome.refreshed, ctx.last_refresh_outcome.?);
    try std.testing.expectEqualStrings("concurrent_rotation_detected", ctx.last_refresh_reason.?);
    try std.testing.expectEqualStrings("at-peer-fresh", ctx.token.?.access_token);
    try std.testing.expectEqualStrings("rt-peer-fresh", ctx.token.?.refresh_token.?);
}

// Shared config for the TIN-1825 proactive-refresh tests: an admitted toy
// account (oauth_mux_refresh owns refresh) over a DEAD token endpoint, with the
// credential read from a file the test seeds.
fn proactiveTestConfig(allocator: std.mem.Allocator, auth_path: []const u8, owner: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "repair": {{ "owner": "{s}" }},
        \\      "auth": {{ "token_endpoint": "http://127.0.0.1:9/token" }},
        \\      "credential": {{
        \\        "access_token_path": "access_token",
        \\        "refresh_token_path": "refresh_token",
        \\        "expires_at_path": "expires_at"
        \\      }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{
        \\      "kind": "toy",
        \\      "accounts": {{
        \\        "warm": {{ "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    , .{ owner, auth_path });
}

const TestRotatingRefreshServerArgs = struct {
    server: std.net.Server,
    credential_path: []const u8,
    blocked_credential_path: ?[]const u8,
    response_body: []const u8,
    failed: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
};

const TestRotatingRefreshServer = struct {
    allocator: std.mem.Allocator,
    args: *TestRotatingRefreshServerArgs,
    thread: std.Thread,
    port: u16,
    joined: bool = false,

    fn start(
        allocator: std.mem.Allocator,
        credential_path: []const u8,
        blocked_credential_path: []const u8,
    ) !TestRotatingRefreshServer {
        return startConfigured(
            allocator,
            credential_path,
            blocked_credential_path,
            "{\"access_token\":\"at-new\",\"refresh_token\":\"rt-new\",\"expires_in\":3600}",
        );
    }

    fn startWithResponse(
        allocator: std.mem.Allocator,
        credential_path: []const u8,
        response_body: []const u8,
    ) !TestRotatingRefreshServer {
        return startConfigured(
            allocator,
            credential_path,
            null,
            response_body,
        );
    }

    fn startConfigured(
        allocator: std.mem.Allocator,
        credential_path: []const u8,
        blocked_credential_path: ?[]const u8,
        response_body: []const u8,
    ) !TestRotatingRefreshServer {
        const address = try std.net.Address.parseIp("127.0.0.1", 0);
        var server = try address.listen(.{ .reuse_address = true });
        errdefer server.deinit();
        const args = try allocator.create(TestRotatingRefreshServerArgs);
        errdefer allocator.destroy(args);
        args.* = .{
            .server = server,
            .credential_path = credential_path,
            .blocked_credential_path = blocked_credential_path,
            .response_body = response_body,
        };
        const thread = try std.Thread.spawn(.{}, runTestRotatingRefreshServer, .{args});
        return .{
            .allocator = allocator,
            .args = args,
            .thread = thread,
            .port = server.listen_address.getPort(),
        };
    }

    fn join(self: *TestRotatingRefreshServer) bool {
        if (!self.joined) {
            self.thread.join();
            self.joined = true;
        }
        return self.args.failed.load(.seq_cst);
    }

    fn deinit(self: *TestRotatingRefreshServer) void {
        _ = self.join();
        self.allocator.destroy(self.args);
    }
};

fn runTestRotatingRefreshServer(args: *TestRotatingRefreshServerArgs) void {
    defer args.server.deinit();
    runTestRotatingRefreshServerInner(args) catch {
        args.failed.store(true, .seq_cst);
    };
}

fn runTestRotatingRefreshServerInner(args: *TestRotatingRefreshServerArgs) !void {
    const connection = try args.server.accept();
    defer connection.stream.close();
    var head_buffer: [4096]u8 = undefined;
    var server = std.http.Server.init(connection, &head_buffer);
    var request = try server.receiveHead();
    const body_reader = try request.reader();
    var discard: [1024]u8 = undefined;
    while (try body_reader.read(&discard) != 0) {}

    if (args.blocked_credential_path) |blocked_path| {
        // Replace the canonical file with a directory after the endpoint has
        // consumed the request. Atomic file replacement then fails under both
        // privileged and unprivileged test runners.
        try std.fs.renameAbsolute(args.credential_path, blocked_path);
        try std.fs.makeDirAbsolute(args.credential_path);
    }

    try request.respond(
        args.response_body,
        .{
            .status = .ok,
            .keep_alive = false,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json" },
            },
        },
    );
}

test "endpoint success plus canonical write failure quarantines stale lineage across restart" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;
    var scope = try repair_state.TestRuntimeDirScope.init(allocator);
    defer scope.deinit(allocator);
    scope.activate();
    const auth_path = try std.fs.path.join(
        allocator,
        &.{ scope.root, "write-failure.json" },
    );
    defer allocator.free(auth_path);
    const blocked_auth_path = try std.fs.path.join(
        allocator,
        &.{ scope.root, "write-failure.stale.json" },
    );
    defer allocator.free(blocked_auth_path);
    const stale_credential =
        "{\"access_token\":\"at-old\",\"refresh_token\":\"rt-old\",\"expires_at\":9999999999}";
    {
        const file = try std.fs.createFileAbsolute(auth_path, .{ .mode = 0o600 });
        defer file.close();
        try file.writeAll(stale_credential);
    }

    var restore_blocked_credential = true;
    defer if (restore_blocked_credential) {
        std.fs.deleteDirAbsolute(auth_path) catch {};
        std.fs.renameAbsolute(blocked_auth_path, auth_path) catch {};
    };
    var server = try TestRotatingRefreshServer.start(
        allocator,
        auth_path,
        blocked_auth_path,
    );
    defer server.deinit();
    const config_json = try std.fmt.allocPrint(
        allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "repair": {{ "owner": "oauth_mux_refresh", "proactive_refresh": "oauth_refresh_token" }},
        \\      "auth": {{ "token_endpoint": "http://127.0.0.1:{d}/token" }},
        \\      "credential": {{
        \\        "access_token_path": "access_token",
        \\        "refresh_token_path": "refresh_token",
        \\        "expires_at_path": "expires_at"
        \\      }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{ "kind": "toy", "accounts": {{
        \\      "lineage": {{
        \\        "allow_proactive_refresh": true,
        \\        "secret": {{ "backend": "file", "path": "{s}" }}
        \\      }},
        \\      "alias": {{
        \\        "allow_proactive_refresh": true,
        \\        "secret": {{ "backend": "file", "path": "{s}" }}
        \\      }}
        \\    }} }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ,
        .{ server.port, auth_path, auth_path },
    );
    defer allocator.free(config_json);
    const parsed = try config_mod.loadFromBytes(allocator, config_json);
    defer parsed.deinit();

    var health = health_mod.HealthStore.init(allocator, .{});
    defer health.deinit();
    var ctx = Context.init(allocator, parsed.value, &health);
    defer ctx.deinit();
    ctx.provider_name = "toy";
    ctx.account_name = "lineage";
    try std.testing.expectError(
        error.RefreshLineageIndeterminate,
        refreshAccount(&ctx),
    );
    try std.testing.expect(!server.join());

    try std.fs.deleteDirAbsolute(auth_path);
    try std.fs.renameAbsolute(blocked_auth_path, auth_path);
    restore_blocked_credential = false;

    try std.testing.expect(ctx.last_refresh_quarantined);
    try std.testing.expectEqual(
        types.RefreshOutcome.transient_store,
        ctx.last_refresh_outcome.?,
    );
    try std.testing.expectEqual(
        repair_state.RefreshQuarantineState.indeterminate_lineage,
        (try repair_state.refreshQuarantineForRoute(
            allocator,
            "toy",
            "lineage",
        )).?,
    );
    const canonical = try std.fs.openFileAbsolute(auth_path, .{});
    defer canonical.close();
    const canonical_bytes = try canonical.readToEndAlloc(allocator, 4096);
    defer allocator.free(canonical_bytes);
    try std.testing.expectEqualStrings(stale_credential, canonical_bytes);

    // A fresh process context must stop at the marker before reading/replaying
    // the stale canonical refresh token. The one-shot server is already gone.
    var restart_health = health_mod.HealthStore.init(allocator, .{});
    defer restart_health.deinit();
    var restart_ctx = Context.init(allocator, parsed.value, &restart_health);
    defer restart_ctx.deinit();
    restart_ctx.provider_name = "toy";
    restart_ctx.account_name = "lineage";
    try std.testing.expectError(
        error.RefreshLineageIndeterminate,
        refreshAccount(&restart_ctx),
    );
    try std.testing.expect(restart_ctx.last_refresh_quarantined);

    var alias_ctx = Context.init(allocator, parsed.value, &restart_health);
    defer alias_ctx.deinit();
    alias_ctx.provider_name = "toy";
    alias_ctx.account_name = "alias";
    try std.testing.expectError(
        error.RefreshLineageIndeterminate,
        refreshAccount(&alias_ctx),
    );
    try std.testing.expect(alias_ctx.last_refresh_quarantined);

    const marker_path = try repair_state.refreshQuarantineMarkerPathForTest(
        allocator,
        "toy",
        "lineage",
    );
    defer allocator.free(marker_path);
    const marker = try std.fs.openFileAbsolute(marker_path, .{});
    defer marker.close();
    const marker_bytes = try marker.readToEndAlloc(allocator, 4096);
    defer allocator.free(marker_bytes);
    try std.testing.expect(std.mem.indexOf(u8, marker_bytes, "rt-old") == null);
    try std.testing.expect(std.mem.indexOf(u8, marker_bytes, "rt-new") == null);
    try std.testing.expect(std.mem.indexOf(u8, marker_bytes, "at-new") == null);

    // Damaged durable evidence must not fail open for a different account label
    // that resolves to the same canonical store.
    {
        const torn_marker = try std.fs.createFileAbsolute(
            marker_path,
            .{ .truncate = true, .mode = 0o600 },
        );
        defer torn_marker.close();
        try torn_marker.writeAll("{\"torn\":");
        try torn_marker.sync();
    }
    var damaged_alias_ctx = Context.init(allocator, parsed.value, &restart_health);
    defer damaged_alias_ctx.deinit();
    damaged_alias_ctx.provider_name = "toy";
    damaged_alias_ctx.account_name = "alias";
    try std.testing.expectError(
        error.RefreshTransientStore,
        refreshAccount(&damaged_alias_ctx),
    );
    try std.testing.expect(!damaged_alias_ctx.last_refresh_quarantined);
}

test "explicit reusable-token policy preserves the submitted refresh token" {
    const allocator = std.testing.allocator;
    var scope = try repair_state.TestRuntimeDirScope.init(allocator);
    defer scope.deinit(allocator);
    scope.activate();

    const auth_path = try std.fs.path.join(
        allocator,
        &.{ scope.root, "reusable.json" },
    );
    defer allocator.free(auth_path);
    {
        const file = try std.fs.createFileAbsolute(auth_path, .{ .mode = 0o600 });
        defer file.close();
        try file.writeAll(
            "{\"access_token\":\"at-old\",\"refresh_token\":\"rt-reusable\",\"expires_at\":1,\"preserved\":\"yes\"}",
        );
    }

    var server = try TestRotatingRefreshServer.startWithResponse(
        allocator,
        scope.root,
        "{\"access_token\":\"at-new\",\"expires_in\":3600}",
    );
    defer server.deinit();
    const config_json = try std.fmt.allocPrint(allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "repair": {{
        \\        "owner": "oauth_mux_refresh",
        \\        "proactive_refresh": "oauth_refresh_token",
        \\        "refresh_token_response": "reuse_submitted_if_omitted"
        \\      }},
        \\      "auth": {{ "token_endpoint": "http://127.0.0.1:{d}/token" }},
        \\      "credential": {{
        \\        "access_token_path": "access_token",
        \\        "refresh_token_path": "refresh_token",
        \\        "expires_at_path": "expires_at"
        \\      }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{ "kind": "toy", "accounts": {{
        \\      "reusable": {{
        \\        "allow_proactive_refresh": true,
        \\        "secret": {{ "backend": "file", "path": "{s}" }}
        \\      }}
        \\    }} }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    , .{ server.port, auth_path });
    defer allocator.free(config_json);
    const parsed = try config_mod.loadFromBytes(allocator, config_json);
    defer parsed.deinit();

    var health = health_mod.HealthStore.init(allocator, .{});
    defer health.deinit();
    var ctx = Context.init(allocator, parsed.value, &health);
    defer ctx.deinit();
    ctx.provider_name = "toy";
    ctx.account_name = "reusable";
    try refreshAccount(&ctx);
    try std.testing.expect(!server.join());

    try std.testing.expectEqual(
        types.RefreshOutcome.refreshed,
        ctx.last_refresh_outcome.?,
    );
    try std.testing.expectEqualStrings("at-new", ctx.token.?.access_token);
    try std.testing.expectEqualStrings(
        "rt-reusable",
        ctx.token.?.refresh_token.?,
    );
    try std.testing.expect(
        (try repair_state.refreshQuarantineForRoute(
            allocator,
            "toy",
            "reusable",
        )) == null,
    );

    const canonical = try std.fs.openFileAbsolute(auth_path, .{});
    defer canonical.close();
    const canonical_bytes = try canonical.readToEndAlloc(allocator, 4096);
    defer allocator.free(canonical_bytes);
    try std.testing.expect(
        std.mem.indexOf(u8, canonical_bytes, "\"access_token\":\"at-new\"") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            canonical_bytes,
            "\"refresh_token\":\"rt-reusable\"",
        ) != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, canonical_bytes, "\"preserved\":\"yes\"") != null,
    );
}

fn expectNoPersistedPermanentAuthFailure(
    allocator: std.mem.Allocator,
    provider_name: []const u8,
    account_name: []const u8,
) !void {
    var loaded = health_mod.HealthStore.load(allocator, .{});
    defer loaded.deinit();
    const key = health_mod.accountKey(provider_name, account_name);
    const health = loaded.accounts.get(key.slice()) orelse
        return error.TestExpectedPersistedHealthEntry;
    switch (health.liveness) {
        .dead => |dead| try std.testing.expect(
            dead.reason != .auth_permanently_failed,
        ),
        else => {},
    }
}

test "typed refresh dispositions stay out of persisted permanent auth health" {
    const allocator = std.testing.allocator;
    var scope = try repair_state.TestRuntimeDirScope.init(allocator);
    defer scope.deinit(allocator);
    scope.activate();

    var store = health_mod.HealthStore.init(allocator, .{});
    defer store.deinit();
    const cases = [_]struct {
        account: []const u8,
        err: PipelineError,
    }{
        .{ .account = "lock", .err = error.RefreshTransientLock },
        .{ .account = "network", .err = error.RefreshTransientNetwork },
        .{ .account = "store", .err = error.RefreshTransientStore },
        .{ .account = "endpoint", .err = error.RefreshTransientEndpoint },
        .{ .account = "quarantine-read", .err = error.RefreshLineageIndeterminate },
    };
    var ctx: Context = undefined;
    ctx.health = &store;
    for (cases) |case| {
        const key = health_mod.accountKey("toy", case.account);
        _ = try store.getOrCreate(key.slice());
        recordCandidateFailure(&ctx, key.slice(), case.err);
    }
    store.persist();
    for (cases) |case| {
        try expectNoPersistedPermanentAuthFailure(
            allocator,
            "toy",
            case.account,
        );
    }
}

test "runEnv runProbe and runExec preserve quarantine read dispositions through persistence" {
    const allocator = std.testing.allocator;
    var scope = try repair_state.TestRuntimeDirScope.init(allocator);
    defer scope.deinit(allocator);
    scope.activate();
    const auth_path = try std.fs.path.join(
        allocator,
        &.{ scope.root, "consumer-auth.json" },
    );
    defer allocator.free(auth_path);
    {
        const file = try std.fs.createFileAbsolute(auth_path, .{ .mode = 0o600 });
        defer file.close();
        try file.writeAll("{\"access_token\":\"api-key\"}");
    }
    const config_json = try std.fmt.allocPrint(
        allocator,
        \\{{
        \\  "version": 1,
        \\  "providers": {{
        \\    "toy": {{ "kind": "toy", "accounts": {{
        \\      "consumer": {{ "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\    }} }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ,
        .{auth_path},
    );
    defer allocator.free(config_json);
    const parsed = try config_mod.loadFromBytes(allocator, config_json);
    defer parsed.deinit();

    const marker_path = try repair_state.refreshQuarantineMarkerPathForTest(
        allocator,
        "toy",
        "consumer",
    );
    defer allocator.free(marker_path);
    if (std.fs.path.dirname(marker_path)) |parent| {
        try std.fs.cwd().makePath(parent);
    }
    {
        const marker = try std.fs.createFileAbsolute(
            marker_path,
            .{ .mode = 0o600 },
        );
        defer marker.close();
        try marker.writeAll("{\"torn\":");
    }

    const Runner = enum { env, probe, exec };
    const runners = [_]Runner{ .env, .probe, .exec };
    var store = health_mod.HealthStore.init(allocator, .{});
    defer store.deinit();
    _ = try store.getOrCreate("toy:consumer");
    store.persist();
    for (runners) |runner| {
        var ctx = Context.init(allocator, parsed.value, &store);
        defer ctx.deinit();
        ctx.provider_name = "toy";
        const result = switch (runner) {
            .env => runEnv(&ctx),
            .probe => runProbe(&ctx),
            .exec => runExec(&ctx),
        };
        try std.testing.expectError(error.RefreshTransientStore, result);
        try std.testing.expect(!ctx.last_refresh_quarantined);
        store.persist();
        try expectNoPersistedPermanentAuthFailure(
            allocator,
            "toy",
            "consumer",
        );
    }

    try std.fs.deleteFileAbsolute(marker_path);
    try repair_state.persistIndeterminateRefreshQuarantine(
        allocator,
        "toy",
        "consumer",
    );
    for (runners) |runner| {
        var ctx = Context.init(allocator, parsed.value, &store);
        defer ctx.deinit();
        ctx.provider_name = "toy";
        const result = switch (runner) {
            .env => runEnv(&ctx),
            .probe => runProbe(&ctx),
            .exec => runExec(&ctx),
        };
        try std.testing.expectError(error.RefreshLineageIndeterminate, result);
        try std.testing.expect(ctx.last_refresh_quarantined);
        store.persist();
        try expectNoPersistedPermanentAuthFailure(
            allocator,
            "toy",
            "consumer",
        );
    }
}

test "proof-created hard lineage blocks refresh before credential read and kills health" {
    const allocator = std.testing.allocator;
    var scope = try repair_state.TestRuntimeDirScope.init(allocator);
    defer scope.deinit(allocator);
    scope.activate();

    const auth_path = try std.fs.path.join(
        allocator,
        &.{ scope.root, "lineage.json" },
    );
    defer allocator.free(auth_path);
    {
        const file = try std.fs.createFileAbsolute(auth_path, .{ .mode = 0o600 });
        defer file.close();
        try file.writeAll(
            "{\"access_token\":\"at\",\"refresh_token\":\"rt-current\",\"expires_at\":9999999999,\"account_id\":\"identity-current\"}",
        );
    }
    const json = try std.fmt.allocPrint(
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
        .{auth_path},
    );
    defer allocator.free(json);
    const parsed = try config_mod.loadFromBytes(allocator, json);
    defer parsed.deinit();
    const acct_cfg = parsed.value.providers.map.get("toy").?.accounts.map.get("lineage").?;
    const backend = try config_mod.resolveSecretBackend(acct_cfg.secret);
    const def = config_mod.resolveProviderDefinition(parsed.value, "toy");
    try repair_state.establishHardRefreshQuarantineForTest(
        allocator,
        "toy",
        "lineage",
        backend,
        def,
    );
    try std.fs.deleteFileAbsolute(auth_path);

    var store = health_mod.HealthStore.init(allocator, .{});
    defer store.deinit();
    var ctx = Context.init(allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.provider_name = "toy";
    ctx.account_name = "lineage";
    try std.testing.expectError(error.TokenRefreshFailed, refreshAccount(&ctx));
    try std.testing.expectEqual(
        types.RefreshOutcome.hard_lineage_invalidated,
        ctx.last_refresh_outcome.?,
    );
    try std.testing.expectEqualStrings("refresh_lineage_quarantined", ctx.last_refresh_reason.?);
    const key = health_mod.accountKey("toy", "lineage");
    const health = store.accounts.get(key.slice()).?;
    switch (health.liveness) {
        .dead => |dead| try std.testing.expectEqual(
            types.DeadReason.auth_permanently_failed,
            dead.reason,
        ),
        else => return error.TestUnexpectedResult,
    }
}

test "refreshAccount proactively rotates a still-valid same-RT token — past the adopt (TIN-1825 Option B)" {
    var rt_scope = try repair_state.TestRuntimeDirScope.init(std.testing.allocator);
    defer rt_scope.deinit(std.testing.allocator);
    rt_scope.activate();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/auth.json", .{root_path});
    defer std.testing.allocator.free(auth_path);

    // A STILL-VALID credential (hours from expiry), same RT the warm loop reads.
    const now = std.time.timestamp();
    const cred = try std.fmt.allocPrint(std.testing.allocator, "{{\"access_token\":\"at-A\",\"refresh_token\":\"rt-A\",\"expires_at\":{d}}}", .{now + 7200});
    defer std.testing.allocator.free(cred);
    {
        const f = try std.fs.createFileAbsolute(auth_path, .{});
        defer f.close();
        try f.writeAll(cred);
    }

    const json = try proactiveTestConfig(std.testing.allocator, auth_path, "oauth_mux_refresh");
    defer std.testing.allocator.free(json);
    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.provider_name = "toy";
    ctx.account_name = "warm";

    // The OLD freshness-adopt would short-circuit here ("not_needed") because the
    // token is >30s from expiry. Option B (same RT, expiry not advanced) PROCEEDS
    // past the adopt and rotates — so it fails AT THE DEAD ENDPOINT, proving the
    // proactive rotation actually fired.
    try std.testing.expectError(error.RefreshTransientNetwork, refreshAccount(&ctx));
    try std.testing.expectEqual(types.RefreshOutcome.transient_network, ctx.last_refresh_outcome.?);
}

test "attemptRefresh adopts on an expiry-advance with an unchanged RT (Option B belt-and-suspenders)" {
    var rt_scope = try repair_state.TestRuntimeDirScope.init(std.testing.allocator);
    defer rt_scope.deinit(std.testing.allocator);
    rt_scope.activate();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/auth.json", .{root_path});
    defer std.testing.allocator.free(auth_path);

    const now = std.time.timestamp();
    // Store: SAME RT as pre-lock, but a LATER expiry (a non-rotating peer refresh).
    const cred = try std.fmt.allocPrint(std.testing.allocator, "{{\"access_token\":\"at-A2\",\"refresh_token\":\"rt-A\",\"expires_at\":{d}}}", .{now + 7200});
    defer std.testing.allocator.free(cred);
    {
        const f = try std.fs.createFileAbsolute(auth_path, .{});
        defer f.close();
        try f.writeAll(cred);
    }

    const json = try proactiveTestConfig(std.testing.allocator, auth_path, "oauth_mux_refresh");
    defer std.testing.allocator.free(json);
    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.provider_name = "toy";
    ctx.account_name = "warm";
    // Pre-lock token: same RT, but an EARLIER expiry than the store.
    ctx.token = .{
        .access_token = try std.testing.allocator.dupe(u8, "at-A"),
        .refresh_token = try std.testing.allocator.dupe(u8, "rt-A"),
        .expires_at = now + 100,
    };

    // Same RT but the store expiry advanced → adopt (not_needed), endpoint NOT
    // contacted (it is dead; a rotation attempt would surface token_endpoint_failed).
    try attemptRefresh(&ctx, "rt-A");
    try std.testing.expectEqual(types.RefreshOutcome.refreshed, ctx.last_refresh_outcome.?);
    try std.testing.expectEqualStrings("concurrent_rotation_detected", ctx.last_refresh_reason.?);
    try std.testing.expectEqual(@as(i64, now + 7200), ctx.token.?.expires_at.?);
}

test "refreshAccount refuses an un-admitted account at the grant gate (not_admitted, before rotation)" {
    var rt_scope = try repair_state.TestRuntimeDirScope.init(std.testing.allocator);
    defer rt_scope.deinit(std.testing.allocator);
    rt_scope.activate();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/auth.json", .{root_path});
    defer std.testing.allocator.free(auth_path);

    const now = std.time.timestamp();
    const cred = try std.fmt.allocPrint(std.testing.allocator, "{{\"access_token\":\"at-A\",\"refresh_token\":\"rt-A\",\"expires_at\":{d}}}", .{now + 7200});
    defer std.testing.allocator.free(cred);
    {
        const f = try std.fs.createFileAbsolute(auth_path, .{});
        defer f.close();
        try f.writeAll(cred);
    }

    // upstream_cli_login owner + no proactive_refresh grant + no opt-in = builtin posture.
    const json = try proactiveTestConfig(std.testing.allocator, auth_path, "upstream_cli_login");
    defer std.testing.allocator.free(json);
    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.provider_name = "toy";
    ctx.account_name = "warm";

    // The warm loop over a builtin (no grant) refuses BEFORE any lock/network —
    // safe no-op until the proactive_refresh flip + live proof.
    try std.testing.expectError(error.RefreshTransientStore, refreshAccount(&ctx));
    try std.testing.expectEqual(types.RefreshOutcome.transient_store, ctx.last_refresh_outcome.?);
}

test "readAccountExpiryMs returns the credential expiry as Unix milliseconds" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/auth.json", .{root_path});
    defer std.testing.allocator.free(auth_path);

    // expires_at stored in seconds (toy default unit); reader scales to ms.
    {
        const f = try std.fs.createFileAbsolute(auth_path, .{});
        defer f.close();
        try f.writeAll("{\"access_token\":\"at-A\",\"refresh_token\":\"rt-A\",\"expires_at\":9999999999}");
    }

    const json = try proactiveTestConfig(std.testing.allocator, auth_path, "oauth_mux_refresh");
    defer std.testing.allocator.free(json);
    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.provider_name = "toy";
    ctx.account_name = "warm";

    const exp_ms = try readAccountExpiryMs(&ctx);
    try std.testing.expectEqual(@as(?i64, 9999999999 * std.time.ms_per_s), exp_ms);
}

test "attemptRefresh refuses lossy writeback when the store became unreadable under the lock (TIN-2074 review)" {
    var rt_scope = try repair_state.TestRuntimeDirScope.init(std.testing.allocator);
    defer rt_scope.deinit(std.testing.allocator);
    rt_scope.activate();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/auth.json", .{root_path});
    defer std.testing.allocator.free(auth_path);

    const json = try std.fmt.allocPrint(
        std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "toy": {{
        \\      "name": "toy",
        \\      "repair": {{ "owner": "oauth_mux_refresh" }},
        \\      "auth": {{ "token_endpoint": "http://127.0.0.1:9/token" }},
        \\      "credential": {{ "access_token_path": "access_token", "refresh_token_path": "refresh_token", "expires_at_path": "expires_at" }}
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "toy": {{
        \\      "kind": "toy",
        \\      "accounts": {{
        \\        "default": {{ "secret": {{ "backend": "file", "path": "{s}" }} }}
        \\      }}
        \\    }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    ,
        .{auth_path},
    );
    defer std.testing.allocator.free(json);

    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.provider_name = "toy";
    ctx.account_name = "default";

    // ctx.token carries a refresh token (read earlier), but the on-disk
    // store does NOT exist — simulating a transient read failure of the
    // canonical store between the initial read and the under-lock re-read.
    ctx.token = .{
        .access_token = try std.testing.allocator.dupe(u8, "at-stale"),
        .refresh_token = try std.testing.allocator.dupe(u8, "rt-stale"),
        .expires_at = std.time.timestamp() - 10,
    };

    // The refresh must refuse rather than write a lossy template blob over
    // the (absent, but in production canonical) store. The endpoint is
    // never reached.
    try std.testing.expectError(error.RefreshTransientStore, validateToken(&ctx));
    try std.testing.expectEqual(types.RefreshOutcome.transient_store, ctx.last_refresh_outcome.?);
    try std.testing.expectEqualStrings("store_unreadable_refusing_lossy_write", ctx.last_refresh_reason.?);
    // The store was not created by a fallback template write.
    try std.testing.expect(!fileExists(auth_path));
}

fn fileExists(path: []const u8) bool {
    std.fs.accessAbsolute(path, .{}) catch return false;
    return true;
}

test "attemptRefresh defers when the identity lock is held by a sibling-identity session (TIN-2043)" {
    var rt_scope = try repair_state.TestRuntimeDirScope.init(std.testing.allocator);
    defer rt_scope.deinit(std.testing.allocator);
    rt_scope.activate();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/auth.json", .{root_path});
    defer std.testing.allocator.free(auth_path);

    // Two config accounts (tin2043-a, tin2043-b) sharing ONE upstream
    // account_id — the max-1 == max-4 shape. We refresh tin2043-b while a
    // foreign holder simulates tin2043-a's live session holding the shared
    // identity flock.
    const account_id = "shared-identity-uuid";
    {
        const f = try std.fs.createFileAbsolute(auth_path, .{});
        defer f.close();
        try f.writeAll(
            \\{"auth_mode":"chatgpt","tokens":{"access_token":"at","refresh_token":"rt","account_id":"shared-identity-uuid"}}
        );
    }

    const json = try std.fmt.allocPrint(std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "codex": {{ "name": "codex", "kind": "codex", "repair": {{ "owner": "oauth_mux_refresh" }}, "auth": {{ "token_endpoint": "http://127.0.0.1:9/token" }}, "credential": {{ "access_token_path": "tokens.access_token", "refresh_token_path": "tokens.refresh_token", "identity_claim_path": "tokens.account_id" }} }}
        \\  }},
        \\  "providers": {{
        \\    "codex": {{ "kind": "codex", "accounts": {{ "tin2043-b": {{ "secret": {{ "backend": "file", "path": "{s}" }} }} }} }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    , .{auth_path});
    defer std.testing.allocator.free(json);

    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.provider_name = "codex";
    ctx.account_name = "tin2043-b";
    ctx.token = .{
        .access_token = try std.testing.allocator.dupe(u8, "at"),
        .refresh_token = try std.testing.allocator.dupe(u8, "rt"),
        .expires_at = std.time.timestamp() - 10,
    };

    // Foreign holder on the IDENTITY lock (codex-identity-<hash>), keyed
    // exactly as attemptRefresh will compute it.
    const id_hash = try identity_hash.sha256_12hex(std.testing.allocator, account_id);
    defer std.testing.allocator.free(id_hash);
    const identity_domain = try std.fmt.allocPrint(std.testing.allocator, "codex-identity", .{});
    defer std.testing.allocator.free(identity_domain);
    const lock_path = try repair_state.lockPath(std.testing.allocator, identity_domain, id_hash);
    defer std.testing.allocator.free(lock_path);
    if (std.fs.path.dirname(lock_path)) |dir| try std.fs.cwd().makePath(dir);
    const holder = try std.fs.createFileAbsolute(lock_path, .{ .truncate = false, .mode = 0o600, .lock = .exclusive, .lock_nonblocking = true });

    {
        defer holder.close();
        // expired token + held identity lock → defer typed, fail closed (no endpoint).
        try std.testing.expectError(error.RefreshTransientLock, validateToken(&ctx));
        try std.testing.expectEqual(types.RefreshOutcome.transient_lock, ctx.last_refresh_outcome.?);
        try std.testing.expectEqualStrings("identity_lock_held", ctx.last_refresh_reason.?);
    }

    // Holder released: the refresh proceeds past BOTH locks to the endpoint
    // (closed port), proving the deferral was the identity lock.
    ctx.last_refresh_outcome = null;
    ctx.last_refresh_reason = null;
    try std.testing.expectError(error.RefreshTransientNetwork, validateToken(&ctx));
    try std.testing.expectEqual(types.RefreshOutcome.transient_network, ctx.last_refresh_outcome.?);
}

test "attemptRefresh refuses when an identity path is declared but the store has no id (TIN-2043 missing-id policy)" {
    var rt_scope = try repair_state.TestRuntimeDirScope.init(std.testing.allocator);
    defer rt_scope.deinit(std.testing.allocator);
    rt_scope.activate();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root_path = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root_path);
    const auth_path = try std.fmt.allocPrint(std.testing.allocator, "{s}/auth.json", .{root_path});
    defer std.testing.allocator.free(auth_path);

    // Store declares the shape but carries NO account_id.
    {
        const f = try std.fs.createFileAbsolute(auth_path, .{});
        defer f.close();
        try f.writeAll(
            \\{"auth_mode":"chatgpt","tokens":{"access_token":"at","refresh_token":"rt"}}
        );
    }

    const json = try std.fmt.allocPrint(std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "codex": {{ "name": "codex", "kind": "codex", "repair": {{ "owner": "oauth_mux_refresh" }}, "auth": {{ "token_endpoint": "http://127.0.0.1:9/token" }}, "credential": {{ "access_token_path": "tokens.access_token", "refresh_token_path": "tokens.refresh_token", "identity_claim_path": "tokens.account_id" }} }}
        \\  }},
        \\  "providers": {{
        \\    "codex": {{ "kind": "codex", "accounts": {{ "noid": {{ "secret": {{ "backend": "file", "path": "{s}" }} }} }} }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    , .{auth_path});
    defer std.testing.allocator.free(json);

    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.provider_name = "codex";
    ctx.account_name = "noid";
    ctx.token = .{
        .access_token = try std.testing.allocator.dupe(u8, "at"),
        .refresh_token = try std.testing.allocator.dupe(u8, "rt"),
        .expires_at = std.time.timestamp() - 10,
    };

    // Refuses before the endpoint rather than dodging the identity guard.
    try std.testing.expectError(error.RefreshTransientStore, validateToken(&ctx));
    try std.testing.expectEqual(types.RefreshOutcome.transient_store, ctx.last_refresh_outcome.?);
    try std.testing.expectEqualStrings("identity_unresolved_refusing_refresh", ctx.last_refresh_reason.?);
}

test "probeTargetsRealAccountStore gates on config_dir + a config-dir env (TIN-2039)" {
    const json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "config_dir_env": "CODEX_HOME",
        \\      "accounts": {
        \\        "homed": { "secret": { "backend": "file", "path": "/tmp/x" }, "config_dir": "/tmp/codex-homed" },
        \\        "tmpd": { "secret": { "backend": "file", "path": "/tmp/y" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    const def = config_mod.resolveProviderDefinition(parsed.value, "codex");
    // config_dir present + config_dir_env present → store is real → guard.
    try std.testing.expect(probeTargetsRealAccountStore(&ctx, "codex", "homed", def));
    // No config_dir → tmpdir mode, no real store to guard.
    try std.testing.expect(!probeTargetsRealAccountStore(&ctx, "codex", "tmpd", def));
}

test "command probe of a lock-held account store reports lock_busy without touching the store (TIN-2039)" {
    var rt_scope = try repair_state.TestRuntimeDirScope.init(std.testing.allocator);
    defer rt_scope.deinit(std.testing.allocator);
    rt_scope.activate();

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const store_dir = try tmp.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(store_dir);

    // A command probe whose command writes a marker file — proves whether
    // the probe actually executed (it must NOT when the lock is held).
    const marker = try std.fmt.allocPrint(std.testing.allocator, "{s}/probe-ran", .{store_dir});
    defer std.testing.allocator.free(marker);

    const json = try std.fmt.allocPrint(std.testing.allocator,
        \\{{
        \\  "version": 1,
        \\  "provider_definitions": {{
        \\    "codex": {{
        \\      "name": "codex", "kind": "codex", "config_dir_env": "CODEX_HOME",
        \\      "capabilities": [
        \\        {{ "name": "cap", "probe": {{ "transport": "command", "auth": "none", "timeout_ms": 5000, "command": ["/usr/bin/touch", "{s}"] }} }}
        \\      ]
        \\    }}
        \\  }},
        \\  "providers": {{
        \\    "codex": {{ "kind": "codex", "config_dir_env": "CODEX_HOME", "accounts": {{ "homed": {{ "secret": {{ "backend": "file", "path": "{s}/auth.json" }}, "config_dir": "{s}" }} }} }}
        \\  }},
        \\  "profiles": {{}},
        \\  "strategies": {{}}
        \\}}
    , .{ marker, store_dir, store_dir });
    defer std.testing.allocator.free(json);

    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.provider_name = "codex";
    ctx.account_name = "homed";
    ctx.capability_name = "cap";

    // Foreign holder on the per-account lock (the session's key).
    const lock_path = try repair_state.lockPath(std.testing.allocator, "codex", "homed");
    defer std.testing.allocator.free(lock_path);
    if (std.fs.path.dirname(lock_path)) |dir| try std.fs.cwd().makePath(dir);
    const holder = try std.fs.createFileAbsolute(lock_path, .{ .truncate = false, .mode = 0o600, .lock = .exclusive, .lock_nonblocking = true });

    {
        defer holder.close();
        const decision = try probeCapability(&ctx);
        _ = decision;
        try std.testing.expect(ctx.last_probe_lock_busy);
        try std.testing.expect(!ctx.last_probe_executed);
        // The probe command never ran → no marker, the store was untouched.
        try std.testing.expect(std.fs.accessAbsolute(marker, .{}) == error.FileNotFound);
    }
}

test "injectEnv refuses a claude account without config_dir (TIN-2054 tmpdir guard)" {
    const json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "claude": {
        \\      "kind": "claude",
        \\      "config_dir_env": "CLAUDE_CONFIG_DIR",
        \\      "accounts": {
        \\        "nodir": { "secret": { "backend": "keychain", "service": "Claude Code-credentials", "account": "jess" } },
        \\        "homed": { "secret": { "backend": "keychain", "service": "Claude Code-credentials", "account": "jess" }, "config_dir": "~/.local/share/oauth-mux/claude/x" }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    // No config_dir → refuse with the typed error, before any tmpdir write.
    {
        var ctx = Context.init(std.testing.allocator, parsed.value, &store);
        defer ctx.deinit();
        ctx.provider_name = "claude";
        ctx.account_name = "nodir";
        ctx.provider_kind = .claude;
        ctx.token = .{ .access_token = try std.testing.allocator.dupe(u8, "at") };
        try std.testing.expectError(error.ProviderNeedsConfigDir, injectEnv(&ctx));
    }

    // Hardening: even if provider_kind was never resolved (null), the guard
    // still fires by deriving the kind from the provider name.
    {
        var ctx = Context.init(std.testing.allocator, parsed.value, &store);
        defer ctx.deinit();
        ctx.provider_name = "claude";
        ctx.account_name = "nodir";
        ctx.provider_kind = null;
        ctx.token = .{ .access_token = try std.testing.allocator.dupe(u8, "at") };
        try std.testing.expectError(error.ProviderNeedsConfigDir, injectEnv(&ctx));
    }

    // With config_dir → safe path: CLAUDE_CONFIG_DIR is set to the (expanded) dir.
    {
        var ctx = Context.init(std.testing.allocator, parsed.value, &store);
        defer ctx.deinit();
        ctx.provider_name = "claude";
        ctx.account_name = "homed";
        ctx.provider_kind = .claude;
        ctx.token = .{ .access_token = try std.testing.allocator.dupe(u8, "at") };
        try injectEnv(&ctx);
        try expectEnvPairContains(ctx.env_pairs.items, "CLAUDE_CONFIG_DIR", "oauth-mux/claude/x");
    }
}

test "injectEnv refuses a custom-kind provider that sets CLAUDE_CONFIG_DIR (TIN-2054 hazard-signal guard)" {
    // A provider_definitions entry with a NON-enum kind (provider_kind resolves
    // null) but config_dir_env=CLAUDE_CONFIG_DIR is the keychain-hazard shape —
    // reachable because runEnv/runProbe skip config.validate. Keyed on the
    // env-var hazard signal, not the enum, so it is still refused.
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "claude-kc": { "name": "claude-kc", "injection": { "config_dir_env": "CLAUDE_CONFIG_DIR", "credential_filename": ".credentials.json" } }
        \\  },
        \\  "providers": {
        \\    "claude-kc": { "kind": "claude-kc", "accounts": { "nodir": { "secret": { "backend": "keychain", "service": "Claude Code-credentials", "account": "jess" } } } }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    var ctx = Context.init(std.testing.allocator, parsed.value, &store);
    defer ctx.deinit();
    ctx.provider_name = "claude-kc";
    ctx.account_name = "nodir";
    ctx.provider_kind = null; // non-enum kind → null
    ctx.token = .{ .access_token = try std.testing.allocator.dupe(u8, "at") };
    try std.testing.expectError(error.ProviderNeedsConfigDir, injectEnv(&ctx));
}

fn expectEnvPairContains(pairs: []const [2][]const u8, key: []const u8, needle: []const u8) !void {
    for (pairs) |p| {
        if (std.mem.eql(u8, p[0], key)) {
            if (std.mem.indexOf(u8, p[1], needle) != null) return;
            std.debug.print("env {s}={s} does not contain {s}\n", .{ key, p[1], needle });
            return error.TestUnexpectedResult;
        }
    }
    return error.TestUnexpectedResult;
}

test "refreshWritebackBackend refuses the canonical shared Claude keychain item (TIN-2054 #2)" {
    var rt_scope = try repair_state.TestRuntimeDirScope.init(std.testing.allocator);
    defer rt_scope.deinit(std.testing.allocator);
    rt_scope.activate();

    // An account whose keychain service is the UNSUFFIXED canonical
    // `Claude Code-credentials` (the bare-Claude credential) must never be a
    // proactive-refresh target — rotating it would revoke the user's own
    // Claude RT. Refused regardless of platform/grant (defense in depth).
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "claude": { "name": "claude", "repair": { "owner": "oauth_mux_refresh" }, "auth": { "token_endpoint": "https://example.invalid/token" } }
        \\  },
        \\  "providers": {
        \\    "claude": {
        \\      "kind": "claude",
        \\      "accounts": {
        \\        "canonical": { "secret": { "backend": "keychain", "service": "Claude Code-credentials", "account": "jess" } },
        \\        "suffixed": { "secret": { "backend": "keychain", "service": "Claude Code-credentials-26ae8e92", "account": "jess" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try config_mod.loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();
    var store = health_mod.HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();
    const def = config_mod.resolveProviderDefinition(parsed.value, "claude");

    // Canonical unsuffixed service → refused with the canonical-item reason.
    {
        var ctx = Context.init(std.testing.allocator, parsed.value, &store);
        defer ctx.deinit();
        ctx.provider_name = "claude";
        ctx.account_name = "canonical";
        try std.testing.expectError(error.TokenRefreshFailed, refreshWritebackBackend(&ctx, def));
        try std.testing.expectEqualStrings("writeback_refused_canonical_keychain_item", ctx.last_refresh_reason.?);

        var events = std.ArrayList(u8).init(std.testing.allocator);
        defer events.deinit();
        try repair_state.writeEvents(std.testing.allocator, events.writer(), true, 10);
        try std.testing.expect(std.mem.indexOf(
            u8,
            events.items,
            "\"refresh_outcome\":null,\"outcome\":\"not_admitted\",\"reason\":\"writeback_refused_canonical_keychain_item\",\"ok\":false,\"executed\":false",
        ) != null);
    }

    // A per-config-dir SUFFIXED service is NOT caught by this guard — it
    // proceeds to the normal admission ladder (which then gates on platform
    // keychain-write support + consent), never the canonical-item refusal.
    {
        var ctx = Context.init(std.testing.allocator, parsed.value, &store);
        defer ctx.deinit();
        ctx.provider_name = "claude";
        ctx.account_name = "suffixed";
        const result = refreshWritebackBackend(&ctx, def);
        if (result) |_| {} else |_| {}
        if (ctx.last_refresh_reason) |reason| {
            try std.testing.expect(!std.mem.eql(u8, reason, "writeback_refused_canonical_keychain_item"));
        }
    }
}

test "canonical Claude keychain refusal block is byte-identical to main" {
    const source = @embedFile("pipeline.zig");
    const canonical_block =
        \\    if (backend == .keychain and std.mem.eql(u8, backend.keychain.service, provider_schema.claude_keychain_service_base)) {
        \\        const plan = secret.WritebackPlan{
        \\            .capability = secret.writeCapability(backend),
        \\            .automatic_refresh_admitted = false,
        \\            .reason = "writeback_refused_canonical_keychain_item",
        \\        };
        \\        log.err("token: refusing refresh writeback for {s}:{s}: targets the canonical shared keychain item '{s}' (the bare-Claude credential) — use a per-config-dir suffixed service", .{ prov, acct, provider_schema.claude_keychain_service_base });
        \\        recordRefreshEvent(ctx, plan, "not_admitted", plan.reason, false, false);
        \\        return error.TokenRefreshFailed;
        \\    }
    ;
    try std.testing.expectEqual(
        @as(usize, 1),
        std.mem.count(u8, source, canonical_block),
    );
}
