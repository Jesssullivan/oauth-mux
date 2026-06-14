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
    // Diagnostics: the most recent refresh outcome/reason recorded for this
    // context (also the assertable seam in tests, where events are skipped).
    last_refresh_outcome: ?[]const u8 = null,
    last_refresh_reason: ?[]const u8 = null,

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

        // Set context for this attempt
        ctx.provider_name = candidate.provider;
        ctx.account_name = candidate.account;
        ctx.capability_name = candidate.capability;
        ctx.provider_kind = config_mod.resolveProviderKind(ctx.cfg, candidate.provider);

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
        error.TokenRevoked,
        => ctx.health.recordFailure(key, .auth_failure),
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
                        recordRefreshEvent(ctx, writeback.plan, "deferred", "refresh_requires_mutating_budget", false, false);
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
    switch (classification) {
        .dead => {
            const key = health_mod.accountKey(prov, acct);
            ctx.health.recordHttpClassification(key.slice(), result.status, classification);
            evidence_key = key;
        },
        else => {
            const key = health_mod.capabilityKey(prov, acct, capability);
            ctx.health.recordHttpClassification(key.slice(), result.status, classification);
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

    return probe_env;
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
            recordRefreshEvent(ctx, writeback.plan, "deferred", "refresh_lock_held", false, false);
            // Inside the 30s skew the current token is still provider-valid:
            // keep serving it so a benign in-flight peer rotation does not
            // poison route health as an auth failure. Only an actually
            // expired token fails closed.
            if (ctx.token) |tok| {
                if (tok.expires_at) |exp| {
                    if (std.time.timestamp() < exp) return;
                }
            }
            return error.TokenRefreshFailed;
        },
        else => {
            recordRefreshEvent(ctx, writeback.plan, "lock_failed", @errorName(e), false, false);
            return error.TokenRefreshFailed;
        },
    };
    defer refresh_lock.release();

    // TIN-2073 (review): revalidate under the lock — the broker's
    // lock-then-revalidate pattern. The rt argument was read BEFORE the
    // flock; a peer's rotation may have completed inside that window. If
    // the re-read credential is already fresh, adopt it and skip the
    // endpoint; otherwise rotate with the re-read refresh token, never the
    // pre-lock snapshot.
    const existing_raw: ?[]const u8 = readSecretRaw(ctx) catch null;
    defer if (existing_raw) |r| ctx.allocator.free(r);
    const fresh_snapshot: ?provider.TokenFields = if (existing_raw) |r| (parseRawToken(ctx, r) catch null) else null;
    var fresh_adopted = false;
    defer if (fresh_snapshot) |f| {
        if (!fresh_adopted) freeTokenFields(ctx.allocator, f);
    };
    if (fresh_snapshot) |f| {
        if (f.expires_at) |exp| {
            if (std.time.timestamp() < exp - 30) {
                if (ctx.token) |old| freeTokenFields(ctx.allocator, old);
                ctx.token = f;
                fresh_adopted = true;
                log.info("token: concurrent rotation detected for {s}:{s}; adopted fresh credential", .{ prov, acct });
                recordRefreshEvent(ctx, writeback.plan, "not_needed", "concurrent_rotation_detected", true, false);
                return;
            }
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
        recordRefreshEvent(ctx, writeback.plan, "writeback_refused", "store_unreadable_refusing_lossy_write", false, false);
        return error.TokenRefreshFailed;
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
            recordRefreshEvent(ctx, writeback.plan, "writeback_refused", "identity_unresolved_refusing_refresh", false, false);
            return error.TokenRefreshFailed;
        };
        defer ctx.allocator.free(account_id);
        const id_hash = identity_hash.sha256_12hex(ctx.allocator, account_id) catch return error.OutOfMemory;
        defer ctx.allocator.free(id_hash);
        const identity_domain = std.fmt.allocPrint(ctx.allocator, "{s}-identity", .{prov}) catch return error.OutOfMemory;
        defer ctx.allocator.free(identity_domain);
        identity_lock = repair_state.acquireRepairLock(ctx.allocator, identity_domain, id_hash) catch |e| switch (e) {
            error.RepairInProgress => {
                log.warn("token: refresh deferred for {s}:{s}: identity lock held by a live session", .{ prov, acct });
                recordRefreshEvent(ctx, writeback.plan, "deferred", "identity_lock_held", false, false);
                // Token still valid inside the skew → keep serving it.
                if (ctx.token) |tok| {
                    if (tok.expires_at) |exp| {
                        if (std.time.timestamp() < exp) return;
                    }
                }
                return error.TokenRefreshFailed;
            },
            else => {
                recordRefreshEvent(ctx, writeback.plan, "lock_failed", @errorName(e), false, false);
                return error.TokenRefreshFailed;
            },
        };
    }

    const url = def.auth.token_endpoint orelse fallbackRefreshUrl(ctx) orelse {
        log.warn("token: no refresh URL for {s}", .{prov});
        recordRefreshEvent(ctx, writeback.plan, "no_token_endpoint", "token_endpoint_missing", false, false);
        return error.TokenRefreshFailed;
    };

    // oauth.refreshToken bounds the post-connect send/recv legs with a
    // 30s socket deadline (TIN-2074, posix only), so the dominant hang
    // mode — server accepts then stalls — can no longer wedge the held
    // flock indefinitely. Residual: DNS/TCP-connect/TLS-handshake are
    // bounded only by the OS TCP timeout, and Windows has no deadline
    // (winsock SO_RCVTIMEO takes DWORD ms, gated off). Acceptable while
    // builtin grants stay off; revisit if a connect-phase stall proves
    // material before the flip.
    const result = oauth.refreshToken(ctx.allocator, url, effective_rt, def.auth.client_id) catch |e| {
        log.err("token: refresh failed: {s}", .{@errorName(e)});
        recordRefreshEvent(ctx, writeback.plan, "token_endpoint_failed", @errorName(e), false, true);
        return error.TokenRefreshFailed;
    };
    errdefer ctx.allocator.free(result.access_token);
    errdefer if (result.refresh_token) |new_rt| ctx.allocator.free(new_rt);

    const expires_at = if (result.expires_in) |ei| std.time.timestamp() + ei else null;
    var retained_refresh_token: ?[]const u8 = null;
    var retained_refresh_token_from_old = false;
    if (result.refresh_token) |new_rt| {
        retained_refresh_token = new_rt;
    } else {
        retained_refresh_token = ctx.allocator.dupe(u8, effective_rt) catch return error.OutOfMemory;
        retained_refresh_token_from_old = true;
    }
    errdefer if (retained_refresh_token_from_old) {
        if (retained_refresh_token) |old_rt| ctx.allocator.free(old_rt);
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
    // keep the store intact; the just-minted access token stays usable
    // in-process for this run. (buildCredentialGeneric remains the
    // legitimate writer only for first-time injection of a fresh tmpdir
    // credential, in injectEnv — a different path with no existing store.)
    const schema_token = provider_schema.TokenFields{
        .access_token = result.access_token,
        .refresh_token = retained_refresh_token,
        .expires_at = expires_at,
    };
    const credential = provider_schema.mergeCredentialGeneric(def, raw_for_merge, schema_token, ctx.allocator) catch |e| {
        log.err("token: refusing lossy writeback for {s}: merge failed ({s})", .{ prov, @errorName(e) });
        recordRefreshEvent(ctx, writeback.plan, "writeback_refused", "merge_failed_refusing_lossy_write", false, false);
        return error.TokenRefreshFailed;
    };
    defer ctx.allocator.free(credential);

    secret.writeReplace(writeback.backend, credential, ctx.allocator) catch |e| {
        log.err("token: refresh writeback failed for {s}: {s}", .{ prov, @errorName(e) });
        recordRefreshEvent(ctx, writeback.plan, "writeback_failed", @errorName(e), false, true);
        return error.TokenRefreshFailed;
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

    recordRefreshEvent(ctx, writeback.plan, "persisted", writeback.plan.reason, true, true);
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
        recordRefreshEvent(ctx, plan, "not_admitted", plan.reason, false, false);
        return error.TokenRefreshFailed;
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
    ctx.last_refresh_outcome = outcome;
    ctx.last_refresh_reason = reason;
    if (comptime builtin.is_test) return;
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
        .ok = ok,
        .executed = executed,
        .interactive = false,
        .mutating = executed,
    }) catch {};
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
        error.TokenRefreshFailed,
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
        error.TokenRefreshFailed,
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
        \\            "command": ["sh", "-c", "printf '{\"loggedIn\":true}'"],
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
    store.recordHttpClassification("toy:default#status", 400, .{ .degraded = .unknown_4xx });

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
    store.recordHttpClassification("codex:max-1", 500, .provider_degraded);

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
        error.TokenRefreshFailed,
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
    try std.testing.expectEqualStrings("deferred", ctx.last_refresh_outcome.?);
    try std.testing.expectEqualStrings("refresh_requires_mutating_budget", ctx.last_refresh_reason.?);

    // Actually expired: fails closed for the repair phase, still no rotation.
    ctx.token.?.expires_at = now - 10;
    ctx.last_refresh_outcome = null;
    ctx.last_refresh_reason = null;
    try std.testing.expectError(error.TokenExpired, validateToken(&ctx));
    try std.testing.expectEqualStrings("deferred", ctx.last_refresh_outcome.?);
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
        try std.testing.expectError(error.TokenRefreshFailed, validateToken(&ctx));
        try std.testing.expectEqualStrings("deferred", ctx.last_refresh_outcome.?);
        try std.testing.expectEqualStrings("refresh_lock_held", ctx.last_refresh_reason.?);

        // Within the skew window (expiring but not expired) a held lock
        // defers WITHOUT failing the candidate: the token is still valid
        // and health must not be poisoned by a benign peer rotation.
        ctx.token.?.expires_at = std.time.timestamp() + 10;
        ctx.last_refresh_outcome = null;
        ctx.last_refresh_reason = null;
        try validateToken(&ctx);
        try std.testing.expectEqualStrings("deferred", ctx.last_refresh_outcome.?);
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
    try std.testing.expectError(error.TokenRefreshFailed, validateToken(&ctx));
    try std.testing.expectEqualStrings("token_endpoint_failed", ctx.last_refresh_outcome.?);
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
    try std.testing.expectEqualStrings("not_needed", ctx.last_refresh_outcome.?);
    try std.testing.expectEqualStrings("concurrent_rotation_detected", ctx.last_refresh_reason.?);
    try std.testing.expectEqualStrings("at-peer-fresh", ctx.token.?.access_token);
    try std.testing.expectEqualStrings("rt-peer-fresh", ctx.token.?.refresh_token.?);
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
    try std.testing.expectError(error.TokenRefreshFailed, validateToken(&ctx));
    try std.testing.expectEqualStrings("writeback_refused", ctx.last_refresh_outcome.?);
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
        try std.testing.expectError(error.TokenRefreshFailed, validateToken(&ctx));
        try std.testing.expectEqualStrings("deferred", ctx.last_refresh_outcome.?);
        try std.testing.expectEqualStrings("identity_lock_held", ctx.last_refresh_reason.?);
    }

    // Holder released: the refresh proceeds past BOTH locks to the endpoint
    // (closed port), proving the deferral was the identity lock.
    ctx.last_refresh_outcome = null;
    ctx.last_refresh_reason = null;
    try std.testing.expectError(error.TokenRefreshFailed, validateToken(&ctx));
    try std.testing.expectEqualStrings("token_endpoint_failed", ctx.last_refresh_outcome.?);
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
    try std.testing.expectError(error.TokenRefreshFailed, validateToken(&ctx));
    try std.testing.expectEqualStrings("writeback_refused", ctx.last_refresh_outcome.?);
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
