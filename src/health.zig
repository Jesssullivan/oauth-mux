const std = @import("std");
const types = @import("types.zig");
const paths = @import("paths.zig");
const provider_schema = @import("provider_schema.zig");
const log = @import("log.zig");

pub const AccountHealth = struct {
    score: types.HealthScore = .{},
    circuit: types.CircuitState = .closed,
    bucket: types.TokenBucket = .{},
    liveness: types.CredentialLiveness = .{ .live = .{ .availability = .available } },
    last_http_status: ?u16 = null,
    last_probe_source: ?ProbeEvidenceSource = null,
    last_probe_observed_at: ?i64 = null,
    last_probe_retry_after_s: ?u32 = null,
    last_probe_hint_class: ?ProbeHintClass = null,
    last_probe_decision: ?types.MuxDecision = null,
    consecutive_failures: u32 = 0,
    quota_exhausted_until: ?i64 = null,
    rate_limited_until: ?i64 = null,
};

pub const ProbeEvidenceSource = enum {
    credential_validation,
    capability_probe,
    broker_run_live,
    observed_child_output,
    supervised_child_output,
    http_status,
};

pub const ProbeHintClass = enum {
    none,
    rate_limit,
    quota_exhausted,
    auth_dead,
    provider_degraded,
    tier_insufficient,
    subscription_paused,
    scope_insufficient,
    audience_mismatch,
    schema_invalid,
    terms_required,
    step_up_required,
    pending_verification,
    unknown_4xx,
    failure,
};

pub const HealthKey = struct {
    provider: []const u8,
    account: []const u8,
    capability: ?[]const u8 = null,
};

pub const KeyBuf = struct {
    buf: [256]u8 = undefined,
    len: usize = 0,

    pub fn slice(self: *const KeyBuf) []const u8 {
        return self.buf[0..self.len];
    }

    fn append(self: *KeyBuf, value: []const u8) void {
        for (value) |c| {
            if (self.len >= self.buf.len) break;
            self.buf[self.len] = c;
            self.len += 1;
        }
    }

    fn appendByte(self: *KeyBuf, value: u8) void {
        if (self.len >= self.buf.len) return;
        self.buf[self.len] = value;
        self.len += 1;
    }
};

pub fn accountKey(provider: []const u8, account: []const u8) KeyBuf {
    var kb = KeyBuf{};
    kb.append(provider);
    kb.appendByte(':');
    kb.append(account);
    return kb;
}

pub fn capabilityKey(provider: []const u8, account: []const u8, capability: []const u8) KeyBuf {
    var kb = accountKey(provider, account);
    kb.appendByte('#');
    kb.append(capability);
    return kb;
}

pub fn parseHealthKey(key: []const u8) ?HealthKey {
    const colon = std.mem.indexOf(u8, key, ":") orelse return null;
    if (colon == 0 or colon + 1 >= key.len) return null;

    const rest = key[colon + 1 ..];
    if (std.mem.indexOf(u8, rest, "#")) |hash| {
        if (hash == 0 or hash + 1 >= rest.len) return null;
        return .{
            .provider = key[0..colon],
            .account = rest[0..hash],
            .capability = rest[hash + 1 ..],
        };
    }

    return .{
        .provider = key[0..colon],
        .account = rest,
    };
}

pub fn writeLivenessSummary(writer: anytype, liveness: types.CredentialLiveness) !void {
    switch (liveness) {
        .live => |live| switch (live.availability) {
            .available => try writer.writeAll("available"),
            .rate_limited => |rl| try writer.print("rate_limited:{s}:{d}s", .{
                @tagName(rl.window),
                rl.retry_after_s,
            }),
            .quota_exhausted => |q| {
                if (q.window_resets_at) |reset| {
                    try writer.print("quota_exhausted:reset@{d}", .{reset});
                } else {
                    try writer.writeAll("quota_exhausted");
                }
            },
            .cooldown => |c| try writer.print("cooldown:until@{d}", .{c.until}),
        },
        .degraded => |d| try writer.print("degraded:{s}", .{@tagName(d.reason)}),
        .dead => |d| try writer.print("dead:{s}", .{@tagName(d.reason)}),
    }
}

pub fn hintClassFromClassification(classification: types.HttpClassification) ProbeHintClass {
    return switch (classification) {
        .success => .none,
        .rate_limited => .rate_limit,
        .quota_exhausted => .quota_exhausted,
        .dead => .auth_dead,
        .provider_degraded => .provider_degraded,
        .degraded => |reason| switch (reason) {
            .tier_insufficient => .tier_insufficient,
            .subscription_paused => .subscription_paused,
            .scope_insufficient => .scope_insufficient,
            .audience_mismatch => .audience_mismatch,
            .schema_invalid => .schema_invalid,
            .terms_required => .terms_required,
            .step_up_required => .step_up_required,
            .pending_verification => .pending_verification,
            .provider_degraded => .provider_degraded,
            .unknown_4xx => .unknown_4xx,
        },
        .failure => .failure,
    };
}

pub fn retryAfterFromClassification(classification: types.HttpClassification) ?u32 {
    return switch (classification) {
        .rate_limited => |rl| rl.retry_after_s,
        .quota_exhausted => |quota| quota.retry_after_s,
        else => null,
    };
}

pub fn decisionFromClassification(classification: types.HttpClassification) types.MuxDecision {
    return switch (classification) {
        .success => .use_this,
        .rate_limited => .wait_and_retry,
        .quota_exhausted, .dead, .degraded, .failure => .try_next_account,
        .provider_degraded => .try_next_provider,
    };
}

pub const HealthStore = struct {
    allocator: std.mem.Allocator,
    accounts: std.StringHashMap(AccountHealth),
    config: types.HealthConfig,

    pub fn init(allocator: std.mem.Allocator, hc: types.HealthConfig) HealthStore {
        return .{
            .allocator = allocator,
            .accounts = std.StringHashMap(AccountHealth).init(allocator),
            .config = hc,
        };
    }

    pub fn deinit(self: *HealthStore) void {
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.accounts.deinit();
    }

    pub fn getOrCreate(self: *HealthStore, key: []const u8) !*AccountHealth {
        const result = self.accounts.getOrPut(key) catch return error.OutOfMemory;
        if (!result.found_existing) {
            result.key_ptr.* = self.allocator.dupe(u8, key) catch return error.OutOfMemory;
            result.value_ptr.* = .{
                .score = .{ .score = self.config.initial_score },
            };
        }
        return result.value_ptr;
    }

    pub fn recordSuccess(self: *HealthStore, key: []const u8) void {
        const health = self.getOrCreate(key) catch return;
        health.score.score += self.config.success_bonus;
        health.score.successes += 1;
        health.score.clamp();
        health.score.last_updated = std.time.timestamp();

        switch (health.circuit) {
            .half_open => |*ho| {
                ho.successes_so_far += 1;
                if (ho.successes_so_far >= ho.successes_needed) {
                    health.circuit = .closed;
                    log.debug("health: {s} circuit closed", .{key});
                }
            },
            else => {},
        }
    }

    pub fn recordProbeEvidence(
        self: *HealthStore,
        key: []const u8,
        source: ProbeEvidenceSource,
        retry_after_s: ?u32,
        hint_class: ProbeHintClass,
        decision: types.MuxDecision,
    ) void {
        const health = self.getOrCreate(key) catch return;
        health.last_probe_source = source;
        health.last_probe_observed_at = std.time.timestamp();
        health.last_probe_retry_after_s = retry_after_s;
        health.last_probe_hint_class = hint_class;
        health.last_probe_decision = decision;
    }

    pub fn recordFailure(self: *HealthStore, key: []const u8, kind: FailureKind) void {
        const health = self.getOrCreate(key) catch return;
        const now = std.time.timestamp();

        const penalty = switch (kind) {
            .rate_limited => blk: {
                health.score.rate_limits += 1;
                break :blk self.config.rate_limit_penalty;
            },
            else => blk: {
                health.score.failures += 1;
                break :blk self.config.failure_penalty;
            },
        };
        health.score.score += penalty;
        health.score.clamp();
        health.score.last_updated = now;

        // Check circuit breaker threshold: 3 failures in 60s window
        if (now - health.score.window_start > 60) {
            health.score.window_start = now;
            health.score.failures = 1;
        }
        if (health.score.failures >= 3) {
            health.circuit = .{ .open = .{
                .opened_at = now,
                .failure_count = health.score.failures,
                .retry_at = now + 30,
            } };
            log.debug("health: {s} circuit opened", .{key});
        }

        // Half-open → open on any failure
        switch (health.circuit) {
            .half_open => {
                health.circuit = .{ .open = .{
                    .opened_at = now,
                    .failure_count = health.score.failures,
                    .retry_at = now + 30,
                } };
            },
            else => {},
        }

        if (kind == .auth_failure) {
            health.rate_limited_until = null;
            health.quota_exhausted_until = null;
            health.liveness = .{ .dead = .{
                .reason = .auth_permanently_failed,
                .since = now,
            } };
            health.last_probe_source = .credential_validation;
            health.last_probe_observed_at = now;
            health.last_probe_retry_after_s = null;
            health.last_probe_hint_class = .auth_dead;
            health.last_probe_decision = .try_next_account;
        }
    }

    pub fn isAvailable(self: *HealthStore, key: []const u8) bool {
        const health = self.getOrCreate(key) catch return true;
        const now = std.time.timestamp();
        const now_ns: i128 = @as(i128, now) * 1_000_000_000;

        switch (health.circuit) {
            .closed => {},
            .open => |oc| {
                if (now >= oc.retry_at) {
                    health.circuit = .{ .half_open = .{
                        .probe_started_at = now,
                    } };
                } else {
                    return false;
                }
            },
            .half_open => {},
        }

        return health.bucket.tryConsume(now_ns);
    }

    pub fn passiveRecovery(self: *HealthStore) void {
        const now = std.time.timestamp();
        var it = self.accounts.valueIterator();
        while (it.next()) |health| {
            if (health.score.last_updated > 0) {
                const elapsed_hours = @divFloor(now - health.score.last_updated, 3600);
                if (elapsed_hours > 0) {
                    health.score.score += self.config.decay_per_hour * @as(i32, @intCast(@min(elapsed_hours, 100)));
                    health.score.clamp();
                }
            }
        }
    }

    pub fn load(allocator: std.mem.Allocator, hc: types.HealthConfig) HealthStore {
        const path = paths.healthFilePath(allocator) catch return init(allocator, hc);
        defer allocator.free(path);

        const file = std.fs.openFileAbsolute(path, .{}) catch return init(allocator, hc);
        defer file.close();

        const bytes = file.readToEndAlloc(allocator, 256 * 1024) catch return init(allocator, hc);
        defer allocator.free(bytes);

        var store = loadFromBytes(allocator, hc, bytes);
        log.debug("health: loaded {d} accounts from {s}", .{ store.accounts.count(), path });
        return store;
    }

    pub fn loadFromBytes(allocator: std.mem.Allocator, hc: types.HealthConfig, bytes: []const u8) HealthStore {
        var store = init(allocator, hc);

        const parsed = std.json.parseFromSlice(HealthFile, allocator, bytes, .{
            .ignore_unknown_fields = true,
            .allocate = .alloc_always,
        }) catch return store;
        defer parsed.deinit();

        for (parsed.value.accounts) |entry| {
            store.putHealthEntry(entry) catch continue;
        }

        return store;
    }

    pub fn persist(self: *HealthStore) void {
        const path = paths.healthFilePath(self.allocator) catch return;
        defer self.allocator.free(path);

        if (std.fs.path.dirname(path)) |dir| {
            std.fs.makeDirAbsolute(dir) catch |e| switch (e) {
                error.PathAlreadyExists => {},
                else => return,
            };
        }

        const file = std.fs.createFileAbsolute(path, .{ .mode = 0o600 }) catch return;
        defer file.close();

        writeJson(self, file.writer()) catch return;
        log.debug("health: persisted {d} accounts to {s}", .{ self.accounts.count(), path });
    }

    fn writeJson(self: *HealthStore, writer: anytype) !void {
        try writer.writeAll("{\"accounts\":[");
        var first = true;
        var it = self.accounts.iterator();
        while (it.next()) |entry| {
            if (!first) try writer.writeByte(',');
            first = false;
            const h = entry.value_ptr.*;
            try writer.writeByte('{');
            try writer.writeAll("\"key\":");
            try writeJsonString(writer, entry.key_ptr.*);
            try writer.print(
                ",\"score\":{d},\"window_start\":{d},\"successes\":{d},\"failures\":{d},\"rate_limits\":{d},\"last_updated\":{d},\"circuit_open\":{s},\"consecutive_failures\":{d}",
                .{
                    h.score.score,
                    h.score.window_start,
                    h.score.successes,
                    h.score.failures,
                    h.score.rate_limits,
                    h.score.last_updated,
                    if (h.circuit.isClosed()) "false" else "true",
                    h.consecutive_failures,
                },
            );
            try writeOptU16Field(writer, "last_http_status", h.last_http_status);
            try writeProbeEvidenceFields(writer, h);
            try writeOptI64Field(writer, "quota_exhausted_until", h.quota_exhausted_until);
            try writeOptI64Field(writer, "rate_limited_until", h.rate_limited_until);
            try writer.writeAll(",\"liveness\":");
            try writeLiveness(writer, h.liveness);
            try writer.writeByte('}');
        }
        try writer.writeAll("],\"version\":2}");
    }

    const HealthFile = struct {
        version: u32 = 1,
        accounts: []const HealthEntry = &.{},
    };

    const HealthEntry = struct {
        key: []const u8,
        score: i32 = 50,
        successes: u32 = 0,
        failures: u32 = 0,
        rate_limits: u32 = 0,
        window_start: i64 = 0,
        last_updated: i64 = 0,
        circuit_open: bool = false,
        last_http_status: ?u16 = null,
        last_probe_source: ?[]const u8 = null,
        last_probe_observed_at: ?i64 = null,
        last_probe_retry_after_s: ?u32 = null,
        last_probe_hint_class: ?[]const u8 = null,
        last_probe_decision: ?[]const u8 = null,
        consecutive_failures: u32 = 0,
        quota_exhausted_until: ?i64 = null,
        rate_limited_until: ?i64 = null,
        liveness: ?LivenessEntry = null,
    };

    const LivenessEntry = struct {
        state: []const u8,
        availability: ?[]const u8 = null,
        reason: ?[]const u8 = null,
        since: ?i64 = null,
        retry_at: ?i64 = null,
        retry_after_s: ?u32 = null,
        limited_at: ?i64 = null,
        window: ?[]const u8 = null,
        window_resets_at: ?i64 = null,
        usage_pct: ?u8 = null,
        exhausted_at: ?i64 = null,
        cooldown_until: ?i64 = null,
        cooldown_reason: ?[]const u8 = null,
    };

    fn putHealthEntry(self: *HealthStore, entry: HealthEntry) !void {
        const key = try self.allocator.dupe(u8, entry.key);
        self.accounts.put(key, .{
            .score = .{
                .score = entry.score,
                .window_start = entry.window_start,
                .successes = entry.successes,
                .failures = entry.failures,
                .rate_limits = entry.rate_limits,
                .last_updated = entry.last_updated,
            },
            .circuit = if (entry.circuit_open) .{ .open = .{
                .opened_at = entry.last_updated,
                .failure_count = entry.failures,
                .retry_at = entry.last_updated + 30,
            } } else .closed,
            .liveness = if (entry.liveness) |le| livenessFromEntry(le) else .{ .live = .{ .availability = .available } },
            .last_http_status = entry.last_http_status,
            .last_probe_source = if (entry.last_probe_source) |source| probeEvidenceSourceFromString(source) else null,
            .last_probe_observed_at = entry.last_probe_observed_at,
            .last_probe_retry_after_s = entry.last_probe_retry_after_s,
            .last_probe_hint_class = if (entry.last_probe_hint_class) |hint| probeHintClassFromString(hint) else null,
            .last_probe_decision = if (entry.last_probe_decision) |decision| muxDecisionFromString(decision) else null,
            .consecutive_failures = entry.consecutive_failures,
            .quota_exhausted_until = entry.quota_exhausted_until,
            .rate_limited_until = entry.rate_limited_until,
        }) catch |e| {
            self.allocator.free(key);
            return e;
        };
    }

    fn livenessFromEntry(entry: LivenessEntry) types.CredentialLiveness {
        if (std.mem.eql(u8, entry.state, "dead")) {
            return .{ .dead = .{
                .reason = deadReasonFromString(entry.reason orelse "auth_permanently_failed"),
                .since = entry.since orelse 0,
            } };
        }

        if (std.mem.eql(u8, entry.state, "degraded")) {
            return .{ .degraded = .{
                .reason = degradedReasonFromString(entry.reason orelse "unknown_4xx"),
                .since = entry.since orelse 0,
                .retry_at = entry.retry_at,
            } };
        }

        const availability_name = entry.availability orelse "available";
        if (std.mem.eql(u8, availability_name, "rate_limited")) {
            return .{ .live = .{ .availability = .{ .rate_limited = .{
                .retry_after_s = entry.retry_after_s orelse 0,
                .limited_at = entry.limited_at orelse 0,
                .window = rateLimitWindowFromString(entry.window orelse "unknown"),
            } } } };
        }
        if (std.mem.eql(u8, availability_name, "quota_exhausted")) {
            return .{ .live = .{ .availability = .{ .quota_exhausted = .{
                .window_resets_at = entry.window_resets_at,
                .usage_pct = entry.usage_pct,
                .exhausted_at = entry.exhausted_at orelse 0,
            } } } };
        }
        if (std.mem.eql(u8, availability_name, "cooldown")) {
            return .{ .live = .{ .availability = .{ .cooldown = .{
                .until = entry.cooldown_until orelse 0,
                .reason = "persisted",
            } } } };
        }

        return .{ .live = .{ .availability = .available } };
    }

    fn degradedReasonFromString(s: []const u8) types.DegradedReason {
        inline for (std.meta.fields(types.DegradedReason)) |field| {
            if (std.mem.eql(u8, s, field.name)) return @enumFromInt(field.value);
        }
        return .unknown_4xx;
    }

    fn deadReasonFromString(s: []const u8) types.DeadReason {
        inline for (std.meta.fields(types.DeadReason)) |field| {
            if (std.mem.eql(u8, s, field.name)) return @enumFromInt(field.value);
        }
        return .auth_permanently_failed;
    }

    fn rateLimitWindowFromString(s: []const u8) types.RateLimitWindow {
        inline for (std.meta.fields(types.RateLimitWindow)) |field| {
            if (std.mem.eql(u8, s, field.name)) return @enumFromInt(field.value);
        }
        return .unknown;
    }

    fn probeEvidenceSourceFromString(s: []const u8) ?ProbeEvidenceSource {
        inline for (std.meta.fields(ProbeEvidenceSource)) |field| {
            if (std.mem.eql(u8, s, field.name)) return @enumFromInt(field.value);
        }
        return null;
    }

    fn probeHintClassFromString(s: []const u8) ?ProbeHintClass {
        inline for (std.meta.fields(ProbeHintClass)) |field| {
            if (std.mem.eql(u8, s, field.name)) return @enumFromInt(field.value);
        }
        return null;
    }

    fn muxDecisionFromString(s: []const u8) ?types.MuxDecision {
        inline for (std.meta.fields(types.MuxDecision)) |field| {
            if (std.mem.eql(u8, s, field.name)) return @enumFromInt(field.value);
        }
        return null;
    }

    fn writeProbeEvidenceFields(writer: anytype, health: AccountHealth) !void {
        try writer.writeAll(",\"last_probe_source\":");
        if (health.last_probe_source) |source| {
            try writeJsonString(writer, @tagName(source));
        } else {
            try writer.writeAll("null");
        }
        try writeOptI64Field(writer, "last_probe_observed_at", health.last_probe_observed_at);
        try writer.writeAll(",\"last_probe_retry_after_s\":");
        if (health.last_probe_retry_after_s) |retry_after| {
            try writer.print("{d}", .{retry_after});
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(",\"last_probe_hint_class\":");
        if (health.last_probe_hint_class) |hint_class| {
            try writeJsonString(writer, @tagName(hint_class));
        } else {
            try writer.writeAll("null");
        }
        try writer.writeAll(",\"last_probe_decision\":");
        if (health.last_probe_decision) |decision| {
            try writeJsonString(writer, @tagName(decision));
        } else {
            try writer.writeAll("null");
        }
    }

    fn writeLiveness(writer: anytype, liveness: types.CredentialLiveness) !void {
        try writer.writeByte('{');
        switch (liveness) {
            .live => |live| {
                try writer.writeAll("\"state\":\"live\"");
                switch (live.availability) {
                    .available => try writer.writeAll(",\"availability\":\"available\""),
                    .rate_limited => |rl| {
                        try writer.writeAll(",\"availability\":\"rate_limited\"");
                        try writer.print(",\"retry_after_s\":{d},\"limited_at\":{d},\"window\":\"{s}\"", .{
                            rl.retry_after_s,
                            rl.limited_at,
                            @tagName(rl.window),
                        });
                    },
                    .quota_exhausted => |q| {
                        try writer.writeAll(",\"availability\":\"quota_exhausted\"");
                        try writeOptI64Field(writer, "window_resets_at", q.window_resets_at);
                        try writeOptU8Field(writer, "usage_pct", q.usage_pct);
                        try writer.print(",\"exhausted_at\":{d}", .{q.exhausted_at});
                    },
                    .cooldown => |c| {
                        try writer.writeAll(",\"availability\":\"cooldown\"");
                        try writer.print(",\"cooldown_until\":{d},\"cooldown_reason\":", .{c.until});
                        try writeJsonString(writer, c.reason);
                    },
                }
            },
            .degraded => |d| {
                try writer.print("\"state\":\"degraded\",\"reason\":\"{s}\",\"since\":{d}", .{
                    @tagName(d.reason),
                    d.since,
                });
                try writeOptI64Field(writer, "retry_at", d.retry_at);
            },
            .dead => |d| {
                try writer.print("\"state\":\"dead\",\"reason\":\"{s}\",\"since\":{d}", .{
                    @tagName(d.reason),
                    d.since,
                });
            },
        }
        try writer.writeByte('}');
    }

    fn writeJsonString(writer: anytype, value: []const u8) !void {
        try std.json.stringify(value, .{}, writer);
    }

    fn writeOptI64Field(writer: anytype, name: []const u8, value: ?i64) !void {
        try writer.print(",\"{s}\":", .{name});
        if (value) |v| {
            try writer.print("{d}", .{v});
        } else {
            try writer.writeAll("null");
        }
    }

    fn writeOptU16Field(writer: anytype, name: []const u8, value: ?u16) !void {
        try writer.print(",\"{s}\":", .{name});
        if (value) |v| {
            try writer.print("{d}", .{v});
        } else {
            try writer.writeAll("null");
        }
    }

    fn writeOptU8Field(writer: anytype, name: []const u8, value: ?u8) !void {
        try writer.print(",\"{s}\":", .{name});
        if (value) |v| {
            try writer.print("{d}", .{v});
        } else {
            try writer.writeAll("null");
        }
    }

    pub fn recordHttpStatus(self: *HealthStore, key: []const u8, status: u16, retry_after: ?u32) void {
        self.recordHttpStatusForProvider(key, provider_schema.generic_def, status, retry_after, null);
    }

    pub fn recordCapabilityHttpStatus(
        self: *HealthStore,
        provider_name: []const u8,
        account_name: []const u8,
        capability: []const u8,
        status: u16,
        retry_after: ?u32,
    ) void {
        const key = capabilityKey(provider_name, account_name, capability);
        self.recordHttpStatus(key.slice(), status, retry_after);
    }

    pub fn recordCapabilityHttpStatusForProvider(
        self: *HealthStore,
        provider_name: []const u8,
        account_name: []const u8,
        capability: []const u8,
        def: provider_schema.ProviderDefinition,
        status: u16,
        retry_after: ?u32,
        hint: ?[]const u8,
    ) void {
        const key = capabilityKey(provider_name, account_name, capability);
        self.recordHttpStatusForProvider(key.slice(), def, status, retry_after, hint);
    }

    pub fn recordHttpStatusForProvider(
        self: *HealthStore,
        key: []const u8,
        def: provider_schema.ProviderDefinition,
        status: u16,
        retry_after: ?u32,
        hint: ?[]const u8,
    ) void {
        const classification = provider_schema.classifyHttp(def, status, retry_after, hint);
        self.recordHttpClassification(key, status, classification);
        self.recordProbeEvidence(
            key,
            .http_status,
            retry_after,
            hintClassFromClassification(classification),
            decisionFromClassification(classification),
        );
    }

    pub fn recordHttpClassification(
        self: *HealthStore,
        key: []const u8,
        status: u16,
        classification: types.HttpClassification,
    ) void {
        const health = self.getOrCreate(key) catch return;
        const now = std.time.timestamp();
        health.last_http_status = status;

        switch (classification) {
            .success => {
                self.recordSuccess(key);
                health.consecutive_failures = 0;
                health.liveness = .{ .live = .{ .availability = .available } };
                health.rate_limited_until = null;
                health.quota_exhausted_until = null;
            },
            .rate_limited => |rl| {
                health.score.rate_limits += 1;
                health.score.score += self.config.rate_limit_penalty;
                health.score.clamp();
                health.score.last_updated = now;
                health.quota_exhausted_until = null;
                health.rate_limited_until = now + @as(i64, rl.retry_after_s);
                health.liveness = .{ .live = .{ .availability = .{
                    .rate_limited = .{
                        .retry_after_s = rl.retry_after_s,
                        .limited_at = now,
                        .window = rl.window,
                    },
                } } };
                log.debug("health: {s} rate limited for {d}s", .{ key, rl.retry_after_s });
            },
            .quota_exhausted => |quota| {
                health.score.rate_limits += 1;
                health.score.score += self.config.rate_limit_penalty;
                health.score.clamp();
                health.score.last_updated = now;
                health.rate_limited_until = null;
                health.quota_exhausted_until = now + @as(i64, quota.retry_after_s);
                health.liveness = .{ .live = .{ .availability = .{
                    .quota_exhausted = .{
                        .exhausted_at = now,
                        .window_resets_at = now + @as(i64, quota.retry_after_s),
                    },
                } } };
                log.info("health: {s} quota exhausted, window resets in {d}s", .{ key, quota.retry_after_s });
            },
            .dead => |reason| {
                health.rate_limited_until = null;
                health.quota_exhausted_until = null;
                health.liveness = .{ .dead = .{
                    .reason = reason,
                    .since = now,
                } };
                health.score.score = -100;
                health.score.last_updated = now;
                log.warn("health: {s} auth failed ({d}), marking dead", .{ key, status });
            },
            .degraded => |reason| {
                health.rate_limited_until = null;
                health.quota_exhausted_until = null;
                health.consecutive_failures += 1;
                health.liveness = .{ .degraded = .{
                    .reason = reason,
                    .since = now,
                    .retry_at = now + 3600,
                } };
                health.score.score += self.config.failure_penalty;
                health.score.clamp();
                health.score.last_updated = now;
                log.warn("health: {s} status {d}, marking degraded", .{ key, status });
            },
            .provider_degraded => {
                health.rate_limited_until = null;
                health.quota_exhausted_until = null;
                health.consecutive_failures += 1;
                health.liveness = .{ .degraded = .{
                    .reason = .provider_degraded,
                    .since = now,
                    .retry_at = now + 60,
                } };
                health.score.last_updated = now;
                log.debug("health: {s} provider error ({d})", .{ key, status });
            },
            .failure => {
                self.recordFailure(key, .error_response);
            },
        }
    }

    pub fn muxDecision(self: *HealthStore, key: []const u8) types.MuxDecision {
        const health = self.getOrCreate(key) catch return .try_next_account;
        const now = std.time.timestamp();

        // Check liveness state
        switch (health.liveness) {
            .dead => return .try_next_account,
            .degraded => |d| {
                if (d.retry_at) |ra| {
                    if (now < ra) {
                        if (d.reason == .provider_degraded) return .try_next_provider;
                        return .try_next_account;
                    }
                    // Retry window passed, upgrade to live
                    health.liveness = .{ .live = .{ .availability = .available } };
                } else {
                    if (d.reason == .provider_degraded) return .try_next_provider;
                    return .try_next_account;
                }
            },
            .live => |l| {
                switch (l.availability) {
                    .available => {},
                    .rate_limited => |rl| {
                        if (now < rl.limited_at + @as(i64, rl.retry_after_s)) {
                            return .wait_and_retry;
                        }
                        health.liveness = .{ .live = .{ .availability = .available } };
                    },
                    .quota_exhausted => |q| {
                        if (q.window_resets_at) |reset| {
                            if (now < reset) return .try_next_account;
                        }
                        health.liveness = .{ .live = .{ .availability = .available } };
                    },
                    .cooldown => |c| {
                        if (now < c.until) return .wait_and_retry;
                        health.liveness = .{ .live = .{ .availability = .available } };
                    },
                }
            },
        }

        // Check circuit breaker
        switch (health.circuit) {
            .closed => {},
            .open => |oc| {
                if (now < oc.retry_at) return .try_next_account;
            },
            .half_open => {},
        }

        // Check token bucket
        const now_ns: i128 = @as(i128, now) * 1_000_000_000;
        if (!health.bucket.tryConsume(now_ns)) return .wait_and_retry;

        return .use_this;
    }

    pub fn muxDecisionFor(
        self: *HealthStore,
        provider_name: []const u8,
        account_name: []const u8,
        capability: ?[]const u8,
    ) types.MuxDecision {
        const base_key = accountKey(provider_name, account_name);
        const base_decision = self.muxDecision(base_key.slice());
        if (base_decision != .use_this) return base_decision;

        if (capability) |cap| {
            const route_key = capabilityKey(provider_name, account_name, cap);
            return self.muxDecision(route_key.slice());
        }

        return .use_this;
    }

    pub const FailureKind = enum {
        error_response,
        rate_limited,
        timeout,
        auth_failure,
    };
};

test "HealthStore basic lifecycle" {
    var store = HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    store.recordSuccess("claude:work");
    const health = store.accounts.get("claude:work").?;
    try std.testing.expectEqual(@as(i32, 51), health.score.score);
    try std.testing.expectEqual(@as(u32, 1), health.score.successes);
    try std.testing.expect(health.circuit.isClosed());
}

test "HealthStore circuit breaker opens after failures" {
    var store = HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    store.recordFailure("codex:main", .error_response);
    store.recordFailure("codex:main", .error_response);
    store.recordFailure("codex:main", .error_response);

    const health = store.accounts.get("codex:main").?;
    try std.testing.expect(!health.circuit.isClosed());
}

test "HealthStore muxDecision with typed failures" {
    var store = HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    // Fresh account is available
    try std.testing.expectEqual(types.MuxDecision.use_this, store.muxDecision("codex:plan1"));

    // Rate limit (short) → wait_and_retry
    store.recordHttpStatus("codex:plan1", 429, 30);
    try std.testing.expectEqual(types.MuxDecision.wait_and_retry, store.muxDecision("codex:plan1"));

    // Second account still available
    try std.testing.expectEqual(types.MuxDecision.use_this, store.muxDecision("codex:plan2"));

    // Quota exhausted (long wait) → try_next_account
    store.recordHttpStatus("codex:plan2", 429, 7200);
    try std.testing.expectEqual(types.MuxDecision.try_next_account, store.muxDecision("codex:plan2"));

    // Third account still available
    try std.testing.expectEqual(types.MuxDecision.use_this, store.muxDecision("codex:plan3"));

    // Auth failure → try_next (dead)
    store.recordHttpStatus("codex:plan3", 401, null);
    try std.testing.expectEqual(types.MuxDecision.try_next_account, store.muxDecision("codex:plan3"));

    // Provider-side failure routes away from the provider, not only the account.
    store.recordHttpStatus("codex:provider", 500, null);
    try std.testing.expectEqual(types.MuxDecision.try_next_provider, store.muxDecision("codex:provider"));
}

test "HealthStore capability route decisions do not poison account" {
    var store = HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    store.recordCapabilityHttpStatus("codex", "max-1", "codex-max", 429, 7200);

    try std.testing.expectEqual(
        types.MuxDecision.try_next_account,
        store.muxDecisionFor("codex", "max-1", "codex-max"),
    );
    try std.testing.expectEqual(
        types.MuxDecision.use_this,
        store.muxDecisionFor("codex", "max-1", "codex-mini"),
    );
}

test "HealthStore account decisions dominate capability route decisions" {
    var store = HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    store.recordHttpStatus("codex:max-1", 401, null);
    try std.testing.expectEqual(
        types.MuxDecision.try_next_account,
        store.muxDecisionFor("codex", "max-1", "codex-max"),
    );
}

test "parseHealthKey supports account and capability routes" {
    const account = parseHealthKey("codex:max-1").?;
    try std.testing.expectEqualStrings("codex", account.provider);
    try std.testing.expectEqualStrings("max-1", account.account);
    try std.testing.expect(account.capability == null);

    const route = parseHealthKey("codex:max-1#codex-max").?;
    try std.testing.expectEqualStrings("codex", route.provider);
    try std.testing.expectEqualStrings("max-1", route.account);
    try std.testing.expectEqualStrings("codex-max", route.capability.?);
}

test "HealthStore 429 distinguishes rate limit from quota exhaustion" {
    var store = HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    // Short retry = rate limit
    store.recordHttpStatus("a:1", 429, 30);
    const h1 = store.accounts.get("a:1").?;
    switch (h1.liveness) {
        .live => |l| switch (l.availability) {
            .rate_limited => |rl| try std.testing.expectEqual(types.RateLimitWindow.per_minute, rl.window),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }

    // Long retry = quota exhausted
    store.recordHttpStatus("a:2", 429, 7200);
    const h2 = store.accounts.get("a:2").?;
    switch (h2.liveness) {
        .live => |l| switch (l.availability) {
            .quota_exhausted => |q| try std.testing.expect(q.window_resets_at != null),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "HealthStore persists typed liveness" {
    var store = HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    store.recordHttpStatus("codex:max-1", 429, 30);
    store.recordHttpStatus("codex:max-2", 429, 7200);
    store.recordHttpStatus("codex:max-3", 401, null);

    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try store.writeJson(buf.writer());

    var loaded = HealthStore.loadFromBytes(std.testing.allocator, .{}, buf.items);
    defer loaded.deinit();

    try std.testing.expectEqual(types.MuxDecision.wait_and_retry, loaded.muxDecision("codex:max-1"));
    try std.testing.expectEqual(types.MuxDecision.try_next_account, loaded.muxDecision("codex:max-2"));
    try std.testing.expectEqual(types.MuxDecision.try_next_account, loaded.muxDecision("codex:max-3"));

    const rate_limited = loaded.accounts.get("codex:max-1").?;
    try std.testing.expectEqual(ProbeEvidenceSource.http_status, rate_limited.last_probe_source.?);
    try std.testing.expect(rate_limited.last_probe_observed_at != null);
    try std.testing.expectEqual(@as(?u32, 30), rate_limited.last_probe_retry_after_s);
    try std.testing.expectEqual(ProbeHintClass.rate_limit, rate_limited.last_probe_hint_class.?);
    try std.testing.expectEqual(types.MuxDecision.wait_and_retry, rate_limited.last_probe_decision.?);

    const quota = loaded.accounts.get("codex:max-2").?;
    try std.testing.expectEqual(@as(?u16, 429), quota.last_http_status);
    switch (quota.liveness) {
        .live => |l| switch (l.availability) {
            .quota_exhausted => |q| try std.testing.expect(q.window_resets_at != null),
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "HealthStore loads legacy health file without liveness" {
    const json =
        \\{"accounts":[{"key":"codex:legacy","score":40,"successes":1,"failures":0,"rate_limits":1,"last_updated":123,"circuit_open":false}]}
    ;

    var loaded = HealthStore.loadFromBytes(std.testing.allocator, .{}, json);
    defer loaded.deinit();

    const health = loaded.accounts.get("codex:legacy").?;
    try std.testing.expectEqual(@as(i32, 40), health.score.score);
    try std.testing.expectEqual(@as(u32, 1), health.score.successes);
    switch (health.liveness) {
        .live => |l| switch (l.availability) {
            .available => {},
            else => return error.TestUnexpectedResult,
        },
        else => return error.TestUnexpectedResult,
    }
}

test "writeLivenessSummary redacts to typed labels" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeLivenessSummary(buf.writer(), .{ .degraded = .{
        .reason = .step_up_required,
        .since = 123,
        .retry_at = null,
    } });
    try std.testing.expectEqualStrings("degraded:step_up_required", buf.items);

    buf.clearRetainingCapacity();
    try writeLivenessSummary(buf.writer(), .{ .dead = .{
        .reason = .token_revoked,
        .since = 123,
    } });
    try std.testing.expectEqualStrings("dead:token_revoked", buf.items);
}

test "HealthStore provider classifier handles MCP step-up" {
    var store = HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    store.recordHttpStatusForProvider(
        "mcp:figma",
        provider_schema.mcp_def,
        403,
        null,
        "mcp step_up required",
    );

    const health = store.accounts.get("mcp:figma").?;
    switch (health.liveness) {
        .degraded => |d| try std.testing.expectEqual(types.DegradedReason.step_up_required, d.reason),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(types.MuxDecision.try_next_account, store.muxDecision("mcp:figma"));
}

test "HealthStore rate limit penalty" {
    var store = HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    store.recordFailure("gemini:default", .rate_limited);
    const health = store.accounts.get("gemini:default").?;
    try std.testing.expectEqual(@as(i32, 40), health.score.score); // 50 + (-10)
    try std.testing.expectEqual(@as(u32, 1), health.score.rate_limits);
}

test "HealthStore auth failure marks credential dead" {
    var store = HealthStore.init(std.testing.allocator, .{});
    defer store.deinit();

    store.recordFailure("codex:max-1", .auth_failure);

    const health = store.accounts.get("codex:max-1").?;
    switch (health.liveness) {
        .dead => |dead| try std.testing.expectEqual(types.DeadReason.auth_permanently_failed, dead.reason),
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(ProbeHintClass.auth_dead, health.last_probe_hint_class.?);
    try std.testing.expectEqual(types.MuxDecision.try_next_account, store.muxDecision("codex:max-1"));
}
