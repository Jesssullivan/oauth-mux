const std = @import("std");

// ── Provider Identity ──

pub const ProviderKind = enum {
    claude,
    codex,
    gemini,
    vercel,
    github,
    mcp,

    pub fn configDirEnv(self: ProviderKind) ?[]const u8 {
        return switch (self) {
            .claude => "CLAUDE_CONFIG_DIR",
            .codex => "CODEX_HOME",
            .gemini => "GEMINI_CLI_HOME",
            .vercel, .github, .mcp => null,
        };
    }

    pub fn displayName(self: ProviderKind) []const u8 {
        return switch (self) {
            .claude => "Claude Code",
            .codex => "Codex CLI",
            .gemini => "Gemini CLI",
            .vercel => "Vercel CLI",
            .github => "GitHub CLI",
            .mcp => "MCP Server",
        };
    }

    pub fn fromString(s: []const u8) ?ProviderKind {
        const map = std.StaticStringMap(ProviderKind).initComptime(.{
            .{ "claude", .claude },
            .{ "codex", .codex },
            .{ "gemini", .gemini },
            .{ "vercel", .vercel },
            .{ "github", .github },
            .{ "mcp", .mcp },
        });
        return map.get(s);
    }
};

// ── Secret Backend ──

pub const SecretBackend = union(enum) {
    keychain: KeychainRef,
    sops: SopsRef,
    age: AgeRef,
    env: EnvRef,
    file: FileRef,
    command: CommandRef,
    stdin,

    pub const KeychainRef = struct {
        service: []const u8,
        account: []const u8,
    };

    pub const SopsRef = struct {
        path: []const u8,
        key_path: ?[]const u8 = null,
    };

    pub const AgeRef = struct {
        path: []const u8,
        identity: []const u8,
    };

    pub const EnvRef = struct {
        variable: []const u8,
    };

    pub const FileRef = struct {
        path: []const u8,
    };

    pub const CommandRef = struct {
        argv: []const []const u8,
    };
};

// ── Token State Machine ──
//
// State transitions:
//   unresolved ─read─→ raw ─parse─→ valid
//                                  └─→ expired ─refresh─→ valid
//                                                       └─→ failed
//   Any state can transition to failed on unrecoverable error.

pub const TokenState = union(enum) {
    unresolved,
    raw: RawToken,
    valid: ValidToken,
    expired: ExpiredToken,
    refreshing: RefreshingToken,
    failed: FailedToken,

    pub const RawToken = struct {
        bytes: []const u8,
        read_at: i64,
    };

    pub const ValidToken = struct {
        access_token: []const u8,
        refresh_token: ?[]const u8 = null,
        token_type: TokenType = .bearer,
        expires_at: ?i64 = null,
        scopes: ?[]const u8 = null,
    };

    pub const ExpiredToken = struct {
        refresh_token: []const u8,
        token_type: TokenType = .bearer,
        expired_at: i64,
    };

    pub const RefreshingToken = struct {
        started_at: i64,
        refresh_token: []const u8,
    };

    pub const FailedToken = struct {
        reason: FailReason,
        failed_at: i64,
        retry_after: ?i64 = null,
    };

    pub fn isUsable(self: TokenState) bool {
        return self == .valid;
    }
};

pub const TokenType = enum {
    bearer,
    dpop,
    api_key,
};

pub const FailReason = enum {
    secret_not_found,
    secret_decrypt_failed,
    parse_failed,
    refresh_failed,
    revoked,
    rate_limited,
    network_error,
};

// ── Credential Liveness ──
//
// Three distinct layers that the mux pipeline must reason about:
//
// 1. Authentication: Can the token prove identity to the provider?
//    (not expired, not revoked, parseable)
//
// 2. Operability: Is the account in a state where it can serve requests?
//    (not suspended, subscription active, tier sufficient)
//
// 3. Availability: Does the account have capacity right now?
//    (not rate-limited, quota not exhausted, not in cooldown)
//
// The mux response differs for each:
//   Auth failed    → mark dead, never retry automatically
//   Inoperable     → mark degraded, retry after long interval (hours)
//   Rate limited   → cooldown timer, retry same account after seconds
//   Quota exhausted → switch account, retry after window reset (hours/days)
//   Provider down  → switch provider entirely, not just account

pub const CredentialLiveness = union(enum) {
    live: LiveCredential,
    degraded: DegradedCredential,
    dead: DeadCredential,

    pub const LiveCredential = struct {
        availability: Availability,
    };

    pub const DegradedCredential = struct {
        reason: DegradedReason,
        since: i64,
        retry_at: ?i64 = null,
    };

    pub const DeadCredential = struct {
        reason: DeadReason,
        since: i64,
    };
};

pub const Availability = union(enum) {
    available,
    rate_limited: RateLimitInfo,
    quota_exhausted: QuotaInfo,
    cooldown: CooldownInfo,

    pub const RateLimitInfo = struct {
        retry_after_s: u32,
        limited_at: i64,
        window: RateLimitWindow,
    };

    pub const QuotaInfo = struct {
        window_resets_at: ?i64 = null,
        usage_pct: ?u8 = null,
        exhausted_at: i64,
    };

    pub const CooldownInfo = struct {
        until: i64,
        reason: []const u8,
    };
};

pub const RateLimitWindow = enum {
    per_minute,
    per_hour,
    per_day,
    unknown,
};

pub const DegradedReason = enum {
    tier_insufficient,
    subscription_paused,
    provider_degraded,
    scope_insufficient,
    schema_invalid,
    terms_required,
    step_up_required,
    pending_verification,
    unknown_4xx,
};

pub const DeadReason = enum {
    token_revoked,
    account_deleted,
    auth_permanently_failed,
};

// ── Mux Decision ──
// What the pipeline should do after probing a credential.

pub const MuxDecision = enum {
    use_this,
    try_next_account,
    try_next_provider,
    wait_and_retry,
    give_up,

    pub fn fromHttpStatus(status: u16) MuxDecision {
        return switch (status) {
            200...299 => .use_this,
            401 => .try_next_account,
            403 => .try_next_account,
            429 => .wait_and_retry,
            500...599 => .try_next_provider,
            else => .try_next_account,
        };
    }

    pub fn isRecoverable(self: MuxDecision) bool {
        return self != .give_up;
    }
};

pub const HttpClassification = union(enum) {
    success,
    rate_limited: RateLimitClassification,
    quota_exhausted: QuotaClassification,
    degraded: DegradedReason,
    dead: DeadReason,
    provider_degraded,
    failure,

    pub const RateLimitClassification = struct {
        retry_after_s: u32,
        window: RateLimitWindow,
    };

    pub const QuotaClassification = struct {
        retry_after_s: u32,
    };
};

// ── Health & Circuit Breaker ──

pub const HealthScore = struct {
    score: i32 = 50,
    window_start: i64 = 0,
    successes: u32 = 0,
    failures: u32 = 0,
    rate_limits: u32 = 0,
    last_updated: i64 = 0,

    pub fn clamp(self: *HealthScore) void {
        self.score = @max(-100, @min(100, self.score));
    }
};

pub const CircuitState = union(enum) {
    closed,
    open: OpenCircuit,
    half_open: HalfOpenCircuit,

    pub const OpenCircuit = struct {
        opened_at: i64,
        failure_count: u32,
        retry_at: i64,
    };

    pub const HalfOpenCircuit = struct {
        probe_started_at: i64,
        successes_needed: u32 = 2,
        successes_so_far: u32 = 0,
    };

    pub fn isClosed(self: CircuitState) bool {
        return self == .closed;
    }
};

pub const TokenBucket = struct {
    tokens: f64 = 50.0,
    max_tokens: f64 = 50.0,
    refill_rate: f64 = 0.1, // tokens per second (6/min)
    last_refill_ns: i128 = 0,

    pub fn tryConsume(self: *TokenBucket, now_ns: i128) bool {
        self.refill(now_ns);
        if (self.tokens >= 1.0) {
            self.tokens -= 1.0;
            return true;
        }
        return false;
    }

    pub fn refill(self: *TokenBucket, now_ns: i128) void {
        if (self.last_refill_ns == 0) {
            self.last_refill_ns = now_ns;
            return;
        }
        const elapsed_ns = now_ns - self.last_refill_ns;
        if (elapsed_ns <= 0) return;
        const elapsed_s: f64 = @as(f64, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;
        self.tokens = @min(self.max_tokens, self.tokens + elapsed_s * self.refill_rate);
        self.last_refill_ns = now_ns;
    }
};

// ── Account Selection ──

pub const AccountRef = struct {
    provider: []const u8,
    account: []const u8,

    pub fn key(self: AccountRef, buf: []u8) []const u8 {
        const len = @min(buf.len - 1, self.provider.len + 1 + self.account.len);
        var i: usize = 0;
        for (self.provider) |c| {
            if (i >= buf.len - 1) break;
            buf[i] = c;
            i += 1;
        }
        if (i < buf.len - 1) {
            buf[i] = ':';
            i += 1;
        }
        for (self.account) |c| {
            if (i >= buf.len - 1) break;
            buf[i] = c;
            i += 1;
        }
        _ = len;
        return buf[0..i];
    }
};

pub const SelectionResult = union(enum) {
    selected: SelectedAccount,
    all_exhausted,
    no_accounts,

    pub const SelectedAccount = struct {
        ref: AccountRef,
        reason: SelectionReason,
    };
};

pub const SelectionReason = enum {
    highest_priority,
    best_health,
    session_affinity,
    round_robin,
    only_available,
};

// ── Strategy ──

pub const StrategyKind = enum {
    priority_failover,
    health_weighted,
    round_robin,

    pub fn fromString(s: []const u8) ?StrategyKind {
        const map = std.StaticStringMap(StrategyKind).initComptime(.{
            .{ "priority-failover", .priority_failover },
            .{ "health-weighted", .health_weighted },
            .{ "round-robin", .round_robin },
        });
        return map.get(s);
    }
};

pub const HealthConfig = struct {
    decay_per_hour: i32 = 2,
    rate_limit_penalty: i32 = -10,
    failure_penalty: i32 = -20,
    success_bonus: i32 = 1,
    initial_score: i32 = 50,
};

// ── Shell ──

pub const ShellKind = enum {
    fish,
    zsh,
    bash,
    ksh,
    posix,

    pub fn exportStatement(self: ShellKind, writer: anytype, key: []const u8, value: []const u8) !void {
        switch (self) {
            .fish => try writer.print("set -gx {s} '{s}';\n", .{ key, value }),
            .zsh, .bash, .ksh, .posix => try writer.print("export {s}='{s}'\n", .{ key, value }),
        }
    }

    pub fn unsetStatement(self: ShellKind, writer: anytype, key: []const u8) !void {
        switch (self) {
            .fish => try writer.print("set -e {s};\n", .{key}),
            .zsh, .bash, .ksh, .posix => try writer.print("unset {s}\n", .{key}),
        }
    }
};

// ── Pipeline ──

pub const PipelineError = error{
    ConfigNotFound,
    ConfigParseError,
    ConfigValidationError,
    ProviderNotFound,
    AccountNotFound,
    AllAccountsExhausted,
    SecretReadFailed,
    SecretDecryptFailed,
    TokenParseFailed,
    TokenExpired,
    TokenRefreshFailed,
    TokenRevoked,
    RateLimited,
    NetworkError,
    ExecFailed,
    ShellDetectionFailed,
    OutOfMemory,
};

// ── Exit Codes ──

pub const ExitCode = enum(u8) {
    success = 0,
    general_error = 1,
    config_error = 200,
    all_accounts_exhausted = 201,
    secret_read_failed = 202,
    token_refresh_failed = 203,
    network_error = 204,

    pub fn int(self: ExitCode) u8 {
        return @intFromEnum(self);
    }
};

// ── Tests ──

test "ProviderKind.fromString" {
    const testing = std.testing;
    try testing.expectEqual(ProviderKind.claude, ProviderKind.fromString("claude").?);
    try testing.expectEqual(ProviderKind.codex, ProviderKind.fromString("codex").?);
    try testing.expectEqual(ProviderKind.gemini, ProviderKind.fromString("gemini").?);
    try testing.expectEqual(@as(?ProviderKind, null), ProviderKind.fromString("unknown"));
}

test "ProviderKind.configDirEnv" {
    const testing = std.testing;
    try testing.expectEqualStrings("CLAUDE_CONFIG_DIR", ProviderKind.claude.configDirEnv().?);
    try testing.expectEqualStrings("CODEX_HOME", ProviderKind.codex.configDirEnv().?);
    try testing.expect(ProviderKind.github.configDirEnv() == null);
}

test "TokenBucket.tryConsume" {
    var bucket = TokenBucket{};
    const now: i128 = 1_000_000_000_000;
    try std.testing.expect(bucket.tryConsume(now));
    try std.testing.expectApproxEqAbs(@as(f64, 49.0), bucket.tokens, 0.01);
}

test "TokenBucket.refill" {
    var bucket = TokenBucket{ .tokens = 0.0, .last_refill_ns = 1 };
    bucket.refill(10_000_000_001); // 10 seconds later
    try std.testing.expectApproxEqAbs(@as(f64, 1.0), bucket.tokens, 0.01);
}

test "HealthScore.clamp" {
    var h = HealthScore{ .score = 200 };
    h.clamp();
    try std.testing.expectEqual(@as(i32, 100), h.score);

    h.score = -200;
    h.clamp();
    try std.testing.expectEqual(@as(i32, -100), h.score);
}

test "StrategyKind.fromString" {
    try std.testing.expectEqual(StrategyKind.priority_failover, StrategyKind.fromString("priority-failover").?);
    try std.testing.expectEqual(StrategyKind.health_weighted, StrategyKind.fromString("health-weighted").?);
    try std.testing.expectEqual(@as(?StrategyKind, null), StrategyKind.fromString("unknown"));
}

test "ShellKind.exportStatement" {
    var buf: [256]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    const writer = fbs.writer();

    try ShellKind.fish.exportStatement(writer, "FOO", "bar");
    try std.testing.expectEqualStrings("set -gx FOO 'bar';\n", fbs.getWritten());

    fbs.reset();
    try ShellKind.bash.exportStatement(writer, "FOO", "bar");
    try std.testing.expectEqualStrings("export FOO='bar'\n", fbs.getWritten());
}

test "CircuitState.isClosed" {
    const closed = CircuitState{ .closed = {} };
    try std.testing.expect(closed.isClosed());

    const open = CircuitState{ .open = .{ .opened_at = 0, .failure_count = 3, .retry_at = 100 } };
    try std.testing.expect(!open.isClosed());
}
