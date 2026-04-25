const std = @import("std");
const types = @import("types.zig");
const log = @import("log.zig");

// ── Declarative Provider Definition ──
//
// A provider is fully described by data — no code required.
// This schema captures everything oauth-mux needs to:
//   1. Read credentials from any storage format
//   2. Parse tokens from any JSON structure
//   3. Refresh tokens against any OAuth 2.x token endpoint
//   4. Inject credentials into any tool's expected environment
//   5. Interpret rate limit / error responses
//
// Adding a new provider is a JSON block in the config file under
// "provider_definitions". Built-in providers ship as compile-time
// defaults that can be overridden.
//
// The schema is informed by:
//   RFC 8414 — OAuth Authorization Server Metadata
//   RFC 9728 — Protected Resource Metadata
//   MCP Auth Spec (2025-11-25) — HTTP auth, stdio env credentials, CIMD
//   RFC 9449 — DPoP (sender-constrained tokens)
//   RFC 8628 — Device Authorization Grant

pub const ProviderDefinition = struct {
    // ── Identity ──
    name: []const u8,
    display_name: []const u8 = "",

    // ── OAuth Server ──
    // If discovery_url is set, metadata is fetched at runtime (RFC 8414).
    // Otherwise, endpoints are specified directly.
    auth: AuthConfig = .{},

    // ── Credential Format ──
    // How to extract tokens from the raw secret material.
    // Supports nested JSON paths (e.g., "claudeAiOauth.accessToken")
    // and alternative field mappings for API key mode.
    credential: CredentialFormat = .{},

    // ── Environment Injection ──
    // How to make the credential available to the target tool.
    injection: InjectionConfig = .{},

    // ── Detection ──
    // How to auto-detect this provider from the target command.
    detection: DetectionConfig = .{},

    // ── Capability Probes ──
    // Optional route/capability probes. These are declarative plans, not
    // secrets: token material is added by the caller at execution time.
    capabilities: []const CapabilityDefinition = &.{},

    // ── Rate Limit Interpretation ──
    // How to parse rate limit signals from HTTP responses.
    rate_limits: RateLimitConfig = .{},

    // ── Failure Classification ──
    // Provider-specific HTTP/status/body hints that override generic OAuth
    // fallback classification. No regex; only exact status/range and substring
    // hints so the parser remains std-only.
    failure_rules: []const FailureRule = &.{},
};

pub const AuthConfig = struct {
    // RFC 8414 discovery URL — if set, endpoints are discovered at runtime
    discovery_url: ?[]const u8 = null,
    // Direct endpoint URLs (used if discovery_url is null)
    token_endpoint: ?[]const u8 = null,
    authorization_endpoint: ?[]const u8 = null,
    revocation_endpoint: ?[]const u8 = null,
    device_authorization_endpoint: ?[]const u8 = null,
    // OAuth client identity
    client_id: ?[]const u8 = null,
    // Supported features
    pkce: bool = true,
    dpop: bool = false,
    // Grant types this provider uses
    grant_types: []const []const u8 = &.{ "authorization_code", "refresh_token" },
};

pub const CredentialFormat = struct {
    // JSON path to the access token (dot-separated)
    // e.g., "accessToken" or "claudeAiOauth.accessToken" or "tokens.access_token"
    access_token_path: []const u8 = "access_token",
    refresh_token_path: []const u8 = "refresh_token",
    expires_at_path: ?[]const u8 = null,
    expires_in_path: ?[]const u8 = null,
    // Alternative paths for API key mode
    api_key_path: ?[]const u8 = null,
    // Wrapper key — if the credential JSON is nested under a top-level key
    wrapper_key: ?[]const u8 = null,
    // Token type detection: if api_key_path resolves, treat as api_key
    token_type: []const u8 = "bearer",
};

pub const InjectionConfig = struct {
    // Config dir env var (e.g., CLAUDE_CONFIG_DIR, CODEX_HOME)
    config_dir_env: ?[]const u8 = null,
    // Filename for the credential file within the config dir
    credential_filename: []const u8 = "credentials.json",
    // Template for rebuilding the credential file from token fields.
    // Uses {{access_token}}, {{refresh_token}}, {{expires_at}} placeholders.
    credential_template: ?[]const u8 = null,
    // Direct env vars to set (key = env var name, value = token field)
    // e.g., {"GH_TOKEN": "access_token", "OPENAI_API_KEY": "access_token"}
    direct_env: ?[]const [2][]const u8 = null,
};

pub const DetectionConfig = struct {
    // Binary names that identify this provider
    binary_names: []const []const u8 = &.{},
    // Env vars whose presence indicates this provider
    env_markers: []const []const u8 = &.{},
};

pub const CapabilityDefinition = struct {
    name: []const u8,
    aliases: []const []const u8 = &.{},
    probe: ?ProbeDefinition = null,
};

pub const ProbeDefinition = struct {
    method: []const u8 = "GET",
    url: []const u8,
    auth: ProbeAuth = .bearer,
    success_status_min: u16 = 200,
    success_status_max: u16 = 299,
    hint_header: ?[]const u8 = null,
};

pub const ProbeAuth = enum {
    bearer,
    none,
};

pub const ProbePlan = struct {
    capability: []const u8,
    method: []const u8,
    url: []const u8,
    auth: ProbeAuth,
    success_status_min: u16,
    success_status_max: u16,
    hint_header: ?[]const u8 = null,
};

pub const RateLimitConfig = struct {
    // HTTP header names for rate limit info
    retry_after_header: []const u8 = "retry-after",
    remaining_header: ?[]const u8 = null,
    reset_header: ?[]const u8 = null,
    limit_header: ?[]const u8 = null,
    // Threshold: retry_after above this (seconds) = quota exhaustion, below = rate limit
    quota_threshold_seconds: u32 = 3600,
};

pub const FailureRule = struct {
    status: ?u16 = null,
    status_min: ?u16 = null,
    status_max: ?u16 = null,
    retry_after_gte: ?u32 = null,
    retry_after_lt: ?u32 = null,
    hint_contains: ?[]const u8 = null,
    class: FailureClass,
};

pub const FailureClass = union(enum) {
    success,
    rate_limited,
    quota_exhausted,
    degraded: types.DegradedReason,
    dead: types.DeadReason,
    provider_degraded,
    failure,
};

// ── Built-in Provider Definitions ──
// These are compile-time defaults. Users can override any field in their config.

pub const builtin_providers = [_]ProviderDefinition{
    claude_def,
    codex_def,
    gemini_def,
    vercel_def,
    github_def,
    mcp_def,
};

pub const generic_def = ProviderDefinition{
    .name = "generic",
    .display_name = "Generic OAuth Provider",
};

const mcp_failure_rules = [_]FailureRule{
    .{
        .status = 403,
        .hint_contains = "insufficient_scope",
        .class = .{ .degraded = .scope_insufficient },
    },
    .{
        .status = 403,
        .hint_contains = "step_up",
        .class = .{ .degraded = .step_up_required },
    },
    .{
        .status = 403,
        .hint_contains = "pending",
        .class = .{ .degraded = .pending_verification },
    },
    .{
        .status = 400,
        .hint_contains = "schema",
        .class = .{ .degraded = .schema_invalid },
    },
    .{
        .status = 422,
        .hint_contains = "schema",
        .class = .{ .degraded = .schema_invalid },
    },
};

pub const claude_def = ProviderDefinition{
    .name = "claude",
    .display_name = "Claude Code",
    .auth = .{
        .token_endpoint = "https://claude.ai/api/auth/oauth/token",
    },
    .credential = .{
        .access_token_path = "accessToken",
        .refresh_token_path = "refreshToken",
        .expires_at_path = "expiresAt",
        .wrapper_key = "claudeAiOauth",
    },
    .injection = .{
        .config_dir_env = "CLAUDE_CONFIG_DIR",
        .credential_filename = ".credentials.json",
        .credential_template =
        \\{"claudeAiOauth":{"accessToken":"{{access_token}}","refreshToken":"{{refresh_token}}"}}
        ,
    },
    .detection = .{
        .binary_names = &.{"claude"},
    },
    .rate_limits = .{
        .remaining_header = "x-ratelimit-remaining",
        .reset_header = "x-ratelimit-reset",
    },
};

pub const codex_def = ProviderDefinition{
    .name = "codex",
    .display_name = "Codex CLI",
    .auth = .{
        .token_endpoint = "https://auth0.openai.com/oauth/token",
        .device_authorization_endpoint = "https://auth.openai.com/deviceauth/usercode",
    },
    .credential = .{
        .access_token_path = "tokens.access_token",
        .refresh_token_path = "tokens.refresh_token",
        .expires_in_path = "tokens.expires_in",
        .api_key_path = "OPENAI_API_KEY",
    },
    .injection = .{
        .config_dir_env = "CODEX_HOME",
        .credential_filename = "auth.json",
        .credential_template =
        \\{"auth_mode":"chatgpt","tokens":{"access_token":"{{access_token}}","refresh_token":"{{refresh_token}}"}}
        ,
    },
    .detection = .{
        .binary_names = &.{"codex"},
        .env_markers = &.{"CODEX_HOME"},
    },
    .rate_limits = .{
        .remaining_header = "x-ratelimit-remaining-requests",
        .reset_header = "x-ratelimit-reset-requests",
    },
};

pub const gemini_def = ProviderDefinition{
    .name = "gemini",
    .display_name = "Gemini CLI",
    .auth = .{
        .token_endpoint = "https://oauth2.googleapis.com/token",
    },
    .credential = .{
        .access_token_path = "access_token",
        .refresh_token_path = "refresh_token",
    },
    .injection = .{
        .config_dir_env = "GEMINI_CLI_HOME",
        .credential_filename = "oauth_creds.json",
    },
    .detection = .{
        .binary_names = &.{"gemini"},
        .env_markers = &.{"GEMINI_CLI_HOME"},
    },
};

pub const vercel_def = ProviderDefinition{
    .name = "vercel",
    .display_name = "Vercel CLI",
    .auth = .{
        .discovery_url = "https://vercel.com/.well-known/openid-configuration",
    },
    .credential = .{
        .access_token_path = "token",
        .refresh_token_path = "refreshToken",
        .expires_at_path = "expiresAt",
    },
    .injection = .{
        .direct_env = &.{.{ "VERCEL_TOKEN", "access_token" }},
    },
    .detection = .{
        .binary_names = &.{"vercel"},
    },
};

pub const github_def = ProviderDefinition{
    .name = "github",
    .display_name = "GitHub CLI",
    .auth = .{
        // GitHub tokens don't expire — no refresh endpoint
    },
    .credential = .{
        .access_token_path = "oauth_token",
        .token_type = "bearer",
    },
    .injection = .{
        .direct_env = &.{.{ "GH_TOKEN", "access_token" }},
    },
    .detection = .{
        .binary_names = &.{"gh"},
    },
};

pub const mcp_def = ProviderDefinition{
    .name = "mcp",
    .display_name = "MCP Server",
    .auth = .{
        // MCP uses RFC 9728 discovery — resource_metadata from 401 response
        .pkce = true,
    },
    .credential = .{
        .access_token_path = "access_token",
        .refresh_token_path = "refresh_token",
    },
    .injection = .{
        .direct_env = &.{.{ "MCP_TOKEN", "access_token" }},
    },
    .failure_rules = &mcp_failure_rules,
};

// ── HTTP Failure Classifier ──

pub fn classifyHttp(
    def: ProviderDefinition,
    status: u16,
    retry_after: ?u32,
    hint: ?[]const u8,
) types.HttpClassification {
    for (def.failure_rules) |rule| {
        if (!failureRuleMatches(rule, status, retry_after, hint)) continue;
        return classificationFromRule(rule.class, retry_after);
    }

    if (status >= 200 and status <= 299) return .success;

    if (status == 429) {
        const wait = retry_after orelse 30;
        if (wait > def.rate_limits.quota_threshold_seconds) {
            return .{ .quota_exhausted = .{ .retry_after_s = wait } };
        }
        return .{ .rate_limited = .{
            .retry_after_s = wait,
            .window = windowFromRetryAfter(wait),
        } };
    }

    if (status == 401) return .{ .dead = .token_revoked };

    if (status == 403) {
        if (hint) |h| {
            if (containsIgnoreAsciiCase(h, "insufficient_scope") or containsIgnoreAsciiCase(h, "scope")) {
                return .{ .degraded = .scope_insufficient };
            }
            if (containsIgnoreAsciiCase(h, "step_up")) {
                return .{ .degraded = .step_up_required };
            }
            if (containsIgnoreAsciiCase(h, "pending") or containsIgnoreAsciiCase(h, "verification")) {
                return .{ .degraded = .pending_verification };
            }
            if (containsIgnoreAsciiCase(h, "terms")) {
                return .{ .degraded = .terms_required };
            }
        }
        return .{ .degraded = .tier_insufficient };
    }

    if (status >= 500 and status <= 599) return .provider_degraded;

    if (status >= 400 and status <= 499) return .{ .degraded = .unknown_4xx };

    return .failure;
}

pub fn probePlanForCapability(def: ProviderDefinition, capability: []const u8) ?ProbePlan {
    for (def.capabilities) |cap| {
        if (!capabilityMatches(cap, capability)) continue;
        const probe = cap.probe orelse return null;
        return .{
            .capability = cap.name,
            .method = probe.method,
            .url = probe.url,
            .auth = probe.auth,
            .success_status_min = probe.success_status_min,
            .success_status_max = probe.success_status_max,
            .hint_header = probe.hint_header,
        };
    }
    return null;
}

fn capabilityMatches(cap: CapabilityDefinition, requested: []const u8) bool {
    if (std.mem.eql(u8, cap.name, requested)) return true;
    for (cap.aliases) |alias| {
        if (std.mem.eql(u8, alias, requested)) return true;
    }
    return false;
}

fn failureRuleMatches(rule: FailureRule, status: u16, retry_after: ?u32, hint: ?[]const u8) bool {
    if (rule.status) |exact| {
        if (status != exact) return false;
    }
    if (rule.status_min) |min| {
        if (status < min) return false;
    }
    if (rule.status_max) |max| {
        if (status > max) return false;
    }
    if (rule.retry_after_gte) |min_wait| {
        const wait = retry_after orelse return false;
        if (wait < min_wait) return false;
    }
    if (rule.retry_after_lt) |max_wait| {
        const wait = retry_after orelse return false;
        if (wait >= max_wait) return false;
    }
    if (rule.hint_contains) |needle| {
        const h = hint orelse return false;
        if (!containsIgnoreAsciiCase(h, needle)) return false;
    }
    return true;
}

fn classificationFromRule(class: FailureClass, retry_after: ?u32) types.HttpClassification {
    return switch (class) {
        .success => .success,
        .rate_limited => blk: {
            const wait = retry_after orelse 30;
            break :blk .{ .rate_limited = .{
                .retry_after_s = wait,
                .window = windowFromRetryAfter(wait),
            } };
        },
        .quota_exhausted => .{ .quota_exhausted = .{ .retry_after_s = retry_after orelse 3600 } },
        .degraded => |reason| .{ .degraded = reason },
        .dead => |reason| .{ .dead = reason },
        .provider_degraded => .provider_degraded,
        .failure => .failure,
    };
}

fn windowFromRetryAfter(wait: u32) types.RateLimitWindow {
    return if (wait <= 60) .per_minute else if (wait <= 3600) .per_hour else .per_day;
}

fn containsIgnoreAsciiCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;

    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var matched = true;
        for (needle, 0..) |needle_char, j| {
            if (std.ascii.toLower(haystack[i + j]) != std.ascii.toLower(needle_char)) {
                matched = false;
                break;
            }
        }
        if (matched) return true;
    }
    return false;
}

// ── JSON Path Resolver ──
// Resolves dot-separated paths like "claudeAiOauth.accessToken" against parsed JSON.

pub fn resolveJsonPath(value: std.json.Value, path: []const u8) ?std.json.Value {
    var current = value;
    var remaining = path;

    while (remaining.len > 0) {
        const dot = std.mem.indexOf(u8, remaining, ".") orelse remaining.len;
        const key = remaining[0..dot];
        remaining = if (dot < remaining.len) remaining[dot + 1 ..] else "";

        switch (current) {
            .object => |obj| {
                current = obj.get(key) orelse return null;
            },
            else => return null,
        }
    }
    return current;
}

pub fn resolveJsonString(value: std.json.Value, path: []const u8) ?[]const u8 {
    const resolved = resolveJsonPath(value, path) orelse return null;
    return switch (resolved) {
        .string => |s| s,
        else => null,
    };
}

pub fn resolveJsonInt(value: std.json.Value, path: []const u8) ?i64 {
    const resolved = resolveJsonPath(value, path) orelse return null;
    return switch (resolved) {
        .integer => |i| i,
        else => null,
    };
}

// ── Generic Token Parser ──
// Parses any credential format using a ProviderDefinition ��� no provider-specific code.

pub const TokenFields = struct {
    access_token: []const u8,
    refresh_token: ?[]const u8 = null,
    token_type: types.TokenType = .bearer,
    expires_at: ?i64 = null,
};

pub fn parseTokenGeneric(
    def: ProviderDefinition,
    raw: []const u8,
    allocator: std.mem.Allocator,
) !TokenFields {
    const parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch {
        // Not valid JSON — treat as raw token string
        const trimmed = std.mem.trim(u8, raw, " \t\n\r");
        if (trimmed.len > 0) {
            return .{
                .access_token = try allocator.dupe(u8, trimmed),
                .token_type = .api_key,
            };
        }
        return error.InvalidCharacter;
    };
    defer parsed.deinit();

    var root = parsed.value;

    // If wrapper_key is set, unwrap first
    if (def.credential.wrapper_key) |wk| {
        root = resolveJsonPath(root, wk) orelse root;
    }

    // Try API key path first
    if (def.credential.api_key_path) |akp| {
        if (resolveJsonString(root, akp)) |key| {
            return .{
                .access_token = try allocator.dupe(u8, key),
                .token_type = .api_key,
            };
        }
    }

    // Resolve access token (required)
    const at = resolveJsonString(root, def.credential.access_token_path) orelse {
        // Fallback: treat entire input as raw token
        const trimmed = std.mem.trim(u8, raw, " \t\n\r");
        if (trimmed.len > 0) {
            return .{
                .access_token = try allocator.dupe(u8, trimmed),
                .token_type = .api_key,
            };
        }
        return error.InvalidCharacter;
    };

    var result = TokenFields{
        .access_token = try allocator.dupe(u8, at),
    };

    // Resolve refresh token (optional)
    if (resolveJsonString(root, def.credential.refresh_token_path)) |rt| {
        result.refresh_token = try allocator.dupe(u8, rt);
    }

    // Resolve expiry
    if (def.credential.expires_at_path) |eap| {
        result.expires_at = resolveJsonInt(root, eap);
    }
    if (result.expires_at == null) {
        if (def.credential.expires_in_path) |eip| {
            if (resolveJsonInt(root, eip)) |ei| {
                result.expires_at = std.time.timestamp() + ei;
            }
        }
    }

    // Token type
    if (std.mem.eql(u8, def.credential.token_type, "api_key")) {
        result.token_type = .api_key;
    }

    return result;
}

// ── Generic Credential Builder ──
// Builds a credential file from a template + token fields.

pub fn buildCredentialGeneric(
    def: ProviderDefinition,
    token: TokenFields,
    allocator: std.mem.Allocator,
) ![]const u8 {
    const template = def.injection.credential_template orelse {
        // Default: simple JSON
        var buf = std.ArrayList(u8).init(allocator);
        const w = buf.writer();
        try w.writeAll("{\"access_token\":\"");
        try w.writeAll(token.access_token);
        try w.writeAll("\"");
        if (token.refresh_token) |rt| {
            try w.writeAll(",\"refresh_token\":\"");
            try w.writeAll(rt);
            try w.writeAll("\"");
        }
        try w.writeAll("}");
        return buf.toOwnedSlice();
    };

    // Template substitution: {{access_token}}, {{refresh_token}}, {{expires_at}}
    var buf = std.ArrayList(u8).init(allocator);
    const w = buf.writer();
    var i: usize = 0;
    while (i < template.len) {
        if (i + 2 < template.len and template[i] == '{' and template[i + 1] == '{') {
            const end = std.mem.indexOfPos(u8, template, i + 2, "}}") orelse {
                try w.writeByte(template[i]);
                i += 1;
                continue;
            };
            const key = template[i + 2 .. end];
            if (std.mem.eql(u8, key, "access_token")) {
                try w.writeAll(token.access_token);
            } else if (std.mem.eql(u8, key, "refresh_token")) {
                try w.writeAll(token.refresh_token orelse "");
            } else if (std.mem.eql(u8, key, "expires_at")) {
                if (token.expires_at) |ea| {
                    try w.print("{d}", .{ea});
                }
            }
            i = end + 2;
        } else {
            try w.writeByte(template[i]);
            i += 1;
        }
    }
    return buf.toOwnedSlice();
}

// ── Provider Lookup ──

pub fn findBuiltin(name: []const u8) ?ProviderDefinition {
    for (builtin_providers) |def| {
        if (std.mem.eql(u8, def.name, name)) return def;
    }
    return null;
}

pub fn detectFromCommand(argv: []const []const u8) ?ProviderDefinition {
    if (argv.len == 0) return null;
    const cmd = std.fs.path.basename(argv[0]);
    for (builtin_providers) |def| {
        for (def.detection.binary_names) |bn| {
            if (std.mem.eql(u8, cmd, bn)) return def;
        }
    }
    return null;
}

// ── Tests ──

test "resolveJsonPath flat" {
    const json =
        \\{"access_token":"tok123","expires_in":3600}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("tok123", resolveJsonString(parsed.value, "access_token").?);
    try std.testing.expectEqual(@as(?i64, 3600), resolveJsonInt(parsed.value, "expires_in"));
}

test "resolveJsonPath nested" {
    const json =
        \\{"claudeAiOauth":{"accessToken":"sk-123","refreshToken":"rt-456"}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("sk-123", resolveJsonString(parsed.value, "claudeAiOauth.accessToken").?);
    try std.testing.expectEqualStrings("rt-456", resolveJsonString(parsed.value, "claudeAiOauth.refreshToken").?);
}

test "resolveJsonPath deep nesting" {
    const json =
        \\{"tokens":{"oauth":{"access_token":"deep"}}}
    ;
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, json, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("deep", resolveJsonString(parsed.value, "tokens.oauth.access_token").?);
}

test "parseTokenGeneric with claude def" {
    const json =
        \\{"claudeAiOauth":{"accessToken":"sk-ant-123","refreshToken":"rt-456","expiresAt":9999999999}}
    ;
    const result = try parseTokenGeneric(claude_def, json, std.testing.allocator);
    defer std.testing.allocator.free(result.access_token);
    defer if (result.refresh_token) |rt| std.testing.allocator.free(rt);
    try std.testing.expectEqualStrings("sk-ant-123", result.access_token);
    try std.testing.expectEqualStrings("rt-456", result.refresh_token.?);
    try std.testing.expectEqual(@as(?i64, 9999999999), result.expires_at);
}

test "parseTokenGeneric with codex def" {
    const json =
        \\{"auth_mode":"chatgpt","tokens":{"access_token":"oat-789","refresh_token":"ort-012","expires_in":3600}}
    ;
    const result = try parseTokenGeneric(codex_def, json, std.testing.allocator);
    defer std.testing.allocator.free(result.access_token);
    defer if (result.refresh_token) |rt| std.testing.allocator.free(rt);
    try std.testing.expectEqualStrings("oat-789", result.access_token);
    try std.testing.expectEqualStrings("ort-012", result.refresh_token.?);
    try std.testing.expect(result.expires_at != null);
}

test "parseTokenGeneric with codex API key mode" {
    const json =
        \\{"auth_mode":"api","OPENAI_API_KEY":"sk-proj-abc"}
    ;
    const result = try parseTokenGeneric(codex_def, json, std.testing.allocator);
    defer std.testing.allocator.free(result.access_token);
    try std.testing.expectEqualStrings("sk-proj-abc", result.access_token);
    try std.testing.expectEqual(types.TokenType.api_key, result.token_type);
}

test "parseTokenGeneric with github def (raw token)" {
    const result = try parseTokenGeneric(github_def, "gho_abc123\n", std.testing.allocator);
    defer std.testing.allocator.free(result.access_token);
    try std.testing.expectEqualStrings("gho_abc123", result.access_token);
    try std.testing.expectEqual(types.TokenType.api_key, result.token_type);
}

test "buildCredentialGeneric with claude template" {
    const token = TokenFields{
        .access_token = "sk-test",
        .refresh_token = "rt-test",
    };
    const result = try buildCredentialGeneric(claude_def, token, std.testing.allocator);
    defer std.testing.allocator.free(result);
    // Should produce the wrapped format
    try std.testing.expect(std.mem.indexOf(u8, result, "claudeAiOauth") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "sk-test") != null);
}

test "findBuiltin" {
    try std.testing.expectEqualStrings("Claude Code", findBuiltin("claude").?.display_name);
    try std.testing.expectEqualStrings("Codex CLI", findBuiltin("codex").?.display_name);
    try std.testing.expect(findBuiltin("nonexistent") == null);
}

test "detectFromCommand" {
    try std.testing.expectEqualStrings("claude", detectFromCommand(&.{"claude"}).?.name);
    try std.testing.expectEqualStrings("codex", detectFromCommand(&.{"codex"}).?.name);
    try std.testing.expectEqualStrings("github", detectFromCommand(&.{"gh"}).?.name);
    try std.testing.expect(detectFromCommand(&.{"unknown"}) == null);
}

test "classifyHttp generic rate limit and quota" {
    const short = classifyHttp(generic_def, 429, 30, null);
    switch (short) {
        .rate_limited => |rl| {
            try std.testing.expectEqual(@as(u32, 30), rl.retry_after_s);
            try std.testing.expectEqual(types.RateLimitWindow.per_minute, rl.window);
        },
        else => return error.TestUnexpectedResult,
    }

    const long = classifyHttp(generic_def, 429, 7200, null);
    switch (long) {
        .quota_exhausted => |q| try std.testing.expectEqual(@as(u32, 7200), q.retry_after_s),
        else => return error.TestUnexpectedResult,
    }
}

test "classifyHttp MCP route failures" {
    const scope = classifyHttp(mcp_def, 403, null, "Bearer error=\"insufficient_scope\"");
    switch (scope) {
        .degraded => |reason| try std.testing.expectEqual(types.DegradedReason.scope_insufficient, reason),
        else => return error.TestUnexpectedResult,
    }

    const step_up = classifyHttp(mcp_def, 403, null, "mcp step_up required");
    switch (step_up) {
        .degraded => |reason| try std.testing.expectEqual(types.DegradedReason.step_up_required, reason),
        else => return error.TestUnexpectedResult,
    }

    const schema = classifyHttp(mcp_def, 422, null, "tool schema invalid");
    switch (schema) {
        .degraded => |reason| try std.testing.expectEqual(types.DegradedReason.schema_invalid, reason),
        else => return error.TestUnexpectedResult,
    }
}

test "probePlanForCapability resolves aliases" {
    const caps = [_]CapabilityDefinition{
        .{
            .name = "chat:max",
            .aliases = &.{"gpt-5.1-codex-max"},
            .probe = .{
                .method = "POST",
                .url = "https://example.invalid/v1/probe",
                .hint_header = "www-authenticate",
            },
        },
    };
    const def = ProviderDefinition{
        .name = "toy",
        .capabilities = &caps,
    };

    const plan = probePlanForCapability(def, "gpt-5.1-codex-max").?;
    try std.testing.expectEqualStrings("chat:max", plan.capability);
    try std.testing.expectEqualStrings("POST", plan.method);
    try std.testing.expectEqual(ProbeAuth.bearer, plan.auth);
    try std.testing.expectEqualStrings("www-authenticate", plan.hint_header.?);
    try std.testing.expect(probePlanForCapability(def, "unknown") == null);
}
