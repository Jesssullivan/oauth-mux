const std = @import("std");
const types = @import("types.zig");
const log = @import("log.zig");

pub const proof_needs_operator = "needs_operator_proof";
pub const proof_live = "live_proven";
pub const proof_local_live = "local_live_proven";
pub const proof_public_live = "public_live_proven";

// TIN-2722: the committed, redacted live-capture evidence dir behind the Claude
// model-class capabilities below. Used verbatim as their proof_status — rendered
// exactly like the marker constants above (a []const u8 the operator resolves to
// on-disk evidence; there is no semantic comparison of proof_status anywhere, it
// is only surfaced as JSON). Presence proves the ROUTE ID was observed live on
// the wire in this capture: haiku served an HTTP 200 carrying the
// anthropic-ratelimit-unified-* headers, while fable/opus were gated with a 429 —
// a DIRECT-PROBE artifact, NOT harness quota, per the dir's README §3. It does
// NOT license any per-model serving or quota claim; that needs the harness-traffic
// or browser channel (TIN-2720).
pub const claude_quota_fixture_dir = "test/evidence/quota-observation/claude-20260709T220705Z";

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
    extension_mode: types.ProviderExtensionMode = .schema_only,

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

    // ── Runtime ──
    // Platform-neutral harness runtime requirements. Service-manager wrappers
    // live outside this schema; the core only models commands, env, paths, and
    // repair ownership.
    runtime: RuntimeConfig = .{},
    repair: RepairConfig = .{},

    // ── Capability Probes ──
    // Optional route/capability probes. These are declarative plans, not
    // secrets: token material is added by the caller at execution time.
    capabilities: []const CapabilityDefinition = &.{},

    // ── Rate Limit Interpretation ──
    // How to parse rate limit signals from HTTP responses.
    rate_limits: RateLimitConfig = .{},

    // ── Failure Classification ──
    // Provider-specific HTTP/status/body hints that override generic OAuth
    // fallback classification. No regex; only exact status/range and simple
    // exact/substring hints so the parser remains std-only.
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
    // TIN-2087: derive expiry from the `exp` claim of a JWT at this path
    // (e.g. codex stores no wall-clock expiry — only a JWT access token).
    // Tried only after expires_at_path/expires_in_path yield nothing. The
    // payload is base64url-decoded and read; no signature verification (we
    // trust our own store). `exp` is epoch seconds per RFC 7519.
    expires_from_jwt_path: ?[]const u8 = null,
    // Alternative paths for API key mode
    api_key_path: ?[]const u8 = null,
    // TIN-2043: JSON path (relative to wrapper) to the stable UPSTREAM
    // account identity carried in the credential — e.g. codex
    // "tokens.account_id". The refresh path hashes it (sha256_12hex) and
    // takes the same per-identity flock the managed session does, so a warm
    // refresh of one config account never rotates the single-use RT chain
    // shared by a sibling config account's live session. null = the
    // credential carries no in-band identity (claude's lives in
    // .claude.json, not the keychain blob).
    identity_claim_path: ?[]const u8 = null,
    // Wrapper key — if the credential JSON is nested under a top-level key
    wrapper_key: ?[]const u8 = null,
    // Token type detection: if api_key_path resolves, treat as api_key
    token_type: []const u8 = "bearer",
    // Unit of the value at expires_at_path IN THE STORE. TokenFields is
    // always epoch seconds; reads convert from this unit and writes convert
    // back to it. Claude Code stores epoch milliseconds (verified live,
    // TIN-2074: 13-digit expiresAt) — without this, expiry math treats a
    // Claude token as never expiring.
    expires_at_unit: ExpiresAtUnit = .seconds,
};

pub const ExpiresAtUnit = enum { seconds, milliseconds };

// Convert a stored expiry value into epoch seconds (TokenFields' unit).
// For .milliseconds, a value that is implausibly small to be epoch-ms
// (< 1e12 ≈ year 2001 in ms) is treated as already-seconds rather than
// divided — so a legacy or hand-edited seconds-valued store is never
// corrupted into year 1970.
pub fn expiryStoreToSeconds(unit: ExpiresAtUnit, raw: i64) i64 {
    return switch (unit) {
        .seconds => raw,
        .milliseconds => if (raw >= 1_000_000_000_000) @divTrunc(raw, 1000) else raw,
    };
}

// Convert epoch seconds back into the store's unit. Saturating: a token
// endpoint that returns an absurd expires_in must not overflow i64 and
// panic while the repair flock is held.
pub fn expirySecondsToStore(unit: ExpiresAtUnit, secs: i64) i64 {
    return switch (unit) {
        .seconds => secs,
        .milliseconds => secs *| 1000,
    };
}

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

pub const RuntimeConfig = struct {
    required_binaries: []const []const u8 = &.{},
    env_vars: []const []const u8 = &.{},
    writable_paths: []const []const u8 = &.{},
    session_paths: []const []const u8 = &.{},
};

pub const RepairConfig = struct {
    owner: types.RepairOwner = .manual_only,
    // TIN-2058: whether oauth-mux is technically able to drive a proactive
    // token refresh for this provider (a refresh_token grant the mux can
    // execute against the provider's token endpoint). This declares
    // capability, not permission — admission additionally requires the
    // account's explicit `allow_proactive_refresh` consent in config. Login
    // ownership (`owner`) is unaffected: interactive re-auth stays with the
    // upstream CLI.
    proactive_refresh: ProactiveRefreshSupport = .unsupported,
    // OAuth permits a successful token response to omit refresh_token. Keep
    // rotating-token providers fail-closed by default; a custom provider must
    // explicitly declare reusable submitted-token semantics.
    refresh_token_response: RefreshTokenResponsePolicy = .require_rotated,
};

pub const ProactiveRefreshSupport = enum {
    unsupported,
    oauth_refresh_token,
};

pub const RefreshTokenResponsePolicy = enum {
    require_rotated,
    reuse_submitted_if_omitted,
};

pub const CapabilityDefinition = struct {
    name: []const u8,
    aliases: []const []const u8 = &.{},
    proof_status: []const u8 = proof_needs_operator,
    proof_requirements: []const []const u8 = &.{},
    probe: ?ProbeDefinition = null,
};

pub const ProbeDefinition = struct {
    transport: ProbeTransport = .http,
    method: []const u8 = "GET",
    url: []const u8 = "",
    body: ?[]const u8 = null,
    content_type: ?[]const u8 = null,
    command: ?[]const []const u8 = null,
    auth: ProbeAuth = .bearer,
    auth_header: ?[]const u8 = null,
    timeout_ms: u32 = 30_000,
    success_status_min: u16 = 200,
    success_status_max: u16 = 299,
    hint_header: ?[]const u8 = null,
    hint_body: bool = false,
    budget: ?types.ActionBudget = null,
};

pub const ProbeTransport = enum {
    http,
    command,
};

pub const ProbeAuth = enum {
    bearer,
    authorization_header,
    token_header,
    none,
};

pub const ProbePlan = struct {
    capability: []const u8,
    transport: ProbeTransport,
    method: []const u8,
    url: []const u8,
    body: ?[]const u8 = null,
    content_type: ?[]const u8 = null,
    command: ?[]const []const u8 = null,
    auth: ProbeAuth,
    auth_header: ?[]const u8 = null,
    timeout_ms: u32,
    success_status_min: u16,
    success_status_max: u16,
    hint_header: ?[]const u8 = null,
    hint_body: bool = false,
    budget: types.ActionBudget,
};

// ── Unified rate-limit header family (TIN-2722) ──
//
// Some providers (Anthropic/Claude) express quota not as a single
// remaining/reset pair but as a family of prefixed headers describing two
// independent, ACCOUNT-WIDE windows — a 5-hour rolling window plus a 7-day
// weekly window — each carrying a status, an ABSOLUTE reset (epoch SECONDS, a
// wall-clock instant, NOT a delta), and a utilization fraction in 0.0..1.0.
// Captured live off a 200 in `claude_quota_fixture_dir`; the exact 12-header
// block is asserted verbatim in the tests below. A provider declares EITHER the
// legacy remaining_header/reset_header pair OR this unified scheme.
//
// This is a DECLARATIVE description of the header grammar; the pure fold that
// reads a response's headers against it is `foldUnifiedRateLimit`. The signal
// is account-unified (there is NO per-model dimension in any header name), so
// per-model quota MUST NOT be inferred from it.
pub const UnifiedRateLimitScheme = struct {
    // Shared prefix of every header in the family. Concrete names are
    // "<prefix>-<suffix>" (account-wide fields) and
    // "<prefix>-<window-segment>-<suffix>" (per-window fields). Header-name
    // matching is ASCII case-insensitive (HTTP header names are case-insensitive).
    prefix: []const u8 = "anthropic-ratelimit-unified",
    status_suffix: []const u8 = "status",
    reset_suffix: []const u8 = "reset",
    utilization_suffix: []const u8 = "utilization",
    representative_suffix: []const u8 = "representative-claim",
    overage_status_suffix: []const u8 = "overage-status",
    overage_disabled_reason_suffix: []const u8 = "overage-disabled-reason",
    fallback_percentage_suffix: []const u8 = "fallback-percentage",
    // Header segment for each observed window (inserted between prefix and the
    // per-window suffix), e.g. "5h" → anthropic-ratelimit-unified-5h-status.
    five_hour_segment: []const u8 = "5h",
    seven_day_segment: []const u8 = "7d",
};

// The parsed result of folding a response's headers against a
// UnifiedRateLimitScheme. EVERY field is optional — absence is data: a header
// the server did not send stays null, never a fabricated default. String fields
// BORROW the header value slices passed to foldUnifiedRateLimit (no allocation);
// they are valid only while those headers are. reset_s / representative_reset_s
// are epoch seconds; utilization / fallback_percentage are 0..1 fractions.
pub const UnifiedRateLimit = struct {
    pub const Window = struct {
        status: ?[]const u8 = null,
        reset_s: ?i64 = null,
        utilization: ?f64 = null,
    };

    overall_status: ?[]const u8 = null,
    five_h: Window = .{},
    seven_d: Window = .{},
    representative: ?[]const u8 = null,
    representative_reset_s: ?i64 = null,
    fallback_percentage: ?f64 = null,
    overage_status: ?[]const u8 = null,
    overage_disabled_reason: ?[]const u8 = null,
};

// Pure, total, allocation-free fold of a response's headers into a
// UnifiedRateLimit. Never panics: a malformed numeric value yields null for
// that field — this covers a bad int/float, a NON-FINITE float ("NaN"/"inf"/
// "Infinity"/an overflowing "1e999", all of which std.fmt.parseFloat otherwise
// accepts), an out-of-range fraction (outside 0..1), and a negative epoch. And
// unrecognized headers (e.g. the account-conditional `-fallback` /
// `-*-surpassed-threshold` extras) are ignored. Header names are matched ASCII
// case-insensitively.
//
// BOUNDARY (TIN-2722): this is the future Observed-event source for the quota
// bucket algebra. It is deliberately NOT consumed by health/routing in this
// increment — it ships as a tested pure fold that a later increment wires in.
pub fn foldUnifiedRateLimit(
    scheme: UnifiedRateLimitScheme,
    headers: []const std.http.Header,
) UnifiedRateLimit {
    var out = UnifiedRateLimit{};
    for (headers) |header| {
        const rest = stripDelimitedPrefix(header.name, scheme.prefix) orelse continue;
        const value = std.mem.trim(u8, header.value, " \t\r\n");
        if (std.ascii.eqlIgnoreCase(rest, scheme.status_suffix)) {
            out.overall_status = value;
        } else if (std.ascii.eqlIgnoreCase(rest, scheme.reset_suffix)) {
            out.representative_reset_s = parseEpochSecondsOrNull(value);
        } else if (std.ascii.eqlIgnoreCase(rest, scheme.representative_suffix)) {
            out.representative = value;
        } else if (std.ascii.eqlIgnoreCase(rest, scheme.overage_status_suffix)) {
            out.overage_status = value;
        } else if (std.ascii.eqlIgnoreCase(rest, scheme.overage_disabled_reason_suffix)) {
            out.overage_disabled_reason = value;
        } else if (std.ascii.eqlIgnoreCase(rest, scheme.fallback_percentage_suffix)) {
            out.fallback_percentage = parseFractionOrNull(value);
        } else if (stripDelimitedPrefix(rest, scheme.five_hour_segment)) |suffix| {
            applyUnifiedWindowField(&out.five_h, scheme, suffix, value);
        } else if (stripDelimitedPrefix(rest, scheme.seven_day_segment)) |suffix| {
            applyUnifiedWindowField(&out.seven_d, scheme, suffix, value);
        }
    }
    return out;
}

fn applyUnifiedWindowField(
    window: *UnifiedRateLimit.Window,
    scheme: UnifiedRateLimitScheme,
    suffix: []const u8,
    value: []const u8,
) void {
    if (std.ascii.eqlIgnoreCase(suffix, scheme.status_suffix)) {
        window.status = value;
    } else if (std.ascii.eqlIgnoreCase(suffix, scheme.reset_suffix)) {
        window.reset_s = parseEpochSecondsOrNull(value);
    } else if (std.ascii.eqlIgnoreCase(suffix, scheme.utilization_suffix)) {
        window.utilization = parseFractionOrNull(value);
    }
}

// Returns the part of `name` after "<prefix>-", or null if `name` is not of the
// form "<prefix>-…". Case-insensitive, allocation-free.
fn stripDelimitedPrefix(name: []const u8, prefix: []const u8) ?[]const u8 {
    if (name.len <= prefix.len) return null;
    if (!std.ascii.startsWithIgnoreCase(name, prefix)) return null;
    if (name[prefix.len] != '-') return null;
    return name[prefix.len + 1 ..];
}

fn parseEpochSecondsOrNull(value: []const u8) ?i64 {
    const parsed = std.fmt.parseInt(i64, value, 10) catch return null;
    // Contract: an ABSOLUTE epoch-seconds instant. A negative epoch is nonsense
    // for a reset time, so treat it as malformed → null rather than store a
    // bogus pre-1970 instant a later quota consumer could mis-route on.
    if (parsed < 0) return null;
    return parsed;
}

fn parseFractionOrNull(value: []const u8) ?f64 {
    const parsed = std.fmt.parseFloat(f64, value) catch return null;
    // Contract: a fraction in 0.0..1.0. std.fmt.parseFloat also ACCEPTS the
    // non-finite spellings "NaN"/"inf"/"-inf"/"Infinity" and overflows like
    // "1e999" → +inf; those (and any out-of-range magnitude) are malformed for
    // a utilization/percentage and must yield null, never leak past as a bogus
    // fraction. The range test also rejects the non-finite cases (every
    // comparison with NaN is false; ±inf falls outside 0..1).
    if (!std.math.isFinite(parsed)) return null;
    if (parsed < 0.0 or parsed > 1.0) return null;
    return parsed;
}

pub const RateLimitConfig = struct {
    // HTTP header names for rate limit info
    retry_after_header: []const u8 = "retry-after",
    remaining_header: ?[]const u8 = null,
    reset_header: ?[]const u8 = null,
    limit_header: ?[]const u8 = null,
    // Threshold: retry_after above this (seconds) = quota exhaustion, below = rate limit
    quota_threshold_seconds: u32 = 3600,
    // TIN-2722: the Anthropic unified header-family scheme (see
    // UnifiedRateLimitScheme). A provider sets EITHER remaining_header/
    // reset_header above OR this — never both meaningfully. null = the provider
    // uses the legacy pair. Reset values in the family are epoch SECONDS
    // (non-negative) and utilization is a 0..1 fraction; foldUnifiedRateLimit
    // parses them with the tolerance the fixture shows — any malformed value
    // (bad/non-finite/out-of-range number, negative epoch) → null, never a panic.
    unified: ?UnifiedRateLimitScheme = null,
};

pub const FailureRule = struct {
    status: ?u16 = null,
    status_min: ?u16 = null,
    status_max: ?u16 = null,
    retry_after_gte: ?u32 = null,
    retry_after_lt: ?u32 = null,
    hint_equals: ?[]const u8 = null,
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
    linear_def,
    figma_def,
    flakehub_def,
    mcp_def,
};

pub const generic_def = ProviderDefinition{
    .name = "generic",
    .display_name = "Generic OAuth Provider",
};

const claude_failure_rules = [_]FailureRule{
    .{
        .status = 400,
        .hint_contains = "\"loggedIn\": false",
        .class = .{ .dead = .token_revoked },
    },
    .{
        .status = 400,
        .hint_contains = "\"loggedIn\":false",
        .class = .{ .dead = .token_revoked },
    },
    .{
        .status = 400,
        .class = .{ .degraded = .unknown_4xx },
    },
    .{
        .status_min = 500,
        .status_max = 599,
        .class = .provider_degraded,
    },
};

const claude_capabilities = [_]CapabilityDefinition{
    .{
        .name = "auth-status",
        .aliases = &.{ "status", "identity", "whoami" },
        .proof_status = proof_local_live,
        .proof_requirements = &.{
            "claude CLI installed",
            "account-scoped CLAUDE_CONFIG_DIR",
            "user-mediated claude auth login",
        },
        .probe = .{
            .transport = .command,
            .auth = .none,
            .timeout_ms = 30_000,
            .command = &.{ "claude", "auth", "status", "--json" },
            .budget = .free_command,
        },
    },
    // ── Model-class routes (TIN-2722) ──
    // Passive-only declarations: probe = null. There is deliberately NO spend
    // path here — a synthetic direct probe is not the operator's own harness
    // traffic and cannot observe model-quota state (per claude_quota_fixture_dir
    // README §3). `aliases` are the real model ids seen on the wire. proof_status
    // points at the committed capture for the three ids observed there; sonnet
    // carries the lower needs-operator marker (its id was not in the capture).
    .{
        .name = "haiku",
        .aliases = &.{"claude-haiku-4-5-20251001"},
        .proof_status = claude_quota_fixture_dir,
        .proof_requirements = &.{
            "test/evidence/quota-observation/claude-20260709T220705Z",
            "served HTTP 200 with the anthropic-ratelimit-unified-* headers on every enrolled account",
        },
    },
    .{
        .name = "fable",
        .aliases = &.{"claude-fable-5"},
        .proof_status = claude_quota_fixture_dir,
        .proof_requirements = &.{
            "test/evidence/quota-observation/claude-20260709T220705Z",
            "model id observed live but GATED (429) on the direct-probe path — a probe-path artifact, NOT harness quota; serving/quota unproven on this channel (TIN-2720)",
        },
    },
    .{
        .name = "opus",
        .aliases = &.{"claude-opus-4-8"},
        .proof_status = claude_quota_fixture_dir,
        .proof_requirements = &.{
            "test/evidence/quota-observation/claude-20260709T220705Z",
            "model id observed live but GATED (429) on the direct-probe path — a probe-path artifact, NOT harness quota; serving/quota unproven on this channel (TIN-2720)",
        },
    },
    .{
        // The current Sonnet id (claude-sonnet-5) was NOT present in the E2
        // capture — declared prior, not fixture-observed. Lower proof marker.
        .name = "sonnet",
        .aliases = &.{"claude-sonnet-5"},
        .proof_status = proof_needs_operator,
        .proof_requirements = &.{
            "claude-sonnet-5 id declared prior; NOT observed in any committed capture — needs a live capture to graduate",
        },
    },
};

const mcp_failure_rules = [_]FailureRule{
    .{
        .status = 401,
        .hint_contains = "invalid_target",
        .class = .{ .degraded = .audience_mismatch },
    },
    .{
        .status = 403,
        .hint_contains = "invalid_target",
        .class = .{ .degraded = .audience_mismatch },
    },
    .{
        .status = 401,
        .hint_contains = "audience",
        .class = .{ .degraded = .audience_mismatch },
    },
    .{
        .status = 403,
        .hint_contains = "audience",
        .class = .{ .degraded = .audience_mismatch },
    },
    .{
        .status = 401,
        .hint_contains = "resource mismatch",
        .class = .{ .degraded = .audience_mismatch },
    },
    .{
        .status = 403,
        .hint_contains = "resource mismatch",
        .class = .{ .degraded = .audience_mismatch },
    },
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

const mcp_capabilities = [_]CapabilityDefinition{
    .{
        .name = "resource-metadata",
        .aliases = &.{ "metadata", "protected-resource-metadata" },
        .proof_status = proof_public_live,
        .proof_requirements = &.{
            "OMUX_MCP_RESOURCE_METADATA_URL",
            "public RFC 9728 protected resource metadata",
        },
        .probe = .{
            .method = "GET",
            .url = "{{OMUX_MCP_RESOURCE_METADATA_URL}}",
            .auth = .none,
            .hint_body = true,
            .budget = .cheap_provider,
        },
    },
    .{
        .name = "resource",
        .aliases = &.{ "resource-probe", "http" },
        .proof_requirements = &.{
            "OMUX_MCP_RESOURCE_TOKEN",
            "OMUX_MCP_RESOURCE_PROBE_URL",
            "resource-bound bearer token for the probed MCP resource",
        },
        .probe = .{
            .method = "GET",
            .url = "{{OMUX_MCP_RESOURCE_PROBE_URL}}",
            .auth = .bearer,
            .hint_header = "www-authenticate",
            .budget = .cheap_provider,
        },
    },
};

const codex_failure_rules = [_]FailureRule{
    .{
        .status = 400,
        .hint_contains = "not supported when using Codex with a ChatGPT account",
        .class = .{ .degraded = .tier_insufficient },
    },
    .{
        .status = 400,
        .hint_contains = "model is not supported",
        .class = .{ .degraded = .tier_insufficient },
    },
};

const github_failure_rules = [_]FailureRule{
    .{
        .status = 403,
        .hint_equals = "0",
        .class = .rate_limited,
    },
    .{
        .status = 403,
        .class = .{ .degraded = .scope_insufficient },
    },
    .{
        .status_min = 500,
        .status_max = 599,
        .class = .provider_degraded,
    },
};

const vercel_failure_rules = [_]FailureRule{
    .{
        .status = 403,
        .hint_contains = "scope",
        .class = .{ .degraded = .scope_insufficient },
    },
    .{
        .status = 403,
        .class = .{ .degraded = .tier_insufficient },
    },
    .{
        .status_min = 500,
        .status_max = 599,
        .class = .provider_degraded,
    },
};

const vercel_capabilities = [_]CapabilityDefinition{
    .{
        .name = "identity",
        .aliases = &.{ "user", "whoami" },
        .proof_status = proof_local_live,
        .proof_requirements = &.{
            "VERCEL_TOKEN",
            "Vercel token accepted by GET /v2/user",
        },
        .probe = .{
            .method = "GET",
            .url = "https://api.vercel.com/v2/user",
            .auth = .bearer,
        },
    },
};

const github_capabilities = [_]CapabilityDefinition{
    .{
        .name = "identity",
        .aliases = &.{ "user", "whoami" },
        .proof_status = proof_local_live,
        .proof_requirements = &.{
            "GH_TOKEN or gh auth token",
            "GitHub token accepted by GET /user",
        },
        .probe = .{
            .method = "GET",
            .url = "https://api.github.com/user",
            .auth = .bearer,
            .hint_header = "x-ratelimit-remaining",
        },
    },
};

const linear_failure_rules = [_]FailureRule{
    .{
        .status = 200,
        .hint_contains = "\"errors\"",
        .class = .{ .degraded = .unknown_4xx },
    },
    .{
        .status = 403,
        .class = .{ .degraded = .scope_insufficient },
    },
    .{
        .status_min = 500,
        .status_max = 599,
        .class = .provider_degraded,
    },
};

const linear_capabilities = [_]CapabilityDefinition{
    .{
        .name = "identity",
        .aliases = &.{ "viewer", "whoami" },
        .proof_requirements = &.{
            "LINEAR_ACCESS_TOKEN",
            "OAuth bearer token accepted by Linear GraphQL viewer query",
        },
        .probe = .{
            .method = "POST",
            .url = "https://api.linear.app/graphql",
            .body = "{\"query\":\"query Me { viewer { id name email } }\"}",
            .content_type = "application/json",
            .auth = .bearer,
            .hint_body = true,
        },
    },
    .{
        .name = "identity-api-key",
        .aliases = &.{ "api-key", "personal-api-key", "pat", "whoami-api-key" },
        .proof_status = proof_local_live,
        .proof_requirements = &.{
            "Linear personal API key",
            "raw Authorization header accepted by Linear GraphQL viewer query",
        },
        .probe = .{
            .method = "POST",
            .url = "https://api.linear.app/graphql",
            .body = "{\"query\":\"query Me { viewer { id name email } }\"}",
            .content_type = "application/json",
            .auth = .authorization_header,
            .hint_body = true,
        },
    },
};

const figma_failure_rules = [_]FailureRule{
    .{
        .status = 403,
        .class = .{ .degraded = .scope_insufficient },
    },
    .{
        .status = 404,
        .class = .{ .degraded = .unknown_4xx },
    },
    .{
        .status_min = 500,
        .status_max = 599,
        .class = .provider_degraded,
    },
};

const figma_capabilities = [_]CapabilityDefinition{
    .{
        .name = "identity",
        .aliases = &.{ "me", "whoami" },
        .proof_requirements = &.{
            "FIGMA_ACCESS_TOKEN",
            "OAuth token with current_user:read",
        },
        .probe = .{
            .method = "GET",
            .url = "https://api.figma.com/v1/me",
            .auth = .bearer,
        },
    },
    .{
        .name = "identity-pat",
        .aliases = &.{ "me-pat", "pat" },
        .proof_status = proof_local_live,
        .proof_requirements = &.{
            "OMUX_FIGMA_PAT or FIGMA_ACCESS_TOKEN",
            "Figma personal access token accepted by X-Figma-Token",
        },
        .probe = .{
            .method = "GET",
            .url = "https://api.figma.com/v1/me",
            .auth = .token_header,
            .auth_header = "X-Figma-Token",
        },
    },
    .{
        .name = "file-metadata-plan",
        .aliases = &.{ "plan-file-meta", "plan-file-metadata", "plan" },
        .proof_requirements = &.{
            "OMUX_FIGMA_PLAN_TOKEN",
            "OMUX_FIGMA_PLAN_FILE_KEY",
            "Organization or Enterprise plan access token with file metadata scope",
        },
        .probe = .{
            .method = "GET",
            .url = "https://api.figma.com/v1/files/{{OMUX_FIGMA_PLAN_FILE_KEY}}/meta",
            .auth = .token_header,
            .auth_header = "X-Figma-Token",
        },
    },
};

const flakehub_failure_rules = [_]FailureRule{
    .{
        .status = 200,
        .hint_contains = "Logged in: false",
        .class = .{ .dead = .token_revoked },
    },
    .{
        .status = 400,
        .hint_contains = "Logged in: false",
        .class = .{ .dead = .token_revoked },
    },
    .{
        .status = 400,
        .class = .{ .degraded = .unknown_4xx },
    },
    .{
        .status_min = 500,
        .status_max = 599,
        .class = .provider_degraded,
    },
};

const flakehub_capabilities = [_]CapabilityDefinition{
    .{
        .name = "status",
        .aliases = &.{ "identity", "whoami" },
        .proof_status = proof_local_live,
        .proof_requirements = &.{
            "determinate-nixd installed",
            "local Determinate/FlakeHub auth state",
        },
        .probe = .{
            .transport = .command,
            .auth = .none,
            .timeout_ms = 30_000,
            .command = &.{ "determinate-nixd", "status" },
            .budget = .free_command,
        },
    },
};

const codex_capabilities = [_]CapabilityDefinition{
    .{
        .name = "codex-max",
        .aliases = &.{ "max", "gpt-5.5", "gpt-5.3-codex", "gpt-5.1-codex-max" },
        .proof_status = proof_live,
        .proof_requirements = &.{
            "codex CLI installed",
            "account-scoped CODEX_HOME",
            "ChatGPT account with Codex Max-capable subscription or API path",
            "OMUX_LIVE_QA_CONFIRM=spend-real-calls for live proof",
        },
        .probe = .{
            .transport = .command,
            .auth = .none,
            .timeout_ms = 120_000,
            .command = &.{
                "codex",
                "exec",
                "--json",
                "--ephemeral",
                "--ignore-rules",
                "-m",
                "gpt-5.5",
                "Reply exactly: OMUX_CODEX_MAX_PROBE",
            },
            .budget = .spend_provider,
        },
    },
    .{
        .name = "codex-mini",
        .aliases = &.{ "mini", "spark", "gpt-5.3-codex-spark", "gpt-5.1-codex-mini" },
        .proof_status = proof_live,
        .proof_requirements = &.{
            "codex CLI installed",
            "account-scoped CODEX_HOME",
            "ChatGPT account with Codex CLI access",
            "OMUX_LIVE_QA_CONFIRM=spend-real-calls for live proof",
        },
        .probe = .{
            .transport = .command,
            .auth = .none,
            .timeout_ms = 120_000,
            .command = &.{
                "codex",
                "exec",
                "--json",
                "--ephemeral",
                "--ignore-rules",
                "-m",
                "gpt-5.3-codex-spark",
                "Reply exactly: OMUX_CODEX_MINI_PROBE",
            },
            .budget = .spend_provider,
        },
    },
};

pub const claude_keychain_service_base = "Claude Code-credentials";

// Claude Code keys its macOS login-keychain item on a per-config-dir service
// name: the default dir (~/.claude) uses the unsuffixed base, and any other
// CLAUDE_CONFIG_DIR appends "-<first 8 hex of sha256(absolute dir)>". The
// input must be the same absolute string exported as CLAUDE_CONFIG_DIR
// (tilde-expanded, not realpath'd) or the hash diverges from the CLI's own.
// Verified live: docs/spec/provider-proof-claude-credential-store-2026-06-12.md.
pub fn claudeKeychainService(allocator: std.mem.Allocator, config_dir_absolute: []const u8) error{OutOfMemory}![]u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(config_dir_absolute, &digest, .{});
    return std.fmt.allocPrint(allocator, "{s}-{x}", .{
        claude_keychain_service_base,
        std.fmt.fmtSliceHexLower(digest[0..4]),
    });
}

pub const claude_def = ProviderDefinition{
    .name = "claude",
    .display_name = "Claude Code",
    .extension_mode = .command_adapter,
    .auth = .{
        .token_endpoint = "https://console.anthropic.com/v1/oauth/token",
        .authorization_endpoint = "https://console.anthropic.com/oauth/authorize",
        .client_id = "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
    },
    .credential = .{
        .access_token_path = "accessToken",
        .refresh_token_path = "refreshToken",
        .expires_at_path = "expiresAt",
        .wrapper_key = "claudeAiOauth",
        // Verified live (TIN-2074): Claude Code stores 13-digit epoch ms.
        .expires_at_unit = .milliseconds,
    },
    .injection = .{
        .config_dir_env = "CLAUDE_CONFIG_DIR",
        .credential_filename = ".credentials.json",
        // Bootstrap-only: refresh writeback merges into the existing store
        // (mergeCredentialGeneric) and never goes through this template
        // when a credential already exists.
        .credential_template =
        \\{"claudeAiOauth":{"accessToken":"{{access_token}}","refreshToken":"{{refresh_token}}","expiresAt":{{expires_at}}}}
        ,
    },
    .detection = .{
        .binary_names = &.{"claude"},
    },
    .runtime = .{
        .required_binaries = &.{"claude"},
        .env_vars = &.{"CLAUDE_CONFIG_DIR"},
    },
    // GRANT FLIPPED (TIN-2057): the provider now SUPPORTS proactive refresh.
    // Substrate complete — serialization (TIN-2073), field-preserving writeback
    // (TIN-2074: merge preserves expiresAt/scopes/subscriptionType, ms-unit
    // aware), Option B proactive-rotation (TIN-2055), the per-account + identity
    // flocks, and the canonical-keychain writeback refusal (TIN-2054/#406). Login
    // stays upstream_cli_login, so refresh is admitted ONLY for an account that
    // also opts in (allow_proactive_refresh: true) — no behaviour change for any
    // account that hasn't opted in. The bare-CLI dual-writer (R3, TIN-2059) is the
    // accepted residual: the store-invariant (never persist an RT it didn't mint)
    // downgrades a concurrent native-CLI rotation to a wasted refresh, never
    // corruption. Live-proven 2026-06-14 (2×Claude proactively refreshed via
    // `oauth-mux keepalive`, scopes/subscriptionType preserved, zero collateral).
    .repair = .{
        .owner = .upstream_cli_login,
        .proactive_refresh = .oauth_refresh_token,
        .refresh_token_response = .require_rotated,
    },
    .capabilities = &claude_capabilities,
    .failure_rules = &claude_failure_rules,
    // TIN-2722: corrected to the observed truth. The x-ratelimit-remaining /
    // x-ratelimit-reset placeholders here were never emitted by Anthropic on
    // this path; the real signal is the anthropic-ratelimit-unified-* family
    // (5h + 7d account-wide windows), captured live in `claude_quota_fixture_dir`
    // and parsed by foldUnifiedRateLimit. Declaring the unified scheme (and no
    // legacy remaining/reset pair) is the "either/or" invariant in RateLimitConfig.
    .rate_limits = .{
        .unified = .{},
    },
};

pub const codex_def = ProviderDefinition{
    .name = "codex",
    .display_name = "Codex CLI",
    .extension_mode = .command_adapter,
    .auth = .{
        .token_endpoint = "https://auth.openai.com/oauth/token",
        .device_authorization_endpoint = "https://auth.openai.com/deviceauth/usercode",
        .client_id = "app_EMoamEEZ73f0CkXaXp7hrann",
    },
    .credential = .{
        .access_token_path = "tokens.access_token",
        .refresh_token_path = "tokens.refresh_token",
        // Codex auth.json has no wall-clock expiry; the access token is a
        // JWT whose `exp` claim is the truth (TIN-2087). The previously
        // declared "tokens.expires_in" never existed in the real store.
        .expires_from_jwt_path = "tokens.access_token",
        // TIN-2043: the duplicate-identity guard keys on this (the live
        // max-1 == max-4 Apple-ID shape). Same id the managed session
        // hashes for codex-identity-<hash>.
        .identity_claim_path = "tokens.account_id",
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
    .runtime = .{
        .required_binaries = &.{"codex"},
        .env_vars = &.{"CODEX_HOME"},
        .writable_paths = &.{"CODEX_HOME"},
        .session_paths = &.{"CODEX_HOME/auth.json"},
    },
    // GRANT FLIPPED (TIN-2057): the provider now SUPPORTS proactive refresh.
    // Substrate complete — serialization (TIN-2073), field-preserving merge
    // (TIN-2074: preserves tokens.id_token, the codex identity source), JWT-exp
    // expiry derivation (TIN-2087), Option B proactive-rotation (TIN-2055), and —
    // critically for codex's shared-identity shape (max-N == one Apple ID) — the
    // warm-loop identity flock (TIN-2043), which serializes any two config
    // accounts on one RT chain. Login stays upstream_cli_login → refresh admitted
    // ONLY for an opted-in account. Live-proven 2026-06-14 (2×Codex proactively
    // refreshed via `oauth-mux keepalive`, zero collateral). NOTE: two accounts
    // that share an account_id MUST NOT both be opted in (provider family
    // revocation is outside the lock domain) — see TIN-2113.
    .repair = .{
        .owner = .upstream_cli_login,
        .proactive_refresh = .oauth_refresh_token,
        .refresh_token_response = .require_rotated,
    },
    .rate_limits = .{
        .remaining_header = "x-ratelimit-remaining-requests",
        .reset_header = "x-ratelimit-reset-requests",
    },
    .capabilities = &codex_capabilities,
    .failure_rules = &codex_failure_rules,
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
    .capabilities = &vercel_capabilities,
    .failure_rules = &vercel_failure_rules,
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
    .capabilities = &github_capabilities,
    .failure_rules = &github_failure_rules,
};

pub const linear_def = ProviderDefinition{
    .name = "linear",
    .display_name = "Linear",
    .auth = .{
        .authorization_endpoint = "https://linear.app/oauth/authorize",
        .token_endpoint = "https://api.linear.app/oauth/token",
    },
    .credential = .{
        .access_token_path = "access_token",
        .refresh_token_path = "refresh_token",
        .expires_in_path = "expires_in",
    },
    .injection = .{
        .direct_env = &.{.{ "LINEAR_ACCESS_TOKEN", "access_token" }},
    },
    .detection = .{
        .env_markers = &.{"LINEAR_ACCESS_TOKEN"},
    },
    .capabilities = &linear_capabilities,
    .failure_rules = &linear_failure_rules,
};

pub const figma_def = ProviderDefinition{
    .name = "figma",
    .display_name = "Figma REST API",
    .auth = .{
        .authorization_endpoint = "https://www.figma.com/oauth",
        .token_endpoint = "https://api.figma.com/v1/oauth/token",
    },
    .credential = .{
        .access_token_path = "access_token",
        .refresh_token_path = "refresh_token",
        .expires_in_path = "expires_in",
    },
    .injection = .{
        .direct_env = &.{.{ "FIGMA_ACCESS_TOKEN", "access_token" }},
    },
    .detection = .{
        .env_markers = &.{"FIGMA_ACCESS_TOKEN"},
    },
    .capabilities = &figma_capabilities,
    .failure_rules = &figma_failure_rules,
};

pub const flakehub_def = ProviderDefinition{
    .name = "flakehub",
    .display_name = "FlakeHub / Determinate Nix",
    .extension_mode = .command_adapter,
    .credential = .{
        .access_token_path = "token",
        .token_type = "api_key",
    },
    .detection = .{
        .binary_names = &.{ "determinate-nixd", "fh" },
    },
    .runtime = .{
        .required_binaries = &.{"determinate-nixd"},
    },
    .repair = .{
        .owner = .upstream_cli_login,
    },
    .capabilities = &flakehub_capabilities,
    .failure_rules = &flakehub_failure_rules,
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
    .capabilities = &mcp_capabilities,
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
            .transport = probe.transport,
            .method = probe.method,
            .url = probe.url,
            .body = probe.body,
            .content_type = probe.content_type,
            .command = probe.command,
            .auth = probe.auth,
            .auth_header = probe.auth_header,
            .timeout_ms = probe.timeout_ms,
            .success_status_min = probe.success_status_min,
            .success_status_max = probe.success_status_max,
            .hint_header = probe.hint_header,
            .hint_body = probe.hint_body,
            .budget = probe.budget orelse defaultProbeBudget(probe.transport),
        };
    }
    return null;
}

pub fn defaultProbeBudget(transport: ProbeTransport) types.ActionBudget {
    return switch (transport) {
        .http => .cheap_provider,
        .command => .free_command,
    };
}

pub fn classifyCodexExecJsonl(allocator: std.mem.Allocator, jsonl: []const u8) ?types.HttpClassification {
    var first_error: ?types.HttpClassification = null;
    var lines = std.mem.splitScalar(u8, jsonl, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, trimmed, .{}) catch continue;
        defer parsed.deinit();

        if (resolveJsonString(parsed.value, "type")) |event_type| {
            if (std.mem.eql(u8, event_type, "turn.completed")) return .success;

            if (std.mem.eql(u8, event_type, "error")) {
                if (resolveJsonString(parsed.value, "message")) |message| {
                    if (first_error == null) first_error = classifyCodexErrorMessage(allocator, message);
                    continue;
                }
            }
        }

        if (classifyCodexErrorValue(parsed.value)) |classification| {
            if (first_error == null) first_error = classification;
        }
    }

    return first_error;
}

pub fn classifyCodexAppServerJsonRpc(allocator: std.mem.Allocator, jsonl: []const u8) ?types.HttpClassification {
    var lines = std.mem.splitScalar(u8, jsonl, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;

        const parsed = std.json.parseFromSlice(std.json.Value, allocator, trimmed, .{}) catch {
            if (classifyCodexPlainErrorMessage(trimmed)) |classification| return classification;
            continue;
        };
        defer parsed.deinit();

        if (resolveJsonString(parsed.value, "method")) |method| {
            if (std.mem.eql(u8, method, "turn/completed")) {
                if (resolveJsonString(parsed.value, "params.turn.status")) |status| {
                    if (std.mem.eql(u8, status, "failed")) {
                        if (classifyCodexAppServerErrorValue(allocator, parsed.value)) |classification| return classification;
                    }
                }
            } else if (std.mem.eql(u8, method, "error")) {
                if (classifyCodexAppServerErrorValue(allocator, parsed.value)) |classification| return classification;
            }
        }

        if (classifyCodexAppServerErrorValue(allocator, parsed.value)) |classification| return classification;
    }

    return null;
}

fn classifyCodexAppServerErrorValue(allocator: std.mem.Allocator, value: std.json.Value) ?types.HttpClassification {
    if (resolveJsonString(value, "params.turn.error.type")) |error_type| {
        if (std.mem.eql(u8, error_type, "usage_limit_reached")) {
            return .{ .quota_exhausted = .{
                .retry_after_s = boundedRetryAfter(
                    resolveJsonInt(value, "params.turn.error.resets_in_seconds") orelse
                        resolveJsonInt(value, "params.turn.error.retry_after_s"),
                ) orelse 86_400,
            } };
        }
    }
    if (resolveJsonString(value, "params.error.type")) |error_type| {
        if (std.mem.eql(u8, error_type, "usage_limit_reached")) {
            return .{ .quota_exhausted = .{
                .retry_after_s = boundedRetryAfter(
                    resolveJsonInt(value, "params.error.resets_in_seconds") orelse
                        resolveJsonInt(value, "params.error.retry_after_s"),
                ) orelse 86_400,
            } };
        }
    }

    if (resolveJsonString(value, "params.turn.error.message")) |message| {
        return classifyCodexErrorMessage(allocator, message);
    }
    if (resolveJsonString(value, "params.error.message")) |message| {
        return classifyCodexErrorMessage(allocator, message);
    }
    if (resolveJsonString(value, "error.message")) |message| {
        return classifyCodexErrorMessage(allocator, message);
    }

    return classifyCodexErrorValue(value);
}

fn boundedRetryAfter(value: ?i64) ?u32 {
    const seconds = value orelse return null;
    if (seconds < 0) return null;
    return @intCast(@min(seconds, std.math.maxInt(u32)));
}

fn classifyCodexErrorMessage(allocator: std.mem.Allocator, message: []const u8) types.HttpClassification {
    if (classifyCodexPlainErrorMessage(message)) |classification| return classification;

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, message, .{}) catch {
        return classifyHttp(codex_def, 400, null, message);
    };
    defer parsed.deinit();
    return classifyCodexErrorValue(parsed.value) orelse classifyHttp(codex_def, 400, null, message);
}

fn classifyCodexErrorValue(value: std.json.Value) ?types.HttpClassification {
    const status_i = resolveJsonInt(value, "status") orelse return null;
    if (status_i < 0 or status_i > 65535) return null;
    const status: u16 = @intCast(status_i);
    const hint = resolveJsonString(value, "error.message");
    if (hint) |message| {
        if (classifyCodexPlainErrorMessage(message)) |classification| return classification;
    }
    return classifyHttp(codex_def, status, null, hint);
}

fn classifyCodexPlainErrorMessage(message: []const u8) ?types.HttpClassification {
    if (!(containsIgnoreAsciiCase(message, "usage limit") or
        containsIgnoreAsciiCase(message, "purchase more credits") or
        containsIgnoreAsciiCase(message, "try again at")))
    {
        return null;
    }

    return .{ .quota_exhausted = .{
        .retry_after_s = parseCodexUsageRetryAfter(message) orelse 86_400,
    } };
}

fn parseCodexUsageRetryAfter(message: []const u8) ?u32 {
    const marker = "try again at ";
    const start = std.ascii.indexOfIgnoreCase(message, marker) orelse return null;
    var rest = std.mem.trim(u8, message[start + marker.len ..], " \t\r\n.");

    const month = parseCodexMonth(rest[0..@min(rest.len, 9)]) orelse return null;
    rest = rest[3..];
    rest = std.mem.trimLeft(u8, rest, " \t");

    const day_digits = leadingDigitCount(rest);
    if (day_digits == 0) return null;
    const day = std.fmt.parseInt(u8, rest[0..day_digits], 10) catch return null;
    rest = rest[day_digits..];
    if (std.ascii.startsWithIgnoreCase(rest, "st") or
        std.ascii.startsWithIgnoreCase(rest, "nd") or
        std.ascii.startsWithIgnoreCase(rest, "rd") or
        std.ascii.startsWithIgnoreCase(rest, "th"))
    {
        rest = rest[2..];
    }
    rest = std.mem.trimLeft(u8, rest, " \t,");

    const year_digits = leadingDigitCount(rest);
    if (year_digits != 4) return null;
    const year = std.fmt.parseInt(u16, rest[0..year_digits], 10) catch return null;
    rest = rest[year_digits..];
    rest = std.mem.trimLeft(u8, rest, " \t");

    const hour_digits = leadingDigitCount(rest);
    if (hour_digits == 0 or hour_digits > 2) return null;
    var hour = std.fmt.parseInt(u8, rest[0..hour_digits], 10) catch return null;
    rest = rest[hour_digits..];
    if (rest.len == 0 or rest[0] != ':') return null;
    rest = rest[1..];

    const minute_digits = leadingDigitCount(rest);
    if (minute_digits == 0 or minute_digits > 2) return null;
    const minute = std.fmt.parseInt(u8, rest[0..minute_digits], 10) catch return null;
    rest = rest[minute_digits..];
    rest = std.mem.trimLeft(u8, rest, " \t");

    if (std.ascii.startsWithIgnoreCase(rest, "PM")) {
        if (hour < 12) hour += 12;
    } else if (std.ascii.startsWithIgnoreCase(rest, "AM")) {
        if (hour == 12) hour = 0;
    } else {
        return null;
    }

    const target = epochSecondsUtc(year, month, day, hour, minute) orelse return null;
    const now = std.time.timestamp();
    if (target <= now) return null;
    const diff: u64 = @intCast(target - now);
    return @intCast(@min(diff, std.math.maxInt(u32)));
}

fn parseCodexMonth(value: []const u8) ?u8 {
    if (value.len < 3) return null;
    const prefix = value[0..3];
    if (std.ascii.eqlIgnoreCase(prefix, "Jan")) return 1;
    if (std.ascii.eqlIgnoreCase(prefix, "Feb")) return 2;
    if (std.ascii.eqlIgnoreCase(prefix, "Mar")) return 3;
    if (std.ascii.eqlIgnoreCase(prefix, "Apr")) return 4;
    if (std.ascii.eqlIgnoreCase(prefix, "May")) return 5;
    if (std.ascii.eqlIgnoreCase(prefix, "Jun")) return 6;
    if (std.ascii.eqlIgnoreCase(prefix, "Jul")) return 7;
    if (std.ascii.eqlIgnoreCase(prefix, "Aug")) return 8;
    if (std.ascii.eqlIgnoreCase(prefix, "Sep")) return 9;
    if (std.ascii.eqlIgnoreCase(prefix, "Oct")) return 10;
    if (std.ascii.eqlIgnoreCase(prefix, "Nov")) return 11;
    if (std.ascii.eqlIgnoreCase(prefix, "Dec")) return 12;
    return null;
}

fn leadingDigitCount(value: []const u8) usize {
    var count: usize = 0;
    while (count < value.len and std.ascii.isDigit(value[count])) : (count += 1) {}
    return count;
}

fn epochSecondsUtc(year: u16, month: u8, day: u8, hour: u8, minute: u8) ?i64 {
    if (year < std.time.epoch.epoch_year or month < 1 or month > 12 or day < 1 or hour > 23 or minute > 59) return null;

    const leap_kind: std.time.epoch.YearLeapKind = if (std.time.epoch.isLeapYear(year)) .leap else .not_leap;
    const month_enum: std.time.epoch.Month = @enumFromInt(month);
    if (day > std.time.epoch.getDaysInMonth(leap_kind, month_enum)) return null;

    var days: u64 = 0;
    var y: u16 = std.time.epoch.epoch_year;
    while (y < year) : (y += 1) {
        days += std.time.epoch.getDaysInYear(y);
    }
    var m: u8 = 1;
    while (m < month) : (m += 1) {
        const current: std.time.epoch.Month = @enumFromInt(m);
        days += std.time.epoch.getDaysInMonth(leap_kind, current);
    }
    days += day - 1;

    return @intCast(days * std.time.epoch.secs_per_day + @as(u64, hour) * 3600 + @as(u64, minute) * 60);
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
    if (rule.hint_equals) |expected| {
        const h = hint orelse return false;
        if (!equalsIgnoreAsciiCaseTrimmed(h, expected)) return false;
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

fn equalsIgnoreAsciiCaseTrimmed(left: []const u8, right: []const u8) bool {
    const left_trimmed = std.mem.trim(u8, left, " \t\r\n");
    const right_trimmed = std.mem.trim(u8, right, " \t\r\n");
    if (left_trimmed.len != right_trimmed.len) return false;
    for (left_trimmed, right_trimmed) |l, r| {
        if (std.ascii.toLower(l) != std.ascii.toLower(r)) return false;
    }
    return true;
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

// TIN-2087: read the `exp` claim (epoch seconds, RFC 7519) from a JWT's
// payload. Decode-only — no signature verification, since the token comes
// from our own credential store. Returns null on any malformation rather
// than failing the whole parse (a token without a readable exp just means
// "no proactive-refresh signal", the pre-TIN-2087 behavior).
pub fn jwtExpSeconds(jwt: []const u8, allocator: std.mem.Allocator) ?i64 {
    var it = std.mem.splitScalar(u8, jwt, '.');
    _ = it.next() orelse return null; // header
    const payload_b64 = it.next() orelse return null; // payload
    if (payload_b64.len == 0) return null;

    const decoder = std.base64.url_safe_no_pad.Decoder;
    const decoded_len = decoder.calcSizeForSlice(payload_b64) catch return null;
    const buf = allocator.alloc(u8, decoded_len) catch return null;
    defer allocator.free(buf);
    decoder.decode(buf, payload_b64) catch return null;

    const parsed = std.json.parseFromSlice(std.json.Value, allocator, buf, .{}) catch return null;
    defer parsed.deinit();
    if (parsed.value != .object) return null;
    const exp = parsed.value.object.get("exp") orelse return null;
    return switch (exp) {
        .integer => |i| i,
        // Some issuers emit exp as a float; truncate to seconds. Range-guard
        // before @intFromFloat — in ReleaseSafe (the production lane) it
        // PANICS on an out-of-i64-range value, which `catch` cannot recover
        // (a panic is not an error), so a hand-edited/hostile exp like 1e30
        // would abort the process instead of degrading to null. (NaN/inf
        // never reach here — std.json routes them to .number_string.)
        .float => |f| if (f >= @as(f64, @floatFromInt(std.math.minInt(i64))) and
            f < @as(f64, @floatFromInt(std.math.maxInt(i64))))
            @intFromFloat(f)
        else
            null,
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

// TIN-2043: resolve the upstream account-identity string declared at
// `identity_claim_path` from a raw credential. Returns an owned copy, or
// null if the provider declares no identity path or the value is absent.
// Hashing is the caller's job (keeps this module free of identity_hash).
pub fn identityClaimFromCredential(def: ProviderDefinition, raw: []const u8, allocator: std.mem.Allocator) !?[]u8 {
    const path = def.credential.identity_claim_path orelse return null;
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, raw, .{}) catch return null;
    defer parsed.deinit();
    var root = parsed.value;
    if (def.credential.wrapper_key) |wk| {
        root = resolveJsonPath(root, wk) orelse root;
    }
    const value = resolveJsonString(root, path) orelse return null;
    if (value.len == 0) return null;
    return try allocator.dupe(u8, value);
}

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

    // Resolve expiry (store unit -> epoch seconds)
    if (def.credential.expires_at_path) |eap| {
        if (resolveJsonInt(root, eap)) |raw_exp| {
            result.expires_at = expiryStoreToSeconds(def.credential.expires_at_unit, raw_exp);
        }
    }
    if (result.expires_at == null) {
        if (def.credential.expires_in_path) |eip| {
            if (resolveJsonInt(root, eip)) |ei| {
                result.expires_at = std.time.timestamp() + ei;
            }
        }
    }
    // TIN-2087: last resort — read `exp` from a JWT (codex's access token).
    if (result.expires_at == null) {
        if (def.credential.expires_from_jwt_path) |jp| {
            if (resolveJsonString(root, jp)) |jwt| {
                result.expires_at = jwtExpSeconds(jwt, allocator);
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

// ── Field-Preserving Credential Merge (TIN-2074) ──
// Refresh writeback must not be lossy: the native store carries fields the
// token response does not own (claude: scopes/subscriptionType/rateLimitTier;
// codex: tokens.id_token/last_refresh — the identity source). Parse the
// existing credential, replace ONLY the token fields at the definition's
// declared paths, preserve everything else (including key order), and
// serialize. Callers fall back to buildCredentialGeneric when there is no
// existing credential to merge into.
pub fn mergeCredentialGeneric(
    def: ProviderDefinition,
    existing_raw: []const u8,
    token: TokenFields,
    allocator: std.mem.Allocator,
) ![]const u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, existing_raw, .{}) catch
        return error.InvalidCharacter;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidCharacter;

    const arena = parsed.arena.allocator();

    // Resolve (creating if absent) the wrapper object the credential paths
    // are relative to. A wrapped store (claude keychain, prior merge) is
    // used in place; a flat store for a wrapper-declaring provider gets the
    // wrapper established and tokens written into it. This is safe because
    // every reader of a wrapper-declaring store — the upstream CLI and
    // oauth-mux's own parseTokenGeneric (resolveJsonPath(root, wk) orelse
    // root) — resolves the wrapper FIRST and ignores any stale top-level
    // fields, so there is no dual-format ambiguity, and a flat custom
    // oauth_mux_refresh provider is not falsely refused on its first
    // refresh. ensureJsonObjectPath errors only if the path collides with a
    // non-object (e.g. wrapper_key points at a string), where the caller
    // fails closed rather than corrupt an unexpected shape.
    var root: *std.json.Value = &parsed.value;
    if (def.credential.wrapper_key) |wk| {
        root = try ensureJsonObjectPath(root, wk, arena);
    }

    try setJsonPathString(root, def.credential.access_token_path, token.access_token, arena);
    if (token.refresh_token) |rt| {
        try setJsonPathString(root, def.credential.refresh_token_path, rt, arena);
    }
    if (def.credential.expires_at_path) |eap| {
        if (token.expires_at) |ea| {
            const store_exp = expirySecondsToStore(def.credential.expires_at_unit, ea);
            try setJsonPath(root, eap, .{ .integer = store_exp }, arena);
        }
    }

    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    try std.json.stringify(parsed.value, .{}, out.writer());
    return out.toOwnedSlice();
}

// Walks a dot-separated path of objects below `root`, creating missing
// intermediate objects, and returns a pointer to the object at the path.
fn ensureJsonObjectPath(root: *std.json.Value, path: []const u8, arena: std.mem.Allocator) !*std.json.Value {
    var current = root;
    var it = std.mem.splitScalar(u8, path, '.');
    while (it.next()) |segment| {
        if (current.* != .object) return error.InvalidCharacter;
        const gop = try current.object.getOrPut(try arena.dupe(u8, segment));
        if (!gop.found_existing) {
            gop.value_ptr.* = .{ .object = std.json.ObjectMap.init(arena) };
        } else if (gop.value_ptr.* != .object) {
            return error.InvalidCharacter;
        }
        current = gop.value_ptr;
    }
    return current;
}

fn setJsonPath(root: *std.json.Value, path: []const u8, value: std.json.Value, arena: std.mem.Allocator) !void {
    const last_dot = std.mem.lastIndexOfScalar(u8, path, '.');
    const parent = if (last_dot) |idx|
        try ensureJsonObjectPath(root, path[0..idx], arena)
    else
        root;
    if (parent.* != .object) return error.InvalidCharacter;
    const leaf = if (last_dot) |idx| path[idx + 1 ..] else path;
    try parent.object.put(try arena.dupe(u8, leaf), value);
}

fn setJsonPathString(root: *std.json.Value, path: []const u8, value: []const u8, arena: std.mem.Allocator) !void {
    try setJsonPath(root, path, .{ .string = try arena.dupe(u8, value) }, arena);
}

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
                    try w.print("{d}", .{expirySecondsToStore(def.credential.expires_at_unit, ea)});
                } else {
                    // Bare {{expires_at}} in a JSON template would emit
                    // malformed output if elided; epoch 0 reads back as
                    // long-expired, which forces a refresh — the honest
                    // value for "unknown".
                    try w.writeAll("0");
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
        \\{"claudeAiOauth":{"accessToken":"sk-ant-123","refreshToken":"rt-456","expiresAt":9999999999000}}
    ;
    const result = try parseTokenGeneric(claude_def, json, std.testing.allocator);
    defer std.testing.allocator.free(result.access_token);
    defer if (result.refresh_token) |rt| std.testing.allocator.free(rt);
    try std.testing.expectEqualStrings("sk-ant-123", result.access_token);
    try std.testing.expectEqualStrings("rt-456", result.refresh_token.?);
    try std.testing.expectEqual(@as(?i64, 9999999999), result.expires_at);
}

test "parseTokenGeneric with codex def" {
    // Real codex shape (TIN-2087): JWT access token, opaque refresh token,
    // no expires_in. Expiry derives from the JWT exp claim.
    const access_jwt = try testMakeJwt(std.testing.allocator, "{\"exp\":9999999999}");
    defer std.testing.allocator.free(access_jwt);
    const json = try std.fmt.allocPrint(std.testing.allocator,
        \\{{"auth_mode":"chatgpt","tokens":{{"access_token":"{s}","refresh_token":"ort-012"}}}}
    , .{access_jwt});
    defer std.testing.allocator.free(json);

    const result = try parseTokenGeneric(codex_def, json, std.testing.allocator);
    defer std.testing.allocator.free(result.access_token);
    defer if (result.refresh_token) |rt| std.testing.allocator.free(rt);
    try std.testing.expectEqualStrings(access_jwt, result.access_token);
    try std.testing.expectEqualStrings("ort-012", result.refresh_token.?);
    try std.testing.expectEqual(@as(?i64, 9999999999), result.expires_at);
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

test "claude_def pins verified Anthropic OAuth constants" {
    // TIN-1817: the Claude OAuth endpoints live on console.anthropic.com,
    // not claude.ai (verified against four independent sources in PR #354).
    // Constants only — never perform live HTTP in tests.
    try std.testing.expectEqualStrings(
        "https://console.anthropic.com/v1/oauth/token",
        claude_def.auth.token_endpoint.?,
    );
    try std.testing.expectEqualStrings(
        "https://console.anthropic.com/oauth/authorize",
        claude_def.auth.authorization_endpoint.?,
    );
    // Anthropic's token endpoint requires client_id, and oauth.refreshToken
    // only sends client_id when the definition carries one (compare codex_def).
    try std.testing.expectEqualStrings(
        "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
        claude_def.auth.client_id.?,
    );
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

    const invalid_target = classifyHttp(mcp_def, 401, null, "Bearer error=\"invalid_target\"");
    switch (invalid_target) {
        .degraded => |reason| try std.testing.expectEqual(types.DegradedReason.audience_mismatch, reason),
        else => return error.TestUnexpectedResult,
    }

    const audience = classifyHttp(mcp_def, 401, null, "Bearer error=\"invalid_token\", error_description=\"audience mismatch\"");
    switch (audience) {
        .degraded => |reason| try std.testing.expectEqual(types.DegradedReason.audience_mismatch, reason),
        else => return error.TestUnexpectedResult,
    }

    const revoked = classifyHttp(mcp_def, 401, null, "Bearer error=\"invalid_token\"");
    switch (revoked) {
        .dead => |reason| try std.testing.expectEqual(types.DeadReason.token_revoked, reason),
        else => return error.TestUnexpectedResult,
    }

    const schema = classifyHttp(mcp_def, 422, null, "tool schema invalid");
    switch (schema) {
        .degraded => |reason| try std.testing.expectEqual(types.DegradedReason.schema_invalid, reason),
        else => return error.TestUnexpectedResult,
    }
}

test "mcp resource metadata capability uses unauthenticated metadata URL" {
    const plan = probePlanForCapability(mcp_def, "metadata").?;
    try std.testing.expectEqual(ProbeTransport.http, plan.transport);
    try std.testing.expectEqualStrings("resource-metadata", plan.capability);
    try std.testing.expectEqualStrings("GET", plan.method);
    try std.testing.expectEqualStrings("{{OMUX_MCP_RESOURCE_METADATA_URL}}", plan.url);
    try std.testing.expectEqual(ProbeAuth.none, plan.auth);
    try std.testing.expect(plan.hint_body);
}

test "mcp resource capability uses bearer resource URL" {
    const plan = probePlanForCapability(mcp_def, "resource-probe").?;
    try std.testing.expectEqual(ProbeTransport.http, plan.transport);
    try std.testing.expectEqualStrings("resource", plan.capability);
    try std.testing.expectEqualStrings("GET", plan.method);
    try std.testing.expectEqualStrings("{{OMUX_MCP_RESOURCE_PROBE_URL}}", plan.url);
    try std.testing.expectEqual(ProbeAuth.bearer, plan.auth);
    try std.testing.expectEqualStrings("www-authenticate", plan.hint_header.?);
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
    try std.testing.expectEqual(types.ActionBudget.cheap_provider, plan.budget);
    try std.testing.expectEqualStrings("www-authenticate", plan.hint_header.?);
    try std.testing.expect(probePlanForCapability(def, "unknown") == null);
}

test "codex capabilities include semantic max and mini command probes" {
    try std.testing.expectEqual(types.ProviderExtensionMode.command_adapter, codex_def.extension_mode);
    try std.testing.expectEqual(types.RepairOwner.upstream_cli_login, codex_def.repair.owner);
    try std.testing.expectEqualStrings("codex", codex_def.runtime.required_binaries[0]);

    try std.testing.expectEqualStrings("codex-max", codex_def.capabilities[0].name);
    const max_plan = probePlanForCapability(codex_def, "gpt-5.5").?;
    try std.testing.expectEqual(ProbeTransport.command, max_plan.transport);
    try std.testing.expectEqualStrings("codex-max", max_plan.capability);
    try std.testing.expectEqualStrings("codex", max_plan.command.?[0]);
    try std.testing.expectEqualStrings("gpt-5.5", max_plan.command.?[6]);
    try std.testing.expectEqual(@as(u32, 120_000), max_plan.timeout_ms);
    try std.testing.expectEqual(types.ActionBudget.spend_provider, max_plan.budget);
    try std.testing.expectEqualStrings("codex-max", probePlanForCapability(codex_def, "max").?.capability);
    try std.testing.expectEqualStrings("codex-mini", codex_def.capabilities[1].name);
    const mini_plan = probePlanForCapability(codex_def, "gpt-5.3-codex-spark").?;
    try std.testing.expectEqual(ProbeTransport.command, mini_plan.transport);
    try std.testing.expectEqualStrings("codex-mini", mini_plan.capability);
    try std.testing.expectEqualStrings("gpt-5.3-codex-spark", mini_plan.command.?[6]);
    try std.testing.expectEqual(types.ActionBudget.spend_provider, mini_plan.budget);
}

test "claude auth status capability uses admitted command probe" {
    const plan = probePlanForCapability(claude_def, "whoami").?;
    try std.testing.expectEqual(ProbeTransport.command, plan.transport);
    try std.testing.expectEqualStrings("auth-status", plan.capability);
    try std.testing.expectEqual(ProbeAuth.none, plan.auth);
    try std.testing.expectEqual(types.ActionBudget.free_command, plan.budget);
    try std.testing.expectEqualStrings("claude", plan.command.?[0]);
    try std.testing.expectEqualStrings("auth", plan.command.?[1]);
    try std.testing.expectEqualStrings("status", plan.command.?[2]);
    try std.testing.expectEqualStrings("--json", plan.command.?[3]);
}

test "claude failure rules classify logged out status as dead" {
    const classification = classifyHttp(claude_def, 400, null, "{\"loggedIn\":false}");
    switch (classification) {
        .dead => |reason| try std.testing.expectEqual(types.DeadReason.token_revoked, reason),
        else => return error.TestUnexpectedResult,
    }
}

test "github identity capability uses admitted user probe" {
    const plan = probePlanForCapability(github_def, "whoami").?;
    try std.testing.expectEqual(ProbeTransport.http, plan.transport);
    try std.testing.expectEqualStrings("identity", plan.capability);
    try std.testing.expectEqualStrings("GET", plan.method);
    try std.testing.expectEqualStrings("https://api.github.com/user", plan.url);
    try std.testing.expectEqual(ProbeAuth.bearer, plan.auth);
    try std.testing.expectEqualStrings("x-ratelimit-remaining", plan.hint_header.?);
}

test "vercel identity capability uses admitted user probe" {
    const plan = probePlanForCapability(vercel_def, "whoami").?;
    try std.testing.expectEqual(ProbeTransport.http, plan.transport);
    try std.testing.expectEqualStrings("identity", plan.capability);
    try std.testing.expectEqualStrings("GET", plan.method);
    try std.testing.expectEqualStrings("https://api.vercel.com/v2/user", plan.url);
    try std.testing.expectEqual(ProbeAuth.bearer, plan.auth);
}

test "vercel failure rules classify forbidden as tier degradation" {
    const classification = classifyHttp(vercel_def, 403, null, null);
    switch (classification) {
        .degraded => |reason| try std.testing.expectEqual(types.DegradedReason.tier_insufficient, reason),
        else => return error.TestUnexpectedResult,
    }
}

test "linear identity capability uses GraphQL viewer probe" {
    const plan = probePlanForCapability(linear_def, "viewer").?;
    try std.testing.expectEqual(ProbeTransport.http, plan.transport);
    try std.testing.expectEqualStrings("identity", plan.capability);
    try std.testing.expectEqualStrings("POST", plan.method);
    try std.testing.expectEqualStrings("https://api.linear.app/graphql", plan.url);
    try std.testing.expect(plan.body != null);
    try std.testing.expect(std.mem.indexOf(u8, plan.body.?, "viewer") != null);
    try std.testing.expectEqualStrings("application/json", plan.content_type.?);
    try std.testing.expect(plan.hint_body);
}

test "linear api key identity capability uses raw authorization probe" {
    const plan = probePlanForCapability(linear_def, "personal-api-key").?;
    try std.testing.expectEqual(ProbeTransport.http, plan.transport);
    try std.testing.expectEqualStrings("identity-api-key", plan.capability);
    try std.testing.expectEqualStrings("POST", plan.method);
    try std.testing.expectEqualStrings("https://api.linear.app/graphql", plan.url);
    try std.testing.expectEqual(ProbeAuth.authorization_header, plan.auth);
    try std.testing.expect(plan.auth_header == null);
    try std.testing.expect(plan.body != null);
    try std.testing.expect(std.mem.indexOf(u8, plan.body.?, "viewer") != null);
    try std.testing.expectEqualStrings("application/json", plan.content_type.?);
    try std.testing.expect(plan.hint_body);
}

test "linear failure rules classify GraphQL errors as degraded" {
    const classification = classifyHttp(linear_def, 200, null, "{\"errors\":[{\"message\":\"Forbidden\"}]}");
    switch (classification) {
        .degraded => |reason| try std.testing.expectEqual(types.DegradedReason.unknown_4xx, reason),
        else => return error.TestUnexpectedResult,
    }
}

test "linear generic OAuth failures stay typed" {
    const revoked = classifyHttp(linear_def, 401, null, null);
    switch (revoked) {
        .dead => |reason| try std.testing.expectEqual(types.DeadReason.token_revoked, reason),
        else => return error.TestUnexpectedResult,
    }

    const limited = classifyHttp(linear_def, 429, 45, null);
    switch (limited) {
        .rate_limited => |rl| {
            try std.testing.expectEqual(@as(u32, 45), rl.retry_after_s);
            try std.testing.expectEqual(types.RateLimitWindow.per_minute, rl.window);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "figma identity capability uses OAuth me probe" {
    const plan = probePlanForCapability(figma_def, "me").?;
    try std.testing.expectEqual(ProbeTransport.http, plan.transport);
    try std.testing.expectEqualStrings("identity", plan.capability);
    try std.testing.expectEqualStrings("GET", plan.method);
    try std.testing.expectEqualStrings("https://api.figma.com/v1/me", plan.url);
    try std.testing.expectEqual(ProbeAuth.bearer, plan.auth);
}

test "figma pat identity capability uses explicit token header" {
    var proof_status: ?[]const u8 = null;
    for (figma_def.capabilities) |capability| {
        if (std.mem.eql(u8, capability.name, "identity-pat")) {
            proof_status = capability.proof_status;
            break;
        }
    }
    try std.testing.expectEqualStrings(proof_local_live, proof_status.?);

    const plan = probePlanForCapability(figma_def, "me-pat").?;
    try std.testing.expectEqual(ProbeTransport.http, plan.transport);
    try std.testing.expectEqualStrings("identity-pat", plan.capability);
    try std.testing.expectEqualStrings("GET", plan.method);
    try std.testing.expectEqualStrings("https://api.figma.com/v1/me", plan.url);
    try std.testing.expectEqual(ProbeAuth.token_header, plan.auth);
    try std.testing.expectEqualStrings("X-Figma-Token", plan.auth_header.?);
}

test "figma plan capability uses resource scoped file metadata probe" {
    var proof_requirement_found = false;
    for (figma_def.capabilities) |capability| {
        if (std.mem.eql(u8, capability.name, "file-metadata-plan")) {
            for (capability.proof_requirements) |requirement| {
                if (std.mem.eql(u8, requirement, "OMUX_FIGMA_PLAN_FILE_KEY")) proof_requirement_found = true;
            }
            break;
        }
    }
    try std.testing.expect(proof_requirement_found);

    const plan = probePlanForCapability(figma_def, "plan-file-meta").?;
    try std.testing.expectEqual(ProbeTransport.http, plan.transport);
    try std.testing.expectEqualStrings("file-metadata-plan", plan.capability);
    try std.testing.expectEqualStrings("GET", plan.method);
    try std.testing.expectEqualStrings("https://api.figma.com/v1/files/{{OMUX_FIGMA_PLAN_FILE_KEY}}/meta", plan.url);
    try std.testing.expectEqual(ProbeAuth.token_header, plan.auth);
    try std.testing.expectEqualStrings("X-Figma-Token", plan.auth_header.?);
}

test "figma failure rules classify forbidden as scope degradation" {
    const classification = classifyHttp(figma_def, 403, null, null);
    switch (classification) {
        .degraded => |reason| try std.testing.expectEqual(types.DegradedReason.scope_insufficient, reason),
        else => return error.TestUnexpectedResult,
    }
}

test "figma failure rules classify missing resource as route degradation" {
    const classification = classifyHttp(figma_def, 404, null, null);
    switch (classification) {
        .degraded => |reason| try std.testing.expectEqual(types.DegradedReason.unknown_4xx, reason),
        else => return error.TestUnexpectedResult,
    }
}

test "flakehub status capability uses admitted command probe" {
    const plan = probePlanForCapability(flakehub_def, "whoami").?;
    try std.testing.expectEqual(ProbeTransport.command, plan.transport);
    try std.testing.expectEqualStrings("status", plan.capability);
    try std.testing.expectEqual(ProbeAuth.none, plan.auth);
    try std.testing.expectEqualStrings("determinate-nixd", plan.command.?[0]);
    try std.testing.expectEqualStrings("status", plan.command.?[1]);
}

test "flakehub failure rules classify logged out status as dead" {
    const classification = classifyHttp(flakehub_def, 200, null, "Logged in: false");
    switch (classification) {
        .dead => |reason| try std.testing.expectEqual(types.DeadReason.token_revoked, reason),
        else => return error.TestUnexpectedResult,
    }
}

test "github failure rules distinguish rate limit from scope degradation" {
    const limited = classifyHttp(github_def, 403, null, " 0 ");
    switch (limited) {
        .rate_limited => |rl| try std.testing.expectEqual(@as(u32, 30), rl.retry_after_s),
        else => return error.TestUnexpectedResult,
    }

    const forbidden = classifyHttp(github_def, 403, null, "1");
    switch (forbidden) {
        .degraded => |reason| try std.testing.expectEqual(types.DegradedReason.scope_insufficient, reason),
        else => return error.TestUnexpectedResult,
    }

    const double_digit_remaining = classifyHttp(github_def, 403, null, "10");
    switch (double_digit_remaining) {
        .degraded => |reason| try std.testing.expectEqual(types.DegradedReason.scope_insufficient, reason),
        else => return error.TestUnexpectedResult,
    }
}

test "github generic OAuth failures stay typed" {
    const revoked = classifyHttp(github_def, 401, null, null);
    switch (revoked) {
        .dead => |reason| try std.testing.expectEqual(types.DeadReason.token_revoked, reason),
        else => return error.TestUnexpectedResult,
    }

    const limited = classifyHttp(github_def, 429, 90, null);
    switch (limited) {
        .rate_limited => |rl| {
            try std.testing.expectEqual(@as(u32, 90), rl.retry_after_s);
            try std.testing.expectEqual(types.RateLimitWindow.per_hour, rl.window);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "classifyCodexExecJsonl success cassette" {
    const jsonl =
        \\{"type":"thread.started","thread_id":"redacted"}
        \\{"type":"turn.started"}
        \\{"type":"item.completed","item":{"type":"agent_message","text":"OMUX_CODEX_SPARK_PROBE"}}
        \\{"type":"turn.completed","usage":{"input_tokens":26656,"cached_input_tokens":3712,"output_tokens":57,"reasoning_output_tokens":43}}
        \\
    ;
    try std.testing.expectEqual(
        types.HttpClassification.success,
        classifyCodexExecJsonl(std.testing.allocator, jsonl).?,
    );
}

test "classifyCodexExecJsonl treats transient reconnect errors before completion as success" {
    const jsonl =
        \\Reading additional input from stdin...
        \\{"type":"thread.started","thread_id":"redacted"}
        \\{"type":"turn.started"}
        \\2026-06-01T19:45:49Z ERROR codex_api::endpoint::responses_websocket: failed to connect to websocket: HTTP error: 405 Method Not Allowed
        \\{"type":"error","message":"Reconnecting... 2/5 (unexpected status 405 Method Not Allowed: {\"detail\":\"Method Not Allowed\"}, url: ws://127.0.0.1:51243/backend-api/responses)"}
        \\2026-06-01T19:45:50Z ERROR codex_api::endpoint::responses_websocket: failed to connect to websocket: HTTP error: 405 Method Not Allowed
        \\{"type":"error","message":"Reconnecting... 5/5 (unexpected status 405 Method Not Allowed: {\"detail\":\"Method Not Allowed\"}, url: ws://127.0.0.1:51243/backend-api/responses)"}
        \\{"type":"item.completed","item":{"type":"agent_message","text":"OMUX_CODEX_MINI_PROBE"}}
        \\{"type":"turn.completed","usage":{"input_tokens":26656,"cached_input_tokens":3712,"output_tokens":57,"reasoning_output_tokens":43}}
        \\
    ;
    try std.testing.expectEqual(
        types.HttpClassification.success,
        classifyCodexExecJsonl(std.testing.allocator, jsonl).?,
    );
}

test "classifyCodexExecJsonl unsupported model cassette" {
    const jsonl =
        \\{"type":"thread.started","thread_id":"redacted"}
        \\{"type":"turn.started"}
        \\{"type":"error","message":"{\"type\":\"error\",\"status\":400,\"error\":{\"type\":\"invalid_request_error\",\"message\":\"The 'gpt-5.1-codex-max' model is not supported when using Codex with a ChatGPT account.\"}}"}
        \\{"type":"turn.failed","error":{"message":"redacted"}}
        \\
    ;
    const classification = classifyCodexExecJsonl(std.testing.allocator, jsonl).?;
    switch (classification) {
        .degraded => |reason| try std.testing.expectEqual(types.DegradedReason.tier_insufficient, reason),
        else => return error.TestUnexpectedResult,
    }
}

test "classifyCodexExecJsonl usage limit as quota exhaustion" {
    const jsonl =
        \\{"type":"thread.started","thread_id":"redacted"}
        \\{"type":"turn.started"}
        \\{"type":"error","message":"You've hit your usage limit. Visit https://chatgpt.com/codex/settings/usage to purchase more credits or try again at Apr 28th, 2099 2:19 PM."}
        \\{"type":"turn.failed","error":{"message":"You've hit your usage limit. Visit https://chatgpt.com/codex/settings/usage to purchase more credits or try again at Apr 28th, 2099 2:19 PM."}}
        \\
    ;
    const classification = classifyCodexExecJsonl(std.testing.allocator, jsonl).?;
    switch (classification) {
        .quota_exhausted => |quota| try std.testing.expect(quota.retry_after_s > 0),
        else => return error.TestUnexpectedResult,
    }
}

test "classifyCodexExecJsonl usage limit without reset as quota exhaustion" {
    const jsonl =
        \\{"type":"error","message":"You've hit your usage limit. Visit https://chatgpt.com/codex/settings/usage to purchase more credits."}
        \\
    ;
    const classification = classifyCodexExecJsonl(std.testing.allocator, jsonl).?;
    switch (classification) {
        .quota_exhausted => |quota| try std.testing.expectEqual(@as(u32, 86_400), quota.retry_after_s),
        else => return error.TestUnexpectedResult,
    }
}

test "classifyCodexAppServerJsonRpc ignores successful turn completion" {
    const jsonl =
        \\{"method":"turn/completed","params":{"turn":{"id":"turn-ok","status":"completed"}}}
        \\
    ;
    try std.testing.expect(classifyCodexAppServerJsonRpc(std.testing.allocator, jsonl) == null);
}

test "classifyCodexAppServerJsonRpc usage limit as quota exhaustion" {
    const jsonl =
        \\{"method":"turn/completed","params":{"turn":{"id":"turn-quota","status":"failed","error":{"type":"usage_limit_reached","message":"The usage limit has been reached","resets_in_seconds":7200}}}}
        \\
    ;
    const classification = classifyCodexAppServerJsonRpc(std.testing.allocator, jsonl).?;
    switch (classification) {
        .quota_exhausted => |quota| try std.testing.expectEqual(@as(u32, 7200), quota.retry_after_s),
        else => return error.TestUnexpectedResult,
    }
}

test "claudeKeychainService derives the TIN-2060 golden vectors" {
    // Two real enrolled accounts, predicted-then-confirmed live against the
    // macOS keychain (docs/spec/provider-proof-claude-credential-store-2026-06-12.md).
    const xoxd = try claudeKeychainService(std.testing.allocator, "/Users/jess/.local/share/oauth-mux/claude/xoxd");
    defer std.testing.allocator.free(xoxd);
    try std.testing.expectEqualStrings("Claude Code-credentials-26ae8e92", xoxd);

    const sulliwood = try claudeKeychainService(std.testing.allocator, "/Users/jess/.local/share/oauth-mux/claude/sulliwood");
    defer std.testing.allocator.free(sulliwood);
    try std.testing.expectEqualStrings("Claude Code-credentials-cec7498b", sulliwood);
}

test "claudeKeychainService distinct dirs never collide on the base service" {
    const derived = try claudeKeychainService(std.testing.allocator, "/tmp/omux-claude-any");
    defer std.testing.allocator.free(derived);
    try std.testing.expect(!std.mem.eql(u8, derived, claude_keychain_service_base));
    try std.testing.expect(std.mem.startsWith(u8, derived, "Claude Code-credentials-"));
    try std.testing.expectEqual(claude_keychain_service_base.len + 1 + 8, derived.len);
}

test "parseTokenGeneric converts millisecond expiresAt to epoch seconds (TIN-2074)" {
    // The live claude store carries 13-digit epoch ms; without conversion
    // the expiry math treats the token as never expiring.
    const raw =
        \\{"claudeAiOauth":{"accessToken":"at-ms-unit","refreshToken":"rt-ms-unit","expiresAt":1781400000000}}
    ;
    const result = try parseTokenGeneric(claude_def, raw, std.testing.allocator);
    defer {
        std.testing.allocator.free(result.access_token);
        if (result.refresh_token) |rt| std.testing.allocator.free(rt);
    }
    try std.testing.expectEqual(@as(?i64, 1781400000), result.expires_at);
}

test "mergeCredentialGeneric preserves the claude store fields the token response does not own (TIN-2074)" {
    // Field inventory verified live: accessToken, expiresAt, rateLimitTier,
    // refreshToken, scopes, subscriptionType.
    const existing =
        \\{"claudeAiOauth":{"accessToken":"at-old","refreshToken":"rt-old","expiresAt":1781300000000,"scopes":["user:inference","user:profile"],"subscriptionType":"max","rateLimitTier":"default_claude_ai"}}
    ;
    const merged = try mergeCredentialGeneric(claude_def, existing, .{
        .access_token = "at-rotated",
        .refresh_token = "rt-rotated",
        .expires_at = 1781400000,
    }, std.testing.allocator);
    defer std.testing.allocator.free(merged);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, merged, .{});
    defer parsed.deinit();
    const oa = parsed.value.object.get("claudeAiOauth").?.object;

    try std.testing.expectEqualStrings("at-rotated", oa.get("accessToken").?.string);
    try std.testing.expectEqualStrings("rt-rotated", oa.get("refreshToken").?.string);
    // Written back in the STORE unit (ms).
    try std.testing.expectEqual(@as(i64, 1781400000000), oa.get("expiresAt").?.integer);
    // Every field the rotation does not own survives with value + order
    // intact (string/int/array fidelity; the live claude store carries no
    // floats, which std.json re-serializes in exponent form).
    try std.testing.expectEqualStrings("max", oa.get("subscriptionType").?.string);
    try std.testing.expectEqualStrings("default_claude_ai", oa.get("rateLimitTier").?.string);
    try std.testing.expectEqual(@as(usize, 2), oa.get("scopes").?.array.items.len);
    try std.testing.expectEqualStrings("user:inference", oa.get("scopes").?.array.items[0].string);
    // Key order preserved: accessToken stays first.
    try std.testing.expectEqualStrings("accessToken", oa.keys()[0]);
}

test "mergeCredentialGeneric preserves codex tokens.id_token and last_refresh (TIN-2074)" {
    const existing =
        \\{"auth_mode":"chatgpt","tokens":{"id_token":"idt-identity-source","access_token":"at-old","refresh_token":"rt-old","account_id":"acct-fixture"},"last_refresh":"2026-06-01T00:00:00Z"}
    ;
    const merged = try mergeCredentialGeneric(codex_def, existing, .{
        .access_token = "at-rotated",
        .refresh_token = "rt-rotated",
        .expires_at = null,
    }, std.testing.allocator);
    defer std.testing.allocator.free(merged);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, merged, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    const tokens = root.get("tokens").?.object;

    try std.testing.expectEqualStrings("at-rotated", tokens.get("access_token").?.string);
    try std.testing.expectEqualStrings("rt-rotated", tokens.get("refresh_token").?.string);
    // The identity source and CLI metadata survive.
    try std.testing.expectEqualStrings("idt-identity-source", tokens.get("id_token").?.string);
    try std.testing.expectEqualStrings("acct-fixture", tokens.get("account_id").?.string);
    try std.testing.expectEqualStrings("chatgpt", root.get("auth_mode").?.string);
    try std.testing.expectEqualStrings("2026-06-01T00:00:00Z", root.get("last_refresh").?.string);
}

test "mergeCredentialGeneric creates missing token paths without disturbing siblings" {
    const existing =
        \\{"operator_note":"hand-managed","tokens":{}}
    ;
    const merged = try mergeCredentialGeneric(codex_def, existing, .{
        .access_token = "at-bootstrap",
        .refresh_token = "rt-bootstrap",
        .expires_at = null,
    }, std.testing.allocator);
    defer std.testing.allocator.free(merged);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, merged, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("hand-managed", parsed.value.object.get("operator_note").?.string);
    try std.testing.expectEqualStrings("at-bootstrap", parsed.value.object.get("tokens").?.object.get("access_token").?.string);
}

test "mergeCredentialGeneric refuses non-object stores (caller falls back to template)" {
    try std.testing.expectError(error.InvalidCharacter, mergeCredentialGeneric(claude_def, "raw-api-key-not-json", .{
        .access_token = "at-x",
    }, std.testing.allocator));
    try std.testing.expectError(error.InvalidCharacter, mergeCredentialGeneric(claude_def, "[1,2]", .{
        .access_token = "at-x",
    }, std.testing.allocator));
}

test "claude bootstrap template writes expiresAt in store milliseconds (TIN-2074)" {
    const built = try buildCredentialGeneric(claude_def, .{
        .access_token = "at-bootstrap",
        .refresh_token = "rt-bootstrap",
        .expires_at = 1781400000,
    }, std.testing.allocator);
    defer std.testing.allocator.free(built);
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, built, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(i64, 1781400000000), parsed.value.object.get("claudeAiOauth").?.object.get("expiresAt").?.integer);
}

test "mergeCredentialGeneric establishes the wrapper for a flat wrapper-declaring store (TIN-2074 re-review)" {
    // A flat store for a wrapper-declaring provider must NOT be refused
    // (that would false-refuse a custom oauth_mux_refresh provider's first
    // refresh, burning the rotated RT each attempt). The wrapper is
    // established and the fresh tokens written into it; the reader resolves
    // the wrapper first, so the new tokens win.
    const flat =
        \\{"accessToken":"at-flat-stale","refreshToken":"rt-flat-stale"}
    ;
    const merged = try mergeCredentialGeneric(claude_def, flat, .{
        .access_token = "at-new",
        .refresh_token = "rt-new",
        .expires_at = 1781400000,
    }, std.testing.allocator);
    defer std.testing.allocator.free(merged);

    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, merged, .{});
    defer parsed.deinit();
    const oa = parsed.value.object.get("claudeAiOauth").?.object;
    try std.testing.expectEqualStrings("at-new", oa.get("accessToken").?.string);
    try std.testing.expectEqualStrings("rt-new", oa.get("refreshToken").?.string);
    try std.testing.expectEqual(@as(i64, 1781400000000), oa.get("expiresAt").?.integer);

    // parseTokenGeneric reads the wrapper, so the fresh tokens win over any
    // inert top-level remnants.
    const reparsed = try parseTokenGeneric(claude_def, merged, std.testing.allocator);
    defer {
        std.testing.allocator.free(reparsed.access_token);
        if (reparsed.refresh_token) |rt| std.testing.allocator.free(rt);
    }
    try std.testing.expectEqualStrings("at-new", reparsed.access_token);
    try std.testing.expectEqualStrings("rt-new", reparsed.refresh_token.?);

    // A non-object wrapper collision still fails closed.
    const collision =
        \\{"claudeAiOauth":"not-an-object"}
    ;
    try std.testing.expectError(error.InvalidCharacter, mergeCredentialGeneric(claude_def, collision, .{
        .access_token = "x",
    }, std.testing.allocator));
}

test "expiryStoreToSeconds guards a seconds-valued store declared milliseconds (TIN-2074 review)" {
    // 13-digit ms -> seconds.
    try std.testing.expectEqual(@as(i64, 1781400000), expiryStoreToSeconds(.milliseconds, 1781400000000));
    // A value too small to be epoch-ms is left alone, not divided into 1970.
    try std.testing.expectEqual(@as(i64, 1781400000), expiryStoreToSeconds(.milliseconds, 1781400000));
    // seconds unit passes through.
    try std.testing.expectEqual(@as(i64, 1781400000), expiryStoreToSeconds(.seconds, 1781400000));
}

test "expirySecondsToStore saturates instead of overflowing i64 (TIN-2074 review)" {
    // A normal value round-trips.
    try std.testing.expectEqual(@as(i64, 1781400000000), expirySecondsToStore(.milliseconds, 1781400000));
    // An absurd endpoint expires_in must not panic the writeback under the
    // repair flock — saturate to i64 max.
    try std.testing.expectEqual(std.math.maxInt(i64), expirySecondsToStore(.milliseconds, std.math.maxInt(i64)));
    try std.testing.expectEqual(@as(i64, 1781400000), expirySecondsToStore(.seconds, 1781400000));
}

// Helper for the tests below: assemble a JWT "header.payload.sig" whose
// payload is the given JSON (base64url-no-pad), with throwaway header/sig.
fn testMakeJwt(allocator: std.mem.Allocator, payload_json: []const u8) ![]const u8 {
    const enc = std.base64.url_safe_no_pad.Encoder;
    const buf = try allocator.alloc(u8, enc.calcSize(payload_json.len));
    defer allocator.free(buf);
    const payload_b64 = enc.encode(buf, payload_json);
    return std.fmt.allocPrint(allocator, "eyJhbGciOiJSUzI1NiJ9.{s}.sig", .{payload_b64});
}

test "jwtExpSeconds reads the exp claim from a JWT (TIN-2087)" {
    const jwt = try testMakeJwt(std.testing.allocator, "{\"exp\":1781400000,\"sub\":\"x\"}");
    defer std.testing.allocator.free(jwt);
    try std.testing.expectEqual(@as(?i64, 1781400000), jwtExpSeconds(jwt, std.testing.allocator));
}

test "jwtExpSeconds returns null on malformation rather than failing (TIN-2087)" {
    try std.testing.expectEqual(@as(?i64, null), jwtExpSeconds("not-a-jwt", std.testing.allocator));
    try std.testing.expectEqual(@as(?i64, null), jwtExpSeconds("only.two", std.testing.allocator));
    try std.testing.expectEqual(@as(?i64, null), jwtExpSeconds("h..s", std.testing.allocator));
    // Valid base64url payload but no exp claim.
    const no_exp = try testMakeJwt(std.testing.allocator, "{\"sub\":\"x\"}");
    defer std.testing.allocator.free(no_exp);
    try std.testing.expectEqual(@as(?i64, null), jwtExpSeconds(no_exp, std.testing.allocator));

    // A finite-but-out-of-i64-range float exp must yield null, never panic
    // in ReleaseSafe (review finding). Integer-overflow exp -> number_string
    // -> null already; this covers the .float branch's range guard.
    const huge_float = try testMakeJwt(std.testing.allocator, "{\"exp\":1e30}");
    defer std.testing.allocator.free(huge_float);
    try std.testing.expectEqual(@as(?i64, null), jwtExpSeconds(huge_float, std.testing.allocator));
    const neg_huge = try testMakeJwt(std.testing.allocator, "{\"exp\":-1e30}");
    defer std.testing.allocator.free(neg_huge);
    try std.testing.expectEqual(@as(?i64, null), jwtExpSeconds(neg_huge, std.testing.allocator));
    // A normal float exp still truncates to seconds.
    const float_exp = try testMakeJwt(std.testing.allocator, "{\"exp\":1781400000.5}");
    defer std.testing.allocator.free(float_exp);
    try std.testing.expectEqual(@as(?i64, 1781400000), jwtExpSeconds(float_exp, std.testing.allocator));
}

test "parseTokenGeneric derives codex expiry from the access-token JWT exp (TIN-2087)" {
    const allocator = std.testing.allocator;
    const access_jwt = try testMakeJwt(allocator, "{\"exp\":1781400000}");
    defer allocator.free(access_jwt);

    // Real codex auth.json shape: JWT access token, opaque refresh token,
    // no expires_in / expires_at anywhere.
    const raw = try std.fmt.allocPrint(allocator,
        \\{{"auth_mode":"chatgpt","OPENAI_API_KEY":null,"tokens":{{"access_token":"{s}","refresh_token":"rt.1.opaque","id_token":"idt","account_id":"acct"}},"last_refresh":"2026-06-03T01:51:47Z"}}
    , .{access_jwt});
    defer allocator.free(raw);

    const result = try parseTokenGeneric(codex_def, raw, allocator);
    defer {
        allocator.free(result.access_token);
        if (result.refresh_token) |rt| allocator.free(rt);
    }
    try std.testing.expectEqual(@as(?i64, 1781400000), result.expires_at);
    try std.testing.expectEqualStrings("rt.1.opaque", result.refresh_token.?);
}

test "parseTokenGeneric leaves codex expiry null when the access token is not a readable JWT (TIN-2087)" {
    const allocator = std.testing.allocator;
    const raw =
        \\{"auth_mode":"chatgpt","tokens":{"access_token":"opaque-not-a-jwt","refresh_token":"rt.1.x"}}
    ;
    const result = try parseTokenGeneric(codex_def, raw, allocator);
    defer {
        allocator.free(result.access_token);
        if (result.refresh_token) |rt| allocator.free(rt);
    }
    try std.testing.expectEqual(@as(?i64, null), result.expires_at);
}

test "identityClaimFromCredential resolves codex tokens.account_id (TIN-2043)" {
    const raw =
        \\{"auth_mode":"chatgpt","tokens":{"access_token":"at","refresh_token":"rt","account_id":"acct-uuid-xyz"}}
    ;
    const id = (try identityClaimFromCredential(codex_def, raw, std.testing.allocator)).?;
    defer std.testing.allocator.free(id);
    try std.testing.expectEqualStrings("acct-uuid-xyz", id);

    // Absent account_id -> null (caller must not key a guard on a missing id).
    const no_id =
        \\{"auth_mode":"chatgpt","tokens":{"access_token":"at","refresh_token":"rt"}}
    ;
    try std.testing.expectEqual(@as(?[]u8, null), try identityClaimFromCredential(codex_def, no_id, std.testing.allocator));

    // A provider that declares no identity_claim_path -> null (e.g. claude).
    const claude_raw =
        \\{"claudeAiOauth":{"accessToken":"at","refreshToken":"rt"}}
    ;
    try std.testing.expectEqual(@as(?[]u8, null), try identityClaimFromCredential(claude_def, claude_raw, std.testing.allocator));
}

test "claude/codex builtins declare the proactive_refresh grant but still require opt-in (TIN-2057)" {
    // The grant flip: both providers SUPPORT proactive refresh now.
    try std.testing.expect(claude_def.repair.proactive_refresh == .oauth_refresh_token);
    try std.testing.expect(codex_def.repair.proactive_refresh == .oauth_refresh_token);
    // Ownership stays upstream_cli_login, so secret.writebackPlan still admits a
    // refresh ONLY for an account that also sets allow_proactive_refresh — the
    // grant is provider-CAPABILITY, not auto-enable. (The admission logic itself
    // is covered by the writebackPlan tests in secret.zig.)
    try std.testing.expect(claude_def.repair.owner == .upstream_cli_login);
    try std.testing.expect(codex_def.repair.owner == .upstream_cli_login);
    // Both observed providers rotate single-use refresh tokens. A successful
    // response without a new token cannot silently reuse the submitted one.
    try std.testing.expect(
        claude_def.repair.refresh_token_response == .require_rotated,
    );
    try std.testing.expect(
        codex_def.repair.refresh_token_response == .require_rotated,
    );
}

test "claude_def declares the unified rate-limit family, not the x-ratelimit placeholders (TIN-2722)" {
    // Point 1: the observed truth replaces the bogus x-ratelimit-* placeholders.
    try std.testing.expect(claude_def.rate_limits.unified != null);
    try std.testing.expectEqualStrings("anthropic-ratelimit-unified", claude_def.rate_limits.unified.?.prefix);
    try std.testing.expectEqualStrings("5h", claude_def.rate_limits.unified.?.five_hour_segment);
    try std.testing.expectEqualStrings("7d", claude_def.rate_limits.unified.?.seven_day_segment);
    // The either/or invariant: unified providers carry no legacy remaining/reset pair.
    try std.testing.expect(claude_def.rate_limits.remaining_header == null);
    try std.testing.expect(claude_def.rate_limits.reset_header == null);
    // Codex still rides the legacy pair — the unified change must not touch it.
    try std.testing.expect(codex_def.rate_limits.unified == null);
    try std.testing.expect(codex_def.rate_limits.remaining_header != null);
}

test "foldUnifiedRateLimit parses the E2 haiku 200 header block verbatim (TIN-2722)" {
    // (a) Copied verbatim from test/evidence/quota-observation/
    //   claude-20260709T220705Z/808e810325f2/micro-spend-haiku-response-headers.txt
    // (the canonical 12-header 200). Folded with the scheme claude_def actually
    // ships, so this proves the wired config field is load-bearing.
    const headers = [_]std.http.Header{
        .{ .name = "anthropic-ratelimit-unified-status", .value = "allowed" },
        .{ .name = "anthropic-ratelimit-unified-5h-status", .value = "allowed" },
        .{ .name = "anthropic-ratelimit-unified-5h-reset", .value = "1783652400" },
        .{ .name = "anthropic-ratelimit-unified-5h-utilization", .value = "0.0" },
        .{ .name = "anthropic-ratelimit-unified-7d-status", .value = "allowed" },
        .{ .name = "anthropic-ratelimit-unified-7d-reset", .value = "1783879200" },
        .{ .name = "anthropic-ratelimit-unified-7d-utilization", .value = "0.0" },
        .{ .name = "anthropic-ratelimit-unified-representative-claim", .value = "five_hour" },
        .{ .name = "anthropic-ratelimit-unified-fallback-percentage", .value = "0.5" },
        .{ .name = "anthropic-ratelimit-unified-reset", .value = "1783652400" },
        .{ .name = "anthropic-ratelimit-unified-overage-disabled-reason", .value = "out_of_credits" },
        .{ .name = "anthropic-ratelimit-unified-overage-status", .value = "rejected" },
    };
    const parsed = foldUnifiedRateLimit(claude_def.rate_limits.unified.?, &headers);

    try std.testing.expectEqualStrings("allowed", parsed.overall_status.?);
    try std.testing.expectEqualStrings("allowed", parsed.five_h.status.?);
    try std.testing.expectEqual(@as(i64, 1783652400), parsed.five_h.reset_s.?);
    try std.testing.expectEqual(@as(f64, 0.0), parsed.five_h.utilization.?);
    try std.testing.expectEqualStrings("allowed", parsed.seven_d.status.?);
    try std.testing.expectEqual(@as(i64, 1783879200), parsed.seven_d.reset_s.?);
    try std.testing.expectEqual(@as(f64, 0.0), parsed.seven_d.utilization.?);
    try std.testing.expectEqualStrings("five_hour", parsed.representative.?);
    try std.testing.expectEqual(@as(i64, 1783652400), parsed.representative_reset_s.?);
    try std.testing.expectEqual(@as(f64, 0.5), parsed.fallback_percentage.?);
    try std.testing.expectEqualStrings("out_of_credits", parsed.overage_disabled_reason.?);
    try std.testing.expectEqualStrings("rejected", parsed.overage_status.?);
}

test "claude 429 with only x-should-retry classifies as the weak rate_limited class (TIN-2722)" {
    // (b) The E2 fable/opus 429 carried x-should-retry:true and NO ratelimit
    // headers, NO retry-after. The generic 429 arm defaults to a 30s burst
    // window → the weaker rate_limited class (DOR under-claim rule), never
    // quota_exhausted. No provider rule is needed; this pins that behaviour.
    const classification = classifyHttp(
        claude_def,
        429,
        null,
        "{\"error\":{\"message\":\"Error\",\"type\":\"rate_limit_error\"}}",
    );
    switch (classification) {
        .rate_limited => |rl| {
            try std.testing.expectEqual(@as(u32, 30), rl.retry_after_s);
            try std.testing.expectEqual(types.RateLimitWindow.per_minute, rl.window);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "claude 404 model-not-found is a non-quota classification (TIN-2722)" {
    // (c) The E2 unknown-model 404 body names the model with type
    // not_found_error. It must NOT read as a quota/rate-limit state — the
    // generic 4xx arm yields degraded:unknown_4xx (non-quota), cleanly distinct
    // from the 429 path by status alone. Landing on any other arm (incl. a
    // quota arm) fails the switch.
    const classification = classifyHttp(
        claude_def,
        404,
        null,
        "{\"error\":{\"message\":\"model: claude-omux-e2-unknown-model-probe\",\"type\":\"not_found_error\"}}",
    );
    switch (classification) {
        .degraded => |reason| try std.testing.expectEqual(types.DegradedReason.unknown_4xx, reason),
        else => return error.TestUnexpectedResult,
    }
}

test "foldUnifiedRateLimit yields null on malformed numerics without panicking (TIN-2722)" {
    // (d) Bad float/int → null for that field; present strings still captured;
    // untouched fields stay null (absence is data). Nothing panics.
    const headers = [_]std.http.Header{
        .{ .name = "anthropic-ratelimit-unified-status", .value = "allowed_warning" },
        .{ .name = "anthropic-ratelimit-unified-5h-utilization", .value = "not-a-float" },
        .{ .name = "anthropic-ratelimit-unified-5h-reset", .value = "" },
        .{ .name = "anthropic-ratelimit-unified-7d-reset", .value = "12x34" },
        .{ .name = "anthropic-ratelimit-unified-fallback-percentage", .value = "NaNaN" },
    };
    const parsed = foldUnifiedRateLimit(.{}, &headers);
    try std.testing.expectEqualStrings("allowed_warning", parsed.overall_status.?);
    try std.testing.expect(parsed.five_h.utilization == null);
    try std.testing.expect(parsed.five_h.reset_s == null);
    try std.testing.expect(parsed.seven_d.reset_s == null);
    try std.testing.expect(parsed.fallback_percentage == null);
    // Never-sent fields are null, not fabricated.
    try std.testing.expect(parsed.overage_status == null);
    try std.testing.expect(parsed.seven_d.status == null);
    try std.testing.expect(parsed.representative == null);
}

test "foldUnifiedRateLimit rejects non-finite/out-of-range floats and negative epochs (TIN-2722)" {
    // (d2) std.fmt.parseFloat ACCEPTS "NaN"/"inf"/"Infinity"/"1e999"(→+inf) and
    // parseInt accepts "-1"; none are a valid utilization fraction or an
    // absolute epoch, so each must fold to null (contract: malformed → null).
    // A NaN/inf utilization (NaN compares false everywhere) or a negative reset
    // could silently mis-route a future quota consumer — this pins them out.
    const nonfinite = [_][]const u8{ "NaN", "inf", "-inf", "Infinity", "1e999", "-1e999" };
    for (nonfinite) |bad| {
        const headers = [_]std.http.Header{
            .{ .name = "anthropic-ratelimit-unified-5h-utilization", .value = bad },
            .{ .name = "anthropic-ratelimit-unified-fallback-percentage", .value = bad },
        };
        const parsed = foldUnifiedRateLimit(.{}, &headers);
        try std.testing.expect(parsed.five_h.utilization == null);
        try std.testing.expect(parsed.fallback_percentage == null);
    }

    // Out-of-range finite fractions (>1 or <0) are malformed for a 0..1 field.
    const out_of_range = [_][]const u8{ "1.5", "-0.1", "2", "100" };
    for (out_of_range) |bad| {
        const headers = [_]std.http.Header{
            .{ .name = "anthropic-ratelimit-unified-7d-utilization", .value = bad },
        };
        const parsed = foldUnifiedRateLimit(.{}, &headers);
        try std.testing.expect(parsed.seven_d.utilization == null);
    }

    // Negative epochs are nonsense reset instants → null (both per-window and
    // the representative reset).
    const neg_headers = [_]std.http.Header{
        .{ .name = "anthropic-ratelimit-unified-5h-reset", .value = "-1" },
        .{ .name = "anthropic-ratelimit-unified-reset", .value = "-1783652400" },
    };
    const neg = foldUnifiedRateLimit(.{}, &neg_headers);
    try std.testing.expect(neg.five_h.reset_s == null);
    try std.testing.expect(neg.representative_reset_s == null);

    // Boundary sanity: the documented endpoints 0.0/1.0 and epoch 0 still parse.
    const ok_headers = [_]std.http.Header{
        .{ .name = "anthropic-ratelimit-unified-5h-utilization", .value = "1.0" },
        .{ .name = "anthropic-ratelimit-unified-7d-utilization", .value = "0.0" },
        .{ .name = "anthropic-ratelimit-unified-5h-reset", .value = "0" },
    };
    const ok = foldUnifiedRateLimit(.{}, &ok_headers);
    try std.testing.expectEqual(@as(f64, 1.0), ok.five_h.utilization.?);
    try std.testing.expectEqual(@as(f64, 0.0), ok.seven_d.utilization.?);
    try std.testing.expectEqual(@as(i64, 0), ok.five_h.reset_s.?);
}

test "claude model-class capabilities match real ids and reject the unknown-model probe (TIN-2722)" {
    // (e) alias matching: the observed ids resolve to their class; the fabricated
    // probe id used for the 404 capture matches nothing.
    const Case = struct { model: []const u8, class: ?[]const u8 };
    const cases = [_]Case{
        .{ .model = "claude-fable-5", .class = "fable" },
        .{ .model = "claude-opus-4-8", .class = "opus" },
        .{ .model = "claude-haiku-4-5-20251001", .class = "haiku" },
        .{ .model = "claude-sonnet-5", .class = "sonnet" },
        .{ .model = "claude-omux-e2-unknown-model-probe", .class = null },
    };
    for (cases) |case| {
        var matched: ?CapabilityDefinition = null;
        for (claude_capabilities) |cap| {
            if (capabilityMatches(cap, case.model)) {
                matched = cap;
                break;
            }
        }
        if (case.class) |expected| {
            try std.testing.expect(matched != null);
            try std.testing.expectEqualStrings(expected, matched.?.name);
        } else {
            try std.testing.expect(matched == null);
        }
    }

    // The three observed classes point proof_status at the committed capture;
    // sonnet (declared-not-observed) carries the lower needs-operator marker.
    for (claude_capabilities) |cap| {
        if (std.mem.eql(u8, cap.name, "haiku") or
            std.mem.eql(u8, cap.name, "fable") or
            std.mem.eql(u8, cap.name, "opus"))
        {
            try std.testing.expectEqualStrings(claude_quota_fixture_dir, cap.proof_status);
            try std.testing.expect(cap.probe == null);
        } else if (std.mem.eql(u8, cap.name, "sonnet")) {
            try std.testing.expectEqualStrings(proof_needs_operator, cap.proof_status);
            try std.testing.expect(cap.probe == null);
        }
    }
}
