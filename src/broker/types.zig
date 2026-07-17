//! Broker public types. Surface-v1 compatibility wrappers remain distinct
//! from the active managed-harness surface-v2 handle types.
//! Anchor: docs/spec/broker-mcp-contract-2026-05-03.md §2.

const std = @import("std");
const identifiers = @import("identifiers.zig");

/// Shipped broker MCP surface-v1 compatibility version. This is not the
/// separately planned managed-harness surface-v2 version.
pub const surface_version: u32 = 1;

/// Active managed-harness surface-v2 opaque handle types.
pub const SessionHandle = identifiers.SessionHandle;
pub const AccountHandle = identifiers.AccountHandle;
pub const RouteHandle = identifiers.RouteHandle;

/// Internal and surface-v1 compatibility parser types.
pub const AccountKey = identifiers.AccountKey;
pub const LegacySessionId = identifiers.LegacySessionId;
pub const LegacyCredentialHandle = identifiers.LegacyCredentialHandle;

/// The claim ladder. Lower = weaker; the product target is `next_turn_seamless`.
/// `mid_turn_seamless` is a stretch; `cross_session_thread_continuity` is
/// honestly labelled as may-not-exist.
pub const ClaimLevel = enum {
    unmuxed,
    prepared_fallback,
    broker_owned,
    next_turn_seamless,
    mid_turn_seamless,
    cross_session_thread_continuity,

    pub fn toString(self: ClaimLevel) []const u8 {
        return switch (self) {
            .unmuxed => "unmuxed",
            .prepared_fallback => "prepared_fallback",
            .broker_owned => "broker_owned",
            .next_turn_seamless => "next_turn_seamless",
            .mid_turn_seamless => "mid_turn_seamless",
            .cross_session_thread_continuity => "cross_session_thread_continuity",
        };
    }
};

/// Surface-v1 compatibility wrapper for a `provider:account` identity.
/// Owned by the broker config; not an active-v2 `AccountHandle`.
pub const AccountId = struct {
    text: []const u8, // e.g. "codex:max-1"

    pub fn parse(text: []const u8) identifiers.ParseError!AccountId {
        const key = try AccountKey.parse(text);
        return .{ .text = key.text };
    }
};

/// Surface-v1 compatibility wrapper for the session id returned by the
/// broker MCP handshake; not an active-v2 `SessionHandle`.
pub const SessionId = struct {
    text: []const u8,

    pub fn parse(text: []const u8) identifiers.ParseError!SessionId {
        const id = try LegacySessionId.parse(text);
        return .{ .text = id.text };
    }
};

/// Surface-v1 compatibility wrapper returned by `account/select`; not an
/// active-v2 account or route handle. Resolves to concrete token bytes only
/// via `credential/materialize` (kept local when possible; never crosses the
/// wire).
pub const CredentialHandle = struct {
    text: []const u8,

    pub fn parse(text: []const u8) identifiers.ParseError!CredentialHandle {
        const handle = try LegacyCredentialHandle.parse(text);
        return .{ .text = handle.text };
    }
};

/// Quota observation kinds. Matches broker spec §2.4 `quota/observe`.
pub const QuotaKind = enum {
    ok,
    rate_limited,
    quota_exhausted,
    auth_unauthorized,
    tier_insufficient,
    provider_5xx,
};

/// Refresh trigger reasons. Matches broker spec §2.3 `credential/refresh`.
pub const RefreshTrigger = enum {
    proactive_exp,
    unauthorized_401,
    external_event,
};

/// Typed reasons for `account/swap` and the underlying state machine.
pub const SwapReason = enum {
    quota_exhausted,
    rate_limited_long,
    auth_unauthorized,
    operator_requested,
};

/// Refresh failure classification from the provider's token endpoint.
/// Mirrors codex `classify_refresh_token_failure` (manager.rs L850–871).
pub const RefreshFailure = enum {
    refresh_token_expired,
    refresh_token_reused,
    refresh_token_invalidated,
    provider_5xx,
    policy_denied,
    other,
};

/// Session-wide policy (from `policy/get`).
pub const Policy = struct {
    allowed_budgets: []const []const u8 = &.{ "free_local", "free_command" },
    allow_interactive: bool = false,
    allow_mutating: bool = false,
    spend_admitted_for_session: bool = false,
};

/// All errors the broker surfaces to its callers. Out-of-band protocol
/// errors are JSON-RPC errors; these are semantic ones.
pub const BrokerError = error{
    NotImplemented,
    NoAccountSelectable,
    AccountNotFound,
    SessionNotFound,
    PolicyDenied,
    InvalidParams,
    InvalidShape,
    ParseError,
    RefreshFailed,
    /// Adapter requested a credential shape this account/backend cannot
    /// produce (e.g. chatgpt_auth_tokens for a non-codex account).
    UnsupportedShape,
    /// Secret backend or file unavailable when materializing.
    SecretUnavailable,
    OutOfMemory,
};

/// Codex-shaped token tuple per Codex app-server's `chatgptAuthTokens`
/// login mode (see codex-rs/login/src/auth/storage.rs auth.json).
/// All fields are owned by the caller's allocator.
pub const ChatgptAuthTokens = struct {
    access_token: []const u8,
    account_id: []const u8,
    plan_type: ?[]const u8 = null,
    fedramp: bool = false,

    pub fn deinit(self: ChatgptAuthTokens, allocator: std.mem.Allocator) void {
        allocator.free(self.access_token);
        allocator.free(self.account_id);
        if (self.plan_type) |s| allocator.free(s);
    }
};

/// Plumb-through resolver. The broker is config-agnostic; the wiring
/// code (main.zig) provides this implementation against the loaded
/// Config + secret backends.
pub const CredentialMaterializer = struct {
    ctx: *anyopaque,
    /// Materialize a chatgpt_auth_tokens tuple for the given
    /// `provider:account`. The returned struct owns memory in the
    /// caller's allocator; caller must call `.deinit(allocator)`.
    materialize_chatgpt: *const fn (
        ctx: *anyopaque,
        allocator: std.mem.Allocator,
        account_id: []const u8,
    ) BrokerError!ChatgptAuthTokens,
};

test "ClaimLevel.toString round-trip subset" {
    try std.testing.expectEqualStrings("broker_owned", ClaimLevel.broker_owned.toString());
    try std.testing.expectEqualStrings("next_turn_seamless", ClaimLevel.next_turn_seamless.toString());
}
