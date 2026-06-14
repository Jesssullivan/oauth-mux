//! Claude (Claude Code) stable-identity labeler — greenfield, the producer half of
//! TIN-1822. It turns a Claude account profile (the `oauthAccount` block of
//! `<CLAUDE_CONFIG_DIR>/.claude.json`, or `~/.claude.json`) into a stable,
//! non-secret `ClaudeIdentity` whose `account_id_hash` feeds the identity graph
//! (`identity_graph.zig`, its `IdentityKey.hash`).
//!
//! Canonical key: `oauthAccount.accountUuid` (server-issued, durable per-account
//! UUID; stable across re-logins, distinct across accounts). NOT `userID` (a
//! 64-char per-INSTALL anonymous hash that collides across accounts in one config
//! dir and fragments one account across installs) and NOT `organizationUuid` (a
//! many-accounts-to-one billing/rate-limit pool — context-dependent, never the
//! per-account key, never composited into it). This mirrors Codex exactly:
//! Codex hashes `chatgpt_account_id`, Claude hashes `accountUuid`, both via the
//! same `sha256_12hex` (first 6 bytes of SHA-256 → 12 lowercase hex).
//!
//! Fail-safe: any empty/malformed input, absent `oauthAccount`, or absent
//! `accountUuid` yields `present=false` with `account_id_hash=null` — so the graph
//! keys the slot as an OPAQUE per-(provider,account) identity (the honest
//! representation of "authenticated-but-unprofiled"), instead of coalescing all
//! profile-less Claude accounts under one hashed-empty-string key.
//!
//! Redaction (enforced structurally): the struct holds NO raw UUID, email, or
//! token — only `sha256_12hex` hashes, a masked email hint (`j***@domain`), and an
//! `org_display` that is flagged identifying and must be gated to operator-only,
//! non-agent surfaces.
//!
//! OWNERSHIP / LIFETIME: a `ClaudeIdentity` OWNS its slices and frees them in
//! `deinit`. The identity graph's `AccountSlot` BORROWS `account_id_hash`, so a
//! `ClaudeIdentity` MUST outlive any `AccountSlot` that borrows it — do not
//! `deinit` it until graph analysis is done (or `dupe` the hash into the slot's
//! arena). `stable_label`/`org_id_hash`/`org_display` are producer-local
//! diagnostics — only `account_id_hash` (and a masked `email_hint`) ever crosses
//! into the graph.
//!
//! Self-contained: `std` only, NO `@import` of existing `src` (the `sha256_12hex`,
//! `maskEmail`, `nonEmpty` helpers are re-derived locally to match the Codex ones
//! byte-for-byte). Pure (no I/O — the caller reads the file and passes the bytes).
//! `std.testing.allocator`-clean. Zig 0.14.1.

const std = @import("std");

pub const account_id_source_label: []const u8 = "oauthAccount.accountUuid";

/// Parse result. `present` is true only when a usable `accountUuid` was found.
/// `reason` is a static string literal (never owned). All `?[]const u8` payloads
/// are allocator-OWNED when non-null and freed by `deinit`.
pub const ClaudeIdentity = struct {
    present: bool = false,
    /// One of: "input_empty", "json_invalid", "oauth_account_missing",
    /// "account_uuid_missing", "identity_present". Static literal.
    reason: []const u8 = "input_empty",
    /// Static provenance for the canonical id when present, else null.
    account_id_source: ?[]const u8 = null,
    /// sha256_12hex(accountUuid). THIS is what the identity graph consumes as
    /// `IdentityKey.hash`. OWNED. null when no stable identity (graph keys opaque).
    account_id_hash: ?[]const u8 = null,
    /// sha256_12hex(organizationUuid): a SEPARATE hashed grouping dimension, NOT a
    /// graph input. OWNED. null when org absent/empty (never a hash of "").
    org_id_hash: ?[]const u8 = null,
    /// Hashed, non-secret composite label for logs/UX: `claude:<org12|noorg>:<acct12>`.
    /// Producer-local diagnostic, not a graph input. OWNED. null iff no identity.
    stable_label: ?[]const u8 = null,
    /// Masked email "j***@domain" — never the raw local part. OWNED. null when absent.
    email_hint: ?[]const u8 = null,
    /// organizationName — IDENTIFYING human display for OPERATOR-ONLY surfaces;
    /// must NOT be emitted on agent/MCP surfaces. OWNED. null when absent.
    org_display: ?[]const u8 = null,

    /// Frees every owned slice. Safe on the zero/unknown value (all nulls).
    pub fn deinit(self: ClaudeIdentity, allocator: std.mem.Allocator) void {
        if (self.account_id_hash) |v| allocator.free(v);
        if (self.org_id_hash) |v| allocator.free(v);
        if (self.stable_label) |v| allocator.free(v);
        if (self.email_hint) |v| allocator.free(v);
        if (self.org_display) |v| allocator.free(v);
    }
};

// ── Local helpers (re-derived to match the Codex ones; no @import of src) ─────

/// Lowercase hex of the first 6 bytes of SHA-256 → 12 chars. Matches the repo's
/// `shortSha256HexAlloc` (golden: sha256_12hex("acct-test") == "660d25a9d7ee").
fn sha256_12hex(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(value, &digest, .{});
    const hex = "0123456789abcdef";
    const out = try allocator.alloc(u8, 12);
    for (digest[0..6], 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0x0f];
    }
    return out;
}

fn nonEmpty(s: ?[]const u8) ?[]const u8 {
    if (s) |v| {
        if (v.len > 0) return v;
    }
    return null;
}

/// "jess@sulliwood.org" → "j***@sulliwood.org". Returns null for a non-email
/// (no '@', or empty local part) so a malformed value never produces a hint.
fn maskEmail(allocator: std.mem.Allocator, email: []const u8) !?[]u8 {
    const at = std.mem.indexOfScalar(u8, email, '@') orelse return null;
    if (at == 0) return null; // empty local part
    const domain = email[at..]; // includes '@'
    // Keep a single-char hint for an ASCII local part (`j***@domain`). For a
    // non-ASCII first byte, `{c}` would emit one partial UTF-8 byte — invalid
    // encoding that mojibakes or fails re-encode on a JSON/MCP surface — so mask
    // the whole local part instead (also the more conservative redaction).
    if (std.ascii.isAscii(email[0])) {
        return try std.fmt.allocPrint(allocator, "{c}***{s}", .{ email[0], domain });
    }
    return try std.fmt.allocPrint(allocator, "***{s}", .{domain});
}

fn buildStableLabel(allocator: std.mem.Allocator, acct12: []const u8, org12: ?[]const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "claude:{s}:{s}", .{ org12 orelse "noorg", acct12 });
}

// ── Parser ───────────────────────────────────────────────────────────────────

const OAuthAccount = struct {
    accountUuid: ?[]const u8 = null,
    organizationUuid: ?[]const u8 = null,
    organizationName: ?[]const u8 = null,
    emailAddress: ?[]const u8 = null,
};

const RootJson = struct {
    oauthAccount: ?OAuthAccount = null,
};

/// Parse a Claude account profile JSON (the contents of `.claude.json`) into a
/// stable identity. Pure + fail-safe: never crashes; an unusable input returns a
/// `present=false` value with `account_id_hash=null`.
pub fn parseClaudeIdentity(allocator: std.mem.Allocator, raw: []const u8) !ClaudeIdentity {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return .{ .present = false, .reason = "input_empty" };

    const parsed = std.json.parseFromSlice(RootJson, allocator, raw, .{
        .ignore_unknown_fields = true,
    }) catch |e| switch (e) {
        // A transient allocator failure must not masquerade as malformed input
        // (never-halt callers retry OOM, but treat json_invalid as terminal).
        error.OutOfMemory => return e,
        else => return .{ .present = false, .reason = "json_invalid" },
    };
    defer parsed.deinit();

    const oauth = parsed.value.oauthAccount orelse
        return .{ .present = false, .reason = "oauth_account_missing" };
    const acct_uuid = nonEmpty(oauth.accountUuid) orelse
        return .{ .present = false, .reason = "account_uuid_missing" };

    var result = ClaudeIdentity{
        .present = true,
        .reason = "identity_present",
        .account_id_source = account_id_source_label,
    };
    errdefer result.deinit(allocator);

    result.account_id_hash = try sha256_12hex(allocator, acct_uuid);
    if (nonEmpty(oauth.organizationUuid)) |org_uuid| {
        result.org_id_hash = try sha256_12hex(allocator, org_uuid);
    }
    if (nonEmpty(oauth.organizationName)) |org_name| {
        result.org_display = try allocator.dupe(u8, org_name);
    }
    if (nonEmpty(oauth.emailAddress)) |email| {
        result.email_hint = try maskEmail(allocator, email);
    }
    result.stable_label = try buildStableLabel(allocator, result.account_id_hash.?, result.org_id_hash);

    return result;
}
