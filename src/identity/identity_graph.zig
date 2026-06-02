//! Identity graph — greenfield, provider-agnostic read-only ANALYSIS over the
//! account inventory (TIN-1822 / A.6). It answers the questions the mux needs to
//! keep its never-halt promise honest:
//!
//!   * Which config slots are actually the SAME underlying account? (group by
//!     `account_id_hash` = sha256_12hex of the provider's account-id claim).
//!   * What is the TRUE redundancy depth for a capability — counting DISTINCT
//!     LIVE identities, not slots — so a duplicate slot is never mistaken for
//!     real failover (the max-2==max-1 trap).
//!   * Is a capability still afloat? (>=1 distinct live identity remains.)
//!   * Is retiring a slot safe, per capability? Is re-authing a dead slot a
//!     STRICT-LOSS operation (it shares an identity with a live sibling, so a
//!     re-login would revoke the live one)?
//!
//! NORTH STAR (never-halt): one dead / duplicate / rate-limited / quota-exhausted
//! account must NEVER halt the mux. `afloat` is defined over the SET of distinct
//! live identities, so a non-live slot contributes 0 and can never remove a member
//! another live slot put there. The ONLY false case is every distinct identity
//! down. This module makes that depth visible; it is the analysis the keepalive
//! escalation and the operator diagnostics consume.
//!
//! SCOPE / NO-CLOBBER: this is pure analysis. Route SELECTION lives in
//! `src/pipeline.zig` (`selectWithFallback` + the health-store `muxDecisionFor`)
//! and is NOT touched or reimplemented here. The graph only reads account records
//! the caller fills from `accounts list` evidence and returns verdicts.
//!
//! Self-contained: `std` only, NO `@import` of existing `src`; pure data functions
//! (no I/O, no seams). Liveness classes mirror the repo's `CredentialLiveness`
//! (`types.zig`): `.live.{available,rate_limited,quota_exhausted,cooldown}`,
//! `.degraded:*`, `.dead:*`. Allocation-explicit; `std.testing.allocator`-clean.

const std = @import("std");

// ── Liveness (mirrors types.zig CredentialLiveness summary classes) ──────────

/// The liveness of one (account, capability) route. Only `.live` (i.e. the repo's
/// `.live.available`) counts toward redundancy depth / afloat. `rate_limited`,
/// `quota_exhausted`, `cooldown` are the repo's other `.live.*` arms — the account
/// is alive but transiently unusable (recoverable; wait, don't escalate).
/// `degraded` is a `.degraded:*` reason (tier/scope/schema — needs intervention,
/// not auto-recovering, but not dead). `dead` is a `.dead:*` reason (needs reauth).
pub const Liveness = enum {
    live,
    rate_limited,
    quota_exhausted,
    cooldown,
    degraded,
    dead,
    unknown,

    /// Counts toward redundancy depth / afloat — usable right now.
    pub fn countsAfloat(self: Liveness) bool {
        return self == .live;
    }

    /// Alive but transiently unusable — will return on its own; do not escalate.
    pub fn isRecoverable(self: Liveness) bool {
        return self == .rate_limited or self == .quota_exhausted or self == .cooldown;
    }

    pub fn isDead(self: Liveness) bool {
        return self == .dead;
    }
};

// ── Identity key (verify fix #1: null hash => per-slot-unique opaque key) ─────

/// The real underlying identity of a slot. A non-null `account_id_hash` groups
/// slots that are the SAME account. A null hash (identity unknown — e.g. a codex
/// account whose auth.json is unavailable) is keyed by the per-slot-unique
/// (provider, account) tuple, so two UNKNOWN identities are NEVER coalesced into
/// one, and one real account's capability rows (same provider+account) DO group.
pub const IdentityKey = union(enum) {
    hash: []const u8,
    opaque_slot: struct { provider: []const u8, account: []const u8 },

    pub fn eql(a: IdentityKey, b: IdentityKey) bool {
        return switch (a) {
            .hash => |ah| switch (b) {
                .hash => |bh| std.mem.eql(u8, ah, bh),
                .opaque_slot => false,
            },
            .opaque_slot => |ao| switch (b) {
                .hash => false,
                .opaque_slot => |bo| std.mem.eql(u8, ao.provider, bo.provider) and
                    std.mem.eql(u8, ao.account, bo.account),
            },
        };
    }
};

// ── Account slot (one (account, capability) route) ───────────────────────────

/// One route row, as the caller flattens it from `accounts list` (an account with
/// N capabilities → N slots). All slices are borrowed; the input must outlive any
/// returned analysis (collisions/strict-loss/retire results borrow these strings).
pub const AccountSlot = struct {
    /// Config slot name, e.g. "max-2". The caller guarantees (provider, account)
    /// is unique per real slot (asserted in debug for the unknown-identity case).
    account: []const u8,
    provider: []const u8, // "codex" / "claude" / …
    capability: []const u8, // "codex-max" / "codex-mini" / "auth-status" / …
    /// sha256_12hex of the provider account-id claim; null = identity unknown.
    account_id_hash: ?[]const u8 = null,
    email_hint: ?[]const u8 = null,
    liveness: Liveness,
    /// false when the identity cannot be re-authed (e.g. AAS phone-OTP lockout,
    /// openai/codex#25737) — surfaced on strict-loss/collision for escalation.
    reauthable: bool = true,

    pub fn identityKey(self: AccountSlot) IdentityKey {
        if (self.account_id_hash) |h| return .{ .hash = h };
        return .{ .opaque_slot = .{ .provider = self.provider, .account = self.account } };
    }
};

fn matchesPC(s: AccountSlot, provider: []const u8, capability: []const u8) bool {
    return std.mem.eql(u8, s.provider, provider) and std.mem.eql(u8, s.capability, capability);
}

// ── Core redundancy math (allocation-free) ───────────────────────────────────

/// Count DISTINCT live identities for (provider, capability), optionally excluding
/// one account (for retire-safety). First-occurrence dedup by `IdentityKey`.
fn countDistinctLive(
    slots: []const AccountSlot,
    provider: []const u8,
    capability: []const u8,
    exclude_account: ?[]const u8,
) usize {
    var count: usize = 0;
    for (slots, 0..) |s, i| {
        if (!matchesPC(s, provider, capability)) continue;
        if (!s.liveness.countsAfloat()) continue;
        if (exclude_account) |ex| {
            if (std.mem.eql(u8, s.account, ex)) continue;
        }
        var dup = false;
        var j: usize = 0;
        while (j < i) : (j += 1) {
            const t = slots[j];
            if (!matchesPC(t, provider, capability)) continue;
            if (!t.liveness.countsAfloat()) continue;
            if (exclude_account) |ex| {
                if (std.mem.eql(u8, t.account, ex)) continue;
            }
            if (s.identityKey().eql(t.identityKey())) {
                dup = true;
                break;
            }
        }
        if (!dup) count += 1;
    }
    return count;
}

/// The TRUE redundancy depth: how many distinct live identities serve this
/// (provider, capability). Duplicate slots of one identity count once.
pub fn distinctLiveIdentities(slots: []const AccountSlot, provider: []const u8, capability: []const u8) usize {
    return countDistinctLive(slots, provider, capability, null);
}

/// The never-halt predicate: a capability is afloat iff >=1 distinct live identity
/// remains. A dead/duplicate/rate-limited/quota slot can never flip this false on
/// its own.
pub fn isAfloat(slots: []const AccountSlot, provider: []const u8, capability: []const u8) bool {
    return distinctLiveIdentities(slots, provider, capability) >= 1;
}

/// What the keepalive should do for a (provider, capability) — separates "wait"
/// (recoverable) from "escalate" (needs reauth/probe), so a transient blip is
/// never escalated as a death and a real death is never silently waited on.
pub const Disposition = enum {
    afloat, // >=1 live identity — usable now
    recoverable_only, // 0 live, >=1 recoverable (rate/quota/cooldown) — WAIT
    needs_intervention, // 0 live, 0 recoverable, >=1 dead/degraded/unknown — ESCALATE
    empty, // no slots for this (provider, capability)
};

pub fn disposition(slots: []const AccountSlot, provider: []const u8, capability: []const u8) Disposition {
    var any = false;
    var any_recoverable = false;
    for (slots) |s| {
        if (!matchesPC(s, provider, capability)) continue;
        any = true;
        if (s.liveness.countsAfloat()) return .afloat;
        if (s.liveness.isRecoverable()) any_recoverable = true;
    }
    if (!any) return .empty;
    return if (any_recoverable) .recoverable_only else .needs_intervention;
}

// ── Duplicate-enrollment collisions ──────────────────────────────────────────

/// An identity enrolled into >=2 distinct config slots — i.e. apparent redundancy
/// that is not real. `accounts` are the distinct slot names (borrowed). Free with
/// `freeCollisions`.
pub const Collision = struct {
    identity: IdentityKey,
    accounts: [][]const u8,
    has_live_slot: bool, // at least one slot of this identity is live somewhere
    any_unreauthable: bool, // at least one slot of this identity is un-reauthable
};

pub fn duplicateCollisions(allocator: std.mem.Allocator, slots: []const AccountSlot) ![]Collision {
    var list = std.ArrayList(Collision).init(allocator);
    errdefer {
        for (list.items) |c| allocator.free(c.accounts);
        list.deinit();
    }

    for (slots, 0..) |s, i| {
        // process each identity once (at its first-occurrence slot)
        var first = true;
        var j: usize = 0;
        while (j < i) : (j += 1) {
            if (s.identityKey().eql(slots[j].identityKey())) {
                first = false;
                break;
            }
        }
        if (!first) continue;

        const key = s.identityKey();
        var accts = std.ArrayList([]const u8).init(allocator);
        errdefer accts.deinit();
        var has_live = false;
        var any_unreauth = false;
        for (slots) |t| {
            if (!key.eql(t.identityKey())) continue;
            if (t.liveness.countsAfloat()) has_live = true;
            if (!t.reauthable) any_unreauth = true;
            var dup = false;
            for (accts.items) |a| {
                if (std.mem.eql(u8, a, t.account)) {
                    dup = true;
                    break;
                }
            }
            if (!dup) try accts.append(t.account);
        }

        if (accts.items.len >= 2) {
            try list.append(.{
                .identity = key,
                .accounts = try accts.toOwnedSlice(),
                .has_live_slot = has_live,
                .any_unreauthable = any_unreauth,
            });
        } else {
            accts.deinit();
        }
    }

    return list.toOwnedSlice();
}

pub fn freeCollisions(allocator: std.mem.Allocator, collisions: []Collision) void {
    for (collisions) |c| allocator.free(c.accounts);
    allocator.free(collisions);
}

// ── Strict-loss-to-reauth (verify fix #2: per-capability) ────────────────────

/// A non-live slot whose identity is ALSO live (for the same capability) via a
/// sibling slot — so re-authing it would revoke the live sibling's tokens. One
/// entry per (slot, capability). Advisory only — pure metadata, never mutates.
pub const StrictLossSlot = struct {
    account: []const u8,
    provider: []const u8,
    capability: []const u8,
    live_sibling: []const u8, // the slot whose tokens a reauth would revoke
    identity_unreauthable: bool, // the shared identity also can't be re-authed (#25737)
};

pub fn strictLossSlots(allocator: std.mem.Allocator, slots: []const AccountSlot) ![]StrictLossSlot {
    var list = std.ArrayList(StrictLossSlot).init(allocator);
    errdefer list.deinit();

    for (slots, 0..) |s, i| {
        if (s.liveness.countsAfloat()) continue; // strict-loss applies to NON-live slots
        for (slots, 0..) |t, j| {
            if (i == j) continue;
            if (!matchesPC(t, s.provider, s.capability)) continue;
            if (!t.liveness.countsAfloat()) continue;
            if (!s.identityKey().eql(t.identityKey())) continue;
            try list.append(.{
                .account = s.account,
                .provider = s.provider,
                .capability = s.capability,
                .live_sibling = t.account,
                .identity_unreauthable = !s.reauthable or !t.reauthable,
            });
            break; // one live sibling is enough
        }
    }

    return list.toOwnedSlice();
}

// ── Retire-safety (verify fix #3: per-capability delta) ──────────────────────

pub const CapabilityDelta = struct {
    capability: []const u8,
    distinct_live_before: usize,
    distinct_live_after: usize,
    flips_afloat: bool, // before >= 1 and after == 0
};

/// The per-capability effect of removing (provider, account) from the inventory.
/// `overall_safe` is true iff no capability is flipped from afloat to not-afloat.
/// Free with `freeRetireSafety`.
pub const RetireSafety = struct {
    overall_safe: bool,
    per_capability: []CapabilityDelta,
};

pub fn wouldRetireReduceRedundancy(
    allocator: std.mem.Allocator,
    slots: []const AccountSlot,
    retire_provider: []const u8,
    retire_account: []const u8,
) !RetireSafety {
    var list = std.ArrayList(CapabilityDelta).init(allocator);
    errdefer list.deinit();
    var overall_safe = true;

    for (slots, 0..) |s, i| {
        if (!std.mem.eql(u8, s.provider, retire_provider)) continue;
        if (!std.mem.eql(u8, s.account, retire_account)) continue;
        // each capability of the retire account once
        var seen = false;
        var j: usize = 0;
        while (j < i) : (j += 1) {
            const t = slots[j];
            if (std.mem.eql(u8, t.provider, retire_provider) and
                std.mem.eql(u8, t.account, retire_account) and
                std.mem.eql(u8, t.capability, s.capability))
            {
                seen = true;
                break;
            }
        }
        if (seen) continue;

        const before = countDistinctLive(slots, retire_provider, s.capability, null);
        const after = countDistinctLive(slots, retire_provider, s.capability, retire_account);
        const flips = before >= 1 and after == 0;
        if (flips) overall_safe = false;
        try list.append(.{
            .capability = s.capability,
            .distinct_live_before = before,
            .distinct_live_after = after,
            .flips_afloat = flips,
        });
    }

    return .{ .overall_safe = overall_safe, .per_capability = try list.toOwnedSlice() };
}

pub fn freeRetireSafety(allocator: std.mem.Allocator, rs: RetireSafety) void {
    allocator.free(rs.per_capability);
}
