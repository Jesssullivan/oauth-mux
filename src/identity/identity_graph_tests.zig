//! Unit tests for the identity graph. Pure: in-memory account inventories, no I/O.
//! Proves the six never-halt invariants + the real ground-truth inventory.
//!
//!     zig test src/identity/identity_graph_tests.zig

const std = @import("std");
const testing = std.testing;
const ig = @import("identity_graph.zig");

test {
    std.testing.refAllDeclsRecursive(ig);
}

const Slot = ig.AccountSlot;

// ── The real inventory (oauth-mux accounts list, 2026-06-01) as the ground truth ──
// max-1 == max-2 (same hash 38079d6acec6, the AAS-locked sulliwood.org account);
// max-3 (columbari.us) is distinct; claude personal is keychain (null hash).
const real_inventory = [_]Slot{
    .{ .account = "max-1", .provider = "codex", .capability = "codex-max", .account_id_hash = "38079d6acec6", .liveness = .live, .reauthable = false },
    .{ .account = "max-1", .provider = "codex", .capability = "codex-mini", .account_id_hash = "38079d6acec6", .liveness = .live, .reauthable = false },
    .{ .account = "max-2", .provider = "codex", .capability = "codex-max", .account_id_hash = "38079d6acec6", .liveness = .dead, .reauthable = false },
    .{ .account = "max-2", .provider = "codex", .capability = "codex-mini", .account_id_hash = "38079d6acec6", .liveness = .dead, .reauthable = false },
    .{ .account = "max-3", .provider = "codex", .capability = "codex-max", .account_id_hash = "c0dfbc44912c", .liveness = .degraded, .reauthable = true },
    .{ .account = "max-3", .provider = "codex", .capability = "codex-mini", .account_id_hash = "c0dfbc44912c", .liveness = .live, .reauthable = true },
    .{ .account = "personal", .provider = "claude", .capability = "auth-status", .account_id_hash = null, .liveness = .live, .reauthable = true },
};

// ── IdentityKey ──────────────────────────────────────────────────────────────

test "IdentityKey: hash equality, opaque tuple equality, hash != opaque" {
    const h1 = ig.IdentityKey{ .hash = "abc" };
    const h1b = ig.IdentityKey{ .hash = "abc" };
    const h2 = ig.IdentityKey{ .hash = "xyz" };
    try testing.expect(h1.eql(h1b));
    try testing.expect(!h1.eql(h2));

    const o1 = ig.IdentityKey{ .opaque_slot = .{ .provider = "codex", .account = "default" } };
    const o1b = ig.IdentityKey{ .opaque_slot = .{ .provider = "codex", .account = "default" } };
    const o2 = ig.IdentityKey{ .opaque_slot = .{ .provider = "gemini", .account = "default" } };
    try testing.expect(o1.eql(o1b));
    try testing.expect(!o1.eql(o2)); // different provider, same name => distinct
    try testing.expect(!h1.eql(o1)); // a hash key never equals an opaque key
}

// ── Core redundancy math + INV-IDENTITIES-NOT-SLOTS + INV-PER-CAPABILITY ──────

test "distinctLiveIdentities counts identities not slots, per capability (real inventory)" {
    const inv = &real_inventory;
    // codex-max: only max-1 is live (max-2 dead, max-3 degraded) => 1
    try testing.expectEqual(@as(usize, 1), ig.distinctLiveIdentities(inv, "codex", "codex-max"));
    // codex-mini: max-1 + max-3 live (max-2 dead) => 2 distinct identities
    try testing.expectEqual(@as(usize, 2), ig.distinctLiveIdentities(inv, "codex", "codex-mini"));
    // claude auth-status: 1
    try testing.expectEqual(@as(usize, 1), ig.distinctLiveIdentities(inv, "claude", "auth-status"));
}

test "INV-IDENTITIES-NOT-SLOTS: two live slots of the SAME identity count as 1" {
    const slots = [_]Slot{
        .{ .account = "max-1", .provider = "codex", .capability = "codex-max", .account_id_hash = "dup", .liveness = .live },
        .{ .account = "max-2", .provider = "codex", .capability = "codex-max", .account_id_hash = "dup", .liveness = .live },
    };
    try testing.expectEqual(@as(usize, 1), ig.distinctLiveIdentities(&slots, "codex", "codex-max"));
}

test "isAfloat true on the real inventory for served capabilities" {
    const inv = &real_inventory;
    try testing.expect(ig.isAfloat(inv, "codex", "codex-max"));
    try testing.expect(ig.isAfloat(inv, "codex", "codex-mini"));
    try testing.expect(ig.isAfloat(inv, "claude", "auth-status"));
}

// ── INV-AFLOAT-MONOTONE-UNDER-NONLIVE ────────────────────────────────────────

test "INV-AFLOAT-MONOTONE: non-live slots never flip a live capability to not-afloat" {
    // one live identity, surrounded by dead/rate-limited/quota/degraded of OTHER identities
    const slots = [_]Slot{
        .{ .account = "live", .provider = "codex", .capability = "codex-max", .account_id_hash = "A", .liveness = .live },
        .{ .account = "d1", .provider = "codex", .capability = "codex-max", .account_id_hash = "B", .liveness = .dead },
        .{ .account = "r1", .provider = "codex", .capability = "codex-max", .account_id_hash = "C", .liveness = .rate_limited },
        .{ .account = "q1", .provider = "codex", .capability = "codex-max", .account_id_hash = "D", .liveness = .quota_exhausted },
        .{ .account = "g1", .provider = "codex", .capability = "codex-max", .account_id_hash = "E", .liveness = .degraded },
    };
    try testing.expect(ig.isAfloat(&slots, "codex", "codex-max"));
    try testing.expectEqual(@as(usize, 1), ig.distinctLiveIdentities(&slots, "codex", "codex-max"));
    try testing.expectEqual(ig.Disposition.afloat, ig.disposition(&slots, "codex", "codex-max"));
}

// ── Disposition: wait vs escalate (never-halt nuance) ────────────────────────

test "disposition: recoverable_only => WAIT, never escalate a transient blip" {
    const slots = [_]Slot{
        .{ .account = "a", .provider = "codex", .capability = "codex-max", .account_id_hash = "A", .liveness = .rate_limited },
        .{ .account = "b", .provider = "codex", .capability = "codex-max", .account_id_hash = "B", .liveness = .quota_exhausted },
    };
    try testing.expect(!ig.isAfloat(&slots, "codex", "codex-max"));
    try testing.expectEqual(ig.Disposition.recoverable_only, ig.disposition(&slots, "codex", "codex-max"));
}

test "disposition: all dead => needs_intervention (the only escalate case)" {
    const slots = [_]Slot{
        .{ .account = "a", .provider = "codex", .capability = "codex-max", .account_id_hash = "A", .liveness = .dead },
        .{ .account = "b", .provider = "codex", .capability = "codex-max", .account_id_hash = "B", .liveness = .degraded },
    };
    try testing.expect(!ig.isAfloat(&slots, "codex", "codex-max"));
    try testing.expectEqual(ig.Disposition.needs_intervention, ig.disposition(&slots, "codex", "codex-max"));
}

test "disposition: empty for an unknown capability" {
    const inv = &real_inventory;
    try testing.expectEqual(ig.Disposition.empty, ig.disposition(inv, "codex", "no-such-capability"));
}

// ── INV-CROSS-PROVIDER-ISOLATION ─────────────────────────────────────────────

test "INV-CROSS-PROVIDER: total codex outage leaves claude afloat" {
    const slots = [_]Slot{
        .{ .account = "max-1", .provider = "codex", .capability = "codex-max", .account_id_hash = "A", .liveness = .dead },
        .{ .account = "max-3", .provider = "codex", .capability = "codex-max", .account_id_hash = "B", .liveness = .dead },
        .{ .account = "personal", .provider = "claude", .capability = "auth-status", .account_id_hash = null, .liveness = .live },
    };
    try testing.expect(!ig.isAfloat(&slots, "codex", "codex-max"));
    try testing.expect(ig.isAfloat(&slots, "claude", "auth-status")); // unaffected
}

// ── Duplicate collisions (the max-2==max-1 auto-detector) ────────────────────

test "duplicateCollisions flags max-1/max-2 as the same identity, with no false positives" {
    const a = testing.allocator;
    const inv = &real_inventory;
    const cols = try ig.duplicateCollisions(a, inv);
    defer ig.freeCollisions(a, cols);

    try testing.expectEqual(@as(usize, 1), cols.len); // only the sulliwood duplicate
    const c = cols[0];
    try testing.expect(c.identity.eql(.{ .hash = "38079d6acec6" }));
    try testing.expectEqual(@as(usize, 2), c.accounts.len); // max-1, max-2
    try testing.expect(c.has_live_slot); // max-1 is live
    try testing.expect(c.any_unreauthable); // AAS-locked (#25737)
}

test "duplicateCollisions: two distinct unknown identities are NOT coalesced (null-key safety)" {
    const a = testing.allocator;
    // two different accounts, both null hash, same provider — must NOT collide
    const slots = [_]Slot{
        .{ .account = "default", .provider = "codex", .capability = "codex-mini", .account_id_hash = null, .liveness = .live },
        .{ .account = "other", .provider = "codex", .capability = "codex-mini", .account_id_hash = null, .liveness = .live },
    };
    const cols = try ig.duplicateCollisions(a, &slots);
    defer ig.freeCollisions(a, cols);
    try testing.expectEqual(@as(usize, 0), cols.len);
    // and they count as 2 distinct live identities, not coalesced to 1
    try testing.expectEqual(@as(usize, 2), ig.distinctLiveIdentities(&slots, "codex", "codex-mini"));
}

test "an unknown account's capability rows DO group as one identity" {
    const slots = [_]Slot{
        .{ .account = "default", .provider = "codex", .capability = "codex-max", .account_id_hash = null, .liveness = .live },
        .{ .account = "default", .provider = "codex", .capability = "codex-mini", .account_id_hash = null, .liveness = .live },
    };
    // same (provider, account) => same opaque identity; one live identity per capability
    try testing.expectEqual(@as(usize, 1), ig.distinctLiveIdentities(&slots, "codex", "codex-max"));
    try testing.expectEqual(@as(usize, 1), ig.distinctLiveIdentities(&slots, "codex", "codex-mini"));
}

// ── INV-STRICT-LOSS (per-capability, verify fix #2) ──────────────────────────

test "strictLossSlots: max-2 is strict-loss for BOTH capabilities; max-3 for none" {
    const a = testing.allocator;
    const inv = &real_inventory;
    const sl = try ig.strictLossSlots(a, inv);
    defer a.free(sl);

    try testing.expectEqual(@as(usize, 2), sl.len); // max-2 codex-max + max-2 codex-mini
    for (sl) |entry| {
        try testing.expectEqualStrings("max-2", entry.account);
        try testing.expectEqualStrings("max-1", entry.live_sibling); // reauth would revoke the live max-1
        try testing.expect(entry.identity_unreauthable); // shared identity is AAS-locked
    }
    // max-3's degraded codex-max has no live same-identity sibling => not strict-loss
    for (sl) |entry| try testing.expect(!std.mem.eql(u8, entry.account, "max-3"));
}

// ── INV-RETIRE (per-capability delta, verify fix #3) ─────────────────────────

test "retire max-2 is SAFE on every capability (dead duplicate of live max-1)" {
    const a = testing.allocator;
    const inv = &real_inventory;
    const rs = try ig.wouldRetireReduceRedundancy(a, inv, "codex", "max-2");
    defer ig.freeRetireSafety(a, rs);

    try testing.expect(rs.overall_safe);
    try testing.expectEqual(@as(usize, 2), rs.per_capability.len);
    for (rs.per_capability) |d| {
        try testing.expect(!d.flips_afloat);
        try testing.expectEqual(d.distinct_live_before, d.distinct_live_after); // unchanged
    }
}

test "retire max-1 is UNSAFE for codex-max but codex-mini visibly survives (per-capability)" {
    const a = testing.allocator;
    const inv = &real_inventory;
    const rs = try ig.wouldRetireReduceRedundancy(a, inv, "codex", "max-1");
    defer ig.freeRetireSafety(a, rs);

    try testing.expect(!rs.overall_safe);
    var saw_max = false;
    var saw_mini = false;
    for (rs.per_capability) |d| {
        if (std.mem.eql(u8, d.capability, "codex-max")) {
            saw_max = true;
            try testing.expectEqual(@as(usize, 1), d.distinct_live_before);
            try testing.expectEqual(@as(usize, 0), d.distinct_live_after);
            try testing.expect(d.flips_afloat); // would halt codex-max
        } else if (std.mem.eql(u8, d.capability, "codex-mini")) {
            saw_mini = true;
            try testing.expectEqual(@as(usize, 2), d.distinct_live_before);
            try testing.expectEqual(@as(usize, 1), d.distinct_live_after);
            try testing.expect(!d.flips_afloat); // codex-mini survives — visible to the operator
        }
    }
    try testing.expect(saw_max and saw_mini);
}

// ── Allocator hygiene on empty inputs ────────────────────────────────────────

test "empty inventory: no collisions, no strict-loss, safe retire" {
    const a = testing.allocator;
    const slots = [_]Slot{};
    const cols = try ig.duplicateCollisions(a, &slots);
    defer ig.freeCollisions(a, cols);
    try testing.expectEqual(@as(usize, 0), cols.len);

    const sl = try ig.strictLossSlots(a, &slots);
    defer a.free(sl);
    try testing.expectEqual(@as(usize, 0), sl.len);

    const rs = try ig.wouldRetireReduceRedundancy(a, &slots, "codex", "nope");
    defer ig.freeRetireSafety(a, rs);
    try testing.expect(rs.overall_safe);
    try testing.expectEqual(@as(usize, 0), rs.per_capability.len);
}
