//! Integration: the Claude identity PRODUCER (`claude_identity.zig`) feeds the
//! identity-graph CONSUMER (`identity_graph.zig`) — the producer→graph seam the
//! two separately-parked greenfield modules never exercised together. Proves the
//! `account_id_hash` the labeler emits is exactly what the graph groups on, so:
//!   * two config slots backed by the SAME Claude account count as ONE distinct
//!     live identity (the max-2 == max-1 trap the golden metric must not fall for);
//!   * two DISTINCT accounts count as two (real failover depth);
//!   * an unprofiled slot (no accountUuid → null hash) keys OPAQUELY and is never
//!     coalesced with another unprofiled account (honest never-halt accounting).
//!
//! Borrowing discipline (per claude_identity.zig's ownership note): the graph's
//! AccountSlot BORROWS the producer's hash, so each ClaudeIdentity outlives the
//! slots that reference it (deinit deferred to end of test).

const std = @import("std");
const testing = std.testing;
const ci = @import("claude_identity.zig");
const ig = @import("identity_graph.zig");

test {
    testing.refAllDeclsRecursive(@This());
}

test "producer→graph: two slots on the SAME Claude account = ONE distinct live identity" {
    const a = testing.allocator;
    // One real account (accountUuid) fronted by two config slots (e.g. max-1/max-2).
    const id = try ci.parseClaudeIdentity(a,
        "{\"oauthAccount\":{\"accountUuid\":\"acct-shared\",\"organizationUuid\":\"org-1\"}}");
    defer id.deinit(a);
    try testing.expect(id.present);
    const hash = id.account_id_hash.?;

    const slots = [_]ig.AccountSlot{
        .{ .account = "claude-a", .provider = "claude", .capability = "claude-max", .account_id_hash = hash, .liveness = .live },
        .{ .account = "claude-b", .provider = "claude", .capability = "claude-max", .account_id_hash = hash, .liveness = .live },
    };
    // Two live SLOTS, but ONE distinct live IDENTITY — the duplicate is not failover.
    try testing.expectEqual(@as(usize, 1), ig.distinctLiveIdentities(&slots, "claude", "claude-max"));
    try testing.expect(ig.isAfloat(&slots, "claude", "claude-max"));
}

test "producer→graph: two DISTINCT Claude accounts = TWO distinct live identities" {
    const a = testing.allocator;
    const id1 = try ci.parseClaudeIdentity(a, "{\"oauthAccount\":{\"accountUuid\":\"acct-1\"}}");
    defer id1.deinit(a);
    const id2 = try ci.parseClaudeIdentity(a, "{\"oauthAccount\":{\"accountUuid\":\"acct-2\"}}");
    defer id2.deinit(a);
    try testing.expect(!std.mem.eql(u8, id1.account_id_hash.?, id2.account_id_hash.?));

    const slots = [_]ig.AccountSlot{
        .{ .account = "claude-a", .provider = "claude", .capability = "claude-max", .account_id_hash = id1.account_id_hash.?, .liveness = .live },
        .{ .account = "claude-b", .provider = "claude", .capability = "claude-max", .account_id_hash = id2.account_id_hash.?, .liveness = .live },
    };
    try testing.expectEqual(@as(usize, 2), ig.distinctLiveIdentities(&slots, "claude", "claude-max"));
}

test "producer→graph: two unprofiled accounts key opaquely and are never coalesced" {
    const a = testing.allocator;
    // No accountUuid → present=false, null hash (the honest "authenticated but
    // unprofiled" state). The graph must key each opaquely by (provider, account).
    const id = try ci.parseClaudeIdentity(a, "{\"oauthAccount\":{}}");
    defer id.deinit(a);
    try testing.expect(!id.present);
    try testing.expect(id.account_id_hash == null);

    const slots = [_]ig.AccountSlot{
        .{ .account = "claude-x", .provider = "claude", .capability = "claude-max", .account_id_hash = null, .liveness = .live },
        .{ .account = "claude-y", .provider = "claude", .capability = "claude-max", .account_id_hash = null, .liveness = .live },
    };
    // Two distinct unprofiled accounts → two distinct opaque identities, NOT one
    // coalesced hashed-empty-string identity.
    try testing.expectEqual(@as(usize, 2), ig.distinctLiveIdentities(&slots, "claude", "claude-max"));
}

test "producer→graph: a duplicate slot does not fake failover when its twin is the only live one" {
    const a = testing.allocator;
    // Same account behind two slots; the second is dead. Distinct LIVE depth = 1,
    // and re-authing the dead twin would be strict-loss (shares the live identity).
    const id = try ci.parseClaudeIdentity(a, "{\"oauthAccount\":{\"accountUuid\":\"acct-shared\"}}");
    defer id.deinit(a);
    const hash = id.account_id_hash.?;
    const slots = [_]ig.AccountSlot{
        .{ .account = "claude-a", .provider = "claude", .capability = "claude-max", .account_id_hash = hash, .liveness = .live },
        .{ .account = "claude-b", .provider = "claude", .capability = "claude-max", .account_id_hash = hash, .liveness = .dead },
    };
    // Still afloat on the one live slot; depth is 1 (the dead twin adds nothing).
    try testing.expectEqual(@as(usize, 1), ig.distinctLiveIdentities(&slots, "claude", "claude-max"));
    try testing.expect(ig.isAfloat(&slots, "claude", "claude-max"));
}
