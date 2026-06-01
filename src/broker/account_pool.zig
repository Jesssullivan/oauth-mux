//! Account pool. Read-side store of `provider:account` identities.
//!
//! Phase 1 scope: in-memory list with selectability and (eventual)
//! availability. Population from the active oauth-mux Config lives in
//! `src/broker_loader.zig` so this module stays config-agnostic; the
//! broker's contract should not depend on Config's struct shape.
//!
//! No token bytes EVER cross this boundary in either direction.

const std = @import("std");
const types = @import("types.zig");

pub const Liveness = enum { live, degraded, dead, unknown };
pub const Availability = enum { available, rate_limited, quota_exhausted, cooldown, unknown };

pub const AccountSummary = struct {
    id: []const u8, // owned by pool
    capability: ?[]const u8 = null, // owned by pool when present
    selectable: bool,
    liveness: Liveness,
    availability: Availability,
    next_eligible_at: ?i64 = null,
};

/// The pool. Phase 1 implementation uses an in-memory list seeded from
/// the existing config; later tasks wire health/quota state from
/// src/health.zig and src/repair_state.zig.
pub const AccountPool = struct {
    allocator: std.mem.Allocator,
    accounts: std.ArrayListUnmanaged(AccountSummary) = .{},

    pub fn init(allocator: std.mem.Allocator) AccountPool {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *AccountPool) void {
        for (self.accounts.items) |a| {
            self.allocator.free(a.id);
            if (a.capability) |capability| self.allocator.free(capability);
        }
        self.accounts.deinit(self.allocator);
    }

    pub fn add(self: *AccountPool, summary: AccountSummary) !void {
        const owned_id = try self.allocator.dupe(u8, summary.id);
        errdefer self.allocator.free(owned_id);
        const owned_capability = if (summary.capability) |capability|
            try self.allocator.dupe(u8, capability)
        else
            null;
        errdefer if (owned_capability) |capability| self.allocator.free(capability);
        var owned = summary;
        owned.id = owned_id;
        owned.capability = owned_capability;
        try self.accounts.append(self.allocator, owned);
    }

    /// Limit visible accounts to a set of allowed `provider:account`
    /// ids. Accounts not in the allowed set are marked non-selectable
    /// in place (the entry stays so callers can see why it's hidden).
    pub fn restrictToAllowList(self: *AccountPool, allow: []const []const u8) void {
        for (self.accounts.items) |*a| {
            var found = false;
            for (allow) |allowed| {
                if (std.mem.eql(u8, allowed, a.id)) {
                    found = true;
                    break;
                }
            }
            if (!found) a.selectable = false;
        }
    }

    /// Mark an account as quota-exhausted with an absolute reset
    /// timestamp. The account becomes non-selectable until the
    /// timestamp passes (callers consult `now` against
    /// `next_eligible_at` at elect-time).
    /// Anchor: docs/spec/broker-mcp-contract-2026-05-03.md §2.2 account/swap
    /// + §2.4 quota/observe.
    pub fn markQuotaExhausted(
        self: *AccountPool,
        account_id: []const u8,
        resets_at: i64,
    ) types.BrokerError!void {
        for (self.accounts.items) |*a| {
            if (std.mem.eql(u8, a.id, account_id)) {
                a.availability = .quota_exhausted;
                a.next_eligible_at = resets_at;
                a.selectable = false;
                return;
            }
        }
        return types.BrokerError.AccountNotFound;
    }

    /// Mark an account as rate-limited with a Retry-After hint. Sets
    /// availability = .rate_limited and next_eligible_at, but does
    /// not flip `selectable` because rate-limit windows are short
    /// enough that we may want this account back within the same
    /// turn boundary.
    pub fn markRateLimited(
        self: *AccountPool,
        account_id: []const u8,
        retry_after_at: i64,
    ) types.BrokerError!void {
        for (self.accounts.items) |*a| {
            if (std.mem.eql(u8, a.id, account_id)) {
                a.availability = .rate_limited;
                a.next_eligible_at = retry_after_at;
                return;
            }
        }
        return types.BrokerError.AccountNotFound;
    }

    /// Mark a route as provider-degraded for a short retry window. This is not
    /// credential death; the account can become selectable again once the
    /// transport/provider window passes.
    pub fn markProviderDegraded(
        self: *AccountPool,
        account_id: []const u8,
        retry_after_at: i64,
    ) types.BrokerError!void {
        for (self.accounts.items) |*a| {
            if (std.mem.eql(u8, a.id, account_id)) {
                a.liveness = .degraded;
                a.availability = .cooldown;
                a.next_eligible_at = retry_after_at;
                a.selectable = false;
                return;
            }
        }
        return types.BrokerError.AccountNotFound;
    }

    /// Mark an account as authorization-failed (401). Becomes
    /// non-selectable; recovery requires either credential refresh
    /// (Phase 3) or operator re-enrollment.
    pub fn markUnauthorized(
        self: *AccountPool,
        account_id: []const u8,
    ) types.BrokerError!void {
        for (self.accounts.items) |*a| {
            if (std.mem.eql(u8, a.id, account_id)) {
                a.liveness = .dead;
                a.selectable = false;
                return;
            }
        }
        return types.BrokerError.AccountNotFound;
    }

    /// Walk the pool, restoring any accounts whose `next_eligible_at`
    /// is in the past. Called opportunistically before elect.
    pub fn refreshTimeBased(self: *AccountPool, now_unix: i64) void {
        for (self.accounts.items) |*a| {
            if (a.next_eligible_at) |t| {
                if (t <= now_unix) {
                    // Reset to available; selectability flag follows.
                    a.availability = .available;
                    a.next_eligible_at = null;
                    if (a.liveness == .degraded) a.liveness = .live;
                    if (a.liveness != .dead) a.selectable = true;
                }
            }
        }
    }

    /// List accounts visible to a session, optionally filtered by profile
    /// and capability. Phase 1: returns all configured accounts; profile/
    /// capability filtering wired in task #17.
    pub fn list(
        self: *const AccountPool,
        out: *std.ArrayListUnmanaged(AccountSummary),
        out_alloc: std.mem.Allocator,
        profile: ?[]const u8,
        capability: ?[]const u8,
    ) !void {
        _ = profile;
        _ = capability;
        try out.ensureTotalCapacity(out_alloc, self.accounts.items.len);
        for (self.accounts.items) |a| out.appendAssumeCapacity(a);
    }

    /// Pick a selectable account, optionally excluding some. Returns
    /// BrokerError.NoAccountSelectable when no candidate qualifies.
    pub fn elect(
        self: *const AccountPool,
        profile: ?[]const u8,
        capability: ?[]const u8,
        exclude: []const []const u8,
    ) types.BrokerError!AccountSummary {
        _ = profile;
        _ = capability;
        outer: for (self.accounts.items) |a| {
            if (!a.selectable) continue;
            if (a.availability != .available) continue;
            for (exclude) |ex| {
                if (std.mem.eql(u8, ex, a.id)) continue :outer;
            }
            return a;
        }
        return types.BrokerError.NoAccountSelectable;
    }
};

const ElectionMatrixState = enum {
    available,
    auth_dead,
    quota_exhausted,
    rate_limited,
    tier_insufficient,
    credential_unavailable,
    provider_degraded,
};

fn matrixAccountSummary(id: []const u8, state: ElectionMatrixState) AccountSummary {
    return switch (state) {
        .available => .{
            .id = id,
            .selectable = true,
            .liveness = .live,
            .availability = .available,
        },
        .auth_dead => .{
            .id = id,
            .selectable = false,
            .liveness = .dead,
            .availability = .unknown,
        },
        .quota_exhausted => .{
            .id = id,
            .selectable = false,
            .liveness = .live,
            .availability = .quota_exhausted,
        },
        .rate_limited => .{
            .id = id,
            .selectable = true,
            .liveness = .live,
            .availability = .rate_limited,
        },
        .tier_insufficient => .{
            .id = id,
            .selectable = false,
            .liveness = .degraded,
            .availability = .unknown,
        },
        .credential_unavailable => .{
            .id = id,
            .selectable = false,
            .liveness = .live,
            .availability = .unknown,
        },
        .provider_degraded => .{
            .id = id,
            .selectable = false,
            .liveness = .degraded,
            .availability = .unknown,
        },
    };
}

test "AccountPool markQuotaExhausted blocks selection until reset" {
    var pool = AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try pool.add(.{ .id = "codex:max-1", .selectable = true, .liveness = .live, .availability = .available });
    try pool.add(.{ .id = "codex:max-2", .selectable = true, .liveness = .live, .availability = .available });

    try pool.markQuotaExhausted("codex:max-1", 1_800_000_000);
    const a = try pool.elect(null, null, &.{});
    try std.testing.expectEqualStrings("codex:max-2", a.id);

    // After reset clock passes, refreshTimeBased restores selectability.
    pool.refreshTimeBased(1_800_000_001);
    var found_max1_available = false;
    for (pool.accounts.items) |entry| {
        if (std.mem.eql(u8, entry.id, "codex:max-1")) {
            try std.testing.expect(entry.selectable);
            try std.testing.expectEqual(Availability.available, entry.availability);
            found_max1_available = true;
        }
    }
    try std.testing.expect(found_max1_available);
}

test "AccountPool markProviderDegraded blocks selection until retry window" {
    var pool = AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try pool.add(.{ .id = "codex:max-1", .selectable = true, .liveness = .live, .availability = .available });
    try pool.add(.{ .id = "codex:max-2", .selectable = true, .liveness = .live, .availability = .available });

    try pool.markProviderDegraded("codex:max-1", 1_800_000_060);
    const elected = try pool.elect(null, null, &.{});
    try std.testing.expectEqualStrings("codex:max-2", elected.id);

    pool.refreshTimeBased(1_800_000_059);
    const before_window = try pool.elect(null, null, &.{});
    try std.testing.expectEqualStrings("codex:max-2", before_window.id);

    pool.refreshTimeBased(1_800_000_060);
    var found_max1_available = false;
    for (pool.accounts.items) |entry| {
        if (std.mem.eql(u8, entry.id, "codex:max-1")) {
            try std.testing.expect(entry.selectable);
            try std.testing.expectEqual(Liveness.live, entry.liveness);
            try std.testing.expectEqual(Availability.available, entry.availability);
            found_max1_available = true;
        }
    }
    try std.testing.expect(found_max1_available);
}

test "AccountPool markUnauthorized stays dead through refresh" {
    var pool = AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try pool.add(.{ .id = "codex:max-1", .selectable = true, .liveness = .live, .availability = .available });

    try pool.markUnauthorized("codex:max-1");
    try std.testing.expectError(
        types.BrokerError.NoAccountSelectable,
        pool.elect(null, null, &.{}),
    );
    pool.refreshTimeBased(std.math.maxInt(i64));
    // Dead is sticky — refresh does not resurrect it.
    try std.testing.expectError(
        types.BrokerError.NoAccountSelectable,
        pool.elect(null, null, &.{}),
    );
}

test "AccountPool restrictToAllowList narrows selectability" {
    var pool = AccountPool.init(std.testing.allocator);
    defer pool.deinit();
    try pool.add(.{ .id = "codex:max-1", .selectable = true, .liveness = .live, .availability = .available });
    try pool.add(.{ .id = "codex:max-2", .selectable = true, .liveness = .live, .availability = .available });
    try pool.add(.{ .id = "claude:personal", .selectable = true, .liveness = .live, .availability = .available });

    pool.restrictToAllowList(&.{ "codex:max-1", "codex:max-2" });
    try std.testing.expectEqual(@as(usize, 3), pool.accounts.items.len);

    const elected = try pool.elect(null, null, &.{});
    try std.testing.expect(std.mem.eql(u8, elected.id, "codex:max-1"));

    // claude:personal is non-selectable now
    var found = false;
    for (pool.accounts.items) |a| {
        if (std.mem.eql(u8, a.id, "claude:personal")) {
            found = true;
            try std.testing.expect(!a.selectable);
        }
    }
    try std.testing.expect(found);
}

test "AccountPool deterministic route-state matrix skips blocked accounts across 1-4 pools" {
    const ids = [_][]const u8{
        "codex:max-1",
        "codex:max-2",
        "codex:max-3",
        "codex:max-4",
    };
    const blocked_states = [_]ElectionMatrixState{
        .auth_dead,
        .quota_exhausted,
        .rate_limited,
        .tier_insufficient,
        .credential_unavailable,
        .provider_degraded,
    };

    var pool_size: usize = 1;
    while (pool_size <= ids.len) : (pool_size += 1) {
        for (blocked_states) |blocked_state| {
            var pool = AccountPool.init(std.testing.allocator);
            defer pool.deinit();

            var idx: usize = 0;
            while (idx < pool_size) : (idx += 1) {
                const state: ElectionMatrixState = if (pool_size > 1 and idx + 1 == pool_size)
                    .available
                else
                    blocked_state;
                try pool.add(matrixAccountSummary(ids[idx], state));
            }

            if (pool_size == 1) {
                try std.testing.expectError(
                    types.BrokerError.NoAccountSelectable,
                    pool.elect(null, null, &.{}),
                );
            } else {
                const elected = try pool.elect(null, null, &.{});
                try std.testing.expectEqualStrings(ids[pool_size - 1], elected.id);
            }
        }
    }
}

test "AccountPool deterministic route-state matrix skips attempted accounts across 1-4 pools" {
    const ids = [_][]const u8{
        "codex:max-1",
        "codex:max-2",
        "codex:max-3",
        "codex:max-4",
    };

    var pool_size: usize = 1;
    while (pool_size <= ids.len) : (pool_size += 1) {
        var pool = AccountPool.init(std.testing.allocator);
        defer pool.deinit();

        var idx: usize = 0;
        while (idx < pool_size) : (idx += 1) {
            try pool.add(matrixAccountSummary(ids[idx], .available));
        }

        var attempted: [4][]const u8 = undefined;
        var attempted_count: usize = 0;
        while (attempted_count + 1 < pool_size) : (attempted_count += 1) {
            attempted[attempted_count] = ids[attempted_count];
        }

        const elected = try pool.elect(null, null, attempted[0..attempted_count]);
        try std.testing.expectEqualStrings(ids[pool_size - 1], elected.id);

        attempted[attempted_count] = ids[pool_size - 1];
        attempted_count += 1;
        try std.testing.expectError(
            types.BrokerError.NoAccountSelectable,
            pool.elect(null, null, attempted[0..attempted_count]),
        );
    }
}

test "AccountPool.elect property: never returns excluded id (random)" {
    // PBT: 100 random pool configurations; assert elect never returns
    // an id that's in the exclude slice. Catches off-by-one in the
    // continue:outer loop.
    var prng = std.Random.DefaultPrng.init(0xDEADBEEF);
    const r = prng.random();
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        var pool = AccountPool.init(std.testing.allocator);
        defer pool.deinit();

        const n = 1 + r.intRangeAtMost(usize, 0, 7); // 1..8 accounts
        var ids_buf: [8][]const u8 = undefined;
        const id_strs = [_][]const u8{
            "codex:a", "codex:b", "codex:c", "codex:d",
            "codex:e", "codex:f", "codex:g", "codex:h",
        };
        var j: usize = 0;
        while (j < n) : (j += 1) {
            try pool.add(.{
                .id = id_strs[j],
                .selectable = true,
                .liveness = .live,
                .availability = .available,
            });
            ids_buf[j] = id_strs[j];
        }

        // Random exclude: each id is in/out independently with p=0.5.
        var exc_buf: [8][]const u8 = undefined;
        var exc_count: usize = 0;
        for (ids_buf[0..n]) |id| {
            if (r.boolean()) {
                exc_buf[exc_count] = id;
                exc_count += 1;
            }
        }

        const elected = pool.elect(null, null, exc_buf[0..exc_count]) catch {
            // No selectable account is acceptable (all-excluded).
            // Verify that all ids are in fact excluded.
            try std.testing.expectEqual(n, exc_count);
            continue;
        };
        // Elected id MUST NOT appear in the exclude slice.
        for (exc_buf[0..exc_count]) |ex| {
            try std.testing.expect(!std.mem.eql(u8, ex, elected.id));
        }
    }
}

test "AccountPool elect honors exclude" {
    var pool = AccountPool.init(std.testing.allocator);
    defer pool.deinit();

    try pool.add(.{ .id = "codex:max-1", .selectable = true, .liveness = .live, .availability = .available });
    try pool.add(.{ .id = "codex:max-2", .selectable = true, .liveness = .live, .availability = .available });

    const a = try pool.elect(null, null, &.{});
    try std.testing.expectEqualStrings("codex:max-1", a.id);

    const b = try pool.elect(null, null, &.{"codex:max-1"});
    try std.testing.expectEqualStrings("codex:max-2", b.id);

    try std.testing.expectError(
        types.BrokerError.NoAccountSelectable,
        pool.elect(null, null, &.{ "codex:max-1", "codex:max-2" }),
    );
}
