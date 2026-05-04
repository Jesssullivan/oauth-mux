//! Session table. Sessions are scoped to one adapter handshake and live
//! for the duration of that adapter's MCP connection.

const std = @import("std");
const types = @import("types.zig");

pub const Session = struct {
    id: []const u8,
    adapter: []const u8, // e.g. "codex"
    adapter_version: []const u8,
    harness_target: []const u8,
    session_pid: u32,
    claim_floor: types.ClaimLevel,
    started_at_ms: i64,
    /// Adapter's currently-elected account, if any. Updated on
    /// `account/select` and `account/swap`.
    current_account: ?[]const u8 = null,
    policy: types.Policy = .{},
};

pub const SessionTable = struct {
    allocator: std.mem.Allocator,
    /// Maps session id -> Session. Owns string memory for ids and adapter
    /// fields.
    map: std.StringHashMap(Session),
    /// Monotonic counter for id generation.
    next_id: u64 = 1,
    rand: std.Random.DefaultPrng,

    pub fn init(allocator: std.mem.Allocator) SessionTable {
        const seed: u64 = @intCast(std.time.nanoTimestamp() & std.math.maxInt(u64));
        return .{
            .allocator = allocator,
            .map = std.StringHashMap(Session).init(allocator),
            .rand = std.Random.DefaultPrng.init(seed),
        };
    }

    pub fn deinit(self: *SessionTable) void {
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.adapter);
            self.allocator.free(entry.value_ptr.adapter_version);
            self.allocator.free(entry.value_ptr.harness_target);
            if (entry.value_ptr.current_account) |a| self.allocator.free(a);
        }
        self.map.deinit();
    }

    /// Generate a fresh opaque session id. Format: `oms-<base36-counter>-<rand-hex>`.
    pub fn newId(self: *SessionTable) ![]const u8 {
        const counter = self.next_id;
        self.next_id += 1;
        const r = self.rand.random().int(u32);
        return std.fmt.allocPrint(self.allocator, "oms-{x}-{x}", .{ counter, r });
    }

    pub fn create(self: *SessionTable, s: Session) !void {
        const owned_id = try self.allocator.dupe(u8, s.id);
        errdefer self.allocator.free(owned_id);
        var owned = s;
        owned.id = owned_id;
        owned.adapter = try self.allocator.dupe(u8, s.adapter);
        owned.adapter_version = try self.allocator.dupe(u8, s.adapter_version);
        owned.harness_target = try self.allocator.dupe(u8, s.harness_target);
        try self.map.put(owned_id, owned);
    }

    pub fn get(self: *SessionTable, id: []const u8) ?Session {
        return self.map.get(id);
    }

    pub fn drop(self: *SessionTable, id: []const u8) bool {
        const entry = self.map.fetchRemove(id) orelse return false;
        self.allocator.free(entry.key);
        self.allocator.free(entry.value.adapter);
        self.allocator.free(entry.value.adapter_version);
        self.allocator.free(entry.value.harness_target);
        if (entry.value.current_account) |a| self.allocator.free(a);
        return true;
    }
};

test "SessionTable.newId property: 1000 ids never collide" {
    // PBT (broker-spec §2.1 surface/handshake): minted session ids
    // must be globally unique within a SessionTable lifetime so the
    // adapter's session_id can't accidentally alias an old session.
    var t = SessionTable.init(std.testing.allocator);
    defer t.deinit();

    var seen = std.StringHashMap(void).init(std.testing.allocator);
    defer {
        var it = seen.iterator();
        while (it.next()) |e| std.testing.allocator.free(e.key_ptr.*);
        seen.deinit();
    }

    var i: usize = 0;
    while (i < 1000) : (i += 1) {
        const id = try t.newId();
        // Property: id is never empty.
        try std.testing.expect(id.len > 0);
        // Property: id starts with our prefix.
        try std.testing.expect(std.mem.startsWith(u8, id, "oms-"));
        // Property: never collides with any prior id.
        const gop = try seen.getOrPut(id);
        if (gop.found_existing) {
            std.testing.allocator.free(id);
            return error.IdCollision;
        }
        // hand the id over to the seen-set; it owns the memory.
    }
}

test "SessionTable create/get/drop" {
    var t = SessionTable.init(std.testing.allocator);
    defer t.deinit();

    const id = try t.newId();
    defer std.testing.allocator.free(id);

    try t.create(.{
        .id = id,
        .adapter = "codex",
        .adapter_version = "0.1.0",
        .harness_target = "codex 0.128.0",
        .session_pid = 1234,
        .claim_floor = .broker_owned,
        .started_at_ms = std.time.milliTimestamp(),
    });

    const got = t.get(id) orelse return error.TestFailed;
    try std.testing.expectEqualStrings("codex", got.adapter);

    try std.testing.expect(t.drop(id));
    try std.testing.expect(t.get(id) == null);
}
