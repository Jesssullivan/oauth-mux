//! Bounded refusal replay authority for browser enrollment ingress.
//! Caller must establish an existing authorized connected source/context before
//! using this ledger. Syntax/provenance claims alone are not that authority.
//! Persist a fresh refusal and its lifecycle counter in the SAME authenticated
//! engine snapshot transaction before acknowledging it. Never count replay.
//! This does not admit grants or enable any production browser export.
const std = @import("std");
const reliability = @import("reliability.zig");

pub const max_records = 256;
pub const max_id_bytes = 64;
pub const max_payload_bytes = 256 * 1024;
pub const maximum_snapshot_bytes = 512 * 1024;
pub const Refusal = enum { needs_provider_adapter_proof };
pub const Record = struct {
    context_key: [32]u8,
    id: [max_id_bytes]u8 = @splat(0),
    id_len: u8,
    intent_fingerprint: [32]u8,
    refusal: Refusal,
    cause: reliability.Cause,
};
pub const Snapshot = struct {
    version: u32 = 1,
    records: []const Record = &.{},
};
pub const Decision = union(enum) { fresh: usize, replay: *const Record };

pub const Ledger = struct {
    allocator: std.mem.Allocator,
    records: []Record,
    count: usize = 0,

    pub fn init(allocator: std.mem.Allocator) !Ledger {
        return .{ .allocator = allocator, .records = try allocator.alloc(Record, max_records) };
    }
    pub fn deinit(self: *Ledger) void {
        self.allocator.free(self.records);
        self.* = undefined;
    }
    pub fn snapshot(self: *const Ledger) Snapshot {
        return .{ .records = self.records[0..self.count] };
    }
    pub fn fromSnapshot(allocator: std.mem.Allocator, saved: Snapshot) !Ledger {
        if (saved.version != 1 or saved.records.len > max_records) return error.InvalidBrowserAttemptSnapshot;
        var result = try init(allocator);
        errdefer result.deinit();
        for (saved.records) |record| {
            if (record.id_len == 0 or record.id_len > max_id_bytes or !validId(record.id[0..record.id_len])) return error.InvalidBrowserAttemptSnapshot;
            // Padding is canonical; it must not hide arbitrary retained data.
            for (record.id[record.id_len..]) |byte| if (byte != 0) return error.InvalidBrowserAttemptSnapshot;
            for (result.records[0..result.count]) |previous| {
                if (std.mem.eql(u8, &previous.context_key, &record.context_key) and std.mem.eql(u8, previous.id[0..previous.id_len], record.id[0..record.id_len])) return error.InvalidBrowserAttemptSnapshot;
            }
            result.records[result.count] = record;
            result.count += 1;
        }
        return result;
    }
    /// A request ID is stable only within its authorized source generation.
    /// Exact-byte intent replay is the contract: a changed payload cannot reuse
    /// the same ID to become a second opportunity. IDs never expire or evict.
    pub fn refuse(self: *Ledger, context_key: [32]u8, id: []const u8, intent_fingerprint: [32]u8, refusal: Refusal, cause: reliability.Cause) !Decision {
        if (!validId(id)) return error.InvalidBrowserAttemptId;
        for (self.records[0..self.count]) |*record| {
            if (!std.mem.eql(u8, &record.context_key, &context_key) or !std.mem.eql(u8, record.id[0..record.id_len], id)) continue;
            if (!std.mem.eql(u8, &record.intent_fingerprint, &intent_fingerprint)) return error.BrowserAttemptConflict;
            // The original terminal classification is immutable across updates.
            return .{ .replay = record };
        }
        if (self.count == self.records.len) return error.BrowserAttemptCapacity;
        const slot = self.count;
        self.records[slot] = .{ .context_key = context_key, .id_len = @intCast(id.len), .intent_fingerprint = intent_fingerprint, .refusal = refusal, .cause = cause };
        @memcpy(self.records[slot].id[0..id.len], id);
        self.count += 1;
        return .{ .fresh = slot };
    }
};

fn validId(id: []const u8) bool {
    if (id.len == 0 or id.len > max_id_bytes) return false;
    for (id) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '-' and byte != ':' and byte != '.') return false;
    return true;
}

/// Installation-keyed digest avoids storing browser labels/source IDs here.
/// Four bounded fields are browser, extension ID, source ID and adapter.
pub fn contextKey(key: [32]u8, parts: [4][]const u8, source_generation: u64) ![32]u8 {
    if (source_generation == 0) return error.InvalidBrowserAttemptContext;
    var message: [1024]u8 = undefined;
    const domain = "omux.browser-refusal.context.v1";
    @memcpy(message[0..domain.len], domain);
    var used: usize = domain.len;
    for (parts) |part| {
        if (part.len == 0 or part.len > 128) return error.InvalidBrowserAttemptContext;
        std.mem.writeInt(u32, message[used..][0..4], @intCast(part.len), .little);
        used += 4;
        @memcpy(message[used..][0..part.len], part);
        used += part.len;
    }
    std.mem.writeInt(u64, message[used..][0..8], source_generation, .little);
    used += 8;
    var digest: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&digest, message[0..used], &key);
    return digest;
}

pub fn fingerprint(key: [32]u8, bounded_payload: []const u8) ![32]u8 {
    if (bounded_payload.len == 0 or bounded_payload.len > max_payload_bytes) return error.InvalidBrowserAttemptPayload;
    var domain_key: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&domain_key, "omux.browser-refusal.intent.v1", &key);
    defer std.crypto.secureZero(u8, &domain_key);
    var digest: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&digest, bounded_payload, &domain_key);
    return digest;
}
