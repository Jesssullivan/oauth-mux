//! Grant ciphertext format. Plaintext never enters SQLite. Account, grant,
//! generation, purpose and scope are authenticated independently of the row.
const std = @import("std");

const Aead = std.crypto.aead.chacha_poly.XChaCha20Poly1305;
pub const Key = [Aead.key_length]u8;
pub const default_key_id = "installation-v1";
const magic = "OMUXG001";
const header_length = magic.len + Aead.nonce_length + Aead.tag_length;
pub const maximum_plaintext = 1024 * 1024;
const maximum_context_field = 16 * 1024;

pub const Context = struct {
    key_id: []const u8 = default_key_id,
    account_id: []const u8,
    grant_id: []const u8,
    generation: u64,
    purpose: []const u8,
    scope: []const u8,

    pub fn validate(self: Context) !void {
        if (self.generation == 0) return error.InvalidGeneration;
        for ([_][]const u8{ self.key_id, self.account_id, self.grant_id, self.purpose }) |field| {
            if (field.len == 0 or field.len > maximum_context_field) return error.InvalidContext;
        }
        if (self.scope.len > maximum_context_field) return error.InvalidContext;
    }
};

/// Owned plaintext. Release with deinit even after application transport fails.
pub const Secret = struct {
    allocator: std.mem.Allocator,
    bytes: []u8,

    pub fn deinit(self: *Secret) void {
        std.crypto.secureZero(u8, self.bytes);
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

fn associatedData(allocator: std.mem.Allocator, context: Context) ![]u8 {
    try context.validate();
    const fields = [_][]const u8{ context.key_id, context.account_id, context.grant_id, context.purpose, context.scope };
    var length: usize = magic.len + 8;
    for (fields) |field| length += 4 + field.len;
    const result = try allocator.alloc(u8, length);
    @memcpy(result[0..magic.len], magic);
    std.mem.writeInt(u64, result[magic.len..][0..8], context.generation, .little);
    var cursor: usize = magic.len + 8;
    for (fields) |field| {
        std.mem.writeInt(u32, result[cursor..][0..4], @intCast(field.len), .little);
        cursor += 4;
        @memcpy(result[cursor..][0..field.len], field);
        cursor += field.len;
    }
    return result;
}

/// No entropy fallback: failing to acquire a secure nonce aborts the write.
/// The caller owns and must scrub its input plaintext buffer.
pub fn seal(io: std.Io, allocator: std.mem.Allocator, key: Key, context: Context, plaintext: []const u8) ![]u8 {
    if (plaintext.len > maximum_plaintext) return error.GrantTooLarge;
    const ad = try associatedData(allocator, context);
    defer allocator.free(ad);
    var nonce: [Aead.nonce_length]u8 = undefined;
    try io.randomSecure(&nonce);
    const result = try allocator.alloc(u8, header_length + plaintext.len);
    @memcpy(result[0..magic.len], magic);
    @memcpy(result[magic.len..][0..Aead.nonce_length], &nonce);
    const tag: *[Aead.tag_length]u8 = result[magic.len + Aead.nonce_length ..][0..Aead.tag_length];
    Aead.encrypt(result[header_length..], tag, plaintext, ad, nonce, key);
    return result;
}

pub fn open(allocator: std.mem.Allocator, key: Key, context: Context, ciphertext: []const u8) !Secret {
    if (ciphertext.len < header_length or ciphertext.len > header_length + maximum_plaintext) return error.InvalidEnvelope;
    if (!std.mem.eql(u8, ciphertext[0..magic.len], magic)) return error.InvalidEnvelope;
    const ad = try associatedData(allocator, context);
    defer allocator.free(ad);
    const bytes = try allocator.alloc(u8, ciphertext.len - header_length);
    errdefer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    const nonce = ciphertext[magic.len..][0..Aead.nonce_length].*;
    const tag = ciphertext[magic.len + Aead.nonce_length ..][0..Aead.tag_length].*;
    try Aead.decrypt(bytes, ciphertext[header_length..], tag, ad, nonce, key);
    return .{ .allocator = allocator, .bytes = bytes };
}

test "grants authenticate every authority field and cannot be swapped" {
    const allocator = std.testing.allocator;
    const key: Key = @splat(42);
    const context: Context = .{ .account_id = "a", .grant_id = "g", .generation = 1, .purpose = "request", .scope = "read" };
    const ciphertext = try seal(std.testing.io, allocator, key, context, "a-secret-token");
    defer allocator.free(ciphertext);
    var secret = try open(allocator, key, context, ciphertext);
    defer secret.deinit();
    try std.testing.expectEqualStrings("a-secret-token", secret.bytes);
    for ([_]Context{
        .{ .key_id = "installation-v2", .account_id = "a", .grant_id = "g", .generation = 1, .purpose = "request", .scope = "read" },
        .{ .account_id = "b", .grant_id = "g", .generation = 1, .purpose = "request", .scope = "read" },
        .{ .account_id = "a", .grant_id = "h", .generation = 1, .purpose = "request", .scope = "read" },
        .{ .account_id = "a", .grant_id = "g", .generation = 2, .purpose = "request", .scope = "read" },
        .{ .account_id = "a", .grant_id = "g", .generation = 1, .purpose = "observation", .scope = "read" },
        .{ .account_id = "a", .grant_id = "g", .generation = 1, .purpose = "request", .scope = "write" },
    }) |swapped| try std.testing.expectError(error.AuthenticationFailed, open(allocator, key, swapped, ciphertext));
    ciphertext[ciphertext.len - 1] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, open(allocator, key, context, ciphertext));
}

test "context encoding is unambiguous and malformed envelopes fail closed" {
    const allocator = std.testing.allocator;
    const key: Key = @splat(7);
    const context: Context = .{ .account_id = "ab", .grant_id = "c", .generation = 1, .purpose = "request", .scope = "" };
    const ciphertext = try seal(std.testing.io, allocator, key, context, "secret");
    defer allocator.free(ciphertext);
    var ambiguous = context;
    ambiguous.account_id = "a";
    ambiguous.grant_id = "bc";
    try std.testing.expectError(error.AuthenticationFailed, open(allocator, key, ambiguous, ciphertext));
    try std.testing.expectError(error.InvalidEnvelope, open(allocator, key, context, ciphertext[0..10]));
    try std.testing.expectError(error.AuthenticationFailed, open(allocator, @splat(8), context, ciphertext));
    const second = try seal(std.testing.io, allocator, key, context, "secret");
    defer allocator.free(second);
    try std.testing.expect(!std.mem.eql(u8, ciphertext, second));
}
