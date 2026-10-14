//! Bounded OAuth wire encoding and response evidence. These types never issue
//! HTTP, certify a registration/family, activate a grant, or choose a writer.
const std = @import("std");
const envelope = @import("envelope.zig");

pub const max_body_bytes = 64 * 1024;
pub const max_credential_bytes = 16 * 1024;
pub const Encoding = enum { form, json };
pub const Code = struct {
    code: []const u8,
    verifier: []const u8,
    redirect_uri: []const u8,
};
pub const Grant = union(enum) {
    code: Code,
    refresh: []const u8,
};

/// Only the separately sealed issued-ticket channel can dispatch this output.
/// Calling an encoder does not provide provider authority.
pub fn encode(a: std.mem.Allocator, encoding: Encoding, client_id: []const u8, resource: ?[]const u8, grant: Grant) !envelope.Secret {
    try visible(client_id, 256);
    if (resource) |value| try visible(value, 2048);
    switch (grant) {
        .code => |code| {
            try visible(code.code, 4096);
            try visible(code.redirect_uri, 2048);
            if (code.verifier.len < 43 or code.verifier.len > 128) return error.InvalidOAuthVerifier;
            for (code.verifier) |byte| if (!unreserved(byte)) return error.InvalidOAuthVerifier;
        },
        .refresh => |refresh| try visible(refresh, max_credential_bytes),
    }
    var storage: [max_body_bytes]u8 = undefined;
    defer std.crypto.secureZero(u8, &storage);
    var body: Writer = .{ .storage = &storage };
    if (encoding == .json) try body.byte('{');
    try body.field(encoding, "grant_type", if (grant == .code) "authorization_code" else "refresh_token");
    try body.field(encoding, "client_id", client_id);
    switch (grant) {
        .code => |code| {
            try body.field(encoding, "code", code.code);
            try body.field(encoding, "redirect_uri", code.redirect_uri);
            try body.field(encoding, "code_verifier", code.verifier);
        },
        .refresh => |refresh| try body.field(encoding, "refresh_token", refresh),
    }
    if (resource) |value| try body.field(encoding, "resource", value);
    if (encoding == .json) try body.byte('}');
    return .{ .allocator = a, .bytes = try a.dupe(u8, storage[0..body.length]) };
}

fn visible(value: []const u8, limit: usize) !void {
    if (value.len == 0 or value.len > limit) return error.InvalidOAuthField;
    for (value) |byte| if (byte < 0x20 or byte > 0x7e) return error.InvalidOAuthField;
}
fn unreserved(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '.' or byte == '_' or byte == '~';
}
const Writer = struct {
    storage: []u8,
    length: usize = 0,
    fields: usize = 0,
    fn byte(self: *Writer, value: u8) !void {
        if (self.length == self.storage.len) return error.OAuthRequestTooLarge;
        self.storage[self.length] = value;
        self.length += 1;
    }
    fn text(self: *Writer, value: []const u8) !void {
        for (value) |v| try self.byte(v);
    }
    fn percent(self: *Writer, value: []const u8) !void {
        const hex = "0123456789ABCDEF";
        for (value) |v| {
            if (unreserved(v)) {
                try self.byte(v);
            } else {
                try self.byte('%');
                try self.byte(hex[v >> 4]);
                try self.byte(hex[v & 15]);
            }
        }
    }
    fn quoted(self: *Writer, value: []const u8) !void {
        try self.byte('"');
        for (value) |v| {
            if (v == '"' or v == '\\') try self.byte('\\');
            try self.byte(v);
        }
        try self.byte('"');
    }
    fn field(self: *Writer, encoding: Encoding, name: []const u8, value: []const u8) !void {
        if (self.fields != 0) try self.byte(if (encoding == .form) '&' else ',');
        if (encoding == .form) {
            try self.percent(name);
            try self.byte('=');
            try self.percent(value);
        } else {
            try self.quoted(name);
            try self.byte(':');
            try self.quoted(value);
        }
        self.fields += 1;
    }
};

/// Owned unverified token response. Omitted refresh/expiry/scope are evidence
/// gaps; this parser never restores an old refresh token or grants authority.
pub const Evidence = struct {
    allocator: std.mem.Allocator,
    response_sha256: [32]u8,
    access_token: []u8,
    refresh_token: ?[]u8,
    id_token: ?[]u8,
    expires_in: ?u32,
    // Unverified response metadata. The parser supplies no scheduling units,
    // authenticated deadline or renewal permission from this integer.
    earliest_refresh_at: ?i64,
    scope: ?[]u8,
    pub fn deinit(self: *Evidence) void {
        const a = self.allocator;
        for ([_]?[]u8{ self.access_token, self.refresh_token, self.id_token, self.scope }) |value| if (value) |bytes| {
            std.crypto.secureZero(u8, bytes);
            a.free(bytes);
        };
        self.* = undefined;
    }
};

pub fn parse(a: std.mem.Allocator, status: u16, body: []const u8) !Evidence {
    if (body.len > max_body_bytes) return error.OAuthResponseTooLarge;
    // No provider response body/detail is returned as a diagnostic.
    if (status != 200) return error.OAuthEndpointRejected;
    var scratch: [max_body_bytes * 4]u8 = undefined;
    defer std.crypto.secureZero(u8, &scratch);
    var fixed = std.heap.FixedBufferAllocator.init(&scratch);
    var parsed = std.json.parseFromSlice(std.json.Value, fixed.allocator(), body, .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error", .max_value_len = max_credential_bytes }) catch return error.InvalidOAuthResponse;
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidOAuthResponse;
    const object = parsed.value.object;
    if (object.contains("error")) return error.OAuthEndpointRejected;
    const token_type = try string(object, "token_type", 16);
    if (!std.ascii.eqlIgnoreCase(token_type, "Bearer")) return error.InvalidOAuthResponse;
    const access = try string(object, "access_token", max_credential_bytes);
    const refresh = try optionalString(object, "refresh_token", max_credential_bytes);
    const identity = try optionalString(object, "id_token", max_credential_bytes);
    const scopes = try optionalString(object, "scope", 4096);
    var expires: ?u32 = null;
    if (object.get("expires_in")) |value| {
        if (value != .integer or value.integer <= 0 or value.integer > 31_536_000) return error.InvalidOAuthResponse;
        expires = @intCast(value.integer);
    }
    var earliest: ?i64 = null;
    if (object.get("earliest_refresh_at")) |value| {
        if (value != .integer or value.integer < 0 or value.integer > 253_402_300_799) return error.InvalidOAuthResponse;
        earliest = value.integer;
    }
    var response_sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &response_sha256, .{});
    var result: Evidence = .{ .allocator = a, .response_sha256 = response_sha256, .access_token = try a.dupe(u8, access), .refresh_token = null, .id_token = null, .expires_in = expires, .earliest_refresh_at = earliest, .scope = null };
    errdefer result.deinit();
    result.refresh_token = if (refresh) |value| try a.dupe(u8, value) else null;
    result.id_token = if (identity) |value| try a.dupe(u8, value) else null;
    result.scope = if (scopes) |value| try a.dupe(u8, value) else null;
    return result;
}
fn string(object: std.json.ObjectMap, name: []const u8, limit: usize) ![]const u8 {
    const value = object.get(name) orelse return error.InvalidOAuthResponse;
    if (value != .string) return error.InvalidOAuthResponse;
    visible(value.string, limit) catch return error.InvalidOAuthResponse;
    return value.string;
}
fn optionalString(object: std.json.ObjectMap, name: []const u8, limit: usize) !?[]const u8 {
    if (!object.contains(name)) return null;
    return try string(object, name, limit);
}

test "OAuth form and JSON encoding preserve secret fields without parameter injection" {
    const a = std.testing.allocator;
    const verifier: [43]u8 = @splat('v');
    var form = try encode(a, .form, "fixture-client", null, .{ .code = .{ .code = "synthetic+code&=", .verifier = &verifier, .redirect_uri = "http://localhost:1455/auth/callback" } });
    defer form.deinit();
    try std.testing.expect(std.mem.indexOf(u8, form.bytes, "code=synthetic%2Bcode%26%3D&redirect_uri=http%3A%2F%2Flocalhost%3A1455%2Fauth%2Fcallback&code_verifier=") != null);
    try std.testing.expect(std.mem.indexOf(u8, form.bytes, "resource=") == null);
    var json = try encode(a, .json, "fixture-client", "urn:fixture", .{ .refresh = "synthetic\\refresh\"&" });
    defer json.deinit();
    var parsed = try std.json.parseFromSlice(std.json.Value, a, json.bytes, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("synthetic\\refresh\"&", parsed.value.object.get("refresh_token").?.string);
    try std.testing.expectEqualStrings("refresh_token", parsed.value.object.get("grant_type").?.string);
    try std.testing.expectEqualStrings("urn:fixture", parsed.value.object.get("resource").?.string);
}
test "OAuth response evidence refuses duplicates and malformed or unbounded tokens" {
    const a = std.testing.allocator;
    var result = try parse(a, 200, "{\"access_token\":\"synthetic-access\",\"refresh_token\":\"synthetic-refresh\",\"token_type\":\"Bearer\",\"expires_in\":3600,\"scope\":\"openid offline_access\"}");
    defer result.deinit();
    try std.testing.expectEqual(@as(?u32, 3600), result.expires_in);
    try std.testing.expectEqualStrings("synthetic-refresh", result.refresh_token.?);
    var omitted = try parse(a, 200, "{\"access_token\":\"synthetic-access\",\"token_type\":\"bearer\"}");
    defer omitted.deinit();
    try std.testing.expect(omitted.refresh_token == null and omitted.expires_in == null and omitted.scope == null and omitted.earliest_refresh_at == null);
    for ([_][]const u8{
        "{\"access_token\":\"a\",\"access_token\":\"b\",\"token_type\":\"Bearer\"}",
        "{\"access_token\":\"a\",\"token_type\":\"Basic\"}",
        "{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"expires_in\":-1}",
        "{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"refresh_token\":null}",
        "{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"earliest_refresh_at\":-1}",
        "{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"earliest_refresh_at\":253402300800}",
        "{\"access_token\":\"a\",\"token_type\":\"Bearer\",\"earliest_refresh_at\":\"later\"}",
    }) |bad| try std.testing.expectError(error.InvalidOAuthResponse, parse(a, 200, bad));
    try std.testing.expectError(error.OAuthEndpointRejected, parse(a, 302, "provider-body-is-not-a-diagnostic"));
    const large: [max_body_bytes + 1]u8 = @splat('x');
    try std.testing.expectError(error.OAuthResponseTooLarge, parse(a, 200, &large));
}
test "OAuth encoding and parse allocation failure cannot leak a partial secret result" {
    const a = std.testing.allocator;
    var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, encode(fail.allocator(), .json, "fixture", null, .{ .refresh = "synthetic-refresh" }));
    var second = std.testing.FailingAllocator.init(a, .{ .fail_index = 1 });
    try std.testing.expectError(error.OutOfMemory, parse(second.allocator(), 200, "{\"access_token\":\"synthetic-access\",\"refresh_token\":\"synthetic-refresh\",\"token_type\":\"Bearer\"}"));
    const excessive: [max_credential_bytes + 1]u8 = @splat('x');
    try std.testing.expectError(error.InvalidOAuthField, encode(a, .json, "fixture", null, .{ .refresh = &excessive }));
}

test "Omux OSS token wire keeps issued client and API resource together and omits refresh scope" {
    const a = std.testing.allocator;
    const verifier: [43]u8 = @splat('v');
    var code = try encode(a, .form, "oaiapp_synthetic_fixture", "https://api.openai.com/v1", .{ .code = .{ .code = "synthetic-code", .verifier = &verifier, .redirect_uri = "http://127.0.0.1:54321/auth/callback" } });
    defer code.deinit();
    try std.testing.expect(std.mem.indexOf(u8, code.bytes, "client_id=oaiapp_synthetic_fixture&code=synthetic-code&redirect_uri=http%3A%2F%2F127.0.0.1%3A54321%2Fauth%2Fcallback&code_verifier=") != null);
    try std.testing.expect(std.mem.endsWith(u8, code.bytes, "&resource=https%3A%2F%2Fapi.openai.com%2Fv1"));
    var refresh = try encode(a, .form, "oaiapp_synthetic_fixture", "https://api.openai.com/v1", .{ .refresh = "synthetic-owned-refresh" });
    defer refresh.deinit();
    try std.testing.expectEqualStrings("grant_type=refresh_token&client_id=oaiapp_synthetic_fixture&refresh_token=synthetic-owned-refresh&resource=https%3A%2F%2Fapi.openai.com%2Fv1", refresh.bytes);
    try std.testing.expect(std.mem.indexOf(u8, refresh.bytes, "scope=") == null);
    var metadata = try parse(a, 200, "{\"access_token\":\"synthetic-access\",\"token_type\":\"Bearer\",\"earliest_refresh_at\":1790032532}");
    defer metadata.deinit();
    try std.testing.expectEqual(@as(?i64, 1790032532), metadata.earliest_refresh_at);
    // This is wire syntax coverage, not a constructed renewal permit or family.
    try std.testing.expect(metadata.refresh_token == null and metadata.id_token == null);
    const raw = "{\"access_token\":\"synthetic-access\",\"token_type\":\"Bearer\",\"earliest_refresh_at\":1790032532}";
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &metadata.response_sha256);
}
