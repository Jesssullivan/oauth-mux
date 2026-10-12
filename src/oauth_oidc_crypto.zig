//! Bounded RS256/JWKS verification using the locked Zig 0.17 RSA implementation.
//! This module has no network/registration/activation authority. The profile
//! producer must supply only the transport owner's authenticated JWKS lease.
const std = @import("std");
const Hash = std.crypto.hash.sha2.Sha256;
const Rsa = std.crypto.Certificate.rsa;
pub const issuer = "https://auth.openai.com";
pub const max_jwt_bytes = 16 * 1024;
pub const max_jwks_bytes = 64 * 1024;
const max_keys = 16;

pub const Claims = struct {
    allocator: std.mem.Allocator,
    subject: []u8,
    expires_at: i64,
    issued_at: i64,
    access_token_hash: ?[16]u8,
    pub fn deinit(self: *Claims) void {
        std.crypto.secureZero(u8, self.subject);
        self.allocator.free(self.subject);
        self.* = undefined;
    }
};

/// Successful cryptography/claims are still not a registration/grant permit.
pub fn verifyIdToken(a: std.mem.Allocator, jwt: []const u8, jwks_bytes: []const u8, client: []const u8, nonce_digest: [32]u8, now: i64) !Claims {
    if (jwt.len == 0 or jwt.len > max_jwt_bytes or jwks_bytes.len == 0 or jwks_bytes.len > max_jwks_bytes) return error.OidcInputBound;
    var parts = std.mem.splitScalar(u8, jwt, '.');
    const header64 = parts.next() orelse return error.InvalidJose;
    const payload64 = parts.next() orelse return error.InvalidJose;
    const signature64 = parts.next() orelse return error.InvalidJose;
    if (parts.next() != null) return error.InvalidJose;
    var header: [2048]u8 = undefined;
    var payload: [12 * 1024]u8 = undefined;
    var signature: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &header);
    defer std.crypto.secureZero(u8, &payload);
    defer std.crypto.secureZero(u8, &signature);
    const header_raw = try decode64(&header, header64);
    const payload_raw = try decode64(&payload, payload64);
    const signature_raw = try decode64(&signature, signature64);
    var scratch: [512 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &scratch);
    var fixed = std.heap.FixedBufferAllocator.init(&scratch);
    const allocator = fixed.allocator();
    const parsed_header = try document(allocator, header_raw);
    defer parsed_header.deinit();
    const object = try asObject(parsed_header.value, 3);
    var fields = object.iterator();
    while (fields.next()) |row| {
        const name = row.key_ptr.*;
        if (!std.mem.eql(u8, name, "alg") and !std.mem.eql(u8, name, "kid") and !std.mem.eql(u8, name, "typ")) return error.UnsupportedJoseHeader;
    }
    if (!std.mem.eql(u8, try text(object, "alg", 16), "RS256")) return error.UnsupportedSigningAlgorithm;
    const kid = try text(object, "kid", 128);
    if (object.get("typ")) |value| {
        if (value != .string or !std.mem.eql(u8, value.string, "JWT")) return error.UnsupportedJoseHeader;
    }
    const parsed_keys = try document(allocator, jwks_bytes);
    defer parsed_keys.deinit();
    const key = try selectKey(parsed_keys.value, kid);
    const signing_input = jwt[0 .. header64.len + 1 + payload64.len];
    try verifyRsa(signing_input, signature_raw, key);
    // Claims cannot become authoritative before signature verification.
    const parsed_claims = try document(allocator, payload_raw);
    defer parsed_claims.deinit();
    const checked = try validateClaims(parsed_claims.value, client, nonce_digest, now);
    return .{ .allocator = a, .subject = try a.dupe(u8, checked.subject), .expires_at = checked.expires_at, .issued_at = checked.issued_at, .access_token_hash = checked.access_token_hash };
}


/// Refresh validates the signed resource token, not a fresh-login ID nonce.
/// This primitive has no HTTP/pair/renewal authority; only the opaque response
/// producer joins its claims to authenticated prior lineage and writer state.
pub const AccessClaims = struct {
    allocator: std.mem.Allocator,
    subject: []u8,
    scope: []u8,
    expires_at: i64,
    issued_at: i64,
    pub fn deinit(self: *AccessClaims) void {
        std.crypto.secureZero(u8, self.subject);
        std.crypto.secureZero(u8, self.scope);
        self.allocator.free(self.subject);
        self.allocator.free(self.scope);
        self.* = undefined;
    }
};
pub fn verifyAccessToken(a: std.mem.Allocator, jwt: []const u8, jwks_bytes: []const u8, client: []const u8, now: i64) !AccessClaims {
    if (jwt.len == 0 or jwt.len > max_jwt_bytes or jwks_bytes.len == 0 or jwks_bytes.len > max_jwks_bytes) return error.OidcInputBound;
    var parts = std.mem.splitScalar(u8, jwt, '.');
    const header64 = parts.next() orelse return error.InvalidJose;
    const payload64 = parts.next() orelse return error.InvalidJose;
    const signature64 = parts.next() orelse return error.InvalidJose;
    if (parts.next() != null) return error.InvalidJose;
    var header: [2048]u8 = undefined;
    var payload: [12 * 1024]u8 = undefined;
    var signature: [512]u8 = undefined;
    defer std.crypto.secureZero(u8, &header);
    defer std.crypto.secureZero(u8, &payload);
    defer std.crypto.secureZero(u8, &signature);
    const header_raw = try decode64(&header, header64);
    const payload_raw = try decode64(&payload, payload64);
    const signature_raw = try decode64(&signature, signature64);
    var scratch: [512 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &scratch);
    var fixed = std.heap.FixedBufferAllocator.init(&scratch);
    const allocator = fixed.allocator();
    const parsed_header = try document(allocator, header_raw);
    defer parsed_header.deinit();
    const object = try asObject(parsed_header.value, 3);
    var fields = object.iterator();
    while (fields.next()) |row| {
        const name = row.key_ptr.*;
        if (!std.mem.eql(u8, name, "alg") and !std.mem.eql(u8, name, "kid") and !std.mem.eql(u8, name, "typ")) return error.UnsupportedJoseHeader;
    }
    if (!std.mem.eql(u8, try text(object, "alg", 16), "RS256")) return error.UnsupportedSigningAlgorithm;
    const kid = try text(object, "kid", 128);
    if (object.get("typ")) |value| {
        if (value != .string or !std.mem.eql(u8, value.string, "JWT")) return error.UnsupportedJoseHeader;
    }
    const parsed_keys = try document(allocator, jwks_bytes);
    defer parsed_keys.deinit();
    const key = try selectKey(parsed_keys.value, kid);
    const signing_input = jwt[0 .. header64.len + 1 + payload64.len];
    try verifyRsa(signing_input, signature_raw, key);
    // Claims cannot become authoritative before signature verification.
    const parsed_claims = try document(allocator, payload_raw);
    defer parsed_claims.deinit();
    const checked = try validateAccessClaims(parsed_claims.value, client, now);
    const subject = try a.dupe(u8, checked.subject);
    errdefer { std.crypto.secureZero(u8, subject); a.free(subject); }
    const scope = try a.dupe(u8, checked.scope);
    return .{ .allocator = a, .subject = subject, .scope = scope, .expires_at = checked.expires_at, .issued_at = checked.issued_at };
}

const CheckedAccess = struct { subject: []const u8, scope: []const u8, expires_at: i64, issued_at: i64 };
fn validateAccessClaims(value: std.json.Value, client: []const u8, now: i64) !CheckedAccess {
    if (now <= 0 or now > 253_402_300_794) return error.InvalidOidcClock;
    try visible(client, 256);
    const object = try asObject(value, 32);
    if (!std.mem.eql(u8, try text(object, "iss", 128), issuer)) return error.OidcIssuerMismatch;
    if (!std.mem.eql(u8, try text(object, "aud", 128), "https://api.openai.com/v1")) return error.OidcAudienceMismatch;
    if (!std.mem.eql(u8, try text(object, "client_id", 256), client)) return error.OidcAudienceMismatch;
    const exp = try timestamp(object, "exp");
    const iat = try timestamp(object, "iat");
    if (exp <= now or exp <= iat or iat > now + 5) return error.OidcTokenTime;
    if (object.get("nbf")) |_| {
        const nbf = try timestamp(object, "nbf");
        if (nbf > now + 5 or nbf >= exp) return error.OidcTokenTime;
    }
    const subject = try text(object, "sub", 512);
    const scope_value = object.get("scope") orelse return error.OidcScopeMissing;
    if (scope_value != .string) return error.OidcScopeInvalid;
    const scope = scope_value.string;
    _ = try directAccessScopeMask(scope);
    // OpenAI authentication metadata remains opaque. No workspace/email/quota
    // identity is inferred from it or from this registration's client ID.
    return .{ .subject = subject, .scope = scope, .expires_at = exp, .issued_at = iat };
}
/// Closed semantic scope comparison also permits equivalent provider ordering.
fn knownScopeMask(value: []const u8) !u8 {
    if (value.len == 0 or value.len > 4096) return error.OidcScopeMissing;
    var parts = std.mem.splitScalar(u8, value, ' ');
    var mask: u8 = 0;
    while (parts.next()) |part| {
        if (part.len == 0) return error.OidcScopeInvalid;
        var found = false;
        for ([_][]const u8{ "openid", "profile", "email", "offline_access", "resource.invoke", "chatgpt.tokens.use.direct" }, 0..) |allowed, index| {
            if (!std.mem.eql(u8, part, allowed)) continue;
            const bit: u8 = @as(u8, 1) << @as(u3, @intCast(index));
            if (mask & bit != 0) return error.OidcScopeInvalid;
            mask |= bit;
            found = true;
            break;
        }
        if (!found) return error.OidcScopeInvalid;
    }
    return mask;
}
pub fn directScopeMask(value: []const u8) !u8 {
    const mask = try knownScopeMask(value);
    const required: u8 = (1 << 0) | (1 << 3) | (1 << 4) | (1 << 5);
    if (mask & required != required) return error.OidcScopeMissing;
    return mask;
}
/// Initial OpenID/offline authority is already authenticated in the pair.
/// A renewed resource token needs the two direct request scopes, without
/// inventing ID-token/nonce requirements for the refresh-token exchange.
pub fn directAccessScopeMask(value: []const u8) !u8 {
    const mask = try knownScopeMask(value);
    const required: u8 = (1 << 4) | (1 << 5);
    if (mask & required != required) return error.OidcScopeMissing;
    return mask;
}

fn document(a: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(std.json.Value) {
    // Bound nesting before parser allocations; quoted braces are inert.
    var depth: usize = 0;
    var quoted = false;
    var escaped = false;
    for (bytes) |byte| {
        if (quoted) {
            if (escaped) {
                escaped = false;
                continue;
            }
            if (byte == '\\') {
                escaped = true;
                continue;
            }
            if (byte == '"') quoted = false;
        } else if (byte == '"') {
            quoted = true;
        } else if (byte == '{' or byte == '[') {
            depth += 1;
            if (depth > 12) return error.OidcInputBound;
        } else if (byte == '}' or byte == ']') {
            if (depth == 0) return error.InvalidOidcJson;
            depth -= 1;
        }
    }
    if (quoted or escaped or depth != 0) return error.InvalidOidcJson;
    return std.json.parseFromSlice(std.json.Value, a, bytes, .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error", .max_value_len = max_jwt_bytes }) catch return error.InvalidOidcJson;
}
fn asObject(value: std.json.Value, count: usize) !std.json.ObjectMap {
    if (value != .object or value.object.count() > count) return error.InvalidOidcJson;
    return value.object;
}
fn visible(value: []const u8, limit: usize) !void {
    if (value.len == 0 or value.len > limit) return error.InvalidOidcClaim;
    for (value) |byte| if (byte < 0x21 or byte > 0x7e) return error.InvalidOidcClaim;
}
fn text(object: std.json.ObjectMap, name: []const u8, limit: usize) ![]const u8 {
    const value = object.get(name) orelse return error.InvalidOidcClaim;
    if (value != .string) return error.InvalidOidcClaim;
    try visible(value.string, limit);
    return value.string;
}
fn timestamp(object: std.json.ObjectMap, name: []const u8) !i64 {
    const value = object.get(name) orelse return error.InvalidOidcClaim;
    if (value != .integer or value.integer <= 0 or value.integer > 253_402_300_799) return error.InvalidOidcClaim;
    return value.integer;
}
fn decode64(storage: []u8, encoded: []const u8) ![]u8 {
    if (encoded.len == 0) return error.InvalidJose;
    for (encoded) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return error.InvalidJose;
    const codec = std.base64.url_safe_no_pad;
    const length = codec.Decoder.calcSizeForSlice(encoded) catch return error.InvalidJose;
    if (length > storage.len) return error.OidcInputBound;
    codec.Decoder.decode(storage[0..length], encoded) catch return error.InvalidJose;
    // Reject nonzero unused bits and every alternate/padded spelling.
    var canonical: [max_jwt_bytes * 2]u8 = undefined;
    defer std.crypto.secureZero(u8, &canonical);
    const n = codec.Encoder.calcSize(length);
    if (n > canonical.len) return error.OidcInputBound;
    _ = codec.Encoder.encode(canonical[0..n], storage[0..length]);
    if (!std.mem.eql(u8, canonical[0..n], encoded)) return error.InvalidJose;
    return storage[0..length];
}
const Key = struct { n: [512]u8, n_len: usize, e: [4]u8, e_len: usize };
fn selectKey(value: std.json.Value, kid: []const u8) !Key {
    const root = try asObject(value, 1);
    const values = root.get("keys") orelse return error.InvalidJwks;
    if (values != .array or values.array.items.len == 0 or values.array.items.len > max_keys) return error.InvalidJwks;
    var selected: ?std.json.ObjectMap = null;
    var ids: [max_keys][]const u8 = undefined;
    for (values.array.items, 0..) |row, index| {
        const object = try asObject(row, 16);
        const id = try text(object, "kid", 128);
        for (ids[0..index]) |prior| if (std.mem.eql(u8, id, prior)) return error.AmbiguousJwksKey;
        ids[index] = id;
        for ([_][]const u8{ "d", "p", "q", "dp", "dq", "qi", "oth" }) |private_name| if (object.contains(private_name)) return error.InvalidJwks;
        if (std.mem.eql(u8, id, kid)) selected = object;
    }
    const object = selected orelse return error.UnknownSigningKey;
    if (!std.mem.eql(u8, try text(object, "kty", 16), "RSA")) return error.UnsupportedSigningKey;
    if (object.get("alg")) |alg| if (alg != .string or !std.mem.eql(u8, alg.string, "RS256")) return error.UnsupportedSigningAlgorithm;
    if (object.get("use")) |use| if (use != .string or !std.mem.eql(u8, use.string, "sig")) return error.UnsupportedSigningKey;
    if (object.get("key_ops")) |ops| {
        if (ops != .array or ops.array.items.len != 1 or ops.array.items[0] != .string or !std.mem.eql(u8, ops.array.items[0].string, "verify")) return error.UnsupportedSigningKey;
    }
    var names = object.iterator();
    while (names.next()) |entry| {
        const name = entry.key_ptr.*;
        var accepted = false;
        for ([_][]const u8{ "kid", "kty", "n", "e", "alg", "use", "key_ops", "x5c", "x5t", "x5t#S256" }) |allowed| if (std.mem.eql(u8, name, allowed)) {
            accepted = true;
            break;
        };
        if (!accepted) return error.UnsupportedSigningKey;
    }
    var result: Key = undefined;
    result.n_len = (try decode64(&result.n, try text(object, "n", 700))).len;
    result.e_len = (try decode64(&result.e, try text(object, "e", 8))).len;
    if ((result.n_len != 256 and result.n_len != 384 and result.n_len != 512) or result.n[0] < 0x80 or result.n[result.n_len - 1] & 1 == 0 or result.e_len == 0 or result.e[0] == 0) return error.UnsupportedSigningKey;
    _ = Rsa.PublicKey.fromBytes(result.e[0..result.e_len], result.n[0..result.n_len]) catch return error.UnsupportedSigningKey;
    return result;
}
fn verifyRsa(message: []const u8, signature: []const u8, key: Key) !void {
    if (signature.len != key.n_len) return error.InvalidOidcSignature;
    const public = Rsa.PublicKey.fromBytes(key.e[0..key.e_len], key.n[0..key.n_len]) catch return error.UnsupportedSigningKey;
    switch (key.n_len) {
        256 => Rsa.PKCS1v1_5Signature.verify(256, signature[0..256], message, public, Hash) catch return error.InvalidOidcSignature,
        384 => Rsa.PKCS1v1_5Signature.verify(384, signature[0..384], message, public, Hash) catch return error.InvalidOidcSignature,
        512 => Rsa.PKCS1v1_5Signature.verify(512, signature[0..512], message, public, Hash) catch return error.InvalidOidcSignature,
        else => return error.UnsupportedSigningKey,
    }
}
const CheckedClaims = struct { subject: []const u8, expires_at: i64, issued_at: i64, access_token_hash: ?[16]u8 };
fn validateClaims(value: std.json.Value, client: []const u8, nonce_digest: [32]u8, now: i64) !CheckedClaims {
    if (now <= 0 or now > 253_402_300_794) return error.InvalidOidcClock;
    try visible(client, 256);
    const object = try asObject(value, 32);
    if (!std.mem.eql(u8, try text(object, "iss", 128), issuer)) return error.OidcIssuerMismatch;
    const aud = object.get("aud") orelse return error.OidcAudienceMismatch;
    var multi = false;
    if (aud == .string) {
        if (!std.mem.eql(u8, aud.string, client)) return error.OidcAudienceMismatch;
    } else if (aud == .array) {
        if (aud.array.items.len == 0 or aud.array.items.len > 8) return error.OidcAudienceMismatch;
        var found = false;
        var seen: [8][]const u8 = undefined;
        for (aud.array.items, 0..) |item, index| {
            if (item != .string) return error.OidcAudienceMismatch;
            try visible(item.string, 256);
            for (seen[0..index]) |prior| if (std.mem.eql(u8, prior, item.string)) return error.OidcAudienceMismatch;
            seen[index] = item.string;
            if (std.mem.eql(u8, item.string, client)) found = true;
        }
        if (!found) return error.OidcAudienceMismatch;
        multi = aud.array.items.len > 1;
    } else return error.OidcAudienceMismatch;
    if (object.get("azp")) |azp| {
        if (azp != .string or !std.mem.eql(u8, azp.string, client)) return error.OidcAudienceMismatch;
    } else if (multi) return error.OidcAudienceMismatch;
    const nonce = try text(object, "nonce", 43);
    if (nonce.len != 43) return error.OidcNonceMismatch;
    var nonce_bytes: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &nonce_bytes);
    if ((try decode64(&nonce_bytes, nonce)).len != 32) return error.OidcNonceMismatch;
    var digest: [32]u8 = undefined;
    Hash.hash(nonce, &digest, .{});
    if (!std.crypto.timing_safe.eql([32]u8, digest, nonce_digest)) return error.OidcNonceMismatch;
    const exp = try timestamp(object, "exp");
    const iat = try timestamp(object, "iat");
    // No expiration grace permits activation of an already-expired identity.
    if (exp <= now or exp <= iat or iat > now + 5) return error.OidcTokenTime;
    if (object.get("nbf")) |_| {
        const nbf = try timestamp(object, "nbf");
        if (nbf > now + 5 or nbf >= exp) return error.OidcTokenTime;
    }
    const subject = try text(object, "sub", 512);
    var access_hash: ?[16]u8 = null;
    if (object.get("at_hash")) |_| {
        const encoded = try text(object, "at_hash", 22);
        var decoded: [16]u8 = undefined;
        if (encoded.len != 22 or (try decode64(&decoded, encoded)).len != 16) return error.OidcAccessHashMismatch;
        access_hash = decoded;
    }
    return .{ .subject = subject, .expires_at = exp, .issued_at = iat, .access_token_hash = access_hash };
}

const vector_n = "ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddx" ++
    "HmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMs" ++
    "D1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSH" ++
    "SXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdV" ++
    "MTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8" ++
    "NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ";
const vector_input = "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";
const vector_sig = "cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7" ++
    "AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4" ++
    "BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K" ++
    "0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqv" ++
    "hJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrB" ++
    "p0igcN_IoypGlUPQGe77Rw";
fn vectorKey() !Key {
    var key: Key = undefined;
    key.n_len = (try decode64(&key.n, vector_n)).len;
    key.e_len = (try decode64(&key.e, "AQAB")).len;
    return key;
}
test "RFC 7515 A2 public RS256 vector verifies using actual pinned RSA, tamper refuses" {
    // Public n/e/signature only. No RFC private exponent/factor is copied.
    // This is a crypto known-answer, not an OpenAI token/account fixture.
    const key = try vectorKey();
    var signature: [512]u8 = undefined;
    const raw = try decode64(&signature, vector_sig);
    try verifyRsa(vector_input, raw, key);
    try std.testing.expectError(error.InvalidOidcSignature, verifyRsa("changed signing input", raw, key));
    var changed_key = key;
    changed_key.n[1] ^= 1;
    try std.testing.expectError(error.InvalidOidcSignature, verifyRsa(vector_input, raw, changed_key));
    signature[0] ^= 1;
    try std.testing.expectError(error.InvalidOidcSignature, verifyRsa(vector_input, raw, key));
    try std.testing.expectError(error.InvalidOidcSignature, verifyRsa(vector_input, raw[0 .. raw.len - 1], key));
}
test "canonical JOSE base64 refuses alternate bits padding whitespace and oversized decode" {
    var storage: [32]u8 = undefined;
    try std.testing.expectEqualStrings("\x00", try decode64(&storage, "AA"));
    for ([_][]const u8{ "AB", "AA=", "A A", "AA\n", "A", "" }) |bad|
        try std.testing.expectError(error.InvalidJose, decode64(&storage, bad));
    var small: [1]u8 = undefined;
    try std.testing.expectError(error.OidcInputBound, decode64(&small, "AAAA"));
}
test "JOSE decoded claims none HMAC and embedded key never authorize" {
    const a = std.testing.allocator;
    const payload = "e30"; // {}
    const cases = [_]struct { header: []const u8, expected: anyerror }{
        .{ .header = "{\"alg\":\"none\",\"kid\":\"fixture\"}", .expected = error.UnsupportedSigningAlgorithm },
        .{ .header = "{\"alg\":\"HS256\",\"kid\":\"fixture\"}", .expected = error.UnsupportedSigningAlgorithm },
        .{ .header = "{\"alg\":\"RS256\",\"kid\":\"fixture\",\"jku\":\"https://untrusted.invalid/keys\"}", .expected = error.UnsupportedJoseHeader },
        .{ .header = "{\"alg\":\"RS256\",\"kid\":\"fixture\",\"crit\":[]}", .expected = error.UnsupportedJoseHeader },
    };
    for (cases) |row| {
        var encoded: [512]u8 = undefined;
        const header64 = std.base64.url_safe_no_pad.Encoder.encode(&encoded, row.header);
        const jwt = try std.fmt.allocPrint(a, "{s}.{s}.AA", .{ header64, payload });
        defer a.free(jwt);
        try std.testing.expectError(row.expected, verifyIdToken(a, jwt, "{\"keys\":[]}", "oaiapp_fixture", @splat(1), 1000));
    }
}
test "bounded JSON rejects duplicate fields excessive depth and malformed roots" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.InvalidOidcJson, document(a, "{\"alg\":\"RS256\",\"alg\":\"none\"}"));
    try std.testing.expectError(error.OidcInputBound, document(a, "[[[[[[[[[[[[[0]]]]]]]]]]]]]"));
    try std.testing.expectError(error.InvalidOidcJson, document(a, "{\"x\":\"unterminated}"));
}
fn jwks(a: std.mem.Allocator, extra: []const u8, suffix: []const u8) ![]u8 {
    return std.fmt.allocPrint(a, "{{\"keys\":[{{\"kid\":\"fixture\",\"kty\":\"RSA\",\"n\":\"{s}\",\"e\":\"AQAB\"{s}}}{s}]}}", .{ vector_n, extra, suffix });
}
test "JWKS public key selection verifies bounds purpose and unambiguous kid" {
    const a = std.testing.allocator;
    const good = try jwks(a, ",\"alg\":\"RS256\",\"use\":\"sig\",\"key_ops\":[\"verify\"]", "");
    defer a.free(good);
    const parsed = try document(a, good);
    defer parsed.deinit();
    const key = try selectKey(parsed.value, "fixture");
    try std.testing.expectEqual(@as(usize, 256), key.n_len);
    try std.testing.expectError(error.UnknownSigningKey, selectKey(parsed.value, "other"));
    const duplicate = try jwks(a, "", ",{\"kid\":\"fixture\",\"kty\":\"RSA\"}");
    defer a.free(duplicate);
    const repeated = try document(a, duplicate);
    defer repeated.deinit();
    try std.testing.expectError(error.AmbiguousJwksKey, selectKey(repeated.value, "fixture"));
    for ([_][]const u8{ ",\"alg\":\"HS256\"", ",\"use\":\"enc\"", ",\"key_ops\":[\"sign\"]", ",\"x5u\":\"https://untrusted.invalid\"" }) |extra| {
        const raw = try jwks(a, extra, "");
        defer a.free(raw);
        const value = try document(a, raw);
        defer value.deinit();
        if (std.mem.startsWith(u8, extra, ",\"alg\""))
            try std.testing.expectError(error.UnsupportedSigningAlgorithm, selectKey(value.value, "fixture"))
        else
            try std.testing.expectError(error.UnsupportedSigningKey, selectKey(value.value, "fixture"));
    }
}
const fixture_nonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
fn nonceHash() [32]u8 {
    var hash: [32]u8 = undefined;
    Hash.hash(fixture_nonce, &hash, .{});
    return hash;
}
fn claimsFixture(a: std.mem.Allocator, changes: []const u8) !std.json.Parsed(std.json.Value) {
    const raw = try std.fmt.allocPrint(a, "{{\"iss\":\"https://auth.openai.com\",\"aud\":\"oaiapp_fixture\",\"sub\":\"synthetic-subject\",\"nonce\":\"{s}\",\"iat\":990,\"exp\":1100{s}}}", .{ fixture_nonce, changes });
    defer a.free(raw);
    return document(a, raw);
}
test "claim predicates check exact issuer CID nonce and real time after signature gate" {
    // These private predicates return no opaque profile proof. Signature known
    // answer above is separate; this is not fabricated full enrollment success.
    const a = std.testing.allocator;
    var good = try claimsFixture(a, "");
    defer good.deinit();
    const checked = try validateClaims(good.value, "oaiapp_fixture", nonceHash(), 1000);
    try std.testing.expectEqualStrings("synthetic-subject", checked.subject);
    try std.testing.expectError(error.OidcAudienceMismatch, validateClaims(good.value, "oaiapp_other", nonceHash(), 1000));
    try std.testing.expectError(error.OidcNonceMismatch, validateClaims(good.value, "oaiapp_fixture", @splat(7), 1000));
    try std.testing.expectError(error.OidcTokenTime, validateClaims(good.value, "oaiapp_fixture", nonceHash(), 1100));
    try std.testing.expectError(error.OidcTokenTime, validateClaims(good.value, "oaiapp_fixture", nonceHash(), 980));
    try std.testing.expectError(error.InvalidOidcClock, validateClaims(good.value, "oaiapp_fixture", nonceHash(), 0));
    try good.value.object.put(good.arena.allocator(), "iss", .{ .string = "https://untrusted.invalid" });
    try std.testing.expectError(error.OidcIssuerMismatch, validateClaims(good.value, "oaiapp_fixture", nonceHash(), 1000));
}
test "multi audience requires matching azp and rejects repeated audience and future nbf" {
    const a = std.testing.allocator;
    const good = try claimsFixture(a, ",\"nbf\":1006");
    defer good.deinit();
    try std.testing.expectError(error.OidcTokenTime, validateClaims(good.value, "oaiapp_fixture", nonceHash(), 1000));
    // Rewrite the entire owned fixture to preserve duplicate-field refusal.
    const raw = "{\"iss\":\"https://auth.openai.com\",\"aud\":[\"oaiapp_fixture\",\"other\"],\"sub\":\"synthetic-subject\",\"nonce\":\"" ++ fixture_nonce ++ "\",\"iat\":990,\"exp\":1100}";
    var multiple = try document(a, raw);
    defer multiple.deinit();
    try std.testing.expectError(error.OidcAudienceMismatch, validateClaims(multiple.value, "oaiapp_fixture", nonceHash(), 1000));
    try multiple.value.object.put(multiple.arena.allocator(), "azp", .{ .string = "oaiapp_fixture" });
    _ = try validateClaims(multiple.value, "oaiapp_fixture", nonceHash(), 1000);
    try multiple.value.object.put(multiple.arena.allocator(), "azp", .{ .string = "other" });
    try std.testing.expectError(error.OidcAudienceMismatch, validateClaims(multiple.value, "oaiapp_fixture", nonceHash(), 1000));
    multiple.value.object.getPtr("aud").?.array.items[1] = .{ .string = "oaiapp_fixture" };
    try std.testing.expectError(error.OidcAudienceMismatch, validateClaims(multiple.value, "oaiapp_fixture", nonceHash(), 1000));
}
test "JWKS rejects weak noncanonical private exponent and excessive key inventories" {
    const a = std.testing.allocator;
    const raw = try jwks(a, "", "");
    defer a.free(raw);
    const parsed = try document(a, raw);
    defer parsed.deinit();
    const selected = &parsed.value.object.getPtr("keys").?.array.items[0].object;
    try selected.put(parsed.arena.allocator(), "e", .{ .string = "Ag" }); // even exponent
    try std.testing.expectError(error.UnsupportedSigningKey, selectKey(parsed.value, "fixture"));
    try selected.put(parsed.arena.allocator(), "e", .{ .string = "AAEAAQ" }); // leading zero
    try std.testing.expectError(error.UnsupportedSigningKey, selectKey(parsed.value, "fixture"));
    try selected.put(parsed.arena.allocator(), "e", .{ .string = "AQAB" });
    try selected.put(parsed.arena.allocator(), "n", .{ .string = "AQ" });
    try std.testing.expectError(error.UnsupportedSigningKey, selectKey(parsed.value, "fixture"));
    try selected.put(parsed.arena.allocator(), "n", .{ .string = vector_n });
    try selected.put(parsed.arena.allocator(), "d", .{ .string = "forbidden-placeholder" });
    try std.testing.expectError(error.InvalidJwks, selectKey(parsed.value, "fixture"));
    // Admission count is checked before traversing the newly added rows.
    const too_many = try document(a, raw);
    defer too_many.deinit();
    const rows = &too_many.value.object.getPtr("keys").?.array;
    while (rows.items.len <= max_keys) try rows.append(.null);
    try std.testing.expectError(error.InvalidJwks, selectKey(too_many.value, "fixture"));
}
test "actual JOSE signature refusal precedes claim interpretation and input limits" {
    const a = std.testing.allocator;
    const raw = try jwks(a, "", "");
    defer a.free(raw);
    var header: [128]u8 = undefined;
    const h = std.base64.url_safe_no_pad.Encoder.encode(&header, "{\"alg\":\"RS256\",\"kid\":\"fixture\"}");
    const jwt = try std.fmt.allocPrint(a, "{s}.e30.{s}", .{ h, vector_sig });
    defer a.free(jwt);
    try std.testing.expectError(error.InvalidOidcSignature, verifyIdToken(a, jwt, raw, "oaiapp_fixture", nonceHash(), 1000));
    const huge: [max_jwt_bytes + 1]u8 = @splat('A');
    try std.testing.expectError(error.OidcInputBound, verifyIdToken(a, &huge, raw, "oaiapp_fixture", nonceHash(), 1000));
}

test "rotated resource access scopes do not borrow initial OIDC nonce or offline scopes" {
    try std.testing.expectEqual(@as(u8, 0b11_0000), try directAccessScopeMask("resource.invoke chatgpt.tokens.use.direct"));
    try std.testing.expectError(error.OidcScopeMissing, directScopeMask("resource.invoke chatgpt.tokens.use.direct"));
    for ([_][]const u8{ "openid offline_access", "resource.invoke", "chatgpt.tokens.use.direct" }) |scope|
        try std.testing.expectError(error.OidcScopeMissing, directAccessScopeMask(scope));
    for ([_][]const u8{ "resource.invoke chatgpt.tokens.use.direct admin", "resource.invoke chatgpt.tokens.use.direct resource.invoke", " resource.invoke chatgpt.tokens.use.direct" }) |scope|
        try std.testing.expectError(error.OidcScopeInvalid, directAccessScopeMask(scope));
}

test "rotated access claim validation joins API resource issued client subject and current times" {
    const a = std.testing.allocator;
    const cases = [_]struct { issuer: []const u8 = "https://auth.openai.com", audience: []const u8 = "https://api.openai.com/v1", client: []const u8 = "oaiapp_synthetic_rotate", sub: []const u8 = "synthetic-rotate-subject", iat: i64 = 1000, exp: i64 = 1300, nbf: i64 = 1000, scope: []const u8 = "resource.invoke chatgpt.tokens.use.direct", expected: ?anyerror = null }{
        .{}, .{ .issuer = "https://untrusted.invalid", .expected = error.OidcIssuerMismatch },
        .{ .audience = "https://chatgpt.com", .expected = error.OidcAudienceMismatch },
        .{ .client = "dynamic_agent_client", .expected = error.OidcAudienceMismatch },
        .{ .exp = 1000, .expected = error.OidcTokenTime },
        .{ .iat = 1100, .expected = error.OidcTokenTime },
        .{ .nbf = 1100, .expected = error.OidcTokenTime },
        .{ .sub = "", .expected = error.InvalidOidcClaim },
        .{ .scope = "openid offline_access", .expected = error.OidcScopeMissing },
    };
    for (cases) |case| {
        const bytes = try std.json.Stringify.valueAlloc(a, .{ .iss = case.issuer, .aud = case.audience, .client_id = case.client, .sub = case.sub, .iat = case.iat, .exp = case.exp, .nbf = case.nbf, .scope = case.scope }, .{});
        defer a.free(bytes);
        const parsed = try document(a, bytes); defer parsed.deinit();
        if (case.expected) |expected| try std.testing.expectError(expected, validateAccessClaims(parsed.value, "oaiapp_synthetic_rotate", 1000)) else {
            const claims = try validateAccessClaims(parsed.value, "oaiapp_synthetic_rotate", 1000);
            try std.testing.expectEqualStrings("synthetic-rotate-subject", claims.subject);
            try std.testing.expectEqual(@as(i64, 1300), claims.expires_at);
        }
    }
}
