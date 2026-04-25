const std = @import("std");
const log = @import("log.zig");

pub const DecryptError = error{
    InvalidFormat,
    UnsupportedRecipient,
    DecryptFailed,
    WrongIdentity,
    OutOfMemory,
    IoError,
};

/// Decrypt an age-encrypted file using an X25519 identity.
/// Identity format: AGE-SECRET-KEY-1... (Bech32-encoded)
pub fn decryptFile(allocator: std.mem.Allocator, ciphertext: []const u8, identity_key: []const u8) DecryptError![]const u8 {
    // Parse the age file header
    const header = parseHeader(ciphertext) orelse return error.InvalidFormat;

    // Decode the identity (age secret key is bech32-encoded X25519 private key)
    const identity_privkey = decodeIdentity(identity_key) orelse return error.WrongIdentity;

    // Find an X25519 recipient stanza we can decrypt
    const file_key = unwrapFileKey(header.stanzas, &identity_privkey) orelse return error.WrongIdentity;

    // Verify HMAC
    if (!verifyHeaderMac(header.header_bytes, &file_key, header.mac)) {
        return error.DecryptFailed;
    }

    // Decrypt the payload with the file key
    return decryptPayload(allocator, header.payload, &file_key) catch return error.DecryptFailed;
}

const Header = struct {
    stanzas: []const Stanza,
    mac: [32]u8,
    header_bytes: []const u8,
    payload: []const u8,
};

const Stanza = struct {
    recipient_type: []const u8,
    args: []const u8,
    body: []const u8,
};

fn parseHeader(data: []const u8) ?Header {
    // age files start with "age-encryption.org/v1\n"
    const magic = "age-encryption.org/v1\n";
    if (data.len < magic.len or !std.mem.eql(u8, data[0..magic.len], magic)) {
        return null;
    }

    // Find the "---" separator line (marks end of header)
    const separator = "---";
    var sep_pos: ?usize = null;
    var i: usize = magic.len;
    while (i + separator.len <= data.len) : (i += 1) {
        if (i == 0 or data[i - 1] == '\n') {
            if (std.mem.startsWith(u8, data[i..], separator)) {
                sep_pos = i;
                break;
            }
        }
    }
    const sep = sep_pos orelse return null;

    // MAC is base64-encoded after "--- " on the separator line
    const sep_line_end = std.mem.indexOfPos(u8, data, sep, "\n") orelse return null;
    const sep_line = data[sep..sep_line_end];
    if (sep_line.len < 5) return null; // "--- " + at least 1 char

    var mac: [32]u8 = undefined;
    const mac_b64 = std.mem.trimLeft(u8, sep_line[3..], " ");
    _ = std.base64.standard_no_pad.Decoder.decode(&mac, mac_b64) catch return null;

    const header_bytes = data[0..sep];
    const payload = data[sep_line_end + 1 ..];

    // Parse stanzas (simplified: we only handle X25519)
    // Each stanza starts with "-> " followed by type and args
    var stanzas_buf: [16]Stanza = undefined;
    var stanza_count: usize = 0;
    var pos: usize = magic.len;
    while (pos < sep) {
        if (std.mem.startsWith(u8, data[pos..], "-> ")) {
            const line_end = std.mem.indexOfPos(u8, data, pos, "\n") orelse break;
            const stanza_line = data[pos + 3 .. line_end];

            // Next lines until empty line or next stanza are the body
            const body_start = line_end + 1;
            var body_end = body_start;
            while (body_end < sep) {
                const next_nl = std.mem.indexOfPos(u8, data, body_end, "\n") orelse break;
                if (next_nl == body_end) break; // empty line
                if (std.mem.startsWith(u8, data[body_end..], "-> ")) break;
                if (std.mem.startsWith(u8, data[body_end..], "---")) break;
                body_end = next_nl + 1;
            }

            // Split stanza_line into type and args at first space
            const type_end = std.mem.indexOf(u8, stanza_line, " ") orelse stanza_line.len;

            if (stanza_count < stanzas_buf.len) {
                stanzas_buf[stanza_count] = .{
                    .recipient_type = stanza_line[0..type_end],
                    .args = if (type_end < stanza_line.len) stanza_line[type_end + 1 ..] else "",
                    .body = data[body_start..body_end],
                };
                stanza_count += 1;
            }
            pos = body_end;
        } else {
            pos = (std.mem.indexOfPos(u8, data, pos, "\n") orelse break) + 1;
        }
    }

    return .{
        .stanzas = stanzas_buf[0..stanza_count],
        .mac = mac,
        .header_bytes = header_bytes,
        .payload = payload,
    };
}

fn decodeIdentity(identity: []const u8) ?[32]u8 {
    // age identity format: AGE-SECRET-KEY-1<bech32 data>
    const prefix = "AGE-SECRET-KEY-1";
    const trimmed = std.mem.trim(u8, identity, " \t\n\r");
    if (!std.mem.startsWith(u8, trimmed, prefix)) return null;

    // The bech32 data after the prefix encodes the 32-byte X25519 private key
    // age uses a custom bech32 encoding; for now we use a simplified decoder
    const bech_data = trimmed[prefix.len..];
    var key: [32]u8 = undefined;
    decodeBech32Lower(bech_data, &key) catch return null;
    return key;
}

fn decodeBech32Lower(input: []const u8, out: *[32]u8) !void {
    const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    var bits: u32 = 0;
    var bit_count: u5 = 0;
    var out_idx: usize = 0;

    for (input) |c| {
        const lower = std.ascii.toLower(c);
        const val: u5 = for (charset, 0..) |ch, idx| {
            if (ch == lower) break @intCast(idx);
        } else return error.InvalidCharacter;

        bits = (bits << 5) | val;
        bit_count += 5;

        if (bit_count >= 8) {
            bit_count -= 8;
            if (out_idx >= 32) return error.Overflow;
            out[out_idx] = @truncate(bits >> bit_count);
            out_idx += 1;
        }
    }
    if (out_idx < 32) return error.Overflow;
}

fn unwrapFileKey(stanzas: []const Stanza, identity_privkey: *const [32]u8) ?[16]u8 {
    for (stanzas) |s| {
        if (!std.mem.eql(u8, s.recipient_type, "X25519")) continue;

        // args contains the base64-encoded ephemeral public key (32 bytes)
        var ephemeral_pub: [32]u8 = undefined;
        _ = std.base64.standard_no_pad.Decoder.decode(&ephemeral_pub, std.mem.trim(u8, s.args, " \n\r")) catch continue;

        // Compute shared secret: X25519(identity_privkey, ephemeral_pub)
        const shared = std.crypto.dh.X25519.scalarmult(identity_privkey.*, ephemeral_pub) catch continue;

        // Derive wrapping key via HKDF-SHA-256
        // salt = ephemeral_pub || recipient_pub
        // info = "age-encryption.org/v1/X25519"
        const our_pub = std.crypto.dh.X25519.recoverPublicKey(identity_privkey.*) catch continue;
        var salt: [64]u8 = undefined;
        @memcpy(salt[0..32], &ephemeral_pub);
        @memcpy(salt[32..64], &our_pub);

        const prk = std.crypto.kdf.hkdf.HkdfSha256.extract(&salt, &shared);
        var wrap_key: [32]u8 = undefined;
        std.crypto.kdf.hkdf.HkdfSha256.expand(&wrap_key, "age-encryption.org/v1/X25519", prk);

        // Unwrap the file key: body is base64-encoded ChaCha20-Poly1305 ciphertext
        const body_trimmed = std.mem.trim(u8, s.body, " \n\r");
        var wrapped: [32]u8 = undefined; // 16-byte file key + 16-byte Poly1305 tag
        const decoded_len = std.base64.standard_no_pad.Decoder.calcSizeForSlice(body_trimmed) catch continue;
        if (decoded_len != 32) continue;
        _ = std.base64.standard_no_pad.Decoder.decode(&wrapped, body_trimmed) catch continue;

        // Decrypt with ChaCha20-Poly1305, nonce = all zeros
        var file_key: [16]u8 = undefined;
        const nonce = [_]u8{0} ** 12;
        const tag: [16]u8 = wrapped[16..].*;
        std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
            &file_key,
            wrapped[0..16],
            tag,
            "",
            nonce,
            wrap_key,
        ) catch continue;

        return file_key;
    }
    return null;
}

fn verifyHeaderMac(header_bytes: []const u8, file_key: *const [16]u8, expected_mac: [32]u8) bool {
    // HMAC-SHA-256(key = HKDF("", file_key, "header"), message = header_bytes)
    const prk = std.crypto.kdf.hkdf.HkdfSha256.extract("", file_key);
    var mac_key: [32]u8 = undefined;
    std.crypto.kdf.hkdf.HkdfSha256.expand(&mac_key, "header", prk);

    var mac: [32]u8 = undefined;
    var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(&mac_key);
    hmac.update(header_bytes);
    hmac.final(&mac);

    return std.mem.eql(u8, &mac, &expected_mac);
}

fn decryptPayload(allocator: std.mem.Allocator, payload: []const u8, file_key: *const [16]u8) ![]const u8 {
    // Derive the payload key via HKDF
    // payload nonce is first 16 bytes of payload
    if (payload.len < 16) return error.InvalidFormat;
    const nonce_bytes = payload[0..16];
    const ciphertext = payload[16..];

    const prk = std.crypto.kdf.hkdf.HkdfSha256.extract(nonce_bytes, file_key);
    var payload_key: [32]u8 = undefined;
    std.crypto.kdf.hkdf.HkdfSha256.expand(&payload_key, "payload", prk);

    // Payload is split into 64KB chunks, each encrypted with ChaCha20-Poly1305
    // with incrementing nonce (last chunk is marked as final)
    var result = std.ArrayList(u8).init(allocator);
    errdefer result.deinit();

    const chunk_size = 64 * 1024;
    const overhead = 16; // Poly1305 tag
    var chunk_idx: u32 = 0;
    var pos: usize = 0;

    while (pos < ciphertext.len) {
        const remaining = ciphertext.len - pos;
        const is_last = remaining <= chunk_size + overhead;
        const this_chunk_len = if (is_last) remaining else chunk_size + overhead;

        if (this_chunk_len < overhead) break;

        const ct = ciphertext[pos .. pos + this_chunk_len - overhead];
        const tag_bytes = ciphertext[pos + this_chunk_len - overhead .. pos + this_chunk_len];

        // Nonce: 11 bytes counter (big-endian) + 1 byte final flag
        var nonce: [12]u8 = [_]u8{0} ** 12;
        std.mem.writeInt(u32, nonce[0..4], 0, .big);
        std.mem.writeInt(u32, nonce[4..8], chunk_idx, .big);
        std.mem.writeInt(u32, nonce[8..12], if (is_last) @as(u32, 1) else @as(u32, 0), .big);

        var tag: [16]u8 = undefined;
        @memcpy(&tag, tag_bytes);

        const start = result.items.len;
        try result.resize(start + ct.len);
        std.crypto.aead.chacha_poly.ChaCha20Poly1305.decrypt(
            result.items[start..][0..ct.len],
            ct,
            tag,
            "",
            nonce,
            payload_key,
        ) catch return error.DecryptFailed;

        pos += this_chunk_len;
        chunk_idx += 1;

        if (is_last) break;
    }

    return result.toOwnedSlice();
}

// ── Tests ──

test "decodeIdentity rejects invalid prefix" {
    try std.testing.expect(decodeIdentity("not-an-age-key") == null);
    try std.testing.expect(decodeIdentity("") == null);
}

test "parseHeader rejects non-age data" {
    try std.testing.expect(parseHeader("not age data") == null);
    try std.testing.expect(parseHeader("") == null);
}
