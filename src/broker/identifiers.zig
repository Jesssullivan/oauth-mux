//! Borrowed, byte-preserving broker identifier parsers.

const std = @import("std");

pub const max_handle_len: usize = 256;
pub const ParseError = error{InvalidIdentifier};

const ActiveHandleKind = enum { session, account, route };

fn ActiveHandle(comptime handle_kind: ActiveHandleKind) type {
    return struct {
        pub const kind = handle_kind;

        text: []const u8,

        pub fn parse(text: []const u8) ParseError!@This() {
            try validateActiveHandle(text);
            return .{ .text = text };
        }
    };
}

/// Managed-harness surface-v2 handles are opaque ASCII tokens. The parser
/// borrows the caller's bytes and never normalizes prefixes or case.
pub const SessionHandle = ActiveHandle(.session);
pub const AccountHandle = ActiveHandle(.account);
pub const RouteHandle = ActiveHandle(.route);

fn validateActiveHandle(text: []const u8) ParseError!void {
    if (text.len == 0 or text.len > max_handle_len) return error.InvalidIdentifier;
    for (text) |byte| {
        const valid = switch (byte) {
            'A'...'Z', 'a'...'z', '0'...'9', '_', '-' => true,
            else => false,
        };
        if (!valid) return error.InvalidIdentifier;
    }
}

fn hasWhitespaceOrControl(text: []const u8) bool {
    for (text) |byte| {
        if (byte <= ' ' or byte == 0x7f) return true;
    }
    return false;
}

/// Internal `provider:account` key. Only the first colon is structural;
/// later colons remain part of the account label.
pub const AccountKey = struct {
    text: []const u8,
    provider: []const u8,
    account: []const u8,

    pub fn parse(text: []const u8) ParseError!AccountKey {
        if (text.len == 0 or text.len > max_handle_len) return error.InvalidIdentifier;
        if (hasWhitespaceOrControl(text)) return error.InvalidIdentifier;
        const separator = std.mem.indexOfScalar(u8, text, ':') orelse
            return error.InvalidIdentifier;
        if (separator == 0 or separator + 1 == text.len) return error.InvalidIdentifier;
        return .{
            .text = text,
            .provider = text[0..separator],
            .account = text[separator + 1 ..],
        };
    }
};

/// Surface-v1 session id minted as `oms-<hex>-<hex>`.
pub const LegacySessionId = struct {
    text: []const u8,
    counter_hex: []const u8,
    random_hex: []const u8,

    pub fn parse(text: []const u8) ParseError!LegacySessionId {
        if (text.len == 0 or text.len > max_handle_len) return error.InvalidIdentifier;
        if (!std.mem.startsWith(u8, text, "oms-")) return error.InvalidIdentifier;

        const payload = text[4..];
        const separator = std.mem.indexOfScalar(u8, payload, '-') orelse
            return error.InvalidIdentifier;
        if (separator == 0 or separator + 1 == payload.len) return error.InvalidIdentifier;
        if (std.mem.indexOfScalar(u8, payload[separator + 1 ..], '-') != null)
            return error.InvalidIdentifier;

        const counter_hex = payload[0..separator];
        const random_hex = payload[separator + 1 ..];
        for (counter_hex) |byte| if (!isHex(byte)) return error.InvalidIdentifier;
        for (random_hex) |byte| if (!isHex(byte)) return error.InvalidIdentifier;

        return .{
            .text = text,
            .counter_hex = counter_hex,
            .random_hex = random_hex,
        };
    }
};

/// Surface-v1 credential handle. The first payload colon separates provider;
/// the final colon separates the opaque tail, so account labels may contain
/// any number of intervening colons.
pub const LegacyCredentialHandle = struct {
    text: []const u8,
    account_key: []const u8,
    provider: []const u8,
    account: []const u8,
    tail: []const u8,

    pub fn parse(text: []const u8) ParseError!LegacyCredentialHandle {
        if (text.len == 0 or text.len > max_handle_len) return error.InvalidIdentifier;
        if (hasWhitespaceOrControl(text)) return error.InvalidIdentifier;
        if (!std.mem.startsWith(u8, text, "ch:")) return error.InvalidIdentifier;

        const payload = text[3..];
        const tail_separator = std.mem.lastIndexOfScalar(u8, payload, ':') orelse
            return error.InvalidIdentifier;
        if (tail_separator + 1 == payload.len) return error.InvalidIdentifier;

        const account_key_text = payload[0..tail_separator];
        const account_key = try AccountKey.parse(account_key_text);
        return .{
            .text = text,
            .account_key = account_key.text,
            .provider = account_key.provider,
            .account = account_key.account,
            .tail = payload[tail_separator + 1 ..],
        };
    }
};

fn isHex(byte: u8) bool {
    return switch (byte) {
        '0'...'9', 'A'...'F', 'a'...'f' => true,
        else => false,
    };
}

fn expectActiveHandleContract(comptime Handle: type) !void {
    const input = "Az09_-oms-dead-beef";
    const parsed = try Handle.parse(input);
    try std.testing.expectEqualStrings(input, parsed.text);
    try std.testing.expect(parsed.text.ptr == input.ptr);

    var max: [max_handle_len]u8 = [_]u8{'a'} ** max_handle_len;
    _ = try Handle.parse(max[0..]);

    var overlong: [max_handle_len + 1]u8 = [_]u8{'a'} ** (max_handle_len + 1);
    try std.testing.expectError(error.InvalidIdentifier, Handle.parse(overlong[0..]));
    try std.testing.expectError(error.InvalidIdentifier, Handle.parse(""));
    try std.testing.expectError(error.InvalidIdentifier, Handle.parse("has:colon"));
    try std.testing.expectError(error.InvalidIdentifier, Handle.parse("has space"));
    try std.testing.expectError(error.InvalidIdentifier, Handle.parse("caf\xc3\xa9"));
}

test "active-v2 handles enforce one bounded byte-preserving grammar" {
    try expectActiveHandleContract(SessionHandle);
    try expectActiveHandleContract(AccountHandle);
    try expectActiveHandleContract(RouteHandle);

    // Legacy-looking bytes are valid active handles; prefixes are opaque.
    try std.testing.expectEqualStrings(
        "oms-dead-beef",
        (try SessionHandle.parse("oms-dead-beef")).text,
    );
}

test "AccountKey splits only its first colon" {
    const input = "codex:team:blue";
    const key = try AccountKey.parse(input);
    try std.testing.expectEqualStrings(input, key.text);
    try std.testing.expect(key.text.ptr == input.ptr);
    try std.testing.expectEqualStrings("codex", key.provider);
    try std.testing.expectEqualStrings("team:blue", key.account);

    for ([_][]const u8{
        "",
        "codex",
        ":account",
        "codex:",
        "codex:bad account",
        "codex:bad\taccount",
        "codex:bad\x00account",
    }) |invalid| {
        try std.testing.expectError(error.InvalidIdentifier, AccountKey.parse(invalid));
    }

    var max_account: [254]u8 = [_]u8{'a'} ** 254;
    const max = try std.fmt.allocPrint(std.testing.allocator, "p:{s}", .{max_account[0..]});
    defer std.testing.allocator.free(max);
    try std.testing.expectEqual(@as(usize, max_handle_len), max.len);
    _ = try AccountKey.parse(max);

    var overlong_account: [255]u8 = [_]u8{'a'} ** 255;
    const overlong = try std.fmt.allocPrint(std.testing.allocator, "p:{s}", .{overlong_account[0..]});
    defer std.testing.allocator.free(overlong);
    try std.testing.expectError(error.InvalidIdentifier, AccountKey.parse(overlong));
}

test "LegacySessionId parses exact legacy shape without rewriting" {
    const input = "oms-A0-bC9";
    const id = try LegacySessionId.parse(input);
    try std.testing.expectEqualStrings(input, id.text);
    try std.testing.expect(id.text.ptr == input.ptr);
    try std.testing.expectEqualStrings("A0", id.counter_hex);
    try std.testing.expectEqualStrings("bC9", id.random_hex);

    for ([_][]const u8{
        "",
        "oms--beef",
        "oms-dead-",
        "oms-dead-beef-more",
        "oms-nope-beef",
        "not-oms-dead-beef",
    }) |invalid| {
        try std.testing.expectError(error.InvalidIdentifier, LegacySessionId.parse(invalid));
    }

    var max_counter: [125]u8 = [_]u8{'a'} ** 125;
    var max_random: [126]u8 = [_]u8{'b'} ** 126;
    const max = try std.fmt.allocPrint(std.testing.allocator, "oms-{s}-{s}", .{ max_counter[0..], max_random[0..] });
    defer std.testing.allocator.free(max);
    try std.testing.expectEqual(@as(usize, max_handle_len), max.len);
    _ = try LegacySessionId.parse(max);

    var overlong_random: [127]u8 = [_]u8{'b'} ** 127;
    const overlong = try std.fmt.allocPrint(std.testing.allocator, "oms-{s}-{s}", .{ max_counter[0..], overlong_random[0..] });
    defer std.testing.allocator.free(overlong);
    try std.testing.expectEqual(@as(usize, max_handle_len + 1), overlong.len);
    try std.testing.expectError(error.InvalidIdentifier, LegacySessionId.parse(overlong));
}

test "LegacyCredentialHandle preserves colon-bearing account labels" {
    const input = "ch:codex:org:team:deadbeef";
    const handle = try LegacyCredentialHandle.parse(input);
    try std.testing.expectEqualStrings(input, handle.text);
    try std.testing.expect(handle.text.ptr == input.ptr);
    try std.testing.expectEqualStrings("codex:org:team", handle.account_key);
    try std.testing.expectEqualStrings("codex", handle.provider);
    try std.testing.expectEqualStrings("org:team", handle.account);
    try std.testing.expectEqualStrings("deadbeef", handle.tail);

    for ([_][]const u8{
        "",
        "ch::account:tail",
        "ch:provider::tail",
        "ch:provider:account:",
        "ch:provider:account tail:opaque",
        "ch:provider:account:\x00",
        "not-ch:provider:account:tail",
    }) |invalid| {
        try std.testing.expectError(error.InvalidIdentifier, LegacyCredentialHandle.parse(invalid));
    }

    var max_account: [249]u8 = [_]u8{'a'} ** 249;
    const max = try std.fmt.allocPrint(std.testing.allocator, "ch:p:{s}:t", .{max_account[0..]});
    defer std.testing.allocator.free(max);
    try std.testing.expectEqual(@as(usize, max_handle_len), max.len);
    _ = try LegacyCredentialHandle.parse(max);

    var overlong_account: [250]u8 = [_]u8{'a'} ** 250;
    const overlong = try std.fmt.allocPrint(std.testing.allocator, "ch:p:{s}:t", .{overlong_account[0..]});
    defer std.testing.allocator.free(overlong);
    try std.testing.expectError(error.InvalidIdentifier, LegacyCredentialHandle.parse(overlong));
}

test "LegacyCredentialHandle round-trips generated legacy account keys" {
    var prng = std.Random.DefaultPrng.init(0xCAFEF00D);
    const random = prng.random();
    const providers = [_][]const u8{ "codex", "claude", "anthropic", "p" };
    const accounts = [_][]const u8{ "a", "max-1", "team/work", "org:team:blue" };

    var i: usize = 0;
    while (i < 200) : (i += 1) {
        const provider = providers[random.uintLessThan(usize, providers.len)];
        const account = accounts[random.uintLessThan(usize, accounts.len)];
        const tail = random.int(u32);

        const account_key = try std.fmt.allocPrint(std.testing.allocator, "{s}:{s}", .{ provider, account });
        defer std.testing.allocator.free(account_key);
        const text = try std.fmt.allocPrint(std.testing.allocator, "ch:{s}:{x}", .{ account_key, tail });
        defer std.testing.allocator.free(text);

        const parsed = try LegacyCredentialHandle.parse(text);
        try std.testing.expectEqualStrings(text, parsed.text);
        try std.testing.expectEqualStrings(account_key, parsed.account_key);
        try std.testing.expectEqualStrings(provider, parsed.provider);
        try std.testing.expectEqualStrings(account, parsed.account);
    }
}
