//! Unit tests for the Claude stable-identity labeler. Pure: synthetic profiles
//! inline (no real PII, no fixtures), no I/O.
//!
//!     zig test src/identity/claude_identity_tests.zig

const std = @import("std");
const testing = std.testing;
const ci = @import("claude_identity.zig");

test {
    std.testing.refAllDeclsRecursive(ci);
}

// sha256_12hex of the empty string — must NEVER be emitted as any identity hash
// (emitting it would coalesce all profile-less / no-org accounts into one).
const empty_hash = "e3b0c44298fc";

// A synthetic full profile. All UUIDs/email are fake — this file lives under
// src/ (not scanned) and carries no real PII or tokens.
const full_profile =
    \\{
    \\  "userID": "0000000000000000000000000000000000000000000000000000000000000000",
    \\  "oauthAccount": {
    \\    "accountUuid": "11111111-2222-3333-4444-555555555555",
    \\    "organizationUuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    \\    "organizationName": "Acme Robotics",
    \\    "emailAddress": "jess@example.com",
    \\    "billingType": "subscription"
    \\  }
    \\}
;

// ── Happy path ──────────────────────────────────────────────────────────────

test "parse a full profile: present, hashed identity, masked email, org display" {
    const a = testing.allocator;
    const id = try ci.parseClaudeIdentity(a, full_profile);
    defer id.deinit(a);

    try testing.expect(id.present);
    try testing.expectEqualStrings("identity_present", id.reason);
    try testing.expectEqualStrings("oauthAccount.accountUuid", id.account_id_source.?);

    try testing.expectEqual(@as(usize, 12), id.account_id_hash.?.len);
    try testing.expectEqual(@as(usize, 12), id.org_id_hash.?.len);
    // stable label = claude:<org12>:<acct12>
    var buf: [64]u8 = undefined;
    const want = try std.fmt.bufPrint(&buf, "claude:{s}:{s}", .{ id.org_id_hash.?, id.account_id_hash.? });
    try testing.expectEqualStrings(want, id.stable_label.?);
    // masked email, raw local part gone
    try testing.expectEqualStrings("j***@example.com", id.email_hint.?);
    try testing.expectEqualStrings("Acme Robotics", id.org_display.?);
}

test "golden vector: sha256_12hex matches the Codex shortSha256HexAlloc" {
    // Codex golden (main.zig:791): sha256_12hex("acct-test") == "660d25a9d7ee".
    // Feed accountUuid="acct-test" and assert the produced hash matches.
    const a = testing.allocator;
    const id = try ci.parseClaudeIdentity(a,
        \\{"oauthAccount":{"accountUuid":"acct-test"}}
    );
    defer id.deinit(a);
    try testing.expectEqualStrings("660d25a9d7ee", id.account_id_hash.?);
}

// ── Redaction ───────────────────────────────────────────────────────────────

test "redaction: no raw uuid or email local-part in label/hint" {
    const a = testing.allocator;
    const id = try ci.parseClaudeIdentity(a, full_profile);
    defer id.deinit(a);

    // raw account/org UUID segments never appear in the label
    try testing.expect(std.mem.indexOf(u8, id.stable_label.?, "11111111") == null);
    try testing.expect(std.mem.indexOf(u8, id.stable_label.?, "aaaaaaaa") == null);
    // raw email local part never appears in the hint
    try testing.expect(std.mem.indexOf(u8, id.email_hint.?, "jess") == null);
}

test "redaction: a non-ASCII email local part is masked whole and stays valid UTF-8" {
    const a = testing.allocator;
    // "école@example.com" — é is the 2-byte UTF-8 sequence \xc3\xa9. A `{c}` hint
    // would emit only the lead byte \xc3 → invalid UTF-8; the whole local must be
    // masked instead.
    const id = try ci.parseClaudeIdentity(a,
        "{\"oauthAccount\":{\"accountUuid\":\"u-1\",\"emailAddress\":\"\xc3\xa9cole@example.com\"}}");
    defer id.deinit(a);
    try testing.expect(id.present);
    try testing.expectEqualStrings("***@example.com", id.email_hint.?);
    try testing.expect(std.unicode.utf8ValidateSlice(id.email_hint.?)); // never invalid UTF-8
    try testing.expect(std.mem.indexOf(u8, id.email_hint.?, "cole") == null); // local not leaked
}

// ── Stability + uniqueness ──────────────────────────────────────────────────

test "stability: same profile yields an identical hash + label" {
    const a = testing.allocator;
    const id1 = try ci.parseClaudeIdentity(a, full_profile);
    defer id1.deinit(a);
    const id2 = try ci.parseClaudeIdentity(a, full_profile);
    defer id2.deinit(a);
    try testing.expectEqualStrings(id1.account_id_hash.?, id2.account_id_hash.?);
    try testing.expectEqualStrings(id1.stable_label.?, id2.stable_label.?);
}

test "uniqueness: distinct accountUuids yield distinct hashes" {
    const a = testing.allocator;
    const id1 = try ci.parseClaudeIdentity(a,
        \\{"oauthAccount":{"accountUuid":"account-one"}}
    );
    defer id1.deinit(a);
    const id2 = try ci.parseClaudeIdentity(a,
        \\{"oauthAccount":{"accountUuid":"account-two"}}
    );
    defer id2.deinit(a);
    try testing.expect(!std.mem.eql(u8, id1.account_id_hash.?, id2.account_id_hash.?));
}

// ── No-org (personal) ───────────────────────────────────────────────────────

test "no-org account: org_id_hash is null (NOT a hash of empty), label uses noorg" {
    const a = testing.allocator;
    const id = try ci.parseClaudeIdentity(a,
        \\{"oauthAccount":{"accountUuid":"solo-account","emailAddress":"a@b.com"}}
    );
    defer id.deinit(a);
    try testing.expect(id.present);
    try testing.expect(id.org_id_hash == null); // never sha256_12hex("")
    try testing.expect(id.org_display == null);
    var buf: [48]u8 = undefined;
    const want = try std.fmt.bufPrint(&buf, "claude:noorg:{s}", .{id.account_id_hash.?});
    try testing.expectEqualStrings(want, id.stable_label.?);
}

// ── The empty-string-hash coalescing guard (verify correction #5) ───────────

test "no identity hash is ever the hash of the empty string" {
    const a = testing.allocator;
    // a profile with an empty-string org and a real account
    const id = try ci.parseClaudeIdentity(a,
        \\{"oauthAccount":{"accountUuid":"x","organizationUuid":"","organizationName":""}}
    );
    defer id.deinit(a);
    try testing.expect(id.account_id_hash == null or !std.mem.eql(u8, id.account_id_hash.?, empty_hash));
    try testing.expect(id.org_id_hash == null); // empty org => null, never empty_hash
    try testing.expect(id.org_display == null); // empty name => null
}

// ── Fail-safe branches (never crash; present=false; hash=null) ──────────────

test "fail-safe: empty input => input_empty, unknown identity" {
    const a = testing.allocator;
    for ([_][]const u8{ "", "   \n\t " }) |raw| {
        const id = try ci.parseClaudeIdentity(a, raw);
        defer id.deinit(a);
        try testing.expect(!id.present);
        try testing.expectEqualStrings("input_empty", id.reason);
        try testing.expect(id.account_id_hash == null);
    }
}

test "fail-safe: malformed JSON => json_invalid" {
    const a = testing.allocator;
    const id = try ci.parseClaudeIdentity(a, "{ not json");
    defer id.deinit(a);
    try testing.expect(!id.present);
    try testing.expectEqualStrings("json_invalid", id.reason);
    try testing.expect(id.account_id_hash == null);
}

test "fail-safe: JSON null literal never crashes, returns unknown (reason pinned)" {
    const a = testing.allocator;
    const id = try ci.parseClaudeIdentity(a, "null");
    defer id.deinit(a);
    try testing.expect(!id.present);
    try testing.expect(id.account_id_hash == null);
    // Pin the classification so a std.json version bump can't silently change it.
    // (json `null` into a struct-typed parse is a parse error in 0.14.1 => json_invalid.)
    try testing.expectEqualStrings("json_invalid", id.reason);
}

test "fail-safe: no oauthAccount => oauth_account_missing" {
    const a = testing.allocator;
    const id = try ci.parseClaudeIdentity(a,
        \\{"userID":"abc","projects":{}}
    );
    defer id.deinit(a);
    try testing.expect(!id.present);
    try testing.expectEqualStrings("oauth_account_missing", id.reason);
    try testing.expect(id.account_id_hash == null);
}

test "fail-safe: oauthAccount without accountUuid => account_uuid_missing" {
    const a = testing.allocator;
    const id = try ci.parseClaudeIdentity(a,
        \\{"oauthAccount":{"organizationUuid":"o","emailAddress":"a@b.com"}}
    );
    defer id.deinit(a);
    try testing.expect(!id.present);
    try testing.expectEqualStrings("account_uuid_missing", id.reason);
    try testing.expect(id.account_id_hash == null);
}

test "fail-safe: empty accountUuid string => account_uuid_missing (not empty hash)" {
    const a = testing.allocator;
    const id = try ci.parseClaudeIdentity(a,
        \\{"oauthAccount":{"accountUuid":""}}
    );
    defer id.deinit(a);
    try testing.expect(!id.present);
    try testing.expectEqualStrings("account_uuid_missing", id.reason);
    try testing.expect(id.account_id_hash == null);
}
