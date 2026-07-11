const std = @import("std");

const max_fixture_bytes = 1024 * 1024;

const forbidden_markers = [_][]const u8{
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "authorization:",
    "authorization=",
    "bearer ",
    "bearer%20",
    "set-cookie:",
    "cookie:",
    "sk-",
    "sess-",
};

fn assertRedactedFixture(path: []const u8, bytes: []const u8) !void {
    for (forbidden_markers) |marker| {
        if (indexOfIgnoreCase(bytes, marker) != null) {
            std.debug.print("fixture redaction error: {s} contains forbidden marker '{s}'\n", .{ path, marker });
            return error.UnredactedFixture;
        }
    }
    if (findRawEmail(bytes) != null) {
        std.debug.print("fixture redaction error: {s} contains a raw email-like value\n", .{path});
        return error.UnredactedFixture;
    }
}

fn indexOfIgnoreCase(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0) return 0;
    if (needle.len > haystack.len) return null;

    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return i;
    }

    return null;
}

fn findRawEmail(bytes: []const u8) ?usize {
    // Browser/account-juggling evidence must use account hashes or deliberately
    // masked hints (`j***@example.com` is still too close to PII for committed
    // browser cassettes). Keep the heuristic tight enough to avoid matching
    // prose around `@`, while catching ordinary raw addresses in JSON/text.
    var at: usize = 0;
    while (std.mem.indexOfScalarPos(u8, bytes, at, '@')) |i| : (at = i + 1) {
        if (i == 0 or i + 1 >= bytes.len) continue;

        var left = i;
        while (left > 0 and isEmailLocalChar(bytes[left - 1])) : (left -= 1) {}
        var right = i + 1;
        while (right < bytes.len and isEmailDomainChar(bytes[right])) : (right += 1) {}

        const local = bytes[left..i];
        const domain = bytes[i + 1 .. right];
        if (local.len == 0 or domain.len < 3) continue;
        if (std.mem.indexOfScalar(u8, domain, '.') == null) continue;
        return i;
    }
    return null;
}

fn isEmailLocalChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '%' or c == '+' or c == '-';
}

fn isEmailDomainChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '.' or c == '-';
}

/// Walks `root_path` and asserts every file is free of forbidden secret
/// markers. Returns the number of files scanned. A missing directory is
/// only tolerated when `require_present` is false — `test/evidence/`
/// (TIN-2722) is a second walk root that may be empty or absent until a
/// capture is reviewed and promoted into it.
fn scanRootForSecrets(root_path: []const u8, require_present: bool) !usize {
    var root = std.fs.cwd().openDir(root_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => {
            if (require_present) return error.FixtureDirectoryMissing;
            return 0;
        },
        else => return err,
    };
    defer root.close();

    var walker = try root.walk(std.testing.allocator);
    defer walker.deinit();

    var scanned: usize = 0;
    while (try walker.next()) |entry| {
        if (entry.kind != .file) continue;
        scanned += 1;

        const bytes = try root.readFileAlloc(std.testing.allocator, entry.path, max_fixture_bytes);
        defer std.testing.allocator.free(bytes);

        try assertRedactedFixture(entry.path, bytes);
    }

    return scanned;
}

test "test fixtures contain no obvious OAuth secrets" {
    const scanned = try scanRootForSecrets("test/fixtures", true);
    try std.testing.expect(scanned > 0);
}

test "evidence captures contain no obvious OAuth secrets" {
    // test/evidence/ (TIN-2722) is the committed, redacted quota-observation
    // fixture root. It may be empty or absent until a capture is promoted
    // into it, so only an unredacted secret marker fails this test — not
    // an empty or missing directory.
    _ = try scanRootForSecrets("test/evidence", false);
}

const BrowserEvidenceManifest = struct {
    schema_version: u8,
    evidence_kind: []const u8,
    tracker: []const u8,
    provenance: struct {
        capture_mode: []const u8,
        cookie_values_observed: bool,
        provider_api_contract_claimed: bool,
        operator_assisted: bool,
    },
    accounts_observed: []struct {
        account_ref: []const u8,
        identity_hash: []const u8,
        identity_hash_algo: []const u8,
        raw_email_present: bool,
        cookie_value_present: bool,
    },
    observations: []struct {
        source: []const u8,
        model_class: []const u8,
        confidence: []const u8,
        raw_text_committed: bool,
    },
    singleton_switch: struct {
        attempted: bool,
        method: []const u8,
        before_identity_hash: ?[]const u8,
        after_identity_hash: ?[]const u8,
        active_harness_outcome: []const u8,
    },
    redaction: struct {
        cookie_values: bool,
        tokens: bool,
        raw_emails: bool,
        raw_account_ids: bool,
        pii_screenshots: bool,
        raw_page_dumps: bool,
    },
};

test "browser account-juggling evidence manifest is redacted and provenance-bound (TIN-2720)" {
    const path = "test/evidence/browser-account-juggling/dry-run-20260711T050543Z/manifest.json";
    const bytes = try std.fs.cwd().readFileAlloc(std.testing.allocator, path, max_fixture_bytes);
    defer std.testing.allocator.free(bytes);
    try assertRedactedFixture(path, bytes);

    const parsed = try std.json.parseFromSlice(BrowserEvidenceManifest, std.testing.allocator, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u8, 1), parsed.value.schema_version);
    try std.testing.expectEqualStrings("browser_account_juggling", parsed.value.evidence_kind);
    try std.testing.expectEqualStrings("TIN-2720", parsed.value.tracker);
    try std.testing.expectEqualStrings("operator_selected_cookie_picker_dry_run", parsed.value.provenance.capture_mode);
    try std.testing.expect(!parsed.value.provenance.cookie_values_observed);
    try std.testing.expect(!parsed.value.provenance.provider_api_contract_claimed);
    try std.testing.expect(parsed.value.provenance.operator_assisted);
    try std.testing.expect(parsed.value.accounts_observed.len >= 2);
    for (parsed.value.accounts_observed) |account| {
        try std.testing.expectEqualStrings("sha256_12hex", account.identity_hash_algo);
        try std.testing.expectEqual(@as(usize, 12), account.identity_hash.len);
        try std.testing.expect(!account.raw_email_present);
        try std.testing.expect(!account.cookie_value_present);
    }
    for (parsed.value.observations) |obs| {
        try std.testing.expect(std.mem.eql(u8, obs.source, "browser_usage_ui") or
            std.mem.eql(u8, obs.source, "browser_account_picker"));
        try std.testing.expect(!obs.raw_text_committed);
    }
    try std.testing.expect(!parsed.value.singleton_switch.attempted);
    try std.testing.expectEqualStrings("not_attempted_dry_run", parsed.value.singleton_switch.active_harness_outcome);
    try std.testing.expect(!parsed.value.redaction.cookie_values);
    try std.testing.expect(!parsed.value.redaction.tokens);
    try std.testing.expect(!parsed.value.redaction.raw_emails);
    try std.testing.expect(!parsed.value.redaction.raw_account_ids);
    try std.testing.expect(!parsed.value.redaction.pii_screenshots);
    try std.testing.expect(!parsed.value.redaction.raw_page_dumps);
}
