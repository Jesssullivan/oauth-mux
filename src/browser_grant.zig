//! Browser source scopes survive import. A source/store/partition is provenance,
//! never provider identity. Import validates custody; identity verification is
//! a separate fixed-endpoint operation before account enrollment.
const std = @import("std");

pub const SameSite = enum { unspecified, no_restriction, lax, strict };
pub const PartitionKey = struct {
    top_level_site: []const u8,
    has_cross_site_ancestor: ?bool = null,

    pub fn eql(a: PartitionKey, b: PartitionKey) bool {
        return std.mem.eql(u8, a.top_level_site, b.top_level_site) and a.has_cross_site_ancestor == b.has_cross_site_ancestor;
    }
};

pub const Cookie = struct {
    name: []const u8,
    value: []const u8,
    domain: []const u8,
    path: []const u8,
    host_only: bool,
    secure: bool,
    http_only: bool,
    same_site: SameSite = .unspecified,
    store_id: []const u8,
    partition_key: ?PartitionKey = null,
    first_party_domain: ?[]const u8 = null,
    /// null is a browser session cookie, not an infinite provider lifetime.
    expires_unix: ?i64 = null,
};

pub const StorageEntry = struct {
    origin: []const u8,
    key: []const u8,
    value: []const u8,
};

pub const Manifest = struct {
    host: []const u8,
    allowed_cookie_names: []const []const u8,
    allowed_cookie_paths: []const []const u8,
    allowed_storage_keys: []const []const u8 = &.{},
    exportability: enum { reusable, browser_required } = .browser_required,
};

pub const Context = struct {
    host: []const u8,
    request_path: []const u8,
    secure: bool = true,
    store_id: []const u8,
    partition_key: ?PartitionKey = null,
    first_party_domain: ?[]const u8 = null,
    now_unix: i64,
    /// Omux's custody ceiling may shorten, never lengthen, provider validity.
    custody_until_unix: i64,
};

pub const Limits = struct {
    pub const cookies = 32;
    pub const storage_entries = 16;
    pub const name_bytes = 128;
    pub const value_bytes = 8192;
    pub const capsule_bytes = 128 * 1024;
    pub const header_bytes = 16 * 1024;
};

/// Header and origin/lease provenance travel together to the network owner.
/// Metadata is borrowed from Context; bytes are owned by the caller.
pub const ScopedHeader = struct {
    bytes: []u8,
    host: []const u8,
    request_path: []const u8,
    store_id: []const u8,
    partition_key: ?PartitionKey,
    first_party_domain: ?[]const u8,
    custody_until_unix: i64,
    provider_expires_unix: ?i64,

    pub fn deinit(self: *ScopedHeader, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, self.bytes);
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub fn buildScopedCookieHeader(allocator: std.mem.Allocator, manifest: Manifest, context: Context, cookies: []const Cookie) !ScopedHeader {
    const bytes = try buildCookieHeader(allocator, manifest, context, cookies);
    var provider_expires: ?i64 = null;
    for (cookies) |cookie| {
        if (!pathMatches(context.request_path, cookie.path)) continue;
        if (cookie.expires_unix) |expiry| provider_expires = if (provider_expires) |prior| @min(prior, expiry) else expiry;
    }
    return .{ .bytes = bytes, .host = context.host, .request_path = context.request_path, .store_id = context.store_id, .partition_key = context.partition_key, .first_party_domain = context.first_party_domain, .custody_until_unix = context.custody_until_unix, .provider_expires_unix = provider_expires };
}

pub fn validateImport(manifest: Manifest, context: Context, cookies: []const Cookie, storage: []const StorageEntry) !void {
    if (manifest.exportability == .browser_required) return error.BrowserRequired;
    if (!validHost(manifest.host) or !std.mem.eql(u8, context.host, manifest.host)) return error.UndeclaredOrigin;
    if (!context.secure or !validPath(context.request_path)) return error.InvalidContext;
    if (!validStoreId(context.store_id)) return error.InvalidContext;
    if (context.first_party_domain) |domain| if (!validFirstPartyDomain(domain)) return error.InvalidContext;
    if (context.custody_until_unix <= context.now_unix) return error.CustodyExpired;
    if (cookies.len > Limits.cookies or storage.len > Limits.storage_entries) return error.CapsuleTooLarge;
    if (context.partition_key) |key| try validatePartition(key);
    var total: usize = 0;
    for (cookies, 0..) |cookie, index| {
        if (!listed(manifest.allowed_cookie_names, cookie.name) or !listed(manifest.allowed_cookie_paths, cookie.path)) return error.UndeclaredCookie;
        if (!validCookieName(cookie.name) or !validCookieValue(cookie.value)) return error.InvalidCookie;
        if (!validPath(cookie.path) or !cookie.secure) return error.InvalidCookie;
        const declared_domain = if (std.mem.startsWith(u8, cookie.domain, ".")) cookie.domain[1..] else cookie.domain;
        // The reviewed manifest names the exact export domain. RFC suffix
        // matching alone would also admit public suffixes such as co.uk.
        if (!std.mem.eql(u8, declared_domain, manifest.host) or !domainMatches(manifest.host, cookie.domain, cookie.host_only)) return error.CookieDomainMismatch;
        if (!std.mem.eql(u8, cookie.store_id, context.store_id) or !partitionEqual(cookie.partition_key, context.partition_key) or !optionalEqual(cookie.first_party_domain, context.first_party_domain)) return error.SourceScopeMismatch;
        if (cookie.partition_key) |key| try validatePartition(key);
        if (cookie.first_party_domain) |domain| if (!validFirstPartyDomain(domain)) return error.InvalidCookie;
        if (cookie.expires_unix) |expiry| if (expiry <= context.now_unix) return error.ProviderExpired;
        if (std.mem.startsWith(u8, cookie.name, "__Host-") and (!cookie.host_only or !std.mem.eql(u8, cookie.path, "/"))) return error.InvalidCookie;
        for (cookies[0..index]) |prior| {
            if (std.mem.eql(u8, prior.name, cookie.name) and std.mem.eql(u8, prior.domain, cookie.domain) and std.mem.eql(u8, prior.path, cookie.path)) return error.DuplicateCookie;
        }
        total += cookie.name.len + cookie.value.len + cookie.domain.len + cookie.path.len;
    }
    for (storage, 0..) |entry, index| {
        if (!listed(manifest.allowed_storage_keys, entry.key)) return error.UndeclaredStorage;
        if (!originMatches(entry.origin, manifest.host)) return error.UndeclaredOrigin;
        if (entry.value.len > Limits.value_bytes) return error.CapsuleTooLarge;
        for (storage[0..index]) |prior| if (std.mem.eql(u8, entry.key, prior.key)) return error.DuplicateStorage;
        total += entry.origin.len + entry.key.len + entry.value.len;
    }
    if (total > Limits.capsule_bytes) return error.CapsuleTooLarge;
}

/// No cross-store merging, implicit discovery, URL rewriting, or browser lifetime
/// extension occurs here. Caller securely destroys the returned header after use.
pub fn buildCookieHeader(allocator: std.mem.Allocator, manifest: Manifest, context: Context, cookies: []const Cookie) ![]u8 {
    try validateImport(manifest, context, cookies, &.{});
    var output: std.ArrayList(u8) = .empty;
    errdefer {
        std.crypto.secureZero(u8, output.items);
        output.deinit(allocator);
    }
    // RFC cookie ordering: longest paths precede shorter paths. Imports do not
    // pretend to know browser creation time; equal paths retain source ordering.
    var indices: [Limits.cookies]usize = undefined;
    var count: usize = 0;
    for (cookies, 0..) |cookie, index| {
        if (!pathMatches(context.request_path, cookie.path)) continue;
        var position = count;
        while (position > 0 and cookies[indices[position - 1]].path.len < cookie.path.len) : (position -= 1) indices[position] = indices[position - 1];
        indices[position] = index;
        count += 1;
    }
    for (indices[0..count]) |index| {
        const cookie = cookies[index];
        if (output.items.len + cookie.name.len + cookie.value.len + 3 > Limits.header_bytes) return error.HeaderTooLarge;
        if (output.items.len != 0) try output.appendSlice(allocator, "; ");
        try output.appendSlice(allocator, cookie.name);
        try output.append(allocator, '=');
        try output.appendSlice(allocator, cookie.value);
    }
    if (count == 0) return error.NoMatchingCookies;
    return output.toOwnedSlice(allocator);
}

fn listed(names: []const []const u8, value: []const u8) bool {
    for (names) |name| if (std.mem.eql(u8, name, value)) return true;
    return false;
}

fn validCookieName(name: []const u8) bool {
    if (name.len == 0 or name.len > Limits.name_bytes) return false;
    for (name) |byte| if (byte <= 0x20 or byte >= 0x7f or std.mem.indexOfScalar(u8, "()<>@,;:\\[]?={}/\"", byte) != null) return false;
    return true;
}

fn validStoreId(value: []const u8) bool {
    if (value.len == 0 or value.len > 128) return false;
    for (value) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '-' and byte != ':' and byte != '.') return false;
    return true;
}

fn validCookieValue(value: []const u8) bool {
    if (value.len > Limits.value_bytes) return false;
    for (value) |byte| if (byte < 0x21 or byte >= 0x7f or byte == ';' or byte == ',' or byte == '\\' or byte == '"') return false;
    return true;
}

fn validHost(host: []const u8) bool {
    if (host.len == 0 or host.len > 253 or host[0] == '.' or host[host.len - 1] == '.') return false;
    for (host) |byte| if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and byte != '.' and byte != '-') return false;
    return std.mem.indexOf(u8, host, "..") == null;
}

fn validPath(path: []const u8) bool {
    if (path.len == 0 or path.len > 1024 or path[0] != '/') return false;
    for (path) |byte| if (byte < 0x21 or byte >= 0x7f or byte == '?' or byte == '#' or byte == '\\') return false;
    return true;
}

pub fn domainMatches(host: []const u8, cookie_domain: []const u8, host_only: bool) bool {
    const domain = if (std.mem.startsWith(u8, cookie_domain, ".")) cookie_domain[1..] else cookie_domain;
    if (!validHost(host) or !validHost(domain)) return false;
    if (host_only) return !std.mem.startsWith(u8, cookie_domain, ".") and std.mem.eql(u8, host, domain);
    // Single-label domains cannot be exported. Import additionally requires the
    // exact manifest domain instead of attempting an incomplete public-suffix list.
    if (std.mem.indexOfScalar(u8, domain, '.') == null) return false;
    if (std.mem.eql(u8, host, domain)) return true;
    return host.len > domain.len and std.mem.endsWith(u8, host, domain) and host[host.len - domain.len - 1] == '.';
}

pub fn pathMatches(request_path: []const u8, cookie_path: []const u8) bool {
    if (!std.mem.startsWith(u8, request_path, cookie_path)) return false;
    return request_path.len == cookie_path.len or std.mem.endsWith(u8, cookie_path, "/") or request_path[cookie_path.len] == '/';
}

fn originMatches(origin: []const u8, host: []const u8) bool {
    if (!std.mem.startsWith(u8, origin, "https://")) return false;
    return std.mem.eql(u8, origin["https://".len..], host);
}

pub fn validatePartition(key: PartitionKey) !void {
    if (!std.mem.startsWith(u8, key.top_level_site, "https://") or !validHost(key.top_level_site["https://".len..])) return error.InvalidPartition;
}

pub fn validFirstPartyDomain(domain: []const u8) bool {
    return domain.len == 0 or validHost(domain);
}

fn partitionEqual(a: ?PartitionKey, b: ?PartitionKey) bool {
    if (a) |first| return if (b) |second| first.eql(second) else false;
    return b == null;
}

fn optionalEqual(a: ?[]const u8, b: ?[]const u8) bool {
    if (a) |first| return if (b) |second| std.mem.eql(u8, first, second) else false;
    return b == null;
}

test "browser imports retain scope, lease and path semantics" {
    const manifest: Manifest = .{ .host = "fixture.invalid", .allowed_cookie_names = &.{ "session", "detail" }, .allowed_cookie_paths = &.{ "/", "/api" }, .exportability = .reusable };
    const context: Context = .{ .host = "fixture.invalid", .request_path = "/api/profile", .store_id = "store-1", .now_unix = 100, .custody_until_unix = 200 };
    var cookies = [_]Cookie{
        .{ .name = "session", .value = "opaque1", .domain = "fixture.invalid", .path = "/", .host_only = true, .secure = true, .http_only = true, .store_id = "store-1", .expires_unix = 150 },
        .{ .name = "detail", .value = "opaque2", .domain = ".fixture.invalid", .path = "/api", .host_only = false, .secure = true, .http_only = true, .store_id = "store-1" },
    };
    const header = try buildCookieHeader(std.testing.allocator, manifest, context, &cookies);
    defer std.testing.allocator.free(header);
    try std.testing.expectEqualStrings("detail=opaque2; session=opaque1", header);
    var scoped = try buildScopedCookieHeader(std.testing.allocator, manifest, context, &cookies);
    defer scoped.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(i64, 200), scoped.custody_until_unix);
    try std.testing.expectEqual(@as(?i64, 150), scoped.provider_expires_unix);
    try std.testing.expectEqualStrings("store-1", scoped.store_id);
    cookies[0].store_id = "store-2";
    try std.testing.expectError(error.SourceScopeMismatch, validateImport(manifest, context, &cookies, &.{}));
    cookies[0].store_id = "store-1";
    cookies[0].expires_unix = 99;
    try std.testing.expectError(error.ProviderExpired, validateImport(manifest, context, &cookies, &.{}));
}

test "partition or undeclared scope cannot flatten into portable authority" {
    const manifest: Manifest = .{ .host = "fixture.invalid", .allowed_cookie_names = &.{"session"}, .allowed_cookie_paths = &.{"/"}, .exportability = .reusable };
    const context: Context = .{ .host = "fixture.invalid", .request_path = "/", .store_id = "store-1", .now_unix = 1, .custody_until_unix = 100 };
    var cookie: Cookie = .{ .name = "session", .value = "opaque", .domain = "fixture.invalid", .path = "/", .host_only = true, .secure = true, .http_only = true, .store_id = "store-1", .partition_key = .{ .top_level_site = "https://other.invalid" } };
    try std.testing.expectError(error.SourceScopeMismatch, validateImport(manifest, context, &.{cookie}, &.{}));
    cookie.partition_key = null;
    cookie.value = "value; injected=secret";
    try std.testing.expectError(error.InvalidCookie, validateImport(manifest, context, &.{cookie}, &.{}));
    cookie.value = "opaque";
    cookie.name = "unrelated";
    try std.testing.expectError(error.UndeclaredCookie, validateImport(manifest, context, &.{cookie}, &.{}));
    try std.testing.expect(!domainMatches("fixture.invalid.evil.invalid", "fixture.invalid", false));
    try std.testing.expect(!domainMatches("fixture.invalid", ".invalid", false));
    try std.testing.expect(!pathMatches("/apix", "/api"));
    var bound = manifest;
    bound.exportability = .browser_required;
    try std.testing.expectError(error.BrowserRequired, validateImport(bound, context, &.{cookie}, &.{}));
}

test "browser context identifiers cannot carry path or diagnostic injection" {
    const manifest: Manifest = .{ .host = "fixture.invalid", .allowed_cookie_names = &.{"session"}, .allowed_cookie_paths = &.{"/"}, .exportability = .reusable };
    var context: Context = .{ .host = "fixture.invalid", .request_path = "/", .store_id = "../store", .now_unix = 1, .custody_until_unix = 100 };
    try std.testing.expectError(error.InvalidContext, validateImport(manifest, context, &.{}, &.{}));
    context.store_id = "store\nforged";
    try std.testing.expectError(error.InvalidContext, validateImport(manifest, context, &.{}, &.{}));
    context.store_id = "firefox-container-1";
    try validateImport(manifest, context, &.{}, &.{});
}
