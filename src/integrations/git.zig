//! Git's native credential-helper boundary; no Git wrapper or request replay.
//! Credentials are scoped to the requested HTTPS context. `erase` reports a
//! rejected lease; it is never account deletion or upstream revocation.
const std = @import("std");

pub const max_input = 64 * 1024;
pub const max_line = 8192;
pub const Operation = enum { get, store, erase, unsupported };
pub const Request = struct {
    protocol: []const u8 = "",
    host: []const u8 = "",
    path: ?[]const u8 = null,
    username: ?[]const u8 = null,
    password: ?[]const u8 = null,
    password_expiry_utc: ?i64 = null,
    oauth_refresh_token: ?[]const u8 = null,
};
pub const Scope = struct {
    protocol: []const u8 = "https",
    host: []const u8,
    path: ?[]const u8 = null,
    username: ?[]const u8 = null,
};
pub const Credential = struct { username: []const u8, password: []const u8, expires_at: ?i64 = null };
pub const Counters = struct {
    gets: u64 = 0,
    stores: u64 = 0,
    erases: u64 = 0,
    unsupported: u64 = 0,
    rejected: u64 = 0,
    pub fn record(self: *Counters, op: Operation) void {
        switch (op) {
            .get => self.gets +|= 1,
            .store => self.stores +|= 1,
            .erase => self.erases +|= 1,
            .unsupported => self.unsupported +|= 1,
        }
    }
};

pub fn operation(name: []const u8) Operation {
    if (std.mem.eql(u8, name, "get")) return .get;
    if (std.mem.eql(u8, name, "store")) return .store;
    // `git credential reject` calls helpers with `erase`.
    if (std.mem.eql(u8, name, "erase")) return .erase;
    return .unsupported;
}

fn validValue(value: []const u8) bool {
    for (value) |c| if (c == 0 or c == '\n' or c == '\r' or c < 0x20 or c == 0x7f) return false;
    return true;
}

fn setOnce(target: *?[]const u8, value: []const u8) !void {
    if (target.* != null) return error.DuplicateAttribute;
    target.* = value;
}

pub fn parse(input: []const u8) !Request {
    if (input.len > max_input) return error.InputTooLarge;
    var result: Request = .{};
    var protocol: ?[]const u8 = null;
    var host: ?[]const u8 = null;
    var expiry: ?[]const u8 = null;
    var lines = std.mem.splitScalar(u8, input, '\n');
    var ended = false;
    while (lines.next()) |line| {
        if (line.len == 0) {
            ended = true;
            continue;
        }
        if (ended) return error.TrailingData;
        if (line.len > max_line) return error.LineTooLarge;
        const separator = std.mem.indexOfScalar(u8, line, '=') orelse return error.InvalidAttribute;
        const key = line[0..separator];
        const value = line[separator + 1 ..];
        if (!validValue(key) or !validValue(value) or key.len == 0) return error.InvalidAttribute;
        if (std.mem.eql(u8, key, "protocol")) try setOnce(&protocol, value) else if (std.mem.eql(u8, key, "host")) try setOnce(&host, value) else if (std.mem.eql(u8, key, "path")) try setOnce(&result.path, value) else if (std.mem.eql(u8, key, "username")) try setOnce(&result.username, value) else if (std.mem.eql(u8, key, "password")) try setOnce(&result.password, value) else if (std.mem.eql(u8, key, "oauth_refresh_token")) try setOnce(&result.oauth_refresh_token, value) else if (std.mem.eql(u8, key, "password_expiry_utc")) try setOnce(&expiry, value);
        // Git capabilities and provider-specific attributes are ignored.
    }
    result.protocol = protocol orelse return error.MissingProtocol;
    result.host = host orelse return error.MissingHost;
    if (!std.mem.eql(u8, result.protocol, "https")) return error.UnsupportedProtocol;
    if (!validHost(result.host)) return error.InvalidHost;
    if (result.path) |path| if (!validPath(path)) return error.InvalidPath;
    if (expiry) |value| result.password_expiry_utc = try std.fmt.parseInt(i64, value, 10);
    return result;
}

fn validPath(path: []const u8) bool {
    if (path.len == 0 or path[0] == '/' or path[path.len - 1] == '/' or std.mem.indexOfScalar(u8, path, '\\') != null or !validValue(path)) return false;
    var segments = std.mem.splitScalar(u8, path, '/');
    while (segments.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) return false;
        var index: usize = 0;
        var dot_count: usize = 0;
        var dot_only = true;
        while (index < segment.len) : (index += 1) {
            const c = segment[index];
            if (c == '%') {
                if (index + 2 >= segment.len) return false;
                const decoded = std.fmt.parseInt(u8, segment[index + 1 .. index + 3], 16) catch return false;
                if (decoded == '/' or decoded == '\\' or decoded == '%' or decoded < 0x20 or decoded == 0x7f) return false;
                if (decoded == '.') dot_count += 1 else dot_only = false;
                index += 2;
            } else if (c == '.') dot_count += 1 else dot_only = false;
        }
        if (dot_only and (dot_count == 1 or dot_count == 2)) return false;
    }
    return true;
}

pub fn validHost(host: []const u8) bool {
    if (host.len == 0 or host.len > 253) return false;
    // DNS/IPv4 hosts with optional numeric port. No wildcards or userinfo.
    var parts = std.mem.splitScalar(u8, host, ':');
    const hostname = parts.next().?;
    if (hostname.len == 0 or hostname[0] == '.' or hostname[hostname.len - 1] == '.') return false;
    for (hostname) |c| if (!std.ascii.isAlphanumeric(c) and c != '.' and c != '-') return false;
    if (parts.next()) |port| {
        const value = std.fmt.parseInt(u16, port, 10) catch return false;
        if (value == 0 or parts.next() != null) return false;
    }
    return true;
}

pub fn matches(scope: Scope, request: Request) bool {
    if (!std.mem.eql(u8, scope.protocol, "https") or !std.mem.eql(u8, request.protocol, "https") or !validHost(scope.host) or !validHost(request.host)) return false;
    if (!std.mem.eql(u8, scope.protocol, request.protocol) or !std.ascii.eqlIgnoreCase(scope.host, request.host)) return false;
    if (scope.username) |username| if (request.username) |requested| {
        if (!std.mem.eql(u8, username, requested)) return false;
    };
    if (scope.path) |path| {
        const requested = request.path orelse return false;
        if (!validPath(path) or !validPath(requested)) return false;
        if (!std.mem.eql(u8, path, requested)) {
            if (!std.mem.startsWith(u8, requested, path) or requested.len <= path.len or requested[path.len] != '/') return false;
        }
    }
    return true;
}

pub fn response(allocator: std.mem.Allocator, request: Request, scope: Scope, credential: Credential, now: i64) ![]u8 {
    if (!matches(scope, request)) return error.ScopeMismatch;
    if (!validValue(credential.username) or credential.username.len == 0 or !validValue(credential.password) or credential.password.len == 0) return error.InvalidCredential;
    if (scope.username) |username| if (!std.mem.eql(u8, username, credential.username)) return error.ScopeMismatch;
    if (request.username) |username| if (!std.mem.eql(u8, username, credential.username)) return error.ScopeMismatch;
    if (credential.expires_at) |expiry| {
        if (expiry <= now) return error.Expired;
        return std.fmt.allocPrint(allocator, "username={s}\npassword={s}\npassword_expiry_utc={d}\n\n", .{ credential.username, credential.password, expiry });
    }
    return std.fmt.allocPrint(allocator, "username={s}\npassword={s}\n\n", .{ credential.username, credential.password });
}

const begin_marker = "# BEGIN OMUX GIT INTEGRATION v1\n";
const end_marker = "# END OMUX GIT INTEGRATION v1\n";

/// Append one helper without resetting other helpers. Preserve existing
/// useHttpPath settings, and override it only for the supported GitHub origin
/// so repository-scoped grants receive a repository context from normal Git.
/// This makes native helper coexistence explicit; earlier complete helpers can
/// satisfy Git before Omux is consulted. Never promise exclusive routing here.
pub fn installConfig(allocator: std.mem.Allocator, original: []const u8, helper_name: []const u8) ![]u8 {
    if (std.mem.indexOf(u8, original, begin_marker) != null or std.mem.indexOf(u8, original, end_marker) != null) return error.AlreadyInstalled;
    if (helper_name.len == 0) return error.InvalidHelper;
    for (helper_name) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return error.InvalidHelper;
    return std.fmt.allocPrint(allocator, "{s}{s}{s}[credential]\n\thelper = {s}\n[credential \"https://github.com\"]\n\tuseHttpPath = true\n{s}", .{ original, if (original.len == 0 or original[original.len - 1] == '\n') "" else "\n", begin_marker, helper_name, end_marker });
}

pub fn removeConfig(allocator: std.mem.Allocator, current: []const u8, installed: []const u8, original: []const u8) ![]u8 {
    if (std.mem.eql(u8, current, installed)) return allocator.dupe(u8, original);
    const start = std.mem.indexOf(u8, current, begin_marker) orelse return error.NotInstalled;
    const finish = std.mem.indexOfPos(u8, current, start, end_marker) orelse return error.IntegrationModified;
    const end = finish + end_marker.len;
    if (std.mem.indexOfPos(u8, current, start + begin_marker.len, begin_marker) != null or std.mem.indexOfPos(u8, current, end, end_marker) != null) return error.IntegrationModified;
    const installed_start = std.mem.indexOf(u8, installed, begin_marker) orelse return error.IntegrationModified;
    if (!std.mem.eql(u8, current[start..end], installed[installed_start..])) return error.IntegrationModified;
    if (!independentSuffix(current[end..])) return error.IntegrationModified;
    return std.mem.concat(allocator, u8, &.{ current[0..start], current[end..] });
}

fn independentSuffix(suffix: []const u8) bool {
    var lines = std.mem.splitScalar(u8, suffix, '\n');
    while (lines.next()) |line| {
        const text = std.mem.trim(u8, line, " \t\r");
        if (text.len == 0 or text[0] == '#' or text[0] == ';') continue;
        // Removing a managed section must not reinterpret an appended key in
        // the preceding user section. Only independent sections are safe.
        return text[0] == '[';
    }
    return true;
}

test "credential parsing scopes paths and never exposes host credential to a subdomain" {
    const request = try parse("protocol=https\nhost=github.com\npath=lab/project.git\nusername=scientist\n\n");
    try std.testing.expect(matches(.{ .host = "github.com", .path = "lab", .username = "scientist" }, request));
    try std.testing.expect(!matches(.{ .host = "evil.github.com" }, request));
    try std.testing.expect(!matches(.{ .host = "github.com", .path = "labs" }, request));
    try std.testing.expect(!matches(.{ .host = "github.com", .path = "lab" }, .{ .protocol = "https", .host = "github.com" }));
    try std.testing.expectError(error.DuplicateAttribute, parse("protocol=https\nhost=github.com\nhost=evil.invalid\n"));
    try std.testing.expectError(error.UnsupportedProtocol, parse("protocol=http\nhost=github.com\n"));
    try std.testing.expectError(error.InvalidPath, parse("protocol=https\nhost=github.com\npath=lab/%2e%2e/other.git\n"));
    try std.testing.expectError(error.InvalidPath, parse("protocol=https\nhost=github.com\npath=lab%2fother/repo.git\n"));
    try std.testing.expectError(error.InvalidPath, parse("protocol=https\nhost=github.com\npath=lab/../other.git\n"));
    try std.testing.expectError(error.InvalidPath, parse("protocol=https\nhost=github.com\npath=lab/%2\n"));
}

test "Git response contains only materialized credentials and rejects injected fields" {
    const allocator = std.testing.allocator;
    const request = try parse("protocol=https\nhost=github.com\npath=lab/repo.git\n\n");
    const output = try response(allocator, request, .{ .host = "github.com", .path = "lab" }, .{ .username = "oauth2", .password = "fixture", .expires_at = 100 }, 50);
    defer allocator.free(output);
    try std.testing.expectEqualStrings("username=oauth2\npassword=fixture\npassword_expiry_utc=100\n\n", output);
    try std.testing.expectError(error.InvalidCredential, response(allocator, request, .{ .host = "github.com" }, .{ .username = "oauth2", .password = "secret\nquit=true" }, 50));
    try std.testing.expectError(error.Expired, response(allocator, request, .{ .host = "github.com" }, .{ .username = "oauth2", .password = "fixture", .expires_at = 50 }, 50));
    try std.testing.expectError(error.ScopeMismatch, response(allocator, request, .{ .host = "github.com", .username = "alice" }, .{ .username = "bob", .password = "fixture" }, 50));
}

test "install and remove preserve existing helpers and later unrelated changes" {
    const allocator = std.testing.allocator;
    const original = "[credential]\n helper = osxkeychain\n useHttpPath = true\n";
    const installed = try installConfig(allocator, original, "omux");
    defer allocator.free(installed);
    const current = try std.mem.concat(allocator, u8, &.{ installed, "[user]\n name = Researcher\n" });
    defer allocator.free(current);
    const removed = try removeConfig(allocator, current, installed, original);
    defer allocator.free(removed);
    const expected = original ++ "[user]\n name = Researcher\n";
    try std.testing.expectEqualStrings(expected, removed);
    var counters: Counters = .{};
    counters.record(operation("erase"));
    counters.record(operation("get"));
    try std.testing.expectEqual(@as(u64, 1), counters.erases);
    try std.testing.expectEqual(@as(u64, 1), counters.gets);
}
