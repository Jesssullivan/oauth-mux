//! Explicitly authorized native credential acquisition. No default home paths,
//! directory search, browser stores, or implicit personal-account reads.
//! Candidates remain externally owned and unverified until a declared provider
//! identity operation succeeds; copying a file never transfers refresh custody.
const std = @import("std");
const c = std.c;
const domain = @import("domain.zig");
const paths = @import("paths.zig");
const metadata = @import("platform/file_metadata.zig");

pub const maximum_source_bytes = 128 * 1024;
pub const maximum_credential_bytes = 16 * 1024;
pub const default_custody_seconds = 3600;
pub const maximum_custody_seconds = 24 * 3600;

pub const Provider = enum {
    github,
    codex,

    pub fn verifier(self: Provider) IdentityVerifier {
        return switch (self) {
            .github => .github_api,
            .codex => .codex_account_api,
        };
    }
};
/// Names a fixed-endpoint verification operation, not proof of provider support.
pub const IdentityVerifier = enum { github_api, codex_account_api };

/// Persist this exact path only after the user connects the source. Never
/// substitute a conventional auth path when this path is missing.
pub const AuthorizedSource = struct {
    source: domain.Source,
    provider: Provider,
    path: []const u8,
    custody_seconds: u32 = default_custody_seconds,
};

/// Private acquisition result. No refresh token, password or factor is copied.
/// Even direct JSON serialization emits metadata only, omitting credential and
/// fingerprint fields; callers still keep this object on the private channel.
pub const OwnedCandidate = struct {
    allocator: std.mem.Allocator,
    source_id: []u8,
    provider: Provider,
    credential_kind: domain.CredentialKind,
    ownership: domain.RenewalOwnership = .external,
    identity_verified: bool = false,
    access_token: []u8,
    /// Unverified native account-selection hint. It must match independently
    /// authenticated provider identity before admission and is never public.
    provider_account_id: ?[]u8 = null,
    /// Adapter-supplied expiry can shorten custody, never establish validity.
    expires_at_limit: ?i64 = null,
    custody_expires_at: i64,
    /// Private reconciliation token. Never publish token-derived fingerprints.
    content_digest: [32]u8,

    pub fn deinit(self: *OwnedCandidate) void {
        std.crypto.secureZero(u8, self.access_token);
        self.allocator.free(self.access_token);
        self.allocator.free(self.source_id);
        if (self.provider_account_id) |hint| {
            std.crypto.secureZero(u8, hint);
            self.allocator.free(hint);
        }
        std.crypto.secureZero(u8, &self.content_digest);
        self.* = undefined;
    }

    pub fn jsonStringify(self: OwnedCandidate, writer: anytype) !void {
        try writer.write(.{
            .source_id = self.source_id,
            .provider = self.provider,
            .credential_kind = self.credential_kind,
            .ownership = self.ownership,
            .identity_verified = false,
            .verification_required = self.provider.verifier(),
            .expires_at_limit = self.expires_at_limit,
            .custody_expires_at = self.custody_expires_at,
        });
    }
};

pub const Reconciliation = union(enum) {
    candidate: OwnedCandidate,
    /// Disappearance is detachment, not grant deletion or account removal.
    detached,

    pub fn deinit(self: *Reconciliation) void {
        switch (self.*) {
            .candidate => |*candidate| candidate.deinit(),
            .detached => {},
        }
        self.* = undefined;
    }
};

/// Parse arenas can contain unescaped credentials, including on failure.
/// Scrub every arena allocation before release and forbid reallocations which
/// could silently free an old secret-bearing buffer without that scrub.
const ScrubbingAllocator = struct {
    parent: std.mem.Allocator,
    fn allocator(self: *ScrubbingAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(context: *anyopaque, length: usize, alignment: std.mem.Alignment, address: usize) ?[*]u8 {
        const self: *ScrubbingAllocator = @ptrCast(@alignCast(context));
        return self.parent.rawAlloc(length, alignment, address);
    }
    fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        return false;
    }
    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }
    fn free(context: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, address: usize) void {
        const self: *ScrubbingAllocator = @ptrCast(@alignCast(context));
        std.crypto.secureZero(u8, bytes);
        self.parent.rawFree(bytes, alignment, address);
    }
};

const GitDocument = struct {
    access_token: ?[]const u8 = null,
    token: ?[]const u8 = null,
    expires_at: ?i64 = null,
    credential_kind: ?domain.CredentialKind = null,
};
const CodexDocument = struct {
    OPENAI_API_KEY: ?[]const u8 = null,
    tokens: ?struct { access_token: ?[]const u8 = null, account_id: ?[]const u8 = null } = null,
    expires_at: ?i64 = null,
};

fn validateToken(token: []const u8, expires_at: ?i64, now: i64) !void {
    if (token.len == 0 or token.len > maximum_credential_bytes) return error.InvalidCredential;
    for (token) |byte| if (byte < 0x21 or byte > 0x7e) return error.InvalidCredential;
    if (expires_at) |expiry| if (expiry <= now) return error.ExpiredCredential;
}

/// Parsing alone never verifies identity. Provider subjects/emails and unsigned
/// JWT claims are excluded; the native account-selection hint stays unverified.
/// The input is borrowed; callers clear their owned source buffer afterward.
pub fn parseDocument(allocator: std.mem.Allocator, provider: Provider, source_id: []const u8, document: []const u8, now: i64) !OwnedCandidate {
    if (source_id.len == 0 or source_id.len > domain.max_text_bytes) return error.InvalidSource;
    if (document.len == 0 or document.len > maximum_source_bytes) return error.InvalidSourceDocument;
    const ceiling = std.math.add(i64, now, default_custody_seconds) catch return error.InvalidCustodyLease;
    var scrub: ScrubbingAllocator = .{ .parent = allocator };
    const secure_allocator = scrub.allocator();
    const options: std.json.ParseOptions = .{ .ignore_unknown_fields = true, .allocate = .alloc_if_needed, .max_value_len = maximum_source_bytes };
    var token: []const u8 = undefined;
    var kind: domain.CredentialKind = undefined;
    var expiry: ?i64 = null;
    var owned_token: []u8 = undefined;
    var account_hint: ?[]u8 = null;
    errdefer if (account_hint) |hint| {
        std.crypto.secureZero(u8, hint);
        allocator.free(hint);
    };
    switch (provider) {
        .github => {
            const parsed = try std.json.parseFromSlice(GitDocument, secure_allocator, document, options);
            defer parsed.deinit();
            if (parsed.value.access_token != null and parsed.value.token != null) return error.AmbiguousCredential;
            token = parsed.value.access_token orelse parsed.value.token orelse return error.CredentialMissing;
            expiry = parsed.value.expires_at;
            kind = parsed.value.credential_kind orelse if (parsed.value.access_token != null) domain.CredentialKind.oauth_access else domain.CredentialKind.api_key;
            if (kind != .oauth_access and kind != .api_key) return error.UnsupportedCredentialKind;
            try validateToken(token, expiry, now);
            owned_token = try allocator.dupe(u8, token);
        },
        .codex => {
            const parsed = try std.json.parseFromSlice(CodexDocument, secure_allocator, document, options);
            defer parsed.deinit();
            const native_access = if (parsed.value.tokens) |tokens| tokens.access_token else null;
            if (parsed.value.OPENAI_API_KEY != null and native_access != null) return error.AmbiguousCredential;
            token = native_access orelse parsed.value.OPENAI_API_KEY orelse return error.CredentialMissing;
            expiry = parsed.value.expires_at;
            try validateToken(token, expiry, now);
            if (parsed.value.tokens) |tokens| if (tokens.account_id) |hint| {
                if (hint.len == 0 or hint.len > 256) return error.InvalidAccountHint;
                for (hint) |byte| if (byte < 0x21 or byte > 0x7e) return error.InvalidAccountHint;
                account_hint = try allocator.dupe(u8, hint);
            };
            owned_token = try allocator.dupe(u8, token);
            kind = if (native_access != null) .oauth_access else .api_key;
        },
    }
    errdefer {
        std.crypto.secureZero(u8, owned_token);
        allocator.free(owned_token);
    }
    const owned_source = try allocator.dupe(u8, source_id);
    errdefer allocator.free(owned_source);
    var digest: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &digest);
    std.crypto.hash.sha2.Sha256.hash(document, &digest, .{});
    return .{ .allocator = allocator, .source_id = owned_source, .provider = provider, .credential_kind = kind, .access_token = owned_token, .provider_account_id = account_hint, .expires_at_limit = expiry, .custody_expires_at = if (expiry) |limit| @min(ceiling, limit) else ceiling, .content_digest = digest };
}

fn checkSource(source: AuthorizedSource, now: i64) !void {
    if (source.source.status == .disconnected or source.source.authorized_at > now or
        (source.source.authorized_until != null and source.source.authorized_until.? <= now)) return error.SourceUnauthorized;
    if (source.source.kind != .native_store and source.source.kind != .explicit) return error.WrongSourceKind;
    if (source.source.provider.len != 0 and !std.mem.eql(u8, source.source.provider, @tagName(source.provider))) return error.SourceProviderMismatch;
    if (source.custody_seconds == 0 or source.custody_seconds > maximum_custody_seconds) return error.InvalidCustodyLease;
    try paths.validateAbsolute(source.path);
}

fn validateDirectory(status: metadata.Metadata) !void {
    const sticky_root = status.uid == 0 and status.mode & 0o1000 != 0;
    if (status.mode & c.S.IFMT != c.S.IFDIR or (status.uid != c.getuid() and status.uid != 0) or
        (status.mode & 0o022 != 0 and !sticky_root)) return error.UnsafeSourceDirectory;
}

fn validateFile(status: metadata.Metadata) !void {
    if (status.mode & c.S.IFMT != c.S.IFREG or status.uid != c.getuid() or
        status.mode & 0o077 != 0 or status.nlink != 1) return error.UnsafeSourceFile;
    if (status.size < 0 or status.size > maximum_source_bytes) return error.SourceTooLarge;
}

fn readAuthorized(io: std.Io, allocator: std.mem.Allocator, absolute_path: []const u8) ![]u8 {
    var directory = c.open("/", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (directory < 0) return error.SourceOpenFailed;
    defer _ = c.close(directory);
    var parts = std.mem.splitScalar(u8, absolute_path[1..], '/');
    var component = parts.next().?;
    while (parts.next()) |next_component| {
        try io.checkCancel();
        const status = try metadata.statFd(directory);
        try validateDirectory(status);
        const name = try allocator.dupeSentinel(u8, component, 0);
        defer allocator.free(name);
        const next = c.openat(directory, name.ptr, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
        if (next < 0) return if (c.errno(next) == .NOENT) error.SourceMissing else error.SourceOpenFailed;
        _ = c.close(directory);
        directory = next;
        component = next_component;
    }
    const parent_status = try metadata.statFd(directory);
    try validateDirectory(parent_status);
    const name = try allocator.dupeSentinel(u8, component, 0);
    defer allocator.free(name);
    const descriptor = c.openat(directory, name.ptr, .{ .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true });
    if (descriptor < 0) return if (c.errno(descriptor) == .NOENT) error.SourceMissing else error.SourceOpenFailed;
    defer _ = c.close(descriptor);
    const before = try metadata.statFd(descriptor);
    try validateFile(before);
    const bytes = try allocator.alloc(u8, maximum_source_bytes + 1);
    errdefer {
        std.crypto.secureZero(u8, bytes);
        allocator.free(bytes);
    }
    var length: usize = 0;
    var interruptions: usize = 0;
    while (length < bytes.len) {
        try io.checkCancel();
        const count = c.read(descriptor, bytes.ptr + length, bytes.len - length);
        if (count < 0) {
            if (c.errno(count) == .INTR and interruptions < 16) {
                interruptions += 1;
                continue;
            }
            return error.SourceReadFailed;
        }
        if (count == 0) break;
        length += @intCast(count);
    }
    if (length > maximum_source_bytes) return error.SourceTooLarge;
    const after = try metadata.statFd(descriptor);
    try validateFile(after);
    try requireStable(before, after, length);
    // Return an exact owned buffer so callers scrub every allocated byte.
    const result = try allocator.dupe(u8, bytes[0..length]);
    std.crypto.secureZero(u8, bytes);
    allocator.free(bytes);
    return result;
}

pub fn reconcile(io: std.Io, allocator: std.mem.Allocator, source: AuthorizedSource, now: i64) !Reconciliation {
    try checkSource(source, now);
    const document = readAuthorized(io, allocator, source.path) catch |failure| switch (failure) {
        error.SourceMissing => return .detached,
        else => return failure,
    };
    defer {
        std.crypto.secureZero(u8, document);
        allocator.free(document);
    }
    var candidate = try parseDocument(allocator, source.provider, source.source.id, document, now);
    errdefer candidate.deinit();
    const ceiling = std.math.add(i64, now, source.custody_seconds) catch return error.InvalidCustodyLease;
    candidate.custody_expires_at = if (candidate.expires_at_limit) |limit| @min(ceiling, limit) else ceiling;
    if (source.source.authorized_until) |limit| candidate.custody_expires_at = @min(candidate.custody_expires_at, limit);
    return .{ .candidate = candidate };
}

fn requireStable(before: metadata.Metadata, after: metadata.Metadata, length: usize) !void {
    if (before.ino != after.ino or before.dev != after.dev or before.size != after.size or
        after.size != @as(i64, @intCast(length)) or before.mtime_ns != after.mtime_ns or
        before.ctime_ns != after.ctime_ns) return error.SourceChanged;
}

test "native Codex candidate never adopts refresh or trusts copied identity" {
    var candidate = try parseDocument(std.testing.allocator, .codex, "source", "{\"tokens\":{\"access_token\":\"fixture-access\",\"refresh_token\":\"fixture-refresh-do-not-copy\",\"account_id\":\"unverified-subject\"},\"email\":\"unverified@example.invalid\"}", 10);
    defer candidate.deinit();
    try std.testing.expectEqual(.external, candidate.ownership);
    try std.testing.expectEqual(.oauth_access, candidate.credential_kind);
    try std.testing.expect(!candidate.identity_verified);
    try std.testing.expectEqualStrings("unverified-subject", candidate.provider_account_id.?);
    try std.testing.expectEqual(.codex_account_api, candidate.provider.verifier());
    const snapshot = try std.json.Stringify.valueAlloc(std.testing.allocator, candidate, .{});
    defer std.testing.allocator.free(snapshot);
    for ([_][]const u8{ "fixture-access", "fixture-refresh", "unverified-subject", "example.invalid", "content_digest", "access_token" }) |secret| try std.testing.expect(std.mem.indexOf(u8, snapshot, secret) == null);
}

test "explicit token parsing rejects ambiguity expiry controls and duplicate fields" {
    try std.testing.expectError(error.AmbiguousCredential, parseDocument(std.testing.allocator, .github, "source", "{\"token\":\"one\",\"access_token\":\"two\"}", 10));
    try std.testing.expectError(error.ExpiredCredential, parseDocument(std.testing.allocator, .github, "source", "{\"token\":\"fixture\",\"expires_at\":10}", 10));
    try std.testing.expectError(error.InvalidCredential, parseDocument(std.testing.allocator, .github, "source", "{\"token\":\"bearer\\nheader\"}", 10));
    try std.testing.expectError(error.DuplicateField, parseDocument(std.testing.allocator, .github, "source", "{\"token\":\"one\",\"token\":\"two\"}", 10));
    try std.testing.expectError(error.CredentialMissing, parseDocument(std.testing.allocator, .codex, "source", "{\"tokens\":{\"refresh_token\":\"never-export\"}}", 10));
}

test "escaped credentials are copied before scrubbed parse arena releases" {
    var candidate = try parseDocument(std.testing.allocator, .github, "source", "{\"token\":\"fixture-\\u0061ccess\"}", 10);
    defer candidate.deinit();
    try std.testing.expectEqualStrings("fixture-access", candidate.access_token);
    try std.testing.expectEqual(.github_api, candidate.provider.verifier());
}

test "Git acquisition preserves declared credential type and limits custody" {
    var oauth = try parseDocument(std.testing.allocator, .github, "source", "{\"access_token\":\"fixture-access\",\"expires_at\":20}", 10);
    defer oauth.deinit();
    try std.testing.expectEqual(.oauth_access, oauth.credential_kind);
    try std.testing.expectEqual(@as(i64, 20), oauth.custody_expires_at);
    var key = try parseDocument(std.testing.allocator, .github, "source", "{\"access_token\":\"fixture-key\",\"credential_kind\":\"api_key\"}", 10);
    defer key.deinit();
    try std.testing.expectEqual(.api_key, key.credential_kind);
    try std.testing.expectEqual(@as(i64, 3610), key.custody_expires_at);
    try std.testing.expectError(error.UnsupportedCredentialKind, parseDocument(std.testing.allocator, .github, "source", "{\"token\":\"fixture\",\"credential_kind\":\"oauth_refresh\"}", 10));
}

fn fixturePath(allocator: std.mem.Allocator, tmp: std.testing.TmpDir, filename: []const u8) ![]u8 {
    const cwd = try std.process.currentPathAlloc(std.testing.io, allocator);
    defer allocator.free(cwd);
    return std.fmt.allocPrint(allocator, "{s}/.zig-cache/tmp/{s}/{s}", .{ cwd, tmp.sub_path, filename });
}

test "authorized native scan imports only exact owned private file and detaches when missing" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "credential.json", .data = "{\"token\":\"fixture-native\"}" });
    if (c.fchmodat(tmp.dir.handle, "credential.json", 0o600, 0) != 0) return error.FixtureMode;
    const path = try fixturePath(std.testing.allocator, tmp, "credential.json");
    defer std.testing.allocator.free(path);
    const source: AuthorizedSource = .{ .source = .{ .id = "source", .provider = "github", .kind = .native_store }, .provider = .github, .path = path };
    var result = try reconcile(std.testing.io, std.testing.allocator, source, 10);
    defer result.deinit();
    try std.testing.expectEqualStrings("fixture-native", result.candidate.access_token);
    const missing_path = try fixturePath(std.testing.allocator, tmp, "missing.json");
    defer std.testing.allocator.free(missing_path);
    var missing = source;
    missing.path = missing_path;
    var detached = try reconcile(std.testing.io, std.testing.allocator, missing, 10);
    defer detached.deinit();
    try std.testing.expect(std.meta.activeTag(detached) == .detached);
    missing.source.status = .detached;
    missing.source.authorized_until = 20;
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "missing.json", .data = "{\"token\":\"fixture-returned\"}" });
    if (c.fchmodat(tmp.dir.handle, "missing.json", 0o600, 0) != 0) return error.FixtureMode;
    var returned = try reconcile(std.testing.io, std.testing.allocator, missing, 10);
    defer returned.deinit();
    try std.testing.expectEqualStrings("fixture-returned", returned.candidate.access_token);
    try std.testing.expectEqual(@as(i64, 20), returned.candidate.custody_expires_at);
}

test "authorization checked before any source IO and native file symlinks rejected" {
    const unauthorized: AuthorizedSource = .{ .source = .{ .id = "source", .kind = .native_store, .status = .disconnected }, .provider = .github, .path = "/does-not-exist/never-read" };
    try std.testing.expectError(error.SourceUnauthorized, reconcile(std.testing.io, std.testing.allocator, unauthorized, 10));
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "credential.json", .data = "{\"token\":\"fixture-native\"}" });
    if (c.fchmodat(tmp.dir.handle, "credential.json", 0o600, 0) != 0 or c.symlinkat("credential.json", tmp.dir.handle, "alias.json") != 0) return error.FixtureMode;
    const path = try fixturePath(std.testing.allocator, tmp, "alias.json");
    defer std.testing.allocator.free(path);
    try std.testing.expectError(error.SourceOpenFailed, reconcile(std.testing.io, std.testing.allocator, .{ .source = .{ .id = "source", .kind = .native_store }, .provider = .github, .path = path }, 10));
}

test "world readable native credentials fail closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "credential.json", .data = "{\"token\":\"fixture-native\"}" });
    if (c.fchmodat(tmp.dir.handle, "credential.json", 0o644, 0) != 0) return error.FixtureMode;
    const path = try fixturePath(std.testing.allocator, tmp, "credential.json");
    defer std.testing.allocator.free(path);
    try std.testing.expectError(error.UnsafeSourceFile, reconcile(std.testing.io, std.testing.allocator, .{ .source = .{ .id = "source", .kind = .native_store }, .provider = .github, .path = path }, 10));
}

test "same-size source rewrites are detected through modification timestamps" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "credential.json", .data = "same-size" });
    const descriptor = c.openat(tmp.dir.handle, "credential.json", .{ .NOFOLLOW = true, .CLOEXEC = true });
    if (descriptor < 0) return error.FixtureOpen;
    defer _ = c.close(descriptor);
    const before = try metadata.statFd(descriptor);
    try tmp.dir.writeFile(std.testing.io, .{ .sub_path = "credential.json", .data = "rewritten" });
    const changed = [_]c.timespec{ .{ .sec = 1, .nsec = 0 }, .{ .sec = 2, .nsec = 0 } };
    if (c.utimensat(tmp.dir.handle, "credential.json", &changed, 0) != 0) return error.FixtureTime;
    const after = try metadata.statFd(descriptor);
    try std.testing.expectEqual(before.size, after.size);
    try std.testing.expectError(error.SourceChanged, requireStable(before, after, 9));
}
