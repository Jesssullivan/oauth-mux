//! Omux OSS Sign in with ChatGPT verified identity and paired response proof.
//! Only actual ticket + token completion + JWKS owner capabilities enter here.
//! This proof is not model entitlement, workspace linking or renewal policy.
const std = @import("std");
const crypto = @import("oauth_oidc_crypto.zig");
const issue = @import("oauth_issue_authority.zig");
const token = @import("oauth_token.zig");
const transport = @import("transport.zig");
const envelope = @import("envelope.zig");
const Hash = std.crypto.hash.sha2.Sha256;
pub const resource = "https://api.openai.com/v1";
const max_jwks_age_seconds = 300;
const ProofData = struct {
    allocator: std.mem.Allocator,
    client: []u8,
    subject: []u8,
    binding_sha256: [32]u8,
    profile_sha256: [32]u8,
    nonce_sha256: [32]u8,
    response_sha256: [32]u8,
    pair_sha256: [32]u8,
    identity_sha256: [32]u8,
    received_at: i64,
    id_expires_at: i64,
    access_expires_at: i64,
    deadline: transport.AbsoluteDeadline,
    jwks: *transport.JwksLease,
};

/// Only verifyOwnedResponse constructs this opaque owner. No caller-supplied
/// subject, key set, source digest, tuple or "verified" flag is a constructor.
pub const VerifiedProfile = opaque {
    pub fn deinit(self: *VerifiedProfile) void {
        const data = mutable(self);
        data.jwks.deinit();
        wipeFree(data.allocator, data.client);
        wipeFree(data.allocator, data.subject);
        const a = data.allocator;
        std.crypto.secureZero(u8, std.mem.asBytes(data));
        a.destroy(data);
    }
    pub fn identityCommitment(self: *const VerifiedProfile) [32]u8 { return view(self).identity_sha256; }
    /// Signed provider subject association, separate from registration. The
    /// official OSS claims do not disclose a workspace or independent quota
    /// bucket: adding a client registration must never multiply capacity.
    pub fn providerSubjectCommitment(self: *const VerifiedProfile) [32]u8 {
        return providerSubjectDigest(view(self).subject);
    }
    pub fn accessExpiresAt(self: *const VerifiedProfile) i64 { return view(self).access_expires_at; }
    pub fn responseSha256(self: *const VerifiedProfile) [32]u8 { return view(self).response_sha256; }
    pub fn bindingSha256(self: *const VerifiedProfile) [32]u8 { return view(self).binding_sha256; }
    /// Registration authority commitment, not a provider quota-bucket identity.
    pub fn issuedClientCommitment(self: *const VerifiedProfile) [32]u8 {
        var hash = Hash.init(.{});
        framed(&hash, "omux-siwc-issued-client-v1");
        framed(&hash, view(self).client);
        var result: [32]u8 = undefined;
        hash.final(&result);
        return result;
    }
    /// Exact verified activation tuple. This digest is useful only together
    /// with this opaque owner and its recheck; it is never a proof constructor.
    pub fn activationCommitment(self: *const VerifiedProfile) [32]u8 {
        const data = view(self);
        var hash = Hash.init(.{});
        framed(&hash, "omux-siwc-activation-v1");
        framed(&hash, crypto.issuer);
        framed(&hash, resource);
        framed(&hash, "RS256");
        framed(&hash, data.client);
        for ([_][32]u8{ data.binding_sha256, data.profile_sha256, data.nonce_sha256,
            data.response_sha256, data.pair_sha256, data.identity_sha256, data.jwks.sha256() }) |digest| hash.update(&digest);
        var number: [8]u8 = undefined;
        for ([_]i64{ data.received_at, data.id_expires_at, data.access_expires_at, data.jwks.receivedUnix() }) |value| {
            std.mem.writeInt(i64, &number, value, .big);
            hash.update(&number);
        }
        var cutoff: [12]u8 = undefined;
        std.mem.writeInt(i96, &cutoff, data.deadline.until.raw.nanoseconds, .big);
        hash.update(&cutoff);
        var result: [32]u8 = undefined;
        hash.final(&result);
        return result;
    }

    /// Private-custody call site only: encrypt immediately, never send to control
    /// RPC/logs. No email or inferred workspace/account hint is included.
    pub fn copyIdentityForEncryption(self: *const VerifiedProfile, a: std.mem.Allocator) !envelope.Secret {
        const data = view(self);
        try checkTimes(data.deadline, data.received_at, data.id_expires_at, data.access_expires_at);
        try data.jwks.recheck(data.deadline);
        const bytes = try std.json.Stringify.valueAlloc(a, .{ .schema_version = @as(u32, 1), .issuer = crypto.issuer,
            .client_id = data.client, .subject = data.subject }, .{});
        errdefer wipeFree(a, bytes);
        if (bytes.len > 4096) return error.OidcIdentityTooLarge;
        try checkTimes(data.deadline, data.received_at, data.id_expires_at, data.access_expires_at);
        try data.jwks.recheck(data.deadline);
        return .{ .allocator = a, .bytes = bytes };
    }

    /// Required before paired ciphertext grant commit after actor Store fences.
    /// It rejects mutation of any parsed secret/scope/expiry field after verify.
    pub fn matchesEvidence(self: *const VerifiedProfile, ticket: *const issue.IssuedTicket, evidence: *const token.Evidence) !void {
        const data = view(self);
        try recheckTicket(data, ticket);
        try data.jwks.recheckTicket(ticket);
        if (!same(data.response_sha256, evidence.response_sha256) or !same(data.pair_sha256, try pairDigest(evidence))) return error.OidcResponseChanged;
        try checkTimes(data.deadline, data.received_at, data.id_expires_at, data.access_expires_at);
        try data.jwks.recheck(data.deadline);
        try recheckTicket(data, ticket);
    }

    /// Authentic response producer join is mandatory as well as parsed pair
    /// equality. Hashes alone are never endpoint/TLS/transaction authority.
    pub fn recheck(self: *const VerifiedProfile, ticket: *const issue.IssuedTicket, response: *const transport.OAuthResponse) !void {
        const data = view(self);
        try recheckTicket(data, ticket);
        try response.recheck(ticket);
        if (!response.isOwnOss() or response.status() != 200 or response.receivedUnix() != data.received_at or
            !same(response.responseSha256(), data.response_sha256) or
            !std.mem.eql(u8, response.issuedClientId(), data.client)) return error.OidcResponseChanged;
        var evidence = try response.evidence(data.allocator);
        defer evidence.deinit();
        try self.matchesEvidence(ticket, &evidence);
        try response.recheck(ticket);
    }
};
fn view(self: *const VerifiedProfile) *const ProofData { return @ptrCast(@alignCast(self)); }
fn mutable(self: *VerifiedProfile) *ProofData { return @ptrCast(@alignCast(self)); }
fn wipeFree(a: std.mem.Allocator, bytes: []u8) void { std.crypto.secureZero(u8, bytes); a.free(bytes); }
fn same(a: [32]u8, b: [32]u8) bool { return std.crypto.timing_safe.eql([32]u8, a, b); }
fn checkAccessHash(expected: ?[16]u8, access: []const u8) !void {
    // When supplied, this claim is inside the already verified ID signature.
    // Otherwise the actual matching OAuth response remains the pair authority.
    if (expected) |signed| {
        var digest: [32]u8 = undefined;
        Hash.hash(access, &digest, .{});
        if (!std.crypto.timing_safe.eql([16]u8, signed, digest[0..16].*)) return error.OidcAccessHashMismatch;
    }
}

/// Runs in bounded trusted work under the ticket's ORIGINAL awake cutoff.
/// Caller must separately recheck actor source/consent/forget/generation/Store
/// issued row before AND after verification; this function performs no SQL.
pub fn verifyOwnedResponse(a: std.mem.Allocator, ticket: *const issue.IssuedTicket, response: *const transport.OAuthResponse, jwks: *transport.JwksLease) !*VerifiedProfile {
    try ticket.requireOwnedOssEnrollment();
    try ticket.checkBeforeVerification();
    const deadline: transport.AbsoluteDeadline = .{ .io = ticket.clockIo(), .until = ticket.originalUntil() };
    _ = try deadline.remaining();
    try response.recheck(ticket);
    try jwks.recheckTicket(ticket);
    try jwks.recheck(deadline);
    if (!response.isOwnOss() or response.status() != 200 or !std.mem.eql(u8, ticket.issuedClientId(), response.issuedClientId())) return error.OidcResponseChanged;
    const received = response.receivedUnix();
    const now = try wallTime(deadline.io);
    const key_time = jwks.receivedUnix();
    if (key_time <= 0 or key_time > 253_402_300_799 or key_time > now + 5 or now - key_time > max_jwks_age_seconds or received <= 0 or received > 253_402_300_799 or received > now + 5) return error.OidcClockChanged;
    var evidence = try response.evidence(a);
    defer evidence.deinit();
    if (!same(evidence.response_sha256, response.responseSha256())) return error.OidcResponseChanged;
    const identity = evidence.id_token orelse return error.OidcIdentityMissing;
    var claims = try crypto.verifyIdToken(a, identity, jwks.bytes(), ticket.issuedClientId(), ticket.nonceDigest(), now);
    defer claims.deinit();
    try checkAccessHash(claims.access_token_hash, evidence.access_token);
    const pair = try pairDigest(&evidence);
    const seconds = evidence.expires_in orelse return error.OidcExpiryMissing;
    // Access expiry comes from actual token completion time, never later parse
    // or JWKS fetch time. Official one-hour contract bounds accepted metadata.
    if (seconds == 0 or seconds > 3600) return error.OidcExpiryInvalid;
    const access_until = std.math.add(i64, received, seconds) catch return error.OidcExpiryInvalid;
    const expires = @min(access_until, claims.expires_at);
    try checkTimes(deadline, received, claims.expires_at, expires);
    const binding = try ticket.bindingSha256(a);
    const client = try a.dupe(u8, ticket.issuedClientId());
    errdefer wipeFree(a, client);
    const subject = try a.dupe(u8, claims.subject);
    errdefer wipeFree(a, subject);
    const data = try a.create(ProofData);
    errdefer { std.crypto.secureZero(u8, std.mem.asBytes(data)); a.destroy(data); }
    const subject_hash = identityDigest(client, subject);
    // Retain the authentic same-attempt keys through final paired actor commit.
    jwks.retain();
    errdefer jwks.deinit();
    data.* = .{ .allocator = a, .client = client, .subject = subject, .binding_sha256 = binding,
        .profile_sha256 = ticket.registrationProfileSha256(), .nonce_sha256 = ticket.nonceDigest(),
        .response_sha256 = evidence.response_sha256, .pair_sha256 = pair, .identity_sha256 = subject_hash,
        .received_at = received, .id_expires_at = claims.expires_at, .access_expires_at = expires,
        .deadline = deadline, .jwks = jwks };
    const proof: *VerifiedProfile = @ptrCast(data);
    try proof.recheck(ticket, response);
    // Last original-clock/fence/key check after every allocation and readback.
    try jwks.recheck(deadline);
    try jwks.recheckTicket(ticket);
    try ticket.checkBeforeVerification();
    _ = try deadline.remaining();
    return proof;
}
fn checkTimes(deadline: transport.AbsoluteDeadline, received: i64, identity_until: i64, access_until: i64) !void {
    _ = try deadline.remaining();
    const now = try wallTime(deadline.io);
    if (received <= 0 or received > 253_402_300_799 or received > now + 5 or identity_until <= now or access_until <= now) return error.OidcTokenExpired;
}
fn wallTime(io: std.Io) !i64 {
    const now = std.Io.Clock.real.now(io).toSeconds();
    if (now <= 0 or now > 253_402_300_794) return error.OidcClockChanged;
    return now;
}
fn recheckTicket(data: *const ProofData, ticket: *const issue.IssuedTicket) !void {
    try ticket.requireOwnedOssEnrollment();
    try ticket.checkBeforeVerification();
    if (!std.meta.eql(data.deadline.io, ticket.clockIo()) or !std.meta.eql(data.deadline.until, ticket.originalUntil()) or
        !same(data.binding_sha256, try ticket.bindingSha256(data.allocator)) or
        !same(data.profile_sha256, ticket.registrationProfileSha256()) or !same(data.nonce_sha256, ticket.nonceDigest()) or
        !std.mem.eql(u8, data.client, ticket.issuedClientId())) return error.OidcAuthorityChanged;
    _ = try data.deadline.remaining();
}
fn framed(hash: *Hash, value: []const u8) void {
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, @intCast(value.len), .big);
    hash.update(&length);
    hash.update(value);
}
fn optional(hash: *Hash, value: ?[]const u8) void {
    hash.update(if (value != null) "\x01" else "\x00");
    if (value) |bytes| framed(hash, bytes);
}
fn identityDigest(client: []const u8, subject: []const u8) [32]u8 {
    var hash = Hash.init(.{});
    framed(&hash, "omux-siwc-identity-v1");
    framed(&hash, crypto.issuer);
    framed(&hash, client);
    framed(&hash, subject);
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}
fn providerSubjectDigest(subject: []const u8) [32]u8 {
    var hash = Hash.init(.{});
    framed(&hash, "omux-siwc-provider-subject-v1");
    framed(&hash, crypto.issuer);
    framed(&hash, subject);
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}
fn pairDigest(value: *const token.Evidence) ![32]u8 {
    // Parser output remains unverified. Explicit small limits bound every hash.
    if (value.access_token.len == 0 or value.access_token.len > token.max_credential_bytes or value.refresh_token == null or
        value.id_token == null or value.scope == null or value.expires_in == null) return error.OidcPairMissing;
    for ([_]?[]const u8{ value.refresh_token, value.id_token }) |field| if (field) |bytes| {
        if (bytes.len == 0 or bytes.len > token.max_credential_bytes) return error.OidcPairMissing;
    };
    try scopes(value.scope.?);
    var hash = Hash.init(.{});
    framed(&hash, "omux-siwc-exact-response-pair-v1");
    hash.update(&value.response_sha256);
    framed(&hash, value.access_token);
    optional(&hash, value.refresh_token);
    optional(&hash, value.id_token);
    optional(&hash, value.scope);
    var number: [8]u8 = undefined;
    std.mem.writeInt(u64, &number, value.expires_in.?, .big);
    hash.update(&number);
    hash.update(if (value.earliest_refresh_at != null) "\x01" else "\x00");
    if (value.earliest_refresh_at) |at| {
        if (at < 0 or at > 253_402_300_799) return error.OidcExpiryInvalid;
        std.mem.writeInt(u64, &number, @intCast(at), .big);
        hash.update(&number);
    }
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}
fn scopes(value: []const u8) !void {
    if (value.len == 0 or value.len > 4096) return error.OidcScopeMissing;
    var parts = std.mem.splitScalar(u8, value, ' ');
    var seen: [6][]const u8 = undefined;
    var count: usize = 0;
    var direct = false;
    var invoke = false;
    var identity = false;
    var offline = false;
    while (parts.next()) |part| {
        if (part.len == 0 or count == seen.len) return error.OidcScopeInvalid;
        for (seen[0..count]) |prior| if (std.mem.eql(u8, prior, part)) return error.OidcScopeInvalid;
        var known = false;
        for ([_][]const u8{ "openid", "profile", "email", "offline_access", "resource.invoke", "chatgpt.tokens.use.direct" }) |allowed| if (std.mem.eql(u8, part, allowed)) { known = true; break; };
        if (!known) return error.OidcScopeInvalid;
        seen[count] = part;
        count += 1;
        direct = direct or std.mem.eql(u8, part, "chatgpt.tokens.use.direct");
        invoke = invoke or std.mem.eql(u8, part, "resource.invoke");
        identity = identity or std.mem.eql(u8, part, "openid");
        offline = offline or std.mem.eql(u8, part, "offline_access");
    }
    if (!direct or !invoke or !identity or !offline) return error.OidcScopeMissing;
}

test "returned direct scope relation refuses callback-only missing duplicate and unknown scope" {
    try scopes("openid offline_access resource.invoke chatgpt.tokens.use.direct");
    try scopes("chatgpt.tokens.use.direct email offline_access openid profile resource.invoke");
    for ([_][]const u8{
        "openid profile email offline_access", "resource.invoke chatgpt.tokens.use.direct",
        "openid resource.invoke chatgpt.tokens.use.direct", "openid offline_access resource.invoke",
    }) |bad| try std.testing.expectError(error.OidcScopeMissing, scopes(bad));
    for ([_][]const u8{
        "openid offline_access resource.invoke chatgpt.tokens.use.direct unknown",
        "openid openid offline_access resource.invoke chatgpt.tokens.use.direct",
        "openid  offline_access resource.invoke chatgpt.tokens.use.direct",
        "openid\toffline_access resource.invoke chatgpt.tokens.use.direct",
        "openid offline_access resource.invoke chatgpt.tokens.use.direct ",
    }) |bad| try std.testing.expectError(error.OidcScopeInvalid, scopes(bad));
}
test "exact response pair digest changes for either credential ID scope expiry or response binding" {
    const a = std.testing.allocator;
    var parsed = try token.parse(a, 200, "{\"access_token\":\"synthetic-access\",\"refresh_token\":\"synthetic-refresh\",\"id_token\":\"synthetic-id\",\"token_type\":\"Bearer\",\"scope\":\"openid offline_access resource.invoke chatgpt.tokens.use.direct\",\"expires_in\":3600,\"earliest_refresh_at\":1000}");
    defer parsed.deinit();
    const original = try pairDigest(&parsed);
    for ([_]?[]u8{ parsed.access_token, parsed.refresh_token, parsed.id_token }) |field| if (field) |bytes| {
        bytes[0] ^= 1;
        try std.testing.expect(!same(original, try pairDigest(&parsed)));
        bytes[0] ^= 1;
    };
    parsed.expires_in = 3599;
    try std.testing.expect(!same(original, try pairDigest(&parsed)));
    parsed.expires_in = 3600;
    parsed.earliest_refresh_at = 1001;
    try std.testing.expect(!same(original, try pairDigest(&parsed)));
    parsed.earliest_refresh_at = 1000;
    parsed.response_sha256[0] ^= 1;
    try std.testing.expect(!same(original, try pairDigest(&parsed)));
    parsed.response_sha256[0] ^= 1;
    try std.testing.expect(same(original, try pairDigest(&parsed)));
    const original_scope = try a.dupe(u8, parsed.scope.?);
    defer a.free(original_scope);
    @memcpy(parsed.scope.?, "resource.invoke openid offline_access chatgpt.tokens.use.direct");
    try std.testing.expect(!same(original, try pairDigest(&parsed)));
    @memcpy(parsed.scope.?, original_scope);
    var omitted = try token.parse(a, 200, "{\"access_token\":\"synthetic-access\",\"token_type\":\"Bearer\",\"scope\":\"openid offline_access resource.invoke chatgpt.tokens.use.direct\",\"expires_in\":3600}");
    defer omitted.deinit();
    try std.testing.expectError(error.OidcPairMissing, pairDigest(&omitted));
}
test "identity commitment separates issuer client subject contexts without workspace invention" {
    const one = identityDigest("oaiapp_fixture_one", "synthetic-subject");
    const other_client = identityDigest("oaiapp_fixture_two", "synthetic-subject");
    const other_subject = identityDigest("oaiapp_fixture_one", "other-synthetic-subject");
    try std.testing.expect(!same(one, other_client));
    try std.testing.expect(!same(one, other_subject));
    try std.testing.expect(same(one, identityDigest("oaiapp_fixture_one", "synthetic-subject")));
}
test "signed ID access hash refuses a substituted access credential" {
    var digest: [32]u8 = undefined;
    Hash.hash("synthetic-access", &digest, .{});
    try checkAccessHash(digest[0..16].*, "synthetic-access");
    try std.testing.expectError(error.OidcAccessHashMismatch, checkAccessHash(digest[0..16].*, "other-synthetic-access"));
    try checkAccessHash(null, "synthetic-access");
}
