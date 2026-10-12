//! Authenticated SIWC rotating response. Only an actual paired-refresh ticket,
//! same-attempt TLS response and held issuer JWKS can construct this proof.
//! No fresh-login nonce or undocumented refresh ID-token shape is assumed.
const std = @import("std");
const issue = @import("oauth_issue_authority.zig");
const transport = @import("transport.zig");
const token = @import("oauth_token.zig");
const crypto = @import("oauth_oidc_crypto.zig");
const pair = @import("siwc_pair.zig");
const Hash = std.crypto.hash.sha2.Sha256;
const RotationData = struct {
    allocator: std.mem.Allocator,
    binding_sha256: [32]u8,
    response_sha256: [32]u8,
    pair_sha256: [32]u8,
    identity_commitment: [32]u8,
    received_at: i64,
    signed_expires_at: i64,
    access_expires_at: i64,
    scope_mask: u8,
    keys: *transport.JwksLease,
};
pub const VerifiedRotation = opaque {
    pub fn deinit(self: *VerifiedRotation) void {
        const owner = rotationMutable(self);
        owner.keys.deinit();
        const a = owner.allocator;
        std.crypto.secureZero(u8, std.mem.asBytes(owner));
        a.destroy(owner);
    }
    pub fn accessExpiresAt(self: *const VerifiedRotation) i64 { return rotationView(self).access_expires_at; }
    pub fn responseSha256(self: *const VerifiedRotation) [32]u8 { return rotationView(self).response_sha256; }
    pub fn identityCommitment(self: *const VerifiedRotation) [32]u8 { return rotationView(self).identity_commitment; }
    /// New receipt authority is valid only while this opaque proof rechecks.
    /// A serialized commitment is never a renewal/admission constructor.
    pub fn successorCommitment(self: *const VerifiedRotation, ticket: *const issue.IssuedTicket) ![32]u8 {
        try self.checkTicket(ticket);
        const owner = rotationView(self);
        const binding = try ticket.renewalBinding();
        var hash = Hash.init(.{});
        frame(&hash, "omux-owned-siwc-paired-rotation-v1");
        frame(&hash, pair.issuer_uri);
        frame(&hash, pair.resource_uri);
        frame(&hash, ticket.issuedClientId());
        for ([_][32]u8{ binding.prior_activation, binding.profile_sha256, binding.lineage_id, owner.binding_sha256,
            owner.response_sha256, owner.pair_sha256, owner.identity_commitment, owner.keys.sha256() }) |digest| hash.update(&digest);
        var number: [8]u8 = undefined;
        for ([_]i64{ owner.received_at, owner.signed_expires_at, owner.access_expires_at, owner.keys.receivedUnix() }) |value| {
            std.mem.writeInt(i64, &number, value, .big);
            hash.update(&number);
        }
        var cutoff: [12]u8 = undefined;
        std.mem.writeInt(i96, &cutoff, ticket.originalUntil().raw.nanoseconds, .big);
        hash.update(&cutoff);
        var result: [32]u8 = undefined;
        hash.final(&result);
        try self.checkTicket(ticket);
        return result;
    }
    fn checkTicket(self: *const VerifiedRotation, ticket: *const issue.IssuedTicket) !void {
        const owner = rotationView(self);
        try ticket.requireOwnedOssRenewal();
        try ticket.checkBeforeVerification();
        try owner.keys.recheckTicket(ticket);
        if (!same(owner.binding_sha256, try ticket.bindingSha256(owner.allocator))) return error.OidcAuthorityChanged;
        const now = try wallTime(ticket.clockIo());
        if (now < owner.received_at or owner.access_expires_at <= now or owner.signed_expires_at <= now) return error.OidcTokenExpired;
        _ = try (transport.AbsoluteDeadline{ .io = ticket.clockIo(), .until = ticket.originalUntil() }).remaining();
    }
    pub fn matchesEvidence(self: *const VerifiedRotation, ticket: *const issue.IssuedTicket, evidence: *const token.Evidence) !void {
        try self.checkTicket(ticket);
        const owner = rotationView(self);
        if (!same(owner.response_sha256, evidence.response_sha256) or !same(owner.pair_sha256, try evidenceDigest(evidence))) return error.OidcResponseChanged;
        if (evidence.scope) |scope| if (((try crypto.directAccessScopeMask(scope)) & 0b11_0000) != (owner.scope_mask & 0b11_0000)) return error.OidcScopeInvalid;
        try self.checkTicket(ticket);
    }
    pub fn recheck(self: *const VerifiedRotation, ticket: *const issue.IssuedTicket, response: *const transport.OAuthResponse) !void {
        try self.checkTicket(ticket);
        try response.recheck(ticket);
        const owner = rotationView(self);
        if (!response.isOwnOss() or response.status() != 200 or response.receivedUnix() != owner.received_at or
            !same(response.responseSha256(), owner.response_sha256) or !std.mem.eql(u8, response.issuedClientId(), ticket.issuedClientId())) return error.OidcResponseChanged;
        var evidence = try response.evidence(owner.allocator);
        defer evidence.deinit();
        try self.matchesEvidence(ticket, &evidence);
        try response.recheck(ticket);
        try self.checkTicket(ticket);
    }
};
fn rotationView(self: *const VerifiedRotation) *const RotationData { return @ptrCast(@alignCast(self)); }
fn rotationMutable(self: *VerifiedRotation) *RotationData { return @ptrCast(@alignCast(self)); }
fn same(a: [32]u8, b: [32]u8) bool { return std.crypto.timing_safe.eql([32]u8, a, b); }
fn wallTime(io: std.Io) !i64 {
    const now = std.Io.Clock.real.now(io).toSeconds();
    if (now <= 0 or now > 253_402_300_794) return error.OidcClockChanged;
    return now;
}
fn frame(hash: *Hash, value: []const u8) void {
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, @intCast(value.len), .big);
    hash.update(&length);
    hash.update(value);
}
fn signedIdentity(client: []const u8, subject: []const u8, provider_only: bool) [32]u8 {
    var hash = Hash.init(.{});
    frame(&hash, if (provider_only) "omux-siwc-provider-subject-v1" else "omux-siwc-identity-v1");
    frame(&hash, pair.issuer_uri);
    if (!provider_only) frame(&hash, client);
    frame(&hash, subject);
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}
fn optional(hash: *Hash, value: ?[]const u8) void {
    hash.update(if (value != null) "\x01" else "\x00");
    if (value) |bytes| frame(hash, bytes);
}
fn evidenceDigest(evidence: *const token.Evidence) ![32]u8 {
    if (evidence.access_token.len == 0 or evidence.access_token.len > token.max_credential_bytes) return error.OidcPairMissing;
    const refresh = evidence.refresh_token orelse return error.OwnedRefreshTokenMissing;
    if (refresh.len == 0 or refresh.len > token.max_credential_bytes) return error.OwnedRefreshTokenMissing;
    const seconds = evidence.expires_in orelse return error.OidcExpiryMissing;
    if (seconds == 0 or seconds > 3600) return error.OidcExpiryInvalid;
    if (evidence.scope) |scope| _ = try crypto.directAccessScopeMask(scope);
    var hash = Hash.init(.{});
    frame(&hash, "omux-owned-siwc-actual-refresh-response-v1");
    hash.update(&evidence.response_sha256);
    frame(&hash, evidence.access_token);
    frame(&hash, refresh);
    optional(&hash, evidence.id_token);
    optional(&hash, evidence.scope);
    var number: [8]u8 = undefined;
    std.mem.writeInt(u64, &number, seconds, .big);
    hash.update(&number);
    hash.update(if (evidence.earliest_refresh_at != null) "\x01" else "\x00");
    if (evidence.earliest_refresh_at) |value| {
        std.mem.writeInt(i64, &number, value, .big);
        hash.update(&number);
    }
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}
/// Bounded worker only; actor Store/source/consent/family/forget/CAS fences
/// still run before AND after work and at every irreversible writer boundary.
pub fn verifyOwnedRotation(a: std.mem.Allocator, ticket: *const issue.IssuedTicket, response: *const transport.OAuthResponse, keys: *transport.JwksLease) !*VerifiedRotation {
    try ticket.requireOwnedOssRenewal();
    try ticket.checkBeforeVerification();
    try response.recheck(ticket);
    try keys.recheckTicket(ticket);
    const deadline: transport.AbsoluteDeadline = .{ .io = ticket.clockIo(), .until = ticket.originalUntil() };
    _ = try deadline.remaining();
    if (!response.isOwnOss() or response.status() != 200 or !std.mem.eql(u8, response.issuedClientId(), ticket.issuedClientId())) return error.OidcResponseChanged;
    const received = response.receivedUnix();
    const now = try wallTime(ticket.clockIo());
    if (received <= 0 or received > now + 5 or keys.receivedUnix() <= 0 or keys.receivedUnix() > now + 5 or now - keys.receivedUnix() > 300) return error.OidcClockChanged;
    var evidence = try response.evidence(a);
    defer evidence.deinit();
    const digest = try evidenceDigest(&evidence);
    var claims = try crypto.verifyAccessToken(a, evidence.access_token, keys.bytes(), ticket.issuedClientId(), now);
    defer claims.deinit();
    const binding = try ticket.renewalBinding();
    const identity = signedIdentity(ticket.issuedClientId(), claims.subject, false);
    if (!same(identity, binding.identity_commitment) or !same(signedIdentity(ticket.issuedClientId(), claims.subject, true), binding.provider_subject_commitment)) return error.OidcIdentityChanged;
    const mask = try crypto.directAccessScopeMask(claims.scope);
    if (evidence.scope) |scope| if (((try crypto.directAccessScopeMask(scope)) & 0b11_0000) != (mask & 0b11_0000)) return error.OidcScopeInvalid;
    const access_until = std.math.add(i64, received, evidence.expires_in.?) catch return error.OidcExpiryInvalid;
    const expires = @min(access_until, claims.expires_at);
    if (expires <= now) return error.OidcTokenExpired;
    const binding_digest = try ticket.bindingSha256(a);
    const owner = try a.create(RotationData);
    keys.retain();
    owner.* = .{ .allocator = a, .binding_sha256 = binding_digest, .response_sha256 = evidence.response_sha256,
        .pair_sha256 = digest, .identity_commitment = identity, .received_at = received, .signed_expires_at = claims.expires_at,
        .access_expires_at = expires, .scope_mask = mask, .keys = keys };
    const proof: *VerifiedRotation = @ptrCast(owner);
    errdefer proof.deinit();
    try proof.recheck(ticket, response);
    try keys.recheckTicket(ticket);
    try ticket.checkBeforeVerification();
    _ = try deadline.remaining();
    return proof;
}
