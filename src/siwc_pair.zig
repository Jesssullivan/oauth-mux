//! Authenticated daemon-owned OSS session pair registry. The producer commits
//! this registry with both encrypted grant rows; imported/native rows cannot
//! construct request or renewal authority merely by recording owner=omux.
const std = @import("std");
const storage = @import("storage.zig");
const domain = @import("domain.zig");
const enrollment = @import("oauth_enrollment.zig");
const envelope = @import("envelope.zig");
const admission = @import("snapshot_admission.zig");
pub const maximum_pairs = domain.max_records;
pub const maximum_snapshot_bytes = 2 * 1024 * 1024;
pub const request_profile = "openai_siwc_responses_v1";
pub const issuer_uri = "https://auth.openai.com";
pub const resource_uri = "https://api.openai.com/v1";
pub const auth_mode = "openai_siwc_access_token";
pub const Record = struct {
    transaction_id: [32]u8,
    source_id: []const u8,
    account_id: []const u8,
    access_grant_id: []const u8,
    refresh_grant_id: []const u8,
    source_generation: u64,
    consent_id: [32]u8,
    consent_generation: u64,
    consent_status: enrollment.ConsentStatus = .recorded,
    retirement_reason: enum { none, withdrawn, source_disconnected, forgotten } = .none,
    access_generation: u64 = 1,
    refresh_generation: u64 = 1,
    lineage_id: [32]u8,
    family_generation: u64 = 1,
    writer_generation: u64 = 1,
    status: enum { ready, refreshing, quarantined, retired } = .ready,
    access_expires_at: i64,
    profile_sha256: [32]u8,
    binding_sha256: [32]u8,
    response_sha256: [32]u8,
    activation_commitment: [32]u8,
    issued_client_commitment: [32]u8,
    identity_commitment: [32]u8,
    provider_subject_commitment: [32]u8,
    refresh_token_commitment: [32]u8,
    access_token_commitment: [32]u8,
    identity_capsule: []const u8,
    identity_generation: u64 = 1,
    forget_tombstone: bool = false,
};
pub const Snapshot = struct { version: u32 = 1, records: []const Record = &.{} };
pub const Registry = struct {
    records: std.ArrayList(Record) = .empty,
    pub fn deinit(self: *Registry, a: std.mem.Allocator) void {
        for (self.records.items) |record| freeRecord(a, record);
        self.records.deinit(a);
        self.* = .{};
    }
    pub fn snapshot(self: *const Registry) Snapshot {
        return .{ .records = self.records.items };
    }
    pub fn fromSnapshot(a: std.mem.Allocator, saved: Snapshot) !Registry {
        try validate(saved);
        var result: Registry = .{};
        errdefer result.deinit(a);
        try result.records.ensureTotalCapacity(a, saved.records.len);
        for (saved.records) |row| result.records.appendAssumeCapacity(try copyRecord(a, row));
        return result;
    }
    pub fn find(self: *Registry, transaction_id: [32]u8) ?*Record {
        for (self.records.items) |*row| if (std.meta.eql(row.transaction_id, transaction_id)) return row;
        return null;
    }
    pub fn retireFor(self: *Registry, a: std.mem.Allocator, source_id: ?[]const u8, account_id: ?[]const u8) void {
        for (self.records.items) |*row| {
            if (source_id) |id| if (!std.mem.eql(u8, id, row.source_id)) continue;
            if (account_id) |id| if (!std.mem.eql(u8, id, row.account_id)) continue;
            row.status = .retired;
            if (account_id != null) {
                row.forget_tombstone = true;
                row.retirement_reason = .forgotten;
            } else row.retirement_reason = .source_disconnected;
            a.free(row.identity_capsule);
            row.identity_capsule = &.{};
        }
    }
    pub fn append(self: *Registry, a: std.mem.Allocator, input: Record) !void {
        if (self.records.items.len == maximum_pairs) return error.SiwcPairCapacity;
        try validate(.{ .records = &.{input} });
        for (self.records.items) |prior| {
            if (std.meta.eql(prior.transaction_id, input.transaction_id) or std.meta.eql(prior.lineage_id, input.lineage_id) or same(prior.refresh_token_commitment, input.refresh_token_commitment) or std.mem.eql(u8, prior.access_grant_id, input.access_grant_id) or std.mem.eql(u8, prior.refresh_grant_id, input.refresh_grant_id)) return error.SiwcDuplicateLineage;
        }
        const owned = try copyRecord(a, input);
        errdefer freeRecord(a, owned);
        try self.records.append(a, owned);
    }
};
fn copyRecord(a: std.mem.Allocator, input: Record) !Record {
    var out = input;
    out.source_id = try a.dupe(u8, input.source_id);
    errdefer a.free(out.source_id);
    out.account_id = try a.dupe(u8, input.account_id);
    errdefer a.free(out.account_id);
    out.access_grant_id = try a.dupe(u8, input.access_grant_id);
    errdefer a.free(out.access_grant_id);
    out.refresh_grant_id = try a.dupe(u8, input.refresh_grant_id);
    errdefer a.free(out.refresh_grant_id);
    out.identity_capsule = try a.dupe(u8, input.identity_capsule);
    return out;
}
fn freeRecord(a: std.mem.Allocator, row: Record) void {
    a.free(row.source_id);
    a.free(row.account_id);
    a.free(row.access_grant_id);
    a.free(row.refresh_grant_id);
    a.free(row.identity_capsule);
}
fn same(a: [32]u8, b: [32]u8) bool {
    return std.crypto.timing_safe.eql([32]u8, a, b);
}
pub fn validate(saved: Snapshot) !void {
    if (saved.version != 1 or saved.records.len > maximum_pairs) return error.InvalidSiwcPair;
    for (saved.records, 0..) |row, index| {
        for ([_][]const u8{ row.source_id, row.account_id, row.access_grant_id, row.refresh_grant_id }) |id| {
            if (id.len == 0 or id.len > 64) return error.InvalidSiwcPair;
            for (id) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-' and byte != '_') return error.InvalidSiwcPair;
        }
        if (std.mem.eql(u8, row.access_grant_id, row.refresh_grant_id) or row.source_generation == 0 or row.consent_generation == 0 or row.access_generation == 0 or row.refresh_generation == 0 or row.family_generation == 0 or row.identity_generation == 0 or row.identity_generation > row.family_generation or row.writer_generation != row.family_generation or row.access_generation != row.family_generation or row.refresh_generation != row.family_generation or row.access_expires_at <= 0 or (row.status != .retired and row.identity_capsule.len < 49) or row.identity_capsule.len > 32 * 1024) return error.InvalidSiwcPair;
        if (row.status == .ready and (row.consent_status != .recorded or row.retirement_reason != .none or row.forget_tombstone)) return error.InvalidSiwcPair;
        inline for (.{ "lineage_id", "profile_sha256", "binding_sha256", "response_sha256", "activation_commitment", "issued_client_commitment", "identity_commitment", "provider_subject_commitment", "refresh_token_commitment", "access_token_commitment" }) |field| if (std.mem.allEqual(u8, &@field(row, field), 0)) return error.InvalidSiwcPair;
        for (saved.records[0..index]) |prior| if (std.meta.eql(prior.transaction_id, row.transaction_id) or std.meta.eql(prior.lineage_id, row.lineage_id) or same(prior.refresh_token_commitment, row.refresh_token_commitment) or std.mem.eql(u8, prior.access_grant_id, row.access_grant_id) or std.mem.eql(u8, prior.refresh_grant_id, row.refresh_grant_id)) return error.InvalidSiwcPair;
    }
    _ = try admission.countJson(saved, maximum_snapshot_bytes);
}
/// Equality/duplicate detection inside Omux custody, not a vendor family ID,
/// independent capacity, adoption authority, or a control-visible token hash.
pub fn tokenCommitment(key: envelope.Key, token: []const u8, kind: enum { access, refresh }) [32]u8 {
    var hmac = std.crypto.auth.hmac.sha2.HmacSha256.init(&key);
    hmac.update(if (kind == .access) "omux-owned-siwc-access-v1" else "omux-owned-siwc-refresh-v1");
    var size: [8]u8 = undefined;
    std.mem.writeInt(u64, &size, @intCast(token.len), .big);
    hmac.update(&size);
    hmac.update(token);
    var result: [32]u8 = undefined;
    hmac.final(&result);
    return result;
}
const Data = struct { allocator: std.mem.Allocator, row: Record };
pub const PairAuthority = opaque {
    pub fn deinit(self: *PairAuthority) void {
        const d = data(self);
        freeRecord(d.allocator, d.row);
        d.allocator.destroy(d);
    }
    pub fn issuer(_: *const PairAuthority) []const u8 {
        return issuer_uri;
    }
    pub fn audience(_: *const PairAuthority) []const u8 {
        return resource_uri;
    }
    pub fn profile(_: *const PairAuthority) []const u8 {
        return request_profile;
    }
    pub fn authMode(_: *const PairAuthority) []const u8 {
        return auth_mode;
    }
    pub fn expiresAt(self: *const PairAuthority) i64 {
        return view(self).row.access_expires_at;
    }
    pub fn familyGeneration(self: *const PairAuthority) u64 {
        return view(self).row.family_generation;
    }
    pub fn refreshGrantId(self: *const PairAuthority) []const u8 {
        return view(self).row.refresh_grant_id;
    }
    pub fn refreshGeneration(self: *const PairAuthority) u64 {
        return view(self).row.refresh_generation;
    }
    pub fn writerRegistryGeneration(self: *const PairAuthority) u64 {
        return view(self).row.writer_generation;
    }
    pub fn sourceGeneration(self: *const PairAuthority) u64 {
        return view(self).row.source_generation;
    }
    pub fn consentGeneration(self: *const PairAuthority) u64 {
        return view(self).row.consent_generation;
    }
    pub fn activationCommitment(self: *const PairAuthority) [32]u8 {
        return view(self).row.activation_commitment;
    }
};
fn data(self: *PairAuthority) *Data {
    return @ptrCast(@alignCast(self));
}
fn view(self: *const PairAuthority) *const Data {
    return @ptrCast(@alignCast(self));
}
const Retained = struct {
    schema_version: u32,
    state: domain.Snapshot,
    owned_siwc_pairs: ?Snapshot = null,
    fresh_oauth_authority: ?enrollment.Snapshot = null,
    import_source_authority: []const struct { source_id: []const u8, generation: u64 } = &.{},
};
/// Actor-owner only. Actual authenticated metadata and both encrypted SQL
/// status rows are reread; no cache, caller flag or .omux row is sufficient.
pub fn currentPair(store: *storage.Store, account_id: []const u8, access_grant_id: []const u8, access_generation: u64, now: i64) !*PairAuthority {
    const a = store.allocator;
    const observed = std.Io.Clock.real.now(store.io).toSeconds();
    if (now <= 0 or now > observed or observed - now > 1) return error.SiwcPairAuthorityChanged;
    var saved = try store.readSnapshot();
    defer saved.deinit();
    const parsed = try std.json.parseFromSlice(Retained, a, saved.json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    if (parsed.value.schema_version != 2) return error.SiwcPairUnavailable;
    const registry = parsed.value.owned_siwc_pairs orelse return error.SiwcPairUnavailable;
    try validate(registry);
    const records = if (parsed.value.fresh_oauth_authority) |saved_attempts| saved_attempts.records else &.{};
    for (registry.records) |row| {
        if (!std.mem.eql(u8, row.account_id, account_id) or !std.mem.eql(u8, row.access_grant_id, access_grant_id)) continue;
        if (row.status != .ready or row.consent_status != .recorded) return error.SiwcPairQuarantined;
        if (row.access_generation != access_generation) return error.SiwcPairAuthorityChanged;
        if (row.access_expires_at <= now) return error.SiwcPairExpired;
        // The activation transaction moves complete consent authority into the
        // pair registry. A still-retained attempt must agree; settled attempts
        // are not required forever and can never reconstruct an issue ticket.
        for (records) |record| if (std.meta.eql(record.binding.transaction_id, row.transaction_id)) {
            if (record.phase != .active or record.provider != .openai_siwc or record.consent_status != .recorded or record.binding.source_generation != row.source_generation or record.binding.consent_generation != row.consent_generation or !std.meta.eql(record.binding.consent_id, row.consent_id) or record.registration_profile_sha256 == null or !same(record.registration_profile_sha256.?, row.profile_sha256)) return error.SiwcPairAuthorityChanged;
        };
        var source = false;
        for (parsed.value.state.sources) |item| if (std.mem.eql(u8, item.id, row.source_id)) {
            if (item.kind != .oauth or item.status == .disconnected or !std.mem.eql(u8, item.provider, "openai_siwc") or item.authorized_at > now or (item.authorized_until != null and item.authorized_until.? <= now)) return error.SiwcPairAuthorityChanged;
            source = true;
        };
        var source_generation = false;
        for (parsed.value.import_source_authority) |item| if (std.mem.eql(u8, item.source_id, row.source_id) and item.generation == row.source_generation) {
            source_generation = true;
        };
        var account = false;
        for (parsed.value.state.accounts) |item| if (std.mem.eql(u8, item.id, row.account_id)) {
            const expected = std.fmt.bytesToHex(row.identity_commitment, .lower);
            if (!item.identity.verified or !std.mem.eql(u8, item.identity.provider, "openai_siwc") or !std.mem.eql(u8, item.identity.issuer, issuer_uri) or item.identity.tenant.len != 0 or !std.mem.eql(u8, item.identity.subject, &expected)) return error.SiwcPairAuthorityChanged;
            for (item.source_ids) |id| if (std.mem.eql(u8, id, row.source_id)) {
                account = true;
            };
        };
        var access = false;
        var refresh = false;
        for (parsed.value.state.grants) |grant| {
            if (!std.mem.eql(u8, grant.account_id, account_id) or !std.mem.eql(u8, grant.source_id, row.source_id)) continue;
            if (std.mem.eql(u8, grant.id, row.access_grant_id)) {
                if (grant.credential_kind != .oauth_access or grant.ownership != .omux or grant.status != .ready or grant.generation != row.access_generation or !std.mem.eql(u8, grant.audience, resource_uri) or grant.provider_expires_at != row.access_expires_at) return error.SiwcPairAuthorityChanged;
                var request = false;
                var invoke = false;
                var direct = false;
                for (grant.purposes) |purpose| if (purpose == .request) {
                    request = true;
                };
                for (grant.scopes) |scope| {
                    if (std.mem.eql(u8, scope, "resource.invoke")) invoke = true;
                    if (std.mem.eql(u8, scope, "chatgpt.tokens.use.direct")) direct = true;
                }
                if (!request or !invoke or !direct) return error.SiwcPairAuthorityChanged;
                access = true;
            }
            if (std.mem.eql(u8, grant.id, row.refresh_grant_id)) {
                if (grant.credential_kind != .oauth_refresh or grant.ownership != .omux or grant.status != .ready or grant.generation != row.refresh_generation or !std.mem.eql(u8, grant.audience, resource_uri)) return error.SiwcPairAuthorityChanged;
                var renewal = false;
                for (grant.purposes) |purpose| if (purpose == .renewal) {
                    renewal = true;
                };
                if (!renewal) return error.SiwcPairAuthorityChanged;
                refresh = true;
            }
        }
        if (!source or !source_generation or !account or !access or !refresh) return error.SiwcPairAuthorityChanged;
        const access_row = (try store.readGrantStatus(account_id, row.access_grant_id)) orelse return error.SiwcPairAuthorityChanged;
        const refresh_row = (try store.readGrantStatus(account_id, row.refresh_grant_id)) orelse return error.SiwcPairAuthorityChanged;
        if (access_row.state != .ready or refresh_row.state != .ready or access_row.renewal_owner != .omux or refresh_row.renewal_owner != .omux or access_row.generation != row.access_generation or refresh_row.generation != row.refresh_generation) return error.SiwcPairQuarantined;
        var access_secret = try store.loadGrant(.{ .key_id = store.key_id, .account_id = row.account_id, .grant_id = row.access_grant_id, .generation = row.access_generation, .purpose = "request", .scope = resource_uri });
        defer access_secret.deinit();
        var refresh_secret = try store.loadGrant(.{ .key_id = store.key_id, .account_id = row.account_id, .grant_id = row.refresh_grant_id, .generation = row.refresh_generation, .purpose = "renewal", .scope = resource_uri });
        defer refresh_secret.deinit();
        var scratch: [256 * 1024]u8 = undefined;
        defer std.crypto.secureZero(u8, &scratch);
        var buffer = std.heap.FixedBufferAllocator.init(&scratch);
        const access_envelope = try std.json.parseFromSlice(struct { access_token: []const u8 }, buffer.allocator(), access_secret.bytes, .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error" });
        defer access_envelope.deinit();
        const refresh_envelope = try std.json.parseFromSlice(struct { refresh_token: []const u8, client_id: []const u8 }, buffer.allocator(), refresh_secret.bytes, .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error" });
        defer refresh_envelope.deinit();
        if (access_envelope.value.access_token.len == 0 or access_envelope.value.access_token.len > 16 * 1024 or refresh_envelope.value.refresh_token.len == 0 or refresh_envelope.value.refresh_token.len > 16 * 1024 or !same(tokenCommitment(store.key, access_envelope.value.access_token, .access), row.access_token_commitment) or !same(tokenCommitment(store.key, refresh_envelope.value.refresh_token, .refresh), row.refresh_token_commitment) or !enrollment.validIssuedClient(refresh_envelope.value.client_id) or !same(clientCommitment(refresh_envelope.value.client_id), row.issued_client_commitment)) return error.SiwcPairAuthorityChanged;
        var identity = try envelope.open(a, store.key, identityContext(store.key_id, row), row.identity_capsule);
        defer identity.deinit();
        const identity_envelope = try std.json.parseFromSlice(struct { schema_version: u32, issuer: []const u8, client_id: []const u8, subject: []const u8 }, buffer.allocator(), identity.bytes, .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error" });
        defer identity_envelope.deinit();
        if (identity_envelope.value.schema_version != 1 or !std.mem.eql(u8, identity_envelope.value.issuer, issuer_uri) or !std.mem.eql(u8, identity_envelope.value.client_id, refresh_envelope.value.client_id) or !same(registrationIdentity(identity_envelope.value.client_id, identity_envelope.value.subject), row.identity_commitment)) return error.SiwcPairAuthorityChanged;
        const fresh_now = std.Io.Clock.real.now(store.io).toSeconds();
        if (fresh_now < observed or row.access_expires_at <= fresh_now) return error.SiwcPairExpired;
        const owned = try copyRecord(a, row);
        errdefer freeRecord(a, owned);
        const result = try a.create(Data);
        result.* = .{ .allocator = a, .row = owned };
        return @ptrCast(result);
    }
    return error.SiwcPairUnavailable;
}
pub fn identityContext(key_id: []const u8, row: Record) envelope.Context {
    return .{ .key_id = key_id, .account_id = row.account_id, .grant_id = row.refresh_grant_id, .generation = row.identity_generation, .purpose = "siwc_owned_identity_v1", .scope = resource_uri };
}
fn frame(hash: *std.crypto.hash.sha2.Sha256, bytes: []const u8) void {
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, @intCast(bytes.len), .big);
    hash.update(&length);
    hash.update(bytes);
}
fn clientCommitment(client: []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    frame(&hash, "omux-siwc-issued-client-v1");
    frame(&hash, client);
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}
fn registrationIdentity(client: []const u8, subject: []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    frame(&hash, "omux-siwc-identity-v1");
    frame(&hash, issuer_uri);
    frame(&hash, client);
    frame(&hash, subject);
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}
