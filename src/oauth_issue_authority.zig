//! Private one-shot OAuth dispatch authority. No control/profile digest, native
//! client literal or Boolean can construct a profile or a dispatch ticket.
//! Ticket construction commits the exact issued transition in the actual Store
//! and rereads it before returning. Issued work is never reconstructed/replayed.
const std = @import("std");
const builtin = @import("builtin");
const envelope = @import("envelope.zig");
const storage = @import("storage.zig");
const enrollment = @import("oauth_enrollment.zig");
const token = @import("oauth_token.zig");

const pair = @import("siwc_pair.zig");
const domain = @import("domain.zig");
pub const Endpoint = union(enum) { codex_token, omux_oss_token, fixture_token: u16 };
pub const ProfileView = struct {
    endpoint: Endpoint,
    code_encoding: token.Encoding,
    refresh_encoding: token.Encoding,
    client_id: []const u8,
    resource: ?[]const u8,
    exact_redirect_uri: []const u8,
    sha256: [32]u8,
    host_id: [32]u8 = @splat(0),
};
const ProfileData = struct { allocator: std.mem.Allocator, view: ProfileView, references: std.atomic.Value(usize) = .init(1), qualification: enum { model_only, documented_oss_enrollment, owned_oss_renewal } = .model_only };
/// Purpose-limited enrollment authority, not authenticated identity or ready
/// request/renewal authority. The native Codex client remains unavailable.
pub const EnrollmentProfile = opaque {
    pub fn view(self: *const EnrollmentProfile) ProfileView {
        return profileData(self).view;
    }
    pub fn retain(self: *EnrollmentProfile) void {
        _ = profileDataMut(self).references.fetchAdd(1, .monotonic);
    }
    pub fn deinit(self: *EnrollmentProfile) void {
        const data = profileDataMut(self);
        if (data.references.fetchSub(1, .acq_rel) != 1) return;
        std.crypto.secureZero(u8, @constCast(data.view.client_id));
        data.allocator.free(data.view.client_id);
        if (data.view.resource) |resource| data.allocator.free(resource);
        data.allocator.free(data.view.exact_redirect_uri);
        data.allocator.destroy(data);
    }
    pub fn requireAvailable(self: *const EnrollmentProfile) !void {
        switch (profileData(self).qualification) {
            .model_only => if (!builtin.is_test or self.view().endpoint != .fixture_token) return error.RegistrationProfileUnavailable,
            .documented_oss_enrollment, .owned_oss_renewal => if (self.view().endpoint != .omux_oss_token or std.mem.allEqual(u8, &self.view().host_id, 0)) return error.RegistrationProfileUnavailable,
        }
    }
};
/// Reviewed public OSS registration contract supplies initial enrollment IO
/// authority before an issued client exists. Host ID comes from committed
/// daemon custody; it is an application host label, not an identity assertion.
/// https://developers.openai.com/siwc/token-sharing-open-source/sign-in
pub fn documentedOssEnrollment(a: std.mem.Allocator, host_id: [32]u8, redirect: []const u8) !*EnrollmentProfile {
    if (std.mem.allEqual(u8, &host_id, 0)) return error.RegistrationProfileUnavailable;
    _ = try loopbackPort(redirect);
    const client = try a.dupe(u8, "dynamic_agent_client");
    errdefer a.free(client);
    const callback = try a.dupe(u8, redirect);
    errdefer a.free(callback);
    const resource = try a.dupe(u8, "https://api.openai.com/v1");
    errdefer a.free(resource);
    const framed = try std.json.Stringify.valueAlloc(a, .{ .version = "omux-openai-siwc-oss-enrollment-v1", .issuer = "https://auth.openai.com", .authorize = "https://auth.openai.com/api/accounts/authorize", .token = "https://auth.openai.com/api/accounts/oauth/token", .initial_client = client, .agent_name_hint = "omux", .host_id = host_id, .redirect = callback, .scope = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct", .resource = resource, .pkce = "S256" }, .{});
    defer a.free(framed);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(framed, &digest, .{});
    const data = try a.create(ProfileData);
    data.* = .{ .allocator = a, .qualification = .documented_oss_enrollment, .view = .{ .endpoint = .omux_oss_token, .code_encoding = .form, .refresh_encoding = .form, .client_id = client, .resource = resource, .exact_redirect_uri = callback, .sha256 = digest, .host_id = host_id } };
    return @ptrCast(data);
}
pub fn loopbackPort(uri: []const u8) !u16 {
    const prefix = "http://127.0.0.1:";
    const suffix = "/auth/callback";
    if (uri.len > 256 or !std.mem.startsWith(u8, uri, prefix) or !std.mem.endsWith(u8, uri, suffix)) return error.InvalidOAuthRedirect;
    const raw = uri[prefix.len .. uri.len - suffix.len];
    if (raw.len == 0 or raw.len > 5 or raw[0] == '0') return error.InvalidOAuthRedirect;
    for (raw) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidOAuthRedirect;
    return std.fmt.parseInt(u16, raw, 10) catch error.InvalidOAuthRedirect;
}
/// Initial registration URL only. The issued callback ID, never this initial
/// client, is used by issueCode. No browser launch or provider call occurs here.
pub fn authorizationUrl(io: std.Io, a: std.mem.Allocator, profile: *EnrollmentProfile, attempt: enrollment.Attempt, challenge: [43]u8) ![]u8 {
    try profile.requireAvailable();
    try enrollment.checkFlow(io, attempt);
    var state: [43]u8 = undefined;
    defer std.crypto.secureZero(u8, &state);
    _ = std.base64.url_safe_no_pad.Encoder.encode(&state, &attempt.callback_state);
    var nonce: [43]u8 = undefined;
    defer std.crypto.secureZero(u8, &nonce);
    _ = std.base64.url_safe_no_pad.Encoder.encode(&nonce, &attempt.oidc_nonce);
    const host = std.fmt.bytesToHex(profile.view().host_id, .lower);
    var output: std.ArrayList(u8) = .empty;
    errdefer {
        std.crypto.secureZero(u8, output.items);
        output.deinit(a);
    }
    if (profile.view().endpoint == .omux_oss_token) {
        try output.appendSlice(a, "https://auth.openai.com/api/accounts/authorize?");
    } else if (profile.view().endpoint == .fixture_token) {
        const start = try std.fmt.allocPrint(a, "http://127.0.0.1:{d}/authorize?", .{profile.view().endpoint.fixture_token});
        defer a.free(start);
        try output.appendSlice(a, start);
    } else return error.RegistrationProfileUnavailable;
    const Pair = struct { key: []const u8, value: []const u8 };
    for ([_]Pair{
        .{ .key = "client_id", .value = profile.view().client_id },
        .{ .key = "agent_name_hint", .value = "omux" },
        .{ .key = "ext_agent_host_id", .value = &host },
        .{ .key = "response_type", .value = "code" },
        .{ .key = "redirect_uri", .value = profile.view().exact_redirect_uri },
        .{ .key = "scope", .value = "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct" },
        .{ .key = "state", .value = &state },
        .{ .key = "nonce", .value = &nonce },
        .{ .key = "code_challenge_method", .value = "S256" },
        .{ .key = "code_challenge", .value = &challenge },
    }, 0..) |form_field, index| {
        if (index != 0) try output.append(a, '&');
        try output.appendSlice(a, form_field.key);
        try output.append(a, '=');
        try appendEncoded(a, &output, form_field.value);
    }
    if (profile.view().resource) |resource| {
        try output.appendSlice(a, "&resource=");
        try appendEncoded(a, &output, resource);
    }
    if (output.items.len > 4096) return error.OAuthRequestTooLarge;
    return output.toOwnedSlice(a);
}
fn appendEncoded(a: std.mem.Allocator, output: *std.ArrayList(u8), value: []const u8) !void {
    const hex = "0123456789ABCDEF";
    for (value) |byte| {
        if (std.ascii.isAlphanumeric(byte) or std.mem.indexOfScalar(u8, "-._~", byte) != null) try output.append(a, byte) else try output.appendSlice(a, &.{ '%', hex[byte >> 4], hex[byte & 15] });
    }
}
fn profileData(self: *const EnrollmentProfile) *const ProfileData {
    return @ptrCast(@alignCast(self));
}
fn profileDataMut(self: *EnrollmentProfile) *ProfileData {
    return @ptrCast(@alignCast(self));
}

const FencePhase = enum(u8) { pending, dispatching, cancelled };
const FenceData = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    until: std.Io.Clock.Timestamp,
    consent_expires_at: i64,
    grant_window: ?pair.GrantWindow = null,
    renewal_admitted_unix: ?i64 = null,
    references: std.atomic.Value(usize) = .init(1),
    phase: std.atomic.Value(FencePhase) = .init(.pending),
};
pub const Cancellation = enum { prevented_before_dispatch, issued_or_racing };
pub const DispatchFence = opaque {
    pub fn retain(self: *DispatchFence) void {
        _ = fenceData(self).references.fetchAdd(1, .monotonic);
    }
    pub fn deinit(self: *DispatchFence) void {
        const data = fenceData(self);
        if (data.references.fetchSub(1, .acq_rel) == 1) data.allocator.destroy(data);
    }
    pub fn checkBeforeDispatch(self: *DispatchFence) !void {
        const data = fenceData(self);
        try deadline(data.io, data.until);
        if (data.renewal_admitted_unix) |admitted| if (std.Io.Clock.real.now(data.io).toSeconds() < admitted) return error.OAuthAuthorityChanged;
        if (data.grant_window) |window| try window.check(std.Io.Clock.real.now(data.io).toSeconds());
        if (std.Io.Clock.real.now(data.io).toSeconds() >= data.consent_expires_at) return error.OAuthConsentExpired;
        if (data.phase.load(.acquire) != .pending) return error.OAuthDispatchRefused;
    }
    /// Actor-side queued/in-flight liveness, not another dispatch permission.
    pub fn checkLive(self: *DispatchFence) !void {
        const owner = fenceData(self);
        try deadline(owner.io, owner.until);
        if (owner.renewal_admitted_unix) |admitted| if (std.Io.Clock.real.now(owner.io).toSeconds() < admitted) return error.OAuthAuthorityChanged;
        if (owner.grant_window) |window| try window.check(std.Io.Clock.real.now(owner.io).toSeconds());
        if (std.Io.Clock.real.now(owner.io).toSeconds() >= owner.consent_expires_at or owner.phase.load(.acquire) == .cancelled) return error.OAuthCompletionIndeterminate;
    }
    /// Linearization, not a claim that cancellation can undo a sent request.
    pub fn beginDispatch(self: *DispatchFence) !void {
        try self.checkBeforeDispatch();
        if (fenceData(self).phase.cmpxchgStrong(.pending, .dispatching, .acq_rel, .acquire) != null) return error.OAuthDispatchRefused;
    }
    pub fn checkBeforeCompletion(self: *DispatchFence) !void {
        const data = fenceData(self);
        try deadline(data.io, data.until);
        if (data.renewal_admitted_unix) |admitted| if (std.Io.Clock.real.now(data.io).toSeconds() < admitted) return error.OAuthAuthorityChanged;
        if (data.grant_window) |window| try window.check(std.Io.Clock.real.now(data.io).toSeconds());
        if (std.Io.Clock.real.now(data.io).toSeconds() >= data.consent_expires_at) return error.OAuthConsentExpired;
        if (data.phase.load(.acquire) != .dispatching) return error.OAuthCompletionIndeterminate;
    }
    pub fn invalidate(self: *DispatchFence) Cancellation {
        return if (fenceData(self).phase.swap(.cancelled, .acq_rel) == .pending) .prevented_before_dispatch else .issued_or_racing;
    }
};
fn fenceData(self: *DispatchFence) *FenceData {
    return @ptrCast(@alignCast(self));
}

pub const DispatchMaterial = struct {
    grant: token.Grant,
    endpoint: Endpoint,
    encoding: token.Encoding,
    client_id: []const u8,
    resource: ?[]const u8,
    account_id: ?[]const u8,
    grant_id: []const u8,
    io: std.Io,
    until: std.Io.Clock.Timestamp,
    fence: *DispatchFence,
    pub fn deinit(self: *DispatchMaterial, a: std.mem.Allocator) void {
        switch (self.grant) {
            .code => |code| {
                wipeFree(a, code.code);
                wipeFree(a, code.verifier);
                a.free(code.redirect_uri);
            },
            .refresh => |refresh| wipeFree(a, refresh),
        }
        a.free(self.client_id);
        if (self.resource) |resource| a.free(resource);
        if (self.account_id) |account| a.free(account);
        a.free(self.grant_id);
        self.fence.deinit();
        self.* = undefined;
    }
};
/// Immutable current-family tuple derived only from authenticated paired
/// custody. It is secret-free diagnostic binding, not a ticket constructor.
pub const RenewalBinding = struct {
    account_id: [64]u8,
    source_id: [64]u8,
    access_grant_id: [64]u8,
    refresh_grant_id: [64]u8,
    lineage_id: [32]u8,
    registration_transaction: [32]u8,
    prior_record_commitment: [32]u8,
    prior_activation: [32]u8,
    profile_sha256: [32]u8,
    identity_commitment: [32]u8,
    provider_subject_commitment: [32]u8,
    issued_client_commitment: [32]u8,
    refresh_token_commitment: [32]u8,
    previous_renewal: ?pair.Renewal,
    operation: pair.Renewal,
};
const TicketData = struct {
    allocator: std.mem.Allocator,
    material: DispatchMaterial,
    profile: *EnrollmentProfile,
    claimed: std.atomic.Value(bool) = .init(false),
    jwks_claimed: std.atomic.Value(bool) = .init(false),
    committed_revision: u64 = 0,
    binding: enrollment.Binding,
    model_routes: ?ModelRoutes = null,
    renewal_binding: ?RenewalBinding = null,
    references: std.atomic.Value(usize) = .init(1),
};
pub const ModelRoutes = struct { token_port: u16, jwks_port: u16 };
pub const IssuedTicket = opaque {
    /// Consumption precedes every allocation/queue failure. Active enrollment
    /// and owned-renewal caps bound all retained tickets and secret clones.
    pub fn claim(self: *IssuedTicket, a: std.mem.Allocator) !DispatchMaterial {
        const data = ticketData(self);
        if (data.claimed.swap(true, .acq_rel)) return error.OAuthTicketConsumed;
        try data.profile.requireAvailable();
        try data.material.fence.checkBeforeDispatch();
        return cloneMaterial(a, data.material);
    }
    pub fn claimJwks(self: *IssuedTicket) !void {
        if (ticketData(self).jwks_claimed.swap(true, .acq_rel)) return error.OAuthJwksAlreadyIssued;
        if (ticketData(self).renewal_binding != null) try self.requireOwnedOssRenewal() else try self.requireOwnedOssEnrollment();
        try self.checkBeforeVerification();
    }
    pub fn deinit(self: *IssuedTicket) void {
        const data = ticketData(self);
        if (data.references.fetchSub(1, .acq_rel) != 1) return;
        data.material.deinit(data.allocator);
        data.profile.deinit();
        data.allocator.destroy(data);
    }
    pub fn retain(self: *IssuedTicket) void {
        _ = ticketData(self).references.fetchAdd(1, .monotonic);
    }
    pub fn retainFence(self: *IssuedTicket) *DispatchFence {
        const result = ticketData(self).material.fence;
        result.retain();
        return result;
    }
    pub fn committedRevision(self: *const IssuedTicket) u64 {
        return ticketDataConst(self).committed_revision;
    }
    pub fn binding(self: *const IssuedTicket) enrollment.Binding {
        return ticketDataConst(self).binding;
    }
    pub fn registrationProfileSha256(self: *const IssuedTicket) [32]u8 {
        return ticketDataConst(self).profile.view().sha256;
    }
    pub fn modelRoutes(self: *const IssuedTicket) ?ModelRoutes {
        return if (builtin.is_test) ticketDataConst(self).model_routes else null;
    }
    pub fn matchesDispatchFence(self: *const IssuedTicket, fence: *const DispatchFence) bool {
        return ticketDataConst(self).material.fence == fence;
    }
    pub fn issuedClientId(self: *const IssuedTicket) []const u8 {
        return ticketDataConst(self).material.client_id;
    }
    pub fn nonceDigest(self: *const IssuedTicket) [32]u8 {
        return ticketDataConst(self).binding.oidc_nonce_digest;
    }
    pub fn clockIo(self: *const IssuedTicket) std.Io {
        return ticketDataConst(self).material.io;
    }
    pub fn originalUntil(self: *const IssuedTicket) std.Io.Clock.Timestamp {
        return ticketDataConst(self).material.until;
    }
    pub fn checkBeforeVerification(self: *const IssuedTicket) !void {
        try ticketDataConst(self).material.fence.checkBeforeCompletion();
    }
    pub fn requireOwnedOssEnrollment(self: *const IssuedTicket) !void {
        const data = ticketDataConst(self);
        if (data.renewal_binding != null or data.material.grant != .code or data.profile.view().endpoint != .omux_oss_token or data.profile.view().resource == null or !std.mem.eql(u8, data.profile.view().resource.?, "https://api.openai.com/v1") or data.material.encoding != .form) return error.OAuthAuthorityChanged;
        try data.profile.requireAvailable();
    }
    pub fn renewalBinding(self: *const IssuedTicket) !RenewalBinding {
        return ticketDataConst(self).renewal_binding orelse error.OAuthWrongPurpose;
    }
    pub fn requireOwnedOssRenewal(self: *const IssuedTicket) !void {
        const data = ticketDataConst(self);
        const owned = data.renewal_binding orelse return error.OAuthWrongPurpose;
        if (profileData(data.profile).qualification != .owned_oss_renewal or data.material.grant != .refresh or data.material.account_id == null or
            !std.mem.eql(u8, data.material.account_id.?, &owned.account_id) or !std.mem.eql(u8, data.material.grant_id, &owned.refresh_grant_id) or
            data.profile.view().endpoint != .omux_oss_token or data.material.encoding != .form or data.material.resource == null or !std.mem.eql(u8, data.material.resource.?, pair.resource_uri)) return error.OAuthAuthorityChanged;
        try data.profile.requireAvailable();
    }
    pub fn bindingSha256(self: *const IssuedTicket, a: std.mem.Allocator) ![32]u8 {
        const data = ticketDataConst(self);
        const encoded = if (data.renewal_binding) |renewal_context| try std.json.Stringify.valueAlloc(a, .{ .purpose = "owned_siwc_pair_refresh_v1", .dispatch = data.binding, .pair = renewal_context }, .{}) else try std.json.Stringify.valueAlloc(a, data.binding, .{});
        defer a.free(encoded);
        var result: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(encoded, &result, .{});
        return result;
    }
};
fn ticketData(self: *IssuedTicket) *TicketData {
    return @ptrCast(@alignCast(self));
}
fn ticketDataConst(self: *const IssuedTicket) *const TicketData {
    return @ptrCast(@alignCast(self));
}
fn wipeFree(a: std.mem.Allocator, bytes: []const u8) void {
    std.crypto.secureZero(u8, @constCast(bytes));
    a.free(bytes);
}
fn deadline(io: std.Io, until: std.Io.Clock.Timestamp) !void {
    if (until.clock != .awake) return error.OAuthDeadline;
    const remaining = until.durationFromNow(io).raw.toNanoseconds();
    if (remaining <= 0 or remaining > 120_000_000_000) return error.OAuthDeadline;
}
fn cloneMaterial(a: std.mem.Allocator, input: DispatchMaterial) !DispatchMaterial {
    var result = input;
    result.client_id = try a.dupe(u8, input.client_id);
    errdefer a.free(result.client_id);
    result.resource = if (input.resource) |resource| try a.dupe(u8, resource) else null;
    errdefer if (result.resource) |resource| a.free(resource);
    result.account_id = if (input.account_id) |account| try a.dupe(u8, account) else null;
    errdefer if (result.account_id) |account| a.free(account);
    result.grant_id = try a.dupe(u8, input.grant_id);
    errdefer a.free(result.grant_id);
    result.grant = switch (input.grant) {
        .code => |code| blk: {
            const body = try a.dupe(u8, code.code);
            errdefer wipeFree(a, body);
            const verifier = try a.dupe(u8, code.verifier);
            errdefer wipeFree(a, verifier);
            const redirect = try a.dupe(u8, code.redirect_uri);
            break :blk .{ .code = .{ .code = body, .verifier = verifier, .redirect_uri = redirect } };
        },
        .refresh => |refresh| .{ .refresh = try a.dupe(u8, refresh) },
    };
    result.fence.retain();
    return result;
}

const Retained = struct {
    schema_version: u32,
    import_forget_epoch: u64,
    fresh_oauth_authority: ?enrollment.Snapshot,
    fresh_oauth_host_id: ?[32]u8 = null,
};
fn retainedRecord(saved: Retained, binding: enrollment.Binding) !enrollment.Record {
    if (saved.schema_version != 2 or saved.import_forget_epoch != binding.forget_epoch) return error.OAuthAuthorityChanged;
    const ledger = saved.fresh_oauth_authority orelse return error.OAuthAuthorityChanged;
    try enrollment.validate(ledger);
    for (ledger.records) |record| if (std.meta.eql(record.binding.transaction_id, binding.transaction_id)) {
        if (!std.meta.eql(record.binding, binding)) return error.OAuthAuthorityChanged;
        return record;
    };
    return error.OAuthAuthorityChanged;
}
/// Actual Store-backed constructor. `after` is the actor's complete capacity-
/// checked snapshot, with ONLY this row's issued phase/capsule deletion and
/// its exact maintenance obligation changed. No accepted-work history changes.
pub fn issueCode(io: std.Io, a: std.mem.Allocator, store: *storage.Store, key: ?envelope.Key, key_id: []const u8, expected_revision: u64, after: []const u8, binding: enrollment.Binding, qualified: ?*EnrollmentProfile, until: std.Io.Clock.Timestamp) !*IssuedTicket {
    const profile = qualified orelse return error.RegistrationProfileUnavailable;
    try profile.requireAvailable();
    const wrapping = key orelse return error.WrappingKeyUnavailable;
    try deadline(io, until);
    if (binding.flow_kind == .owned_consent and (until.raw.nanoseconds > binding.flow_until_nanoseconds or std.Io.Clock.real.now(io).toSeconds() < binding.flow_admitted_unix)) return error.OAuthAuthorityChanged;
    const view = profile.view();
    if (std.Io.Clock.real.now(io).toSeconds() >= binding.consent_expires_at) return error.OAuthAuthorityChanged;
    if (binding.registration_profile_sha256 == null or !std.crypto.timing_safe.eql([32]u8, binding.registration_profile_sha256.?, view.sha256) or !std.mem.eql(u8, binding.redirect(), view.exact_redirect_uri)) return error.OAuthAuthorityChanged;
    var before = try store.readSnapshot();
    defer before.deinit();
    if (before.revision != expected_revision) return error.StaleRevision;
    const old = try std.json.parseFromSlice(Retained, a, before.json, .{ .ignore_unknown_fields = true });
    defer old.deinit();
    if (view.endpoint == .omux_oss_token and !std.meta.eql(old.value.fresh_oauth_host_id, @as(?[32]u8, view.host_id))) return error.OAuthAuthorityChanged;
    const prior = try retainedRecord(old.value, binding);
    if (prior.phase != .callback_consumed or prior.consent_status != .recorded or prior.callback_format != .issued_client_bundle or !std.meta.eql(binding.host_id, view.host_id)) return error.OAuthIssueAlreadyAdmitted;
    const proposed = try std.json.parseFromSlice(Retained, a, after, .{ .ignore_unknown_fields = true });
    defer proposed.deinit();
    const next = try retainedRecord(proposed.value, binding);
    if (next.phase != .exchange_issued) return error.OAuthIssueAlreadyAdmitted;
    try exactTransition(a, before.json, after, binding.transaction_id);
    var verifier = try enrollment.openCapsule(a, wrapping, key_id, prior, .verifier);
    defer verifier.deinit();
    var callback = try enrollment.openCapsule(a, wrapping, key_id, prior, .callback);
    defer callback.deinit();
    var nonce = try enrollment.openCapsule(a, wrapping, key_id, prior, .nonce);
    defer nonce.deinit();
    var nonce_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(nonce.bytes, &nonce_hash, .{});
    if (nonce.bytes.len != 43 or !std.crypto.timing_safe.eql([32]u8, nonce_hash, binding.oidc_nonce_digest)) return error.InvalidOAuthCapsule;
    const bundle = try std.json.parseFromSlice(struct { code: []const u8, client_id: []const u8 }, a, callback.bytes, .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error" });
    defer bundle.deinit();
    defer {
        std.crypto.secureZero(u8, @constCast(bundle.value.code));
        std.crypto.secureZero(u8, @constCast(bundle.value.client_id));
    }
    if (verifier.bytes.len < 43 or verifier.bytes.len > 128 or bundle.value.code.len == 0 or bundle.value.code.len > enrollment.max_code_bytes or !enrollment.validIssuedClient(bundle.value.client_id)) return error.InvalidOAuthCapsule;
    const fence = try a.create(FenceData);
    fence.* = .{ .allocator = a, .io = io, .until = until, .consent_expires_at = binding.consent_expires_at };
    const opaque_fence: *DispatchFence = @ptrCast(fence);
    errdefer opaque_fence.deinit();
    const id = std.fmt.bytesToHex(binding.grant_id, .lower);
    const raw: DispatchMaterial = .{ .grant = .{ .code = .{ .code = bundle.value.code, .verifier = verifier.bytes, .redirect_uri = view.exact_redirect_uri } }, .endpoint = view.endpoint, .encoding = view.code_encoding, .client_id = bundle.value.client_id, .resource = view.resource, .account_id = null, .grant_id = &id, .io = io, .until = until, .fence = opaque_fence };
    var material = try cloneMaterial(a, raw);
    errdefer material.deinit(a);
    const ticket = try a.create(TicketData);
    errdefer a.destroy(ticket);
    try deadline(io, until);
    const committed = try store.commit(expected_revision, after, &.{});
    var final = try store.readSnapshot();
    defer final.deinit();
    if (final.revision != committed or !std.mem.eql(u8, final.json, after)) return error.OAuthIssueReadbackLost;
    // Last original-clock/consent check after authenticated readback.
    try deadline(io, until);
    if (std.Io.Clock.real.now(io).toSeconds() >= binding.consent_expires_at) return error.OAuthConsentExpired;
    profile.retain();
    ticket.* = .{ .allocator = a, .material = material, .profile = profile, .committed_revision = committed, .binding = binding };
    opaque_fence.deinit();
    return @ptrCast(ticket);
}
const RenewalRetained = struct {
    schema_version: u32,
    state: domain.Snapshot,
    import_forget_epoch: u64,
    fresh_oauth_host_id: ?[32]u8 = null,
    owned_siwc_pairs: ?pair.Snapshot = null,
    import_source_authority: []const struct { source_id: []const u8, generation: u64 } = &.{},
};
fn pairedRow(saved: RenewalRetained, account_id: []const u8, access_id: []const u8) !pair.Record {
    if (saved.schema_version != 2) return error.OAuthAuthorityChanged;
    const rows = saved.owned_siwc_pairs orelse return error.SiwcPairUnavailable;
    try pair.validate(rows);
    for (rows.records) |row| if (std.mem.eql(u8, row.account_id, account_id) and std.mem.eql(u8, row.access_grant_id, access_id)) return row;
    return error.SiwcPairUnavailable;
}
fn recordCommitment(a: std.mem.Allocator, row: pair.Record) ![32]u8 {
    const bytes = try std.json.Stringify.valueAlloc(a, row, .{});
    defer a.free(bytes);
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}
fn fixedId(value: []const u8) ![64]u8 {
    if (value.len != 64) return error.OAuthAuthorityChanged;
    var out: [64]u8 = undefined;
    for (value) |byte| if (!std.ascii.isHex(byte)) return error.OAuthAuthorityChanged;
    @memcpy(&out, value);
    return out;
}
fn decodedId(value: []const u8) ![32]u8 {
    _ = try fixedId(value);
    var out: [32]u8 = undefined;
    if ((try std.fmt.hexToBytes(&out, value)).len != out.len) return error.OAuthAuthorityChanged;
    return out;
}
fn renewalTuple(store: *storage.Store, binding: *const RenewalBinding) storage.OwnedPairRotation {
    return .{
        .operation_id = &binding.operation.operation_id,
        .access = .{ .key_id = store.key_id, .account_id = &binding.account_id, .grant_id = &binding.access_grant_id, .generation = binding.operation.family_generation, .purpose = "request", .scope = pair.resource_uri },
        .refresh = .{ .key_id = store.key_id, .account_id = &binding.account_id, .grant_id = &binding.refresh_grant_id, .generation = binding.operation.family_generation, .purpose = "renewal", .scope = pair.resource_uri },
    };
}
fn ongoingSourceExpiry(saved: RenewalRetained, row: pair.Record, now: i64) !i64 {
    var source_ok = false;
    var expires: i64 = 0;
    for (saved.state.sources) |source| if (std.mem.eql(u8, source.id, row.source_id)) {
        if (source.kind != .oauth or source.status == .disconnected or !std.mem.eql(u8, source.provider, "openai_siwc") or source.authorized_at > now or
            (source.authorized_until != null and source.authorized_until.? <= now)) return error.OAuthAuthorityChanged;
        source_ok = true;
        expires = source.authorized_until orelse 253_402_300_799;
    };
    var generation_ok = false;
    for (saved.import_source_authority) |source| if (std.mem.eql(u8, source.source_id, row.source_id) and source.generation == row.source_generation) {
        generation_ok = true;
    };
    var account_ok = false;
    const identity = std.fmt.bytesToHex(row.identity_commitment, .lower);
    for (saved.state.accounts) |account| if (std.mem.eql(u8, account.id, row.account_id)) {
        if (!account.identity.verified or !std.mem.eql(u8, account.identity.provider, "openai_siwc") or !std.mem.eql(u8, account.identity.issuer, pair.issuer_uri) or
            !std.mem.eql(u8, account.identity.subject, &identity) or account.identity.tenant.len != 0) return error.OAuthAuthorityChanged;
        for (account.source_ids) |source| if (std.mem.eql(u8, source, row.source_id)) {
            account_ok = true;
        };
    };
    if (!source_ok or !generation_ok or !account_ok or row.forget_tombstone or row.consent_status != .recorded) return error.OAuthAuthorityChanged;
    return expires;
}
fn checkRenewalClock(io: std.Io, until: std.Io.Clock.Timestamp, binding: RenewalBinding) !void {
    try deadline(io, until);
    const now = std.Io.Clock.real.now(io).toSeconds();
    try binding.operation.grant_window.check(now);
    if (until.raw.nanoseconds != binding.operation.until_nanoseconds or now < binding.operation.admitted_unix or now >= binding.operation.source_expires_at) return error.OAuthAuthorityChanged;
}
fn checkRenewalRow(a: std.mem.Allocator, saved: RenewalRetained, binding: RenewalBinding, now: i64) !pair.Record {
    const row = try pairedRow(saved, &binding.account_id, &binding.access_grant_id);
    if (row.status != .refreshing or row.renewal == null or !std.meta.eql(row.renewal.?, binding.operation) or row.consent_status != .recorded or row.forget_tombstone or
        row.family_generation != binding.operation.family_generation or row.writer_generation != binding.operation.writer_generation or
        row.source_generation != binding.operation.source_generation or row.consent_generation != binding.operation.consent_generation or
        saved.import_forget_epoch < binding.operation.forget_epoch) return error.OAuthAuthorityChanged;
    const window = try pair.grantWindow(saved.state.grants, row);
    if (!std.meta.eql(window, binding.operation.grant_window)) return error.OAuthAuthorityChanged;
    try window.check(now);
    if (try ongoingSourceExpiry(saved, row, now) != binding.operation.source_expires_at) return error.OAuthAuthorityChanged;
    // Unrelated account forget can advance the global epoch without erasing an
    // independently valid known family. Exact account/source/tombstone guards
    // above still reject its own forget; rollback epochs always refuse.
    var old = row;
    old.status = .ready;
    old.renewal = binding.previous_renewal;
    if (!std.crypto.timing_safe.eql([32]u8, try recordCommitment(a, old), binding.prior_record_commitment)) return error.OAuthAuthorityChanged;
    var access_ok = false;
    var refresh_ok = false;
    for (saved.state.grants) |grant| {
        if (!std.mem.eql(u8, grant.account_id, row.account_id) or !std.mem.eql(u8, grant.source_id, row.source_id) or grant.ownership != .omux or !std.mem.eql(u8, grant.audience, pair.resource_uri)) continue;
        if (std.mem.eql(u8, grant.id, row.access_grant_id) and grant.credential_kind == .oauth_access and grant.status == .ready and grant.generation == row.access_generation and grant.provider_expires_at == row.access_expires_at) {
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
            access_ok = request and invoke and direct;
        }
        if (std.mem.eql(u8, grant.id, row.refresh_grant_id) and grant.credential_kind == .oauth_refresh and grant.status == .refreshing and grant.generation == row.refresh_generation) {
            for (grant.purposes) |purpose| if (purpose == .renewal) {
                refresh_ok = true;
            };
        }
    }
    if (!access_ok or !refresh_ok) return error.OAuthAuthorityChanged;
    return row;
}
const RenewalIssueFence = struct {
    io: std.Io,
    until: std.Io.Clock.Timestamp,
    allocator: std.mem.Allocator,
    store: *storage.Store,
    binding: RenewalBinding,
    actor: *const storage.CommitFence,
    client_id: []const u8,
    pub fn check(raw: *anyopaque, stage: storage.CommitStage) !void {
        const self: *RenewalIssueFence = @ptrCast(@alignCast(raw));
        try checkRenewalClock(self.io, self.until, self.binding);
        try self.actor.check(self.actor.context, stage);
        if (stage == .before_begin) {
            const current = try pair.currentRenewalOwner(self.store, &self.binding.account_id, &self.binding.access_grant_id, self.binding.operation.family_generation, std.Io.Clock.real.now(self.io).toSeconds());
            defer current.deinit();
            if (!std.crypto.timing_safe.eql([32]u8, current.activationCommitment(), self.binding.prior_activation)) return error.OAuthAuthorityChanged;
        } else {
            try self.store.authenticateOwnedPairRefresh(renewalTuple(self.store, &self.binding), self.client_id, self.binding.refresh_token_commitment);
        }
        try checkRenewalClock(self.io, self.until, self.binding);
    }
};
/// New paired constructor, never a generic owner=omux-row shortcut. A real
/// authenticated ready pair and exact original actor mutation precede the
/// snapshot-coupled one-use intent. No source/registry/identity can change here.
pub fn issueOwnedRefresh(io: std.Io, a: std.mem.Allocator, store: *storage.Store, expected_revision: u64, after: []const u8, account_id: []const u8, access_id: []const u8, generation: u64, until: std.Io.Clock.Timestamp, actor_fence: *const storage.CommitFence) !*IssuedTicket {
    try deadline(io, until);
    const authority = try pair.currentRenewalOwner(store, account_id, access_id, generation, std.Io.Clock.real.now(io).toSeconds());
    defer authority.deinit();
    var before = try store.readSnapshot();
    defer before.deinit();
    if (before.revision != expected_revision) return error.StaleRevision;
    const prior = try std.json.parseFromSlice(RenewalRetained, a, before.json, .{ .ignore_unknown_fields = true });
    defer prior.deinit();
    const next = try std.json.parseFromSlice(RenewalRetained, a, after, .{ .ignore_unknown_fields = true });
    defer next.deinit();
    const old = try pairedRow(prior.value, account_id, access_id);
    const proposed = try pairedRow(next.value, account_id, access_id);
    if (old.status != .ready or old.family_generation != generation or !std.crypto.timing_safe.eql([32]u8, authority.activationCommitment(), old.activation_commitment)) return error.OAuthAuthorityChanged;
    const operation = proposed.renewal orelse return error.OAuthAuthorityChanged;
    const now = std.Io.Clock.real.now(io).toSeconds();
    const original_window = try pair.grantWindow(prior.value.state.grants, old);
    try original_window.check(now);
    if (!std.meta.eql(operation.grant_window, original_window)) return error.OAuthAuthorityChanged;
    if (proposed.status != .refreshing or operation.state != .issued or operation.family_generation != old.family_generation or operation.writer_generation != old.writer_generation or
        operation.source_generation != old.source_generation or operation.consent_generation != old.consent_generation or operation.forget_epoch != prior.value.import_forget_epoch or
        operation.admitted_unix > now or operation.until_nanoseconds != until.raw.nanoseconds or operation.admitted_awake_nanoseconds > std.Io.Clock.awake.now(io).nanoseconds or
        operation.source_expires_at != try ongoingSourceExpiry(prior.value, old, now)) return error.OAuthAuthorityChanged;
    const binding: RenewalBinding = .{ .account_id = try fixedId(old.account_id), .source_id = try fixedId(old.source_id), .access_grant_id = try fixedId(old.access_grant_id), .refresh_grant_id = try fixedId(old.refresh_grant_id), .lineage_id = old.lineage_id, .registration_transaction = old.transaction_id, .prior_record_commitment = try recordCommitment(a, old), .prior_activation = old.activation_commitment, .profile_sha256 = old.profile_sha256, .identity_commitment = old.identity_commitment, .provider_subject_commitment = old.provider_subject_commitment, .issued_client_commitment = old.issued_client_commitment, .refresh_token_commitment = old.refresh_token_commitment, .previous_renewal = old.renewal, .operation = operation };
    try checkRenewalClock(io, until, binding);
    _ = try checkRenewalRow(a, next.value, binding, now);
    try exactPairedIssueTransition(a, before.json, after, old.transaction_id, old.refresh_grant_id, operation);
    var refresh_secret = try store.loadGrant(.{ .key_id = store.key_id, .account_id = old.account_id, .grant_id = old.refresh_grant_id, .generation = old.refresh_generation, .purpose = "renewal", .scope = pair.resource_uri });
    defer refresh_secret.deinit();
    var scratch: [128 * 1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &scratch);
    var fixed = std.heap.FixedBufferAllocator.init(&scratch);
    const saved = try std.json.parseFromSlice(struct { refresh_token: []const u8, client_id: []const u8 }, fixed.allocator(), refresh_secret.bytes, .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error" });
    defer saved.deinit();
    if (!enrollment.validIssuedClient(saved.value.client_id) or saved.value.refresh_token.len == 0 or saved.value.refresh_token.len > token.max_credential_bytes or
        !std.crypto.timing_safe.eql([32]u8, pair.tokenCommitment(store.key, saved.value.refresh_token, .refresh), old.refresh_token_commitment)) return error.OAuthAuthorityChanged;
    const host = prior.value.fresh_oauth_host_id orelse return error.OAuthAuthorityChanged;
    if (std.mem.allEqual(u8, &host, 0)) return error.OAuthAuthorityChanged;
    const client = try a.dupe(u8, saved.value.client_id);
    errdefer wipeFree(a, client);
    const resource = try a.dupe(u8, pair.resource_uri);
    errdefer a.free(resource);
    const redirect = try a.dupe(u8, "");
    errdefer a.free(redirect);
    const profile_owner = try a.create(ProfileData);
    errdefer a.destroy(profile_owner);
    profile_owner.* = .{ .allocator = a, .qualification = .owned_oss_renewal, .view = .{ .endpoint = .omux_oss_token, .code_encoding = .form, .refresh_encoding = .form, .client_id = client, .resource = resource, .exact_redirect_uri = redirect, .sha256 = old.profile_sha256, .host_id = host } };
    const profile: *EnrollmentProfile = @ptrCast(profile_owner);
    // Field and owner errdefers remain disjoint until ticket ownership is
    // transferred after the actual durable/readback boundary.
    const fence_owner = try a.create(FenceData);
    fence_owner.* = .{ .allocator = a, .io = io, .until = until, .consent_expires_at = operation.source_expires_at, .grant_window = operation.grant_window, .renewal_admitted_unix = operation.admitted_unix };
    const fence: *DispatchFence = @ptrCast(fence_owner);
    defer fence.deinit();
    var material = try cloneMaterial(a, .{ .grant = .{ .refresh = saved.value.refresh_token }, .endpoint = .omux_oss_token, .encoding = .form, .client_id = saved.value.client_id, .resource = pair.resource_uri, .account_id = old.account_id, .grant_id = old.refresh_grant_id, .io = io, .until = until, .fence = fence });
    errdefer material.deinit(a);
    const dispatch_binding: enrollment.Binding = .{ .transaction_id = operation.issued_transaction, .source_id = try decodedId(old.source_id), .source_generation = old.source_generation, .consent_id = old.consent_id, .consent_generation = old.consent_generation, .forget_epoch = operation.forget_epoch, .grant_id = try decodedId(old.refresh_grant_id), .expected_grant_generation = old.refresh_generation, .consent_expires_at = operation.source_expires_at, .host_id = host, .operation_id = operation.operation_id, .operation_id_len = 64, .registration_profile_sha256 = old.profile_sha256 };
    const data = try a.create(TicketData);
    errdefer a.destroy(data);
    var joined: RenewalIssueFence = .{ .io = io, .until = until, .allocator = a, .store = store, .binding = binding, .actor = actor_fence, .client_id = saved.value.client_id };
    const guarded: storage.CommitFence = .{ .context = &joined, .check = RenewalIssueFence.check };
    const committed = try store.beginOwnedPairRotation(expected_revision, after, renewalTuple(store, &binding), &guarded);
    var final = try store.readSnapshot();
    defer final.deinit();
    if (final.revision != committed or !std.mem.eql(u8, final.json, after)) return error.OAuthIssueReadbackLost;
    try store.authenticateOwnedPairRefresh(renewalTuple(store, &binding), saved.value.client_id, binding.refresh_token_commitment);
    try checkRenewalClock(io, until, binding);
    data.* = .{ .allocator = a, .material = material, .profile = profile, .committed_revision = committed, .renewal_binding = binding, .binding = dispatch_binding };
    return @ptrCast(data);
}
/// Actor-owner SQL reread. Old access expiry does not forbid a timely authentic
/// refresh completion; request-only currentPair still refuses expired access.
pub fn verifyCurrentOwnedRefresh(a: std.mem.Allocator, store: *storage.Store, ticket: *const IssuedTicket) !void {
    try ticket.requireOwnedOssRenewal();
    const binding = try ticket.renewalBinding();
    try checkRenewalClock(ticket.clockIo(), ticket.originalUntil(), binding);
    var current = try store.readSnapshot();
    defer current.deinit();
    if (current.revision < ticket.committedRevision()) return error.OAuthAuthorityChanged;
    const parsed = try std.json.parseFromSlice(RenewalRetained, a, current.json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    _ = try checkRenewalRow(a, parsed.value, binding, std.Io.Clock.real.now(store.io).toSeconds());
    if (!std.meta.eql(parsed.value.fresh_oauth_host_id, @as(?[32]u8, ticketDataConst(ticket).profile.view().host_id))) return error.OAuthAuthorityChanged;
    try store.authenticateOwnedPairRefresh(renewalTuple(store, &binding), ticket.issuedClientId(), binding.refresh_token_commitment);
    try checkRenewalClock(ticket.clockIo(), ticket.originalUntil(), binding);
}
fn exactPairedIssueTransition(a: std.mem.Allocator, before: []const u8, after: []const u8, transaction: [32]u8, refresh_id: []const u8, operation: pair.Renewal) !void {
    var old = try std.json.parseFromSlice(std.json.Value, a, before, .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error" });
    defer old.deinit();
    const next = try std.json.parseFromSlice(std.json.Value, a, after, .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error" });
    defer next.deinit();
    if (old.value != .object or next.value != .object) return error.OAuthAuthorityChanged;
    const section = old.value.object.get("owned_siwc_pairs") orelse return error.OAuthAuthorityChanged;
    const rows = if (section == .object) section.object.get("records") orelse return error.OAuthAuthorityChanged else return error.OAuthAuthorityChanged;
    if (rows != .array) return error.OAuthAuthorityChanged;
    const operation_bytes = try std.json.Stringify.valueAlloc(a, operation, .{});
    defer a.free(operation_bytes);
    const parsed_operation = try std.json.parseFromSlice(std.json.Value, a, operation_bytes, .{ .allocate = .alloc_always });
    defer parsed_operation.deinit();
    var found = false;
    for (rows.array.items) |*row| {
        const bytes = try std.json.Stringify.valueAlloc(a, row.*, .{});
        defer a.free(bytes);
        const checked = try std.json.parseFromSlice(pair.Record, a, bytes, .{});
        defer checked.deinit();
        if (!std.meta.eql(checked.value.transaction_id, transaction)) continue;
        if (found or row.* != .object) return error.OAuthAuthorityChanged;
        found = true;
        try row.object.put(a, "status", .{ .string = "refreshing" });
        try row.object.put(a, "renewal", parsed_operation.value);
    }
    if (!found) return error.OAuthAuthorityChanged;
    var state = old.value.object.get("state") orelse return error.OAuthAuthorityChanged;
    const next_state = next.value.object.get("state") orelse return error.OAuthAuthorityChanged;
    if (state != .object or next_state != .object) return error.OAuthAuthorityChanged;
    const grants = state.object.get("grants") orelse return error.OAuthAuthorityChanged;
    if (grants != .array) return error.OAuthAuthorityChanged;
    found = false;
    for (grants.array.items) |*grant| {
        if (grant.* != .object) return error.OAuthAuthorityChanged;
        const id = grant.object.get("id") orelse return error.OAuthAuthorityChanged;
        if (id != .string or !std.mem.eql(u8, id.string, refresh_id)) continue;
        if (found) return error.OAuthAuthorityChanged;
        found = true;
        try grant.object.put(a, "status", .{ .string = "refreshing" });
    }
    if (!found) return error.OAuthAuthorityChanged;
    const old_revision = state.object.get("revision") orelse return error.OAuthAuthorityChanged;
    const next_revision = next_state.object.get("revision") orelse return error.OAuthAuthorityChanged;
    if (old_revision != .integer or next_revision != .integer or old_revision.integer == std.math.maxInt(i64) or next_revision.integer != old_revision.integer + 1) return error.OAuthAuthorityChanged;
    try state.object.put(a, "revision", next_revision);
    const growth = next.value.object.get("maintenance_growth_bytes") orelse return error.OAuthAuthorityChanged;
    if (growth != .integer or growth.integer < 0 or growth.integer > storage.maximum_snapshot_bytes) return error.OAuthAuthorityChanged;
    try old.value.object.put(a, "maintenance_growth_bytes", growth);
    const normalized = try std.json.Stringify.valueAlloc(a, old.value, .{});
    defer a.free(normalized);
    const expected = try std.json.Stringify.valueAlloc(a, next.value, .{});
    defer a.free(expected);
    if (!std.mem.eql(u8, normalized, expected)) return error.OAuthAuthorityChanged;
}

/// Actor-owner reread, never called on the libcurl thread. Parsed wire evidence
/// has no authority to replace this exact issued-row/profile/generation join.
pub fn verifyCurrentIssued(a: std.mem.Allocator, store: *storage.Store, ticket: *IssuedTicket, binding: enrollment.Binding, until: std.Io.Clock.Timestamp) !void {
    const data = ticketData(ticket);
    try deadline(data.material.io, until);
    if (!std.meta.eql(data.binding, binding) or !std.meta.eql(data.material.until, until) or std.Io.Clock.real.now(data.material.io).toSeconds() >= binding.consent_expires_at) return error.OAuthAuthorityChanged;
    var current = try store.readSnapshot();
    defer current.deinit();
    if (current.revision < data.committed_revision) return error.OAuthAuthorityChanged;
    const parsed = try std.json.parseFromSlice(Retained, a, current.json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const record = try retainedRecord(parsed.value, binding);
    if (ticketData(ticket).profile.view().endpoint == .omux_oss_token and !std.meta.eql(parsed.value.fresh_oauth_host_id, @as(?[32]u8, ticketData(ticket).profile.view().host_id))) return error.OAuthAuthorityChanged;
    if (record.consent_status != .recorded or (record.phase != .exchange_issued and record.phase != .verifying) or record.registration_profile_sha256 == null or !std.crypto.timing_safe.eql([32]u8, record.registration_profile_sha256.?, ticket.registrationProfileSha256())) return error.OAuthAuthorityChanged;
    try deadline(data.material.io, until);
    if (std.Io.Clock.real.now(data.material.io).toSeconds() >= binding.consent_expires_at) return error.OAuthConsentExpired;
}
fn exactTransition(a: std.mem.Allocator, before: []const u8, after: []const u8, id: [32]u8) !void {
    var old = try std.json.parseFromSlice(std.json.Value, a, before, .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error" });
    defer old.deinit();
    const next = try std.json.parseFromSlice(std.json.Value, a, after, .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error" });
    defer next.deinit();
    if (old.value != .object or next.value != .object) return error.OAuthAuthorityChanged;
    const section = old.value.object.get("fresh_oauth_authority") orelse return error.OAuthAuthorityChanged;
    if (section != .object) return error.OAuthAuthorityChanged;
    const rows = section.object.get("records") orelse return error.OAuthAuthorityChanged;
    if (rows != .array) return error.OAuthAuthorityChanged;
    var found = false;
    for (rows.array.items) |*row| {
        if (row.* != .object) return error.OAuthAuthorityChanged;
        const record = try std.json.Stringify.valueAlloc(a, row.*, .{});
        defer a.free(record);
        const parsed = try std.json.parseFromSlice(enrollment.Record, a, record, .{});
        defer parsed.deinit();
        if (!std.meta.eql(parsed.value.binding.transaction_id, id)) continue;
        if (found) return error.OAuthAuthorityChanged;
        found = true;
        try row.object.put(a, "phase", .{ .string = "exchange_issued" });
        try row.object.put(a, "verifier_capsule", .{ .string = "" });
        try row.object.put(a, "callback_capsule", .{ .string = "" });
        try row.object.put(a, "nonce_capsule", .{ .string = "" });
    }
    if (!found) return error.OAuthAuthorityChanged;
    const growth = next.value.object.get("maintenance_growth_bytes") orelse return error.OAuthAuthorityChanged;
    const prior_growth = old.value.object.get("maintenance_growth_bytes") orelse return error.OAuthAuthorityChanged;
    if (growth != .integer or growth.integer < 0 or prior_growth != .integer or prior_growth.integer < 0) return error.OAuthAuthorityChanged;
    const old_section = old.value.object.get("fresh_oauth_authority") orelse return error.OAuthAuthorityChanged;
    const next_section = next.value.object.get("fresh_oauth_authority") orelse return error.OAuthAuthorityChanged;
    // The old section above has been transformed to the issued row already.
    // Measure original bytes separately; preserve exactly the prepaid sum.
    const original = try std.json.parseFromSlice(std.json.Value, a, before, .{});
    defer original.deinit();
    const original_section = original.value.object.get("fresh_oauth_authority") orelse return error.OAuthAuthorityChanged;
    const old_bytes = try std.json.Stringify.valueAlloc(a, original_section, .{});
    defer a.free(old_bytes);
    const next_bytes = try std.json.Stringify.valueAlloc(a, next_section, .{});
    defer a.free(next_bytes);
    const transformed = try std.json.Stringify.valueAlloc(a, old_section, .{});
    defer a.free(transformed);
    if (!std.mem.eql(u8, transformed, next_bytes) or old_bytes.len < next_bytes.len) return error.OAuthAuthorityChanged;
    const expected_growth = std.math.add(u64, @intCast(prior_growth.integer), old_bytes.len - next_bytes.len) catch return error.OAuthAuthorityChanged;
    if (expected_growth > storage.maximum_snapshot_bytes or @as(u64, @intCast(growth.integer)) != expected_growth) return error.OAuthAuthorityChanged;
    try old.value.object.put(a, "maintenance_growth_bytes", growth);
    const normalized = try std.json.Stringify.valueAlloc(a, old.value, .{});
    defer a.free(normalized);
    const expected = try std.json.Stringify.valueAlloc(a, next.value, .{});
    defer a.free(expected);
    if (!std.mem.eql(u8, normalized, expected)) return error.OAuthAuthorityChanged;
}

pub const testing = struct {
    /// Private retained-ticket comparison for the real loopback wire observer.
    /// No bearer getter, ticket construction or production admission authority.
    pub fn matchesOwnedRefreshWire(ticket: *const IssuedTicket, candidate: []const u8) bool {
        if (!builtin.is_test) return false;
        ticket.requireOwnedOssRenewal() catch return false;
        const selected = ticketDataConst(ticket).material.grant;
        return selected == .refresh and std.mem.eql(u8, selected.refresh, candidate);
    }

    pub fn attachOssModelRoutes(ticket: *IssuedTicket, routes: ModelRoutes) !void {
        if (!builtin.is_test) return error.TestOnly;
        try ticket.requireOwnedOssEnrollment();
        const data = ticketData(ticket);
        if (routes.token_port == 0 or routes.jwks_port == 0 or data.model_routes != null or data.claimed.load(.acquire) or data.jwks_claimed.load(.acquire)) return error.InvalidModelProfile;
        data.model_routes = routes;
    }
    pub fn attachPairedRefreshModelRoutes(ticket: *IssuedTicket, routes: ModelRoutes) !void {
        if (!builtin.is_test) return error.TestOnly;
        try ticket.requireOwnedOssRenewal();
        const owner = ticketData(ticket);
        if (routes.token_port == 0 or routes.jwks_port == 0 or owner.model_routes != null or owner.claimed.load(.acquire) or owner.jwks_claimed.load(.acquire)) return error.InvalidModelProfile;
        owner.model_routes = routes;
    }
    pub const OssRegistrationFixture = struct {
        pub fn create(io: std.Io, a: std.mem.Allocator, token_port: u16, jwks_port: u16, until: std.Io.Clock.Timestamp) !CodeFixture {
            return CodeFixture.createWithRoutes(io, a, token_port, until, .{ .token_port = token_port, .jwks_port = jwks_port });
        }
    };
    /// Plain isolated model, not provider registration or an installed issuer.
    /// Available only in the declared test graph; provider endpoints forbidden.
    pub fn profile(a: std.mem.Allocator, port: u16, redirect: []const u8) !*EnrollmentProfile {
        if (!builtin.is_test) return error.TestOnly;
        if (port == 0 or redirect.len == 0 or redirect.len > 256 or !std.mem.startsWith(u8, redirect, "http://127.0.0.1")) return error.InvalidModelProfile;
        const client = try a.dupe(u8, "omux-fixture-client");
        errdefer a.free(client);
        const callback = try a.dupe(u8, redirect);
        errdefer a.free(callback);
        var digest: [32]u8 = undefined;
        const framed = try std.json.Stringify.valueAlloc(a, .{ .kind = "model-only-oauth-profile", .fixture_port = port, .client_id = client, .redirect = callback }, .{});
        defer a.free(framed);
        std.crypto.hash.sha2.Sha256.hash(framed, &digest, .{});
        const data = try a.create(ProfileData);
        data.* = .{ .allocator = a, .view = .{ .endpoint = .{ .fixture_token = port }, .code_encoding = .form, .refresh_encoding = .json, .client_id = client, .resource = null, .exact_redirect_uri = callback, .sha256 = digest } };
        return @ptrCast(data);
    }
    pub const CodeFixture = struct {
        allocator: std.mem.Allocator,
        directory: std.testing.TmpDir,
        path: [:0]u8,
        store: storage.Store,
        ledger: enrollment.Ledger,
        profile: *EnrollmentProfile,
        ticket: *IssuedTicket,
        fence: *DispatchFence,
        issued_revision: u64,
        binding: enrollment.Binding,
        model_nonce: ?envelope.Secret = null,
        pub fn create(io: std.Io, a: std.mem.Allocator, port: u16, until: std.Io.Clock.Timestamp) !CodeFixture {
            return createWithRoutes(io, a, port, until, null);
        }
        fn createWithRoutes(io: std.Io, a: std.mem.Allocator, port: u16, until: std.Io.Clock.Timestamp, routes: ?ModelRoutes) !CodeFixture {
            if (!builtin.is_test) return error.TestOnly;
            if (routes) |selected| if (selected.token_port == 0 or selected.jwks_port == 0) return error.InvalidModelProfile;
            var directory = std.testing.tmpDir(.{});
            errdefer directory.cleanup();
            if (std.c.fchmodat(directory.dir.handle, ".", 0o700, 0) != 0) return error.UnsafeModelDirectory;
            const root = try directory.dir.realPathFileAlloc(io, ".", a);
            defer a.free(root);
            const path = try std.fmt.allocPrintSentinel(a, "{s}/state.sqlite", .{root}, 0);
            errdefer a.free(path);
            const key: envelope.Key = @splat(0x39);
            var store = try storage.Store.openRoot(io, a, path, "fixture-oauth-root", key);
            errdefer store.close();
            var host: [32]u8 = undefined;
            try io.randomSecure(&host);
            const registered = if (routes != null) try documentedOssEnrollment(a, host, "http://127.0.0.1:54321/auth/callback") else try testing.profile(a, port, "http://127.0.0.1/auth/callback");
            errdefer registered.deinit();
            var ledger: enrollment.Ledger = .{};
            errdefer ledger.deinit(a);
            var original = try ledger.prepare(io, a, key, "fixture-oauth-root", 0, std.Io.Clock.real.now(io).toSeconds(), 60, until);
            defer original.deinit();
            ledger.records.items[0].provider = .openai_siwc;
            ledger.records.items[0].consent_purpose = .fresh_openai_siwc_oauth_enrollment;
            var prepared = try ledger.bindForIssue(io, a, key, "fixture-oauth-root", original, "fixture-code-operation", registered.view().sha256, registered.view().exact_redirect_uri, registered.view().host_id);
            defer prepared.deinit();
            var model_nonce: ?envelope.Secret = null;
            errdefer if (model_nonce) |*nonce| nonce.deinit();
            if (routes != null) {
                var raw: [43]u8 = undefined;
                defer std.crypto.secureZero(u8, &raw);
                _ = std.base64.url_safe_no_pad.Encoder.encode(&raw, &original.oidc_nonce);
                model_nonce = .{ .allocator = a, .bytes = try a.dupe(u8, &raw) };
            }
            var saved: ModelSnapshot = .{ .fresh_oauth_host_id = if (routes != null) host else null, .fresh_oauth_authority = ledger.snapshot(), .maintenance_growth_bytes = try modelGrowth(a, ledger.snapshot()) };
            const initial = try std.json.Stringify.valueAlloc(a, saved, .{});
            defer a.free(initial);
            var revision = try store.commit(0, initial, &.{});
            try ledger.consumeOwnedCallback(io, a, key, "fixture-oauth-root", prepared, prepared.binding, std.Io.Clock.real.now(io).toSeconds(), &prepared.callback_state, "synthetic-callback-code", "omux-fixture-client");
            saved.fresh_oauth_authority = ledger.snapshot();
            saved.maintenance_growth_bytes = try modelGrowth(a, ledger.snapshot());
            const consumed = try std.json.Stringify.valueAlloc(a, saved, .{});
            defer a.free(consumed);
            revision = try store.commit(revision, consumed, &.{});
            try ledger.markIssued(a, prepared.binding);
            saved.fresh_oauth_authority = ledger.snapshot();
            saved.maintenance_growth_bytes = try modelGrowth(a, ledger.snapshot());
            const issued = try std.json.Stringify.valueAlloc(a, saved, .{});
            defer a.free(issued);
            const ticket = try issueCode(io, a, &store, key, "fixture-oauth-root", revision, issued, prepared.binding, registered, until);
            errdefer ticket.deinit();
            if (routes) |selected| try testing.attachOssModelRoutes(ticket, selected);
            const fence = ticket.retainFence();
            return .{ .model_nonce = model_nonce, .allocator = a, .directory = directory, .path = path, .store = store, .ledger = ledger, .profile = registered, .ticket = ticket, .fence = fence, .issued_revision = ticket.committedRevision(), .binding = prepared.binding };
        }
        pub fn invalidate(self: *CodeFixture) Cancellation {
            return self.fence.invalidate();
        }
        pub fn deinit(self: *CodeFixture) void {
            _ = self.invalidate();
            self.fence.deinit();
            self.ticket.deinit();
            self.profile.deinit();
            if (self.model_nonce) |*nonce| nonce.deinit();
            self.ledger.deinit(self.allocator);
            self.store.close();
            self.allocator.free(self.path);
            self.directory.cleanup();
            self.* = undefined;
        }
    };
};
fn modelGrowth(a: std.mem.Allocator, value: enrollment.Snapshot) !usize {
    const encoded = try std.json.Stringify.valueAlloc(a, value, .{});
    defer a.free(encoded);
    if (encoded.len > enrollment.maximum_snapshot_bytes) return error.InvalidOAuthEnrollment;
    return enrollment.maximum_snapshot_bytes - encoded.len;
}
const ModelSnapshot = struct {
    schema_version: u32 = 2,
    import_forget_epoch: u64 = 0,
    fresh_oauth_authority: enrollment.Snapshot,
    fresh_oauth_host_id: ?[32]u8 = null,
    maintenance_growth_bytes: usize = 0,
};

test "actual SQLite code issue is single use and cancelled dispatch is not replay" {
    const a = std.testing.allocator;
    var fixture = try testing.CodeFixture.create(std.testing.io, a, 12345, .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(5) }));
    defer fixture.deinit();
    try std.testing.expectEqual(@as(u64, 3), fixture.issued_revision);
    var material = try fixture.ticket.claim(a);
    defer material.deinit(a);
    try std.testing.expectEqualSlices(u8, "synthetic-callback-code", material.grant.code.code);
    try std.testing.expect(material.account_id == null);
    try std.testing.expectError(error.OAuthTicketConsumed, fixture.ticket.claim(a));
    try std.testing.expectEqual(Cancellation.prevented_before_dispatch, fixture.invalidate());
    try std.testing.expectError(error.OAuthDispatchRefused, material.fence.beginDispatch());
    var retained = try fixture.store.readSnapshot();
    defer retained.deinit();
    const parsed = try std.json.parseFromSlice(Retained, a, retained.json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    var recovered = try enrollment.Ledger.fromSnapshot(a, parsed.value.fresh_oauth_authority.?);
    defer recovered.deinit(a);
    recovered.recoverAfterRestart(a);
    try std.testing.expectEqual(enrollment.Phase.completion_unknown, recovered.records.items[0].phase);
}

test "dispatch linearization and claim allocation failure remain one shot" {
    const a = std.testing.allocator;
    var fixture = try testing.CodeFixture.create(std.testing.io, a, 12345, .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(5) }));
    defer fixture.deinit();
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, fixture.ticket.claim(failing.allocator()));
    try std.testing.expectError(error.OAuthTicketConsumed, fixture.ticket.claim(a));
    try fixture.fence.beginDispatch();
    try std.testing.expectError(error.OAuthDispatchRefused, fixture.fence.beginDispatch());
    try std.testing.expectEqual(Cancellation.issued_or_racing, fixture.invalidate());
    try std.testing.expectError(error.OAuthCompletionIndeterminate, fixture.fence.checkBeforeCompletion());
}

test "actual issued Store reread refuses successor context forget and metadata tampering without a second ticket" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    for ([_]enum { source_generation, consent_generation, forget }{ .source_generation, .consent_generation, .forget }) |change| {
        var fixture = try testing.CodeFixture.create(io, a, 12345, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) }));
        defer fixture.deinit();
        try verifyCurrentIssued(a, &fixture.store, fixture.ticket, fixture.binding, fixture.ticket.originalUntil());
        switch (change) {
            .source_generation => fixture.ledger.records.items[0].binding.source_generation += 1,
            .consent_generation => fixture.ledger.records.items[0].binding.consent_generation += 1,
            .forget => {},
        }
        const saved: ModelSnapshot = .{ .import_forget_epoch = if (change == .forget) 1 else 0, .fresh_oauth_authority = fixture.ledger.snapshot(), .maintenance_growth_bytes = try modelGrowth(a, fixture.ledger.snapshot()) };
        const encoded = try std.json.Stringify.valueAlloc(a, saved, .{});
        defer a.free(encoded);
        _ = try fixture.store.commit(fixture.issued_revision, encoded, &.{});
        try std.testing.expectError(error.OAuthAuthorityChanged, verifyCurrentIssued(a, &fixture.store, fixture.ticket, fixture.binding, fixture.ticket.originalUntil()));
        _ = fixture.invalidate();
        try std.testing.expectError(error.OAuthDispatchRefused, fixture.ticket.claim(a));
        try std.testing.expectError(error.OAuthTicketConsumed, fixture.ticket.claim(a));
        try std.testing.expectError(error.OAuthAuthorityChanged, fixture.ticket.requireOwnedOssEnrollment());
    }
}

test "documented enrollment authority is initial only and rejects native redirect and empty host without provider IO" {
    const a = std.testing.allocator;
    try std.testing.expectError(error.RegistrationProfileUnavailable, documentedOssEnrollment(a, @splat(0), "http://127.0.0.1:54321/auth/callback"));
    for ([_][]const u8{ "http://localhost:1455/auth/callback", "http://127.0.0.1:0/auth/callback", "http://127.0.0.1:054321/auth/callback", "http://127.0.0.1:54321/callback", "https://127.0.0.1:54321/auth/callback", "http://127.0.0.1:54321/auth/callback?next=anything" }) |bad| try std.testing.expectError(error.InvalidOAuthRedirect, documentedOssEnrollment(a, @splat(0x42), bad));
    const profile = try documentedOssEnrollment(a, @splat(0x42), "http://127.0.0.1:54321/auth/callback");
    defer profile.deinit();
    try profile.requireAvailable();
    try std.testing.expect(profile.view().endpoint == .omux_oss_token);
    try std.testing.expectEqual(token.Encoding.form, profile.view().code_encoding);
    try std.testing.expectEqual(token.Encoding.form, profile.view().refresh_encoding);
    try std.testing.expectEqualStrings("dynamic_agent_client", profile.view().client_id);
    try std.testing.expectEqualStrings("https://api.openai.com/v1", profile.view().resource.?);
    try std.testing.expect(!enrollment.validIssuedClient(profile.view().client_id));
}
