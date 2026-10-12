//! Daemon-owned fresh OAuth intent and encrypted PKCE custody. This ledger
//! cannot authorize provider IO or activate a grant. A native client literal,
//! new code or authenticated account identity is not registration/family proof.
//! The actor commits every transition before any dependent effect. No callback
//! listener or dispatcher is reconstructed from this durable ledger. Owned OSS
//! registration is dispatched through oauth_issue_authority.OssEnrollment; this
//! ledger alone cannot supply that authority or adopt an external refresh writer.
const std = @import("std");
const envelope = @import("envelope.zig");

pub const max_records = 16;
pub const max_code_bytes = 4096;
pub const maximum_snapshot_bytes = 512 * 1024;
pub const purpose = "fresh_codex_oauth_enrollment";
pub const oss_purpose = "fresh_openai_siwc_oauth_enrollment";
pub const ConsentStatus = enum { recorded, withdrawn };
pub const Registration = enum { unqualified, enrollment_policy };
pub const BlockedReason = enum { registration_profile_unavailable };
pub const Phase = enum { prepared, callback_consumed, exchange_issued, verifying, active, completion_unknown, quarantined, retired };
pub const Binding = struct {
    transaction_id: [32]u8,
    source_id: [32]u8,
    source_generation: u64 = 1,
    consent_id: [32]u8,
    consent_generation: u64 = 1,
    forget_epoch: u64,
    grant_id: [32]u8,
    expected_grant_generation: u64 = 1,
    consent_expires_at: i64,
    flow_kind: enum { legacy_control, owned_consent } = .legacy_control,
    flow_duration_seconds: u32 = 0,
    flow_admitted_unix: i64 = 0,
    flow_until_nanoseconds: i96 = 0,
    oidc_nonce_digest: [32]u8 = @splat(0),
    host_id: [32]u8 = @splat(0),
    operation_id: [64]u8 = @splat(0),
    operation_id_len: usize = 0,
    registration_profile_sha256: ?[32]u8 = null,
    redirect_uri: [256]u8 = @splat(0),
    redirect_uri_len: usize = 0,
    pub fn redirect(self: *const Binding) []const u8 {
        return self.redirect_uri[0..self.redirect_uri_len];
    }
};
pub const Record = struct {
    binding: Binding,
    aad_version: u32 = 1,
    provider: enum { codex, openai_siwc } = .codex,
    consent_purpose: enum { fresh_codex_oauth_enrollment, fresh_openai_siwc_oauth_enrollment } = .fresh_codex_oauth_enrollment,
    phase: Phase = .prepared,
    consent_status: ConsentStatus = .recorded,
    state_digest: [32]u8,
    challenge: [43]u8,
    // Null is actual unavailable registration authority, never permission.
    registration_profile_sha256: ?[32]u8 = null,
    verifier_capsule: []const u8 = &.{},
    callback_capsule: []const u8 = &.{},
    callback_format: enum { legacy_code, issued_client_bundle } = .legacy_code,
    response_capsule: []const u8 = &.{},
    nonce_capsule: []const u8 = &.{},
};
pub const Snapshot = struct { version: u32 = 1, records: []const Record = &.{} };
/// Private worker lifetime, never serialized, accepted from control, restored
/// after restart, or renewed at callback. It provides no provider permission.
pub const Attempt = struct {
    binding: Binding,
    until: std.Io.Clock.Timestamp,
    callback_state: [32]u8,
    oidc_nonce: [32]u8 = @splat(0),
    pub fn deinit(self: *Attempt) void {
        std.crypto.secureZero(u8, &self.callback_state);
        std.crypto.secureZero(u8, &self.oidc_nonce);
        self.* = undefined;
    }
};
pub const Ledger = struct {
    records: std.ArrayList(Record) = .empty,

    pub fn deinit(self: *Ledger, a: std.mem.Allocator) void {
        for (self.records.items) |*record| clearCapsules(a, record);
        self.records.deinit(a);
        self.* = .{};
    }
    pub fn snapshot(self: *const Ledger) Snapshot {
        return .{ .records = self.records.items };
    }
    pub fn find(self: *Ledger, id: [32]u8) ?*Record {
        for (self.records.items) |*record| if (std.crypto.timing_safe.eql([32]u8, record.binding.transaction_id, id)) return record;
        return null;
    }
    pub fn fromSnapshot(a: std.mem.Allocator, saved: Snapshot) !Ledger {
        try validate(saved);
        var result: Ledger = .{};
        errdefer result.deinit(a);
        try result.records.ensureTotalCapacity(a, saved.records.len);
        for (saved.records) |input| {
            var owned = input;
            owned.verifier_capsule = try a.dupe(u8, input.verifier_capsule);
            errdefer a.free(owned.verifier_capsule);
            owned.callback_capsule = try a.dupe(u8, input.callback_capsule);
            errdefer a.free(owned.callback_capsule);
            owned.response_capsule = try a.dupe(u8, input.response_capsule);
            errdefer a.free(owned.response_capsule);
            owned.nonce_capsule = try a.dupe(u8, input.nonce_capsule);
            result.records.appendAssumeCapacity(owned);
        }
        return result;
    }
    /// Real secure state/verifier generation and encryption precede insertion.
    /// Unavailable key is a separate failure; no key mint/fallback is possible.
    pub fn prepare(self: *Ledger, io: std.Io, a: std.mem.Allocator, key: ?envelope.Key, key_id: []const u8, forget_epoch: u64, now: i64, consent_seconds: u32, until: std.Io.Clock.Timestamp) !Attempt {
        return self.prepareLease(io, a, key, key_id, forget_epoch, now, consent_seconds, until, null);
    }
    /// One explicitly authorized human flow, separate from the control reply.
    /// This factory runs once at prepare; no poll/query/reconnect calls it.
    pub fn prepareFlow(self: *Ledger, io: std.Io, a: std.mem.Allocator, key: ?envelope.Key, key_id: []const u8, forget_epoch: u64, now: i64, consent_seconds: u32, control_until: std.Io.Clock.Timestamp) !Attempt {
        _ = key orelse return error.WrappingKeyUnavailable;
        try deadline(io, control_until);
        if (consent_seconds == 0 or consent_seconds > 3600) return error.InvalidConsent;
        const flow_until: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(consent_seconds) });
        const result = try self.prepareLease(io, a, key, key_id, forget_epoch, now, consent_seconds, flow_until, control_until);
        return result;
    }
    fn prepareLease(self: *Ledger, io: std.Io, a: std.mem.Allocator, key: ?envelope.Key, key_id: []const u8, forget_epoch: u64, now: i64, consent_seconds: u32, until: std.Io.Clock.Timestamp, control_until: ?std.Io.Clock.Timestamp) !Attempt {
        const wrapping = key orelse return error.WrappingKeyUnavailable;
        if (consent_seconds == 0 or consent_seconds > 3600) return error.InvalidConsent;
        if (control_until == null) try deadline(io, until) else if (until.clock != .awake or until.durationFromNow(io).raw.toNanoseconds() <= 0 or until.durationFromNow(io).raw.toNanoseconds() > 3_600_000_000_000) return error.EnrollmentExpired;
        if (self.records.items.len >= max_records) return error.EnrollmentCapacity;
        const expires = std.math.add(i64, now, @as(i64, consent_seconds)) catch return error.InvalidConsent;
        var random: [32 * 6 + 64]u8 = undefined;
        try io.randomSecure(&random);
        defer std.crypto.secureZero(u8, &random);
        var nonce_text: [43]u8 = undefined;
        defer std.crypto.secureZero(u8, &nonce_text);
        _ = std.base64.url_safe_no_pad.Encoder.encode(&nonce_text, random[224..256]);
        var nonce_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&nonce_text, &nonce_digest, .{});
        const binding: Binding = .{ .transaction_id = random[0..32].*, .source_id = random[32..64].*, .consent_id = random[64..96].*, .grant_id = random[96..128].*, .forget_epoch = forget_epoch, .consent_expires_at = expires, .flow_kind = if (control_until != null) .owned_consent else .legacy_control, .flow_duration_seconds = if (control_until != null) consent_seconds else 0, .flow_admitted_unix = if (control_until != null) now else 0, .flow_until_nanoseconds = if (control_until != null) until.raw.nanoseconds else 0, .oidc_nonce_digest = nonce_digest };
        if (self.find(binding.transaction_id) != null) return error.EnrollmentIdCollision;
        var verifier: [86]u8 = undefined;
        defer std.crypto.secureZero(u8, &verifier);
        _ = std.base64.url_safe_no_pad.Encoder.encode(&verifier, random[160..224]);
        var state_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(random[128..160], &state_digest, .{});
        var verifier_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&verifier, &verifier_digest, .{});
        var challenge: [43]u8 = undefined;
        _ = std.base64.url_safe_no_pad.Encoder.encode(&challenge, &verifier_digest);
        const ad = try capsuleContext(a, key_id, binding, 1, "fresh_oauth_pkce_verifier");
        defer a.free(ad.scope);
        const ciphertext = try envelope.seal(io, a, wrapping, ad, &verifier);
        errdefer a.free(ciphertext);
        if (control_until) |reply_until| try deadline(io, reply_until);
        try checkFlow(io, .{ .binding = binding, .until = until, .callback_state = @splat(0) });
        try self.records.append(a, .{ .binding = binding, .state_digest = state_digest, .challenge = challenge, .verifier_capsule = ciphertext });
        // The state belongs only to a future owned callback receiver. Until
        // that receiver/profile exists, no browser URL or raw state is exposed.
        return .{ .binding = binding, .until = until, .callback_state = random[128..160].*, .oidc_nonce = random[224..256].* };
    }
    /// Typed single-use callback primitive. The future actor-owned receiver
    /// must persist this result before exchange. This function never issues IO
    /// or grants, and cannot change the original source/consent/forget tuple.
    pub fn consumeCallback(self: *Ledger, io: std.Io, a: std.mem.Allocator, key: ?envelope.Key, key_id: []const u8, attempt: Attempt, current: Binding, now: i64, state: []const u8, code: []const u8) !void {
        const wrapping = key orelse return error.WrappingKeyUnavailable;
        try checkFlow(io, attempt);
        if (!std.meta.eql(attempt.binding, current) or now >= current.consent_expires_at) return error.EnrollmentAuthorityChanged;
        const record = self.find(current.transaction_id) orelse return error.EnrollmentNotFound;
        if (!std.meta.eql(record.binding, current)) return error.EnrollmentAuthorityChanged;
        if (record.phase != .prepared) return error.CallbackAlreadyConsumed;
        if (state.len != 32 or code.len == 0 or code.len > max_code_bytes) return error.InvalidCallback;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(state, &digest, .{});
        if (!std.crypto.timing_safe.eql([32]u8, record.state_digest, digest)) return error.InvalidCallback;
        const ad = try capsuleContext(a, key_id, current, record.aad_version, "fresh_oauth_callback_code");
        defer a.free(ad.scope);
        const ciphertext = try envelope.seal(io, a, wrapping, ad, code);
        errdefer a.free(ciphertext);
        try checkFlow(io, attempt);
        record.callback_capsule = ciphertext;
        record.phase = .callback_consumed;
    }
    /// Rebind encrypted intent before owned callback work. A profile digest
    /// never constructs registration authority or a provider dispatch ticket.
    pub fn bindForIssue(self: *Ledger, io: std.Io, a: std.mem.Allocator, key: envelope.Key, key_id: []const u8, original: Attempt, operation_id: []const u8, profile_sha: [32]u8, redirect: []const u8, host_id: [32]u8) !Attempt {
        try checkFlow(io, original);
        if (operation_id.len == 0 or operation_id.len > 64 or redirect.len == 0 or redirect.len > 256 or std.mem.allEqual(u8, &profile_sha, 0)) return error.InvalidOAuthEnrollment;
        for (operation_id) |byte| if (!std.ascii.isAlphanumeric(byte) and std.mem.indexOfScalar(u8, "-_.:", byte) == null) return error.InvalidOAuthEnrollment;
        const record = self.find(original.binding.transaction_id) orelse return error.EnrollmentNotFound;
        if (record.phase != .prepared or !std.meta.eql(record.binding, original.binding) or record.registration_profile_sha256 != null) return error.EnrollmentAuthorityChanged;
        var verifier = try openCapsule(a, key, key_id, record.*, .verifier);
        defer verifier.deinit();
        var binding = original.binding;
        binding.operation_id_len = operation_id.len;
        @memcpy(binding.operation_id[0..operation_id.len], operation_id);
        binding.redirect_uri_len = redirect.len;
        @memcpy(binding.redirect_uri[0..redirect.len], redirect);
        binding.registration_profile_sha256 = profile_sha;
        binding.host_id = host_id;
        const ad = try capsuleContext(a, key_id, binding, 2, "fresh_oauth_pkce_verifier");
        defer a.free(ad.scope);
        const encrypted = try envelope.seal(io, a, key, ad, verifier.bytes);
        errdefer a.free(encrypted);
        var nonce: [43]u8 = undefined;
        defer std.crypto.secureZero(u8, &nonce);
        _ = std.base64.url_safe_no_pad.Encoder.encode(&nonce, &original.oidc_nonce);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&nonce, &digest, .{});
        if (!std.crypto.timing_safe.eql([32]u8, digest, binding.oidc_nonce_digest)) return error.EnrollmentAuthorityChanged;
        const nonce_ad = try capsuleContext(a, key_id, binding, 2, "fresh_oauth_oidc_nonce_v1");
        defer a.free(nonce_ad.scope);
        const encrypted_nonce = try envelope.seal(io, a, key, nonce_ad, &nonce);
        errdefer a.free(encrypted_nonce);
        try checkFlow(io, original);
        a.free(record.verifier_capsule);
        record.verifier_capsule = encrypted;
        record.nonce_capsule = encrypted_nonce;
        record.binding = binding;
        record.aad_version = 2;
        record.registration_profile_sha256 = profile_sha;
        var result = original;
        result.binding = binding;
        return result;
    }
    pub fn markIssued(self: *Ledger, a: std.mem.Allocator, binding: Binding) !void {
        const record = self.find(binding.transaction_id) orelse return error.EnrollmentNotFound;
        if (record.phase != .callback_consumed or record.aad_version != 2 or !std.meta.eql(record.binding, binding)) return error.EnrollmentAuthorityChanged;
        clearCapsules(a, record);
        record.phase = .exchange_issued;
    }
    /// New registration callback's issued client is encrypted with its code;
    /// neither callback scope nor client syntax is activation authority.
    pub fn consumeOwnedCallback(self: *Ledger, io: std.Io, a: std.mem.Allocator, key: ?envelope.Key, key_id: []const u8, attempt: Attempt, current: Binding, now: i64, state: []const u8, code: []const u8, client_id: []const u8) !void {
        if (code.len == 0 or code.len > max_code_bytes or !validIssuedClient(client_id) or std.mem.allEqual(u8, &current.oidc_nonce_digest, 0)) return error.InvalidCallback;
        const encoded = try std.json.Stringify.valueAlloc(a, .{ .code = code, .client_id = client_id }, .{});
        defer {
            std.crypto.secureZero(u8, encoded);
            a.free(encoded);
        }
        // Reuse exact state/single-use authority checks before replacing the
        // temporary legacy capsule with the purpose-separated client bundle.
        try self.consumeCallback(io, a, key, key_id, attempt, current, now, state, code);
        const record = self.find(current.transaction_id).?;
        const ad = try capsuleContext(a, key_id, current, record.aad_version, "fresh_oauth_issued_client_callback_v1");
        defer a.free(ad.scope);
        const encrypted = try envelope.seal(io, a, key.?, ad, encoded);
        errdefer a.free(encrypted);
        try checkFlow(io, attempt);
        a.free(record.callback_capsule);
        record.callback_capsule = encrypted;
        record.callback_format = .issued_client_bundle;
    }
    pub fn markUnknown(self: *Ledger, a: std.mem.Allocator, id: [32]u8) !void {
        const record = self.find(id) orelse return error.EnrollmentNotFound;
        if (record.phase != .exchange_issued and record.phase != .completion_unknown and record.phase != .verifying) return error.EnrollmentAuthorityChanged;
        clearCapsules(a, record);
        record.phase = .completion_unknown;
    }
    /// This legacy ledger-only entry point remains unavailable. Owned OSS
    /// issuance requires the separate registered-client dispatcher and proof;
    /// ledger state or a native client literal cannot manufacture that authority.
    pub fn requireIssueAuthority(self: *Ledger, id: [32]u8) !void {
        const record = self.find(id) orelse return error.EnrollmentNotFound;
        if (record.phase == .exchange_issued or record.phase == .verifying or record.phase == .completion_unknown) return error.ExchangeIndeterminate;
        if (record.phase == .active) return error.EnrollmentAlreadyActivated;
        if (record.phase == .retired or record.phase == .quarantined) return error.EnrollmentRetired;
        return error.RegistrationProfileUnavailable;
    }
    pub fn retire(self: *Ledger, a: std.mem.Allocator, id: [32]u8) !void {
        const record = self.find(id) orelse return error.EnrollmentNotFound;
        if (record.phase == .exchange_issued or record.phase == .verifying or record.phase == .completion_unknown) return error.ExchangeIndeterminate;
        if (record.phase == .active) return error.EnrollmentAlreadyActivated;
        clearCapsules(a, record);
        record.phase = .retired;
    }
    /// Separate withdrawal grammar covers issued uncertainty without claiming
    /// provider revocation, an unsent request, or restoration of spent secrets.
    pub fn withdraw(self: *Ledger, a: std.mem.Allocator, id: [32]u8) !void {
        const record = self.find(id) orelse return error.EnrollmentNotFound;
        if (record.consent_status == .withdrawn) return;
        const next = std.math.add(u64, record.binding.consent_generation, 1) catch return error.GenerationExhausted;
        clearCapsules(a, record);
        record.consent_status = .withdrawn;
        record.binding.consent_generation = next;
        record.phase = switch (record.phase) {
            .exchange_issued, .verifying, .completion_unknown => .completion_unknown,
            .prepared, .callback_consumed, .retired => .retired,
            .quarantined => .quarantined,
            .active => .retired,
        };
    }
    pub fn invalidateUnissued(self: *Ledger, a: std.mem.Allocator) void {
        for (self.records.items) |*record| switch (record.phase) {
            .prepared, .callback_consumed => {
                clearCapsules(a, record);
                record.phase = .retired;
            },
            .exchange_issued => {
                clearCapsules(a, record);
                record.phase = .completion_unknown;
            },
            .verifying => {
                clearCapsules(a, record);
                record.phase = .quarantined;
            },
            .active, .completion_unknown, .quarantined, .retired => {},
        };
    }
    /// Actor proves no live callback/ticket/worker references before settlement.
    /// Old identified mutation ACKs remain in their original ledger. Removing a
    /// terminal row grants no issue authority: absent bindings always refuse.
    pub fn settle(self: *Ledger, a: std.mem.Allocator, id: [32]u8, active_pair_transferred: bool) !void {
        for (self.records.items, 0..) |*record, index| if (std.meta.eql(record.binding.transaction_id, id)) {
            switch (record.phase) {
                .retired, .quarantined, .completion_unknown => {},
                .active => if (!active_pair_transferred) return error.EnrollmentAlreadyActivated,
                .prepared, .callback_consumed, .exchange_issued, .verifying => return error.ExchangeIndeterminate,
            }
            clearCapsules(a, record);
            _ = self.records.orderedRemove(index);
            return;
        };
        return error.EnrollmentNotFound;
    }
    pub fn activate(self: *Ledger, a: std.mem.Allocator, binding: Binding) !void {
        const record = self.find(binding.transaction_id) orelse return error.EnrollmentNotFound;
        if (record.phase != .verifying or record.consent_status != .recorded or !std.meta.eql(record.binding, binding)) return error.EnrollmentAuthorityChanged;
        clearCapsules(a, record);
        record.phase = .active;
    }
    pub fn invalidateForForget(self: *Ledger, a: std.mem.Allocator) void {
        self.invalidateUnissued(a);
        for (self.records.items) |*record| if (record.phase != .active) clearCapsules(a, record);
    }
    pub fn recoverAfterRestart(self: *Ledger, a: std.mem.Allocator) void {
        self.invalidateUnissued(a);
    }
};
pub const Capsule = enum { verifier, callback, response, nonce };
pub fn openCapsule(a: std.mem.Allocator, key: envelope.Key, key_id: []const u8, record: Record, kind: Capsule) !envelope.Secret {
    const ad = try capsuleContext(a, key_id, record.binding, record.aad_version, switch (kind) {
        .verifier => "fresh_oauth_pkce_verifier",
        .callback => if (record.callback_format == .issued_client_bundle) "fresh_oauth_issued_client_callback_v1" else "fresh_oauth_callback_code",
        .response => "fresh_oauth_unverified_response_v1",
        .nonce => "fresh_oauth_oidc_nonce_v1",
    });
    defer a.free(ad.scope);
    return envelope.open(a, key, ad, switch (kind) {
        .verifier => record.verifier_capsule,
        .callback => record.callback_capsule,
        .response => record.response_capsule,
        .nonce => record.nonce_capsule,
    });
}
fn clearCapsules(a: std.mem.Allocator, record: *Record) void {
    a.free(record.verifier_capsule);
    a.free(record.callback_capsule);
    a.free(record.response_capsule);
    a.free(record.nonce_capsule);
    record.verifier_capsule = &.{};
    record.callback_capsule = &.{};
    record.response_capsule = &.{};
    record.nonce_capsule = &.{};
}
pub fn validIssuedClient(value: []const u8) bool {
    if (value.len == 0 or value.len > 256 or std.mem.eql(u8, value, "dynamic_agent_client")) return false;
    for (value) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '-') return false;
    return true;
}
pub fn sealUnverifiedResponse(io: std.Io, a: std.mem.Allocator, key: envelope.Key, key_id: []const u8, record: *Record, body: []const u8, until: std.Io.Clock.Timestamp) !void {
    try deadline(io, until);
    if (record.phase != .exchange_issued or record.consent_status != .recorded or body.len == 0 or body.len > 64 * 1024) return error.EnrollmentAuthorityChanged;
    const ad = try capsuleContext(a, key_id, record.binding, record.aad_version, "fresh_oauth_unverified_response_v1");
    defer a.free(ad.scope);
    const encrypted = try envelope.seal(io, a, key, ad, body);
    errdefer a.free(encrypted);
    try deadline(io, until);
    a.free(record.response_capsule);
    record.response_capsule = encrypted;
    record.phase = .quarantined;
}
pub fn checkFlow(io: std.Io, attempt: Attempt) !void {
    if (attempt.binding.flow_kind == .legacy_control) return deadline(io, attempt.until);
    const b = attempt.binding;
    if (b.flow_duration_seconds == 0 or b.flow_duration_seconds > 3600 or b.flow_admitted_unix <= 0 or b.consent_expires_at - b.flow_admitted_unix != b.flow_duration_seconds or attempt.until.clock != .awake or attempt.until.raw.nanoseconds != b.flow_until_nanoseconds) return error.EnrollmentAuthorityChanged;
    const wall = std.Io.Clock.real.now(io).toSeconds();
    const remaining = attempt.until.durationFromNow(io).raw.toNanoseconds();
    if (wall < b.flow_admitted_unix or wall >= b.consent_expires_at or remaining <= 0 or remaining > 3_600_000_000_000) return error.EnrollmentExpired;
}
pub fn exchangeDeadline(io: std.Io, attempt: Attempt) !std.Io.Clock.Timestamp {
    try checkFlow(io, attempt);
    var until: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(120) });
    if (until.raw.nanoseconds > attempt.until.raw.nanoseconds) until = attempt.until;
    return until;
}
fn deadline(io: std.Io, until: std.Io.Clock.Timestamp) !void {
    if (until.clock != .awake) return error.EnrollmentExpired;
    const remaining = until.durationFromNow(io).raw.toNanoseconds();
    if (remaining <= 0 or remaining > 120_000_000_000) return error.EnrollmentExpired;
}
fn capsuleContext(a: std.mem.Allocator, key_id: []const u8, binding: Binding, aad_version: u32, capsule_purpose: []const u8) !envelope.Context {
    // Every retained tuple member is authenticated; profile authority remains
    // absent and cannot be injected into this domain by changing labels.
    const scope = if (aad_version == 1) try std.json.Stringify.valueAlloc(a, .{ .transaction_id = binding.transaction_id, .source_id = binding.source_id, .source_generation = binding.source_generation, .consent_id = binding.consent_id, .consent_generation = binding.consent_generation, .forget_epoch = binding.forget_epoch, .grant_id = binding.grant_id, .expected_grant_generation = binding.expected_grant_generation, .consent_expires_at = binding.consent_expires_at }, .{}) else if (aad_version == 2) try std.json.Stringify.valueAlloc(a, binding, .{}) else return error.InvalidOAuthEnrollment;
    return .{ .key_id = key_id, .account_id = "fresh-oauth-intent", .grant_id = "fresh-oauth-capsule", .generation = binding.consent_generation, .purpose = capsule_purpose, .scope = scope };
}
pub fn validate(saved: Snapshot) !void {
    if (saved.version != 1 or saved.records.len > max_records) return error.InvalidOAuthEnrollment;
    for (saved.records, 0..) |record, index| {
        if (record.binding.source_generation == 0 or record.binding.consent_generation == 0 or record.binding.expected_grant_generation == 0 or record.binding.consent_expires_at <= 0) return error.InvalidOAuthEnrollment;
        if (record.aad_version != 1 and record.aad_version != 2) return error.InvalidOAuthEnrollment;
        if (record.binding.flow_kind == .legacy_control) {
            if (record.binding.flow_duration_seconds != 0 or record.binding.flow_admitted_unix != 0 or record.binding.flow_until_nanoseconds != 0) return error.InvalidOAuthEnrollment;
        } else if (record.binding.flow_duration_seconds == 0 or record.binding.flow_duration_seconds > 3600 or record.binding.flow_admitted_unix <= 0 or record.binding.consent_expires_at - record.binding.flow_admitted_unix != record.binding.flow_duration_seconds or record.binding.flow_until_nanoseconds <= 0) return error.InvalidOAuthEnrollment;
        if ((record.provider == .openai_siwc) != (record.consent_purpose == .fresh_openai_siwc_oauth_enrollment)) return error.InvalidOAuthEnrollment;
        if (record.binding.operation_id_len > 64 or record.binding.redirect_uri_len > 256 or !std.meta.eql(record.registration_profile_sha256, record.binding.registration_profile_sha256)) return error.InvalidOAuthEnrollment;
        if (record.registration_profile_sha256 != null and (record.aad_version != 2 or record.binding.operation_id_len == 0 or record.binding.redirect_uri_len == 0)) return error.InvalidOAuthEnrollment;
        for (saved.records[0..index]) |previous| if (std.meta.eql(previous.binding.transaction_id, record.binding.transaction_id) or std.meta.eql(previous.binding.source_id, record.binding.source_id) or std.meta.eql(previous.binding.consent_id, record.binding.consent_id) or std.meta.eql(previous.binding.grant_id, record.binding.grant_id)) return error.InvalidOAuthEnrollment;
        switch (record.phase) {
            .prepared => if (record.verifier_capsule.len != 134 or record.callback_capsule.len != 0) return error.InvalidOAuthEnrollment,
            .callback_consumed => if (record.verifier_capsule.len != 134 or record.callback_capsule.len < 49 or record.callback_capsule.len > (if (record.callback_format == .legacy_code) @as(usize, max_code_bytes + 48) else 32 * 1024)) return error.InvalidOAuthEnrollment,
            // Issued rows never reconstruct a ticket; the exact Store-backed
            // private constructor must join the original committed transition.
            .exchange_issued, .verifying, .active, .completion_unknown, .quarantined, .retired => if (record.verifier_capsule.len != 0 or record.callback_capsule.len != 0) return error.InvalidOAuthEnrollment,
        }
        if (record.consent_status == .withdrawn and (record.phase == .prepared or record.phase == .callback_consumed or record.phase == .exchange_issued or record.phase == .verifying or record.phase == .active)) return error.InvalidOAuthEnrollment;
        if (record.response_capsule.len > 64 * 1024 + 48 or (record.response_capsule.len != 0 and ((record.phase != .quarantined and record.phase != .verifying) or record.consent_status != .recorded))) return error.InvalidOAuthEnrollment;
        const nonce_pending = record.aad_version == 2 and (record.phase == .prepared or record.phase == .callback_consumed);
        if (record.nonce_capsule.len != (if (nonce_pending) @as(usize, 91) else 0)) return error.InvalidOAuthEnrollment;
    }
}

test "fresh PKCE is real encrypted custody with independent purpose and S256" {
    const a = std.testing.allocator;
    var ledger: Ledger = .{};
    defer ledger.deinit(a);
    const until: std.Io.Clock.Timestamp = .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) });
    try std.testing.expectError(error.WrappingKeyUnavailable, ledger.prepare(std.testing.io, a, null, "fixture-key", 9, 100, 60, until));
    try std.testing.expectEqual(@as(usize, 0), ledger.records.items.len);
    var attempt = try ledger.prepare(std.testing.io, a, @as(envelope.Key, @splat(0x59)), "fixture-key", 9, 100, 60, until);
    defer attempt.deinit();
    const record = ledger.records.items[0];
    try validate(ledger.snapshot());
    const ad = try capsuleContext(a, "fixture-key", record.binding, record.aad_version, "fresh_oauth_pkce_verifier");
    defer a.free(ad.scope);
    var verifier = try envelope.open(a, @as(envelope.Key, @splat(0x59)), ad, record.verifier_capsule);
    defer verifier.deinit();
    try std.testing.expectEqual(@as(usize, 86), verifier.bytes.len);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(verifier.bytes, &digest, .{});
    var challenge: [43]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&challenge, &digest);
    try std.testing.expectEqualSlices(u8, &challenge, &record.challenge);
    var wrong = ad;
    wrong.purpose = "native_access_copy_for_identity_and_request";
    try std.testing.expectError(error.AuthenticationFailed, envelope.open(a, @as(envelope.Key, @splat(0x59)), wrong, record.verifier_capsule));
    const encoded = try std.json.Stringify.valueAlloc(a, ledger.snapshot(), .{});
    defer a.free(encoded);
    try std.testing.expect(std.mem.indexOf(u8, encoded, verifier.bytes) == null);
    try std.testing.expect(record.registration_profile_sha256 == null);
    try std.testing.expectError(error.RegistrationProfileUnavailable, ledger.requireIssueAuthority(attempt.binding.transaction_id));
}

test "callback consumes one encrypted code under exact consent source forget and original cutoff" {
    const a = std.testing.allocator;
    var ledger: Ledger = .{};
    defer ledger.deinit(a);
    const until: std.Io.Clock.Timestamp = .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) });
    var attempt = try ledger.prepare(std.testing.io, a, @as(envelope.Key, @splat(0x59)), "fixture-key", 9, 100, 60, until);
    defer attempt.deinit();
    var changed = attempt.binding;
    changed.forget_epoch += 1;
    try std.testing.expectError(error.EnrollmentAuthorityChanged, ledger.consumeCallback(std.testing.io, a, @as(envelope.Key, @splat(0x59)), "fixture-key", attempt, changed, 101, &attempt.callback_state, "synthetic-callback-code"));
    changed = attempt.binding;
    changed.source_generation += 1;
    try std.testing.expectError(error.EnrollmentAuthorityChanged, ledger.consumeCallback(std.testing.io, a, @as(envelope.Key, @splat(0x59)), "fixture-key", attempt, changed, 101, &attempt.callback_state, "synthetic-callback-code"));
    var wrong_state = attempt.callback_state;
    wrong_state[0] ^= 1;
    try std.testing.expectError(error.InvalidCallback, ledger.consumeCallback(std.testing.io, a, @as(envelope.Key, @splat(0x59)), "fixture-key", attempt, attempt.binding, 101, &wrong_state, "synthetic-callback-code"));
    var expired = attempt;
    expired.until = .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromMilliseconds(-1) });
    try std.testing.expectError(error.EnrollmentExpired, ledger.consumeCallback(std.testing.io, a, @as(envelope.Key, @splat(0x59)), "fixture-key", expired, attempt.binding, 101, &attempt.callback_state, "synthetic-callback-code"));
    try std.testing.expectEqual(Phase.prepared, ledger.records.items[0].phase);
    try ledger.consumeCallback(std.testing.io, a, @as(envelope.Key, @splat(0x59)), "fixture-key", attempt, attempt.binding, 101, &attempt.callback_state, "synthetic-callback-code");
    try std.testing.expectEqual(Phase.callback_consumed, ledger.records.items[0].phase);
    try std.testing.expectError(error.CallbackAlreadyConsumed, ledger.consumeCallback(std.testing.io, a, @as(envelope.Key, @splat(0x59)), "fixture-key", attempt, attempt.binding, 101, &attempt.callback_state, "synthetic-callback-code"));
    try std.testing.expectError(error.RegistrationProfileUnavailable, ledger.requireIssueAuthority(attempt.binding.transaction_id));
    const ad = try capsuleContext(a, "fixture-key", attempt.binding, ledger.records.items[0].aad_version, "fresh_oauth_callback_code");
    defer a.free(ad.scope);
    var code = try envelope.open(a, @as(envelope.Key, @splat(0x59)), ad, ledger.records.items[0].callback_capsule);
    defer code.deinit();
    try std.testing.expectEqualSlices(u8, "synthetic-callback-code", code.bytes);
    try ledger.retire(a, attempt.binding.transaction_id);
    try validate(ledger.snapshot());
    try std.testing.expectEqual(@as(usize, 0), ledger.records.items[0].verifier_capsule.len);
    try std.testing.expectEqual(@as(usize, 0), ledger.records.items[0].callback_capsule.len);
    try std.testing.expectError(error.EnrollmentRetired, ledger.requireIssueAuthority(attempt.binding.transaction_id));
}

test "restart never reconstructs callback lease or replayable issued work" {
    const a = std.testing.allocator;
    var ledger: Ledger = .{};
    defer ledger.deinit(a);
    var attempt = try ledger.prepare(std.testing.io, a, @as(envelope.Key, @splat(0x59)), "fixture-key", 9, 100, 60, .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(2) }));
    defer attempt.deinit();
    var restored = try Ledger.fromSnapshot(a, ledger.snapshot());
    defer restored.deinit(a);
    restored.recoverAfterRestart(a);
    try std.testing.expectEqual(Phase.retired, restored.records.items[0].phase);
    try std.testing.expectEqual(Phase.prepared, ledger.records.items[0].phase);
    // Model a historical issued diagnostic fence, not an issue producer or
    // successful dispatch. No production constructor can make an issue permit.
    clearCapsules(a, &ledger.records.items[0]);
    ledger.records.items[0].phase = .exchange_issued;
    try validate(ledger.snapshot());
    var interrupted = try Ledger.fromSnapshot(a, ledger.snapshot());
    defer interrupted.deinit(a);
    interrupted.recoverAfterRestart(a);
    try std.testing.expectEqual(Phase.completion_unknown, interrupted.records.items[0].phase);
    try std.testing.expectError(error.ExchangeIndeterminate, interrupted.requireIssueAuthority(attempt.binding.transaction_id));
    try std.testing.expectError(error.ExchangeIndeterminate, interrupted.retire(a, attempt.binding.transaction_id));
}

test "finite admission and failed allocation leave no callback or issue authority" {
    const a = std.testing.allocator;
    var ledger: Ledger = .{};
    defer ledger.deinit(a);
    const until: std.Io.Clock.Timestamp = .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromSeconds(5) });
    for (0..max_records) |_| {
        var attempt = try ledger.prepare(std.testing.io, a, @as(envelope.Key, @splat(0x59)), "fixture-key", 9, 100, 60, until);
        attempt.deinit();
    }
    try std.testing.expectError(error.EnrollmentCapacity, ledger.prepare(std.testing.io, a, @as(envelope.Key, @splat(0x59)), "fixture-key", 9, 100, 60, until));
    try validate(ledger.snapshot());
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, Ledger.fromSnapshot(failing.allocator(), ledger.snapshot()));
    try std.testing.expectEqual(@as(usize, max_records), ledger.records.items.len);
    const encoded = try std.json.Stringify.valueAlloc(a, ledger.snapshot(), .{});
    defer a.free(encoded);
    try std.testing.expect(encoded.len < maximum_snapshot_bytes);
    for (ledger.records.items) |record| try std.testing.expectError(error.RegistrationProfileUnavailable, ledger.requireIssueAuthority(record.binding.transaction_id));
}

test "owned nonce and callback client have separate ciphertext and withdrawal advances consent once without restoring issued capsules" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const key: envelope.Key = @splat(0x46);
    var ledger: Ledger = .{};
    defer ledger.deinit(a);
    var original = try ledger.prepare(io, a, key, "fixture-owned-root", 0, std.Io.Clock.real.now(io).toSeconds(), 60, .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(5) }));
    defer original.deinit();
    var bound = try ledger.bindForIssue(io, a, key, "fixture-owned-root", original, "fixture-owned-operation", @splat(0x53), "http://127.0.0.1:54321/auth/callback", @splat(0x27));
    defer bound.deinit();
    var nonce = try openCapsule(a, key, "fixture-owned-root", ledger.records.items[0], .nonce);
    defer nonce.deinit();
    var nonce_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(nonce.bytes, &nonce_hash, .{});
    try std.testing.expectEqualSlices(u8, &bound.binding.oidc_nonce_digest, &nonce_hash);
    try std.testing.expectError(error.InvalidCallback, ledger.consumeOwnedCallback(io, a, key, "fixture-owned-root", bound, bound.binding, std.Io.Clock.real.now(io).toSeconds(), &bound.callback_state, "synthetic-owned-code", "dynamic_agent_client"));
    try std.testing.expectEqual(Phase.prepared, ledger.records.items[0].phase);
    try ledger.consumeOwnedCallback(io, a, key, "fixture-owned-root", bound, bound.binding, std.Io.Clock.real.now(io).toSeconds(), &bound.callback_state, "synthetic-owned-code", "oaiapp_synthetic_owned_client");
    var bundle = try openCapsule(a, key, "fixture-owned-root", ledger.records.items[0], .callback);
    defer bundle.deinit();
    try std.testing.expect(std.mem.indexOf(u8, bundle.bytes, "oaiapp_synthetic_owned_client") != null);
    try std.testing.expectError(error.CallbackAlreadyConsumed, ledger.consumeOwnedCallback(io, a, key, "fixture-owned-root", bound, bound.binding, std.Io.Clock.real.now(io).toSeconds(), &bound.callback_state, "synthetic-owned-code", "oaiapp_synthetic_owned_client"));
    try ledger.markIssued(a, bound.binding);
    try std.testing.expectEqual(@as(usize, 0), ledger.records.items[0].nonce_capsule.len);
    try std.testing.expectError(error.ExchangeIndeterminate, ledger.retire(a, bound.binding.transaction_id));
    try ledger.withdraw(a, bound.binding.transaction_id);
    try ledger.withdraw(a, bound.binding.transaction_id);
    try std.testing.expectEqual(@as(u64, 2), ledger.records.items[0].binding.consent_generation);
    try std.testing.expectEqual(Phase.completion_unknown, ledger.records.items[0].phase);
    try std.testing.expectEqual(@as(usize, 0), ledger.records.items[0].callback_capsule.len);
    try validate(ledger.snapshot());
}

test "owned human flow is minted once independently of short control RPC and caps one exchange budget" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var ledger: Ledger = .{};
    defer ledger.deinit(a);
    const reply_until: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(1) });
    var attempt = try ledger.prepareFlow(io, a, @as(envelope.Key, @splat(0x61)), "synthetic-flow-key", 0, std.Io.Clock.real.now(io).toSeconds(), 900, reply_until);
    defer attempt.deinit();
    const original = attempt.until;
    try io.sleep(.fromMilliseconds(1100), .awake);
    try std.testing.expect(reply_until.durationFromNow(io).raw.toNanoseconds() <= 0);
    try checkFlow(io, attempt);
    const exchange = try exchangeDeadline(io, attempt);
    try std.testing.expect(exchange.raw.nanoseconds <= original.raw.nanoseconds);
    try std.testing.expect(exchange.durationFromNow(io).raw.toNanoseconds() <= 120_000_000_000);
    try std.testing.expect(std.meta.eql(original, attempt.until));
    var forged = attempt;
    forged.until = .fromNow(io, .{ .clock = .awake, .raw = .fromSeconds(901) });
    try std.testing.expectError(error.EnrollmentAuthorityChanged, checkFlow(io, forged));
    // Actual consent expiry remains a separate wall fence, even while awake
    // work remains. No restart reconstruction or caller tuple can extend it.
    forged = attempt;
    forged.binding.flow_admitted_unix -= 901;
    forged.binding.consent_expires_at -= 901;
    try std.testing.expectError(error.EnrollmentExpired, checkFlow(io, forged));
    try ledger.withdraw(a, attempt.binding.transaction_id);
    try std.testing.expectEqual(Phase.retired, ledger.records.items[0].phase);
    try std.testing.expectEqual(@as(usize, 0), ledger.records.items[0].verifier_capsule.len);
}
