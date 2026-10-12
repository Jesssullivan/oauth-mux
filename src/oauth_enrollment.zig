//! Daemon-owned fresh OAuth intent and encrypted PKCE custody. This ledger
//! cannot authorize provider IO or activate a grant. A native client literal,
//! new code or authenticated account identity is not registration/family proof.
//! The actor commits every transition before any dependent effect. No callback
//! listener, qualified profile producer or exchange dispatcher exists here.
const std = @import("std");
const envelope = @import("envelope.zig");

pub const max_records = 16;
pub const max_code_bytes = 4096;
pub const maximum_snapshot_bytes = 512 * 1024;
pub const purpose = "fresh_codex_oauth_enrollment";
pub const Registration = enum { unqualified };
pub const BlockedReason = enum { registration_profile_unavailable };
pub const Phase = enum { prepared, callback_consumed, exchange_issued, completion_unknown, quarantined, retired };
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
};
pub const Record = struct {
    binding: Binding,
    provider: enum { codex } = .codex,
    consent_purpose: enum { fresh_codex_oauth_enrollment } = .fresh_codex_oauth_enrollment,
    phase: Phase = .prepared,
    state_digest: [32]u8,
    challenge: [43]u8,
    // Null is actual unavailable registration authority, never permission.
    registration_profile_sha256: ?[32]u8 = null,
    verifier_capsule: []const u8 = &.{},
    callback_capsule: []const u8 = &.{},
};
pub const Snapshot = struct { version: u32 = 1, records: []const Record = &.{} };
/// Private worker lifetime, never serialized, accepted from control, restored
/// after restart, or renewed at callback. It provides no provider permission.
pub const Attempt = struct {
    binding: Binding, until: std.Io.Clock.Timestamp, callback_state: [32]u8,
    pub fn deinit(self: *Attempt) void { std.crypto.secureZero(u8, &self.callback_state); self.* = undefined; }
};
pub const Ledger = struct {
    records: std.ArrayList(Record) = .empty,

    pub fn deinit(self: *Ledger, a: std.mem.Allocator) void {
        for (self.records.items) |*record| clearCapsules(a, record);
        self.records.deinit(a);
        self.* = .{};
    }
    pub fn snapshot(self: *const Ledger) Snapshot { return .{ .records = self.records.items }; }
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
            result.records.appendAssumeCapacity(owned);
        }
        return result;
    }
    /// Real secure state/verifier generation and encryption precede insertion.
    /// Unavailable key is a separate failure; no key mint/fallback is possible.
    pub fn prepare(self: *Ledger, io: std.Io, a: std.mem.Allocator, key: ?envelope.Key, key_id: []const u8, forget_epoch: u64, now: i64, consent_seconds: u32, until: std.Io.Clock.Timestamp) !Attempt {
        const wrapping = key orelse return error.WrappingKeyUnavailable;
        if (consent_seconds == 0 or consent_seconds > 3600) return error.InvalidConsent;
        try deadline(io, until);
        if (self.records.items.len >= max_records) return error.EnrollmentCapacity;
        const expires = std.math.add(i64, now, @as(i64, consent_seconds)) catch return error.InvalidConsent;
        var random: [32 * 5 + 64]u8 = undefined;
        try io.randomSecure(&random);
        defer std.crypto.secureZero(u8, &random);
        const binding: Binding = .{ .transaction_id = random[0..32].*, .source_id = random[32..64].*, .consent_id = random[64..96].*, .grant_id = random[96..128].*, .forget_epoch = forget_epoch, .consent_expires_at = expires };
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
        const ad = try capsuleContext(a, key_id, binding, "fresh_oauth_pkce_verifier");
        defer a.free(ad.scope);
        const ciphertext = try envelope.seal(io, a, wrapping, ad, &verifier);
        errdefer a.free(ciphertext);
        try deadline(io, until);
        try self.records.append(a, .{ .binding = binding, .state_digest = state_digest, .challenge = challenge, .verifier_capsule = ciphertext });
        // The state belongs only to a future owned callback receiver. Until
        // that receiver/profile exists, no browser URL or raw state is exposed.
        return .{ .binding = binding, .until = until, .callback_state = random[128..160].* };
    }
    /// Typed single-use callback primitive. The future actor-owned receiver
    /// must persist this result before exchange. This function never issues IO
    /// or grants, and cannot change the original source/consent/forget tuple.
    pub fn consumeCallback(self: *Ledger, io: std.Io, a: std.mem.Allocator, key: ?envelope.Key, key_id: []const u8, attempt: Attempt, current: Binding, now: i64, state: []const u8, code: []const u8) !void {
        const wrapping = key orelse return error.WrappingKeyUnavailable;
        try deadline(io, attempt.until);
        if (!std.meta.eql(attempt.binding, current) or now >= current.consent_expires_at) return error.EnrollmentAuthorityChanged;
        const record = self.find(current.transaction_id) orelse return error.EnrollmentNotFound;
        if (!std.meta.eql(record.binding, current)) return error.EnrollmentAuthorityChanged;
        if (record.phase != .prepared) return error.CallbackAlreadyConsumed;
        if (state.len != 32 or code.len == 0 or code.len > max_code_bytes) return error.InvalidCallback;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(state, &digest, .{});
        if (!std.crypto.timing_safe.eql([32]u8, record.state_digest, digest)) return error.InvalidCallback;
        const ad = try capsuleContext(a, key_id, current, "fresh_oauth_callback_code");
        defer a.free(ad.scope);
        const ciphertext = try envelope.seal(io, a, wrapping, ad, code);
        errdefer a.free(ciphertext);
        try deadline(io, attempt.until);
        record.callback_capsule = ciphertext;
        record.phase = .callback_consumed;
    }
    /// No qualified registration constructor/dispatcher exists yet. Keep this
    /// exact failure separate from wrapping custody or accepted provider work.
    pub fn requireIssueAuthority(self: *Ledger, id: [32]u8) !void {
        const record = self.find(id) orelse return error.EnrollmentNotFound;
        if (record.phase == .exchange_issued or record.phase == .completion_unknown) return error.ExchangeIndeterminate;
        if (record.phase == .retired or record.phase == .quarantined) return error.EnrollmentRetired;
        return error.RegistrationProfileUnavailable;
    }
    pub fn retire(self: *Ledger, a: std.mem.Allocator, id: [32]u8) !void {
        const record = self.find(id) orelse return error.EnrollmentNotFound;
        if (record.phase == .exchange_issued or record.phase == .completion_unknown) return error.ExchangeIndeterminate;
        clearCapsules(a, record);
        record.phase = .retired;
    }
    pub fn invalidateUnissued(self: *Ledger, a: std.mem.Allocator) void {
        for (self.records.items) |*record| switch (record.phase) {
            .prepared, .callback_consumed => { clearCapsules(a, record); record.phase = .retired; },
            .exchange_issued => { clearCapsules(a, record); record.phase = .completion_unknown; },
            .completion_unknown, .quarantined, .retired => {},
        };
    }
    pub fn recoverAfterRestart(self: *Ledger, a: std.mem.Allocator) void { self.invalidateUnissued(a); }
};
fn clearCapsules(a: std.mem.Allocator, record: *Record) void {
    a.free(record.verifier_capsule);
    a.free(record.callback_capsule);
    record.verifier_capsule = &.{};
    record.callback_capsule = &.{};
}
fn deadline(io: std.Io, until: std.Io.Clock.Timestamp) !void {
    if (until.clock != .awake) return error.EnrollmentExpired;
    const remaining = until.durationFromNow(io).raw.toNanoseconds();
    if (remaining <= 0 or remaining > 120_000_000_000) return error.EnrollmentExpired;
}
fn capsuleContext(a: std.mem.Allocator, key_id: []const u8, binding: Binding, capsule_purpose: []const u8) !envelope.Context {
    // Every retained tuple member is authenticated; profile authority remains
    // absent and cannot be injected into this domain by changing labels.
    const scope = try std.json.Stringify.valueAlloc(a, binding, .{});
    return .{ .key_id = key_id, .account_id = "fresh-oauth-intent", .grant_id = "fresh-oauth-capsule", .generation = binding.consent_generation, .purpose = capsule_purpose, .scope = scope };
}
pub fn validate(saved: Snapshot) !void {
    if (saved.version != 1 or saved.records.len > max_records) return error.InvalidOAuthEnrollment;
    for (saved.records, 0..) |record, index| {
        if (record.binding.source_generation == 0 or record.binding.consent_generation == 0 or record.binding.expected_grant_generation == 0 or record.binding.consent_expires_at <= 0 or record.registration_profile_sha256 != null) return error.InvalidOAuthEnrollment;
        for (saved.records[0..index]) |previous| if (std.meta.eql(previous.binding.transaction_id, record.binding.transaction_id) or std.meta.eql(previous.binding.source_id, record.binding.source_id) or std.meta.eql(previous.binding.consent_id, record.binding.consent_id) or std.meta.eql(previous.binding.grant_id, record.binding.grant_id)) return error.InvalidOAuthEnrollment;
        switch (record.phase) {
            .prepared => if (record.verifier_capsule.len != 134 or record.callback_capsule.len != 0) return error.InvalidOAuthEnrollment,
            .callback_consumed => if (record.verifier_capsule.len != 134 or record.callback_capsule.len < 49 or record.callback_capsule.len > max_code_bytes + 48) return error.InvalidOAuthEnrollment,
            // Historical issued rows are non-replayable diagnostic fences;
            // this implementation has no constructor which issues one.
            .exchange_issued, .completion_unknown, .quarantined, .retired => if (record.verifier_capsule.len != 0 or record.callback_capsule.len != 0) return error.InvalidOAuthEnrollment,
        }
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
    const ad = try capsuleContext(a, "fixture-key", record.binding, "fresh_oauth_pkce_verifier");
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
    const ad = try capsuleContext(a, "fixture-key", attempt.binding, "fresh_oauth_callback_code");
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
