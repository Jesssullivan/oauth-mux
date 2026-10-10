//! Pure source-consent/admission fences. No transport, paths or credentials.
//! Trusted caller must obtain fresh peer/context evidence; saved witnesses are
//! equality fences only. This module cannot materialize native credentials.
const std = @import("std");
const peer = @import("platform/peer.zig");

pub const Handle = [32]u8;
pub const Owner = struct {
    id: Handle,
    nonce: Handle,
    endpoint_generation: u64,
    witness: peer.Witness,
    pub fn validate(self: Owner) !void {
        try validHandle(self.id);
        try validHandle(self.nonce);
        if (self.endpoint_generation == 0) return error.InvalidNativeSourceAuthority;
        try self.witness.validate();
    }
    pub fn same(self: Owner, other: Owner) bool {
        return equal(self.id, other.id) and equal(self.nonce, other.nonce) and
            self.endpoint_generation == other.endpoint_generation and self.witness.sameOriginal(other.witness);
    }
};
pub const Context = struct {
    id: Handle,
    generation: u64,
    pub fn validate(self: Context) !void {
        try validHandle(self.id);
        if (self.generation == 0) return error.InvalidNativeSourceAuthority;
    }
    pub fn same(self: Context, other: Context) bool {
        return equal(self.id, other.id) and self.generation == other.generation;
    }
};
// Current native protocol has no stable home-origin attestation. Accordingly a
// consent scope binds the exact original owner, never an endpoint-derived path.
// A new owner requires new consent until a separately qualified stable origin
// descriptor protocol can correlate it to an already authorized source.
pub const Consent = struct {
    id: Handle,
    generation: u64,
    source_id: Handle,
    source_generation: u64,
    owner: Owner,
    expires_at: i64,
    // Explicit read/copy authority is distinct from read-only metadata access.
    purpose: enum { native_access_copy_for_identity_and_request },
    allow_reenrollment: bool = false,
    forget_epoch: u64,
    pub fn validate(self: Consent) !void {
        try validHandle(self.id);
        try validHandle(self.source_id);
        try self.owner.validate();
        if (self.generation == 0 or self.source_generation == 0) return error.InvalidNativeSourceAuthority;
    }
};
pub const Current = struct {
    source_id: Handle,
    source_generation: u64,
    status: enum { connected, detached, disconnected },
    consent: ?Consent,
    owner: Owner,
    context: Context,
    store_present: bool,
    forget_epoch: u64,
};
// Value-only fence; never a credential or authorization transferable to an
// untrusted client. Store in the daemon-owned pending operation, not wire input.
pub const Admission = struct {
    source_id: Handle,
    source_generation: u64,
    consent_id: Handle,
    consent_generation: u64,
    owner: Owner,
    context: Context,
    forget_epoch: u64,
    allow_reenrollment: bool,
    // Original process-local monotonic cutoff; never persisted/reconstructed.
    cutoff: u64,
};

pub fn admit(current: Current, now_wall: i64, now_monotonic: u64, cutoff: u64) !Admission {
    try current.owner.validate();
    try current.context.validate();
    const consent = try authorized(current, now_wall);
    if (!current.store_present) return error.NativeSourceUnavailable;
    if (now_monotonic >= cutoff) return error.NativeSourceDeadline;
    return .{ .source_id = current.source_id, .source_generation = current.source_generation,
        .consent_id = consent.id, .consent_generation = consent.generation,
        .owner = current.owner, .context = current.context, .forget_epoch = current.forget_epoch,
        .allow_reenrollment = consent.allow_reenrollment, .cutoff = cutoff };
}
// Called before materialization, after descriptor receipt, and immediately
// before adopting a verified identity/credential. Current must be fresh evidence
// from the trusted adapter, never an initial hint or cached declaration alone.
pub fn check(admission: Admission, current: Current, now_wall: i64, now_monotonic: u64) !void {
    const consent = try authorized(current, now_wall);
    try current.owner.validate();
    try current.context.validate();
    if (!equal(admission.source_id, current.source_id) or admission.source_generation != current.source_generation or
        !equal(admission.consent_id, consent.id) or admission.consent_generation != consent.generation)
        return error.NativeSourceSuperseded;
    if (!admission.owner.same(current.owner)) return error.NativeSourceOwnerChanged;
    if (!admission.context.same(current.context)) return error.NativeSourceContextChanged;
    if (!current.store_present) return error.NativeSourceUnavailable;
    if (admission.forget_epoch != current.forget_epoch or admission.allow_reenrollment != consent.allow_reenrollment)
        return error.NativeSourceSuperseded;
    if (now_monotonic >= admission.cutoff) return error.NativeSourceDeadline;
}
// The missing native descriptor protocol must create this binding from the
// actual authenticated FD response, not from JSON metadata or client parameters.
// Matching it proves tuple equality only, not descriptor/content authenticity.
pub const MaterializedBinding = struct { owner: Owner, context: Context };
pub fn checkMaterialized(admission: Admission, current: Current, received: MaterializedBinding,
    now_wall: i64, now_monotonic: u64) !void {
    try check(admission, current, now_wall, now_monotonic);
    if (!admission.owner.same(received.owner)) return error.NativeSourceOwnerChanged;
    if (!admission.context.same(received.context)) return error.NativeSourceContextChanged;
}
// Provider identity verification and domain tombstone checks remain mandatory.
// This check fences explicit re-enrollment against forget after admission.
pub fn checkEnrollment(admission: Admission, current: Current, tombstoned: bool,
    now_wall: i64, now_monotonic: u64) !void {
    try check(admission, current, now_wall, now_monotonic);
    if (tombstoned and !admission.allow_reenrollment) return error.NativeSourceTombstoned;
}
fn authorized(current: Current, now_wall: i64) !Consent {
    try validHandle(current.source_id);
    if (current.status != .connected or current.source_generation == 0) return error.NativeSourceUnauthorized;
    const consent = current.consent orelse return error.NativeSourceConsentRequired;
    try consent.validate();
    if (!equal(consent.source_id, current.source_id) or consent.source_generation != current.source_generation or
        !consent.owner.same(current.owner) or consent.forget_epoch != current.forget_epoch or consent.expires_at <= now_wall)
        return error.NativeSourceUnauthorized;
    return consent;
}
fn validHandle(value: Handle) !void {
    if (std.mem.allEqual(u8, &value, 0)) return error.InvalidNativeSourceAuthority;
}
fn equal(a: Handle, b: Handle) bool { return std.mem.eql(u8, &a, &b); }
