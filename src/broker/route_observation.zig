//! Typed route/model observation projection for the shared broker core.
//!
//! This module does not interpret provider payloads. It projects already-typed
//! reactive and advisory observations by delegating to
//! `quota/advisory_usage.elect`, preserving that landed core's precedence and
//! asymmetric staleness rules as the single source of truth.

const std = @import("std");
const advisory_usage = @import("../quota/advisory_usage.zig");
const model_demand = @import("model_demand.zig");
const broker_types = @import("types.zig");

pub const ExactModel = model_demand.ExactModel;
pub const Readiness = advisory_usage.Readiness;

/// Reuse the landed quota provenance lattice rather than defining a broker-local
/// copy. Direct request evidence is `.proven`, advisory evidence is `.inferred`,
/// and absent/expired evidence is `.unobserved`.
pub const EvidenceProvenance = advisory_usage.Provenance;

/// Reuse the active managed-harness surface-v2 route handle. It borrows opaque
/// validated ASCII bytes and requires no adapter-local interning table.
pub const RouteHandle = broker_types.RouteHandle;

/// Borrowed stable identity-hash evidence already produced by the existing
/// identity admission path. It is a redacted hash/opaque identifier, never an
/// account label, email, provider payload, or credential.
pub const IdentityEvidence = struct {
    bytes: []const u8,

    pub fn fromBorrowed(bytes: []const u8) IdentityEvidence {
        return .{ .bytes = bytes };
    }

    pub fn eql(self: IdentityEvidence, other: IdentityEvidence) bool {
        return std.mem.eql(u8, self.bytes, other.bytes);
    }

    pub fn isValid(self: IdentityEvidence) bool {
        return self.bytes.len > 0;
    }
};

/// Admission truth independent of quota readiness. An admitted route still
/// requires a non-null identity, and duplicate identities fail closed in the
/// decision reducer.
pub const RouteAdmission = enum {
    admitted,
    identity_conflict,
    dead,
    unavailable,
};

/// Typed observations for one route's exact-model capability. All source
/// parsing, provider mapping, and capture happens before this boundary.
pub const RouteObservation = struct {
    route: RouteHandle,
    identity: ?IdentityEvidence,
    exact_model: ExactModel,
    admission: RouteAdmission,
    advisory: ?advisory_usage.Advisory = null,
    reactive: ?advisory_usage.Reactive = null,
};

/// Query-time route view consumed by the deterministic decision reducer.
pub const RouteEvidence = struct {
    route: RouteHandle,
    identity: ?IdentityEvidence,
    exact_model: ExactModel,
    admission: RouteAdmission,
    readiness: Readiness,
    provenance: EvidenceProvenance,
    resets_at_s: ?i64,
};

/// Project one observation at an injected instant. Temporal semantics and
/// evidence precedence live exclusively in `advisory_usage.elect`.
pub fn project(observation: RouteObservation, now_s: i64) RouteEvidence {
    const elected = advisory_usage.elect(
        observation.advisory,
        observation.reactive,
        now_s,
    );
    return .{
        .route = observation.route,
        .identity = observation.identity,
        .exact_model = observation.exact_model,
        .admission = observation.admission,
        .readiness = elected.readiness,
        .provenance = elected.provenance,
        .resets_at_s = elected.resets_at_s,
    };
}

test {
    std.testing.refAllDeclsRecursive(@This());
}

fn makeObservation(
    advisory: ?advisory_usage.Advisory,
    reactive: ?advisory_usage.Reactive,
) RouteObservation {
    return .{
        .route = RouteHandle.parse("route-11") catch unreachable,
        .identity = IdentityEvidence.fromBorrowed("identity-22"),
        .exact_model = ExactModel.init("model-33") catch unreachable,
        .admission = .admitted,
        .advisory = advisory,
        .reactive = reactive,
    };
}

test "projection delegates every readiness combination to landed election" {
    const readiness_values = std.meta.tags(Readiness);
    const instants = [_]i64{ 99, 100, 101 };

    for (readiness_values) |advisory_readiness| {
        for (readiness_values) |reactive_readiness| {
            for (instants) |now_s| {
                const advisory: advisory_usage.Advisory = .{
                    .readiness = advisory_readiness,
                    .resets_at_s = 100,
                };
                const reactive: advisory_usage.Reactive = .{
                    .readiness = reactive_readiness,
                    .resets_at_s = 100,
                };
                const expected = advisory_usage.elect(advisory, reactive, now_s);
                const actual = project(makeObservation(advisory, reactive), now_s);
                try std.testing.expectEqual(expected.readiness, actual.readiness);
                try std.testing.expectEqual(expected.provenance, actual.provenance);
                try std.testing.expectEqual(expected.resets_at_s, actual.resets_at_s);
            }
        }
    }
}

test "reactive evidence outranks advisory and expiry falls through" {
    const advisory: advisory_usage.Advisory = .{
        .readiness = .exhausted,
        .resets_at_s = 200,
    };
    const reactive: advisory_usage.Reactive = .{
        .readiness = .available,
        .resets_at_s = 100,
    };

    const before_deadline = project(makeObservation(advisory, reactive), 99);
    try std.testing.expectEqual(Readiness.available, before_deadline.readiness);
    try std.testing.expectEqual(EvidenceProvenance.proven, before_deadline.provenance);
    try std.testing.expectEqual(@as(?i64, null), before_deadline.resets_at_s);

    const at_deadline = project(makeObservation(advisory, reactive), 100);
    try std.testing.expectEqual(Readiness.exhausted, at_deadline.readiness);
    try std.testing.expectEqual(EvidenceProvenance.inferred, at_deadline.provenance);
    try std.testing.expectEqual(@as(?i64, 200), at_deadline.resets_at_s);
}

test "availability and exhaustion expire to unknown at their exact boundary" {
    inline for (.{ Readiness.available, Readiness.exhausted }) |readiness| {
        const reactive: advisory_usage.Reactive = .{
            .readiness = readiness,
            .resets_at_s = 100,
        };

        const before = project(makeObservation(null, reactive), 99);
        try std.testing.expectEqual(readiness, before.readiness);
        try std.testing.expectEqual(EvidenceProvenance.proven, before.provenance);

        const boundary = project(makeObservation(null, reactive), 100);
        try std.testing.expectEqual(Readiness.unknown, boundary.readiness);
        try std.testing.expectEqual(EvidenceProvenance.unobserved, boundary.provenance);
        try std.testing.expectEqual(@as(?i64, null), boundary.resets_at_s);
    }
}

test "projection preserves opaque route identity model and admission exactly" {
    const input: RouteObservation = .{
        .route = try RouteHandle.parse("route-Zz09_-"),
        .identity = IdentityEvidence.fromBorrowed("identity-zero"),
        .exact_model = try ExactModel.init("model/abc"),
        .admission = .identity_conflict,
    };
    const actual = project(input, std.math.minInt(i64));
    try std.testing.expectEqualStrings(input.route.text, actual.route.text);
    try std.testing.expectEqualStrings(input.identity.?.bytes, actual.identity.?.bytes);
    try std.testing.expectEqualStrings(input.exact_model.bytes(), actual.exact_model.bytes());
    try std.testing.expectEqual(input.admission, actual.admission);
    try std.testing.expectEqual(Readiness.unknown, actual.readiness);
    try std.testing.expectEqual(EvidenceProvenance.unobserved, actual.provenance);
}

fn projectAdvisoryBeforeReactive(observation: RouteObservation, now_s: i64) RouteEvidence {
    const elected = advisory_usage.elect(observation.advisory, null, now_s);
    return .{
        .route = observation.route,
        .identity = observation.identity,
        .exact_model = observation.exact_model,
        .admission = observation.admission,
        .readiness = elected.readiness,
        .provenance = elected.provenance,
        .resets_at_s = elected.resets_at_s,
    };
}

test "negative control: advisory-first projection loses reactive precedence" {
    const observation = makeObservation(
        .{ .readiness = .available, .resets_at_s = 200 },
        .{ .readiness = .exhausted, .resets_at_s = 300 },
    );

    const actual = project(observation, 100);
    const broken = projectAdvisoryBeforeReactive(observation, 100);
    try std.testing.expectEqual(Readiness.exhausted, actual.readiness);
    try std.testing.expectEqual(EvidenceProvenance.proven, actual.provenance);
    try std.testing.expectEqual(Readiness.available, broken.readiness);
    try std.testing.expectEqual(EvidenceProvenance.inferred, broken.provenance);
}
