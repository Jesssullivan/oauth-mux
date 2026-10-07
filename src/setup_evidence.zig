//! Bounded redacted projection of read-only installation probes. Collectors
//! must compare bytes/ownership against receipts or immutable Nix derivations;
//! path names, environment variables and a live RPC alone are not attestations.
const onboarding = @import("onboarding.zig");

pub const Probe = enum { unknown, absent, matches, differs };
pub const Artifact = struct {
    channel: onboarding.Channel = .unknown,
    ownership: onboarding.Ownership = .unknown,
    /// All declared runtime components, not just the responder executable.
    payload: Probe = .unknown,
    running_executable: Probe = .unknown,
    ownership_record: Probe = .unknown,
    freshness: onboarding.Freshness = .unknown,
};
pub const Service = struct {
    definition: Probe = .unknown,
    instance_binding: Probe = .unknown,
    login_enabled: Probe = .unknown,
    /// OS service-manager PID matches authenticated responder PID/executable.
    responder_binding: Probe = .unknown,
    freshness: onboarding.Freshness = .unknown,
};
pub const Result = struct {
    installed_channel: onboarding.Channel,
    ownership: onboarding.Ownership,
    artifact: onboarding.Observation,
    service: onboarding.Observation,
};

pub fn project(artifact: Artifact, service: Service) Result {
    const ownership_verified = artifact.ownership_record == .matches and artifact.freshness == .current;
    return .{
        .installed_channel = if (ownership_verified and artifact.payload == .matches and artifact.running_executable == .matches) artifact.channel else .unknown,
        .ownership = if (ownership_verified) artifact.ownership else .unknown,
        .artifact = observation(artifact.freshness, &.{ artifact.payload, artifact.running_executable, artifact.ownership_record }),
        .service = observation(service.freshness, &.{ service.definition, service.instance_binding, service.login_enabled, service.responder_binding }),
    };
}

fn observation(freshness: onboarding.Freshness, probes: []const Probe) onboarding.Observation {
    var absent = false;
    var differs = false;
    var unknown = false;
    for (probes) |probe| switch (probe) {
        .unknown => {
            unknown = true;
        },
        .absent => {
            absent = true;
        },
        .differs => {
            differs = true;
        },
        .matches => {},
    };
    return .{
        .state = if (differs) .incompatible else if (absent) .missing else if (unknown) .unknown else .ready,
        .freshness = freshness,
        .evidence = if (freshness == .current and !unknown) .diagnostic else .unobserved,
    };
}

/// Adds only independently collected installation observations; account and
/// native capability observations remain daemon/application-owned.
pub fn apply(snapshot: *onboarding.Snapshot, result: Result) void {
    snapshot.installed_channel = result.installed_channel;
    snapshot.ownership = result.ownership;
    snapshot.artifact = result.artifact;
    snapshot.service = result.service;
}
