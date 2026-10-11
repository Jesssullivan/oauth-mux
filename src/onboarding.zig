//! Shared redacted setup model for CLI and native controls. Pure observations
//! and plans: evaluating readiness never installs files or activates services.
pub const Channel = enum { unknown, development, release };
pub const Ownership = enum { unknown, home_manager, installation_receipt };
pub const Evidence = enum { unobserved, diagnostic, synthetic, native_conformance, live };
pub const Freshness = enum { unknown, current, stale };
pub const State = enum { unknown, ready, missing, pending, incompatible, locked, key_lost, expired, browser_required, unsupported, unverified };
pub const Observation = struct {
    state: State = .unknown,
    freshness: Freshness = .unknown,
    evidence: Evidence = .unobserved,
};
pub const Phase = enum { artifact, service, vault, source, identity, grant, native };
pub const Snapshot = struct {
    expected_channel: Channel = .unknown,
    installed_channel: Channel = .unknown,
    ownership: Ownership = .unknown,
    artifact: Observation = .{},
    service: Observation = .{},
    vault: Observation = .{},
    source: Observation = .{},
    identity: Observation = .{},
    grant: Observation = .{},
    native: Observation = .{},
};
pub const Reason = enum {
    ready,
    observation_unknown,
    observation_stale,
    evidence_unobserved,
    synthetic_only,
    native_evidence_missing,
    channel_unknown,
    channel_mismatch,
    missing,
    pending,
    incompatible,
    vault_locked,
    vault_key_lost,
    authority_expired,
    browser_required,
    native_unsupported,
};
pub const Action = enum {
    none,
    refresh_observation,
    verify_installed_artifact,
    select_matching_channel,
    install_artifact,
    activate_service,
    unlock_vault,
    preserve_and_offer_fresh_enrollment,
    connect_source,
    verify_identity,
    enroll_usable_authority,
    maintain_authority,
    reconnect_browser,
    install_native_adapter,
    verify_native_capability,
    inspect_compatibility,
};
pub const Finding = struct { phase: Phase, reason: Reason, action: Action };
pub const Readiness = struct {
    schema_version: u32 = 1,
    ready: bool = false,
    /// Seven independent phase results; a channel failure belongs to artifact.
    findings: [7]Finding,
    /// Operational readiness is never a seamless-handoff or release proof.
    seamless_handoff_proven: bool = false,
};

pub fn assess(snapshot: Snapshot) Readiness {
    const observations = [_]Observation{ snapshot.artifact, snapshot.service, snapshot.vault, snapshot.source, snapshot.identity, snapshot.grant, snapshot.native };
    const phases = [_]Phase{ .artifact, .service, .vault, .source, .identity, .grant, .native };
    var result: Readiness = .{ .findings = undefined, .ready = true };
    for (observations, phases, 0..) |observation, phase, index| {
        result.findings[index] = finding(phase, observation);
    }
    // Channel qualification cannot erase observed payload failure, stale
    // evidence, or an active refresh. It adds a fence after artifact readiness.
    if (result.findings[0].reason == .ready) {
        if (snapshot.expected_channel == .unknown or snapshot.installed_channel == .unknown) {
            result.findings[0] = .{ .phase = .artifact, .reason = .channel_unknown, .action = .verify_installed_artifact };
        } else if (snapshot.expected_channel != snapshot.installed_channel) {
            result.findings[0] = .{ .phase = .artifact, .reason = .channel_mismatch, .action = .select_matching_channel };
        }
    }
    for (result.findings) |item| {
        if (item.reason != .ready) result.ready = false;
    }
    return result;
}

fn finding(phase: Phase, observation: Observation) Finding {
    // Lost-key guidance must remain visible even if its observation is stale.
    if (phase == .vault and observation.state == .key_lost) return .{ .phase = phase, .reason = .vault_key_lost, .action = .preserve_and_offer_fresh_enrollment };
    const reason: Reason = switch (observation.freshness) {
        .unknown => .observation_unknown,
        .stale => .observation_stale,
        .current => switch (observation.state) {
            .unknown => .observation_unknown,
            .missing => .missing,
            .pending => .pending,
            .incompatible => .incompatible,
            .locked => .vault_locked,
            .key_lost => .vault_key_lost,
            .expired => .authority_expired,
            .browser_required => .browser_required,
            .unsupported => .native_unsupported,
            .unverified => if (phase == .native) .native_evidence_missing else .evidence_unobserved,
            .ready => switch (observation.evidence) {
                .unobserved => .evidence_unobserved,
                .synthetic => .synthetic_only,
                .diagnostic => if (phase == .native) .native_evidence_missing else .ready,
                .native_conformance, .live => .ready,
            },
        },
    };
    const action: Action = switch (reason) {
        .ready => .none,
        .observation_unknown, .observation_stale, .evidence_unobserved, .synthetic_only => .refresh_observation,
        .native_evidence_missing => .verify_native_capability,
        .channel_unknown => .verify_installed_artifact,
        .channel_mismatch => .select_matching_channel,
        .missing, .pending => switch (phase) {
            .artifact => .install_artifact,
            .service => .activate_service,
            .vault => .unlock_vault,
            .source => .connect_source,
            .identity => .verify_identity,
            .grant => .enroll_usable_authority,
            .native => .install_native_adapter,
        },
        .incompatible => .inspect_compatibility,
        .vault_locked => .unlock_vault,
        .vault_key_lost => .preserve_and_offer_fresh_enrollment,
        .authority_expired => .maintain_authority,
        .browser_required => .reconnect_browser,
        .native_unsupported => .install_native_adapter,
    };
    return .{ .phase = phase, .reason = reason, .action = action };
}

pub const SetupTarget = enum { artifact, service_definition, browser_host_registration, native_adapter };
pub const SetupAction = enum { inspect_ownership, home_manager_change, receipt_install };
pub const SetupPlan = struct {
    target: SetupTarget,
    action: SetupAction,
    /// Plans are instructions, never evidence of successful activation.
    activation_observed: bool = false,
    overwrite_declarative_files: bool = false,
};
pub fn planSetup(ownership: Ownership, target: SetupTarget) SetupPlan {
    return .{ .target = target, .action = switch (ownership) {
        .unknown => .inspect_ownership,
        .home_manager => .home_manager_change,
        .installation_receipt => .receipt_install,
    } };
}
