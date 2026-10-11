const std = @import("std");
const model = @import("onboarding.zig");

fn observed() model.Snapshot {
    const runtime: model.Observation = .{ .state = .ready, .freshness = .current, .evidence = .diagnostic };
    return .{ .expected_channel = .development, .installed_channel = .development, .ownership = .home_manager, .artifact = runtime, .service = runtime, .vault = runtime, .source = runtime, .identity = runtime, .grant = runtime, .native = .{ .state = .ready, .freshness = .current, .evidence = .native_conformance } };
}

test "installation and service never imply verified identity usable grant or native capability" {
    var snapshot = observed();
    snapshot.identity = .{};
    snapshot.grant = .{};
    snapshot.native = .{};
    const result = model.assess(snapshot);
    try std.testing.expect(!result.ready);
    try std.testing.expectEqual(model.Reason.ready, result.findings[0].reason);
    try std.testing.expectEqual(model.Reason.observation_unknown, result.findings[4].reason);
    try std.testing.expectEqual(model.Reason.observation_unknown, result.findings[5].reason);
    try std.testing.expectEqual(model.Reason.observation_unknown, result.findings[6].reason);
}

test "stale synthetic and wrong channel observations cannot become readiness" {
    var snapshot = observed();
    try std.testing.expect(model.assess(snapshot).ready);
    try std.testing.expect(!model.assess(snapshot).seamless_handoff_proven);
    snapshot.service.freshness = .stale;
    snapshot.grant.evidence = .synthetic;
    snapshot.installed_channel = .release;
    const result = model.assess(snapshot);
    try std.testing.expect(!result.ready);
    try std.testing.expectEqual(model.Reason.channel_mismatch, result.findings[0].reason);
    try std.testing.expectEqual(model.Reason.observation_stale, result.findings[1].reason);
    try std.testing.expectEqual(model.Reason.synthetic_only, result.findings[5].reason);
}

test "declarative and unknown ownership cannot plan overwrites or report activation" {
    inline for (.{ model.SetupTarget.artifact, .service_definition, .browser_host_registration, .native_adapter }) |target| {
        const managed = model.planSetup(.home_manager, target);
        try std.testing.expectEqual(model.SetupAction.home_manager_change, managed.action);
        try std.testing.expect(!managed.overwrite_declarative_files);
        try std.testing.expect(!managed.activation_observed);
        try std.testing.expectEqual(model.SetupAction.inspect_ownership, model.planSetup(.unknown, target).action);
    }
}

test "key loss preserves failed custody and offers separate explicit enrollment" {
    var snapshot = observed();
    snapshot.vault = .{ .state = .key_lost, .freshness = .stale };
    const result = model.assess(snapshot);
    try std.testing.expect(!result.ready);
    try std.testing.expectEqual(model.Action.preserve_and_offer_fresh_enrollment, result.findings[2].action);
}

test "diagnostic native observation lacks version-bound conformance" {
    var snapshot = observed();
    snapshot.native.evidence = .diagnostic;
    try std.testing.expectEqual(model.Reason.native_evidence_missing, model.assess(snapshot).findings[6].reason);
}

test "configured but unverified native capability cannot be promoted by evidence labels" {
    var snapshot = observed();
    snapshot.native.state = .unverified;
    inline for (.{ model.Evidence.unobserved, .diagnostic, .synthetic, .native_conformance, .live }) |evidence| {
        snapshot.native.evidence = evidence;
        const result = model.assess(snapshot);
        try std.testing.expect(!result.ready);
        try std.testing.expect(!result.seamless_handoff_proven);
        try std.testing.expectEqual(model.Reason.native_evidence_missing, result.findings[6].reason);
        try std.testing.expectEqual(model.Action.verify_native_capability, result.findings[6].action);
    }
    snapshot.native.freshness = .stale;
    try std.testing.expectEqual(model.Reason.observation_stale, model.assess(snapshot).findings[6].reason);
}

test "channel diagnostics cannot hide observed artifact failure or pending refresh" {
    var snapshot = observed();
    snapshot.installed_channel = .unknown;
    snapshot.artifact.state = .incompatible;
    var result = model.assess(snapshot);
    try std.testing.expect(!result.ready);
    try std.testing.expectEqual(model.Reason.incompatible, result.findings[0].reason);
    try std.testing.expectEqual(model.Action.inspect_compatibility, result.findings[0].action);
    snapshot.artifact.state = .pending;
    result = model.assess(snapshot);
    try std.testing.expect(!result.ready);
    try std.testing.expectEqual(model.Reason.pending, result.findings[0].reason);
    snapshot.artifact.state = .missing;
    result = model.assess(snapshot);
    try std.testing.expectEqual(model.Reason.missing, result.findings[0].reason);
    try std.testing.expectEqual(model.Action.install_artifact, result.findings[0].action);
}

test "stale artifact observation takes precedence over channel mismatch" {
    var snapshot = observed();
    snapshot.installed_channel = .release;
    snapshot.artifact.freshness = .stale;
    const result = model.assess(snapshot);
    try std.testing.expect(!result.ready);
    try std.testing.expectEqual(model.Reason.observation_stale, result.findings[0].reason);
    try std.testing.expectEqual(model.Action.refresh_observation, result.findings[0].action);
}

test "otherwise ready artifacts still require a known matching channel" {
    var snapshot = observed();
    snapshot.installed_channel = .unknown;
    var result = model.assess(snapshot);
    try std.testing.expect(!result.ready);
    try std.testing.expectEqual(model.Reason.channel_unknown, result.findings[0].reason);
    snapshot.installed_channel = .release;
    result = model.assess(snapshot);
    try std.testing.expect(!result.ready);
    try std.testing.expectEqual(model.Reason.channel_mismatch, result.findings[0].reason);
    snapshot.installed_channel = .development;
    try std.testing.expect(model.assess(snapshot).ready);
    snapshot.expected_channel = .unknown;
    result = model.assess(snapshot);
    try std.testing.expect(!result.ready);
    try std.testing.expectEqual(model.Reason.channel_unknown, result.findings[0].reason);
}


test "retained unavailable vault diagnoses give restoration guidance without asserting permanent loss or unlock" {
    const cases = [_]struct { state: model.State, reason: model.Reason, action: model.Action }{
        .{ .state = .key_unavailable, .reason = .vault_key_unavailable, .action = .restore_original_vault_key },
        .{ .state = .access_denied, .reason = .vault_access_denied, .action = .restore_vault_access },
        .{ .state = .unavailable, .reason = .vault_unavailable, .action = .restore_vault_access },
    };
    for (cases) |selected| {
        var snapshot = observed();
        snapshot.vault = .{ .state = selected.state, .freshness = .stale, .evidence = .diagnostic };
        const result = model.assess(snapshot);
        try std.testing.expect(!result.ready and !result.seamless_handoff_proven);
        try std.testing.expectEqual(selected.reason, result.findings[2].reason);
        try std.testing.expectEqual(selected.action, result.findings[2].action);
    }
    var locked = observed();
    locked.vault = .{ .state = .locked, .freshness = .stale, .evidence = .diagnostic };
    try std.testing.expectEqual(model.Reason.observation_stale, model.assess(locked).findings[2].reason);
}
