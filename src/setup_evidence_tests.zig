const std = @import("std");
const evidence = @import("setup_evidence.zig");
const onboarding = @import("onboarding.zig");

fn installed() evidence.Artifact {
    return .{ .channel = .development, .ownership = .home_manager, .payload = .matches, .running_executable = .matches, .ownership_record = .matches, .freshness = .current };
}
fn activated() evidence.Service {
    return .{ .definition = .matches, .instance_binding = .matches, .login_enabled = .matches, .responder_binding = .matches, .freshness = .current };
}

test "running daemon alone cannot establish installed resident service" {
    const result = evidence.project(installed(), .{ .responder_binding = .matches, .freshness = .current });
    try std.testing.expectEqual(onboarding.State.ready, result.artifact.state);
    try std.testing.expectEqual(onboarding.State.unknown, result.service.state);
}
test "modified artifact or wrong service binding denies installed readiness" {
    var artifact = installed();
    artifact.payload = .differs;
    var service = activated();
    service.instance_binding = .differs;
    const result = evidence.project(artifact, service);
    try std.testing.expectEqual(onboarding.Channel.unknown, result.installed_channel);
    try std.testing.expectEqual(onboarding.State.incompatible, result.artifact.state);
    try std.testing.expectEqual(onboarding.State.incompatible, result.service.state);
}
test "stale ownership cannot authorize installer or claim channel" {
    var artifact = installed();
    artifact.freshness = .stale;
    const result = evidence.project(artifact, activated());
    try std.testing.expectEqual(onboarding.Ownership.unknown, result.ownership);
    try std.testing.expectEqual(onboarding.Channel.unknown, result.installed_channel);
    try std.testing.expectEqual(onboarding.SetupAction.inspect_ownership, onboarding.planSetup(result.ownership, .artifact).action);
}
test "installation proof never changes account or native capability results" {
    var snapshot: onboarding.Snapshot = .{ .expected_channel = .development };
    evidence.apply(&snapshot, evidence.project(installed(), activated()));
    const result = onboarding.assess(snapshot);
    try std.testing.expectEqual(onboarding.Reason.ready, result.findings[0].reason);
    try std.testing.expectEqual(onboarding.Reason.ready, result.findings[1].reason);
    try std.testing.expectEqual(onboarding.Reason.observation_unknown, result.findings[6].reason);
    try std.testing.expect(!result.ready);
}
