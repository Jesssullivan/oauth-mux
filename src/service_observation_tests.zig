const std = @import("std");
const observation = @import("service_observation.zig");
const evidence = @import("setup_evidence.zig");
const onboarding = @import("onboarding.zig");
const matching: observation.Raw = .{ .unit_identity = 1, .fragment_binding = 1, .responder_pid = 1, .no_dropins = 1, .persistent_enabled = 1, .active = 1, .no_reload = 1 };
const verified: observation.Expectation = .{ .selection = .default, .definition = .matches, .running_executable = .matches };

test "manager enabled state alone never proves login activation" {
    const result = try observation.project(matching, verified);
    try std.testing.expectEqual(evidence.Probe.matches, result.service.definition);
    try std.testing.expectEqual(evidence.Probe.matches, result.service.instance_binding);
    try std.testing.expectEqual(evidence.Probe.matches, result.service.responder_binding);
    try std.testing.expectEqual(evidence.Probe.unknown, result.service.login_enabled);
    const projected = evidence.project(.{}, result.service);
    try std.testing.expectEqual(onboarding.State.unknown, projected.service.state);
}

test "unit responder fragment and dropin mismatches remain independent" {
    var raw = matching;
    raw.unit_identity = 2;
    var result = try observation.project(raw, verified);
    try std.testing.expectEqual(evidence.Probe.differs, result.service.instance_binding);
    try std.testing.expectEqual(evidence.Probe.matches, result.service.responder_binding);
    raw = matching;
    raw.responder_pid = 2;
    result = try observation.project(raw, verified);
    try std.testing.expectEqual(evidence.Probe.differs, result.service.responder_binding);
    raw = matching;
    raw.fragment_binding = 2;
    result = try observation.project(raw, verified);
    try std.testing.expectEqual(evidence.Probe.differs, result.service.definition);
    raw = matching;
    raw.no_dropins = 2;
    result = try observation.project(raw, verified);
    try std.testing.expectEqual(evidence.Probe.differs, result.service.definition);
    raw = matching;
    raw.no_reload = 2;
    result = try observation.project(raw, verified);
    try std.testing.expectEqual(evidence.Probe.differs, result.service.definition);
}

test "missing foreign and timedout bus observations are unknown not ready" {
    for ([_]observation.Status{ .unavailable, .unsafe_bus, .timeout, .unsupported }) |status| {
        var raw = matching;
        raw.status = @backingInt(status);
        const result = try observation.project(raw, verified);
        try std.testing.expectEqual(evidence.Probe.unknown, result.service.responder_binding);
        try std.testing.expectEqual(onboarding.Freshness.unknown, result.service.freshness);
    }
    var malformed = matching;
    malformed.responder_pid = 999;
    try std.testing.expectError(error.InvalidObservation, observation.project(malformed, verified));
}

test "channel names and unverified definitions fail closed" {
    try std.testing.expectEqualStrings("ai.xoxd.omux.service", observation.unitName(.default));
    try std.testing.expectEqualStrings("ai.xoxd.omux.dev.service", observation.unitName(.dev));
    var expected = verified;
    expected.definition = .unknown;
    expected.running_executable = .unknown;
    const result = try observation.project(matching, expected);
    try std.testing.expectEqual(evidence.Probe.unknown, result.service.definition);
    try std.testing.expectEqual(evidence.Probe.unknown, result.service.responder_binding);
    expected = verified;
    expected.login_link = .matches;
    const linked = try observation.project(matching, expected);
    try std.testing.expectEqual(evidence.Probe.matches, linked.service.login_enabled);
}
