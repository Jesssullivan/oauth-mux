//! Read-only Linux service-manager diagnostics. Only digest-verified collector
//! evidence may supply definition/executable/link matches to this projection.
//! Observing a unit never starts, enables, reloads or changes it.
const std = @import("std");
const builtin = @import("builtin");
const instance = @import("instance.zig");
const evidence = @import("setup_evidence.zig");
const paths = @import("paths.zig");

pub const Status = enum(u32) { ok, unsupported, unavailable, unsafe_bus, timeout, invalid };
pub const Raw = extern struct {
    status: u32 = 0,
    unit_identity: u32 = 0,
    fragment_binding: u32 = 0,
    responder_pid: u32 = 0,
    no_dropins: u32 = 0,
    persistent_enabled: u32 = 0,
    active: u32 = 0,
    no_reload: u32 = 0,
};
extern fn omux_service_observe(runtime_dir: [*:0]const u8, unit: [*:0]const u8, expected_fragment: [*:0]const u8, timeout_ms: u32, out: *Raw) c_int;

pub const Expectation = struct {
    selection: instance.Selection,
    definition: evidence.Probe = .unknown,
    running_executable: evidence.Probe = .unknown,
    /// An independently verified persistent default.target.wants link to the
    /// same definition. A manager's "enabled" string alone is insufficient.
    login_link: evidence.Probe = .unknown,
};
pub const Result = struct {
    service: evidence.Service = .{},
    status: Status = .unavailable,
    persistent_enabled: evidence.Probe = .unknown,
};
pub const Options = struct {
    runtime_dir: [:0]const u8,
    expected_fragment: [:0]const u8,
    expected: Expectation,
    timeout_ms: u32 = 2000,
};
pub fn unitName(selection: instance.Selection) [:0]const u8 {
    return if (selection == .dev) "ai.xoxd.omux.dev.service" else "ai.xoxd.omux.service";
}

/// Unknown installation custody is never promoted by service-manager replies.
/// The explicit local runtime selector is checked again in the native bridge;
/// no ambient session-bus address or shell command is used.
pub fn observe(options: Options) !Result {
    if (builtin.os.tag != .linux) return .{ .status = .unsupported };
    if (options.expected.definition != .matches or options.expected.running_executable != .matches) return .{};
    try paths.validateAbsolute(options.runtime_dir);
    try paths.validateAbsolute(options.expected_fragment);
    if (options.runtime_dir.len > 4096 or options.expected_fragment.len > 4096) return error.InvalidSelection;
    var raw: Raw = .{};
    _ = omux_service_observe(options.runtime_dir, unitName(options.expected.selection), options.expected_fragment, @min(@max(options.timeout_ms, 1), 2000), &raw);
    return project(raw, options.expected);
}

fn probe(value: u32) !evidence.Probe {
    return switch (value) {
        0 => .unknown,
        1 => .matches,
        2 => .differs,
        3 => .absent,
        else => error.InvalidObservation,
    };
}
fn conjunction(values: []const evidence.Probe) evidence.Probe {
    var missing = false;
    var unknown = false;
    for (values) |value| switch (value) {
        .differs => return .differs,
        .absent => {
            missing = true;
        },
        .unknown => {
            unknown = true;
        },
        .matches => {},
    };
    return if (missing) .absent else if (unknown) .unknown else .matches;
}

/// Projection is credential-free; it retains only typed matches and failures.
/// It does not expose a PID, bus owner, executable pathname or unit environment.
pub fn project(raw: Raw, expected: Expectation) !Result {
    const status = std.enums.fromInt(Status, raw.status) orelse return error.InvalidObservation;
    if (status != .ok) return .{ .status = status };
    const unit = try probe(raw.unit_identity);
    const fragment = try probe(raw.fragment_binding);
    const process = try probe(raw.responder_pid);
    const drops = try probe(raw.no_dropins);
    const persistent = try probe(raw.persistent_enabled);
    const active = try probe(raw.active);
    const reload = try probe(raw.no_reload);
    return .{
        .status = .ok,
        .persistent_enabled = persistent,
        .service = .{
            .definition = conjunction(&.{ expected.definition, fragment, drops, reload }),
            .instance_binding = conjunction(&.{ expected.definition, unit, fragment, drops, reload }),
            .responder_binding = conjunction(&.{ expected.running_executable, process, active }),
            .login_enabled = conjunction(&.{ persistent, expected.login_link }),
            .freshness = .current,
        },
    };
}
