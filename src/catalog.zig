//! Source authority for adapter support and generated documentation.
//! A declared hook, unit test, or credential parser never establishes live
//! application continuity. Capability promotions require versioned evidence.
const std = @import("std");

pub const Proof = enum { declared, implemented, synthetic_proven, live_proven };
pub const Capability = struct {
    name: []const u8,
    proof: Proof,
    limitation: []const u8,
};
pub const Adapter = struct {
    id: []const u8,
    display_name: []const u8,
    status: []const u8 = "prototype",
    summary: []const u8,
    normal_launch: bool,
    capabilities: []const Capability,
    native_reference: []const u8,
};

pub const adapters = [_]Adapter{
    .{ .id = "codex", .display_name = "Codex", .summary = "Omux-developed Codex authentication adapter is experimental; live same-process continuity remains unproved.", .normal_launch = true, .native_reference = "https://github.com/openai/codex/tree/00c972ed5d6ff6499317fd41b7f23605b8e6850d/codex-rs/app-server", .capabilities = &.{
        .{ .name = "native_capability_handshake", .proof = .implemented, .limitation = "Bounded read-only authenticated owner V2 Unix packet inspection uses the selected native context; a manual explicit endpoint remains a compatibility override. Legacy WebSocket inspection confers no custody. Installed automatic discovery, ordinary TUI/resume and live continuity require separate proof; stock Codex without the hook reports native_unsupported." },
        .{ .name = "per_thread_request_handoff", .proof = .synthetic_proven, .limitation = "Local Bazel state-machine fixtures pass for portable native context; opaque account-bound items fail closed. Live version-bound native-hook evidence is still required." },
        .{ .name = "late_session_attachment", .proof = .implemented, .limitation = "Requires the compatible native per-thread hook and portable context; live continuity remains unproven. Removal retains custody until reachable native threads acknowledge safe detach." },
        .{ .name = "refresh_ownership_transfer", .proof = .declared, .limitation = "Native writer must acknowledge retirement before Omux adopts refresh authority." },
    } },
    .{ .id = "git", .display_name = "Git HTTPS", .summary = "Scoped Git credential-helper boundary; no live remote-account proof.", .normal_launch = true, .native_reference = "https://git-scm.com/docs/gitcredentials", .capabilities = &.{
        .{ .name = "credential_helper", .proof = .implemented, .limitation = "Uses native get/store/erase boundaries; only declared HTTPS contexts are eligible." },
        .{ .name = "scoped_materialization", .proof = .synthetic_proven, .limitation = "Local Bazel host/path/user isolation fixtures pass; live remote-account permissions are still unproven." },
        .{ .name = "in_request_recovery", .proof = .declared, .limitation = "A helper invocation is the safe boundary; no upload or accepted HTTP request is replayed." },
    } },
    .{ .id = "claude", .display_name = "Claude Code", .summary = "Claude reversible configuration foundation; no live request-proxy proof.", .normal_launch = true, .native_reference = "https://code.claude.com/docs/en/settings", .capabilities = &.{
        .{ .name = "persistent_endpoint_configuration", .proof = .implemented, .limitation = "Reversible settings edits are implemented; an authenticated managed request proxy is required before activation." },
        .{ .name = "managed_request_handoff", .proof = .declared, .limitation = "No live proxy/refresh-ownership proof; configuration support alone is not seamless continuity." },
        .{ .name = "existing_process_attachment", .proof = .declared, .limitation = "Existing processes do not reload startup environment routing; requires a native hook." },
    } },
};

pub fn find(id: []const u8) ?*const Adapter {
    for (&adapters) |*adapter| if (std.mem.eql(u8, adapter.id, id)) return adapter;
    return null;
}

pub fn json(allocator: std.mem.Allocator) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, .{ .schema_version = @as(u32, 1), .adapters = adapters }, .{ .whitespace = .indent_2 });
}

test "catalog never claims live proof from synthetic tests" {
    for (adapters) |adapter| for (adapter.capabilities) |capability| {
        try std.testing.expect(capability.proof != .live_proven);
        try std.testing.expect(capability.limitation.len > 0);
    };
    try std.testing.expect(find("codex") != null);
    try std.testing.expect(find("unsupported") == null);
}
