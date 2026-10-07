//! Public documentation is a projection of implemented source catalogs.
//! An integration declaration never promotes synthetic proof to live support.
const std = @import("std");
const product = @import("product.zig");
const catalog = @import("catalog.zig");
const control = @import("control.zig");

pub const Cli = struct { name: []const u8, summary: []const u8, usage: []const u8 };
pub const cli = [_]Cli{
    .{ .name = "daemon", .summary = "Run the per-user lifecycle daemon; UI closure does not stop it.", .usage = "omux daemon" },
    .{ .name = "status", .summary = "Inspect redacted lifecycle and service metadata.", .usage = "omux status" },
    .{ .name = "accounts", .summary = "Inspect enrolled identities and independent account lifecycle.", .usage = "omux accounts" },
    .{ .name = "sources", .summary = "Inspect authorized native, OAuth, browser and explicit sources.", .usage = "omux sources" },
    .{ .name = "usage", .summary = "Inspect resource observations without mixing incompatible quotas.", .usage = "omux usage" },
    .{ .name = "setup", .summary = "Inspect ownership-aware setup plans without altering managed files.", .usage = "omux setup" },
    .{ .name = "readiness", .summary = "Inspect seven independent readiness phases; this does not establish seamless handoff.", .usage = "omux readiness" },
    .{ .name = "application-readiness", .summary = "Read selected application and optional caller-declared demand JSON from stdin; report independent source, identity, authority, renewal and capacity diagnostics without provider access or a launch/support claim.", .usage = "omux application-readiness -" },
    .{ .name = "setup evidence", .summary = "Read cached installation probes and freshness without provider access.", .usage = "omux setup evidence" },
    .{ .name = "setup refresh", .summary = "Refresh bounded diagnostic probes without recording a durable operation.", .usage = "omux setup refresh" },
    .{ .name = "setup verify", .summary = "Record identified readiness verification; query operation.status with the returned operation ID. Completion does not establish installation, enrollment or handoff.", .usage = "omux setup verify" },
    .{ .name = "source connect", .summary = "Authorize an account source using JSON on stdin before provider identity verification.", .usage = "omux source connect -" },
    .{ .name = "source disconnect", .summary = "End source authorization, invalidate its grants and delete their retained secrets.", .usage = "omux source disconnect <opaque-source-id>" },
    .{ .name = "source reconcile", .summary = "Request reconciliation of an authorized source.", .usage = "omux source reconcile <opaque-source-id>" },
    .{ .name = "account", .summary = "Apply distinct pause, resume, drain or forget lifecycle actions.", .usage = "omux account <pause|resume|drain|forget> <opaque-account-id>" },
    .{ .name = "repair", .summary = "Reconcile an account's authorized sources and inspect readiness without restoring spent credentials.", .usage = "omux repair <opaque-account-id>" },
    .{ .name = "enroll", .summary = "Verify a supported provider credential received as JSON on stdin.", .usage = "omux enroll <opaque-source-id>" },
    .{ .name = "integration status", .summary = "Inspect native integration readiness and proof limitations.", .usage = "omux integration status" },
    .{ .name = "integration install", .summary = "Install a reversible integration after proving its prerequisites.", .usage = "omux integration install <adapter> [config-path]" },
    .{ .name = "integration discover", .summary = "Inspect bounded authenticated native owner inventory in the selected integration context; hook compatibility is experimental, not native support.", .usage = "omux integration discover [codex [config-path]]" },
    .{ .name = "integration attach", .summary = "An owner endpoint is required; use stdin RPC integrations.attach or native controls with the selected owner tuple. This typed command cannot select a process automatically.", .usage = "omux integration attach <adapter> [thread-id]" },
    .{ .name = "integration detach", .summary = "A committed native_ref and owner endpoint are required; use stdin RPC integrations.detach or native controls. This typed command cannot derive attachment authority.", .usage = "omux integration detach <adapter> [thread-id]" },
    .{ .name = "integration remove", .summary = "Restore owned integration settings while preserving later edits.", .usage = "omux integration remove <adapter>" },
    .{ .name = "rpc", .summary = "Invoke an implemented control method using a JSON request on stdin.", .usage = "omux rpc <method> -" },
    .{ .name = "native-host", .summary = "Run the browser native-messaging conduit.", .usage = "omux native-host" },
    .{ .name = "git-credential", .summary = "Handle a native Git credential-helper operation.", .usage = "omux git-credential <get|store|erase>" },
    .{ .name = "reference", .summary = "Emit this versioned source-derived documentation bundle.", .usage = "omux reference" },
    .{ .name = "--version", .summary = "Inspect the experimental successor version.", .usage = "omux --version" },
};

pub fn commandHelp(allocator: std.mem.Allocator) ![]u8 {
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    try output.appendSlice(allocator, "Omux — per-user account continuity (experimental)\nUsage: omux [--state-dir <absolute-path>] <command>\n");
    for (cli) |command| {
        try output.appendSlice(allocator, "  ");
        try output.appendSlice(allocator, command.usage["omux ".len..]);
        try output.appendSlice(allocator, "\n    ");
        try output.appendSlice(allocator, command.summary);
        try output.appendSlice(allocator, "\n");
    }
    try output.appendSlice(allocator, "\nApplications do not require an Omux launch wrapper.\n" ++
        "Candidate ordinary launch/resume and live handoff still require separate proof.\n" ++
        "Discovery is read-only; hook_compatible is experimental and native_support remains false.\n" ++
        "Credentials belong on stdin; never place them in argv.\n" ++
        "Daemon startup requires available OS-vault custody.\n" ++
        "Integration status reports missing native hooks and live proof.\n");
    return output.toOwnedSlice(allocator);
}

const Download = struct { target: []const u8, url: []const u8 };
const stable_base = product.repository ++ "/releases/download/v" ++ product.stable_version;
const stable_downloads = [_]Download{
    .{ .target = "x86_64-linux", .url = stable_base ++ "/oauth-mux-x86_64-linux.tar.gz" },
    .{ .target = "aarch64-linux", .url = stable_base ++ "/oauth-mux-aarch64-linux.tar.gz" },
    .{ .target = "x86_64-macos", .url = stable_base ++ "/oauth-mux-x86_64-macos.tar.gz" },
    .{ .target = "aarch64-macos", .url = stable_base ++ "/oauth-mux-aarch64-macos.tar.gz" },
    .{ .target = "x86_64-windows", .url = stable_base ++ "/oauth-mux-x86_64-windows.tar.gz" },
    .{ .target = "aarch64-windows", .url = stable_base ++ "/oauth-mux-aarch64-windows.tar.gz" },
};
const Integration = struct {
    id: []const u8,
    label: []const u8,
    status: []const u8,
    summary: []const u8,
    capabilities: []const []const u8,
    capabilityDetails: []const catalog.Capability,
};
const State = struct { id: []const u8, summary: []const u8 };
const states = [_]State{
    .{ .id = "active", .summary = "Eligible accounts remain subject to grant, entitlement, resource and runtime readiness." },
    .{ .id = "paused", .summary = "No new route may select the account." },
    .{ .id = "draining", .summary = "Retain in-flight work while excluding new selections." },
    .{ .id = "detached", .summary = "A disappeared source retains account history and independently valid grants." },
    .{ .id = "disconnected", .summary = "Explicitly end a source's custody authorization." },
    .{ .id = "forgotten", .summary = "Remove retained account secrets and leave a re-enrollment tombstone." },
    .{ .id = "quarantined", .summary = "Ambiguous identity or renewal evidence requires reconciliation before use." },
};

pub fn render(allocator: std.mem.Allocator) ![]u8 {
    var integrations: [catalog.adapters.len]Integration = undefined;
    var allocated: usize = 0;
    defer {
        for (integrations[0..allocated]) |item| {
            allocator.free(item.capabilities);
        }
    }
    for (catalog.adapters, 0..) |adapter, i| {
        const capabilities = try allocator.alloc([]const u8, adapter.capabilities.len);
        integrations[i] = .{
            .id = adapter.id,
            .label = adapter.display_name,
            .status = adapter.status,
            .summary = adapter.summary,
            .capabilities = capabilities,
            .capabilityDetails = adapter.capabilities,
        };
        allocated += 1;
        for (adapter.capabilities, 0..) |capability, j| capabilities[j] = capability.name;
    }
    return std.json.Stringify.valueAlloc(allocator, .{
        .schemaVersion = product.documentation_schema_version,
        .product = .{ .version = product.version, .status = product.status },
        .provenance = .{ .sourceRevision = @as(?[]const u8, null), .sourceDirty = true },
        .stableRelease = .{
            .version = product.stable_version,
            .releaseUrl = product.repository ++ "/releases/tag/v" ++ product.stable_version,
            .downloads = stable_downloads,
            .installCommands = .{.{
                .label = "Stable v0.1.15 installer",
                .command = "curl -fsSLo install.sh " ++ stable_base ++ "/install.sh && VERSION=0.1.15 sh install.sh",
            }},
        },
        .cli = cli,
        .api = .{ .version = control.protocol_version, .methods = control.methods },
        .integrations = integrations,
        .lifecycle = .{ .states = states },
    }, .{ .whitespace = .indent_2 });
}

test "reference separates experimental successor and historical stable downloads" {
    const bytes = try render(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, bytes, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqual(@as(i64, 1), root.get("schemaVersion").?.integer);
    try std.testing.expectEqualStrings("experimental", root.get("product").?.object.get("status").?.string);
    try std.testing.expectEqualStrings("0.1.15", root.get("stableRelease").?.object.get("version").?.string);
    try std.testing.expectEqual(@as(usize, 6), root.get("stableRelease").?.object.get("downloads").?.array.items.len);
    try std.testing.expect(root.get("provenance").?.object.get("sourceDirty").?.bool);
    try std.testing.expect(root.get("provenance").?.object.get("sourceRevision").? == .null);
    for (root.get("integrations").?.array.items) |item| {
        try std.testing.expect(!std.mem.eql(u8, "live-proven", item.object.get("status").?.string));
        const details = item.object.get("capabilityDetails").?.array.items;
        try std.testing.expect(details.len > 0);
        for (details) |detail| {
            try std.testing.expect(detail.object.get("limitation").?.string.len > 0);
            try std.testing.expect(!std.mem.eql(u8, "live_proven", detail.object.get("proof").?.string));
        }
    }
}

test "CLI help and generated commands share the same catalog" {
    const bytes = try commandHelp(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    for (cli) |command| try std.testing.expect(std.mem.indexOf(u8, bytes, command.usage["omux ".len..]) != null);
    try std.testing.expect(std.mem.indexOf(u8, bytes, "enroll <opaque-source-id>") != null);
}
