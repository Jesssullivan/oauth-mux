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
    .{ .name = "sign-in start", .summary = "Explicit finite daemon-owned Sign in with ChatGPT enrollment; opens the default browser through the packaged Linux control helper. Prints opaque handles only. Separate API Responses authority; no native Codex or continuity proof.", .usage = "omux sign-in start --consent-seconds <1..3600> --confirm" },
    .{ .name = "sign-in providers", .summary = "Inspect negotiated experimental enrollment availability and custody without provider access.", .usage = "omux sign-in providers" },
    .{ .name = "sign-in pending", .summary = "List original live enrollment handles without renewing consent or repeating one-use authorization.", .usage = "omux sign-in pending" },
    .{ .name = "sign-in status", .summary = "Read redacted actual paired/grant readiness for this original transaction; Unknown custody never means zero accounts.", .usage = "omux sign-in status <opaque-transaction-id>" },
    .{ .name = "sign-in cancel", .summary = "Withdraw this enrollment/source's local consent and paired grants; issued work may have occurred and provider revocation is not claimed.", .usage = "omux sign-in <cancel|remove> <opaque-transaction-id>" },
    .{ .name = "operation status", .summary = "Resolve the original opaque mutation after an unknown reply; never replay or submit a new operation automatically.", .usage = "omux operation status <opaque-operation-id>" },
    .{ .name = "enroll", .summary = "Experimental external-source credential import using JSON on stdin; separate from daemon-owned sign-in. --wait observes only the original enrollment job for up to 30 seconds; unresolved outcomes never retry import.", .usage = "omux enroll [--wait] <opaque-source-id>" },
    .{ .name = "integration status", .summary = "Inspect native integration readiness and proof limitations.", .usage = "omux integration status" },
    .{ .name = "integration install", .summary = "Install a reversible integration after proving its prerequisites.", .usage = "omux integration install <adapter> [config-path]" },
    .{ .name = "integration discover", .summary = "Inspect bounded authenticated native owner inventory in the selected integration context; hook compatibility is experimental, not native support.", .usage = "omux integration discover [codex [config-path]]" },
    .{ .name = "integration attach", .summary = "An owner endpoint is required; use stdin RPC integrations.attach or native controls with the selected owner tuple. This typed command cannot select a process automatically.", .usage = "omux integration attach <adapter> [thread-id]" },
    .{ .name = "integration detach", .summary = "A committed native_ref and owner endpoint are required; use stdin RPC integrations.detach or native controls. This typed command cannot derive attachment authority.", .usage = "omux integration detach <adapter> [thread-id]" },
    .{ .name = "integration remove", .summary = "Restore owned integration settings while preserving later edits.", .usage = "omux integration remove <adapter>" },
    .{ .name = "rpc", .summary = "Invoke an implemented control method using a JSON request on stdin.", .usage = "omux rpc <method> -" },
    .{ .name = "native-host", .summary = "Run the browser native-messaging conduit.", .usage = "omux native-host" },
    .{ .name = "git-credential", .summary = "Handle a native Git credential-helper operation.", .usage = "omux git-credential <get|store|erase>" },
    .{ .name = "reference", .summary = "Emit this versioned source-derived documentation bundle.", .usage = "omux reference [--source-commit <full-commit> --source-dirty <true|false>]" },
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
        "Typed startup vault failures retain bounded diagnostics; custody work requires restored OS-vault custody.\n" ++
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

const Provenance = struct {
    sourceRevision: ?[]const u8 = null,
    sourceDirty: bool = true,
};

fn argumentProvenance(arguments: []const []const u8) !Provenance {
    // Explicit producer assertions, not Git discovery or support qualification.
    if (arguments.len == 0) return .{};
    if (arguments.len != 4 or !std.mem.eql(u8, arguments[0], "--source-commit") or
        !std.mem.eql(u8, arguments[2], "--source-dirty")) return error.InvalidArguments;
    const commit = arguments[1];
    if (commit.len != 40) return error.InvalidArguments;
    for (commit) |byte| {
        if (!((byte >= '0' and byte <= '9') or (byte >= 'a' and byte <= 'f'))) return error.InvalidArguments;
    }
    const dirty = if (std.mem.eql(u8, arguments[3], "true")) true else if (std.mem.eql(u8, arguments[3], "false")) false else return error.InvalidArguments;
    return .{ .sourceRevision = commit, .sourceDirty = dirty };
}

pub fn renderArguments(allocator: std.mem.Allocator, arguments: []const []const u8) ![]u8 {
    return renderWithProvenance(allocator, try argumentProvenance(arguments));
}

pub fn render(allocator: std.mem.Allocator) ![]u8 {
    return renderWithProvenance(allocator, .{});
}

fn renderWithProvenance(allocator: std.mem.Allocator, provenance: Provenance) ![]u8 {
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
        .provenance = provenance,
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
    try std.testing.expect(std.mem.indexOf(u8, bytes, "enroll [--wait] <opaque-source-id>") != null);
}

test "reference producer arguments preserve explicit clean and dirty assertions" {
    const commit = "0123456789abcdef0123456789abcdef01234567";
    for ([_][]const u8{ "true", "false" }) |dirty| {
        const bytes = try renderArguments(std.testing.allocator, &.{ "--source-commit", commit, "--source-dirty", dirty });
        defer std.testing.allocator.free(bytes);
        const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, bytes, .{});
        defer parsed.deinit();
        const root = parsed.value.object;
        const provenance = root.get("provenance").?.object;
        try std.testing.expectEqualStrings(commit, provenance.get("sourceRevision").?.string);
        try std.testing.expectEqual(std.mem.eql(u8, dirty, "true"), provenance.get("sourceDirty").?.bool);
        try std.testing.expectEqualStrings("experimental", root.get("product").?.object.get("status").?.string);
        try std.testing.expectEqualStrings("0.1.15", root.get("stableRelease").?.object.get("version").?.string);
        for (root.get("integrations").?.array.items) |item| {
            try std.testing.expect(!std.mem.eql(u8, "live-proven", item.object.get("status").?.string));
        }
    }
}

test "bare reference arguments preserve unknown provenance exactly" {
    const bare = try renderArguments(std.testing.allocator, &.{});
    defer std.testing.allocator.free(bare);
    const unbound = try render(std.testing.allocator);
    defer std.testing.allocator.free(unbound);
    try std.testing.expectEqualSlices(u8, unbound, bare);
}

test "reference producer rejects partial malformed reordered and extra arguments" {
    const commit = "0123456789abcdef0123456789abcdef01234567";
    const invalid = [_][]const []const u8{
        &.{"--source-commit"},
        &.{ "--source-commit", commit },
        &.{ "--source-dirty", "false" },
        &.{ "--source-commit", "", "--source-dirty", "false" },
        &.{ "--source-commit", "0123456789abcdef0123456789abcdef0123456", "--source-dirty", "false" },
        &.{ "--source-commit", "0123456789abcdef0123456789abcdef012345678", "--source-dirty", "false" },
        &.{ "--source-commit", "0123456789ABCDEF0123456789ABCDEF01234567", "--source-dirty", "false" },
        &.{ "--source-commit", "0123456789abcdef0123456789abcdef0123456g", "--source-dirty", "false" },
        &.{ "--source-commit", "0123456789abcdef0123456789abcdef0123456\n", "--source-dirty", "false" },
        &.{ "--source-commit", commit, "--source-dirty", "" },
        &.{ "--source-commit", commit, "--source-dirty", "False" },
        &.{ "--source-commit", commit, "--source-dirty", "0" },
        &.{ "--source-dirty", "false", "--source-commit", commit },
        &.{ "--source-commit", commit, "--unknown", "false" },
        &.{ "--source-commit", commit, "--source-dirty", "false", "extra" },
    };
    for (invalid) |arguments| try std.testing.expectError(error.InvalidArguments, renderArguments(std.testing.allocator, arguments));
}
