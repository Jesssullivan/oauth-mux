const std = @import("std");
const broker_types = @import("broker/types.zig");
const product_identity = @import("product_identity.zig");

pub const schema_version: u32 = 1;

pub const ReleaseTarget = struct {
    id: []const u8,
    cpu_arch: std.Target.Cpu.Arch,
    os_tag: std.Target.Os.Tag,
    abi: ?std.Target.Abi,
    archive_asset_id: []const u8,
    archive_asset: []const u8,
    archive_staged_path: []const u8,
    buildable: bool,
    published: bool,
    managed_broker_state: []const u8,
    v0_2_managed_broker_target: []const u8,
    artifact_policy: []const u8,
    legacy_preservation: ?[]const u8,

    pub fn query(self: ReleaseTarget) std.Target.Query {
        return .{
            .cpu_arch = self.cpu_arch,
            .os_tag = self.os_tag,
            .abi = self.abi,
        };
    }

    pub fn zigTarget(self: ReleaseTarget) []const u8 {
        return switch (self.os_tag) {
            .linux => blk: {
                std.debug.assert(self.abi == .musl);
                break :blk switch (self.cpu_arch) {
                    .x86_64 => "x86_64-linux-musl",
                    .aarch64 => "aarch64-linux-musl",
                    else => unreachable,
                };
            },
            .macos => switch (self.cpu_arch) {
                .x86_64 => "x86_64-macos",
                .aarch64 => "aarch64-macos",
                else => unreachable,
            },
            .windows => switch (self.cpu_arch) {
                .x86_64 => "x86_64-windows",
                .aarch64 => "aarch64-windows",
                else => unreachable,
            },
            else => unreachable,
        };
    }
};

/// Zig-owned release target and archive-name authority. Packaging consumers
/// migrate to the generated projection under TIN-2050.
pub const release_targets = [_]ReleaseTarget{
    .{
        .id = "x86_64-linux",
        .cpu_arch = .x86_64,
        .os_tag = .linux,
        .abi = .musl,
        .archive_asset_id = "archive-x86_64-linux",
        .archive_asset = "oauth-mux-x86_64-linux.tar.gz",
        .archive_staged_path = "artifacts/oauth-mux-x86_64-linux.tar.gz",
        .buildable = true,
        .published = true,
        .managed_broker_state = "unshipped",
        .v0_2_managed_broker_target = "beta",
        .artifact_policy = "release",
        .legacy_preservation = null,
    },
    .{
        .id = "aarch64-linux",
        .cpu_arch = .aarch64,
        .os_tag = .linux,
        .abi = .musl,
        .archive_asset_id = "archive-aarch64-linux",
        .archive_asset = "oauth-mux-aarch64-linux.tar.gz",
        .archive_staged_path = "artifacts/oauth-mux-aarch64-linux.tar.gz",
        .buildable = true,
        .published = true,
        .managed_broker_state = "unshipped",
        .v0_2_managed_broker_target = "beta",
        .artifact_policy = "release",
        .legacy_preservation = null,
    },
    .{
        .id = "x86_64-macos",
        .cpu_arch = .x86_64,
        .os_tag = .macos,
        .abi = null,
        .archive_asset_id = "archive-x86_64-macos",
        .archive_asset = "oauth-mux-x86_64-macos.tar.gz",
        .archive_staged_path = "artifacts/oauth-mux-x86_64-macos.tar.gz",
        .buildable = true,
        .published = true,
        .managed_broker_state = "unshipped",
        .v0_2_managed_broker_target = "ga",
        .artifact_policy = "release",
        .legacy_preservation = null,
    },
    .{
        .id = "aarch64-macos",
        .cpu_arch = .aarch64,
        .os_tag = .macos,
        .abi = null,
        .archive_asset_id = "archive-aarch64-macos",
        .archive_asset = "oauth-mux-aarch64-macos.tar.gz",
        .archive_staged_path = "artifacts/oauth-mux-aarch64-macos.tar.gz",
        .buildable = true,
        .published = true,
        .managed_broker_state = "unshipped",
        .v0_2_managed_broker_target = "ga",
        .artifact_policy = "release",
        .legacy_preservation = null,
    },
    .{
        .id = "x86_64-windows",
        .cpu_arch = .x86_64,
        .os_tag = .windows,
        .abi = null,
        .archive_asset_id = "archive-x86_64-windows",
        .archive_asset = "oauth-mux-x86_64-windows.tar.gz",
        .archive_staged_path = "artifacts/oauth-mux-x86_64-windows.tar.gz",
        .buildable = true,
        .published = true,
        .managed_broker_state = "unsupported",
        .v0_2_managed_broker_target = "unsupported",
        .artifact_policy = "compatibility_only",
        .legacy_preservation = "v0.1.15_stable_only",
    },
    .{
        .id = "aarch64-windows",
        .cpu_arch = .aarch64,
        .os_tag = .windows,
        .abi = null,
        .archive_asset_id = "archive-aarch64-windows",
        .archive_asset = "oauth-mux-aarch64-windows.tar.gz",
        .archive_staged_path = "artifacts/oauth-mux-aarch64-windows.tar.gz",
        .buildable = true,
        .published = true,
        .managed_broker_state = "unsupported",
        .v0_2_managed_broker_target = "unsupported",
        .artifact_policy = "compatibility_only",
        .legacy_preservation = "v0.1.15_stable_only",
    },
};

const current_posix_archive_members = [_][]const u8{ "oauth-mux", "codex" };
const declared_posix_archive_members = [_][]const u8{ "omux", "oauth-mux", "codex" };
const current_windows_archive_members = [_][]const u8{"oauth-mux.exe"};
const declared_windows_archive_members = [_][]const u8{ "omux.exe", "oauth-mux.exe" };
const current_system_package_members = [_][]const u8{ "/usr/bin/oauth-mux", "/usr/bin/codex" };
const declared_system_package_members = [_][]const u8{ "/usr/bin/omux", "/usr/bin/oauth-mux", "/usr/bin/codex" };
const no_members = [_][]const u8{};

pub const service_assets = [_]ServiceAsset{
    .{
        .id = "launchd-keepalive-template",
        .platform = "macos",
        .source = "dist/launchd/dev.xoxd.omux.keepalive.plist.tmpl",
        .release_name = "dev.xoxd.omux.keepalive.plist",
        .status = "unshipped_substrate",
    },
    .{
        .id = "systemd-keepalive-template",
        .platform = "linux",
        .source = "dist/systemd/oauth-mux-keepalive.service.tmpl",
        .release_name = "oauth-mux-keepalive.service",
        .status = "unshipped_substrate",
    },
};

const CompatibilityLink = struct {
    name: []const u8,
    target: []const u8,
    materialization: []const u8,
};

const Product = struct {
    package_name: []const u8,
    primary_executable: []const u8,
    compatibility_links: []const CompatibilityLink,
    storage_namespace: []const u8,
};

const BuildId = struct {
    value: ?[]const u8,
    source_order: []const []const u8,
};

const Release = struct {
    version: []const u8,
    build_id: BuildId,
    source_commit: ?[]const u8,
};

const Protocol = struct {
    name: []const u8,
    surface_version: u32,
    status: []const u8,
};

const ArtifactAvailability = struct {
    buildable: bool,
    published: bool,
    policy: []const u8,
    legacy_preservation: ?[]const u8,
};

const ManagedBrokerPromotion = struct {
    state: []const u8,
    v0_2_target: []const u8,
};

const TargetProjection = struct {
    id: []const u8,
    zig_target: []const u8,
    cpu_arch: []const u8,
    os: []const u8,
    abi: ?[]const u8,
    release_directory: []const u8,
    artifact: ArtifactAvailability,
    managed_broker: ManagedBrokerPromotion,
};

const MaterializationState = enum {
    v0_1_15_present_v0_2_pending_tin_2050,
    emitted_not_published_pending_tin_2050,
    resolved,
};

const ReleaseAsset = struct {
    id: []const u8,
    kind: []const u8,
    target_id: ?[]const u8,
    source_path: ?[]const u8,
    staged_path: []const u8,
    release_name: []const u8,
    materialization_state: MaterializationState,
    current_v0_1_15_members: []const []const u8,
    declared_v0_2_members: []const []const u8,
    sha256: ?[]const u8,
    signature_ref: ?[]const u8,
    sbom_ref: ?[]const u8,
    provenance_ref: ?[]const u8,
};

pub const ServiceAsset = struct {
    id: []const u8,
    platform: []const u8,
    source: []const u8,
    release_name: []const u8,
    status: []const u8,
};

const AttestationReference = struct {
    status: []const u8,
    reference: ?[]const u8,
};

const Integrity = struct {
    hash_algorithm: []const u8,
    checksum_asset: []const u8,
    signing_inputs: []const []const u8,
    sbom: AttestationReference,
    provenance: AttestationReference,
};

const ManifestPhase = enum { declaration, resolved };

const Manifest = struct {
    schema_version: u32,
    phase: ManifestPhase,
    release: Release,
    product: Product,
    adapter_protocols: []const Protocol,
    targets: []const TargetProjection,
    release_assets: []const ReleaseAsset,
    service_assets: []const ServiceAsset,
    integrity: Integrity,
    intended_consumers: []const Consumer,
};

const Consumer = struct {
    name: []const u8,
    state: []const u8,
    owner_ticket: []const u8,
    prerelease_blocking: bool,
};

pub fn renderDeclaration(allocator: std.mem.Allocator, version: []const u8) ![]u8 {
    try validateStatic();
    var compatibility_links: [product_identity.compatibility_executable_names.len]CompatibilityLink = undefined;
    for (product_identity.compatibility_executable_names, 0..) |name, index| {
        compatibility_links[index] = .{
            .name = name,
            .target = product_identity.primary_executable_name,
            .materialization = "same_bytes",
        };
    }

    var targets: [release_targets.len]TargetProjection = undefined;
    for (release_targets, 0..) |target, index| {
        targets[index] = .{
            .id = target.id,
            .zig_target = target.zigTarget(),
            .cpu_arch = @tagName(target.cpu_arch),
            .os = @tagName(target.os_tag),
            .abi = if (target.abi) |abi| @tagName(abi) else null,
            .release_directory = target.id,
            .artifact = .{
                .buildable = target.buildable,
                .published = target.published,
                .policy = target.artifact_policy,
                .legacy_preservation = target.legacy_preservation,
            },
            .managed_broker = .{
                .state = target.managed_broker_state,
                .v0_2_target = target.v0_2_managed_broker_target,
            },
        };
    }

    var system_package_names = std.ArrayList([]const u8).init(allocator);
    defer {
        for (system_package_names.items) |name| allocator.free(name);
        system_package_names.deinit();
    }
    try appendFormatted(&system_package_names, allocator, "oauth-mux_{s}_amd64.deb", .{version});
    try appendFormatted(&system_package_names, allocator, "oauth-mux_{s}_arm64.deb", .{version});
    try appendFormatted(&system_package_names, allocator, "oauth-mux-{s}-1.x86_64.rpm", .{version});
    try appendFormatted(&system_package_names, allocator, "oauth-mux-{s}-1.aarch64.rpm", .{version});

    var system_package_staged_paths = std.ArrayList([]const u8).init(allocator);
    defer {
        for (system_package_staged_paths.items) |path| allocator.free(path);
        system_package_staged_paths.deinit();
    }
    for (system_package_names.items) |name| {
        try appendFormatted(&system_package_staged_paths, allocator, "artifacts/{s}", .{name});
    }

    var release_assets: [release_targets.len + 4 + 4]ReleaseAsset = undefined;
    var asset_index: usize = 0;
    for (release_targets) |target| {
        release_assets[asset_index] = unresolvedAsset(
            target.archive_asset_id,
            "archive",
            target.id,
            null,
            target.archive_staged_path,
            target.archive_asset,
            .v0_1_15_present_v0_2_pending_tin_2050,
            if (target.os_tag == .windows) &current_windows_archive_members else &current_posix_archive_members,
            if (target.os_tag == .windows) &declared_windows_archive_members else &declared_posix_archive_members,
        );
        asset_index += 1;
    }
    const system_package_specs = [_]struct {
        id: []const u8,
        kind: []const u8,
        target_id: []const u8,
    }{
        .{ .id = "deb-x86_64-linux", .kind = "deb", .target_id = "x86_64-linux" },
        .{ .id = "deb-aarch64-linux", .kind = "deb", .target_id = "aarch64-linux" },
        .{ .id = "rpm-x86_64-linux", .kind = "rpm", .target_id = "x86_64-linux" },
        .{ .id = "rpm-aarch64-linux", .kind = "rpm", .target_id = "aarch64-linux" },
    };
    for (system_package_specs, system_package_names.items, system_package_staged_paths.items) |spec, name, staged_path| {
        release_assets[asset_index] = unresolvedAsset(
            spec.id,
            spec.kind,
            spec.target_id,
            null,
            staged_path,
            name,
            .v0_1_15_present_v0_2_pending_tin_2050,
            &current_system_package_members,
            &declared_system_package_members,
        );
        asset_index += 1;
    }
    for ([_]struct {
        id: []const u8,
        kind: []const u8,
        source_path: ?[]const u8,
        staged_path: []const u8,
        release_name: []const u8,
        materialization_state: MaterializationState,
    }{
        .{ .id = "curl-installer", .kind = "installer", .source_path = "dist/install.sh", .staged_path = "artifacts/install.sh", .release_name = "install.sh", .materialization_state = .v0_1_15_present_v0_2_pending_tin_2050 },
        .{ .id = "checksums", .kind = "checksums", .source_path = null, .staged_path = "artifacts/SHA256SUMS", .release_name = "SHA256SUMS", .materialization_state = .v0_1_15_present_v0_2_pending_tin_2050 },
        .{ .id = "homebrew-formula", .kind = "formula", .source_path = "dist/homebrew/oauth-mux.rb", .staged_path = "homebrew/oauth-mux.rb", .release_name = "oauth-mux.rb", .materialization_state = .v0_1_15_present_v0_2_pending_tin_2050 },
        .{ .id = "release-manifest", .kind = "manifest", .source_path = "release-manifest.json", .staged_path = "artifacts/release-manifest.json", .release_name = "release-manifest.json", .materialization_state = .emitted_not_published_pending_tin_2050 },
    }) |asset| {
        release_assets[asset_index] = unresolvedAsset(
            asset.id,
            asset.kind,
            null,
            asset.source_path,
            asset.staged_path,
            asset.release_name,
            asset.materialization_state,
            &no_members,
            &no_members,
        );
        asset_index += 1;
    }

    const protocols = [_]Protocol{
        .{ .name = "broker-jsonrpc", .surface_version = broker_types.surface_version, .status = "shipped" },
        .{ .name = "managed-harness-jsonrpc", .surface_version = 2, .status = "planned_unshipped" },
    };
    const build_id_sources = [_][]const u8{
        "zig-option:build-id",
        "env:OMUX_BUILD_ID",
        "git-describe",
        "release.version",
    };
    const signing_inputs = [_][]const u8{ "release-manifest.json", "SHA256SUMS" };
    const consumers = [_]Consumer{
        .{ .name = "github-release", .state = "pending", .owner_ticket = "TIN-2050", .prerelease_blocking = true },
        .{ .name = "curl", .state = "pending", .owner_ticket = "TIN-2050", .prerelease_blocking = true },
        .{ .name = "homebrew", .state = "pending", .owner_ticket = "TIN-2050", .prerelease_blocking = true },
        .{ .name = "deb", .state = "pending", .owner_ticket = "TIN-2050", .prerelease_blocking = true },
        .{ .name = "rpm", .state = "pending", .owner_ticket = "TIN-2050", .prerelease_blocking = true },
        .{ .name = "nix-source", .state = "pending", .owner_ticket = "TIN-2050", .prerelease_blocking = true },
        .{ .name = "bazel", .state = "pending", .owner_ticket = "TIN-2105", .prerelease_blocking = false },
        .{ .name = "gloriousflywheel", .state = "pending", .owner_ticket = "TIN-2105", .prerelease_blocking = false },
    };
    const manifest = Manifest{
        .schema_version = schema_version,
        .phase = .declaration,
        .release = .{
            .version = version,
            .build_id = .{ .value = null, .source_order = &build_id_sources },
            .source_commit = null,
        },
        .product = .{
            .package_name = product_identity.package_name,
            .primary_executable = product_identity.primary_executable_name,
            .compatibility_links = &compatibility_links,
            .storage_namespace = product_identity.storage_namespace,
        },
        .adapter_protocols = &protocols,
        .targets = &targets,
        .release_assets = &release_assets,
        .service_assets = &service_assets,
        .integrity = .{
            .hash_algorithm = "sha256",
            .checksum_asset = "SHA256SUMS",
            .signing_inputs = &signing_inputs,
            .sbom = .{ .status = "not_emitted", .reference = null },
            .provenance = .{ .status = "not_emitted", .reference = null },
        },
        .intended_consumers = &consumers,
    };

    try validateDeclaration(manifest);

    var output = std.ArrayList(u8).init(allocator);
    errdefer output.deinit();
    try std.json.stringify(manifest, .{ .whitespace = .indent_2 }, output.writer());
    try output.append('\n');
    return output.toOwnedSlice();
}

fn appendFormatted(
    list: *std.ArrayList([]const u8),
    allocator: std.mem.Allocator,
    comptime format: []const u8,
    args: anytype,
) !void {
    const value = try std.fmt.allocPrint(allocator, format, args);
    errdefer allocator.free(value);
    try list.append(value);
}

pub fn validateStatic() !void {
    if (release_targets.len == 0) return error.NoReleaseTargets;
    for (release_targets, 0..) |target, index| {
        if (target.id.len == 0 or target.archive_asset_id.len == 0 or target.archive_asset.len == 0) {
            return error.InvalidReleaseTarget;
        }
        _ = target.zigTarget();
        for (release_targets[index + 1 ..]) |other| {
            if (std.mem.eql(u8, target.id, other.id) or
                std.mem.eql(u8, target.archive_asset_id, other.archive_asset_id) or
                std.mem.eql(u8, target.archive_asset, other.archive_asset))
            {
                return error.DuplicateReleaseTarget;
            }
        }
    }
    for (service_assets, 0..) |asset, index| {
        if (asset.id.len == 0 or asset.source.len == 0 or asset.release_name.len == 0) {
            return error.InvalidServiceAsset;
        }
        for (service_assets[index + 1 ..]) |other| {
            if (std.mem.eql(u8, asset.id, other.id) or
                std.mem.eql(u8, asset.source, other.source) or
                std.mem.eql(u8, asset.release_name, other.release_name))
            {
                return error.DuplicateServiceAsset;
            }
        }
    }
}

fn validateDeclaration(manifest: Manifest) !void {
    if (manifest.phase != .declaration or manifest.release.version.len == 0) {
        return error.InvalidDeclarationPhase;
    }
    if (manifest.release.build_id.value != null or manifest.release.source_commit != null) {
        return error.ResolvedFieldInDeclaration;
    }
    for (manifest.product.compatibility_links, 0..) |link, index| {
        if (link.name.len == 0 or
            !std.mem.eql(u8, link.target, manifest.product.primary_executable) or
            !std.mem.eql(u8, link.materialization, "same_bytes"))
        {
            return error.InvalidCompatibilityLink;
        }
        for (manifest.product.compatibility_links[index + 1 ..]) |other| {
            if (std.mem.eql(u8, link.name, other.name)) return error.DuplicateCompatibilityLink;
        }
    }
    var shipped_broker_protocol = false;
    var planned_managed_protocol = false;
    for (manifest.adapter_protocols, 0..) |protocol, index| {
        if (std.mem.eql(u8, protocol.name, "broker-jsonrpc") and
            protocol.surface_version == broker_types.surface_version and
            std.mem.eql(u8, protocol.status, "shipped"))
        {
            shipped_broker_protocol = true;
        } else if (std.mem.eql(u8, protocol.name, "managed-harness-jsonrpc") and
            protocol.surface_version == 2 and
            std.mem.eql(u8, protocol.status, "planned_unshipped"))
        {
            planned_managed_protocol = true;
        } else {
            return error.InvalidAdapterProtocol;
        }
        for (manifest.adapter_protocols[index + 1 ..]) |other| {
            if (std.mem.eql(u8, protocol.name, other.name)) return error.DuplicateAdapterProtocol;
        }
    }
    if (!shipped_broker_protocol or !planned_managed_protocol) return error.MissingAdapterProtocol;
    for (manifest.release_assets, 0..) |asset, index| {
        if (asset.id.len == 0 or asset.staged_path.len == 0 or asset.release_name.len == 0) {
            return error.InvalidReleaseAsset;
        }
        if (asset.materialization_state == .resolved or asset.sha256 != null or
            asset.signature_ref != null or asset.sbom_ref != null or asset.provenance_ref != null)
        {
            return error.ResolvedFieldInDeclaration;
        }
        if (asset.target_id) |target_id| {
            var found = false;
            for (release_targets) |target| {
                if (std.mem.eql(u8, target.id, target_id)) {
                    found = true;
                    break;
                }
            }
            if (!found) return error.UnknownReleaseTarget;
        }
        if (containsForbiddenLane(asset.release_name)) return error.ForbiddenReleaseLane;
        for (manifest.release_assets[index + 1 ..]) |other| {
            if (std.mem.eql(u8, asset.id, other.id) or
                std.mem.eql(u8, asset.staged_path, other.staged_path) or
                std.mem.eql(u8, asset.release_name, other.release_name))
            {
                return error.DuplicateReleaseAsset;
            }
        }
    }
    for (manifest.intended_consumers, 0..) |consumer, index| {
        if (consumer.name.len == 0 or consumer.owner_ticket.len == 0) return error.InvalidConsumer;
        const is_bazel_lane = std.mem.eql(u8, consumer.name, "bazel") or
            std.mem.eql(u8, consumer.name, "gloriousflywheel");
        if (is_bazel_lane) {
            if (!std.mem.eql(u8, consumer.owner_ticket, "TIN-2105") or consumer.prerelease_blocking) {
                return error.InvalidConsumerOwnership;
            }
        } else if (!std.mem.eql(u8, consumer.owner_ticket, "TIN-2050")) {
            return error.InvalidConsumerOwnership;
        }
        for (manifest.intended_consumers[index + 1 ..]) |other| {
            if (std.mem.eql(u8, consumer.name, other.name)) return error.DuplicateConsumer;
        }
    }
    var checksum_asset_found = false;
    for (manifest.release_assets) |asset| {
        if (std.mem.eql(u8, asset.release_name, manifest.integrity.checksum_asset)) {
            checksum_asset_found = true;
            break;
        }
    }
    if (!checksum_asset_found) return error.MissingChecksumAsset;
    for (manifest.integrity.signing_inputs) |input| {
        var found = false;
        for (manifest.release_assets) |asset| {
            if (std.mem.eql(u8, asset.release_name, input)) {
                found = true;
                break;
            }
        }
        if (!found) return error.UnknownSigningInput;
    }
    if (!std.mem.eql(u8, manifest.integrity.sbom.status, "not_emitted") or
        !std.mem.eql(u8, manifest.integrity.provenance.status, "not_emitted") or
        manifest.integrity.sbom.reference != null or manifest.integrity.provenance.reference != null)
    {
        return error.ResolvedFieldInDeclaration;
    }
}

fn containsForbiddenLane(value: []const u8) bool {
    return std.mem.indexOf(u8, value, "npm") != null or
        std.mem.endsWith(u8, value, ".pkg") or
        std.mem.endsWith(u8, value, ".dmg") or
        std.mem.indexOf(u8, value, "AppImage") != null;
}

fn unresolvedAsset(
    id: []const u8,
    kind: []const u8,
    target_id: ?[]const u8,
    source_path: ?[]const u8,
    staged_path: []const u8,
    release_name: []const u8,
    materialization_state: MaterializationState,
    current_v0_1_15_members: []const []const u8,
    declared_v0_2_members: []const []const u8,
) ReleaseAsset {
    return .{
        .id = id,
        .kind = kind,
        .target_id = target_id,
        .source_path = source_path,
        .staged_path = staged_path,
        .release_name = release_name,
        .materialization_state = materialization_state,
        .current_v0_1_15_members = current_v0_1_15_members,
        .declared_v0_2_members = declared_v0_2_members,
        .sha256 = null,
        .signature_ref = null,
        .sbom_ref = null,
        .provenance_ref = null,
    };
}

test "release target table is unique and preserves explicit platform policy" {
    try validateStatic();
    try std.testing.expectEqual(@as(usize, 6), release_targets.len);
    for (release_targets, 0..) |target, index| {
        try std.testing.expect(target.id.len != 0);
        try std.testing.expect(target.archive_asset.len != 0);
        try std.testing.expectEqualStrings(
            switch (target.os_tag) {
                .linux => if (target.cpu_arch == .x86_64) "x86_64-linux-musl" else "aarch64-linux-musl",
                .macos => if (target.cpu_arch == .x86_64) "x86_64-macos" else "aarch64-macos",
                .windows => if (target.cpu_arch == .x86_64) "x86_64-windows" else "aarch64-windows",
                else => unreachable,
            },
            target.zigTarget(),
        );
        try std.testing.expect(target.buildable);
        try std.testing.expect(target.published);
        if (target.os_tag == .windows) {
            try std.testing.expectEqualStrings("unsupported", target.managed_broker_state);
            try std.testing.expectEqualStrings("compatibility_only", target.artifact_policy);
            try std.testing.expectEqualStrings("v0.1.15_stable_only", target.legacy_preservation.?);
        }
        for (release_targets[index + 1 ..]) |other| {
            try std.testing.expect(!std.mem.eql(u8, target.id, other.id));
            try std.testing.expect(!std.mem.eql(u8, target.archive_asset, other.archive_asset));
        }
    }
}

test "declaration manifest is deterministic, parseable, and claim bounded" {
    const first = try renderDeclaration(std.testing.allocator, "0.1.15");
    defer std.testing.allocator.free(first);
    const second = try renderDeclaration(std.testing.allocator, "0.1.15");
    defer std.testing.allocator.free(second);
    try std.testing.expectEqualStrings(first, second);

    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, first, .{});
    defer parsed.deinit();
    const root = parsed.value.object;
    try std.testing.expectEqual(@as(i64, schema_version), root.get("schema_version").?.integer);
    try std.testing.expectEqualStrings("declaration", root.get("phase").?.string);
    const release = root.get("release").?.object;
    try std.testing.expectEqualStrings("0.1.15", release.get("version").?.string);
    try std.testing.expect(release.get("build_id").?.object.get("value").? == .null);
    try std.testing.expect(release.get("source_commit").? == .null);
    try std.testing.expectEqual(@as(usize, release_targets.len), root.get("targets").?.array.items.len);
    const assets = root.get("release_assets").?.array.items;
    try std.testing.expectEqual(@as(usize, 14), assets.len);
    for (assets, 0..) |asset_value, index| {
        const asset = asset_value.object;
        const id = asset.get("id").?.string;
        const name = asset.get("release_name").?.string;
        try std.testing.expect(id.len != 0);
        try std.testing.expect(name.len != 0);
        try std.testing.expect(asset.get("sha256").? == .null);
        try std.testing.expect(asset.get("signature_ref").? == .null);
        try std.testing.expect(asset.get("sbom_ref").? == .null);
        try std.testing.expect(asset.get("provenance_ref").? == .null);
        for (assets[index + 1 ..]) |other_value| {
            const other = other_value.object;
            try std.testing.expect(!std.mem.eql(u8, id, other.get("id").?.string));
            try std.testing.expect(!std.mem.eql(u8, name, other.get("release_name").?.string));
        }
    }

    const product = root.get("product").?.object;
    try std.testing.expectEqualStrings("omux", product.get("primary_executable").?.string);
    try std.testing.expectEqualStrings("oauth-mux", product.get("storage_namespace").?.string);
    const protocols = root.get("adapter_protocols").?.array.items;
    try std.testing.expectEqual(@as(usize, 2), protocols.len);
    try std.testing.expectEqual(
        @as(i64, broker_types.surface_version),
        protocols[0].object.get("surface_version").?.integer,
    );
    for (root.get("service_assets").?.array.items) |service_value| {
        try std.testing.expectEqualStrings("unshipped_substrate", service_value.object.get("status").?.string);
    }

    try std.testing.expect(std.mem.indexOf(u8, first, "npm") == null);
    try std.testing.expect(std.mem.indexOf(u8, first, ".pkg") == null);
    try std.testing.expect(std.mem.indexOf(u8, first, ".dmg") == null);
    try std.testing.expect(std.mem.indexOf(u8, first, "AppImage") == null);
    try std.testing.expect(std.mem.indexOf(u8, first, "not_emitted") != null);
}

test "service asset declarations point at tracked source files" {
    for (service_assets) |asset| try std.fs.cwd().access(asset.source, .{});
}
