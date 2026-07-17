const std = @import("std");
const managed_harness_contract = @import("src/managed_harness_contract.zig");
const product_identity = @import("src/product_identity.zig");
const release_manifest = @import("src/release_manifest.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const project_version = readProjectVersion(b) catch |err| {
        std.debug.panic("failed to read project version from build.zig.zon: {s}", .{@errorName(err)});
    };
    const project_build_id = b.option([]const u8, "build-id", "Build provenance id") orelse
        readBuildId(b, project_version);
    const source_manifest = release_manifest.renderDeclaration(
        b.allocator,
        project_version,
    ) catch @panic("failed to render source release manifest");
    const managed_harness_schema = managed_harness_contract.renderSchema(
        b.allocator,
    ) catch @panic("failed to render managed-harness JSON-RPC schema");

    const update_manifest_files = b.addUpdateSourceFiles();
    update_manifest_files.addBytesToSource(source_manifest, "release-manifest.json");
    const update_manifest_step = b.step(
        "update-release-manifest",
        "Regenerate the checked release-manifest.json projection",
    );
    update_manifest_step.dependOn(&update_manifest_files.step);

    const check_manifest_step = b.step(
        "check-release-manifest",
        "Check that release-manifest.json matches the Zig release graph",
    );
    const committed_manifest = std.fs.cwd().readFileAlloc(
        b.allocator,
        "release-manifest.json",
        1024 * 1024,
    ) catch null;
    if (committed_manifest == null or !std.mem.eql(u8, committed_manifest.?, source_manifest)) {
        const fail = b.addFail(
            "release-manifest.json is stale; run `just release-manifest-update` and commit the result",
        );
        check_manifest_step.dependOn(&fail.step);
    }

    const update_managed_schema_files = b.addUpdateSourceFiles();
    update_managed_schema_files.addBytesToSource(
        managed_harness_schema,
        "schemas/managed-harness-jsonrpc-v2.schema.json",
    );
    const update_managed_schema_step = b.step(
        "update-managed-harness-schema",
        "Regenerate the checked managed-harness JSON-RPC v2 schema",
    );
    update_managed_schema_step.dependOn(&update_managed_schema_files.step);

    const check_managed_schema_step = b.step(
        "check-managed-harness-schema",
        "Check that the managed-harness JSON-RPC v2 schema matches Zig authority",
    );
    const committed_managed_schema = std.fs.cwd().readFileAlloc(
        b.allocator,
        "schemas/managed-harness-jsonrpc-v2.schema.json",
        1024 * 1024,
    ) catch null;
    if (committed_managed_schema == null or
        !std.mem.eql(u8, committed_managed_schema.?, managed_harness_schema))
    {
        const fail = b.addFail(
            "managed-harness schema is stale; run `just managed-harness-schema-update` and commit the result",
        );
        check_managed_schema_step.dependOn(&fail.step);
    }
    for (release_manifest.service_assets) |asset| {
        std.fs.cwd().access(asset.source, .{}) catch {
            const fail = b.addFail(b.fmt(
                "release manifest service asset is missing: {s}",
                .{asset.source},
            ));
            check_manifest_step.dependOn(&fail.step);
        };
    }
    b.getInstallStep().dependOn(check_manifest_step);
    b.getInstallStep().dependOn(check_managed_schema_step);

    const manifest_files = b.addWriteFiles();
    const emitted_manifest_path = manifest_files.add("release-manifest.json", source_manifest);
    const install_manifest = b.addInstallFile(emitted_manifest_path, "release-manifest.json");
    install_manifest.step.dependOn(check_manifest_step);
    b.getInstallStep().dependOn(&install_manifest.step);
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", project_version);
    build_options.addOption([]const u8, "build_id", project_build_id);

    const exe = b.addExecutable(.{
        .name = product_identity.primary_executable_name,
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = optimize != .Debug,
    });
    exe.root_module.addOptions("build_options", build_options);
    const install_exe = b.addInstallArtifact(exe, .{});
    install_exe.step.dependOn(check_manifest_step);
    b.getInstallStep().dependOn(&install_exe.step);
    for (product_identity.compatibility_executable_names) |name| {
        const compatibility_install = b.addInstallBinFile(
            exe.getEmittedBin(),
            executableFileName(b, name, target.result.os.tag),
        );
        compatibility_install.step.dependOn(check_manifest_step);
        b.getInstallStep().dependOn(&compatibility_install.step);
    }

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run omux");
    run_step.dependOn(&run_cmd.step);

    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    unit_tests.root_module.addOptions("build_options", build_options);
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
    test_step.dependOn(check_manifest_step);
    test_step.dependOn(check_managed_schema_step);

    const stage2_options = b.addOptions();
    stage2_options.addOption(
        []const u8,
        "candidate_sha",
        b.option([]const u8, "v02-candidate-sha", "Exact v0.2 candidate commit") orelse "",
    );
    stage2_options.addOption(
        []const u8,
        "candidate_tree",
        b.option([]const u8, "v02-candidate-tree", "Exact v0.2 candidate tree") orelse "",
    );
    stage2_options.addOption(
        []const u8,
        "workflow_run_id",
        b.option([]const u8, "v02-workflow-run-id", "Authoritative workflow run id") orelse "",
    );
    stage2_options.addOption(
        []const u8,
        "workflow_run_attempt",
        b.option([]const u8, "v02-workflow-run-attempt", "Authoritative workflow run attempt") orelse "",
    );
    stage2_options.addOption(
        []const u8,
        "gf_target_class",
        b.option([]const u8, "v02-gf-target-class", "GloriousFlywheel target class") orelse "",
    );
    const stage2_observer = b.addTest(.{
        .root_source_file = b.path("test/stage2_observer_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const stage2_observer_module = b.createModule(.{
        .root_source_file = b.path("src/adapters/claude/stage2_observer.zig"),
        .target = target,
        .optimize = optimize,
    });
    stage2_observer.root_module.addImport("stage2_observer", stage2_observer_module);
    stage2_observer.root_module.addOptions("stage2_build_options", stage2_options);
    const run_stage2_observer = b.addRunArtifact(stage2_observer);
    const stage2_observer_step = b.step(
        "v02-stage2-observe",
        "Emit typed Claude fake-upstream Stage 2 observations",
    );
    stage2_observer_step.dependOn(&run_stage2_observer.step);

    const release_step = b.step("release", "Build release binaries for all platforms");
    release_step.dependOn(check_manifest_step);
    release_step.dependOn(check_managed_schema_step);
    release_step.dependOn(&install_manifest.step);

    for (release_manifest.release_targets) |release_target| {
        const t = release_target.query();
        const rel_exe = b.addExecutable(.{
            .name = product_identity.primary_executable_name,
            .root_source_file = b.path("src/main.zig"),
            .target = b.resolveTargetQuery(t),
            .optimize = .ReleaseSafe,
            .strip = true,
        });
        rel_exe.root_module.addOptions("build_options", build_options);
        const release_dir: std.Build.InstallDir = .{ .custom = release_target.id };
        const install = b.addInstallArtifact(rel_exe, .{
            .dest_dir = .{
                .override = release_dir,
            },
        });
        install.step.dependOn(check_manifest_step);
        release_step.dependOn(&install.step);
        for (product_identity.compatibility_executable_names) |name| {
            const compatibility_install = b.addInstallFileWithDir(
                rel_exe.getEmittedBin(),
                release_dir,
                executableFileName(b, name, t.os_tag orelse .linux),
            );
            compatibility_install.step.dependOn(check_manifest_step);
            release_step.dependOn(&compatibility_install.step);
        }
    }
}

fn executableFileName(b: *std.Build, stem: []const u8, os_tag: std.Target.Os.Tag) []const u8 {
    return if (os_tag == .windows) b.fmt("{s}.exe", .{stem}) else stem;
}

fn readProjectVersion(b: *std.Build) ![]const u8 {
    const contents = try std.fs.cwd().readFileAlloc(b.allocator, "build.zig.zon", 64 * 1024);
    const marker = ".version";
    const version_pos = std.mem.indexOf(u8, contents, marker) orelse return error.ProjectVersionMissing;
    const after_marker = contents[version_pos + marker.len ..];
    const first_quote = std.mem.indexOfScalar(u8, after_marker, '"') orelse return error.ProjectVersionMissing;
    const after_first_quote = after_marker[first_quote + 1 ..];
    const second_quote = std.mem.indexOfScalar(u8, after_first_quote, '"') orelse return error.ProjectVersionMissing;
    return try b.allocator.dupe(u8, after_first_quote[0..second_quote]);
}

fn readBuildId(b: *std.Build, project_version: []const u8) []const u8 {
    const env_build_id = std.process.getEnvVarOwned(b.allocator, "OMUX_BUILD_ID") catch null;
    if (env_build_id) |value| {
        if (std.mem.trim(u8, value, " \t\r\n").len != 0) return value;
        b.allocator.free(value);
    }

    const result = std.process.Child.run(.{
        .allocator = b.allocator,
        .argv = &.{ "git", "describe", "--tags", "--dirty", "--always" },
    }) catch return project_version;
    defer b.allocator.free(result.stderr);

    if (result.term != .Exited or result.term.Exited != 0) {
        b.allocator.free(result.stdout);
        return project_version;
    }

    const trimmed = std.mem.trim(u8, result.stdout, " \t\r\n");
    if (trimmed.len == 0) {
        b.allocator.free(result.stdout);
        return project_version;
    }

    const build_id = b.allocator.dupe(u8, trimmed) catch {
        b.allocator.free(result.stdout);
        return project_version;
    };
    b.allocator.free(result.stdout);
    return build_id;
}
