const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const project_version = readProjectVersion(b) catch |err| {
        std.debug.panic("failed to read project version from build.zig.zon: {s}", .{@errorName(err)});
    };
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", project_version);

    const exe = b.addExecutable(.{
        .name = "oauth-mux",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .strip = optimize != .Debug,
    });
    exe.root_module.addOptions("build_options", build_options);
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run oauth-mux");
    run_step.dependOn(&run_cmd.step);

    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    unit_tests.root_module.addOptions("build_options", build_options);
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);

    const release_step = b.step("release", "Build release binaries for all platforms");
    const release_targets: []const std.Target.Query = &.{
        .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl },
        .{ .cpu_arch = .aarch64, .os_tag = .linux, .abi = .musl },
        .{ .cpu_arch = .x86_64, .os_tag = .macos },
        .{ .cpu_arch = .aarch64, .os_tag = .macos },
        .{ .cpu_arch = .x86_64, .os_tag = .windows },
        .{ .cpu_arch = .aarch64, .os_tag = .windows },
    };

    for (release_targets) |t| {
        const rel_exe = b.addExecutable(.{
            .name = "oauth-mux",
            .root_source_file = b.path("src/main.zig"),
            .target = b.resolveTargetQuery(t),
            .optimize = .ReleaseSafe,
            .strip = true,
        });
        rel_exe.root_module.addOptions("build_options", build_options);
        const install = b.addInstallArtifact(rel_exe, .{
            .dest_dir = .{
                .override = .{
                    .custom = b.fmt("{s}-{s}", .{
                        @tagName(t.cpu_arch orelse .x86_64),
                        @tagName(t.os_tag orelse .linux),
                    }),
                },
            },
        });
        release_step.dependOn(&install.step);
    }
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
