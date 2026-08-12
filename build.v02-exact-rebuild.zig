const std = @import("std");

pub fn build(b: *std.Build) void {
    const version = b.option(
        []const u8,
        "candidate-version",
        "Exact source/test candidate version",
    ) orelse @panic("-Dcandidate-version is required");
    const build_id = b.option(
        []const u8,
        "candidate-build-id",
        "Exact source/test candidate build id",
    ) orelse @panic("-Dcandidate-build-id is required");

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", version);
    build_options.addOption([]const u8, "build_id", build_id);

    const candidate = b.addExecutable(.{
        .name = "omux",
        .root_source_file = b.path("src/main.zig"),
        .target = b.graph.host,
        .optimize = .ReleaseSafe,
        .strip = true,
    });
    candidate.root_module.addOptions("build_options", build_options);
    b.installArtifact(candidate);
}
