const std = @import("std");
const release_manifest = @import("release_manifest");

const version = "0.2.0-rc.0";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len != 5) {
        std.debug.print(
            "usage: v02-prerelease-bundle <bundle-dir> <candidate-sha> <candidate-tree> <build-id>\n",
            .{},
        );
        std.process.exit(2);
    }

    var bundle_dir = try std.fs.cwd().openDir(args[1], .{});
    defer bundle_dir.close();
    var artifact_dir = try bundle_dir.openDir("artifacts", .{});
    defer artifact_dir.close();

    var digests: [release_manifest.v0_2_prerelease_targets.len][64]u8 = undefined;
    var digest_slices: [release_manifest.v0_2_prerelease_targets.len][]const u8 = undefined;
    for (release_manifest.v0_2_prerelease_targets, 0..) |spec, index| {
        const payload = try std.fmt.allocPrint(
            allocator,
            "TIN-3005 bounded outer-artifact fixture\n" ++
                "target={s}\n" ++
                "candidate_sha={s}\n" ++
                "candidate_tree={s}\n",
            .{ spec.id, args[2], args[3] },
        );
        defer allocator.free(payload);
        try artifact_dir.writeFile(.{
            .sub_path = spec.asset_name,
            .data = payload,
        });
        digests[index] = hashBytes(payload);
        digest_slices[index] = &digests[index];

        try writeReference(
            allocator,
            artifact_dir,
            spec.signature_ref,
            "signature-reference",
            spec.asset_name,
        );
        try writeReference(
            allocator,
            artifact_dir,
            spec.sbom_ref,
            "sbom-reference",
            spec.asset_name,
        );
        try writeReference(
            allocator,
            artifact_dir,
            spec.provenance_ref,
            "provenance-reference",
            spec.asset_name,
        );
    }

    const rendered = try release_manifest.renderV02PrereleaseResolved(allocator, .{
        .version = version,
        .build_id = args[4],
        .source_commit = args[2],
        .source_tree = args[3],
        .archive_sha256 = digest_slices,
    });
    defer allocator.free(rendered);
    try bundle_dir.writeFile(.{
        .sub_path = "resolved-manifest.json",
        .data = rendered,
    });
}

fn writeReference(
    allocator: std.mem.Allocator,
    artifact_dir: std.fs.Dir,
    path: []const u8,
    kind: []const u8,
    asset_name: []const u8,
) !void {
    const payload = try std.fmt.allocPrint(
        allocator,
        "placeholder_only=true\nkind={s}\nasset={s}\n",
        .{ kind, asset_name },
    );
    defer allocator.free(payload);
    try artifact_dir.writeFile(.{
        .sub_path = path,
        .data = payload,
    });
}

fn hashBytes(bytes: []const u8) [64]u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}
