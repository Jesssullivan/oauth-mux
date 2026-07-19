const std = @import("std");
const release_manifest_gate = @import("release_manifest_gate");
const release_manifest = release_manifest_gate.release_manifest_module;

const commit = "0123456789abcdef0123456789abcdef01234567";
const tree = "89abcdef0123456789abcdef0123456789abcdef";
const wrong_commit = "1123456789abcdef0123456789abcdef01234567";
const wrong_tree = "99abcdef0123456789abcdef0123456789abcdef";
const version = "0.2.0-rc.1";
const build_id = "tin-3005.synthetic.1";
const expected_candidate: release_manifest_gate.ExpectedCandidate = .{
    .source_commit = commit,
    .source_tree = tree,
};
const archive_payloads = [_][]const u8{
    "synthetic x86_64 Linux archive\n",
    "synthetic aarch64 Linux archive\n",
    "synthetic x86_64 macOS archive\n",
    "synthetic aarch64 macOS archive\n",
};

const Fixture = struct {
    tmp: std.testing.TmpDir,
    manifest_path: []u8,
    artifact_root: []u8,

    fn init() !Fixture {
        const allocator = std.testing.allocator;
        var tmp = std.testing.tmpDir(.{});
        errdefer tmp.cleanup();
        try tmp.dir.makeDir("artifacts");

        var digests: [release_manifest.v0_2_prerelease_targets.len][64]u8 = undefined;
        var digest_slices: [release_manifest.v0_2_prerelease_targets.len][]const u8 = undefined;
        for (release_manifest.v0_2_prerelease_targets, 0..) |spec, index| {
            const asset_path = try std.fmt.allocPrint(
                allocator,
                "artifacts/{s}",
                .{spec.asset_name},
            );
            defer allocator.free(asset_path);
            try tmp.dir.writeFile(.{
                .sub_path = asset_path,
                .data = archive_payloads[index],
            });
            digests[index] = hashBytes(archive_payloads[index]);
            digest_slices[index] = &digests[index];

            for ([_][]const u8{
                spec.signature_ref,
                spec.sbom_ref,
                spec.provenance_ref,
            }) |reference| {
                const path = try std.fmt.allocPrint(allocator, "artifacts/{s}", .{reference});
                defer allocator.free(path);
                try tmp.dir.writeFile(.{
                    .sub_path = path,
                    .data = "synthetic nonempty reference placeholder\n",
                });
            }
        }

        const rendered = try release_manifest.renderV02PrereleaseResolved(allocator, .{
            .version = version,
            .build_id = build_id,
            .source_commit = commit,
            .source_tree = tree,
            .archive_sha256 = digest_slices,
        });
        defer allocator.free(rendered);
        try tmp.dir.writeFile(.{
            .sub_path = "resolved-manifest.json",
            .data = rendered,
        });

        const manifest_path = try tmp.dir.realpathAlloc(allocator, "resolved-manifest.json");
        errdefer allocator.free(manifest_path);
        const artifact_root = try tmp.dir.realpathAlloc(allocator, "artifacts");
        errdefer allocator.free(artifact_root);
        return .{
            .tmp = tmp,
            .manifest_path = manifest_path,
            .artifact_root = artifact_root,
        };
    }

    fn deinit(self: *Fixture) void {
        const allocator = std.testing.allocator;
        allocator.free(self.manifest_path);
        allocator.free(self.artifact_root);
        self.tmp.cleanup();
    }

    fn artifactDir(self: *Fixture) !std.fs.Dir {
        return self.tmp.dir.openDir("artifacts", .{});
    }

    fn rewrite(self: *Fixture, manifest: release_manifest.V02PrereleaseManifest) !void {
        var output = std.ArrayList(u8).init(std.testing.allocator);
        defer output.deinit();
        try std.json.stringify(manifest, .{ .whitespace = .indent_2 }, output.writer());
        try output.append('\n');
        try self.tmp.dir.writeFile(.{
            .sub_path = "resolved-manifest.json",
            .data = output.items,
        });
    }

    fn parse(self: *Fixture) !std.json.Parsed(release_manifest.V02PrereleaseManifest) {
        const bytes = try self.tmp.dir.readFileAlloc(
            std.testing.allocator,
            "resolved-manifest.json",
            1024 * 1024,
        );
        defer std.testing.allocator.free(bytes);
        return std.json.parseFromSlice(
            release_manifest.V02PrereleaseManifest,
            std.testing.allocator,
            bytes,
            .{ .allocate = .alloc_always },
        );
    }

    fn replaceManifestText(
        self: *Fixture,
        needle: []const u8,
        replacement: []const u8,
    ) !void {
        const allocator = std.testing.allocator;
        const bytes = try self.tmp.dir.readFileAlloc(
            allocator,
            "resolved-manifest.json",
            1024 * 1024,
        );
        defer allocator.free(bytes);
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, bytes, needle));
        const rewritten = try std.mem.replaceOwned(u8, allocator, bytes, needle, replacement);
        defer allocator.free(rewritten);
        try self.tmp.dir.writeFile(.{
            .sub_path = "resolved-manifest.json",
            .data = rewritten,
        });
    }
};

fn hashBytes(bytes: []const u8) [64]u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn replaceFirstArchiveWithSymlink(dir: std.fs.Dir) !void {
    const first = release_manifest.v0_2_prerelease_targets[0];
    const second = release_manifest.v0_2_prerelease_targets[1];
    try dir.deleteFile(first.asset_name);
    try dir.symLink(second.asset_name, first.asset_name, .{});
}

fn validResolvedManifest() !std.json.Parsed(release_manifest.V02PrereleaseManifest) {
    const digests = [_][]const u8{
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "4444444444444444444444444444444444444444444444444444444444444444",
    };
    const rendered = try release_manifest.renderV02PrereleaseResolved(
        std.testing.allocator,
        .{
            .version = version,
            .build_id = build_id,
            .source_commit = commit,
            .source_tree = tree,
            .archive_sha256 = digests,
        },
    );
    defer std.testing.allocator.free(rendered);
    return std.json.parseFromSlice(
        release_manifest.V02PrereleaseManifest,
        std.testing.allocator,
        rendered,
        .{ .allocate = .alloc_always },
    );
}

test "resolved v0.2 profile schema is experimental and nonpublishing" {
    var parsed = try validResolvedManifest();
    defer parsed.deinit();
    try release_manifest.validateV02PrereleaseSchema(parsed.value);
    try std.testing.expect(!parsed.value.profile.publication_enabled);
    try std.testing.expect(parsed.value.release.prerelease);
    try std.testing.expect(!parsed.value.release.make_latest);
    try std.testing.expectEqualStrings(
        "unsupported_stable_history_only",
        parsed.value.platforms.windows,
    );
    try std.testing.expectEqualStrings("omux", parsed.value.product.primary_executable);
    try std.testing.expectEqualStrings(
        "oauth-mux",
        parsed.value.product.compatibility_links[0].name,
    );
    try std.testing.expectEqualStrings(
        "omux",
        parsed.value.product.compatibility_links[0].target,
    );
    try std.testing.expectEqualStrings(
        release_manifest.compatibility_materialization,
        parsed.value.product.compatibility_links[0].materialization,
    );
    try std.testing.expectEqualStrings(
        "required_nonempty_file_only",
        parsed.value.integrity.signature_references,
    );

    const stable_rendered = try release_manifest.renderDeclaration(
        std.testing.allocator,
        "0.1.15",
    );
    defer std.testing.allocator.free(stable_rendered);
    var stable = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        stable_rendered,
        .{},
    );
    defer stable.deinit();
    const stable_compatibility = stable.value.object
        .get("product").?.object
        .get("compatibility_links").?.array.items[0].object;
    try std.testing.expectEqualStrings(
        stable_compatibility.get("materialization").?.string,
        parsed.value.product.compatibility_links[0].materialization,
    );

    const rendered = try release_manifest.renderV02PrereleaseResolved(
        std.testing.allocator,
        .{
            .version = version,
            .build_id = build_id,
            .source_commit = commit,
            .source_tree = tree,
            .archive_sha256 = .{
                "1111111111111111111111111111111111111111111111111111111111111111",
                "2222222222222222222222222222222222222222222222222222222222222222",
                "3333333333333333333333333333333333333333333333333333333333333333",
                "4444444444444444444444444444444444444444444444444444444444444444",
            },
        },
    );
    defer std.testing.allocator.free(rendered);
    try std.testing.expect(
        std.mem.indexOf(u8, rendered, "\"make_latest\": false") != null,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        std.mem.count(
            u8,
            rendered,
            "\"materialization\": \"same_bytes\"",
        ),
    );
    for ([_][]const u8{
        "\"signed\"",
        "\"members\"",
        "\"signatures\"",
    }) |unsupported_claim| {
        try std.testing.expect(std.mem.indexOf(u8, rendered, unsupported_claim) == null);
    }
}

test "resolved v0.2 profile schema rejects compatibility materialization drift and duplicate links" {
    var parsed = try validResolvedManifest();
    defer parsed.deinit();

    var links = [_]release_manifest.V02CompatibilityLink{
        parsed.value.product.compatibility_links[0],
    };
    parsed.value.product.compatibility_links = &links;
    links[0].materialization = "copied_bytes";
    try std.testing.expectError(
        error.InvalidPrereleaseProduct,
        release_manifest.validateV02PrereleaseSchema(parsed.value),
    );

    links[0].materialization = release_manifest.compatibility_materialization;
    var duplicate_links = [_]release_manifest.V02CompatibilityLink{
        links[0],
        links[0],
    };
    parsed.value.product.compatibility_links = &duplicate_links;
    try std.testing.expectError(
        error.InvalidPrereleaseProduct,
        release_manifest.validateV02PrereleaseSchema(parsed.value),
    );
}

test "resolved v0.2 profile schema rejects malformed SemVer and GA policy" {
    var parsed = try validResolvedManifest();
    defer parsed.deinit();

    parsed.value.release.version = "0.2";
    try std.testing.expectError(
        error.InvalidPrereleaseVersion,
        release_manifest.validateV02PrereleaseSchema(parsed.value),
    );
    parsed.value.release.version = "0.2.0";
    try std.testing.expectError(
        error.InvalidPrereleaseVersion,
        release_manifest.validateV02PrereleaseSchema(parsed.value),
    );
    parsed.value.release.version = version;
    parsed.value.release.prerelease = false;
    try std.testing.expectError(
        error.InvalidPrereleaseReleasePolicy,
        release_manifest.validateV02PrereleaseSchema(parsed.value),
    );
    parsed.value.release.prerelease = true;
    parsed.value.release.make_latest = true;
    try std.testing.expectError(
        error.InvalidPrereleaseReleasePolicy,
        release_manifest.validateV02PrereleaseSchema(parsed.value),
    );
}

test "resolved v0.2 profile schema requires shaped identity and exact asset set" {
    var parsed = try validResolvedManifest();
    defer parsed.deinit();
    var assets: [release_manifest.v0_2_prerelease_targets.len]release_manifest.V02PrereleaseAsset =
        undefined;
    @memcpy(&assets, parsed.value.release_assets);
    parsed.value.release_assets = &assets;

    parsed.value.release.source_commit = commit[0..39];
    try std.testing.expectError(
        error.InvalidSourceCommit,
        release_manifest.validateV02PrereleaseSchema(parsed.value),
    );
    parsed.value.release.source_commit = commit;
    parsed.value.release.source_tree = "89ABCDEF0123456789abcdef0123456789abcdef";
    try std.testing.expectError(
        error.InvalidSourceTree,
        release_manifest.validateV02PrereleaseSchema(parsed.value),
    );
    parsed.value.release.source_tree = tree;
    parsed.value.release.build_id.value = "";
    try std.testing.expectError(
        error.InvalidBuildId,
        release_manifest.validateV02PrereleaseSchema(parsed.value),
    );
    parsed.value.release.build_id.value = build_id;
    assets[0].sha256 = "abcd";
    try std.testing.expectError(
        error.InvalidAssetDigest,
        release_manifest.validateV02PrereleaseSchema(parsed.value),
    );
    assets[0].sha256 =
        "1111111111111111111111111111111111111111111111111111111111111111";
    parsed.value.release_assets = assets[0..3];
    try std.testing.expectError(
        error.InvalidPrereleaseAssetSet,
        release_manifest.validateV02PrereleaseSchema(parsed.value),
    );

    parsed.value.release_assets = &assets;
    const original_second = assets[1];
    assets[1] = assets[0];
    try std.testing.expectError(
        error.DuplicateArtifactReference,
        release_manifest.validateV02PrereleaseSchema(parsed.value),
    );
    assets[1] = original_second;

    var extra_assets: [release_manifest.v0_2_prerelease_targets.len + 1]release_manifest.V02PrereleaseAsset =
        undefined;
    @memcpy(extra_assets[0..release_manifest.v0_2_prerelease_targets.len], &assets);
    extra_assets[release_manifest.v0_2_prerelease_targets.len] = assets[0];
    parsed.value.release_assets = &extra_assets;
    try std.testing.expectError(
        error.InvalidPrereleaseAssetSet,
        release_manifest.validateV02PrereleaseSchema(parsed.value),
    );
}

test "bounded gate accepts exact candidate, nonempty references, and outer digests" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try release_manifest_gate.validateResolvedManifestFiles(
        std.testing.allocator,
        fixture.manifest_path,
        fixture.artifact_root,
        expected_candidate,
    );
}

test "bounded gate rejects missing, wrong, duplicate, and drifted compatibility materialization" {
    const field = "\"materialization\": \"same_bytes\"";
    {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        try fixture.replaceManifestText(",\n        " ++ field, "");
        try std.testing.expectError(
            error.InvalidResolvedManifest,
            release_manifest_gate.validateResolvedManifestFiles(
                std.testing.allocator,
                fixture.manifest_path,
                fixture.artifact_root,
                expected_candidate,
            ),
        );
    }
    {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        try fixture.replaceManifestText(field, "\"materialization\": false");
        try std.testing.expectError(
            error.InvalidResolvedManifest,
            release_manifest_gate.validateResolvedManifestFiles(
                std.testing.allocator,
                fixture.manifest_path,
                fixture.artifact_root,
                expected_candidate,
            ),
        );
    }
    {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        try fixture.replaceManifestText(
            field,
            field ++ ",\n        " ++ field,
        );
        try std.testing.expectError(
            error.InvalidResolvedManifest,
            release_manifest_gate.validateResolvedManifestFiles(
                std.testing.allocator,
                fixture.manifest_path,
                fixture.artifact_root,
                expected_candidate,
            ),
        );
    }
    {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        try fixture.replaceManifestText(
            field,
            "\"materialization\": \"copied_bytes\"",
        );
        try std.testing.expectError(
            error.InvalidPrereleaseProduct,
            release_manifest_gate.validateResolvedManifestFiles(
                std.testing.allocator,
                fixture.manifest_path,
                fixture.artifact_root,
                expected_candidate,
            ),
        );
    }
}

test "bounded gate rejects valid but wrong candidate commit and tree" {
    {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var parsed = try fixture.parse();
        defer parsed.deinit();
        parsed.value.release.source_commit = wrong_commit;
        try fixture.rewrite(parsed.value);
        try std.testing.expectError(
            error.CandidateSourceCommitMismatch,
            release_manifest_gate.validateResolvedManifestFiles(
                std.testing.allocator,
                fixture.manifest_path,
                fixture.artifact_root,
                expected_candidate,
            ),
        );
    }
    {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var parsed = try fixture.parse();
        defer parsed.deinit();
        parsed.value.release.source_tree = wrong_tree;
        try fixture.rewrite(parsed.value);
        try std.testing.expectError(
            error.CandidateSourceTreeMismatch,
            release_manifest_gate.validateResolvedManifestFiles(
                std.testing.allocator,
                fixture.manifest_path,
                fixture.artifact_root,
                expected_candidate,
            ),
        );
    }
}

test "bounded gate rejects malformed expected candidate inputs" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try std.testing.expectError(
        error.InvalidExpectedSourceCommit,
        release_manifest_gate.validateResolvedManifestFiles(
            std.testing.allocator,
            fixture.manifest_path,
            fixture.artifact_root,
            .{
                .source_commit = commit[0..39],
                .source_tree = tree,
            },
        ),
    );
    try std.testing.expectError(
        error.InvalidExpectedSourceTree,
        release_manifest_gate.validateResolvedManifestFiles(
            std.testing.allocator,
            fixture.manifest_path,
            fixture.artifact_root,
            .{
                .source_commit = commit,
                .source_tree = tree[0..39],
            },
        ),
    );
}

test "bounded gate rejects missing, empty, and extra references" {
    {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var artifacts = try fixture.artifactDir();
        defer artifacts.close();
        try artifacts.deleteFile(release_manifest.v0_2_prerelease_targets[0].signature_ref);
        try std.testing.expectError(
            error.MissingArtifactReference,
            release_manifest_gate.validateResolvedManifestFiles(
                std.testing.allocator,
                fixture.manifest_path,
                fixture.artifact_root,
                expected_candidate,
            ),
        );
    }
    {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var artifacts = try fixture.artifactDir();
        defer artifacts.close();
        try artifacts.writeFile(.{
            .sub_path = release_manifest.v0_2_prerelease_targets[0].provenance_ref,
            .data = "",
        });
        try std.testing.expectError(
            error.EmptyArtifactReference,
            release_manifest_gate.validateResolvedManifestFiles(
                std.testing.allocator,
                fixture.manifest_path,
                fixture.artifact_root,
                expected_candidate,
            ),
        );
    }
    {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var artifacts = try fixture.artifactDir();
        defer artifacts.close();
        try artifacts.writeFile(.{ .sub_path = "unexpected.txt", .data = "extra\n" });
        try std.testing.expectError(
            error.ExtraArtifactReference,
            release_manifest_gate.validateResolvedManifestFiles(
                std.testing.allocator,
                fixture.manifest_path,
                fixture.artifact_root,
                expected_candidate,
            ),
        );
    }
}

test "bounded gate rejects symlink replacement after directory enumeration" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var parsed = try fixture.parse();
    defer parsed.deinit();
    try std.testing.expectError(
        error.NonRegularArtifactReference,
        release_manifest_gate.validateArtifactDirectoryWithPreOpenHook(
            parsed.value,
            fixture.artifact_root,
            replaceFirstArchiveWithSymlink,
        ),
    );
}

test "bounded gate rejects duplicate references" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var parsed = try fixture.parse();
    defer parsed.deinit();
    var assets: [release_manifest.v0_2_prerelease_targets.len]release_manifest.V02PrereleaseAsset =
        undefined;
    @memcpy(&assets, parsed.value.release_assets);
    parsed.value.release_assets = &assets;
    assets[1].signature_ref = assets[0].signature_ref;
    try fixture.rewrite(parsed.value);
    try std.testing.expectError(
        error.DuplicateArtifactReference,
        release_manifest_gate.validateResolvedManifestFiles(
            std.testing.allocator,
            fixture.manifest_path,
            fixture.artifact_root,
            expected_candidate,
        ),
    );
}

test "bounded gate rejects symlink and nonregular references" {
    {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var artifacts = try fixture.artifactDir();
        defer artifacts.close();
        const spec = release_manifest.v0_2_prerelease_targets[0];
        try artifacts.deleteFile(spec.signature_ref);
        try artifacts.symLink(
            release_manifest.v0_2_prerelease_targets[1].signature_ref,
            spec.signature_ref,
            .{},
        );
        try std.testing.expectError(
            error.NonRegularArtifactReference,
            release_manifest_gate.validateResolvedManifestFiles(
                std.testing.allocator,
                fixture.manifest_path,
                fixture.artifact_root,
                expected_candidate,
            ),
        );
    }
    {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var artifacts = try fixture.artifactDir();
        defer artifacts.close();
        const reference = release_manifest.v0_2_prerelease_targets[0].sbom_ref;
        try artifacts.deleteFile(reference);
        try artifacts.makeDir(reference);
        try std.testing.expectError(
            error.NonRegularArtifactReference,
            release_manifest_gate.validateResolvedManifestFiles(
                std.testing.allocator,
                fixture.manifest_path,
                fixture.artifact_root,
                expected_candidate,
            ),
        );
    }
}

test "bounded gate rejects symlink manifests and outer digest drift" {
    {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        try fixture.tmp.dir.deleteFile("resolved-manifest.json");
        try fixture.tmp.dir.symLink(
            "artifacts/oauth-mux-x86_64-linux.tar.gz",
            "resolved-manifest.json",
            .{},
        );
        try std.testing.expectError(
            error.NonRegularManifest,
            release_manifest_gate.validateResolvedManifestFiles(
                std.testing.allocator,
                fixture.manifest_path,
                fixture.artifact_root,
                expected_candidate,
            ),
        );
    }
    {
        var fixture = try Fixture.init();
        defer fixture.deinit();
        var artifacts = try fixture.artifactDir();
        defer artifacts.close();
        try artifacts.writeFile(.{
            .sub_path = release_manifest.v0_2_prerelease_targets[0].asset_name,
            .data = "changed archive bytes\n",
        });
        try std.testing.expectError(
            error.AssetDigestMismatch,
            release_manifest_gate.validateResolvedManifestFiles(
                std.testing.allocator,
                fixture.manifest_path,
                fixture.artifact_root,
                expected_candidate,
            ),
        );
    }
}
