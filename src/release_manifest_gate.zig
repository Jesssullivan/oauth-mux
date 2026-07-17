const std = @import("std");
const builtin = @import("builtin");
pub const release_manifest_module = @import("release_manifest.zig");
const release_manifest = release_manifest_module;

const max_manifest_bytes = 1024 * 1024;
const references_per_asset = 4;
const expected_reference_count =
    release_manifest.v0_2_prerelease_targets.len * references_per_asset;

pub const ExpectedCandidate = struct {
    source_commit: []const u8,
    source_tree: []const u8,
};

pub const PreOpenHook = *const fn (std.fs.Dir) anyerror!void;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len != 5) {
        std.debug.print(
            "usage: release-manifest-gate <resolved-manifest.json> <artifact-directory> <expected-source-commit> <expected-source-tree>\n",
            .{},
        );
        std.process.exit(2);
    }

    validateResolvedManifestFiles(allocator, args[1], args[2], .{
        .source_commit = args[3],
        .source_tree = args[4],
    }) catch |err| {
        std.debug.print("v0.2 bounded manifest gate rejected: {s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
    std.io.getStdOut().writer().writeAll(
        "v0.2 bounded manifest gate: pass (schema, nonempty references, exact outer digests; nonpublishing)\n",
    ) catch {};
}

pub fn validateResolvedManifestFiles(
    allocator: std.mem.Allocator,
    manifest_path: []const u8,
    artifact_root: []const u8,
    expected: ExpectedCandidate,
) !void {
    if (!atomicNoFollowSupported()) return error.AtomicNoFollowUnavailable;
    try validateExpectedCandidate(expected);

    const parent_path = std.fs.path.dirname(manifest_path) orelse ".";
    const base_name = std.fs.path.basename(manifest_path);
    if (base_name.len == 0) return error.NonRegularManifest;
    var parent = std.fs.cwd().openDir(parent_path, .{
        .no_follow = true,
    }) catch return error.NonRegularManifest;
    defer parent.close();

    var manifest_file = try openRegularNoFollow(parent, base_name, .manifest);
    defer manifest_file.close();
    const bytes = manifest_file.readToEndAlloc(allocator, max_manifest_bytes) catch
        return error.ManifestUnreadable;
    defer allocator.free(bytes);

    var parsed = std.json.parseFromSlice(
        release_manifest.V02PrereleaseManifest,
        allocator,
        bytes,
        .{},
    ) catch return error.InvalidResolvedManifest;
    defer parsed.deinit();

    try release_manifest.validateV02PrereleaseSchema(parsed.value);
    if (!std.mem.eql(u8, parsed.value.release.source_commit, expected.source_commit)) {
        return error.CandidateSourceCommitMismatch;
    }
    if (!std.mem.eql(u8, parsed.value.release.source_tree, expected.source_tree)) {
        return error.CandidateSourceTreeMismatch;
    }
    try validateArtifactDirectory(parsed.value, artifact_root);
}

pub fn validateArtifactDirectory(
    manifest: release_manifest.V02PrereleaseManifest,
    artifact_root: []const u8,
) !void {
    return validateArtifactDirectoryWithPreOpenHook(manifest, artifact_root, null);
}

pub fn validateArtifactDirectoryWithPreOpenHook(
    manifest: release_manifest.V02PrereleaseManifest,
    artifact_root: []const u8,
    pre_open_hook: ?PreOpenHook,
) !void {
    if (!atomicNoFollowSupported()) return error.AtomicNoFollowUnavailable;

    var dir = std.fs.cwd().openDir(artifact_root, .{
        .iterate = true,
        .no_follow = true,
    }) catch return error.ArtifactDirectoryUnavailable;
    defer dir.close();

    var seen = [_]bool{false} ** expected_reference_count;
    var iterator = dir.iterate();
    while (iterator.next() catch return error.ArtifactDirectoryUnreadable) |entry| {
        const reference_index = findReference(manifest, entry.name) orelse
            return error.ExtraArtifactReference;
        if (entry.kind != .file) return error.NonRegularArtifactReference;
        if (seen[reference_index]) return error.DuplicateArtifactReference;
        seen[reference_index] = true;
    }
    for (seen) |was_seen| {
        if (!was_seen) return error.MissingArtifactReference;
    }

    if (pre_open_hook) |hook| try hook(dir);

    for (manifest.release_assets) |asset| {
        try requireNonemptyRegularFile(dir, asset.signature_ref);
        try requireNonemptyRegularFile(dir, asset.sbom_ref);
        try requireNonemptyRegularFile(dir, asset.provenance_ref);
        const actual_sha256 = try hashFileSha256(dir, asset.release_name);
        if (!std.mem.eql(u8, &actual_sha256, asset.sha256)) {
            return error.AssetDigestMismatch;
        }
    }
}

fn validateExpectedCandidate(expected: ExpectedCandidate) !void {
    if (!isLowerHex(expected.source_commit, 40)) return error.InvalidExpectedSourceCommit;
    if (!isLowerHex(expected.source_tree, 40)) return error.InvalidExpectedSourceTree;
}

fn findReference(
    manifest: release_manifest.V02PrereleaseManifest,
    name: []const u8,
) ?usize {
    var index: usize = 0;
    for (manifest.release_assets) |asset| {
        for ([_][]const u8{
            asset.release_name,
            asset.signature_ref,
            asset.sbom_ref,
            asset.provenance_ref,
        }) |reference| {
            if (std.mem.eql(u8, name, reference)) return index;
            index += 1;
        }
    }
    return null;
}

fn requireNonemptyRegularFile(dir: std.fs.Dir, path: []const u8) !void {
    var file = try openRegularNoFollow(dir, path, .artifact);
    defer file.close();
    const stat = file.stat() catch return error.ArtifactReferenceUnreadable;
    if (stat.size == 0) return error.EmptyArtifactReference;
}

fn hashFileSha256(dir: std.fs.Dir, path: []const u8) ![64]u8 {
    var file = try openRegularNoFollow(dir, path, .artifact);
    defer file.close();
    const stat = file.stat() catch return error.ArtifactReferenceUnreadable;
    if (stat.size == 0) return error.EmptyArtifactReference;

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [16 * 1024]u8 = undefined;
    while (true) {
        const count = file.read(&buffer) catch return error.ArtifactReferenceUnreadable;
        if (count == 0) break;
        hasher.update(buffer[0..count]);
    }
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    hasher.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

const FileRole = enum {
    manifest,
    artifact,
};

fn atomicNoFollowSupported() bool {
    return builtin.os.tag == .linux or builtin.os.tag == .macos;
}

fn openRegularNoFollow(
    dir: std.fs.Dir,
    path: []const u8,
    comptime role: FileRole,
) !std.fs.File {
    if (comptime atomicNoFollowSupported()) {
        var flags: std.posix.O = .{
            .ACCMODE = .RDONLY,
            .NOFOLLOW = true,
        };
        if (@hasField(std.posix.O, "CLOEXEC")) flags.CLOEXEC = true;
        if (@hasField(std.posix.O, "NONBLOCK")) flags.NONBLOCK = true;
        const fd = std.posix.openat(dir.fd, path, flags, 0) catch |err| switch (err) {
            error.SymLinkLoop, error.IsDir => return nonRegularError(role),
            error.FileNotFound => return missingError(role),
            else => return unreadableError(role),
        };
        var file: std.fs.File = .{ .handle = fd };
        errdefer file.close();
        const stat = file.stat() catch return unreadableError(role);
        if (stat.kind != .file) return nonRegularError(role);
        return file;
    }
    return error.AtomicNoFollowUnavailable;
}

fn missingError(comptime role: FileRole) anyerror {
    return switch (role) {
        .manifest => error.ManifestMissing,
        .artifact => error.MissingArtifactReference,
    };
}

fn nonRegularError(comptime role: FileRole) anyerror {
    return switch (role) {
        .manifest => error.NonRegularManifest,
        .artifact => error.NonRegularArtifactReference,
    };
}

fn unreadableError(comptime role: FileRole) anyerror {
    return switch (role) {
        .manifest => error.ManifestUnreadable,
        .artifact => error.ArtifactReferenceUnreadable,
    };
}

fn isLowerHex(value: []const u8, expected_len: usize) bool {
    if (value.len != expected_len) return false;
    for (value) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return false;
    }
    return true;
}
