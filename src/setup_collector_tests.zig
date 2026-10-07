const std = @import("std");
const collector = @import("setup_collector.zig");
const evidence = @import("setup_evidence.zig");
const onboarding = @import("onboarding.zig");
const builtin = @import("builtin");
const paths = @import("paths.zig");
const c = std.c;
const self_image = @import("self_image.zig");
const metadata = @import("platform/file_metadata.zig");

test "propagated collection failure classes never collapse timeout into a read failure" {
    try std.testing.expectEqual(collector.Failure.timed_out, collector.failureForError(error.Timeout));
    try std.testing.expectEqual(collector.Failure.cancelled, collector.failureForError(error.Canceled));
    try std.testing.expectEqual(collector.Failure.resource_exhausted, collector.failureForError(error.OutOfMemory));
    try std.testing.expectEqual(collector.Failure.invalid_deadline, collector.failureForError(error.InvalidDeadline));
    try std.testing.expectEqual(collector.Failure.read_failed, collector.failureForError(error.ReadFailed));
}

test "self image diagnostic exports a finite status without code address or mapping fields" {
    const result: collector.Collected = .{ .self_image_status = .role_identity_mismatch };
    const bytes = try std.json.Stringify.valueAlloc(std.testing.allocator, result, .{});
    defer std.testing.allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, bytes, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 4), parsed.value.object.count());
    try std.testing.expectEqualStrings("role_identity_mismatch", parsed.value.object.get("self_image_status").?.string);
    try std.testing.expect(!parsed.value.object.contains("anchor") and !parsed.value.object.contains("witness") and !parsed.value.object.contains("records"));
}

test "hardlinked daemon roles cannot retain readiness after later anchor loss or change" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    const prefix = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(prefix);
    for ([_][:0]const u8{ "bin", "lib", "lib/omux", "lib/omux/libexec" }) |name| {
        if (c.mkdirat(directory.dir.handle, name.ptr, 0o700) != 0) return error.FixtureWriteFailed;
    }
    const first_path = try std.fmt.allocPrint(allocator, "{s}/bin/omuxd", .{prefix});
    defer allocator.free(first_path);
    const second_path = try std.fmt.allocPrint(allocator, "{s}/lib/omux/libexec/omuxd.bin", .{prefix});
    defer allocator.free(second_path);
    try fixtureWrite(allocator, first_path, "synthetic mapped image bytes\n", 0o755);
    if (c.linkat(directory.dir.handle, "bin/omuxd", directory.dir.handle, "lib/omux/libexec/omuxd.bin", 0) != 0) return error.FixtureWriteFailed;
    const first_fd = c.openat(directory.dir.handle, "bin/omuxd", .{ .NOFOLLOW = true, .CLOEXEC = true });
    if (first_fd < 0) return error.FixtureOpenFailed;
    defer _ = c.close(first_fd);
    const second_fd = c.openat(directory.dir.handle, "lib/omux/libexec/omuxd.bin", .{ .NOFOLLOW = true, .CLOEXEC = true });
    if (second_fd < 0) return error.FixtureOpenFailed;
    defer _ = c.close(second_fd);
    const first_file = try metadata.statFd(first_fd);
    const second_file = try metadata.statFd(second_fd);
    try std.testing.expect(first_file.nlink == 2 and std.meta.eql(first_file, second_file));
    // Synthetic anchor facts exercise the collector's commit boundary using
    // genuine hardlinked fixture FDs; this is not live executable evidence.
    const witness: self_image.Witness = .{ .anchor = 0x1000, .start = 0x1000, .end = 0x2000, .permissions = "r-xp".*, .offset = 0, .dev = first_file.dev, .ino = first_file.ino };
    for ([_]self_image.Status{ .unavailable, .read_failed, .malformed_mapping, .anchor_missing }) |lost| {
        var result: collector.Collected = .{ .artifact = .{ .payload = .matches, .ownership_record = .matches, .freshness = .current } };
        collector.applySelfImageRecheck(&result, prefix, first_path, witness, .{ .status = .observed, .witness = witness }, first_file, first_file, first_file, true);
        try std.testing.expectEqual(evidence.Probe.matches, result.artifact.running_executable);
        collector.applySelfImageRecheck(&result, prefix, second_path, witness, .{ .status = lost }, second_file, second_file, second_file, true);
        try std.testing.expectEqual(evidence.Probe.unknown, result.artifact.running_executable);
        try std.testing.expectEqual(lost, result.self_image_status);
        try std.testing.expectEqual(onboarding.State.unknown, evidence.project(result.artifact, result.service).artifact.state);
    }
    var changed = witness;
    changed.offset = 1;
    var result: collector.Collected = .{};
    collector.applySelfImageRecheck(&result, prefix, first_path, witness, .{ .status = .observed, .witness = witness }, first_file, first_file, first_file, true);
    collector.applySelfImageRecheck(&result, prefix, second_path, witness, .{ .status = .observed, .witness = changed }, second_file, second_file, second_file, true);
    try std.testing.expectEqual(evidence.Probe.unknown, result.artifact.running_executable);
    try std.testing.expectEqual(self_image.Status.mapping_changed, result.self_image_status);
}

const digest = "1111111111111111111111111111111111111111111111111111111111111111";
const files = [_]collector.Entry{
    .{ .path = "/opt/omux/bin/omux", .sha256 = digest, .mode = 0o755 },
    .{ .path = "/opt/omux/bin/omuxd", .sha256 = digest, .mode = 0o755 },
    .{ .path = "/opt/omux/bin/omux-native-host", .sha256 = digest, .mode = 0o755 },
};
fn valid() collector.Receipt {
    return .{ .schemaVersion = 1, .prefix = "/opt/omux", .files = &files };
}

test "packaged prefix without receipt remains unobserved while explicit record needs prefix" {
    try std.testing.expect((try collector.selectInstallationHints(null, null)) == null);
    try std.testing.expect((try collector.selectInstallationHints("/opt/omux", null)) == null);
    try std.testing.expectError(error.InvalidInstallationSelection, collector.selectInstallationHints(null, "/owned/install.json"));
    const selected = (try collector.selectInstallationHints("/opt/omux", "/owned/install.json")) orelse return error.MissingSelection;
    try std.testing.expectEqualStrings("/opt/omux", selected.prefix);
    try std.testing.expectEqualStrings("/owned/install.json", selected.receipt_path);
    // Selection strings do not contain an ownership or readiness assertion.
    try std.testing.expectEqual(onboarding.Ownership.unknown, evidence.project(.{}, .{}).ownership);
}

test "explicit complete installation selectors retain strict bounded path validation" {
    for ([_][]const u8{ "", "relative", "/opt/../other", "/opt/omux/" }) |unsafe| {
        try std.testing.expectError(error.InvalidInstallationSelection, collector.selectInstallationHints(unsafe, "/owned/install.json"));
        try std.testing.expectError(error.InvalidInstallationSelection, collector.selectInstallationHints("/opt/omux", unsafe));
    }
    var oversized: [collector.max_path_bytes + 1]u8 = @splat('a');
    oversized[0] = '/';
    try std.testing.expectError(error.InvalidInstallationSelection, collector.selectInstallationHints(&oversized, "/owned/install.json"));
    try std.testing.expectError(error.InvalidInstallationSelection, collector.selectInstallationHints("/opt/omux", &oversized));
}
test "receipt filenames do not establish ownership without exact prefix and required components" {
    try collector.validateReceipt(valid(), "/opt/omux", null);
    try std.testing.expectError(error.InvalidReceipt, collector.validateReceipt(valid(), "/opt/other", null));
    var receipt = valid();
    receipt.files = files[0..2];
    try std.testing.expectError(error.InvalidReceipt, collector.validateReceipt(receipt, "/opt/omux", null));
}
test "receipt cannot nominate arbitrary service path or traversal" {
    var receipt = valid();
    receipt.userService = "/home/operator/private-file";
    try std.testing.expectError(error.InvalidReceipt, collector.validateReceipt(receipt, "/opt/omux", null));
    var invalid = files;
    invalid[2].path = "/opt/omux/../private-file";
    receipt = valid();
    receipt.files = &invalid;
    try std.testing.expectError(error.InvalidReceipt, collector.validateReceipt(receipt, "/opt/omux", null));
}
test "prefix sibling digest mode and duplicate entry validation deny forged inventory" {
    var invalid = files;
    var receipt = valid();
    receipt.files = &invalid;
    invalid[2].path = "/opt/omux-other/bin/omux-native-host";
    try std.testing.expectError(error.InvalidReceipt, collector.validateReceipt(receipt, "/opt/omux", null));
    invalid = files;
    invalid[2].sha256 = "not-a-digest";
    try std.testing.expectError(error.InvalidReceipt, collector.validateReceipt(receipt, "/opt/omux", null));
    invalid = files;
    invalid[2].mode = 0o777;
    try std.testing.expectError(error.InvalidReceipt, collector.validateReceipt(receipt, "/opt/omux", null));
    invalid = files;
    invalid[2] = invalid[0];
    try std.testing.expectError(error.InvalidReceipt, collector.validateReceipt(receipt, "/opt/omux", null));
}
test "legacy serviceActivated field remains declaration rather than live service evidence" {
    var receipt = valid();
    receipt.serviceActivated = true;
    try collector.validateReceipt(receipt, "/opt/omux", null);
    const collected: collector.Collected = .{};
    try std.testing.expectEqual(@TypeOf(collected.service.login_enabled).unknown, collected.service.login_enabled);
    try std.testing.expectEqual(@TypeOf(collected.service.responder_binding).unknown, collected.service.responder_binding);
}

test "legacy and explicit unknown channels stay unknown and malformed metadata fails" {
    var receipt = valid();
    try std.testing.expectEqual(onboarding.Channel.unknown, try collector.receiptChannel(receipt));
    receipt.artifact = .{ .channel = "unknown", .manifestSha256 = digest, .archiveSha256 = digest };
    try std.testing.expectEqual(onboarding.Channel.unknown, try collector.receiptChannel(receipt));
    receipt.artifact.?.channel = "development";
    try std.testing.expectEqual(onboarding.Channel.development, try collector.receiptChannel(receipt));
    receipt.artifact.?.manifestSha256 = "bad";
    try std.testing.expectError(error.InvalidReceipt, collector.validateReceipt(receipt, "/opt/omux", null));
}

test "Nix-looking paths and unknown ownership labels cannot claim Home Manager" {
    var receipt = valid();
    receipt.owner = "home-manager";
    try std.testing.expectError(error.InvalidReceipt, collector.validateReceipt(receipt, "/opt/omux", null));
    receipt.owner = "other-manager";
    try std.testing.expectError(error.InvalidReceipt, collector.receiptOwnership(receipt));
    receipt.owner = null;
    try std.testing.expectEqual(onboarding.Ownership.installation_receipt, try collector.receiptOwnership(receipt));
}

test "mismatches dominate missing regardless of file scan order" {
    try std.testing.expectEqual(evidence.Probe.differs, collector.mergeProbe(.differs, .absent));
    try std.testing.expectEqual(evidence.Probe.differs, collector.mergeProbe(.absent, .differs));
    try std.testing.expectEqual(evidence.Probe.absent, collector.mergeProbe(.absent, .matches));
    try std.testing.expectEqual(evidence.Probe.unknown, collector.mergeProbe(.unknown, .matches));
}

fn fixtureWrite(allocator: std.mem.Allocator, path: []const u8, bytes: []const u8, mode: c.mode_t) !void {
    const name = try allocator.dupeSentinel(u8, path, 0);
    defer allocator.free(name);
    const fd = c.open(name.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true, .NOFOLLOW = true, .CLOEXEC = true }, mode);
    if (fd < 0) return error.FixtureWriteFailed;
    defer _ = c.close(fd);
    if (c.fchmod(fd, mode) != 0) return error.FixtureWriteFailed;
    var cursor: usize = 0;
    while (cursor < bytes.len) {
        const count = c.write(fd, bytes[cursor..].ptr, bytes.len - cursor);
        if (count <= 0) return error.FixtureWriteFailed;
        cursor += @intCast(count);
    }
}

test "real collector verifies bytes but fixture inventory cannot prove current executable or service" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var nonce: [8]u8 = undefined;
    io.random(&nonce);
    const base = try std.fmt.allocPrint(allocator, "{s}/omux-collector-{s}", .{ if (builtin.os.tag == .macos) "/private/tmp" else "/tmp", std.fmt.bytesToHex(nonce, .lower) });
    defer std.Io.Dir.cwd().deleteTree(io, base) catch |err| std.log.err("collector fixture cleanup failed: {s}", .{@errorName(err)});
    const root = try paths.openPrivateRoot(allocator, base, true);
    defer _ = c.close(root);
    if (c.mkdirat(root, "bin", 0o700) != 0) return error.FixtureWriteFailed;
    const payload = "synthetic executable fixture\n";
    var payload_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &payload_digest, .{});
    const payload_hex = std.fmt.bytesToHex(payload_digest, .lower);
    var entries: [3]collector.Entry = undefined;
    for ([_][]const u8{ "omux", "omuxd", "omux-native-host" }, 0..) |name, index| {
        const path = try std.fmt.allocPrint(allocator, "{s}/bin/{s}", .{ base, name });
        try fixtureWrite(allocator, path, payload, 0o755);
        entries[index] = .{ .path = path, .sha256 = &payload_hex, .mode = 0o755 };
    }
    const receipt_path = try std.fmt.allocPrint(allocator, "{s}/install.json", .{base});
    const receipt = collector.Receipt{ .schemaVersion = 1, .prefix = base, .files = &entries, .serviceActivated = true };
    const bytes = try std.json.Stringify.valueAlloc(allocator, receipt, .{});
    try fixtureWrite(allocator, receipt_path, bytes, 0o600);
    const options = collector.Options{ .prefix = base, .receipt_path = receipt_path, .deadline = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) }) };
    const result = try collector.collect(io, allocator, options);
    try std.testing.expectEqual(collector.Failure.none, result.failure);
    try std.testing.expectEqual(evidence.Probe.matches, result.artifact.payload);
    try std.testing.expectEqual(evidence.Probe.unknown, result.artifact.running_executable);
    try std.testing.expectEqual(evidence.Probe.unknown, result.service.login_enabled);
    try std.testing.expectEqual(onboarding.Channel.unknown, evidence.project(result.artifact, result.service).installed_channel);
    // Private mutable ownership records never inherit the Nix hardlink policy.
    if (c.linkat(root, "install.json", root, "private-record-alias", 0) != 0) return error.FixtureWriteFailed;
    var private_refresh = options;
    private_refresh.deadline = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) });
    try std.testing.expectEqual(collector.Failure.unsafe_file, (try collector.collect(io, allocator, private_refresh)).failure);
    if (c.unlinkat(root, "private-record-alias", 0) != 0) return error.FixtureWriteFailed;
    // A modified early member and absent later member must retain the mismatch.
    try fixtureWrite(allocator, entries[0].path, "modified fixture\n", 0o755);
    const absent = try allocator.dupeSentinel(u8, entries[2].path, 0);
    if (c.unlink(absent.ptr) != 0) return error.FixtureWriteFailed;
    var refresh = options;
    refresh.deadline = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) });
    const changed = try collector.collect(io, allocator, refresh);
    try std.testing.expectEqual(evidence.Probe.differs, changed.artifact.payload);
    // Receipt mode is a custody predicate even when its JSON is otherwise valid.
    try fixtureWrite(allocator, receipt_path, bytes, 0o644);
    refresh.deadline = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) });
    try std.testing.expectEqual(collector.Failure.unsafe_file, (try collector.collect(io, allocator, refresh)).failure);
}

test "verified definition and persistent link remain internal and cannot establish service process readiness" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var nonce: [8]u8 = undefined;
    io.random(&nonce);
    const base = try std.fmt.allocPrint(allocator, "{s}/omux-service-evidence-{s}", .{ if (builtin.os.tag == .macos) "/private/tmp" else "/tmp", std.fmt.bytesToHex(nonce, .lower) });
    defer std.Io.Dir.cwd().deleteTree(io, base) catch |err| std.log.err("service fixture cleanup failed: {s}", .{@errorName(err)});
    const root = try paths.openPrivateRoot(allocator, base, true);
    defer _ = c.close(root);
    if (c.mkdirat(root, "bin", 0o700) != 0 or c.mkdirat(root, "default.target.wants", 0o700) != 0) return error.FixtureWriteFailed;
    const payload = "synthetic service evidence fixture\n";
    var payload_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &payload_digest, .{});
    const payload_hex = std.fmt.bytesToHex(payload_digest, .lower);
    var entries: [4]collector.Entry = undefined;
    for ([_][]const u8{ "bin/omux", "bin/omuxd", "bin/omux-native-host", "ai.xoxd.omux.service" }, 0..) |name, index| {
        const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ base, name });
        const mode: c.mode_t = if (index == 3) 0o644 else 0o755;
        try fixtureWrite(allocator, path, payload, mode);
        entries[index] = .{ .path = path, .sha256 = &payload_hex, .mode = mode };
    }
    if (c.symlinkat("../ai.xoxd.omux.service", root, "default.target.wants/ai.xoxd.omux.service") != 0) return error.FixtureWriteFailed;
    const receipt_path = try std.fmt.allocPrint(allocator, "{s}/install.json", .{base});
    const receipt = collector.Receipt{ .schemaVersion = 1, .prefix = base, .files = &entries, .userService = entries[3].path };
    const bytes = try std.json.Stringify.valueAlloc(allocator, receipt, .{});
    try fixtureWrite(allocator, receipt_path, bytes, 0o600);
    const result = try collector.collect(io, allocator, .{ .prefix = base, .receipt_path = receipt_path, .service_path = entries[3].path, .deadline = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) }) });
    try std.testing.expectEqual(collector.Failure.none, result.failure);
    try std.testing.expectEqual(evidence.Probe.matches, result.service.definition);
    const witness = result.service_witness orelse return error.MissingServiceWitness;
    try std.testing.expectEqual(evidence.Probe.matches, witness.login_link);
    try std.testing.expectEqual(evidence.Probe.unknown, result.service.login_enabled);
    try std.testing.expectEqual(evidence.Probe.unknown, result.service.responder_binding);
    const redacted = try std.json.Stringify.valueAlloc(allocator, result, .{});
    try std.testing.expect(std.mem.indexOf(u8, redacted, base) == null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "service_witness") == null);
    if (c.unlinkat(root, "default.target.wants/ai.xoxd.omux.service", 0) != 0 or c.symlinkat(witness.fragment().ptr, root, "default.target.wants/ai.xoxd.omux.service") != 0) return error.FixtureWriteFailed;
    try std.testing.expectEqual(evidence.Probe.matches, try collector.recheckLoginLink(io, allocator, &witness, .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) })));
    try fixtureWrite(allocator, entries[3].path, "changed service fixture\n", 0o644);
    try std.testing.expectEqual(evidence.Probe.differs, try collector.recheckServiceWitness(io, allocator, &witness, .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) })));
    // Lexically normalizing this target produces the verified fragment, but
    // the kernel follows alias into bin, then .. reaches the fixture root,
    // then the extra .. reaches its parent. This is a different lookup.
    const lexical = try std.fs.path.resolveAlloc(allocator, &.{ base, "default.target.wants/alias/../../ai.xoxd.omux.service" });
    try std.testing.expectEqualStrings(witness.fragment(), lexical);
    if (c.symlinkat("../bin", root, "default.target.wants/alias") != 0) return error.FixtureWriteFailed;
    if (c.unlinkat(root, "default.target.wants/ai.xoxd.omux.service", 0) != 0 or c.symlinkat("alias/../../ai.xoxd.omux.service", root, "default.target.wants/ai.xoxd.omux.service") != 0) return error.FixtureWriteFailed;
    try std.testing.expectEqual(evidence.Probe.differs, try collector.recheckLoginLink(io, allocator, &witness, .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) })));
    if (c.unlinkat(root, "default.target.wants/ai.xoxd.omux.service", 0) != 0 or c.symlinkat("../bin/omux", root, "default.target.wants/ai.xoxd.omux.service") != 0) return error.FixtureWriteFailed;
    try std.testing.expectEqual(evidence.Probe.differs, try collector.recheckLoginLink(io, allocator, &witness, .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) })));
}

fn fixtureRecord(allocator: std.mem.Allocator, path: []const u8, record: collector.ServiceRecord) !void {
    const name = try allocator.dupeSentinel(u8, path, 0);
    defer allocator.free(name);
    if (c.unlink(name.ptr) != 0 and c.errno(-1) != .NOENT) return error.FixtureWriteFailed;
    const bytes = try std.json.Stringify.valueAlloc(allocator, record, .{});
    defer allocator.free(bytes);
    try fixtureWrite(allocator, path, bytes, 0o444);
}

test "managed direct link custody requires record binding immutable bytes and exact source chain" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    var nonce: [8]u8 = undefined;
    io.random(&nonce);
    const base = try std.fmt.allocPrint(allocator, "{s}/omux-managed-service-{s}", .{ if (builtin.os.tag == .macos) "/private/tmp" else "/tmp", std.fmt.bytesToHex(nonce, .lower) });
    defer std.Io.Dir.cwd().deleteTree(io, base) catch |err| std.log.err("managed fixture cleanup failed: {s}", .{@errorName(err)});
    const root = try paths.openPrivateRoot(allocator, base, true);
    defer _ = c.close(root);
    for ([_][:0]const u8{ "store", "systemd", "systemd/user", "systemd/user/default.target.wants" }) |directory| {
        if (c.mkdirat(root, directory.ptr, 0o700) != 0) return error.FixtureWriteFailed;
    }
    const store = try std.fmt.allocPrint(allocator, "{s}/store", .{base});
    const source = try std.fmt.allocPrint(allocator, "{s}/unit.service", .{store});
    const source_z = try allocator.dupeSentinel(u8, source, 0);
    const installed = try std.fmt.allocPrint(allocator, "{s}/systemd/user/ai.xoxd.omux.service", .{base});
    const login = try std.fmt.allocPrint(allocator, "{s}/systemd/user/default.target.wants/ai.xoxd.omux.service", .{base});
    const record_path = try std.fmt.allocPrint(allocator, "{s}/service-record.json", .{store});
    const payload = "[Service]\nExecStart=/synthetic/fixture daemon\n";
    var unit_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &unit_digest, .{});
    const unit_hex = std.fmt.bytesToHex(unit_digest, .lower);
    try fixtureWrite(allocator, source, payload, 0o444);
    if (c.symlinkat(source_z.ptr, root, "systemd/user/ai.xoxd.omux.service") != 0 or c.symlinkat("../ai.xoxd.omux.service", root, "systemd/user/default.target.wants/ai.xoxd.omux.service") != 0) return error.FixtureWriteFailed;
    var record: collector.ServiceRecord = .{ .schemaVersion = 1, .owner = "home-manager", .channel = "release", .instance = "default", .artifactManifestSha256 = digest, .unit = .{ .name = "ai.xoxd.omux.service", .installedPath = installed, .sourcePath = source, .sha256 = &unit_hex, .mode = 0o644 }, .login = .{ .installedPath = login, .sourcePath = source }, .scope = "definition-only-not-activation" };
    const artifact = collector.Receipt{ .schemaVersion = 1, .prefix = store, .owner = "home-manager", .artifact = .{ .channel = "release", .manifestSha256 = digest }, .files = &.{} };
    var options = collector.Options{ .prefix = store, .receipt_path = "unused-fixture-selector", .service_path = installed, .service_record_path = record_path, .deadline = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) }) };
    try fixtureRecord(allocator, record_path, record);
    const witness = (try collector.managedDefinitionFixture(io, allocator, artifact, options, store)) orelse return error.MissingServiceWitness;
    try std.testing.expectEqual(evidence.Probe.matches, witness.login_link);
    const partial: collector.Collected = .{ .service_witness = witness, .service = .{ .definition = .matches, .freshness = .current } };
    try std.testing.expectEqual(onboarding.State.unknown, evidence.project(partial.artifact, partial.service).service.state);
    record.channel = "development";
    try fixtureRecord(allocator, record_path, record);
    options.deadline = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) });
    try std.testing.expect((try collector.managedDefinitionFixture(io, allocator, artifact, options, store)) == null);
    record.channel = "release";
    record.artifactManifestSha256 = "2222222222222222222222222222222222222222222222222222222222222222";
    try fixtureRecord(allocator, record_path, record);
    options.deadline = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) });
    try std.testing.expect((try collector.managedDefinitionFixture(io, allocator, artifact, options, store)) == null);
    record.artifactManifestSha256 = digest;
    try fixtureRecord(allocator, record_path, record);
    const source_fd = c.open(source_z.ptr, .{ .CLOEXEC = true });
    if (source_fd < 0) return error.FixtureWriteFailed;
    defer _ = c.close(source_fd);
    if (c.fchmod(source_fd, 0o644) != 0) return error.FixtureWriteFailed;
    options.deadline = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) });
    try std.testing.expect((try collector.managedDefinitionFixture(io, allocator, artifact, options, store)) == null);
    if (c.fchmod(source_fd, 0o444) != 0) return error.FixtureWriteFailed;
    // Same source text through an intermediary is deliberately unsupported.
    if (c.symlinkat(source_z.ptr, root, "store/intermediary") != 0) return error.FixtureWriteFailed;
    const intermediary = try std.fmt.allocPrint(allocator, "{s}/intermediary", .{store});
    const intermediary_z = try allocator.dupeSentinel(u8, intermediary, 0);
    if (c.unlinkat(root, "systemd/user/ai.xoxd.omux.service", 0) != 0 or c.symlinkat(intermediary_z.ptr, root, "systemd/user/ai.xoxd.omux.service") != 0) return error.FixtureWriteFailed;
    options.deadline = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) });
    try std.testing.expect((try collector.managedDefinitionFixture(io, allocator, artifact, options, store)) == null);
    try std.testing.expectEqual(evidence.Probe.differs, try collector.recheckServiceWitness(io, allocator, &witness, options.deadline));
}

const hm_generation = "00000000000000000000000000000000-home-manager-files";
const hm_other_generation = "33333333333333333333333333333333-home-manager-files";
const hm_unit_directory = "11111111111111111111111111111111-ai.xoxd.omux.service";
const hm_record_name = "22222222222222222222222222222222-omux-release-service.json";
const hm_unit_relative = ".config/systemd/user/ai.xoxd.omux.service";
const hm_login_relative = ".config/systemd/user/default.target.wants/ai.xoxd.omux.service";
const hm_record_relative = ".config/omux/instances/release/service.json";
const hm_payload = "[Service]\nExecStart=/synthetic/home-manager-fixture daemon\n";

fn fixtureLink(allocator: std.mem.Allocator, path: []const u8, target: []const u8) !void {
    const name = try allocator.dupeSentinel(u8, path, 0);
    defer allocator.free(name);
    const target_z = try allocator.dupeSentinel(u8, target, 0);
    defer allocator.free(target_z);
    if (c.unlink(name.ptr) != 0 and c.errno(-1) != .NOENT) return error.FixtureWriteFailed;
    if (c.symlinkat(target_z.ptr, c.AT.FDCWD, name.ptr) != 0) return error.FixtureWriteFailed;
}

fn fixtureHardlink(allocator: std.mem.Allocator, source: []const u8, alias: []const u8) !void {
    const source_z = try allocator.dupeSentinel(u8, source, 0);
    defer allocator.free(source_z);
    const alias_z = try allocator.dupeSentinel(u8, alias, 0);
    defer allocator.free(alias_z);
    if (c.linkat(c.AT.FDCWD, source_z.ptr, c.AT.FDCWD, alias_z.ptr, 0) != 0) return error.FixtureWriteFailed;
}

// These are modeled immutable store directories owned by the fixture user.
// Production always requires root custody in /nix/store; this never activates HM.
const HmFixture = struct {
    allocator: std.mem.Allocator,
    base: []const u8,
    root: c.fd_t,
    store: []const u8,
    source: []const u8,
    record_source: []const u8,
    installed: []const u8,
    login: []const u8,
    record: []const u8,
    generation_unit: []const u8,
    generation_login: []const u8,
    generation_record: []const u8,
    immutable_directories: []const []const u8,

    fn init(allocator: std.mem.Allocator) !HmFixture {
        const io = std.testing.io;
        var nonce: [8]u8 = undefined;
        io.random(&nonce);
        const base = try std.fmt.allocPrint(allocator, "{s}/omux-hm-leaves-{s}", .{ if (builtin.os.tag == .macos) "/private/tmp" else "/tmp", std.fmt.bytesToHex(nonce, .lower) });
        const root = try paths.openPrivateRoot(allocator, base, true);
        errdefer _ = c.close(root);
        errdefer std.Io.Dir.cwd().deleteTree(io, base) catch |err| std.log.err("HM fixture initialization cleanup failed: {s}", .{@errorName(err)});
        for ([_][:0]const u8{ "store", "home", "home/.config", "home/.config/systemd", "home/.config/systemd/user", "home/.config/systemd/user/default.target.wants", "home/.config/omux", "home/.config/omux/instances", "home/.config/omux/instances/release" }) |directory| {
            if (c.mkdirat(root, directory.ptr, 0o700) != 0) return error.FixtureWriteFailed;
        }
        var immutable: std.array_list.Managed([]const u8) = .init(allocator);
        for ([_][]const u8{ hm_generation, hm_other_generation }) |generation| {
            for ([_][]const u8{ "", "/.config", "/.config/systemd", "/.config/systemd/user", "/.config/systemd/user/default.target.wants", "/.config/omux", "/.config/omux/instances", "/.config/omux/instances/release" }) |suffix| {
                const directory = try std.fmt.allocPrint(allocator, "store/{s}{s}", .{ generation, suffix });
                const name = try allocator.dupeSentinel(u8, directory, 0);
                if (c.mkdirat(root, name.ptr, 0o700) != 0) return error.FixtureWriteFailed;
                try immutable.append(directory);
            }
        }
        const unit_directory = try std.fmt.allocPrint(allocator, "store/{s}", .{hm_unit_directory});
        const unit_name = try allocator.dupeSentinel(u8, unit_directory, 0);
        if (c.mkdirat(root, unit_name.ptr, 0o700) != 0) return error.FixtureWriteFailed;
        try immutable.append(unit_directory);
        const store = try std.fmt.allocPrint(allocator, "{s}/store", .{base});
        const fixture: HmFixture = .{
            .allocator = allocator,
            .base = base,
            .root = root,
            .store = store,
            .source = try std.fmt.allocPrint(allocator, "{s}/{s}/ai.xoxd.omux.service", .{ store, hm_unit_directory }),
            .record_source = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ store, hm_record_name }),
            .installed = try std.fmt.allocPrint(allocator, "{s}/home/{s}", .{ base, hm_unit_relative }),
            .login = try std.fmt.allocPrint(allocator, "{s}/home/{s}", .{ base, hm_login_relative }),
            .record = try std.fmt.allocPrint(allocator, "{s}/home/{s}", .{ base, hm_record_relative }),
            .generation_unit = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}", .{ store, hm_generation, hm_unit_relative }),
            .generation_login = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}", .{ store, hm_generation, hm_login_relative }),
            .generation_record = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}", .{ store, hm_generation, hm_record_relative }),
            .immutable_directories = try immutable.toOwnedSlice(),
        };
        try fixtureWrite(allocator, fixture.source, hm_payload, 0o444);
        var unit_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(hm_payload, &unit_digest, .{});
        const unit_hex = std.fmt.bytesToHex(unit_digest, .lower);
        try fixtureRecord(allocator, fixture.record_source, .{
            .schemaVersion = 1,
            .owner = "home-manager",
            .channel = "release",
            .instance = "default",
            .artifactManifestSha256 = digest,
            .unit = .{ .name = "ai.xoxd.omux.service", .installedPath = fixture.installed, .sourcePath = fixture.source, .sha256 = &unit_hex, .mode = 0o644 },
            .login = .{ .installedPath = fixture.login, .sourcePath = fixture.source },
            .scope = "definition-only-not-activation",
        });
        for ([_][]const u8{ hm_generation, hm_other_generation }) |generation| {
            const unit = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}", .{ store, generation, hm_unit_relative });
            const login = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}", .{ store, generation, hm_login_relative });
            const record = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}", .{ store, generation, hm_record_relative });
            try fixtureLink(allocator, unit, fixture.source);
            try fixtureLink(allocator, login, fixture.source);
            try fixtureLink(allocator, record, fixture.record_source);
        }
        try fixtureLink(allocator, fixture.installed, fixture.generation_unit);
        try fixtureLink(allocator, fixture.login, fixture.generation_login);
        try fixtureLink(allocator, fixture.record, fixture.generation_record);
        errdefer fixture.setImmutable(false) catch |err| std.log.err("HM fixture permission cleanup failed: {s}", .{@errorName(err)});
        try fixture.setImmutable(true);
        return fixture;
    }

    fn setImmutable(self: *const HmFixture, immutable: bool) !void {
        for (self.immutable_directories) |directory| {
            const name = try self.allocator.dupeSentinel(u8, directory, 0);
            defer self.allocator.free(name);
            if (c.fchmodat(self.root, name.ptr, if (immutable) @as(c.mode_t, 0o555) else @as(c.mode_t, 0o700), 0) != 0) return error.FixtureWriteFailed;
        }
    }

    fn deinit(self: *const HmFixture) void {
        self.setImmutable(false) catch |err| std.log.err("HM fixture permission cleanup failed: {s}", .{@errorName(err)});
        _ = c.close(self.root);
        std.Io.Dir.cwd().deleteTree(std.testing.io, self.base) catch |err| std.log.err("HM fixture cleanup failed: {s}", .{@errorName(err)});
    }

    fn observe(self: *const HmFixture) !?collector.ServiceWitness {
        const artifact: collector.Receipt = .{ .schemaVersion = 1, .prefix = self.store, .owner = "home-manager", .artifact = .{ .channel = "release", .manifestSha256 = digest }, .files = &.{} };
        return collector.managedDefinitionFixture(std.testing.io, self.allocator, artifact, .{
            .prefix = self.store,
            .receipt_path = "unused-fixture-selector",
            .service_path = self.installed,
            .service_record_path = self.record,
            .deadline = .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) }),
        }, self.store);
    }

    fn recheck(self: *const HmFixture, witness: *const collector.ServiceWitness) !evidence.Probe {
        return collector.recheckServiceWitness(std.testing.io, self.allocator, witness, .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) }));
    }

    fn recheckLogin(self: *const HmFixture, witness: *const collector.ServiceWitness) !evidence.Probe {
        return collector.recheckLoginLink(std.testing.io, self.allocator, witness, .fromNow(std.testing.io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) }));
    }
};

test "modeled pinned HM record unit and login generation leaves verify without activation claims" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const fixture = try HmFixture.init(arena.allocator());
    defer fixture.deinit();
    const witness = (try fixture.observe()) orelse return error.MissingServiceWitness;
    try std.testing.expectEqual(evidence.Probe.matches, witness.login_link);
    try std.testing.expectEqual(evidence.Probe.matches, try fixture.recheck(&witness));
    try std.testing.expectEqual(evidence.Probe.matches, try fixture.recheckLogin(&witness));
    const collected: collector.Collected = .{ .service_witness = witness, .service = .{ .definition = .matches, .freshness = .current } };
    try std.testing.expectEqual(onboarding.State.unknown, evidence.project(collected.artifact, collected.service).service.state);
    const redacted = try std.json.Stringify.valueAlloc(arena.allocator(), collected, .{});
    try std.testing.expect(std.mem.indexOf(u8, redacted, fixture.base) == null);
    try std.testing.expect(std.mem.indexOf(u8, redacted, "managed") == null);
    // The store root can gain unrelated objects while immutable parents remain.
    const unrelated = try std.fmt.allocPrint(arena.allocator(), "{s}/unrelated", .{fixture.store});
    try fixtureWrite(arena.allocator(), unrelated, "unrelated store object", 0o444);
    try std.testing.expectEqual(evidence.Probe.matches, try fixture.recheck(&witness));
}

test "HM generation readback detects identical installed-link replacement and record replacement" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const fixture = try HmFixture.init(allocator);
    defer fixture.deinit();
    const witness = (try fixture.observe()) orelse return error.MissingServiceWitness;
    // Same bytes/target are insufficient after the selected inode changes.
    try fixtureLink(allocator, fixture.installed, fixture.generation_unit);
    try std.testing.expectEqual(evidence.Probe.differs, try fixture.recheck(&witness));
    const refreshed = (try fixture.observe()) orelse return error.MissingServiceWitness;
    try fixtureLink(allocator, fixture.record, fixture.generation_record);
    try std.testing.expectEqual(evidence.Probe.differs, try fixture.recheck(&refreshed));
}

test "optimized immutable HM records and units preserve definition custody and detect link drift" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const fixture = try HmFixture.init(allocator);
    defer fixture.deinit();
    const record_alias = try std.fmt.allocPrint(allocator, "{s}/optimized-record", .{fixture.store});
    const unit_alias = try std.fmt.allocPrint(allocator, "{s}/optimized-unit", .{fixture.store});
    try fixtureHardlink(allocator, fixture.record_source, record_alias);
    try fixtureHardlink(allocator, fixture.source, unit_alias);
    const witness = (try fixture.observe()) orelse return error.MissingServiceWitness;
    try std.testing.expectEqual(@as(u64, 2), witness.file.nlink);
    try std.testing.expectEqual(evidence.Probe.matches, try fixture.recheck(&witness));
    try std.testing.expectEqual(evidence.Probe.matches, try fixture.recheckLogin(&witness));
    const projected = evidence.project(.{}, .{ .definition = .matches, .freshness = .current });
    try std.testing.expectEqual(onboarding.State.unknown, projected.service.state);
    const added_alias = try std.fmt.allocPrint(allocator, "{s}/later-record-alias", .{fixture.store});
    try fixtureHardlink(allocator, fixture.record_source, added_alias);
    try std.testing.expectEqual(evidence.Probe.differs, try fixture.recheck(&witness));
    const refreshed = (try fixture.observe()) orelse return error.MissingServiceWitness;
    const unit_alias_z = try allocator.dupeSentinel(u8, unit_alias, 0);
    if (c.unlink(unit_alias_z.ptr) != 0) return error.FixtureWriteFailed;
    try std.testing.expectEqual(evidence.Probe.differs, try fixture.recheck(&refreshed));
    const current = (try fixture.observe()) orelse return error.MissingServiceWitness;
    const record_alias_z = try allocator.dupeSentinel(u8, record_alias, 0);
    if (c.chmod(record_alias_z.ptr, 0o644) != 0) return error.FixtureWriteFailed;
    try std.testing.expect((try fixture.observe()) == null);
    try std.testing.expectEqual(evidence.Probe.differs, try fixture.recheck(&current));
}

test "HM record and login cannot mix immutable generations even with identical source bytes" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const fixture = try HmFixture.init(allocator);
    defer fixture.deinit();
    const witness = (try fixture.observe()) orelse return error.MissingServiceWitness;
    const other_record = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}", .{ fixture.store, hm_other_generation, hm_record_relative });
    try fixtureLink(allocator, fixture.record, other_record);
    try std.testing.expect((try fixture.observe()) == null);
    try std.testing.expectEqual(evidence.Probe.differs, try fixture.recheck(&witness));
    try fixtureLink(allocator, fixture.record, fixture.generation_record);
    const refreshed = (try fixture.observe()) orelse return error.MissingServiceWitness;
    const other_login = try std.fmt.allocPrint(allocator, "{s}/{s}/{s}", .{ fixture.store, hm_other_generation, hm_login_relative });
    try fixtureLink(allocator, fixture.login, other_login);
    const wrong_login = (try fixture.observe()) orelse return error.MissingServiceWitness;
    try std.testing.expectEqual(evidence.Probe.differs, wrong_login.login_link);
    try std.testing.expectEqual(evidence.Probe.differs, try fixture.recheckLogin(&refreshed));
    // A relative link is supported by the direct fixture, but cannot replace
    // the exact generation leaf after a managed-generation witness was taken.
    try fixtureLink(allocator, fixture.login, "../ai.xoxd.omux.service");
    const relative_login = (try fixture.observe()) orelse return error.MissingServiceWitness;
    try std.testing.expectEqual(evidence.Probe.differs, relative_login.login_link);
}

test "HM immutable parent snapshots detect permission excursions and writable parents refuse" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const fixture = try HmFixture.init(arena.allocator());
    defer fixture.deinit();
    const witness = (try fixture.observe()) orelse return error.MissingServiceWitness;
    try fixture.setImmutable(false);
    try std.testing.expect((try fixture.observe()) == null);
    try fixture.setImmutable(true);
    // Returning to 0555 does not erase ctime from a previously taken snapshot.
    try std.testing.expectEqual(evidence.Probe.differs, try fixture.recheck(&witness));
    try std.testing.expect((try fixture.observe()) != null);
}

test "HM generation leaves refuse alias chains foreign targets and unwitnessed relative paths" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const fixture = try HmFixture.init(allocator);
    defer fixture.deinit();
    const witness = (try fixture.observe()) orelse return error.MissingServiceWitness;
    const alias = try std.fmt.allocPrint(allocator, "{s}/arbitrary-alias", .{fixture.store});
    try fixtureLink(allocator, alias, fixture.source);
    try fixture.setImmutable(false);
    try fixtureLink(allocator, fixture.generation_unit, alias);
    try fixture.setImmutable(true);
    try std.testing.expect((try fixture.observe()) == null);
    try std.testing.expectEqual(evidence.Probe.differs, try fixture.recheck(&witness));
    const foreign = try std.fmt.allocPrint(allocator, "{s}/foreign-unit", .{fixture.base});
    try fixtureWrite(allocator, foreign, hm_payload, 0o444);
    try fixture.setImmutable(false);
    try fixtureLink(allocator, fixture.generation_unit, foreign);
    try fixture.setImmutable(true);
    try std.testing.expect((try fixture.observe()) == null);
    try fixture.setImmutable(false);
    try fixtureLink(allocator, fixture.generation_unit, fixture.source);
    const wrong_relative = try std.fmt.allocPrint(allocator, "{s}/{s}/.config/systemd/user/wrong.service", .{ fixture.store, hm_generation });
    try fixtureLink(allocator, wrong_relative, fixture.source);
    try fixture.setImmutable(true);
    try fixtureLink(allocator, fixture.installed, wrong_relative);
    try std.testing.expect((try fixture.observe()) == null);
    // Matching suffix bytes after an arbitrary directory symlink do not help.
    const fake_generation = try std.fmt.allocPrint(allocator, "{s}/44444444444444444444444444444444-home-manager-files", .{fixture.store});
    const generation_root = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ fixture.store, hm_generation });
    try fixtureLink(allocator, fake_generation, generation_root);
    const fake_unit = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ fake_generation, hm_unit_relative });
    try fixtureLink(allocator, fixture.installed, fake_unit);
    try std.testing.expect((try fixture.observe()) == null);
}
