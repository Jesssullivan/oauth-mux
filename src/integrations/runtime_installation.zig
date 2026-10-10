//! Reversible private staging/publication, called only by the supervised actor
//! install task. Publication is not selection: final acquire + writer + actor
//! commit remain required, under the same original caller clock.
const std = @import("std");
const builtin = @import("builtin");
const c = std.c;
const metadata = @import("../platform/file_metadata.zig");
const producer = @import("runtime_selection_producer.zig");
const deployment = @import("runtime_deployment.zig");
const artifact = @import("runtime_artifact_verifier.zig");
extern "c" fn renameat2(c_int, [*:0]const u8, c_int, [*:0]const u8, c_uint) c_int;

pub const OwnedInstallation = struct {
    directory: c.fd_t,
    witness: metadata.Metadata,
    created: bool,
    pub fn deinit(self: *OwnedInstallation) void { _ = c.close(self.directory); self.directory = -1; }
    pub fn recheck(self: *const OwnedInstallation, io: std.Io, until: std.Io.Clock.Timestamp, parent: c.fd_t, basename: [:0]const u8) !void {
        const budget: artifact.Budget = .{.io=io,.deadline=until};
        try budget.check();
        try component(basename);
        const named = c.openat(parent,basename.ptr,.{.DIRECTORY=true,.NOFOLLOW=true,.CLOEXEC=true});
        if (named < 0) return error.RuntimeSelectionDrift;
        defer _ = c.close(named);
        if (!std.meta.eql(self.witness,try metadata.statFd(self.directory)) or
            !std.meta.eql(self.witness,try metadata.statFd(named))) return error.RuntimeSelectionDrift;
        try budget.check();
    }
};
fn component(name: []const u8) !void {
    if (name.len == 0 or name.len > 255 or std.mem.eql(u8,name,".") or std.mem.eql(u8,name,"..")) return error.InvalidInstallationDestination;
    for (name) |ch| if (!std.ascii.isAlphanumeric(ch) and ch != '-' and ch != '_' and ch != '.') return error.InvalidInstallationDestination;
}
fn identity(first: metadata.Metadata, second: metadata.Metadata) bool {
    return first.dev == second.dev and first.ino == second.ino and first.uid == second.uid and
        first.gid == second.gid and first.mode == second.mode;
}
fn privateDirectory(status: metadata.Metadata, exact: bool) !void {
    if (status.mode & c.S.IFMT != c.S.IFDIR or status.uid != c.geteuid() or
        status.mode & 0o6022 != 0 or (exact and status.mode & 0o7777 != 0o700)) return error.UnsafeInstallationDestination;
}
fn duplicateDirectory(fd: c.fd_t) !c.fd_t {
    const result = c.openat(fd,".",.{.DIRECTORY=true,.NOFOLLOW=true,.CLOEXEC=true});
    if (result < 0) return error.InstallationDestinationUnavailable;
    return result;
}
fn qualify(io: std.Io, allocator: std.mem.Allocator, context: producer.ActorContext, selected: *const deployment.OwnedInputs, directory: c.fd_t) !void {
    try selected.recheck(io);
    const verified = try producer.acquire(io,allocator,context,selected.inputsForInstallation(directory));
    defer verified.deinit();
    if (verified.runtimeRecord().launch_profile != .linux_nix_direct_main_v1) return error.UnsupportedNativeAcquisition;
    // Genuine evaluation-only provenance may be installed with unsupported
    // acquisition contract. Runtime qualification is separate; only SourceImage
    // can gate credential acquisition on its later exact supported contract.
    try verified.recheck(io,context);
    try selected.recheck(io);
}
fn parentFor(ledger: *const artifact.StagingLedger, root: c.fd_t, path: []const u8) !struct {descriptor:c.fd_t,name:[]const u8} {
    const slash = std.mem.lastIndexOfScalar(u8,path,'/') orelse return .{.descriptor=root,.name=path};
    const prefix = path[0..slash];
    for (ledger.entries.items) |entry| {
        if (entry.kind == .directory and std.mem.eql(u8,entry.path,prefix)) {
            const status = entry.status orelse return error.RuntimeInstallationCleanupConflict;
            if (entry.descriptor < 0 or !identity(status,try metadata.statFd(entry.descriptor))) return error.RuntimeInstallationCleanupConflict;
            return .{.descriptor=entry.descriptor,.name=path[slash+1..]};
        }
    }
    return error.RuntimeInstallationCleanupConflict;
}
fn abort(allocator: std.mem.Allocator, parent: c.fd_t, name: [:0]const u8, root: c.fd_t, original: metadata.Metadata, ledger: *const artifact.StagingLedger) !void {
    if (!identity(original,try metadata.statFd(root))) return error.RuntimeInstallationCleanupConflict;
    const named_root = c.openat(parent,name.ptr,.{.DIRECTORY=true,.NOFOLLOW=true,.CLOEXEC=true});
    if (named_root < 0) return error.RuntimeInstallationCleanupConflict;
    defer _ = c.close(named_root);
    if (!identity(original,try metadata.statFd(named_root))) return error.RuntimeInstallationCleanupConflict;
    var remaining = ledger.entries.items.len;
    while (remaining != 0) {
        remaining -= 1;
        const entry = ledger.entries.items[remaining];
        const status = entry.status orelse return error.RuntimeInstallationCleanupConflict;
        if (entry.descriptor < 0 or !identity(status,try metadata.statFd(entry.descriptor))) return error.RuntimeInstallationCleanupConflict;
        const location = try parentFor(ledger,root,entry.path);
        const basename = try allocator.dupeSentinel(u8,location.name,0);
        defer allocator.free(basename);
        const named = c.openat(location.descriptor,basename.ptr,.{.DIRECTORY=entry.kind == .directory,.NOFOLLOW=true,.CLOEXEC=true,.NONBLOCK=true});
        if (named < 0) return error.RuntimeInstallationCleanupConflict;
        defer _ = c.close(named);
        const current = try metadata.statFd(named);
        if (!identity(status,current) or !std.meta.eql(current,try metadata.statFd(entry.descriptor)) or
            (entry.kind == .file and current.nlink != 1)) return error.RuntimeInstallationCleanupConflict;
        if (c.unlinkat(location.descriptor,basename.ptr,if (entry.kind == .directory) c.AT.REMOVEDIR else 0) != 0) return error.RuntimeInstallationCleanupConflict;
    }
    if (!identity(original,try metadata.statFd(root)) or !identity(original,try metadata.statFd(named_root))) return error.RuntimeInstallationCleanupConflict;
    if (c.unlinkat(parent,name.ptr,c.AT.REMOVEDIR) != 0) return error.RuntimeInstallationCleanupConflict;
    // Cancellation/deadline never claims this owned cleanup physically stopped.
    // The supervised task remains owned until actual cleanup and descriptor join.
}
fn materialize(io: std.Io, allocator: std.mem.Allocator, context: producer.ActorContext, selected: *const deployment.OwnedInputs, root: c.fd_t, ledger: *artifact.StagingLedger) !void {
    const input = selected.inputs();
    const budget: artifact.Budget = .{.io=io,.deadline=context.deadline};
    // Genuine producer wrapper enforces direct fixed-four-file layout before
    // any write, bounds manifest parsing at 4MiB, and streams the full archive.
    try producer.materializeSelectedArchive(io,allocator,context,input,root,ledger);
    try selected.recheck(io);
    try qualify(io,allocator,context,selected,root);
    while (c.fsync(root) != 0) { try budget.check(); if (c.errno(-1) != .INTR) return error.RuntimeInstallationSyncFailed; }
    try budget.check();
}
fn publish(budget: artifact.Budget, parent: c.fd_t, parent_status: metadata.Metadata, staging_name: [:0]const u8, basename: [:0]const u8, root: c.fd_t, original: metadata.Metadata) !void {
    try budget.check();
    if (!identity(parent_status,try metadata.statFd(parent)) or !identity(original,try metadata.statFd(root))) return error.RuntimeSelectionDrift;
    const named = c.openat(parent,staging_name.ptr,.{.DIRECTORY=true,.NOFOLLOW=true,.CLOEXEC=true});
    if (named < 0) return error.RuntimeInstallationCleanupConflict;
    defer _ = c.close(named);
    if (!identity(original,try metadata.statFd(named))) return error.RuntimeSelectionDrift;
    try budget.check();
    // Linux RENAME_NOREPLACE; no fallback replacing rename is permitted.
    if (renameat2(parent,staging_name.ptr,parent,basename.ptr,1) != 0) return error.RuntimeInstallationPublishRefused;
}

/// parent and basename come solely from captured typed installation configuration.
/// Never overwrite an existing destination or a declarative package. Existing
/// qualified installation is an idempotent retry, not an update transaction.
pub fn installQualifiedPackage(io: std.Io, allocator: std.mem.Allocator, context: producer.ActorContext, selected: *const deployment.OwnedInputs, parent_fd: c.fd_t, basename: [:0]const u8) !OwnedInstallation {
    const budget: artifact.Budget = .{.io=io,.deadline=context.deadline};
    try budget.check();
    if (builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) return error.UnsupportedRuntimeInstallation;
    try component(basename);
    const parent = try duplicateDirectory(parent_fd);
    defer _ = c.close(parent);
    const parent_status = try metadata.statFd(parent);
    try privateDirectory(parent_status,false);
    const existing = c.openat(parent,basename.ptr,.{.DIRECTORY=true,.NOFOLLOW=true,.CLOEXEC=true});
    if (existing >= 0) {
        errdefer _ = c.close(existing);
        try privateDirectory(try metadata.statFd(existing),true);
        try qualify(io,allocator,context,selected,existing);
        try budget.check();
        const installed: OwnedInstallation = .{.directory=existing,.witness=try metadata.statFd(existing),.created=false};
        try installed.recheck(io,context.deadline,parent,basename);
        return installed;
    }
    if (c.errno(existing) != .NOENT) return error.UnsafeInstallationDestination;
    const custody = context.options.native_custody orelse return error.NativeCustodyPending;
    const transaction = custody.registry_transaction orelse return error.NativeCustodyPending;
    const staging_name = try std.fmt.allocPrintSentinel(allocator,".omux-runtime-{s}.staging",.{std.fmt.bytesToHex(transaction,.lower)},0);
    defer allocator.free(staging_name);
    try selected.recheck(io);
    try budget.check();
    if (!identity(parent_status,try metadata.statFd(parent))) return error.RuntimeSelectionDrift;
    if (c.mkdirat(parent,staging_name.ptr,0o700) != 0) return error.RuntimeStagingAlreadyExists;
    const root = c.openat(parent,staging_name.ptr,.{.DIRECTORY=true,.NOFOLLOW=true,.CLOEXEC=true});
    // Failed witness acquisition leaves the one transaction-specific stage
    // explicitly unselected. Unknown identities are never blindly removed.
    if (root < 0) return error.RuntimeInstallationCleanupConflict;
    var keep_root = false;
    defer if (!keep_root) { _ = c.close(root); };
    const original = metadata.statFd(root) catch return error.RuntimeInstallationCleanupConflict;
    privateDirectory(original,true) catch return error.RuntimeInstallationCleanupConflict;
    var ledger = artifact.StagingLedger.init(allocator);
    defer ledger.deinit();
    materialize(io,allocator,context,selected,root,&ledger) catch |failure| {
        abort(allocator,parent,staging_name,root,original,&ledger) catch return error.RuntimeInstallationCleanupConflict;
        return failure;
    };
    publish(budget,parent,parent_status,staging_name,basename,root,original) catch |failure| {
        abort(allocator,parent,staging_name,root,original,&ledger) catch return error.RuntimeInstallationCleanupConflict;
        return failure;
    };
    // After this point failure leaves a published-but-unselected installation;
    // retry must genuinely qualify it. No rollback deletes the published root.
    while (c.fsync(parent) != 0) { try budget.check(); if (c.errno(-1) != .INTR) return error.RuntimeInstallationSyncFailed; }
    const final = c.openat(parent,basename.ptr,.{.DIRECTORY=true,.NOFOLLOW=true,.CLOEXEC=true});
    if (final < 0) return error.RuntimeInstallationCleanupConflict;
    defer _ = c.close(final);
    if (!identity(original,try metadata.statFd(final)) or !identity(original,try metadata.statFd(root))) return error.RuntimeSelectionDrift;
    try budget.check();
    keep_root = true;
    return .{.directory=root,.witness=try metadata.statFd(root),.created=true};
}

test "qualified package factory rejects unsafe destination before any selected material access" {
    try std.testing.expectError(error.InvalidInstallationDestination,component("../foreign"));
    try std.testing.expectError(error.InvalidInstallationDestination,component("."));
    try component("codex-maintained");
}

const FilesystemFixture = struct {
    path: [:0]u8, parent: c.fd_t, root: c.fd_t, status: metadata.Metadata,
    fn init() !FilesystemFixture {
        if (builtin.os.tag != .linux) return error.SkipZigTest;
        const allocator = std.testing.allocator;
        var nonce: [16]u8 = undefined;
        std.testing.io.random(&nonce);
        const path = try std.fmt.allocPrintSentinel(allocator,"/tmp/omux-runtime-install-{s}",.{std.fmt.bytesToHex(nonce,.lower)},0);
        errdefer allocator.free(path);
        if (c.mkdir(path.ptr,0o700) != 0) return error.FixtureSetupFailed;
        errdefer std.Io.Dir.cwd().deleteTree(std.testing.io,path) catch @panic("owned fixture cleanup failed");
        const parent = c.open(path.ptr,.{.DIRECTORY=true,.NOFOLLOW=true,.CLOEXEC=true});
        if (parent < 0) return error.FixtureSetupFailed;
        errdefer _ = c.close(parent);
        if (c.mkdirat(parent,"stage",0o700) != 0) return error.FixtureSetupFailed;
        const root = c.openat(parent,"stage",.{.DIRECTORY=true,.NOFOLLOW=true,.CLOEXEC=true});
        if (root < 0) return error.FixtureSetupFailed;
        errdefer _ = c.close(root);
        return .{.path=path,.parent=parent,.root=root,.status=try metadata.statFd(root)};
    }
    fn deinit(self: *FilesystemFixture) void {
        _ = c.close(self.root); _ = c.close(self.parent);
        std.Io.Dir.cwd().deleteTree(std.testing.io,self.path) catch @panic("owned fixture cleanup failed");
        std.testing.allocator.free(self.path);
    }
    fn payload(self: *const FilesystemFixture, ledger: *artifact.StagingLedger) !c.fd_t {
        const path = try ledger.allocator.dupe(u8,"payload");
        errdefer ledger.allocator.free(path);
        const fd = c.openat(self.root,"payload",.{.ACCMODE=.RDWR,.CREAT=true,.EXCL=true,.NOFOLLOW=true,.CLOEXEC=true},@as(c.mode_t,0o600));
        if (fd < 0) return error.FixtureSetupFailed;
        errdefer _ = c.close(fd);
        try ledger.entries.append(ledger.allocator,.{.path=path,.kind=.file,.descriptor=fd,.status=try metadata.statFd(fd)});
        return fd;
    }
};

test "staging rollback removes original partial bytes using retained creation identities" {
    var fixture = try FilesystemFixture.init();
    defer fixture.deinit();
    var ledger = artifact.StagingLedger.init(std.testing.allocator);
    defer ledger.deinit();
    const fd = try fixture.payload(&ledger);
    const bytes = "partial synthetic archive output";
    if (c.write(fd,bytes.ptr,bytes.len) != bytes.len) return error.FixtureSetupFailed;
    // The creation witness predates this partial write, as on parser failure.
    try abort(std.testing.allocator,fixture.parent,"stage",fixture.root,fixture.status,&ledger);
    const named = c.openat(fixture.parent,"stage",.{.DIRECTORY=true,.NOFOLLOW=true,.CLOEXEC=true});
    if (named >= 0) { _ = c.close(named); return error.TestUnexpectedResult; }
    try std.testing.expect(c.errno(named) == .NOENT);
}

test "staging rollback refuses a replaced file and leaves replacement untouched" {
    var fixture = try FilesystemFixture.init();
    defer fixture.deinit();
    var ledger = artifact.StagingLedger.init(std.testing.allocator);
    defer ledger.deinit();
    _ = try fixture.payload(&ledger);
    if (c.unlinkat(fixture.root,"payload",0) != 0) return error.FixtureSetupFailed;
    const replacement = c.openat(fixture.root,"payload",.{.ACCMODE=.RDWR,.CREAT=true,.EXCL=true,.NOFOLLOW=true,.CLOEXEC=true},@as(c.mode_t,0o600));
    if (replacement < 0) return error.FixtureSetupFailed;
    defer _ = c.close(replacement);
    const before = try metadata.statFd(replacement);
    try std.testing.expectError(error.RuntimeInstallationCleanupConflict,abort(std.testing.allocator,fixture.parent,"stage",fixture.root,fixture.status,&ledger));
    const named = c.openat(fixture.root,"payload",.{.NOFOLLOW=true,.CLOEXEC=true});
    if (named < 0) return error.TestUnexpectedResult;
    defer _ = c.close(named);
    try std.testing.expectEqual(before,try metadata.statFd(named));
}

test "no-replace publication preserves an existing destination and its stage" {
    var fixture = try FilesystemFixture.init();
    defer fixture.deinit();
    if (c.mkdirat(fixture.parent,"installed",0o700) != 0) return error.FixtureSetupFailed;
    const existing = c.openat(fixture.parent,"installed",.{.DIRECTORY=true,.NOFOLLOW=true,.CLOEXEC=true});
    if (existing < 0) return error.FixtureSetupFailed;
    defer _ = c.close(existing);
    const original = try metadata.statFd(existing);
    const budget: artifact.Budget = .{.io=std.testing.io,.deadline=.fromNow(std.testing.io,.{.clock=.awake,.raw=.fromSeconds(10)})};
    try std.testing.expectError(error.RuntimeInstallationPublishRefused,publish(budget,fixture.parent,try metadata.statFd(fixture.parent),"stage","installed",fixture.root,fixture.status));
    try std.testing.expectEqual(original,try metadata.statFd(existing));
    const named = c.openat(fixture.parent,"stage",.{.DIRECTORY=true,.NOFOLLOW=true,.CLOEXEC=true});
    if (named < 0) return error.TestUnexpectedResult;
    defer _ = c.close(named);
    try std.testing.expect(identity(fixture.status,try metadata.statFd(named)));
}

test "expired publication refuses before rename and remains available for owned rollback" {
    var fixture = try FilesystemFixture.init();
    defer fixture.deinit();
    const budget: artifact.Budget = .{.io=std.testing.io,.deadline=.fromNow(std.testing.io,.{.clock=.awake,.raw=.fromMilliseconds(-1)})};
    try std.testing.expectError(error.Timeout,publish(budget,fixture.parent,try metadata.statFd(fixture.parent),"stage","installed",fixture.root,fixture.status));
    var ledger = artifact.StagingLedger.init(std.testing.allocator);
    defer ledger.deinit();
    try abort(std.testing.allocator,fixture.parent,"stage",fixture.root,fixture.status,&ledger);
}

test "final installation handoff refuses named root replacement after worker completion" {
    var fixture = try FilesystemFixture.init();
    defer fixture.deinit();
    const until: std.Io.Clock.Timestamp = .fromNow(std.testing.io,.{.clock=.awake,.raw=.fromSeconds(10)});
    // The completed worker holds this exact FD and witness. A later actor
    // boundary must independently test the configured name, not just its FD.
    const installed: OwnedInstallation = .{.directory=fixture.root,.witness=fixture.status,.created=true};
    try installed.recheck(std.testing.io,until,fixture.parent,"stage");
    if (c.renameat(fixture.parent,"stage",fixture.parent,"retired") != 0 or
        c.mkdirat(fixture.parent,"stage",0o700) != 0) return error.FixtureSetupFailed;
    const replacement = c.openat(fixture.parent,"stage",.{.DIRECTORY=true,.NOFOLLOW=true,.CLOEXEC=true});
    if (replacement < 0) return error.FixtureSetupFailed;
    defer _ = c.close(replacement);
    const replacement_status = try metadata.statFd(replacement);
    try std.testing.expectError(error.RuntimeSelectionDrift,installed.recheck(std.testing.io,until,fixture.parent,"stage"));
    try std.testing.expectEqual(replacement_status,try metadata.statFd(replacement));
}
