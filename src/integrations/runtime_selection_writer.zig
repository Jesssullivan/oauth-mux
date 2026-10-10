//! Private qualified-installation preparation. Actor commit is separate and
//! must succeed before any returned digest/evidence becomes admission authority.
const std = @import("std");
const c = std.c;
const setup = @import("setup.zig");
const producer = @import("runtime_selection_producer.zig");
const metadata = @import("../platform/file_metadata.zig");

const Retained = struct {
    evidence: []u8,
    record_sha256: [32]u8,
    directory: c.fd_t,
    directory_status: metadata.Metadata,
    channel: setup.RuntimeChannel,
    target: setup.RuntimeTarget,

    selected: *const producer.ValidatedSelection,
    deadline: std.Io.Clock.Timestamp,
};

pub const Prepared = opaque {
    fn held(self: *const Prepared) *const Retained { return @ptrCast(@alignCast(self)); }
    pub fn evidence(self: *const Prepared) []const u8 { return self.held().evidence; }
    pub fn recordDigest(self: *const Prepared) [32]u8 { return self.held().record_sha256; }
    pub fn expectation(self: *const Prepared) setup.RuntimeSelectionExpectation {
        const retained = self.held();
        return .{ .record_sha256 = retained.record_sha256, .directory = retained.directory,
            .channel = retained.channel, .target = retained.target };
    }
    pub fn recheck(self: *const Prepared, io: std.Io, context: producer.ActorContext) !void {
        const retained = self.held();
        // Original actor snapshot and clock cannot be replaced by a later call.
        if (!std.meta.eql(context.deadline, retained.deadline))
            return error.RuntimeSelectionDrift;
        try retained.selected.recheck(io, context);
    }
    pub fn recheckIdentity(self: *const Prepared, io: std.Io, context: producer.ActorContext) !void {
        const retained = self.held();
        if (!std.meta.eql(context.deadline,retained.deadline)) return error.RuntimeSelectionDrift;
        try retained.selected.recheckIdentity(io,context);
        if (!std.meta.eql(retained.directory_status,try metadata.statFd(retained.directory))) return error.RuntimeSelectionDrift;
        try retained.selected.recheckIdentity(io,context);
    }
    pub fn deinit(self: *Prepared, allocator: std.mem.Allocator) void {
        const retained: *Retained = @ptrCast(@alignCast(self));
        allocator.free(retained.evidence);
        _ = c.close(retained.directory);
        allocator.destroy(retained);
    }
};

/// Neither control records nor measured-installed-byte carriers can enter this
/// operation. The genuine producer constructor owns provenance qualification.
/// Borrowing contract: selected MUST outlive Prepared through actor commit and
/// Prepared.deinit. The supervised actor task owns both and destroys Prepared
/// first; this API does not retain borrowed context slices or a wrapping key.
pub fn prepare(io: std.Io, allocator: std.mem.Allocator, context: producer.ActorContext, selected: *const producer.ValidatedSelection) !*Prepared {
    try selected.recheck(io, context);
    const record = selected.runtimeRecord();
    const plaintext = try std.json.Stringify.valueAlloc(allocator, record, .{});
    defer allocator.free(plaintext);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(plaintext, &digest, .{});
    const directory = try selected.duplicateInstallationDirectory();
    errdefer _ = c.close(directory);
    const expected: setup.RuntimeSelectionExpectation = .{
        .record_sha256 = digest, .channel = record.channel,
        .target = record.target, .directory = directory,
    };
    var options = context.options;
    options.deadline = context.deadline;
    const evidence = try setup.encodeRuntimeSelection(io, allocator, options, expected, record);
    errdefer allocator.free(evidence);
    try selected.recheck(io, context);
    // Exercise the actual authenticated decoder before the actor can commit.
    // This local roundtrip is integrity verification, not actor admission.
    const verified = try setup.verifyRetainedRuntimeSelection(io, allocator, options, expected, evidence);
    defer verified.deinit(allocator);
    try selected.recheck(io, context);
    const directory_status = try metadata.statFd(directory);
    const retained = try allocator.create(Retained);
    retained.* = .{ .evidence = evidence, .record_sha256 = digest, .directory = directory, .directory_status=directory_status,
        .channel = record.channel, .target = record.target, .selected = selected, .deadline = context.deadline };
    return @ptrCast(retained);
}
