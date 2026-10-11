//! R-HOOK-CONVERGENCE-20261004 / R-N13: retained-descriptor acquisition.
//! Qualification binds actor/deployment-selected raw artifact and receipt bytes
//! to an exact installed closure. It does not attribute processes, execute the
//! SDK or grant native support. The separate writer and actor commit own custody.
const std = @import("std");
const builtin = @import("builtin");
const c = std.c;
const setup = @import("setup.zig");
const instance = @import("../instance.zig");
const metadata = @import("../platform/file_metadata.zig");
const verifier = @import("runtime_artifact_verifier.zig");
const nix = @import("nix_runtime_closure.zig");
const nix_artifact = @import("runtime_nix_artifact_verifier.zig");
const deployment = @import("runtime_deployment.zig");

pub const maximum_archive_bytes = 256 * 1024 * 1024;
pub const maximum_metadata_bytes = 16 * 1024 * 1024;
pub const maximum_files = 4096;
pub const maximum_payload_bytes = 512 * 1024 * 1024;
const maximum_backend_bytes = 512 * 1024 * 1024;
const maximum_library_bytes = 128 * 1024 * 1024;
const launcher = "bin/codex";
const backend = "lib/codex/libexec/codex.bin";
const loader = "lib/codex/lib/ld-linux-x86-64.so.2";
const ca_bundle = "lib/codex/share/ca-bundle.crt";

/// Borrowed descriptor, selected digest and exact byte count from independent
/// actor/deployment authority. A digest computed from the incoming input is not
/// a selection. Descriptor offsets are never consumed or changed by this API.
pub const Input = verifier.SelectedArchive;
pub const DeploymentRoot = struct { path: []const u8, descriptor: c.fd_t };
pub const ModernRole = enum {
    source,
    sdk,
    sdk_metadata,
    plan,
    query,
    compiler_selection,
    compiler_ledger,
    compiler_ledger_snapshot,
    compiler,
    compiler_outer,
    codex,
    config_schema,
};
pub const ModernMember = struct { name: []const u8, input: Input };
pub const ModernAuthority = struct { outer: Input, evidence: Input, members: []const ModernMember };
pub const ModernAuthorityRole = enum { source, sdk, plan, query, compiler };
/// Compact retained proof only. Original transport leaves are inert digest/size
/// tuples in the selected authority document, never installed payload inputs.
pub const CarrierReceiptRole = enum { authority_document, carrier_receipt, seal_program, metadata_program };
pub const CarrierAuthorityRole = enum { seal, metadata };
pub const CarrierInputs = struct {
    receipts: [4]Input,
    authority_receipts: [2]ModernAuthority,
};
/// Finite modern family. Every Input is selected by the protected deployment
/// declaration, never calculated from a wire reply. Names are exact map keys.
pub const ModernInputs = struct {
    package_selection: Input,
    package_outputs: Input,
    package_output_root: []const u8,
    package_authority: ModernAuthority,
    roles: [12]Input,
    protocol_schema_files: []const ModernMember,
    native_acquisition_artifact_files: []const ModernMember,
    /// Independently selected original action receipts and copied evidence.
    authority_receipts: [5]ModernAuthority,
    carrier_materials: ?CarrierInputs = null,
};
pub const Inputs = struct {
    archive: Input,
    manifest: Input,
    runtime_receipt: Input,
    source_receipt: Input,
    producer_receipt: Input,
    registration_receipt: ?Input = null,
    modern_materials: ?ModernInputs = null,
    deployment_root: ?DeploymentRoot = null,
    deployment_declaration: ?Input = null,
    /// Retained installation root, supplied explicitly; no PATH or cwd search.
    installation_directory: c.fd_t,
};

/// In-process actor input only. Derive instance, custody, epoch, transaction and
/// capability from Engine's committed state. Never deserialize this from wire.
pub const ActorContext = struct {
    options: setup.Options,
    selection: instance.Selection,
    deadline: std.Io.Clock.Timestamp,
};

const Qualified = struct {
    observed: *Observation,
    record: setup.RuntimeSelectionRecord,
    deadline: std.Io.Clock.Timestamp,
    owner_allocator: std.mem.Allocator,
    metadata_storage: []u8,
    metadata_allocator: *std.heap.FixedBufferAllocator,
    modern: ?*ModernRetained = null,
    nix_owned: ?nix_artifact.Owned = null,
};
/// Only acquire's concrete raw archive/ELF/receipt qualification constructs this
/// in-process carrier. No wire record, measured observation or boolean callback
/// is a constructor. Actor persistence remains a separate required boundary.
pub const ValidatedSelection = opaque {
    pub fn deinit(self: *ValidatedSelection) void {
        const q: *Qualified = @ptrCast(@alignCast(self));
        const retained: *Retained = @ptrCast(@alignCast(q.observed));
        const allocator = q.owner_allocator;
        if (q.modern) |modern| modern.deinit() else {
            for (inputArray(retained.inputs)) |input| _ = c.close(input.descriptor);
        }
        if (q.nix_owned) |owned_value| {
            var owned = owned_value;
            owned.deinit();
        }
        _ = c.close(retained.inputs.installation_directory);
        q.observed.deinit();
        const storage = q.metadata_storage;
        const bounded = q.metadata_allocator;
        allocator.destroy(q);
        allocator.destroy(bounded);
        allocator.free(storage);
    }
    pub fn recheck(self: *const ValidatedSelection, io: std.Io, context: ActorContext) !void {
        const q: *const Qualified = @ptrCast(@alignCast(self));
        if (!std.meta.eql(q.deadline, context.deadline)) return error.RuntimeSelectionDrift;
        try q.observed.recheck(io, context);
        if (q.modern) |modern| {
            try modern.recheck(.{ .io = io, .deadline = context.deadline });
            try modern.recheckIdentity(.{ .io = io, .deadline = context.deadline });
            try recheckDirectManifest(q, .{ .io = io, .deadline = context.deadline }, true);
        }
        if (q.nix_owned) |owned| try nix.recheck(io, q.metadata_allocator.allocator(), context.deadline, owned.record);
    }
    pub fn recheckIdentity(self: *const ValidatedSelection, io: std.Io, context: ActorContext) !void {
        const q: *const Qualified = @ptrCast(@alignCast(self));
        if (!std.meta.eql(q.deadline, context.deadline)) return error.RuntimeSelectionDrift;
        try q.observed.recheckIdentity(io, context);
        if (q.modern) |modern| {
            try modern.recheckIdentity(.{ .io = io, .deadline = context.deadline });
            try recheckDirectManifest(q, .{ .io = io, .deadline = context.deadline }, false);
        }
        if (q.nix_owned) |owned| try nix_artifact.recheckIdentity(.{ .io = io, .deadline = context.deadline }, q.metadata_allocator.allocator(), owned.record);
    }
    pub fn acquisitionContract(self: *const ValidatedSelection) setup.RuntimeAcquisitionContract {
        return self.runtimeRecord().acquisition_contract;
    }
    pub fn runtimeRecord(self: *const ValidatedSelection) setup.RuntimeSelectionRecord {
        const q: *const Qualified = @ptrCast(@alignCast(self));
        return q.record;
    }
    pub fn duplicateInstallationDirectory(self: *const ValidatedSelection) !c.fd_t {
        const q: *const Qualified = @ptrCast(@alignCast(self));
        const retained: *const Retained = @ptrCast(@alignCast(q.observed));
        if (!std.meta.eql(retained.directory, try metadata.statFd(retained.inputs.installation_directory))) return error.RuntimeSelectionDrift;
        const fd = c.openat(retained.inputs.installation_directory, ".", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
        if (fd < 0) return error.UnsafeRuntimeInput;
        errdefer _ = c.close(fd);
        if (!std.meta.eql(retained.directory, try metadata.statFd(fd)) or !std.meta.eql(retained.directory, try metadata.statFd(retained.inputs.installation_directory))) return error.RuntimeSelectionDrift;
        return fd;
    }
};

const FileObservation = struct {
    path: []const u8,
    sha256: [32]u8,
    bytes: u64,
    mode: u32,
    status: metadata.Metadata,
};
const Retained = struct {
    allocator: std.mem.Allocator,
    inputs: Inputs,
    statuses: [5]metadata.Metadata,
    registry: setup.RegistryWitness,
    context_digest: [32]u8,
    directory: metadata.Metadata,
    files: []FileObservation,
    payload_bytes: u64,
};

/// An opaque observation, explicitly excluded from selection authority. Its
/// contents are diagnostic installation facts; no credential or native state
/// is materialized. This object must never be serialized as a control reply.
pub const Observation = opaque {
    pub fn deinit(self: *Observation) void {
        const retained: *Retained = @ptrCast(@alignCast(self));
        for (retained.files) |file| retained.allocator.free(file.path);
        retained.allocator.free(retained.files);
        retained.allocator.destroy(retained);
    }

    /// Actor-side fence only. Full payload qualification stays in the worker.
    pub fn recheckIdentity(self: *const Observation, io: std.Io, context: ActorContext) !void {
        const retained: *const Retained = @ptrCast(@alignCast(self));
        const budget: Budget = .{ .io = io, .deadline = context.deadline };
        try budget.check();
        const custody = context.options.native_custody orelse return error.NativeCustodyPending;
        try custody.validate();
        if (custody.state != .retain_ready and custody.state != .install_ready) return error.NativeCustodyPending;
        const transaction = custody.registry_transaction orelse return error.NativeCustodyPending;
        const capability = custody.registry_capability_digest orelse return error.NativeCustodyPending;
        var actual_capability: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&context.options.capability, &actual_capability, .{});
        if (!std.meta.eql(retained.context_digest, try contextDigest(context)) or
            !std.meta.eql(retained.registry.transaction, transaction) or
            !std.meta.eql(retained.registry.capability_digest, capability) or
            !std.meta.eql(capability, actual_capability)) return error.RuntimeSelectionDrift;
        if (!std.meta.eql(retained.directory, try metadata.statFd(retained.inputs.installation_directory))) return error.RuntimeSelectionDrift;
        for (inputArray(retained.inputs), retained.statuses) |input, status| {
            try budget.check();
            if (!std.meta.eql(status, try metadata.statFd(input.descriptor))) return error.RuntimeSelectionDrift;
        }
        for (retained.files) |file| {
            const descriptor = try openMember(budget, retained.inputs.installation_directory, retained.directory, file.path);
            defer _ = c.close(descriptor);
            if (!std.meta.eql(file.status, try metadata.statFd(descriptor))) return error.RuntimeSelectionDrift;
        }
        try budget.check();
    }

    pub fn fileCount(self: *const Observation) usize {
        const retained: *const Retained = @ptrCast(@alignCast(self));
        return retained.files.len;
    }

    pub fn payloadBytes(self: *const Observation) u64 {
        const retained: *const Retained = @ptrCast(@alignCast(self));
        return retained.payload_bytes;
    }

    /// Rehash every raw input and installed member under the original actor
    /// context. Same digest on a replacement inode is still selection drift.
    pub fn recheck(self: *const Observation, io: std.Io, context: ActorContext) !void {
        const retained: *const Retained = @ptrCast(@alignCast(self));
        const budget: Budget = .{ .io = io, .deadline = context.deadline };
        const registry = try actorWitness(io, retained.allocator, context);
        if (!std.meta.eql(registry, retained.registry) or !std.meta.eql(try contextDigest(context), retained.context_digest)) return error.RuntimeSelectionDrift;
        const directory = try metadata.statFd(retained.inputs.installation_directory);
        if (!std.meta.eql(directory, retained.directory)) return error.RuntimeSelectionDrift;
        const selected = inputArray(retained.inputs);
        for (selected, retained.statuses, 0..) |input, status, index| {
            const after = try hashInput(budget, input, inputLimit(index));
            if (!std.meta.eql(status, after)) return error.RuntimeSelectionDrift;
        }
        for (retained.files) |file| {
            const after = try inspectFile(budget, retained.inputs.installation_directory, directory, file);
            if (!std.meta.eql(file.status, after)) return error.RuntimeSelectionDrift;
        }
        if (!std.meta.eql(directory, try metadata.statFd(retained.inputs.installation_directory)) or !std.meta.eql(registry, try actorWitness(io, retained.allocator, context))) return error.RuntimeSelectionDrift;
    }
};

/// Actor/deployment selection supplies all expected digests independently.
/// Duplicate descriptors before collecting evidence; all reads use pread and
/// never consume caller offsets. Only a complete verifier result can survive.
/// Hash-bound raw bytes only; this is not a package/installation constructor.
/// Selected hash and size must originate in protected deployment authority.
pub fn readSelectedInput(io: std.Io, allocator: std.mem.Allocator, deadline: std.Io.Clock.Timestamp, input: Input, maximum: u64) ![]u8 {
    if (maximum == 0 or maximum > maximum_archive_bytes) return error.RuntimeInputLimit;
    const budget: Budget = .{ .io = io, .deadline = deadline };
    const status = try hashInput(budget, input, maximum);
    return readMetadata(allocator, budget, input, status);
}

pub const maximum_direct_manifest_bytes = 64 * 1024;
pub const maximum_deployment_declaration_bytes = 64 * 1024;
/// A staging copy, not publication or acquisition authority. The protected
/// reader owns every input selection. This parser uses a fixed metadata budget
/// and fixed compressed windows; it never buffers archive/backend payloads.
pub fn materializeSelectedArchive(io: std.Io, allocator: std.mem.Allocator, context: ActorContext, inputs: Inputs, staging_fd: c.fd_t, ledger: *verifier.StagingLedger) !void {
    if (inputs.manifest.bytes > maximum_direct_manifest_bytes) return error.RuntimeInputLimit;
    const storage = try allocator.alloc(u8, 4 * 1024 * 1024);
    defer allocator.free(storage);
    var bounded = std.heap.FixedBufferAllocator.init(storage);
    const a = bounded.allocator();
    const raw = try readSelectedInput(io, a, context.deadline, inputs.manifest, maximum_direct_manifest_bytes);
    const manifest = try std.json.parseFromSlice(std.json.Value, a, raw, .{ .duplicate_field_behavior = .@"error", .max_value_len = 4096 });
    defer manifest.deinit();
    const budget: verifier.Budget = .{ .io = io, .deadline = context.deadline };
    try directArchiveLayout(manifest.value, inputs.manifest.bytes);
    try verifier.materializeSelectedArchive(budget, .{ .descriptor = inputs.archive.descriptor, .sha256 = inputs.archive.sha256, .bytes = inputs.archive.bytes }, manifest.value, inputs.manifest.sha256, inputs.manifest.bytes, staging_fd, ledger);
}

fn directArchiveLayout(manifest: std.json.Value, manifest_bytes: u64) !void {
    if (manifest_bytes == 0 or manifest_bytes > maximum_direct_manifest_bytes) return error.RuntimeInputLimit;
    const files = try objectField(manifest, "files");
    if (files.object.count() != 4) return error.InvalidRuntimeManifest;
    var total: u64 = manifest_bytes;
    for ([_][]const u8{ launcher, backend, loader, ca_bundle }) |path| {
        const member = try objectField(files, path);
        const mode = try positiveInteger(member, "mode");
        const bytes = try positiveInteger(member, "bytes");
        if (mode != @as(u64, if (std.mem.eql(u8, path, ca_bundle)) 0o644 else 0o755) or bytes > try pathLimit(path)) return error.InvalidRuntimeManifest;
        _ = try digestField(member, "sha256");
        if (bytes > maximum_payload_bytes - total) return error.RuntimeInputLimit;
        total += bytes;
    }
    const runtime = try objectField(manifest, "runtime");
    if (!std.mem.eql(u8, try stringField(runtime, "launchProfile"), "linux_nix_direct_main_v1")) return error.InvalidRuntimeManifest;
}

pub const maximum_qualification_metadata_allocation = 64 * 1024 * 1024;
pub fn acquire(io: std.Io, allocator: std.mem.Allocator, context: ActorContext, inputs: Inputs) !*ValidatedSelection {
    const budget: Budget = .{ .io = io, .deadline = context.deadline };
    try budget.check();
    const storage = try allocator.alloc(u8, maximum_qualification_metadata_allocation);
    errdefer allocator.free(storage);
    const bounded = try allocator.create(std.heap.FixedBufferAllocator);
    errdefer allocator.destroy(bounded);
    bounded.* = std.heap.FixedBufferAllocator.init(storage);
    const a = bounded.allocator();
    if (inputs.modern_materials != null) return acquireModern(io, allocator, context, inputs, storage, bounded);
    var selected = inputArray(inputs);
    var opened: usize = 0;
    errdefer for (selected[0..opened]) |input| {
        _ = c.close(input.descriptor);
    };
    for (&selected) |*input| {
        const fd = c.fcntl(input.descriptor, c.F.DUPFD_CLOEXEC, @as(c_int, 0));
        if (fd < 0) return error.UnsafeRuntimeInput;
        input.descriptor = fd;
        opened += 1;
    }
    const directory = c.openat(inputs.installation_directory, ".", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (directory < 0) return error.UnsafeRuntimeInput;
    errdefer _ = c.close(directory);
    if (!std.meta.eql(try metadata.statFd(inputs.installation_directory), try metadata.statFd(directory))) return error.RuntimeSelectionDrift;
    const owned_inputs: Inputs = .{ .archive = selected[0], .manifest = selected[1], .runtime_receipt = selected[2], .source_receipt = selected[3], .producer_receipt = selected[4], .installation_directory = directory };
    const observed = try observe(io, a, context, owned_inputs);
    errdefer observed.deinit();
    const retained: *Retained = @ptrCast(@alignCast(observed));
    const manifest_bytes = try readMetadata(a, budget, selected[1], retained.statuses[1]);
    defer a.free(manifest_bytes);
    const receipt_bytes = try readMetadata(a, budget, selected[2], retained.statuses[2]);
    defer a.free(receipt_bytes);
    const source_bytes = try readMetadata(a, budget, selected[3], retained.statuses[3]);
    defer a.free(source_bytes);
    const producer_bytes = try readMetadata(a, budget, selected[4], retained.statuses[4]);
    defer a.free(producer_bytes);
    const manifest = try parse(a, manifest_bytes);
    defer manifest.deinit();
    const receipt = try parse(a, receipt_bytes);
    defer receipt.deinit();
    const source = try parse(a, source_bytes);
    defer source.deinit();
    const producer = try parse(a, producer_bytes);
    defer producer.deinit();
    const proof_budget: verifier.Budget = .{ .io = io, .deadline = context.deadline };
    try verifier.provenance(a, proof_budget, manifest.value, receipt.value, source.value, producer.value, selected[3].sha256, selected[4].sha256);
    // Stream selected compressed bytes through fixed windows; disk size limits
    // do not become resident allocations. Offsets remain caller-independent.
    try verifier.archiveSelected(proof_budget, selected[0], manifest.value, selected[1].sha256, selected[1].bytes);
    const dependencies = try field(try objectField(manifest.value, "runtime"), "dependencies");
    var roles: [3]setup.RuntimeRole = undefined;
    for (retained.files) |file| {
        if (std.mem.eql(u8, file.path, launcher)) {
            var expected: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(verifier.launcher_bytes, &expected, .{});
            if (file.bytes != verifier.launcher_bytes.len or !std.meta.eql(file.sha256, expected)) return error.InvalidRuntimeLauncher;
            roles[0] = .{ .sha256 = file.sha256, .bytes = file.bytes };
        } else {
            const fd = try openMember(budget, directory, retained.directory, file.path);
            defer _ = c.close(fd);
            if (std.mem.eql(u8, file.path, ca_bundle)) {
                const value = try readMetadata(a, budget, .{ .descriptor = fd, .sha256 = file.sha256, .bytes = file.bytes }, file.status);
                defer a.free(value);
                try verifier.ca(a, value);
            } else {
                try verifier.elf(a, proof_budget, fd, file.bytes, std.mem.eql(u8, file.path, backend), dependencies);
                if (std.mem.eql(u8, file.path, backend)) roles[1] = .{ .sha256 = file.sha256, .bytes = file.bytes };
                if (std.mem.eql(u8, file.path, loader)) roles[2] = .{ .sha256 = file.sha256, .bytes = file.bytes };
            }
            if (!std.meta.eql(file.status, try metadata.statFd(fd))) return error.RuntimeSelectionDrift;
        }
    }
    try observed.recheck(io, context);
    const custody = context.options.native_custody.?;
    const record: setup.RuntimeSelectionRecord = .{
        .schema_version = 1,
        .channel = if (context.selection == .dev) .development else .release,
        .target = .x86_64_linux,
        .launch_profile = .linux_explicit_bundled_loader_v1,
        .upstream_commit = verifier.upstream_commit[0..40].*,
        .artifact_selection_sha256 = artifactDigest(selected),
        .archive_sha256 = selected[0].sha256,
        .manifest_sha256 = selected[1].sha256,
        .runtime_receipt_sha256 = selected[2].sha256,
        .source_receipt_sha256 = selected[3].sha256,
        .producer_receipt_sha256 = selected[4].sha256,
        .installation = .{ .transaction = retained.registry.transaction, .adapter_epoch = custody.adapter_epoch, .capability_digest = retained.registry.capability_digest, .directory_device = retained.directory.dev, .directory_inode = retained.directory.ino, .uid = retained.directory.uid, .gid = retained.directory.gid },
        .launcher = roles[0],
        .backend = roles[1],
        .loader = roles[2],
    };
    const q = try allocator.create(Qualified);
    q.* = .{ .observed = observed, .record = record, .deadline = context.deadline, .owner_allocator = allocator, .metadata_storage = storage, .metadata_allocator = bounded };
    return @ptrCast(q);
}
fn artifactDigest(selected: [5]Input) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("omux-qualified-runtime-artifact-v1\x00");
    for (selected) |input| {
        hash.update(&input.sha256);
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, input.bytes, .big);
        hash.update(&bytes);
    }
    var value: [32]u8 = undefined;
    hash.final(&value);
    return value;
}

/// Read-only observation remains distinct from full artifact qualification.
pub fn observe(io: std.Io, allocator: std.mem.Allocator, context: ActorContext, inputs: Inputs) !*Observation {
    if (builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) return error.UnsupportedRuntimeSelection;
    const budget: Budget = .{ .io = io, .deadline = context.deadline };
    try budget.check();
    const registry = try actorWitness(io, allocator, context);
    const directory = try metadata.statFd(inputs.installation_directory);
    try validateDirectory(directory);
    var statuses: [5]metadata.Metadata = undefined;
    for (inputArray(inputs), &statuses, 0..) |input, *status, index| status.* = try hashInput(budget, input, inputLimit(index));
    // Raw metadata is read only after digest/descriptor bounds pass. At most
    // four finite buffers are live, and each subsequent pass checks identity.
    const manifest_bytes = try readMetadata(allocator, budget, inputs.manifest, statuses[1]);
    defer allocator.free(manifest_bytes);
    const receipt_bytes = try readMetadata(allocator, budget, inputs.runtime_receipt, statuses[2]);
    defer allocator.free(receipt_bytes);
    const source_bytes = try readMetadata(allocator, budget, inputs.source_receipt, statuses[3]);
    defer allocator.free(source_bytes);
    const producer_bytes = try readMetadata(allocator, budget, inputs.producer_receipt, statuses[4]);
    defer allocator.free(producer_bytes);
    const manifest = try parse(allocator, manifest_bytes);
    defer manifest.deinit();
    const receipt = try parse(allocator, receipt_bytes);
    defer receipt.deinit();
    const source = try parse(allocator, source_bytes);
    defer source.deinit();
    const producer = try parse(allocator, producer_bytes);
    defer producer.deinit();
    if (inputs.modern_materials != null) {
        try directArchiveLayout(manifest.value, inputs.manifest.bytes);
        try modernMaterial(allocator, budget, inputs, manifest.value, receipt.value, source.value);
    } else try references(manifest.value, receipt.value, source.value, producer.value, inputs);
    const records = try objectField(manifest.value, "files");
    if (records.object.count() == 0 or records.object.count() > maximum_files) return error.RuntimeInputLimit;
    const files = try allocator.alloc(FileObservation, records.object.count());
    var owned: usize = 0;
    errdefer {
        for (files[0..owned]) |file| allocator.free(file.path);
        allocator.free(files);
    }
    var total: u64 = 0;
    var iterator = records.object.iterator();
    while (iterator.next()) |entry| {
        try budget.check();
        const path = entry.key_ptr.*;
        const mode: u32 = if (std.mem.eql(u8, path, ca_bundle)) 0o644 else 0o755;
        const limit = try pathLimit(path);
        const record = entry.value_ptr.*;
        if (record != .object or record.object.count() != 3) return error.InvalidRuntimeManifest;
        const bytes = try positiveInteger(record, "bytes");
        if (bytes > limit or bytes > maximum_payload_bytes - total or try positiveInteger(record, "mode") != mode) return error.RuntimeInputLimit;
        total += bytes;
        const digest = try digestField(record, "sha256");
        files[owned] = .{ .path = try allocator.dupe(u8, path), .sha256 = digest, .bytes = bytes, .mode = mode, .status = undefined };
        owned += 1;
        files[owned - 1].status = try inspectFile(budget, inputs.installation_directory, directory, files[owned - 1]);
    }
    try declaredMembership(manifest.value, files);
    if (!std.meta.eql(directory, try metadata.statFd(inputs.installation_directory)) or !std.meta.eql(registry, try actorWitness(io, allocator, context))) return error.RuntimeSelectionDrift;
    // Rehash raw evidence once more to reject replacement during collection.
    for (inputArray(inputs), statuses, 0..) |input, status, index| if (!std.meta.eql(status, try hashInput(budget, input, inputLimit(index)))) return error.RuntimeSelectionDrift;
    // Earlier members may change while later members or raw evidence are read.
    // Rewalk and rehash all retained member identities before returning facts.
    for (files) |file| if (!std.meta.eql(file.status, try inspectFile(budget, inputs.installation_directory, directory, file))) return error.RuntimeSelectionDrift;
    if (!std.meta.eql(directory, try metadata.statFd(inputs.installation_directory)) or !std.meta.eql(registry, try actorWitness(io, allocator, context))) return error.RuntimeSelectionDrift;
    try budget.check();
    const context_digest = try contextDigest(context);
    const retained = try allocator.create(Retained);
    retained.* = .{ .allocator = allocator, .inputs = inputs, .statuses = statuses, .registry = registry, .context_digest = context_digest, .directory = directory, .files = files, .payload_bytes = total };
    return @ptrCast(retained);
}

const Budget = struct {
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
    fn check(self: Budget) !void {
        try self.io.checkCancel();
        if (self.deadline.clock != .awake) return error.InvalidDeadline;
        if (self.deadline.durationFromNow(self.io).raw.toMilliseconds() <= 0) return error.Timeout;
    }
};

fn actorWitness(io: std.Io, allocator: std.mem.Allocator, context: ActorContext) !setup.RegistryWitness {
    if (context.options.adapter != .codex) return error.UnsupportedAdapter;
    const custody = context.options.native_custody orelse return error.NativeCustodyPending;
    try custody.validate();
    if (custody.state != .retain_ready and custody.state != .install_ready) return error.NativeCustodyPending;
    const transaction = custody.registry_transaction orelse return error.NativeCustodyPending;
    const capability = custody.registry_capability_digest orelse return error.NativeCustodyPending;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&context.options.capability, &digest, .{});
    if (!std.meta.eql(capability, digest) or !std.meta.eql(custody.capability_digest, digest)) return error.NativeCustodyGenerationMismatch;
    var options = context.options;
    options.deadline = context.deadline;
    const witness = (try setup.registryWitness(io, allocator, options)) orelse return error.NativeCustodyPending;
    if (witness.phase != .installed) return error.NativeCustodyPending;
    if (!std.meta.eql(witness.transaction, transaction) or !std.meta.eql(witness.capability_digest, capability)) return error.RuntimeSelectionDrift;
    return witness;
}

fn contextDigest(context: ActorContext) ![32]u8 {
    const custody = context.options.native_custody orelse return error.NativeCustodyPending;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("omux-runtime-acquisition-v1\x00");
    hash.update(@tagName(context.selection));
    hash.update("\x00");
    hash.update(context.options.state_dir);
    var epoch: [8]u8 = undefined;
    std.mem.writeInt(u64, &epoch, custody.adapter_epoch, .little);
    hash.update(&epoch);
    hash.update(&custody.capability_digest);
    hash.update(&custody.snapshot_digest);
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}

fn inputArray(inputs: Inputs) [5]Input {
    return .{ inputs.archive, inputs.manifest, inputs.runtime_receipt, inputs.source_receipt, inputs.producer_receipt };
}
fn inputLimit(index: usize) u64 {
    return if (index == 0) maximum_archive_bytes else maximum_metadata_bytes;
}
fn validateDirectory(status: metadata.Metadata) !void {
    if (status.mode & c.S.IFMT != c.S.IFDIR or status.mode & 0o7022 != 0 or (status.uid != 0 and status.uid != c.getuid())) return error.UnsafeRuntimeInput;
}
fn regular(status: metadata.Metadata) !void {
    if (status.mode & c.S.IFMT != c.S.IFREG or status.mode & 0o7022 != 0 or status.nlink != 1 or status.size <= 0 or (status.uid != 0 and status.uid != c.getuid())) return error.UnsafeRuntimeInput;
}
fn readAt(budget: Budget, descriptor: c.fd_t, bytes: []u8, offset: u64) !usize {
    while (true) {
        try budget.check();
        const count = c.pread(descriptor, bytes.ptr, bytes.len, @intCast(offset));
        if (count < 0) {
            if (c.errno(count) == .INTR) continue;
            return error.RuntimeInputReadFailed;
        }
        return @intCast(count);
    }
}
fn selectedRegular(status: metadata.Metadata) !void {
    if (status.uid == 0 and status.mode & c.S.IFMT == c.S.IFREG and status.mode & 0o7222 == 0 and status.nlink >= 1 and status.size > 0) return;
    return regular(status);
}
fn hashInput(budget: Budget, input: Input, limit: u64) !metadata.Metadata {
    if (std.mem.allEqual(u8, &input.sha256, 0) or input.bytes == 0 or input.bytes > limit) return error.RuntimeInputLimit;
    const before = try metadata.statFd(input.descriptor);
    try selectedRegular(before);
    if (@as(u64, @intCast(before.size)) != input.bytes) return error.RuntimeSelectionDrift;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < input.bytes) {
        const length = try readAt(budget, input.descriptor, buffer[0..@intCast(@min(buffer.len, input.bytes - offset))], offset);
        if (length == 0) return error.RuntimeSelectionDrift;
        hash.update(buffer[0..length]);
        offset += length;
    }
    var extra: [1]u8 = undefined;
    if (try readAt(budget, input.descriptor, &extra, offset) != 0) return error.RuntimeSelectionDrift;
    const after = try metadata.statFd(input.descriptor);
    if (!std.meta.eql(before, after)) return error.RuntimeSelectionDrift;
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    if (!std.meta.eql(digest, input.sha256)) return error.RuntimeSelectionDrift;
    return after;
}
fn readMetadata(allocator: std.mem.Allocator, budget: Budget, input: Input, status: metadata.Metadata) ![]u8 {
    const bytes = try allocator.alloc(u8, @intCast(input.bytes));
    errdefer allocator.free(bytes);
    var offset: usize = 0;
    while (offset < bytes.len) {
        const length = try readAt(budget, input.descriptor, bytes[offset..@min(bytes.len, offset + 64 * 1024)], offset);
        if (length == 0) return error.RuntimeSelectionDrift;
        offset += length;
    }
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    if (!std.meta.eql(digest, input.sha256) or !std.meta.eql(status, try metadata.statFd(input.descriptor))) return error.RuntimeSelectionDrift;
    return bytes;
}
fn openMember(budget: Budget, directory: c.fd_t, owner: metadata.Metadata, path: []const u8) !c.fd_t {
    _ = try pathLimit(path);
    var parent = c.openat(directory, ".", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (parent < 0) return error.UnsafeRuntimeInput;
    defer _ = c.close(parent);
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        try budget.check();
        const status = try metadata.statFd(parent);
        try validateDirectory(status);
        if (status.uid != owner.uid or status.gid != owner.gid) return error.UnsafeRuntimeInput;
        var name: [256:0]u8 = @splat(0);
        if (part.len >= name.len) return error.InvalidRuntimeManifest;
        @memcpy(name[0..part.len], part);
        if (parts.peek() != null) {
            const next = c.openat(parent, &name, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
            if (next < 0) return error.UnsafeRuntimeInput;
            _ = c.close(parent);
            parent = next;
        } else {
            const file = c.openat(parent, &name, .{ .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true });
            if (file < 0) return error.UnsafeRuntimeInput;
            return file;
        }
    }
    return error.InvalidRuntimeManifest;
}
fn inspectFile(budget: Budget, directory: c.fd_t, owner: metadata.Metadata, file: FileObservation) !metadata.Metadata {
    const descriptor = try openMember(budget, directory, owner, file.path);
    defer _ = c.close(descriptor);
    const after = try hashInput(budget, .{ .descriptor = descriptor, .sha256 = file.sha256, .bytes = file.bytes }, try pathLimit(file.path));
    // Immutable Nix mode normalization is not qualified by this foundation.
    if (after.mode & 0o7777 != file.mode or after.uid != owner.uid or after.gid != owner.gid) return error.UnsafeRuntimeInput;
    const reopened = try openMember(budget, directory, owner, file.path);
    defer _ = c.close(reopened);
    if (!std.meta.eql(after, try metadata.statFd(reopened))) return error.RuntimeSelectionDrift;
    return after;
}

fn parse(allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, allocator, bytes, .{ .duplicate_field_behavior = .@"error", .max_value_len = maximum_metadata_bytes });
}
fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidRuntimeManifest;
    return value.object.get(name) orelse error.InvalidRuntimeManifest;
}
fn objectField(value: std.json.Value, name: []const u8) !std.json.Value {
    const child = try field(value, name);
    if (child != .object) return error.InvalidRuntimeManifest;
    return child;
}
fn stringField(value: std.json.Value, name: []const u8) ![]const u8 {
    const child = try field(value, name);
    if (child != .string) return error.InvalidRuntimeManifest;
    return child.string;
}
fn positiveInteger(value: std.json.Value, name: []const u8) !u64 {
    const child = try field(value, name);
    if (child != .integer or child.integer <= 0) return error.InvalidRuntimeManifest;
    return @intCast(child.integer);
}
fn digestField(value: std.json.Value, name: []const u8) ![32]u8 {
    const text = try stringField(value, name);
    if (text.len != 64) return error.InvalidRuntimeManifest;
    for (text) |byte| if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return error.InvalidRuntimeManifest;
    var digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&digest, text);
    if (std.mem.allEqual(u8, &digest, 0)) return error.InvalidRuntimeManifest;
    return digest;
}
fn pathLimit(path: []const u8) !u64 {
    if (std.mem.eql(u8, path, launcher)) return 16 * 1024;
    if (std.mem.eql(u8, path, backend)) return maximum_backend_bytes;
    if (std.mem.eql(u8, path, ca_bundle)) return 16 * 1024 * 1024;
    const prefix = "lib/codex/lib/";
    if (!std.mem.startsWith(u8, path, prefix) or path.len <= prefix.len or path.len > prefix.len + 255) return error.InvalidRuntimeManifest;
    const basename = path[prefix.len..];
    if (std.mem.eql(u8, basename, ".") or std.mem.eql(u8, basename, "..")) return error.InvalidRuntimeManifest;
    for (basename) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '.' and byte != '_' and byte != '+' and byte != '-') return error.InvalidRuntimeManifest;
    return maximum_library_bytes;
}
fn references(manifest: std.json.Value, receipt: std.json.Value, source: std.json.Value, producer: std.json.Value, inputs: Inputs) !void {
    for ([_]std.json.Value{ manifest, receipt }) |value| {
        if (try positiveInteger(value, "schema_version") != 1 or !std.mem.eql(u8, try stringField(value, "status"), "native-owner-runtime-proof-candidate")) return error.InvalidRuntimeManifest;
        const support = try field(value, "native_support");
        if (support != .bool or support.bool) return error.InvalidRuntimeManifest;
    }
    if (!std.mem.eql(u8, try stringField(manifest, "target"), "x86_64-linux") or !std.meta.eql(try digestField(receipt, "archive_sha256"), inputs.archive.sha256) or try positiveInteger(receipt, "archive_bytes") != inputs.archive.bytes or !std.meta.eql(try digestField(receipt, "manifest_sha256"), inputs.manifest.sha256)) return error.RuntimeSelectionDrift;
    const transform = try objectField(manifest, "transformations");
    const candidate = try objectField(manifest, "candidate");
    if (!std.meta.eql(try digestField(transform, "source_receipt_sha256"), inputs.source_receipt.sha256) or !std.meta.eql(try digestField(transform, "producer_receipt_sha256"), inputs.producer_receipt.sha256) or !std.meta.eql(try digestField(candidate, "current_source_receipt_sha256"), inputs.source_receipt.sha256)) return error.RuntimeSelectionDrift;
    // Structural cross-references only; these do not establish a build result.
    const commit = try stringField(candidate, "upstream_commit");
    if (commit.len != 40 or !std.mem.eql(u8, commit, try stringField(source, "commit")) or !std.mem.eql(u8, commit, try stringField(producer, "upstream_commit")) or !std.meta.eql(try digestField(producer, "current_source_receipt_sha256"), inputs.source_receipt.sha256)) return error.RuntimeSelectionDrift;
    const runtime = try objectField(manifest, "runtime");
    if (!std.mem.eql(u8, try stringField(runtime, "loader"), loader) or !std.mem.eql(u8, try stringField(runtime, "caBundle"), ca_bundle)) return error.InvalidRuntimeManifest;
}
fn declaredMembership(manifest: std.json.Value, files: []const FileObservation) !void {
    const runtime = try objectField(manifest, "runtime");
    const dependencies = try field(runtime, "dependencies");
    if (dependencies != .array or dependencies.array.items.len == 0 or dependencies.array.items.len + 3 != files.len) return error.InvalidRuntimeManifest;
    const records = try objectField(manifest, "files");
    for ([_][]const u8{ launcher, backend, ca_bundle, loader }) |name| if (!records.object.contains(name)) return error.InvalidRuntimeManifest;
    var previous: ?[]const u8 = null;
    for (dependencies.array.items) |dependency| {
        if (dependency != .string or !std.mem.startsWith(u8, dependency.string, "lib/codex/lib/") or !records.object.contains(dependency.string)) return error.InvalidRuntimeManifest;
        _ = try pathLimit(dependency.string);
        if (previous) |name| if (std.mem.order(u8, name, dependency.string) != .lt) return error.InvalidRuntimeManifest;
        previous = dependency.string;
    }
}

/// Owned selected descriptors and names for the modern branch. The declaration
/// reader may be released after construction; no parsed reader slice survives.
const InputWitness = struct { input: Input, status: metadata.Metadata, limit: u64 };
const ModernRetained = struct {
    allocator: std.mem.Allocator,
    inputs: Inputs,
    witnesses: std.ArrayList(InputWitness) = .empty,
    root_status: metadata.Metadata,
    retained_bytes: u64 = 0,
    declaration_reader: ?*deployment.OwnedInputs = null,
    pub fn deinit(self: *ModernRetained) void {
        if (self.declaration_reader) |reader| reader.deinit();
        for (self.witnesses.items) |row| _ = c.close(row.input.descriptor);
        if (self.inputs.deployment_root) |root| _ = c.close(root.descriptor);
        // All names and arrays are in the qualification-owned bounded arena.
    }
    pub fn recheckIdentity(self: *const ModernRetained, budget: Budget) !void {
        try budget.check();
        const root = self.inputs.deployment_root orelse return error.InvalidDeploymentSelection;
        const named = try nix.openSelectedDirectory(budget.io, self.allocator, budget.deadline, root.path);
        defer _ = c.close(named);
        if (!std.meta.eql(self.root_status, try metadata.statFd(root.descriptor)) or
            !std.meta.eql(self.root_status, try metadata.statFd(named))) return error.RuntimeSelectionDrift;
        for (self.witnesses.items) |row| {
            try budget.check();
            if (!std.meta.eql(row.status, try metadata.statFd(row.input.descriptor))) return error.RuntimeSelectionDrift;
        }
        const reader = self.declaration_reader orelse return error.InvalidDeploymentSelection;
        try reader.recheckIdentity(budget.io);
        // Engine independently fences its original reader and publication name.
    }
    pub fn recheck(self: *const ModernRetained, budget: Budget) !void {
        try budget.check();
        const root = self.inputs.deployment_root orelse return error.InvalidDeploymentSelection;
        const named = try nix.openSelectedDirectory(budget.io, self.allocator, budget.deadline, root.path);
        defer _ = c.close(named);
        if (!std.meta.eql(self.root_status, try metadata.statFd(root.descriptor)) or
            !std.meta.eql(self.root_status, try metadata.statFd(named))) return error.RuntimeSelectionDrift;
        for (self.witnesses.items) |row| {
            if (!std.meta.eql(row.status, try hashInput(budget, row.input, row.limit))) return error.RuntimeSelectionDrift;
        }
        try budget.check();
    }
    fn take(self: *ModernRetained, budget: Budget, input: Input, limit: u64) !Input {
        try budget.check();
        if (input.bytes == 0 or input.bytes > maximum_payload_bytes - self.retained_bytes) return error.RuntimeInputLimit;
        const before = try hashInput(budget, input, limit);
        const descriptor = c.fcntl(input.descriptor, c.F.DUPFD_CLOEXEC, @as(c_int, 0));
        if (descriptor < 0) return error.UnsafeRuntimeInput;
        errdefer _ = c.close(descriptor);
        const copied: Input = .{ .descriptor = descriptor, .sha256 = input.sha256, .bytes = input.bytes };
        if (!std.meta.eql(before, try hashInput(budget, copied, limit))) return error.RuntimeSelectionDrift;
        try self.witnesses.append(self.allocator, .{ .input = copied, .status = before, .limit = limit });
        self.retained_bytes += input.bytes;
        return copied;
    }
    fn members(self: *ModernRetained, budget: Budget, rows: []const ModernMember, maximum: usize) ![]const ModernMember {
        if (rows.len > maximum) return error.RuntimeInputLimit;
        const owned = try self.allocator.alloc(ModernMember, rows.len);
        for (rows, owned, 0..) |row, *copy, index| {
            try budget.check();
            if (row.name.len == 0 or row.name.len > 4096 or
                (index > 0 and std.mem.order(u8, rows[index - 1].name, row.name) != .lt)) return error.InvalidRuntimeProvenance;
            copy.* = .{ .name = try self.allocator.dupe(u8, row.name), .input = try self.take(budget, row.input, maximum_metadata_bytes) };
        }
        return owned;
    }
    fn authority(self: *ModernRetained, budget: Budget, value: ModernAuthority, count: usize) !ModernAuthority {
        if (value.members.len != count) return error.InvalidRuntimeProvenance;
        return .{ .outer = try self.take(budget, value.outer, maximum_metadata_bytes), .evidence = try self.take(budget, value.evidence, maximum_metadata_bytes), .members = try self.members(budget, value.members, count) };
    }
};
fn retainedInputBudget(budget: Budget, total: *u64, input: Input, limit: u64) !void {
    try budget.check();
    if (input.bytes == 0 or input.bytes > limit or input.bytes > maximum_payload_bytes - total.*) return error.RuntimeInputLimit;
    total.* += input.bytes;
}
fn retainedAuthorityBudget(budget: Budget, total: *u64, authority: ModernAuthority, count: usize) !void {
    if (authority.members.len != count) return error.InvalidRuntimeProvenance;
    try retainedInputBudget(budget, total, authority.outer, maximum_metadata_bytes);
    try retainedInputBudget(budget, total, authority.evidence, maximum_metadata_bytes);
    for (authority.members) |member| try retainedInputBudget(budget, total, member.input, maximum_metadata_bytes);
}
fn preflightCarrierRetention(budget: Budget, inputs: Inputs, material: ModernInputs) !void {
    try budget.check();
    const carrier = material.carrier_materials orelse return error.InvalidRuntimeProvenance;
    // 49 original witnesses + four compact receipts + two four-row proofs.
    if (material.protocol_schema_files.len > maximum_files - 61 or
        material.native_acquisition_artifact_files.len > maximum_files - 61 - material.protocol_schema_files.len)
        return error.RuntimeInputLimit;
    var total: u64 = 0;
    for (inputArray(inputs), 0..) |input, index| try retainedInputBudget(budget, &total, input, switch (index) {
        0 => maximum_archive_bytes,
        1 => maximum_direct_manifest_bytes,
        else => maximum_metadata_bytes,
    });
    try retainedInputBudget(budget, &total, inputs.registration_receipt orelse return error.InvalidNixRuntimeProvenance, maximum_metadata_bytes);
    try retainedInputBudget(budget, &total, inputs.deployment_declaration orelse return error.InvalidDeploymentSelection, maximum_deployment_declaration_bytes);
    for (material.roles, 0..) |input, index| try retainedInputBudget(budget, &total, input, if (index == @backingInt(ModernRole.codex)) maximum_backend_bytes else maximum_metadata_bytes);
    for (material.authority_receipts, 0..) |group, index| try retainedAuthorityBudget(budget, &total, group, if (index == 0) 6 else 2);
    try retainedInputBudget(budget, &total, material.package_selection, maximum_metadata_bytes);
    try retainedInputBudget(budget, &total, material.package_outputs, maximum_deployment_declaration_bytes);
    try retainedAuthorityBudget(budget, &total, material.package_authority, 2);
    for ([_][]const ModernMember{ material.protocol_schema_files, material.native_acquisition_artifact_files }) |members| {
        for (members) |member| try retainedInputBudget(budget, &total, member.input, maximum_metadata_bytes);
    }
    for (carrier.receipts) |input| try retainedInputBudget(budget, &total, input, maximum_metadata_bytes);
    for (carrier.authority_receipts) |group| try retainedAuthorityBudget(budget, &total, group, 2);
}
fn retainModern(a: std.mem.Allocator, budget: Budget, inputs: Inputs) !*ModernRetained {
    try budget.check();
    const material = inputs.modern_materials orelse return error.InvalidRuntimeProvenance;
    const root = inputs.deployment_root orelse return error.InvalidDeploymentSelection;
    const declaration = inputs.deployment_declaration orelse return error.InvalidDeploymentSelection;
    const registration = inputs.registration_receipt orelse return error.InvalidNixRuntimeProvenance;
    // V2 accounts for every retained witness, including the declaration. The
    // historical V1 branch keeps its existing bounds and representation.
    if (material.carrier_materials != null) try preflightCarrierRetention(budget, inputs, material);
    if (material.protocol_schema_files.len < 2 or material.native_acquisition_artifact_files.len != 6 or
        material.protocol_schema_files.len + material.native_acquisition_artifact_files.len + 48 > maximum_files)
        return error.RuntimeInputLimit;
    const status = try metadata.statFd(root.descriptor);
    if (status.mode & c.S.IFMT != c.S.IFDIR or status.uid != 0 or status.mode & 0o7222 != 0)
        return error.InvalidDeploymentSelection;
    const descriptor = c.openat(root.descriptor, ".", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (descriptor < 0) return error.InvalidDeploymentSelection;
    errdefer _ = c.close(descriptor);
    if (!std.meta.eql(status, try metadata.statFd(descriptor))) return error.RuntimeSelectionDrift;
    const retained = try a.create(ModernRetained);
    retained.* = .{ .allocator = a, .inputs = inputs, .root_status = status };
    retained.inputs.deployment_root = .{ .path = try a.dupe(u8, root.path), .descriptor = descriptor };
    errdefer for (retained.witnesses.items) |row| {
        _ = c.close(row.input.descriptor);
    };
    retained.inputs.archive = try retained.take(budget, inputs.archive, maximum_archive_bytes);
    retained.inputs.manifest = try retained.take(budget, inputs.manifest, maximum_direct_manifest_bytes);
    retained.inputs.runtime_receipt = try retained.take(budget, inputs.runtime_receipt, maximum_metadata_bytes);
    retained.inputs.source_receipt = try retained.take(budget, inputs.source_receipt, maximum_metadata_bytes);
    retained.inputs.producer_receipt = try retained.take(budget, inputs.producer_receipt, maximum_metadata_bytes);
    retained.inputs.registration_receipt = try retained.take(budget, registration, maximum_metadata_bytes);
    retained.inputs.deployment_declaration = try retained.take(budget, declaration, maximum_deployment_declaration_bytes);
    var roles: [12]Input = undefined;
    for (material.roles, &roles, 0..) |row, *copy, index| copy.* = try retained.take(budget, row, if (index == @backingInt(ModernRole.codex)) maximum_backend_bytes else maximum_metadata_bytes);
    var authorities: [5]ModernAuthority = undefined;
    for (material.authority_receipts, &authorities, 0..) |group, *copy, index| copy.* =
        try retained.authority(budget, group, if (index == 0) 6 else 2);
    var carrier_materials: ?CarrierInputs = null;
    if (material.carrier_materials) |carrier| {
        var receipts: [4]Input = undefined;
        for (carrier.receipts, &receipts) |row, *copy| copy.* = try retained.take(budget, row, maximum_metadata_bytes);
        var proof: [2]ModernAuthority = undefined;
        for (carrier.authority_receipts, &proof) |group, *copy| copy.* = try retained.authority(budget, group, 2);
        carrier_materials = .{ .receipts = receipts, .authority_receipts = proof };
    }
    retained.inputs.modern_materials = .{
        .package_selection = try retained.take(budget, material.package_selection, maximum_metadata_bytes),
        .package_outputs = try retained.take(budget, material.package_outputs, maximum_deployment_declaration_bytes),
        .package_output_root = try a.dupe(u8, material.package_output_root),
        .package_authority = try retained.authority(budget, material.package_authority, 2),
        .roles = roles,
        .protocol_schema_files = try retained.members(budget, material.protocol_schema_files, maximum_files),
        .native_acquisition_artifact_files = try retained.members(budget, material.native_acquisition_artifact_files, 6),
        .authority_receipts = authorities,
        .carrier_materials = carrier_materials,
    };
    try retained.recheck(budget);
    const owned_reader = try deployment.load(budget.io, a, .{ .path = retained.inputs.deployment_root.?.path, .descriptor = descriptor }, budget.deadline);
    errdefer owned_reader.deinit();
    try equalSelectedInputs(budget, retained.inputs, owned_reader.inputs());
    retained.declaration_reader = owned_reader;
    return retained;
}

fn exactObject(value: std.json.Value, names: []const []const u8) !void {
    if (value != .object or value.object.count() != names.len) return error.InvalidRuntimeProvenance;
    for (names) |name| if (!value.object.contains(name)) return error.InvalidRuntimeProvenance;
}
fn expectText(value: std.json.Value, key: []const u8, expected: []const u8) !void {
    if (!std.mem.eql(u8, try stringField(value, key), expected)) return error.InvalidRuntimeProvenance;
}
fn expectBool(value: std.json.Value, key: []const u8, expected: bool) !void {
    const child = try field(value, key);
    if (child != .bool or child.bool != expected) return error.InvalidRuntimeProvenance;
}
fn integer(value: std.json.Value, key: []const u8) !u64 {
    const child = try field(value, key);
    if (child != .integer or child.integer < 0) return error.InvalidRuntimeProvenance;
    return @intCast(child.integer);
}
fn inputRow(value: std.json.Value, input: Input) !void {
    if (try positiveInteger(value, "bytes") != input.bytes or
        !std.meta.eql(try digestField(value, "sha256"), input.sha256)) return error.RuntimeSelectionDrift;
}
fn loadSelectedJson(a: std.mem.Allocator, budget: Budget, input: Input, maximum: u64) !std.json.Parsed(std.json.Value) {
    const bytes = try readSelectedInput(budget.io, a, budget.deadline, input, maximum);
    defer a.free(bytes);
    return std.json.parseFromSlice(std.json.Value, a, bytes, .{ .duplicate_field_behavior = .@"error", .allocate = .alloc_always, .max_value_len = 4096 });
}
fn canonicalAbsolute(value: []const u8) !void {
    if (value.len < 2 or value.len > 4096 or value[0] != '/') return error.InvalidRuntimeProvenance;
    var parts = std.mem.splitScalar(u8, value[1..], '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.InvalidRuntimeProvenance;
        for (part) |byte| if (byte < 32 or byte >= 127 or byte == '\\') return error.InvalidRuntimeProvenance;
    }
}
const PackageProducerContract = struct {
    target: []const u8,
    profile: []const u8,
    output_suffix: []const u8,
};
/// Select the declared producer family; the complete selection schema/kind and
/// retained PACKAGE evidence still have to agree before any adoption.
fn packageProducerContract(carrier_family: bool) PackageProducerContract {
    return if (carrier_family) .{
        .target = "//tools:codex_native_carrier_runtime_package",
        .profile = "native-sdk-carrier-package-reserved",
        .output_suffix = "/testlogs/tools/codex_native_carrier_runtime_package/test.outputs/fresh-native-runtime",
    } else .{
        .target = "//tools:codex_native_acquisition_runtime_package",
        .profile = "native-acquisition-package-reserved",
        .output_suffix = "/testlogs/tools/codex_native_acquisition_runtime_package/test.outputs/fresh-native-runtime",
    };
}
/// Bind the five exact selected outputs to the independently selected actual
/// package action's copied stdout. The producer never creates its own guardian.
fn packageOutputBinding(a: std.mem.Allocator, budget: Budget, inputs: Inputs) !void {
    const modern = inputs.modern_materials orelse return error.InvalidRuntimeProvenance;
    if (!std.meta.eql(inputs.producer_receipt.sha256, modern.package_authority.outer.sha256) or
        inputs.producer_receipt.bytes != modern.package_authority.outer.bytes) return error.RuntimeSelectionDrift;
    try canonicalAbsolute(modern.package_output_root);
    const output = try loadSelectedJson(a, budget, modern.package_outputs, maximum_deployment_declaration_bytes);
    defer output.deinit();
    try exactObject(output.value, &.{ "schema_version", "kind", "purpose", "acquisitionContract", "files" });
    if (try integer(output.value, "schema_version") != 1) return error.InvalidRuntimeProvenance;
    try expectText(output.value, "kind", "omux-native-acquisition-package-output-v1");
    try expectText(output.value, "purpose", "evaluation-only");
    try expectText(output.value, "acquisitionContract", "unsupported");
    const files = try objectField(output.value, "files");
    const names = [_][]const u8{ "fresh-native-runtime.tar.gz", "runtime-manifest.json", "runtime-receipt.json", "registration-receipt.json", "package-selection.json" };
    try exactObject(files, &names);
    const selected = [_]Input{ inputs.archive, inputs.manifest, inputs.runtime_receipt, inputs.registration_receipt orelse return error.InvalidNixRuntimeProvenance, modern.package_selection };
    for (names, selected) |name, input| {
        try budget.check();
        const row = try objectField(files, name);
        try exactObject(row, &.{ "sha256", "bytes" });
        try inputRow(row, input);
    }
    const outer = try loadSelectedJson(a, budget, modern.package_authority.outer, maximum_metadata_bytes);
    defer outer.deinit();
    const contract = packageProducerContract(modern.carrier_materials != null);
    const target = contract.target;
    const package_source = try stringField(outer.value, "source_commit");
    if (package_source.len != 40 or std.mem.allEqual(u8, package_source, '0')) return error.InvalidRuntimeProvenance;
    for (package_source) |byte| if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return error.InvalidRuntimeProvenance;
    _ = try digestField(outer.value, "graph_sha256");
    try reservedProducerPolicy(a, outer.value, contract.profile, "native_acquisition_inputs_reservation");
    try expectText(outer.value, "manager", "system");
    try expectText(outer.value, "verb", "test");
    if (try integer(outer.value, "exit") != 0 or try integer(outer.value, "workload_exit") != 0 or
        try field(outer.value, "controller_failure") != .null) return error.InvalidRuntimeProvenance;
    try expectBool(outer.value, "descendants_empty", true);
    try expectText(try objectField(outer.value, "cleanup"), "state", "empty");
    try expectText(outer.value, "source_dirty", "false");
    try expectBool(outer.value, "cache_reuse_requested", false);
    if (try field(outer.value, "cache_policy") != .null or try field(outer.value, "cache_key") != .null) return error.InvalidRuntimeProvenance;
    const targets = try field(outer.value, "targets");
    if (targets != .array or targets.array.items.len != 1 or targets.array.items[0] != .string or
        !std.mem.eql(u8, targets.array.items[0].string, target)) return error.InvalidRuntimeProvenance;
    const id = try stringField(outer.value, "id");
    if (id.len != 36) return error.InvalidRuntimeProvenance;
    for (id, 0..) |byte, index| {
        if (index == 8 or index == 13 or index == 18 or index == 23) {
            if (byte != '-') return error.InvalidRuntimeProvenance;
        } else if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return error.InvalidRuntimeProvenance;
    }
    const unit = try std.fmt.allocPrint(a, "omux-execution-{s}.service", .{id});
    defer a.free(unit);
    try expectText(outer.value, "unit", unit);
    const base = try stringField(outer.value, "output_base");
    try canonicalAbsolute(base);
    const prefix = try std.fmt.allocPrint(a, "{s}/execroot/_main/bazel-out/", .{base});
    defer a.free(prefix);
    const suffix = contract.output_suffix;
    if (!std.mem.startsWith(u8, modern.package_output_root, prefix) or
        !std.mem.endsWith(u8, modern.package_output_root, suffix) or modern.package_output_root.len <= prefix.len + suffix.len)
        return error.InvalidRuntimeProvenance;
    const configuration = modern.package_output_root[prefix.len .. modern.package_output_root.len - suffix.len];
    if (modern.carrier_materials != null) {
        try collectorConfiguration(configuration);
    } else {
        for (configuration) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '-' and byte != '.') return error.InvalidRuntimeProvenance;
    }
    const evidence_row = try objectField(outer.value, "test_evidence");
    try expectText(evidence_row, "state", "preserved");
    if (!std.meta.eql(try digestField(evidence_row, "sha256"), modern.package_authority.evidence.sha256)) return error.RuntimeSelectionDrift;
    const evidence = try loadSelectedJson(a, budget, modern.package_authority.evidence, maximum_metadata_bytes);
    defer evidence.deinit();
    if (try integer(evidence.value, "schema") != 1 or try integer(evidence.value, "bazel_exit") != 0 or
        try integer(evidence.value, "epoch_start_ns") != try integer(outer.value, "epoch_start_ns")) return error.InvalidRuntimeProvenance;
    const observed_targets = try field(evidence.value, "targets");
    if (observed_targets != .array or observed_targets.array.items.len != 1 or observed_targets.array.items[0] != .string or
        !std.mem.eql(u8, observed_targets.array.items[0].string, target)) return error.InvalidRuntimeProvenance;
    const results = try field(evidence.value, "results");
    if (results != .array or results.array.items.len != 1) return error.InvalidRuntimeProvenance;
    const result = results.array.items[0];
    try expectText(result, "target", target);
    try expectText(result, "state", "observed");
    var log: ?Input = null;
    var xml: ?Input = null;
    if (modern.carrier_materials != null) {
        // PACKAGE members are protected declaration aliases, not the original
        // producer-path map used by the SDK/core. Bind their collector names
        // and actual content pins without inventing original host paths.
        const copied = try selectedCopiedTestFiles(a, budget, result, null, modern.package_authority, target, configuration, null);
        log = copied.log;
        xml = copied.xml;
        const raw_xml = try readSelectedInput(budget.io, a, budget.deadline, copied.xml, maximum_metadata_bytes);
        defer a.free(raw_xml);
        try successfulTestXml(budget, raw_xml);
    } else {
        const members = try field(result, "files");
        if (members != .array or members.array.items.len != 2 or modern.package_authority.members.len != 2) return error.InvalidRuntimeProvenance;
        for (members.array.items) |row| {
            try budget.check();
            try expectText(row, "state", "copied");
            const name = try stringField(row, "file");
            var selected_member: ?Input = null;
            for (modern.package_authority.members) |member| if (std.mem.eql(u8, member.name, name)) {
                if (selected_member != null) return error.InvalidRuntimeProvenance;
                selected_member = member.input;
            };
            const chosen = selected_member orelse return error.InvalidRuntimeProvenance;
            try inputRow(row, chosen);
            const source = try stringField(row, "source");
            if (std.mem.eql(u8, source, "test.log")) {
                if (log != null) return error.InvalidRuntimeProvenance;
                log = chosen;
            } else if (std.mem.eql(u8, source, "test.xml")) {
                if (xml != null) return error.InvalidRuntimeProvenance;
                xml = chosen;
            } else return error.InvalidRuntimeProvenance;
        }
    }
    if (xml == null) return error.InvalidRuntimeProvenance;
    const raw_log = try readSelectedInput(budget.io, a, budget.deadline, log orelse return error.InvalidRuntimeProvenance, maximum_metadata_bytes);
    defer a.free(raw_log);
    try validateOutputMarker(a, budget, raw_log, modern.package_outputs.sha256);
}

fn decimal(value: []const u8, maximum_digits: usize) !u64 {
    if (value.len == 0 or value.len > maximum_digits) return error.InvalidRuntimeProvenance;
    for (value) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidRuntimeProvenance;
    return std.fmt.parseInt(u64, value, 10) catch error.InvalidRuntimeProvenance;
}
fn durationMicros(value: []const u8) !u64 {
    if (value.len == 0 or value.len > 64) return error.InvalidRuntimeProvenance;
    var index: usize = 0;
    var total: u64 = 0;
    while (index < value.len) {
        if (value[index] == ' ') {
            index += 1;
            continue;
        }
        const start = index;
        while (index < value.len and std.ascii.isDigit(value[index])) : (index += 1) {}
        const whole = try decimal(value[start..index], 12);
        var fraction: u64 = 0;
        var denominator: u64 = 1;
        if (index < value.len and value[index] == '.') {
            index += 1;
            const fraction_start = index;
            while (index < value.len and std.ascii.isDigit(value[index])) : (index += 1) {}
            const digits = value[fraction_start..index];
            fraction = try decimal(digits, 6);
            for (digits) |_| denominator = try std.math.mul(u64, denominator, 10);
        }
        var scale: u64 = 0;
        inline for (.{ .{ "min", @as(u64, 60000000) }, .{ "us", @as(u64, 1) }, .{ "ms", @as(u64, 1000) }, .{ "s", @as(u64, 1000000) }, .{ "h", @as(u64, 3600000000) } }) |unit| {
            if (scale == 0 and std.mem.startsWith(u8, value[index..], unit[0])) {
                scale = unit[1];
                index += unit[0].len;
            }
        }
        if (scale == 0) return error.InvalidRuntimeProvenance;
        total = try std.math.add(u64, total, try std.math.mul(u64, whole, scale));
        total = try std.math.add(u64, total, (try std.math.mul(u64, fraction, scale)) / denominator);
    }
    if (total == 0) return error.InvalidRuntimeProvenance;
    return total;
}
fn reservedProducerPolicy(a: std.mem.Allocator, value: std.json.Value, profile: []const u8, key: []const u8) !void {
    try expectText(value, "profile", profile);
    const observed = try objectField(value, "observed_properties");
    inline for (.{ .{ "MemoryMax", "4026531840" }, .{ "MemorySwapMax", "0" }, .{ "TasksMax", "480" }, .{ "PrivateNetwork", "yes" }, .{ "KillMode", "control-group" }, .{ "SendSIGKILL", "yes" }, .{ "OOMPolicy", "kill" }, .{ "RemainAfterExit", "yes" } }) |item| try expectText(observed, item[0], item[1]);
    if (try durationMicros(try stringField(observed, "CPUQuotaPerSecUSec")) != 1900000 or
        try durationMicros(try stringField(observed, "RuntimeMaxUSec")) > 1200000000) return error.InvalidRuntimeProvenance;
    const reservation = try objectField(value, key);
    try exactObject(reservation, &.{ "scope", "profile", "original_entry_monotonic_ns", "original_deadline_monotonic_ns", "verified_after_cleanup", "resident", "input_predicates_required", "query_tools_qualified", "metadata_qualified", "sdk_qualified", "schema_qualified", "compiler_qualified", "native_runtime_qualified", "continuity_qualified", "custody_qualified", "health_qualified", "credential_acquisition", "native_source_finalized", "native_support", "provider_identity_proved", "live_handoff_proven", "context_rotation", "daemon_context_acquisition" });
    const scope = try std.fmt.allocPrint(a, "fixed-{s}-v1", .{profile});
    defer a.free(scope);
    try expectText(reservation, "scope", scope);
    try expectText(reservation, "profile", profile);
    const entry = try integer(reservation, "original_entry_monotonic_ns");
    const deadline = try integer(reservation, "original_deadline_monotonic_ns");
    if (deadline <= entry or deadline - entry != 1200000000000) return error.InvalidRuntimeProvenance;
    try expectBool(reservation, "verified_after_cleanup", true);
    try expectBool(reservation, "input_predicates_required", true);
    inline for (.{ "query_tools_qualified", "metadata_qualified", "sdk_qualified", "schema_qualified", "compiler_qualified", "native_runtime_qualified", "continuity_qualified", "custody_qualified", "health_qualified", "credential_acquisition", "native_source_finalized", "native_support", "provider_identity_proved", "live_handoff_proven", "context_rotation", "daemon_context_acquisition" }) |name| try expectBool(reservation, name, false);
    const resident = try objectField(reservation, "resident");
    try exactObject(resident, &.{ "scope", "kernel_bounds", "observations", "initial_direct_processes_retained", "initial_direct_process_count", "outer_pid_namespace_matched", "hierarchical_caps", "descendant_process_inventory", "installation_qualified", "health_observed", "custody_observed", "resident_signalled", "whole_host_reservation" });
    try expectText(resident, "scope", "sampled-fixed-default-cgroup-kernel-reservation-v1");
    const observations = try integer(resident, "observations");
    const processes = try integer(resident, "initial_direct_process_count");
    if (observations == 0 or observations > 65535 or processes == 0 or processes > 32) return error.InvalidRuntimeProvenance;
    inline for (.{ "initial_direct_processes_retained", "outer_pid_namespace_matched", "hierarchical_caps" }) |name| try expectBool(resident, name, true);
    inline for (.{ "descendant_process_inventory", "installation_qualified", "health_observed", "custody_observed", "resident_signalled", "whole_host_reservation" }) |name| try expectBool(resident, name, false);
    const bounds = try objectField(resident, "kernel_bounds");
    try exactObject(bounds, &.{ "memory.max", "memory.swap.max", "pids.max", "cpu.max" });
    try expectText(bounds, "memory.swap.max", "0");
    const memory = try decimal(try stringField(bounds, "memory.max"), 10);
    const tasks = try decimal(try stringField(bounds, "pids.max"), 2);
    if (memory == 0 or memory > 268435456 or tasks == 0 or tasks > 32 or processes > tasks) return error.InvalidRuntimeProvenance;
    var cpu = std.mem.tokenizeScalar(u8, try stringField(bounds, "cpu.max"), ' ');
    const quota = try decimal(cpu.next() orelse return error.InvalidRuntimeProvenance, 9);
    const period = try decimal(cpu.next() orelse return error.InvalidRuntimeProvenance, 9);
    if (cpu.next() != null or quota == 0 or period == 0 or try std.math.mul(u64, quota, 10) > period) return error.InvalidRuntimeProvenance;
}

fn equalInput(budget: Budget, left: Input, right: Input) !void {
    try budget.check();
    if (left.bytes != right.bytes or !std.meta.eql(left.sha256, right.sha256) or
        !std.meta.eql(try metadata.statFd(left.descriptor), try metadata.statFd(right.descriptor))) return error.RuntimeSelectionDrift;
}
fn equalMembers(budget: Budget, left: []const ModernMember, right: []const ModernMember) !void {
    if (left.len != right.len) return error.RuntimeSelectionDrift;
    for (left, right) |x, y| {
        if (!std.mem.eql(u8, x.name, y.name)) return error.RuntimeSelectionDrift;
        try equalInput(budget, x.input, y.input);
    }
}
fn equalAuthority(budget: Budget, left: ModernAuthority, right: ModernAuthority) !void {
    try equalInput(budget, left.outer, right.outer);
    try equalInput(budget, left.evidence, right.evidence);
    try equalMembers(budget, left.members, right.members);
}
fn equalSelectedInputs(budget: Budget, left: Inputs, right: Inputs) !void {
    for (inputArray(left), inputArray(right)) |x, y| try equalInput(budget, x, y);
    try equalInput(budget, left.registration_receipt orelse return error.InvalidDeploymentSelection, right.registration_receipt orelse return error.InvalidDeploymentSelection);
    try equalInput(budget, left.deployment_declaration orelse return error.InvalidDeploymentSelection, right.deployment_declaration orelse return error.InvalidDeploymentSelection);
    const x = left.modern_materials orelse return error.InvalidDeploymentSelection;
    const y = right.modern_materials orelse return error.InvalidDeploymentSelection;
    try equalInput(budget, x.package_selection, y.package_selection);
    try equalInput(budget, x.package_outputs, y.package_outputs);
    if (!std.mem.eql(u8, x.package_output_root, y.package_output_root)) return error.RuntimeSelectionDrift;
    try equalAuthority(budget, x.package_authority, y.package_authority);
    for (x.roles, y.roles) |one, two| try equalInput(budget, one, two);
    for (x.authority_receipts, y.authority_receipts) |one, two| try equalAuthority(budget, one, two);
    if ((x.carrier_materials == null) != (y.carrier_materials == null)) return error.RuntimeSelectionDrift;
    if (x.carrier_materials) |one| {
        const two = y.carrier_materials.?;
        for (one.receipts, two.receipts) |first, second| try equalInput(budget, first, second);
        for (one.authority_receipts, two.authority_receipts) |first, second| try equalAuthority(budget, first, second);
    }
    try equalMembers(budget, x.protocol_schema_files, y.protocol_schema_files);
    try equalMembers(budget, x.native_acquisition_artifact_files, y.native_acquisition_artifact_files);
}

fn jsonEqual(budget: Budget, left: std.json.Value, right: std.json.Value, depth: usize) !bool {
    try budget.check();
    if (depth > 64) return error.RuntimeInputLimit;
    if (std.meta.activeTag(left) != std.meta.activeTag(right)) return false;
    return switch (left) {
        .null => true,
        .bool => left.bool == right.bool,
        .integer => left.integer == right.integer,
        .float => left.float == right.float,
        .number_string => std.mem.eql(u8, left.number_string, right.number_string),
        .string => std.mem.eql(u8, left.string, right.string),
        .array => blk: {
            if (left.array.items.len != right.array.items.len) break :blk false;
            for (left.array.items, right.array.items) |x, y| if (!try jsonEqual(budget, x, y, depth + 1)) break :blk false;
            break :blk true;
        },
        .object => blk: {
            if (left.object.count() != right.object.count()) break :blk false;
            var entries = left.object.iterator();
            while (entries.next()) |entry| {
                const other = right.object.get(entry.key_ptr.*) orelse break :blk false;
                if (!try jsonEqual(budget, entry.value_ptr.*, other, depth + 1)) break :blk false;
            }
            break :blk true;
        },
    };
}
fn sameValue(budget: Budget, left: std.json.Value, right: std.json.Value, key: []const u8) !void {
    if (!try jsonEqual(budget, try field(left, key), try field(right, key), 0)) return error.RuntimeSelectionDrift;
}
fn memberMap(budget: Budget, rows: std.json.Value, members: []const ModernMember) !void {
    if (rows != .object or rows.object.count() != members.len) return error.InvalidRuntimeProvenance;
    for (members) |member| {
        try budget.check();
        const row = try objectField(rows, member.name);
        try exactObject(row, &.{ "path", "sha256", "bytes" });
        try canonicalAbsolute(try stringField(row, "path"));
        try inputRow(row, member.input);
    }
}
fn authorityMap(budget: Budget, rows: std.json.Value, group: ModernAuthority) !void {
    try exactObject(rows, &.{ "outer", "evidence", "members" });
    for ([_][]const u8{ "outer", "evidence" }, [_]Input{ group.outer, group.evidence }) |name, input| {
        const row = try objectField(rows, name);
        try exactObject(row, &.{ "path", "sha256", "bytes" });
        try canonicalAbsolute(try stringField(row, "path"));
        try inputRow(row, input);
    }
    try memberMap(budget, try field(rows, "members"), group.members);
}
fn relativeProjectionPath(path: []const u8) !void {
    if (path.len == 0 or path.len > 4096 or path[0] == '/') return error.InvalidRuntimeProvenance;
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.InvalidRuntimeProvenance;
        for (part) |byte| if (byte < 32 or byte >= 127 or byte == '\\') return error.InvalidRuntimeProvenance;
    }
}
fn commitField(value: std.json.Value, key: []const u8) !void {
    const text = try stringField(value, key);
    if (text.len != 40 or std.mem.allEqual(u8, text, '0')) return error.InvalidRuntimeProvenance;
    for (text) |byte| if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return error.InvalidRuntimeProvenance;
}
fn equalJson(budget: Budget, left: std.json.Value, right: std.json.Value) !void {
    if (!try jsonEqual(budget, left, right, 0)) return error.RuntimeSelectionDrift;
}
fn digestEquals(value: std.json.Value, key: []const u8, expected: [32]u8) !void {
    if (!std.meta.eql(try digestField(value, key), expected)) return error.RuntimeSelectionDrift;
}
fn producerRow(value: std.json.Value) !void {
    try exactObject(value, &.{ "receipt", "sha256", "source_commit", "graph_sha256" });
    try canonicalAbsolute(try stringField(value, "receipt"));
    _ = try digestField(value, "sha256");
    _ = try digestField(value, "graph_sha256");
    try commitField(value, "source_commit");
}
fn materialRow(value: std.json.Value) !void {
    try exactObject(value, &.{ "root", "receipt_sha256", "inventory_sha256", "producer" });
    try canonicalAbsolute(try stringField(value, "root"));
    _ = try digestField(value, "receipt_sha256");
    _ = try digestField(value, "inventory_sha256");
    try producerRow(try field(value, "producer"));
}
fn programRow(value: std.json.Value, input: Input) !void {
    try exactObject(value, &.{ "path", "sha256", "bytes" });
    try canonicalAbsolute(try stringField(value, "path"));
    try inputRow(value, input);
}
fn pathJoined(a: std.mem.Allocator, value: std.json.Value, key: []const u8, root: []const u8, leaf: []const u8) !void {
    const expected = try std.fmt.allocPrint(a, "{s}/{s}", .{ root, leaf });
    defer a.free(expected);
    try expectText(value, key, expected);
}
fn projectionMap(budget: Budget, value: std.json.Value) !void {
    if (value != .object or value.object.count() == 0 or value.object.count() > maximum_files) return error.RuntimeInputLimit;
    var entries = value.object.iterator();
    while (entries.next()) |entry| {
        try budget.check();
        try relativeProjectionPath(entry.key_ptr.*);
        const row = entry.value_ptr.*;
        try exactObject(row, &.{ "sha256", "bytes", "mode" });
        _ = try digestField(row, "sha256");
        if (try integer(row, "bytes") > maximum_metadata_bytes) return error.RuntimeInputLimit;
        const mode = try stringField(row, "mode");
        if (!std.mem.eql(u8, mode, "100644") and !std.mem.eql(u8, mode, "100755")) return error.InvalidRuntimeProvenance;
    }
}
fn carrierTuple(budget: Budget, tuple: std.json.Value, seal_files: std.json.Value, carrier: std.json.Value, receipt: Input) !void {
    const names = [_][]const u8{ "manifest.json", "origin-receipt.json", "payload.bin", "receipt.json" };
    if (tuple != .array or tuple.array.items.len != 4 or seal_files != .array or seal_files.array.items.len != 4) return error.InvalidRuntimeProvenance;
    for (tuple.array.items, seal_files.array.items, names, 0..) |row, sealed, name, index| {
        try budget.check();
        try exactObject(row, &.{ "name", "sha256", "bytes" });
        try exactObject(sealed, &.{ "name", "sha256", "size" });
        try expectText(row, "name", name);
        try expectText(sealed, "name", name);
        const bytes = try positiveInteger(row, "bytes");
        // Full transport size is inert provenance, never a staging exemption.
        if (bytes > 16 * 1024 * 1024 * 1024 or bytes != try integer(sealed, "size")) return error.InvalidRuntimeProvenance;
        try digestEquals(sealed, "sha256", try digestField(row, "sha256"));
        const selected = switch (index) {
            0 => carrier,
            1 => try objectField(carrier, "origin"),
            2 => carrier,
            else => row,
        };
        const hash_key = switch (index) {
            0 => "manifest_sha256",
            1 => "receipt_sha256",
            2 => "payload_sha256",
            else => "sha256",
        };
        const bytes_key = switch (index) {
            0 => "manifest_bytes",
            1 => "receipt_bytes",
            2 => "payload_bytes",
            else => "bytes",
        };
        try digestEquals(row, "sha256", if (index == 3) receipt.sha256 else try digestField(selected, hash_key));
        if (bytes != if (index == 3) receipt.bytes else try positiveInteger(selected, bytes_key)) return error.RuntimeSelectionDrift;
    }
}
fn producerContext(a: std.mem.Allocator, context: std.json.Value, producer: std.json.Value, outer: std.json.Value, profile: []const u8, cutoff: bool) !void {
    if (cutoff) {
        try exactObject(context, &.{ "mode", "epoch", "source_commit", "graph_sha256", "entry_monotonic_ns", "deadline_monotonic_ns", "work_cutoff_monotonic_ns" });
    } else {
        try exactObject(context, &.{ "mode", "epoch", "source_commit", "graph_sha256", "entry_monotonic_ns", "deadline_monotonic_ns" });
    }
    try expectText(context, "mode", profile);
    const pin_path = try stringField(producer, "receipt");
    if (!std.mem.endsWith(u8, pin_path, "/receipt.json")) return error.InvalidRuntimeProvenance;
    try expectText(context, "epoch", pin_path[0 .. pin_path.len - "/receipt.json".len]);
    try expectText(context, "source_commit", try stringField(producer, "source_commit"));
    try digestEquals(context, "graph_sha256", try digestField(producer, "graph_sha256"));
    const reservation = try objectField(outer, "native_acquisition_inputs_reservation");
    const entry = try integer(reservation, "original_entry_monotonic_ns");
    const deadline = try integer(reservation, "original_deadline_monotonic_ns");
    if (entry == 0 or try integer(context, "entry_monotonic_ns") != entry or try integer(context, "deadline_monotonic_ns") != deadline or
        (cutoff and try integer(context, "work_cutoff_monotonic_ns") != deadline - 30000000000)) return error.RuntimeSelectionDrift;
    _ = a;
}
fn producerOutputPath(a: std.mem.Allocator, outer: std.json.Value, target: []const u8, path: []const u8, leaf: []const u8) ![]const u8 {
    try canonicalAbsolute(path);
    const base = try stringField(outer, "output_base");
    try canonicalAbsolute(base);
    const prefix = try std.fmt.allocPrint(a, "{s}/execroot/_main/bazel-out/", .{base});
    defer a.free(prefix);
    const suffix = try std.fmt.allocPrint(a, "/testlogs/tools/{s}/test.outputs/{s}", .{ target["//tools:".len..], leaf });
    defer a.free(suffix);
    if (!std.mem.startsWith(u8, path, prefix) or !std.mem.endsWith(u8, path, suffix) or path.len <= prefix.len + suffix.len) return error.InvalidRuntimeProvenance;
    const configuration = path[prefix.len .. path.len - suffix.len];
    try collectorConfiguration(configuration);
    return configuration;
}
fn collectorConfiguration(value: []const u8) !void {
    if (value.len == 0 or value.len > 255 or std.mem.eql(u8, value, ".") or std.mem.eql(u8, value, "..")) return error.InvalidRuntimeProvenance;
    for (value) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '_' and byte != '-' and byte != '.' and byte != '+') return error.InvalidRuntimeProvenance;
}
fn collectorEvidenceName(a: std.mem.Allocator, target: []const u8, configuration: []const u8, source: []const u8) ![]u8 {
    try collectorConfiguration(configuration);
    if (target.len == 0 or target.len > 4096 or source.len == 0 or source.len > 128) return error.InvalidRuntimeProvenance;
    const selected = try std.fmt.allocPrint(a, "{s}\x00{s}\x00{s}", .{ target, configuration, source });
    defer a.free(selected);
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(selected, &hash, .{});
    return std.fmt.allocPrint(a, "{s}.evidence", .{std.fmt.bytesToHex(hash, .lower)});
}
const CopiedTestFiles = struct { log: Input, xml: Input };
/// The collector always records up to four base sources. Only copied log/XML
/// are proof members. Optional output-manifest rows remain inert diagnostics
/// inside the already authenticated raw index; they add no staged roles.
fn selectedCopiedTestFiles(a: std.mem.Allocator, budget: Budget, result: std.json.Value, rows: ?std.json.Value, group: ModernAuthority, target: []const u8, configuration: []const u8, epoch: ?[]const u8) !CopiedTestFiles {
    try expectText(result, "target", target);
    try expectText(result, "state", "observed");
    try expectText(result, "configuration", configuration);
    try collectorConfiguration(configuration);
    const files = try field(result, "files");
    if (files != .array or files.array.items.len < 2 or files.array.items.len > 4 or group.members.len != 2) return error.InvalidRuntimeProvenance;
    var seen: [4]bool = @splat(false);
    var copied_bytes: u64 = 0;
    var log: ?Input = null;
    var xml: ?Input = null;
    if ((rows == null) != (epoch == null)) return error.InvalidRuntimeProvenance;
    for (files.array.items) |entry| {
        try budget.check();
        const source_name = try stringField(entry, "source");
        const source_index: usize = if (std.mem.eql(u8, source_name, "test.log")) 0 else if (std.mem.eql(u8, source_name, "test.xml")) 1 else if (std.mem.eql(u8, source_name, "test.outputs_manifest/MANIFEST")) 2 else if (std.mem.eql(u8, source_name, "test.outputs_manifest/ANNOTATIONS")) 3 else return error.InvalidRuntimeProvenance;
        if (seen[source_index]) return error.InvalidRuntimeProvenance;
        seen[source_index] = true;
        const state = try stringField(entry, "state");
        if (source_index >= 2 and std.mem.eql(u8, state, "missing")) {
            try exactObject(entry, &.{ "source", "state", "bytes" });
            if (try integer(entry, "bytes") != 0) return error.InvalidRuntimeProvenance;
            continue;
        }
        try exactObject(entry, &.{ "source", "state", "bytes", "sha256", "file" });
        try expectText(entry, "state", "copied");
        const name = try stringField(entry, "file");
        const expected_name = try collectorEvidenceName(a, target, configuration, source_name);
        defer a.free(expected_name);
        if (!std.mem.eql(u8, name, expected_name)) return error.InvalidRuntimeProvenance;
        _ = try digestField(entry, "sha256");
        copied_bytes = std.math.add(u64, copied_bytes, try integer(entry, "bytes")) catch return error.RuntimeInputLimit;
        if (copied_bytes > 64 * 1024 * 1024) return error.RuntimeInputLimit;
        if (source_index >= 2) continue;
        var selected: ?Input = null;
        for (group.members) |member| if (std.mem.eql(u8, member.name, name)) {
            if (selected != null) return error.InvalidRuntimeProvenance;
            selected = member.input;
        };
        const input = selected orelse return error.InvalidRuntimeProvenance;
        try inputRow(entry, input);
        if (rows) |original| {
            const member_path = try std.fmt.allocPrint(a, "{s}/test-evidence/{s}", .{ epoch.?, name });
            defer a.free(member_path);
            try expectText(try field(try objectField(original, "members"), name), "path", member_path);
        }
        if (source_index == 0) log = input else xml = input;
    }
    return .{ .log = log orelse return error.InvalidRuntimeProvenance, .xml = xml orelse return error.InvalidRuntimeProvenance };
}
fn uniqueHashMarker(a: std.mem.Allocator, budget: Budget, raw: []const u8, prefix: []const u8, hash: [32]u8) !void {
    const expected = try std.fmt.allocPrint(a, "{s}{s}", .{ prefix, std.fmt.bytesToHex(hash, .lower) });
    defer a.free(expected);
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, raw, '\n');
    while (lines.next()) |line| {
        try budget.check();
        if (std.mem.indexOf(u8, line, prefix) != null) {
            if (!std.mem.eql(u8, line, expected)) return error.InvalidRuntimeProvenance;
            count += 1;
        }
    }
    if (count != 1) return error.InvalidRuntimeProvenance;
}
fn xmlSpace(byte: u8) bool {
    return byte == ' ' or byte == '\t' or byte == '\r' or byte == '\n';
}
fn xmlName(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or byte == '_' or byte == '-' or byte == '.';
}
/// Deliberately finite Bazel test XML grammar: no DTD/entity expansion/namespaces,
/// bounded nesting/attributes, matching tags and positive successful suites.
/// Unsupported XML refuses rather than falling back to substring admission.
fn successfulTestXml(budget: Budget, raw: []const u8) !void {
    var stack: [64][]const u8 = undefined;
    var depth: usize = 0;
    var roots: usize = 0;
    var suites: usize = 0;
    var index: usize = 0;
    while (index < raw.len) {
        try budget.check();
        if (raw[index] != '<') {
            if (depth == 0 and !xmlSpace(raw[index])) return error.InvalidRuntimeProvenance;
            index += 1;
            continue;
        }
        if (std.mem.startsWith(u8, raw[index..], "<!--")) {
            const end = std.mem.indexOf(u8, raw[index + 4 ..], "-->") orelse return error.InvalidRuntimeProvenance;
            if (std.mem.indexOf(u8, raw[index + 4 .. index + 4 + end], "--") != null) return error.InvalidRuntimeProvenance;
            index += 4 + end + 3;
            continue;
        }
        if (std.mem.startsWith(u8, raw[index..], "<![CDATA[")) {
            if (depth == 0) return error.InvalidRuntimeProvenance;
            const end = std.mem.indexOf(u8, raw[index + 9 ..], "]]>") orelse return error.InvalidRuntimeProvenance;
            index += 9 + end + 3;
            continue;
        }
        if (std.mem.startsWith(u8, raw[index..], "<?xml ")) {
            if (index != 0) return error.InvalidRuntimeProvenance;
            const end = std.mem.indexOf(u8, raw[index + 6 ..], "?>") orelse return error.InvalidRuntimeProvenance;
            index += 6 + end + 2;
            continue;
        }
        index += 1;
        if (index >= raw.len) return error.InvalidRuntimeProvenance;
        const closing = raw[index] == '/';
        if (closing) index += 1;
        const start = index;
        while (index < raw.len and xmlName(raw[index])) : (index += 1) {}
        if (index == start or std.ascii.isDigit(raw[start])) return error.InvalidRuntimeProvenance;
        const name = raw[start..index];
        if (closing) {
            while (index < raw.len and xmlSpace(raw[index])) : (index += 1) {}
            if (index >= raw.len or raw[index] != '>' or depth == 0 or !std.mem.eql(u8, stack[depth - 1], name)) return error.InvalidRuntimeProvenance;
            depth -= 1;
            index += 1;
            continue;
        }
        if (std.mem.eql(u8, name, "failure") or std.mem.eql(u8, name, "error") or std.mem.eql(u8, name, "skipped")) return error.InvalidRuntimeProvenance;
        if (depth == 0) {
            roots += 1;
            if (roots != 1 or (!std.mem.eql(u8, name, "testsuite") and !std.mem.eql(u8, name, "testsuites"))) return error.InvalidRuntimeProvenance;
        }
        var attributes: [64][]const u8 = undefined;
        var count: usize = 0;
        var tests: ?u64 = null;
        var self_closing = false;
        while (true) {
            const spaced = index < raw.len and xmlSpace(raw[index]);
            while (index < raw.len and xmlSpace(raw[index])) : (index += 1) {}
            if (index >= raw.len) return error.InvalidRuntimeProvenance;
            if (raw[index] == '>') {
                index += 1;
                break;
            }
            if (raw[index] == '/' and index + 1 < raw.len and raw[index + 1] == '>') {
                self_closing = true;
                index += 2;
                break;
            }
            if (!spaced or count == attributes.len) return error.InvalidRuntimeProvenance;
            const key_start = index;
            while (index < raw.len and xmlName(raw[index])) : (index += 1) {}
            if (index == key_start) return error.InvalidRuntimeProvenance;
            const key = raw[key_start..index];
            for (attributes[0..count]) |old| if (std.mem.eql(u8, key, old)) return error.InvalidRuntimeProvenance;
            attributes[count] = key;
            count += 1;
            while (index < raw.len and xmlSpace(raw[index])) : (index += 1) {}
            if (index >= raw.len or raw[index] != '=') return error.InvalidRuntimeProvenance;
            index += 1;
            while (index < raw.len and xmlSpace(raw[index])) : (index += 1) {}
            if (index >= raw.len or (raw[index] != '"' and raw[index] != '\'')) return error.InvalidRuntimeProvenance;
            const quote = raw[index];
            index += 1;
            const value_start = index;
            while (index < raw.len and raw[index] != quote) : (index += 1) {
                if (raw[index] == '<') return error.InvalidRuntimeProvenance;
            }
            if (index >= raw.len) return error.InvalidRuntimeProvenance;
            const value = raw[value_start..index];
            index += 1;
            if (std.mem.eql(u8, name, "testsuite")) {
                if (std.mem.eql(u8, key, "tests")) tests = try decimal(value, 12);
            }
            if (std.mem.eql(u8, name, "testsuite") or std.mem.eql(u8, name, "testsuites")) {
                if (std.mem.eql(u8, key, "failures") or std.mem.eql(u8, key, "errors") or std.mem.eql(u8, key, "skipped")) {
                    if (try decimal(value, 12) != 0) return error.InvalidRuntimeProvenance;
                }
            }
        }
        if (std.mem.eql(u8, name, "testsuite")) {
            if ((tests orelse return error.InvalidRuntimeProvenance) == 0) return error.InvalidRuntimeProvenance;
            suites += 1;
        }
        if (!self_closing) {
            if (depth == stack.len) return error.RuntimeInputLimit;
            stack[depth] = name;
            depth += 1;
        }
    }
    if (depth != 0 or roots != 1 or suites == 0) return error.InvalidRuntimeProvenance;
}
/// Authenticate copied evidence from the independently selected action, never
/// from a program's own booleans. All reads use held declaration descriptors.
fn carrierProducerProof(a: std.mem.Allocator, budget: Budget, group: ModernAuthority, rows: std.json.Value, producer: std.json.Value, program: std.json.Value, target: []const u8, profile: []const u8, leaf: []const u8, marker: ?[]const u8, program_input: Input) !std.json.Parsed(std.json.Value) {
    try authorityMap(budget, rows, group);
    try programRow(program, program_input);
    try producerRow(producer);
    const selected_outer = try objectField(rows, "outer");
    try expectText(selected_outer, "path", try stringField(producer, "receipt"));
    try digestEquals(producer, "sha256", group.outer.sha256);
    const path = try stringField(producer, "receipt");
    if (!std.mem.endsWith(u8, path, "/receipt.json")) return error.InvalidRuntimeProvenance;
    const epoch = path[0 .. path.len - "/receipt.json".len];
    const id = epoch[(std.mem.lastIndexOfScalar(u8, epoch, '/') orelse return error.InvalidRuntimeProvenance) + 1 ..];
    if (id.len != 36) return error.InvalidRuntimeProvenance;
    for (id, 0..) |byte, index| {
        if (index == 8 or index == 13 or index == 18 or index == 23) {
            if (byte != '-') return error.InvalidRuntimeProvenance;
        } else if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return error.InvalidRuntimeProvenance;
    }
    const outer = try loadSelectedJson(a, budget, group.outer, maximum_metadata_bytes);
    errdefer outer.deinit();
    try reservedProducerPolicy(a, outer.value, profile, "native_acquisition_inputs_reservation");
    if (try integer(try objectField(outer.value, "native_acquisition_inputs_reservation"), "original_entry_monotonic_ns") == 0) return error.InvalidRuntimeProvenance;
    try expectText(outer.value, "id", id);
    const unit = try std.fmt.allocPrint(a, "omux-execution-{s}.service", .{id});
    defer a.free(unit);
    try expectText(outer.value, "unit", unit);
    try expectText(outer.value, "source_commit", try stringField(producer, "source_commit"));
    try digestEquals(outer.value, "graph_sha256", try digestField(producer, "graph_sha256"));
    try expectText(outer.value, "manager", "system");
    try expectText(outer.value, "verb", "test");
    if (try integer(outer.value, "exit") != 0 or try integer(outer.value, "workload_exit") != 0 or try field(outer.value, "controller_failure") != .null) return error.InvalidRuntimeProvenance;
    try expectBool(outer.value, "descendants_empty", true);
    try expectText(try objectField(outer.value, "cleanup"), "state", "empty");
    try expectText(outer.value, "source_dirty", "false");
    try expectBool(outer.value, "cache_reuse_requested", false);
    if (try field(outer.value, "cache_policy") != .null or try field(outer.value, "cache_key") != .null) return error.InvalidRuntimeProvenance;
    const targets = try field(outer.value, "targets");
    if (targets != .array or targets.array.items.len != 1 or targets.array.items[0] != .string or !std.mem.eql(u8, targets.array.items[0].string, target)) return error.InvalidRuntimeProvenance;
    const configuration = try producerOutputPath(a, outer.value, target, try stringField(program, "path"), leaf);
    const evidence_row = try objectField(rows, "evidence");
    try pathJoined(a, evidence_row, "path", epoch, "test-evidence.json");
    const retained_evidence = try objectField(outer.value, "test_evidence");
    try expectText(retained_evidence, "state", "preserved");
    try digestEquals(retained_evidence, "sha256", group.evidence.sha256);
    const evidence = try loadSelectedJson(a, budget, group.evidence, maximum_metadata_bytes);
    defer evidence.deinit();
    if (try integer(evidence.value, "schema") != 1 or try integer(evidence.value, "bazel_exit") != 0 or try integer(evidence.value, "epoch_start_ns") != try integer(outer.value, "epoch_start_ns")) return error.InvalidRuntimeProvenance;
    try equalJson(budget, targets, try field(evidence.value, "targets"));
    const results = try field(evidence.value, "results");
    if (results != .array or results.array.items.len != 1 or group.members.len != 2) return error.InvalidRuntimeProvenance;
    const result = results.array.items[0];
    try expectText(result, "target", target);
    try expectText(result, "state", "observed");
    const copied = try selectedCopiedTestFiles(a, budget, result, rows, group, target, configuration, epoch);
    const raw_xml = try readSelectedInput(budget.io, a, budget.deadline, copied.xml, maximum_metadata_bytes);
    defer a.free(raw_xml);
    try successfulTestXml(budget, raw_xml);
    const raw_log = try readSelectedInput(budget.io, a, budget.deadline, copied.log, maximum_metadata_bytes);
    defer a.free(raw_log);
    if (marker) |prefix| {
        try uniqueHashMarker(a, budget, raw_log, prefix, program_input.sha256);
    } else {
        // Seal's existing complete canonical JSON line binds the actual held
        // program bytes; neither a text substring nor an echoed pin suffices.
        const raw_program = try readSelectedInput(budget.io, a, budget.deadline, program_input, maximum_metadata_bytes);
        defer a.free(raw_program);
        if (std.mem.indexOfScalar(u8, raw_program, '\n') != null) return error.InvalidRuntimeProvenance;
        var lines = std.mem.splitScalar(u8, raw_log, '\n');
        var count: usize = 0;
        while (lines.next()) |line| {
            try budget.check();
            if (std.mem.indexOf(u8, line, "omux-native-sdk-carrier-producer-v1") != null) {
                if (!std.mem.eql(u8, line, raw_program)) return error.InvalidRuntimeProvenance;
                count += 1;
            }
        }
        if (count != 1) return error.InvalidRuntimeProvenance;
    }
    return outer;
}

fn carrierReports(budget: Budget, core: std.json.Value, sdk: std.json.Value, seal: std.json.Value, metadata_report: std.json.Value, carrier: std.json.Value, source: std.json.Value, material: std.json.Value, compact: std.json.Value, receipts: std.json.Value, inputs: CarrierInputs, roles: std.json.Value, modern: ModernInputs) !void {
    try exactObject(core, &.{ "schema_version", "kind", "source", "original_selection", "carrier_files", "seal", "metadata", "hub_inventory_sha256", "graph_inventory_sha256" });
    if (try integer(core, "schema_version") != 2) return error.InvalidRuntimeProvenance;
    try expectText(core, "kind", "omux-native-carrier-sdk-authority-core-v2");
    try exactObject(sdk, &.{ "schema_version", "kind", "status", "source", "original_selection", "authority_sha256", "inventory_sha256", "carrier_files", "seal", "metadata", "hub_files", "graph_files", "hub_inventory_sha256", "graph_inventory_sha256", "mapping_sha256", "patch_sha256", "sdk_export_qualified", "source_and_carrier_rechecked", "compiler_qualified", "native_compile_passed", "runtime_qualified", "installed_package_primary_qualified", "schema_producer_qualified", "native_support", "provider_evaluation", "credential_acquisition_qualified", "live_handoff_proven", "source_witnesses_replaced" });
    if (try integer(sdk, "schema_version") != 2) return error.InvalidRuntimeProvenance;
    try expectText(sdk, "kind", "omux-native-carrier-sdk-projection-v2");
    try expectText(sdk, "status", "verified-carrier-sdk-projection-with-fresh-custody");
    inline for (.{ "sdk_export_qualified", "source_and_carrier_rechecked" }) |key| try expectBool(sdk, key, true);
    inline for (.{ "compiler_qualified", "native_compile_passed", "runtime_qualified", "installed_package_primary_qualified", "schema_producer_qualified", "native_support", "provider_evaluation", "credential_acquisition_qualified", "live_handoff_proven", "source_witnesses_replaced" }) |key| try expectBool(sdk, key, false);
    inline for (.{ "source", "original_selection", "carrier_files", "seal", "metadata", "hub_inventory_sha256", "graph_inventory_sha256" }) |key| try sameValue(budget, core, sdk, key);
    inline for (.{ "authority_sha256", "inventory_sha256" }) |key| try digestEquals(sdk, key, inputs.receipts[@backingInt(CarrierReceiptRole.authority_document)].sha256);
    try digestEquals(compact, "authority_sha256", inputs.receipts[@backingInt(CarrierReceiptRole.authority_document)].sha256);
    const projection = try objectField(compact, "projection");
    try exactObject(projection, &.{ "receipt_sha256", "inventory_sha256", "hub_inventory_sha256", "graph_inventory_sha256" });
    try digestEquals(projection, "receipt_sha256", modern.roles[@backingInt(ModernRole.sdk)].sha256);
    try digestEquals(projection, "inventory_sha256", inputs.receipts[@backingInt(CarrierReceiptRole.authority_document)].sha256);
    inline for (.{ "hub_inventory_sha256", "graph_inventory_sha256" }) |key| {
        _ = try digestField(core, key);
        try sameValue(budget, core, projection, key);
    }
    try sameValue(budget, core, compact, "carrier_files");
    try exactObject(material, &.{ "schema_version", "kind", "source", "sdk", "controller_source_commit", "controller_graph_sha256" });
    if (try integer(material, "schema_version") != 2) return error.InvalidRuntimeProvenance;
    try expectText(material, "kind", "omux-native-carrier-native-selection-v2");
    const source_row = try objectField(material, "source");
    const sdk_row = try objectField(material, "sdk");
    try materialRow(source_row);
    try materialRow(sdk_row);
    try sameValue(budget, core, material, "source");
    try digestEquals(source_row, "receipt_sha256", modern.roles[@backingInt(ModernRole.source)].sha256);
    try digestEquals(source_row, "inventory_sha256", try digestField(source, "inventory_sha256"));
    try digestEquals(sdk_row, "receipt_sha256", modern.roles[@backingInt(ModernRole.sdk)].sha256);
    try digestEquals(sdk_row, "inventory_sha256", inputs.receipts[@backingInt(CarrierReceiptRole.authority_document)].sha256);
    const sdk_producer = try objectField(sdk_row, "producer");
    try expectText(material, "controller_source_commit", try stringField(sdk_producer, "source_commit"));
    try digestEquals(material, "controller_graph_sha256", try digestField(sdk_producer, "graph_sha256"));
    const original = try objectField(core, "original_selection");
    try exactObject(original, &.{ "kind", "source_root", "source_receipt_sha256", "source_inventory_sha256", "export_root", "export_receipt_sha256", "binding_receipt_sha256" });
    try expectText(original, "kind", "omux-native-source-acquisition-metadata-input-v1");
    try expectText(original, "source_root", try stringField(source_row, "root"));
    try digestEquals(original, "source_receipt_sha256", try digestField(source_row, "receipt_sha256"));
    try digestEquals(original, "source_inventory_sha256", try digestField(source_row, "inventory_sha256"));
    // Fixed original N9 export authority is inert. It is never opened or used
    // as a consumer extraction path, nor inferred from a fresh inode.
    try expectText(original, "export_root", "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/e5b17d7e-d19d-4cb2-be22-41a86b98af7b/sdk-private/sdk-export");
    try expectText(original, "export_receipt_sha256", "1aa4c87d689f464e576a5c6a51b4c6350a8f0346f6b94299856d01db5147d4f0");
    _ = try digestField(original, "binding_receipt_sha256");
    const patches = try field(source, "patch_sha256");
    if (patches != .array or patches.array.items.len != 9) return error.InvalidRuntimeProvenance;
    for (patches.array.items) |patch| {
        if (patch != .string or patch.string.len != 64) return error.InvalidRuntimeProvenance;
        for (patch.string) |byte| if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return error.InvalidRuntimeProvenance;
    }
    try sameValue(budget, sdk, source, "patch_sha256");
    try projectionMap(budget, try field(sdk, "hub_files"));
    try projectionMap(budget, try field(sdk, "graph_files"));
    const graph = try objectField(sdk, "graph_files");
    const source_graph = try objectField(source, "graph_files");
    if (graph.object.count() != source_graph.object.count()) return error.RuntimeSelectionDrift;
    var graph_rows = graph.object.iterator();
    while (graph_rows.next()) |row| {
        try budget.check();
        const selected = try objectField(source_graph, row.key_ptr.*);
        try exactObject(selected, &.{"sha256"});
        try digestEquals(row.value_ptr.*, "sha256", try digestField(selected, "sha256"));
        const source_member = try objectField(try objectField(source, "source_inventory"), row.key_ptr.*);
        try expectText(row.value_ptr.*, "mode", try stringField(source_member, "mode"));
    }
    try digestEquals(sdk, "mapping_sha256", try digestField(try objectField(graph, "MODULE.bazel.lock"), "sha256"));
    // Map digests are executed SDK/PACKAGE output authority. Native never
    // reserializes Python JSON, and independently joins each selected graph
    // hash/mode to SOURCE and HUB path/hash to regenerated metadata below.
    try exactObject(seal, &.{ "kind", "producer", "carrier_receipt_sha256", "origin_receipt_sha256", "producer_context", "files", "all_four_leaves_rechecked", "sdk_execution_qualified", "metadata_qualified", "compiler_qualified", "runtime_qualified" });
    try expectText(seal, "kind", "omux-native-sdk-carrier-producer-v1");
    try expectText(seal, "producer", "//tools:codex_native_sdk_carrier_seal_producer");
    try digestEquals(seal, "carrier_receipt_sha256", inputs.receipts[@backingInt(CarrierReceiptRole.carrier_receipt)].sha256);
    try digestEquals(seal, "origin_receipt_sha256", try digestField(original, "export_receipt_sha256"));
    try expectBool(seal, "all_four_leaves_rechecked", true);
    inline for (.{ "sdk_execution_qualified", "metadata_qualified", "compiler_qualified", "runtime_qualified" }) |key| try expectBool(seal, key, false);
    try exactObject(carrier, &.{ "kind", "producer_context", "origin", "origin_custody", "manifest_sha256", "manifest_bytes", "payload_sha256", "payload_bytes", "entry_count", "origin_fully_rechecked", "sdk_execution_qualified", "metadata_qualified", "source_witnesses_replaced" });
    try expectText(carrier, "kind", "omux-native-sdk-carrier-v1");
    try expectBool(carrier, "origin_fully_rechecked", true);
    inline for (.{ "sdk_execution_qualified", "metadata_qualified", "source_witnesses_replaced" }) |key| try expectBool(carrier, key, false);
    if (try positiveInteger(carrier, "entry_count") > 500000) return error.RuntimeInputLimit;
    const origin = try objectField(carrier, "origin");
    try exactObject(origin, &.{ "root", "receipt_sha256", "receipt_bytes", "baseline_receipt_sha256", "baseline_inventory_sha256", "inventory_sha256", "mapping_sha256", "selection_sha256", "producer" });
    try expectText(origin, "root", try stringField(original, "export_root"));
    try digestEquals(origin, "receipt_sha256", try digestField(original, "export_receipt_sha256"));
    inline for (.{ "baseline_receipt_sha256", "baseline_inventory_sha256", "inventory_sha256", "mapping_sha256", "selection_sha256" }) |key| _ = try digestField(origin, key);
    try expectText(origin, "producer", "//tools:codex_retained_sdk_export_run");
    const custody = try objectField(carrier, "origin_custody");
    try exactObject(custody, &.{ "sdk", "jdk" });
    inline for (.{ "sdk", "jdk" }) |key| {
        const row = try objectField(custody, key);
        try exactObject(row, &.{ "root", "root_identity", "ancestry_sha256", "members_sha256" });
        try canonicalAbsolute(try stringField(row, "root"));
        _ = try digestField(row, "ancestry_sha256");
        _ = try digestField(row, "members_sha256");
        const identity = try field(row, "root_identity");
        if (identity != .array or identity.array.items.len != 5) return error.InvalidRuntimeProvenance;
        for (identity.array.items) |item| if (item != .integer or item.integer < 0) return error.InvalidRuntimeProvenance;
    }
    try expectText(try field(custody, "sdk"), "root", try stringField(origin, "root"));
    try sameValue(budget, carrier, seal, "producer_context");
    try carrierTuple(budget, try field(core, "carrier_files"), try field(seal, "files"), carrier, inputs.receipts[@backingInt(CarrierReceiptRole.carrier_receipt)]);
    try exactObject(metadata_report, &.{ "schema_version", "kind", "status", "original_selection", "selector_sha256", "source_inventory_sha256", "source_graph", "patch_sha256", "carrier", "extraction", "extraction_receipt_sha256", "consumer_context", "consumer_deadline", "query_exit", "query_plan", "output_parent_mode", "query_tool_closure_independently_rechecked", "packaged_jdk_used_as_query_tool_relocation", "module_and_cargo_lock_unchanged", "retained_hub", "generated_hub", "source_and_extracted_carrier_rechecked", "sdk_export_qualified", "sdk_execution_qualified", "metadata_qualified", "compiler_qualified", "native_compile_passed", "runtime_qualified", "installed_package_primary_qualified", "schema_producer_qualified", "native_support", "provider_evaluation", "credential_acquisition_qualified", "live_handoff_proven", "source_witnesses_replaced", "legacy_metadata_family_qualified" });
    if (try integer(metadata_report, "schema_version") != 2 or try integer(metadata_report, "query_exit") != 0) return error.InvalidRuntimeProvenance;
    try expectText(metadata_report, "kind", "omux-native-sdk-carrier-metadata-v2");
    try expectText(metadata_report, "status", "verified-fresh-carrier-custody-regenerated-native-acquisition-hub");
    try expectText(metadata_report, "output_parent_mode", "0700");
    inline for (.{ "query_tool_closure_independently_rechecked", "module_and_cargo_lock_unchanged", "source_and_extracted_carrier_rechecked" }) |key| try expectBool(metadata_report, key, true);
    inline for (.{ "packaged_jdk_used_as_query_tool_relocation", "sdk_export_qualified", "sdk_execution_qualified", "metadata_qualified", "compiler_qualified", "native_compile_passed", "runtime_qualified", "installed_package_primary_qualified", "schema_producer_qualified", "native_support", "provider_evaluation", "credential_acquisition_qualified", "live_handoff_proven", "source_witnesses_replaced", "legacy_metadata_family_qualified" }) |key| try expectBool(metadata_report, key, false);
    try sameValue(budget, metadata_report, core, "original_selection");
    try digestEquals(metadata_report, "source_inventory_sha256", try digestField(source, "inventory_sha256"));
    try equalJson(budget, try field(metadata_report, "source_graph"), source_graph);
    try sameValue(budget, metadata_report, source, "patch_sha256");
    const metadata_carrier = try objectField(metadata_report, "carrier");
    try digestEquals(metadata_carrier, "receipt_sha256", inputs.receipts[@backingInt(CarrierReceiptRole.carrier_receipt)].sha256);
    inline for (.{ "origin", "origin_custody", "producer_context" }) |key| try sameValue(budget, metadata_carrier, carrier, key);
    const qualified = try objectField(metadata_carrier, "qualification");
    try digestEquals(qualified, "outer_receipt_sha256", inputs.authority_receipts[@backingInt(CarrierAuthorityRole.seal)].outer.sha256);
    try digestEquals(qualified, "report_sha256", inputs.receipts[@backingInt(CarrierReceiptRole.seal_program)].sha256);
    try equalJson(budget, try field(qualified, "report"), seal);
    const generated = try field(metadata_report, "generated_hub");
    const hub = try objectField(sdk, "hub_files");
    if (generated != .array or generated.array.items.len != hub.object.count()) return error.RuntimeSelectionDrift;
    var previous: ?[]const u8 = null;
    for (generated.array.items) |row| {
        try budget.check();
        try exactObject(row, &.{ "path", "sha256" });
        const path = try stringField(row, "path");
        if (previous) |old| if (std.mem.order(u8, old, path) != .lt) return error.InvalidRuntimeProvenance;
        previous = path;
        try digestEquals(try objectField(hub, path), "sha256", try digestField(row, "sha256"));
    }
    inline for (.{ "seal", "metadata" }, 0..) |key, index| {
        const row = try objectField(core, key);
        try exactObject(row, &.{ "producer", "program" });
        try producerRow(try field(row, "producer"));
        const role: CarrierReceiptRole = if (index == 0) .seal_program else .metadata_program;
        try programRow(try field(row, "program"), inputs.receipts[@backingInt(role)]);
        try equalJson(budget, try field(row, "program"), try field(receipts, @tagName(role)));
    }
    // Same retained metadata alias, never two divergent copies of one role.
    try equalJson(budget, try field(receipts, "metadata_program"), try field(roles, "sdk_metadata"));
}
fn carrierMaterial(a: std.mem.Allocator, budget: Budget, modern: ModernInputs, selection: std.json.Value, source: std.json.Value) !void {
    const selected = modern.carrier_materials orelse return error.InvalidRuntimeProvenance;
    const compact = try objectField(selection, "carrier_materials");
    try exactObject(compact, &.{ "schema_version", "kind", "authority_sha256", "carrier_files", "projection", "receipts", "authorities" });
    if (try integer(compact, "schema_version") != 2) return error.InvalidRuntimeProvenance;
    try expectText(compact, "kind", "omux-native-carrier-retained-authority-v2");
    const receipts = try objectField(compact, "receipts");
    try exactObject(receipts, &.{ "authority_document", "carrier_receipt", "seal_program", "metadata_program" });
    inline for (@typeInfo(CarrierReceiptRole).@"enum".field_names, 0..) |name, index| try programRow(try field(receipts, name), selected.receipts[index]);
    const authorities = try objectField(compact, "authorities");
    try exactObject(authorities, &.{ "seal", "metadata" });
    const core = try loadSelectedJson(a, budget, selected.receipts[@backingInt(CarrierReceiptRole.authority_document)], maximum_metadata_bytes);
    defer core.deinit();
    const sdk_input = modern.roles[@backingInt(ModernRole.sdk)];
    const sdk = try loadSelectedJson(a, budget, sdk_input, maximum_metadata_bytes);
    defer sdk.deinit();
    const seal_input = selected.receipts[@backingInt(CarrierReceiptRole.seal_program)];
    const seal = try loadSelectedJson(a, budget, seal_input, maximum_metadata_bytes);
    defer seal.deinit();
    const metadata_report = try loadSelectedJson(a, budget, selected.receipts[@backingInt(CarrierReceiptRole.metadata_program)], maximum_metadata_bytes);
    defer metadata_report.deinit();
    const carrier = try loadSelectedJson(a, budget, selected.receipts[@backingInt(CarrierReceiptRole.carrier_receipt)], maximum_metadata_bytes);
    defer carrier.deinit();
    const material = try objectField(selection, "material");
    const roles = try objectField(selection, "files");
    try carrierReports(budget, core.value, sdk.value, seal.value, metadata_report.value, carrier.value, source, material, compact, receipts, selected, roles, modern);
    const seal_row = try objectField(core.value, "seal");
    const metadata_row = try objectField(core.value, "metadata");
    const seal_outer = try carrierProducerProof(a, budget, selected.authority_receipts[@backingInt(CarrierAuthorityRole.seal)], try field(authorities, "seal"), try field(seal_row, "producer"), try field(seal_row, "program"), "//tools:codex_native_sdk_carrier_seal_producer", "native-sdk-carrier-seal-reserved", "sdk-private/native-sdk-carrier-producer.json", null, seal_input);
    defer seal_outer.deinit();
    try producerContext(a, try field(seal.value, "producer_context"), try field(seal_row, "producer"), seal_outer.value, "native-sdk-carrier-seal-reserved", true);
    const metadata_outer = try carrierProducerProof(a, budget, selected.authority_receipts[@backingInt(CarrierAuthorityRole.metadata)], try field(authorities, "metadata"), try field(metadata_row, "producer"), try field(metadata_row, "program"), "//tools:codex_native_carrier_metadata_producer", "native-sdk-carrier-metadata-reserved", "native-sdk-carrier-metadata/metadata-receipt.json", "omux-native-carrier-metadata-output-sha256=", selected.receipts[@backingInt(CarrierReceiptRole.metadata_program)]);
    defer metadata_outer.deinit();
    try producerContext(a, try field(metadata_report.value, "consumer_context"), try field(metadata_row, "producer"), metadata_outer.value, "native-sdk-carrier-metadata-reserved", false);
    const metadata_context = try field(metadata_report.value, "consumer_context");
    const metadata_until = try field(metadata_report.value, "consumer_deadline");
    const original_query_cutoff = @as(f64, @floatFromInt(try integer(metadata_context, "entry_monotonic_ns"))) / 1000000000.0 + 600.0;
    if (metadata_until != .float or !std.math.isFinite(metadata_until.float) or metadata_until.float != original_query_cutoff) return error.RuntimeSelectionDrift;
    const sdk_row = try objectField(material, "sdk");
    const sdk_outer = try carrierProducerProof(a, budget, modern.authority_receipts[@backingInt(ModernAuthorityRole.sdk)], try field(try field(selection, "authority_receipts"), "sdk"), try field(sdk_row, "producer"), try field(roles, "sdk"), "//tools:codex_native_carrier_sdk_export_producer", "native-sdk-carrier-sdk-export-reserved", "native-carrier-sdk-export/sdk-receipt.json", "omux-native-carrier-sdk-output-sha256=", sdk_input);
    defer sdk_outer.deinit();
    try pathJoined(a, try field(roles, "source"), "path", try stringField(try field(material, "source"), "root"), "source-receipt.json");
    try pathJoined(a, try field(roles, "sdk"), "path", try stringField(sdk_row, "root"), "sdk-receipt.json");
    try pathJoined(a, try field(receipts, "authority_document"), "path", try stringField(sdk_row, "root"), "authority.json");
    const source_producer = try field(try field(material, "source"), "producer");
    const source_group = try field(try field(selection, "authority_receipts"), "source");
    try expectText(try field(source_group, "outer"), "path", try stringField(source_producer, "receipt"));
    try digestEquals(source_producer, "sha256", modern.authority_receipts[@backingInt(ModernAuthorityRole.source)].outer.sha256);
    const compiler_selection = try loadSelectedJson(a, budget, modern.roles[@backingInt(ModernRole.compiler_selection)], maximum_metadata_bytes);
    defer compiler_selection.deinit();
    try sameValue(budget, compiler_selection.value, selection, "material");
    const compilation = try objectField(selection, "compilation");
    try exactObject(compilation, &.{ "selection", "result" });
    inline for (.{ "compiler_selection", "compiler" }, .{ "selection", "result" }) |role, name| {
        const row = try field(compilation, name);
        const actual = try field(roles, role);
        try expectText(actual, "path", try stringField(row, "path"));
        try digestEquals(actual, "sha256", try digestField(row, "sha256"));
    }
    // Plan/query/compiler summaries independently carry the actual selected
    // material pin; genuine PACKAGE authenticates its raw canonical selection.
    var material_pin: ?[32]u8 = null;
    inline for (.{ ModernRole.plan, ModernRole.query, ModernRole.compiler }) |role| {
        const report = try loadSelectedJson(a, budget, modern.roles[@backingInt(role)], maximum_metadata_bytes);
        defer report.deinit();
        const summary = try objectField(report.value, "material");
        try exactObject(summary, &.{ "source_inventory_sha256", "sdk_inventory_sha256", "mapping_sha256", "patch_sha256", "material_selection_sha256" });
        try digestEquals(summary, "source_inventory_sha256", try digestField(source, "inventory_sha256"));
        try digestEquals(summary, "sdk_inventory_sha256", selected.receipts[@backingInt(CarrierReceiptRole.authority_document)].sha256);
        try sameValue(budget, summary, sdk.value, "mapping_sha256");
        try sameValue(budget, summary, source, "patch_sha256");
        const pin = try digestField(summary, "material_selection_sha256");
        if (material_pin) |expected| {
            if (!std.meta.eql(expected, pin)) return error.RuntimeSelectionDrift;
        } else material_pin = pin;
    }
    try carrierCompilerJoins(a, budget, modern, selection, compiler_selection.value);
}
fn selectedRoleJoin(rows: std.json.Value, role: []const u8, binding: std.json.Value) !void {
    const selected = try field(rows, role);
    try expectText(selected, "path", try stringField(binding, "path"));
    try digestEquals(selected, "sha256", try digestField(binding, "sha256"));
}
fn selectedArtifactJoin(budget: Budget, artifacts: *const std.StringHashMapUnmanaged(std.json.Value), selected: std.json.Value, expected_role: []const u8) !void {
    try budget.check();
    const artifact = artifacts.get(try stringField(selected, "path")) orelse return error.RuntimeSelectionDrift;
    try expectText(artifact, "role", expected_role);
    try digestEquals(selected, "sha256", try digestField(artifact, "sha256"));
    if (try positiveInteger(selected, "bytes") != try positiveInteger(artifact, "bytes")) return error.RuntimeSelectionDrift;
}
fn carrierCompilerJoins(a: std.mem.Allocator, budget: Budget, modern: ModernInputs, package: std.json.Value, document: std.json.Value) !void {
    const rows = try objectField(package, "files");
    try selectedRoleJoin(rows, "compiler_ledger", try field(document, "ledger"));
    inline for (.{ "plan", "query" }, 0..) |name, index| {
        const row = try field(document, name);
        try selectedRoleJoin(rows, name, row);
        const producer_pin = try field(row, "producer");
        try producerRow(producer_pin);
        const group = modern.authority_receipts[index + @backingInt(ModernAuthorityRole.plan)];
        const authority = try field(try field(package, "authority_receipts"), name);
        try expectText(try field(authority, "outer"), "path", try stringField(producer_pin, "receipt"));
        try digestEquals(producer_pin, "sha256", group.outer.sha256);
        const outer = try loadSelectedJson(a, budget, group.outer, maximum_metadata_bytes);
        defer outer.deinit();
        try expectText(outer.value, "source_commit", try stringField(producer_pin, "source_commit"));
        try digestEquals(outer.value, "graph_sha256", try digestField(producer_pin, "graph_sha256"));
    }
    const result = try field(try field(package, "compilation"), "result");
    const compiler_pin = try field(result, "producer");
    try producerRow(compiler_pin);
    try expectText(try field(rows, "compiler_outer"), "path", try stringField(compiler_pin, "receipt"));
    try digestEquals(compiler_pin, "sha256", modern.roles[@backingInt(ModernRole.compiler_outer)].sha256);
    try digestEquals(compiler_pin, "sha256", modern.authority_receipts[@backingInt(ModernAuthorityRole.compiler)].outer.sha256);
    const compiler_outer = try loadSelectedJson(a, budget, modern.roles[@backingInt(ModernRole.compiler_outer)], maximum_metadata_bytes);
    defer compiler_outer.deinit();
    try expectText(compiler_outer.value, "source_commit", try stringField(compiler_pin, "source_commit"));
    try digestEquals(compiler_outer.value, "graph_sha256", try digestField(compiler_pin, "graph_sha256"));
    const ledger = try loadSelectedJson(a, budget, modern.roles[@backingInt(ModernRole.compiler_ledger)], maximum_metadata_bytes);
    defer ledger.deinit();
    const snapshot = try objectField(ledger.value, "goal_snapshot");
    const snapshot_relative = try stringField(snapshot, "path");
    const expected_snapshot = try std.fmt.allocPrint(a, "docs/agent-notes/2026-10-10-native-acquisition-input-lift.UNAPPLIED/ledger-snapshots/{s}.json", .{std.fmt.bytesToHex(try digestField(snapshot, "sha256"), .lower)});
    defer a.free(expected_snapshot);
    if (!std.mem.eql(u8, snapshot_relative, expected_snapshot)) return error.InvalidRuntimeProvenance;
    try pathJoined(a, try field(rows, "compiler_ledger_snapshot"), "path", "/srv/fast-local/jess/git/oauth-mux", snapshot_relative);
    try digestEquals(try field(rows, "compiler_ledger_snapshot"), "sha256", try digestField(snapshot, "sha256"));
    const compiler = try loadSelectedJson(a, budget, modern.roles[@backingInt(ModernRole.compiler)], maximum_metadata_bytes);
    defer compiler.deinit();
    try digestEquals(compiler.value, "ledger_sha256", modern.roles[@backingInt(ModernRole.compiler_ledger)].sha256);
    try sameValue(budget, compiler.value, document, "controller_inventory_sha256");
    const artifact_rows = try field(compiler.value, "artifacts");
    if (artifact_rows != .array or artifact_rows.array.items.len != 2 + modern.protocol_schema_files.len + modern.native_acquisition_artifact_files.len or artifact_rows.array.items.len > maximum_files) return error.InvalidRuntimeProvenance;
    var artifacts: std.StringHashMapUnmanaged(std.json.Value) = .empty;
    defer artifacts.deinit(a);
    for (artifact_rows.array.items) |row| {
        try budget.check();
        try exactObject(row, &.{ "path", "sha256", "bytes", "role" });
        const path = try stringField(row, "path");
        try canonicalAbsolute(path);
        _ = try digestField(row, "sha256");
        _ = try positiveInteger(row, "bytes");
        const slot = try artifacts.getOrPut(a, path);
        if (slot.found_existing) return error.InvalidRuntimeProvenance;
        slot.value_ptr.* = row;
    }
    try selectedArtifactJoin(budget, &artifacts, try field(rows, "codex"), "native-cli");
    try selectedArtifactJoin(budget, &artifacts, try field(rows, "config_schema"), "config-schema");
    const schemas = try field(package, "protocol_schema_files");
    for (modern.protocol_schema_files) |member| {
        const role: []const u8 = if (std.mem.startsWith(u8, member.name, "stable/")) "stable-schema" else if (std.mem.startsWith(u8, member.name, "experimental/")) "experimental-schema" else return error.InvalidRuntimeProvenance;
        try selectedArtifactJoin(budget, &artifacts, try field(schemas, member.name), role);
    }
    const evidence = try field(package, "native_acquisition_artifact_files");
    for (modern.native_acquisition_artifact_files) |member| {
        const role: []const u8 = if (std.mem.endsWith(u8, member.name, "/test.xml")) "test-xml" else if (std.mem.endsWith(u8, member.name, "/test.log")) "test-log" else return error.InvalidRuntimeProvenance;
        try selectedArtifactJoin(budget, &artifacts, try field(evidence, member.name), role);
    }
}

/// The actual package action performs full physical source/SDK/compiler
/// readbacks. This boundary independently retains and joins the raw documents
/// and copied evidence to that action; it does not rerun a compiler or loader.
fn modernMaterial(a: std.mem.Allocator, budget: Budget, inputs: Inputs, manifest: std.json.Value, receipt: std.json.Value, source: std.json.Value) !void {
    const modern = inputs.modern_materials orelse return error.InvalidRuntimeProvenance;
    try packageOutputBinding(a, budget, inputs);
    const selection = try loadSelectedJson(a, budget, modern.package_selection, maximum_metadata_bytes);
    defer selection.deinit();
    const carrier_family = modern.carrier_materials != null;
    if (carrier_family) {
        try exactObject(selection.value, &.{ "schema_version", "kind", "purpose", "material", "compilation", "files", "protocol_schema_files", "native_acquisition_artifact_files", "authority_receipts", "carrier_materials" });
        if (try integer(selection.value, "schema_version") != 2) return error.InvalidRuntimeProvenance;
        try expectText(selection.value, "kind", "omux-native-carrier-native-package-selection-v2");
    } else {
        try exactObject(selection.value, &.{ "schema_version", "kind", "purpose", "material", "compilation", "files", "protocol_schema_files", "native_acquisition_artifact_files", "authority_receipts" });
        if (try integer(selection.value, "schema_version") != 1) return error.InvalidRuntimeProvenance;
        try expectText(selection.value, "kind", "omux-native-source-acquisition-native-package-selection-v1");
    }
    try expectText(selection.value, "purpose", "evaluation-only");
    const roles = try objectField(selection.value, "files");
    if (roles.object.count() != 12) return error.InvalidRuntimeProvenance;
    inline for (@typeInfo(ModernRole).@"enum".field_names, 0..) |role, index| {
        const row = try objectField(roles, role);
        try exactObject(row, &.{ "path", "sha256", "bytes" });
        try canonicalAbsolute(try stringField(row, "path"));
        try inputRow(row, modern.roles[index]);
    }
    try memberMap(budget, try field(selection.value, "protocol_schema_files"), modern.protocol_schema_files);
    try memberMap(budget, try field(selection.value, "native_acquisition_artifact_files"), modern.native_acquisition_artifact_files);
    const authorities = try objectField(selection.value, "authority_receipts");
    try exactObject(authorities, &.{ "source", "sdk", "plan", "query", "compiler" });
    inline for (@typeInfo(ModernAuthorityRole).@"enum".field_names, 0..) |role, index| try authorityMap(budget, try field(authorities, role), modern.authority_receipts[index]);
    if (!std.meta.eql(modern.roles[@backingInt(ModernRole.source)].sha256, inputs.source_receipt.sha256) or
        modern.roles[@backingInt(ModernRole.source)].bytes != inputs.source_receipt.bytes) return error.RuntimeSelectionDrift;
    // The exact declared PACKAGE producer performs full source/SDK/compiler,
    // successful XML and physical readback qualification before emitting the
    // inventory marker. Its independently selected successful guardian binds
    // this full selection and every output. These retained raw tuples are
    // rehashed above; evaluation does not reproduce that physical pipeline or
    // infer supported runtime/loader authority from its summary.
    try expectText(source, "kind", "omux-native-source-acquisition-source-v1");
    try expectText(source, "status", "verified-ninth-acquisition-source-uncompiled");
    try expectText(source, "commit", verifier.upstream_commit);
    try expectBool(source, "acquisition_source_present", true);
    if (carrier_family) try carrierMaterial(a, budget, modern, selection.value, source);
    for ([_]std.json.Value{ manifest, receipt }) |value| {
        try expectText(value, "kind", "omux-native-source-acquisition-fresh-native-package-v1");
        try expectText(value, "status", "experimental-qualified-native-runtime");
        try expectText(value, "producer_target", packageProducerContract(carrier_family).target);
        try expectBool(value, "native_support", false);
        try expectBool(value, "provider_evaluation", false);
        if (!std.meta.eql(try digestField(value, "selection_sha256"), modern.package_selection.sha256)) return error.RuntimeSelectionDrift;
        const chain = try objectField(value, "chain");
        try exactObject(chain, &.{ "material_family", "compiler_qualified", "schema_qualified", "acquisitionContract", "runtime_qualified", "provider_identity_proved", "live_handoff_proven" });
        try expectText(chain, "material_family", if (carrier_family) "native-carrier-acquisition-evaluation-v2" else "native-acquisition-evaluation-v1");
        try expectText(chain, "acquisitionContract", "unsupported");
        try expectBool(chain, "compiler_qualified", true);
        try expectBool(chain, "schema_qualified", true);
        try expectBool(chain, "runtime_qualified", false);
        try expectBool(chain, "provider_identity_proved", false);
        try expectBool(chain, "live_handoff_proven", false);
        try expectBool(try objectField(value, "runtime"), "loader_lookup_qualified", false);
    }
    try expectText(manifest, "target", "x86_64-linux");
    try expectText(receipt, "launchProfile", "linux_nix_direct_main_v1");
    try expectText(receipt, "purpose", "evaluation-only");
    try expectText(receipt, "acquisitionContract", "unsupported");
    const runtime = try objectField(manifest, "runtime");
    try expectText(runtime, "launchProfile", "linux_nix_direct_main_v1");
    try expectText(runtime, "loader", loader);
    try expectText(runtime, "caBundle", ca_bundle);
    if (try positiveInteger(runtime, "backend_max_bytes") != maximum_backend_bytes) return error.InvalidRuntimeProvenance;
    try sameValue(budget, manifest, receipt, "chain");
    try sameValue(budget, manifest, receipt, "runtime");
    try sameValue(budget, manifest, receipt, "executable");
    if (!std.meta.eql(try digestField(receipt, "archive_sha256"), inputs.archive.sha256) or
        try positiveInteger(receipt, "archive_bytes") != inputs.archive.bytes or
        !std.meta.eql(try digestField(receipt, "manifest_sha256"), inputs.manifest.sha256)) return error.RuntimeSelectionDrift;
}

const direct_launcher_bytes = "#!/bin/sh\nset -eu\nunset LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH\n" ++
    "launch_dir=${0%/*}\nif [ \"$launch_dir\" = \"$0\" ]; then launch_dir=.; fi\n" ++
    "pkg_root=$(CDPATH= cd -P \"$launch_dir/..\" && pwd -P) || exit 1\n" ++
    "runtime=$pkg_root/lib/codex\nSSL_CERT_FILE=\"$runtime/share/ca-bundle.crt\"\nexport SSL_CERT_FILE\n" ++
    "exec \"$runtime/libexec/codex.bin\" \"$@\"\n";

fn manifestFd(budget: Budget, directory: c.fd_t) !c.fd_t {
    try budget.check();
    const fd = c.openat(directory, "runtime-manifest.json", .{ .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true });
    if (fd < 0) return error.UnsafeRuntimeInput;
    errdefer _ = c.close(fd);
    const status = try metadata.statFd(fd);
    try regular(status);
    if (status.mode & 0o7777 != 0o644 or status.size > maximum_direct_manifest_bytes) return error.InvalidRuntimeManifest;
    return fd;
}
fn recheckDirectManifest(q: *const Qualified, budget: Budget, hash_payload: bool) !void {
    const observed: *const Retained = @ptrCast(@alignCast(q.observed));
    const fd = try manifestFd(budget, observed.inputs.installation_directory);
    defer _ = c.close(fd);
    const expected = q.record.installed_manifest_status orelse return error.InvalidRuntimeManifest;
    if (!std.meta.eql(expected, try metadata.statFd(fd))) return error.RuntimeSelectionDrift;
    if (hash_payload) {
        const actual = try hashInput(budget, .{ .descriptor = fd, .sha256 = q.record.manifest_sha256, .bytes = @intCast(expected.size) }, maximum_direct_manifest_bytes);
        if (!std.meta.eql(actual, expected)) return error.RuntimeSelectionDrift;
    }
    try budget.check();
}

fn acquireModern(io: std.Io, owner: std.mem.Allocator, context: ActorContext, inputs: Inputs, storage: []u8, bounded: *std.heap.FixedBufferAllocator) !*ValidatedSelection {
    const budget: Budget = .{ .io = io, .deadline = context.deadline };
    const proof_budget: verifier.Budget = .{ .io = io, .deadline = context.deadline };
    const a = bounded.allocator();
    const retained_modern = try retainModern(a, budget, inputs);
    errdefer retained_modern.deinit();
    const directory = c.openat(inputs.installation_directory, ".", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (directory < 0) return error.UnsafeRuntimeInput;
    errdefer _ = c.close(directory);
    if (!std.meta.eql(try metadata.statFd(directory), try metadata.statFd(inputs.installation_directory))) return error.RuntimeSelectionDrift;
    retained_modern.inputs.installation_directory = directory;
    const observed = try observe(io, a, context, retained_modern.inputs);
    errdefer observed.deinit();
    const retained: *Retained = @ptrCast(@alignCast(observed));
    const manifest = try loadSelectedJson(a, budget, retained_modern.inputs.manifest, maximum_direct_manifest_bytes);
    defer manifest.deinit();
    try directArchiveLayout(manifest.value, retained_modern.inputs.manifest.bytes);
    try verifier.archiveSelected(proof_budget, retained_modern.inputs.archive, manifest.value, retained_modern.inputs.manifest.sha256, retained_modern.inputs.manifest.bytes);
    const registration_input = retained_modern.inputs.registration_receipt orelse return error.InvalidRuntimeProvenance;
    const registration_bytes = try readSelectedInput(io, a, context.deadline, registration_input, maximum_metadata_bytes);
    defer a.free(registration_bytes);
    const qualified_nix = try nix_artifact.decode(a, proof_budget, registration_bytes, registration_input.sha256);
    errdefer {
        var value = qualified_nix;
        value.deinit();
    }
    const runtime = try objectField(manifest.value, "runtime");
    try expectText(runtime, "original_interpreter", qualified_nix.record.original_interpreter);
    try expectText(runtime, "backendInterpreter", qualified_nix.record.original_interpreter);
    if (!std.meta.eql(try digestField(runtime, "registration_receipt_sha256"), registration_input.sha256)) return error.RuntimeSelectionDrift;
    var roles: [3]setup.RuntimeRole = undefined;
    for (retained.files) |file| {
        const fd = try openMember(budget, directory, retained.directory, file.path);
        defer _ = c.close(fd);
        if (std.mem.eql(u8, file.path, launcher)) {
            var expected: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(direct_launcher_bytes, &expected, .{});
            if (file.bytes != direct_launcher_bytes.len or !std.meta.eql(file.sha256, expected)) return error.InvalidRuntimeLauncher;
            roles[0] = .{ .sha256 = file.sha256, .bytes = file.bytes };
        } else if (std.mem.eql(u8, file.path, backend)) {
            try nix_artifact.graph(a, proof_budget, qualified_nix.record, fd, file.bytes);
            roles[1] = .{ .sha256 = file.sha256, .bytes = file.bytes };
        } else if (std.mem.eql(u8, file.path, loader)) {
            const external = qualified_nix.record.files[qualified_nix.record.interpreter_file_index];
            if (file.bytes != external.bytes or !std.meta.eql(file.sha256, external.sha256)) return error.RuntimeSelectionDrift;
            roles[2] = .{ .sha256 = file.sha256, .bytes = file.bytes };
        } else if (std.mem.eql(u8, file.path, ca_bundle)) {
            const bytes = try readMetadata(a, budget, .{ .descriptor = fd, .sha256 = file.sha256, .bytes = file.bytes }, file.status);
            defer a.free(bytes);
            try verifier.ca(a, bytes);
        } else return error.InvalidRuntimeManifest;
        if (!std.meta.eql(file.status, try metadata.statFd(fd))) return error.RuntimeSelectionDrift;
    }
    const installed_manifest = try manifestFd(budget, directory);
    defer _ = c.close(installed_manifest);
    const installed_status = try hashInput(budget, .{ .descriptor = installed_manifest, .sha256 = inputs.manifest.sha256, .bytes = inputs.manifest.bytes }, maximum_direct_manifest_bytes);
    if (installed_status.uid != retained.directory.uid or installed_status.gid != retained.directory.gid) return error.UnsafeRuntimeInput;
    const declaration = retained_modern.inputs.deployment_declaration orelse return error.InvalidDeploymentSelection;
    const root = retained_modern.inputs.deployment_root orelse return error.InvalidDeploymentSelection;
    const custody = context.options.native_custody orelse return error.NativeCustodyPending;
    const record: setup.RuntimeSelectionRecord = .{
        .schema_version = 2,
        .channel = if (context.selection == .dev) .development else .release,
        .target = .x86_64_linux,
        .launch_profile = .linux_nix_direct_main_v1,
        .acquisition_contract = .unsupported,
        .upstream_commit = verifier.upstream_commit[0..40].*,
        .artifact_selection_sha256 = artifactDigest(inputArray(retained_modern.inputs)),
        .archive_sha256 = inputs.archive.sha256,
        .manifest_sha256 = inputs.manifest.sha256,
        .runtime_receipt_sha256 = inputs.runtime_receipt.sha256,
        .source_receipt_sha256 = inputs.source_receipt.sha256,
        .producer_receipt_sha256 = inputs.producer_receipt.sha256,
        .installation = .{ .transaction = retained.registry.transaction, .adapter_epoch = custody.adapter_epoch, .capability_digest = retained.registry.capability_digest, .directory_device = retained.directory.dev, .directory_inode = retained.directory.ino, .uid = retained.directory.uid, .gid = retained.directory.gid },
        .launcher = roles[0],
        .backend = roles[1],
        .loader = roles[2],
        .nix_closure = qualified_nix.record,
        .installed_manifest_status = installed_status,
        .deployment = .{ .root = .{ .path = root.path, .status = retained_modern.root_status }, .declaration = .{ .path = try std.fmt.allocPrint(a, "{s}/share/omux/native/codex/deployment.json", .{root.path}), .sha256 = declaration.sha256, .bytes = declaration.bytes, .status = try metadata.statFd(declaration.descriptor) } },
    };
    try observed.recheck(io, context);
    try retained_modern.recheck(budget);
    try retained_modern.recheckIdentity(budget);
    try nix.recheck(io, a, context.deadline, qualified_nix.record);
    const q = try owner.create(Qualified);
    q.* = .{ .observed = observed, .record = record, .deadline = context.deadline, .owner_allocator = owner, .metadata_storage = storage, .metadata_allocator = bounded, .modern = retained_modern, .nix_owned = qualified_nix };
    errdefer owner.destroy(q);
    try recheckDirectManifest(q, budget, true);
    return @ptrCast(q);
}

fn validateOutputMarker(a: std.mem.Allocator, budget: Budget, raw_log: []const u8, inventory_hash: [32]u8) !void {
    const expected_hash = std.fmt.bytesToHex(inventory_hash, .lower);
    const marker = try std.fmt.allocPrint(a, "omux-native-package-output-sha256={s}", .{expected_hash});
    defer a.free(marker);
    var lines = std.mem.splitScalar(u8, raw_log, '\n');
    var count: usize = 0;
    while (lines.next()) |line| {
        try budget.check();
        if (std.mem.indexOf(u8, line, "omux-native-package-output-sha256=") != null) {
            if (!std.mem.eql(u8, line, marker)) return error.InvalidRuntimeProvenance;
            count += 1;
        }
    }
    if (count != 1) return error.InvalidRuntimeProvenance;
}

test "evaluation package output marker refuses absence duplication unrelated hash and expired clock" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const until = std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{ .clock = .awake, .raw = .fromSeconds(30) });
    const budget: Budget = .{ .io = io, .deadline = until };
    const hash: [32]u8 = @splat(0x12);
    const hex = std.fmt.bytesToHex(hash, .lower);
    const one = try std.fmt.allocPrint(a, "test banner\nomux-native-package-output-sha256={s}\n", .{hex});
    defer a.free(one);
    try validateOutputMarker(a, budget, one, hash);
    try std.testing.expectError(error.InvalidRuntimeProvenance, validateOutputMarker(a, budget, "no output marker\n", hash));
    const duplicate = try std.mem.concat(a, u8, &.{ one, one });
    defer a.free(duplicate);
    try std.testing.expectError(error.InvalidRuntimeProvenance, validateOutputMarker(a, budget, duplicate, hash));
    const prefixed = try std.mem.concat(a, u8, &.{ one, "prefix omux-native-package-output-sha256=garbage\n" });
    defer a.free(prefixed);
    try std.testing.expectError(error.InvalidRuntimeProvenance, validateOutputMarker(a, budget, prefixed, hash));
    var wrong = hash;
    wrong[0] ^= 1;
    try std.testing.expectError(error.InvalidRuntimeProvenance, validateOutputMarker(a, budget, one, wrong));
    const expired: Budget = .{ .io = io, .deadline = std.Io.Clock.Timestamp.now(io, .awake) };
    try std.testing.expectError(error.Timeout, validateOutputMarker(a, expired, one, hash));
}

test "carrier retained output markers and copied successful XML require exact finite evidence" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const budget: Budget = .{ .io = io, .deadline = std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{ .clock = .awake, .raw = .fromSeconds(30) }) };
    const hash: [32]u8 = @splat(0x23);
    const prefix = "omux-native-carrier-sdk-output-sha256=";
    const marker = try std.fmt.allocPrint(a, "{s}{s}\n", .{ prefix, std.fmt.bytesToHex(hash, .lower) });
    defer a.free(marker);
    try uniqueHashMarker(a, budget, marker, prefix, hash);
    const twice = try std.mem.concat(a, u8, &.{ marker, marker });
    defer a.free(twice);
    try std.testing.expectError(error.InvalidRuntimeProvenance, uniqueHashMarker(a, budget, twice, prefix, hash));
    try std.testing.expectError(error.InvalidRuntimeProvenance, uniqueHashMarker(a, budget, marker, "omux-native-carrier-metadata-output-sha256=", hash));
    var different = hash;
    different[0] ^= 1;
    try std.testing.expectError(error.InvalidRuntimeProvenance, uniqueHashMarker(a, budget, marker, prefix, different));
    try successfulTestXml(budget, "<?xml version=\"1.0\"?><testsuites><testsuite tests=\"1\" failures=\"0\" errors=\"0\" skipped=\"0\"><testcase name=\"bounded\"><system-out><![CDATA[<untrusted>]]></system-out></testcase></testsuite></testsuites>");
    for ([_][]const u8{
        "<testsuite tests=\"0\"/>",
        "<testsuite tests=\"1\" failures=\"1\"/>",
        "<testsuite tests=\"1\" errors=\"1\"/>",
        "<testsuite tests=\"1\" skipped=\"1\"/>",
        "<testsuites failures=\"1\"><testsuite tests=\"1\" failures=\"0\"/></testsuites>",
        "<testsuites errors=\"1\"><testsuite tests=\"1\" errors=\"0\"/></testsuites>",
        "<testsuites skipped=\"1\"><testsuite tests=\"1\" skipped=\"0\"/></testsuites>",
        "<testsuite tests=\"1\" tests=\"1\"/>",
        "<testsuite tests=\"1\"><failure/></testsuite>",
        "<testsuite tests=\"1\"><testcase></testsuite>",
        "<testsuite tests=\"1\"/><testsuite tests=\"1\"/>",
        "<!DOCTYPE testsuite [<!ENTITY external SYSTEM 'file:///ambient'>]><testsuite tests=\"1\"/>",
        "<testsuites><!-- <testsuite tests=\"1\"/> --></testsuites>",
    }) |raw| try std.testing.expectError(error.InvalidRuntimeProvenance, successfulTestXml(budget, raw));
    const expired: Budget = .{ .io = io, .deadline = std.Io.Clock.Timestamp.now(io, .awake) };
    try std.testing.expectError(error.Timeout, uniqueHashMarker(a, expired, marker, prefix, hash));
    try std.testing.expectError(error.Timeout, successfulTestXml(expired, "<testsuite tests=\"1\"/>"));
}

test "carrier transport tuple keeps original four ordered leaf pins independent of retained capacity" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const budget: Budget = .{ .io = io, .deadline = std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{ .clock = .awake, .raw = .fromSeconds(30) }) };
    const pin = "1111111111111111111111111111111111111111111111111111111111111111";
    const names = [_][]const u8{ "manifest.json", "origin-receipt.json", "payload.bin", "receipt.json" };
    const tuple_raw = try std.json.Stringify.valueAlloc(a, .{
        .{ .name = names[0], .sha256 = pin, .bytes = @as(u64, 32) },
        .{ .name = names[1], .sha256 = pin, .bytes = @as(u64, 32) },
        .{ .name = names[2], .sha256 = pin, .bytes = @as(u64, 4 * 1024 * 1024 * 1024) },
        .{ .name = names[3], .sha256 = pin, .bytes = @as(u64, 32) },
    }, .{});
    defer a.free(tuple_raw);
    const seal_raw = try std.json.Stringify.valueAlloc(a, .{
        .{ .name = names[0], .sha256 = pin, .size = @as(u64, 32) },
        .{ .name = names[1], .sha256 = pin, .size = @as(u64, 32) },
        .{ .name = names[2], .sha256 = pin, .size = @as(u64, 4 * 1024 * 1024 * 1024) },
        .{ .name = names[3], .sha256 = pin, .size = @as(u64, 32) },
    }, .{});
    defer a.free(seal_raw);
    const receipt_raw = try std.json.Stringify.valueAlloc(a, .{ .manifest_sha256 = pin, .manifest_bytes = @as(u64, 32), .origin = .{ .receipt_sha256 = pin, .receipt_bytes = @as(u64, 32) }, .payload_sha256 = pin, .payload_bytes = @as(u64, 4 * 1024 * 1024 * 1024) }, .{});
    defer a.free(receipt_raw);
    var tuple = try std.json.parseFromSlice(std.json.Value, a, tuple_raw, .{});
    defer tuple.deinit();
    const seal = try std.json.parseFromSlice(std.json.Value, a, seal_raw, .{});
    defer seal.deinit();
    const receipt = try std.json.parseFromSlice(std.json.Value, a, receipt_raw, .{});
    defer receipt.deinit();
    const input: Input = .{ .descriptor = -1, .bytes = 32, .sha256 = @splat(0x11) };
    try carrierTuple(budget, tuple.value, seal.value, receipt.value, input);
    const first = tuple.value.array.items[0];
    tuple.value.array.items[0] = tuple.value.array.items[1];
    try std.testing.expectError(error.InvalidRuntimeProvenance, carrierTuple(budget, tuple.value, seal.value, receipt.value, input));
    tuple.value.array.items[0] = first;
    tuple.value.array.items[2].object.getPtr("bytes").?.* = .{ .integer = 1 };
    try std.testing.expectError(error.InvalidRuntimeProvenance, carrierTuple(budget, tuple.value, seal.value, receipt.value, input));
    tuple.value.array.items[2].object.getPtr("bytes").?.* = .{ .integer = 4 * 1024 * 1024 * 1024 };
    var wrong_input = input;
    wrong_input.sha256[0] ^= 1;
    try std.testing.expectError(error.RuntimeSelectionDrift, carrierTuple(budget, tuple.value, seal.value, receipt.value, wrong_input));
    tuple.value.array.items.len = 3;
    try std.testing.expectError(error.InvalidRuntimeProvenance, carrierTuple(budget, tuple.value, seal.value, receipt.value, input));
}

test "carrier projection map preserves empty HUB members and rejects unsafe or unbounded leaf metadata" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const budget: Budget = .{ .io = io, .deadline = std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{ .clock = .awake, .raw = .fromSeconds(30) }) };
    const pin = "1111111111111111111111111111111111111111111111111111111111111111";
    const raw = try std.json.Stringify.valueAlloc(a, .{ .@"hub/empty.bzl" = .{ .sha256 = pin, .bytes = @as(u64, 0), .mode = "100644" } }, .{});
    defer a.free(raw);
    var parsed = try std.json.parseFromSlice(std.json.Value, a, raw, .{});
    defer parsed.deinit();
    try projectionMap(budget, parsed.value);
    const row = parsed.value.object.getPtr("hub/empty.bzl").?;
    row.object.getPtr("bytes").?.* = .{ .integer = maximum_metadata_bytes + 1 };
    try std.testing.expectError(error.RuntimeInputLimit, projectionMap(budget, parsed.value));
    row.object.getPtr("bytes").?.* = .{ .integer = 0 };
    row.object.getPtr("mode").?.* = .{ .integer = 0o444 };
    try std.testing.expectError(error.InvalidRuntimeManifest, projectionMap(budget, parsed.value));
    for ([_][]const u8{ "../host", "/ambient", "safe/../../host", "safe//leaf", "safe/./leaf", "safe\\leaf" }) |path| try std.testing.expectError(error.InvalidRuntimeProvenance, relativeProjectionPath(path));
}

fn carrierModelJson(a: std.mem.Allocator, value: anytype) !std.json.Value {
    const raw = try std.json.Stringify.valueAlloc(a, value, .{});
    // The test arena owns both encoded and parsed bytes for the whole case.
    return (try std.json.parseFromSlice(std.json.Value, a, raw, .{ .duplicate_field_behavior = .@"error", .allocate = .alloc_always })).value;
}
fn carrierModelInput(a: std.mem.Allocator, tmp: std.Io.Dir, name: [:0]const u8, value: std.json.Value) !Input {
    const raw = try std.json.Stringify.valueAlloc(a, value, .{});
    return carrierModelRawInput(tmp, name, raw);
}
fn carrierModelRawInput(tmp: std.Io.Dir, name: [:0]const u8, raw: []const u8) !Input {
    try tmp.writeFile(std.testing.io, .{ .sub_path = name, .data = raw });
    const fd = c.openat(tmp.handle, name.ptr, .{ .NOFOLLOW = true, .CLOEXEC = true });
    if (fd < 0) return error.FixtureOpenFailed;
    errdefer _ = c.close(fd);
    if (c.fchmod(fd, 0o644) != 0) return error.FixtureChmodFailed;
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &hash, .{});
    return .{ .descriptor = fd, .bytes = raw.len, .sha256 = hash };
}
fn carrierModelRow(a: std.mem.Allocator, path: []const u8, input: Input) !std.json.Value {
    return carrierModelJson(a, .{ .path = path, .sha256 = std.fmt.bytesToHex(input.sha256, .lower), .bytes = input.bytes });
}
fn carrierModelSet(value: *std.json.Value, key: []const u8, child: std.json.Value) void {
    value.object.getPtr(key).?.* = child;
}
test "held compact carrier reports independently join SOURCE original authority SDK metadata graph and HUB" {
    // Actual temporary regular bytes are selected and hashed before parsing.
    // This tests report joins, not real producer execution/full qualification.
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const budget: Budget = .{ .io = io, .deadline = std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{ .clock = .awake, .raw = .fromSeconds(30) }) };
    const pin = "1111111111111111111111111111111111111111111111111111111111111111";
    const origin_pin = "1aa4c87d689f464e576a5c6a51b4c6350a8f0346f6b94299856d01db5147d4f0";
    const origin_root = "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/e5b17d7e-d19d-4cb2-be22-41a86b98af7b/sdk-private/sdk-export";
    const producer_pin = try carrierModelJson(a, .{ .receipt = "/proof/11111111-1111-1111-1111-111111111111/receipt.json", .sha256 = pin, .source_commit = "1111111111111111111111111111111111111111", .graph_sha256 = pin });
    const graph = try carrierModelJson(a, .{ .@"MODULE.bazel.lock" = .{ .sha256 = pin } });
    const graph_projection = try carrierModelJson(a, .{ .@"MODULE.bazel.lock" = .{ .sha256 = pin, .bytes = @as(u64, 32), .mode = "100644" } });
    const patches = [_][]const u8{ pin, pin, pin, pin, pin, pin, pin, pin, pin };
    var source = try carrierModelJson(a, .{ .inventory_sha256 = pin, .graph_files = graph, .source_inventory = .{ .@"MODULE.bazel.lock" = .{ .sha256 = pin, .mode = "100644" } }, .patch_sha256 = patches });
    // Value is inserted explicitly; Stringify(Value) represents the JSON value.
    carrierModelSet(&source, "graph_files", graph);
    const source_input = try carrierModelInput(a, tmp.dir, "source", source);
    defer _ = c.close(source_input.descriptor);
    var source_row = try carrierModelJson(a, .{ .root = "/source", .receipt_sha256 = std.fmt.bytesToHex(source_input.sha256, .lower), .inventory_sha256 = pin, .producer = null });
    carrierModelSet(&source_row, "producer", producer_pin);
    const original = try carrierModelJson(a, .{ .kind = "omux-native-source-acquisition-metadata-input-v1", .source_root = "/source", .source_receipt_sha256 = std.fmt.bytesToHex(source_input.sha256, .lower), .source_inventory_sha256 = pin, .export_root = origin_root, .export_receipt_sha256 = origin_pin, .binding_receipt_sha256 = pin });
    const carrier = try carrierModelJson(a, .{
        .kind = "omux-native-sdk-carrier-v1",
        .producer_context = .{},
        .origin = .{ .root = origin_root, .receipt_sha256 = origin_pin, .receipt_bytes = @as(u64, 32), .baseline_receipt_sha256 = pin, .baseline_inventory_sha256 = pin, .inventory_sha256 = pin, .mapping_sha256 = pin, .selection_sha256 = pin, .producer = "//tools:codex_retained_sdk_export_run" },
        .origin_custody = .{ .sdk = .{ .root = origin_root, .root_identity = .{ 1, 2, 0, 0, 0o40555 }, .ancestry_sha256 = pin, .members_sha256 = pin }, .jdk = .{ .root = "/inert-jdk", .root_identity = .{ 1, 3, 0, 0, 0o40555 }, .ancestry_sha256 = pin, .members_sha256 = pin } },
        .manifest_sha256 = pin,
        .manifest_bytes = @as(u64, 32),
        .payload_sha256 = pin,
        .payload_bytes = @as(u64, 4 * 1024 * 1024 * 1024),
        .entry_count = @as(u64, 1),
        .origin_fully_rechecked = true,
        .sdk_execution_qualified = false,
        .metadata_qualified = false,
        .source_witnesses_replaced = false,
    });
    const carrier_input = try carrierModelInput(a, tmp.dir, "carrier", carrier);
    defer _ = c.close(carrier_input.descriptor);
    const tuple = try carrierModelJson(a, .{
        .{ .name = "manifest.json", .sha256 = pin, .bytes = @as(u64, 32) },
        .{ .name = "origin-receipt.json", .sha256 = origin_pin, .bytes = @as(u64, 32) },
        .{ .name = "payload.bin", .sha256 = pin, .bytes = @as(u64, 4 * 1024 * 1024 * 1024) },
        .{ .name = "receipt.json", .sha256 = std.fmt.bytesToHex(carrier_input.sha256, .lower), .bytes = carrier_input.bytes },
    });
    const seal = try carrierModelJson(a, .{
        .kind = "omux-native-sdk-carrier-producer-v1",
        .producer = "//tools:codex_native_sdk_carrier_seal_producer",
        .carrier_receipt_sha256 = std.fmt.bytesToHex(carrier_input.sha256, .lower),
        .origin_receipt_sha256 = origin_pin,
        .producer_context = .{},
        .files = .{ .{ .name = "manifest.json", .sha256 = pin, .size = @as(u64, 32) }, .{ .name = "origin-receipt.json", .sha256 = origin_pin, .size = @as(u64, 32) }, .{ .name = "payload.bin", .sha256 = pin, .size = @as(u64, 4 * 1024 * 1024 * 1024) }, .{ .name = "receipt.json", .sha256 = std.fmt.bytesToHex(carrier_input.sha256, .lower), .size = carrier_input.bytes } },
        .all_four_leaves_rechecked = true,
        .sdk_execution_qualified = false,
        .metadata_qualified = false,
        .compiler_qualified = false,
        .runtime_qualified = false,
    });
    const seal_input = try carrierModelInput(a, tmp.dir, "seal", seal);
    defer _ = c.close(seal_input.descriptor);
    const seal_row = try carrierModelRow(a, "/seal/native-sdk-carrier-producer.json", seal_input);
    var metadata_report = try carrierModelJson(a, .{
        .schema_version = @as(u64, 2),
        .kind = "omux-native-sdk-carrier-metadata-v2",
        .status = "verified-fresh-carrier-custody-regenerated-native-acquisition-hub",
        .original_selection = null,
        .selector_sha256 = pin,
        .source_inventory_sha256 = pin,
        .source_graph = null,
        .patch_sha256 = patches,
        .carrier = .{ .receipt_sha256 = std.fmt.bytesToHex(carrier_input.sha256, .lower), .origin = null, .origin_custody = null, .producer_context = .{}, .qualification = .{ .outer_receipt_sha256 = pin, .report_sha256 = std.fmt.bytesToHex(seal_input.sha256, .lower), .report = null } },
        .extraction = .{},
        .extraction_receipt_sha256 = pin,
        .consumer_context = .{},
        .consumer_deadline = @as(f64, 600),
        .query_exit = @as(u64, 0),
        .query_plan = .{},
        .output_parent_mode = "0700",
        .query_tool_closure_independently_rechecked = true,
        .packaged_jdk_used_as_query_tool_relocation = false,
        .module_and_cargo_lock_unchanged = true,
        .retained_hub = .{},
        .generated_hub = .{.{ .path = "empty.bzl", .sha256 = pin }},
        .source_and_extracted_carrier_rechecked = true,
        .sdk_export_qualified = false,
        .sdk_execution_qualified = false,
        .metadata_qualified = false,
        .compiler_qualified = false,
        .native_compile_passed = false,
        .runtime_qualified = false,
        .installed_package_primary_qualified = false,
        .schema_producer_qualified = false,
        .native_support = false,
        .provider_evaluation = false,
        .credential_acquisition_qualified = false,
        .live_handoff_proven = false,
        .source_witnesses_replaced = false,
        .legacy_metadata_family_qualified = false,
    });
    carrierModelSet(&metadata_report, "original_selection", original);
    carrierModelSet(&metadata_report, "source_graph", graph);
    const metadata_carrier = metadata_report.object.getPtr("carrier").?;
    carrierModelSet(metadata_carrier, "origin", try field(carrier, "origin"));
    carrierModelSet(metadata_carrier, "origin_custody", try field(carrier, "origin_custody"));
    carrierModelSet(metadata_carrier.object.getPtr("qualification").?, "report", seal);
    const metadata_input = try carrierModelInput(a, tmp.dir, "metadata", metadata_report);
    defer _ = c.close(metadata_input.descriptor);
    const metadata_row = try carrierModelRow(a, "/metadata/metadata-receipt.json", metadata_input);
    var core = try carrierModelJson(a, .{ .schema_version = @as(u64, 2), .kind = "omux-native-carrier-sdk-authority-core-v2", .source = null, .original_selection = null, .carrier_files = null, .seal = .{ .producer = null, .program = null }, .metadata = .{ .producer = null, .program = null }, .hub_inventory_sha256 = pin, .graph_inventory_sha256 = pin });
    carrierModelSet(&core, "source", source_row);
    carrierModelSet(&core, "original_selection", original);
    carrierModelSet(&core, "carrier_files", tuple);
    inline for (.{ "seal", "metadata" }, .{ seal_row, metadata_row }) |key, row| {
        carrierModelSet(core.object.getPtr(key).?, "producer", producer_pin);
        carrierModelSet(core.object.getPtr(key).?, "program", row);
    }
    const core_input = try carrierModelInput(a, tmp.dir, "core", core);
    defer _ = c.close(core_input.descriptor);
    const core_hex = std.fmt.bytesToHex(core_input.sha256, .lower);
    var sdk = try carrierModelJson(a, .{ .schema_version = @as(u64, 2), .kind = "omux-native-carrier-sdk-projection-v2", .status = "verified-carrier-sdk-projection-with-fresh-custody", .source = null, .original_selection = null, .authority_sha256 = core_hex, .inventory_sha256 = core_hex, .carrier_files = null, .seal = null, .metadata = null, .hub_files = .{ .@"empty.bzl" = .{ .sha256 = pin, .bytes = @as(u64, 0), .mode = "100644" } }, .graph_files = null, .hub_inventory_sha256 = pin, .graph_inventory_sha256 = pin, .mapping_sha256 = pin, .patch_sha256 = patches, .sdk_export_qualified = true, .source_and_carrier_rechecked = true, .compiler_qualified = false, .native_compile_passed = false, .runtime_qualified = false, .installed_package_primary_qualified = false, .schema_producer_qualified = false, .native_support = false, .provider_evaluation = false, .credential_acquisition_qualified = false, .live_handoff_proven = false, .source_witnesses_replaced = false });
    inline for (.{ "source", "original_selection", "carrier_files", "seal", "metadata" }) |key| carrierModelSet(&sdk, key, try field(core, key));
    carrierModelSet(&sdk, "graph_files", graph_projection);
    const sdk_input = try carrierModelInput(a, tmp.dir, "sdk", sdk);
    defer _ = c.close(sdk_input.descriptor);
    var sdk_row = try carrierModelJson(a, .{ .root = "/sdk", .receipt_sha256 = std.fmt.bytesToHex(sdk_input.sha256, .lower), .inventory_sha256 = core_hex, .producer = null });
    carrierModelSet(&sdk_row, "producer", producer_pin);
    var material = try carrierModelJson(a, .{ .schema_version = @as(u64, 2), .kind = "omux-native-carrier-native-selection-v2", .source = null, .sdk = null, .controller_source_commit = "1111111111111111111111111111111111111111", .controller_graph_sha256 = pin });
    carrierModelSet(&material, "source", source_row);
    carrierModelSet(&material, "sdk", sdk_row);
    var receipt_rows = try carrierModelJson(a, .{ .authority_document = null, .carrier_receipt = null, .seal_program = null, .metadata_program = null });
    carrierModelSet(&receipt_rows, "authority_document", try carrierModelRow(a, "/sdk/authority.json", core_input));
    carrierModelSet(&receipt_rows, "carrier_receipt", try carrierModelRow(a, "/carrier/receipt.json", carrier_input));
    carrierModelSet(&receipt_rows, "seal_program", seal_row);
    carrierModelSet(&receipt_rows, "metadata_program", metadata_row);
    const compact = try carrierModelJson(a, .{ .authority_sha256 = core_hex, .projection = .{ .receipt_sha256 = std.fmt.bytesToHex(sdk_input.sha256, .lower), .inventory_sha256 = core_hex, .hub_inventory_sha256 = pin, .graph_inventory_sha256 = pin }, .carrier_files = tuple });
    var role_rows = try carrierModelJson(a, .{ .sdk_metadata = null });
    carrierModelSet(&role_rows, "sdk_metadata", metadata_row);
    const blank: Input = .{ .descriptor = -1, .sha256 = @splat(0x11), .bytes = 32 };
    const group: ModernAuthority = .{ .outer = blank, .evidence = blank, .members = &.{} };
    const selected: CarrierInputs = .{ .receipts = .{ core_input, carrier_input, seal_input, metadata_input }, .authority_receipts = .{ group, group } };
    var modern: ModernInputs = .{ .package_selection = blank, .package_outputs = blank, .package_output_root = "/package", .package_authority = group, .roles = @splat(blank), .authority_receipts = @splat(group), .protocol_schema_files = &.{}, .native_acquisition_artifact_files = &.{}, .carrier_materials = selected };
    modern.roles[@backingInt(ModernRole.source)] = source_input;
    modern.roles[@backingInt(ModernRole.sdk)] = sdk_input;
    modern.roles[@backingInt(ModernRole.sdk_metadata)] = metadata_input;
    const read_core = try loadSelectedJson(a, budget, core_input, maximum_metadata_bytes);
    const read_seal = try loadSelectedJson(a, budget, seal_input, maximum_metadata_bytes);
    const read_carrier = try loadSelectedJson(a, budget, carrier_input, maximum_metadata_bytes);
    var read_sdk = try loadSelectedJson(a, budget, sdk_input, maximum_metadata_bytes);
    var read_metadata = try loadSelectedJson(a, budget, metadata_input, maximum_metadata_bytes);
    try carrierReports(budget, read_core.value, read_sdk.value, read_seal.value, read_metadata.value, read_carrier.value, source, material, compact, receipt_rows, selected, role_rows, modern);
    // Internally consistent-looking wire flags cannot replace selected SHA or
    // independently retained SOURCE/metadata joins.
    const good_authority = try field(read_sdk.value, "authority_sha256");
    carrierModelSet(&read_sdk.value, "authority_sha256", .{ .string = pin });
    try std.testing.expectError(error.RuntimeSelectionDrift, carrierReports(budget, read_core.value, read_sdk.value, read_seal.value, read_metadata.value, read_carrier.value, source, material, compact, receipt_rows, selected, role_rows, modern));
    carrierModelSet(&read_sdk.value, "authority_sha256", good_authority);
    carrierModelSet(&read_sdk.value, "live_handoff_proven", .{ .bool = true });
    try std.testing.expectError(error.InvalidRuntimeProvenance, carrierReports(budget, read_core.value, read_sdk.value, read_seal.value, read_metadata.value, read_carrier.value, source, material, compact, receipt_rows, selected, role_rows, modern));
    carrierModelSet(&read_sdk.value, "live_handoff_proven", .{ .bool = false });
    const hub_row = read_sdk.value.object.getPtr("hub_files").?.object.getPtr("empty.bzl").?;
    carrierModelSet(hub_row, "sha256", .{ .string = "2222222222222222222222222222222222222222222222222222222222222222" });
    try std.testing.expectError(error.RuntimeSelectionDrift, carrierReports(budget, read_core.value, read_sdk.value, read_seal.value, read_metadata.value, read_carrier.value, source, material, compact, receipt_rows, selected, role_rows, modern));
    carrierModelSet(hub_row, "sha256", .{ .string = pin });
    const graph_row = read_sdk.value.object.getPtr("graph_files").?.object.getPtr("MODULE.bazel.lock").?;
    carrierModelSet(graph_row, "sha256", .{ .string = "2222222222222222222222222222222222222222222222222222222222222222" });
    try std.testing.expectError(error.RuntimeSelectionDrift, carrierReports(budget, read_core.value, read_sdk.value, read_seal.value, read_metadata.value, read_carrier.value, source, material, compact, receipt_rows, selected, role_rows, modern));
    carrierModelSet(graph_row, "sha256", .{ .string = pin });
    read_sdk.value.object.getPtr("patch_sha256").?.array.items[8] = .{ .string = "2222222222222222222222222222222222222222222222222222222222222222" };
    try std.testing.expectError(error.RuntimeSelectionDrift, carrierReports(budget, read_core.value, read_sdk.value, read_seal.value, read_metadata.value, read_carrier.value, source, material, compact, receipt_rows, selected, role_rows, modern));
    read_sdk.value.object.getPtr("patch_sha256").?.array.items[8] = .{ .string = pin };
    carrierModelSet(read_metadata.value.object.getPtr("original_selection").?, "binding_receipt_sha256", .{ .string = "2222222222222222222222222222222222222222222222222222222222222222" });
    try std.testing.expectError(error.RuntimeSelectionDrift, carrierReports(budget, read_core.value, read_sdk.value, read_seal.value, read_metadata.value, read_carrier.value, source, material, compact, receipt_rows, selected, role_rows, modern));
    var corrupt_core = core_input;
    corrupt_core.sha256[0] ^= 1;
    try std.testing.expectError(error.RuntimeSelectionDrift, loadSelectedJson(a, budget, corrupt_core, maximum_metadata_bytes));
}

test "carrier proof uses held raw guardian copied index XML and actual program digest marker" {
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const budget: Budget = .{ .io = io, .deadline = std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{ .clock = .awake, .raw = .fromSeconds(30) }) };
    const pin = "1111111111111111111111111111111111111111111111111111111111111111";
    const commit = "1111111111111111111111111111111111111111";
    const id = "11111111-1111-1111-1111-111111111111";
    const epoch = "/proof/11111111-1111-1111-1111-111111111111";
    const target = "//tools:codex_native_carrier_sdk_export_producer";
    const profile = "native-sdk-carrier-sdk-export-reserved";
    const leaf = "native-carrier-sdk-export/sdk-receipt.json";
    const marker = "omux-native-carrier-sdk-output-sha256=";
    const program = try carrierModelInput(a, tmp.dir, "program-proof", try carrierModelJson(a, .{ .kind = "synthetic-retained-program-model" }));
    defer _ = c.close(program.descriptor);
    const log_bytes = try std.fmt.allocPrint(a, "{s}{s}\n", .{ marker, std.fmt.bytesToHex(program.sha256, .lower) });
    const log = try carrierModelRawInput(tmp.dir, "copied-log", log_bytes);
    defer _ = c.close(log.descriptor);
    const xml = try carrierModelRawInput(tmp.dir, "copied-xml", "<testsuites><testsuite tests=\"1\" failures=\"0\" errors=\"0\" skipped=\"0\"><testcase name=\"program-model\"/></testsuite></testsuites>");
    defer _ = c.close(xml.descriptor);
    const log_name = try collectorEvidenceName(a, target, "k8", "test.log");
    const xml_name = try collectorEvidenceName(a, target, "k8", "test.xml");
    const manifest_name = try collectorEvidenceName(a, target, "k8", "test.outputs_manifest/MANIFEST");
    try std.testing.expect(!std.mem.eql(u8, log_name[0..64], &std.fmt.bytesToHex(log.sha256, .lower)));
    try std.testing.expect(!std.mem.eql(u8, xml_name[0..64], &std.fmt.bytesToHex(xml.sha256, .lower)));
    const evidence_doc = try carrierModelJson(a, .{ .schema = @as(u64, 1), .bazel_exit = @as(u64, 0), .epoch_start_ns = @as(u64, 10), .targets = .{target}, .results = .{.{ .target = target, .configuration = "k8", .state = "observed", .files = .{
        .{ .source = "test.log", .file = log_name, .sha256 = std.fmt.bytesToHex(log.sha256, .lower), .bytes = log.bytes, .state = "copied" },
        .{ .source = "test.xml", .file = xml_name, .sha256 = std.fmt.bytesToHex(xml.sha256, .lower), .bytes = xml.bytes, .state = "copied" },
        .{ .source = "test.outputs_manifest/MANIFEST", .file = manifest_name, .sha256 = pin, .bytes = @as(u64, 324), .state = "copied" },
        .{ .source = "test.outputs_manifest/ANNOTATIONS", .bytes = @as(u64, 0), .state = "missing" },
    } }} });
    const evidence = try carrierModelInput(a, tmp.dir, "copied-index", evidence_doc);
    defer _ = c.close(evidence.descriptor);
    const reservation = .{
        .scope = "fixed-native-sdk-carrier-sdk-export-reserved-v1",
        .profile = profile,
        .original_entry_monotonic_ns = @as(u64, 1000000000),
        .original_deadline_monotonic_ns = @as(u64, 1201000000000),
        .verified_after_cleanup = true,
        .resident = .{ .scope = "sampled-fixed-default-cgroup-kernel-reservation-v1", .kernel_bounds = .{ .@"memory.max" = "268435456", .@"memory.swap.max" = "0", .@"pids.max" = "32", .@"cpu.max" = "10000 100000" }, .observations = @as(u64, 1), .initial_direct_processes_retained = true, .initial_direct_process_count = @as(u64, 1), .outer_pid_namespace_matched = true, .hierarchical_caps = true, .descendant_process_inventory = false, .installation_qualified = false, .health_observed = false, .custody_observed = false, .resident_signalled = false, .whole_host_reservation = false },
        .input_predicates_required = true,
        .query_tools_qualified = false,
        .metadata_qualified = false,
        .sdk_qualified = false,
        .schema_qualified = false,
        .compiler_qualified = false,
        .native_runtime_qualified = false,
        .continuity_qualified = false,
        .custody_qualified = false,
        .health_qualified = false,
        .credential_acquisition = false,
        .native_source_finalized = false,
        .native_support = false,
        .provider_identity_proved = false,
        .live_handoff_proven = false,
        .context_rotation = false,
        .daemon_context_acquisition = false,
    };
    const outer_doc = try carrierModelJson(a, .{
        .profile = profile,
        .id = id,
        .unit = "omux-execution-11111111-1111-1111-1111-111111111111.service",
        .source_commit = commit,
        .graph_sha256 = pin,
        .manager = "system",
        .verb = "test",
        .exit = @as(u64, 0),
        .workload_exit = @as(u64, 0),
        .controller_failure = null,
        .descendants_empty = true,
        .cleanup = .{ .state = "empty" },
        .source_dirty = "false",
        .cache_reuse_requested = false,
        .cache_policy = null,
        .cache_key = null,
        .targets = .{target},
        .output_base = "/output",
        .epoch_start_ns = @as(u64, 10),
        .test_evidence = .{ .state = "preserved", .sha256 = std.fmt.bytesToHex(evidence.sha256, .lower) },
        .observed_properties = .{ .MemoryMax = "4026531840", .MemorySwapMax = "0", .TasksMax = "480", .PrivateNetwork = "yes", .KillMode = "control-group", .SendSIGKILL = "yes", .OOMPolicy = "kill", .RemainAfterExit = "yes", .CPUQuotaPerSecUSec = "1.9s", .RuntimeMaxUSec = "1200s" },
        .native_acquisition_inputs_reservation = reservation,
    });
    const outer = try carrierModelInput(a, tmp.dir, "guardian", outer_doc);
    defer _ = c.close(outer.descriptor);
    const producer_pin = try carrierModelJson(a, .{ .receipt = epoch ++ "/receipt.json", .sha256 = std.fmt.bytesToHex(outer.sha256, .lower), .source_commit = commit, .graph_sha256 = pin });
    var group_rows = try carrierModelJson(a, .{ .outer = null, .evidence = null, .members = null });
    carrierModelSet(&group_rows, "outer", try carrierModelRow(a, epoch ++ "/receipt.json", outer));
    carrierModelSet(&group_rows, "evidence", try carrierModelRow(a, epoch ++ "/test-evidence.json", evidence));
    var member_rows = try carrierModelJson(a, .{});
    // Empty tuple stringify is an array; obtain an explicit object for names.
    member_rows = (try std.json.parseFromSlice(std.json.Value, a, "{}", .{})).value;
    try member_rows.object.put(a, log_name, try carrierModelRow(a, try std.fmt.allocPrint(a, "{s}/test-evidence/{s}", .{ epoch, log_name }), log));
    try member_rows.object.put(a, xml_name, try carrierModelRow(a, try std.fmt.allocPrint(a, "{s}/test-evidence/{s}", .{ epoch, xml_name }), xml));
    carrierModelSet(&group_rows, "members", member_rows);
    const members = [_]ModernMember{ .{ .name = log_name, .input = log }, .{ .name = xml_name, .input = xml } };
    const group: ModernAuthority = .{ .outer = outer, .evidence = evidence, .members = &members };
    const program_row = try carrierModelRow(a, "/output/execroot/_main/bazel-out/k8/testlogs/tools/codex_native_carrier_sdk_export_producer/test.outputs/native-carrier-sdk-export/sdk-receipt.json", program);
    const accepted = try carrierProducerProof(a, budget, group, group_rows, producer_pin, program_row, target, profile, leaf, marker, program);
    var context = try carrierModelJson(a, .{ .mode = profile, .epoch = epoch, .source_commit = commit, .graph_sha256 = pin, .entry_monotonic_ns = @as(u64, 1000000000), .deadline_monotonic_ns = @as(u64, 1201000000000) });
    try producerContext(a, context, producer_pin, accepted.value, profile, false);
    carrierModelSet(&context, "deadline_monotonic_ns", .{ .integer = 1202000000000 });
    try std.testing.expectError(error.RuntimeSelectionDrift, producerContext(a, context, producer_pin, accepted.value, profile, false));
    accepted.deinit();
    try std.testing.expectError(error.InvalidRuntimeProvenance, carrierProducerProof(a, budget, group, group_rows, producer_pin, program_row, target, "native-sdk-carrier-metadata-reserved", leaf, marker, program));
    try std.testing.expectError(error.InvalidRuntimeProvenance, carrierProducerProof(a, budget, group, group_rows, producer_pin, program_row, "//tools:codex_native_carrier_metadata_producer", profile, leaf, marker, program));
    try std.testing.expectError(error.InvalidRuntimeProvenance, carrierProducerProof(a, budget, group, group_rows, producer_pin, program_row, target, profile, leaf, "omux-native-carrier-metadata-output-sha256=", program));
    var different = program;
    different.sha256[0] ^= 1;
    try std.testing.expectError(error.RuntimeSelectionDrift, carrierProducerProof(a, budget, group, group_rows, producer_pin, program_row, target, profile, leaf, marker, different));
    var wrong_epoch = producer_pin;
    carrierModelSet(&wrong_epoch, "receipt", .{ .string = "/other/22222222-2222-2222-2222-222222222222/receipt.json" });
    try std.testing.expectError(error.InvalidRuntimeProvenance, carrierProducerProof(a, budget, group, group_rows, wrong_epoch, program_row, target, profile, leaf, marker, program));
    const expired: Budget = .{ .io = io, .deadline = std.Io.Clock.Timestamp.now(io, .awake) };
    try std.testing.expectError(error.Timeout, carrierProducerProof(a, expired, group, group_rows, producer_pin, program_row, target, profile, leaf, marker, program));
}

test "retained PACKAGE proof binds each family target profile namespace and original guardian clock" {
    // This is a retained-byte consumer model, not a genuine PACKAGE action.
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const budget: Budget = .{ .io = io, .deadline = std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{ .clock = .awake, .raw = .fromSeconds(30) }) };
    const pin = "1111111111111111111111111111111111111111111111111111111111111111";
    const names = [_][]const u8{ "fresh-native-runtime.tar.gz", "runtime-manifest.json", "runtime-receipt.json", "registration-receipt.json", "package-selection.json" };
    for ([_]bool{ false, true }) |carrier_family| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        const contract = packageProducerContract(carrier_family);
        const other = packageProducerContract(!carrier_family);
        var selected: [5]Input = undefined;
        for (names, &selected) |name, *input| input.* = try carrierModelRawInput(tmp.dir, try a.dupeZ(u8, name), name);
        defer for (selected) |input| _ = c.close(input.descriptor);
        var files = (try std.json.parseFromSlice(std.json.Value, a, "{}", .{})).value;
        for (names, selected) |name, input| try files.object.put(a, name, try carrierModelJson(a, .{ .sha256 = std.fmt.bytesToHex(input.sha256, .lower), .bytes = input.bytes }));
        var output_doc = try carrierModelJson(a, .{ .schema_version = @as(u64, 1), .kind = "omux-native-acquisition-package-output-v1", .purpose = "evaluation-only", .acquisitionContract = "unsupported", .files = null });
        carrierModelSet(&output_doc, "files", files);
        const output = try carrierModelInput(a, tmp.dir, "output-inventory", output_doc);
        defer _ = c.close(output.descriptor);
        const log = try carrierModelRawInput(tmp.dir, "copied-package-log", try std.fmt.allocPrint(a, "omux-native-package-output-sha256={s}\n", .{std.fmt.bytesToHex(output.sha256, .lower)}));
        defer _ = c.close(log.descriptor);
        const xml = try carrierModelRawInput(tmp.dir, "copied-package-xml", "<testsuites><testsuite tests=\"1\" failures=\"0\" errors=\"0\" skipped=\"0\"><testcase name=\"package-consumer-model\"/></testsuite></testsuites>");
        defer _ = c.close(xml.descriptor);
        const log_name = if (carrier_family) try collectorEvidenceName(a, contract.target, "k8", "test.log") else try std.fmt.allocPrint(a, "{s}.evidence", .{std.fmt.bytesToHex(log.sha256, .lower)});
        const xml_name = if (carrier_family) try collectorEvidenceName(a, contract.target, "k8", "test.xml") else try std.fmt.allocPrint(a, "{s}.evidence", .{std.fmt.bytesToHex(xml.sha256, .lower)});
        const evidence_doc = try carrierModelJson(a, .{ .schema = @as(u64, 1), .bazel_exit = @as(u64, 0), .epoch_start_ns = @as(u64, 10), .targets = .{contract.target}, .results = .{.{ .target = contract.target, .configuration = "k8", .state = "observed", .files = .{
            .{ .source = "test.log", .file = log_name, .sha256 = std.fmt.bytesToHex(log.sha256, .lower), .bytes = log.bytes, .state = "copied" },
            .{ .source = "test.xml", .file = xml_name, .sha256 = std.fmt.bytesToHex(xml.sha256, .lower), .bytes = xml.bytes, .state = "copied" },
        } }} });
        const evidence = try carrierModelInput(a, tmp.dir, "package-index", evidence_doc);
        defer _ = c.close(evidence.descriptor);
        const reservation = .{
            .scope = try std.fmt.allocPrint(a, "fixed-{s}-v1", .{contract.profile}),
            .profile = contract.profile,
            .original_entry_monotonic_ns = @as(u64, 1000000000),
            .original_deadline_monotonic_ns = @as(u64, 1201000000000),
            .verified_after_cleanup = true,
            .resident = .{ .scope = "sampled-fixed-default-cgroup-kernel-reservation-v1", .kernel_bounds = .{ .@"memory.max" = "268435456", .@"memory.swap.max" = "0", .@"pids.max" = "32", .@"cpu.max" = "10000 100000" }, .observations = @as(u64, 1), .initial_direct_processes_retained = true, .initial_direct_process_count = @as(u64, 1), .outer_pid_namespace_matched = true, .hierarchical_caps = true, .descendant_process_inventory = false, .installation_qualified = false, .health_observed = false, .custody_observed = false, .resident_signalled = false, .whole_host_reservation = false },
            .input_predicates_required = true,
            .query_tools_qualified = false,
            .metadata_qualified = false,
            .sdk_qualified = false,
            .schema_qualified = false,
            .compiler_qualified = false,
            .native_runtime_qualified = false,
            .continuity_qualified = false,
            .custody_qualified = false,
            .health_qualified = false,
            .credential_acquisition = false,
            .native_source_finalized = false,
            .native_support = false,
            .provider_identity_proved = false,
            .live_handoff_proven = false,
            .context_rotation = false,
            .daemon_context_acquisition = false,
        };
        var outer_doc = try carrierModelJson(a, .{
            .profile = contract.profile,
            .id = "11111111-1111-1111-1111-111111111111",
            .unit = "omux-execution-11111111-1111-1111-1111-111111111111.service",
            .source_commit = "1111111111111111111111111111111111111111",
            .graph_sha256 = pin,
            .manager = "system",
            .verb = "test",
            .exit = @as(u64, 0),
            .workload_exit = @as(u64, 0),
            .controller_failure = null,
            .descendants_empty = true,
            .cleanup = .{ .state = "empty" },
            .source_dirty = "false",
            .cache_reuse_requested = false,
            .cache_policy = null,
            .cache_key = null,
            .targets = .{contract.target},
            .output_base = "/output",
            .epoch_start_ns = @as(u64, 10),
            .test_evidence = .{ .state = "preserved", .sha256 = std.fmt.bytesToHex(evidence.sha256, .lower) },
            .observed_properties = .{ .MemoryMax = "4026531840", .MemorySwapMax = "0", .TasksMax = "480", .PrivateNetwork = "yes", .KillMode = "control-group", .SendSIGKILL = "yes", .OOMPolicy = "kill", .RemainAfterExit = "yes", .CPUQuotaPerSecUSec = "1.9s", .RuntimeMaxUSec = "1200s" },
            .native_acquisition_inputs_reservation = reservation,
        });
        const outer = try carrierModelInput(a, tmp.dir, "package-guardian", outer_doc);
        defer _ = c.close(outer.descriptor);
        const members = [_]ModernMember{ .{ .name = log_name, .input = log }, .{ .name = xml_name, .input = xml } };
        const group: ModernAuthority = .{ .outer = outer, .evidence = evidence, .members = &members };
        const modern: ModernInputs = .{ .package_selection = selected[4], .package_outputs = output, .package_output_root = try std.fmt.allocPrint(a, "/output/execroot/_main/bazel-out/k8{s}", .{contract.output_suffix}), .package_authority = group, .roles = @splat(selected[4]), .protocol_schema_files = &.{}, .native_acquisition_artifact_files = &.{}, .authority_receipts = @splat(group), .carrier_materials = if (carrier_family) .{ .receipts = @splat(selected[4]), .authority_receipts = @splat(group) } else null };
        const inputs: Inputs = .{ .archive = selected[0], .manifest = selected[1], .runtime_receipt = selected[2], .registration_receipt = selected[3], .source_receipt = selected[4], .producer_receipt = outer, .installation_directory = -1, .modern_materials = modern };
        try packageOutputBinding(a, budget, inputs);
        var wrong_namespace = inputs;
        wrong_namespace.modern_materials.?.package_output_root = try std.fmt.allocPrint(a, "/output/execroot/_main/bazel-out/k8{s}", .{other.output_suffix});
        try std.testing.expectError(error.InvalidRuntimeProvenance, packageOutputBinding(a, budget, wrong_namespace));
        var wrong_inventory = inputs;
        wrong_inventory.archive.sha256[0] ^= 1;
        try std.testing.expectError(error.RuntimeSelectionDrift, packageOutputBinding(a, budget, wrong_inventory));
        // Rehash every changed raw guardian and select its new held descriptor:
        // refusals below concern semantic branch/clock joins, not stale hashes.
        const saved_targets = outer_doc.object.get("targets").?;
        const saved_reservation = outer_doc.object.get("native_acquisition_inputs_reservation").?;
        for (0..4) |negative| {
            carrierModelSet(&outer_doc, "profile", .{ .string = contract.profile });
            carrierModelSet(&outer_doc, "targets", saved_targets);
            var changed_reservation = try carrierModelJson(a, reservation);
            switch (negative) {
                0 => outer_doc.object.getPtr("targets").?.array.items[0] = .{ .string = other.target },
                1 => carrierModelSet(&outer_doc, "profile", .{ .string = other.profile }),
                2 => carrierModelSet(&changed_reservation, "scope", .{ .string = try std.fmt.allocPrint(a, "fixed-{s}-v1", .{other.profile}) }),
                3 => carrierModelSet(&changed_reservation, "original_deadline_monotonic_ns", .{ .integer = 1202000000000 }),
                else => unreachable,
            }
            carrierModelSet(&outer_doc, "native_acquisition_inputs_reservation", changed_reservation);
            const changed_outer = try carrierModelInput(a, tmp.dir, try a.dupeZ(u8, try std.fmt.allocPrint(a, "changed-guardian-{d}", .{negative})), outer_doc);
            defer _ = c.close(changed_outer.descriptor);
            var changed = inputs;
            changed.producer_receipt = changed_outer;
            changed.modern_materials.?.package_authority.outer = changed_outer;
            try std.testing.expectError(error.InvalidRuntimeProvenance, packageOutputBinding(a, budget, changed));
            // The targets array is shared by Value copies; restore its element.
            outer_doc.object.getPtr("targets").?.array.items[0] = .{ .string = contract.target };
        }
        carrierModelSet(&outer_doc, "native_acquisition_inputs_reservation", saved_reservation);
        const expired: Budget = .{ .io = io, .deadline = std.Io.Clock.Timestamp.now(io, .awake) };
        try std.testing.expectError(error.Timeout, packageOutputBinding(a, expired, inputs));
    }
}

test "carrier copied member selection accepts actual CS2 collector shape without treating names as content hashes" {
    // Exact non-secret CS2 collector tuples. This exercises selected-index
    // semantics only; the held-file proof above supplies actual model bytes.
    const io = std.testing.io;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const budget: Budget = .{ .io = io, .deadline = std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{ .clock = .awake, .raw = .fromSeconds(30) }) };
    const target = "//tools:codex_native_sdk_carrier_seal_producer";
    const configuration = "k8-fastbuild";
    const log_name = "ea1f9312aa20d326215c378fbaa9b7fb3ab3f2d53e3e0d4c784b6193d1e32b43.evidence";
    const xml_name = "a15b7a08edaac07aafb177ff16dd333ddfae594d871eab2b79cafe382eba6af9.evidence";
    var result = try carrierModelJson(a, .{ .target = target, .configuration = configuration, .state = "observed", .files = .{
        .{ .source = "test.log", .state = "copied", .bytes = @as(u64, 1540), .file = log_name, .sha256 = "b97b5a72bb207b508ec37ea286b345164636a8b8d4906634c0c11338f5bb3318" },
        .{ .source = "test.xml", .state = "copied", .bytes = @as(u64, 1973), .file = xml_name, .sha256 = "f3dac8e579d04e01da260f9e9be250a9e9358bbb6a742c4ade1cb69036425612" },
        .{ .source = "test.outputs_manifest/MANIFEST", .state = "copied", .bytes = @as(u64, 324), .file = "a35719a85d1c1e6bd614f4f82c783a365be233b395e8c52a2a770e2c72ef2de6.evidence", .sha256 = "57def00979f8f20dfb76f19d2b21e9a35f298cf9d84b76c7688c38cd4ef78a37" },
        .{ .source = "test.outputs_manifest/ANNOTATIONS", .state = "missing", .bytes = @as(u64, 0) },
    } });
    const files = result.object.getPtr("files").?;
    const blank: Input = .{ .descriptor = -1, .sha256 = @splat(0x11), .bytes = 1 };
    const log: Input = .{ .descriptor = -1, .sha256 = try digestField(files.array.items[0], "sha256"), .bytes = 1540 };
    const xml: Input = .{ .descriptor = -1, .sha256 = try digestField(files.array.items[1], "sha256"), .bytes = 1973 };
    const members = [_]ModernMember{ .{ .name = xml_name, .input = xml }, .{ .name = log_name, .input = log } };
    const group: ModernAuthority = .{ .outer = blank, .evidence = blank, .members = &members };
    const accepted = try selectedCopiedTestFiles(a, budget, result, null, group, target, configuration, null);
    try std.testing.expectEqual(log.bytes, accepted.log.bytes);
    try std.testing.expectEqual(xml.sha256, accepted.xml.sha256);
    try std.testing.expect(!std.mem.eql(u8, log_name[0..64], &std.fmt.bytesToHex(log.sha256, .lower)));
    try std.testing.expect(!std.mem.eql(u8, xml_name[0..64], &std.fmt.bytesToHex(xml.sha256, .lower)));
    try std.testing.expectError(error.InvalidRuntimeProvenance, selectedCopiedTestFiles(a, budget, result, null, group, "//tools:codex_native_carrier_metadata_producer", configuration, null));
    try std.testing.expectError(error.InvalidRuntimeProvenance, selectedCopiedTestFiles(a, budget, result, null, group, target, "k8-other", null));
    try std.testing.expectError(error.InvalidRuntimeProvenance, selectedCopiedTestFiles(a, budget, result, null, group, target, "../k8-fastbuild", null));
    carrierModelSet(&result, "state", .{ .string = "missing-testlog-directory" });
    try std.testing.expectError(error.InvalidRuntimeProvenance, selectedCopiedTestFiles(a, budget, result, null, group, target, configuration, null));
    carrierModelSet(&result, "state", .{ .string = "observed" });
    const epoch = "/proof/ab09d29e-f91f-4e56-940c-c3cee6ab32f5";
    var member_rows = (try std.json.parseFromSlice(std.json.Value, a, "{}", .{})).value;
    try member_rows.object.put(a, log_name, try carrierModelRow(a, try std.fmt.allocPrint(a, "{s}/test-evidence/{s}", .{ epoch, log_name }), log));
    try member_rows.object.put(a, xml_name, try carrierModelRow(a, try std.fmt.allocPrint(a, "{s}/test-evidence/{s}", .{ epoch, xml_name }), xml));
    var original_rows = try carrierModelJson(a, .{ .members = null });
    carrierModelSet(&original_rows, "members", member_rows);
    _ = try selectedCopiedTestFiles(a, budget, result, original_rows, group, target, configuration, epoch);
    try std.testing.expectError(error.InvalidRuntimeProvenance, selectedCopiedTestFiles(a, budget, result, original_rows, group, target, configuration, "/proof/other-epoch"));
    try std.testing.expectError(error.InvalidRuntimeProvenance, selectedCopiedTestFiles(a, budget, result, original_rows, group, target, configuration, null));
    const original_files = files.array.items;
    files.array.items = original_files[0..2];
    _ = try selectedCopiedTestFiles(a, budget, result, null, group, target, configuration, null);
    files.array.items = original_files[0..1];
    try std.testing.expectError(error.InvalidRuntimeProvenance, selectedCopiedTestFiles(a, budget, result, null, group, target, configuration, null));
    files.array.items = original_files;
    const original_diagnostic = original_files[2];
    original_files[2] = original_files[0];
    try std.testing.expectError(error.InvalidRuntimeProvenance, selectedCopiedTestFiles(a, budget, result, null, group, target, configuration, null));
    original_files[2] = original_diagnostic;
    const original_source = try field(original_files[2], "source");
    carrierModelSet(&original_files[2], "source", .{ .string = "test.outputs/unknown" });
    try std.testing.expectError(error.InvalidRuntimeProvenance, selectedCopiedTestFiles(a, budget, result, null, group, target, configuration, null));
    carrierModelSet(&original_files[2], "source", original_source);
    const original_name = try field(original_files[0], "file");
    carrierModelSet(&original_files[0], "file", .{ .string = xml_name });
    try std.testing.expectError(error.InvalidRuntimeProvenance, selectedCopiedTestFiles(a, budget, result, null, group, target, configuration, null));
    carrierModelSet(&original_files[0], "file", original_name);
    inline for (.{ "missing", "stale", "copy-refused", "changed-during-copy", "unknown" }) |state| {
        carrierModelSet(&original_files[0], "state", .{ .string = state });
        try std.testing.expectError(error.InvalidRuntimeProvenance, selectedCopiedTestFiles(a, budget, result, null, group, target, configuration, null));
    }
    carrierModelSet(&original_files[0], "state", .{ .string = "copied" });
    inline for (.{ "stale", "over-budget", "file-budget-exhausted", "copy-refused", "changed-during-copy", "unknown" }) |state| {
        carrierModelSet(&original_files[2], "state", .{ .string = state });
        try std.testing.expectError(error.InvalidRuntimeProvenance, selectedCopiedTestFiles(a, budget, result, null, group, target, configuration, null));
    }
    carrierModelSet(&original_files[2], "state", .{ .string = "copied" });
    carrierModelSet(&original_files[3], "bytes", .{ .integer = 1 });
    try std.testing.expectError(error.InvalidRuntimeProvenance, selectedCopiedTestFiles(a, budget, result, null, group, target, configuration, null));
    carrierModelSet(&original_files[3], "bytes", .{ .integer = 0 });
    carrierModelSet(&original_files[2], "bytes", .{ .integer = 64 * 1024 * 1024 + 1 });
    try std.testing.expectError(error.RuntimeInputLimit, selectedCopiedTestFiles(a, budget, result, null, group, target, configuration, null));
    carrierModelSet(&original_files[2], "bytes", .{ .integer = 324 });
    const original_sha = try field(original_files[0], "sha256");
    carrierModelSet(&original_files[0], "sha256", .{ .string = "1111111111111111111111111111111111111111111111111111111111111111" });
    try std.testing.expectError(error.RuntimeSelectionDrift, selectedCopiedTestFiles(a, budget, result, null, group, target, configuration, null));
    carrierModelSet(&original_files[0], "sha256", original_sha);
    const duplicate_members = [_]ModernMember{ members[0], members[0] };
    var duplicate_group = group;
    duplicate_group.members = &duplicate_members;
    try std.testing.expectError(error.InvalidRuntimeProvenance, selectedCopiedTestFiles(a, budget, result, null, duplicate_group, target, configuration, null));
    _ = try selectedCopiedTestFiles(a, budget, result, null, group, target, configuration, null);
}

test "carrier preflight counts every logical receipt proof declaration and alias before descriptor work" {
    const io = std.testing.io;
    const budget: Budget = .{ .io = io, .deadline = std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{ .clock = .awake, .raw = .fromSeconds(30) }) };
    const input: Input = .{ .descriptor = -1, .bytes = 32, .sha256 = @splat(0x11) };
    const members = [_]ModernMember{
        .{ .name = "model", .input = input },
        .{ .name = "model", .input = input },
        .{ .name = "model", .input = input },
        .{ .name = "model", .input = input },
        .{ .name = "model", .input = input },
        .{ .name = "model", .input = input },
    };
    const group: ModernAuthority = .{ .outer = input, .evidence = input, .members = members[0..2] };
    var modern: ModernInputs = .{ .package_selection = input, .package_outputs = input, .package_output_root = "/package", .package_authority = group, .roles = @splat(input), .protocol_schema_files = &.{}, .native_acquisition_artifact_files = &.{}, .authority_receipts = @splat(group), .carrier_materials = .{ .receipts = @splat(input), .authority_receipts = @splat(group) } };
    modern.authority_receipts[0].members = &members;
    const inputs: Inputs = .{ .archive = input, .manifest = input, .runtime_receipt = input, .source_receipt = input, .producer_receipt = input, .registration_receipt = input, .deployment_declaration = input, .installation_directory = -1 };
    try preflightCarrierRetention(budget, inputs, modern);
    const saved = modern;
    modern.carrier_materials.?.receipts[0].bytes = maximum_metadata_bytes + 1;
    try std.testing.expectError(error.RuntimeInputLimit, preflightCarrierRetention(budget, inputs, modern));
    modern = saved;
    var large = inputs;
    large.archive.bytes = maximum_archive_bytes;
    modern.roles[@backingInt(ModernRole.codex)].bytes = maximum_backend_bytes;
    try std.testing.expectError(error.RuntimeInputLimit, preflightCarrierRetention(budget, large, modern));
    modern = saved;
    const a = std.testing.allocator;
    const too_many = try a.alloc(ModernMember, maximum_files - 60);
    defer a.free(too_many);
    @memset(too_many, .{ .name = "never-opened", .input = input });
    modern.protocol_schema_files = too_many;
    try std.testing.expectError(error.RuntimeInputLimit, preflightCarrierRetention(budget, inputs, modern));
    modern = saved;
    modern.carrier_materials.?.authority_receipts[1].members = &members;
    try std.testing.expectError(error.InvalidRuntimeProvenance, preflightCarrierRetention(budget, inputs, modern));
}

test "protected selection equality includes every added carrier role and proof member" {
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const input = try carrierModelRawInput(tmp.dir, "selected-equality", "held compact role equality model");
    defer _ = c.close(input.descriptor);
    const budget: Budget = .{ .io = io, .deadline = std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{ .clock = .awake, .raw = .fromSeconds(30) }) };
    const members = [_]ModernMember{ .{ .name = "one", .input = input }, .{ .name = "two", .input = input } };
    const group: ModernAuthority = .{ .outer = input, .evidence = input, .members = &members };
    const modern: ModernInputs = .{ .package_selection = input, .package_outputs = input, .package_output_root = "/package", .package_authority = group, .roles = @splat(input), .protocol_schema_files = &.{}, .native_acquisition_artifact_files = &.{}, .authority_receipts = @splat(group), .carrier_materials = .{ .receipts = @splat(input), .authority_receipts = @splat(group) } };
    const left: Inputs = .{ .archive = input, .manifest = input, .runtime_receipt = input, .source_receipt = input, .producer_receipt = input, .registration_receipt = input, .deployment_declaration = input, .installation_directory = -1, .modern_materials = modern };
    try equalSelectedInputs(budget, left, left);
    for (0..4) |index| {
        var right = left;
        right.modern_materials.?.carrier_materials.?.receipts[index].sha256[0] ^= 1;
        try std.testing.expectError(error.RuntimeSelectionDrift, equalSelectedInputs(budget, left, right));
    }
    for (0..2) |index| {
        var right = left;
        right.modern_materials.?.carrier_materials.?.authority_receipts[index].outer.sha256[0] ^= 1;
        try std.testing.expectError(error.RuntimeSelectionDrift, equalSelectedInputs(budget, left, right));
        right = left;
        right.modern_materials.?.carrier_materials.?.authority_receipts[index].evidence.bytes += 1;
        try std.testing.expectError(error.RuntimeSelectionDrift, equalSelectedInputs(budget, left, right));
        for (0..2) |member_index| {
            var different = members;
            different[member_index].input.sha256[0] ^= 1;
            right = left;
            right.modern_materials.?.carrier_materials.?.authority_receipts[index].members = &different;
            try std.testing.expectError(error.RuntimeSelectionDrift, equalSelectedInputs(budget, left, right));
        }
    }
    var omitted = left;
    omitted.modern_materials.?.carrier_materials = null;
    try std.testing.expectError(error.RuntimeSelectionDrift, equalSelectedInputs(budget, left, omitted));
}

test "modern retention hashes actual selected FD bytes owns duplicates and rejects metadata drift" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const payload = "actual selected raw proof";
    try tmp.dir.writeFile(io, .{ .sub_path = "proof", .data = payload });
    var fd = c.openat(tmp.dir.handle, "proof", .{ .NOFOLLOW = true, .CLOEXEC = true });
    if (fd < 0) return error.FixtureOpenFailed;
    defer if (fd >= 0) {
        _ = c.close(fd);
    };
    if (c.fchmod(fd, 0o644) != 0) return error.FixtureChmodFailed;
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &hash, .{});
    const budget: Budget = .{ .io = io, .deadline = std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{ .clock = .awake, .raw = .fromSeconds(30) }) };
    var retained: ModernRetained = .{ .allocator = a, .inputs = undefined, .root_status = undefined };
    defer {
        for (retained.witnesses.items) |row| _ = c.close(row.input.descriptor);
        retained.witnesses.deinit(a);
    }
    var bad = hash;
    bad[0] ^= 1;
    try std.testing.expectError(error.RuntimeSelectionDrift, retained.take(budget, .{ .descriptor = fd, .sha256 = bad, .bytes = payload.len }, maximum_metadata_bytes));
    try std.testing.expectEqual(@as(usize, 0), retained.witnesses.items.len);
    const copied = try retained.take(budget, .{ .descriptor = fd, .sha256 = hash, .bytes = payload.len }, maximum_metadata_bytes);
    const status = retained.witnesses.items[0].status;
    try std.testing.expect(copied.descriptor != fd);
    _ = c.close(fd);
    fd = -1;
    try std.testing.expectEqualDeep(status, try hashInput(budget, copied, maximum_metadata_bytes));
    const changed = c.openat(tmp.dir.handle, "proof", .{ .ACCMODE = .WRONLY, .NOFOLLOW = true, .CLOEXEC = true });
    if (changed < 0) return error.FixtureOpenFailed;
    defer _ = c.close(changed);
    if (c.fchmod(changed, 0o600) != 0) return error.FixtureChmodFailed;
    try std.testing.expect(!std.meta.eql(status, try metadata.statFd(copied.descriptor)));
    // The fence compares the complete original witness; same payload digest
    // does not authorize a changed mode/ctime on the retained inode.
    const changed_status = try hashInput(budget, copied, maximum_metadata_bytes);
    try std.testing.expect(!std.meta.eql(status, changed_status));
    const expired: Budget = .{ .io = io, .deadline = std.Io.Clock.Timestamp.now(io, .awake) };
    try std.testing.expectError(error.Timeout, retained.take(expired, copied, maximum_metadata_bytes));
}

test "direct materialization rejects aggregate disk payload before a staging sink" {
    const a = std.testing.allocator;
    const hash: [64]u8 = @splat('1');
    var parsed = try std.json.parseFromSlice(std.json.Value, a, "{\"runtime\":{\"launchProfile\":\"linux_nix_direct_main_v1\"},\"files\":{}}", .{});
    defer parsed.deinit();
    const rows = &parsed.value.object.getPtr("files").?.object;
    for ([_][]const u8{ launcher, backend, loader, ca_bundle }) |path| {
        const raw = try std.json.Stringify.valueAlloc(a, .{ .mode = @as(u64, if (std.mem.eql(u8, path, ca_bundle)) 0o644 else 0o755), .bytes = @as(u64, if (std.mem.eql(u8, path, backend)) maximum_payload_bytes else 1), .sha256 = hash }, .{});
        defer a.free(raw);
        // This parser-only model owns its inserted objects through a shared
        // arena, never instantiates a selection or writes a candidate payload.
        const row = try std.json.parseFromSlice(std.json.Value, parsed.arena.allocator(), raw, .{ .allocate = .alloc_always });
        try rows.put(parsed.arena.allocator(), path, row.value);
    }
    try std.testing.expectError(error.RuntimeInputLimit, directArchiveLayout(parsed.value, 64));
    const backend_row = rows.getPtr(backend).?;
    backend_row.object.getPtr("bytes").?.* = .{ .integer = maximum_payload_bytes - 3 - 64 };
    try directArchiveLayout(parsed.value, 64);
}
