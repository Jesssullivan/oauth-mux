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
    source, sdk, sdk_metadata, plan, query, compiler_selection, compiler_ledger,
    compiler_ledger_snapshot, compiler, compiler_outer, codex, config_schema,
};
pub const ModernMember = struct { name: []const u8, input: Input };
pub const ModernAuthority = struct { outer: Input, evidence: Input, members: []const ModernMember };
pub const ModernAuthorityRole = enum { source, sdk, plan, query, compiler };
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
        if(q.nix_owned) |owned_value| { var owned=owned_value; owned.deinit(); }
        _ = c.close(retained.inputs.installation_directory);
        q.observed.deinit();
        const storage = q.metadata_storage; const bounded = q.metadata_allocator;
        allocator.destroy(q); allocator.destroy(bounded); allocator.free(storage);
    }
    pub fn recheck(self: *const ValidatedSelection, io: std.Io, context: ActorContext) !void {
        const q: *const Qualified = @ptrCast(@alignCast(self));
        if (!std.meta.eql(q.deadline, context.deadline)) return error.RuntimeSelectionDrift;
        try q.observed.recheck(io, context);
        if(q.modern) |modern| {
            try modern.recheck(.{.io=io,.deadline=context.deadline});
            try modern.recheckIdentity(.{.io=io,.deadline=context.deadline});
            try recheckDirectManifest(q,.{.io=io,.deadline=context.deadline},true);
        }
        if(q.nix_owned) |owned| try nix.recheck(io,q.metadata_allocator.allocator(),context.deadline,owned.record);
    }
    pub fn recheckIdentity(self: *const ValidatedSelection, io: std.Io, context: ActorContext) !void {
        const q: *const Qualified = @ptrCast(@alignCast(self));
        if (!std.meta.eql(q.deadline,context.deadline)) return error.RuntimeSelectionDrift;
        try q.observed.recheckIdentity(io,context);
        if (q.modern) |modern| {
            try modern.recheckIdentity(.{.io=io,.deadline=context.deadline});
            try recheckDirectManifest(q,.{.io=io,.deadline=context.deadline},false);
        }
        if(q.nix_owned) |owned| try nix_artifact.recheckIdentity(.{.io=io,.deadline=context.deadline},q.metadata_allocator.allocator(),owned.record);
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
    pub fn recheckIdentity(self: *const Observation,io: std.Io,context: ActorContext) !void {
        const retained: *const Retained=@ptrCast(@alignCast(self));
        const budget: Budget=.{.io=io,.deadline=context.deadline}; try budget.check();
        const custody=context.options.native_custody orelse return error.NativeCustodyPending;
        try custody.validate();
        if(custody.state!=.retain_ready and custody.state!=.install_ready) return error.NativeCustodyPending;
        const transaction=custody.registry_transaction orelse return error.NativeCustodyPending;
        const capability=custody.registry_capability_digest orelse return error.NativeCustodyPending;
        var actual_capability: [32]u8=undefined;
        std.crypto.hash.sha2.Sha256.hash(&context.options.capability,&actual_capability,.{});
        if(!std.meta.eql(retained.context_digest,try contextDigest(context)) or
            !std.meta.eql(retained.registry.transaction,transaction) or
            !std.meta.eql(retained.registry.capability_digest,capability) or
            !std.meta.eql(capability,actual_capability)) return error.RuntimeSelectionDrift;
        if(!std.meta.eql(retained.directory,try metadata.statFd(retained.inputs.installation_directory))) return error.RuntimeSelectionDrift;
        for(inputArray(retained.inputs),retained.statuses) |input,status| {
            try budget.check();
            if(!std.meta.eql(status,try metadata.statFd(input.descriptor))) return error.RuntimeSelectionDrift;
        }
        for(retained.files) |file| {
            const descriptor=try openMember(budget,retained.inputs.installation_directory,retained.directory,file.path);
            defer _=c.close(descriptor);
            if(!std.meta.eql(file.status,try metadata.statFd(descriptor))) return error.RuntimeSelectionDrift;
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
    if(inputs.manifest.bytes > maximum_direct_manifest_bytes) return error.RuntimeInputLimit;
    const storage = try allocator.alloc(u8,4*1024*1024); defer allocator.free(storage);
    var bounded = std.heap.FixedBufferAllocator.init(storage); const a = bounded.allocator();
    const raw = try readSelectedInput(io,a,context.deadline,inputs.manifest,maximum_direct_manifest_bytes);
    const manifest = try std.json.parseFromSlice(std.json.Value,a,raw,.{ .duplicate_field_behavior=.@"error",.max_value_len=4096 }); defer manifest.deinit();
    const budget: verifier.Budget = .{ .io=io,.deadline=context.deadline };
    try directArchiveLayout(manifest.value,inputs.manifest.bytes);
    try verifier.materializeSelectedArchive(budget,.{ .descriptor=inputs.archive.descriptor,.sha256=inputs.archive.sha256,.bytes=inputs.archive.bytes },manifest.value,inputs.manifest.sha256,inputs.manifest.bytes,staging_fd,ledger);
}

fn directArchiveLayout(manifest: std.json.Value,manifest_bytes: u64) !void {
    if(manifest_bytes==0 or manifest_bytes>maximum_direct_manifest_bytes) return error.RuntimeInputLimit;
    const files = try objectField(manifest,"files");
    if(files.object.count()!=4) return error.InvalidRuntimeManifest;
    var total: u64=manifest_bytes;
    for ([_][]const u8{launcher,backend,loader,ca_bundle}) |path| {
        const member = try objectField(files,path);
        const mode = try positiveInteger(member,"mode");
        const bytes = try positiveInteger(member,"bytes");
        if(mode != @as(u64,if(std.mem.eql(u8,path,ca_bundle)) 0o644 else 0o755) or bytes > try pathLimit(path)) return error.InvalidRuntimeManifest;
        _ = try digestField(member,"sha256");
        if(bytes>maximum_payload_bytes-total) return error.RuntimeInputLimit;
        total+=bytes;
    }
    const runtime = try objectField(manifest,"runtime");
    if(!std.mem.eql(u8,try stringField(runtime,"launchProfile"),"linux_nix_direct_main_v1")) return error.InvalidRuntimeManifest;
}

pub const maximum_qualification_metadata_allocation = 64 * 1024 * 1024;
pub fn acquire(io: std.Io, allocator: std.mem.Allocator, context: ActorContext, inputs: Inputs) !*ValidatedSelection {
    const budget: Budget = .{ .io = io, .deadline = context.deadline };
    try budget.check();
    const storage = try allocator.alloc(u8,maximum_qualification_metadata_allocation);
    errdefer allocator.free(storage);
    const bounded = try allocator.create(std.heap.FixedBufferAllocator);
    errdefer allocator.destroy(bounded);
    bounded.* = std.heap.FixedBufferAllocator.init(storage);
    const a = bounded.allocator();
    if(inputs.modern_materials!=null) return acquireModern(io,allocator,context,inputs,storage,bounded);
    var selected = inputArray(inputs);
    var opened: usize = 0;
    errdefer for (selected[0..opened]) |input| { _ = c.close(input.descriptor); };
    for (&selected) |*input| {
        const fd = c.fcntl(input.descriptor, c.F.DUPFD_CLOEXEC, @as(c_int, 0));
        if (fd < 0) return error.UnsafeRuntimeInput;
        input.descriptor = fd; opened += 1;
    }
    const directory = c.openat(inputs.installation_directory, ".", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (directory < 0) return error.UnsafeRuntimeInput;
    errdefer _ = c.close(directory);
    if (!std.meta.eql(try metadata.statFd(inputs.installation_directory), try metadata.statFd(directory))) return error.RuntimeSelectionDrift;
    const owned_inputs: Inputs = .{ .archive = selected[0], .manifest = selected[1], .runtime_receipt = selected[2], .source_receipt = selected[3], .producer_receipt = selected[4], .installation_directory = directory };
    const observed = try observe(io, a, context, owned_inputs);
    errdefer observed.deinit();
    const retained: *Retained = @ptrCast(@alignCast(observed));
    const manifest_bytes = try readMetadata(a, budget, selected[1], retained.statuses[1]); defer a.free(manifest_bytes);
    const receipt_bytes = try readMetadata(a, budget, selected[2], retained.statuses[2]); defer a.free(receipt_bytes);
    const source_bytes = try readMetadata(a, budget, selected[3], retained.statuses[3]); defer a.free(source_bytes);
    const producer_bytes = try readMetadata(a, budget, selected[4], retained.statuses[4]); defer a.free(producer_bytes);
    const manifest = try parse(a, manifest_bytes); defer manifest.deinit();
    const receipt = try parse(a, receipt_bytes); defer receipt.deinit();
    const source = try parse(a, source_bytes); defer source.deinit();
    const producer = try parse(a, producer_bytes); defer producer.deinit();
    const proof_budget: verifier.Budget = .{ .io = io, .deadline = context.deadline };
    try verifier.provenance(a, proof_budget, manifest.value, receipt.value, source.value, producer.value, selected[3].sha256, selected[4].sha256);
    // Stream selected compressed bytes through fixed windows; disk size limits
    // do not become resident allocations. Offsets remain caller-independent.
    try verifier.archiveSelected(proof_budget, selected[0], manifest.value, selected[1].sha256, selected[1].bytes);
    const dependencies = try field(try objectField(manifest.value, "runtime"), "dependencies");
    var roles: [3]setup.RuntimeRole = undefined;
    for (retained.files) |file| {
        if (std.mem.eql(u8, file.path, launcher)) {
            var expected: [32]u8 = undefined; std.crypto.hash.sha2.Sha256.hash(verifier.launcher_bytes, &expected, .{});
            if (file.bytes != verifier.launcher_bytes.len or !std.meta.eql(file.sha256, expected)) return error.InvalidRuntimeLauncher;
            roles[0] = .{ .sha256 = file.sha256, .bytes = file.bytes };
        } else {
            const fd = try openMember(budget, directory, retained.directory, file.path); defer _ = c.close(fd);
            if (std.mem.eql(u8, file.path, ca_bundle)) {
                const value = try readMetadata(a, budget, .{ .descriptor = fd, .sha256 = file.sha256, .bytes = file.bytes }, file.status); defer a.free(value);
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
        .schema_version = 1, .channel = if (context.selection == .dev) .development else .release,
        .target = .x86_64_linux, .launch_profile = .linux_explicit_bundled_loader_v1,
        .upstream_commit = verifier.upstream_commit[0..40].*, .artifact_selection_sha256 = artifactDigest(selected),
        .archive_sha256 = selected[0].sha256, .manifest_sha256 = selected[1].sha256,
        .runtime_receipt_sha256 = selected[2].sha256, .source_receipt_sha256 = selected[3].sha256, .producer_receipt_sha256 = selected[4].sha256,
        .installation = .{ .transaction = retained.registry.transaction, .adapter_epoch = custody.adapter_epoch,
            .capability_digest = retained.registry.capability_digest, .directory_device = retained.directory.dev,
            .directory_inode = retained.directory.ino, .uid = retained.directory.uid, .gid = retained.directory.gid },
        .launcher = roles[0], .backend = roles[1], .loader = roles[2],
    };
    const q = try allocator.create(Qualified);
    q.* = .{ .observed = observed, .record = record, .deadline = context.deadline, .owner_allocator=allocator,.metadata_storage=storage,.metadata_allocator=bounded };
    return @ptrCast(q);
}
fn artifactDigest(selected: [5]Input) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("omux-qualified-runtime-artifact-v1\x00");
    for (selected) |input| { hash.update(&input.sha256); var bytes: [8]u8 = undefined; std.mem.writeInt(u64, &bytes, input.bytes, .big); hash.update(&bytes); }
    var value: [32]u8 = undefined; hash.final(&value); return value;
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
    if(inputs.modern_materials!=null) {
        try directArchiveLayout(manifest.value,inputs.manifest.bytes);
        try modernMaterial(allocator,budget,inputs,manifest.value,receipt.value,source.value);
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
        if(self.declaration_reader) |reader| reader.deinit();
        for (self.witnesses.items) |row| _ = c.close(row.input.descriptor);
        if (self.inputs.deployment_root) |root| _ = c.close(root.descriptor);
        // All names and arrays are in the qualification-owned bounded arena.
    }
    pub fn recheckIdentity(self: *const ModernRetained,budget: Budget) !void {
        try budget.check();
        const root=self.inputs.deployment_root orelse return error.InvalidDeploymentSelection;
        const named=try nix.openSelectedDirectory(budget.io,self.allocator,budget.deadline,root.path);
        defer _=c.close(named);
        if(!std.meta.eql(self.root_status,try metadata.statFd(root.descriptor)) or
            !std.meta.eql(self.root_status,try metadata.statFd(named))) return error.RuntimeSelectionDrift;
        for(self.witnesses.items) |row| {
            try budget.check(); if(!std.meta.eql(row.status,try metadata.statFd(row.input.descriptor))) return error.RuntimeSelectionDrift;
        }
        const reader=self.declaration_reader orelse return error.InvalidDeploymentSelection;
        try reader.recheckIdentity(budget.io);
        // Engine independently fences its original reader and publication name.
    }
    pub fn recheck(self: *const ModernRetained, budget: Budget) !void {
        try budget.check();
        const root = self.inputs.deployment_root orelse return error.InvalidDeploymentSelection;
        const named = try nix.openSelectedDirectory(budget.io,self.allocator,budget.deadline,root.path);
        defer _ = c.close(named);
        if (!std.meta.eql(self.root_status,try metadata.statFd(root.descriptor)) or
            !std.meta.eql(self.root_status,try metadata.statFd(named))) return error.RuntimeSelectionDrift;
        for (self.witnesses.items) |row| {
            if (!std.meta.eql(row.status,try hashInput(budget,row.input,row.limit))) return error.RuntimeSelectionDrift;
        }
        try budget.check();
    }
    fn take(self: *ModernRetained,budget: Budget,input: Input,limit: u64) !Input {
        try budget.check();
        if (input.bytes==0 or input.bytes>maximum_payload_bytes-self.retained_bytes) return error.RuntimeInputLimit;
        const before = try hashInput(budget,input,limit);
        const descriptor = c.fcntl(input.descriptor,c.F.DUPFD_CLOEXEC,@as(c_int,0));
        if (descriptor < 0) return error.UnsafeRuntimeInput;
        errdefer _ = c.close(descriptor);
        const copied: Input = .{.descriptor=descriptor,.sha256=input.sha256,.bytes=input.bytes};
        if (!std.meta.eql(before,try hashInput(budget,copied,limit))) return error.RuntimeSelectionDrift;
        try self.witnesses.append(self.allocator,.{.input=copied,.status=before,.limit=limit});
        self.retained_bytes+=input.bytes;
        return copied;
    }
    fn members(self: *ModernRetained,budget: Budget,rows: []const ModernMember,maximum: usize) ![]const ModernMember {
        if (rows.len > maximum) return error.RuntimeInputLimit;
        const owned = try self.allocator.alloc(ModernMember,rows.len);
        for (rows,owned,0..) |row,*copy,index| {
            try budget.check();
            if (row.name.len==0 or row.name.len>4096 or
                (index>0 and std.mem.order(u8,rows[index-1].name,row.name)!=.lt)) return error.InvalidRuntimeProvenance;
            copy.*=.{.name=try self.allocator.dupe(u8,row.name),.input=try self.take(budget,row.input,maximum_metadata_bytes)};
        }
        return owned;
    }
    fn authority(self: *ModernRetained,budget: Budget,value: ModernAuthority,count: usize) !ModernAuthority {
        if (value.members.len!=count) return error.InvalidRuntimeProvenance;
        return .{.outer=try self.take(budget,value.outer,maximum_metadata_bytes),
            .evidence=try self.take(budget,value.evidence,maximum_metadata_bytes),
            .members=try self.members(budget,value.members,count)};
    }
};
fn retainModern(a: std.mem.Allocator,budget: Budget,inputs: Inputs) !*ModernRetained {
    try budget.check();
    const material=inputs.modern_materials orelse return error.InvalidRuntimeProvenance;
    const root=inputs.deployment_root orelse return error.InvalidDeploymentSelection;
    const declaration=inputs.deployment_declaration orelse return error.InvalidDeploymentSelection;
    const registration=inputs.registration_receipt orelse return error.InvalidNixRuntimeProvenance;
    if (material.protocol_schema_files.len<2 or material.native_acquisition_artifact_files.len!=6 or
        material.protocol_schema_files.len+material.native_acquisition_artifact_files.len+48>maximum_files)
        return error.RuntimeInputLimit;
    const status=try metadata.statFd(root.descriptor);
    if (status.mode & c.S.IFMT!=c.S.IFDIR or status.uid!=0 or status.mode & 0o7222!=0)
        return error.InvalidDeploymentSelection;
    const descriptor=c.openat(root.descriptor,".",.{.DIRECTORY=true,.NOFOLLOW=true,.CLOEXEC=true});
    if (descriptor<0) return error.InvalidDeploymentSelection;
    errdefer _=c.close(descriptor);
    if (!std.meta.eql(status,try metadata.statFd(descriptor))) return error.RuntimeSelectionDrift;
    const retained=try a.create(ModernRetained);
    retained.*=.{.allocator=a,.inputs=inputs,.root_status=status};
    retained.inputs.deployment_root=.{.path=try a.dupe(u8,root.path),.descriptor=descriptor};
    errdefer for (retained.witnesses.items) |row| { _=c.close(row.input.descriptor); };
    retained.inputs.archive=try retained.take(budget,inputs.archive,maximum_archive_bytes);
    retained.inputs.manifest=try retained.take(budget,inputs.manifest,maximum_direct_manifest_bytes);
    retained.inputs.runtime_receipt=try retained.take(budget,inputs.runtime_receipt,maximum_metadata_bytes);
    retained.inputs.source_receipt=try retained.take(budget,inputs.source_receipt,maximum_metadata_bytes);
    retained.inputs.producer_receipt=try retained.take(budget,inputs.producer_receipt,maximum_metadata_bytes);
    retained.inputs.registration_receipt=try retained.take(budget,registration,maximum_metadata_bytes);
    retained.inputs.deployment_declaration=try retained.take(budget,declaration,maximum_deployment_declaration_bytes);
    var roles: [12]Input=undefined;
    for (material.roles,&roles,0..) |row,*copy,index| copy.*=try retained.take(budget,row,
        if (index==@intFromEnum(ModernRole.codex)) maximum_backend_bytes else maximum_metadata_bytes);
    var authorities: [5]ModernAuthority=undefined;
    for (material.authority_receipts,&authorities,0..) |group,*copy,index| copy.*=
        try retained.authority(budget,group,if(index==0) 6 else 2);
    retained.inputs.modern_materials=.{
        .package_selection=try retained.take(budget,material.package_selection,maximum_metadata_bytes),
        .package_outputs=try retained.take(budget,material.package_outputs,maximum_deployment_declaration_bytes),
        .package_output_root=try a.dupe(u8,material.package_output_root),
        .package_authority=try retained.authority(budget,material.package_authority,2),.roles=roles,
        .protocol_schema_files=try retained.members(budget,material.protocol_schema_files,maximum_files),
        .native_acquisition_artifact_files=try retained.members(budget,material.native_acquisition_artifact_files,6),
        .authority_receipts=authorities,
    };
    try retained.recheck(budget);
    const owned_reader=try deployment.load(budget.io,a,.{.path=retained.inputs.deployment_root.?.path,
        .descriptor=descriptor},budget.deadline);
    errdefer owned_reader.deinit();
    try equalSelectedInputs(budget,retained.inputs,owned_reader.inputs());
    retained.declaration_reader=owned_reader;
    return retained;
}

fn exactObject(value: std.json.Value,names: []const []const u8) !void {
    if (value!=.object or value.object.count()!=names.len) return error.InvalidRuntimeProvenance;
    for (names) |name| if (!value.object.contains(name)) return error.InvalidRuntimeProvenance;
}
fn expectText(value: std.json.Value,key: []const u8,expected: []const u8) !void {
    if (!std.mem.eql(u8,try stringField(value,key),expected)) return error.InvalidRuntimeProvenance;
}
fn expectBool(value: std.json.Value,key: []const u8,expected: bool) !void {
    const child=try field(value,key);
    if (child!=.bool or child.bool!=expected) return error.InvalidRuntimeProvenance;
}
fn integer(value: std.json.Value,key: []const u8) !u64 {
    const child=try field(value,key);
    if (child!=.integer or child.integer<0) return error.InvalidRuntimeProvenance;
    return @intCast(child.integer);
}
fn inputRow(value: std.json.Value,input: Input) !void {
    if (try positiveInteger(value,"bytes")!=input.bytes or
        !std.meta.eql(try digestField(value,"sha256"),input.sha256)) return error.RuntimeSelectionDrift;
}
fn loadSelectedJson(a: std.mem.Allocator,budget: Budget,input: Input,maximum: u64) !std.json.Parsed(std.json.Value) {
    const bytes=try readSelectedInput(budget.io,a,budget.deadline,input,maximum);
    defer a.free(bytes);
    return std.json.parseFromSlice(std.json.Value,a,bytes,.{.duplicate_field_behavior=.@"error",
        .allocate=.alloc_always,.max_value_len=4096});
}
fn canonicalAbsolute(value: []const u8) !void {
    if (value.len<2 or value.len>4096 or value[0]!='/') return error.InvalidRuntimeProvenance;
    var parts=std.mem.splitScalar(u8,value[1..],'/');
    while(parts.next()) |part| {
        if(part.len==0 or std.mem.eql(u8,part,".") or std.mem.eql(u8,part,"..")) return error.InvalidRuntimeProvenance;
        for(part) |byte| if(byte<32 or byte>=127 or byte=='\\') return error.InvalidRuntimeProvenance;
    }
}
/// Bind the five exact selected outputs to the independently selected actual
/// package action's copied stdout. The producer never creates its own guardian.
fn packageOutputBinding(a: std.mem.Allocator,budget: Budget,inputs: Inputs) !void {
    const modern=inputs.modern_materials orelse return error.InvalidRuntimeProvenance;
    if(!std.meta.eql(inputs.producer_receipt.sha256,modern.package_authority.outer.sha256) or
        inputs.producer_receipt.bytes!=modern.package_authority.outer.bytes) return error.RuntimeSelectionDrift;
    try canonicalAbsolute(modern.package_output_root);
    const output=try loadSelectedJson(a,budget,modern.package_outputs,maximum_deployment_declaration_bytes);
    defer output.deinit();
    try exactObject(output.value,&.{"schema_version","kind","purpose","acquisitionContract","files"});
    if(try integer(output.value,"schema_version")!=1) return error.InvalidRuntimeProvenance;
    try expectText(output.value,"kind","omux-native-acquisition-package-output-v1");
    try expectText(output.value,"purpose","evaluation-only");
    try expectText(output.value,"acquisitionContract","unsupported");
    const files=try objectField(output.value,"files");
    const names=[_] []const u8{"fresh-native-runtime.tar.gz","runtime-manifest.json","runtime-receipt.json","registration-receipt.json","package-selection.json"};
    try exactObject(files,&names);
    const selected=[_]Input{inputs.archive,inputs.manifest,inputs.runtime_receipt,
        inputs.registration_receipt orelse return error.InvalidNixRuntimeProvenance,modern.package_selection};
    for(names,selected) |name,input| {
        try budget.check(); const row=try objectField(files,name);
        try exactObject(row,&.{"sha256","bytes"}); try inputRow(row,input);
    }
    const outer=try loadSelectedJson(a,budget,modern.package_authority.outer,maximum_metadata_bytes);
    defer outer.deinit();
    const target="//tools:codex_native_acquisition_runtime_package";
    const package_source=try stringField(outer.value,"source_commit");
    if(package_source.len!=40 or std.mem.allEqual(u8,package_source,'0')) return error.InvalidRuntimeProvenance;
    for(package_source) |byte| if(!std.ascii.isDigit(byte) and !(byte>='a' and byte<='f')) return error.InvalidRuntimeProvenance;
    _=try digestField(outer.value,"graph_sha256");
    try reservedProducerPolicy(a,outer.value,"native-acquisition-package-reserved","native_acquisition_inputs_reservation");
    try expectText(outer.value,"manager","system"); try expectText(outer.value,"verb","test");
    if(try integer(outer.value,"exit")!=0 or try integer(outer.value,"workload_exit")!=0 or
        try field(outer.value,"controller_failure")!=.null) return error.InvalidRuntimeProvenance;
    try expectBool(outer.value,"descendants_empty",true);
    try expectText(try objectField(outer.value,"cleanup"),"state","empty");
    try expectText(outer.value,"source_dirty","false");
    try expectBool(outer.value,"cache_reuse_requested",false);
    if(try field(outer.value,"cache_policy")!=.null or try field(outer.value,"cache_key")!=.null) return error.InvalidRuntimeProvenance;
    const targets=try field(outer.value,"targets");
    if(targets!=.array or targets.array.items.len!=1 or targets.array.items[0]!=.string or
        !std.mem.eql(u8,targets.array.items[0].string,target)) return error.InvalidRuntimeProvenance;
    const id=try stringField(outer.value,"id");
    if(id.len!=36) return error.InvalidRuntimeProvenance;
    for(id,0..) |byte,index| {
        if(index==8 or index==13 or index==18 or index==23) {
            if(byte!='-') return error.InvalidRuntimeProvenance;
        } else if(!std.ascii.isDigit(byte) and !(byte>='a' and byte<='f')) return error.InvalidRuntimeProvenance;
    }
    const unit=try std.fmt.allocPrint(a,"omux-execution-{s}.service",.{id}); defer a.free(unit);
    try expectText(outer.value,"unit",unit);
    const base=try stringField(outer.value,"output_base"); try canonicalAbsolute(base);
    const prefix=try std.fmt.allocPrint(a,"{s}/execroot/_main/bazel-out/",.{base}); defer a.free(prefix);
    const suffix="/testlogs/tools/codex_native_acquisition_runtime_package/test.outputs/fresh-native-runtime";
    if(!std.mem.startsWith(u8,modern.package_output_root,prefix) or
        !std.mem.endsWith(u8,modern.package_output_root,suffix) or modern.package_output_root.len<=prefix.len+suffix.len)
        return error.InvalidRuntimeProvenance;
    const configuration=modern.package_output_root[prefix.len..modern.package_output_root.len-suffix.len];
    for(configuration) |byte| if(!std.ascii.isAlphanumeric(byte) and byte!='_' and byte!='-' and byte!='.') return error.InvalidRuntimeProvenance;
    const evidence_row=try objectField(outer.value,"test_evidence"); try expectText(evidence_row,"state","preserved");
    if(!std.meta.eql(try digestField(evidence_row,"sha256"),modern.package_authority.evidence.sha256)) return error.RuntimeSelectionDrift;
    const evidence=try loadSelectedJson(a,budget,modern.package_authority.evidence,maximum_metadata_bytes);
    defer evidence.deinit();
    if(try integer(evidence.value,"schema")!=1 or try integer(evidence.value,"bazel_exit")!=0 or
        try integer(evidence.value,"epoch_start_ns")!=try integer(outer.value,"epoch_start_ns")) return error.InvalidRuntimeProvenance;
    const observed_targets=try field(evidence.value,"targets");
    if(observed_targets!=.array or observed_targets.array.items.len!=1 or observed_targets.array.items[0]!=.string or
        !std.mem.eql(u8,observed_targets.array.items[0].string,target)) return error.InvalidRuntimeProvenance;
    const results=try field(evidence.value,"results");
    if(results!=.array or results.array.items.len!=1) return error.InvalidRuntimeProvenance;
    const result=results.array.items[0]; try expectText(result,"target",target); try expectText(result,"state","observed");
    const members=try field(result,"files"); if(members!=.array or members.array.items.len!=2 or modern.package_authority.members.len!=2) return error.InvalidRuntimeProvenance;
    var log: ?Input=null; var xml: ?Input=null;
    for(members.array.items) |row| {
        try budget.check(); try expectText(row,"state","copied");
        const name=try stringField(row,"file");
        var selected_member: ?Input=null;
        for(modern.package_authority.members) |member| if(std.mem.eql(u8,member.name,name)) {
            if(selected_member!=null) return error.InvalidRuntimeProvenance; selected_member=member.input;
        };
        const chosen=selected_member orelse return error.InvalidRuntimeProvenance;
        try inputRow(row,chosen);
        const source=try stringField(row,"source");
        if(std.mem.eql(u8,source,"test.log")) { if(log!=null) return error.InvalidRuntimeProvenance; log=chosen; }
        else if(std.mem.eql(u8,source,"test.xml")) { if(xml!=null) return error.InvalidRuntimeProvenance; xml=chosen; }
        else return error.InvalidRuntimeProvenance;
    }
    if(xml==null) return error.InvalidRuntimeProvenance;
    const raw_log=try readSelectedInput(budget.io,a,budget.deadline,log orelse return error.InvalidRuntimeProvenance,maximum_metadata_bytes);
    defer a.free(raw_log);
    try validateOutputMarker(a,budget,raw_log,modern.package_outputs.sha256);
}

fn decimal(value: []const u8,maximum_digits: usize) !u64 {
    if(value.len==0 or value.len>maximum_digits) return error.InvalidRuntimeProvenance;
    for(value) |byte| if(!std.ascii.isDigit(byte)) return error.InvalidRuntimeProvenance;
    return std.fmt.parseInt(u64,value,10) catch error.InvalidRuntimeProvenance;
}
fn durationMicros(value: []const u8) !u64 {
    if(value.len==0 or value.len>64) return error.InvalidRuntimeProvenance;
    var index: usize=0; var total: u64=0;
    while(index<value.len) {
        if(value[index]==' ') { index+=1; continue; }
        const start=index; while(index<value.len and std.ascii.isDigit(value[index])) : (index+=1) {}
        const whole=try decimal(value[start..index],12);
        var fraction: u64=0; var denominator: u64=1;
        if(index<value.len and value[index]=='.') {
            index+=1; const fraction_start=index;
            while(index<value.len and std.ascii.isDigit(value[index])) : (index+=1) {}
            const digits=value[fraction_start..index]; fraction=try decimal(digits,6);
            for(digits) |_| denominator=try std.math.mul(u64,denominator,10);
        }
        var scale: u64=0;
        inline for(.{.{"min",@as(u64,60000000)},.{"us",@as(u64,1)},.{"ms",@as(u64,1000)},.{"s",@as(u64,1000000)},.{"h",@as(u64,3600000000)}}) |unit| {
            if(scale==0 and std.mem.startsWith(u8,value[index..],unit[0])) { scale=unit[1]; index+=unit[0].len; }
        }
        if(scale==0) return error.InvalidRuntimeProvenance;
        total=try std.math.add(u64,total,try std.math.mul(u64,whole,scale));
        total=try std.math.add(u64,total,(try std.math.mul(u64,fraction,scale))/denominator);
    }
    if(total==0) return error.InvalidRuntimeProvenance;
    return total;
}
fn reservedProducerPolicy(a: std.mem.Allocator,value: std.json.Value,profile: []const u8,key: []const u8) !void {
    try expectText(value,"profile",profile);
    const observed=try objectField(value,"observed_properties");
    inline for(.{.{"MemoryMax","4026531840"},.{"MemorySwapMax","0"},.{"TasksMax","480"},
        .{"PrivateNetwork","yes"},.{"KillMode","control-group"},.{"SendSIGKILL","yes"},
        .{"OOMPolicy","kill"},.{"RemainAfterExit","yes"}}) |item| try expectText(observed,item[0],item[1]);
    if(try durationMicros(try stringField(observed,"CPUQuotaPerSecUSec"))!=1900000 or
        try durationMicros(try stringField(observed,"RuntimeMaxUSec"))>1200000000) return error.InvalidRuntimeProvenance;
    const reservation=try objectField(value,key);
    try exactObject(reservation,&.{"scope","profile","original_entry_monotonic_ns","original_deadline_monotonic_ns",
        "verified_after_cleanup","resident","input_predicates_required","query_tools_qualified","metadata_qualified",
        "sdk_qualified","schema_qualified","compiler_qualified","native_runtime_qualified","continuity_qualified",
        "custody_qualified","health_qualified","credential_acquisition","native_source_finalized",
        "native_support","provider_identity_proved","live_handoff_proven","context_rotation","daemon_context_acquisition"});
    const scope=try std.fmt.allocPrint(a,"fixed-{s}-v1",.{profile}); defer a.free(scope);
    try expectText(reservation,"scope",scope); try expectText(reservation,"profile",profile);
    const entry=try integer(reservation,"original_entry_monotonic_ns");
    const deadline=try integer(reservation,"original_deadline_monotonic_ns");
    if(deadline<=entry or deadline-entry!=1200000000000) return error.InvalidRuntimeProvenance;
    try expectBool(reservation,"verified_after_cleanup",true); try expectBool(reservation,"input_predicates_required",true);
    inline for(.{"query_tools_qualified","metadata_qualified","sdk_qualified","schema_qualified","compiler_qualified",
        "native_runtime_qualified","continuity_qualified","custody_qualified","health_qualified",
        "credential_acquisition","native_source_finalized","native_support","provider_identity_proved",
        "live_handoff_proven","context_rotation","daemon_context_acquisition"}) |name| try expectBool(reservation,name,false);
    const resident=try objectField(reservation,"resident");
    try exactObject(resident,&.{"scope","kernel_bounds","observations","initial_direct_processes_retained",
        "initial_direct_process_count","outer_pid_namespace_matched","hierarchical_caps","descendant_process_inventory",
        "installation_qualified","health_observed","custody_observed","resident_signalled","whole_host_reservation"});
    try expectText(resident,"scope","sampled-fixed-default-cgroup-kernel-reservation-v1");
    const observations=try integer(resident,"observations"); const processes=try integer(resident,"initial_direct_process_count");
    if(observations==0 or observations>65535 or processes==0 or processes>32) return error.InvalidRuntimeProvenance;
    inline for(.{"initial_direct_processes_retained","outer_pid_namespace_matched","hierarchical_caps"}) |name| try expectBool(resident,name,true);
    inline for(.{"descendant_process_inventory","installation_qualified","health_observed","custody_observed","resident_signalled","whole_host_reservation"}) |name| try expectBool(resident,name,false);
    const bounds=try objectField(resident,"kernel_bounds"); try exactObject(bounds,&.{"memory.max","memory.swap.max","pids.max","cpu.max"});
    try expectText(bounds,"memory.swap.max","0");
    const memory=try decimal(try stringField(bounds,"memory.max"),10);
    const tasks=try decimal(try stringField(bounds,"pids.max"),2);
    if(memory==0 or memory>268435456 or tasks==0 or tasks>32 or processes>tasks) return error.InvalidRuntimeProvenance;
    var cpu=std.mem.tokenizeScalar(u8,try stringField(bounds,"cpu.max"),' ');
    const quota=try decimal(cpu.next() orelse return error.InvalidRuntimeProvenance,9);
    const period=try decimal(cpu.next() orelse return error.InvalidRuntimeProvenance,9);
    if(cpu.next()!=null or quota==0 or period==0 or try std.math.mul(u64,quota,10)>period) return error.InvalidRuntimeProvenance;
}

fn equalInput(budget: Budget,left: Input,right: Input) !void {
    try budget.check();
    if(left.bytes!=right.bytes or !std.meta.eql(left.sha256,right.sha256) or
        !std.meta.eql(try metadata.statFd(left.descriptor),try metadata.statFd(right.descriptor))) return error.RuntimeSelectionDrift;
}
fn equalMembers(budget: Budget,left: []const ModernMember,right: []const ModernMember) !void {
    if(left.len!=right.len) return error.RuntimeSelectionDrift;
    for(left,right) |x,y| { if(!std.mem.eql(u8,x.name,y.name)) return error.RuntimeSelectionDrift; try equalInput(budget,x.input,y.input); }
}
fn equalAuthority(budget: Budget,left: ModernAuthority,right: ModernAuthority) !void {
    try equalInput(budget,left.outer,right.outer); try equalInput(budget,left.evidence,right.evidence);
    try equalMembers(budget,left.members,right.members);
}
fn equalSelectedInputs(budget: Budget,left: Inputs,right: Inputs) !void {
    for(inputArray(left),inputArray(right)) |x,y| try equalInput(budget,x,y);
    try equalInput(budget,left.registration_receipt orelse return error.InvalidDeploymentSelection,
        right.registration_receipt orelse return error.InvalidDeploymentSelection);
    try equalInput(budget,left.deployment_declaration orelse return error.InvalidDeploymentSelection,
        right.deployment_declaration orelse return error.InvalidDeploymentSelection);
    const x=left.modern_materials orelse return error.InvalidDeploymentSelection;
    const y=right.modern_materials orelse return error.InvalidDeploymentSelection;
    try equalInput(budget,x.package_selection,y.package_selection); try equalInput(budget,x.package_outputs,y.package_outputs);
    if(!std.mem.eql(u8,x.package_output_root,y.package_output_root)) return error.RuntimeSelectionDrift;
    try equalAuthority(budget,x.package_authority,y.package_authority);
    for(x.roles,y.roles) |one,two| try equalInput(budget,one,two);
    for(x.authority_receipts,y.authority_receipts) |one,two| try equalAuthority(budget,one,two);
    try equalMembers(budget,x.protocol_schema_files,y.protocol_schema_files);
    try equalMembers(budget,x.native_acquisition_artifact_files,y.native_acquisition_artifact_files);
}

fn jsonEqual(budget: Budget,left: std.json.Value,right: std.json.Value,depth: usize) !bool {
    try budget.check(); if(depth>64) return error.RuntimeInputLimit;
    if(std.meta.activeTag(left)!=std.meta.activeTag(right)) return false;
    return switch(left) {
        .null=>true,.bool=>left.bool==right.bool,.integer=>left.integer==right.integer,
        .float=>left.float==right.float,.number_string=>std.mem.eql(u8,left.number_string,right.number_string),
        .string=>std.mem.eql(u8,left.string,right.string),
        .array=>blk: {
            if(left.array.items.len!=right.array.items.len) break :blk false;
            for(left.array.items,right.array.items) |x,y| if(!try jsonEqual(budget,x,y,depth+1)) break :blk false;
            break :blk true;
        },
        .object=>blk: {
            if(left.object.count()!=right.object.count()) break :blk false;
            var entries=left.object.iterator();
            while(entries.next()) |entry| {
                const other=right.object.get(entry.key_ptr.*) orelse break :blk false;
                if(!try jsonEqual(budget,entry.value_ptr.*,other,depth+1)) break :blk false;
            }
            break :blk true;
        },
    };
}
fn sameValue(budget: Budget,left: std.json.Value,right: std.json.Value,key: []const u8) !void {
    if(!try jsonEqual(budget,try field(left,key),try field(right,key),0)) return error.RuntimeSelectionDrift;
}
fn memberMap(budget: Budget,rows: std.json.Value,members: []const ModernMember) !void {
    if(rows!=.object or rows.object.count()!=members.len) return error.InvalidRuntimeProvenance;
    for(members) |member| {
        try budget.check(); const row=try objectField(rows,member.name);
        try exactObject(row,&.{"path","sha256","bytes"}); try canonicalAbsolute(try stringField(row,"path")); try inputRow(row,member.input);
    }
}
fn authorityMap(budget: Budget,rows: std.json.Value,group: ModernAuthority) !void {
    try exactObject(rows,&.{"outer","evidence","members"});
    for([_] []const u8{"outer","evidence"},[_]Input{group.outer,group.evidence}) |name,input| {
        const row=try objectField(rows,name); try exactObject(row,&.{"path","sha256","bytes"});
        try canonicalAbsolute(try stringField(row,"path")); try inputRow(row,input);
    }
    try memberMap(budget,try field(rows,"members"),group.members);
}
/// The actual package action performs full physical source/SDK/compiler
/// readbacks. This boundary independently retains and joins the raw documents
/// and copied evidence to that action; it does not rerun a compiler or loader.
fn modernMaterial(a: std.mem.Allocator,budget: Budget,inputs: Inputs,manifest: std.json.Value,receipt: std.json.Value,source: std.json.Value) !void {
    const modern=inputs.modern_materials orelse return error.InvalidRuntimeProvenance;
    try packageOutputBinding(a,budget,inputs);
    const selection=try loadSelectedJson(a,budget,modern.package_selection,maximum_metadata_bytes);
    defer selection.deinit();
    try exactObject(selection.value,&.{"schema_version","kind","purpose","material","compilation","files",
        "protocol_schema_files","native_acquisition_artifact_files","authority_receipts"});
    if(try integer(selection.value,"schema_version")!=1) return error.InvalidRuntimeProvenance;
    try expectText(selection.value,"kind","omux-native-source-acquisition-native-package-selection-v1");
    try expectText(selection.value,"purpose","evaluation-only");
    const roles=try objectField(selection.value,"files");
    if(roles.object.count()!=12) return error.InvalidRuntimeProvenance;
    inline for(@typeInfo(ModernRole).@"enum".field_names,0..) |role,index| {
        const row=try objectField(roles,role); try exactObject(row,&.{"path","sha256","bytes"});
        try canonicalAbsolute(try stringField(row,"path")); try inputRow(row,modern.roles[index]);
    }
    try memberMap(budget,try field(selection.value,"protocol_schema_files"),modern.protocol_schema_files);
    try memberMap(budget,try field(selection.value,"native_acquisition_artifact_files"),modern.native_acquisition_artifact_files);
    const authorities=try objectField(selection.value,"authority_receipts");
    try exactObject(authorities,&.{"source","sdk","plan","query","compiler"});
    inline for(@typeInfo(ModernAuthorityRole).@"enum".field_names,0..) |role,index| try authorityMap(budget,try field(authorities,role),modern.authority_receipts[index]);
    if(!std.meta.eql(modern.roles[@intFromEnum(ModernRole.source)].sha256,inputs.source_receipt.sha256) or
        modern.roles[@intFromEnum(ModernRole.source)].bytes!=inputs.source_receipt.bytes) return error.RuntimeSelectionDrift;
    // The exact declared PACKAGE producer performs full source/SDK/compiler,
    // successful XML and physical readback qualification before emitting the
    // inventory marker. Its independently selected successful guardian binds
    // this full selection and every output. These retained raw tuples are
    // rehashed above; evaluation does not reproduce that physical pipeline or
    // infer supported runtime/loader authority from its summary.
    try expectText(source,"kind","omux-native-source-acquisition-source-v1");
    try expectText(source,"status","verified-ninth-acquisition-source-uncompiled");
    try expectText(source,"commit",verifier.upstream_commit);
    try expectBool(source,"acquisition_source_present",true);
    for([_]std.json.Value{manifest,receipt}) |value| {
        try expectText(value,"kind","omux-native-source-acquisition-fresh-native-package-v1");
        try expectText(value,"status","experimental-qualified-native-runtime");
        try expectText(value,"producer_target","//tools:codex_native_acquisition_runtime_package");
        try expectBool(value,"native_support",false); try expectBool(value,"provider_evaluation",false);
        if(!std.meta.eql(try digestField(value,"selection_sha256"),modern.package_selection.sha256)) return error.RuntimeSelectionDrift;
        const chain=try objectField(value,"chain");
        try exactObject(chain,&.{"material_family","compiler_qualified","schema_qualified","acquisitionContract","runtime_qualified","provider_identity_proved","live_handoff_proven"});
        try expectText(chain,"material_family","native-acquisition-evaluation-v1");
        try expectText(chain,"acquisitionContract","unsupported");
        try expectBool(chain,"compiler_qualified",true); try expectBool(chain,"schema_qualified",true);
        try expectBool(chain,"runtime_qualified",false);
        try expectBool(chain,"provider_identity_proved",false); try expectBool(chain,"live_handoff_proven",false);
        try expectBool(try objectField(value,"runtime"),"loader_lookup_qualified",false);
    }
    try expectText(manifest,"target","x86_64-linux");
    try expectText(receipt,"launchProfile","linux_nix_direct_main_v1");
    try expectText(receipt,"purpose","evaluation-only"); try expectText(receipt,"acquisitionContract","unsupported");
    const runtime=try objectField(manifest,"runtime");
    try expectText(runtime,"launchProfile","linux_nix_direct_main_v1");
    try expectText(runtime,"loader",loader); try expectText(runtime,"caBundle",ca_bundle);
    if(try positiveInteger(runtime,"backend_max_bytes")!=maximum_backend_bytes) return error.InvalidRuntimeProvenance;
    try sameValue(budget,manifest,receipt,"chain"); try sameValue(budget,manifest,receipt,"runtime");
    try sameValue(budget,manifest,receipt,"executable");
    if(!std.meta.eql(try digestField(receipt,"archive_sha256"),inputs.archive.sha256) or
        try positiveInteger(receipt,"archive_bytes")!=inputs.archive.bytes or
        !std.meta.eql(try digestField(receipt,"manifest_sha256"),inputs.manifest.sha256)) return error.RuntimeSelectionDrift;
}

const direct_launcher_bytes = "#!/bin/sh\nset -eu\nunset LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH\n" ++
    "launch_dir=${0%/*}\nif [ \"$launch_dir\" = \"$0\" ]; then launch_dir=.; fi\n" ++
    "pkg_root=$(CDPATH= cd -P \"$launch_dir/..\" && pwd -P) || exit 1\n" ++
    "runtime=$pkg_root/lib/codex\nSSL_CERT_FILE=\"$runtime/share/ca-bundle.crt\"\nexport SSL_CERT_FILE\n" ++
    "exec \"$runtime/libexec/codex.bin\" \"$@\"\n";

fn manifestFd(budget: Budget,directory: c.fd_t) !c.fd_t {
    try budget.check();
    const fd=c.openat(directory,"runtime-manifest.json",.{.NOFOLLOW=true,.CLOEXEC=true,.NONBLOCK=true});
    if(fd<0) return error.UnsafeRuntimeInput;
    errdefer _=c.close(fd);
    const status=try metadata.statFd(fd);
    try regular(status);
    if(status.mode & 0o7777!=0o644 or status.size>maximum_direct_manifest_bytes) return error.InvalidRuntimeManifest;
    return fd;
}
fn recheckDirectManifest(q: *const Qualified,budget: Budget,hash_payload: bool) !void {
    const observed: *const Retained=@ptrCast(@alignCast(q.observed));
    const fd=try manifestFd(budget,observed.inputs.installation_directory); defer _=c.close(fd);
    const expected=q.record.installed_manifest_status orelse return error.InvalidRuntimeManifest;
    if(!std.meta.eql(expected,try metadata.statFd(fd))) return error.RuntimeSelectionDrift;
    if(hash_payload) {
        const actual=try hashInput(budget,.{.descriptor=fd,.sha256=q.record.manifest_sha256,.bytes=@intCast(expected.size)},maximum_direct_manifest_bytes);
        if(!std.meta.eql(actual,expected)) return error.RuntimeSelectionDrift;
    }
    try budget.check();
}

fn acquireModern(io: std.Io,owner: std.mem.Allocator,context: ActorContext,inputs: Inputs,storage: []u8,bounded: *std.heap.FixedBufferAllocator) !*ValidatedSelection {
    const budget: Budget=.{.io=io,.deadline=context.deadline};
    const proof_budget: verifier.Budget=.{.io=io,.deadline=context.deadline};
    const a=bounded.allocator();
    const retained_modern=try retainModern(a,budget,inputs);
    errdefer retained_modern.deinit();
    const directory=c.openat(inputs.installation_directory,".",.{.DIRECTORY=true,.NOFOLLOW=true,.CLOEXEC=true});
    if(directory<0) return error.UnsafeRuntimeInput;
    errdefer _=c.close(directory);
    if(!std.meta.eql(try metadata.statFd(directory),try metadata.statFd(inputs.installation_directory))) return error.RuntimeSelectionDrift;
    retained_modern.inputs.installation_directory=directory;
    const observed=try observe(io,a,context,retained_modern.inputs); errdefer observed.deinit();
    const retained: *Retained=@ptrCast(@alignCast(observed));
    const manifest=try loadSelectedJson(a,budget,retained_modern.inputs.manifest,maximum_direct_manifest_bytes); defer manifest.deinit();
    try directArchiveLayout(manifest.value,retained_modern.inputs.manifest.bytes);
    try verifier.archiveSelected(proof_budget,retained_modern.inputs.archive,manifest.value,retained_modern.inputs.manifest.sha256,retained_modern.inputs.manifest.bytes);
    const registration_input=retained_modern.inputs.registration_receipt orelse return error.InvalidRuntimeProvenance;
    const registration_bytes=try readSelectedInput(io,a,context.deadline,registration_input,maximum_metadata_bytes); defer a.free(registration_bytes);
    const qualified_nix=try nix_artifact.decode(a,proof_budget,registration_bytes,registration_input.sha256);
    errdefer { var value=qualified_nix; value.deinit(); }
    const runtime=try objectField(manifest.value,"runtime");
    try expectText(runtime,"original_interpreter",qualified_nix.record.original_interpreter);
    try expectText(runtime,"backendInterpreter",qualified_nix.record.original_interpreter);
    if(!std.meta.eql(try digestField(runtime,"registration_receipt_sha256"),registration_input.sha256)) return error.RuntimeSelectionDrift;
    var roles: [3]setup.RuntimeRole=undefined;
    for(retained.files) |file| {
        const fd=try openMember(budget,directory,retained.directory,file.path); defer _=c.close(fd);
        if(std.mem.eql(u8,file.path,launcher)) {
            var expected: [32]u8=undefined; std.crypto.hash.sha2.Sha256.hash(direct_launcher_bytes,&expected,.{});
            if(file.bytes!=direct_launcher_bytes.len or !std.meta.eql(file.sha256,expected)) return error.InvalidRuntimeLauncher;
            roles[0]=.{.sha256=file.sha256,.bytes=file.bytes};
        } else if(std.mem.eql(u8,file.path,backend)) {
            try nix_artifact.graph(a,proof_budget,qualified_nix.record,fd,file.bytes);
            roles[1]=.{.sha256=file.sha256,.bytes=file.bytes};
        } else if(std.mem.eql(u8,file.path,loader)) {
            const external=qualified_nix.record.files[qualified_nix.record.interpreter_file_index];
            if(file.bytes!=external.bytes or !std.meta.eql(file.sha256,external.sha256)) return error.RuntimeSelectionDrift;
            roles[2]=.{.sha256=file.sha256,.bytes=file.bytes};
        } else if(std.mem.eql(u8,file.path,ca_bundle)) {
            const bytes=try readMetadata(a,budget,.{.descriptor=fd,.sha256=file.sha256,.bytes=file.bytes},file.status); defer a.free(bytes);
            try verifier.ca(a,bytes);
        } else return error.InvalidRuntimeManifest;
        if(!std.meta.eql(file.status,try metadata.statFd(fd))) return error.RuntimeSelectionDrift;
    }
    const installed_manifest=try manifestFd(budget,directory); defer _=c.close(installed_manifest);
    const installed_status=try hashInput(budget,.{.descriptor=installed_manifest,.sha256=inputs.manifest.sha256,.bytes=inputs.manifest.bytes},maximum_direct_manifest_bytes);
    if(installed_status.uid!=retained.directory.uid or installed_status.gid!=retained.directory.gid) return error.UnsafeRuntimeInput;
    const declaration=retained_modern.inputs.deployment_declaration orelse return error.InvalidDeploymentSelection;
    const root=retained_modern.inputs.deployment_root orelse return error.InvalidDeploymentSelection;
    const custody=context.options.native_custody orelse return error.NativeCustodyPending;
    const record: setup.RuntimeSelectionRecord=.{
        .schema_version=2,.channel=if(context.selection==.dev) .development else .release,.target=.x86_64_linux,
        .launch_profile=.linux_nix_direct_main_v1,.acquisition_contract=.unsupported,
        .upstream_commit=verifier.upstream_commit[0..40].*,.artifact_selection_sha256=artifactDigest(inputArray(retained_modern.inputs)),
        .archive_sha256=inputs.archive.sha256,.manifest_sha256=inputs.manifest.sha256,.runtime_receipt_sha256=inputs.runtime_receipt.sha256,
        .source_receipt_sha256=inputs.source_receipt.sha256,.producer_receipt_sha256=inputs.producer_receipt.sha256,
        .installation=.{.transaction=retained.registry.transaction,.adapter_epoch=custody.adapter_epoch,
            .capability_digest=retained.registry.capability_digest,.directory_device=retained.directory.dev,.directory_inode=retained.directory.ino,
            .uid=retained.directory.uid,.gid=retained.directory.gid},.launcher=roles[0],.backend=roles[1],.loader=roles[2],
        .nix_closure=qualified_nix.record,.installed_manifest_status=installed_status,
        .deployment=.{.root=.{.path=root.path,.status=retained_modern.root_status},
            .declaration=.{.path=try std.fmt.allocPrint(a,"{s}/share/omux/native/codex/deployment.json",.{root.path}),
                .sha256=declaration.sha256,.bytes=declaration.bytes,.status=try metadata.statFd(declaration.descriptor)}},
    };
    try observed.recheck(io,context);
    try retained_modern.recheck(budget); try retained_modern.recheckIdentity(budget);
    try nix.recheck(io,a,context.deadline,qualified_nix.record);
    const q=try owner.create(Qualified);
    q.*=.{.observed=observed,.record=record,.deadline=context.deadline,.owner_allocator=owner,
        .metadata_storage=storage,.metadata_allocator=bounded,.modern=retained_modern,.nix_owned=qualified_nix};
    errdefer owner.destroy(q);
    try recheckDirectManifest(q,budget,true);
    return @ptrCast(q);
}

fn validateOutputMarker(a: std.mem.Allocator,budget: Budget,raw_log: []const u8,inventory_hash: [32]u8) !void {
    const expected_hash=std.fmt.bytesToHex(inventory_hash,.lower);
    const marker=try std.fmt.allocPrint(a,"omux-native-package-output-sha256={s}",.{expected_hash}); defer a.free(marker);
    var lines=std.mem.splitScalar(u8,raw_log,'\n'); var count: usize=0;
    while(lines.next()) |line| {
        try budget.check();
        if(std.mem.indexOf(u8,line,"omux-native-package-output-sha256=")!=null) {
            if(!std.mem.eql(u8,line,marker)) return error.InvalidRuntimeProvenance; count+=1;
        }
    }
    if(count!=1) return error.InvalidRuntimeProvenance;
}

test "evaluation package output marker refuses absence duplication unrelated hash and expired clock" {
    const a=std.testing.allocator;
    const io=std.testing.io;
    const until=std.Io.Clock.Timestamp.now(io,.awake).addDuration(.{.clock=.awake,.raw=.fromSeconds(30)});
    const budget: Budget=.{.io=io,.deadline=until};
    const hash: [32]u8 = @splat(0x12);
    const hex=std.fmt.bytesToHex(hash,.lower);
    const one=try std.fmt.allocPrint(a,"test banner\nomux-native-package-output-sha256={s}\n",.{hex}); defer a.free(one);
    try validateOutputMarker(a,budget,one,hash);
    try std.testing.expectError(error.InvalidRuntimeProvenance,validateOutputMarker(a,budget,"no output marker\n",hash));
    const duplicate=try std.mem.concat(a,u8,&.{one,one}); defer a.free(duplicate);
    try std.testing.expectError(error.InvalidRuntimeProvenance,validateOutputMarker(a,budget,duplicate,hash));
    const prefixed=try std.mem.concat(a,u8,&.{one,"prefix omux-native-package-output-sha256=garbage\n"}); defer a.free(prefixed);
    try std.testing.expectError(error.InvalidRuntimeProvenance,validateOutputMarker(a,budget,prefixed,hash));
    var wrong=hash; wrong[0]^=1;
    try std.testing.expectError(error.InvalidRuntimeProvenance,validateOutputMarker(a,budget,one,wrong));
    const expired: Budget=.{.io=io,.deadline=std.Io.Clock.Timestamp.now(io,.awake)};
    try std.testing.expectError(error.Timeout,validateOutputMarker(a,expired,one,hash));
}

test "modern retention hashes actual selected FD bytes owns duplicates and rejects metadata drift" {
    const a=std.testing.allocator;
    const io=std.testing.io;
    var tmp=std.testing.tmpDir(.{}); defer tmp.cleanup();
    const payload="actual selected raw proof";
    try tmp.dir.writeFile(io,.{.sub_path="proof",.data=payload});
    var fd=c.openat(tmp.dir.handle,"proof",.{.NOFOLLOW=true,.CLOEXEC=true});
    if(fd<0) return error.FixtureOpenFailed;
    defer if(fd>=0) { _=c.close(fd); };
    if(c.fchmod(fd,0o644)!=0) return error.FixtureChmodFailed;
    var hash: [32]u8=undefined; std.crypto.hash.sha2.Sha256.hash(payload,&hash,.{});
    const budget: Budget=.{.io=io,.deadline=std.Io.Clock.Timestamp.now(io,.awake).addDuration(.{.clock=.awake,.raw=.fromSeconds(30)})};
    var retained: ModernRetained=.{.allocator=a,.inputs=undefined,.root_status=undefined};
    defer {
        for(retained.witnesses.items) |row| _=c.close(row.input.descriptor);
        retained.witnesses.deinit(a);
    }
    var bad=hash; bad[0]^=1;
    try std.testing.expectError(error.RuntimeSelectionDrift,retained.take(budget,.{.descriptor=fd,.sha256=bad,.bytes=payload.len},maximum_metadata_bytes));
    try std.testing.expectEqual(@as(usize,0),retained.witnesses.items.len);
    const copied=try retained.take(budget,.{.descriptor=fd,.sha256=hash,.bytes=payload.len},maximum_metadata_bytes);
    const status=retained.witnesses.items[0].status;
    try std.testing.expect(copied.descriptor!=fd);
    _=c.close(fd); fd=-1;
    try std.testing.expectEqualDeep(status,try hashInput(budget,copied,maximum_metadata_bytes));
    const changed=c.openat(tmp.dir.handle,"proof",.{.ACCMODE=.WRONLY,.NOFOLLOW=true,.CLOEXEC=true});
    if(changed<0) return error.FixtureOpenFailed; defer _=c.close(changed);
    if(c.fchmod(changed,0o600)!=0) return error.FixtureChmodFailed;
    try std.testing.expect(!std.meta.eql(status,try metadata.statFd(copied.descriptor)));
    // The fence compares the complete original witness; same payload digest
    // does not authorize a changed mode/ctime on the retained inode.
    const changed_status=try hashInput(budget,copied,maximum_metadata_bytes);
    try std.testing.expect(!std.meta.eql(status,changed_status));
    const expired: Budget=.{.io=io,.deadline=std.Io.Clock.Timestamp.now(io,.awake)};
    try std.testing.expectError(error.Timeout,retained.take(expired,copied,maximum_metadata_bytes));
}


test "direct materialization rejects aggregate disk payload before a staging sink" {
    const a=std.testing.allocator;
    const hash: [64]u8 = @splat('1');
    var parsed=try std.json.parseFromSlice(std.json.Value,a,
        "{\"runtime\":{\"launchProfile\":\"linux_nix_direct_main_v1\"},\"files\":{}}",.{});
    defer parsed.deinit();
    const rows=&parsed.value.object.getPtr("files").?.object;
    for([_] []const u8{launcher,backend,loader,ca_bundle}) |path| {
        const raw=try std.json.Stringify.valueAlloc(a,.{.mode=@as(u64,if(std.mem.eql(u8,path,ca_bundle)) 0o644 else 0o755),
            .bytes=@as(u64,if(std.mem.eql(u8,path,backend)) maximum_payload_bytes else 1),.sha256=hash},.{});
        defer a.free(raw);
        // This parser-only model owns its inserted objects through a shared
        // arena, never instantiates a selection or writes a candidate payload.
        const row=try std.json.parseFromSlice(std.json.Value,parsed.arena.allocator(),raw,.{.allocate=.alloc_always});
        try rows.put(parsed.arena.allocator(),path,row.value);
    }
    try std.testing.expectError(error.RuntimeInputLimit,directArchiveLayout(parsed.value,64));
    const backend_row=rows.getPtr(backend).?;
    backend_row.object.getPtr("bytes").?.*=.{.integer=maximum_payload_bytes-3-64};
    try directArchiveLayout(parsed.value,64);
}
