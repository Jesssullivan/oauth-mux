//! Pure bounded package/source provenance predicates; no process execution or
//! path discovery. Expected hashes are selected by the actor, never a reply.
const std = @import("std");
const c = std.c;
const metadata = @import("../platform/file_metadata.zig");
pub const maximum_metadata_bytes = 16 * 1024 * 1024;
pub const backend_path = "lib/codex/libexec/codex.bin";
pub const loader_path = "lib/codex/lib/ld-linux-x86-64.so.2";
pub const ca_path = "lib/codex/share/ca-bundle.crt";
pub const interpreter = "/omux/launch-via-bin-wrapper";
pub const upstream_commit = "00c972ed5d6ff6499317fd41b7f23605b8e6850d";
pub const launcher_bytes = "#!/bin/sh\nset -eu\nunset LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH\nlaunch_dir=${0%/*}\nif [ \"$launch_dir\" = \"$0\" ]; then launch_dir=.; fi\npkg_root=$(CDPATH= cd -P \"$launch_dir/..\" && pwd -P) || exit 1\nruntime=$pkg_root/lib/codex\nSSL_CERT_FILE=\"$runtime/share/ca-bundle.crt\"\nexport SSL_CERT_FILE\nexec \"$runtime/lib/ld-linux-x86-64.so.2\" --inhibit-cache --library-path \"$runtime/lib\" --argv0 \"$0\" \"$runtime/libexec/codex.bin\" \"$@\"\n";
pub const Budget = struct {
    io: std.Io,
    deadline: std.Io.Clock.Timestamp,
    pub fn check(self: Budget) !void {
        try self.io.checkCancel();
        if (self.deadline.clock != .awake) return error.InvalidDeadline;
        if (self.deadline.durationFromNow(self.io).raw.toMilliseconds() <= 0) return error.Timeout;
    }
};
pub fn field(v: std.json.Value, key: []const u8) !std.json.Value {
    if (v != .object) return error.InvalidRuntimeProvenance;
    return v.object.get(key) orelse error.InvalidRuntimeProvenance;
}
pub fn text(v: std.json.Value, key: []const u8) ![]const u8 {
    const x = try field(v, key);
    if (x != .string) return error.InvalidRuntimeProvenance;
    return x.string;
}
pub fn number(v: std.json.Value, key: []const u8) !u64 {
    const x = try field(v, key);
    if (x != .integer or x.integer <= 0) return error.InvalidRuntimeProvenance;
    return @intCast(x.integer);
}
pub fn digest(v: std.json.Value, key: []const u8) ![32]u8 {
    const x = try text(v, key);
    if (x.len != 64) return error.InvalidRuntimeProvenance;
    for (x) |b| if (!std.ascii.isDigit(b) and !(b >= 'a' and b <= 'f')) return error.InvalidRuntimeProvenance;
    var result: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&result, x);
    if (std.mem.allEqual(u8, &result, 0)) return error.InvalidRuntimeProvenance;
    return result;
}
fn equal(v: std.json.Value, key: []const u8, expected: []const u8) !void {
    if (!std.mem.eql(u8, try text(v, key), expected)) return error.InvalidRuntimeProvenance;
}
fn same(a: std.json.Value, b: std.json.Value, key: []const u8) !void {
    try equal(a, key, try text(b, key));
}
fn uuid(value: []const u8) !void {
    if (value.len != 36) return error.InvalidRuntimeProvenance;
    for (value, 0..) |b, i| {
        if (i == 8 or i == 13 or i == 18 or i == 23) {
            if (b != '-') return error.InvalidRuntimeProvenance;
        } else if (!std.ascii.isDigit(b) and !(b >= 'a' and b <= 'f')) return error.InvalidRuntimeProvenance;
    }
}
fn sourcePath(path: []const u8) !void {
    if (path.len == 0 or path.len > 4096 or path[0] == '/') return error.InvalidRuntimeProvenance;
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.InvalidRuntimeProvenance;
        // The pinned public candidate's inventory uses ASCII names. Refusing
        // foreign Unicode avoids a second incompatible canonical JSON encoder.
        for (part) |b| if (b < 32 or b >= 127 or b == '\\') return error.InvalidRuntimeProvenance;
    }
}
fn hashJsonString(hash: *std.crypto.hash.sha2.Sha256, value: []const u8) void {
    hash.update("\"");
    for (value) |b| switch (b) {
        '\\' => hash.update("\\\\"),
        '"' => hash.update("\\\""),
        else => hash.update(&.{b}),
    };
    hash.update("\"");
}
/// Match json.dumps(inventory, sort_keys=True): exact keys and default spaces.
/// This checks complete inventory metadata, not unselected source file bytes.
pub fn inventoryDigest(a: std.mem.Allocator, budget: Budget, inventory: std.json.Value) ![32]u8 {
    if (inventory != .object or inventory.object.count() == 0 or inventory.object.count() > 50000) return error.InvalidRuntimeProvenance;
    const keys = try a.alloc([]const u8, inventory.object.count());
    defer a.free(keys);
    var it = inventory.object.iterator();
    var i: usize = 0;
    while (it.next()) |entry| { keys[i] = entry.key_ptr.*; i += 1; }
    std.mem.sort([]const u8, keys, {}, struct {
        fn less(_: void, x: []const u8, y: []const u8) bool { return std.mem.order(u8, x, y) == .lt; }
    }.less);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("{");
    for (keys, 0..) |key, index| {
        try budget.check();
        try sourcePath(key);
        const record = inventory.object.get(key).?;
        if (record != .object or record.object.count() != 2) return error.InvalidRuntimeProvenance;
        const mode = try text(record, "mode");
        if (!std.mem.eql(u8, mode, "100644") and !std.mem.eql(u8, mode, "100755") and !std.mem.eql(u8, mode, "120000")) return error.InvalidRuntimeProvenance;
        _ = try digest(record, "sha256");
        if (index != 0) hash.update(", ");
        hashJsonString(&hash, key);
        hash.update(": {\"mode\": "); hashJsonString(&hash, mode);
        hash.update(", \"sha256\": "); hashJsonString(&hash, try text(record, "sha256")); hash.update("}");
    }
    hash.update("}");
    var result: [32]u8 = undefined; hash.final(&result); return result;
}
pub fn provenance(a: std.mem.Allocator, budget: Budget, manifest: std.json.Value, receipt: std.json.Value, source: std.json.Value, producer: std.json.Value, source_hash: [32]u8, producer_hash: [32]u8) !void {
    try budget.check();
    const candidate = try field(manifest, "candidate");
    if (candidate != .object or candidate.object.count() != 12) return error.InvalidRuntimeProvenance;
    const runtime_candidate = try field(receipt, "candidate");
    if (runtime_candidate != .object or runtime_candidate.object.count() != candidate.object.count()) return error.InvalidRuntimeProvenance;
    try equal(candidate, "upstream_commit", upstream_commit);
    try equal(source, "commit", upstream_commit);
    try equal(source, "phase", "verify-prepared");
    try equal(producer, "upstream_commit", upstream_commit);
    try equal(producer, "target", "//codex-rs/cli:codex");
    const config = try text(producer, "configuration");
    if (!std.mem.eql(u8, config, "owner-linux-fastbuild") and !std.mem.eql(u8, config, "owner-linux-opt")) return error.InvalidRuntimeProvenance;
    try equal(source, "bazel_configuration", config);
    try equal(candidate, "current_configuration", config);
    const digests = [_][]const u8{ "patch_sha256", "base_sha256", "binary_overlay_sha256", "validation_sha256", "complete_source_inventory_sha256", "current_source_receipt_sha256" };
    for (digests) |key| {
        _ = try digest(candidate, key);
        try same(candidate, runtime_candidate, key);
        try same(candidate, producer, key);
    }
    const ids = [_][]const u8{ "compile_invocation_id", "source_verification_invocation_id", "current_compile_invocation_id", "current_source_verification_invocation_id" };
    for (ids) |key| { try uuid(try text(candidate, key)); try same(candidate, runtime_candidate, key); try same(candidate, producer, key); }
    try same(candidate, runtime_candidate, "upstream_commit");
    try same(candidate, runtime_candidate, "current_configuration");
    try same(candidate, source, "patch_sha256");
    const inventory = try field(source, "files");
    if (inventory != .object or try number(source, "tracked_files") != inventory.object.count()) return error.InvalidRuntimeProvenance;
    const inventory_hash = try inventoryDigest(a, budget, inventory);
    if (!std.meta.eql(inventory_hash, try digest(source, "complete_inventory_sha256")) or !std.meta.eql(inventory_hash, try digest(candidate, "complete_source_inventory_sha256"))) return error.InvalidRuntimeProvenance;
    const transform = try field(manifest, "transformations");
    if (!std.meta.eql(source_hash, try digest(candidate, "current_source_receipt_sha256")) or !std.meta.eql(source_hash, try digest(transform, "source_receipt_sha256")) or !std.meta.eql(producer_hash, try digest(transform, "producer_receipt_sha256"))) return error.InvalidRuntimeProvenance;
    _ = try digest(transform, "strip_tool_sha256"); _ = try digest(transform, "patchelf_tool_sha256");
    const executable = try field(manifest, "executable");
    const external = try field(receipt, "executable");
    if (executable != .object or external != .object or executable.object.count() != 7 or external.object.count() != 7) return error.InvalidRuntimeProvenance;
    if (try number(executable, "backend_max_bytes") != 512 * 1024 * 1024 or try number(external, "backend_max_bytes") != 512 * 1024 * 1024) return error.InvalidRuntimeProvenance;
    for ([_][]const u8{ "original_sha256", "stripped_sha256", "packaged_sha256" }) |key| { _ = try digest(executable, key); try same(executable, external, key); }
    for ([_][]const u8{ "original_bytes", "stripped_bytes", "packaged_bytes" }, [_]u64{ 1024 * 1024 * 1024, 512 * 1024 * 1024, 512 * 1024 * 1024 }) |key, bound| {
        if (try number(executable, key) > bound or try number(executable, key) != try number(external, key)) return error.InvalidRuntimeProvenance;
    }
    try same(executable, producer, "original_sha256");
    if (try number(executable, "original_bytes") != try number(producer, "original_bytes")) return error.InvalidRuntimeProvenance;
    const files = try field(manifest, "files");
    const backend = try field(files, backend_path);
    if (!std.meta.eql(try digest(executable, "packaged_sha256"), try digest(backend, "sha256")) or try number(executable, "packaged_bytes") != try number(backend, "bytes")) return error.InvalidRuntimeProvenance;
    const runtime = try field(manifest, "runtime");
    if (try number(runtime, "backend_max_bytes") != 512 * 1024 * 1024) return error.InvalidRuntimeProvenance;
    try equal(runtime, "backendInterpreter", interpreter);
}

// Checks every bounded compressed-input transfer, including deflate blocks
// which yield no output. The decompressor cannot consume the full transfer
// buffer between cooperative cancellation/deadline checks.
pub const SelectedArchive = struct { descriptor: c.fd_t, sha256: [32]u8, bytes: u64 };
const ArchiveSource = union(enum) {
    bytes: []const u8, selected: SelectedArchive,
    fn size(self: ArchiveSource) u64 { return switch(self) { .bytes => |value| value.len, .selected => |value| value.bytes }; }
};
const CompressedReader = struct {
    budget: Budget,
    source: ArchiveSource,
    before: ?metadata.Metadata = null,
    hash: std.crypto.hash.sha2.Sha256 = .init(.{}),
    offset: usize = 0,
    failure: ?anyerror = null,
    reader: std.Io.Reader,
    fn init(budget: Budget, bytes: []const u8, buffer: []u8) CompressedReader {
        return .{ .budget = budget, .source = .{ .bytes = bytes },
            .reader = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 } };
    }
    fn selected(budget: Budget, value: SelectedArchive, buffer: []u8) !CompressedReader {
        try budget.check();
        if (value.bytes < 18 or value.bytes > 256 * 1024 * 1024 or std.mem.allEqual(u8, &value.sha256, 0)) return error.RuntimeInputLimit;
        const status = try metadata.statFd(value.descriptor);
        if (status.mode & c.S.IFMT != c.S.IFREG or status.size < 0 or @as(u64,@intCast(status.size)) != value.bytes or (status.uid != c.geteuid() and status.uid != 0) or status.mode & 0o7022 != 0 or (status.nlink != 1 and !(status.uid == 0 and status.mode & 0o222 == 0 and status.nlink >= 1))) return error.UnsafeRuntimeInput;
        var result = init(budget, &.{}, buffer); result.source = .{ .selected = value }; result.before = status; return result;
    }
    fn finish(self: *CompressedReader) !void {
        if (self.offset != self.source.size() or self.reader.seek != self.reader.end) return error.InvalidRuntimeArchive;
        switch(self.source) {
            .bytes => {},
            .selected => |value| {
                try self.budget.check();
                var actual: [32]u8 = undefined; self.hash.final(&actual);
                if (!std.meta.eql(actual,value.sha256) or !std.meta.eql(self.before.?,try metadata.statFd(value.descriptor))) return error.RuntimeSelectionDrift;
            },
        }
    }
    fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *CompressedReader = @alignCast(@fieldParentPtr("reader", r));
        self.budget.check() catch |err| { self.failure = err; return error.ReadFailed; };
        if (self.offset == self.source.size()) return error.EndOfStream;
        const length = @min(@as(usize,1024),limit.minInt(@as(usize,@intCast(self.source.size()-self.offset))));
        var buffer: [1024]u8 = undefined;
        const bytes: []const u8 = switch(self.source) {
            .bytes => |value| value[self.offset..][0..length],
            .selected => |value| blk: {
                var done: usize = 0;
                while (done < length) {
                    self.budget.check() catch |err| { self.failure=err; return error.ReadFailed; };
                    const n = c.pread(value.descriptor,buffer[done..].ptr,length-done,@intCast(self.offset+done));
                    if (n < 0) { if(c.errno(n)==.INTR) continue; self.failure=error.RuntimeInputReadFailed; return error.ReadFailed; }
                    if (n == 0) { self.failure=error.RuntimeSelectionDrift; return error.ReadFailed; }
                    done += @intCast(n);
                }
                break :blk buffer[0..length];
            },
        };
        try w.writeAll(bytes); self.hash.update(bytes); self.offset += length; return length;
    }
};

const ArchiveReader = struct {
    budget: Budget,
    reader: *std.Io.Reader,
    compressed: *CompressedReader,
    crc: std.hash.Crc32 = .init(),
    count: u64 = 0,
    fn read(self: *ArchiveReader, bytes: []u8) !void {
        try self.budget.check();
        self.reader.readSliceAll(bytes) catch { return self.compressed.failure orelse error.InvalidRuntimeArchive; };
        self.count = try std.math.add(u64, self.count, bytes.len);
        if (self.count > 512 * 1024 * 1024 + maximum_metadata_bytes + 4096 * 1024 + 10240) return error.RuntimeInputLimit;
        self.crc.update(bytes);
    }
};
fn octal(bytes: []const u8) !u64 {
    var value: u64 = 0;
    var digits: usize = 0;
    for (bytes) |b| {
        if (b == 0 or b == ' ') continue;
        if (b < '0' or b > '7') return error.InvalidRuntimeArchive;
        value = try std.math.add(u64, try std.math.mul(u64, value, 8), b - '0'); digits += 1;
    }
    if (digits == 0) return error.InvalidRuntimeArchive;
    return value;
}
fn terminated(bytes: []const u8) ![]const u8 {
    const end = std.mem.indexOfScalar(u8, bytes, 0) orelse bytes.len;
    if (!std.mem.allEqual(u8, bytes[end..], 0)) return error.InvalidRuntimeArchive;
    return bytes[0..end];
}
/// Decode one bounded gzip member; reject auxiliary headers, concatenated
/// members, non-USTAR/link/extension records and foreign members. CRC and ISIZE
/// are checked here: std.flate exposes their values but does not verify them.
pub fn archive(budget: Budget, bytes: []const u8, manifest: std.json.Value, manifest_hash: [32]u8, manifest_bytes: u64) !void {
    return archiveImpl(budget, .{ .bytes = bytes }, manifest, manifest_hash, manifest_bytes, null);
}
/// Owned user-private staging only. No publication occurs here. The same
/// parser first checks every member, hash, padding and gzip footer before any
/// destination write; the second pass repeats validation while copying.
pub const Created = struct {
    path: []const u8, kind: enum { file, directory }, descriptor: c.fd_t,
    // Creation is accounted before the first fallible stat. Missing witness is
    // an explicit incomplete-custody outcome, never permission to unlink.
    status: ?metadata.Metadata = null,
};
pub const StagingLedger = struct {
    allocator: std.mem.Allocator, entries: std.ArrayList(Created) = .empty,
    index: std.StringHashMapUnmanaged(usize) = .empty,
    pub fn init(a: std.mem.Allocator) StagingLedger { return .{ .allocator = a }; }
    pub fn deinit(self: *StagingLedger) void {
        for (self.entries.items) |entry| { if(entry.descriptor>=0) _ = c.close(entry.descriptor); self.allocator.free(entry.path); }
        self.entries.deinit(self.allocator); self.index.deinit(self.allocator);
    }
    fn prepare(self: *StagingLedger, path: []const u8) ![]u8 {
        if (self.entries.items.len >= 4096 or self.index.contains(path)) return error.RuntimeInputLimit;
        try self.entries.ensureUnusedCapacity(self.allocator,1);
        try self.index.ensureUnusedCapacity(self.allocator,1);
        return self.allocator.dupe(u8,path);
    }
    fn created(self: *StagingLedger, path: []u8, kind: @FieldType(Created,"kind"), fd: c.fd_t) usize {
        const index = self.entries.items.len;
        self.entries.appendAssumeCapacity(.{ .path=path,.kind=kind,.descriptor=fd });
        self.index.putAssumeCapacityNoClobber(path,index); return index;
    }
};
pub fn materializeArchive(budget: Budget, bytes: []const u8, manifest: std.json.Value, manifest_hash: [32]u8, manifest_bytes: u64, staging_fd: c.fd_t, ledger: *StagingLedger) !void {
    const status = try metadata.statFd(staging_fd);
    if (status.mode & c.S.IFMT != c.S.IFDIR or status.uid != c.geteuid() or status.mode & 0o7777 != 0o700 or ledger.entries.items.len != 0) return error.UnsafeRuntimeStaging;
    try archive(budget, bytes, manifest, manifest_hash, manifest_bytes);
    try archiveImpl(budget, .{ .bytes = bytes }, manifest, manifest_hash, manifest_bytes, .{ .root=staging_fd,.ledger=ledger });
}
fn archivePath(path: []const u8) !void {
    if (path.len == 0 or path.len > 256 or path[0] == '/') return error.InvalidRuntimeArchive;
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8, part, ".") or std.mem.eql(u8, part, "..")) return error.InvalidRuntimeArchive;
        for (part) |b| if (b < 32 or b >= 127 or b == '\\') return error.InvalidRuntimeArchive;
    }
}
fn identity(a: metadata.Metadata, b: metadata.Metadata) bool {
    return a.dev==b.dev and a.ino==b.ino and a.uid==b.uid and a.gid==b.gid and a.mode==b.mode;
}
const Staging = struct { root: c.fd_t, ledger: *StagingLedger };
const Destination = struct { fd: c.fd_t, index: usize };
fn stageMember(budget: Budget, staging: Staging, path: []const u8) !Destination {
    try archivePath(path);
    var parent = staging.root;
    var parts = std.mem.splitScalar(u8,path,'/');
    var component = parts.next().?; var prefix_length: usize = 0;
    while(true) {
        try budget.check(); prefix_length += component.len;
        const prefix = path[0..prefix_length];
        var name: [257]u8 = undefined; @memcpy(name[0..component.len],component); name[component.len]=0;
        const next = parts.next();
        if(next==null) {
            const owned_path = try staging.ledger.prepare(prefix);
            const fd = c.openat(parent,@ptrCast(&name),.{ .ACCMODE=.WRONLY,.CREAT=true,.EXCL=true,.NOFOLLOW=true,.CLOEXEC=true },@as(c.mode_t,0o600));
            if(fd<0) { staging.ledger.allocator.free(owned_path); return error.UnsafeRuntimeStaging; }
            const index = staging.ledger.created(owned_path,.file,fd);
            staging.ledger.entries.items[index].status = try metadata.statFd(fd);
            return .{ .fd=fd,.index=index };
        }
        if(staging.ledger.index.get(prefix)) |index| {
            const entry = staging.ledger.entries.items[index];
            if(entry.kind!=.directory or entry.descriptor<0 or entry.status==null) return error.UnsafeRuntimeStaging;
            const named = c.openat(parent,@ptrCast(&name),.{ .DIRECTORY=true,.NOFOLLOW=true,.CLOEXEC=true });
            if(named<0) return error.UnsafeRuntimeStaging;
            defer _ = c.close(named);
            if(!identity(entry.status.?,try metadata.statFd(named)) or !identity(entry.status.?,try metadata.statFd(entry.descriptor))) return error.UnsafeRuntimeStaging;
            parent = entry.descriptor;
        } else {
            const owned_path = try staging.ledger.prepare(prefix);
            if(c.mkdirat(parent,@ptrCast(&name),0o700)!=0) { staging.ledger.allocator.free(owned_path); return error.UnsafeRuntimeStaging; }
            const fd = c.openat(parent,@ptrCast(&name),.{ .DIRECTORY=true,.NOFOLLOW=true,.CLOEXEC=true });
            const index = staging.ledger.created(owned_path,.directory,fd);
            if(fd<0) return error.UnsafeRuntimeStaging;
            const status = try metadata.statFd(fd); staging.ledger.entries.items[index].status=status;
            if(status.mode & c.S.IFMT!=c.S.IFDIR or status.uid!=c.geteuid() or status.mode & 0o7777!=0o700) return error.UnsafeRuntimeStaging;
            parent = fd;
        }
        prefix_length += 1; component=next.?;
    }
}
fn stageWrite(budget: Budget, fd: c.fd_t, bytes: []const u8) !void {
    var done: usize = 0;
    while (done < bytes.len) {
        try budget.check(); const n = c.write(fd, bytes[done..].ptr, bytes.len - done);
        if (n < 0) { if (c.errno(n) == .INTR) continue; return error.RuntimeStagingWriteFailed; }
        if (n == 0) return error.RuntimeStagingWriteFailed;
        done += @intCast(n);
    }
}
pub fn archiveSelected(budget: Budget, input: SelectedArchive, manifest: std.json.Value, manifest_hash: [32]u8, manifest_bytes: u64) !void {
    return archiveImpl(budget,.{ .selected=input },manifest,manifest_hash,manifest_bytes,null);
}
pub fn materializeSelectedArchive(budget: Budget, input: SelectedArchive, manifest: std.json.Value, manifest_hash: [32]u8, manifest_bytes: u64, staging_fd: c.fd_t, ledger: *StagingLedger) !void {
    const status = try metadata.statFd(staging_fd);
    if(ledger.entries.items.len != 0 or status.mode & c.S.IFMT != c.S.IFDIR or status.uid != c.geteuid() or status.mode & 0o7777 != 0o700) return error.UnsafeRuntimeStaging;
    try archiveSelected(budget,input,manifest,manifest_hash,manifest_bytes);
    try archiveImpl(budget,.{ .selected=input },manifest,manifest_hash,manifest_bytes,.{ .root=staging_fd,.ledger=ledger });
}
fn archiveImpl(budget: Budget, source: ArchiveSource, manifest: std.json.Value, manifest_hash: [32]u8, manifest_bytes: u64, staging: ?Staging) !void {
    try budget.check();
    if(source.size()<18 or source.size()>256*1024*1024) return error.InvalidRuntimeArchive;
    var input_buffer: [4096]u8 = undefined;
    var input = switch(source) { .bytes => |bytes| CompressedReader.init(budget,bytes,&input_buffer), .selected => |value| try CompressedReader.selected(budget,value,&input_buffer) };
    const gzip_prefix = input.reader.peek(4) catch { return input.failure orelse error.InvalidRuntimeArchive; };
    if(!std.mem.eql(u8,gzip_prefix,&.{0x1f,0x8b,8,0})) return error.InvalidRuntimeArchive;
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decoder = std.compress.flate.Decompress.init(&input.reader, .gzip, &window);
    var raw: ArchiveReader = .{ .budget = budget, .reader = &decoder.reader, .compressed = &input };
    const files = try field(manifest, "files");
    if (files != .object or files.object.count() + 1 > 4096) return error.RuntimeInputLimit;
    var seen: usize = 0;
    var previous: [256]u8 = undefined;
    var previous_len: usize = 0;
    while (true) {
        var header: [512]u8 = undefined; try raw.read(&header);
        if (std.mem.allEqual(u8, &header, 0)) {
            var final: [512]u8 = undefined; try raw.read(&final);
            if (!std.mem.allEqual(u8, &final, 0)) return error.InvalidRuntimeArchive;
            // Python's pinned producer pads to a 10240-byte tar record.
            while (raw.count % 10240 != 0) { try raw.read(&final); if (!std.mem.allEqual(u8, &final, 0)) return error.InvalidRuntimeArchive; }
            if ((decoder.reader.readSliceShort(final[0..1]) catch { return input.failure orelse error.InvalidRuntimeArchive; }) != 0 ) return error.InvalidRuntimeArchive;
            if (decoder.container_metadata.gzip.crc != raw.crc.final() or decoder.container_metadata.gzip.count != @as(u32, @intCast(raw.count))) return error.InvalidRuntimeArchive;
            try input.finish();
            if (seen != files.object.count() + 1) return error.InvalidRuntimeArchive;
            return;
        }
        if (seen >= files.object.count() + 1 or header[156] != '0' or !std.mem.eql(u8, header[257..265], "ustar\x0000") or !std.mem.allEqual(u8, header[157..257], 0) or !std.mem.allEqual(u8, header[265..329], 0) or !std.mem.allEqual(u8, header[500..], 0)) return error.InvalidRuntimeArchive;
        var checksum: u64 = 0; for (header, 0..) |b, i| checksum += if (i >= 148 and i < 156) @as(u8, ' ') else b;
        if (try octal(header[148..156]) != checksum or try octal(header[108..116]) != 0 or try octal(header[116..124]) != 0 or try octal(header[136..148]) != 0 or !std.mem.allEqual(u8, header[329..345], 0)) return error.InvalidRuntimeArchive;
        const leaf = try terminated(header[0..100]); const prefix = try terminated(header[345..500]);
        var name: [256]u8 = undefined;
        const length = prefix.len + @as(usize, if (prefix.len != 0) 1 else 0) + leaf.len;
        if (length == 0 or length > name.len) return error.InvalidRuntimeArchive;
        var pos: usize = 0;
        if (prefix.len != 0) { @memcpy(name[0..prefix.len], prefix); pos = prefix.len; name[pos] = '/'; pos += 1; }
        @memcpy(name[pos..length], leaf); const path = name[0..length];
        try archivePath(path);
        if (seen != 0 and std.mem.order(u8, previous[0..previous_len], path) != .lt) return error.InvalidRuntimeArchive;
        @memcpy(previous[0..length], path); previous_len = length;
        const is_manifest = std.mem.eql(u8, path, "runtime-manifest.json");
        const record = if (is_manifest) null else files.object.get(path) orelse return error.InvalidRuntimeArchive;
        const size = try octal(header[124..136]); const mode = try octal(header[100..108]);
        const expected_size = if (record) |r| try number(r, "bytes") else manifest_bytes;
        const expected_mode = if (record) |r| try number(r, "mode") else 0o644;
        const expected_hash = if (record) |r| try digest(r, "sha256") else manifest_hash;
        if (size != expected_size or mode != expected_mode) return error.InvalidRuntimeArchive;
        if (mode != 0o644 and mode != 0o755) return error.InvalidRuntimeArchive;
        const destination = if (staging) |value| try stageMember(budget,value,path) else null;
        var hash = std.crypto.hash.sha2.Sha256.init(.{}); var buffer: [64 * 1024]u8 = undefined; var remaining = size;
        while (remaining != 0) { const count: usize = @intCast(@min(buffer.len, remaining)); try raw.read(buffer[0..count]); hash.update(buffer[0..count]); if (destination) |value| try stageWrite(budget, value.fd, buffer[0..count]);
            remaining -= count; }
        var actual: [32]u8 = undefined; hash.final(&actual); if (!std.meta.eql(actual, expected_hash)) return error.InvalidRuntimeArchive;
        const padding: usize = @intCast((512 - size % 512) % 512);
        try raw.read(buffer[0..padding]); if (!std.mem.allEqual(u8, buffer[0..padding], 0)) return error.InvalidRuntimeArchive;
        if (destination) |value| {
            const fd=value.fd;
            try budget.check();
            if (c.fchmod(fd, @intCast(mode)) != 0) return error.RuntimeStagingWriteFailed;
            staging.?.ledger.entries.items[value.index].status.?.mode = (staging.?.ledger.entries.items[value.index].status.?.mode & ~@as(u32,0o777)) | @as(u32,@intCast(mode));
            while (c.fsync(fd) != 0) { try budget.check(); if (c.errno(-1) != .INTR) return error.RuntimeStagingWriteFailed; }
            const status = try metadata.statFd(fd);
            staging.?.ledger.entries.items[value.index].status=status;
            if (status.size < 0 or @as(u64, @intCast(status.size)) != size or status.uid != c.geteuid() or status.mode & 0o777 != mode or status.mode & c.S.IFMT != c.S.IFREG or status.nlink != 1) return error.UnsafeRuntimeStaging;
        }
        seen += 1;
    }
}

const FileReader = struct {
    budget: Budget,
    fd: ?c.fd_t = null,
    bytes: ?[]const u8 = null,
    size: u64,
    fn read(self: FileReader, offset: u64, data: []u8) !void {
        if (offset > self.size or data.len > self.size - offset) return error.InvalidRuntimeElf;
        try self.budget.check();
        if (self.bytes) |bytes| {
            @memcpy(data, bytes[@intCast(offset)..][0..data.len]);
            return;
        }
        var done: usize = 0;
        while (done < data.len) {
            try self.budget.check();
            const n = c.pread(self.fd.?, data[done..].ptr, data.len - done, @intCast(offset + done));
            if (n < 0) { if (c.errno(n) == .INTR) continue; return error.RuntimeInputReadFailed; }
            if (n == 0) return error.RuntimeSelectionDrift;
            done += @intCast(n);
        }
    }
};
fn readU16(bytes: []const u8, offset: usize) u16 { return std.mem.readInt(u16, bytes[offset..][0..2], .little); }
fn readU32(bytes: []const u8, offset: usize) u32 { return std.mem.readInt(u32, bytes[offset..][0..4], .little); }
fn readU64(bytes: []const u8, offset: usize) u64 { return std.mem.readInt(u64, bytes[offset..][0..8], .little); }
fn cstring(bytes: []const u8, offset: u64) ![]const u8 {
    if (offset >= bytes.len) return error.InvalidRuntimeElf;
    const start: usize = @intCast(offset);
    const tail = bytes[start..@min(bytes.len, start + 4097)];
    const end = std.mem.indexOfScalar(u8, tail, 0) orelse return error.InvalidRuntimeElf;
    if (end > 4096) return error.InvalidRuntimeElf;
    for (tail[0..end]) |b| if (b < 32 or b >= 127) return error.InvalidRuntimeElf;
    return tail[0..end];
}
const Segment = struct { virtual: u64, offset: u64, length: u64, memory: u64 = 0 };
/// Real ELF64 program-header/dynamic parsing on the installed bytes already
/// proven identical to archive members. No section-header, loader execution,
/// system search path, environment or externally resolved dependency is used.
pub const ElfDescription = struct {
    allocator: std.mem.Allocator,
    interpreter: ?[]u8 = null,
    soname: ?[]u8 = null,
    needed: std.ArrayList([]u8) = .empty,
    rpath: std.ArrayList([]u8) = .empty,
    runpath: std.ArrayList([]u8) = .empty,
    pub fn deinit(self: *ElfDescription) void {
        if (self.interpreter) |value| self.allocator.free(value);
        if (self.soname) |value| self.allocator.free(value);
        for (self.needed.items) |value| self.allocator.free(value);
        for (self.rpath.items) |value| self.allocator.free(value);
        for (self.runpath.items) |value| self.allocator.free(value);
        self.needed.deinit(self.allocator); self.rpath.deinit(self.allocator); self.runpath.deinit(self.allocator);
    }
};
pub fn elfDescription(a: std.mem.Allocator, budget: Budget, fd: c.fd_t, size: u64, maximum: u64) !ElfDescription {
    return elfDescriptionInput(a, .{ .budget = budget, .fd = fd, .size = size }, maximum);
}
pub fn elfDescriptionBytes(a: std.mem.Allocator, budget: Budget, bytes: []const u8, maximum: u64) !ElfDescription {
    return elfDescriptionInput(a, .{ .budget = budget, .bytes = bytes, .size = bytes.len }, maximum);
}
fn elfDescriptionInput(a: std.mem.Allocator, input: FileReader, maximum: u64) !ElfDescription {
    const budget = input.budget; const size = input.size;
    var result: ElfDescription = .{ .allocator = a };
    errdefer result.deinit();
    try budget.check();
    if (size < 64 or size > maximum or maximum > 512 * 1024 * 1024) return error.InvalidRuntimeElf;
    var header: [64]u8 = undefined; try input.read(0, &header);
    if (!std.mem.eql(u8, header[0..7], "\x7fELF\x02\x01\x01") or (readU16(&header, 16) != 2 and readU16(&header, 16) != 3) or readU16(&header, 18) != 62 or readU32(&header, 20) != 1 or readU16(&header, 52) != 64 or readU16(&header, 54) != 56) return error.InvalidRuntimeElf;
    const phoff = readU64(&header, 32); const phnum = readU16(&header, 56);
    if (phnum == 0 or phnum > 4096 or phoff < 64 or phoff > size or @as(u64, phnum) * 56 > size - phoff) return error.InvalidRuntimeElf;
    const loads = try a.alloc(Segment, phnum); defer a.free(loads); var load_count: usize = 0;
    var dynamic: ?Segment = null; var interp_seen = false;
    for (0..phnum) |index| {
        var h: [56]u8 = undefined; try input.read(phoff + index * 56, &h);
        const tag = readU32(&h, 0); const offset = readU64(&h, 8); const virtual = readU64(&h, 16); const filesz = readU64(&h, 32); const memsz = readU64(&h, 40);
        if (filesz > memsz or offset > size or filesz > size - offset or memsz > std.math.maxInt(u64) - virtual) return error.InvalidRuntimeElf;
        switch (tag) {
            1 => {
                for (loads[0..load_count]) |prior| {
                    if (memsz != 0 and prior.memory != 0 and virtual < prior.virtual + prior.memory and prior.virtual < virtual + memsz) return error.InvalidRuntimeElf;
                }
                loads[load_count] = .{ .virtual = virtual, .offset = offset, .length = filesz, .memory = memsz }; load_count += 1;
            },
            2 => { if (dynamic != null or filesz == 0 or filesz % 16 != 0 or filesz / 16 > 4096) return error.InvalidRuntimeElf; dynamic = .{ .virtual = virtual, .offset = offset, .length = filesz }; },
            3 => {
                if (interp_seen or filesz == 0 or filesz > 4097) return error.InvalidRuntimeElf;
                interp_seen = true; var data: [4097]u8 = undefined; const n: usize = @intCast(filesz); try input.read(offset, data[0..n]);
                const value = try cstring(data[0..n], 0);
                if (value.len == 0 or value.len + 1 != n) return error.InvalidRuntimeElf;
                result.interpreter = try a.dupe(u8, value);
            },
            else => {},
        }
    }
    const dyn = dynamic orelse return result;
    var dynamic_mapping: ?u64 = null;
    for (loads[0..load_count]) |load| {
        if (dyn.virtual >= load.virtual and dyn.virtual - load.virtual <= load.length and dyn.length <= load.length - (dyn.virtual - load.virtual)) {
            if (dynamic_mapping != null) return error.InvalidRuntimeElf;
            dynamic_mapping = load.offset + (dyn.virtual - load.virtual);
        }
    }
    if (dynamic_mapping == null or dynamic_mapping.? != dyn.offset) return error.InvalidRuntimeElf;
    const entries = try a.alloc(u8, @intCast(dyn.length)); defer a.free(entries); try input.read(dyn.offset, entries);
    var address: ?u64 = null; var strsize: ?u64 = null; var terminated_dynamic = false; var refs: usize = 0;
    var rpath_seen = false; var runpath_seen = false;
    var end: usize = 0;
    while (end < entries.len) : (end += 16) {
        try budget.check(); const tag = readU64(entries, end); const value = readU64(entries, end + 8);
        if (tag == 0) { terminated_dynamic = true; break; }
        switch (tag) {
            5 => { if (address != null) return error.InvalidRuntimeElf; address = value; },
            10 => { if (strsize != null or value == 0 or value > 8 * 1024 * 1024) return error.InvalidRuntimeElf; strsize = value; },
            1, 14 => refs += 1,
            15 => { if (rpath_seen) return error.InvalidRuntimeElf; rpath_seen = true; refs += 1; },
            29 => { if (runpath_seen) return error.InvalidRuntimeElf; runpath_seen = true; refs += 1; },
            0x7fffffff, 0x7ffffffd, 0x6ffffefc, 0x6ffffefb, 0x6ffffefa => return error.InvalidRuntimeElf,
            else => {},
        }
    }
    if (!terminated_dynamic) return error.InvalidRuntimeElf;
    if (refs == 0 and address == null and strsize == null) return result;
    const addr = address orelse return error.InvalidRuntimeElf; const length = strsize orelse return error.InvalidRuntimeElf;
    var mapping: ?u64 = null;
    for (loads[0..load_count]) |load| {
        if (addr >= load.virtual and addr - load.virtual <= load.length and length <= load.length - (addr - load.virtual)) {
            if (mapping != null) return error.InvalidRuntimeElf; mapping = load.offset + (addr - load.virtual);
        }
    }
    const table = try a.alloc(u8, @intCast(length)); defer a.free(table); try input.read(mapping orelse return error.InvalidRuntimeElf, table);
    var i: usize = 0;
    while (i < end) : (i += 16) {
        try budget.check(); const tag = readU64(entries, i);
        if (tag != 1 and tag != 14 and tag != 15 and tag != 29) continue;
        const value = try cstring(table, readU64(entries, i + 8));
        if (tag == 14) {
            if (result.soname != null or value.len == 0 or std.mem.indexOfScalar(u8, value, '/') != null) return error.InvalidRuntimeElf;
            result.soname = try a.dupe(u8, value);
        } else if (tag == 1) {
            if (value.len == 0 or std.mem.indexOfScalar(u8, value, '/') != null) return error.InvalidRuntimeElf;
            if (result.needed.items.len >= 64) return error.RuntimeInputLimit;
            const owned = try a.dupe(u8, value); errdefer a.free(owned); try result.needed.append(a, owned);
        } else {
            var paths = std.mem.splitScalar(u8, value, ':');
            while (paths.next()) |path| {
                if ((if(tag==15) result.rpath.items.len else result.runpath.items.len) >= 64) return error.RuntimeInputLimit;
                const owned = try a.dupe(u8, path); errdefer a.free(owned);
                if (tag == 15) try result.rpath.append(a, owned) else try result.runpath.append(a, owned);
            }
        }
    }
    return result;
}

pub fn elf(a: std.mem.Allocator, budget: Budget, fd: c.fd_t, size: u64, is_backend: bool, dependencies: std.json.Value) !void {
    if (dependencies != .array) return error.InvalidRuntimeElf;
    var parsed = try elfDescription(a, budget, fd, size, if (is_backend) 512 * 1024 * 1024 else 128 * 1024 * 1024); defer parsed.deinit();
    if (parsed.interpreter) |value| { if (!std.mem.eql(u8, value, interpreter)) return error.InvalidRuntimeElf; } else if (is_backend) return error.InvalidRuntimeElf;
    for (parsed.needed.items) |name| {
        var found = false;
        for (dependencies.array.items) |dep| {
            if (dep != .string or !std.mem.startsWith(u8, dep.string, "lib/codex/lib/")) return error.InvalidRuntimeElf;
            if (std.mem.eql(u8, dep.string["lib/codex/lib/".len..], name)) found = true;
        }
        if (!found) return error.InvalidRuntimeElf;
    }
    for (parsed.rpath.items) |path| if (!std.mem.eql(u8, path, if (is_backend) "$ORIGIN/../lib" else "$ORIGIN")) return error.InvalidRuntimeElf;
    for (parsed.runpath.items) |path| if (!std.mem.eql(u8, path, if (is_backend) "$ORIGIN/../lib" else "$ORIGIN")) return error.InvalidRuntimeElf;
    if (is_backend and parsed.rpath.items.len + parsed.runpath.items.len != 1) return error.InvalidRuntimeElf;
}

/// Public PEM-only custody check, with bounded base64 certificate blocks.
/// The cryptographic TLS library still owns X.509 parsing/trust semantics.
pub fn ca(a: std.mem.Allocator, bytes: []const u8) !void {
    if (bytes.len == 0 or bytes.len > maximum_metadata_bytes or !std.unicode.utf8ValidateSlice(bytes)) return error.InvalidRuntimeCa;
    var cursor: usize = 0; var count: usize = 0;
    while (std.mem.indexOfPos(u8, bytes, cursor, "-----")) |start| {
        const normal = "-----BEGIN CERTIFICATE-----"; const trusted = "-----BEGIN TRUSTED CERTIFICATE-----";
        const begin = if (std.mem.startsWith(u8, bytes[start..], normal)) normal else if (std.mem.startsWith(u8, bytes[start..], trusted)) trusted else return error.InvalidRuntimeCa;
        const finish = if (begin.len == normal.len) "-----END CERTIFICATE-----" else "-----END TRUSTED CERTIFICATE-----";
        const body_start = start + begin.len;
        const stop = std.mem.indexOfPos(u8, bytes, body_start, finish) orelse return error.InvalidRuntimeCa;
        var encoded: std.ArrayList(u8) = .empty; defer encoded.deinit(a);
        for (bytes[body_start..stop]) |b| {
            if (b == ' ' or b == '\t' or b == '\r' or b == '\n') continue;
            if (!std.ascii.isAlphanumeric(b) and b != '+' and b != '/' and b != '=') return error.InvalidRuntimeCa;
            if (encoded.items.len >= 87384) return error.InvalidRuntimeCa;
            try encoded.append(a, b);
        }
        const length = std.base64.standard.Decoder.calcSizeForSlice(encoded.items) catch return error.InvalidRuntimeCa;
        if (length == 0 or length > 64 * 1024) return error.InvalidRuntimeCa;
        const decoded = try a.alloc(u8, length); defer a.free(decoded);
        std.base64.standard.Decoder.decode(decoded, encoded.items) catch return error.InvalidRuntimeCa;
        cursor = stop + finish.len; count += 1;
    }
    if (count == 0) return error.InvalidRuntimeCa;
}

test "compressed reader rechecks original budget after bounded input progress" {
    const io = std.testing.io;
    const future = std.Io.Clock.Timestamp.now(io, .awake).addDuration(.{ .clock = .awake, .raw = .fromSeconds(30) });
    const source: [4096]u8 = @splat(0);
    var buffer: [4096]u8 = undefined;
    var input = CompressedReader.init(.{ .io = io, .deadline = future }, &source, &buffer);
    var first: [1]u8 = undefined;
    try input.reader.readSliceAll(&first);
    try std.testing.expect(input.offset > 0 and input.offset <= 1024);
    const progressed = input.offset;
    input.budget.deadline = std.Io.Clock.Timestamp.now(io, .awake);
    var rest: [2048]u8 = undefined;
    try std.testing.expectError(error.ReadFailed, input.reader.readSliceAll(&rest));
    try std.testing.expectEqual(error.Timeout, input.failure.?);
    try std.testing.expectEqual(progressed, input.offset);
}
