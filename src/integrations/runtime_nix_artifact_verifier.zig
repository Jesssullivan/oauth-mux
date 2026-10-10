//! Registered, independently selected declared direct-main ELF metadata graph.
//! This evaluation parser does not prove live loader search or process inventory.
//! No Nix query/registration, provider call, process launch or ambient lookup.
const std = @import("std");
const c = std.c;
const metadata = @import("../platform/file_metadata.zig");
const closure = @import("nix_runtime_closure.zig");
const artifact = @import("runtime_artifact_verifier.zig");
pub const profile = "linux_nix_direct_main_v1";
pub const DeclaredFile = struct { path: []const u8, sha256: []const u8, bytes: u64, status: metadata.Metadata };
pub const RegistrationRow = struct { path: []const u8, narHash: []const u8, narSize: u64, references: []const []const u8 };
pub const Receipt = struct {
    schema_version: u8,
    status: []const u8,
    native_support: bool,
    loader_lookup_qualified: bool,
    target: []const u8,
    original_interpreter: []const u8,
    interpreter_file_index: u8,
    roots: []const closure.Root,
    files: []const DeclaredFile,
    aliases: []const closure.Alias,
    edges: []const closure.Edge,
    registration_rows: []const RegistrationRow,
};
pub const Owned = struct {
    allocator: std.mem.Allocator,
    parsed: std.json.Parsed(Receipt),
    record: closure.Record,
    pub fn deinit(self: *Owned) void { self.allocator.free(self.record.files); self.parsed.deinit(); }
};
fn require(value: bool) !void { if (!value) return error.InvalidNixRuntimeProvenance; }
fn hash(text: []const u8) ![32]u8 {
    try require(text.len == 64);
    for (text) |b| try require(std.ascii.isDigit(b) or (b >= 'a' and b <= 'f'));
    var result: [32]u8 = undefined; _ = try std.fmt.hexToBytes(&result, text);
    try require(!std.mem.allEqual(u8, &result, 0)); return result;
}
fn rootOf(path: []const u8) ![]const u8 {
    try require(std.mem.startsWith(u8, path, "/nix/store/") and path.len <= 4096 and path.len > 44);
    const end = std.mem.indexOfScalarPos(u8, path, 11, '/') orelse path.len;
    const name = path[11..end]; try require(name.len >= 34 and name.len <= 244 and name[32] == '-');
    for (name[0..32]) |b| try require(std.mem.indexOfScalar(u8, "0123456789abcdfghijklmnpqrsvwxyz", b) != null);
    for (name[33..]) |b| try require(std.ascii.isAlphanumeric(b) or std.mem.indexOfScalar(u8, "+._?=-", b) != null);
    try require(!std.mem.startsWith(u8, name[33..], ".-") and !std.mem.startsWith(u8, name[33..], "..-"));
    var parts = std.mem.splitScalar(u8, path[end..], '/');
    _ = parts.next();
    while (parts.next()) |part| {
        try require(part.len != 0 and !std.mem.eql(u8, part, ".") and !std.mem.eql(u8, part, ".."));
        for (part) |b| try require(b >= 32 and b < 127 and b != '\\');
    }
    return path[0..end];
}
fn selected(record: closure.Record, path: []const u8) !void {
    const root = try rootOf(path);
    for (record.roots) |row| if (std.mem.eql(u8, root, row.path)) return;
    return error.InvalidNixRuntimeProvenance;
}
fn normalize(a: std.mem.Allocator, parent: []const u8, target: []const u8) ![]u8 {
    if (target.len == 0 or target.len > 4096) return error.InvalidNixRuntimeProvenance;
    // std.fs.path.resolve is lexical only; the explicit absolute parent avoids
    // cwd dependence. All normalization is checked against the selected roots.
    return std.fs.path.resolve(a, &.{ parent, target });
}
fn fileIndex(record: closure.Record, path: []const u8) ?u8 {
    for (record.files, 0..) |file, i| if (std.mem.eql(u8, path, file.path)) return @intCast(i);
    return null;
}
/// Resolve only recorded links. No lstat/open occurs while choosing an edge.
/// Intermediate aliases are expanded before a final exact selected file match.
fn resolve(a: std.mem.Allocator, record: closure.Record, path: []const u8) !?u8 {
    var current = try a.dupe(u8, path); defer a.free(current);
    for (0..64) |_| {
        try selected(record, current);
        var found: ?closure.Alias = null;
        for (record.aliases) |alias| {
            if (std.mem.eql(u8, current, alias.path) or (std.mem.startsWith(u8, current, alias.path) and current.len > alias.path.len and current[alias.path.len] == '/')) {
                if (found == null or alias.path.len < found.?.path.len) found = alias;
            }
        }
        const alias = found orelse return fileIndex(record, current);
        const target = try normalize(a, std.fs.path.dirname(alias.path).?, alias.target); defer a.free(target);
        const joined = try std.fmt.allocPrint(a, "{s}{s}", .{ target, current[alias.path.len..] });
        defer a.free(joined);
        const next = try normalize(a, "/", joined);
        a.free(current); current = next;
    }
    return error.InvalidNixRuntimeProvenance;
}
fn narHash(text: []const u8) !void {
    if (std.mem.startsWith(u8, text, "sha256:")) {
        const encoded = text[7..];
        if (encoded.len == 64) { _ = try hash(encoded); return; }
        try require(encoded.len == 52 and encoded[0] <= '1' and !std.mem.allEqual(u8, encoded, '0'));
        for (encoded) |b| try require(std.mem.indexOfScalar(u8, "0123456789abcdfghijklmnpqrsvwxyz", b) != null);
        return;
    }
    return error.InvalidNixRuntimeProvenance;
}
fn shape(a: std.mem.Allocator, budget: artifact.Budget, receipt: Receipt, record: closure.Record) !void {
    try budget.check();
    try require(receipt.schema_version == 1 and !receipt.native_support and !receipt.loader_lookup_qualified and std.mem.eql(u8, receipt.status, "registered-linux-nix-runtime-closure-proof-candidate") and std.mem.eql(u8, receipt.target, "x86_64-linux"));
    try require(record.roots.len > 0 and record.roots.len <= 32 and record.files.len > 0 and record.files.len <= 32 and record.aliases.len <= 32 and record.edges.len <= 64 and record.interpreter_file_index < record.files.len and receipt.registration_rows.len == record.roots.len);
    for (record.roots, 0..) |root, i| {
        try require(std.mem.eql(u8, try rootOf(root.path), root.path));
        if (i != 0) try require(std.mem.order(u8, record.roots[i - 1].path, root.path) == .lt);
    }
    for (record.files, 0..) |file, i| {
        try selected(record, file.path);
        if (i != 0) try require(std.mem.order(u8, record.files[i - 1].path, file.path) == .lt);
    }
    for (record.aliases, 0..) |alias, i| {
        try selected(record, alias.path);
        if (i != 0) try require(std.mem.order(u8, record.aliases[i - 1].path, alias.path) == .lt);
        try require(fileIndex(record, alias.path) == null);
        const target = try normalize(a, std.fs.path.dirname(alias.path).?, alias.target); defer a.free(target);
        try selected(record, target);
        // Reject declared link loops even when no current ELF edge uses them.
        _ = try resolve(a, record, alias.path);
    }
    var total: u64 = 0;
    for (receipt.registration_rows, 0..) |row, i| {
        try budget.check();
        try require(std.mem.eql(u8, row.path, record.roots[i].path) and row.narSize > 0 and row.narSize <= 16 * 1024 * 1024 * 1024 and row.references.len <= record.roots.len);
        total = try std.math.add(u64, total, row.narSize); try require(total <= 16 * 1024 * 1024 * 1024);
        try narHash(row.narHash);
        for (row.references, 0..) |ref, j| {
            try require(std.mem.eql(u8, try rootOf(ref), ref));
            if (j != 0) try require(std.mem.order(u8, row.references[j - 1], ref) == .lt);
            var found = false; for (record.roots) |root| if (std.mem.eql(u8, ref, root.path)) { found = true; break; };
            try require(found);
        }
    }
    const interpreter_index = try resolve(a, record, record.original_interpreter);
    try require(interpreter_index != null and interpreter_index.? == record.interpreter_file_index);
}
pub fn decode(a: std.mem.Allocator, budget: artifact.Budget, bytes: []const u8, selected_hash: [32]u8) !Owned {
    try budget.check(); try require(bytes.len > 0 and bytes.len <= artifact.maximum_metadata_bytes);
    const parsed = try std.json.parseFromSlice(Receipt, a, bytes, .{ .duplicate_field_behavior = .@"error", .ignore_unknown_fields = false, .allocate = .alloc_always });
    errdefer parsed.deinit();
    try require(parsed.value.files.len > 0 and parsed.value.files.len <= 32);
    const files = try a.alloc(closure.File, parsed.value.files.len); errdefer a.free(files);
    for (parsed.value.files, files) |raw, *file| file.* = .{ .path = raw.path, .sha256 = try hash(raw.sha256), .bytes = raw.bytes, .status = raw.status };
    const record: closure.Record = .{ .registration_receipt_sha256 = selected_hash, .original_interpreter = parsed.value.original_interpreter,
        .interpreter_file_index = parsed.value.interpreter_file_index, .roots = parsed.value.roots, .files = files, .aliases = parsed.value.aliases, .edges = parsed.value.edges, .loader_lookup_qualified=false };
    try shape(a, budget, parsed.value, record);
    // Concrete namespace, root ownership and every selected byte are checked.
    try closure.recheck(budget.io, a, budget.deadline, record);
    return .{ .allocator = a, .parsed = parsed, .record = record };
}
fn directory(a: std.mem.Allocator, record: closure.Record, source_index: u8, path: []const u8) ![]u8 {
    if (std.mem.startsWith(u8, path, "/")) { try selected(record, path); return a.dupe(u8, path); }
    try require(source_index != 255);
    const origin = std.fs.path.dirname(record.files[source_index].path).?;
    const prefix = if (std.mem.startsWith(u8, path, "$ORIGIN")) "$ORIGIN" else if (std.mem.startsWith(u8, path, "${ORIGIN}")) "${ORIGIN}" else return error.InvalidNixRuntimeProvenance;
    const suffix = path[prefix.len..]; try require(suffix.len == 0 or suffix[0] == '/');
    const joined = try std.fmt.allocPrint(a, "{s}{s}", .{ origin, suffix }); defer a.free(joined);
    const result = try normalize(a, "/", joined); errdefer a.free(result); try selected(record, result); return result;
}
const ResolvedEdge = struct { index: usize, target: u8 };
fn edge(record: closure.Record, source_index: u8, needed: []const u8) !ResolvedEdge {
    var result: ?ResolvedEdge = null;
    for (record.edges, 0..) |row, i| if (row.source_index == source_index and std.mem.eql(u8, needed, row.needed)) {
        try require(result == null and row.target_index < record.files.len);
        result = .{ .index = i, .target = row.target_index };
    };
    return result orelse error.InvalidNixRuntimeProvenance;
}
/// Independently derive every ordered lookup edge from actual retained ELF
/// bytes. Cache/default directory fallback is outside this narrow profile.
pub fn graph(a: std.mem.Allocator, budget: artifact.Budget, record: closure.Record, backend_fd: c.fd_t, backend_bytes: u64) !void {
    try budget.check();
    var backend = try artifact.elfDescription(a, budget, backend_fd, backend_bytes, 512 * 1024 * 1024); defer backend.deinit();
    try graphDescription(a, budget, record, &backend);
}
pub fn graphBytes(a: std.mem.Allocator, budget: artifact.Budget, record: closure.Record, bytes: []const u8) !void {
    var backend = try artifact.elfDescriptionBytes(a, budget, bytes, 512 * 1024 * 1024); defer backend.deinit();
    try graphDescription(a, budget, record, &backend);
}
fn graphDescription(a: std.mem.Allocator, budget: artifact.Budget, record: closure.Record, backend: *const artifact.ElfDescription) !void {
    try require(backend.interpreter != null and std.mem.eql(u8, backend.interpreter.?, record.original_interpreter));
    try require(backend.rpath.items.len == 0);
    const all = try a.alloc(artifact.ElfDescription, record.files.len); var owned: usize = 0;
    defer { for (all[0..owned]) |*elf| elf.deinit(); a.free(all); }
    for (record.files, 0..) |file, i| {
        try budget.check();
        // Descriptor-relative nofollow walk checks the selected root and file
        // before returning this owned descriptor; no ambient alias traversal.
        const fd = try closure.openVerifiedFile(budget.io, a, budget.deadline, record, i);
        defer _ = c.close(fd);
        try require(std.meta.eql(file.status, try metadata.statFd(fd)));
        all[i] = try artifact.elfDescription(a, budget, fd, file.bytes, 128 * 1024 * 1024); owned += 1;
        // Original RPATH requires an ancestry-aware loader model. This
        // finite profile preserves bytes and refuses unsupported RPATH.
        try require(all[i].rpath.items.len == 0);
        try require(std.meta.eql(file.status, try metadata.statFd(fd)));
        if (all[i].interpreter) |interp| { const resolved = try resolve(a, record, interp); try require(resolved != null and resolved.? == record.interpreter_file_index); }
        if (all[i].soname) |name| for (all[0..i]) |prior| if (prior.soname) |other| try require(!std.mem.eql(u8, name, other));
    }
    try validateElfGraph(a, budget, record, backend, all);
    try closure.recheck(budget.io, a, budget.deadline, record);
}
/// Deterministic parser output seam. This validates edge semantics only and
/// never returns a selection or skips graph()'s physical custody proof.
pub fn validateElfGraph(a: std.mem.Allocator, budget: artifact.Budget, record: closure.Record, backend: *const artifact.ElfDescription, all: []const artifact.ElfDescription) !void {
    try budget.check();
    try require(record.files.len > 0 and record.files.len <= 32 and all.len == record.files.len and record.interpreter_file_index < all.len and record.edges.len <= 64);
    try require(backend.interpreter != null and std.mem.eql(u8, backend.interpreter.?, record.original_interpreter) and backend.rpath.items.len == 0);
    for (all) |elf| try require(elf.rpath.items.len == 0);
    var loaded: [32]bool = @splat(false); loaded[record.interpreter_file_index] = true;
    var pending: [33]u8 = undefined; pending[0] = 255; pending[1] = record.interpreter_file_index; var head: usize = 0; var tail: usize = 2;
    var used: [64]bool = @splat(false);
    while (head < tail) : (head += 1) {
        try budget.check(); const source_index = pending[head]; const elf = if (source_index == 255) backend else &all[source_index];
        for (elf.needed.items) |needed| {
            const declared = try edge(record, source_index, needed); try require(!used[declared.index]); used[declared.index] = true;
            var actual: ?u8 = null;
            for (all, loaded[0..all.len], 0..) |other, is_loaded, i| if (is_loaded) {
                if (other.soname) |name| if (std.mem.eql(u8, name, needed)) { try require(actual == null); actual = @intCast(i); };
            };
            if (actual == null) {
                // RUNPATH is direct-only; there is no cache/default search.
                const paths = elf.runpath.items;
                for (paths) |path| {
                    const base = try directory(a, record, source_index, path); defer a.free(base);
                    const candidate = try std.fmt.allocPrint(a, "{s}/{s}", .{ base, needed }); defer a.free(candidate);
                    actual = try resolve(a, record, candidate);
                    if (actual != null) break;
                }
            }
            try require(actual != null and actual.? == declared.target);
            if (!loaded[declared.target]) { try require(tail < pending.len); loaded[declared.target] = true; pending[tail] = declared.target; tail += 1; }
        }
    }
    for (loaded[0..record.files.len]) |is_loaded| try require(is_loaded);
    for (used[0..record.edges.len]) |is_used| try require(is_used);
}

/// Final actor fence: names and retained immutable identities only. Full byte
/// hashing and static ELF parsing remain on the supervised worker path.
pub fn recheckIdentity(budget: artifact.Budget,a: std.mem.Allocator,record: closure.Record) !void {
    try budget.check();
    try require(record.roots.len>0 and record.roots.len<=32 and record.files.len>0 and record.files.len<=32 and record.aliases.len<=32);
    for(record.roots) |root| {
        const fd=try closure.openSelectedDirectory(budget.io,a,budget.deadline,root.path); defer _=c.close(fd);
        if(!std.meta.eql(root.status,try metadata.statFd(fd))) return error.RuntimeSelectionDrift;
    }
    for(record.files,0..) |_,index| {
        const fd=try closure.openVerifiedFile(budget.io,a,budget.deadline,record,index); defer _=c.close(fd);
    }
    for(record.aliases) |alias| {
        try budget.check();
        const parent_path=std.fs.path.dirname(alias.path) orelse return error.InvalidNixRuntimeProvenance;
        const parent=try closure.openSelectedDirectory(budget.io,a,budget.deadline,parent_path); defer _=c.close(parent);
        const name=try a.dupeSentinel(u8,std.fs.path.basename(alias.path),0); defer a.free(name);
        const before=try metadata.statAt(parent,name.ptr,c.AT.SYMLINK_NOFOLLOW);
        if(!std.meta.eql(before,alias.status) or before.mode & c.S.IFMT!=c.S.IFLNK) return error.RuntimeSelectionDrift;
        var target: [4097]u8=undefined;
        const count=c.readlinkat(parent,name.ptr,&target,target.len);
        if(count<=0 or !std.mem.eql(u8,target[0..@intCast(count)],alias.target) or
            !std.meta.eql(before,try metadata.statAt(parent,name.ptr,c.AT.SYMLINK_NOFOLLOW))) return error.RuntimeSelectionDrift;
    }
    try budget.check();
}
