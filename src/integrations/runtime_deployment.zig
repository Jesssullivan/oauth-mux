//! One-time configured fleet package selection. Never read this from control,
//! observation environment, native peer fields or a pasted digest.
const std = @import("std");
const c = std.c;
const producer = @import("runtime_selection_producer.zig");
const metadata = @import("../platform/file_metadata.zig");
const nix = @import("nix_runtime_closure.zig");
pub const maximum_declaration_bytes = 64 * 1024;
const maximum_metadata = maximum_declaration_bytes;
const selector = "share/omux/native/codex/deployment.json";
const Role = struct { path: []const u8, sha256: []const u8, bytes: u64 };
pub const RegisteredDeployment = struct { path: []const u8, descriptor: c.fd_t };
pub fn openRegisteredRoot(io: std.Io, allocator: std.mem.Allocator, path: []const u8, until: std.Io.Clock.Timestamp) !c.fd_t {
    return nix.openSelectedDirectory(io,allocator,until,path);
}
const Member = struct { name: []const u8, path: []const u8, sha256: []const u8, bytes: u64 };
const ModernRoles = struct {
    source: Role, sdk: Role, sdk_metadata: Role, plan: Role, query: Role,
    compiler_selection: Role, compiler_ledger: Role, compiler_ledger_snapshot: Role,
    compiler: Role, compiler_outer: Role, codex: Role, config_schema: Role,
};
const AuthorityGroup = struct { outer: Role, evidence: Role, members: []const Member };
const Authorities = struct { source: AuthorityGroup, sdk: AuthorityGroup, plan: AuthorityGroup, query: AuthorityGroup, compiler: AuthorityGroup };
const Modern = struct { package_selection: Role, package_outputs: Role, package_output_root: []const u8, package_authority: AuthorityGroup, roles: ModernRoles, protocol_schema_files: []const Member, native_acquisition_artifact_files: []const Member, authority_receipts: Authorities };
const Declaration = struct {
    schema_version: u8,
    kind: []const u8,
    target: []const u8,
    launch_profile: []const u8,
    inputs: struct { archive: Role, manifest: Role, runtime_receipt: Role,
        source_receipt: Role, producer_receipt: Role, registration_receipt: Role },
    modern_materials: ?Modern = null,
};
const Held = struct {
    allocator: std.mem.Allocator,
    root: c.fd_t,
    root_status: metadata.Metadata,
    root_path: []u8,
    selector_fd: c.fd_t,
    selector_status: metadata.Metadata,
    parsed: std.json.Parsed(Declaration),
    descriptors: []c.fd_t,
    statuses: []metadata.Metadata,
    selected_roles: []Role,
    protocol_members: []producer.ModernMember,
    acquisition_members: []producer.ModernMember,
    authority_members: []producer.ModernMember,
    selected: producer.Inputs,
    until: std.Io.Clock.Timestamp,
};

pub const OwnedInputs = opaque {
    fn held(self: *const OwnedInputs) *const Held { return @ptrCast(@alignCast(self)); }
    pub fn inputs(self: *const OwnedInputs) producer.Inputs { return self.held().selected; }
    pub fn inputsForInstallation(self: *const OwnedInputs, directory: c.fd_t) producer.Inputs {
        var selected = self.held().selected;
        selected.installation_directory = directory;
        return selected;
    }
    pub fn recheck(self: *const OwnedInputs, io: std.Io) !void {
        try self.recheckIdentity(io);
        const held = self.held();
        const declaration_hex = std.fmt.bytesToHex(held.selected.deployment_declaration.?.sha256,.lower);
        try hash(io,held.until,held.selector_fd,.{.path=selector,.sha256=&declaration_hex,.bytes=held.selected.deployment_declaration.?.bytes});
        for (held.selected_roles,held.descriptors) |role,fd| try hash(io,held.until,fd,role);
        try self.recheckIdentity(io);
    }
    /// Final actor handoff uses only finite held/named metadata; full byte
    /// validation remains in the supervised worker under this original clock.
    pub fn recheckIdentity(self: *const OwnedInputs, io: std.Io) !void {
        const held = self.held();
        try check(io, held.until);
        if (!std.meta.eql(held.root_status, try metadata.statFd(held.root)) or
            !std.meta.eql(held.selector_status, try metadata.statFd(held.selector_fd))) return error.RuntimeSelectionDrift;
        const named_root = try nix.openSelectedDirectory(io, held.allocator, held.until, held.root_path);
        defer _ = c.close(named_root);
        if (!std.meta.eql(held.root_status, try metadata.statFd(named_root))) return error.RuntimeSelectionDrift;
        const named = try openSelector(held.allocator, held.root);
        defer _ = c.close(named);
        if (!std.meta.eql(held.selector_status, try metadata.statFd(named))) return error.RuntimeSelectionDrift;
        for (held.selected_roles, held.descriptors, held.statuses) |role, fd, status| {
            const reopened = try openRelative(held.allocator, held.root, role.path);
            defer _ = c.close(reopened);
            if (!std.meta.eql(status, try metadata.statFd(reopened)) or !std.meta.eql(status, try metadata.statFd(fd))) return error.RuntimeSelectionDrift;
        }
        try check(io, held.until);
    }
    pub fn deinit(self: *OwnedInputs) void {
        const held: *Held = @ptrCast(@alignCast(self));
        for (held.descriptors) |fd| _ = c.close(fd);
        _ = c.close(held.selector_fd);
        _ = c.close(held.root);
        held.parsed.deinit();
        held.allocator.free(held.descriptors);
        held.allocator.free(held.statuses);
        held.allocator.free(held.selected_roles);
        held.allocator.free(held.protocol_members);
        held.allocator.free(held.acquisition_members);
        held.allocator.free(held.authority_members);
        held.allocator.free(held.root_path);
        held.allocator.destroy(held);
    }
};
fn check(io: std.Io, until: std.Io.Clock.Timestamp) !void {
    try io.checkCancel();
    if (until.clock != .awake) return error.InvalidDeadline;
    if (until.durationFromNow(io).raw.toMilliseconds() <= 0) return error.Timeout;
}
fn protected(status: metadata.Metadata, kind: u32) !void {
    if (status.uid != 0 or status.mode & c.S.IFMT != kind or status.mode & 0o7222 != 0) return error.UnsafeDeploymentSelection;
}
fn duplicate(fd: c.fd_t) !c.fd_t {
    const result = c.openat(fd, ".", .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true });
    if (result < 0) return error.DeploymentSelectionUnavailable;
    return result;
}
fn openSelector(allocator: std.mem.Allocator, root: c.fd_t) !c.fd_t {
    return openRelative(allocator, root, selector);
}
fn relative(path: []const u8) !void {
    if (path.len == 0 or path.len > 4096 or path[0] == '/' or path[path.len-1] == '/') return error.InvalidDeploymentSelection;
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        if (part.len == 0 or std.mem.eql(u8,part,".") or std.mem.eql(u8,part,"..")) return error.InvalidDeploymentSelection;
        for (part) |ch| if (ch < 0x20 or ch > 0x7e or ch == '\\') return error.InvalidDeploymentSelection;
    }
}
fn openRelative(allocator: std.mem.Allocator, root: c.fd_t, path: []const u8) !c.fd_t {
    try relative(path);
    var current = try duplicate(root);
    defer _ = c.close(current);
    var parts = std.mem.splitScalar(u8, path, '/');
    while (parts.next()) |part| {
        try protected(try metadata.statFd(current), c.S.IFDIR);
        const name = try allocator.dupeSentinel(u8, part, 0);
        defer allocator.free(name);
        const next = c.openat(current, name.ptr, .{ .DIRECTORY = parts.peek() != null, .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true });
        if (next < 0) return error.DeploymentSelectionUnavailable;
        if (parts.peek() == null) return next;
        _ = c.close(current);
        current = next;
    }
    return error.InvalidDeploymentSelection;
}
fn roles(value: Declaration) [6]Role {
    return .{ value.inputs.archive, value.inputs.manifest, value.inputs.runtime_receipt,
        value.inputs.source_receipt, value.inputs.producer_receipt, value.inputs.registration_receipt };
}
fn roleDigest(role: Role) ![32]u8 {
    try relative(role.path);
    if (role.sha256.len != 64 or role.bytes == 0 or role.bytes > producer.maximum_payload_bytes) return error.InvalidDeploymentSelection;
    for (role.sha256) |ch| if (!std.ascii.isDigit(ch) and !(ch >= 'a' and ch <= 'f')) return error.InvalidDeploymentSelection;
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, role.sha256) catch return error.InvalidDeploymentSelection;
    if (std.mem.allEqual(u8, &result, 0)) return error.InvalidDeploymentSelection;
    return result;
}
fn consistentRole(allocator: std.mem.Allocator, seen: *std.StringHashMapUnmanaged(Role), role: Role) !void {
    const entry = try seen.getOrPut(allocator,role.path);
    if (entry.found_existing) {
        if (entry.value_ptr.bytes != role.bytes or !std.mem.eql(u8,entry.value_ptr.sha256,role.sha256)) return error.InvalidDeploymentSelection;
    } else entry.value_ptr.* = role;
}
fn parseDeclaration(allocator: std.mem.Allocator, raw: []const u8) !std.json.Parsed(Declaration) {
    if (raw.len == 0 or raw.len > maximum_metadata) return error.InvalidDeploymentSelection;
    const parsed = try std.json.parseFromSlice(Declaration,allocator,raw,.{ .duplicate_field_behavior=.@"error", .ignore_unknown_fields=false, .allocate=.alloc_always, .max_value_len=4096 });
    errdefer parsed.deinit();
    const value = parsed.value;
    if (value.schema_version != 2 or !std.mem.eql(u8,value.kind,"omux-native-source-acquisition-deployment-v1") or
        !std.mem.eql(u8,value.target,"x86_64-linux") or !std.mem.eql(u8,value.launch_profile,"linux_nix_direct_main_v1")) return error.InvalidDeploymentSelection;
    const selected = roles(value);
    for (selected,0..) |role,index| {
        _ = try roleDigest(role);
        if (role.bytes > (if (index == 0) producer.maximum_archive_bytes else producer.maximum_metadata_bytes)) return error.InvalidDeploymentSelection;
        for (selected[0..index]) |previous| if (std.mem.eql(u8,previous.path,role.path)) return error.InvalidDeploymentSelection;
    }
    const modern = value.modern_materials orelse return error.InvalidDeploymentSelection;
    if (48 + modern.protocol_schema_files.len + modern.native_acquisition_artifact_files.len > producer.maximum_files) return error.InvalidDeploymentSelection;
    if (!std.mem.startsWith(u8,modern.package_output_root,"/")) return error.InvalidDeploymentSelection;
    try relative(modern.package_output_root[1..]);
    var total: u64 = 0;
    _ = try roleDigest(modern.package_selection);
    if (modern.package_selection.bytes > producer.maximum_metadata_bytes) return error.InvalidDeploymentSelection;
    total = modern.package_selection.bytes;
    _ = try roleDigest(modern.package_outputs);
    if (modern.package_outputs.bytes > maximum_declaration_bytes) return error.InvalidDeploymentSelection;
    total = std.math.add(u64,total,modern.package_outputs.bytes) catch return error.InvalidDeploymentSelection;
    inline for (std.meta.fields(ModernRoles),0..) |field,index| {
        const role = @field(modern.roles,field.name);
        _ = try roleDigest(role);
        if (role.bytes > (if (index == 10) producer.maximum_payload_bytes else producer.maximum_metadata_bytes)) return error.InvalidDeploymentSelection;
        total = std.math.add(u64,total,role.bytes) catch return error.InvalidDeploymentSelection;
    }
    for ([_][]const Member{modern.protocol_schema_files,modern.native_acquisition_artifact_files}) |members| {
        for (members,0..) |member,index| {
            try relative(member.name);
            _ = try roleDigest(.{.path=member.path,.sha256=member.sha256,.bytes=member.bytes});
            if (member.bytes > producer.maximum_metadata_bytes or (index > 0 and std.mem.order(u8,members[index-1].name,member.name) != .lt)) return error.InvalidDeploymentSelection;
            total = std.math.add(u64,total,member.bytes) catch return error.InvalidDeploymentSelection;
        }
    }
    for ([_]AuthorityGroup{modern.authority_receipts.source,modern.authority_receipts.sdk,
        modern.authority_receipts.plan,modern.authority_receipts.query,modern.authority_receipts.compiler,
        modern.package_authority},0..) |group,group_index| {
        if (group.members.len != (if (group_index == 0) 6 else 2)) return error.InvalidDeploymentSelection;
        for ([_]Role{group.outer,group.evidence}) |role| {
            _ = try roleDigest(role);
            if (role.bytes > producer.maximum_metadata_bytes) return error.InvalidDeploymentSelection;
            total = std.math.add(u64,total,role.bytes) catch return error.InvalidDeploymentSelection;
        }
        for (group.members,0..) |member,index| {
            if (member.name.len != 73 or !std.mem.endsWith(u8,member.name,".evidence")) return error.InvalidDeploymentSelection;
            for (member.name[0..64]) |ch| if (!std.ascii.isDigit(ch) and !(ch >= 'a' and ch <= 'f')) return error.InvalidDeploymentSelection;
            if (index > 0 and std.mem.order(u8,group.members[index-1].name,member.name) != .lt) return error.InvalidDeploymentSelection;
            _ = try roleDigest(.{.path=member.path,.sha256=member.sha256,.bytes=member.bytes});
            if (member.bytes > producer.maximum_metadata_bytes or !std.mem.eql(u8,member.name[0..64],member.sha256)) return error.InvalidDeploymentSelection;
            total = std.math.add(u64,total,member.bytes) catch return error.InvalidDeploymentSelection;
        }
    }
    if (total > producer.maximum_payload_bytes) return error.InvalidDeploymentSelection;
    var seen: std.StringHashMapUnmanaged(Role) = .empty;
    defer seen.deinit(allocator);
    for (selected) |role| try consistentRole(allocator,&seen,role);
    try consistentRole(allocator,&seen,modern.package_selection);
    try consistentRole(allocator,&seen,modern.package_outputs);
    inline for (std.meta.fields(ModernRoles)) |field| try consistentRole(allocator,&seen,@field(modern.roles,field.name));
    for ([_][]const Member{modern.protocol_schema_files,modern.native_acquisition_artifact_files}) |members| {
        for (members) |member| try consistentRole(allocator,&seen,.{.path=member.path,.sha256=member.sha256,.bytes=member.bytes});
    }
    for ([_]AuthorityGroup{modern.authority_receipts.source,modern.authority_receipts.sdk,
        modern.authority_receipts.plan,modern.authority_receipts.query,modern.authority_receipts.compiler,
        modern.package_authority}) |group| {
        try consistentRole(allocator,&seen,group.outer);
        try consistentRole(allocator,&seen,group.evidence);
        for (group.members) |member| try consistentRole(allocator,&seen,.{.path=member.path,.sha256=member.sha256,.bytes=member.bytes});
    }
    return parsed;
}
fn hash(io: std.Io, until: std.Io.Clock.Timestamp, fd: c.fd_t, role: Role) !void {
    const expected = try roleDigest(role);
    const before = try metadata.statFd(fd);
    try protected(before, c.S.IFREG);
    if (before.nlink < 1 or before.size < 0 or @as(u64,@intCast(before.size)) != role.bytes) return error.RuntimeSelectionDrift;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64*1024]u8 = undefined;
    var cursor: u64 = 0;
    while (cursor < role.bytes) {
        try check(io, until);
        const count = c.pread(fd, &buffer, @min(buffer.len, role.bytes-cursor), @intCast(cursor));
        if (count < 0 and c.errno(count) == .INTR) continue;
        if (count <= 0) return error.RuntimeSelectionDrift;
        hasher.update(buffer[0..@intCast(count)]);
        cursor += @intCast(count);
    }
    var actual: [32]u8 = undefined;
    hasher.final(&actual);
    if (!std.meta.eql(actual, expected) or !std.meta.eql(before, try metadata.statFd(fd))) return error.RuntimeSelectionDrift;
}

/// Registered package root is selected by explicit typed daemon configuration
/// and retained before control admission. The caller retains installation FD.
pub fn load(io: std.Io, allocator: std.mem.Allocator, registered: RegisteredDeployment, until: std.Io.Clock.Timestamp) !*OwnedInputs {
    try check(io, until);
    const root = try duplicate(registered.descriptor);
    errdefer _ = c.close(root);
    const root_status = try metadata.statFd(root);
    try protected(root_status,c.S.IFDIR);
    const named_root = try nix.openSelectedDirectory(io, allocator, until, registered.path);
    defer _ = c.close(named_root);
    if (!std.meta.eql(root_status, try metadata.statFd(named_root))) return error.RuntimeSelectionDrift;
    const root_path = try allocator.dupe(u8, registered.path);
    errdefer allocator.free(root_path);
    const selector_fd = try openSelector(allocator,root);
    errdefer _ = c.close(selector_fd);
    const status = try metadata.statFd(selector_fd);
    try protected(status,c.S.IFREG);
    if (status.nlink < 1 or status.size <= 0 or status.size > maximum_metadata) return error.InvalidDeploymentSelection;
    const raw = try allocator.alloc(u8,@intCast(status.size));
    defer allocator.free(raw);
    var cursor: usize = 0;
    while (cursor < raw.len) {
        try check(io,until);
        const count = c.pread(selector_fd,raw[cursor..].ptr,raw.len-cursor,@intCast(cursor));
        if (count < 0 and c.errno(count) == .INTR) continue;
        if (count <= 0) return error.RuntimeSelectionDrift;
        cursor += @intCast(count);
    }
    if (!std.meta.eql(status,try metadata.statFd(selector_fd))) return error.RuntimeSelectionDrift;
    const parsed = try parseDeclaration(allocator,raw);
    errdefer parsed.deinit();
    const value = parsed.value;
    const modern = value.modern_materials.?;
    const authority_count = 28;
    const count = 20 + modern.protocol_schema_files.len + modern.native_acquisition_artifact_files.len + authority_count;
    const descriptors = try allocator.alloc(c.fd_t,count);
    errdefer allocator.free(descriptors);
    @memset(descriptors,-1);
    errdefer for (descriptors) |fd| { if (fd >= 0) _ = c.close(fd); };
    const statuses = try allocator.alloc(metadata.Metadata,count);
    errdefer allocator.free(statuses);
    const selected_roles = try allocator.alloc(Role,count);
    errdefer allocator.free(selected_roles);
    const base_roles = roles(value);
    @memcpy(selected_roles[0..6],&base_roles);
    inline for (std.meta.fields(ModernRoles),0..) |field,index| selected_roles[6+index] = @field(modern.roles,field.name);
    for (modern.protocol_schema_files,0..) |member,index| selected_roles[18+index] = .{.path=member.path,.sha256=member.sha256,.bytes=member.bytes};
    for (modern.native_acquisition_artifact_files,0..) |member,index| selected_roles[18+modern.protocol_schema_files.len+index] = .{.path=member.path,.sha256=member.sha256,.bytes=member.bytes};
    const authority_start = 18 + modern.protocol_schema_files.len + modern.native_acquisition_artifact_files.len;
    var authority_cursor: usize = authority_start;
    inline for (std.meta.fields(Authorities)) |field| {
        const group = @field(modern.authority_receipts,field.name);
        selected_roles[authority_cursor] = group.outer;
        selected_roles[authority_cursor+1] = group.evidence;
        authority_cursor += 2;
        for (group.members) |member| {
            selected_roles[authority_cursor] = .{.path=member.path,.sha256=member.sha256,.bytes=member.bytes};
            authority_cursor += 1;
        }
    }
    selected_roles[authority_cursor] = modern.package_authority.outer;
    selected_roles[authority_cursor+1] = modern.package_authority.evidence;
    authority_cursor += 2;
    for (modern.package_authority.members) |member| {
        selected_roles[authority_cursor] = .{.path=member.path,.sha256=member.sha256,.bytes=member.bytes};
        authority_cursor += 1;
    }
    selected_roles[count-2] = modern.package_selection;
    selected_roles[count-1] = modern.package_outputs;
    const inputs = try allocator.alloc(producer.Input,count);
    defer allocator.free(inputs);
    for (selected_roles,0..) |role,index| {
        const digest = try roleDigest(role);
        const fd = try openRelative(allocator,root,role.path);
        descriptors[index] = fd;
        try hash(io,until,fd,role);
        statuses[index] = try metadata.statFd(fd);
        inputs[index] = .{ .descriptor=fd,.sha256=digest,.bytes=role.bytes };
    }
    const protocol_members = try allocator.alloc(producer.ModernMember,modern.protocol_schema_files.len);
    errdefer allocator.free(protocol_members);
    const acquisition_members = try allocator.alloc(producer.ModernMember,modern.native_acquisition_artifact_files.len);
    errdefer allocator.free(acquisition_members);
    const authority_members = try allocator.alloc(producer.ModernMember,16);
    errdefer allocator.free(authority_members);
    for (modern.protocol_schema_files,0..) |member,index| protocol_members[index] = .{.name=member.name,.input=inputs[18+index]};
    for (modern.native_acquisition_artifact_files,0..) |member,index| acquisition_members[index] = .{.name=member.name,.input=inputs[18+protocol_members.len+index]};
    var modern_inputs: [12]producer.Input = undefined;
    @memcpy(&modern_inputs,inputs[6..18]);
    var authorities: [5]producer.ModernAuthority = undefined;
    authority_cursor = authority_start;
    var member_cursor: usize = 0;
    inline for (std.meta.fields(Authorities),0..) |field,index| {
        const group = @field(modern.authority_receipts,field.name);
        const first = member_cursor;
        authorities[index] = .{.outer=inputs[authority_cursor],.evidence=inputs[authority_cursor+1],.members=authority_members[first..first+group.members.len]};
        authority_cursor += 2;
        for (group.members) |member| {
            authority_members[member_cursor] = .{.name=member.name,.input=inputs[authority_cursor]};
            member_cursor += 1; authority_cursor += 1;
        }
    }
    const package_authority: producer.ModernAuthority = .{.outer=inputs[authority_cursor],.evidence=inputs[authority_cursor+1],.members=authority_members[14..16]};
    authority_cursor += 2;
    for (modern.package_authority.members) |member| {
        authority_members[member_cursor] = .{.name=member.name,.input=inputs[authority_cursor]};
        member_cursor += 1; authority_cursor += 1;
    }
    var declaration_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw,&declaration_digest,.{});
    const held = try allocator.create(Held);
    errdefer allocator.destroy(held);
    held.* = .{ .allocator=allocator,.root=root,.root_status=root_status,.root_path=root_path,.selector_fd=selector_fd,.selector_status=status,
        .parsed=parsed,.descriptors=descriptors,.statuses=statuses,.selected_roles=selected_roles,.protocol_members=protocol_members,.acquisition_members=acquisition_members,.authority_members=authority_members,.until=until,
        .selected=.{ .archive=inputs[0],.manifest=inputs[1],.runtime_receipt=inputs[2],
            .source_receipt=inputs[3],.producer_receipt=inputs[4],.registration_receipt=inputs[5],.installation_directory=-1,
            .modern_materials=.{.package_selection=inputs[count-2],.package_outputs=inputs[count-1],.package_output_root=modern.package_output_root,.package_authority=package_authority,.roles=modern_inputs,.protocol_schema_files=protocol_members,.native_acquisition_artifact_files=acquisition_members,.authority_receipts=authorities},
            .deployment_root=.{.path=root_path,.descriptor=root},
            .deployment_declaration=.{.descriptor=selector_fd,.sha256=declaration_digest,.bytes=raw.len} } };
    const owned: *OwnedInputs = @ptrCast(held);
    try owned.recheck(io);
    return owned;
}

/// Restore checks immutable producer-selected bytes, not another constructor
/// or an incoming declaration. The encrypted record owns both witnesses.
pub fn recheckWitness(io: std.Io, allocator: std.mem.Allocator, until: std.Io.Clock.Timestamp, root: nix.Root, declaration: nix.File) !void {
    try check(io,until);
    const expected_path = try std.fmt.allocPrint(allocator,"{s}/{s}",.{root.path,selector});
    defer allocator.free(expected_path);
    if (!std.mem.eql(u8,declaration.path,expected_path)) return error.InvalidDeploymentSelection;
    const fd = try nix.openSelectedDirectory(io,allocator,until,root.path);
    defer _ = c.close(fd);
    if (!std.meta.eql(root.status,try metadata.statFd(fd))) return error.RuntimeSelectionDrift;
    const selected = try load(io,allocator,.{.path=root.path,.descriptor=fd},until);
    defer selected.deinit();
    const held = selected.held();
    const raw_input = held.selected.deployment_declaration.?;
    if (!std.meta.eql(declaration.status,held.selector_status) or declaration.bytes != raw_input.bytes or
        !std.meta.eql(declaration.sha256,raw_input.sha256)) return error.RuntimeSelectionDrift;
    try selected.recheck(io);
    try check(io,until);
}

test "fleet deployment selector rejects an observation profile and duplicate role paths before file access" {
    const allocator = std.testing.allocator;
    const bytes = try std.json.Stringify.valueAlloc(allocator, Declaration{
        .schema_version=1,.kind="omux-native-source-acquisition-deployment-v1",.target="x86_64-linux",.launch_profile="linux_explicit_bundled_loader_v1",
        .inputs=.{ .archive=.{.path="/unselected",.sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",.bytes=1},
            .manifest=.{.path="/unselected",.sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",.bytes=1},
            .runtime_receipt=.{.path="/unselected",.sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",.bytes=1},
            .source_receipt=.{.path="/unselected",.sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",.bytes=1},
            .producer_receipt=.{.path="/unselected",.sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",.bytes=1},
            .registration_receipt=.{.path="/unselected",.sha256="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",.bytes=1} } }, .{});
    defer allocator.free(bytes);
    try std.testing.expectError(error.InvalidDeploymentSelection,parseDeclaration(allocator,bytes));
    const parsed = try std.json.parseFromSlice(Declaration,allocator,bytes,.{});
    defer parsed.deinit();
    var declaration = parsed.value;
    declaration.launch_profile="linux_nix_direct_main_v1";
    const direct = try std.json.Stringify.valueAlloc(allocator,declaration,.{});
    defer allocator.free(direct);
    try std.testing.expectError(error.InvalidDeploymentSelection,parseDeclaration(allocator,direct));
}

test "fleet deployment selector refuses expired original clock without borrowing inputs" {
    const until: std.Io.Clock.Timestamp = .fromNow(std.testing.io,.{ .clock=.awake,.raw=.fromMilliseconds(-1) });
    try std.testing.expectError(error.Timeout,load(std.testing.io,std.testing.allocator,.{.path="/unselected",.descriptor=-1},until));
}

test "actual declaration parser binds distinct package output input and canonical original namespace" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const digest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const role: Role = .{.path="selected/shared.json",.sha256=digest,.bytes=1};
    var members: [6]Member = undefined;
    for (&members,0..) |*member,index| {
        const sha = try std.fmt.allocPrint(allocator,"{x:0>64}",.{index+1});
        member.* = .{.name=try std.fmt.allocPrint(allocator,"{s}.evidence",.{sha}),
            .path=try std.fmt.allocPrint(allocator,"selected/{s}.evidence",.{sha}),.sha256=sha,.bytes=1};
    }
    const group: AuthorityGroup = .{.outer=role,.evidence=role,.members=members[0..2]};
    var modern_roles: ModernRoles = undefined;
    inline for (std.meta.fields(ModernRoles)) |field| @field(modern_roles,field.name)=role;
    var value: Declaration = .{.schema_version=2,.kind="omux-native-source-acquisition-deployment-v1",
        .target="x86_64-linux",.launch_profile="linux_nix_direct_main_v1",
        .inputs=undefined,.modern_materials=.{.package_selection=role,
            .package_outputs=.{.path="selected/package-outputs.json",.sha256=digest,.bytes=1},
            .package_output_root="/home/model/public/output-base/test.outputs/fresh-native-runtime",
            .package_authority=group,.roles=modern_roles,
            .protocol_schema_files=&.{},.native_acquisition_artifact_files=&.{},
            .authority_receipts=.{.source=.{.outer=role,.evidence=role,.members=&members},
                .sdk=group,.plan=group,.query=group,.compiler=group}}};
    inline for (std.meta.fields(@TypeOf(value.inputs))) |field| {
        @field(value.inputs,field.name)=.{.path=try std.fmt.allocPrint(allocator,"selected/{s}.json",.{field.name}),.sha256=digest,.bytes=1};
    }
    const accepted_raw = try std.json.Stringify.valueAlloc(allocator,value,.{});
    const accepted = try parseDeclaration(allocator,accepted_raw);
    accepted.deinit();
    value.modern_materials.?.package_output_root="relative/output";
    try std.testing.expectError(error.InvalidDeploymentSelection,
        parseDeclaration(allocator,try std.json.Stringify.valueAlloc(allocator,value,.{})));
    value.modern_materials.?.package_output_root="/home/model/../output";
    try std.testing.expectError(error.InvalidDeploymentSelection,
        parseDeclaration(allocator,try std.json.Stringify.valueAlloc(allocator,value,.{})));
    value.modern_materials.?.package_output_root="/home/model/public/output";
    value.modern_materials.?.package_outputs.bytes=maximum_declaration_bytes+1;
    try std.testing.expectError(error.InvalidDeploymentSelection,
        parseDeclaration(allocator,try std.json.Stringify.valueAlloc(allocator,value,.{})));
    value.modern_materials.?.package_outputs=role;
    value.modern_materials.?.package_outputs.bytes=2;
    try std.testing.expectError(error.InvalidDeploymentSelection,
        parseDeclaration(allocator,try std.json.Stringify.valueAlloc(allocator,value,.{})));
}
