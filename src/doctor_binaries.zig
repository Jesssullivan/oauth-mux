//! doctor "binaries" section (TIN-2723): version/SHA truth for the resident
//! keepalive service and the PATH-resolved oauth-mux, plus stale-binary and
//! PATH-shadow detection. Split from the service-residency proof in TIN-1830.
//!
//! Design notes:
//!  * The PATH scan never *executes* a found binary to enumerate it — it only
//!    stats + checks the execute bit (access X_OK). Executing a discovered
//!    `oauth-mux` is confined to the version fallback below.
//!  * Version is resolved WITHOUT exec whenever possible: for our own binary we
//!    already know `cli.version`, and for any file whose SHA-256 matches ours we
//!    reuse it. Only a genuinely-different binary triggers a bounded
//!    `<path> version --json` subprocess (short watchdog-killed timeout,
//!    tolerant of old binaries that predate the subcommand → version "unknown").
//!  * Every gather step is catch-guarded: a missing plist, an unreadable file,
//!    or an exec failure produces informative nulls — the doctor overall stays
//!    ok and never errors out of this section.

const std = @import("std");
const builtin = @import("builtin");
const runtime = @import("runtime.zig");
const env = @import("env.zig");

pub const keepalive_label = "dev.xoxd.omux.keepalive";
pub const keepalive_plist_rel = "Library/LaunchAgents/dev.xoxd.omux.keepalive.plist";

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

pub const BinaryFacts = struct {
    path: []const u8,
    exists: bool,
    sha256: ?[]const u8,
    version: ?[]const u8,
    /// how `version` was resolved: "self" | "sha_match_self" | "subprocess" | "unknown"
    version_source: []const u8,
    /// classifyOauthMuxBinarySource: repo_local | user_local | homebrew | nix_store | npm | path_or_installed
    source: []const u8,
};

pub const ResidentInfo = struct {
    /// launchd is darwin-only; false on other platforms (section still renders).
    supported: bool,
    label: []const u8,
    plist_path: []const u8,
    plist_present: bool,
    program_path: ?[]const u8,
    binary: ?BinaryFacts,
};

pub const ShadowVerdict = struct {
    /// > 1 distinct SHA across the oauth-mux binaries on PATH.
    shadowed: bool,
    distinct_sha_count: usize,
};

pub const StaleInputs = struct {
    resident_sha: ?[]const u8,
    resident_version: ?[]const u8,
    /// PATH-winner ("installed") reference.
    installed_sha: ?[]const u8,
    installed_version: ?[]const u8,
    /// the running doctor binary's version.
    self_version: ?[]const u8,
};

pub const StaleVerdict = struct {
    stale: bool,
    sha_mismatch: bool,
    version_older: bool,
    reason: []const u8,
};

pub const BinariesReport = struct {
    self: BinaryFacts,
    path_env_present: bool,
    path_entries: []const BinaryFacts,
    path_winner: ?BinaryFacts,
    shadow: ShadowVerdict,
    resident: ?ResidentInfo,
    stale: StaleVerdict,
};

pub const GatherOptions = struct {
    /// Allow the `<path> version --json` subprocess fallback. Tests set false.
    exec_versions: bool = true,
    version_exec_timeout_ms: u64 = 2000,
};

// ---------------------------------------------------------------------------
// Pure core: PATH scan
// ---------------------------------------------------------------------------

pub const ExecCheck = *const fn (ctx: *anyopaque, path: []const u8) bool;

pub const PathScan = struct {
    /// Full paths to executable oauth-mux binaries, in PATH order, deduped.
    paths: []const []const u8,

    pub fn winner(self: PathScan) ?[]const u8 {
        return if (self.paths.len > 0) self.paths[0] else null;
    }
};

/// Pure over `path_env`: splits on `delimiter`, joins each non-empty dir with
/// `binary_name`, and keeps the ones the injected `check` marks executable.
/// The first survivor wins (PATH precedence). Exact-duplicate paths collapse.
/// No side effects beyond allocation; callers pass an arena.
pub fn scanPath(
    allocator: std.mem.Allocator,
    path_env: []const u8,
    delimiter: u8,
    binary_name: []const u8,
    ctx: *anyopaque,
    check: ExecCheck,
) !PathScan {
    var list = std.ArrayList([]const u8).init(allocator);
    errdefer list.deinit();

    var it = std.mem.splitScalar(u8, path_env, delimiter);
    while (it.next()) |dir| {
        if (dir.len == 0) continue;
        const candidate = try std.fs.path.join(allocator, &.{ dir, binary_name });
        if (!check(ctx, candidate)) continue;
        var dup = false;
        for (list.items) |seen| {
            if (std.mem.eql(u8, seen, candidate)) {
                dup = true;
                break;
            }
        }
        if (!dup) try list.append(candidate);
    }

    return .{ .paths = try list.toOwnedSlice() };
}

/// Count of distinct non-null SHAs — the PATH-shadow signal.
pub fn distinctShaCount(shas: []const ?[]const u8) usize {
    var count: usize = 0;
    var i: usize = 0;
    outer: while (i < shas.len) : (i += 1) {
        const s = shas[i] orelse continue;
        var j: usize = 0;
        while (j < i) : (j += 1) {
            if (shas[j]) |prev| {
                if (std.mem.eql(u8, prev, s)) continue :outer;
            }
        }
        count += 1;
    }
    return count;
}

// ---------------------------------------------------------------------------
// Pure core: version compare + staleness
// ---------------------------------------------------------------------------

pub const Ordering = enum { lt, eq, gt, unknown };

/// Offline, numeric semver compare over the first three dotted components.
/// Tolerant of a leading 'v' and of trailing build suffixes (`0.1.14-5-gabc`
/// compares as `0.1.14`). Any non-numeric component → `.unknown`.
pub fn compareSemver(a_in: []const u8, b_in: []const u8) Ordering {
    const a = std.mem.trimLeft(u8, a_in, "v");
    const b = std.mem.trimLeft(u8, b_in, "v");
    var ai = std.mem.splitScalar(u8, a, '.');
    var bi = std.mem.splitScalar(u8, b, '.');
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        const av = parseLeadingUint(ai.next() orelse "0") orelse return .unknown;
        const bv = parseLeadingUint(bi.next() orelse "0") orelse return .unknown;
        if (av < bv) return .lt;
        if (av > bv) return .gt;
    }
    return .eq;
}

fn parseLeadingUint(s: []const u8) ?u64 {
    var end: usize = 0;
    while (end < s.len and s[end] >= '0' and s[end] <= '9') : (end += 1) {}
    if (end == 0) return null;
    return std.fmt.parseInt(u64, s[0..end], 10) catch null;
}

/// Offline staleness verdict for the resident keepalive binary. Stale when its
/// SHA differs from the installed (PATH-winner) binary, or its version is older
/// than the installed binary or the running doctor. Absent/unreadable resident
/// → not stale (informative, never a false alarm).
pub fn evaluateStaleness(in: StaleInputs) StaleVerdict {
    if (in.resident_sha == null and in.resident_version == null) {
        return .{
            .stale = false,
            .sha_mismatch = false,
            .version_older = false,
            .reason = "no_resident_or_unreadable",
        };
    }

    var sha_mismatch = false;
    if (in.resident_sha) |rs| {
        if (in.installed_sha) |is| sha_mismatch = !std.mem.eql(u8, rs, is);
    }

    var version_older = false;
    if (in.resident_version) |rv| {
        if (in.installed_version) |iv| {
            if (compareSemver(rv, iv) == .lt) version_older = true;
        }
        if (in.self_version) |sv| {
            if (compareSemver(rv, sv) == .lt) version_older = true;
        }
    }

    const stale = sha_mismatch or version_older;
    const reason: []const u8 = if (sha_mismatch and version_older)
        "resident_sha_differs_and_version_older"
    else if (sha_mismatch)
        "resident_sha_differs_from_installed"
    else if (version_older)
        "resident_version_older"
    else
        "in_sync";

    return .{
        .stale = stale,
        .sha_mismatch = sha_mismatch,
        .version_older = version_older,
        .reason = reason,
    };
}

// ---------------------------------------------------------------------------
// Pure core: LaunchAgent plist parse
// ---------------------------------------------------------------------------

/// Extract ProgramArguments[0] (the program path) from a LaunchAgent plist.
/// Tolerant: any missing marker → null (no error). Used only for reporting.
pub fn parseLaunchAgentProgramPath(allocator: std.mem.Allocator, contents: []const u8) !?[]const u8 {
    const pa = std.mem.indexOf(u8, contents, "ProgramArguments") orelse return null;
    const after_pa = contents[pa..];
    const arr = std.mem.indexOf(u8, after_pa, "<array>") orelse return null;
    const after_arr = after_pa[arr + "<array>".len ..];
    const s_open = std.mem.indexOf(u8, after_arr, "<string>") orelse return null;
    const after_open = after_arr[s_open + "<string>".len ..];
    const s_close = std.mem.indexOf(u8, after_open, "</string>") orelse return null;
    const trimmed = std.mem.trim(u8, after_open[0..s_close], " \t\r\n");
    if (trimmed.len == 0) return null;
    return try allocator.dupe(u8, trimmed);
}

// ---------------------------------------------------------------------------
// Effectful gather
// ---------------------------------------------------------------------------

/// Build the full binaries report. Every step is catch-guarded; on total
/// failure the caller renders "unavailable" and the doctor stays ok.
pub fn gather(arena: std.mem.Allocator, self_version: []const u8, opts: GatherOptions) !BinariesReport {
    // Self.
    const self_path = std.fs.selfExePathAlloc(arena) catch try arena.dupe(u8, "unknown");
    const self_known = !std.mem.eql(u8, self_path, "unknown");
    const self_sha: ?[]const u8 = if (self_known) (runtime.hashFileSha256Hex(arena, self_path) catch null) else null;
    const self_facts = BinaryFacts{
        .path = self_path,
        .exists = self_known,
        .sha256 = self_sha,
        .version = try arena.dupe(u8, self_version),
        .version_source = "self",
        .source = runtime.classifyOauthMuxBinarySource(self_path),
    };

    // PATH scan.
    const path_env = std.process.getEnvVarOwned(arena, "PATH") catch null;
    const path_present = path_env != null and path_env.?.len > 0;
    var entries = std.ArrayList(BinaryFacts).init(arena);
    if (path_env) |pe| {
        var scan_ctx: u8 = 0;
        const scan = scanPath(arena, pe, pathDelimiter(), "oauth-mux", &scan_ctx, realExecCheck) catch PathScan{ .paths = &.{} };
        for (scan.paths) |p| {
            try entries.append(factsFor(arena, p, self_sha, self_version, opts));
        }
    }
    const entries_slice = try entries.toOwnedSlice();
    const winner: ?BinaryFacts = if (entries_slice.len > 0) entries_slice[0] else null;

    // PATH shadow.
    var shas = std.ArrayList(?[]const u8).init(arena);
    for (entries_slice) |f| try shas.append(f.sha256);
    const distinct = distinctShaCount(shas.items);

    // Resident service.
    const resident = gatherResident(arena, self_sha, self_version, opts) catch null;

    // Staleness.
    const resident_binary: ?BinaryFacts = if (resident) |res| res.binary else null;
    const stale = evaluateStaleness(.{
        .resident_sha = if (resident_binary) |b| b.sha256 else null,
        .resident_version = if (resident_binary) |b| b.version else null,
        .installed_sha = if (winner) |w| w.sha256 else null,
        .installed_version = if (winner) |w| w.version else null,
        .self_version = self_version,
    });

    return .{
        .self = self_facts,
        .path_env_present = path_present,
        .path_entries = entries_slice,
        .path_winner = winner,
        .shadow = .{ .shadowed = distinct > 1, .distinct_sha_count = distinct },
        .resident = resident,
        .stale = stale,
    };
}

fn gatherResident(arena: std.mem.Allocator, self_sha: ?[]const u8, self_version: []const u8, opts: GatherOptions) !?ResidentInfo {
    if (builtin.os.tag != .macos) {
        return ResidentInfo{
            .supported = false,
            .label = keepalive_label,
            .plist_path = "",
            .plist_present = false,
            .program_path = null,
            .binary = null,
        };
    }

    const home = (env.get(arena, "HOME") catch null) orelse return ResidentInfo{
        .supported = true,
        .label = keepalive_label,
        .plist_path = "",
        .plist_present = false,
        .program_path = null,
        .binary = null,
    };

    const plist_path = try std.fs.path.join(arena, &.{ home, keepalive_plist_rel });
    const contents = std.fs.cwd().readFileAlloc(arena, plist_path, 256 * 1024) catch {
        return ResidentInfo{
            .supported = true,
            .label = keepalive_label,
            .plist_path = plist_path,
            .plist_present = false,
            .program_path = null,
            .binary = null,
        };
    };

    const program = parseLaunchAgentProgramPath(arena, contents) catch null;
    const binary: ?BinaryFacts = if (program) |p| factsFor(arena, p, self_sha, self_version, opts) else null;

    return ResidentInfo{
        .supported = true,
        .label = keepalive_label,
        .plist_path = plist_path,
        .plist_present = true,
        .program_path = program,
        .binary = binary,
    };
}

fn factsFor(arena: std.mem.Allocator, path: []const u8, self_sha: ?[]const u8, self_version: []const u8, opts: GatherOptions) BinaryFacts {
    const exists = isRegularExecutable(path);
    const sha: ?[]const u8 = if (exists) (runtime.hashFileSha256Hex(arena, path) catch null) else null;

    var version: ?[]const u8 = null;
    var version_source: []const u8 = "unknown";
    if (exists) {
        if (self_sha != null and sha != null and std.mem.eql(u8, self_sha.?, sha.?)) {
            // Same bytes as us — reuse our own version, no exec.
            version = arena.dupe(u8, self_version) catch null;
            if (version != null) version_source = "sha_match_self";
        } else if (opts.exec_versions) {
            version = runVersionJsonBounded(arena, path, opts.version_exec_timeout_ms);
            if (version != null) version_source = "subprocess";
        }
    }

    return .{
        .path = arena.dupe(u8, path) catch path,
        .exists = exists,
        .sha256 = sha,
        .version = version,
        .version_source = version_source,
        .source = runtime.classifyOauthMuxBinarySource(path),
    };
}

fn realExecCheck(_: *anyopaque, path: []const u8) bool {
    return isRegularExecutable(path);
}

/// Stat + execute-bit check only (never runs the file).
fn isRegularExecutable(path: []const u8) bool {
    const st = std.fs.cwd().statFile(path) catch return false;
    if (st.kind != .file) return false;
    if (builtin.os.tag == .windows) return true;
    std.posix.access(path, std.posix.X_OK) catch return false;
    return true;
}

fn pathDelimiter() u8 {
    return if (builtin.os.tag == .windows) ';' else ':';
}

// ---------------------------------------------------------------------------
// Bounded `<path> version --json` subprocess (version fallback)
// ---------------------------------------------------------------------------

/// Run `<path> version --json` with a watchdog-enforced timeout and parse the
/// top-level "version" field. Tolerant of every failure mode (spawn error,
/// non-zero exit, killed by timeout, missing subcommand, unparsable output) →
/// returns null so an old resident binary reports "unknown" rather than
/// erroring the doctor.
fn runVersionJsonBounded(allocator: std.mem.Allocator, path: []const u8, timeout_ms: u64) ?[]const u8 {
    var child = std.process.Child.init(&.{ path, "version", "--json" }, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    child.spawn() catch return null;

    // POSIX: a watchdog thread kills the child if it overruns; the resulting
    // pipe EOF unblocks the read below. Windows: best-effort, no watchdog.
    var wctx = WatchCtx{
        .pid = child.id,
        .timeout_ms = timeout_ms,
        .done = std.atomic.Value(bool).init(false),
    };
    const watch_thread: ?std.Thread = if (builtin.os.tag == .windows)
        null
    else
        std.Thread.spawn(.{}, watchdogRun, .{&wctx}) catch null;

    const stdout_data: ?[]u8 = if (child.stdout) |so|
        so.reader().readAllAlloc(allocator, 64 * 1024) catch null
    else
        null;

    const term = child.wait() catch {
        wctx.done.store(true, .release);
        if (watch_thread) |t| t.join();
        if (stdout_data) |d| allocator.free(d);
        return null;
    };
    wctx.done.store(true, .release);
    if (watch_thread) |t| t.join();

    const clean = switch (term) {
        .Exited => |code| code == 0,
        else => false,
    };
    const data = stdout_data orelse return null;
    defer allocator.free(data);
    if (!clean) return null;
    return parseVersionField(allocator, data);
}

const WatchCtx = struct {
    pid: if (builtin.os.tag == .windows) void else std.posix.pid_t,
    timeout_ms: u64,
    done: std.atomic.Value(bool),
};

fn watchdogRun(ctx: *WatchCtx) void {
    if (builtin.os.tag == .windows) return;
    const step_ms: u64 = 10;
    var waited: u64 = 0;
    while (waited < ctx.timeout_ms) : (waited += step_ms) {
        if (ctx.done.load(.acquire)) return;
        std.time.sleep(step_ms * std.time.ns_per_ms);
    }
    if (!ctx.done.load(.acquire)) {
        std.posix.kill(ctx.pid, std.posix.SIG.KILL) catch {};
    }
}

fn parseVersionField(allocator: std.mem.Allocator, data: []const u8) ?[]const u8 {
    const Shape = struct { version: []const u8 };
    const parsed = std.json.parseFromSlice(Shape, allocator, data, .{ .ignore_unknown_fields = true }) catch return null;
    defer parsed.deinit();
    if (parsed.value.version.len == 0) return null;
    return allocator.dupe(u8, parsed.value.version) catch null;
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

pub fn writeJson(report: ?BinariesReport, writer: anytype) !void {
    try writer.writeAll("\"binaries\":");
    const r = report orelse {
        try writer.writeAll("{\"available\":false}");
        return;
    };

    try writer.writeAll("{\"available\":true,\"path_env_present\":");
    try writer.writeAll(if (r.path_env_present) "true" else "false");

    try writer.writeAll(",\"self\":");
    try writeFactsJson(writer, r.self);

    try writer.writeAll(",\"path_winner\":");
    if (r.path_winner) |w| try writeFactsJson(writer, w) else try writer.writeAll("null");

    try writer.writeAll(",\"path_entries\":[");
    for (r.path_entries, 0..) |f, i| {
        if (i > 0) try writer.writeByte(',');
        try writeFactsJson(writer, f);
    }
    try writer.writeAll("]");

    try writer.print(",\"path_shadow\":{{\"shadowed\":{s},\"distinct_sha_count\":{d}}}", .{
        if (r.shadow.shadowed) "true" else "false",
        r.shadow.distinct_sha_count,
    });

    try writer.writeAll(",\"resident\":");
    if (r.resident) |res| {
        try writer.writeAll("{\"supported\":");
        try writer.writeAll(if (res.supported) "true" else "false");
        try writer.writeAll(",\"label\":");
        try std.json.stringify(res.label, .{}, writer);
        try writer.writeAll(",\"plist_path\":");
        try std.json.stringify(res.plist_path, .{}, writer);
        try writer.writeAll(",\"plist_present\":");
        try writer.writeAll(if (res.plist_present) "true" else "false");
        try writer.writeAll(",\"program_path\":");
        if (res.program_path) |p| try std.json.stringify(p, .{}, writer) else try writer.writeAll("null");
        try writer.writeAll(",\"binary\":");
        if (res.binary) |bf| try writeFactsJson(writer, bf) else try writer.writeAll("null");
        try writer.writeByte('}');
    } else {
        try writer.writeAll("null");
    }

    try writer.print(",\"stale\":{{\"stale\":{s},\"sha_mismatch\":{s},\"version_older\":{s},\"reason\":", .{
        if (r.stale.stale) "true" else "false",
        if (r.stale.sha_mismatch) "true" else "false",
        if (r.stale.version_older) "true" else "false",
    });
    try std.json.stringify(r.stale.reason, .{}, writer);
    try writer.writeAll("}}");
}

fn writeFactsJson(writer: anytype, f: BinaryFacts) !void {
    try writer.writeAll("{\"path\":");
    try std.json.stringify(f.path, .{}, writer);
    try writer.writeAll(",\"exists\":");
    try writer.writeAll(if (f.exists) "true" else "false");
    try writer.writeAll(",\"sha256\":");
    if (f.sha256) |s| try std.json.stringify(s, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"version\":");
    if (f.version) |v| try std.json.stringify(v, .{}, writer) else try writer.writeAll("null");
    try writer.writeAll(",\"version_source\":");
    try std.json.stringify(f.version_source, .{}, writer);
    try writer.writeAll(",\"source\":");
    try std.json.stringify(f.source, .{}, writer);
    try writer.writeByte('}');
}

pub fn writeText(report: ?BinariesReport, writer: anytype) !void {
    try writer.writeAll("\n  binaries:\n");
    const r = report orelse {
        try writer.writeAll("    unavailable (could not gather binary facts)\n");
        return;
    };

    try writer.writeAll("    self:        ");
    try writeFactsLine(writer, r.self);

    if (r.path_winner) |w| {
        try writer.writeAll("    path winner: ");
        try writeFactsLine(writer, w);
    } else {
        try writer.print("    path winner: none on PATH{s}\n", .{
            if (r.path_env_present) "" else " (PATH unset)",
        });
    }

    try writer.print("    path entries: {d}\n", .{r.path_entries.len});
    for (r.path_entries, 0..) |f, idx| {
        try writer.print("      {d}. ", .{idx + 1});
        try writeFactsLine(writer, f);
    }

    if (r.resident) |res| {
        if (!res.supported) {
            try writer.writeAll("    resident service: not supported on this platform (launchd is darwin-only)\n");
        } else {
            try writer.print("    resident service: {s}\n", .{res.label});
            try writer.print("      plist:   {s} ({s})\n", .{
                if (res.plist_path.len == 0) "(HOME unset)" else res.plist_path,
                if (res.plist_present) "present" else "absent",
            });
            if (res.binary) |bf| {
                try writer.writeAll("      program: ");
                try writeFactsLine(writer, bf);
            } else if (res.plist_present) {
                try writer.writeAll("      program: (could not parse program path from plist)\n");
            } else {
                try writer.writeAll("      program: (no resident service)\n");
            }
        }
    }

    if (r.stale.stale) {
        try writer.print("    WARN: resident keepalive binary is stale ({s}); reload the service after installing a new binary\n", .{r.stale.reason});
    }
    if (r.shadow.shadowed) {
        try writer.print("    WARN: PATH shadow — {d} distinct oauth-mux binaries on PATH; winner: {s}\n", .{
            r.shadow.distinct_sha_count,
            if (r.path_winner) |w| w.path else "unknown",
        });
    }
}

fn writeFactsLine(writer: anytype, f: BinaryFacts) !void {
    try writer.print("{s} (", .{f.path});
    if (f.version) |v| {
        try writer.print("{s}", .{v});
    } else {
        try writer.writeAll("version=unknown");
    }
    try writer.writeAll(", sha ");
    if (f.sha256) |s| {
        try writer.print("{s}", .{s[0..@min(@as(usize, 12), s.len)]});
    } else {
        try writer.writeAll("unreadable");
    }
    try writer.print(", {s})\n", .{f.source});
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const FakeChecker = struct {
    execs: []const []const u8,

    fn check(ctx: *anyopaque, path: []const u8) bool {
        const self: *FakeChecker = @ptrCast(@alignCast(ctx));
        for (self.execs) |e| {
            if (std.mem.eql(u8, e, path)) return true;
        }
        return false;
    }
};

test "scanPath lists executable oauth-mux dirs, winner first, dedups" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();

    var fake = FakeChecker{ .execs = &.{ "/a/oauth-mux", "/b/oauth-mux" } };
    // /a and /b hold executables, /x does not, /a is listed twice.
    const scan = try scanPath(a, "/a:/x:/b:/a", ':', "oauth-mux", &fake, FakeChecker.check);
    try std.testing.expectEqual(@as(usize, 2), scan.paths.len);
    try std.testing.expectEqualStrings("/a/oauth-mux", scan.paths[0]);
    try std.testing.expectEqualStrings("/b/oauth-mux", scan.paths[1]);
    try std.testing.expectEqualStrings("/a/oauth-mux", scan.winner().?);
}

test "scanPath empty PATH yields no entries" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var fake = FakeChecker{ .execs = &.{"/a/oauth-mux"} };
    const scan = try scanPath(arena.allocator(), "", ':', "oauth-mux", &fake, FakeChecker.check);
    try std.testing.expectEqual(@as(usize, 0), scan.paths.len);
    try std.testing.expect(scan.winner() == null);
}

test "scanPath skips dirs without an executable oauth-mux" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var fake = FakeChecker{ .execs = &.{} }; // nothing is executable
    const scan = try scanPath(arena.allocator(), "/a:/b:/c", ':', "oauth-mux", &fake, FakeChecker.check);
    try std.testing.expectEqual(@as(usize, 0), scan.paths.len);
}

test "distinctShaCount counts distinct non-null shas" {
    const a: ?[]const u8 = "aaa";
    const b: ?[]const u8 = "bbb";
    const n: ?[]const u8 = null;
    try std.testing.expectEqual(@as(usize, 0), distinctShaCount(&.{}));
    try std.testing.expectEqual(@as(usize, 1), distinctShaCount(&.{ a, a }));
    try std.testing.expectEqual(@as(usize, 2), distinctShaCount(&.{ a, b, a }));
    try std.testing.expectEqual(@as(usize, 1), distinctShaCount(&.{ a, n, a }));
}

test "compareSemver ordering table" {
    try std.testing.expectEqual(Ordering.eq, compareSemver("0.1.14", "0.1.14"));
    try std.testing.expectEqual(Ordering.lt, compareSemver("0.1.13", "0.1.14"));
    try std.testing.expectEqual(Ordering.gt, compareSemver("0.1.14", "0.1.13"));
    // numeric, not lexical: 14 > 4
    try std.testing.expectEqual(Ordering.gt, compareSemver("0.1.14", "0.1.4"));
    try std.testing.expectEqual(Ordering.eq, compareSemver("v0.1.14", "0.1.14"));
    try std.testing.expectEqual(Ordering.eq, compareSemver("1.2", "1.2.0"));
    try std.testing.expectEqual(Ordering.lt, compareSemver("0.9.0", "1.0.0"));
    // trailing build suffix ignored
    try std.testing.expectEqual(Ordering.eq, compareSemver("0.1.14-5-gabc", "0.1.14"));
    // non-numeric → unknown
    try std.testing.expectEqual(Ordering.unknown, compareSemver("abc", "0.1.0"));
}

test "evaluateStaleness table" {
    // Absent resident → not stale.
    var v = evaluateStaleness(.{ .resident_sha = null, .resident_version = null, .installed_sha = "aaa", .installed_version = "0.1.14", .self_version = "0.1.14" });
    try std.testing.expect(!v.stale);
    try std.testing.expectEqualStrings("no_resident_or_unreadable", v.reason);

    // In sync.
    v = evaluateStaleness(.{ .resident_sha = "aaa", .resident_version = "0.1.14", .installed_sha = "aaa", .installed_version = "0.1.14", .self_version = "0.1.14" });
    try std.testing.expect(!v.stale);
    try std.testing.expectEqualStrings("in_sync", v.reason);

    // SHA mismatch only.
    v = evaluateStaleness(.{ .resident_sha = "aaa", .resident_version = "0.1.14", .installed_sha = "bbb", .installed_version = "0.1.14", .self_version = "0.1.14" });
    try std.testing.expect(v.stale and v.sha_mismatch and !v.version_older);
    try std.testing.expectEqualStrings("resident_sha_differs_from_installed", v.reason);

    // Version older only (vs installed).
    v = evaluateStaleness(.{ .resident_sha = "aaa", .resident_version = "0.1.13", .installed_sha = "aaa", .installed_version = "0.1.14", .self_version = "0.1.14" });
    try std.testing.expect(v.stale and !v.sha_mismatch and v.version_older);
    try std.testing.expectEqualStrings("resident_version_older", v.reason);

    // Both.
    v = evaluateStaleness(.{ .resident_sha = "aaa", .resident_version = "0.1.13", .installed_sha = "bbb", .installed_version = "0.1.14", .self_version = "0.1.14" });
    try std.testing.expect(v.stale and v.sha_mismatch and v.version_older);
    try std.testing.expectEqualStrings("resident_sha_differs_and_version_older", v.reason);

    // Older than self even when installed reference is unknown.
    v = evaluateStaleness(.{ .resident_sha = "aaa", .resident_version = "0.1.13", .installed_sha = null, .installed_version = null, .self_version = "0.1.14" });
    try std.testing.expect(v.stale and v.version_older);
}

test "parseLaunchAgentProgramPath extracts first program string" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const plist =
        \\<plist version="1.0"><dict>
        \\  <key>Label</key>
        \\  <string>dev.xoxd.omux.keepalive</string>
        \\  <key>ProgramArguments</key>
        \\  <array>
        \\    <string>/Users/x/.local/bin/oauth-mux</string>
        \\    <string>keepalive</string>
        \\  </array>
        \\</dict></plist>
    ;
    const p = try parseLaunchAgentProgramPath(arena.allocator(), plist);
    try std.testing.expectEqualStrings("/Users/x/.local/bin/oauth-mux", p.?);
}

test "parseLaunchAgentProgramPath tolerates absence and malformed input" {
    const a = std.testing.allocator;
    try std.testing.expect((try parseLaunchAgentProgramPath(a, "")) == null);
    try std.testing.expect((try parseLaunchAgentProgramPath(a, "<plist>no program args here</plist>")) == null);
    try std.testing.expect((try parseLaunchAgentProgramPath(a, "ProgramArguments but no array element")) == null);
    // ProgramArguments + array but empty string element → null, no error.
    try std.testing.expect((try parseLaunchAgentProgramPath(a, "ProgramArguments<array><string></string></array>")) == null);
}

fn sampleReport() BinariesReport {
    const facts = BinaryFacts{
        .path = "/x/oauth-mux",
        .exists = true,
        .sha256 = null,
        .version = null,
        .version_source = "unknown",
        .source = "path_or_installed",
    };
    return .{
        .self = facts,
        .path_env_present = false,
        .path_entries = &.{},
        .path_winner = null,
        .shadow = .{ .shadowed = false, .distinct_sha_count = 0 },
        .resident = ResidentInfo{
            .supported = false,
            .label = keepalive_label,
            .plist_path = "",
            .plist_present = false,
            .program_path = null,
            .binary = null,
        },
        .stale = .{ .stale = false, .sha_mismatch = false, .version_older = false, .reason = "no_resident_or_unreadable" },
    };
}

test "writeJson renders a null-safe, well-formed binaries object" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try writeJson(sampleReport(), buf.writer());
    const out = buf.items;
    try std.testing.expect(std.mem.indexOf(u8, out, "\"binaries\":") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"path_winner\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"sha256\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"shadowed\":false") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"reason\":\"no_resident_or_unreadable\"") != null);

    // Wrap and parse to confirm it is valid JSON.
    var full = std.ArrayList(u8).init(std.testing.allocator);
    defer full.deinit();
    try full.append('{');
    try full.appendSlice(out);
    try full.append('}');
    const parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, full.items, .{});
    parsed.deinit();
}

test "writeJson unavailable when report is null" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();
    try writeJson(null, buf.writer());
    try std.testing.expectEqualStrings("\"binaries\":{\"available\":false}", buf.items);
}

test "writeText renders and is null-safe" {
    var buf = std.ArrayList(u8).init(std.testing.allocator);
    defer buf.deinit();

    try writeText(null, buf.writer());
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "binaries:") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "unavailable") != null);

    buf.clearRetainingCapacity();
    try writeText(sampleReport(), buf.writer());
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "self:") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "not supported") != null);
    try std.testing.expect(std.mem.indexOf(u8, buf.items, "none on PATH") != null);
}
