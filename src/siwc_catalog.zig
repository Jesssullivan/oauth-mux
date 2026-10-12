//! Bounded account-scoped SIWC catalog syntax. Parsed metadata is an
//! observation, never inference entitlement, quota or grant authority. Only
//! the actor's exact current-pair/opaque curl receipt path can publish it.
const std = @import("std");

pub const maximum_body_bytes = 128 * 1024;
pub const maximum_models = 256;
pub const maximum_slug_bytes = 128;
pub const maximum_display_bytes = 256;
pub const maximum_depth = 12;
pub const freshness_seconds: i64 = 60;
pub const Model = struct {
    slug: []const u8,
    display_name: []const u8,
    visibility: []const u8 = "list",
};
pub const Catalog = struct {
    allocator: std.mem.Allocator,
    rows: std.ArrayList(Model) = .empty,
    response_sha256: [32]u8,
    pub fn models(self: *const Catalog) []const Model { return self.rows.items; }
    pub fn contains(self: *const Catalog, slug: []const u8) bool {
        for (self.rows.items) |row| if (std.mem.eql(u8, row.slug, slug)) return true;
        return false;
    }
    pub fn deinit(self: *Catalog) void {
        for (self.rows.items) |row| {
            std.crypto.secureZero(u8, @constCast(row.slug));
            std.crypto.secureZero(u8, @constCast(row.display_name));
            self.allocator.free(row.slug);
            self.allocator.free(row.display_name);
        }
        self.rows.deinit(self.allocator);
        self.* = undefined;
    }
};

pub fn parse(a: std.mem.Allocator, status: u16, body: []const u8) !Catalog {
    if (status != 200) return error.SiwcCatalogUnavailable;
    if (body.len == 0 or body.len > maximum_body_bytes) return error.InvalidSiwcCatalog;
    try boundedDepth(body);
    // Unknown provider fields cannot grow an unbounded heap or recursive
    // parser stack. Raw replies/scratch are not diagnostics or public views.
    var scratch: [maximum_body_bytes * 8]u8 = undefined;
    defer std.crypto.secureZero(u8, &scratch);
    var fixed = std.heap.FixedBufferAllocator.init(&scratch);
    const parsed = std.json.parseFromSlice(std.json.Value, fixed.allocator(), body, .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error", .max_value_len = maximum_body_bytes }) catch return error.InvalidSiwcCatalog;
    defer parsed.deinit();
    if (parsed.value != .object or parsed.value.object.contains("error")) return error.InvalidSiwcCatalog;
    const models_value = parsed.value.object.get("models") orelse return error.InvalidSiwcCatalog;
    if (models_value != .array or models_value.array.items.len > maximum_models) return error.InvalidSiwcCatalog;
    const raw = models_value.array.items;
    // Compare every declared slug, including hidden rows. A contradictory
    // duplicate must not disappear while filtering displayable observations.
    var listed: usize = 0;
    for (raw, 0..) |entry, index| {
        if (entry != .object) return error.InvalidSiwcCatalog;
        const slug = try field(entry.object, "slug", maximum_slug_bytes);
        try validateSlug(slug);
        const visibility = try field(entry.object, "visibility", 32);
        try printableAscii(visibility);
        for (raw[0..index]) |prior| {
            const old_slug = try field(prior.object, "slug", maximum_slug_bytes);
            if (std.mem.eql(u8, old_slug, slug)) return error.InvalidSiwcCatalog;
        }
        if (!std.mem.eql(u8, visibility, "list")) continue;
        try validateDisplay(try field(entry.object, "display_name", maximum_display_bytes));
        listed += 1;
    }
    // A valid empty/hidden-only result supplies no picker. It does not change
    // account eligibility or infer a provider-wide entitlement decision.
    if (listed == 0) return error.SiwcCatalogUnavailable;
    var response_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &response_digest, .{});
    var result: Catalog = .{ .allocator = a, .response_sha256 = response_digest };
    errdefer result.deinit();
    try result.rows.ensureTotalCapacity(a, listed);
    for (raw) |entry| {
        const visibility = try field(entry.object, "visibility", 32);
        if (!std.mem.eql(u8, visibility, "list")) continue;
        const slug = try a.dupe(u8, try field(entry.object, "slug", maximum_slug_bytes));
        errdefer { std.crypto.secureZero(u8, slug); a.free(slug); }
        const display = try a.dupe(u8, try field(entry.object, "display_name", maximum_display_bytes));
        result.rows.appendAssumeCapacity(.{ .slug = slug, .display_name = display });
    }
    return result;
}
fn field(object: std.json.ObjectMap, key: []const u8, limit: usize) ![]const u8 {
    const value = object.get(key) orelse return error.InvalidSiwcCatalog;
    if (value != .string or value.string.len == 0 or value.string.len > limit) return error.InvalidSiwcCatalog;
    return value.string;
}
fn printableAscii(value: []const u8) !void {
    for (value) |byte| if (byte < 0x21 or byte > 0x7e) return error.InvalidSiwcCatalog;
}
fn validateSlug(value: []const u8) !void { try printableAscii(value); }
fn validateDisplay(value: []const u8) !void {
    if (!std.unicode.utf8ValidateSlice(value)) return error.InvalidSiwcCatalog;
    var it = (try std.unicode.Utf8View.init(value)).iterator();
    while (it.nextCodepoint()) |point| {
        if (point < 0x20 or (point >= 0x7f and point <= 0x9f) or point == 0x2028 or point == 0x2029) return error.InvalidSiwcCatalog;
    }
}
fn boundedDepth(body: []const u8) !void {
    var depth: usize = 0;
    var quoted = false;
    var escaped = false;
    for (body) |byte| {
        if (quoted) {
            if (escaped) { escaped = false; continue; }
            if (byte == '\\') { escaped = true; continue; }
            if (byte == '"') quoted = false;
            continue;
        }
        if (byte == '"') { quoted = true; continue; }
        if (byte == '{' or byte == '[') {
            depth += 1;
            if (depth > maximum_depth) return error.InvalidSiwcCatalog;
        } else if (byte == '}' or byte == ']') {
            if (depth == 0) return error.InvalidSiwcCatalog;
            depth -= 1;
        }
    }
    if (quoted or escaped or depth != 0) return error.InvalidSiwcCatalog;
}

test "account catalog preserves server order and only displayable named metadata" {
    const body = "{\"models\":[{\"slug\":\"synthetic-hidden\",\"visibility\":\"hidden\"},{\"slug\":\"synthetic-b\",\"display_name\":\"Synthetic B\",\"visibility\":\"list\",\"unprojected\":17},{\"slug\":\"synthetic-a\",\"display_name\":\"Synthetic A\",\"visibility\":\"list\"}]}";
    var observed = try parse(std.testing.allocator, 200, body);
    defer observed.deinit();
    try std.testing.expectEqual(@as(usize, 2), observed.models().len);
    try std.testing.expectEqualStrings("synthetic-b", observed.models()[0].slug);
    try std.testing.expectEqualStrings("Synthetic A", observed.models()[1].display_name);
    try std.testing.expect(observed.contains("synthetic-a") and !observed.contains("synthetic-hidden"));
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &digest, .{});
    try std.testing.expectEqualSlices(u8, &digest, &observed.response_sha256);
}
test "catalog duplicate contradictions and conventional API aliases never invent choices" {
    for ([_][]const u8{
        "{\"data\":[{\"id\":\"synthetic-model\"}]}",
        "{\"models\":[{\"slug\":\"same\",\"visibility\":\"hidden\"},{\"slug\":\"same\",\"display_name\":\"Same\",\"visibility\":\"list\"}]}",
        "{\"models\":[{\"slug\":\"a\",\"display_name\":\"A\",\"visibility\":\"list\",\"visibility\":\"hidden\"}]}",
        "{\"models\":[{\"slug\":\"a\",\"display_name\":12,\"visibility\":\"list\"}]}",
        "{\"models\":[{\"slug\":\"a\",\"display_name\":\"bad\\nline\",\"visibility\":\"list\"}]}",
        "{\"models\":[{\"slug\":\"a b\",\"display_name\":\"A\",\"visibility\":\"list\"}]}",
    }) |body| try std.testing.expectError(error.InvalidSiwcCatalog, parse(std.testing.allocator, 200, body));
    try std.testing.expectError(error.SiwcCatalogUnavailable, parse(std.testing.allocator, 200, "{\"models\":[]}"));
    try std.testing.expectError(error.SiwcCatalogUnavailable, parse(std.testing.allocator, 403, "not-a-public-diagnostic"));
}
test "catalog body depth and partial allocation bounds are finite" {
    const large: [maximum_body_bytes + 1]u8 = @splat('x');
    try std.testing.expectError(error.InvalidSiwcCatalog, parse(std.testing.allocator, 200, &large));
    try std.testing.expectError(error.InvalidSiwcCatalog, parse(std.testing.allocator, 200, "{\"models\":[],\"unknown\":[[[[[[[[[[[[[0]]]]]]]]]]]]]}"));
    var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 2 });
    try std.testing.expectError(error.OutOfMemory, parse(fail.allocator(), 200, "{\"models\":[{\"slug\":\"synthetic-a\",\"display_name\":\"A\",\"visibility\":\"list\"}]}"));
}

test "catalog declared row count and selected display slug limits refuse" {
    const a = std.testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    const slug: [maximum_slug_bytes + 1]u8 = @splat('s');
    const display: [maximum_display_bytes + 1]u8 = @splat('D');
    const oversized_slug = try std.json.Stringify.valueAlloc(scratch, .{ .models = &.{.{ .slug = &slug, .display_name = "Synthetic", .visibility = "list" }} }, .{});
    const oversized_display = try std.json.Stringify.valueAlloc(scratch, .{ .models = &.{.{ .slug = "synthetic", .display_name = &display, .visibility = "list" }} }, .{});
    try std.testing.expectError(error.InvalidSiwcCatalog, parse(a, 200, oversized_slug));
    try std.testing.expectError(error.InvalidSiwcCatalog, parse(a, 200, oversized_display));
    var rows: [maximum_models + 1]Model = undefined;
    for (&rows, 0..) |*row, index| row.* = .{ .slug = try std.fmt.allocPrint(scratch, "synthetic-{d}", .{index}), .display_name = "Synthetic", .visibility = "list" };
    const too_many = try std.json.Stringify.valueAlloc(scratch, .{ .models = &rows }, .{});
    try std.testing.expectError(error.InvalidSiwcCatalog, parse(a, 200, too_many));
}
