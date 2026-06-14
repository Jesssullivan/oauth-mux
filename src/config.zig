const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");
const paths = @import("paths.zig");
const provider_schema = @import("provider_schema.zig");
const env = @import("env.zig");
const log = @import("log.zig");

pub const Config = struct {
    version: u32 = 1,
    defaults: Defaults = .{},
    policy: PolicyConfig = .{},
    provider_definitions: std.json.ArrayHashMap(provider_schema.ProviderDefinition) = .{},
    providers: std.json.ArrayHashMap(ProviderConfig) = .{},
    profiles: std.json.ArrayHashMap(ProfileConfig) = .{},
    strategies: std.json.ArrayHashMap(StrategyConfig) = .{},
};

pub const Defaults = struct {
    provider: ?[]const u8 = null,
    strategy: ?[]const u8 = null,
    profile: ?[]const u8 = null,
    capability: ?[]const u8 = null,
    shell: ?[]const u8 = null,
    daemon: bool = false,
};

pub const PolicyConfig = struct {
    daemon: DaemonPolicyConfig = .{},
    codex: CodexPolicyConfig = .{},
};

pub const DaemonPolicyConfig = struct {
    allowed_budgets: []const types.ActionBudget = &.{ .free_local, .free_command },
    allow_interactive: bool = false,
    allow_mutating: bool = false,
};

pub const CodexPolicyConfig = struct {
    auto_stay_afloat: bool = true,
    allow_provider_spend: bool = true,
    allow_interactive_auth: bool = false,
};

pub const ProviderConfig = struct {
    kind: []const u8,
    config_dir_env: ?[]const u8 = null,
    accounts: std.json.ArrayHashMap(AccountConfig) = .{},
};

pub const AccountConfig = struct {
    priority: i32 = 0,
    secret: SecretConfig,
    config_dir: ?[]const u8 = null,
    quota: ?QuotaConfig = null,
    tags: ?[]const []const u8 = null,
    // TIN-2058: explicit operator consent for oauth-mux to refresh this
    // account's token proactively. Login stays upstream-CLI-owned; this
    // only admits the non-interactive refresh writeback, and only for
    // providers whose definition declares proactive_refresh support. Leave
    // false until the dual-writer story (TIN-2059) covers your native CLI's
    // own refresh behavior for this account.
    allow_proactive_refresh: bool = false,
};

pub const SecretConfig = struct {
    backend: []const u8,
    service: ?[]const u8 = null,
    account: ?[]const u8 = null,
    path: ?[]const u8 = null,
    key: ?[]const u8 = null,
    key_path: ?[]const u8 = null,
    variable: ?[]const u8 = null,
    command: ?[]const []const u8 = null,
    identity: ?[]const u8 = null,
    // TIN-2070: set by applyClaudeKeychainDefaults when service/account were
    // derived at load rather than written by the operator. Derived values are
    // re-derivable from (config_dir, local user), so serialization elides
    // them — otherwise any enroll rewrite would freeze a load-time hash into
    // the config file as a fake operator pin that goes stale if config_dir
    // ever moves.
    derived_service: bool = false,
    derived_account: bool = false,

    pub fn jsonStringify(self: SecretConfig, jws: anytype) !void {
        try jws.beginObject();
        try jws.objectField("backend");
        try jws.write(self.backend);
        if (self.service) |v| if (!self.derived_service) {
            try jws.objectField("service");
            try jws.write(v);
        };
        if (self.account) |v| if (!self.derived_account) {
            try jws.objectField("account");
            try jws.write(v);
        };
        if (self.path) |v| {
            try jws.objectField("path");
            try jws.write(v);
        }
        if (self.key) |v| {
            try jws.objectField("key");
            try jws.write(v);
        }
        if (self.key_path) |v| {
            try jws.objectField("key_path");
            try jws.write(v);
        }
        if (self.variable) |v| {
            try jws.objectField("variable");
            try jws.write(v);
        }
        if (self.command) |v| {
            try jws.objectField("command");
            try jws.write(v);
        }
        if (self.identity) |v| {
            try jws.objectField("identity");
            try jws.write(v);
        }
        try jws.endObject();
    }
};

pub const QuotaConfig = struct {
    monthly_limit: ?u64 = null,
    warn_at_pct: u32 = 5,
};

pub const ProfileConfig = struct {
    providers: []const []const u8,
    strategy: ?[]const u8 = null,
    affinity_ttl_minutes: u32 = 20,
    // TIN-1811: ordered cross-capability degradation chain. When the requested
    // capability has no selectable route, the selector re-evaluates routes for
    // each capability listed here, in order, and selects the first live one.
    // null (default) preserves today's strictly capability-scoped behavior.
    capability_degradation_chain: ?[]const []const u8 = null,
};

pub const StrategyConfig = struct {
    kind: []const u8,
    max_retries: u32 = 2,
    health_decay_per_hour: ?i32 = null,
    rate_limit_penalty: ?i32 = null,
    failure_penalty: ?i32 = null,
    success_bonus: ?i32 = null,
};

pub fn load(allocator: std.mem.Allocator) !std.json.Parsed(Config) {
    const path = try paths.configFilePath(allocator);
    defer allocator.free(path);
    return loadFromPath(allocator, path);
}

pub fn loadFromPath(allocator: std.mem.Allocator, path: []const u8) !std.json.Parsed(Config) {
    const file = (if (std.fs.path.isAbsolute(path))
        std.fs.openFileAbsolute(path, .{})
    else
        std.fs.cwd().openFile(path, .{})) catch |e| switch (e) {
        error.FileNotFound => return error.FileNotFound,
        else => return error.Unexpected,
    };
    defer file.close();

    const bytes = file.readToEndAlloc(allocator, 1024 * 1024) catch return error.Unexpected;
    defer allocator.free(bytes);

    return loadFromBytes(allocator, bytes);
}

pub fn loadFromBytes(allocator: std.mem.Allocator, bytes: []const u8) !std.json.Parsed(Config) {
    var parsed = try std.json.parseFromSlice(Config, allocator, bytes, .{
        .ignore_unknown_fields = true,
        .allocate = .alloc_always,
    });
    errdefer parsed.deinit();
    try applyClaudeKeychainDefaults(&parsed.value, parsed.arena.allocator());
    return parsed;
}

// TIN-2070: Claude Code keys its macOS keychain item on a per-config-dir
// service name and the local username as the item account. When an enrolled
// claude account with a config_dir omits keychain service/account, derive
// them the same way the CLI does so reads and refresh writebacks target the
// item the CLI actually uses. The hash input is the tilde-expanded config_dir
// — the exact string the launcher exports as CLAUDE_CONFIG_DIR. Explicit
// config always wins; accounts without a config_dir keep requiring an
// explicit service (the launcher tmpdir-modes them, so no on-disk keychain
// identity exists to derive). macOS only: the store contract is verified
// there and nowhere else, so other platforms keep failing fast at validation.
fn applyClaudeKeychainDefaults(cfg: *Config, arena: std.mem.Allocator) error{OutOfMemory}!void {
    if (comptime builtin.os.tag != .macos) return;
    var prov_it = cfg.providers.map.iterator();
    while (prov_it.next()) |prov_entry| {
        if (!std.mem.eql(u8, prov_entry.value_ptr.kind, "claude")) continue;
        var acct_it = prov_entry.value_ptr.accounts.map.iterator();
        while (acct_it.next()) |acct_entry| {
            const acct = acct_entry.value_ptr;
            if (!std.mem.eql(u8, acct.secret.backend, "keychain")) continue;
            if (acct.secret.service == null) {
                if (acct.config_dir) |dir| {
                    const expanded = paths.expandTilde(arena, dir) catch return error.OutOfMemory;
                    acct.secret.service = try provider_schema.claudeKeychainService(arena, expanded);
                    acct.secret.derived_service = true;
                }
            }
            if (acct.secret.account == null) {
                // USER is a proxy for the passwd-database username Claude
                // Code keys the item on; it diverges under sudo and is unset
                // in launchd contexts — set secret.account explicitly there.
                if (try env.get(arena, "USER")) |user| {
                    acct.secret.account = user;
                    acct.secret.derived_account = true;
                } else {
                    log.debug("config: USER unset; claude account '{s}' keychain account left for validation", .{acct_entry.key_ptr.*});
                }
            }
        }
    }
}

pub fn validate(cfg: Config, writer: anytype) !void {
    var ok = true;

    if (cfg.defaults.provider) |provider_name| {
        if (cfg.providers.map.get(provider_name) == null) {
            try writer.print("config error: defaults.provider references unknown provider '{s}'\n", .{provider_name});
            ok = false;
        }
    }

    if (cfg.defaults.strategy) |strategy_name| {
        if (cfg.strategies.map.get(strategy_name) == null) {
            try writer.print("config error: defaults.strategy references unknown strategy '{s}'\n", .{strategy_name});
            ok = false;
        }
    }

    if (cfg.defaults.profile) |profile_name| {
        if (cfg.profiles.map.get(profile_name) == null) {
            try writer.print("config error: defaults.profile references unknown profile '{s}'\n", .{profile_name});
            ok = false;
        }
    }

    var def_it = cfg.provider_definitions.map.iterator();
    while (def_it.next()) |entry| {
        try validateProviderDefinition(entry.key_ptr.*, entry.value_ptr.*, writer, &ok);
    }

    var provider_it = cfg.providers.map.iterator();
    while (provider_it.next()) |entry| {
        const provider_name = entry.key_ptr.*;
        const prov = entry.value_ptr.*;
        try validateProviderConfig(cfg, provider_name, prov, writer, &ok);
    }

    var profile_it = cfg.profiles.map.iterator();
    while (profile_it.next()) |entry| {
        const profile_name = entry.key_ptr.*;
        const profile = entry.value_ptr.*;

        if (profile.strategy) |strategy_name| {
            if (cfg.strategies.map.get(strategy_name) == null) {
                try writer.print("config error: profiles.{s}.strategy references unknown strategy '{s}'\n", .{ profile_name, strategy_name });
                ok = false;
            }
        }

        for (profile.providers) |spec| {
            const ref = splitProviderAccount(spec) orelse {
                try writer.print("config error: profiles.{s}.providers entry '{s}' must be provider:account[#capability]\n", .{ profile_name, spec });
                ok = false;
                continue;
            };

            const prov = cfg.providers.map.get(ref.provider) orelse {
                try writer.print("config error: profiles.{s}.providers references unknown provider '{s}'\n", .{ profile_name, ref.provider });
                ok = false;
                continue;
            };

            if (prov.accounts.map.get(ref.account) == null) {
                try writer.print("config error: profiles.{s}.providers references unknown account '{s}:{s}'\n", .{ profile_name, ref.provider, ref.account });
                ok = false;
            }
        }

        // TIN-1811: every capability named in the degradation chain must have at
        // least one provider route declaring that capability in this profile, so
        // a typo errors clearly at load instead of silently no-op'ing.
        if (profile.capability_degradation_chain) |chain| {
            for (chain, 0..) |capability_name, chain_idx| {
                var found = false;
                for (profile.providers) |spec| {
                    const ref = splitProviderAccount(spec) orelse continue;
                    const route_capability = ref.capability orelse continue;
                    if (std.mem.eql(u8, route_capability, capability_name)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    try writer.print("config error: profiles.{s}.capability_degradation_chain[{d}] references capability '{s}' with no provider routes in this profile\n", .{ profile_name, chain_idx, capability_name });
                    ok = false;
                }
            }
        }
    }

    if (!ok) return error.ConfigValidationError;
}

pub fn resolveSecretBackend(secret: SecretConfig) !types.SecretBackend {
    const map = std.StaticStringMap(enum { keychain, sops, age, env, file, command, stdin }).initComptime(.{
        .{ "keychain", .keychain },
        .{ "sops", .sops },
        .{ "age", .age },
        .{ "env", .env },
        .{ "file", .file },
        .{ "command", .command },
        .{ "stdin", .stdin },
    });

    const kind = map.get(secret.backend) orelse return error.InvalidCharacter;

    return switch (kind) {
        .keychain => .{ .keychain = .{
            .service = secret.service orelse return error.InvalidCharacter,
            .account = secret.account orelse return error.InvalidCharacter,
        } },
        .sops => .{ .sops = .{
            .path = secret.path orelse return error.InvalidCharacter,
            .key_path = secret.key_path,
        } },
        .age => .{ .age = .{
            .path = secret.path orelse return error.InvalidCharacter,
            .identity = secret.identity orelse return error.InvalidCharacter,
        } },
        .env => .{ .env = .{
            .variable = secret.variable orelse return error.InvalidCharacter,
        } },
        .file => .{ .file = .{
            .path = secret.path orelse return error.InvalidCharacter,
        } },
        .command => .{ .command = .{
            .argv = secret.command orelse return error.InvalidCharacter,
        } },
        .stdin => .stdin,
    };
}

pub fn resolveProviderDefinition(cfg: Config, provider_name: []const u8) provider_schema.ProviderDefinition {
    if (cfg.provider_definitions.map.get(provider_name)) |def| return def;

    if (cfg.providers.map.get(provider_name)) |prov_cfg| {
        if (cfg.provider_definitions.map.get(prov_cfg.kind)) |def| return def;
        if (provider_schema.findBuiltin(prov_cfg.kind)) |def| return def;
    }

    if (provider_schema.findBuiltin(provider_name)) |def| return def;
    return provider_schema.generic_def;
}

pub fn resolveProviderKind(cfg: Config, provider_name: []const u8) ?types.ProviderKind {
    if (cfg.providers.map.get(provider_name)) |prov_cfg| {
        return types.ProviderKind.fromString(prov_cfg.kind);
    }
    return types.ProviderKind.fromString(provider_name);
}

pub fn daemonPolicyAllowsBudget(policy: DaemonPolicyConfig, budget: types.ActionBudget) bool {
    for (policy.allowed_budgets) |allowed| {
        if (allowed == budget) return true;
    }
    return false;
}

pub fn effectiveDaemonPolicyForProvider(policy: PolicyConfig, provider_name: []const u8) DaemonPolicyConfig {
    var effective = policy.daemon;
    if (std.mem.eql(u8, provider_name, "codex") and policy.codex.auto_stay_afloat) {
        if (policy.codex.allow_provider_spend) {
            effective.allowed_budgets = &.{
                .free_local,
                .free_command,
                .cheap_provider,
                .spend_provider,
            };
        }
        if (policy.codex.allow_interactive_auth) {
            effective.allow_interactive = true;
        }
    }
    return effective;
}

fn validateProviderConfig(cfg: Config, provider_name: []const u8, prov: ProviderConfig, writer: anytype, ok: *bool) !void {
    if (provider_name.len == 0) {
        try writer.writeAll("config error: provider name must not be empty\n");
        ok.* = false;
    }

    // A provider name must not contain ':': the keepalive warm-loop encodes an
    // account key as "<provider>:<account>" and decodes by splitting on the FIRST
    // ':' (so account names may contain ':' but provider names may not). A colon
    // here would mis-target the decoded (provider, account) — refuse it at load.
    if (std.mem.indexOfScalar(u8, provider_name, ':') != null) {
        try writer.print("config error: provider name '{s}' must not contain ':'\n", .{provider_name});
        ok.* = false;
    }

    if (prov.kind.len == 0) {
        try writer.print("config error: providers.{s}.kind must not be empty\n", .{provider_name});
        ok.* = false;
    }

    if (!hasProviderDefinition(cfg, provider_name, prov.kind)) {
        try writer.print("config error: providers.{s}.kind '{s}' has no built-in or provider_definitions entry\n", .{ provider_name, prov.kind });
        ok.* = false;
    }

    var account_it = prov.accounts.map.iterator();
    while (account_it.next()) |entry| {
        const account_name = entry.key_ptr.*;
        const account = entry.value_ptr.*;

        if (account_name.len == 0) {
            try writer.print("config error: providers.{s}.accounts contains an empty account name\n", .{provider_name});
            ok.* = false;
        }

        validateSecretConfig(provider_name, account_name, account.secret, writer, ok) catch |e| switch (e) {
            error.ConfigValidationError => {},
            else => return e,
        };
    }
}

fn validateProviderDefinition(def_key: []const u8, def: provider_schema.ProviderDefinition, writer: anytype, ok: *bool) !void {
    if (def.name.len == 0) {
        try writer.print("config error: provider_definitions.{s}.name must not be empty\n", .{def_key});
        ok.* = false;
    }

    if (def.credential.access_token_path.len == 0) {
        try writer.print("config error: provider_definitions.{s}.credential.access_token_path must not be empty\n", .{def_key});
        ok.* = false;
    }

    if (def.credential.refresh_token_path.len == 0) {
        try writer.print("config error: provider_definitions.{s}.credential.refresh_token_path must not be empty\n", .{def_key});
        ok.* = false;
    }

    if (def.injection.credential_filename.len == 0) {
        try writer.print("config error: provider_definitions.{s}.injection.credential_filename must not be empty\n", .{def_key});
        ok.* = false;
    }

    if (def.injection.direct_env) |direct_env| {
        for (direct_env) |mapping| {
            if (mapping[0].len == 0) {
                try writer.print("config error: provider_definitions.{s}.injection.direct_env contains an empty env var name\n", .{def_key});
                ok.* = false;
            }
            if (!isSupportedTokenField(mapping[1])) {
                try writer.print("config error: provider_definitions.{s}.injection.direct_env maps {s} to unsupported token field '{s}'\n", .{ def_key, mapping[0], mapping[1] });
                ok.* = false;
            }
        }
    }

    try validateRuntimeConfig(def_key, def.runtime, writer, ok);

    var has_capability_probe = false;
    for (def.capabilities, 0..) |capability, idx| {
        if (capability.name.len == 0) {
            try writer.print("config error: provider_definitions.{s}.capabilities[{d}].name must not be empty\n", .{ def_key, idx });
            ok.* = false;
        }
        if (capability.probe) |probe| {
            has_capability_probe = true;
            try validateProbeDefinition(def_key, idx, probe, writer, ok);
            if (probe.timeout_ms == 0) {
                try writer.print("config error: provider_definitions.{s}.capabilities[{d}].probe.timeout_ms must be greater than zero\n", .{ def_key, idx });
                ok.* = false;
            }
            if (probe.success_status_min > probe.success_status_max) {
                try writer.print("config error: provider_definitions.{s}.capabilities[{d}].probe success status range is invalid\n", .{ def_key, idx });
                ok.* = false;
            }
            if (probe.budget) |budget| {
                if (!budget.allowedForProbe()) {
                    try writer.print("config error: provider_definitions.{s}.capabilities[{d}].probe.budget '{s}' is not valid for probes\n", .{ def_key, idx, @tagName(budget) });
                    ok.* = false;
                }
            }
        }
    }

    if (has_capability_probe and def.failure_rules.len == 0) {
        try writer.print("config error: provider_definitions.{s} must define failure_rules when capabilities include probes\n", .{def_key});
        ok.* = false;
    }

    for (def.failure_rules, 0..) |rule, idx| {
        try validateFailureRule(def_key, idx, rule, writer, ok);
    }
}

fn validateRuntimeConfig(
    def_key: []const u8,
    runtime: provider_schema.RuntimeConfig,
    writer: anytype,
    ok: *bool,
) !void {
    try validateNonEmptyStringList(def_key, "runtime.required_binaries", runtime.required_binaries, writer, ok);
    try validateNonEmptyStringList(def_key, "runtime.env_vars", runtime.env_vars, writer, ok);
    try validateNonEmptyStringList(def_key, "runtime.writable_paths", runtime.writable_paths, writer, ok);
    try validateNonEmptyStringList(def_key, "runtime.session_paths", runtime.session_paths, writer, ok);
}

fn validateNonEmptyStringList(
    def_key: []const u8,
    field_name: []const u8,
    values: []const []const u8,
    writer: anytype,
    ok: *bool,
) !void {
    for (values, 0..) |value, idx| {
        if (value.len == 0) {
            try writer.print("config error: provider_definitions.{s}.{s}[{d}] must not be empty\n", .{ def_key, field_name, idx });
            ok.* = false;
        }
    }
}

fn validateFailureRule(
    def_key: []const u8,
    rule_idx: usize,
    rule: provider_schema.FailureRule,
    writer: anytype,
    ok: *bool,
) !void {
    if (!failureRuleHasMatcher(rule)) {
        try writer.print("config error: provider_definitions.{s}.failure_rules[{d}] must include at least one matcher\n", .{ def_key, rule_idx });
        ok.* = false;
    }

    if (rule.hint_equals) |hint| {
        if (hint.len == 0) {
            try writer.print("config error: provider_definitions.{s}.failure_rules[{d}].hint_equals must not be empty\n", .{ def_key, rule_idx });
            ok.* = false;
        }
    }

    if (rule.hint_contains) |hint| {
        if (hint.len == 0) {
            try writer.print("config error: provider_definitions.{s}.failure_rules[{d}].hint_contains must not be empty\n", .{ def_key, rule_idx });
            ok.* = false;
        }
    }

    if (rule.status_min) |min| {
        if (rule.status_max) |max| {
            if (min > max) {
                try writer.print("config error: provider_definitions.{s}.failure_rules[{d}] has status_min greater than status_max\n", .{ def_key, rule_idx });
                ok.* = false;
            }
        }
    }

    if (rule.retry_after_gte) |min_wait| {
        if (rule.retry_after_lt) |max_wait| {
            if (min_wait >= max_wait) {
                try writer.print("config error: provider_definitions.{s}.failure_rules[{d}] retry_after_gte must be less than retry_after_lt\n", .{ def_key, rule_idx });
                ok.* = false;
            }
        }
    }
}

fn failureRuleHasMatcher(rule: provider_schema.FailureRule) bool {
    return rule.status != null or
        rule.status_min != null or
        rule.status_max != null or
        rule.retry_after_gte != null or
        rule.retry_after_lt != null or
        rule.hint_equals != null or
        rule.hint_contains != null;
}

fn validateProbeDefinition(
    def_key: []const u8,
    capability_idx: usize,
    probe: provider_schema.ProbeDefinition,
    writer: anytype,
    ok: *bool,
) !void {
    switch (probe.transport) {
        .http => {
            if (!isSupportedProbeMethod(probe.method)) {
                try writer.print("config error: provider_definitions.{s}.capabilities[{d}].probe.method '{s}' is unsupported\n", .{ def_key, capability_idx, probe.method });
                ok.* = false;
            }
            if (probe.url.len == 0) {
                try writer.print("config error: provider_definitions.{s}.capabilities[{d}].probe.url must not be empty\n", .{ def_key, capability_idx });
                ok.* = false;
            }
            if (containsSecretLikeProbeMaterial(probe.url)) {
                try writer.print("config error: provider_definitions.{s}.capabilities[{d}].probe.url must not contain token material\n", .{ def_key, capability_idx });
                ok.* = false;
            }
            if (!isValidUrlTemplate(probe.url)) {
                try writer.print("config error: provider_definitions.{s}.capabilities[{d}].probe.url contains an invalid template placeholder\n", .{ def_key, capability_idx });
                ok.* = false;
            }
            if (probe.auth == .token_header) {
                if (probe.auth_header) |header| {
                    if (!isSafeTokenHeaderName(header)) {
                        try writer.print("config error: provider_definitions.{s}.capabilities[{d}].probe.auth_header must be a non-Authorization HTTP header name without control characters\n", .{ def_key, capability_idx });
                        ok.* = false;
                    }
                } else {
                    try writer.print("config error: provider_definitions.{s}.capabilities[{d}].probe.auth_header is required when auth is token_header\n", .{ def_key, capability_idx });
                    ok.* = false;
                }
            } else if (probe.auth_header != null) {
                try writer.print("config error: provider_definitions.{s}.capabilities[{d}].probe.auth_header requires auth token_header\n", .{ def_key, capability_idx });
                ok.* = false;
            }
            if (probe.body) |body| {
                if (!std.mem.eql(u8, probe.method, "POST")) {
                    try writer.print("config error: provider_definitions.{s}.capabilities[{d}].probe.body requires method POST\n", .{ def_key, capability_idx });
                    ok.* = false;
                }
                if (body.len == 0) {
                    try writer.print("config error: provider_definitions.{s}.capabilities[{d}].probe.body must not be empty\n", .{ def_key, capability_idx });
                    ok.* = false;
                }
                if (containsSecretLikeProbeMaterial(body)) {
                    try writer.print("config error: provider_definitions.{s}.capabilities[{d}].probe.body must not contain token material\n", .{ def_key, capability_idx });
                    ok.* = false;
                }
            }
            if (probe.content_type) |content_type| {
                if (content_type.len == 0) {
                    try writer.print("config error: provider_definitions.{s}.capabilities[{d}].probe.content_type must not be empty\n", .{ def_key, capability_idx });
                    ok.* = false;
                }
            }
        },
        .command => {
            if (probe.command == null or probe.command.?.len == 0) {
                try writer.print("config error: provider_definitions.{s}.capabilities[{d}].probe.command must not be empty\n", .{ def_key, capability_idx });
                ok.* = false;
            }
            if (probe.command) |command| {
                for (command, 0..) |arg, arg_idx| {
                    if (containsSecretLikeProbeMaterial(arg)) {
                        try writer.print("config error: provider_definitions.{s}.capabilities[{d}].probe.command[{d}] must not contain token material\n", .{ def_key, capability_idx, arg_idx });
                        ok.* = false;
                    }
                }
            }
        },
    }
}

fn containsSecretLikeProbeMaterial(value: []const u8) bool {
    const needles = [_][]const u8{
        "access_token=",
        "refresh_token=",
        "id_token=",
        "authorization=",
        "authorization:",
        "bearer ",
        "bearer%20",
        "\"access_token\"",
        "\"refresh_token\"",
        "\"id_token\"",
        "{{access_token}}",
        "{{refresh_token}}",
        "{{id_token}}",
    };

    for (needles) |needle| {
        if (indexOfIgnoreCase(value, needle) != null) return true;
    }

    return false;
}

fn indexOfIgnoreCase(haystack: []const u8, needle: []const u8) ?usize {
    if (needle.len == 0) return 0;
    if (needle.len > haystack.len) return null;

    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[i .. i + needle.len], needle)) return i;
    }

    return null;
}

fn validateSecretConfig(provider_name: []const u8, account_name: []const u8, secret: SecretConfig, writer: anytype, ok: *bool) !void {
    _ = resolveSecretBackend(secret) catch {
        try writer.print("config error: providers.{s}.accounts.{s}.secret is incomplete for backend '{s}'\n", .{ provider_name, account_name, secret.backend });
        ok.* = false;
        return error.ConfigValidationError;
    };

    if (std.mem.eql(u8, secret.backend, "command")) {
        if (secret.command == null or secret.command.?.len == 0) {
            try writer.print("config error: providers.{s}.accounts.{s}.secret.command must not be empty\n", .{ provider_name, account_name });
            ok.* = false;
        }
    }
}

fn hasProviderDefinition(cfg: Config, provider_name: []const u8, provider_kind: []const u8) bool {
    if (cfg.provider_definitions.map.get(provider_name) != null) return true;
    if (cfg.provider_definitions.map.get(provider_kind) != null) return true;
    return provider_schema.findBuiltin(provider_kind) != null or provider_schema.findBuiltin(provider_name) != null;
}

const ProviderAccountRef = struct {
    provider: []const u8,
    account: []const u8,
    capability: ?[]const u8 = null,
};

fn splitProviderAccount(spec: []const u8) ?ProviderAccountRef {
    const idx = std.mem.indexOf(u8, spec, ":") orelse return null;
    if (idx == 0 or idx + 1 >= spec.len) return null;

    const rest = spec[idx + 1 ..];
    if (std.mem.indexOf(u8, rest, "#")) |hash| {
        if (hash == 0 or hash + 1 >= rest.len) return null;
        return .{
            .provider = spec[0..idx],
            .account = rest[0..hash],
            .capability = rest[hash + 1 ..],
        };
    }

    return .{ .provider = spec[0..idx], .account = rest };
}

fn isSupportedTokenField(field: []const u8) bool {
    return std.mem.eql(u8, field, "access_token") or
        std.mem.eql(u8, field, "refresh_token");
}

fn isSupportedProbeMethod(method: []const u8) bool {
    return std.mem.eql(u8, method, "GET") or
        std.mem.eql(u8, method, "POST") or
        std.mem.eql(u8, method, "HEAD");
}

fn isValidUrlTemplate(template: []const u8) bool {
    var offset: usize = 0;
    while (std.mem.indexOfPos(u8, template, offset, "{{")) |start| {
        const name_start = start + 2;
        const end = std.mem.indexOfPos(u8, template, name_start, "}}") orelse return false;
        if (!isSafeUrlTemplateName(template[name_start..end])) return false;
        offset = end + 2;
    }
    return std.mem.indexOfPos(u8, template, offset, "}}") == null;
}

fn isSafeUrlTemplateName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '_') continue;
        return false;
    }
    return true;
}

fn isSafeTokenHeaderName(header: []const u8) bool {
    if (header.len == 0) return false;
    if (std.ascii.eqlIgnoreCase(header, "authorization")) return false;
    for (header) |c| {
        if (c <= 32 or c == 127 or c == ':') return false;
    }
    return true;
}

test "loadFromBytes minimal config" {
    const json =
        \\{
        \\  "version": 1,
        \\  "defaults": { "provider": "claude" },
        \\  "providers": {
        \\    "claude": {
        \\      "kind": "claude",
        \\      "config_dir_env": "CLAUDE_CONFIG_DIR",
        \\      "accounts": {
        \\        "work": {
        \\          "priority": 10,
        \\          "secret": { "backend": "env", "variable": "CLAUDE_TOKEN" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u32, 1), parsed.value.version);
    try std.testing.expectEqualStrings("claude", parsed.value.defaults.provider.?);

    const providers = parsed.value.providers.map;
    try std.testing.expectEqual(@as(usize, 1), providers.count());
    const claude = providers.get("claude").?;
    try std.testing.expectEqualStrings("claude", claude.kind);

    const accounts = claude.accounts.map;
    try std.testing.expectEqual(@as(usize, 1), accounts.count());
    const work = accounts.get("work").?;
    try std.testing.expectEqual(@as(i32, 10), work.priority);
    try std.testing.expectEqualStrings("env", work.secret.backend);
    try std.testing.expectEqualStrings("CLAUDE_TOKEN", work.secret.variable.?);
}

test "loadFromBytes accepts managed launch defaults" {
    const json =
        \\{
        \\  "version": 1,
        \\  "defaults": {
        \\    "provider": "codex",
        \\    "profile": "codex-max",
        \\    "capability": "codex-max"
        \\  },
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": {
        \\          "secret": { "backend": "env", "variable": "CODEX_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": { "providers": ["codex:max-1#codex-max"] }
        \\  },
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    try std.testing.expectEqualStrings("codex", parsed.value.defaults.provider.?);
    try std.testing.expectEqualStrings("codex-max", parsed.value.defaults.profile.?);
    try std.testing.expectEqualStrings("codex-max", parsed.value.defaults.capability.?);

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try validate(parsed.value, out.writer());
    try std.testing.expectEqual(@as(usize, 0), out.items.len);
}

test "loadFromBytes provider definition override" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "display_name": "Toy CLI",
        \\      "extension_mode": "command_adapter",
        \\      "runtime": {
        \\        "required_binaries": ["toy"],
        \\        "env_vars": ["TOY_HOME"]
        \\      },
        \\      "repair": {
        \\        "owner": "upstream_cli_login"
        \\      },
        \\      "credential": {
        \\        "access_token_path": "tokens.access",
        \\        "refresh_token_path": "tokens.refresh"
        \\      },
        \\      "injection": {
        \\        "direct_env": [["TOY_TOKEN", "access_token"]]
        \\      },
        \\      "capabilities": [
        \\        {
        \\          "name": "chat:max",
        \\          "aliases": ["codex-max"],
        \\          "probe": {
        \\            "method": "POST",
        \\            "url": "https://example.invalid/v1/probe",
        \\            "hint_header": "www-authenticate",
        \\            "budget": "spend_provider"
        \\          }
        \\        }
        \\      ],
        \\      "failure_rules": [
        \\        {
        \\          "status": 403,
        \\          "hint_contains": "scope",
        \\          "class": { "degraded": "scope_insufficient" }
        \\        }
        \\      ]
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "TOY_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    const def = resolveProviderDefinition(parsed.value, "toy");
    try std.testing.expectEqualStrings("Toy CLI", def.display_name);
    try std.testing.expectEqual(types.ProviderExtensionMode.command_adapter, def.extension_mode);
    try std.testing.expectEqual(types.RepairOwner.upstream_cli_login, def.repair.owner);
    try std.testing.expectEqualStrings("toy", def.runtime.required_binaries[0]);
    try std.testing.expectEqualStrings("TOY_HOME", def.runtime.env_vars[0]);
    try std.testing.expectEqualStrings("tokens.access", def.credential.access_token_path);
    try std.testing.expectEqual(@as(usize, 1), def.capabilities.len);
    const plan = provider_schema.probePlanForCapability(def, "codex-max").?;
    try std.testing.expectEqualStrings("chat:max", plan.capability);
    try std.testing.expectEqualStrings("POST", plan.method);
    try std.testing.expectEqual(types.ActionBudget.spend_provider, plan.budget);
    try std.testing.expectEqual(@as(usize, 1), def.failure_rules.len);
    const classified = provider_schema.classifyHttp(def, 403, null, "missing scope");
    switch (classified) {
        .degraded => |reason| try std.testing.expectEqual(types.DegradedReason.scope_insufficient, reason),
        else => return error.TestUnexpectedResult,
    }

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try validate(parsed.value, out.writer());
    try std.testing.expectEqual(@as(usize, 0), out.items.len);
}

test "loadFromBytes accepts daemon budget policy" {
    const json =
        \\{
        \\  "version": 1,
        \\  "policy": {
        \\    "daemon": {
        \\      "allowed_budgets": ["free_local", "free_command", "cheap_provider"],
        \\      "allow_interactive": false,
        \\      "allow_mutating": false
        \\    }
        \\  },
        \\  "providers": {
        \\    "claude": {
        \\      "kind": "claude",
        \\      "accounts": {
        \\        "work": {
        \\          "secret": { "backend": "env", "variable": "CLAUDE_TOKEN" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    try std.testing.expect(daemonPolicyAllowsBudget(parsed.value.policy.daemon, .free_local));
    try std.testing.expect(daemonPolicyAllowsBudget(parsed.value.policy.daemon, .cheap_provider));
    try std.testing.expect(!daemonPolicyAllowsBudget(parsed.value.policy.daemon, .spend_provider));
    try std.testing.expect(!parsed.value.policy.daemon.allow_interactive);
    try std.testing.expect(!parsed.value.policy.daemon.allow_mutating);
}

test "default daemon policy admits only local and command budgets" {
    const policy = PolicyConfig{};
    try std.testing.expect(daemonPolicyAllowsBudget(policy.daemon, .free_local));
    try std.testing.expect(daemonPolicyAllowsBudget(policy.daemon, .free_command));
    try std.testing.expect(!daemonPolicyAllowsBudget(policy.daemon, .cheap_provider));
    try std.testing.expect(!daemonPolicyAllowsBudget(policy.daemon, .spend_provider));
    try std.testing.expect(!policy.daemon.allow_interactive);
    try std.testing.expect(!policy.daemon.allow_mutating);
}

test "default Codex policy admits provider spend only for Codex stay-afloat" {
    const policy = PolicyConfig{};
    const codex = effectiveDaemonPolicyForProvider(policy, "codex");
    try std.testing.expect(daemonPolicyAllowsBudget(codex, .spend_provider));
    try std.testing.expect(daemonPolicyAllowsBudget(codex, .cheap_provider));
    try std.testing.expect(!codex.allow_interactive);
    try std.testing.expect(!codex.allow_mutating);

    const claude = effectiveDaemonPolicyForProvider(policy, "claude");
    try std.testing.expect(!daemonPolicyAllowsBudget(claude, .spend_provider));
    try std.testing.expect(!daemonPolicyAllowsBudget(claude, .cheap_provider));
}

test "validate rejects unknown provider kind without definition" {
    const json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "TOY_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.ConfigValidationError, validate(parsed.value, out.writer()));
    try std.testing.expect(std.mem.indexOf(u8, out.items, "has no built-in or provider_definitions entry") != null);
}

test "validate rejects a provider name containing ':' (warm-loop key codec contract)" {
    const json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "a:b": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "default": { "secret": { "backend": "env", "variable": "X" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.ConfigValidationError, validate(parsed.value, out.writer()));
    try std.testing.expect(std.mem.indexOf(u8, out.items, "must not contain ':'") != null);
}

test "validate rejects unknown profile account" {
    const json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": {
        \\          "secret": { "backend": "env", "variable": "CODEX_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "research": { "providers": ["codex:max-2"] }
        \\  },
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.ConfigValidationError, validate(parsed.value, out.writer()));
    try std.testing.expect(std.mem.indexOf(u8, out.items, "unknown account 'codex:max-2'") != null);
}

test "validate rejects unknown default profile" {
    const json =
        \\{
        \\  "version": 1,
        \\  "defaults": {
        \\    "profile": "missing"
        \\  },
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": {
        \\          "secret": { "backend": "env", "variable": "CODEX_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "codex-max": { "providers": ["codex:max-1#codex-max"] }
        \\  },
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.ConfigValidationError, validate(parsed.value, out.writer()));
    try std.testing.expect(std.mem.indexOf(u8, out.items, "defaults.profile references unknown profile 'missing'") != null);
}

test "validate accepts capability profile route" {
    const json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "max-1": {
        \\          "secret": { "backend": "env", "variable": "CODEX_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {
        \\    "research": { "providers": ["codex:max-1#codex-max"] }
        \\  },
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try validate(parsed.value, out.writer());
    try std.testing.expectEqual(@as(usize, 0), out.items.len);
}

test "validate rejects unsupported direct env token field" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "credential": { "access_token_path": "access" },
        \\      "injection": {
        \\        "direct_env": [["TOY_EXPIRES", "expires_at"]]
        \\      }
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "TOY_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.ConfigValidationError, validate(parsed.value, out.writer()));
    try std.testing.expect(std.mem.indexOf(u8, out.items, "unsupported token field 'expires_at'") != null);
}

test "validate rejects unsupported capability probe method" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "credential": { "access_token_path": "access" },
        \\      "capabilities": [
        \\        {
        \\          "name": "chat:max",
        \\          "probe": {
        \\            "method": "TRACE",
        \\            "url": "https://example.invalid/v1/probe"
        \\          }
        \\        }
        \\      ]
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "TOY_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.ConfigValidationError, validate(parsed.value, out.writer()));
    try std.testing.expect(std.mem.indexOf(u8, out.items, "probe.method 'TRACE' is unsupported") != null);
}

test "validate rejects empty command capability probe" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "credential": { "access_token_path": "access" },
        \\      "capabilities": [
        \\        {
        \\          "name": "chat:max",
        \\          "probe": {
        \\            "transport": "command",
        \\            "command": []
        \\          }
        \\        }
        \\      ]
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "TOY_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.ConfigValidationError, validate(parsed.value, out.writer()));
    try std.testing.expect(std.mem.indexOf(u8, out.items, "probe.command must not be empty") != null);
}

test "validate rejects zero capability probe timeout" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "credential": { "access_token_path": "access" },
        \\      "capabilities": [
        \\        {
        \\          "name": "chat:max",
        \\          "probe": {
        \\            "method": "GET",
        \\            "url": "https://example.invalid/v1/probe",
        \\            "timeout_ms": 0
        \\          }
        \\        }
        \\      ]
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "TOY_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.ConfigValidationError, validate(parsed.value, out.writer()));
    try std.testing.expect(std.mem.indexOf(u8, out.items, "probe.timeout_ms must be greater than zero") != null);
}

test "validate rejects interactive probe budget" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "credential": { "access_token_path": "access" },
        \\      "capabilities": [
        \\        {
        \\          "name": "chat:max",
        \\          "probe": {
        \\            "method": "GET",
        \\            "url": "https://example.invalid/v1/probe",
        \\            "budget": "interactive"
        \\          }
        \\        }
        \\      ],
        \\      "failure_rules": [
        \\        { "status": 401, "class": { "dead": "token_revoked" } }
        \\      ]
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "TOY_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.ConfigValidationError, validate(parsed.value, out.writer()));
    try std.testing.expect(std.mem.indexOf(u8, out.items, "probe.budget 'interactive' is not valid for probes") != null);
}

test "validate rejects token material in http probe url" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "credential": { "access_token_path": "access" },
        \\      "capabilities": [
        \\        {
        \\          "name": "chat:max",
        \\          "probe": {
        \\            "method": "GET",
        \\            "url": "https://example.invalid/v1/probe?access_token=secret"
        \\          }
        \\        }
        \\      ]
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "TOY_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.ConfigValidationError, validate(parsed.value, out.writer()));
    try std.testing.expect(std.mem.indexOf(u8, out.items, "probe.url must not contain token material") != null);
}

test "validate rejects malformed url template placeholder" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "credential": { "access_token_path": "access" },
        \\      "capabilities": [
        \\        {
        \\          "name": "identity",
        \\          "probe": {
        \\            "method": "GET",
        \\            "url": "https://example.invalid/v1/files/{{BAD-NAME}}/meta"
        \\          }
        \\        }
        \\      ],
        \\      "failure_rules": [
        \\        { "status": 403, "class": { "degraded": "scope_insufficient" } }
        \\      ]
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "TOY_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.ConfigValidationError, validate(parsed.value, out.writer()));
    try std.testing.expect(std.mem.indexOf(u8, out.items, "probe.url contains an invalid template placeholder") != null);
}

test "validate rejects token material in http probe body" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "credential": { "access_token_path": "access" },
        \\      "capabilities": [
        \\        {
        \\          "name": "chat:max",
        \\          "probe": {
        \\            "method": "POST",
        \\            "url": "https://example.invalid/v1/probe",
        \\            "body": "{\"access_token\":\"secret\"}"
        \\          }
        \\        }
        \\      ]
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "TOY_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.ConfigValidationError, validate(parsed.value, out.writer()));
    try std.testing.expect(std.mem.indexOf(u8, out.items, "probe.body must not contain token material") != null);
}

test "validate rejects http probe body without post" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "credential": { "access_token_path": "access" },
        \\      "capabilities": [
        \\        {
        \\          "name": "chat:max",
        \\          "probe": {
        \\            "method": "GET",
        \\            "url": "https://example.invalid/v1/probe",
        \\            "body": "{}"
        \\          }
        \\        }
        \\      ],
        \\      "failure_rules": [
        \\        { "status": 401, "class": { "dead": "token_revoked" } }
        \\      ]
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "TOY_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.ConfigValidationError, validate(parsed.value, out.writer()));
    try std.testing.expect(std.mem.indexOf(u8, out.items, "probe.body requires method POST") != null);
}

test "validate rejects token header auth without header name" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "credential": { "access_token_path": "access" },
        \\      "capabilities": [
        \\        {
        \\          "name": "identity",
        \\          "probe": {
        \\            "method": "GET",
        \\            "url": "https://example.invalid/v1/me",
        \\            "auth": "token_header"
        \\          }
        \\        }
        \\      ],
        \\      "failure_rules": [
        \\        { "status": 403, "class": { "degraded": "scope_insufficient" } }
        \\      ]
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "TOY_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.ConfigValidationError, validate(parsed.value, out.writer()));
    try std.testing.expect(std.mem.indexOf(u8, out.items, "probe.auth_header is required when auth is token_header") != null);
}

test "validate rejects authorization as custom token header" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "credential": { "access_token_path": "access" },
        \\      "capabilities": [
        \\        {
        \\          "name": "identity",
        \\          "probe": {
        \\            "method": "GET",
        \\            "url": "https://example.invalid/v1/me",
        \\            "auth": "token_header",
        \\            "auth_header": "Authorization"
        \\          }
        \\        }
        \\      ],
        \\      "failure_rules": [
        \\        { "status": 403, "class": { "degraded": "scope_insufficient" } }
        \\      ]
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "TOY_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.ConfigValidationError, validate(parsed.value, out.writer()));
    try std.testing.expect(std.mem.indexOf(u8, out.items, "probe.auth_header must be a non-Authorization HTTP header name") != null);
}

test "validate accepts raw authorization header auth" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "credential": { "access_token_path": "access" },
        \\      "capabilities": [
        \\        {
        \\          "name": "identity-api-key",
        \\          "probe": {
        \\            "method": "GET",
        \\            "url": "https://example.invalid/v1/me",
        \\            "auth": "authorization_header"
        \\          }
        \\        }
        \\      ],
        \\      "failure_rules": [
        \\        { "status": 403, "class": { "degraded": "scope_insufficient" } }
        \\      ]
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "TOY_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try validate(parsed.value, out.writer());
}

test "validate rejects auth header without token header auth" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "credential": { "access_token_path": "access" },
        \\      "capabilities": [
        \\        {
        \\          "name": "identity",
        \\          "probe": {
        \\            "method": "GET",
        \\            "url": "https://example.invalid/v1/me",
        \\            "auth": "bearer",
        \\            "auth_header": "X-Figma-Token"
        \\          }
        \\        }
        \\      ],
        \\      "failure_rules": [
        \\        { "status": 403, "class": { "degraded": "scope_insufficient" } }
        \\      ]
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "TOY_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.ConfigValidationError, validate(parsed.value, out.writer()));
    try std.testing.expect(std.mem.indexOf(u8, out.items, "probe.auth_header requires auth token_header") != null);
}

test "validate rejects token material in command probe argv" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "credential": { "access_token_path": "access" },
        \\      "capabilities": [
        \\        {
        \\          "name": "chat:max",
        \\          "probe": {
        \\            "transport": "command",
        \\            "command": ["toy", "probe", "--header", "Authorization: Bearer secret"]
        \\          }
        \\        }
        \\      ]
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "TOY_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.ConfigValidationError, validate(parsed.value, out.writer()));
    try std.testing.expect(std.mem.indexOf(u8, out.items, "probe.command[3] must not contain token material") != null);
}

test "validate rejects probed provider without failure rules" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "credential": { "access_token_path": "access" },
        \\      "capabilities": [
        \\        {
        \\          "name": "chat:max",
        \\          "probe": {
        \\            "method": "GET",
        \\            "url": "https://example.invalid/v1/probe"
        \\          }
        \\        }
        \\      ]
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "TOY_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.ConfigValidationError, validate(parsed.value, out.writer()));
    try std.testing.expect(std.mem.indexOf(u8, out.items, "must define failure_rules when capabilities include probes") != null);
}

test "validate rejects catch-all failure rule" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "credential": { "access_token_path": "access" },
        \\      "failure_rules": [
        \\        { "class": { "degraded": "unknown_4xx" } }
        \\      ]
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "TOY_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.ConfigValidationError, validate(parsed.value, out.writer()));
    try std.testing.expect(std.mem.indexOf(u8, out.items, "failure_rules[0] must include at least one matcher") != null);
}

test "validate accepts exact failure rule hint matcher" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "credential": { "access_token_path": "access" },
        \\      "failure_rules": [
        \\        { "hint_equals": "0", "class": { "rate_limited": {} } }
        \\      ]
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "TOY_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try validate(parsed.value, out.writer());
}

test "validate rejects empty failure rule exact hint" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "credential": { "access_token_path": "access" },
        \\      "failure_rules": [
        \\        { "status": 403, "hint_equals": "", "class": { "degraded": "unknown_4xx" } }
        \\      ]
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "TOY_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.ConfigValidationError, validate(parsed.value, out.writer()));
    try std.testing.expect(std.mem.indexOf(u8, out.items, "failure_rules[0].hint_equals must not be empty") != null);
}

test "validate rejects empty failure rule hint" {
    const json =
        \\{
        \\  "version": 1,
        \\  "provider_definitions": {
        \\    "toy": {
        \\      "name": "toy",
        \\      "credential": { "access_token_path": "access" },
        \\      "failure_rules": [
        \\        { "status": 403, "hint_contains": "", "class": { "degraded": "unknown_4xx" } }
        \\      ]
        \\    }
        \\  },
        \\  "providers": {
        \\    "toy": {
        \\      "kind": "toy",
        \\      "accounts": {
        \\        "default": {
        \\          "secret": { "backend": "env", "variable": "TOY_AUTH" }
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;
    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.testing.expectError(error.ConfigValidationError, validate(parsed.value, out.writer()));
    try std.testing.expect(std.mem.indexOf(u8, out.items, "failure_rules[0].hint_contains must not be empty") != null);
}

test "loadFromPath accepts relative config paths" {
    const allocator = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    {
        const file = try tmp.dir.createFile("config.json", .{});
        defer file.close();
        try file.writeAll(
            \\{
            \\  "version": 1,
            \\  "providers": {},
            \\  "profiles": {},
            \\  "strategies": {}
            \\}
        );
    }

    const cwd_path = try std.fs.cwd().realpathAlloc(allocator, ".");
    defer allocator.free(cwd_path);
    const config_path = try tmp.dir.realpathAlloc(allocator, "config.json");
    defer allocator.free(config_path);
    const relative_path = try std.fs.path.relative(allocator, cwd_path, config_path);
    defer allocator.free(relative_path);

    const parsed = try loadFromPath(allocator, relative_path);
    defer parsed.deinit();

    try std.testing.expectEqual(@as(u32, 1), parsed.value.version);
}

test "resolveSecretBackend keychain" {
    const secret = SecretConfig{
        .backend = "keychain",
        .service = "Claude Code-credentials",
        .account = "jess",
    };
    const backend = try resolveSecretBackend(secret);
    switch (backend) {
        .keychain => |ref| {
            try std.testing.expectEqualStrings("Claude Code-credentials", ref.service);
            try std.testing.expectEqualStrings("jess", ref.account);
        },
        else => return error.InvalidCharacter,
    }
}

test "resolveSecretBackend env" {
    const secret = SecretConfig{
        .backend = "env",
        .variable = "MY_TOKEN",
    };
    const backend = try resolveSecretBackend(secret);
    switch (backend) {
        .env => |ref| try std.testing.expectEqualStrings("MY_TOKEN", ref.variable),
        else => return error.InvalidCharacter,
    }
}

test "claude keychain accounts derive suffixed service from config_dir at load" {
    if (comptime builtin.os.tag != .macos) return error.SkipZigTest;
    const json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "claude": {
        \\      "kind": "claude",
        \\      "accounts": {
        \\        "xoxd": {
        \\          "secret": { "backend": "keychain" },
        \\          "config_dir": "/Users/jess/.local/share/oauth-mux/claude/xoxd"
        \\        },
        \\        "canonical": {
        \\          "secret": { "backend": "keychain" }
        \\        },
        \\        "pinned": {
        \\          "secret": { "backend": "keychain", "service": "Custom Service", "account": "explicit" },
        \\          "config_dir": "/Users/jess/.local/share/oauth-mux/claude/sulliwood"
        \\        }
        \\      }
        \\    },
        \\    "codex": {
        \\      "kind": "codex",
        \\      "accounts": {
        \\        "work": { "secret": { "backend": "keychain", "service": "Codex Auth", "account": "work" } }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;

    var overrides = std.process.EnvMap.init(std.testing.allocator);
    defer overrides.deinit();
    try overrides.put("USER", "jess");
    env.test_overrides = &overrides;
    defer env.test_overrides = null;

    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    const claude_accounts = parsed.value.providers.map.get("claude").?.accounts;

    // TIN-2060 golden vector: derived from the absolute config_dir, and
    // flagged derived so enroll rewrites never persist it as an operator pin.
    const xoxd = claude_accounts.map.get("xoxd").?;
    try std.testing.expectEqualStrings("Claude Code-credentials-26ae8e92", xoxd.secret.service.?);
    try std.testing.expectEqualStrings("jess", xoxd.secret.account.?);
    try std.testing.expect(xoxd.secret.derived_service);
    try std.testing.expect(xoxd.secret.derived_account);

    // No config_dir: nothing to derive a keychain identity from (the
    // launcher tmpdir-modes such accounts) — service stays null and the
    // account keeps failing validation loudly.
    const canonical = claude_accounts.map.get("canonical").?;
    try std.testing.expect(canonical.secret.service == null);

    // Explicit service/account always win over derivation.
    const pinned = claude_accounts.map.get("pinned").?;
    try std.testing.expectEqualStrings("Custom Service", pinned.secret.service.?);
    try std.testing.expectEqualStrings("explicit", pinned.secret.account.?);
    try std.testing.expect(!pinned.secret.derived_service);
    try std.testing.expect(!pinned.secret.derived_account);

    // Non-claude providers are untouched.
    const codex_work = parsed.value.providers.map.get("codex").?.accounts.map.get("work").?;
    try std.testing.expectEqualStrings("Codex Auth", codex_work.secret.service.?);

    // Round-trip: serializing a derived account elides the derived fields —
    // the on-disk config stays pristine operator truth.
    var out = std.ArrayList(u8).init(std.testing.allocator);
    defer out.deinit();
    try std.json.stringify(xoxd.secret, .{}, out.writer());
    try std.testing.expectEqualStrings("{\"backend\":\"keychain\"}", out.items);

    out.clearRetainingCapacity();
    try std.json.stringify(pinned.secret, .{}, out.writer());
    try std.testing.expectEqualStrings("{\"backend\":\"keychain\",\"service\":\"Custom Service\",\"account\":\"explicit\"}", out.items);
}

test "claude keychain derivation feeds resolveSecretBackend without explicit service" {
    if (comptime builtin.os.tag != .macos) return error.SkipZigTest;
    const json =
        \\{
        \\  "version": 1,
        \\  "providers": {
        \\    "claude": {
        \\      "kind": "claude",
        \\      "accounts": {
        \\        "sulliwood": {
        \\          "secret": { "backend": "keychain", "account": "jess" },
        \\          "config_dir": "/Users/jess/.local/share/oauth-mux/claude/sulliwood"
        \\        }
        \\      }
        \\    }
        \\  },
        \\  "profiles": {},
        \\  "strategies": {}
        \\}
    ;

    const parsed = try loadFromBytes(std.testing.allocator, json);
    defer parsed.deinit();

    const acct = parsed.value.providers.map.get("claude").?.accounts.map.get("sulliwood").?;
    const backend = try resolveSecretBackend(acct.secret);
    switch (backend) {
        .keychain => |ref| {
            try std.testing.expectEqualStrings("Claude Code-credentials-cec7498b", ref.service);
            try std.testing.expectEqualStrings("jess", ref.account);
        },
        else => return error.TestUnexpectedResult,
    }
}
