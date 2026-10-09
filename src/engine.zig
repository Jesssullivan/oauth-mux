//! Single-writer daemon actor. Public responses contain metadata only; grant
//! materialization is confined to capability-authenticated native channels.
const std = @import("std");
const builtin = @import("builtin");
const control = @import("control.zig");
const domain = @import("domain.zig");
const storage = @import("storage.zig");
const envelope = @import("envelope.zig");
const instance = @import("instance.zig");
const onboarding = @import("onboarding.zig");
const setup_evidence = @import("setup_evidence.zig");
const setup_collector = @import("setup_collector.zig");
const service_observation = @import("service_observation.zig");
const reliability_commit = @import("reliability_commit.zig");
const setup_verification = @import("setup_verification.zig");
const application_readiness = @import("application_readiness.zig");
const terminal_adapter_setup = @import("terminal_adapter_setup.zig");
const terminal_removal = @import("terminal_removal.zig");
const lifecycle_witness = @import("reliability_lifecycle_witness.zig");
const native_removal_witness = @import("reliability_lifecycle_native_removal_witness.zig");
const native_removal_timing = @import("reliability_lifecycle_native_removal.zig");
const lifecycle_source = @import("reliability_lifecycle_source.zig");
const vault = @import("vault.zig");
const transport = @import("transport.zig");
const browser = @import("browser_bridge.zig");
const browser_attempt = @import("browser_attempt.zig");
const catalog = @import("catalog.zig");
const git = @import("integrations/git.zig");
const codex = @import("integrations/codex.zig");
const paths = @import("paths.zig");
const setup = @import("integrations/setup.zig");
const measured_runtime = @import("integrations/measured_runtime_selection.zig");
const product = @import("product.zig");
const discovery = @import("discovery.zig");
const observer = @import("observer.zig");
const native_probe = @import("integrations/native_probe.zig");
const native_inventory = @import("integrations/native_inventory.zig");
const request_authority = @import("request_authority.zig");
const mutation_authority = @import("mutation_authority.zig");
const snapshot_admission = @import("snapshot_admission.zig");
const native_owner = @import("native_owner.zig");
const native_work = @import("native_owner_work.zig");
const peer = @import("platform/peer.zig");
const reliability = @import("reliability.zig");
const sql_api = @import("c");

pub const Channel = control.Channel;
const Policy = struct { sticky_routes: bool = true, warm_alternatives: bool = true };
const PublicAccountView = struct {
    id: []const u8,
    label: []const u8,
    account_type: []const u8,
    lifecycle: domain.AccountLifecycle,
    identity: struct { provider: []const u8, verified: bool },
    source_ids: []const []const u8,
};

fn publicAccountView(account: domain.Account) PublicAccountView {
    return .{
        .id = account.id,
        .label = account.label,
        .account_type = account.account_type,
        .lifecycle = account.lifecycle,
        .identity = .{ .provider = account.identity.provider, .verified = account.identity.verified },
        .source_ids = account.source_ids,
    };
}

const SourceDescription = struct { source_id: []const u8, provider: []const u8, label: []const u8 = "", path: []const u8 = "" };
const OutcomeIntent = struct {
    key: snapshot_admission.Key,
    owner_id: []const u8,
    secondary_id: []const u8 = "",
    source_id: []const u8 = "",
    source_generation: u64 = 0,
    provider: []const u8 = "",
    label: []const u8 = "",
    grant_generation: u64 = 0,
    plan_bytes: usize,
    plan_counts: snapshot_admission.Counts = .{},
    used_bytes: usize = 0,
    used_counts: snapshot_admission.Counts = .{},
    native_ref: ?native_owner.NativeRef = null,
};
const InstallationSelection = struct {
    prefix: []u8,
    receipt_path: []u8,
    service_path: ?[]u8 = null,
    runtime_dir: ?[]u8 = null,
    service_record_path: ?[]u8 = null,
    selection: instance.Selection = .default,
};
const InstallationObserved = struct { probe: setup_collector.Collected = .{}, service_status: ?service_observation.Status = null };

fn serviceObservationBudget(remaining_ms: i128) !u32 {
    if (remaining_ms <= 0) return error.Timeout;
    return @intCast(@min(remaining_ms, 2000));
}

fn serviceObservationNeedsRecheck(status: service_observation.Status) !bool {
    return switch (status) {
        .timeout => error.Timeout,
        .ok => true,
        .unsupported, .unavailable, .unsafe_bus, .invalid => false,
    };
}

fn collectInstallation(io: std.Io, allocator: std.mem.Allocator, selected: InstallationSelection, deadline: std.Io.Clock.Timestamp) !InstallationObserved {
    var observed: InstallationObserved = .{ .probe = try setup_collector.collect(io, allocator, .{
        .prefix = selected.prefix,
        .receipt_path = selected.receipt_path,
        .service_path = selected.service_path,
        .service_record_path = selected.service_record_path,
        .deadline = deadline,
    }) };
    if (builtin.os.tag != .linux) return observed;
    const runtime = selected.runtime_dir orelse return observed;
    const witness = observed.probe.service_witness orelse return observed;
    if (observed.probe.artifact.payload != .matches or observed.probe.artifact.running_executable != .matches or observed.probe.service.definition != .matches) return observed;
    if (!eql(std.fs.path.basename(witness.fragment()), service_observation.unitName(selected.selection))) {
        observed.service_status = .invalid;
        observed.probe.service.instance_binding = .differs;
        return observed;
    }
    const runtime_z = try allocator.dupeSentinel(u8, runtime, 0);
    defer allocator.free(runtime_z);
    const timeout_ms = try serviceObservationBudget(deadline.durationFromNow(io).raw.toMilliseconds());
    const live = try service_observation.observe(.{
        .runtime_dir = runtime_z,
        .expected_fragment = witness.fragment(),
        .expected = .{ .selection = selected.selection, .definition = .matches, .running_executable = .matches, .login_link = witness.login_link },
        .timeout_ms = timeout_ms,
    });
    observed.service_status = live.status;
    if (!try serviceObservationNeedsRecheck(live.status)) return observed;
    const definition = try setup_collector.recheckServiceWitness(io, allocator, &witness, deadline);
    if (definition != .matches) {
        observed.probe.service = .{ .definition = definition, .instance_binding = definition, .freshness = .current };
        return observed;
    }
    observed.probe.service = live.service;
    const login_link = try setup_collector.recheckLoginLink(io, allocator, &witness, deadline);
    if (login_link != .matches) observed.probe.service.login_enabled = login_link;
    return observed;
}

const SetupVerificationRef = struct { slot: usize, fingerprint: [32]u8, credit: snapshot_admission.Key, started: std.Io.Timestamp };
const SetupRefreshTask = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    selected: InstallationSelection,
    deadline: std.Io.Clock.Timestamp,
    generation: u64,
    verification: ?SetupVerificationRef = null,
    thread: ?std.Thread = null,
    done: std.atomic.Value(bool) = .init(false),
    result: InstallationObserved = .{},
    collection_error: ?anyerror = null,
    observed_at: i64 = 0,

    fn run(self: *SetupRefreshTask) void {
        self.result = collectInstallation(self.io, self.allocator, self.selected, self.deadline) catch |err| observed: {
            self.collection_error = err;
            break :observed .{ .probe = .{ .failure = setup_collector.failureForError(err) } };
        };
        self.observed_at = std.Io.Clock.real.now(self.io).toSeconds();
        self.done.store(true, .release);
    }
};
const MutationPlan = struct { bytes: usize, slots: snapshot_admission.Counts = .{} };
// One bounded read-only job on the existing native I/O supervisor. It owns
// mutable collection buffers, participates in shutdown, and executes no app.
const RuntimeMeasureTask = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    arena: std.heap.ArenaAllocator,
    context: measured_runtime.Context,
    directory: std.c.fd_t,
    job: native_work.Job,
    observed: ?*measured_runtime.MeasuredInstalledRuntime = null,
    failure: ?anyerror = null,
    fn run(opaque_context: *anyopaque, canceled: bool) void {
        const self: *RuntimeMeasureTask = @ptrCast(@alignCast(opaque_context));
        if (canceled) {
            self.failure = error.ServiceStopping;
            return;
        }
        self.observed = measured_runtime.observe(self.io, self.allocator, self.context, self.directory) catch |err| failed: {
            self.failure = err;
            break :failed null;
        };
    }
    fn deinit(self: *RuntimeMeasureTask) void {
        if (self.observed) |observed| observed.deinit();
        _ = std.c.close(self.directory);
        self.arena.deinit();
        self.allocator.destroy(self);
    }
};
const Persisted = struct {
    // Empty initialization remains decodable. Legacy database/checkpoint
    // versions require explicit migration before custody effects.
    schema_version: u32 = 1,
    lifecycle_measurements: ?*const reliability.LifecycleRecorder = null,
    browser_attempt_authority: ?browser_attempt.Snapshot = null,
    state: domain.Snapshot = .{},
    policy: Policy = .{},
    installed_integrations: []const []const u8 = &.{},
    source_descriptions: []const SourceDescription = &.{},
    adapter_epochs: [4]u64 = .{ 1, 1, 1, 1 },
    request_authority: request_authority.Snapshot = .{},
    mutation_authority: mutation_authority.Snapshot = .{},
    snapshot_admission: snapshot_admission.Snapshot = .{},
    import_source_authority: []const ImportSourceAuthority = &.{},
    import_forget_epoch: u64 = 0,
    outcome_intents: []const OutcomeIntent = &.{},
    maintenance_growth_bytes: ?usize = null,
    native_owner_authority: native_owner.Snapshot = .{},
    native_registry: ?setup.RegistryWitness = null,
    // Optional historical metadata. Absence never selects or activates bytes.
    measured_codex_runtime: ?measured_runtime.Committed = null,
};
const Invocation = struct {
    allocator: std.mem.Allocator,
    payload: []const u8,
    channel: Channel,
    until: std.Io.Clock.Timestamp,
    response: ?[]u8 = null,
    failure: ?anyerror = null,
    finished: bool = false,
    condition: std.Io.Condition = .init,
    peer_context: ?peer.Context = null,
};
// An invocation cannot return while its continuation owns this stack waiter.
// Protocol arguments, socket context and replies are heap-owned independently
// of the caller and parser. Only the actor writes durable lifecycle state.
const NativeTask = struct {
    engine: *Engine,
    invocation: *Invocation,
    request: control.Request,
    job: native_work.Job,
    stage: enum { identify, registration, announcement_identify, announcement, detachment, discovery },
    operation: native_owner.OperationId,
    native_operation: ?native_owner.OperationId = null,
    removal_operation: ?native_owner.OperationId = null,
    endpoint: []u8,
    thread_id: []u8,
    broker_socket: []u8,
    capability_path: []u8,
    expected: ?peer.Witness = null,
    claimed_owner: [32]u8 = @splat(0),
    nonce: [32]u8 = @splat(0),
    endpoint_generation: u64 = 0,
    thread_generation: u64 = 0,
    reference: ?native_owner.NativeRef = null,
    connection: ?native_probe.OwnerConnection = null,
    identity: ?native_probe.OwnerIdentity = null,
    acknowledgement: ?native_probe.OwnerAck = null,
    discovered: std.ArrayList(native_probe.OwnerLoadedThreads) = .empty,
    discovery_context: ?*std.heap.ArenaAllocator = null,
    discovery_options: ?setup.Options = null,
    discovery_until: ?std.Io.Clock.Timestamp = null,
    scanned_entries: usize = 0,
    ignored_stale_entries: usize = 0,
    selected_owner: bool = false,
    selected_registry: ?setup.RegistryWitness = null,
    failure: ?anyerror = null,
    mutation_slot: ?usize = null,
    removal_measurement: ?native_removal_witness.Session = null,
    credit: ?snapshot_admission.Key = null,
    admitted: bool = false,
    removing: bool = false,
    registry: ?setup.RegistryWitness = null,

    fn run(opaque_context: *anyopaque, canceled: bool) void {
        const self: *NativeTask = @ptrCast(@alignCast(opaque_context));
        self.failure = null;
        if (canceled) {
            self.failure = error.ServiceStopping;
            return;
        }
        self.perform() catch |err| {
            self.failure = err;
        };
    }
    fn perform(self: *NativeTask) !void {
        const io = self.engine.io;
        const allocator = self.engine.allocator;
        if (self.stage == .discovery) {
            var budget = try native_inventory.Budget.init(io, self.invocation.until);
            self.discovery_until = budget.until;
            if (self.endpoint.len != 0) {
                const options = self.discovery_options orelse return error.InvalidNativeOwnerContext;
                if (options.codex_home_explicit or options.config_path != null) {
                    const selected_home = try setup.selectedCodexHome(io, allocator, options);
                    allocator.free(selected_home);
                }
                const loaded = try native_probe.loadedOwnerThreadsWithDeadline(io, allocator, self.endpoint, product.version, budget.until);
                self.discovered.append(allocator, loaded) catch |err| {
                    loaded.deinit(allocator);
                    return err;
                };
            } else {
                var options = self.discovery_options orelse return error.InvalidNativeOwnerContext;
                options.deadline = budget.until;
                const selected_home = try setup.selectedCodexHome(io, allocator, options);
                defer allocator.free(selected_home);
                var inventory = try native_inventory.collect(io, allocator, selected_home, &budget);
                defer inventory.deinit();
                self.scanned_entries = inventory.scanned_entries;
                self.ignored_stale_entries = inventory.ignored_stale_entries;
                for (inventory.candidates) |*candidate| {
                    try budget.check(io);
                    const loaded = try native_probe.loadedAutomaticOwnerThreadsWithDeadline(io, allocator, candidate, product.version, budget.until);
                    self.discovered.append(allocator, loaded) catch |err| {
                        loaded.deinit(allocator);
                        return err;
                    };
                    // Refuse the entire query before further probes once the
                    // exact public aggregate exceeds its response boundary.
                    var arena: std.heap.ArenaAllocator = .init(allocator);
                    defer arena.deinit();
                    try requireNativeDiscoveryFits(self.request.id, try nativeDiscoveryResult(arena.allocator(), self, null, false));
                }
                try budget.check(io);
                try inventory.verify(allocator);
            }
            try budget.check(io);
            return;
        }
        if (self.stage == .announcement_identify and self.selected_owner) {
            // A UI-selected publication remains a hint until the original
            // selected context, pinned path and fresh peer have all matched.
            // No mutation admission or native effect precedes these checks.
            var budget = try native_inventory.Budget.init(io, self.invocation.until);
            self.discovery_until = budget.until;
            var options = self.discovery_options orelse return error.InvalidNativeOwnerContext;
            options.deadline = budget.until;
            if (!std.meta.eql(self.selected_registry, try setup.registryWitness(io, allocator, options))) return error.NativeCustodyGenerationMismatch;
            const selected_home = try setup.selectedCodexHome(io, allocator, options);
            defer allocator.free(selected_home);
            var inventory = try native_inventory.collect(io, allocator, selected_home, &budget);
            defer inventory.deinit();
            var selected: ?*const native_inventory.Candidate = null;
            for (inventory.candidates) |*candidate| {
                if (!eql(candidate.endpoint_path, self.endpoint)) continue;
                if (selected != null) return error.NativeOwnerAmbiguous;
                if (!candidate.matchesOwner(self.claimed_owner)) return error.NativeOwnerMismatch;
                selected = candidate;
            }
            const candidate = selected orelse return error.NativeEndpointOutsideContext;
            self.connection = try native_probe.OwnerConnection.openAutomatic(io, allocator, candidate, budget.until);
            self.identity = try self.connection.?.identify(self.thread_id, self.operation);
            const identity = self.identity.?;
            if (!std.mem.eql(u8, &identity.owner_id, &self.claimed_owner) or !std.mem.eql(u8, &identity.native_nonce, &self.nonce) or identity.endpoint_generation != self.endpoint_generation or identity.thread_instance_generation != self.thread_generation or !eql(identity.thread_id, self.thread_id)) return error.NativeOwnerMismatch;
            try budget.check(io);
            try inventory.verify(allocator);
            if (!std.meta.eql(self.selected_registry, try setup.registryWitness(io, allocator, options))) return error.NativeCustodyGenerationMismatch;
            try budget.check(io);
            return;
        }
        if (self.connection == null) self.connection = try native_probe.OwnerConnection.open(io, allocator, self.endpoint, self.expected, self.invocation.until);
        switch (self.stage) {
            .identify, .announcement_identify => self.identity = try self.connection.?.identify(self.thread_id, self.operation),
            .registration => self.acknowledgement = try self.connection.?.register(.{ .reference = self.reference.?, .thread_id = self.thread_id, .native_nonce = self.nonce, .operation_id = self.operation, .broker_socket = self.broker_socket, .capability_path = self.capability_path }, self.expected.?),
            .announcement => self.acknowledgement = try self.connection.?.announce(self.thread_id, self.operation, .{ .broker_socket = self.broker_socket, .capability_path = self.capability_path }),
            .detachment => self.acknowledgement = try self.connection.?.detach(.{ .reference = self.reference.?, .thread_id = self.thread_id, .native_nonce = self.nonce, .operation_id = self.native_operation orelse self.operation }, self.expected.?),
            .discovery => unreachable,
        }
    }
    fn deinit(self: *NativeTask) void {
        const allocator = self.engine.allocator;
        if (self.identity) |*value| value.deinit(allocator);
        if (self.acknowledgement) |*value| value.deinit(allocator);
        if (self.connection) |*value| value.deinit();
        for (self.discovered.items) |value| value.deinit(allocator);
        self.discovered.deinit(allocator);
        if (self.discovery_options) |*options| {
            std.crypto.secureZero(u8, &options.key);
            std.crypto.secureZero(u8, &options.capability);
        }
        if (self.discovery_context) |arena| {
            arena.deinit();
            allocator.destroy(arena);
        }
        self.request.deinit();
        allocator.free(self.endpoint);
        allocator.free(self.thread_id);
        allocator.free(self.broker_socket);
        allocator.free(self.capability_path);
        allocator.destroy(self);
    }
};
const PendingImport = struct {
    network_id: u64,
    source_id: []u8,
    provider: []u8,
    credential_kind: domain.CredentialKind,
    allow_reenrollment: bool = false,
    source_generation: u64,
    job_generation: u64 = 0,
    // Process-local monotonic admission clock; never reconstructed on restart.
    measurement_started_at: ?std.Io.Timestamp = null,
    credit_key: snapshot_admission.Key,
    forget_epoch: u64,
    provider_account_id: ?[]u8 = null,
    custody_expires_at: ?i64 = null,
    job_id: []u8,
    token: []u8,
    label: []u8,
    expires_at: ?i64,
    fn deinit(self: *PendingImport, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, self.token);
        allocator.free(self.token);
        allocator.free(self.source_id);
        allocator.free(self.provider);
        if (self.provider_account_id) |hint| {
            std.crypto.secureZero(u8, hint);
            allocator.free(hint);
        }
        allocator.free(self.job_id);
        allocator.free(self.label);
    }
};
// Network completions are process-local. Source and job generations are durable
// fences; restart retains their unresolved outcome credits without adopting or
// resubmitting the missing completion.
const ImportSourceAuthority = struct { source_id: []u8, generation: u64 = 1 };
const ObservationCredit = struct { network_id: u64, key: snapshot_admission.Key };
const NativeLease = struct {
    handle: [64]u8,
    application: []u8,
    request_id: []u8,
    binding_id: []u8,
    demand_json: []u8,
    status: enum { issued, accepted, rejected, completed, abandoned } = .issued,
    native_ref: ?native_owner.NativeRef = null,
    expires_at: i64,
    account_id: []u8,
    attempt: u8 = 1,
    fn create(allocator: std.mem.Allocator, handle: [64]u8, application: []const u8, request_id: []const u8, binding_id: []const u8, account_id: []const u8, demand_json: []const u8, attempt: u8, expires_at: i64, native_ref: ?native_owner.NativeRef) !NativeLease {
        const owned_application = try allocator.dupe(u8, application);
        errdefer allocator.free(owned_application);
        const owned_request = try allocator.dupe(u8, request_id);
        errdefer allocator.free(owned_request);
        const owned_binding = try allocator.dupe(u8, binding_id);
        errdefer allocator.free(owned_binding);
        const owned_account = try allocator.dupe(u8, account_id);
        errdefer allocator.free(owned_account);
        const owned_demand = try allocator.dupe(u8, demand_json);
        return .{ .handle = handle, .application = owned_application, .request_id = owned_request, .binding_id = owned_binding, .account_id = owned_account, .demand_json = owned_demand, .attempt = attempt, .expires_at = expires_at, .native_ref = native_ref };
    }
    fn deinit(self: *NativeLease, allocator: std.mem.Allocator) void {
        allocator.free(self.account_id);
        allocator.free(self.application);
        allocator.free(self.request_id);
        allocator.free(self.binding_id);
        allocator.free(self.demand_json);
        std.crypto.secureZero(u8, &self.handle);
    }
};

pub const Engine = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    state_dir: []u8,
    instance_selection: instance.Selection = .default,
    installation_selection: ?InstallationSelection = null,
    installation_probe: setup_collector.Collected = .{},
    installation_probe_at: ?i64 = null,
    installation_service_status: ?service_observation.Status = null,
    installation_refresh: ?*SetupRefreshTask = null,
    installation_refresh_generation: u64 = 0,
    root_key: envelope.Key = @splat(0),
    root_id: ?[:0]u8 = null,
    poisoned: bool = false,
    vault_locked: bool = false,
    fixture_startup_vault_locked: bool = false,
    test_key: ?envelope.Key = null,
    test_vault: ?vault.Backend = null,
    fixture_custody_stage_failure: enum { none, database_open, state_allocation, supervisor_ready } = .none,
    state: domain.State,
    db: ?storage.Store = null,
    network: ?*transport.Client = null,
    observers: observer.Coordinator,
    last_source_poll: i64 = 0,
    last_secret_prune: i64 = 0,
    revision: u64 = 0,
    policy: Policy = .{},
    adapter_epochs: [4]u64 = .{ 1, 1, 1, 1 },
    installed: std.ArrayList([]const u8) = .empty,
    descriptions: std.ArrayList(SourceDescription) = .empty,
    pending_imports: std.ArrayList(PendingImport) = .empty,
    import_sources: std.ArrayList(ImportSourceAuthority) = .empty,
    import_forget_epoch: u64 = 0,
    native_leases: std.ArrayList(NativeLease) = .empty,
    requests: request_authority.Ledger,
    mutations: mutation_authority.Ledger,
    admission: snapshot_admission.Ledger,
    native_owners: native_owner.Ledger,
    active_peer: ?*const peer.Context = null,
    native_registry: ?setup.RegistryWitness = null,
    measured_codex_runtime: ?measured_runtime.Committed = null,
    codex_runtime_root: ?[]u8 = null,
    runtime_measurement: ?*RuntimeMeasureTask = null,
    runtime_measurement_requested: bool = false,
    runtime_measurement_failure: ?anyerror = null,
    native_workers: ?*native_work.Supervisor = null,
    native_tasks: std.ArrayList(*NativeTask) = .empty,
    active_credit: ?snapshot_admission.Key = null,
    committed_nonledger_bytes: usize = 0,
    committed_counts: snapshot_admission.Counts = .{},
    observation_credits: std.ArrayList(ObservationCredit) = .empty,
    fixture_identity_submissions: usize = 0,
    fixture_observation_submissions: usize = 0,
    fixture_force_poll: bool = false,
    fixture_hold_enrollment_start: bool = false,
    fixture_lifecycle_fault: enum { none, preparation, sqlite_commit, native_preparation_allocation } = .none,
    fixture_native_allocation_failed: bool = false,
    outcome_intents: std.ArrayList(OutcomeIntent) = .empty,
    maintenance_growth_bytes: usize = 0,
    lifecycle_measurements: ?*reliability.LifecycleRecorder = null,
    browser_attempts: ?browser_attempt.Ledger = null,
    staging_mutation: bool = false,
    staged_changes: std.ArrayList(storage.GrantChange) = .empty,
    metrics: reliability.Recorder,
    metrics_mutex: std.Io.Mutex = .init,
    metrics_failure: bool = false,
    mutex: std.Io.Mutex = .init,
    condition: std.Io.Condition = .init,
    queue: [32]?*Invocation = @splat(null),
    queue_head: usize = 0,
    queue_count: usize = 0,
    startup_complete: bool = false,
    startup_error: ?anyerror = null,
    stopping: bool = false,
    thread: ?std.Thread = null,
    active_until: ?std.Io.Clock.Timestamp = null,

    pub fn open(io: std.Io, allocator: std.mem.Allocator, state_dir: []const u8) !*Engine {
        return create(io, allocator, state_dir, null, .default);
    }

    pub fn openForInstance(io: std.Io, allocator: std.mem.Allocator, state_dir: []const u8, selection: instance.Selection) !*Engine {
        return create(io, allocator, state_dir, null, selection);
    }

    /// Synthetic tests supply keys; production cannot bypass vault custody.
    pub fn openWithKey(io: std.Io, allocator: std.mem.Allocator, state_dir: []const u8, key: envelope.Key) !*Engine {
        if (!builtin.is_test) return error.TestOnly;
        return create(io, allocator, state_dir, key, .default);
    }

    fn create(io: std.Io, allocator: std.mem.Allocator, state_dir: []const u8, key: ?envelope.Key, selection: instance.Selection) !*Engine {
        return createConfigured(io, allocator, state_dir, key, selection, null, false, null);
    }

    pub fn openWithMeasuredRootForTest(io: std.Io, allocator: std.mem.Allocator, state_dir: []const u8, key: envelope.Key, root: []const u8) !*Engine {
        if (!builtin.is_test) return error.TestOnly;
        return createConfigured(io, allocator, state_dir, key, .default, root, false, null);
    }

    fn createConfigured(io: std.Io, allocator: std.mem.Allocator, state_dir: []const u8, key: ?envelope.Key, selection: instance.Selection, test_root: ?[]const u8, locked_fixture: bool, test_backend: ?vault.Backend) !*Engine {
        if (locked_fixture and !builtin.is_test) return error.TestOnly;
        if (test_backend != null and !builtin.is_test) return error.TestOnly;
        try paths.validateAbsolute(state_dir);
        const self = try allocator.create(Engine);
        errdefer allocator.destroy(self);
        const owned_directory = try allocator.dupe(u8, state_dir);
        errdefer allocator.free(owned_directory);
        self.* = .{ .allocator = allocator, .io = io, .state_dir = owned_directory, .instance_selection = selection, .state = domain.State.init(allocator), .observers = observer.Coordinator.init(allocator), .requests = request_authority.Ledger.init(allocator, 4096), .mutations = try mutation_authority.Ledger.init(allocator, 4096), .admission = snapshot_admission.Ledger.init(allocator), .native_owners = native_owner.Ledger.init(allocator), .metrics = reliability.Recorder.init(std.Io.Clock.real.now(io).toSeconds(), .{ .os = switch (builtin.os.tag) {
            .linux => .linux,
            .macos => .macos,
            else => .other,
        }, .architecture = switch (builtin.cpu.arch) {
            .x86_64 => .x86_64,
            .aarch64 => .aarch64,
            else => .other,
        }, .evidence = if (builtin.is_test) .synthetic else .diagnostic }), .test_key = key };
        errdefer self.release();
        if (test_root) |root| {
            if (!builtin.is_test) return error.TestOnly;
            if (root.len > setup_collector.max_path_bytes) return error.InvalidInstallationSelection;
            const descriptor = try paths.openPrivateRoot(allocator, root, false);
            _ = std.c.close(descriptor);
            self.codex_runtime_root = try allocator.dupe(u8, root);
        }
        // A launch-time path is only a local observation selector. It is never
        // a package digest authority or a process/credential capability.
        if (!builtin.is_test) if (std.c.getenv("OMUX_CODEX_INSTALL_ROOT")) |value| {
            const root = std.mem.span(value);
            if (root.len > setup_collector.max_path_bytes) return error.InvalidInstallationSelection;
            const root_fd = try paths.openPrivateRoot(allocator, root, false);
            _ = std.c.close(root_fd);
            self.codex_runtime_root = try allocator.dupe(u8, root);
        };
        // Read-only installation probes run before the actor exists. Hints are
        // selectors only; the collector verifies receipt bytes and executable
        // binding before granting them any diagnostic ownership meaning.
        self.captureInstallationSelection() catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => self.installation_probe.failure = .invalid_receipt,
        };
        if (self.installation_selection) |selected| {
            var collection_timed_out = false;
            const observed = collectInstallation(io, allocator, selected, .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) })) catch |err| switch (err) {
                error.Timeout => observed: {
                    collection_timed_out = true;
                    break :observed InstallationObserved{ .probe = .{ .failure = setup_collector.failureForError(err) } };
                },
                else => return err,
            };
            self.installation_probe = observed.probe;
            self.installation_service_status = observed.service_status;
            self.installation_probe_at = if (collection_timed_out) null else self.now();
        }
        self.fixture_startup_vault_locked = locked_fixture;
        self.test_vault = test_backend;
        self.thread = try std.Thread.spawn(.{}, actor, .{self});
        self.mutex.lockUncancelable(io);
        while (!self.startup_complete) self.condition.waitUncancelable(io, &self.mutex);
        const failure = self.startup_error;
        self.mutex.unlock(io);
        if (failure) |err| {
            self.thread.?.join();
            return err;
        }
        return self;
    }

    pub fn deinit(self: *Engine) void {
        self.mutex.lockUncancelable(self.io);
        self.stopping = true;
        if (self.native_workers) |workers| workers.stop();
        self.condition.broadcast(self.io);
        self.mutex.unlock(self.io);
        self.thread.?.join();
        // The collector owns no custody state; finish its bounded local read
        // before releasing immutable selectors or the shared allocator.
        self.stopSetupRefresh();
        self.release();
        self.allocator.free(self.state_dir);
        self.allocator.destroy(self);
    }

    fn release(self: *Engine) void {
        self.state.deinit();
        if (self.codex_runtime_root) |root| self.allocator.free(root);
        if (self.installation_selection) |selected| {
            self.allocator.free(selected.prefix);
            self.allocator.free(selected.receipt_path);
            if (selected.service_path) |path| self.allocator.free(path);
            if (selected.runtime_dir) |path| self.allocator.free(path);
            if (selected.service_record_path) |path| self.allocator.free(path);
        }
        if (self.lifecycle_measurements) |measurements| self.allocator.destroy(measurements);
        if (self.browser_attempts) |*attempts| attempts.deinit();
        self.observers.deinit();
        for (self.installed.items) |item| self.allocator.free(item);
        self.installed.deinit(self.allocator);
        for (self.descriptions.items) |item| {
            self.allocator.free(item.source_id);
            self.allocator.free(item.provider);
            self.allocator.free(item.label);
            self.allocator.free(item.path);
        }
        self.descriptions.deinit(self.allocator);
        for (self.pending_imports.items) |*item| item.deinit(self.allocator);
        self.pending_imports.deinit(self.allocator);
        for (self.import_sources.items) |item| self.allocator.free(item.source_id);
        self.import_sources.deinit(self.allocator);
        for (self.native_leases.items) |*item| item.deinit(self.allocator);
        self.native_leases.deinit(self.allocator);
        self.requests.deinit();
        self.mutations.deinit();
        self.admission.deinit();
        self.native_owners.deinit();
        self.native_tasks.deinit(self.allocator);
        self.observation_credits.deinit(self.allocator);
        for (self.outcome_intents.items) |intent| freeIntent(self.allocator, intent);
        self.outcome_intents.deinit(self.allocator);
        self.staged_changes.deinit(self.allocator);
        if (self.root_id) |id| self.allocator.free(id);
        std.crypto.secureZero(u8, &self.root_key);
        if (self.test_key) |*key| std.crypto.secureZero(u8, key);
    }

    pub fn dispatch(self: *Engine, allocator: std.mem.Allocator, payload: []const u8, channel: Channel) ![]u8 {
        return self.dispatchUntil(allocator, payload, channel, .fromNow(self.io, .{ .clock = .awake, .raw = .fromMilliseconds(15_000) }));
    }

    pub fn dispatchUntil(self: *Engine, allocator: std.mem.Allocator, payload: []const u8, channel: Channel, until: std.Io.Clock.Timestamp) ![]u8 {
        return self.dispatchOwnedPeer(allocator, payload, channel, until, null);
    }

    pub fn dispatchWithPeer(self: *Engine, allocator: std.mem.Allocator, payload: []const u8, channel: Channel, context: *const peer.Context) ![]u8 {
        return self.dispatchUntilWithPeer(allocator, payload, channel, .fromNow(self.io, .{ .clock = .awake, .raw = .fromMilliseconds(15_000) }), context);
    }

    pub fn dispatchUntilWithPeer(self: *Engine, allocator: std.mem.Allocator, payload: []const u8, channel: Channel, until: std.Io.Clock.Timestamp, context: *const peer.Context) ![]u8 {
        return self.dispatchOwnedPeer(allocator, payload, channel, until, context);
    }

    fn dispatchOwnedPeer(self: *Engine, allocator: std.mem.Allocator, payload: []const u8, channel: Channel, until: std.Io.Clock.Timestamp, context: ?*const peer.Context) ![]u8 {
        const started = std.Io.Clock.awake.now(self.io);
        const operation = diagnosticOperation(allocator, payload, channel);
        var cause: reliability.Cause = .none;
        var outcome: reliability.Outcome = .good;
        defer {
            const elapsed_raw = started.durationTo(std.Io.Clock.awake.now(self.io)).toNanoseconds();
            const elapsed: u64 = @intCast(@min(@as(i96, std.math.maxInt(u64)), @max(0, elapsed_raw)));
            if (outcome == .good) outcome = reliability.classifyLatency(elapsed, 250_000_000);
            self.metrics_mutex.lockUncancelable(self.io);
            self.metrics.record(self.now(), .control_request, operation, outcome, cause, elapsed) catch {
                self.metrics_failure = true;
            };
            self.metrics_mutex.unlock(self.io);
        }
        if (until.durationFromNow(self.io).raw.toMilliseconds() <= 0) {
            outcome = .bad;
            cause = .timeout;
            return error.Timeout;
        }
        var invocation: Invocation = .{ .allocator = allocator, .payload = payload, .channel = channel, .until = until };
        if (context) |verified| invocation.peer_context = try verified.duplicate();
        defer if (invocation.peer_context) |*verified| verified.deinit();
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.stopping) {
            outcome = .excluded;
            cause = .operator_shutdown;
            return error.ServiceStopping;
        }
        if (self.queue_count == self.queue.len) {
            outcome = .bad;
            cause = .busy;
            return error.ServiceBusy;
        }
        self.queue[(self.queue_head + self.queue_count) % self.queue.len] = &invocation;
        self.queue_count += 1;
        self.condition.signal(self.io);
        // The actor owns this stack reference until completion. Cancellation
        // must not free the request while its transaction is still executing.
        while (!invocation.finished) invocation.condition.waitUncancelable(self.io, &self.mutex);
        if (invocation.failure) |err| {
            outcome = .bad;
            cause = diagnosticCause(err);
            return err;
        }
        const decoded = std.json.parseFromSlice(std.json.Value, allocator, invocation.response.?, .{}) catch null;
        if (decoded) |response| {
            defer response.deinit();
            if (control.get(response.value, "error")) |failure| {
                outcome = .bad;
                cause = diagnosticCauseName(control.string(failure, "message") catch "InvalidReply");
            }
        } else {
            outcome = .bad;
            cause = .protocol_mismatch;
        }
        return invocation.response.?;
    }

    fn actor(self: *Engine) void {
        self.initializeCustody() catch |err| {
            // Vault loading precedes database/network creation. Preserve a
            // bounded local control plane for an ordinary platform unlock;
            // never turn an unavailable wrapping key into fresh custody.
            if (err == error.Locked and self.db == null and self.network == null) {
                self.vault_locked = true;
                self.poisoned = true;
                std.crypto.secureZero(u8, &self.root_key);
                if (!self.lockedActor()) return;
                self.normalActor();
                return;
            }
            if (self.network) |client| client.deinit();
            if (self.db) |*db| db.close();
            self.mutex.lockUncancelable(self.io);
            self.startup_error = err;
            self.startup_complete = true;
            self.condition.broadcast(self.io);
            self.mutex.unlock(self.io);
            return;
        };
        self.normalActor();
    }

    fn normalActor(self: *Engine) void {
        defer {
            self.native_workers.?.deinit();
            self.network.?.deinit();
            self.db.?.close();
        }
        self.mutex.lockUncancelable(self.io);
        self.startup_complete = true;
        self.condition.broadcast(self.io);
        self.mutex.unlock(self.io);
        var maintenance_due = std.Io.Clock.Timestamp.fromNow(self.io, .{ .clock = .awake, .raw = .fromMilliseconds(100) });
        while (true) {
            self.completeSetupRefresh();
            if (self.runtime_measurement_requested and self.runtime_measurement == null and !self.stopping and !self.poisoned) {
                self.runtime_measurement_requested = false;
                self.startRuntimeMeasurement() catch |err| {
                    self.runtime_measurement_failure = err;
                };
            }
            self.mutex.lockUncancelable(self.io);
            while (self.queue_count == 0 and !self.native_workers.?.hasCompleted() and (!self.stopping or self.native_tasks.items.len != 0 or self.runtime_measurement != null) and maintenance_due.durationFromNow(self.io).raw.toNanoseconds() > 0) {
                self.condition.waitTimeout(self.io, &self.mutex, .{ .deadline = maintenance_due }) catch |err| switch (err) {
                    error.Timeout => {},
                    // Finish every queued stack reference before exiting. A
                    // cancelled wait cannot spin or start fresh maintenance.
                    error.Canceled => {
                        self.stopping = true;
                        self.native_workers.?.stop();
                    },
                };
            }
            if (self.native_workers.?.hasCompleted()) {
                self.mutex.unlock(self.io);
                self.completeNativeWork();
                continue;
            }
            if (self.queue_count == 0 and self.stopping and self.native_tasks.items.len == 0 and self.runtime_measurement == null) {
                self.mutex.unlock(self.io);
                return;
            }
            if (self.queue_count == 0 and self.stopping) {
                maintenance_due = .fromNow(self.io, .{ .clock = .awake, .raw = .fromMilliseconds(100) });
                self.mutex.unlock(self.io);
                continue;
            }
            if (!self.stopping and maintenance_due.durationFromNow(self.io).raw.toNanoseconds() <= 0) {
                self.mutex.unlock(self.io);
                // This awake-clock schedule is independent of dispatch and
                // queue emptiness. Continued inspection cannot starve already
                // issued identity reads or credential expiry maintenance.
                if (!self.poisoned) self.pollNetwork() catch {
                    self.fence();
                };
                if (!self.poisoned) self.expireLeases() catch {
                    self.fence();
                };
                if (!self.poisoned and !builtin.is_test) self.pollSources() catch {
                    self.fence();
                };
                maintenance_due = .fromNow(self.io, .{ .clock = .awake, .raw = .fromMilliseconds(100) });
                continue;
            }
            const item = self.queue[self.queue_head].?;
            self.queue[self.queue_head] = null;
            self.queue_head = (self.queue_head + 1) % self.queue.len;
            self.queue_count -= 1;
            self.mutex.unlock(self.io);
            // Dispatch never initiates maintenance. In particular, local
            // health and metadata inspection must not read authorized sources,
            // poll a provider, or change credential custody as a side effect.
            // Admission paths explicitly enforce their own freshness gates;
            // periodic work belongs to the actor's independent clock schedule.
            self.active_until = item.until;
            self.active_peer = if (item.peer_context) |*verified| verified else null;
            const deferred = if (!self.poisoned and !self.stopping and item.until.durationFromNow(self.io).raw.toMilliseconds() > 0) self.startNativeInvocation(item) catch |err| blk: {
                self.restoreCommitted() catch {
                    self.poisoned = true;
                };
                var parsed = control.parse(item.allocator, item.payload) catch {
                    self.finishInvocation(item, control.failure(item.allocator, .null, -32000, @errorName(err)));
                    break :blk true;
                };
                defer parsed.deinit();
                self.finishInvocation(item, control.failure(item.allocator, parsed.id, -32000, @errorName(err)));
                break :blk true;
            } else false;
            if (deferred) {
                self.active_peer = null;
                self.active_until = null;
                continue;
            }
            const response = if (self.stopping) error.ServiceStopping else if (item.until.durationFromNow(self.io).raw.toMilliseconds() <= 0) error.Timeout else self.execute(item.allocator, item.payload, item.channel);
            self.active_peer = null;
            self.active_until = null;
            self.finishInvocation(item, response);
        }
    }

    fn nativeWake(opaque_context: *anyopaque) void {
        const self: *Engine = @ptrCast(@alignCast(opaque_context));
        self.mutex.lockUncancelable(self.io);
        self.condition.broadcast(self.io);
        self.mutex.unlock(self.io);
    }
    fn lockedActor(self: *Engine) bool {
        self.mutex.lockUncancelable(self.io);
        self.startup_complete = true;
        self.condition.broadcast(self.io);
        while (true) {
            while (self.queue_count == 0 and !self.stopping) self.condition.waitUncancelable(self.io, &self.mutex);
            if (self.queue_count == 0 and self.stopping) {
                self.mutex.unlock(self.io);
                return false;
            }
            const item = self.queue[self.queue_head].?;
            self.queue[self.queue_head] = null;
            self.queue_head = (self.queue_head + 1) % self.queue.len;
            self.queue_count -= 1;
            const stopping = self.stopping;
            self.mutex.unlock(self.io);
            // No maintenance, source reads, provider work, native workers,
            // mutation ledger admission or database access exists here.
            self.active_until = item.until;
            const response = if (stopping) error.ServiceStopping else if (item.until.durationFromNow(self.io).raw.toMilliseconds() <= 0) error.Timeout else self.lockedRequest(item.allocator, item.payload, item.channel);
            self.active_until = null;
            self.finishInvocation(item, response);
            if (!self.vault_locked) return true;
            self.mutex.lockUncancelable(self.io);
        }
    }

    fn lockedRequest(self: *Engine, allocator: std.mem.Allocator, payload: []const u8, channel: Channel) ![]u8 {
        if (channel == .browser) return std.json.Stringify.valueAlloc(allocator, .{ .version = 1, .id = @as(?[]const u8, null), .@"error" = .{ .code = "VaultLocked", .message = "Unlock the platform vault, then explicitly reopen custody through local controls." } }, .{});
        var request = control.parse(allocator, payload) catch return control.failure(allocator, .null, -32600, "InvalidRequest");
        defer request.deinit();
        if (channel != .control) return control.failure(allocator, request.id, -32000, "VaultLocked");
        if (eql(request.method, "system.handshake")) return control.success(allocator, request.id, .{
            .protocol_version = control.protocol_version,
            .service = "omuxd",
            .channel = "control",
            .custody_available = false,
            .capabilities = .{ .credential_free_control = true, .custody_reopen = true, .native_launch = false, .live_handoff_proven = false },
        });
        if (eql(request.method, "custody.reopen")) {
            if (request.params != .null and (request.params != .object or request.params.object.count() != 0)) return control.failure(allocator, request.id, -32602, "InvalidParams");
            self.initializeCustody() catch |err| return control.failure(allocator, request.id, -32000, @errorName(err));
            self.vault_locked = false;
            self.poisoned = false;
            return control.success(allocator, request.id, .{ .reopened = true, .custody_available = true, .metadata_loaded = true, .account_count = self.state.accounts.items.len, .provider_request_initiated = false, .live_handoff_proven = false });
        }
        if (eql(request.method, "system.health")) return control.success(allocator, request.id, .{
            .protocol_version = control.protocol_version,
            .status = "vault_locked",
            .custody_available = false,
            .metadata_loaded = false,
            .account_count = @as(?usize, null),
            .provider_access = false,
            .live_handoff_proven = false,
            .recovery_action = "unlock_platform_vault_then_reopen_custody",
        });
        if (eql(request.method, "setup.readiness") or eql(request.method, "setup.evidence") or eql(request.method, "setup.plan")) return self.handleRequest(allocator, request, channel);
        return control.failure(allocator, request.id, -32000, "VaultLocked");
    }
    fn finishInvocation(self: *Engine, item: *Invocation, response: anyerror![]u8) void {
        self.mutex.lockUncancelable(self.io);
        if (response) |value| item.response = value else |err| item.failure = err;
        item.finished = true;
        item.condition.signal(self.io);
        self.mutex.unlock(self.io);
    }

    fn startNativeInvocation(self: *Engine, invocation: *Invocation) !bool {
        if (invocation.channel == .browser) return false;
        var request = try control.parse(self.allocator, invocation.payload);
        var transferred = false;
        defer if (!transferred) request.deinit();
        const registration = eql(request.method, "adapter.owner.register");
        const announcement = eql(request.method, "integrations.attach");
        const detachment = eql(request.method, "integrations.detach");
        const discovering = eql(request.method, "integrations.discover");
        const removal = eql(request.method, "integrations.remove") and eql((try control.optionalString(request.params, "adapter")) orelse "codex", "codex");
        if (!registration and !announcement and !detachment and !removal and !discovering) return false;
        if (registration) {
            if (invocation.channel != .adapter or !eql(try self.authenticate(request.params), "codex")) return error.WrongPurpose;
            const context = self.active_peer orelse return error.NativePeerRequired;
            try context.alive();
        } else {
            if (invocation.channel != .control) return error.WrongChannel;
            if (!eql((try control.optionalString(request.params, "adapter")) orelse "codex", "codex")) return error.NativeHookRequired;
        }
        const operation: native_owner.OperationId = if (discovering) try self.identifier() else blk: {
            const operation_text = try control.operationId(request.params);
            if (operation_text.len != 64) return error.InvalidNativeOperation;
            break :blk operation_text[0..64].*;
        };
        try native_owner.validateOperation(operation);
        if (!registration and !discovering and try self.cachedNativeControl(invocation, request, operation)) return true;
        if (!registration and !discovering and !self.integrationInstalled("codex")) return error.AdapterNotInstalled;
        var paired_callback = false;
        var callback_slots: usize = 0;
        for (self.native_tasks.items) |parent| {
            if (parent.stage != .announcement_identify and parent.stage != .announcement) continue;
            var callback_present = false;
            for (self.native_tasks.items) |child| if (child != parent and std.mem.eql(u8, &child.operation, &parent.operation)) {
                callback_present = true;
            };
            if (!callback_present) callback_slots += 1;
            if (registration and parent.stage == .announcement and std.mem.eql(u8, &parent.operation, &operation)) paired_callback = true;
        }
        const extra = if (announcement) @as(usize, 2) else if (paired_callback) @as(usize, 0) else @as(usize, 1);
        const internal_id = nativeRegistrationMutationId(operation);
        const existing_registration = if (registration) try self.mutations.lookup(&internal_id) else null;
        const cached_registration = existing_registration != null and existing_registration.?.state == .completed;
        if (!cached_registration and (self.native_tasks.items.len >= native_work.capacity or self.native_tasks.items.len + callback_slots + extra > native_work.capacity)) return error.NativeWorkCapacity;
        for (self.native_tasks.items) |task| if (std.mem.eql(u8, &task.operation, &operation) and !(registration and task.stage == .announcement and task.reference != null)) return error.OperationIndeterminate;
        if (removal) return self.startNativeRemoval(invocation, &request, &transferred, operation);
        const endpoint: []const u8 = if (registration) try control.string(request.params, "owner_endpoint") else if (try control.optionalString(request.params, "owner_endpoint")) |value| value else (try control.optionalString(request.params, "native_socket")) orelse if (discovering) "" else return error.NativeEndpointRequired;
        if (endpoint.len != 0) try paths.validateAbsolute(endpoint);
        if (endpoint.len > 107) return error.SocketPathTooLong;
        const thread_id = if (discovering) "discovery" else try control.string(request.params, "thread_id");
        if (thread_id.len > native_owner.maximum_thread_bytes) return error.InvalidNativeOwnerThread;
        const task = try self.newNativeTask(invocation, request, operation, endpoint, thread_id, if (discovering) .discovery else if (registration) .identify else if (announcement) .announcement_identify else .detachment);
        transferred = true;
        errdefer task.deinit();
        if (announcement or detachment) {
            const selected = control.get(request.params, "owner_id") != null or control.get(request.params, "process_nonce") != null or control.get(request.params, "endpoint_generation") != null or control.get(request.params, "thread_instance_generation") != null;
            if (selected) {
                task.claimed_owner = try parseOpaqueId(try control.string(request.params, "owner_id"));
                task.nonce = try parseOpaqueId(try control.string(request.params, "process_nonce"));
                task.endpoint_generation = try parseGeneration(control.get(request.params, "endpoint_generation") orelse return error.InvalidParams);
                task.thread_generation = try parseGeneration(control.get(request.params, "thread_instance_generation") orelse return error.InvalidParams);
                task.selected_owner = true;
            }
        }
        if (registration) {
            task.expected = self.active_peer.?.witness();
            task.claimed_owner = try parseOpaqueId(try control.string(request.params, "owner_id"));
            task.nonce = try parseOpaqueId(try control.string(request.params, "process_nonce"));
            task.endpoint_generation = try parseGeneration(control.get(request.params, "endpoint_generation") orelse return error.InvalidParams);
            task.thread_generation = try parseGeneration(control.get(request.params, "thread_instance_generation") orelse return error.InvalidParams);
            if (self.native_owners.applicationRemoval("codex", self.adapter_epochs[0]) != null) return error.NativeRemovalPending;
            if (try self.registrationReplay(task)) return true;
        } else if (!discovering) {
            if (announcement) {
                if (self.native_owners.applicationRemoval("codex", self.adapter_epochs[0]) != null) return error.NativeRemovalPending;
                if (!task.selected_owner and try self.admitNativeControl(task)) return true;
            } else {
                task.reference = try parseNativeRef(request.params);
                if (try self.prepareNativeDetach(task)) return true;
            }
        }
        try self.native_tasks.ensureUnusedCapacity(self.allocator, 1);
        try self.native_workers.?.enqueue(&task.job);
        self.native_tasks.appendAssumeCapacity(task);
        return true;
    }

    fn cachedNativeControl(self: *Engine, invocation: *Invocation, request: control.Request, operation: native_owner.OperationId) !bool {
        const record = (try self.mutations.lookup(&operation)) orelse return false;
        const fingerprint = try mutationFingerprint(self.allocator, request.method, request.params, self.root_key);
        if (record.kind != .external or !eql(record.method[0..record.method_len], request.method) or record.expected_revision != try control.expectedRevision(request.params) or !std.mem.eql(u8, &record.fingerprint, &fingerprint)) return error.OperationIdConflict;
        if (record.state != .completed) return error.OperationIndeterminate;
        const decoded = try std.json.parseFromSlice(std.json.Value, self.allocator, record.result, .{});
        defer decoded.deinit();
        self.finishInvocation(invocation, control.success(invocation.allocator, request.id, decoded.value));
        return true;
    }

    fn newNativeTask(self: *Engine, invocation: *Invocation, request: control.Request, operation: native_owner.OperationId, endpoint: []const u8, thread_id: []const u8, stage: @FieldType(NativeTask, "stage")) !*NativeTask {
        const task = try self.allocator.create(NativeTask);
        errdefer self.allocator.destroy(task);
        const owned_endpoint = try self.allocator.dupe(u8, endpoint);
        errdefer self.allocator.free(owned_endpoint);
        const owned_thread = try self.allocator.dupe(u8, thread_id);
        errdefer self.allocator.free(owned_thread);
        var arena: std.heap.ArenaAllocator = .init(self.allocator);
        defer arena.deinit();
        const options = try self.setupOptions(arena.allocator(), .codex, request.params);
        const broker_socket = try self.allocator.dupe(u8, options.broker_socket);
        errdefer self.allocator.free(broker_socket);
        const capability_path = try std.fmt.allocPrint(self.allocator, "{s}/integrations/codex.capability", .{self.state_dir});
        errdefer self.allocator.free(capability_path);
        task.* = .{ .engine = self, .invocation = invocation, .request = request, .operation = operation, .endpoint = owned_endpoint, .thread_id = owned_thread, .broker_socket = broker_socket, .capability_path = capability_path, .stage = stage, .job = .{ .lane = if (stage == .announcement) .announcement else .continuation, .context = task, .run = NativeTask.run } };
        if (stage == .discovery or stage == .announcement_identify) {
            const context = try self.allocator.create(std.heap.ArenaAllocator);
            errdefer self.allocator.destroy(context);
            context.* = .init(self.allocator);
            errdefer context.deinit();
            const owned = context.allocator();
            var captured = options;
            captured.home = try owned.dupe(u8, options.home);
            captured.codex_home = if (options.codex_home) |value| try owned.dupe(u8, value) else null;
            captured.config_path = if (options.config_path) |value| try owned.dupe(u8, value) else null;
            captured.xdg_config_home = if (options.xdg_config_home) |value| try owned.dupe(u8, value) else null;
            captured.broker_socket = broker_socket;
            task.discovery_context = context;
            task.discovery_options = captured;
            task.selected_registry = self.native_registry;
        }
        return task;
    }

    fn registrationReplay(self: *Engine, task: *NativeTask) !bool {
        const mutation_id = nativeRegistrationMutationId(task.operation);
        const record = (try self.mutations.lookup(&mutation_id)) orelse return false;
        var original_found = false;
        for (self.native_owners.attachments.items) |row| if (std.mem.eql(u8, &row.registration_operation, &task.operation)) {
            const owner = self.native_owners.lookupOwnerForRef(row.reference) orelse return error.UnknownNativeOwner;
            if (!peer.sameOriginal(owner.witness, task.expected.?) or !std.mem.eql(u8, &owner.id, &task.claimed_owner) or !std.mem.eql(u8, &owner.native_nonce, &task.nonce) or !eql(owner.endpoint_path, task.endpoint) or !eql(row.thread_id, task.thread_id) or row.reference.endpoint_generation != task.endpoint_generation or row.reference.thread_instance_generation != task.thread_generation) return error.NativeOwnerMismatch;
            original_found = true;
        };
        if (!original_found) return error.InvalidNativeCreditAuthority;
        const fingerprint = try mutationFingerprint(self.allocator, task.request.method, task.request.params, self.root_key);
        if (!eql(record.method[0..record.method_len], task.request.method) or !std.mem.eql(u8, &record.fingerprint, &fingerprint)) return error.OperationIdConflict;
        if (record.state != .completed) {
            // Only the original live, pre-admitted announce can accept its
            // genuine producer callback. Restored phase is never a waiter.
            if (record.state == .started) for (self.native_tasks.items) |parent| {
                if (parent.stage != .announcement or !std.mem.eql(u8, &parent.operation, &task.operation)) continue;
                const reference = parent.reference orelse continue;
                const owner = self.native_owners.lookupOwnerForRef(reference) orelse return error.UnknownNativeOwner;
                const row = self.native_owners.lookupAttachment(reference) orelse return error.UnknownNativeAttachment;
                if (row.phase != .pending_registration or !peer.sameOriginal(owner.witness, task.expected.?) or !std.mem.eql(u8, &owner.id, &task.claimed_owner) or !std.mem.eql(u8, &owner.native_nonce, &task.nonce) or !eql(owner.endpoint_path, task.endpoint) or !eql(row.thread_id, task.thread_id) or reference.endpoint_generation != task.endpoint_generation or reference.thread_instance_generation != task.thread_generation) return error.NativeOwnerMismatch;
                task.reference = reference;
                return false;
            };
            return error.OperationIndeterminate;
        }
        var reference: ?native_owner.NativeRef = null;
        for (self.native_owners.attachments.items) |row| if (std.mem.eql(u8, &row.registration_operation, &task.operation)) {
            const owner = self.native_owners.lookupOwnerForRef(row.reference) orelse return error.UnknownNativeOwner;
            if (row.phase != .attached or owner.phase != .open or row.reference.adapter_epoch != self.adapter_epochs[0]) return error.OperationIndeterminate;
            if (!peer.sameOriginal(owner.witness, task.expected.?) or !std.mem.eql(u8, &owner.id, &task.claimed_owner) or !std.mem.eql(u8, &owner.native_nonce, &task.nonce) or !eql(owner.endpoint_path, task.endpoint) or !eql(row.thread_id, task.thread_id) or row.reference.endpoint_generation != task.endpoint_generation or row.reference.thread_instance_generation != task.thread_generation) return error.NativeOwnerMismatch;
            reference = row.reference;
        };
        if (reference == null) return error.InvalidNativeCreditAuthority;
        const decoded = try std.json.parseFromSlice(std.json.Value, self.allocator, record.result, .{});
        defer decoded.deinit();
        self.finishInvocation(task.invocation, control.success(task.invocation.allocator, task.request.id, decoded.value));
        task.deinit();
        return true;
    }

    fn prepareNativeRegistration(self: *Engine, task: *NativeTask) !void {
        const identity = task.identity orelse return error.InvalidNativeOwnerAck;
        const announcing = task.stage == .announcement_identify;
        if (!announcing) {
            const original_context = if (task.invocation.peer_context) |*context| context else return error.NativePeerRequired;
            try original_context.alive();
            if (!peer.sameOriginal(original_context.witness(), identity.witness) or !peer.sameOriginal(task.expected.?, identity.witness) or !std.mem.eql(u8, &identity.owner_id, &task.claimed_owner) or !std.mem.eql(u8, &identity.native_nonce, &task.nonce) or identity.endpoint_generation != task.endpoint_generation or identity.thread_instance_generation != task.thread_generation or !eql(identity.thread_id, task.thread_id)) return error.NativeOwnerMismatch;
        } else {
            if (task.selected_owner and (!std.mem.eql(u8, &identity.owner_id, &task.claimed_owner) or !std.mem.eql(u8, &identity.native_nonce, &task.nonce) or identity.endpoint_generation != task.endpoint_generation or identity.thread_instance_generation != task.thread_generation or !eql(identity.thread_id, task.thread_id))) return error.NativeOwnerMismatch;
            task.expected = identity.witness;
            task.claimed_owner = identity.owner_id;
            task.nonce = identity.native_nonce;
            task.endpoint_generation = identity.endpoint_generation;
            task.thread_generation = identity.thread_instance_generation;
        }
        const epoch = self.adapter_epochs[0];
        if (self.native_owners.applicationRemoval("codex", epoch) != null) return error.NativeRemovalPending;
        if (!announcing and task.reference != null) {
            const reference = task.reference.?;
            const row = self.native_owners.lookupAttachment(reference) orelse return error.UnknownNativeAttachment;
            if (row.phase != .pending_registration or reference.adapter_epoch != epoch) return error.NativeRemovalPending;
            const internal_id = nativeRegistrationMutationId(task.operation);
            for (self.mutations.snapshot().records, 0..) |record, index| if (eql(record.id[0..record.id_len], &internal_id) and record.state == .started) {
                task.mutation_slot = index;
            };
            if (task.mutation_slot == null) return error.OperationIndeterminate;
            task.credit = creditKey(.native_registration, &task.operation, epoch);
            if (self.admission.lookup(task.credit.?) == null) return error.InvalidNativeCreditAuthority;
            task.admitted = true;
            task.stage = .registration;
            try self.native_workers.?.enqueue(&task.job);
            return;
        }
        if (self.native_owners.lookupOwnerQualified(identity.owner_id, epoch, identity.endpoint_generation)) |owner| {
            if (owner.phase != .open or owner.adapter_epoch != epoch or owner.endpoint_generation != identity.endpoint_generation or !peer.sameOriginal(owner.witness, identity.witness) or !std.mem.eql(u8, &owner.native_nonce, &identity.native_nonce) or !eql(owner.endpoint_path, task.endpoint)) return error.NativeOwnerMismatch;
        } else try self.native_owners.admitOwner(.{ .id = identity.owner_id, .application = "codex", .adapter_epoch = epoch, .endpoint_generation = identity.endpoint_generation, .witness = identity.witness, .native_nonce = identity.native_nonce, .endpoint_path = task.endpoint });
        var generation: u64 = 1;
        for (self.native_owners.attachments.items) |row| if (std.mem.eql(u8, &row.reference.owner_id, &identity.owner_id) and row.reference.adapter_epoch == epoch and row.reference.endpoint_generation == identity.endpoint_generation and row.reference.thread_instance_generation == identity.thread_instance_generation) {
            generation = @max(generation, try std.math.add(u64, row.reference.attachment_generation, 1));
        };
        const reference: native_owner.NativeRef = .{ .owner_id = identity.owner_id, .adapter_epoch = epoch, .endpoint_generation = identity.endpoint_generation, .thread_instance_generation = identity.thread_instance_generation, .attachment_generation = generation };
        task.reference = reference;
        var arena: std.heap.ArenaAllocator = .init(self.allocator);
        defer arena.deinit();
        const result = try nativeRegistrationResult(arena.allocator(), task.operation, reference);
        try setup.requireResultFits(arena.allocator(), result);
        const fingerprint = if (announcing) try self.announcedRegistrationFingerprint(task, arena.allocator()) else try mutationFingerprint(self.allocator, task.request.method, task.request.params, self.root_key);
        const mutation_id = nativeRegistrationMutationId(task.operation);
        const slot = switch (try self.mutations.begin(&mutation_id, "adapter.owner.register", fingerprint, self.revision, self.revision, .external)) {
            .execute => |index| index,
            .replay, .indeterminate => return error.OperationIndeterminate,
        };
        if (!announcing) task.mutation_slot = slot;
        try self.native_owners.admitAttachment(.{ .reference = reference, .thread_id = task.thread_id, .registration_operation = task.operation });
        const key = creditKey(.native_registration, &task.operation, epoch);
        // Native row/phase growth is permanently prepaid by its structural
        // ledger, and cached ACK bytes by mutation authority. The positive
        // one-byte obligation has no additional non-ledger output or slots.
        try self.reserveOutcome(.{ .key = key, .owner_id = &task.operation, .provider = "adapter.owner.register", .plan_bytes = 1, .native_ref = reference });
        if (!announcing) task.credit = key;
        try self.persist(&.{});
        task.admitted = true;
        task.stage = if (announcing) .announcement else .registration;
        task.job.lane = if (announcing) .announcement else .continuation;
        try self.native_workers.?.enqueue(&task.job);
    }

    fn announcedRegistrationFingerprint(self: *Engine, task: *NativeTask, allocator: std.mem.Allocator) ![32]u8 {
        var native_capability = try self.capability("codex");
        defer std.crypto.secureZero(u8, &native_capability);
        const owner_hex = std.fmt.bytesToHex(task.claimed_owner, .lower);
        const nonce_hex = std.fmt.bytesToHex(task.nonce, .lower);
        const encoded = try std.json.Stringify.valueAlloc(allocator, .{
            .application = "codex",
            .capability = native_capability[0..],
            .operation_id = task.operation[0..],
            .owner_id = owner_hex[0..],
            .process_nonce = nonce_hex[0..],
            .owner_endpoint = task.endpoint,
            .thread_id = task.thread_id,
            .endpoint_generation = try std.fmt.allocPrint(allocator, "{d}", .{task.endpoint_generation}),
            .thread_instance_generation = try std.fmt.allocPrint(allocator, "{d}", .{task.thread_generation}),
        }, .{});
        defer std.crypto.secureZero(u8, encoded);
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, encoded, .{ .allocate = .alloc_always });
        defer {
            control.wipeJson(parsed.value);
            parsed.deinit();
        }
        return mutationFingerprint(allocator, "adapter.owner.register", parsed.value, self.root_key);
    }

    fn completeNativeWork(self: *Engine) void {
        const job = self.native_workers.?.takeCompleted() orelse return;
        if (self.runtime_measurement) |measurement| if (job == &measurement.job) {
            self.completeRuntimeMeasurement(measurement);
            return;
        };
        const task: *NativeTask = @ptrCast(@alignCast(job.context));
        self.active_until = task.invocation.until;
        self.active_peer = if (task.invocation.peer_context) |*context| context else null;
        defer {
            self.active_until = null;
            self.active_peer = null;
            self.active_credit = null;
        }
        if (task.failure == null and (task.stage == .identify or task.stage == .announcement_identify) and !self.stopping and !self.poisoned) {
            if (task.stage == .announcement_identify and task.selected_owner and !task.admitted) {
                // The worker already verified the selected context and fresh
                // exact identity. A removal fence may have appeared meanwhile.
                const options = task.discovery_options.?;
                const deadline = task.discovery_until.?;
                if (deadline.durationFromNow(self.io).raw.toMilliseconds() <= 0) {
                    task.failure = error.NativeTimeout;
                } else if (options.native_custody.?.adapter_epoch != self.adapter_epochs[0] or !std.meta.eql(task.selected_registry, self.native_registry)) {
                    task.failure = error.NativeCustodyGenerationMismatch;
                } else if (self.native_owners.applicationRemoval("codex", self.adapter_epochs[0]) != null) {
                    task.failure = error.NativeRemovalPending;
                } else {
                    const replayed = self.admitNativeControl(task) catch |err| blk: {
                        task.failure = err;
                        break :blk false;
                    };
                    if (replayed) {
                        for (self.native_tasks.items, 0..) |candidate, index| if (candidate == task) {
                            _ = self.native_tasks.orderedRemove(index);
                            break;
                        };
                        return;
                    }
                }
            }
            if (task.failure == null) {
                self.prepareNativeRegistration(task) catch |err| {
                    task.failure = err;
                };
                if (task.failure == null) return;
            }
        } else if (task.failure == null and (self.stopping or self.poisoned)) task.failure = error.ServiceStopping;
        const response = if (task.failure) |err| self.failNativeTask(task, err) else blk: {
            const reply = self.finishNativeTask(task) catch |err| {
                if (err == error.NativeContinuationPending) return;
                break :blk self.failNativeTask(task, err);
            };
            break :blk reply;
        };
        self.finishInvocation(task.invocation, response);
        for (self.native_tasks.items, 0..) |candidate, index| if (candidate == task) {
            _ = self.native_tasks.orderedRemove(index);
            break;
        };
        task.deinit();
    }

    fn failNativeTask(self: *Engine, task: *NativeTask, failure: anyerror) ![]u8 {
        if (task.stage == .discovery) return control.failure(task.invocation.allocator, task.request.id, -32000, @errorName(failure));
        errdefer self.poisoned = true;
        try self.restoreCommitted();
        if (task.admitted) {
            var unresolved = true;
            if (task.mutation_slot) |slot| {
                const state = self.mutations.snapshot().records[slot].state;
                unresolved = state != .completed;
                if (state == .started) try self.mutations.markIndeterminate(slot);
            }
            if (unresolved) {
                if (task.reference) |reference| if (self.native_owners.lookupAttachment(reference) != null) try self.native_owners.markUnresolved(reference);
                if (task.credit) |key| if (self.admission.lookup(key) != null) try self.admission.markIndeterminate(key);
                try self.persist(&.{});
            }
        }
        return control.failure(task.invocation.allocator, task.request.id, -32000, @errorName(failure));
    }

    fn finishNativeTask(self: *Engine, task: *NativeTask) ![]u8 {
        if (task.stage == .discovery) {
            var arena: std.heap.ArenaAllocator = .init(self.allocator);
            defer arena.deinit();
            const result = try nativeDiscoveryResult(arena.allocator(), task, self, self.integrationInstalled("codex"));
            try requireNativeDiscoveryFits(task.request.id, result);
            const response = try control.success(task.invocation.allocator, task.request.id, result);
            errdefer task.invocation.allocator.free(response);
            const deadline = task.discovery_until orelse return error.InvalidDeadline;
            if (deadline.durationFromNow(self.io).raw.toMilliseconds() <= 0) return error.NativeTimeout;
            return response;
        }
        const ack = task.acknowledgement orelse return error.InvalidNativeOwnerAck;
        const reference = task.reference orelse ack.reference;
        const owner = self.native_owners.lookupOwnerForRef(reference) orelse return error.UnknownNativeOwner;
        const row = self.native_owners.lookupAttachment(reference) orelse return error.UnknownNativeAttachment;
        const native_operation = task.native_operation orelse task.operation;
        if (!reference.same(ack.reference) or !peer.sameOriginal(owner.witness, ack.witness) or !std.mem.eql(u8, &owner.native_nonce, &ack.native_nonce) or !std.mem.eql(u8, &native_operation, &ack.operation_id) or !eql(row.thread_id, ack.thread_id)) return error.NativeOwnerMismatch;
        if (task.stage == .registration) {
            if (ack.action != .register or row.phase != .pending_registration or !std.mem.eql(u8, &row.registration_operation, &task.operation)) return error.InvalidNativeTransition;
            const original_context = if (task.invocation.peer_context) |*context| context else return error.NativePeerRequired;
            try original_context.alive();
            if (!peer.sameOriginal(original_context.witness(), owner.witness)) return error.NativeOwnerMismatch;
            try self.native_owners.completeRegistration(reference, task.operation);
        } else if (task.stage == .announcement) {
            if (ack.action != .announce or row.phase != .attached or !std.mem.eql(u8, &row.registration_operation, &task.operation)) return error.InvalidNativeTransition;
        } else if (task.stage == .detachment) {
            if (ack.action != .detach) return error.InvalidNativeTransition;
            try self.native_owners.completeDetach(reference, native_operation);
            try self.releaseBindingsForNativeRef(reference);
            if (task.credit) |key| {
                try self.releaseOutcome(key);
                task.credit = null;
            }
            try self.persist(&.{});
            if (task.removing) return self.advanceNativeRemoval(task);
        } else return error.InvalidNativeTransition;
        var arena: std.heap.ArenaAllocator = .init(self.allocator);
        defer arena.deinit();
        const cached = if (task.stage == .detachment) try std.json.Stringify.valueAlloc(arena.allocator(), try nativeDetachResult(arena.allocator(), task.operation, reference), .{}) else try std.json.Stringify.valueAlloc(arena.allocator(), try nativeRegistrationResult(arena.allocator(), task.operation, reference), .{});
        try self.mutations.complete(task.mutation_slot.?, cached);
        if (task.credit) |key| try self.releaseOutcome(key);
        if (task.stage == .detachment) {
            const record = self.mutations.snapshot().records[task.mutation_slot.?];
            try self.releaseOutcome(creditKey(.mutation, &task.operation, record.expected_revision));
        }
        try self.persist(&.{});
        const decoded = try std.json.parseFromSlice(std.json.Value, arena.allocator(), cached, .{});
        defer decoded.deinit();
        return control.success(task.invocation.allocator, task.request.id, decoded.value);
    }

    fn admitNativeControl(self: *Engine, task: *NativeTask) !bool {
        const expected_revision = try control.expectedRevision(task.request.params);
        const fingerprint = try mutationFingerprint(self.allocator, task.request.method, task.request.params, self.root_key);
        switch (try self.mutations.begin(&task.operation, task.request.method, fingerprint, expected_revision, self.revision, .external)) {
            .replay => |bytes| {
                const decoded = try std.json.parseFromSlice(std.json.Value, self.allocator, bytes, .{});
                defer decoded.deinit();
                self.finishInvocation(task.invocation, control.success(task.invocation.allocator, task.request.id, decoded.value));
                task.deinit();
                return true;
            },
            .indeterminate => return error.OperationIndeterminate,
            .execute => |slot| task.mutation_slot = slot,
        }
        const plan = try self.mutationOutcomePlan(self.allocator, task.request.method, task.request.params);
        const key = creditKey(.mutation, &task.operation, expected_revision);
        try self.reserveOutcome(.{ .key = key, .owner_id = &task.operation, .provider = task.request.method, .plan_bytes = plan.bytes, .plan_counts = plan.slots });
        task.credit = key;
        if (task.removing and try self.mutations.tryReserveNativeRemovalWitness(task.mutation_slot.?)) {
            task.removal_measurement = try native_removal_witness.Session.begin(self.io, self.mutations.snapshot().records[task.mutation_slot.?], .{});
            try self.checkNativeRemovalMeasurementCapacity(task);
        }
        try self.persist(&.{});
        task.admitted = true;
        return false;
    }

    fn nativeRequestsPending(self: *Engine, reference: ?native_owner.NativeRef) bool {
        for (self.requests.snapshot().records) |record| {
            const ref = record.intent.native_ref orelse continue;
            if (reference) |wanted| if (!ref.same(wanted)) continue;
            if (reference == null and ref.adapter_epoch != self.adapter_epochs[0]) continue;
            if (unresolvedAttempt(record.first)) return true;
            if (record.alternate) |attempt| if (unresolvedAttempt(attempt)) return true;
        }
        for (self.state.leases.items) |lease| if (lease.native_ref) |ref| {
            if (reference) |wanted| if (!ref.same(wanted)) continue;
            if (reference == null and ref.adapter_epoch != self.adapter_epochs[0]) continue;
            return true;
        };
        return false;
    }

    fn prepareNativeDetach(self: *Engine, task: *NativeTask) !bool {
        const reference = task.reference.?;
        const owner = self.native_owners.lookupOwnerForRef(reference) orelse return error.UnknownNativeOwner;
        const row = self.native_owners.lookupAttachment(reference) orelse return error.UnknownNativeAttachment;
        if (!eql(owner.application, "codex") or owner.adapter_epoch != self.adapter_epochs[0] or !eql(row.thread_id, task.thread_id) or !eql(owner.endpoint_path, task.endpoint)) return error.NativeOwnerMismatch;
        if (task.selected_owner and (!std.mem.eql(u8, &owner.id, &task.claimed_owner) or !std.mem.eql(u8, &owner.native_nonce, &task.nonce) or reference.endpoint_generation != task.endpoint_generation or reference.thread_instance_generation != task.thread_generation)) return error.NativeOwnerMismatch;
        if (self.nativeRequestsPending(reference)) return error.NativeRequestsPending;
        var result_arena: std.heap.ArenaAllocator = .init(self.allocator);
        defer result_arena.deinit();
        try setup.requireResultFits(result_arena.allocator(), try nativeDetachResult(result_arena.allocator(), task.operation, reference));
        task.expected = owner.witness;
        task.nonce = owner.native_nonce;
        if (!task.removing and try self.admitNativeControl(task)) return true;
        const operation = task.native_operation orelse task.operation;
        try self.native_owners.beginDetach(reference, operation);
        const key = creditKey(.native_detach, &operation, reference.attachment_generation);
        try self.reserveOutcome(.{ .key = key, .owner_id = &operation, .secondary_id = &task.operation, .provider = task.request.method, .plan_bytes = 1, .native_ref = reference });
        if (task.removing) try self.checkNativeRemovalMeasurementCapacity(task);
        // Control intent remains independently owned until its final result;
        // each exact detach has its own credit and stable operation witness.
        task.credit = key;
        try self.persist(&.{});
        task.admitted = true;
        return false;
    }

    fn releaseBindingsForNativeRef(self: *Engine, reference: native_owner.NativeRef) !void {
        if (self.nativeRequestsPending(reference)) return error.NativeRequestsPending;
        var index: usize = 0;
        while (index < self.state.bindings.items.len) {
            const binding = self.state.bindings.items[index];
            if (binding.native_ref) |ref| if (ref.same(reference)) {
                try self.state.releaseBindingExact(binding.id, reference);
                continue;
            };
            index += 1;
        }
    }

    fn startNativeRemoval(self: *Engine, invocation: *Invocation, request: *control.Request, transferred: *bool, operation: native_owner.OperationId) !bool {
        var arena: std.heap.ArenaAllocator = .init(self.allocator);
        defer arena.deinit();
        const options = try self.setupOptions(arena.allocator(), .codex, request.params);
        try setup.preflightResult(self.io, arena.allocator(), options, .remove);
        const witness = try setup.registryWitness(self.io, arena.allocator(), options) orelse return error.NotInstalled;
        const retained = self.native_registry orelse return error.NativeCustodyPending;
        if (!sameRegistryWitness(retained, witness)) return error.NativeCustodyGenerationMismatch;
        if (self.measured_codex_runtime) |selected| {
            if (!selected.ownedBy(retained, self.adapter_epochs[0])) return error.RuntimeSelectionDrift;
        }
        // Endpoint/thread arguments are filled from original sealed attribution,
        // never the endpoint selected by the control caller.
        const task = try self.newNativeTask(invocation, request.*, operation, self.state_dir, "removal", .detachment);
        transferred.* = true;
        errdefer task.deinit();
        try self.native_tasks.ensureUnusedCapacity(self.allocator, 1);
        task.removing = true;
        task.registry = retained;
        if (try self.admitNativeControl(task)) return true;
        const epoch = self.adapter_epochs[0];
        if (self.native_owners.applicationRemoval("codex", epoch)) |removal| task.removal_operation = removal.operation else {
            try self.native_owners.beginApplicationRemoval("codex", epoch, operation);
            task.removal_operation = operation;
        }
        try self.checkNativeRemovalMeasurementCapacity(task);
        try self.persist(&.{});
        if (self.nativeRequestsPending(null)) {
            self.finishInvocation(invocation, self.completeNativeRemovalPending(task, "NativeRequestsPending"));
            task.deinit();
            return true;
        }
        if (try self.scheduleNextNativeRemoval(task)) {
            self.native_tasks.appendAssumeCapacity(task);
        } else {
            const response = self.finishNativeRemoval(task) catch |err| self.failNativeTask(task, err);
            self.finishInvocation(invocation, response);
            task.deinit();
        }
        return true;
    }

    fn scheduleNextNativeRemoval(self: *Engine, task: *NativeTask) !bool {
        const epoch = self.adapter_epochs[0];
        for (self.native_owners.attachments.items) |row| {
            if (row.reference.adapter_epoch != epoch or row.phase == .retired) continue;
            const owner = self.native_owners.lookupOwnerForRef(row.reference) orelse return error.UnknownNativeOwner;
            if (!eql(owner.application, "codex")) continue;
            if (row.phase != .attached and !(row.phase == .unresolved and row.unresolved_from == .attachment)) continue;
            if (row.detach_operation != null or self.nativeRequestsPending(row.reference)) continue;
            const next_endpoint = try self.allocator.dupe(u8, owner.endpoint_path);
            const next_thread = self.allocator.dupe(u8, row.thread_id) catch |err| {
                self.allocator.free(next_endpoint);
                return err;
            };
            self.allocator.free(task.endpoint);
            self.allocator.free(task.thread_id);
            task.endpoint = next_endpoint;
            task.thread_id = next_thread;
            if (task.connection) |*connection| connection.deinit();
            task.connection = null;
            if (task.acknowledgement) |*ack| ack.deinit(self.allocator);
            task.acknowledgement = null;
            task.reference = row.reference;
            task.native_operation = nativeDetachOperation(task.removal_operation.?, row.reference);
            _ = try self.prepareNativeDetach(task);
            try self.native_workers.?.enqueue(&task.job);
            return true;
        }
        return false;
    }

    fn advanceNativeRemoval(self: *Engine, task: *NativeTask) ![]u8 {
        // The caller of finishNativeTask handles the deferred sentinel before
        // completing the waiter. No native effect is issued on the actor.
        if (try self.scheduleNextNativeRemoval(task)) return error.NativeContinuationPending;
        return self.finishNativeRemoval(task);
    }

    fn completeNativeRemovalPending(self: *Engine, task: *NativeTask, reason: []const u8) ![]u8 {
        const result = .{ .removed = false, .adapter = "codex", .installed = true, .pending_safe_detach = true, .reason = reason };
        const cached = try std.json.Stringify.valueAlloc(self.allocator, result, .{});
        defer self.allocator.free(cached);
        try self.mutations.complete(task.mutation_slot.?, cached);
        const record = self.mutations.snapshot().records[task.mutation_slot.?];
        try self.releaseOutcome(creditKey(.mutation, &task.operation, record.expected_revision));
        try self.persist(&.{});
        self.captureNativeRemovalMeasurement(task);
        return control.success(task.invocation.allocator, task.request.id, result);
    }

    fn finishNativeRemoval(self: *Engine, task: *NativeTask) ![]u8 {
        const original_registry = task.registry orelse return error.NativeCustodyPending;
        if (self.native_registry == null or !sameRegistryWitness(original_registry, self.native_registry.?)) return error.NativeCustodyGenerationMismatch;
        for (self.native_owners.owners.items) |owner| {
            if (!eql(owner.application, "codex") or owner.adapter_epoch != self.adapter_epochs[0] or owner.phase == .retired) continue;
            var all_retired = true;
            for (self.native_owners.attachments.items) |row| if (std.mem.eql(u8, &row.reference.owner_id, &owner.id) and row.reference.adapter_epoch == owner.adapter_epoch and row.reference.endpoint_generation == owner.endpoint_generation and row.phase != .retired) {
                all_retired = false;
            };
            if (all_retired) try self.native_owners.retireOwnerForOwner(.{ .owner_id = owner.id, .adapter_epoch = owner.adapter_epoch, .endpoint_generation = owner.endpoint_generation }, task.removal_operation.?);
        }
        if (!self.native_owners.removalReady("codex", self.adapter_epochs[0], task.removal_operation.?) or self.nativeRequestsPending(null)) return self.completeNativeRemovalPending(task, "NativeCustodyPending");
        try self.persist(&.{});
        const options = try self.setupOptions(self.allocator, .codex, task.request.params);
        defer self.allocator.free(options.broker_socket);
        const actual_registry = try setup.registryWitness(self.io, self.allocator, options) orelse return error.NativeCustodyPending;
        if (!sameRegistryWitness(original_registry, actual_registry)) return error.NativeCustodyGenerationMismatch;
        if (self.measured_codex_runtime) |selected| {
            if (!selected.ownedBy(original_registry, self.adapter_epochs[0])) return error.RuntimeSelectionDrift;
        }
        const record = self.mutations.snapshot().records[task.mutation_slot.?];
        const mutation_key = creditKey(.mutation, &task.operation, record.expected_revision);
        self.active_credit = mutation_key;
        defer self.active_credit = null;
        const outcome = try setup.remove(self.io, self.allocator, options);
        defer outcome.deinit(self.allocator);
        self.native_registry = try setup.registryWitness(self.io, self.allocator, options);
        // Only the preflighted actor-owned removal clears this metadata.
        self.measured_codex_runtime = null;
        self.runtime_measurement_requested = false;
        try self.native_owners.completeApplicationRemoval("codex", self.adapter_epochs[0], task.removal_operation.?);
        for (self.installed.items, 0..) |name, index| if (eql(name, "codex")) {
            self.allocator.free(self.installed.orderedRemove(index));
            break;
        };
        self.adapter_epochs[0] = try std.math.add(u64, self.adapter_epochs[0], 1);
        const result = setup.removeResult(.codex, outcome);
        const cached = try std.json.Stringify.valueAlloc(self.allocator, result, .{});
        defer self.allocator.free(cached);
        try self.mutations.complete(task.mutation_slot.?, cached);
        try self.releaseOutcome(mutation_key);
        try self.persist(&.{});
        self.captureNativeRemovalMeasurement(task);
        return control.success(task.invocation.allocator, task.request.id, result);
    }

    fn checkNativeRemovalMeasurementCapacity(self: *Engine, task: *NativeTask) !void {
        if (task.removal_measurement == null) return;
        _ = self.snapshotUsage() catch |err| switch (err) {
            error.SnapshotTooLarge, error.SnapshotCardinalityExceeded => blk: {
                try self.mutations.abandonNativeRemovalWitness(task.mutation_slot.?);
                task.removal_measurement = null;
                break :blk try self.snapshotUsage();
            },
            else => return err,
        };
    }

    fn captureNativeRemovalMeasurement(self: *Engine, task: *NativeTask) void {
        if (task.removal_measurement) |*session| {
            const captured: anyerror!native_removal_witness.Witness = capture: {
                if (builtin.is_test and self.fixture_lifecycle_fault == .native_preparation_allocation) {
                    var failing = std.testing.FailingAllocator.init(self.allocator, .{ .fail_index = 0 });
                    const result = session.afterCommitted(self.io, failing.allocator(), self.mutations.snapshot().records[task.mutation_slot.?], self.revision);
                    const exhausted = if (result) |_| false else |err| err == error.OutOfMemory;
                    self.fixture_native_allocation_failed = failing.has_induced_failure and exhausted;
                    break :capture result;
                }
                break :capture session.afterCommitted(self.io, self.allocator, self.mutations.snapshot().records[task.mutation_slot.?], self.revision);
            };
            self.finishNativeRemovalWitness(task.mutation_slot.?, captured);
        }
    }

    fn finishNativeRemovalWitness(self: *Engine, slot: usize, captured: anyerror!native_removal_witness.Witness) void {
        const fault = self.fixture_lifecycle_fault;
        self.fixture_lifecycle_fault = .none;
        const fact = captured catch {
            self.mutations.abandonNativeRemovalWitness(slot) catch {
                self.poisoned = true;
            };
            return;
        };
        if (builtin.is_test and fault == .preparation) {
            self.mutations.abandonNativeRemovalWitness(slot) catch {
                self.poisoned = true;
            };
            return;
        }
        self.mutations.setNativeRemovalWitnessOnce(slot, fact, self.revision) catch {
            self.mutations.abandonNativeRemovalWitness(slot) catch {
                self.poisoned = true;
            };
            return;
        };
        if (builtin.is_test and fault == .sqlite_commit) {
            if (sql_api.sqlite3_exec(self.db.?.db, "PRAGMA query_only=ON", null, null, null) != sql_api.SQLITE_OK) {
                self.poisoned = true;
                return;
            }
        }
        self.persist(&.{}) catch {
            self.restoreCommitted() catch {
                self.poisoned = true;
            };
        };
    }

    /// Both ordinary startup and explicit locked retry stage all custody state.
    /// The actor is the single writer; queue/mutex/thread identity never moves.
    fn initializeCustody(self: *Engine) !void {
        if (self.db != null or self.network != null or self.native_workers != null) return error.CustodyAlreadyLoaded;
        if (self.active_until) |until| if (until.durationFromNow(self.io).raw.toMilliseconds() <= 0) return error.Timeout;
        self.metrics_mutex.lockUncancelable(self.io);
        const metrics = self.metrics;
        self.metrics_mutex.unlock(self.io);
        var staged: Engine = .{
            .allocator = self.allocator,
            .io = self.io,
            .state_dir = self.state_dir,
            .instance_selection = self.instance_selection,
            .state = domain.State.init(self.allocator),
            .observers = observer.Coordinator.init(self.allocator),
            .requests = request_authority.Ledger.init(self.allocator, 4096),
            .mutations = try mutation_authority.Ledger.init(self.allocator, 4096),
            .admission = snapshot_admission.Ledger.init(self.allocator),
            .native_owners = native_owner.Ledger.init(self.allocator),
            .metrics = metrics,
            .test_key = self.test_key,
            .test_vault = self.test_vault,
            .fixture_startup_vault_locked = self.fixture_startup_vault_locked,
            .fixture_custody_stage_failure = self.fixture_custody_stage_failure,
            .active_until = self.active_until,
        };
        defer {
            if (staged.network) |client| client.deinit();
            if (staged.db) |*db| db.close();
            staged.release();
        }
        if (self.codex_runtime_root) |root| staged.codex_runtime_root = try self.allocator.dupe(u8, root);
        try staged.bootstrap();
        if (self.active_until) |until| if (until.durationFromNow(self.io).raw.toMilliseconds() <= 0) return error.Timeout;
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.stopping) return error.ServiceStopping;
        // Create the only supervisor with the final stable Engine callback.
        const workers = try native_work.Supervisor.create(self.io, self.allocator, .{ .context = self, .signal = nativeWake });
        errdefer workers.deinit();
        try self.custodyDeadline();
        if (builtin.is_test and self.fixture_custody_stage_failure == .supervisor_ready) return error.CustodyStageFailure;
        inline for (.{ "root_key", "root_id", "state", "db", "network", "revision", "policy", "adapter_epochs", "installed", "descriptions", "import_sources", "import_forget_epoch", "requests", "mutations", "admission", "native_owners", "native_registry", "measured_codex_runtime", "runtime_measurement_requested", "outcome_intents", "maintenance_growth_bytes", "committed_nonledger_bytes", "committed_counts", "lifecycle_measurements", "browser_attempts" }) |name| {
            std.mem.swap(@TypeOf(@field(self.*, name)), &@field(self.*, name), &@field(staged, name));
        }
        self.native_workers = workers;
    }

    fn bootstrap(self: *Engine) !void {
        try self.custodyDeadline();
        const database_path = try std.fmt.allocPrintSentinel(self.allocator, "{s}/state.sqlite", .{self.state_dir}, 0);
        defer self.allocator.free(database_path);
        const existing = if (std.Io.Dir.cwd().statFile(self.io, database_path, .{ .follow_symlinks = false })) |stat| blk: {
            if (stat.kind != .file) return error.UnsafeDatabase;
            break :blk true;
        } else |err| switch (err) {
            error.FileNotFound => false,
            else => return err,
        };
        if (!existing) for ([_][]const u8{ ".authority", ".authority.lock" }) |suffix| {
            const authority_path = try std.fmt.allocPrint(self.allocator, "{s}{s}", .{ database_path, suffix });
            defer self.allocator.free(authority_path);
            if (std.Io.Dir.cwd().statFile(self.io, authority_path, .{ .follow_symlinks = false })) |_| return error.RecoveryDatabaseMissing else |err| switch (err) {
                error.FileNotFound => {},
                else => return err,
            }
        };
        self.root_id = if (existing) try storage.Store.readRootId(self.allocator, database_path) else try self.allocator.dupeSentinel(u8, self.instance_selection.vaultRoot(), 0);
        if (!eql(self.root_id.?, self.instance_selection.vaultRoot())) return error.InstanceCustodyMismatch;
        if (!existing) try validatePersistedAdmission(self.allocator, "{}", 0);
        if (builtin.is_test and self.fixture_startup_vault_locked) return error.Locked;
        self.root_key = if (self.test_vault) |backend| try vault.loadOrCreateForTest(backend, self.root_id.?, existing) else self.test_key orelse if (existing) try vault.Vault.loadRoot(self.root_id.?) else try vault.Vault.loadOrCreateRoot(self.instance_selection.vaultRoot(), false);
        try self.custodyDeadline();
        self.db = try storage.Store.openRootWithSnapshotValidator(self.io, self.allocator, database_path, self.root_id.?, self.root_key, validatePersistedAdmission);
        if (builtin.is_test and self.fixture_custody_stage_failure == .database_open) return error.CustodyStageFailure;
        var saved = try self.db.?.readSnapshot();
        defer saved.deinit();
        const parsed = try std.json.parseFromSlice(Persisted, self.allocator, saved.json, .{});
        defer parsed.deinit();
        if (parsed.value.lifecycle_measurements) |measurements| {
            self.lifecycle_measurements = try measurements.clone(self.allocator);
        }
        try validatePersistedAdmission(self.allocator, saved.json, saved.revision);
        if (parsed.value.browser_attempt_authority) |attempts| self.browser_attempts = try browser_attempt.Ledger.fromSnapshot(self.allocator, attempts);
        const restored_state = restored: {
            if (builtin.is_test and self.fixture_custody_stage_failure == .state_allocation) {
                var failing = std.testing.FailingAllocator.init(self.allocator, .{ .fail_index = 0 });
                var unexpected = try domain.State.fromSnapshot(failing.allocator(), parsed.value.state);
                unexpected.deinit();
                return error.CustodyFixtureDidNotAllocate;
            }
            break :restored try domain.State.fromSnapshot(self.allocator, parsed.value.state);
        };
        self.state.deinit();
        self.state = restored_state;
        self.revision = saved.revision;
        self.policy = parsed.value.policy;
        self.adapter_epochs = parsed.value.adapter_epochs;
        self.import_forget_epoch = parsed.value.import_forget_epoch;
        for (parsed.value.import_source_authority) |authority| try self.import_sources.append(self.allocator, .{ .source_id = try self.allocator.dupe(u8, authority.source_id), .generation = authority.generation });
        const restored_requests = try request_authority.Ledger.fromSnapshot(self.allocator, 4096, parsed.value.request_authority);
        self.requests.deinit();
        self.requests = restored_requests;
        self.requests.recoverAfterRestart();
        const restored_mutations = try mutation_authority.Ledger.fromSnapshotAtRevision(self.allocator, parsed.value.mutation_authority, saved.revision);
        self.mutations.deinit();
        self.mutations = restored_mutations;
        self.mutations.recoverAfterRestart();
        const restored_admission = try snapshot_admission.Ledger.fromSnapshot(self.allocator, parsed.value.snapshot_admission);
        self.admission.deinit();
        self.admission = restored_admission;
        self.admission.recoverAfterRestart();
        const restored_native = try native_owner.Ledger.fromSnapshot(self.allocator, parsed.value.native_owner_authority);
        self.native_owners.deinit();
        self.native_owners = restored_native;
        self.native_owners.recoverAfterRestart();
        self.native_registry = parsed.value.native_registry;
        self.measured_codex_runtime = parsed.value.measured_codex_runtime;
        if (self.measured_codex_runtime) |selected| {
            if (selected.record.channel != (if (self.instance_selection == .dev) setup.RuntimeChannel.development else setup.RuntimeChannel.release)) return error.RuntimeSelectionDrift;
        }
        // Restoration keeps authenticated historical facts, never fresh readiness.
        self.runtime_measurement_requested = self.measured_codex_runtime != null and self.codex_runtime_root != null;
        for (parsed.value.outcome_intents) |intent| {
            const copied = try copyIntent(self.allocator, intent);
            errdefer freeIntent(self.allocator, copied);
            try self.outcome_intents.append(self.allocator, copied);
        }
        self.maintenance_growth_bytes = try maintenanceReservation(self.persisted());
        for (parsed.value.installed_integrations) |name| try self.installed.append(self.allocator, try self.allocator.dupe(u8, name));
        for (parsed.value.source_descriptions) |description| try self.addDescription(description);
        // Access capabilities are not restored, but native work may still be
        // running. Retain its resource/lifecycle fence until an authenticated
        // terminal report resolves it; restart alone cannot prove completion.
        for (self.state.grants.items) |*grant| {
            const actual = try self.db.?.readGrantStatus(grant.account_id, grant.id);
            if (actual) |status| {
                if (status.generation != grant.generation or status.state == .quarantined or status.state == .refreshing) grant.status = .quarantined;
            } else grant.status = .invalid;
        }
        // Missing local transport cannot resolve a durable admitted read.
        // Its job and indeterminate credit remain until an explicit generation
        // or cancellation fence rejects every possible old completion.
        self.maintenance_growth_bytes = try maintenanceReservation(self.persisted());
        _ = try self.snapshotUsage();
        try self.custodyDeadline();
        try self.persist(&.{});
        self.network = try transport.Client.init(self.allocator);
        if (!builtin.is_test) {
            for (self.outcome_intents.items) |intent| if (intent.key.kind == .rotation) return error.SnapshotRecoveryIndeterminate;
            const key = creditKey(.rotation, "integration-recovery", self.revision);
            try self.reserveOutcome(.{ .key = key, .owner_id = "integration-recovery", .provider = "all", .plan_bytes = try integrationRecoveryGrowth() });
            try self.persist(&.{});
            self.active_credit = key;
            defer self.active_credit = null;
            try self.recoverIntegrations();
            try self.releaseOutcome(key);
            try self.persist(&.{});
        }
    }

    fn custodyDeadline(self: *Engine) !void {
        if (self.active_until) |until| if (until.durationFromNow(self.io).raw.toMilliseconds() <= 0) return error.Timeout;
    }

    fn captureInstallationSelection(self: *Engine) !void {
        const prefix_raw = std.c.getenv("OMUX_INSTALL_PREFIX");
        const receipt_raw = std.c.getenv("OMUX_INSTALL_RECORD");
        const hints = try setup_collector.selectInstallationHints(
            if (prefix_raw) |value| std.mem.span(value) else null,
            if (receipt_raw) |value| std.mem.span(value) else null,
        ) orelse return;
        const prefix = hints.prefix;
        const receipt = hints.receipt_path;
        const owned_prefix = try self.allocator.dupe(u8, prefix);
        errdefer self.allocator.free(owned_prefix);
        const owned_receipt = try self.allocator.dupe(u8, receipt);
        errdefer self.allocator.free(owned_receipt);
        const service = if (std.c.getenv("OMUX_INSTALL_SERVICE_PATH")) |path| std.mem.span(path) else null;
        const owned_service: ?[]u8 = if (service) |path| blk: {
            if (path.len > setup_collector.max_path_bytes) return error.InvalidInstallationSelection;
            try paths.validateAbsolute(path);
            break :blk try self.allocator.dupe(u8, path);
        } else null;
        errdefer if (owned_service) |path| self.allocator.free(path);
        const service_record = if (std.c.getenv("OMUX_INSTALL_SERVICE_RECORD")) |path| std.mem.span(path) else null;
        const owned_service_record: ?[]u8 = if (service_record) |path| blk: {
            if (path.len > setup_collector.max_path_bytes) return error.InvalidInstallationSelection;
            try paths.validateAbsolute(path);
            break :blk try self.allocator.dupe(u8, path);
        } else null;
        errdefer if (owned_service_record) |path| self.allocator.free(path);
        const runtime = if (std.c.getenv("XDG_RUNTIME_DIR")) |path| std.mem.span(path) else null;
        const owned_runtime: ?[]u8 = if (runtime) |path| blk: {
            if (path.len > setup_collector.max_path_bytes) break :blk null;
            paths.validateAbsolute(path) catch break :blk null;
            break :blk try self.allocator.dupe(u8, path);
        } else null;
        self.installation_selection = .{ .prefix = owned_prefix, .receipt_path = owned_receipt, .service_path = owned_service, .runtime_dir = owned_runtime, .service_record_path = owned_service_record, .selection = self.instance_selection };
    }

    fn identifiedSetupRefresh(self: *Engine, allocator: std.mem.Allocator, request: control.Request, channel: Channel) ![]u8 {
        if (channel != .control) return error.WrongChannel;
        if (self.poisoned) return error.CustodyUnavailable;
        if (request.params != .object or request.params.object.count() != 2 or control.get(request.params, "operation_id") == null or control.get(request.params, "expected_revision") == null) return error.InvalidParams;
        const id = try control.operationId(request.params);
        const revision = try control.expectedRevision(request.params);
        const fingerprint = try mutationFingerprint(allocator, request.method, request.params, self.root_key);
        if (try self.mutations.lookup(id)) |record| {
            if (!eql(record.method[0..record.method_len], request.method) or record.expected_revision != revision or record.kind != .external or !std.crypto.timing_safe.eql([32]u8, record.fingerprint, fingerprint)) return error.OperationIdConflict;
            if (record.state == .completed) {
                const decoded = try std.json.parseFromSlice(std.json.Value, allocator, record.result[0..record.result_len], .{});
                defer decoded.deinit();
                return control.success(allocator, request.id, decoded.value);
            }
            if (record.state == .started) if (self.installation_refresh) |task| if (task.verification) |reference| {
                if (task.generation == self.installation_refresh_generation and reference.slot < self.mutations.snapshot().records.len and &self.mutations.snapshot().records[reference.slot] == record and std.crypto.timing_safe.eql([32]u8, reference.fingerprint, fingerprint)) return control.success(allocator, request.id, .{ .schema_version = 1, .operation_id = id, .generation = task.generation, .status = "pending" });
            };
            return error.OperationIndeterminate;
        }
        const started = std.Io.Clock.awake.now(self.io);
        const admission = try self.mutations.begin(id, request.method, fingerprint, revision, self.revision, .external);
        const slot = switch (admission) {
            .execute => |index| index,
            else => return error.OperationIndeterminate,
        };
        const credit = creditKey(.mutation, id, revision);
        // The mutation ledger independently prepays its maximum cached result.
        // No runtime domain growth is needed for this read-only verification.
        try self.reserveOutcome(.{ .key = credit, .owner_id = id, .provider = request.method, .plan_bytes = 1 });
        try self.persist(&.{});
        if (self.installation_refresh != null or self.installation_selection == null) {
            const result = try setup_verification.makeRefusal(id, self.installation_refresh_generation, self.now(), if (self.installation_refresh != null) .busy else .installation_selection_required);
            const cached = try setup_verification.serialize(allocator, result);
            defer allocator.free(cached);
            try self.mutations.complete(slot, cached);
            try self.releaseOutcome(credit);
            try self.persist(&.{});
            return control.success(allocator, request.id, result);
        }
        self.startSetupRefresh() catch |err| {
            try self.mutations.markIndeterminate(slot);
            try self.admission.markIndeterminate(credit);
            try self.persist(&.{});
            return err;
        };
        self.installation_refresh.?.verification = .{ .slot = slot, .fingerprint = fingerprint, .credit = credit, .started = started };
        if (self.codex_runtime_root != null and self.integrationInstalled("codex")) self.runtime_measurement_requested = true;
        return control.success(allocator, request.id, .{ .schema_version = 1, .operation_id = id, .generation = self.installation_refresh_generation, .status = "pending" });
    }

    fn startSetupRefresh(self: *Engine) !void {
        if (self.installation_refresh != null) return;
        const selected = self.installation_selection orelse return;
        const generation = try std.math.add(u64, self.installation_refresh_generation, 1);
        const task = try self.allocator.create(SetupRefreshTask);
        errdefer self.allocator.destroy(task);
        task.* = .{ .io = self.io, .allocator = self.allocator, .selected = selected, .generation = generation, .deadline = .fromNow(self.io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) }) };
        task.thread = try std.Thread.spawn(.{}, SetupRefreshTask.run, .{task});
        self.installation_refresh_generation = generation;
        self.installation_refresh = task;
    }

    fn stopSetupRefresh(self: *Engine) void {
        if (self.installation_refresh) |task| {
            task.thread.?.join();
            self.allocator.destroy(task);
            self.installation_refresh = null;
        }
    }

    fn completeSetupRefresh(self: *Engine) void {
        const task = self.installation_refresh orelse return;
        if (!task.done.load(.acquire)) return;
        // Join outside the mutex: deinit may request shutdown while the bounded
        // reader finishes. The shared lock linearizes terminal publication with
        // that request; an already requested shutdown retains its started fence.
        task.thread.?.join();
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.stopping) {
            self.installation_refresh = null;
            self.allocator.destroy(task);
            return;
        }
        if (task.verification) |reference| {
            self.commitSetupVerification(task, reference) catch {
                // A failed terminal commit cannot publish fresh verification or
                // manufacture a completion. Restore the durable started fence.
                self.restoreCommitted() catch {
                    self.poisoned = true;
                };
                if (!self.poisoned and reference.slot < self.mutations.snapshot().records.len) {
                    const record = self.mutations.snapshot().records[reference.slot];
                    if (record.state == .started and std.crypto.timing_safe.eql([32]u8, record.fingerprint, reference.fingerprint)) {
                        self.mutations.markIndeterminate(reference.slot) catch {
                            self.poisoned = true;
                        };
                        if (!self.poisoned) self.admission.markIndeterminate(reference.credit) catch {
                            self.poisoned = true;
                        };
                        if (!self.poisoned) self.persist(&.{}) catch {
                            self.poisoned = true;
                        };
                    }
                }
                if (task.collection_error != null) {
                    self.installation_probe = task.result.probe;
                    self.installation_service_status = null;
                    self.installation_probe_at = null;
                }
                self.installation_refresh = null;
                self.allocator.destroy(task);
                return;
            };
        }
        self.installation_probe = task.result.probe;
        self.installation_service_status = task.result.service_status;
        self.installation_probe_at = if (task.collection_error == null) task.observed_at else null;
        self.installation_refresh = null;
        self.allocator.destroy(task);
    }

    fn commitSetupVerification(self: *Engine, task: *const SetupRefreshTask, reference: SetupVerificationRef) !void {
        if (self.poisoned or self.installation_refresh != task or task.generation != self.installation_refresh_generation) return error.StaleSetupVerification;
        const records = self.mutations.snapshot().records;
        if (reference.slot >= records.len) return error.StaleSetupVerification;
        const record = records[reference.slot];
        if (record.state != .started or record.kind != .external or !eql(record.method[0..record.method_len], "setup.refresh") or !std.crypto.timing_safe.eql([32]u8, record.fingerprint, reference.fingerprint) or !std.meta.eql(reference.credit, creditKey(.mutation, record.id[0..record.id_len], record.expected_revision))) return error.StaleSetupVerification;
        const elapsed = reference.started.durationTo(std.Io.Clock.awake.now(self.io)).toNanoseconds();
        const result = if (task.collection_error) |err| switch (err) {
            error.Timeout => try setup_verification.makeRefusal(record.id[0..record.id_len], task.generation, task.observed_at, .collection_timed_out),
            else => return err,
        } else try setup_verification.makeCompleted(record.id[0..record.id_len], task.generation, task.observed_at, onboarding.assess(self.setupSnapshot(task.result.probe, false)), if (elapsed >= 0 and elapsed <= std.math.maxInt(u64)) @intCast(elapsed) else null);
        const cached = try setup_verification.serialize(self.allocator, result);
        defer self.allocator.free(cached);
        try self.mutations.complete(reference.slot, cached);
        try self.releaseOutcome(reference.credit);
        try self.persist(&.{});
    }

    fn setupSnapshot(self: *Engine, selected_probe: setup_collector.Collected, pending: bool) onboarding.Snapshot {
        var snapshot: onboarding.Snapshot = .{ .expected_channel = if (self.instance_selection == .dev) .development else .release };
        const probe = selected_probe;
        setup_evidence.apply(&snapshot, setup_evidence.project(probe.artifact, probe.service));
        if (pending) {
            snapshot.artifact = .{ .state = .pending, .freshness = .current, .evidence = .diagnostic };
            snapshot.service = .{ .state = .pending, .freshness = .current, .evidence = .diagnostic };
        }
        snapshot.vault = .{ .state = if (self.vault_locked) .locked else if (self.poisoned) .unknown else .ready, .freshness = if (self.vault_locked) .stale else .current, .evidence = .diagnostic };
        // A locked startup has not loaded retained source/account metadata.
        if (self.vault_locked) return snapshot;
        const timestamp = self.now();
        var connected = false;
        for (self.state.sources.items) |source| if (source.status == .connected and source.authorized_at <= timestamp and (source.authorized_until == null or source.authorized_until.? > timestamp)) {
            connected = true;
        };
        snapshot.source = .{ .state = if (connected) .ready else .missing, .freshness = .current, .evidence = .diagnostic };
        var verified = false;
        for (self.state.accounts.items) |account| if (account.identity.verified) {
            verified = true;
        };
        snapshot.identity = .{ .state = if (verified) .ready else .pending, .freshness = .current, .evidence = .diagnostic };
        var usable = false;
        for (self.state.grants.items) |grant| {
            if (grant.status != .ready or grant.credential_kind == .oauth_refresh or grant.credential_kind == .browser_bound or (grant.provider_expires_at != null and grant.provider_expires_at.? <= timestamp) or (grant.custody_expires_at != null and grant.custody_expires_at.? <= timestamp)) continue;
            const account = self.state.account(grant.account_id) orelse continue;
            if (!account.identity.verified or account.lifecycle != .active) continue;
            // The grant's exact source lineage must still authorize requests.
            // Detached sources keep independently valid non-browser grants.
            var source_authorized = false;
            for (self.state.sources.items) |source| if (eql(source.id, grant.source_id)) {
                source_authorized = source.status != .disconnected and source.authorized_at <= timestamp and
                    (source.authorized_until == null or source.authorized_until.? > timestamp);
                break;
            };
            if (!source_authorized) continue;
            for (grant.purposes) |purpose| if (purpose == .request) {
                usable = true;
            };
        }
        snapshot.grant = .{ .state = if (usable and !self.poisoned) .ready else .missing, .freshness = .current, .evidence = .diagnostic };
        return snapshot;
    }

    fn currentInstallationProbe(self: *const Engine) setup_collector.Collected {
        var result = self.installation_probe;
        if (self.installation_probe_at) |observed_at| {
            const timestamp = self.now();
            if (timestamp < observed_at or timestamp - observed_at > 60) {
                result.artifact.freshness = .stale;
                result.service.freshness = .stale;
            }
        }
        return result;
    }

    fn now(self: *const Engine) i64 {
        return std.Io.Clock.real.now(self.io).toSeconds();
    }

    fn fence(self: *Engine) void {
        self.poisoned = true;
        // Maintenance can fail after preparing an in-memory update. Public
        // inspection retains committed metadata whenever storage can read it.
        self.restoreCommitted() catch {};
    }

    fn persist(self: *Engine, changes: []const storage.GrantChange) !void {
        if (self.staging_mutation) {
            try self.staged_changes.appendSlice(self.allocator, changes);
            return;
        }
        // Only the original owner can debit its committed positive growth.
        // Every other writer must leave all outstanding credits available.
        const candidate_nonledger = try self.nonledgerBytes();
        const candidate_counts = self.actualCounts();
        if (self.active_credit) |key| if (self.admission.lookup(key) != null) {
            var growth: snapshot_admission.Counts = .{};
            inline for (@typeInfo(snapshot_admission.Counts).@"struct".field_names) |name| {
                @field(growth, name) = @field(candidate_counts, name) -| @field(self.committed_counts, name);
            }
            try self.admission.consumeWithCounts(key, candidate_nonledger -| self.committed_nonledger_bytes, growth);
            const intent = self.outcomeIntent(key) orelse return error.InvalidSnapshotCreditAuthority;
            intent.used_bytes = try std.math.add(usize, intent.used_bytes, candidate_nonledger -| self.committed_nonledger_bytes);
            inline for (@typeInfo(snapshot_admission.Counts).@"struct".field_names) |name| @field(intent.used_counts, name) += @field(growth, name);
        };
        self.maintenance_growth_bytes = try maintenanceReservation(self.persisted());
        _ = try self.snapshotUsage();
        const committed_growth_bytes = try self.nonledgerBytes();
        const serialized = try std.json.Stringify.valueAlloc(self.allocator, self.persisted(), .{});
        defer self.allocator.free(serialized);
        self.revision = self.db.?.commit(self.revision, serialized, changes) catch |err| {
            // Ambiguous storage failure fences all further credential service.
            self.poisoned = true;
            return err;
        };
        self.committed_nonledger_bytes = committed_growth_bytes;
        self.committed_counts = candidate_counts;
    }

    fn persisted(self: *const Engine) Persisted {
        return .{
            .schema_version = 2,
            .lifecycle_measurements = self.lifecycle_measurements,
            .browser_attempt_authority = if (self.browser_attempts) |*attempts| attempts.snapshot() else null,
            .state = self.state.snapshot(),
            .policy = self.policy,
            .installed_integrations = self.installed.items,
            .source_descriptions = self.descriptions.items,
            .adapter_epochs = self.adapter_epochs,
            .request_authority = self.requests.snapshot(),
            .mutation_authority = self.mutations.snapshot(),
            .snapshot_admission = self.admission.snapshot(),
            .import_source_authority = self.import_sources.items,
            .import_forget_epoch = self.import_forget_epoch,
            .outcome_intents = self.outcome_intents.items,
            .maintenance_growth_bytes = self.maintenance_growth_bytes,
            .native_owner_authority = self.native_owners.snapshot(),
            .native_registry = self.native_registry,
            .measured_codex_runtime = self.measured_codex_runtime,
        };
    }

    fn snapshotUsage(self: *const Engine) !snapshot_admission.Usage {
        return snapshot_admission.checkEnvelopeWithNative(self.persisted(), self.requests.reservedSnapshotBytes(), self.mutations.reservedSnapshotBytes(), try self.native_owners.reservedSnapshotBytes());
    }

    fn nonledgerBytes(self: *const Engine) !usize {
        const value = self.persisted();
        return (try snapshot_admission.countJson(value, storage.maximum_snapshot_bytes)) -
            (try snapshot_admission.countJson(value.request_authority, storage.maximum_snapshot_bytes)) -
            (try snapshot_admission.countJson(value.mutation_authority, storage.maximum_snapshot_bytes)) -
            (try snapshot_admission.countJson(value.snapshot_admission, storage.maximum_snapshot_bytes)) -
            (try snapshot_admission.countJson(value.native_owner_authority, storage.maximum_snapshot_bytes)) -
            (try snapshot_admission.countJson(value.maintenance_growth_bytes, storage.maximum_snapshot_bytes)) -
            (try snapshot_admission.countJson(value.lifecycle_measurements, reliability.max_lifecycle_checkpoint_bytes)) -
            (try snapshot_admission.countJson(value.browser_attempt_authority, browser_attempt.maximum_snapshot_bytes));
    }

    fn actualCounts(self: *const Engine) snapshot_admission.Counts {
        const state = self.state.snapshot();
        var counts: snapshot_admission.Counts = .{ .source_descriptions = self.descriptions.items.len };
        inline for (@typeInfo(snapshot_admission.Counts).@"struct".field_names) |name| {
            if (@hasField(domain.Snapshot, name)) @field(counts, name) = @field(state, name).len;
        }
        for (state.accounts) |account| counts.source_links = @max(counts.source_links, account.source_ids.len);
        counts.native_owners = self.native_owners.owners.items.len;
        counts.native_authority_records = self.native_owners.attachments.items.len + self.native_owners.removals.items.len;
        return counts;
    }

    fn outcomeIntent(self: *Engine, key: snapshot_admission.Key) ?*OutcomeIntent {
        for (self.outcome_intents.items) |*intent| if (std.meta.eql(intent.key, key)) return intent;
        return null;
    }

    fn reserveOutcome(self: *Engine, input: OutcomeIntent) !void {
        if (self.outcome_intents.items.len >= snapshot_admission.maximum_credits) return error.SnapshotTooLarge;
        const owned = try copyIntent(self.allocator, input);
        errdefer freeIntent(self.allocator, owned);
        try self.outcome_intents.ensureUnusedCapacity(self.allocator, 1);
        try self.admission.reserveWithCounts(input.key, input.plan_bytes, input.plan_counts);
        self.outcome_intents.appendAssumeCapacity(owned);
    }

    fn releaseOutcome(self: *Engine, key: snapshot_admission.Key) !void {
        try self.admission.release(key);
        for (self.outcome_intents.items, 0..) |intent, index| if (std.meta.eql(intent.key, key)) {
            freeIntent(self.allocator, self.outcome_intents.orderedRemove(index));
            return;
        };
        return error.InvalidSnapshotCreditAuthority;
    }

    fn restoreCommitted(self: *Engine) !void {
        var saved = try self.db.?.readSnapshot();
        defer saved.deinit();
        try validatePersistedAdmission(self.allocator, saved.json, saved.revision);
        const parsed = try std.json.parseFromSlice(Persisted, self.allocator, saved.json, .{});
        defer parsed.deinit();
        if (parsed.value.measured_codex_runtime) |selected| {
            if (selected.record.channel != (if (self.instance_selection == .dev) setup.RuntimeChannel.development else setup.RuntimeChannel.release)) return error.RuntimeSelectionDrift;
        }
        const restored_measurements: ?*reliability.LifecycleRecorder = if (parsed.value.lifecycle_measurements) |measurements| blk: {
            break :blk try measurements.clone(self.allocator);
        } else null;
        var ownership_transferred = false;
        errdefer if (!ownership_transferred) {
            if (restored_measurements) |measurements| self.allocator.destroy(measurements);
        };
        var restored_browser_attempts: ?browser_attempt.Ledger = if (parsed.value.browser_attempt_authority) |attempts| try browser_attempt.Ledger.fromSnapshot(self.allocator, attempts) else null;
        errdefer if (!ownership_transferred) {
            if (restored_browser_attempts) |*attempts| attempts.deinit();
        };
        var replacement = try domain.State.fromSnapshot(self.allocator, parsed.value.state);
        errdefer if (!ownership_transferred) replacement.deinit();
        var requests = try request_authority.Ledger.fromSnapshot(self.allocator, 4096, parsed.value.request_authority);
        errdefer if (!ownership_transferred) requests.deinit();
        var mutations = try mutation_authority.Ledger.fromSnapshotAtRevision(self.allocator, parsed.value.mutation_authority, saved.revision);
        errdefer if (!ownership_transferred) mutations.deinit();
        var admission = try snapshot_admission.Ledger.fromSnapshot(self.allocator, parsed.value.snapshot_admission);
        errdefer if (!ownership_transferred) admission.deinit();
        var native = try native_owner.Ledger.fromSnapshot(self.allocator, parsed.value.native_owner_authority);
        errdefer if (!ownership_transferred) native.deinit();
        var installed: std.ArrayList([]const u8) = .empty;
        errdefer if (!ownership_transferred) {
            for (installed.items) |item| self.allocator.free(item);
            installed.deinit(self.allocator);
        };
        for (parsed.value.installed_integrations) |name| {
            const copied = try self.allocator.dupe(u8, name);
            errdefer self.allocator.free(copied);
            try installed.append(self.allocator, copied);
        }
        var descriptions: std.ArrayList(SourceDescription) = .empty;
        errdefer if (!ownership_transferred) {
            for (descriptions.items) |item| freeDescription(self.allocator, item);
            descriptions.deinit(self.allocator);
        };
        for (parsed.value.source_descriptions) |description| {
            const copied = try copyDescription(self.allocator, description);
            errdefer freeDescription(self.allocator, copied);
            try descriptions.append(self.allocator, copied);
        }
        var import_sources: std.ArrayList(ImportSourceAuthority) = .empty;
        errdefer if (!ownership_transferred) {
            for (import_sources.items) |authority| self.allocator.free(authority.source_id);
            import_sources.deinit(self.allocator);
        };
        for (parsed.value.import_source_authority) |authority| {
            const copied = try self.allocator.dupe(u8, authority.source_id);
            errdefer self.allocator.free(copied);
            try import_sources.append(self.allocator, .{ .source_id = copied, .generation = authority.generation });
        }
        var outcome_intents: std.ArrayList(OutcomeIntent) = .empty;
        errdefer if (!ownership_transferred) {
            for (outcome_intents.items) |intent| freeIntent(self.allocator, intent);
            outcome_intents.deinit(self.allocator);
        };
        for (parsed.value.outcome_intents) |intent| {
            const copied = try copyIntent(self.allocator, intent);
            errdefer freeIntent(self.allocator, copied);
            try outcome_intents.append(self.allocator, copied);
        }
        self.state.deinit();
        self.state = replacement;
        self.requests.deinit();
        self.requests = requests;
        self.mutations.deinit();
        self.mutations = mutations;
        self.admission.deinit();
        self.admission = admission;
        self.native_owners.deinit();
        self.native_owners = native;
        self.native_registry = parsed.value.native_registry;
        self.measured_codex_runtime = parsed.value.measured_codex_runtime;
        for (self.installed.items) |item| self.allocator.free(item);
        self.installed.deinit(self.allocator);
        self.installed = installed;
        for (self.descriptions.items) |item| freeDescription(self.allocator, item);
        self.descriptions.deinit(self.allocator);
        self.descriptions = descriptions;
        self.revision = saved.revision;
        self.policy = parsed.value.policy;
        self.adapter_epochs = parsed.value.adapter_epochs;
        for (self.import_sources.items) |authority| self.allocator.free(authority.source_id);
        self.import_sources.deinit(self.allocator);
        self.import_sources = import_sources;
        self.import_forget_epoch = parsed.value.import_forget_epoch;
        if (self.lifecycle_measurements) |measurements| self.allocator.destroy(measurements);
        self.lifecycle_measurements = restored_measurements;
        if (self.browser_attempts) |*attempts| attempts.deinit();
        self.browser_attempts = restored_browser_attempts;

        for (self.outcome_intents.items) |intent| freeIntent(self.allocator, intent);
        self.outcome_intents.deinit(self.allocator);
        self.outcome_intents = outcome_intents;
        // Later derived checks may fail; self owns every replacement now.
        ownership_transferred = true;
        self.maintenance_growth_bytes = try maintenanceReservation(self.persisted());
        _ = try self.snapshotUsage();
        self.committed_nonledger_bytes = try self.nonledgerBytes();
        self.committed_counts = self.actualCounts();
    }

    pub fn capabilityForTest(self: *Engine, application: []const u8) ![64]u8 {
        if (!builtin.is_test) return error.TestOnly;
        return self.capability(application);
    }

    /// Queue a complete bounded backlog before waking the actor. Each fixture
    /// response must be produced by that actor; caller threads never mutate
    /// custody or infer success from a test clock/counter.
    pub fn maintenanceBacklogForTest(self: *Engine, allocator: std.mem.Allocator, first_payload: []const u8, busy_payload: []const u8) !bool {
        if (!builtin.is_test) return error.TestOnly;
        var batch: [16]Invocation = undefined;
        for (&batch, 0..) |*item, index| item.* = .{ .allocator = allocator, .payload = if (index == 0) first_payload else busy_payload, .channel = .adapter, .until = .fromNow(self.io, .{ .clock = .awake, .raw = .fromMilliseconds(15000) }) };
        self.mutex.lockUncancelable(self.io);
        defer self.mutex.unlock(self.io);
        if (self.stopping) return error.ServiceStopping;
        if (self.queue_count + batch.len > self.queue.len) return error.ServiceBusy;
        for (&batch) |*item| {
            self.queue[(self.queue_head + self.queue_count) % self.queue.len] = item;
            self.queue_count += 1;
        }
        self.condition.signal(self.io);
        // Every stack reference remains owned until the entire batch drains,
        // including on a failed fixture response.
        for (&batch) |*item| while (!item.finished) item.condition.waitUncancelable(self.io, &self.mutex);
        defer for (&batch) |*item| if (item.response) |response| allocator.free(response);
        var progressed_while_busy = false;
        for (&batch) |*item| {
            if (item.failure) |err| return err;
            const parsed = try std.json.parseFromSlice(std.json.Value, allocator, item.response.?, .{});
            defer parsed.deinit();
            const result = control.get(parsed.value, "result") orelse return error.InvalidReply;
            if (eql(try control.string(result, "grant_status"), "invalid") and !try control.boolean(result, "secret_retained", true) and control.get(result, "backlog").?.integer > 0) progressed_while_busy = true;
        }
        return progressed_while_busy;
    }

    fn addDescription(self: *Engine, input: SourceDescription) !void {
        const copied = try copyDescription(self.allocator, input);
        errdefer freeDescription(self.allocator, copied);
        try self.descriptions.append(self.allocator, copied);
    }

    fn identifier(self: *Engine) ![64]u8 {
        var bytes: [32]u8 = undefined;
        try self.io.randomSecure(&bytes);
        defer std.crypto.secureZero(u8, &bytes);
        return std.fmt.bytesToHex(bytes, .lower);
    }

    /// Capabilities authorize a named installed adapter, not arbitrary RPCs.
    fn capability(self: *Engine, application: []const u8) ![64]u8 {
        if (catalog.find(application) == null and !eql(application, "enrollment")) return error.UnknownAdapter;
        var mac: [32]u8 = undefined;
        // A wrapping key may serve more than one local installation. Authority
        // is bound to the authenticated immutable installation identity, never
        // a mutable checkpoint nonce or a relocatable filesystem path.
        const installation = std.fmt.bytesToHex(self.db.?.checkpoint.installation, .lower);
        const message = try std.fmt.allocPrint(self.allocator, "omux.adapter.v2.{s}.{d}.{s}.{d}", .{ installation, application.len, application, self.adapter_epochs[try adapterIndex(application)] });
        defer self.allocator.free(message);
        std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, message, &self.root_key);
        defer std.crypto.secureZero(u8, &mac);
        return std.fmt.bytesToHex(mac, .lower);
    }

    fn authenticate(self: *Engine, params: std.json.Value) ![]const u8 {
        const application = try control.string(params, "application");
        var installed = eql(application, "enrollment") or builtin.is_test;
        for (self.installed.items) |name| if (eql(name, application)) {
            installed = true;
        };
        if (!installed) return error.AdapterNotInstalled;
        const supplied = try control.string(params, "capability");
        var expected = try self.capability(application);
        defer std.crypto.secureZero(u8, &expected);
        if (supplied.len != expected.len or !std.crypto.timing_safe.eql([64]u8, supplied[0..64].*, expected)) return error.Unauthorized;
        return application;
    }

    fn protectedNativeRef(self: *Engine, params: std.json.Value, require_active: bool) !?native_owner.NativeRef {
        const application = try control.string(params, "application");
        if (!eql(application, "codex")) return null;
        const context = self.active_peer orelse return error.NativePeerRequired;
        try context.alive();
        const reference = try parseNativeRef(params);
        const owner = self.native_owners.lookupOwnerForRef(reference) orelse return error.UnknownNativeOwner;
        const attachment = self.native_owners.lookupAttachment(reference) orelse return error.UnknownNativeAttachment;
        if (!eql(owner.application, application) or owner.adapter_epoch != reference.adapter_epoch or owner.endpoint_generation != reference.endpoint_generation or !peer.sameOriginal(owner.witness, context.witness())) return error.NativeOwnerMismatch;
        if (try control.optionalString(params, "session_id")) |session| if (!eql(attachment.thread_id, session)) return error.NativeOwnerMismatch;
        if (require_active) {
            if (reference.adapter_epoch != self.adapter_epochs[try adapterIndex(application)] or owner.phase != .open or attachment.phase != .attached or self.native_owners.applicationRemoval(application, reference.adapter_epoch) != null) return error.NativeRemovalPending;
        }
        return reference;
    }

    fn execute(self: *Engine, allocator: std.mem.Allocator, payload: []const u8, channel: Channel) ![]u8 {
        // Fence the selected instance before proof decoding, mutation admission,
        // or diagnostic refusal accounting, including custody-repair health.
        if (channel == .browser) {
            var ingress = browser.decodeIngress(allocator, payload, builtin.is_test) catch |err| return std.json.Stringify.valueAlloc(allocator, .{ .version = 1, .id = @as(?[]const u8, null), .@"error" = .{ .code = @errorName(err), .message = "Browser request was not admitted." } }, .{});
            defer ingress.deinit();
            const expected: browser.Channel = if (self.instance_selection == .dev) .development else .release;
            if (ingress.validated.provenance.channel != expected) return std.json.Stringify.valueAlloc(allocator, .{ .version = 1, .id = ingress.validated.id, .@"error" = .{ .code = "BrowserChannelMismatch", .message = "Browser request targets a different instance." } }, .{});
        }
        if (self.poisoned) {
            if (channel == .browser) {
                var decoded = browser.decodeRequest(allocator, payload, builtin.is_test, self.now()) catch return std.json.Stringify.valueAlloc(allocator, .{ .version = 1, .id = @as(?[]const u8, null), .@"error" = .{ .code = "CustodyUnavailable", .message = "Credential custody requires repair." } }, .{});
                defer decoded.deinit();
                if (decoded.validated.method == .health) return self.handleBrowser(allocator, decoded.validated);
                return std.json.Stringify.valueAlloc(allocator, .{ .version = 1, .id = decoded.validated.id, .@"error" = .{ .code = "CustodyUnavailable", .message = "Credential custody requires repair." } }, .{});
            }
            var failed = control.parse(allocator, payload) catch return control.failure(allocator, .null, -32000, "CustodyUnavailable");
            defer failed.deinit();
            if (channel == .control and (eql(failed.method, "system.handshake") or eql(failed.method, "state.snapshot") or eql(failed.method, "system.health") or eql(failed.method, "reliability.export") or eql(failed.method, "reliability.lifecycle") or eql(failed.method, "setup.readiness") or eql(failed.method, "setup.plan") or eql(failed.method, "setup.evidence") or eql(failed.method, "setup.refresh") or eql(failed.method, application_readiness.method))) return self.handleRequest(allocator, failed, channel);
            return control.failure(allocator, failed.id, -32000, "CustodyUnavailable");
        }
        if (channel == .browser) return self.executeBrowser(allocator, payload) catch |err| {
            self.restoreCommitted() catch {
                self.poisoned = true;
            };
            return std.json.Stringify.valueAlloc(allocator, .{ .version = 1, .id = @as(?[]const u8, null), .@"error" = .{ .code = @errorName(err), .message = "Browser request was not admitted." } }, .{});
        };
        var request = control.parse(allocator, payload) catch |err| return control.failure(allocator, .null, -32600, @errorName(err));
        defer request.deinit();
        // Audit refusals do not restore or rewrite the actor's committed state.
        // Production control ingress already verifies the socket's peer user.
        if (eql(request.method, "integrations.nativeRequestAudit") or eql(request.method, "custody.reopen")) return self.handleRequest(allocator, request, channel) catch |err| return control.failure(allocator, request.id, -32000, @errorName(err));
        return self.authorizedRequest(allocator, request, channel) catch |err| {
            self.restoreCommitted() catch {
                self.poisoned = true;
            };
            return control.failure(allocator, request.id, -32000, @errorName(err));
        };
    }

    fn authorizedRequest(self: *Engine, allocator: std.mem.Allocator, request: control.Request, channel: Channel) ![]u8 {
        if (eql(request.method, "setup.refresh")) return self.handleRequest(allocator, request, channel);
        const kind = mutationKind(request.method) orelse return self.handleRequest(allocator, request, channel);
        if (channel != .control) return error.WrongChannel;
        const operation_id = try control.operationId(request.params);
        const expected_revision = try control.expectedRevision(request.params);
        const fingerprint = try mutationFingerprint(allocator, request.method, request.params, self.root_key);
        const admission = try self.mutations.begin(operation_id, request.method, fingerprint, expected_revision, self.revision, kind);
        const slot = switch (admission) {
            .replay => |bytes| {
                const result = try std.json.parseFromSlice(std.json.Value, allocator, bytes, .{});
                defer result.deinit();
                return control.success(allocator, request.id, result.value);
            },
            .indeterminate => return error.OperationIndeterminate,
            .execute => |index| index,
        };
        const key = creditKey(.mutation, operation_id, expected_revision);
        var measurement: ?lifecycle_witness.Session = null;
        if (eql(request.method, lifecycle_witness.method)) {
            // Optional timing capacity belongs to the original authority row.
            // No clock is restored or started for cached acknowledgments.
            if (try self.mutations.tryReserveLifecycleWitness(slot)) measurement = try lifecycle_witness.Session.begin(self.io, self.mutations.snapshot().records[slot], .{
                .os = switch (builtin.os.tag) {
                    .linux => .linux,
                    .macos => .macos,
                    else => .other,
                },
                .architecture = switch (builtin.cpu.arch) {
                    .x86_64 => .x86_64,
                    .aarch64 => .aarch64,
                    else => .other,
                },
                .channel = if (self.instance_selection == .dev) .development else .release,
            });
        }
        if (kind == .external) {
            try self.preflightMutationResult(allocator, request.method, request.params);
            const plan = try self.mutationOutcomePlan(allocator, request.method, request.params);
            try self.reserveOutcome(.{ .key = key, .owner_id = operation_id, .provider = request.method, .plan_bytes = plan.bytes, .plan_counts = plan.slots });
            if (measurement != null) {
                self.maintenance_growth_bytes = try maintenanceReservation(self.persisted());
                _ = self.snapshotUsage() catch |err| switch (err) {
                    error.SnapshotTooLarge, error.SnapshotCardinalityExceeded => blk: {
                        try self.mutations.abandonLifecycleWitness(slot);
                        measurement = null;
                        self.maintenance_growth_bytes = try maintenanceReservation(self.persisted());
                        break :blk try self.snapshotUsage();
                    },
                    else => return err,
                };
            }
            // Lazy measurement activation leaves older checkpoints readable and
            // prepays the complete bounded aggregate before any source effect.
            if (eql(request.method, "source.disconnect") and self.lifecycle_measurements == null) {
                self.lifecycle_measurements = reliability.LifecycleRecorder.create(self.allocator, self.now(), self.metrics.stratum) catch |err| switch (err) {
                    error.OutOfMemory => null,
                };
                if (self.lifecycle_measurements != null) {
                    self.maintenance_growth_bytes = try maintenanceReservation(self.persisted());
                    _ = self.snapshotUsage() catch |err| switch (err) {
                        error.SnapshotTooLarge, error.SnapshotCardinalityExceeded => blk: {
                            // Telemetry is optional: lack of aggregate headroom must
                            // never prevent a security-sensitive source removal.
                            self.allocator.destroy(self.lifecycle_measurements.?);
                            self.lifecycle_measurements = null;
                            self.maintenance_growth_bytes = try maintenanceReservation(self.persisted());
                            break :blk try self.snapshotUsage();
                        },
                        else => return err,
                    };
                }
            }
            // The started replay fence and outcome space commit together.
            try self.persist(&.{});
        }
        self.active_credit = if (kind == .external) key else null;
        defer self.active_credit = null;
        errdefer {
            // A reply encoder/allocation failure after external I/O is just as
            // uncertain as an I/O failure. Never leave a retryable execution
            // path merely because no redacted completion could be encoded.
            if (kind == .external and !self.poisoned) {
                self.staging_mutation = false;
                self.restoreCommitted() catch {
                    self.poisoned = true;
                };
                self.mutations.markIndeterminate(slot) catch {
                    self.poisoned = true;
                };
                if (!self.poisoned) self.admission.markIndeterminate(key) catch {
                    self.poisoned = true;
                };
                if (!self.poisoned) self.persist(&.{}) catch {
                    self.poisoned = true;
                };
            }
        }
        self.staging_mutation = kind == .local_atomic;
        defer {
            self.staging_mutation = false;
            self.staged_changes.clearRetainingCapacity();
        }
        const reply = try self.handleRequest(allocator, request, channel);
        errdefer allocator.free(reply);
        const decoded = try std.json.parseFromSlice(std.json.Value, allocator, reply, .{});
        defer decoded.deinit();
        const result = control.get(decoded.value, "result") orelse return error.InvalidMutationResult;
        const cached = try std.json.Stringify.valueAlloc(allocator, result, .{});
        defer allocator.free(cached);
        const previous_mutation = self.mutations.snapshot().records[slot];
        try self.mutations.complete(slot, cached);
        if (kind == .external and eql(request.method, "source.disconnect")) if (self.lifecycle_measurements) |current| {
            var correlation: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(operation_id, &correlation, .{});
            const prepared: ?reliability_commit.Prepared = reliability_commit.terminalTransition(self.allocator, current, previous_mutation, self.mutations.snapshot().records[slot], self.now(), .{
                .operation_correlation = std.mem.readInt(u64, correlation[0..8], .little),
                .phase = .remove,
                .outcome = .success,
            }) catch |err| switch (err) {
                error.ClockAnomaly, error.CounterSaturated => blk: {
                    if (err == error.ClockAnomaly) current.clock_anomaly = true else current.saturated = true;
                    break :blk null;
                },
                error.OutOfMemory => null,
                else => return err,
            };
            if (prepared) |candidate| {
                self.allocator.destroy(current);
                self.lifecycle_measurements = candidate.recorder;
            }
        };
        if (kind == .external) try self.releaseOutcome(key);
        self.staging_mutation = false;
        try self.persist(self.staged_changes.items);
        // This is AFTER original terminal authority commits. Optional errors
        // are contained here: the outer uncertainty errdefer must never turn
        // a durable completed effect into indeterminate or repeat it.
        if (measurement) |*session| {
            const fact = session.afterCommitted(self.io, self.allocator, self.mutations.snapshot().records[slot], self.revision);
            self.finishLifecycleWitness(slot, fact);
        }
        return reply;
    }

    fn finishLifecycleWitness(self: *Engine, slot: usize, captured: anyerror!lifecycle_witness.Witness) void {
        const fault = self.fixture_lifecycle_fault;
        self.fixture_lifecycle_fault = .none;
        const fact = captured catch {
            self.mutations.abandonLifecycleWitness(slot) catch {
                self.poisoned = true;
            };
            return;
        };
        if (builtin.is_test and fault == .preparation) {
            self.mutations.abandonLifecycleWitness(slot) catch {
                self.poisoned = true;
            };
            return;
        }
        self.mutations.setLifecycleWitnessOnce(slot, fact, self.revision) catch {
            self.mutations.abandonLifecycleWitness(slot) catch {
                self.poisoned = true;
            };
            return;
        };
        if (builtin.is_test and fault == .sqlite_commit) {
            if (sql_api.sqlite3_exec(self.db.?.db, "PRAGMA query_only=ON", null, null, null) != sql_api.SQLITE_OK) {
                self.poisoned = true;
                return;
            }
        }
        self.persist(&.{}) catch {
            // persist preserves its poison on an actual Store failure. Even
            // failed best-effort restoration cannot rewrite original success.
            self.restoreCommitted() catch {
                self.poisoned = true;
            };
        };
    }

    fn preflightMutationResult(self: *Engine, allocator: std.mem.Allocator, method: []const u8, params: std.json.Value) !void {
        if (eql(method, "source.reconcile") or eql(method, "enrollment.start")) {
            const job = try std.fmt.allocPrint(allocator, "reconcile-{s}", .{try control.string(params, "source_id")});
            defer allocator.free(job);
            if (try control.boolean(params, "include_operation_generation", false)) {
                try setup.requireResultFits(allocator, .{ .operation_id = job, .status = "verifying_identity", .operation_generation = std.math.maxInt(u64), .admitted_revision = std.math.maxInt(u64) });
            } else try setup.requireResultFits(allocator, .{ .operation_id = job, .status = "verifying_identity" });
        } else if (eql(method, "repair.start")) {
            const account = self.state.account(try control.string(params, "account_id")) orelse return error.NotFound;
            var jobs: std.ArrayList([]const u8) = .empty;
            defer {
                for (jobs.items) |job| allocator.free(job);
                jobs.deinit(allocator);
            }
            for (account.source_ids) |source_id| {
                var possible = false;
                for (self.state.sources.items) |source| if (eql(source.id, source_id)) {
                    possible = source.kind != .browser and source.status != .disconnected and source.authorized_at <= self.now() and (source.authorized_until == null or source.authorized_until.? > self.now()) and (eql(source.provider, "github") or eql(source.provider, "codex"));
                };
                var configured = false;
                for (self.descriptions.items) |description| if (eql(description.source_id, source_id) and description.path.len != 0) {
                    configured = true;
                };
                if (possible and configured) {
                    const job = try std.fmt.allocPrint(allocator, "reconcile-{s}", .{source_id});
                    errdefer allocator.free(job);
                    try jobs.append(allocator, job);
                }
            }
            if (jobs.items.len != 0) try setup.requireResultFits(allocator, .{ .operation_id = jobs.items[0], .operation_ids = jobs.items, .status = "verifying_identity", .reconciled_sources = account.source_ids.len });
        }
    }

    fn mutationOutcomePlan(self: *Engine, allocator: std.mem.Allocator, method: []const u8, params: std.json.Value) !MutationPlan {
        // Known input is counted with the production serializer. Duplicate
        // retained label/provider fields and fixed generated handles are prepaid.
        const input_bytes = try snapshot_admission.countJson(params, storage.maximum_snapshot_bytes);
        if (eql(method, "source.connect")) {
            var path_bytes: usize = 0;
            const source_path: []const u8 = (try control.optionalString(params, "source_path")) orelse "";
            if (source_path.len == 0 and eql(try control.string(params, "kind"), "native_store") and eql(try control.string(params, "provider"), "codex")) {
                const home = if (std.c.getenv("CODEX_HOME")) |value| std.mem.span(value) else std.mem.span(std.c.getenv("HOME") orelse return error.MissingHome);
                path_bytes = try snapshot_admission.countJson(home, storage.maximum_snapshot_bytes);
            }
            const handle: [64]u8 = @splat('a');
            const fixed = try snapshot_admission.countJson(domain.Source{ .id = &handle, .kind = .native_store, .provider = "github", .authorized_at = std.math.maxInt(i64), .authorized_until = std.math.minInt(i64) }, storage.maximum_snapshot_bytes);
            return .{ .bytes = try std.math.add(usize, try std.math.mul(usize, input_bytes, 2), path_bytes + fixed + (try snapshot_admission.countJson(SourceDescription{ .source_id = &handle, .provider = "github", .path = "/.codex/auth.json" }, storage.maximum_snapshot_bytes)) + (try snapshot_admission.countJson(ImportSourceAuthority{ .source_id = @constCast(&handle), .generation = std.math.maxInt(u64) }, storage.maximum_snapshot_bytes))), .slots = .{ .sources = 1, .source_descriptions = 1 } };
        }
        if (eql(method, "source.reconcile") or eql(method, "enrollment.start") or eql(method, "repair.start")) {
            var bytes: usize = 1;
            var jobs: usize = 0;
            const single = if (!eql(method, "repair.start")) try control.string(params, "source_id") else null;
            const ids: []const []const u8 = if (single) |source_id| &.{source_id} else (self.state.account(try control.string(params, "account_id")) orelse return error.NotFound).source_ids;
            for (ids) |source_id| {
                const job_id = try std.fmt.allocPrint(allocator, "reconcile-{s}", .{source_id});
                defer allocator.free(job_id);
                bytes += (try snapshot_admission.countJson(domain.Job{ .id = job_id, .kind = .enrollment, .status = .completed, .operation_generation = std.math.maxInt(u64) }, storage.maximum_snapshot_bytes)) + 1;
                jobs += 1;
                // Admission of a nested import also records nonsecret bounded
                // provenance before I/O; its own future output is separate.
                const maximum_label: [domain.max_text_bytes]u8 = @splat(1);
                const template: OutcomeIntent = .{ .key = creditKey(.import, job_id, std.math.maxInt(u64)), .owner_id = job_id, .secondary_id = source_id, .source_id = source_id, .source_generation = std.math.maxInt(u64), .provider = "github", .label = &maximum_label, .plan_bytes = storage.maximum_snapshot_bytes };
                bytes += try snapshot_admission.countJson(template, storage.maximum_snapshot_bytes);
                bytes += (try snapshot_admission.countJson(ImportSourceAuthority{ .source_id = @constCast(source_id), .generation = std.math.maxInt(u64) }, storage.maximum_snapshot_bytes)) + 1;
            }
            return .{ .bytes = bytes + input_bytes, .slots = .{ .jobs = jobs } };
        }
        if (eql(method, "source.disconnect")) return .{ .bytes = (try domain.maintenanceGrowth(self.state.snapshot())).bytes + input_bytes };
        if (std.mem.startsWith(u8, method, "integrations.")) {
            const adapter = (try control.optionalString(params, "adapter")) orelse "codex";
            const registry: setup.RegistryWitness = .{ .phase = .pending_install, .transaction = @splat('f'), .capability_digest = @splat(1) };
            return .{ .bytes = (try snapshot_admission.countJson(adapter, storage.maximum_snapshot_bytes)) + 1 + (try snapshot_admission.countJson(registry, storage.maximum_snapshot_bytes)) + (try snapshot_admission.countJson(@as(u64, std.math.maxInt(u64)), storage.maximum_snapshot_bytes)) * self.adapter_epochs.len };
        }
        if (builtin.is_test and eql(method, "fixture.externalEffect")) return .{ .bytes = try snapshot_admission.countJson(.{ .effect = true }, storage.maximum_snapshot_bytes) };
        return error.MissingOutcomeBound;
    }

    fn snapshotBudgetReply(self: *Engine, allocator: std.mem.Allocator, id: std.json.Value) ![]u8 {
        const usage = try self.snapshotUsage();
        return control.success(allocator, id, .{ .exact_snapshot_bytes = usage.exact_snapshot_bytes, .nonledger_bytes = usage.nonledger_bytes, .reserved_bytes = usage.reserved_bytes, .credits_bytes = usage.credits_bytes, .credit_count = self.admission.credits.items.len, .credit_metadata_growth_bytes = usage.credit_metadata_growth_bytes, .maintenance_growth_bytes = usage.maintenance_growth_bytes, .maintenance_metadata_growth_bytes = usage.maintenance_metadata_growth_bytes, .native_ledger_reserved_bytes = usage.native_ledger_reserved_bytes, .counts_reserved = usage.counts_reserved, .remaining_bytes = usage.remaining_bytes });
    }

    fn saturateSnapshot(self: *Engine, spare: usize, fill_observations: bool) !void {
        const initial = try self.snapshotUsage();
        if (spare > initial.remaining_bytes) return error.InvalidParams;
        if (!fill_observations and initial.remaining_bytes - spare <= 64) return;
        var previous = self.state;
        self.state = try previous.clone(self.allocator);
        var committed = false;
        defer {
            if (committed) previous.deinit() else {
                self.state.deinit();
                self.state = previous;
            }
        }
        if (fill_observations) {
            if (self.state.accounts.items.len == 0) return error.InvalidParams;
            const account_id = self.state.accounts.items[0].id;
            const target = domain.max_records - self.admission.countsRemaining().observations;
            while (self.state.observations.items.len < target) {
                var buffer: [64]u8 = undefined;
                const target_id = try std.fmt.bufPrint(&buffer, "capacity-{d}", .{self.state.observations.items.len});
                _ = try self.state.observe(.{ .account_id = account_id, .resource = .{ .kind = "capacity-fixture", .target = target_id, .unit = .calls }, .bucket_id = target_id, .remaining = 0, .window_start = self.now(), .window_end = self.now() + 3600, .observed_at = self.now(), .expires_at = self.now() + 3600, .provenance = .fixture });
            }
        }
        const source_id = "snapshot-capacity-source";
        _ = try self.state.connectSource(.{ .id = source_id, .provider = "capacity-fixture", .kind = .explicit, .label = "Synthetic snapshot capacity" });
        self.maintenance_growth_bytes = try maintenanceReservation(self.persisted());
        var remaining = (try self.snapshotUsage()).remaining_bytes;
        if (remaining < spare) return error.InvalidParams;
        const padding: [domain.max_text_bytes]u8 = @splat(1);
        var id_buffer: [64]u8 = undefined;
        var template: domain.QuarantinedImport = .{ .source_id = source_id, .candidate_id = "capacity-00000000", .identity = .{ .provider = "capacity-fixture", .issuer = &padding, .subject = &padding, .tenant = &padding, .verified = false }, .reason = .unverified_identity };
        const maximum_cost = (try snapshot_admission.countJson(template, storage.maximum_snapshot_bytes)) + 1 - (try scalarWidening(template));
        while (remaining - spare > maximum_cost + 64) {
            template.candidate_id = try std.fmt.bufPrint(&id_buffer, "capacity-{d:0>8}", .{self.state.quarantined_imports.items.len});
            _ = try self.state.enroll(.{ .account_id = template.candidate_id, .source_id = source_id, .identity = template.identity }, self.now());
            remaining -= maximum_cost;
        }
        template.identity.issuer = "i";
        template.identity.subject = "s";
        template.identity.tenant = "";
        const minimum_cost = (try snapshot_admission.countJson(template, storage.maximum_snapshot_bytes)) + 1 - (try scalarWidening(template));
        if (remaining - spare > minimum_cost + 80) {
            var characters = @min(3 * domain.max_text_bytes, (remaining - spare - minimum_cost - 64) / 6);
            const issuer_length = @max(@as(usize, 1), @min(domain.max_text_bytes, characters));
            characters -|= issuer_length;
            const subject_length = @max(@as(usize, 1), @min(domain.max_text_bytes, characters));
            characters -|= subject_length;
            template.identity.issuer = padding[0..issuer_length];
            template.identity.subject = padding[0..subject_length];
            template.identity.tenant = padding[0..@min(domain.max_text_bytes, characters)];
            template.candidate_id = try std.fmt.bufPrint(&id_buffer, "capacity-{d:0>8}", .{self.state.quarantined_imports.items.len});
            _ = try self.state.enroll(.{ .account_id = template.candidate_id, .source_id = source_id, .identity = template.identity }, self.now());
        }
        self.maintenance_growth_bytes = try maintenanceReservation(self.persisted());
        remaining = (try self.snapshotUsage()).remaining_bytes;
        if (remaining < spare) return error.SnapshotTooLarge;
        const extra = remaining - spare;
        if (extra != 0) {
            // Refine the final few bytes with ordinary valid ASCII metadata;
            // no repeated full-envelope counting and no synthetic budget limit.
            var label: *[]const u8 = undefined;
            for (self.state.sources.items) |*source| if (eql(source.id, source_id)) {
                label = &source.label;
                break;
            };
            if (label.*.len + extra > domain.max_text_bytes) return error.FixtureCapacityFillFailed;
            const extended = try self.allocator.alloc(u8, label.*.len + extra);
            @memcpy(extended[0..label.*.len], label.*);
            @memset(extended[label.*.len..], 'c');
            self.allocator.free(label.*);
            label.* = extended;
        }
        try self.persist(&.{});
        committed = true;
        if ((try self.snapshotUsage()).remaining_bytes != spare) return error.FixtureCapacityFillFailed;
    }

    fn snapshotStoredReply(self: *Engine, allocator: std.mem.Allocator, id: std.json.Value, params: std.json.Value) ![]u8 {
        const grants = control.get(params, "grants") orelse return error.InvalidParams;
        if (grants != .array or grants.array.items.len > domain.max_list_items) return error.InvalidParams;
        var saved = try self.db.?.readSnapshot();
        defer saved.deinit();
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(saved.json, &digest, .{});
        const snapshot_hex = std.fmt.bytesToHex(digest, .lower);
        const hashes = try allocator.alloc(?[]const u8, grants.array.items.len);
        @memset(hashes, null);
        defer {
            for (hashes) |value| if (value) |hash| allocator.free(hash);
            allocator.free(hashes);
        }
        for (grants.array.items, 0..) |grant, index| {
            const account_id = try control.string(grant, "account_id");
            const grant_id = try control.string(grant, "grant_id");
            if (account_id.len == 0 or account_id.len > domain.max_text_bytes or grant_id.len == 0 or grant_id.len > domain.max_text_bytes) return error.InvalidParams;
            var statement: ?*sql_api.sqlite3_stmt = null;
            if (sql_api.sqlite3_prepare_v2(self.db.?.db, "SELECT ciphertext FROM grants WHERE account_id=?1 AND grant_id=?2;", -1, &statement, null) != sql_api.SQLITE_OK) return error.FixtureSqlFailed;
            defer _ = sql_api.sqlite3_finalize(statement.?);
            if (sql_api.sqlite3_bind_text(statement.?, 1, account_id.ptr, @intCast(account_id.len), null) != sql_api.SQLITE_OK or sql_api.sqlite3_bind_text(statement.?, 2, grant_id.ptr, @intCast(grant_id.len), null) != sql_api.SQLITE_OK) return error.FixtureSqlFailed;
            switch (sql_api.sqlite3_step(statement.?)) {
                sql_api.SQLITE_DONE => continue,
                sql_api.SQLITE_ROW => {},
                else => return error.FixtureSqlFailed,
            }
            const length = sql_api.sqlite3_column_bytes(statement.?, 0);
            if (sql_api.sqlite3_column_type(statement.?, 0) != sql_api.SQLITE_BLOB or length <= 0 or length > envelope.maximum_plaintext + 48) return error.InvalidFixtureCiphertext;
            const pointer: [*]const u8 = @ptrCast(sql_api.sqlite3_column_blob(statement.?, 0) orelse return error.InvalidFixtureCiphertext);
            std.crypto.hash.sha2.Sha256.hash(pointer[0..@intCast(length)], &digest, .{});
            const hex = std.fmt.bytesToHex(digest, .lower);
            hashes[index] = try allocator.dupe(u8, &hex);
        }
        const excluded = (try control.optionalString(params, "exclude_account_id")) orelse "";
        if (excluded.len > domain.max_text_bytes) return error.InvalidParams;
        var statement: ?*sql_api.sqlite3_stmt = null;
        if (sql_api.sqlite3_prepare_v2(self.db.?.db, "SELECT account_id FROM tombstones WHERE account_id!=?1 ORDER BY account_id;", -1, &statement, null) != sql_api.SQLITE_OK) return error.FixtureSqlFailed;
        defer _ = sql_api.sqlite3_finalize(statement.?);
        if (sql_api.sqlite3_bind_text(statement.?, 1, excluded.ptr, @intCast(excluded.len), null) != sql_api.SQLITE_OK) return error.FixtureSqlFailed;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        var count: usize = 0;
        while (true) switch (sql_api.sqlite3_step(statement.?)) {
            sql_api.SQLITE_DONE => break,
            sql_api.SQLITE_ROW => {
                const length = sql_api.sqlite3_column_bytes(statement.?, 0);
                if (sql_api.sqlite3_column_type(statement.?, 0) != sql_api.SQLITE_TEXT or length <= 0 or length > domain.max_text_bytes or count >= 16 * domain.max_records) return error.InvalidFixtureTombstone;
                const pointer: [*]const u8 = @ptrCast(sql_api.sqlite3_column_text(statement.?, 0) orelse return error.InvalidFixtureTombstone);
                var framed: [8]u8 = undefined;
                std.mem.writeInt(u64, &framed, @intCast(length), .little);
                hash.update(&framed);
                hash.update(pointer[0..@intCast(length)]);
                count += 1;
            },
            else => return error.FixtureSqlFailed,
        };
        hash.final(&digest);
        const tombstone_hex = std.fmt.bytesToHex(digest, .lower);
        return control.success(allocator, id, .{ .revision = saved.revision, .snapshot_bytes = saved.json.len, .snapshot_sha256 = snapshot_hex[0..], .ciphertext_sha256 = hashes, .tombstone_count = count, .tombstone_sha256 = tombstone_hex[0..] });
    }

    fn applicationReadiness(self: *Engine, allocator: std.mem.Allocator, request: control.Request) ![]u8 {
        if (request.params != .object) return error.InvalidParams;
        var fields = request.params.object.iterator();
        while (fields.next()) |field| if (!eql(field.key_ptr.*, "application") and !eql(field.key_ptr.*, "expected_revision") and !eql(field.key_ptr.*, "demand")) return error.InvalidParams;
        const application = std.meta.stringToEnum(application_readiness.Application, try control.string(request.params, "application")) orelse return error.UnknownAdapter;
        const expected: ?u64 = if (control.get(request.params, "expected_revision") != null) try control.expectedRevision(request.params) else null;
        const DemandInput = struct {
            provider: []const u8,
            audience: []const u8,
            issuer: ?[]const u8 = null,
            resource: domain.Resource,
            purpose: domain.Purpose = .request,
            required: f64 = 1,
            scopes: []const []const u8 = &.{},
            requires_capacity: bool = false,
        };
        var parsed: ?std.json.Parsed(DemandInput) = null;
        defer if (parsed) |*value| value.deinit();
        var scopes: ?[][]const u8 = null;
        defer if (scopes) |value| allocator.free(value);
        var demand: ?domain.Demand = null;
        var context: ?[64]u8 = null;
        if (control.get(request.params, "demand")) |value| {
            if (value != .object) return error.InvalidParams;
            var demand_fields = value.object.iterator();
            while (demand_fields.next()) |field| {
                var known = false;
                inline for (@typeInfo(DemandInput).@"struct".field_names) |name| if (eql(field.key_ptr.*, name)) {
                    known = true;
                };
                if (!known) return error.InvalidParams;
            }
            const encoded = try std.json.Stringify.valueAlloc(allocator, value, .{});
            defer allocator.free(encoded);
            if (encoded.len > 32768) return error.InvalidParams;
            // The encoded block buffer is released before projection; retain
            // every borrowed demand string in the parsed arena through reply.
            parsed = try std.json.parseFromSlice(DemandInput, allocator, encoded, .{ .allocate = .alloc_always });
            const d = parsed.?.value;
            if (d.purpose != .request or !std.math.isFinite(d.required) or d.required < 0 or d.required > 1e15 or d.scopes.len > 64) return error.InvalidParams;
            for ([_][]const u8{ d.provider, d.audience, d.resource.kind, d.resource.target, d.resource.unit_name, d.resource.scope }) |text| if (text.len > 256) return error.InvalidParams;
            if (d.issuer) |issuer| if (issuer.len > 256) return error.InvalidParams;
            scopes = try allocator.dupe([]const u8, d.scopes);
            std.mem.sort([]const u8, scopes.?, {}, struct {
                fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                    return std.mem.order(u8, a, b) == .lt;
                }
            }.lessThan);
            for (scopes.?, 0..) |scope, index| if (scope.len == 0 or scope.len > 256 or (index > 0 and eql(scope, scopes.?[index - 1]))) return error.InvalidParams;
            demand = .{ .provider = d.provider, .audience = d.audience, .issuer = d.issuer, .purpose = d.purpose, .resource = d.resource, .required = d.required, .scopes = scopes.?, .requires_capacity = d.requires_capacity, .now = self.now() };
            var normalized = d;
            normalized.scopes = scopes.?;
            const intent = try std.json.Stringify.valueAlloc(allocator, .{ .domain = "omux.application-readiness.v1", .installation = self.db.?.checkpoint.installation, .revision = self.revision, .application = application, .demand = normalized }, .{});
            defer allocator.free(intent);
            var digest: [32]u8 = undefined;
            std.crypto.auth.hmac.sha2.HmacSha256.create(&digest, intent, &self.root_key);
            context = std.fmt.bytesToHex(digest, .lower);
        }
        var custody: std.ArrayList(application_readiness.Custody) = .empty;
        defer custody.deinit(allocator);
        if (!self.poisoned and demand != null and (expected == null or expected.? == self.revision)) for (self.state.grants.items) |grant| {
            const row = (try self.db.?.readGrantStatus(grant.account_id, grant.id)) orelse continue;
            try custody.append(allocator, .{ .account_id = grant.account_id, .grant_id = grant.id, .generation = row.generation, .state = switch (row.state) {
                .ready => .ready,
                .refreshing => .refreshing,
                .quarantined => .quarantined,
            }, .renewal_owner = switch (row.renewal_owner) {
                .none => .none,
                .external => .external,
                .omux => .omux,
            } });
        };
        const readiness_report = try application_readiness.project(&self.state, .{ .application = application, .revision = self.revision, .expected_revision = expected, .context_ref = if (context) |*value| value else null, .demand = demand, .custody = custody.items, .custody_available = !self.poisoned, .adapter = .{ .application = application, .revision = self.revision, .configuration = if (self.integrationInstalled(@tagName(application))) .installed else .absent } });
        return control.success(allocator, request.id, readiness_report);
    }

    fn applicationReadinessPoisonedForTest(self: *Engine, allocator: std.mem.Allocator, request: control.Request, channel: Channel) anyerror![]u8 {
        if (!builtin.is_test) return error.TestOnly;
        if (channel != .control) return error.WrongChannel;
        const previous_poisoned = self.poisoned;
        self.poisoned = true;
        defer self.poisoned = previous_poisoned;
        const payload = try std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = request.id, .method = application_readiness.method, .params = request.params }, .{});
        defer allocator.free(payload);
        return self.execute(allocator, payload, .control);
    }

    fn handleRequest(self: *Engine, allocator: std.mem.Allocator, request: control.Request, channel: Channel) ![]u8 {
        const method = request.method;
        const params = request.params;
        if (builtin.is_test and eql(method, "fixture.measuredRuntime")) return self.measuredRuntimeFixture(allocator, request, channel);
        if (builtin.is_test and eql(method, "fixture.lifecycleMeasurementFault")) {
            if (channel != .control) return error.WrongChannel;
            if (request.params != .object or request.params.object.count() != 1) return error.InvalidParams;
            const selected = try control.string(request.params, "mode");
            self.fixture_lifecycle_fault = std.meta.stringToEnum(@TypeOf(self.fixture_lifecycle_fault), selected) orelse return error.InvalidParams;
            self.fixture_native_allocation_failed = false;
            return control.success(allocator, request.id, .{ .armed = true });
        }
        if (builtin.is_test and eql(method, "fixture.applicationReadinessPoisoned")) return self.applicationReadinessPoisonedForTest(allocator, request, channel);
        if (eql(method, application_readiness.method)) {
            if (channel != .control) return error.WrongChannel;
            return self.applicationReadiness(allocator, request);
        }
        if (builtin.is_test and std.mem.startsWith(u8, method, "fixture.snapshot")) {
            if (channel != .adapter or !eql(try self.authenticate(params), "enrollment")) return error.WrongPurpose;
            if (eql(method, "fixture.snapshotBudget")) return self.snapshotBudgetReply(allocator, request.id);
            if (eql(method, "fixture.snapshotSaturate")) {
                const spare = control.get(params, "spare_bytes") orelse return error.InvalidParams;
                if (spare != .integer or spare.integer < 0 or spare.integer > storage.maximum_snapshot_bytes) return error.InvalidParams;
                try self.saturateSnapshot(@intCast(spare.integer), try control.boolean(params, "fill_observations", false));
                return self.snapshotBudgetReply(allocator, request.id);
            }
            if (eql(method, "fixture.snapshotStored")) return self.snapshotStoredReply(allocator, request.id, params);
            return error.MethodNotFound;
        }
        if (builtin.is_test and (eql(method, "fixture.providerSubmissions") or eql(method, "fixture.pollSources"))) {
            if (channel != .adapter or !eql(try self.authenticate(params), "enrollment")) return error.WrongPurpose;
            if (eql(method, "fixture.pollSources")) {
                self.fixture_force_poll = true;
                defer self.fixture_force_poll = false;
                self.last_source_poll = 0;
                try self.pollSources();
            }
            return control.success(allocator, request.id, .{ .identity_submissions = self.fixture_identity_submissions, .observation_submissions = self.fixture_observation_submissions });
        }
        if (builtin.is_test and eql(method, "fixture.externalEffect")) {
            if (channel != .control) return error.WrongChannel;
            const fd = try paths.openPrivateRoot(self.allocator, self.state_dir, false);
            defer _ = std.c.close(fd);
            const file = std.c.openat(fd, "fixture-effect.log", .{ .ACCMODE = .WRONLY, .APPEND = true, .CREAT = true, .NOFOLLOW = true, .CLOEXEC = true }, @as(std.c.mode_t, 0o600));
            if (file < 0) return error.FixtureEffectFailed;
            defer _ = std.c.close(file);
            try paths.verifyPrivateFd(file, std.c.S.IFREG, 0o600);
            const marker = "effect\n";
            var written: usize = 0;
            while (written < marker.len) {
                const count = std.c.write(file, marker[written..].ptr, marker.len - written);
                if (count < 0 and std.posix.errno(count) == .INTR) continue;
                if (count <= 0) return error.FixtureEffectFailed;
                written += @intCast(count);
            }
            if (std.c.fsync(file) != 0) return error.FixtureEffectFailed;
            if (try control.boolean(params, "crash_after_effect", false)) std.process.exit(0);
            return control.success(allocator, request.id, .{ .effect = true });
        }
        if (builtin.is_test and eql(method, "fixture.integrationRecover")) {
            if (channel != .adapter or !eql(try self.authenticate(params), "enrollment")) return error.WrongPurpose;
            const name = try control.string(params, "adapter");
            const adapter = std.meta.stringToEnum(setup.Adapter, name) orelse return error.NativeHookRequired;
            if ((try control.optionalString(params, "config_path")) == null) return error.InvalidParams;
            const options = try self.setupOptions(allocator, adapter, params);
            defer allocator.free(options.broker_socket);
            for (self.outcome_intents.items) |intent| if (intent.key.kind == .rotation) return error.SnapshotRecoveryIndeterminate;
            const key = creditKey(.rotation, "fixture-integration-recovery", self.revision);
            try self.reserveOutcome(.{ .key = key, .owner_id = "fixture-integration-recovery", .secondary_id = try control.string(params, "config_path"), .provider = name, .plan_bytes = try integrationRecoveryGrowth() });
            try self.persist(&.{});
            const previous_credit = self.active_credit;
            self.active_credit = key;
            defer self.active_credit = previous_credit;
            errdefer {
                self.restoreCommitted() catch {
                    self.poisoned = true;
                };
                if (!self.poisoned) self.admission.markIndeterminate(key) catch {
                    self.poisoned = true;
                };
                if (!self.poisoned) self.persist(&.{}) catch {
                    self.poisoned = true;
                };
            }
            const actual = try setup.recover(self.io, allocator, options);
            if (actual == .installed and !self.integrationInstalled(name)) try self.installed.append(self.allocator, try self.allocator.dupe(u8, name));
            try self.releaseOutcome(key);
            try self.persist(&.{});
            return control.success(allocator, request.id, .{ .recovered = true, .installed = self.integrationInstalled(name) });
        }
        if (builtin.is_test and eql(method, "fixture.enroll")) {
            if (channel != .adapter) return error.WrongChannel;
            _ = try self.authenticate(params);
            return self.enrollFixture(allocator, request.id, params);
        }
        if (builtin.is_test and eql(method, "fixture.maintenanceBusy")) {
            if (channel != .adapter) return error.WrongChannel;
            if (!eql(try self.authenticate(params), "enrollment")) return error.WrongPurpose;
            const grant_id = try control.string(params, "grant_id");
            if (try control.boolean(params, "expire", false)) {
                var found = false;
                for (self.state.grants.items) |*grant| if (eql(grant.id, grant_id)) {
                    grant.custody_expires_at = self.now() - 1;
                    found = true;
                };
                if (!found) return error.NotFound;
                self.last_secret_prune = 0;
                try self.persist(&.{});
            }
            // A bounded fixture workload holds the single writer for 20ms;
            // all sixteen invocations were queued before its first execution.
            try self.io.sleep(.fromMilliseconds(20), .awake);
            const grant = self.state.grant(grant_id) orelse return error.NotFound;
            const retained = (try self.db.?.readGrantStatus(grant.account_id, grant.id)) != null;
            self.mutex.lockUncancelable(self.io);
            const backlog = self.queue_count;
            self.mutex.unlock(self.io);
            return control.success(allocator, request.id, .{ .grant_status = @tagName(grant.status), .secret_retained = retained, .backlog = backlog });
        }
        if (builtin.is_test and std.mem.startsWith(u8, method, "fixture.import")) {
            if (channel != .adapter) return error.WrongChannel;
            if (!eql(try self.authenticate(params), "enrollment")) return error.WrongPurpose;
            if (eql(method, "fixture.importStart")) {
                const reply = try self.startImportMode(allocator, request.id, params, true);
                if (try control.boolean(params, "include_operation_generation", false)) return reply;
                allocator.free(reply);
                const source_id = try control.string(params, "source_id");
                for (self.pending_imports.items) |pending| if (eql(pending.source_id, source_id) and self.importJobRunning(pending)) {
                    return control.success(allocator, request.id, .{ .operation_id = pending.job_id, .generation = pending.job_generation });
                };
                return error.NotFound;
            }
            if (eql(method, "fixture.importReconcile")) {
                const source_id = try control.string(params, "source_id");
                const operation = try self.reconcileSourceMode(source_id, true);
                if (operation == null) return control.success(allocator, request.id, .{ .operation_id = @as(?[]const u8, null), .generation = @as(?u64, null) });
                for (self.pending_imports.items) |pending| if (eql(pending.job_id, operation.?) and self.importJobRunning(pending)) {
                    return control.success(allocator, request.id, .{ .operation_id = pending.job_id, .generation = pending.job_generation });
                };
                for (self.state.jobs.items) |job| if (eql(job.id, operation.?) and job.status == .running and self.admission.lookup(creditKey(.import, job.id, job.operation_generation)) != null) {
                    return control.success(allocator, request.id, .{ .operation_id = job.id, .generation = job.operation_generation });
                };
                return error.NotFound;
            }
            if (eql(method, "fixture.importEnrollmentHold")) {
                // Actor-owned test transport hold for the ordinary control RPC;
                // neither a production parameter nor persisted authorization.
                self.fixture_hold_enrollment_start = true;
                return control.success(allocator, request.id, .{ .held = true });
            }
            if (eql(method, "fixture.importComplete")) {
                const source_id = try control.string(params, "source_id");
                const generation = control.get(params, "generation") orelse return error.InvalidParams;
                if (generation != .integer or generation.integer < 1) return error.InvalidParams;
                const response = control.get(params, "response") orelse return error.InvalidParams;
                if (response != .string or response.string.len == 0 or response.string.len > transport.Limits.response_bytes) return error.InvalidParams;
                for (self.pending_imports.items, 0..) |pending, index| if (eql(pending.source_id, source_id) and pending.job_generation == @as(u64, @intCast(generation.integer))) {
                    var held = self.pending_imports.orderedRemove(index);
                    defer held.deinit(self.allocator);
                    var completion: transport.Completion = .{ .id = held.network_id, .result = .{ .response = .{ .status = 200, .streaming = false, .body = try self.allocator.dupe(u8, response.string) } } };
                    defer completion.deinit(self.allocator);
                    self.finishImport(held, completion) catch |err| {
                        try self.failImport(held, diagnosticCause(err));
                        return control.success(allocator, request.id, .{ .admitted = false, .reason = @errorName(err) });
                    };
                    return control.success(allocator, request.id, .{ .admitted = true });
                };
                return error.NotFound;
            }
            if (eql(method, "fixture.importSource")) {
                const source_id = try control.string(params, "source_id");
                const transition = try control.string(params, "transition");
                if (eql(transition, "detach")) {
                    try self.detachImportSource(source_id);
                } else if (eql(transition, "connect")) {
                    var source: ?domain.Source = null;
                    for (self.state.sources.items) |item| if (eql(item.id, source_id)) {
                        source = item;
                        break;
                    };
                    var restored = source orelse return error.NotFound;
                    restored.status = .connected;
                    _ = try self.connectImportSource(restored);
                } else if (eql(transition, "expire")) {
                    for (self.state.sources.items) |*item| if (eql(item.id, source_id)) {
                        item.authorized_at = self.now() - 60;
                        item.authorized_until = self.now();
                    };
                } else return error.InvalidParams;
                try self.persist(&.{});
                return control.success(allocator, request.id, .{ .updated = true });
            }
            if (eql(method, "fixture.importJob")) {
                const job_id = try control.string(params, "target_operation_id");
                for (self.state.jobs.items) |*job| if (eql(job.id, job_id)) {
                    job.status = std.meta.stringToEnum(@TypeOf(job.status), try control.string(params, "status")) orelse return error.InvalidParams;
                    if (job.status == .completed or job.status == .failed) {
                        const key = creditKey(.import, job.id, job.operation_generation);
                        if (self.admission.lookup(key) != null) try self.releaseOutcome(key);
                    }
                    try self.persist(&.{});
                    return control.success(allocator, request.id, .{ .updated = true });
                };
                return error.NotFound;
            }
            if (eql(method, "fixture.importExpire")) {
                const source_id = try control.string(params, "source_id");
                const kind = try control.string(params, "kind");
                for (self.pending_imports.items) |*pending| if (eql(pending.source_id, source_id)) {
                    if (eql(kind, "provider")) pending.expires_at = self.now() else if (eql(kind, "custody")) pending.custody_expires_at = self.now() else return error.InvalidParams;
                    return control.success(allocator, request.id, .{ .expired = true });
                };
                return error.NotFound;
            }
            return error.MethodNotFound;
        }
        if (builtin.is_test and eql(method, "fixture.storageReadOnly")) {
            if (channel != .adapter) return error.WrongChannel;
            if (!eql(try self.authenticate(params), "enrollment")) return error.WrongPurpose;
            // SQLite itself denies the following writer action. This tests the
            // real commit error path without fabricating a poisoned flag or
            // copying an expected response into daemon memory.
            if (sql_api.sqlite3_exec(self.db.?.db, "PRAGMA query_only=ON", null, null, null) != sql_api.SQLITE_OK) return error.StorageFaultInjectionFailed;
            return control.success(allocator, request.id, .{ .read_only = true });
        }
        if (builtin.is_test and eql(method, "fixture.expireLease")) {
            if (channel != .adapter) return error.WrongChannel;
            _ = try self.authenticate(params);
            const native = try self.nativeLease(params);
            native.expires_at = self.now() - 86401;
            for (self.state.leases.items) |*lease| if (eql(lease.id, &native.handle)) {
                lease.expires_at = native.expires_at;
                lease.started_at = native.expires_at - 1;
            };
            try self.expireLeases();
            try self.persist(&.{});
            return control.success(allocator, request.id, .{ .expired = true });
        }
        if (builtin.is_test and eql(method, "fixture.expireGrant")) {
            if (channel != .adapter) return error.WrongChannel;
            _ = try self.authenticate(params);
            const native = try self.nativeLease(params);
            var grant_id: ?[]const u8 = null;
            for (self.state.leases.items) |lease| if (eql(lease.id, &native.handle)) {
                grant_id = lease.grant_id;
            };
            const selected = grant_id orelse return error.UnknownLease;
            for (self.state.grants.items) |*grant| if (eql(grant.id, selected)) {
                grant.custody_expires_at = self.now() - 1;
            };
            self.last_secret_prune = 0;
            try self.expireLeases();
            return control.success(allocator, request.id, .{ .expired = true });
        }
        var definition: ?control.Method = null;
        for (control.methods) |item| if (eql(item.name, method)) {
            definition = item;
            break;
        };
        if (definition == null) return error.MethodNotFound;
        if (definition.?.channel != channel and !eql(method, "system.handshake")) return error.WrongChannel;
        if (channel == .adapter and !eql(method, "system.handshake")) _ = try self.authenticate(params);
        if (eql(method, "custody.reopen")) {
            if (params != .null and (params != .object or params.object.count() != 0)) return error.InvalidParams;
            if (self.poisoned) return error.RepairRequired;
            return control.success(allocator, request.id, .{ .reopened = false, .custody_available = true, .metadata_loaded = true, .account_count = self.state.accounts.items.len, .provider_request_initiated = false, .live_handoff_proven = false });
        }
        if (eql(method, "system.handshake")) return control.success(allocator, request.id, .{
            .protocol_version = control.protocol_version,
            .service = "omuxd",
            .channel = @tagName(channel),
            .capabilities = .{ .native_launch = true, .credential_free_control = true, .custody_reopen = true, .late_codex_attachment = true, .native_hook_required = true, .live_handoff_proven = false, .enrollment_generation_reply = true },
            .custody_available = !self.poisoned,
        });
        if (eql(method, "state.snapshot") or eql(method, "events.watch") or eql(method, "accounts.list") or eql(method, "sources.list") or eql(method, "usage.summary")) return self.publicSnapshot(allocator, request.id);
        if (eql(method, "integrations.nativeRequestAudit")) {
            if (params != .object or params.object.count() != 2) return error.InvalidParams;
            const reference_value = control.get(params, "native_ref") orelse return error.NativeOwnerRequired;
            if (reference_value != .object or reference_value.object.count() != 5) return error.InvalidNativeRef;
            const reference = try parseNativeRef(params);
            const thread_id = try control.string(params, "thread_id");
            var arena: std.heap.ArenaAllocator = .init(allocator);
            defer arena.deinit();
            const result = try nativeRequestAuditResult(arena.allocator(), &self.state, &self.requests, &self.native_owners, self.outcome_intents.items, self.revision, reference, thread_id);
            _ = snapshot_admission.countJson(.{ .jsonrpc = "2.0", .id = request.id, .result = result }, 32 * 1024) catch |err| switch (err) {
                error.SnapshotTooLarge => return error.NativeResultTooLarge,
            };
            return control.success(allocator, request.id, result);
        }
        if (eql(method, "sources.catalog")) return control.success(allocator, request.id, .{
            .providers = .{
                .{ .provider = "codex", .native_store = true, .explicit_import = true, .browser_import = "needs_provider_adapter_proof", .identity_verification_required = true, .live_handoff_proven = false },
                .{ .provider = "github", .native_store = true, .explicit_import = true, .browser_import = "needs_provider_adapter_proof", .identity_verification_required = true, .live_handoff_proven = false },
                .{ .provider = "claude", .native_store = false, .explicit_import = false, .browser_import = "needs_provider_adapter_proof", .identity_verification_required = true, .live_handoff_proven = false },
            },
            .personal_sources_inspected = false,
        });
        if (eql(method, "policy.get")) return control.success(allocator, request.id, self.policy);
        if (eql(method, "setup.refresh")) {
            if (request.params == .object and request.params.object.count() != 0) return self.identifiedSetupRefresh(allocator, request, channel);
            // Selectors are captured at launch. An RPC cannot nominate paths,
            // ownership, a service or a replacement installation identity.
            if (request.params != .null and (request.params != .object or request.params.object.count() != 0)) return error.InvalidParams;
            try self.startSetupRefresh();
            return control.success(allocator, request.id, .{
                .schema_version = 1,
                .generation = self.installation_refresh_generation,
                .status = if (self.installation_refresh != null) "pending" else "installation_selection_required",
                .provider_access = false,
            });
        }
        if (eql(method, "setup.evidence")) return control.success(allocator, request.id, .{
            .schema_version = 1,
            .probe = self.currentInstallationProbe(),
            .service_observation_status = self.installation_service_status,
            .observed_at = self.installation_probe_at,
            .refresh_pending = self.installation_refresh != null,
            .generation = self.installation_refresh_generation,
            .refresh_required = self.installation_probe_at == null or self.currentInstallationProbe().artifact.freshness != .current,
            .provider_access = false,
        });
        if (eql(method, "setup.plan")) {
            const probe = self.currentInstallationProbe();
            const ownership = setup_evidence.project(probe.artifact, probe.service).ownership;
            return control.success(allocator, request.id, .{
                .schema_version = 1,
                .ownership = ownership,
                .plans = .{
                    onboarding.planSetup(ownership, .artifact),
                    onboarding.planSetup(ownership, .service_definition),
                    onboarding.planSetup(ownership, .browser_host_registration),
                    onboarding.planSetup(ownership, .native_adapter),
                },
            });
        }
        if (eql(method, "setup.readiness")) {
            const snapshot = self.setupSnapshot(self.currentInstallationProbe(), self.installation_refresh != null);
            return control.success(allocator, request.id, onboarding.assess(snapshot));
        }
        if (eql(method, "system.health")) {
            self.metrics_mutex.lockUncancelable(self.io);
            const metric_failure = self.metrics_failure;
            self.metrics_mutex.unlock(self.io);
            return control.success(allocator, request.id, .{
                .protocol_version = control.protocol_version,
                .revision = self.revision,
                .custody_available = !self.poisoned,
                .metadata_loaded = true,
                .account_count = self.state.accounts.items.len,
                .status = if (self.poisoned) "repair_required" else "ready",
                .metrics_available = !metric_failure,
                .live_handoff_proven = false,
                .request_authority = .{
                    .capacity = self.requests.capacity,
                    .remaining = self.requests.capacity - self.requests.records.items.len,
                    .snapshot_bytes_limit = request_authority.maximum_snapshot_bytes,
                    .snapshot_bytes_reserved = self.requests.reservedSnapshotBytes(),
                    .snapshot_bytes_remaining = self.requests.remainingSnapshotBytes(),
                    .retirement_supported = false,
                },
                .mutation_authority = .{
                    .capacity = self.mutations.capacity(),
                    .remaining = self.mutations.remainingCapacity(),
                    .snapshot_bytes_limit = mutation_authority.maximum_snapshot_bytes,
                    .snapshot_bytes_reserved = self.mutations.reservedSnapshotBytes(),
                    .snapshot_bytes_remaining = self.mutations.remainingSnapshotBytes(),
                    .guaranteed_admissions_remaining = self.mutations.remainingAdmissionCapacity(),
                    .retirement_supported = false,
                },
            });
        }
        if (eql(method, "reliability.lifecycle")) return control.success(allocator, request.id, .{
            .source_disconnect_timing = try lifecycle_source.summarize(allocator, self.mutations.snapshot(), self.revision, !self.poisoned),
            .native_removal_timing = try native_removal_timing.summarize(allocator, self.mutations.snapshot(), self.revision, !self.poisoned),
            .setup_verification = try setup_verification.summarize(allocator, self.mutations.snapshot(), self.now()),
            .terminal_adapter_setup = try terminal_adapter_setup.summarize(allocator, self.mutations.snapshot()),
            .terminal_removal = try terminal_removal.summarize(allocator, self.mutations.snapshot()),
            .schema_version = 1,
            .measurements = self.lifecycle_measurements,
            .scope = "terminal_source_removal_native_import_and_authorized_browser_refusal",
            .coverage = if (self.lifecycle_measurements == null) "unmeasured" else "partial",
            .latency = "partial_native_import_admission_to_terminal",
            .import_latency_scope = "admission_to_terminal_before_commit_process_local",
            .browser_refusal_timing = "unknown",
            .browser_refusal_coverage = if (self.browser_attempts == null or self.lifecycle_measurements == null) "recorder_unavailable" else if (self.browser_attempts.?.count == browser_attempt.max_records) "authority_capacity_exhausted" else "partial_authorized_context_ingress",
            .browser_refusal_authority = .{ .capacity = browser_attempt.max_records, .retained = if (self.browser_attempts) |ledger| ledger.count else 0, .retirement_supported = false },
            .achieved_slo = false,
        });
        if (eql(method, "reliability.export")) {
            self.metrics_mutex.lockUncancelable(self.io);
            defer self.metrics_mutex.unlock(self.io);
            return control.success(allocator, request.id, try self.metrics.exportSnapshot(self.now()));
        }
        if (eql(method, "operation.status")) {
            const operation_id = try control.operationId(params);
            const record = (try self.mutations.lookup(operation_id)) orelse return error.UnknownOperation;
            if (record.state == .completed) {
                const result = try std.json.parseFromSlice(std.json.Value, allocator, record.result[0..record.result_len], .{});
                defer result.deinit();
                return control.success(allocator, request.id, .{ .operation_id = operation_id, .status = @tagName(record.state), .result = result.value });
            }
            return control.success(allocator, request.id, .{ .operation_id = operation_id, .status = @tagName(record.state), .result = @as(?u8, null) });
        }
        if (eql(method, "policy.set")) {
            if (!try control.boolean(params, "sticky_routes", true)) return error.UnsupportedPolicy;
            self.policy.warm_alternatives = try control.boolean(params, "warm_alternatives", true);
            try self.persist(&.{});
            return control.success(allocator, request.id, self.policy);
        }
        if (eql(method, "source.connect")) {
            const kind_name = try control.string(params, "kind");
            const kind = std.meta.stringToEnum(domain.SourceKind, kind_name) orelse return error.InvalidParams;
            const provider = try control.string(params, "provider");
            if (!eql(provider, "github") and catalog.find(provider) == null) return error.UnknownProvider;
            var source_path: []const u8 = (try control.optionalString(params, "source_path")) orelse "";
            var default_path: ?[]u8 = null;
            defer if (default_path) |path| allocator.free(path);
            if (source_path.len == 0 and kind == .native_store and eql(provider, "codex")) {
                const home = if (std.c.getenv("CODEX_HOME")) |path| std.mem.span(path) else null;
                default_path = if (home) |path| try std.fmt.allocPrint(allocator, "{s}/auth.json", .{path}) else try std.fmt.allocPrint(allocator, "{s}/.codex/auth.json", .{std.mem.span(std.c.getenv("HOME") orelse return error.MissingHome)});
                source_path = default_path.?;
            }
            if (source_path.len > 0) try paths.validateAbsolute(source_path);
            const id = try self.identifier();
            _ = try self.connectImportSource(.{ .id = &id, .kind = kind, .provider = provider, .label = (try control.optionalString(params, "label")) orelse "", .authorized_at = self.now() });
            try self.addDescription(.{ .source_id = &id, .provider = provider, .label = (try control.optionalString(params, "label")) orelse "", .path = source_path });
            try self.persist(&.{});
            try self.publishEnrollmentCapability();
            return control.success(allocator, request.id, .{ .source_id = id[0..], .status = "authorized", .identity_admission = "verification_required" });
        }
        if (eql(method, "source.disconnect")) {
            const id = try control.string(params, "source_id");
            var changes: std.ArrayList(storage.GrantChange) = .empty;
            defer changes.deinit(allocator);
            for (self.state.grants.items) |grant| if (eql(grant.source_id, id)) try changes.append(allocator, .{ .delete = .{ .account_id = grant.account_id, .grant_id = grant.id } });
            try self.disconnectImportSource(id);
            try self.persist(changes.items);
            return control.success(allocator, request.id, .{ .disconnected = true });
        }
        if (eql(method, "source.reconcile") or eql(method, "enrollment.start")) {
            const source_id = try control.string(params, "source_id");
            // Parse before reconciliation can perform external I/O. Generation
            // is the admitted persisted job, never inferred from a later snapshot.
            const include_generation = try control.boolean(params, "include_operation_generation", false);
            // Only a newly admitted explicit enrollment may fence stranded
            // import ownership. Mutation replay returns before this dispatch.
            const operation = if (eql(method, "enrollment.start"))
                try self.reconcileSourceAuthorization(source_id, builtin.is_test and self.fixture_hold_enrollment_start, true)
            else
                try self.reconcileSource(source_id);
            return self.sourceReconcileReply(allocator, request.id, operation, include_generation);
        }
        if (eql(method, "repair.start")) {
            const account_id = try control.string(params, "account_id");
            const account = self.state.account(account_id) orelse return error.NotFound;
            // Reconciliation can replace state records. Keep only owned source
            // handles while visiting the account's already authorized sources.
            var source_ids: std.ArrayList([]const u8) = .empty;
            defer {
                for (source_ids.items) |source_id| allocator.free(source_id);
                source_ids.deinit(allocator);
            }
            try source_ids.ensureTotalCapacity(allocator, account.source_ids.len);
            for (account.source_ids) |source_id| source_ids.appendAssumeCapacity(try allocator.dupe(u8, source_id));
            var operations: std.ArrayList([]const u8) = .empty;
            defer {
                for (operations.items) |operation| allocator.free(operation);
                operations.deinit(allocator);
            }
            try operations.ensureTotalCapacity(allocator, source_ids.items.len);
            var reconciled_sources: usize = 0;
            const timestamp = self.now();
            for (source_ids.items) |source_id| {
                var authorized = false;
                for (self.state.sources.items) |source| if (eql(source.id, source_id)) {
                    authorized = source.status != .disconnected and source.authorized_at <= timestamp and (source.authorized_until == null or source.authorized_until.? > timestamp);
                    break;
                };
                if (!authorized) continue;
                const operation = self.reconcileSource(source_id) catch |err| switch (err) {
                    error.SourcePathRequired, error.NeedsProviderAdapterProof, error.SourceUnauthorized => continue,
                    else => return err,
                };
                reconciled_sources += 1;
                if (operation) |value| operations.appendAssumeCapacity(try allocator.dupe(u8, value));
            }
            if (operations.items.len > 0) return control.success(allocator, request.id, .{
                .operation_id = operations.items[0],
                .operation_ids = operations.items,
                .status = "verifying_identity",
                .reconciled_sources = reconciled_sources,
            });
            var ready_grants: usize = 0;
            for (self.state.grants.items) |grant| {
                if (!eql(grant.account_id, account_id) or grant.status != .ready or grant.credential_kind == .oauth_refresh or grant.credential_kind == .browser_bound or (grant.provider_expires_at != null and grant.provider_expires_at.? <= timestamp) or (grant.custody_expires_at != null and grant.custody_expires_at.? <= timestamp)) continue;
                var authorized = false;
                for (self.state.sources.items) |source| if (eql(source.id, grant.source_id)) {
                    authorized = source.status != .disconnected and source.authorized_at <= timestamp and (source.authorized_until == null or source.authorized_until.? > timestamp);
                    break;
                };
                if (!authorized) continue;
                const held = (try self.db.?.readGrantStatus(grant.account_id, grant.id)) orelse continue;
                if (held.state == .ready and held.generation == grant.generation) ready_grants += 1;
            }
            if (ready_grants > 0) return control.success(allocator, request.id, .{
                .operation_id = @as(?[]const u8, null),
                .status = if (reconciled_sources > 0) "reconciled" else "ready",
                .reconciled_sources = reconciled_sources,
                .ready_grants = ready_grants,
            });
            return control.success(allocator, request.id, .{
                .operation_id = @as(?[]const u8, null),
                .status = "needs_user",
                .action = "provider_authorization",
                .message = "Authorize or repair a provider source, then reconcile its independently verified credential.",
            });
        }
        if (eql(method, "operation.cancel")) {
            const id = try control.string(params, "target_operation_id");
            var found = false;
            for (self.state.jobs.items) |*job| if (eql(job.id, id)) {
                if (job.status == .running) return error.AlreadyIssued;
                if (job.status == .completed) return error.AlreadyCompleted;
                if (job.status == .pending) job.status = .failed;
                try self.retireImportCredits(job.id, job.operation_generation);
                found = true;
                break;
            };
            if (!found) return error.NotFound;
            try self.persist(&.{});
            return control.success(allocator, request.id, .{ .cancelled = true });
        }
        if (std.mem.startsWith(u8, method, "account.")) {
            const id = try control.string(params, "account_id");
            if (eql(method, "account.pause")) try self.state.pause(id, true) else if (eql(method, "account.resume")) try self.state.pause(id, false) else if (eql(method, "account.drain")) try self.state.drain(id) else if (eql(method, "account.forget")) {
                if (self.import_forget_epoch == std.math.maxInt(u64)) return error.GenerationConflict;
                try self.state.forget(id);
                try self.retireObservationCredits(null, id, null);
                self.import_forget_epoch += 1;
                try self.persist(&.{.{ .tombstone_account = id }});
                return control.success(allocator, request.id, .{ .forgotten = true });
            } else return error.MethodNotFound;
            try self.persist(&.{});
            return control.success(allocator, request.id, .{ .updated = true });
        }
        if (std.mem.startsWith(u8, method, "integrations.")) return self.publicIntegration(allocator, request.id, method, params);
        if (eql(method, "credential.import")) return self.startImport(allocator, request.id, params);
        if (eql(method, "adapter.acquire")) return self.acquire(allocator, request.id, params);
        if (eql(method, "adapter.materialize")) return self.materialize(allocator, request.id, params);
        if (eql(method, "adapter.report")) return self.report(allocator, request.id, params);
        if (eql(method, "adapter.metadata")) return self.adapterMetadata(allocator, request.id, params);
        if (eql(method, "adapter.releaseBinding")) {
            const native_ref = try self.protectedNativeRef(params, false);
            const application = try control.string(params, "application");
            if (eql(application, "enrollment")) return error.WrongPurpose;
            const session = try control.string(params, "session_id");
            const external = (try control.optionalString(params, "binding_id")) orelse session;
            const digest = bindingIdentityForOwner(application, session, external, native_ref);
            if (self.state.binding(&digest) != null) {
                const expected = (try control.optionalString(params, "expected_lease_handle")) orelse return error.BindingChanged;
                const actual = self.requests.latestHandleForBinding(application, &digest) orelse return error.BindingChanged;
                if (!eql(expected, actual)) return error.BindingChanged;
                if (native_ref) |reference| try self.state.releaseBindingExact(&digest, reference) else try self.state.releaseBinding(&digest);
            }
            try self.persist(&.{});
            return control.success(allocator, request.id, .{ .released = true });
        }
        if (eql(method, "adapter.gitGet") or eql(method, "adapter.gitErase")) return self.gitCredential(allocator, request.id, params, eql(method, "adapter.gitErase"));
        return error.MethodNotFound;
    }

    fn publicSnapshot(self: *Engine, allocator: std.mem.Allocator, id: std.json.Value) ![]u8 {
        const accounts = try allocator.alloc(PublicAccountView, self.state.accounts.items.len);
        defer allocator.free(accounts);
        for (self.state.accounts.items, accounts) |account, *view| view.* = publicAccountView(account);
        const Capacity = struct { provider: []const u8, issuer: []const u8, complete: bool, resource: domain.Resource, window_start: i64, window_end: i64, remaining: f64, limit: ?f64, buckets: usize, unknown_buckets: usize };
        var capacities: std.ArrayList(Capacity) = .empty;
        defer capacities.deinit(allocator);
        for (self.state.observations.items) |observation| {
            const account = self.state.account(observation.account_id) orelse continue;
            var seen = false;
            for (capacities.items) |row| if (eql(row.provider, account.identity.provider) and eql(row.issuer, account.identity.issuer) and row.window_start == observation.window_start and row.window_end == observation.window_end and domain.sameResource(row.resource, observation.resource)) {
                seen = true;
                break;
            };
            if (seen) continue;
            const aggregate = self.state.aggregate(account.identity.provider, account.identity.issuer, observation.resource, observation.window_start, observation.window_end, self.now());
            try capacities.append(allocator, .{ .provider = account.identity.provider, .issuer = account.identity.issuer, .complete = aggregate.complete, .resource = observation.resource, .window_start = observation.window_start, .window_end = observation.window_end, .remaining = aggregate.remaining, .limit = aggregate.limit, .buckets = aggregate.buckets, .unknown_buckets = aggregate.unknown_buckets });
        }
        return control.success(allocator, id, .{
            .protocol_version = control.protocol_version,
            .revision = self.revision,
            .captured_at = self.now(),
            .custody_available = !self.poisoned,
            .accounts = accounts,
            .sources = self.state.sources.items,
            .source_descriptions = self.descriptions.items,
            .grants = self.state.grants.items,
            .leases = self.state.leases.items,
            .bindings = self.state.bindings.items,
            .jobs = self.state.jobs.items,
            .observations = self.state.observations.items,
            .capacity = capacities.items,
            .policy = self.policy,
        });
    }

    fn executeBrowser(self: *Engine, allocator: std.mem.Allocator, payload: []const u8) ![]u8 {
        var parsed = browser.decodeRequest(allocator, payload, builtin.is_test, self.now()) catch |err| {
            if (err == error.NeedsProviderAdapterProof) {
                const refusal = self.browserIngressRefusal(allocator, payload) catch |record_error| {
                    self.restoreCommitted() catch {
                        self.poisoned = true;
                    };
                    return std.json.Stringify.valueAlloc(allocator, .{ .version = 1, .id = @as(?[]const u8, null), .@"error" = .{ .code = @errorName(record_error), .message = "Browser request was not admitted." } }, .{});
                };
                if (refusal) |reply| return reply;
            }
            return std.json.Stringify.valueAlloc(allocator, .{ .version = 1, .id = @as(?[]const u8, null), .@"error" = .{ .code = @errorName(err), .message = "Browser request was not admitted." } }, .{});
        };
        defer parsed.deinit();
        const input = parsed.validated;
        return self.handleBrowser(allocator, input) catch |err| {
            self.restoreCommitted() catch {
                self.poisoned = true;
            };
            return std.json.Stringify.valueAlloc(allocator, .{ .version = 1, .id = input.id, .@"error" = .{ .code = @errorName(err), .message = "Browser request was not admitted." } }, .{});
        };
    }

    fn prepareBrowserAttemptMeasurements(self: *Engine) !bool {
        const had_measurements = self.lifecycle_measurements != null;
        if (!had_measurements) try self.prepareImportMeasurements();
        if (self.lifecycle_measurements == null) return false;
        if (self.browser_attempts != null) return true;
        self.browser_attempts = browser_attempt.Ledger.init(self.allocator) catch return false;
        self.maintenance_growth_bytes = try maintenanceReservation(self.persisted());
        _ = self.snapshotUsage() catch |err| switch (err) {
            error.SnapshotTooLarge, error.SnapshotCardinalityExceeded => {
                self.browser_attempts.?.deinit();
                self.browser_attempts = null;
                if (!had_measurements) {
                    self.allocator.destroy(self.lifecycle_measurements.?);
                    self.lifecycle_measurements = null;
                }
                self.maintenance_growth_bytes = try maintenanceReservation(self.persisted());
                _ = try self.snapshotUsage();
                return false;
            },
            else => return err,
        };
        return true;
    }

    /// Only called after the strict browser decoder reached its capability
    /// refusal. It has already validated version, ID, method, scope/provenance
    /// and origin; production capsule fields have deliberately not been read.
    fn browserIngressRefusal(self: *Engine, allocator: std.mem.Allocator, payload: []const u8) !?[]u8 {
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, payload, .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error", .max_value_len = browser.max_message_bytes });
        defer {
            control.wipeJson(parsed.value);
            parsed.deinit();
        }
        if (!eql(try control.string(parsed.value, "method"), "browser.importGrant")) return null;
        const id = try control.string(parsed.value, "id");
        const params = control.get(parsed.value, "params") orelse return error.InvalidRequest;
        const source_id = try control.string(params, "sourceId");
        const adapter = try control.string(params, "adapter");
        const provenance = control.get(params, "provenance") orelse return error.InvalidRequest;
        const browser_name = try control.string(provenance, "browser");
        const extension = try control.string(provenance, "extensionId");
        var label_hash = std.crypto.hash.sha2.Sha256.init(.{});
        for ([_][]const u8{ browser_name, extension, source_id }) |part| {
            label_hash.update(part);
            label_hash.update("\x00");
        }
        var label_digest: [32]u8 = undefined;
        label_hash.final(&label_digest);
        const expected_label = try std.fmt.allocPrint(allocator, "browser:{s}", .{std.fmt.bytesToHex(label_digest, .lower)});
        defer allocator.free(expected_label);
        var authorized = false;
        for (self.state.sources.items) |source| if (eql(source.id, source_id) and source.kind == .browser and source.status == .connected and eql(source.provider, adapter) and eql(source.label, expected_label) and source.authorized_at <= self.now() and (source.authorized_until == null or source.authorized_until.? > self.now())) {
            authorized = true;
        };
        if (!authorized) return null;
        var generation: ?u64 = null;
        for (self.import_sources.items) |authority| if (eql(authority.source_id, source_id)) {
            generation = authority.generation;
        };
        const current_generation = generation orelse return null;
        const context = try browser_attempt.contextKey(self.root_key, .{ browser_name, extension, source_id, adapter }, current_generation);
        const intent = try browser_attempt.fingerprint(self.root_key, payload);
        if (try self.prepareBrowserAttemptMeasurements()) {
            // Both candidates remain private until the entire fact+authority
            // snapshot has passed admission and is ready for its atomic commit.
            var candidate = try browser_attempt.Ledger.fromSnapshot(self.allocator, self.browser_attempts.?.snapshot());
            var candidate_owned = true;
            defer if (candidate_owned) candidate.deinit();
            const decision = candidate.refuse(context, id, intent, .needs_provider_adapter_proof, .other) catch |err| switch (err) {
                error.BrowserAttemptCapacity => return try std.json.Stringify.valueAlloc(allocator, .{ .version = 1, .id = id, .@"error" = .{ .code = "NeedsProviderAdapterProof", .message = "Browser request was not admitted." } }, .{}),
                else => return err,
            };
            switch (decision) {
                .replay => {},
                .fresh => |slot| {
                    const measurements = try self.lifecycle_measurements.?.clone(self.allocator);
                    var measurements_owned = true;
                    defer if (measurements_owned) self.allocator.destroy(measurements);
                    try measurements.record(self.now(), .{ .operation_correlation = std.mem.readInt(u64, candidate.records[slot].intent_fingerprint[0..8], .little), .phase = .enroll, .outcome = .safe_refusal, .cause = .other });
                    self.browser_attempts.?.deinit();
                    self.browser_attempts = candidate;
                    candidate_owned = false;
                    self.allocator.destroy(self.lifecycle_measurements.?);
                    self.lifecycle_measurements = measurements;
                    measurements_owned = false;
                    try self.persist(&.{});
                },
            }
        }
        return try std.json.Stringify.valueAlloc(allocator, .{ .version = 1, .id = id, .@"error" = .{ .code = "NeedsProviderAdapterProof", .message = "Browser request was not admitted." } }, .{});
    }

    fn handleBrowser(self: *Engine, allocator: std.mem.Allocator, input: browser.Validated) ![]u8 {
        const expected: browser.Channel = if (self.instance_selection == .dev) .development else .release;
        if (input.provenance.channel != expected) return error.BrowserChannelMismatch;
        if (input.method == .health) return std.json.Stringify.valueAlloc(allocator, .{ .version = 1, .id = input.id, .result = .{ .status = if (self.poisoned) "repair_required" else "ready", .custody_available = !self.poisoned, .provider_access = false, .protocolVersion = 1, .channel = if (self.instance_selection == .dev) "development" else "release", .capabilities = .{ .source_connection = true, .production_export = false } } }, .{});
        var provenance_hash = std.crypto.hash.sha2.Sha256.init(.{});
        for ([_][]const u8{ input.provenance.browser, input.provenance.extension_id, input.source_id }) |part| {
            provenance_hash.update(part);
            provenance_hash.update("\x00");
        }
        var digest: [32]u8 = undefined;
        provenance_hash.final(&digest);
        const context_label = try std.fmt.allocPrint(allocator, "browser:{s}", .{std.fmt.bytesToHex(digest, .lower)});
        defer allocator.free(context_label);
        var source_exists = false;
        for (self.state.sources.items) |source| if (eql(source.id, input.source_id)) {
            if (source.kind != .browser or !eql(source.provider, @tagName(input.adapter)) or !eql(source.label, context_label)) return error.BrowserContextMismatch;
            source_exists = true;
        };
        if (input.method != .connect and !source_exists) return error.NotFound;
        switch (input.method) {
            .health => unreachable,
            .connect => {
                _ = try self.connectImportSource(.{ .id = input.source_id, .kind = .browser, .provider = @tagName(input.adapter), .label = context_label, .authorized_at = self.now() });
                // Bind future diagnostic ingress IDs to this explicit source
                // authorization generation, including the first connection.
                _ = try self.importSourceGeneration(input.source_id);
                try self.persist(&.{});
            },
            .disconnect => {
                var changes: std.ArrayList(storage.GrantChange) = .empty;
                defer changes.deinit(allocator);
                for (self.state.grants.items) |grant| if (eql(grant.source_id, input.source_id)) try changes.append(allocator, .{ .delete = .{ .account_id = grant.account_id, .grant_id = grant.id } });
                var exists = false;
                for (self.state.sources.items) |source| if (eql(source.id, input.source_id)) {
                    if (source.kind != .browser) return error.WrongSourceKind;
                    exists = true;
                };
                if (exists) {
                    try self.disconnectImportSource(input.source_id);
                    try self.persist(changes.items);
                }
            },
            .reconcile => {
                var found = false;
                for (self.state.sources.items) |source| if (eql(source.id, input.source_id)) {
                    found = true;
                    break;
                };
                if (!found) return error.NotFound;
            },
            .import_grant, .observation => return error.NeedsProviderAdapterProof,
        }
        return std.json.Stringify.valueAlloc(allocator, .{ .version = 1, .id = input.id, .result = .{ .accepted = true, .revision = self.revision, .source_id = input.source_id } }, .{});
    }

    fn importSourceGeneration(self: *Engine, source_id: []const u8) !u64 {
        for (self.import_sources.items) |authority| if (eql(authority.source_id, source_id)) return authority.generation;
        if (self.import_sources.items.len >= domain.max_records) return error.ServiceBusy;
        const owned = try self.allocator.dupe(u8, source_id);
        errdefer self.allocator.free(owned);
        try self.import_sources.append(self.allocator, .{ .source_id = owned });
        return 1;
    }

    fn importJobRunning(self: *const Engine, pending: PendingImport) bool {
        for (self.state.jobs.items) |job| if (eql(job.id, pending.job_id)) return job.kind == .enrollment and job.status == .running and job.operation_generation == pending.job_generation;
        return false;
    }

    fn failImportJob(self: *Engine, pending: PendingImport) !void {
        return self.failImportJobCause(pending, .other);
    }

    fn failImportJobCause(self: *Engine, pending: PendingImport, cause: reliability.Cause) !void {
        for (self.state.jobs.items) |*job| if (eql(job.id, pending.job_id) and job.operation_generation == pending.job_generation and job.status == .running) {
            const previous = job.*;
            job.status = .failed;
            try self.recordImportTerminal(pending, previous, job.*, cause);
        };
        if (self.admission.lookup(pending.credit_key) != null) try self.releaseOutcome(pending.credit_key);
    }

    fn recordImportTerminal(self: *Engine, pending: PendingImport, previous: domain.Job, next: domain.Job, cause: reliability.Cause) !void {
        const current = self.lifecycle_measurements orelse return;
        const elapsed: ?u64 = if (pending.measurement_started_at) |started| blk: {
            const raw = started.durationTo(std.Io.Clock.awake.now(self.io)).toNanoseconds();
            // A clock anomaly is missing timing, not a fabricated zero latency.
            if (raw < 0 or raw > std.math.maxInt(u64)) break :blk null;
            break :blk @intCast(raw);
        } else null;
        const prepared = reliability_commit.enrollmentTransition(self.allocator, current, previous, next, self.now(), cause, elapsed) catch |err| switch (err) {
            error.ClockAnomaly, error.CounterSaturated => {
                if (err == error.ClockAnomaly) current.clock_anomaly = true else current.saturated = true;
                return;
            },
            error.OutOfMemory => return,
            else => return err,
        };
        self.allocator.destroy(current);
        self.lifecycle_measurements = prepared.recorder;
    }

    fn prepareImportMeasurements(self: *Engine) !void {
        if (self.lifecycle_measurements != null) return;
        self.lifecycle_measurements = reliability.LifecycleRecorder.create(self.allocator, self.now(), self.metrics.stratum) catch return;
        self.maintenance_growth_bytes = try maintenanceReservation(self.persisted());
        _ = self.snapshotUsage() catch |err| switch (err) {
            error.SnapshotTooLarge, error.SnapshotCardinalityExceeded => {
                // Account operation authority takes priority over optional SLI
                // coverage. No reserved terminal outcome space is borrowed.
                self.allocator.destroy(self.lifecycle_measurements.?);
                self.lifecycle_measurements = null;
                self.maintenance_growth_bytes = try maintenanceReservation(self.persisted());
                _ = try self.snapshotUsage();
                return;
            },
            else => return err,
        };
    }

    fn retireImportCredits(self: *Engine, job_id: []const u8, through_generation: u64) !void {
        var index: usize = 0;
        while (index < self.outcome_intents.items.len) {
            const intent = self.outcome_intents.items[index];
            if (intent.key.kind == .import and eql(intent.owner_id, job_id) and intent.key.generation <= through_generation) {
                try self.releaseOutcome(intent.key);
            } else index += 1;
        }
    }

    fn retireObservationCredits(self: *Engine, source_id: ?[]const u8, account_id: ?[]const u8, grant_id: ?[]const u8) !void {
        var index: usize = 0;
        while (index < self.outcome_intents.items.len) {
            const intent = self.outcome_intents.items[index];
            const matches = intent.key.kind == .observation and
                (source_id == null or eql(intent.source_id, source_id.?)) and
                (account_id == null or eql(intent.secondary_id, account_id.?)) and
                (grant_id == null or eql(intent.owner_id, grant_id.?));
            if (matches) try self.releaseOutcome(intent.key) else index += 1;
        }
    }

    fn advanceImportSource(self: *Engine, source_id: []const u8) !void {
        for (self.import_sources.items) |*authority| if (eql(authority.source_id, source_id)) {
            if (authority.generation == std.math.maxInt(u64)) return error.GenerationConflict;
            authority.generation += 1;
            try self.retireObservationCredits(source_id, null, null);
            for (self.pending_imports.items) |pending| if (eql(pending.source_id, source_id)) try self.failImportJob(pending);
            const job_id = try std.fmt.allocPrint(self.allocator, "reconcile-{s}", .{source_id});
            defer self.allocator.free(job_id);
            for (self.state.jobs.items) |*job| if (eql(job.id, job_id)) {
                if (job.status == .running or job.status == .pending) job.status = .failed;
                try self.retireImportCredits(job_id, job.operation_generation);
            };
            return;
        };
    }

    fn connectImportSource(self: *Engine, source: domain.Source) !domain.Source {
        try self.advanceImportSource(source.id);
        return self.state.connectSource(source);
    }

    fn detachImportSource(self: *Engine, source_id: []const u8) !void {
        try self.advanceImportSource(source_id);
        try self.state.detachSource(source_id);
    }

    fn disconnectImportSource(self: *Engine, source_id: []const u8) !void {
        try self.advanceImportSource(source_id);
        try self.state.disconnectSource(source_id);
    }

    fn queueImport(self: *Engine, source_id: []const u8, provider: []const u8, token: []const u8, label: []const u8, expires_at: ?i64, custody_expires_at: ?i64, provider_account_id: ?[]const u8, credential_kind: domain.CredentialKind, allow_reenrollment: bool) ![]const u8 {
        return self.queueImportMode(source_id, provider, token, label, expires_at, custody_expires_at, provider_account_id, credential_kind, allow_reenrollment, false, false);
    }

    fn queueImportMode(self: *Engine, source_id: []const u8, provider: []const u8, token: []const u8, label: []const u8, expires_at: ?i64, custody_expires_at: ?i64, provider_account_id: ?[]const u8, credential_kind: domain.CredentialKind, allow_reenrollment: bool, fixture_hold: bool, explicit_authorization: bool) ![]const u8 {
        if (fixture_hold and !builtin.is_test) return error.TestOnly;
        if (!eql(provider, "github") and !eql(provider, "codex")) return error.NeedsProviderAdapterProof;
        if (credential_kind != .oauth_access and credential_kind != .api_key) return error.UnsupportedCredentialKind;
        if (eql(provider, "codex") and credential_kind != .oauth_access) return error.NeedsProviderAdapterProof;
        if (token.len == 0 or token.len > discovery.maximum_credential_bytes) return error.InvalidCredential;
        for (token) |byte| if (byte < 0x21 or byte > 0x7e) return error.InvalidCredential;
        if (expires_at) |expiry| if (expiry <= self.now()) return error.ExpiredCredential;
        if (custody_expires_at) |expiry| if (expiry <= self.now()) return error.InvalidCustodyLease;
        var authorized = false;
        for (self.state.sources.items) |source| if (eql(source.id, source_id) and source.status == .connected and source.kind != .browser and eql(source.provider, provider) and source.authorized_at <= self.now() and (source.authorized_until == null or source.authorized_until.? > self.now())) {
            authorized = true;
        };
        if (!authorized) return error.SourceUnauthorized;
        const source_generation = try self.importSourceGeneration(source_id);
        for (self.pending_imports.items) |pending| if (eql(pending.source_id, source_id) and pending.source_generation == source_generation and self.importJobRunning(pending) and (!allow_reenrollment or pending.allow_reenrollment) and (!pending.allow_reenrollment or pending.forget_epoch == self.import_forget_epoch)) return pending.job_id;
        const random_id = try self.identifier();
        var pending: PendingImport = .{ .network_id = 0, .source_id = try self.allocator.dupe(u8, source_id), .provider = undefined, .credential_kind = credential_kind, .allow_reenrollment = allow_reenrollment, .source_generation = source_generation, .forget_epoch = self.import_forget_epoch, .job_id = undefined, .credit_key = undefined, .token = undefined, .label = undefined, .expires_at = expires_at, .custody_expires_at = custody_expires_at };
        errdefer self.allocator.free(pending.source_id);
        pending.provider = try self.allocator.dupe(u8, provider);
        errdefer self.allocator.free(pending.provider);
        pending.job_id = try std.fmt.allocPrint(self.allocator, "reconcile-{s}", .{source_id});
        errdefer self.allocator.free(pending.job_id);
        // Missing process-local transport is uncertainty, not a cancellation.
        // Automatic reconciliation retains the original durable owner; only a
        // fresh explicit import may fence it and admit a replacement generation.
        for (self.state.jobs.items) |job| if (eql(job.id, pending.job_id) and job.status == .running) {
            var live = false;
            for (self.pending_imports.items) |previous| if (eql(previous.job_id, job.id) and previous.job_generation == job.operation_generation) {
                live = true;
            };
            if (!live and !explicit_authorization) {
                self.allocator.free(pending.source_id);
                self.allocator.free(pending.provider);
                self.allocator.free(pending.job_id);
                return job.id;
            }
        };
        if (self.pending_imports.items.len >= 16) return error.ServiceBusy;
        pending.token = try self.allocator.dupe(u8, token);
        errdefer {
            std.crypto.secureZero(u8, pending.token);
            self.allocator.free(pending.token);
        }
        pending.label = try self.allocator.dupe(u8, label);
        errdefer self.allocator.free(pending.label);
        if (provider_account_id) |hint| pending.provider_account_id = try self.allocator.dupe(u8, hint);
        errdefer if (pending.provider_account_id) |hint| {
            std.crypto.secureZero(u8, hint);
            self.allocator.free(hint);
        };
        try self.pending_imports.ensureUnusedCapacity(self.allocator, 1);
        // A fresh explicit authorization must not share a pre-forget request's
        // still-running generation, even when its source handle is unchanged.
        for (self.pending_imports.items) |previous| if (eql(previous.job_id, pending.job_id)) try self.failImportJob(previous);
        if (explicit_authorization) for (self.state.jobs.items) |*job| if (eql(job.id, pending.job_id) and job.status == .running) {
            job.status = .failed;
        };
        pending.job_generation = (try self.state.reopenJob(.{ .id = pending.job_id, .kind = .enrollment, .status = .running })).operation_generation;
        try self.retireImportCredits(pending.job_id, pending.job_generation - 1);
        pending.credit_key = creditKey(.import, pending.job_id, pending.job_generation);
        const plan = try domain.importGrowth(provider, source_id, label);
        try self.reserveOutcome(.{ .key = pending.credit_key, .owner_id = pending.job_id, .secondary_id = source_id, .source_id = source_id, .source_generation = source_generation, .provider = provider, .label = label, .plan_bytes = plan.bytes, .plan_counts = plan.counts() });
        try self.prepareImportMeasurements();
        pending.measurement_started_at = std.Io.Clock.awake.now(self.io);
        // Persist admission intent before issuing an authenticated read.
        try self.persist(&.{});
        pending.network_id = if (fixture_hold) 0 else self.submitIdentity(provider, source_id, &random_id, token, provider_account_id) catch |err| {
            try self.failImportJobCause(pending, diagnosticCause(err));
            try self.persist(&.{});
            return err;
        };
        self.pending_imports.appendAssumeCapacity(pending);
        return pending.job_id;
    }

    fn submitIdentity(self: *Engine, provider: []const u8, source_id: []const u8, grant_id: []const u8, token: []const u8, hint: ?[]const u8) !u64 {
        if (builtin.is_test) {
            self.fixture_identity_submissions += 1;
            return error.TestProviderEffectDisabled;
        }
        return self.network.?.fetchIdentity(.{ .endpoint = if (eql(provider, "codex")) .codex_identity else .github_identity, .account_id = source_id, .grant_id = grant_id, .access_token = token, .provider_account_id = hint });
    }

    fn startImport(self: *Engine, allocator: std.mem.Allocator, id: std.json.Value, params: std.json.Value) ![]u8 {
        return self.startImportMode(allocator, id, params, false);
    }

    fn startImportMode(self: *Engine, allocator: std.mem.Allocator, id: std.json.Value, params: std.json.Value, fixture_hold: bool) ![]u8 {
        const include_generation = try control.boolean(params, "include_operation_generation", false);
        if (!eql(try control.string(params, "application"), "enrollment")) return error.WrongPurpose;
        const provider = try control.string(params, "provider");
        const kind = if (try control.optionalString(params, "credential_kind")) |name| std.meta.stringToEnum(domain.CredentialKind, name) orelse return error.UnsupportedCredentialKind else if (eql(provider, "github")) domain.CredentialKind.api_key else domain.CredentialKind.oauth_access;
        const default_custody: i64 = if (kind == .api_key) 30 * 86400 else 3600;
        const seconds: i64 = if (control.get(params, "custody_seconds")) |value| switch (value) {
            .null => default_custody,
            .integer => value.integer,
            else => return error.InvalidParams,
        } else default_custody;
        if (seconds < 1 or seconds > 30 * 86400) return error.InvalidCustodyLease;
        const expiry: ?i64 = if (control.get(params, "expires_at")) |value| switch (value) {
            .null => null,
            .integer => value.integer,
            else => return error.InvalidParams,
        } else null;
        const operation = try self.queueImportMode(try control.string(params, "source_id"), provider, try control.string(params, "access_token"), (try control.optionalString(params, "label")) orelse "", expiry, self.now() + seconds, try control.optionalString(params, "provider_account_id"), kind, try control.boolean(params, "allow_reenrollment", false), fixture_hold, true);
        if (include_generation) {
            // queueImportMode persisted this exact generation before returning.
            // Do not make the client infer generation from a later snapshot.
            for (self.state.jobs.items) |job| if (eql(job.id, operation) and job.kind == .enrollment) {
                return control.success(allocator, id, .{ .operation_id = operation, .status = "verifying_identity", .operation_generation = job.operation_generation, .admitted_revision = self.revision });
            };
            return error.NotFound;
        }
        return control.success(allocator, id, .{ .operation_id = operation, .status = "verifying_identity" });
    }

    fn sourceReconcileReply(self: *Engine, allocator: std.mem.Allocator, id: std.json.Value, operation: ?[]const u8, include_generation: bool) ![]u8 {
        if (include_generation) {
            if (operation) |job_id| {
                for (self.state.jobs.items) |job| if (eql(job.id, job_id) and job.kind == .enrollment and job.operation_generation > 0) {
                    return control.success(allocator, id, .{ .operation_id = job.id, .status = "verifying_identity", .operation_generation = job.operation_generation, .admitted_revision = self.revision });
                };
                return error.NotFound;
            }
            return control.success(allocator, id, .{ .operation_id = operation, .status = "reconciled", .operation_generation = @as(?u64, null), .admitted_revision = self.revision });
        }
        return control.success(allocator, id, .{ .operation_id = operation, .status = if (operation != null) "verifying_identity" else "reconciled" });
    }

    fn reconcileSource(self: *Engine, source_id: []const u8) !?[]const u8 {
        return self.reconcileSourceMode(source_id, false);
    }

    fn reconcileSourceMode(self: *Engine, source_id: []const u8, fixture_hold: bool) !?[]const u8 {
        return self.reconcileSourceAuthorization(source_id, fixture_hold, false);
    }

    fn reconcileSourceAuthorization(self: *Engine, source_id: []const u8, fixture_hold: bool, explicit_authorization: bool) !?[]const u8 {
        if (fixture_hold and !builtin.is_test) return error.TestOnly;
        var source_value: ?domain.Source = null;
        for (self.state.sources.items) |source| if (eql(source.id, source_id)) {
            source_value = source;
            break;
        };
        var source = source_value orelse return error.NotFound;
        var description_value: ?SourceDescription = null;
        for (self.descriptions.items) |description| if (eql(description.source_id, source_id)) {
            description_value = description;
            break;
        };
        const description = description_value orelse return error.SourcePathRequired;
        if (description.path.len == 0) return error.SourcePathRequired;
        const provider = std.meta.stringToEnum(discovery.Provider, description.provider) orelse return error.NeedsProviderAdapterProof;
        var result = try discovery.reconcile(self.io, self.allocator, .{ .source = source, .provider = provider, .path = description.path }, self.now());
        defer result.deinit();
        switch (result) {
            .detached => {
                try self.detachImportSource(source_id);
                try self.persist(&.{});
                return null;
            },
            .candidate => |candidate| {
                if (source.status == .detached) {
                    var restored = source;
                    restored.status = .connected;
                    // Replacing a source frees all borrowed strings in its old
                    // record. Continue with the owned replacement, including
                    // its label, provider and ID, rather than the old snapshot.
                    source = try self.connectImportSource(restored);
                    try self.persist(&.{});
                }
                // Polling may reuse identical usable custody. A fresh explicit
                // enrollment needs an admitted identity-verification generation.
                if (!explicit_authorization) for (self.state.grants.items) |grant| if (eql(grant.source_id, source_id) and grant.status == .ready) {
                    var secret = self.db.?.loadGrant(.{ .key_id = self.root_id.?, .account_id = grant.account_id, .grant_id = grant.id, .generation = grant.generation, .purpose = "request", .scope = grant.audience }) catch continue;
                    defer secret.deinit();
                    const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, secret.bytes, .{ .allocate = .alloc_always });
                    defer {
                        control.wipeJson(parsed.value);
                        parsed.deinit();
                    }
                    const previous = try control.string(parsed.value, "access_token");
                    const previous_hint = try control.optionalString(parsed.value, "provider_account_id");
                    const same_hint = if (previous_hint) |hint| if (candidate.provider_account_id) |next| eql(hint, next) else false else candidate.provider_account_id == null;
                    const same_provider_expiry = if (candidate.expires_at_limit) |limit| if (grant.provider_expires_at) |retained| retained <= limit else false else true;
                    const same_custody_ceiling = if (grant.custody_expires_at) |retained| retained <= candidate.custody_expires_at else false;
                    if (eql(previous, candidate.access_token) and same_hint and grant.credential_kind == candidate.credential_kind and same_provider_expiry and same_custody_ceiling and (grant.custody_expires_at == null or grant.custody_expires_at.? > self.now() + 300)) return null;
                };
                return try self.queueImportMode(source_id, @tagName(candidate.provider), candidate.access_token, source.label, candidate.expires_at_limit, candidate.custody_expires_at, candidate.provider_account_id, candidate.credential_kind, false, fixture_hold, explicit_authorization);
            },
        }
    }

    fn pollSources(self: *Engine) !void {
        if (!self.policy.warm_alternatives and !(builtin.is_test and self.fixture_force_poll)) return;
        if (self.now() - self.last_source_poll < 60) return;
        self.last_source_poll = self.now();
        var source_ids: std.ArrayList([]const u8) = .empty;
        defer {
            for (source_ids.items) |id| self.allocator.free(id);
            source_ids.deinit(self.allocator);
        }
        for (self.descriptions.items) |description| if (description.path.len != 0) {
            const id = try self.allocator.dupe(u8, description.source_id);
            errdefer self.allocator.free(id);
            try source_ids.append(self.allocator, id);
        };
        for (source_ids.items) |source_id| {
            _ = self.reconcileSource(source_id) catch |err| {
                if (err == error.OutOfMemory or self.poisoned) return err;
                try self.restoreCommitted();
                // A malformed/unavailable source cannot poison other accounts.
                continue;
            };
        }
        self.observers.prune(&self.state, self.now());
        if (self.state.pruneObservations(self.now()) > 0) try self.persist(&.{});
        var grant_ids: std.ArrayList([]const u8) = .empty;
        defer {
            for (grant_ids.items) |id| self.allocator.free(id);
            grant_ids.deinit(self.allocator);
        }
        for (self.state.grants.items) |grant| {
            const id = try self.allocator.dupe(u8, grant.id);
            errdefer self.allocator.free(id);
            try grant_ids.append(self.allocator, id);
        }
        for (grant_ids.items) |grant_id| {
            const grant = self.state.grant(grant_id) orelse continue;
            const github_eligible = observer.githubCapacityEligible(&self.state, grant, self.now());
            const codex_eligible = observer.codexCapacityEligible(&self.state, grant, self.now());
            if ((!github_eligible and !codex_eligible) or !self.observers.due(grant.account_id, self.now())) continue;
            var secret = self.db.?.loadGrant(.{ .key_id = self.root_id.?, .account_id = grant.account_id, .grant_id = grant.id, .generation = grant.generation, .purpose = "request", .scope = grant.audience }) catch continue;
            defer secret.deinit();
            const parsed = try std.json.parseFromSlice(std.json.Value, self.allocator, secret.bytes, .{ .allocate = .alloc_always });
            defer {
                control.wipeJson(parsed.value);
                parsed.deinit();
            }
            const provider = if (codex_eligible) "codex" else "github";
            const plan = try domain.observationGrowth(provider, grant.account_id);
            const key = creditKey(.observation, grant.id, self.revision);
            const source_generation = try self.importSourceGeneration(grant.source_id);
            try self.observation_credits.ensureUnusedCapacity(self.allocator, 1);
            self.reserveOutcome(.{ .key = key, .owner_id = grant.id, .secondary_id = grant.account_id, .source_id = grant.source_id, .source_generation = source_generation, .provider = provider, .grant_generation = grant.generation, .plan_bytes = plan.bytes, .plan_counts = plan.counts() }) catch |err| {
                try self.restoreCommitted();
                if (err == error.SnapshotTooLarge or err == error.SnapshotCardinalityExceeded) continue;
                return err;
            };
            self.persist(&.{}) catch |err| {
                try self.restoreCommitted();
                if (err == error.SnapshotTooLarge or err == error.SnapshotCardinalityExceeded) continue;
                return err;
            };
            if (builtin.is_test) {
                self.fixture_observation_submissions += 1;
                try self.releaseOutcome(key);
                try self.persist(&.{});
                continue;
            }
            const operation = if (codex_eligible) self.observers.submitCodexUsage(self.network.?, grant, try control.string(parsed.value, "access_token"), try control.optionalString(parsed.value, "provider_account_id"), self.now()) else self.observers.submitGithubCapacity(self.network.?, grant, try control.string(parsed.value, "access_token"), self.now());
            const network_id = operation catch |err| {
                // No admitted coordinator/transport completion can use this
                // intent after submission failed. Removal is the durable fence.
                try self.releaseOutcome(key);
                try self.persist(&.{});
                switch (err) {
                    error.PollTooSoon, error.PollBackpressure, error.AlreadyPolling, error.GrantExpired, error.GrantNotReady => continue,
                    else => return err,
                }
            };
            self.observation_credits.appendAssumeCapacity(.{ .network_id = network_id, .key = key });
        }
    }

    fn pollNetwork(self: *Engine) !void {
        const client = self.network orelse return;
        while (client.poll()) |value| {
            var completion = value;
            defer completion.deinit(self.allocator);
            var index: ?usize = null;
            for (self.pending_imports.items, 0..) |pending, i| if (pending.network_id == completion.id) {
                index = i;
                break;
            };
            const i = index orelse {
                var held: ?snapshot_admission.Key = null;
                for (self.observation_credits.items, 0..) |credit, credit_index| if (credit.network_id == completion.id) {
                    held = self.observation_credits.orderedRemove(credit_index).key;
                    break;
                };
                if (held) |key| {
                    if (self.admission.lookup(key) != null) {
                        const used = self.observers.take(&completion, &self.state, self.now()) catch |err| {
                            try self.restoreCommitted();
                            try self.admission.markIndeterminate(key);
                            try self.persist(&.{});
                            return err;
                        };
                        if (!used) return error.InvalidSnapshotCreditAuthority;
                        try self.releaseOutcome(key);
                        try self.persist(&.{});
                        continue;
                    }
                }
                // A durable source/grant cancellation can retire the intent
                // while transport is still completing. Drain coordinator state
                // against an empty model so it cannot mutate the real account.
                var inert = domain.State.init(self.allocator);
                defer inert.deinit();
                _ = try self.observers.take(&completion, &inert, self.now());
                continue;
            };
            var pending = self.pending_imports.orderedRemove(i);
            defer pending.deinit(self.allocator);
            self.finishImport(pending, completion) catch |err| {
                try self.failImport(pending, diagnosticCause(err));
            };
        }
    }

    fn failImport(self: *Engine, pending: PendingImport, cause: reliability.Cause) !void {
        try self.restoreCommitted();
        // A retired read may complete after a new generation has been issued.
        // Its failure cannot invalidate that newer durable operation.
        if (!self.importJobRunning(pending)) return;
        try self.failImportJobCause(pending, cause);
        try self.persist(&.{});
    }

    fn finishImport(self: *Engine, pending: PendingImport, completion: transport.Completion) !void {
        if (completion.id != pending.network_id or !self.importJobRunning(pending)) return error.ImportSuperseded;
        var authorized = false;
        const timestamp = self.now();
        for (self.import_sources.items) |authority| if (eql(authority.source_id, pending.source_id) and authority.generation == pending.source_generation) {
            for (self.state.sources.items) |source| if (eql(source.id, pending.source_id) and source.kind != .browser and source.status == .connected and eql(source.provider, pending.provider) and source.authorized_at <= timestamp and (source.authorized_until == null or source.authorized_until.? > timestamp)) {
                authorized = true;
            };
        };
        if (!authorized) return error.SourceUnauthorized;
        if (pending.expires_at) |expiry| if (expiry <= timestamp) return error.ExpiredCredential;
        if (pending.custody_expires_at) |expiry| if (expiry <= timestamp) return error.InvalidCustodyLease;
        // Re-enrollment permission belongs to this admission, not to future
        // tombstones created while the authenticated identity read was pending.
        if (pending.allow_reenrollment and pending.forget_epoch != self.import_forget_epoch) return error.ImportSuperseded;
        const response = switch (completion.result) {
            .response => |value| value,
            .failure => return error.ProviderUnavailable,
        };
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        defer arena.deinit();
        const scratch = arena.allocator();
        const Proof = struct { subject: []const u8, tenant: []const u8, issuer: []const u8, kind: []const u8, username: ?[]const u8 = null, provider_account_id: ?[]const u8 = null };
        const proof: Proof = if (eql(pending.provider, "github")) blk: {
            const parsed = try response.githubIdentity(scratch);
            break :blk .{ .subject = try std.fmt.allocPrint(scratch, "{d}", .{parsed.value.id}), .tenant = "", .issuer = "https://github.com", .kind = parsed.value.type, .username = parsed.value.login };
        } else blk: {
            const parsed = try response.codexIdentity(scratch);
            if (!parsed.value.matchesHint(pending.provider_account_id)) return error.IdentityMismatch;
            break :blk .{ .subject = parsed.value.user_id, .tenant = parsed.value.account_id, .issuer = "https://chatgpt.com", .kind = parsed.value.plan_type, .provider_account_id = parsed.value.account_id };
        };
        const identity: domain.Identity = .{ .provider = pending.provider, .issuer = proof.issuer, .subject = proof.subject, .tenant = proof.tenant, .verified = true };
        if (pending.allow_reenrollment) try self.state.permitReenrollment(identity, pending.source_id, self.now());
        const opaque_id = try self.identifier();
        const enrollment = try self.state.enroll(.{ .account_id = &opaque_id, .source_id = pending.source_id, .identity = identity, .label = if (pending.label.len != 0) pending.label else if (eql(pending.provider, "github")) "GitHub account" else "Codex account", .account_type = proof.kind }, self.now());
        const account_id = enrollment.account_id orelse return error.IdentityNotAdmitted;
        const random_grant = try self.identifier();
        var grant_id: []const u8 = &random_grant;
        for (self.state.grants.items) |grant| if (eql(grant.account_id, account_id) and eql(grant.source_id, pending.source_id) and grant.credential_kind == pending.credential_kind and eql(grant.audience, proof.issuer)) {
            grant_id = grant.id;
            break;
        };
        // Stabilize IDs because a rotated domain grant frees its old record.
        const owned_grant = try self.allocator.dupe(u8, grant_id);
        defer self.allocator.free(owned_grant);
        const generation = try self.db.?.nextGeneration(account_id, owned_grant);
        try self.retireObservationCredits(null, null, owned_grant);
        _ = try self.state.addGrant(.{ .id = owned_grant, .account_id = account_id, .source_id = pending.source_id, .credential_kind = pending.credential_kind, .ownership = .external, .purposes = &.{ .request, .account_read }, .audience = proof.issuer, .provider_expires_at = pending.expires_at, .custody_expires_at = pending.custody_expires_at, .generation = generation });
        if (eql(pending.provider, "codex")) _ = try observer.observeCodexUsage(&self.state, self.state.grant(owned_grant).?, response, self.now());
        const credential = try std.json.Stringify.valueAlloc(self.allocator, .{ .access_token = pending.token, .username = proof.username, .provider_account_id = proof.provider_account_id }, .{});
        defer {
            std.crypto.secureZero(u8, credential);
            self.allocator.free(credential);
        }
        for (self.state.jobs.items) |*job| if (eql(job.id, pending.job_id) and job.operation_generation == pending.job_generation and job.status == .running) {
            const previous = job.*;
            job.status = .completed;
            try self.recordImportTerminal(pending, previous, job.*, .none);
        };
        try self.releaseOutcome(pending.credit_key);
        try self.persist(&.{.{ .put = .{ .context = .{ .key_id = self.root_id.?, .account_id = account_id, .grant_id = owned_grant, .generation = generation, .purpose = "request", .scope = proof.issuer }, .plaintext = credential, .renewal_owner = .external } }});
    }

    fn acquire(self: *Engine, allocator: std.mem.Allocator, id: std.json.Value, params: std.json.Value) ![]u8 {
        const native_ref = try self.protectedNativeRef(params, true);
        try self.expireLeases();
        const application = try control.string(params, "application");
        const session_id = try control.string(params, "session_id");
        const request_id = try control.requestId(params);
        const external_binding = (try control.optionalString(params, "binding_id")) orelse session_id;
        const binding_digest = bindingIdentityForOwner(application, session_id, external_binding, native_ref);
        const binding_id: []const u8 = &binding_digest;
        const input = control.get(params, "demand") orelse return error.InvalidParams;
        const encoded = try std.json.Stringify.valueAlloc(allocator, input, .{});
        defer allocator.free(encoded);
        const DemandInput = struct { provider: []const u8, audience: []const u8, purpose: domain.Purpose = .request, resource: domain.Resource, required: f64 = 1, scopes: []const []const u8 = &.{} };
        const parsed = try std.json.parseFromSlice(DemandInput, allocator, encoded, .{});
        defer parsed.deinit();
        const d = parsed.value;
        if (eql(application, "enrollment") or d.purpose != .request) return error.WrongPurpose;
        if ((eql(application, "codex") and (!eql(d.provider, "codex") or !eql(d.audience, "https://chatgpt.com") or !eql(d.resource.kind, "model"))) or (eql(application, "git") and (!eql(d.provider, "github") or !eql(d.audience, "https://github.com"))) or (eql(application, "claude") and !eql(d.provider, "claude"))) return error.WrongPurpose;
        // A typed representation normalizes field order and default values.
        // Scope order does not affect authority, but duplicate scopes are
        // malformed instead of silently changing the declared demand.
        const scopes = try allocator.dupe([]const u8, d.scopes);
        defer allocator.free(scopes);
        std.mem.sort([]const u8, scopes, {}, struct {
            fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.order(u8, a, b) == .lt;
            }
        }.lessThan);
        for (scopes, 0..) |scope, index| if (index != 0 and eql(scope, scopes[index - 1])) return error.InvalidParams;
        var normalized = d;
        normalized.scopes = scopes;
        const normalized_bytes = try std.json.Stringify.valueAlloc(allocator, normalized, .{});
        defer allocator.free(normalized_bytes);
        var fingerprint_bytes: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(normalized_bytes, &fingerprint_bytes, .{});
        const fingerprint = std.fmt.bytesToHex(fingerprint_bytes, .lower);
        const intent: request_authority.Intent = .{ .key = .{ .application = application, .session_id = session_id, .request_id = request_id }, .binding_id = binding_id, .demand_fingerprint = &fingerprint, .native_ref = native_ref };
        const attempt = try self.requests.checkIssue(intent);
        const rejected_account = try self.requests.rejectedAccount(intent);
        if (self.native_leases.items.len >= 4096) return error.ServiceBusy;
        var allowed: std.ArrayList([]const u8) = .empty;
        defer allowed.deinit(allocator);
        for (self.state.accounts.items) |account| {
            const rejected = if (rejected_account) |prior| eql(prior, account.id) else false;
            if (!rejected) try allowed.append(allocator, account.id);
        }
        if (allowed.items.len == 0) return error.NoReadyAccount;
        const demand: domain.Demand = .{ .allowed_account_ids = allowed.items, .provider = d.provider, .audience = d.audience, .purpose = d.purpose, .resource = d.resource, .required = d.required, .scopes = d.scopes, .now = self.now() };
        const previous = self.state.binding(binding_id);
        const selected = try self.state.select(demand, if (previous != null) binding_id else null);
        const grant = self.state.grant(selected.grant_id).?;
        const custody = (try self.db.?.readGrantStatus(grant.account_id, grant.id)) orelse return error.GrantNotReady;
        if (custody.state != .ready or custody.generation != grant.generation) return error.GrantNotReady;
        const route_generation = if (previous) |old| old.route_generation + @as(u64, @intFromBool(!eql(old.grant_id, grant.id) or old.grant_generation != grant.generation)) else 1;
        if (previous == null or !selected.sticky) _ = try self.state.bind(.{ .id = binding_id, .application = application, .session_id = session_id, .account_id = grant.account_id, .grant_id = grant.id, .grant_generation = grant.generation, .route_generation = route_generation, .native_ref = native_ref });
        const handle = try self.identifier();
        var expires = self.now() + 300;
        if (grant.provider_expires_at) |expiry| expires = @min(expires, expiry);
        if (grant.custody_expires_at) |expiry| expires = @min(expires, expiry);
        for (self.state.sources.items) |source| if (eql(source.id, grant.source_id)) {
            if (source.authorized_until) |expiry| expires = @min(expires, expiry);
        };
        const held_lease: domain.Lease = .{ .id = &handle, .binding_id = binding_id, .account_id = grant.account_id, .grant_id = grant.id, .grant_generation = grant.generation, .route_generation = route_generation, .purpose = d.purpose, .audience = d.audience, .scopes = d.scopes, .resource = d.resource, .required = d.required, .started_at = self.now(), .expires_at = expires, .native_ref = native_ref };
        const report_plan = try domain.reportGrowth(held_lease);
        _ = try self.state.beginLease(held_lease, self.now());
        var record = try NativeLease.create(self.allocator, handle, application, request_id, binding_id, grant.account_id, encoded, attempt, expires, native_ref);
        var committed = false;
        errdefer if (!committed) record.deinit(self.allocator);
        try self.native_leases.append(self.allocator, record);
        errdefer if (!committed) {
            _ = self.native_leases.pop();
        };
        _ = try self.requests.issue(intent, &handle, grant.account_id, expires);
        const issued = self.requests.attempt(application, &handle) orelse return error.UnknownLease;
        const key = creditKey(.request, &handle, issued.issued_sequence);
        try self.reserveOutcome(.{ .key = key, .owner_id = &handle, .secondary_id = grant.account_id, .source_id = grant.source_id, .grant_generation = grant.generation, .plan_bytes = report_plan.bytes, .plan_counts = report_plan.counts() });
        try self.persist(&.{});
        committed = true;
        return control.success(allocator, id, .{ .lease_handle = handle[0..], .account_id = grant.account_id, .grant_id = grant.id, .generation = grant.generation, .route_generation = route_generation, .expires_at = expires });
    }

    fn adapterMetadata(self: *Engine, allocator: std.mem.Allocator, id: std.json.Value, params: std.json.Value) ![]u8 {
        const native_ref = try self.protectedNativeRef(params, false);
        const application = try control.string(params, "application");
        if (eql(application, "enrollment")) return error.WrongPurpose;
        const session = try control.string(params, "session_id");
        const external = (try control.optionalString(params, "binding_id")) orelse session;
        const digest = bindingIdentityForOwner(application, session, external, native_ref);
        const binding = self.state.binding(&digest) orelse return control.success(allocator, id, .{ .bound = false, .custody_available = !self.poisoned });
        const account = self.state.account(binding.account_id) orelse return error.NotFound;
        const grant = self.state.grant(binding.grant_id) orelse return error.GrantNotReady;
        return control.success(allocator, id, .{
            .bound = true,
            .binding_id = binding.id,
            .account_id = account.id,
            .account_label = account.label,
            .account_type = account.account_type,
            .provider = account.identity.provider,
            .grant_id = grant.id,
            .generation = binding.grant_generation,
            .route_generation = binding.route_generation,
            .lifecycle = account.lifecycle,
            .grant_status = grant.status,
            .provider_expires_at = grant.provider_expires_at,
            .custody_expires_at = grant.custody_expires_at,
            .custody_available = !self.poisoned,
        });
    }

    fn nativeLease(self: *Engine, params: std.json.Value) !*NativeLease {
        const native_ref = try self.protectedNativeRef(params, false);
        const supplied = try control.string(params, "lease_handle");
        const application = try control.string(params, "application");
        if (supplied.len != 64) return error.Unauthorized;
        for (self.native_leases.items) |*lease| if (eql(lease.application, application) and std.crypto.timing_safe.eql([64]u8, supplied[0..64].*, lease.handle)) {
            if (!sameOptionalNativeRef(lease.native_ref, native_ref)) return error.NativeOwnerMismatch;
            return lease;
        };
        return error.UnknownLease;
    }

    fn expireLeases(self: *Engine) !void {
        var i: usize = 0;
        var changed = false;
        while (i < self.native_leases.items.len) {
            const record = self.native_leases.items[i];
            // A capability deadline is not evidence that native work ended.
            // Even issued work may have been accepted before a lost report.
            // Retire only handles whose authenticated terminal event already
            // released the domain lease; all uncertain work remains fenced.
            if (record.expires_at <= self.now() and (record.status == .completed or record.status == .rejected or record.status == .abandoned)) {
                var removed = self.native_leases.orderedRemove(i);
                removed.deinit(self.allocator);
            } else i += 1;
        }
        var expired_grants: std.ArrayList(storage.GrantChange) = .empty;
        defer expired_grants.deinit(self.allocator);
        const timestamp = self.now();
        if (self.last_secret_prune != timestamp) for (self.state.grants.items) |*grant| {
            var source_expired = false;
            for (self.state.sources.items) |source| if (eql(source.id, grant.source_id)) {
                source_expired = source.authorized_until != null and source.authorized_until.? <= timestamp;
            };
            if (source_expired or (grant.provider_expires_at != null and grant.provider_expires_at.? <= timestamp) or (grant.custody_expires_at != null and grant.custody_expires_at.? <= timestamp)) {
                _ = (try self.db.?.readGrantStatus(grant.account_id, grant.id)) orelse continue;
                try expired_grants.append(self.allocator, .{ .delete = .{ .account_id = grant.account_id, .grant_id = grant.id } });
                grant.status = .invalid;
                changed = true;
            }
        };
        if (changed) try self.persist(expired_grants.items);
        self.last_secret_prune = timestamp;
    }

    fn publishEnrollmentCapability(self: *Engine) !void {
        const directory = try std.fmt.allocPrint(self.allocator, "{s}/integrations", .{self.state_dir});
        defer self.allocator.free(directory);
        const fd = try paths.openPrivateRoot(self.allocator, directory, true);
        defer _ = std.c.close(fd);
        var token = try self.capability("enrollment");
        defer std.crypto.secureZero(u8, &token);
        const existing: ?[]u8 = paths.readCapability(self.allocator, self.state_dir, "enrollment") catch |err| switch (err) {
            error.AdapterNotInstalled => null,
            else => return err,
        };
        if (existing) |value| {
            defer {
                std.crypto.secureZero(u8, value);
                self.allocator.free(value);
            }
            if (!std.crypto.timing_safe.eql([64]u8, value[0..64].*, token)) return error.InvalidAdapterCapability;
            return;
        }
        // The fixed private scratch name can only be a preceding interrupted
        // publication. Validate it before cleanup; never replace a final file.
        const pending_name = "enrollment.capability.pending";
        const stale = std.c.openat(fd, pending_name, .{ .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true });
        if (stale >= 0) {
            defer _ = std.c.close(stale);
            try paths.verifyPrivateFd(stale, std.c.S.IFREG, 0o600);
            if (std.c.unlinkat(fd, pending_name, 0) != 0) return error.CapabilityWriteFailed;
        } else if (std.posix.errno(stale) != .NOENT) return error.CapabilityWriteFailed;
        const file = std.c.openat(fd, pending_name, .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true, .NOFOLLOW = true, .CLOEXEC = true }, @as(std.c.mode_t, 0o600));
        if (file < 0) return error.CapabilityWriteFailed;
        defer _ = std.c.close(file);
        defer _ = std.c.unlinkat(fd, pending_name, 0);
        var written: usize = 0;
        while (written < token.len) {
            const count = std.c.write(file, token[written..].ptr, token.len - written);
            if (count < 0 and std.posix.errno(count) == .INTR) continue;
            if (count <= 0) return error.CapabilityWriteFailed;
            written += @intCast(count);
        }
        if (std.c.fsync(file) != 0) return error.CapabilityWriteFailed;
        // linkat publishes the complete fsynced inode without replacing any
        // existing capability. A crash leaves the final path absent or complete.
        if (std.c.linkat(fd, pending_name, fd, "enrollment.capability", 0) != 0) return error.CapabilityWriteFailed;
        if (std.c.unlinkat(fd, pending_name, 0) != 0 or std.c.fsync(fd) != 0) return error.CapabilityWriteFailed;
    }

    fn enrollFixture(self: *Engine, allocator: std.mem.Allocator, id: std.json.Value, params: std.json.Value) ![]u8 {
        if (!builtin.is_test) return error.TestOnly;
        if (!eql(try control.string(params, "application"), "enrollment")) return error.WrongPurpose;
        const account = try self.identifier();
        const provider = try control.string(params, "provider");
        const audience = try control.string(params, "audience");
        const result = try self.state.enroll(.{ .account_id = &account, .source_id = try control.string(params, "source_id"), .identity = .{ .provider = provider, .issuer = audience, .subject = try control.string(params, "subject"), .verified = true }, .label = (try control.optionalString(params, "label")) orelse "Fixture", .account_type = "fixture" }, self.now());
        const account_id = result.account_id orelse return control.success(allocator, id, .{ .status = @tagName(result.status) });
        const grant_id = try self.identifier();
        const generation = try self.db.?.nextGeneration(account_id, &grant_id);
        _ = try self.state.addGrant(.{ .id = &grant_id, .account_id = account_id, .source_id = try control.string(params, "source_id"), .credential_kind = .oauth_access, .ownership = .external, .purposes = &.{ .request, .account_read }, .audience = audience, .generation = generation });
        const secret = try std.json.Stringify.valueAlloc(allocator, .{ .access_token = try control.string(params, "access_token"), .provider_account_id = try control.optionalString(params, "provider_account_id"), .username = try control.optionalString(params, "username") }, .{});
        defer {
            std.crypto.secureZero(u8, secret);
            allocator.free(secret);
        }
        try self.persist(&.{.{ .put = .{ .context = .{ .key_id = self.root_id.?, .account_id = account_id, .grant_id = &grant_id, .generation = generation, .purpose = "request", .scope = audience }, .plaintext = secret, .renewal_owner = .external } }});
        return control.success(allocator, id, .{ .status = @tagName(result.status), .account_id = account_id, .grant_id = grant_id[0..], .generation = generation });
    }

    fn materialize(self: *Engine, allocator: std.mem.Allocator, id: std.json.Value, params: std.json.Value) ![]u8 {
        _ = try self.protectedNativeRef(params, true);
        const native = try self.nativeLease(params);
        if (native.status != .issued) return error.LeaseNotMaterializable;
        var lease: ?domain.Lease = null;
        for (self.state.leases.items) |item| if (eql(item.id, &native.handle)) {
            lease = item;
            break;
        };
        const held = lease orelse return error.UnknownLease;
        if (held.expires_at <= self.now()) return error.LeaseExpired;
        const grant = self.state.grant(held.grant_id) orelse return error.GrantNotReady;
        if (held.purpose != .request or !eql(held.audience, grant.audience)) return error.WrongPurpose;
        _ = self.state.account(held.account_id) orelse return error.GrantNotReady;
        for (self.state.sources.items) |source| if (eql(source.id, grant.source_id)) {
            if (source.status == .disconnected or (source.authorized_until != null and source.authorized_until.? <= self.now())) return error.SourceUnauthorized;
        };
        if (grant.generation != held.grant_generation or grant.status != .ready) return error.GenerationConflict;
        var secret = try self.db.?.loadGrant(.{ .key_id = self.root_id.?, .account_id = grant.account_id, .grant_id = grant.id, .generation = grant.generation, .purpose = "request", .scope = grant.audience });
        defer secret.deinit();
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, secret.bytes, .{ .allocate = .alloc_always });
        defer {
            control.wipeJson(parsed.value);
            parsed.deinit();
        }
        return control.success(allocator, id, .{ .access_token = try control.string(parsed.value, "access_token"), .provider_account_id = try control.optionalString(parsed.value, "provider_account_id"), .expires_at = held.expires_at, .route_generation = held.route_generation });
    }

    fn report(self: *Engine, allocator: std.mem.Allocator, id: std.json.Value, params: std.json.Value) ![]u8 {
        const native_ref = try self.protectedNativeRef(params, false);
        const event = try control.string(params, "event");
        const application = try control.string(params, "application");
        const handle = try control.string(params, "lease_handle");
        const status_value = control.get(params, "status");
        const reported_status: u16 = if (status_value) |value| blk: {
            if (value != .integer or value.integer < 0 or value.integer > std.math.maxInt(u16)) return error.InvalidParams;
            break :blk @intCast(value.integer);
        } else 0;
        const evidence: request_authority.Report = .{
            .event = std.meta.stringToEnum(request_authority.Event, event) orelse return error.InvalidParams,
            .pre_acceptance = try control.boolean(params, "pre_acceptance", false),
            .response_started = try control.boolean(params, "response_started", true),
            .status = reported_status,
        };
        const transition = if (native_ref) |reference| try self.requests.checkReportForOwner(application, handle, reference, evidence) else try self.requests.checkReport(application, handle, evidence);
        if (!transition) return control.success(allocator, id, .{ .recorded = true });
        const authority = self.requests.attempt(application, handle) orelse return error.UnknownLease;
        const credit_key = creditKey(.request, handle, authority.issued_sequence);
        // Restart leaves uncertain work fenced. Explicit abandonment may
        // release that uncertainty, but can never enable another attempt.
        if (authority.state == .unknown and (evidence.event == .abandoned or evidence.event == .completed)) {
            for (self.state.leases.items) |lease| if (eql(lease.id, handle)) {
                try self.state.completeLease(handle);
                break;
            };
            _ = if (native_ref) |reference| try self.requests.reportForOwner(application, handle, reference, evidence) else try self.requests.report(handle, evidence);
            try self.releaseOutcome(credit_key);
            try self.persist(&.{});
            return control.success(allocator, id, .{ .recorded = true });
        }
        const native = self.nativeLease(params) catch |err| {
            if (err != error.UnknownLease or authority.state != .accepted or evidence.event != .completed) return err;
            for (self.state.leases.items) |lease| if (eql(lease.id, handle)) {
                try self.state.completeLease(handle);
                break;
            };
            _ = if (native_ref) |reference| try self.requests.reportForOwner(application, handle, reference, evidence) else try self.requests.report(handle, evidence);
            try self.releaseOutcome(credit_key);
            try self.persist(&.{});
            return control.success(allocator, id, .{ .recorded = true });
        };
        var held: ?domain.Lease = null;
        for (self.state.leases.items) |lease| if (eql(lease.id, &native.handle)) {
            held = lease;
            break;
        };
        const lease = held orelse return error.UnknownLease;
        const next: @TypeOf(native.status) = if (eql(event, "accepted")) .accepted else if (eql(event, "completed")) .completed else if (eql(event, "rejected")) .rejected else if (eql(event, "abandoned")) .abandoned else return error.InvalidParams;
        if (lease.expires_at <= self.now() and (next == .accepted or next == .rejected)) return error.LeaseExpired;
        switch (next) {
            .accepted => if (native.status != .issued) return error.InvalidTransition,
            .completed => {
                if (native.status != .accepted) return error.InvalidTransition;
                try self.state.completeLease(&native.handle);
            },
            .abandoned => {
                if (native.status != .issued and native.status != .accepted) return error.InvalidTransition;
                try self.state.completeLease(&native.handle);
            },
            .rejected => {
                if (native.status != .issued or !try control.boolean(params, "pre_acceptance", false) or try control.boolean(params, "response_started", true)) return error.UnsafeReplay;
                const status = control.get(params, "status") orelse return error.InvalidParams;
                if (status != .integer or (status.integer != 401 and status.integer != 403 and status.integer != 429)) return error.UnsafeReplay;
                if (status.integer == 401) {
                    for (self.state.grants.items) |*grant| if (eql(grant.id, lease.grant_id) and grant.generation == lease.grant_generation) {
                        grant.status = .invalid;
                    };
                } else {
                    const resource = lease.resource orelse return error.InvalidParams;
                    const timestamp = self.now();
                    const cooldown: i64 = if (status.integer == 403) 300 else 60;
                    try self.state.observe(.{ .account_id = lease.account_id, .resource = resource, .bucket_id = "", .remaining = 0, .window_start = timestamp, .window_end = timestamp + cooldown, .observed_at = timestamp, .expires_at = timestamp + cooldown, .status = .unavailable, .provenance = .native_application });
                }
                try self.state.completeLease(&native.handle);
            },
            .issued => unreachable,
        }
        native.status = next;
        _ = if (native_ref) |reference| try self.requests.reportForOwner(application, handle, reference, evidence) else try self.requests.report(handle, evidence);
        if (next != .accepted) try self.releaseOutcome(credit_key);
        try self.persist(&.{});
        return control.success(allocator, id, .{ .recorded = true });
    }

    fn gitCredential(self: *Engine, allocator: std.mem.Allocator, id: std.json.Value, params: std.json.Value, erase: bool) ![]u8 {
        if (!eql(try control.string(params, "application"), "git")) return error.WrongPurpose;
        const input = control.get(params, "request") orelse return error.InvalidParams;
        const protocol = try control.string(input, "protocol");
        const host = try control.string(input, "host");
        if (!eql(protocol, "https") or !std.ascii.eqlIgnoreCase(host, "github.com")) return error.ScopeMismatch;
        const requested_path = (try control.optionalString(input, "path")) orelse return error.RepositoryScopeRequired;
        const requested_user = try control.optionalString(input, "username");
        // The private RPC uses exactly the same path/value validator as Git's
        // native helper. Control strings already reject embedded newlines.
        const encoded_context = if (requested_user) |username|
            try std.fmt.allocPrint(allocator, "protocol={s}\nhost={s}\npath={s}\nusername={s}\n", .{ protocol, host, requested_path, username })
        else
            try std.fmt.allocPrint(allocator, "protocol={s}\nhost={s}\npath={s}\n", .{ protocol, host, requested_path });
        defer {
            std.crypto.secureZero(u8, encoded_context);
            allocator.free(encoded_context);
        }
        const context = try git.parse(encoded_context);
        const binding_digest = bindingIdentity("git", requested_user orelse "", requested_path);
        const binding_id: []const u8 = &binding_digest;
        const repository_digest = bindingIdentity("git-repository", "https://github.com", requested_path);
        const resource: domain.Resource = .{ .kind = "repository", .target = &repository_digest, .unit = .calls, .scope = "https://github.com" };
        const timestamp = self.now();
        if (erase) {
            // A username alone does not identify the rejected generation after
            // reconciliation. Git normally returns the password with erase;
            // incomplete rejection reports cannot cool down a newer credential.
            const rejected_password = (try control.optionalString(input, "password")) orelse return control.success(allocator, id, .{ .erased = true });
            var rejected: [2]?domain.Binding = .{ self.state.binding(binding_id), null };
            // A normal get may omit username; Git supplies the returned verified
            // username when rejecting it. Validate that private username before
            // touching the anonymous route, including after a route changes.
            if (requested_user != null) {
                const anonymous = bindingIdentity("git", "", requested_path);
                rejected[1] = self.state.binding(&anonymous);
            }
            for (rejected) |candidate_binding| {
                const binding = candidate_binding orelse continue;
                const grant = self.state.grant(binding.grant_id) orelse continue;
                if (grant.generation != binding.grant_generation) continue;
                const held = (try self.db.?.readGrantStatus(grant.account_id, grant.id)) orelse continue;
                if (held.state != .ready or held.generation != grant.generation) continue;
                var secret = try self.db.?.loadGrant(.{ .key_id = self.root_id.?, .account_id = grant.account_id, .grant_id = grant.id, .generation = grant.generation, .purpose = "request", .scope = grant.audience });
                defer secret.deinit();
                const parsed = try std.json.parseFromSlice(std.json.Value, allocator, secret.bytes, .{ .allocate = .alloc_always });
                defer {
                    control.wipeJson(parsed.value);
                    parsed.deinit();
                }
                const username = (try control.optionalString(parsed.value, "username")) orelse continue;
                if (requested_user) |user| if (!eql(user, username)) continue;
                var expected: [32]u8 = undefined;
                var supplied: [32]u8 = undefined;
                defer {
                    std.crypto.secureZero(u8, &expected);
                    std.crypto.secureZero(u8, &supplied);
                }
                std.crypto.hash.sha2.Sha256.hash(try control.string(parsed.value, "access_token"), &expected, .{});
                std.crypto.hash.sha2.Sha256.hash(rejected_password, &supplied, .{});
                if (!std.crypto.timing_safe.eql([32]u8, expected, supplied)) continue;
                // Git cannot report the provider's HTTP status, so keep a short
                // conservative rejection for only this account/repository context.
                // Credential custody, other repositories and account lifecycle stay
                // independent of the failed request.
                try self.state.observe(.{ .account_id = grant.account_id, .resource = resource, .bucket_id = "", .remaining = 0, .window_start = timestamp, .window_end = timestamp + 60, .observed_at = timestamp, .expires_at = timestamp + 60, .status = .unavailable, .provenance = .native_application });
                try self.persist(&.{});
                break;
            }
            return control.success(allocator, id, .{ .erased = true });
        }
        const demand: domain.Demand = .{ .provider = "github", .issuer = "https://github.com", .audience = "https://github.com", .purpose = .request, .resource = resource, .now = timestamp };
        var allowed_grants: std.ArrayList(domain.Grant) = .empty;
        defer allowed_grants.deinit(allocator);
        for (self.state.grants.items) |grant| {
            // Read-only views reuse the lifecycle/source/resource eligibility
            // rules without first selecting an incompatible private username.
            var candidate = grant;
            var candidate_state = self.state;
            candidate_state.grants = .empty;
            candidate_state.grants.items = (&candidate)[0..1];
            candidate_state.grants.capacity = 1;
            _ = candidate_state.select(demand, null) catch |err| switch (err) {
                error.NoEligibleAccount => continue,
                else => return err,
            };
            const held = (try self.db.?.readGrantStatus(grant.account_id, grant.id)) orelse continue;
            if (held.state != .ready or held.generation != grant.generation) continue;
            var secret = try self.db.?.loadGrant(.{ .key_id = self.root_id.?, .account_id = grant.account_id, .grant_id = grant.id, .generation = grant.generation, .purpose = "request", .scope = grant.audience });
            defer secret.deinit();
            const parsed = try std.json.parseFromSlice(std.json.Value, allocator, secret.bytes, .{ .allocate = .alloc_always });
            defer {
                control.wipeJson(parsed.value);
                parsed.deinit();
            }
            const username = (try control.optionalString(parsed.value, "username")) orelse continue;
            if (requested_user) |user| if (!eql(user, username)) continue;
            try allowed_grants.append(allocator, grant);
        }
        if (allowed_grants.items.len == 0) return error.NoEligibleAccount;
        var selectable = self.state;
        selectable.grants = allowed_grants;
        const existing = self.state.binding(binding_id);
        const selection = try selectable.select(demand, if (existing != null) binding_id else null);
        const grant = self.state.grant(selection.grant_id).?;
        var secret = try self.db.?.loadGrant(.{ .key_id = self.root_id.?, .account_id = grant.account_id, .grant_id = grant.id, .generation = grant.generation, .purpose = "request", .scope = grant.audience });
        defer secret.deinit();
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, secret.bytes, .{ .allocate = .alloc_always });
        defer {
            control.wipeJson(parsed.value);
            parsed.deinit();
        }
        const username = try control.string(parsed.value, "username");
        const password = try control.string(parsed.value, "access_token");
        var expires_at = grant.provider_expires_at;
        if (grant.custody_expires_at) |expiry| expires_at = if (expires_at) |retained| @min(retained, expiry) else expiry;
        for (self.state.sources.items) |source| if (eql(source.id, grant.source_id)) {
            if (source.authorized_until) |expiry| expires_at = if (expires_at) |retained| @min(retained, expiry) else expiry;
            break;
        };
        const validated = try git.response(allocator, context, .{ .host = "github.com", .path = requested_path, .username = username }, .{ .username = username, .password = password, .expires_at = expires_at }, timestamp);
        defer {
            std.crypto.secureZero(u8, validated);
            allocator.free(validated);
        }
        try retireIdleGitBindings(&self.state, binding_id);
        const route_generation = if (existing) |old| std.math.add(u64, old.route_generation, @as(u64, @intFromBool(!eql(old.grant_id, grant.id) or old.grant_generation != grant.generation))) catch return error.GenerationConflict else 1;
        _ = try self.state.bind(.{ .id = binding_id, .application = "git", .session_id = binding_id, .account_id = grant.account_id, .grant_id = grant.id, .grant_generation = grant.generation, .route_generation = route_generation, .last_used_revision = try std.math.add(u64, self.revision, 1) });
        try self.persist(&.{});
        return control.success(allocator, id, .{ .username = username, .password = password, .expires_at = expires_at });
    }

    /// Git helper invocations do not hold native sessions or in-flight leases.
    /// Retire only their oldest idle route cache, reserving room for 64 native
    /// bindings where possible. Active/native bindings and the current route
    /// remain intact; retiring a cache never changes a grant or account.
    fn retireIdleGitBindings(state: *domain.State, preserved_id: []const u8) !void {
        const cache_limit = domain.max_records - 64;
        while (state.bindings.items.len >= cache_limit) {
            var oldest: ?usize = null;
            for (state.bindings.items, 0..) |binding, index| {
                if (!eql(binding.application, "git") or binding.in_flight != 0 or eql(binding.id, preserved_id)) continue;
                if (oldest == null or binding.last_used_revision < state.bindings.items[oldest.?].last_used_revision) oldest = index;
            }
            const index = oldest orelse {
                if (state.binding(preserved_id) == null and state.bindings.items.len >= domain.max_records) return error.ServiceBusy;
                return;
            };
            try state.releaseBinding(state.bindings.items[index].id);
        }
    }

    fn setupOptions(self: *Engine, allocator: std.mem.Allocator, adapter: setup.Adapter, params: std.json.Value) !setup.Options {
        const home = std.mem.span(std.c.getenv("HOME") orelse return error.MissingHome);
        try paths.validateAbsolute(home);
        const deadline = try self.nativeDeadline();
        const config_path = try control.optionalString(params, "config_path");
        const selected_codex_home = try control.optionalString(params, "codex_home");
        const native_socket = try control.optionalString(params, "native_socket");
        const adapter_capability = try self.capability(@tagName(adapter));
        var path_arena: std.heap.ArenaAllocator = .init(allocator);
        defer path_arena.deinit();
        const runtime = if (!builtin.is_test and builtin.os.tag == .linux) if (std.c.getenv("XDG_RUNTIME_DIR")) |value| std.mem.span(value) else null else null;
        const locations = try paths.Locations.fromRuntime(path_arena.allocator(), self.state_dir, runtime);
        var options: setup.Options = .{ .state_dir = self.state_dir, .home = home, .xdg_config_home = if (std.c.getenv("XDG_CONFIG_HOME")) |v| std.mem.span(v) else null, .codex_home = if (selected_codex_home) |value| value else if (std.c.getenv("CODEX_HOME")) |v| std.mem.span(v) else null, .codex_home_explicit = selected_codex_home != null, .config_path = config_path, .adapter = adapter, .capability = adapter_capability, .broker_socket = try allocator.dupe(u8, locations.adapter), .native_socket = native_socket, .omux_version = product.version, .key = self.root_key, .deadline = deadline };
        errdefer allocator.free(options.broker_socket);
        if (adapter == .codex) {
            var saved = try self.db.?.readSnapshot();
            defer saved.deinit();
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(saved.json, &digest, .{});
            var cap_digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(&adapter_capability, &cap_digest, .{});
            const removal = self.native_owners.applicationRemoval("codex", self.adapter_epochs[0]);
            const state: setup.NativeCustodyState = if (removal) |removal_fence| if (self.native_owners.removalReady("codex", self.adapter_epochs[0], removal_fence.operation) and !self.nativeRequestsPending(null)) .removal_ready else .removal_pending else if (self.native_registry == null or self.native_registry.?.phase == .removed) .install_ready else .retain_ready;
            options.native_custody = .{ .adapter_epoch = self.adapter_epochs[0], .capability_digest = cap_digest, .snapshot_digest = digest, .state = state, .removal_operation = if (removal) |removal_fence| try parseOpaqueId(&removal_fence.operation) else null, .registry_transaction = if (self.native_registry) |registry| registry.transaction else null, .registry_capability_digest = if (self.native_registry) |registry| registry.capability_digest else null };
        }
        return options;
    }

    fn nativeDeadline(self: *Engine) !?std.Io.Clock.Timestamp {
        const caller = self.active_until orelse return null;
        if (caller.clock != .awake) return error.InvalidDeadline;
        const reserved = caller.subDuration(.{ .clock = .awake, .raw = .fromMilliseconds(1000) });
        if (reserved.durationFromNow(self.io).raw.toMilliseconds() <= 0) return error.NativeTimeout;
        return reserved;
    }

    fn integrationInstalled(self: *Engine, adapter: []const u8) bool {
        for (self.installed.items) |name| if (eql(name, adapter)) return true;
        return false;
    }

    fn codexSocket(allocator: std.mem.Allocator, params: std.json.Value) ![]u8 {
        if (try control.optionalString(params, "native_socket")) |socket| {
            try paths.validateAbsolute(socket);
            return allocator.dupe(u8, socket);
        }
        if (std.c.getenv("CODEX_HOME")) |home| return codex.advertisedSocket(allocator, std.mem.span(home));
        const home = std.mem.span(std.c.getenv("HOME") orelse return error.MissingHome);
        try paths.validateAbsolute(home);
        const codex_home = try std.fmt.allocPrint(allocator, "{s}/.codex", .{home});
        defer allocator.free(codex_home);
        return codex.advertisedSocket(allocator, codex_home);
    }

    fn publicIntegration(self: *Engine, allocator: std.mem.Allocator, id: std.json.Value, method: []const u8, params: std.json.Value) ![]u8 {
        if (eql(method, "integrations.status")) return control.success(allocator, id, .{ .adapters = catalog.adapters, .installed = self.installed.items, .runtime_selection = .{
            .qualification = "measured_installed_bytes_only",
            .native_support = false,
            .state = if (self.runtime_measurement != null or self.runtime_measurement_requested) "pending" else if (self.runtime_measurement_failure != null) "refused" else if (self.measured_codex_runtime != null) "committed_historical_facts" else "unselected",
            .reason = if (self.runtime_measurement_failure) |err| @errorName(err) else null,
        } });
        if (eql(method, "integrations.install")) return self.install(allocator, id, params);
        if (eql(method, "integrations.remove")) return self.uninstall(allocator, id, params);
        if (eql(method, "integrations.discover") or eql(method, "integrations.attach") or eql(method, "integrations.detach")) return error.NativePeerRequired;
        return error.MethodNotFound;
    }

    fn recoverIntegrations(self: *Engine) !void {
        for ([_]setup.Adapter{ .git, .codex }) |adapter| {
            const options = try self.setupOptions(self.allocator, adapter, .null);
            defer self.allocator.free(options.broker_socket);
            if (adapter == .codex) {
                if (self.measured_codex_runtime) |selected| {
                    const original = self.native_registry orelse return error.RuntimeSelectionDrift;
                    const actual_registry = (try setup.registryWitness(self.io, self.allocator, options)) orelse return error.RuntimeSelectionDrift;
                    if (!sameRegistryWitness(original, actual_registry) or !selected.ownedBy(original, self.adapter_epochs[0])) return error.RuntimeSelectionDrift;
                }
                if (self.native_owners.applicationRemoval("codex", self.adapter_epochs[0]) != null) continue;
                if (self.native_registry) |registry| if (registry.phase == .pending_install or registry.phase == .pending_remove) continue;
            }
            const actual = try setup.recover(self.io, self.allocator, options);
            if (adapter == .codex) self.native_registry = try setup.registryWitness(self.io, self.allocator, options);
            // A config/custody observation cannot retire native report
            // authority or manufacture an acknowledged owner-removal fence.
            if (adapter == .codex and actual != .installed and self.integrationInstalled("codex")) continue;
            var index: ?usize = null;
            for (self.installed.items, 0..) |name, i| if (eql(name, @tagName(adapter))) {
                index = i;
                break;
            };
            switch (actual) {
                .installed => if (index == null) {
                    try self.installed.append(self.allocator, try self.allocator.dupe(u8, @tagName(adapter)));
                },
                .removed, .conflict, .none => if (index) |i| {
                    self.allocator.free(self.installed.orderedRemove(i));
                    self.adapter_epochs[try adapterIndex(@tagName(adapter))] = try std.math.add(u64, self.adapter_epochs[try adapterIndex(@tagName(adapter))], 1);
                },
            }
        }
    }

    fn install(self: *Engine, allocator: std.mem.Allocator, id: std.json.Value, params: std.json.Value) ![]u8 {
        const name = try control.string(params, "adapter");
        const adapter = std.meta.stringToEnum(setup.Adapter, name) orelse return error.NativeHookRequired;
        if (adapter == .codex and self.native_owners.applicationRemoval("codex", self.adapter_epochs[0]) != null) return error.NativeRemovalPending;
        const options = try self.setupOptions(allocator, adapter, params);
        defer allocator.free(options.broker_socket);
        if (adapter == .codex) if (self.measured_codex_runtime) |selected| {
            const original = self.native_registry orelse return error.RuntimeSelectionDrift;
            const actual_registry = (try setup.registryWitness(self.io, allocator, options)) orelse return error.RuntimeSelectionDrift;
            if (!sameRegistryWitness(original, actual_registry) or !selected.ownedBy(original, self.adapter_epochs[0])) return error.RuntimeSelectionDrift;
        };
        const outcome = try setup.install(self.io, allocator, options);
        defer outcome.deinit(allocator);
        if (adapter == .codex) self.native_registry = try setup.registryWitness(self.io, allocator, options);
        var found = false;
        for (self.installed.items) |installed| if (eql(installed, name)) {
            found = true;
        };
        if (!found) try self.installed.append(self.allocator, try self.allocator.dupe(u8, name));
        try self.persist(&.{});
        if (adapter == .codex and self.codex_runtime_root != null) self.runtime_measurement_requested = true;
        return control.success(allocator, id, setup.installResult(adapter, outcome));
    }

    fn startRuntimeMeasurement(self: *Engine) !void {
        const root = self.codex_runtime_root orelse return;
        if (self.runtime_measurement != null) return error.ServiceBusy;
        if (!self.integrationInstalled("codex")) return error.AdapterNotInstalled;
        const task = try self.allocator.create(RuntimeMeasureTask);
        errdefer self.allocator.destroy(task);
        var arena = std.heap.ArenaAllocator.init(self.allocator);
        errdefer arena.deinit();
        const a = arena.allocator();
        var options = try self.setupOptions(a, .codex, .null);
        // Capture borrowed environment context into the worker's own arena.
        options.home = try a.dupe(u8, options.home);
        options.codex_home = if (options.codex_home) |value| try a.dupe(u8, value) else null;
        options.config_path = if (options.config_path) |value| try a.dupe(u8, value) else null;
        options.xdg_config_home = if (options.xdg_config_home) |value| try a.dupe(u8, value) else null;
        const fd = try paths.openPrivateRoot(a, root, false);
        errdefer _ = std.c.close(fd);
        const deadline: std.Io.Clock.Timestamp = .fromNow(self.io, .{ .clock = .awake, .raw = .fromMilliseconds(5000) });
        options.deadline = deadline;
        task.* = .{ .allocator = self.allocator, .io = self.io, .arena = arena, .directory = fd, .job = undefined, .context = .{ .options = options, .selection = self.instance_selection, .revision = self.revision, .deadline = deadline, .installation_path = root } };
        task.job = .{ .lane = .continuation, .context = task, .run = RuntimeMeasureTask.run };
        try self.native_workers.?.enqueue(&task.job);
        self.runtime_measurement_failure = null;
        self.runtime_measurement = task;
    }

    fn completeRuntimeMeasurement(self: *Engine, task: *RuntimeMeasureTask) void {
        std.debug.assert(self.runtime_measurement == task);
        defer task.deinit();
        self.runtime_measurement = null;
        if (self.stopping or self.poisoned) return;
        if (task.failure) |err| {
            self.runtime_measurement_failure = err;
            return;
        }
        const deadline: std.Io.Clock.Timestamp = .fromNow(self.io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) });
        self.commitMeasuredCodexRuntime(task.observed orelse return, deadline) catch |err| {
            self.runtime_measurement_failure = err;
        };
    }

    /// Private actor completion boundary. No control method supplies a record,
    /// digest or descriptor; the configured setup worker owns every input.
    fn commitMeasuredCodexRuntime(self: *Engine, observed: *const measured_runtime.MeasuredInstalledRuntime, deadline: std.Io.Clock.Timestamp) !void {
        if (self.poisoned or self.staging_mutation) return error.NativeCustodyPending;
        if (self.native_owners.applicationRemoval("codex", self.adapter_epochs[0]) != null or self.nativeRequestsPending(null)) return error.NativeCustodyPending;
        const options = try self.setupOptions(self.allocator, .codex, .null);
        defer self.allocator.free(options.broker_socket);
        const candidate = try observed.prepareCommit(self.io, self.allocator, .{ .options = options, .selection = self.instance_selection, .revision = self.revision, .deadline = deadline, .installation_path = self.codex_runtime_root orelse return error.InvalidInstallationSelection });
        try candidate.validate(self.allocator, self.native_registry, self.adapter_epochs[0], candidate.committed_revision);
        if (self.measured_codex_runtime) |previous| {
            // Byte-identical retry is idempotent; changing a selection needs a
            // separate reviewed installation replacement operation.
            if (!std.meta.eql(previous.record, candidate.record)) return error.RuntimeSelectionDrift;
            return;
        }
        const previous = self.measured_codex_runtime;
        self.measured_codex_runtime = candidate;
        self.persist(&.{}) catch |err| {
            self.measured_codex_runtime = previous;
            // Store.commit already fences ambiguous writes; no usable authority
            // escapes a failed commit. Capacity refusal remains reversible.
            return err;
        };
        if (self.revision != candidate.committed_revision) {
            self.fence();
            return error.RuntimeSelectionDrift;
        }
    }

    /// All fixture actions are compiled only for tests, run on the actual
    /// actor, and require a separately configured private synthetic root.
    fn measuredRuntimeFixture(self: *Engine, allocator: std.mem.Allocator, request: control.Request, channel: Channel) anyerror![]u8 {
        if (!builtin.is_test) return error.TestOnly;
        if (channel != .control or self.codex_runtime_root == null) return error.WrongChannel;
        const mode = try control.string(request.params, "mode");
        if (eql(mode, "inspect")) return control.success(allocator, request.id, .{
            .selected = self.measured_codex_runtime,
            .pending = self.runtime_measurement != null or self.runtime_measurement_requested,
            .failure = if (self.runtime_measurement_failure) |err| @errorName(err) else null,
            .registry = self.native_registry,
            .epoch = self.adapter_epochs[0],
            .revision = self.revision,
            .poisoned = self.poisoned,
            .removal_pending = self.native_owners.applicationRemoval("codex", self.adapter_epochs[0]) != null,
        });
        const original = self.measured_codex_runtime orelse return error.MissingMeasuredFixtureSelection;
        if (eql(mode, "restore")) {
            try self.restoreCommitted();
            return control.success(allocator, request.id, .{ .preserved = std.meta.eql(self.measured_codex_runtime.?, original) });
        }
        if (eql(mode, "digest_refusal")) {
            var candidate = self.persisted();
            candidate.measured_codex_runtime.?.record_sha256[0] ^= 1;
            const encoded = try std.json.Stringify.valueAlloc(allocator, candidate, .{});
            defer allocator.free(encoded);
            var refused = false;
            validatePersistedAdmission(allocator, encoded, self.revision) catch |err| {
                if (err != error.InvalidMeasuredRuntimeSelection) return err;
                refused = true;
            };
            return control.success(allocator, request.id, .{ .refused = refused, .preserved = std.meta.eql(self.measured_codex_runtime.?, original) });
        }
        if (eql(mode, "channel_restore")) {
            const original_registry = self.native_registry;
            const original_epoch = self.adapter_epochs[0];
            var changed = original;
            changed.record.channel = if (changed.record.channel == .release) .development else .release;
            changed.record_sha256 = try measured_runtime.digest(allocator, changed.record);
            // Authenticated but wrong-channel metadata reaches the real restore
            // path. Return memory to its prior state before exercising restore.
            self.measured_codex_runtime = changed;
            try self.persist(&.{});
            self.measured_codex_runtime = original;
            var refused = false;
            self.restoreCommitted() catch |err| {
                if (err != error.RuntimeSelectionDrift) return err;
                refused = true;
            };
            const preserved = std.meta.eql(self.measured_codex_runtime.?, original) and std.meta.eql(self.native_registry, original_registry) and self.adapter_epochs[0] == original_epoch;
            self.measured_codex_runtime = original;
            self.native_registry = original_registry;
            self.adapter_epochs[0] = original_epoch;
            try self.persist(&.{});
            return control.success(allocator, request.id, .{ .refused = refused, .preserved = preserved });
        }
        if (eql(mode, "wrong_transaction") or eql(mode, "recover_wrong_transaction") or eql(mode, "install_wrong_transaction")) {
            var changed = original;
            changed.record.installation.transaction[0] = if (changed.record.installation.transaction[0] == 'a') 'b' else 'a';
            changed.record_sha256 = try measured_runtime.digest(allocator, changed.record);
            self.measured_codex_runtime = changed;
            if (eql(mode, "wrong_transaction")) return control.success(allocator, request.id, .{ .armed = true });
            defer self.measured_codex_runtime = original;
            var refused = false;
            if (eql(mode, "recover_wrong_transaction")) {
                self.recoverIntegrations() catch |err| {
                    if (err != error.RuntimeSelectionDrift) return err;
                    refused = true;
                };
            } else {
                const encoded = try std.json.Stringify.valueAlloc(allocator, .{ .adapter = "codex" }, .{});
                defer allocator.free(encoded);
                const parsed = try std.json.parseFromSlice(std.json.Value, allocator, encoded, .{});
                defer parsed.deinit();
                if (self.install(allocator, request.id, parsed.value)) |reply| {
                    allocator.free(reply);
                } else |err| {
                    if (err != error.RuntimeSelectionDrift) return err;
                    refused = true;
                }
            }
            return control.success(allocator, request.id, .{ .refused = refused });
        }
        if (eql(mode, "capacity_refusal")) {
            // A real bounded carrier must still fail to acquire actor authority
            // when its authenticated snapshot cannot fit. No success stub or
            // direct Committed constructor is used for this commit attempt.
            self.measured_codex_runtime = null;
            try self.persist(&.{});
            try self.saturateSnapshot(1, false);
            const deadline: std.Io.Clock.Timestamp = .fromNow(self.io, .{ .clock = .awake, .raw = .fromMilliseconds(5000) });
            const options = try self.setupOptions(allocator, .codex, .null);
            defer allocator.free(options.broker_socket);
            const descriptor = try paths.openPrivateRoot(allocator, self.codex_runtime_root.?, false);
            defer _ = std.c.close(descriptor);
            const observed = try measured_runtime.observe(self.io, allocator, .{ .options = options, .selection = self.instance_selection, .revision = self.revision, .deadline = deadline, .installation_path = self.codex_runtime_root.? }, descriptor);
            defer observed.deinit();
            var refused = false;
            self.commitMeasuredCodexRuntime(observed, deadline) catch |err| {
                if (err != error.SnapshotTooLarge) return err;
                refused = true;
            };
            var saved = try self.db.?.readSnapshot();
            defer saved.deinit();
            const parsed = try std.json.parseFromSlice(Persisted, allocator, saved.json, .{});
            defer parsed.deinit();
            return control.success(allocator, request.id, .{ .refused = refused, .memory_unselected = self.measured_codex_runtime == null, .stored_unselected = parsed.value.measured_codex_runtime == null, .poisoned = self.poisoned });
        }
        return error.InvalidParams;
    }

    fn uninstall(self: *Engine, allocator: std.mem.Allocator, id: std.json.Value, params: std.json.Value) ![]u8 {
        const name = try control.string(params, "adapter");
        const adapter = std.meta.stringToEnum(setup.Adapter, name) orelse return error.NativeHookRequired;
        if (adapter == .codex) return error.NativePeerRequired;
        const options = try self.setupOptions(allocator, adapter, params);
        defer allocator.free(options.broker_socket);
        // Removal must fit its durable redacted result before the first native
        // detach, not only before setup changes the configuration afterward.
        try setup.preflightResult(self.io, allocator, options, .remove);
        const outcome = try setup.remove(self.io, allocator, options);
        defer outcome.deinit(allocator);
        for (self.installed.items, 0..) |installed, i| if (eql(installed, name)) {
            self.allocator.free(self.installed.orderedRemove(i));
            self.adapter_epochs[try adapterIndex(name)] = try std.math.add(u64, self.adapter_epochs[try adapterIndex(name)], 1);
            break;
        };
        try self.persist(&.{});
        return control.success(allocator, id, setup.removeResult(adapter, outcome));
    }
};

fn eql(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

const NativeRefWire = struct {
    owner_id: []const u8,
    adapter_epoch: []const u8,
    endpoint_generation: []const u8,
    thread_instance_generation: []const u8,
    attachment_generation: []const u8,
};
const NativeAuditAttempt = struct {
    account_handle: []const u8,
    issued_sequence: u64,
    state: request_authority.Status,
    accepted_report: ?request_authority.Report,
    terminal_report: ?request_authority.Report,
    // A current binding is not historical route authority. Lease retirement
    // leaves this null; do not infer a completed request's route from a binding.
    route_generation: ?u64,
};
const NativeAuditRecord = struct { request_id: []const u8, first: NativeAuditAttempt, alternate: ?NativeAuditAttempt };
const NativeAuditBinding = struct { account_handle: []const u8, route_generation: u64 };
const NativeRequestAuditResult = struct {
    schema_version: u32 = 1,
    native_ref: NativeRefWire,
    thread_id: []const u8,
    revision: u64,
    records: []NativeAuditRecord,
    binding: ?NativeAuditBinding = null,
    pending_requests: bool = false,
    pending_outcomes: bool = false,
};

// Enrollment creates random daemon-local identifiers, already used as opaque
// control handles by accounts.list and account.drain. Refuse noncanonical
// legacy identifiers instead of exposing a label or provider account ID.
fn nativeAuditAccountHandle(id: []const u8) ![]const u8 {
    if (id.len != 64) return error.InvalidNativeAuditAccountHandle;
    for (id) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return error.InvalidNativeAuditAccountHandle;
    return id;
}

fn nativeAuditAttempt(state: *const domain.State, reference: native_owner.NativeRef, record: *const request_authority.Record, attempt: request_authority.Attempt) !NativeAuditAttempt {
    var result: NativeAuditAttempt = .{
        .account_handle = try nativeAuditAccountHandle(attempt.account_id),
        .issued_sequence = attempt.issued_sequence,
        .state = attempt.state,
        .accepted_report = attempt.accepted_report,
        .terminal_report = attempt.terminal_report,
        .route_generation = null,
    };
    for (state.leases.items) |lease| {
        if (!eql(lease.id, attempt.lease_handle)) continue;
        const original = lease.native_ref orelse return error.InvalidNativeAttribution;
        if (!original.same(reference) or !eql(lease.binding_id, record.intent.binding_id) or !eql(lease.account_id, attempt.account_id) or lease.purpose != .request) return error.InvalidNativeAttribution;
        result.route_generation = lease.route_generation;
    }
    return result;
}

fn nativeRequestAuditResult(allocator: std.mem.Allocator, state: *const domain.State, requests: *const request_authority.Ledger, owners: *const native_owner.Ledger, outcomes: []const OutcomeIntent, revision: u64, reference: native_owner.NativeRef, thread_id: []const u8) !NativeRequestAuditResult {
    try reference.validate();
    if (thread_id.len == 0 or thread_id.len > native_owner.maximum_thread_bytes) return error.InvalidNativeAttachment;
    const owner = owners.lookupOwnerForRef(reference) orelse return error.UnknownNativeOwner;
    if (!eql(owner.application, "codex")) return error.WrongPurpose;
    const attachment = owners.lookupAttachment(reference) orelse return error.UnknownNativeAttachment;
    if (!eql(attachment.thread_id, thread_id)) return error.NativeOwnerMismatch;
    // Terminal/retired attribution remains readable. This does not authorize
    // attachment, native access, renewal, routing, or a new request attempt.
    const selected = try requests.nativeAuditRecords(allocator, "codex", reference, thread_id);
    defer allocator.free(selected);
    const records = try allocator.alloc(NativeAuditRecord, selected.len);
    var result: NativeRequestAuditResult = .{ .native_ref = try nativeRefWire(allocator, reference), .thread_id = thread_id, .revision = revision, .records = records };
    for (selected, records) |record, *output| {
        output.* = .{
            .request_id = record.intent.key.request_id,
            .first = try nativeAuditAttempt(state, reference, record, record.first),
            .alternate = if (record.alternate) |alternate| try nativeAuditAttempt(state, reference, record, alternate) else null,
        };
        if (unresolvedAttempt(record.first)) result.pending_requests = true;
        if (record.alternate) |alternate| {
            if (unresolvedAttempt(alternate)) result.pending_requests = true;
        }
    }
    for (state.leases.items) |lease| if (lease.native_ref) |original| {
        if (original.same(reference)) result.pending_requests = true;
    };
    for (state.bindings.items) |binding| {
        const original = binding.native_ref orelse continue;
        if (!original.same(reference) or !eql(binding.application, "codex") or !eql(binding.session_id, thread_id)) continue;
        if (result.binding != null) return error.NativeAuditBindingAmbiguous;
        result.binding = .{ .account_handle = try nativeAuditAccountHandle(binding.account_id), .route_generation = binding.route_generation };
    }
    for (outcomes) |outcome| {
        if (outcome.native_ref) |original| if (original.same(reference)) {
            result.pending_outcomes = true;
            continue;
        };
        if (outcome.key.kind != .request) continue;
        const intent = requests.intentForHandle("codex", outcome.owner_id) orelse continue;
        const original = intent.native_ref orelse continue;
        if (original.same(reference) and eql(intent.key.session_id, thread_id)) result.pending_outcomes = true;
    }
    return result;
}

test "native request audit preserves terminal truth and redacts unselected custody and internal request fields" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const reference: native_owner.NativeRef = .{ .owner_id = @splat(7), .adapter_epoch = 1, .endpoint_generation = 1, .thread_instance_generation = 1, .attachment_generation = 1 };
    var owners = native_owner.Ledger.init(allocator);
    try owners.owners.append(allocator, .{ .id = reference.owner_id, .application = "codex", .adapter_epoch = 1, .endpoint_generation = 1, .witness = undefined, .native_nonce = @splat(9), .endpoint_path = "/generated-private-owner-path" });
    try owners.attachments.append(allocator, .{ .reference = reference, .thread_id = "selected-thread", .registration_operation = @splat('1'), .phase = .attached });
    var requests = request_authority.Ledger.init(allocator, 8);
    const account: [64]u8 = @splat('b');
    const handle: [64]u8 = @splat('a');
    const fingerprint: [64]u8 = @splat('f');
    const intent: request_authority.Intent = .{ .key = .{ .application = "codex", .session_id = "selected-thread", .request_id = "selected-request" }, .binding_id = "private-binding", .demand_fingerprint = &fingerprint, .native_ref = reference };
    _ = try requests.issue(intent, &handle, &account, 10);
    _ = try requests.reportForOwner("codex", &handle, reference, .{ .event = .accepted, .status = 200 });
    _ = try requests.reportForOwner("codex", &handle, reference, .{ .event = .completed });
    var foreign = intent;
    foreign.native_ref.?.attachment_generation += 1;
    foreign.key.request_id = "foreign-private-request";
    const foreign_handle: [64]u8 = @splat('c');
    _ = try requests.issue(foreign, &foreign_handle, &account, 10);
    var state = domain.State.init(allocator);
    try state.bindings.append(allocator, .{ .id = "private-binding", .application = "codex", .session_id = "selected-thread", .native_ref = reference, .account_id = &account, .grant_id = "private-grant", .grant_generation = 1, .route_generation = 2 });
    const before = try std.json.Stringify.valueAlloc(allocator, requests.snapshot(), .{});
    const result = try nativeRequestAuditResult(allocator, &state, &requests, &owners, &.{}, 12, reference, "selected-thread");
    try std.testing.expectEqual(@as(usize, 1), result.records.len);
    try std.testing.expectEqualStrings("selected-request", result.records[0].request_id);
    try std.testing.expectEqualStrings(&account, result.records[0].first.account_handle);
    try std.testing.expectEqual(request_authority.Status.completed, result.records[0].first.state);
    try std.testing.expectEqual(request_authority.Event.accepted, result.records[0].first.accepted_report.?.event);
    try std.testing.expectEqual(request_authority.Event.completed, result.records[0].first.terminal_report.?.event);
    try std.testing.expect(result.records[0].first.route_generation == null);
    try std.testing.expectEqual(@as(u64, 2), result.binding.?.route_generation);
    try std.testing.expect(!result.pending_requests and !result.pending_outcomes);
    const encoded = try std.json.Stringify.valueAlloc(allocator, result, .{});
    for ([_][]const u8{ "lease_handle", "account_id", "binding_id", "demand_fingerprint", "native_nonce", "endpoint_path", "private-binding", "private-grant", "generated-private-owner-path", "foreign-private-request" }) |private_field| try std.testing.expect(std.mem.indexOf(u8, encoded, private_field) == null);
    const after = try std.json.Stringify.valueAlloc(allocator, requests.snapshot(), .{});
    try std.testing.expectEqualStrings(before, after);
    try std.testing.expectError(error.NativeOwnerMismatch, nativeRequestAuditResult(allocator, &state, &requests, &owners, &.{}, 12, reference, "different-thread"));
    var changed = reference;
    changed.endpoint_generation += 1;
    try std.testing.expectError(error.UnknownNativeOwner, nativeRequestAuditResult(allocator, &state, &requests, &owners, &.{}, 12, changed, "selected-thread"));
    try std.testing.expectError(error.InvalidNativeAuditAccountHandle, nativeAuditAccountHandle("generated-label"));
}

test "native request audit exposes unknown and outstanding request credit without fabricating terminal completion" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const reference: native_owner.NativeRef = .{ .owner_id = @splat(7), .adapter_epoch = 1, .endpoint_generation = 1, .thread_instance_generation = 1, .attachment_generation = 1 };
    var owners = native_owner.Ledger.init(allocator);
    try owners.owners.append(allocator, .{ .id = reference.owner_id, .application = "codex", .adapter_epoch = 1, .endpoint_generation = 1, .witness = undefined, .native_nonce = @splat(9), .endpoint_path = "/generated-private-owner-path" });
    try owners.attachments.append(allocator, .{ .reference = reference, .thread_id = "selected-thread", .registration_operation = @splat('1'), .phase = .attached });
    var requests = request_authority.Ledger.init(allocator, 8);
    const account: [64]u8 = @splat('b');
    const handle: [64]u8 = @splat('a');
    const fingerprint: [64]u8 = @splat('f');
    const intent: request_authority.Intent = .{ .key = .{ .application = "codex", .session_id = "selected-thread", .request_id = "selected-request" }, .binding_id = "private-binding", .demand_fingerprint = &fingerprint, .native_ref = reference };
    _ = try requests.issue(intent, &handle, &account, 10);
    _ = try requests.reportForOwner("codex", &handle, reference, .{ .event = .accepted });
    requests.recoverAfterRestart();
    const state = domain.State.init(allocator);
    const outcomes = [_]OutcomeIntent{.{ .key = creditKey(.request, &handle, 1), .owner_id = &handle, .plan_bytes = 1 }};
    const result = try nativeRequestAuditResult(allocator, &state, &requests, &owners, &outcomes, 12, reference, "selected-thread");
    try std.testing.expect(result.pending_requests and result.pending_outcomes);
    try std.testing.expectEqual(request_authority.Status.unknown, result.records[0].first.state);
    try std.testing.expect(result.records[0].first.accepted_report != null);
    try std.testing.expect(result.records[0].first.terminal_report == null);
    try std.testing.expect(result.binding == null);
    try std.testing.expectError(error.AttemptBudgetExhausted, requests.checkIssue(intent));
}

test "native audit RPC rejects adapter purpose, unknown selectors and poisoned custody without restore or mutation" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var current: Engine = undefined;
    current.poisoned = false;
    // Wrong channel and malformed selectors must refuse before reading any
    // uninitialized custody fields, including a database restore path.
    var request = try control.parse(allocator, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"integrations.nativeRequestAudit\",\"params\":{\"cursor\":\"unbounded\"}}");
    defer request.deinit();
    try std.testing.expectError(error.WrongChannel, current.handleRequest(allocator, request, .adapter));
    const refused = try current.execute(allocator, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"integrations.nativeRequestAudit\",\"params\":{\"cursor\":\"unbounded\"}}", .control);
    try std.testing.expect(std.mem.indexOf(u8, refused, "InvalidParams") != null);
    current.poisoned = true;
    const poisoned = try current.execute(allocator, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"integrations.nativeRequestAudit\",\"params\":{}}", .control);
    try std.testing.expect(std.mem.indexOf(u8, poisoned, "CustodyUnavailable") != null);
}

const NativeDiscoveryThread = struct {
    thread_id: []const u8,
    thread_instance_generation: []const u8,
    attachment_generation: []const u8,
    native_ref: ?NativeRefWire = null,
};
const NativeDiscoveryOwner = struct {
    owner_id: []const u8,
    process_nonce: []const u8,
    endpoint_generation: []const u8,
    owner_endpoint: []const u8,
    native_version: []const u8,
    support: codex.Support,
    threads: []NativeDiscoveryThread,
};
const NativeDiscoveryResult = struct {
    adapter: []const u8 = "codex",
    installed: bool,
    native_support: bool = false,
    hook_compatible: bool = false,
    owners: []NativeDiscoveryOwner,
    scanned_entries: usize,
    ignored_stale_entries: usize,
};
// The worker passes no actor: peer-verified discovery remains observation-only.
// The actor may project an existing committed attachment, never synthesize one
// from the producer's prospective diagnostic attachment generation.
fn nativeDiscoveryResult(allocator: std.mem.Allocator, task: *const NativeTask, actor: ?*Engine, installed: bool) !NativeDiscoveryResult {
    const owners = try allocator.alloc(NativeDiscoveryOwner, task.discovered.items.len);
    var result: NativeDiscoveryResult = .{ .installed = installed, .owners = owners, .scanned_entries = task.scanned_entries, .ignored_stale_entries = task.ignored_stale_entries };
    for (task.discovered.items, owners, 0..) |loaded, *output, index| {
        for (task.discovered.items[0..index]) |prior| {
            // Two endpoints advertising one process identity cannot be selected
            // by an unauthenticated wire tuple or by an arbitrary first match.
            if (std.mem.eql(u8, &prior.owner_id, &loaded.owner_id)) return error.NativeOwnerAmbiguous;
        }
        const threads = try allocator.alloc(NativeDiscoveryThread, loaded.threads.len);
        output.* = .{
            .owner_id = try allocator.dupe(u8, &std.fmt.bytesToHex(loaded.owner_id, .lower)),
            .process_nonce = try allocator.dupe(u8, &std.fmt.bytesToHex(loaded.native_nonce, .lower)),
            .endpoint_generation = try std.fmt.allocPrint(allocator, "{d}", .{loaded.endpoint_generation}),
            .owner_endpoint = loaded.socket_path,
            .native_version = loaded.native_version,
            .support = loaded.support,
            .threads = threads,
        };
        if (loaded.support == .compatible_hook) result.hook_compatible = true;
        for (loaded.threads, threads) |input, *thread| {
            thread.* = .{ .thread_id = input.thread_id, .thread_instance_generation = try std.fmt.allocPrint(allocator, "{d}", .{input.thread_instance_generation}), .attachment_generation = try std.fmt.allocPrint(allocator, "{d}", .{input.attachment_generation}) };
            if (actor) |engine| {
                const owner = engine.native_owners.lookupOwnerQualified(loaded.owner_id, engine.adapter_epochs[0], loaded.endpoint_generation) orelse continue;
                if (owner.phase != .open or !peer.sameOriginal(owner.witness, loaded.witness) or !std.mem.eql(u8, &owner.native_nonce, &loaded.native_nonce) or !eql(owner.endpoint_path, loaded.socket_path)) continue;
                for (engine.native_owners.attachments.items) |row| {
                    if (row.phase != .attached or !row.reference.ownerKey().same(owner.key()) or !eql(row.thread_id, input.thread_id) or row.reference.thread_instance_generation != input.thread_instance_generation or row.reference.attachment_generation != input.attachment_generation) continue;
                    thread.native_ref = try nativeRefWire(allocator, row.reference);
                    break;
                }
            }
        }
    }
    return result;
}
fn requireNativeDiscoveryFits(id: std.json.Value, result: NativeDiscoveryResult) !void {
    _ = snapshot_admission.countJson(.{ .jsonrpc = "2.0", .id = id, .result = result }, native_probe.maximum_owner_packet) catch |err| switch (err) {
        error.SnapshotTooLarge => return error.NativeResultTooLarge,
    };
}
test "native discovery bounds the combined escaped owner response rather than each endpoint alone" {
    const escaped_thread: [256]u8 = @splat('\\');
    var threads: [64]NativeDiscoveryThread = undefined;
    for (&threads) |*thread| thread.* = .{ .thread_id = &escaped_thread, .thread_instance_generation = "1", .attachment_generation = "1" };
    const owner: NativeDiscoveryOwner = .{ .owner_id = "generated-owner", .process_nonce = "generated-nonce", .endpoint_generation = "1", .owner_endpoint = "/generated/owner.sock", .native_version = product.version, .support = .compatible_hook, .threads = &threads };
    var owners = [_]NativeDiscoveryOwner{ owner, owner };
    var result: NativeDiscoveryResult = .{ .installed = false, .owners = owners[0..1], .scanned_entries = 2, .ignored_stale_entries = 0 };
    const request_id: std.json.Value = .{ .integer = 1 };
    try requireNativeDiscoveryFits(request_id, result);
    result.owners = &owners;
    try std.testing.expectError(error.NativeResultTooLarge, requireNativeDiscoveryFits(request_id, result));
}
test "compatible native discovery mechanism does not promote live support" {
    var task: NativeTask = undefined;
    task.discovered = .empty;
    defer task.discovered.deinit(std.testing.allocator);
    task.scanned_entries = 1;
    task.ignored_stale_entries = 0;
    try task.discovered.append(std.testing.allocator, .{
        .owner_id = @splat(1),
        .native_nonce = @splat(2),
        .endpoint_generation = 1,
        .witness = undefined,
        .socket_path = @constCast("/generated/owner.sock"),
        .native_version = @constCast(product.version),
        .support = .compatible_hook,
        .threads = &.{},
        .thread_ids = &.{},
    });
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const result = try nativeDiscoveryResult(arena.allocator(), &task, null, false);
    try std.testing.expect(result.hook_compatible);
    try std.testing.expect(!result.native_support);
    try requireNativeDiscoveryFits(.{ .integer = 1 }, result);
}
const NativeOperationResult = struct {
    registered: bool,
    operation_id: []const u8,
    native_ref: NativeRefWire,
};
const NativeDetachResult = struct { detached: bool, operation_id: []const u8, native_ref: NativeRefWire };
fn nativeRefWire(allocator: std.mem.Allocator, reference: native_owner.NativeRef) !NativeRefWire {
    return .{
        .owner_id = try allocator.dupe(u8, &std.fmt.bytesToHex(reference.owner_id, .lower)),
        .adapter_epoch = try std.fmt.allocPrint(allocator, "{d}", .{reference.adapter_epoch}),
        .endpoint_generation = try std.fmt.allocPrint(allocator, "{d}", .{reference.endpoint_generation}),
        .thread_instance_generation = try std.fmt.allocPrint(allocator, "{d}", .{reference.thread_instance_generation}),
        .attachment_generation = try std.fmt.allocPrint(allocator, "{d}", .{reference.attachment_generation}),
    };
}
fn nativeRegistrationResult(allocator: std.mem.Allocator, operation: native_owner.OperationId, reference: native_owner.NativeRef) !NativeOperationResult {
    return .{ .registered = true, .operation_id = try allocator.dupe(u8, &operation), .native_ref = try nativeRefWire(allocator, reference) };
}
fn nativeDetachResult(allocator: std.mem.Allocator, operation: native_owner.OperationId, reference: native_owner.NativeRef) !NativeDetachResult {
    return .{ .detached = true, .operation_id = try allocator.dupe(u8, &operation), .native_ref = try nativeRefWire(allocator, reference) };
}
// Only the mutation ledger's storage ID is namespaced. Original native op,
// immutable attachment, credit and wire ACK remain the producer's same ID.
fn nativeRegistrationMutationId(operation: native_owner.OperationId) [64]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("omux.native.mutation.v1.adapter.owner.register");
    hash.update(&operation);
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}
fn nativeDetachOperation(removal: native_owner.OperationId, reference: native_owner.NativeRef) [64]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("omux.native.removal.detach.v1");
    hash.update(&removal);
    hash.update(&reference.owner_id);
    for ([_]u64{ reference.adapter_epoch, reference.endpoint_generation, reference.thread_instance_generation, reference.attachment_generation }) |generation| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, generation, .little);
        hash.update(&bytes);
    }
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}
fn sameRegistryWitness(a: setup.RegistryWitness, b: setup.RegistryWitness) bool {
    return a.phase == b.phase and std.mem.eql(u8, &a.transaction, &b.transaction) and std.crypto.timing_safe.eql([32]u8, a.capability_digest, b.capability_digest);
}

comptime {
    if (domain.max_records != snapshot_admission.maximum_domain_records or domain.max_list_items != snapshot_admission.maximum_account_sources or storage.maximum_snapshot_bytes != snapshot_admission.maximum_snapshot_bytes) @compileError("snapshot admission limits must match their owners");
}

fn creditKey(kind: snapshot_admission.Kind, id: []const u8, generation: u64) snapshot_admission.Key {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(id, &digest, .{});
    return .{ .kind = kind, .id = digest, .generation = generation };
}

fn creditPresent(saved: snapshot_admission.Snapshot, key: snapshot_admission.Key) bool {
    for (saved.credits) |credit| if (std.meta.eql(credit.key, key)) return true;
    return false;
}

fn unresolvedAttempt(attempt: request_authority.Attempt) bool {
    return attempt.state == .issued or attempt.state == .accepted or attempt.state == .unknown;
}

fn integrationRecoveryGrowth() !usize {
    const epochs: [4]u64 = @splat(std.math.maxInt(u64));
    // Exact typed envelope dominates both installed-name insertions and every
    // adapter epoch's maximum decimal width in all recovery outcomes.
    return snapshot_admission.countJson(.{ .installed = [_][]const u8{ "git", "codex" }, .adapter_epochs = epochs }, storage.maximum_snapshot_bytes);
}

const ScalarRange = struct { minimum: usize, maximum: usize };
fn scalarRange(comptime T: type) !ScalarRange {
    return switch (@typeInfo(T)) {
        .int => |info| .{ .minimum = 1, .maximum = @max(try snapshot_admission.countJson(std.math.maxInt(T), storage.maximum_snapshot_bytes), if (info.signedness == .signed) try snapshot_admission.countJson(std.math.minInt(T), storage.maximum_snapshot_bytes) else 1) },
        // The locked JSON writer uses decimal floats. Its documented minimum
        // subnormal bound exceeds the decimal width of the largest finite f64.
        .float => blk: {
            if (@bitSizeOf(T) > 64) @compileError("snapshot maintenance needs an explicit wider-float bound");
            break :blk .{ .minimum = 1, .maximum = std.fmt.float.bufferSize(.decimal, f64) };
        },
        .bool => .{ .minimum = 4, .maximum = 5 },
        .@"enum" => blk: {
            var range: ScalarRange = .{ .minimum = std.math.maxInt(usize), .maximum = 0 };
            inline for (@typeInfo(T).@"enum".field_names) |name| {
                const size = try snapshot_admission.countJson(@field(T, name), storage.maximum_snapshot_bytes);
                range.minimum = @min(range.minimum, size);
                range.maximum = @max(range.maximum, size);
            }
            break :blk range;
        },
        .optional => |info| switch (@typeInfo(info.child)) {
            .int, .float, .bool, .@"enum" => blk: {
                const child = try scalarRange(info.child);
                break :blk .{ .minimum = @min(4, child.minimum), .maximum = @max(4, child.maximum) };
            },
            .@"struct" => try scalarRange(info.child),
            else => .{ .minimum = 0, .maximum = 0 },
        },
        .@"struct" => blk: {
            var range: ScalarRange = .{ .minimum = 0, .maximum = 0 };
            inline for (@typeInfo(T).@"struct".field_types) |field_type| {
                const child = try scalarRange(field_type);
                range.minimum += child.minimum;
                range.maximum += child.maximum;
            }
            break :blk range;
        },
        else => .{ .minimum = 0, .maximum = 0 },
    };
}

fn scalarWidening(value: anytype) !usize {
    const T = @TypeOf(value);
    return switch (@typeInfo(T)) {
        .int, .float, .bool, .@"enum" => (try snapshot_admission.countJson(value, storage.maximum_snapshot_bytes)) - (try scalarRange(T)).minimum,
        .optional => |info| switch (@typeInfo(info.child)) {
            .int, .float, .bool, .@"enum" => (try snapshot_admission.countJson(value, storage.maximum_snapshot_bytes)) - (try scalarRange(T)).minimum,
            .@"struct" => if (value) |child| try scalarWidening(child) else 0,
            else => 0,
        },
        .@"struct" => blk: {
            var widened: usize = 0;
            inline for (@typeInfo(T).@"struct".field_names) |name| widened += try scalarWidening(@field(value, name));
            break :blk widened;
        },
        else => 0,
    };
}

// Prepay the scalar width span of every legal domain slot, even absent slots.
// Current occupied widening spends that fixed ceiling. A later expiry/status
// transition increases actual bytes and decreases this reserve atomically.
fn maintenanceReservation(saved: Persisted) !usize {
    var reserve: usize = 0;
    inline for (@typeInfo(domain.Snapshot).@"struct".field_names, @typeInfo(domain.Snapshot).@"struct".field_types) |name, field_type| {
        switch (@typeInfo(field_type)) {
            .pointer => |pointer| if (pointer.size == .slice) {
                const range = try scalarRange(pointer.child);
                reserve += (range.maximum - range.minimum) * domain.max_records;
                for (@field(saved.state, name)) |record| reserve -= try scalarWidening(record);
            },
            .int => {
                const range = try scalarRange(field_type);
                reserve += range.maximum - range.minimum - (try scalarWidening(@field(saved.state, name)));
            },
            else => {},
        }
    }
    const epoch_range = try scalarRange(u64);
    reserve += (epoch_range.maximum - epoch_range.minimum) * (domain.max_records + saved.adapter_epochs.len + 1);
    for (saved.import_source_authority) |authority| reserve -= try scalarWidening(authority.generation);
    for (saved.adapter_epochs) |epoch| reserve -= try scalarWidening(epoch);
    reserve -= try scalarWidening(saved.import_forget_epoch);
    const intent_range = try scalarRange(OutcomeIntent);
    reserve += (intent_range.maximum - intent_range.minimum) * saved.outcome_intents.len;
    for (saved.outcome_intents) |intent| reserve -= try scalarWidening(intent);
    if (saved.lifecycle_measurements) |measurements| {
        const actual = try snapshot_admission.countJson(measurements, reliability.max_lifecycle_checkpoint_bytes);
        reserve = try std.math.add(usize, reserve, try reliability_commit.remainingReservation(actual));
    }
    if (saved.browser_attempt_authority) |attempts| {
        const actual = try snapshot_admission.countJson(attempts, browser_attempt.maximum_snapshot_bytes);
        reserve = try std.math.add(usize, reserve, browser_attempt.maximum_snapshot_bytes - actual);
    }
    return reserve;
}

fn copyIntent(allocator: std.mem.Allocator, input: OutcomeIntent) !OutcomeIntent {
    var owned = input;
    owned.owner_id = try allocator.dupe(u8, input.owner_id);
    errdefer allocator.free(owned.owner_id);
    owned.secondary_id = try allocator.dupe(u8, input.secondary_id);
    errdefer allocator.free(owned.secondary_id);
    owned.source_id = try allocator.dupe(u8, input.source_id);
    errdefer allocator.free(owned.source_id);
    owned.provider = try allocator.dupe(u8, input.provider);
    errdefer allocator.free(owned.provider);
    owned.label = try allocator.dupe(u8, input.label);
    return owned;
}
fn freeIntent(allocator: std.mem.Allocator, intent: OutcomeIntent) void {
    allocator.free(intent.owner_id);
    allocator.free(intent.secondary_id);
    allocator.free(intent.source_id);
    allocator.free(intent.provider);
    allocator.free(intent.label);
}

// Storage invokes this after key verification and before recovery authority or
// custody effects. Legacy snapshots cannot gain invented completion promises.
fn validatePersistedAdmission(allocator: std.mem.Allocator, json: []const u8, current_revision: u64) !void {
    // Check raw witness presence before typed defaults can replace missing
    // scope/provenance/duration fields with plausible measurements.
    const raw = try std.json.parseFromSlice(std.json.Value, allocator, json, .{ .allocate = .alloc_always, .duplicate_field_behavior = .@"error" });
    defer raw.deinit();
    if (control.get(raw.value, "mutation_authority")) |authority| if (control.get(authority, "records")) |records| {
        if (records != .array) return error.InvalidMutationSnapshot;
        for (records.array.items) |record| if (control.get(record, "lifecycle_witness")) |fact| {
            if (fact == .null) continue;
            const encoded = try std.json.Stringify.valueAlloc(allocator, fact, .{});
            defer allocator.free(encoded);
            var strict = try lifecycle_witness.read(allocator, encoded);
            strict.deinit();
        };
        for (records.array.items) |record| if (control.get(record, "native_removal_witness")) |fact| {
            if (fact == .null) continue;
            const encoded = try std.json.Stringify.valueAlloc(allocator, fact, .{});
            defer allocator.free(encoded);
            var strict = try native_removal_witness.read(allocator, encoded);
            strict.deinit();
        };
    };
    const parsed = try std.json.parseFromSlice(Persisted, allocator, json, .{});
    defer parsed.deinit();
    const saved = parsed.value;
    if (saved.schema_version != 1 and saved.schema_version != 2) return error.UnsupportedSchema;
    if (saved.measured_codex_runtime) |selected| {
        if (saved.schema_version != 2) return error.InvalidMeasuredRuntimeSelection;
        try selected.validate(allocator, saved.native_registry, saved.adapter_epochs[0], current_revision);
    }
    if (saved.browser_attempt_authority) |attempts| {
        if (saved.schema_version != 2 or saved.lifecycle_measurements == null) return error.InvalidBrowserAttemptSnapshot;
        var verified = try browser_attempt.Ledger.fromSnapshot(allocator, attempts);
        defer verified.deinit();
        _ = try snapshot_admission.countJson(attempts, browser_attempt.maximum_snapshot_bytes);
    }
    var state = try domain.State.fromSnapshot(allocator, saved.state);
    defer state.deinit();
    var requests = try request_authority.Ledger.fromSnapshot(allocator, 4096, saved.request_authority);
    defer requests.deinit();
    var mutations = try mutation_authority.Ledger.fromSnapshotAtRevision(allocator, saved.mutation_authority, current_revision);
    defer mutations.deinit();
    for (saved.mutation_authority.records) |record| if (eql(record.method[0..record.method_len], "setup.refresh")) {
        if (record.kind != .external) return error.InvalidSetupVerificationRecord;
        if (record.state == .completed) {
            var terminal = try setup_verification.parseCompletedRecord(allocator, record);
            terminal.deinit();
        }
    };
    var admission = try snapshot_admission.Ledger.fromSnapshot(allocator, saved.snapshot_admission);
    defer admission.deinit();
    var native = try native_owner.Ledger.fromSnapshot(allocator, saved.native_owner_authority);
    defer native.deinit();
    try validateNativeAttribution(allocator, saved, &native);
    if (saved.schema_version == 1) {
        if (saved.snapshot_admission.credits.len != 0 or saved.state.leases.len != 0) return error.SnapshotAdmissionMigrationRequired;
        for (saved.state.jobs) |job| if (job.status == .running) return error.SnapshotAdmissionMigrationRequired;
        for (saved.mutation_authority.records) |record| if (record.kind == .external and record.state != .completed) return error.SnapshotAdmissionMigrationRequired;
        for (saved.request_authority.records) |record| {
            if (unresolvedAttempt(record.first)) return error.SnapshotAdmissionMigrationRequired;
            if (record.alternate) |attempt| if (unresolvedAttempt(attempt)) return error.SnapshotAdmissionMigrationRequired;
        }
    } else {
        for (saved.mutation_authority.records) |record| if (record.kind == .external and record.state != .completed) {
            if (eql(record.method[0..record.method_len], "adapter.owner.register")) {
                var found = false;
                for (saved.native_owner_authority.attachments) |row| {
                    const internal_id = nativeRegistrationMutationId(row.registration_operation);
                    if (eql(record.id[0..record.id_len], &internal_id) and creditPresent(saved.snapshot_admission, creditKey(.native_registration, &row.registration_operation, row.reference.adapter_epoch))) found = true;
                }
                if (!found) return error.InvalidNativeCreditAuthority;
            } else if (!creditPresent(saved.snapshot_admission, creditKey(.mutation, record.id[0..record.id_len], record.expected_revision))) return error.InvalidSnapshotCreditAuthority;
        };
        for (saved.request_authority.records) |record| {
            if (unresolvedAttempt(record.first) and !creditPresent(saved.snapshot_admission, creditKey(.request, record.first.lease_handle, record.first.issued_sequence))) return error.InvalidSnapshotCreditAuthority;
            if (record.alternate) |attempt| if (unresolvedAttempt(attempt) and !creditPresent(saved.snapshot_admission, creditKey(.request, attempt.lease_handle, attempt.issued_sequence))) return error.InvalidSnapshotCreditAuthority;
        }
        for (saved.state.jobs) |job| if (job.status == .running and (job.kind == .enrollment or job.kind == .repair)) {
            if (!creditPresent(saved.snapshot_admission, creditKey(.import, job.id, job.operation_generation))) return error.InvalidSnapshotCreditAuthority;
        };
    }
    if (saved.import_source_authority.len > domain.max_records or saved.outcome_intents.len > snapshot_admission.maximum_credits or saved.outcome_intents.len != saved.snapshot_admission.credits.len) return error.InvalidSnapshotCreditAuthority;
    for (saved.import_source_authority, 0..) |authority, index| {
        if (authority.generation == 0 or authority.source_id.len == 0 or authority.source_id.len > domain.max_text_bytes) return error.InvalidSnapshotCreditAuthority;
        for (saved.import_source_authority[0..index]) |previous| if (eql(authority.source_id, previous.source_id)) return error.InvalidSnapshotCreditAuthority;
    }
    for (saved.outcome_intents, 0..) |intent, index| {
        const credit = admission.lookup(intent.key) orelse return error.InvalidSnapshotCreditAuthority;
        if (intent.owner_id.len == 0 or intent.owner_id.len > domain.max_text_bytes or intent.secondary_id.len > domain.max_text_bytes or intent.source_id.len > domain.max_text_bytes or intent.label.len > domain.max_text_bytes or intent.plan_bytes == 0 or intent.plan_bytes > storage.maximum_snapshot_bytes or intent.used_bytes > intent.plan_bytes or credit.bytes != intent.plan_bytes - intent.used_bytes) return error.InvalidSnapshotCreditAuthority;
        for (saved.outcome_intents[0..index]) |previous| if (std.meta.eql(previous.key, intent.key)) return error.InvalidSnapshotCreditAuthority;
        inline for (@typeInfo(snapshot_admission.Counts).@"struct".field_names) |name| {
            if (@field(intent.used_counts, name) > @field(intent.plan_counts, name) or @field(credit.counts, name) != @field(intent.plan_counts, name) - @field(intent.used_counts, name)) return error.InvalidSnapshotCreditAuthority;
        }
        if (!std.meta.eql(intent.key, creditKey(intent.key.kind, intent.owner_id, intent.key.generation))) return error.InvalidSnapshotCreditAuthority;
        if (intent.key.kind == .import or intent.key.kind == .observation) {
            var source: ?domain.Source = null;
            var source_generation: ?u64 = null;
            for (saved.state.sources) |candidate_source| if (eql(candidate_source.id, intent.source_id)) {
                source = candidate_source;
            };
            for (saved.import_source_authority) |authority| if (eql(authority.source_id, intent.source_id)) {
                source_generation = authority.generation;
            };
            const original_source = source orelse return error.InvalidSnapshotCreditAuthority;
            if (source_generation == null or source_generation.? != intent.source_generation or !eql(original_source.provider, intent.provider) or original_source.status == .disconnected or (intent.key.kind == .import and original_source.status != .connected)) return error.InvalidSnapshotCreditAuthority;
        }
        switch (intent.key.kind) {
            .mutation => {
                const record = (try mutations.lookup(intent.owner_id)) orelse return error.InvalidSnapshotCreditAuthority;
                if (record.kind != .external or record.state == .completed or record.expected_revision != intent.key.generation or !eql(record.method[0..record.method_len], intent.provider)) return error.InvalidSnapshotCreditAuthority;
            },
            .import => {
                var owner: ?domain.Job = null;
                for (saved.state.jobs) |job| if (eql(job.id, intent.owner_id)) {
                    owner = job;
                };
                const job = owner orelse return error.InvalidSnapshotCreditAuthority;
                if (job.operation_generation != intent.key.generation or job.kind != .enrollment or job.status == .completed or !eql(intent.secondary_id, intent.source_id)) return error.InvalidSnapshotCreditAuthority;
                const plan = try domain.importGrowth(intent.provider, intent.secondary_id, intent.label);
                if (intent.plan_bytes < plan.bytes or !std.meta.eql(intent.plan_counts, plan.counts())) return error.InvalidSnapshotCreditAuthority;
            },
            .request => {
                var owner: ?request_authority.Attempt = null;
                for (saved.request_authority.records) |record| {
                    if (eql(record.first.lease_handle, intent.owner_id)) owner = record.first;
                    if (record.alternate) |attempt| if (eql(attempt.lease_handle, intent.owner_id)) {
                        owner = attempt;
                    };
                }
                const attempt = owner orelse return error.InvalidSnapshotCreditAuthority;
                if (!unresolvedAttempt(attempt) or attempt.issued_sequence != intent.key.generation) return error.InvalidSnapshotCreditAuthority;
                var lease: ?domain.Lease = null;
                for (saved.state.leases) |candidate| if (eql(candidate.id, intent.owner_id)) {
                    lease = candidate;
                };
                const held = lease orelse return error.InvalidSnapshotCreditAuthority;
                const plan = try domain.reportGrowth(held);
                if (intent.plan_bytes < plan.bytes or !std.meta.eql(intent.plan_counts, plan.counts())) return error.InvalidSnapshotCreditAuthority;
            },
            .observation => {
                const grant = state.grant(intent.owner_id) orelse return error.InvalidSnapshotCreditAuthority;
                if (grant.generation != intent.grant_generation or !eql(grant.account_id, intent.secondary_id) or !eql(grant.source_id, intent.source_id)) return error.InvalidSnapshotCreditAuthority;
                const plan = try domain.observationGrowth(intent.provider, intent.secondary_id);
                if (intent.plan_bytes < plan.bytes or !std.meta.eql(intent.plan_counts, plan.counts())) return error.InvalidSnapshotCreditAuthority;
            },
            .rotation => {
                if (!eql(intent.owner_id, "integration-recovery") and !eql(intent.owner_id, "fixture-integration-recovery")) return error.InvalidSnapshotCreditAuthority;
                if (eql(intent.owner_id, "integration-recovery") and !eql(intent.provider, "all")) return error.InvalidSnapshotCreditAuthority;
                if (eql(intent.owner_id, "fixture-integration-recovery") and (!builtin.is_test or intent.secondary_id.len == 0 or (!eql(intent.provider, "git") and !eql(intent.provider, "codex")))) return error.InvalidSnapshotCreditAuthority;
                if (!std.meta.eql(intent.plan_counts, snapshot_admission.Counts{})) return error.InvalidSnapshotCreditAuthority;
                if (intent.plan_bytes < try integrationRecoveryGrowth()) return error.InvalidSnapshotCreditAuthority;
            },
            .native_registration, .native_detach => {
                const reference = intent.native_ref orelse return error.InvalidNativeCreditAuthority;
                const row = native.lookupAttachment(reference) orelse return error.InvalidNativeCreditAuthority;
                const owner = native.lookupOwnerForRef(reference) orelse return error.InvalidNativeCreditAuthority;
                if (!eql(owner.application, "codex") or intent.owner_id.len != 64 or intent.plan_bytes != 1 or intent.used_bytes != 0 or !std.meta.eql(intent.plan_counts, snapshot_admission.Counts{})) return error.InvalidNativeCreditAuthority;
                const operation: native_owner.OperationId = intent.owner_id[0..64].*;
                try native_owner.validateOperation(operation);
                if (intent.key.kind == .native_registration) {
                    if (!std.mem.eql(u8, &row.registration_operation, &operation) or intent.key.generation != reference.adapter_epoch or !eql(intent.provider, "adapter.owner.register") or (row.phase != .pending_registration and !(row.phase == .unresolved and row.unresolved_from == .registration))) return error.InvalidNativeCreditAuthority;
                    const internal_id = nativeRegistrationMutationId(operation);
                    const mutation = (try mutations.lookup(&internal_id)) orelse return error.InvalidNativeCreditAuthority;
                    if (!eql(mutation.method[0..mutation.method_len], "adapter.owner.register") or mutation.kind != .external or mutation.state == .completed) return error.InvalidNativeCreditAuthority;
                } else {
                    if (row.detach_operation == null or !std.mem.eql(u8, &row.detach_operation.?, &operation) or intent.key.generation != reference.attachment_generation or (row.phase != .pending_detach and !(row.phase == .unresolved and row.unresolved_from == .detachment))) return error.InvalidNativeCreditAuthority;
                    if (intent.secondary_id.len != 64) return error.InvalidNativeCreditAuthority;
                    const mutation = (try mutations.lookup(intent.secondary_id)) orelse return error.InvalidNativeCreditAuthority;
                    if (mutation.kind != .external or (!eql(mutation.method[0..mutation.method_len], "integrations.detach") and !eql(mutation.method[0..mutation.method_len], "integrations.remove")) or !eql(intent.provider, mutation.method[0..mutation.method_len])) return error.InvalidNativeCreditAuthority;
                    if (eql(intent.provider, "integrations.detach")) {
                        if (!eql(intent.owner_id, intent.secondary_id)) return error.InvalidNativeCreditAuthority;
                    } else {
                        const removal = native.applicationRemoval("codex", reference.adapter_epoch) orelse return error.InvalidNativeCreditAuthority;
                        const child = nativeDetachOperation(removal.operation, reference);
                        if (!std.mem.eql(u8, &child, &operation)) return error.InvalidNativeCreditAuthority;
                    }
                }
            },
        }
    }
    if (saved.lifecycle_measurements) |measurements| {
        try measurements.validate();
    }
    var candidate = saved;
    candidate.schema_version = 2;
    const maintenance = try maintenanceReservation(candidate);
    if (saved.schema_version == 2 and (saved.maintenance_growth_bytes == null or saved.maintenance_growth_bytes.? != maintenance)) return error.InvalidMaintenanceReservation;
    candidate.maintenance_growth_bytes = maintenance;
    _ = snapshot_admission.checkEnvelopeWithNative(candidate, requests.reservedSnapshotBytes(), mutations.reservedSnapshotBytes(), try native.reservedSnapshotBytes()) catch |err| {
        if (saved.schema_version == 1 and (err == error.SnapshotTooLarge or err == error.SnapshotCardinalityExceeded)) return error.SnapshotAdmissionMigrationRequired;
        return err;
    };
}

fn validateNativeLink(ledger: *const native_owner.Ledger, reference: native_owner.NativeRef, application: []const u8, session: []const u8) !*const native_owner.Attachment {
    try reference.validate();
    const owner = ledger.lookupOwnerForRef(reference) orelse return error.InvalidNativeAttribution;
    const row = ledger.lookupAttachment(reference) orelse return error.InvalidNativeAttribution;
    if (!eql(application, "codex") or !eql(owner.application, application) or owner.adapter_epoch != reference.adapter_epoch or owner.endpoint_generation != reference.endpoint_generation or !eql(row.thread_id, session)) return error.InvalidNativeAttribution;
    return row;
}
fn validateNativeAttribution(allocator: std.mem.Allocator, saved: Persisted, ledger: *const native_owner.Ledger) !void {
    for (saved.state.bindings) |binding| {
        if (binding.native_ref) |reference| {
            const row = try validateNativeLink(ledger, reference, binding.application, binding.session_id);
            if (row.phase == .retired) return error.InvalidNativeAttribution;
        } else if (eql(binding.application, "codex")) return error.NativeOwnerMigrationRequired;
    }
    for (saved.request_authority.records) |record| {
        if (record.intent.native_ref) |reference| {
            _ = try validateNativeLink(ledger, reference, record.intent.key.application, record.intent.key.session_id);
        } else if (eql(record.intent.key.application, "codex")) return error.NativeOwnerMigrationRequired;
    }
    for (saved.state.leases) |lease| {
        var matched = false;
        for (saved.request_authority.records) |record| {
            var owned = eql(record.first.lease_handle, lease.id);
            if (record.alternate) |attempt| if (eql(attempt.lease_handle, lease.id)) {
                owned = true;
            };
            if (!owned) continue;
            if (!sameOptionalNativeRef(lease.native_ref, record.intent.native_ref) or !eql(lease.binding_id, record.intent.binding_id)) return error.InvalidNativeAttribution;
            if (lease.native_ref) |reference| {
                const row = try validateNativeLink(ledger, reference, record.intent.key.application, record.intent.key.session_id);
                if (row.phase == .retired) return error.InvalidNativeAttribution;
            }
            matched = true;
        }
        if (lease.native_ref != null and !matched) return error.InvalidNativeAttribution;
    }
    for (saved.native_owner_authority.attachments) |row| {
        const internal_id = nativeRegistrationMutationId(row.registration_operation);
        var original_found = false;
        for (saved.mutation_authority.records) |record| if (eql(record.id[0..record.id_len], &internal_id)) {
            if (record.kind != .external or !eql(record.method[0..record.method_len], "adapter.owner.register")) return error.InvalidNativeAttribution;
            if (row.unresolved_from != .registration and record.state != .completed) return error.InvalidNativeAttribution;
            if (record.state == .completed) {
                const result = try std.json.parseFromSlice(std.json.Value, allocator, record.result, .{});
                defer result.deinit();
                if (result.value != .object or result.value.object.count() != 3 or !(try parseNativeRef(result.value)).same(row.reference) or !eql(try control.string(result.value, "operation_id"), &row.registration_operation)) return error.InvalidNativeAttribution;
                const registered = control.get(result.value, "registered") orelse return error.InvalidNativeAttribution;
                if (registered != .bool or registered.bool != (row.retirement != .verified_registration_no_effect)) return error.InvalidNativeAttribution;
            }
            original_found = true;
        };
        if (!original_found) return error.InvalidNativeAttribution;
        if (row.phase == .pending_registration or (row.phase == .unresolved and row.unresolved_from == .registration)) {
            if (!creditPresent(saved.snapshot_admission, creditKey(.native_registration, &row.registration_operation, row.reference.adapter_epoch))) return error.InvalidNativeCreditAuthority;
        }
        if (row.phase == .pending_detach or (row.phase == .unresolved and row.unresolved_from == .detachment)) {
            const operation = row.detach_operation orelse return error.InvalidNativeCreditAuthority;
            if (!creditPresent(saved.snapshot_admission, creditKey(.native_detach, &operation, row.reference.attachment_generation))) return error.InvalidNativeCreditAuthority;
        }
    }
    for (saved.mutation_authority.records) |record| if (eql(record.method[0..record.method_len], "adapter.owner.register")) {
        var original_found = false;
        for (saved.native_owner_authority.attachments) |row| {
            const internal_id = nativeRegistrationMutationId(row.registration_operation);
            if (eql(record.id[0..record.id_len], &internal_id)) original_found = true;
        }
        if (!original_found) return error.InvalidNativeAttribution;
    };
    if (saved.native_registry) |registry| {
        for (registry.transaction) |byte| if (!std.ascii.isHex(byte)) return error.InvalidNativeCustody;
        if (std.mem.allEqual(u8, &registry.capability_digest, 0)) return error.InvalidNativeCustody;
    }
}

fn copyDescription(allocator: std.mem.Allocator, input: SourceDescription) !SourceDescription {
    const source_id = try allocator.dupe(u8, input.source_id);
    errdefer allocator.free(source_id);
    const provider = try allocator.dupe(u8, input.provider);
    errdefer allocator.free(provider);
    const label = try allocator.dupe(u8, input.label);
    errdefer allocator.free(label);
    const path = try allocator.dupe(u8, input.path);
    return .{ .source_id = source_id, .provider = provider, .label = label, .path = path };
}

fn freeDescription(allocator: std.mem.Allocator, input: SourceDescription) void {
    allocator.free(input.source_id);
    allocator.free(input.provider);
    allocator.free(input.label);
    allocator.free(input.path);
}

fn adapterIndex(application: []const u8) !usize {
    if (eql(application, "codex")) return 0;
    if (eql(application, "claude")) return 1;
    if (eql(application, "git")) return 2;
    if (eql(application, "enrollment")) return 3;
    return error.UnknownAdapter;
}

fn bindingIdentity(application: []const u8, session: []const u8, external: []const u8) [64]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    for ([_][]const u8{ application, session, external }) |component| {
        var size: [8]u8 = undefined;
        std.mem.writeInt(u64, &size, component.len, .little);
        hash.update(&size);
        hash.update(component);
    }
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

fn bindingIdentityForOwner(application: []const u8, session: []const u8, external: []const u8, reference: ?native_owner.NativeRef) [64]u8 {
    const base = bindingIdentity(application, session, external);
    const owner = reference orelse return base;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("omux.native.binding.v2");
    hash.update(&base);
    hash.update(&owner.owner_id);
    for ([_]u64{ owner.adapter_epoch, owner.endpoint_generation, owner.thread_instance_generation, owner.attachment_generation }) |generation| {
        var bytes: [8]u8 = undefined;
        std.mem.writeInt(u64, &bytes, generation, .little);
        hash.update(&bytes);
    }
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

fn sameOptionalNativeRef(a: ?native_owner.NativeRef, b: ?native_owner.NativeRef) bool {
    if (a) |first| return if (b) |second| first.same(second) else false;
    return b == null;
}

fn parseOpaqueId(value: []const u8) ![32]u8 {
    if (value.len != 64) return error.InvalidNativeOwner;
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index| {
        const digits = value[index * 2 ..][0..2];
        for (digits) |digit| if (!std.ascii.isDigit(digit) and (digit < 'a' or digit > 'f')) return error.InvalidNativeOwner;
        byte.* = std.fmt.parseUnsigned(u8, digits, 16) catch return error.InvalidNativeOwner;
    }
    return result;
}

fn parseGeneration(value: std.json.Value) !u64 {
    if (value != .string or value.string.len == 0 or value.string.len > 20 or value.string[0] == '0') return error.InvalidNativeGeneration;
    for (value.string) |digit| if (!std.ascii.isDigit(digit)) return error.InvalidNativeGeneration;
    return std.fmt.parseUnsigned(u64, value.string, 10) catch error.InvalidNativeGeneration;
}

fn parseNativeRef(params: std.json.Value) !native_owner.NativeRef {
    const value = control.get(params, "native_ref") orelse return error.NativeOwnerRequired;
    const reference: native_owner.NativeRef = .{
        .owner_id = try parseOpaqueId(try control.string(value, "owner_id")),
        .adapter_epoch = try parseGeneration(control.get(value, "adapter_epoch") orelse return error.InvalidNativeRef),
        .endpoint_generation = try parseGeneration(control.get(value, "endpoint_generation") orelse return error.InvalidNativeRef),
        .thread_instance_generation = try parseGeneration(control.get(value, "thread_instance_generation") orelse return error.InvalidNativeRef),
        .attachment_generation = try parseGeneration(control.get(value, "attachment_generation") orelse return error.InvalidNativeRef),
    };
    try reference.validate();
    return reference;
}

pub fn mutationKind(method: []const u8) ?mutation_authority.Kind {
    if (builtin.is_test and eql(method, "fixture.externalEffect")) return .external;
    for ([_][]const u8{ "policy.set", "account.pause", "account.resume", "account.drain", "account.forget", "operation.cancel" }) |candidate| if (eql(method, candidate)) return .local_atomic;
    for ([_][]const u8{ "setup.refresh", "source.connect", "source.disconnect", "source.reconcile", "enrollment.start", "repair.start", "integrations.install", "integrations.remove", "integrations.attach", "integrations.detach" }) |candidate| if (eql(method, candidate)) return .external;
    return null;
}

fn diagnosticOperation(allocator: std.mem.Allocator, payload: []const u8, channel: Channel) reliability.Operation {
    if (channel == .browser) return .browser;
    if (channel == .adapter) return .adapter;
    var parsed = control.parse(allocator, payload) catch return .unknown;
    defer parsed.deinit();
    const method = parsed.method;
    if (eql(method, "system.health")) return .health;
    if (eql(method, "reliability.export")) return .metrics_export;
    if (eql(method, "state.snapshot") or eql(method, "events.watch")) return .snapshot;
    if (mutationKind(method) != null) return .mutation;
    return .metadata_read;
}

fn diagnosticCause(err: anyerror) reliability.Cause {
    return diagnosticCauseName(@errorName(err));
}

fn diagnosticCauseName(name: []const u8) reliability.Cause {
    if (eql(name, "SnapshotTooLarge") or eql(name, "SnapshotCardinalityExceeded")) return .local_capacity;
    if (eql(name, "ResultTooLarge") or eql(name, "NativeResultTooLarge")) return .result_bound;
    if (eql(name, "Timeout") or eql(name, "NativeTimeout")) return .timeout;
    if (eql(name, "ServiceBusy") or eql(name, "RequestLedgerFull")) return .busy;
    if (eql(name, "ServiceStopping")) return .operator_shutdown;
    if (eql(name, "CustodyUnavailable")) return .custody_unavailable;
    if (eql(name, "InvalidRequest") or eql(name, "InvalidParams") or eql(name, "WrongChannel") or eql(name, "MethodNotFound")) return .protocol_mismatch;
    return .other;
}

fn canonicalValue(allocator: std.mem.Allocator, value: std.json.Value, omit_authority: bool) !std.json.Value {
    switch (value) {
        .object => |object| {
            const keys = try allocator.dupe([]const u8, object.keys());
            std.mem.sort([]const u8, keys, {}, struct {
                fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                    return std.mem.order(u8, a, b) == .lt;
                }
            }.lessThan);
            var result: std.json.ObjectMap = .empty;
            for (keys) |key| {
                if (omit_authority and (eql(key, "operation_id") or eql(key, "expected_revision"))) continue;
                try result.put(allocator, key, try canonicalValue(allocator, object.get(key).?, false));
            }
            return .{ .object = result };
        },
        .array => |array| {
            var result: std.array_list.Managed(std.json.Value) = .init(allocator);
            for (array.items) |item| try result.append(try canonicalValue(allocator, item, false));
            return .{ .array = result };
        },
        else => return value,
    }
}

fn mutationFingerprint(allocator: std.mem.Allocator, method: []const u8, params: std.json.Value, key: envelope.Key) ![32]u8 {
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const normalized = try canonicalValue(arena.allocator(), params, true);
    const encoded = try std.json.Stringify.valueAlloc(arena.allocator(), .{ .method = method, .params = normalized }, .{});
    defer std.crypto.secureZero(u8, encoded);
    var fingerprint: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&fingerprint, encoded, &key);
    return fingerprint;
}

fn sameDemand(a: anytype, b: @TypeOf(a)) bool {
    if (!eql(a.provider, b.provider) or !eql(a.audience, b.audience) or a.purpose != b.purpose or !domain.sameResource(a.resource, b.resource) or a.required != b.required or a.scopes.len != b.scopes.len) return false;
    for (a.scopes, 0..) |scope, index| {
        for (a.scopes[0..index]) |previous| if (eql(scope, previous)) return false;
        var found = false;
        for (b.scopes) |other| if (eql(scope, other)) {
            found = true;
            break;
        };
        if (!found) return false;
    }
    for (b.scopes, 0..) |scope, index| {
        for (b.scopes[0..index]) |previous| if (eql(scope, previous)) return false;
    }
    return true;
}

test "locked vault startup keeps bounded diagnostics and refuses all custody work" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try std.testing.expectEqual(@as(c_int, 0), std.c.fchmodat(directory.dir.handle, ".", 0o700, 0));
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const current = try Engine.createConfigured(io, allocator, path, null, .default, null, true, null);
    defer current.deinit();
    try std.testing.expect(current.vault_locked and current.poisoned);
    try std.testing.expect(current.db == null and current.network == null and current.native_workers == null);
    const cleared_key: envelope.Key = @splat(0);
    try std.testing.expectEqualSlices(u8, &cleared_key, &current.root_key);
    for ([_][]const u8{ "system.handshake", "system.health", "setup.readiness", "setup.evidence", "setup.plan" }) |method| {
        const request = try std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = 1, .method = method }, .{});
        defer allocator.free(request);
        const reply = try current.dispatch(allocator, request, .control);
        defer allocator.free(reply);
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, reply, .{});
        defer parsed.deinit();
        const result = control.get(parsed.value, "result") orelse return error.UnexpectedRpcFailure;
        if (eql(method, "system.health")) {
            try std.testing.expectEqualStrings("vault_locked", try control.string(result, "status"));
            try std.testing.expect(!try control.boolean(result, "custody_available", true));
            try std.testing.expect(!try control.boolean(result, "metadata_loaded", true));
            try std.testing.expectEqualStrings("unlock_platform_vault_then_reopen_custody", try control.string(result, "recovery_action"));
            try std.testing.expect(control.get(result, "account_count").? == .null);
        }
        if (eql(method, "setup.readiness")) {
            try std.testing.expect(!try control.boolean(result, "ready", true));
            const findings = control.get(result, "findings").?.array.items;
            try std.testing.expectEqualStrings("observation_stale", try control.string(findings[2], "reason"));
            try std.testing.expectEqualStrings("refresh_observation", try control.string(findings[2], "action"));
            try std.testing.expectEqualStrings("observation_unknown", try control.string(findings[3], "reason"));
        }
    }
    for (control.methods) |method| {
        if (eql(method.name, "custody.reopen") or eql(method.name, "system.handshake") or eql(method.name, "system.health") or eql(method.name, "setup.readiness") or eql(method.name, "setup.evidence") or eql(method.name, "setup.plan")) continue;
        // Absent params is a valid envelope. An empty Zig tuple serializes
        // as [], which the control wire contract correctly refuses first.
        const request = try std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = 2, .method = method.name }, .{});
        defer allocator.free(request);
        const reply = try current.dispatch(allocator, request, method.channel);
        defer allocator.free(reply);
        var parsed = try std.json.parseFromSlice(std.json.Value, allocator, reply, .{});
        defer parsed.deinit();
        try std.testing.expectEqualStrings("VaultLocked", try control.string(control.get(parsed.value, "error").?, "message"));
    }
    for ([_][]const u8{
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"source.connect\",\"params\":[]}",
        "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"source.connect\",\"params\":true}",
    }) |malformed| {
        const refusal = try current.dispatch(allocator, malformed, .control);
        defer allocator.free(refusal);
        var result = try std.json.parseFromSlice(std.json.Value, allocator, refusal, .{});
        defer result.deinit();
        const failure = control.get(result.value, "error").?;
        try std.testing.expectEqualStrings("InvalidRequest", try control.string(failure, "message"));
        try std.testing.expectEqual(@as(i64, -32600), control.get(failure, "code").?.integer);
    }
    const native_handshake = try current.dispatch(allocator, "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"system.handshake\"}", .adapter);
    defer allocator.free(native_handshake);
    var native_result = try std.json.parseFromSlice(std.json.Value, allocator, native_handshake, .{});
    defer native_result.deinit();
    try std.testing.expectEqualStrings("VaultLocked", try control.string(control.get(native_result.value, "error").?, "message"));
    const browser_reply = try current.dispatch(allocator, "untrusted browser payload", .browser);
    defer allocator.free(browser_reply);
    var browser_result = try std.json.parseFromSlice(std.json.Value, allocator, browser_reply, .{});
    defer browser_result.deinit();
    try std.testing.expectEqualStrings("VaultLocked", try control.string(control.get(browser_result.value, "error").?, "code"));
    try std.testing.expectEqual(@as(usize, 0), current.state.sources.items.len);
    try std.testing.expectEqual(@as(usize, 0), current.mutations.snapshot().records.len);
    try std.testing.expect(current.db == null and current.network == null and current.native_workers == null);
    try std.testing.expectError(error.FileNotFound, directory.dir.statFile(io, "state.sqlite", .{ .follow_symlinks = false }));
}

test "locked existing custody retains its original database and key across explicit restart" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try std.testing.expectEqual(@as(c_int, 0), std.c.fchmodat(directory.dir.handle, ".", 0o700, 0));
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const key: envelope.Key = @splat(0x63);
    const original = try Engine.openWithKey(io, allocator, path, key);
    original.deinit();
    const before = try directory.dir.readFileAlloc(io, "state.sqlite", allocator, .limited(4 * 1024 * 1024));
    defer allocator.free(before);
    const authority_before = try directory.dir.readFileAlloc(io, "state.sqlite.authority", allocator, .limited(1024));
    defer allocator.free(authority_before);
    const locked = try Engine.createConfigured(io, allocator, path, null, .default, null, true, null);
    try std.testing.expect(locked.vault_locked and locked.db == null);
    locked.deinit();
    const after = try directory.dir.readFileAlloc(io, "state.sqlite", allocator, .limited(4 * 1024 * 1024));
    defer allocator.free(after);
    const authority_after = try directory.dir.readFileAlloc(io, "state.sqlite.authority", allocator, .limited(1024));
    defer allocator.free(authority_after);
    try std.testing.expectEqualSlices(u8, before, after);
    try std.testing.expectEqualSlices(u8, authority_before, authority_after);
    try std.testing.expectError(error.WrongKey, Engine.openWithKey(io, allocator, path, @splat(0x64)));
    const reopened = try Engine.openWithKey(io, allocator, path, key);
    defer reopened.deinit();
    try std.testing.expect(!reopened.vault_locked and !reopened.poisoned);
    try std.testing.expect(reopened.db != null);
    // Synthetic supplied key only: this is not a real platform unlock proof.
}

const ReopenVaultFixture = struct {
    mode: std.atomic.Value(u8) = .init(0),
    loads: std.atomic.Value(usize) = .init(0),
    creates: std.atomic.Value(usize) = .init(0),
    fn load(context: ?*anyopaque, _: [:0]const u8) vault.VaultError!vault.Key {
        const self: *ReopenVaultFixture = @ptrCast(@alignCast(context.?));
        _ = self.loads.fetchAdd(1, .seq_cst);
        return switch (self.mode.load(.seq_cst)) {
            0 => error.Locked,
            1 => @splat(0x63),
            2 => error.Missing,
            3 => @splat(0x64),
            4 => error.InvalidKey,
            else => error.Unavailable,
        };
    }
    fn create(context: ?*anyopaque, _: [:0]const u8) vault.VaultError!vault.Key {
        const self: *ReopenVaultFixture = @ptrCast(@alignCast(context.?));
        _ = self.creates.fetchAdd(1, .seq_cst);
        return error.Denied;
    }
    fn backend(self: *ReopenVaultFixture) vault.Backend {
        return .{ .context = self, .load_fn = load, .create_fn = create };
    }
};

fn reopenTestReply(current: *Engine, method: []const u8, channel: Channel) !std.json.Parsed(std.json.Value) {
    const allocator = std.testing.allocator;
    const payload = try std.json.Stringify.valueAlloc(allocator, .{ .jsonrpc = "2.0", .id = 1, .method = method }, .{});
    defer allocator.free(payload);
    const reply = try current.dispatch(allocator, payload, channel);
    defer allocator.free(reply);
    return std.json.parseFromSlice(std.json.Value, allocator, reply, .{});
}

test "explicit custody reopen uses actual staged SQLite and preserves the actor through eventual unlock" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try std.testing.expectEqual(@as(c_int, 0), std.c.fchmodat(directory.dir.handle, ".", 0o700, 0));
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const seed = try Engine.openWithKey(io, allocator, path, @splat(0x63));
    seed.deinit();
    var backend: ReopenVaultFixture = .{};
    const current = try Engine.createConfigured(io, allocator, path, null, .default, null, false, backend.backend());
    defer current.deinit();
    const actor_id = current.thread.?.getHandle();
    var health = try reopenTestReply(current, "system.health", .control);
    defer health.deinit();
    try std.testing.expect(control.get(control.get(health.value, "result").?, "account_count").? == .null);
    var refused = try reopenTestReply(current, "custody.reopen", .control);
    defer refused.deinit();
    try std.testing.expectEqualStrings("Locked", try control.string(control.get(refused.value, "error").?, "message"));
    try std.testing.expect(current.db == null and current.network == null and current.native_workers == null);
    backend.mode.store(1, .seq_cst);
    var reopened = try reopenTestReply(current, "custody.reopen", .control);
    defer reopened.deinit();
    const result = control.get(reopened.value, "result").?;
    try std.testing.expect(try control.boolean(result, "reopened", false));
    try std.testing.expectEqual(@as(i64, 0), control.get(result, "account_count").?.integer);
    try std.testing.expect(!try control.boolean(result, "provider_request_initiated", true));
    try std.testing.expectEqual(actor_id, current.thread.?.getHandle());
    const workers = current.native_workers;
    const loads = backend.loads.load(.seq_cst);
    var repeated = try reopenTestReply(current, "custody.reopen", .control);
    defer repeated.deinit();
    try std.testing.expect(!try control.boolean(control.get(repeated.value, "result").?, "reopened", true));
    try std.testing.expectEqual(loads, backend.loads.load(.seq_cst));
    try std.testing.expect(workers == current.native_workers);
    try std.testing.expectEqual(@as(usize, 0), backend.creates.load(.seq_cst));
    var accounts = try reopenTestReply(current, "accounts.list", .control);
    defer accounts.deinit();
    try std.testing.expectEqual(@as(usize, 0), control.get(control.get(accounts.value, "result").?, "accounts").?.array.items.len);
}

test "missing corrupt and unavailable existing wrapping keys refuse without regeneration or partial adoption" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try std.testing.expectEqual(@as(c_int, 0), std.c.fchmodat(directory.dir.handle, ".", 0o700, 0));
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const seed = try Engine.openWithKey(io, allocator, path, @splat(0x63));
    seed.deinit();
    const before = try directory.dir.readFileAlloc(io, "state.sqlite", allocator, .limited(4 * 1024 * 1024));
    defer allocator.free(before);
    var backend: ReopenVaultFixture = .{};
    const current = try Engine.createConfigured(io, allocator, path, null, .default, null, false, backend.backend());
    defer current.deinit();
    for ([_]u8{ 2, 3, 4, 5 }) |mode| {
        backend.mode.store(mode, .seq_cst);
        var reply = try reopenTestReply(current, "custody.reopen", .control);
        defer reply.deinit();
        try std.testing.expect(control.get(reply.value, "error") != null);
        try std.testing.expect(current.vault_locked and current.poisoned);
        try std.testing.expect(current.root_id == null and current.db == null and current.network == null and current.native_workers == null);
        try std.testing.expectEqualSlices(u8, &(@as(envelope.Key, @splat(0))), &current.root_key);
        try std.testing.expectEqual(@as(usize, 0), backend.creates.load(.seq_cst));
    }
    const after = try directory.dir.readFileAlloc(io, "state.sqlite", allocator, .limited(4 * 1024 * 1024));
    defer allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    backend.mode.store(1, .seq_cst);
    var successful = try reopenTestReply(current, "custody.reopen", .control);
    defer successful.deinit();
    try std.testing.expect(control.get(successful.value, "result") != null);
}

test "custody reopen rejects asserted secret authority foreign channels and expired admission" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try std.testing.expectEqual(@as(c_int, 0), std.c.fchmodat(directory.dir.handle, ".", 0o700, 0));
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    var backend: ReopenVaultFixture = .{};
    const current = try Engine.createConfigured(io, allocator, path, null, .default, null, false, backend.backend());
    defer current.deinit();
    const loads = backend.loads.load(.seq_cst);
    const bad = try current.dispatch(allocator, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"custody.reopen\",\"params\":{\"key\":\"synthetic-public-invalid\"}}", .control);
    defer allocator.free(bad);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, bad, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("InvalidParams", try control.string(control.get(parsed.value, "error").?, "message"));
    var foreign = try reopenTestReply(current, "custody.reopen", .adapter);
    defer foreign.deinit();
    try std.testing.expectEqualStrings("VaultLocked", try control.string(control.get(foreign.value, "error").?, "message"));
    try std.testing.expectError(error.Timeout, current.dispatchUntil(allocator, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"custody.reopen\"}", .control, .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(-1) })));
    try std.testing.expectEqual(loads, backend.loads.load(.seq_cst));
}

test "failed custody stage closes real database and permits a clean later retry" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try std.testing.expectEqual(@as(c_int, 0), std.c.fchmodat(directory.dir.handle, ".", 0o700, 0));
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const seed = try Engine.openWithKey(io, allocator, path, @splat(0x63));
    seed.deinit();
    var backend: ReopenVaultFixture = .{};
    const current = try Engine.createConfigured(io, allocator, path, null, .default, null, false, backend.backend());
    defer current.deinit();
    backend.mode.store(1, .seq_cst);
    for ([_]@TypeOf(current.fixture_custody_stage_failure){ .database_open, .supervisor_ready }) |fault| {
        current.mutex.lockUncancelable(io);
        current.fixture_custody_stage_failure = fault;
        current.mutex.unlock(io);
        var failed = try reopenTestReply(current, "custody.reopen", .control);
        defer failed.deinit();
        try std.testing.expectEqualStrings("CustodyStageFailure", try control.string(control.get(failed.value, "error").?, "message"));
        try std.testing.expect(current.db == null and current.root_id == null and current.network == null and current.native_workers == null);
        try std.testing.expectEqualSlices(u8, &(@as(envelope.Key, @splat(0))), &current.root_key);
    }
    current.mutex.lockUncancelable(io);
    current.fixture_custody_stage_failure = .none;
    current.mutex.unlock(io);
    var successful = try reopenTestReply(current, "custody.reopen", .control);
    defer successful.deinit();
    try std.testing.expect(control.get(successful.value, "result") != null);
    try std.testing.expectEqual(@as(usize, 0), backend.creates.load(.seq_cst));
}

const ReopenCaller = struct {
    engine: *Engine,
    reopened: bool = false,
    failure: ?anyerror = null,
    fn run(self: *ReopenCaller) void {
        self.call() catch |err| {
            self.failure = err;
        };
    }
    fn call(self: *ReopenCaller) !void {
        var reply = try reopenTestReply(self.engine, "custody.reopen", .control);
        defer reply.deinit();
        const result = control.get(reply.value, "result") orelse return error.UnexpectedRpcFailure;
        self.reopened = try control.boolean(result, "reopened", false);
    }
};

test "concurrent explicit reopen requests adopt one custody owner and one supervisor" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try std.testing.expectEqual(@as(c_int, 0), std.c.fchmodat(directory.dir.handle, ".", 0o700, 0));
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const seed = try Engine.openWithKey(io, allocator, path, @splat(0x63));
    seed.deinit();
    var backend: ReopenVaultFixture = .{};
    const current = try Engine.createConfigured(io, allocator, path, null, .default, null, false, backend.backend());
    defer current.deinit();
    const loads = backend.loads.load(.seq_cst);
    backend.mode.store(1, .seq_cst);
    var first: ReopenCaller = .{ .engine = current };
    var second: ReopenCaller = .{ .engine = current };
    const one = try std.Thread.spawn(.{}, ReopenCaller.run, .{&first});
    const two = std.Thread.spawn(.{}, ReopenCaller.run, .{&second}) catch |err| {
        one.join();
        return err;
    };
    one.join();
    two.join();
    try std.testing.expect(first.failure == null and second.failure == null);
    try std.testing.expect(first.reopened != second.reopened);
    try std.testing.expectEqual(loads + 1, backend.loads.load(.seq_cst));
    try std.testing.expect(current.native_workers != null and current.db != null);
    try std.testing.expectEqual(@as(usize, 0), backend.creates.load(.seq_cst));
}

test "reopened status counts genuinely retained accounts rather than treating unloaded metadata as zero" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try std.testing.expectEqual(@as(c_int, 0), std.c.fchmodat(directory.dir.handle, ".", 0o700, 0));
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    var model = domain.State.init(allocator);
    defer model.deinit();
    _ = try model.connectSource(.{ .id = "fixture-count-source", .kind = .explicit, .provider = "github" });
    _ = try model.enroll(.{ .account_id = "fixture-count-account", .source_id = "fixture-count-source", .identity = .{ .provider = "github", .issuer = "https://github.com", .subject = "fixture-count-subject", .verified = true } }, 1);
    const metadata = try std.json.Stringify.valueAlloc(allocator, Persisted{ .state = model.snapshot() }, .{});
    defer allocator.free(metadata);
    const database = try std.fmt.allocPrintSentinel(allocator, "{s}/state.sqlite", .{path}, 0);
    defer allocator.free(database);
    {
        var store = try storage.Store.openRootWithSnapshotValidator(io, allocator, database, instance.Selection.default.vaultRoot(), @splat(0x63), validatePersistedAdmission);
        defer store.close();
        _ = try store.commit(0, metadata, &.{});
    }
    var backend: ReopenVaultFixture = .{};
    const current = try Engine.createConfigured(io, allocator, path, null, .default, null, false, backend.backend());
    defer current.deinit();
    var initial = try reopenTestReply(current, "system.health", .control);
    defer initial.deinit();
    try std.testing.expect(control.get(control.get(initial.value, "result").?, "account_count").? == .null);
    current.mutex.lockUncancelable(io);
    current.fixture_custody_stage_failure = .state_allocation;
    current.mutex.unlock(io);
    backend.mode.store(1, .seq_cst);
    var refused = try reopenTestReply(current, "custody.reopen", .control);
    defer refused.deinit();
    try std.testing.expectEqualStrings("OutOfMemory", try control.string(control.get(refused.value, "error").?, "message"));
    try std.testing.expect(current.vault_locked and current.db == null and current.root_id == null and current.native_workers == null);
    try std.testing.expectEqualSlices(u8, &(@as(envelope.Key, @splat(0))), &current.root_key);
    current.mutex.lockUncancelable(io);
    current.fixture_custody_stage_failure = .none;
    current.mutex.unlock(io);
    var reopened = try reopenTestReply(current, "custody.reopen", .control);
    defer reopened.deinit();
    try std.testing.expectEqual(@as(i64, 1), control.get(control.get(reopened.value, "result").?, "account_count").?.integer);
    var health = try reopenTestReply(current, "system.health", .control);
    defer health.deinit();
    try std.testing.expectEqual(@as(i64, 1), control.get(control.get(health.value, "result").?, "account_count").?.integer);
    try std.testing.expectEqual(@as(usize, 0), backend.creates.load(.seq_cst));
}

test "snapshot maintenance float reserve covers decimal smallest subnormals" {
    const smallest: f64 = @bitCast(@as(u64, 1));
    const range = try scalarRange(f64);
    const positive = try snapshot_admission.countJson(smallest, storage.maximum_snapshot_bytes);
    const negative = try snapshot_admission.countJson(-smallest, storage.maximum_snapshot_bytes);
    const largest = try snapshot_admission.countJson(std.math.floatMax(f64), storage.maximum_snapshot_bytes);
    try std.testing.expect(positive > largest);
    try std.testing.expect(negative <= range.maximum);
    try std.testing.expectEqual(negative - range.minimum, try scalarWidening(-smallest));
    const before: Persisted = .{};
    const observation: domain.Observation = .{ .account_id = "maintenance-account", .resource = .{ .kind = "maintenance-resource" }, .bucket_id = "maintenance-bucket", .remaining = -smallest, .limit = smallest, .window_start = 0, .window_end = 0, .observed_at = 0, .expires_at = 0, .provenance = .fixture };
    var after = before;
    after.state.observations = &.{observation};
    try std.testing.expectEqual(try scalarWidening(observation), (try maintenanceReservation(before)) - (try maintenanceReservation(after)));
}

test "saturated actor restart prepays SQL missing-ciphertext grant status overlay" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const Rpc = struct {
        fn call(actor_engine: *Engine, channel: Channel, method: []const u8, params: anytype) !std.json.Parsed(std.json.Value) {
            const request = try std.json.Stringify.valueAlloc(std.testing.allocator, .{ .jsonrpc = "2.0", .id = 1, .method = method, .params = params }, .{});
            defer {
                std.crypto.secureZero(u8, request);
                std.testing.allocator.free(request);
            }
            const response = try actor_engine.dispatch(std.testing.allocator, request, channel);
            defer std.testing.allocator.free(response);
            var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, response, .{ .allocate = .alloc_always });
            errdefer {
                control.wipeJson(parsed.value);
                parsed.deinit();
            }
            if (control.get(parsed.value, "result") == null) return error.UnexpectedRpcFailure;
            return parsed;
        }
    };
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try std.testing.expectEqual(@as(c_int, 0), std.c.fchmodat(directory.dir.handle, ".", 0o700, 0));
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    var key: envelope.Key = undefined;
    try io.randomSecure(&key);
    defer std.crypto.secureZero(u8, &key);
    var engine: ?*Engine = try Engine.openWithKey(io, allocator, path, key);
    defer if (engine) |current| current.deinit();
    var connected = try Rpc.call(engine.?, .control, "source.connect", .{ .operation_id = "startup-overlay-source", .expected_revision = engine.?.revision, .kind = "explicit", .provider = "codex" });
    defer {
        control.wipeJson(connected.value);
        connected.deinit();
    }
    const source_id = try control.string(control.get(connected.value, "result").?, "source_id");
    var capability = try engine.?.capabilityForTest("enrollment");
    defer std.crypto.secureZero(u8, &capability);
    var random: [32]u8 = undefined;
    try io.randomSecure(&random);
    defer std.crypto.secureZero(u8, &random);
    var token = std.fmt.bytesToHex(random, .lower);
    defer std.crypto.secureZero(u8, &token);
    try io.randomSecure(&random);
    var subject = std.fmt.bytesToHex(random, .lower);
    defer std.crypto.secureZero(u8, &subject);
    var enrolled = try Rpc.call(engine.?, .adapter, "fixture.enroll", .{ .application = "enrollment", .capability = capability[0..], .source_id = source_id, .provider = "codex", .audience = "https://chatgpt.com", .subject = subject[0..], .access_token = token[0..] });
    defer {
        control.wipeJson(enrolled.value);
        enrolled.deinit();
    }
    const admitted = control.get(enrolled.value, "result").?;
    const account_id = try control.string(admitted, "account_id");
    const grant_id = try control.string(admitted, "grant_id");
    var saturated = try Rpc.call(engine.?, .adapter, "fixture.snapshotSaturate", .{ .application = "enrollment", .capability = capability[0..], .spare_bytes = 0 });
    defer {
        control.wipeJson(saturated.value);
        saturated.deinit();
    }
    var before = try Rpc.call(engine.?, .adapter, "fixture.snapshotBudget", .{ .application = "enrollment", .capability = capability[0..] });
    defer {
        control.wipeJson(before.value);
        before.deinit();
    }
    const before_budget = control.get(before.value, "result").?;
    try std.testing.expectEqual(@as(i64, 0), control.get(before_budget, "remaining_bytes").?.integer);
    engine.?.deinit();
    engine = null;
    {
        const database_path = try std.fmt.allocPrintSentinel(allocator, "{s}/state.sqlite", .{path}, 0);
        defer allocator.free(database_path);
        const root_id = try storage.Store.readRootId(allocator, database_path);
        defer allocator.free(root_id);
        var store = try storage.Store.openRoot(io, allocator, database_path, root_id, key);
        defer store.close();
        var saved = try store.readSnapshot();
        defer saved.deinit();
        // A settled missing ciphertext is distinct from a pending SQL rotation.
        // Keep the admitted metadata byte-for-byte, then exercise real startup.
        _ = try store.commit(saved.revision, saved.json, &.{.{ .delete = .{ .account_id = account_id, .grant_id = grant_id } }});
    }
    engine = try Engine.openWithKey(io, allocator, path, key);
    var snapshot = try Rpc.call(engine.?, .control, "state.snapshot", @as(?u8, null));
    defer {
        control.wipeJson(snapshot.value);
        snapshot.deinit();
    }
    const grants = control.get(control.get(snapshot.value, "result").?, "grants").?;
    try std.testing.expectEqual(@as(usize, 1), grants.array.items.len);
    try std.testing.expectEqualStrings("invalid", try control.string(grants.array.items[0], "status"));
    var after = try Rpc.call(engine.?, .adapter, "fixture.snapshotBudget", .{ .application = "enrollment", .capability = capability[0..] });
    defer {
        control.wipeJson(after.value);
        after.deinit();
    }
    const after_budget = control.get(after.value, "result").?;
    try std.testing.expectEqual(control.get(before_budget, "reserved_bytes").?.integer, control.get(after_budget, "reserved_bytes").?.integer);
    try std.testing.expect(control.get(after_budget, "maintenance_growth_bytes").?.integer < control.get(before_budget, "maintenance_growth_bytes").?.integer);
}

test "actor state survives restart and control cannot materialize credentials" {
    const allocator = std.testing.allocator;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try std.testing.expectEqual(@as(c_int, 0), std.c.fchmodat(directory.dir.handle, ".", 0o700, 0));
    const path = try directory.dir.realPathFileAlloc(std.testing.io, ".", allocator);
    defer allocator.free(path);
    var engine = try Engine.openWithKey(std.testing.io, allocator, path, @splat(9));
    const request = try std.fmt.allocPrint(allocator, "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"source.connect\",\"params\":{{\"operation_id\":\"test-connect\",\"expected_revision\":{d},\"kind\":\"explicit\",\"provider\":\"github\",\"label\":\"work\"}}}}", .{engine.revision});
    defer allocator.free(request);
    const connected = try engine.dispatch(allocator, request, .control);
    defer allocator.free(connected);
    try std.testing.expect(std.mem.indexOf(u8, connected, "authorized") != null);
    const denied = try engine.dispatch(allocator, "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"adapter.materialize\",\"params\":{}}", .control);
    defer allocator.free(denied);
    try std.testing.expect(std.mem.indexOf(u8, denied, "WrongChannel") != null);
    engine.deinit();
    engine = try Engine.openWithKey(std.testing.io, allocator, path, @splat(9));
    defer engine.deinit();
    const snapshot = try engine.dispatch(allocator, "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"state.snapshot\"}", .control);
    defer allocator.free(snapshot);
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "work") != null);
    try std.testing.expect(std.mem.indexOf(u8, snapshot, "access_token") == null);
}

test "public account identity exposes only provider and actual verification truth" {
    const allocator = std.testing.allocator;
    for ([_]bool{ true, false }) |verified| {
        // Threadless DTO model reports the stored identity bit. The same
        // projector is used by the actor's actual publicSnapshot serializer.
        const account: domain.Account = .{
            .id = "public-account-model",
            .identity = .{
                .provider = "codex",
                .issuer = "private-issuer-model",
                .subject = "private-subject-model",
                .tenant = "private-tenant-model",
                .verified = verified,
            },
            .source_ids = &.{"public-source-model"},
        };
        const raw = try std.json.Stringify.valueAlloc(allocator, publicAccountView(account), .{});
        defer allocator.free(raw);
        const parsed = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
        defer parsed.deinit();
        const identity = control.get(parsed.value, "identity").?;
        try std.testing.expectEqual(@as(usize, 2), identity.object.count());
        try std.testing.expectEqualStrings("codex", try control.string(identity, "provider"));
        try std.testing.expectEqual(verified, control.get(identity, "verified").?.bool);
        for ([_][]const u8{ "issuer", "subject", "tenant" }) |field| try std.testing.expect(control.get(identity, field) == null);
        try std.testing.expect(std.mem.indexOf(u8, raw, "private-issuer-model") == null);
        try std.testing.expect(std.mem.indexOf(u8, raw, "private-subject-model") == null);
        try std.testing.expect(std.mem.indexOf(u8, raw, "private-tenant-model") == null);
    }
}

test "setup usable authority follows its own source authorization and actual routing" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try std.testing.expectEqual(@as(c_int, 0), std.c.fchmodat(directory.dir.handle, ".", 0o700, 0));
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    // Threadless synthetic state: direct model mutations have one owner.
    // No actor maintenance, database, platform-vault or provider work exists.
    var current: Engine = .{
        .allocator = allocator,
        .io = io,
        .state_dir = @constCast(path),
        .state = domain.State.init(allocator),
        .observers = observer.Coordinator.init(allocator),
        .requests = request_authority.Ledger.init(allocator, 4096),
        .mutations = try mutation_authority.Ledger.init(allocator, 4096),
        .admission = snapshot_admission.Ledger.init(allocator),
        .native_owners = native_owner.Ledger.init(allocator),
        .metrics = reliability.Recorder.init(0, .{ .evidence = .synthetic }),
    };
    defer current.release();
    try std.testing.expect(current.thread == null and current.db == null and current.network == null);
    const timestamp = current.now();
    _ = try current.state.connectSource(.{ .id = "first-source", .kind = .native_store, .provider = "codex", .authorized_at = 0, .authorized_until = timestamp + 3600 });
    _ = try current.state.connectSource(.{ .id = "unrelated-source", .kind = .native_store, .provider = "codex", .authorized_at = 0 });
    _ = try current.state.enroll(.{ .account_id = "first-account", .source_id = "first-source", .identity = .{ .provider = "codex", .issuer = "https://chatgpt.com", .subject = "fixture-subject", .verified = true } }, timestamp);
    _ = try current.state.addGrant(.{ .id = "first-grant", .account_id = "first-account", .source_id = "first-source", .credential_kind = .oauth_access, .purposes = &.{.request}, .audience = "https://chatgpt.com", .provider_expires_at = timestamp + 7200, .custody_expires_at = timestamp + 7200, .generation = 7 });
    const demand: domain.Demand = .{ .provider = "codex", .audience = "https://chatgpt.com", .resource = .{ .kind = "model", .target = "fixture" }, .now = timestamp };
    try std.testing.expectEqual(onboarding.State.ready, current.setupSnapshot(.{}, false).grant.state);
    try std.testing.expectEqual(@as(u64, 7), (try current.state.select(demand, null)).generation);
    // Detachment does not revoke independent, still-authorized access authority.
    current.state.sources.items[0].status = .detached;
    try std.testing.expectEqual(onboarding.State.ready, current.setupSnapshot(.{}, false).grant.state);
    _ = try current.state.select(demand, null);
    // A different connected source cannot renew this grant's expired lineage.
    current.state.sources.items[0].authorized_until = timestamp;
    const expired = current.setupSnapshot(.{}, false);
    try std.testing.expectEqual(onboarding.State.ready, expired.source.state);
    try std.testing.expectEqual(onboarding.State.ready, expired.identity.state);
    try std.testing.expectEqual(onboarding.State.missing, expired.grant.state);
    try std.testing.expect(!onboarding.assess(expired).ready);
    try std.testing.expectError(error.NoEligibleAccount, current.state.select(demand, null));
    // Future authorization and explicit disconnection use the same routing fence.
    current.state.sources.items[0].authorized_at = timestamp + 3600;
    current.state.sources.items[0].authorized_until = timestamp + 7200;
    try std.testing.expectEqual(onboarding.State.missing, current.setupSnapshot(.{}, false).grant.state);
    try std.testing.expectError(error.NoEligibleAccount, current.state.select(demand, null));
    current.state.sources.items[0].authorized_at = 0;
    current.state.sources.items[0].status = .disconnected;
    try std.testing.expectEqual(onboarding.State.missing, current.setupSnapshot(.{}, false).grant.state);
    try std.testing.expectError(error.NoEligibleAccount, current.state.select(demand, null));
    try std.testing.expectEqual(@as(u64, 7), current.state.grants.items[0].generation);
}

test "Git route cache retires oldest idle context while preserving native and leased routes" {
    const allocator = std.testing.allocator;
    var state = domain.State.init(allocator);
    defer state.deinit();
    _ = try state.connectSource(.{ .id = "fixture-source", .kind = .explicit, .provider = "github" });
    _ = try state.enroll(.{ .account_id = "fixture-account", .source_id = "fixture-source", .identity = .{ .provider = "github", .issuer = "https://github.com", .subject = "fixture-subject", .verified = true } }, 1);
    _ = try state.addGrant(.{ .id = "fixture-grant", .account_id = "fixture-account", .source_id = "fixture-source", .credential_kind = .oauth_access, .purposes = &.{.request}, .audience = "https://github.com" });
    for ([_][]const u8{ "native-route", "leased-git-route", "current-git-route" }) |id| {
        _ = try state.bind(.{ .id = id, .application = if (eql(id, "native-route")) "codex" else "git", .session_id = id, .account_id = "fixture-account", .grant_id = "fixture-grant", .grant_generation = 1, .last_used_revision = 1 });
    }
    _ = try state.beginLease(.{ .id = "fixture-lease", .binding_id = "leased-git-route", .account_id = "fixture-account", .grant_id = "fixture-grant", .grant_generation = 1, .route_generation = 1, .purpose = .request, .started_at = 1, .expires_at = 100 }, 2);
    const initial_binding_count = domain.max_records - 64;
    for (0..initial_binding_count - 3) |index| {
        const id = try std.fmt.allocPrint(allocator, "fixture-git-{d}", .{index});
        defer allocator.free(id);
        _ = try state.bind(.{ .id = id, .application = "git", .session_id = id, .account_id = "fixture-account", .grant_id = "fixture-grant", .grant_generation = 1, .last_used_revision = index + 2 });
    }
    try Engine.retireIdleGitBindings(&state, "current-git-route");
    try std.testing.expectEqual(initial_binding_count - 1, state.bindings.items.len);
    try std.testing.expect(state.binding("fixture-git-0") == null);
    try std.testing.expect(state.binding("fixture-git-1") != null);
    try std.testing.expect(state.binding("current-git-route") != null);
    try std.testing.expect(state.binding("native-route") != null);
    try std.testing.expectEqual(@as(u32, 1), state.binding("leased-git-route").?.in_flight);
    try std.testing.expectEqual(@as(usize, 1), state.leases.items.len);
    try std.testing.expectEqual(domain.GrantStatus.ready, state.grant("fixture-grant").?.status);
    try std.testing.expectEqual(domain.AccountLifecycle.active, state.account("fixture-account").?.lifecycle);
}

test "native registration completion matches strict producer fields with lossless maximum generations" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const operation: native_owner.OperationId = @splat('b');
    const reference: native_owner.NativeRef = .{ .owner_id = @splat(7), .adapter_epoch = std.math.maxInt(u64), .endpoint_generation = std.math.maxInt(u64), .thread_instance_generation = std.math.maxInt(u64), .attachment_generation = std.math.maxInt(u64) };
    const result = try nativeRegistrationResult(allocator, operation, reference);
    const encoded = try std.json.Stringify.valueAlloc(allocator, result, .{});
    try std.testing.expect(encoded.len <= mutation_authority.max_result_bytes);
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, encoded, .{});
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 3), parsed.value.object.count());
    try std.testing.expect(control.get(parsed.value, "detached") == null);
    try std.testing.expect(control.get(parsed.value, "registered").?.bool);
    try std.testing.expectEqualStrings(&operation, try control.string(parsed.value, "operation_id"));
    const wire = control.get(parsed.value, "native_ref").?;
    for ([_][]const u8{ "adapter_epoch", "endpoint_generation", "thread_instance_generation", "attachment_generation" }) |field| try std.testing.expectEqualStrings("18446744073709551615", try control.string(wire, field));
    try std.testing.expect((try parseNativeRef(parsed.value)).same(reference));
    const internal = nativeRegistrationMutationId(operation);
    try std.testing.expect(!eql(&operation, &internal));
    try std.testing.expectEqualStrings(&internal, &nativeRegistrationMutationId(operation));
}

test "lifecycle activation prepays bounded widening while legacy null keeps original reserve" {
    const legacy: Persisted = .{};
    const legacy_reserve = try maintenanceReservation(legacy);
    var active = legacy;
    const recorder = try reliability.LifecycleRecorder.create(std.testing.allocator, 0, .{ .evidence = .synthetic });
    defer std.testing.allocator.destroy(recorder);
    active.lifecycle_measurements = recorder;
    const initial_bytes = try snapshot_admission.countJson(active.lifecycle_measurements.?, reliability.max_lifecycle_checkpoint_bytes);
    try std.testing.expectEqual(reliability.max_lifecycle_checkpoint_bytes - initial_bytes, (try maintenanceReservation(active)) - legacy_reserve);
    try recorder.record(0, .{ .operation_correlation = 1, .phase = .remove, .outcome = .success });
    const grown_bytes = try snapshot_admission.countJson(active.lifecycle_measurements.?, reliability.max_lifecycle_checkpoint_bytes);
    try std.testing.expectEqual(reliability.max_lifecycle_checkpoint_bytes, grown_bytes + (try maintenanceReservation(active)) - legacy_reserve);
    const encoded = try std.json.Stringify.valueAlloc(std.testing.allocator, legacy, .{});
    defer std.testing.allocator.free(encoded);
    try validatePersistedAdmission(std.testing.allocator, encoded, 0);
}

test "external source removal counts terminal completion once and skips telemetry under capacity pressure" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const Rpc = struct {
        fn call(current: *Engine, channel: Channel, method: []const u8, params: anytype) !std.json.Parsed(std.json.Value) {
            const payload = try std.json.Stringify.valueAlloc(std.testing.allocator, .{ .jsonrpc = "2.0", .id = 1, .method = method, .params = params }, .{});
            defer std.testing.allocator.free(payload);
            const bytes = try current.dispatch(std.testing.allocator, payload, channel);
            defer std.testing.allocator.free(bytes);
            var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, bytes, .{ .allocate = .alloc_always });
            errdefer parsed.deinit();
            if (control.get(parsed.value, "result") == null) return error.UnexpectedRpcFailure;
            return parsed;
        }
    };
    try std.testing.expectEqual(mutation_authority.Kind.external, mutationKind("source.disconnect").?);
    for ([_]bool{ false, true }) |constrained| {
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        try std.testing.expectEqual(@as(c_int, 0), std.c.fchmodat(directory.dir.handle, ".", 0o700, 0));
        const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
        defer allocator.free(path);
        var key: envelope.Key = undefined;
        try io.randomSecure(&key);
        defer std.crypto.secureZero(u8, &key);
        var current: ?*Engine = try Engine.openWithKey(io, allocator, path, key);
        defer if (current) |value| value.deinit();
        var connected = try Rpc.call(current.?, .control, "source.connect", .{ .operation_id = "lifecycle-source-connect", .expected_revision = current.?.revision, .kind = "explicit", .provider = "codex" });
        defer connected.deinit();
        const source = try control.string(control.get(connected.value, "result").?, "source_id");
        if (constrained) {
            var capability = try current.?.capabilityForTest("enrollment");
            defer std.crypto.secureZero(u8, &capability);
            var saturated = try Rpc.call(current.?, .adapter, "fixture.snapshotSaturate", .{ .application = "enrollment", .capability = capability[0..], .spare_bytes = 64 * 1024 });
            saturated.deinit();
        }
        const removal = .{ .operation_id = "lifecycle-source-disconnect", .expected_revision = current.?.revision, .source_id = source };
        var removed = try Rpc.call(current.?, .control, "source.disconnect", removal);
        removed.deinit();
        var replay = try Rpc.call(current.?, .control, "source.disconnect", removal);
        replay.deinit();
        current.?.deinit();
        current = null;
        current = try Engine.openWithKey(io, allocator, path, key);
        var disconnected = false;
        for (current.?.state.sources.items) |row| if (eql(row.id, source)) {
            disconnected = row.status == .disconnected;
        };
        try std.testing.expect(disconnected);
        if (constrained) {
            try std.testing.expect(current.?.lifecycle_measurements == null);
        } else {
            const windows = try current.?.lifecycle_measurements.?.window(current.?.now());
            try std.testing.expectEqual(@as(u64, 1), windows[@backingInt(reliability.Phase.remove)][@backingInt(reliability.LifecycleOutcome.success)].count);
        }
    }
}

test "setup refresh has one owned worker, deferred publication, stale observations and joined shutdown" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    const prefix = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(prefix);
    const receipt = try std.fmt.allocPrint(allocator, "{s}/missing-installation.json", .{prefix});
    defer allocator.free(receipt);
    const state_dir = try allocator.dupe(u8, prefix);
    defer allocator.free(state_dir);
    var probe_engine: Engine = .{
        .allocator = allocator,
        .io = io,
        .state_dir = state_dir,
        .state = domain.State.init(allocator),
        .observers = observer.Coordinator.init(allocator),
        .requests = request_authority.Ledger.init(allocator, 4096),
        .mutations = try mutation_authority.Ledger.init(allocator, 4096),
        .admission = snapshot_admission.Ledger.init(allocator),
        .native_owners = native_owner.Ledger.init(allocator),
        .metrics = reliability.Recorder.init(0, .{ .evidence = .synthetic }),
    };
    defer probe_engine.release();
    probe_engine.installation_selection = blk: {
        const owned_prefix = try allocator.dupe(u8, prefix);
        errdefer allocator.free(owned_prefix);
        const owned_receipt = try allocator.dupe(u8, receipt);
        break :blk .{ .prefix = owned_prefix, .receipt_path = owned_receipt };
    };
    try probe_engine.startSetupRefresh();
    defer probe_engine.stopSetupRefresh();
    const first = probe_engine.installation_refresh.?;
    try probe_engine.startSetupRefresh();
    try std.testing.expect(first == probe_engine.installation_refresh.?);
    try std.testing.expectEqual(@as(u64, 1), probe_engine.installation_refresh_generation);
    try std.testing.expect(probe_engine.installation_probe_at == null);
    const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(3000) });
    while (!first.done.load(.acquire)) {
        if (deadline.durationFromNow(io).raw.toNanoseconds() <= 0) return error.SetupRefreshDidNotFinish;
        try io.sleep(.fromMilliseconds(1), .awake);
    }
    // Worker completion alone does not publish evidence; the actor boundary does.
    try std.testing.expect(probe_engine.installation_probe_at == null);
    probe_engine.completeSetupRefresh();
    try std.testing.expect(probe_engine.installation_refresh == null);
    try std.testing.expectEqual(setup_collector.Failure.receipt_absent, probe_engine.installation_probe.failure);
    probe_engine.installation_probe_at = probe_engine.now() - 61;
    try std.testing.expectEqual(onboarding.Freshness.stale, probe_engine.currentInstallationProbe().artifact.freshness);
    try probe_engine.startSetupRefresh();
    try std.testing.expectEqual(@as(u64, 2), probe_engine.installation_refresh_generation);
    probe_engine.stopSetupRefresh();
    try std.testing.expect(probe_engine.installation_refresh == null);
}

test "native service collection budget and stall status propagate timeout before completion" {
    try std.testing.expectError(error.Timeout, serviceObservationBudget(0));
    try std.testing.expectError(error.Timeout, serviceObservationBudget(-1));
    try std.testing.expectEqual(@as(u32, 1), try serviceObservationBudget(1));
    try std.testing.expectEqual(@as(u32, 2000), try serviceObservationBudget(std.math.maxInt(i128)));
    // OMUX_SERVICE_TIMEOUT=4 is the status returned by the independently
    // bounded C handshake-stall fixture. Projection cannot turn it into an
    // ordinary unknown service observation that counts as a completed scan.
    const stalled = try service_observation.project(.{ .status = 4 }, .{ .selection = .default });
    try std.testing.expectError(error.Timeout, serviceObservationNeedsRecheck(stalled.status));
    inline for (@typeInfo(service_observation.Status).@"enum".field_names) |name| {
        const status = std.meta.stringToEnum(service_observation.Status, name).?;
        if (status != .timeout) try std.testing.expectEqual(status == .ok, try serviceObservationNeedsRecheck(status));
    }
}

test "setup worker preserves timeout invalid deadline and allocator failure classes" {
    const io = std.testing.io;
    const selected: InstallationSelection = .{ .prefix = @constCast("/tmp"), .receipt_path = @constCast("/tmp/omux-unused-receipt") };
    var timed_out: SetupRefreshTask = .{ .io = io, .allocator = std.testing.allocator, .selected = selected, .generation = 1, .deadline = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(0) }) };
    timed_out.run();
    try std.testing.expect(timed_out.done.load(.acquire));
    try std.testing.expectEqual(error.Timeout, timed_out.collection_error.?);
    try std.testing.expectEqual(setup_collector.Failure.timed_out, timed_out.result.probe.failure);
    try std.testing.expectEqual(onboarding.Freshness.unknown, timed_out.result.probe.artifact.freshness);
    var invalid: SetupRefreshTask = .{ .io = io, .allocator = std.testing.allocator, .selected = selected, .generation = 1, .deadline = .fromNow(io, .{ .clock = .real, .raw = .fromMilliseconds(2000) }) };
    invalid.run();
    try std.testing.expectEqual(error.InvalidDeadline, invalid.collection_error.?);
    try std.testing.expectEqual(setup_collector.Failure.invalid_deadline, invalid.result.probe.failure);
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var exhausted: SetupRefreshTask = .{ .io = io, .allocator = failing.allocator(), .selected = selected, .generation = 1, .deadline = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(2000) }) };
    exhausted.run();
    try std.testing.expectEqual(error.OutOfMemory, exhausted.collection_error.?);
    try std.testing.expectEqual(setup_collector.Failure.resource_exhausted, exhausted.result.probe.failure);
}

test "browser refusal authority prepays fixed capacity and requires lifecycle transaction presence" {
    const allocator = std.testing.allocator;
    var attempts = try browser_attempt.Ledger.init(allocator);
    defer attempts.deinit();
    const legacy: Persisted = .{};
    const legacy_reserve = try maintenanceReservation(legacy);
    var active = legacy;
    active.browser_attempt_authority = attempts.snapshot();
    const initial_bytes = try snapshot_admission.countJson(active.browser_attempt_authority.?, browser_attempt.maximum_snapshot_bytes);
    try std.testing.expectEqual(browser_attempt.maximum_snapshot_bytes, initial_bytes + (try maintenanceReservation(active)) - legacy_reserve);
    _ = try attempts.refuse(@splat(1), "fixture-request", @splat(2), .needs_provider_adapter_proof, .other);
    active.browser_attempt_authority = attempts.snapshot();
    const grown_bytes = try snapshot_admission.countJson(active.browser_attempt_authority.?, browser_attempt.maximum_snapshot_bytes);
    try std.testing.expectEqual(browser_attempt.maximum_snapshot_bytes, grown_bytes + (try maintenanceReservation(active)) - legacy_reserve);
    active.schema_version = 2;
    const encoded = try std.json.Stringify.valueAlloc(allocator, active, .{});
    defer allocator.free(encoded);
    try std.testing.expectError(error.InvalidBrowserAttemptSnapshot, validatePersistedAdmission(allocator, encoded, 0));
    const unmeasured = try std.json.Stringify.valueAlloc(allocator, legacy, .{});
    defer allocator.free(unmeasured);
    try validatePersistedAdmission(allocator, unmeasured, 0);
}

test "identified setup refresh terminal authority replay busy uncertainty and diagnostic separation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try std.testing.expectEqual(@as(c_int, 0), std.c.fchmodat(directory.dir.handle, ".", 0o700, 0));
    const prefix = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(prefix);
    const database = try std.fmt.allocPrintSentinel(allocator, "{s}/verification.sqlite", .{prefix}, 0);
    defer allocator.free(database);
    var current: Engine = .{
        .allocator = allocator,
        .io = io,
        .state_dir = @constCast(prefix),
        .state = domain.State.init(allocator),
        .observers = observer.Coordinator.init(allocator),
        .requests = request_authority.Ledger.init(allocator, 4096),
        .mutations = try mutation_authority.Ledger.init(allocator, 4096),
        .admission = snapshot_admission.Ledger.init(allocator),
        .native_owners = native_owner.Ledger.init(allocator),
        .metrics = reliability.Recorder.init(0, .{ .evidence = .synthetic }),
        .root_key = @splat(73),
        .test_key = @splat(73),
        .db = try storage.Store.open(io, allocator, database, @splat(73)),
    };
    defer {
        current.stopSetupRefresh();
        current.db.?.close();
        current.release();
    }
    try current.persist(&.{});
    const Call = struct {
        fn run(actor: *Engine, params: anytype) ![]u8 {
            const payload = try std.json.Stringify.valueAlloc(std.testing.allocator, .{ .jsonrpc = "2.0", .id = 1, .method = "setup.refresh", .params = params }, .{});
            defer std.testing.allocator.free(payload);
            var request = try control.parse(std.testing.allocator, payload);
            defer request.deinit();
            return actor.handleRequest(std.testing.allocator, request, .control);
        }
    };
    const missing = .{ .operation_id = "verify-no-selection", .expected_revision = current.revision };
    const first = try Call.run(&current, missing);
    defer allocator.free(first);
    const replay = try Call.run(&current, missing);
    defer allocator.free(replay);
    try std.testing.expectEqualStrings(first, replay);
    try std.testing.expectEqual(@as(usize, 1), current.mutations.snapshot().count);
    try std.testing.expectError(error.OperationIdConflict, Call.run(&current, .{ .operation_id = missing.operation_id, .expected_revision = current.revision }));
    const revision_before = current.revision;
    const diagnostic = try Call.run(&current, @as(?u8, null));
    allocator.free(diagnostic);
    try std.testing.expectEqual(revision_before, current.revision);
    try std.testing.expectEqual(@as(usize, 1), current.mutations.snapshot().count);
    current.installation_selection = .{ .prefix = try allocator.dupe(u8, prefix), .receipt_path = try std.fmt.allocPrint(allocator, "{s}/absent-receipt", .{prefix}) };
    const active_params = .{ .operation_id = "verify-active", .expected_revision = current.revision };
    const pending = try Call.run(&current, active_params);
    defer allocator.free(pending);
    const task = current.installation_refresh.?;
    const pending_replay = try Call.run(&current, active_params);
    defer allocator.free(pending_replay);
    try std.testing.expectEqualStrings(pending, pending_replay);
    try std.testing.expect(task == current.installation_refresh.?);
    const busy = try Call.run(&current, .{ .operation_id = "verify-busy", .expected_revision = current.revision });
    allocator.free(busy);
    try std.testing.expect(task == current.installation_refresh.?);
    try std.testing.expectEqual(@as(u64, 1), current.installation_refresh_generation);
    task.thread.?.join();
    // Join only synchronizes the collector; completion still belongs to actor.
    try std.testing.expect(current.installation_probe_at == null);
    // Infrastructure failures cannot turn a started record into completion.
    inline for (.{ error.OutOfMemory, error.Canceled, error.InvalidDeadline }) |failure| {
        task.collection_error = failure;
        try std.testing.expectError(failure, current.commitSetupVerification(task, task.verification.?));
        try std.testing.expectEqual(mutation_authority.State.started, (try current.mutations.lookup(active_params.operation_id)).?.state);
    }
    task.collection_error = null;
    // Thread has already joined; prevent a second join by publishing directly.
    try current.commitSetupVerification(task, task.verification.?);
    current.installation_probe = task.result.probe;
    current.installation_probe_at = task.observed_at;
    current.installation_refresh = null;
    allocator.destroy(task);
    const completed = try Call.run(&current, active_params);
    defer allocator.free(completed);
    const terminal = (try current.mutations.lookup(active_params.operation_id)).?;
    try std.testing.expectEqual(mutation_authority.State.completed, terminal.state);
    try std.testing.expect(terminal.result_len <= mutation_authority.max_result_bytes);
    const before_timeout = try setup_verification.summarize(allocator, current.mutations.snapshot(), current.now());
    const timeout_params = .{ .operation_id = "verify-timeout", .expected_revision = current.revision };
    const timeout_pending = try Call.run(&current, timeout_params);
    allocator.free(timeout_pending);
    const timeout_task = current.installation_refresh.?;
    timeout_task.thread.?.join();
    // Re-run the bounded reader with an actually expired deadline, without
    // fabricating payload evidence or issuing any provider request.
    timeout_task.deadline = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(0) });
    timeout_task.run();
    try std.testing.expectEqual(error.Timeout, timeout_task.collection_error.?);
    try current.commitSetupVerification(timeout_task, timeout_task.verification.?);
    current.installation_probe = timeout_task.result.probe;
    current.installation_probe_at = null;
    current.installation_refresh = null;
    allocator.destroy(timeout_task);
    const timeout_reply = try Call.run(&current, timeout_params);
    defer allocator.free(timeout_reply);
    const timeout_replay = try Call.run(&current, timeout_params);
    defer allocator.free(timeout_replay);
    try std.testing.expectEqualStrings(timeout_reply, timeout_replay);
    const timeout_record = (try current.mutations.lookup(timeout_params.operation_id)).?;
    const timeout_fact = try setup_verification.parseCompletedRecord(allocator, timeout_record.*);
    defer timeout_fact.deinit();
    try std.testing.expectEqual(setup_verification.Outcome.safe_refusal, timeout_fact.value.outcome);
    try std.testing.expectEqual(setup_verification.Refusal.collection_timed_out, timeout_fact.value.refusal.?);
    try std.testing.expect(timeout_fact.value.elapsed_ns == null);
    const after_timeout = try setup_verification.summarize(allocator, current.mutations.snapshot(), current.now());
    try std.testing.expectEqual(before_timeout.verification_completed, after_timeout.verification_completed);
    try std.testing.expectEqual(before_timeout.collection_timed_out_refusals + 1, after_timeout.collection_timed_out_refusals);
    try std.testing.expectEqualDeep(before_timeout.completed_timing, after_timeout.completed_timing);
    try std.testing.expectEqualDeep(before_timeout.phases, after_timeout.phases);
    const interrupted = .{ .operation_id = "verify-interrupted", .expected_revision = current.revision };
    const interrupted_pending = try Call.run(&current, interrupted);
    allocator.free(interrupted_pending);
    current.stopSetupRefresh();
    try current.restoreCommitted();
    try std.testing.expectError(error.OperationIndeterminate, Call.run(&current, interrupted));
    try std.testing.expect(current.installation_refresh == null);
    current.mutations.recoverAfterRestart();
    current.admission.recoverAfterRestart();
    try current.persist(&.{});
    try std.testing.expectEqual(mutation_authority.State.indeterminate, (try current.mutations.lookup(interrupted.operation_id)).?.state);
    const shutdown_params = .{ .operation_id = "verify-shutdown", .expected_revision = current.revision };
    const shutdown_pending = try Call.run(&current, shutdown_params);
    allocator.free(shutdown_pending);
    const shutdown_task = current.installation_refresh.?;
    const shutdown_deadline: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(3000) });
    while (!shutdown_task.done.load(.acquire)) {
        if (shutdown_deadline.durationFromNow(io).raw.toNanoseconds() <= 0) return error.SetupRefreshDidNotFinish;
        try io.sleep(.fromMilliseconds(1), .awake);
    }
    const shutdown_checkpoint = current.db.?.checkpoint;
    const shutdown_probe_at = current.installation_probe_at;
    current.mutex.lockUncancelable(io);
    current.stopping = true;
    current.mutex.unlock(io);
    current.completeSetupRefresh();
    try std.testing.expect(current.installation_refresh == null);
    try std.testing.expectEqualDeep(shutdown_checkpoint, current.db.?.checkpoint);
    try std.testing.expectEqual(shutdown_probe_at, current.installation_probe_at);
    try std.testing.expectEqual(mutation_authority.State.started, (try current.mutations.lookup(shutdown_params.operation_id)).?.state);
    current.stopping = false;
    try current.restoreCommitted();
    current.mutations.recoverAfterRestart();
    current.admission.recoverAfterRestart();
    try current.persist(&.{});
    try std.testing.expectError(error.OperationIndeterminate, Call.run(&current, shutdown_params));
    const summary_before = try setup_verification.summarize(allocator, current.mutations.snapshot(), current.now());
    const failed_params = .{ .operation_id = "verify-store-failure", .expected_revision = current.revision };
    const failed_pending = try Call.run(&current, failed_params);
    allocator.free(failed_pending);
    const failing_task = current.installation_refresh.?;
    const deadline: std.Io.Clock.Timestamp = .fromNow(io, .{ .clock = .awake, .raw = .fromMilliseconds(3000) });
    while (!failing_task.done.load(.acquire)) {
        if (deadline.durationFromNow(io).raw.toNanoseconds() <= 0) return error.SetupRefreshDidNotFinish;
        try io.sleep(.fromMilliseconds(1), .awake);
    }
    const old_observed_at = current.installation_probe_at;
    const checkpoint_before = current.db.?.checkpoint;
    if (sql_api.sqlite3_exec(current.db.?.db, "PRAGMA query_only=ON;", null, null, null) != sql_api.SQLITE_OK) return error.SqliteError;
    current.completeSetupRefresh();
    try std.testing.expect(current.installation_refresh == null);
    try std.testing.expectEqual(old_observed_at, current.installation_probe_at);
    try std.testing.expectEqualDeep(checkpoint_before, current.db.?.checkpoint);
    try std.testing.expect((try current.mutations.lookup(failed_params.operation_id)).?.state != .completed);
    const summary_after = try setup_verification.summarize(allocator, current.mutations.snapshot(), current.now());
    try std.testing.expectEqual(summary_before.verification_completed, summary_after.verification_completed);
}

test "source enrollment generation reply stays bound to the admitted job and preserves legacy shape" {
    const allocator = std.testing.allocator;
    var threaded: std.Io.Threaded = .init(allocator, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try std.testing.expectEqual(@as(c_int, 0), std.c.fchmodat(directory.dir.handle, ".", 0o700, 0));
    const path = try directory.dir.realPathFileAlloc(io, ".", allocator);
    defer allocator.free(path);
    const database = try std.fmt.allocPrintSentinel(allocator, "{s}/enrollment-generation.sqlite", .{path}, 0);
    defer allocator.free(database);
    // Threadless synthetic writer: the Store and all direct model mutations
    // have the same real thread owner, as in the setup-refresh fixture above.
    // Opening an actor would give its Store to a different owner thread.
    var current: Engine = .{
        .allocator = allocator,
        .io = io,
        .state_dir = @constCast(path),
        .state = domain.State.init(allocator),
        .observers = observer.Coordinator.init(allocator),
        .requests = request_authority.Ledger.init(allocator, 4096),
        .mutations = try mutation_authority.Ledger.init(allocator, 4096),
        .admission = snapshot_admission.Ledger.init(allocator),
        .native_owners = native_owner.Ledger.init(allocator),
        .metrics = reliability.Recorder.init(0, .{ .evidence = .synthetic }),
        .root_key = @splat(0x51),
        .test_key = @splat(0x51),
        .db = try storage.Store.open(io, allocator, database, @splat(0x51)),
    };
    defer {
        current.db.?.close();
        current.release();
    }
    try std.testing.expect(current.thread == null and current.network == null and current.native_workers == null);
    try std.testing.expectEqual(std.Thread.getCurrentId(), current.db.?.owner_thread);
    const engine = &current;
    _ = try engine.state.putJob(.{ .id = "reconcile-fixture-source", .kind = .enrollment, .status = .running, .operation_generation = 7 });
    try engine.persist(&.{});
    const admitted = try engine.sourceReconcileReply(allocator, .{ .integer = 1 }, "reconcile-fixture-source", true);
    defer allocator.free(admitted);
    var reply = try std.json.parseFromSlice(std.json.Value, allocator, admitted, .{});
    defer reply.deinit();
    const result = control.get(reply.value, "result").?;
    try std.testing.expectEqual(@as(i64, 7), control.get(result, "operation_generation").?.integer);
    const admitted_revision = control.get(result, "admitted_revision").?.integer;
    try std.testing.expectEqual(@as(u64, @intCast(admitted_revision)), engine.revision);
    _ = try engine.state.putJob(.{ .id = "reconcile-fixture-source", .kind = .enrollment, .status = .completed, .operation_generation = 7 });
    _ = try engine.state.reopenJob(.{ .id = "reconcile-fixture-source", .kind = .enrollment, .status = .running, .operation_generation = 7 });
    try engine.persist(&.{});
    // The immutable original result retains generation7 despite later state.
    try std.testing.expectEqual(@as(i64, 7), control.get(result, "operation_generation").?.integer);
    const legacy = try engine.sourceReconcileReply(allocator, .{ .integer = 2 }, "reconcile-fixture-source", false);
    defer allocator.free(legacy);
    var old = try std.json.parseFromSlice(std.json.Value, allocator, legacy, .{});
    defer old.deinit();
    try std.testing.expectEqual(@as(usize, 2), control.get(old.value, "result").?.object.count());
    var malformed = try std.json.parseFromSlice(std.json.Value, allocator, "{\"source_id\":\"fixture-source\",\"include_operation_generation\":1}", .{});
    defer malformed.deinit();
    const before = engine.revision;
    try std.testing.expectError(error.InvalidParams, engine.preflightMutationResult(allocator, "enrollment.start", malformed.value));
    try std.testing.expectEqual(before, engine.revision);
    try std.testing.expectError(error.NotFound, engine.sourceReconcileReply(allocator, .{ .integer = 3 }, "missing-job", true));
}
