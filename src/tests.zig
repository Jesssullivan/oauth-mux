const std = @import("std");

// Keep this list explicit. scripts/check-zig-test-root.sh fails when a source
// file is added without joining the test graph.
const AllModules = struct {
    pub const main = @import("main.zig");
    pub const age = @import("age.zig");
    pub const broker_loader = @import("broker_loader.zig");
    pub const cli = @import("cli.zig");
    pub const config = @import("config.zig");
    pub const daemon = @import("daemon.zig");
    pub const doctor_binaries = @import("doctor_binaries.zig");
    pub const env = @import("env.zig");
    pub const fixture_redaction = @import("fixture_redaction.zig");
    pub const health = @import("health.zig");
    pub const identity_hash = @import("identity_hash.zig");
    pub const lock_wait = @import("lock_wait.zig");
    pub const log = @import("log.zig");
    pub const notify = @import("notify.zig");
    pub const oauth = @import("oauth.zig");
    pub const paths = @import("paths.zig");
    pub const pipeline = @import("pipeline.zig");
    pub const probe = @import("probe.zig");
    pub const product_identity = @import("product_identity.zig");
    pub const provider = @import("provider.zig");
    pub const provider_schema = @import("provider_schema.zig");
    pub const repair_state = @import("repair_state.zig");
    pub const runtime = @import("runtime.zig");
    pub const secret = @import("secret.zig");
    pub const shell = @import("shell.zig");
    pub const trace = @import("trace.zig");
    pub const types = @import("types.zig");
    pub const version_check = @import("version_check.zig");

    pub const codex_adapter = @import("adapters/codex/main.zig");
    pub const codex_app_server_client = @import("adapters/codex/app_server_client.zig");
    pub const codex_wire_proxy = @import("adapters/codex/wire_proxy.zig");

    pub const broker = @import("broker/mod.zig");
    pub const broker_account_pool = @import("broker/account_pool.zig");
    pub const broker_methods = @import("broker/methods.zig");
    pub const broker_server = @import("broker/server.zig");
    pub const broker_session = @import("broker/session.zig");
    pub const broker_types = @import("broker/types.zig");

    pub const claude_oauth_cassette = @import("cassettes/claude_oauth_cassette.zig");
    pub const claude_oauth_cassette_tests = @import("cassettes/claude_oauth_cassette_tests.zig");

    pub const enroll_browser_launch = @import("enroll/browser_launch.zig");
    pub const enroll_callback_server = @import("enroll/callback_server.zig");
    pub const enroll_callback_server_tests = @import("enroll/callback_server_tests.zig");
    pub const enroll_claude_reauth = @import("enroll/claude_reauth.zig");
    pub const enroll_claude_reauth_tests = @import("enroll/claude_reauth_tests.zig");
    pub const enroll_device_code = @import("enroll/device_code.zig");
    pub const enroll_flow_composition = @import("enroll/flow_composition.zig");
    pub const enroll_reauth = @import("enroll/reauth.zig");
    pub const enroll_tests = @import("enroll/tests.zig");
    pub const enroll_web_ui = @import("enroll/web_ui.zig");
    pub const enroll_web_ui_tests = @import("enroll/web_ui_tests.zig");

    pub const claude_identity = @import("identity/claude_identity.zig");
    pub const claude_identity_tests = @import("identity/claude_identity_tests.zig");
    pub const identity_graph = @import("identity/identity_graph.zig");
    pub const identity_graph_tests = @import("identity/identity_graph_tests.zig");
    pub const identity_lane_integration_tests = @import("identity/identity_lane_integration_tests.zig");

    pub const keepalive_notify_adapter = @import("keepalive/notify_adapter.zig");
    pub const keepalive_refresh_race_tests = @import("keepalive/refresh_race_tests.zig");
    pub const keepalive_ui_server = @import("keepalive/ui_server.zig");
    pub const keepalive_ui_server_tests = @import("keepalive/ui_server_tests.zig");
    pub const keepalive_warm_binding = @import("keepalive/warm_binding.zig");
    pub const keepalive_warm_binding_tests = @import("keepalive/warm_binding_tests.zig");
    pub const keepalive_warm_runner = @import("keepalive/warm_runner.zig");
    pub const keepalive_warm_runner_tests = @import("keepalive/warm_runner_tests.zig");
    pub const keepalive_warm_scheduler = @import("keepalive/warm_scheduler.zig");
    pub const keepalive_warm_scheduler_tests = @import("keepalive/warm_scheduler_tests.zig");

    pub const quota_advise = @import("quota/advise.zig");
    pub const quota_advise_tests = @import("quota/advise_tests.zig");
    pub const quota_bucket = @import("quota/bucket.zig");
    pub const quota_bucket_tests = @import("quota/bucket_tests.zig");

    pub const reauth_orchestrator = @import("reauth/orchestrator.zig");
};

test "every Zig source module joins the test graph" {
    std.testing.refAllDeclsRecursive(AllModules);
}
