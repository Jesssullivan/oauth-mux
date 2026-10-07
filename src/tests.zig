//! Whole-runtime tests. Build authority is //:unit_tests under Bazel.
comptime {
    _ = @import("domain.zig");
    _ = @import("envelope.zig");
    _ = @import("storage.zig");
    _ = @import("vault.zig");
    _ = @import("transport.zig");
    _ = @import("browser_bridge.zig");
    _ = @import("browser_grant.zig");
    _ = @import("control.zig");
    _ = @import("paths.zig");
    _ = @import("instance_tests.zig");
    _ = @import("onboarding_tests.zig");
    _ = @import("reliability_lifecycle_tests.zig");
    _ = @import("catalog.zig");
    _ = @import("integrations/git.zig");
    _ = @import("integrations/codex.zig");
    _ = @import("integrations/claude.zig");
    _ = @import("integrations/native_probe.zig");
    _ = @import("engine.zig");
    _ = @import("engine_acceptance.zig");
    _ = @import("daemon.zig");
    _ = @import("reference.zig");
    _ = @import("main.zig");
    _ = @import("discovery.zig");
    _ = @import("observer.zig");
    _ = @import("integrations/setup.zig");
    _ = @import("platform/file_metadata.zig");
}
