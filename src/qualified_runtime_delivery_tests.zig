test {
    _ = @import("integrations/setup.zig");
    _ = @import("integrations/nix_runtime_closure.zig");
    _ = @import("integrations/runtime_deployment.zig");
    _ = @import("integrations/runtime_selection_writer.zig");
    _ = @import("integrations/runtime_installation.zig");
}
