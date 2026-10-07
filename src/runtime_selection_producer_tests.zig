//! Keep the Zig module root at src/ for the integrations' sibling imports.
test {
    _ = @import("integrations/runtime_selection_producer_tests.zig");
    _ = @import("integrations/measured_runtime_selection_tests.zig");
}
