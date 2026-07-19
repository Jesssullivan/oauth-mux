//! Module root for the v02-stage2-observe compilation. Lives at src/ so the
//! module path spans the whole src/ tree: stage2_observer imports wire_proxy,
//! which reaches src/quota/advisory_usage.zig — an import that escapes a
//! module rooted at src/adapters/claude/.
const observer = @import("adapters/claude/stage2_observer.zig");

pub const BuildIdentity = observer.BuildIdentity;
pub const emit = observer.emit;
