//! oauth-mux broker module — public entry.
//!
//! The broker is the product anchor (see
//! docs/spec/broker-mcp-contract-2026-05-03.md). It exposes an MCP-shaped
//! JSON-RPC 2.0 surface over stdio that adapters (oauth-mux codex,
//! oauth-mux claude, …) consume to drive seamless in-place account swap
//! against their respective harnesses.
//!
//! This module is the namespace; concrete machinery lives in:
//!   types.zig         — broker-public types (SessionId, AccountId, …)
//!   server.zig        — JSON-RPC stdio server + dispatch
//!   methods.zig       — method handlers (surface/*, account/*, …)
//!   session.zig       — session table
//!   account_pool.zig  — read-side account access over the existing config
//!
//! Surface version is `1` (see broker spec §2). Method shapes are stable
//! within a major; adding optional fields is allowed.

const std = @import("std");

pub const types = @import("types.zig");
pub const server = @import("server.zig");
pub const methods = @import("methods.zig");
pub const session_mod = @import("session.zig");
pub const account_pool_mod = @import("account_pool.zig");

pub const SURFACE_VERSION: u32 = types.surface_version;
pub const BUILD_TAG: []const u8 = "oauth-mux 0.2.0+broker";

pub const Server = server.Server;
pub const Session = session_mod.Session;
pub const AccountPool = account_pool_mod.AccountPool;
pub const ClaimLevel = types.ClaimLevel;
pub const BrokerError = types.BrokerError;

test {
    std.testing.refAllDeclsRecursive(@This());
}
