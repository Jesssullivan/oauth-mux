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
//!   model_demand.zig  — parse-free exact-model demand
//!   route_observation.zig — typed route evidence projection
//!   decision.zig      — pure deterministic route election
//!   lease_state.zig   — pure in-process lease state and projection
//!   lease_store.zig   — redacted cross-process lease persistence
//!
//! Surface version is `1` (see broker spec §2). Method shapes are stable
//! within a major; adding optional fields is allowed.

const std = @import("std");

pub const types = @import("types.zig");
pub const server = @import("server.zig");
pub const methods = @import("methods.zig");
pub const session_mod = @import("session.zig");
pub const account_pool_mod = @import("account_pool.zig");
pub const model_demand = @import("model_demand.zig");
pub const route_observation = @import("route_observation.zig");
pub const decision = @import("decision.zig");
pub const lease_state = @import("lease_state.zig");
pub const lease_store = @import("lease_store.zig");

pub const SURFACE_VERSION: u32 = types.surface_version;
pub const BUILD_TAG: []const u8 = "oauth-mux 0.2.0+broker";

pub const Server = server.Server;
pub const Session = session_mod.Session;
pub const AccountPool = account_pool_mod.AccountPool;
pub const ClaimLevel = types.ClaimLevel;
pub const BrokerError = types.BrokerError;
pub const ModelDemand = model_demand.ModelDemand;
pub const RouteObservation = route_observation.RouteObservation;
pub const EvidenceProvenance = route_observation.EvidenceProvenance;
pub const BrokerDecision = decision.BrokerDecision;
pub const LeaseState = lease_state.LeaseState;
pub const LeaseStore = lease_store.LeaseStore;

test {
    std.testing.refAllDeclsRecursive(@This());
}
