//! Optional per-thread, access-token-only authentication custody.
//!
//! This module never imports refresh tokens, writes auth.json, or touches native history.
//! A binding can be installed after a thread is loaded; each request snapshots its binding.

use crate::native_peer::PeerWitness;
use crate::broker_request_profile::{RequestProfile, SIWC_PROFILE, SIWC_ISSUER, SIWC_AUDIENCE, SIWC_AUTH_MODE};
use codex_api::ApiError;
use codex_api::AuthProvider;
use codex_api::TransportError;
use codex_protocol::ThreadId;
use http::HeaderMap;
use http::HeaderValue;
use http::StatusCode;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Value;
use serde_json::json;
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

pub const PROTOCOL_VERSION: u32 = 2;
pub const CAPABILITIES: [&str; 7] = [
    "late_thread_binding",
    "per_request_auth",
    "exclusive_refresh_owner",
    "preacceptance_failure",
    "account_transport_invalidation",
    "native_context_reconstruction",
    "native_owner_custody",
];
pub const ISSUER: &str = "https://chatgpt.com";
pub const ENDPOINT: &str = "https://chatgpt.com/backend-api/codex";
const MAX_FRAME: usize = 1024 * 1024;
const MAX_NATIVE_THREADS: usize = 4096;
static BROKER_EXCHANGES: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(8);

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeRef {
    pub owner_id: String,
    pub adapter_epoch: String,
    pub endpoint_generation: String,
    pub thread_instance_generation: String,
    pub attachment_generation: String,
}

impl NativeRef {
    pub fn validate(&self) -> std::io::Result<()> {
        opaque(&self.owner_id)?;
        for generation in [
            &self.adapter_epoch,
            &self.endpoint_generation,
            &self.thread_instance_generation,
            &self.attachment_generation,
        ] {
            canonical_generation(generation)?;
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ProcessOwner {
    pub owner_id: String,
    pub process_nonce: String,
    pub owner_endpoint: PathBuf,
    pub endpoint_generation: String,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnerIdentity {
    pub protocol_version: u32,
    pub owner_id: String,
    pub process_nonce: String,
    pub endpoint_generation: String,
    pub thread_id: String,
    pub thread_instance_generation: String,
    pub operation_id: String,
}

#[derive(Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NativeAckTuple {
    pub protocol_version: u32,
    pub owner_id: String,
    pub process_nonce: String,
    pub adapter_epoch: String,
    pub endpoint_generation: String,
    pub thread_id: String,
    pub thread_instance_generation: String,
    pub attachment_generation: String,
    pub operation_id: String,
}

impl NativeAckTuple {
    pub fn native_ref(&self) -> NativeRef {
        NativeRef {
            owner_id: self.owner_id.clone(),
            adapter_epoch: self.adapter_epoch.clone(),
            endpoint_generation: self.endpoint_generation.clone(),
            thread_instance_generation: self.thread_instance_generation.clone(),
            attachment_generation: self.attachment_generation.clone(),
        }
    }
    pub fn validate(&self) -> std::io::Result<()> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(invalid("unsupported native owner protocol"));
        }
        self.native_ref().validate()?;
        opaque(&self.process_nonce)?;
        opaque(&self.operation_id)?;
        ThreadId::from_string(&self.thread_id)
            .map_err(|_| invalid("invalid native thread identity"))?;
        Ok(())
    }
}

fn opaque(value: &str) -> std::io::Result<()> {
    if value.len() != 64
        || value
            .bytes()
            .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
        || value.bytes().all(|b| b == b'0')
    {
        return Err(invalid("invalid native opaque identity"));
    }
    Ok(())
}

fn canonical_generation(value: &str) -> std::io::Result<()> {
    if value.is_empty()
        || value.starts_with('0')
        || value.len() > 20
        || !value.bytes().all(|b| b.is_ascii_digit())
        || value.parse::<u64>().ok().filter(|v| *v != 0).is_none()
    {
        return Err(invalid("invalid native generation"));
    }
    Ok(())
}

fn new_operation() -> String {
    rand::random::<[u8; 32]>()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

// Value's usual map decoding overwrites duplicate fields. Reject them before
// decoding any authority-bearing result or materialized request credential.
struct StrictValue(Value);
impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> serde::de::Visitor<'de> for StrictVisitor {
            type Value = Value;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("unambiguous JSON")
            }
            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Value, E> {
                Ok(Value::Bool(value))
            }
            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> {
                Ok(json!(value))
            }
            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
                Ok(json!(value))
            }
            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Value, E> {
                serde_json::Number::from_f64(value)
                    .map(Value::Number)
                    .ok_or_else(|| E::custom("invalid JSON number"))
            }
            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
                Ok(Value::String(value.to_owned()))
            }
            fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Value, E> {
                Ok(Value::String(value))
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Value, A::Error> {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(Value::Array(values))
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut fields: A,
            ) -> Result<Value, A::Error> {
                let mut values = serde_json::Map::new();
                while let Some(key) = fields.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate broker response field"));
                    }
                    values.insert(key, fields.next_value::<StrictValue>()?.0);
                }
                Ok(Value::Object(values))
            }
        }
        deserializer.deserialize_any(StrictVisitor).map(Self)
    }
}

pub struct BrokerBinding {
    socket: PathBuf,
    capability_path: PathBuf,
    binding_id: String,
    route: Mutex<Option<(String, u64)>>,
    request_profile: OnceLock<RequestProfile>,
    last_lease: Mutex<Option<String>>,
    metadata: Mutex<Option<CachedMetadata>>,
    context_report: Mutex<Option<crate::broker_text_context::ContextReport>>,
    native_ref: OnceLock<NativeRef>,
    native_thread: OnceLock<ThreadId>,
    daemon_peer: Arc<Mutex<Option<PeerWitness>>>,
}

impl std::fmt::Debug for BrokerBinding {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerBinding")
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct BrokerRegistry {
    process_owner: Option<ProcessOwner>,
    thread_identities: HashMap<ThreadId, (String, String)>,
    next_thread_generation: u64,
    pending: HashMap<ThreadId, PendingRegistration>,
    attachment: HashMap<ThreadId, NativeAckTuple>,
    detached_receipts: Vec<NativeRetirementReceipt>,
    active_requests: HashMap<ThreadId, usize>,
    native_work: HashMap<ThreadId, usize>,
    bindings: HashMap<ThreadId, Arc<BrokerBinding>>,
    detached: HashSet<ThreadId>,
    ambient_activity: HashMap<ThreadId, usize>,
    threadless_ambient_activity: usize,
}

struct PendingRegistration {
    binding: Arc<BrokerBinding>,
    identity: OwnerIdentity,
    activated: Option<NativeAckTuple>,
    startup: bool,
    inflight: bool,
    unresolved: bool,
}

/// Both operations are retained from authenticated native transitions.
#[derive(Clone)]
struct NativeRetirementReceipt {
    registration: NativeAckTuple,
    detach: NativeAckTuple,
    peer: PeerWitness,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum OwnerAttachmentDisposition {
    Unmanaged,
    Pending,
    Unresolved,
    Attached,
    Retired,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnerAttachmentSnapshot {
    pub protocol_version: u32,
    pub owner_id: String,
    pub process_nonce: String,
    pub endpoint_generation: String,
    pub thread_id: String,
    pub thread_instance_generation: String,
    pub disposition: OwnerAttachmentDisposition,
    pub native_ref: Option<NativeRef>,
    pub registration_operation_id: Option<String>,
    pub detach_operation_id: Option<String>,
}

/// Read-only: never prepares identity, calls the daemon or admits native work.
pub fn owner_attachment_snapshot(thread_id: ThreadId) -> std::io::Result<OwnerAttachmentSnapshot> {
    let registry = bindings().lock().map_err(|_| invalid("native registry unavailable"))?;
    attachment_snapshot(&registry, thread_id)
}

fn attachment_snapshot(registry: &BrokerRegistry, thread_id: ThreadId) -> std::io::Result<OwnerAttachmentSnapshot> {
    let owner = registry.process_owner.as_ref().ok_or_else(|| invalid("native owner endpoint unavailable"))?;
    let (generation, _) = registry.thread_identities.get(&thread_id).ok_or_else(|| invalid("native thread identity is not prepared"))?;
    let thread = thread_id.to_string();
    let matches = |tuple: &NativeAckTuple| tuple.owner_id == owner.owner_id
        && tuple.process_nonce == owner.process_nonce
        && tuple.endpoint_generation == owner.endpoint_generation
        && tuple.thread_id == thread
        && &tuple.thread_instance_generation == generation;
    let mut snapshot = OwnerAttachmentSnapshot {
        protocol_version: PROTOCOL_VERSION,
        owner_id: owner.owner_id.clone(),
        process_nonce: owner.process_nonce.clone(),
        endpoint_generation: owner.endpoint_generation.clone(),
        thread_id: thread.clone(),
        thread_instance_generation: generation.clone(),
        disposition: OwnerAttachmentDisposition::Unmanaged,
        native_ref: None,
        registration_operation_id: None,
        detach_operation_id: None,
    };
    if let Some(pending) = registry.pending.get(&thread_id) {
        let identity = &pending.identity;
        if identity.owner_id != owner.owner_id || identity.process_nonce != owner.process_nonce
            || identity.endpoint_generation != owner.endpoint_generation || identity.thread_id != thread
            || &identity.thread_instance_generation != generation {
            return Err(invalid("native pending incarnation mismatch"));
        }
        snapshot.disposition = if pending.unresolved { OwnerAttachmentDisposition::Unresolved } else { OwnerAttachmentDisposition::Pending };
        snapshot.registration_operation_id = Some(identity.operation_id.clone());
        // A pending activated tuple is not a committed attachment.
        return Ok(snapshot);
    }
    if let Some(active) = registry.attachment.get(&thread_id) {
        if !matches(active) || !registry.bindings.contains_key(&thread_id) || registry.detached.contains(&thread_id) {
            return Err(invalid("native committed attachment mismatch"));
        }
        snapshot.disposition = OwnerAttachmentDisposition::Attached;
        snapshot.native_ref = Some(active.native_ref());
        snapshot.registration_operation_id = Some(active.operation_id.clone());
        return Ok(snapshot);
    }
    if registry.detached.contains(&thread_id) {
        let receipt = registry.detached_receipts.iter().rev().find(|receipt| matches(&receipt.detach))
            .ok_or_else(|| invalid("native retirement receipt unavailable"))?;
        if !matches(&receipt.registration) || receipt.registration.native_ref() != receipt.detach.native_ref() {
            return Err(invalid("native retirement attribution mismatch"));
        }
        snapshot.disposition = OwnerAttachmentDisposition::Retired;
        snapshot.native_ref = Some(receipt.registration.native_ref());
        snapshot.registration_operation_id = Some(receipt.registration.operation_id.clone());
        snapshot.detach_operation_id = Some(receipt.detach.operation_id.clone());
    }
    Ok(snapshot)
}

pub fn install_process_owner(owner: ProcessOwner) -> std::io::Result<()> {
    opaque(&owner.owner_id)?;
    opaque(&owner.process_nonce)?;
    canonical_generation(&owner.endpoint_generation)?;
    validate_private_path(&owner.owner_endpoint, false)?;
    let mut registry = bindings()
        .lock()
        .map_err(|_| invalid("native registry unavailable"))?;
    if registry.process_owner.as_ref() == Some(&owner) {
        return Ok(());
    }
    if registry.process_owner.is_some()
        || !registry.pending.is_empty()
        || !registry.bindings.is_empty()
    {
        return Err(invalid("native process owner cannot be replaced"));
    }
    registry.process_owner = Some(owner);
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeThreadPreparation {
    Prepared,
    Unavailable,
}

pub fn prepare_native_thread(thread_id: ThreadId) -> std::io::Result<NativeThreadPreparation> {
    let mut registry = bindings()
        .lock()
        .map_err(|_| invalid("native registry unavailable"))?;
    if registry.process_owner.is_none() {
        return Ok(NativeThreadPreparation::Unavailable);
    }
    prepare_thread_identity(&mut registry, thread_id)
}

fn ensure_thread_identity(
    registry: &mut BrokerRegistry,
    thread_id: ThreadId,
) -> std::io::Result<()> {
    match prepare_thread_identity(registry, thread_id)? {
        NativeThreadPreparation::Prepared => Ok(()),
        NativeThreadPreparation::Unavailable => Err(invalid(
            "native thread identity capacity or generation unavailable",
        )),
    }
}

fn prepare_thread_identity(
    registry: &mut BrokerRegistry,
    thread_id: ThreadId,
) -> std::io::Result<NativeThreadPreparation> {
    if registry.thread_identities.contains_key(&thread_id) {
        return Ok(NativeThreadPreparation::Prepared);
    }
    if registry.thread_identities.len() >= MAX_NATIVE_THREADS
        || registry.next_thread_generation == u64::MAX
    {
        return Ok(NativeThreadPreparation::Unavailable);
    }
    registry.next_thread_generation = registry
        .next_thread_generation
        .checked_add(1)
        .ok_or_else(|| invalid("native thread generation exhausted"))?;
    registry.thread_identities.insert(
        thread_id,
        (registry.next_thread_generation.to_string(), new_operation()),
    );
    Ok(NativeThreadPreparation::Prepared)
}

pub fn identify(thread_id: ThreadId) -> std::io::Result<OwnerIdentity> {
    let registry = bindings()
        .lock()
        .map_err(|_| invalid("native registry unavailable"))?;
    if let Some(pending) = registry.pending.get(&thread_id) {
        return Ok(pending.identity.clone());
    }
    let owner = registry
        .process_owner
        .as_ref()
        .ok_or_else(|| invalid("native owner endpoint unavailable"))?;
    let (generation, operation_id) = registry
        .thread_identities
        .get(&thread_id)
        .ok_or_else(|| invalid("native thread identity is not prepared"))?;
    Ok(OwnerIdentity {
        protocol_version: PROTOCOL_VERSION,
        owner_id: owner.owner_id.clone(),
        process_nonce: owner.process_nonce.clone(),
        endpoint_generation: owner.endpoint_generation.clone(),
        thread_id: thread_id.to_string(),
        thread_instance_generation: generation.clone(),
        operation_id: operation_id.clone(),
    })
}

fn next_attachment_generation(
    registry: &BrokerRegistry,
    thread_id: ThreadId,
    adapter_epoch: &str,
    endpoint_generation: &str,
) -> std::io::Result<String> {
    let (generation, _) = registry
        .thread_identities
        .get(&thread_id)
        .ok_or_else(|| invalid("native thread identity is not prepared"))?;
    let owner = registry
        .process_owner
        .as_ref()
        .ok_or_else(|| invalid("native owner endpoint unavailable"))?;
    let mut highest = 0u64;
    for receipt in &registry.detached_receipts {
        let retired = &receipt.detach;
        if retired.owner_id == owner.owner_id
            && retired.adapter_epoch == adapter_epoch
            && retired.endpoint_generation == endpoint_generation
            && retired.thread_id == thread_id.to_string()
            && &retired.thread_instance_generation == generation
        {
            highest = highest.max(
                retired
                    .attachment_generation
                    .parse::<u64>()
                    .map_err(|_| invalid("retained native generation invalid"))?,
            );
        }
    }
    highest
        .checked_add(1)
        .map(|next| next.to_string())
        .ok_or_else(|| invalid("native attachment generation exhausted"))
}

pub fn owner_thread_descriptor(thread_id: ThreadId) -> std::io::Result<(String, String)> {
    let registry = bindings()
        .lock()
        .map_err(|_| invalid("native registry unavailable"))?;
    let (generation, _) = registry
        .thread_identities
        .get(&thread_id)
        .ok_or_else(|| invalid("native thread identity is not prepared"))?;
    let attachment = if let Some(active) = registry.attachment.get(&thread_id) {
        active.attachment_generation.clone()
    } else if let Some(active) = registry
        .pending
        .get(&thread_id)
        .and_then(|pending| pending.activated.as_ref())
    {
        active.attachment_generation.clone()
    } else {
        // Unattached listing is diagnostic only: it cannot predict a future
        // actor epoch. Activation derives authority from the incoming tuple.
        let owner = registry
            .process_owner
            .as_ref()
            .ok_or_else(|| invalid("native owner endpoint unavailable"))?;
        let mut latest_epoch = 1u64;
        for receipt in &registry.detached_receipts {
            let retired = &receipt.detach;
            if retired.owner_id == owner.owner_id
                && retired.endpoint_generation == owner.endpoint_generation
                && retired.thread_id == thread_id.to_string()
                && &retired.thread_instance_generation == generation
            {
                latest_epoch = latest_epoch.max(
                    retired
                        .adapter_epoch
                        .parse::<u64>()
                        .map_err(|_| invalid("retained native epoch invalid"))?,
                );
            }
        }
        next_attachment_generation(
            &registry,
            thread_id,
            &latest_epoch.to_string(),
            &owner.endpoint_generation,
        )?
    };
    Ok((generation.clone(), attachment))
}

pub fn is_startup_registration(thread_id: ThreadId) -> bool {
    bindings()
        .lock()
        .ok()
        .and_then(|registry| registry.pending.get(&thread_id).map(|p| p.startup))
        .unwrap_or(false)
}

pub fn require_owner_ready(thread_id: ThreadId) -> std::io::Result<()> {
    let registry = bindings()
        .lock()
        .map_err(|_| invalid("native registry unavailable"))?;
    if registry.pending.contains_key(&thread_id) {
        return Err(invalid(
            "native owner registration is pending or unresolved",
        ));
    }
    Ok(())
}

static BINDINGS: OnceLock<Mutex<BrokerRegistry>> = OnceLock::new();

fn bindings() -> &'static Mutex<BrokerRegistry> {
    BINDINGS.get_or_init(Mutex::default)
}

pub fn binding(thread_id: ThreadId) -> Option<Arc<BrokerBinding>> {
    bindings()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .bindings
        .get(&thread_id)
        .cloned()
}

pub fn unregister(thread_id: ThreadId, release_binding: bool) {
    let mut registry = bindings()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if registry.pending.contains_key(&thread_id)
        || registry
            .bindings
            .get(&thread_id)
            .is_some_and(|binding| binding.native_ref.get().is_some())
    {
        // Version-2 authority can be removed only by its exact native ACK.
        return;
    }
    if let Some(binding) = registry.bindings.remove(&thread_id) {
        registry.detached.insert(thread_id);
        if release_binding {
            binding.schedule_release(thread_id);
        }
    }
}

/// Teardown never leaves a native-reentry marker for a destroyed thread instance.
pub fn forget(thread_id: ThreadId) {
    if bindings().lock().ok().is_none_or(|registry| {
        registry.pending.contains_key(&thread_id) || registry.attachment.contains_key(&thread_id)
    }) {
        // Teardown/absence is not authenticated detach authority.
        return;
    }
    unregister(thread_id, true);
    let mut registry = bindings()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    registry.detached.remove(&thread_id);
    registry.thread_identities.remove(&thread_id);
}

pub fn ambient_blocked(thread_id: ThreadId) -> bool {
    let registry = bindings()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    registry.pending.contains_key(&thread_id)
        || registry.bindings.contains_key(&thread_id)
        || registry.detached.contains(&thread_id)
}

pub fn any_ambient_blocked() -> bool {
    let registry = bindings()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    !registry.pending.is_empty() || !registry.bindings.is_empty() || !registry.detached.is_empty()
}

/// Holds native ancillary authorization ownership until its real work drains.
/// Registration cannot acknowledge a new owner while an earlier task can
/// refresh or send using canonical native credentials.
pub struct AmbientActivityGuard {
    thread_id: Option<ThreadId>,
}

pub fn try_acquire_ambient_activity(thread_id: ThreadId) -> Option<AmbientActivityGuard> {
    let mut registry = bindings()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if registry.pending.contains_key(&thread_id)
        || registry.bindings.contains_key(&thread_id)
        || registry.detached.contains(&thread_id)
    {
        return None;
    }
    let count = registry.ambient_activity.entry(thread_id).or_default();
    *count = count.checked_add(1)?;
    Some(AmbientActivityGuard {
        thread_id: Some(thread_id),
    })
}

/// Process-global native account operations cannot be assigned to a thread.
/// They block every registration until their original authorization drains.
pub fn try_acquire_threadless_ambient_activity() -> Option<AmbientActivityGuard> {
    let mut registry = bindings()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !registry.pending.is_empty()
        || !registry.bindings.is_empty()
        || !registry.detached.is_empty()
    {
        return None;
    }
    registry.threadless_ambient_activity = registry.threadless_ambient_activity.checked_add(1)?;
    Some(AmbientActivityGuard { thread_id: None })
}

impl Drop for AmbientActivityGuard {
    fn drop(&mut self) {
        let mut registry = bindings()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(thread_id) = self.thread_id else {
            registry.threadless_ambient_activity -= 1;
            return;
        };
        if let Some(count) = registry.ambient_activity.get_mut(&thread_id) {
            *count -= 1;
            if *count == 0 {
                registry.ambient_activity.remove(&thread_id);
            }
        }
    }
}

pub(crate) fn native_reentry_pending(thread_id: ThreadId) -> bool {
    bindings()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .detached
        .contains(&thread_id)
}

/// A racing final managed response can add opaque state after the idle control-plane check.
/// Recheck the actual next request before permitting ambient auth or prewarming again.
pub(crate) fn validate_native_reentry(thread_id: ThreadId, input: &Value) -> std::io::Result<bool> {
    let mut registry = bindings()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if registry.pending.contains_key(&thread_id) || registry.bindings.contains_key(&thread_id) {
        return Err(invalid(
            "broker binding changed while preparing native reentry",
        ));
    }
    if !registry.detached.contains(&thread_id) {
        return Ok(false);
    }
    if !context_portable(input) {
        return Err(invalid("native context requires retained broker custody"));
    }
    registry.detached.remove(&thread_id);
    Ok(true)
}

pub(crate) struct BrokerRequestGuard {
    thread_id: ThreadId,
    binding: Arc<BrokerBinding>,
}

pub(crate) struct NativeWorkGuard {
    thread_id: ThreadId,
}

#[derive(Debug)]
struct NativeOwnerPending;

impl std::fmt::Display for NativeOwnerPending {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("native owner registration is pending or unresolved")
    }
}

impl std::error::Error for NativeOwnerPending {}

pub(crate) fn native_owner_pending_error(error: &std::io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|cause| cause.is::<NativeOwnerPending>())
}

pub(crate) fn begin_native_work(thread_id: ThreadId) -> std::io::Result<NativeWorkGuard> {
    let mut registry = bindings()
        .lock()
        .map_err(|_| invalid("native registry unavailable"))?;
    if registry.pending.contains_key(&thread_id) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            NativeOwnerPending,
        ));
    }
    let count = registry.native_work.entry(thread_id).or_default();
    *count = count
        .checked_add(1)
        .ok_or_else(|| invalid("native work capacity reached"))?;
    Ok(NativeWorkGuard { thread_id })
}

impl Drop for NativeWorkGuard {
    fn drop(&mut self) {
        let mut registry = bindings()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = registry.native_work.get_mut(&self.thread_id) {
            *count -= 1;
            if *count == 0 {
                registry.native_work.remove(&self.thread_id);
            }
        }
    }
}

impl BrokerRequestGuard {
    pub(crate) fn binding(&self) -> Arc<BrokerBinding> {
        Arc::clone(&self.binding)
    }
}

pub(crate) fn begin_broker_request(
    thread_id: ThreadId,
) -> std::io::Result<Option<BrokerRequestGuard>> {
    let mut registry = bindings()
        .lock()
        .map_err(|_| invalid("native registry unavailable"))?;
    if registry.pending.contains_key(&thread_id) {
        return Err(invalid(
            "native owner registration is pending or unresolved",
        ));
    }
    let Some(binding) = registry.bindings.get(&thread_id).cloned() else {
        return Ok(None);
    };
    let count = registry.active_requests.entry(thread_id).or_default();
    *count = count
        .checked_add(1)
        .ok_or_else(|| invalid("native request capacity reached"))?;
    Ok(Some(BrokerRequestGuard { thread_id, binding }))
}

impl Drop for BrokerRequestGuard {
    fn drop(&mut self) {
        let mut registry = bindings()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = registry.active_requests.get_mut(&self.thread_id) {
            *count -= 1;
            if *count == 0 {
                registry.active_requests.remove(&self.thread_id);
            }
        }
    }
}

/// Cached, sanitized thread metadata. This never performs a broker callback from a control RPC.
pub fn status(thread_id: ThreadId) -> Option<Value> {
    let binding = binding(thread_id)?;
    let cached = binding
        .metadata
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let route = cached
        .as_ref()
        .and_then(|metadata| serde_json::to_value(metadata).ok());
    let context = binding.context_report.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    match (route, context.as_ref()) {
        (Some(mut route), Some(context)) => {
            route["native_context"] = serde_json::to_value(context).ok()?;
            Some(route)
        }
        (Some(route), None) => Some(route),
        (None, Some(context)) => Some(json!({"bound":true, "native_context":context})),
        (None, None) => None,
    }
}

/// Validates a local endpoint before accepting custody; no upstream calls are made.
pub async fn register(
    thread_id: ThreadId,
    socket: PathBuf,
    capability_path: PathBuf,
    binding_id: String,
) -> std::io::Result<()> {
    prepare_registration_inner(thread_id, socket, capability_path, binding_id, None, true)
}

pub fn prepare_registration(
    thread_id: ThreadId,
    socket: PathBuf,
    capability_path: PathBuf,
    binding_id: String,
    operation_id: Option<String>,
) -> std::io::Result<()> {
    prepare_registration_inner(
        thread_id,
        socket,
        capability_path,
        binding_id,
        operation_id,
        false,
    )
}

/// Reject malformed late-attachment inputs before native ancillary drain.
/// Activity is deliberately rechecked by prepare_registration after that drain.
pub fn check_registration_request(
    thread_id: ThreadId,
    socket: &Path,
    capability_path: &Path,
    binding_id: &str,
    operation_id: &str,
) -> std::io::Result<()> {
    opaque(operation_id)?;
    if binding_id.is_empty() || binding_id.len() > 256 {
        return Err(invalid("invalid broker binding id"));
    }
    validate_private_path(socket, false)?;
    validate_private_path(capability_path, true)?;
    let candidate = BrokerBinding {
        socket: socket.to_path_buf(),
        capability_path: capability_path.to_path_buf(),
        binding_id: binding_id.to_owned(),
        request_profile: OnceLock::new(),
        route: Mutex::new(None),
        last_lease: Mutex::new(None),
        metadata: Mutex::new(None),
        context_report: Mutex::new(None),
        native_ref: OnceLock::new(),
        native_thread: OnceLock::new(),
        daemon_peer: Arc::new(Mutex::new(None)),
    };
    candidate.capability()?;
    let registry = bindings()
        .lock()
        .map_err(|_| invalid("native registry unavailable"))?;
    if registry.process_owner.is_none() {
        return Err(invalid("native owner endpoint unavailable"));
    }
    if let Some(pending) = registry.pending.get(&thread_id) {
        if pending.binding.socket != socket
            || pending.binding.capability_path != capability_path
            || pending.binding.binding_id != binding_id
            || pending.identity.operation_id != operation_id
            || pending.unresolved
        {
            return Err(invalid(
                "native registration conflicts with retained authority",
            ));
        }
    } else if registry.bindings.contains_key(&thread_id) {
        return Err(invalid("native attachment is already active"));
    }
    Ok(())
}

fn prepare_registration_inner(
    thread_id: ThreadId,
    socket: PathBuf,
    capability_path: PathBuf,
    binding_id: String,
    operation_id: Option<String>,
    startup: bool,
) -> std::io::Result<()> {
    if binding_id.is_empty() || binding_id.len() > 256 {
        return Err(invalid("invalid broker binding id"));
    }
    validate_private_path(&socket, false)?;
    validate_private_path(&capability_path, true)?;
    let new_binding = Arc::new(BrokerBinding {
        socket,
        capability_path,
        binding_id,
        request_profile: OnceLock::new(),
        route: Mutex::new(None),
        last_lease: Mutex::new(None),
        metadata: Mutex::new(None),
        context_report: Mutex::new(None),
        native_ref: OnceLock::new(),
        native_thread: OnceLock::new(),
        daemon_peer: Arc::new(Mutex::new(None)),
    });
    // Reading verifies capability syntax but never exposes its value to the caller.
    new_binding.capability()?;
    let mut registry = bindings()
        .lock()
        .map_err(|_| invalid("native registry unavailable"))?;
    let owner = registry
        .process_owner
        .clone()
        .ok_or_else(|| invalid("native owner endpoint unavailable"))?;
    if let Some(pending) = registry.pending.get(&thread_id) {
        if pending.binding.socket == new_binding.socket
            && pending.binding.capability_path == new_binding.capability_path
            && pending.binding.binding_id == new_binding.binding_id
            && operation_id
                .as_ref()
                .is_none_or(|op| op == &pending.identity.operation_id)
            && !pending.unresolved
        {
            return Ok(());
        }
        return Err(invalid(
            "native registration conflicts with retained authority",
        ));
    }
    if registry.bindings.contains_key(&thread_id) {
        return Err(invalid("native attachment is already active"));
    }
    if registry.threadless_ambient_activity != 0
        || registry.ambient_activity.contains_key(&thread_id)
        || registry.active_requests.contains_key(&thread_id)
        || registry.native_work.contains_key(&thread_id)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "native ancillary authorization is still active; retry after it drains",
        ));
    }
    ensure_thread_identity(&mut registry, thread_id)?;
    let (generation, retained_operation) = registry
        .thread_identities
        .get_mut(&thread_id)
        .expect("prepared native identity");
    if let Some(operation_id) = operation_id {
        opaque(&operation_id)?;
        *retained_operation = operation_id;
    }
    let identity = OwnerIdentity {
        protocol_version: PROTOCOL_VERSION,
        owner_id: owner.owner_id,
        process_nonce: owner.process_nonce,
        endpoint_generation: owner.endpoint_generation,
        thread_id: thread_id.to_string(),
        thread_instance_generation: generation.clone(),
        operation_id: retained_operation.clone(),
    };
    registry.pending.insert(
        thread_id,
        PendingRegistration {
            binding: new_binding,
            identity,
            activated: None,
            startup,
            inflight: false,
            unresolved: false,
        },
    );
    Ok(())
}

fn check_registration_locked(
    registry: &BrokerRegistry,
    thread_id: ThreadId,
    tuple: &NativeAckTuple,
    peer: &PeerWitness,
) -> std::io::Result<()> {
    tuple.validate()?;
    if registry.threadless_ambient_activity != 0
        || registry.ambient_activity.contains_key(&thread_id)
        || registry.active_requests.contains_key(&thread_id)
        || registry.native_work.contains_key(&thread_id)
    {
        return Err(invalid("native authorization activity has not drained"));
    }
    let pending = registry
        .pending
        .get(&thread_id)
        .ok_or_else(|| invalid("native registration was not prepared"))?;
    if pending
        .binding
        .daemon_peer
        .lock()
        .map_err(|_| invalid("native daemon witness unavailable"))?
        .as_ref()
        != Some(peer)
    {
        return Err(invalid(
            "native registration peer differs from original daemon",
        ));
    }
    let identity = &pending.identity;
    if pending.activated.is_none()
        && tuple.attachment_generation
            != next_attachment_generation(
                registry,
                thread_id,
                &tuple.adapter_epoch,
                &tuple.endpoint_generation,
            )?
    {
        return Err(invalid(
            "native attachment differs from reserved generation",
        ));
    }
    if pending.unresolved
        || tuple.owner_id != identity.owner_id
        || tuple.process_nonce != identity.process_nonce
        || tuple.endpoint_generation != identity.endpoint_generation
        || tuple.thread_id != identity.thread_id
        || tuple.thread_instance_generation != identity.thread_instance_generation
        || tuple.operation_id != identity.operation_id
    {
        return Err(invalid(
            "native registration acknowledgment mismatches original authority",
        ));
    }
    if pending
        .activated
        .as_ref()
        .is_some_and(|previous| previous != tuple)
    {
        return Err(invalid("native attachment generation cannot be replaced"));
    }
    Ok(())
}

pub fn check_registration(
    thread_id: ThreadId,
    tuple: &NativeAckTuple,
    peer: PeerWitness,
) -> std::io::Result<()> {
    let registry = bindings()
        .lock()
        .map_err(|_| invalid("native registry unavailable"))?;
    check_registration_locked(&registry, thread_id, tuple, &peer)
}

pub fn activate_registration(
    thread_id: ThreadId,
    tuple: NativeAckTuple,
    peer: PeerWitness,
) -> std::io::Result<NativeAckTuple> {
    let mut registry = bindings()
        .lock()
        .map_err(|_| invalid("native registry unavailable"))?;
    check_registration_locked(&registry, thread_id, &tuple, &peer)?;
    let pending = registry
        .pending
        .get_mut(&thread_id)
        .ok_or_else(|| invalid("native registration was not prepared"))?;
    if let Some(previous) = &pending.activated {
        return if previous == &tuple {
            Ok(previous.clone())
        } else {
            Err(invalid("native attachment generation cannot be replaced"))
        };
    }
    pending
        .binding
        .native_ref
        .set(tuple.native_ref())
        .map_err(|_| invalid("native attachment generation already assigned"))?;
    pending
        .binding
        .native_thread
        .set(thread_id)
        .map_err(|_| invalid("native thread instance already assigned"))?;
    pending.activated = Some(tuple.clone());
    Ok(tuple)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistrationResult {
    native_ref: NativeRef,
    operation_id: String,
    registered: bool,
}

pub async fn finish_registration(thread_id: ThreadId) -> std::io::Result<NativeAckTuple> {
    let (binding, identity, endpoint) = {
        let mut registry = bindings()
            .lock()
            .map_err(|_| invalid("native registry unavailable"))?;
        if let Some(attached) = registry.attachment.get(&thread_id) {
            return Ok(attached.clone());
        }
        let endpoint = registry
            .process_owner
            .as_ref()
            .ok_or_else(|| invalid("native owner endpoint unavailable"))?
            .owner_endpoint
            .clone();
        let pending = registry
            .pending
            .get_mut(&thread_id)
            .ok_or_else(|| invalid("native registration was not prepared"))?;
        if pending.inflight || pending.unresolved {
            return Err(invalid("native registration remains pending or unresolved"));
        }
        pending.inflight = true;
        (
            Arc::clone(&pending.binding),
            pending.identity.clone(),
            endpoint,
        )
    };
    let outcome = binding
        .rpc(
            "adapter.owner.register",
            json!({
                "owner_id":identity.owner_id, "process_nonce":identity.process_nonce,
                "owner_endpoint":endpoint, "thread_id":identity.thread_id,
                "endpoint_generation":identity.endpoint_generation,
                "thread_instance_generation":identity.thread_instance_generation,
                "operation_id":identity.operation_id,
            }),
        )
        .await;
    let mut registry = bindings()
        .lock()
        .map_err(|_| invalid("native registry unavailable"))?;
    let result = outcome.and_then(|value| {
        serde_json::from_value::<RegistrationResult>(value)
            .map_err(|_| invalid("native registration result is invalid"))
    });
    let pending = registry
        .pending
        .get_mut(&thread_id)
        .ok_or_else(|| invalid("native registration custody disappeared"))?;
    let checked = result.and_then(|result| {
        result.native_ref.validate()?;
        let activated = pending
            .activated
            .as_ref()
            .ok_or_else(|| invalid("native activation acknowledgment is absent"))?;
        if !result.registered
            || result.operation_id != identity.operation_id
            || result.native_ref != activated.native_ref()
        {
            return Err(invalid("native committed result mismatches activation"));
        }
        Ok(activated.clone())
    });
    let tuple = match checked {
        Ok(tuple) => tuple,
        Err(error) => {
            pending.unresolved = true;
            return Err(error);
        }
    };
    let pending = registry
        .pending
        .remove(&thread_id)
        .ok_or_else(|| invalid("native pending authority disappeared"))?;
    registry.detached.remove(&thread_id);
    registry.bindings.insert(thread_id, pending.binding);
    registry.attachment.insert(thread_id, tuple.clone());
    Ok(tuple)
}

pub fn registration_paths_match(
    thread_id: ThreadId,
    socket: &Path,
    capability_path: &Path,
) -> bool {
    bindings().lock().ok().is_some_and(|registry| {
        registry.pending.get(&thread_id).is_some_and(|pending| {
            pending.binding.socket == socket && pending.binding.capability_path == capability_path
        })
    })
}

pub fn detach_exact(
    thread_id: ThreadId,
    tuple: NativeAckTuple,
    peer: PeerWitness,
) -> std::io::Result<NativeAckTuple> {
    tuple.validate()?;
    let mut registry = bindings()
        .lock()
        .map_err(|_| invalid("native registry unavailable"))?;
    if let Some(receipt) = registry
        .detached_receipts
        .iter()
        .find(|receipt| receipt.detach == tuple)
    {
        return if receipt.peer == peer {
            Ok(receipt.detach.clone())
        } else {
            Err(invalid("native detach peer differs from original daemon"))
        };
    }
    let original_peer = registry
        .bindings
        .get(&thread_id)
        .ok_or_else(|| invalid("native attachment binding is absent"))?
        .daemon_peer
        .lock()
        .map_err(|_| invalid("native daemon witness unavailable"))?
        .clone();
    if original_peer.as_ref() != Some(&peer) {
        return Err(invalid("native detach peer differs from original daemon"));
    }
    let active = registry
        .attachment
        .get(&thread_id)
        .ok_or_else(|| invalid("native attachment is not active"))?;
    if active.native_ref() != tuple.native_ref()
        || active.process_nonce != tuple.process_nonce
        || active.thread_id != tuple.thread_id
        || registry.pending.contains_key(&thread_id)
    {
        return Err(invalid("native detach mismatches retained attachment"));
    }
    if registry.threadless_ambient_activity != 0
        || registry.ambient_activity.contains_key(&thread_id)
        || registry.active_requests.contains_key(&thread_id)
        || registry.native_work.contains_key(&thread_id)
    {
        return Err(invalid("native authorization activity has not drained"));
    }
    if registry.detached_receipts.len() >= MAX_NATIVE_THREADS {
        return Err(invalid("native retirement capacity reached"));
    }
    let registration = active.clone();
    registry.bindings.remove(&thread_id);
    registry.attachment.remove(&thread_id);
    registry.detached.insert(thread_id);
    registry.detached_receipts.push(NativeRetirementReceipt { registration, detach: tuple.clone(), peer });
    Ok(tuple)
}

/// This reports local custody readiness only; it is neither account nor entitlement verification.
pub fn configuration_ready(
    config: &codex_config::config_toml::OmuxBrokerConfig,
) -> std::io::Result<()> {
    validate_private_path(&config.broker_socket, false)?;
    validate_private_path(&config.capability_path, true)?;
    BrokerBinding {
        socket: config.broker_socket.clone(),
        capability_path: config.capability_path.clone(),
        binding_id: "configuration-probe".to_string(),
        request_profile: OnceLock::new(),
        route: Mutex::new(None),
        last_lease: Mutex::new(None),
        metadata: Mutex::new(None),
        context_report: Mutex::new(None),
        native_ref: OnceLock::new(),
        native_thread: OnceLock::new(),
        daemon_peer: Arc::new(Mutex::new(None)),
    }
    .capability()
    .map(|_| ())
}

fn invalid(message: &'static str) -> std::io::Error {
    std::io::Error::other(message)
}

#[cfg(unix)]
fn validate_private_path(path: &Path, regular_file: bool) -> std::io::Result<()> {
    use std::os::unix::fs::FileTypeExt;
    use std::os::unix::fs::MetadataExt;
    // Safety: geteuid has no arguments and does not mutate process state.
    let uid = unsafe { libc::geteuid() };
    let parent = path
        .parent()
        .ok_or_else(|| invalid("broker path needs private parent"))?;
    if !path.is_absolute() {
        return Err(invalid("broker paths must be absolute"));
    }
    let parent_meta = std::fs::symlink_metadata(parent)?;
    let meta = std::fs::symlink_metadata(path)?;
    if !parent_meta.is_dir()
        || parent_meta.uid() != uid
        || parent_meta.mode() & 0o077 != 0
        || meta.uid() != uid
        || meta.mode() & 0o077 != 0
        || (regular_file && (!meta.is_file() || meta.len() != 64))
        || (!regular_file && !meta.file_type().is_socket())
    {
        return Err(invalid("broker endpoint is not private to this user"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_path(_path: &Path, _regular_file: bool) -> std::io::Result<()> {
    Err(invalid(
        "auth broker transport is unavailable on this platform",
    ))
}

#[cfg(unix)]
fn read_private_capability(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::OpenOptionsExt;

    // Reject leaf symlink substitution, and never block if a checked regular
    // file was replaced with a FIFO before open. Validate the opened object.
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    // Safety: geteuid only reads this process's credentials.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o077 != 0
        || metadata.len() != 64
    {
        return Err(invalid(
            "broker capability object is not private and regular",
        ));
    }
    let mut bytes = Vec::with_capacity(65);
    file.take(65).read_to_end(&mut bytes)?;
    if bytes.len() != 64 || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return Err(invalid("broker capability is invalid"));
    }
    String::from_utf8(bytes).map_err(|_| invalid("broker capability is invalid"))
}

#[derive(Clone, Deserialize)]
pub(crate) struct Lease {
    pub lease_handle: String,
    pub account_id: String,
    pub route_generation: u64,
    pub expires_at: u64,
}

/// Terminal cleanup is installed as soon as acquisition succeeds, including before preparation.
pub(crate) struct LeaseGuard {
    pub lease: Lease,
    binding: Arc<BrokerBinding>,
    armed: bool,
}

impl LeaseGuard {
    pub(crate) fn new(binding: Arc<BrokerBinding>, lease: Lease) -> Self {
        Self {
            binding,
            lease,
            armed: true,
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.armed = false;
    }

    /// Native completion is visible only after the daemon's terminal commit.
    /// Accepted output stays visible immediately. No outcome permits replay.
    pub(crate) async fn forward_event(
        &mut self,
        event: codex_protocol::error::Result<codex_api::ResponseEvent>,
        sender: &tokio::sync::mpsc::Sender<codex_protocol::error::Result<codex_api::ResponseEvent>>,
    ) -> bool {
        let completed = matches!(&event, Ok(codex_api::ResponseEvent::Completed { .. }));
        if completed {
            if self.binding.report(&self.lease, "completed", None).await.is_err() {
                tracing::warn!("broker completion report could not be recorded");
                let failure = std::io::Error::other(
                    "broker completion could not be committed; native work remains fenced",
                );
                let _ = sender.send(Err(failure.into())).await;
                return false;
            }
            self.disarm();
        }
        if sender.send(event).await.is_err() {
            return false;
        }
        !completed
    }
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let binding = Arc::clone(&self.binding);
        let lease = self.lease.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn(async move {
                    if binding.report(&lease, "abandoned", None).await.is_err() {
                        tracing::warn!(
                            "broker terminal cleanup could not be recorded; custody remains fenced until terminal acknowledgment"
                        );
                    }
                });
            }
            Err(_) => {
                tracing::warn!(
                    "broker runtime stopped before lease cleanup; custody remains fenced until terminal acknowledgment"
                )
            }
        }
    }
}

#[derive(Deserialize)]
pub(crate) struct MaterializedGrant {
    access_token: String,
    provider_account_id: Option<String>,
    expires_at: u64,
    route_generation: u64,
}

/// Closed API-Responses credential exported only by qualified daemon activation.
/// Deserialization consumes authority; it does not verify identity or issue a grant.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SiwcMaterializedGrant {
    request_profile: String, issuer: String, audience: String, auth_mode: String,
    access_token: String, expires_at: u64, route_generation: u64,
}
fn materialized_siwc(value: Value, lease: &Lease) -> std::io::Result<Arc<RequestAuth>> {
    if !value.is_object() { return Err(invalid("SIWC broker grant must be a named object")); }
    let grant: SiwcMaterializedGrant = serde_json::from_value(value)
        .map_err(|_| invalid("SIWC broker grant is invalid"))?;
    if grant.request_profile != SIWC_PROFILE || grant.issuer != SIWC_ISSUER || grant.audience != SIWC_AUDIENCE
        || grant.auth_mode != SIWC_AUTH_MODE || grant.route_generation != lease.route_generation
        || grant.expires_at <= now()? || grant.access_token.is_empty() || grant.access_token.len() > 65536
    { return Err(invalid("SIWC broker grant is invalid or expired")); }
    let mut authorization = HeaderValue::from_str(&format!("Bearer {}", grant.access_token))
        .map_err(|_| invalid("SIWC broker authorization is invalid"))?;
    authorization.set_sensitive(true);
    Ok(Arc::new(RequestAuth { authorization, account: None, expires_at: grant.expires_at.min(lease.expires_at) }))
}

/// A classified error exists only for the exact HTTP Responses route before
/// ResponsesClient returns a stream. Detail-only, policy and SSE errors are not permits.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SiwcErrorBody { error: SiwcErrorObject }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SiwcErrorObject {
    code: String, param: Option<String>,
    #[serde(rename = "message")]
    _message: Option<String>,
    #[serde(rename = "type")]
    _kind: Option<String>,
}
pub(crate) struct SiwcFailure {
    status: u16, code: String, param: Option<String>, provider_request_id: Option<String>,
}
impl SiwcFailure {
    pub(crate) fn from_error(error: &ApiError) -> Option<Self> {
        let ApiError::Transport(TransportError::Http { status, url: Some(url), headers, body: Some(body) }) = error else { return None; };
        if url != "https://api.openai.com/v1/responses" || body.len() > 8192 { return None; }
        let body: StrictValue = serde_json::from_str(body).ok()?;
        if !body.0.is_object() || !body.0.get("error").is_some_and(Value::is_object) { return None; }
        let body: SiwcErrorBody = serde_json::from_value(body.0).ok()?;
        if !matches!((status.as_u16(), body.error.code.as_str()),
            (401, "subscription_sharing_invalid_user") | (429, "subscription_sharing_usage_limit_exceeded")) { return None; }
        if body.error.param.as_ref().is_some_and(|value| value.len() > 128 || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b"_.[]-".contains(&b))) { return None; }
        let provider_request_id = headers.as_ref().and_then(|headers| {
            let all = headers.get_all("x-request-id");
            let mut values = all.iter();
            let value = values.next()?.to_str().ok()?;
            if values.next().is_some() || !value.starts_with("req_") || value.len() > 256
                || !value.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)) { return None; }
            Some(value.to_owned())
        });
        Some(Self { status: status.as_u16(), code: body.error.code, param: body.error.param, provider_request_id })
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SiwcReplacementWire { ticket: String, request_id: String, expires_at: u64 }
pub(crate) struct SiwcReplacement { ticket: String, request_id: String, expires_at: u64, rejected_account_id: String }
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum SiwcDisposition { Stop, RetryCompatible }
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SiwcRejectReceipt {
    recorded: bool, request_profile: String, rejected_lease_handle: String,
    rejected_route_generation: u64, disposition: SiwcDisposition,
    // Explicit null is part of the closed actor reply grammar.
    #[serde(deserialize_with = "required_siwc_replacement")]
    replacement: Option<SiwcReplacementWire>,
}
fn required_siwc_replacement<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<SiwcReplacementWire>, D::Error> {
    Option::<SiwcReplacementWire>::deserialize(d)
}

fn validated_siwc_rejection(value: Value, lease: &Lease, request_id: &str, failure: &SiwcFailure, allow_replacement: bool) -> std::io::Result<Option<SiwcReplacement>> {
    if !value.is_object() || !value.get("replacement").is_some_and(|v| v.is_null() || v.is_object()) {
        return Err(invalid("SIWC rejection receipt must have named objects"));
    }
    let receipt: SiwcRejectReceipt = serde_json::from_value(value).map_err(|_| invalid("SIWC rejection receipt is invalid"))?;
    if !receipt.recorded || receipt.request_profile != SIWC_PROFILE || receipt.rejected_lease_handle != lease.lease_handle
        || receipt.rejected_route_generation != lease.route_generation { return Err(invalid("SIWC rejection receipt is mismatched")); }
    match (receipt.disposition, receipt.replacement) {
        (SiwcDisposition::Stop, None) => Ok(None),
        (SiwcDisposition::RetryCompatible, Some(replacement)) => {
            if !allow_replacement || failure.status != 429 || failure.code != "subscription_sharing_usage_limit_exceeded"
                || replacement.request_id != request_id || replacement.expires_at > lease.expires_at || replacement.expires_at <= now()?
            { return Err(invalid("SIWC replacement admission is invalid")); }
            opaque(&replacement.ticket)?;
            Ok(Some(SiwcReplacement { ticket: replacement.ticket, request_id: replacement.request_id, expires_at: replacement.expires_at,
                rejected_account_id: lease.account_id.clone() }))
        },
        _ => Err(invalid("SIWC rejection disposition is invalid")),
    }
}

/// An allowlist separates broker status from materialized identity headers and credentials.
#[derive(Clone, Deserialize, Serialize)]
struct BrokerMetadata {
    bound: bool,
    custody_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    route_generation: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lifecycle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider_expires_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    custody_expires_at: Option<i64>,
}

#[derive(Clone, Serialize)]
struct CachedMetadata {
    observed_at: u64,
    #[serde(flatten)]
    metadata: BrokerMetadata,
}

pub(crate) struct RequestAuth {
    authorization: HeaderValue,
    account: Option<HeaderValue>,
    expires_at: u64,
}

impl AuthProvider for RequestAuth {
    fn add_auth_headers(&self, headers: &mut HeaderMap) {
        headers.insert(http::header::AUTHORIZATION, self.authorization.clone());
        if let Some(account) = &self.account {
            headers.insert("chatgpt-account-id", account.clone());
        }
    }

    fn resolve_auth_headers(&self) -> codex_api::AuthHeadersFuture<'_> {
        Box::pin(async move {
            if now().map_or(true, |now| now >= self.expires_at) {
                return Err(codex_api::AuthError::Build(
                    "broker request lease has expired".to_owned(),
                ));
            }
            Ok(self.to_auth_headers())
        })
    }
}

impl BrokerBinding {
    pub(crate) fn record_context_report(&self, report: crate::broker_text_context::ContextReport) {
        *self.context_report.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = Some(report);
    }

    fn require_thread(&self, thread_id: ThreadId) -> std::io::Result<()> {
        if self.native_thread.get() != Some(&thread_id) {
            return Err(invalid("native request belongs to another thread instance"));
        }
        Ok(())
    }
    fn capability(&self) -> std::io::Result<String> {
        validate_private_path(&self.capability_path, true)?;
        #[cfg(unix)]
        {
            read_private_capability(&self.capability_path)
        }
        #[cfg(not(unix))]
        {
            Err(invalid(
                "auth broker transport is unavailable on this platform",
            ))
        }
    }

    #[cfg(unix)]
    async fn rpc(&self, method: &str, mut params: Value) -> std::io::Result<Value> {
        validate_private_path(&self.socket, false)?;
        params["capability"] = Value::String(self.capability()?);
        params["application"] = Value::String("codex".to_string());
        if method != "adapter.owner.register" {
            let native_ref = self
                .native_ref
                .get()
                .ok_or_else(|| invalid("native owner custody is absent"))?;
            native_ref.validate()?;
            params["native_ref"] = serde_json::to_value(native_ref)
                .map_err(|_| invalid("native owner scope could not be encoded"))?;
        }
        let path = self.socket.clone();
        let method = method.to_owned();
        let daemon_peer = Arc::clone(&self.daemon_peer);
        let permit = BROKER_EXCHANGES
            .try_acquire()
            .map_err(|_| invalid("broker exchange capacity reached"))?;
        let exchange = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut socket = crate::native_peer::VerifiedStream::connect(&path)?;
            {
                let mut original = daemon_peer
                    .lock()
                    .map_err(|_| invalid("native daemon witness unavailable"))?;
                let current = socket.witness();
                if let Some(original) = original.as_ref() {
                    if original != &current {
                        return Err(invalid("native daemon incarnation changed"));
                    }
                } else {
                    if method != "adapter.owner.register" {
                        return Err(invalid("native daemon identity was not registered"));
                    }
                    *original = Some(current);
                }
            }
            let mut frame = serde_json::to_vec(&json!({
                "jsonrpc":"2.0", "id":1, "method":method, "params":params,
            }))
            .map_err(|_| invalid("broker request could not be encoded"))?;
            frame.push(b'\n');
            if frame.len() > MAX_FRAME {
                return Err(invalid("broker request exceeds framing bounds"));
            }
            socket.send_all(&frame)?;
            let mut response = Vec::new();
            let mut segment = [0u8; 4096];
            loop {
                // Each segment's current writer is proven before any JSON parsing.
                let length = socket.recv_segment(&mut segment)?;
                if length == 0
                    || response
                        .len()
                        .checked_add(length)
                        .is_none_or(|n| n > MAX_FRAME)
                {
                    return Err(invalid("broker response exceeds framing bounds"));
                }
                response.extend_from_slice(&segment[..length]);
                if let Some(newline) = response.iter().position(|byte| *byte == b'\n') {
                    if newline + 1 != response.len() {
                        return Err(invalid("broker response contains extra frames"));
                    }
                    break;
                }
            }
            let value = serde_json::from_slice::<StrictValue>(&response)
                .map_err(|_| invalid("broker response is invalid"))?
                .0;
            if value["jsonrpc"] != "2.0"
                || value["id"] != 1
                || value.get("error").is_some()
                || value.get("method").is_some()
            {
                // Never propagate raw broker payloads; they can contain credential material.
                return Err(invalid("broker rejected the operation"));
            }
            value
                .get("result")
                .cloned()
                .ok_or_else(|| invalid("broker result is missing"))
        });
        tokio::time::timeout(Duration::from_secs(10), exchange)
            .await
            .map_err(|_| invalid("broker operation timed out"))?
            .map_err(|_| invalid("broker exchange worker failed"))?
    }

    #[cfg(not(unix))]
    async fn rpc(&self, _method: &str, _params: Value) -> std::io::Result<Value> {
        Err(invalid(
            "auth broker transport is unavailable on this platform",
        ))
    }

    pub(crate) async fn acquire(
        self: &Arc<Self>,
        thread_id: ThreadId,
        request_id: &str,
        model: &str,
    ) -> std::io::Result<Lease> {
        self.acquire_for_profile(thread_id, request_id, model, RequestProfile::NativeChatgpt).await
    }

    pub(crate) async fn acquire_for_profile(
        self: &Arc<Self>, thread_id: ThreadId, request_id: &str, model: &str, profile: RequestProfile,
    ) -> std::io::Result<Lease> {
        self.acquire_with_replacement(thread_id, request_id, model, profile, None).await
    }

    pub(crate) async fn acquire_siwc_replacement(
        self: &Arc<Self>, thread_id: ThreadId, request_id: &str, model: &str, replacement: &SiwcReplacement,
    ) -> std::io::Result<Lease> {
        if replacement.request_id != request_id || now()? >= replacement.expires_at { return Err(invalid("SIWC replacement admission expired or mismatched")); }
        self.acquire_with_replacement(thread_id, request_id, model, RequestProfile::SiwcResponses, Some(replacement)).await
    }

    async fn acquire_with_replacement(
        self: &Arc<Self>, thread_id: ThreadId, request_id: &str, model: &str, profile: RequestProfile, replacement: Option<&SiwcReplacement>,
    ) -> std::io::Result<Lease> {
        self.require_thread(thread_id)?;
        if *self.request_profile.get_or_init(|| profile) != profile {
            return Err(invalid("broker binding request profile changed"));
        }
        let mut params = json!({
            "binding_id":self.binding_id, "session_id":thread_id.to_string(), "request_id":request_id,
            "demand":{"provider":profile.provider(), "audience":profile.audience(), "purpose":"request",
                "resource":{"kind":"model", "target":model, "unit":"tokens", "scope":""}, "required":1},
        });
        if profile == RequestProfile::SiwcResponses { params["request_profile"] = json!(SIWC_PROFILE); }
        let method = if let Some(replacement) = replacement {
            params["replacement_ticket"] = json!(replacement.ticket);
            "adapter.siwcAcquireReplacement"
        } else { "adapter.acquire" };
        let value = self.rpc(method, params).await?;
        let lease: Lease =
            serde_json::from_value(value).map_err(|_| invalid("broker lease is invalid"))?;
        if lease.lease_handle.len() != 64
            || !lease
                .lease_handle
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
            || lease.account_id.is_empty()
        {
            return Err(invalid("broker lease is invalid"));
        }
        // Structurally valid daemon authority already belongs to this request.
        // Expiry or a clock/preparation failure must abandon it even before the
        // caller receives its lease. Transfer to the caller without an await.
        let mut cleanup = LeaseGuard::new(Arc::clone(self), lease);
        *self
            .last_lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(cleanup.lease.lease_handle.clone());
        if cleanup.lease.expires_at <= now()? {
            return Err(invalid("broker lease is expired"));
        }
        if replacement.is_some_and(|replacement| cleanup.lease.expires_at > replacement.expires_at || cleanup.lease.account_id == replacement.rejected_account_id) {
            return Err(invalid("SIWC replacement lease exceeds admission or repeats rejected account"));
        }
        cleanup.disarm();
        Ok(cleanup.lease.clone())
    }

    /// Status refresh belongs to request execution, never synchronous native control ACKs.
    pub(crate) async fn refresh_metadata(
        &self,
        thread_id: ThreadId,
        lease: &Lease,
    ) -> std::io::Result<()> {
        self.require_thread(thread_id)?;
        let value = self
            .rpc(
                "adapter.metadata",
                json!({
                    "session_id":thread_id.to_string(), "binding_id":self.binding_id,
                }),
            )
            .await?;
        let metadata: BrokerMetadata =
            serde_json::from_value(value).map_err(|_| invalid("broker metadata is invalid"))?;
        if !metadata.bound
            || metadata.account_id.as_deref() != Some(lease.account_id.as_str())
            || metadata.route_generation != Some(lease.route_generation)
        {
            return Err(invalid(
                "broker metadata belongs to another route generation",
            ));
        }
        let route = self
            .route
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !route.as_ref().is_some_and(|(account, generation)| {
            account == &lease.account_id && *generation == lease.route_generation
        }) {
            return Err(invalid(
                "broker metadata was superseded by another native route",
            ));
        }
        *self
            .metadata
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(CachedMetadata {
            observed_at: now()?,
            metadata,
        });
        Ok(())
    }

    pub(crate) fn schedule_metadata(self: &Arc<Self>, thread_id: ThreadId, lease: &Lease) {
        let binding = Arc::clone(self);
        let lease = lease.clone();
        tokio::spawn(async move {
            if binding.refresh_metadata(thread_id, &lease).await.is_err() {
                tracing::debug!("broker route metadata could not be refreshed");
            }
        });
    }

    fn schedule_release(self: &Arc<Self>, thread_id: ThreadId) {
        let Some(last_lease) = self
            .last_lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        else {
            return;
        };
        if self.require_thread(thread_id).is_err() {
            tracing::warn!("broker binding cleanup thread mismatch; custody remains retained");
            return;
        }
        let binding = Arc::clone(self);
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let result = binding
                    .rpc(
                        "adapter.releaseBinding",
                        json!({
                            "session_id":thread_id.to_string(), "binding_id":binding.binding_id,
                            "expected_lease_handle":last_lease,
                        }),
                    )
                    .await;
                if !matches!(result, Ok(value) if value["released"] == true) {
                    tracing::warn!("broker binding cleanup could not be recorded");
                }
            });
        } else {
            tracing::warn!("broker runtime stopped before binding cleanup");
        }
    }

    pub(crate) async fn materialize(&self, lease: &Lease) -> std::io::Result<Arc<RequestAuth>> {
        self.materialize_for_profile(lease, RequestProfile::NativeChatgpt).await
    }

    pub(crate) async fn materialize_for_profile(&self, lease: &Lease, profile: RequestProfile) -> std::io::Result<Arc<RequestAuth>> {
        if self.request_profile.get().is_some_and(|selected| *selected != profile)
            || (profile == RequestProfile::SiwcResponses && self.request_profile.get() != Some(&profile))
        {
            return Err(invalid("broker materialization request profile changed"));
        }
        let mut params = json!({"lease_handle":lease.lease_handle});
        if profile == RequestProfile::SiwcResponses { params["request_profile"] = json!(SIWC_PROFILE); }
        let value = self.rpc("adapter.materialize", params).await?;
        if profile == RequestProfile::SiwcResponses {
            return materialized_siwc(value, lease);
        }
        // Opaque access-token bytes do not disclose their audience. Refuse the
        // separately typed API authority rather than interpreting it as native ChatGPT.
        if ["request_profile", "issuer", "audience", "auth_mode"].iter().any(|name| value.get(*name).is_some()) {
            return Err(invalid("API authority cannot enter the native ChatGPT slot"));
        }
        let grant: MaterializedGrant =
            serde_json::from_value(value).map_err(|_| invalid("broker grant is invalid"))?;
        if grant.expires_at <= now()?
            || grant.route_generation != lease.route_generation
            || grant.access_token.is_empty()
            || grant.access_token.len() > 65536
        {
            return Err(invalid("broker grant is invalid or expired"));
        }
        let mut authorization = HeaderValue::from_str(&format!("Bearer {}", grant.access_token))
            .map_err(|_| invalid("broker authorization is invalid"))?;
        authorization.set_sensitive(true);
        let account = grant
            .provider_account_id
            .map(|account| {
                let mut value = HeaderValue::from_str(&account)
                    .map_err(|_| invalid("broker account routing is invalid"))?;
                value.set_sensitive(true);
                Ok::<_, std::io::Error>(value)
            })
            .transpose()?;
        Ok(Arc::new(RequestAuth {
            authorization,
            account,
            expires_at: grant.expires_at.min(lease.expires_at),
        }))
    }

    /// Actor owns original intent/current pair/independent bucket admission and
    /// atomically spent tickets. Native code cannot derive those facts from a code.
    pub(crate) async fn reject_siwc(
        &self, lease: &Lease, request_id: &str, failure: &SiwcFailure, allow_replacement: bool,
    ) -> std::io::Result<Option<SiwcReplacement>> {
        if self.request_profile.get() != Some(&RequestProfile::SiwcResponses) {
            return Err(invalid("SIWC rejection profile is not current"));
        }
        let value = self.rpc("adapter.siwcReject", json!({
            "lease_handle":lease.lease_handle,"request_profile":SIWC_PROFILE,
            "status":failure.status,"error_code":failure.code,"error_param":failure.param,
            "provider_request_id":failure.provider_request_id,"pre_acceptance":true,"response_started":false,
        })).await?;
        validated_siwc_rejection(value, lease, request_id, failure, allow_replacement)
    }

    /// The account identity and generation are compared together; a generation alone is not unique.
    pub(crate) fn adopt_route(&self, lease: &Lease, input: &Value) -> std::io::Result<bool> {
        let next = (lease.account_id.clone(), lease.route_generation);
        let mut route = self
            .route
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let changed = route.as_ref() != Some(&next);
        let account_changed = route
            .as_ref()
            .is_none_or(|(account, _)| account != &lease.account_id);
        if account_changed && contains_account_bound_context(input) {
            return Err(invalid(
                "native context contains account-bound data; route cannot be substituted",
            ));
        }
        if changed {
            *self
                .metadata
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        }
        *route = Some(next);
        Ok(changed)
    }

    pub(crate) async fn report(
        &self,
        lease: &Lease,
        event: &str,
        status: Option<u16>,
    ) -> std::io::Result<()> {
        let mut params = json!({"lease_handle":lease.lease_handle, "event":event});
        if let Some(status) = status {
            params["status"] = json!(status);
            params["pre_acceptance"] = json!(true);
            params["response_started"] = json!(false);
        } else if event == "abandoned" {
            // An abandoned reservation is terminal and never authorizes an alternate/replay.
            params["pre_acceptance"] = json!(false);
            params["response_started"] = json!(true);
        }
        let value = self.rpc("adapter.report", params).await?;
        if value["recorded"] != true {
            return Err(invalid("broker report was not recorded"));
        }
        Ok(())
    }
}

fn now() -> std::io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|time| time.as_secs())
        .map_err(|_| invalid("system clock precedes the epoch"))
}

pub(crate) fn pre_acceptance_rejection(error: &ApiError) -> Option<u16> {
    match error {
        ApiError::Transport(TransportError::Http { status, .. })
            if matches!(
                *status,
                StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS
            ) =>
        {
            Some(status.as_u16())
        }
        // SSE quota/auth errors and ambiguous network outcomes must never authorize replay.
        _ => None,
    }
}

fn contains_account_bound_context(value: &Value) -> bool {
    match value {
        Value::Object(fields) => fields.iter().any(|(name, value)| {
            (matches!(
                name.as_str(),
                "encrypted_content" | "encrypted_function_args" | "file_id"
            ) && !value.is_null()
                && value != ""
                && value != &json!([]))
                || contains_account_bound_context(value)
        }),
        Value::Array(items) => items.iter().any(contains_account_bound_context),
        _ => false,
    }
}

pub fn context_portable(value: &Value) -> bool {
    !contains_account_bound_context(value)
}

#[cfg(all(test, target_os = "linux"))]
#[path = "auth_broker_owner_tests.rs"]
pub(crate) mod owner_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_pending_refusal_cannot_be_spoofed_by_error_kind_or_message() {
        let typed = std::io::Error::new(std::io::ErrorKind::WouldBlock, NativeOwnerPending);
        assert!(native_owner_pending_error(&typed));
        let same_text = std::io::Error::new(std::io::ErrorKind::WouldBlock, typed.to_string());
        assert!(!native_owner_pending_error(&same_text));
        assert!(!native_owner_pending_error(&invalid(
            "native registry unavailable"
        )));
        assert!(!native_owner_pending_error(&invalid(
            "native work capacity reached"
        )));
    }

    #[test]
    fn only_rejected_http_requests_allow_an_alternate() {
        for status in [401, 403, 429] {
            let err = ApiError::Transport(TransportError::Http {
                status: StatusCode::from_u16(status).unwrap(),
                url: None,
                headers: None,
                body: None,
            });
            assert_eq!(pre_acceptance_rejection(&err), Some(status));
        }
        assert_eq!(pre_acceptance_rejection(&ApiError::QuotaExceeded), None);
        assert_eq!(
            pre_acceptance_rejection(&ApiError::Transport(TransportError::Timeout)),
            None
        );
    }

    #[test]
    fn opaque_context_is_retained_and_blocks_unproven_substitution() {
        assert!(!contains_account_bound_context(
            &json!([{"type":"message","content":"hello"}])
        ));
        for input in [
            json!({"encrypted_content":"opaque"}),
            json!({"image":{"file_id":"file_1"}}),
            json!({"encrypted_function_args":["opaque"]}),
        ] {
            assert!(contains_account_bound_context(&input));
        }
    }

    #[test]
    fn same_account_generation_keeps_opaque_context_but_new_identity_is_rejected() {
        let binding = BrokerBinding {
            socket: PathBuf::new(),
            capability_path: PathBuf::new(),
            binding_id: "thread".into(),
            request_profile: OnceLock::new(),
            route: Mutex::new(None),
            last_lease: Mutex::new(None),
            metadata: Mutex::new(None),
            context_report: Mutex::new(None),
            native_ref: OnceLock::new(),
            native_thread: OnceLock::new(),
            daemon_peer: Arc::new(Mutex::new(None)),
        };
        let mut lease = Lease {
            lease_handle: "0".repeat(64),
            account_id: "work".into(),
            route_generation: 1,
            expires_at: u64::MAX,
        };
        assert!(binding.adopt_route(&lease, &json!([])).unwrap());
        let opaque = json!([{"encrypted_content":"retained"}]);
        lease.route_generation = 2;
        assert!(binding.adopt_route(&lease, &opaque).unwrap());
        lease.account_id = "home".into();
        assert!(binding.adopt_route(&lease, &opaque).is_err());
        assert_eq!(binding.route.lock().unwrap().as_ref().unwrap().0, "work");
    }

    #[test]
    fn generation_numbers_are_scoped_to_the_account() {
        let binding = BrokerBinding {
            socket: PathBuf::new(),
            capability_path: PathBuf::new(),
            binding_id: "thread".into(),
            request_profile: OnceLock::new(),
            route: Mutex::new(None),
            last_lease: Mutex::new(None),
            metadata: Mutex::new(None),
            context_report: Mutex::new(None),
            native_ref: OnceLock::new(),
            native_thread: OnceLock::new(),
            daemon_peer: Arc::new(Mutex::new(None)),
        };
        let mut lease = Lease {
            lease_handle: "0".repeat(64),
            account_id: "work".into(),
            route_generation: 1,
            expires_at: u64::MAX,
        };
        assert!(binding.adopt_route(&lease, &json!([])).unwrap());
        assert!(!binding.adopt_route(&lease, &json!([])).unwrap());
        lease.account_id = "home".into();
        assert!(binding.adopt_route(&lease, &json!([])).unwrap());
    }

    #[cfg(target_os = "linux")]
    mod unix_transport {
        use super::*;
        use std::os::unix::fs::PermissionsExt;
        use tempfile::TempDir;
        use tokio::io::AsyncBufReadExt;
        use tokio::io::AsyncWriteExt;
        use tokio::io::BufReader;
        use tokio::net::UnixListener;
        use tokio::task::JoinHandle;

        const TEST_CAPABILITY: &str =
            "0000000000000000000000000000000000000000000000000000000000000000";
        const TEST_LEASE: &str = "1111111111111111111111111111111111111111111111111111111111111111";

        struct MockBroker {
            // Retain the private directory until every asynchronous exchange has finished.
            _directory: TempDir,
            listener: UnixListener,
            binding: Arc<BrokerBinding>,
            _custody: owner_tests::Custody,
        }

        impl MockBroker {
            fn thread_id(&self) -> std::io::Result<ThreadId> {
                ThreadId::from_string(&self._custody.tuple.thread_id)
                    .map_err(|_| invalid("owned fixture thread invalid"))
            }
            async fn new() -> std::io::Result<Self> {
                owner_tests::initialize()?;
                let directory = tempfile::tempdir()?;
                std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))?;
                let socket = directory.path().join("adapter.sock");
                let capability_path = directory.path().join("codex.capability");
                std::fs::write(&capability_path, TEST_CAPABILITY)?;
                std::fs::set_permissions(&capability_path, std::fs::Permissions::from_mode(0o600))?;
                let listener = UnixListener::bind(&socket)?;
                std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
                let thread_id = ThreadId::new();
                register(
                    thread_id,
                    socket,
                    capability_path,
                    "test-binding".to_owned(),
                )
                .await?;
                let (binding, custody) = owner_tests::complete(thread_id, &listener).await?;
                Ok(Self {
                    _directory: directory,
                    listener,
                    binding,
                    _custody: custody,
                })
            }
        }

        struct MockStep {
            method: &'static str,
            response: Value,
        }

        fn scoped(mut value: Value, custody: &owner_tests::Custody) -> Value {
            value["native_ref"] = json!(custody.tuple.native_ref());
            value
        }

        fn result(method: &'static str, value: Value) -> MockStep {
            MockStep {
                method,
                response: json!({"jsonrpc":"2.0", "id":1, "result":value}),
            }
        }

        fn lease_result(expires_at: u64) -> Value {
            json!({
                "lease_handle":TEST_LEASE,
                "account_id":"test-account",
                "grant_id":"test-grant",
                "generation":1,
                "route_generation":7,
                "expires_at":expires_at,
            })
        }

        fn grant_result(expires_at: u64, route_generation: u64) -> Value {
            json!({
                "access_token":"synthetic-test-token",
                "provider_account_id":"synthetic-test-workspace",
                "expires_at":expires_at,
                "route_generation":route_generation,
            })
        }

        fn test_lease(expires_at: u64) -> Lease {
            Lease {
                lease_handle: TEST_LEASE.to_owned(),
                account_id: "test-account".to_owned(),
                route_generation: 7,
                expires_at,
            }
        }

        fn serve(
            listener: UnixListener,
            steps: Vec<MockStep>,
        ) -> JoinHandle<std::io::Result<Vec<Value>>> {
            tokio::spawn(async move {
                let (requests, _listener) = serve_retaining_listener(listener, steps).await?;
                Ok(requests)
            })
        }

        async fn serve_retaining_listener(
            listener: UnixListener,
            steps: Vec<MockStep>,
        ) -> std::io::Result<(Vec<Value>, UnixListener)> {
            let mut requests = Vec::new();
            for step in steps {
                let (socket, _) = listener.accept().await?;
                // Safety: geteuid only reads the credentials of this test process.
                if socket.peer_cred()?.uid() != unsafe { libc::geteuid() } {
                    return Err(invalid("test socket peer is not the current user"));
                }
                let mut socket = BufReader::new(socket);
                let mut frame = Vec::new();
                socket.read_until(b'\n', &mut frame).await?;
                if frame.last() != Some(&b'\n') || frame.len() > MAX_FRAME {
                    return Err(invalid("test request framing is invalid"));
                }
                let request: Value = serde_json::from_slice(&frame)
                    .map_err(|_| invalid("test request is not JSON"))?;
                // Return fixed diagnostics rather than printing private-channel frames.
                if request["jsonrpc"] != "2.0"
                    || request["id"] != 1
                    || request["method"] != step.method
                    || request["params"]["application"] != "codex"
                    || request["params"]["capability"] != TEST_CAPABILITY
                {
                    return Err(invalid(
                        "test broker request envelope differs from the contract",
                    ));
                }
                let reference: NativeRef =
                    serde_json::from_value(request["params"]["native_ref"].clone())
                        .map_err(|_| invalid("owned fixture native scope missing"))?;
                reference.validate()?;
                if !bindings()
                    .lock()
                    .map_err(|_| invalid("native fixture registry unavailable"))?
                    .attachment
                    .values()
                    .any(|tuple| tuple.native_ref() == reference)
                {
                    return Err(invalid("owned fixture native scope is not registered"));
                }
                requests.push(request);
                let mut response = serde_json::to_vec(&step.response)
                    .map_err(|_| invalid("test response cannot be encoded"))?;
                response.push(b'\n');
                socket.get_mut().write_all(&response).await?;
            }
            Ok((requests, listener))
        }

        async fn served(
            server: JoinHandle<std::io::Result<Vec<Value>>>,
        ) -> std::io::Result<Vec<Value>> {
            tokio::time::timeout(Duration::from_secs(5), server)
                .await
                .map_err(|_| invalid("test broker did not receive the expected requests"))?
                .map_err(|_| invalid("test broker task did not finish"))?
        }

        fn siwc_http_error(status: u16, code: &str, param: Option<&str>) -> ApiError {
            let mut headers = HeaderMap::new();
            headers.insert("x-request-id", HeaderValue::from_static("req_synthetic_fixture"));
            ApiError::Transport(TransportError::Http { status:StatusCode::from_u16(status).unwrap(),
                url:Some("https://api.openai.com/v1/responses".into()),headers:Some(headers),
                body:Some(json!({"error":{"code":code,"param":param,"type":"fixture_error","message":"synthetic failure"}}).to_string()) })
        }
        fn siwc_stop(lease: &Lease) -> Value {
            json!({"recorded":true,"request_profile":SIWC_PROFILE,"rejected_lease_handle":lease.lease_handle,
                "rejected_route_generation":lease.route_generation,"disposition":"stop","replacement":null})
        }

        #[test]
        fn structured_siwc_classifier_refuses_status_only_policy_duplicate_unknown_and_open_stream_errors() {
            assert!(SiwcFailure::from_error(&siwc_http_error(429,"subscription_sharing_usage_limit_exceeded",Some("model"))).is_some());
            assert!(SiwcFailure::from_error(&siwc_http_error(401,"subscription_sharing_invalid_user",None)).is_some());
            for error in [siwc_http_error(403,"subscription_sharing_user_not_eligible",Some("model")),
                siwc_http_error(401,"unknown",None),siwc_http_error(429,"unknown",Some("model")),ApiError::QuotaExceeded,
                ApiError::Stream("synthetic post-open failure".into()),ApiError::Transport(TransportError::Timeout)] {
                assert!(SiwcFailure::from_error(&error).is_none());
            }
            for body in [r#"{"detail":"synthetic admission failure"}"#,
                r#"[{"code":"subscription_sharing_usage_limit_exceeded","param":"model"}]"#,
                r#"{"error":["subscription_sharing_usage_limit_exceeded","model",null,null]}"#,
                r#"{"error":{"code":"subscription_sharing_usage_limit_exceeded","code":"subscription_sharing_usage_limit_exceeded","param":"model"}}"#]
            {
                let error=ApiError::Transport(TransportError::Http { status:StatusCode::TOO_MANY_REQUESTS,url:Some("https://api.openai.com/v1/responses".into()),headers:None,body:Some(body.into()) });
                assert!(SiwcFailure::from_error(&error).is_none());
            }
            let mut wrong_route=siwc_http_error(429,"subscription_sharing_usage_limit_exceeded",Some("model"));
            if let ApiError::Transport(TransportError::Http { url,.. })=&mut wrong_route { *url=Some("https://chatgpt.com/backend-api/codex/responses".into()); }
            assert!(SiwcFailure::from_error(&wrong_route).is_none());
        }

        #[tokio::test]
        async fn actual_private_structured_siwc_reject_records_literal_cause_and_stop_without_refresh_or_alternate() -> std::io::Result<()> {
            let broker=MockBroker::new().await?;let thread_id=broker.thread_id()?;
            let lease=test_lease(u64::MAX);
            let server=serve(broker.listener,vec![result("adapter.acquire",lease_result(u64::MAX)),result("adapter.siwcReject",siwc_stop(&lease))]);
            let acquired=broker.binding.acquire_for_profile(thread_id,"siwc-original-request","fixture-model",RequestProfile::SiwcResponses).await?;
            let failure=SiwcFailure::from_error(&siwc_http_error(401,"subscription_sharing_invalid_user",None)).ok_or_else(||invalid("fixture classification failed"))?;
            assert!(broker.binding.reject_siwc(&acquired,"siwc-original-request",&failure,true).await?.is_none());
            let requests=served(server).await?;assert_eq!(requests.len(),2);
            assert_eq!(requests[1]["params"]["error_code"],"subscription_sharing_invalid_user");
            assert!(requests[1]["params"]["error_param"].is_null());
            assert_eq!(requests[1]["params"]["provider_request_id"],"req_synthetic_fixture");
            assert_eq!(requests[1]["params"]["pre_acceptance"],true);
            assert_eq!(requests[1]["params"]["response_started"],false);
            Ok(())
        }

        #[tokio::test]
        async fn actual_private_siwc_ticket_binds_request_expiry_and_distinct_replacement_method() -> std::io::Result<()> {
            let broker=MockBroker::new().await?;let thread_id=broker.thread_id()?;let lease=test_lease(u64::MAX);
            let mut receipt=siwc_stop(&lease);receipt["disposition"]=json!("retry_compatible");
            receipt["replacement"]=json!({"ticket":"c".repeat(64),"request_id":"siwc-original-request","expires_at":u64::MAX});
            let mut next=lease_result(u64::MAX);next["account_id"]=json!("synthetic-independent-account");next["lease_handle"]=json!("d".repeat(64));
            let server=serve(broker.listener,vec![result("adapter.acquire",lease_result(u64::MAX)),result("adapter.siwcReject",receipt),result("adapter.siwcAcquireReplacement",next),result("adapter.report",json!({"recorded":true}))]);
            let acquired=broker.binding.acquire_for_profile(thread_id,"siwc-original-request","fixture-model",RequestProfile::SiwcResponses).await?;
            let failure=SiwcFailure::from_error(&siwc_http_error(429,"subscription_sharing_usage_limit_exceeded",Some("model"))).ok_or_else(||invalid("fixture classification failed"))?;
            let ticket=broker.binding.reject_siwc(&acquired,"siwc-original-request",&failure,true).await?.ok_or_else(||invalid("fixture ticket missing"))?;
            assert!(broker.binding.acquire_siwc_replacement(thread_id,"different-request","fixture-model",&ticket).await.is_err());
            let next=broker.binding.acquire_siwc_replacement(thread_id,"siwc-original-request","fixture-model",&ticket).await?;
            assert_ne!(next.account_id,acquired.account_id);
            broker.binding.report(&next,"abandoned",None).await?;
            let requests=served(server).await?;assert_eq!(requests.len(),4);
            assert_eq!(requests[2]["params"]["request_id"],"siwc-original-request");
            assert_eq!(requests[2]["params"]["replacement_ticket"],"c".repeat(64));
            assert_eq!(requests[2]["params"]["request_profile"],SIWC_PROFILE);
            Ok(())
        }

        #[test]
        fn actual_siwc_receipt_validator_refuses_stale_or_expired_or_second_attempt_tickets() -> std::io::Result<()> {
            let mut lease=test_lease(u64::MAX);lease.expires_at=now()?+600;
            let failure=SiwcFailure::from_error(&siwc_http_error(429,"subscription_sharing_usage_limit_exceeded",Some("model"))).ok_or_else(||invalid("fixture classification failed"))?;
            let mut receipt=siwc_stop(&lease);receipt["disposition"]=json!("retry_compatible");
            receipt["replacement"]=json!({"ticket":"c".repeat(64),"request_id":"original-request","expires_at":lease.expires_at});
            assert!(validated_siwc_rejection(receipt.clone(),&lease,"original-request",&failure,true)?.is_some());
            assert!(validated_siwc_rejection(receipt.clone(),&lease,"different-request",&failure,true).is_err());
            assert!(validated_siwc_rejection(receipt.clone(),&lease,"original-request",&failure,false).is_err());
            let auth_failure=SiwcFailure::from_error(&siwc_http_error(401,"subscription_sharing_invalid_user",Some("model"))).ok_or_else(||invalid("fixture classification failed"))?;
            assert!(validated_siwc_rejection(receipt.clone(),&lease,"original-request",&auth_failure,true).is_err());
            for (field,value) in [("recorded",json!(false)),("request_profile",json!("native_chatgpt")),
                ("rejected_lease_handle",json!("d".repeat(64))),("rejected_route_generation",json!(8)),("replacement",Value::Null)]
            {
                let mut changed=receipt.clone();changed[field]=value;
                assert!(validated_siwc_rejection(changed,&lease,"original-request",&failure,true).is_err());
            }
            for (field,value) in [("ticket",json!("0".repeat(64))),("expires_at",json!(0)),("expires_at",json!(lease.expires_at+1))] {
                let mut changed=receipt.clone();changed["replacement"][field]=value;
                assert!(validated_siwc_rejection(changed,&lease,"original-request",&failure,true).is_err());
            }
            assert!(validated_siwc_rejection(json!([true,SIWC_PROFILE,lease.lease_handle,lease.route_generation,"stop",null]),&lease,"original-request",&failure,true).is_err());
            let mut sequence=receipt.clone();sequence["replacement"]=json!(["c".repeat(64),"original-request",lease.expires_at]);
            assert!(validated_siwc_rejection(sequence,&lease,"original-request",&failure,true).is_err());
            let mut missing=siwc_stop(&lease);missing.as_object_mut().unwrap().remove("replacement");
            assert!(validated_siwc_rejection(missing,&lease,"original-request",&failure,true).is_err());
            Ok(())
        }

        #[derive(Clone)]
        struct SiwcLocalTransport {
            calls: Arc<Mutex<Vec<codex_client::Request>>>,
            after_open: bool,
        }
        impl codex_client::HttpTransport for SiwcLocalTransport {
            async fn execute(&self,_request:codex_client::Request)->Result<codex_client::Response,TransportError> {
                Err(TransportError::Build("fixture execute forbidden".into()))
            }
            async fn stream(&self,request:codex_client::Request)->Result<codex_client::StreamResponse,TransportError> {
                let url=request.url.clone();
                self.calls.lock().map_err(|_|TransportError::Build("fixture capture unavailable".into()))?.push(request);
                if self.after_open {
                    let bytes: codex_client::ByteStream = Box::pin(futures::stream::iter(vec![Ok(
                        b"event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"error\":{\"code\":\"subscription_sharing_usage_limit_exceeded\",\"message\":\"synthetic usage error\"}}}\n\n".to_vec().into()
                    )]));
                    Ok(codex_client::StreamResponse { status:StatusCode::OK,headers:HeaderMap::new(),bytes })
                } else {
                    Err(TransportError::Http {status:StatusCode::TOO_MANY_REQUESTS,url:Some(url),headers:None,
                        body:Some(json!({"error":{"code":"subscription_sharing_usage_limit_exceeded","param":"model","message":"synthetic usage error"}}).to_string())})
                }
            }
        }

        fn actual_siwc_request_fixture() -> codex_api::ResponsesApiRequest {
            codex_api::ResponsesApiRequest {model:"synthetic-siwc-model".into(),instructions:"synthetic developer instructions".into(),
                input:vec![serde_json::from_value(json!({"type":"message","role":"user","content":[{"type":"input_text","text":"synthetic request"}]})).unwrap()],
                tools:None,tool_choice:"auto".into(),parallel_tool_calls:true,reasoning:None,store:false,stream:true,
                stream_options:None,include:vec![],service_tier:None,prompt_cache_key:None,text:None,client_metadata:None,access_programs:None}
        }

        #[tokio::test]
        async fn actual_responses_client_encodes_fixed_route_and_bearer_then_classifies_only_before_stream_open() -> std::io::Result<()> {
            let calls=Arc::new(Mutex::new(Vec::new()));
            let transport=SiwcLocalTransport {calls:Arc::clone(&calls),after_open:false};
            let info:codex_model_provider_info::ModelProviderInfo=serde_json::from_value(json!({"name":"Omux SIWC Responses","base_url":SIWC_AUDIENCE,"requires_openai_auth":false,"supports_websockets":false})).map_err(|_|invalid("fixture provider invalid"))?;
            assert!(RequestProfile::for_provider(&info)?==RequestProfile::SiwcResponses);
            let mut provider=info.to_api_provider(None).map_err(|_|invalid("fixture provider invalid"))?;
            provider.headers.clear();provider.retry.max_attempts=0;provider.retry.retry_429=false;provider.retry.retry_5xx=false;provider.retry.retry_transport=false;
            let auth=materialized_siwc(siwc_grant_result(u64::MAX),&test_lease(u64::MAX))?;
            let client=codex_api::ResponsesClient::new(transport,provider,auth);
            let mut request=actual_siwc_request_fixture();crate::broker_request_profile::prepare_siwc_request(&mut request)?;
            let error=client.stream_request(request,codex_api::ResponsesOptions::default()).await.err().ok_or_else(||invalid("fixture expected HTTP refusal"))?;
            assert!(SiwcFailure::from_error(&error).is_some());
            let captured=calls.lock().map_err(|_|invalid("fixture capture unavailable"))?;
            assert_eq!(captured.len(),1);let actual=&captured[0];assert_eq!(actual.method,http::Method::POST);assert_eq!(actual.url,"https://api.openai.com/v1/responses");
            assert!(actual.headers[http::header::AUTHORIZATION].is_sensitive());
            assert_eq!(actual.headers[http::header::AUTHORIZATION],"Bearer synthetic-siwc-access");
            assert!(actual.headers.get("chatgpt-account-id").is_none() && actual.headers.get(http::header::COOKIE).is_none());
            let body=match actual.body.as_ref() {Some(codex_client::RequestBody::EncodedJson(body))=>body.as_bytes(),_=>return Err(invalid("fixture expected actual encoded JSON"))};
            let body:Value=serde_json::from_slice(body).map_err(|_|invalid("fixture actual body invalid"))?;
            assert_eq!(body["store"],false);assert_eq!(body["stream"],true);assert_eq!(body["input"].as_array().map(Vec::len),Some(1));
            assert!(body.get("previous_response_id").is_none());
            Ok(())
        }

        #[tokio::test]
        async fn actual_responses_open_stream_usage_failure_never_becomes_replacement_authority() -> std::io::Result<()> {
            use futures::StreamExt;
            let calls=Arc::new(Mutex::new(Vec::new()));let transport=SiwcLocalTransport {calls:Arc::clone(&calls),after_open:true};
            let info:codex_model_provider_info::ModelProviderInfo=serde_json::from_value(json!({"name":"Omux SIWC Responses","base_url":SIWC_AUDIENCE,"requires_openai_auth":false,"supports_websockets":false})).map_err(|_|invalid("fixture provider invalid"))?;
            let mut provider=info.to_api_provider(None).map_err(|_|invalid("fixture provider invalid"))?;provider.headers.clear();provider.retry.max_attempts=0;
            provider.retry.retry_429=false;provider.retry.retry_5xx=false;provider.retry.retry_transport=false;
            let client=codex_api::ResponsesClient::new(transport,provider,materialized_siwc(siwc_grant_result(u64::MAX),&test_lease(u64::MAX))?);
            let mut stream=client.stream_request(actual_siwc_request_fixture(),codex_api::ResponsesOptions::default()).await.map_err(|_|invalid("fixture stream did not open"))?;
            let event=stream.next().await.ok_or_else(||invalid("fixture failed stream event absent"))?;
            assert!(event.is_err());
            assert!(SiwcFailure::from_error(&ApiError::QuotaExceeded).is_none());
            assert_eq!(calls.lock().map_err(|_|invalid("fixture capture unavailable"))?.len(),1);
            Ok(())
        }

        fn siwc_grant_result(expiry: u64) -> Value {
            json!({"request_profile":SIWC_PROFILE,"issuer":SIWC_ISSUER,"audience":SIWC_AUDIENCE,
                "auth_mode":SIWC_AUTH_MODE,"access_token":"synthetic-siwc-access","expires_at":expiry,"route_generation":7})
        }

        #[tokio::test]
        async fn siwc_private_request_joins_distinct_profile_and_bearer_without_native_account_header() -> std::io::Result<()> {
            let broker = MockBroker::new().await?;
            let thread_id = broker.thread_id()?;
            let server = serve(broker.listener, vec![
                result("adapter.acquire", lease_result(u64::MAX)),
                result("adapter.materialize", siwc_grant_result(u64::MAX)),
                result("adapter.report", json!({"recorded":true})),
            ]);
            let lease = broker.binding.acquire_for_profile(thread_id, "siwc-request", "siwc-model", RequestProfile::SiwcResponses).await?;
            let auth = broker.binding.materialize_for_profile(&lease, RequestProfile::SiwcResponses).await?;
            let headers = auth.resolve_auth_headers().await.map_err(|_| invalid("SIWC fixture authorization failed"))?;
            assert_eq!(headers.len(), 1);
            assert_eq!(headers[http::header::AUTHORIZATION], "Bearer synthetic-siwc-access");
            assert!(headers[http::header::AUTHORIZATION].is_sensitive());
            assert!(broker.binding.materialize(&lease).await.is_err());
            assert!(broker.binding.acquire(thread_id, "wrong-profile", "siwc-model").await.is_err());
            broker.binding.report(&lease, "abandoned", None).await?;
            let requests = served(server).await?;
            assert_eq!(requests.len(), 3);
            assert_eq!(requests[0]["params"]["request_profile"], SIWC_PROFILE);
            assert_eq!(requests[0]["params"]["demand"]["provider"], "openai_siwc");
            assert_eq!(requests[0]["params"]["demand"]["audience"], SIWC_AUDIENCE);
            assert_eq!(requests[1]["params"]["request_profile"], SIWC_PROFILE);
            assert_eq!(requests[1]["params"]["lease_handle"], lease.lease_handle);
            Ok(())
        }

        #[tokio::test]
        async fn legacy_private_materialization_refuses_typed_siwc_authority() -> std::io::Result<()> {
            let broker = MockBroker::new().await?;
            let server = serve(broker.listener, vec![result("adapter.materialize", siwc_grant_result(u64::MAX))]);
            assert!(broker.binding.materialize(&test_lease(u64::MAX)).await.is_err());
            assert_eq!(served(server).await?.len(), 1);
            Ok(())
        }

        #[test]
        fn siwc_materialization_refuses_old_grant_wrong_authority_and_extra_account_header() -> std::io::Result<()> {
            let lease = test_lease(u64::MAX);
            assert!(materialized_siwc(grant_result(u64::MAX, 7), &lease).is_err());
            assert!(materialized_siwc(json!([SIWC_PROFILE,SIWC_ISSUER,SIWC_AUDIENCE,SIWC_AUTH_MODE,"synthetic-siwc-access",u64::MAX,7]), &lease).is_err());
            for (key, value) in [
                ("request_profile", json!("native_chatgpt")), ("issuer", json!(ISSUER)),
                ("audience", json!(ISSUER)), ("auth_mode", json!("chatgpt_access_token")),
                ("route_generation", json!(8)), ("expires_at", json!(0)),
                ("provider_account_id", json!("synthetic-workspace")), ("ready", json!(true)),
            ] {
                let mut grant = siwc_grant_result(u64::MAX); grant[key] = value;
                assert!(materialized_siwc(grant, &lease).is_err());
            }
            let auth = materialized_siwc(siwc_grant_result(u64::MAX), &test_lease(0))?;
            assert_eq!(auth.expires_at, 0);
            assert!(auth.account.is_none());
            Ok(())
        }

        #[tokio::test]
        async fn acquire_materialize_and_rejection_use_the_exact_private_contract()
        -> std::io::Result<()> {
            let broker = MockBroker::new().await?;
            let thread_id = broker.thread_id()?;
            let server = serve(
                broker.listener,
                vec![
                    result("adapter.acquire", lease_result(u64::MAX)),
                    result("adapter.materialize", grant_result(u64::MAX, 7)),
                    result("adapter.report", json!({"recorded":true})),
                ],
            );
            let lease = broker
                .binding
                .acquire(thread_id, "test-request", "test-exact-model")
                .await?;
            let auth = broker.binding.materialize(&lease).await?;
            let headers = auth
                .resolve_auth_headers()
                .await
                .map_err(|_| invalid("test authorization was not materialized"))?;
            assert!(
                headers
                    .get(http::header::AUTHORIZATION)
                    .is_some_and(HeaderValue::is_sensitive)
            );
            assert!(
                headers
                    .get("chatgpt-account-id")
                    .is_some_and(HeaderValue::is_sensitive)
            );
            broker.binding.report(&lease, "rejected", Some(429)).await?;

            let requests = served(server).await?;
            let expected_acquire = scoped(
                json!({
                    "capability":TEST_CAPABILITY,
                    "application":"codex",
                    "binding_id":"test-binding",
                    "session_id":thread_id.to_string(),
                    "request_id":"test-request",
                    "demand":{
                        "provider":"codex", "audience":ISSUER, "purpose":"request",
                        "resource":{"kind":"model", "target":"test-exact-model", "unit":"tokens", "scope":""},
                        "required":1,
                    },
                }),
                &broker._custody,
            );
            assert!(requests[0]["params"] == expected_acquire);
            assert!(
                requests[1]["params"]
                    == scoped(
                        json!({
                            "capability":TEST_CAPABILITY, "application":"codex", "lease_handle":TEST_LEASE,
                        }),
                        &broker._custody
                    )
            );
            assert!(
                requests[2]["params"]
                    == scoped(
                        json!({
                            "capability":TEST_CAPABILITY, "application":"codex", "lease_handle":TEST_LEASE,
                            "event":"rejected", "status":429, "pre_acceptance":true, "response_started":false,
                        }),
                        &broker._custody
                    )
            );
            Ok(())
        }

        #[tokio::test]
        async fn ambient_activity_blocks_registration_until_actual_work_drains()
        -> std::io::Result<()> {
            let broker = MockBroker::new().await?;
            let thread_id = ThreadId::new();
            let first = try_acquire_ambient_activity(thread_id)
                .ok_or_else(|| invalid("first native activity was unexpectedly blocked"))?;
            let second = try_acquire_ambient_activity(thread_id)
                .ok_or_else(|| invalid("second native activity was unexpectedly blocked"))?;
            let error = register(
                thread_id,
                broker.binding.socket.clone(),
                broker.binding.capability_path.clone(),
                "test-binding".to_owned(),
            )
            .await
            .expect_err("active native work prevents adoption");
            assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
            assert!(binding(thread_id).is_none());
            assert!(!ambient_blocked(thread_id));
            drop(first);
            assert!(
                register(
                    thread_id,
                    broker.binding.socket.clone(),
                    broker.binding.capability_path.clone(),
                    "test-binding".to_owned(),
                )
                .await
                .is_err()
            );
            drop(second);
            register(
                thread_id,
                broker.binding.socket.clone(),
                broker.binding.capability_path.clone(),
                "test-binding".to_owned(),
            )
            .await?;
            let (_, custody) = owner_tests::complete(thread_id, &broker.listener).await?;
            assert!(try_acquire_ambient_activity(thread_id).is_none());
            unregister(thread_id, false);
            assert!(try_acquire_ambient_activity(thread_id).is_none());
            forget(thread_id);
            assert!(try_acquire_ambient_activity(thread_id).is_none());
            custody.detach()?;
            forget(thread_id);
            assert!(try_acquire_ambient_activity(thread_id).is_some());
            Ok(())
        }

        #[tokio::test]
        async fn opened_capability_rejects_symlink_and_fifo_substitution() -> std::io::Result<()> {
            use std::os::unix::ffi::OsStrExt;
            let broker = MockBroker::new().await?;
            let path = &broker.binding.capability_path;
            let saved = path.with_extension("saved");
            std::fs::rename(path, &saved)?;
            std::os::unix::fs::symlink(&saved, path)?;
            assert!(read_private_capability(path).is_err());
            std::fs::remove_file(path)?;
            let fifo_path = std::ffi::CString::new(path.as_os_str().as_bytes())
                .map_err(|_| invalid("test FIFO path is invalid"))?;
            // Safety: fifo_path is a valid NUL-terminated path; mkfifo copies it.
            if unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            assert!(read_private_capability(path).is_err());
            Ok(())
        }

        #[tokio::test]
        async fn registration_requires_private_paths_and_a_valid_capability() -> std::io::Result<()>
        {
            let broker = MockBroker::new().await?;
            let thread_id = ThreadId::new();
            let socket = broker.binding.socket.clone();
            let capability_path = broker.binding.capability_path.clone();
            register(
                thread_id,
                socket.clone(),
                capability_path.clone(),
                "test-binding".to_owned(),
            )
            .await?;
            let (_, custody) = owner_tests::complete(thread_id, &broker.listener).await?;
            assert!(binding(thread_id).is_some());
            forget(thread_id);
            assert!(binding(thread_id).is_some());
            custody.detach()?;
            forget(thread_id);
            assert!(binding(thread_id).is_none());

            for (path, mode) in [
                (broker._directory.path(), 0o770),
                (capability_path.as_path(), 0o640),
                (socket.as_path(), 0o660),
            ] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
                assert!(
                    register(
                        thread_id,
                        socket.clone(),
                        capability_path.clone(),
                        "test-binding".to_owned()
                    )
                    .await
                    .is_err()
                );
                assert!(binding(thread_id).is_none());
                let private_mode = if path == broker._directory.path() {
                    0o700
                } else {
                    0o600
                };
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(private_mode))?;
            }
            std::fs::write(&capability_path, "g".repeat(64))?;
            assert!(
                register(
                    thread_id,
                    socket.clone(),
                    capability_path.clone(),
                    "test-binding".to_owned()
                )
                .await
                .is_err()
            );
            std::fs::write(&capability_path, &TEST_CAPABILITY[..63])?;
            assert!(
                register(
                    thread_id,
                    socket,
                    capability_path,
                    "test-binding".to_owned()
                )
                .await
                .is_err()
            );
            assert!(binding(thread_id).is_none());
            Ok(())
        }

        #[tokio::test]
        async fn expired_grants_and_mismatched_generations_fail_closed() -> std::io::Result<()> {
            let broker = MockBroker::new().await?;
            let server = serve(
                broker.listener,
                vec![
                    result("adapter.materialize", grant_result(0, 7)),
                    result("adapter.materialize", grant_result(u64::MAX, 8)),
                    result("adapter.materialize", grant_result(u64::MAX, 7)),
                ],
            );
            assert!(
                broker
                    .binding
                    .materialize(&test_lease(u64::MAX))
                    .await
                    .is_err()
            );
            assert!(
                broker
                    .binding
                    .materialize(&test_lease(u64::MAX))
                    .await
                    .is_err()
            );
            // Request-time validation also respects the lease bound, even when the grant lives longer.
            let auth = broker.binding.materialize(&test_lease(0)).await?;
            assert!(auth.resolve_auth_headers().await.is_err());
            let requests = served(server).await?;
            assert_eq!(requests.len(), 3);
            Ok(())
        }

        #[tokio::test]
        async fn expired_acquired_lease_abandons_exactly_once_without_replay() -> std::io::Result<()>
        {
            let broker = MockBroker::new().await?;
            let thread_id = broker.thread_id()?;
            let server = tokio::spawn(serve_retaining_listener(
                broker.listener,
                vec![
                    result("adapter.acquire", lease_result(0)),
                    result("adapter.report", json!({"recorded":true})),
                ],
            ));
            assert!(
                broker
                    .binding
                    .acquire(thread_id, "test-expired-request", "test-model")
                    .await
                    .is_err()
            );
            let (requests, listener) = tokio::time::timeout(Duration::from_secs(5), server)
                .await
                .map_err(|_| invalid("expired lease cleanup did not finish"))?
                .map_err(|_| invalid("expired lease cleanup task did not finish"))??;
            assert_eq!(requests.len(), 2);
            assert!(
                requests[1]["params"]
                    == scoped(
                        json!({
                            "application":"codex", "capability":TEST_CAPABILITY,
                            "lease_handle":TEST_LEASE, "event":"abandoned",
                            "pre_acceptance":false, "response_started":true,
                        }),
                        &broker._custody
                    )
            );
            // Keep the endpoint available so a duplicate report, materialization
            // or reacquisition would be observed rather than fail to connect.
            assert!(
                tokio::time::timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err()
            );
            Ok(())
        }

        #[tokio::test]
        async fn preparation_failure_abandons_the_acquired_lease_without_allowing_replay()
        -> std::io::Result<()> {
            let broker = MockBroker::new().await?;
            let thread_id = broker.thread_id()?;
            let server = serve(
                broker.listener,
                vec![
                    result("adapter.acquire", lease_result(u64::MAX)),
                    result("adapter.materialize", grant_result(0, 7)),
                    result("adapter.report", json!({"recorded":true})),
                ],
            );
            let lease = broker
                .binding
                .acquire(thread_id, "test-request", "test-model")
                .await?;
            let guard = LeaseGuard::new(Arc::clone(&broker.binding), lease);
            assert!(broker.binding.materialize(&guard.lease).await.is_err());
            drop(guard);
            let requests = served(server).await?;
            assert!(
                requests[2]["params"]
                    == scoped(
                        json!({
                            "capability":TEST_CAPABILITY, "application":"codex", "lease_handle":TEST_LEASE,
                            "event":"abandoned", "pre_acceptance":false, "response_started":true,
                        }),
                        &broker._custody
                    )
            );
            Ok(())
        }

        #[tokio::test]
        async fn cancelling_an_inflight_request_reports_terminal_abandonment() -> std::io::Result<()>
        {
            let broker = MockBroker::new().await?;
            let server = serve(
                broker.listener,
                vec![result("adapter.report", json!({"recorded":true}))],
            );
            let guard = LeaseGuard::new(Arc::clone(&broker.binding), test_lease(u64::MAX));
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let operation = tokio::spawn(async move {
                let _guard = guard;
                ready_tx
                    .send(())
                    .map_err(|_| invalid("test cancellation receiver stopped"))?;
                std::future::pending::<()>().await;
                Ok::<(), std::io::Error>(())
            });
            tokio::time::timeout(Duration::from_secs(5), ready_rx)
                .await
                .map_err(|_| invalid("test request did not become active"))?
                .map_err(|_| invalid("test request stopped before cancellation"))?;
            operation.abort();
            assert!(matches!(operation.await, Err(error) if error.is_cancelled()));
            let requests = served(server).await?;
            assert!(requests[0]["params"]["event"] == "abandoned");
            assert!(requests[0]["params"]["pre_acceptance"] == false);
            assert!(requests[0]["params"]["response_started"] == true);
            Ok(())
        }

        #[tokio::test]
        async fn recorded_completion_disarms_terminal_cleanup() -> std::io::Result<()> {
            let broker = MockBroker::new().await?;
            let mut guard = LeaseGuard::new(Arc::clone(&broker.binding), test_lease(u64::MAX));
            // An explicit recorded completion is the sole reason this request is disarmed.
            let completed = tokio::spawn(async move {
                let (socket, _) = broker.listener.accept().await?;
                let mut socket = BufReader::new(socket);
                let mut frame = Vec::new();
                socket.read_until(b'\n', &mut frame).await?;
                let request: Value = serde_json::from_slice(&frame)
                    .map_err(|_| invalid("test completion request is not JSON"))?;
                if request["method"] != "adapter.report"
                    || request["params"]["event"] != "completed"
                {
                    return Err(invalid("test completion differs from the contract"));
                }
                socket
                    .get_mut()
                    .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"recorded\":true}}\n")
                    .await?;
                Ok::<_, std::io::Error>((broker._directory, broker.listener))
            });
            guard
                .binding
                .report(&guard.lease, "completed", None)
                .await?;
            guard.disarm();
            drop(guard);
            let (_directory, listener) = tokio::time::timeout(Duration::from_secs(5), completed)
                .await
                .map_err(|_| invalid("test completion was not recorded"))?
                .map_err(|_| invalid("test completion task did not finish"))??;
            assert!(
                tokio::time::timeout(Duration::from_millis(100), listener.accept())
                    .await
                    .is_err()
            );
            Ok(())
        }

        #[tokio::test]
        async fn native_completed_waits_for_committed_terminal_report() -> std::io::Result<()> {
            let broker = MockBroker::new().await?;
            let mut guard = LeaseGuard::new(Arc::clone(&broker.binding), test_lease(u64::MAX));
            let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
            let (seen_sender, seen_receiver) = tokio::sync::oneshot::channel();
            let (ack_sender, ack_receiver) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let (socket, _) = broker.listener.accept().await?;
                let mut socket = BufReader::new(socket);
                let mut frame = Vec::new();
                socket.read_until(b'\n', &mut frame).await?;
                let request: Value = serde_json::from_slice(&frame)
                    .map_err(|_| invalid("test completion request is not JSON"))?;
                if request["method"] != "adapter.report"
                    || request["params"]["event"] != "completed"
                    || request["params"]["lease_handle"] != TEST_LEASE
                    || request["params"]["native_ref"] != json!(broker._custody.tuple.native_ref())
                {
                    return Err(invalid("test completion differs from owned contract"));
                }
                seen_sender.send(()).map_err(|_| invalid("completion observer stopped"))?;
                ack_receiver.await.map_err(|_| invalid("completion acknowledgment stopped"))?;
                socket.get_mut()
                    .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"recorded\":true}}\n")
                    .await?;
                Ok::<_, std::io::Error>((broker._directory, broker.listener))
            });
            let producer = tokio::spawn(async move {
                assert!(guard.forward_event(
                    Ok(codex_api::ResponseEvent::OutputTextDelta("synthetic accepted output".into())),
                    &sender,
                ).await);
                assert!(!guard.forward_event(
                    Ok(codex_api::ResponseEvent::Completed {
                        response_id: "synthetic-response".into(),
                        token_usage: None,
                        usage_metadata: None,
                        end_turn: Some(true),
                    }),
                    &sender,
                ).await);
                assert!(!guard.armed);
            });
            assert!(matches!(receiver.recv().await,
                Some(Ok(codex_api::ResponseEvent::OutputTextDelta(_)))));
            seen_receiver.await.map_err(|_| invalid("completion request was not observed"))?;
            assert!(matches!(receiver.try_recv(), Err(tokio::sync::mpsc::error::TryRecvError::Empty)));
            assert!(!producer.is_finished());
            ack_sender.send(()).map_err(|_| invalid("completion producer stopped"))?;
            assert!(matches!(receiver.recv().await,
                Some(Ok(codex_api::ResponseEvent::Completed { .. }))));
            producer.await.map_err(|_| invalid("completion producer failed"))?;
            let (_directory, listener) = server.await
                .map_err(|_| invalid("completion server failed"))??;
            assert!(tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await.is_err());
            Ok(())
        }

        #[tokio::test]
        async fn uncommitted_terminal_report_never_exposes_native_completed() -> std::io::Result<()> {
            let broker = MockBroker::new().await?;
            let mut guard = LeaseGuard::new(Arc::clone(&broker.binding), test_lease(u64::MAX));
            let (sender, mut receiver) = tokio::sync::mpsc::channel(4);
            let server = serve(broker.listener, vec![
                result("adapter.report", json!({"recorded":false})),
                result("adapter.report", json!({"recorded":true})),
            ]);
            assert!(!guard.forward_event(
                Ok(codex_api::ResponseEvent::Completed {
                    response_id: "synthetic-response".into(),
                    token_usage: None,
                    usage_metadata: None,
                    end_turn: Some(true),
                }),
                &sender,
            ).await);
            assert!(guard.armed);
            assert!(matches!(receiver.recv().await, Some(Err(_))));
            drop(guard);
            drop(sender);
            assert!(receiver.recv().await.is_none());
            let requests = served(server).await?;
            assert!(requests.len() == 2);
            assert!(requests[0]["params"]["event"] == "completed");
            assert!(requests[1]["params"]["event"] == "abandoned");
            assert!(requests[1]["params"]["lease_handle"] == TEST_LEASE);
            Ok(())
        }

        #[tokio::test]
        async fn detached_native_reentry_checks_actual_context_before_restoring_ambient_auth()
        -> std::io::Result<()> {
            let broker = MockBroker::new().await?;
            let thread_id = ThreadId::new();
            register(
                thread_id,
                broker.binding.socket.clone(),
                broker.binding.capability_path.clone(),
                "test-binding".to_owned(),
            )
            .await?;
            let (_, first_custody) = owner_tests::complete(thread_id, &broker.listener).await?;
            assert!(ambient_blocked(thread_id));
            assert!(!native_reentry_pending(thread_id));
            assert!(validate_native_reentry(thread_id, &json!([])).is_err());

            // Detachment retains a fence even when a racing final response added opaque state.
            first_custody.detach()?;
            assert!(binding(thread_id).is_none());
            assert!(native_reentry_pending(thread_id));
            assert!(ambient_blocked(thread_id));
            for input in [
                json!([{"encrypted_content":"synthetic-opaque-context"}]),
                json!([{"image":{"file_id":"synthetic-file"}}]),
                json!([{"encrypted_function_args":["synthetic-opaque-arguments"]}]),
            ] {
                assert!(validate_native_reentry(thread_id, &input).is_err());
                assert!(native_reentry_pending(thread_id));
                assert!(ambient_blocked(thread_id));
            }

            let portable = json!([{"type":"message", "content":"retained portable text"}]);
            assert!(validate_native_reentry(thread_id, &portable)?);
            assert!(!native_reentry_pending(thread_id));
            assert!(!ambient_blocked(thread_id));
            assert!(!validate_native_reentry(thread_id, &portable)?);

            register(
                thread_id,
                broker.binding.socket.clone(),
                broker.binding.capability_path.clone(),
                "test-binding".to_owned(),
            )
            .await?;
            let (_, second_custody) = owner_tests::complete(thread_id, &broker.listener).await?;
            second_custody.detach()?;
            assert!(native_reentry_pending(thread_id));
            forget(thread_id);
            assert!(binding(thread_id).is_none());
            assert!(!native_reentry_pending(thread_id));
            assert!(!ambient_blocked(thread_id));
            // With no issued lease, none of these registry operations calls the broker.
            assert!(
                tokio::time::timeout(Duration::from_millis(100), broker.listener.accept())
                    .await
                    .is_err()
            );
            Ok(())
        }

        #[tokio::test]
        async fn metadata_status_is_allowlisted_and_rejects_other_account_or_generation()
        -> std::io::Result<()> {
            let broker = MockBroker::new().await?;
            let thread_id = ThreadId::new();
            register(
                thread_id,
                broker.binding.socket.clone(),
                broker.binding.capability_path.clone(),
                "test-binding".to_owned(),
            )
            .await?;
            let (_, custody) = owner_tests::complete(thread_id, &broker.listener).await?;
            let registered =
                binding(thread_id).ok_or_else(|| invalid("test binding was not registered"))?;
            let lease = test_lease(u64::MAX);
            registered.adopt_route(&lease, &json!([]))?;
            assert!(status(thread_id).is_none());
            let expected_metadata = json!({
                "bound":true, "custody_available":true,
                "binding_id":"test-binding", "account_id":"test-account",
                "account_label":"Synthetic lab account", "account_type":"oauth",
                "provider":"codex", "grant_id":"test-grant", "generation":1,
                "route_generation":7, "lifecycle":"active", "grant_status":"active",
                "provider_expires_at":9000, "custody_expires_at":8000,
            });
            let mut hostile_metadata = expected_metadata.clone();
            for field in ["access_token", "provider_account_id", "subject", "email"] {
                hostile_metadata[field] = json!("synthetic-private-value");
            }
            hostile_metadata["unrecognized_nested_data"] =
                json!({"access_token":"synthetic-private-value"});
            let mut other_account = expected_metadata.clone();
            other_account["account_id"] = json!("test-other-account");
            let mut other_generation = expected_metadata.clone();
            other_generation["route_generation"] = json!(8);
            let server = serve(
                broker.listener,
                vec![
                    result("adapter.metadata", hostile_metadata),
                    result("adapter.metadata", other_account),
                    result("adapter.metadata", other_generation),
                    result("adapter.metadata", expected_metadata.clone()),
                ],
            );
            registered.refresh_metadata(thread_id, &lease).await?;
            let cached =
                status(thread_id).ok_or_else(|| invalid("test metadata was not cached"))?;
            assert!(
                cached["observed_at"]
                    .as_u64()
                    .is_some_and(|observed| observed > 0)
            );
            let mut sanitized = cached.clone();
            sanitized
                .as_object_mut()
                .ok_or_else(|| invalid("test status was not an object"))?
                .remove("observed_at");
            assert!(sanitized == expected_metadata);
            for field in [
                "access_token",
                "provider_account_id",
                "subject",
                "email",
                "unrecognized_nested_data",
            ] {
                assert!(cached.get(field).is_none());
            }
            assert!(
                registered
                    .refresh_metadata(thread_id, &lease)
                    .await
                    .is_err()
            );
            assert!(status(thread_id).as_ref() == Some(&cached));
            assert!(
                registered
                    .refresh_metadata(thread_id, &lease)
                    .await
                    .is_err()
            );
            assert!(status(thread_id).as_ref() == Some(&cached));

            let mut next_lease = lease.clone();
            next_lease.account_id = "test-other-account".to_owned();
            next_lease.route_generation = 8;
            assert!(registered.adopt_route(&next_lease, &json!([]))?);
            assert!(status(thread_id).is_none());
            // A delayed response can match its captured old lease while being stale for this thread.
            assert!(
                registered
                    .refresh_metadata(thread_id, &lease)
                    .await
                    .is_err()
            );
            assert!(status(thread_id).is_none());

            let requests = served(server).await?;
            assert_eq!(requests.len(), 4);
            for request in requests {
                assert!(
                    request["params"]
                        == scoped(
                            json!({
                                "application":"codex", "capability":TEST_CAPABILITY,
                                "session_id":thread_id.to_string(), "binding_id":"test-binding",
                            }),
                            &custody
                        )
                );
            }
            custody.detach()?;
            forget(thread_id);
            assert!(status(thread_id).is_none());
            Ok(())
        }

        #[tokio::test]
        async fn binding_release_uses_the_most_recent_issued_lease_as_a_compare_and_swap()
        -> std::io::Result<()> {
            let broker = MockBroker::new().await?;
            let thread_id = broker.thread_id()?;
            let latest_lease_handle = "2".repeat(64);
            let mut next_lease = lease_result(u64::MAX);
            next_lease["lease_handle"] = json!(latest_lease_handle);
            next_lease["route_generation"] = json!(8);
            let server = serve(
                broker.listener,
                vec![
                    result("adapter.acquire", lease_result(u64::MAX)),
                    result("adapter.acquire", next_lease),
                    result("adapter.releaseBinding", json!({"released":true})),
                ],
            );
            broker
                .binding
                .acquire(thread_id, "test-first-request", "test-model")
                .await?;
            broker
                .binding
                .acquire(thread_id, "test-next-request", "test-model")
                .await?;
            // This call schedules cleanup and returns without waiting for the broker callback.
            broker.binding.schedule_release(thread_id);
            let requests = served(server).await?;
            assert!(
                requests[2]["params"]
                    == scoped(
                        json!({
                            "application":"codex", "capability":TEST_CAPABILITY,
                            "session_id":thread_id.to_string(), "binding_id":"test-binding",
                            "expected_lease_handle":latest_lease_handle,
                        }),
                        &broker._custody
                    )
            );
            Ok(())
        }

        #[tokio::test]
        async fn binding_release_does_not_call_the_broker_without_an_issued_lease()
        -> std::io::Result<()> {
            let broker = MockBroker::new().await?;
            broker.binding.schedule_release(ThreadId::new());
            assert!(
                tokio::time::timeout(Duration::from_millis(100), broker.listener.accept())
                    .await
                    .is_err()
            );
            Ok(())
        }
    }
}
