//! Same-process private native owner carrier. R-N13.

use crate::message_processor::MessageProcessor;
use crate::owner_source_context::SourceContext;
use codex_app_server_protocol::{
    OmuxBrokerCapabilities, OmuxOwnerAnnounceParams, OmuxOwnerAnnounceResponse,
    OmuxOwnerCapabilitiesParams, OmuxOwnerCapabilitiesResponse, OmuxOwnerIdentifyParams,
    OmuxOwnerIdentifyResponse, OmuxOwnerRegisterParams, OmuxOwnerThreadsParams,
    OmuxOwnerThreadsResponse, OmuxOwnerUnregisterParams,
    OmuxOwnerAttachmentStatusParams, OmuxOwnerAttachmentStatusResponse,
    OmuxOwnerAttachmentDisposition, OmuxOwnerNativeRef,
    OmuxOwnerSourceContextParams, OmuxOwnerSourceContextResponse, OmuxOwnerSourceContextStatus,
};
use codex_core::auth_broker::{self, NativeAckTuple, ProcessOwner};
use codex_core::native_peer::{self, MAX_PACKET, PacketListener, VerifiedPacket};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request<T> {
    jsonrpc: String,
    id: Value,
    method: String,
    params: T,
}

pub(crate) struct OwnerService {
    cancellation: CancellationToken,
}
impl Drop for OwnerService {
    fn drop(&mut self) {
        self.cancellation.cancel();
    }
}

#[cfg(target_os = "linux")]
struct EndpointCleanup {
    endpoint: PathBuf,
    directory: PathBuf,
    endpoint_identity: Option<(u64, u64)>,
    directory_identity: (u64, u64),
}
#[cfg(target_os = "linux")]
impl Drop for EndpointCleanup {
    fn drop(&mut self) {
        use std::os::unix::fs::MetadataExt;
        let identity = |path: &Path| {
            std::fs::symlink_metadata(path)
                .ok()
                .map(|m| (m.dev(), m.ino()))
        };
        // Remove only the exact filesystem objects created by this service.
        // A replacement endpoint/directory is somebody else's custody.
        if self.endpoint_identity.is_some() && identity(&self.endpoint) == self.endpoint_identity {
            let _ = std::fs::remove_file(&self.endpoint);
        }
        if identity(&self.directory) == Some(self.directory_identity) {
            let _ = std::fs::remove_dir(&self.directory);
        }
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "native owner operation refused")
}

fn params<T: for<'a> Deserialize<'a>>(value: Value) -> io::Result<T> {
    serde_json::from_value(value).map_err(|_| invalid())
}
fn frame_params<T: for<'a> Deserialize<'a>>(bytes: &[u8]) -> io::Result<T> {
    // Parse the original frame into the actual typed payload: converting an
    // untyped JSON object first would erase duplicate authority-bearing keys.
    let request: Request<T> = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    Ok(request.params)
}
fn encoded<T: Serialize>(value: T) -> io::Result<Value> {
    serde_json::to_value(value).map_err(|_| invalid())
}
fn thread(value: &str) -> io::Result<codex_protocol::ThreadId> {
    if value.is_empty() || value.len() > 256 {
        return Err(invalid());
    }
    codex_protocol::ThreadId::from_string(value).map_err(|_| invalid())
}
fn version(value: u32) -> io::Result<()> {
    if value == 2 { Ok(()) } else { Err(invalid()) }
}
fn ack_from_params(value: &Value) -> io::Result<NativeAckTuple> {
    let mut value = value.clone();
    let object = value.as_object_mut().ok_or_else(invalid)?;
    object.remove("brokerSocket");
    object.remove("capabilityPath");
    let ack: NativeAckTuple = params(value)?;
    thread(&ack.thread_id)?;
    ack.validate()?;
    Ok(ack)
}
fn ack_result(ack: NativeAckTuple, field: &str) -> io::Result<Value> {
    let mut value = encoded(ack)?;
    value
        .as_object_mut()
        .ok_or_else(invalid)?
        .insert(field.to_owned(), Value::Bool(true));
    Ok(value)
}

// A new optional declaration cannot disable existing owner/handoff service.
// Preparation/recheck refusal is explicit unavailable metadata, never readiness.
struct SourceDeclaration(Option<SourceContext>);
fn install_owner_with_source_context(
    prepare: impl FnOnce() -> io::Result<SourceContext>,
    install: impl FnOnce() -> io::Result<()>,
) -> io::Result<SourceDeclaration> {
    let declaration = match prepare() {
        Ok(context) => SourceDeclaration(Some(context)),
        Err(_) => SourceDeclaration(None), // Explicit unavailable reply; no I/O diagnostic material.
    };
    install()?;
    Ok(declaration)
}
impl SourceDeclaration {
    fn response(&self, owner: &ProcessOwner) -> OmuxOwnerSourceContextResponse {
        let mut result = OmuxOwnerSourceContextResponse {
            protocol_version: 2, owner_id: owner.owner_id.clone(),
            process_nonce: owner.process_nonce.clone(),
            endpoint_generation: owner.endpoint_generation.clone(),
            status: OmuxOwnerSourceContextStatus::Unavailable,
            source_context_id: None, source_context_generation: None,
            store_present: None, credential_acquisition_authorized: false,
        };
        if let Some(context) = &self.0 {
            if context.recheck(owner).is_ok() {
                result.status = OmuxOwnerSourceContextStatus::Available;
                result.source_context_id = Some(context.context_id.clone());
                result.source_context_generation = Some(context.generation.clone());
                result.store_present = Some(context.store_present);
                if context.recheck(owner).is_err() {
                    result.status = OmuxOwnerSourceContextStatus::Unavailable;
                    result.source_context_id = None;
                    result.source_context_generation = None;
                    result.store_present = None;
                }
            }
        }
        result
    }
}

fn source_context_selector(p: &OmuxOwnerSourceContextParams, owner: &ProcessOwner) -> io::Result<()> {
    version(p.protocol_version)?;
    if p.owner_id != owner.owner_id || p.process_nonce != owner.process_nonce
        || p.endpoint_generation != owner.endpoint_generation {
        return Err(invalid());
    }
    Ok(())
}

impl MessageProcessor {
    async fn dispatch_owner(
        &self,
        method: &str,
        bytes: &[u8],
        peer: native_peer::PeerWitness,
        owner: &ProcessOwner,
        source_context: &SourceDeclaration,
    ) -> io::Result<Value> {
        match method {
            "owner/source/context" => {
                let p: OmuxOwnerSourceContextParams = frame_params(bytes)?;
                source_context_selector(&p, owner)?;
                encoded(source_context.response(owner))
            }
            "owner/capabilities" => {
                let p: OmuxOwnerCapabilitiesParams = frame_params(bytes)?;
                version(p.protocol_version)?;
                let native_version = env!("CARGO_PKG_VERSION").to_owned();
                if native_version.len() > 256 {
                    return Err(invalid());
                }
                encoded(OmuxOwnerCapabilitiesResponse {
                    protocol_version: 2,
                    owner_id: owner.owner_id.clone(),
                    process_nonce: owner.process_nonce.clone(),
                    endpoint_generation: owner.endpoint_generation.clone(),
                    native_version,
                    capabilities: OmuxBrokerCapabilities {
                        protocol_version: 1,
                        late_thread_binding: true,
                        per_request_auth: true,
                        exclusive_refresh_owner: true,
                        preacceptance_failure: true,
                        account_transport_invalidation: true,
                        native_context_reconstruction: true,
                    },
                })
            }
            "owner/threads" => {
                let p: OmuxOwnerThreadsParams = frame_params(bytes)?;
                version(p.protocol_version)?;
                let threads = self.thread_processor.owner_threads().await?;
                encoded(OmuxOwnerThreadsResponse {
                    protocol_version: 2,
                    owner_id: owner.owner_id.clone(),
                    process_nonce: owner.process_nonce.clone(),
                    endpoint_generation: owner.endpoint_generation.clone(),
                    threads,
                })
            }
            "owner/identify" => {
                let p: OmuxOwnerIdentifyParams = frame_params(bytes)?;
                version(p.protocol_version)?;
                let id = thread(&p.thread_id)?;
                self.thread_processor.owner_loaded_thread(id).await?;
                let identity = auth_broker::identify(id)?;
                encoded(OmuxOwnerIdentifyResponse {
                    protocol_version: 2,
                    owner_id: identity.owner_id,
                    process_nonce: identity.process_nonce,
                    endpoint_generation: identity.endpoint_generation,
                    thread_instance_generation: identity.thread_instance_generation,
                    thread_id: identity.thread_id,
                })
            }
            "owner/attachment/status" => {
                let p: OmuxOwnerAttachmentStatusParams = frame_params(bytes)?;
                version(p.protocol_version)?;
                let id = thread(&p.thread_id)?;
                self.thread_processor.owner_loaded_thread(id).await?;
                let snapshot = auth_broker::owner_attachment_snapshot(id)?;
                let disposition = match snapshot.disposition {
                    auth_broker::OwnerAttachmentDisposition::Unmanaged => OmuxOwnerAttachmentDisposition::Unmanaged,
                    auth_broker::OwnerAttachmentDisposition::Pending => OmuxOwnerAttachmentDisposition::Pending,
                    auth_broker::OwnerAttachmentDisposition::Unresolved => OmuxOwnerAttachmentDisposition::Unresolved,
                    auth_broker::OwnerAttachmentDisposition::Attached => OmuxOwnerAttachmentDisposition::Attached,
                    auth_broker::OwnerAttachmentDisposition::Retired => OmuxOwnerAttachmentDisposition::Retired,
                };
                encoded(OmuxOwnerAttachmentStatusResponse {
                    protocol_version: snapshot.protocol_version,
                    owner_id: snapshot.owner_id,
                    process_nonce: snapshot.process_nonce,
                    endpoint_generation: snapshot.endpoint_generation,
                    thread_id: snapshot.thread_id,
                    thread_instance_generation: snapshot.thread_instance_generation,
                    disposition,
                    native_ref: snapshot.native_ref.map(|reference| OmuxOwnerNativeRef {
                        owner_id: reference.owner_id,
                        adapter_epoch: reference.adapter_epoch,
                        endpoint_generation: reference.endpoint_generation,
                        thread_instance_generation: reference.thread_instance_generation,
                        attachment_generation: reference.attachment_generation,
                    }),
                    registration_operation_id: snapshot.registration_operation_id,
                    detach_operation_id: snapshot.detach_operation_id,
                })
            }
            "owner/register" => {
                let p: OmuxOwnerRegisterParams = frame_params(bytes)?;
                let ack = ack_from_params(&encoded(&p)?)?;
                let id = thread(&p.thread_id)?;
                self.activate_native_owner(
                    id,
                    &p.broker_socket,
                    &p.capability_path,
                    ack.clone(),
                    peer,
                )
                .await?;
                ack_result(ack, "registered")
            }
            "owner/unregister" => {
                let p: OmuxOwnerUnregisterParams = frame_params(bytes)?;
                version(p.protocol_version)?;
                let ack = ack_from_params(&encoded(&p)?)?;
                self.thread_processor
                    .owner_detach(thread(&p.thread_id)?, ack.clone(), peer)
                    .await?;
                ack_result(ack, "unregistered")
            }
            "owner/announce" => {
                let p: OmuxOwnerAnnounceParams = frame_params(bytes)?;
                version(p.protocol_version)?;
                let id = thread(&p.thread_id)?;
                let ack = self
                    .thread_processor
                    .owner_announce(id, p.broker_socket, p.capability_path, p.operation_id)
                    .await?;
                encoded(OmuxOwnerAnnounceResponse {
                    protocol_version: ack.protocol_version,
                    owner_id: ack.owner_id,
                    process_nonce: ack.process_nonce,
                    adapter_epoch: ack.adapter_epoch,
                    endpoint_generation: ack.endpoint_generation,
                    thread_instance_generation: ack.thread_instance_generation,
                    attachment_generation: ack.attachment_generation,
                    thread_id: ack.thread_id,
                    operation_id: ack.operation_id,
                    registered: true,
                })
            }
            _ => Err(invalid()),
        }
    }
}

async fn serve(
    mut connection: VerifiedPacket,
    processor: Arc<MessageProcessor>,
    owner: ProcessOwner,
    source_context: Arc<SourceDeclaration>,
) -> io::Result<()> {
    // This connection has one reader throughout; no raw stream read can bypass
    // the C bridge. Its absolute intrinsic deadline bounds blocking workers.
    for _ in 0..8 {
        let (returned, bytes) = tokio::task::spawn_blocking(move || {
            let mut bytes = vec![0; MAX_PACKET];
            let size = connection.recv_packet(&mut bytes)?;
            bytes.truncate(size);
            Ok::<_, io::Error>((connection, bytes))
        })
        .await
        .map_err(|_| invalid())??;
        connection = returned;
        let request: Request<Value> = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if request.jsonrpc != "2.0"
            || !request.id.is_string()
            || request
                .id
                .as_str()
                .is_none_or(|id| id.is_empty() || id.len() > 64)
        {
            return Err(invalid());
        }
        let peer = connection.witness();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(8),
            processor.dispatch_owner(&request.method, &bytes, peer, &owner, &source_context),
        )
        .await;
        let response = match result {
            Ok(Ok(result)) => json!({"jsonrpc":"2.0","id":request.id,"result":result}),
            Ok(Err(error)) => {
                #[cfg(test)]
                eprintln!("native owner operation refused: {:?}", error.kind());
                #[cfg(not(test))]
                let _ = error;
                json!({"jsonrpc":"2.0","id":request.id,"error":{"code":-32602,"message":"native owner operation refused"}})
            }
            Err(_) => {
                #[cfg(test)]
                eprintln!("native owner operation refused: dispatch timeout");
                json!({"jsonrpc":"2.0","id":request.id,"error":{"code":-32602,"message":"native owner operation refused"}})
            }
        };
        let bytes = serde_json::to_vec(&response).map_err(|_| invalid())?;
        if bytes.len() > MAX_PACKET {
            return Err(invalid());
        }
        connection = tokio::task::spawn_blocking(move || {
            connection.send_packet(&bytes)?;
            Ok::<_, io::Error>(connection)
        })
        .await
        .map_err(|_| invalid())??;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn prepare_endpoint(home: &Path) -> io::Result<(PacketListener, EndpointCleanup, ProcessOwner, SourceDeclaration)> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let owner_id = native_peer::random_handle()?;
    let process_nonce = native_peer::random_handle()?;
    let directory = home.join(format!("omux-owner-{}", &owner_id[..16]));
    std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
    let endpoint = directory.join("owner.sock");
    let metadata = std::fs::symlink_metadata(&directory)?;
    let mut cleanup = EndpointCleanup {
        endpoint: endpoint.clone(),
        directory,
        endpoint_identity: None,
        directory_identity: (metadata.dev(), metadata.ino()),
    };
    let listener = PacketListener::bind(&endpoint)?;
    let metadata = std::fs::symlink_metadata(&endpoint)?;
    cleanup.endpoint_identity = Some((metadata.dev(), metadata.ino()));
    std::fs::set_permissions(&endpoint, std::fs::Permissions::from_mode(0o600))?;
    // Actual bidirectional self-exchange checks runtime pidfs/namespace/
    // ancillary support before advertising a capable process endpoint.
    let mut client = VerifiedPacket::connect(&endpoint)?;
    let mut server = listener.try_accept()?;
    client.send_packet(b"profile")?;
    let mut buffer = [0u8; 16];
    if server.recv_packet(&mut buffer)? != 7 || &buffer[..7] != b"profile" {
        return Err(invalid());
    }
    server.send_packet(b"verified")?;
    if client.recv_packet(&mut buffer)? != 8 || &buffer[..8] != b"verified" {
        return Err(invalid());
    }
    let owner = ProcessOwner {
        owner_id,
        process_nonce,
        owner_endpoint: endpoint.clone(),
        endpoint_generation: "1".to_owned(),
    };
    let source_context = install_owner_with_source_context(
        || SourceContext::prepare(home, &owner, &endpoint),
        || auth_broker::install_process_owner(owner.clone()),
    )?;
    Ok((listener, cleanup, owner, source_context))
}

pub(crate) async fn start(
    processor: Arc<MessageProcessor>,
    home: PathBuf,
) -> io::Result<OwnerService> {
    #[cfg(target_os = "linux")]
    {
        let (listener, cleanup, owner, source_context) =
            tokio::task::spawn_blocking(move || prepare_endpoint(&home))
                .await
                .map_err(|_| invalid())??;
        let source_context = Arc::new(source_context);
        let cancellation = CancellationToken::new();
        let stop = cancellation.clone();
        let permits = Arc::new(Semaphore::new(16));
        tokio::spawn(async move {
            let mut workers = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _ = stop.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {},
                    _ = workers.join_next(), if !workers.is_empty() => {},
                }
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    continue;
                };
                match listener.try_accept() {
                    Ok(connection) => {
                        let processor = Arc::clone(&processor);
                        let owner = owner.clone();
                        let source_context = Arc::clone(&source_context);
                        workers.spawn(async move {
                            let _permit = permit;
                            let _ = serve(connection, processor, owner, source_context).await;
                        });
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => {} // Rejected peers never enter protocol dispatch.
                }
            }
            // Do not cancel a worker halfway through an authority transition.
            // Every worker/connection has an intrinsic bounded deadline.
            while workers.join_next().await.is_some() {}
            drop(source_context);
            drop(listener);
            let _ = tokio::task::spawn_blocking(move || drop(cleanup)).await;
        });
        Ok(OwnerService { cancellation })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (processor, home);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "native owner peer profile unavailable",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn refused_optional_context_preserves_owner_installation_and_rotation_is_unavailable() {
        use std::cell::Cell;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixListener;
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let runtime = root.path().join("runtime");
        let endpoint_parent = home.join("owner");
        for path in [&home, &runtime, &endpoint_parent] {
            std::fs::create_dir(path).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let endpoint = endpoint_parent.join("owner.sock");
        let _listener = UnixListener::bind(&endpoint).unwrap();
        std::fs::set_permissions(&endpoint, std::fs::Permissions::from_mode(0o600)).unwrap();
        let owner = ProcessOwner { owner_id: "a".repeat(64), process_nonce: "b".repeat(64),
            owner_endpoint: endpoint, endpoint_generation: "1".to_owned() };
        let installed = Cell::new(0);
        let install = || { installed.set(installed.get() + 1); Ok(()) };
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o755)).unwrap();
        let unavailable = install_owner_with_source_context(
            || SourceContext::prepare_fixture(&home, &owner, &owner.owner_endpoint, &runtime), install).unwrap();
        assert_eq!(installed.get(), 1);
        let reply = unavailable.response(&owner);
        assert_eq!(reply.status, OmuxOwnerSourceContextStatus::Unavailable);
        assert!(reply.source_context_id.is_none() && reply.store_present.is_none());
        assert!(!reply.credential_acquisition_authorized);
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        let available = install_owner_with_source_context(
            || SourceContext::prepare_fixture(&home, &owner, &owner.owner_endpoint, &runtime), install).unwrap();
        assert_eq!(installed.get(), 2);
        assert_eq!(available.response(&owner).status, OmuxOwnerSourceContextStatus::Available);
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(available.response(&owner).status, OmuxOwnerSourceContextStatus::Unavailable);
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        let auth = home.join("auth.json");
        std::fs::write(&auth, b"synthetic metadata-only test material").unwrap();
        std::fs::set_permissions(&auth, std::fs::Permissions::from_mode(0o600)).unwrap();
        let rotated = available.response(&owner);
        assert_eq!(rotated.status, OmuxOwnerSourceContextStatus::Unavailable);
        assert!(rotated.source_context_id.is_none() && rotated.store_present.is_none());
        let refused_install = install_owner_with_source_context(
            || Err(io::Error::new(io::ErrorKind::Unsupported, "fixture unavailable")),
            || Err(io::Error::new(io::ErrorKind::PermissionDenied, "fixture installer refusal")));
        assert_eq!(refused_install.err().unwrap().kind(), io::ErrorKind::PermissionDenied);
        // Optional context failure is contained; an actual owner-install failure still propagates.
    }

    #[test]
    fn source_context_requires_exact_owner_incarnation_and_strict_original_frame() {
        let owner = ProcessOwner { owner_id: "a".repeat(64), process_nonce: "b".repeat(64),
            owner_endpoint: PathBuf::from("/fixture/owner.sock"), endpoint_generation: "1".to_owned() };
        let mut p = OmuxOwnerSourceContextParams { protocol_version: 2,
            owner_id: owner.owner_id.clone(), process_nonce: owner.process_nonce.clone(),
            endpoint_generation: owner.endpoint_generation.clone() };
        assert!(source_context_selector(&p, &owner).is_ok());
        p.process_nonce = "c".repeat(64);
        assert!(source_context_selector(&p, &owner).is_err());
        p.process_nonce = owner.process_nonce.clone(); p.endpoint_generation = "2".to_owned();
        assert!(source_context_selector(&p, &owner).is_err());
        p.endpoint_generation = "1".to_owned(); p.protocol_version = 1;
        assert!(source_context_selector(&p, &owner).is_err());
        p.protocol_version = 2; p.owner_id = "d".repeat(64);
        assert!(source_context_selector(&p, &owner).is_err());
        let forged = br#"{"jsonrpc":"2.0","id":"x","method":"owner/source/context","params":{"protocolVersion":2,"ownerId":"a","processNonce":"b","endpointGeneration":"1","sourcePath":"/arbitrary/auth.json"}}"#;
        assert!(frame_params::<OmuxOwnerSourceContextParams>(forged).is_err());
        let duplicate = br#"{"jsonrpc":"2.0","id":"x","method":"owner/source/context","params":{"protocolVersion":2,"ownerId":"a","ownerId":"c","processNonce":"b","endpointGeneration":"1"}}"#;
        assert!(frame_params::<OmuxOwnerSourceContextParams>(duplicate).is_err());
    }

    #[test]
    fn attachment_status_rejects_asserted_authority_and_duplicate_params() {
        let duplicate = br#"{"jsonrpc":"2.0","id":"test","method":"owner/attachment/status","params":{"protocolVersion":2,"threadId":"a","threadId":"b"}}"#;
        assert!(frame_params::<OmuxOwnerAttachmentStatusParams>(duplicate).is_err());
        let asserted = br#"{"jsonrpc":"2.0","id":"test","method":"owner/attachment/status","params":{"protocolVersion":2,"threadId":"a","nativeRef":{}}}"#;
        assert!(frame_params::<OmuxOwnerAttachmentStatusParams>(asserted).is_err());
        let malformed = br#"{"jsonrpc":"2.0","id":"test","method":"owner/attachment/status","params":{"protocolVersion":"2","threadId":"a"}}"#;
        assert!(frame_params::<OmuxOwnerAttachmentStatusParams>(malformed).is_err());
        assert!(version(1).is_err());
        assert!(thread("a").is_err());
    }

    #[test]
    fn original_frame_rejects_duplicate_and_unknown_owner_fields() {
        let duplicate = br#"{"jsonrpc":"2.0","id":"test","method":"owner/identify","params":{"protocolVersion":2,"threadId":"a","threadId":"b"}}"#;
        assert!(frame_params::<OmuxOwnerIdentifyParams>(duplicate).is_err());
        let extra = br#"{"jsonrpc":"2.0","id":"test","method":"owner/identify","params":{"protocolVersion":2,"threadId":"a","ownerId":"asserted"}}"#;
        assert!(frame_params::<OmuxOwnerIdentifyParams>(extra).is_err());
        let duplicate_id = br#"{"jsonrpc":"2.0","id":"first","id":"second","method":"owner/identify","params":{"protocolVersion":2,"threadId":"a"}}"#;
        assert!(frame_params::<OmuxOwnerIdentifyParams>(duplicate_id).is_err());
    }
}
