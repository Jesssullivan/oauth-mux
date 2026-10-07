"""Offline provenance/apply oracle. This does not promote native runtime support."""

import argparse
import copy
import json
import re
import tempfile
from pathlib import Path

from patch_io import (apply_exact, combine_changes, deterministic_archive, digest,
                      read_archive, validate_manifest, verify_artifact, verify_base,
                      verify_inputs)
from refresh_artifact import package, text_patch


def compact(source: str) -> str:
    return re.sub(r"\s+", "", source)


def require(source: str, *needles: str) -> None:
    source = compact(source)
    for needle in needles:
        if compact(needle) not in source:
            raise AssertionError(f"native hook invariant is absent: {needle}")


def precedes(source: str, before: str, after: str) -> None:
    require(source, before, after)
    source = compact(source)
    assert source.index(compact(before)) < source.index(compact(after)), (before, after)


def rejects(operation, message: str) -> None:
    try:
        operation()
    except (ValueError, UnicodeError):
        return
    raise AssertionError(message)


def tooling_cases() -> None:
    """Exercise binary custody and exact patch boundaries independently of native source."""
    path = "codex-rs/generated/context.rs"
    for before, after in [(b"old", b"new"), (b"old\n", b"new"), (b"old", b"new\n"),
                          (b"first\n--- content\nlast\n", b"first\n+++ content\nlast\n"),
                          (None, b"new"), (b"", b"first\n")]:
        original = {} if before is None else {path: before}
        changed = apply_exact(text_patch(path, before, after), original)
        assert changed == {path: after}
    # Insertion ranges with zero old lines must retain the requested insertion point.
    insert = f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -1,0 +2 @@\n+middle\n"
    assert apply_exact(insert, {path: b"first\nlast\n"})[path] == b"first\nmiddle\nlast\n"
    rejects(lambda: apply_exact(insert.replace("+2 @@", "+3 @@"), {path: b"first\nlast\n"}),
            "destination line mismatch accepted")
    rejects(lambda: apply_exact(insert + "unreviewed\n", {path: b"first\nlast\n"}),
            "trailing patch content accepted")
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        original = {"LICENSE": b"license\n", "NOTICE": b"notice\n",
                    "codex-rs/schema/existing.json": b'{"old":1}\n',
                    "codex-rs/schema/export.json.zst": b"\x28\xb5\x2f\xfd\x00old"}
        edited = {"codex-rs/schema/existing.json": b'{"new":2}\n',
                  "codex-rs/schema/export.json.zst": b"\x28\xb5\x2f\xfd\x00new",
                  "codex-rs/schema/new.json": b'{"new":true}\n'}
        for name, value in edited.items():
            destination = root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(value)
        args = (original, root, ["codex-rs/schema/new.json"])
        manifest, patch, base, overlay = package(*args)
        assert (manifest, patch, base, overlay) == package(*args)
        assert b"base64" not in patch and b"export.json.zst" not in patch
        originals = read_archive(base)
        verify_base(originals, manifest)
        assert combine_changes(patch, overlay, originals, manifest) == edited
        assert read_archive(overlay) == {"codex-rs/schema/export.json.zst": edited["codex-rs/schema/export.json.zst"]}
        rejects(lambda: combine_changes(patch, overlay + b"changed", originals, manifest),
                "binary overlay checksum was not enforced")
        modified = copy.deepcopy(manifest)
        modified["files"]["codex-rs/schema/export.json.zst"]["after_sha256"] = "0" * 64
        rejects(lambda: combine_changes(patch, overlay, originals, modified),
                "binary after checksum was not enforced")
        modified = copy.deepcopy(manifest)
        modified["files"]["codex-rs/schema/export.json.zst"]["before_sha256"] = "0" * 64
        rejects(lambda: verify_base(originals, modified), "binary before checksum was not enforced")
        unlisted = read_archive(overlay)
        unlisted["codex-rs/schema/unlisted.zst"] = b"unlisted"
        unlisted_overlay = deterministic_archive(unlisted)
        modified = copy.deepcopy(manifest)
        modified["binary_overlay_sha256"] = digest(unlisted_overlay)
        rejects(lambda: combine_changes(patch, unlisted_overlay, originals, modified),
                "unlisted binary overlay member was accepted")
        modified = copy.deepcopy(manifest)
        modified["files"]["../outside"] = modified["files"].pop("codex-rs/schema/new.json")
        rejects(lambda: validate_manifest(modified), "unsafe manifest path was accepted")
        # A write checkout must preserve binary originals and refuse any parent symlink.
        checkout = root / "checkout"
        for name, value in original.items():
            destination = checkout / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(value)
        verify_inputs(checkout, manifest)
        (checkout / "codex-rs/schema/export.json.zst").write_bytes(b"different")
        rejects(lambda: verify_inputs(checkout, manifest), "binary checkout mismatch was accepted")
        (checkout / "codex-rs/schema/export.json.zst").write_bytes(original["codex-rs/schema/export.json.zst"])
        link = checkout / "codex-rs/schema/new.json"
        link.symlink_to(root / "absent")
        rejects(lambda: verify_inputs(checkout, manifest), "dangling output symlink was accepted")
    assert read_archive(deterministic_archive({})) == {}


def generated_contract_cases(changed: dict[str, bytes], manifest: dict) -> None:
    """Require the generated wire/config contract to travel with the reviewed source."""
    schema_root = "codex-rs/app-server-protocol/schema/"
    request = json.loads(changed[schema_root + "json/ClientRequest.json"])
    methods = {method for variant in request["oneOf"]
               for method in variant["properties"]["method"]["enum"]}
    broker_methods = {"omux/broker/capabilities", "omux/broker/register",
                      "omux/broker/unregister", "omux/broker/thread/status"}
    assert broker_methods <= methods
    require(changed[schema_root + "typescript/ClientRequest.ts"].decode(), *broker_methods)
    unregister = json.loads(changed[schema_root + "json/v2/OmuxBrokerUnregisterParams.json"])
    assert unregister["required"] == ["threadId"]
    assert set(unregister["properties"]["releaseBinding"]["type"]) == {"boolean", "null"}
    assert unregister["additionalProperties"] is False
    require(changed[schema_root + "typescript/v2/OmuxBrokerUnregisterParams.ts"].decode(),
            "threadId: string", "releaseBinding?: boolean | null")
    status = json.loads(changed[schema_root + "json/v2/OmuxBrokerThreadStatusResponse.json"])
    assert set(status["required"]) == {"threadId", "bound"}
    assert status["properties"]["bound"]["type"] == "boolean"
    assert "lastObservedRoute" in status["properties"]
    require(changed[schema_root + "typescript/v2/OmuxBrokerThreadStatusResponse.ts"].decode(),
            "threadId: string", "bound: boolean", "lastObservedRoute: JsonValue | null")
    require(changed[schema_root + "typescript/v2/Account.ts"].decode(),
            '"type": "brokerManaged"', "endpointConfigured: boolean")
    require(changed[schema_root + "json/v2/GetAccountResponse.json"].decode(), '"brokerManaged"')
    config = json.loads(changed["codex-rs/core/config.schema.json"])
    assert "omux_broker" in config["properties"]
    broker_config = config["definitions"]["OmuxBrokerConfig"]
    assert set(broker_config["required"]) == {"broker_socket", "capability_path"}
    assert broker_config["additionalProperties"] is False
    for field in ["broker_socket", "capability_path"]:
        assert broker_config["properties"][field]["type"] == "string"
    for lane in ["stable", "experimental"]:
        name = schema_root + f"precomputed/app-server-exports-{lane}.json.zst"
        assert manifest["files"][name]["representation"] == "binary_overlay"
        assert changed[name].startswith(b"\x28\xb5\x2f\xfd") and len(changed[name]) > 4


def late_authority_cases(changed: dict[str, bytes], broker: str, processor: str) -> None:
    """Fence native global/ancillary authority and stale selected-thread metadata."""
    def source(path: str) -> str:
        return changed["codex-rs/" + path].decode()

    require(broker, "pub fn any_ambient_blocked", "pub struct AmbientActivityGuard",
            "pub fn try_acquire_threadless_ambient_activity", "threadless_ambient_activity",
            "libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK",
            "file.metadata()?", "metadata.is_file()", "file.take(65)")
    registration = processor.split("async fn omux_broker_register(", 1)[1].split(
        "async fn omux_broker_unregister(", 1)[0]
    require(registration, "admit_broker_attach", "disable_native_analytics_delivery",
            "enter_broker_local_only().await", "drain_broker_mcp_authority(thread_id)",
            "enter_broker_descriptive_mode()", "std::io::ErrorKind::WouldBlock",
            "SessionSource::Internal(_)")
    precedes(registration, "drain_broker_mcp_authority", "auth_broker::register(")
    precedes(registration, "enter_broker_descriptive_mode", "OmuxBrokerRegisterResponse")

    models = source("models-manager/src/manager.rs")
    require(models, "fn enter_broker_descriptive_mode", "fn is_broker_descriptive",
            "broker_descriptive.store(true", "broker_mode_changed.notify_waiters()",
            "async fn native_operation", "changed.as_mut().enable()",
            "remote_models = self.broker_catalog_models()", "self.native_operation(cache.store(&entry))")
    for function in ["async fn refresh_available_models(", "async fn fetch_and_update_models(",
                     "async fn should_refresh_models(", "async fn try_load_cache("]:
        require(models.split(function, 1)[1].split("\n    }", 1)[0], "self.is_broker_descriptive()")
    for test in ["late_broker_catalog_blocks_native_endpoint_cache_and_auth_filtering",
                 "late_broker_catalog_cancels_pending_native_fetch_and_rejects_publication",
                 "late_broker_static_catalog_discards_native_entitlement_snapshot"]:
        require(source("models-manager/src/manager_tests.rs"), test)
    require(source("app-server/src/model_catalog.rs"), "any_ambient_blocked()",
            "self.models_manager.is_broker_descriptive()", "bundled_models_response()",
            "try_acquire_threadless_ambient_activity()")
    require(source("app-server/src/request_processors/catalog_processor.rs"),
            "if !broker_descriptive", "try_acquire_threadless_ambient_activity()")

    account = source("app-server/src/request_processors/account_processor.rs")
    authority = account.split("async fn ensure_global_account_operation_allowed(", 1)[1].split(
        "fn current_account_updated_notification", 1)[0]
    require(authority, "try_acquire_threadless_ambient_activity()", "omux_broker_config()", "Ok(ambient_activity)")
    auth_status = account.split("async fn get_auth_status_response(", 1)[1].split(
        "async fn get_account_rate_limits_response(", 1)[0]
    precedes(auth_status, "try_acquire_threadless_ambient_activity", "refresh_token_if_requested")
    for function, end in [("async fn login_chatgpt_response(", "async fn login_chatgpt_device_code_v2("),
                          ("async fn login_chatgpt_device_code_response(", "async fn cancel_login_response(")]:
        login = account.split(function, 1)[1].split(end, 1)[0]
        require(login, "let ambient_activity = self.ensure_global_account_operation_allowed().await?",
                "tokio::spawn(async move", "let _ambient_activity = ambient_activity")
    require(source("app-server/src/request_processors/account_processor/gateway_oauth.rs"),
            "let _ambient_activity = self.ensure_global_account_operation_allowed().await?")
    require(source("app-server/src/request_processors/account_processor/rate_limit_resets.rs"),
            "let _ambient_activity = self.ensure_global_account_operation_allowed().await?")

    plugins = source("core-plugins/src/manager.rs")
    require(plugins, "fn enter_broker_local_only", "async fn await_broker_local_only",
            "broker_remote_cancel.send_replace(true)", "task.abort()", "task.await",
            "broker_remote_admission.write().await", "broker_local_plugins_for_config",
            "async fn native_remote_work")
    require(source("core-plugins/src/manager_tests.rs"),
            "broker_plugin_adoption_drains_remote_auth_and_preserves_local_skills",
            "broker_plugin_config_presence_blocks_remote_work_even_when_malformed")
    mcp = source("core/src/session/mcp.rs")
    require(mcp, "fn mcp_broker_ambient_blocked", "config.auth_broker_configured()",
            "ambient_blocked(self.thread_id())", "plugins_manager.is_broker_local_only()",
            "mcp_runtime.cancel_startup()", "mcp_runtime.shutdown().await",
            "async fn mcp_native_auth", "self.mcp_native_auth().await")
    # The borrowed Arc<Config> spelling may change; custody must still be checked
    # before canonical auth is resolved, and the blocked branch must omit auth.
    native_mcp_auth = mcp.split("async fn mcp_native_auth(", 1)[1].split(
        "pub(crate) async fn runtime_mcp_config(", 1)[0]
    require(native_mcp_auth, "if self.mcp_broker_ambient_blocked(", "None")
    precedes(native_mcp_auth, "self.mcp_broker_ambient_blocked(", "self.services.auth_manager.auth().await")
    for function in ["async fn refresh_codex_apps_tools(", "async fn hard_refresh_latest_codex_apps_tools("]:
        apps = mcp.split(function, 1)[1].split("\n    }", 1)[0]
        require(apps, "!self.mcp_broker_ambient_blocked(",
                "Codex Apps require a separate broker authorization capability")
    require(source("core/src/connectors.rs"), "try_acquire_threadless_ambient_activity()",
            "discover_accessible_connectors_owned", "_ambient_activity: crate::auth_broker::AmbientActivityGuard",
            "tokio::spawn(async move", "configured_connector_discovery_rejects_before_runtime_or_native_auth")
    require(source("core/src/tools/handlers/request_plugin_install.rs"),
            "try_acquire_ambient_activity", "configured_remote_and_apps_installs_reject_before_auth_or_elicitation")

    events = source("tui/src/app_event.rs")
    require(events, "BrokerThreadStatusLoaded", "request_generation: u64", "thread_id: ThreadId")
    background = source("tui/src/app/background_requests.rs")
    require(background, "self.active_thread_id == Some(thread_id)",
            "self.chat_widget.thread_id() == Some(thread_id)", "checked_add(1)",
            "OmuxBrokerThreadStatusResponse", "response.thread_id == thread_id.to_string()",
            "source.code == -32601")
    completion = source("tui/src/app/event_dispatch.rs").split("AppEvent::BrokerThreadStatusLoaded", 1)[1]
    require(completion, "!self.broker_status_targets_selected_thread(thread_id)",
            "request_generation <= self.broker_status_last_applied_generation",
            "response.thread_id != thread_id.to_string()", "apply_broker_account_status(&response)")
    metadata = source("tui/src/status/account.rs")
    fields = metadata.split("struct BrokerAccountMetadata {", 1)[1].split("\n}", 1)[0]
    for forbidden in ["access_token", "account_id", "subject", "email", "tenant"]:
        assert forbidden not in fields
    require(metadata, "fn from_cached_route", "safe_display_text", "safe_timestamp")
    require(source("tui/src/status/card.rs"), "fn broker_route_values", "Provider expiry",
            "Custody expiry", "Route observed", "stale cache", "clock mismatch")
    require(source("tui/src/status/tests.rs"), "broker_cached_route_parser_keeps_only_display_metadata",
            "broker_cached_route_parser_rejects_unsafe_text_and_timestamps",
            "broker_status_renders_safe_cached_route_and_independent_expiries",
            "broker_status_reports_unknown_stale_and_future_cached_routes")
    require(source("tui/src/app/tests.rs"),
            "broker_status_completion_is_scoped_to_both_active_and_displayed_thread",
            "broker_status_generation_prevents_older_unbound_response_from_restoring_native_auth")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", type=Path)
    parser.add_argument("--tooling-only", action="store_true")
    args = parser.parse_args()
    if args.tooling_only:
        tooling_cases()
        print("Binary overlay integrity, deterministic packaging and exact patch safety passed.")
        return
    if args.artifact_dir is None:
        parser.error("--artifact-dir is required unless --tooling-only is selected")
    artifact = args.artifact_dir.parent if args.artifact_dir.is_file() else args.artifact_dir
    manifest = json.loads((artifact / "manifest.json").read_text())
    assert manifest["upstream_commit"] == "00c972ed5d6ff6499317fd41b7f23605b8e6850d"
    assert manifest["native_support"] is False and manifest["status"] == "upstream-patch-candidate"
    # A refreshed producer cannot inherit the prior candidate's artifact facts.
    # Receipts retain their own scopes; this checks their current artifact epoch.
    validation = json.loads((artifact / "validation.json").read_text())
    assert validation["native_support"] is False
    assert validation["upstream_commit"] == manifest["upstream_commit"]
    current = validation["artifact"]
    for checksum in ["patch_sha256", "base_sha256", "binary_overlay_sha256"]:
        assert current[checksum] == manifest[checksum], checksum
    assert current["reviewed_changed_files"] == len(manifest["files"])
    assert current["changed_source_sha256"] == manifest["files"][current["changed_source"]]["after_sha256"]
    assert validation["historical_artifact"]["patch_sha256"] != current["patch_sha256"]
    original, patch, overlay = verify_artifact(artifact, manifest)
    changed = combine_changes(patch, overlay, original, manifest)
    tooling_cases()
    client = changed["codex-rs/core/src/client.rs"].decode()
    broker = changed["codex-rs/core/src/auth_broker.rs"].decode()
    retry = changed["codex-rs/core/src/responses_retry.rs"].decode()
    require(client, "self.broker_replay_fence = true", "for attempt in 0..=1", "provider.retry.max_attempts = 0",
            "provider.retry.retry_transport = false", "options.turn_state = None",
            "with_chatgpt_cookies(std::iter::empty::<HeaderValue>())",
            "prepare_response_items_for_request(&mut request.input)", "stream_broker_responses_api")
    require(retry, "if client_session.broker_replay_fenced()", "return Err(err);")
    precedes(retry, "if client_session.broker_replay_fenced()", "err.retry_delay")
    require(broker, 'self.rpc("adapter.acquire"', 'self.rpc("adapter.materialize"', 'self.rpc("adapter.report"',
            '"capability"', "set_sensitive(true)", "socket.peer_cred()?.uid()", "account_changed",
            "contains_account_bound_context(input)", "StatusCode::UNAUTHORIZED", "StatusCode::TOO_MANY_REQUESTS")
    require(broker, "LeaseGuard", 'binding.report(&lease, "abandoned", None)',
            "detached: HashSet<ThreadId>", "registry.detached.insert(thread_id)",
            "registry.bindings.contains_key(&thread_id) || registry.detached.contains(&thread_id)",
            "fn validate_native_reentry", "if !context_portable(input)",
            "registry.detached.remove(&thread_id)",
            '"adapter.metadata"', "metadata.account_id.as_deref() != Some(lease.account_id.as_str())",
            "metadata.route_generation != Some(lease.route_generation)",
            "account == &lease.account_id && *generation == lease.route_generation",
            "observed_at: now()?", '"adapter.releaseBinding"',
            '"expected_lease_handle": last_lease', "runtime.spawn(async move")
    acquire_reader = broker.split("pub(crate) async fn acquire(", 1)[1].split(
        "pub(crate) async fn refresh_metadata(", 1)[0]
    precedes(acquire_reader, "LeaseGuard::new(Arc::clone(self), lease)",
             "if cleanup.lease.expires_at <= now()?")
    precedes(acquire_reader, "if cleanup.lease.expires_at <= now()?", "cleanup.disarm()")
    require(broker, "expired_acquired_lease_abandons_exactly_once_without_replay",
            "custody remains fenced until terminal acknowledgment")
    assert "lease will expire" not in broker
    # Control-plane status must read a typed local cache, never call into the daemon actor.
    status_reader = broker.split("pub fn status(", 1)[1].split("pub async fn register(", 1)[0]
    assert ".rpc(" not in status_reader and ".await" not in status_reader
    metadata_fields = broker.split("struct BrokerMetadata {", 1)[1].split("\n}", 1)[0]
    for forbidden in ["access_token", "provider_account_id", "subject", "email"]:
        assert forbidden not in metadata_fields
    # Detach readiness is rechecked against actual input before ambient request setup resumes.
    stream_entry = client.split("pub async fn stream(", 1)[1]
    require(stream_entry, "native_reentry_pending(self.client.state.thread_id)",
            "serde_json::to_value(&prompt.input)", "validate_native_reentry",
            "self.broker_route = None")
    precedes(stream_entry, "validate_native_reentry", "self.broker_replay_fence = false")
    dispatch = changed["codex-rs/app-server/src/message_processor.rs"].decode()
    for method in ["OmuxBrokerCapabilities", "OmuxBrokerRegister", "OmuxBrokerUnregister", "OmuxBrokerThreadStatus"]:
        require(dispatch, f"ClientRequest::{method}")
    processor = changed["codex-rs/app-server/src/request_processors/thread_processor.rs"].decode()
    require(processor, "fn admit_broker_detach", "ThreadStatus::Idle", "AgentStatus::Running",
            "context_portable(&item)", "history.items().map(serde_json::to_value)",
            "params.release_binding.unwrap_or(true)", "codex_core::auth_broker::status(thread_id)")
    unregister = processor.split("async fn omux_broker_unregister(", 1)[1].split("async fn omux_broker_thread_status(", 1)[0]
    precedes(unregister, "admit_broker_detach(", "auth_broker::unregister(")
    late_authority_cases(changed, broker, processor)
    thread_protocol = changed["codex-rs/app-server-protocol/src/protocol/v2/thread.rs"].decode()
    require(thread_protocol, "pub release_binding: Option<bool>", "pub last_observed_route: Option<JsonValue>")
    for native_test in ["detached_native_reentry_checks_actual_context_before_restoring_ambient_auth",
                        "metadata_status_is_allowlisted_and_rejects_other_account_or_generation",
                        "binding_release_uses_the_most_recent_issued_lease_as_a_compare_and_swap"]:
        require(broker, native_test)
    require(changed["codex-rs/core/src/session/session.rs"].decode(), "with_auth_broker_config(config.omux_broker_config()?)")
    # A valid patch must fail closed if even one upstream line differs; no fuzz fallback.
    mutated = dict(original)
    name = "codex-rs/core/src/lib.rs"
    mutated[name] = mutated[name].replace(b"mod client;", b"mod renamed_client;", 1)
    try:
        apply_exact(patch.decode(), mutated)
    except ValueError:
        pass
    else:
        raise AssertionError("patch accepted a changed source boundary")
    generated_contract_cases(changed, manifest)
    print("Pinned upstream patch provenance and exact application passed; source invariants passed. No Rust/live support claim.")


if __name__ == "__main__":
    main()
