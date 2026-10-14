"""Opt-in real provider operator-drain proof. No credential source is read here."""
from __future__ import annotations
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import subprocess
import socket
import struct
import sys
import tempfile
import time

import test_installed_native_tui as tui
import test_installed_native_interop as support

MARKER = b"OMUX_CODEX_OPERATOR_DRAIN_SAME_PROCESS_OK\n"
MAX_MANIFEST = 65536
EFFORT_RANK = {value: index for index, value in enumerate(
    ("none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra", "persistent"))}
MAX_HISTORY = 1024 * 1024
NATIVE_PEERS = {}
_ORIGINAL_OWNED_ENDPOINT = support.owned_endpoint

def checked_owned_endpoint(home, native):
    endpoint = _ORIGINAL_OWNED_ENDPOINT(home, native)
    NATIVE_PEERS[str(endpoint)] = native.process.pid
    return endpoint

# Private native reads retain no raw packet or diagnostic output.
def checked_native_rpc(endpoint, method, params, *, deadline=None):
    identifier = os.urandom(32).hex()
    packet = json.dumps({"jsonrpc": "2.0", "id": identifier, "method": method,
                         "params": params}, separators=(",", ":")).encode()
    require(len(packet) <= tui.FRAME_LIMIT, "live native packet exceeds bound")
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
        def phase_budget():
            left = 5 if deadline is None else deadline - time.monotonic()
            require(left > 0, "live native action deadline expired")
            channel.settimeout(min(5, left))
        phase_budget()
        channel.connect(str(endpoint))
        pid, uid, gid = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(pid == NATIVE_PEERS.get(str(endpoint)) and uid == os.getuid() and gid == os.getgid(),
                "live native peer differs")
        phase_budget()
        require(channel.send(packet) == len(packet), "live native packet incomplete")
        phase_budget()
        raw, _, flags, _ = channel.recvmsg(tui.FRAME_LIMIT)
        require(deadline is None or time.monotonic() < deadline, "live native action deadline expired")
        require(raw and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), "live native reply exceeds bound")
    value = json.loads(raw, object_pairs_hook=tui.strict_object)
    require(isinstance(value, dict) and set(value) == {"jsonrpc", "id", "result"}
            and value["jsonrpc"] == "2.0" and value["id"] == identifier
            and isinstance(value["result"], dict), "live native envelope differs")
    return value["result"]
TIMEOUT = 120
NATIVE_CONTEXT_KINDS = {
    "user": frozenset(("agents_md.instructions", "environments.environment_context")),
    "developer": frozenset((
        "generic.developer_instructions", "managed_config.developer_instructions",
        "permissions.instructions", "environments.instructions", "model.base_instructions",
        "model_switch.instructions", "multi_agent.role_instructions", "multi_agent.mode_instructions",
        "multi_agent.usage_hint", "collaboration_mode.instructions", "persistent_mode.instructions",
        "apps.instructions", "plugins.instructions", "plugins.usage_instructions",
        "plugins.recommendations", "tools.deferred_namespaces",
        "token_budget.context_window_guidance", "token_budget.context_window",
        "rollout_budget.remaining_tokens", "current_time.reminder", "current_time.unavailable",
    )),
}

def submitted_text_prompt(marker, nonce):
    require(marker in ("OMUX_INITIAL_DONE", "OMUX_A_DONE", "OMUX_B_DONE") and isinstance(nonce, str)
            and re.fullmatch(r"[0-9a-f]{32}", nonce), "live submitted prompt identity differs")
    return "Reply with exactly " + marker + ". Do not use tools. Proof nonce: " + nonce + "."

def classify_native_message(envelope, body, expected_prompt):
    """Read pinned native annotations; never modify or discard rollout records."""
    content = body.get("content")
    require(isinstance(content, list) and content
            and all(isinstance(part, dict) and part.get("type") in ("input_text", "output_text")
                    and isinstance(part.get("text"), str) for part in content),
            "live proof observed non-text native message")
    metadata = envelope.get("metadata")
    require(metadata is None or isinstance(metadata, dict), "native history metadata differs")
    metadata = metadata or {}
    passthrough = body.get("internal_chat_message_metadata_passthrough")
    require(passthrough is None or isinstance(passthrough, dict), "native message annotation differs")
    passthrough = passthrough or {}
    require(all(passthrough.get(field) is None for field in
                ("cell_id", "executed_tool_calls", "tool_calls_complete"))
            and metadata.get("client_authored", False) is False
            and metadata.get("inherited_user_message", False) is False
            and metadata.get("sender_user_messages") is None
            and metadata.get("delivered_assistant_message") is None,
            "live proof observed tool, inherited or client-authored message metadata")
    role = body.get("role")
    text = "".join(part["text"] for part in content)
    kinds = passthrough.get("content_item_kinds")
    if role == "assistant":
        require(all(part["type"] == "output_text" for part in content),
                "live assistant message representation differs")
        return "assistant", text
    require(role in NATIVE_CONTEXT_KINDS and all(part["type"] == "input_text" for part in content),
            "live native message role differs")
    if role == "user" and text == expected_prompt:
        # Legacy mode has no accepted-input order; exact fresh nonce remains required.
        order = metadata.get("user_input_order")
        require(order is None or (type(order) is int and 0 <= order < 2**64),
                "native submitted input order differs")
        require(kinds is None or (isinstance(kinds, list) and len(kinds) == len(content)
                and all(isinstance(kind, str) and kind.startswith("user.") for kind in kinds)),
                "native contextual input cannot impersonate the submitted prompt")
        return "submitted_user", text
    require(metadata.get("user_input_order") is None and isinstance(kinds, list)
            and len(kinds) == len(content)
            and all(isinstance(kind, str) and kind in NATIVE_CONTEXT_KINDS[role] for kind in kinds),
            "live unqualified native context or unexpected submitted input")
    return "native_context", text

FRESH_KIND = "omux-fresh-native-runtime-v1"
MAX_PUBLIC_RUNTIME_METADATA = 16 * 1024 * 1024
RECEIPT_KEYS = {"schema_version", "scope", "transition_reason", "application", "application_version", "model", "provider_usage_records",
                "native_context_mode", "reasoning_summary", "reasoning_effort",
                "minimum_reasoning_effort_verified", "native_detach_proven", "integration_restoration_proven",
                "upstream_commit", "candidate_patch_sha256", "runtime_archive_sha256",
                "accounts", "submitted_turns", "accepted_completed_turns", "tool_calls",
                "same_process", "same_native_owner", "same_native_thread",
                "native_store_identity_preserved", "accepted_history_prefix_preserved",
                "accepted_work_repeated", "empty_native_resume_checkpoint_proven",
                "accepted_history_cold_resume_proven", "provider_rejection_handoff_proven",
                "concurrent_handoff_proven", "full_native_account_lifecycle_proven"}

def require(condition, message):
    support.require(condition, message)

def runtime_arguments(arguments):
    if arguments[:1] == ["--runtime-kind=fresh"]:
        require(len(arguments) >= 2 and arguments[1].startswith("--runtime-pin="),
                "fresh runtime requires independently admitted public input pin")
        pin = arguments[1].split("=", 1)[1]
        require(pin and not any(value.startswith("--runtime-") for value in arguments[2:]),
                "runtime selector duplicated")
        return "fresh", Path(pin).resolve(strict=True), arguments[2:]
    require(not any(value.startswith("--runtime-") for value in arguments),
            "unknown runtime selection")
    return "retained", None, arguments

def public_runtime_file(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and not before.st_mode & 0o022 and 0 < before.st_size <= maximum,
                "public runtime input custody differs")
        parts, length = [], 0
        while length < before.st_size:
            part = os.read(descriptor, min(1024 * 1024, before.st_size - length))
            require(part, "public runtime input incomplete")
            parts.append(part)
            length += len(part)
        stable = lambda info: (info.st_dev, info.st_ino, info.st_uid, info.st_mode,
                               info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        require(stable(before) == stable(os.fstat(descriptor)), "public runtime input changed")
        return b"".join(parts)
    finally:
        os.close(descriptor)

def fresh_runtime_bundle(candidate, receipt, pin_path, verifier=None):
    require(pin_path is not None, "fresh runtime public pin absent")
    pin = json.loads(public_runtime_file(pin_path, 65536), object_pairs_hook=tui.strict_object)
    fields = {"kind", "archive_sha256", "archive_bytes", "receipt_sha256", "receipt_bytes",
              "manifest_sha256", "manifest_bytes"}
    require(isinstance(pin, dict) and set(pin) == fields and pin["kind"] == FRESH_KIND,
            "fresh runtime public pin schema differs")
    for role, maximum in (("archive", support.runtime_package.MAX_ARCHIVE_BYTES),
                          ("receipt", MAX_PUBLIC_RUNTIME_METADATA),
                          ("manifest", MAX_PUBLIC_RUNTIME_METADATA)):
        require(isinstance(pin[role + "_sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", pin[role + "_sha256"])
                and type(pin[role + "_bytes"]) is int and 0 < pin[role + "_bytes"] <= maximum,
                "fresh runtime public input pin differs")
    payload = public_runtime_file(candidate, support.runtime_package.MAX_ARCHIVE_BYTES)
    raw_receipt = public_runtime_file(receipt, MAX_PUBLIC_RUNTIME_METADATA)
    require(len(payload) == pin["archive_bytes"] and hashlib.sha256(payload).hexdigest() == pin["archive_sha256"]
            and len(raw_receipt) == pin["receipt_bytes"] and hashlib.sha256(raw_receipt).hexdigest() == pin["receipt_sha256"],
            "fresh runtime differs from independently admitted input")
    document = json.loads(raw_receipt, object_pairs_hook=tui.strict_object)
    require(isinstance(document, dict) and document.get("kind") == FRESH_KIND,
            "fresh runtime receipt kind differs")
    if verifier is None:
        import codex_fresh_native_runtime
        verifier = codex_fresh_native_runtime.verify_runtime_files
    manifest, files = verifier(payload, document)
    encoded = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    require(manifest.get("kind") == FRESH_KIND and len(encoded) == pin["manifest_bytes"]
            and hashlib.sha256(encoded).hexdigest() == pin["manifest_sha256"],
            "fresh manifest differs from independently admitted input")
    return manifest, files

# This distinct fourth delta is a public source identity, not a live claim.
PROTOCOL_HISTORY_PATCHES = ["5b9eb9d8ffc19ac6e53429186b3dc3e51ab05ab9bbb30564c3b621d7d5383ef6","3851e3d5c1901cafa7cd0bae63a7ac84b1baac7b1f6be3102cc7b185e97ecd53","84ec6ddc333361b4785ac0c9b0a212ce7b25f200fb22c30eb0abdc21883c5ec5","b4dd868ac11d863f65e9fe3031d83b8fb7164a5551abca20dc46424c0465c48c"]

def validate_fresh_patches(pins):
    require(type(pins) is list and (
        len(pins) == 3 and all(type(pin) is str and re.fullmatch(r"[0-9a-f]{64}",pin) for pin in pins)
        or pins == PROTOCOL_HISTORY_PATCHES),
        "fresh runtime patch chain differs")

def runtime_identity(manifest, kind):
    if kind == "retained":
        return {"upstream_commit": manifest["candidate"]["upstream_commit"],
                "candidate_patch_sha256": manifest["candidate"]["patch_sha256"]}
    require(kind == "fresh" and manifest.get("kind") == FRESH_KIND,
            "runtime identity kind differs")
    validate_fresh_patches(manifest["chain"]["patch_sha256"])
    if len(manifest["chain"]["patch_sha256"]) == 4:
        proof = manifest["chain"].get("native_protocol_history")
        require(type(proof) is dict and set(proof) == {"protocol","schema","cli","artifact_envelopes","artifact_files"}
                and proof["protocol"]["kind"] == proof["schema"]["kind"] == "omux-protocol-history-native-checks-v1"
                and proof["protocol"]["stage"] == 1 and type(proof["protocol"]["stage"]) is int
                and proof["schema"]["stage"] == 2 and type(proof["schema"]["stage"]) is int
                and proof["cli"]["kind"] == "omux-protocol-history-cli-qualification-v1",
                "fresh protocol-history runtime omitted its admitted actual chain")
    return {"runtime_kind": FRESH_KIND, "upstream_commit": manifest["chain"]["upstream_commit"],
            "candidate_patch_sha256s": manifest["chain"]["patch_sha256"]}

def read_manifest():
    require(os.environ.get("OMUX_CODEX_LIVE_INPUT_MANIFEST") == "/omux-live-inputs/input.json",
            "private live manifest binding required")
    path = Path("/omux-live-inputs/input.json")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and stat.S_IMODE(before.st_mode) in (0o400, 0o600)
                and before.st_nlink == 1 and 0 < before.st_size <= MAX_MANIFEST,
                "private live manifest custody differs")
        raw = os.read(fd, MAX_MANIFEST + 1)
        after = os.fstat(fd)
        stable = lambda info: (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
                               info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        require(len(raw) == before.st_size and stable(before) == stable(after),
                "private live manifest changed")
    finally:
        os.close(fd)
    document = json.loads(raw, object_pairs_hook=tui.strict_object)
    require(isinstance(document, dict)
            and set(document) == {"schema_version", "authorized_source_paths", "model"}
            and type(document["schema_version"]) is int and document["schema_version"] == 1,
            "private live manifest schema differs")
    paths = document["authorized_source_paths"]
    require(isinstance(paths, list) and len(paths) == 2 and paths[0] != paths[1],
            "exactly two distinct authorized native sources required")
    for item in paths:
        # Metadata selectors only: the daemon alone opens credential source bytes.
        require(isinstance(item, str) and 0 < len(item) <= 4096 and item.startswith("/")
                and str(Path(item)) == item and os.path.normpath(item) == item
                and all(32 <= ord(char) < 127 for char in item),
                "authorized native source selector differs")
    model = document["model"]
    require(isinstance(model, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", model),
            "explicit live model selector required")
    return document

def minimum_reasoning_effort(catalog, model):
    require(isinstance(catalog, dict) and isinstance(catalog.get("models"), list)
            and 0 < len(catalog["models"]) <= 256, "bounded bundled model catalogue required")
    selected = [item for item in catalog["models"] if isinstance(item, dict) and item.get("slug") == model]
    require(len(selected) == 1 and isinstance(selected[0].get("input_modalities"), list)
            and "text" in selected[0]["input_modalities"],
            "selected text model is absent from candidate catalogue")
    levels = selected[0].get("supported_reasoning_levels")
    require(isinstance(levels, list) and 0 < len(levels) <= 16, "model reasoning support is unknown")
    efforts = [item.get("effort") for item in levels if isinstance(item, dict)]
    require(len(efforts) == len(levels) and all(isinstance(value, str) and value in EFFORT_RANK
            for value in efforts), "model reasoning support is unknown")
    return min(efforts, key=EFFORT_RANK.__getitem__)

def validate_receipt(value):
    _validate_receipt(value, accepted_history=True)

def validate_same_process_receipt(value):
    _validate_receipt(value, accepted_history=False)

def _validate_receipt(value, *, accepted_history):
    fresh = isinstance(value, dict) and value.get("runtime_kind") == FRESH_KIND
    keys = (RECEIPT_KEYS - {"candidate_patch_sha256"}) | {"runtime_kind", "candidate_patch_sha256s"} if fresh else RECEIPT_KEYS
    require(isinstance(value, dict) and set(value) == keys,
            "redacted live receipt shape differs")
    fixed = {"schema_version": 1,
             "scope": ("accepted_history_cold_resume_and_operator_drain_same_process_substitution"
                       if accepted_history else "operator_drain_same_process_completed_turn_substitution"),
             "transition_reason": "operator_drain", "application": "omux-maintained-codex",
             "native_context_mode": "text_transcript_v1", "reasoning_summary": "none",
             "minimum_reasoning_effort_verified": True, "native_detach_proven": False,
             "integration_restoration_proven": False,
             "accounts": ["account_a", "account_b"], "submitted_turns": 3 if accepted_history else 2,
             "accepted_completed_turns": 3 if accepted_history else 2, "tool_calls": 0,
             "provider_usage_records": 3 if accepted_history else 2,
             "same_process": True, "same_native_owner": True, "same_native_thread": True,
             "native_store_identity_preserved": True, "accepted_history_prefix_preserved": True,
             "accepted_work_repeated": False, "empty_native_resume_checkpoint_proven": not accepted_history,
             "accepted_history_cold_resume_proven": accepted_history, "provider_rejection_handoff_proven": False,
             "concurrent_handoff_proven": False, "full_native_account_lifecycle_proven": False}
    require(all(type(value[key]) is type(expected) and value[key] == expected
                for key, expected in fixed.items()), "redacted live receipt predicates differ")
    require(isinstance(value["reasoning_effort"], str) and value["reasoning_effort"] in EFFORT_RANK,
            "redacted reasoning effort differs")
    if fresh:
        pins = value["candidate_patch_sha256s"]
        validate_fresh_patches(pins)
    for key, width in (("upstream_commit", 40),
                       ("runtime_archive_sha256", 64)):
        require(isinstance(value[key], str)
                and re.fullmatch(r"[0-9a-f]{" + str(width) + r"}", value[key]),
                "redacted public source digest differs")
    if not fresh:
        require(isinstance(value["candidate_patch_sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", value["candidate_patch_sha256"]),
                "redacted retained runtime identity differs")
    require(isinstance(value["application_version"], str)
            and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?", value["application_version"]),
            "redacted native application version differs")
    require(isinstance(value["model"], str)
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value["model"]),
            "redacted model selector differs")

class LiveScenario:
    def __init__(self, manifest, runtime_kind="retained", runtime_pin=None):
        self.manifest = manifest
        self.marker = MARKER
        self.sources = []
        self.accounts = []
        self.reasoning_effort = None
        self.cli_overrides = ()
        require(runtime_kind in ("retained", "fresh")
                and (runtime_pin is not None) == (runtime_kind == "fresh"), "runtime selection differs")
        self.runtime_kind = runtime_kind
        self.runtime_pin = runtime_pin
        self.verified_runtime_identity = None
        self.initial_accepted = None
        self.accepted_resume_verified = False

    def read_runtime_bundle(self, candidate, receipt):
        if self.runtime_kind == "fresh":
            manifest, files = fresh_runtime_bundle(candidate, receipt, self.runtime_pin)
        else:
            manifest, files = support.runtime_package.read_runtime_bundle(candidate, receipt)
        self.verified_runtime_identity = runtime_identity(manifest, self.runtime_kind)
        return manifest, files

    def configure(self, config):
        contents = config.read_text()
        config.write_text("model = " + json.dumps(self.manifest["model"]) + "\n" + contents)
        config.chmod(0o600)

    def prepare_native_profile(self, binary, environment, work):
        # This exact pinned CLI branch dumps only its bundled catalogue: it does
        # not build config/AuthManager, read native auth or refresh online models.
        process = subprocess.Popen([str(binary), "debug", "models", "--bundled"],
                                   env=environment, cwd=work, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   start_new_session=True, umask=0o077)
        original_deadline = support.DEADLINE_SECONDS
        try:
            support.DEADLINE_SECONDS = 15
            code, output, _ = support.bounded_private_session(process)
        finally:
            support.DEADLINE_SECONDS = original_deadline
        require(code == 0, "candidate bundled model catalogue failed")
        catalog = json.loads(output, object_pairs_hook=tui.strict_object)
        self.reasoning_effort = minimum_reasoning_effort(catalog, self.manifest["model"])
        self.cli_overrides = (
            'omux_broker.context_mode="text_transcript_v1"',
            'model_reasoning_summary="none"',
            'model_reasoning_effort=' + json.dumps(self.reasoning_effort),
        )

    def mutate(self, cli, method, params):
        return cli(method, {**params, "operation_id": os.urandom(32).hex(),
                            "expected_revision": cli("system.health")["revision"]})

    def check_domain(self, snapshot):
        require(len(snapshot["accounts"]) == 2 and len(snapshot["sources"]) == 2
                and {item["id"] for item in snapshot["accounts"]} == set(self.accounts)
                and {item["id"] for item in snapshot["sources"]} == set(self.sources),
                "isolated authorized account domain changed")

    def enroll(self, cli):
        for index, path in enumerate(self.manifest["authorized_source_paths"]):
            source = self.mutate(cli, "source.connect",
                                 {"kind": "native_store", "provider": "codex",
                                  "source_path": path, "label": "Account " + ("A" if index == 0 else "B")})
            self.sources.append(source["source_id"])
            self.mutate(cli, "source.reconcile", {"source_id": source["source_id"]})
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            snapshot = cli("state.snapshot")
            if len(snapshot.get("accounts", [])) == 2:
                accounts = snapshot["accounts"]
                require(all(item["identity"]["provider"] == "codex"
                            and item["lifecycle"] == "active" for item in accounts)
                        and all(len(item["source_ids"]) == 1
                                and item["source_ids"][0] in self.sources for item in accounts),
                        "authorized source enrollment attribution differs")
                self.accounts = [item["id"] for item in accounts]
                require(len(set(self.accounts)) == 2, "authorized sources resolve to one account")
                self.check_domain(snapshot)
                ready = {item["account_id"] for item in snapshot["grants"]
                         if item["status"] == "ready" and item["credential_kind"] == "oauth_access"
                         and item["ownership"] == "external"}
                if ready == set(self.accounts):
                    return
            time.sleep(0.05)
        raise ValueError("verified two-account enrollment deadline exceeded")

    def audit(self, cli, thread, native_ref):
        value = cli("integrations.nativeRequestAudit",
                    {"thread_id": thread, "native_ref": native_ref})
        require(value.get("schema_version") == 1 and value.get("native_ref") == native_ref
                and value.get("thread_id") == thread and isinstance(value.get("records"), list)
                and len(value["records"]) <= 6 and type(value.get("pending_requests")) is bool
                and type(value.get("pending_outcomes")) is bool,
                "selected native request audit shape differs")
        return value

    def history(self, home, thread, baseline=None):
        with closing(sqlite3.connect((home / "state_5.sqlite").as_uri() + "?mode=ro",
                                     uri=True, timeout=1)) as connection:
            rows = connection.execute("SELECT id,rollout_path,source,cwd,history_mode,cli_version,name,"
                                      "tokens_used,has_user_event FROM threads WHERE id=?", (thread,)).fetchall()
        require(len(rows) == 1 and rows[0][0] == thread
                and (baseline is None or rows[0][:7] == baseline[0][:7]),
                "live native metadata identity changed")
        path = Path(rows[0][1])
        require(path.resolve(strict=True) == path and path.is_relative_to(home.resolve(strict=True)),
                "live native history custody escaped selected home")
        info = path.stat()
        payload = support.private_file(path, MAX_HISTORY)
        require((baseline is None or ((info.st_dev, info.st_ino) == baseline[1]
                and payload.startswith(baseline[3]))) and payload.endswith(b"\n"),
                "live native history changed accepted prefix or store identity")
        sessions = [item["payload"] for item in
                    (json.loads(line, object_pairs_hook=tui.strict_object) for line in payload.splitlines())
                    if item.get("type") == "session_meta"]
        require(len(sessions) == 1 and sessions[0].get("id") == thread
                and sessions[0].get("session_id") == thread, "live native root identity changed")
        return rows[0], (info.st_dev, info.st_ino), hashlib.sha256(payload).digest(), payload

    def completed_text(self, current, previous, marker, expected_prompt):
        require(current[3].startswith(previous[3]), "live accepted history prefix changed")
        user, assistant, completed, usage = [], [], [], []
        for line in current[3][len(previous[3]):].splitlines():
            item = json.loads(line, object_pairs_hook=tui.strict_object)
            body = item.get("payload")
            require(isinstance(body, dict), "live native rollout envelope differs")
            if item.get("type") == "token_usage_record":
                usage.append(body)
            if item.get("type") == "compacted":
                raise ValueError("live proof unexpectedly compacted accepted history")
            if item.get("type") == "response_item":
                kind = body.get("type")
                require(kind in ("message", "reasoning"), "live proof observed non-text accepted work")
                if kind == "reasoning":
                    require(body.get("summary", []) == [] and body.get("content") in (None, []),
                            "live text policy observed readable reasoning")
                if kind == "message":
                    classification, text = classify_native_message(item, body, expected_prompt)
                    if classification == "submitted_user":
                        user.append(text)
                    elif classification == "assistant":
                        assistant.append(text)
                    # Qualified native context stays in history and does not count as human input.
            if item.get("type") == "event_msg":
                kind = body.get("type", "")
                require(isinstance(kind, str) and not any(part in kind for part in
                        ("exec_command", "patch", "tool_call", "web_search", "error", "abort")),
                        "live proof observed tool work or native failure")
                if kind == "task_complete":
                    completed.append(body)
        return len(user) == 1 and len(assistant) == 1 and assistant[0].strip() == marker \
            and len(completed) == 1 and completed[0].get("error") is None \
            and completed[0].get("last_agent_message", "").strip() == marker and len(usage) == 1

    def first_accepted_history(self, cli, home, thread, terminal, endpoint, observed):
        require(self.initial_accepted is None, "initial accepted turn cannot repeat")
        initial = self.audit(cli, thread, observed["nativeRef"])
        require(initial["records"] == [] and not initial["pending_requests"]
                and not initial["pending_outcomes"], "initial native authority was not empty")
        pid, witness = terminal.process.pid, tui.process_witness(terminal.process.pid)
        marker = "OMUX_INITIAL_DONE"
        prompt = submitted_text_prompt(marker, os.urandom(16).hex())
        terminal.send(prompt + "\r")
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            terminal.alive()
            audit = self.audit(cli, thread, observed["nativeRef"])
            require(len(audit["records"]) <= 1, "initial turn exceeded one request allowance")
            if len(audit["records"]) == 1:
                record = audit["records"][0]
                attempt = record["first"]
                accepted, finished = attempt["accepted_report"], attempt["terminal_report"]
                require(record["alternate"] is None, "initial turn attempted alternate replay")
                if attempt["state"] == "completed" and accepted is not None and finished is not None:
                    require(attempt["account_handle"] in self.accounts
                            and accepted["event"] == "accepted" and finished["event"] == "completed"
                            and accepted["response_started"] and not accepted["pre_acceptance"]
                            and finished["response_started"] and not finished["pre_acceptance"]
                            and not audit["pending_requests"] and not audit["pending_outcomes"]
                            and audit["binding"]["account_handle"] == attempt["account_handle"],
                            "initial turn lacks accepted completed account authority")
                    # Only genuine accepted native work materializes this history.
                    # No export, rename, synthetic SessionMeta or seeded rollout.
                    history = self.history(home, thread)
                    if self.completed_text(history, ((), (), b"", b""), marker, prompt):
                        require(terminal.process.pid == pid and tui.process_witness(pid) == witness
                                and tui.status(endpoint, thread) == observed,
                                "initial accepted turn changed native authority")
                        self.initial_accepted = {"account":attempt["account_handle"],
                            "request_id":record["request_id"], "native_ref":observed["nativeRef"],
                            "pid":pid, "witness":witness, "history":history,
                            "record":{**record,"first":{key:value for key,value in attempt.items()
                                                      if key != "route_generation"}}}
                        return history
            terminal.pump(0.05)
        raise ValueError("initial accepted native text deadline exceeded")

    def verify_accepted_resume(self, before, resumed, thread, terminal, observed):
        initial = self.initial_accepted
        require(initial is not None and before[3].startswith(initial["history"][3])
                and before[1] == initial["history"][1]
                and terminal.process.pid != initial["pid"]
                and observed["nativeRef"] != initial["native_ref"],
                "accepted cold resume lacks distinct process and preserved initial work")
        tui.resumed_history(before, resumed, thread)
        self.accepted_resume_verified = True

    def prove(self, cli, home, thread, terminal, endpoint, observed, baseline, candidate, receipt):
        require(self.accepted_resume_verified and self.initial_accepted is not None,
                "accepted cold resume must precede resumed-process handoff")
        result, completed = self.prove_same_process(cli, home, thread, terminal, endpoint,
            observed, baseline, candidate, receipt, initial_account=self.initial_accepted["account"],
            forbidden_request_id=self.initial_accepted["request_id"])
        retired = self.audit(cli, thread, self.initial_accepted["native_ref"])
        require(len(retired["records"]) == 1 and not retired["pending_requests"]
                and not retired["pending_outcomes"], "retired initial accepted authority changed")
        initial_record = retired["records"][0]
        require({**initial_record,"first":{key:value for key,value in initial_record["first"].items()
                                           if key != "route_generation"}} == self.initial_accepted["record"],
                "initial accepted record was repeated or changed across resume")
        result.update(scope="accepted_history_cold_resume_and_operator_drain_same_process_substitution",
            submitted_turns=3, accepted_completed_turns=3, provider_usage_records=3,
            empty_native_resume_checkpoint_proven=False, accepted_history_cold_resume_proven=True)
        validate_receipt(result)
        return result, completed

    def prove_same_process(self, cli, home, thread, terminal, endpoint, observed, baseline, candidate, receipt,
                           *, initial_account=None, forbidden_request_id=None):
        """Two accepted turns under one native ref; no accepted cold-resume claim."""
        checkpoint = json.loads(baseline[3].splitlines()[-1], object_pairs_hook=tui.strict_object)
        settings = checkpoint.get("payload", {}).get("thread_settings", {})
        require(settings.get("model") == self.manifest["model"]
                and settings.get("reasoning_summary") == "none"
                and settings.get("reasoning_effort") == self.reasoning_effort
                and len(self.cli_overrides) == 3, "live native text profile checkpoint differs")
        initial = self.audit(cli, thread, observed["nativeRef"])
        require(initial["records"] == [] and not initial["pending_requests"]
                and not initial["pending_outcomes"], "live proof started with prior request authority")
        pid = terminal.process.pid
        witness = tui.process_witness(pid)
        histories = [baseline]
        attempts = []
        for index, marker in enumerate(("OMUX_A_DONE", "OMUX_B_DONE")):
            if index:
                drained = self.mutate(cli, "account.drain", {"account_id": attempts[0]["account_handle"]})
                require(drained.get("updated") is True, "operator account drain was not acknowledged")
                snapshot = cli("state.snapshot")
                self.check_domain(snapshot)
                require(next(item for item in snapshot["accounts"]
                             if item["id"] == attempts[0]["account_handle"])["lifecycle"] == "draining",
                        "operator drain did not change eligibility")
            expected_prompt = submitted_text_prompt(marker, os.urandom(16).hex())
            terminal.send(expected_prompt + "\r")
            deadline = time.monotonic() + TIMEOUT
            while time.monotonic() < deadline:
                terminal.alive()
                audit = self.audit(cli, thread, observed["nativeRef"])
                require(len(audit["records"]) <= index + 1, "live proof exceeded finite request allowance")
                ordered = sorted(audit["records"], key=lambda row: row["first"]["issued_sequence"])
                if len(ordered) == index + 1:
                    current = ordered[-1]
                    first = current["first"]
                    require(current["alternate"] is None
                            and first["account_handle"] in self.accounts,
                            "live proof observed alternate or unauthorized request account")
                    accepted, finished = first["accepted_report"], first["terminal_report"]
                    if first["state"] == "completed" and accepted is not None and finished is not None:
                        require(current["request_id"] != forbidden_request_id
                                and (initial_account is None or index != 0 or first["account_handle"] == initial_account),
                                "resumed initial account differs or repeated accepted request")
                        require(accepted["event"] == "accepted" and finished["event"] == "completed"
                                and accepted["response_started"] and not accepted["pre_acceptance"]
                                and finished["response_started"] and not finished["pre_acceptance"]
                                and not audit["pending_requests"] and not audit["pending_outcomes"]
                                and audit["binding"]["account_handle"] == first["account_handle"],
                                "live request lacked accepted completed boundary")
                        history = self.history(home, thread, baseline)
                        if self.completed_text(history, histories[-1], marker, expected_prompt):
                            if index:
                                immutable = lambda row: {**row, "first": {key: value for key, value in row["first"].items() if key != "route_generation"}}
                                require(immutable(ordered[0]) == immutable(attempts[0]["record"])
                                        and first["account_handle"] != attempts[0]["account_handle"]
                                        and current["request_id"] != attempts[0]["record"]["request_id"]
                                        and audit["binding"]["route_generation"] > attempts[0]["route_generation"],
                                        "live substitution repeated accepted work or preserved old account route")
                            attempts.append({**first, "record": current,
                                             "route_generation": audit["binding"]["route_generation"]})
                            histories.append(history)
                            break
                terminal.pump(0.05)
            else:
                raise ValueError("live accepted text completion deadline exceeded")
            require(terminal.process.pid == pid and tui.process_witness(pid) == witness
                    and tui.status(endpoint, thread) == observed,
                    "live substitution changed process or native custody")
        require(self.verified_runtime_identity is not None, "runtime verification identity absent")
        manifest = json.loads(public_runtime_file(receipt, MAX_PUBLIC_RUNTIME_METADATA), object_pairs_hook=tui.strict_object)
        result = {"schema_version": 1,
                  "scope": "operator_drain_same_process_completed_turn_substitution",
                  "transition_reason": "operator_drain", "application": "omux-maintained-codex",
                  "application_version": baseline[0][5], "model": self.manifest["model"],
                  "provider_usage_records": 2,
                  "native_context_mode": "text_transcript_v1", "reasoning_summary": "none",
                  "reasoning_effort": self.reasoning_effort, "minimum_reasoning_effort_verified": True,
                  "native_detach_proven": False, "integration_restoration_proven": False,
                  **self.verified_runtime_identity,
                  "runtime_archive_sha256": manifest["archive_sha256"],
                  "accounts": ["account_a", "account_b"], "submitted_turns": 2,
                  "accepted_completed_turns": 2, "tool_calls": 0,
                  "same_process": True, "same_native_owner": True, "same_native_thread": True,
                  "native_store_identity_preserved": True, "accepted_history_prefix_preserved": True,
                  "accepted_work_repeated": False, "empty_native_resume_checkpoint_proven": True,
                  "accepted_history_cold_resume_proven": False, "provider_rejection_handoff_proven": False,
                  "concurrent_handoff_proven": False, "full_native_account_lifecycle_proven": False}
        validate_same_process_receipt(result)
        return result, histories[-1]

def main():
    support.DEADLINE_SECONDS = 480
    tui.native_rpc = checked_native_rpc
    support.owned_endpoint = checked_owned_endpoint
    runtime_kind, runtime_pin, arguments = runtime_arguments(sys.argv[1:])
    if len(arguments) == 6 and arguments[0] == "--inside-live":
        scenario = LiveScenario(read_manifest(), runtime_kind, runtime_pin)
        tui.inside(*(Path(value).resolve(strict=True) for value in arguments[1:]), live=scenario)
        return 0
    require(len(arguments) == 6, "declared installed/native inputs required")
    bundle, candidate, receipt, session, bus, keyring = (
        Path(value).resolve(strict=True) for value in arguments)
    runtime_options = ([] if runtime_kind == "retained" else
                       ["--runtime-kind=fresh", "--runtime-pin=" + str(runtime_pin)])
    read_manifest()  # Fail before any provider-capable daemon exists.
    with tempfile.TemporaryDirectory(prefix="omux-l-", dir="/tmp") as temporary:
        root = Path(temporary)
        environment = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/nonexistent",
                       "HOME": str(root), "OMUX_ISOLATED_VAULT_PROOF": "private-bus-private-xdg",
                       "OMUX_CODEX_LIVE_INPUT_MANIFEST": "/omux-live-inputs/input.json"}
        for name, child in (("XDG_RUNTIME_DIR", "r"), ("XDG_DATA_HOME", "d"), ("XDG_CONFIG_HOME", "c"),
                            ("XDG_CACHE_HOME", "k"), ("XDG_STATE_HOME", "s")):
            directory = root / child
            directory.mkdir(mode=0o700)
            environment[name] = str(directory)
        configuration = root / "bus.conf"
        configuration.write_text('<busconfig><type>session</type><listen>unix:abstract=omux-live-' + root.name
                                 + '</listen><auth>EXTERNAL</auth><policy context="default">'
                                 '<allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/>'
                                 '</policy></busconfig>')
        bootstrap = ("import os,runpy,sys;p=sys.argv.pop(1);sys.path.insert(0,os.path.dirname(p));"
                     "sys.argv[0]=p;runpy.run_path(p,run_name='__main__')")
        process = subprocess.Popen([str(session), "--dbus-daemon=" + str(bus),
                                    "--config-file=" + str(configuration), "--", sys.executable,
                                    "-I", "-B", "-c", bootstrap, str(Path(__file__).absolute()),
                                    *runtime_options, "--inside-live", str(bundle), str(candidate), str(receipt), str(keyring), str(root)],
                                   env=environment, start_new_session=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, umask=0o077)
        code, output, diagnostics = support.bounded_private_session(process)
        require(code == 0 and output.startswith(MARKER), "live operator-drain fixture did not complete")
        result = json.loads(output[len(MARKER):], object_pairs_hook=tui.strict_object)
        validate_receipt(result)
        output_root = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"])
        with (output_root / "codex-live-proof.json").open("x") as stream:
            json.dump(result, stream, sort_keys=True, indent=2)
            stream.write("\n")
        print(MARKER.decode("ascii"), end="")
        return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("Codex operator-drain same-process proof failed", file=sys.stderr)
        sys.exit(1)
