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
def checked_native_rpc(endpoint, method, params):
    identifier = os.urandom(32).hex()
    packet = json.dumps({"jsonrpc": "2.0", "id": identifier, "method": method,
                         "params": params}, separators=(",", ":")).encode()
    require(len(packet) <= tui.FRAME_LIMIT, "live native packet exceeds bound")
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
        channel.settimeout(5)
        channel.connect(str(endpoint))
        pid, uid, gid = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(pid == NATIVE_PEERS.get(str(endpoint)) and uid == os.getuid() and gid == os.getgid(),
                "live native peer differs")
        require(channel.send(packet) == len(packet), "live native packet incomplete")
        raw, _, flags, _ = channel.recvmsg(tui.FRAME_LIMIT)
        require(raw and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), "live native reply exceeds bound")
    value = json.loads(raw, object_pairs_hook=tui.strict_object)
    require(isinstance(value, dict) and set(value) == {"jsonrpc", "id", "result"}
            and value["jsonrpc"] == "2.0" and value["id"] == identifier
            and isinstance(value["result"], dict), "live native envelope differs")
    return value["result"]
TIMEOUT = 120
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

def runtime_identity(manifest, kind):
    if kind == "retained":
        return {"upstream_commit": manifest["candidate"]["upstream_commit"],
                "candidate_patch_sha256": manifest["candidate"]["patch_sha256"]}
    require(kind == "fresh" and manifest.get("kind") == FRESH_KIND,
            "runtime identity kind differs")
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
    fresh = isinstance(value, dict) and value.get("runtime_kind") == FRESH_KIND
    keys = (RECEIPT_KEYS - {"candidate_patch_sha256"}) | {"runtime_kind", "candidate_patch_sha256s"} if fresh else RECEIPT_KEYS
    require(isinstance(value, dict) and set(value) == keys,
            "redacted live receipt shape differs")
    fixed = {"schema_version": 1,
             "scope": "operator_drain_same_process_completed_turn_substitution",
             "transition_reason": "operator_drain", "application": "omux-maintained-codex",
             "native_context_mode": "text_transcript_v1", "reasoning_summary": "none",
             "minimum_reasoning_effort_verified": True, "native_detach_proven": False,
             "integration_restoration_proven": False,
             "accounts": ["account_a", "account_b"], "submitted_turns": 2,
             "accepted_completed_turns": 2, "tool_calls": 0, "provider_usage_records": 2,
             "same_process": True, "same_native_owner": True, "same_native_thread": True,
             "native_store_identity_preserved": True, "accepted_history_prefix_preserved": True,
             "accepted_work_repeated": False, "empty_native_resume_checkpoint_proven": True,
             "accepted_history_cold_resume_proven": False, "provider_rejection_handoff_proven": False,
             "concurrent_handoff_proven": False, "full_native_account_lifecycle_proven": False}
    require(all(type(value[key]) is type(expected) and value[key] == expected
                for key, expected in fixed.items()), "redacted live receipt predicates differ")
    require(isinstance(value["reasoning_effort"], str) and value["reasoning_effort"] in EFFORT_RANK,
            "redacted reasoning effort differs")
    if fresh:
        pins = value["candidate_patch_sha256s"]
        require(isinstance(pins, list) and len(pins) == 3
                and all(isinstance(pin, str) and re.fullmatch(r"[0-9a-f]{64}", pin) for pin in pins),
                "fresh runtime patch chain differs")
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

    def history(self, home, thread, baseline):
        with closing(sqlite3.connect((home / "state_5.sqlite").as_uri() + "?mode=ro",
                                     uri=True, timeout=1)) as connection:
            rows = connection.execute("SELECT id,rollout_path,source,cwd,history_mode,cli_version,name,"
                                      "tokens_used,has_user_event FROM threads WHERE id=?", (thread,)).fetchall()
        require(len(rows) == 1 and rows[0][:7] == baseline[0][:7],
                "live native metadata identity changed")
        path = Path(rows[0][1])
        require(path.resolve(strict=True) == path and path.is_relative_to(home.resolve(strict=True)),
                "live native history custody escaped selected home")
        info = path.stat()
        payload = support.private_file(path, MAX_HISTORY)
        require((info.st_dev, info.st_ino) == baseline[1]
                and payload.startswith(baseline[3]) and payload.endswith(b"\n"),
                "live native history changed accepted prefix or store identity")
        return rows[0], (info.st_dev, info.st_ino), hashlib.sha256(payload).digest(), payload

    def completed_text(self, current, previous, marker):
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
                    content = body.get("content")
                    require(isinstance(content, list)
                            and all(isinstance(part, dict) and part.get("type") in ("input_text", "output_text")
                                    and isinstance(part.get("text"), str) for part in content),
                            "live proof observed non-text native message")
                    text = "".join(part["text"] for part in content)
                    if body.get("role") == "user":
                        user.append(text)
                    elif body.get("role") == "assistant":
                        assistant.append(text)
                    else:
                        raise ValueError("live proof observed unexpected appended message role")
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

    def prove(self, cli, home, thread, terminal, endpoint, observed, baseline, candidate, receipt):
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
            terminal.send("Reply with exactly " + marker + ". Do not use tools.\r")
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
                        require(accepted["event"] == "accepted" and finished["event"] == "completed"
                                and accepted["response_started"] and not accepted["pre_acceptance"]
                                and finished["response_started"] and not finished["pre_acceptance"]
                                and not audit["pending_requests"] and not audit["pending_outcomes"]
                                and audit["binding"]["account_handle"] == first["account_handle"],
                                "live request lacked accepted completed boundary")
                        history = self.history(home, thread, baseline)
                        if self.completed_text(history, histories[-1], marker):
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
        validate_receipt(result)
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
