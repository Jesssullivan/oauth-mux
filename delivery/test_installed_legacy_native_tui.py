"""Exact frozen164/runtime009 ordinary TUI cold resume of native empty history.

R-HOOK-CONVERGENCE-20261004 / R-N13. Genuine native app-server APIs create
and name the empty rollout. After ACK detach and clean app-server EOF, an
ordinary PTY codex resume opens that same UUID in a new process. Uses an
installed daemon and disposable Secret Service; no fixture writes history.
References come from daemon discovery's committed attached-ledger projection;
no owner/attachment/status method or manufactured status is supplied.
No accounts, prompts, tools or provider usage. Native support remains false.
Excludes recovery delta, retirement repair, native status conformance, accepted
nonempty history, bare TUI history creation, same-process replacement/handoff, executable attribution,
channel-qualified native installation, stock Codex, Darwin and release support.
The inherited outer deadline is 180 seconds, with exact owned-group cleanup.
"""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import time

import codex_runtime_selection as selection
import test_installed_native_tui as tui
import native_cli_stderr
import native_fd2_observer
import native_history_diagnostic
import native_run_cli_failure
import native_thread_census as native_threads

support = tui.support
require = support.require
PHASE = "private-context"
PHASES = ("private-context", "runtime-verification", "keyring-startup", "daemon-startup",
          "bootstrap-native", "integration-install", "native-seed-start",
          "native-seed-uninitialized-history", "native-seed-name", "native-seed-full-read",
          "native-seed-history", "selected-detach", "native-preservation", "native-seed-clean-exit",
          "cold-native-resume", "resumed-preservation", "resumed-detach", "durable-inspection",
          "owned-cleanup")
DIAGNOSTIC = "unclassified"
CLI_FAILURE = "unclassified"
CLI_EXIT = "unclassified"
CLI_PROTOCOL = "unclassified"
CLI_STDERR = "unclassified"
CLI_COMPLETION = "unclassified"
FD2_OBSERVER = None
FD2_CONTEXT = None
CLI_OBSERVATION = None
DETACH_CLI_FAILURE_RECORD = None
CLI_EXITS = ("exit-zero-stderr", "exit-one", "exit-two", "exit-positive-other",
             "exit-signal", "unclassified")
TERMINAL_EXITS = ("exit-zero", "exit-one", "exit-two", "exit-101",
                  "exit-positive-other", "exit-signal", "exit-core", "exit-unavailable")
TERMINAL_MESSAGES = (
    ("runtime-thread-spawn", (b"failed to spawn thread", b"failed to spawn scoped thread",
                              b"OS can't spawn worker thread")),
    ("os-resource-unavailable", (b"Resource temporarily unavailable (os error 11)",)),
    ("config-load", (b"Error loading configuration:", b"Error parsing -c overrides:",
                     b"Error finding codex home:")),
    ("terminal-not-tty", (b"stdin is not a terminal", b"stdout is not a terminal")),
    ("resume-session-missing", (b"No saved session found with ID ",)),
    ("daemon-startup", (b"To work without the background server, rerun the same command",)),
    ("rust-panic", (b"panicked at ",)),
    ("python-bootstrap", (b"Traceback (most recent call last):",)),
)
TERMINAL_CATEGORIES = tuple(value[0] for value in TERMINAL_MESSAGES) + ("unrecognized",)
TERMINAL_MARKER = "installed legacy native terminal exit "


class TerminalFailureObservation:
    """Private literal recognition; no native bytes or interpolated text emitted.

    Rank recognition only as a diagnostic, never as native error authority or
    evidence of continuity. Keep a bounded suffix to recognize split packets.
    The original terminal output bound, liveness and cleanup remain mandatory.
    """

    def __init__(self):
        self.suffix = b""
        self.seen = set()

    def observe(self, packet):
        observed = self.suffix + packet
        for category, literals in TERMINAL_MESSAGES:
            if any(literal in observed for literal in literals):
                self.seen.add(category)
        self.suffix = observed[-127:]

    def record(self, terminal):
        self.suffix = b""
        info = terminal.exited()  # WNOWAIT preserves the owned cleanup anchor.
        category = next((value for value, _ in TERMINAL_MESSAGES if value in self.seen), "unrecognized")
        exit_category = "exit-unavailable"
        if info is not None:
            if info.si_code == os.CLD_EXITED:
                exit_category = {0: "exit-zero", 1: "exit-one", 2: "exit-two",
                                 101: "exit-101"}.get(info.si_status, "exit-positive-other")
            elif info.si_code == os.CLD_KILLED:
                exit_category = "exit-signal"
            elif info.si_code == os.CLD_DUMPED:
                exit_category = "exit-core"
        return TERMINAL_MARKER + exit_category + "/" + category + "\n"

STATUS_REFUSALS = {
    (-32000, "CustodyUnavailable"): "status-custody-unavailable",
    (-32000, "UnknownOperation"): "status-unknown-operation",
    (-32000, "InvalidOperationId"): "status-invalid-operation",
    (-32000, "InvalidParams"): "status-invalid-params",
    (-32000, "ServiceStopping"): "status-service-stopping",
    (-32000, "Timeout"): "status-timeout",
}
CLI_PROTOCOLS = (*STATUS_REFUSALS.values(), "status-other-refusal", "status-result",
                 "status-envelope-unrecognized", "status-json-unrecognized", "unclassified")
CLI_STDERRS = (*native_cli_stderr.CATEGORIES, "unclassified")
CLI_COMPLETIONS = ("completion-exact", "completion-other-result",
                   "completion-not-result", "unclassified")
RESUME_DIAGNOSTICS = ("resume-terminal-spawn", "resume-new-process-predicate",
                      "resume-owner-endpoint", "resume-terminal-alive",
                      "resume-owner-discovery", "resume-terminal-pump",
                      "resume-attachment-deadline", "resume-process-witness",
                      "resume-identity-predicate", "resume-settings-checkpoint",
                      "resume-retained-config-predicate")
RESUME_FAILURE_MESSAGES = {
    "ordinary native terminal exited early": "resume-terminal-exited",
    "native terminal output exceeded bound": "resume-terminal-output-bound",
    "genuine owner endpoint unavailable": "resume-endpoint-deadline",
    "fresh native home has multiple owner endpoints": "resume-endpoint-cardinality",
    "native endpoint custody changed": "resume-endpoint-custody",
    "native generation is not canonical": "resume-generation",
    "legacy native committed attachment deadline exceeded": "resume-attachment-deadline",
    "OS boot witness changed": "resume-os-boot-witness",
    "legacy owned private terminal process cleanup failed": "resume-owned-cleanup",
    "installed CLI predicate failed": "resume-cli-process-failure",
    "installed CLI response rejected": "resume-cli-result-rejected",
    "installed CLI output exceeded its bound": "resume-cli-output-bound",
    "installed CLI deadline exceeded": "resume-cli-stream-deadline",
    "legacy cold resume reused original process": "resume-process-reused",
    "legacy cold resume lost original thread or reused authority": "resume-identity-changed",
    "native metadata row is absent or ambiguous": "resume-metadata-row-cardinality",
    "native metadata was not initialized provider-free": "resume-metadata-provider-free-fields",
    "native rollout custody escaped selected home": "resume-rollout-path-custody",
    "native rollout custody traversed a symlink": "resume-rollout-symlink",
    "native rollout frame changed": "resume-rollout-frame-shape",
    "native root session identity changed": "resume-rollout-root-identity",
    "provider-free native rollout contains user or tool work": "resume-rollout-accepted-work",
    "native session metadata is absent or ambiguous": "resume-rollout-session-cardinality",
    "native JSON contains duplicate keys": "resume-rollout-duplicate-key",
    "native private file custody changed": "resume-private-file-custody",
    "native private file exceeded its bound": "resume-private-file-bound",
    "cold native resume changed original history before checkpoint": "resume-checkpoint-original-changed",
    "cold native settings checkpoint did not flush": "resume-checkpoint-deadline",
    "cold native resume changed original history bytes or identity": "resume-history-original-changed",
    "cold native resume appended unexpected history": "resume-history-append-cardinality",
    "cold native metadata append envelope changed": "resume-settings-envelope",
    "cold native append was not settings metadata": "resume-settings-kind",
    "cold native settings snapshot changed provider-free policy": "resume-settings-policy",
    "legacy cold resume changed retained configuration": "resume-retained-config-changed",
}
RESUME_FAILURES = (*RESUME_FAILURE_MESSAGES.values(), "resume-json", "resume-missing-input",
                   "resume-permission", "resume-os-failure", "resume-process-deadline",
                   "resume-database-busy", "resume-database-query", "resume-database-error",
                   "resume-other-predicate", "resume-shape", "resume-type", "resume-unrecognized")
RESUME_FAILURES += tuple("resume-" + value for value in native_run_cli_failure.FAILURES if value.startswith("os-"))
CLI_FAILURE_MESSAGES = {
    "installed CLI deadline exceeded": "cli-stream-deadline",
    "installed CLI output exceeded its bound": "cli-output-bound",
    "installed CLI predicate failed": "cli-process-failure",
    "installed CLI response rejected": "cli-result-rejected",
}
CLI_FAILURES = (*CLI_FAILURE_MESSAGES.values(), "cli-json", "cli-process-deadline", "unclassified")
METADATA_DIAGNOSTICS = {
    "native metadata row is absent or ambiguous": "metadata-row-cardinality",
    "native metadata was not initialized provider-free": "metadata-provider-free-fields",
    "native rollout custody escaped selected home": "rollout-path-custody",
    "native rollout custody traversed a symlink": "rollout-symlink",
    "native rollout frame changed": "rollout-frame-shape",
    "native root session identity changed": "rollout-root-identity",
    "provider-free native rollout contains user or tool work": "rollout-accepted-work",
    "native session metadata is absent or ambiguous": "rollout-session-cardinality",
    "native JSON contains duplicate keys": "rollout-duplicate-key",
}
SEED_ATTACHMENT_DIAGNOSTICS = (
    "seed-history-discovery-rpc", "seed-history-discovery-validation",
    "seed-history-attachment-comparison", "seed-history-attachment-absent",
    "seed-history-attachment-identity", "seed-history-attachment-reference",
    "seed-history-attachment-other",
)

DIAGNOSTICS = (*METADATA_DIAGNOSTICS.values(), "metadata-database-absent",
               "metadata-database-busy", "metadata-database-query", "metadata-database-error",
               "rollout-file-absent", "rollout-json", "metadata-other-predicate",
               "detach-health-rpc", "detach-rpc", "detach-ack-predicate",
               "detach-status-rpc", "detach-completion-predicate",
               "detach-replay-rpc", "detach-replay-predicate",
               "detach-discovery-rpc", "detach-retirement-predicate",
               *native_history_diagnostic.CATEGORIES,
               "seed-history-metadata", "seed-history-sql-match",
               "seed-history-liveness", "seed-history-process", "seed-history-attachment",
               *SEED_ATTACHMENT_DIAGNOSTICS,
               *RESUME_DIAGNOSTICS,
               *support.FAILURES)
MARKER = b"OMUX_INSTALLED_LEGACY_NATIVE_TUI_OK\n"
OBSERVER_MARKER = b"OMUX_INSTALLED_LEGACY_NATIVE_FD2_DIAGNOSTIC_OK\n"
UPSTREAM = "00c972ed5d6ff6499317fd41b7f23605b8e6850d"
ARCHIVE_SHA = "0094334d7fd27b81f613ebe734305412bd13f95f1f3396ba2f0396168e5223ad"
MANIFEST_SHA = "5626b375f0f3c1818340345c952394ef44b59acbc177ab83f7b910c6fb105678"
SOURCE_MANIFEST_SHA = "8eb4ed424b0373bd77250eaf59334cb765141d1fc6a2885480c840771d462b23"
VALIDATION_SHA = "1e0f27681a57f4c7d2102d69d01f73586d743341b9baea306e863069c74fc86a"
SCHEMA_SHA = "485672178e95148b88b96b9bc30970636d365a4f74be2d084a41b8d95dc1e12c"
SOURCE_RECEIPT_SHA = "e3c6d45bc93119ddf1da8bee6e02de3c7c3a3bbe52bb6d2664eb4b7b3d7b5273"
PRODUCER_RECEIPT_SHA = "545727183aa4e361eb1967fa3599dd30e5fd38a78f68dad9fec74793f8f713ee"
EXPECTED_CANDIDATE = {
    "upstream_commit": UPSTREAM,
    "patch_sha256": "2e5542c5f6a44e3a8dd38b4a4093d1735ff19771721b05fc51f55b475b1a8d46",
    "base_sha256": "a794a67af4b6aecd9e91aeb4281354b90d10e10134e7cf6a6028b33f26a2f9d9",
    "binary_overlay_sha256": "9d47862cd9e7e1a911d8512dad0ad0f124c928e139b778cd1e89ecfce17c5703",
    "validation_sha256": VALIDATION_SHA,
    "complete_source_inventory_sha256": "3400115fae8ef204f2ce085880b40887bcb14e2080236ba87a34be9b14fe7d3b",
    "compile_invocation_id": "185ffba7-9b08-450f-ab29-1d405810892a",
    "source_verification_invocation_id": "5a9d8326-5327-4052-8a6e-946dcc4d18ac",
    "current_compile_invocation_id": "c9757a04-8de8-4a61-9029-6c312e153ac6",
    "current_configuration": "owner-linux-opt",
    "current_source_verification_invocation_id": "fe794e5f-a4ae-4edb-8496-7df5b14c8c77",
    "current_source_receipt_sha256": SOURCE_RECEIPT_SHA,
}
EXPECTED_EXECUTABLE = {
    "backend_max_bytes": 536870912,
    "original_sha256": "4635bbee6d7f19ddcdbaa3247fe197c11c7169f191255baaaa41579f54ca2695",
    "original_bytes": 405575744,
    "stripped_sha256": "37e8eaafa9e83e90bc4e804bad37ccdb4660252a1a4804946b776d1e1fe132a3",
    "stripped_bytes": 318558680,
    "packaged_sha256": "0b82d7f1535ab98ca2854dad0ac908912c9df56f29bb70c664e18e9956dc4a3f",
    "packaged_bytes": 318579008,
}


def read_bound(path, maximum):
    # Bazel's declared runfiles may be symlinks. Resolve that selected input,
    # then pin the actual regular descriptor; this conveys no install ownership.
    descriptor = os.open(Path(path).resolve(strict=True), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum,
                "legacy proof input is not a bounded regular file")
        payload = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    fields = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
    require(len(payload) == before.st_size and fields(before) == fields(after),
            "legacy proof input changed during bounded read")
    return payload


def pinned_json(path, expected, maximum=16 * 1024 * 1024):
    payload = read_bound(path, maximum)
    require(hashlib.sha256(payload).hexdigest() == expected, "legacy proof input digest differs")
    return payload, json.loads(payload, object_pairs_hook=tui.strict_object)


def verify_legacy_inputs(candidate, receipt):
    artifact = Path(__file__).parent.parent / "integrations/codex-owner-candidate"
    _, source = pinned_json(artifact / "manifest.json", SOURCE_MANIFEST_SHA)
    _, validation = pinned_json(artifact / "validation.json", VALIDATION_SHA)
    _, schemas = pinned_json(artifact / "schema-import-receipt.json", SCHEMA_SHA)
    require(source["upstream_commit"] == UPSTREAM and source["native_support"] is False
            and len(source["files"]) == 164
            and all(source[field] == EXPECTED_CANDIDATE[field] for field in
                    ("patch_sha256", "base_sha256", "binary_overlay_sha256")),
            "frozen164 source candidate identity differs")
    require(validation["native_support"] is False and validation["upstream_commit"] == UPSTREAM
            and validation["schema_import"]["receipt_sha256"] == SCHEMA_SHA
            and schemas["status"] == "passed" and schemas["native_support"] is False
            and schemas["producer_invocation_id"] == validation["schema_import"]["producer_invocation_id"]
            and schemas["file_count"] == len(schemas["files"]) == 1098,
            "frozen164 schema provenance differs")
    archive = read_bound(candidate, selection.runtime.MAX_ARCHIVE_BYTES)
    require(len(archive) == 119923125 and hashlib.sha256(archive).hexdigest() == ARCHIVE_SHA,
            "runtime009 archive identity differs")
    manifest_bytes, manifest = pinned_json(receipt.parent / "runtime-manifest.json", MANIFEST_SHA)
    receipt_bytes = read_bound(receipt, selection.runtime.MAX_METADATA_BYTES)
    expected_receipt = {
        "schema_version": 1, "ruling_id": "R-N13",
        "additional_ruling_id": "R-HOOK-CONVERGENCE-20261004",
        "status": "native-owner-runtime-proof-candidate", "native_support": False,
        "candidate": EXPECTED_CANDIDATE, "executable": EXPECTED_EXECUTABLE,
        "archive_sha256": ARCHIVE_SHA, "archive_bytes": 119923125,
        "manifest_sha256": MANIFEST_SHA,
        "scope": "Declared transformed runtime proof input; no SDK execution, installation or continuity proof.",
    }
    require(receipt_bytes == (json.dumps(expected_receipt, indent=2) + "\n").encode(),
            "runtime009 exact external receipt differs")
    qualified = selection.qualify_runtime(archive, manifest_bytes, receipt_bytes,
        expected_source_receipt_sha256=SOURCE_RECEIPT_SHA,
        expected_producer_receipt_sha256=PRODUCER_RECEIPT_SHA)
    require(manifest["candidate"] == EXPECTED_CANDIDATE and manifest["executable"] == EXPECTED_EXECUTABLE
            and qualified["selection"]["native_support"] is False
            and qualified["selection"]["executable_attribution"] == "unproved"
            and qualified["selection"]["channel_authority"] == "absent",
            "runtime009 artifact-only selection scope differs")
    checked, files = selection.runtime.verify_runtime_files(archive, expected_receipt)
    require(checked == manifest, "runtime009 separate manifest differs from embedded manifest")
    return manifest, files


def discovered_attachment(cli, endpoint):
    found = cli("integrations.discover", {"adapter": "codex"})
    require(found.get("installed") is True and found.get("native_support") is False
            and found.get("hook_compatible") is True and len(found.get("owners", [])) == 1,
            "legacy native discovery lacks exact installed owner")
    owner = found["owners"][0]
    require(owner["owner_endpoint"] == str(endpoint) and owner["support"] == "compatible_hook"
            and endpoint.parent.name == "omux-owner-" + owner["owner_id"][:16]
            and re.fullmatch(r"[0-9a-f]{64}", owner["owner_id"]) is not None
            and re.fullmatch(r"[0-9a-f]{64}", owner["process_nonce"]) is not None
            and len(owner["threads"]) <= 1, "legacy discovery owner identity differs")
    tui.generation(owner["endpoint_generation"])
    if not owner["threads"]:
        return None
    thread = owner["threads"][0]
    require(re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                         thread["thread_id"]) is not None, "legacy native thread identity differs")
    reference = thread.get("native_ref")
    if reference is None:
        return None
    require(set(reference) == {"owner_id", "adapter_epoch", "endpoint_generation",
                               "thread_instance_generation", "attachment_generation"}
            and reference["owner_id"] == owner["owner_id"], "legacy committed reference differs")
    for field in reference:
        if field != "owner_id":
            tui.generation(reference[field])
    require(reference["endpoint_generation"] == owner["endpoint_generation"]
            and reference["thread_instance_generation"] == thread["thread_instance_generation"]
            and reference["attachment_generation"] == thread["attachment_generation"],
            "legacy discovery disagrees with committed attached ledger")
    # These are actual daemon discovery fields, not a fabricated native status.
    return {"owner": owner, "thread_id": thread["thread_id"], "reference": reference}


def pump_native(native):
    if isinstance(native, tui.TerminalProcess):
        native.pump(0.05)
    else:
        time.sleep(0.05)


def native_call(native, method, params):
    global DIAGNOSTIC
    try:
        return native.call(method, params)
    except ValueError:
        DIAGNOSTIC = support.FAILURE if support.FAILURE in support.FAILURES else "unclassified"
        raise


def classify_status_stderr(diagnostics, params):
    # Classifications are private recognition, never a reason to admit stderr.
    return native_cli_stderr.classify(diagnostics, params, tui.strict_object)


def classify_status_process(code, output, diagnostics, params, expected_completion):
    # Privately recognize the bounded streams. Only fixed enum labels survive;
    # even an exact completed body never overrides the mandatory stderr refusal.
    global CLI_EXIT, CLI_PROTOCOL, CLI_STDERR, CLI_COMPLETION
    CLI_STDERR = classify_status_stderr(diagnostics, params)
    CLI_COMPLETION = "completion-not-result"
    CLI_EXIT = ("exit-zero-stderr" if code == 0 else "exit-one" if code == 1 else
                "exit-two" if code == 2 else "exit-positive-other" if code > 0 else "exit-signal")
    try:
        value = json.loads(output, object_pairs_hook=tui.strict_object)
    except (ValueError, UnicodeDecodeError, RecursionError):
        CLI_PROTOCOL = "status-json-unrecognized"
        return
    CLI_PROTOCOL = "status-envelope-unrecognized"
    if (not isinstance(value, dict) or value.get("jsonrpc") != "2.0"
            or type(value.get("id")) is not int or value["id"] != 1):
        return
    if set(value) == {"jsonrpc", "id", "result"} and isinstance(value["result"], dict):
        CLI_PROTOCOL = "status-result"
        CLI_COMPLETION = ("completion-exact" if expected_completion is not None
                          and value["result"] == expected_completion else "completion-other-result")
        return
    if set(value) != {"jsonrpc", "id", "error"}:
        return
    error = value["error"]
    if (not isinstance(error, dict) or set(error) != {"code", "message"}
            or type(error["code"]) is not int or not isinstance(error["message"], str)):
        return
    CLI_PROTOCOL = STATUS_REFUSALS.get((error["code"], error["message"]), "status-other-refusal")


def status_cli(command, environment, params, *, expected_completion):
    # Same single CLI invocation, stdin, capture limits, 20-second deadline and
    # cleanup as support.run_cli. Only its process-failure branch gains private
    # classification before the original mandatory rejection.
    global CLI_EXIT, CLI_PROTOCOL, CLI_STDERR, CLI_COMPLETION
    CLI_EXIT = CLI_PROTOCOL = CLI_STDERR = CLI_COMPLETION = "unclassified"
    global CLI_OBSERVATION
    CLI_OBSERVATION = None
    deadline = time.monotonic() + 20 if FD2_OBSERVER is not None else None
    observed = bytearray()
    launch = None
    if FD2_OBSERVER is not None:
        prefix, files, loader = FD2_CONTEXT
        launch = native_fd2_observer.Launch(FD2_OBSERVER, command, prefix, files, loader,
                                           int(deadline * 10**9))
    process = None
    selector = selectors.DefaultSelector()
    output, diagnostics = bytearray(), bytearray()
    try:
        process = subprocess.Popen(launch.command if launch else command, env=environment,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   pass_fds=launch.pass_fds if launch else ())
        if launch:
            launch.child_started()
            os.set_blocking(launch.read_fd, False)
            selector.register(launch.read_fd, selectors.EVENT_READ, observed)
        process.stdin.write(json.dumps(params, separators=(",", ":")).encode())
        process.stdin.close()
        for stream, destination in ((process.stdout, output), (process.stderr, diagnostics)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, destination)
        if deadline is None:
            deadline = time.monotonic() + 20
        while selector.get_map() and time.monotonic() < deadline:
            for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fd, 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                key.data.extend(chunk)
                maximum = native_fd2_observer.MAX_RECORD if key.data is observed else support.FRAME_LIMIT
                require(len(key.data) <= maximum, "installed CLI output exceeded its bound")
        require(not selector.get_map(), "installed CLI deadline exceeded")
        process.wait(timeout=max(0.1, deadline - time.monotonic()))
        if launch:
            launch.recheck()
            CLI_OBSERVATION = native_fd2_observer.parse_record(bytes(observed))
        if process.returncode != 0 or diagnostics:
            classify_status_process(process.returncode, output, diagnostics, params, expected_completion)
        require(process.returncode == 0 and not diagnostics, "installed CLI predicate failed")
        if launch:
            require(CLI_OBSERVATION.startswith(("observed/", "no-write/")),
                    "installed CLI observer unavailable")
        value = json.loads(output, object_pairs_hook=tui.strict_object)
        require(isinstance(value, dict) and set(value) == {"jsonrpc", "id", "result"}
                and value["jsonrpc"] == "2.0" and type(value["id"]) is int
                and value["id"] == 1 and isinstance(value["result"], dict),
                "installed CLI response rejected")
        return value["result"]
    finally:
        if process is not None:
            support.stop(process)
            if process.stdin and not process.stdin.closed:
                process.stdin.close()
            process.stdout.close()
            process.stderr.close()
        selector.close()
        if launch:
            launch.close()


def classify_resume_failure(error):
    # Inspect only type or compare literal helper messages privately. No raw
    # exception text, errno, terminal bytes, path, UUID or reference is emitted.
    if isinstance(error, json.JSONDecodeError):
        return "resume-json"
    if isinstance(error, sqlite3.Error):
        # A finite SQLite code category only; query text and database paths
        # remain private. This changes no retry or metadata acceptance behavior.
        code = getattr(error, "sqlite_errorcode", None)
        if code in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
            return "resume-database-busy"
        if code == sqlite3.SQLITE_ERROR:
            return "resume-database-query"
        return "resume-database-error"
    if isinstance(error, FileNotFoundError):
        return "resume-missing-input"
    if isinstance(error, PermissionError):
        return "resume-permission"
    if isinstance(error, OSError):
        return "resume-" + native_run_cli_failure.failure_kind(error)
    if isinstance(error, subprocess.TimeoutExpired):
        return "resume-process-deadline"
    if isinstance(error, ValueError):
        return RESUME_FAILURE_MESSAGES.get(str(error), "resume-other-predicate")
    if isinstance(error, KeyError):
        return "resume-shape"
    if isinstance(error, TypeError):
        return "resume-type"
    return "resume-unrecognized"


def cold_discovery(socket_path, daemon_pid, params):
    """Read actual daemon discovery without a short-lived CLI process per poll.

    Install, seed discovery, detach and preservation still exercise installed
    CLI boundaries. Only cold attachment polling uses this bounded control
    client; it never substitutes an owner response or guessed attachment.
    """
    deadline = time.monotonic() + 20

    def exchange(method, supplied):
        information = socket_path.lstat()
        parent = socket_path.parent.lstat()
        require(stat.S_ISSOCK(information.st_mode) and information.st_uid == os.getuid()
                and stat.S_IMODE(information.st_mode) == 0o600
                and stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid()
                and stat.S_IMODE(parent.st_mode) == 0o700,
                "cold discovery control socket custody changed")
        packet = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                             "params": supplied}, separators=(",", ":")).encode() + b"\n"
        require(len(packet) <= 8192, "cold discovery request exceeded bound")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            remaining = deadline - time.monotonic()
            require(remaining > 0, "cold discovery control deadline exceeded")
            channel.settimeout(remaining)
            channel.connect(str(socket_path))
            peer = struct.unpack("3i", channel.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            require(peer[0] == daemon_pid and peer[1] == os.getuid(),
                    "cold discovery control peer changed")
            channel.sendall(packet)
            response = bytearray()
            while b"\n" not in response:
                remaining = deadline - time.monotonic()
                require(remaining > 0, "cold discovery control deadline exceeded")
                channel.settimeout(remaining)
                chunk = channel.recv(8192)
                require(chunk and len(response) + len(chunk) <= tui.FRAME_LIMIT,
                        "cold discovery control frame exceeded bound")
                response.extend(chunk)
        require(response.endswith(b"\n") and response.count(b"\n") == 1,
                "cold discovery control frame changed")
        value = json.loads(response, object_pairs_hook=tui.strict_object)
        require(isinstance(value, dict) and set(value) == {"jsonrpc", "id", "result"}
                and value["jsonrpc"] == "2.0" and type(value["id"]) is int and value["id"] == 1
                and isinstance(value["result"], dict), "cold discovery control response rejected")
        return value["result"]

    hello = exchange("system.handshake", {"protocol_version": 2, "client": "omux-tui-fixture"})
    require(type(hello.get("protocol_version")) is int and hello["protocol_version"] == 2,
            "cold discovery control handshake rejected")
    return exchange("integrations.discover", params)


def wait_attached(cli, home, native, *, resume_diagnostics=False):
    global DIAGNOSTIC
    if resume_diagnostics:
        DIAGNOSTIC = "resume-owner-endpoint"
    endpoint = support.owned_endpoint(home, native)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if resume_diagnostics:
            DIAGNOSTIC = "resume-terminal-alive"
        native.alive()
        if resume_diagnostics:
            DIAGNOSTIC = "resume-owner-discovery"
        observed = discovered_attachment(cli, endpoint)
        if observed is not None:
            return endpoint, observed["thread_id"], observed
        if resume_diagnostics:
            DIAGNOSTIC = "resume-terminal-pump"
        pump_native(native)
    if resume_diagnostics:
        DIAGNOSTIC = "resume-attachment-deadline"
    raise ValueError("legacy native committed attachment deadline exceeded")


def diagnostic_history_witness(home, thread, *, phase_prefix):
    # Execute the existing shared witness exactly once. It changes support.PHASE
    # but its plain require() never sets support.FAILURE; retain only its finite
    # stage/type or exact original predicate before outer cleanup erases context.
    global DIAGNOSTIC
    previous = DIAGNOSTIC
    try:
        observed = support.history_witness(home, thread, phase_prefix=phase_prefix)
    except Exception as error:
        DIAGNOSTIC = native_history_diagnostic.classify(error, support.PHASE)
        raise
    DIAGNOSTIC = previous
    return observed


def seed_history_attachment_difference(observed, expected):
    # Private projection only after the original complete equality was false.
    # Values, IDs, endpoints and exception text never become diagnostic output.
    if observed is None:
        return "seed-history-attachment-absent"
    if observed["thread_id"] != expected["thread_id"] or any(
            observed["owner"][field] != expected["owner"][field]
            for field in ("owner_id", "process_nonce", "owner_endpoint")):
        return "seed-history-attachment-identity"
    if observed["reference"] != expected["reference"]:
        return "seed-history-attachment-reference"
    return "seed-history-attachment-other"


def seed_history_attachment(cli, endpoint, expected):
    # Called only through the original process-identity short circuit.
    global DIAGNOSTIC

    def discovery_cli(*arguments, **options):
        global DIAGNOSTIC
        DIAGNOSTIC = "seed-history-discovery-rpc"
        found = cli(*arguments, **options)
        DIAGNOSTIC = "seed-history-discovery-validation"
        return found

    observed = discovered_attachment(discovery_cli, endpoint)
    DIAGNOSTIC = "seed-history-attachment-comparison"
    # Keep the original complete dictionary equality, exactly once.
    matches = observed == expected
    if matches is False:
        DIAGNOSTIC = "seed-history-attachment-other"
        try:
            DIAGNOSTIC = seed_history_attachment_difference(observed, expected)
        except Exception:
            pass  # Ordinary diagnostic faults cannot admit a false comparison.
        # Control exceptions propagate through the original fixture cleanup.
    return matches


def wait_metadata(home, thread, terminal, *, expected_name=tui.FIXTURE_NAME):
    # Keep the shared genuine native metadata predicates and original deadline.
    # Only a finite diagnostic survives temporary-home cleanup; no native bytes,
    # paths, SQLite text, thread IDs or terminal output enter failure evidence.
    global DIAGNOSTIC
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        terminal.alive()
        try:
            observed = tui.metadata(home, thread, expected_name=expected_name)
        except sqlite3.OperationalError as error:
            if not (home / "state_5.sqlite").exists():
                DIAGNOSTIC = "metadata-database-absent"
            elif getattr(error, "sqlite_errorcode", None) in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED):
                DIAGNOSTIC = "metadata-database-busy"
            elif getattr(error, "sqlite_errorcode", None) == sqlite3.SQLITE_ERROR:
                DIAGNOSTIC = "metadata-database-query"
            else:
                DIAGNOSTIC = "metadata-database-error"
        except FileNotFoundError:
            DIAGNOSTIC = "rollout-file-absent"
        except json.JSONDecodeError:
            DIAGNOSTIC = "rollout-json"
        except ValueError as error:
            DIAGNOSTIC = METADATA_DIAGNOSTICS.get(str(error), "metadata-other-predicate")
        else:
            DIAGNOSTIC = "unclassified"
            return observed
        pump_native(terminal)
    raise ValueError("ordinary native metadata did not flush")


def capture_detach_cli_failure(data):
    # Shared helper delivers finite bytes only. Preserve no raw CLI output.
    global DETACH_CLI_FAILURE_RECORD
    DETACH_CLI_FAILURE_RECORD = native_run_cli_failure.parse_record(data)


def run_detach_cli(command, environment, params):
    # The normal target keeps its original helper call and output.
    if FD2_OBSERVER is None:
        return support.run_cli(command, environment, params)
    global DETACH_CLI_FAILURE_RECORD
    DETACH_CLI_FAILURE_RECORD = None
    return support.run_cli(command, environment, params,
                           failure_observer=capture_detach_cli_failure)


def detach(cli, endpoint, observed):
    global DIAGNOSTIC, CLI_FAILURE
    operation = os.urandom(32).hex()
    # CLI helpers discard their raw RPC replies/diagnostics. Keep only the
    # finite failing edge; every original hard detach predicate remains.
    DIAGNOSTIC = "detach-health-rpc"
    revision = cli("system.health")["revision"]
    params = {"adapter": "codex", "owner_endpoint": str(endpoint),
              "thread_id": observed["thread_id"], "native_ref": observed["reference"],
              "operation_id": operation, "expected_revision": revision}
    DIAGNOSTIC = "detach-rpc"
    result = cli("integrations.detach", params)
    DIAGNOSTIC = "detach-ack-predicate"
    require(result == {"detached": True, "operation_id": operation, "native_ref": observed["reference"]},
            "legacy exact detach did not acknowledge original reference")
    DIAGNOSTIC = "detach-status-rpc"
    CLI_FAILURE = "unclassified"
    try:
        completed = cli("operation.status", {"operation_id": operation},
                        expected_completion={"operation_id": operation, "status": "completed", "result": result})
    except json.JSONDecodeError:
        CLI_FAILURE = "cli-json"
        raise
    except subprocess.TimeoutExpired:
        CLI_FAILURE = "cli-process-deadline"
        raise
    except ValueError as error:
        # Compare static helper messages privately. No exception text, reply,
        # diagnostic bytes, argv or operation identifier enters evidence.
        CLI_FAILURE = CLI_FAILURE_MESSAGES.get(str(error), "unclassified")
        raise
    DIAGNOSTIC = "detach-completion-predicate"
    require(completed == {"operation_id": operation, "status": "completed", "result": result},
            "legacy detach completion or exact replay differs")
    DIAGNOSTIC = "detach-replay-rpc"
    replay = cli("integrations.detach", params)
    DIAGNOSTIC = "detach-replay-predicate"
    require(replay == result, "legacy detach completion or exact replay differs")
    DIAGNOSTIC = "detach-discovery-rpc"
    after = discovered_attachment(cli, endpoint)
    DIAGNOSTIC = "detach-retirement-predicate"
    require(after is None,
            "legacy detached reference remained projected as committed attached")
    DIAGNOSTIC = "unclassified"
    return operation


def inspect_durable(state, observations, operations, endpoints, witnesses, thread):
    with closing(sqlite3.connect((state / "state.sqlite").as_uri() + "?mode=ro", uri=True)) as connection:
        support.check_sealed_snapshot(connection, state / "state.sqlite.authority")
        require(connection.execute("SELECT count(*) FROM grants").fetchone()[0] == 0,
                "legacy terminal acquired encrypted credentials")
        raw = connection.execute("SELECT CAST(metadata_json AS BLOB) FROM snapshot").fetchone()[0]
    require(len(raw) <= 16 * 1024 * 1024, "legacy sealed snapshot exceeds bound")
    saved = json.loads(raw, object_pairs_hook=tui.strict_object)
    support.check_empty_domain(saved["state"])
    require(saved["request_authority"]["records"] == [] and saved["outcome_intents"] == []
            and saved["snapshot_admission"]["credits"] == []
            and "codex" in saved["installed_integrations"] and saved["native_registry"]["phase"] == "installed",
            "legacy terminal changed domain obligations or installation custody")
    ledger = saved["native_owner_authority"]
    require(len(ledger["owners"]) == len(ledger["attachments"]) == 2 and ledger["removals"] == [],
            "legacy cold-resume custody cardinality differs")
    registrations = []
    for observed, operation, endpoint, witness in zip(observations, operations, endpoints, witnesses, strict=True):
        reference = observed["reference"]
        matched = [row for row in ledger["attachments"]
                   if support.fixed_bytes(row["reference"]["owner_id"], 32).hex() == reference["owner_id"]
                   and all(str(row["reference"][key]) == reference[key] for key in reference if key != "owner_id")]
        require(len(matched) == 1 and matched[0]["phase"] == "retired"
                and matched[0]["retirement"] == "verified_detach" and matched[0]["thread_id"] == thread
                and support.fixed_bytes(matched[0]["detach_operation"], 64).decode("ascii") == operation,
                "legacy sealed exact detach attribution differs")
        registration = support.fixed_bytes(matched[0]["registration_operation"], 64).decode("ascii")
        require(re.fullmatch(r"[0-9a-f]{64}", registration) is not None,
                "legacy sealed registration operation differs")
        registrations.append(registration)
        internal_id = hashlib.sha256(b"omux.native.mutation.v1.adapter.owner.register" + registration.encode()).hexdigest()
        records = [row for row in saved["mutation_authority"]["records"]
                   if row["id_len"] == 64 and support.fixed_bytes(row["id"], 64).decode("ascii") == internal_id]
        require(len(records) == 1 and records[0]["state"] == "completed"
                and support.fixed_bytes(records[0]["method"], 64)[:records[0]["method_len"]] == b"adapter.owner.register",
                "legacy native registration has no immutable completed result")
        encoded = records[0]["result"]
        if isinstance(encoded, list):
            encoded = bytes(encoded).decode("utf-8")
        require(json.loads(encoded, object_pairs_hook=tui.strict_object) == {
            "registered": True, "operation_id": registration, "native_ref": reference},
            "legacy immutable registration result differs from original reference")
        owners = [row for row in ledger["owners"] if support.fixed_bytes(row["id"], 32).hex() == reference["owner_id"]
                  and str(row["adapter_epoch"]) == reference["adapter_epoch"]
                  and str(row["endpoint_generation"]) == reference["endpoint_generation"]]
        require(len(owners) == 1, "legacy sealed native owner is absent or ambiguous")
        owner = owners[0]
        saved_witness = dict(owner["witness"])
        saved_witness["boot_id"] = list(support.fixed_bytes(saved_witness["boot_id"], 16))
        require(owner["application"] == "codex" and owner["endpoint_path"] == str(endpoint)
                and owner["phase"] == "open" and saved_witness == witness
                and support.fixed_bytes(owner["native_nonce"], 32).hex() == observed["owner"]["process_nonce"],
                "legacy sealed process incarnation differs")
    require(registrations[0] != registrations[1], "legacy cold resume reused registration operation")


ORDINARY_MARKER = b"OMUX_INSTALLED_RETAINED_ORDINARY_NATIVE_TUI_OK\n"
ORDINARY_PHASES = ("private-context", "runtime-verification", "keyring-startup", "daemon-startup",
    "bootstrap-native", "integration-install", "ordinary-tui-startup",
    "native-history-materialization", "native-rename", "selected-detach",
    "native-preservation", "ordinary-clean-exit", "cold-native-resume",
    "resumed-preservation", "resumed-detach", "durable-inspection", "owned-cleanup")


def ordinary_first_history(binary, environment, work, home, cli, config, configured,
                           capability_path, capability, failure_observer):
    """Real terminal commands and actual committed daemon discovery only.

    Own the first terminal through partial failure; no status normalization,
    app-server history call, submitted turn or accepted work replay is possible.
    """
    global PHASE
    PHASE = "ordinary-tui-startup"
    terminal = tui.TerminalProcess(binary, environment, work, failure_observer=failure_observer)
    try:
        first_pid = terminal.process.pid
        endpoint, thread, first = wait_attached(cli, home, terminal)
        witness = tui.process_witness(first_pid)
        PHASE = "native-history-materialization"
        terminal.send("/export omux-native-resume-fixture.md\r")
        wait_metadata(home, thread, terminal, expected_name=None)
        terminal.alive()
        require(terminal.process.pid == first_pid and tui.process_witness(first_pid) == witness
                and discovered_attachment(cli, endpoint) == first,
                "retained ordinary export changed process or committed attachment")
        PHASE = "native-rename"
        terminal.send("/rename " + tui.FIXTURE_NAME + "\r")
        before = wait_metadata(home, thread, terminal)
        require(before[0][4] == "paginated", "retained ordinary history mode differs")
        support.HISTORY_MODE = "paginated"
        PHASE = "selected-detach"
        operation = detach(cli, endpoint, first)
        PHASE = "native-preservation"
        terminal.alive()
        require(terminal.process.pid == first_pid and tui.process_witness(first_pid) == witness
                and tui.metadata(home, thread) == before,
                "retained ordinary detach changed process or native history")
        require(support.private_file(config, 1024 * 1024) == configured
                and support.private_file(capability_path, 128) == capability,
                "retained ordinary detach changed native configuration")
        support.check_empty_domain(cli("state.snapshot"))
        PHASE = "ordinary-clean-exit"
        terminal.close(require_success=True)
        require(tui.metadata(home, thread) == before and not endpoint.exists(),
                "retained ordinary clean exit changed history or retained endpoint")
        return {"pid": first_pid, "endpoint": endpoint, "witness": witness,
                "thread": thread, "attachment": first, "before": before, "operation": operation}
    except BaseException as primary:
        try:
            terminal.close()
        except BaseException:
            primary.add_note("retained ordinary owned terminal cleanup refused")
        raise


def inside(bundle, candidate, receipt, keyring, root, *, census_deadline_ns=None,
           ordinary_first=False):
    global PHASE, DIAGNOSTIC
    require(os.environ.get("OMUX_ISOLATED_VAULT_PROOF") == "private-bus-private-xdg",
            "disposable genuine vault context required")
    PHASE = "runtime-verification"
    candidate_manifest, files = verify_legacy_inputs(candidate, receipt)
    candidate_prefix = root / "candidate"
    candidate_prefix.mkdir(mode=0o700)
    for name, payload in files.items():
        destination = candidate_prefix / name
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(payload)
        os.chmod(destination, 0o644 if name == "runtime-manifest.json" else candidate_manifest["files"][name]["mode"])
    prefix, records, state, home, work = (root / name for name in ("installed", "records", "state", "h", "w"))
    for directory in (state, home, work):
        directory.mkdir(mode=0o700)
    codex_home = home / "c"
    codex_home.mkdir(mode=0o700)
    require(len(os.fsencode(codex_home)) <= 68, "native home exceeds bounded endpoint layout")
    config = codex_home / "config.toml"
    # Skip the candidate's one-time screen-reader bookkeeping before capture.
    # Cold resume still requires exact retained config and capability bytes.
    config.write_text('cli_auth_credentials_store = "file"\nsandbox_mode = "read-only"\napproval_policy = "never"\n'
                      'check_for_update_on_startup = false\n'
                      '[tui]\nscreen_reader_detection_done = true\n'
                      '[otel]\nexporter = "none"\ntrace_exporter = "none"\nmetrics_exporter = "none"\nlog_user_prompt = false\n'
                      '[cloud.skills]\nenabled = false\n[analytics]\nenabled = false\n'
                      '[features]\nplugins = false\nrecommended_plugins = false\napps = false\nenable_mcp_apps = false\n'
                      '[projects.' + json.dumps(str(work)) + ']\ntrust_level = "trusted"\n')
    config.chmod(0o600)
    payload = support.pack.read_bundle(bundle)
    manifest, installed_files = support.pack.verify_bundle(payload)
    require(manifest["distribution"] == "portable-linux" and manifest.get("channel") == "release",
            "actual default-instance portable Omux archive required")
    record = support.install.install_bundle(payload, prefix, records)
    global FD2_CONTEXT
    if FD2_OBSERVER is not None:
        FD2_CONTEXT = (prefix, installed_files, manifest["runtime"]["loader"])
    require(not record["serviceActivated"], "legacy fixture activated host service")
    environment = dict(os.environ)
    # Retained009 fixture: two Tokio async scheduler workers for this profile.
    # This does not bound blocking threads or diagnose prior fork EAGAIN.
    # Bootstrap and ordinary cold resume share the explicit test budget.
    environment.update(HOME=str(home), CODEX_HOME=str(codex_home), PATH="/nonexistent",
                       TERM="xterm-256color", OMUX_INSTANCE="default", TOKIO_WORKER_THREADS="2")
    socket_path = Path(environment["XDG_RUNTIME_DIR"]) / ("omux-" + hashlib.sha256(str(state).encode()).hexdigest()[:32]) / "control.sock"
    require(len(os.fsencode(socket_path)) <= 107, "installed control path too long")
    keyring_process = daemon = bootstrap_native = terminal = None
    terminal_failure = TerminalFailureObservation()
    drains = []
    try:
        census = native_threads.Census(census_deadline_ns)
    except Exception:
        census = None  # Ordinary diagnostic errors never replace fixture setup.

    def cli(method, params=None, *, expected_completion=None):
        for drain in drains:
            drain.check()
        if method == "integrations.discover" and PHASE == "cold-native-resume":
            return cold_discovery(socket_path, daemon.pid, params or {})
        command = [str(prefix / "bin/omux"), "--state-dir", str(state), "rpc", method, "-"]
        if method == "operation.status" and DIAGNOSTIC == "detach-status-rpc":
            return status_cli(command, environment, params or {}, expected_completion=expected_completion)
        if FD2_OBSERVER is not None and method == "integrations.detach" and DIAGNOSTIC == "detach-rpc":
            return run_detach_cli(command, environment, params or {})
        return support.run_cli(command, environment, params or {})

    try:
        PHASE = "keyring-startup"
        keyring_process = native_threads.owned_popen(census, "keyring", [str(keyring), "--foreground", "--unlock", "--components=secrets"],
                                           env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, umask=0o077)
        native_threads.checkpoint(census)
        drains.append(support.DiscardLog(keyring_process.stdout))
        keyring_process.stdin.write(b"\n")
        keyring_process.stdin.close()
        time.sleep(0.5)
        PHASE = "daemon-startup"
        daemon = native_threads.owned_popen(census, "daemon", [str(prefix / "bin/omuxd"), "--state-dir", str(state)], env=environment,
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, umask=0o077)
        native_threads.checkpoint(census)
        drains.append(support.DiscardLog(daemon.stdout))
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            require(daemon.poll() is None and keyring_process.poll() is None, "installed custody process exited")
            if socket_path.is_socket():
                information = socket_path.lstat()
                require(information.st_uid == os.getuid() and stat.S_IMODE(information.st_mode) == 0o600,
                        "installed control socket custody changed")
                health = cli("system.health")
                require(health["custody_available"] and health["protocol_version"] == 2
                        and health["live_handoff_proven"] is False, "installed custody unavailable")
                break
            time.sleep(0.05)
        else:
            raise ValueError("installed custody startup deadline exceeded")
        support.check_empty_domain(cli("state.snapshot"))
        PHASE = "bootstrap-native"
        binary = candidate_prefix / "bin/codex"
        bootstrap_native = support.JsonProcess([str(binary), "app-server", "--listen", "stdio://", "--strict-config"], environment, work,
                                               popen_factory=native_threads.factory(census, "native-bootstrap"))
        native_threads.checkpoint(census)
        native_call(bootstrap_native, "initialize", {"clientInfo": {"name": "omux-legacy-tui-proof", "title": None, "version": "1"},
                              "capabilities": {"experimentalApi": False, "requestAttestation": False}})
        bootstrap_native.send("initialized", {})
        endpoint = support.owned_endpoint(codex_home, bootstrap_native)
        PHASE = "integration-install"
        installed = cli("integrations.install", {"adapter": "codex", "config_path": str(config), "native_socket": str(endpoint),
                        "operation_id": os.urandom(32).hex(), "expected_revision": cli("system.health")["revision"]})
        require(installed.get("installed") is True and installed.get("changed") is True, "legacy genuine integration setup failed")
        configured = support.private_file(config, 1024 * 1024)
        capability_path = state / "integrations/codex.capability"
        capability = support.private_file(capability_path, 128)
        require(len(capability) == 64 and b"[omux_broker]" in configured, "legacy installed native custody changed")
        if ordinary_first:
            # Setup bootstrap never creates/names/reads the tested thread.
            bootstrap_native.close(require_success=True)
            native_threads.retire(census, "native-bootstrap")
            bootstrap_native = None
            require(not endpoint.exists(), "retained setup bootstrap endpoint remained")
            first_checkpoint = ordinary_first_history(binary, environment, work, codex_home, cli,
                config, configured, capability_path, capability, terminal_failure)
            first_pid = first_checkpoint["pid"]
            first_endpoint = endpoint = first_checkpoint["endpoint"]
            first_witness = first_checkpoint["witness"]
            thread = first_checkpoint["thread"]
            first = first_checkpoint["attachment"]
            before = first_checkpoint["before"]
            first_operation = first_checkpoint["operation"]
        else:
            PHASE = "native-seed-start"
            # The native APIs own every history write. Reuse the exact retained
            # candidate's observed empty-history initialization sequence; the failed
            # full read is required, not an inferred successful checkpoint.
            started = native_call(bootstrap_native, "thread/start", {"cwd": str(work), "ephemeral": False})
            seed = started.get("thread")
            require(isinstance(seed, dict) and isinstance(seed.get("id"), str)
                    and seed.get("sessionId") == seed["id"] and seed.get("historyMode") == "paginated"
                    and seed.get("ephemeral") is False and seed.get("status", {}).get("type") == "idle",
                    "legacy native empty seed identity or history mode differs")
            support.HISTORY_MODE = "paginated"
            first_pid = bootstrap_native.process.pid
            endpoint, thread, first = wait_attached(cli, codex_home, bootstrap_native)
            require(thread == seed["id"], "legacy seed discovery did not match actual native UUID")
            first_endpoint, first_witness = endpoint, tui.process_witness(first_pid)
            PHASE = "native-seed-uninitialized-history"
            try:
                native_call(bootstrap_native, "thread/read", {"threadId": thread, "includeTurns": True})
            except ValueError:
                require(support.FAILURE == "native-list-turns-unsupported",
                        "legacy uninitialized native history rejection differs")
            else:
                raise ValueError("legacy uninitialized native history unexpectedly succeeded")
            support.FAILURE = DIAGNOSTIC = "unclassified"
            PHASE = "native-seed-name"
            native_call(bootstrap_native, "thread/name/set", {"threadId": thread, "name": tui.FIXTURE_NAME})
            PHASE = "native-seed-full-read"
            full = native_call(bootstrap_native, "thread/read", {"threadId": thread, "includeTurns": True}).get("thread")
            require(isinstance(full, dict) and full.get("id") == thread and full.get("sessionId") == thread
                    and full.get("historyMode") == "paginated" and full.get("ephemeral") is False
                    and full.get("cwd") == str(work) and full.get("turns") == []
                    and full.get("name") == tui.FIXTURE_NAME and full.get("status", {}).get("type") == "idle",
                    "legacy native full read did not retain actual provider-free seed")
            PHASE = "native-seed-history"
            seed_history = diagnostic_history_witness(codex_home, full, phase_prefix="first-native-history")
            DIAGNOSTIC = "seed-history-metadata"
            before = wait_metadata(codex_home, thread, bootstrap_native)
            DIAGNOSTIC = "seed-history-sql-match"
            require(before[0][1] == str(seed_history[0]) and before[1:3] == seed_history[1:]
                    and before[0][4] == "paginated",
                    "legacy seed full-read history and native SQL witnesses disagree")
            DIAGNOSTIC = "seed-history-liveness"
            bootstrap_native.alive()
            DIAGNOSTIC = "seed-history-process"
            require(bootstrap_native.process.pid == first_pid and seed_history_attachment(cli, endpoint, first),
                    "legacy seed initialization changed process or attachment")
            DIAGNOSTIC = "unclassified"
            PHASE = "selected-detach"
            first_operation = detach(cli, endpoint, first)
            PHASE = "native-preservation"
            bootstrap_native.alive()
            detached = native_call(bootstrap_native, "thread/read", {"threadId": thread, "includeTurns": True}).get("thread")
            require(isinstance(detached, dict) and all(detached.get(field) == full.get(field) for field in
                    ("id", "sessionId", "path", "cwd", "historyMode", "cliVersion", "source", "turns", "name", "ephemeral"))
                    and detached.get("status", {}).get("type") == "idle"
                    and diagnostic_history_witness(codex_home, detached, phase_prefix="second-native-history") == seed_history
                    and bootstrap_native.process.pid == first_pid and tui.metadata(codex_home, thread) == before,
                    "legacy detach changed native process or persistent state")
            require(support.private_file(config, 1024 * 1024) == configured
                    and support.private_file(capability_path, 128) == capability,
                    "legacy selected detach removed installed configuration")
            support.check_empty_domain(cli("state.snapshot"))
            PHASE = "native-seed-clean-exit"
            bootstrap_native.close(require_success=True)
            native_threads.retire(census, "native-bootstrap")
            bootstrap_native = None
            support.inspect_native_history(codex_home, full, seed_history[0])
            require(tui.metadata(codex_home, thread) == before and not endpoint.exists(),
                    "legacy seed EOF changed persistent metadata or retained writer endpoint")
        PHASE = "cold-native-resume"
        DIAGNOSTIC = "resume-terminal-spawn"
        terminal = tui.TerminalProcess(binary, environment, work, resume=thread,
                                       popen_factory=native_threads.factory(census, "native-resume"),
                                       failure_observer=terminal_failure)
        native_threads.checkpoint(census)
        DIAGNOSTIC = "resume-new-process-predicate"
        require(terminal.process.pid != first_pid, "legacy cold resume reused original process")
        endpoint, resumed_thread, second = wait_attached(cli, codex_home, terminal, resume_diagnostics=True)
        DIAGNOSTIC = "resume-process-witness"
        second_witness = tui.process_witness(terminal.process.pid)
        DIAGNOSTIC = "resume-identity-predicate"
        require(resumed_thread == thread and second["reference"] != first["reference"]
                and second["owner"]["owner_id"] != first["owner"]["owner_id"],
                "legacy cold resume lost original thread or reused authority")
        DIAGNOSTIC = "unclassified"
        PHASE = "resumed-preservation"
        DIAGNOSTIC = "resume-settings-checkpoint"
        resumed = tui.wait_resumed_checkpoint(codex_home, thread, terminal, before)
        DIAGNOSTIC = "resume-retained-config-predicate"
        require(support.private_file(config, 1024 * 1024) == configured
                and support.private_file(capability_path, 128) == capability,
                "legacy cold resume changed retained configuration")
        DIAGNOSTIC = "unclassified"
        PHASE = "resumed-detach"
        second_operation = detach(cli, endpoint, second)
        terminal.alive()
        require(tui.metadata(codex_home, thread) == resumed, "legacy resumed detach changed retained history")
        terminal.close(require_success=True)
        native_threads.retire(census, "native-resume")
        terminal = None
        require(tui.metadata(codex_home, thread) == resumed, "legacy resumed clean exit changed retained history")
        require(support.private_file(config, 1024 * 1024) == configured
                and support.private_file(capability_path, 128) == capability,
                "legacy resumed selected detach removed installed configuration")
        support.check_empty_domain(cli("state.snapshot"))
        support.stop(daemon, require_success=True)
        native_threads.retire(census, "daemon")
        daemon = None
        PHASE = "durable-inspection"
        inspect_durable(state, [first, second], [first_operation, second_operation],
                        [first_endpoint, endpoint], [first_witness, second_witness], thread)
        PHASE = "owned-cleanup"
        uninstalled = support.install.uninstall(prefix, records)
        require(uninstalled["preserved"] == [] and len(uninstalled["removed"]) == len(record["files"]),
                "legacy owned distribution uninstall failed")
        print((ORDINARY_MARKER if ordinary_first else (OBSERVER_MARKER if FD2_OBSERVER else MARKER)).decode("ascii"), end="")
    except BaseException:
        # This hook runs once before the original cleanup. Diagnostic failures,
        # cancellation or exit never replace the primary exception or predicates.
        if terminal is not None:
            try:
                # No extra read, drain or deadline extension. The original alive()
                # call already pumped output; inspect only its finite recognition.
                sys.stderr.write(terminal_failure.record(terminal))
            except BaseException:
                pass
        try:
            native_threads.emit_failure(census, lambda value: sys.stderr.write(value.decode("ascii")))
        except BaseException:
            pass
        raise
    finally:
        try:
            actions = []
            if terminal is not None:
                actions.append(terminal.close)
            if bootstrap_native is not None:
                actions.append(bootstrap_native.close)
            if daemon is not None:
                actions.append(lambda: support.stop(daemon))
            if keyring_process is not None:
                actions.append(lambda: support.stop(keyring_process))
            actions.extend(drain.join for drain in drains)
            failed = False
            for action in actions:
                try:
                    action()
                except Exception:
                    failed = True
            require(not failed, "legacy owned private terminal process cleanup failed")
        finally:
            native_threads.close(census, primary=sys.exc_info()[0] is not None)


def main(*, ordinary_first=False, entrypoint=None):
    global FD2_OBSERVER
    require(type(ordinary_first) is bool and (not ordinary_first or
            (entrypoint is not None and FD2_OBSERVER is None and "--fd2-observer" not in sys.argv[1:])),
            "retained ordinary mode cannot select diagnostic observer")
    census_deadline_ns = None
    if len(sys.argv) > 2 and sys.argv[1] == "--census-deadline-ns":
        value = sys.argv[2]
        if re.fullmatch(r"[1-9][0-9]{0,18}", value) and int(value) <= 2**63 - 1:
            census_deadline_ns = int(value)
        del sys.argv[1:3]
    # Explicit diagnostic target only. Ordinary target supplies no observer.
    if len(sys.argv) > 2 and sys.argv[1] == "--fd2-observer":
        FD2_OBSERVER = Path(sys.argv[2]).resolve(strict=True)
        del sys.argv[1:3]
    if len(sys.argv) == 7 and sys.argv[1] == "--inside":
        if ordinary_first:
            inside(*(Path(value).resolve(strict=True) for value in sys.argv[2:]),
                   census_deadline_ns=census_deadline_ns, ordinary_first=True)
        else:
            inside(*(Path(value).resolve(strict=True) for value in sys.argv[2:]),
                   census_deadline_ns=census_deadline_ns)
        return 0
    require(len(sys.argv) == 7, "declared Omux/runtime009 archives, receipt and vault tools required")
    bundle, candidate, receipt, session, bus, keyring = (Path(value).resolve(strict=True) for value in sys.argv[1:])
    with tempfile.TemporaryDirectory(prefix="omux-lt-", dir="/tmp") as temporary:
        root = Path(temporary)
        environment = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/nonexistent", "HOME": str(root),
                       "OMUX_ISOLATED_VAULT_PROOF": "private-bus-private-xdg"}
        for name, child in (("XDG_RUNTIME_DIR", "r"), ("XDG_DATA_HOME", "d"), ("XDG_CONFIG_HOME", "c"),
                            ("XDG_CACHE_HOME", "k"), ("XDG_STATE_HOME", "s")):
            directory = root / child
            directory.mkdir(mode=0o700)
            environment[name] = str(directory)
        configuration = root / "bus.conf"
        configuration.write_text('<busconfig><type>session</type><listen>unix:abstract=omux-native-' + root.name
                                 + '</listen><auth>EXTERNAL</auth><policy context="default">'
                                 '<allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/>'
                                 '</policy></busconfig>')
        bootstrap = ("import os,runpy,sys;p=sys.argv.pop(1);sys.path.insert(0,os.path.dirname(p));"
                     "sys.argv[0]=p;runpy.run_path(p,run_name='__main__')")
        # Same original 90s outer gate. This earlier absolute deadline only
        # bounds diagnostics; support still applies its unchanged 90s timeout.
        census_deadline_ns = time.monotonic_ns() + 90_000_000_000
        process = subprocess.Popen([str(session), "--dbus-daemon=" + str(bus), "--config-file=" + str(configuration),
                                    "--", sys.executable, "-I", "-B", "-c", bootstrap, str(Path(entrypoint or __file__).absolute()),
                                    "--census-deadline-ns", str(census_deadline_ns),
                                    *(["--fd2-observer", str(FD2_OBSERVER)] if FD2_OBSERVER else []),
                                    "--inside", str(bundle), str(candidate), str(receipt), str(keyring), str(root)],
                                   env=environment, start_new_session=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, umask=0o077)
        code, output, diagnostics = support.bounded_private_session(process)
        if code == 0:
            expected_marker = ORDINARY_MARKER if ordinary_first else (OBSERVER_MARKER if FD2_OBSERVER else MARKER)
            require(output == expected_marker, "legacy ordinary TUI proof marker missing")
            print(expected_marker.decode("ascii"), end="")
        else:
            for line in diagnostics.splitlines():
                if not line.startswith(TERMINAL_MARKER.encode("ascii")):
                    continue
                parts = line[len(TERMINAL_MARKER):].split(b"/")
                if (len(parts) == 2 and parts[0] in tuple(value.encode("ascii") for value in TERMINAL_EXITS)
                        and parts[1] in tuple(value.encode("ascii") for value in TERMINAL_CATEGORIES)):
                    print(line.decode("ascii"), file=sys.stderr)
                    break
            seen_thread_roles = set()
            for line in diagnostics.splitlines():
                try:
                    projected = native_threads.parse_record(line + b"\n")
                except ValueError:
                    continue
                role = projected.split(b"/")[2]
                if role not in seen_thread_roles and len(seen_thread_roles) < len(native_threads.ROLES):
                    seen_thread_roles.add(role)
                    print(projected.decode("ascii"), end="", file=sys.stderr)
            if FD2_OBSERVER:
                fixed_detach = b"installed legacy native detach cli observation "
                for line in diagnostics.splitlines():
                    if line.startswith(fixed_detach):
                        try:
                            value = native_run_cli_failure.parse_record(line[len(fixed_detach):] + b"\n")
                        except ValueError:
                            continue
                        print(fixed_detach.decode("ascii") + value.decode("ascii"), end="", file=sys.stderr)
                fixed = b"installed legacy native fd2 observation "
                for line in diagnostics.splitlines():
                    if line.startswith(fixed):
                        try:
                            value = native_fd2_observer.parse_record(line[len(fixed):] + b"\n")
                        except ValueError:
                            continue
                        print(fixed.decode("ascii") + native_fd2_observer.PREFIX.decode("ascii")
                              + "/" + value, file=sys.stderr)
            for phase in (ORDINARY_PHASES if ordinary_first else PHASES):
                marker = "installed legacy native terminal proof failed at " + phase
                if marker.encode() + b"\n" in diagnostics:
                    print(marker, file=sys.stderr)
                    break
            for diagnostic in DIAGNOSTICS:
                marker = "installed legacy native terminal diagnostic " + diagnostic
                if diagnostic in RESUME_DIAGNOSTICS:
                    for line in diagnostics.splitlines():
                        parts = line.split(b"/")
                        if (len(parts) == 2 and parts[0] == marker.encode()
                                and parts[1] in tuple(value.encode() for value in RESUME_FAILURES)):
                            print(line.decode("ascii"), file=sys.stderr)
                    continue
                if diagnostic == "detach-status-rpc":
                    # Closed enum projection only; no raw private subprocess line
                    # is decoded or forwarded unless every component is known.
                    for line in diagnostics.splitlines():
                        parts = line.split(b"/")
                        if len(parts) != 6 or parts[0] != marker.encode():
                            continue
                        choices = (CLI_FAILURES, CLI_EXITS, CLI_PROTOCOLS, CLI_STDERRS, CLI_COMPLETIONS)
                        if all(part in tuple(choice.encode() for choice in allowed)
                               for part, allowed in zip(parts[1:], choices)):
                            print(line.decode("ascii"), file=sys.stderr)
                    continue
                if marker.encode() + b"\n" in diagnostics:
                    print(marker, file=sys.stderr)
                    break
        return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as error:
        if FD2_OBSERVER is not None and DETACH_CLI_FAILURE_RECORD is not None:
            print("installed legacy native detach cli observation "
                  + native_run_cli_failure.parse_record(DETACH_CLI_FAILURE_RECORD).decode("ascii"),
                  end="", file=sys.stderr)
        if FD2_OBSERVER and CLI_OBSERVATION:
            print("installed legacy native fd2 observation "
                  + native_fd2_observer.PREFIX.decode("ascii") + "/" + CLI_OBSERVATION, file=sys.stderr)
        print("installed legacy native terminal proof failed at " + PHASE, file=sys.stderr)
        suffix = ("/" + CLI_FAILURE + "/" + CLI_EXIT + "/" + CLI_PROTOCOL + "/" + CLI_STDERR
                  + "/" + CLI_COMPLETION) if DIAGNOSTIC == "detach-status-rpc" else ""
        if DIAGNOSTIC in RESUME_DIAGNOSTICS:
            suffix = "/" + classify_resume_failure(error)
        print("installed legacy native terminal diagnostic " + DIAGNOSTIC + suffix, file=sys.stderr)
        sys.exit(1)
