"""R-N13: actual installed Omux and candidate Codex, without provider work.

Declared Bazel fixture only. Ordinary app-server startup, native persistent
thread registration and acknowledged removal use the real packet/adapter
channels and disposable genuine Secret Service. The exact uninitialized
paginated-history rejection is checked before one ordinary thread/name/set
initializes native metadata; full-history preservation checks then stay intact.
This is configured provider-
free interoperability, not network denial, account handoff or release support.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import threading
import time

# Preserve the declared runfiles tree, including the second private-bus Python
# invocation; resolving the main symlink would admit an ambient source checkout.
sys.path.insert(0, str(Path(__file__).parent.parent / "integrations/codex-owner-runtime"))
import install
import pack
import runtime_package
from test_installed_custody import check_sealed_snapshot, require, stop

PHASE = "private-context"
FAILURE = "unclassified"
HISTORY_MODE = "unobserved"
FAILURES = ("unclassified", "native-rpc-error", "legacy-history-unmaterialized",
            "native-rpc-deadline", "native-process-exited", "native-process-eof",
            "native-rpc-unexpected-response", "native-rpc-invalid-envelope", "native-rpc-output-limit",
            "native-history-unmaterialized", "native-thread-not-loaded", "native-rollout-missing",
            "native-experimental-required", "native-rpc-invalid-request", "native-store-unsupported",
            "native-list-turns-unsupported", "native-paginated-history-unsupported",
            "native-rpc-method-unavailable", "native-pending-metadata-error", "native-thread-metadata-error",
            "native-thread-history-error", "native-thread-history-list-error", "native-full-turns-error",
            "native-full-turn-items-error", "native-stored-item-error", "native-thread-list-error",
            "native-rpc-internal-error")
HISTORY_MODES = ("unobserved", "legacy", "paginated", "unknown")
PHASES = ("private-context", "runtime-verification", "keyring-startup", "daemon-startup",
          "ordinary-native-startup", "integration-install", "native-thread-start",
          "native-uninitialized-history-probe", "native-metadata-initialization",
          "first-native-read-rpc", "first-native-read-shape", "first-native-read-identity",
          "first-native-history-path", "first-native-history-custody",
          "first-native-discovery-rpc", "first-native-discovery-identity",
          "integration-remove", "native-state-preservation", "second-native-read-rpc",
          "second-native-read-shape", "second-native-read-identity",
          "second-native-history-path", "second-native-history-custody",
          "second-native-discovery-rpc", "second-native-discovery-identity",
          "native-domain-preservation",
          "durable-owner-inspection", "ownership-uninstall")
FRAME_LIMIT = 1024 * 1024
OUTPUT_LIMIT = 4 * FRAME_LIMIT
DEADLINE_SECONDS = 180
NATIVE_FIXTURE_NAME = "omux-installed-native-fixture"


def native_require(condition: bool, failure: str, message: str):
    global FAILURE
    if not condition:
        FAILURE = failure
        raise ValueError(message)


def native_error_kind(method: str, params: dict, returned_error) -> str:
    # R-N13: pinned upstream error formats are matched only in private memory.
    # Every returned classification is a literal allowlisted above. Unknown
    # codes/messages never become diagnostics or authorize continued execution.
    if not isinstance(returned_error, dict):
        return "native-rpc-error"
    code, message = returned_error.get("code"), returned_error.get("message")
    if type(code) is not int or not isinstance(message, str):
        return "native-rpc-error"
    thread_id = params.get("threadId") if method == "thread/read" else None
    if code == -32600:
        if isinstance(thread_id, str):
            if message == "thread " + thread_id + " is not materialized yet; includeTurns is unavailable before first user message":
                return "legacy-history-unmaterialized" if HISTORY_MODE == "legacy" else "native-history-unmaterialized"
            if message == "thread not loaded: " + thread_id:
                return "native-thread-not-loaded"
            if message == "no rollout found for thread id " + thread_id:
                return "native-rollout-missing"
        if message.endswith(" requires experimentalApi capability"):
            return "native-experimental-required"
        return "native-rpc-invalid-request"
    if code == -32601:
        if message == "list_turns is not supported yet":
            return "native-list-turns-unsupported"
        if message == "paginated_history is not supported yet":
            return "native-paginated-history-unsupported"
        return "native-store-unsupported" if message.endswith(" is not supported yet") else "native-rpc-method-unavailable"
    if code == -32603:
        prefixes = (("failed to read pending thread metadata: ", "native-pending-metadata-error"),
                    ("failed to read thread: ", "native-thread-metadata-error"),
                    ("failed to list thread history: ", "native-thread-history-list-error"),
                    ("failed to load full turn items for ", "native-full-turn-items-error"),
                    ("failed to deserialize stored thread item ", "native-stored-item-error"),
                    ("failed to list threads: ", "native-thread-list-error"))
        if isinstance(thread_id, str):
            prefixes += (("failed to load thread history for thread " + thread_id + ": ", "native-thread-history-error"),
                         ("failed to load full thread turns for " + thread_id + ": ", "native-full-turns-error"))
        for prefix, failure in prefixes:
            if message.startswith(prefix):
                return failure
        return "native-rpc-internal-error"
    return "native-rpc-error"


class DiscardLog:
    """Continuously drain owned diagnostics, retaining no private text."""

    def __init__(self, stream):
        self.stream = stream
        self.exceeded = False
        self.thread = threading.Thread(target=self.drain, daemon=True)
        self.thread.start()

    def drain(self):
        count = 0
        try:
            while True:
                chunk = self.stream.read(8192)
                if not chunk:
                    break
                count += len(chunk)
                if count > OUTPUT_LIMIT:
                    self.exceeded = True
                    break
        finally:
            self.stream.close()

    def check(self):
        require(not self.exceeded, "owned diagnostic output exceeded its bound")

    def join(self):
        self.thread.join(timeout=5)
        require(not self.thread.is_alive(), "owned diagnostic drain did not finish")
        self.check()


class JsonProcess:
    """Bounded real stdio JSON client; interleaved notifications stay private."""

    def __init__(self, command: list[str], environment: dict, cwd: Path):
        self.process = subprocess.Popen(command, env=environment, cwd=cwd,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, umask=0o077)
        self.diagnostics = DiscardLog(self.process.stderr)
        self.selector = selectors.DefaultSelector()
        os.set_blocking(self.process.stdout.fileno(), False)
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.buffer = bytearray()
        self.output_bytes = 0
        self.identifier = 0

    def alive(self):
        self.diagnostics.check()
        native_require(self.process.poll() is None, "native-process-exited", "ordinary native process exited")

    def send(self, method: str, params: dict, identifier: int | None = None):
        self.alive()
        value = {"method": method, "params": params}
        if identifier is not None:
            value["id"] = identifier
        payload = json.dumps(value, separators=(",", ":")).encode() + b"\n"
        require(len(payload) <= 8192, "fixture native request exceeded its bound")
        self.process.stdin.write(payload)
        self.process.stdin.flush()

    def call(self, method: str, params: dict, timeout: float = 20) -> dict:
        global FAILURE
        FAILURE = "unclassified"
        self.identifier += 1
        identifier = self.identifier
        self.send(method, params, identifier)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.alive()
            if b"\n" in self.buffer:
                line, _, remaining = self.buffer.partition(b"\n")
                self.buffer = bytearray(remaining)
                native_require(len(line) <= FRAME_LIMIT, "native-rpc-output-limit",
                               "native JSON frame exceeded its bound")
                try:
                    value = json.loads(line)
                except (ValueError, UnicodeDecodeError):
                    FAILURE = "native-rpc-invalid-envelope"
                    raise ValueError("native JSON envelope changed") from None
                native_require(isinstance(value, dict), "native-rpc-invalid-envelope", "native JSON envelope changed")
                if value.get("id") == identifier:
                    if "error" in value:
                        native_require(False, native_error_kind(method, params, value["error"]),
                                       "native RPC predicate failed")
                    native_require(isinstance(value.get("result"), dict), "native-rpc-invalid-envelope",
                                   "native RPC predicate failed")
                    return value["result"]
                # These are genuine native notifications, not commands to the
                # fixture. No request/tool/provider replay or reply is invented.
                native_require("id" not in value, "native-rpc-unexpected-response", "unexpected native request/response")
                continue
            for key, _ in self.selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fd, 8192)
                native_require(bool(chunk), "native-process-eof", "ordinary native stdio closed")
                self.output_bytes += len(chunk)
                native_require(self.output_bytes <= OUTPUT_LIMIT, "native-rpc-output-limit",
                               "native stdio exceeded its total bound")
                self.buffer.extend(chunk)
                native_require(len(self.buffer) <= FRAME_LIMIT, "native-rpc-output-limit",
                               "native JSON frame exceeded its bound")
        FAILURE = "native-rpc-deadline"
        raise ValueError("native RPC deadline exceeded")

    def close(self, require_success: bool = False):
        try:
            self.process.stdin.close()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                stop(self.process)
            if require_success:
                require(self.process.returncode == 0, "ordinary native process did not close cleanly")
        finally:
            stop(self.process)
            self.selector.close()
            self.process.stdout.close()
            self.diagnostics.join()


def run_cli(command: list[str], environment: dict, params: dict) -> dict:
    """Drain both pipes within a byte/deadline bound, never print RPC contents."""
    process = subprocess.Popen(command, env=environment, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    selector = selectors.DefaultSelector()
    output, diagnostics = bytearray(), bytearray()
    try:
        process.stdin.write(json.dumps(params, separators=(",", ":")).encode())
        process.stdin.close()
        for stream, destination in ((process.stdout, output), (process.stderr, diagnostics)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, destination)
        deadline = time.monotonic() + 20
        while selector.get_map() and time.monotonic() < deadline:
            for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                chunk = os.read(key.fd, 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                key.data.extend(chunk)
                require(len(key.data) <= FRAME_LIMIT, "installed CLI output exceeded its bound")
        require(not selector.get_map(), "installed CLI deadline exceeded")
        process.wait(timeout=max(0.1, deadline - time.monotonic()))
        require(process.returncode == 0 and not diagnostics, "installed CLI predicate failed")
        value = json.loads(output)
        require(isinstance(value, dict) and "error" not in value
                and isinstance(value.get("result"), dict), "installed CLI response rejected")
        return value["result"]
    finally:
        stop(process)
        selector.close()
        process.stdout.close()
        process.stderr.close()


def bounded_private_session(process: subprocess.Popen) -> tuple[int, bytes, bytes]:
    """Bound output while preserving the owned group leader until cleanup.

    No poll/communicate/wait may reap this leader before group signaling. A
    live child or WNOWAIT zombie anchors its PID, preventing numeric PGID reuse.
    """
    selector = selectors.DefaultSelector()
    output, diagnostics = bytearray(), bytearray()
    deadline = time.monotonic() + DEADLINE_SECONDS
    try:
        for stream, destination in ((process.stdout, output), (process.stderr, diagnostics)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, destination)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, "installed native interoperability deadline exceeded")
            for key, _ in selector.select(min(0.1, remaining)):
                chunk = os.read(key.fd, 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                require(len(key.data) + len(chunk) <= FRAME_LIMIT,
                        "private fixture output exceeded its bound")
                key.data.extend(chunk)
        while True:
            status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if status is not None:
                require(status.si_pid == process.pid, "private session leader identity changed")
                code = status.si_status if status.si_code == os.CLD_EXITED else -status.si_status
                return code, bytes(output), bytes(diagnostics)
            require(time.monotonic() < deadline, "private session leader exit deadline exceeded")
            time.sleep(0.05)
    finally:
        selector.close()
        # R-N13/R-N11: the exact child remains unreaped here. waitid refuses an
        # already-reaped/nonchild PID; no later numeric group signal is issued.
        # This dedicated group contains only the private proof's own children.
        os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        require(os.getpgid(process.pid) == process.pid, "private process group ownership changed")
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            # The unreaped child still anchors the PID; a group containing only
            # zombies may already have no signalable members.
            pass
        process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


def private_file(path: Path, maximum: int) -> bytes:
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        information = os.fstat(stream.fileno())
        require(stat.S_ISREG(information.st_mode) and information.st_uid == os.getuid()
                and information.st_nlink == 1 and not information.st_mode & 0o077
                and information.st_size <= maximum, "native private file custody changed")
        value = stream.read(maximum + 1)
    require(len(value) <= maximum, "native private file exceeded its bound")
    return value


def check_empty_domain(value: dict):
    for field in ("sources", "accounts", "grants", "bindings", "leases"):
        require(value.get(field) == [], "provider-free fixture acquired domain authority")


def fixed_bytes(value, length: int) -> bytes:
    # Locked Stringify.zig coerces even fixed u8 arrays to strings when their
    # bytes are valid UTF-8; other byte arrays remain JSON integer arrays.
    if isinstance(value, str):
        result = value.encode("utf-8")
    else:
        require(isinstance(value, list) and all(type(byte) is int and 0 <= byte <= 255 for byte in value),
                "sealed fixed byte field changed")
        result = bytes(value)
    require(len(result) == length, "sealed fixed byte field length changed")
    return result


def history_witness(home: Path, thread: dict, *, phase_prefix: str) -> tuple[Path, tuple[int, int], bytes]:
    global PHASE
    PHASE = phase_prefix + "-path"
    value = thread.get("path")
    require(isinstance(value, str), "native persistent history did not materialize")
    path = Path(value)
    require(path.is_absolute() and path.resolve(strict=True) == path and path.is_relative_to(home),
            "native history left its private owned home")
    for parent in path.parents:
        if parent == home:
            break
        require(not parent.is_symlink(), "native history parent changed custody")
    PHASE = phase_prefix + "-custody"
    payload = private_file(path, FRAME_LIMIT)
    information = path.lstat()
    return path, (information.st_dev, information.st_ino), hashlib.sha256(payload).digest()


def inspect_native_history(home: Path, thread: dict, expected_path: Path):
    # The native process is stopped before inspecting its actual own database.
    database = home / "state_5.sqlite"
    require(database.is_file() and not database.is_symlink(), "native metadata database missing")
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as metadata:
        rows = metadata.execute("SELECT rollout_path,history_mode FROM threads WHERE id=?",
                                (thread["id"],)).fetchall()
    require(rows == [(str(expected_path), thread["historyMode"])],
            "native persisted thread/history identity changed")


def owned_endpoint(home: Path, native: JsonProcess) -> Path:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        native.alive()
        entries = list(home.glob("omux-owner-*/owner.sock"))
        require(len(entries) <= 1, "fresh native home has multiple owner endpoints")
        if entries:
            endpoint = entries[0]
            parent, information = endpoint.parent.lstat(), endpoint.lstat()
            require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid()
                    and stat.S_IMODE(parent.st_mode) == 0o700
                    and stat.S_ISSOCK(information.st_mode) and information.st_uid == os.getuid()
                    and stat.S_IMODE(information.st_mode) == 0o600
                    and len(os.fsencode(endpoint)) <= 107, "native endpoint custody changed")
            return endpoint
        time.sleep(0.05)
    raise ValueError("genuine owner endpoint unavailable")


def inspect_retirement(state: Path, thread: dict, endpoint: Path, removal_operation: str,
                       peer_witness: dict):
    # R-N13: this runs only after clean production daemon shutdown. No vault key
    # or encrypted registry is decoded, no unsealed state is written/adopted.
    with closing(sqlite3.connect((state / "state.sqlite").as_uri() + "?mode=ro", uri=True)) as metadata:
        require(metadata.execute("PRAGMA user_version").fetchone()[0] == 3, "fresh SQL schema changed")
        require(metadata.execute("SELECT count(*) FROM grants").fetchone()[0] == 0,
                "native fixture acquired encrypted credentials")
        check_sealed_snapshot(metadata, state / "state.sqlite.authority")
        encoded = metadata.execute("SELECT CAST(metadata_json AS BLOB) FROM snapshot").fetchone()[0]
    require(len(encoded) <= 16 * FRAME_LIMIT, "native sealed snapshot exceeded its bound")
    persisted = json.loads(encoded)
    check_empty_domain(persisted["state"])
    require(persisted["request_authority"]["records"] == []
            and persisted["outcome_intents"] == []
            and persisted["snapshot_admission"]["credits"] == [],
            "completed provider-free removal retained effect/request obligations")
    ledger = persisted["native_owner_authority"]
    require(len(ledger["owners"]) == len(ledger["attachments"]) == len(ledger["removals"]) == 1,
            "native custody cardinality changed")
    owner, attachment, removal = ledger["owners"][0], ledger["attachments"][0], ledger["removals"][0]
    reference = attachment["reference"]
    saved_witness = dict(owner["witness"])
    saved_witness["boot_id"] = list(fixed_bytes(saved_witness["boot_id"], 16))
    require(owner["application"] == removal["application"] == "codex"
            and owner["endpoint_path"] == str(endpoint) and owner["phase"] == "retired"
            and attachment["phase"] == "retired" and attachment["retirement"] == "verified_detach"
            and attachment["thread_id"] == thread["id"] and removal["phase"] == "retired"
            and reference["owner_id"] == owner["id"]
            and reference["adapter_epoch"] == owner["adapter_epoch"] == removal["adapter_epoch"]
            and reference["endpoint_generation"] == owner["endpoint_generation"]
            and saved_witness == peer_witness,
            "sealed original native retirement attribution changed")
    require(all(type(reference[name]) is int and reference[name] > 0 for name in
                ("adapter_epoch", "endpoint_generation", "thread_instance_generation", "attachment_generation")),
            "sealed native generations changed")
    operation = removal_operation.encode("ascii")
    require(fixed_bytes(owner["removal_operation"], 64) == fixed_bytes(removal["operation"], 64) == operation,
            "sealed global removal lost its original operation")
    registration = fixed_bytes(attachment["registration_operation"], 64)
    require(re.fullmatch(rb"[0-9a-f]{64}", registration) is not None,
            "sealed producer registration operation changed")
    digest = hashlib.sha256(b"omux.native.removal.detach.v1" + removal_operation.encode()
                            + fixed_bytes(reference["owner_id"], 32)
                            + b"".join(reference[name].to_bytes(8, "little") for name in
                                       ("adapter_epoch", "endpoint_generation", "thread_instance_generation",
                                        "attachment_generation"))).hexdigest()
    require(fixed_bytes(attachment["detach_operation"], 64) == digest.encode(),
            "sealed detach operation was not derived from the original fence/ref")
    require(persisted["adapter_epochs"][0] == reference["adapter_epoch"] + 1
            and "codex" not in persisted["installed_integrations"]
            and persisted["native_registry"]["phase"] == "removed",
            "native removal did not retire its installed generation")
    # Permanent owner/attachment records remain. Their bounded lifetime reserve
    # is not an outstanding effect credit and is deliberately not asserted zero.


def inside(bundle: Path, candidate: Path, receipt: Path, keyring: Path, root: Path):
    global PHASE, HISTORY_MODE, FAILURE
    require(os.environ.get("OMUX_ISOLATED_VAULT_PROOF") == "private-bus-private-xdg",
            "disposable genuine vault context required")
    PHASE = "runtime-verification"
    candidate_manifest, files = runtime_package.read_runtime_bundle(candidate, receipt)
    candidate_prefix = root / "candidate"
    candidate_prefix.mkdir(mode=0o700)
    for name, payload in files.items():
        destination = candidate_prefix / name
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with destination.open("xb") as stream:
            stream.write(payload)
        os.chmod(destination, 0o644 if name == "runtime-manifest.json"
                 else candidate_manifest["files"][name]["mode"])
    prefix, records, state, home, work = (root / name for name in ("installed", "records", "state", "h", "w"))
    for directory in (state, home, work):
        directory.mkdir(mode=0o700)
    codex_home = home / "c"
    codex_home.mkdir(mode=0o700)
    require(len(os.fsencode(codex_home)) <= 68, "native home exceeds bounded endpoint layout")
    config = codex_home / "config.toml"
    original = ('cli_auth_credentials_store = "file"\nsandbox_mode = "read-only"\napproval_policy = "never"\n'
                '[analytics]\nenabled = false\n[features]\nplugins = false\nrecommended_plugins = false\n'
                'apps = false\nenable_mcp_apps = false\n[projects.' + json.dumps(str(work))
                + ']\ntrust_level = "trusted"\n').encode()
    config.write_bytes(original)
    config.chmod(0o600)
    payload = pack.read_bundle(bundle)
    manifest, _ = pack.verify_bundle(payload)
    require(manifest["distribution"] == "portable-linux", "actual portable Omux archive required")
    require(manifest.get("channel") == "release", "default-instance archive required")
    record = install.install_bundle(payload, prefix, records)
    require(not record["serviceActivated"], "fixture activated a host service")
    environment = dict(os.environ)
    environment.update(HOME=str(home), CODEX_HOME=str(codex_home), PATH="/nonexistent", OMUX_INSTANCE="default")
    socket_path = Path(environment["XDG_RUNTIME_DIR"]) / (
        "omux-" + hashlib.sha256(str(state).encode()).hexdigest()[:32]) / "control.sock"
    require(len(os.fsencode(socket_path)) <= 107, "installed control path too long")
    keyring_process = daemon = native = None
    drains = []

    def cli(method: str, params: dict | None = None) -> dict:
        for drain in drains:
            drain.check()
        return run_cli([str(prefix / "bin/omux"), "--state-dir", str(state), "rpc", method, "-"],
                       environment, params or {})

    try:
        PHASE = "keyring-startup"
        keyring_process = subprocess.Popen([str(keyring), "--foreground", "--unlock", "--components=secrets"],
                                           env=environment, stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        drains.append(DiscardLog(keyring_process.stdout))
        keyring_process.stdin.write(b"\n")
        keyring_process.stdin.close()
        time.sleep(0.5)
        PHASE = "daemon-startup"
        daemon = subprocess.Popen([str(prefix / "bin/omuxd"), "--state-dir", str(state)], env=environment,
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        drains.append(DiscardLog(daemon.stdout))
        deadline = time.monotonic() + 12
        ready = False
        while time.monotonic() < deadline:
            require(daemon.poll() is None and keyring_process.poll() is None,
                    "installed custody process exited")
            if socket_path.is_socket():
                information = socket_path.lstat()
                require(information.st_uid == os.getuid() and stat.S_ISSOCK(information.st_mode)
                        and stat.S_IMODE(information.st_mode) == 0o600,
                        "installed control socket custody changed")
                health = cli("system.health")
                require(health["custody_available"] and health["protocol_version"] == 2
                        and health["live_handoff_proven"] is False, "installed custody unavailable")
                ready = True
                break
            time.sleep(0.05)
        require(ready, "installed daemon startup deadline exceeded")
        check_empty_domain(cli("state.snapshot"))
        PHASE = "ordinary-native-startup"
        native = JsonProcess([str(candidate_prefix / "bin/codex"), "app-server", "--listen", "stdio://",
                              "--strict-config"], environment, work)
        pid = native.process.pid
        native.call("initialize", {"clientInfo": {"name": "omux-native-interop", "title": None, "version": "1"},
                                   "capabilities": {"experimentalApi": False, "requestAttestation": False}})
        native.send("initialized", {})
        endpoint = owned_endpoint(codex_home, native)
        # Independent OS readback of our actual child, not construction of a
        # trusted channel. Production still captures/authenticates each writer.
        pidfd = os.pidfd_open(pid)
        try:
            information = os.fstat(pidfd)
        finally:
            os.close(pidfd)
        namespace = {}
        for name in ("user", "pid"):
            information_ns = os.stat(f"/proc/{pid}/ns/{name}")
            namespace[name] = {"device": information_ns.st_dev, "inode": information_ns.st_ino}
        with open("/proc/sys/kernel/random/boot_id", "rb") as stream:
            boot_id = stream.read(64).strip().replace(b"-", b"")
        require(re.fullmatch(rb"[0-9a-f]{32}", boot_id) is not None, "OS boot witness changed")
        peer_witness = {"profile": "linux_pidfs64_v1", "boot_id": list(bytes.fromhex(boot_id.decode("ascii"))),
                        "pidfs_device": information.st_dev, "pidfs_inode": information.st_ino,
                        "user_namespace": namespace["user"], "pid_namespace": namespace["pid"],
                        "uid": os.getuid(), "gid": os.getgid()}
        PHASE = "integration-install"
        install_operation = os.urandom(32).hex()
        installed = cli("integrations.install", {"adapter": "codex", "config_path": str(config),
                        "native_socket": str(endpoint), "operation_id": install_operation,
                        "expected_revision": cli("system.health")["revision"]})
        require(installed.get("installed") is True and installed.get("changed") is True,
                "actual native integration was not installed")
        capability = state / "integrations/codex.capability"
        require(len(private_file(capability, 128)) == 64, "installed capability custody changed")
        require(b"[omux_broker]" in private_file(config, FRAME_LIMIT), "native broker block missing")
        PHASE = "native-thread-start"
        # No turn/start, credential acquire, source import, model or tool work.
        # Real configured startup waits for daemon commit ACK before this reply.
        started = native.call("thread/start", {"cwd": str(work), "ephemeral": False})
        thread = started["thread"]
        HISTORY_MODE = thread.get("historyMode") if thread.get("historyMode") in ("legacy", "paginated") else "unknown"
        require(isinstance(thread.get("id"), str) and isinstance(thread.get("sessionId"), str)
                and thread.get("ephemeral") is False and thread.get("status", {}).get("type") == "idle",
                "ordinary persistent native thread was not ready")
        PHASE = "native-uninitialized-history-probe"
        require(HISTORY_MODE == "paginated", "candidate default history mode changed")
        try:
            native.call("thread/read", {"threadId": thread["id"], "includeTurns": True})
        except ValueError:
            require(FAILURE == "native-list-turns-unsupported",
                    "uninitialized native history rejection changed")
        else:
            raise ValueError("uninitialized native history unexpectedly succeeded")
        FAILURE = "unclassified"
        PHASE = "native-metadata-initialization"
        # R-N13: supported native metadata API flushes this actual thread's
        # pending create metadata. No SQL row, history file or ledger is seeded.
        native.call("thread/name/set", {"threadId": thread["id"], "name": NATIVE_FIXTURE_NAME})
        PHASE = "first-native-read-rpc"
        first_read = native.call("thread/read", {"threadId": thread["id"], "includeTurns": True})
        PHASE = "first-native-read-shape"
        before = first_read["thread"]
        PHASE = "first-native-read-identity"
        require(before["id"] == thread["id"] and before["sessionId"] == thread["sessionId"]
                and before["turns"] == [], "native thread/history changed before removal")
        require(before.get("name") == NATIVE_FIXTURE_NAME, "native fixture name did not persist")
        saved_history = history_witness(codex_home, before, phase_prefix="first-native-history")
        PHASE = "first-native-discovery-rpc"
        discovered = cli("integrations.discover", {"adapter": "codex", "native_socket": str(endpoint)})
        PHASE = "first-native-discovery-identity"
        require(discovered["thread_ids"] == [thread["id"]], "actual loaded thread discovery changed")
        PHASE = "integration-remove"
        removal_operation = os.urandom(32).hex()
        removed = cli("integrations.remove", {"adapter": "codex", "config_path": str(config),
                      "operation_id": removal_operation, "expected_revision": cli("system.health")["revision"]})
        require(removed.get("removed") is True and removed.get("changed") is True
                and not removed.get("pending_safe_detach", False), "actual removal lacked exact native ACK")
        PHASE = "native-state-preservation"
        native.alive()
        require(native.process.pid == pid and private_file(config, FRAME_LIMIT) == original
                and not capability.exists(), "native removal changed process/configuration custody")
        PHASE = "second-native-read-rpc"
        second_read = native.call("thread/read", {"threadId": thread["id"], "includeTurns": True})
        PHASE = "second-native-read-shape"
        after = second_read["thread"]
        PHASE = "second-native-read-identity"
        for field in ("id", "sessionId", "path", "cwd", "historyMode", "cliVersion", "source", "turns", "name"):
            require(after.get(field) == before.get(field), "native persistent state changed during removal")
        require(after.get("status", {}).get("type") == "idle", "removed native thread is no longer loaded idle")
        require(history_witness(codex_home, after, phase_prefix="second-native-history") == saved_history,
                "native history bytes/path/inode changed during removal")
        PHASE = "second-native-discovery-rpc"
        discovered_after = cli("integrations.discover", {"adapter": "codex", "native_socket": str(endpoint)})
        PHASE = "second-native-discovery-identity"
        require(discovered_after["thread_ids"]
                == [thread["id"]], "native removal unloaded the original thread")
        PHASE = "native-domain-preservation"
        check_empty_domain(cli("state.snapshot"))
        stop(daemon, require_success=True)
        daemon = None
        PHASE = "durable-owner-inspection"
        inspect_retirement(state, thread, endpoint, removal_operation, peer_witness)
        native.close(require_success=True)
        native = None
        inspect_native_history(codex_home, after, saved_history[0])
        PHASE = "ownership-uninstall"
        uninstalled = install.uninstall(prefix, records)
        require(uninstalled["preserved"] == [] and len(uninstalled["removed"]) == len(record["files"])
                and (state / "state.sqlite.authority").is_file(), "ownership uninstall changed custody state")
        print("OMUX_INSTALLED_NATIVE_INTEROP_OK")
    finally:
        cleanup = []
        if native is not None:
            cleanup.append(native.close)
        if daemon is not None:
            cleanup.append(lambda process=daemon: stop(process))
        if keyring_process is not None:
            cleanup.append(lambda process=keyring_process: stop(process))
        for drain in drains:
            cleanup.append(drain.join)
        failed = False
        for action in cleanup:
            try:
                action()
            except Exception:
                # Each independent owned child/drain is still handled. Never
                # publish an SDK/vault exception or skip later custody cleanup.
                failed = True
        require(not failed, "owned private process cleanup failed")


def main() -> int:
    if len(sys.argv) == 7 and sys.argv[1] == "--inside":
        inside(*(Path(value).resolve(strict=True) for value in sys.argv[2:]))
        return 0
    require(len(sys.argv) == 7, "declared Omux/Codex archives, receipt and vault tools required")
    bundle, candidate, receipt, session, bus, keyring = (Path(value).resolve(strict=True) for value in sys.argv[1:])
    with tempfile.TemporaryDirectory(prefix="omux-n-", dir="/tmp") as temporary:
        root = Path(temporary)
        # Allowlist rather than inherit provider/auth/proxy/key/agent settings.
        # This profile is not an OS-enforced network denial mechanism.
        environment = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/nonexistent"}
        for name, child in (("XDG_RUNTIME_DIR", "r"), ("XDG_DATA_HOME", "d"), ("XDG_CONFIG_HOME", "c"),
                            ("XDG_CACHE_HOME", "k"), ("XDG_STATE_HOME", "s")):
            directory = root / child
            directory.mkdir(mode=0o700)
            environment[name] = str(directory)
        environment["OMUX_ISOLATED_VAULT_PROOF"] = "private-bus-private-xdg"
        environment["HOME"] = str(root)
        configuration = root / "bus.conf"
        configuration.write_text('<busconfig><type>session</type><listen>unix:abstract=omux-native-' + root.name
                                 + '</listen><auth>EXTERNAL</auth><policy context="default">'
                                 '<allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/>'
                                 '</policy></busconfig>')
        bootstrap = "import os,runpy,sys;p=sys.argv.pop(1);sys.path.insert(0,os.path.dirname(p));sys.argv[0]=p;runpy.run_path(p,run_name='__main__')"
        process = subprocess.Popen([str(session), "--dbus-daemon=" + str(bus), "--config-file=" + str(configuration),
                                    "--", sys.executable, "-I", "-B", "-c", bootstrap, str(Path(__file__).absolute()),
                                    "--inside", str(bundle), str(candidate), str(receipt), str(keyring), str(root)],
                                   env=environment, start_new_session=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        code, output, diagnostics = bounded_private_session(process)
        if code == 0:
            require(output == b"OMUX_INSTALLED_NATIVE_INTEROP_OK\n", "native interoperability marker missing")
            print("OMUX_INSTALLED_NATIVE_INTEROP_OK")
        else:
            for phase in PHASES:
                marker = "installed native interoperability failed at " + phase
                if marker.encode() + b"\n" in diagnostics:
                    print(marker, file=sys.stderr)
                    break
            for failure in FAILURES:
                marker = "installed native RPC failure classification: " + failure
                if marker.encode() + b"\n" in diagnostics:
                    print(marker, file=sys.stderr)
                    break
            for mode in HISTORY_MODES:
                marker = "installed native history mode: " + mode
                if marker.encode() + b"\n" in diagnostics:
                    print(marker, file=sys.stderr)
                    break
        return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("installed native interoperability failed at " + PHASE, file=sys.stderr)
        print("installed native RPC failure classification: " + FAILURE, file=sys.stderr)
        print("installed native history mode: " + HISTORY_MODE, file=sys.stderr)
        sys.exit(1)
