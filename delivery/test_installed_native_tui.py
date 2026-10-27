"""Declared provider-free ordinary TUI /export, /rename and cold native resume proof.

Uses an installed daemon, genuine disposable Secret Service and the exact SDK
archive. A PTY exercises ordinary native commands; no turns, accounts, synthetic
history or guessed attachment authority are supplied. Native /export materializes
the original empty rollout before /rename; an empty export need not write Markdown.
Cold resume is a separate new native process, never evidence of same-process
account handoff or accepted nonempty history.
"""

from contextlib import closing
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import selectors
import signal
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import time

import test_installed_native_interop as support
import native_resumed_checkpoint

PHASE = "private-context"
PHASES = ("private-context", "runtime-verification", "keyring-startup", "daemon-startup",
          "bootstrap-native", "integration-install", "ordinary-tui-startup",
          "native-history-materialization", "native-rename",
          "selected-detach", "native-preservation", "ordinary-clean-exit", "cold-native-resume",
          "resumed-preservation", "resumed-detach", "durable-inspection", "owned-cleanup")
MARKER = b"OMUX_INSTALLED_NATIVE_TUI_OK\n"
FIXTURE_NAME = "omux-native-resume-fixture"
FRAME_LIMIT = 65536
OUTPUT_LIMIT = 4 * 1024 * 1024
GENERATION = re.compile(r"[1-9][0-9]{0,19}\Z")


def require(condition, message):
    # Every message is a static diagnostic; native data never enters output.
    support.require(condition, message)


def strict_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "native JSON contains duplicate keys")
        value[key] = item
    return value


def generation(value):
    require(isinstance(value, str) and GENERATION.fullmatch(value) is not None
            and int(value) <= (1 << 64) - 1, "native generation is not canonical")
    return value


def native_rpc(endpoint, method, params):
    identifier = os.urandom(32).hex()
    packet = json.dumps({"jsonrpc": "2.0", "id": identifier, "method": method,
                         "params": params}, separators=(",", ":")).encode()
    require(len(packet) <= FRAME_LIMIT, "native request exceeds packet bound")
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as channel:
        channel.settimeout(5)
        channel.connect(str(endpoint))
        require(channel.send(packet) == len(packet), "native request packet was incomplete")
        raw, _, flags, _ = channel.recvmsg(FRAME_LIMIT)
        require(raw and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), "native reply exceeds packet bound")
    value = json.loads(raw, object_pairs_hook=strict_object)
    require(isinstance(value, dict) and set(value) == {"jsonrpc", "id", "result"}
            and value["jsonrpc"] == "2.0" and value["id"] == identifier
            and isinstance(value["result"], dict), "native read-only reply envelope changed")
    return value["result"]


def status(endpoint, thread):
    value = native_rpc(endpoint, "owner/attachment/status", {"protocolVersion": 2, "threadId": thread})
    require(set(value) == {"protocolVersion", "ownerId", "processNonce", "endpointGeneration",
                          "threadId", "threadInstanceGeneration", "disposition", "nativeRef",
                          "registrationOperationId", "detachOperationId"}
            and value["protocolVersion"] == 2 and value["threadId"] == thread,
            "native attachment status shape changed")
    for field in ("ownerId", "processNonce"):
        require(isinstance(value[field], str) and re.fullmatch(r"[0-9a-f]{64}", value[field]) is not None,
                "native owner identity shape changed")
    require(endpoint.parent.name == "omux-owner-" + value["ownerId"][:16],
            "native endpoint does not match its observed owner")
    generation(value["endpointGeneration"])
    generation(value["threadInstanceGeneration"])
    require(value["disposition"] in ("unmanaged", "pending", "unresolved", "attached", "retired"),
            "native attachment disposition changed")
    reference = value["nativeRef"]
    if reference is not None:
        require(isinstance(reference, dict) and set(reference) == {"owner_id", "adapter_epoch",
                "endpoint_generation", "thread_instance_generation", "attachment_generation"}
                and reference["owner_id"] == value["ownerId"], "native committed reference shape changed")
        for field in ("adapter_epoch", "endpoint_generation", "thread_instance_generation", "attachment_generation"):
            generation(reference[field])
        require(reference["endpoint_generation"] == value["endpointGeneration"]
                and reference["thread_instance_generation"] == value["threadInstanceGeneration"],
                "native committed reference disagrees with observation")
    for field in ("registrationOperationId", "detachOperationId"):
        require(value[field] is None or (isinstance(value[field], str)
                and re.fullmatch(r"[0-9a-f]{64}", value[field]) is not None), "native operation shape changed")
    return value


class TerminalProcess:
    """Discard terminal bytes; retain only bounded terminal-query suffixes.

    The small declared --pty-exec branch acquires the terminal before exec. It
    avoids preexec_fn in this parent, which already owns output-drain threads.
    No poll/wait may reap the child before exact owned process-group cleanup.
    """

    def __init__(self, candidate, environment, cwd, resume=None, *, cli_overrides=(), popen_factory=None, failure_observer=None):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
        bootstrap = ("import os,runpy,sys;p=sys.argv.pop(1);sys.path.insert(0,os.path.dirname(p));"
                     "sys.argv[0]=p;runpy.run_path(p,run_name='__main__')")
        command = [sys.executable, "-I", "-B", "-c", bootstrap, str(Path(__file__).absolute()),
                   "--pty-exec", str(candidate), str(cwd), str(os.getpid())]
        if resume is not None:
            command.append(resume)
        if cli_overrides:
            command.extend(["--cli-overrides", json.dumps(list(cli_overrides), separators=(",", ":"))])
        self.selector = selectors.DefaultSelector()
        self.closed = False
        self.total = 0
        self.suffix = b""
        self.failure_observer = failure_observer
        try:
            os.set_blocking(self.master, False)
            self.selector.register(self.master, selectors.EVENT_READ)
            launch = subprocess.Popen if popen_factory is None else popen_factory
            self.process = launch(command, env=environment, cwd=cwd, stdin=slave,
                                            stdout=slave, stderr=slave, start_new_session=True, umask=0o077)
        except BaseException:
            self.selector.close()
            os.close(self.master)
            raise
        finally:
            os.close(slave)

    def exited(self):
        return os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)

    def pump(self, duration=0.05):
        for _, _ in self.selector.select(duration):
            try:
                packet = os.read(self.master, 8192)
            except OSError as error:
                if error.errno == errno.EIO:
                    return
                raise
            self.total += len(packet)
            require(self.total <= OUTPUT_LIMIT, "native terminal output exceeded bound")
            if self.failure_observer is not None:
                self.failure_observer.observe(packet)
            observed = self.suffix + packet
            # A terminal-emulator reply only: this never submits application
            # input or a provider prompt. Account/model output is not retained.
            if b"\x1b[6n" in observed:
                os.write(self.master, b"\x1b[1;1R")
            self.suffix = observed[-3:]

    def alive(self):
        self.pump()
        require(self.exited() is None, "ordinary native terminal exited early")

    def send(self, text):
        self.alive()
        packet = text.encode("ascii")
        require(len(packet) <= 128, "terminal fixture input exceeds bound")
        require(os.write(self.master, packet) == len(packet), "terminal fixture input was incomplete")

    def close(self, require_success=False):
        if self.closed:
            return
        info = None
        try:
            if require_success:
                self.send("/quit\r")
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    self.pump()
                    info = self.exited()
                    if info is not None:
                        break
                require(info is not None and info.si_code == os.CLD_EXITED and info.si_status == 0,
                        "ordinary native terminal did not exit cleanly")
        finally:
            # The unreaped child anchors its numeric process-group identity,
            # including on failure. Signal no host/user process group.
            os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            require(os.getpgid(self.process.pid) == self.process.pid, "owned terminal process group changed")
            try:
                os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError:
                # An unreaped zombie still anchors identity even when no
                # member remains signalable.
                pass
            self.process.wait(timeout=5)
            self.selector.close()
            os.close(self.master)
            self.closed = True


def wait_loaded(home, terminal):
    endpoint = support.owned_endpoint(home, terminal)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        terminal.alive()
        value = native_rpc(endpoint, "owner/threads", {"protocolVersion": 2})
        require(isinstance(value.get("threads"), list) and len(value["threads"]) <= 1,
                "ordinary native process exposed unexpected threads")
        if value["threads"]:
            thread = value["threads"][0].get("threadId")
            require(isinstance(thread, str) and re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", thread) is not None,
                "native thread identity shape changed")
            observed = status(endpoint, thread)
            if observed["disposition"] == "attached":
                require(observed["nativeRef"] is not None and observed["registrationOperationId"] is not None
                        and observed["detachOperationId"] is None, "native thread lacks committed attachment")
                return endpoint, thread, observed
        terminal.pump(0.05)
    raise ValueError("ordinary native attachment deadline exceeded")


def metadata(home, thread, *, expected_name=FIXTURE_NAME):
    database = home / "state_5.sqlite"
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=1)) as connection:
        rows = connection.execute("SELECT id,rollout_path,source,cwd,history_mode,cli_version,name,"
                                  "tokens_used,has_user_event FROM threads WHERE id=?", (thread,)).fetchall()
    require(len(rows) == 1, "native metadata row is absent or ambiguous")
    row = rows[0]
    require(row[0] == thread and row[6] == expected_name and row[7:] == (0, 0),
            "native metadata was not initialized provider-free")
    path = Path(row[1])
    require(path.is_absolute() and path.resolve(strict=True) == path
            and path.is_relative_to(home.resolve(strict=True)), "native rollout custody escaped selected home")
    for parent in (path, *path.parents):
        if parent == home.parent:
            break
        require(not parent.is_symlink(), "native rollout custody traversed a symlink")
    payload = support.private_file(path, 1024 * 1024)
    information = path.stat()
    # Read genuine native rollout lines; never manufacture a history row/file.
    session = []
    for line in payload.splitlines():
        item = json.loads(line, object_pairs_hook=strict_object)
        require(isinstance(item, dict), "native rollout frame changed")
        body = item.get("payload", {})
        if item.get("type") == "session_meta":
            require(isinstance(body, dict) and body.get("id") == thread
                    and body.get("session_id") == thread, "native root session identity changed")
            session.append(body)
        require(not (item.get("type") == "response_item" and isinstance(body, dict)
                     and (body.get("role") == "user" or body.get("type") in
                          ("function_call", "custom_tool_call", "function_call_output", "custom_tool_call_output"))),
                "provider-free native rollout contains user or tool work")
    require(len(session) == 1, "native session metadata is absent or ambiguous")
    return row, (information.st_dev, information.st_ino), hashlib.sha256(payload).digest(), payload


def resumed_history(before, resumed, thread):
    # Native Session::initialize_history checkpoints effective settings on
    # resume even without a turn. Preserve every original byte and allow only
    # that one explicitly typed native metadata append, never accepted work.
    require(resumed[:2] == before[:2] and resumed[3].startswith(before[3]) and before[3].endswith(b"\n"),
            "cold native resume changed original history bytes or identity")
    native_resumed_checkpoint.validate_paginated_checkpoint(
        before[3], resumed[3][len(before[3]):], thread, before[0][3])


def wait_resumed_checkpoint(home, thread, terminal, before):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        terminal.alive()
        observed = metadata(home, thread)
        # Only the exact unchanged original history is a pending checkpoint.
        # Changed identity, original bytes or unexpected appends fail promptly.
        require(observed[:2] == before[:2] and observed[3].startswith(before[3]),
                "cold native resume changed original history before checkpoint")
        if observed[3] != before[3]:
            resumed_history(before, observed, thread)
            return observed
        terminal.pump(0.05)
    raise ValueError("cold native settings checkpoint did not flush")


def process_witness(pid):
    descriptor = os.pidfd_open(pid)
    try:
        information = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    namespaces = {}
    for name in ("user", "pid"):
        item = os.stat(f"/proc/{pid}/ns/{name}")
        namespaces[name] = {"device": item.st_dev, "inode": item.st_ino}
    with open("/proc/sys/kernel/random/boot_id", "rb") as stream:
        boot = stream.read(64).strip().replace(b"-", b"")
    require(re.fullmatch(rb"[0-9a-f]{32}", boot) is not None, "OS boot witness changed")
    return {"profile": "linux_pidfs64_v1", "boot_id": list(bytes.fromhex(boot.decode("ascii"))),
            "pidfs_device": information.st_dev, "pidfs_inode": information.st_ino,
            "user_namespace": namespaces["user"], "pid_namespace": namespaces["pid"],
            "uid": os.getuid(), "gid": os.getgid()}


def wait_metadata(home, thread, terminal, *, expected_name=FIXTURE_NAME):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        terminal.alive()
        try:
            return metadata(home, thread, expected_name=expected_name)
        except (ValueError, sqlite3.OperationalError, FileNotFoundError):
            terminal.pump(0.05)
    raise ValueError("ordinary native metadata did not flush")


def detach(cli, endpoint, thread, observed):
    operation = os.urandom(32).hex()
    result = cli("integrations.detach", {"adapter": "codex", "owner_endpoint": str(endpoint),
                 "thread_id": thread, "native_ref": observed["nativeRef"], "operation_id": operation,
                 "expected_revision": cli("system.health")["revision"]})
    require(result.get("detached") is True and result.get("operation_id") == operation
            and result.get("native_ref") == observed["nativeRef"], "selected detach did not acknowledge exact reference")
    after = status(endpoint, thread)
    require(after["disposition"] == "retired" and after["nativeRef"] == observed["nativeRef"]
            and after["registrationOperationId"] == observed["registrationOperationId"]
            and after["detachOperationId"] == operation, "native selected retirement attribution changed")
    require(all(after[field] == observed[field] for field in
                ("ownerId", "processNonce", "endpointGeneration", "threadInstanceGeneration")),
            "native selected retirement changed original incarnation")
    return operation


def inspect_durable(state, observations, operations, endpoints, witnesses, thread):
    with closing(sqlite3.connect((state / "state.sqlite").as_uri() + "?mode=ro", uri=True)) as connection:
        support.check_sealed_snapshot(connection, state / "state.sqlite.authority")
        require(connection.execute("SELECT count(*) FROM grants").fetchone()[0] == 0,
                "provider-free terminal acquired encrypted credentials")
        raw = connection.execute("SELECT CAST(metadata_json AS BLOB) FROM snapshot").fetchone()[0]
    require(len(raw) <= 16 * 1024 * 1024, "sealed native snapshot exceeded bound")
    persisted = json.loads(raw, object_pairs_hook=strict_object)
    support.check_empty_domain(persisted["state"])
    require(persisted["request_authority"]["records"] == [] and persisted["outcome_intents"] == []
            and persisted["snapshot_admission"]["credits"] == [], "provider-free terminal retained request/effect obligations")
    require("codex" in persisted["installed_integrations"] and persisted["native_registry"]["phase"] == "installed",
            "selected detach removed integration configuration")
    ledger = persisted["native_owner_authority"]
    require(len(ledger["owners"]) == len(ledger["attachments"]) == 2 and ledger["removals"] == [],
            "cold resume native custody cardinality changed")
    for observed, operation, endpoint, witness in zip(observations, operations, endpoints, witnesses, strict=True):
        reference = observed["nativeRef"]
        matched = [item for item in ledger["attachments"]
                   if support.fixed_bytes(item["reference"]["owner_id"], 32).hex() == reference["owner_id"]
                   and all(str(item["reference"][key]) == reference[key] for key in reference if key != "owner_id")]
        require(len(matched) == 1 and matched[0]["phase"] == "retired"
                and matched[0]["retirement"] == "verified_detach"
                and matched[0]["thread_id"] == thread
                and support.fixed_bytes(matched[0]["registration_operation"], 64).decode("ascii") == observed["registrationOperationId"]
                and support.fixed_bytes(matched[0]["detach_operation"], 64).decode("ascii") == operation,
                "sealed exact selected detach history changed")
        owners = [item for item in ledger["owners"] if support.fixed_bytes(item["id"], 32).hex() == reference["owner_id"]
                  and str(item["adapter_epoch"]) == reference["adapter_epoch"]
                  and str(item["endpoint_generation"]) == reference["endpoint_generation"]]
        require(len(owners) == 1, "sealed original native owner is absent or ambiguous")
        owner = owners[0]
        saved_witness = dict(owner["witness"])
        saved_witness["boot_id"] = list(support.fixed_bytes(saved_witness["boot_id"], 16))
        require(owner["application"] == "codex" and owner["endpoint_path"] == str(endpoint)
                and owner["phase"] == "open" and saved_witness == witness
                and support.fixed_bytes(owner["native_nonce"], 32).hex() == observed["processNonce"],
                "sealed original native process attribution changed")


def inside(bundle, candidate, receipt, keyring, root, *, live=None):
    global PHASE
    require(os.environ.get("OMUX_ISOLATED_VAULT_PROOF") == "private-bus-private-xdg",
            "disposable genuine vault context required")
    PHASE = "runtime-verification"
    reader = getattr(live, "read_runtime_bundle", None) if live is not None else None
    candidate_manifest, files = (reader or support.runtime_package.read_runtime_bundle)(candidate, receipt)
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
                      '[cloud.skills]\nenabled = false\n'
                      '[analytics]\nenabled = false\n[features]\nplugins = false\nrecommended_plugins = false\n'
                      'apps = false\nenable_mcp_apps = false\n[projects.' + json.dumps(str(work)) + ']\ntrust_level = "trusted"\n')
    config.chmod(0o600)
    if live is not None:
        live.configure(config)
    payload = support.pack.read_bundle(bundle)
    manifest, _ = support.pack.verify_bundle(payload)
    require(manifest["distribution"] == "portable-linux", "actual portable Omux archive required")
    require(manifest.get("channel") == "release", "default-instance archive required")
    record = support.install.install_bundle(payload, prefix, records)
    require(not record["serviceActivated"], "fixture activated host service")
    environment = dict(os.environ)
    environment.update(HOME=str(home), CODEX_HOME=str(codex_home), PATH="/nonexistent", TERM="xterm-256color", OMUX_INSTANCE="default")
    socket_path = Path(environment["XDG_RUNTIME_DIR"]) / ("omux-" + hashlib.sha256(str(state).encode()).hexdigest()[:32]) / "control.sock"
    require(len(os.fsencode(socket_path)) <= 107, "installed control path too long")
    keyring_process = daemon = bootstrap_native = terminal = None
    drains = []

    def cli(method, params=None):
        for drain in drains:
            drain.check()
        return support.run_cli([str(prefix / "bin/omux"), "--state-dir", str(state), "rpc", method, "-"], environment, params or {})

    try:
        PHASE = "keyring-startup"
        keyring_process = subprocess.Popen([str(keyring), "--foreground", "--unlock", "--components=secrets"],
                                           env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, umask=0o077)
        drains.append(support.DiscardLog(keyring_process.stdout))
        keyring_process.stdin.write(b"\n")
        keyring_process.stdin.close()
        time.sleep(0.5)
        PHASE = "daemon-startup"
        daemon = subprocess.Popen([str(prefix / "bin/omuxd"), "--state-dir", str(state)], env=environment,
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, umask=0o077)
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
        if live is None:
            support.check_empty_domain(cli("state.snapshot"))
        else:
            support.check_empty_domain(cli("state.snapshot"))
            live.enroll(cli)
        PHASE = "bootstrap-native"
        # This process only supplies genuine capability inventory for initial
        # reversible setup. It creates no native thread or owner attachment.
        binary = candidate_prefix / "bin/codex"
        bootstrap_native = support.JsonProcess([str(binary), "app-server", "--listen", "stdio://", "--strict-config"], environment, work)
        bootstrap_native.call("initialize", {"clientInfo": {"name": "omux-native-tui-proof", "title": None, "version": "1"},
                               "capabilities": {"experimentalApi": False, "requestAttestation": False}})
        bootstrap_native.send("initialized", {})
        endpoint = support.owned_endpoint(codex_home, bootstrap_native)
        PHASE = "integration-install"
        installed = cli("integrations.install", {"adapter": "codex", "config_path": str(config), "native_socket": str(endpoint),
                        "operation_id": os.urandom(32).hex(), "expected_revision": cli("system.health")["revision"]})
        require(installed.get("installed") is True and installed.get("changed") is True, "genuine integration setup failed")
        configured = support.private_file(config, 1024 * 1024)
        capability_path = state / "integrations/codex.capability"
        capability = support.private_file(capability_path, 128)
        require(len(capability) == 64 and b"[omux_broker]" in configured, "installed native custody changed")
        bootstrap_native.close(require_success=True)
        bootstrap_native = None
        require(not endpoint.exists(), "bootstrap native endpoint remained after clean shutdown")
        PHASE = "ordinary-tui-startup"
        if live is not None:
            live.prepare_native_profile(binary, environment, work)
        terminal = TerminalProcess(binary, environment, work,
                                   cli_overrides=live.cli_overrides if live is not None else ())
        first_pid = terminal.process.pid
        endpoint, thread, first = wait_loaded(codex_home, terminal)
        first_endpoint, first_witness = endpoint, process_witness(first_pid)
        PHASE = "native-history-materialization"
        # Paginated zero-turn /rename only updates metadata; it cannot create
        # the rollout. The real export command hydrates history and falls back
        # to thread/read(includeTurns=true), which persists the original thread.
        # Do not seed a SessionMeta or treat empty-export Markdown as success.
        terminal.send("/export omux-native-resume-fixture.md\r")
        wait_metadata(codex_home, thread, terminal, expected_name=None)
        terminal.alive()
        require(terminal.process.pid == first_pid and status(endpoint, thread) == first,
                "native history materialization changed process or attachment authority")
        PHASE = "native-rename"
        terminal.send("/rename " + FIXTURE_NAME + "\r")
        before = wait_metadata(codex_home, thread, terminal)
        PHASE = "selected-detach"
        first_operation = detach(cli, endpoint, thread, first)
        PHASE = "native-preservation"
        terminal.alive()
        require(terminal.process.pid == first_pid and metadata(codex_home, thread) == before,
                "selected detach changed native process or persistent state")
        require(support.private_file(config, 1024 * 1024) == configured
                and support.private_file(capability_path, 128) == capability,
                "selected detach removed installed configuration")
        if live is None:
            support.check_empty_domain(cli("state.snapshot"))
        else:
            live.check_domain(cli("state.snapshot"))
        PHASE = "ordinary-clean-exit"
        terminal.close(require_success=True)
        terminal = None
        require(metadata(codex_home, thread) == before and not endpoint.exists(),
                "clean native exit changed persistent metadata")
        PHASE = "cold-native-resume"
        terminal = TerminalProcess(binary, environment, work, resume=thread,
                                   cli_overrides=live.cli_overrides if live is not None else ())
        require(terminal.process.pid != first_pid, "cold native resume reused original process")
        endpoint, resumed_thread, second = wait_loaded(codex_home, terminal)
        second_witness = process_witness(terminal.process.pid)
        require(resumed_thread == thread and second["nativeRef"] != first["nativeRef"]
                and second["ownerId"] != first["ownerId"], "cold native resume lost original thread or reused authority")
        PHASE = "resumed-preservation"
        # Native startup appends its explicit settings checkpoint. The exact
        # original byte prefix/inode and stable metadata remain preserved.
        resumed = wait_resumed_checkpoint(codex_home, thread, terminal, before)
        require(support.private_file(config, 1024 * 1024) == configured
                and support.private_file(capability_path, 128) == capability,
                "cold native resume changed retained history or configuration")
        if live is not None:
            result, completed = live.prove(cli, codex_home, thread, terminal, endpoint,
                                           second, resumed, candidate, receipt)
            # Raw encrypted native history retains the existing detach/reentry refusal.
            # Ordinary clean exit is owned cleanup, not a native-removal proof.
            terminal.alive()
            require(live.history(codex_home, thread, resumed) == completed,
                    "live completed boundary changed accepted native history")
            terminal.close(require_success=True)
            terminal = None
            require(live.history(codex_home, thread, resumed) == completed,
                    "live clean exit changed accepted native history")
            require(support.private_file(config, 1024 * 1024) == configured
                    and support.private_file(capability_path, 128) == capability,
                    "live cleanup changed installed native configuration")
            support.stop(daemon, require_success=True)
            daemon = None
            uninstalled = support.install.uninstall(prefix, records)
            require(uninstalled["preserved"] == [] and len(uninstalled["removed"]) == len(record["files"]),
                    "live owned distribution uninstall failed")
            print(live.marker.decode("ascii"), end="")
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return
        PHASE = "resumed-detach"
        second_operation = detach(cli, endpoint, thread, second)
        terminal.alive()
        require(metadata(codex_home, thread) == resumed, "resumed selected detach changed retained history")
        terminal.close(require_success=True)
        terminal = None
        require(metadata(codex_home, thread) == resumed, "resumed clean exit changed retained history")
        require(support.private_file(config, 1024 * 1024) == configured
                and support.private_file(capability_path, 128) == capability,
                "resumed selected detach removed installed configuration")
        if live is None:
            support.check_empty_domain(cli("state.snapshot"))
        else:
            live.check_domain(cli("state.snapshot"))
        support.stop(daemon, require_success=True)
        daemon = None
        PHASE = "durable-inspection"
        inspect_durable(state, [first, second], [first_operation, second_operation],
                        [first_endpoint, endpoint], [first_witness, second_witness], thread)
        PHASE = "owned-cleanup"
        uninstalled = support.install.uninstall(prefix, records)
        require(uninstalled["preserved"] == [] and len(uninstalled["removed"]) == len(record["files"]),
                "owned distribution uninstall failed")
        print(MARKER.decode("ascii"), end="")
    finally:
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
        require(not failed, "owned private terminal process cleanup failed")


def main():
    if len(sys.argv) >= 5 and sys.argv[1] == "--pty-exec":
        binary, cwd = (Path(value).resolve(strict=True) for value in sys.argv[2:4])
        # The PTY needs a separate controlling-terminal session. Bind its
        # lifetime to the exact parent in the kernel so the outer private-bus
        # deadline cannot orphan this separate group if Python is killed.
        parent = int(sys.argv[4])
        require(os.getppid() == parent, "native terminal parent changed before binding")
        libc = ctypes.CDLL(None, use_errno=True)
        prctl = libc.prctl
        prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
        prctl.restype = ctypes.c_int
        require(prctl(1, signal.SIGKILL, 0, 0, 0) == 0 and os.getppid() == parent,
                "native terminal parent-death binding failed")
        fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        os.chdir(cwd)
        command = [str(binary)]
        extra = sys.argv[5:]
        if extra and extra[0] != "--cli-overrides":
            require(re.fullmatch(r"[0-9a-f-]{36}", extra[0]) is not None, "native resume identity changed")
            command.extend(["resume", extra.pop(0)])
        if extra:
            require(len(extra) == 2 and extra[0] == "--cli-overrides", "native text profile flags differ")
            overrides = json.loads(extra[1], object_pairs_hook=strict_object)
            require(isinstance(overrides, list) and len(overrides) == 3
                    and overrides[:2] == ['omux_broker.context_mode="text_transcript_v1"',
                                          'model_reasoning_summary="none"']
                    and re.fullmatch(r'model_reasoning_effort="(?:none|minimal|low|medium|high|xhigh|max|ultra|persistent)"',
                                     overrides[2]) is not None,
                    "native text profile flags differ")
            for value in overrides:
                command.extend(["-c", value])
        command.extend(["--no-alt-screen", "--strict-config"])
        os.execve(str(binary), command, os.environ)
    if len(sys.argv) == 7 and sys.argv[1] == "--inside":
        inside(*(Path(value).resolve(strict=True) for value in sys.argv[2:]))
        return 0
    require(len(sys.argv) == 7, "declared Omux/native archives, receipt and vault tools required")
    bundle, candidate, receipt, session, bus, keyring = (Path(value).resolve(strict=True) for value in sys.argv[1:])
    with tempfile.TemporaryDirectory(prefix="omux-t-", dir="/tmp") as temporary:
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
        process = subprocess.Popen([str(session), "--dbus-daemon=" + str(bus), "--config-file=" + str(configuration),
                                    "--", sys.executable, "-I", "-B", "-c", bootstrap, str(Path(__file__).absolute()),
                                    "--inside", str(bundle), str(candidate), str(receipt), str(keyring), str(root)],
                                   env=environment, start_new_session=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, umask=0o077)
        code, output, diagnostics = support.bounded_private_session(process)
        if code == 0:
            require(output == MARKER, "ordinary native terminal proof marker missing")
            print(MARKER.decode("ascii"), end="")
        else:
            for phase in PHASES:
                marker = "installed native terminal proof failed at " + phase
                if marker.encode() + b"\n" in diagnostics:
                    print(marker, file=sys.stderr)
                    break
        return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("installed native terminal proof failed at " + PHASE, file=sys.stderr)
        sys.exit(1)
