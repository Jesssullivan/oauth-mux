"""Actual installed two-process default native discovery, without provider work.

The production inventory selects endpoints. This fixture never supplies a
native socket or enumerates endpoints to select an owner. Returned endpoints
are checked independently against the real child processes and read-only
native responses. Installation means the actual portable package, not native
attachment: discovery must preserve the public revision/domain and authority
budgets. Sealed SQLite inspection happens only after clean daemon shutdown;
the fixture does not compare hidden metadata bytes while its writer is live.
Each process starts its own native thread. Concurrent resume of one persisted
UUID is intentionally blocked by native writer custody; this discovery fixture
does not prove same-UUID concurrency or cold resume and never seeds history.
"""
from __future__ import annotations

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

import test_installed_native_interop as shared

require = shared.require
PHASE = "private-context"
PHASES = ("private-context", "runtime-verification", "keyring-startup", "native-first-startup",
          "native-first-thread", "native-second-startup", "native-second-thread", "daemon-startup",
          "default-discovery", "owner-evidence", "stale-discovery", "unsafe-discovery",
          "restored-discovery", "custody-preservation", "durable-owner-inspection", "ownership-uninstall",
          "private-context-cleanup")
MARKER = b"OMUX_INSTALLED_NATIVE_DISCOVERY_OK\n"
OWNER_FRAME_LIMIT = 64 * 1024


def cli_reply(command: list[str], environment: dict, params: dict) -> dict:
    """Bounded installed CLI exchange that preserves typed refusal evidence."""
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
                require(len(key.data) <= shared.FRAME_LIMIT, "installed CLI output exceeded its bound")
        require(not selector.get_map(), "installed CLI deadline exceeded")
        process.wait(timeout=max(0.1, deadline - time.monotonic()))
        value = json.loads(output)
        require(isinstance(value, dict) and value.get("jsonrpc") == "2.0"
                and (("result" in value) != ("error" in value)), "installed CLI envelope changed")
        # Production main prints the redacted daemon envelope, then returns
        # ControlRequestRejected for an error. Its bounded stderr stays private;
        # the caller must match the exact daemon refusal, never arbitrary exits.
        if "error" in value:
            require(process.returncode == 1, "installed CLI refusal exit changed")
        else:
            require(process.returncode == 0 and not diagnostics, "installed CLI exchange failed")
        return value
    finally:
        shared.stop(process)
        selector.close()
        process.stdout.close()
        process.stderr.close()


def inspect_stopped_custody(state: Path, expected_revision: int):
    """Inspect sealed metadata only after the sole daemon writer has stopped.

    This proves the final empty authority state and exact checkpoint binding,
    not byte equality of private metadata before/after each live discovery.
    No wrapping key is obtained and no handwritten authority is adopted.
    """
    with closing(sqlite3.connect((state / "state.sqlite").as_uri() + "?mode=ro", uri=True)) as metadata:
        shared.check_sealed_snapshot(metadata, state / "state.sqlite.authority")
        require(metadata.execute("SELECT count(*) FROM grants").fetchone()[0] == 0,
                "discovery acquired encrypted credentials")
        revision, encoded = metadata.execute("SELECT revision,CAST(metadata_json AS BLOB) FROM snapshot").fetchone()
    require(type(encoded) is bytes and len(encoded) <= 16 * shared.FRAME_LIMIT,
            "owned metadata exceeded its bound")
    require(type(revision) is int and revision == expected_revision,
            "final sealed revision changed after read-only discovery")
    saved = json.loads(encoded)
    shared.check_empty_domain(saved["state"])
    require(saved["request_authority"]["records"] == []
            and saved["mutation_authority"]["records"] == []
            and saved["outcome_intents"] == [] and saved["snapshot_admission"]["credits"] == [],
            "read-only discovery acquired durable effect authority")
    ledger = saved["native_owner_authority"]
    require(ledger["owners"] == ledger["attachments"] == ledger["removals"] == []
            and saved["native_registry"] is None and saved["installed_integrations"] == [],
            "read-only discovery enrolled or installed native custody")


def generation(value) -> str:
    require(isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,19}", value) is not None
            and int(value) <= 2**64 - 1, "native generation is not an exact canonical u64")
    return value


def native_evidence(owner: dict, home: Path, children: dict[int, shared.JsonProcess],
                    expected_threads: dict[int, str]) -> int:
    """Independently inspect a returned locator; never feed it into discovery."""
    endpoint_value = owner.get("owner_endpoint")
    require(isinstance(endpoint_value, str), "discovered owner lacks its locator")
    endpoint = Path(endpoint_value)
    require(endpoint.is_absolute() and endpoint.is_relative_to(home)
            and endpoint.resolve(strict=True) == endpoint and len(os.fsencode(endpoint)) <= 107,
            "discovered endpoint escaped its private home")
    require(endpoint.name == "owner.sock" and endpoint.parent.parent == home
            and re.fullmatch(r"omux-owner-[0-9a-f]{16}", endpoint.parent.name) is not None,
            "discovered endpoint layout changed")
    parent, information = endpoint.parent.lstat(), endpoint.lstat()
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == os.getuid()
            and stat.S_IMODE(parent.st_mode) == 0o700 and stat.S_ISSOCK(information.st_mode)
            and information.st_uid == os.getuid() and stat.S_IMODE(information.st_mode) == 0o600
            and information.st_nlink == 1, "discovered endpoint custody changed")
    owner_id, nonce = owner.get("owner_id"), owner.get("process_nonce")
    require(isinstance(owner_id, str) and re.fullmatch(r"[0-9a-f]{64}", owner_id) is not None
            and isinstance(nonce, str) and re.fullmatch(r"[0-9a-f]{64}", nonce) is not None
            and endpoint.parent.name == "omux-owner-" + owner_id[:16], "discovered owner identity changed")
    endpoint_generation = generation(owner.get("endpoint_generation"))
    require(owner.get("support") == "compatible_hook", "discovery lost the candidate native hook")
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC) as connection:
        connection.settimeout(8)
        connection.connect(str(endpoint))
        pid, uid, gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(pid in children and uid == os.getuid() and gid == os.getgid(),
                "discovered owner is not a genuine fixture child")
        children[pid].alive()
        # This is independent expected-process evidence. Production still uses
        # its stricter pidfd/writer witness; numeric PID is never discovery authority.
        retained = os.pidfd_open(pid)
        try:
            def call(method: str, identifier: str) -> dict:
                payload = json.dumps({"jsonrpc": "2.0", "id": identifier, "method": method,
                                      "params": {"protocolVersion": 2}}, separators=(",", ":")).encode()
                require(connection.send(payload) == len(payload), "native expected-evidence packet was incomplete")
                encoded, ancillary, flags, _ = connection.recvmsg(OWNER_FRAME_LIMIT + 1, 0)
                require(encoded and len(encoded) <= OWNER_FRAME_LIMIT and not ancillary
                        and not flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC), "native evidence packet exceeded its bound")
                response = json.loads(encoded)
                require(isinstance(response, dict) and response.get("jsonrpc") == "2.0"
                        and response.get("id") == identifier and "error" not in response
                        and isinstance(response.get("result"), dict), "native evidence response rejected")
                return response["result"]

            capabilities = call("owner/capabilities", "fixture-expected-capabilities")
            threads = call("owner/threads", "fixture-expected-threads")
            for result in (capabilities, threads):
                require(result.get("protocolVersion") == 2 and result.get("ownerId") == owner_id
                        and result.get("processNonce") == nonce
                        and generation(result.get("endpointGeneration")) == endpoint_generation,
                        "production inventory disagreed with actual native identity")
            require(capabilities.get("nativeVersion") == owner.get("native_version"),
                    "production inventory changed the native version")
            actual_threads = threads.get("threads")
            rows = owner.get("threads")
            require(isinstance(actual_threads, list) and isinstance(rows, list)
                    and len(actual_threads) == len(rows) == 1,
                    "two-process fixture lost its actual loaded thread")
            actual, row = actual_threads[0], rows[0]
            require(isinstance(actual, dict) and isinstance(row, dict)
                    and actual.get("threadId") == row.get("thread_id") == expected_threads[pid]
                    and generation(actual.get("threadInstanceGeneration")) == generation(row.get("thread_instance_generation"))
                    and generation(actual.get("attachmentGeneration")) == generation(row.get("attachment_generation"))
                    and row.get("native_ref") is None,
                    "read-only discovery invented or merged native attachment authority")
            children[pid].alive()
        finally:
            os.close(retained)
    return pid


def inside(bundle: Path, candidate: Path, receipt: Path, keyring: Path, root: Path):
    global PHASE
    require(os.environ.get("OMUX_ISOLATED_VAULT_PROOF") == "private-bus-private-xdg",
            "disposable genuine vault context required")
    PHASE = "runtime-verification"
    candidate_manifest, files = shared.runtime_package.read_runtime_bundle(candidate, receipt)
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
    payload = shared.pack.read_bundle(bundle)
    manifest, _ = shared.pack.verify_bundle(payload)
    require(manifest["distribution"] == "portable-linux", "actual portable Omux archive required")
    require(manifest.get("channel") == "release", "default-instance archive required")
    record = shared.install.install_bundle(payload, prefix, records)
    require(not record["serviceActivated"], "fixture activated a host service")
    environment = dict(os.environ)
    environment.update(HOME=str(home), CODEX_HOME=str(codex_home), PATH="/nonexistent", OMUX_INSTANCE="default")
    socket_path = Path(environment["XDG_RUNTIME_DIR"]) / (
        "omux-" + hashlib.sha256(str(state).encode()).hexdigest()[:32]) / "control.sock"
    require(len(os.fsencode(socket_path)) <= 107, "installed control path too long")
    keyring_process = daemon = None
    natives, drains = [], []

    def cli(method: str, params: dict | None = None) -> dict:
        for drain in drains:
            drain.check()
        return cli_reply([str(prefix / "bin/omux"), "--state-dir", str(state), "rpc", method, "-"],
                         environment, params or {})

    def result(method: str, params: dict | None = None) -> dict:
        reply = cli(method, params)
        require("error" not in reply and isinstance(reply.get("result"), dict), "installed RPC predicate rejected")
        return reply["result"]

    def public_witness() -> dict:
        snapshot = result("state.snapshot")
        health = result("system.health")
        shared.check_empty_domain(snapshot)
        require(all(snapshot.get(field) == [] for field in
                    ("source_descriptions", "jobs", "observations", "capacity")),
                "read-only fixture acquired public domain state")
        require(snapshot.get("protocol_version") == health.get("protocol_version") == 2
                and snapshot.get("custody_available") is True and health.get("custody_available") is True
                and type(snapshot.get("revision")) is int and snapshot["revision"] == health.get("revision")
                and health.get("status") == "ready" and health.get("live_handoff_proven") is False,
                "public custody or revision changed")
        for field in ("request_authority", "mutation_authority"):
            ledger = health.get(field)
            require(isinstance(ledger, dict) and type(ledger.get("capacity")) is int
                    and ledger["capacity"] > 0 and ledger.get("remaining") == ledger["capacity"],
                    "discovery acquired public request or mutation authority")
        # captured_at is an observation timestamp, not a committed mutation.
        # Health currently exposes request/mutation budgets, not native counts;
        # the final stopped inspection checks native/admission rows directly.
        return {"snapshot": {name: value for name, value in snapshot.items() if name != "captured_at"},
                "health": health}

    def start_native() -> shared.JsonProcess:
        native = shared.JsonProcess([str(candidate_prefix / "bin/codex"), "app-server", "--listen", "stdio://",
                                     "--strict-config"], environment, work)
        natives.append(native)
        native.call("initialize", {"clientInfo": {"name": "omux-native-discovery", "title": None, "version": "1"},
                                   "capabilities": {"experimentalApi": False, "requestAttestation": False}})
        native.send("initialized", {})
        return native

    try:
        PHASE = "keyring-startup"
        keyring_process = subprocess.Popen([str(keyring), "--foreground", "--unlock", "--components=secrets"],
                                           env=environment, stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        drains.append(shared.DiscardLog(keyring_process.stdout))
        keyring_process.stdin.write(b"\n")
        keyring_process.stdin.close()
        time.sleep(0.5)
        # Both native applications are already running before daemon discovery;
        # no Omux launch wrapper, broker config, grant or native registration.
        PHASE = "native-first-startup"
        first = start_native()
        PHASE = "native-first-thread"
        thread = first.call("thread/start", {"cwd": str(work), "ephemeral": False})["thread"]
        require(isinstance(thread.get("id"), str) and thread.get("ephemeral") is False
                and thread.get("status", {}).get("type") == "idle", "ordinary native thread was not ready")
        PHASE = "native-second-startup"
        second = start_native()
        PHASE = "native-second-thread"
        second_thread = second.call("thread/start", {"cwd": str(work), "ephemeral": False})["thread"]
        require(isinstance(second_thread.get("id"), str) and second_thread["id"] != thread["id"]
                and second_thread.get("ephemeral") is False
                and second_thread.get("status", {}).get("type") == "idle",
                "second genuine owner did not start its distinct native thread")
        children = {native.process.pid: native for native in natives}
        require(len(children) == 2, "native producer process identities collapsed")
        expected_threads = {first.process.pid: thread["id"], second.process.pid: second_thread["id"]}
        PHASE = "daemon-startup"
        daemon = subprocess.Popen([str(prefix / "bin/omuxd"), "--state-dir", str(state)], env=environment,
                                  stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        drains.append(shared.DiscardLog(daemon.stdout))
        deadline = time.monotonic() + 12
        ready = False
        while time.monotonic() < deadline:
            require(daemon.poll() is None and keyring_process.poll() is None, "installed custody process exited")
            if socket_path.is_socket():
                information = socket_path.lstat()
                require(information.st_uid == os.getuid() and stat.S_ISSOCK(information.st_mode)
                        and stat.S_IMODE(information.st_mode) == 0o600, "installed control socket custody changed")
                health = result("system.health")
                require(health["custody_available"] and health["protocol_version"] == 2
                        and health["live_handoff_proven"] is False, "installed custody unavailable")
                ready = True
                break
            time.sleep(0.05)
        require(ready, "installed daemon startup deadline exceeded")
        baseline = public_witness()

        def discover(stale: int) -> dict:
            before = public_witness()
            require(before == baseline, "public state changed before read-only discovery")
            # Sole production selector: no socket argument and no fixture glob.
            found = result("integrations.discover", {"adapter": "codex"})
            require(found.get("adapter") == "codex" and found.get("installed") is False
                    and isinstance(found.get("owners"), list) and len(found["owners"]) == 2
                    and type(found.get("scanned_entries")) is int
                    and 2 + stale <= found["scanned_entries"] <= 4096
                    and type(found.get("ignored_stale_entries")) is int
                    and found["ignored_stale_entries"] == stale,
                    "default discovery lost an owner or stale classification")
            observed = {native_evidence(owner, codex_home, children, expected_threads) for owner in found["owners"]}
            require(observed == set(children) and len({owner["owner_id"] for owner in found["owners"]}) == 2
                    and len({owner["process_nonce"] for owner in found["owners"]}) == 2,
                    "default discovery merged independent native processes")
            require(public_witness() == before, "read-only discovery changed public state or authority budgets")
            return found

        PHASE = "default-discovery"
        discover(0)
        # A missing socket under an exact safe owned parent is classified as
        # stale. It is not selected as an endpoint and never creates authority.
        stale_parent = codex_home / ("omux-owner-" + os.urandom(8).hex())
        stale_parent.mkdir(mode=0o700)
        try:
            PHASE = "stale-discovery"
            discover(1)
            PHASE = "unsafe-discovery"
            stale_parent.chmod(0o755)
            before_refusal = public_witness()
            require(before_refusal == baseline, "public state changed before unsafe discovery")
            refused = cli("integrations.discover", {"adapter": "codex"})
            require("result" not in refused and refused.get("error") ==
                    {"code": -32000, "message": "UnsafeNativeInventory"},
                    "unsafe inventory produced partial success or an unrelated refusal")
            require(public_witness() == before_refusal, "unsafe discovery changed public state or authority budgets")
        finally:
            stale_parent.chmod(0o700)
            stale_parent.rmdir()
        PHASE = "restored-discovery"
        discover(0)
        PHASE = "custody-preservation"
        require(shared.private_file(config, shared.FRAME_LIMIT) == original
                and not (codex_home / "auth.json").exists()
                and not (state / "integrations/codex.capability").exists(),
                "read-only discovery changed native authorization or configuration")
        shared.check_empty_domain(result("state.snapshot"))
        require(public_witness() == baseline, "final live public state changed")
        shared.stop(daemon, require_success=True)
        daemon = None
        PHASE = "durable-owner-inspection"
        inspect_stopped_custody(state, baseline["snapshot"]["revision"])
        for native in natives:
            native.close(require_success=True)
        natives.clear()
        PHASE = "ownership-uninstall"
        uninstalled = shared.install.uninstall(prefix, records)
        require(uninstalled["preserved"] == [] and len(uninstalled["removed"]) == len(record["files"])
                and (state / "state.sqlite.authority").is_file(), "ownership uninstall changed custody state")
    finally:
        cleanup = [native.close for native in natives]
        if daemon is not None:
            cleanup.append(lambda process=daemon: shared.stop(process))
        if keyring_process is not None:
            cleanup.append(lambda process=keyring_process: shared.stop(process))
        cleanup.extend(drain.join for drain in drains)
        failed = False
        for action in cleanup:
            try:
                action()
            except Exception:
                failed = True
        require(not failed, "owned private process cleanup failed")
    # Private success is emitted only after vault/native diagnostic drains and
    # owned-process cleanup. The parent separately checks exact exit status.
    print(MARKER.decode("ascii").strip())


def main() -> int:
    global PHASE
    if len(sys.argv) == 7 and sys.argv[1] == "--inside":
        inside(*(Path(value).resolve(strict=True) for value in sys.argv[2:]))
        return 0
    require(len(sys.argv) == 7, "declared Omux/Codex archives, receipt and vault tools required")
    bundle, candidate, receipt, session, bus, keyring = (Path(value).resolve(strict=True) for value in sys.argv[1:])
    with tempfile.TemporaryDirectory(prefix="omux-d-", dir="/tmp") as temporary:
        root = Path(temporary)
        environment = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/nonexistent"}
        for name, child in (("XDG_RUNTIME_DIR", "r"), ("XDG_DATA_HOME", "d"), ("XDG_CONFIG_HOME", "c"),
                            ("XDG_CACHE_HOME", "k"), ("XDG_STATE_HOME", "s")):
            directory = root / child
            directory.mkdir(mode=0o700)
            environment[name] = str(directory)
        environment["OMUX_ISOLATED_VAULT_PROOF"] = "private-bus-private-xdg"
        environment["HOME"] = str(root)
        configuration = root / "bus.conf"
        configuration.write_text('<busconfig><type>session</type><listen>unix:abstract=omux-discovery-' + root.name
                                 + '</listen><auth>EXTERNAL</auth><policy context="default">'
                                 '<allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/>'
                                 '</policy></busconfig>')
        bootstrap = "import os,runpy,sys;p=sys.argv.pop(1);sys.path.insert(0,os.path.dirname(p));sys.argv[0]=p;runpy.run_path(p,run_name='__main__')"
        process = subprocess.Popen([str(session), "--dbus-daemon=" + str(bus), "--config-file=" + str(configuration),
                                    "--", sys.executable, "-I", "-B", "-c", bootstrap, str(Path(__file__).absolute()),
                                    "--inside", str(bundle), str(candidate), str(receipt), str(keyring), str(root)],
                                   env=environment, start_new_session=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        code, output, diagnostics = shared.bounded_private_session(process)
        if code == 0:
            require(output == MARKER, "installed discovery marker missing")
        else:
            for phase in PHASES:
                marker = "installed native discovery failed at " + phase
                if marker.encode() + b"\n" in diagnostics:
                    print(marker, file=sys.stderr)
                    break
            for failure in shared.FAILURES:
                marker = "installed native RPC failure classification: " + failure
                if marker.encode() + b"\n" in diagnostics:
                    print(marker, file=sys.stderr)
                    break
        PHASE = "private-context-cleanup"
    # TemporaryDirectory.__exit__ must also return before public success.
    # This marker still never overrides Bazel's final PASS/TIMEOUT result.
    if code == 0:
        print(MARKER.decode("ascii").strip())
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("installed native discovery failed at " + PHASE, file=sys.stderr)
        print("installed native RPC failure classification: " + shared.FAILURE, file=sys.stderr)
        sys.exit(1)
