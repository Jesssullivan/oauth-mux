"""Opt-in installed real Codex source enrollment; credential files stay daemon-only.

The genuine Secret Service, installed package, daemon and SQLite are disposable.
No native application runs and this receipt makes no continuity/deployment claim.
"""
from __future__ import annotations
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

import install
import pack
from test_installed_custody import bounded_private_session, check_sealed_snapshot, require, stop

PHASE = "private-context"
PHASES = ("private-context", "manifest", "keyring-startup", "install", "daemon-startup",
          "artifact-verification", "source-connect", "source-reconcile", "verified-enrollment",
          "sealed-custody", "daemon-restart", "restart-verification", "ownership-uninstall",
          "receipt", "cleanup")
MARKER = b"OMUX_INSTALLED_CODEX_LIVE_ENROLLMENT_OK\n"
MANIFEST_PATH = "/omux-live-inputs/input.json"
OUTPUT_NAME = "codex-live-enrollment-proof.json"
MAX_FRAME = 1024 * 1024
FIXED_FACTS = {
    "schema_version": 1,
    "scope": "isolated_installed_codex_source_enrollment_and_custody_restart",
    "provider": "codex",
    "identity_endpoint": "https://chatgpt.com/backend-api/wham/usage",
    "authorized_sources": 1,
    "verified_accounts": 1,
    "access_grants": 1,
    "refresh_grants": 0,
    "renewal_writer": "external",
    "installed_payload_verified": True,
    "authenticated_identity_verified": True,
    "encrypted_sqlite_custody": True,
    "sealed_snapshot_verified": True,
    "daemon_restart_verified": True,
    "grant_generation_preserved": True,
    "ciphertext_preserved": True,
    "source_contents_read_by_fixture": False,
    "native_application_launched": False,
    "sign_in_performed": False,
    "native_auth_written": False,
    "resident_user_deployment_proven": False,
    "same_process_handoff_proven": False,
    "isolated_custody_removed_after_receipt": True,
}
RECEIPT_KEYS = set(FIXED_FACTS) | {"source_handle", "account_handle", "grant_handle",
                                 "grant_generation", "installed_bundle_sha256"}


def strict_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate private JSON field")
        value[key] = item
    return value


def validate_manifest(value):
    require(isinstance(value, dict) and set(value) == {"schema_version", "authorized_source_paths"}
            and type(value["schema_version"]) is int and value["schema_version"] == 1,
            "private enrollment manifest schema differs")
    paths = value["authorized_source_paths"]
    require(isinstance(paths, list) and len(paths) == 1, "one authorized source required")
    path = paths[0]
    require(isinstance(path, str) and 0 < len(path) <= 4096 and path.startswith("/")
            and str(Path(path)) == path and os.path.normpath(path) == path
            and Path(path).name == "auth.json" and all(32 <= ord(char) < 127 for char in path),
            "authorized source selector differs")
    return value


def metadata_identity(information):
    # Reading may update atime. Custody, content and namespace identity may not.
    return (information.st_dev, information.st_ino, information.st_mode, information.st_uid,
            information.st_gid, information.st_nlink, information.st_size,
            information.st_mtime_ns, information.st_ctime_ns)


def read_manifest_namespace(root_path="/"):
    """Held destination namespace. Alternate roots are offline test models only."""
    root_fd = parent_fd = fd = None
    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        root_fd = os.open(root_path, directory_flags)
        root_before = os.fstat(root_fd)
        require(stat.S_ISDIR(root_before.st_mode) and root_before.st_uid in (0, os.getuid())
                and not stat.S_IMODE(root_before.st_mode) & 0o022,
                "manifest destination root custody differs")
        require(metadata_identity(root_before) == metadata_identity(os.stat(root_path, follow_symlinks=False)),
                "manifest destination root identity differs")
        parent_fd = os.open("omux-live-inputs", directory_flags, dir_fd=root_fd)
        parent_before = os.fstat(parent_fd)
        require(stat.S_ISDIR(parent_before.st_mode) and parent_before.st_uid in (0, os.getuid())
                and not stat.S_IMODE(parent_before.st_mode) & 0o022,
                "manifest destination parent custody differs")
        require(metadata_identity(parent_before) == metadata_identity(
                    os.stat("omux-live-inputs", dir_fd=root_fd, follow_symlinks=False)),
                "manifest destination parent identity differs")
        fd = os.open("input.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=parent_fd)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and stat.S_IMODE(before.st_mode) in (0o400, 0o600) and before.st_nlink == 1
                and 0 < before.st_size <= 65536, "private manifest custody differs")
        require(metadata_identity(before) == metadata_identity(
                    os.stat("input.json", dir_fd=parent_fd, follow_symlinks=False)),
                "private manifest named identity differs")
        raw = os.read(fd, 65537)
        require(len(raw) == before.st_size
                and metadata_identity(before) == metadata_identity(os.fstat(fd))
                == metadata_identity(os.stat("input.json", dir_fd=parent_fd, follow_symlinks=False)),
                "private manifest changed")
        require(metadata_identity(parent_before) == metadata_identity(os.fstat(parent_fd))
                == metadata_identity(os.stat("omux-live-inputs", dir_fd=root_fd, follow_symlinks=False))
                and metadata_identity(root_before) == metadata_identity(os.fstat(root_fd))
                == metadata_identity(os.stat(root_path, follow_symlinks=False)),
                "manifest destination namespace changed")
    except OSError:
        raise ValueError("private manifest namespace unavailable") from None
    finally:
        for descriptor in (fd, parent_fd, root_fd):
            if descriptor is not None:
                os.close(descriptor)
    return validate_manifest(json.loads(raw, object_pairs_hook=strict_object))


def read_manifest():
    require(os.environ.get("OMUX_CODEX_LIVE_INPUT_MANIFEST") == MANIFEST_PATH,
            "private enrollment manifest binding required")
    return read_manifest_namespace()


def handle(value):
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value),
            "daemon opaque handle differs")
    return value


def validate_receipt(value):
    require(isinstance(value, dict) and set(value) == RECEIPT_KEYS, "redacted enrollment receipt shape differs")
    require(all(type(value[key]) is type(expected) and value[key] == expected
                for key, expected in FIXED_FACTS.items()), "enrollment receipt predicates differ")
    for key in ("source_handle", "account_handle", "grant_handle", "installed_bundle_sha256"):
        handle(value[key])
    require(len({value[key] for key in ("source_handle", "account_handle", "grant_handle")}) == 3
            and type(value["grant_generation"]) is int and 0 < value["grant_generation"] < 2**63,
            "enrollment receipt authority differs")
    return value


def cli_reply(command, environment, params):
    """Bound output before parsing; private daemon refusals never become evidence."""
    process = subprocess.Popen(command, env=environment, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, umask=0o077)
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
                require(len(key.data) + len(chunk) <= MAX_FRAME, "installed CLI output limit")
                key.data.extend(chunk)
        require(not selector.get_map(), "installed CLI deadline")
        process.wait(timeout=max(0.1, deadline - time.monotonic()))
        require(process.returncode == 0 and not diagnostics, "installed CLI request refused")
        value = json.loads(output, object_pairs_hook=strict_object)
        require(isinstance(value, dict) and set(value) == {"jsonrpc", "id", "result"}
                and value["jsonrpc"] == "2.0" and isinstance(value["result"], dict),
                "installed CLI response differs")
        return value["result"]
    finally:
        selector.close()
        stop(process)
        process.stdout.close()
        process.stderr.close()


def enrollment_facts(snapshot, source_id, now):
    accounts, sources, grants, jobs = (snapshot[key] for key in ("accounts", "sources", "grants", "jobs"))
    require(len(accounts) == len(sources) == len(grants) == len(jobs) == 1,
            "isolated enrolled authority cardinality differs")
    account, source, grant, job = accounts[0], sources[0], grants[0], jobs[0]
    account_id, grant_id = handle(account["id"]), handle(grant["id"])
    require(account["identity"] == {"provider": "codex"} and account["source_ids"] == [source_id]
            and account["lifecycle"] == "active" and source["id"] == source_id
            and source["kind"] == "native_store" and source["status"] == "connected"
            and source["provider"] == "codex" and grant["account_id"] == account_id
            and grant["source_id"] == source_id and grant["credential_kind"] == "oauth_access"
            and grant["ownership"] == "external" and grant["status"] == "ready"
            and set(grant["purposes"]) == {"request", "account_read"}
            and grant["audience"] == "https://chatgpt.com"
            and type(grant["generation"]) is int and 0 < grant["generation"] < 2**63
            and (grant["provider_expires_at"] is None or grant["provider_expires_at"] > now)
            and type(grant["custody_expires_at"]) is int and grant["custody_expires_at"] > now
            and job["kind"] == "enrollment" and job["status"] == "completed"
            and not snapshot["leases"] and not snapshot["bindings"], "verified enrolled authority differs")
    return {"source_handle": source_id, "account_handle": account_id, "grant_handle": grant_id,
            "grant_generation": grant["generation"]}


def sealed_facts(state, facts):
    database = state / "state.sqlite"
    information = database.lstat()
    require(stat.S_ISREG(information.st_mode) and information.st_uid == os.getuid()
            and stat.S_IMODE(information.st_mode) == 0o600 and information.st_nlink == 1,
            "installed database custody differs")
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as metadata:
        check_sealed_snapshot(metadata, state / "state.sqlite.authority")
        rows = metadata.execute("SELECT account_id,grant_id,generation,purpose,scope,renewal_owner,state,ciphertext FROM grants").fetchall()
        require(len(rows) == 1, "sealed grant cardinality differs")
        row = rows[0]
        require(row[:7] == (facts["account_handle"], facts["grant_handle"], facts["grant_generation"],
                            "request", "https://chatgpt.com", "external", "ready")
                and type(row[7]) is bytes and 48 < len(row[7]) <= MAX_FRAME + 48
                and row[7][:8] == b"OMUXG001", "sealed access grant envelope differs")
        # Select booleans and public provider/issuer only, never raw identity IDs.
        identity = metadata.execute("SELECT json_extract(metadata_json,'$.state.accounts[0].identity.verified'),"
                                    "json_extract(metadata_json,'$.state.accounts[0].identity.provider'),"
                                    "json_extract(metadata_json,'$.state.accounts[0].identity.issuer'),"
                                    "json_array_length(metadata_json,'$.state.accounts') FROM snapshot").fetchall()
        require(identity == [(1, "codex", "https://chatgpt.com", 1)], "sealed authenticated identity differs")
        return hashlib.sha256(row[7]).digest()


def inside(bundle, keyring, root):
    global PHASE
    require(os.environ.get("OMUX_ISOLATED_VAULT_PROOF") == "private-bus-private-xdg",
            "isolated genuine vault context required")
    PHASE = "manifest"
    manifest = read_manifest()
    PHASE = "keyring-startup"
    keyring_process = subprocess.Popen([str(keyring), "--foreground", "--unlock", "--components=secrets"],
                                       stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    daemon = None
    try:
        keyring_process.stdin.write(b"\n")
        keyring_process.stdin.close()
        PHASE = "install"
        payload = pack.read_bundle(bundle)
        archive, _ = pack.verify_bundle(payload)
        require(archive["distribution"] == "portable-linux" and archive["channel"] == "release",
                "installed release portable archive required")
        prefix, records, state = root / "prefix", root / "records", root / "state"
        state.mkdir(mode=0o700)
        record = install.install_bundle(payload, prefix, records)
        require(not record["serviceActivated"], "isolated install activated service")
        environment = os.environ.copy()
        for name in list(environment):
            if name.startswith("OMUX_"):
                environment.pop(name)
        environment.pop("CODEX_HOME", None)
        environment.update(OMUX_INSTANCE="default", OMUX_INSTALL_PREFIX=str(prefix),
                           OMUX_INSTALL_RECORD=str(records / install.RECORD), PATH="/nonexistent")

        def cli(method, params=None):
            return cli_reply([str(prefix / "bin/omux"), "--state-dir", str(state), "rpc", method, "-"],
                             environment, params or {})

        def mutate(method, params):
            return cli(method, {**params, "operation_id": os.urandom(32).hex(),
                                "expected_revision": cli("system.health")["revision"]})

        def start():
            process = subprocess.Popen([str(prefix / "bin/omuxd"), "--state-dir", str(state)],
                                       env=environment, stdin=subprocess.DEVNULL,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 20
                while time.monotonic() < deadline:
                    require(process.poll() is None and keyring_process.poll() is None, "owned custody process exited")
                    try:
                        health = cli("system.health")
                        require(health["custody_available"] and health["protocol_version"] == 2,
                                "installed daemon health differs")
                        return process
                    except (ValueError, OSError, subprocess.TimeoutExpired):
                        time.sleep(0.05)
                raise ValueError("installed daemon startup deadline")
            except Exception:
                stop(process)
                raise

        def artifact():
            evidence = cli("setup.evidence")
            probe = evidence["probe"]
            require(probe["failure"] == "none" and probe["artifact"]["ownership"] == "installation_receipt"
                    and probe["artifact"]["payload"] == probe["artifact"]["running_executable"] == "matches",
                    "actual installed daemon artifact differs")

        PHASE = "daemon-startup"
        daemon = start()
        PHASE = "artifact-verification"
        artifact()
        empty = cli("state.snapshot")
        require(all(not empty[key] for key in ("accounts", "sources", "grants", "jobs", "bindings", "leases")),
                "fresh isolated authority was not empty")
        PHASE = "source-connect"
        connected = mutate("source.connect", {"kind": "native_store", "provider": "codex",
                           "source_path": manifest["authorized_source_paths"][0], "label": "Authorized Codex account"})
        source_id = handle(connected["source_id"])
        require(connected["status"] == "authorized" and connected["identity_admission"] == "verification_required",
                "source authorization overclaimed identity")
        PHASE = "source-reconcile"
        reconciliation = mutate("source.reconcile", {"source_id": source_id})
        require(reconciliation["status"] == "verifying_identity" and isinstance(reconciliation["operation_id"], str),
                "fresh source reconciliation did not submit identity verification")
        PHASE = "verified-enrollment"
        deadline = time.monotonic() + 120
        while True:
            snapshot = cli("state.snapshot")
            jobs = snapshot["jobs"]
            require(not any(job["status"] == "failed" for job in jobs), "authenticated identity verification refused")
            if snapshot["accounts"] and jobs and all(job["status"] == "completed" for job in jobs):
                facts = enrollment_facts(snapshot, source_id, int(time.time()))
                break
            require(time.monotonic() < deadline and daemon.poll() is None, "verified enrollment deadline")
            time.sleep(0.1)
        PHASE = "sealed-custody"
        stop(daemon, require_success=True)
        daemon = None
        ciphertext = sealed_facts(state, facts)
        PHASE = "daemon-restart"
        daemon = start()
        PHASE = "restart-verification"
        artifact()
        require(enrollment_facts(cli("state.snapshot"), source_id, int(time.time())) == facts,
                "daemon restart changed enrolled authority")
        # This daemon-only read authenticates retained ciphertext and compares
        # unchanged source access authority; no refresh or replacement is adopted.
        resumed = mutate("source.reconcile", {"source_id": source_id})
        require(resumed == {"operation_id": None, "status": "reconciled"}
                and enrollment_facts(cli("state.snapshot"), source_id, int(time.time())) == facts,
                "unchanged source restart created a new grant generation")
        stop(daemon, require_success=True)
        daemon = None
        require(sealed_facts(state, facts) == ciphertext, "restart changed encrypted grant bytes")
        PHASE = "ownership-uninstall"
        removed = install.uninstall(prefix, records)
        require(removed["preserved"] == [] and len(removed["removed"]) == len(record["files"]),
                "isolated installed files were not removed")
        PHASE = "receipt"
        receipt = validate_receipt({**FIXED_FACTS, **facts,
                                    "installed_bundle_sha256": hashlib.sha256(payload).hexdigest()})
        print(MARKER.decode("ascii"), end="")
        print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    finally:
        if daemon is not None:
            stop(daemon)
        stop(keyring_process)


def main():
    global PHASE
    arguments = sys.argv[1:]
    if len(arguments) == 4 and arguments[0] == "--inside":
        inside(*(Path(value).resolve(strict=True) for value in arguments[1:]))
        return 0
    require(len(arguments) == 4 and "--inside" not in arguments, "declared bundle and vault tools required")
    bundle, session, bus, keyring = (Path(value).resolve(strict=True) for value in arguments)
    PHASE = "manifest"
    read_manifest()
    receipt = None
    with tempfile.TemporaryDirectory(prefix="omux-e-", dir="/tmp") as temporary:
        root = Path(temporary)
        environment = os.environ.copy()
        for name in ("DBUS_SESSION_BUS_ADDRESS", "DBUS_STARTER_ADDRESS", "DBUS_STARTER_BUS_TYPE",
                     "GNOME_KEYRING_CONTROL", "SSH_AUTH_SOCK", "LD_PRELOAD", "LD_AUDIT", "LD_DEBUG", "CODEX_HOME"):
            environment.pop(name, None)
        for name, child in (("XDG_RUNTIME_DIR", "r"), ("XDG_DATA_HOME", "d"), ("XDG_CONFIG_HOME", "c"),
                            ("XDG_CACHE_HOME", "k"), ("XDG_STATE_HOME", "s"), ("HOME", "h")):
            directory = root / child
            directory.mkdir(mode=0o700)
            environment[name] = str(directory)
        environment["OMUX_ISOLATED_VAULT_PROOF"] = "private-bus-private-xdg"
        configuration = root / "bus.conf"
        configuration.write_text('<busconfig><type>session</type><listen>unix:abstract=omux-enrollment-' + root.name +
                                 '</listen><auth>EXTERNAL</auth><policy context="default">'
                                 '<allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/>'
                                 '</policy></busconfig>')
        bootstrap = "import os,runpy,sys;p=sys.argv.pop(1);sys.path.insert(0,os.path.dirname(p));sys.argv[0]=p;runpy.run_path(p,run_name='__main__')"
        process = subprocess.Popen([str(session), "--dbus-daemon=" + str(bus), "--config-file=" + str(configuration),
                                    "--", sys.executable, "-I", "-B", "-c", bootstrap, str(Path(__file__)),
                                    "--inside", str(bundle), str(keyring), str(root)],
                                   env=environment, start_new_session=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        code, output, diagnostics = bounded_private_session(process, deadline_seconds=240)
        if code != 0:
            for phase in PHASES:
                marker = ("installed live enrollment failed at " + phase + "\n").encode()
                if marker in diagnostics:
                    print(marker.decode("ascii"), end="", file=sys.stderr)
                    break
            return 1
        require(not diagnostics and output.startswith(MARKER) and len(output.splitlines()) == 2,
                "redacted child enrollment receipt differs")
        receipt = validate_receipt(json.loads(output[len(MARKER):], object_pairs_hook=strict_object))
    # All private source selectors, bus/vault and custody are gone before output.
    PHASE = "receipt"
    directory = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"])
    target = directory / OUTPUT_NAME
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(receipt, stream, sort_keys=True, separators=(",", ":"))
        stream.write("\n")
    print(MARKER.decode("ascii"), end="")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("installed live enrollment failed at " + (PHASE if PHASE in PHASES else "private-context"), file=sys.stderr)
        sys.exit(1)
