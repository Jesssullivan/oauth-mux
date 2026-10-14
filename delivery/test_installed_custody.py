"""Production portable executables with disposable genuine Secret Service.

Runs only as the declared Bazel installed_custody_test. This proves manual
process installation/custody and restart, not OS-service activation or handoff.
No sources, accounts, native application stores or provider IO are authorized.
The explicit --core-only lane omits Qt and has its own success marker; it proves
CLI transport/custody only. Neither lane proves locked-vault recovery, backup
restoration or forget tombstones.
"""
from __future__ import annotations

from contextlib import closing
import hashlib
import json
import os
import re
import selectors
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import install
import pack

PHASE = "private-context"
FAULT = "unclassified"
SUBPHASE = "unclassified"
READINESS_REASON = "unclassified"
PROBE_FAILURE = "unclassified"
PROBE_FAILURES = ("none", "receipt_absent", "invalid_receipt", "unsafe_path", "unsafe_file", "changed_file",
                  "limit_exceeded", "read_failed", "metadata_unavailable", "timed_out", "cancelled",
                  "resource_exhausted", "invalid_deadline")
READINESS_REASONS = ("ready", "observation_unknown", "observation_stale", "evidence_unobserved",
                     "synthetic_only", "native_evidence_missing", "channel_unknown", "channel_mismatch",
                     "missing", "pending", "incompatible", "vault_locked", "vault_key_lost",
                     "vault_key_unavailable", "vault_access_denied", "vault_unavailable",
                     "authority_expired", "browser_required", "native_unsupported")
SUBPHASES = ("readiness-command", "readiness-shared-result", "readiness-claims", "readiness-phases",
             "readiness-artifact", "readiness-service", "readiness-vault", "readiness-source",
             "readiness-identity", "readiness-grant", "readiness-native", "setup-plan-command",
             "setup-plan-fields", "setup-plan-actions", "setup-evidence-command", "setup-evidence-fields",
             "setup-evidence-artifact", "setup-evidence-observed", "setup-daemon-survival")
FAULTS = ("Missing", "Locked", "Denied", "Cancelled", "Unavailable", "InvalidKey", "Conflict",
          "BackendFailure", "InvalidRoot", "UnsafePrivatePath", "UnsafePathOwner", "UnsafePathPermissions",
          "PathOpenFailed", "SocketPathTooLong", "UnsafeRecoveryDirectory", "KeyMismatch", "CurlFailure",
          "RecoveryAuthenticationFailed", "RecoveryAuthorityUnavailable", "MissingSchema", "MissingSnapshot",
          "loader-library-unavailable", "loader-symbol-unavailable", "startup-deadline-vault-pending",
          "startup-deadline-database-created", "startup-deadline-sockets-created", "keyring-exited",
          "daemon-segmentation-fault", "daemon-aborted", "daemon-other-exit")
PUBLIC_EVIDENCE_LIMIT = 8192
PUBLIC_MEMBERS = ("bin/omux", "bin/omuxd", "lib/omux/libexec/omux.bin", "lib/omux/libexec/omuxd.bin")
PUBLIC_DIGEST_FIELDS = ("safe_refusal_terminal", "verification_completed_terminal", "samples_before_refusal",
                        "samples_after_refusal", "samples_after_completion", "selected_status_reply_before_restart",
                        "selected_status_reply_after_restart", "selected_refresh_reply_before_restart",
                        "selected_refresh_reply_after_restart")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def public_evidence_line(receipt: dict, core_only: bool) -> str:
    """Allow only this fixture's finite public tuple, never arbitrary child output."""
    require(type(receipt) is dict and set(receipt) == {
        "schema_version", "kind", "lane", "capture_point", "caller_source_binding", "fixture_source_sha256",
        "archive_sha256", "archive_bytes", "manifest_sha256", "manifest_bytes", "artifact_target",
        "artifact_distribution", "artifact_channel", "artifact_status", "raw_source_revision", "raw_source_revision_present",
        "raw_source_dirty", "installed_members", "observed_artifact", "verification"},
        "installed public evidence shape changed")
    require(type(receipt["schema_version"]) is int and receipt["schema_version"] == 1
            and receipt["kind"] == "installed_private_custody_public_evidence"
            and receipt["lane"] == ("core_only" if core_only else "full_qt")
            and receipt["capture_point"] == "checked_restart_and_rollback_before_owned_uninstall"
            and receipt["caller_source_binding"] == "enclosing_guard_receipt_only"
            and receipt["artifact_target"] in {"x86_64-linux", "aarch64-linux"}
            and receipt["artifact_status"] == "experimental"
            and receipt["artifact_distribution"] == "portable-linux" and receipt["artifact_channel"] == "release",
            "installed public evidence scope changed")
    for name in ("fixture_source_sha256", "archive_sha256", "manifest_sha256"):
        require(type(receipt[name]) is str and re.fullmatch(r"[0-9a-f]{64}", receipt[name]) is not None,
                "installed public evidence digest changed")
    for name in ("archive_bytes", "manifest_bytes"):
        require(type(receipt[name]) is int and 0 < receipt[name] <= pack.MAX_BYTES,
                "installed public evidence byte bound changed")
    require(type(receipt["raw_source_dirty"]) is bool and type(receipt["raw_source_revision_present"]) is bool
            and (receipt["raw_source_revision"] is None or type(receipt["raw_source_revision"]) is str
                 and re.fullmatch(r"[0-9a-f]{40,64}", receipt["raw_source_revision"]) is not None)
            and (receipt["raw_source_revision_present"] or receipt["raw_source_revision"] is None),
            "installed raw public source fields changed")
    members = receipt["installed_members"]
    require(type(members) is dict and set(members) == set(PUBLIC_MEMBERS),
            "installed public member set changed")
    for member in members.values():
        require(type(member) is dict and set(member) == {"sha256", "bytes", "format", "matches_verified_archive"}
                and type(member["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", member["sha256"]) is not None
                and type(member["bytes"]) is int and 4 <= member["bytes"] <= pack.MAX_BYTES
                and member["format"] == "elf" and member["matches_verified_archive"] is True,
                "installed public member facts changed")
    require(receipt["observed_artifact"] == {"ownership": "installation_receipt", "payload": "matches",
                                             "running_executable": "matches",
                                             "scope": "checked_selected_startup_before_final_restart"},
            "installed observed artifact facts changed")
    verification = receipt["verification"]
    require(type(verification) is dict and set(verification) == {
        "refusal_schema_version", "completion_schema_version", "safe_refusal_count_delta",
        "verification_completed_count_delta", "installation_success_measured", "end_to_end_latency_measured",
        "achieved_slo", "digests"}
        and type(verification["refusal_schema_version"]) is int and verification["refusal_schema_version"] == 2
        and type(verification["completion_schema_version"]) is int and verification["completion_schema_version"] in {1, 2}
        and type(verification["safe_refusal_count_delta"]) is int and verification["safe_refusal_count_delta"] == 1
        and type(verification["verification_completed_count_delta"]) is int
        and verification["verification_completed_count_delta"] == 1
        and verification["installation_success_measured"] is False
        and verification["end_to_end_latency_measured"] is False and verification["achieved_slo"] is False,
        "installed verification evidence scope changed")
    digests = verification["digests"]
    require(type(digests) is dict and set(digests) == set(PUBLIC_DIGEST_FIELDS)
            and all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None
                    for value in digests.values()), "installed verification evidence digests changed")
    require(digests["selected_status_reply_before_restart"] == digests["selected_status_reply_after_restart"]
            and digests["selected_refresh_reply_before_restart"] == digests["selected_refresh_reply_after_restart"],
            "installed public restart digests changed")
    encoded = json.dumps(receipt, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    require(len(encoded.encode("ascii")) <= PUBLIC_EVIDENCE_LIMIT, "installed public evidence exceeded its bound")
    return encoded


def stop(process: subprocess.Popen, require_success: bool = False) -> None:
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    if require_success:
        require(process.returncode == 0, "installed daemon did not shut down cleanly")


def bounded_private_session(process: subprocess.Popen, deadline_seconds: float = 90) -> tuple[int, bytes, bytes]:
    """Keep the owned leader unreaped until its private group is cleaned up.

    A live child or WNOWAIT zombie anchors the numeric PID/PGID on success,
    timeout and output failure. No poll/communicate/wait occurs before killpg.
    """
    selector = selectors.DefaultSelector()
    output, diagnostics = bytearray(), bytearray()
    deadline = time.monotonic() + deadline_seconds
    try:
        for stream, destination in ((process.stdout, output), (process.stderr, diagnostics)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, destination)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, "installed custody proof exceeded bounded execution")
            for key, _ in selector.select(min(0.1, remaining)):
                chunk = os.read(key.fd, 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                require(len(key.data) + len(chunk) <= 256 * 1024,
                        "installed custody fixture output exceeded its bound")
                key.data.extend(chunk)
        while True:
            status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if status is not None:
                require(status.si_pid == process.pid, "private custody leader identity changed")
                code = status.si_status if status.si_code == os.CLD_EXITED else -status.si_status
                return code, bytes(output), bytes(diagnostics)
            require(time.monotonic() < deadline, "private custody leader exit deadline exceeded")
            time.sleep(0.05)
    finally:
        selector.close()
        # waitid rejects an already reaped/nonchild PID. The still-owned child
        # prevents reuse, and its dedicated session contains only fixture work.
        os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        require(os.getpgid(process.pid) == process.pid, "private custody process group ownership changed")
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass  # An anchored zombie-only group can have no signalable members.
        process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


def check_sealed_snapshot(metadata: sqlite3.Connection, authority: Path) -> None:
    # R-N13: inspect only this disposable fixture's owned public record shape.
    # Exact v2 encoding follows src/recovery.zig. Python neither obtains the
    # vault key nor authenticates the MAC; production startup does that itself.
    with os.fdopen(os.open(authority, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        information = os.fstat(stream.fileno())
        require(stat.S_ISREG(information.st_mode) and information.st_uid == os.getuid()
                and stat.S_IMODE(information.st_mode) == 0o600 and information.st_nlink == 1
                and information.st_size == 152, "installed authority record custody/size changed")
        encoded = stream.read(153)
    require(len(encoded) == 152 and encoded[:8] == b"OMUXR002",
            "installed authority is not the exact sealed v2 record")
    snapshots = metadata.execute("SELECT revision,CAST(metadata_json AS BLOB) FROM snapshot").fetchall()
    checkpoints = metadata.execute(
        "SELECT installation,sequence,nonce,snapshot_revision,snapshot_digest FROM recovery_checkpoint"
    ).fetchall()
    require(len(snapshots) == 1 and len(checkpoints) == 1, "installed snapshot/checkpoint cardinality changed")
    revision, snapshot = snapshots[0]
    installation, sequence, nonce, sealed_revision, digest = checkpoints[0]
    require(type(revision) is int and 0 <= revision <= 2**63 - 1
            and type(sequence) is int and 0 <= sequence <= 2**63 - 1
            and type(sealed_revision) is int and 0 <= sealed_revision <= 2**63 - 1
            and type(snapshot) is bytes and len(snapshot) <= 16 * 1024 * 1024
            and type(installation) is bytes and len(installation) == 32
            and type(nonce) is bytes and len(nonce) == 32
            and type(digest) is bytes and len(digest) == 32,
            "installed sealed checkpoint fields changed")
    require(encoded[8:40] == installation and int.from_bytes(encoded[40:48], "little") == sequence
            and encoded[48:80] == nonce and int.from_bytes(encoded[80:88], "little") == revision == sealed_revision
            and encoded[88:120] == digest == hashlib.sha256(snapshot).digest(),
            "installed authority does not bind exact snapshot bytes and revision")


def inside(bundle: Path, keyring: Path, root: Path, core_only: bool = False) -> None:
    global PHASE
    PHASE = "keyring-startup"
    # The bus, HOME and every XDG directory belong to this disposable namespace;
    # all Omux state paths are explicit and no ambient user profile is opened.
    require(os.environ.get("OMUX_ISOLATED_VAULT_PROOF") == "private-bus-private-xdg",
            "isolated custody context is required")
    keyring_output = tempfile.TemporaryFile(dir=root)
    keyring_process = subprocess.Popen(
        [str(keyring), "--foreground", "--unlock", "--components=secrets"],
        stdin=subprocess.PIPE, stdout=keyring_output, stderr=keyring_output,
    )
    keyring_process.stdin.write(b"\n")
    keyring_process.stdin.close()
    prefix, records, state = root / "installed prefix", root / "records", root / "state"
    state.mkdir(mode=0o700)
    payload = pack.read_bundle(bundle)
    manifest, archive_files = pack.verify_bundle(payload)
    require(manifest["distribution"] == "portable-linux", "Linux portable archive required")
    require(manifest.get("channel") == "release", "default-instance archive required")
    if not core_only:
        require("bin/omux-control" in archive_files, "full installed product requires Qt controls")
    record = install.install_bundle(payload, prefix, records)
    require(not record["serviceActivated"], "installer activated a service")
    environment = os.environ.copy()
    for name in ("OMUX_INSTALL_PREFIX", "OMUX_INSTALL_RECORD", "OMUX_INSTALL_SERVICE_PATH",
                 "OMUX_INSTALL_SERVICE_RECORD"):
        environment.pop(name, None)
    environment["OMUX_INSTANCE"] = "default"
    environment["PATH"] = "/nonexistent"
    environment["QT_QPA_PLATFORM"] = "offscreen"
    runtime = Path(environment["XDG_RUNTIME_DIR"])
    socket_path = runtime / ("omux-" + hashlib.sha256(str(state).encode()).hexdigest()[:32]) / "control.sock"
    require(len(os.fsencode(socket_path)) <= 107, "fixture socket path exceeds Linux limit")
    daemon_output = tempfile.TemporaryFile(dir=root)
    daemon_process = None
    gui_process = None

    def cli_response(method: str, params: dict | None = None, alias: str = "omux") -> tuple[dict, bytes]:
        completed = subprocess.run(
            [str(prefix / "bin" / alias), "--state-dir", str(state), "rpc", method, "-"],
            input=json.dumps(params or {}, separators=(",", ":")).encode(),
            capture_output=True, env=environment, timeout=12,
        )
        require(completed.returncode == 0, "installed CLI request failed")
        require(completed.stderr == b"", "installed CLI emitted diagnostics")
        value = json.loads(completed.stdout)
        require("result" in value and "error" not in value, "installed CLI response was rejected")
        return value["result"], completed.stdout

    def cli(method: str, params: dict | None = None, alias: str = "omux") -> dict:
        return cli_response(method, params, alias)[0]

    def start() -> subprocess.Popen:
        global FAULT
        process = subprocess.Popen([str(prefix / "bin/omuxd"), "--state-dir", str(state)],
                                   stdin=subprocess.DEVNULL, stdout=daemon_output,
                                   stderr=daemon_output, env=environment)
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if process.poll() is not None:
                daemon_output.seek(0)
                diagnostic = daemon_output.read(256 * 1024)
                FAULT = next((name for name in FAULTS if ("error: " + name + "\n").encode() in diagnostic), "unclassified")
                tag = re.search(rb"(?:^|\n)error: ([A-Z][A-Za-z0-9]{0,63})(?:\n|$)", diagnostic)
                if tag is not None:
                    FAULT = tag[1].decode("ascii")
                if b"error while loading shared libraries:" in diagnostic:
                    FAULT = "loader-library-unavailable"
                elif b"undefined symbol:" in diagnostic:
                    FAULT = "loader-symbol-unavailable"
                if FAULT == "unclassified":
                    FAULT = ("daemon-segmentation-fault" if process.returncode == -signal.SIGSEGV else
                             "daemon-aborted" if process.returncode == -signal.SIGABRT else
                             "daemon-other-exit")
                raise ValueError("installed daemon failed startup")
            if socket_path.is_socket():
                try:
                    value = cli("system.health")
                    require(value["custody_available"] and value["protocol_version"] == 2,
                            "installed daemon custody/protocol unavailable")
                    metadata = socket_path.lstat()
                    require(metadata.st_uid == os.getuid() and stat.S_IMODE(metadata.st_mode) == 0o600,
                            "installed control socket was not privately owned")
                    return process
                except (ValueError, OSError, subprocess.TimeoutExpired):
                    pass
            time.sleep(0.05)
        stop(process)
        FAULT = ("keyring-exited" if keyring_process.poll() is not None else
                 "startup-deadline-sockets-created" if socket_path.is_socket() else
                 "startup-deadline-database-created" if (state / "state.sqlite").is_file() else
                 "startup-deadline-vault-pending")
        raise ValueError("installed daemon did not become ready")

    def snapshot_count() -> int:
        exported = cli("reliability.export")
        metric = exported["metrics"].index("control_request")
        operation = exported["operations"].index("snapshot")
        cell = exported["cells"][metric][operation]
        return cell["good"] + cell["bad"]

    def setup_command(arguments: list[str], expected_pid: int) -> dict:
        require(daemon_process is not None and daemon_process.pid == expected_pid
                and daemon_process.poll() is None, "daemon changed before installed setup inspection")
        completed = subprocess.run(
            [str(prefix / "bin/omux"), "--state-dir", str(state), *arguments],
            stdin=subprocess.DEVNULL, capture_output=True, env=environment, timeout=12,
        )
        require(completed.returncode == 0 and completed.stderr == b"",
                "installed setup command failed or emitted diagnostics")
        envelope = json.loads(completed.stdout)
        require(isinstance(envelope, dict) and "result" in envelope and "error" not in envelope,
                "installed setup command returned a rejected envelope")
        require(daemon_process.pid == expected_pid and daemon_process.poll() is None,
                "installed CLI exit stopped or replaced the daemon")
        return envelope["result"]

    def verification_facts(summary: dict) -> dict:
        # UTC midnight may move the reporting window during this bounded run.
        # Every counter, phase, timing and claim field must remain exact.
        require("window_start_utc_s" in summary, "verification summary omitted UTC window")
        return {name: value for name, value in summary.items() if name != "window_start_utc_s"}

    def sealed_verification_results(metadata: sqlite3.Connection, expected_results: tuple[dict, ...]) -> dict[str, bytes]:
        check_sealed_snapshot(metadata, authority)
        raw_snapshot = metadata.execute("SELECT CAST(metadata_json AS BLOB) FROM snapshot").fetchone()[0]
        require(type(raw_snapshot) is bytes and len(raw_snapshot) <= 16 * 1024 * 1024,
                "installed verification snapshot exceeded bounded metadata shape")
        saved = json.loads(raw_snapshot)
        terminals = {}
        for expected in expected_results:
            matching = [entry for entry in saved["mutation_authority"]["records"]
                        if (entry["id"][:entry["id_len"]] if isinstance(entry["id"], str)
                            else bytes(entry["id"][:entry["id_len"]]).decode("ascii")) == expected["operation_id"]]
            require(len(matching) == 1 and matching[0]["state"] == "completed",
                    "sealed installed verification terminal record missing or ambiguous")
            terminal = matching[0]["result"]
            require(isinstance(terminal, str) and len(terminal.encode()) == matching[0]["result_len"]
                    and matching[0]["result_len"] <= 1024 and json.loads(terminal) == expected,
                    "sealed installed verification result differs from acknowledged terminal facts")
            terminals[expected["operation_id"]] = terminal.encode()
        return terminals

    def check_installed_setup(expected_pid: int, selected: bool = False) -> None:
        global SUBPHASE, READINESS_REASON, PROBE_FAILURE
        # A selected receipt is collected synchronously at daemon startup.
        # Neither manual launch proves OS-service activation or account use.
        READINESS_REASON = "unclassified"
        PROBE_FAILURE = "unclassified"
        SUBPHASE = "readiness-command"
        readiness = setup_command(["readiness"], expected_pid)
        SUBPHASE = "readiness-shared-result"
        require(readiness == cli("setup.readiness"), "installed readiness differs from shared daemon result")
        SUBPHASE = "readiness-claims"
        require(readiness.get("schema_version") == 1 and readiness.get("ready") is False
                and readiness.get("seamless_handoff_proven") is False,
                "installed readiness overclaimed product or continuity readiness")
        findings = readiness.get("findings", [])
        SUBPHASE = "readiness-phases"
        require(len(findings) == 7 and {row["phase"] for row in findings}
                == {"artifact", "service", "vault", "source", "identity", "grant", "native"},
                "installed readiness lost independent phases")
        rows = {row["phase"]: row for row in findings}
        for phase, expected in (("artifact", "ready" if selected else "observation_unknown"),
                                ("service", "observation_unknown"), ("vault", "ready"),
                                ("source", "missing"), ("identity", "pending"), ("grant", "missing"),
                                ("native", "missing")):
            SUBPHASE = "readiness-" + phase
            READINESS_REASON = "unclassified"
            if rows[phase]["reason"] in READINESS_REASONS:
                READINESS_REASON = rows[phase]["reason"]
            if phase == "artifact" and rows[phase]["reason"] != expected:
                # A read-only diagnostic explains collector failure without
                # exposing receipts, paths, provider metadata or response bytes.
                observed_failure = cli("setup.evidence")["probe"]["failure"]
                if observed_failure in PROBE_FAILURES:
                    PROBE_FAILURE = observed_failure
            require(rows[phase]["reason"] == expected,
                    "installed readiness collapsed custody into acquisition or native capability")
        require(rows["native"]["action"] == "install_native_adapter",
                "unconfigured installed fixture lost actionable native adapter gap")
        SUBPHASE = "setup-plan-command"
        plan = setup_command(["setup"], expected_pid)
        SUBPHASE = "setup-plan-fields"
        require(plan == cli("setup.plan") and plan.get("schema_version") == 1
                and plan.get("ownership") == ("installation_receipt" if selected else "unknown")
                and len(plan.get("plans", [])) == 4,
                "installed setup plan inferred unobserved installation ownership")
        SUBPHASE = "setup-plan-actions"
        require(all(row["action"] == ("receipt_install" if selected else "inspect_ownership")
                    and row["activation_observed"] is False
                    and row["overwrite_declarative_files"] is False for row in plan["plans"]),
                "installed setup plan permitted declarative overwrite or claimed activation")
        SUBPHASE = "setup-evidence-command"
        evidence = setup_command(["setup", "evidence"], expected_pid)
        SUBPHASE = "setup-evidence-fields"
        require(evidence == cli("setup.evidence") and evidence.get("schema_version") == 1
                and evidence.get("provider_access") is False and evidence.get("refresh_pending") is False
                and evidence.get("refresh_required") is (not selected),
                "installed evidence inspection accessed providers or manufactured freshness")
        artifact = evidence["probe"]["artifact"]
        SUBPHASE = "setup-evidence-artifact"
        require(artifact["ownership"] == ("installation_receipt" if selected else "unknown")
                and artifact["channel"] == ("release" if selected else "unknown")
                and all(artifact[name] == ("matches" if selected else "unknown")
                        for name in ("payload", "running_executable", "ownership_record"))
                and artifact["freshness"] == ("current" if selected else "unknown"),
                "installed setup evidence did not match actual receipt selection and witness")
        SUBPHASE = "setup-evidence-observed"
        if selected:
            require(evidence["probe"]["failure"] == "none" and type(evidence["observed_at"]) is int,
                    "selected startup did not collect fresh receipt-backed evidence")
        else:
            require(evidence["observed_at"] is None, "unselected startup invented observation time")
        SUBPHASE = "setup-daemon-survival"
        require(daemon_process.pid == expected_pid and daemon_process.poll() is None,
                "daemon did not survive all installed setup CLI exits")
        SUBPHASE = "unclassified"
        READINESS_REASON = "unclassified"
        PROBE_FAILURE = "unclassified"

    try:
        # Private keyring bus acquisition may race its initial registration.
        time.sleep(0.5)
        PHASE = "initial-daemon-startup"
        daemon_process = start()
        PHASE = "installed-cli-readiness"
        check_installed_setup(daemon_process.pid)
        PHASE = "installed-setup-verification"
        refusal_revision = cli("system.health")["revision"]
        verification_before = cli("reliability.lifecycle")["setup_verification"]
        refusal = setup_command(["setup", "verify"], daemon_process.pid)
        require(refusal.get("schema_version") == 2 and refusal.get("outcome") == "safe_refusal"
                and refusal.get("refusal") == "installation_selection_required"
                and isinstance(refusal.get("operation_id"), str) and len(refusal["operation_id"]) == 64
                and type(refusal.get("elapsed_ns")) is int and refusal["elapsed_ns"] >= 0
                and refusal.get("timing_scope") == "admission_to_terminal_before_commit_process_local"
                and refusal.get("phases") == [{"outcome": "unknown", "reason": "observation_unknown"}] * 7,
                "unselected installed verification manufactured successful phase evidence")
        refusal_params = {"operation_id": refusal["operation_id"], "expected_revision": refusal_revision}
        refusal_status = cli("operation.status", {"operation_id": refusal["operation_id"]})
        require(refusal_status == {"operation_id": refusal["operation_id"], "status": "completed", "result": refusal},
                "installed verification refusal lost terminal operation authority")
        refusal_committed_revision = cli("system.health")["revision"]
        verification_after = cli("reliability.lifecycle")["setup_verification"]
        require(verification_after["safe_refusals"] == verification_before["safe_refusals"] + 1
                and verification_after["installation_selection_required_refusals"]
                == verification_before["installation_selection_required_refusals"] + 1
                and verification_after["verification_completed"] == verification_before["verification_completed"]
                and sum(verification_after["refusal_timing"]["latency"])
                == sum(verification_before["refusal_timing"]["latency"]) + 1
                and verification_after["refusal_timing"]["missing_latency"]
                == verification_before["refusal_timing"]["missing_latency"]
                and verification_after["achieved_slo"] is False,
                "installed refusal counted as completed verification or achieved SLO")
        require(cli("setup.refresh", refusal_params) == refusal,
                "installed exact verification replay changed cached refusal")
        passive = setup_command(["setup", "refresh"], daemon_process.pid)
        require(passive.get("status") == "installation_selection_required" and passive.get("provider_access") is False,
                "passive installed refresh inferred selection or provider authority")
        require(cli("system.health")["revision"] == refusal_committed_revision
                and verification_facts(cli("reliability.lifecycle")["setup_verification"])
                == verification_facts(verification_after),
                "verification replay or passive refresh changed revision or durable samples")
        PHASE = "installed-cli-deduplication"
        initial = cli("state.snapshot")
        require(initial["accounts"] == [] and initial["sources"] == [], "fixture unexpectedly enrolled sources")
        params = {"operation_id": "installed-custody-policy", "expected_revision": initial["revision"],
                  "warm_alternatives": False}
        # Simulate response loss with a fully delivered request and no reply read.
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as abandoned:
            abandoned.connect(str(socket_path))
            abandoned.sendall(json.dumps({"jsonrpc": "2.0", "id": 97, "method": "policy.set",
                                         "params": params}, separators=(",", ":")).encode() + b"\n")
        cached = cli("policy.set", params)
        require(cached == {"sticky_routes": True, "warm_alternatives": False}, "installed policy result changed")
        revision = cli("system.health")["revision"]
        require(revision == initial["revision"] + 1, "duplicate mutation changed revision more than once")
        require(cli("policy.set", dict(reversed(list(params.items()))), "oauth-mux") == cached,
                "installed alias duplicate changed cached result")
        require(cli("system.health")["revision"] == revision, "installed duplicate advanced revision")
        if not core_only:
            # Qt --socket performs the genuine handshake and snapshot request.
            # --self-check deliberately disables daemon connections.
            before = snapshot_count()
            PHASE = "installed-qt-connection"
            gui_process = subprocess.Popen([str(prefix / "bin/omux-control"), "--socket", str(socket_path)],
                                           stdin=subprocess.DEVNULL, stdout=daemon_output,
                                           stderr=daemon_output, env=environment)
            deadline = time.monotonic() + 8
            connected = False
            while time.monotonic() < deadline:
                require(gui_process.poll() is None, "installed Qt control exited before connecting")
                if snapshot_count() > before:
                    connected = True
                    break
                time.sleep(0.05)
            require(connected, "installed Qt control did not request daemon state")
            stop(gui_process)
            gui_process = None
            require(cli("system.health")["revision"] == revision, "Qt inspection changed authority")
        stop(daemon_process, require_success=True)
        daemon_process = None
        database, authority = state / "state.sqlite", state / "state.sqlite.authority"
        PHASE = "durable-custody-inspection"
        require(database.is_file() and authority.is_file(), "installed daemon omitted durable custody")
        # R-N13: SQLite's transaction context does not close its connection.
        # Release this fixture reader before the daemon resumes exclusive custody.
        with closing(sqlite3.connect(database)) as metadata:
            # R-N13: this new fixture requires the fresh sealed schema. Historical
            # installed schema-2 receipts retain their original artifact scope.
            require(metadata.execute("PRAGMA user_version").fetchone()[0] == 3, "installed database schema changed")
            require(metadata.execute("SELECT count(*) FROM grants").fetchone()[0] == 0,
                    "fixture retained unexpected credential grants")
            require(metadata.execute("SELECT length(key_check) FROM custody").fetchone()[0] > 32,
                    "wrapping-key custody check is not an envelope")
            check_sealed_snapshot(metadata, authority)
        older_database = database.read_bytes()
        PHASE = "daemon-process-restart"
        # Legitimate selectors are captured only by the next manual launch.
        # They nominate the actual receipt/prefix, never OS-service activation.
        environment["OMUX_INSTALL_PREFIX"] = str(prefix)
        environment["OMUX_INSTALL_RECORD"] = str(records / install.RECORD)
        daemon_process = start()
        PHASE = "installed-cli-readiness-after-restart"
        check_installed_setup(daemon_process.pid, selected=True)
        require(cli("operation.status", {"operation_id": refusal["operation_id"]}) == refusal_status
                and cli("setup.refresh", refusal_params) == refusal
                and verification_facts(cli("reliability.lifecycle")["setup_verification"])
                == verification_facts(verification_after),
                "installed daemon restart lost cached refusal or verification samples")
        PHASE = "installed-selected-setup-verification"
        selected_revision = cli("system.health")["revision"]
        selected = setup_command(["setup", "verify"], daemon_process.pid)
        require(isinstance(selected.get("operation_id"), str) and selected["operation_id"] != refusal["operation_id"],
                "fresh installed verification reused prior refusal identity")
        deadline = time.monotonic() + 12
        while True:
            selected_status, selected_status_bytes = cli_response(
                "operation.status", {"operation_id": selected["operation_id"]})
            if selected_status.get("status") == "completed":
                break
            require(selected_status.get("status") == "started" and time.monotonic() < deadline,
                    "installed selected verification did not reach bounded terminal authority")
            time.sleep(0.05)
        selected_result = selected_status["result"]
        require(selected_result.get("outcome") == "verification_completed"
                and selected_result.get("refusal") is None and selected_result.get("generation", 0) > 0
                and selected_result.get("phases") == [
                    {"outcome": "verified_ready", "reason": "ready"},
                    {"outcome": "unknown", "reason": "observation_unknown"},
                    {"outcome": "verified_ready", "reason": "ready"},
                    {"outcome": "action_required", "reason": "missing"},
                    {"outcome": "action_required", "reason": "pending"},
                    {"outcome": "action_required", "reason": "missing"},
                    {"outcome": "action_required", "reason": "missing"}],
                "selected verification overclaimed service, enrollment or native readiness")
        selected_evidence = setup_command(["setup", "evidence"], daemon_process.pid)
        require(selected_evidence["provider_access"] is False and selected_evidence["refresh_pending"] is False
                and selected_evidence["probe"]["failure"] == "none"
                and selected_evidence["probe"]["artifact"]["ownership"] == "installation_receipt"
                and selected_evidence["probe"]["artifact"]["payload"] == "matches"
                and selected_evidence["probe"]["artifact"]["running_executable"] == "matches",
                "installed collector did not verify actual receipt and daemon bytes")
        selected_committed_revision = cli("system.health")["revision"]
        selected_summary = cli("reliability.lifecycle")["setup_verification"]
        selected_params = {"operation_id": selected["operation_id"], "expected_revision": selected_revision}
        selected_replay, selected_replay_bytes = cli_response("setup.refresh", selected_params)
        require(selected_replay == selected_result and cli("system.health")["revision"] == selected_committed_revision
                and verification_facts(cli("reliability.lifecycle")["setup_verification"])
                == verification_facts(selected_summary),
                "selected verification replay changed terminal authority")
        require(selected_summary["verification_completed"] == verification_after["verification_completed"] + 1
                and selected_summary["safe_refusals"] == verification_after["safe_refusals"]
                and selected_summary["scope"] == "explicit_setup_verification_not_installation_success"
                and selected_summary["achieved_slo"] is False
                and selected_summary["end_to_end_latency_measured"] is False
                and selected_summary["legacy_empty_refresh_measured"] is False
                and selected_summary["ids_retired"] is False
                and cli("state.snapshot")["accounts"] == cli("state.snapshot")["sources"] == [],
                "local verification claimed install success, SLO or account enrollment")
        for before, after, observed in zip(verification_after["phases"], selected_summary["phases"],
                                           selected_result["phases"], strict=True):
            require(all(after[name] == before[name] + int(name == observed["outcome"])
                        for name in ("verified_ready", "action_required", "unknown")),
                    "completed verification summary changed unrelated phase counts")
        PHASE = "daemon-process-restart"
        restarted_revision = cli("system.health")["revision"]
        require(cli("policy.set", params) == cached, "restart lost mutation acknowledgment")
        require(cli("system.health")["revision"] == restarted_revision, "restart replay advanced revision")
        cli("policy.set", {"operation_id": "installed-custody-new-policy", "expected_revision": restarted_revision,
                           "warm_alternatives": True})
        stop(daemon_process, require_success=True)
        daemon_process = None
        with closing(sqlite3.connect(database)) as metadata:
            terminal_bytes_before_restart = sealed_verification_results(metadata, (refusal, selected_result))
        PHASE = "daemon-process-restart"
        daemon_process = start()
        PHASE = "installed-completed-verification-after-restart"
        check_installed_setup(daemon_process.pid, selected=True)
        completed_restart_revision = cli("system.health")["revision"]
        # Startup recollects current readiness under the same actual receipt.
        # Its generation/time may differ; the acknowledged terminal result may not.
        restarted_status, restarted_status_bytes = cli_response(
            "operation.status", {"operation_id": selected["operation_id"]})
        restarted_replay, restarted_replay_bytes = cli_response("setup.refresh", selected_params)
        require(restarted_status == selected_status and restarted_status_bytes == selected_status_bytes
                and restarted_replay == selected_result and restarted_replay_bytes == selected_replay_bytes,
                "completed installed verification changed terminal bytes after daemon restart")
        require(cli("operation.status", {"operation_id": refusal["operation_id"]}) == refusal_status
                and cli("setup.refresh", refusal_params) == refusal
                and cli("system.health")["revision"] == completed_restart_revision
                and verification_facts(cli("reliability.lifecycle")["setup_verification"])
                == verification_facts(selected_summary)
                and cli("state.snapshot")["accounts"] == cli("state.snapshot")["sources"] == [],
                "completed verification restart/replay changed samples, revision or enrollment")
        stop(daemon_process, require_success=True)
        daemon_process = None
        with closing(sqlite3.connect(database)) as metadata:
            require(sealed_verification_results(metadata, (refusal, selected_result)) == terminal_bytes_before_restart,
                    "completed installed verification restart changed sealed terminal bytes")
        authority_before = authority.read_bytes()
        PHASE = "database-rollback-rejection"
        database.write_bytes(older_database)
        rejected = subprocess.run([str(prefix / "bin/omuxd"), "--state-dir", str(state)],
                                  stdin=subprocess.DEVNULL, capture_output=True, timeout=12, env=environment)
        require(rejected.returncode != 0 and b"RecoveryRollbackDetected" in rejected.stderr,
                "installed daemon admitted an older restored database")
        require(authority.read_bytes() == authority_before, "rollback rejection reseeded recovery authority")
        PHASE = "public-evidence"
        # Retain the PUBLIC byte tuple while installed files still exist. No
        # database, authority record, key, ciphertext, operation ID or path is
        # exported. These hashes do not recover the archive after it is pruned.
        installed_members = {}
        for name in PUBLIC_MEMBERS:
            expected = archive_files[name]
            descriptor = os.open(prefix / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                initial = os.fstat(descriptor)
                require(stat.S_ISREG(initial.st_mode) and initial.st_uid == os.getuid()
                        and initial.st_nlink == 1 and initial.st_size == len(expected) <= pack.MAX_BYTES,
                        "installed public evidence member custody changed")
                digest = hashlib.sha256()
                remaining = len(expected)
                magic = b""
                while remaining:
                    chunk = os.read(descriptor, min(65536, remaining))
                    require(bool(chunk), "installed public evidence member shortened")
                    if len(magic) < 4:
                        magic += chunk[:4 - len(magic)]
                    digest.update(chunk)
                    remaining -= len(chunk)
                final = os.fstat(descriptor)
                named = os.stat(prefix / name, follow_symlinks=False)
                stable_fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
                require(os.read(descriptor, 1) == b""
                        and all(getattr(initial, field) == getattr(final, field) == getattr(named, field)
                                for field in stable_fields)
                        and magic == b"\x7fELF" and digest.hexdigest() == pack.digest(expected),
                        "installed public evidence member differs from verified archive")
                installed_members[name] = {"sha256": digest.hexdigest(), "bytes": len(expected),
                                           "format": "elf", "matches_verified_archive": True}
            finally:
                os.close(descriptor)
        with Path(__file__).open("rb") as fixture_source:
            source_bytes = fixture_source.read(256 * 1024 + 1)
        require(0 < len(source_bytes) <= 256 * 1024, "installed fixture source exceeded public evidence bound")

        def fact_digest(value: dict) -> str:
            return pack.digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())

        receipt = {
            "schema_version": 1, "kind": "installed_private_custody_public_evidence",
            "lane": "core_only" if core_only else "full_qt",
            "capture_point": "checked_restart_and_rollback_before_owned_uninstall",
            "caller_source_binding": "enclosing_guard_receipt_only",
            "fixture_source_sha256": pack.digest(source_bytes),
            "archive_sha256": pack.digest(payload), "archive_bytes": len(payload),
            "manifest_sha256": pack.digest(archive_files["release-manifest.json"]),
            "manifest_bytes": len(archive_files["release-manifest.json"]),
            "artifact_target": manifest["target"], "artifact_distribution": manifest["distribution"],
            "artifact_channel": manifest["channel"],
            "artifact_status": manifest["product"]["status"],
            "raw_source_revision": manifest["provenance"].get("sourceRevision"),
            "raw_source_revision_present": "sourceRevision" in manifest["provenance"],
            "raw_source_dirty": manifest["provenance"]["sourceDirty"],
            "installed_members": installed_members,
            "observed_artifact": {**{name: selected_evidence["probe"]["artifact"][name]
                                     for name in ("ownership", "payload", "running_executable")},
                                  "scope": "checked_selected_startup_before_final_restart"},
            "verification": {
                "refusal_schema_version": refusal["schema_version"],
                "completion_schema_version": selected_result["schema_version"],
                "safe_refusal_count_delta": verification_after["safe_refusals"] - verification_before["safe_refusals"],
                "verification_completed_count_delta": selected_summary["verification_completed"] - verification_after["verification_completed"],
                "installation_success_measured": selected_summary["installation_success_measured"],
                "end_to_end_latency_measured": selected_summary["end_to_end_latency_measured"],
                "achieved_slo": selected_summary["achieved_slo"],
                "digests": {
                    "safe_refusal_terminal": pack.digest(terminal_bytes_before_restart[refusal["operation_id"]]),
                    "verification_completed_terminal": pack.digest(terminal_bytes_before_restart[selected_result["operation_id"]]),
                    "samples_before_refusal": fact_digest(verification_facts(verification_before)),
                    "samples_after_refusal": fact_digest(verification_facts(verification_after)),
                    "samples_after_completion": fact_digest(verification_facts(selected_summary)),
                    "selected_status_reply_before_restart": pack.digest(selected_status_bytes),
                    "selected_status_reply_after_restart": pack.digest(restarted_status_bytes),
                    "selected_refresh_reply_before_restart": pack.digest(selected_replay_bytes),
                    "selected_refresh_reply_after_restart": pack.digest(restarted_replay_bytes),
                },
            },
        }
        print(public_evidence_line(receipt, core_only), flush=True)
        PHASE = "ownership-uninstall"
        uninstalled = install.uninstall(prefix, records)
        require(uninstalled["preserved"] == [] and len(uninstalled["removed"]) == len(record["files"]),
                "installed files were not completely ownership-uninstalled")
        require(database.is_file() and authority.is_file(), "uninstall removed separate user custody state")
        print("OMUX_INSTALLED_CORE_PRIVATE_CUSTODY_OK" if core_only else "OMUX_INSTALLED_PRIVATE_CUSTODY_OK")
    finally:
        if gui_process is not None:
            stop(gui_process)
        if daemon_process is not None:
            stop(daemon_process)
        daemon_output.close()
        stop(keyring_process)
        keyring_output.close()


def main() -> int:
    arguments = sys.argv[1:]
    core_only = bool(arguments and arguments[-1] == "--core-only")
    if core_only:
        arguments = arguments[:-1]
    require("--core-only" not in arguments, "core-only flag must appear exactly once at the end")
    if len(arguments) == 4 and arguments[0] == "--inside":
        inside(*(Path(value).resolve() for value in arguments[1:]), core_only=core_only)
        return 0
    require(len(arguments) == 4 and "--inside" not in arguments, "declared bundle and isolated vault tools required")
    bundle, session, bus, keyring = (Path(value).resolve(strict=True) for value in arguments)
    staged_public_line = None
    staged_success_marker = None
    with tempfile.TemporaryDirectory(prefix="omux-i-", dir="/tmp") as temporary:
        root = Path(temporary)
        environment = os.environ.copy()
        for name in ("DBUS_SESSION_BUS_ADDRESS", "DBUS_STARTER_ADDRESS", "DBUS_STARTER_BUS_TYPE",
                     "GNOME_KEYRING_CONTROL", "SSH_AUTH_SOCK", "LD_PRELOAD", "LD_AUDIT", "LD_DEBUG"):
            environment.pop(name, None)
        for name, child in (("XDG_RUNTIME_DIR", "r"), ("XDG_DATA_HOME", "d"), ("XDG_CONFIG_HOME", "c"),
                            ("XDG_CACHE_HOME", "k"), ("XDG_STATE_HOME", "s"), ("HOME", "h")):
            directory = root / child
            directory.mkdir(mode=0o700)
            environment[name] = str(directory)
        environment["OMUX_ISOLATED_VAULT_PROOF"] = "private-bus-private-xdg"
        configuration = root / "bus.conf"
        configuration.write_text('<busconfig><type>session</type><listen>unix:abstract=omux-installed-' +
                                 root.name + '</listen><auth>EXTERNAL</auth><policy context="default">' +
                                 '<allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/>' +
                                 '</policy></busconfig>')
        bootstrap = "import os,runpy,sys;p=sys.argv.pop(1);sys.path.insert(0,os.path.dirname(p));sys.argv[0]=p;runpy.run_path(p,run_name='__main__')"
        # Keep declared sibling Python inputs, including the generated trusted
        # launcher template, in the child's isolated import path. Resolving this
        # runfiles alias would instead select the physical source checkout.
        process = subprocess.Popen([str(session), "--dbus-daemon=" + str(bus), "--config-file=" + str(configuration),
                                    "--", sys.executable, "-I", "-B", "-c", bootstrap, str(Path(__file__).absolute()),
                                    "--inside", str(bundle), str(keyring), str(root)] + (["--core-only"] if core_only else []),
                                   env=environment, start_new_session=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        code, output, diagnostics = bounded_private_session(process)
        if code == 0:
            marker = "OMUX_INSTALLED_CORE_PRIVATE_CUSTODY_OK" if core_only else "OMUX_INSTALLED_PRIVATE_CUSTODY_OK"
            require((marker + "\n").encode() in output,
                    "installed custody success marker missing")
            lines = output.splitlines()
            require(len(lines) == 2 and lines[1] == marker.encode() and len(lines[0]) <= PUBLIC_EVIDENCE_LIMIT,
                    "installed public evidence line missing or ambiguous")
            # Stage only the independently bounded allowlist. The child and
            # private group are done; outer filesystem cleanup is still pending.
            receipt = json.loads(lines[0])
            encoded = public_evidence_line(receipt, core_only)
            require(lines[0] == encoded.encode("ascii"), "installed public evidence is not canonical")
            staged_public_line = encoded
            staged_success_marker = marker
        else:
            # Forward only our finite phase names, never bus/vault output.
            for phase in ("keyring-startup", "initial-daemon-startup", "installed-cli-deduplication",
                          "installed-cli-readiness", "installed-cli-readiness-after-restart",
                          "installed-setup-verification", "installed-selected-setup-verification",
                          "installed-completed-verification-after-restart",
                          "installed-qt-connection", "durable-custody-inspection", "daemon-process-restart",
                          "database-rollback-rejection", "public-evidence", "ownership-uninstall", "private-context"):
                marker = "installed private custody proof failed at " + phase
                # The initial readiness name is a prefix of its restart name;
                # forward only the exact finite phase emitted by the child.
                if (marker + "\n").encode() in diagnostics:
                    print(marker, file=sys.stderr)
                    break
            for fault in FAULTS:
                if ("installed custody failure classification: " + fault + "\n").encode() in diagnostics:
                    print("installed custody failure classification: " + fault, file=sys.stderr)
                    break
            for subphase in SUBPHASES:
                marker = "installed custody failure subphase: " + subphase
                if (marker + "\n").encode() in diagnostics:
                    print(marker, file=sys.stderr)
                    break
            for reason in READINESS_REASONS:
                marker = "installed custody readiness reason: " + reason
                if (marker + "\n").encode() in diagnostics:
                    print(marker, file=sys.stderr)
                    break
            for failure in PROBE_FAILURES:
                marker = "installed custody probe failure: " + failure
                if (marker + "\n").encode() in diagnostics:
                    print(marker, file=sys.stderr)
                    break
            tag = re.search(rb"(?:^|\n)installed custody failure classification: ([A-Z][A-Za-z0-9]{0,63})(?:\n|$)", diagnostics)
            if tag is not None:
                print("installed custody failure classification: " + tag[1].decode("ascii"), file=sys.stderr)
    # Context exit must succeed before a public terminal receipt or marker.
    # A cleanup exception follows the existing finite failure path, with neither
    # staged success line forwarded from captured child output.
    if code == 0:
        require(staged_public_line is not None and staged_success_marker is not None,
                "installed public evidence was not staged")
        print(staged_public_line)
        print(staged_success_marker)
    return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        # No unbounded exception messages, private bus diagnostics or custody
        # content are published from this proof.
        print("installed private custody proof failed at " + PHASE, file=sys.stderr)
        print("installed custody failure classification: " + FAULT, file=sys.stderr)
        if SUBPHASE in SUBPHASES:
            print("installed custody failure subphase: " + SUBPHASE, file=sys.stderr)
        if SUBPHASE.startswith("readiness-") and READINESS_REASON in READINESS_REASONS:
            print("installed custody readiness reason: " + READINESS_REASON, file=sys.stderr)
        if SUBPHASE == "readiness-artifact" and PROBE_FAILURE in PROBE_FAILURES:
            print("installed custody probe failure: " + PROBE_FAILURE, file=sys.stderr)
        sys.exit(1)
