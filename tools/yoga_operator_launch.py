"""Local Yoga guard worker handshake; never a standalone or remote executor.

The sole guard prepares a pinned private plan before system-manager launch.
Worker namespace readbacks precede ready; supervisor admission precedes go.
No operator descriptors or personal desktop environment reach the workload.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time

import yoga_display_binding as display
import yoga_operator_coordinator as support

MAX_FILE = 65536
OUTPUT_LIMIT = 8 * 1024 * 1024
PLAN_FIELDS = frozenset({"schemaVersion", "scope", "proofId", "root", "uid", "gid", "unit", "deadlineNs",
                         "hostHome", "commandSha256", "inputPaths", "inputSha256", "displayWitness",
                         "vaultWrapperAuthority", "sourceRoot", "sourceFilesSha256"})
READY_FIELDS = frozenset({"schemaVersion", "scope", "proofId", "planSha256", "commandSha256", "pid", "startTicks",
                          "coordinator", "displaySnapshot", "inputSha256", "namespaceChecked", "vaultWrapperAuthoritySha256"})


class LaunchError(ValueError):
    def __init__(self, reason):
        self.reason = reason if reason in {"plan_invalid", "ready_invalid", "go_invalid", "namespace_invalid",
            "deadline_exceeded", "input_digest_mismatch", "input_changed", "cleanup_invalid", "worker_unavailable"} else "worker_unavailable"
        super().__init__(self.reason)


def require(condition, reason):
    if not condition:
        raise LaunchError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def decode(payload):
    require(type(payload) is bytes and len(payload) <= MAX_FILE, "plan_invalid")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "plan_invalid")
            result[key] = value
        return result
    try:
        return json.loads(payload, object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(LaunchError("plan_invalid")))
    except (ValueError, UnicodeError, RecursionError):
        raise LaunchError("plan_invalid") from None


def bounded_read(directory, name, uid, *, limit=MAX_FILE, now=time.monotonic_ns, deadline=None):
    require(name in {"worker-plan.json", "worker-ready.json", "worker-refused.json", "session.json", "go", "workload.log",
                     "denial.json", "approval.json", "reload.json", "progress.jsonl"}, "plan_invalid")
    require(type(limit) is int and 0 < limit <= OUTPUT_LIMIT, "plan_invalid")
    if deadline is not None:
        require(now() < deadline, "deadline_exceeded")
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == uid and stat.S_IMODE(before.st_mode) == 0o600
                and before.st_nlink == 1 and (0 <= before.st_size <= limit if name == "progress.jsonl"
                                             else 0 < before.st_size <= limit), "plan_invalid")
        chunks, size = [], 0
        while True:
            if deadline is not None:
                require(now() < deadline, "deadline_exceeded")
            chunk = os.read(descriptor, min(65536, limit + 1 - size))
            if not chunk:
                break
            size += len(chunk)
            require(size <= limit, "plan_invalid")
            chunks.append(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory, follow_symlinks=False)
        def identity(info):
            return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
                    info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        for info in (after, named):
            require(stat.S_ISREG(info.st_mode) and info.st_uid == uid and stat.S_IMODE(info.st_mode) == 0o600
                    and info.st_nlink == 1 and (info.st_dev, info.st_ino) == (before.st_dev, before.st_ino)
                    and (0 <= info.st_size <= limit if name == "progress.jsonl" else 0 < info.st_size <= limit), "plan_invalid")
        require(len(payload) == before.st_size and identity(before) == identity(after) == identity(named), "input_changed")
        if deadline is not None:
            require(now() < deadline, "deadline_exceeded")
        return payload
    finally:
        os.close(descriptor)


def command_digest(command):
    require(type(command) is list and command and all(type(part) is str and "\0" not in part for part in command), "plan_invalid")
    require(command[0].startswith(("/nix/store/", "/srv/")) and command.count("run") == 1
            and command[-1] == support.LABEL and "--" not in command
            and not any(part.startswith("//") and part != support.LABEL for part in command), "plan_invalid")
    return hashlib.sha256(canonical(command)).hexdigest()


def prepare_worker(coordinator, command, input_paths, *, host_home, gid):
    coordinator.check()
    require(coordinator.operator_descriptor is not None and not coordinator.admitted, "plan_invalid")
    support.wrapper_metadata(coordinator.vault_wrapper_authority, coordinator.source_root, coordinator.source_files_sha256)
    require(type(input_paths) is dict and set(input_paths) == support.INPUTS
            and all(type(path) is str and path.startswith(("/srv/", "/nix/store/")) for path in input_paths.values()), "plan_invalid")
    require(type(host_home) is str and host_home.startswith("/") and str(Path(host_home)) == host_home
            and not {".", ".."}.intersection(host_home.split("/"))
            and not host_home.startswith(("/srv/", "/nix/store/")) and type(gid) is int and gid > 0, "plan_invalid")
    plan = {"schemaVersion": 1, "scope": "yoga-guard-worker-plan-v1", "proofId": coordinator.proof_id,
        "root": coordinator.root, "uid": coordinator.uid, "gid": gid,
        "unit": "omux-execution-" + coordinator.proof_id + ".service", "deadlineNs": coordinator.deadline,
        "hostHome": host_home, "commandSha256": command_digest(command), "inputPaths": dict(input_paths),
        "inputSha256": dict(coordinator.digests), "displayWitness": coordinator.witness,
        "vaultWrapperAuthority": coordinator.vault_wrapper_authority, "sourceRoot": coordinator.source_root,
        "sourceFilesSha256": coordinator.source_files_sha256}
    payload = canonical(plan)
    coordinator.write("worker-plan.json", payload)
    coordinator.launch_plan = plan
    coordinator.launch_plan_sha256 = hashlib.sha256(payload).hexdigest()
    return coordinator.launch_plan_sha256


def read_worker_ready(coordinator, *, expected_pid):
    coordinator.check()
    require(type(expected_pid) is int and expected_pid > 1, "ready_invalid")
    require(hasattr(coordinator, "launch_plan"), "ready_invalid")
    until = min(coordinator.deadline - 120 * 10**9, coordinator.now() + 120 * 10**9)
    while coordinator.now() < until:
        try:
            payload = bounded_read(coordinator.descriptor, "worker-ready.json", coordinator.uid)
        except FileNotFoundError:
            try:
                bounded_read(coordinator.descriptor, "worker-refused.json", coordinator.uid)
            except FileNotFoundError:
                time.sleep(0.05)
                continue
            raise LaunchError("worker_unavailable") from None
        value = decode(payload)
        require(type(value) is dict and set(value) == READY_FIELDS and type(value["schemaVersion"]) is int
                and value["schemaVersion"] == 1 and value["scope"] == "yoga-guard-worker-ready-v1"
                and value["proofId"] == coordinator.proof_id and value["planSha256"] == coordinator.launch_plan_sha256
                and value["commandSha256"] == coordinator.launch_plan["commandSha256"]
                and type(value["pid"]) is int and value["pid"] == expected_pid
                and type(value["startTicks"]) is int and value["startTicks"] == display.pid_start(expected_pid, coordinator.uid)
                and value["inputSha256"] == coordinator.digests and value["namespaceChecked"] is True, "ready_invalid")
        require(value['vaultWrapperAuthoritySha256'] == hashlib.sha256(canonical(coordinator.vault_wrapper_authority)).hexdigest(), 'ready_invalid')
        require(value["displaySnapshot"] == coordinator.witness["snapshot"], "ready_invalid")
        cgroup = value["coordinator"]
        require(type(cgroup) is dict and set(cgroup) == {"pid", "cgroupPath", "device", "inode"}
                and all(type(cgroup[key]) is int and cgroup[key] > 1 for key in ("pid", "device", "inode"))
                and cgroup["pid"] == expected_pid and type(cgroup["cgroupPath"]) is str
                and re.fullmatch(r"/sys/fs/cgroup/[A-Za-z0-9_.:/-]{1,512}", cgroup["cgroupPath"])
                and not {".", ".."}.intersection(cgroup["cgroupPath"].split("/"))
                and Path(cgroup["cgroupPath"]).name == coordinator.launch_plan["unit"], "ready_invalid")
        info = Path(cgroup["cgroupPath"]).stat()
        require((info.st_dev, info.st_ino) == (cgroup["device"], cgroup["inode"])
                and Path(f"/proc/{expected_pid}/cgroup").read_text() ==
                "0::" + cgroup["cgroupPath"].removeprefix("/sys/fs/cgroup") + "\n", "ready_invalid")
        coordinator.worker_ready = value
        coordinator.worker_ready_sha256 = hashlib.sha256(payload).hexdigest()
        return value, coordinator.worker_ready_sha256
    raise LaunchError("deadline_exceeded")


def admit_worker(coordinator, ready, *, properties, source_snapshot, effective_readonly_binds, effective_writable_binds):
    coordinator.check()
    require(ready == getattr(coordinator, "worker_ready", None) and coordinator.operator_descriptor is not None, "ready_invalid")
    require(properties.get("Id") == coordinator.launch_plan["unit"] and properties.get("ActiveState") == "active"
            and properties.get("MainPID") == str(ready["pid"])
            and properties.get("ControlGroup") == ready["coordinator"]["cgroupPath"].removeprefix("/sys/fs/cgroup")
            and properties.get("User") == str(coordinator.uid) and properties.get("Group") == str(coordinator.launch_plan["gid"])
            and properties.get("PrivateUsers") == "no" and properties.get("CapabilityBoundingSet") == ""
            and properties.get("AmbientCapabilities") == "" and properties.get("StandardInput") == "null", "namespace_invalid")
    require(effective_writable_binds == [], "namespace_invalid")
    require(display.pid_start(ready["pid"], coordinator.uid) == ready["startTicks"], "ready_invalid")
    session_sha = coordinator.admit(properties=properties, coordinator=ready["coordinator"], source_snapshot=source_snapshot,
        destination_snapshot=ready["displaySnapshot"], effective_binds=effective_readonly_binds, checked_input_digests=ready["inputSha256"],
        checked_wrapper_authority_sha256=ready['vaultWrapperAuthoritySha256'])
    coordinator.write("go", canonical({"schemaVersion": 1, "scope": "yoga-guard-go-v1", "proofId": coordinator.proof_id,
        "planSha256": coordinator.launch_plan_sha256, "readySha256": coordinator.worker_ready_sha256, "sessionSha256": session_sha}))
    return session_sha


def finish_proof(coordinator, *, workload_exit, aggregate_empty, cancellation_requested=False):
    """Join categorical machine results and operator statements before closing custody.

    Human gesture provenance remains an operator statement. Neither observation
    nor this join establishes that a privileged driver could not impersonate it.
    """
    joined = False
    try:
        coordinator.check()
        require(coordinator.admitted and coordinator.events == list(support.STATEMENTS), "ready_invalid")
        read = lambda name, limit=MAX_FILE: bounded_read(coordinator.descriptor, name, coordinator.uid,
            limit=limit, now=coordinator.now, deadline=coordinator.deadline)
        session_payload = read("session.json")
        go = decode(read("go"))
        session_sha = hashlib.sha256(session_payload).hexdigest()
        session = decode(session_payload)
        require(go == {"schemaVersion": 1, "scope": "yoga-guard-go-v1", "proofId": coordinator.proof_id,
            "planSha256": coordinator.launch_plan_sha256, "readySha256": coordinator.worker_ready_sha256,
            "sessionSha256": session_sha}, "go_invalid")
        require(session == {"schemaVersion": 1, "scope": "yoga-operator-local-toolbar-v1", "hostAlias": "yoga",
            "proofId": coordinator.proof_id, "operatorAccess": "local-console", "deadlineMonotonicNs": coordinator.deadline,
            "coordinator": coordinator.worker_ready["coordinator"], "inputSha256": coordinator.digests,
            "vaultWrapperAuthority": coordinator.vault_wrapper_authority, "wrapperSourceSha256": coordinator.wrapper_source_sha256,
            "display": {"adapter": "qualified-wayland-unix", "socketPath": coordinator.root + "/wayland.sock",
                "socketDevice": coordinator.witness["snapshot"]["device"], "socketInode": coordinator.witness["snapshot"]["inode"],
                "serverPid": coordinator.witness["snapshot"]["pid"]}}, "go_invalid")
        require(coordinator.worker_ready['vaultWrapperAuthoritySha256'] == hashlib.sha256(canonical(coordinator.vault_wrapper_authority)).hexdigest(), 'ready_invalid')
        outcomes = []
        for line in read("workload.log", OUTPUT_LIMIT).splitlines():
            require(len(line) <= MAX_FILE, "ready_invalid")
            # Bazel diagnostics remain private and carry no observation authority.
            if not line.startswith(b"{"):
                continue
            value = decode(line)
            if type(value) is dict and value.get("scope") == "yoga-toolbar-local-observations":
                outcomes.append(value)
        require(len(outcomes) == 1, "ready_invalid")
        value = outcomes[0]
        require(set(value) == {"scope", "proofId", "extensionId", "extensionVersion", "channel", "cases", "providerAccess",
            "grantExport", "remoteExecution", "aggregateCleanupJoinRequired", "privateProfilesRemoved", "visibleSessionSha256", "inputSha256"}
            and value["proofId"] == coordinator.proof_id and value["visibleSessionSha256"] == session_sha
            and value["inputSha256"] == coordinator.digests and value["channel"] == "development"
            and type(value["extensionId"]) is str and re.fullmatch(r"[a-p]{32}", value["extensionId"])
            and type(value["extensionVersion"]) is str and re.fullmatch(r"[0-9]+(?:\.[0-9]+){0,3}", value["extensionVersion"])
            and value["providerAccess"] is False and value["grantExport"] is False and value["remoteExecution"] is False
            and value["aggregateCleanupJoinRequired"] is True and value["privateProfilesRemoved"] is True
            and type(value["cases"]) is list and len(value["cases"]) == 3, "ready_invalid")
        for case, observed in zip(support.STATEMENTS, value["cases"]):
            human_payload = read(case + ".json")
            interacted = case != "reload"
            require(decode(human_payload) == {"schemaVersion": 1, "scope": "human-toolbar-attestation", "proofId": coordinator.proof_id,
                "case": case, "toolbarOpened": True, "consentChecked": interacted, "connectClicked": interacted,
                "browserPromptSeen": interacted, "browserDecision": {"denial": "denied", "approval": "approved", "reload": "not_requested"}[case]}, "ready_invalid")
            require(type(observed) is dict and set(observed) == {"scope", "case", "browserVersion", "initialGateObserved",
                "optionalPermissionApproved", "emptyBrowserMetadata", "outcome", "driverInteraction", "humanAttestationRequired", "operatorAttestationSha256"}
                and observed["scope"] == "yoga-toolbar-observed-case" and observed["case"] == case
                and observed["browserVersion"] in {"Chrome/147.0.7727.116", "Chromium/147.0.7727.116"}
                and observed["initialGateObserved"] is True and observed["optionalPermissionApproved"] is (case != "denial")
                and observed["emptyBrowserMetadata"] is True and observed["driverInteraction"] is False
                and observed["humanAttestationRequired"] is True and observed["outcome"] ==
                {"denial": "permission_denied", "approval": "open_provider_tab", "reload": "reload_gate_reset"}[case]
                # Runner hashes its parsed attestation's compact JSON bytes;
                # coordinator writes sorted keys, so reserialization is exact.
                and observed["operatorAttestationSha256"] == hashlib.sha256(canonical(decode(human_payload))).hexdigest(), "ready_invalid")
        coordinator.check()
        joined = True
    except (Exception, KeyboardInterrupt):
        joined = False
    result = coordinator.finish(workload_exit=workload_exit, aggregate_empty=aggregate_empty,
                                cancellation_requested=cancellation_requested)
    result["machineObservationsJoined"] = joined
    result["humanGestureProvenance"] = "operator-attested"
    result["executionPassed"] = result["executionPassed"] and joined
    result["toolbarConsentProved"] = result["executionPassed"]
    return result


def progress_record(line):
    if not line.startswith(b"{"):
        return None
    value = decode(line)
    if type(value) is not dict or value.get("scope") != "yoga-toolbar-progress":
        return None
    require(set(value) == {"scope", "case", "phase"} and value["case"] in support.STATEMENTS
            and value["phase"] in {"await-toolbar", "await-human-decision", "await-attestation"}, "ready_invalid")
    return value


def read_progress(coordinator):
    """Return only new fixed categorical phases to the qualified guard console."""
    coordinator.check()
    require(coordinator.admitted, "ready_invalid")
    try:
        payload = bounded_read(coordinator.descriptor, "progress.jsonl", coordinator.uid,
            now=coordinator.now, deadline=coordinator.deadline)
    except FileNotFoundError:
        return []
    except LaunchError as error:
        # Only a same-object append race is retryable; unsafe or oversize files
        # fail admission and no raced bytes reach the operator console.
        if error.reason == "input_changed":
            return []
        raise
    require(not payload or payload.endswith(b"\n"), "ready_invalid")
    records = [progress_record(line) for line in payload.splitlines()]
    require(len(records) <= 9 and all(record is not None for record in records), "ready_invalid")
    previous = getattr(coordinator, "progress_records", [])
    require(type(previous) is list and records[:len(previous)] == previous
            and len(records) >= len(previous), "ready_invalid")
    coordinator.progress_records = records
    return records[len(previous):]


def _masked(path, directory):
    try:
        info = os.lstat(path)
    except (FileNotFoundError, PermissionError):
        return
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and stat.S_IMODE(info.st_mode) == 0, "namespace_invalid")


def namespace_snapshot(plan, *, now=time.monotonic_ns):
    display.budget(plan["deadlineNs"], now)
    require(os.getuid() == plan["uid"] and os.getgid() == plan["gid"] and os.getuid() > 0, "namespace_invalid")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    require(status["Uid"].split() == [str(plan["uid"])] * 4 and status["Gid"].split() == [str(plan["gid"])] * 4
            and status["NoNewPrivs"].strip() == "1"
            and all(int(status[key].strip(), 16) == 0 for key in ("CapEff", "CapPrm", "CapAmb")), "namespace_invalid")
    require(os.environ.get("HOME") == plan["root"] + "/home"
            and not any(key in os.environ for key in ("DBUS_SESSION_BUS_ADDRESS", "DBUS_SYSTEM_BUS_ADDRESS", "SSH_AUTH_SOCK",
                "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY",
                "ALL_PROXY", "LD_PRELOAD", "NODE_OPTIONS")), "namespace_invalid")
    for path in ("/run", "/nix/var/nix/daemon-socket", plan["hostHome"], "/etc/bluetooth"):
        _masked(path, True)
    _masked("/etc/environment", False)
    require(socket.if_nameindex() == [(1, "lo")] and len(Path("/proc/net/route").read_text().splitlines()) == 1
            and all(row.split()[-1] == "lo" for row in Path("/proc/net/ipv6_route").read_text().splitlines()), "namespace_invalid")
    text = Path("/proc/self/cgroup").read_text()
    require(text.startswith("0::/") and len(text.splitlines()) == 1, "namespace_invalid")
    relative = text.removeprefix("0::").strip()
    require(Path(relative).name == plan["unit"] and ".." not in Path(relative).parts, "namespace_invalid")
    path = Path("/sys/fs/cgroup") / relative.lstrip("/")
    expected = {"memory.max": "4294967296", "memory.swap.max": "0", "pids.max": "512", "memory.oom.group": "1"}
    require(all((path / name).read_text().strip() == value for name, value in expected.items()), "namespace_invalid")
    quota, period = (path / "cpu.max").read_text().split()
    require(quota.isdecimal() and period.isdecimal() and 0 < int(quota) <= 2 * int(period), "namespace_invalid")
    info = path.stat()
    return {"pid": os.getpid(), "cgroupPath": str(path), "device": info.st_dev, "inode": info.st_ino}


def _write(directory, name, payload):
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=directory)
    try:
        os.fchmod(descriptor, 0o600)
        require(os.write(descriptor, payload) == len(payload), "ready_invalid")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.fsync(directory)


def _execute(command, root, until):
    require(type(until) is int and time.monotonic_ns() < until, "deadline_exceeded")
    selector = selectors.DefaultSelector()
    process = None
    output = None
    progress = None
    try:
        descriptor = os.open(root / "workload.log", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        output = os.fdopen(descriptor, "wb")
        descriptor = os.open(root / "progress.jsonl", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        progress = os.fdopen(descriptor, "wb")
        require(time.monotonic_ns() < until, "deadline_exceeded")
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True, close_fds=True)
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        total = 0
        pending, recorded = b"", []
        while selector.get_map():
            require(time.monotonic_ns() < until, "deadline_exceeded")
            for key, _ in selector.select(0.1):
                data = os.read(key.fd, 65536)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                total += len(data)
                require(total <= OUTPUT_LIMIT, "worker_unavailable")
                output.write(data); output.flush()
                pending += data
                while b"\n" in pending:
                    line, pending = pending.split(b"\n", 1)
                    require(len(line) <= MAX_FILE, "worker_unavailable")
                    record = progress_record(line)
                    if record is not None:
                        require(len(recorded) < 9 and record not in recorded, "ready_invalid")
                        recorded.append(record)
                        progress.write(canonical(record) + b"\n"); progress.flush()
                require(len(pending) <= MAX_FILE, "worker_unavailable")
        while time.monotonic_ns() < until:
            status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if status is not None:
                return status.si_status if status.si_code == os.CLD_EXITED else 125
            time.sleep(0.05)
        raise LaunchError("deadline_exceeded")
    finally:
        selector.close()
        if process is not None:
            os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            require(os.getpgid(process.pid) == process.pid, "cleanup_invalid")
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5); process.stdout.close()
        if output is not None:
            output.close()
        if progress is not None:
            progress.close()


def run_worker(run, command):
    import yoga_proof_inputs
    import guard_yoga_profile as guard
    root = str(Path(run))
    require(os.environ.get("OMUX_EXECUTION_GUARD") == root and root.startswith("/srv/"), "plan_invalid")
    expected_sha = os.environ.get("OMUX_YOGA_WORKER_PLAN_SHA256", "")
    require(re.fullmatch(r"[0-9a-f]{64}", expected_sha), "plan_invalid")
    directory = display.parent_descriptor(root, os.getuid())
    captured_wrappers = None
    try:
        payload = bounded_read(directory, "worker-plan.json", os.getuid())
        require(hashlib.sha256(payload).hexdigest() == expected_sha, "plan_invalid")
        plan = decode(payload)
        require(type(plan) is dict and set(plan) == PLAN_FIELDS and type(plan["schemaVersion"]) is int
                and plan["schemaVersion"] == 1 and plan["scope"] == "yoga-guard-worker-plan-v1"
                and plan["root"] == root and type(plan["uid"]) is int and plan["uid"] == os.getuid()
                and type(plan["gid"]) is int and plan["gid"] == os.getgid()
                and type(plan["proofId"]) is str and support.UUID.fullmatch(plan["proofId"])
                and plan["unit"] == "omux-execution-" + plan["proofId"] + ".service"
                and plan["commandSha256"] == command_digest(command), "plan_invalid")
        support.wrapper_metadata(plan['vaultWrapperAuthority'], plan['sourceRoot'], plan['sourceFilesSha256'])
        wrapper_value = dict(plan, controllerTools=plan['vaultWrapperAuthority']['controllerTools'],
            controllerInventory=plan['vaultWrapperAuthority']['controllerInventory'],
            controllerNarProof=plan['vaultWrapperAuthority']['controllerNarProof'])
        captured_wrappers = guard.wrapper_capture(wrapper_value, plan['deadlineNs'])
        own = namespace_snapshot(plan)
        bound = display.inspect_endpoint(root + "/wayland.sock", os.getuid(), plan["deadlineNs"])
        require(bound == plan["displayWitness"]["snapshot"], "ready_invalid")
        checked = yoga_proof_inputs.check_inputs(plan["inputPaths"], plan["inputSha256"], plan["deadlineNs"])
        captured_wrappers.check()
        ready = {"schemaVersion": 1, "scope": "yoga-guard-worker-ready-v1", "proofId": plan["proofId"],
            "planSha256": expected_sha, "commandSha256": plan["commandSha256"], "pid": os.getpid(),
            "startTicks": display.pid_start(os.getpid(), os.getuid()), "coordinator": own, "displaySnapshot": bound,
            "inputSha256": checked, "namespaceChecked": True,
            "vaultWrapperAuthoritySha256": hashlib.sha256(canonical(plan['vaultWrapperAuthority'])).hexdigest()}
        ready_payload = canonical(ready)
        _write(directory, "worker-ready.json", ready_payload)
        until = plan["deadlineNs"] - 120 * 10**9
        while time.monotonic_ns() < until:
            try:
                go = decode(bounded_read(directory, "go", os.getuid()))
            except FileNotFoundError:
                time.sleep(0.05); continue
            require(type(go) is dict and set(go) == {"schemaVersion", "scope", "proofId", "planSha256", "readySha256", "sessionSha256"}
                    and type(go["schemaVersion"]) is int and go["schemaVersion"] == 1 and go["scope"] == "yoga-guard-go-v1"
                    and go["proofId"] == plan["proofId"] and go["planSha256"] == expected_sha
                    and go["readySha256"] == hashlib.sha256(ready_payload).hexdigest(), "go_invalid")
            session_payload = bounded_read(directory, "session.json", os.getuid())
            require(hashlib.sha256(session_payload).hexdigest() == go["sessionSha256"], "go_invalid")
            session = decode(session_payload)
            expected_session = {"schemaVersion": 1, "scope": "yoga-operator-local-toolbar-v1", "hostAlias": "yoga",
                "proofId": plan["proofId"], "operatorAccess": "local-console", "deadlineMonotonicNs": plan["deadlineNs"],
                "coordinator": own, "inputSha256": checked,
                "vaultWrapperAuthority": plan['vaultWrapperAuthority'],
                "wrapperSourceSha256": {name: plan['sourceFilesSha256'][name] for name in sorted(support.WRAPPER_SOURCE_FILES)},
                "display": {"adapter": "qualified-wayland-unix", "socketPath": root + "/wayland.sock",
                    "socketDevice": bound["device"], "socketInode": bound["inode"], "serverPid": bound["pid"]}}
            require(session == expected_session and namespace_snapshot(plan) == own, "go_invalid")
            require(display.inspect_endpoint(root + "/wayland.sock", os.getuid(), plan["deadlineNs"]) == bound, "go_invalid")
            require(yoga_proof_inputs.check_inputs(plan["inputPaths"], checked, plan["deadlineNs"]) == checked, "input_digest_mismatch")
            captured_wrappers.check()
            runtime_args = ["--visible-session", root + "/session.json", "--visible-session-sha256", go["sessionSha256"],
                            "--attestation-dir", root]
            result = _execute(command + ["--"] + runtime_args, Path(root), until)
            captured_wrappers.check()
            return result
        raise LaunchError("deadline_exceeded")
    except (Exception, KeyboardInterrupt) as error:
        reason = error.reason if isinstance(error, LaunchError) else "worker_unavailable"
        try:
            _write(directory, "worker-refused.json", canonical({"scope": "yoga-worker-refused", "reason": reason}))
        except OSError:
            pass
        raise
    finally:
        try:
            if captured_wrappers is not None: captured_wrappers.close()
        finally:
            os.close(directory)


if __name__ == "__main__":
    try:
        require(len(sys.argv) >= 5 and sys.argv[1] == "--worker" and sys.argv[3] == "--", "plan_invalid")
        def interrupted(signum, frame):
            raise KeyboardInterrupt
        for signum in (signal.SIGTERM, signal.SIGHUP):
            signal.signal(signum, interrupted)
        sys.exit(run_worker(sys.argv[2], sys.argv[4:]))
    except (Exception, KeyboardInterrupt) as error:
        reason = error.reason if isinstance(error, LaunchError) else "worker_unavailable"
        print(json.dumps({"scope": "yoga-worker-refused", "reason": reason}), file=sys.stderr)
        sys.exit(125)
