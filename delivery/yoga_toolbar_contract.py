"""Test-driver admission and categorical receipts; never a product capability."""
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import time

INPUTS = frozenset({"bundle", "extension", "chromium", "node", "observer", "dbus_session",
                    "dbus_daemon", "keyring", "runtime_authority", "recorder", "recorder_implementation"})
SHA = re.compile(r"[0-9a-f]{64}")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
REASONS = frozenset({"visible_session_required", "visible_session_invalid", "visible_adapter_unsupported",
    "input_digest_mismatch", "unsafe_private_input", "display_custody_invalid", "aggregate_unqualified",
    "network_unqualified", "deadline_exceeded", "attestation_invalid", "browser_predicate_failed",
    "private_session_failed", "cleanup_incomplete", "runtime_unqualified", "fixture_unavailable"})
CASES = frozenset({"denial", "approval", "reload"})


class Refusal(ValueError):
    def __init__(self, reason):
        self.reason = reason if reason in REASONS else "fixture_unavailable"
        super().__init__(self.reason)


def require(condition, reason):
    if not condition:
        raise Refusal(reason)


def parse(payload):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "visible_session_invalid")
            result[key] = value
        return result
    try:
        return json.loads(payload, object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(Refusal("visible_session_invalid")))
    except (ValueError, UnicodeError, RecursionError) as error:
        if isinstance(error, Refusal):
            raise
        raise Refusal("visible_session_invalid") from None


def private_directory(path):
    path = Path(path)
    require(path.is_absolute() and str(path.resolve(strict=True)) == str(path), "unsafe_private_input")
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and stat.S_IMODE(info.st_mode) == 0o700, "unsafe_private_input")
    return path


def private_read(path, maximum=16384):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and stat.S_IMODE(before.st_mode) == 0o600 and before.st_nlink == 1
                and before.st_size <= maximum, "unsafe_private_input")
        payload = os.read(descriptor, maximum + 1)
        after = os.fstat(descriptor)
        require(before == after and len(payload) == before.st_size, "unsafe_private_input")
        return payload
    finally:
        os.close(descriptor)


def validate_session(value, now_ns):
    fields = {"schemaVersion", "scope", "hostAlias", "proofId", "operatorAccess", "deadlineMonotonicNs",
              "coordinator", "display", "inputSha256", "vaultWrapperAuthority", "wrapperSourceSha256"}
    require(type(value) is dict and set(value) == fields and type(value["schemaVersion"]) is int
            and value["schemaVersion"] == 1 and value["scope"] == "yoga-operator-local-toolbar-v1"
            and value["hostAlias"] == "yoga" and value["operatorAccess"] == "local-console"
            and type(value["proofId"]) is str and UUID.fullmatch(value["proofId"]), "visible_session_invalid")
    require(type(value["deadlineMonotonicNs"]) is int
            and 0 < value["deadlineMonotonicNs"] - now_ns <= 1200 * 10**9, "deadline_exceeded")
    hashes = value["inputSha256"]
    require(type(hashes) is dict and set(hashes) == INPUTS
            and all(type(item) is str and SHA.fullmatch(item) for item in hashes.values()), "visible_session_invalid")
    import yoga_wrapper_custody as custody
    try:
        custody.envelope(value['vaultWrapperAuthority'])
        custody.source_hashes(value['wrapperSourceSha256'])
    except custody.CustodyRefusal:
        raise Refusal('visible_session_invalid') from None
    coordinator = value["coordinator"]
    require(type(coordinator) is dict and set(coordinator) == {"pid", "cgroupPath", "device", "inode"}
            and type(coordinator["pid"]) is int and coordinator["pid"] > 1
            and type(coordinator["cgroupPath"]) is str
            and re.fullmatch(r"/sys/fs/cgroup/[A-Za-z0-9_.:/-]{1,512}", coordinator["cgroupPath"])
            and ".." not in coordinator["cgroupPath"].split("/")
            and all(type(coordinator[key]) is int and coordinator[key] > 0 for key in ("device", "inode")),
            "aggregate_unqualified")
    display = value["display"]
    common = {"adapter", "socketPath", "socketDevice", "socketInode", "serverPid"}
    require(type(display) is dict and type(display.get("adapter")) is str, "display_custody_invalid")
    adapter = display["adapter"]
    require(adapter == "qualified-wayland-unix", "visible_adapter_unsupported")
    require(set(display) == common
            and type(display["socketPath"]) is str and re.fullmatch(r"/[A-Za-z0-9._/-]{1,106}", display["socketPath"])
            and str(Path(display["socketPath"])) == display["socketPath"]
            and len(os.fsencode(display["socketPath"])) <= 107
            and not {".", ".."}.intersection(display["socketPath"].split("/"))
            and all(type(display[key]) is int and display[key] > 0
                    for key in ("socketDevice", "socketInode", "serverPid")), "display_custody_invalid")
    return value


def limits_valid(memory, swap, tasks, cpu):
    # Effective limits are read from the inherited aggregate, not trusted booleans.
    return (memory.isdecimal() and 0 < int(memory) <= 4294967296 and swap == "0"
            and tasks.isdecimal() and 0 < int(tasks) <= 512 and len(cpu.split()) == 2
            and all(part.isdecimal() for part in cpu.split())
            and 0 < int(cpu.split()[0]) <= 2 * int(cpu.split()[1]) and int(cpu.split()[1]) > 0)


def verify_live(session):
    require(time.monotonic_ns() < session["deadlineMonotonicNs"], "deadline_exceeded")
    coordinator = session["coordinator"]
    root = Path(coordinator["cgroupPath"])
    info = root.stat()
    require(stat.S_ISDIR(info.st_mode) and (info.st_dev, info.st_ino) ==
            (coordinator["device"], coordinator["inode"]), "aggregate_unqualified")
    own = Path("/proc/self/cgroup").read_text()
    require(own == Path(f'/proc/{coordinator["pid"]}/cgroup').read_text()
            and own == "0::" + str(root).removeprefix("/sys/fs/cgroup") + "\n"
            and Path(f'/proc/{coordinator["pid"]}').stat().st_uid == os.getuid(), "aggregate_unqualified")
    require(limits_valid(*((root / name).read_text().strip() for name in
                          ("memory.max", "memory.swap.max", "pids.max", "cpu.max"))), "aggregate_unqualified")
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    require(os.getuid() != 0 and status.get("NoNewPrivs", "").strip() == "1"
            and status.get("CapEff", "").strip() == "0000000000000000", "aggregate_unqualified")
    require(socket.if_nameindex() == [(1, "lo")], "network_unqualified")
    # No external interface/route is admitted; IPv6's unreachable lo rows are inert.
    require(len(Path("/proc/net/route").read_text().splitlines()) == 1
            and all(row.split()[-1] == "lo"
                    for row in Path("/proc/net/ipv6_route").read_text().splitlines()), "network_unqualified")
    display = session["display"]
    path = Path(display["socketPath"])
    require(str(path.resolve(strict=True)) == str(path), "display_custody_invalid")
    info = path.lstat()
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.getuid()
            and (info.st_dev, info.st_ino) == (display["socketDevice"], display["socketInode"])
            and Path(f'/proc/{display["serverPid"]}').stat().st_uid == os.getuid(), "display_custody_invalid")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(1)
        connection.connect(str(path))
        pid, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        require(pid == display["serverPid"] and uid == os.getuid(), "display_custody_invalid")
    after = path.lstat()
    require((after.st_dev, after.st_ino) == (info.st_dev, info.st_ino), "display_custody_invalid")


def display_environment(display):
    require(display["adapter"] == "qualified-wayland-unix", "visible_adapter_unsupported")
    return {"WAYLAND_DISPLAY": display["socketPath"]}, "wayland"


def validate_attestation(value, proof_id, case):
    fields = {"schemaVersion", "scope", "proofId", "case", "toolbarOpened", "consentChecked",
              "connectClicked", "browserPromptSeen", "browserDecision"}
    require(case in CASES and type(value) is dict and set(value) == fields
            and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
            and value["scope"] == "human-toolbar-attestation" and value["proofId"] == proof_id
            and value["case"] == case and value["toolbarOpened"] is True, "attestation_invalid")
    interacted = case != "reload"
    require(all(value[key] is interacted for key in ("consentChecked", "connectClicked", "browserPromptSeen"))
            and value["browserDecision"] == {"denial": "denied", "approval": "approved", "reload": "not_requested"}[case],
            "attestation_invalid")
    return value
