"""Support for the sole execution guard's local Yoga proof.

No CLI, bootstrap, executor or live qualification. The guard supplies verified
properties, bound-namespace snapshots and an owned anonymous operator pipe.
All session data stays private; final facts never claim toolbar acceptance.
"""
import hashlib
import fcntl
import json
import os
from pathlib import Path
import re
import select
import stat
import time
import yoga_display_binding as display

LABEL = "//delivery:yoga_toolbar_consent_proof"
INPUTS = frozenset(("bundle", "extension", "chromium", "node", "observer", "dbus_session",
                   "dbus_daemon", "keyring", "runtime_authority", "recorder", "recorder_implementation"))
WRAPPER_SOURCE_FILES = frozenset(('delivery/yoga_wrapper_authority.py', 'delivery/yoga_wrapper_custody.py'))
WRAPPER_EVIDENCE = frozenset(('companion', 'nativeManifest', 'registeredNativeManifest', 'controllerInventory', 'controllerNarProof'))
CONTROLLER_TOOLS = frozenset(('python', 'systemd_run', 'systemctl', 'bazel', 'closure', 'bootstrap_closure', 'zig_sdk', 'java_home'))
STATEMENTS = {"denial": "toolbar-checkbox-connect-prompt-denied",
              "approval": "toolbar-checkbox-connect-prompt-approved", "reload": "toolbar-reopened-without-request"}
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
LIMITS = {"MemoryMax": "4294967296", "MemorySwapMax": "0", "TasksMax": "512",
          "CPUQuotaPerSecUSec": "2s", "RuntimeMaxUSec": "20min", "KillMode": "control-group",
          "SendSIGKILL": "yes", "TimeoutStopUSec": "10s", "OOMPolicy": "kill",
          "PrivateNetwork": "yes", "NoNewPrivileges": "yes", "ProtectControlGroups": "yes",
          "RestrictSUIDSGID": "yes"}


class CoordinatorError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise CoordinatorError(reason)


def wrapper_metadata(value, source_root, source_files_sha256):
    require(type(value) is dict and set(value) == WRAPPER_EVIDENCE | {'controllerTools'}, 'wrapper_authority_invalid')
    for name in WRAPPER_EVIDENCE:
        item = value[name]
        require(type(item) is dict and set(item) == {'path', 'sha256'} and type(item['sha256']) is str
                and re.fullmatch(r'[0-9a-f]{64}', item['sha256']) and type(item['path']) is str
                and len(item['path']) <= 4096 and item['path'].startswith(('/srv/', '/nix/store/'))
                and str(Path(item['path'])) == item['path'] and not {'.', '..'}.intersection(item['path'].split('/'))
                and not any(c.isspace() for c in item['path']), 'wrapper_authority_invalid')
    require(type(value['controllerTools']) is dict and set(value['controllerTools']) == CONTROLLER_TOOLS
            and all(type(path) is str and re.fullmatch(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]{1,211}(?:/[A-Za-z0-9+._?=@/-]+)?', path)
                    and str(Path(path)) == path and '..' not in Path(path).parts for path in value['controllerTools'].values()), 'wrapper_authority_invalid')
    require(type(source_root) is str and source_root.startswith('/srv/') and str(Path(source_root)) == source_root
            and '..' not in Path(source_root).parts and not any(c.isspace() for c in source_root), 'wrapper_authority_invalid')
    require(type(source_files_sha256) is dict and WRAPPER_SOURCE_FILES.issubset(source_files_sha256)
            and all(type(name) is str and type(sha) is str and re.fullmatch(r'[0-9a-f]{64}', sha)
                    for name, sha in source_files_sha256.items()), 'wrapper_authority_invalid')
    return json.loads(json.dumps(value, sort_keys=True, allow_nan=False))


def parse(payload):
    require(type(payload) is bytes and len(payload) <= 2048, "operator_event_invalid")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "operator_event_invalid")
            result[key] = value
        return result
    try:
        return json.loads(payload, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise CoordinatorError("operator_event_invalid") from None


class Coordinator:
    def __init__(self, *, profile, manager, arguments, proof_id, proof_root, source_socket,
                 uid, deadline_ns, input_digests, vault_wrapper_authority, source_root, source_files_sha256,
                 now=time.monotonic_ns, inspector=display.inspect_endpoint):
        require(profile == "yoga-toolbar" and manager == "system" and arguments == ["run", LABEL], "profile_invalid")
        require(type(proof_id) is str and UUID.fullmatch(proof_id), "proof_id_invalid")
        require(type(input_digests) is dict and set(input_digests) == INPUTS
                and all(type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) for value in input_digests.values()), "input_digest_invalid")
        self.now, self.deadline = now, deadline_ns
        self.uid, self.proof_id, self.root = uid, proof_id, proof_root
        self.digests = dict(input_digests)
        self.vault_wrapper_authority = wrapper_metadata(vault_wrapper_authority, source_root, source_files_sha256)
        self.source_root, self.source_files_sha256 = source_root, dict(source_files_sha256)
        self.wrapper_source_sha256 = {name: source_files_sha256[name] for name in sorted(WRAPPER_SOURCE_FILES)}
        self.admitted, self.finished, self.events = False, False, []
        self.operator_buffer = b""
        self.descriptor, self.operator_descriptor = None, None
        display.selectors(source_socket, proof_root + "/wayland.sock", proof_root, uid)
        display.budget(deadline_ns, now)
        try:
            self.descriptor = display.parent_descriptor(proof_root, uid)
            self.root_identity = os.fstat(self.descriptor)
            self.witness = display.capture(source_socket, proof_root + "/wayland.sock", proof_root,
                                           uid, deadline_ns, inspector, now)
        except BaseException:
            self.close()
            raise

    def close(self):
        for name in ("operator_descriptor", "descriptor"):
            descriptor = getattr(self, name)
            if descriptor is not None:
                setattr(self, name, None)
                os.close(descriptor)

    def retain_operator_channel(self, guard_read_descriptor):
        self.check()
        require(self.operator_descriptor is None, "operator_channel_invalid")
        # Guard creates/provides this pipe. Filesystem metadata cannot establish
        # guard provenance; retention only narrows its descriptor authority.
        descriptor = os.dup(guard_read_descriptor)
        try:
            os.set_inheritable(descriptor, False)
            info = os.fstat(descriptor)
            require(stat.S_ISFIFO(info.st_mode) and info.st_nlink in (0, 1) and info.st_uid == self.uid
                    and stat.S_IMODE(info.st_mode) == 0o600
                    and fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY,
                    "operator_channel_invalid")
            require(os.readlink(f"/proc/self/fd/{descriptor}") == f"pipe:[{info.st_ino}]", "operator_channel_invalid")
            self.operator_identity = (info.st_dev, info.st_ino)
        except BaseException:
            os.close(descriptor)
            raise
        self.operator_descriptor = descriptor

    def check(self):
        require(not self.finished, "coordinator_finished")
        display.budget(self.deadline, self.now)
        current = os.stat(self.root, follow_symlinks=False)
        require(stat.S_ISDIR(current.st_mode) and current.st_uid == self.uid
                and stat.S_IMODE(current.st_mode) == 0o700
                and (current.st_dev, current.st_ino) == (self.root_identity.st_dev, self.root_identity.st_ino), "proof_root_changed")

    def write(self, name, payload):
        self.check()
        require(name in {"session.json", "proof-id", "denial.json", "approval.json", "reload.json", "worker-plan.json", "go"}
                and type(payload) is bytes and len(payload) <= 65536, "private_output_invalid")
        output = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.descriptor)
        with os.fdopen(output, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.fsync(self.descriptor)

    def admit(self, *, properties, coordinator, source_snapshot, destination_snapshot, effective_binds,
              checked_input_digests, checked_wrapper_authority_sha256):
        self.check()
        require(not self.admitted and checked_input_digests == self.digests, "input_digest_mismatch")
        expected_wrapper_sha = hashlib.sha256(json.dumps(self.vault_wrapper_authority, sort_keys=True,
            separators=(',', ':'), ensure_ascii=True, allow_nan=False).encode('ascii')).hexdigest()
        require(checked_wrapper_authority_sha256 == expected_wrapper_sha, 'wrapper_authority_invalid')
        require(all(properties.get(key) == value for key, value in LIMITS.items()), "aggregate_unqualified")
        require(type(coordinator) is dict and set(coordinator) == {"pid", "cgroupPath", "device", "inode"}
                and all(type(coordinator[key]) is int and coordinator[key] > 1 for key in ("pid", "device", "inode"))
                and type(coordinator["cgroupPath"]) is str
                and re.fullmatch(r"/sys/fs/cgroup/[A-Za-z0-9_.:/-]{1,512}", coordinator["cgroupPath"])
                and ".." not in coordinator["cgroupPath"].split("/"), "aggregate_unqualified")
        presented = display.verify_binding(self.witness, source_snapshot, destination_snapshot, effective_binds, self.now)
        session = {"schemaVersion": 1, "scope": "yoga-operator-local-toolbar-v1", "hostAlias": "yoga",
                   "proofId": self.proof_id, "operatorAccess": "local-console", "deadlineMonotonicNs": self.deadline,
                   "coordinator": dict(coordinator), "display": presented, "inputSha256": self.digests,
                   "vaultWrapperAuthority": self.vault_wrapper_authority, "wrapperSourceSha256": self.wrapper_source_sha256}
        payload = json.dumps(session, sort_keys=True).encode("ascii")
        self.write("session.json", payload)
        self.write("proof-id", self.proof_id.encode("ascii"))
        self.admitted = True
        return hashlib.sha256(payload).hexdigest()

    def accept_event(self, payload):
        self.check()
        require(self.admitted and len(self.events) < 3, "operator_event_invalid")
        event = parse(payload)
        case = tuple(STATEMENTS)[len(self.events)]
        require(type(event) is dict and set(event) == {"proofId", "case", "observed"}
                and event["proofId"] == self.proof_id and event["case"] == case
                and event["observed"] == STATEMENTS[case], "operator_event_invalid")
        interacted = case != "reload"
        attestation = {"schemaVersion": 1, "scope": "human-toolbar-attestation", "proofId": self.proof_id,
                       "case": case, "toolbarOpened": True, "consentChecked": interacted,
                       "connectClicked": interacted, "browserPromptSeen": interacted,
                       "browserDecision": {"denial": "denied", "approval": "approved", "reload": "not_requested"}[case]}
        self.write(case + ".json", json.dumps(attestation, sort_keys=True).encode("ascii"))
        self.events.append(case)
        return {"case": case, "operatorStatementRecorded": True, "observedBrowserProof": False}

    def receive_event(self, *, timeout=60.0):
        self.check()
        require(self.operator_descriptor is not None, "operator_channel_invalid")
        descriptor = self.operator_descriptor
        info = os.fstat(descriptor)
        require(stat.S_ISFIFO(info.st_mode) and info.st_nlink in (0, 1) and info.st_uid == self.uid
                and stat.S_IMODE(info.st_mode) == 0o600
                and (info.st_dev, info.st_ino) == self.operator_identity
                and fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE == os.O_RDONLY,
                "operator_channel_invalid")
        require(os.readlink(f"/proc/self/fd/{descriptor}") == f"pipe:[{info.st_ino}]", "operator_channel_invalid")
        require(type(timeout) in (int, float) and 0 <= timeout <= 60, "operator_event_invalid")
        until = min(self.deadline, self.now() + int(timeout * 10**9))
        while b"\n" not in self.operator_buffer:
            remaining = max(0.0, (until - self.now()) / 10**9)
            if not select.select([descriptor], [], [], remaining)[0]:
                if timeout == 0:
                    return None
                raise CoordinatorError("operator_event_timeout")
            data = os.read(descriptor, 2049)
            require(data and len(self.operator_buffer) + len(data) <= 6147, "operator_event_invalid")
            self.operator_buffer += data
            require(b"\n" in self.operator_buffer or len(self.operator_buffer) <= 2048, "operator_event_invalid")
        payload, self.operator_buffer = self.operator_buffer.split(b"\n", 1)
        require(0 < len(payload) <= 2048, "operator_event_invalid")
        return self.accept_event(payload)

    def finish(self, *, workload_exit, aggregate_empty, cancellation_requested=False):
        require(not self.finished and type(workload_exit) is int and type(aggregate_empty) is bool
                and type(cancellation_requested) is bool, "cleanup_invalid")
        self.finished = True
        self.close()
        return {"scope": "yoga-coordinator-support", "admitted": self.admitted,
                "operatorStatements": len(self.events), "cancelled": cancellation_requested,
                "deadlineExceeded": self.now() >= self.deadline, "descendantsEmpty": aggregate_empty,
                "executionPassed": workload_exit == 0 and aggregate_empty and not cancellation_requested
                                   and self.now() < self.deadline and self.admitted and self.events == list(STATEMENTS),
                "toolbarConsentProved": False}
