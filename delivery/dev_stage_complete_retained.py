"""Fixed guarded TEST adapter for retained four-component byte staging.

The stage stays outside test outputs, which Bazel may chmod after this process.
No daemon, Qt client, browser, registration or provider operation is performed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

from dev_generation import (DIRECTORY_FLAGS, GenerationError, MAX_RECEIPT,
                            open_root, parse, read_file, select_generation)
from dev_stage import StageError, artifact
from dev_stage_selected import encode, input_hashes, produce

LABEL = "//delivery:dev_stage_complete_retained"
CHILD = "dev-stage-complete"
ADMISSION = "dev-stage-admission.json"
SCOPE = "guarded-development-four-component-byte-stage-v1"
DEADLINE_ENV = "OMUX_DEV_STAGE_DEADLINE_NS"
ENTRY_ENV = "OMUX_DEV_STAGE_ENTRY_NS"
RESERVE_NS = 30 * 10**9
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
SHA = re.compile(r"[0-9a-f]{64}")


def require(condition):
    if not condition:
        raise ValueError("complete-stage-boundary-refused")


def budget(entry, deadline, *, clock=time.monotonic_ns):
    require(type(entry) is int and type(deadline) is int and entry > 0
            and deadline - entry == 1200 * 10**9)
    now = clock()
    require(entry <= now < deadline - RESERVE_NS)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode))


def process(pid):
    require(type(pid) is int and pid > 1)
    directory = Path("/proc") / str(pid)
    require(directory.stat().st_uid == os.geteuid())
    raw = (directory / "stat").read_text()
    value = raw[raw.rindex(")") + 2:].split()[19]
    require(value.isascii() and value.isdecimal() and int(value) > 0)
    return value


class Epoch:
    def __init__(self, environment, *, clock=time.monotonic_ns):
        self.descriptor = None
        self.clock = clock
        root = environment.get("OMUX_EXECUTION_GUARD", "")
        require(type(root) is str and len(root) <= 4096 and root.startswith("/"))
        self.root = Path(root)
        require(str(self.root) == root and UUID.fullmatch(self.root.name))
        entry = environment.get(ENTRY_ENV, "")
        deadline = environment.get(DEADLINE_ENV, "")
        require(type(entry) is str and type(deadline) is str
                and re.fullmatch(r"[0-9]{1,20}", entry)
                and re.fullmatch(r"[0-9]{1,20}", deadline))
        self.entry, self.deadline = int(entry), int(deadline)
        budget(self.entry, self.deadline, clock=self.clock)
        self.descriptor = open_root(self.root)
        try:
            self.identity = identity(os.fstat(self.descriptor))
            raw, _, _ = read_file(self.descriptor, ADMISSION, 8192)
            value = parse(raw)
            require(type(value) is dict and set(value) == {"schemaVersion", "scope", "label",
                "epoch", "entryMonotonicNs", "deadlineMonotonicNs", "graphSha256"}
                and type(value["schemaVersion"]) is int and value["schemaVersion"] == 1
                and value["scope"] == SCOPE and value["label"] == LABEL
                and value["epoch"] == self.root.name
                and type(value["entryMonotonicNs"]) is int
                and type(value["deadlineMonotonicNs"]) is int
                and value["entryMonotonicNs"] == self.entry
                and value["deadlineMonotonicNs"] == self.deadline
                and type(value["graphSha256"]) is str and SHA.fullmatch(value["graphSha256"]))
            self.admission = raw
            self.graph = value["graphSha256"]
            supervisor, _, _ = read_file(self.descriptor, "supervisor.json", 8192)
            witness = parse(supervisor)
            require(type(witness) is dict and set(witness) == {"id", "pid", "start_ticks"}
                and witness["id"] == self.root.name
                and type(witness["pid"]) is int and type(witness["start_ticks"]) is str)
            require(process(witness["pid"]) == witness["start_ticks"])
            self.supervisor, self.witness = supervisor, witness
            go, _, _ = read_file(self.descriptor, "go", 0)
            require(go == b"")
            self.recheck()
        except BaseException:
            self.close()
            raise

    def recheck(self):
        budget(self.entry, self.deadline, clock=self.clock)
        fresh = open_root(self.root)
        try:
            require(identity(os.fstat(self.descriptor)) == self.identity
                and identity(os.fstat(fresh)) == self.identity)
        finally:
            os.close(fresh)
        require(read_file(self.descriptor, ADMISSION, 8192)[0] == self.admission
            and read_file(self.descriptor, "supervisor.json", 8192)[0] == self.supervisor
            and read_file(self.descriptor, "go", 0)[0] == b"")
        require(process(self.witness["pid"]) == self.witness["start_ticks"])
        try:
            os.stat("receipt.json", dir_fd=self.descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            require(False)  # An already-completed epoch is never an admission.

    def allocate(self):
        self.recheck()
        os.mkdir(CHILD, mode=0o700, dir_fd=self.descriptor)
        self.stage = self.root / CHILD
        self.stage_fd = open_root(self.stage)
        self.stage_identity = identity(os.fstat(self.stage_fd))
        require(not os.listdir(self.stage_fd))
        return self.stage

    def stage_recheck(self):
        self.recheck()
        fresh = open_root(self.stage)
        try:
            require(identity(os.fstat(self.stage_fd)) == self.stage_identity
                and identity(os.fstat(fresh)) == self.stage_identity)
        finally:
            os.close(fresh)

    def close(self):
        for name in ("stage_fd", "descriptor"):
            descriptor = getattr(self, name, None)
            if descriptor is not None:
                os.close(descriptor)
                setattr(self, name, None)


def output_directory(root, epoch, *, empty=True):
    require(type(root) is str and len(root) <= 4096 and root.startswith("/"))
    path = Path(root)
    require(str(path) == root)
    relative = path.relative_to(epoch.root / "output-base")
    require(re.fullmatch(r"(?:sandbox/(?:processwrapper-sandbox|linux-sandbox)/[1-9][0-9]*/)?"
        r"execroot/_main/bazel-out/[A-Za-z0-9_.+-]+/testlogs/delivery/"
        r"dev_stage_complete_retained/test.outputs", relative.as_posix()))
    descriptor = os.open("/", DIRECTORY_FLAGS)
    try:
        for component in path.parts[1:]:
            parent = os.fstat(descriptor)
            sticky = parent.st_uid == 0 and bool(parent.st_mode & stat.S_ISVTX)
            require(parent.st_uid in (0, os.geteuid()) and (not parent.st_mode & 0o022 or sticky))
            child = os.open(component, DIRECTORY_FLAGS, dir_fd=descriptor)
            try:
                if sticky:
                    require(os.fstat(child).st_uid == os.geteuid())
            except BaseException:
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        require(info.st_uid == os.geteuid() and not info.st_mode & 0o022)
        if empty:
            require(not os.listdir(descriptor))
        return descriptor, path, identity(info)
    except BaseException:
        os.close(descriptor)
        raise


def recheck_output(descriptor, path, expected, epoch):
    fresh, _, observed = output_directory(str(path), epoch, empty=False)
    try:
        require(identity(os.fstat(descriptor)) == expected and observed == expected)
    finally:
        os.close(fresh)


def publish(descriptor, name, data):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o600, dir_fd=descriptor)
    try:
        view = memoryview(data)
        while view:
            count = os.write(fd, view)
            require(count > 0)
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    require(read_file(descriptor, name, max(len(data), 1))[0] == data)


def run(args, environment=None):
    environment = os.environ if environment is None else environment
    require(len(args.runtime_file) <= 4096 and len(args.qt_runtime_file) <= 4096
            and 0 < len(args.qt_plugin) <= 128 and args.runtime_file and args.qt_runtime_file)
    epoch = Epoch(environment)
    output = None
    try:
        output, output_path, output_identity = output_directory(
            environment.get("TEST_UNDECLARED_OUTPUTS_DIR", ""), epoch)
        raw = artifact(args.resolution_witness)
        require(len(raw) <= MAX_RECEIPT)
        witness = parse(raw)
        expected = input_hashes(args.core, args.daemon, args.extension, args.control)
        root = epoch.allocate()
        # Exactly one existing producer invocation, then an independent consumer
        # joins its captured id/digest to independently measured declared inputs.
        facts = produce(root, args.core, args.daemon, args.extension, args.metadata,
            runtime_files=args.runtime_file, patchelf=args.patchelf, ca_bundle=args.ca_bundle,
            control=args.control, qt_runtime_files=args.qt_runtime_file,
            qt_plugins=args.qt_plugin, resolution_witness=witness)
        epoch.stage_recheck()
        require(input_hashes(args.core, args.daemon, args.extension, args.control) == expected)
        selected = select_generation(root, facts["generation"], facts["receiptSha256"],
            expected_artifacts=expected, require_portable=True)
        require(selected.control is not None and dict(selected.artifact_sha256) == expected
                and facts["artifacts"] == expected and facts.get("controlStaged") is True)
        selected_fd = open_root(selected.directory)
        try:
            receipt = read_file(selected_fd, "receipt.json", MAX_RECEIPT)[0]
        finally:
            os.close(selected_fd)
        require(hashlib.sha256(receipt).hexdigest() == selected.receipt_sha256)
        result = {"schemaVersion": 1, "scope": SCOPE, "guardEpoch": epoch.root.name,
            "stageChild": CHILD, "graphSha256": epoch.graph, "selection": facts,
            "receiptBytes": len(receipt), "receiptSha256": selected.receipt_sha256,
            "outerCleanupVerified": False, "qtExecuted": False,
            "daemonRestarted": False, "chromiumReloaded": False, "providerAccess": False}
        encoded = encode(result)
        epoch.stage_recheck()
        recheck_output(output,output_path,output_identity,epoch)
        publish(output, "dev-stage-receipt.json", receipt)
        publish(output, "dev-stage-selection.json", encoded)
        os.fsync(output)
        require(set(os.listdir(output)) == {"dev-stage-receipt.json", "dev-stage-selection.json"})
        # Revalidate after publication. A later outer failure still disqualifies
        # the TEST result; the tuple never claims its enclosing cleanup succeeded.
        epoch.stage_recheck()
        select_generation(root, selected.generation, selected.receipt_sha256,
            expected_artifacts=expected, require_portable=True)
        recheck_output(output,output_path,output_identity,epoch)
        return result
    finally:
        if output is not None:
            os.close(output)
        epoch.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("core", "daemon", "control", "extension", "metadata", "resolution-witness",
                 "patchelf", "ca-bundle"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("runtime-file", "qt-runtime-file", "qt-plugin"):
        parser.add_argument("--" + name, type=Path, action="append", default=[])
    args = parser.parse_args()
    try:
        run(args)
        print("OMUX_DEVELOPMENT_COMPLETE_STAGE_BYTES_VERIFIED")
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError, StageError, GenerationError):
        print("OMUX_DEVELOPMENT_COMPLETE_STAGE_REFUSED", file=sys.stderr)
        return 125


if __name__ == "__main__":
    sys.exit(main())
