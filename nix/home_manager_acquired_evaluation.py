"""Offline genuine HM evaluation from independently frozen acquired byte proofs.

The caller separately declares both physical roots and trusted receipt digests.
No probe, ambient source cache, fetch, build, registration or activation is used.
The development artifact retains caller-declared dirty source qualification.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

import home_manager_acquired_inputs as acquired
import home_manager_acquisition as acquisition
import home_manager_artifact as artifact
from evaluation_runner import EvaluationFailure, evaluate
from home_manager_evaluation_runner import evaluation_command

MODULES = ("home-manager-qualified-evaluation.nix", "consume-bazel-artifact.nix",
           "home-manager.nix", "ownership-witness.nix", "service-witness.nix")
PREDICATES = {"genuineModule", "activationUnproved", "bytesUnverified", "witnessScope",
              "manifestBound", "recordGenerated"}
MAX_MODULE_BYTES = 65536
MAX_SECONDS = 900
require = acquired.require


def remaining(deadline):
    acquired.check_deadline(deadline)
    return min(300, max(1, int(deadline - time.monotonic())))


def read_at(parent, name, maximum, deadline, *, readonly=True):
    parent.check()
    fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                 dir_fd=parent.fd)
    try:
        before = acquired.snapshot(os.fstat(fd))
        require(stat.S_ISREG(before[2]) and before[3] in (0, os.getuid())
                and before[5] == 1 and 0 <= before[6] <= maximum
                and (not readonly or not before[2] & 0o222), "hm-evaluation-input-custody")
        data = bytearray()
        while len(data) <= maximum:
            acquired.check_deadline(deadline)
            chunk = os.read(fd, min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        require(len(data) == before[6] and before == acquired.snapshot(os.fstat(fd))
                == acquired.snapshot(os.stat(name, dir_fd=parent.fd, follow_symlinks=False)),
                "hm-evaluation-input-changed")
        parent.check()
        return bytes(data), before
    finally:
        os.close(fd)


def read_declared(path, maximum, deadline, *, readonly=False):
    # Only an explicitly declared runfile alias is resolved. No directory is
    # searched for missing inputs and no metadata nominates another path.
    logical = Path(path).absolute()
    selected = logical.resolve(strict=True)
    with acquisition.HeldDirectory(selected.parent, owned_leaf=False) as parent:
        data, facts = read_at(parent, selected.name, maximum, deadline, readonly=readonly)
        require(logical.resolve(strict=True) == selected, "hm-evaluation-declared-alias-changed")
    return data, (str(selected), facts)


def native_nix(path, deadline):
    selected = Path(path).resolve(strict=True)
    require(selected == acquisition.PINNED_NIX, "hm-evaluation-native-nix-pin")
    # Full native closure inputs/qualification belong to the declared Bazel
    # target. This predicate additionally excludes wrappers or arbitrary tools.
    with acquisition.HeldDirectory(selected.parent, owned_leaf=False) as parent:
        fd = os.open(selected.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=parent.fd)
        try:
            info = os.fstat(fd)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
                    and not info.st_mode & 0o222 and os.read(fd, 4) == b"\x7fELF",
                    "hm-evaluation-native-nix-custody")
            parent.check()
            acquired.check_deadline(deadline)
        finally:
            os.close(fd)
    return str(selected)


def pair_metadata(pair, deadline):
    pair.check()
    require(not os.fstat(pair.fd).st_mode & 0o222, "hm-evaluation-pair-envelope-writable")
    receipt = read_at(pair, "receipt.json", acquired.MAX_RECEIPT_BYTES, deadline)
    inventory = read_at(pair, "inventory.json", acquired.MAX_INVENTORY_BYTES, deadline)
    return receipt, inventory


def check_envelope(selected, capture, deadline, category):
    acquired.check_deadline(deadline)
    selected.check()
    require(acquired.snapshot(os.fstat(selected.fd)) == capture, category)


def pair_commitment(pair, deadline):
    # ctime/inode facts detect restored bytes or identical-content replacement,
    # in addition to the verifier's expected NAR digest before and after use.
    captured = {}
    pair.check()
    for name in acquired.NAMES:
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=pair.fd)
        try:
            nodes, facts = acquired.scan(fd, deadline)
            require(acquired.snapshot(os.stat(name, dir_fd=pair.fd, follow_symlinks=False)) == facts[""],
                    "hm-evaluation-pair-source-replaced")
            captured[name] = {"nodes": nodes, "facts": facts}
        finally:
            os.close(fd)
    pair.check()
    return hashlib.sha256(acquisition.encoded(captured)).hexdigest()


def tree_commitment(root, deadline):
    with acquisition.HeldDirectory(acquired.physical_path(root)) as selected:
        _, facts = acquired.scan(selected.fd, deadline)
        selected.check()
        return hashlib.sha256(acquisition.encoded(facts)).hexdigest()


def check_copied_modules(home, copied, directory_capture, captures, deadline):
    def directory_check():
        acquired.check_deadline(deadline)
        home.check()
        copied.check()
        require(acquired.snapshot(os.fstat(copied.fd)) == directory_capture
                == acquired.snapshot(os.stat("modules", dir_fd=home.fd, follow_symlinks=False)),
                "hm-evaluation-private-module-directory-changed")
    directory_check()
    for name in MODULES:
        require(read_at(copied, name, MAX_MODULE_BYTES, deadline) == captures[name],
                "hm-evaluation-private-module-changed")
    directory_check()


def copy_modules(modules, home, deadline):
    acquired.fields(modules, MODULES)
    home.check()
    require(stat.S_IMODE(os.fstat(home.fd).st_mode) == 0o700, "hm-evaluation-private-home")
    os.lseek(home.fd, 0, os.SEEK_SET)
    with os.scandir(home.fd) as entries:
        require(next(entries, None) is None, "hm-evaluation-requires-fresh-home")
    os.mkdir("modules", 0o700, dir_fd=home.fd)
    captures, copied_captures = {}, {}
    with acquisition.HeldDirectory(home.path / "modules") as output:
        for name in MODULES:
            data, facts = read_declared(modules[name], MAX_MODULE_BYTES, deadline)
            captures[name] = (data, facts)
            output.check()
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o600, dir_fd=output.fd)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fchmod(stream.fileno(), 0o444)
                os.fsync(stream.fileno())
                require(acquired.snapshot(os.fstat(stream.fileno()))
                        == acquired.snapshot(os.stat(name, dir_fd=output.fd, follow_symlinks=False)),
                        "hm-evaluation-module-copy-replaced")
                output.check()
            copied_captures[name] = read_at(output, name, MAX_MODULE_BYTES, deadline)
            require(copied_captures[name][0] == data, "hm-evaluation-module-copy-mismatch")
        output.mode(0o555)
        directory_capture = acquired.snapshot(os.fstat(output.fd))
        require(directory_capture == acquired.snapshot(os.stat("modules", dir_fd=home.fd,
                                                               follow_symlinks=False)),
                "hm-evaluation-private-module-directory-changed")
    home.check()
    return home.path / "modules" / MODULES[0], captures, copied_captures, directory_capture


def evaluate_acquired_pair(nix, modules, lock_bytes, pair_root, pair_receipt_sha256,
                           artifact_root, artifact_receipt_bytes, artifact_receipt_sha256,
                           private_home, *, system="x86_64-linux", deadline=None, current_selection=None, original_clock=None):
    require(system == "x86_64-linux", "hm-evaluation-platform-unqualified")
    started = time.monotonic()
    deadline = started + MAX_SECONDS if deadline is None else deadline
    if current_selection is None:
        require(original_clock is None and type(deadline) in (int, float) and started < deadline <= started + MAX_SECONDS,
                "hm-evaluation-enclosing-deadline")
    else:
        import home_manager_current_artifact as current
        require(type(original_clock) is tuple and len(original_clock)==2,"current-hm-original-clock-required")
        current.kernel.remaining(*original_clock)
        require(type(deadline) in (int,float) and started<deadline<=started+MAX_SECONDS
            and deadline<=current.kernel.envelope(*original_clock)/1e9,"current-hm-original-work-cutoff")
        require(artifact_root==str(Path(current_selection['root'])/'artifact')
            and artifact_receipt_sha256==current_selection['receiptSha256'],"current-hm-selected-artifact-arguments")
    def verify_selected_artifact():
        if current_selection is None:
            return artifact.verify_artifact(artifact_root,artifact_receipt_bytes,artifact_receipt_sha256,
                                            deadline_seconds=remaining(deadline), deadline=deadline)
        require(artifact.sha(artifact_receipt_bytes)==artifact_receipt_sha256,"current-hm-selected-receipt-argument")
        value=current.verify_selected(current_selection,deadline)
        require(current.read(Path(current_selection['root'])/'receipt.json',65536,deadline,
                             artifact_receipt_sha256)[0]==artifact_receipt_bytes,"current-hm-receipt-argument-changed")
        return value
    with acquisition.HeldDirectory(acquired.physical_path(pair_root)) as pair, \
            acquisition.held(private_home) as home, ExitStack() as custody:
        receipt, inventory = pair_metadata(pair, deadline)
        pair_envelope = acquired.snapshot(os.fstat(pair.fd))
        roots = {name: str(pair.path / name) for name in acquired.NAMES}
        before_commitment = pair_commitment(pair, deadline)
        before_pair = acquired.verify_acquired_pair(lock_bytes, receipt[0], pair_receipt_sha256,
            inventory[0], roots, deadline_seconds=remaining(deadline), deadline=deadline)
        before_artifact = verify_selected_artifact()
        require(before_artifact["system"] == system, "hm-evaluation-artifact-platform")
        expression, module_captures, copied_captures, directory_capture = copy_modules(modules, home, deadline)
        copied = custody.enter_context(acquisition.HeldDirectory(home.path / "modules", parent_anchor=home))
        # Directory rename/restore changes the containing inode's ctime even
        # when its descendants' bytes and inode facts are unchanged. No cache
        # or configuration writes to this fresh evaluator home are authorized.
        home_envelope = acquired.snapshot(os.fstat(home.fd))
        qualified_nix = native_nix(nix, deadline)
        sources = {name: {"source": roots[name]} for name in acquired.NAMES}
        artifact_input = {"directory": acquired.physical_path(artifact_root),
                          "narHash": before_artifact["narHash"],
                          "sourceRevision": before_artifact["sourceRevision"],
                          "channel": "development"}
        argv = evaluation_command(qualified_nix, expression, sources, system, artifact_input)
        require(pair_metadata(pair, deadline) == (receipt, inventory)
                and pair_commitment(pair, deadline) == before_commitment,
                "hm-evaluation-pair-changed-before-evaluator")
        check_envelope(pair, pair_envelope, deadline, "hm-evaluation-pair-envelope-changed")
        require(tree_commitment(artifact_root, deadline) == before_artifact["metadataCommitment"],
                "hm-evaluation-artifact-changed-before-evaluator")
        check_copied_modules(home, copied, directory_capture, copied_captures, deadline)
        check_envelope(home, home_envelope, deadline, "hm-evaluation-private-home-changed")
        predicates = evaluate(argv, str(home.path), deadline=deadline)
        require(isinstance(predicates, dict) and set(predicates) == PREDICATES
                and all(value is True for value in predicates.values()),
                "hm-evaluation-genuine-predicates-required")
        pair.check()
        home.check()
        require(pair_metadata(pair, deadline) == (receipt, inventory),
                "hm-evaluation-pair-metadata-changed")
        check_envelope(pair, pair_envelope, deadline, "hm-evaluation-pair-envelope-changed")
        check_envelope(home, home_envelope, deadline, "hm-evaluation-private-home-changed")
        after_pair = acquired.verify_acquired_pair(lock_bytes, receipt[0], pair_receipt_sha256,
            inventory[0], roots, deadline_seconds=remaining(deadline), deadline=deadline)
        require(before_pair == after_pair and pair_commitment(pair, deadline) == before_commitment,
                "hm-evaluation-pair-changed-through-evaluator")
        after_artifact = verify_selected_artifact()
        require(before_artifact == after_artifact, "hm-evaluation-artifact-changed-through-evaluator")
        for name in MODULES:
            require(read_declared(modules[name], MAX_MODULE_BYTES, deadline) == module_captures[name],
                    "hm-evaluation-declared-module-changed")
        check_copied_modules(home, copied, directory_capture, copied_captures, deadline)
        require(tree_commitment(artifact_root, deadline) == before_artifact["metadataCommitment"],
                "hm-evaluation-artifact-changed-through-evaluator")
        require(pair_metadata(pair, deadline) == (receipt, inventory)
                and pair_commitment(pair, deadline) == before_commitment,
                "hm-evaluation-pair-changed-through-evaluator")
        check_envelope(pair, pair_envelope, deadline, "hm-evaluation-pair-envelope-changed")
        check_envelope(home, home_envelope, deadline, "hm-evaluation-private-home-changed")
        home.check()
        pair.check()
    return {"schemaVersion": 1, "passed": True, "scope": "genuine-module-evaluation-only",
            "activation": "unproved", "generatedBytes": "unrealized-unverified",
            "nativeContinuity": "unproved", "system": system, "predicates": predicates,
            "pairReceiptSha256": pair_receipt_sha256,
            "sourceNars": {name: before_pair["sources"][name]["narHash"] for name in acquired.NAMES},
            "sourceCustodyBeforeAfterMatched": True,
            "artifactReceiptSha256": artifact_receipt_sha256,
            "artifact": {key: before_artifact[key] for key in (
                "archiveSha256", "manifestSha256", "narHash", "sourceRevision", "sourceDirty",
                "channel", "fullQt", "sourceQualification")},
            "artifactCustodyBeforeAfterMatched": True,
            "moduleSha256": {name: hashlib.sha256(module_captures[name][0]).hexdigest() for name in MODULES},
            "compiledSourceBindingProved": False, "releaseProvenance": "unproved",
            **({"artifactFamily":"current-coordinator-artifact-v1","currentArtifactAuthoritySha256":
                before_artifact['selectedAuthoritySha256']} if current_selection is not None else {})}


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("nix", "lock", "pair-root", "pair-receipt-sha256", "artifact-root",
                 "artifact-receipt", "artifact-receipt-sha256"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--module", action="append", default=[])
    args = parser.parse_args(arguments)
    try:
        require(os.environ.get("OMUX_EXECUTION_GUARD"), "hm-evaluation-contained-context-required")
        modules = {}
        for item in args.module:
            name, path = item.split("=", 1)
            require(name not in modules, "hm-evaluation-duplicate-module")
            modules[name] = path
        acquired.fields(modules, MODULES)
        deadline = time.monotonic() + 10
        lock, lock_capture = read_declared(args.lock, acquired.MAX_LOCK_BYTES, deadline)
        artifact_receipt, artifact_capture = read_declared(args.artifact_receipt, 65536, deadline,
                                                          readonly=True)
        scratch = Path(os.environ["TEST_TMPDIR"]).resolve(strict=True)
        with acquisition.HeldDirectory(scratch) as scratch_root, acquisition.private_worker(scratch_root) as home:
            report = evaluate_acquired_pair(args.nix, modules, lock, args.pair_root,
                args.pair_receipt_sha256, args.artifact_root, artifact_receipt,
                args.artifact_receipt_sha256, home)
            deadline = time.monotonic() + 10
            require(read_declared(args.lock, acquired.MAX_LOCK_BYTES, deadline) == (lock, lock_capture)
                    and read_declared(args.artifact_receipt, 65536, deadline, readonly=True)
                    == (artifact_receipt, artifact_capture), "hm-evaluation-declared-receipt-changed")
        print(json.dumps(report, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        result = {"passed": False, "scope": "genuine-module-evaluation-only", "activation": "unproved",
                  "category": error.category if isinstance(error, EvaluationFailure)
                  else "bounded-declared-input-or-custody-failed"}
        if isinstance(error, EvaluationFailure):
            result["diagnostic"] = error.diagnostic
        if getattr(error, "cleanup_category", None) is not None:
            result["cleanup_category"] = error.cleanup_category
        print(json.dumps(result, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
