"""Finite acquisition of the exact Lab HM pair into an action-owned private store.

Run only as its separately admitted Bazel producer. No evaluation, build,
activation, shared-store registration or caller-selected source is supported.
The emitted receipt must be frozen independently before another action trusts it.
"""
import argparse
import base64
import hashlib
import json
import math
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import shutil
import stat
import subprocess
import threading
import time
import uuid
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from contextvars import ContextVar
import sys

import home_manager_acquired_inputs as acquired
import home_manager_source_pack as source_pack
from home_manager_inputs import paired_lock

PINNED_NIX = Path("/nix/store/fphbr6vvc2fdmx02nkagnbx0nv04f709-nix-2.34.6/bin/nix")
PINNED_CA = Path("/nix/store/zp564phiicll8d53d973gbh8y3iiwlm7-nss-cacert-3.121/etc/ssl/certs/ca-bundle.crt")
MAX_SECONDS = 1200
# Fixed-input preparation allowance, not a product latency objective. Prefetch,
# export and their byte proofs share this absolute deadline, clipped by the
# overall budget. The enclosing Bazel/guard timers can terminate the action
# earlier; this does not promise two complete source allowances plus publication.
SOURCE_SECONDS = 600
MAX_STDOUT = 65536
MAX_STDERR = 262144
MAX_PRIVATE_NODES = 600000
MAX_PRIVATE_METADATA = 128 * 1024 * 1024
DISK_BUDGET = 8 * 1024 * 1024 * 1024
FREE_FLOOR = 4 * 1024 * 1024 * 1024
MAX_RETAINED_BYTES = 4 * 1024 * 1024 * 1024
MONITOR_SCAN_SECONDS = 1
MAX_PENDING_SYNCS = 4
MAX_DIAGNOSTIC_EVENTS = 64
MAX_DIAGNOSTIC_BYTES = 32768
PHASES = {"inputs", "source", "prefetch", "prefetch-admission", "prefetch-monitor", "prefetch-completion",
          "private-budget-scan", "source-inventory", "source-nar", "source-recheck", "export",
          "copy", "copy-baseline", "copy-final-budget", "copied-proof", "metadata",
          "pair-proof", "publication", "publication-witness", "publication-proof",
          "publication-recheck", "publication-rename", "packed-source", "owned-child-cleanup", "owned-tree-cleanup"}
COUNTERS = {"privateScanCount", "privateScanMs", "narPassCount", "narPassMs",
            "pairProofCount", "pairProofMs", "copiedNodes", "copiedBytes", "monitorPolls",
            "ancestryCheckCount", "ancestryCheckMs", "fileSyncCount", "fileSyncMs",
            "sourceExpectedNodes", "sourceExpectedBytes"}
PROGRESS = ContextVar("omux_hm_acquisition_progress", default=None)
ERROR_SUFFIXES = {
    "acquisition": frozenset((
        "diagnostic-event diagnostic-counter diagnostic-phase diagnostic-depth diagnostic-source-total "
        "held-directory-owner held-directory-custody held-directory-replaced held-directory-mode "
        "held-directory-closed held-parent-scope held-parent-lifetime held-parent-prefix "
        "output-metadata-bound lock-regular-byte-bound lock-replaced native-input-pin native-input-custody "
        "native-nix-required source-name private-inventory-bound private-mount-or-owner private-depth-bound "
        "private-path-bound private-directory-replaced private-file-bound private-special-file private-disk-budget "
        "free-floor private-scan-mode private-ancestor-changed inherited-file-limit child-output-bound child-live-group child-failed private-source-path "
        "prefetch-hash private-source-alias source-nar-bound hash-root export-nar-mismatch export-source-changed "
        "export-root-changed copy-depth-bound copy-directory-replaced copy-file-or-tree-bound copy-short-write "
        "copy-file-size copy-file-replaced copy-link-replaced copy-undeclared-node export-output-replaced "
        "copy-sync-bound copy-sync-owner "
        "export-copy-mismatch metadata-name metadata-replaced metadata-custody metadata-byte-mismatch "
        "metadata-changed-before-publication source-changed-through-publication rollback-envelope-replaced "
        "rollback-destination-exists publication-envelope-mode output-exists publication-source-replaced "
        "publication-replaced retained-pair-bound output-filesystem cleanup-custody cleanup-inventory-bound "
        "cleanup-replaced cleanup-fd-support contained-context-required action-filesystem requires-empty-outputs"
    ).split()),
    "source": frozenset((
        "pack-header-bound pack-inventory pack-source-inventory pack-truncated pack-growth "
        "pack-source-changed pack-output-changed pack-byte-bound pack-short-write pack-custody pack-closed pack-readback"
    ).split()),
    "acquired": frozenset((
        "duplicate-json-key metadata-byte-bound metadata-fields verification-deadline physical-root unsafe-ancestor "
        "ancestor-changed tree-root-custody tree-node-owner tree-link-custody tree-node-writable tree-file-custody "
        "tree-entry-or-metadata-bound tree-entry-bound tree-path-bound tree-metadata-bound directory-changed "
        "tree-byte-bound link-target-bound tree-special-file tree-node-changed hash-parent-changed hash-file-changed "
        "deadline-bound paired-lock-invalid receipt-binding lock-binding inventory-binding inventory-schema "
        "physical-root-alias source-lock-binding inventory-entry-bound invalid-nar-inventory inventory-directory-root "
        "complete-inventory-mismatch nar-byte-bound undeclared-hash-input source-nar-mismatch tree-changed-during-hash "
        "selected-root-replaced pair-changed-during-verification"
    ).split()),
}
require = acquired.require


class Progress:
    """Finite redacted phase evidence; never stores paths, argv or native output."""
    def __init__(self, sink=None):
        self.sink = sink if sink is not None else sys.stderr
        self.started = time.monotonic()
        self.current = ("pair", "inputs", self.started, self.started, None)
        self.counters = {name: 0 for name in COUNTERS}
        self.stack = []
        self.failure = None
        self.cleanup_category = None
        self.events = self.bytes = 0

    def milliseconds(self, start):
        return min((MAX_SECONDS + SOURCE_SECONDS) * 1000,
                   max(0, int((time.monotonic() - start) * 1000)))

    def snapshot(self):
        source, phase_name, phase_start, source_start, deadline = self.current
        result = {"source": source, "phase": phase_name,
                  "phasePath": list(self.stack),
                  "elapsedMs": self.milliseconds(self.started),
                  "sourceElapsedMs": self.milliseconds(source_start),
                  "phaseElapsedMs": self.milliseconds(phase_start)}
        if deadline is not None:
            result["remainingMs"] = min(MAX_SECONDS * 1000,
                max(0, int((deadline - time.monotonic()) * 1000)))
        return result

    def event(self, state):
        require(state in {"begin", "end"}, "acquisition-diagnostic-event")
        if self.events >= MAX_DIAGNOSTIC_EVENTS:
            return
        payload = encoded({"event": state, **self.snapshot(), "counters": self.counters}) + b"\n"
        if self.bytes + len(payload) > MAX_DIAGNOSTIC_BYTES:
            return
        self.events += 1
        self.bytes += len(payload)
        self.sink.write(payload.decode())
        self.sink.flush()

    def add(self, counter, amount):
        require(counter in COUNTERS and type(amount) is int and amount >= 0,
                "acquisition-diagnostic-counter")
        require(amount <= MAX_RETAINED_BYTES, "acquisition-diagnostic-counter")
        self.counters[counter] = min(1 << 53, self.counters[counter] + amount)

    def capture(self, error):
        if self.failure is None:
            self.failure = {**self.snapshot(), "category": failure_category(error)}
        elif self.current[1] in {"owned-child-cleanup", "owned-tree-cleanup"}:
            self.cleanup_category = failure_category(error)

    def summary(self):
        result = {**(self.failure or self.snapshot()), "counters": dict(self.counters),
                  "finalElapsedMs": self.milliseconds(self.started),
                  "diagnosticEvents": self.events, "diagnosticBytes": self.bytes}
        if self.cleanup_category is not None:
            result["cleanupCategory"] = self.cleanup_category
        return result


@contextmanager
def phase(name, *, source=None, deadline=None, emit=True):
    require(name in PHASES and (source is None or source in (*acquired.NAMES, "pair", "cleanup")),
            "acquisition-diagnostic-phase")
    require(type(emit) is bool and (deadline is None
            or (type(deadline) in (int, float) and math.isfinite(deadline))),
            "acquisition-diagnostic-phase")
    progress = PROGRESS.get()
    if progress is None:
        yield
        return
    previous = progress.current
    require(len(progress.stack) < 16, "acquisition-diagnostic-depth")
    progress.stack.append(name)
    now = time.monotonic()
    selected_source = source if source is not None else previous[0]
    source_start = previous[3] if selected_source == previous[0] else now
    progress.current = (selected_source, name, now, source_start,
                        deadline if deadline is not None else previous[4])
    if name == "source":
        progress.counters["sourceExpectedNodes"] = 0
        progress.counters["sourceExpectedBytes"] = 0
    try:
        if emit:
            progress.event("begin")
        yield
        if emit:
            progress.event("end")
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, MemoryError, subprocess.TimeoutExpired,
            KeyboardInterrupt) as error:
        progress.capture(error)
        raise
    finally:
        progress.current = previous
        progress.stack.pop()


def count(counter, amount=1):
    progress = PROGRESS.get()
    if progress is not None:
        progress.add(counter, amount)


def expected_source(nodes):
    progress = PROGRESS.get()
    if progress is not None:
        total_bytes = sum(node["size"] for node in nodes if node["type"] == "regular")
        require(1 <= len(nodes) <= acquired.MAX_NODES and type(total_bytes) is int
                and 0 <= total_bytes <= acquired.MAX_TREE_BYTES, "acquisition-diagnostic-source-total")
        # This runs only after the original pinned NAR and full inventory proof.
        # Exclude the already-created source root to match copiedNodes counting.
        progress.counters["sourceExpectedNodes"] = len(nodes) - 1
        progress.counters["sourceExpectedBytes"] = total_bytes


def directory_identity(info):
    return info.st_dev, info.st_ino, info.st_uid


class HeldDirectory:
    """Hold every nofollow ancestor and witness its live pathname identity."""
    def __init__(self, path, *, owned_leaf=True, parent_anchor=None):
        self.path = Path(acquired.physical_path(Path(path).absolute()))
        self.chain = []
        self._owned_start = 0
        self._closed = False
        self._lifetime = object()
        self._parent_anchor = None
        self._parent_lifetime = None
        self._parent_prefix = ()
        self._owners = ()

        def remember(parent, name, fd):
            try:
                witness = directory_identity(os.fstat(fd))
            except BaseException as original:
                try:
                    os.close(fd)
                except BaseException:
                    original.cleanup_category = "acquisition-held-close-refused"
                raise
            self.chain.append((parent, name, fd, witness))

        try:
            if parent_anchor is None:
                fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                remember(None, "", fd)
                components = self.path.parts[1:]
            else:
                require(isinstance(parent_anchor, HeldDirectory)
                        and parent_anchor.path in self.path.parents, "acquisition-held-parent-scope")
                require(len(parent_anchor._owners) < acquired.MAX_DEPTH,
                        "acquisition-held-parent-scope")
                parent_anchor.check()
                # The child borrows these exact descriptors, not reopened
                # equivalents. Freeze the witnesses and record owner lifetime.
                self._parent_anchor = parent_anchor
                self._parent_lifetime = parent_anchor._lifetime
                self._parent_prefix = tuple(parent_anchor.chain)
                self._owners = parent_anchor._owners + (
                    (parent_anchor, self._parent_lifetime, self._parent_prefix),)
                self.chain = list(self._parent_prefix)
                self._owned_start = len(self.chain)
                components = self.path.relative_to(parent_anchor.path).parts
            for component in components:
                parent = self.chain[-1][2]
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                | os.O_CLOEXEC, dir_fd=parent)
                remember(parent, component, child)
            self.fd = self.chain[-1][2]
            self.check()
            require(not owned_leaf or os.fstat(self.fd).st_uid == os.getuid(),
                    "acquisition-held-directory-owner")
        except BaseException as original:
            try:
                self.close()
            except BaseException:
                original.cleanup_category = "acquisition-held-close-refused"
            raise

    def check(self):
        progress = PROGRESS.get()
        if progress is None:
            return self.check_held()
        progress.add("ancestryCheckCount", 1)
        started = time.monotonic()
        try:
            return self.check_held()
        finally:
            progress.add("ancestryCheckMs", min((MAX_SECONDS + SOURCE_SECONDS) * 1000,
                                               max(0, int((time.monotonic() - started) * 1000))))

    def check_held(self):
        require(not self._closed and self._lifetime is not None and self.chain
                and self.fd == self.chain[-1][2], "acquisition-held-directory-closed")
        if self._parent_anchor is not None:
            require(tuple(self.chain[:self._owned_start]) == self._parent_prefix,
                    "acquisition-held-parent-prefix")
        for owner, lifetime, prefix in self._owners:
            require(not owner._closed and owner._lifetime is lifetime,
                    "acquisition-held-parent-lifetime")
            require(tuple(owner.chain) == prefix and owner.fd == prefix[-1][2],
                    "acquisition-held-parent-prefix")
        for parent, name, fd, identity in self.chain:
            info = os.fstat(fd)
            protected = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            require(directory_identity(info) == identity and stat.S_ISDIR(info.st_mode)
                    and info.st_uid in (0, os.getuid())
                    and (not info.st_mode & 0o022 or protected),
                    "acquisition-held-directory-custody")
            if parent is not None:
                require(directory_identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == identity,
                        "acquisition-held-directory-replaced")

    def mode(self, mode):
        self.check()
        os.fchmod(self.fd, mode)
        require(stat.S_IMODE(os.fstat(self.fd).st_mode) == mode,
                "acquisition-held-directory-mode")
        self.check()

    def close(self):
        self._closed = True
        self._lifetime = None
        owned = tuple(reversed(self.chain[self._owned_start:]))
        self.chain = []
        self._parent_anchor = None
        self._parent_prefix = ()
        self._parent_lifetime = None
        self._owners = ()
        failure = None
        for _, _, fd, _ in owned:
            try:
                os.close(fd)
            except BaseException as error:
                failure = failure or error
        if failure is not None:
            raise failure

    def __enter__(self):
        return self

    def __exit__(self, error_type, original, traceback):
        try:
            self.close()
        except BaseException:
            if original is None:
                raise
            original.cleanup_category = "acquisition-held-close-refused"


@contextmanager
def held(directory, *, owned_leaf=True):
    if isinstance(directory, HeldDirectory):
        directory.check()
        yield directory
    else:
        with HeldDirectory(directory, owned_leaf=owned_leaf) as selected:
            yield selected


def check_copy_anchors(root, staging):
    # Only the genuine borrowed view covers both anchors. It checks every
    # shared FD, path link and current permission directly on every tick, and
    # validates the root owner's lifetime even if FD numbers were reused.
    if staging._parent_anchor is root and staging._owned_start == len(root.chain) \
            and staging._parent_prefix == tuple(root.chain):
        staging.check()
    else:
        root.check()
        staging.check()


def file_sync(fd):
    progress = PROGRESS.get()
    if progress is None:
        return os.fsync(fd)
    progress.add("fileSyncCount", 1)
    started = time.monotonic()
    try:
        return os.fsync(fd)
    finally:
        progress.add("fileSyncMs", min((MAX_SECONDS + SOURCE_SECONDS) * 1000,
                                     max(0, int((time.monotonic() - started) * 1000))))


class FileSyncLease:
    """A registered duplicate-FD lease, claimed/cancelled under one lock."""
    def __init__(self, fd, parent, name, before, blocks):
        self.fd, self.parent = fd, parent
        self.name, self.before, self.blocks = name, before, blocks
        self.lock, self.finished = threading.Lock(), threading.Event()
        self.state = "pending"
        self.error, self.elapsed, self.counted = None, 0, False

    def run(self):
        with self.lock:
            if self.state != "pending":
                return  # Cancellation prohibits any use of a reused FD number.
            self.state = "running"
        started, error, elapsed = None, None, 0
        try:
            started = time.monotonic()
            os.fsync(self.fd)  # Worker never reads paths or writes content.
        except BaseException as failure:
            error = failure
        finally:
            try:
                if started is not None:
                    elapsed = min((MAX_SECONDS + SOURCE_SECONDS) * 1000,
                        max(0, int((time.monotonic() - started) * 1000)))
            except BaseException as failure:
                error = error or failure
            with self.lock:
                self.error, self.elapsed, self.state = error, elapsed, "done"
            self.finished.set()  # No FD use after this ownership-release event.

    def cancel(self):
        with self.lock:
            if self.state == "pending":
                self.state = "cancelled"
                self.finished.set()

    def result(self, *, allow_cancelled=False):
        with self.lock:
            if allow_cancelled and self.state == "cancelled":
                return
            require(self.finished.is_set() and self.state == "done",
                    "acquisition-copy-sync-owner")
            if not self.counted:
                count("fileSyncCount")
                count("fileSyncMs", self.elapsed)
                self.counted = True
            error = self.error
        if error is not None:
            raise error

    def close(self):
        require(self.finished.is_set(), "acquisition-copy-sync-owner")
        failure = None
        for attribute in ("parent", "fd"):
            owned = getattr(self, attribute)
            setattr(self, attribute, None)
            if owned is not None:
                try:
                    os.close(owned)
                except OSError as error:
                    failure = failure or error
        if failure is not None:
            raise failure


class FileSyncOwner:
    """At most four queued/running per-file flushes, joined before proof/cleanup.

    The copy thread remains the only namespace/content writer. Kernel fsync is
    uncancellable, as in the serial implementation; cancellation joins active
    calls before closing their descriptors. fileSyncMs is summed task time,
    including overlap, rather than wall time.
    """
    def __init__(self, tick, charge_blocks):
        self.tick, self.charge_blocks = tick, charge_blocks
        self.pending = deque()
        self.executor = ThreadPoolExecutor(max_workers=MAX_PENDING_SYNCS,
                                           thread_name_prefix="omux-owned-file-sync")
        self.closed = False

    def submit(self, fd, parent_fd, name, blocks):
        require(not self.closed, "acquisition-copy-sync-owner")
        self.check_failed()
        self.tick()
        if len(self.pending) == MAX_PENDING_SYNCS:
            self.finish_one()
        require(len(self.pending) < MAX_PENDING_SYNCS, "acquisition-copy-sync-bound")
        self.tick()
        self.check_failed()
        before = acquired.snapshot(os.fstat(fd))
        require(before == acquired.snapshot(os.stat(name, dir_fd=parent_fd, follow_symlinks=False)),
                "acquisition-copy-file-replaced")
        duplicate, parent, lease = None, None, None
        try:
            duplicate = os.dup(fd)
            parent = os.dup(parent_fd)
            require(acquired.snapshot(os.fstat(duplicate)) == before
                    == acquired.snapshot(os.stat(name, dir_fd=parent, follow_symlinks=False)),
                    "acquisition-copy-file-replaced")
            self.tick()
            lease = FileSyncLease(duplicate, parent, name, before, blocks)
            # Register ownership before admission, including ambiguous submit
            # failures after an executor has queued/started the callable.
            self.pending.append(lease)
            self.executor.submit(lease.run)
        except BaseException as original:
            self.closed = True
            progress = PROGRESS.get()
            if progress is not None:
                progress.capture(original)
            if lease is not None:
                cleanup_error = self.cleanup_lease(lease)
                # Even append which retained an item before raising remains
                # bounded/owned; remove only this exact registered lease.
                if lease in self.pending:
                    self.pending.remove(lease)
                if cleanup_error is not None and progress is not None:
                    progress.cleanup_category = failure_category(cleanup_error)
                if cleanup_error is not None:
                    original.cleanup_category = "acquisition-copy-sync-cleanup-refused"
            else:
                for owned in (parent, duplicate):
                    if owned is not None:
                        try:
                            os.close(owned)
                        except OSError as cleanup_error:
                            if progress is not None:
                                progress.cleanup_category = failure_category(cleanup_error)
                            original.cleanup_category = "acquisition-copy-sync-cleanup-refused"
            raise

    def check_failed(self):
        # Inspect without consuming/counting results; cleanup remains the sole
        # owner of every retained task. A later completed failure must stop
        # admissions even while the oldest successful fsync is still blocked.
        for lease in self.pending:
            with lease.lock:
                error = lease.error if lease.state == "done" else None
            if error is not None:
                raise error

    def finish_one(self):
        # Keep the task registered until result/witness checks finish, so an
        # exception cannot orphan descriptors or close an in-flight worker FD.
        lease = self.pending[0]
        while not lease.finished.is_set():
            self.check_failed()
            self.tick()
            lease.finished.wait(0.01)
        self.tick()
        failure = None
        try:
            lease.result()
            self.charge_blocks(os.fstat(lease.fd), lease.blocks)
            require(acquired.snapshot(os.fstat(lease.fd)) == lease.before
                    == acquired.snapshot(os.stat(lease.name, dir_fd=lease.parent, follow_symlinks=False)),
                    "acquisition-copy-file-replaced")
            self.tick()
        except BaseException as error:
            failure = error
        finally:
            self.pending.popleft()
            try:
                lease.close()
            except OSError as error:
                failure = failure or error
        if failure is not None:
            raise failure

    def drain(self):
        while self.pending:
            self.finish_one()
        self.tick()

    def __enter__(self):
        return self

    @staticmethod
    def cleanup_lease(lease):
        lease.cancel()  # Atomic with worker claim, so unclaimed work uses no FD.
        failure = None
        while not lease.finished.is_set():
            try:
                time.sleep(0.01)
            except BaseException as error:
                failure = failure or error
        try:
            lease.result(allow_cancelled=True)
        except BaseException as error:
            failure = failure or error
        try:
            lease.close()
        except OSError as error:
            failure = failure or error
        return failure

    def __exit__(self, error_type, original, traceback):
        self.closed = True
        progress = PROGRESS.get()
        if original is not None and progress is not None:
            progress.capture(original)  # Freeze phase/deadline before draining workers.
        cleanup_error = None
        if original is None and self.pending:
            cleanup_error = ValueError("acquisition-copy-sync-owner")
            if progress is not None:
                progress.capture(cleanup_error)
        # Stop new admissions and cancel only tasks which have not started.
        for lease in self.pending:
            lease.cancel()
        while self.pending:
            failure = self.cleanup_lease(self.pending.popleft())
            cleanup_error = cleanup_error or failure
        # Every FD lease is now safely released even if executor bookkeeping
        # refuses a join. A permanent refusal is finite failure, never retry.
        try:
            self.executor.shutdown(wait=True, cancel_futures=True)
        except BaseException as failure:
            cleanup_error = cleanup_error or failure
        if cleanup_error is not None:
            if original is None:
                raise cleanup_error
            original.cleanup_category = "acquisition-copy-sync-cleanup-refused"
            if progress is not None:
                progress.cleanup_category = failure_category(cleanup_error)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha(payload):
    return hashlib.sha256(payload).hexdigest()


def bounded_encoded(value, maximum):
    payload = bytearray()
    encoder = json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    for chunk in encoder.iterencode(value):
        content = chunk.encode()
        require(len(payload) + len(content) <= maximum, "acquisition-output-metadata-bound")
        payload.extend(content)
    return bytes(payload)


def read_lock(path):
    # Read the declared runfile, not an ambient Lab path. A copied runfile can
    # be a Bazel alias; its contents still must satisfy the fixed pair contract.
    declared = Path(path).absolute()
    selected = declared.resolve(strict=True)
    deadline = time.monotonic() + 10
    with HeldDirectory(selected.parent, owned_leaf=False) as parent:
        fd = os.open(selected.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
                     | os.O_CLOEXEC, dir_fd=parent.fd)
        try:
            before = acquired.snapshot(os.fstat(fd))
            require(stat.S_ISREG(before[2]) and before[6] <= acquired.MAX_LOCK_BYTES,
                    "acquisition-lock-regular-byte-bound")
            require(before == acquired.snapshot(os.stat(selected.name, dir_fd=parent.fd,
                                                        follow_symlinks=False)),
                    "acquisition-lock-replaced")
            payload = bytearray()
            while len(payload) <= acquired.MAX_LOCK_BYTES:
                acquired.check_deadline(deadline)
                chunk = os.read(fd, min(16384, acquired.MAX_LOCK_BYTES + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
            require(before == acquired.snapshot(os.fstat(fd))
                    == acquired.snapshot(os.stat(selected.name, dir_fd=parent.fd,
                                                 follow_symlinks=False))
                    and declared.resolve(strict=True) == selected,
                    "acquisition-lock-replaced")
            parent.check()
            payload = bytes(payload)
        finally:
            os.close(fd)
    locked = paired_lock(acquired.decode(payload, acquired.MAX_LOCK_BYTES))
    return payload, locked


def native_inputs(nix, ca):
    result = []
    for supplied, expected in ((nix, PINNED_NIX), (ca, PINNED_CA)):
        selected = Path(supplied).resolve(strict=True)
        require(selected == expected, "acquisition-native-input-pin")
        info = selected.stat()
        require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
                and not info.st_mode & 0o222, "acquisition-native-input-custody")
        result.append(selected)
    with result[0].open("rb") as stream:
        require(stream.read(4) == b"\x7fELF", "acquisition-native-nix-required")
    return result


def source_url(name, pin):
    owner, repository = acquired.REPOSITORIES[name]
    return f"https://github.com/{owner}/{repository}/archive/{pin['rev']}.tar.gz"


def command(nix, root, name, pin):
    require(name in acquired.NAMES, "acquisition-source-name")
    return [str(nix), "--store", "local?root=" + str(root / "private-store"),
            "store", "prefetch-file", "--json", "--unpack", "--hash-type", "sha256",
            "--expected-hash", pin["narHash"], "--name", "source", source_url(name, pin)]


def environment(root, ca):
    return {"HOME": str(root / "home"), "XDG_CONFIG_HOME": str(root / "home/config"),
            "XDG_CACHE_HOME": str(root / "home/cache"), "NIX_CONF_DIR": str(root / "config"),
            "NIX_USER_CONF_FILES": "", "NIX_PATH": "", "NIX_REMOTE": "", "PATH": "",
            "TMPDIR": str(root / "tmp"), "SSL_CERT_FILE": str(ca), "NIX_SSL_CERT_FILE": str(ca),
            "LC_ALL": "C", "NIX_CONFIG": "experimental-features = nix-command\n"
            "build-users-group =\nbuilders =\nsubstituters =\nmax-jobs = 0\n"
            "http-connections = 1\ndownload-attempts = 1\nconnect-timeout = 15\n"
            "stalled-download-timeout = 30\n"}


def usage(root, deadline, *, details=False, quiescent=False):
    with phase("private-budget-scan", deadline=deadline, emit=False):
        count("privateScanCount")
        started = time.monotonic()
        try:
            return private_usage(root, deadline, details=details, quiescent=quiescent)
        finally:
            count("privateScanMs", min((MAX_SECONDS + SOURCE_SECONDS) * 1000,
                                      max(0, int((time.monotonic() - started) * 1000))))


def private_usage(root, deadline, *, details=False, quiescent=False):
    """Bound all retained pending paths; never follow links or cross mounts."""
    require(type(quiescent) is bool, "acquisition-private-scan-mode")
    discovered, metadata_bytes, logical, allocated = 1, 128, 0, 0
    require(discovered <= MAX_PRIVATE_NODES and metadata_bytes <= MAX_PRIVATE_METADATA,
            "acquisition-private-inventory-bound")

    def visit(fd, relative, depth, device, anchor):
        nonlocal discovered, metadata_bytes, logical, allocated
        acquired.check_deadline(deadline)
        anchor.check()
        parent = os.fstat(fd)
        require(parent.st_dev == device and parent.st_uid == os.getuid(),
                "acquisition-private-mount-or-owner")
        allocated += parent.st_blocks * 512
        require(depth <= acquired.MAX_DEPTH, "acquisition-private-depth-bound")
        names = []
        os.lseek(fd, 0, os.SEEK_SET)
        with os.scandir(fd) as entries:
            for entry in entries:
                acquired.check_deadline(deadline)
                child_path = relative + "/" + entry.name if relative else entry.name
                path_bytes = len(os.fsencode(child_path))
                charge = path_bytes + 128
                require(path_bytes <= acquired.MAX_PATH_BYTES and depth + 1 <= acquired.MAX_DEPTH,
                        "acquisition-private-path-bound")
                require(discovered + 1 <= MAX_PRIVATE_NODES
                        and metadata_bytes + charge <= MAX_PRIVATE_METADATA,
                        "acquisition-private-inventory-bound")
                discovered += 1
                metadata_bytes += charge
                names.append(entry.name)
        for name in names:
            acquired.check_deadline(deadline)
            if not quiescent:
                anchor.check()
            try:
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                continue  # The owned Nix child relocates temporary nodes.
            require(info.st_dev == device and info.st_uid == os.getuid(),
                    "acquisition-private-mount-or-owner")
            if stat.S_ISDIR(info.st_mode):
                try:
                    child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                    | os.O_CLOEXEC, dir_fd=fd)
                except FileNotFoundError:
                    continue
                try:
                    identity = directory_identity(info)
                    require(directory_identity(os.fstat(child)) == identity,
                            "acquisition-private-directory-replaced")
                    child_path = relative + "/" + name if relative else name
                    visit(child, child_path, depth + 1, device, anchor)
                    try:
                        after = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    except FileNotFoundError:
                        after = None
                    require(after is None or directory_identity(after) == identity,
                            "acquisition-private-directory-replaced")
                finally:
                    os.close(child)
            else:
                allocated += info.st_blocks * 512
                if stat.S_ISREG(info.st_mode):
                    require(info.st_size <= acquired.MAX_FILE_BYTES,
                            "acquisition-private-file-bound")
                    logical += info.st_size
                else:
                    require(stat.S_ISLNK(info.st_mode), "acquisition-private-special-file")
            require(max(logical, allocated) <= DISK_BUDGET,
                    "acquisition-private-disk-budget")
        anchor.check()

    with held(root) as anchor:
        # Only after owned child/flush writers have been joined. Descent stays
        # on held nofollow FDs; full checks remain at every directory boundary.
        # The stable task-private root has a full before/after state witness.
        # Shared ancestors can legitimately acquire unrelated sibling entries:
        # their identities, modes, owners and named links are observed at the
        # directory fences, not claimed immutable between those observations.
        # Held FD descent prevents redirecting the scan through an alias. A
        # transient restored external namespace is outside that fence scope.
        # Live Nix monitoring keeps the original per-node ancestry checks.
        captured = None
        if quiescent:
            chain, lifetime = tuple(anchor.chain), anchor._lifetime
            acquired.check_deadline(deadline)
            captured = (chain, lifetime, acquired.snapshot(os.fstat(anchor.fd)))
        visit(anchor.fd, "", 0, os.fstat(anchor.fd).st_dev, anchor)
        if captured is not None:
            chain, lifetime, before = captured
            anchor.check()
            require(anchor._lifetime is lifetime and tuple(anchor.chain) == chain,
                    "acquisition-private-ancestor-changed")
            acquired.check_deadline(deadline)
            require(acquired.snapshot(os.fstat(anchor.fd)) == before,
                    "acquisition-private-ancestor-changed")
    require(max(logical, allocated) <= DISK_BUDGET, "acquisition-private-disk-budget")
    if details:
        return {"logical": logical, "allocated": allocated, "nodes": discovered,
                "metadata": metadata_bytes}
    return max(logical, allocated)


def disk_check(root, deadline, *, quiescent=False):
    usage(root, deadline, quiescent=quiescent)
    free_space_check(root, deadline)


def free_space_check(root, deadline):
    acquired.check_deadline(deadline)
    with held(root) as directory:
        space = os.fstatvfs(directory.fd)
        require(space.f_bavail * space.f_frsize >= FREE_FLOOR, "acquisition-free-floor")
        directory.check()
    acquired.check_deadline(deadline)


def file_limits():
    inherited = resource.getrlimit(resource.RLIMIT_FSIZE)
    finite = [v for v in inherited if v != resource.RLIM_INFINITY]
    bound = min([acquired.MAX_FILE_BYTES] + finite)
    require(bound > 0, "acquisition-inherited-file-limit")
    return bound, bound


def child_limit():
    resource.setrlimit(resource.RLIMIT_FSIZE, file_limits())


def prefetch(argv, env, root, deadline):
    with phase("prefetch-admission", deadline=deadline):
        disk_check(root, deadline)
    root_path = root.path if isinstance(root, HeldDirectory) else root
    process = subprocess.Popen(argv, env=env, cwd=root_path, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True, preexec_fn=child_limit)
    selector = selectors.DefaultSelector()
    output, totals = bytearray(), {"stdout": 0, "stderr": 0}
    next_scan = time.monotonic() + MONITOR_SCAN_SECONDS

    def monitor():
        nonlocal next_scan
        with phase("prefetch-monitor", deadline=deadline, emit=False):
            count("monitorPolls")
            # This is a sampled allocation monitor, not an aggregate disk quota.
            # Poll-level free-space/deadline/ancestry checks continue between
            # scans; a completed scan schedules the next one from its end.
            free_space_check(root, deadline)
            if time.monotonic() >= next_scan:
                disk_check(root, deadline)
                next_scan = time.monotonic() + MONITOR_SCAN_SECONDS
    try:
        for name in totals:
            stream = getattr(process, name)
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            monitor()
            for key, _ in selector.select(0.1):
                packet = os.read(key.fileobj.fileno(), 8192)
                if not packet:
                    selector.unregister(key.fileobj)
                    continue
                totals[key.data] += len(packet)
                maximum = MAX_STDOUT if key.data == "stdout" else MAX_STDERR
                require(totals[key.data] <= maximum, "acquisition-child-output-bound")
                if key.data == "stdout":
                    output.extend(packet)
        # Keep our leader unreaped until group cleanup so its PGID cannot be
        # recycled. This owns only the process group just created above.
        while os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
            monitor()
            time.sleep(0.05)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, MemoryError, subprocess.TimeoutExpired,
            KeyboardInterrupt) as error:
        progress = PROGRESS.get()
        if progress is not None:
            progress.capture(error)
        raise
    finally:
        with phase("owned-child-cleanup", emit=False):
            try:
                try:
                    try:
                        require(os.getpgid(process.pid) == process.pid,
                                "acquisition-child-live-group")
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                finally:
                    process.wait(timeout=5)
            finally:
                selector.close()
                process.stdout.close()
                process.stderr.close()
    require(process.returncode == 0, "acquisition-child-failed")
    with phase("prefetch-completion", deadline=deadline):
        disk_check(root, deadline, quiescent=True)
    return acquired.decode(bytes(output), MAX_STDOUT)


def retained_source(root, reply, pin):
    acquired.fields(reply, ("storePath", "hash"))
    logical = reply["storePath"]
    require(isinstance(logical, str) and re.fullmatch(
        r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-source", logical),
        "acquisition-private-source-path")
    require(reply["hash"] == pin["narHash"], "acquisition-prefetch-hash")
    # Map only this fixed logical store namespace into our private physical
    # root. Never open the same logical path in the ambient global store.
    root_path = root.path if isinstance(root, HeldDirectory) else root
    if isinstance(root, HeldDirectory):
        root.check()
    path = root_path / "private-store" / logical.lstrip("/")
    require(path.resolve(strict=True) == path, "acquisition-private-source-alias")
    if isinstance(root, HeldDirectory):
        root.check()
    return path


def inventory_source(path, pin, deadline, root_anchor=None):
    fd = acquired.open_root(acquired.physical_path(path), deadline)
    try:
        if root_anchor is not None:
            root_anchor.check()
        with phase("source-inventory", deadline=deadline, emit=False):
            nodes, facts = acquired.scan(fd, deadline)
        descriptor = {"schemaVersion": 1, "root": str(path), "nodes": nodes}
        digest, size = hashlib.sha256(), 0

        def emit(content):
            nonlocal size
            acquired.check_deadline(deadline)
            size += len(content)
            require(size <= acquired.MAX_NAR_BYTES, "acquisition-source-nar-bound")
            digest.update(content)

        def opener(selected, relative):
            require(selected == str(path), "acquisition-hash-root")
            return acquired.regular_stream(fd, relative, facts, deadline)

        with phase("source-nar", deadline=deadline):
            count("narPassCount")
            started = time.monotonic()
            try:
                acquired.serialize(descriptor, emit, opener=opener, deadline=deadline)
            finally:
                count("narPassMs", min((MAX_SECONDS + SOURCE_SECONDS) * 1000,
                                      max(0, int((time.monotonic() - started) * 1000))))
        require("sha256-" + base64.b64encode(digest.digest()).decode() == pin["narHash"],
                "acquisition-export-nar-mismatch")
        with phase("source-recheck", deadline=deadline, emit=False):
            require(acquired.scan(fd, deadline) == (nodes, facts), "acquisition-export-source-changed")
        selected = acquired.open_root(str(path), deadline)
        try:
            require(acquired.snapshot(os.fstat(selected)) == facts[""], "acquisition-export-root-changed")
        finally:
            os.close(selected)
        return nodes, size, facts
    finally:
        os.close(fd)


def copy_source_tree(source_fd, destination_fd, nodes, facts, root, staging, deadline):
    """Copy only witnessed NAR nodes; never mutate or link store input inodes."""
    children = {}
    for node in nodes:
        if node["path"]:
            parent = node["path"].rsplit("/", 1)[0] if "/" in node["path"] else ""
            children.setdefault(parent, []).append(node)
    # The child has been reaped. Take one complete private-tree baseline, then
    # charge only our new output nodes/bytes/allocations while copying. Walking
    # the growing private tree every second made this phase quadratic.
    with phase("copy-baseline", deadline=deadline):
        budget = usage(root, deadline, details=True, quiescent=True)
    copied_bytes = 0
    next_space_check = time.monotonic()
    prefix = str(staging.path.relative_to(root.path))
    prefix_bytes = len(os.fsencode(prefix)) + 1 + max(map(len, acquired.NAMES))

    def check_budget():
        require(max(budget["logical"], budget["allocated"]) <= DISK_BUDGET,
                "acquisition-private-disk-budget")
        require(budget["nodes"] <= MAX_PRIVATE_NODES
                and budget["metadata"] <= MAX_PRIVATE_METADATA,
                "acquisition-private-inventory-bound")

    def reserve_node(node):
        budget["nodes"] += 1
        # Includes the destination source leaf and staging ancestors. Using
        # the longer of the two fixed source names is a conservative charge.
        budget["metadata"] += prefix_bytes + 1 + len(os.fsencode(node["path"])) + 128
        check_budget()

    def charge_blocks(info, previous=0):
        current = info.st_blocks * 512
        budget["allocated"] += max(0, current - previous)
        check_budget()
        return current

    def tick():
        nonlocal next_space_check
        acquired.check_deadline(deadline)
        syncs.check_failed()
        check_copy_anchors(root, staging)
        if time.monotonic() >= next_space_check:
            free_space_check(root, deadline)
            next_space_check = time.monotonic() + 1

    def visit(directory, relative, depth, *, new_directory=False):
        nonlocal copied_bytes
        tick()
        require(depth <= acquired.MAX_DEPTH, "acquisition-copy-depth-bound")
        directory_info = os.fstat(directory)
        directory_identity_before = directory_identity(directory_info)
        directory_blocks = charge_blocks(directory_info) if new_directory else directory_info.st_blocks * 512
        for node in children.get(relative, ()):
            tick()
            reserve_node(node)
            name = node["path"].rsplit("/", 1)[-1]
            if node["type"] == "directory":
                os.mkdir(name, 0o700, dir_fd=directory)
                count("copiedNodes")
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                | os.O_CLOEXEC, dir_fd=directory)
                try:
                    witness = directory_identity(os.fstat(child))
                    visit(child, node["path"], depth + 1, new_directory=True)
                    require(directory_identity(os.stat(name, dir_fd=directory, follow_symlinks=False))
                            == witness, "acquisition-copy-directory-replaced")
                finally:
                    os.close(child)
            elif node["type"] == "regular":
                output = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                                 | os.O_CLOEXEC, 0o600, dir_fd=directory)
                try:
                    count("copiedNodes")
                    size = 0
                    file_blocks = charge_blocks(os.fstat(output))
                    with acquired.regular_stream(source_fd, node["path"], facts, deadline) as incoming:
                        while size <= node["size"]:
                            tick()
                            content = incoming.read(min(1024 * 1024, node["size"] + 1 - size))
                            if not content:
                                break
                            size += len(content)
                            copied_bytes += len(content)
                            require(size <= node["size"] and copied_bytes <= acquired.MAX_TREE_BYTES,
                                    "acquisition-copy-file-or-tree-bound")
                            budget["logical"] += len(content)
                            check_budget()
                            remaining = memoryview(content)
                            while remaining:
                                acquired.check_deadline(deadline)
                                written = os.write(output, remaining)
                                require(written > 0, "acquisition-copy-short-write")
                                remaining = remaining[written:]
                                count("copiedBytes", written)
                                file_blocks = charge_blocks(os.fstat(output), file_blocks)
                    require(size == node["size"], "acquisition-copy-file-size")
                    os.fchmod(output, 0o555 if node["executable"] else 0o444)
                    file_blocks = charge_blocks(os.fstat(output), file_blocks)
                    require(acquired.snapshot(os.fstat(output))
                            == acquired.snapshot(os.stat(name, dir_fd=directory, follow_symlinks=False)),
                            "acquisition-copy-file-replaced")
                    syncs.submit(output, directory, name, file_blocks)
                finally:
                    os.close(output)
            elif node["type"] == "symlink":
                os.symlink(node["target"], name, dir_fd=directory)
                count("copiedNodes")
                charge_blocks(os.stat(name, dir_fd=directory, follow_symlinks=False))
                require(os.readlink(name, dir_fd=directory) == node["target"],
                        "acquisition-copy-link-replaced")
            else:
                raise ValueError("acquisition-copy-undeclared-node")
            directory_blocks = charge_blocks(os.fstat(directory), directory_blocks)
        tick()
        require(directory_identity(os.fstat(directory)) == directory_identity_before,
                "acquisition-copy-directory-replaced")
        os.fchmod(directory, 0o555)

    with FileSyncOwner(tick, charge_blocks) as syncs:
        visit(destination_fd, "", 0)
        syncs.drain()
    # A complete phase-boundary scan also catches unrelated private-tree drift;
    # the incremental monitor is sampled allocation enforcement, not a quota.
    with phase("copy-final-budget", deadline=deadline):
        disk_check(root, deadline, quiescent=True)


def export_source(root, staging, name, reply, pin, deadline):
    source = retained_source(root, reply, pin)
    with phase("source-inventory", deadline=deadline):
        nodes, size, facts = inventory_source(source, pin, deadline,
                                             root if isinstance(root, HeldDirectory) else None)
        expected_source(nodes)
    with held(root) as root_anchor, HeldDirectory(source.parent) as source_parent, held(staging) as destination:
        root_anchor.check()
        source_parent.check()
        destination.check()
        source_fd = os.open(source.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                            | os.O_CLOEXEC, dir_fd=source_parent.fd)
        output_fd = None
        try:
            require(acquired.snapshot(os.fstat(source_fd)) == facts[""],
                    "acquisition-export-root-changed")
            with phase("source-recheck", deadline=deadline, emit=False):
                require(acquired.scan(source_fd, deadline) == (nodes, facts),
                        "acquisition-export-source-changed")
            # Read-only private store parents are inputs. Create distinct output
            # inodes through our held staging descriptor; never rename/chmod a
            # store node to obtain write permission.
            os.mkdir(name, 0o700, dir_fd=destination.fd)
            output_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                | os.O_CLOEXEC, dir_fd=destination.fd)
            output_identity = directory_identity(os.fstat(output_fd))
            with phase("copy", deadline=deadline):
                copy_source_tree(source_fd, output_fd, nodes, facts, root_anchor, destination, deadline)
            with phase("source-recheck", deadline=deadline, emit=False):
                require(acquired.scan(source_fd, deadline) == (nodes, facts),
                        "acquisition-export-source-changed")
            require(acquired.snapshot(os.stat(source.name, dir_fd=source_parent.fd,
                                              follow_symlinks=False)) == facts[""],
                    "acquisition-export-root-changed")
            require(directory_identity(os.stat(name, dir_fd=destination.fd, follow_symlinks=False))
                    == output_identity, "acquisition-export-output-replaced")
            root_anchor.check()
            source_parent.check()
            destination.check()
            with phase("copied-proof", deadline=deadline):
                copied_nodes, copied_size, copied_facts = inventory_source(
                    destination.path / name, pin, deadline, root_anchor)
            require(copied_nodes == nodes and copied_size == size
                    and directory_identity(os.fstat(output_fd))
                    == (copied_facts[""][0], copied_facts[""][1], copied_facts[""][3]),
                    "acquisition-export-copy-mismatch")
            with phase("source-recheck", deadline=deadline, emit=False):
                require(acquired.scan(source_fd, deadline) == (nodes, facts),
                        "acquisition-export-source-changed")
            source_parent.check()
            destination.check()
        finally:
            if output_fd is not None:
                os.close(output_fd)
            os.close(source_fd)
    return {"nodes": nodes}, size


def write_metadata(directory, name, value, maximum):
    payload = bounded_encoded(value, maximum)
    require(isinstance(name, str) and re.fullmatch(r"[a-z-]+\.json", name),
            "acquisition-metadata-name")
    with held(directory) as target:
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
                     | os.O_CLOEXEC, 0o600, dir_fd=target.fd)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fchmod(stream.fileno(), 0o444)
            file_sync(stream.fileno())
            witness = acquired.snapshot(os.fstat(stream.fileno()))
            require(witness == acquired.snapshot(os.stat(name, dir_fd=target.fd,
                                                        follow_symlinks=False)),
                    "acquisition-metadata-replaced")
            target.check()
    return payload


@contextmanager
def metadata_witnesses(staging, expected, deadline):
    """Keep the actual published metadata bytes bound through publication."""
    witnesses = []
    try:
        staging.check()
        for name, payload in expected.items():
            acquired.check_deadline(deadline)
            fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
                         | os.O_CLOEXEC, dir_fd=staging.fd)
            before = acquired.snapshot(os.fstat(fd))
            witnesses.append((name, fd, before))
            require(stat.S_ISREG(before[2]) and not before[2] & 0o222
                    and before[3] == os.getuid() and before[5] == 1
                    and before[6] == len(payload), "acquisition-metadata-custody")
            digest, size = hashlib.sha256(), 0
            while size <= len(payload):
                acquired.check_deadline(deadline)
                content = os.read(fd, min(16384, len(payload) + 1 - size))
                if not content:
                    break
                size += len(content)
                digest.update(content)
            require(size == len(payload) and digest.hexdigest() == sha(payload),
                    "acquisition-metadata-byte-mismatch")
        check_metadata_witnesses(staging, witnesses)
        yield witnesses
    finally:
        for _, fd, _ in witnesses:
            os.close(fd)


def check_metadata_witnesses(staging, witnesses):
    for name, fd, before in witnesses:
        require(before == acquired.snapshot(os.fstat(fd))
                == acquired.snapshot(os.stat(name, dir_fd=staging.fd, follow_symlinks=False)),
                "acquisition-metadata-changed-before-publication")


def verify_pair(lock_bytes, receipt_bytes, receipt_digest, inventory_bytes, roots, deadline, phase_name):
    seconds = max(1, min(acquired.MAX_SECONDS, int(deadline - time.monotonic())))
    with phase(phase_name, deadline=min(deadline, time.monotonic() + seconds)):
        count("pairProofCount")
        started = time.monotonic()
        try:
            return acquired.verify_acquired_pair(lock_bytes, receipt_bytes, receipt_digest,
                inventory_bytes, roots, deadline_seconds=seconds)
        finally:
            count("pairProofMs", min((MAX_SECONDS + SOURCE_SECONDS) * 1000,
                                     max(0, int((time.monotonic() - started) * 1000))))


@contextmanager
def source_witnesses(staging, deadline):
    witnesses = []
    try:
        staging.check()
        for name in acquired.NAMES:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                         | os.O_CLOEXEC, dir_fd=staging.fd)
            try:
                with phase("publication-witness", source=name, deadline=deadline, emit=False):
                    capture = acquired.scan(fd, deadline)
            except BaseException:
                os.close(fd)
                raise
            witnesses.append((name, fd, capture))
        check_source_witnesses(staging, witnesses, deadline)
        yield witnesses
    finally:
        for _, fd, _ in witnesses:
            os.close(fd)


def check_source_witnesses(staging, witnesses, deadline):
    for name, fd, capture in witnesses:
        with phase("publication-recheck", source=name, deadline=deadline, emit=False):
            require(acquired.scan(fd, deadline) == capture
                    and acquired.snapshot(os.stat(name, dir_fd=staging.fd,
                                                  follow_symlinks=False)) == capture[1][""],
                    "acquisition-source-changed-through-publication")


def rollback_envelope(root, outputs, staging):
    """Withdraw only this action's held envelope after a publication refusal."""
    root.check()
    outputs.check()
    require(directory_identity(os.stat("home-manager-pair", dir_fd=outputs.fd, follow_symlinks=False))
            == directory_identity(os.fstat(staging.fd)), "acquisition-rollback-envelope-replaced")
    try:
        os.stat("pair", dir_fd=root.fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise ValueError("acquisition-rollback-destination-exists")
    # Only our containing envelope needs write permission to update '..'. No
    # source directory/file permission is relaxed during export/publication.
    os.fchmod(staging.fd, 0o700)
    root.check()
    outputs.check()
    require(directory_identity(os.stat("home-manager-pair", dir_fd=outputs.fd, follow_symlinks=False))
            == directory_identity(os.fstat(staging.fd)), "acquisition-rollback-envelope-replaced")
    try:
        os.stat("pair", dir_fd=root.fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise ValueError("acquisition-rollback-destination-exists")
    os.rename("home-manager-pair", "pair", src_dir_fd=outputs.fd, dst_dir_fd=root.fd)
    staging.check()


@contextmanager
def packed_witness(staging, raw_metadata, deadline):
    if raw_metadata is None:
        yield None
        return
    value = source_pack.metadata(raw_metadata)
    packed = source_pack.PackedFile(staging.fd, value, deadline)
    try:
        yield packed
    finally:
        primary = sys.exc_info()[1]
        try: packed.close()
        except BaseException:
            if primary is None: raise
            primary.cleanup_category = "source-pack-close-refused"


def publish_pair(root, outputs, staging, lock_bytes, receipt_bytes, receipt_digest,
                 inventory_bytes, report_bytes, deadline, *, packed_metadata=None):
    root.check()
    outputs.check()
    staging.check()
    require(stat.S_IMODE(os.fstat(staging.fd).st_mode) == 0o700,
            "acquisition-publication-envelope-mode")
    metadata = {"inventory.json": inventory_bytes, "receipt.json": receipt_bytes, "acquisition.json": report_bytes}
    if packed_metadata is not None: metadata["source-pack.json"] = packed_metadata
    with metadata_witnesses(staging, metadata, deadline) as witnesses, \
            source_witnesses(staging, deadline) as source_capture, \
            packed_witness(staging, packed_metadata, deadline) as packed:
        # All writes, chmod and disk traversal are finished. Rehash the expected
        # pair after that interval, then recheck held metadata and publish.
        verify_pair(lock_bytes, receipt_bytes, receipt_digest, inventory_bytes,
            {name: str(staging.path / name) for name in acquired.NAMES}, deadline, "publication-proof")
        acquired.check_deadline(deadline)
        root.check()
        outputs.check()
        staging.check()
        check_metadata_witnesses(staging, witnesses)
        check_source_witnesses(staging, source_capture, deadline)
        if packed is not None: packed.recheck()
        try:
            os.stat("home-manager-pair", dir_fd=outputs.fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise ValueError("acquisition-output-exists")
        require(directory_identity(os.stat("pair", dir_fd=root.fd, follow_symlinks=False))
                == directory_identity(os.fstat(staging.fd)), "acquisition-publication-source-replaced")
        with phase("publication-rename", deadline=deadline):
            os.rename("pair", "home-manager-pair", src_dir_fd=root.fd, dst_dir_fd=outputs.fd)
        try:
            require(directory_identity(os.stat("home-manager-pair", dir_fd=outputs.fd, follow_symlinks=False))
                    == directory_identity(os.fstat(staging.fd)), "acquisition-publication-replaced")
            # Linux needs the containing directory writable when a cross-parent
            # rename updates '..'. Seal this owned envelope after that operation;
            # all retained source nodes remain readonly for the entire interval.
            os.fchmod(staging.fd, 0o555)
            require(stat.S_IMODE(os.fstat(staging.fd).st_mode) == 0o555,
                    "acquisition-publication-envelope-mode")
            check_metadata_witnesses(staging, witnesses)
            check_source_witnesses(staging, source_capture, deadline)
            if packed is not None: packed.recheck()
            root.check()
            outputs.check()
        except BaseException:
            rollback_envelope(root, outputs, staging)
            raise


def produce_held(nix, ca, lock_bytes, locked, root, outputs, staging):
    deadline = time.monotonic() + MAX_SECONDS
    inventory = {"schemaVersion": 1, "sources": {}}
    receipt = {"schemaVersion": 1, "kind": "omux-home-manager-acquired-pair",
               "lockSha256": sha(lock_bytes), "sources": {}}
    retained_bytes = 0
    for name in acquired.NAMES:
        pin = locked[name]
        source_deadline = min(deadline, time.monotonic() + SOURCE_SECONDS)
        with phase("source", source=name, deadline=source_deadline):
            root.check()
            with phase("prefetch", deadline=source_deadline):
                reply = prefetch(command(nix, root.path, name, pin), environment(root.path, ca), root, source_deadline)
            with phase("export", deadline=source_deadline):
                inventory["sources"][name], size = export_source(root, staging, name, reply, pin, source_deadline)
            retained_bytes += size
            require(retained_bytes <= MAX_RETAINED_BYTES, "acquisition-retained-pair-bound")
            receipt["sources"][name] = {"revision": pin["rev"], "narHash": pin["narHash"],
                                       "narSize": size, "url": source_url(name, pin)}
            # Post-source aggregate accounting belongs to the overall budget;
            # the preparation deadline above is not a timer for this scan.
            disk_check(root, deadline, quiescent=True)
    with phase("metadata", source="pair", deadline=deadline):
        inventory_bytes = write_metadata(staging, "inventory.json", inventory, acquired.MAX_INVENTORY_BYTES)
        receipt["inventorySha256"] = sha(inventory_bytes)
        receipt_bytes = write_metadata(staging, "receipt.json", receipt, acquired.MAX_RECEIPT_BYTES)
    receipt_digest = sha(receipt_bytes)
    # This action authored this receipt from fixed-pin reads. This internal
    # readback does not supply independent receipt trust for a later consumer;
    # the coordinator must freeze receipt_digest in that consumer's declaration.
    proof = verify_pair(lock_bytes, receipt_bytes, receipt_digest, inventory_bytes,
        {name: str(staging.path / name) for name in acquired.NAMES}, deadline, "pair-proof")
    acquired.check_deadline(deadline)
    # One bounded regular transport is authored inside the existing private
    # owner. Source proof before/through publication still reads all NAR bytes.
    with phase("packed-source", source="pair", deadline=deadline):
        baseline = usage(root, deadline, details=True, quiescent=True)
        require(baseline["nodes"] + 2 <= MAX_PRIVATE_NODES
            and baseline["metadata"] + 1024 <= MAX_PRIVATE_METADATA, "acquisition-private-inventory-bound")
        def charge_pack(info):
            acquired.check_deadline(deadline)
            require(max(baseline["logical"] + info.st_size + 65536,
                baseline["allocated"] + info.st_blocks * 512 + 65536) <= DISK_BUDGET,
                "acquisition-private-disk-budget")
        pack = source_pack.write(staging.fd, receipt_bytes, inventory_bytes, deadline,
            anchor=lambda: (root.check(), staging.check()), charge=charge_pack, sync=file_sync)
        packed_metadata = write_metadata(staging, "source-pack.json", pack, acquired.MAX_RECEIPT_BYTES)
        disk_check(root, deadline, quiescent=True)
    destination = outputs.path / "home-manager-pair"
    require(os.fstat(staging.fd).st_dev == os.fstat(outputs.fd).st_dev, "acquisition-output-filesystem")
    # The report describes the final declared physical roots. Source inode
    # custody survives this containing-directory rename; consumer rehash remains
    # mandatory and never trusts this report in place of actual bytes.
    for name in acquired.NAMES:
        proof["sources"][name]["sourceDirectory"] = str(destination / name)
    report = {"schemaVersion": 1, "scope": "finite-paired-source-acquisition",
              "sourcesAcquired": list(acquired.NAMES), "receiptSha256": receipt_digest,
              "inventorySha256": sha(inventory_bytes), "byteProof": proof,
              "nix": str(nix), "caFile": str(ca), "activation": "unproved",
              "evaluationExecuted": False, "globalStoreWritten": False,
              "diskBudgetBytes": DISK_BUDGET, "freeFloorBytes": FREE_FLOOR,
              "diskEnforcement": "sampled allocation monitor with possible overshoot; not an aggregate quota",
              "childFileLimitBytes": file_limits()[0], "packedSource": pack}
    with phase("metadata", source="pair", deadline=deadline):
        report_bytes = write_metadata(staging, "acquisition.json", report, acquired.MAX_RECEIPT_BYTES)
        staging.check()
        disk_check(root, deadline, quiescent=True)
    with phase("publication", source="pair", deadline=deadline):
        publish_pair(root, outputs, staging, lock_bytes, receipt_bytes, receipt_digest,
                     inventory_bytes, report_bytes, deadline, packed_metadata=packed_metadata)
    return report


def produce(nix, ca, lock_bytes, locked, root, outputs):
    with held(root) as root_anchor, held(outputs) as output_anchor:
        for name in ("home", "tmp", "config", "private-store", "pair"):
            root_anchor.check()
            os.mkdir(name, mode=0o700, dir_fd=root_anchor.fd)
            root_anchor.check()
        with HeldDirectory(root_anchor.path / "pair", parent_anchor=root_anchor) as staging:
            root_anchor.check()
            return produce_held(nix, ca, lock_bytes, locked, root_anchor, output_anchor, staging)


def restore_cleanup_directories(fd, deadline):
    """Make only held action-owned directories removable; links stay inert."""
    discovered, metadata = 1, 128
    device = os.fstat(fd).st_dev

    def visit(directory, depth):
        nonlocal discovered, metadata
        acquired.check_deadline(deadline)
        info = os.fstat(directory)
        require(info.st_uid == os.getuid() and info.st_dev == device
                and depth <= acquired.MAX_DEPTH, "acquisition-cleanup-custody")
        os.fchmod(directory, 0o700)
        names = []
        os.lseek(directory, 0, os.SEEK_SET)
        with os.scandir(directory) as entries:
            for entry in entries:
                acquired.check_deadline(deadline)
                charge = len(os.fsencode(entry.name)) + 128
                require(discovered + 1 <= MAX_PRIVATE_NODES
                        and metadata + charge <= MAX_PRIVATE_METADATA,
                        "acquisition-cleanup-inventory-bound")
                discovered += 1
                metadata += charge
                names.append(entry.name)
        for name in names:
            acquired.check_deadline(deadline)
            child_info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            require(child_info.st_uid == os.getuid() and child_info.st_dev == device,
                    "acquisition-cleanup-custody")
            if stat.S_ISDIR(child_info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                                | os.O_CLOEXEC, dir_fd=directory)
                try:
                    require(directory_identity(os.fstat(child)) == directory_identity(child_info),
                            "acquisition-cleanup-replaced")
                    visit(child, depth + 1)
                    require(directory_identity(os.stat(name, dir_fd=directory, follow_symlinks=False))
                            == directory_identity(child_info), "acquisition-cleanup-replaced")
                finally:
                    os.close(child)

    visit(fd, 0)


@contextmanager
def private_worker(scratch):
    name = "omux-hm-acquisition-" + uuid.uuid4().hex
    scratch.check()
    os.mkdir(name, mode=0o700, dir_fd=scratch.fd)
    scratch.check()
    with HeldDirectory(scratch.path / name) as worker:
        scratch.check()
        try:
            yield worker
        except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired,
                KeyboardInterrupt) as error:
            progress = PROGRESS.get()
            if progress is not None:
                progress.capture(error)
            raise
        finally:
            # Cleanup evidence cannot replace a failure already captured in the
            # source/proof phase, including when cleanup itself also refuses.
            # Cleanup must execute even if the diagnostic output stream refuses
            # a write. Its phase/failure is recorded silently, then main reports
            # both the original failure time and the post-cleanup elapsed time.
            with phase("owned-tree-cleanup", source="cleanup", emit=False):
                scratch.check()
                worker.check()
                restore_cleanup_directories(worker.fd, time.monotonic() + 60)
                worker.check()
                # Python's FD-safe rmtree keeps deletion under this held parent.
                require(shutil.rmtree.avoids_symlink_attacks, "acquisition-cleanup-fd-support")
                shutil.rmtree(name, dir_fd=scratch.fd)
                scratch.check()


def run(args):
    require(os.environ.get("OMUX_EXECUTION_GUARD"), "acquisition-contained-context-required")
    nix, ca = native_inputs(args.nix, args.ca_file)
    lock_bytes, locked = read_lock(args.lock)
    scratch = Path(os.environ["TEST_TMPDIR"]).resolve(strict=True)
    outputs = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"]).resolve(strict=True)
    with HeldDirectory(scratch) as scratch_anchor, HeldDirectory(outputs) as output_anchor:
        require(os.fstat(scratch_anchor.fd).st_dev == os.fstat(output_anchor.fd).st_dev,
                "acquisition-action-filesystem")
        os.lseek(output_anchor.fd, 0, os.SEEK_SET)
        with os.scandir(output_anchor.fd) as entries:
            require(next(entries, None) is None, "acquisition-requires-empty-outputs")
        with private_worker(scratch_anchor) as worker:
            report = produce(nix, ca, lock_bytes, locked, worker, output_anchor)
    print(encoded({"scope": report["scope"], "receiptSha256": report["receiptSha256"],
                   "evaluationExecuted": False, "activation": "unproved",
                   "packedSourceSha256": report["packedSource"]["packSha256"],
                   "packedSourceMetadataSha256": sha(encoded(report["packedSource"]))}).decode())
    return 0


def failure_category(error):
    # Never print exception text, filenames, child diagnostics or a traceback.
    # Only our finite predicate names may pass through as a failure category.
    if isinstance(error, ValueError):
        prefix, _, suffix = str(error).partition("-")
        if suffix in ERROR_SUFFIXES.get(prefix, ()):
            return str(error)
    if isinstance(error, KeyboardInterrupt):
        return "acquisition-interrupted"
    if isinstance(error, subprocess.TimeoutExpired):
        return "acquisition-deadline"
    if isinstance(error, OSError):
        return "acquisition-filesystem-refusal"
    return "acquisition-bounded-input-or-custody-failed"


def main(arguments=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("nix", "ca-file", "lock"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args(arguments)
    progress = Progress()
    token = PROGRESS.set(progress)
    try:
        with phase("inputs"):
            return run(args)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError, MemoryError, subprocess.TimeoutExpired,
            KeyboardInterrupt) as error:
        progress.capture(error)
        context = progress.summary()
        print(bounded_encoded({"passed": False, "scope": "finite-paired-source-acquisition",
                       "category": context["category"], "context": context,
                       "evaluationExecuted": False, "activation": "unproved"}, 4096).decode())
        return 2
    finally:
        PROGRESS.reset(token)


if __name__ == "__main__":
    raise SystemExit(main())
