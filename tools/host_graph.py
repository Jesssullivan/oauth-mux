"""Bounded Linux Bazel worker and reusable historical custody deadline helpers."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import select
import signal
import stat
import subprocess
import sys
import time

RECIPES = {
    "linux-package": ("build", "//delivery:release_archive"),
    "linux-installed": ("test", "//delivery:installed_custody_test"),
    "linux-vault": ("test", "//:vault_realproof"),
}
PHASES = ["repository-mapping", "loading-analysis", "analysis-complete", "action-execution", "graph-complete"]
EXECUTION_HOLD = "unsupported execution capability: bootstrap-inclusive aggregate containment is not established for the legacy host worker"


def graph_command(bazelisk, output_root, recipe, proof):
    if recipe not in RECIPES or not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", proof):
        raise ValueError("Linux graph recipe or proof UUID rejected")
    verb, target = RECIPES[recipe]
    return [str(bazelisk), "--batch", "--nosystem_rc", "--nohome_rc",
            "--output_user_root=" + str(output_root), verb, target,
            "--jobs=4", "--invocation_id=" + proof]


def record_cleanup_deadline(path, proof, anchor, budget, total):
    now = time.monotonic()
    if not re.fullmatch(r"[0-9a-f-]{36}", proof) or not math.isfinite(anchor) or anchor > now or not 1 <= budget <= total - 20 or not 30 <= total <= 3600:
        raise ValueError("original deadline rejected")
    payload = json.dumps({"proof_id": proof, "deadline": anchor + budget + 20, "total": total}, sort_keys=True).encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, payload)
    finally:
        os.close(descriptor)


def classify(line):
    if len(line) > 4096:
        return None
    line = re.sub(r"^\(\d\d:\d\d:\d\d\) ", "", line)
    if line.startswith("Computing main repo mapping:"):
        return "repository-mapping"
    if line.startswith(("Loading:", "Analyzing:")):
        return "loading-analysis"
    if line.startswith("INFO: Analyzed "):
        return "analysis-complete"
    if re.match(r"^\[\d+ / \d+\] (?:\d+ / \d+ tests; )?(?:Compiling|Translating|Linking|Testing|Creating|Running|Building|Executing|Zig)\b", line):
        return "action-execution"
    if line.startswith("INFO: Build completed "):
        return "graph-complete"
    return None


class Progress:
    def __init__(self, emit):
        self.rank = -1
        self.emit = emit
        self.pending = bytearray()
        self.discard = False

    def feed(self, data):
        for byte in data:
            if byte == 10:
                if not self.discard:
                    phase = classify(self.pending.decode("utf-8", errors="replace"))
                    if phase and PHASES.index(phase) > self.rank:
                        self.rank = PHASES.index(phase)
                        self.emit(phase)
                self.pending.clear()
                self.discard = False
            elif not self.discard:
                self.pending.append(byte)
                if len(self.pending) > 4096:
                    self.pending.clear()
                    self.discard = True


def private_log(path):
    parent = path.parent
    metadata = os.lstat(parent)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValueError("private graph log parent rejected")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    return os.fdopen(descriptor, "wb")


def remaining(total, elapsed):
    if not 30 <= total <= 3600 or not 0 <= elapsed <= total:
        raise ValueError("invalid proof deadline accounting")
    value = total - 21 - elapsed
    if value < 1:
        raise ValueError("proof bootstrap exhausted deadline")
    return value


class GraphSignal(Exception):
    def __init__(self, signum):
        self.signum = signum


def read_budget(descriptor, total):
    metadata = os.fstat(descriptor)
    if not stat.S_ISFIFO(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1:
        raise ValueError("private deadline channel rejected")
    payload = bytearray()
    deadline = time.monotonic() + 10
    while not payload.endswith(b"\n"):
        delay = deadline - time.monotonic()
        if delay <= 0 or not select.select([descriptor], [], [], delay)[0]:
            raise ValueError("private deadline handshake expired")
        data = os.read(descriptor, 6 - len(payload))
        if not data:
            time.sleep(0.01)
            continue
        if len(payload) + len(data) > 5:
            raise ValueError("private deadline payload rejected")
        payload.extend(data)
    if not re.fullmatch(rb"[1-9]\d{0,3}\n", payload):
        raise ValueError("private deadline payload rejected")
    budget = int(payload)
    if not 1 <= budget <= total - 20:
        raise ValueError("private deadline exceeds original bound")
    return budget


def run_graph(command, log, seconds, emit, custody=None, original_deadline=None):
    raise ValueError(EXECUTION_HOLD)
    # Historical custody implementation retained for receipt interpretation.
    deadline = original_deadline if original_deadline is not None else time.monotonic() + seconds
    digest = hashlib.sha256()
    progress = Progress(emit)
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
    total = 0
    status = None
    def terminate():
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        while True:
            delay = deadline - time.monotonic()
            if delay <= 0:
                status = 124
                terminate()
                break
            watched = [process.stdout] + ([custody] if custody is not None else [])
            ready = select.select(watched, [], [], min(delay, 0.25))[0]
            if custody is not None and custody in ready:
                if os.read(custody, 1):
                    raise ValueError("private deadline channel repeated data")
                status = 130
                terminate()
                break
            if process.stdout in ready:
                data = os.read(process.stdout.fileno(), 65536)
                if not data:
                    status = process.wait(timeout=min(5, max(0.01, deadline - time.monotonic())))
                    break
                total += len(data)
                if total > 128 * 1024 * 1024:
                    raise ValueError("private graph log exceeds bound")
                log.write(data)
                digest.update(data)
                progress.feed(data)
        if status in {124, 130}:
            # Drain only currently available bytes after terminating our group.
            until = time.monotonic() + 5
            while time.monotonic() < until and select.select([process.stdout], [], [], 0.1)[0]:
                data = os.read(process.stdout.fileno(), 65536)
                if not data:
                    break
                total += len(data)
                if total > 128 * 1024 * 1024:
                    raise ValueError("private graph log exceeds bound")
                log.write(data)
                digest.update(data)
            process.wait(timeout=5)
        log.flush()
        return status, digest.hexdigest()
    except GraphSignal as interruption:
        terminate()
        log.flush()
        return 128 + interruption.signum, digest.hexdigest()
    finally:
        terminate()
        process.stdout.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--recipe", choices=RECIPES, required=True)
    parser.add_argument("--bazelisk", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--budget-pipe", type=Path, required=True)
    parser.add_argument("--total", type=int, required=True)
    parser.add_argument("--proof-id", required=True)
    args = parser.parse_args()
    print(json.dumps({"passed": False, "gate": "unsupported-execution-capability",
                      "reason": EXECUTION_HOLD, "recipe": args.recipe}, sort_keys=True))
    return 2
    command = graph_command(args.bazelisk, args.output_root, args.recipe, args.proof_id)
    if (not 30 <= args.total <= 3600 or not str(args.bazelisk.resolve(strict=True)).startswith("/nix/store/")
            or not args.log.is_absolute() or args.log.name != "build.log"
            or args.output_root != args.log.parent / "bazel" or args.budget_pipe != args.log.parent / "graph.deadline"):
        parser.error("declared graph tool or bounded budget rejected")
    def interrupted(signum, frame):
        raise GraphSignal(signum)
    for signum in [signal.SIGHUP, signal.SIGTERM, signal.SIGINT]:
        signal.signal(signum, interrupted)
    descriptor = os.open(args.budget_pipe, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    metadata = os.fstat(descriptor)
    if not stat.S_ISFIFO(metadata.st_mode) or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1:
        raise ValueError("private deadline channel rejected")
    anchor = time.monotonic()
    ready = os.open(args.log.parent / "graph.ready", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(ready, b"ready\n")
    finally:
        os.close(ready)
    seconds = read_budget(descriptor, args.total)
    read_seconds = seconds
    record_cleanup_deadline(args.log.parent / "cleanup.deadline", args.proof_id, anchor, seconds, args.total)
    seconds = anchor + seconds - time.monotonic()
    if seconds <= 0:
        raise ValueError("original graph allowance exhausted")
    with private_log(args.log) as log:
        status, digest = run_graph(command, log, seconds, lambda phase: print("phase=" + phase, flush=True), descriptor, anchor + read_seconds)
    os.close(descriptor)
    print("graph-exit=" + str(status), flush=True)
    print("log-sha256=" + digest, flush=True)
    return status


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.TimeoutExpired, GraphSignal):
        sys.exit("bounded graph worker rejected")
