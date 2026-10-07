"""Declared, offline module evaluation; no builder, downloader or shared daemon."""
import argparse
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import tempfile
import time


class EvaluationFailure(ValueError):
    def __init__(self, phase, category, status=None, stderr=b""):
        super().__init__(category)
        self.phase = phase
        self.category = category
        self.status = status
        self.diagnostic = sanitize_diagnostic(stderr)


def sanitize_diagnostic(stderr):
    text = stderr.decode("utf-8", errors="replace")
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = "".join(character for character in text if character in "\n\t" or character.isprintable())
    text = re.sub(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s'\"<>]+", "<url>", text)
    text = re.sub(r"(?<![A-Za-z0-9])/(?:[^\s'\"<>:,;\[\]{}()]+/?)+", "<path>", text)
    text = re.sub(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", "<address>", text)
    source_lines = text.splitlines()
    # Nix may print evaluation context before its final error. Retain the cause
    # first, then bounded context, instead of truncating away the final line.
    selected = [line for line in source_lines if "error:" in line.lower()][:8]
    selected += source_lines[:8] + source_lines[-8:]
    lines = []
    for line in selected[:24]:
        if re.search(r"token|password|cookie|authorization|secret|otp|private.?key", line, re.I):
            line = "<redacted sensitive diagnostic>"
        lines.append(line)
    return "\n".join(lines).encode("utf-8")[:4096].decode("utf-8", errors="ignore")


def failure_category(stderr):
    text = stderr.decode("utf-8", errors="replace").lower()
    for needles, category in [
        (("syntax error",), "expression-syntax"),
        (("read-only", "dummy store", "not supported by this store", "unsupported store"), "dummy-store-capability"),
        (("does not exist", "no such file", "not available in the nix store"), "declared-input-missing"),
        (("attribute", "option", "undefined variable"), "expression-attribute-or-option"),
        (("predicates failed", "assertion failed"), "module-predicate-failed"),
        (("cannot build", "no builders", "import from derivation"), "build-request-refused"),
    ]:
        if any(needle in text for needle in needles):
            return category
    return "offline-evaluation-failed"


def checked_inputs(manifest, store_paths):
    source = manifest.get("packages", {}).get("nixpkgs", {}).get("out", "")
    if not re.fullmatch(r"/nix/store/[0-9a-z]{32}-[A-Za-z0-9._+-]+", source):
        raise ValueError("locked-nixpkgs-source-missing")
    if source not in store_paths:
        raise ValueError("locked-nixpkgs-source-undeclared")
    system = manifest.get("system", "")
    if system not in {"x86_64-linux", "aarch64-linux", "x86_64-darwin", "aarch64-darwin"}:
        raise ValueError("unsupported-declared-system")
    return source, system


def command(nix, expression, source, system):
    # An explicit dummy store cannot contact the shared Nix daemon or realize a
    # derivation. If a Nix release cannot evaluate these predicates this way,
    # that is a failed gate, never permission to retry with the live store.
    code = "import " + json.dumps(str(Path(expression).resolve())) + " { pkgs = import " + json.dumps(source) + " { system = " + json.dumps(system) + "; config = {}; overlays = []; }; }"
    return [nix, "--extra-experimental-features", "nix-command", "--store", "dummy://?read-only=false",
            # Absolute Bazel-declared source/runfile paths require impure path
            # access. Configuration and process environment remain isolated;
            # no flake resolution, fetching or derivation execution is allowed.
            "eval", "--impure", "--offline", "--json", "--option", "allow-import-from-derivation", "false",
            "--option", "builders", "", "--option", "substituters", "",
            "--option", "max-jobs", "0", "--expr", code]


def checked_source(source_input, lock):
    node = lock["nodes"][lock["root"]]["inputs"]["nixpkgs"]
    locked = lock["nodes"][node]["locked"]
    source = source_input.get("source", "")
    if (source_input.get("schemaVersion") != 1
            or source_input.get("narHash") != locked["narHash"]
            or source_input.get("revision") != locked["rev"]
            or not re.fullmatch(r"sha256-[A-Za-z0-9+/]{43}=", locked["narHash"])):
        raise ValueError("locked-source-binding-invalid")
    checked_inputs({"system": source_input.get("system"), "packages": {"nixpkgs": {"out": source}}}, [source])
    return source, source_input["system"], locked["narHash"]


def hash_command(nix, source):
    return [nix, "--extra-experimental-features", "nix-command", "--store", "dummy://",
            "hash", "path", "--offline", "--type", "sha256", "--sri", source]


def evaluator_environment(home):
    # The caller creates this empty private directory before either subprocess.
    # An explicit dictionary excludes ambient plugin/configuration variables.
    return {"HOME": str(home), "PATH": "", "NIX_PATH": "", "NIX_CONFIG": "",
            "NIX_CONF_DIR": str(home), "NIX_USER_CONF_FILES": ""}


def wait_unreaped(process, deadline):
    while True:
        status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        if status is not None:
            return status.si_status if status.si_code == os.CLD_EXITED else -status.si_status
        if time.monotonic() >= deadline:
            raise subprocess.TimeoutExpired('owned evaluator', 60)
        time.sleep(0.01)


def cleanup_owned_group(process, *, deadline=None):
    # Direct-child waitability plus an unreaped leader pins its PID/PGID.
    deadline = time.monotonic() + 5 if deadline is None else deadline
    def remaining():
        budget = min(5, deadline - time.monotonic())
        if budget <= 0:
            raise subprocess.TimeoutExpired('owned evaluator cleanup', 0)
        return budget
    remaining()
    if process.returncode is not None:
        raise ValueError('evaluator leader was reaped before group cleanup')
    os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
    if os.getpgid(process.pid) != process.pid:
        raise ValueError('owned evaluator process group changed')
    remaining()
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=remaining())
    remaining()


def cleanup_failure_category(error):
    if isinstance(error, subprocess.TimeoutExpired):
        return "cleanup-deadline"
    if isinstance(error, KeyboardInterrupt):
        return "cleanup-interrupted"
    if isinstance(error, ValueError):
        return "cleanup-ownership-refusal"
    if isinstance(error, OSError):
        return "cleanup-io-refusal"
    return "cleanup-refused"


def evaluate(argv, home, expected_hash=None, *, deadline=None):
    """Keep 60 seconds of work and at most five seconds of owned cleanup.

    An enclosing monotonic deadline includes that cleanup reserve. All absolute
    bounds are selected before spawning; no read or wait renews them.
    """
    phase = "locked-source-nar" if expected_hash is not None else "module-evaluation"
    if deadline is not None:
        try:
            valid = type(deadline) in (int, float) and math.isfinite(deadline)
        except OverflowError:
            valid = False
        if not valid:
            raise EvaluationFailure(phase, "evaluation-deadline-input")
    started = time.monotonic()
    cleanup_deadline = min(started + 65, deadline) if deadline is not None else started + 65
    deadline = min(started + 60, cleanup_deadline - 5)
    if started >= deadline:
        raise EvaluationFailure(phase, "evaluation-deadline")
    output = bytearray()
    stderr = bytearray()
    limits = {True: 8192, False: 32768}
    counts = {True: 0, False: 0}
    handlers = {}
    primary, cleanup_error = None, None
    selected = None
    def interrupted(signum, frame):
        raise KeyboardInterrupt
    process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True,
                               env=evaluator_environment(home))
    try:
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, interrupted)
        selected = selectors.DefaultSelector()
        selected.register(process.stdout, selectors.EVENT_READ, True)
        selected.register(process.stderr, selectors.EVENT_READ, False)
        while selected.get_map():
            if time.monotonic() >= deadline:
                raise EvaluationFailure(phase, "evaluation-deadline", stderr=stderr)
            for key, _ in selected.select(min(1, max(0, deadline - time.monotonic()))):
                if time.monotonic() >= deadline:
                    raise EvaluationFailure(phase, "evaluation-deadline", stderr=stderr)
                data = os.read(key.fileobj.fileno(), 4096)
                if not data:
                    selected.unregister(key.fileobj)
                    continue
                counts[key.data] += len(data)
                if counts[key.data] > limits[key.data]:
                    raise EvaluationFailure(phase, "evaluation-output-bound", stderr=stderr)
                if key.data:
                    output.extend(data)
                else:
                    stderr.extend(data)
        if time.monotonic() >= deadline:
            raise EvaluationFailure(phase, "evaluation-deadline", stderr=stderr)
        status = wait_unreaped(process, deadline)
        if time.monotonic() >= deadline:
            raise EvaluationFailure(phase, "evaluation-deadline", stderr=stderr)
        if status != 0:
            raise EvaluationFailure(phase, failure_category(stderr), status=status, stderr=stderr)
    except BaseException as error:
        primary = error
    finally:
        if selected is not None:
            try:
                selected.close()
            except BaseException as error:
                cleanup_error = error
        try:
            cleanup_owned_group(process, deadline=cleanup_deadline)
        except BaseException as error:
            cleanup_error = cleanup_error or error
        # These independent releases must run even when ownership, wait, close
        # or a previous signal restoration refuses. Preserve the primary cause.
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except BaseException as error:
                cleanup_error = cleanup_error or error
        for signum, handler in handlers.items():
            try:
                signal.signal(signum, handler)
            except BaseException as error:
                cleanup_error = cleanup_error or error
        if time.monotonic() >= cleanup_deadline and cleanup_error is None:
            cleanup_error = subprocess.TimeoutExpired('owned evaluator cleanup', 0)
    if primary is not None:
        if cleanup_error is not None:
            primary.cleanup_category = cleanup_failure_category(cleanup_error)
        raise primary
    if cleanup_error is not None:
        failure = EvaluationFailure(phase, "evaluation-cleanup-refused", stderr=stderr)
        failure.cleanup_category = cleanup_failure_category(cleanup_error)
        raise failure
    if expected_hash is not None:
        if output.decode("ascii").strip() != expected_hash:
            raise EvaluationFailure(phase, "locked-source-nar-mismatch")
        if time.monotonic() >= cleanup_deadline:
            raise EvaluationFailure(phase, "evaluation-deadline", stderr=stderr)
        return {"lockedSourceNar": True}
    try:
        results = json.loads(output)
    except ValueError:
        raise EvaluationFailure(phase, "invalid-predicate-json") from None
    if not isinstance(results, dict) or not results or any(value is not True for value in results.values()):
        raise EvaluationFailure(phase, "evaluation-predicate-failed")
    if time.monotonic() >= cleanup_deadline:
        raise EvaluationFailure(phase, "evaluation-deadline", stderr=stderr)
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("nix", "expression", "source-input", "lock"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    phase = "source-input"
    try:
        source, system, expected_hash = checked_source(json.loads(Path(args.source_input).read_text()), json.loads(Path(args.lock).read_text()))
        if not Path(source, "default.nix").is_file():
            raise ValueError("locked-nixpkgs-source-unavailable")
        with tempfile.TemporaryDirectory(prefix="omux-nix-evaluation-", dir=os.environ.get("TEST_TMPDIR")) as home:
            phase = "locked-source-nar"
            evaluate(hash_command(args.nix, source), home, expected_hash)
            phase = "module-evaluation"
            results = evaluate(command(args.nix, args.expression, source, system), home)
            results["lockedSourceNar"] = True
        print(json.dumps({"passed": True, "scope": "nixpkgs-module-harness", "predicates": results}, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        result = {"passed": False, "scope": "nixpkgs-module-harness", "gate": "declared-offline-evaluation-unavailable",
                  "phase": error.phase if isinstance(error, EvaluationFailure) else phase,
                  "failure_category": error.category if isinstance(error, EvaluationFailure) else "bounded-input-or-execution-failed"}
        if isinstance(error, EvaluationFailure):
            result["exit_status"] = error.status
            # This diagnostic originates only in declared public source
            # evaluation. Paths, URLs, sensitive lines and output size are
            # removed/bounded before it can appear in the test log.
            result["diagnostic"] = error.diagnostic
        if getattr(error, "cleanup_category", None) is not None:
            result["cleanup_category"] = error.cleanup_category
        print(json.dumps(result, sort_keys=True))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
