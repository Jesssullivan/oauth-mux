"""Explicit isolated daemon restart of one admitted retained generation.

The declared Bazel/Nix lane supplies the retained receipt, three independently
declared artifact hashes and private-session tools. A bounded copied carrier is
revalidated before each launch. This is disposable development-daemon restart,
not a browser reload, service activation, native handoff or atomic exec witness.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time

import dev_generation as generation

SCOPE = "development-selected-generation-private-daemon-restart"
MAX_OUTPUT = 65536
MAX_RECEIPT_OUTPUT = 4096
EMPTY_AUTHORITY_FIELDS = ("sources", "accounts", "grants", "observations")
MAX_REVISION = (1 << 64) - 1
PRIVATE_DIRECTORIES = (("HOME", "h"), ("XDG_RUNTIME_DIR", "r"), ("XDG_DATA_HOME", "d"),
                       ("XDG_CONFIG_HOME", "c"), ("XDG_CACHE_HOME", "k"), ("XDG_STATE_HOME", "s"))
PHASE = "argument-contract"
PHASES = {"argument-contract", "declared-tools", "carrier-copy", "private-vault-context", "private-keyring",
          "selected-daemon-startup", "selected-empty-authority", "selected-daemon-shutdown", "private-session",
          "private-session-result", "receipt-output"}
CHILD_PHASE = None
CHILD_REASON = None
REASONS = {"fixture-refused", "generation-validation-refused", "private-io-refused", "deadline-exceeded",
           "protocol-data-invalid", "resource-exhausted", "carrier-depth-bound", "carrier-entry-bound",
           "carrier-directory-changed", "carrier-total-bound", "owned-daemon-shutdown-refused",
           "owned-process-deadline", "owned-process-output-bound", "owned-session-identity",
           "owned-session-deadline", "owned-session-group", "private-fixture-root", "private-vault-context",
           "private-directory-binding", "private-socket-path-bound", "selected-cli-refused",
           "selected-cli-response-shape", "private-keyring-exited", "selected-daemon-exited",
           "private-socket-custody", "selected-daemon-startup-deadline", "private-empty-authority",
           "private-snapshot-revision", "private-snapshot-sources", "private-snapshot-accounts",
           "private-snapshot-grants", "private-snapshot-observations", "private-restart-revision-not-advanced",
           "private-restart-revision-delta", "expected-artifact-digest-shape", "declared-private-tool",
           "declared-tool-manifest", "declared-tool-wrapper-changed", "declared-tool-wrapper-bound",
           "private-selected-session-refused", "private-selected-session-receipt", "restart-receipt-bound"}


class RestartError(ValueError):
    def __init__(self, reason):
        self.reason = reason if reason in REASONS else "fixture-refused"
        super().__init__(self.reason)


def require(condition, code):
    if not condition:
        raise RestartError(code)


def failure_diagnostic(failure):
    reason = "fixture-refused"
    if isinstance(failure, RestartError):
        reason = failure.reason
    elif isinstance(failure, generation.GenerationError):
        reason = "generation-validation-refused"
    elif isinstance(failure, (subprocess.TimeoutExpired, TimeoutError)):
        reason = "deadline-exceeded"
    elif isinstance(failure, OSError):
        reason = "private-io-refused"
    elif isinstance(failure, MemoryError):
        reason = "resource-exhausted"
    elif isinstance(failure, (ValueError, TypeError, KeyError)):
        reason = "protocol-data-invalid"
    value = {"scope": SCOPE, "result": "refused", "phase": PHASE if PHASE in PHASES else "argument-contract",
             "reason": reason}
    if CHILD_PHASE is not None and CHILD_REASON is not None:
        value.update(childPhase=CHILD_PHASE, childReason=CHILD_REASON)
    return value


NIX_ROOT = re.compile(r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]{1,211}")
PRIVATE_TOOLS = (("session", "dbus_run_session", "dbus-run-session"),
                 ("bus", "dbus_daemon", "dbus-daemon"),
                 ("keyring", "gnome_keyring_daemon", "gnome-keyring-daemon"))


def declared_bytes(path, maximum, executable=False):
    resolved = Path(path).resolve(strict=True)
    descriptor = os.open(resolved, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        require(stat.S_ISREG(before.st_mode) and before.st_uid in (0, os.geteuid())
                and not before.st_mode & 0o022 and (not executable or before.st_mode & 0o111),
                "declared-private-tool")
        require(before.st_size <= maximum, "declared-tool-wrapper-bound")
        output = bytearray()
        while len(output) <= maximum:
            data = os.read(descriptor, min(65536, maximum + 1 - len(output)))
            if not data:
                break
            output.extend(data)
        require(len(output) <= maximum and generation.snapshot(before) == generation.snapshot(os.fstat(descriptor))
                and generation.snapshot(before) == generation.snapshot(resolved.lstat()), "declared-tool-wrapper-changed")
        return resolved, bytes(output)
    finally:
        os.close(descriptor)


def available_store_executable(path):
    require(path.is_file() and os.access(path, os.X_OK), "declared-private-tool")


def qualify_private_tools(args):
    """Bind declared repository wrapper bytes to the pinned native manifest.

    Both the manifest and wrappers are explicit Bazel data. Invoke the wrappers,
    preserving their selected Nix package backend's own runtime environment.
    No wrapper is executed during qualification and no generic path is accepted.
    """
    manifest_path, raw = declared_bytes(args.tool_manifest, generation.MAX_RECEIPT)
    require(manifest_path.name == "native.json", "declared-tool-manifest")
    manifest = generation.parse(raw)
    require(type(manifest) is dict and manifest.get("system") in ("x86_64-linux", "aarch64-linux")
            and type(manifest.get("packages")) is dict and type(manifest.get("tools")) is dict,
            "declared-tool-manifest")
    bash = manifest["packages"].get("bash")
    require(type(bash) is dict and type(bash.get("out")) is str and NIX_ROOT.fullmatch(bash["out"]),
            "declared-tool-manifest")
    shell = bash["out"] + "/bin/bash"
    available_store_executable(Path(shell))
    bound_wrappers = []
    for argument, key, basename in PRIVATE_TOOLS:
        backend = manifest["tools"].get(key)
        require(type(backend) is str and backend.endswith("/bin/" + basename)
                and NIX_ROOT.fullmatch(backend[:-len("/bin/" + basename)]), "declared-private-tool")
        available_store_executable(Path(backend))
        wrapper, data = declared_bytes(getattr(args, argument), 8192, executable=True)
        require(wrapper == manifest_path.parent / "tool_wrappers" / key, "declared-private-tool")
        # Exactly tools/nix_repository.bzl's generated capability wrapper.
        expected = ('#!' + shell + '\nset -eu\nexec \'' + backend + '\' "$@"\n').encode("ascii")
        require(data == expected, "declared-private-tool")
        setattr(args, argument, wrapper)
        bound_wrappers.append((wrapper, expected))
    # Reobserve all earlier bindings after the complete capture. This remains
    # a byte-selection predicate, not an atomic execution attestation.
    final_manifest_path, final_raw = declared_bytes(manifest_path, generation.MAX_RECEIPT)
    require(final_manifest_path == manifest_path and final_raw == raw, "declared-tool-wrapper-changed")
    for wrapper, expected in bound_wrappers:
        final_wrapper, final_data = declared_bytes(wrapper, 8192, executable=True)
        require(final_wrapper == wrapper and final_data == expected, "declared-tool-wrapper-changed")
    args.tool_manifest = manifest_path
    args.tool_manifest_sha256 = generation.digest(raw)


def write_private_at(directory, name, data, mode):
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         mode, dir_fd=directory)
    with os.fdopen(descriptor, "wb") as stream:
        os.fchmod(stream.fileno(), mode)
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def write_private(path, data, mode):
    descriptor = generation.open_root(path.parent)
    try:
        write_private_at(descriptor, path.name, data, mode)
    finally:
        os.close(descriptor)


def create_directory(parent, name):
    os.mkdir(name, 0o700, dir_fd=parent)
    descriptor = os.open(name, generation.DIRECTORY_FLAGS, dir_fd=parent)
    try:
        generation.owned_directory(descriptor)
        require(generation.snapshot(os.fstat(descriptor)) == generation.snapshot(os.stat(
            name, dir_fd=parent, follow_symlinks=False)), "carrier-directory-changed")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def carrier(stage_root, identifier, receipt_sha256, expected_artifacts, destination):
    """Copy through held nofollow descriptors, then validate exact copied bytes.

    The source receipt bytes are retained unchanged. The destination is a fresh
    fixture-owned namespace; staging/current/stable launchers are never changed.
    Its paths still require revalidation and do not attest a live backing file.
    """
    generation.select_generation(stage_root, identifier, receipt_sha256,
                                 expected_artifacts=expected_artifacts, require_portable=True)
    destination = Path(destination)
    root_fd, generations_fd, selected_fd = None, None, None
    destination_parent, destination_fd, copied_generations_fd, copied_fd = None, None, None, None
    entries, total = 0, 0
    try:
        destination_parent = generation.open_root(destination.parent)
        destination_fd = create_directory(destination_parent, destination.name)
        root_fd = generation.open_root(Path(stage_root))
        marker, mode, _ = generation.read_file(root_fd, ".omux-stage-owner.json", generation.MAX_RECEIPT)
        write_private_at(destination_fd, ".omux-stage-owner.json", marker, mode)
        copied_generations_fd = create_directory(destination_fd, "generations")
        copied_fd = create_directory(copied_generations_fd, identifier)
        generations_fd = os.open("generations", generation.DIRECTORY_FLAGS, dir_fd=root_fd)
        generation.owned_directory(generations_fd)
        selected_fd = os.open(identifier, generation.DIRECTORY_FLAGS, dir_fd=generations_fd)

        def copy_directory(descriptor, target, depth):
            nonlocal entries, total
            require(depth <= generation.MAX_DEPTH, "carrier-depth-bound")
            generation.owned_directory(descriptor)
            generation.owned_directory(target)
            before = generation.snapshot(os.fstat(descriptor))
            os.lseek(descriptor, 0, os.SEEK_SET)
            with os.scandir(descriptor) as children:
                for child in children:
                    entries += 1
                    require(entries <= generation.MAX_ENTRIES, "carrier-entry-bound")
                    info = os.stat(child.name, dir_fd=descriptor, follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        nested = os.open(child.name, generation.DIRECTORY_FLAGS, dir_fd=descriptor)
                        copied_nested = None
                        try:
                            require(generation.snapshot(os.fstat(nested)) == generation.snapshot(info),
                                    "carrier-directory-changed")
                            copied_nested = create_directory(target, child.name)
                            copy_directory(nested, copied_nested, depth + 1)
                            require(generation.snapshot(os.fstat(nested)) == generation.snapshot(os.stat(
                                child.name, dir_fd=descriptor, follow_symlinks=False)), "carrier-directory-changed")
                            require(generation.snapshot(os.fstat(copied_nested)) == generation.snapshot(os.stat(
                                child.name, dir_fd=target, follow_symlinks=False)), "carrier-directory-changed")
                        finally:
                            if copied_nested is not None:
                                os.close(copied_nested)
                            os.close(nested)
                    else:
                        maximum = generation.MAX_RECEIPT if depth == 0 and child.name == "receipt.json" else generation.MAX_FILE
                        data, mode, _ = generation.read_file(descriptor, child.name, maximum, (0o600, 0o700))
                        total += len(data)
                        require(total <= generation.MAX_TOTAL + generation.MAX_RECEIPT, "carrier-total-bound")
                        write_private_at(target, child.name, data, mode)
            require(before == generation.snapshot(os.fstat(descriptor)), "carrier-directory-changed")

        copy_directory(selected_fd, copied_fd, 0)
        for descriptor, parent, name in ((copied_fd, copied_generations_fd, identifier),
                                         (copied_generations_fd, destination_fd, "generations"),
                                         (destination_fd, destination_parent, destination.name)):
            require(generation.snapshot(os.fstat(descriptor)) == generation.snapshot(os.stat(
                name, dir_fd=parent, follow_symlinks=False)), "carrier-directory-changed")
    finally:
        for descriptor in (selected_fd, generations_fd, root_fd, copied_fd, copied_generations_fd,
                           destination_fd, destination_parent):
            if descriptor is not None:
                os.close(descriptor)
    return generation.select_generation(destination, identifier, receipt_sha256,
                                        expected_artifacts=expected_artifacts, require_portable=True)


def private_environment(root):
    environment = {"PATH": "/nonexistent", "LANG": "C", "LC_ALL": "C", "OMUX_INSTANCE": "dev",
                   "OMUX_ISOLATED_VAULT_PROOF": "private-bus-private-xdg"}
    descriptor = generation.open_root(root)
    try:
        for variable, name in PRIVATE_DIRECTORIES:
            child = create_directory(descriptor, name)
            os.close(child)
            environment[variable] = str(root / name)
        require(generation.snapshot(os.fstat(descriptor)) == generation.snapshot(root.lstat()), "private-fixture-root")
    finally:
        os.close(descriptor)
    environment["XDG_CONFIG_DIRS"] = environment["XDG_CONFIG_HOME"]
    environment["XDG_DATA_DIRS"] = environment["XDG_DATA_HOME"]
    return environment


def stop_owned(process, clean=False):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    require(not clean or process.returncode == 0, "owned-daemon-shutdown-refused")


def collect(process, seconds, maximum, *, private_group=False):
    """Bound both streams; pin a private-group leader until descendant cleanup."""
    selector = selectors.DefaultSelector()
    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    deadline = time.monotonic() + seconds
    try:
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            require(time.monotonic() < deadline, "owned-process-deadline")
            for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                data = os.read(key.fd, 4096)
                if not data:
                    selector.unregister(key.fileobj)
                    continue
                output = streams[key.fileobj]
                require(len(output) + len(data) <= maximum, "owned-process-output-bound")
                output.extend(data)
        if private_group:
            while True:
                status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if status is not None:
                    require(status.si_pid == process.pid, "owned-session-identity")
                    code = status.si_status if status.si_code == os.CLD_EXITED else -status.si_status
                    break
                require(time.monotonic() < deadline, "owned-session-deadline")
                time.sleep(0.05)
        else:
            code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        return code, bytes(streams[process.stdout]), bytes(streams[process.stderr])
    finally:
        selector.close()
        if private_group:
            status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            require(status is None or status.si_pid == process.pid, "owned-session-identity")
            require(os.getpgid(process.pid) == process.pid, "owned-session-group")
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        else:
            stop_owned(process)
        process.stdout.close()
        process.stderr.close()


def restart_facts(identifier, receipt_sha256, expected, tool_manifest_sha256=None, *, startup_revision_delta):
    require(type(startup_revision_delta) is int and 1 <= startup_revision_delta <= MAX_REVISION,
            "private-restart-revision-delta")
    return {"schemaVersion": 1, "scope": SCOPE, "generation": identifier,
            "receiptSha256": receipt_sha256, "artifacts": expected,
            "toolManifestSha256": tool_manifest_sha256,
            "channel": "development", "instance": "dev", "daemonStartedTwice": True,
            "daemonRestarted": True, "cleanShutdowns": 2, "emptyAuthorityPreserved": True,
            "startupRevisionDelta": startup_revision_delta,
            "browserReloaded": False, "nativeContinuityProved": False, "serviceActivated": False,
            "providerAccess": False, "liveExecutableAttributed": False, "atomicExecutionWitness": False}


def empty_snapshot_revision(snapshot, prior_revision=None):
    """Verify unchanged empty authority separately from startup lifecycle writes.

    Only finite field/revision diagnostics escape; snapshot contents never do.
    Ordinary bootstrap in the selected candidate performs three recovery
    commits (engine.zig bootstrap: recovered snapshot, integration-recovery
    reservation, released reservation). Each storage.commit advances revision;
    metadata reads and clean shutdown do not commit. That source-derived +3 is a
    candidate diagnostic, not a normative lifecycle promise. Require a strict
    advance separately from unchanged empty authority, refusing a fresh/reset
    database whose revision would repeat the first startup.
    """
    revision = snapshot.get("revision")
    require(type(revision) is int and 0 <= revision <= MAX_REVISION, "private-snapshot-revision")
    for name in EMPTY_AUTHORITY_FIELDS:
        require(type(snapshot.get(name)) is list and snapshot[name] == [], "private-snapshot-" + name)
    if prior_revision is not None:
        require(revision > prior_revision, "private-restart-revision-not-advanced")
    return revision


def inside(args, root, expected):
    global PHASE
    PHASE = "private-vault-context"
    require(root.is_absolute() and root.parent == Path("/tmp").resolve() and root.name.startswith("omux-g-")
            and args.stage_root == root / "carrier", "private-fixture-root")
    root_descriptor = generation.open_root(root)
    os.close(root_descriptor)
    require(os.environ.get("OMUX_ISOLATED_VAULT_PROOF") == "private-bus-private-xdg"
            and os.environ.get("DBUS_SESSION_BUS_ADDRESS", "").split(",")[0] == "unix:abstract=omux-selected-" + root.name,
            "private-vault-context")
    # The caller-created private HOME/XDG directories must still be owned.
    for name, child in PRIVATE_DIRECTORIES:
        require(os.environ.get(name) == str(root / child), "private-directory-binding")
        descriptor = generation.open_root(root / child)
        os.close(descriptor)
    state = Path(os.environ["XDG_STATE_HOME"]) / "omux-dev"
    state_parent = generation.open_root(state.parent)
    try:
        state_descriptor = create_directory(state_parent, state.name)
        os.close(state_descriptor)
    finally:
        os.close(state_parent)
    environment = dict(os.environ, OMUX_INSTANCE="dev", PATH="/nonexistent")
    socket_path = Path(environment["XDG_RUNTIME_DIR"]) / (
        "omux-" + hashlib.sha256(str(state).encode()).hexdigest()[:32]) / "control.sock"
    require(len(os.fsencode(socket_path)) <= 107, "private-socket-path-bound")
    keyring_process, daemon_process = None, None

    def select():
        return generation.select_generation(args.stage_root, args.generation, args.receipt_sha256,
                                            expected_artifacts=expected, require_portable=True)

    def cli(method):
        selected = select()
        process = subprocess.Popen([str(selected.cli), "--state-dir", str(state), "rpc", method, "-"],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=environment)
        try:
            process.stdin.write(b"{}")
            process.stdin.close()
            code, output, diagnostics = collect(process, 3, MAX_OUTPUT)
        except BaseException:
            stop_owned(process)
            raise
        finally:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
        require(code == 0 and diagnostics == b"", "selected-cli-refused")
        response = generation.parse(output)
        require(type(response) is dict and type(response.get("result")) is dict and "error" not in response,
                "selected-cli-response-shape")
        return response["result"]

    try:
        PHASE = "private-keyring"
        keyring_process = subprocess.Popen([str(args.keyring), "--foreground", "--unlock", "--components=secrets"],
                                           stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                           env=environment)
        keyring_process.stdin.write(b"\n")
        keyring_process.stdin.close()
        # Match the verified isolated custody lane's bounded allowance for
        # Secret Service to acquire its private bus name. Actual health still
        # has to prove available custody; this delay is not a readiness claim.
        time.sleep(0.5)
        baseline = None
        initial_revision = None
        for attempt in range(2):
            PHASE = "selected-daemon-startup"
            selected = select()
            daemon_process = subprocess.Popen([str(selected.daemon), "--state-dir", str(state)],
                                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                              stderr=subprocess.DEVNULL, env=environment)
            deadline = time.monotonic() + 15
            ready = False
            while time.monotonic() < deadline:
                require(keyring_process.poll() is None, "private-keyring-exited")
                require(daemon_process.poll() is None, "selected-daemon-exited")
                if socket_path.is_socket():
                    try:
                        health = cli("system.health")
                        ready = health.get("custody_available") is True and health.get("protocol_version") == 2
                        if ready:
                            info = socket_path.lstat()
                            require(stat.S_ISSOCK(info.st_mode) and info.st_uid == os.geteuid()
                                    and stat.S_IMODE(info.st_mode) == 0o600, "private-socket-custody")
                            break
                    except (RestartError, OSError, subprocess.TimeoutExpired):
                        pass
                time.sleep(0.05)
            require(ready, "selected-daemon-startup-deadline")
            PHASE = "selected-empty-authority"
            baseline = empty_snapshot_revision(cli("state.snapshot"), baseline)
            if initial_revision is None:
                initial_revision = baseline
            PHASE = "selected-daemon-shutdown"
            stop_owned(daemon_process, clean=True)
            daemon_process = None
        return restart_facts(args.generation, args.receipt_sha256, expected, args.tool_manifest_sha256,
                             startup_revision_delta=baseline - initial_revision)
    finally:
        if daemon_process is not None:
            stop_owned(daemon_process)
        if keyring_process is not None:
            stop_owned(keyring_process)


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("--stage-root", type=Path, required=True)
    value.add_argument("--generation", required=True)
    value.add_argument("--receipt-sha256", required=True)
    for name in ("core", "daemon", "extension"):
        value.add_argument("--" + name + "-sha256", required=True)
    for name in ("session", "bus", "keyring"):
        value.add_argument("--" + name, type=Path, required=True)
    value.add_argument("--tool-manifest", type=Path, required=True)
    value.add_argument("--inside", type=Path, help=argparse.SUPPRESS)
    return value


def main():
    global PHASE, CHILD_PHASE, CHILD_REASON
    args = parser().parse_args()
    expected = {name: getattr(args, name + "_sha256") for name in ("core", "daemon", "extension")}
    require(all(generation.SHA256.fullmatch(value) for value in expected.values()), "expected-artifact-digest-shape")
    PHASE = "declared-tools"
    qualify_private_tools(args)
    if args.inside is not None:
        facts = inside(args, args.inside, expected)
    else:
        with tempfile.TemporaryDirectory(prefix="omux-g-", dir="/tmp") as temporary:
            root = Path(temporary)
            environment = private_environment(root)
            copied_root = root / "carrier"
            PHASE = "carrier-copy"
            carrier(args.stage_root, args.generation, args.receipt_sha256, expected, copied_root)
            configuration = root / "bus.conf"
            write_private(configuration, ('<busconfig><type>session</type><listen>unix:abstract=omux-selected-'
                          + root.name + '</listen><auth>EXTERNAL</auth><policy context="default">'
                          '<allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/>'
                          '</policy></busconfig>').encode(), 0o600)
            bootstrap = "import os,runpy,sys;p=sys.argv.pop(1);sys.path.insert(0,os.path.dirname(p));sys.argv[0]=p;runpy.run_path(p,run_name='__main__')"
            child_arguments = ["--stage-root", str(copied_root), "--generation", args.generation,
                               "--receipt-sha256", args.receipt_sha256, "--session", str(args.session),
                               "--bus", str(args.bus), "--keyring", str(args.keyring),
                               "--tool-manifest", str(args.tool_manifest), "--inside", str(root)]
            for name, digest in expected.items():
                child_arguments.extend(["--" + name + "-sha256", digest])
            PHASE = "private-session"
            process = subprocess.Popen([str(args.session), "--dbus-daemon=" + str(args.bus),
                                        "--config-file=" + str(configuration), "--", sys.executable,
                                        "-I", "-B", "-c", bootstrap, str(Path(__file__).absolute()), *child_arguments],
                                       env=environment, start_new_session=True, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, umask=0o077)
            code, output, diagnostics = collect(process, 80, MAX_RECEIPT_OUTPUT, private_group=True)
            PHASE = "private-session-result"
            for line in diagnostics.splitlines():
                if len(line) > 1024:
                    continue
                try:
                    diagnostic = generation.parse(line)
                except (ValueError, UnicodeError, RecursionError):
                    continue
                if (type(diagnostic) is dict and set(diagnostic) == {"scope", "result", "phase", "reason"}
                        and diagnostic.get("scope") == SCOPE and diagnostic.get("result") == "refused"
                        and type(diagnostic.get("phase")) is str and diagnostic["phase"] in PHASES
                        and type(diagnostic.get("reason")) is str and diagnostic["reason"] in REASONS):
                    CHILD_PHASE = diagnostic["phase"]
                    CHILD_REASON = diagnostic["reason"]
            require(code == 0, "private-selected-session-refused")
            facts = generation.parse(output)
            require(type(facts) is dict, "private-selected-session-receipt")
            require(facts == restart_facts(args.generation, args.receipt_sha256, expected,
                                          args.tool_manifest_sha256,
                                          startup_revision_delta=facts.get("startupRevisionDelta")),
                    "private-selected-session-receipt")
    PHASE = "receipt-output"
    encoded = json.dumps(facts, sort_keys=True, separators=(",", ":"))
    require(len(encoded.encode()) + 1 <= MAX_RECEIPT_OUTPUT, "restart-receipt-bound")
    print(encoded)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as failure:
        print(json.dumps(failure_diagnostic(failure), sort_keys=True), file=sys.stderr)
        sys.exit(1)
