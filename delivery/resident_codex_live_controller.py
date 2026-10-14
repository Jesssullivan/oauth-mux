"""Guard-admitted resident RUN using genuine ordinary Codex native history.

No resident installation, lifecycle control, credential-source read, vault
process or working-profile write occurs here. One-time native integration setup
is allowed only before an active Codex registry exists.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import stat
import fcntl
import pty
import signal
import struct
import termios
import selectors
import subprocess
import sys
import time

# Only the declared sibling runfiles tools are admitted; never resolve this
# main's symlink into an ambient working checkout.
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))

import resident_codex_live_composition as resident
import test_installed_codex_live_continuity as live
import test_installed_native_tui as tui
import test_installed_native_interop as support


def require(value):
    live.require(value, "resident Codex controller refused")


def identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def directory_identity(info):
    # Native state legitimately changes child entries and directory timestamps.
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)


def private_directory(path):
    """Hold the exact canonical directory, rejecting aliases and writable parents."""
    path = Path(path)
    require(path.is_absolute() and os.path.normpath(str(path)) == str(path)
            and all(part not in ("", ".", "..") for part in path.parts[1:]))
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in path.parts[1:]:
            before = os.fstat(descriptor)
            require(before.st_uid in (0, os.getuid())
                    and (before.st_mode & 0o022 == 0
                         or (before.st_uid == 0 and before.st_mode & 0o1000 != 0)))
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def write_new(directory, name, contents, mode):
    require(isinstance(contents, bytes) and name not in ("", ".", "..")
            and "/" not in name and mode in (0o600, 0o644, 0o755))
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 mode, dir_fd=directory)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            require(stream.write(contents) == len(contents))
            stream.flush()
        os.fchmod(fd, mode)
        os.fsync(fd)
    finally:
        os.close(fd)


def profile_config(model, work):
    require(isinstance(model, str) and live.re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", model))
    # This new profile contains no auth source or copied broker configuration.
    # The daemon's genuine reversible install is the sole broker-table writer.
    return ('model = ' + json.dumps(model) + '\n'
        'cli_auth_credentials_store = "file"\nsandbox_mode = "read-only"\napproval_policy = "never"\n'
        'check_for_update_on_startup = false\n'
        '[tui]\nscreen_reader_detection_done = true\n'
        '[otel]\nexporter = "none"\ntrace_exporter = "none"\nmetrics_exporter = "none"\nlog_user_prompt = false\n'
        '[cloud.skills]\nenabled = false\n'
        '[analytics]\nenabled = false\n'
        '[features]\nplugins = false\nrecommended_plugins = false\napps = false\nenable_mcp_apps = false\n'
        '[projects.' + json.dumps(str(work)) + ']\ntrust_level = "trusted"\n').encode()


class ProofProfile:
    """Create only fresh children of the guard-selected host-visible proof root."""

    def __init__(self, root, model, manifest, files, *, remaining=lambda: None):
        self.remaining = remaining
        self.remaining()
        self.root = Path(root)
        self.fd = private_directory(self.root)
        self.root_identity = os.fstat(self.fd)
        self.closed = False
        self.runtime_fences = []
        self.directory_fences = []
        try:
            require(os.listdir(self.fd) == [])
            self.home, self.work = self.root / "c", self.root / "w"
            require(len(os.fsencode(self.home)) <= 68)
            for name in ("c", "w", "h", "r", "d", "k", "s", "candidate"):
                os.mkdir(name, 0o700, dir_fd=self.fd)
            self.config = self.home / "config.toml"
            home_fd = private_directory(self.home)
            try:
                write_new(home_fd, "config.toml", profile_config(model, self.work), 0o600)
                os.fsync(home_fd)
            finally:
                os.close(home_fd)
            self.candidate = self.root / "candidate"
            runtime_directories = {self.root / name for name in ("c", "w", "h", "r", "d", "k", "s", "candidate")}
            # The independent public verifier already admitted every package
            # pathname/mode/digest. Still refuse links, traversal or overwrites.
            for name, payload in files.items():
                self.remaining()
                path = Path(name)
                require(not path.is_absolute() and all(part not in ("", ".", "..") for part in path.parts)
                        and str(path) == name)
                parent = self.candidate
                for part in path.parts[:-1]:
                    parent = parent / part
                    runtime_directories.add(parent)
                    try:
                        parent.mkdir(mode=0o700)
                    except FileExistsError:
                        pass
                    directory = private_directory(parent)
                    os.close(directory)
                directory = private_directory(parent)
                try:
                    mode = 0o644 if name == "runtime-manifest.json" else manifest["files"][name]["mode"]
                    # Public runtime may contain data with read-only mode.
                    require(mode in (0o644, 0o755))
                    write_new(directory, path.name, payload, mode)
                    os.fsync(directory)
                finally:
                    os.close(directory)
                file_fd = os.open(self.candidate / path,
                                  os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    info = os.fstat(file_fd)
                    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                            and info.st_nlink == 1 and info.st_size == len(payload)
                            and stat.S_IMODE(info.st_mode) == mode)
                    digest = hashlib.sha256()
                    total = 0
                    while total < len(payload):
                        self.remaining()
                        block = os.read(file_fd, min(1024 * 1024, len(payload) - total))
                        require(block)
                        digest.update(block)
                        total += len(block)
                    require(total == len(payload) and not os.read(file_fd, 1)
                            and digest.digest() == hashlib.sha256(payload).digest()
                            and identity(info) == identity(os.fstat(file_fd)))
                    self.runtime_fences.append((self.candidate / path, file_fd, info))
                except BaseException:
                    os.close(file_fd)
                    raise
            for directory in sorted(runtime_directories):
                directory_fd = private_directory(directory)
                self.directory_fences.append((directory, directory_fd, os.fstat(directory_fd)))
            self.binary = self.candidate / "bin/codex"
            require(self.binary.is_file() and not self.binary.is_symlink())
            self.recheck()
        except BaseException:
            self.close()
            raise

    def recheck(self):
        # Root directory timestamps may change as owned children are created;
        # its inode, owner, kind and mode must remain exact.
        self.remaining()
        current = os.fstat(self.fd)
        named_fd = private_directory(self.root)
        try:
            require(directory_identity(current) == directory_identity(self.root_identity)
                    == directory_identity(os.fstat(named_fd)))
        finally:
            os.close(named_fd)
        try:
            os.stat(self.home / "auth.json", follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            require(False)
        for directory, held_fd, expected in self.directory_fences:
            named_fd = private_directory(directory)
            try:
                require(directory_identity(os.fstat(held_fd)) == directory_identity(expected)
                        == directory_identity(os.fstat(named_fd)))
            finally:
                os.close(named_fd)
        for path, fd, expected in self.runtime_fences:
            self.remaining()
            require(identity(os.fstat(fd)) == identity(expected)
                    == identity(os.stat(path, follow_symlinks=False)))

    def environment(self):
        # The native process has only its empty owned profile and configured
        # daemon capability path. It never inherits a working CODEX_HOME/auth.
        return {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/nonexistent",
                "HOME": str(self.root / "h"), "CODEX_HOME": str(self.home),
                "TERM": "xterm-256color", "OMUX_INSTANCE": "default",
                "XDG_RUNTIME_DIR": str(self.root / "r"),
                "XDG_DATA_HOME": str(self.root / "d"),
                "XDG_CONFIG_HOME": str(self.root / "h"),
                "XDG_CACHE_HOME": str(self.root / "k"),
                "XDG_STATE_HOME": str(self.root / "s")}

    def close(self):
        if not self.closed:
            for _, fd, _ in self.runtime_fences:
                os.close(fd)
            self.runtime_fences = []
            for _, fd, _ in self.directory_fences:
                os.close(fd)
            self.directory_fences = []
            os.close(self.fd)
            self.closed = True
        # Keep genuinely prepared native state and owned integration registry.
        # Removing either is a separate custody operation, never failure cleanup.


class ResidentBootstrap(support.JsonProcess):
    """Bound native bootstrap IO/cleanup to the original guardian deadline."""

    def __init__(self, context, command, environment, cwd, *, popen_factory=None):
        self.context, self.guard_active = context, True
        self.process = self.selector = self.diagnostics = None
        self.buffer, self.output_bytes, self.identifier = bytearray(), 0, 0
        try:
            context.recheck()
            require(context.remaining() >= 20)
            launch = subprocess.Popen if popen_factory is None else popen_factory
            self.process = launch(command, env=environment, cwd=cwd,
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, umask=0o077)
            self.diagnostics = support.DiscardLog(self.process.stderr)
            self.selector = selectors.DefaultSelector()
            os.set_blocking(self.process.stdout.fileno(), False)
            os.set_blocking(self.process.stdin.fileno(), False)
            self.selector.register(self.process.stdout, selectors.EVENT_READ)
        except BaseException:
            self.close()
            raise

    def alive(self):
        if self.guard_active:
            self.context.remaining()
        super().alive()

    def send(self, method, params, identifier=None):
        self.alive()
        value = {"method": method, "params": params}
        if identifier is not None:
            value["id"] = identifier
        packet = json.dumps(value, separators=(",", ":")).encode() + b"\n"
        require(len(packet) <= 8192)
        offset = 0
        with selectors.DefaultSelector() as writable:
            writable.register(self.process.stdin, selectors.EVENT_WRITE)
            while offset < len(packet):
                self.alive()
                left = self.context.remaining()
                if not writable.select(min(0.1, left)):
                    continue
                try:
                    count = os.write(self.process.stdin.fileno(), packet[offset:])
                except (BlockingIOError, InterruptedError):
                    continue
                require(0 < count <= len(packet) - offset)
                offset += count

    def call(self, method, params, timeout=20):
        return super().call(method, params, min(timeout, self.context.remaining()))

    def close(self, require_success=False):
        self.guard_active = False
        process = self.process
        if process is None:
            return
        self.process = None
        code = None
        try:
            if process.stdin is not None:
                process.stdin.close()
            if require_success:
                try:
                    code = process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        finally:
            try:
                support.stop(process)
            finally:
                if self.selector is not None:
                    selector, self.selector = self.selector, None
                else:
                    selector = None
                try:
                    if selector is not None:
                        selector.close()
                finally:
                    try:
                        if process.stdout is not None:
                            process.stdout.close()
                    finally:
                        if self.diagnostics is not None:
                            diagnostics, self.diagnostics = self.diagnostics, None
                            diagnostics.join()
                        elif process.stderr is not None:
                            process.stderr.close()
        if require_success:
            require(code == 0)


class ResidentTerminal(tui.TerminalProcess):
    """Use the ordinary declared PTY branch with owned cleanup on setup faults."""

    def __init__(self, context, candidate, environment, cwd, resume=None,
                 *, cli_overrides=(), popen_factory=None):
        self.context, self.guard_active = context, True
        self.master = self.selector = self.process = None
        self.closed, self.total, self.suffix = False, 0, b""
        self.failure_observer = None
        slave = None
        try:
            context.recheck()
            require(context.remaining() >= 20)
            self.master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
            bootstrap = ("import os,runpy,sys;p=sys.argv.pop(1);sys.path.insert(0,os.path.dirname(p));"
                         "sys.argv[0]=p;runpy.run_path(p,run_name='__main__')")
            command = [sys.executable, "-I", "-B", "-c", bootstrap,
                       str(Path(tui.__file__).absolute()), "--pty-exec",
                       str(candidate), str(cwd), str(os.getpid())]
            if resume is not None:
                command.append(resume)
            if cli_overrides:
                command.extend(["--cli-overrides", json.dumps(list(cli_overrides), separators=(",", ":"))])
            self.selector = selectors.DefaultSelector()
            os.set_blocking(self.master, False)
            self.selector.register(self.master, selectors.EVENT_READ)
            launch = subprocess.Popen if popen_factory is None else popen_factory
            self.process = launch(command, env=environment, cwd=cwd, stdin=slave,
                                  stdout=slave, stderr=slave, start_new_session=True, umask=0o077)
        except BaseException:
            self.close()
            raise
        finally:
            if slave is not None:
                os.close(slave)

    def pump(self, duration=0.05):
        if self.guard_active:
            duration = min(duration, self.context.remaining())
        super().pump(duration)
        if self.guard_active:
            self.context.remaining()

    def send(self, value):
        if self.guard_active:
            self.context.recheck()
            self.context.remaining()
        super().send(value)

    def close(self, require_success=False):
        if self.closed:
            return
        try:
            if self.process is not None and require_success:
                self.send("/quit\r")
                deadline = time.monotonic() + min(10, self.context.remaining())
                status = None
                while time.monotonic() < deadline:
                    self.pump()
                    status = self.exited()
                    if status is not None:
                        break
                require(status is not None and status.si_code == os.CLD_EXITED and status.si_status == 0)
        finally:
            self.guard_active = False
            try:
                if self.process is not None:
                    # WNOWAIT anchors this own child/PGID even after natural
                    # exit. Never reap it before signaling its exact group.
                    os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    require(os.getpgid(self.process.pid) == self.process.pid)
                    try:
                        os.killpg(self.process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    self.process.wait(timeout=5)
            finally:
                try:
                    if self.selector is not None:
                        selector, self.selector = self.selector, None
                        selector.close()
                finally:
                    try:
                        if self.master is not None:
                            master, self.master = self.master, None
                            os.close(master)
                    finally:
                        self.closed = True


def require_absent_integration(context):
    status = context.control("integrations.status")
    require(isinstance(status, dict) and isinstance(status.get("installed"), list)
            and "codex" not in status["installed"])


def install_native(context, profile, environment):
    bootstrap = None
    try:
        context.recheck()
        require_absent_integration(context)
        bootstrap = ResidentBootstrap(context,
            [str(profile.binary), "app-server", "--listen", "stdio://", "--strict-config"],
            environment, profile.work)
        bootstrap.call("initialize", {"clientInfo": {
            "name": "omux-resident-native-proof", "title": None, "version": "1"},
            "capabilities": {"experimentalApi": False, "requestAttestation": False}})
        bootstrap.send("initialized", {})
        endpoint = support.owned_endpoint(profile.home, bootstrap)
        context.recheck()
        operation = os.urandom(32).hex()
        result = context.control("integrations.install", {
            "adapter": "codex", "codex_home": str(profile.home),
            "config_path": str(profile.config), "native_socket": str(endpoint),
            "operation_id": operation,
            "expected_revision": context.control("system.health")["revision"]})
        require(result.get("installed") is True and result.get("changed") is True
                and result.get("config_path") == str(profile.config))
        # Context captures capability metadata through O_PATH only. Native
        # opens its bytes through the daemon-produced config, not this reader.
        context.capture_native_capability(profile.config)
        context.recheck()
        bootstrap.close(require_success=True)
        bootstrap = None
        require(not endpoint.exists())
        profile.recheck()
        return support.private_file(profile.config, 1024 * 1024)
    finally:
        if bootstrap is not None:
            bootstrap.close()


def prepare_native_profile(context, scenario, profile, environment):
    """Read the qualified CLI's bundled catalogue within the original budget."""
    context.recheck()
    profile.recheck()
    require(context.remaining() >= 20)
    process = None
    original = support.DEADLINE_SECONDS
    try:
        process = subprocess.Popen([str(profile.binary), "debug", "models", "--bundled"],
            env=environment, cwd=profile.work, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, umask=0o077)
        # Reserve owned group/stream cleanup before the external metadata call.
        support.DEADLINE_SECONDS = min(15, context.remaining() - 5)
        require(support.DEADLINE_SECONDS > 0)
        code, output, _ = support.bounded_private_session(process)
        context.remaining()
        require(code == 0)
        catalogue = json.loads(output, object_pairs_hook=tui.strict_object)
        scenario.reasoning_effort = live.minimum_reasoning_effort(catalogue, scenario.manifest["model"])
        scenario.cli_overrides = (
            'omux_broker.context_mode="text_transcript_v1"',
            'model_reasoning_summary="none"',
            'model_reasoning_effort=' + json.dumps(scenario.reasoning_effort),
        )
    finally:
        support.DEADLINE_SECONDS = original
        if process is not None:
            try:
                # The shared helper ordinarily cleans its group itself.
                # Constructor/selector/early IO faults still leave our exact
                # leader unreaped, so preserve ownership before fallback kill.
                if process.returncode is None:
                    os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    require(os.getpgid(process.pid) == process.pid)
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5)
            finally:
                try:
                    if process.stdout is not None:
                        process.stdout.close()
                finally:
                    if process.stderr is not None:
                        process.stderr.close()


def qualified_runtime_pin(context, pin, *, bound=Path("/omux-resident-live-inputs/runtime-pin.json")):
    """Compare only closed public packaging metadata with the guard's selection."""
    context.remaining()
    public_pin = json.loads(live.public_runtime_file(pin, 65536), object_pairs_hook=tui.strict_object)
    bound_pin = json.loads(live.public_runtime_file(bound, 65536), object_pairs_hook=tui.strict_object)
    fields = {"kind", "archive_sha256", "archive_bytes", "receipt_sha256", "receipt_bytes",
              "manifest_sha256", "manifest_bytes"}
    for value in (public_pin, bound_pin):
        require(type(value) is dict and set(value) == fields and value["kind"] == live.FRESH_KIND)
        for role, maximum in (("archive", support.runtime_package.MAX_ARCHIVE_BYTES),
                              ("receipt", live.MAX_PUBLIC_RUNTIME_METADATA),
                              ("manifest", live.MAX_PUBLIC_RUNTIME_METADATA)):
            require(type(value[role + "_sha256"]) is str
                    and live.re.fullmatch(r"[0-9a-f]{64}", value[role + "_sha256"])
                    and type(value[role + "_bytes"]) is int
                    and 0 < value[role + "_bytes"] <= maximum)
    require(public_pin == bound_pin)
    context.remaining()
    return public_pin


def materialize_native_history(home, thread, terminal, endpoint, observed):
    """Require genuine rollout metadata before rename; empty Markdown is no proof."""
    pid = terminal.process.pid
    terminal.send("/export omux-native-resume-fixture.md\r")
    tui.wait_metadata(home, thread, terminal, expected_name=None)
    terminal.alive()
    require(terminal.process.pid == pid and tui.status(endpoint, thread) == observed)
    terminal.send("/rename " + tui.FIXTURE_NAME + "\r")
    return tui.wait_metadata(home, thread, terminal)


def execute(context, candidate, receipt, pin):
    context.recheck()
    require(context.remaining() >= 360)
    # The guardian independently validates the actual complete package chain.
    qualified_runtime_pin(context, pin)
    require_absent_integration(context)
    scenario = resident.ResidentScenario(
        context.model, context.selected_accounts, pin,
        allow_account_wide_drain=context.allow_account_wide_drain,
        drain_account_handle=context.drain_account_handle)
    scenario.check_domain(context.control("state.snapshot"))
    context.remaining()
    manifest, files = scenario.read_runtime_bundle(candidate, receipt)
    context.remaining()
    terminal = None
    require(manifest["chain"]["patch_sha256"] == live.PROTOCOL_HISTORY_PATCHES)
    require(set(manifest["chain"]["native_protocol_history"]) ==
            {"protocol", "schema", "cli", "artifact_envelopes", "artifact_files"})
    context.remaining()
    with_profile = ProofProfile(context.proof_root, context.model, manifest, files, remaining=context.remaining)
    try:
        environment = with_profile.environment()
        require(context.remaining() >= 20)
        prepare_native_profile(context, scenario, with_profile, environment)
        configured = install_native(context, with_profile, environment)
        def retained_setup():
            context.remaining()
            with_profile.recheck()
            context.recheck()
            require(support.private_file(with_profile.config, 1024 * 1024) == configured)
        retained_setup()
        terminal = ResidentTerminal(context, with_profile.binary, environment, with_profile.work,
                                       cli_overrides=scenario.cli_overrides)
        first_pid = terminal.process.pid
        endpoint, thread, first = tui.wait_loaded(with_profile.home, terminal)
        original = materialize_native_history(with_profile.home, thread, terminal, endpoint, first)
        tui.detach(context.control, endpoint, thread, first)
        require(tui.metadata(with_profile.home, thread) == original)
        retained_setup()
        terminal.close(require_success=True)
        terminal = None
        require(not endpoint.exists() and tui.metadata(with_profile.home, thread) == original)
        retained_setup()
        terminal = ResidentTerminal(context, with_profile.binary, environment, with_profile.work,
                                       resume=thread, cli_overrides=scenario.cli_overrides)
        endpoint, resumed_thread, second = tui.wait_loaded(with_profile.home, terminal)
        require(resumed_thread == thread and terminal.process.pid != first_pid
                and second["nativeRef"] != first["nativeRef"]
                and second["ownerId"] != first["ownerId"])
        resumed = tui.wait_resumed_checkpoint(with_profile.home, thread, terminal, original)
        retained_setup()
        proof = scenario.prove_attached(
            context.control, retained_setup, with_profile.home, thread, terminal,
            endpoint, second, resumed, candidate, receipt)
        require(scenario.history(with_profile.home, thread, resumed) == proof["completed_history"])
        terminal.close(require_success=True)
        terminal = None
        require(scenario.history(with_profile.home, thread, resumed) == proof["completed_history"]
                and not endpoint.exists())
        retained_setup()
        # The guard-owned publisher wraps only this validated closed projection.
        # Exact rollout/config/private binding observations never leave memory.
        context.publish_native_projection(proof["native_result"])
    finally:
        try:
            if terminal is not None:
                terminal.close()
        finally:
            with_profile.close()


def bounded_native_rpc(context, endpoint, method, params):
    context.recheck()
    # Resident recheck may consume time. Reserve the native call only after
    # it returns and preserve one absolute cap across every socket phase.
    started = time.monotonic()
    deadline = started + min(5, context.remaining())
    result = live.checked_native_rpc(endpoint, method, params, deadline=deadline)
    context.remaining()
    return result


def main():
    require(len(sys.argv) == 4)
    candidate, receipt, pin = (Path(value).resolve(strict=True) for value in sys.argv[1:])
    from guard_resident_continuity_profile import ControllerContext
    support.owned_endpoint = live.checked_owned_endpoint
    with ControllerContext.open() as context:
        tui.native_rpc = lambda endpoint, method, params: bounded_native_rpc(context, endpoint, method, params)
        execute(context, candidate, receipt, pin)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("resident Codex controller failed", file=sys.stderr)
        sys.exit(1)
