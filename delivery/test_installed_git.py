"""Actual installed helper invoked by ordinary Git, without provider work.

No accounts or credential payloads are supplied. Genuine isolated Secret
Service and the production daemon establish the NoEligibleAccount boundary.
Normal Git config/helper lookup, no-prompt fallback and owned removal are the
predicates; this is neither remote repository access nor process handoff.
"""
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time

import test_installed_native_interop as support

PHASE = "private-context"
PHASES = ("private-context", "package-install", "keyring-startup", "daemon-startup",
          "git-integration-install", "installed-baseline", "ordinary-git-fill",
          "installed-baseline-stop", "installed-baseline-reopen", "installed-baseline-revision",
          "installed-baseline-public-snapshot", "installed-baseline-post-restart-seal", "installed-baseline-adapter-count",
          "no-eligible-boundary", "fallback-preservation", "owned-integration-remove", "owned-cleanup")
WITNESS_PREFIXES = ("installed-baseline", "fallback-preservation", "owned-integration-remove")
WITNESS_PHASES = ("sql-open", "sql-schema", "sql-seal", "sql-grants", "sql-snapshot",
                  "snapshot-decode", "snapshot-domain", "snapshot-obligations", "snapshot-owners",
                  "snapshot-installed", "authority-read")
PHASES += tuple(prefix + "-" + stage for prefix in WITNESS_PREFIXES for stage in WITNESS_PHASES)
MARKER = b"OMUX_INSTALLED_GIT_HELPER_OK\n"
RESTART_PREFIX = b"OMUX_INSTALLED_GIT_RESTART_DELTA="
LIMIT = 65536
CONTEXT = b"protocol=https\nhost=github.com\npath=fixture/repository.git\n\n"


def require(condition, message):
    support.require(condition, message)


def snapshot_witness(value):
    # Engine.publicSnapshot captures the real clock on every read. Exclude
    # only that observation timestamp; revision and every authority/domain
    # field remain part of the exact comparison.
    require(isinstance(value, dict) and type(value.get("captured_at")) is int,
            "public snapshot observation shape changed")
    return {name: item for name, item in value.items() if name != "captured_at"}


def run_git(git, environment, cwd, arguments, payload=b""):
    require(len(payload) <= 1024, "private Git input exceeded bound")
    selector = selectors.DefaultSelector()
    try:
        process = subprocess.Popen([str(git), *arguments], cwd=cwd, env=environment,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, umask=0o077)
    except BaseException:
        selector.close()
        raise
    output, diagnostics = bytearray(), bytearray()
    try:
        process.stdin.write(payload)
        process.stdin.close()
        for stream, target in ((process.stdout, output), (process.stderr, diagnostics)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, target)
        deadline = time.monotonic() + 12
        while selector.get_map():
            require(time.monotonic() < deadline, "private Git output deadline exceeded")
            for key, _ in selector.select(0.1):
                chunk = os.read(key.fd, 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                require(len(key.data) + len(chunk) <= LIMIT, "private Git output exceeded bound")
                key.data.extend(chunk)
        code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        return code, bytes(output), bytes(diagnostics)
    finally:
        selector.close()
        if not process.stdin.closed:
            process.stdin.close()
        support.stop(process)
        process.stdout.close()
        process.stderr.close()


def stopped_witness(state, *, installed, phase_prefix):
    global PHASE
    require(phase_prefix in WITNESS_PREFIXES, "stopped witness phase is not declared")
    # Only after the production daemon closes. Read SQL through a genuinely
    # read-only connection and release it before any exclusive writer restart.
    PHASE = phase_prefix + "-sql-open"
    with closing(sqlite3.connect((state / "state.sqlite").as_uri() + "?mode=ro", uri=True)) as metadata:
        PHASE = phase_prefix + "-sql-schema"
        require(metadata.execute("PRAGMA user_version").fetchone()[0] == 3, "fresh SQL schema changed")
        PHASE = phase_prefix + "-sql-seal"
        support.check_sealed_snapshot(metadata, state / "state.sqlite.authority")
        PHASE = phase_prefix + "-sql-grants"
        require(metadata.execute("SELECT count(*) FROM grants").fetchone()[0] == 0,
                "provider-free Git retained encrypted credentials")
        PHASE = phase_prefix + "-sql-snapshot"
        rows = metadata.execute("SELECT revision,CAST(metadata_json AS BLOB) FROM snapshot").fetchall()
    require(len(rows) == 1 and len(rows[0][1]) <= 16 * 1024 * 1024, "sealed snapshot bound changed")
    PHASE = phase_prefix + "-snapshot-decode"
    persisted = json.loads(rows[0][1])
    PHASE = phase_prefix + "-snapshot-domain"
    support.check_empty_domain(persisted["state"])
    PHASE = phase_prefix + "-snapshot-obligations"
    require(persisted["request_authority"]["records"] == [] and persisted["outcome_intents"] == []
            and persisted["snapshot_admission"]["credits"] == [], "Git fallback retained request/effect authority")
    PHASE = phase_prefix + "-snapshot-owners"
    ledger = persisted["native_owner_authority"]
    require(all(ledger[field] == [] for field in ("owners", "attachments", "removals")),
            "Git helper created rich-session native custody")
    PHASE = phase_prefix + "-snapshot-installed"
    require(("git" in persisted["installed_integrations"]) is installed, "Git installed state changed")
    PHASE = phase_prefix + "-authority-read"
    return rows[0], support.private_file(state / "state.sqlite.authority", 152)


def no_eligible(adapter_socket, capability):
    # Independent truthful production error classification. This is a real
    # authenticated adapter packet; it neither fabricates a grant nor bypasses
    # the helper's ordinary Git invocation, counted separately below.
    request = {"jsonrpc": "2.0", "id": 1, "method": "adapter.gitGet", "params": {
        "application": "git", "capability": capability.decode("ascii"), "request": {
            "protocol": "https", "host": "github.com", "path": "fixture/repository.git"}}}
    packet = json.dumps(request, separators=(",", ":")).encode() + b"\n"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(5)
        channel.connect(str(adapter_socket))
        channel.sendall(packet)
        response = bytearray()
        while b"\n" not in response:
            chunk = channel.recv(4096)
            require(chunk and len(response) + len(chunk) <= LIMIT, "private adapter reply exceeded bound")
            response.extend(chunk)
    require(response.endswith(b"\n") and response.count(b"\n") == 1, "private adapter reply frame changed")
    value = json.loads(response)
    require(value.get("jsonrpc") == "2.0" and value.get("id") == 1 and "result" not in value
            and value.get("error", {}).get("message") == "NoEligibleAccount",
            "empty account set did not report NoEligibleAccount")
    require(b"password" not in response and b"access_token" not in response,
            "private adapter refusal exposed credential fields")


def inside(bundle, keyring, git, root):
    global PHASE
    require(os.environ.get("OMUX_ISOLATED_VAULT_PROOF") == "private-bus-private-xdg",
            "disposable genuine vault context required")
    PHASE = "package-install"
    prefix, records = root / "installed", root / "records"
    payload = support.pack.read_bundle(bundle)
    manifest, _ = support.pack.verify_bundle(payload)
    require(manifest["distribution"] == "portable-linux", "actual portable Linux archive required")
    require(manifest.get("channel") == "release", "default-instance archive required")
    record = support.install.install_bundle(payload, prefix, records)
    require(not record["serviceActivated"], "fixture activated host service")
    # Ordinary helper invocation supplies no --state-dir override. Match the
    # real Linux XDG default, so a missing capability cannot masquerade as an
    # authenticated empty-account fallback.
    state = Path(os.environ["XDG_STATE_HOME"]) / "omux"
    state.mkdir(mode=0o700)
    home, work = root / "h", root / "w"
    home.mkdir(mode=0o700)
    work.mkdir(mode=0o700)
    config = home / ".gitconfig"
    original = b"# private installed Git fixture\n[core]\n\tautocrlf = false\n"
    config.write_bytes(original)
    config.chmod(0o600)
    environment = dict(os.environ)
    environment.update(HOME=str(home), PATH=str(prefix / "bin") + os.pathsep + str(git.parent),
                       GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0", OMUX_INSTANCE="default")
    run = Path(environment["XDG_RUNTIME_DIR"]) / ("omux-" + hashlib.sha256(str(state).encode()).hexdigest()[:32])
    control_socket, adapter_socket = run / "control.sock", run / "adapter.sock"
    require(len(os.fsencode(control_socket)) <= 107, "installed control path too long")
    keyring_process = daemon = None
    drains = []

    def cli(method, params=None):
        for drain in drains:
            drain.check()
        return support.run_cli([str(prefix / "bin/omux"), "rpc", method, "-"], environment, params or {})

    def start():
        process = subprocess.Popen([str(prefix / "bin/omuxd")], env=environment,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, umask=0o077)
        drains.append(support.DiscardLog(process.stdout))
        try:
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                require(process.poll() is None and keyring_process.poll() is None, "installed custody process exited")
                if control_socket.is_socket() and adapter_socket.is_socket():
                    for path in (control_socket, adapter_socket):
                        information = path.lstat()
                        require(information.st_uid == os.getuid() and stat.S_IMODE(information.st_mode) == 0o600,
                                "installed socket custody changed")
                    health = cli("system.health")
                    require(health["custody_available"] and health["protocol_version"] == 2
                            and health["live_handoff_proven"] is False, "installed custody unavailable")
                    return process
                time.sleep(0.05)
            raise ValueError("installed daemon startup deadline exceeded")
        except BaseException:
            support.stop(process)
            raise

    def adapter_count():
        value = cli("reliability.export")
        cell = value["cells"][value["metrics"].index("control_request")][value["operations"].index("adapter")]
        return sum(cell[field] for field in ("good", "bad", "excluded", "unobserved"))

    try:
        PHASE = "keyring-startup"
        keyring_process = subprocess.Popen([str(keyring), "--foreground", "--unlock", "--components=secrets"],
                                           env=environment, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.STDOUT, umask=0o077)
        drains.append(support.DiscardLog(keyring_process.stdout))
        keyring_process.stdin.write(b"\n")
        keyring_process.stdin.close()
        time.sleep(0.5)
        PHASE = "daemon-startup"
        daemon = start()
        support.check_empty_domain(cli("state.snapshot"))
        PHASE = "git-integration-install"
        installed = cli("integrations.install", {"adapter": "git", "config_path": str(config),
                        "operation_id": os.urandom(32).hex(), "expected_revision": cli("system.health")["revision"]})
        require(installed.get("installed") is True and installed.get("changed") is True
                and installed.get("config_path") == str(config), "actual Git integration was not installed")
        capability_path = state / "integrations/git.capability"
        capability = support.private_file(capability_path, 128)
        require(re.fullmatch(rb"[0-9a-f]{64}", capability) is not None, "installed Git capability changed")
        code, output, diagnostics = run_git(git, environment, work, ["config", "--global", "--get-all", "credential.helper"])
        require(code == 0 and output == b"omux\n" and diagnostics == b"", "ordinary Git did not read installed helper")
        code, output, diagnostics = run_git(git, environment, work,
                                          ["config", "--global", "--get-urlmatch", "credential.useHttpPath", "https://github.com/fixture/repository.git"])
        require(code == 0 and output == b"true\n" and diagnostics == b"", "ordinary Git repository context was disabled")
        PHASE = "installed-baseline"
        prior_public = snapshot_witness(cli("state.snapshot"))
        PHASE = "installed-baseline-stop"
        support.stop(daemon, require_success=True)
        daemon = None
        baseline = stopped_witness(state, installed=True, phase_prefix="installed-baseline")
        PHASE = "installed-baseline-reopen"
        daemon = start()
        PHASE = "installed-baseline-revision"
        restart_revision = cli("system.health")["revision"]
        require(type(restart_revision) is int and baseline[0][0] < restart_revision <= 2**63 - 1,
                "production restart did not advance committed revision")
        restart_delta = restart_revision - baseline[0][0]
        PHASE = "installed-baseline-public-snapshot"
        before = snapshot_witness(cli("state.snapshot"))
        require(before.get("revision") == restart_revision
                and {key: value for key, value in before.items() if key != "revision"}
                == {key: value for key, value in prior_public.items() if key != "revision"},
                "production restart changed logical domain or integration state")
        # Production startup commits restored metadata and integration recovery.
        # Freeze its new seal before either helper request, without opening the
        # exclusively owned SQL writer. Successful startup authenticates custody;
        # stopped_witness later independently joins this exact seal to SQL bytes.
        PHASE = "installed-baseline-post-restart-seal"
        authority_before = support.private_file(state / "state.sqlite.authority", 152)
        require(len(authority_before) == 152 and authority_before[:8] == b"OMUXR002"
                and int.from_bytes(authority_before[80:88], "little") == restart_revision
                and authority_before[8:40] == baseline[1][8:40]
                and int.from_bytes(authority_before[40:48], "little") > int.from_bytes(baseline[1][40:48], "little"),
                "post-restart sealed baseline did not join committed custody")
        post_restart = (restart_revision, authority_before[88:120], authority_before)
        PHASE = "installed-baseline-adapter-count"
        before_count = adapter_count()
        PHASE = "ordinary-git-fill"
        code, output, diagnostics = run_git(git, environment | {"GIT_TRACE": "1"}, work, ["credential", "fill"], CONTEXT)
        require(code != 0 and output == b"" and b"terminal prompts disabled" in diagnostics,
                "ordinary Git empty-account fallback prompted or emitted credentials")
        require(re.search(rb"run_command:.*git credential-omux get", diagnostics) is not None,
                "ordinary Git did not invoke the installed helper")
        require(adapter_count() == before_count + 1, "installed Git helper did not reach production adapter")
        PHASE = "no-eligible-boundary"
        no_eligible(adapter_socket, capability)
        require(adapter_count() == before_count + 2, "independent empty-account request was not recorded")
        PHASE = "fallback-preservation"
        require(snapshot_witness(cli("state.snapshot")) == before, "Git fallback changed domain state or revision")
        support.stop(daemon, require_success=True)
        daemon = None
        final_stored, final_authority = stopped_witness(state, installed=True, phase_prefix="fallback-preservation")
        require((final_stored[0], hashlib.sha256(final_stored[1]).digest(), final_authority) == post_restart,
                "Git fallback changed post-restart sealed snapshot or authority")
        require(json.loads(final_stored[1])["state"] == json.loads(baseline[0][1])["state"],
                "production reopen or Git fallback changed durable logical domain")
        daemon = start()
        PHASE = "owned-integration-remove"
        unrelated = b"[alias]\n\tstatusshort = status --short\n"
        with config.open("ab") as stream:
            stream.write(unrelated)
        removed = cli("integrations.remove", {"adapter": "git", "config_path": str(config),
                      "operation_id": os.urandom(32).hex(), "expected_revision": cli("system.health")["revision"]})
        require(removed.get("removed") is True and removed.get("changed") is True
                and removed.get("config_path") == str(config), "owned Git integration removal failed")
        require(support.private_file(config, LIMIT) == original + unrelated and not capability_path.exists(),
                "Git removal lost unrelated configuration or retained capability")
        support.stop(daemon, require_success=True)
        daemon = None
        stopped_witness(state, installed=False, phase_prefix="owned-integration-remove")
        PHASE = "owned-cleanup"
        uninstalled = support.install.uninstall(prefix, records)
        require(uninstalled["preserved"] == [] and len(uninstalled["removed"]) == len(record["files"])
                and (state / "state.sqlite.authority").is_file(), "owned distribution cleanup changed retained state")
        print((RESTART_PREFIX + str(restart_delta).encode("ascii") + b"\n" + MARKER).decode("ascii"), end="")
    finally:
        actions = []
        if daemon is not None:
            actions.append(lambda: support.stop(daemon))
        if keyring_process is not None:
            actions.append(lambda: support.stop(keyring_process))
        actions.extend(drain.join for drain in drains)
        failed = False
        for action in actions:
            try:
                action()
            except Exception:
                failed = True
        require(not failed, "owned private Git process cleanup failed")


def main():
    if len(sys.argv) == 6 and sys.argv[1] == "--inside":
        inside(*(Path(value).resolve(strict=True) for value in sys.argv[2:]))
        return 0
    require(len(sys.argv) == 6, "declared archive, private vault tools and pinned Git required")
    bundle, session, bus, keyring, git = (Path(value).resolve(strict=True) for value in sys.argv[1:])
    with tempfile.TemporaryDirectory(prefix="omux-g-", dir="/tmp") as temporary:
        root = Path(temporary)
        environment = {"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "/nonexistent", "HOME": str(root),
                       "OMUX_ISOLATED_VAULT_PROOF": "private-bus-private-xdg"}
        for name, child in (("XDG_RUNTIME_DIR", "r"), ("XDG_DATA_HOME", "d"), ("XDG_CONFIG_HOME", "c"),
                            ("XDG_CACHE_HOME", "k"), ("XDG_STATE_HOME", "s")):
            directory = root / child
            directory.mkdir(mode=0o700)
            environment[name] = str(directory)
        configuration = root / "bus.conf"
        configuration.write_text('<busconfig><type>session</type><listen>unix:abstract=omux-git-' + root.name
                                 + '</listen><auth>EXTERNAL</auth><policy context="default">'
                                 '<allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/>'
                                 '</policy></busconfig>')
        bootstrap = ("import os,runpy,sys;p=sys.argv.pop(1);sys.path.insert(0,os.path.dirname(p));"
                     "sys.argv[0]=p;runpy.run_path(p,run_name='__main__')")
        process = subprocess.Popen([str(session), "--dbus-daemon=" + str(bus), "--config-file=" + str(configuration),
                                    "--", sys.executable, "-I", "-B", "-c", bootstrap, str(Path(__file__).absolute()),
                                    "--inside", str(bundle), str(keyring), str(git), str(root)],
                                   env=environment, start_new_session=True, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, umask=0o077)
        code, output, diagnostics = support.bounded_private_session(process)
        if code == 0:
            observed = re.fullmatch(re.escape(RESTART_PREFIX) + rb"([1-9][0-9]{0,18})\n" + re.escape(MARKER), output)
            require(observed is not None and int(observed.group(1)) <= 2**63 - 1,
                    "installed ordinary Git proof marker or bounded restart delta missing")
            print(output.decode("ascii"), end="")
        else:
            for phase in PHASES:
                marker = "installed ordinary Git proof failed at " + phase
                if marker.encode() + b"\n" in diagnostics:
                    print(marker, file=sys.stderr)
                    break
        return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("installed ordinary Git proof failed at " + PHASE, file=sys.stderr)
        sys.exit(1)
