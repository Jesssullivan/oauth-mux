"""Actual Chromium extension/native-host transport, isolated synthetic context.

Declared Linux Bazel lane only. Uses a fresh private profile, D-Bus vault and
development daemon. CDP is a test harness, never product browser automation.
No provider navigation, cookie reading, account verification or grants occur.
The browser executable and complete closure must be declared Nix/Bazel inputs.
"""
from contextlib import closing
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

import install
import pack
import test_installed_custody as custody
import browser_runtime_authority

stop = custody.stop
PHASE = "private-context"
SESSION = "outer"
REASON = "unclassified"
SUBPHASE = "none"
CHILD_DIAGNOSTIC = None
ROOT_METADATA = {}
PHASES = {
    "private-context", "argument-contract", "runtime-authority", "runtime-mask", "runtime-closure",
    "runtime-tools", "private-session", "private-session-bootstrap", "private-session-wait", "private-session-result",
    "private-session-cleanup", "install-extension", "private-keyring", "development-daemon",
    "cross-channel", "independent-synthetic-source", "actual-chromium", "durable-metadata",
    "ownership-uninstall",
}
REASONS = {
    "unclassified", "assertion_failed", "runtime_authority_invalid", "runtime_authority_unavailable",
    "runtime_mask_missing", "runtime_mask_invalid", "runtime_closure_unavailable", "runtime_tool_unqualified",
    "declared_input_unavailable", "child_refused", "child_startup_failed", "child_import_failed", "deadline_exceeded",
    "fixture_io_failed", "resource_exhausted",
    "runtime_closure_missing", "runtime_closure_unreadable", "runtime_closure_special",
    "runtime_closure_alias_unqualified", "runtime_closure_alias_target_invalid",
    "runtime_closure_alias_nar_mismatch",
}
HARNESS_PHASES = {
    "chromium-startup", "chromium-native-health", "chromium-extension-tab-boundary",
    "chromium-service-permission-refusal", "chromium-service-uncertain-connect",
    "chromium-restart", "chromium-shipped-worker-recovery",
    "chromium-uncertain-source-seed", "chromium-uncertain-host-disabled", "chromium-uncertain-native-dispatch",
    "chromium-uncertain-service-outcome", "chromium-uncertain-source-metadata", "chromium-uncertain-source-state",
    "chromium-uncertain-request-identity", "chromium-uncertain-redacted-status",
    "chromium-uncertain-no-mutations", "chromium-uncertain-permissions",
}
SUBPHASES = HARNESS_PHASES | {
    "none", "harness-invocation", "harness-completion", "receipt-bound", "receipt-json",
    "receipt-contract", "journal-bound", "journal-json", "journal-fields", "journal-mutation-order",
    "snapshot-query", "snapshot-source-isolation", "daemon-stop", "sealed-snapshot", "retained-grants",
    "owned-uninstall",
}
MARKER = b"OMUX_INSTALLED_CHROMIUM_SYNTHETIC_SERVICE_RECOVERY_OK\n"


def require(condition, message, reason="assertion_failed"):
    global REASON
    if not condition:
        REASON = reason if reason in REASONS else "unclassified"
    custody.require(condition, message)


def project_child_diagnostic(stream):
    # Private child diagnostics may contain native/library output. Read only a
    # bounded tail and project our finite vocabulary; never forward raw lines.
    stream.seek(0, os.SEEK_END)
    stream.seek(max(0, stream.tell() - 16384))
    selected = None
    for line in stream.read(16384).splitlines():
        if len(line) > 1024 or not line.startswith(b"{"):
            continue
        try:
            value = json.loads(line)
        except (ValueError, UnicodeError, RecursionError):
            continue
        if (type(value) is dict and set(value) in (
                {"scope", "session", "phase", "reason"}, {"scope", "session", "phase", "reason", "subphase"})
                and all(type(item) is str for item in value.values())
                and value.get("scope") == "installed-chromium-fixture-diagnostic"
                and value.get("session") == "inner" and value.get("phase") in PHASES
                and value.get("reason") in REASONS and value.get("subphase", "none") in SUBPHASES):
            selected = {"child_phase": value["phase"], "child_reason": value["reason"],
                        "child_subphase": value.get("subphase", "none")}
    return selected


def project_harness_subphase(stream):
    # The harness already emits one fixed phase line on failure. Project only
    # exact allowlisted lines from a bounded tail, never arbitrary stderr text.
    stream.seek(0, os.SEEK_END)
    stream.seek(max(0, stream.tell() - 16384))
    allowed = {("installed Chromium transport failed at " + phase).encode("ascii"): phase
               for phase in HARNESS_PHASES}
    selected = "harness-completion"
    for line in stream.read(16384).splitlines():
        if line in allowed:
            selected = allowed[line]
    return selected


def diagnostic(failure):
    reason = REASON
    if reason == "unclassified":
        if isinstance(failure, (subprocess.TimeoutExpired, TimeoutError)):
            reason = "deadline_exceeded"
        elif isinstance(failure, OSError):
            reason = "fixture_io_failed"
        elif isinstance(failure, MemoryError):
            reason = "resource_exhausted"
        elif isinstance(failure, ValueError):
            reason = "assertion_failed"
    value = {"scope": "installed-chromium-fixture-diagnostic", "session": SESSION,
             "phase": PHASE if PHASE in PHASES else "private-context", "reason": reason,
             "subphase": SUBPHASE if SUBPHASE in SUBPHASES else "none"}
    if CHILD_DIAGNOSTIC is not None:
        value.update(CHILD_DIAGNOSTIC)
    return value


def inside(bundle, extension_archive, chromium, node, harness, keyring, root, recorder):
    global PHASE, SUBPHASE
    require(os.environ.get("OMUX_ISOLATED_VAULT_PROOF") == "private-bus-private-xdg",
            "private browser/vault namespace required")
    PHASE = "install-extension"
    prefix, records, extension, profile = root / "prefix", root / "records", root / "extension", root / "profile"
    payload = pack.read_bundle(bundle)
    bundle_manifest, _ = pack.verify_bundle(payload)
    require(bundle_manifest["distribution"] == "portable-linux" and bundle_manifest.get("channel") == "development",
            "Chromium fixture requires development-bound Linux bundle")
    record = install.install_bundle(payload, prefix, records)
    require(record["serviceActivated"] is False, "fixture installer activated a host service")
    extension.mkdir(mode=0o700)
    profile.mkdir(mode=0o700)
    with zipfile.ZipFile(extension_archive) as archive:
        require(len(archive.infolist()) <= 64, "extension archive entry bound exceeded")
        names = set()
        for entry in archive.infolist():
            path = PurePosixPath(entry.filename)
            require(not path.is_absolute() and ".." not in path.parts and len(path.parts) <= 2
                    and entry.filename not in names and not entry.is_dir() and entry.file_size <= 262144,
                    "extension archive shape invalid")
            require((entry.external_attr >> 16) & 0o170000 != stat.S_IFLNK,
                    "extension archive contains symbolic link")
            names.add(entry.filename)
            destination = extension / entry.filename
            destination.parent.mkdir(mode=0o700, exist_ok=True)
            destination.write_bytes(archive.read(entry))
            destination.chmod(0o600)
    manifest = json.loads((extension / "manifest.json").read_bytes())
    import base64
    key = base64.b64decode(manifest["key"], validate=True)
    identity = "".join(chr(97 + int(value, 16)) for value in hashlib.sha256(key).hexdigest()[:32])
    require((extension / "shared/channel.mjs").read_text() ==
            'export const CHANNEL = "development";\nexport const INSTANCE = "dev";\n'
            'export const NATIVE_HOST = "ai.xoxd.omux.dev";\n', "development archive channel mismatch")
    # Chromium's user-level native host lookup is below its user-data-dir.
    # These fixture-owned manifests are the same exact-ID stdio contract as the
    # declarative installation; no real user profile or managed file is touched.
    host_directory = profile / "NativeMessagingHosts"
    host_directory.mkdir(mode=0o700)
    # The declared test-only observer forwards only bounded synthetic frames to
    # this exact installed host. It is not included in any product artifact.
    native_host = prefix / "bin/omux-native-host"
    journal, configuration, observed_host = root / "native-journal.jsonl", root / "native-recorder.json", root / "recorder-host"
    journal.write_bytes(b"")
    journal.chmod(0o600)
    configuration.write_text(json.dumps({"nativeHost": str(native_host),
                                         "nativeHostSha256": hashlib.sha256(native_host.read_bytes()).hexdigest(),
                                         "journal": str(journal), "extensionId": identity}, separators=(",", ":")))
    configuration.chmod(0o600)
    recorder_payload = recorder.read_bytes()
    require(len(recorder_payload) <= 262144, "declared native observer exceeds bound")
    interpreter = str(Path(sys.executable).resolve(strict=True))
    require(interpreter.startswith("/nix/store/") and "\n" not in interpreter and " " not in interpreter,
            "native observer requires declared Python interpreter")
    observed_host.write_bytes(("#!" + interpreter + " -I\n").encode("ascii") + recorder_payload)
    observed_host.chmod(0o700)
    host_manifest = {"name": "ai.xoxd.omux.dev", "description": "Omux isolated browser test host",
                     "path": str(observed_host), "type": "stdio",
                     "allowed_origins": ["chrome-extension://" + identity + "/"]}
    registration = host_directory / "ai.xoxd.omux.dev.json"
    registration.write_text(json.dumps(host_manifest, separators=(",", ":")))
    registration.chmod(0o600)
    environment = dict(os.environ, PATH="/nonexistent", OMUX_INSTANCE="dev",
                       OMUX_CHROMIUM_RECORDER_CONFIG=str(configuration))
    # Host uses default state selection; daemon receives that identical path.
    state = Path(environment["XDG_STATE_HOME"]) / "omux-dev"
    state.mkdir(mode=0o700)
    diagnostics = tempfile.TemporaryFile(dir=root)
    keyring_process, daemon_process = None, None

    def cli(method):
        completed = subprocess.run([str(prefix / "bin/omux"), "--state-dir", str(state), "rpc", method, "-"],
                                   input=b"{}", capture_output=True, env=environment, timeout=12)
        require(completed.returncode == 0 and completed.stderr == b"", "browser fixture control query failed")
        response = json.loads(completed.stdout)
        require("result" in response and "error" not in response, "browser fixture control refused")
        return response["result"]

    def native_request(method, identifier, params):
        request = json.dumps({"version": 1, "id": identifier, "method": method, "params": params},
                             separators=(",", ":")).encode("ascii")
        completed = subprocess.run([str(prefix / "bin/omux-native-host"),
                                    "chrome-extension://" + identity + "/", "--state-dir", str(state)],
                                   input=len(request).to_bytes(4, "little") + request,
                                   stdout=subprocess.PIPE, stderr=diagnostics, env=environment, timeout=12)
        require(completed.returncode == 0 and 4 < len(completed.stdout) <= 4096,
                "fixture native request did not return a bounded response")
        require(int.from_bytes(completed.stdout[:4], "little") == len(completed.stdout) - 4,
                "fixture native response frame changed")
        response = json.loads(completed.stdout[4:])
        require(response.get("version") == 1 and response.get("id") == identifier,
                "fixture native response correlation changed")
        return response

    def reject_other_channel(method):
        identifier = "chromium-wrong-channel-" + method
        params = {"provenance": {"browser": "chromium", "extensionId": identity, "channel": "release"}}
        if method == "browser.connect":
            params.update(sourceId="chromium-cross-channel-context", adapter="github", origin="https://github.com")
        response = native_request(method, identifier, params)
        require(response.get("version") == 1 and response.get("id") == identifier
                and "result" not in response and response.get("error", {}).get("code") == "BrowserChannelMismatch",
                "cross-channel browser request reached the wrong refusal boundary")

    try:
        PHASE = "private-keyring"
        keyring_process = subprocess.Popen([str(keyring), "--foreground", "--unlock", "--components=secrets"],
                                           stdin=subprocess.PIPE, stdout=diagnostics, stderr=diagnostics)
        keyring_process.stdin.write(b"\n")
        keyring_process.stdin.close()
        time.sleep(0.5)
        PHASE = "development-daemon"
        daemon_process = subprocess.Popen([str(prefix / "bin/omuxd"), "--state-dir", str(state)],
                                          stdin=subprocess.DEVNULL, stdout=diagnostics,
                                          stderr=diagnostics, env=environment)
        socket_path = Path(environment["XDG_RUNTIME_DIR"]) / (
            "omux-" + hashlib.sha256(str(state).encode()).hexdigest()[:32]) / "control.sock"
        deadline = time.monotonic() + 12
        ready = False
        while time.monotonic() < deadline:
            require(daemon_process.poll() is None, "development daemon startup failed")
            if socket_path.is_socket():
                try:
                    ready = cli("system.health")["custody_available"] is True
                    if ready:
                        break
                except (ValueError, OSError, subprocess.TimeoutExpired):
                    pass
            time.sleep(0.05)
        require(ready, "development daemon startup deadline exceeded")
        before_crossed = cli("state.snapshot")
        require(before_crossed["sources"] == [], "browser fixture started with preexisting context")
        PHASE = "cross-channel"
        reject_other_channel("browser.health")
        reject_other_channel("browser.connect")
        after_crossed = cli("state.snapshot")
        for field in ("revision", "sources", "accounts", "grants", "observations"):
            require(after_crossed[field] == before_crossed[field],
                    "cross-channel browser request changed development authority")
        PHASE = "independent-synthetic-source"
        independent_id = "installed-chromium-independent-context"
        independent_response = native_request("browser.connect", "chromium-independent-connect", {
            "sourceId": independent_id, "adapter": "github", "origin": "https://github.com",
            "provenance": {"browser": "chromium", "extensionId": identity, "channel": "development"}})
        require(independent_response.get("result", {}).get("accepted") is True
                and "error" not in independent_response, "independent synthetic source refused")
        before_browser = cli("state.snapshot")
        require(before_browser["accounts"] == [] and before_browser["grants"] == []
                and len(before_browser["sources"]) == 1
                and before_browser["sources"][0]["id"] == independent_id
                and before_browser["sources"][0]["status"] == "connected",
                "independent synthetic source scope changed")
        independent = before_browser["sources"][0]
        PHASE = "actual-chromium"
        with tempfile.TemporaryFile(dir=root) as browser_output:
            SUBPHASE = "harness-invocation"
            completed = subprocess.run([str(node), str(harness), str(chromium), str(extension), str(profile), str(journal)],
                                       stdin=subprocess.DEVNULL, stdout=browser_output,
                                       stderr=diagnostics, env=environment, timeout=70)
            SUBPHASE = project_harness_subphase(diagnostics) if completed.returncode != 0 else "harness-completion"
            require(completed.returncode == 0, "actual Chromium transport fixture failed", "child_refused")
            browser_output.seek(0)
            SUBPHASE = "receipt-bound"
            receipt_payload = browser_output.read(4097)
            require(len(receipt_payload) <= 4096, "actual browser receipt exceeds bound")
            SUBPHASE = "receipt-json"
            receipt = json.loads(receipt_payload)
        SUBPHASE = "receipt-contract"
        require(receipt == {"scope": "installed-chromium-synthetic-browser-service-recovery",
                            "browserVersion": "Chrome/147.0.7727.116", "extensionId": identity,
                            "channel": "development", "providerAccess": False, "grantExport": False,
                            "restarted": True, "permissionGranted": False, "toolbarConsentProved": False,
                            "retainedConnectId": True, "distinctDisconnectId": True},
                "actual browser receipt scope/version mismatch")
        SUBPHASE = "journal-bound"
        journal_payload = journal.read_bytes()
        require(len(journal_payload) <= 16384, "native observer journal exceeds bound")
        SUBPHASE = "journal-json"
        rows = [json.loads(value) for value in journal_payload.splitlines()]
        SUBPHASE = "journal-fields"
        require(len(rows) <= 64 and all(set(row) == {"id", "method", "sourceId"} for row in rows),
                "native observer retained unexpected fields")
        SUBPHASE = "journal-mutation-order"
        mutations = [row for row in rows if row["method"] != "browser.health"]
        require(len(mutations) == 2 and mutations[0] == {
            "id": "chromium-recovery-connect", "method": "browser.connect",
            "sourceId": "installed-chromium-synthetic-context"}
                and mutations[1]["method"] == "browser.disconnect"
                and mutations[1]["sourceId"] == mutations[0]["sourceId"]
                and mutations[1]["id"] != mutations[0]["id"],
                "shipped worker did not replay retained connect before distinct disconnect")
        SUBPHASE = "snapshot-query"
        snapshot = cli("state.snapshot")
        SUBPHASE = "snapshot-source-isolation"
        sources = {source["id"]: source for source in snapshot["sources"]}
        require(snapshot["accounts"] == [] and snapshot["grants"] == [] and len(sources) == 2
                and sources.get(independent_id) == independent
                and sources.get("installed-chromium-synthetic-context", {}).get("status") == "disconnected",
                "actual browser source lifecycle changed unexpected authority")
        PHASE = "durable-metadata"
        SUBPHASE = "daemon-stop"
        stop(daemon_process, require_success=True)
        daemon_process = None
        with closing(sqlite3.connect(state / "state.sqlite")) as metadata:
            SUBPHASE = "sealed-snapshot"
            custody.check_sealed_snapshot(metadata, state / "state.sqlite.authority")
            SUBPHASE = "retained-grants"
            require(metadata.execute("SELECT count(*) FROM grants").fetchone()[0] == 0,
                    "browser fixture retained unexpected grant")
        PHASE = "ownership-uninstall"
        SUBPHASE = "owned-uninstall"
        removed = install.uninstall(prefix, records)
        require(removed["preserved"] == [] and len(removed["removed"]) == len(record["files"]),
                "browser fixture owned uninstall failed")
        print(MARKER.decode(), end="")
    finally:
        if daemon_process is not None:
            stop(daemon_process)
        if keyring_process is not None:
            stop(keyring_process)
        diagnostics.close()


def qualified_runtime(authority_argument):
    global PHASE, REASON, ROOT_METADATA
    # Validate both prior proof bindings before even resolving candidate tool
    # aliases. The producer joins declared public receipts; it runs no browser.
    PHASE = "runtime-authority"
    authority_path = Path(authority_argument).absolute()
    try:
        with authority_path.open("rb") as stream:
            authority_bytes = stream.read(browser_runtime_authority.MAX_AUTHORITY + 1)
    except OSError:
        REASON = "runtime_authority_unavailable"
        raise
    try:
        qualification = browser_runtime_authority.validate_authority(authority_bytes)
    except (ValueError, UnicodeError, KeyError, TypeError, RecursionError):
        REASON = "runtime_authority_invalid"
        raise
    roots = qualification["storePaths"]
    # The authority validator already binds and validates this exact inventory.
    # Retain its declared reference edges for root-symlink qualification only.
    inventory = browser_runtime_authority.parse(base64.b64decode(qualification["inventoryBase64"], validate=True))
    ROOT_METADATA = {row["path"]: row for row in inventory["paths"]}
    # The execution-mask gate is separate from mapping and NAR qualification.
    # Until the contained runner establishes it, no candidate tool is resolved.
    PHASE = "runtime-mask"
    require(os.environ.get("OMUX_BROWSER_HOST_CONFIGURATION") == "host-configurations-unavailable",
            "contained browser host configuration mask not established", "runtime_mask_missing")
    for blocked in qualification["requiredUnavailablePaths"]:
        try:
            information = os.lstat(blocked)
        except (FileNotFoundError, PermissionError):
            continue
        if blocked == "/etc/environment":
            require(stat.S_ISREG(information.st_mode) and information.st_mode & 0o777 == 0,
                    "host environment configuration remains readable", "runtime_mask_invalid")
            continue
        require(stat.S_ISDIR(information.st_mode), "required host config mask is not a directory", "runtime_mask_invalid")
        # The contained lane may mount an empty directory. Check only directory
        # entries; never follow a config alias or read host configuration bytes.
        try:
            require(not os.listdir(blocked), "host Bluetooth configuration remains visible", "runtime_mask_invalid")
        except PermissionError:
            pass
    return roots


def main():
    global PHASE, SESSION, REASON, CHILD_DIAGNOSTIC
    PHASE = "argument-contract"
    SESSION = "inner" if len(sys.argv) > 1 and sys.argv[1] == "--inside" else "outer"
    require(len(sys.argv) == 11, "declared archive/extension/browser/Node/vault/observer inputs required")
    if sys.argv[1] == "--inside":
        roots = qualified_runtime(sys.argv[10])
        PHASE = "runtime-tools"
        try:
            values = [Path(value).resolve(strict=True) for value in sys.argv[2:10]]
        except OSError:
            REASON = "declared_input_unavailable"
            raise
        require(all(any(str(tool).startswith(root + "/") for root in roots) for tool in values[2:4]),
                "private Chromium tools do not belong to qualified closure", "runtime_tool_unqualified")
        inside(*values)
        return 0
    roots = qualified_runtime(sys.argv[10])
    authority_path = Path(sys.argv[10]).absolute()
    PHASE = "runtime-closure"
    try:
        browser_runtime_authority.validate_runtime_roots(roots, ROOT_METADATA)
    except browser_runtime_authority.RuntimeRootError as failure:
        REASON = failure.reason
        raise
    PHASE = "runtime-tools"
    try:
        bundle, extension, chromium, node, harness, session, bus, keyring, recorder = (
            Path(value).resolve(strict=True) for value in sys.argv[1:10])
    except OSError:
        REASON = "declared_input_unavailable"
        raise
    require(any(str(chromium).startswith(value + "/") for value in roots),
            "Chromium executable does not belong to declared browser closure", "runtime_tool_unqualified")
    require(any(str(node).startswith(value + "/") for value in roots),
            "Node executable does not belong to declared qualified closure", "runtime_tool_unqualified")
    PHASE = "private-context"
    with tempfile.TemporaryDirectory(prefix="omux-c-", dir="/tmp") as temporary:
        root = Path(temporary)
        environment = os.environ.copy()
        for name in ("DBUS_SESSION_BUS_ADDRESS", "DBUS_STARTER_ADDRESS", "DBUS_STARTER_BUS_TYPE",
                     "GNOME_KEYRING_CONTROL", "SSH_AUTH_SOCK", "LD_PRELOAD", "LD_AUDIT", "LD_DEBUG",
                     "LD_LIBRARY_PATH", "OMUX_INSTANCE", "XDG_DATA_DIRS", "DISPLAY", "WAYLAND_DISPLAY",
                     "NIXOS_OZONE_WL", "NODE_OPTIONS", "NODE_PATH", "OMUX_CHROMIUM_RECORDER_CONFIG"):
            environment.pop(name, None)
        for name, child in (("XDG_RUNTIME_DIR", "r"), ("XDG_DATA_HOME", "d"), ("XDG_CONFIG_HOME", "c"),
                            ("XDG_CACHE_HOME", "k"), ("XDG_STATE_HOME", "s")):
            directory = root / child
            directory.mkdir(mode=0o700)
            environment[name] = str(directory)
        environment["OMUX_ISOLATED_VAULT_PROOF"] = "private-bus-private-xdg"
        configuration = root / "bus.conf"
        configuration.write_text('<busconfig><type>session</type><listen>unix:abstract=omux-chromium-'
                                 + root.name + '</listen><auth>EXTERNAL</auth><policy context="default">'
                                 '<allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/>'
                                 '</policy></busconfig>')
        bootstrap = (
            "import os,runpy,sys,json\n"
            "p=sys.argv.pop(1);sys.path.insert(0,os.path.dirname(p));sys.argv[0]=p\n"
            "try:\n runpy.run_path(p,run_name='__main__')\n"
            "except Exception:\n"
            " print(json.dumps({'scope':'installed-chromium-fixture-diagnostic','session':'inner',"
            "'phase':'private-session-bootstrap','reason':'child_import_failed'},separators=(',',':')),file=sys.stderr)\n"
            " sys.exit(1)\n")
        with tempfile.TemporaryFile(dir=root) as output, tempfile.TemporaryFile(dir=root) as diagnostics:
            PHASE = "private-session"
            try:
                # Preserve the logical Bazel runfiles parent. Resolving this
                # source alias would import siblings from the source checkout.
                process = subprocess.Popen([str(session), "--dbus-daemon=" + str(bus),
                                            "--config-file=" + str(configuration), "--", sys.executable,
                                            "-I", "-B", "-c", bootstrap, str(Path(__file__).absolute()), "--inside",
                                            str(bundle), str(extension), str(chromium), str(node), str(harness),
                                            str(keyring), str(root), str(recorder), str(authority_path)], env=environment, start_new_session=True,
                                           stdout=output, stderr=diagnostics, umask=0o077)
            except OSError:
                REASON = "child_startup_failed"
                raise
            try:
                PHASE = "private-session-wait"
                deadline = time.monotonic() + 110
                # Do not poll(), communicate() or wait() here: each may reap
                # the leader and free its numeric PID/PGID before cleanup.
                while True:
                    status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    if status is not None:
                        require(status.si_pid == process.pid, "private Chromium leader identity changed")
                        code = status.si_status if status.si_code == os.CLD_EXITED else -status.si_status
                        break
                    require(time.monotonic() < deadline, "private Chromium session deadline exceeded", "deadline_exceeded")
                    time.sleep(0.05)
                PHASE = "private-session-result"
                CHILD_DIAGNOSTIC = project_child_diagnostic(diagnostics)
                output.seek(0)
                require(code == 0 and output.read(len(MARKER) + 1) == MARKER,
                        "actual Chromium private fixture failed", "child_refused")
            finally:
                # Chromium, Node, native hosts, daemon, keyring and bus inherit
                # this unique group. A live or WNOWAIT zombie leader still pins
                # its PID. Refuse signaling if it is no longer our child/group.
                # This validation also covers timeout and exception paths.
                anchored = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                require(anchored is None or anchored.si_pid == process.pid,
                        "private Chromium cleanup leader identity changed")
                require(os.getpgid(process.pid) == process.pid,
                        "private Chromium cleanup group ownership changed")
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    # A zombie leader still pins this ID even if no remaining
                    # group member is signalable. It is safe to reap only now.
                    pass
                process.wait(timeout=5)
            print(MARKER.decode(), end="")
            return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as failure:
        print(json.dumps(diagnostic(failure), separators=(",", ":")), file=sys.stderr)
        sys.exit(1)
