"""Installed native-messaging transport with a disposable genuine OS vault.

This is a synthetic browser-context fixture. It runs the installed production
native host and daemon, not Chromium or Firefox. It proves framing, source
metadata lifecycle, caller/context rejection and development/release separation.
Paired exact-ID registration joins installed artifacts to the development
extension and an explicitly local-only RELEASE_EVALUATION keyed source archive.
That evaluation identity is unsigned, unpublished and not a Web Store identity.
It does not prove browser installation, browser consent, provider acquisition,
verified account enrollment, usable grants, renewal or application continuity.
No provider calls or credential payloads are authorized by this fixture.
"""
from __future__ import annotations

from contextlib import closing
import base64
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

# Keep the declared runfiles spelling: resolving its symlink could select the
# ambient source tree instead of the declared sibling extension input.
FIXTURE_SCRIPT = Path(__file__).absolute()
sys.path.insert(1, str(FIXTURE_SCRIPT.parent.parent / "extensions"))

import install
import native_host_setup
import pack
import test_installed_custody as custody

require = custody.require
stop = custody.stop
LIMIT = 262144
EXTENSION = "abcdefghijklmnopabcdefghijklmnop"
OTHER_EXTENSION = "b" * 32
MARKER = b"OMUX_INSTALLED_SYNTHETIC_BROWSER_TRANSPORT_OK\n"
PHASE = "private-context"
REFUSAL_CODE = "unclassified"
SAFE_REFUSAL_CODES = ("NeedsProviderAdapterProof", "NativeHostProvenanceMismatch", "BrowserContextMismatch",
                      "BrowserChannelMismatch",
                      "NotFound", "InvalidRequest", "InvalidIdentifier", "OriginMismatch", "FixtureDisabled",
                      "SourceUnauthorized", "ServiceBusy", "ServiceStopping", "Timeout", "unclassified")
PHASES = ("private-context", "package-install", "paired-RELEASE_EVALUATION-registration", "keyring-startup", "daemon-startup",
          "native-health", "malformed-frame", "caller-provenance", "context-lifecycle",
          "provider-disabled", "cross-channel", "durable-source-metadata", "registration-removal", "owned-cleanup")


def envelope(method: str, identifier: str, params: dict) -> dict:
    return {"version": 1, "id": identifier, "method": method, "params": params}


def provenance(extension: str = EXTENSION, channel: str = "release") -> dict:
    return {"browser": "chromium", "extensionId": extension, "channel": channel}


def encoded(value: dict) -> bytes:
    payload = json.dumps(value, separators=(",", ":")).encode("ascii")
    require(0 < len(payload) <= LIMIT, "fixture request exceeds native frame bound")
    return len(payload).to_bytes(4, "little") + payload


def read_exact(process: subprocess.Popen, count: int, deadline: float) -> bytes:
    data = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        while len(data) < count:
            remaining = deadline - time.monotonic()
            require(remaining > 0 and bool(selector.select(remaining)), "native reply deadline exceeded")
            chunk = os.read(process.stdout.fileno(), count - len(data))
            require(bool(chunk), "native host returned incomplete frame")
            data.extend(chunk)
    return bytes(data)


class Host:
    def __init__(self, prefix: Path, state: Path, environment: dict, diagnostics, extension: str = EXTENSION):
        self.channel = "development" if environment["OMUX_INSTANCE"] == "dev" else "release"
        self.process = subprocess.Popen(
            [str(prefix / "bin/omux-native-host"), "chrome-extension://" + extension + "/",
             "--state-dir", str(state)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=diagnostics, env=environment, bufsize=0,
        )

    def call(self, request: dict, validation_error: str | None = None) -> dict:
        global REFUSAL_CODE
        frame = encoded(request)
        # Every fixture frame is far smaller than PIPE_BUF: writes are bounded.
        require(len(frame) < 4096, "fixture frame exceeds bounded pipe write")
        require(self.process.stdin.write(frame) == len(frame), "native input write incomplete")
        deadline = time.monotonic() + 12
        header = read_exact(self.process, 4, deadline)
        length = int.from_bytes(header, "little")
        require(0 < length <= LIMIT, "native reply exceeds frame bound")
        reply = json.loads(read_exact(self.process, length, deadline))
        require(type(reply) is dict and type(reply.get("version")) is int and reply["version"] == 1,
                "native envelope changed")
        require(("result" in reply) != ("error" in reply), "native response outcome ambiguous")
        error_value = reply.get("error")
        code = error_value.get("code") if type(error_value) is dict else None
        REFUSAL_CODE = code if type(code) is str and code in SAFE_REFUSAL_CODES else "unclassified"
        if validation_error is not None:
            # Only these production-disabled schema methods are rejected while
            # nativeExchange is decoding, before a Validated request exists.
            # The native host's bounded validation refusal therefore has id:null.
            require(validation_error == "NeedsProviderAdapterProof"
                    and request["method"] in ("browser.importGrant", "browser.observation")
                    and "id" in reply and reply["id"] is None and code == validation_error and "result" not in reply,
                    "native pre-admission refusal changed")
        else:
            require(reply.get("id") == request["id"], "native correlation changed")
        return reply

    def close(self):
        if not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            self.process.wait(timeout=5)
            require(self.process.returncode == 0, "native host did not close cleanly")
            require(self.process.stdout.read(1) == b"", "native host appended unframed output")
        finally:
            stop(self.process)
            self.process.stdout.close()


def result(reply: dict) -> dict:
    require("result" in reply and type(reply["result"]) is dict, "native request rejected")
    return reply["result"]


def rejected(reply: dict, code: str) -> None:
    require("error" in reply and reply["error"].get("code") == code,
            "native request did not reach expected refusal boundary")


def extension_identity(archive: Path, channel: str) -> str:
    """Bind an exact Chromium identity to an actual keyed channel archive."""
    instance = "dev" if channel == "development" else "default"
    host = native_host_setup.host_name(channel)
    with zipfile.ZipFile(archive) as package:
        require(len(package.infolist()) <= 64, "extension archive entry bound exceeded")
        for name in ("manifest.json", "shared/channel.mjs"):
            entries = [entry for entry in package.infolist() if entry.filename == name]
            require(len(entries) == 1 and not entries[0].is_dir() and entries[0].file_size <= 262144,
                    "extension identity input is missing, duplicate or unbounded")
        manifest = json.loads(package.read("manifest.json"))
        key = base64.b64decode(manifest["key"], validate=True)
        require(len(key) >= 32 and manifest.get("manifest_version") == 3,
                "extension archive requires a pinned public identity")
        expected = (f'export const CHANNEL = {json.dumps(channel)};\n'
                    f'export const INSTANCE = {json.dumps(instance)};\n'
                    f'export const NATIVE_HOST = {json.dumps(host)};\n').encode("ascii")
        require(package.read("shared/channel.mjs") == expected, "extension archive channel mismatch")
    return "".join(chr(97 + int(value, 16)) for value in hashlib.sha256(key).hexdigest()[:32])


def registration_pair(destination: Path, binary: Path, identity: str, channel: str) -> dict:
    """Observe exact manifest/receipt bytes and private OS file identities."""
    receipt = Path(str(destination) + ".omux-owner.json")
    entries = {}
    for path in (destination, receipt):
        information = path.lstat()
        require(stat.S_ISREG(information.st_mode) and information.st_uid == os.getuid()
                and stat.S_IMODE(information.st_mode) == 0o600
                and information.st_size <= native_host_setup.MAX_FILE_BYTES,
                "paired registration lost private file custody")
        entries[path] = (path.read_bytes(), native_host_setup._identity(information))
    expected = native_host_setup.manifest("chromium", identity, binary, channel)
    require(json.loads(entries[destination][0]) == expected
            and entries[destination][0] == native_host_setup._bytes(expected),
            "paired registration does not match installed artifact identity/path")
    owner = {"schema": 1, "managed_by": native_host_setup.host_name(channel),
             "manifest": entries[destination][1], "sha256": hashlib.sha256(entries[destination][0]).hexdigest()}
    require(entries[receipt][0] == native_host_setup._bytes(owner),
            "paired registration ownership receipt mismatch")
    return entries


def inside(default_bundle: Path, development_bundle: Path, release_evaluation_extension: Path,
           development_extension: Path, keyring: Path, root: Path) -> None:
    global PHASE
    require(os.environ.get("OMUX_ISOLATED_VAULT_PROOF") == "private-bus-private-xdg",
            "browser fixture requires private vault namespace")
    PHASE = "package-install"
    installations = {}
    for selection, channel, bundle in (("default", "release", default_bundle),
                                       ("dev", "development", development_bundle)):
        payload = pack.read_bundle(bundle)
        manifest, _ = pack.verify_bundle(payload)
        require(manifest["distribution"] == "portable-linux" and manifest.get("channel") == channel,
                "browser fixture requires matching known-channel Linux bundle")
        prefix, records = root / (selection + " prefix"), root / (selection + " records")
        record = install.install_bundle(payload, prefix, records)
        require(record["serviceActivated"] is False, "fixture installer unexpectedly activated service")
        installations[selection] = (prefix, records, record)
    PHASE = "paired-RELEASE_EVALUATION-registration"
    require(release_evaluation_extension.name == "chromium_release_evaluation_package.zip",
            "paired registration requires the explicitly local-only RELEASE_EVALUATION archive")
    identities = {"default": extension_identity(release_evaluation_extension, "release"),
                  "dev": extension_identity(development_extension, "development")}
    require(identities["default"] != identities["dev"], "paired extension identities overlap")
    profile = root / "paired-chromium-profile"
    profile.mkdir(mode=0o700)
    host_directory = profile / "NativeMessagingHosts"
    host_directory.mkdir(mode=0o700)
    registrations, registered_pairs = {}, {}
    for selection, channel in (("default", "release"), ("dev", "development")):
        binary = installations[selection][0] / "bin/omux-native-host"
        ownership = [entry for entry in installations[selection][2]["files"] if entry["path"] == str(binary)]
        require(len(ownership) == 1 and ownership[0]["mode"] == 0o755
                and ownership[0]["sha256"] == hashlib.sha256(binary.read_bytes()).hexdigest(),
                "registered host path is not the verified installed bundle artifact")
        destination = host_directory / (native_host_setup.host_name(channel) + ".json")
        require(native_host_setup.install("chromium", identities[selection], binary, destination, channel) == "installed",
                "paired installed-artifact registration failed")
        registered_pairs[selection] = registration_pair(destination, binary, identities[selection], channel)
        require(native_host_setup.install("chromium", identities[selection], binary, destination, channel) == "unchanged",
                "paired registration changed on an identical install")
        require(registration_pair(destination, binary, identities[selection], channel) == registered_pairs[selection],
                "paired registration identity changed on idempotent install")
        registrations[selection] = destination
    require(len(list(host_directory.iterdir())) == 4, "paired manifest/receipt coexistence changed")
    prefix = installations["default"][0]
    environment = os.environ.copy()
    environment["PATH"] = "/nonexistent"
    PHASE = "keyring-startup"
    keyring_log = tempfile.TemporaryFile(dir=root)
    keyring_process = subprocess.Popen([str(keyring), "--foreground", "--unlock", "--components=secrets"],
                                       stdin=subprocess.PIPE, stdout=keyring_log, stderr=keyring_log)
    keyring_process.stdin.write(b"\n")
    keyring_process.stdin.close()
    diagnostics = tempfile.TemporaryFile(dir=root)
    daemons, hosts = [], []

    def matching_prefix(env: dict) -> Path:
        return installations[env["OMUX_INSTANCE"]][0]

    def cli(state: Path, env: dict, method: str) -> dict:
        completed = subprocess.run([str(matching_prefix(env) / "bin/omux"), "--state-dir", str(state), "rpc", method, "-"],
                                   input=b"{}", capture_output=True, env=env, timeout=12)
        require(completed.returncode == 0 and completed.stderr == b"", "installed control query failed")
        return result(json.loads(completed.stdout))

    def start(state: Path, env: dict):
        state.mkdir(mode=0o700, exist_ok=True)
        daemon = subprocess.Popen([str(matching_prefix(env) / "bin/omuxd"), "--state-dir", str(state)],
                                  stdin=subprocess.DEVNULL, stdout=diagnostics, stderr=diagnostics, env=env)
        daemons.append(daemon)
        socket_path = Path(env["XDG_RUNTIME_DIR"]) / (
            "omux-" + hashlib.sha256(str(state).encode()).hexdigest()[:32]) / "control.sock"
        require(len(os.fsencode(socket_path)) <= 107, "fixture socket path exceeds Linux bound")
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            require(daemon.poll() is None, "installed browser daemon exited during startup")
            if socket_path.is_socket():
                try:
                    health = cli(state, env, "system.health")
                    require(health["custody_available"] and health["protocol_version"] == 2,
                            "installed daemon custody unavailable")
                    information = socket_path.lstat()
                    require(information.st_uid == os.getuid() and stat.S_IMODE(information.st_mode) == 0o600,
                            "installed control socket lacks private ownership")
                    return daemon
                except (ValueError, OSError, subprocess.TimeoutExpired):
                    pass
            time.sleep(0.05)
        raise ValueError("browser daemon startup deadline exceeded")

    def connect_host(state: Path, env: dict) -> Host:
        host = Host(matching_prefix(env), state, env, diagnostics)
        hosts.append(host)
        return host

    def request(host: Host, method: str, identifier: str, *, validation_error: str | None = None, **extra) -> dict:
        params = {"sourceId": "synthetic-context-1", "adapter": "github", "origin": "https://github.com",
                  "provenance": provenance(channel=host.channel)}
        params.update(extra)
        return host.call(envelope(method, identifier, params), validation_error=validation_error)

    try:
        time.sleep(0.5)
        PHASE = "daemon-startup"
        release_state, dev_state = root / "release-state", root / "dev-state"
        release_env = dict(environment, OMUX_INSTANCE="default")
        dev_env = dict(environment, OMUX_INSTANCE="dev")
        release_daemon = start(release_state, release_env)
        start(dev_state, dev_env)
        release_host = connect_host(release_state, release_env)
        dev_host = connect_host(dev_state, dev_env)
        PHASE = "native-health"
        # Invoke the real packaged host path selected by each emitted manifest,
        # with its actual extension identity. This is installed conformance;
        # no browser discovery, popup consent or fleet activation is asserted.
        for selection, channel, state, env in (("default", "release", release_state, release_env),
                                                ("dev", "development", dev_state, dev_env)):
            registration = json.loads(registrations[selection].read_bytes())
            actual = Host(Path(registration["path"]).parent.parent, state, env, diagnostics, identities[selection])
            hosts.append(actual)
            health = result(actual.call(envelope("browser.health", "registered-health-" + selection,
                                                  {"provenance": provenance(identities[selection], channel)})))
            require(health["channel"] == channel and health["status"] == "ready"
                    and health["custody_available"] is True and health["provider_access"] is False
                    and health["capabilities"]["production_export"] is False,
                    "registered installed host did not retain its channel/custody boundary")
            actual.close()
            hosts.remove(actual)
        for host, channel in ((release_host, "release"), (dev_host, "development")):
            health = result(host.call(envelope("browser.health", "health-" + channel,
                                              {"provenance": provenance(channel=channel)})))
            require(health == {"status": "ready", "custody_available": True, "provider_access": False,
                               "protocolVersion": 1, "channel": channel,
                               "capabilities": {"source_connection": True, "production_export": False}},
                    "native protocol/channel/capability shape changed")
            require(type(health["protocolVersion"]) is int
                    and all(type(value) is bool for value in (
                        health["custody_available"], health["provider_access"],
                        health["capabilities"]["source_connection"], health["capabilities"]["production_export"])),
                    "native protocol/capability scalar types changed")
        PHASE = "malformed-frame"
        for wire in (b"\x00" * 4, (LIMIT + 1).to_bytes(4, "little"), b"\x03\x00", b"\x08\x00\x00\x00{}"):
            completed = subprocess.run([str(prefix / "bin/omux-native-host"),
                                        "chrome-extension://" + EXTENSION + "/", "--state-dir", str(release_state)],
                                       input=wire, stdout=subprocess.PIPE, stderr=diagnostics,
                                       env=release_env, timeout=12)
            require(completed.returncode != 0 and completed.stdout == b"",
                    "malformed native frame was not boundedly rejected")
        PHASE = "caller-provenance"
        rejected(release_host.call(envelope("browser.health", "wrong-caller",
                                            {"provenance": provenance(OTHER_EXTENSION)})),
                 "NativeHostProvenanceMismatch")
        PHASE = "context-lifecycle"
        require(result(request(release_host, "browser.connect", "connect"))["accepted"] is True,
                "synthetic source connection failed")
        initial = cli(release_state, release_env, "state.snapshot")
        require(initial["accounts"] == [] and len(initial["sources"]) == 1
                and initial["sources"][0]["status"] == "connected", "source metadata enrollment changed")
        result(request(release_host, "browser.reconcile", "reconcile"))
        # A different caller can speak to the local host, but cannot mutate an
        # already bound context. This is metadata integrity, not profile identity.
        other = Host(prefix, release_state, release_env, diagnostics, OTHER_EXTENSION)
        hosts.append(other)
        rejected(request(other, "browser.disconnect", "wrong-context",
                         provenance=provenance(OTHER_EXTENSION)), "BrowserContextMismatch")
        # Provider rebinding is refused before any mutation or provider access.
        rejected(request(release_host, "browser.disconnect", "wrong-provider", adapter="codex",
                         origin="https://chatgpt.com"), "BrowserContextMismatch")
        result(request(release_host, "browser.disconnect", "disconnect"))
        disconnected = cli(release_state, release_env, "state.snapshot")
        require(disconnected["sources"][0]["status"] == "disconnected"
                and disconnected["accounts"] == [], "disconnect changed wrong lifecycle state")
        result(request(release_host, "browser.connect", "reconnect"))
        require(cli(release_state, release_env, "state.snapshot")["sources"][0]["status"] == "connected",
                "source reconnect did not restore connection")
        # Separately authorized metadata contexts are not enrolled accounts.
        # Disconnecting one must leave the other context intact across a
        # restart of this same private installed daemon and custody database.
        second_context = "synthetic-context-2"
        require(result(request(release_host, "browser.connect", "connect-second",
                               sourceId=second_context))["accepted"] is True,
                "second synthetic source connection failed")
        two_contexts = cli(release_state, release_env, "state.snapshot")
        sources_before = {source["id"]: source for source in two_contexts["sources"]}
        require(len(two_contexts["sources"]) == len(sources_before) == 2
                and set(sources_before) == {"synthetic-context-1", second_context}
                and all(source["status"] == "connected" for source in sources_before.values())
                and two_contexts["accounts"] == two_contexts["grants"] == [],
                "separate context authorization changed metadata-only scope")
        result(request(release_host, "browser.disconnect", "disconnect-first-of-two"))
        separated = cli(release_state, release_env, "state.snapshot")
        sources_after = {source["id"]: source for source in separated["sources"]}
        require(len(separated["sources"]) == len(sources_after) == 2
                and set(sources_after) == set(sources_before)
                and sources_after["synthetic-context-1"]["status"] == "disconnected"
                and sources_after[second_context] == sources_before[second_context]
                and separated["accounts"] == separated["grants"] == [],
                "selected disconnect changed independent context or enrolled authority")
        for host in (release_host, other):
            host.close()
            hosts.remove(host)
        stop(release_daemon, require_success=True)
        daemons.remove(release_daemon)
        release_daemon = start(release_state, release_env)
        restored = cli(release_state, release_env, "state.snapshot")
        require(restored["sources"] == separated["sources"]
                and restored["accounts"] == restored["grants"] == [],
                "isolated daemon restart lost selected disconnect or independent context")
        release_host = connect_host(release_state, release_env)
        result(request(release_host, "browser.reconcile", "reconcile-retained-after-restart",
                       sourceId=second_context))
        result(request(release_host, "browser.connect", "reconnect-first-after-restart"))
        reconnected = cli(release_state, release_env, "state.snapshot")
        reconnected_sources = {source["id"]: source for source in reconnected["sources"]}
        require(len(reconnected["sources"]) == len(reconnected_sources) == 2
                and set(reconnected_sources) == set(sources_before)
                and all(source["status"] == "connected" for source in reconnected_sources.values())
                and reconnected["accounts"] == reconnected["grants"] == [],
                "post-restart context reconciliation or reconnection changed metadata-only scope")
        PHASE = "provider-disabled"
        before_disabled = cli(release_state, release_env, "state.snapshot")
        rejected(request(release_host, "browser.importGrant", "blocked-import", capsule={},
                         validation_error="NeedsProviderAdapterProof"),
                 "NeedsProviderAdapterProof")
        rejected(request(release_host, "browser.observation", "blocked-observation", observation={},
                         validation_error="NeedsProviderAdapterProof"),
                 "NeedsProviderAdapterProof")
        after_disabled = cli(release_state, release_env, "state.snapshot")
        require(after_disabled["revision"] == before_disabled["revision"]
                and after_disabled["accounts"] == before_disabled["accounts"] == []
                and after_disabled["grants"] == before_disabled["grants"] == []
                and after_disabled["observations"] == before_disabled["observations"] == []
                and after_disabled["sources"] == before_disabled["sources"],
                "production-disabled requests changed runtime authority")
        PHASE = "cross-channel"
        # Channel-bound launchers reject a conflicting selection before opening
        # a daemon socket or creating custody. These are intentional refusals.
        for wrong_prefix, wrong_env, target in ((prefix, dev_env, release_state),
                                                (installations["dev"][0], release_env, dev_state)):
            completed = subprocess.run([str(wrong_prefix / "bin/omux-native-host"),
                                        "chrome-extension://" + EXTENSION + "/", "--state-dir", str(target)],
                                       input=encoded(envelope("browser.health", "wrong-instance",
                                                              {"provenance": provenance()})),
                                       stdout=subprocess.PIPE, stderr=diagnostics, env=wrong_env, timeout=12)
            require(completed.returncode != 0 and completed.stdout == b"",
                    "channel-bound launcher admitted conflicting instance")
        require(cli(dev_state, dev_env, "state.snapshot")["sources"] == [],
                "release context leaked into development state")
        rejected(request(dev_host, "browser.disconnect", "cross-context"), "NotFound")
        crossed = connect_host(release_state, dev_env)
        before_crossed = cli(release_state, release_env, "state.snapshot")
        # An explicit state override can reach the other instance's socket;
        # request intent must be refused by the resident daemon before mutation.
        rejected(crossed.call(envelope("browser.health", "cross-health",
                                       {"provenance": provenance(channel="development")})),
                 "BrowserChannelMismatch")
        rejected(request(crossed, "browser.connect", "cross-connect",
                         sourceId="synthetic-cross-channel-context"), "BrowserChannelMismatch")
        after_crossed = cli(release_state, release_env, "state.snapshot")
        for field in ("revision", "sources", "accounts", "grants", "observations"):
            require(after_crossed[field] == before_crossed[field],
                    "cross-channel requests changed resident authority")
        PHASE = "durable-source-metadata"
        for host in hosts:
            host.close()
        hosts.clear()
        for daemon in daemons:
            stop(daemon, require_success=True)
        daemons.clear()
        for state in (release_state, dev_state):
            with closing(sqlite3.connect(state / "state.sqlite")) as metadata:
                custody.check_sealed_snapshot(metadata, state / "state.sqlite.authority")
                require(metadata.execute("SELECT count(*) FROM grants").fetchone()[0] == 0,
                        "synthetic browser fixture unexpectedly retained grants")
        PHASE = "registration-removal"
        for target, wrong_selection, wrong_channel in (("default", "dev", "development"),
                                                        ("dev", "default", "release"),
                                                        ("default", "dev", "release"),
                                                        ("dev", "default", "development")):
            try:
                native_host_setup.remove("chromium", identities[wrong_selection],
                                         installations[wrong_selection][0] / "bin/omux-native-host",
                                         registrations[target], wrong_channel)
            except native_host_setup.SetupError:
                pass
            else:
                raise ValueError("wrong-channel native-host removal was admitted")
            for selection, channel in (("default", "release"), ("dev", "development")):
                require(registration_pair(registrations[selection], installations[selection][0] / "bin/omux-native-host",
                                          identities[selection], channel) == registered_pairs[selection],
                        "wrong-channel removal changed another owned registration")
        require(native_host_setup.remove("chromium", identities["dev"], installations["dev"][0] / "bin/omux-native-host",
                                         registrations["dev"], "development") == "removed",
                "owned development registration removal failed")
        require(not registrations["dev"].exists()
                and not Path(str(registrations["dev"]) + ".omux-owner.json").exists(),
                "development removal retained registration authority")
        require(registration_pair(registrations["default"], installations["default"][0] / "bin/omux-native-host",
                                  identities["default"], "release") == registered_pairs["default"],
                "development removal changed release manifest/receipt authority")
        require(native_host_setup.remove("chromium", identities["dev"], installations["dev"][0] / "bin/omux-native-host",
                                         registrations["dev"], "development") == "absent",
                "development registration removal was not idempotent")
        require(native_host_setup.remove("chromium", identities["default"], installations["default"][0] / "bin/omux-native-host",
                                         registrations["default"], "release") == "removed",
                "owned release registration removal failed")
        require(list(host_directory.iterdir()) == [], "owned registration cleanup left a manifest or receipt")
        PHASE = "owned-cleanup"
        for owned_prefix, records, record in installations.values():
            removed = install.uninstall(owned_prefix, records)
            require(removed["preserved"] == [] and len(removed["removed"]) == len(record["files"]),
                    "owned installed browser files were not completely removed")
        print(MARKER.decode("ascii"), end="")
    finally:
        for host in hosts:
            stop(host.process)
            host.process.stdin.close()
            host.process.stdout.close()
        for daemon in daemons:
            stop(daemon)
        stop(keyring_process)
        diagnostics.close()
        keyring_log.close()


def main() -> int:
    if len(sys.argv) == 8 and sys.argv[1] == "--inside":
        inside(*(Path(value).resolve() for value in sys.argv[2:]))
        return 0
    require(len(sys.argv) == 8, "declared runtime/RELEASE_EVALUATION/development archives and private vault tools required")
    default_bundle, development_bundle, release_evaluation_extension, development_extension, session, bus, keyring = (
        Path(value).resolve(strict=True) for value in sys.argv[1:])
    with tempfile.TemporaryDirectory(prefix="omux-b-", dir="/tmp") as temporary:
        root = Path(temporary)
        environment = os.environ.copy()
        for name in ("DBUS_SESSION_BUS_ADDRESS", "DBUS_STARTER_ADDRESS", "DBUS_STARTER_BUS_TYPE",
                     "GNOME_KEYRING_CONTROL", "SSH_AUTH_SOCK", "LD_PRELOAD", "LD_AUDIT", "LD_DEBUG",
                     "OMUX_INSTANCE"):
            environment.pop(name, None)
        for name, child in (("XDG_RUNTIME_DIR", "r"), ("XDG_DATA_HOME", "d"), ("XDG_CONFIG_HOME", "c"),
                            ("XDG_CACHE_HOME", "k"), ("XDG_STATE_HOME", "s")):
            directory = root / child
            directory.mkdir(mode=0o700)
            environment[name] = str(directory)
        environment["OMUX_ISOLATED_VAULT_PROOF"] = "private-bus-private-xdg"
        configuration = root / "bus.conf"
        configuration.write_text('<busconfig><type>session</type><listen>unix:abstract=omux-browser-'
                                 + root.name + '</listen><auth>EXTERNAL</auth><policy context="default">'
                                 '<allow send_destination="*"/><allow receive_sender="*"/><allow own="*"/>'
                                 '</policy></busconfig>')
        bootstrap = ("import os,runpy,sys;p=sys.argv.pop(1);sys.path.insert(0,os.path.dirname(p));"
                     "sys.path.insert(1,os.path.join(os.path.dirname(os.path.dirname(p)),'extensions'));"
                     "sys.argv[0]=p;runpy.run_path(p,run_name='__main__')")
        with tempfile.TemporaryFile(dir=root) as output, tempfile.TemporaryFile(dir=root) as diagnostics:
            process = subprocess.Popen([str(session), "--dbus-daemon=" + str(bus),
                                        "--config-file=" + str(configuration), "--", sys.executable,
                                        "-I", "-B", "-c", bootstrap, str(FIXTURE_SCRIPT),
                                        "--inside", str(default_bundle), str(development_bundle), str(release_evaluation_extension),
                                        str(development_extension), str(keyring), str(root)],
                                       env=environment, start_new_session=True, stdout=output,
                                       stderr=diagnostics, umask=0o077)
            try:
                deadline = time.monotonic() + 90
                # Keep the child leader unreaped until group cleanup; poll(),
                # communicate() and wait() could free its numeric PID/PGID.
                while True:
                    status = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    if status is not None:
                        require(status.si_pid == process.pid, "private browser transport leader identity changed")
                        code = status.si_status if status.si_code == os.CLD_EXITED else -status.si_status
                        break
                    require(time.monotonic() < deadline, "private browser transport session deadline exceeded")
                    time.sleep(0.05)
                output.seek(0)
                if code == 0:
                    require(output.read(len(MARKER) + 1) == MARKER, "browser transport marker missing")
                else:
                    diagnostics.seek(0)
                    recorded = diagnostics.read(65536)
                    for phase in PHASES:
                        marker = "installed synthetic browser transport failed at " + phase
                        if marker.encode() + b"\n" in recorded:
                            print(marker, file=sys.stderr)
                            break
                    for code in SAFE_REFUSAL_CODES:
                        marker = "installed browser refusal classification: " + code
                        if marker.encode() + b"\n" in recorded:
                            print(marker, file=sys.stderr)
                            break
            finally:
                # This process group contains only our new private fixture bus,
                # vault, daemons and hosts. It never includes existing sessions.
                # A live or WNOWAIT zombie leader pins its PID until we reap;
                # validate that anchor and the current group before signaling.
                anchored = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                require(anchored is None or anchored.si_pid == process.pid,
                        "private browser transport cleanup leader identity changed")
                require(os.getpgid(process.pid) == process.pid,
                        "private browser transport cleanup group ownership changed")
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    # An unreaped zombie still pins the ID when no group member
                    # remains signalable. Reap only after this cleanup attempt.
                    pass
                process.wait(timeout=5)
            if code == 0:
                print(MARKER.decode("ascii"), end="")
            return code


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("installed synthetic browser transport failed at " + PHASE, file=sys.stderr)
        print("installed browser refusal classification: " + REFUSAL_CODE, file=sys.stderr)
        sys.exit(1)
