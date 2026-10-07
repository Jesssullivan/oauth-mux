"""Operator-local Yoga Wayland proof driver; manual declared Bazel lane only.

No SSH or bootstrap, no browser user gestures, no provider IO. An independently
qualified coordinator must supply display/socket and aggregate custody first.
The emitted observations require the coordinator's final cleanup join.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

import yoga_toolbar_contract as contract
import yoga_wrapper_authority as wrapper_authority
import yoga_wrapper_custody as wrapper_custody


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise contract.Refusal("visible_session_invalid")


def arguments():
    parser = Parser(description=__doc__)
    for name in contract.INPUTS:
        parser.add_argument("--" + name.replace("_", "-"))
    parser.add_argument("--visible-session")
    parser.add_argument("--visible-session-sha256")
    parser.add_argument("--attestation-dir")
    parser.add_argument("--inside")
    parser.add_argument('--tool-manifest')
    args = parser.parse_args()
    contract.require(args.visible_session is not None and args.visible_session_sha256 is not None,
                     "visible_session_required")
    contract.require(all(getattr(args, name) is not None for name in contract.INPUTS)
                     and args.attestation_dir is not None and args.tool_manifest is not None, "visible_session_invalid")
    return args


def file_digest(path, *, deadline_ns=None, maximum=512 * 1024 * 1024):
    """Hash a direct regular object without blocking on a substituted FIFO.

    Declared runfiles aliases must be resolved by admission before this boundary.
    Both the descriptor and final path must retain the same complete witness.
    """
    now = time.monotonic_ns()
    if deadline_ns is None:
        deadline_ns = now + 12 * 10**9
    contract.require(type(deadline_ns) is int and now < deadline_ns, "deadline_exceeded")
    until = min(deadline_ns, now + 12 * 10**9)
    contract.require(type(maximum) is int and 0 <= maximum <= 512 * 1024 * 1024, "input_digest_mismatch")
    def witness(information):
        return (information.st_dev, information.st_ino, information.st_mode, information.st_uid,
                information.st_gid, information.st_nlink, information.st_size,
                information.st_mtime_ns, information.st_ctime_ns)
    digest = hashlib.sha256()
    total = 0
    descriptor = None
    try:
        contract.require(time.monotonic_ns() < until, "deadline_exceeded")
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        before = os.fstat(descriptor)
        contract.require(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum, "input_digest_mismatch")
        while True:
            contract.require(time.monotonic_ns() < until, "deadline_exceeded")
            chunk = os.read(descriptor, min(1024 * 1024, maximum - total + 1))
            if not chunk:
                break
            total += len(chunk)
            contract.require(total <= maximum, "input_digest_mismatch")
            digest.update(chunk)
        contract.require(time.monotonic_ns() < until, "deadline_exceeded")
        after = os.fstat(descriptor)
        named = os.stat(path, follow_symlinks=False)
        contract.require(total == before.st_size and witness(before) == witness(after) == witness(named),
                         "input_digest_mismatch")
        contract.require(time.monotonic_ns() < until, "deadline_exceeded")
    except OSError:
        raise contract.Refusal("input_digest_mismatch") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
    return digest.hexdigest()


def admitted(args):
    payload = contract.private_read(args.visible_session)
    contract.require(type(args.visible_session_sha256) is str and contract.SHA.fullmatch(args.visible_session_sha256)
                     and hashlib.sha256(payload).hexdigest() == args.visible_session_sha256, "visible_session_invalid")
    session = contract.validate_session(contract.parse(payload), time.monotonic_ns())
    contract.verify_live(session)
    attestation_dir = contract.private_directory(args.attestation_dir)
    contract.require(contract.private_read(attestation_dir / "proof-id", 64) == session["proofId"].encode("ascii"),
                     "attestation_invalid")
    # Existing authority and exact masks are reused as runtime qualification,
    # never as evidence of this new lane's human consent.
    import browser_runtime_authority
    import test_installed_chromium as chromium_fixture
    # The authority is declared data, not a candidate executable tool alias.
    authority = Path(args.runtime_authority).resolve(strict=True)
    contract.require(file_digest(authority, deadline_ns=session["deadlineMonotonicNs"]) ==
                     session["inputSha256"]["runtime_authority"], "input_digest_mismatch")
    roots = chromium_fixture.qualified_runtime(authority)
    browser_runtime_authority.validate_runtime_roots(roots, chromium_fixture.ROOT_METADATA)
    # Resolve candidate tool aliases only after exact prior mapping/NAR/mask
    # qualification, preserving the installed-browser source contract ordering.
    inputs = {}
    for name in contract.INPUTS:
        path = Path(getattr(args, name)).resolve(strict=True)
        contract.require(file_digest(path, deadline_ns=session["deadlineMonotonicNs"]) == session["inputSha256"][name], "input_digest_mismatch")
        inputs[name] = path
    contract.require(all(any(str(inputs[name]).startswith(root + "/") for root in roots)
                         for name in ("chromium", "node")), "runtime_unqualified")
    contract.require(str(Path(sys.executable).resolve(strict=True)) == session['vaultWrapperAuthority']['controllerTools']['python'],
                     "runtime_unqualified")
    for relative, module in (('delivery/yoga_wrapper_authority.py', wrapper_authority),
                             ('delivery/yoga_wrapper_custody.py', wrapper_custody)):
        contract.require(file_digest(Path(module.__file__).resolve(strict=True), maximum=1024 * 1024,
            deadline_ns=session['deadlineMonotonicNs']) == session['wrapperSourceSha256'][relative], 'input_digest_mismatch')
    native_manifest = str(Path(args.tool_manifest).resolve(strict=True))
    captured = wrapper_custody.AuthorityCapture(session['vaultWrapperAuthority'],
        {name: str(inputs[name]) for name in ('dbus_session', 'dbus_daemon', 'keyring')},
        {name: session['inputSha256'][name] for name in ('dbus_session', 'dbus_daemon', 'keyring')},
        session['deadlineMonotonicNs'], validator=wrapper_authority, native_manifest_path=native_manifest)
    return session, inputs, attestation_dir, captured


def write_private(path, payload, mode=0o600):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        contract.require(os.write(descriptor, payload) == len(payload), "unsafe_private_input")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def json_bytes(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def extract_extension(archive_path, destination):
    destination.mkdir(mode=0o700)
    with zipfile.ZipFile(archive_path) as archive:
        entries = archive.infolist()
        contract.require(1 <= len(entries) <= 64, "input_digest_mismatch")
        names = set()
        for entry in entries:
            path = PurePosixPath(entry.filename)
            contract.require(not path.is_absolute() and ".." not in path.parts and 1 <= len(path.parts) <= 2
                             and str(path) == entry.filename and entry.filename not in names and not entry.is_dir()
                             and entry.file_size <= 262144
                             and (entry.external_attr >> 16) & 0o170000 not in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK),
                             "input_digest_mismatch")
            names.add(entry.filename)
            target = destination / entry.filename
            target.parent.mkdir(mode=0o700, exist_ok=True)
            write_private(target, archive.read(entry))
    manifest = contract.parse((destination / "manifest.json").read_bytes())
    contract.require(manifest.get("manifest_version") == 3
                     and manifest.get("permissions") == ["nativeMessaging", "storage", "activeTab"]
                     and manifest.get("optional_permissions") == ["cookies"]
                     and manifest.get("optional_host_permissions") ==
                     ["https://chatgpt.com/*", "https://claude.ai/*", "https://github.com/*"]
                     and manifest.get("action", {}).get("default_popup") == "shared/popup.html", "input_digest_mismatch")
    contract.require((destination / "shared/channel.mjs").read_bytes() ==
                     b'export const CHANNEL = "development";\nexport const INSTANCE = "dev";\n'
                     b'export const NATIVE_HOST = "ai.xoxd.omux.dev";\n', "input_digest_mismatch")
    key = base64.b64decode(manifest["key"], validate=True)
    identity = "".join(chr(97 + int(char, 16)) for char in hashlib.sha256(key).hexdigest()[:32])
    return identity, manifest["version"]


def progress(case, phase):
    print(json.dumps({"scope": "yoga-toolbar-progress", "case": case, "phase": phase}), flush=True)


def wait_attestation(directory, session, case):
    progress(case, "await-attestation")
    until = min(session["deadlineMonotonicNs"] - 120 * 10**9, time.monotonic_ns() + 60 * 10**9)
    while time.monotonic_ns() < until:
        path = directory / (case + ".json")
        try:
            value = contract.parse(contract.private_read(path, 4096))
        except FileNotFoundError:
            time.sleep(0.1)
            continue
        contract.validate_attestation(value, session["proofId"], case)
        return hashlib.sha256(json_bytes(value)).hexdigest()
    raise contract.Refusal("deadline_exceeded")


def private_group(command, environment, deadline_ns, *, input_bytes=None, allowed_progress=False, output_limit=16384):
    """Never reap the private leader before signalling its anchored group."""
    now = time.monotonic_ns()
    contract.require(type(deadline_ns) is int and 0 < deadline_ns - now <= 1200 * 10**9, "deadline_exceeded")
    contract.require(type(output_limit) is int and 0 <= output_limit <= 65536, "private_session_failed")
    collected = bytearray()
    partial = bytearray()
    # Failure to allocate the selector must happen before a child exists.
    selector = selectors.DefaultSelector()
    process = None
    try:
        contract.require(time.monotonic_ns() < deadline_ns, "deadline_exceeded")
        process = subprocess.Popen(command, env=environment, stdin=subprocess.PIPE if input_bytes is not None else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True, umask=0o077)
        if input_bytes is not None:
            process.stdin.write(input_bytes)
            process.stdin.close()
        os.set_blocking(process.stdout.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            contract.require(time.monotonic_ns() < deadline_ns, "deadline_exceeded")
            for key, _ in selector.select(0.1):
                chunk = os.read(key.fd, 4096)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                collected.extend(chunk)
                contract.require(len(collected) <= output_limit, "private_session_failed")
                if allowed_progress:
                    partial.extend(chunk)
                    while b"\n" in partial:
                        line, _, rest = partial.partition(b"\n")
                        partial = bytearray(rest)
                        value = contract.parse(line)
                        if value.get("scope") == "yoga-toolbar-progress":
                            contract.require(set(value) == {"scope", "case", "phase"} and value["case"] in contract.CASES
                                             and value["phase"] in {"await-toolbar", "await-human-decision", "await-attestation"},
                                             "private_session_failed")
                            progress(value["case"], value["phase"])
        while True:
            observed = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if observed is not None:
                contract.require(observed.si_code == os.CLD_EXITED and observed.si_status == 0, "private_session_failed")
                return bytes(collected)
            contract.require(time.monotonic_ns() < deadline_ns, "deadline_exceeded")
            time.sleep(0.05)
    finally:
        selector.close()
        if process is not None:
            # WNOWAIT identity pins PID/PGID until every group member is signalled.
            os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            contract.require(os.getpgid(process.pid) == process.pid, "cleanup_incomplete")
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
            process.stdout.close()


def inside(args, session, inputs, attestation_dir):
    import install
    import pack
    import test_installed_custody as custody
    contract.require(os.environ.get("OMUX_ISOLATED_VAULT_PROOF") == "private-bus-private-xdg", "private_session_failed")
    root = contract.private_directory(args.inside)
    prefix, records = root / "prefix", root / "records"
    payload = pack.read_bundle(inputs["bundle"])
    manifest, _ = pack.verify_bundle(payload)
    contract.require(manifest["distribution"] == "portable-linux" and manifest.get("channel") == "development",
                     "input_digest_mismatch")
    installed = install.install_bundle(payload, prefix, records)
    contract.require(installed["serviceActivated"] is False, "private_session_failed")
    identity, version = extract_extension(inputs["extension"], root / "extension")
    implementation = inputs["recorder_implementation"].read_bytes()
    wrapper = inputs["recorder"].read_bytes()
    contract.require(len(implementation) <= 262144 and len(wrapper) <= 262144, "input_digest_mismatch")
    write_private(root / "recorder_implementation.py", implementation)
    host = root / "recorder-host"
    interpreter = str(Path(sys.executable).resolve(strict=True))
    contract.require(" " not in interpreter and "\n" not in interpreter, "runtime_unqualified")
    write_private(host, ("#!" + interpreter + " -I\n").encode("ascii") + wrapper, 0o700)
    journal = root / "native-journal.jsonl"
    write_private(journal, b"")
    configuration = root / "recorder.json"
    write_private(configuration, json_bytes({"nativeHost": str(prefix / "bin/omux-native-host"),
        "nativeHostSha256": file_digest(prefix / "bin/omux-native-host", deadline_ns=session["deadlineMonotonicNs"]),
        "journal": str(journal), "extensionId": identity}))
    environment = dict(os.environ, PATH="/nonexistent", OMUX_INSTANCE="dev", OMUX_CHROMIUM_RECORDER_CONFIG=str(configuration))
    state = Path(environment["XDG_STATE_HOME"]) / "omux-dev"
    state.mkdir(mode=0o700)
    keyring = daemon = None
    facts = []

    def snapshot(method="state.snapshot"):
        contract.verify_live(session)
        output = private_group([str(prefix / "bin/omux"), "--state-dir", str(state), "rpc", method, "-"],
                               environment, min(session["deadlineMonotonicNs"], time.monotonic_ns() + 12 * 10**9),
                               input_bytes=b"{}", output_limit=65536)
        value = contract.parse(output)
        contract.require(type(value) is dict and "result" in value and "error" not in value, "private_session_failed")
        return value["result"]

    def empty_snapshot():
        value = snapshot()
        contract.require(all(value[key] == [] for key in ("sources", "accounts", "grants", "observations")),
                         "browser_predicate_failed")
        rows = [contract.parse(line) for line in contract.private_read(journal).splitlines()]
        contract.require(len(rows) <= 64 and all(set(row) == {"id", "method", "sourceId"}
            and row["method"] == "browser.health" and row["sourceId"] is None for row in rows), "browser_predicate_failed")

    try:
        keyring = subprocess.Popen([str(inputs["keyring"]), "--foreground", "--unlock", "--components=secrets"],
                                   stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=environment)
        keyring.stdin.write(b"\n"); keyring.stdin.close()
        daemon = subprocess.Popen([str(prefix / "bin/omuxd"), "--state-dir", str(state)], stdin=subprocess.DEVNULL,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=environment)
        until = min(session["deadlineMonotonicNs"] - 120 * 10**9, time.monotonic_ns() + 12 * 10**9)
        ready = False
        while time.monotonic_ns() < until:
            contract.require(daemon.poll() is None and keyring.poll() is None, "private_session_failed")
            try:
                health = snapshot("system.health")
                ready = health["custody_available"] is True and health["status"] == "ready" and health["live_handoff_proven"] is False
                if ready:
                    break
            except (contract.Refusal, OSError, subprocess.TimeoutExpired):
                pass
            time.sleep(0.1)
        contract.require(ready, "private_session_failed")
        empty_snapshot()
        for case in ("denial", "approval", "reload"):
            contract.verify_live(session)
            profile = root / ("denial-profile" if case == "denial" else "approval-profile")
            if case != "reload":
                profile.mkdir(mode=0o700)
                hosts = profile / "NativeMessagingHosts"
                hosts.mkdir(mode=0o700)
                write_private(hosts / "ai.xoxd.omux.dev.json", json_bytes({"name": "ai.xoxd.omux.dev",
                    "description": "Omux private permission proof", "path": str(host), "type": "stdio",
                    "allowed_origins": ["chrome-extension://" + identity + "/"]}))
            until = min(session["deadlineMonotonicNs"] - 120 * 10**9, time.monotonic_ns() + (180 if case == "reload" else 300) * 10**9)
            config = root / (case + "-observer.json")
            write_private(config, json_bytes({"case": case, "chromium": str(inputs["chromium"]), "extension": str(root / "extension"),
                "profile": str(profile), "extensionId": identity, "ozone": "wayland", "deadlineMonotonicNs": str(until)}))
            output = private_group([str(inputs["node"]), str(inputs["observer"]), str(config)], environment, until, allowed_progress=True)
            receipts = [contract.parse(line) for line in output.splitlines()
                        if contract.parse(line).get("scope") == "yoga-toolbar-observed-case"]
            contract.require(len(receipts) == 1, "browser_predicate_failed")
            receipt = receipts[0]
            contract.require(set(receipt) == {"scope", "case", "browserVersion", "initialGateObserved", "optionalPermissionApproved",
                "emptyBrowserMetadata", "outcome", "driverInteraction", "humanAttestationRequired"}
                and receipt["case"] == case and receipt["browserVersion"] in {"Chrome/147.0.7727.116", "Chromium/147.0.7727.116"}
                and receipt["initialGateObserved"] is True and receipt["optionalPermissionApproved"] is (case != "denial")
                and receipt["emptyBrowserMetadata"] is True and receipt["driverInteraction"] is False
                and receipt["humanAttestationRequired"] is True and receipt["outcome"] ==
                {"denial": "permission_denied", "approval": "open_provider_tab", "reload": "reload_gate_reset"}[case],
                "browser_predicate_failed")
            empty_snapshot()
            receipt["operatorAttestationSha256"] = wait_attestation(attestation_dir, session, case)
            facts.append(receipt)
        custody.stop(daemon, require_success=True); daemon = None
        custody.stop(keyring); keyring = None
        removed = install.uninstall(prefix, records)
        contract.require(removed["preserved"] == [] and len(removed["removed"]) == len(installed["files"]), "cleanup_incomplete")
        print(json.dumps({"scope": "yoga-toolbar-local-observations", "proofId": session["proofId"], "extensionId": identity,
            "extensionVersion": version, "channel": "development", "cases": facts,
            "providerAccess": False, "grantExport": False, "remoteExecution": False, "aggregateCleanupJoinRequired": True}), flush=True)
    finally:
        if daemon is not None:
            custody.stop(daemon)
        if keyring is not None:
            custody.stop(keyring)


def main():
    args = arguments()
    session, inputs, attestation_dir, captured = admitted(args)
    with captured:
        return run_admitted(args, session, inputs, attestation_dir)


def run_admitted(args, session, inputs, attestation_dir):
    if args.inside:
        inside(args, session, inputs, attestation_dir)
        return 0
    for case in contract.CASES:
        contract.require(not os.path.lexists(attestation_dir / (case + ".json")), "attestation_invalid")
    with tempfile.TemporaryDirectory(prefix="omux-yw-", dir="/tmp") as temporary:
        root = Path(temporary)
        environment = {"PATH": "/nonexistent", "HOME": str(root), "OMUX_INSTANCE": "dev",
            "OMUX_ISOLATED_VAULT_PROOF": "private-bus-private-xdg", "OMUX_BROWSER_HOST_CONFIGURATION": "host-configurations-unavailable"}
        # Exact display only. No personal bus, proxy, HOME, agent or node settings.
        environment.update(contract.display_environment(session["display"])[0])
        for name, child in (("XDG_RUNTIME_DIR", "r"), ("XDG_DATA_HOME", "d"), ("XDG_CONFIG_HOME", "c"),
                            ("XDG_CACHE_HOME", "k"), ("XDG_STATE_HOME", "s")):
            directory = root / child; directory.mkdir(mode=0o700); environment[name] = str(directory)
        config = root / "bus.conf"
        write_private(config, ('<busconfig><type>session</type><listen>unix:abstract=omux-yoga-' + root.name
            + '</listen><auth>EXTERNAL</auth><policy context="default"><allow send_destination="*"/>'
            '<allow receive_sender="*"/><allow own="*"/></policy></busconfig>').encode("ascii"))
        bootstrap = "import os,runpy,sys;p=sys.argv.pop(1);sys.path.insert(0,os.path.dirname(p));sys.argv[0]=p;runpy.run_path(p,run_name='__main__')"
        until = session["deadlineMonotonicNs"] - 60 * 10**9
        output = private_group([str(inputs["dbus_session"]), "--dbus-daemon=" + str(inputs["dbus_daemon"]),
            "--config-file=" + str(config), "--", sys.executable, "-I", "-B", "-c", bootstrap,
            str(Path(__file__).absolute()), *sys.argv[1:], "--inside", str(root)], environment, until, allowed_progress=True)
        observations = [contract.parse(line) for line in output.splitlines()
                        if contract.parse(line).get("scope") == "yoga-toolbar-local-observations"]
        contract.require(len(observations) == 1 and observations[0]["proofId"] == session["proofId"], "private_session_failed")
        value = observations[0]
    # Temporary profile/state removal has completed. Aggregate emptiness belongs
    # to the coordinator after this observer itself has exited, never to a flag.
    value["privateProfilesRemoved"] = True
    value["visibleSessionSha256"] = args.visible_session_sha256
    value["inputSha256"] = session["inputSha256"]
    print(json.dumps(value, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    try:
        def interrupted(signum, frame):
            raise KeyboardInterrupt
        for signum in (signal.SIGTERM, signal.SIGHUP):
            signal.signal(signum, interrupted)
        sys.exit(main())
    except (Exception, KeyboardInterrupt) as error:
        reason = error.reason if isinstance(error, contract.Refusal) else "fixture_unavailable"
        print(json.dumps({"scope": "yoga-toolbar-local-refusal", "reason": reason}), file=sys.stderr)
        sys.exit(2)
