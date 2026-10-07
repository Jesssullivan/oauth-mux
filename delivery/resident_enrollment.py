"""Explicit persistent enrollment, using an existing authorized native context.

Future separate declared Bazel lane. No credential contents are read by this
controller. Installed files, service and custody remain after successful use.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time

import install
import pack
# The tools sibling is a declared runfiles source, not an ambient checkout.
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))
import guard_resident_enrollment_profile as resident_guard

MANIFEST = "/omux-resident-inputs/input.json"
PHASE = "manifest"
PHASES = {"manifest", "source-metadata", "installation", "activation", "service-observation",
          "daemon-readiness", "source-connection", "provider-verification", "restart-authority",
          "restart", "retained-verification", "receipt", "session-ownership"}
MAX_OUTPUT = 1024 * 1024
DEADLINE_NS = 0
CLEANUP_RESERVE_NS = 30 * 10**9
ENV_KEYS = frozenset(("HOME", "USER", "LOGNAME", "LANG", "LC_ALL",
                      "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"))
SERVICE_PROPERTIES = ("Id", "MainPID", "ActiveState", "SubState", "FragmentPath", "ControlGroup",
                      "User", "Group", "ExecStart", "MemoryMax", "MemorySwapMax", "TasksMax",
                      "CPUQuotaPerSecUSec")


def original_deadline(environment, now_ns=None):
    raw = environment.get("OMUX_RESIDENT_ORIGINAL_DEADLINE_NS", "")
    require(isinstance(raw, str) and re.fullmatch(r"[0-9]{1,20}", raw))
    deadline = int(raw)
    now = time.monotonic_ns() if now_ns is None else now_ns
    require(now + CLEANUP_RESERVE_NS < deadline <= now + 1200 * 10**9)
    return deadline


def remaining(timeout=20):
    available = (DEADLINE_NS - CLEANUP_RESERVE_NS - time.monotonic_ns()) / 10**9
    require(available > 0)
    return min(timeout, available)


def controller_environment(environment, instance):
    # Service manager launches the daemon with its own real user environment.
    # Controllers inherit only declared noncredential native setup metadata.
    selected = {key: value for key, value in environment.items() if key in ENV_KEYS}
    require(all(isinstance(value, str) and "\x00" not in value for value in selected.values()))
    selected.update(OMUX_INSTANCE=instance, XDG_RUNTIME_DIR="/omux-resident-inputs",
                    DBUS_SESSION_BUS_ADDRESS="unix:path=/omux-resident-inputs/bus")
    return selected


def validate_service_properties(value, unit, uid, gid):
    require(set(value) == set(SERVICE_PROPERTIES) and value["Id"] == unit
            and value["ActiveState"] == "active" and value["SubState"] == "running"
            and value["MainPID"].isdigit() and int(value["MainPID"]) > 1
            and value["User"] in ("", str(uid)) and value["Group"] in ("", str(gid)))
    group = value["ControlGroup"]
    require(isinstance(group, str) and group.startswith("/") and group == os.path.normpath(group)
            and Path(group).name == unit)
    return int(value["MainPID"]), group


def process_identity(pid):
    path = Path("/proc") / str(pid)
    before = path.stat()
    require(before.st_uid == os.getuid())
    raw = (path / "stat").read_bytes()
    require(0 < len(raw) <= 8192 and raw.startswith(str(pid).encode() + b" (")
            and b") " in raw)
    fields = raw.rsplit(b") ", 1)[1].split()
    require(len(fields) >= 20 and fields[0] not in (b"Z", b"X") and fields[19].isdigit())
    after = path.stat()
    require((before.st_dev, before.st_ino, before.st_uid) == (after.st_dev, after.st_ino, after.st_uid))
    return (pid, int(fields[19]), before.st_dev, before.st_ino)


def cgroup_observation(group, pid):
    directory = os.open("/sys/fs/cgroup", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in Path(group).parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = child
        before = os.fstat(directory)
        require(before.st_uid in (0, os.getuid()))
        values = {}
        for name in ("memory.max", "memory.swap.max", "pids.max", "cpu.max", "cgroup.procs"):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            try:
                raw = os.read(fd, 65537)
                require(0 < len(raw) <= 65536)
                values[name] = raw.decode("ascii").strip()
            finally:
                os.close(fd)
        require(str(pid) in values["cgroup.procs"].splitlines())
        membership = (Path("/proc") / str(pid) / "cgroup").read_bytes()
        require(len(membership) <= 65536 and b"0::" + group.encode() + b"\n" in membership)
        after = os.fstat(directory)
        require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino))
        return values, (before.st_dev, before.st_ino)
    finally:
        os.close(directory)


def require(condition):
    if not condition:
        raise ValueError("resident enrollment predicate refused")


def strict_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value)
        value[key] = item
    return value


def absolute(value):
    require(isinstance(value, str) and 0 < len(value) <= 4096 and value.startswith("/")
            and value == os.path.normpath(value) and str(Path(value)) == value
            and all(32 <= ord(char) < 127 for char in value))
    return Path(value)


def validate_manifest(value):
    require(isinstance(value, dict) and set(value) == {"schema_version", "ownership", "action", "instance",
            "prefix", "records", "runtime_state", "service_path", "native_context", "permissions"}
            and type(value["schema_version"]) is int and value["schema_version"] == 1
            and value["ownership"] in ("omux-installation", "home-manager")
            and value["action"] in ("install-and-enroll", "enroll-existing")
            and value["instance"] in ("default", "dev"))
    require(value["action"] != "install-and-enroll" or value["ownership"] == "omux-installation")
    paths = {key: absolute(value[key]) for key in ("prefix", "records", "runtime_state", "service_path")}
    require(len(set(paths.values())) == 4)
    expected_name = "ai.xoxd.omux" + (".dev" if value["instance"] == "dev" else "") + ".service"
    require(paths["service_path"].name == expected_name)
    context = value["native_context"]
    require(isinstance(context, dict) and set(context) == {"application", "provenance", "codex_home"}
            and context["application"] == "codex"
            and context["provenance"] == "authorized-working-native-context")
    absolute(context["codex_home"])
    home = Path(context["codex_home"])
    custody_paths = [paths[key] for key in ("prefix", "records", "runtime_state")]
    for index, path in enumerate(custody_paths):
        require(path != home and path not in home.parents and home not in path.parents)
        for other in custody_paths[index + 1:]:
            require(path not in other.parents and other not in path.parents)
    permissions = value["permissions"]
    require(isinstance(permissions, dict) and set(permissions) == {"connect_source", "activate_service", "restart_daemon"}
            and all(type(item) is bool for item in permissions.values()) and permissions["connect_source"]
            and (value["action"] != "install-and-enroll" or permissions["activate_service"]))
    require(value["ownership"] != "home-manager" or not permissions["activate_service"])
    return value


def identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def private_manifest():
    require(os.environ.get("OMUX_RESIDENT_ENROLLMENT_MANIFEST") == MANIFEST)
    root = parent = fd = None
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC
        root = os.open("/", flags)
        root_before = os.fstat(root)
        parent = os.open("omux-resident-inputs", flags, dir_fd=root)
        before_parent = os.fstat(parent)
        for information in (root_before, before_parent):
            require(information.st_uid in (0, os.getuid()) and not information.st_mode & 0o022)
        require(before_parent.st_uid == os.getuid() and stat.S_IMODE(before_parent.st_mode) == 0o700
                and os.environ.get("OMUX_RESIDENT_NAMESPACE_ID") ==
                    str(before_parent.st_dev) + ":" + str(before_parent.st_ino))
        require(identity(before_parent) == identity(os.stat("omux-resident-inputs", dir_fd=root, follow_symlinks=False)))
        fd = os.open("input.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and stat.S_IMODE(before.st_mode) in (0o400, 0o600) and before.st_nlink == 1
                and 0 < before.st_size <= 65536)
        require(identity(before) == identity(os.stat("input.json", dir_fd=parent, follow_symlinks=False)))
        raw = os.read(fd, 65537)
        require(len(raw) == before.st_size and identity(before) == identity(os.fstat(fd))
                == identity(os.stat("input.json", dir_fd=parent, follow_symlinks=False)))
        require(identity(before_parent) == identity(os.fstat(parent))
                == identity(os.stat("omux-resident-inputs", dir_fd=root, follow_symlinks=False))
                and identity(root_before) == identity(os.fstat(root)))
        return validate_manifest(json.loads(raw, object_pairs_hook=strict_object))
    finally:
        for descriptor in (fd, parent, root):
            if descriptor is not None:
                os.close(descriptor)


def hold_source_metadata(context):
    """No-follow metadata discovery in the authorized working native context."""
    home = absolute(context["codex_home"])
    path = home / "auth.json"
    directory = os.open("/", os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        for part in home.parts[1:]:
            information = os.fstat(directory)
            require(information.st_uid in (0, os.getuid())
                    and (not information.st_mode & 0o022 or
                         information.st_uid == 0 and information.st_mode & stat.S_ISVTX))
            child = os.open(part, os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = child
        information = os.fstat(directory)
        require(information.st_uid == os.getuid() and stat.S_IMODE(information.st_mode) == 0o700)
        source = os.open("auth.json", os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
        try:
            information = os.fstat(source)
            require(stat.S_ISREG(information.st_mode) and information.st_uid == os.getuid()
                    and stat.S_IMODE(information.st_mode) in (0o400, 0o600)
                    and information.st_nlink == 1 and 0 < information.st_size <= 128 * 1024)
            require(identity(information) == identity(os.stat("auth.json", dir_fd=directory, follow_symlinks=False)))
            return directory, source, information, path
        except Exception:
            os.close(source)
            raise
    except Exception:
        os.close(directory)
        raise


def empty_first_install_state(path):
    """Metadata-only qualification; never open an existing database or key."""
    path = absolute(str(path))
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    walked = Path("/")
    try:
        for part in path.parts[1:]:
            info = os.fstat(directory)
            require(info.st_uid in (0, os.getuid()) and
                    (not info.st_mode & 0o022 or info.st_uid == 0 and info.st_mode & stat.S_ISVTX))
            require(identity(info) == identity(os.stat(walked, follow_symlinks=False)))
            try:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
            except FileNotFoundError:
                # A missing suffix contains no retained custody. Its existing
                # ancestor still has to satisfy the held namespace checks.
                return True
            try:
                before = os.fstat(child)
                require(identity(before) == identity(os.stat(part, dir_fd=directory, follow_symlinks=False)))
            except Exception:
                os.close(child)
                raise
            os.close(directory)
            directory = child
            walked /= part
        before = os.fstat(directory)
        require(before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o700)
        require(not os.listdir(directory))
        require(identity(before) == identity(os.fstat(directory))
                == identity(os.stat(path, follow_symlinks=False)))
        return True
    finally:
        os.close(directory)


def session_transition(pinned, observed, *, freeze_secret_service):
    """Transport identity never changes; vault owner freezes at real readiness."""
    require(isinstance(pinned, dict) and isinstance(observed, dict)
            and pinned["broker"] == observed["broker"] and pinned["manager"] == observed["manager"])
    if pinned["secret_service"] is not None:
        require(observed["secret_service"] == pinned["secret_service"])
    if freeze_secret_service:
        require(observed["secret_service"] is not None)
        return observed
    return pinned


def bounded(command, environment, data=None, timeout=20, allowed_returncodes=(0,)):
    timeout = remaining(timeout)
    incoming = memoryview(data or b"")
    require(len(incoming) <= MAX_OUTPUT)
    deadline = time.monotonic() + timeout
    selector = None
    output, diagnostics = bytearray(), bytearray()
    process = subprocess.Popen(command, env=environment, stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, umask=0o077, bufsize=0)
    try:
        selector = selectors.DefaultSelector()
        os.set_blocking(process.stdin.fileno(), False)
        offset = 0
        if incoming:
            selector.register(process.stdin, selectors.EVENT_WRITE, None)
        else:
            process.stdin.close()
        for stream, destination in ((process.stdout, output), (process.stderr, diagnostics)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, destination)
        while selector.get_map():
            remaining()
            left = deadline - time.monotonic()
            require(left > 0)
            for key, _ in selector.select(min(0.1, left)):
                if key.data is None:
                    try:
                        count = os.write(key.fd, incoming[offset:offset + 8192])
                    except (BlockingIOError, InterruptedError):
                        continue
                    require(0 < count <= len(incoming) - offset)
                    offset += count
                    if offset == len(incoming):
                        selector.unregister(key.fileobj)
                        process.stdin.close()
                    continue
                try:
                    chunk = os.read(key.fd, 8192)
                except (BlockingIOError, InterruptedError):
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                require(len(key.data) + len(chunk) <= MAX_OUTPUT)
                key.data.extend(chunk)
        remaining()
        left = deadline - time.monotonic()
        require(left > 0)
        process.wait(timeout=left)
        require(process.returncode in allowed_returncodes and not diagnostics)
        return bytes(output)
    finally:
        try:
            if selector is not None:
                selector.close()
        finally:
            try:
                if process.poll() is None:
                    try:
                        process.terminate()
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        try:
                            process.kill()
                        except ProcessLookupError:
                            pass
                        process.wait(timeout=5)
            finally:
                try:
                    process.stdin.close()
                finally:
                    try:
                        process.stdout.close()
                    finally:
                        process.stderr.close()


def selected_source(snapshot, source_path):
    ids = [description["source_id"] for description in snapshot["source_descriptions"]
           if description["provider"] == "codex" and description["path"] == str(source_path)]
    require(len(ids) <= 1)
    if not ids:
        return None
    sources = [source for source in snapshot["sources"] if source["id"] == ids[0]]
    require(len(sources) == 1 and sources[0]["kind"] == "native_store"
            and sources[0]["status"] == "connected")
    return ids[0]


def enrolled_authority(snapshot, source_id, now):
    accounts = [account for account in snapshot["accounts"] if source_id in account["source_ids"]]
    if not accounts:
        require(not any(job["status"] == "failed" for job in snapshot["jobs"]
                        if job["id"] == "reconcile-" + source_id))
        return None
    require(len(accounts) == 1 and accounts[0]["identity"] == {"provider": "codex"}
            and accounts[0]["lifecycle"] == "active")
    grants = [grant for grant in snapshot["grants"] if grant["source_id"] == source_id]
    require(len(grants) == 1)
    grant = grants[0]
    require(grant["account_id"] == accounts[0]["id"] and grant["credential_kind"] == "oauth_access"
            and grant["ownership"] == "external" and grant["status"] == "ready"
            and grant["audience"] == "https://chatgpt.com" and "request" in grant["purposes"]
            and (grant["provider_expires_at"] is None or grant["provider_expires_at"] > now)
            and type(grant["custody_expires_at"]) is int and grant["custody_expires_at"] > now)
    for value in (source_id, accounts[0]["id"], grant["id"]):
        require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value))
    require(type(grant["generation"]) is int and 0 < grant["generation"] < 2**63)
    return {"source_handle": source_id, "account_handle": accounts[0]["id"],
            "grant_handle": grant["id"], "grant_generation": grant["generation"]}


def execute(bundle, systemctl, session_probe, manifest):
    global PHASE, DEADLINE_NS
    DEADLINE_NS = original_deadline(os.environ)
    manifest = validate_manifest(manifest)
    environment = controller_environment(os.environ, manifest["instance"])
    prefix, records, state, service_path = (absolute(manifest[key]) for key in
                                          ("prefix", "records", "runtime_state", "service_path"))
    unit = service_path.name
    PHASE = "source-metadata"
    directory, source, information, source_path = hold_source_metadata(manifest["native_context"])
    try:
        PHASE = "session-ownership"
        allow_initial_missing_vault = manifest["action"] == "install-and-enroll"
        if allow_initial_missing_vault:
            require(empty_first_install_state(state))
        session_owners = resident_guard.observe_existing_session_services(
            environment, DEADLINE_NS, session_probe, allow_missing_secret_service=allow_initial_missing_vault)
        require(isinstance(session_owners, dict) and session_owners)

        def require_session_owners(*, freeze_secret_service=False):
            nonlocal session_owners
            remaining()
            allow_missing = (allow_initial_missing_vault and session_owners["secret_service"] is None
                             and not freeze_secret_service)
            observed = resident_guard.observe_existing_session_services(
                environment, DEADLINE_NS, session_probe, allow_missing_secret_service=allow_missing)
            session_owners = session_transition(session_owners, observed, freeze_secret_service=freeze_secret_service)

        PHASE = "installation"
        if manifest["action"] == "install-and-enroll":
            absent = bounded([str(systemctl), "--user", "--quiet", "show",
                              "--property=Id,LoadState,ActiveState,MainPID", unit], environment,
                             allowed_returncodes=(0, 4))
            absence = dict(line.split("=", 1) for line in absent.decode("ascii").splitlines())
            require(absence == {"Id": unit, "LoadState": "not-found", "ActiveState": "inactive", "MainPID": "0"})
            require_session_owners()
        payload = pack.read_bundle(bundle)
        artifact, archive_files = pack.verify_bundle(payload)
        expected_channel = "development" if manifest["instance"] == "dev" else "release"
        require(artifact["channel"] == expected_channel and artifact["distribution"] == "portable-linux")
        if manifest["action"] == "install-and-enroll":
            require(manifest["ownership"] == "omux-installation")
            # First install only. Live package replacement is a separate action.
            require(install._record(prefix, records) is None)
            install.install_bundle(payload, prefix, records, service_path, "linux", daemon_state_dir=state)
        else:
            require(prefix.is_dir())
            if manifest["ownership"] == "omux-installation":
                record = install._record(prefix, records)
                require(record is not None and record["userService"] == str(service_path)
                        and record["artifact"]["archiveSha256"] == hashlib.sha256(payload).hexdigest()
                        and all(install._matches(Path(entry["path"]), entry) for entry in record["files"]))
            else:
                # Exact immutable HM artifact selection; collector independently
                # verifies its full witness, payload and active responder.
                fd = os.open(prefix / "release-manifest.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    information_manifest = os.fstat(fd)
                    require(stat.S_ISREG(information_manifest.st_mode) and information_manifest.st_uid == 0
                            and not information_manifest.st_mode & 0o222 and information_manifest.st_size <= 65536)
                    actual = os.read(fd, 65537)
                    require(len(actual) == information_manifest.st_size
                            and identity(information_manifest) == identity(os.fstat(fd))
                            and actual == archive_files["release-manifest.json"])
                finally:
                    os.close(fd)

        def manager(*arguments):
            require_session_owners()
            return bounded([str(systemctl), "--user", "--quiet", *arguments, unit], environment)

        def service():
            remaining()
            output = manager("show", "--property=" + ",".join(SERVICE_PROPERTIES))
            value = dict(line.split("=", 1) for line in output.decode("utf-8").splitlines())
            pid, group = validate_service_properties(value, unit, os.getuid(), os.getgid())
            fragment = absolute(value["FragmentPath"])
            require(fragment == service_path or manifest["ownership"] == "home-manager"
                    and fragment.resolve(strict=True) == service_path.resolve(strict=True))
            actual_fragment = fragment.resolve(strict=True) if manifest["ownership"] == "home-manager" else fragment
            fd = os.open(actual_fragment, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                info = os.fstat(fd)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o022
                        and info.st_uid == (0 if manifest["ownership"] == "home-manager" else os.getuid()))
                if manifest["ownership"] == "home-manager":
                    require(not info.st_mode & 0o222)
                require(identity(info) == identity(os.stat(actual_fragment, follow_symlinks=False)))
            finally:
                os.close(fd)
            require("path=" + str(prefix / "bin/omuxd") + " ;" in value["ExecStart"])
            observed = process_identity(pid)
            values, group_identity = cgroup_observation(group, pid)
            require(resident_guard.check_resident_bounds(value, values) is not False)
            require(process_identity(pid) == observed)
            return {"pid": pid, "process": observed, "cgroup": group_identity}

        def cli(method, params=None):
            require_session_owners()
            encoded = json.dumps(params or {}, separators=(",", ":")).encode()
            raw = bounded([str(prefix / "bin/omux"), "--state-dir", str(state), "rpc", method, "-"], environment, encoded)
            value = json.loads(raw, object_pairs_hook=strict_object)
            require(isinstance(value, dict) and set(value) == {"jsonrpc", "id", "result"}
                    and value["jsonrpc"] == "2.0" and isinstance(value["result"], dict))
            require_session_owners()
            return value["result"]

        def mutate(method, params):
            return cli(method, {**params, "operation_id": os.urandom(32).hex(),
                                "expected_revision": cli("system.health")["revision"]})

        def readiness():
            require(cli("system.health")["custody_available"])
            # Platform startup may normally activate the vault for a fresh
            # installation. Once custody is real, require and freeze its owner.
            require_session_owners(freeze_secret_service=True)
            probe = cli("setup.evidence")["probe"]
            artifact = probe["artifact"]
            expected_owner = "home_manager" if manifest["ownership"] == "home-manager" else "installation_receipt"
            require(probe["failure"] == "none" and artifact["ownership"] == expected_owner
                    and artifact["payload"] == artifact["running_executable"] == artifact["ownership_record"] == "matches"
                    and probe["service"]["responder_binding"] == "matches")

        def await_ready(expected_previous_pid=None):
            deadline = time.monotonic() + remaining(30)
            while time.monotonic() < deadline:
                try:
                    observed = service()
                    require(expected_previous_pid is None or observed["pid"] != expected_previous_pid)
                    readiness()
                    require(service() == observed)
                    return observed
                except (ValueError, OSError, subprocess.TimeoutExpired):
                    remaining()
                    time.sleep(0.1)
            raise ValueError("resident startup refused")

        if manifest["permissions"]["activate_service"]:
            PHASE = "activation"
            # Manager owns only this unit's link; inspect effective limits before
            # any daemon process can escape the resident reservation.
            require_session_owners()
            bounded([str(systemctl), "--user", "--quiet", "enable", str(service_path)], environment)
            # Reload is intentionally a separate bounded command without unit.
            require_session_owners()
            bounded([str(systemctl), "--user", "--quiet", "daemon-reload"], environment)
            loaded = manager("show", "--property=MemoryMax,MemorySwapMax,TasksMax,CPUQuotaPerSecUSec,FragmentPath")
            limits = dict(line.split("=", 1) for line in loaded.decode("ascii").splitlines())
            require(limits == {"MemoryMax": "268435456", "MemorySwapMax": "0", "TasksMax": "32",
                               "CPUQuotaPerSecUSec": "100ms", "FragmentPath": str(service_path)})
            if allow_initial_missing_vault:
                require(empty_first_install_state(state))
            manager("start")
        PHASE = "service-observation"
        PHASE = "daemon-readiness"
        initial_service = await_ready()
        PHASE = "source-connection"
        source_id = selected_source(cli("state.snapshot"), source_path)
        if source_id is None:
            connected = mutate("source.connect", {"kind": "native_store", "provider": "codex",
                                "source_path": str(source_path), "label": "Authorized native account"})
            require(connected["status"] == "authorized" and connected["identity_admission"] == "verification_required")
            source_id = connected["source_id"]
        reconciliation = mutate("source.reconcile", {"source_id": source_id})
        require(reconciliation["status"] in ("verifying_identity", "reconciled"))
        pending_job = reconciliation["operation_id"]
        require(pending_job is None or pending_job == "reconcile-" + source_id)
        PHASE = "provider-verification"
        deadline = time.monotonic() + remaining(120)
        while True:
            remaining()
            snapshot = cli("state.snapshot")
            completed = pending_job is None
            if pending_job is not None:
                jobs = [job for job in snapshot["jobs"] if job["id"] == pending_job]
                require(len(jobs) == 1 and jobs[0]["status"] in ("running", "pending", "completed"))
                completed = jobs[0]["status"] == "completed"
            facts = enrolled_authority(snapshot, source_id, int(time.time())) if completed else None
            if facts is not None:
                break
            require(time.monotonic() < deadline)
            time.sleep(0.1)
        require(service() == initial_service)
        restarted = False
        if manifest["permissions"]["restart_daemon"]:
            PHASE = "restart-authority"
            snapshot = cli("state.snapshot")
            require(not snapshot["leases"] and not snapshot["bindings"] and service() == initial_service)
            # Only this explicitly authorized named service is signalled.
            PHASE = "restart"
            manager("restart")
            retained_service = await_ready(initial_service["pid"])
            PHASE = "retained-verification"
            require(enrolled_authority(cli("state.snapshot"), source_id, int(time.time())) == facts)
            restarted = True
        else:
            retained_service = initial_service
        require(service() == retained_service)
        require_session_owners()
        require(identity(information) == identity(os.fstat(source))
                == identity(os.stat("auth.json", dir_fd=directory, follow_symlinks=False)))
        PHASE = "receipt"
        return {"schema_version": 1, "scope": "resident_authorized_codex_source_enrollment",
                "instance": manifest["instance"], **facts, "renewal_writer": "external",
                "service_active": True, "custody_retained": True, "restart_verified": restarted,
                "resident_service_disposition": "retained_under_existing_user_manager",
                "resident_bounds_verified": True,
                "existing_session_service_ownership_verified": True,
                "resident_memory_max_bytes": 268435456, "resident_swap_max_bytes": 0,
                "resident_tasks_max": 32, "resident_cpu_percent_max": 10,
                "credential_contents_read_by_controller": False, "native_auth_written": False,
                "sign_in_performed": False, "same_process_handoff_proven": False,
                "bundle_sha256": hashlib.sha256(payload).hexdigest()}
    finally:
        os.close(source)
        os.close(directory)
    # No uninstall, state removal, private-bus creation or vault deletion.


def main():
    global DEADLINE_NS
    DEADLINE_NS = original_deadline(os.environ)
    require(len(sys.argv) == 4)
    bundle, systemctl, session_probe = (Path(value).resolve(strict=True) for value in sys.argv[1:])
    result = execute(bundle, systemctl, session_probe, private_manifest())
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        print("resident enrollment refused at " + (PHASE if PHASE in PHASES else "manifest"), file=sys.stderr)
        sys.exit(1)
