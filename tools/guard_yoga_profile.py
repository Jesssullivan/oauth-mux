"""Finite, local Yoga admission. No executor, allocation, bootstrap or browser IO.

The independently selected private receipt is evidence, never a substitute for
current seat, registered closure, input-byte and compositor observations.
"""
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import select
import sqlite3
import stat
import subprocess
import sys
import time
from types import ModuleType

import system_mask_policy as masks
import yoga_display_binding as display
import yoga_proof_inputs as inputs
import yoga_operator_coordinator as coordinator

LABEL = coordinator.LABEL
SHA = re.compile(r"[0-9a-f]{64}")
TOOLS = frozenset(("python", "systemd_run", "systemctl", "bazel", "closure",
                   "bootstrap_closure", "zig_sdk", "java_home"))
SOURCE_FILES = frozenset("delivery/" + name for name in (
    "browser_runtime_authority.py", "yoga_toolbar_consent.py", "yoga_toolbar_contract.py",
    "test_installed_chromium.py", "test_installed_custody.py", "install.py", "pack.py", "portable.py",
    "yoga_wrapper_authority.py", "yoga_wrapper_custody.py"))
WRAPPER_SOURCE_FILES = frozenset(("delivery/yoga_wrapper_authority.py", "delivery/yoga_wrapper_custody.py"))
FIELDS = frozenset(("schemaVersion", "scope", "hostAlias", "proofId", "deadlineMonotonicNs",
                    "host", "seat", "operatorTerminal", "sourceRoot", "sourceGraphSha256",
                    "sourceFilesSha256", "sourceSocket", "compositorSnapshot", "inputPaths", "inputSha256",
                    "controllerTools", "controllerInventory", "controllerNarProof", "vaultWrapperAuthority"))
CLEANUP_RESERVE_NS = 120 * 10**9
BROWSER_INVENTORY_LIMIT = 8 * 1024 * 1024
INSTALLED_SCOPE = 'yoga-local-installed-guard-qualification-v1'
INSTALLED_FIELDS = FIELDS | {'installedWorkspace'}


def require_unit_absent(control, proof_id, deadline_ns):
    require(isinstance(proof_id, str) and coordinator.UUID.fullmatch(proof_id), "invalid Yoga unit selector")
    timeout = min(5.0, display.budget(deadline_ns))
    unit = 'omux-execution-' + proof_id + '.service'
    result = subprocess.run([control, '--system', 'show', '--property=Id,LoadState,ActiveState,ControlGroup,MainPID', unit],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=timeout, check=False)
    require(result.returncode in (0, 4) and len(result.stdout) <= 4096, "Yoga unit absence query failed")
    facts = dict(line.split('=', 1) for line in result.stdout.decode('ascii').splitlines() if '=' in line)
    require(facts.get('Id') == unit and facts.get('LoadState') == 'not-found'
            and facts.get('ActiveState') == 'inactive' and facts.get('MainPID') == '0'
            and not facts.get('ControlGroup'), "Yoga proof identifier already names a unit")


def owns_unit(properties, *, unit, run, nonce, plan_sha256, worker, python, cgroup=None, worker_identity=None):
    expected = {'OMUX_EXECUTION_GUARD=' + str(run), 'OMUX_YOGA_LAUNCH_NONCE=' + nonce,
                'OMUX_YOGA_WORKER_PLAN_SHA256=' + plan_sha256}
    require(properties.get('Id') == unit and properties.get('User') == str(os.getuid())
            and properties.get('Group') == str(os.getgid())
            and expected.issubset(set(properties.get('Environment', '').split())),
            'Yoga unit does not belong to this launch')
    execution = properties.get('ExecStart', '')
    require('path=' + python in execution and worker + ' --worker ' + str(run) + ' --' in execution,
            'Yoga unit executable/epoch identity differs')
    name = properties.get('ControlGroup', '')
    require(name.startswith('/') and '..' not in Path(name).parts and Path(name).name == unit,
            'Yoga unit has no owned cgroup')
    current = Path('/sys/fs/cgroup') / name.lstrip('/')
    require(cgroup is None or current == cgroup, 'Yoga unit cgroup changed before cleanup')
    if worker_identity is not None:
        information = current.stat()
        captured = worker_identity['coordinator']
        require((information.st_dev, information.st_ino) == (captured['device'], captured['inode']),
                'Yoga original cgroup identity changed before cleanup')
        if properties.get('MainPID') != '0':
            require(properties.get('MainPID') == str(worker_identity['pid'])
                    and display.pid_start(worker_identity['pid'], os.getuid()) == worker_identity['startTicks'],
                    'Yoga original worker identity changed before cleanup')
    return current


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def finite(profile, manager, arguments):
    require(profile == "yoga-toolbar" and manager == "system" and arguments == ["run", LABEL],
            "yoga requires one fixed operator-local system-manager run")


def selectors(path, state_root, source_root, home):
    for value in (path, state_root, source_root):
        require(isinstance(value, (str, Path)) and str(value).startswith("/srv/")
                and str(Path(value)) == str(value) and not {".", ".."}.intersection(str(value).split("/"))
                and not any(character.isspace() for character in str(value))
                and not Path(value).is_relative_to(home), "yoga requires exact private /srv selectors outside HOME")


def file_bytes(path, maximum, deadline_ns, *, private=False, expected=None, owner=None):
    display.budget(deadline_ns)
    require(type(maximum) is int and maximum > 0, "invalid yoga file bound")
    require(expected is None or isinstance(expected, str) and SHA.fullmatch(expected), "invalid yoga digest")
    path = Path(path)
    require(path.is_absolute() and str(path) == str(path.absolute()) and ".." not in path.parts,
            "invalid yoga file selector")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        walked = Path('/')
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = child
            metadata = os.fstat(directory)
            walked /= part
            sticky_store = walked == Path('/nix/store') and metadata.st_uid == 0 and stat.S_IMODE(metadata.st_mode) == 0o1775
            require(metadata.st_uid in (0, os.getuid()) and (not metadata.st_mode & 0o022 or sticky_store),
                    "yoga input ancestor custody rejected")
            if walked != Path('/nix/store') and walked.is_relative_to('/nix/store'):
                require(metadata.st_uid == 0 and not metadata.st_mode & 0o222, 'yoga store descendant custody rejected')
            require(owner is None or metadata.st_uid == owner, "yoga authority ancestor owner differs")
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            before = os.fstat(descriptor)
            require(stat.S_ISREG(before.st_mode) and before.st_uid in (0, os.getuid())
                    and not before.st_mode & 0o022 and before.st_nlink == 1
                    and 0 <= before.st_size <= maximum, "yoga file custody rejected")
            require(owner is None or before.st_uid == owner, "yoga authority file owner differs")
            if path.is_relative_to('/nix/store'):
                require(before.st_uid == 0 and not before.st_mode & 0o222, 'yoga store file custody rejected')
            if private:
                require(before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o600,
                        "yoga receipt must be owned single-link 0600")
            payload = bytearray()
            while True:
                display.budget(deadline_ns)
                chunk = os.read(descriptor, min(65536, maximum + 1 - len(payload)))
                if not chunk:
                    break
                payload.extend(chunk)
                require(len(payload) <= maximum, "yoga file exceeds bound")
            after, current = os.fstat(descriptor), os.stat(path.name, dir_fd=directory, follow_symlinks=False)
            identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mode, info.st_uid,
                                     info.st_nlink, info.st_mtime_ns, info.st_ctime_ns)
            require(identity(before) == identity(after) == identity(current), "yoga file changed while reading")
            result = bytes(payload)
            require(expected is None or hashlib.sha256(result).hexdigest() == expected, "yoga input digest differs")
            display.budget(deadline_ns)
            return result
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)


def decode(payload):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate yoga receipt field")
            result[key] = value
        return result
    return json.loads(payload, object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite yoga receipt")))


def schema(value, deadline_ns, source_root, tools, graph_sha256, uid):
    installed = type(value) is dict and value.get('scope') == INSTALLED_SCOPE
    require(type(value) is dict and set(value) == (INSTALLED_FIELDS if installed else FIELDS) and type(value["schemaVersion"]) is int
            and value["schemaVersion"] == 1 and value["scope"] == (INSTALLED_SCOPE if installed else "yoga-local-guard-qualification-v1")
            and value["hostAlias"] == "yoga" and isinstance(value["proofId"], str)
            and coordinator.UUID.fullmatch(value["proofId"])
            and type(value["deadlineMonotonicNs"]) is int and value["deadlineMonotonicNs"] == deadline_ns,
            "invalid yoga qualification scope")
    require(type(value["host"]) is dict and set(value["host"]) == {"machineIdSha256", "bootIdSha256", "uid"}
            and type(value["host"]["uid"]) is int and value["host"]["uid"] == uid
            and all(isinstance(value["host"][key], str) and SHA.fullmatch(value["host"][key])
                    for key in ("machineIdSha256", "bootIdSha256")), "invalid yoga host binding")
    seat = value["seat"]
    require(type(seat) is dict and set(seat) == {"sessionId", "seatId", "uid"}
            and type(seat["uid"]) is int and seat["uid"] == uid
            and isinstance(seat["sessionId"], str) and re.fullmatch(r"[A-Za-z0-9_-]{1,32}", seat["sessionId"])
            and isinstance(seat["seatId"], str) and re.fullmatch(r"seat[0-9]{1,3}", seat["seatId"]),
            "invalid yoga local seat selection")
    require(isinstance(value["operatorTerminal"], str)
            and re.fullmatch(r"/dev/(?:tty[0-9]{1,3}|pts/[0-9]{1,6})", value["operatorTerminal"]),
            "invalid yoga local operator terminal")
    require(value["sourceRoot"] == str(source_root) and value["sourceGraphSha256"] == graph_sha256
            and type(value["controllerTools"]) is dict and set(value["controllerTools"]) == TOOLS
            and value["controllerTools"] == tools, "yoga source/controller selection differs")
    require(type(value["sourceFilesSha256"]) is dict and set(value["sourceFilesSha256"]) == SOURCE_FILES
            and all(isinstance(item, str) and SHA.fullmatch(item) for item in value["sourceFilesSha256"].values()),
            "yoga runner sources require exact independent digests")
    require(type(value["inputPaths"]) is dict and set(value["inputPaths"]) == coordinator.INPUTS
            and all(isinstance(item, str) and (item.startswith("/srv/") or item.startswith("/nix/store/"))
                    and not any(character.isspace() for character in item) and ".." not in Path(item).parts
                    for item in value["inputPaths"].values())
            and type(value["inputSha256"]) is dict and set(value["inputSha256"]) == coordinator.INPUTS
            and all(isinstance(item, str) and SHA.fullmatch(item) for item in value["inputSha256"].values()),
            "invalid yoga declared input tuple")
    for name in ("controllerInventory", "controllerNarProof"):
        require(type(value[name]) is dict and set(value[name]) == {"path", "sha256"}
                and isinstance(value[name]["sha256"], str) and SHA.fullmatch(value[name]["sha256"]),
                "invalid yoga controller closure evidence")
    wrapper_envelope_schema(value)
    if installed:
        selected = value['installedWorkspace']
        require(type(selected) is dict and set(selected) == {'path','sha256'}
                and selected['path'] == str(Path(source_root)/'installed-workspace.json')
                and type(selected['sha256']) is str and SHA.fullmatch(selected['sha256']),
                'invalid Yoga installed inventory selector')
    return value


def wrapper_envelope_schema(value):
    selected = value['vaultWrapperAuthority']
    evidence = {'companion', 'nativeManifest', 'registeredNativeManifest', 'controllerInventory', 'controllerNarProof'}
    require(type(selected) is dict and set(selected) == evidence | {'controllerTools'}, 'invalid Yoga wrapper authority')
    for name in evidence:
        item = selected[name]
        require(type(item) is dict and set(item) == {'path', 'sha256'} and type(item['sha256']) is str
                and SHA.fullmatch(item['sha256']) and type(item['path']) is str and len(item['path']) <= 4096
                and item['path'].startswith(('/srv/', '/nix/store/')) and str(Path(item['path'])) == item['path']
                and not {'.', '..'}.intersection(item['path'].split('/')) and not any(c.isspace() for c in item['path']),
                'invalid Yoga wrapper evidence selector')
    require(Path(selected['nativeManifest']['path']).name == 'native.json'
            and re.fullmatch(r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]{1,211}', selected['registeredNativeManifest']['path']),
            'invalid Yoga wrapper manifest selector')
    require(all(selected[name] == value[name] for name in ('controllerTools', 'controllerInventory', 'controllerNarProof')),
            'Yoga wrapper controller evidence differs')
    return selected


def wrapper_source_hashes(value):
    hashes = value['sourceFilesSha256']
    require(type(hashes) is dict and WRAPPER_SOURCE_FILES.issubset(hashes)
            and all(type(hashes[name]) is str and SHA.fullmatch(hashes[name]) for name in WRAPPER_SOURCE_FILES),
            'Yoga wrapper source authority is unavailable')
    return {name: hashes[name] for name in sorted(WRAPPER_SOURCE_FILES)}


def wrapper_modules(value, deadline_ns):
    root = Path(value['sourceRoot'])
    require(str(root).startswith('/srv/') and str(root) == value['sourceRoot'] and '..' not in root.parts,
            'Yoga wrapper source root differs')
    modules = []
    for relative, sha in wrapper_source_hashes(value).items():
        data = file_bytes(root / relative, 1024 * 1024, deadline_ns, expected=sha)
        module = ModuleType('omux_' + Path(relative).stem)
        module.__file__ = str(root / relative)
        # Dataclasses consult their defining module during construction. Keep
        # only this already-hashed code visible for that construction interval.
        prior = sys.modules.get(module.__name__)
        sys.modules[module.__name__] = module
        try:
            exec(compile(data, module.__file__, 'exec'), module.__dict__)
        finally:
            if prior is None: sys.modules.pop(module.__name__, None)
            else: sys.modules[module.__name__] = prior
        modules.append(module)
    return modules[0], modules[1]


def wrapper_capture(value, deadline_ns, *, wrapper_paths=None, native_manifest_path=None):
    validator, custody = wrapper_modules(value, deadline_ns)
    selected = wrapper_envelope_schema(value)
    paths = {name: value['inputPaths'][name] for name in ('dbus_session', 'dbus_daemon', 'keyring')}
    shas = {name: value['inputSha256'][name] for name in paths}
    return custody.AuthorityCapture(selected, paths if wrapper_paths is None else wrapper_paths, shas,
        deadline_ns, validator=validator, native_manifest_path=native_manifest_path)


def local_identity(value, deadline_ns, uid, operator_descriptor):
    expected = value["host"]
    for key, path in (("machineIdSha256", "/etc/machine-id"), ("bootIdSha256", "/proc/sys/kernel/random/boot_id")):
        require(hashlib.sha256(file_bytes(path, 128, deadline_ns)).hexdigest() == expected[key],
                "yoga current host/boot identity differs")
    saved = file_bytes("/run/systemd/sessions/" + value["seat"]["sessionId"], 16384, deadline_ns, owner=0)
    rows = [line.split("=", 1) for line in saved.decode("ascii").splitlines() if line and not line.startswith("#")]
    require(all(len(row) == 2 for row in rows) and len({row[0] for row in rows}) == len(rows), "invalid live logind seat record")
    facts = dict(rows)
    require(all(facts.get(key) == fact for key, fact in {"UID": str(uid), "SEAT": value["seat"]["seatId"],
            "TYPE": "wayland", "ACTIVE": "1", "REMOTE": "0"}.items()), "yoga local-console Wayland seat is not active")
    # An SSH PTY can share this UID with an unrelated local desktop. Bind the
    # supervisor's kernel login/audit session to the root-owned selected logind
    # session; unsupported/missing audit provenance refuses rather than guessing.
    audit = file_bytes(f"/proc/{os.getpid()}/sessionid", 32, deadline_ns).decode("ascii").strip()
    login = file_bytes(f"/proc/{os.getpid()}/loginuid", 32, deadline_ns).decode("ascii").strip()
    require(audit.isdecimal() and 0 <= int(audit) < 4294967295
            and facts.get("AUDIT") == audit and login == str(uid), "yoga operator process belongs to another login session")
    require(os.isatty(operator_descriptor) and os.ttyname(operator_descriptor) == value["operatorTerminal"],
            "yoga requires the independently selected local console event ingress")
    information = os.fstat(operator_descriptor)
    require(stat.S_ISCHR(information.st_mode) and information.st_uid == uid, "yoga operator terminal custody differs")


def registered_rows(rows, deadline_ns, database="/nix/var/nix/db/db.sqlite"):
    require(type(rows) is list and 1 <= len(rows) <= 4096, "yoga registered closure bound")
    paths = {row["path"] for row in rows}
    require(sum(len(row.get("references", [])) for row in rows) <= 65536
            and sum(row.get("narSize", 0) for row in rows) <= 16 * 1024**3, "yoga registered closure exceeds bound")
    require(len(paths) == len(rows) and all(isinstance(path, str)
            and re.fullmatch(r"/nix/store/[0-9a-z]{32}-[A-Za-z0-9+._?=-]{1,211}", path) for path in paths),
            "yoga registered root selector rejected")
    connection = sqlite3.connect(Path(database).as_uri() + "?mode=ro", uri=True, timeout=1)
    connection.execute("PRAGMA query_only=ON")
    connection.set_progress_handler(lambda: int(time.monotonic_ns() >= deadline_ns), 1000)
    try:
        connection.execute("BEGIN")
        for row in rows:
            display.budget(deadline_ns)
            require(set(row) == {"path", "narHash", "narSize", "references"}
                    and type(row["narSize"]) is int and row["narSize"] > 0
                    and type(row["references"]) is list and set(row["references"]).issubset(paths),
                    "yoga closure inventory is incomplete")
            information = os.lstat(row["path"])
            require(stat.S_ISDIR(information.st_mode) or stat.S_ISREG(information.st_mode) or stat.S_ISLNK(information.st_mode),
                    "yoga registered store root unavailable")
            current = connection.execute("SELECT id, hash, narSize FROM ValidPaths WHERE path=?", (row["path"],)).fetchone()
            require(current is not None and current[1:] == (row["narHash"], row["narSize"]), "yoga registered NAR metadata changed")
            refs = [entry[0] for entry in connection.execute("SELECT v.path FROM Refs r JOIN ValidPaths v ON v.id=r.reference WHERE r.referrer=? ORDER BY v.path", (current[0],))]
            require(refs == row["references"], "yoga registered reference topology changed")
    finally:
        connection.close()


def runtime_qualification(value, deadline_ns, *, retain_inventory=False):
    root = Path(value["sourceRoot"])
    authority_code = None
    for relative, digest in value["sourceFilesSha256"].items():
        checked = file_bytes(root / relative, 1024 * 1024, deadline_ns, expected=digest)
        if relative == "delivery/browser_runtime_authority.py":
            authority_code = checked
    # Execute the identified controller helper's captured bytes, not a second
    # mutable-path open after hashing. This imports no candidate runtime tool.
    require(authority_code is not None, "yoga authority helper is missing")
    authority = ModuleType("omux_yoga_browser_authority")
    authority.__file__ = str(root / "delivery/browser_runtime_authority.py")
    exec(compile(authority_code, authority.__file__, "exec"), authority.__dict__)
    runtime = authority.validate_authority(file_bytes(value["inputPaths"]["runtime_authority"], authority.MAX_AUTHORITY,
                                            deadline_ns, expected=value["inputSha256"]["runtime_authority"]))
    browser_inventory_bytes = base64.b64decode(runtime["inventoryBase64"], validate=True)
    require(0 < len(browser_inventory_bytes) <= BROWSER_INVENTORY_LIMIT
            and hashlib.sha256(browser_inventory_bytes).hexdigest() == runtime['inventorySha256'],
            'Yoga qualified browser inventory binding differs')
    browser_inventory = authority.parse(browser_inventory_bytes)
    inventory_input, nar_input = value["controllerInventory"], value["controllerNarProof"]
    inventory_bytes = file_bytes(inventory_input["path"], 8 * 1024 * 1024, deadline_ns, expected=inventory_input["sha256"])
    inventory = decode(inventory_bytes)
    rows = inventory["paths"]
    nar = authority.receipt_from_input(file_bytes(nar_input["path"], authority.MAX_INPUT, deadline_ns, expected=nar_input["sha256"]))
    nar_fields = {"schemaVersion", "passed", "inventorySha256", "descriptorSha256", "verifiedPaths",
                  "verifiedRegularInputs", "verifiedNarBytes", "contentRehashed", "linkTargetsFollowed",
                  "executionAuthority", "flakeMappingVerified", "realized"}
    require(type(nar) is dict and set(nar) == nar_fields and type(nar["schemaVersion"]) is int and nar["schemaVersion"] == 1
            and isinstance(nar["descriptorSha256"], str) and SHA.fullmatch(nar["descriptorSha256"])
            and type(nar["verifiedRegularInputs"]) is int and nar["verifiedRegularInputs"] > 0
            and nar.get("passed") is True and nar.get("contentRehashed") is True
            and nar.get("inventorySha256") == inventory_input["sha256"]
            and type(nar.get("verifiedPaths")) is int and nar["verifiedPaths"] == len(rows)
            and type(nar.get("verifiedNarBytes")) is int and nar["verifiedNarBytes"] == sum(row["narSize"] for row in rows)
            and all(nar[name] is False for name in ("realized", "executionAuthority", "linkTargetsFollowed", "flakeMappingVerified")),
            "yoga controller byte qualification is unavailable")
    registered_rows(rows, deadline_ns)
    registered_rows(browser_inventory["paths"], deadline_ns)
    controller_roots = {row["path"] for row in rows}
    for path in value["controllerTools"].values():
        require(str(Path(*Path(path).parts[:4])) in controller_roots, "yoga controller tool is outside qualified closure")
    for name, package in (("chromium", "chromium"), ("node", "node")):
        require(str(Path(*Path(value["inputPaths"][name]).parts[:4])) == runtime["packages"][package]["out"],
                "yoga browser executable differs from qualified selection")
    with wrapper_capture(value, deadline_ns):
        checked = inputs.check_inputs(value["inputPaths"], value["inputSha256"], deadline_ns)
    if retain_inventory:
        return checked, {'bytes': browser_inventory_bytes, 'sha256': runtime['inventorySha256']}
    return checked


def preallocate(path, digest, deadline_ns, *, manager, arguments, state_root, source_root,
                home, tools, graph_sha256, uid, operator_descriptor):
    return _preallocate(path, digest, deadline_ns, manager=manager, arguments=arguments,
        state_root=state_root, source_root=source_root, home=home, tools=tools,
        graph_sha256=graph_sha256, uid=uid, operator_descriptor=operator_descriptor)


def _preallocate(path, digest, deadline_ns, *, manager, arguments, state_root, source_root,
                 home, tools, graph_sha256, uid, operator_descriptor, reserved=False):
    finite("yoga-toolbar", manager, arguments)
    validator = schema
    if reserved:
        import guard_yoga_toolbar_reserved as reservation
        validator = reservation.schema
    display.budget(deadline_ns)
    require(deadline_ns - time.monotonic_ns() > CLEANUP_RESERVE_NS, "yoga deadline lacks cleanup reserve")
    selectors(path, state_root, source_root, home)
    value = validator(decode(file_bytes(path, 65536, deadline_ns, private=True, expected=digest)),
                   deadline_ns, source_root, tools, graph_sha256, uid)
    installed_capture = None
    for selection in value["inputPaths"].values():
        require(not Path(selection).is_relative_to(home), "yoga input is hidden by personal HOME mask")
    proof_root = str(Path(state_root) / value["proofId"])
    display.selectors(value["sourceSocket"], proof_root + "/wayland.sock", proof_root, uid)
    display.valid_snapshot(value["compositorSnapshot"], uid)
    local_identity(value, deadline_ns, uid, operator_descriptor)
    require(Path(source_root).resolve(strict=True) == Path(source_root), "Yoga source must remain physical outside HOME")
    _, browser_inventory = runtime_qualification(value, deadline_ns, retain_inventory=True)
    require_unit_absent(tools['systemctl'], value['proofId'], deadline_ns)
    witness, pin = display.capture_pinned(value["sourceSocket"], proof_root + "/wayland.sock", proof_root, uid, deadline_ns)
    try:
        require(witness["snapshot"] == value["compositorSnapshot"], "yoga compositor identity differs")
        if reserved or value['scope'] == INSTALLED_SCOPE:
            import guard_yoga_installed_workspace as installed
            installed_capture = installed.Capture(source_root,value['installedWorkspace'],deadline_ns,file_bytes)
            installed_capture.qualify(value,graph_sha256)
        result = {"receipt": value, "witness": witness, "pin": pin, "receiptPath": path,
                "receiptSha256": digest, "operatorDescriptor": operator_descriptor,
                "browserInventory": browser_inventory}
        if installed_capture is not None:
            result['installedCapture'] = installed_capture
        return result
    except BaseException:
        if installed_capture is not None:
            installed_capture.close()
        pin.close()
        raise


def refresh(admission, home, graph_sha256, *, cleanup=False):
    value, witness = admission["receipt"], admission["witness"]
    validator = schema
    if admission.get('reservedToolbar') is True:
        import guard_yoga_toolbar_reserved as reservation
        reservation.capture(admission, cleanup=cleanup)
        validator = lambda *arguments: reservation.schema(*arguments, cleanup=cleanup)
    if admission.get('reservedToolbar') is True or value['scope'] == INSTALLED_SCOPE:
        import guard_yoga_installed_workspace as installed
        require(installed.verified(admission) is True,'Yoga installed inventory changed')
    require(validator(decode(file_bytes(admission["receiptPath"], 65536, witness["deadline_ns"], private=True,
                                    expected=admission["receiptSha256"])), witness["deadline_ns"], value["sourceRoot"],
                   value["controllerTools"], graph_sha256, witness["uid"]) == value, "yoga receipt changed")
    local_identity(value, witness["deadline_ns"], witness["uid"], admission["operatorDescriptor"])
    _, inventory = runtime_qualification(value, witness["deadline_ns"], retain_inventory=True)
    require(inventory == admission['browserInventory'], 'Yoga qualified browser inventory changed')
    if 'publishedInventory' in admission:
        repository_bindings(admission, witness['proof_root'])
    return admission["pin"].check(witness)


def repository_inventory(admission, run):
    value, witness = admission['receipt'], admission['witness']
    display.budget(witness['deadline_ns'])
    run = Path(run)
    require(str(run) == witness['proof_root'] and run.name == value['proofId']
            and str(run).startswith('/srv/') and '..' not in run.parts,
            'Yoga repository publication requires its exact private epoch')
    inventory = admission['browserInventory']
    require(type(inventory) is dict and set(inventory) == {'bytes', 'sha256'}
            and type(inventory['bytes']) is bytes and 0 < len(inventory['bytes']) <= BROWSER_INVENTORY_LIMIT
            and type(inventory['sha256']) is str and SHA.fullmatch(inventory['sha256'])
            and hashlib.sha256(inventory['bytes']).hexdigest() == inventory['sha256'],
            'Yoga repository inventory is not bound to qualified bytes')
    return run / 'browser-inventory.json', inventory


def repository_bindings(admission, run):
    if admission.get('reservedToolbar') is True or admission['receipt'].get('scope') == INSTALLED_SCOPE:
        import guard_yoga_installed_workspace as installed
        require(installed.verified(admission) is True,'Yoga installed inventory is unqualified')
        # No external project repository selectors enter the closed mini-graph.
        return {}
    path, inventory = repository_inventory(admission, run)
    expected = {'path': str(path), 'sha256': inventory['sha256']}
    require(admission.get('publishedInventory') == expected, 'Yoga repository inventory is not published')
    require(file_bytes(path, BROWSER_INVENTORY_LIMIT, admission['witness']['deadline_ns'],
                       private=True, expected=inventory['sha256']) == inventory['bytes'],
            'Yoga published repository inventory changed')
    bootstrap = admission['receipt']['controllerTools']['bootstrap_closure']
    require(type(bootstrap) is str and re.fullmatch(
        r'/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]{1,211}', bootstrap),
        'Yoga repository bootstrap must be its qualified immutable root')
    return {'OMUX_SITE_INVENTORY': str(path), 'OMUX_SITE_INVENTORY_SHA256': inventory['sha256'],
            'OMUX_BAZEL_BOOTSTRAP_CLOSURE': bootstrap}


def publish_repository_inventory(admission, run):
    if admission.get('reservedToolbar') is True or admission['receipt'].get('scope') == INSTALLED_SCOPE:
        return repository_bindings(admission,run)
    path, inventory = repository_inventory(admission, run)
    deadline = admission['witness']['deadline_ns']
    parent = inputs.open_parent(str(path), os.getuid(), deadline, time.monotonic_ns)
    try:
        before = os.fstat(parent)
        require(before.st_uid == os.getuid() and stat.S_IMODE(before.st_mode) == 0o700,
                'Yoga repository publication directory custody differs')
        descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=parent)
        try:
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(inventory['bytes']):
                display.budget(deadline)
                count = os.write(descriptor, inventory['bytes'][offset:offset + 65536])
                require(count > 0, 'Yoga repository publication did not progress')
                offset += count
            os.fsync(descriptor)
            os.fsync(parent)
            created, named = os.fstat(descriptor), os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            require((created.st_dev, created.st_ino, created.st_size, created.st_uid, created.st_nlink, created.st_mode) ==
                    (named.st_dev, named.st_ino, named.st_size, named.st_uid, named.st_nlink, named.st_mode),
                    'Yoga repository publication object changed')
        finally:
            os.close(descriptor)
        admission['publishedInventory'] = {'path': str(path), 'sha256': inventory['sha256']}
        return repository_bindings(admission, run)
    finally:
        os.close(parent)


def mask_setting(home):
    base = masks.setting(home=home, profile="installed-browser")
    require(str(Path(home)) == str(home) and not any(character.isspace() for character in str(home)), "invalid yoga HOME mask")
    return base + " " + str(home) + ":" + masks.OPTIONS


def verify_masks(properties, home, readonly_binds):
    current = properties.get("TemporaryFileSystem", "").split()
    personal = [entry for entry in current if entry.split(":", 1)[0] == str(home)]
    require(len(personal) == 1, "yoga personal HOME mask missing or duplicate")
    masks.verify_effective(" ".join(entry for entry in current if entry not in personal), home=home, profile="installed-browser")
    require(personal[0] == str(home) + ":" + masks.OPTIONS, "yoga personal HOME mask changed")
    require(properties.get("InaccessiblePaths", "").split() in (["/etc/environment"], ["-/etc/environment"]), "yoga environment mask differs")
    require(len(readonly_binds) == 1 and properties.get("BindReadOnlyPaths", "").split() == readonly_binds
            and not properties.get("BindPaths", "").split(), "yoga display bind differs")


def pump_event(admission, support, writer):
    descriptor = admission["operatorDescriptor"]
    display.budget(admission["witness"]["deadline_ns"])
    if not select.select([descriptor], [], [], 0)[0]:
        return
    require(support.admitted and len(support.events) < 3, "unexpected yoga operator event")
    payload = os.read(descriptor, 2049)
    require(0 < len(payload) <= 2048 and payload.endswith(b"\n") and payload.count(b"\n") == 1,
            "yoga operator event must be one complete bounded record")
    require(os.write(writer, payload) == len(payload), "yoga operator event pipe write incomplete")
    support.receive_event()
