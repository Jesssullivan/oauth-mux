"""Assemble a relocatable Linux runtime from declared Bazel/Nix inputs.

No host loader, library discovery command, or host search path participates in
selection.  The copied binaries and dependency closure are patched before they
enter the archive. Static ELF launchers belong in the user's bin directory;
shared libraries live below the private Omux installation subtree.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import struct
import subprocess
import tempfile
from pathlib import Path

# Bazel provides this generated module from the declared static launcher ELF.
# Missing modules fail the import: no source, shell or host-target fallback.
import portable_launcher_template as _launcher_template

_MAX_FILE = 128 * 1024 * 1024
_MAX_BACKEND_FILE = 512 * 1024 * 1024
_MAX_HEADERS = 4096
_MAX_DYNAMIC = 4096
_MAX_STRING = 4096
_MACHINES = {"x86_64-linux": 62, "aarch64-linux": 183}
_BACKEND_INTERPRETER = "/omux/launch-via-bin-wrapper"
_RUNTIME = "lib/omux"
_CA_BUNDLE = _RUNTIME + "/share/ca-bundle.crt"
_QT_RUNTIME = _RUNTIME + "/qt"
_QT_CONTROL = _QT_RUNTIME + "/libexec/omux-control.bin"
_QT_CONFIG = _QT_RUNTIME + "/libexec/qt.conf"
_QT_PREFIX = _QT_RUNTIME + "/plugins/platforms/"
_QT_PLUGIN_RPATH = "$ORIGIN/../../lib"
_QT_CONFIG_BYTES = b"[Paths]\nPrefix=..\nPlugins=plugins\nLibraries=lib\nLibraryExecutables=libexec\nData=share\n"
_WITNESS_SCOPE = "native-qt-offscreen-startup-only"
_ALIASES = ("omux", "oauth-mux", "omux-native-host", "git-credential-omux")


def _check_range(payload: bytes, offset: int, size: int) -> None:
    if offset < 0 or size < 0 or offset > len(payload) or size > len(payload) - offset:
        raise ValueError("ELF record extends beyond its file")


def _slice(payload: bytes, offset: int, size: int) -> bytes:
    _check_range(payload, offset, size)
    return payload[offset:offset + size]


def _cstring(table: bytes, offset: int) -> str:
    if not 0 <= offset < len(table):
        raise ValueError("ELF string offset is outside its table")
    end = table.find(b"\0", offset, min(len(table), offset + _MAX_STRING + 1))
    if end < 0:
        raise ValueError("ELF string is unterminated or oversized")
    try:
        value = table[offset:end].decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("ELF runtime name is not ASCII") from error
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("ELF runtime name contains control characters")
    return value


def _file_limit(max_bytes: int) -> int:
    # R-N13: the measured native SDK backend needs a narrowly explicit bound.
    # Boolean, fractional, unbounded and caller-invented larger limits refuse.
    if type(max_bytes) is not int or not 0 < max_bytes <= _MAX_BACKEND_FILE:
        raise ValueError("invalid finite runtime file byte limit")
    return max_bytes


def elf_metadata(payload: bytes, *, max_bytes: int = _MAX_FILE) -> dict:
    """Parse bounded ELF64 little-endian runtime metadata without executing it.

    Section headers are deliberately unnecessary: stripped release binaries
    still describe their interpreter and dynamic string table in segments.
    Both DT_RPATH and DT_RUNPATH are retained so verification sees every lookup
    path, even in a malformed input containing both tags.
    """
    max_bytes = _file_limit(max_bytes)
    if len(payload) > max_bytes or len(payload) < 64 or payload[:4] != b"\x7fELF":
        raise ValueError("input is not a bounded ELF executable")
    if payload[4:7] != b"\x02\x01\x01":
        raise ValueError("only ELF64 little-endian version 1 is supported")
    header = struct.unpack_from("<HHIQQQIHHHHHH", payload, 16)
    kind, machine, version, _, phoff, _, _, ehsize, phentsize, phnum, _, _, _ = header
    if kind not in {2, 3} or machine not in _MACHINES.values() or version != 1 or ehsize != 64:
        raise ValueError("unsupported ELF header")
    if not 0 < phnum <= _MAX_HEADERS or phentsize != 56 or phoff < ehsize:
        raise ValueError("invalid ELF program-header table")
    _slice(payload, phoff, phentsize * phnum)
    loads: list[tuple[int, int, int]] = []
    dynamic = None
    interpreter = None
    for index in range(phnum):
        tag, _, offset, virtual, _, filesz, memsz, _ = struct.unpack_from("<IIQQQQQQ", payload, phoff + index * phentsize)
        if filesz > memsz:
            raise ValueError("ELF segment file size exceeds memory size")
        _check_range(payload, offset, filesz)
        if tag == 1:  # PT_LOAD
            loads.append((virtual, offset, filesz))
        elif tag == 2:  # PT_DYNAMIC
            if dynamic is not None or not filesz or filesz % 16 or filesz // 16 > _MAX_DYNAMIC:
                raise ValueError("invalid ELF dynamic segment")
            dynamic = _slice(payload, offset, filesz)
        elif tag == 3:  # PT_INTERP
            if interpreter is not None or not filesz or filesz > _MAX_STRING + 1:
                raise ValueError("invalid ELF interpreter")
            data = _slice(payload, offset, filesz)
            if data[-1:] != b"\0":
                raise ValueError("invalid ELF interpreter")
            interpreter = _cstring(data, 0)
            if not interpreter or len(interpreter) != len(data) - 1:
                raise ValueError("invalid ELF interpreter termination")

    result = {"needed": [], "rpath": [], "interpreter": interpreter, "machine": machine}
    if dynamic is None:
        return result
    entries: list[tuple[int, int]] = []
    terminated = False
    for offset in range(0, len(dynamic), 16):
        tag, value = struct.unpack_from("<qQ", dynamic, offset)
        if tag == 0:
            terminated = True
            break
        if tag in {0x7FFFFFFF, 0x7FFFFFFD, 0x6FFFFEFC, 0x6FFFFEFB, 0x6FFFFEFA}:
            raise ValueError("unsupported ELF auxiliary library, audit or configuration lookup")
        entries.append((tag, value))
    if not terminated:
        raise ValueError("ELF dynamic segment is unterminated")
    string_addresses = [value for tag, value in entries if tag == 5]  # DT_STRTAB
    string_sizes = [value for tag, value in entries if tag == 10]  # DT_STRSZ
    references = [(tag, value) for tag, value in entries if tag in {1, 15, 29}]
    if not references and not string_addresses and not string_sizes:
        return result
    if len(string_addresses) != 1 or len(string_sizes) != 1 or not 0 < string_sizes[0] <= _MAX_FILE:
        raise ValueError("ELF dynamic strings have no unique bounded table")
    address, size = string_addresses[0], string_sizes[0]
    mappings = [file_offset + address - virtual for virtual, file_offset, length in loads
                if address >= virtual and address - virtual <= length and size <= length - (address - virtual)]
    if len(mappings) != 1:
        raise ValueError("ELF string table has no unique file-backed mapping")
    table = _slice(payload, mappings[0], size)
    for tag, offset in references:
        value = _cstring(table, offset)
        if tag == 1:
            if not value:
                raise ValueError("ELF dependency name is empty")
            result["needed"].append(value)
        else:
            result["rpath"].extend(value.split(":"))
    return result


def _read(path: Path, *, max_bytes: int = _MAX_FILE) -> bytes:
    max_bytes = _file_limit(max_bytes)
    if not path.is_file() or path.stat().st_size > max_bytes:
        raise ValueError("runtime inputs must be bounded regular files")
    with path.open("rb") as source:
        result = source.read(max_bytes + 1)
    if len(result) > max_bytes:
        raise ValueError("runtime input exceeds its bounded size")
    return result


def _basename(name: str) -> str:
    value = name.rsplit("/", 1)[-1]
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,127}", value):
        raise ValueError("unsafe runtime dependency basename")
    return value


def channel_instance(channel: str | None) -> str | None:
    if channel is None:
        return None
    if channel not in {"development", "release"}:
        raise ValueError("unsupported artifact channel")
    return "dev" if channel == "development" else "default"


def _trusted_launcher(target: str | None) -> tuple[str, bytes, str]:
    """Select only the generated native target, never archive-owned code."""
    native_target = _launcher_template.TARGET
    selected = native_target if target is None else target
    if (type(_launcher_template.ABI) is not int or _launcher_template.ABI != 1
            or not isinstance(native_target, str) or native_target not in _MACHINES
            or not isinstance(selected, str) or selected != native_target):
        raise ValueError("declared static launcher is unavailable for the requested target")
    template, digest = _launcher_template.TEMPLATE, _launcher_template.SHA256
    if (not isinstance(template, bytes) or not 0 < len(template) <= _MAX_FILE
            or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or hashlib.sha256(template).hexdigest() != digest):
        raise ValueError("declared static launcher template is invalid")
    metadata = elf_metadata(template)
    if (metadata["machine"] != _MACHINES[selected] or metadata["interpreter"] is not None
            or metadata["needed"] or metadata["rpath"]):
        raise ValueError("declared launcher does not have its native static ELF boundary")
    return selected, template, digest


def _launcher_metadata(target: str) -> dict:
    selected, _, digest = _trusted_launcher(target)
    return {"abi": 1, "target": selected, "templateSha256": digest}


def linux_launcher(loader: str, backend: str, channel: str | None = None, *,
                   target: str | None = None) -> bytes:
    """Trusted static ELF plus its canonical ABI1 loader/role/channel record."""
    loader = _basename(loader)
    roles = {"omux.bin": 1, "omuxd.bin": 2, "omux-control.bin": 3}
    if backend not in roles:
        raise ValueError("unsupported backend executable")
    channel_instance(channel)
    selected, template, _ = _trusted_launcher(target)
    record = bytearray(256)
    record[:16] = b"OMUXLNXLAUNCHv1\0"
    record[16] = 1
    record[17] = roles[backend]
    record[18] = {None: 0, "development": 1, "release": 2}[channel]
    struct.pack_into("<H", record, 20, _MACHINES[selected])
    loader_bytes = loader.encode("ascii")
    record[32:32 + len(loader_bytes)] = loader_bytes
    return template + bytes(record)

def _patch(path: Path, metadata: dict, patchelf: Path, backend: bool,
           rpath: str = "$ORIGIN") -> None:
    args = [str(patchelf)]
    for needed in metadata["needed"]:
        if "/" in needed:
            args.extend(["--replace-needed", needed, _basename(needed)])
    if backend:
        args.extend(["--set-interpreter", _BACKEND_INTERPRETER, "--set-rpath", "$ORIGIN/../lib"])
    else:
        if metadata["interpreter"] is not None:
            args.extend(["--set-interpreter", _BACKEND_INTERPRETER])
        args.extend(["--force-rpath", "--set-rpath", rpath])
    args.append(str(path))
    try:
        subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       check=True, timeout=60, env={"LC_ALL": "C", "PATH": "/nonexistent"})
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("declared patchelf could not patch the runtime") from error


def _verify_ca_bundle(payload: bytes) -> None:
    if not payload or len(payload) > 16 * 1024 * 1024:
        raise ValueError("public CA bundle must be nonempty and bounded")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("public CA bundle must use valid UTF-8 text") from error
    labels = re.findall(r"-----((?:BEGIN|END) [^-\r\n]+)-----", text)
    allowed = {prefix + " " + kind for prefix in ("BEGIN", "END")
               for kind in ("CERTIFICATE", "TRUSTED CERTIFICATE")}
    if not labels or any(label not in allowed for label in labels):
        raise ValueError("CA bundle may contain public certificate PEM blocks only")
    blocks = re.findall(r"-----BEGIN (CERTIFICATE|TRUSTED CERTIFICATE)-----[ \t\r\n]*([A-Za-z0-9+/= \t\r\n]+?)[ \t\r\n]*-----END \1-----", text)
    if len(labels) != 2 * len(blocks) or not blocks:
        raise ValueError("CA bundle contains malformed certificate boundaries")
    for _, block in blocks:
        try:
            certificate = base64.b64decode("".join(block.split()), validate=True)
        except (ValueError, binascii.Error) as error:
            raise ValueError("CA bundle certificate payload is malformed") from error
        if not certificate or len(certificate) > 64 * 1024:
            raise ValueError("CA bundle certificate payload is empty or oversized")


def _validate_resolution_witness(value: dict, target: str) -> dict:
    """Validate an input witness; this does not replay its native audit."""
    fields = {"schemaVersion", "scope", "target", "controlSha256", "libraries"}
    if (not isinstance(value, dict) or set(value) != fields or type(value["schemaVersion"]) is not int
            or value["schemaVersion"] != 1 or value["scope"] != _WITNESS_SCOPE or value["target"] != target
            or not isinstance(value["controlSha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["controlSha256"])):
        raise ValueError("invalid native Qt resolution witness")
    libraries = value["libraries"]
    if not isinstance(libraries, list) or not 0 < len(libraries) <= 128:
        raise ValueError("native Qt witness requires bounded canonical libraries")
    checked = []
    names = set()
    for library in libraries:
        if not isinstance(library, dict) or set(library) != {"soname", "sha256", "variants"}:
            raise ValueError("invalid canonical library witness")
        soname, digest = library["soname"], library["sha256"]
        if (not isinstance(soname, str) or _basename(soname) != soname or soname in names
                or soname == "libc.so.6" or soname.startswith("ld-")
                or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)):
            raise ValueError("invalid or forbidden canonical library witness")
        variants = library["variants"]
        if (not isinstance(variants, list) or not 0 < len(variants) <= 128
                or any(not isinstance(variant, str) or not re.fullmatch(r"[0-9a-f]{64}", variant) for variant in variants)
                or variants != sorted(set(variants)) or digest not in variants):
            raise ValueError("invalid canonical library variant custody")
        names.add(soname)
        checked.append({"soname": soname, "sha256": digest, "variants": list(variants)})
    return {"schemaVersion": 1, "scope": _WITNESS_SCOPE, "target": target,
            "controlSha256": value["controlSha256"], "libraries": sorted(checked, key=lambda entry: entry["soname"])}


def _assemble_namespace(binary: Path, daemon: Path, runtime_files: list[Path], patchelf: Path,
                        target: str, ca_bundle: Path, control: Path | None = None,
                        qt_plugins: list[Path] | None = None,
                        resolution_witness: dict | None = None,
                        namespace: str = _RUNTIME, *,
                        backend_max_bytes: int = _MAX_FILE, channel: str | None = None) -> tuple[dict[str, bytes], dict]:
    """Select and patch one process's closure without merging other processes."""
    backend_max_bytes = _file_limit(backend_max_bytes)
    if target not in _MACHINES:
        raise ValueError("portable Linux assembly requires a supported Linux target")
    _trusted_launcher(target)
    if not runtime_files or len(runtime_files) > _MAX_HEADERS:
        raise ValueError("runtime dependency inputs must be nonempty and bounded")
    plugins = qt_plugins or []
    if (control is None and plugins) or (control is not None and not plugins) or len(plugins) > 128:
        raise ValueError("Qt control requires a bounded, declared platform-plugin set")
    plugin_sources: dict[str, Path] = {}
    for path in plugins:
        if path.parent.name != "platforms" or not path.name.endswith(".so"):
            raise ValueError("unsupported Qt plugin category or filename")
        name = "plugins/platforms/" + _basename(path.name)
        if name in plugin_sources:
            raise ValueError("duplicate Qt platform plugin")
        plugin_sources[name] = path
    patchelf = patchelf.resolve(strict=True)
    if not patchelf.is_file():
        raise ValueError("patchelf must be a declared regular executable")
    expected_machine = _MACHINES[target]
    candidates: dict[str, list[Path]] = {}
    payloads: dict[tuple[Path, bool], bytes] = {}
    metadata: dict[tuple[Path, bool], dict] = {}

    def inspect(path: Path, backend: bool = False) -> tuple[bytes, dict]:
        # Role is part of the cache key: a shared path must never let a library
        # acquire the separately authorized executable's larger byte budget.
        key = (path, backend)
        if key not in payloads:
            maximum = backend_max_bytes if backend else _MAX_FILE
            data = _read(path, max_bytes=maximum)
            info = elf_metadata(data, max_bytes=maximum)
            if info["machine"] != expected_machine:
                raise ValueError("ELF machine does not match the archive target")
            payloads[key], metadata[key] = data, info
        return payloads[key], metadata[key]

    for path in runtime_files:
        name = _basename(path.name)
        if path not in candidates.setdefault(name, []):
            candidates[name].append(path)
    selected: dict[str, Path] = {}
    # Resolve only declared inputs. Requested ELF paths must never gain
    # provenance by following an undeclared filesystem alias.
    def aliases_for_declared(path: Path) -> set[Path]:
        aliases = set()
        followed = set()
        current = path.absolute()
        for _ in range(64):
            aliases.add(current)
            # Bazel's sandbox can link each file separately. Preserve the
            # intermediate immutable file alias before following its final
            # symlink (e.g. gcc-lib/libgcc -> gcc-libgcc/libgcc).
            current = current.parent.resolve(strict=True) / current.name
            aliases.add(current)
            if not current.is_symlink():
                return aliases
            if current in followed:
                raise ValueError("cyclic declared runtime dependency alias")
            followed.add(current)
            target = current.readlink()
            current = target if target.is_absolute() else current.parent / target
        raise ValueError("declared runtime dependency alias chain is too long")

    declared_aliases = {path: aliases_for_declared(path)
                        for paths in candidates.values() for path in paths}
    witness = None
    canonical: dict[str, str] = {}
    canonical_variants: dict[str, list[str]] = {}
    used_canonical: set[str] = set()
    if resolution_witness is not None:
        if control is None:
            raise ValueError("native Qt resolution witness requires a control executable")
        witness = _validate_resolution_witness(resolution_witness, target)
        if hashlib.sha256(inspect(control, True)[0]).hexdigest() != witness["controlSha256"]:
            raise ValueError("native Qt witness does not bind the exact control executable")
        canonical = {library["soname"]: library["sha256"] for library in witness["libraries"]}
        canonical_variants = {library["soname"]: library["variants"] for library in witness["libraries"]}

    def resolve(name: str, owner: Path, owner_info: dict, qt_owned: bool = False) -> Path:
        basename = _basename(name)
        choices = candidates.get(basename, [])
        if not choices:
            raise ValueError("declared runtime closure is missing " + basename)
        # Prefer an exact absolute dependency or the original lookup path.  A
        # basename alone is insufficient when two Nix closures supply versions.
        preferred = []
        if qt_owned and basename in canonical:
            candidate_hashes = {path: hashlib.sha256(inspect(path)[0]).hexdigest() for path in choices}
            if sorted(set(candidate_hashes.values())) != canonical_variants[basename]:
                raise ValueError("declared canonical library variants disagree with audited custody: " + basename)
            preferred = [path for path, digest in candidate_hashes.items() if digest == canonical[basename]]
            if not preferred:
                raise ValueError("audited canonical runtime dependency is not declared: " + basename)
            used_canonical.add(basename)
        elif name.startswith("/"):
            wanted = Path(os.path.normpath(name))
            preferred = [path for path in choices if wanted in declared_aliases[path]]
            if not preferred:
                raise ValueError("exact declared runtime dependency is missing " + basename)
        else:
            for directory in owner_info["rpath"]:
                expanded = directory.replace("${ORIGIN}", str(owner.parent.absolute())).replace("$ORIGIN", str(owner.parent.absolute()))
                if not expanded.startswith("/"):
                    continue
                wanted = Path(os.path.normpath(str(Path(expanded) / name)))
                preferred = [path for path in choices if wanted in declared_aliases[path]]
                if preferred:
                    break
        options = preferred or choices
        first = options[0]
        first_payload, _ = inspect(first)
        for other in options[1:]:
            if inspect(other)[0] != first_payload:
                def package_name(value: str) -> str:
                    match = re.search(r"/nix/store/([^/]+)", value)
                    return match[1] if match else "declared-local-input"
                owners = sorted({package_name(str(path.resolve(strict=True))) for path in options})
                lookup = sorted({package_name(directory) for directory in owner_info["rpath"]})
                raise ValueError("ambiguous declared runtime dependency " + basename +
                                 " required by " + owner.name + "; candidates=" + repr(owners) +
                                 "; lookup=" + repr(lookup))
        if basename in selected and inspect(selected[basename])[0] != first_payload:
            raise ValueError("conflicting runtime dependency " + basename)
        selected[basename] = first
        return first

    backend_sources = {"libexec/omux.bin": binary, "libexec/omuxd.bin": daemon} if namespace == _RUNTIME else {
        "libexec/omux-control.bin": control}
    binary_info = inspect(binary, True)[1]
    interpreter = binary_info["interpreter"]
    if not interpreter:
        raise ValueError("backend executable needs a declared ELF loader")
    loader_name = _basename(interpreter)
    loader = resolve(interpreter, binary, binary_info)
    for source in backend_sources.values():
        source_info = inspect(source, True)[1]
        if not source_info["interpreter"] or _basename(source_info["interpreter"]) != loader_name:
            raise ValueError("backend executables need the same declared ELF loader")
        resolve(source_info["interpreter"], source, source_info)
    pending = [(source, namespace == _QT_RUNTIME, True) for source in backend_sources.values()]
    pending.append((loader, namespace == _QT_RUNTIME, False))
    pending.extend((source, True, False) for source in plugin_sources.values())
    seen: set[tuple[Path, bool, bool]] = set()
    while pending:
        owner, qt_owned, backend = pending.pop()
        if (owner, qt_owned, backend) in seen:
            continue
        seen.add((owner, qt_owned, backend))
        owner_info = inspect(owner, backend)[1]
        for needed in owner_info["needed"]:
            pending.append((resolve(needed, owner, owner_info, qt_owned), qt_owned, False))
    if witness is not None and used_canonical != set(canonical):
        raise ValueError("native Qt witness names a library outside the selected Qt graph")

    ca_payload = _read(ca_bundle)
    _verify_ca_bundle(ca_payload)
    files: dict[str, bytes] = {_CA_BUNDLE: ca_payload} if namespace == _RUNTIME else {}
    with tempfile.TemporaryDirectory(prefix="omux-portable-") as temporary:
        staging = Path(temporary)
        inputs = [(name, source, True) for name, source in backend_sources.items()]
        inputs += [("lib/" + name, source, False) for name, source in sorted(selected.items())]
        inputs += [(name, source, False) for name, source in sorted(plugin_sources.items())]
        for name, source, backend in inputs:
            payload, info = inspect(source, backend)
            destination = staging / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(payload)
            destination.chmod(0o755)
            # The loader itself is invoked directly and normally has neither
            # an interpreter nor a search path.  Avoid modifying its bootstrap.
            if name in plugin_sources:
                _patch(destination, info, patchelf, False, _QT_PLUGIN_RPATH)
            elif backend or source.resolve() != loader.resolve():
                _patch(destination, info, patchelf, backend)
            maximum = backend_max_bytes if backend else _MAX_FILE
            patched = _read(destination, max_bytes=maximum)
            check = elf_metadata(patched, max_bytes=maximum)
            if backend and (check["interpreter"] != _BACKEND_INTERPRETER or check["rpath"] != ["$ORIGIN/../lib"]):
                raise ValueError("patched backend has an unexpected runtime lookup")
            if not backend and check["interpreter"] not in {None, _BACKEND_INTERPRETER}:
                raise ValueError("packaged library has an external interpreter")
            if any("/" in needed or needed not in selected for needed in check["needed"]):
                raise ValueError("patched runtime dependency escapes the packaged closure")
            expected_rpath = _QT_PLUGIN_RPATH if name in plugin_sources else "$ORIGIN"
            if any(path != expected_rpath for path in check["rpath"]) and not backend:
                raise ValueError("packaged library has an external runtime lookup")
            files[namespace + "/" + name] = patched
    runtime = {"loader": namespace + "/lib/" + loader_name,
               "dependencies": [namespace + "/lib/" + name for name in sorted(selected)],
               "backendInterpreter": _BACKEND_INTERPRETER,
               "caBundle": _CA_BUNDLE,
               "launcher": _launcher_metadata(target)}
    if namespace == _RUNTIME:
        launcher = linux_launcher(loader_name, "omux.bin", channel, target=target)
        for alias in _ALIASES:
            files["bin/" + alias] = launcher
        files["bin/omuxd"] = linux_launcher(loader_name, "omuxd.bin", channel, target=target)
    else:
        files["bin/omux-control"] = linux_launcher(loader_name, "omux-control.bin", channel, target=target)
        files[_QT_CONFIG] = _QT_CONFIG_BYTES
        runtime = {"loader": runtime["loader"], "dependencies": runtime["dependencies"],
                   "control": _QT_CONTROL, "config": _QT_CONFIG,
                   "plugins": [namespace + "/" + name for name in sorted(plugin_sources)]}
        if witness is not None:
            archived = {**witness, "controlArtifact": {
                "path": _QT_CONTROL, "sha256": hashlib.sha256(files[_QT_CONTROL]).hexdigest()}}
            archived["libraries"] = [{**library, "artifact": {
                "path": namespace + "/lib/" + library["soname"],
                "sha256": hashlib.sha256(files[namespace + "/lib/" + library["soname"]]).hexdigest()}}
                for library in witness["libraries"]]
            runtime["resolutionWitness"] = archived
    return files, runtime


def assemble_linux(binary: Path, daemon: Path, runtime_files: list[Path], patchelf: Path,
                   target: str, ca_bundle: Path, control: Path | None = None,
                   qt_plugins: list[Path] | None = None,
                   resolution_witness: dict | None = None,
                   qt_runtime_files: list[Path] | None = None, *,
                   backend_max_bytes: int = _MAX_FILE, channel: str | None = None) -> tuple[dict[str, bytes], dict]:
    """Assemble separate CLI/daemon and Qt process namespaces from declared inputs."""
    backend_max_bytes = _file_limit(backend_max_bytes)
    channel_instance(channel)
    plugins = qt_plugins or []
    if (control is None and plugins) or (control is not None and not plugins):
        raise ValueError("Qt control requires a declared platform-plugin set")
    if control is None and resolution_witness is not None:
        raise ValueError("native Qt resolution witness requires a control executable")
    if control is None and qt_runtime_files is not None:
        raise ValueError("Qt runtime closure requires a control executable")
    if control is not None and not qt_runtime_files:
        raise ValueError("Qt control requires its declared runtime closure")
    files, runtime = _assemble_namespace(binary, daemon, runtime_files, patchelf, target, ca_bundle,
                                         backend_max_bytes=backend_max_bytes, channel=channel)
    if control is not None:
        qt_files, qt_runtime = _assemble_namespace(control, control, qt_runtime_files, patchelf, target, ca_bundle,
                                                   control, plugins, resolution_witness, _QT_RUNTIME, channel=channel)
        if set(qt_files) & set(files):
            raise ValueError("Qt process namespace overlaps the CLI namespace")
        files.update(qt_files)
        runtime["qt"] = qt_runtime
    return files, runtime


def verify_linux_runtime(files: dict[str, bytes], manifest: dict) -> None:
    """Verify actual runtime-only payloads, including every confined ELF edge."""
    target = manifest.get("target")
    runtime = manifest.get("runtime")
    channel = manifest.get("channel")
    channel_instance(channel)
    if target not in _MACHINES or not isinstance(runtime, dict):
        raise ValueError("portable runtime requires a Linux target and runtime metadata")
    launcher = runtime.get("launcher")
    if (not isinstance(launcher, dict) or set(launcher) != {"abi", "target", "templateSha256"}
            or type(launcher.get("abi")) is not int
            or not isinstance(launcher.get("target"), str)
            or not isinstance(launcher.get("templateSha256"), str)
            or launcher != _launcher_metadata(target)):
        raise ValueError("portable runtime launcher ABI disagrees with the declared native template")
    dependencies = runtime.get("dependencies")
    loader = runtime.get("loader")
    if (not isinstance(dependencies, list) or not dependencies or len(dependencies) > _MAX_HEADERS
            or any(not isinstance(name, str) for name in dependencies)
            or dependencies != sorted(set(dependencies)) or loader not in dependencies
            or runtime.get("backendInterpreter") != _BACKEND_INTERPRETER or runtime.get("caBundle") != _CA_BUNDLE):
        raise ValueError("invalid portable runtime dependency metadata")
    for name in dependencies:
        if name != _RUNTIME + "/lib/" + _basename(name):
            raise ValueError("portable dependency is outside the isolated library directory")
    backends = {_RUNTIME + "/libexec/omux.bin", _RUNTIME + "/libexec/omuxd.bin"}
    qt = runtime.get("qt")
    plugins: list[str] = []
    qt_dependencies: list[str] = []
    qt_files: set[str] = set()
    if qt is not None:
        if not isinstance(qt, dict) or set(qt) not in (
                {"loader", "dependencies", "control", "config", "plugins"},
                {"loader", "dependencies", "control", "config", "plugins", "resolutionWitness"}):
            raise ValueError("invalid Qt runtime metadata")
        qt_dependencies = qt["dependencies"]
        if (not isinstance(qt_dependencies, list) or not 0 < len(qt_dependencies) <= _MAX_HEADERS
                or any(not isinstance(name, str) for name in qt_dependencies)
                or qt_dependencies != sorted(set(qt_dependencies)) or qt["loader"] not in qt_dependencies):
            raise ValueError("invalid isolated Qt dependency metadata")
        for name in qt_dependencies:
            if name != _QT_RUNTIME + "/lib/" + _basename(name):
                raise ValueError("Qt dependency is outside its isolated library directory")
        plugins = qt.get("plugins")
        if (qt["control"] != _QT_CONTROL or qt["config"] != _QT_CONFIG
                or not isinstance(plugins, list) or not 0 < len(plugins) <= 128
                or any(not isinstance(name, str) for name in plugins)
                or plugins != sorted(set(plugins))):
            raise ValueError("invalid Qt control or platform-plugin metadata")
        for name in plugins:
            if name != _QT_PREFIX + _basename(name) or not name.endswith(".so"):
                raise ValueError("Qt platform plugin escapes the isolated runtime")
        qt_files = {"bin/omux-control", _QT_CONTROL, _QT_CONFIG, *plugins, *qt_dependencies}
    core = {*("bin/" + name for name in (*_ALIASES, "omuxd"))}
    if set(files) != core | backends | set(dependencies) | {_CA_BUNDLE} | qt_files:
        raise ValueError("archive has missing or undeclared portable runtime files")
    if qt is not None:
        if files[_QT_CONFIG] != _QT_CONFIG_BYTES or files["bin/omux-control"] != linux_launcher(
                _basename(qt["loader"]), "omux-control.bin", channel, target=target):
            raise ValueError("Qt control has an external plugin or configuration lookup")
        if "resolutionWitness" in qt:
            archived = qt["resolutionWitness"]
            if (not isinstance(archived, dict) or set(archived) != {
                    "schemaVersion", "scope", "target", "controlSha256", "libraries", "controlArtifact"}
                    or not isinstance(archived["libraries"], list)):
                raise ValueError("invalid archived Qt resolution witness")
            raw = {key: value for key, value in archived.items() if key not in {"controlArtifact", "libraries"}}
            raw["libraries"] = []
            for library in archived["libraries"]:
                if not isinstance(library, dict) or set(library) != {"soname", "sha256", "variants", "artifact"}:
                    raise ValueError("invalid archived canonical library witness")
                raw["libraries"].append({"soname": library["soname"], "sha256": library["sha256"],
                                         "variants": library["variants"]})
            if raw != _validate_resolution_witness(raw, target):
                raise ValueError("archived Qt resolution witness is not canonical")
            control_artifact = {"path": _QT_CONTROL, "sha256": hashlib.sha256(files[_QT_CONTROL]).hexdigest()}
            if archived["controlArtifact"] != control_artifact:
                raise ValueError("Qt resolution witness does not bind its packaged control")
            for library in archived["libraries"]:
                path = _QT_RUNTIME + "/lib/" + library["soname"]
                if path not in qt_dependencies or library["artifact"] != {
                        "path": path, "sha256": hashlib.sha256(files[path]).hexdigest()}:
                    raise ValueError("Qt resolution witness does not bind its packaged canonical library")
            # Raw hashes identify the audited inputs; only the artifact hashes
            # can be recomputed after patching.  This is not native-audit replay.
    _verify_ca_bundle(files[_CA_BUNDLE])
    graphs = [(backends, dependencies, [])]
    if qt is not None:
        graphs.append(({_QT_CONTROL}, qt_dependencies, plugins))
    for graph_backends, graph_dependencies, graph_plugins in graphs:
        names = {_basename(name) for name in graph_dependencies}
        for name in sorted(graph_backends | set(graph_dependencies) | set(graph_plugins)):
            metadata = elf_metadata(files[name])
            if metadata["machine"] != _MACHINES[target]:
                raise ValueError("portable runtime ELF machine disagrees with its target")
            if any("/" in needed or needed not in names for needed in metadata["needed"]):
                raise ValueError("portable ELF dependency is outside its process closure")
            if name in graph_backends:
                if metadata["interpreter"] != _BACKEND_INTERPRETER or metadata["rpath"] != ["$ORIGIN/../lib"]:
                    raise ValueError("portable backend has an external runtime lookup")
            elif metadata["interpreter"] not in {None, _BACKEND_INTERPRETER} or any(
                    path != (_QT_PLUGIN_RPATH if name in graph_plugins else "$ORIGIN") for path in metadata["rpath"]):
                raise ValueError("portable library has an external runtime lookup")
    cli = linux_launcher(_basename(loader), "omux.bin", channel, target=target)
    if any(files["bin/" + name] != cli for name in _ALIASES):
        raise ValueError("portable CLI aliases do not match the confined launcher")
    if files["bin/omuxd"] != linux_launcher(_basename(loader), "omuxd.bin", channel, target=target):
        raise ValueError("portable daemon does not match the confined launcher")


def verify_linux(files: dict[str, bytes], manifest: dict) -> None:
    """Retain full-archive metadata requirements and validate its actual runtime."""
    documents = {"share/omux/reference.json", "share/omux/services/omux.service.in",
                 "share/omux/services/dev.xoxd.omux.plist.in", "release-manifest.json", "SHA256SUMS"}
    if not documents <= set(files):
        raise ValueError("archive has missing or undeclared portable runtime files")
    verify_linux_runtime({name: value for name, value in files.items() if name not in documents}, manifest)
