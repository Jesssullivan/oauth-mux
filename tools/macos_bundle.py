"""Relocate and ad-hoc sign a development app using declared Bazel inputs."""

from collections import deque
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import plistlib
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile

from macho import parse_macho


SDK_SUFFIX = "/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
DEVELOPMENT_NOTICE = (
    "Assembly fixture: runtime relocation and signing were not invoked. "
    "This fixture does not prove a runnable macOS application.\n"
)
PORTABLE_NOTICE = (
    "Ad-hoc signed development bundle. Developer ID trust, notarization, Apple "
    "platform verification and live macOS service checks are separate gates.\n"
)


def _immutable_path(value):
    return (
        isinstance(value, str)
        and value.startswith("/nix/store/")
        and ".." not in value.split("/")
        and "\n" not in value
        and "\r" not in value
    )


def validate_custody(custody):
    if not isinstance(custody, dict):
        raise ValueError("Apple toolchain custody must be an object")
    if custody.get("available") is not True or custody.get("system") not in (
        "aarch64-darwin", "x86_64-darwin"
    ):
        raise ValueError("Apple SDK custody requires a declared Darwin execution platform")
    apple = custody.get("apple", {})
    if not isinstance(apple, dict):
        raise ValueError("Apple toolchain inputs must be an object")
    sdk = apple.get("sdk")
    swiftc = apple.get("swiftc")
    if not _immutable_path(sdk) or not sdk.endswith(SDK_SUFFIX):
        raise ValueError("Apple SDK custody requires the immutable flake SDK path")
    if not _immutable_path(swiftc):
        raise ValueError("Swift compiler custody requires an immutable flake path")
    if not all(isinstance(apple.get(key), str) and apple[key] for key in ("sdk_version", "swift_version")):
        raise ValueError("Apple SDK and Swift versions must be recorded")
    developer_dir = sdk[:-len(SDK_SUFFIX)]
    if custody.get("developer_dir") != developer_dir:
        raise ValueError("SDK custody developer directory disagrees with SDK input")
    closure = custody.get("store_paths")
    if not isinstance(closure, list) or not all(_immutable_path(path) for path in closure):
        raise ValueError("Apple custody must record its immutable transitive closure")
    swift_root = "/".join(swiftc.split("/")[:4])
    if developer_dir not in closure or swift_root not in closure:
        raise ValueError("Apple SDK or Swift compiler is missing from custody closure")
    tools = custody.get("tools", {})
    if not isinstance(tools, dict):
        raise ValueError("Darwin packaging tool custody must be an object")
    for name in ("otool", "install_name_tool", "rcodesign"):
        path = tools.get(name)
        if not _immutable_path(path) or "/".join(path.split("/")[:4]) not in closure:
            raise ValueError("Darwin packaging tool must belong to the declared Nix closure")


@dataclass(frozen=True)
class RelocationEntry:
    source: str
    destination: str
    changes: tuple[tuple[str, str], ...]
    remove_rpaths: tuple[str, ...]
    install_id: str | None


@dataclass(frozen=True)
class RelocationPlan:
    architecture: str
    entries: tuple[RelocationEntry, ...]
    system_dependencies: tuple[str, ...]


def _system_path(path):
    normalized = posixpath.normpath(path)
    return normalized if normalized.startswith(("/System/Library/", "/usr/lib/")) else None


def _read_binary(path):
    file = Path(path)
    if file.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("Mach-O input exceeds the bounded package inspection size")
    return file.read_bytes()


def _canonical(path):
    return str(Path(path).resolve(strict=True))


def _expand_path(path, loader, executable):
    for prefix, base in (("@loader_path/", posixpath.dirname(loader)), ("@executable_path/", posixpath.dirname(executable))):
        if path == prefix[:-1]:
            return base
        if path.startswith(prefix):
            return posixpath.normpath(posixpath.join(base, path[len(prefix):]))
    if path.startswith("/"):
        return posixpath.normpath(path)
    raise ValueError("Unsupported relative Mach-O search path")


def plan_relocation(roots, custody, architecture, *, read_binary=_read_binary, canonicalize=_canonical, sdk_file_exists=lambda path: Path(path).is_file()):
    """Resolve actual load commands into a closed, deterministic relocation plan.

    Reader/canonicalizer injection permits byte-fixture tests on Linux. Runtime
    inputs outside the explicitly declared Nix closure are never copied. Apple
    system paths remain system paths; the SDK itself is never redistributed.
    """
    validate_custody(custody)
    if architecture not in ("arm64", "x86_64") or set(roots) != {"Omux", "omux", "omuxd"}:
        raise ValueError("Relocation requires the three declared executables and supported target architecture")
    closure = set(custody["store_paths"])
    sdk_root = custody["developer_dir"]
    root_paths = {name: canonicalize(str(path)) for name, path in roots.items()}
    root_sources = set(root_paths.values())
    metadata = {}
    entries = {}
    routes = {}
    library_names = {}
    retained = set()
    contexts = set()
    queue = deque()

    def inspect(source, required, library):
        if source not in metadata:
            metadata[source] = parse_macho(read_binary(source))
        slices = metadata[source]
        if not required.issubset({item.architecture for item in slices}):
            raise ValueError("Mach-O dependency does not contain all required architectures")
        for item in slices:
            if item.minimum_os is None or item.minimum_os > (14, 0, 0):
                raise ValueError("Mach-O input lacks compatible macOS 14 deployment metadata")
            if item.filetype != (6 if library else 2):
                raise ValueError("Mach-O input has an incompatible executable/dylib type")
            if library and item.install_id is None:
                raise ValueError("A bundled dylib must declare an install ID")
        if len({item.rpaths for item in slices}) > 1:
            raise ValueError("Universal slices with different search paths require architecture-specific relocation")
        return slices

    def native_candidate(candidate):
        try:
            source = canonicalize(candidate)
        except OSError:
            return None
        if not _immutable_path(source) or "/".join(source.split("/")[:4]) not in closure:
            if source in root_sources:
                raise ValueError("Executables cannot serve as runtime dylib dependencies")
            raise ValueError("Mach-O dependency lies outside the declared Nix closure")
        if source == sdk_root or source.startswith(sdk_root + "/"):
            raise ValueError("Apple SDK artifacts cannot be redistributed as runtime libraries")
        if ".framework/" in source:
            raise ValueError("Third-party framework resource bundling requires a separate proven recipe")
        try:
            read_binary(source)
        except OSError:
            return None
        return source

    def resolve(dependency, loader, executable, search_paths):
        system = _system_path(dependency) if dependency.startswith("/") else None
        if system:
            return (None, system)
        if dependency.startswith("@rpath/"):
            suffix = dependency[len("@rpath/"):]
            candidates = [posixpath.normpath(posixpath.join(base, suffix)) for base in search_paths]
        else:
            candidates = [_expand_path(dependency, loader, executable)]
        for candidate in candidates:
            system = _system_path(candidate)
            if system:
                return (None, system)
            source = native_candidate(candidate)
            if source is not None:
                return (source, None)
        # Swift's platform runtime may live in the dyld cache rather than as a
        # physical file. Only a declared SDK stub establishes this fallback.
        if dependency.startswith("@rpath/libswift") and dependency.endswith(".dylib") and "/" not in dependency[len("@rpath/"):]:
            basename = dependency[len("@rpath/"):]
            sdk_stub = custody["apple"]["sdk"] + "/usr/lib/swift/" + basename[:-len(".dylib")] + ".tbd"
            if sdk_file_exists(sdk_stub):
                return (None, "/usr/lib/swift/" + basename)
        raise ValueError("A Mach-O runtime dependency cannot be resolved from declared inputs")

    for name, source in sorted(root_paths.items()):
        for item in inspect(source, {architecture}, False):
            queue.append((source, "Contents/MacOS/" + name, source, (), item.architecture, False))
    while queue:
        source, destination, executable, inherited, current_architecture, library = queue.popleft()
        slices = inspect(source, {current_architecture}, library)
        item = next(item for item in slices if item.architecture == current_architecture)
        search_paths = tuple(dict.fromkeys([_expand_path(path, source, executable) for path in item.rpaths] + list(inherited)))
        context = (source, destination, executable, search_paths, current_architecture)
        if context in contexts:
            continue
        contexts.add(context)
        if len(contexts) > 4096 or len(metadata) > 512:
            raise ValueError("Mach-O dependency graph exceeds bounded packaging limits")
        changes = {}
        for dependency in item.dependencies:
            dependency_source, system = resolve(dependency, source, executable, search_paths)
            if dependency_source:
                basename = hashlib.sha256(dependency_source.encode("utf-8")).hexdigest()[:16] + "-" + posixpath.basename(dependency_source)
                if len(basename.encode("utf-8")) > 240:
                    raise ValueError("Bundled Mach-O dependency filename is too long")
                previous = library_names.get(basename)
                if previous is not None and previous != dependency_source:
                    raise ValueError("Bundled Mach-O dependency filename collision")
                library_names[basename] = dependency_source
                replacement = "@loader_path/" + ("../Frameworks/" if not library else "") + basename
                queue.append((dependency_source, "Contents/Frameworks/" + basename, executable, search_paths, item.architecture, True))
            else:
                replacement = system
                retained.add(system)
            changes[dependency] = replacement
        previous_entry = entries.get(destination)
        if destination in routes:
            for original, replacement in routes[destination].items():
                if original in changes and changes[original] != replacement:
                    raise ValueError("Universal slices or loader contexts disagree on a dependency route")
                changes[original] = replacement
        routes[destination] = changes
        entry = RelocationEntry(
            source, destination,
            tuple(sorted((original, replacement) for original, replacement in changes.items() if original != replacement)),
            tuple(sorted(set(item.rpaths) | (set(previous_entry.remove_rpaths) if previous_entry else set()))),
            "@rpath/" + posixpath.basename(destination) if library else None,
        )
        entries[destination] = entry
    return RelocationPlan(architecture, tuple(entries[path] for path in sorted(entries)), tuple(sorted(retained)))


def _run_tool(tool, arguments, custody):
    # An explicit environment prevents RCODESIGN_* configuration, user signing
    # identities and inherited developer-tool selection from affecting actions.
    result = subprocess.run(
        [tool, *arguments], check=False, capture_output=True, text=True, timeout=60,
        env={"PATH": custody.get("tool_path", ""), "TZ": "UTC", "LC_ALL": "C", "ZERO_AR_DATE": "1"},
    )
    if result.returncode != 0:
        raise ValueError("Declared Darwin packaging tool failed: " + Path(tool).name + ": " + result.stderr[-4096:])
    return result.stdout


def relocate_and_sign(output, plan, custody):
    root = Path(output)
    tools = custody["tools"]
    for entry in plan.entries:
        destination = root / entry.destination
        if entry.destination.startswith("Contents/Frameworks/"):
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(entry.source, destination)
            os.chmod(destination, 0o755)
        _run_tool(tools["otool"], ["-L", str(destination)], custody)
        arguments = []
        for original, replacement in entry.changes:
            arguments.extend(["-change", original, replacement])
        for path in entry.remove_rpaths:
            arguments.extend(["-delete_rpath", path])
        if entry.install_id:
            arguments.extend(["-id", entry.install_id])
        if arguments:
            _run_tool(tools["install_name_tool"], [*arguments, str(destination)], custody)
    for entry in plan.entries:
        file = root / entry.destination
        slices = parse_macho(file.read_bytes())
        for item in slices:
            if item.rpaths or (entry.install_id is not None and item.install_id != entry.install_id):
                raise ValueError("Relocated Mach-O retains an unexpected search path or install ID")
            for dependency in item.dependencies:
                if dependency.startswith("@loader_path/"):
                    resolved = file.parent.joinpath(dependency[len("@loader_path/"):]).resolve(strict=True)
                    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
                        raise ValueError("Relocated Mach-O dependency escaped the application bundle")
                elif not _system_path(dependency):
                    raise ValueError("Relocated Mach-O retains an external non-system dependency")
        _run_tool(tools["otool"], ["-L", str(file)], custody)
    resources = root / "Contents" / "Resources"
    (resources / "development-bundle.txt").write_text(PORTABLE_NOTICE, encoding="utf-8")
    (resources / "runtime-relocation.json").write_text(json.dumps({
        "architecture": plan.architecture,
        "entries": [dict(asdict(entry), source=("declared-executable:" + posixpath.basename(entry.destination) if entry.destination.startswith("Contents/MacOS/") else entry.source)) for entry in plan.entries],
        "system_dependencies": plan.system_dependencies,
        "signing": "ad-hoc",
        "signature_check": "embedded-structure-only",
        "apple_platform_acceptance": "unrun",
    }, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="omux-sign-config-") as temporary:
        config = Path(temporary) / "empty.toml"
        config.write_text("", encoding="utf-8")
        _run_tool(tools["rcodesign"], ["--config-file", str(config), "sign", "--timestamp-url", "none", str(root)], custody)
    seal = root / "Contents" / "_CodeSignature" / "CodeResources"
    if not seal.is_file():
        raise ValueError("Ad-hoc application signing did not emit its resource seal")
    with seal.open("rb") as handle:
        if not isinstance(plistlib.load(handle), dict):
            raise ValueError("Ad-hoc application signing emitted an invalid resource seal")
    for entry in plan.entries:
        if any(item.code_signature is None for item in parse_macho((root / entry.destination).read_bytes())):
            raise ValueError("Ad-hoc application signing omitted a Mach-O embedded signature")
    for directory, _, files in os.walk(root):
        for name in files:
            os.utime(Path(directory) / name, (0, 0))


def archive_application(source, output):
    """Package the signed app TreeArtifact without host timestamps or paths."""
    root = Path(source)
    if root.suffix != ".app" or not root.is_dir():
        raise ValueError("macOS archive requires a declared application directory")
    if not (root / "Contents" / "_CodeSignature" / "CodeResources").is_file() or not (root / "Contents" / "Resources" / "runtime-relocation.json").is_file():
        raise ValueError("macOS archive requires the relocated and resource-sealed application artifact")
    files = sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix())
    for path in files:
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError("macOS archive cannot contain undeclared symlinks or special files")
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            if path.is_dir():
                continue
            destination = root.name + "/" + path.relative_to(root).as_posix()
            info = zipfile.ZipInfo(destination, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (stat.S_IFREG | stat.S_IMODE(path.stat().st_mode)) << 16
            with path.open("rb") as reader, archive.open(info, "w") as writer:
                shutil.copyfileobj(reader, writer)


def product_version(path):
    source = Path(path).read_text(encoding="utf-8")
    match = re.search(r'^pub const version\s*=\s*"([^"\r\n]+)"\s*;', source, re.MULTILINE)
    if not match:
        raise ValueError("Product version is absent from the declared source")
    version = match.group(1)
    numeric = re.fullmatch(r"(\d+\.\d+\.\d+)(?:[-+][A-Za-z0-9.+-]+)?", version)
    if not numeric:
        raise ValueError("Product version must be a three-part semantic version")
    return version, numeric.group(1)


def assemble(output, binary, cli, daemon, info, helper, product, custody):
    """Validate first, then emit the complete declared directory artifact."""
    version, numeric = product_version(product)
    with open(info, "rb") as handle:
        manifest = plistlib.load(handle)
    with open(helper, "rb") as handle:
        agent = plistlib.load(handle)
    custody_bytes = Path(custody).read_bytes()
    validate_custody(json.loads(custody_bytes))
    if manifest.get("LSMinimumSystemVersion") != "14.0":
        raise ValueError("The SwiftUI client deployment target must be macOS 14.0")
    if agent.get("BundleProgram") != "Contents/MacOS/omux":
        raise ValueError("Launch agent must invoke the bundled omux executable")
    if agent.get("ProgramArguments") != ["omux", "daemon"]:
        raise ValueError("Launch agent must use the declared omux daemon command")
    if agent.get("AssociatedBundleIdentifiers") != [manifest.get("CFBundleIdentifier")]:
        raise ValueError("Launch agent must belong to the controls bundle")
    if Path(helper).name != agent.get("Label", "") + ".plist":
        raise ValueError("Launch agent filename must match its service label")
    for source in (binary, cli, daemon):
        if not Path(source).is_file():
            raise ValueError("A declared bundle executable is missing")
    root = Path(output)
    macos = root / "Contents" / "MacOS"
    agents = root / "Contents" / "Library" / "LaunchAgents"
    resources = root / "Contents" / "Resources"
    for directory in (macos, agents, resources):
        directory.mkdir(parents=True, exist_ok=True)
    manifest["CFBundleShortVersionString"] = numeric
    manifest["OmuxProductVersion"] = version
    manifest["CFBundleExecutable"] = "Omux"
    with open(root / "Contents" / "Info.plist", "wb") as handle:
        plistlib.dump(manifest, handle, fmt=plistlib.FMT_XML, sort_keys=True)
    for name, source in (("Omux", binary), ("omux", cli), ("omuxd", daemon)):
        shutil.copyfile(source, macos / name)
        os.chmod(macos / name, 0o755)
    with open(agents / Path(helper).name, "wb") as handle:
        plistlib.dump(agent, handle, fmt=plistlib.FMT_XML, sort_keys=True)
    (resources / "apple-toolchain-custody.json").write_bytes(custody_bytes)
    (resources / "development-bundle.txt").write_text(DEVELOPMENT_NOTICE, encoding="utf-8")
    for directory, _, files in os.walk(root):
        for name in files:
            os.utime(Path(directory) / name, (0, 0))


def main(arguments):
    if len(arguments) == 3 and arguments[0] == "--archive":
        archive_application(*arguments[1:])
        return
    if len(arguments) != 9:
        raise ValueError("Bundle assembly requires eight declared paths and target architecture")
    paths, architecture = arguments[:8], arguments[8]
    with open(paths[7], "rb") as handle:
        custody = json.load(handle)
    plan = plan_relocation(dict(zip(("Omux", "omux", "omuxd"), paths[1:4])), custody, architecture)
    assemble(*paths)
    relocate_and_sign(paths[0], plan, custody)


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except (OSError, ValueError, plistlib.InvalidFileException) as error:
        # Inputs are source/toolchain paths only, never account material.
        raise SystemExit("Omux development bundle assembly failed: " + str(error)) from error
