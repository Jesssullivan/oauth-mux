#!/usr/bin/env python3
"""Source/test oracle for the v0.2 POSIX archive/install contract.

This module is not an end-user installer. The shipped implementation may not
assume Python is present on stock macOS.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import gzip
import hashlib
import io
import json
import os
import re
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable, Iterable


PROFILE_ID = "v0.2-posix-install-contract"
PROVENANCE_PROFILE_ID = "v0.2-independent-zig-rebuild-provenance"
EXACT_REBUILD_GRAPH = "build.v02-exact-rebuild.zig"
ROOT_SENTINEL = ".omux-v02-candidate-root"
ROOT_SENTINEL_CONTENT = b"omux-v0.2-source-contract-v1\n"
EXPECTED_MEMBERS = ("omux", "oauth-mux")
EXPECTED_PRODUCT_AUTHORITY = {
    "package_name": "oauth-mux",
    "primary_executable": "omux",
    "compatibility_executable": "oauth-mux",
    "storage_namespace": "oauth-mux",
    "members": list(EXPECTED_MEMBERS),
}
MAX_MEMBER_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_BYTES = (2 * MAX_MEMBER_BYTES) + (2 * 1024 * 1024)
MAX_METADATA_BYTES = 1024 * 1024
MAX_SOURCE_ARCHIVE_BYTES = 256 * 1024 * 1024
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
PRIVATE_POINTER = re.compile(r"^\.current-[1-9][0-9]*-[0-9a-f]{16}$")
HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")
MAX_USIZE = (1 << (struct.calcsize("P") * 8)) - 1
Hook = Callable[[str], None]


class ContractError(RuntimeError):
    pass


class InjectedFailure(ContractError):
    pass


@dataclass(frozen=True)
class ExactToolAuthority:
    python: Path
    git: Path
    zig: Path


@dataclass
class PinnedMember:
    fd: int
    identity: os.stat_result
    digest: str
    size: int


@dataclass
class PinnedGeneration:
    fd: int
    identity: os.stat_result
    members: dict[str, PinnedMember]

    def close(self) -> None:
        for member in self.members.values():
            os.close(member.fd)
        os.close(self.fd)


def fail(message: str) -> None:
    raise ContractError(message)


def parse_zig_semver_number(value: str, label: str) -> int:
    if not value or any(character < "0" or character > "9" for character in value):
        fail(f"candidate version has an invalid {label}")
    if len(value) > 1 and value[0] == "0":
        fail(f"candidate version has a leading-zero {label}")
    parsed = int(value)
    if parsed > MAX_USIZE:
        fail(f"candidate version {label} overflows Zig usize")
    return parsed


def validate_semver_identifiers(value: str, label: str, numeric_rules: bool) -> None:
    for identifier in value.split("."):
        if not identifier:
            fail(f"candidate version has an empty {label} identifier")
        if any(
            not ("0" <= character <= "9" or "A" <= character <= "Z" or "a" <= character <= "z" or character == "-")
            for character in identifier
        ):
            fail(f"candidate version has an invalid {label} identifier")
        if numeric_rules and all("0" <= character <= "9" for character in identifier):
            parse_zig_semver_number(identifier, f"{label} identifier")


def validate_v02_prerelease(version: object) -> str:
    """Match Zig 0.14.1 std.SemanticVersion.parse plus the v0.2 prerelease gate."""
    if not isinstance(version, str):
        fail("candidate version must be a string")
    extra_indexes = [index for index in (version.find("-"), version.find("+")) if index >= 0]
    extra_index = min(extra_indexes) if extra_indexes else None
    required = version if extra_index is None else version[:extra_index]
    required_parts = required.split(".")
    if len(required_parts) != 3:
        fail("candidate version must contain major, minor, and patch")
    major, minor, _patch = (
        parse_zig_semver_number(value, label)
        for value, label in zip(required_parts, ("major", "minor", "patch"), strict=True)
    )

    prerelease: str | None = None
    build: str | None = None
    if extra_index is not None:
        extra = version[extra_index:]
        if extra[0] == "-":
            build_index = extra.find("+")
            if build_index >= 0:
                prerelease = extra[1:build_index]
                build = extra[build_index + 1:]
            else:
                prerelease = extra[1:]
        else:
            build = extra[1:]
    if prerelease is not None:
        validate_semver_identifiers(prerelease, "prerelease", numeric_rules=True)
    if build is not None:
        validate_semver_identifiers(build, "build", numeric_rules=False)
    if major != 0 or minor != 2 or prerelease is None:
        fail("candidate version must be a v0.2 prerelease")
    return version


def validate_closure_tool(path: Path, executable_name: str) -> Path:
    if not path.is_absolute() or path.name != executable_name:
        fail(f"closure-bound {executable_name} path is invalid")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        fail(f"closure-bound {executable_name} is unavailable: {exc}")
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        fail(f"closure-bound {executable_name} is not executable")
    if Path("/nix/store") not in resolved.parents:
        fail(f"closure-bound {executable_name} must resolve inside the Nix store")
    return path


def validate_exact_tool_authority(authority: ExactToolAuthority) -> ExactToolAuthority:
    python_path = validate_closure_tool(authority.python, "python3")
    git_path = validate_closure_tool(authority.git, "git")
    zig_path = validate_closure_tool(authority.zig, "zig")
    try:
        running_python = Path(sys.executable).resolve(strict=True)
    except OSError as exc:
        fail(f"cannot resolve the exact promoter Python runtime: {exc}")
    if running_python != python_path.resolve(strict=True):
        fail("exact promotion is not running under its closure-bound Python")
    return ExactToolAuthority(python=python_path, git=git_path, zig=zig_path)


def git_invocation(
    tools: ExactToolAuthority,
    repo: Path,
    *arguments: str,
) -> tuple[list[str], dict[str, str]]:
    git_path = tools.git
    repo_path = repo.resolve(strict=True)
    environment = {
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_COUNT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_DISCOVERY_ACROSS_FILESYSTEM": "0",
        "GIT_LITERAL_PATHSPECS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PROTOCOL_FROM_USER": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ASKPASS": "/usr/bin/false",
        "GIT_SSH_COMMAND": "/usr/bin/false",
        "HOME": "/nonexistent-omux-source-contract-home",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.environ.get("PATH", ""),
        "SSH_ASKPASS": "/usr/bin/false",
        "XDG_CONFIG_HOME": "/nonexistent-omux-source-contract-config",
    }
    command = [
        str(git_path),
        "--no-optional-locks",
        "--no-replace-objects",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.untrackedCache=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        f"core.worktree={repo_path}",
        "-C",
        str(repo_path),
        *arguments,
    ]
    return command, environment


def run_git(tools: ExactToolAuthority, repo: Path, *arguments: str) -> str:
    command, environment = git_invocation(tools, repo, *arguments)
    try:
        result = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=15,
            env=environment,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        detail = exc.stderr.strip() if isinstance(exc, subprocess.CalledProcessError) and exc.stderr else str(exc)
        fail(f"cannot prove exact candidate Git identity: {detail}")
    return result.stdout.strip()


def run_git_bytes(tools: ExactToolAuthority, repo: Path, *arguments: str) -> bytes:
    command, environment = git_invocation(tools, repo, *arguments)
    try:
        result = subprocess.run(
            command,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            env=environment,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        detail = (
            exc.stderr.decode("utf-8", errors="replace").strip()
            if isinstance(exc, subprocess.CalledProcessError) and exc.stderr
            else str(exc)
        )
        fail(f"cannot prove exact candidate Git identity: {detail}")
    if len(result.stdout) > MAX_SOURCE_ARCHIVE_BYTES:
        fail("exact candidate Git source archive exceeds the source-contract limit")
    return result.stdout


def verify_exact_git_source(
    tools: ExactToolAuthority,
    authority_path: Path,
    source_commit: str,
    source_tree: str,
) -> Path:
    if not HEX_40.fullmatch(source_commit) or not HEX_40.fullmatch(source_tree):
        fail("exact source commit and tree must be lowercase 40-hex Git object ids")
    authority = authority_path.resolve(strict=True)
    repo_root = Path(run_git(tools, authority.parent, "rev-parse", "--show-toplevel")).resolve(strict=True)
    try:
        authority_relative = authority.relative_to(repo_root)
    except ValueError:
        fail("release authority is outside the candidate source repository")
    run_git(tools, repo_root, "ls-files", "--error-unmatch", "--", authority_relative.as_posix())
    for required_path in (EXACT_REBUILD_GRAPH, "src/main.zig"):
        run_git(tools, repo_root, "ls-files", "--error-unmatch", "--", required_path)

    git_common_dir_raw = run_git(tools, repo_root, "rev-parse", "--git-common-dir")
    git_common_dir = Path(git_common_dir_raw)
    if not git_common_dir.is_absolute():
        git_common_dir = repo_root / git_common_dir
    git_common_dir = git_common_dir.resolve(strict=True)
    for alternate_name in ("alternates", "http-alternates"):
        alternate_path = git_common_dir / "objects" / "info" / alternate_name
        if alternate_path.exists() and alternate_path.read_bytes().strip():
            fail("exact candidate source repository may not use object alternates")

    resolved_commit = run_git(tools, repo_root, "rev-parse", "--verify", f"{source_commit}^{{commit}}")
    resolved_tree = run_git(tools, repo_root, "rev-parse", "--verify", f"{source_tree}^{{tree}}")
    head_commit = run_git(tools, repo_root, "rev-parse", "--verify", "HEAD^{commit}")
    head_tree = run_git(tools, repo_root, "rev-parse", "--verify", "HEAD^{tree}")
    commit_tree = run_git(tools, repo_root, "rev-parse", "--verify", f"{source_commit}^{{tree}}")
    if resolved_commit != source_commit or source_commit != head_commit:
        fail("exact candidate source commit must be the repository HEAD commit object")
    if resolved_tree != source_tree or source_tree != head_tree or source_tree != commit_tree:
        fail("exact candidate source tree must be the HEAD commit tree object")
    if run_git(
        tools,
        repo_root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--ignore-submodules=none",
    ):
        fail("exact candidate source requires a clean index and worktree")
    return repo_root


def extract_exact_source_tree(archive: bytes, destination: Path) -> None:
    seen: set[str] = set()
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:", errorlevel=2) as source:
            for member in source.getmembers():
                path = PurePosixPath(member.name)
                if (
                    path.is_absolute()
                    or not path.parts
                    or any(part in ("", ".", "..") for part in path.parts)
                    or "\\" in member.name
                    or member.name in seen
                ):
                    fail("exact candidate Git archive contains an unsafe or duplicate path")
                seen.add(member.name)
                target = destination.joinpath(*path.parts)
                if member.isdir():
                    target.mkdir(mode=0o755, parents=True, exist_ok=True)
                    continue
                if not member.isreg() or member.size < 0:
                    fail("exact candidate Git archive contains a non-regular source member")
                total += member.size
                if total > MAX_SOURCE_ARCHIVE_BYTES:
                    fail("exact candidate Git tree exceeds the source-contract limit")
                target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                extracted = source.extractfile(member)
                if extracted is None:
                    fail("exact candidate Git archive member has no payload")
                with extracted:
                    payload = extracted.read(member.size + 1)
                if len(payload) != member.size:
                    fail("exact candidate Git archive member is truncated")
                target.write_bytes(payload)
                os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)
    except (OSError, tarfile.TarError, EOFError) as exc:
        fail(f"cannot materialize exact candidate Git tree: {exc}")


def exact_rebuild_evidence(
    tools: ExactToolAuthority,
    authority_path: Path,
    source_commit: str,
    source_tree: str,
    version: str,
    build_id: str,
    expected_payload: bytes,
) -> dict[str, object]:
    tools = validate_exact_tool_authority(tools)
    repo_root = verify_exact_git_source(tools, authority_path, source_commit, source_tree)
    zig_path = tools.zig
    source_archive = run_git_bytes(tools, repo_root, "archive", "--format=tar", source_commit)

    with tempfile.TemporaryDirectory(prefix="omux-v02-exact-rebuild.") as temporary:
        temporary_root = Path(temporary)
        snapshot = temporary_root / "source"
        snapshot.mkdir(mode=0o700)
        extract_exact_source_tree(source_archive, snapshot)
        graph_path = snapshot / EXACT_REBUILD_GRAPH
        if not graph_path.is_file() or graph_path.is_symlink():
            fail("exact candidate source snapshot is missing the pinned rebuild graph")
        prefix = temporary_root / "prefix"
        local_cache = temporary_root / "zig-cache"
        global_cache = temporary_root / "zig-global-cache"
        environment = {
            "HOME": str(temporary_root / "home"),
            "LANG": "C",
            "LC_ALL": "C",
            "NO_COLOR": "1",
            "TMPDIR": str(temporary_root),
        }
        nix_path_entries = []
        for entry in os.environ.get("PATH", "").split(os.pathsep):
            if entry and (
                entry.startswith("/nix/store/")
                or entry in ("/usr/bin", "/bin", "/usr/sbin", "/sbin")
            ):
                nix_path_entries.append(entry)
        environment["PATH"] = os.pathsep.join(
            dict.fromkeys([str(zig_path.parent), *nix_path_entries, "/usr/bin", "/bin"])
        )
        for name in (
            "AR",
            "AS",
            "CC",
            "CXX",
            "DEVELOPER_DIR",
            "LD",
            "MACOSX_DEPLOYMENT_TARGET",
            "NIX_BINTOOLS",
            "NIX_CC",
            "NIX_CFLAGS_COMPILE",
            "NIX_LDFLAGS",
            "RANLIB",
            "SDKROOT",
            "SOURCE_DATE_EPOCH",
            "STRIP",
            "ZERO_AR_DATE",
        ):
            if name in os.environ:
                environment[name] = os.environ[name]
        for name, value in os.environ.items():
            if name.startswith("NIX_CC_WRAPPER_TARGET_HOST_") or name.startswith(
                "NIX_BINTOOLS_WRAPPER_TARGET_HOST_"
            ):
                environment[name] = value
        (temporary_root / "home").mkdir(mode=0o700)
        try:
            version_result = subprocess.run(
                [str(zig_path), "version"],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=15,
                env=environment,
            )
            subprocess.run(
                [
                    str(zig_path),
                    "build",
                    "--build-file",
                    str(graph_path),
                    f"-Dcandidate-version={version}",
                    f"-Dcandidate-build-id={build_id}",
                    "--prefix",
                    str(prefix),
                    "--cache-dir",
                    str(local_cache),
                    "--global-cache-dir",
                    str(global_cache),
                ],
                check=True,
                cwd=snapshot,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=600,
                env=environment,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
            detail = (
                exc.stderr.decode("utf-8", errors="replace").strip()
                if isinstance(exc, subprocess.CalledProcessError) and isinstance(exc.stderr, bytes)
                else exc.stderr.strip()
                if isinstance(exc, subprocess.CalledProcessError) and isinstance(exc.stderr, str)
                else str(exc)
            )
            fail(f"independent exact-source Zig rebuild failed: {detail}")
        rebuilt_path = prefix / "bin" / "omux"
        rebuilt_fd = open_regular_nofollow(
            rebuilt_path,
            MAX_MEMBER_BYTES,
            "independently rebuilt candidate binary",
        )
        try:
            rebuilt_payload = read_fd_bytes(
                rebuilt_fd,
                MAX_MEMBER_BYTES,
                "independently rebuilt candidate binary",
            )
        finally:
            os.close(rebuilt_fd)
        if rebuilt_payload != expected_payload:
            fail("candidate bytes do not match the independent exact-source Zig rebuild")
        graph_digest = sha256_file(graph_path)

    if verify_exact_git_source(tools, authority_path, source_commit, source_tree) != repo_root:
        fail("exact candidate source repository changed during rebuild")
    return {
        "graph": EXACT_REBUILD_GRAPH,
        "graph_sha256": graph_digest,
        "toolchain_version": version_result.stdout.strip(),
        "toolchain_sha256": sha256_file(zig_path),
        "binary_sha256": hashlib.sha256(expected_payload).hexdigest(),
        "binary_size": len(expected_payload),
        "byte_equal": True,
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_fd_bytes(fd: int, maximum: int, label: str) -> bytes:
    os.lseek(fd, 0, os.SEEK_SET)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(fd, min(1024 * 1024, maximum + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            fail(f"{label} exceeds the source-contract size limit")
    os.lseek(fd, 0, os.SEEK_SET)
    return b"".join(chunks)


def sha256_fd(fd: int, maximum: int, label: str) -> tuple[str, int]:
    payload = read_fd_bytes(fd, maximum, label)
    return hashlib.sha256(payload).hexdigest(), len(payload)


def canonical_json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def parse_json_object_without_duplicates(raw: bytes, label: str) -> dict[str, object]:
    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                fail(f"{label} contains duplicate object key: {key}")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        fail(f"cannot parse {label}: {exc}")
    if not isinstance(value, dict):
        fail(f"{label} must be one JSON object")
    return value


def atomic_write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(canonical_json_bytes(value).decode("utf-8"))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass


def load_release_authority(path: Path) -> dict[str, object]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot read release-manifest authority: {exc}")

    try:
        product = manifest["product"]
        primary = product["primary_executable"]
        links = product["compatibility_links"]
        storage_namespace = product["storage_namespace"]
        target_os = {item["id"]: item["os"] for item in manifest["targets"]}
        archives = [
            asset
            for asset in manifest["release_assets"]
            if asset["kind"] == "archive" and target_os[asset["target_id"]] != "windows"
        ]
    except (KeyError, TypeError) as exc:
        fail(f"release-manifest authority is missing product/archive fields: {exc}")

    expected = (primary, *(link["name"] for link in links))
    if expected != EXPECTED_MEMBERS:
        fail(f"product identity is not the two-member v0.2 contract: {expected!r}")
    if storage_namespace != "oauth-mux":
        fail("v0.2 candidate must preserve the oauth-mux storage namespace")
    if not archives:
        fail("release-manifest authority has no POSIX archives")
    for asset in archives:
        if tuple(asset.get("declared_v0_2_members", ())) != expected:
            fail(f"{asset.get('id', 'archive')} diverges from the v0.2 member contract")
    authority = {
        "package_name": product["package_name"],
        "primary_executable": primary,
        "compatibility_executable": links[0]["name"],
        "storage_namespace": storage_namespace,
        "members": list(expected),
    }
    if authority != EXPECTED_PRODUCT_AUTHORITY:
        fail("release-manifest product authority diverges from the v0.2 contract")
    return authority


def read_candidate_binary(binary_path: Path) -> tuple[bytes, str]:
    fd = open_regular_nofollow(binary_path, MAX_MEMBER_BYTES, "Zig LazyPath candidate binary")
    try:
        payload = read_fd_bytes(fd, MAX_MEMBER_BYTES, "Zig LazyPath candidate binary")
        digest = hashlib.sha256(payload).hexdigest()
    finally:
        os.close(fd)
    if sha256_file(binary_path) != digest:
        fail("Zig LazyPath candidate binary changed after descriptor-pinned read")
    return payload, digest


def make_build_provenance(
    authority_path: Path,
    binary_path: Path,
    version: str,
    build_id: str,
    source_commit: str | None,
    source_tree: str | None,
    exact_tools: ExactToolAuthority | None = None,
) -> tuple[dict[str, object], bytes]:
    validate_v02_prerelease(version)
    if not SAFE_ID.fullmatch(build_id):
        fail("candidate build id is not a safe identifier")
    if (source_commit is None) != (source_tree is None):
        fail("source commit and tree must be provided together")
    payload, binary_digest = read_candidate_binary(binary_path)
    binding = "local_debug_only"
    exact_rebuild: dict[str, object] | None = None
    if source_commit is not None:
        assert source_tree is not None
        if exact_tools is None:
            fail("exact candidate promotion requires the Nix closure-bound helper")
        exact_rebuild = exact_rebuild_evidence(
            exact_tools,
            authority_path,
            source_commit,
            source_tree,
            version,
            build_id,
            payload,
        )
        binding = "exact_git_object"
    statement: dict[str, object] = {
        "schema_version": 1,
        "profile": {
            "id": PROVENANCE_PROFILE_ID,
            "producer": (
                "independent_zig_rebuild"
                if binding == "exact_git_object"
                else "named_graph_local_debug"
            ),
            "source_contract_only": True,
            "install_enabled": False,
            "publication_enabled": False,
        },
        "source": {
            "binding": binding,
            "commit": source_commit,
            "tree": source_tree,
        },
        "build": {
            "version": version,
            "build_id": build_id,
            "root_source": "src/main.zig",
            "optimize": "ReleaseSafe",
            "install_step": False,
            "candidate_step": "build.zig:v02-posix-source-candidate",
        },
        "binary": {
            "sha256": binary_digest,
            "size": len(payload),
        },
        "exact_rebuild": exact_rebuild,
    }
    statement["binding_sha256"] = provenance_binding_sha256(statement)
    return statement, payload


def require_exact_json_boolean(value: object, expected: bool, label: str) -> None:
    if type(value) is not bool or value is not expected:
        fail(f"{label} must be the JSON boolean {str(expected).lower()}")


def provenance_binding_sha256(statement: dict[str, object]) -> str:
    binding = {
        "schema_version": statement.get("schema_version"),
        "profile": statement.get("profile"),
        "source": statement.get("source"),
        "build": statement.get("build"),
        "binary": statement.get("binary"),
        "exact_rebuild": statement.get("exact_rebuild"),
    }
    return hashlib.sha256(canonical_json_bytes(binding)).hexdigest()


def validate_build_provenance(
    statement: object,
    authority_path: Path,
    expected_digest: str | None = None,
    expected_size: int | None = None,
    expected_payload: bytes | None = None,
    revalidate_exact: bool = False,
    exact_tools: ExactToolAuthority | None = None,
) -> dict[str, object]:
    if (
        not isinstance(statement, dict)
        or type(statement.get("schema_version")) is not int
        or statement.get("schema_version") != 1
    ):
        fail("candidate build provenance schema is unsupported")
    if set(statement) != {
        "schema_version",
        "profile",
        "source",
        "build",
        "binary",
        "exact_rebuild",
        "binding_sha256",
    }:
        fail("candidate build provenance has unknown authority fields")
    binding_digest = statement.get("binding_sha256")
    if (
        not isinstance(binding_digest, str)
        or not HEX_64.fullmatch(binding_digest)
        or binding_digest != provenance_binding_sha256(statement)
    ):
        fail("candidate build provenance does not bind source, build, and binary identity")
    profile = statement.get("profile")
    if not isinstance(profile, dict):
        fail("candidate build provenance profile must be an object")
    if profile.get("id") != PROVENANCE_PROFILE_ID:
        fail("candidate build provenance has the wrong profile")
    require_exact_json_boolean(profile.get("source_contract_only"), True, "build provenance source_contract_only")
    require_exact_json_boolean(profile.get("install_enabled"), False, "build provenance install_enabled")
    require_exact_json_boolean(profile.get("publication_enabled"), False, "build provenance publication_enabled")
    if set(profile) != {
        "id",
        "producer",
        "source_contract_only",
        "install_enabled",
        "publication_enabled",
    }:
        fail("candidate build provenance profile has unknown authority fields")

    source = statement.get("source")
    build = statement.get("build")
    binary = statement.get("binary")
    exact_rebuild = statement.get("exact_rebuild")
    if (
        not isinstance(source, dict)
        or not isinstance(build, dict)
        or not isinstance(binary, dict)
    ):
        fail("candidate build provenance is missing source/build/binary objects")
    if set(source) != {"binding", "commit", "tree"}:
        fail("candidate build provenance source has unknown fields")
    binding = source.get("binding")
    commit = source.get("commit")
    tree = source.get("tree")
    if binding == "exact_git_object":
        if not isinstance(commit, str) or not isinstance(tree, str):
            fail("exact build provenance requires source commit and tree")
        if exact_tools is None:
            fail("exact candidate verification requires the Nix closure-bound helper")
        exact_tools = validate_exact_tool_authority(exact_tools)
        verify_exact_git_source(exact_tools, authority_path, commit, tree)
        if profile.get("producer") != "independent_zig_rebuild":
            fail("exact build provenance requires independent Zig rebuild authority")
    elif binding == "local_debug_only":
        if commit is not None or tree is not None:
            fail("local-debug build provenance must not claim Git objects")
        if profile.get("producer") != "named_graph_local_debug":
            fail("local-debug provenance has an invalid producer")
    else:
        fail("candidate build provenance has an unknown source binding")

    version = validate_v02_prerelease(build.get("version"))
    build_id = build.get("build_id")
    if not isinstance(build_id, str) or not SAFE_ID.fullmatch(build_id):
        fail("candidate build provenance has an invalid build id")
    if (
        build.get("root_source") != "src/main.zig"
        or build.get("optimize") != "ReleaseSafe"
        or build.get("candidate_step") != "build.zig:v02-posix-source-candidate"
        or set(build) != {
            "version",
            "build_id",
            "root_source",
            "optimize",
            "install_step",
            "candidate_step",
        }
    ):
        fail("candidate build provenance diverges from the named Zig graph")
    require_exact_json_boolean(build.get("install_step"), False, "build provenance install_step")

    digest = binary.get("sha256")
    size = binary.get("size")
    if set(binary) != {"sha256", "size"} or not isinstance(digest, str) or not HEX_64.fullmatch(digest):
        fail("candidate build provenance has an invalid binary digest")
    if type(size) is not int or size <= 0 or size > MAX_MEMBER_BYTES:
        fail("candidate build provenance has an invalid binary size")
    if expected_digest is not None and digest != expected_digest:
        fail("candidate build provenance digest does not match packaged bytes")
    if expected_size is not None and size != expected_size:
        fail("candidate build provenance size does not match packaged bytes")
    if expected_payload is not None:
        if hashlib.sha256(expected_payload).hexdigest() != digest or len(expected_payload) != size:
            fail("candidate build provenance does not bind the supplied payload")

    if binding == "exact_git_object":
        if not isinstance(exact_rebuild, dict) or set(exact_rebuild) != {
            "graph",
            "graph_sha256",
            "toolchain_version",
            "toolchain_sha256",
            "binary_sha256",
            "binary_size",
            "byte_equal",
        }:
            fail("exact build provenance is missing independent rebuild evidence")
        if exact_rebuild.get("graph") != EXACT_REBUILD_GRAPH:
            fail("exact build provenance names the wrong rebuild graph")
        for field in ("graph_sha256", "toolchain_sha256", "binary_sha256"):
            if not isinstance(exact_rebuild.get(field), str) or not HEX_64.fullmatch(exact_rebuild[field]):
                fail(f"exact build provenance has an invalid {field}")
        if (
            not isinstance(exact_rebuild.get("toolchain_version"), str)
            or not exact_rebuild["toolchain_version"]
            or len(exact_rebuild["toolchain_version"]) > 64
            or exact_rebuild.get("binary_sha256") != digest
            or type(exact_rebuild.get("binary_size")) is not int
            or exact_rebuild.get("binary_size") != size
        ):
            fail("exact build provenance rebuild identity does not bind the candidate binary")
        require_exact_json_boolean(exact_rebuild.get("byte_equal"), True, "exact rebuild byte_equal")
        if revalidate_exact:
            if expected_payload is None:
                fail("exact build provenance revalidation requires candidate bytes")
            assert isinstance(commit, str) and isinstance(tree, str)
            rebuilt = exact_rebuild_evidence(
                exact_tools,
                authority_path,
                commit,
                tree,
                version,
                build_id,
                expected_payload,
            )
            if rebuilt != exact_rebuild:
                fail("candidate build provenance does not match the repeated exact-source rebuild")
    elif exact_rebuild is not None:
        fail("local-debug build provenance may not carry exact rebuild evidence")
    _ = version
    return statement


def canonical_archive_bytes(payloads: dict[str, bytes]) -> bytes:
    if tuple(payloads) != EXPECTED_MEMBERS:
        fail("canonical archive payloads must follow product authority order")
    if payloads["omux"] != payloads["oauth-mux"]:
        fail("canonical archive payloads must be byte-identical")
    raw = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=9, mtime=0) as zipped:
        with tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for member_name in EXPECTED_MEMBERS:
                payload = payloads[member_name]
                if not payload or len(payload) > MAX_MEMBER_BYTES:
                    fail(f"canonical archive member has an invalid size: {member_name}")
                entry = tarfile.TarInfo(member_name)
                entry.type = tarfile.REGTYPE
                entry.mode = 0o755
                entry.uid = 0
                entry.gid = 0
                entry.uname = ""
                entry.gname = ""
                entry.mtime = 0
                entry.size = len(payload)
                archive.addfile(entry, io.BytesIO(payload))
    return raw.getvalue()


def read_canonical_json_file(path: Path, label: str) -> tuple[dict[str, object], bytes]:
    fd = open_regular_nofollow(path, MAX_METADATA_BYTES, label)
    try:
        raw = read_fd_bytes(fd, MAX_METADATA_BYTES, label)
    finally:
        os.close(fd)
    value = parse_json_object_without_duplicates(raw, label)
    if raw != canonical_json_bytes(value):
        fail(f"{label} must be one canonical JSON object")
    return value, raw


def atomic_write_executable(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as target:
            target.write(payload)
            target.flush()
            os.fchmod(target.fileno(), 0o755)
            os.fsync(target.fileno())
        os.replace(tmp_path, path)
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass


def pack_archive(
    authority_path: Path,
    binary_path: Path,
    archive_path: Path,
    metadata_path: Path,
    version: str,
    build_id: str,
    build_provenance_path: Path | None,
    exact_tools: ExactToolAuthority | None = None,
) -> dict[str, object]:
    authority = load_release_authority(authority_path)
    validate_v02_prerelease(version)
    if not SAFE_ID.fullmatch(build_id):
        fail("candidate build id is not a safe identifier")

    binary_fd = open_regular_nofollow(binary_path, MAX_MEMBER_BYTES, "source candidate binary")
    try:
        binary_payload = read_fd_bytes(binary_fd, MAX_MEMBER_BYTES, "source candidate binary")
    finally:
        os.close(binary_fd)
    binary_sha = hashlib.sha256(binary_payload).hexdigest()
    if build_provenance_path is None:
        fail("candidate archives require provenance from the named Zig LazyPath graph")
    if build_provenance_path.parent.resolve() != metadata_path.parent.resolve():
        fail("build provenance and candidate metadata must share one bundle directory")
    statement, provenance_bytes = read_canonical_json_file(
        build_provenance_path,
        "candidate build provenance",
    )
    validate_build_provenance(
        statement,
        authority_path,
        expected_digest=binary_sha,
        expected_size=len(binary_payload),
        exact_tools=exact_tools,
    )
    source = statement["source"]
    build = statement["build"]
    assert isinstance(source, dict) and isinstance(build, dict)
    if build.get("version") != version or build.get("build_id") != build_id:
        fail("pack request diverges from Zig LazyPath build provenance")
    candidate_binding = str(source["binding"])
    source_commit = source.get("commit") if isinstance(source.get("commit"), str) else None
    source_tree = source.get("tree") if isinstance(source.get("tree"), str) else None
    provenance_projection: dict[str, object] = {
        "path": build_provenance_path.name,
        "sha256": hashlib.sha256(provenance_bytes).hexdigest(),
        "statement": statement,
    }
    archive_payload = canonical_archive_bytes({name: binary_payload for name in EXPECTED_MEMBERS})

    archive_path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{archive_path.name}.", dir=archive_path.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as raw:
            raw.write(archive_payload)
            raw.flush()
            os.fsync(raw.fileno())
        os.replace(tmp_path, archive_path)
    finally:
        try:
            tmp_path.unlink()
        except FileNotFoundError:
            pass

    verified = verify_archive(archive_path)
    if any(item["sha256"] != binary_sha for item in verified["members"]):
        fail("packed member bytes do not match the source binary")

    metadata = {
        "schema_version": 1,
        "profile": {
            "id": PROFILE_ID,
            "status": "source_contract_only",
            "implementation_role": "source_test_oracle",
            "publication_enabled": False,
            "host_install_enabled": False,
            "end_user_installer_enabled": False,
            "temporary_root_required": True,
            "rollback_enabled": False,
        },
        "candidate_binding": candidate_binding,
        "release": {
            "version": version,
            "build_id": build_id,
            "source_commit": source_commit,
            "source_tree": source_tree,
        },
        "product": authority,
        "build_provenance": provenance_projection,
        "artifact": {
            "path": archive_path.name,
            "sha256": sha256_file(archive_path),
            "members": verified["members"],
        },
    }
    atomic_write_json(metadata_path, metadata)
    return metadata


def materialize_graph_candidate(
    authority_path: Path,
    binary_path: Path,
    output_dir: Path,
    version: str,
    build_id: str,
    source_commit: str | None,
    source_tree: str | None,
    exact_tools: ExactToolAuthority | None = None,
) -> dict[str, object]:
    output_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = output_dir.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or output_dir.is_symlink()
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        fail("source candidate output directory must be private and current-user owned")
    provenance_path = output_dir / "build-provenance.json"
    archive_path = output_dir / "omux-posix-source-contract.tar.gz"
    metadata_path = output_dir / "candidate.json"
    built_dir = output_dir / "built"
    for path in (provenance_path, archive_path, metadata_path, built_dir):
        if path.exists() or path.is_symlink():
            fail(f"source candidate output already exists: {path.name}")

    statement, payload = make_build_provenance(
        authority_path,
        binary_path,
        version,
        build_id,
        source_commit,
        source_tree,
        exact_tools,
    )
    built_dir.mkdir(mode=0o700)
    for name in EXPECTED_MEMBERS:
        atomic_write_executable(built_dir / name, payload)
    atomic_write_json(provenance_path, statement)
    metadata = pack_archive(
        authority_path,
        binary_path,
        archive_path,
        metadata_path,
        version,
        build_id,
        provenance_path,
        exact_tools,
    )
    return {
        "archive": str(archive_path),
        "metadata": str(metadata_path),
        "build_provenance": str(provenance_path),
        "primary": str(built_dir / "omux"),
        "compatibility": str(built_dir / "oauth-mux"),
        "candidate_binding": metadata["candidate_binding"],
    }


def validate_member_set(members: list[tarfile.TarInfo]) -> None:
    if len(members) != len(EXPECTED_MEMBERS):
        fail("archive must contain exactly two members")
    names = [member.name for member in members]
    if tuple(names) != EXPECTED_MEMBERS:
        fail(f"archive members must be exactly {EXPECTED_MEMBERS!r} in authority order")
    if len(set(names)) != len(names):
        fail("archive contains duplicate members")
    for member in members:
        if member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
            fail(f"archive member is not a regular file: {member.name}")
        if member.name.startswith("/") or "/" in member.name or "\\" in member.name:
            fail(f"archive member is not a top-level relative name: {member.name}")
        if member.name in (".", ".."):
            fail("archive member contains traversal syntax")
        if member.pax_headers:
            fail(f"archive member carries unsupported pax metadata: {member.name}")
        if member.size <= 0 or member.size > MAX_MEMBER_BYTES:
            fail(f"archive member has an invalid size: {member.name}")
        if stat.S_IMODE(member.mode) != 0o755:
            fail(f"archive member mode is not canonical executable mode: {member.name}")


def parse_canonical_archive(raw: bytes) -> tuple[dict[str, bytes], dict[str, object]]:
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz", errorlevel=2) as archive:
            members = archive.getmembers()
            validate_member_set(members)
            payloads: dict[str, bytes] = {}
            results: list[dict[str, object]] = []
            for member in members:
                extracted = archive.extractfile(member)
                if extracted is None:
                    fail(f"archive member has no readable payload: {member.name}")
                with extracted:
                    payload = extracted.read(MAX_MEMBER_BYTES + 1)
                if len(payload) != member.size or len(payload) > MAX_MEMBER_BYTES:
                    fail(f"archive member is invalid or truncated: {member.name}")
                payloads[member.name] = payload
                results.append({
                    "name": member.name,
                    "mode": format(member.mode & 0o777, "04o"),
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                })
    except (OSError, tarfile.TarError, EOFError) as exc:
        fail(f"invalid or truncated gzip tar archive: {exc}")
    if payloads["omux"] != payloads["oauth-mux"]:
        fail("omux and oauth-mux archive members are not byte-identical")
    if raw != canonical_archive_bytes(payloads):
        fail("archive is not the exact canonical gzip/USTAR representation")
    return payloads, {"members": results}


def open_regular_nofollow(path: Path, maximum: int, label: str) -> int:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size <= 0 or info.st_size > maximum:
            fail(f"{label} must be a bounded regular file")
        return fd
    except Exception:
        os.close(fd)
        raise


def verify_archive(path: Path) -> dict[str, object]:
    fd = open_regular_nofollow(path, MAX_ARCHIVE_BYTES, "candidate archive")
    try:
        raw = read_fd_bytes(fd, MAX_ARCHIVE_BYTES, "candidate archive")
        _, verified = parse_canonical_archive(raw)
        return verified
    finally:
        os.close(fd)


def read_metadata_nofollow(path: Path) -> dict[str, object]:
    fd = open_regular_nofollow(path, MAX_METADATA_BYTES, "candidate metadata")
    try:
        raw = read_fd_bytes(fd, MAX_METADATA_BYTES, "candidate metadata")
    finally:
        os.close(fd)
    value = parse_json_object_without_duplicates(raw, "candidate metadata")
    if raw != canonical_json_bytes(value):
        fail("candidate metadata must be one canonical JSON object")
    return value


def load_metadata_provenance(
    metadata: dict[str, object],
    metadata_path: Path,
    authority_path: Path,
    exact_tools: ExactToolAuthority | None = None,
) -> dict[str, object] | None:
    projection = metadata.get("build_provenance")
    if projection is None:
        return None
    if not isinstance(projection, dict) or set(projection) != {"path", "sha256", "statement"}:
        fail("candidate metadata build provenance projection is invalid")
    path_name = projection.get("path")
    expected_digest = projection.get("sha256")
    if (
        not isinstance(path_name, str)
        or Path(path_name).name != path_name
        or not isinstance(expected_digest, str)
        or not HEX_64.fullmatch(expected_digest)
    ):
        fail("candidate metadata build provenance identity is invalid")
    statement, raw = read_canonical_json_file(
        metadata_path.parent / path_name,
        "candidate build provenance",
    )
    if hashlib.sha256(raw).hexdigest() != expected_digest or projection.get("statement") != statement:
        fail("candidate metadata does not match its build provenance file")
    return validate_build_provenance(statement, authority_path, exact_tools=exact_tools)


def validate_metadata_shape(
    metadata: dict[str, object],
    authority_path: Path,
    provenance: dict[str, object] | None,
) -> None:
    if set(metadata) != {
        "artifact",
        "build_provenance",
        "candidate_binding",
        "product",
        "profile",
        "release",
        "schema_version",
    }:
        fail("candidate metadata has unknown authority fields")
    if type(metadata.get("schema_version")) is not int or metadata.get("schema_version") != 1:
        fail("candidate metadata schema is unsupported")
    profile = metadata.get("profile", {})
    if not isinstance(profile, dict) or set(profile) != {
        "end_user_installer_enabled",
        "host_install_enabled",
        "id",
        "implementation_role",
        "publication_enabled",
        "rollback_enabled",
        "status",
        "temporary_root_required",
    }:
        fail("candidate metadata is not source-only and nonpublishing")
    if (
        profile.get("id") != PROFILE_ID
        or profile.get("implementation_role") != "source_test_oracle"
        or profile.get("status") != "source_contract_only"
    ):
        fail("candidate metadata profile identity is invalid")
    for field, expected in (
        ("end_user_installer_enabled", False),
        ("host_install_enabled", False),
        ("publication_enabled", False),
        ("rollback_enabled", False),
        ("temporary_root_required", True),
    ):
        require_exact_json_boolean(profile.get(field), expected, f"candidate metadata {field}")
    release = metadata.get("release", {})
    if not isinstance(release, dict) or set(release) != {
        "version",
        "build_id",
        "source_commit",
        "source_tree",
    }:
        fail("candidate metadata release must be an object")
    version = validate_v02_prerelease(release.get("version"))
    build_id = release.get("build_id")
    if not isinstance(build_id, str) or not SAFE_ID.fullmatch(build_id):
        fail("candidate metadata has invalid build identity")
    binding = metadata.get("candidate_binding")
    source_commit = release.get("source_commit")
    source_tree = release.get("source_tree")
    if binding == "local_debug_only":
        if source_commit is not None or source_tree is not None:
            fail("local-debug metadata must not claim exact Git objects")
    elif binding == "exact_git_object":
        if provenance is None:
            fail("exact candidate metadata requires revalidated Zig build provenance")
    else:
        fail("candidate metadata has an unknown binding level")
    product = metadata.get("product", {})
    if not isinstance(product, dict):
        fail("candidate metadata product must be an object")
    if product != load_release_authority(authority_path):
        fail("candidate metadata diverges from product identity")
    artifact = metadata.get("artifact")
    if not isinstance(artifact, dict) or set(artifact) != {"members", "path", "sha256"}:
        fail("candidate metadata artifact has unknown authority fields")
    if provenance is not None:
        source = provenance["source"]
        build = provenance["build"]
        assert isinstance(source, dict) and isinstance(build, dict)
        if (
            binding != source.get("binding")
            or source_commit != source.get("commit")
            or source_tree != source.get("tree")
            or version != build.get("version")
            or build_id != build.get("build_id")
        ):
            fail("candidate metadata release identity diverges from build provenance")


def open_verified_candidate(
    archive_path: Path,
    metadata_path: Path,
    authority_path: Path,
    expected_archive_digest: str,
    hook: Hook | None = None,
    exact_tools: ExactToolAuthority | None = None,
) -> tuple[int, dict[str, bytes], dict[str, object], dict[str, object]]:
    metadata = read_metadata_nofollow(metadata_path)
    provenance = load_metadata_provenance(
        metadata,
        metadata_path,
        authority_path,
        exact_tools=exact_tools,
    )
    validate_metadata_shape(metadata, authority_path, provenance)
    if not HEX_64.fullmatch(expected_archive_digest):
        fail("expected archive digest must be lowercase SHA-256")
    artifact = metadata["artifact"]
    assert isinstance(artifact, dict)
    if artifact.get("path") != archive_path.name or artifact.get("sha256") != expected_archive_digest:
        fail("candidate metadata archive identity mismatch")
    archive_fd = open_regular_nofollow(archive_path, MAX_ARCHIVE_BYTES, "candidate archive")
    try:
        fault_point("after_archive_open", hook)
        raw = read_fd_bytes(archive_fd, MAX_ARCHIVE_BYTES, "candidate archive")
        actual_digest = hashlib.sha256(raw).hexdigest()
        if actual_digest != expected_archive_digest:
            fail("opened candidate archive digest does not match the verified expectation")
        payloads, verified = parse_canonical_archive(raw)
        if artifact.get("members") != verified["members"]:
            fail("candidate metadata member projection mismatch")
        if provenance is not None:
            binary = provenance["binary"]
            assert isinstance(binary, dict)
            for member in verified["members"]:
                if member.get("sha256") != binary.get("sha256") or member.get("size") != binary.get("size"):
                    fail("candidate archive bytes diverge from Zig build provenance")
            validate_build_provenance(
                provenance,
                authority_path,
                expected_digest=hashlib.sha256(payloads["omux"]).hexdigest(),
                expected_size=len(payloads["omux"]),
                expected_payload=payloads["omux"],
                revalidate_exact=True,
                exact_tools=exact_tools,
            )
        return archive_fd, payloads, verified, metadata
    except Exception:
        os.close(archive_fd)
        raise


def verify_metadata(
    archive_path: Path,
    metadata_path: Path,
    authority_path: Path,
    exact_tools: ExactToolAuthority | None = None,
) -> dict[str, object]:
    metadata = read_metadata_nofollow(metadata_path)
    artifact = metadata.get("artifact", {})
    expected_digest = artifact.get("sha256") if isinstance(artifact, dict) else None
    if not isinstance(expected_digest, str):
        fail("candidate metadata is missing the expected archive digest")
    archive_fd, _, _, verified_metadata = open_verified_candidate(
        archive_path,
        metadata_path,
        authority_path,
        expected_digest,
        exact_tools=exact_tools,
    )
    os.close(archive_fd)
    return verified_metadata


def open_absolute_dir_nofollow(path: Path) -> int:
    if not path.is_absolute():
        fail("candidate root must be an absolute injected path")
    parts = path.parts
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in parts[1:]:
            if component in ("", ".", ".."):
                fail("candidate root contains an unsafe path component")
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=fd,
            )
            os.close(fd)
            fd = next_fd
        return fd
    except Exception:
        os.close(fd)
        raise


def open_dir_at(parent_fd: int, name: str, create: bool = False, mode: int = 0o700) -> int:
    if create:
        try:
            os.mkdir(name, mode=mode, dir_fd=parent_fd)
        except FileExistsError:
            pass
    return os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)


def require_owned_private_dir(fd: int, label: str) -> os.stat_result:
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        fail(f"{label} must be a directory")
    if info.st_uid != os.geteuid():
        fail(f"{label} must be owned by the current user")
    if stat.S_IMODE(info.st_mode) & 0o077:
        fail(f"{label} must not grant group or other permissions")
    if info.st_nlink < 2:
        fail(f"{label} has an invalid link count")
    return info


def open_injected_root(root_path: Path, temporary_parent_path: Path) -> int:
    if not root_path.is_absolute() or not temporary_parent_path.is_absolute():
        fail("candidate root and temporary parent must be absolute injected paths")
    try:
        relative = root_path.relative_to(temporary_parent_path)
    except ValueError:
        fail("candidate root must be below the injected temporary parent")
    if not relative.parts or any(component in ("", ".", "..") for component in relative.parts):
        fail("candidate root must be a proper child of the injected temporary parent")

    parent_fd = open_absolute_dir_nofollow(temporary_parent_path)
    root_fd = parent_fd
    try:
        require_owned_private_dir(parent_fd, "injected temporary parent")
        for component in relative.parts:
            next_fd = open_dir_at(root_fd, component)
            if root_fd != parent_fd:
                os.close(root_fd)
            root_fd = next_fd
        return root_fd
    except Exception:
        if root_fd != parent_fd:
            os.close(root_fd)
        raise
    finally:
        os.close(parent_fd)


def require_root_sentinel(root_fd: int) -> None:
    try:
        fd = os.open(
            ROOT_SENTINEL,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=root_fd,
        )
    except OSError as exc:
        fail(f"candidate root sentinel is missing or unsafe: {exc}")
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            fail("candidate root sentinel must be one current-user 0600 regular file")
        if os.read(fd, len(ROOT_SENTINEL_CONTENT) + 1) != ROOT_SENTINEL_CONTENT:
            fail("candidate root sentinel content is invalid")
    finally:
        os.close(fd)


def assert_root_identity(path: Path, root_fd: int) -> None:
    check_fd = open_absolute_dir_nofollow(path)
    try:
        expected = os.fstat(root_fd)
        actual = os.fstat(check_fd)
        if (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino):
            fail("candidate root changed during installation")
    finally:
        os.close(check_fd)


def assert_child_dir_identity(parent_fd: int, name: str, expected: os.stat_result) -> None:
    check_fd = open_dir_at(parent_fd, name)
    try:
        actual = os.fstat(check_fd)
        if (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino):
            fail(f"candidate directory changed during installation: {name}")
    finally:
        os.close(check_fd)


def assert_child_file_identity(parent_fd: int, name: str, expected: os.stat_result) -> None:
    check_fd = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        dir_fd=parent_fd,
    )
    try:
        actual = os.fstat(check_fd)
        if (expected.st_dev, expected.st_ino) != (actual.st_dev, actual.st_ino):
            fail(f"candidate file changed during installation: {name}")
    finally:
        os.close(check_fd)


def write_member(stage_fd: int, name: str, payload: bytes) -> None:
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o755,
        dir_fd=stage_fd,
    )
    try:
        with os.fdopen(fd, "wb", closefd=False) as target:
            target.write(payload)
            target.flush()
            os.fchmod(fd, 0o755)
            os.fsync(fd)
    finally:
        os.close(fd)


def require_candidate_member(fd: int, name: str) -> os.stat_result:
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o755
        or info.st_nlink != 1
    ):
        fail(f"installed candidate member lacks private transaction custody: {name}")
    if info.st_size <= 0 or info.st_size > MAX_MEMBER_BYTES:
        fail(f"installed candidate member has an invalid size: {name}")
    return info


def read_file_at(dir_fd: int, name: str) -> bytes:
    fd = os.open(
        name,
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        dir_fd=dir_fd,
    )
    try:
        require_candidate_member(fd, name)
        return read_fd_bytes(fd, MAX_MEMBER_BYTES, f"installed candidate member {name}")
    finally:
        os.close(fd)


def pin_generation(
    generations_fd: int,
    candidate_id: str,
    expected: dict[str, bytes],
) -> PinnedGeneration:
    generation_fd = open_dir_at(generations_fd, candidate_id)
    pinned: dict[str, PinnedMember] = {}
    try:
        generation_identity = require_owned_private_dir(generation_fd, "candidate generation")
        if sorted(os.listdir(generation_fd)) != sorted(EXPECTED_MEMBERS):
            fail("candidate generation does not contain exactly the two executable members")
        for name in EXPECTED_MEMBERS:
            member_fd = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                dir_fd=generation_fd,
            )
            try:
                identity = require_candidate_member(member_fd, name)
                digest, size = sha256_fd(
                    member_fd,
                    MAX_MEMBER_BYTES,
                    f"installed candidate member {name}",
                )
                expected_digest = hashlib.sha256(expected[name]).hexdigest()
                if digest != expected_digest or size != len(expected[name]):
                    fail(f"candidate generation bytes do not match the archive: {name}")
                pinned[name] = PinnedMember(member_fd, identity, digest, size)
            except Exception:
                os.close(member_fd)
                raise
        return PinnedGeneration(generation_fd, generation_identity, pinned)
    except Exception:
        for member in pinned.values():
            os.close(member.fd)
        os.close(generation_fd)
        raise


def revalidate_pinned_generation(
    generations_fd: int,
    candidate_id: str,
    pinned: PinnedGeneration,
) -> None:
    assert_child_dir_identity(generations_fd, candidate_id, pinned.identity)
    if sorted(os.listdir(pinned.fd)) != sorted(EXPECTED_MEMBERS):
        fail("candidate generation membership changed before publication")
    for name in EXPECTED_MEMBERS:
        member = pinned.members[name]
        pinned_identity = require_candidate_member(member.fd, name)
        if (pinned_identity.st_dev, pinned_identity.st_ino) != (
            member.identity.st_dev,
            member.identity.st_ino,
        ):
            fail(f"pinned candidate member identity changed before publication: {name}")
        pinned_digest, pinned_size = sha256_fd(
            member.fd,
            MAX_MEMBER_BYTES,
            f"pinned candidate member {name}",
        )
        if pinned_digest != member.digest or pinned_size != member.size:
            fail(f"pinned candidate member bytes changed before publication: {name}")

        named_fd = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=pinned.fd,
        )
        try:
            named_identity = require_candidate_member(named_fd, name)
            if (named_identity.st_dev, named_identity.st_ino) != (
                member.identity.st_dev,
                member.identity.st_ino,
            ):
                fail(f"candidate member pathname changed before publication: {name}")
            named_digest, named_size = sha256_fd(
                named_fd,
                MAX_MEMBER_BYTES,
                f"named candidate member {name}",
            )
            if named_digest != member.digest or named_size != member.size:
                fail(f"candidate member digest changed before publication: {name}")
        finally:
            os.close(named_fd)


def validate_generation(generations_fd: int, candidate_id: str, expected: dict[str, bytes]) -> None:
    pinned = pin_generation(generations_fd, candidate_id, expected)
    pinned.close()


def assert_stage_binding(
    root_fd: int,
    generations_fd: int,
    generations_identity: os.stat_result,
    stage_name: str,
    stage_identity: os.stat_result,
) -> None:
    assert_child_dir_identity(root_fd, "generations", generations_identity)
    assert_child_dir_identity(generations_fd, stage_name, stage_identity)


def remove_private_stage(
    root_fd: int,
    generations_fd: int,
    generations_identity: os.stat_result,
    stage_name: str,
    hook: Hook | None = None,
) -> None:
    try:
        stage_fd = open_dir_at(generations_fd, stage_name)
    except FileNotFoundError:
        return
    try:
        stage_identity = require_owned_private_dir(stage_fd, "candidate private staging directory")
        fault_point("before_stale_stage_delete", hook)
        assert_stage_binding(
            root_fd,
            generations_fd,
            generations_identity,
            stage_name,
            stage_identity,
        )
        for name in EXPECTED_MEMBERS:
            try:
                assert_stage_binding(
                    root_fd,
                    generations_fd,
                    generations_identity,
                    stage_name,
                    stage_identity,
                )
                info = os.stat(name, dir_fd=stage_fd, follow_symlinks=False)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o755
                    or info.st_nlink != 1
                ):
                    fail(f"private staging member lacks cleanup custody: {name}")
                member_fd = os.open(
                    name,
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                    dir_fd=stage_fd,
                )
                try:
                    member_identity = os.fstat(member_fd)
                    fault_point("before_stale_stage_member_unlink", hook)
                    assert_stage_binding(
                        root_fd,
                        generations_fd,
                        generations_identity,
                        stage_name,
                        stage_identity,
                    )
                    assert_child_file_identity(stage_fd, name, member_identity)
                finally:
                    os.close(member_fd)
                os.unlink(name, dir_fd=stage_fd)
            except FileNotFoundError:
                pass
        leftovers = os.listdir(stage_fd)
        if leftovers:
            fail(f"private staging directory contains unexpected entries: {leftovers!r}")
        fault_point("before_stale_stage_rmdir", hook)
        assert_stage_binding(
            root_fd,
            generations_fd,
            generations_identity,
            stage_name,
            stage_identity,
        )
        os.rmdir(stage_name, dir_fd=generations_fd)
    finally:
        os.close(stage_fd)


def cleanup_stale_stages(
    root_fd: int,
    generations_fd: int,
    generations_identity: os.stat_result,
    hook: Hook | None,
) -> None:
    for name in os.listdir(generations_fd):
        if name.startswith(".staging-"):
            remove_private_stage(
                root_fd,
                generations_fd,
                generations_identity,
                name,
                hook=hook,
            )


def cleanup_stale_pointers(root_fd: int, hook: Hook | None) -> None:
    for name in os.listdir(root_fd):
        if not name.startswith(".current-"):
            continue
        if not PRIVATE_POINTER.fullmatch(name):
            fail(f"candidate root contains an unrecognized private pointer: {name}")
        identity = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if (
            not stat.S_ISLNK(identity.st_mode)
            or identity.st_uid != os.geteuid()
            or identity.st_nlink != 1
        ):
            fail(f"private candidate pointer lacks cleanup custody: {name}")
        target = os.readlink(name, dir_fd=root_fd)
        if not target.startswith("generations/") or not SAFE_ID.fullmatch(
            target.removeprefix("generations/")
        ):
            fail(f"private candidate pointer has an unsafe target: {name}")
        fault_point("before_stale_pointer_unlink", hook)
        current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
            fail(f"private candidate pointer changed before cleanup: {name}")
        if os.readlink(name, dir_fd=root_fd) != target:
            fail(f"private candidate pointer target changed before cleanup: {name}")
        os.unlink(name, dir_fd=root_fd)


def fault_point(point: str, hook: Hook | None) -> None:
    if hook is not None:
        hook(point)
    if os.environ.get("OMUX_V02_INSTALL_FAILPOINT") == point:
        raise InjectedFailure(f"injected failure at {point}")
    if os.environ.get("OMUX_V02_INSTALL_TERMPOINT") == point:
        os.kill(os.getpid(), signal.SIGTERM)


def test_lock_barrier() -> None:
    ready = os.environ.get("OMUX_V02_INSTALL_TEST_LOCK_READY_FD")
    release = os.environ.get("OMUX_V02_INSTALL_TEST_LOCK_RELEASE_FD")
    if ready is None and release is None:
        return
    if ready is None or release is None:
        fail("both source-contract lock barrier descriptors are required")
    ready_fd = int(ready)
    release_fd = int(release)
    os.write(ready_fd, b"1")
    if os.read(release_fd, 1) != b"1":
        fail("source-contract lock barrier was not released")


def validate_current_pointer(root_fd: int) -> None:
    try:
        info = os.stat("current", dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    if not stat.S_ISLNK(info.st_mode):
        fail("candidate current pointer exists but is not a symlink")
    target = os.readlink("current", dir_fd=root_fd)
    if not target.startswith("generations/") or not SAFE_ID.fullmatch(target.removeprefix("generations/")):
        fail("candidate current pointer has an unsafe target")
    candidate_id = target.removeprefix("generations/")
    generations_fd = open_dir_at(root_fd, "generations")
    try:
        require_owned_private_dir(generations_fd, "visible generations directory")
        generation_fd = open_dir_at(generations_fd, candidate_id)
        try:
            require_owned_private_dir(generation_fd, "visible candidate generation")
            if sorted(os.listdir(generation_fd)) != sorted(EXPECTED_MEMBERS):
                fail("visible candidate generation is not a complete pair")
            primary = read_file_at(generation_fd, "omux")
            compatibility = read_file_at(generation_fd, "oauth-mux")
            if primary != compatibility:
                fail("visible candidate generation contains mixed product bytes")
        finally:
            os.close(generation_fd)
    finally:
        os.close(generations_fd)


def install_archive(
    archive_path: Path,
    metadata_path: Path,
    expected_archive_digest: str,
    root_path: Path,
    temporary_parent_path: Path,
    candidate_id: str,
    hook: Hook | None = None,
    authority_path: Path | None = None,
) -> dict[str, str]:
    if not SAFE_ID.fullmatch(candidate_id):
        fail("candidate id is not a safe identifier")
    archive_fd = -1
    root_fd = -1
    generations_fd = -1
    lock_fd = -1
    stage_fd = -1
    pinned_generation: PinnedGeneration | None = None
    stage_name = f".staging-{os.getpid()}-{os.urandom(8).hex()}"
    pointer_tmp = f".current-{os.getpid()}-{os.urandom(8).hex()}"
    generation_committed = False
    generations_identity: os.stat_result | None = None
    try:
        resolved_authority = authority_path or Path(__file__).resolve().parents[1] / "release-manifest.json"
        archive_fd, payloads, _, metadata = open_verified_candidate(
            archive_path,
            metadata_path,
            resolved_authority,
            expected_archive_digest,
            hook=hook,
        )
        release = metadata.get("release", {})
        if not isinstance(release, dict) or release.get("build_id") != candidate_id:
            fail("candidate id must match the verified metadata build id")
        root_fd = open_injected_root(root_path, temporary_parent_path)
        require_owned_private_dir(root_fd, "candidate root")
        require_root_sentinel(root_fd)
        lock_fd = os.open(
            ".install.lock",
            os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            0o600,
            dir_fd=root_fd,
        )
        lock_info = os.fstat(lock_fd)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_uid != os.geteuid()
            or stat.S_IMODE(lock_info.st_mode) != 0o600
            or lock_info.st_nlink != 1
        ):
            fail("candidate install lock must be one current-user 0600 regular file")
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        fault_point("after_lock_acquire", hook)
        assert_child_file_identity(root_fd, ".install.lock", lock_info)
        require_owned_private_dir(root_fd, "candidate root")
        require_root_sentinel(root_fd)
        test_lock_barrier()
        assert_root_identity(root_path, root_fd)
        cleanup_stale_pointers(root_fd, hook)
        validate_current_pointer(root_fd)
        generations_fd = open_dir_at(root_fd, "generations", create=True)
        generations_identity = require_owned_private_dir(generations_fd, "candidate generations directory")
        cleanup_stale_stages(root_fd, generations_fd, generations_identity, hook)
        os.mkdir(stage_name, mode=0o700, dir_fd=generations_fd)
        stage_fd = open_dir_at(generations_fd, stage_name)
        require_owned_private_dir(stage_fd, "candidate private staging directory")
        fault_point("after_stage_create", hook)

        for index, name in enumerate(EXPECTED_MEMBERS):
            write_member(stage_fd, name, payloads[name])
            fault_point("after_omux_write" if index == 0 else "after_oauth_mux_write", hook)
        os.fsync(stage_fd)
        os.close(stage_fd)
        stage_fd = -1

        fault_point("before_generation_commit", hook)
        assert_root_identity(root_path, root_fd)
        assert_child_dir_identity(root_fd, "generations", generations_identity)
        try:
            os.rename(stage_name, candidate_id, src_dir_fd=generations_fd, dst_dir_fd=generations_fd)
            generation_committed = True
            os.fsync(generations_fd)
        except OSError as exc:
            if exc.errno not in (errno.EEXIST, errno.ENOTEMPTY):
                raise
            validate_generation(generations_fd, candidate_id, payloads)
            remove_private_stage(
                root_fd,
                generations_fd,
                generations_identity,
                stage_name,
            )
        pinned_generation = pin_generation(generations_fd, candidate_id, payloads)
        fault_point("after_generation_commit", hook)

        assert_root_identity(root_path, root_fd)
        validate_current_pointer(root_fd)
        os.symlink(f"generations/{candidate_id}", pointer_tmp, dir_fd=root_fd)
        fault_point("before_pointer_swap", hook)
        assert_root_identity(root_path, root_fd)
        assert_child_dir_identity(root_fd, "generations", generations_identity)
        revalidate_pinned_generation(generations_fd, candidate_id, pinned_generation)
        os.replace(pointer_tmp, "current", src_dir_fd=root_fd, dst_dir_fd=root_fd)
        os.fsync(root_fd)
        fault_point("after_pointer_swap", hook)
        return {
            "profile": PROFILE_ID,
            "candidate_id": candidate_id,
            "archive_sha256": expected_archive_digest,
            "current": f"generations/{candidate_id}",
        }
    finally:
        if stage_fd >= 0:
            os.close(stage_fd)
        if pinned_generation is not None:
            pinned_generation.close()
        if generations_fd >= 0:
            if not generation_committed and generations_identity is not None and root_fd >= 0:
                try:
                    remove_private_stage(
                        root_fd,
                        generations_fd,
                        generations_identity,
                        stage_name,
                    )
                except (OSError, ContractError):
                    pass
            os.close(generations_fd)
        if root_fd >= 0:
            try:
                os.unlink(pointer_tmp, dir_fd=root_fd)
            except (FileNotFoundError, OSError):
                pass
        if lock_fd >= 0:
            os.close(lock_fd)
        if root_fd >= 0:
            os.close(root_fd)
        if archive_fd >= 0:
            os.close(archive_fd)


def parse_args(argv: Iterable[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)

    pack_graph = subcommands.add_parser("_pack-zig-lazy-path")
    pack_graph.add_argument("--authority", type=Path, required=True)
    pack_graph.add_argument("--binary", type=Path, required=True)
    pack_graph.add_argument("--output-dir", type=Path, required=True)
    pack_graph.add_argument("--version", required=True)
    pack_graph.add_argument("--build-id", required=True)

    verify = subcommands.add_parser("verify")
    verify.add_argument("--archive", type=Path, required=True)
    verify.add_argument("--metadata", type=Path)
    verify.add_argument("--authority", type=Path)

    install = subcommands.add_parser("install")
    install.add_argument("--archive", type=Path, required=True)
    install.add_argument("--metadata", type=Path, required=True)
    install.add_argument("--authority", type=Path, required=True)
    install.add_argument("--expected-archive-sha256", required=True)
    install.add_argument("--root", type=Path, required=True)
    install.add_argument("--temporary-parent", type=Path, required=True)
    install.add_argument("--candidate-id", required=True)
    return parser.parse_args(list(argv))


def exact_closure_main(argv: Iterable[str], tools: ExactToolAuthority) -> int:
    parser = argparse.ArgumentParser(description="Nix closure-bound exact candidate promoter")
    subcommands = parser.add_subparsers(dest="command", required=True)
    pack = subcommands.add_parser("pack")
    pack.add_argument("--authority", type=Path, required=True)
    pack.add_argument("--binary", type=Path, required=True)
    pack.add_argument("--output-dir", type=Path, required=True)
    pack.add_argument("--version", required=True)
    pack.add_argument("--build-id", required=True)
    pack.add_argument("--source-commit", required=True)
    pack.add_argument("--source-tree", required=True)
    verify = subcommands.add_parser("verify")
    verify.add_argument("--archive", type=Path, required=True)
    verify.add_argument("--metadata", type=Path, required=True)
    verify.add_argument("--authority", type=Path, required=True)
    arguments = parser.parse_args(list(argv))
    try:
        tools = validate_exact_tool_authority(tools)
        if arguments.command == "pack":
            result = materialize_graph_candidate(
                arguments.authority,
                arguments.binary,
                arguments.output_dir,
                arguments.version,
                arguments.build_id,
                arguments.source_commit,
                arguments.source_tree,
                exact_tools=tools,
            )
        else:
            result = verify_metadata(
                arguments.archive,
                arguments.metadata,
                arguments.authority,
                exact_tools=tools,
            )
        json.dump(result, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    except (ContractError, OSError, tarfile.TarError) as exc:
        print(f"v02-posix-exact-promoter: {exc}", file=sys.stderr)
        return 1


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.command == "_pack-zig-lazy-path":
            result = materialize_graph_candidate(
                args.authority,
                args.binary,
                args.output_dir,
                args.version,
                args.build_id,
                None,
                None,
            )
        elif args.command == "verify":
            if args.metadata is not None and args.authority is None:
                fail("metadata verification requires --authority")
            result = (
                verify_metadata(args.archive, args.metadata, args.authority)
                if args.metadata
                else verify_archive(args.archive)
            )
        else:
            result = install_archive(
                args.archive,
                args.metadata,
                args.expected_archive_sha256,
                args.root,
                args.temporary_parent,
                args.candidate_id,
                authority_path=args.authority,
            )
        json.dump(result, sys.stdout, sort_keys=True)
        sys.stdout.write("\n")
        return 0
    except (ContractError, OSError, tarfile.TarError) as exc:
        print(f"v02-posix-candidate: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
