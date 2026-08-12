#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import gzip
import io
import json
import os
import signal
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")
assert BASH is not None, "the declared test closure must provide Bash"
MKDIR = shutil.which("mkdir")
assert MKDIR is not None, "the declared test closure must provide coreutils"
FALSE = shutil.which("false")
assert FALSE is not None, "the declared test closure must provide coreutils"
MODULE_PATH = ROOT / "scripts" / "v02_posix_candidate.py"
SPEC = importlib.util.spec_from_file_location("v02_posix_candidate", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
candidate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = candidate
SPEC.loader.exec_module(candidate)


def safe_temp_parent() -> str:
    return os.path.realpath(tempfile.gettempdir())


def write_archive(path: Path, entries: list[dict[str, object]]) -> None:
    with tarfile.open(path, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
        for spec in entries:
            info = tarfile.TarInfo(str(spec["name"]))
            info.type = spec.get("type", tarfile.REGTYPE)
            info.mode = int(spec.get("mode", 0o755))
            info.uid = 0
            info.gid = 0
            info.mtime = 0
            info.linkname = str(spec.get("linkname", ""))
            payload = bytes(spec.get("payload", b""))
            info.size = len(payload) if info.type in (tarfile.REGTYPE, tarfile.AREGTYPE) else 0
            archive.addfile(info, fileobj=__import__("io").BytesIO(payload) if info.size else None)


def valid_archive(path: Path, payload: bytes) -> None:
    path.write_bytes(candidate.canonical_archive_bytes({
        "omux": payload,
        "oauth-mux": payload,
    }))


def make_root(path: Path) -> None:
    path.mkdir(mode=0o700)
    (path / candidate.ROOT_SENTINEL).write_bytes(candidate.ROOT_SENTINEL_CONTENT)
    os.chmod(path / candidate.ROOT_SENTINEL, 0o600)


def git(repo: Path, *arguments: str) -> str:
    environment = os.environ.copy()
    environment.update({
        "GIT_AUTHOR_NAME": "omux source contract",
        "GIT_AUTHOR_EMAIL": "source-contract@example.invalid",
        "GIT_COMMITTER_NAME": "omux source contract",
        "GIT_COMMITTER_EMAIL": "source-contract@example.invalid",
        "LC_ALL": "C",
    })
    result = subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=environment,
    )
    return result.stdout.strip()


def current_pair(root: Path) -> tuple[str | None, bytes | None, bytes | None]:
    pointer = root / "current"
    if not pointer.is_symlink():
        return None, None, None
    target = os.readlink(pointer)
    return target, (root / target / "omux").read_bytes(), (root / target / "oauth-mux").read_bytes()


class PosixCandidateContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_context = tempfile.TemporaryDirectory(
            prefix="omux-v02-posix-test.",
            dir=safe_temp_parent(),
        )
        self.tmp = Path(self.tmp_context.name)

    def tearDown(self) -> None:
        self.tmp_context.cleanup()

    @staticmethod
    def shell_function(source: str, name: str) -> str:
        start = source.index(f"{name}() {{")
        end = source.index("\n}\n", start) + len("\n}\n")
        return source[start:end]

    def assert_cleanup_signals(
        self,
        block: str,
        *,
        shell: str,
        setup: str,
        root_variable: str,
    ) -> None:
        for signal_name, expected_status in (("HUP", 129), ("INT", 130), ("TERM", 143)):
            with self.subTest(shell=Path(shell).name, signal=signal_name):
                record = self.tmp / f"{Path(shell).name}-{root_variable}-{signal_name}.root"
                continued = self.tmp / f"{Path(shell).name}-{root_variable}-{signal_name}.continued"
                script = (
                    "set -eu\n"
                    + setup
                    + "\n"
                    + block
                    + f'\nprintf "%s\\n" "${{{root_variable}}}" >"{record}"\n'
                    + f"kill -{signal_name} $$\n"
                    + f'printf "continued\\n" >"{continued}"\n'
                )
                result = subprocess.run(
                    [shell, "-c", script],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env={**os.environ, "TMPDIR": str(self.tmp)},
                )
                self.assertTrue(record.is_file(), result.stderr)
                cleanup_root = Path(record.read_text(encoding="utf-8").strip())
                self.assertEqual(result.returncode, expected_status, result.stderr)
                self.assertFalse(continued.exists())
                self.assertFalse(cleanup_root.exists())

    def run_cleanup_root_swap(
        self,
        block: str,
        *,
        shell: str,
        setup: str,
        root_variable: str,
        sentinel_name: str,
        sentinel_content: str,
    ) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
        record = self.tmp / f"{root_variable}-swap.root"
        script = (
            "set -eu\n"
            + setup
            + "\n"
            + block
            + f'\nprintf "%s\\n" "${{{root_variable}}}" >"{record}"\n'
            + f'original="${{{root_variable}}}.original"\n'
            + f'mv "${{{root_variable}}}" "$original"\n'
            + f'mkdir -m 0700 "${{{root_variable}}}"\n'
            + f'printf "%s\\n" "{sentinel_content}" >"${{{root_variable}}}/{sentinel_name}"\n'
            + f'chmod 0600 "${{{root_variable}}}/{sentinel_name}"\n'
            + f'printf "replacement survives\\n" >"${{{root_variable}}}/victim"\n'
        )
        result = subprocess.run(
            [shell, "-c", script],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "TMPDIR": str(self.tmp)},
        )
        root = Path(record.read_text(encoding="utf-8").strip())
        return result, root, Path(f"{root}.original")

    def assert_cache_block_rejects_reassignment(
        self,
        block: str,
        *,
        setup: str,
    ) -> None:
        variables = (
            "XDG_CACHE_HOME",
            "ZIG_LOCAL_CACHE_DIR",
            "ZIG_GLOBAL_CACHE_DIR",
            "PYTHONPYCACHEPREFIX",
        )
        for variable in variables:
            with self.subTest(cache_variable=variable):
                continued = self.tmp / f"cache-{variable}.continued"
                script = (
                    "set -eu\n"
                    + setup
                    + "\n"
                    + block
                    + f'\n{variable}="$TMPDIR/redirected"\n'
                    + f'printf "continued\\n" >"{continued}"\n'
                )
                result = subprocess.run(
                    [BASH, "-c", script],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env={**os.environ, "TMPDIR": str(self.tmp)},
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(continued.exists())

    def assert_cache_block_allows_reassignment(self, block: str, *, setup: str) -> None:
        continued = self.tmp / "cache-vulnerable.continued"
        continued.unlink(missing_ok=True)
        script = (
            "set -eu\n"
            + setup
            + "\n"
            + block
            + '\nXDG_CACHE_HOME="$TMPDIR/redirected"\n'
            + f'printf "continued\\n" >"{continued}"\n'
        )
        result = subprocess.run(
            [BASH, "-c", script],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "TMPDIR": str(self.tmp)},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(continued.is_file())

    def make_git_source_repo(self, label: str) -> tuple[Path, Path, str, str]:
        repo = self.tmp / f"source-{label}"
        repo.mkdir()
        git(repo, "init", "--quiet", "--object-format=sha1")
        authority = repo / "release-manifest.json"
        authority.write_bytes((ROOT / "release-manifest.json").read_bytes())
        (repo / candidate.EXACT_REBUILD_GRAPH).write_bytes(
            (ROOT / candidate.EXACT_REBUILD_GRAPH).read_bytes()
        )
        (repo / "src").mkdir()
        (repo / "src" / "main.zig").write_text(
            "const std = @import(\"std\");\n"
            "const build_options = @import(\"build_options\");\n"
            "pub fn main() !void {\n"
            f"    try std.io.getStdOut().writer().print(\"{label} {{s}} {{s}}\\n\", .{{ build_options.version, build_options.build_id }});\n"
            "}\n",
            encoding="utf-8",
        )
        (repo / "source.txt").write_text(f"candidate source {label}\n", encoding="utf-8")
        git(repo, "add", ".")
        git(repo, "commit", "--quiet", "-m", f"candidate source {label}")
        head = git(repo, "rev-parse", "HEAD")
        tree = git(repo, "rev-parse", "HEAD^{tree}")
        return repo, authority, head, tree

    def exact_promoter(self) -> tuple[Path, candidate.ExactToolAuthority]:
        helper_text = shutil.which("omux-v02-posix-exact-promote")
        if helper_text is None:
            self.skipTest("exact promotion is available only through the generated Nix helper")
        helper = Path(helper_text)
        probe = subprocess.run(
            [str(helper), "--authority-probe"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=ROOT,
        )
        self.assertEqual(probe.returncode, 0, probe.stderr)
        paths = dict(line.split("=", 1) for line in probe.stdout.splitlines())
        self.assertEqual(set(paths), {"python", "git", "zig"})
        return helper, candidate.ExactToolAuthority(
            python=Path(paths["python"]),
            git=Path(paths["git"]),
            zig=Path(paths["zig"]),
        )

    def build_exact_graph_binary(self, repo: Path, version: str, build_id: str) -> Path:
        _, tools = self.exact_promoter()
        zig = candidate.validate_exact_tool_authority(tools).zig
        prefix = self.tmp / f"exact-build-{repo.name}-{build_id}"
        local_cache = self.tmp / f"exact-cache-{repo.name}-{build_id}"
        global_cache = self.tmp / f"exact-global-cache-{repo.name}-{build_id}"
        subprocess.run(
            [
                str(zig),
                "build",
                "--build-file",
                str(repo / candidate.EXACT_REBUILD_GRAPH),
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
            cwd=repo,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=600,
            env=os.environ.copy(),
        )
        binary = prefix / "bin" / "omux"
        self.assertTrue(binary.is_file())
        self.assertFalse(binary.is_symlink())
        return binary

    def install_archive(
        self,
        archive: Path,
        root: Path,
        candidate_id: str,
        hook: candidate.Hook | None = None,
    ) -> dict[str, str]:
        return self.install_archive_under(archive, root, self.tmp, candidate_id, hook=hook)

    def install_archive_under(
        self,
        archive: Path,
        root: Path,
        temporary_parent: Path,
        candidate_id: str,
        hook: candidate.Hook | None = None,
    ) -> dict[str, str]:
        metadata, digest = self.metadata_for(archive, candidate_id)
        return candidate.install_archive(
            archive,
            metadata,
            digest,
            root,
            temporary_parent,
            candidate_id,
            hook=hook,
        )

    def metadata_for(self, archive: Path, candidate_id: str) -> tuple[Path, str]:
        verified = candidate.verify_archive(archive)
        digest = candidate.sha256_file(archive)
        metadata = self.tmp / f"{archive.name}.{candidate_id}.json"
        metadata.write_bytes(candidate.canonical_json_bytes({
            "schema_version": 1,
            "profile": {
                "id": candidate.PROFILE_ID,
                "status": "source_contract_only",
                "implementation_role": "source_test_oracle",
                "publication_enabled": False,
                "host_install_enabled": False,
                "end_user_installer_enabled": False,
                "temporary_root_required": True,
                "rollback_enabled": False,
            },
            "candidate_binding": "local_debug_only",
            "release": {
                "version": "0.2.0-rc.0",
                "build_id": candidate_id,
                "source_commit": None,
                "source_tree": None,
            },
            "product": candidate.load_release_authority(ROOT / "release-manifest.json"),
            "build_provenance": None,
            "artifact": {
                "path": archive.name,
                "sha256": digest,
                "members": verified["members"],
            },
        }))
        return metadata, digest

    def install_command(self, archive: Path, root: Path, candidate_id: str) -> list[str]:
        metadata, digest = self.metadata_for(archive, candidate_id)
        return [
            sys.executable,
            str(MODULE_PATH),
            "install",
            "--archive", str(archive),
            "--metadata", str(metadata),
            "--authority", str(ROOT / "release-manifest.json"),
            "--expected-archive-sha256", digest,
            "--root", str(root),
            "--temporary-parent", str(self.tmp),
            "--candidate-id", candidate_id,
        ]

    def test_arbitrary_binary_cannot_materialize_candidate_archive(self) -> None:
        binary = self.tmp / "source-omux"
        binary.write_bytes(b"#!/bin/sh\necho source-contract\n")
        os.chmod(binary, 0o755)
        archive = self.tmp / "omux-test.tar.gz"
        metadata = self.tmp / "candidate.json"

        with self.assertRaises(candidate.ContractError):
            candidate.pack_archive(
                ROOT / "release-manifest.json",
                binary,
                archive,
                metadata,
                "0.2.0-rc.0",
                "source-contract-1",
                None,
            )
        self.assertFalse(archive.exists())
        self.assertFalse(metadata.exists())

    def test_exact_git_binding_requires_real_clean_head_objects(self) -> None:
        version = "0.2.1-rc.1+source.7"
        build_id = "exact-source-1"
        helper, tools = self.exact_promoter()
        tools = candidate.validate_exact_tool_authority(tools)
        repo, authority, head, tree = self.make_git_source_repo("exact-valid")
        foreign_repo, _, _, _ = self.make_git_source_repo("exact-foreign")
        candidate.verify_exact_git_source(tools, authority, head, tree)
        self.assertEqual(git(repo, "status", "--porcelain=v1", "--untracked-files=all"), "")
        matching_binary = self.build_exact_graph_binary(repo, version, build_id)
        foreign_binary = self.build_exact_graph_binary(foreign_repo, version, build_id)
        self.assertNotEqual(matching_binary.read_bytes(), foreign_binary.read_bytes())

        environment = os.environ.copy()
        for variable, executable_name in (
            ("OMUX_V02_CONTRACT_PYTHON", "python3"),
            ("OMUX_V02_CONTRACT_GIT", "git"),
            ("OMUX_V02_CONTRACT_ZIG", "zig"),
        ):
            unrelated = self.tmp / f"attacker-{executable_name}"
            unrelated.write_text("#!/bin/sh\nexit 97\n", encoding="utf-8")
            os.chmod(unrelated, 0o700)
            environment[variable] = str(unrelated)

        exact_output = self.tmp / "exact-output"
        exact_output.mkdir(mode=0o700)
        exact = subprocess.run(
            [
                str(helper),
                "pack",
                "--authority", str(authority),
                "--binary", str(matching_binary),
                "--output-dir", str(exact_output),
                "--version", version,
                "--build-id", build_id,
                "--source-commit", head,
                "--source-tree", tree,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
            cwd=ROOT,
        )
        self.assertEqual(exact.returncode, 0, exact.stderr.decode("utf-8", errors="replace"))
        metadata = json.loads((exact_output / "candidate.json").read_text(encoding="utf-8"))
        self.assertEqual(metadata["candidate_binding"], "exact_git_object")
        verified = subprocess.run(
            [
                str(helper),
                "verify",
                "--archive", str(exact_output / "omux-posix-source-contract.tar.gz"),
                "--metadata", str(exact_output / "candidate.json"),
                "--authority", str(authority),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
            cwd=ROOT,
        )
        self.assertEqual(verified.returncode, 0, verified.stderr.decode("utf-8", errors="replace"))

        mismatch_output = self.tmp / "foreign-source-mismatch-output"
        mismatch_output.mkdir(mode=0o700)
        exploit = subprocess.run(
            [
                str(helper),
                "pack",
                "--authority", str(authority),
                "--binary", str(foreign_binary),
                "--output-dir", str(mismatch_output),
                "--version", version,
                "--build-id", build_id,
                "--source-commit", head,
                "--source-tree", tree,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
            cwd=ROOT,
        )
        self.assertNotEqual(exploit.returncode, 0)
        self.assertIn(b"do not match the independent exact-source Zig rebuild", exploit.stderr)
        self.assertFalse((mismatch_output / "build-provenance.json").exists())
        self.assertFalse((mismatch_output / "candidate.json").exists())
        self.assertFalse((mismatch_output / "omux-posix-source-contract.tar.gz").exists())

        bad_cases: list[tuple[str, Path, str, str]] = []
        fake_repo, fake_authority, fake_head, fake_tree = self.make_git_source_repo("exact-fake")
        bad_cases.append(("nonexistent-commit", fake_authority, "0" * 40, fake_tree))
        bad_cases.append(("nonexistent-tree", fake_authority, fake_head, "f" * 40))

        old_repo, old_authority, old_head, old_tree = self.make_git_source_repo("exact-old-head")
        (old_repo / "source.txt").write_text("new head\n", encoding="utf-8")
        git(old_repo, "add", "source.txt")
        git(old_repo, "commit", "--quiet", "-m", "advance head")
        new_head = git(old_repo, "rev-parse", "HEAD")
        bad_cases.append(("commit-not-head", old_authority, old_head, old_tree))
        bad_cases.append(("tree-not-head", old_authority, new_head, old_tree))

        dirty_repo, dirty_authority, dirty_head, dirty_tree = self.make_git_source_repo("exact-dirty")
        (dirty_repo / "source.txt").write_text("dirty worktree\n", encoding="utf-8")
        bad_cases.append(("dirty-worktree", dirty_authority, dirty_head, dirty_tree))

        staged_repo, staged_authority, staged_head, staged_tree = self.make_git_source_repo("exact-staged")
        (staged_repo / "source.txt").write_text("dirty index\n", encoding="utf-8")
        git(staged_repo, "add", "source.txt")
        bad_cases.append(("dirty-index", staged_authority, staged_head, staged_tree))

        untracked_repo, untracked_authority, untracked_head, untracked_tree = self.make_git_source_repo(
            "exact-untracked"
        )
        (untracked_repo / "untracked.txt").write_text("untracked\n", encoding="utf-8")
        bad_cases.append(("untracked", untracked_authority, untracked_head, untracked_tree))

        for label, case_authority, case_commit, case_tree in bad_cases:
            with self.subTest(label=label):
                with self.assertRaises(candidate.ContractError):
                    candidate.verify_exact_git_source(
                        tools,
                        case_authority,
                        case_commit,
                        case_tree,
                    )

        raw_output = self.tmp / "raw-exact-output"
        raw = subprocess.run(
            [
                str(tools.python),
                str(MODULE_PATH),
                "_pack-zig-lazy-path",
                "--authority", str(authority),
                "--binary", str(matching_binary),
                "--output-dir", str(raw_output),
                "--version", version,
                "--build-id", build_id,
                "--source-commit", head,
                "--source-tree", tree,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            env=environment,
            cwd=ROOT,
        )
        self.assertEqual(raw.returncode, 2)
        self.assertFalse(raw_output.exists())

    def test_exact_git_binding_ignores_ambient_repo_and_object_controls(self) -> None:
        _, tools = self.exact_promoter()
        tools = candidate.validate_exact_tool_authority(tools)
        repo_a, authority_a, head_a, tree_a = self.make_git_source_repo("ambient-a")
        repo_b, _, head_b, tree_b = self.make_git_source_repo("ambient-b")
        attack_config = self.tmp / "ambient-attack.gitconfig"
        attack_config.write_text(f"[core]\n\tworktree = {repo_b}\n", encoding="utf-8")
        attack_environment = {
            "GIT_DIR": str(repo_b / ".git"),
            "GIT_WORK_TREE": str(repo_b),
            "GIT_INDEX_FILE": str(repo_b / ".git" / "index"),
            "GIT_OBJECT_DIRECTORY": str(repo_b / ".git" / "objects"),
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(repo_b / ".git" / "objects"),
            "GIT_COMMON_DIR": str(repo_b / ".git"),
            "GIT_CONFIG_GLOBAL": str(attack_config),
            "GIT_CONFIG_SYSTEM": str(attack_config),
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.worktree",
            "GIT_CONFIG_VALUE_0": str(repo_b),
            "GIT_NAMESPACE": "ambient-attack",
            "GIT_REPLACE_REF_BASE": "refs/replace/ambient",
        }
        with mock.patch.dict(os.environ, attack_environment, clear=False):
            candidate.verify_exact_git_source(tools, authority_a, head_a, tree_a)
            with self.assertRaises(candidate.ContractError):
                candidate.verify_exact_git_source(tools, authority_a, head_b, tree_b)

        alternates = repo_a / ".git" / "objects" / "info" / "alternates"
        alternates.write_text(str(repo_b / ".git" / "objects") + "\n", encoding="utf-8")
        with self.assertRaises(candidate.ContractError):
            candidate.verify_exact_git_source(tools, authority_a, head_a, tree_a)

    def test_candidate_versions_match_zig_v02_prerelease_contract(self) -> None:
        accepted = (
            "0.2.0-rc.0",
            "0.2.1-beta",
            "0.2.0-0",
            "0.2.3-rc-1+build.001",
            "0.2.999-alpha.1+build-7",
            "0.2.0--",
        )
        rejected: tuple[object, ...] = (
            None,
            2,
            "0.2.0",
            "0.2.0+build",
            "0.3.0-rc.1",
            "1.2.0-rc.1",
            "0.2-rc.1",
            "00.2.0-rc.1",
            "0.02.0-rc.1",
            "0.2.00-rc.1",
            "0.2.0-01",
            "0.2.0-rc..1",
            "0.2.0-rc_1",
            "0.2.0-rc+",
            "0.2.0-r\u00e9sum\u00e9",
            f"0.2.{candidate.MAX_USIZE + 1}-rc.1",
            f"0.2.0-{candidate.MAX_USIZE + 1}",
        )
        for version in accepted:
            with self.subTest(accepted=version):
                self.assertEqual(candidate.validate_v02_prerelease(version), version)
        for version in rejected:
            with self.subTest(rejected=version):
                with self.assertRaises(candidate.ContractError):
                    candidate.validate_v02_prerelease(version)

    def test_exact_metadata_requires_revalidated_graph_provenance(self) -> None:
        _, authority, head, tree = self.make_git_source_repo("metadata-exact")
        archive = self.tmp / "metadata-exact.tar.gz"
        valid_archive(archive, b"exact-looking pair\n")
        metadata, _ = self.metadata_for(archive, "metadata-exact")
        document = json.loads(metadata.read_text(encoding="utf-8"))
        document["candidate_binding"] = "exact_git_object"
        document["release"]["source_commit"] = head
        document["release"]["source_tree"] = tree
        document["build_provenance"] = None
        metadata.write_bytes(candidate.canonical_json_bytes(document))

        with self.assertRaises(candidate.ContractError):
            candidate.verify_metadata(archive, metadata, authority)

    def test_json_booleans_reject_numeric_aliases(self) -> None:
        archive = self.tmp / "boolean-types.tar.gz"
        valid_archive(archive, b"boolean pair\n")
        metadata, _ = self.metadata_for(archive, "boolean-types")
        base_metadata = json.loads(metadata.read_text(encoding="utf-8"))
        for field, replacement in (
            ("end_user_installer_enabled", 0),
            ("host_install_enabled", 0),
            ("publication_enabled", 0),
            ("rollback_enabled", 0),
            ("temporary_root_required", 1),
        ):
            with self.subTest(metadata_field=field):
                changed = json.loads(json.dumps(base_metadata))
                changed["profile"][field] = replacement
                metadata.write_bytes(candidate.canonical_json_bytes(changed))
                with self.assertRaises(candidate.ContractError):
                    candidate.verify_metadata(
                        archive,
                        metadata,
                        ROOT / "release-manifest.json",
                    )

        provenance = {
            "schema_version": 1,
            "profile": {
                "id": candidate.PROVENANCE_PROFILE_ID,
                "producer": "named_graph_local_debug",
                "source_contract_only": True,
                "install_enabled": False,
                "publication_enabled": False,
            },
            "source": {
                "binding": "local_debug_only",
                "commit": None,
                "tree": None,
            },
            "build": {
                "version": "0.2.0-rc.0",
                "build_id": "boolean-types",
                "root_source": "src/main.zig",
                "optimize": "ReleaseSafe",
                "install_step": False,
                "candidate_step": "build.zig:v02-posix-source-candidate",
            },
            "binary": {
                "sha256": "a" * 64,
                "size": 1,
            },
            "exact_rebuild": None,
        }
        provenance["binding_sha256"] = candidate.provenance_binding_sha256(provenance)
        mutations = (
            (("schema_version",), True),
            (("profile", "source_contract_only"), 1),
            (("profile", "install_enabled"), 0),
            (("profile", "publication_enabled"), 0),
            (("build", "install_step"), 0),
        )
        for path, replacement in mutations:
            with self.subTest(provenance_field=".".join(path)):
                changed = json.loads(json.dumps(provenance))
                target = changed
                for component in path[:-1]:
                    target = target[component]
                target[path[-1]] = replacement
                changed["binding_sha256"] = candidate.provenance_binding_sha256(changed)
                with self.assertRaises(candidate.ContractError):
                    candidate.validate_build_provenance(
                        changed,
                        ROOT / "release-manifest.json",
                    )

    def test_candidate_metadata_is_canonical_duplicate_free_and_closed_schema(self) -> None:
        archive = self.tmp / "closed-metadata.tar.gz"
        valid_archive(archive, b"closed metadata pair\n")
        metadata, _ = self.metadata_for(archive, "closed-metadata")
        canonical_document = json.loads(metadata.read_text(encoding="utf-8"))

        for label, mutate in (
            (
                "unknown-top-level",
                lambda document: document.update({
                    "publication_enabled": True,
                    "host_install_enabled": True,
                    "forged_signature": "trusted",
                }),
            ),
            (
                "unknown-artifact",
                lambda document: document["artifact"].update({
                    "future_interpretation": "trusted",
                }),
            ),
        ):
            with self.subTest(label=label):
                changed = json.loads(json.dumps(canonical_document))
                mutate(changed)
                metadata.write_bytes(candidate.canonical_json_bytes(changed))
                with self.assertRaisesRegex(candidate.ContractError, "unknown authority fields"):
                    candidate.verify_metadata(
                        archive,
                        metadata,
                        ROOT / "release-manifest.json",
                    )

        metadata.write_text(
            json.dumps(canonical_document, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(candidate.ContractError, "canonical JSON"):
            candidate.verify_metadata(
                archive,
                metadata,
                ROOT / "release-manifest.json",
            )

        duplicate = candidate.canonical_json_bytes(canonical_document).replace(
            b"{\n",
            b'{\n  "schema_version": 1,\n',
            1,
        )
        metadata.write_bytes(duplicate)
        with self.assertRaisesRegex(candidate.ContractError, "duplicate object key: schema_version"):
            candidate.verify_metadata(
                archive,
                metadata,
                ROOT / "release-manifest.json",
            )

    def test_metadata_binds_complete_product_authority(self) -> None:
        archive = self.tmp / "product-authority.tar.gz"
        valid_archive(archive, b"product authority pair\n")
        metadata, digest = self.metadata_for(archive, "product-authority")
        document = json.loads(metadata.read_text(encoding="utf-8"))
        document["product"]["package_name"] = "forged-package"
        metadata.write_bytes(candidate.canonical_json_bytes(document))

        root = self.tmp / "product-authority-root"
        make_root(root)
        with self.assertRaises(candidate.ContractError):
            candidate.install_archive(
                archive,
                metadata,
                digest,
                root,
                self.tmp,
                "product-authority",
            )
        self.assertFalse((root / "current").exists())

    def test_rejects_every_malformed_archive_class(self) -> None:
        payload = b"#!/bin/sh\nexit 0\n"
        cases = {
            "duplicate": [
                {"name": "omux", "payload": payload},
                {"name": "omux", "payload": payload},
            ],
            "extra": [
                {"name": "omux", "payload": payload},
                {"name": "oauth-mux", "payload": payload},
                {"name": "extra", "payload": payload},
            ],
            "nested": [
                {"name": "bin/omux", "payload": payload},
                {"name": "oauth-mux", "payload": payload},
            ],
            "absolute": [
                {"name": "/omux", "payload": payload},
                {"name": "oauth-mux", "payload": payload},
            ],
            "traversal": [
                {"name": "../omux", "payload": payload},
                {"name": "oauth-mux", "payload": payload},
            ],
            "symlink": [
                {"name": "omux", "type": tarfile.SYMTYPE, "linkname": "oauth-mux"},
                {"name": "oauth-mux", "payload": payload},
            ],
            "hardlink": [
                {"name": "omux", "type": tarfile.LNKTYPE, "linkname": "oauth-mux"},
                {"name": "oauth-mux", "payload": payload},
            ],
            "fifo": [
                {"name": "omux", "type": tarfile.FIFOTYPE},
                {"name": "oauth-mux", "payload": payload},
            ],
            "directory": [
                {"name": "omux", "type": tarfile.DIRTYPE},
                {"name": "oauth-mux", "payload": payload},
            ],
            "non-executable": [
                {"name": "omux", "payload": payload, "mode": 0o644},
                {"name": "oauth-mux", "payload": payload},
            ],
        }
        for label, entries in cases.items():
            with self.subTest(label=label):
                archive = self.tmp / f"{label}.tar.gz"
                write_archive(archive, entries)
                with self.assertRaises(candidate.ContractError):
                    candidate.verify_archive(archive)

        truncated = self.tmp / "truncated.tar.gz"
        valid_archive(truncated, payload)
        raw = truncated.read_bytes()
        truncated.write_bytes(raw[: len(raw) // 2])
        with self.assertRaises(candidate.ContractError):
            candidate.verify_archive(truncated)

    def test_rejects_trailing_gzip_and_tar_bytes(self) -> None:
        archive = self.tmp / "canonical.tar.gz"
        valid_archive(archive, b"canonical pair\n")
        canonical_bytes = archive.read_bytes()

        noncanonical = self.tmp / "noncanonical.tar.gz"
        write_archive(noncanonical, [
            {"name": "omux", "payload": b"canonical pair\n"},
            {"name": "oauth-mux", "payload": b"canonical pair\n"},
        ])
        with self.assertRaises(candidate.ContractError):
            candidate.verify_archive(noncanonical)

        archive.write_bytes(canonical_bytes + b"trailing-gzip-bytes")
        with self.assertRaises(candidate.ContractError):
            candidate.verify_archive(archive)

        tar_bytes = gzip.decompress(canonical_bytes)
        wrapped = io.BytesIO()
        with gzip.GzipFile(filename="", mode="wb", fileobj=wrapped, compresslevel=9, mtime=0) as stream:
            stream.write(tar_bytes + b"trailing-tar-bytes")
        archive.write_bytes(wrapped.getvalue())
        with self.assertRaises(candidate.ContractError):
            candidate.verify_archive(archive)

    def test_install_pins_verified_archive_descriptor_and_expected_digest(self) -> None:
        archive = self.tmp / "pinned.tar.gz"
        valid_archive(archive, b"pinned original pair\n")
        metadata, digest = self.metadata_for(archive, "pinned")
        replacement = self.tmp / "replacement.tar.gz"
        valid_archive(replacement, b"replacement pair\n")
        displaced = self.tmp / "pinned-original.tar.gz"
        root = self.tmp / "pinned-root"
        make_root(root)

        mismatch_root = self.tmp / "digest-mismatch-root"
        make_root(mismatch_root)
        with self.assertRaises(candidate.ContractError):
            candidate.install_archive(
                archive,
                metadata,
                "0" * 64,
                mismatch_root,
                self.tmp,
                "pinned",
            )
        self.assertFalse((mismatch_root / "current").exists())

        bad_metadata = self.tmp / "bad-candidate.json"
        bad_document = json.loads(metadata.read_text(encoding="utf-8"))
        bad_document["artifact"]["members"][0]["sha256"] = "f" * 64
        bad_metadata.write_bytes(candidate.canonical_json_bytes(bad_document))
        bad_metadata_root = self.tmp / "bad-metadata-root"
        make_root(bad_metadata_root)
        with self.assertRaises(candidate.ContractError):
            candidate.install_archive(
                archive,
                bad_metadata,
                digest,
                bad_metadata_root,
                self.tmp,
                "pinned",
            )
        self.assertFalse((bad_metadata_root / "current").exists())

        def replace_archive(point: str) -> None:
            if point != "after_archive_open":
                return
            archive.rename(displaced)
            replacement.rename(archive)

        candidate.install_archive(
            archive,
            metadata,
            digest,
            root,
            self.tmp,
            "pinned",
            hook=replace_archive,
        )
        self.assertEqual(current_pair(root)[1], b"pinned original pair\n")
        self.assertEqual(archive.read_bytes(), candidate.canonical_archive_bytes({
            "omux": b"replacement pair\n",
            "oauth-mux": b"replacement pair\n",
        }))

    def test_transactional_upgrade_preserves_stable_aliases_and_native_codex(self) -> None:
        root = self.tmp / "candidate-root"
        make_root(root)
        stable = self.tmp / "stable-bin"
        stable.mkdir()
        stable_payloads = {
            "omux": b"nix omux 0.1.15\n",
            "oauth-mux": b"homebrew oauth-mux 0.1.14\n",
            "codex": b"native codex sentinel\n",
        }
        before: dict[str, tuple[bytes, int, int, int]] = {}
        for name, payload in stable_payloads.items():
            path = stable / name
            path.write_bytes(payload)
            os.chmod(path, 0o751)
            info = path.stat()
            before[name] = (payload, stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid)

        old_archive = self.tmp / "old.tar.gz"
        new_archive = self.tmp / "new.tar.gz"
        valid_archive(old_archive, b"old complete pair\n")
        valid_archive(new_archive, b"new complete pair\n")
        self.install_archive(old_archive, root, "rc-old")
        self.install_archive(old_archive, root, "rc-old")
        self.install_archive(new_archive, root, "rc-new")

        target, primary, compatibility = current_pair(root)
        self.assertEqual(target, "generations/rc-new")
        self.assertEqual(primary, b"new complete pair\n")
        self.assertEqual(primary, compatibility)
        self.assertTrue((root / "generations" / "rc-old").is_dir())
        self.assertTrue((root / "generations" / "rc-new").is_dir())
        for name, expected in before.items():
            path = stable / name
            info = path.stat()
            self.assertEqual(
                (path.read_bytes(), stat.S_IMODE(info.st_mode), info.st_uid, info.st_gid),
                expected,
            )

    def test_failure_and_term_leave_only_complete_old_or_new_pair_visible(self) -> None:
        old_archive = self.tmp / "old.tar.gz"
        new_archive = self.tmp / "new.tar.gz"
        valid_archive(old_archive, b"old pair\n")
        valid_archive(new_archive, b"new pair\n")
        points = (
            "after_archive_open",
            "after_lock_acquire",
            "after_stage_create",
            "after_omux_write",
            "after_oauth_mux_write",
            "before_generation_commit",
            "after_generation_commit",
            "before_pointer_swap",
            "after_pointer_swap",
        )
        for mode in ("FAILPOINT", "TERMPOINT"):
            for point in points:
                with self.subTest(mode=mode, point=point):
                    root = self.tmp / f"root-{mode.lower()}-{point}"
                    make_root(root)
                    self.install_archive(old_archive, root, "old")
                    env = os.environ.copy()
                    env[f"OMUX_V02_INSTALL_{mode}"] = point
                    result = subprocess.run(
                        self.install_command(new_archive, root, "new"),
                        env=env,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    target, primary, compatibility = current_pair(root)
                    self.assertEqual(
                        target,
                        "generations/new" if point == "after_pointer_swap" else "generations/old",
                    )
                    self.assertEqual(primary, compatibility)
                    self.assertEqual(
                        primary,
                        b"new pair\n" if point == "after_pointer_swap" else b"old pair\n",
                    )

    def test_next_serialized_run_cleans_interrupted_private_stage(self) -> None:
        root = self.tmp / "stale-stage-root"
        make_root(root)
        old_archive = self.tmp / "stale-old.tar.gz"
        new_archive = self.tmp / "stale-new.tar.gz"
        valid_archive(old_archive, b"old pair\n")
        valid_archive(new_archive, b"new pair\n")
        self.install_archive(old_archive, root, "old")

        env = os.environ.copy()
        env["OMUX_V02_INSTALL_TERMPOINT"] = "after_omux_write"
        result = subprocess.run(
            self.install_command(new_archive, root, "new"),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        stale = [path for path in (root / "generations").iterdir() if path.name.startswith(".staging-")]
        self.assertEqual(len(stale), 1)
        self.assertEqual(current_pair(root)[0], "generations/old")

        self.install_archive(new_archive, root, "new")
        self.assertEqual(
            [path for path in (root / "generations").iterdir() if path.name.startswith(".staging-")],
            [],
        )
        target, primary, compatibility = current_pair(root)
        self.assertEqual(target, "generations/new")
        self.assertEqual(primary, compatibility)
        self.assertEqual(primary, b"new pair\n")

    def test_next_serialized_run_cleans_pre_swap_term_pointer(self) -> None:
        root = self.tmp / "stale-pointer-root"
        make_root(root)
        old_archive = self.tmp / "pointer-old.tar.gz"
        new_archive = self.tmp / "pointer-new.tar.gz"
        valid_archive(old_archive, b"old pair\n")
        valid_archive(new_archive, b"new pair\n")
        self.install_archive(old_archive, root, "old")

        environment = os.environ.copy()
        environment["OMUX_V02_INSTALL_TERMPOINT"] = "before_pointer_swap"
        result = subprocess.run(
            self.install_command(new_archive, root, "new"),
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        residue = [path for path in root.iterdir() if path.name.startswith(".current-")]
        self.assertEqual(len(residue), 1)
        self.assertTrue(residue[0].is_symlink())
        self.assertEqual(current_pair(root)[0], "generations/old")

        self.install_archive(new_archive, root, "new")
        self.assertEqual(
            [path for path in root.iterdir() if path.name.startswith(".current-")],
            [],
        )
        target, primary, compatibility = current_pair(root)
        self.assertEqual(target, "generations/new")
        self.assertEqual(primary, b"new pair\n")
        self.assertEqual(primary, compatibility)

    def test_stale_stage_cleanup_rejects_foreign_links(self) -> None:
        root = self.tmp / "unsafe-stale-stage-root"
        make_root(root)
        generations = root / "generations"
        generations.mkdir(mode=0o700)
        stage = generations / ".staging-foreign"
        stage.mkdir(mode=0o700)
        target = self.tmp / "foreign-target"
        target.write_bytes(b"do not touch\n")
        (stage / "omux").symlink_to(target)

        archive = self.tmp / "unsafe-stale-stage.tar.gz"
        valid_archive(archive, b"new pair\n")
        with self.assertRaises(candidate.ContractError):
            self.install_archive(archive, root, "new")
        self.assertEqual(target.read_bytes(), b"do not touch\n")
        self.assertTrue((stage / "omux").is_symlink())
        self.assertFalse((root / "current").exists())

    def test_stale_stage_cleanup_never_deletes_replaced_parent_or_name(self) -> None:
        archive = self.tmp / "stale-race.tar.gz"
        valid_archive(archive, b"new pair\n")

        for point in ("before_stale_stage_delete", "before_stale_stage_rmdir"):
            with self.subTest(point=point):
                root = self.tmp / f"stale-race-{point}"
                make_root(root)
                generations = root / "generations"
                generations.mkdir(mode=0o700)
                stage = generations / ".staging-old"
                stage.mkdir(mode=0o700)
                moved = self.tmp / f"moved-{point}"
                replacement_marker = b"replacement must survive\n"

                def replace_stage(actual_point: str) -> None:
                    if actual_point != point:
                        return
                    stage.rename(moved)
                    stage.mkdir(mode=0o700)
                    (stage / "replacement").write_bytes(replacement_marker)

                with self.assertRaises(candidate.ContractError):
                    self.install_archive(archive, root, "new", hook=replace_stage)
                self.assertEqual((stage / "replacement").read_bytes(), replacement_marker)
                self.assertTrue(moved.is_dir())
                self.assertFalse((root / "current").exists())

        parent_root = self.tmp / "stale-parent-race"
        make_root(parent_root)
        generations = parent_root / "generations"
        generations.mkdir(mode=0o700)
        (generations / ".staging-old").mkdir(mode=0o700)
        moved_parent = self.tmp / "stale-generations-original"

        def replace_parent(point: str) -> None:
            if point != "before_stale_stage_delete":
                return
            generations.rename(moved_parent)
            generations.mkdir(mode=0o700)
            replacement = generations / ".staging-old"
            replacement.mkdir(mode=0o700)
            (replacement / "replacement").write_bytes(b"parent replacement survives\n")

        with self.assertRaises(candidate.ContractError):
            self.install_archive(archive, parent_root, "new", hook=replace_parent)
        self.assertEqual(
            (generations / ".staging-old" / "replacement").read_bytes(),
            b"parent replacement survives\n",
        )
        self.assertTrue(moved_parent.is_dir())

        member_root = self.tmp / "stale-member-race"
        make_root(member_root)
        member_generations = member_root / "generations"
        member_generations.mkdir(mode=0o700)
        member_stage = member_generations / ".staging-old"
        member_stage.mkdir(mode=0o700)
        member = member_stage / "omux"
        member.write_bytes(b"original stale member\n")
        os.chmod(member, 0o755)
        displaced_member = self.tmp / "stale-member-original"

        def replace_member(point: str) -> None:
            if point != "before_stale_stage_member_unlink":
                return
            member.rename(displaced_member)
            member.write_bytes(b"replacement member survives\n")
            os.chmod(member, 0o755)

        with self.assertRaises(candidate.ContractError):
            self.install_archive(archive, member_root, "new", hook=replace_member)
        self.assertEqual(member.read_bytes(), b"replacement member survives\n")
        self.assertEqual(displaced_member.read_bytes(), b"original stale member\n")

    def test_generation_members_are_pinned_and_revalidated_before_publication(self) -> None:
        archive = self.tmp / "generation-pin.tar.gz"
        valid_archive(archive, b"generation pair\n")

        for mutation in ("bytes", "pathname"):
            with self.subTest(mutation=mutation):
                root = self.tmp / f"generation-pin-{mutation}"
                make_root(root)
                old_archive = self.tmp / f"generation-old-{mutation}.tar.gz"
                valid_archive(old_archive, b"old pair\n")
                self.install_archive(old_archive, root, f"old-{mutation}")

                def mutate_generation(point: str) -> None:
                    if point != "before_pointer_swap":
                        return
                    member = root / "generations" / f"new-{mutation}" / "omux"
                    if mutation == "bytes":
                        member.write_bytes(b"mutated bytes\n")
                        os.chmod(member, 0o755)
                    else:
                        member.rename(self.tmp / f"omux-displaced-{mutation}")
                        member.write_bytes(b"generation pair\n")
                        os.chmod(member, 0o755)

                with self.assertRaises(candidate.ContractError):
                    self.install_archive(
                        archive,
                        root,
                        f"new-{mutation}",
                        hook=mutate_generation,
                    )
                self.assertEqual(current_pair(root)[0], f"generations/old-{mutation}")

    def test_concurrent_installers_serialize(self) -> None:
        root = self.tmp / "concurrent-root"
        make_root(root)
        first_archive = self.tmp / "first.tar.gz"
        second_archive = self.tmp / "second.tar.gz"
        valid_archive(first_archive, b"first pair\n")
        valid_archive(second_archive, b"second pair\n")

        ready_r, ready_w = os.pipe()
        release_r, release_w = os.pipe()
        first_env = os.environ.copy()
        first_env["OMUX_V02_INSTALL_TEST_LOCK_READY_FD"] = str(ready_w)
        first_env["OMUX_V02_INSTALL_TEST_LOCK_RELEASE_FD"] = str(release_r)
        first_command = self.install_command(first_archive, root, "first")
        second_command = self.install_command(second_archive, root, "second")
        first = subprocess.Popen(
            first_command,
            env=first_env,
            pass_fds=(ready_w, release_r),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        os.close(ready_w)
        os.close(release_r)
        self.assertEqual(os.read(ready_r, 1), b"1")
        second = subprocess.Popen(
            second_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        os.write(release_w, b"1")
        os.close(release_w)
        os.close(ready_r)
        first_out, first_err = first.communicate(timeout=30)
        second_out, second_err = second.communicate(timeout=30)
        self.assertEqual(first.returncode, 0, (first_out, first_err))
        self.assertEqual(second.returncode, 0, (second_out, second_err))
        target, primary, compatibility = current_pair(root)
        self.assertEqual(target, "generations/second")
        self.assertEqual(primary, b"second pair\n")
        self.assertEqual(primary, compatibility)

    def test_symlinked_root_parent_destinations_and_pointer_fail_closed(self) -> None:
        archive = self.tmp / "candidate.tar.gz"
        valid_archive(archive, b"candidate pair\n")
        real_root = self.tmp / "real-root"
        make_root(real_root)

        root_link = self.tmp / "root-link"
        root_link.symlink_to(real_root, target_is_directory=True)
        with self.assertRaises(OSError):
            self.install_archive(archive, root_link, "rc1")

        real_parent = self.tmp / "real-parent"
        real_parent.mkdir()
        nested_root = real_parent / "root"
        make_root(nested_root)
        parent_link = self.tmp / "parent-link"
        parent_link.symlink_to(real_parent, target_is_directory=True)
        with self.assertRaises(OSError):
            self.install_archive(archive, parent_link / "root", "rc1")

        generations_target = self.tmp / "generations-target"
        generations_target.mkdir()
        (real_root / "generations").symlink_to(generations_target, target_is_directory=True)
        with self.assertRaises(OSError):
            self.install_archive(archive, real_root, "rc1")
        (real_root / "generations").unlink()

        (real_root / "current").write_text("not a managed pointer\n", encoding="utf-8")
        with self.assertRaises(candidate.ContractError):
            self.install_archive(archive, real_root, "rc1")

        outside_context = tempfile.TemporaryDirectory(
            prefix="omux-v02-outside-parent.",
            dir=safe_temp_parent(),
        )
        try:
            outside_root = Path(outside_context.name) / "candidate-root"
            make_root(outside_root)
            with self.assertRaises(candidate.ContractError):
                self.install_archive_under(archive, outside_root, self.tmp, "rc1")
        finally:
            outside_context.cleanup()

    def test_root_generations_sentinel_and_lock_require_private_current_user_custody(self) -> None:
        archive = self.tmp / "custody.tar.gz"
        valid_archive(archive, b"candidate pair\n")

        permissive_root = self.tmp / "permissive-root"
        make_root(permissive_root)
        os.chmod(permissive_root, 0o755)
        with self.assertRaises(candidate.ContractError):
            self.install_archive(archive, permissive_root, "rc1")

        permissive_sentinel = self.tmp / "permissive-sentinel"
        make_root(permissive_sentinel)
        os.chmod(permissive_sentinel / candidate.ROOT_SENTINEL, 0o644)
        with self.assertRaises(candidate.ContractError):
            self.install_archive(archive, permissive_sentinel, "rc1")

        permissive_generations = self.tmp / "permissive-generations"
        make_root(permissive_generations)
        (permissive_generations / "generations").mkdir(mode=0o755)
        with self.assertRaises(candidate.ContractError):
            self.install_archive(archive, permissive_generations, "rc1")

        permissive_lock = self.tmp / "permissive-lock"
        make_root(permissive_lock)
        (permissive_lock / ".install.lock").write_bytes(b"")
        os.chmod(permissive_lock / ".install.lock", 0o666)
        with self.assertRaises(candidate.ContractError):
            self.install_archive(archive, permissive_lock, "rc1")

        linked_lock = self.tmp / "linked-lock"
        make_root(linked_lock)
        lock_source = linked_lock / "lock-source"
        lock_source.write_bytes(b"")
        os.chmod(lock_source, 0o600)
        os.link(lock_source, linked_lock / ".install.lock")
        with self.assertRaises(candidate.ContractError):
            self.install_archive(archive, linked_lock, "rc1")

        fifo_lock = self.tmp / "fifo-lock"
        make_root(fifo_lock)
        os.mkfifo(fifo_lock / ".install.lock", 0o600)
        with self.assertRaises(candidate.ContractError):
            self.install_archive(archive, fifo_lock, "rc1")

        permissive_parent = self.tmp / "permissive-parent"
        permissive_parent.mkdir(mode=0o755)
        parent_root = permissive_parent / "candidate-root"
        make_root(parent_root)
        with self.assertRaises(candidate.ContractError):
            self.install_archive_under(archive, parent_root, permissive_parent, "rc1")

    def test_preexisting_visible_generation_must_be_one_owned_complete_pair(self) -> None:
        archive = self.tmp / "visible-pair.tar.gz"
        valid_archive(archive, b"new pair\n")

        mixed_root = self.tmp / "mixed-visible-root"
        make_root(mixed_root)
        (mixed_root / "generations").mkdir(mode=0o700)
        mixed_generation = mixed_root / "generations" / "old"
        mixed_generation.mkdir(mode=0o700)
        for name, payload in (("omux", b"old a\n"), ("oauth-mux", b"old b\n")):
            path = mixed_generation / name
            path.write_bytes(payload)
            os.chmod(path, 0o755)
        (mixed_root / "current").symlink_to("generations/old")
        with self.assertRaises(candidate.ContractError):
            self.install_archive(archive, mixed_root, "new")

        linked_root = self.tmp / "linked-visible-root"
        make_root(linked_root)
        (linked_root / "generations").mkdir(mode=0o700)
        linked_generation = linked_root / "generations" / "old"
        linked_generation.mkdir(mode=0o700)
        source = linked_root / "source-binary"
        source.write_bytes(b"old pair\n")
        os.chmod(source, 0o755)
        os.link(source, linked_generation / "omux")
        os.link(source, linked_generation / "oauth-mux")
        (linked_root / "current").symlink_to("generations/old")
        with self.assertRaises(candidate.ContractError):
            self.install_archive(archive, linked_root, "new")

    def test_lock_path_replacement_is_detected_after_flock(self) -> None:
        archive = self.tmp / "lock-race.tar.gz"
        valid_archive(archive, b"candidate pair\n")
        root = self.tmp / "lock-race-root"
        make_root(root)

        def replace_lock(point: str) -> None:
            if point != "after_lock_acquire":
                return
            (root / ".install.lock").unlink()
            (root / ".install.lock").write_bytes(b"")
            os.chmod(root / ".install.lock", 0o600)

        with self.assertRaises(candidate.ContractError):
            self.install_archive(archive, root, "rc1", hook=replace_lock)
        self.assertFalse((root / "current").exists())
        self.assertFalse((root / "generations").exists())

    def test_root_replacement_race_is_detected_before_commit(self) -> None:
        archive = self.tmp / "candidate.tar.gz"
        valid_archive(archive, b"candidate pair\n")
        root = self.tmp / "race-root"
        make_root(root)
        moved = self.tmp / "race-root-original"
        attacker = self.tmp / "attacker"
        attacker.mkdir()

        def replace_root(point: str) -> None:
            if point != "before_generation_commit":
                return
            root.rename(moved)
            root.symlink_to(attacker, target_is_directory=True)

        try:
            with self.assertRaises(OSError):
                self.install_archive(archive, root, "rc1", hook=replace_root)
            self.assertEqual(list(attacker.iterdir()), [])
        finally:
            if root.is_symlink():
                root.unlink()
            if moved.exists():
                moved.rename(root)

    def test_generation_parent_symlink_race_is_detected_before_pointer_swap(self) -> None:
        archive = self.tmp / "candidate.tar.gz"
        valid_archive(archive, b"candidate pair\n")
        root = self.tmp / "generation-race-root"
        make_root(root)
        moved = self.tmp / "generations-original"
        attacker = self.tmp / "generation-attacker"
        attacker.mkdir()

        def replace_generations(point: str) -> None:
            if point != "before_pointer_swap":
                return
            (root / "generations").rename(moved)
            (root / "generations").symlink_to(attacker, target_is_directory=True)

        try:
            with self.assertRaises(OSError):
                self.install_archive(archive, root, "rc1", hook=replace_generations)
            self.assertFalse((root / "current").exists())
            self.assertEqual(list(attacker.iterdir()), [])
        finally:
            if (root / "generations").is_symlink():
                (root / "generations").unlink()
            if moved.exists():
                moved.rename(root / "generations")

    def test_contract_cache_exports_reject_runtime_reassignment(self) -> None:
        inner = (ROOT / "scripts" / "v02-posix-install-contract-inner.sh.in").read_text(
            encoding="utf-8"
        )
        check_local = (ROOT / "scripts" / "check-local.sh").read_text(encoding="utf-8")
        readonly_inner = (
            "readonly XDG_CACHE_HOME ZIG_LOCAL_CACHE_DIR ZIG_GLOBAL_CACHE_DIR "
            "PYTHONPYCACHEPREFIX"
        )

        inner_start = inner.index('zig_local_cache="$tmp/zig-local-cache"')
        inner_end = inner.index("\n\nrun_zig()", inner_start)
        inner_block = inner[inner_start:inner_end]
        inner_setup = 'tmp="$(mktemp -d "$TMPDIR/inner.XXXXXX")"; chmod 0700 "$tmp"'
        self.assertIn(readonly_inner, inner_block)
        self.assert_cache_block_rejects_reassignment(inner_block, setup=inner_setup)
        self.assert_cache_block_allows_reassignment(
            inner_block.replace(readonly_inner, ":", 1),
            setup=inner_setup,
        )

        custody = self.shell_function(check_local, "bind_python_cache_custody")
        self.assertIn('PYTHONPYCACHEPREFIX="$PYTHON_CACHE_ROOT/bytecode"', custody)
        self.assertIn('XDG_CACHE_HOME="$PYTHON_CACHE_ROOT/xdg-cache"', custody)
        self.assertIn("export PYTHONPYCACHEPREFIX XDG_CACHE_HOME", custody)
        self.assertIn(
            "readonly PYTHON_CACHE_ROOT PYTHONPYCACHEPREFIX XDG_CACHE_HOME PYTHON_CACHE_SENTINEL",
            custody,
        )

        module_root = self.tmp / "transitive-module"
        module_root.mkdir(mode=0o700)
        (module_root / "omux_transitive_probe.py").write_text("VALUE = 7\n", encoding="utf-8")
        record = self.tmp / "transitive-environment.json"
        driver = self.tmp / "transitive-driver.py"
        driver.write_text(
            "import json, os, subprocess, sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "import omux_transitive_probe\n"
            "subprocess.run([sys.executable, '-c', "
            "'import json, os, sys; sys.path.insert(0, sys.argv[1]); import omux_transitive_probe; '"
            "+ 'open(sys.argv[2], \\\"w\\\").write(json.dumps({k: os.environ[k] for k in (\\\"PYTHONPYCACHEPREFIX\\\", \\\"XDG_CACHE_HOME\\\")}))', "
            "sys.argv[1], sys.argv[2]], check=True, env=os.environ.copy())\n",
            encoding="utf-8",
        )
        ambient_python = self.tmp / "ambient-python-canary"
        ambient_xdg = self.tmp / "ambient-xdg-canary"
        managed = self.tmp / "managed-python-cache"
        managed.mkdir(mode=0o700)

        def run_custody(block: str) -> subprocess.CompletedProcess[str]:
            environment = {
                **os.environ,
                "PYTHON_CACHE_ROOT": str(managed),
                "PYTHONPYCACHEPREFIX": str(ambient_python),
                "XDG_CACHE_HOME": str(ambient_xdg),
            }
            environment.pop("PYTHONDONTWRITEBYTECODE", None)
            return subprocess.run(
                [
                    BASH,
                    "-c",
                    block
                    + "\nbind_python_cache_custody\n"
                    + f'python3 "{driver}" "{module_root}" "{record}"\n',
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=environment,
            )

        transitive = run_custody(custody)
        self.assertEqual(transitive.returncode, 0, transitive.stderr)
        observed = json.loads(record.read_text(encoding="utf-8"))
        self.assertEqual(observed["PYTHONPYCACHEPREFIX"], str(managed / "bytecode"))
        self.assertEqual(observed["XDG_CACHE_HOME"], str(managed / "xdg-cache"))
        self.assertEqual(list(ambient_python.rglob("*")), [])
        self.assertEqual(list(ambient_xdg.rglob("*")), [])
        self.assertFalse((module_root / "__pycache__").exists())

        mutant = custody.replace(
            'PYTHONPYCACHEPREFIX="$PYTHON_CACHE_ROOT/bytecode"',
            ":",
            1,
        ).replace(
            'XDG_CACHE_HOME="$PYTHON_CACHE_ROOT/xdg-cache"',
            ":",
            1,
        )
        record.unlink()
        vulnerable = run_custody(mutant)
        self.assertEqual(vulnerable.returncode, 0, vulnerable.stderr)
        vulnerable_observed = json.loads(record.read_text(encoding="utf-8"))
        self.assertEqual(vulnerable_observed["PYTHONPYCACHEPREFIX"], str(ambient_python))
        self.assertTrue(any(ambient_python.rglob("*.pyc")))

    def test_owned_temp_runner_preserves_signal_status_and_stops_child(self) -> None:
        runner = ROOT / "scripts" / "owned_temp_runner.py"
        for signal_name, expected_status in (("HUP", 129), ("INT", 130), ("TERM", 143)):
            with self.subTest(signal=signal_name):
                record = self.tmp / f"signal-{signal_name}.root"
                continued = self.tmp / f"signal-{signal_name}.continued"
                child = (
                    f'printf "%s\\n" "$TEST_ROOT" >"{record}"; '
                    f"kill -{signal_name} $$; "
                    f'printf "continued\\n" >"{continued}"'
                )
                result = subprocess.run(
                    [
                        sys.executable,
                        str(runner),
                        "--root",
                        "TEST_ROOT:omux-signal-test",
                        "--",
                        "/bin/sh",
                        "-c",
                        child,
                    ],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env={**os.environ, "TMPDIR": str(self.tmp)},
                )
                root = Path(record.read_text(encoding="utf-8").strip())
                self.assertEqual(result.returncode, expected_status, result.stderr)
                self.assertFalse(continued.exists())
                self.assertTrue(root.is_dir())
                self.assertEqual(list(root.iterdir()), [])
                root.rmdir()

        runner_source = runner.read_text(encoding="utf-8")
        status_fold = "128 - child_status if child_status < 0 else child_status"
        self.assertIn(status_fold, runner_source)
        mutated_runner = self.tmp / "owned-temp-runner-signal-mutant.py"
        mutated_runner.write_text(
            runner_source.replace(status_fold, "child_status", 1),
            encoding="utf-8",
        )
        record = self.tmp / "signal-mutant.root"
        result = subprocess.run(
            [
                sys.executable,
                str(mutated_runner),
                "--root",
                "TEST_ROOT:omux-signal-mutant",
                "--",
                "/bin/sh",
                "-c",
                f'printf "%s\\n" "$TEST_ROOT" >"{record}"; kill -TERM $$',
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "TMPDIR": str(self.tmp)},
        )
        self.assertNotEqual(result.returncode, 143)

        cleanup_call = "removed = root.cleanup(exclusions)"
        cleanup_signal_runner = self.tmp / "owned-temp-runner-cleanup-signal.py"
        cleanup_signal_runner.write_text(
            runner_source.replace(
                cleanup_call,
                "os.kill(os.getpid(), signal.SIGTERM)\n            " + cleanup_call,
                1,
            ),
            encoding="utf-8",
        )
        cleanup_signal = subprocess.run(
            [
                sys.executable,
                str(cleanup_signal_runner),
                "--root",
                "TEST_ROOT:omux-cleanup-signal",
                "--",
                sys.executable,
                "-I",
                "-B",
                "-c",
                "pass",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "TMPDIR": str(self.tmp)},
        )
        self.assertEqual(cleanup_signal.returncode, 143, cleanup_signal.stderr)
        final_signal_fold = "status = 128 + received_signal"
        restore_handlers = "for signum, handler in previous_handlers.items():"
        self.assertGreater(
            runner_source.index(final_signal_fold, runner_source.index(restore_handlers)),
            runner_source.index(restore_handlers),
        )

    def test_owned_temp_runner_rejects_writable_nonsticky_parent(self) -> None:
        runner = ROOT / "scripts" / "owned_temp_runner.py"
        parent = self.tmp / "nonsticky-parent"
        parent.mkdir(mode=0o700)
        os.chmod(parent, 0o777)
        try:
            result = subprocess.run(
                [
                    sys.executable,
                    str(runner),
                    "--root",
                    "TEST_ROOT:omux-nonsticky-test",
                    "--",
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    "pass",
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env={**os.environ, "TMPDIR": str(parent)},
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn("writable without sticky-bit custody", result.stderr)
            self.assertEqual(list(parent.iterdir()), [])
        finally:
            os.chmod(parent, 0o700)

    def test_owned_temp_runner_rejects_parent_path_swap_during_creation(self) -> None:
        runner = ROOT / "scripts" / "owned_temp_runner.py"
        runner_spec = importlib.util.spec_from_file_location(
            "omux_owned_temp_runner_parent_boundary",
            runner,
        )
        assert runner_spec is not None and runner_spec.loader is not None
        runner_module = importlib.util.module_from_spec(runner_spec)
        sys.modules[runner_spec.name] = runner_module
        runner_spec.loader.exec_module(runner_module)

        parent = self.tmp / "trusted-parent"
        parent.mkdir(mode=0o700)
        original = self.tmp / "trusted-parent.original"
        real_mkdir = os.mkdir
        swapped = False

        def swap_before_relative_create(
            path: object,
            mode: int = 0o777,
            *,
            dir_fd: int | None = None,
        ) -> None:
            nonlocal swapped
            if dir_fd is not None and not swapped:
                swapped = True
                parent.rename(original)
                real_mkdir(parent, 0o700)
            real_mkdir(path, mode, dir_fd=dir_fd)

        try:
            with mock.patch.object(
                runner_module.os,
                "mkdir",
                side_effect=swap_before_relative_create,
            ):
                with self.assertRaisesRegex(RuntimeError, "path changed during creation"):
                    runner_module.OwnedRoot.create(parent, "omux-parent-swap")
            self.assertTrue(swapped)
            self.assertEqual(list(parent.iterdir()), [])
            self.assertEqual(list(original.iterdir()), [])
        finally:
            parent.rmdir()
            original.rmdir()

    def test_owned_temp_runner_exports_descriptor_bound_root(self) -> None:
        runner = ROOT / "scripts" / "owned_temp_runner.py"
        child = """
import json
import os
import stat

path = os.environ["TEST_ROOT"]
fd = int(os.environ["TEST_ROOT_FD"], 10)
descriptor = os.fstat(fd)
current = os.stat(path, follow_symlinks=False)
print(json.dumps({
    "fd": fd,
    "descriptor": [descriptor.st_dev, descriptor.st_ino, descriptor.st_uid, stat.S_IMODE(descriptor.st_mode)],
    "path": [current.st_dev, current.st_ino, current.st_uid, stat.S_IMODE(current.st_mode)],
}, sort_keys=True))
"""
        result = subprocess.run(
            [
                sys.executable,
                str(runner),
                "--root",
                "TEST_ROOT:omux-fd-export",
                "--",
                sys.executable,
                "-I",
                "-B",
                "-c",
                child,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "TMPDIR": str(self.tmp)},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = json.loads(result.stdout)
        self.assertGreaterEqual(observed["fd"], 3)
        self.assertEqual(observed["descriptor"], observed["path"])
        self.assertEqual(observed["descriptor"][2:], [os.getuid(), 0o700])

    def test_nested_root_rejects_adopted_parent_path_replacement(self) -> None:
        runner = ROOT / "scripts" / "owned_temp_runner.py"
        runner_spec = importlib.util.spec_from_file_location(
            "omux_owned_temp_runner_nested_parent_boundary",
            runner,
        )
        assert runner_spec is not None and runner_spec.loader is not None
        runner_module = importlib.util.module_from_spec(runner_spec)
        sys.modules[runner_spec.name] = runner_module
        runner_spec.loader.exec_module(runner_module)

        parent = self.tmp / "adopted-parent"
        parent.mkdir(mode=0o700)
        inherited_fd = os.open(
            parent,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        adopted = runner_module.OwnedRoot.adopt(parent, inherited_fd)
        os.close(inherited_fd)
        original = self.tmp / "adopted-parent.original"
        parent.rename(original)
        parent.mkdir(mode=0o700)
        try:
            with self.assertRaisesRegex(
                RuntimeError,
                "parent path changed before nested creation",
            ):
                runner_module.OwnedRoot.create(
                    parent,
                    "omux-nested-swap",
                    adopted.fd,
                )
            self.assertEqual(list(parent.iterdir()), [])
            self.assertEqual(list(original.iterdir()), [])
        finally:
            os.close(adopted.fd)
            parent.rmdir()
            original.rmdir()

    def test_descriptor_cleanup_preserves_replacement_for_all_three_roots(self) -> None:
        runner = ROOT / "scripts" / "owned_temp_runner.py"
        profiles = ("wrapper", "inner", "check-local")
        for profile in profiles:
            with self.subTest(profile=profile):
                record = self.tmp / f"{profile}.root"
                if profile == "wrapper":
                    root = Path(tempfile.mkdtemp(prefix="omux-wrapper.", dir=self.tmp))
                    os.chmod(root, 0o700)
                    inherited_fd = os.open(
                        root,
                        os.O_RDONLY
                        | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                    )
                    arguments = [
                        "--adopt-root",
                        "SWAP_ROOT",
                        str(inherited_fd),
                        str(root),
                    ]
                    pass_fds = (inherited_fd,)
                elif profile == "inner":
                    inherited_fd = -1
                    arguments = [
                        "--root",
                        "WRAPPER_ROOT:omux-wrapper",
                        "--root",
                        "SWAP_ROOT:omux-inner",
                    ]
                    pass_fds = ()
                else:
                    inherited_fd = -1
                    arguments = ["--root", "SWAP_ROOT:oauth-mux-pycache"]
                    pass_fds = ()

                sentinel = {
                    "wrapper": ".omux-v02-wrapper-root",
                    "inner": ".omux-v02-contract-root",
                    "check-local": ".omux-check-local-cache-root",
                }[profile]
                sentinel_content = {
                    "wrapper": "omux-v02-posix-wrapper-v2",
                    "inner": "omux-v02-posix-contract-v2",
                    "check-local": "omux-check-local-cache-v2",
                }[profile]
                child = (
                    f'printf "%s\\n" "$SWAP_ROOT" >"{record}"; '
                    'mv "$SWAP_ROOT" "$SWAP_ROOT.original"; '
                    'mkdir -m 0700 "$SWAP_ROOT"; '
                    f'printf "%s\\n" "{sentinel_content}" >"$SWAP_ROOT/{sentinel}"; '
                    f'chmod 0600 "$SWAP_ROOT/{sentinel}"; '
                    'printf "replacement survives\\n" >"$SWAP_ROOT/victim"'
                )
                try:
                    result = subprocess.run(
                        [
                            sys.executable,
                            str(runner),
                            *arguments,
                            "--",
                            "/bin/sh",
                            "-c",
                            child,
                        ],
                        check=False,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        env={**os.environ, "TMPDIR": str(self.tmp)},
                        pass_fds=pass_fds,
                    )
                finally:
                    if inherited_fd >= 0:
                        os.close(inherited_fd)
                replacement = Path(record.read_text(encoding="utf-8").strip())
                original = Path(f"{replacement}.original")
                try:
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn("replacement left untouched", result.stderr)
                    self.assertEqual(
                        (replacement / "victim").read_text(encoding="utf-8"),
                        "replacement survives\n",
                    )
                    if profile != "inner":
                        self.assertTrue(original.is_dir())
                finally:
                    cleanup_parent = replacement
                    while cleanup_parent.parent != self.tmp and cleanup_parent.parent != cleanup_parent:
                        cleanup_parent = cleanup_parent.parent
                    shutil.rmtree(cleanup_parent, ignore_errors=True)
                    shutil.rmtree(original, ignore_errors=True)

        runner_source = runner.read_text(encoding="utf-8")
        descriptor_cleanup = "clear_directory(self.fd, excluded_names)"
        self.assertIn(descriptor_cleanup, runner_source)
        vulnerable_runner = self.tmp / "owned-temp-runner-pathname-mutant.py"
        vulnerable_runner.write_text(
            runner_source.replace(
                descriptor_cleanup,
                '__import__("shutil").rmtree(self.path)\n            return True',
                1,
            ),
            encoding="utf-8",
        )
        record = self.tmp / "pathname-mutant.root"
        child = (
            f'printf "%s\\n" "$SWAP_ROOT" >"{record}"; '
            'mv "$SWAP_ROOT" "$SWAP_ROOT.original"; '
            'mkdir -m 0700 "$SWAP_ROOT"; '
            'printf "replacement deleted\\n" >"$SWAP_ROOT/victim"'
        )
        result = subprocess.run(
            [
                sys.executable,
                str(vulnerable_runner),
                "--root",
                "SWAP_ROOT:omux-pathname-mutant",
                "--",
                "/bin/sh",
                "-c",
                child,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "TMPDIR": str(self.tmp)},
        )
        replacement = Path(record.read_text(encoding="utf-8").strip())
        original = Path(f"{replacement}.original")
        try:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(replacement.exists())
            self.assertTrue(original.is_dir())
        finally:
            shutil.rmtree(replacement, ignore_errors=True)
            shutil.rmtree(original, ignore_errors=True)

        runner_spec = importlib.util.spec_from_file_location(
            "omux_owned_temp_runner_final_boundary",
            runner,
        )
        assert runner_spec is not None and runner_spec.loader is not None
        runner_module = importlib.util.module_from_spec(runner_spec)
        sys.modules[runner_spec.name] = runner_module
        runner_spec.loader.exec_module(runner_module)
        final_root = runner_module.OwnedRoot.create(self.tmp, "omux-final-boundary")
        final_original = Path(f"{final_root.path}.original")
        real_stat = os.stat
        swapped = False

        def swap_after_identity_read(path: object, *args: object, **kwargs: object) -> os.stat_result:
            nonlocal swapped
            result = real_stat(path, *args, **kwargs)
            if not swapped and Path(path) == final_root.path and not kwargs.get("dir_fd"):
                swapped = True
                final_root.path.rename(final_original)
                final_root.path.mkdir(mode=0o700)
            return result

        try:
            with mock.patch.object(runner_module.os, "stat", side_effect=swap_after_identity_read):
                self.assertTrue(final_root.cleanup())
            self.assertTrue(swapped)
            self.assertTrue(final_root.path.is_dir())
            self.assertEqual(list(final_root.path.iterdir()), [])
            self.assertTrue(final_original.is_dir())
        finally:
            final_root.path.rmdir()
            final_original.rmdir()

    def test_public_contract_has_no_private_or_ambient_authority_bypass(self) -> None:
        public_script = ROOT / "scripts" / "v02-posix-install-contract-local.sh"
        inner_template = ROOT / "scripts" / "v02-posix-install-contract-inner.sh.in"
        self.assertFalse(os.access(inner_template, os.X_OK))

        direct = subprocess.run(
            [str(public_script), "--private-contract"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=ROOT,
        )
        self.assertEqual(direct.returncode, 2)
        self.assertEqual(list(self.tmp.glob("omux-v02-posix-wrapper.*")), [])

        template_direct = subprocess.run(
            [BASH, str(inner_template), "--private-contract"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=ROOT,
        )
        self.assertEqual(template_direct.returncode, 2)
        self.assertNotIn("proving candidate", template_direct.stdout)

        stub_bin = self.tmp / "stub-bin"
        stub_bin.mkdir(mode=0o700)
        nix_log = self.tmp / "nix-calls"
        ambient_log = self.tmp / "ambient-bootstrap-calls"
        attacker_repo = self.tmp / "attacker-repo"
        (attacker_repo / "scripts").mkdir(parents=True)
        for name in ("bash", "dirname", "mktemp", "chmod", "mkdir"):
            stub = stub_bin / name
            output = (
                "printf 'v02-posix-install-contract-local: PASS (forged)\\n'\n"
                if name == "bash"
                else (
                    f"printf '%s\\n' '{attacker_repo / 'scripts'}'\n"
                    if name == "dirname"
                    else "exit 0\n"
                )
            )
            stub.write_text(
                "#!/bin/sh\n"
                f"printf '{name}\\n' >>'{ambient_log}'\n"
                + output,
                encoding="utf-8",
            )
            os.chmod(stub, 0o700)
        nix_stub = stub_bin / "nix"
        nix_stub.write_text(
            "#!/bin/sh\n"
            f'printf "%s\\n" "$*" >>"{nix_log}"\n'
            "exit 0\n",
            encoding="utf-8",
        )
        os.chmod(nix_stub, 0o700)
        environment = os.environ.copy()
        environment.update({"PATH": f"{stub_bin}:{environment.get('PATH', '')}", "TMPDIR": str(self.tmp)})
        bash_env = self.tmp / "bash-env"
        bash_env.write_text(
            f"printf 'bash-env\\n' >>'{ambient_log}'\n"
            "printf 'v02-posix-install-contract-local: PASS (forged startup)\\n'\n"
            "exit 0\n",
            encoding="utf-8",
        )
        hostile_entry_environment = {**environment, "BASH_ENV": str(bash_env)}
        imported_function_marker = self.tmp / "imported-printf-function"
        hostile_entry_environment.update({
            "SHELLOPTS": "privileged",
            "BASH_FUNC_printf%%": (
                "() { command touch " + str(imported_function_marker) + "; "
                "builtin printf \"%s\\n\" \"$@\"; }"
            ),
        })

        guarded_entry = subprocess.run(
            [str(public_script), "--private-contract"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=hostile_entry_environment,
            cwd=ROOT,
        )
        self.assertEqual(guarded_entry.returncode, 2)
        self.assertNotIn("PASS", guarded_entry.stdout)
        self.assertFalse(ambient_log.exists())
        self.assertFalse(imported_function_marker.exists())

        public_source = public_script.read_text(encoding="utf-8")
        resolver = self.shell_function(public_source, "resolve_nix")
        realpath_bin = Path(shutil.which("realpath") or "")
        self.assertTrue(realpath_bin.is_file())
        resolved = subprocess.run(
            [BASH, "-c", f"realpath_bin={realpath_bin}\n" + resolver + "\nresolve_nix"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )
        self.assertEqual(resolved.returncode, 0, resolved.stderr)
        self.assertTrue(resolved.stdout.strip().startswith("/nix/store/"))
        self.assertFalse(nix_log.exists())
        self.assertLess(
            public_source.index('nix_bin="$(resolve_nix)"'),
            public_source.index('exec "$nix_bin" develop'),
        )

        failed_nix = self.tmp / "v02-posix-failed-nix.sh"
        failed_nix.write_text(
            public_source.replace(
                'nix_bin="$(resolve_nix)"',
                f'nix_bin="{FALSE}"',
                1,
            ),
            encoding="utf-8",
        )
        os.chmod(failed_nix, 0o700)
        failed = subprocess.run(
            [BASH, "-p", str(failed_nix)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env={**os.environ, "TMPDIR": str(self.tmp)},
            cwd=ROOT,
        )
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(list(self.tmp.glob("omux-v02-posix-wrapper.*")), [])

        fixed_probe = self.tmp / "fixed-repo" / "scripts" / "v02-posix-install-contract-local.sh"
        fixed_probe.parent.mkdir(parents=True)
        nix_start = public_source.index('exec "$nix_bin" develop --command')
        fixed_source = public_source[:nix_start] + 'printf "repo=%s\\n" "$repo_root"\nexit 0\n'
        fixed_probe.write_text(
            fixed_source,
            encoding="utf-8",
        )
        os.chmod(fixed_probe, 0o700)
        fixed = subprocess.run(
            [str(fixed_probe)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=hostile_entry_environment,
            cwd=ROOT,
        )
        self.assertEqual(fixed.returncode, 0, fixed.stderr)
        self.assertEqual(fixed.stdout, f"repo={fixed_probe.parents[1]}\n")
        self.assertFalse(ambient_log.exists())
        self.assertFalse(nix_log.exists())
        self.assertEqual(list(self.tmp.glob("omux-v02-posix-wrapper.*")), [])

        vulnerable_entry = self.tmp / "v02-posix-env-bash-mutant.sh"
        vulnerable_entry.write_text(
            public_source.replace(
                "#!/usr/bin/env -S PATH=/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:/usr/bin:/bin bash -p",
                "#!/usr/bin/env bash",
                1,
            ),
            encoding="utf-8",
        )
        os.chmod(vulnerable_entry, 0o700)
        vulnerable_entry_environment = hostile_entry_environment.copy()
        vulnerable_entry_environment.pop("SHELLOPTS", None)
        vulnerable_entry_environment.pop("BASH_FUNC_printf%%", None)
        bypassed_entry = subprocess.run(
            [str(vulnerable_entry), "--private-contract"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=vulnerable_entry_environment,
            cwd=ROOT,
        )
        self.assertEqual(bypassed_entry.returncode, 0)
        self.assertIn("PASS (forged)", bypassed_entry.stdout)
        self.assertIn("bash", ambient_log.read_text(encoding="utf-8").splitlines())
        ambient_log.unlink()

        fixed_resolution = '''script_path="$0"
case "$script_path" in
  /*) ;;
  *) script_path="$(pwd -P)/$script_path" ;;
esac
[ -f "$script_path" ] && [ ! -L "$script_path" ] || {
  printf 'source contract entrypoint must be one regular, non-symlink file\\n' >&2
  exit 2
}
script_dir="${script_path%/*}"
[ "$script_dir" != "$script_path" ] || script_dir=.
repo_root="$(cd "$script_dir/.." && pwd -P)"'''
        vulnerable_dirname = self.tmp / "v02-posix-ambient-dirname-mutant.sh"
        vulnerable_dirname.write_text(
            fixed_probe.read_text(encoding="utf-8").replace(
                fixed_resolution,
                'repo_root="$(cd "$(dirname "$0")/.." && pwd)"',
                1,
            ).replace(
                "PATH=/usr/bin:/bin\nexport PATH\nreadonly PATH\n",
                "",
                1,
            ),
            encoding="utf-8",
        )
        os.chmod(vulnerable_dirname, 0o700)
        dirname_only_bin = self.tmp / "dirname-only-bin"
        dirname_only_bin.mkdir(mode=0o700)
        shutil.copy2(stub_bin / "dirname", dirname_only_bin / "dirname")
        dirname_environment = {
            **environment,
            "PATH": f"{dirname_only_bin}:/usr/bin:/bin",
        }
        dirname_bypass = subprocess.run(
            [BASH, "-p", str(vulnerable_dirname)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=dirname_environment,
            cwd=ROOT,
        )
        self.assertEqual(dirname_bypass.returncode, 0, dirname_bypass.stderr)
        self.assertEqual(dirname_bypass.stdout, f"repo={attacker_repo}\n")
        self.assertIn("dirname", ambient_log.read_text(encoding="utf-8").splitlines())
        ambient_log.unlink()
        for root in self.tmp.glob("omux-v02-posix-wrapper.*"):
            shutil.rmtree(root, ignore_errors=True)

        vulnerable_script = self.tmp / "v02-posix-ambient-nix-mutant.sh"
        vulnerable_source = public_source.replace(
            'nix_bin="$(resolve_nix)"',
            'nix_bin="$(command -v nix)"',
            1,
        ).replace(
            "PATH=/usr/bin:/bin\nexport PATH\nreadonly PATH\n",
            "",
            1,
        )
        vulnerable_script.write_text(vulnerable_source, encoding="utf-8")
        os.chmod(vulnerable_script, 0o700)
        nix_only_bin = self.tmp / "nix-only-bin"
        nix_only_bin.mkdir(mode=0o700)
        shutil.copy2(nix_stub, nix_only_bin / "nix")
        nix_environment = {
            **environment,
            "PATH": f"{nix_only_bin}:/usr/bin:/bin",
        }
        try:
            bypass = subprocess.run(
                [BASH, "-p", str(vulnerable_script)],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=nix_environment,
                cwd=ROOT,
            )
            self.assertEqual(bypass.returncode, 0, bypass.stderr)
            self.assertEqual(len(nix_log.read_text(encoding="utf-8").splitlines()), 1)
            self.assertIn(
                "develop --command omux-owned-temp-runner "
                "--root OMUX_V02_WRAPPER_TEMP_ROOT:omux-v02-posix-wrapper "
                "-- omux-v02-posix-install-contract-inner",
                nix_log.read_text(encoding="utf-8"),
            )
        finally:
            for root in self.tmp.glob("omux-v02-posix-wrapper.*"):
                shutil.rmtree(root, ignore_errors=True)

    def test_generated_nix_helper_ignores_all_ambient_tool_mutations(self) -> None:
        helpers = [
            shutil.which("omux-v02-posix-install-contract-inner"),
            shutil.which("omux-v02-posix-exact-promote"),
        ]
        if any(helper is None for helper in helpers):
            self.skipTest("generated helpers are available only inside the named Nix contract")

        baseline_runs: list[str] = []
        for helper in helpers:
            assert helper is not None
            repeated = []
            for _ in range(2):
                result = subprocess.run(
                    [helper, "--authority-probe"],
                    check=False,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=ROOT,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                repeated.append(result.stdout)
            self.assertEqual(repeated[0], repeated[1])
            baseline_runs.append(repeated[0])
        self.assertEqual(baseline_runs[0], baseline_runs[1])
        authority = dict(
            line.split("=", 1)
            for line in baseline_runs[0].splitlines()
            if "=" in line
        )
        self.assertEqual(set(authority), {"python", "git", "zig"})
        for path in authority.values():
            self.assertTrue(path.startswith("/nix/store/"))
            self.assertTrue(os.access(path, os.X_OK))

        startup_dir = self.tmp / "ambient-python-startup"
        startup_dir.mkdir(mode=0o700)
        startup_marker = self.tmp / "ambient-python-startup-ran"
        (startup_dir / "sitecustomize.py").write_text(
            "from pathlib import Path\n"
            f"Path({str(startup_marker)!r}).write_text('ambient startup executed\\n', encoding='utf-8')\n",
            encoding="utf-8",
        )
        startup_environment = {
            **os.environ,
            "PYTHONPATH": str(startup_dir),
            "PYTHONUSERBASE": str(startup_dir / "user-base"),
            "TMPDIR": str(self.tmp),
        }
        vulnerable_python = subprocess.run(
            [authority["python"], "-B", "-c", "pass"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=startup_environment,
        )
        self.assertEqual(vulnerable_python.returncode, 0, vulnerable_python.stderr)
        self.assertTrue(startup_marker.is_file())
        startup_marker.unlink()

        isolated_python = subprocess.run(
            [authority["python"], "-I", "-B", "-c", "pass"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=startup_environment,
        )
        self.assertEqual(isolated_python.returncode, 0, isolated_python.stderr)
        self.assertFalse(startup_marker.exists())

        exact_promoter = helpers[1]
        assert exact_promoter is not None
        isolated_promoter = subprocess.run(
            [exact_promoter],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=startup_environment,
            cwd=ROOT,
        )
        self.assertEqual(isolated_promoter.returncode, 2)
        self.assertFalse(startup_marker.exists())

        owned_runner = shutil.which("omux-owned-temp-runner")
        self.assertIsNotNone(owned_runner)
        assert owned_runner is not None
        isolated_runner = subprocess.run(
            [
                owned_runner,
                "--root",
                "OMUX_TEST_ROOT:omux-python-isolation",
                "--",
                sys.executable,
                "-I",
                "-B",
                "-c",
                "pass",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=startup_environment,
            cwd=ROOT,
        )
        self.assertEqual(isolated_runner.returncode, 0, isolated_runner.stderr)
        self.assertFalse(startup_marker.exists())

        mutated_environment = os.environ.copy()
        for tool_name, executable_name in (("PYTHON", "python3"), ("GIT", "git"), ("ZIG", "zig")):
            unrelated = self.tmp / f"ambient-{executable_name}"
            unrelated.write_text("#!/bin/sh\nexit 98\n", encoding="utf-8")
            os.chmod(unrelated, 0o700)
            mutated_environment[f"OMUX_V02_CONTRACT_{tool_name}"] = str(unrelated)
            mutated_environment[f"OMUX_V02_CONTRACT_AUTHORIZED_{tool_name}"] = str(unrelated)

        direct_environment = mutated_environment.copy()
        direct_environment.pop("OMUX_V02_WRAPPER_TEMP_ROOT", None)
        direct_environment.pop("OMUX_V02_CONTRACT_TEMP_ROOT", None)
        direct_environment["TMPDIR"] = str(self.tmp)

        def side_effect_snapshot() -> list[tuple[str, int, bytes]]:
            snapshot: list[tuple[str, int, bytes]] = []
            for entry in sorted(self.tmp.rglob("*")):
                info = entry.lstat()
                if entry.is_symlink():
                    payload = os.readlink(entry).encode()
                elif entry.is_file():
                    payload = entry.read_bytes()
                else:
                    payload = b""
                snapshot.append((str(entry.relative_to(self.tmp)), info.st_mode, payload))
            return snapshot

        for helper in helpers:
            assert helper is not None
            result = subprocess.run(
                [helper, "--authority-probe"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=mutated_environment,
                cwd=ROOT,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, baseline_runs[0])

            before = side_effect_snapshot()
            direct = subprocess.run(
                [helper],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=direct_environment,
                cwd=ROOT,
            )
            self.assertEqual(direct.returncode, 2)
            self.assertEqual(direct.stdout, "")
            self.assertEqual(side_effect_snapshot(), before)
            if helper == helpers[0]:
                self.assertEqual(
                    direct.stderr,
                    "generated contract helper requires descriptor-owned wrapper custody\n",
                )

        fd_root = self.tmp / "forged-fd-root"
        path_root = self.tmp / "forged-path-root"
        fd_root.mkdir(mode=0o700)
        path_root.mkdir(mode=0o700)
        inherited_fd = os.open(
            fd_root,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        forged_environment = direct_environment.copy()
        forged_environment["OMUX_V02_WRAPPER_TEMP_ROOT"] = str(path_root)
        forged_environment["OMUX_V02_WRAPPER_TEMP_ROOT_FD"] = str(inherited_fd)
        before = side_effect_snapshot()
        try:
            forged = subprocess.run(
                [helpers[0]],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=forged_environment,
                cwd=ROOT,
                pass_fds=(inherited_fd,),
            )
        finally:
            os.close(inherited_fd)
        self.assertEqual(forged.returncode, 2)
        self.assertEqual(forged.stdout, "")
        self.assertEqual(
            forged.stderr,
            "generated contract helper requires descriptor-owned wrapper custody\n",
        )
        self.assertEqual(side_effect_snapshot(), before)

    def test_named_recipe_requires_nix_python_tool_graph(self) -> None:
        flake = (ROOT / "flake.nix").read_text(encoding="utf-8")
        build = (ROOT / "build.zig").read_text(encoding="utf-8")
        justfile = (ROOT / "justfile").read_text(encoding="utf-8")
        public = (ROOT / "scripts" / "v02-posix-install-contract-local.sh").read_text(
            encoding="utf-8"
        )
        inner = (ROOT / "scripts" / "v02-posix-install-contract-inner.sh.in").read_text(
            encoding="utf-8"
        )
        runner = (ROOT / "scripts" / "owned_temp_runner.py").read_text(encoding="utf-8")
        check_local = (ROOT / "scripts" / "check-local.sh").read_text(encoding="utf-8")
        candidate_source = (ROOT / "scripts" / "v02_posix_candidate.py").read_text(
            encoding="utf-8"
        )

        self.assertIn("pkgs.python3", flake)
        self.assertIn("pkgs.git", flake)
        self.assertIn("pkgs.bash", flake)
        self.assertIn("pkgs.coreutils", flake)
        self.assertIn('zig = pkgs.zigpkgs."0.14.1"', flake)
        self.assertIn('name = "omux-v02-posix-install-contract-inner"', flake)
        self.assertIn('name = "omux-v02-posix-exact-promote"', flake)
        self.assertIn('name = "omux-owned-temp-runner"', flake)
        self.assertIn('${pkgs.python3}/bin/python3 -I -B "$runner"', flake)
        self.assertIn("${pkgs.python3}/bin/python3 -I -B -c", flake)
        self.assertIn("module.exact_closure_main", flake)
        self.assertIn("${ownedTempRunner}/bin/omux-owned-temp-runner", flake)
        self.assertIn("OMUX_V02_EMBEDDED_PYTHON=${pkgs.python3}/bin/python3", flake)
        self.assertIn("OMUX_V02_EMBEDDED_GIT=${pkgs.git}/bin/git", flake)
        self.assertIn("OMUX_V02_EMBEDDED_ZIG=${zig}/bin/zig", flake)
        self.assertIn('s|@python@|$OMUX_V02_EMBEDDED_PYTHON|g', flake)
        self.assertIn('s|@git@|$OMUX_V02_EMBEDDED_GIT|g', flake)
        self.assertIn('s|@zig@|$OMUX_V02_EMBEDDED_ZIG|g', flake)
        self.assertIn(
            "--root OMUX_V02_WRAPPER_TEMP_ROOT:omux-v02-posix-wrapper",
            public,
        )
        self.assertIn('wrapper_root="\'\'${OMUX_V02_WRAPPER_TEMP_ROOT:-}"', flake)
        self.assertIn('wrapper_fd="\'\'${OMUX_V02_WRAPPER_TEMP_ROOT_FD:-}"', flake)
        self.assertIn('test -n "$wrapper_root" && test -n "$wrapper_fd"', flake)
        self.assertIn('test "$wrapper_fd" -ge 3', flake)
        self.assertIn("descriptor = os.fstat(int(sys.argv[2], 10))", flake)
        self.assertIn("descriptor_identity != path_identity", flake)
        self.assertIn(
            "generated contract helper requires descriptor-owned wrapper custody",
            flake,
        )
        self.assertIn(
            '--adopt-root OMUX_V02_WRAPPER_TEMP_ROOT "$wrapper_fd" "$wrapper_root"',
            flake,
        )
        self.assertIn(
            "--root OMUX_V02_CONTRACT_TEMP_ROOT:omux-v02-posix-contract",
            flake,
        )
        self.assertNotIn("OMUX_V02_CONTRACT_AUTHORIZED_", flake)
        self.assertNotIn("export OMUX_V02_CONTRACT_PYTHON", flake)
        self.assertNotIn("export OMUX_V02_CONTRACT_GIT", flake)
        self.assertNotIn("export OMUX_V02_CONTRACT_ZIG", flake)

        self.assertIn(
            "v02-posix-install-contract-local:\n"
            "    ./scripts/v02-posix-install-contract-local.sh",
            justfile,
        )
        self.assertNotIn(
            "v02-posix-install-contract-local:\n    nix develop",
            justfile,
        )
        self.assertEqual(public.count('exec "$nix_bin" develop --command'), 1)
        self.assertIn("omux-v02-posix-install-contract-inner", public)
        self.assertIn('/nix/var/nix/profiles/default/bin/nix', public)
        self.assertIn('/nix/store/*/bin/nix', public)
        self.assertTrue(
            public.startswith(
                "#!/usr/bin/env -S PATH=/run/current-system/sw/bin:/nix/var/nix/profiles/default/bin:/usr/bin:/bin bash -p\n"
            )
        )
        self.assertNotIn("BASH_SOURCE", public)
        self.assertNotIn("SHELLOPTS", public)
        self.assertNotIn("bootstrap_bash", public)
        self.assertIn('/run/current-system/sw/bin/realpath', public)
        self.assertIn("PATH=/usr/bin:/bin", public)
        self.assertNotIn("dirname", public)
        self.assertNotIn("command -v nix", public)
        self.assertNotIn("resolve_bootstrap_tool", public)
        self.assertNotIn("cleanup_wrapper_root", public)
        self.assertLess(
            public.index('nix_bin="$(resolve_nix)"'),
            public.index('exec "$nix_bin" develop'),
        )
        self.assertNotIn("--private-contract", public)
        self.assertNotIn("OMUX_V02_CONTRACT_IN_NIX", public)
        self.assertNotIn("OMUX_V02_CONTRACT_PYTHON", public)
        self.assertNotIn("OMUX_V02_CONTRACT_GIT", public)
        self.assertNotIn("OMUX_V02_CONTRACT_ZIG", public)
        self.assertNotIn("HANDSHAKE", public.upper())
        self.assertNotIn("rm -rf", public)

        self.assertFalse(os.access(ROOT / "scripts" / "v02-posix-install-contract-inner.sh.in", os.X_OK))
        self.assertIn('python_bin="@python@"', inner)
        self.assertIn('git_bin="@git@"', inner)
        self.assertIn('zig_bin="@zig@"', inner)
        self.assertNotIn("--private-contract", inner)
        self.assertNotIn("nix develop", inner)
        self.assertNotIn("HANDSHAKE", inner.upper())
        self.assertNotIn("AUTHORIZED_", inner)
        self.assertNotIn("rm -rf", inner)
        self.assertIn('zig_local_cache="$tmp/zig-local-cache"', inner)
        self.assertIn('zig_global_cache="$tmp/zig-global-cache"', inner)
        self.assertIn('python_cache="$tmp/python-cache"', inner)
        self.assertIn('xdg_cache="$tmp/xdg-cache"', inner)
        self.assertIn('runtime_tmp="$tmp/tmp"', inner)
        self.assertIn('export XDG_CACHE_HOME="$xdg_cache"', inner)
        self.assertIn('export ZIG_LOCAL_CACHE_DIR="$zig_local_cache"', inner)
        self.assertIn('export ZIG_GLOBAL_CACHE_DIR="$zig_global_cache"', inner)
        self.assertIn('export PYTHONPYCACHEPREFIX="$python_cache"', inner)
        self.assertEqual(inner.count('"$python_bin" -I -B'), 7)
        self.assertNotIn('"$python_bin" "$candidate_tool"', inner)
        self.assertNotIn('"$python_bin" -m unittest', inner)
        self.assertIn('--cache-dir "$zig_local_cache"', inner)
        self.assertIn('--global-cache-dir "$zig_global_cache"', inner)
        self.assertEqual(inner.count("run_zig build"), 3)
        self.assertNotIn('"$zig_bin" build', inner)
        self.assertEqual(
            [
                line.strip()
                for line in inner.splitlines()
                if line.lstrip().startswith('"$zig_bin"')
            ],
            ['"$zig_bin" "$@" \\'],
        )
        self.assertIn("proving candidate options cannot influence the ordinary install graph", inner)
        self.assertIn("proving candidate options cannot influence the ordinary release graph", inner)
        self.assertIn('[ ! -e "$unreachable_candidate_output" ]', inner)
        self.assertNotIn("v02-candidate-version", inner)
        self.assertNotIn("OMUX_V02_CANDIDATE_SHA", inner)
        self.assertNotIn("OMUX_V02_CANDIDATE_TREE", inner)
        self.assertNotIn("v02-source-commit", inner)
        self.assertNotIn("v02-source-tree", inner)

        self.assertIn(
            "omux-owned-temp-runner --root PYTHON_CACHE_ROOT:oauth-mux-pycache -- /bin/sh ./scripts/check-local.sh",
            justfile,
        )
        self.assertNotIn("trap ", check_local)
        self.assertNotIn("rm -rf", check_local)
        self.assertEqual(check_local.count("run_python -m "), 1)
        self.assertEqual(check_local.count("check_python_source ./scripts/"), 4)
        self.assertEqual(check_local.count("PYTHON_CACHE_ROOT="), 1)
        self.assertEqual(check_local.count("PYTHONPYCACHEPREFIX="), 1)
        self.assertEqual(check_local.count("XDG_CACHE_HOME="), 1)
        self.assertEqual(check_local.count("PYTHON_CACHE_SENTINEL="), 1)
        self.assertIn('PYTHONPYCACHEPREFIX="$PYTHON_CACHE_ROOT/bytecode"', check_local)
        self.assertIn('XDG_CACHE_HOME="$PYTHON_CACHE_ROOT/xdg-cache"', check_local)
        self.assertIn("export PYTHONPYCACHEPREFIX XDG_CACHE_HOME", check_local)
        self.assertIn("python3 -I -B", check_local)
        self.assertIn("check_python_source()", check_local)
        self.assertNotIn("-m py_compile", check_local)
        self.assertIn(
            "run_python -m unittest discover -s test -p 'test_v02_posix_candidate.py'\n"
            "./scripts/v02-posix-install-contract-local.sh",
            check_local,
        )

        self.assertIn("os.listdir(fd)", runner)
        self.assertIn("dir_fd=fd", runner)
        self.assertIn("os.open(name, flags, dir_fd=fd)", runner)
        self.assertIn("os.unlink(name, dir_fd=fd)", runner)
        self.assertIn('environment[f"{environment_name}_FD"] = str(root.fd)', runner)
        self.assertIn("pass_fds=tuple(root.fd for root in roots)", runner)
        self.assertIn("inherited_parent_fd = roots[-1].fd if roots else None", runner)
        self.assertIn("owned temporary parent path changed before nested creation", runner)
        self.assertIn("os.rmdir(name, dir_fd=fd)", runner)
        self.assertNotIn("os.rmdir(self.path)", runner)
        self.assertIn("intentionally leak", runner)
        self.assertIn("OwnedRoot.adopt(path, inherited_fd)", runner)
        self.assertNotIn("shutil", runner)
        self.assertNotIn("rmtree", runner)
        self.assertNotIn("rm -rf", runner)

        self.assertIn('"v02-posix-source-candidate"', build)
        self.assertIn("candidate_exe.getEmittedBin()", build)
        self.assertIn(
            'build_options.addOption([]const u8, "version", project_version)',
            build,
        )
        self.assertIn(
            'rel_exe.root_module.addOptions("build_options", build_options)',
            build,
        )
        self.assertNotIn(
            'rel_exe.root_module.addOptions("build_options", candidate_options)',
            build,
        )
        self.assertIn("build.v02-exact-rebuild.zig", (ROOT / candidate.EXACT_REBUILD_GRAPH).name)
        self.assertNotIn("OMUX_V02_NAMED_GRAPH_STEP", build)
        self.assertNotIn(
            "OMUX_V02_NAMED_GRAPH_STEP",
            (ROOT / "scripts" / "v02_posix_candidate.py").read_text(encoding="utf-8"),
        )
        self.assertNotIn("source_provenance_profile", build)
        self.assertNotIn("v02-candidate-version", build)
        self.assertNotIn("v02-source-commit", build)
        self.assertNotIn("v02-source-tree", build)
        self.assertNotIn("OMUX_V02_CONTRACT_PYTHON", candidate_source)
        self.assertNotIn("OMUX_V02_CONTRACT_GIT", candidate_source)
        self.assertNotIn("OMUX_V02_CONTRACT_ZIG", candidate_source)

if __name__ == "__main__":
    unittest.main()
