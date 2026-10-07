"""Modeled acquisition and real SHA1 object/tar invariants; no subprocess runs."""

from contextlib import ExitStack, contextmanager
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import codex_git_inputs as git


def oid(kind, value):
    return hashlib.sha1(kind.encode() + b" " + str(len(value)).encode() + b"\0" + value).hexdigest()


class MiniRepository:
    def __init__(self, entries=None):
        self.objects = {}
        plain = self.add("blob", b"source bytes\n")
        executable = self.add("blob", b"executable source fixture\n")
        link = self.add("blob", b"plain")
        nested = self.tree([("100755", "tool", executable)])
        self.root = self.tree(entries if entries is not None else [
            ("120000", "link", link), ("100644", "plain", plain), ("40000", "sub", nested)])
        # No author, committer, account IDs or personal data in fixture metadata.
        self.commit_bytes = b"tree " + self.root.encode() + b"\n\nfixture\n"
        self.commit = self.add("commit", self.commit_bytes)
        self.requirement = {"type": "git-repository-input", "remote": git.REQUIREMENTS[0][0],
                            "commit": self.commit, "evidence": [], "materialized": False,
                            "archive_sha256": None}

    def add(self, kind, value):
        key = oid(kind, value)
        self.objects[key] = kind, value
        return key

    def tree(self, entries):
        return self.add("tree", b"".join(mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(key)
                                        for mode, name, key in entries))

    def reader(self, key):
        return self.objects[key]

    def material(self):
        return git.snapshot(self.commit, self.reader, git.Budget())


def stat_text(group, session, start):
    fields = ["S", "1", str(group), str(session)] + ["0"] * 15 + [str(start)]
    return "123 (fixture name) " + " ".join(fields)


class GitObjectsTest(unittest.TestCase):
    def setUp(self):
        self.repo = MiniRepository()

    def test_real_sha1_objects_and_tree_tar_roundtrip(self):
        tree, records, proof, blobs, witness = self.repo.material()
        self.assertEqual(tree, self.repo.root)
        self.assertEqual(witness, {"oid": self.repo.commit, "tree_oid": tree,
                                  "bytes": len(self.repo.commit_bytes),
                                  "sha256": hashlib.sha256(self.repo.commit_bytes).hexdigest()})
        self.assertNotIn(self.repo.commit, proof)
        value = git.proof_bytes(proof)
        self.assertNotIn(self.repo.commit_bytes, value)
        self.assertEqual(set(kind for kind, _ in git.parse_proof(value).values()), {"tree"})
        tar = git.canonical_tar(records, blobs)
        self.assertEqual(git.verify_artifacts(tree, tar, value, git.Budget()), (tree, records))
        with tarfile.open(fileobj=io.BytesIO(tar), mode="r:") as archive:
            members = {item.name: item for item in archive}
        self.assertEqual(members["plain"].mode, 0o444)
        self.assertEqual(members["sub/tool"].mode, 0o555)
        self.assertEqual(members["sub"].mode, 0o555)
        self.assertEqual(members["link"].linkname, "plain")
        self.assertTrue(members["link"].issym())

    def test_corrupt_commit_or_blob_and_wrong_types_refuse(self):
        for key in (self.repo.commit, next(key for key, row in self.repo.objects.items() if row[0] == "blob")):
            with self.subTest(key=key):
                def reader(requested):
                    kind, value = self.repo.reader(requested)
                    return kind, value + b"changed" if requested == key else value
                with self.assertRaises(ValueError):
                    git.snapshot(self.repo.commit, reader, git.Budget())
        with self.assertRaises(ValueError):
            git.checked_object(lambda _: ("tree", b""), oid("blob", b""), "blob", git.Budget())

    def test_tree_modes_order_duplicates_and_path_refusals(self):
        blob = oid("blob", b"x")
        cases = [b"160000 sub\0" + bytes.fromhex(blob),
                 b"100644 b\0" + bytes.fromhex(blob) + b"100644 a\0" + bytes.fromhex(blob),
                 b"100644 a\0" + bytes.fromhex(blob) + b"100755 a\0" + bytes.fromhex(blob),
                 b"100644 ../outside\0" + bytes.fromhex(blob),
                 b"100644 .git\0" + bytes.fromhex(blob),
                 b"100644 bad\\name\0" + bytes.fromhex(blob),
                 b"100644 a\0" + b"short"]
        for value in cases:
            with self.subTest(value=value), self.assertRaises(ValueError):
                git.tree_entries(value)

    def test_git_tree_directory_sort_is_not_plain_name_sort(self):
        empty = oid("tree", b"")
        value = b"100644 a.c\0" + bytes.fromhex(empty) + b"40000 a\0" + bytes.fromhex(empty)
        self.assertEqual([row[1] for row in git.tree_entries(value)], ["a.c", "a"])

    def test_escaping_dangling_and_nested_links_refuse(self):
        for target in (b"../outside", b"/outside", b"absent", b"link", b"sub/../link", b"plain\n", b"plain/../sub"):
            repo = MiniRepository()
            link = repo.add("blob", target)
            old = git.tree_entries(repo.objects[repo.root][1])
            repo.root = repo.tree([(mode, name, link if name == "link" else key) for mode, name, key in old])
            commit = repo.add("commit", b"tree " + repo.root.encode() + b"\n\nfixture\n")
            with self.subTest(target=target), self.assertRaises(ValueError):
                git.snapshot(commit, repo.reader, git.Budget())

    def test_filter_and_byte_entry_deadline_bounds_refuse(self):
        repo = MiniRepository()
        attrs = repo.add("blob", b"*.txt filter=external\n")
        root = repo.tree([("100644", ".gitattributes", attrs)])
        commit = repo.add("commit", b"tree " + root.encode() + b"\n\nfixture\n")
        with self.assertRaises(ValueError):
            git.snapshot(commit, repo.reader, git.Budget())
        for name, value in (("MAX_BLOB", 4), ("MAX_SOURCE", 4), ("MAX_ENTRIES", 1), ("MAX_PROOF", 4)):
            with self.subTest(bound=name), patch.object(git, name, value), self.assertRaises(ValueError):
                self.repo.material()
        budget = git.Budget()
        budget.deadline = 0
        with self.assertRaises(ValueError):
            git.snapshot(self.repo.commit, self.repo.reader, budget)
        budget = git.Budget()
        budget.read_bytes = 4 * 1024 ** 3
        with self.assertRaises(ValueError):
            git.snapshot(self.repo.commit, self.repo.reader, budget)

    def test_proof_commit_injection_corruption_and_extra_tree_refuse(self):
        tree, records, proof, blobs, _ = self.repo.material()
        value, tar = git.proof_bytes(proof), git.canonical_tar(records, blobs)
        with self.assertRaises(ValueError):
            git.parse_proof(value[:-1])
        with self.assertRaises(ValueError):
            git.proof_bytes({self.repo.commit: ("commit", self.repo.commit_bytes)})
        injected = git.MAGIC + bytes.fromhex(self.repo.commit) + b"c" + struct.pack(">Q", len(self.repo.commit_bytes)) + self.repo.commit_bytes
        with self.assertRaises(ValueError):
            git.parse_proof(injected)
        extra = b""
        proof[oid("tree", extra)] = "tree", extra
        with self.assertRaises(ValueError):
            git.verify_artifacts(tree, tar, git.proof_bytes(proof), git.Budget())

    def test_noncanonical_tar_executable_trailing_and_hardlinks_refuse(self):
        tree, records, proof, blobs, _ = self.repo.material()
        tar, raw = git.canonical_tar(records, blobs), git.proof_bytes(proof)
        with self.assertRaises(ValueError):
            git.verify_artifacts(tree, tar + b"unbound trailing bytes", raw, git.Budget())
        for mutation in ("mode", "hardlink", "path"):
            stream = io.BytesIO()
            with tarfile.open(fileobj=io.BytesIO(tar), mode="r:") as source, tarfile.open(
                    fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as output:
                for member in source:
                    payload = source.extractfile(member).read() if member.isfile() else None
                    if member.name == "plain":
                        if mutation == "mode":
                            member.mode = 0o555
                        elif mutation == "hardlink":
                            member.type, member.size, member.linkname = tarfile.LNKTYPE, 0, "sub/tool"
                            payload = None
                        else:
                            member.name = "../outside"
                    output.addfile(member, io.BytesIO(payload) if payload is not None else None)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                git.verify_artifacts(tree, stream.getvalue(), raw, git.Budget())


class GitCustodyTest(unittest.TestCase):
    def setUp(self):
        self.repo = MiniRepository()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.parent = Path(self.tmp.name)

    def destination(self, name="output"):
        path = self.parent / name
        path.mkdir(mode=0o700)
        custody = git.GitOutput(path, git.Budget())
        self.addCleanup(custody.close)
        return custody

    def test_export_and_receipt_pinned_offline_verification(self):
        destination = self.destination()
        report, digest = git.export(self.repo.requirement, self.repo.material(), destination, git.Budget())
        root = destination.root_path / "codex-git-input"
        self.assertEqual(git.offline_verify(root, digest, self.repo.requirement, git.Budget()), report)
        self.assertTrue(report["commit_object_verified_at_acquisition"])
        self.assertFalse(report["offline_commit_identity_verified"])
        self.assertFalse(report["sdk_compilation_admitted"])
        self.assertNotIn(self.repo.commit_bytes, (root / "objects.proof").read_bytes())
        for file in root.iterdir():
            self.assertEqual(file.stat().st_mode & 0o777, 0o400)
        with self.assertRaises(ValueError):
            git.offline_verify(root, "0" * 64, self.repo.requirement, git.Budget())

    def test_forged_receipt_cannot_promote_offline_commit_or_sdk(self):
        for field in ("offline_commit_identity_verified", "sdk_compilation_admitted", "tree_oid", "inventory"):
            destination = self.destination(field)
            report, _ = git.export(self.repo.requirement, self.repo.material(), destination, git.Budget())
            report[field] = "0" * 40 if field == "tree_oid" else [] if field == "inventory" else True
            root = destination.root_path / "codex-git-input"
            path = root / "git-input-receipt.json"
            path.chmod(0o600)
            value = git.encoded(report)
            path.write_bytes(value)
            path.chmod(0o400)
            with self.subTest(field=field), self.assertRaises(ValueError):
                git.offline_verify(root, hashlib.sha256(value).hexdigest(), self.repo.requirement, git.Budget())

    def test_output_ancestor_substitution_cannot_write_outside(self):
        destination = self.destination()
        outside = self.parent / "outside"
        outside.mkdir(mode=0o700)
        original = destination.root_path.parent
        renamed = self.parent / "held-output"
        original.rename(renamed)
        original.symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            destination.write_artifact("source.tar", b"data")
        self.assertEqual(list(outside.iterdir()), [])
        self.assertEqual(list((renamed / "codex-sdk-dependency-union" / "codex-git-input").iterdir()), [])

    def test_leaf_substitution_during_write_keeps_foreign_inode_untouched(self):
        destination = self.destination()
        outside = self.parent / "outside.txt"
        outside.write_bytes(b"sentinel")
        root = destination.root_path / "codex-git-input"
        def substitute(parent, name, fd, value):
            os.unlink(name, dir_fd=parent)
            os.symlink(str(outside), name, dir_fd=parent)
            git.OutputCustody._write(destination, parent, name, fd, value)
        with patch.object(destination, "_write", substitute), self.assertRaises(ValueError):
            destination.write_artifact("source.tar", b"never written")
        self.assertEqual(outside.read_bytes(), b"sentinel")
        self.assertTrue((root / "source.tar").is_symlink())
        self.assertFalse((root / "git-input-receipt.json").exists())

    def test_partial_owned_file_is_rolled_back_after_failure(self):
        destination = self.destination()
        def failed(parent, name, fd, value):
            os.write(fd, b"partial")
            raise ValueError("modeled write failure")
        with patch.object(destination, "_write", failed), self.assertRaises(ValueError):
            destination.write_artifact("source.tar", b"payload")
        self.assertEqual(os.listdir(destination.artifacts_fd), [])
        destination.check()

    def test_subclass_creation_failure_closes_all_held_descriptors(self):
        path = self.parent / "failed-constructor"
        path.mkdir(mode=0o700)
        closed = []
        original_mkdir, original_close = git.GitOutput.mkdir, git.GitOutput.close
        def mkdir(custody, parent, name):
            if name == "codex-git-input":
                raise ValueError("modeled subclass creation failure")
            return original_mkdir(custody, parent, name)
        def close(custody):
            closed.extend(custody.fds)
            return original_close(custody)
        with patch.object(git.GitOutput, "mkdir", mkdir), patch.object(git.GitOutput, "close", close), self.assertRaises(ValueError):
            git.GitOutput(path, git.Budget())
        self.assertTrue(closed)
        for fd in closed:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_symlink_worker_hardlink_and_aggregate_disk_refuse(self):
        worker = self.destination()
        os.symlink("outside", "link", dir_fd=worker.artifacts_fd)
        with self.assertRaises(ValueError):
            git.worker_disk(worker.artifacts_fd, git.Budget())
        os.unlink("link", dir_fd=worker.artifacts_fd)
        fd = os.open("data", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=worker.artifacts_fd)
        os.write(fd, b"data")
        os.close(fd)
        os.link("data", "hardlink", src_dir_fd=worker.artifacts_fd, dst_dir_fd=worker.artifacts_fd)
        with self.assertRaises(ValueError):
            git.worker_disk(worker.artifacts_fd, git.Budget())
        os.unlink("hardlink", dir_fd=worker.artifacts_fd)
        with patch.object(git, "MAX_WORKER_BYTES", 0), self.assertRaises(ValueError):
            git.worker_disk(worker.artifacts_fd, git.Budget())

    def test_offline_custody_holds_ancestors_and_payload_inodes(self):
        destination = self.destination()
        _, digest = git.export(self.repo.requirement, self.repo.material(), destination, git.Budget())
        root = destination.root_path / "codex-git-input"
        custody = git.InputCustody(root, git.Budget())
        self.addCleanup(custody.close)
        custody.read("source.tar", git.MAX_TAR)
        payload = root / "source.tar"
        original = payload.read_bytes()
        payload.unlink()
        payload.write_bytes(original)
        payload.chmod(0o400)
        with self.assertRaises(ValueError):
            custody.check()
        # A new verifier can accept the same independently pinned bytes, but
        # the in-flight verifier must refuse a substituted inode.
        self.assertEqual(git.offline_verify(root, digest, self.repo.requirement, git.Budget())["tree_oid"], self.repo.root)
        moved = self.parent / "held-input"
        root.rename(moved)
        root.symlink_to(moved, target_is_directory=True)
        with self.assertRaises((OSError, ValueError)):
            custody.check()

    def test_retained_selector_is_exact_epoch_and_declared_output(self):
        root = git.FAST_STATE / "00000000-0000-0000-0000-000000000001" / (
            "output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_git_input_producer/"
            "test.outputs/codex-sdk-dependency-union/codex-git-input")
        self.assertEqual(git.retained_git_location(root), root)
        for other in (root.parent, root / "..", Path("/tmp/ambient/git"),
                      Path(str(root).replace("codex_git_input_producer", "arbitrary"))):
            with self.subTest(root=other), self.assertRaises(ValueError):
                git.retained_git_location(other)

    def test_home_retained_selector_accepts_only_first_declared_target_and_exact_epoch(self):
        suffix = ("output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/"
                  "codex_git_input_producer_0/test.outputs/codex-sdk-dependency-union/codex-git-input")
        root = git.HOME_GIT_STATE / "00000000-0000-0000-0000-000000000001" / suffix
        self.assertEqual(git.retained_git_location(root), root)
        for other in (root.parent, root / "..", root / "child",
                      Path(str(root).replace("codex_git_input_producer_0", "codex_git_input_producer")),
                      Path(str(root).replace("codex_git_input_producer_0", "codex_git_input_producer_1")),
                      Path(str(root).replace("00000000-0000-0000-0000-000000000001", "cache-v2-" + "0" * 64)),
                      Path(str(root).replace("omux-codex-git-prefetch-20261006", "omux-codex-git-prefetch-20261005")),
                      git.FAST_STATE / root.relative_to(git.HOME_GIT_STATE)):
            with self.subTest(root=other), self.assertRaises(ValueError):
                git.retained_git_location(other)

    def test_home_first_target_does_not_widen_home_manager_or_controller_roots(self):
        suffix = ("00000000-0000-0000-0000-000000000001/output-base/execroot/_main/bazel-out/"
                  "k8-fastbuild/testlogs/tools/codex_git_input_producer_0/test.outputs/"
                  "codex-sdk-dependency-union/codex-git-input")
        for parent in (Path('/home/jess/.local/state/omux-execution-20261005'),
                       Path('/home/jess/.local/state/omux-home-manager-prefetch-20261006'),
                       git.HOME_GIT_STATE.parent / (git.HOME_GIT_STATE.name + '-foreign')):
            with self.subTest(parent=parent), self.assertRaises(ValueError):
                git.retained_git_location(parent / suffix)

    def test_home_selected_fixture_still_requires_independently_pinned_tar_and_object_proof(self):
        home = self.parent / "modeled-home-state"
        outputs = home / "00000000-0000-0000-0000-000000000001" / (
            "output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/"
            "codex_git_input_producer_0/test.outputs")
        outputs.mkdir(parents=True, mode=0o700)
        destination = git.GitOutput(outputs, git.Budget())
        self.addCleanup(destination.close)
        report, digest = git.export(self.repo.requirement, self.repo.material(), destination, git.Budget())
        root = destination.root_path / "codex-git-input"
        modeled_requirements = ((self.repo.requirement["remote"], self.repo.commit),) + git.REQUIREMENTS[1:]
        with patch.object(git, "HOME_GIT_STATE", home), \
                patch.object(git, "REQUIREMENTS", modeled_requirements), \
                patch.object(git.subprocess, "Popen", side_effect=AssertionError("no Git execution")):
            selected = git.retained_git_location(root)
            self.assertEqual(git.offline_verify(selected, digest, self.repo.requirement, git.Budget()), report)
            tar = selected / "source.tar"
            original = tar.read_bytes()
            tar.chmod(0o600)
            tar.write_bytes(b"x" + original[1:])
            tar.chmod(0o400)
            with self.assertRaisesRegex(ValueError, "artifact digest or length differs"):
                git.offline_verify(git.retained_git_location(root), digest, self.repo.requirement, git.Budget())
        self.assertFalse(report["offline_commit_identity_verified"])
        self.assertFalse(report["sdk_compilation_admitted"])

    def test_valid_other_requirement_is_refused_before_home_payload_open_but_fast_still_verifies(self):
        other = MiniRepository(entries=[("100644", "alternate", oid("blob", b"source bytes\n"))])
        other.requirement["remote"] = git.REQUIREMENTS[1][0]
        modeled_requirements = ((self.repo.requirement["remote"], self.repo.commit),
                                (other.requirement["remote"], other.commit)) + git.REQUIREMENTS[2:]
        self.assertNotEqual(modeled_requirements[0], modeled_requirements[1])
        home, fast = self.parent / "home-state", self.parent / "fast-state"
        epoch = "00000000-0000-0000-0000-000000000001"
        exported = []
        for parent, producer in ((home, "codex_git_input_producer_0"), (fast, "codex_git_input_producer")):
            outputs = parent / epoch / ("output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/"
                                       + producer + "/test.outputs")
            outputs.mkdir(parents=True, mode=0o700)
            destination = git.GitOutput(outputs, git.Budget())
            self.addCleanup(destination.close)
            report, digest = git.export(other.requirement, other.material(), destination, git.Budget())
            exported.append((destination.root_path / "codex-git-input", report, digest))
        with patch.object(git, "HOME_GIT_STATE", home), patch.object(git, "FAST_STATE", fast), \
                patch.object(git, "REQUIREMENTS", modeled_requirements), \
                patch.object(git.subprocess, "Popen", side_effect=AssertionError("no Git execution")):
            fast_root, report, digest = exported[1]
            self.assertEqual(git.offline_verify(git.retained_git_location(fast_root), digest,
                other.requirement, git.Budget()), report)
            home_root, _, digest = exported[0]
            self.assertEqual(git.retained_git_location(home_root), home_root)
            with patch.object(git, "InputCustody", side_effect=AssertionError("no payload open")), \
                    self.assertRaisesRegex(ValueError, "HOME Git input is not the first canonical requirement"):
                git.offline_verify(home_root, digest, other.requirement, git.Budget())
        self.assertFalse(report["offline_commit_identity_verified"])
        self.assertFalse(report["sdk_compilation_admitted"])


class GitTransportModelTest(unittest.TestCase):
    def test_selector_requires_exact_current_source_derived_eleven(self):
        rows = [{"remote": remote, "commit": commit} for remote, commit in git.REQUIREMENTS]
        with patch.object(git, "source_graph", return_value=({}, {}, "")), patch.object(
                git, "git_requirements", return_value=(rows, [])):
            self.assertEqual(git.selected_requirement(10, git.Budget()), rows[10])
            for value in (-1, 11, True):
                with self.subTest(index=value), self.assertRaises(ValueError):
                    git.selected_requirement(value, git.Budget())
        with patch.object(git, "source_graph", return_value=({}, {}, "")), patch.object(
                git, "git_requirements", return_value=(rows[:-1], [])), self.assertRaises(ValueError):
            git.selected_requirement(0, git.Budget())

    def test_modeled_fetch_only_depth_one_without_history_fallback(self):
        repo, calls = MiniRepository(), []
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            worker = git.GitOutput(Path(temporary), git.Budget(), "private-worker")
            stack.callback(worker.close)
            def runner(arguments, root, fd, budget, ca, input_value, limit):
                calls.append(arguments)
                if arguments[0] != "cat-file":
                    return b""
                key = input_value.strip().decode()
                kind, value = repo.reader(key)
                return key.encode() + b" " + kind.encode() + b" " + str(len(value)).encode() + b"\n" + value + b"\n"
            with patch.object(git, "REQUIREMENTS", ((repo.requirement["remote"], repo.commit),)):
                material = git.acquire(repo.requirement, worker, git.Budget(), git.PINNED_CA, runner)
            self.assertEqual(material[0], repo.root)
            self.assertEqual(calls[1], ["fetch", "--depth=1", "--no-tags", "--no-recurse-submodules",
                                      "--no-write-fetch-head", repo.requirement["remote"], repo.commit])
            self.assertEqual(sum(row[0] == "fetch" for row in calls), 1)
            self.assertFalse(any("checkout" in row or "--unshallow" in row for row in calls))

    def test_fetch_failure_is_terminal_and_cannot_publish(self):
        repo, calls = MiniRepository(), []
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            worker = git.GitOutput(Path(temporary), git.Budget(), "private-worker")
            stack.callback(worker.close)
            def runner(arguments, *unused):
                calls.append(arguments)
                if arguments[0] == "fetch":
                    raise ValueError("modeled unavailable pinned commit")
                return b""
            with patch.object(git, "REQUIREMENTS", ((repo.requirement["remote"], repo.commit),)), self.assertRaises(ValueError):
                git.acquire(repo.requirement, worker, git.Budget(), git.PINNED_CA, runner)
            self.assertEqual([row[0] for row in calls], ["init", "fetch"])
            self.assertNotIn("git-input-receipt.json", os.listdir(worker.artifacts_fd))
            with self.assertRaises(ValueError):
                git.acquire(dict(repo.requirement, remote="https://github.com/arbitrary/input"),
                            worker, git.Budget(), git.PINNED_CA, runner)

    def test_modeled_command_count_and_object_frame_are_bounded(self):
        repo = MiniRepository()
        for count, reply in ((2, b""), (100, b"unframed object")):
            with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
                worker = git.GitOutput(Path(temporary), git.Budget(), "private-worker")
                stack.callback(worker.close)
                with patch.object(git, "REQUIREMENTS", ((repo.requirement["remote"], repo.commit),)), patch.object(
                        git, "MAX_COMMANDS", count), self.assertRaises(ValueError):
                    git.acquire(repo.requirement, worker, git.Budget(), git.PINNED_CA, lambda *unused: reply)

    def test_process_metadata_session_and_thread_bounds(self):
        self.assertEqual(git.process_record(stat_text(123, 123, 50)), (123, 123, 50))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            process = root / "123"
            process.mkdir()
            (process / "stat").write_text(stat_text(123, 123, 50))
            (process / "task").mkdir()
            (process / "task" / "123").mkdir()
            self.assertEqual(git.owned_group(123, 50, git.Budget(), proc_root=root), (1, [123]))
            for value in (stat_text(123, 124, 50), stat_text(123, 123, 49)):
                (process / "stat").write_text(value)
                with self.assertRaises(ValueError):
                    git.owned_group(123, 50, git.Budget(), proc_root=root)
            (process / "stat").write_text(stat_text(123, 123, 50))
            with patch.object(git, "MAX_TASKS", 0), self.assertRaises(ValueError):
                git.owned_group(123, 50, git.Budget(), proc_root=root)

    def test_clean_transport_environment_has_no_ambient_credentials(self):
        with patch.dict(os.environ, {"GIT_CONFIG_COUNT": "1", "HTTPS_PROXY": "private", "HOME": "/ambient"}):
            environment = git.git_environment("/owned", git.PINNED_CA)
        self.assertEqual(environment["HOME"], "/owned/home")
        self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
        self.assertNotIn("HTTPS_PROXY", environment)
        self.assertNotIn("GIT_CONFIG_COUNT", environment)
        self.assertEqual(environment["GIT_SSL_CAINFO"], str(git.PINNED_CA))

    def test_drained_final_wait_timeout_never_signals_group(self):
        child = MagicMock()
        child.pid = 123
        child.wait.side_effect = subprocess.TimeoutExpired("fixed command", 1)
        selector = MagicMock()
        selector.get_map.return_value = {}
        with patch.object(git.subprocess, "Popen") as popen, patch.object(
                git.selectors, "DefaultSelector") as selectors, patch.object(
                Path, "read_text", return_value=stat_text(123, 123, 50)), patch.object(
                git, "owned_group", return_value=(1, [123])), patch.object(
                git.os, "waitid", return_value=SimpleNamespace(si_pid=123)), patch.object(git.os, "killpg") as kill:
            popen.return_value = child
            selectors.return_value = selector
            with self.assertRaises(git.GitRefusal) as raised:
                git.run_git(["fetch"], "/owned", 999, git.Budget(), git.PINNED_CA)
            self.assertEqual((raised.exception.category, raised.exception.cleanup),
                             ("cleanup-deadline", "cleanup-deadline"))
            kill.assert_not_called()
            self.assertEqual(child.wait.call_count, 2)
            kwargs = popen.call_args.kwargs
            self.assertTrue(kwargs["start_new_session"])
            self.assertEqual(kwargs["umask"], 0o077)
            self.assertEqual(kwargs["env"]["HOME"], "/owned/home")
            self.assertEqual(popen.call_args.args[0][0], str(git.GIT))

    def test_pipe_eof_then_late_child_cannot_pass_exit_observation(self):
        child, selector, events = MagicMock(), MagicMock(), []
        child.pid = 123
        child.wait.side_effect = lambda **kwargs: events.append("reap") or 0
        selector.get_map.return_value = {}
        observations = iter((None, SimpleNamespace(si_pid=123)))
        def observe(*args):
            self.assertEqual(args, (git.os.P_PID, 123, git.os.WEXITED | git.os.WNOHANG | git.os.WNOWAIT))
            self.assertNotIn("reap", events)
            value = next(observations)
            events.append("leader-exited" if value is not None else "leader-live-after-eof")
            return value
        def group(*args):
            self.assertNotIn("reap", events)
            if "leader-exited" in events:
                events.append("late-child-observed")
                return 2, [123, 124]
            return 1, [123]
        with patch.object(git.subprocess, "Popen", return_value=child), patch.object(
                git.selectors, "DefaultSelector") as selectors, patch.object(
                Path, "read_text", return_value=stat_text(123, 123, 50)), patch.object(
                git, "owned_group", group), patch.object(git.os, "waitid", observe), patch.object(
                git, "worker_disk"), patch.object(git.time, "sleep"), patch.object(git.os, "killpg") as kill:
            selectors.return_value = selector
            kill.side_effect = lambda *args: events.append("kill-owned-group")
            with self.assertRaises(ValueError):
                git.run_git(["fetch"], "/owned", 999, git.Budget(), git.PINNED_CA)
            self.assertEqual(events, ["leader-live-after-eof", "leader-exited", "late-child-observed",
                                      "kill-owned-group", "reap"])
            kill.assert_called_once_with(123, git.signal.SIGKILL)
            child.poll.assert_not_called()



class DeadlineAndDiagnosticTests(unittest.TestCase):
    @contextmanager
    def modeled_transport(self):
        child, selector = MagicMock(), MagicMock()
        child.pid = 123
        child.wait.return_value = 0
        selector.get_map.return_value = {}
        with ExitStack() as stack:
            stack.enter_context(patch.object(git.subprocess, "Popen", return_value=child))
            factory = stack.enter_context(patch.object(
                git.selectors, "DefaultSelector", return_value=selector))
            stack.enter_context(patch.object(
                Path, "read_text", return_value=stat_text(123, 123, 50)))
            stack.enter_context(patch.object(git, "owned_group", return_value=(1, [123])))
            stack.enter_context(patch.object(
                git.os, "waitid", return_value=SimpleNamespace(si_pid=123)))
            stack.enter_context(patch.object(git, "worker_disk"))
            kill = stack.enter_context(patch.object(git.os, "killpg"))
            yield child, selector, factory, kill

    def test_buffer_allocation_failure_precedes_spawn(self):
        with self.modeled_transport() as (child, selector, factory, kill), patch.object(
                git, "bytearray", side_effect=MemoryError(), create=True):
            with self.assertRaises(MemoryError):
                git.run_git(["fetch"], "/owned", 999, git.Budget(), git.PINNED_CA)
            git.subprocess.Popen.assert_not_called()
            factory.assert_not_called()
            kill.assert_not_called()
            child.wait.assert_not_called()
            child.stdin.close.assert_not_called()
            child.stdout.close.assert_not_called()
            child.stderr.close.assert_not_called()

    def test_immediate_postspawn_setup_failure_terminates_reaps_and_releases_all_pipes(self):
        with self.modeled_transport() as (child, selector, factory, kill), patch.object(
                git, "process_record", side_effect=MemoryError()):
            with self.assertRaises(MemoryError):
                git.run_git(["fetch"], "/owned", 999, git.Budget(), git.PINNED_CA)
            git.subprocess.Popen.assert_called_once()
            kill.assert_called_once_with(123, git.signal.SIGKILL)
            child.wait.assert_called_once()
            timeout = child.wait.call_args.kwargs["timeout"]
            self.assertGreaterEqual(timeout, 0)
            self.assertLessEqual(timeout, git.CLEANUP_RESERVE)
            child.stdin.close.assert_called_once()
            child.stdout.close.assert_called_once()
            child.stderr.close.assert_called_once()
            factory.assert_not_called()
            child.poll.assert_not_called()

    def test_interrupt_after_internal_reap_never_signals_and_releases_every_descriptor(self):
        with self.modeled_transport() as (child, selector, factory, kill):
            events = []
            child.returncode = None
            def wait(*, timeout):
                self.assertGreaterEqual(timeout, 0)
                self.assertLessEqual(timeout, git.CLEANUP_RESERVE)
                events.append("bounded-wait")
                if child.returncode is None:
                    child.returncode = 0
                    events.append("internally-reaped")
                    raise KeyboardInterrupt()
                self.assertEqual(child.returncode, 0)
                return child.returncode
            child.wait.side_effect = wait
            with self.assertRaises(KeyboardInterrupt):
                git.run_git(["fetch"], "/owned", 999, git.Budget(), git.PINNED_CA)
            self.assertEqual(events, ["bounded-wait", "internally-reaped", "bounded-wait"])
            kill.assert_not_called()
            self.assertEqual(child.wait.call_count, 2)
            self.assertEqual(child.stdin.close.call_count, 2)
            child.stdout.close.assert_called_once()
            child.stderr.close.assert_called_once()
            selector.close.assert_called_once()
            child.poll.assert_not_called()

    def test_pipe_release_errors_preserve_deadline_and_prior_cleanup_failure(self):
        with self.modeled_transport() as (child, selector, factory, kill), patch.object(
                git, "owned_group", side_effect=git.DeadlineRefusal("synthetic private work")):
            child.wait.side_effect = subprocess.TimeoutExpired("synthetic private argv", 1)
            child.stdout.close.side_effect = OSError("synthetic private stdout")
            child.stderr.close.side_effect = OSError("synthetic private stderr")
            with self.assertRaises(git.GitRefusal) as raised:
                git.run_git(["fetch"], "/owned", 999, git.Budget(), git.PINNED_CA)
            self.assertEqual((raised.exception.category, raised.exception.cleanup),
                             ("deadline", "cleanup-deadline"))
            kill.assert_called_once_with(123, git.signal.SIGKILL)
            child.wait.assert_called_once()
            self.assertEqual(child.stdin.close.call_count, 2)
            child.stdout.close.assert_called_once()
            child.stderr.close.assert_called_once()
            selector.close.assert_called_once()
            self.assertNotIn("synthetic", str(raised.exception))

    def test_pipe_release_failure_refuses_success_and_attempts_every_descriptor(self):
        with self.modeled_transport() as (child, selector, factory, kill):
            child.stdin.close.side_effect = [None, OSError("synthetic private stdin")]
            child.stdout.close.side_effect = OSError("synthetic private stdout")
            child.stderr.close.side_effect = OSError("synthetic private stderr")
            with self.assertRaises(git.GitRefusal) as raised:
                git.run_git(["fetch"], "/owned", 999, git.Budget(), git.PINNED_CA)
            self.assertEqual((raised.exception.category, raised.exception.cleanup), ("io", None))
            kill.assert_not_called()
            child.wait.assert_called_once()
            self.assertEqual(child.stdin.close.call_count, 2)
            child.stdout.close.assert_called_once()
            child.stderr.close.assert_called_once()
            selector.close.assert_called_once()

    def test_closed_diagnostic_stream_cannot_skip_owned_termination_or_reap(self):
        stream = io.StringIO()
        progress = git.Progress(stream)
        progress.phase = "git-fetch"
        stream.close()
        budget = git.Budget()
        budget.progress = progress
        with self.modeled_transport() as (child, selector, factory, kill), patch.object(
                git, "owned_group", side_effect=git.DeadlineRefusal("fixed")):
            with self.assertRaises(git.GitRefusal) as raised:
                git.run_git(["fetch"], "/owned", 999, budget, git.PINNED_CA)
            self.assertEqual((raised.exception.phase, raised.exception.category,
                              raised.exception.cleanup), ("git-fetch", "deadline", "contract"))
            kill.assert_called_once_with(123, git.signal.SIGKILL)
            child.wait.assert_called_once()
            self.assertEqual(child.stdin.close.call_count, 2)
            child.stdout.close.assert_called_once()
            child.stderr.close.assert_called_once()
            self.assertEqual(progress.phase, "git-fetch")

    def test_selector_constructor_register_and_release_failures_unwind_owned_resources(self):
        for boundary in ("constructor", "register", "release"):
            with self.subTest(boundary=boundary), self.modeled_transport() as (
                    child, selector, factory, kill):
                if boundary == "constructor":
                    factory.side_effect = OSError("synthetic private constructor")
                elif boundary == "register":
                    selector.register.side_effect = OSError("synthetic private registration")
                else:
                    selector.get_map.side_effect = git.DeadlineRefusal("synthetic private work")
                    selector.close.side_effect = OSError("synthetic private release")
                    child.stdout.close.side_effect = PermissionError("synthetic private pipe")
                expected = git.GitRefusal if boundary == "release" else OSError
                with self.assertRaises(expected) as raised:
                    git.run_git(["fetch"], "/owned", 999, git.Budget(), git.PINNED_CA)
                if boundary == "release":
                    self.assertEqual((raised.exception.category, raised.exception.cleanup),
                                     ("deadline", "io"))
                else:
                    self.assertEqual(git.refusal_category(raised.exception), "io")
                kill.assert_called_once_with(123, git.signal.SIGKILL)
                child.wait.assert_called_once()
                self.assertEqual(child.stdin.close.call_count, 2)
                child.stdout.close.assert_called_once()
                child.stderr.close.assert_called_once()
                if boundary == "constructor":
                    selector.close.assert_not_called()
                else:
                    selector.close.assert_called_once()

    def test_owned_signal_failure_still_attempts_original_bounded_wait_and_pipe_release(self):
        with self.modeled_transport() as (child, selector, factory, kill), patch.object(
                git, "owned_group", side_effect=git.DeadlineRefusal("fixed")):
            kill.side_effect = PermissionError("synthetic private signal")
            child.wait.side_effect = subprocess.TimeoutExpired("synthetic private argv", 1)
            with self.assertRaises(git.GitRefusal) as raised:
                git.run_git(["fetch"], "/owned", 999, git.Budget(), git.PINNED_CA)
            self.assertEqual((raised.exception.category, raised.exception.cleanup),
                             ("deadline", "permission"))
            kill.assert_called_once_with(123, git.signal.SIGKILL)
            child.wait.assert_called_once()
            self.assertEqual(child.stdin.close.call_count, 2)
            child.stdout.close.assert_called_once()
            child.stderr.close.assert_called_once()

    def test_producer_deadline_clips_observed_and_declared_limits(self):
        with patch.object(git.time, "monotonic", return_value=101):
            for observed, deadline in (("900", 940), ("1200", 940), ("600", 640)):
                budget = git.ProducerBudget({"TEST_TIMEOUT": observed}, 100, git.Progress(io.StringIO()))
                self.assertEqual(budget.deadline, deadline)
                self.assertEqual(budget.read_bytes, 0)
                self.assertEqual(git.declared_budgets()["seconds"], 1200)
                self.assertEqual(git.declared_budgets()["per_command_seconds"], 600)

    def test_missing_malformed_or_reserveless_timeout_refuses(self):
        with patch.object(git.time, "monotonic", return_value=100):
            for observed in (None, "", "0", "-1", "0900", "900.0", "1e3", "9999999", 900, "70"):
                environment = {} if observed is None else {"TEST_TIMEOUT": observed}
                with self.subTest(kind=type(observed).__name__), self.assertRaises(git.ArgumentRefusal):
                    git.ProducerBudget(environment, 100, git.Progress(io.StringIO()))

    def test_elapsed_import_time_does_not_renew_producer_clock(self):
        with patch.object(git.time, "monotonic", return_value=941):
            with self.assertRaises(git.DeadlineRefusal):
                git.ProducerBudget({"TEST_TIMEOUT": "900"}, 100, git.Progress(io.StringIO()))

    def test_command_budget_shares_accounting_and_refuses_original_deadline(self):
        now = [100]
        with patch.object(git.time, "monotonic", side_effect=lambda: now[0]):
            parent = git.Budget(seconds=50)
            command = git.CommandBudget(parent, 140)
            command.tick(7)
            self.assertEqual(parent.read_bytes, 7)
            now[0] = 141
            with self.assertRaises(git.DeadlineRefusal):
                command.tick(9)
            self.assertEqual(parent.read_bytes, 7)
            self.assertEqual(parent.deadline, 150)

    def test_expired_pure_helpers_refuse_before_processing(self):
        repository = MiniRepository()
        material = repository.material()
        tree, records, proof, blobs, _ = material
        for function, arguments in (
                (git.tree_entries, (b"",)),
                (git.resolve_links, (records, blobs)),
                (git.proof_bytes, (proof,)),
                (git.parse_proof, (git.proof_bytes(proof),)),
                (git.canonical_tar, (records, blobs))):
            budget = SimpleNamespace(tick=MagicMock(side_effect=git.DeadlineRefusal("fixed")))
            with self.subTest(helper=function.__name__), self.assertRaises(git.DeadlineRefusal):
                function(*arguments, budget=budget)
            budget.tick.assert_called_once_with()

    def test_original_command_deadline_clips_cleanup_wait(self):
        child, selector = MagicMock(), MagicMock()
        child.pid = 123
        child.wait.return_value = 0
        selector.get_map.return_value = {}
        now = [100]
        def observe(*unused):
            now[0] = 141
            return SimpleNamespace(si_pid=123)
        def group(group_id, start, budget):
            budget.tick()
            return 1, [123]
        with patch.object(git.time, "monotonic", side_effect=lambda: now[0]):
            budget = git.Budget(seconds=50)
            with patch.object(git.subprocess, "Popen", return_value=child), patch.object(
                    git.selectors, "DefaultSelector") as selectors, patch.object(
                    Path, "read_text", return_value=stat_text(123, 123, 50)), patch.object(
                    git, "owned_group", group), patch.object(git.os, "waitid", observe), patch.object(
                    git, "worker_disk"), patch.object(git.os, "killpg") as kill:
                selectors.return_value = selector
                with self.assertRaises(git.DeadlineRefusal):
                    git.run_git(["fetch"], "/owned", 999, budget, git.PINNED_CA)
                kill.assert_called_once_with(123, git.signal.SIGKILL)
                child.wait.assert_called_once_with(timeout=9)
                child.poll.assert_not_called()
                self.assertEqual(budget.deadline, 150)

    def test_cleanup_logging_failure_cannot_skip_owned_termination(self):
        child, selector = MagicMock(), MagicMock()
        child.pid = 123
        child.wait.return_value = 0
        selector.get_map.return_value = {}
        progress = MagicMock()
        progress.phase = "git-fetch"
        progress.enter.side_effect = OSError("synthetic private diagnostic")
        def group(*unused):
            raise git.DeadlineRefusal("fixed")
        with patch.object(git.time, "monotonic", return_value=100):
            budget = git.Budget(seconds=50)
            budget.progress = progress
            with patch.object(git.subprocess, "Popen", return_value=child), patch.object(
                    git.selectors, "DefaultSelector") as selectors, patch.object(
                    Path, "read_text", return_value=stat_text(123, 123, 50)), patch.object(
                    git, "owned_group", group), patch.object(git.os, "waitid",
                    return_value=SimpleNamespace(si_pid=123)), patch.object(git.os, "killpg") as kill:
                selectors.return_value = selector
                with self.assertRaises(git.GitRefusal) as raised:
                    git.run_git(["fetch"], "/owned", 999, budget, git.PINNED_CA)
                self.assertEqual((raised.exception.phase, raised.exception.category,
                                  raised.exception.cleanup), ("git-fetch", "deadline", "io"))
                kill.assert_called_once_with(123, git.signal.SIGKILL)
                child.wait.assert_called_once_with(timeout=10)
                self.assertEqual(progress.phase, "git-fetch")

    def test_progress_is_closed_bounded_and_refusals_are_private(self):
        stream = io.StringIO()
        progress = git.Progress(stream)
        for phase in git.PHASES:
            progress.enter(phase)
            progress.enter(phase)
        git.emit_refusal(progress, ValueError("synthetic private path remote and object"))
        lines = [json.loads(line) for line in stream.getvalue().splitlines()]
        self.assertEqual(lines[:-1], [{"git_input_phase": phase} for phase in git.PHASES])
        self.assertEqual(lines[-1], {"status": "git-input-refused", "phase": "git-cleanup",
                                    "category": "contract", "cleanup": None})
        self.assertNotIn("synthetic", stream.getvalue())
        original = stream.getvalue()
        with self.assertRaises(ValueError):
            progress.enter("synthetic private invalid phase")
        self.assertEqual(stream.getvalue(), original)

    def test_primary_and_cleanup_categories_do_not_emit_exception_text(self):
        stream = io.StringIO()
        error = git.GitRefusal("object-inventory", "deadline", "cleanup-deadline")
        git.emit_refusal(git.Progress(stream), error)
        self.assertEqual(json.loads(stream.getvalue()), {
            "status": "git-input-refused", "phase": "object-inventory",
            "category": "deadline", "cleanup": "cleanup-deadline"})
        for value, category in ((git.ArgumentRefusal("private"), "arguments"),
                                (git.DeadlineRefusal("private"), "deadline"),
                                (subprocess.TimeoutExpired("private argv", 1), "cleanup-deadline"),
                                (PermissionError("private path"), "permission"),
                                (FileNotFoundError("private path"), "missing-input"),
                                (OSError("private"), "io")):
            self.assertEqual(git.refusal_category(value), category)

    def test_offline_verifier_keeps_existing_budget_without_producer_timeout(self):
        requirement = {"remote": "synthetic", "commit": "synthetic"}
        with patch.dict(os.environ, {"OMUX_EXECUTION_GUARD": "synthetic"}), patch.object(
                git, "ProducerBudget") as producer_budget, patch.object(
                git, "selected_requirement", return_value=requirement), patch.object(
                git, "retained_git_location", return_value=Path("/retained")), patch.object(
                git, "offline_verify") as verify, patch.object(
                git.sys, "stderr", io.StringIO()), patch("sys.stdout", io.StringIO()):
            git.main(["--mode", "verify", "--requirement-index", "0",
                      "--bundle-root", "/retained", "--receipt-sha256", "0" * 64])
            producer_budget.assert_not_called()
            verify.assert_called_once()
            self.assertIsInstance(verify.call_args.args[3], git.Budget)

    def test_argument_and_source_refusals_never_start_acquisition(self):
        with patch.dict(os.environ, {"OMUX_EXECUTION_GUARD": "synthetic",
                                    "TEST_TIMEOUT": "900"}), patch.object(
                git, "PRODUCER_STARTED", 100), patch.object(
                git.time, "monotonic", return_value=101), patch.object(
                git.sys, "stderr", io.StringIO()) as stream, patch.object(
                git, "acquire") as acquire, patch.object(
                git, "selected_requirement", side_effect=ValueError("synthetic private source")) as selected:
            with self.assertRaises(git.GitRefusal) as raised:
                git.main(["--mode", "acquire", "--requirement-index", "0"])
            self.assertEqual((raised.exception.phase, raised.exception.category),
                             ("source-authority", "contract"))
            selected.assert_called_once()
            acquire.assert_not_called()
            self.assertNotIn("synthetic", stream.getvalue())
            with self.assertRaises(git.GitRefusal) as raised:
                git.main(["--unknown-synthetic-private-argument"])
            self.assertEqual((raised.exception.phase, raised.exception.category),
                             ("arguments", "arguments"))



if __name__ == "__main__":
    unittest.main()
