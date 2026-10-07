"""Declared real ELF relocation/OS-image predicates; no Codex or continuity proof."""
import argparse
import json
import os
from pathlib import Path
import selectors
import subprocess
import tempfile
import unittest

import codex_direct_exec as direct

OPTIONS = None


class DirectExecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tool_hash = direct.digest(OPTIONS.patchelf.resolve(strict=True).read_bytes())
        files, runtime = direct.runtime.assemble_runtime(
            OPTIONS.fixture, OPTIONS.runtime_file, OPTIONS.patchelf, OPTIONS.ca_bundle)
        cls.files = files
        cls.manifest = {"files": {name: {"mode": 0o644 if name == direct.runtime.CA else 0o755}
                                  for name in files}, "runtime": runtime,
                        "candidate": {"upstream_commit": "synthetic-ELF-fixture-only"}}
        cls.inputs = {"qualification": "synthetic-transformation-test-only"}

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="omux-direct-exec-")
        self.prefix = Path(self.temporary.name) / "installed"
        self.installation = None

    def tearDown(self):
        if self.installation is not None:
            self.installation.close()
        self.temporary.cleanup()

    def install(self):
        tool = direct.Tool(OPTIONS.patchelf, self.tool_hash)
        try:
            self.installation = direct._relocate_verified(
                self.prefix, tool, self.manifest, self.files, self.inputs)
        finally:
            tool.close()
        return self.installation

    def held_child(self, installation):
        child = subprocess.Popen([str(installation.prefix / direct.LAUNCHER)],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, env={"PATH": "/nonexistent"})
        selector = selectors.DefaultSelector()
        try:
            selector.register(child.stdout, selectors.EVENT_READ)
            self.assertTrue(selector.select(10), "declared direct fixture did not start")
            self.assertEqual(child.stdout.readline(), b"OMUX_DIRECT_EXEC_FIXTURE_READY\n")
            return child
        except BaseException:
            child.kill()
            child.wait(timeout=5)
            raise
        finally:
            selector.close()

    def finish_child(self, child):
        try:
            child.communicate(b"q", timeout=5)
            self.assertEqual(child.returncode, 0)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)

    def test_kernel_exe_is_exact_relocated_backend_and_original_bytes_remain(self):
        before = dict(self.files)
        installed = self.install()
        child = self.held_child(installed)
        pidfd = os.pidfd_open(child.pid)
        try:
            observation = direct.observe_kernel_backend(installed, pidfd)
            self.assertEqual(observation["backend_inode"], installed.record["files"][direct.BACKEND]["inode"])
            self.assertEqual(observation["backend_sha256"], installed.record["files"][direct.BACKEND]["sha256"])
            self.assertEqual(observation["exec_incarnation"], "unproved")
            self.assertFalse(installed.record["native_support"])
            self.assertEqual(installed.record["actor_selection"], "uncommitted")
            self.assertEqual(self.files, before)
            backend = (installed.prefix / direct.BACKEND).read_bytes()
            metadata = direct.runtime.portable.elf_metadata(backend)
            self.assertEqual(metadata["interpreter"], str(installed.prefix / direct.LOADER))
            self.assertTrue(all(name.startswith(str(installed.prefix) + "/") for name in metadata["needed"]))
            self.assertNotEqual(backend, before[direct.BACKEND])
        finally:
            os.close(pidfd)
            self.finish_child(child)

    def test_another_kernel_executable_does_not_attest_backend(self):
        installed = self.install()
        pidfd = os.pidfd_open(os.getpid())
        try:
            with self.assertRaisesRegex(ValueError, "kernel executable"):
                direct.observe_kernel_backend(installed, pidfd)
        finally:
            os.close(pidfd)

    def test_exclusive_root_and_symlinked_ancestor_refused(self):
        self.prefix.mkdir(mode=0o700)
        with self.assertRaises(FileExistsError):
            self.install()
        self.prefix.rmdir()
        alias = Path(self.temporary.name) / "alias"
        alias.symlink_to(Path(self.temporary.name), target_is_directory=True)
        self.prefix = alias / "installed"
        with self.assertRaises(OSError):
            self.install()

    def test_root_replacement_refused(self):
        installed = self.install()
        displaced = self.prefix.with_name("displaced")
        self.prefix.rename(displaced)
        self.prefix.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, "root replaced"):
            installed.recheck()

    def test_same_bytes_replaced_backend_inode_refused(self):
        installed = self.install()
        backend = self.prefix / direct.BACKEND
        payload = backend.read_bytes()
        backend.unlink()
        backend.write_bytes(payload)
        backend.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "payload changed"):
            installed.recheck()

    def test_payload_symlink_and_receipt_mutation_refused(self):
        installed = self.install()
        receipt = self.prefix / direct.RECEIPT
        receipt.write_bytes(b"{}\n")
        with self.assertRaisesRegex(ValueError, "receipt changed"):
            installed.recheck()
        receipt.write_bytes(installed.encoded)
        # This changed inode metadata remains a rejection even with identical bytes.
        with self.assertRaisesRegex(ValueError, "receipt changed"):
            installed.recheck()

    def test_installed_backend_symlink_refused(self):
        installed = self.install()
        backend = self.prefix / direct.BACKEND
        target = backend.with_name("copied")
        backend.rename(target)
        backend.symlink_to(target)
        with self.assertRaises(OSError):
            installed.recheck()

    def test_wrong_declared_tool_identity_refused_before_install(self):
        with self.assertRaisesRegex(ValueError, "patchelf identity"):
            direct.Tool(OPTIONS.patchelf, "1" * 64)
        self.assertFalse(self.prefix.exists())

    def test_unverified_runtime_refused_before_root_creation(self):
        with self.assertRaises(ValueError):
            direct.install_runtime(b"not-an-archive", b"{}", b"{}", prefix=self.prefix,
                patchelf=OPTIONS.patchelf, expected_runtime_inputs={},
                expected_source_receipt_sha256="1" * 64,
                expected_producer_receipt_sha256="2" * 64, expected_patchelf_sha256=self.tool_hash)
        self.assertFalse(self.prefix.exists())


    def test_each_independent_runtime_digest_and_byte_count_is_required(self):
        values = (b"synthetic-archive", b"synthetic-manifest", b"synthetic-receipt")
        names = ("archive", "manifest", "runtime_receipt")
        selected = {name: {"sha256": direct.digest(value), "bytes": len(value)}
                    for name, value in zip(names, values)}
        direct.verify_selected_inputs(*values, selected)
        for index, name in enumerate(names):
            with self.subTest(name=name):
                changed = list(values)
                changed[index] += b"forged"
                with self.assertRaises(ValueError):
                    direct.verify_selected_inputs(*changed, selected)
                wrong = json.loads(json.dumps(selected))
                wrong[name]["sha256"] = "1" * 64
                with self.assertRaises(ValueError):
                    direct.verify_selected_inputs(*values, wrong)
                wrong = json.loads(json.dumps(selected))
                wrong[name]["bytes"] = True
                with self.assertRaises(ValueError):
                    direct.verify_selected_inputs(*values, wrong)
        with self.assertRaises(ValueError):
            direct.verify_selected_inputs(*values, {})

    def test_byte_identical_receipt_replacement_refused(self):
        installed = self.install()
        receipt = self.prefix / direct.RECEIPT
        receipt.unlink()
        receipt.write_bytes(installed.encoded)
        receipt.chmod(0o600)
        with self.assertRaisesRegex(ValueError, "receipt changed"):
            installed.recheck()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("fixture", type=Path)
    parser.add_argument("patchelf", type=Path)
    parser.add_argument("ca_bundle", type=Path)
    parser.add_argument("--runtime-file", type=Path, action="append", required=True)
    OPTIONS, rest = parser.parse_known_args()
    unittest.main(argv=[__file__, *rest])
