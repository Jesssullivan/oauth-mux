"""Fixed offline retained input profile and physical artifact refusal predicates."""
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import codex_owner_runtime_input as runtime
import guard_owner_runtime_input as subject


class ProfileTests(unittest.TestCase):
    def test_device_api_qualification_is_offline_exact_consumer_only(self):
        label = "//tools:codex_retained_device_api_qualification"
        self.assertIn(label,subject.CONSUMERS)
        subject.finite("standard",["test",label,"//tools:execution_guard_test"])
        for profile,arguments in (("codex-login",["test",label]),
                ("standard",["run",label]),("standard",["test",label,"//delivery:native_account_login"])):
            with self.subTest(profile=profile,arguments=arguments),self.assertRaises(ValueError):
                subject.finite(profile,arguments)

    def test_retained_ordinary_tui_adds_only_an_exact_offline_test_consumer(self):
        label = "//delivery:installed_retained_ordinary_native_tui_test"
        self.assertIn(label, subject.CONSUMERS)
        self.assertNotIn(label, subject.COMPANIONS)
        companion = "//delivery:retained_ordinary_native_tui_contract_test"
        self.assertIn(companion, subject.COMPANIONS)
        self.assertNotIn(companion, subject.CONSUMERS)
        subject.finite("standard", ["test", label, companion, "//tools:guard_owner_runtime_input_test"])
        with self.assertRaises(ValueError):
            subject.finite("standard", ["test", companion])
        subject.finite("standard", ["test", label, "//tools:execution_guard_test"])
        # Existing finite build behavior is unchanged; this exposes no RUN.
        subject.finite("standard", ["build", label])
        for profile, arguments in (
                ("standard", ["run", label]),
                ("standard", ["test", label, label]),
                ("standard", ["test", label, "//..."]),
                ("standard", ["test", label, "//delivery:resident_codex_live_continuity"]),
                ("standard", ["test", label, "--test_arg=provider"]),
                ("codex-live", ["test", label]),
                ("codex-sdk", ["test", label])):
            with self.subTest(profile=profile, arguments=arguments), self.assertRaises(ValueError):
                subject.finite(profile, arguments)
        with self.assertRaises(ValueError):
            subject.finite("standard", ["test", label], [True])

    def test_finite_retained_consumers_admitted(self):
        for label in subject.CONSUMERS:
            subject.finite("standard", ["test", label, "//tools:execution_guard_test"])

    def test_instrumented_diagnostic_is_separate_from_ordinary_proof_consumers(self):
        label = subject.DIAGNOSTIC
        subject.finite("standard", ["test", label, "//:docs_check"])
        for companion in subject.CONSUMERS - {label}:
            with self.assertRaisesRegex(ValueError, "^retained-diagnostic-profile$"):
                subject.finite("standard", ["test", label, companion])
        for values in ([label, label], [label, "--jobs=9"], [label, "//..."],
                       [label, "//delivery:native_fd2_observer_test"]):
            with self.assertRaises(ValueError):
                subject.finite("standard", ["test", *values])

    def test_no_wildcard_unknown_flags_or_duplicate_labels(self):
        label = "//delivery:installed_legacy_native_tui_test"
        for values in (["//..."], [label, "//:engine_test"], [label, "--jobs=9"], [label, label]):
            with self.assertRaises(ValueError):
                subject.finite("standard", ["test", *values])

    def test_inputs_are_exclusive_to_standard_offline_profile(self):
        for profile in ("dependency-prefetch", "site", "codex-sdk", "installed-browser", "yoga-toolbar", "yoga-controller-delivery"):
            with self.assertRaises(ValueError):
                subject.finite(profile, ["test", "//delivery:installed_native_interop_test"])
        with self.assertRaises(ValueError):
            subject.finite("standard", ["test", "//delivery:installed_native_interop_test"], [True])

    def test_companions_alone_and_run_verb_refused(self):
        for args in (["test", "//:docs_check"], ["run", "//tools:codex_owner_runtime_input_qualification"]):
            with self.assertRaises(ValueError):
                subject.finite("standard", args)


class InputTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR"))
        self.addCleanup(self.scratch.cleanup)
        self.addCleanup(lambda: self.root.chmod(0o700) if self.root.is_dir() else None)
        self.base = Path(self.scratch.name)
        self.source = self.base / "source"
        self.source.mkdir()
        self.manifest = self.source / "runtime-manifest.json"
        self.receipt = self.source / "runtime-receipt.json"
        self.manifest.write_bytes(b'{"native_support":false}\n')
        self.receipt.write_bytes(b'{"scope":"synthetic retained qualification"}\n')
        self.payload = b"fixed retained archive" * 29
        self.root = self.base / hashlib.sha256(self.payload).hexdigest()
        self.root.mkdir(mode=0o700)
        self.archive = self.root / runtime.NAME
        self.archive.write_bytes(self.payload)
        self.archive.chmod(0o400)
        self.pins = patch.multiple(runtime, ARCHIVE_SHA=self.root.name, ARCHIVE_BYTES=len(self.payload),
                                  MANIFEST_SHA=hashlib.sha256(self.manifest.read_bytes()).hexdigest(),
                                  EXPECTED_RECEIPT=self.receipt.read_bytes())
        self.pins.start()
        self.addCleanup(self.pins.stop)
        # Fixtures live in Bazel scratch, whose ancestors are not the operator
        # durable-input boundary. Exercise the leaf with real no-follow opens.
        self.walk = patch.object(subject, "directory", self.fixture_directory)
        self.walk.start()
        self.addCleanup(self.walk.stop)

    def fixture_directory(self, path):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        info = os.fstat(fd)
        try:
            subject.leaf_custody(info)
        except BaseException:
            os.close(fd)
            raise
        return fd

    def selected(self):
        value = subject.Admission(self.root, self.manifest, self.receipt, self.source, time.monotonic_ns() + 5 * 10**9)
        self.addCleanup(value.close)
        return value

    def test_exact_owned_identity_is_not_native_authority(self):
        value = self.selected()
        self.assertFalse(value.recheck()["nativeSupport"])
        self.assertEqual(value.facts()["archiveSha256"], self.root.name)

    def test_bazel_sealed_leaf_and_archive_are_admitted(self):
        self.archive.chmod(0o555)
        self.root.chmod(0o555)
        value = self.selected()
        facts = value.recheck()
        self.assertEqual(facts["physicalDirectory"]["mode"], 0o555)
        self.assertEqual(facts["physicalArchive"]["mode"], 0o555)
        self.assertFalse(facts["nativeSupport"])

    def test_wrong_leaf_modes_refused(self):
        for mode in (0o777, 0o755, 0o575, 0o577):
            self.root.chmod(mode)
            with self.assertRaisesRegex(ValueError, "directory-custody"):
                self.selected()
        self.root.chmod(0o700)

    def test_wrong_leaf_archive_mode_pairs_refused(self):
        for leaf_mode, archive_mode in ((0o700, 0o555), (0o700, 0o600),
                                        (0o555, 0o400), (0o555, 0o444),
                                        (0o555, 0o755)):
            self.root.chmod(leaf_mode)
            self.archive.chmod(archive_mode)
            with self.assertRaisesRegex(ValueError, "archive-mode"):
                self.selected()
        self.root.chmod(0o700)
        self.archive.chmod(0o400)

    def test_sealed_chmod_after_admission_refused(self):
        self.archive.chmod(0o555)
        self.root.chmod(0o555)
        value = self.selected()
        self.archive.chmod(0o400)
        with self.assertRaisesRegex(ValueError, "input-changed"):
            value.recheck()

    def test_sealed_replacement_after_admission_refused(self):
        self.archive.chmod(0o555)
        self.root.chmod(0o555)
        value = self.selected()
        self.root.chmod(0o700)
        self.archive.rename(self.root / "old")
        self.archive.write_bytes(self.payload)
        self.archive.chmod(0o555)
        (self.root / "old").unlink()
        self.root.chmod(0o555)
        with self.assertRaisesRegex(ValueError, "input-changed"):
            value.recheck()

    def test_final_archive_symlink_refused(self):
        self.archive.unlink()
        elsewhere = self.base / "archive"
        elsewhere.write_bytes(self.payload)
        self.archive.symlink_to(elsewhere)
        with self.assertRaises(OSError):
            self.selected()

    def test_hardlink_group_write_and_wrong_bytes_refused(self):
        os.link(self.archive, self.base / "other")
        with self.assertRaises(ValueError):
            self.selected()
        (self.base / "other").unlink()
        self.archive.chmod(0o620)
        with self.assertRaises(ValueError):
            self.selected()
        self.archive.chmod(0o600)
        self.archive.write_bytes(b"x" * len(self.payload))
        self.archive.chmod(0o400)
        with self.assertRaises(ValueError):
            self.selected()

    def test_extra_directory_member_refused(self):
        (self.root / "unexpected").write_bytes(b"no")
        with self.assertRaises(ValueError):
            self.selected()

    def test_same_bytes_new_inode_refused_on_recheck(self):
        value = self.selected()
        self.archive.rename(self.root / "old")
        self.archive.write_bytes(self.payload)
        (self.root / "old").unlink()
        with self.assertRaises(ValueError):
            value.recheck()

    def test_changed_tracked_manifest_refuses(self):
        value = self.selected()
        self.manifest.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            value.recheck()

    def test_wrong_digest_root_and_source_nested_root_refused(self):
        old = self.root
        self.root = self.base / "wrong"
        old.rename(self.root)
        with self.assertRaises(ValueError):
            self.selected()
        self.root = self.source / old.name
        (self.base / "wrong").rename(self.root)
        with self.assertRaises(ValueError):
            self.selected()

    def test_deadline_does_not_restart_on_readback(self):
        value = self.selected()
        value.deadline_ns = time.monotonic_ns()
        with self.assertRaisesRegex(ValueError, "deadline"):
            value.recheck()

    def test_ancestor_writable_and_leaf_link_refused_by_real_walk(self):
        self.walk.stop()
        with self.assertRaises((OSError, ValueError)):
            subject.directory(self.base / "absent")
        link = self.base / "link"
        link.symlink_to(self.root)
        with self.assertRaises((OSError, ValueError)):
            subject.directory(link)


if __name__ == "__main__":
    unittest.main()
