"""Ownership and path safety of explicit native-messaging registration.

All fixtures live under a resolved temporary directory. These tests neither
launch browsers nor register hosts in an actual user profile.
"""

from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest import mock

import native_host_setup as setup


CHROMIUM_ID = "abcdefghijklmnopabcdefghijklmnop"
FIREFOX_ID = "browser-sources@omux.xoxd.ai"
HOST = "ai.xoxd.omux"


class NativeHostSetupTest(unittest.TestCase):
    def test_development_manifest_has_separate_host_and_exact_identity(self):
        binary = Path("/nix/store/example-omux/bin/omux-native-host")
        output = setup.manifest("chromium", "b" * 32, binary, "development")
        self.assertEqual(output["name"], "ai.xoxd.omux.dev")
        self.assertEqual(output["allowed_origins"], ["chrome-extension://" + "b" * 32 + "/"])
        self.assertEqual(output["path"], str(binary))
        with self.assertRaises(setup.SetupError):
            setup.manifest("firefox", FIREFOX_ID, binary, "development")
        with self.assertRaises(setup.SetupError):
            setup.manifest("chromium", CHROMIUM_ID, binary, "unknown")

    def test_development_registration_coexists_and_cannot_remove_release(self):
        self.assertEqual(self.install(), "installed")
        development = self.hosts / "ai.xoxd.omux.dev.json"
        self.assertEqual(setup.install("chromium", "b" * 32, self.binary, development, "development"), "installed")
        owner = json.loads(Path(str(development) + ".omux-owner.json").read_text())
        self.assertEqual(owner["managed_by"], "ai.xoxd.omux.dev")
        with self.assertRaises(setup.SetupError):
            setup.remove("chromium", "b" * 32, self.binary, self.destination, "development")
        self.assertEqual(setup.remove("chromium", "b" * 32, self.binary, development, "development"), "removed")
        self.assertTrue(self.destination.is_file())

    def test_dangling_declarative_registration_is_preserved_with_guidance(self):
        target = "/nix/store/nonexistent-home-manager-files/native-host.json"
        self.destination.symlink_to(target)
        for action in (self.install, self.remove):
            with self.subTest(action=action.__name__):
                with self.assertRaisesRegex(setup.SetupError, "Home Manager"):
                    action()
                self.assertEqual(os.readlink(self.destination), target)
                self.assertFalse(self.receipt.exists())

    def setUp(self):
        # Bazel's default TMPDIR may live below a sandbox/runfiles ancestry
        # that deliberately does not satisfy installed-host custody rules.
        # Use the real OS temporary root (Darwin's /tmp is a symlink) and keep
        # every fixture private; production ancestry validation stays intact.
        fixture_parent = Path("/tmp").resolve()
        self.temporary = tempfile.TemporaryDirectory(prefix="omux-host-setup-", dir=fixture_parent)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.root.chmod(0o700)
        self.binary_dir = self.root / "bin"
        self.binary_dir.mkdir(mode=0o700)
        self.binary = self.binary_dir / "omux-native-host"
        self.binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.binary.chmod(0o700)
        self.hosts = self.root / "hosts"
        self.hosts.mkdir(mode=0o700)
        self.destination = self.hosts / f"{HOST}.json"
        self.receipt = Path(str(self.destination) + ".omux-owner.json")

    def install(self, browser="chromium", extension_id=CHROMIUM_ID, binary=None, destination=None):
        return setup.install(browser, extension_id, binary or self.binary, destination or self.destination)

    def remove(self, browser="chromium", extension_id=CHROMIUM_ID, binary=None, destination=None):
        return setup.remove(browser, extension_id, binary or self.binary, destination or self.destination)

    def reject_existing_pair(self):
        """A rejected update/removal must preserve every existing byte."""
        before = {
            path: path.read_bytes()
            for path in (self.destination, self.receipt)
            if path.exists() and not path.is_symlink()
        }
        with self.assertRaises(setup.SetupError):
            self.install()
        with self.assertRaises(setup.SetupError):
            self.remove()
        for path, contents in before.items():
            self.assertEqual(path.read_bytes(), contents)

    def reject_fifo_promptly(self, action, fifo):
        """A blocking-open regression must fail without hanging the test process."""
        outcomes = []

        def invoke():
            try:
                outcomes.append(("returned", action()))
            except Exception as error:
                outcomes.append(("raised", error))

        worker = threading.Thread(target=invoke, daemon=True)
        worker.start()
        worker.join(0.5)
        blocked = worker.is_alive()
        if blocked:
            # Release an old blocking FIFO open for cleanup where possible. The
            # daemon thread still cannot keep Bazel alive if cleanup also fails.
            try:
                descriptor = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
            except OSError:
                pass
            else:
                os.close(descriptor)
            worker.join(0.5)
        self.assertFalse(blocked, "registration waited for a FIFO writer")
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0][0], "raised")
        self.assertIsInstance(outcomes[0][1], setup.SetupError)

    def test_chromium_manifest_has_only_exact_extension_authority(self):
        manifest = setup.manifest("chromium", CHROMIUM_ID, self.binary)
        self.assertEqual(manifest["name"], HOST)
        self.assertEqual(manifest["type"], "stdio")
        self.assertEqual(manifest["path"], str(self.binary))
        self.assertEqual(manifest["allowed_origins"], [f"chrome-extension://{CHROMIUM_ID}/"])
        self.assertNotIn("allowed_extensions", manifest)

    def test_firefox_manifest_has_only_exact_extension_authority(self):
        manifest = setup.manifest("firefox", FIREFOX_ID, self.binary)
        self.assertEqual(manifest["name"], HOST)
        self.assertEqual(manifest["type"], "stdio")
        self.assertEqual(manifest["path"], str(self.binary))
        self.assertEqual(manifest["allowed_extensions"], [FIREFOX_ID])
        self.assertNotIn("allowed_origins", manifest)

    def test_manifest_can_be_reviewed_before_binary_exists(self):
        candidate = self.root / "future" / "omux-native-host"
        manifest = setup.manifest("chromium", CHROMIUM_ID, candidate)
        self.assertEqual(manifest["path"], str(candidate))
        self.assertFalse(candidate.exists())
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.receipt.exists())

    def test_cli_default_emits_reviewable_json_without_creating_files(self):
        candidate = self.root / "not-installed" / "omux-native-host"
        output = io.StringIO()
        with redirect_stdout(output):
            result = setup.main([
                "--browser", "chromium",
                "--extension-id", CHROMIUM_ID,
                "--binary", str(candidate),
                "--manifest", str(self.destination),
            ])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue()), setup.manifest("chromium", CHROMIUM_ID, candidate))
        self.assertFalse(candidate.parent.exists())
        self.assertEqual(list(self.hosts.iterdir()), [])

    def test_manifest_rejects_unsupported_browser_and_extension_ids(self):
        invalid = [
            ("chrome", CHROMIUM_ID),
            ("safari", CHROMIUM_ID),
            ("chromium", "a" * 31),
            ("chromium", "a" * 33),
            ("chromium", "q" * 32),
            ("chromium", "A" * 32),
            ("chromium", "a" * 31 + "\n"),
            ("chromium", "chrome-extension://" + CHROMIUM_ID + "/"),
            ("firefox", "another-extension@omux.xoxd.ai"),
            ("firefox", CHROMIUM_ID),
            ("firefox", FIREFOX_ID + "\n"),
        ]
        for browser, extension_id in invalid:
            with self.subTest(browser=browser, extension_id=extension_id):
                with self.assertRaises(setup.SetupError):
                    setup.manifest(browser, extension_id, self.binary)

    def test_manifest_rejects_relative_binary_and_wrong_executable_name(self):
        for binary in (Path("omux-native-host"), self.root / "omux", self.root / "omux-native-host.other"):
            with self.subTest(binary=binary):
                with self.assertRaises(setup.SetupError):
                    setup.manifest("chromium", CHROMIUM_ID, binary)

    def test_install_creates_private_manifest_and_ownership_receipt(self):
        self.assertEqual(self.install(), "installed")
        self.assertEqual(json.loads(self.destination.read_text(encoding="utf-8")), setup.manifest("chromium", CHROMIUM_ID, self.binary))
        self.assertTrue(self.receipt.is_file())
        for path in (self.destination, self.receipt):
            with self.subTest(path=path):
                info = path.stat()
                self.assertTrue(stat.S_ISREG(info.st_mode))
                self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
                self.assertEqual(info.st_uid, os.getuid())

    def test_created_files_have_private_mode_even_with_restrictive_umask(self):
        previous_mask = os.umask(0o777)
        try:
            self.assertEqual(self.install(), "installed")
            self.assertEqual(self.install(), "unchanged")
        finally:
            os.umask(previous_mask)
        for path in (self.destination, self.receipt):
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_repeat_install_preserves_bytes_inode_owner_and_group(self):
        self.assertEqual(self.install(), "installed")
        before = {
            path: (path.read_bytes(), path.stat().st_ino, path.stat().st_uid, path.stat().st_gid)
            for path in (self.destination, self.receipt)
        }
        self.assertEqual(self.install(), "unchanged")
        for path, expected in before.items():
            info = path.stat()
            self.assertEqual((path.read_bytes(), info.st_ino, info.st_uid, info.st_gid), expected)

    def test_firefox_install_and_remove_use_the_same_owned_pair_contract(self):
        self.assertEqual(self.install("firefox", FIREFOX_ID), "installed")
        self.assertEqual(self.install("firefox", FIREFOX_ID), "unchanged")
        self.assertEqual(json.loads(self.destination.read_text(encoding="utf-8"))["allowed_extensions"], [FIREFOX_ID])
        self.assertEqual(self.remove("firefox", FIREFOX_ID), "removed")
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.receipt.exists())

    def test_remove_restores_absence_and_is_idempotent(self):
        self.assertEqual(self.remove(), "absent")
        self.assertEqual(self.install(), "installed")
        self.assertEqual(self.remove(), "removed")
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.receipt.exists())
        self.assertEqual(self.remove(), "absent")

    def test_manual_manifest_with_identical_bytes_is_never_adopted(self):
        self.assertEqual(self.install(), "installed")
        self.receipt.unlink()
        self.reject_existing_pair()
        self.assertFalse(self.receipt.exists())

    def test_orphan_receipt_is_not_overwritten_or_silently_removed(self):
        self.assertEqual(self.install(), "installed")
        self.destination.unlink()
        self.reject_existing_pair()
        self.assertFalse(self.destination.exists())

    def test_modified_manifest_bytes_prevent_update_and_removal(self):
        self.assertEqual(self.install(), "installed")
        with self.destination.open("ab") as stream:
            stream.write(b" ")
        self.reject_existing_pair()

    def test_modified_manifest_mode_prevents_update_and_removal(self):
        self.assertEqual(self.install(), "installed")
        self.destination.chmod(0o644)
        self.reject_existing_pair()
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o644)

    def test_replacement_manifest_inode_prevents_update_and_removal(self):
        self.assertEqual(self.install(), "installed")
        previous_inode = self.destination.stat().st_ino
        replacement = self.hosts / "replacement.json"
        replacement.write_bytes(self.destination.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(self.destination)
        self.assertNotEqual(self.destination.stat().st_ino, previous_inode)
        self.reject_existing_pair()

    def test_corrupt_receipt_is_not_trusted_or_replaced(self):
        for contents in (b"not json\n", b"{}\n", b"[]\n", b'{"version":999}\n'):
            with self.subTest(contents=contents):
                if self.destination.exists():
                    self.destination.unlink()
                if self.receipt.exists():
                    self.receipt.unlink()
                self.assertEqual(self.install(), "installed")
                self.receipt.write_bytes(contents)
                self.reject_existing_pair()

    def test_unsafe_receipt_permissions_prevent_update_and_removal(self):
        self.assertEqual(self.install(), "installed")
        self.receipt.chmod(0o666)
        self.reject_existing_pair()

    def test_manifest_symlink_is_refused_without_touching_its_target(self):
        victim = self.root / "unowned-manifest.json"
        victim.write_text("unowned fixture\n", encoding="utf-8")
        self.destination.symlink_to(victim)
        with self.assertRaises(setup.SetupError):
            self.install()
        with self.assertRaises(setup.SetupError):
            self.remove()
        self.assertTrue(self.destination.is_symlink())
        self.assertEqual(victim.read_text(encoding="utf-8"), "unowned fixture\n")
        self.assertFalse(self.receipt.exists())

    def test_receipt_symlink_is_refused_without_touching_its_target(self):
        self.assertEqual(self.install(), "installed")
        victim = self.root / "unowned-receipt.json"
        victim.write_bytes(self.receipt.read_bytes())
        self.receipt.unlink()
        self.receipt.symlink_to(victim)
        original = victim.read_bytes()
        with self.assertRaises(setup.SetupError):
            self.install()
        with self.assertRaises(setup.SetupError):
            self.remove()
        self.assertTrue(self.receipt.is_symlink())
        self.assertEqual(victim.read_bytes(), original)

    def test_manifest_directory_is_refused_without_deleting_it(self):
        self.destination.mkdir(mode=0o700)
        with self.assertRaises(setup.SetupError):
            self.install()
        with self.assertRaises(setup.SetupError):
            self.remove()
        self.assertTrue(self.destination.is_dir())
        self.assertFalse(self.receipt.exists())

    def test_receipt_directory_is_refused_without_deleting_it(self):
        self.receipt.mkdir(mode=0o700)
        with self.assertRaises(setup.SetupError):
            self.install()
        with self.assertRaises(setup.SetupError):
            self.remove()
        self.assertTrue(self.receipt.is_dir())
        self.assertFalse(self.destination.exists())

    def test_manifest_fifo_is_rejected_without_waiting_for_a_writer(self):
        os.mkfifo(self.destination, 0o600)
        self.reject_fifo_promptly(self.install, self.destination)
        self.reject_fifo_promptly(self.remove, self.destination)
        self.assertTrue(stat.S_ISFIFO(self.destination.lstat().st_mode))
        self.assertFalse(self.receipt.exists())

    def test_receipt_fifo_is_rejected_without_waiting_for_a_writer(self):
        self.assertEqual(self.install(), "installed")
        original_manifest = self.destination.read_bytes()
        self.receipt.unlink()
        os.mkfifo(self.receipt, 0o600)
        self.reject_fifo_promptly(self.install, self.receipt)
        self.reject_fifo_promptly(self.remove, self.receipt)
        self.assertTrue(stat.S_ISFIFO(self.receipt.lstat().st_mode))
        self.assertEqual(self.destination.read_bytes(), original_manifest)

    def test_symlink_parent_is_refused_even_when_target_is_owned_and_private(self):
        alias = self.root / "hosts-alias"
        alias.symlink_to(self.hosts, target_is_directory=True)
        destination = alias / f"{HOST}.json"
        with self.assertRaises(setup.SetupError):
            self.install(destination=destination)
        with self.assertRaises(setup.SetupError):
            self.remove(destination=destination)
        self.assertFalse(self.destination.exists())

    def test_destination_must_be_absolute_and_have_exact_host_basename(self):
        for destination in (Path(f"{HOST}.json"), self.hosts / "other-host.json", self.hosts / f"{HOST}.json.other"):
            with self.subTest(destination=destination):
                with self.assertRaises(setup.SetupError):
                    self.install(destination=destination)
                with self.assertRaises(setup.SetupError):
                    self.remove(destination=destination)
        self.assertEqual(list(self.hosts.iterdir()), [])

    def test_destination_parent_must_exist(self):
        destination = self.root / "missing-parent" / f"{HOST}.json"
        with self.assertRaises(setup.SetupError):
            self.install(destination=destination)
        self.assertFalse(destination.parent.exists())

    def test_group_or_world_writable_destination_parent_is_refused(self):
        for mode in (0o770, 0o707, 0o777):
            with self.subTest(mode=oct(mode)):
                self.hosts.chmod(mode)
                with self.assertRaises(setup.SetupError):
                    self.install()
                with self.assertRaises(setup.SetupError):
                    self.remove()
        self.hosts.chmod(0o700)
        self.assertEqual(list(self.hosts.iterdir()), [])

    def test_private_destination_under_writable_nonsticky_ancestor_is_refused(self):
        ancestor = self.root / "replaceable-ancestor"
        ancestor.mkdir(mode=0o700)
        private_parent = ancestor / "private-hosts"
        private_parent.mkdir(mode=0o700)
        destination = private_parent / f"{HOST}.json"
        ancestor.chmod(0o777)
        # The host executable remains in its independent safe directory.
        with self.assertRaises(setup.SetupError):
            self.install(destination=destination)
        with self.assertRaises(setup.SetupError):
            self.remove(destination=destination)
        self.assertEqual(list(private_parent.iterdir()), [])

    def test_install_requires_existing_regular_executable(self):
        self.binary.unlink()
        with self.assertRaises(setup.SetupError):
            self.install()
        self.binary.mkdir(mode=0o700)
        with self.assertRaises(setup.SetupError):
            self.install()
        self.binary.rmdir()
        self.binary.write_text("fixture\n", encoding="utf-8")
        self.binary.chmod(0o600)
        with self.assertRaises(setup.SetupError):
            self.install()
        self.assertEqual(list(self.hosts.iterdir()), [])

    def test_install_refuses_group_or_world_writable_executable(self):
        for mode in (0o770, 0o707, 0o777):
            with self.subTest(mode=oct(mode)):
                self.binary.chmod(mode)
                with self.assertRaises(setup.SetupError):
                    self.install()
        self.assertEqual(list(self.hosts.iterdir()), [])

    def test_install_refuses_writable_nonsticky_executable_parent(self):
        for mode in (0o770, 0o707, 0o777):
            with self.subTest(mode=oct(mode)):
                self.binary_dir.chmod(mode)
                with self.assertRaises(setup.SetupError):
                    self.install()
        self.binary_dir.chmod(0o700)
        self.assertEqual(list(self.hosts.iterdir()), [])

    def test_install_refuses_writable_nonsticky_alias_parent(self):
        aliases = self.root / "untrusted-aliases"
        aliases.mkdir(mode=0o700)
        alias = aliases / "omux-native-host"
        alias.symlink_to(self.binary)
        aliases.chmod(0o777)
        with self.assertRaises(setup.SetupError):
            self.install(binary=alias)
        self.assertEqual(list(self.hosts.iterdir()), [])

    def test_install_refuses_alias_to_executable_in_writable_parent(self):
        aliases = self.root / "safe-aliases"
        aliases.mkdir(mode=0o700)
        alias = aliases / "omux-native-host"
        alias.symlink_to(self.binary)
        self.binary_dir.chmod(0o777)
        with self.assertRaises(setup.SetupError):
            self.install(binary=alias)
        self.binary_dir.chmod(0o700)
        self.assertEqual(list(self.hosts.iterdir()), [])

    def test_install_refuses_foreign_owned_executable_parent(self):
        original_lstat = Path.lstat
        foreign_uid = max(1, os.geteuid() + 1)

        def observed_owner(path):
            info = original_lstat(path)
            if path == self.binary_dir:
                fields = list(info)
                fields[4] = foreign_uid
                return os.stat_result(fields)
            return info

        # Model an owner the unprivileged fixture cannot create. All real paths
        # remain in the private temporary directory and retain their actual UID.
        with mock.patch.object(Path, "lstat", autospec=True, side_effect=observed_owner):
            with self.assertRaises(setup.SetupError):
                self.install()
        self.assertEqual(self.binary_dir.stat().st_uid, os.getuid())
        self.assertEqual(list(self.hosts.iterdir()), [])

    def test_install_accepts_explicit_executable_symlink_alias(self):
        alias_directory = self.root / "alias-bin"
        alias_directory.mkdir(mode=0o700)
        alias = alias_directory / "omux-native-host"
        alias.symlink_to(self.binary)
        self.assertEqual(self.install(binary=alias), "installed")
        self.assertEqual(json.loads(self.destination.read_text(encoding="utf-8")), setup.manifest("chromium", CHROMIUM_ID, alias))
        self.assertEqual(self.remove(binary=alias), "removed")

    def test_install_refuses_writable_intermediate_alias_directory(self):
        initial_directory = self.root / "trusted-initial-alias"
        initial_directory.mkdir(mode=0o700)
        intermediate_directory = self.root / "replaceable-intermediate-alias"
        intermediate_directory.mkdir(mode=0o700)
        intermediate = intermediate_directory / "middle"
        intermediate.symlink_to(self.binary)
        initial = initial_directory / "omux-native-host"
        initial.symlink_to(intermediate)
        intermediate_directory.chmod(0o777)
        # Initial and final paths are both safe; every intervening link must
        # retain custody too, because its directory can replace the link.
        with self.assertRaises(setup.SetupError):
            self.install(binary=initial)
        self.assertEqual(list(self.hosts.iterdir()), [])

    def test_install_accepts_trusted_intermediate_relative_alias(self):
        aliases = self.root / "trusted-alias-chain"
        aliases.mkdir(mode=0o700)
        final = aliases / "final"
        final.write_bytes(self.binary.read_bytes())
        final.chmod(0o700)
        intermediate = aliases / "middle"
        intermediate.symlink_to("final")
        initial = aliases / "omux-native-host"
        initial.symlink_to("middle")
        self.assertEqual(self.install(binary=initial), "installed")
        self.assertEqual(self.install(binary=initial), "unchanged")
        self.assertEqual(json.loads(self.destination.read_text(encoding="utf-8")), setup.manifest("chromium", CHROMIUM_ID, initial))
        self.assertEqual(self.remove(binary=initial), "removed")

    def test_install_refuses_intermediate_directory_symlink(self):
        initial_directory = self.root / "trusted-start"
        initial_directory.mkdir(mode=0o700)
        intermediate_directory = self.root / "trusted-middle-directory"
        intermediate_directory.mkdir(mode=0o700)
        intermediate = intermediate_directory / "middle"
        intermediate.symlink_to(self.binary)
        directory_alias = self.root / "directory-alias"
        directory_alias.symlink_to(intermediate_directory, target_is_directory=True)
        initial = initial_directory / "omux-native-host"
        initial.symlink_to(directory_alias / "middle")
        with self.assertRaises(setup.SetupError):
            self.install(binary=initial)
        self.assertEqual(list(self.hosts.iterdir()), [])

    def test_install_refuses_parent_traversal_in_alias_targets(self):
        aliases = self.root / "parent-traversal-aliases"
        aliases.mkdir(mode=0o700)
        actual_parent = self.root / "other-target-layout"
        actual_parent.mkdir(mode=0o700)
        actual_inner = actual_parent / "inner"
        actual_inner.mkdir(mode=0o700)
        # Both lexical and kernel-selected final files exist. Validation must
        # reject traversal rather than inspect a different normalized target.
        for target in (aliases / "target", actual_parent / "target"):
            target.write_bytes(self.binary.read_bytes())
            target.chmod(0o700)
        (aliases / "directory-alias").symlink_to(actual_inner, target_is_directory=True)
        initial = aliases / "omux-native-host"
        for target in (Path("..") / "bin" / "omux-native-host", Path("directory-alias") / ".." / "target"):
            with self.subTest(target=target):
                initial.symlink_to(target)
                with self.assertRaises(setup.SetupError):
                    self.install(binary=initial)
                initial.unlink()
        self.assertEqual(list(self.hosts.iterdir()), [])

    def test_install_rejects_symlink_cycle_promptly(self):
        aliases = self.root / "cyclic-aliases"
        aliases.mkdir(mode=0o700)
        initial = aliases / "omux-native-host"
        initial.symlink_to("middle")
        (aliases / "middle").symlink_to("omux-native-host")
        outcomes = []

        def invoke():
            try:
                outcomes.append(("returned", self.install(binary=initial)))
            except Exception as error:
                outcomes.append(("raised", error))

        worker = threading.Thread(target=invoke, daemon=True)
        worker.start()
        worker.join(0.5)
        self.assertFalse(worker.is_alive(), "registration did not bound symlink traversal")
        self.assertEqual(len(outcomes), 1)
        self.assertEqual(outcomes[0][0], "raised")
        self.assertIsInstance(outcomes[0][1], setup.SetupError)
        self.assertEqual(list(self.hosts.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
