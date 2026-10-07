import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from host_workspace import safe_directory, validate_ancestry, validate_workspace


class WorkspaceCustodyTest(unittest.TestCase):
    def test_private_directory_rejection_does_not_adopt_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "preexisting"
            path.mkdir(mode=0o755)
            with self.assertRaises(ValueError):
                safe_directory(path, os.getuid(), private=True)
            self.assertEqual(stat.S_IMODE(os.lstat(path).st_mode), 0o755)

    def test_rejects_symlink_ancestors_and_shared_writable_ancestors(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real = root / "real"
            real.mkdir(mode=0o700)
            (root / "alias").symlink_to(real, target_is_directory=True)
            with self.assertRaises(ValueError):
                validate_ancestry(root / "alias", os.getuid(), root)
            real.chmod(0o770)
            with self.assertRaises(ValueError):
                validate_ancestry(real, os.getuid(), root)

    def test_rejects_foreign_owner_without_reading_contents(self):
        class Metadata:
            st_uid = os.getuid() + 1
            st_mode = stat.S_IFDIR | 0o700
        with patch("host_workspace.os.lstat", return_value=Metadata()), self.assertRaises(ValueError):
            safe_directory(Path("/public-fixture"), os.getuid())

    def test_rejects_relative_traversal_and_control_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path in [Path("relative"), root / ".." / "escape", root / "bad\nname", root / "bad\rname"]:
                with self.subTest(path=str(path)), self.assertRaises(ValueError):
                    validate_ancestry(path, os.getuid(), root)

    def test_fixed_darwin_state_path_spaces_and_owned_private_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "Home with spaces"
            base = home / "Library" / "Application Support" / "OmuxProof"
            base.mkdir(parents=True, mode=0o700)
            workspace = base / ".run-public123"
            workspace.mkdir(mode=0o700)
            original = validate_ancestry
            with patch("host_workspace.validate_ancestry", side_effect=lambda path, uid: original(path, uid, root)):
                validate_workspace(workspace, base, home, os.getuid(), "Darwin")
                with self.assertRaises(ValueError):
                    validate_workspace(home, base, home, os.getuid(), "Darwin")

    def test_linux_outside_home_state_requires_safe_ancestry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir(mode=0o700)
            base = root / "operator-state" / "omux-proof"
            base.mkdir(parents=True, mode=0o700)
            workspace = base / ".run-public123"
            workspace.mkdir(mode=0o700)
            original = validate_ancestry
            with patch("host_workspace.validate_ancestry", side_effect=lambda path, uid: original(path, uid, root)):
                validate_workspace(workspace, base, home, os.getuid(), "Linux")
                base.parent.chmod(0o777)
                with self.assertRaises(ValueError):
                    validate_workspace(workspace, base, home, os.getuid(), "Linux")


if __name__ == "__main__":
    unittest.main()
