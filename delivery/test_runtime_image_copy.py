"""Actual built and portable named-runtime parity, only through Bazel.

The default-daemon probe deliberately fails pure path validation before daemon,
vault, database, socket, source, provider or service work. No daemon is started.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

import pack


CORE = Path(sys.argv.pop(1))
DAEMON = Path(sys.argv.pop(1))
ARCHIVE = Path(sys.argv.pop(1))
DISPATCH = ["--native-package-root", "/declared/package",
    "--native-installation-root", "/declared/install", "--state-dir", "relative"]


def invoke(binary, args):
    environment = dict(os.environ)
    environment.pop("OMUX_INSTANCE", None)
    environment.pop("XDG_RUNTIME_DIR", None)
    return subprocess.run([str(binary), *args], stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
        timeout=10, check=False)


def assert_dispatch(test, core, daemon):
    # forCommand rejects deployment locators for ordinary Omux's default help.
    # The omuxd basename selects daemon and instead reaches pure UnsafePath.
    ordinary = invoke(core, DISPATCH)
    named = invoke(daemon, DISPATCH)
    test.assertNotEqual(ordinary.returncode, 0)
    test.assertNotEqual(named.returncode, 0)
    test.assertEqual(ordinary.stdout, b"")
    test.assertEqual(named.stdout, b"")
    test.assertIn(b"error: InvalidArguments", ordinary.stderr)
    test.assertIn(b"error: UnsafePath", named.stderr)


class RuntimeImageCopyTests(unittest.TestCase):
    def test_distinct_regular_executable_output_has_exact_compiled_bytes(self):
        core, daemon = CORE.resolve(strict=True), DAEMON.resolve(strict=True)
        self.assertEqual(core.name, "omux")
        self.assertEqual(daemon.name, "omuxd")
        information = daemon.lstat()
        self.assertTrue(stat.S_ISREG(information.st_mode))
        # Bazel may remove owner-write when admitting an action-cache output.
        self.assertIn(stat.S_IMODE(information.st_mode), (0o555, 0o755))
        self.assertNotEqual((core.stat().st_dev, core.stat().st_ino),
                            (information.st_dev, information.st_ino))
        self.assertEqual(core.stat().st_size, information.st_size)
        with core.open("rb") as original, daemon.open("rb") as named:
            self.assertEqual(hashlib.file_digest(original, "sha256").digest(),
                             hashlib.file_digest(named, "sha256").digest())

    def test_explicit_commands_keep_complete_actual_output(self):
        for arguments in (["--version"], ["help"], ["reference"]):
            with self.subTest(arguments=arguments):
                core = invoke(CORE, arguments)
                daemon = invoke(DAEMON, arguments)
                self.assertEqual(core.returncode, 0)
                self.assertEqual(daemon.returncode, 0)
                self.assertEqual(core.stdout, daemon.stdout)
                self.assertEqual(core.stderr, daemon.stderr)

    def test_basename_selects_default_daemon_before_any_runtime_effect(self):
        assert_dispatch(self, CORE, DAEMON)

    def test_full_verified_portable_archive_preserves_both_roles_and_dispatch(self):
        manifest, files = pack.verify_bundle(ARCHIVE.read_bytes())
        self.assertEqual(manifest["distribution"], "portable-linux")
        self.assertEqual(manifest["channel"], "development")
        self.assertEqual(files["lib/omux/libexec/omux.bin"],
                         files["lib/omux/libexec/omuxd.bin"])
        modes = {row["path"]: int(row["mode"], 8) for row in manifest["artifacts"]}
        for name in ("bin/omux", "bin/omuxd", "lib/omux/libexec/omux.bin",
                     "lib/omux/libexec/omuxd.bin"):
            self.assertEqual(modes[name], 0o755)
            self.assertTrue(files[name].startswith(b"\x7fELF"))
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            root = Path(directory)
            for name, raw in files.items():
                destination = root / name
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                destination.write_bytes(raw)
                destination.chmod(modes.get(name, 0o644))
            assert_dispatch(self, root / "bin/omux", root / "bin/omuxd")


if __name__ == "__main__":
    unittest.main()
