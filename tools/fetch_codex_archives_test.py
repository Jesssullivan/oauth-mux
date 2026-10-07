"""Offline predicates; never start Nix, fetch a URL or inspect user state."""

import base64
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import resource

from fetch_codex_archives import ARCHIVES, MAX_FILE_BYTES, MAX_MANIFEST, MAX_STDOUT, MAX_RETAINED_BYTES, bundle_main, child_environment, child_file_limits, deadline_bounds, declared_manifest_path, disk_check, export_payload, load_manifest, measure, prefetch_command, prefetch_reply, publish_bundle, read_manifest, run_prefetch


def manifest(entries=None):
    return json.dumps({"schema_version": 1, "system": "x86_64-linux", "archives":
                       entries if entries is not None else [{"name": name, "sha256": digest, "url": base + name}
                                                           for name, digest, base in ARCHIVES]}).encode()


class FetchContracts(unittest.TestCase):
    def test_bundle_outputs_only_verified_archives_and_receipt_without_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "worker"
            outputs = Path(directory) / "outputs"
            root.mkdir()
            outputs.mkdir()
            (root / "distdir").mkdir()
            value = b"fixed synthetic archive"
            expected = hashlib.sha256(value).hexdigest()
            payload = root / "distdir/fixed.tar"
            payload.write_bytes(value)
            payload.chmod(0o400)
            inode = payload.stat().st_ino
            report = {"status": "complete-verified-distdir", "missing": [],
                      "verified": [{"name": "fixed.tar", "sha256": expected, "bytes": len(value)}]}
            (root / "receipt.json").write_text(json.dumps(report))
            with patch("fetch_codex_archives.ARCHIVES", (("fixed.tar", expected, "https://invalid/"),)):
                publish_bundle(root, outputs)
            self.assertEqual({p.name for p in (outputs / "bundle").iterdir()}, {"fixed.tar", "receipt.json"})
            self.assertEqual((outputs / "bundle/fixed.tar").stat().st_ino, inode)
            self.assertFalse((root / "distdir").exists())

    def test_bundle_scratch_removed_when_producer_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scratch, outputs = root / "scratch", root / "outputs"
            scratch.mkdir()
            outputs.mkdir()
            def fail(arguments, declared_manifest=False):
                location = Path(arguments[arguments.index("--output-directory") + 1])
                location.mkdir()
                (location / "private-store").mkdir()
                raise ValueError("offline failure")
            with patch.dict(os.environ, {"TEST_TMPDIR": str(scratch), "TEST_UNDECLARED_OUTPUTS_DIR": str(outputs)}), \
                    patch("fetch_codex_archives.main", side_effect=fail):
                with self.assertRaisesRegex(ValueError, "offline failure"):
                    bundle_main([])
            self.assertEqual(list(scratch.iterdir()), [])
            self.assertEqual(list(outputs.iterdir()), [])

    def test_only_paired_declared_manifest_alias_resolves(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, runfiles = root / "source/tools", root / "runfiles/_main/tools"
            source.mkdir(parents=True)
            runfiles.mkdir(parents=True)
            helper_source = source / "fetch_codex_archives.py"
            helper_source.write_text("synthetic helper")
            helper = runfiles / helper_source.name
            helper.symlink_to(helper_source)
            manifest_source = source / "codex_upstream_archives.json"
            content = manifest()
            manifest_source.write_bytes(content)
            alias = runfiles / manifest_source.name
            alias.symlink_to(manifest_source)
            resolved = declared_manifest_path(alias, helper)
            self.assertEqual(len(read_manifest(resolved, hashlib.sha256(content).hexdigest())), 13)
            other = runfiles / "other.json"
            other.symlink_to(manifest_source)
            with self.assertRaisesRegex(ValueError, "paired runfile"):
                declared_manifest_path(other, helper)
            alias.unlink()
            alias.symlink_to(other)
            # Another alias can only resolve to the exact paired source file.
            self.assertEqual(declared_manifest_path(alias, helper), manifest_source)
            alias.unlink()
            outside = root / "outside.json"
            outside.write_bytes(content)
            alias.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "source context"):
                declared_manifest_path(alias, helper)
            alias.unlink()
            manifest_source.unlink()
            os.mkfifo(manifest_source)
            alias.symlink_to(manifest_source)
            with self.assertRaisesRegex(ValueError, "regular file"):
                read_manifest(declared_manifest_path(alias, helper), hashlib.sha256(content).hexdigest())

    def test_manifest_refuses_link_fifo_and_oversized_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "manifest.json"
            payload = manifest()
            original.write_bytes(payload)
            expected = hashlib.sha256(payload).hexdigest()
            self.assertEqual(len(read_manifest(original, expected)), 13)
            linked = root / "linked"
            linked.symlink_to(original)
            with self.assertRaises(OSError):
                read_manifest(linked, expected)
            fifo = root / "fifo"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, "regular file"):
                read_manifest(fifo, expected)
            original.write_bytes(b"x" * (MAX_MANIFEST + 1))
            with self.assertRaisesRegex(ValueError, "bounded regular"):
                read_manifest(original, expected)

    def test_child_limit_never_exceeds_one_gib_or_inherited_bounds(self):
        for inherited, expected in (((resource.RLIM_INFINITY, resource.RLIM_INFINITY), MAX_FILE_BYTES),
                                    ((2048, 4096), 2048)):
            with patch("fetch_codex_archives.resource.getrlimit", return_value=inherited):
                self.assertEqual(child_file_limits(), (expected, expected))

    def test_child_launch_sets_file_limit_before_exec(self):
        with patch("fetch_codex_archives.disk_check"), patch("fetch_codex_archives.child_file_limits", return_value=(1024, 1024)), \
                patch("fetch_codex_archives.subprocess.Popen", side_effect=RuntimeError("offline stop")) as launch:
            with self.assertRaisesRegex(RuntimeError, "offline stop"):
                run_prefetch(["never-executed"], {}, Path("/owned"), time.monotonic() + 10, 4096, 0)
        before_exec = launch.call_args.kwargs["preexec_fn"]
        self.assertIs(before_exec.func, resource.setrlimit)
        self.assertEqual(before_exec.args, (resource.RLIMIT_FSIZE, (1024, 1024)))

    def test_deadlines_fit_controller_and_bad_replies_fail(self):
        deadline_bounds(1200, 300)
        for total, per_file in ((1201, 300), (1200, 1201), (0, 1)):
            with self.assertRaisesRegex(ValueError, "deadline bounds"):
                deadline_bounds(total, per_file)
        with self.assertRaises(json.JSONDecodeError):
            prefetch_reply(b'{"storePath":')
        with self.assertRaisesRegex(ValueError, "output exceeded"):
            prefetch_reply(b"x" * (MAX_STDOUT + 1))

    def test_exact_manifest_and_drift_refusal(self):
        value = manifest()
        self.assertEqual(len(load_manifest(value, hashlib.sha256(value).hexdigest())), 13)
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            load_manifest(value, "0" * 64)
        entries = json.loads(value)["archives"]
        entries[0]["url"] = "https://example.com/unreviewed"
        changed = manifest(entries)
        with self.assertRaisesRegex(ValueError, "allowlist"):
            load_manifest(changed, hashlib.sha256(changed).hexdigest())

    def test_duplicate_and_missing_archive_refusal(self):
        value = manifest(json.loads(manifest())["archives"][:-1])
        with self.assertRaisesRegex(ValueError, "archive set"):
            load_manifest(value, hashlib.sha256(value).hexdigest())
        duplicate = b'{"schema_version":1,"schema_version":1}'
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            load_manifest(duplicate, hashlib.sha256(duplicate).hexdigest())

    def test_no_inherited_credentials_or_daemon_environment(self):
        environment = child_environment(Path("/owned"), Path("/nix/store/pinned-ca"))
        self.assertNotIn("HTTPS_PROXY", environment)
        self.assertNotIn("http_proxy", environment)
        self.assertEqual(environment["NIX_REMOTE"], "")
        self.assertEqual(environment["NIX_CONF_DIR"], "/owned/config")
        entry = load_manifest(manifest(), hashlib.sha256(manifest()).hexdigest())[0]
        command = prefetch_command(Path("/nix/store/pinned/bin/nix"), Path("/owned"), entry)
        self.assertEqual(command[1:3], ["--store", "local?root=/owned/private-store"])
        self.assertEqual(command[3:5], ["store", "prefetch-file"])
        self.assertNotIn("build", command)
        self.assertNotIn("--unpack", command)
        self.assertNotIn("--executable", command)

    def test_disk_monitor_does_not_follow_external_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "outside").symlink_to("/unrelated/unreadable")
            self.assertLess(measure(root), 1024 * 1024)
            (root / "payload").write_bytes(b"x" * 8192)
            with self.assertRaisesRegex(ValueError, "disk budget"):
                disk_check(root, 4096, 0)

    def test_export_hash_mismatch_never_marks_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "distdir").mkdir()
            payload = root / "private-store/nix/store" / ("0" * 32 + "-fixture")
            payload.parent.mkdir(parents=True)
            payload.write_bytes(b"incorrect")
            payload.chmod(0o444)
            expected = hashlib.sha256(b"expected").hexdigest()
            entry = {"name": "fixture", "sha256": expected}
            reply = {"storePath": "/nix/store/" + payload.name,
                     "hash": "sha256-" + base64.b64encode(bytes.fromhex(expected)).decode()}
            with self.assertRaisesRegex(ValueError, "payload digest mismatch"):
                export_payload(root, reply, entry, time.monotonic() + 5, 1024 * 1024, 0)
            self.assertTrue((root / "distdir/fixture").exists())

    def test_oversized_payload_refused_before_export_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "distdir").mkdir()
            payload = root / "private-store/nix/store" / ("0" * 32 + "-fixture")
            payload.parent.mkdir(parents=True)
            with payload.open("wb") as stream:
                stream.truncate(MAX_FILE_BYTES + 1)
            payload.chmod(0o444)
            expected = hashlib.sha256(b"expected").hexdigest()
            reply = {"storePath": "/nix/store/" + payload.name,
                     "hash": "sha256-" + base64.b64encode(bytes.fromhex(expected)).decode()}
            with self.assertRaisesRegex(ValueError, "per-file"):
                export_payload(root, reply, {"name": "fixture", "sha256": expected},
                               time.monotonic() + 5, MAX_FILE_BYTES * 2, 0)
            self.assertFalse((root / "distdir/fixture").exists())


if __name__ == "__main__":
    unittest.main()
