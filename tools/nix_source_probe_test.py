"""Read-only source metadata and complete native-role deadline models."""
import base64
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import nix_source_probe as probe


def lock():
    return {"root": "root", "nodes": {
        "root": {"inputs": {"nixpkgs": "pkgs", "flake-utils": "utils"}},
        "pkgs": {"locked": {"narHash": "sha256-" + base64.b64encode(b"p" * 32).decode()}},
        "utils": {"locked": {"narHash": "sha256-" + base64.b64encode(b"u" * 32).decode()},
                  "inputs": {"systems": "platforms"}},
        "platforms": {"locked": {"narHash": "sha256-" + base64.b64encode(b"s" * 32).decode()}}}}


class SourceProbeModels(unittest.TestCase):
    def test_native_roles_follow_lock_edges_instead_of_guessing_node_names(self):
        hashes = probe.native_source_hashes(lock())
        self.assertEqual(hashes, {"nixpkgs": "sha256:" + (b"p" * 32).hex(),
                                 "flake-utils": "sha256:" + (b"u" * 32).hex(),
                                 "systems": "sha256:" + (b"s" * 32).hex()})
        self.assertEqual(probe.locked_hash(lock()), hashes["nixpkgs"])
        for role in ("nixpkgs", "flake-utils"):
            changed = lock()
            changed["nodes"]["root"]["inputs"][role] = ["unexpected", role]
            with self.assertRaises(ValueError):
                probe.native_source_hashes(changed)
        changed = lock()
        changed["nodes"]["utils"]["inputs"]["systems"] = ["unexpected"]
        with self.assertRaises(ValueError):
            probe.native_source_hashes(changed)

    def test_missing_source_and_invalid_digest_cannot_emit_complete_role_metadata(self):
        missing = lock()
        del missing["nodes"]["utils"]["inputs"]["systems"]
        with self.assertRaises(KeyError):
            probe.native_source_hashes(missing)
        for digest in ("sha1-invalid", "sha256-" + base64.b64encode(b"x" * 31).decode()):
            invalid = lock()
            invalid["nodes"]["platforms"]["locked"]["narHash"] = digest
            with self.assertRaises(ValueError):
                probe.native_source_hashes(invalid)
        with patch.object(probe, "locate", side_effect=[["public-pkgs"], [], ["public-systems"]]):
            result = probe.native_metadata(lock())
        self.assertFalse(result["passed"])
        self.assertEqual(result["source_candidates"]["flake-utils"], [])

    def test_three_queries_share_the_original_deadline_and_never_promote_metadata(self):
        with patch.object(probe.time, "monotonic", side_effect=[100, 101, 104, 108, 109]), \
             patch.object(probe, "locate", return_value=["public-source"]) as selected:
            result = probe.native_metadata(lock())
        self.assertEqual([call.kwargs["seconds"] for call in selected.call_args_list], [9, 6, 2])
        self.assertEqual([call.kwargs["deadline"] for call in selected.call_args_list], [110, 110, 110])
        self.assertTrue(result["passed"])
        self.assertFalse(result["source_nar_verified"])
        self.assertFalse(result["build_seed_verified"])
        self.assertEqual(result["byte_verification"], "pending-declared-nar-action")
        with patch.object(probe.time, "monotonic", side_effect=[100, 101, 104, 110]):
            with patch.object(probe, "locate", return_value=["public-source"]) as selected:
                # The expired budget refuses before another database query.
                with self.assertRaises(ValueError):
                    probe.native_metadata(lock())
                self.assertEqual(selected.call_count, 2)

    def test_delayed_inner_query_entry_cannot_renew_the_original_deadline(self):
        with patch.object(probe.time, "monotonic", side_effect=[100, 101, 111]), \
             patch.object(probe.sqlite3, "connect") as connection:
            with self.assertRaises(ValueError):
                probe.native_metadata(lock())
            connection.assert_not_called()

    def test_expired_or_unbounded_query_budget_refuses_before_database_access(self):
        with patch.object(probe.sqlite3, "connect", side_effect=AssertionError("database opened")):
            for seconds in (0, -1, True, 11, float("inf"), float("nan")):
                with self.assertRaises(ValueError):
                    probe.locate(Path("/never-opened"), "sha256:" + "1" * 64, seconds)

    def test_read_only_database_cannot_be_created_and_queries_only_matching_public_roots(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "db.sqlite"
            with self.assertRaises(sqlite3.OperationalError):
                probe.locate(database, "sha256:" + "1" * 64)
            self.assertFalse(database.exists())
            with sqlite3.connect(database) as db:
                db.execute("CREATE TABLE ValidPaths(path TEXT, hash TEXT)")
                digest = "sha256:" + "1" * 64
                db.executemany("INSERT INTO ValidPaths VALUES (?,?)", [
                    ("/nix/store/" + "a" * 32 + "-source", digest),
                    ("/nix/store/" + "b" * 32 + "-other-package", digest),
                    ("/nix/store/" + "c" * 32 + "-source", "sha256:" + "2" * 64)])
            before = database.read_bytes()
            with patch.object(probe.Path, "is_dir", return_value=True), \
                 patch.object(probe.Path, "is_symlink", return_value=False):
                self.assertEqual(probe.locate(database, digest),
                                 ["/nix/store/" + "a" * 32 + "-source"])
            self.assertEqual(database.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
