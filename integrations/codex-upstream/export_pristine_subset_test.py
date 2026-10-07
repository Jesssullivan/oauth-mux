"""R-N13: bounded pinned-original selection and exclusive-output predicates."""

import copy
import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from export_pristine_subset import (COMMIT, URL, export_subset, main, publish_export,
                                    SCHEMA_PREFIX, selected_originals, unique_object)
from patch_io import digest, read_archive


class ExportPristineSubsetTest(unittest.TestCase):
    def setUp(self):
        self.files = {
            "LICENSE": ("100644", b"upstream license\n"),
            "NOTICE": ("100644", b"upstream notice\n"),
            "codex-rs/core/src/existing.rs": ("100644", b"pinned original\n"),
            "codex-rs/new-area/src/main.rs": ("100755", b"another original\n"),
        }
        self.original = {name: value for name, (_, value) in self.files.items()
                         if name != "codex-rs/new-area/src/main.rs"}
        self.manifest = {
            "upstream_commit": COMMIT,
            "upstream_repository": URL.removesuffix(".git"),
            "native_support": False,
            "files": {
                "codex-rs/core/src/existing.rs": {"before_sha256": digest(b"pinned original\n")},
                "codex-rs/core/src/added.rs": {"before_sha256": None},
            },
        }

    def select(self, additional=(), files=None, manifest=None, original=None):
        return selected_originals(files if files is not None else self.files,
                                  manifest if manifest is not None else self.manifest,
                                  original if original is not None else self.original,
                                  additional)

    def test_selects_verified_originals_and_newly_affected_existing_blob(self):
        archive, metadata = self.select(["codex-rs/new-area/src/main.rs"])
        expected = {name: value for name, (_, value) in self.files.items()}
        self.assertEqual(read_archive(archive), expected)
        self.assertNotIn("codex-rs/core/src/added.rs", metadata)
        self.assertEqual(metadata["codex-rs/new-area/src/main.rs"]["git_mode"], "100755")
        self.assertEqual(metadata["codex-rs/core/src/existing.rs"]["sha256"], digest(b"pinned original\n"))
        self.assertEqual(self.select(["codex-rs/new-area/src/main.rs"])[0], archive)

    def test_foreign_traversing_and_duplicate_requests_rejected(self):
        for names in (["../escape"], ["MODULE.bazel"], ["codex-rs/../escape"],
                      ["codex-rs//invalid"], ["codex-rs/core/src/existing.rs"],
                      ["codex-rs/new-area/src/main.rs", "codex-rs/new-area/src/main.rs"]):
            with self.subTest(names=names), self.assertRaises(ValueError):
                self.select(names)

    def test_full_schema_selection_keeps_pinned_originals_and_existing_overlap(self):
        old_schema = SCHEMA_PREFIX + "json/v2/Existing.json"
        json_schema = SCHEMA_PREFIX + "json/v2/NativeError.json"
        ts_schema = SCHEMA_PREFIX + "typescript/v2/NativeError.ts"
        compressed = SCHEMA_PREFIX + "precomputed/app-server-exports-stable.json.zst"
        excluded = SCHEMA_PREFIX + "README.md"
        foreign = "codex-rs/other/schema/Foreign.json"
        selected = {old_schema: b"old pinned schema", json_schema: b"unchanged pinned json",
                    ts_schema: b"unchanged pinned typescript", compressed: b"pinned compressed map"}
        files = {**self.files, **{name: ("100644", value) for name, value in selected.items()},
                 excluded: ("100644", b"schema readme"), foreign: ("100644", b"foreign schema")}
        manifest = copy.deepcopy(self.manifest)
        manifest["files"][old_schema] = {"before_sha256": digest(selected[old_schema])}
        original = {**self.original, old_schema: selected[old_schema]}
        archive, metadata = selected_originals(files, manifest, original, [],
                                              include_schema_originals=True)
        self.assertEqual(read_archive(archive), {**original, **selected})
        for name, value in selected.items():
            self.assertEqual(metadata[name]["sha256"], digest(value))
        self.assertNotIn(excluded, metadata)
        self.assertNotIn(foreign, metadata)
        self.assertNotIn(json_schema, selected_originals(files, manifest, original, [])[1])
        # Prior original schema custody remains mandatory, even with full selection.
        with self.assertRaises(ValueError):
            selected_originals(files, manifest, {**original, old_schema: b"edited checkout bytes"}, [],
                               include_schema_originals=True)
        with self.assertRaises(ValueError):
            selected_originals({**files, ts_schema: ("120000", b"redirect")}, manifest, original, [],
                               include_schema_originals=True)
        with patch("export_pristine_subset.MAX_SELECTED_FILES", len(original)), self.assertRaises(ValueError):
            selected_originals(files, manifest, original, [], include_schema_originals=True)
        with patch("export_pristine_subset.MAX_ARCHIVE_BYTES", 100), self.assertRaises(ValueError):
            selected_originals(files, manifest, original, [], include_schema_originals=True)

    def test_missing_blob_and_symlink_selection_rejected(self):
        with self.assertRaises(ValueError):
            self.select(["codex-rs/absent.rs"])
        files = {**self.files, "codex-rs/link": ("120000", b"core/src/existing.rs")}
        with self.assertRaises(ValueError):
            self.select(["codex-rs/link"], files=files)

    def test_manifest_pin_support_and_existing_original_custody_rejected(self):
        for key, value in (("upstream_commit", "0" * 40),
                           ("upstream_repository", "https://invalid.example/source"),
                           ("native_support", True)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.select(manifest={**self.manifest, key: value})
        with self.assertRaises(ValueError):
            self.select(original={**self.original, "codex-rs/core/src/existing.rs": b"edited bytes"})
        files = {**self.files, "codex-rs/core/src/added.rs": ("100644", b"already exists")}
        with self.assertRaises(ValueError):
            self.select(files=files)
        manifest = copy.deepcopy(self.manifest)
        manifest["files"]["codex-rs/core/src/existing.rs"]["before_sha256"] = digest(b"other")
        with self.assertRaises(ValueError):
            self.select(manifest=manifest)

    def test_raw_tar_and_file_count_budgets_reject_before_compression(self):
        with patch("export_pristine_subset.MAX_ARCHIVE_BYTES", 100), self.assertRaises(ValueError):
            self.select()
        with patch("export_pristine_subset.MAX_SELECTED_FILES", 2), self.assertRaises(ValueError):
            self.select()

    def test_duplicate_manifest_json_keys_rejected(self):
        with self.assertRaises(ValueError):
            json.loads('{"files":{"path":1,"path":2}}', object_pairs_hook=unique_object)

    def test_destination_overlap_rejected_before_artifact_or_git_read(self):
        parent = Path(os.environ["TEST_TMPDIR"]).resolve()
        with tempfile.TemporaryDirectory(dir=parent) as temporary:
            root = Path(temporary)
            (root / "git").mkdir(mode=0o755)
            with patch("export_pristine_subset.original_files") as git_reader:
                with self.assertRaises(ValueError):
                    export_subset(root, root / "absent-artifact", Path("/declared/git"),
                                  Path("/declared/ca"), [], root / "source/export")
                git_reader.assert_not_called()

    def test_external_exception_text_is_never_retained_in_diagnostic_output(self):
        arguments = ["export", "--artifact-dir", "/declared/artifact", "--git", "/declared/git",
                     "--ca-file", "/declared/ca", "--root", "/owned/root",
                     "--output-directory", "/owned/new-epoch"]
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("sys.argv", arguments), patch("export_pristine_subset.export_subset",
                 side_effect=RuntimeError("credential=fixture-private-diagnostic")):
            with redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(main(), 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "pristine subset export rejected; no success receipt\n")

    def test_exclusive_private_output_preserves_existing_and_symlink_epochs(self):
        parent = Path(os.environ["TEST_TMPDIR"]).resolve()
        with tempfile.TemporaryDirectory(dir=parent) as temporary:
            directory = Path(temporary) / "new-epoch"
            archive, _ = self.select()
            report = {"ruling_id": "R-N13", "archive_sha256": digest(archive), "native_support": False}
            publish_export(directory, archive, report)
            self.assertEqual((directory / "pristine-originals.tar.gz").read_bytes(), archive)
            self.assertEqual(json.loads((directory / "export-receipt.json").read_text()), report)
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((directory / "pristine-originals.tar.gz").stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE((directory / "export-receipt.json").stat().st_mode), 0o600)
            with self.assertRaises(FileExistsError):
                publish_export(directory, b"replacement", {})
            self.assertEqual((directory / "pristine-originals.tar.gz").read_bytes(), archive)
            alias = Path(temporary) / "redirect"
            alias.symlink_to(directory, target_is_directory=True)
            with self.assertRaises(ValueError):
                publish_export(alias, b"replacement", {})
            self.assertEqual((directory / "pristine-originals.tar.gz").read_bytes(), archive)


if __name__ == "__main__":
    unittest.main()
