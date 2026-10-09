"""Source-composition unit predicates; synthetic source has no native authority."""
import unittest
from unittest.mock import patch

import codex_live_source as source
import codex_owner_status_source as status


class OwnerStatusSourceTests(unittest.TestCase):
    def fixture(self):
        files = {name: ("100644", ("before " + name + "\n").encode()) for name in status.ALLOWED}
        for name in status.history.GRAPH:
            files[name] = ("100644", ("graph " + name + "\n").encode())
        files["unselected.txt"] = ("100755", b"untouched\n")
        raw = b"".join((f"--- a/{name}\n+++ b/{name}\n@@ -1 +1 @@\n-before {name}\n+after {name}\n").encode()
            for name in sorted(status.ALLOWED))
        preimages = {name: source.sha(files[name][1]) for name in status.ALLOWED}
        return files, raw, preimages

    def selected(self, raw, preimages):
        # Only local synthetic source-unit pins change, never parent admission.
        return patch.multiple(status, PATCH_SHA=source.sha(raw), PREIMAGES=preimages)

    def test_exact_fifth_changes_only_declared_source_and_keeps_graph_and_modes(self):
        files, raw, preimages = self.fixture()
        with self.selected(raw, preimages):
            result = status.transform(files, raw)
        self.assertEqual(set(result), set(files))
        self.assertEqual({name for name in files if files[name] != result[name]}, status.ALLOWED)
        self.assertEqual(result["unselected.txt"], files["unselected.txt"])
        for name in status.history.GRAPH:
            self.assertEqual(result[name], files[name])
        self.assertEqual(status.inventory(result)["unselected.txt"],
            {"mode": "100755", "sha256": source.sha(b"untouched\n")})

    def test_wrong_patch_digest_preimage_mode_and_missing_member_refuse(self):
        files, raw, preimages = self.fixture()
        name = sorted(status.ALLOWED)[0]
        with self.selected(raw, preimages):
            with self.assertRaises(ValueError):
                status.transform(files, raw + b"\n")
            for changed in (
                {**files, name: ("100644", b"other source\n")},
                {**files, name: ("100755", files[name][1])},
                {key: value for key, value in files.items() if key != name},
            ):
                with self.assertRaises(ValueError):
                    status.transform(changed, raw)

    def test_rehashed_bad_context_position_and_unknown_path_still_refuse(self):
        files, raw, preimages = self.fixture()
        for changed in (
            raw.replace(b"-before ", b"-wrong ", 1),
            raw.replace(b"@@ -1 +1 @@", b"@@ -2 +1 @@", 1),
            raw + b"--- a/unselected.txt\n+++ b/unselected.txt\n@@ -1 +1 @@\n-untouched\n+changed\n",
        ):
            with self.selected(changed, preimages), self.assertRaises(ValueError):
                status.transform(files, changed)

    def test_output_file_set_mode_graph_and_out_of_scope_drift_refuse(self):
        files, raw, preimages = self.fixture()
        with self.selected(raw, preimages):
            result = status.transform(files, raw)
        graph = status.history.GRAPH[0]
        variants = (
            {**result, "extra.txt": ("100644", b"extra\n")},
            {key: value for key, value in result.items() if key != "unselected.txt"},
            {**result, "unselected.txt": ("100644", b"untouched\n")},
            {**result, "unselected.txt": ("100755", b"changed\n")},
            {**result, graph: ("100644", b"different graph\n")},
            {**result, sorted(status.ALLOWED)[0]: files[sorted(status.ALLOWED)[0]]},
        )
        for changed in variants:
            with self.assertRaises(ValueError):
                status.validate_transition(files, changed)

    def test_parser_cannot_return_extra_or_incomplete_footprint(self):
        files, raw, preimages = self.fixture()
        for changes in ({}, {"unselected.txt": b"changed\n"}):
            with self.selected(raw, preimages), patch.object(status.patch_io, "apply_exact", return_value=changes), self.assertRaises(ValueError):
                status.transform(files, raw)


if __name__ == "__main__":
    unittest.main()
