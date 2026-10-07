from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).parent.parent / "integrations/codex-upstream"))
from codex_recovery_delta import build_delta
from patch_io import apply_exact


class RecoveryDeltaTests(unittest.TestCase):
    def test_delta_preserves_selected_unchanged_source_and_exactly_applies(self):
        before = {"codex-rs/core/src/fixture.rs": b"before\n", "codex-rs/core/src/other.rs": b"unchanged\n"}
        after = {**before, "codex-rs/core/src/fixture.rs": b"after\n"}
        patch, changes = build_delta(before, after)
        self.assertEqual(set(changes), {"codex-rs/core/src/fixture.rs"})
        self.assertEqual(apply_exact(patch.decode(), before), {"codex-rs/core/src/fixture.rs": b"after\n"})
        with self.assertRaises(ValueError):
            apply_exact(patch.decode(), {**before, "codex-rs/core/src/fixture.rs": b"drift\n"})

    def test_generated_schema_and_selection_drift_refuse(self):
        with self.assertRaisesRegex(ValueError, "non-code"):
            build_delta({"codex-rs/schema.json": b"before"}, {"codex-rs/schema.json": b"after"})
        with self.assertRaisesRegex(ValueError, "selection differs"):
            build_delta({"codex-rs/core/src/fixture.rs": b"before"}, {})


if __name__ == "__main__":
    unittest.main()
