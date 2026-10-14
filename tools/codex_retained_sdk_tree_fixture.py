"""Model-only actual tiny carrier fixture. No genuine selected SDK authority.

Uses the existing actual SDK validators/sealer/durable writer. Only the synthetic
JDK and original recipe namespace are patched inside the bounded model scope;
no sealed admission token, finished flag or successful provider is constructed.
"""
from contextlib import ExitStack
from pathlib import Path
import os
import time
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import codex_native_sdk_carrier as core
import codex_native_sdk_carrier_test as existing
import codex_original_sdk_inputs as original


class TinyCarrier:
    def __init__(self):
        self.model = None
        self.patches = ExitStack()
        try:
            self.model = existing.CarrierModels()
            # Bind only this existing model's setup to Bazel's declared temp
            # namespace; no process-wide tempfile defaults or validator changes.
            temporary = SimpleNamespace(TemporaryDirectory=lambda:
                tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]))
            with patch.object(existing, "tempfile", temporary):
                self.model.setUp()
            self.root = self.model.root
            self.origin_pin = self.model.pin
            self.carrier_root, self.carrier_report, self.carrier_pin = self.model.seal("tiny-carrier")
            self.patches.enter_context(patch.object(original, "ORIGIN_PIN", self.origin_pin))
        except BaseException as error:
            try: self.close()
            except BaseException as cleanup: raise error from cleanup
            raise

    def durable_tree(self, path):
        with core.HeldCarrier(self.carrier_root, self.carrier_pin, self.model.deadline) as held:
            report, manifest, logical, unused = held._binding()
            extracted = core.extract(self.carrier_root, self.carrier_pin, path, self.model.deadline,
                _held_carrier=held)
            held.full_final()
            core.need(core.revalidate_extraction(self.carrier_root, self.carrier_pin, path, self.model.deadline,
                pinned_extraction_receipt_sha256=core.sha(core.encoded(extracted)), _held_carrier=held) == extracted,
                "tiny-fixture-complete-durable-tree-proof")
        return logical, manifest["nars"], extracted

    def normalize(self, tree_path):
        # Explicit test-only simulation. Actual TreeArtifact normalization has
        # its own declared action/qualifier gate and is not proved by chmod.
        for path, directories, files in os.walk(tree_path, followlinks=False):
            for name in files:
                leaf = Path(path) / name
                if not leaf.is_symlink(): leaf.chmod(0o555)
            Path(path).chmod(0o555)

    def context(self):
        entry = time.monotonic_ns()
        return {"MODE": "native-sdk-tree-producer-reserved", "ENTRY_NS": str(entry),
            "DEADLINE_NS": str(entry + 1200 * 10**9),
            "EPOCH": str(self.root / "11111111-1111-1111-1111-111111111111"),
            "SOURCE_COMMIT": "1" * 40, "GRAPH_SHA256": "2" * 64}

    def close(self):
        patches, self.patches = self.patches, None
        model, self.model = self.model, None
        first = None
        if patches is not None:
            try: patches.close()
            except BaseException as error: first = error
        if model is not None:
            try: model.tearDown()
            except BaseException as error:
                if first is None: first = error
        if first is not None: raise first

    def __enter__(self): return self
    def __exit__(self, kind, error, trace):
        try: self.close()
        except BaseException as cleanup:
            if error is not None: raise BaseException.with_traceback(error, trace) from cleanup
            raise
        return False
