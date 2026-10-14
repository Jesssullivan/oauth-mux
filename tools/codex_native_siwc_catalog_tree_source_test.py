"""Actual distinct SOURCE entry/refusal and literal composition models.

Model-only controls/native source intake are explicit seams. No fake successful
SDK owner, creator verdict or native/source qualification is returned.
"""
from contextlib import ExitStack
import os
import io
import re
from contextlib import redirect_stdout
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import codex_native_siwc_catalog_tree_source as model
import codex_retained_sdk_tree_inputs as admission


class RetainedTreeSourceModels(unittest.TestCase):
    def test_source_only_flag_refuses_before_any_admission_or_payload_owner(self):
        with patch.object(model.sys, "argv", ["tree-source", "--source-only"]), \
                patch.object(model, "admission") as admit, patch.object(model.retained_sdk, "open_declared") as tree:
            with self.assertRaises(ValueError): model.main()
        admit.assert_not_called(); tree.assert_not_called()

    def test_actual_source_producer_keeps_native_composition_and_selects_distinct_regenerator(self):
        for recipe in ("owned-history-thirteen-v3", "siwc-catalog-twelve-v1"):
            with self.subTest(recipe=recipe), patch.object(model, "selected_recipe", return_value=recipe), \
                    patch.object(model.previous, "produce") as produce:
                model.produce("public output", "owned inputs", "declared work", "publication")
            self.assertIs(produce.call_args.kwargs["_regenerator"], model.retained_sdk.regenerate)
            self.assertIs(produce.call_args.kwargs["_sdk_record"], model.retained_sdk.record)
            self.assertIs(produce.call_args.kwargs["_source_intake"], model.content.intake.source_intake)
            self.assertIs(produce.call_args.kwargs["_transform"], model.history.compose if recipe == "owned-history-thirteen-v3"
                else model.content.catalog.compose)

    def test_actual_main_unselected_declared_tree_refuses_before_source_writer_and_drains_inputs(self):
        import codex_native_carrier_metadata as metadata
        source, query = model.source, model.query
        prior = source.DEADLINE, query.DEADLINE
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as temporary:
            root = Path(temporary)
            runfiles = root / "runfiles"; runfiles.mkdir()
            output = root / "outputs"; output.mkdir()
            control = runfiles / admission.CONFIG; control.parent.mkdir(parents=True)
            control.write_bytes(model.source.encoded({"schema_version": 1, "kind": admission.SELECTION_KIND,
                "status": "UNSELECTED", "selection": None})); control.chmod(0o644)
            mapping = runfiles / "_repo_mapping"
            mapping.write_bytes(("_main," + admission.PROOF_REPOSITORY + "," + admission.PROOF_REPOSITORY + "\n").encode())
            mapping.chmod(0o444)
            public = root / "declared-native-model"; public.write_bytes(b"unqualified public native model"); public.chmod(0o444)
            entry = time.monotonic_ns(); until = entry + 1200 * 10**9; cutoff = (entry + 600 * 10**9) / 10**9
            env = {"TEST_SRCDIR": str(runfiles), "TEST_UNDECLARED_OUTPUTS_DIR": str(output), "TEST_TIMEOUT": "840",
                "OMUX_NATIVE_FILE_WRITER_MODELS_MODE": "native-file-writer-models-reserved",
                "OMUX_NATIVE_FILE_WRITER_MODELS_ENTRY_NS": str(entry), "OMUX_NATIVE_FILE_WRITER_MODELS_DEADLINE_NS": str(until),
                "OMUX_NATIVE_FILE_WRITER_MODELS_EPOCH": "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/11111111-1111-1111-1111-111111111111",
                "OMUX_NATIVE_FILE_WRITER_MODELS_SOURCE_COMMIT": "1" * 40,
                "OMUX_NATIVE_FILE_WRITER_MODELS_GRAPH_SHA256": "2" * 64}
            descriptors = []
            class ActualPublicInput:
                # This unqualified source fixture contributes only a real owned
                # FD. It cannot mint SDK authority or get past UNSELECTED.
                def __init__(self, unused_root, unused_rows): self.fd = None
                def __enter__(self):
                    self.fd = os.open(public, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                    descriptors.append(self.fd); return self
                def __exit__(self, *error):
                    fd, self.fd = self.fd, None
                    if fd is not None: os.close(fd)
                    return False
            config, controls = (b"public config model", {}), (b"public controls model", {})
            source.DEADLINE = query.DEADLINE = cutoff
            try:
                with ExitStack() as stack:
                    stack.enter_context(patch.dict(os.environ, env, clear=True))
                    stack.enter_context(patch.object(model.sys, "argv", ["tree-source"]))
                    stack.enter_context(patch.object(model, "configuration", return_value=config))
                    stack.enter_context(patch.object(model, "controls", return_value=controls))
                    # Original SOURCE ancestry is not under test in the NULL
                    # retained-tree path; no successful SDK proof is substituted.
                    stack.enter_context(patch.object(metadata.legacy, "configure_selection", return_value=None))
                    writer = stack.enter_context(patch.object(model, "produce"))
                    admitted = (entry, until, cutoff, source.encoded(model.producer_context()))
                    with self.assertRaises(ValueError):
                        model.main(_retainer=lambda owner: (config, controls), _input_factory=ActualPublicInput, _admitted=admitted)
                    writer.assert_not_called()
                self.assertEqual(len(descriptors), 1)
                for fd in descriptors:
                    with self.assertRaises(OSError): os.fstat(fd)
                self.assertEqual(list(output.iterdir()), [])
                self.assertEqual((source.DEADLINE, query.DEADLINE), (cutoff, cutoff))
            finally: source.DEADLINE, query.DEADLINE = prior

    def test_actual_main_retains_real_admitted_tree_through_publication_and_late_refusal_cleanup(self):
        import codex_native_retained_sdk_tree_producer as producer
        from codex_retained_sdk_tree_fixture import TinyCarrier
        from codex_retained_sdk_tree_admission_fixture import DeclaredTreeFixture
        for fault in ("none", "late-current-tree-inode"):
            with self.subTest(fault=fault), TinyCarrier() as tiny, DeclaredTreeFixture(tiny) as fixture:
                producer.materialize(fixture.materialize_args())
                tiny.normalize(fixture.output / "tree")
                with patch.dict(os.environ, {"TEST_UNDECLARED_OUTPUTS_DIR": str(fixture.qualifier_output)}), redirect_stdout(io.StringIO()):
                    producer.qualify(fixture.qualifier_args())
                fixture.publish_tree()
                native_output = fixture.root / "native-outputs"; native_output.mkdir(mode=0o700)
                public = fixture.root / "unqualified-native-member"
                public.write_bytes(b"explicit unqualified native SOURCE fixture"); public.chmod(0o444)
                config, controls = (b"public source config", {}), (b"public source controls", {})
                descriptors = []
                class PublicInputs:
                    def __init__(self, unused_root, unused_rows): self.fd = None
                    def __enter__(self):
                        self.fd = os.open(public, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                        descriptors.append(self.fd); return self
                    def check(self): os.fstat(self.fd)
                    def check_all(self): self.check()
                    def __exit__(self, *error):
                        fd, self.fd = self.fd, None
                        if fd is not None: os.close(fd)
                        return False
                def publish(output, inputs, work, publication, **kwargs):
                    current = kwargs["sdk_session"]
                    self.assertIs(type(current.inputs), admission.AuthenticatedTreeInputs)
                    self.assertEqual(current.clock.until_ns, fixture.entry + 600 * 10**9)
                    self.assertEqual(current.read_regular("sdk", "receipt.json", admission.core.MAX_METADATA), tiny.model.original)
                    descriptors.extend(root.fd for root in current.roots.values())
                    files = {"public-model.rs": ("100644", public.read_bytes())}
                    fd = model.source.write_source(output, files)
                    receipt = tree = None
                    transferred = False
                    try:
                        raw = model.source.encoded({"kind": "explicit-unqualified-current-source-model",
                            "sdk_execution_qualified": False, "compiler_qualified": False, "runtime_qualified": False})
                        receipt, anchor = model.parent.publish_receipt(fd, raw)
                        before = model.content.tenth.witness(os.fstat(fd))
                        members = {"source/" + name: row for name, row in files.items()}
                        members["source-receipt.json"] = ("100644", raw)
                        tree = model.content.tenth.TreeWitness(output, members, root_mode=0o700, receipt_name="source-receipt.json")
                        os.fchmod(fd, 0o555)
                        tree.accept_root_seal(before, model.content.tenth.witness(os.fstat(fd)))
                        publication.bind(output, fd, receipt, anchor, tree, files, None, raw)
                        transferred = True
                    finally:
                        if not transferred:
                            if tree is not None: tree.close()
                            if receipt is not None: os.close(receipt)
                            os.close(fd)
                    if fault != "none":
                        leaf = fixture.output / "tree/sdk/repositories/public+/tool"
                        raw = leaf.read_bytes(); leaf.parent.chmod(0o700)
                        old = fixture.root / "old-current-tool"
                        leaf.rename(old); leaf.write_bytes(raw); leaf.chmod(0o555); leaf.parent.chmod(0o555)
                        self.assertEqual(old.stat().st_nlink, 1)
                        self.assertNotEqual(old.stat().st_ino, leaf.stat().st_ino)
                    return {"unqualified": True}
                prior_query = model.query.DEADLINE
                with fixture.retained_source(), ExitStack() as stack:
                    cutoff = (fixture.entry + 600 * 10**9) / 10**9
                    model.query.DEADLINE = cutoff
                    stack.enter_context(patch.dict(os.environ, {"TEST_UNDECLARED_OUTPUTS_DIR": str(native_output), "TEST_TIMEOUT": "840"}))
                    stack.enter_context(patch.object(model.sys, "argv", ["tree-source"]))
                    stack.enter_context(patch.object(model.parent.protocol, "PRODUCER_SCOPE", re.compile(
                        "(?:" + re.escape(str(fixture.seal_epoch / "receipt.json")) + "|" +
                        re.escape(str(fixture.source_epoch / "receipt.json")) + ")\\Z")))
                    stack.enter_context(patch.object(model, "configuration", return_value=config))
                    stack.enter_context(patch.object(model, "controls", return_value=controls))
                    # This model does not execute or qualify a query tool/native
                    # graph; it covers the real current SDK/main lifetime join.
                    stack.enter_context(patch.object(model.query, "declared_query_tools"))
                    admitted = (fixture.entry, fixture.until, cutoff, model.source.encoded(model.producer_context()))
                    try:
                        with redirect_stdout(io.StringIO()) as stdout:
                            if fault == "none": model.main(_producer=publish, _retainer=lambda owner: (config, controls),
                                _input_factory=PublicInputs, _admitted=admitted)
                            else:
                                with self.assertRaises(ValueError): model.main(_producer=publish,
                                    _retainer=lambda owner: (config, controls), _input_factory=PublicInputs, _admitted=admitted)
                        if fault == "none": self.assertIn("compilation unqualified", stdout.getvalue())
                        else: self.assertEqual(stdout.getvalue(), "")
                    finally: model.query.DEADLINE = prior_query
                for fd in descriptors:
                    with self.assertRaises(OSError): os.fstat(fd)



if __name__ == "__main__": unittest.main()
