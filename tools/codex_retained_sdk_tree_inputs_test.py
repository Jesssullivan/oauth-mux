"""Real held-metadata refusal models; no fabricated creator/SDK selector.

These helpers alone cannot admit a tree. Full producer/current-reader fixture
composition belongs to the separately declared coauthor integration target.
"""
import copy
import hashlib
import os
import stat
from pathlib import Path
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import codex_native_sdk_carrier as core
import codex_retained_sdk_tree_inputs as inputs


class AdmissionMetadataModels(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"])
        self.root = Path(self.temporary.name)
        self.clock = core.Clock(time.monotonic() + 60)

    def tearDown(self): self.temporary.cleanup()

    def leaf(self, name, raw, mode=0o444):
        path = self.root / name
        path.write_bytes(raw)
        path.chmod(mode)
        return path

    def test_actual_sticky_writable_ancestor_is_allowed_and_nonsticky_refused(self):
        ancestor = self.root / "writable-ancestor"
        ancestor.mkdir(mode=0o700)
        child = ancestor / "private-child"
        child.mkdir(mode=0o700)
        try:
            for mode in (0o777, 0o770, 0o1777, 0o1770):
                with self.subTest(mode=mode):
                    ancestor.chmod(mode)
                    self.assertEqual(stat.S_IMODE(ancestor.stat().st_mode), mode)
                    self.assertEqual(ancestor.stat().st_uid, os.getuid())
                    if not mode & stat.S_ISVTX:
                        with self.assertRaisesRegex(ValueError, "metadata-ancestor-custody"):
                            inputs._Directory(child, self.clock)
                    else:
                        owner = inputs._Directory(child, self.clock)
                        descriptors = [row[1] for row in owner.chain]
                        try:
                            owner.check()
                            self.assertEqual(os.fstat(owner.fd).st_ino, child.stat().st_ino)
                        finally: owner.close()
                        for fd in descriptors:
                            with self.assertRaises(OSError): os.fstat(fd)
        finally: ancestor.chmod(0o700)

    def test_current_domain_is_closed_and_old_creator_boot_is_provenance_only(self):
        boot = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
        context = {"BOOT_ID": boot}
        doc = {"schema_version": 1, "kind": "omux-sdk-tree-current-clock-domain-v1",
            "clock": "linux-CLOCK_MONOTONIC", "boot_id": boot}
        with patch.dict(os.environ, {"OMUX_NATIVE_SDK_TREE_CURRENT_BOOT_ID": boot}):
            self.assertEqual(inputs.current_creator_domain(core.encoded(doc), context), doc)
            for field, value in (("schema_version", True), ("clock", "wall-clock"),
                    ("boot_id", "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA"), ("extra", "fresh epoch")):
                with self.subTest(field=field):
                    changed = {**doc, field: value}
                    with self.assertRaises(ValueError): inputs.current_creator_domain(core.encoded(changed), context)
            with self.assertRaisesRegex(ValueError, "creator-clock-domain-changed"):
                inputs.current_creator_domain(core.encoded(doc), {"BOOT_ID": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"})

    def test_prior_boot_bytes_are_provenance_under_fresh_actual_source_owner(self):
        from contextlib import redirect_stdout
        import io
        import codex_native_retained_sdk_tree_producer as producer
        import codex_retained_sdk_tree_reader as reader
        from codex_retained_sdk_tree_fixture import TinyCarrier
        from codex_retained_sdk_tree_admission_fixture import DeclaredTreeFixture
        with TinyCarrier() as tiny, DeclaredTreeFixture(tiny) as fixture:
            producer.materialize(fixture.materialize_args()); tiny.normalize(fixture.output / "tree")
            with patch.dict(os.environ, {"TEST_UNDECLARED_OUTPUTS_DIR": str(fixture.qualifier_output)}), redirect_stdout(io.StringIO()):
                producer.qualify(fixture.qualifier_args())
            fixture.publish_tree()
            original = dict(fixture.context)
            with patch.dict(os.environ, {"OMUX_NATIVE_SDK_TREE_CURRENT_BOOT_ID": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"}), fixture.retained_source() as held:
                with reader.open_declared(fixture.runfiles, fixture.rows, fixture.entry, fixture.until,
                        fixture.source_context, held) as current:
                    self.assertEqual(current.record()["creator"]["producer_context"]["boot_id"], original["BOOT_ID"])
                    self.assertEqual(current.clock.until_ns, fixture.entry + 600 * 10**9)
                    self.assertFalse(current.record()["sdk_execution_qualified"])
                    self.assertEqual(current.read_regular("sdk", "receipt.json", core.MAX_METADATA), tiny.model.original)
                    current.finish()
            self.assertEqual(fixture.context, original)

    def test_unselected_and_caller_success_flags_never_create_authority(self):
        document = {"schema_version": 1, "kind": inputs.SELECTION_KIND, "status": "UNSELECTED", "selection": None}
        with self.assertRaises(ValueError): inputs.selection(core.encoded(document))
        for field in ("ready", "cached_success", "current_lock", "native_runtime_qualified"):
            changed = {**document, field: True}
            with self.assertRaises(ValueError): inputs.selection(core.encoded(changed))
        with self.assertRaises(ValueError): inputs.AuthenticatedTreeInputs(True)
        with self.assertRaises(ValueError): inputs.AuthenticatedTreeInputs({"selected": True})

    def test_actual_held_leaf_full_read_and_parent_mode_policy(self):
        for mode in (0o444, 0o555):
            path = self.leaf("selected-" + str(mode), b"synthetic declared public metadata", mode)
            owner = inputs._Leaf(path, self.clock, 65536, core.sha(path.read_bytes()), path.stat().st_size)
            try:
                self.assertEqual(owner.raw, path.read_bytes())
                self.assertEqual(owner.read(), owner.raw)
                owner.check()
                held = owner.fd
            finally: owner.close()
            with self.assertRaises(OSError): os.fstat(held)
        for mode in (0o600, 0o644, 0o666, 0o755):
            path = self.leaf("refused-" + str(mode), b"synthetic unqualified public metadata", mode)
            with self.assertRaises(ValueError): inputs._Leaf(path, self.clock, 65536)
        private = self.leaf("outer-proof", b"synthetic proof bytes", 0o600)
        owner = inputs._Leaf(private, self.clock, 65536, proof=True)
        try: self.assertEqual(owner.read(), owner.raw)
        finally: owner.close()

    def test_actual_same_byte_inode_alias_and_content_replacement_refuse(self):
        for fault in ("physical-inode", "alias", "content", "mode"):
            with self.subTest(fault=fault):
                physical = self.leaf("physical-" + fault, b"selected identical metadata")
                alias = self.root / ("declared-" + fault)
                alias.symlink_to(physical)
                owner = inputs._Leaf(alias, self.clock, 65536)
                descriptors = [owner.fd] + [row[1] for row in owner.root.chain + owner.alias_root.chain]
                try:
                    if fault == "physical-inode":
                        replacement = self.leaf("replacement-" + fault, physical.read_bytes())
                        replacement.replace(physical)
                    elif fault == "alias":
                        alias.unlink()
                        alias.symlink_to(physical)
                    elif fault == "content":
                        physical.chmod(0o600)
                        physical.write_bytes(b"different unqualified metadata")
                        physical.chmod(0o444)
                    else: physical.chmod(0o555)
                    with self.assertRaises(ValueError): owner.check()
                finally: owner.close()
                for fd in descriptors:
                    with self.assertRaises(OSError): os.fstat(fd)

    def test_actual_read_refusal_drains_every_fd_once_and_preserves_first_cause(self):
        path = self.leaf("read-refusal", b"bounded synthetic bytes")
        real_open, real_close = os.open, os.close
        opened, closed = [], []
        body, cleanup = MemoryError("synthetic metadata read"), OSError("synthetic successful close")
        def acquire(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            opened.append(fd)
            return fd
        def retire(fd):
            closed.append(fd)
            real_close(fd)
            if len(closed) == 1: raise cleanup
        with patch.object(inputs.os, "open", acquire), patch.object(inputs.os, "read", side_effect=body), \
                patch.object(inputs.os, "close", retire):
            with self.assertRaises(MemoryError) as caught:
                inputs._Leaf(path, self.clock, 65536)
        self.assertIs(caught.exception, body)
        self.assertIs(caught.exception.__cause__, cleanup)
        self.assertEqual(len(closed), len(set(closed)))
        self.assertEqual(set(closed), set(opened))
        for fd in opened:
            with self.assertRaises(OSError): os.fstat(fd)

    def test_original_deadline_expiry_after_actual_read_refuses_and_closes(self):
        path = self.leaf("late-original-clock", b"synthetic selected metadata")
        original = self.clock.deadline
        real_read = os.read
        armed, fds = [False], []
        real_open = os.open
        def opened(*args, **kwargs):
            fd = real_open(*args, **kwargs)
            fds.append(fd)
            return fd
        def read(*args):
            raw = real_read(*args)
            if not raw: armed[0] = True
            return raw
        now = time.monotonic
        with patch.object(inputs.os, "open", opened), patch.object(inputs.os, "read", read), \
                patch.object(core.time, "monotonic", side_effect=lambda: original if armed[0] else now()):
            with self.assertRaises(ValueError): inputs._Leaf(path, self.clock, 65536)
        self.assertTrue(armed[0])
        self.assertEqual(self.clock.deadline, original)
        for fd in fds:
            with self.assertRaises(OSError): os.fstat(fd)

    def test_real_tiny_materializer_qualifier_and_same_owned_reader_complete(self):
        from contextlib import redirect_stdout
        import io
        import codex_native_retained_sdk_tree_producer as producer
        import codex_retained_sdk_tree_reader as reader
        from codex_retained_sdk_tree_fixture import TinyCarrier
        from codex_retained_sdk_tree_admission_fixture import DeclaredTreeFixture
        with TinyCarrier() as tiny, DeclaredTreeFixture(tiny) as fixture:
            producer.materialize(fixture.materialize_args())
            emitted = core.decode((fixture.output / "recipe.json").read_bytes())
            declaration_raw = fixture.original_declaration_path.read_bytes()
            self.assertEqual(next(row for row in emitted["inputs"]["proofs"]
                if row["path"] == "proof/carrier-selection"), {"path": "proof/carrier-selection",
                "sha256": core.sha(declaration_raw), "bytes": len(declaration_raw)})
            for path in fixture.ancestry_paths:
                raw = path.read_bytes()
                logical = str(path.relative_to(fixture.runfiles))
                self.assertEqual(next(row for row in emitted["inputs"]["proofs"] if row["path"] == logical),
                    {"path": logical, "sha256": core.sha(raw), "bytes": len(raw)})
            tiny.normalize(fixture.output / "tree")
            with patch.dict(os.environ, {"TEST_UNDECLARED_OUTPUTS_DIR": str(fixture.qualifier_output)}), redirect_stdout(io.StringIO()) as output:
                producer.qualify(fixture.qualifier_args())
            receipt_raw = (fixture.output / "receipt.json").read_bytes()
            self.assertEqual(output.getvalue().strip(), "retained-sdk-tree: receipt-sha256=" + core.sha(receipt_raw))
            self.assertEqual((fixture.qualifier_output / "sdk-tree-public/receipt.json").read_bytes(), receipt_raw)
            fixture.publish_tree()
            with fixture.retained_source() as held:
                with reader.open_declared(fixture.runfiles, fixture.rows, fixture.entry, fixture.until,
                        fixture.source_context, held) as current:
                    self.assertIs(type(current.inputs), inputs.AuthenticatedTreeInputs)
                    self.assertIs(current.clock, current.inputs.clock)
                    proof = current.qualification_record()
                    self.assertEqual(set(proof["proof_inputs"]["roles"]), set(inputs.ROLES))
                    self.assertEqual(len(current.inputs.leaves), 17)
                    self.assertEqual(current.clock.until_ns, fixture.entry + 600 * 10**9)
                    self.assertEqual(current.read_regular("sdk", "receipt.json", core.MAX_METADATA), tiny.model.original)
                    self.assertEqual(set(current.qualification_record()), {
                        "selector_sha256", "selection", "qualified_producer", "declaration", "proof_inputs"})
                    before = tuple(root.fd for root in current.roots.values())
                    current.finish()
                    current.fence()
            for fd in before:
                with self.assertRaises(OSError): os.fstat(fd)

    def test_real_admitted_tree_late_inode_replacement_after_metadata_full_refuses(self):
        import codex_native_retained_sdk_tree_producer as producer
        from codex_retained_sdk_tree_fixture import TinyCarrier
        from codex_retained_sdk_tree_admission_fixture import DeclaredTreeFixture
        with TinyCarrier() as tiny, DeclaredTreeFixture(tiny) as fixture:
            producer.materialize(fixture.materialize_args())
            tiny.normalize(fixture.output / "tree")
            fixture.publish_tree()
            with fixture.retained_source() as held:
                owner = inputs.admit(fixture.runfiles, fixture.rows, fixture.entry, fixture.until,
                    fixture.source_context, held)
                root_fds = [root.fd for root in owner.roots.values()]
                raw_full = owner.full
                def late_metadata():
                    raw_full()
                    leaf = owner.tree_root / "sdk/receipt.json"
                    parent = leaf.parent
                    parent.chmod(0o700)
                    replacement = parent / "unqualified-replacement"
                    replacement.write_bytes(leaf.read_bytes())
                    replacement.chmod(0o555)
                    preserved = fixture.root / "retained-original-sdk-receipt"
                    leaf.rename(preserved)
                    replacement.rename(leaf)
                    parent.chmod(0o555)
                    self.assertEqual(preserved.stat().st_nlink, 1)
                    self.assertEqual(preserved.read_bytes(), leaf.read_bytes())
                    self.assertNotEqual(preserved.stat().st_ino, leaf.stat().st_ino)
                try:
                    with patch.object(owner, "full", side_effect=late_metadata), self.assertRaises(ValueError): owner.finish()
                    self.assertFalse(owner.finished)
                finally: owner.close()
                for fd in root_fds:
                    with self.assertRaises(OSError): os.fstat(fd)

    def test_actual_creator_declaration_capture_bytes_and_preserved_inode_refuse(self):
        from codex_retained_sdk_tree_fixture import TinyCarrier
        from codex_retained_sdk_tree_admission_fixture import DeclaredTreeFixture
        for fault in ("bytes", "same-byte-inode"):
            with self.subTest(fault=fault), TinyCarrier() as tiny, DeclaredTreeFixture(tiny) as fixture:
                owner = inputs.admit_carrier(fixture.runfiles, fixture.rows, fixture.context, fixture.domain_raw)
                path = fixture.original_declaration_path
                raw = path.read_bytes()
                try:
                    captured = owner.proof_metadata()[str(path)]
                    self.assertEqual((captured["raw"], captured["sha256"], captured["bytes"]),
                        (raw, core.sha(raw), len(raw)))
                    if fault == "bytes":
                        path.chmod(0o600)
                        path.write_bytes(raw + b"\n")
                        path.chmod(0o444)
                    else:
                        preserved = fixture.root / "held-original-carrier-selection"
                        path.rename(preserved)
                        path.write_bytes(raw)
                        path.chmod(0o444)
                        self.assertEqual(preserved.stat().st_nlink, 1)
                        self.assertNotEqual(preserved.stat().st_ino, path.stat().st_ino)
                    with self.assertRaises(ValueError): owner.full()
                    self.assertFalse(owner.finished)
                finally: owner.close()

    def test_actual_xml_counter_and_failed_child_refusals_keep_omitted_aggregate_positive(self):
        clean = b'<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0"><testcase name="synthetic"/></testsuite></testsuites>'
        inputs._success_xml(clean)
        for counter in ("failures", "errors", "skipped"):
            with self.assertRaises(ValueError): inputs._success_xml(clean.replace(b"<testsuites>", ('<testsuites ' + counter + '="1">').encode()))
        for child in (b"<failure/>", b"<error/>", b"<skipped/>"):
            with self.assertRaises(ValueError): inputs._success_xml(clean.replace(b'<testcase name="synthetic"/>', b"<testcase>" + child + b"</testcase>"))
        for raw in (b'<testsuite tests="0"/>', b'<testsuites/>', b'<!DOCTYPE x><testsuite tests="1"/>'):
            with self.assertRaises(ValueError): inputs._success_xml(raw)

    def test_actual_malformed_selected_xml_uses_redacted_source_refusal_and_drains_fds(self):
        from contextlib import redirect_stderr
        import io
        import codex_native_retained_sdk_tree_producer as producer
        import codex_native_siwc_catalog_tree_source as controller
        from codex_retained_sdk_tree_fixture import TinyCarrier
        from codex_retained_sdk_tree_admission_fixture import DeclaredTreeFixture
        malformed = b'<testsuites><testsuite tests="1"><synthetic-unclosed-xml>'
        for raw in (malformed, b'<?xml version="1.0" encoding="synthetic-unknown-codec"?><testsuite tests="1"/>'):
            with self.assertRaises(ValueError) as typed:
                inputs._success_xml(raw)
            self.assertIs(type(typed.exception), ValueError)
            self.assertEqual(str(typed.exception), "SDK carrier refused: retained-tree-xml-malformed")
            self.assertTrue(typed.exception.__suppress_context__)
        with TinyCarrier() as tiny, DeclaredTreeFixture(tiny) as fixture:
            producer.materialize(fixture.materialize_args())
            tiny.normalize(fixture.output / "tree")
            fixture.publish_tree()
            # All selected pins are recomputed coherently before any admission;
            # this forces the actual parser boundary, not an earlier SHA refusal.
            def rewrite(path, raw, mode):
                path.chmod(0o600)
                path.write_bytes(raw)
                path.chmod(mode)
            xml = Path(fixture.tree_paths["test_xml"]["path"])
            rewrite(xml, malformed, 0o600)
            index_path = Path(fixture.tree_paths["test_evidence"]["path"])
            index = core.decode(index_path.read_bytes())
            member = next(row for row in index["results"][0]["files"] if row["source"] == "test.xml")
            member["sha256"], member["bytes"] = core.sha(malformed), len(malformed)
            index_raw = core.encoded(index)
            rewrite(index_path, index_raw, 0o600)
            outer_path = Path(fixture.tree_paths["outer_receipt"]["path"])
            outer = core.decode(outer_path.read_bytes())
            outer["test_evidence"]["sha256"] = core.sha(index_raw)
            outer_raw = core.encoded(outer)
            rewrite(outer_path, outer_raw, 0o600)
            selector_path = fixture.runfiles / inputs.CONFIG
            selector = core.decode(selector_path.read_bytes())
            selector["selection"]["producer"]["sha256"] = core.sha(outer_raw)
            rewrite(selector_path, core.encoded(selector), 0o644)
            mapping_path = fixture.external / inputs.PROOF_REPOSITORY / "sdk-tree-proof-inputs.json"
            mapping = core.decode(mapping_path.read_bytes())
            for role, raw in (("test_xml", malformed), ("test_evidence", index_raw), ("outer_receipt", outer_raw)):
                mapping["proofs"][role]["sha256"], mapping["proofs"][role]["bytes"] = core.sha(raw), len(raw)
            rewrite(mapping_path, core.encoded(mapping), 0o444)
            fixture.refresh_confirmation()
            real_open, real_close = os.open, os.close
            live, peak = set(), [0]
            def opened(*args, **kwargs):
                fd = real_open(*args, **kwargs)
                self.assertNotIn(fd, live)
                live.add(fd); peak[0] = max(peak[0], len(live))
                return fd
            def closed(fd):
                real_close(fd)
                self.assertIn(fd, live)
                live.remove(fd)
            def selected_main():
                with fixture.retained_source() as held:
                    return inputs.admit(fixture.runfiles, fixture.rows, fixture.entry, fixture.until,
                        fixture.source_context, held)
            stderr = io.StringIO()
            with patch.object(inputs.os, "open", side_effect=opened), patch.object(inputs.os, "close", side_effect=closed), \
                    patch.object(inputs.ET, "fromstring", wraps=inputs.ET.fromstring) as parsed, \
                    patch.object(controller, "main", side_effect=selected_main), redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as refused: controller.entrypoint()
            parsed.assert_called_once_with(malformed)
            self.assertEqual(refused.exception.code, 1)
            self.assertGreater(peak[0], 0)
            self.assertEqual(live, set())
            diagnostic = stderr.getvalue()
            self.assertLessEqual(len(diagnostic.encode()), controller.content.MAX_DIAGNOSTIC_BYTES)
            self.assertIn("class=ValueError; errno=0; locus=", diagnostic)
            for forbidden in ("synthetic-unclosed-xml", "ParseError", "Traceback", str(fixture.root)):
                self.assertNotIn(forbidden, diagnostic)

    def test_actual_collector_names_distinct_from_content_and_optional_diagnostics(self):
        configuration = "k8-fastbuild"
        epoch = self.root / "synthetic-collector-epoch"
        selected = {"producer": {"receipt": str(epoch / "receipt.json")}}
        held, files = {}, []
        for source, role, raw in (("test.log", "test_log", b"synthetic successful creator marker\n"),
                                  ("test.xml", "test_xml", b'<testsuite tests="1" failures="0" errors="0" skipped="0"/>')):
            filename = hashlib.sha256((inputs.TARGET + "\0" + configuration + "\0" + source).encode()).hexdigest() + ".evidence"
            self.assertNotEqual(filename[:64], core.sha(raw))
            held[role] = SimpleNamespace(path=epoch / "test-evidence" / filename, raw=raw)
            files.append({"source": source, "state": "copied", "file": filename, "sha256": core.sha(raw), "bytes": len(raw)})
        files += [{"source": "test.outputs_manifest/MANIFEST", "state": "missing", "bytes": 0},
                  {"source": "test.outputs_manifest/ANNOTATIONS", "state": "stale", "bytes": 0}]
        index = {"schema": 1, "bazel_exit": 0, "epoch_start_ns": 123, "targets": [inputs.TARGET],
                 "results": [{"target": inputs.TARGET, "configuration": configuration, "state": "observed", "files": files}]}
        inputs._collector(index, {"epoch_start_ns": 123}, selected, held)
        for fault in ("duplicate", "unknown", "missing-log", "refused-xml", "name-is-content", "configuration", "epoch", "optional-copy-refused"):
            changed = copy.deepcopy(index)
            row = changed["results"][0]
            if fault == "duplicate": row["files"][2] = copy.deepcopy(row["files"][0])
            elif fault == "unknown": row["files"][2]["source"] = "test.outputs/foreign-authority"
            elif fault == "missing-log": row["files"] = row["files"][1:]
            elif fault == "refused-xml": row["files"][1] = {"source": "test.xml", "state": "missing", "bytes": 0}
            elif fault == "name-is-content": row["files"][0]["file"] = row["files"][0]["sha256"] + ".evidence"
            elif fault == "configuration": row["configuration"] = "different-config"
            elif fault == "optional-copy-refused": row["files"][2]["state"] = "copy-refused"
            else: changed["epoch_start_ns"] += 1
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                inputs._collector(changed, {"epoch_start_ns": 123}, selected, held)

    def test_confirmation_is_mandatory_timely_bound_and_same_canonical_inode(self):
        import codex_native_retained_sdk_tree_producer as producer
        from codex_retained_sdk_tree_fixture import TinyCarrier
        from codex_retained_sdk_tree_admission_fixture import DeclaredTreeFixture
        for fault in ("missing-role", "missing-file", "late", "wrong-receipt", "wrong-context",
                "false-proof", "numeric-proof", "numeric-flag", "bool-schema", "wrong-witness", "same-byte-canonical-inode"):
            with self.subTest(fault=fault), TinyCarrier() as tiny, DeclaredTreeFixture(tiny) as fixture:
                producer.materialize(fixture.materialize_args())
                tiny.normalize(fixture.output / "tree")
                fixture.publish_tree()
                confirmation_path = Path(fixture.tree_paths["qualification_confirmation"]["path"])
                selector_path = fixture.runfiles / inputs.CONFIG
                map_path = fixture.external / inputs.PROOF_REPOSITORY / "sdk-tree-proof-inputs.json"
                selector, mapping = core.decode(selector_path.read_bytes()), core.decode(map_path.read_bytes())
                if fault == "missing-role":
                    del mapping["proofs"]["qualification_confirmation"]
                    map_path.chmod(0o600); map_path.write_bytes(core.encoded(mapping)); map_path.chmod(0o444)
                elif fault == "missing-file":
                    # Canonical receipt exists, but crash/unconfirmed metadata
                    # cannot create admission from the remaining eight roles.
                    confirmation_path.unlink()
                    self.assertTrue((fixture.tree_epoch / "receipt.json").is_file())
                elif fault == "same-byte-canonical-inode":
                    canonical = fixture.tree_epoch / "receipt.json"
                    raw = canonical.read_bytes()
                    preserved = fixture.root / "held-confirmed-canonical-receipt"
                    canonical.rename(preserved)
                    canonical.write_bytes(raw); canonical.chmod(0o600)
                    self.assertEqual(preserved.stat().st_nlink, 1)
                    self.assertEqual(preserved.read_bytes(), canonical.read_bytes())
                    self.assertNotEqual(preserved.stat().st_ino, canonical.stat().st_ino)
                else:
                    doc = core.decode(confirmation_path.read_bytes())
                    if fault == "late": doc["observed_qualified_monotonic_ns"] = fixture.until - 30 * 10**9
                    elif fault == "wrong-receipt": doc["receipt"]["sha256"] = "0" * 64
                    elif fault == "wrong-context": doc["original_entry_monotonic_ns"] += 1
                    elif fault == "false-proof": doc["qualification"]["writer_exclusive"] = False
                    elif fault == "numeric-proof": doc["qualification"]["writer_exclusive"] = 1
                    elif fault == "numeric-flag": doc["sdk_execution_qualified"] = 0
                    elif fault == "bool-schema": doc["schema_version"] = True
                    else: doc["canonical_receipt_creator_witness"][1] += 1
                    raw = core.encoded(doc)
                    confirmation_path.chmod(0o600); confirmation_path.write_bytes(raw); confirmation_path.chmod(0o444)
                    # Coherent selected pins force semantic/identity rejection,
                    # not an earlier raw SHA/extent refusal.
                    selected = {"path": str(confirmation_path), "sha256": core.sha(raw), "bytes": len(raw)}
                    selector["selection"]["confirmation"] = selected
                    mapping["proofs"]["qualification_confirmation"] = {**selected,
                        "alias": inputs.ALIASES["qualification_confirmation"]}
                    selector_path.chmod(0o600); selector_path.write_bytes(core.encoded(selector)); selector_path.chmod(0o644)
                    map_path.chmod(0o600); map_path.write_bytes(core.encoded(mapping)); map_path.chmod(0o444)
                with fixture.retained_source() as held:
                    with self.assertRaises((ValueError, OSError)):
                        inputs.admit(fixture.runfiles, fixture.rows, fixture.entry, fixture.until,
                            fixture.source_context, held)

    def test_real_collector_parent_evidence_and_receiver_share_optional_failure_policy(self):
        import guard_test_evidence as collector
        import guard_native_sdk_tree_reserved as guard
        from guard_native_sdk_tree_reserved_test import LeaseBoundaries
        from contextlib import ExitStack
        # This is real collector/FD evidence exercise, not an executed SDK or
        # kernel reservation. The existing helper admits only its temp namespace.
        policy = LeaseBoundaries()
        for case in ("optional-missing", "optional-stale", "optional-copied",
                "optional-copy-refused", "mandatory-missing", "mandatory-stale"):
            with self.subTest(case=case), policy.fixture() as (state, checkout, lease):
                lease.__enter__()
                clock = core.Clock((lease.entry + 1170 * 10**9) / 10**9)
                clock.until_ns = lease.entry + 1170 * 10**9
                run = state / lease.run_id
                run.mkdir(mode=0o700)
                testdir = lease.output_base / "execroot/_main/bazel-out/k8-fastbuild/testlogs" / collector.label_path(inputs.TARGET)
                testdir.mkdir(parents=True, mode=0o700)
                epoch_start = time.time_ns()
                report_pin = core.sha(b"synthetic model program marker, not a successful SDK receipt")
                log = b"retained-sdk-tree: receipt-sha256=" + report_pin.encode() + b"\n"
                xml = b'<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0"/></testsuites>'
                if case != "mandatory-missing": (testdir / "test.log").write_bytes(log)
                (testdir / "test.xml").write_bytes(xml)
                if case == "mandatory-stale":
                    os.utime(testdir / "test.log", ns=(epoch_start - 1, epoch_start - 1))
                if case in ("optional-stale", "optional-copied", "optional-copy-refused"):
                    diagnostics = testdir / "test.outputs_manifest"
                    diagnostics.mkdir(mode=0o700)
                    if case == "optional-copy-refused":
                        # Actual O_NOFOLLOW refusal, never a fabricated copied row.
                        (diagnostics / "MANIFEST").symlink_to(testdir / "test.log")
                    else:
                        (diagnostics / "MANIFEST").write_bytes(b"synthetic optional collector metadata\n")
                        if case == "optional-stale":
                            os.utime(diagnostics / "MANIFEST", ns=(epoch_start - 1, epoch_start - 1))
                # Match the real lifecycle: output mutation precedes capture;
                # evidence copying then retains the final output-base witness.
                lease.prepare_capture()
                index = collector.capture(lease.output_base, run, [inputs.TARGET], 0, epoch_start)
                optional = next(row for row in index["results"][0]["files"]
                    if row["source"] == "test.outputs_manifest/MANIFEST")
                expected_optional = {"optional-stale": "stale", "optional-copied": "copied",
                    "optional-copy-refused": "copy-refused"}.get(case, "missing")
                self.assertEqual(optional["state"], expected_optional)
                incomplete = case == "optional-copy-refused"
                accepted = case in ("optional-missing", "optional-stale", "optional-copied")
                raw = (run / "test-evidence.json").read_bytes()
                outer = {"epoch_start_ns": epoch_start, "targets": [inputs.TARGET],
                    "profile": guard.PRODUCER, "workload_exit": 0,
                    "test_evidence": {"state": "preservation-incomplete" if incomplete else "preserved",
                        "manifest": "test-evidence.json", "sha256": core.sha(raw),
                        "bytes": index["bytes"], "files": index["copied_files"]},
                    "native_sdk_tree_artifact_origin": {"created_metadata": [{"name": "receipt.json", "sha256": report_pin}]}}
                runfd = os.open(run, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                try:
                    if accepted: lease._evidence(runfd, outer)
                    else:
                        with self.assertRaises(ValueError): lease._evidence(runfd, outer)
                    if incomplete:
                        # Even an adversarial false preserved summary cannot
                        # admit the actual partial-failure collector index.
                        adversarial = copy.deepcopy(outer)
                        adversarial["test_evidence"]["state"] = "preserved"
                        with self.assertRaises(ValueError): lease._evidence(runfd, adversarial)
                finally: os.close(runfd)
                with ExitStack() as held:
                    leaves = {}
                    for source, role in (("test.log", "test_log"), ("test.xml", "test_xml")):
                        member = next(row for row in index["results"][0]["files"] if row["source"] == source)
                        if member["state"] == "copied":
                            owner = inputs._Leaf(run / "test-evidence" / member["file"], clock,
                                inputs.MAX_PROOF, member["sha256"], member["bytes"], proof=True)
                            held.callback(owner.close)
                            leaves[role] = owner
                    selected = {"producer": {"receipt": str(run / "receipt.json")}}
                    if accepted: inputs._collector(index, outer, selected, leaves)
                    else:
                        with self.assertRaises(ValueError): inputs._collector(index, outer, selected, leaves)
                    for owner in leaves.values(): owner.check()
                # No completion/publication/selector is minted from these files.
                self.assertFalse(incomplete and accepted)

    def test_recipe_non_circular_complete_inputs_order_roles_and_original_clock(self):
        code = [{"path": "tools/synthetic-materializer.py", "sha256": core.sha(b"synthetic code"), "bytes": 14}]
        tools = [{"path": "locked/python/synthetic-runtime", "sha256": core.sha(b"synthetic tool"), "bytes": 14}]
        proofs = [{"path": "declared/sealed-carrier/synthetic-original-proof.json", "sha256": core.sha(b"synthetic proof"), "bytes": 15}]
        carrier = [{"name": name, "sha256": core.sha(name.encode()), "bytes": len(name)} for name in core.FILES]
        document = {"schema_version": 1, "kind": inputs.RECIPE_KIND, "producer": inputs.TARGET,
                    "profile": inputs.PROFILE, "inputs": {"code": code, "tools": tools, "proofs": proofs, "carrier": carrier},
                    "outputs": list(inputs.OUTPUTS), "physical_mode_policy": inputs.POLICY}
        def pins(doc):
            return {"materialization": {"recipe_sha256": core.sha(core.encoded(doc)),
                    "action_inputs_sha256": core.sha(core.encoded(doc["inputs"]))}}
        self.assertEqual(inputs.recipe(core.encoded(document), pins(document), self.clock), document)
        for fault in ("output-pin-in-recipe", "missing-tool", "missing-proofs", "wrong-input-commitment", "duplicate-code", "cross-role-duplicate", "wrong-carrier-order", "extra-role", "wrong-policy"):
            changed = copy.deepcopy(document)
            if fault == "output-pin-in-recipe": changed["inventory_sha256"] = core.sha(b"synthetic output")
            elif fault == "missing-tool": changed["inputs"]["tools"] = []
            elif fault == "missing-proofs": changed["inputs"].pop("proofs")
            elif fault == "duplicate-code": changed["inputs"]["code"] *= 2
            elif fault == "cross-role-duplicate": changed["inputs"]["proofs"][0]["path"] = changed["inputs"]["code"][0]["path"]
            elif fault == "wrong-carrier-order": changed["inputs"]["carrier"].reverse()
            elif fault == "extra-role": changed["inputs"]["ambient_sdk"] = []
            elif fault == "wrong-policy": changed["physical_mode_policy"] = "unqualified-writable-inputs"
            selected = pins(changed)
            if fault == "wrong-input-commitment": selected["materialization"]["action_inputs_sha256"] = core.sha(b"wrong complete inputs")
            with self.subTest(fault=fault), self.assertRaises(ValueError):
                inputs.recipe(core.encoded(changed), selected, self.clock)
        with patch.object(core, "MAX_ENTRIES", 1), self.assertRaises(ValueError):
            inputs.recipe(core.encoded(document), pins(document), self.clock)
        original = self.clock.deadline
        with patch.object(core.time, "monotonic", return_value=original), self.assertRaises(ValueError):
            inputs.recipe(core.encoded(document), pins(document), self.clock)
        self.assertEqual(self.clock.deadline, original)


if __name__ == "__main__": unittest.main()
