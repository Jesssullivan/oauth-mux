"""Bounded v2 admission models; no real SDK/source/tool or producer qualification.

The fixture boundary substitutes reserved kernel custody/source ancestry only.
Receipt/evidence byte readers, XML success checks, aliases, query planning and
restoration/refusal logic below are the actual consumer implementation.
"""
import copy
from contextlib import contextmanager, ExitStack, redirect_stdout, redirect_stderr
import io
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

import codex_native_carrier_metadata as consumer


class CarrierMetadataModels(unittest.TestCase):
    def setUp(self):
        self.original = {"kind": "original-source-selection", "source_root": "/fixture-source",
            "source_receipt_sha256": "1" * 64, "source_inventory_sha256": "2" * 64,
            "binding_receipt_sha256": "3" * 64, "export_root": str(consumer.legacy.EXPORT_ROOT),
            "export_receipt_sha256": consumer.legacy.EXPORT_SHA}
        self.patches = ExitStack()
        self.addCleanup(self.patches.close)
        self.patches.enter_context(patch.object(consumer.binding, "selected_document", return_value=self.original))
        self.patches.enter_context(patch.object(consumer.time, "monotonic", return_value=101.0))
        self.patches.enter_context(patch.object(consumer.kernel.time, "monotonic_ns", return_value=101 * 10**9))
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.epoch = self.root / "11111111-1111-1111-1111-111111111111"
        self.epoch.mkdir(mode=0o700)
        self.patches.enter_context(patch.object(consumer.protocol, "PRODUCER_SCOPE",
            re.compile(re.escape(str(self.epoch / "receipt.json")) + r"\Z")))
        self.report_path = self.root / "output/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools"
        self.report_path /= "codex_native_sdk_carrier_seal_producer/test.outputs/sdk-private/native-sdk-carrier-producer.json"
        self.report_path.parent.mkdir(parents=True, mode=0o700)
        self.reserved = {"original_entry_monotonic_ns": 10**9, "original_deadline_monotonic_ns": 1201 * 10**9}
        self.program = {"kind": consumer.PRODUCER_KIND, "producer": consumer.SEAL_TARGET,
            "carrier_receipt_sha256": "4" * 64, "origin_receipt_sha256": consumer.legacy.EXPORT_SHA,
            "producer_context": {"mode": consumer.SEAL_PROFILE, "epoch": str(self.epoch),
                "source_commit": "a" * 40, "graph_sha256": "b" * 64,
                "entry_monotonic_ns": 10**9, "deadline_monotonic_ns": 1201 * 10**9,
                "work_cutoff_monotonic_ns": 1171 * 10**9},
            "files": [{"name": name, "sha256": "4" * 64, "size": 32} for name in consumer.carrier.FILES],
            "all_four_leaves_rechecked": True, "sdk_execution_qualified": False,
            "metadata_qualified": False, "compiler_qualified": False, "runtime_qualified": False}
        evidence = self.epoch / "test-evidence"
        evidence.mkdir(mode=0o700)
        self.xml = b'<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0"/></testsuites>'
        files = []
        for name, raw in (("test.log", b"bounded successful model\n"), ("test.xml", self.xml)):
            pin = consumer.source.sha(raw)
            (evidence / (pin + ".evidence")).write_bytes(raw)
            files.append({"source": name, "state": "copied", "file": pin + ".evidence", "sha256": pin, "bytes": len(raw)})
        self.evidence = {"schema": 1, "bazel_exit": 0, "epoch_start_ns": 10**9,
            "targets": [consumer.SEAL_TARGET], "results": [{"target": consumer.SEAL_TARGET, "state": "observed", "files": files}]}
        self.outer = {"id": self.epoch.name, "unit": "omux-execution-" + self.epoch.name + ".service",
            "manager": "system", "exit": 0, "workload_exit": 0, "controller_failure": None,
            "descendants_empty": True, "cleanup": {"state": "empty"}, "source_dirty": "false",
            "source_commit": "a" * 40, "graph_sha256": "b" * 64, "verb": "test",
            "targets": [consumer.SEAL_TARGET], "test_evidence": {"state": "preserved", "sha256": "0" * 64},
            "epoch_start_ns": 10**9, "output_base": str(self.root / "output")}
        self.selected = {"original_selection": self.original, "carrier": {"receipt_sha256": "4" * 64},
            "qualification": {"producer": {"receipt": str(self.epoch / "receipt.json"), "sha256": "0" * 64,
                "source_commit": "a" * 40, "graph_sha256": "b" * 64},
                "report": {"path": str(self.report_path), "sha256": "0" * 64}}}
        # Reserved kernel properties are tested by the guard's declared suite.
        # This explicit fixture does not turn these temp files into real proof.
        self.patches.enter_context(patch.object(consumer, "producer_policy", return_value=self.reserved))
        self.refresh()

    def refresh(self):
        raw = consumer.source.encoded(self.program)
        self.report_path.write_bytes(raw)
        self.selected["qualification"]["report"]["sha256"] = consumer.source.sha(raw)
        raw = consumer.source.encoded(self.evidence)
        (self.epoch / "test-evidence.json").write_bytes(raw)
        self.outer["test_evidence"]["sha256"] = consumer.source.sha(raw)
        raw = consumer.source.encoded(self.outer)
        (self.epoch / "receipt.json").write_bytes(raw)
        self.selected["qualification"]["producer"]["sha256"] = consumer.source.sha(raw)

    def encoded_selection(self, selected=None):
        return consumer.source.encoded({"schema_version": 2, "kind": consumer.KIND,
            "status": "selected-qualified-carrier-for-metadata", "selection": self.selected if selected is None else selected})

    @contextmanager
    def binding_candidate_fixture(self):
        """Actual binding bytes/readers; SOURCE ancestry is an explicit model seam."""
        controls = Path(tempfile.mkdtemp(dir=self.root))
        path = controls / "receipt.json"
        bound = {"kind": "bounded-original-binding-model", "native_support": False}
        raw = consumer.source.encoded(bound)
        path.write_bytes(raw)
        path.chmod(0o444)
        controls.chmod(0o555)
        pin = consumer.source.sha(raw)
        self.original["binding_receipt_sha256"] = pin
        value = {"binding": {"path": str(path), "sha256": pin}}
        report = {"inventory_sha256": "2" * 64, "graph_files": {}, "patch_sha256": []}
        result = (report, {"MODULE.bazel": ("100644", b"# tiny source model\n")}, {"baseline_graph_files": {}})
        try:
            with ExitStack() as stack:
                stack.enter_context(patch.multiple(consumer.legacy, INPUT_CONTROL=path, BINDING_SHA=pin, DEADLINE=601.0))
                stack.enter_context(patch.object(consumer.source, "DEADLINE", 601.0))
                stack.enter_context(patch.object(consumer.binding, "config", side_effect=lambda: copy.deepcopy(value)))
                stack.enter_context(patch.object(consumer.binding, "bind", return_value=bound))
                loaded = stack.enter_context(patch.object(consumer.binding, "load_verified_source", return_value=result))
                yield path, raw, result, loaded, value
        finally:
            controls.chmod(0o700)

    def test_explicit_retained_binding_reads_actual_bazel_mode_without_weakening_default(self):
        with self.binding_candidate_fixture() as (path, raw, result, loaded, value):
            self.assertEqual(consumer.legacy.load_candidate(self.original), result)
            self.assertEqual(consumer.legacy.load_retained_candidate(self.original), result)
            self.assertEqual(path.read_bytes(), raw)
            # Fixture-only immutable retention reproduces Bazel's physical mode.
            path.chmod(0o555)
            loaded.reset_mock()
            with self.assertRaises(ValueError):
                consumer.legacy.load_candidate(self.original)
            loaded.assert_not_called()
            self.assertEqual(consumer.legacy.load_retained_candidate(self.original), result)
            loaded.assert_called_once_with(self.original)
            self.assertEqual((consumer.source.DEADLINE, consumer.legacy.DEADLINE), (601.0, 601.0))
            self.assertEqual(path.read_bytes(), raw)
            self.assertEqual(path.stat().st_mode & 0o7777, 0o555)

    def test_retained_binding_refuses_writable_symlink_pin_and_context_before_source_proof(self):
        with self.binding_candidate_fixture() as (path, raw, result, loaded, value):
            for mode in (0o600, 0o644, 0o666, 0o755):
                with self.subTest(mode=oct(mode)):
                    path.chmod(mode)
                    with self.assertRaises(ValueError):
                        consumer.legacy.load_retained_candidate(self.original)
                    loaded.assert_not_called()
            path.chmod(0o600)
            path.write_bytes(raw + b"\n")
            path.chmod(0o555)
            with self.assertRaises(ValueError):
                consumer.legacy.load_retained_candidate(self.original)
            loaded.assert_not_called()
            path.chmod(0o600)
            path.write_bytes(raw)
            path.chmod(0o555)
            value["binding"]["path"] = str(self.root / "unselected-binding.json")
            with self.assertRaises(ValueError):
                consumer.legacy.load_retained_candidate(self.original)
            loaded.assert_not_called()
            value["binding"]["path"] = str(path)
            path.parent.chmod(0o700)
            foreign = path.parent / "foreign.json"
            path.rename(foreign)
            path.symlink_to(foreign)
            path.parent.chmod(0o555)
            with self.assertRaises(OSError):
                consumer.legacy.load_retained_candidate(self.original)
            loaded.assert_not_called()

    def test_retained_binding_rechecks_exact_mode_inode_bytes_and_config_after_source_proof(self):
        for mutation in ("mode", "inode", "bytes", "config"):
            with self.subTest(mutation=mutation), self.binding_candidate_fixture() as (path, raw, result, loaded, value):
                def mutate(document):
                    self.assertEqual(document, self.original)
                    if mutation == "mode":
                        path.chmod(0o555)
                    elif mutation == "inode":
                        path.parent.chmod(0o700)
                        path.rename(path.parent / "held-original.json")
                        path.write_bytes(raw)
                        path.chmod(0o444)
                        path.parent.chmod(0o555)
                    elif mutation == "bytes":
                        path.chmod(0o600)
                        path.write_bytes(raw + b"\n")
                        path.chmod(0o444)
                    else:
                        value["binding"]["path"] = str(self.root / "changed-configuration.json")
                    return result
                loaded.side_effect = mutate
                with self.assertRaises(ValueError):
                    consumer.legacy.load_retained_candidate(self.original)
                loaded.assert_called_once_with(self.original)

    def test_retained_binding_original_deadline_expires_during_source_proof_without_renewal(self):
        with self.binding_candidate_fixture() as (path, raw, result, loaded, value):
            with patch.object(consumer.time, "monotonic", return_value=601.0):
                with self.assertRaises(ValueError):
                    consumer.legacy.load_retained_candidate(self.original)
            loaded.assert_not_called()
            def expire(document):
                self.patches.enter_context(patch.object(consumer.time, "monotonic", return_value=601.0))
                return result
            loaded.side_effect = expire
            with self.assertRaises(ValueError):
                consumer.legacy.load_retained_candidate(self.original)
            loaded.assert_called_once_with(self.original)
            self.assertEqual((consumer.source.DEADLINE, consumer.legacy.DEADLINE), (601.0, 601.0))

    def declared_proofs(self):
        """Real mapped proof repository fixture, with the selected exact pins."""
        canonical = "extension+" + consumer.PROOF_REPOSITORY
        runfiles = self.root / "proof-runfiles"
        physical = self.root / "external" / canonical
        physical.mkdir(parents=True, exist_ok=True)
        alias_root = runfiles / canonical
        (alias_root / "proof").mkdir(parents=True, exist_ok=True)
        paths = {"outer_receipt": self.epoch / "receipt.json", "test_evidence": self.epoch / "test-evidence.json",
            "program_report": Path(self.selected["qualification"]["report"]["path"])}
        pins = {"outer_receipt": self.selected["qualification"]["producer"]["sha256"],
            "test_evidence": self.outer["test_evidence"]["sha256"],
            "program_report": self.selected["qualification"]["report"]["sha256"]}
        for role, member in (("test_log", "test.log"), ("test_xml", "test.xml")):
            row = next(row for row in self.evidence["results"][0]["files"] if row["source"] == member)
            paths[role] = self.epoch / "test-evidence" / row["file"]
            pins[role] = row["sha256"]
        document = {"kind": consumer.PROOF_KIND, "proofs": {role: {"path": str(paths[role]),
            "sha256": pins[role], "alias": alias} for role, alias in consumer.PROOF_ALIASES.items()}}
        (physical / "proof-inputs.json").write_bytes(consumer.source.encoded(document))
        for name, target in [("proof-inputs.json", physical / "proof-inputs.json")] + [
                (alias, paths[role]) for role, alias in consumer.PROOF_ALIASES.items()]:
            leaf = alias_root / name
            if leaf.is_symlink():
                leaf.unlink()
            leaf.symlink_to(target)
        return consumer.declared_proofs(runfiles, [["_main", consumer.PROOF_REPOSITORY, canonical]], self.selected, 601.0)

    def qualify(self):
        return consumer.qualify_producer(self.selected, 601.0, self.declared_proofs())

    def test_selector_requires_exact_original_source_and_complete_qualified_pins(self):
        self.assertEqual(consumer.selection(self.encoded_selection()), self.selected)
        for mutate in (lambda x: x["original_selection"].update(source_root="/wrong-source"),
                lambda x: x["original_selection"].update(export_root="/wrong-origin"),
                lambda x: x.update(carrier=None), lambda x: x.update(qualification=None),
                lambda x: x["carrier"].update(receipt_sha256="not-a-pin"),
                lambda x: x["qualification"]["producer"].update(source_commit="not-a-commit"),
                lambda x: x["qualification"]["report"].update(path="/a/../wrong.json")):
            value = copy.deepcopy(self.selected)
            mutate(value)
            with self.subTest(value=value), self.assertRaises((ValueError, TypeError, KeyError)):
                consumer.selection(self.encoded_selection(value))
        value = json.loads(self.encoded_selection())
        value["selection"] = None
        with self.assertRaises(ValueError):
            consumer.selection(consumer.source.encoded(value))
        with self.assertRaises(ValueError):
            consumer.selection(b'{"schema_version":2,"schema_version":2}')

    def test_actual_receipt_and_xml_readers_require_genuine_success_shape(self):
        result = self.qualify()
        self.assertEqual(result["report"], self.program)
        original = copy.deepcopy(self.outer)
        for name, value in (("exit", 125), ("workload_exit", 124), ("exit", False),
                ("source_dirty", "true"), ("source_commit", "c" * 40), ("graph_sha256", "d" * 64),
                ("controller_failure", "timeout"), ("descendants_empty", False)):
            self.outer = {**original, name: value}
            self.refresh()
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.qualify()
        self.outer = original
        self.evidence["results"][0]["state"] = "unobserved"
        self.refresh()
        with self.assertRaises(ValueError):
            self.qualify()

    def test_program_report_cannot_change_carrier_epoch_source_deadline_or_promote_flags(self):
        original = copy.deepcopy(self.program)
        mutations = (lambda x: x.update(carrier_receipt_sha256="8" * 64),
            lambda x: x.update(origin_receipt_sha256="9" * 64),
            lambda x: x["producer_context"].update(epoch="/wrong-epoch"),
            lambda x: x["producer_context"].update(source_commit="c" * 40),
            lambda x: x["producer_context"].update(deadline_monotonic_ns=1202 * 10**9),
            lambda x: x["producer_context"].update(work_cutoff_monotonic_ns=1201 * 10**9),
            lambda x: x.update(metadata_qualified=True), lambda x: x.update(metadata_qualified=0),
            lambda x: x.update(all_four_leaves_rechecked=1), lambda x: x.update(extra=True),
            lambda x: x["files"][0].update(size=True), lambda x: x["files"][0].update(sha256="wrong"),
            lambda x: x["files"].pop())
        for mutate in mutations:
            self.program = copy.deepcopy(original)
            mutate(self.program)
            self.refresh()
            with self.subTest(program=self.program), self.assertRaises(ValueError):
                self.qualify()

    def test_missing_modified_or_rebound_qualification_report_refuses(self):
        self.report_path.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.qualify()
        self.refresh()
        alternate = self.root / "wrong-report.json"
        alternate.write_bytes(consumer.source.encoded(self.program))
        self.selected["qualification"]["report"]["path"] = str(alternate)
        with self.assertRaises(ValueError):
            self.qualify()

    def test_failed_empty_or_skipped_xml_is_not_successful_execution_evidence(self):
        for raw in (b'<testsuite tests="0"/>', b'<testsuite tests="1" skipped="1"/>',
                b'<testsuite tests="1" failures="1"/>', b'<testsuite tests="1" errors="1"/>',
                b'<wrong tests="1"/>'):
            pin = consumer.source.sha(raw)
            (self.epoch / "test-evidence" / (pin + ".evidence")).write_bytes(raw)
            self.evidence["results"][0]["files"][1] = {"source": "test.xml", "state": "copied",
                "file": pin + ".evidence", "sha256": pin, "bytes": len(raw)}
            self.refresh()
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                self.qualify()

    def test_declared_aliases_join_one_exact_qualified_output_and_recheck_names(self):
        runfiles = self.root / "runfiles"
        canonical = "extension+" + consumer.REPOSITORY
        alias_root = runfiles / canonical / "carrier"
        alias_root.mkdir(parents=True)
        physical = self.report_path.parent / "sdk-carrier"
        physical.mkdir()
        for name in consumer.carrier.FILES:
            (physical / name).write_bytes(b"model carrier leaf")
            (alias_root / name).symlink_to(physical / name)
        generated = self.root / "external" / canonical
        generated.mkdir(parents=True)
        declared = {"carrier_root": str(physical), "digests": {name: "4" * 64 for name in consumer.carrier.FILES}}
        (generated / "selection.json").write_bytes(consumer.source.encoded(declared))
        (runfiles / canonical / "selection.json").symlink_to(generated / "selection.json")
        rows = [["_main", consumer.REPOSITORY, canonical]]
        root, aliases, declaration = consumer.declared_carrier(runfiles, rows, self.selected, 601.0)
        self.assertEqual(root, physical)
        self.assertEqual(declaration["selection"], declared)
        consumer.recheck_aliases(aliases, 601.0)
        with self.assertRaises(ValueError):
            consumer.declared_carrier(runfiles, rows * 2, self.selected, 601.0)
        wrong = self.root / "foreign.bin"
        wrong.write_bytes(b"model carrier leaf")
        (alias_root / consumer.carrier.FILES[0]).unlink()
        (alias_root / consumer.carrier.FILES[0]).symlink_to(wrong)
        with self.assertRaises(ValueError):
            consumer.declared_carrier(runfiles, rows, self.selected, 601.0)
        with self.assertRaises(ValueError):
            consumer.recheck_aliases(aliases, 601.0)

    def test_declared_digests_are_independent_of_program_pins_and_read_back(self):
        root = self.root / "sdk-carrier"
        path = self.root / "selection.json"
        selection = {"carrier_root": str(root), "digests": {name: "4" * 64 for name in consumer.carrier.FILES}}
        path.write_bytes(consumer.source.encoded(selection))
        declaration = {"selection": selection, "selection_path": str(path), "selection_sha256": consumer.source.sha(path.read_bytes())}
        publication = {"carrier_receipt_sha256": "4" * 64, "files": copy.deepcopy(self.program["files"])}
        qualified = {"report": self.program}
        with patch.object(consumer.carrier, "publication_report", return_value=publication) as proof:
            consumer.recheck_declaration(declaration, qualified, root, "4" * 64, 601.0)
            self.assertEqual(proof.call_args.args, (root, "4" * 64, 601.0))
            publication["files"][0]["sha256"] = "7" * 64
            with self.assertRaises(ValueError):
                consumer.recheck_declaration(declaration, qualified, root, "4" * 64, 601.0)
            publication["files"] = copy.deepcopy(self.program["files"])
            changed = copy.deepcopy(selection)
            changed["digests"][consumer.carrier.FILES[0]] = "8" * 64
            path.write_bytes(consumer.source.encoded(changed))
            with self.assertRaises(ValueError):
                consumer.recheck_declaration(declaration, qualified, root, "4" * 64, 601.0)

    def test_query_plan_uses_only_fresh_sdk_repositories_and_registry(self):
        fresh = self.root / "extracted/sdk"
        exported = {"repositories": {consumer.metadata.HUB: str(fresh / "repositories" / consumer.metadata.HUB),
            "spoke": str(fresh / "repositories/spoke")}, "registry_cache": str(fresh / "registry-cache")}
        plan = consumer.query_plan(self.root / "work", self.root / "source", exported, fresh)
        self.assertIn("--override_repository=spoke=" + str(fresh / "repositories/spoke"), plan["argv"])
        self.assertIn("--repository_cache=" + str(fresh / "registry-cache"), plan["argv"])
        self.assertFalse(any(str(consumer.legacy.EXPORT_ROOT) in arg for arg in plan["argv"]))
        self.assertFalse(any(arg.startswith("--override_repository=" + consumer.metadata.HUB + "=") for arg in plan["argv"]))
        for mutate in (lambda x: x.update(registry_cache=str(consumer.legacy.EXPORT_ROOT / "registry-cache")),
                lambda x: x["repositories"].update(spoke=str(consumer.legacy.EXPORT_ROOT / "repositories/spoke")),
                lambda x: x["repositories"].pop(consumer.metadata.HUB)):
            invalid = copy.deepcopy(exported)
            mutate(invalid)
            with self.assertRaises(ValueError):
                consumer.query_plan(self.root / "work", self.root / "source", invalid, fresh)

    def initial_declaration_fixture(self):
        # The caller seam supplies an already authenticated, canonical binding.
        # This tiny document models joins, never a genuine SDK or NAR proof.
        root = self.root / "sdk-carrier"
        candidate = {"origin": {"receipt_sha256": "1" * 64, "receipt_bytes": 97},
            "manifest_sha256": "2" * 64, "manifest_bytes": 83,
            "payload_sha256": "3" * 64, "payload_bytes": 79}
        pin = consumer.carrier.sha(consumer.carrier.encoded(candidate))
        digests = dict(zip(consumer.carrier.FILES, ("2" * 64, "1" * 64, "3" * 64, pin)))
        sizes = dict(zip(consumer.carrier.FILES, (83, 97, 79, len(consumer.carrier.encoded(candidate)))))
        selected = {"carrier_root": str(root), "digests": digests}
        path = self.root / "initial-selection.json"
        raw = consumer.source.encoded(selected)
        path.write_bytes(raw)
        declaration = {"selection": selected, "selection_path": str(path), "selection_sha256": consumer.source.sha(raw)}
        qualified = {"report": {"carrier_receipt_sha256": pin, "files": [
            {"name": name, "sha256": digests[name], "size": sizes[name]} for name in consumer.carrier.FILES]}}
        return root, candidate, pin, declaration, qualified

    def test_initial_join_reads_independent_declaration_without_reopening_carrier(self):
        root, candidate, pin, declaration, qualified = self.initial_declaration_fixture()
        with patch.object(consumer.carrier, "publication_report", side_effect=AssertionError("duplicate full proof")) as full:
            consumer._recheck_initial_declaration(declaration, qualified, root, pin, candidate, 601.0)
            full.assert_not_called()
            # Original expiry still refuses before any dependent output.
            with patch.object(consumer.time, "monotonic", return_value=601.0), self.assertRaises(ValueError):
                consumer._recheck_initial_declaration(declaration, qualified, root, pin, candidate, 601.0)

    def test_initial_join_refuses_each_independent_digest_size_order_and_receipt_pin(self):
        root, candidate, pin, declaration, qualified = self.initial_declaration_fixture()
        mutations = [
            lambda d, q: d["selection"].update(carrier_root=str(self.root / "foreign")),
            lambda d, q: q["report"].update(carrier_receipt_sha256="7" * 64),
            lambda d, q: q["report"]["files"].reverse(),
        ]
        for index in range(len(consumer.carrier.FILES)):
            mutations.extend((
                lambda d, q, i=index: q["report"]["files"][i].update(sha256="8" * 64),
                lambda d, q, i=index: q["report"]["files"][i].update(size=q["report"]["files"][i]["size"] + 1),
                lambda d, q, i=index: d["selection"]["digests"].update({consumer.carrier.FILES[i]: "9" * 64}),
            ))
        for mutate in mutations:
            d, q = copy.deepcopy(declaration), copy.deepcopy(qualified)
            mutate(d, q)
            raw = consumer.source.encoded(d["selection"])
            Path(d["selection_path"]).write_bytes(raw)
            d["selection_sha256"] = consumer.source.sha(raw)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                consumer._recheck_initial_declaration(d, q, root, pin, candidate, 601.0)
        Path(declaration["selection_path"]).write_bytes(consumer.source.encoded(declaration["selection"]))
        changed = dict(candidate, payload_bytes=candidate["payload_bytes"] + 1)
        with self.assertRaises(ValueError):
            consumer._recheck_initial_declaration(declaration, qualified, root, pin, changed, 601.0)
        # Equal JSON with different bytes still loses the original declared pin.
        Path(declaration["selection_path"]).write_bytes(consumer.source.encoded(declaration["selection"]) + b"\n")
        with self.assertRaises(ValueError):
            consumer._recheck_initial_declaration(declaration, qualified, root, pin, candidate, 601.0)

    def test_scope_restores_every_original_clock_control_and_query_root_on_exception(self):
        names = ("DEADLINE", "INPUT_CONTROL", "BINDING_SHA", "QUERY_REPOSITORY")
        before = tuple(getattr(consumer.legacy, name) for name in names)
        source_before, origin = consumer.source.DEADLINE, consumer.legacy.EXPORT_ROOT
        with patch.object(consumer.legacy, "configure_selection"):
            with self.assertRaises(RuntimeError), consumer.proof_scope(601.0):
                self.assertEqual(consumer.source.DEADLINE, 601.0)
                self.assertEqual(consumer.legacy.DEADLINE, 601.0)
                self.assertEqual(consumer.legacy.EXPORT_ROOT, origin)
                consumer.legacy.QUERY_REPOSITORY = Path("/fixture-query")
                with self.assertRaises(ValueError), consumer.proof_scope(601.0):
                    self.fail("nested clock renewal admitted")
                raise RuntimeError("owned model interruption")
        self.assertEqual(tuple(getattr(consumer.legacy, name) for name in names), before)
        self.assertEqual(consumer.source.DEADLINE, source_before)
        self.assertIsNone(consumer._SCOPE.get())

    def test_original_guard_clock_is_required_and_never_rebased(self):
        environment = {"OMUX_SDK_CARRIER_MODE": consumer.PROFILE,
            "OMUX_SDK_CARRIER_ENTRY_NS": str(100 * 10**9), "OMUX_SDK_CARRIER_DEADLINE_NS": str(1300 * 10**9),
            "OMUX_SDK_CARRIER_EPOCH": str(self.epoch), "OMUX_SDK_CARRIER_SOURCE_COMMIT": "a" * 40,
            "OMUX_SDK_CARRIER_GRAPH_SHA256": "b" * 64}
        entry, until, _ = consumer.envelope(environment)
        self.assertEqual((entry, until), (100 * 10**9, 1300 * 10**9))
        self.assertEqual(consumer.query_tools.consumer_deadline(float(entry / 10**9), 600), 700.0)
        for key, value in (("OMUX_SDK_CARRIER_MODE", "standard"), ("OMUX_SDK_CARRIER_ENTRY_NS", "0100"),
                ("OMUX_SDK_CARRIER_DEADLINE_NS", str(1400 * 10**9)), ("OMUX_SDK_CARRIER_SOURCE_COMMIT", "wrong")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                consumer.envelope({**environment, key: value})
        with patch.object(consumer.time, "monotonic", return_value=701.0), self.assertRaises(ValueError):
            consumer.query_tools.consumer_deadline(float(entry / 10**9), 600)
        with patch.object(consumer.time, "monotonic", return_value=601.0), self.assertRaises(ValueError):
            consumer.tick(601.0)

    def test_proof_repository_requires_exact_mapping_and_every_declared_role(self):
        proofs = self.declared_proofs()
        canonical = "extension+" + consumer.PROOF_REPOSITORY
        runfiles = self.root / "proof-runfiles"
        rows = [["_main", consumer.PROOF_REPOSITORY, canonical]]
        original = copy.deepcopy(proofs.document)
        mutations = (lambda x: x["proofs"].pop("test_xml"), lambda x: x["proofs"].update(extra={}),
            lambda x: x.update(kind="wrong-kind"),
            lambda x: x["proofs"]["outer_receipt"].update(sha256="8" * 64),
            lambda x: x["proofs"]["test_xml"].update(alias=consumer.PROOF_ALIASES["test_log"]),
            lambda x: x["proofs"]["program_report"].update(path=str(self.epoch / "receipt.json")))
        with patch.object(consumer.protocol, "read_json", wraps=consumer.protocol.read_json) as reader:
            for mutate in mutations:
                value = copy.deepcopy(original)
                mutate(value)
                proofs.path.write_bytes(consumer.source.encoded(value))
                with self.subTest(value=value), self.assertRaises(ValueError):
                    consumer.declared_proofs(runfiles, rows, self.selected, 601.0)
            reader.assert_not_called()
        duplicate = copy.deepcopy(original)
        duplicate["proofs"]["test_xml"].update(path=original["proofs"]["test_log"]["path"],
            sha256=original["proofs"]["test_log"]["sha256"])
        xml_alias = runfiles / canonical / consumer.PROOF_ALIASES["test_xml"]
        xml_alias.unlink()
        xml_alias.symlink_to(duplicate["proofs"]["test_xml"]["path"])
        proofs.path.write_bytes(consumer.source.encoded(duplicate))
        with patch.object(consumer.protocol, "read_json", wraps=consumer.protocol.read_json) as reader:
            with self.assertRaises(ValueError):
                consumer.declared_proofs(runfiles, rows, self.selected, 601.0)
            reader.assert_not_called()
        xml_alias.unlink()
        xml_alias.symlink_to(original["proofs"]["test_xml"]["path"])
        proofs.path.write_bytes(consumer.source.encoded(original))
        for wrong in ([], rows * 2, [["_main", consumer.PROOF_REPOSITORY, "foreign-repository"]]):
            with self.subTest(rows=wrong), self.assertRaises(ValueError):
                consumer.declared_proofs(runfiles, wrong, self.selected, 601.0)

    def test_rebound_proof_alias_refuses_before_any_authentication_read(self):
        proofs = self.declared_proofs()
        omitted, target = next((alias, target) for alias, target in proofs.aliases if alias.name == "test-xml.evidence")
        omitted.unlink()
        with patch.object(consumer.protocol, "read_json", wraps=consumer.protocol.read_json) as reader:
            with self.assertRaises((OSError, ValueError)):
                consumer.qualify_producer(self.selected, 601.0, proofs)
            reader.assert_not_called()
        omitted.symlink_to(target)
        alias = next(alias for alias, _ in proofs.aliases if alias.name == "outer-receipt.json")
        foreign = self.root / "foreign-outer.json"
        foreign.write_bytes((self.epoch / "receipt.json").read_bytes())
        alias.unlink()
        alias.symlink_to(foreign)
        with patch.object(consumer.protocol, "read_json", wraps=consumer.protocol.read_json) as reader:
            with self.assertRaises(ValueError):
                consumer.qualify_producer(self.selected, 601.0, proofs)
            reader.assert_not_called()

    def test_independent_evidence_pin_joins_outer_before_evidence_io(self):
        proofs = self.declared_proofs()
        value = copy.deepcopy(proofs.document)
        value["proofs"]["test_evidence"]["sha256"] = "9" * 64
        proofs.path.write_bytes(consumer.source.encoded(value))
        canonical = "extension+" + consumer.PROOF_REPOSITORY
        declared = consumer.declared_proofs(self.root / "proof-runfiles",
            [["_main", consumer.PROOF_REPOSITORY, canonical]], self.selected, 601.0)
        with patch.object(consumer.protocol, "read_json", wraps=consumer.protocol.read_json) as reader:
            with self.assertRaises(ValueError):
                consumer.qualify_producer(self.selected, 601.0, declared)
            self.assertEqual([call.args[0] for call in reader.call_args_list], [self.epoch / "receipt.json"])

    def test_mid_authentication_alias_mutation_refuses_before_next_proof_read(self):
        proofs = self.declared_proofs()
        alias = next(alias for alias, _ in proofs.aliases if alias.name == "test-log.evidence")
        foreign = self.root / "foreign-log.evidence"
        foreign.write_bytes(b"same harmless log fixture\n")
        original_reader = consumer.protocol.read_json

        def mutate_after_outer(path, pin, deadline, *args):
            result = original_reader(path, pin, deadline, *args)
            if path == self.epoch / "receipt.json":
                alias.unlink()
                alias.symlink_to(foreign)
            return result

        with patch.object(consumer.protocol, "read_json", side_effect=mutate_after_outer) as reader:
            with self.assertRaises(ValueError):
                consumer.qualify_producer(self.selected, 601.0, proofs)
            self.assertEqual([call.args[0] for call in reader.call_args_list], [self.epoch / "receipt.json"])

    def test_pinned_proof_mapping_and_actual_copied_xml_mutations_refuse(self):
        proofs = self.declared_proofs()
        consumer.qualify_producer(self.selected, 601.0, proofs)
        proofs.path.write_bytes(proofs.path.read_bytes() + b" ")
        with self.assertRaises(ValueError):
            consumer.qualify_producer(self.selected, 601.0, proofs)
        proofs = self.declared_proofs()
        xml = Path(proofs.document["proofs"]["test_xml"]["path"])
        xml.write_bytes(b'<testsuite tests="1" failures="1"/>')
        with self.assertRaises(ValueError):
            consumer.qualify_producer(self.selected, 601.0, proofs)

    def test_failed_genuine_producer_refuses_before_extraction_or_source_reads(self):
        context = {"mode": consumer.PROFILE, "epoch": str(self.epoch), "source_commit": "a" * 40,
            "graph_sha256": "b" * 64, "entry_monotonic_ns": 10**9, "deadline_monotonic_ns": 1201 * 10**9}
        with patch.object(consumer.legacy, "configure_selection"), \
                patch.object(consumer, "qualify_producer", side_effect=ValueError("producer refused")), \
                patch.object(consumer.carrier, "extract") as extract, \
                patch.object(consumer.legacy, "load_retained_candidate") as source_read:
            with self.assertRaises(ValueError), consumer.proof_scope(601.0):
                consumer.produce(self.selected, "5" * 64, self.root / "carrier", (), {}, self.declared_proofs(),
                    self.root / "work", self.root / "result", 601.0, context)
            extract.assert_not_called()
            source_read.assert_not_called()
        self.assertFalse((self.root / "result").exists())
        self.assertIsNone(consumer._SCOPE.get())

    def run_bounded_consumer(self, *, mutate_workspace=False, fail_final_custody=False,
            mutate_ready_workspace=False, fail_ready_custody=False, mutate_ready_proof=False,
            mutate_binding=False, bad_initial_context=False, fail_initial_declaration=False,
            fail_initial_source=False):
        """Actual workspace/output FD writes and root holds; explicit proof seams.

        A tiny source/SDK/carrier is a trusted model boundary, never qualification.
        The orchestration must still reject its own query mutations/final gate.
        """
        retained = self.root / "retained-source"
        retained.mkdir(mode=0o555)
        self.original["source_root"] = str(retained)
        controls = self.root / "binding-controls"
        controls.mkdir(mode=0o700)
        binding_path = controls / "receipt.json"
        bound = {"kind": "bounded-original-binding-model", "native_support": False}
        binding_raw = consumer.source.encoded(bound)
        binding_path.write_bytes(binding_raw)
        binding_path.chmod(0o555)
        controls.chmod(0o555)
        binding_pin = consumer.source.sha(binding_raw)
        self.original["binding_receipt_sha256"] = binding_pin
        packed = self.root / "packed"
        packed.mkdir(mode=0o555)
        work, output = self.root / "work", self.root / "result"
        context = {"mode": consumer.PROFILE, "epoch": str(self.epoch), "source_commit": "a" * 40,
            "graph_sha256": "b" * 64, "entry_monotonic_ns": 10**9, "deadline_monotonic_ns": 1201 * 10**9}
        files = {"MODULE.bazel": ("100644", b"# immutable tiny source model\n")}
        report = {"inventory_sha256": "2" * 64, "graph_files": {}, "patch_sha256": []}
        baseline = {"baseline_graph_files": {}}
        origin = {"origin": {"root": str(consumer.legacy.EXPORT_ROOT), "receipt_sha256": consumer.legacy.EXPORT_SHA,
            "baseline_inventory_sha256": consumer.source.BASE_INVENTORY}, "producer_context": self.program["producer_context"],
            "origin_custody": {}}
        if bad_initial_context:
            origin["producer_context"] = dict(origin["producer_context"], source_commit="c" * 40)
        extraction = {"kind": "bounded-extraction-model"}
        events = []

        def configure():
            consumer.legacy.INPUT_CONTROL = binding_path
            consumer.legacy.BINDING_SHA = binding_pin
            consumer.legacy.QUERY_REPOSITORY = self.root / "independent-query-tools"

        def extract(root, pin, destination, deadline, *, on_bound):
            self.assertEqual((root, pin, deadline), (packed, "4" * 64, 601.0))
            events.append("extract")
            self.assertFalse(output.exists())
            self.assertFalse(work.exists())
            on_bound(origin)
            events.append("bound")
            self.assertTrue(output.is_dir())
            destination.mkdir(mode=0o700)
            for role in ("sdk", "jdk"):
                (destination / role).mkdir(mode=0o555)
            destination.chmod(0o555)
            return extraction

        def validate_export(root, pin, inventory, graph, *, on_read):
            self.assertEqual(root, output / "extracted/sdk")
            self.assertEqual((pin, inventory, graph), (consumer.legacy.EXPORT_SHA, consumer.source.BASE_INVENTORY, {}))
            on_read(0)
            events.append("sdk")
            return {"repositories": {consumer.metadata.HUB: str(root / "repositories" / consumer.metadata.HUB),
                "spoke": str(root / "repositories/spoke")}, "registry_cache": str(root / "registry-cache")}

        def run_query(plan, directory):
            events.append("query")
            self.assertEqual(consumer.source.DEADLINE, 601.0)
            self.assertEqual(consumer.legacy.DEADLINE, 601.0)
            self.assertEqual(directory, output)
            self.assertFalse(any(str(consumer.legacy.EXPORT_ROOT) in arg for arg in plan["argv"]))
            if mutate_workspace:
                path = work / "workspace/source/MODULE.bazel"
                path.chmod(0o600)
                path.write_bytes(b"query changed its own module\n")
                path.chmod(0o555)
            if mutate_binding:
                binding_path.chmod(0o600)
                binding_path.write_bytes(binding_raw + b"\n")
                binding_path.chmod(0o555)
            return 0

        def revalidate(root, pin, destination, deadline, *, pinned_extraction_receipt_sha256):
            self.assertEqual(deadline, 601.0)
            self.assertEqual(pinned_extraction_receipt_sha256, consumer.carrier.sha(consumer.carrier.encoded(extraction)))
            events.append("fresh")
            if fail_final_custody and "query-tools" in events:
                raise ValueError("late fresh custody refused")
            if fail_ready_custody and (output / "metadata-receipt.json").exists():
                raise ValueError("ready fresh custody refused")
            return extraction

        original_writer = consumer.write_receipt

        def write_ready(root, receipt, deadline):
            original_writer(root, receipt, deadline)
            if mutate_ready_workspace:
                path = work / "workspace/source/MODULE.bazel"
                path.chmod(0o600)
                path.write_bytes(b"ready publication changed workspace\n")
                path.chmod(0o555)
            if mutate_ready_proof:
                alias = self.root / "proof-runfiles" / ("extension+" + consumer.PROOF_REPOSITORY) / "proof/program-report.json"
                foreign = self.root / "foreign-ready-report.json"
                foreign.write_bytes(self.report_path.read_bytes())
                alias.unlink()
                alias.symlink_to(foreign)

        def tools(root, deadline):
            self.assertEqual((root, deadline), (self.root / "independent-query-tools", 601.0))
            events.append("query-tools")
            return {"status": "declared-fixed-query-tools-byte-qualified", "inputs_rechecked": True}

        with ExitStack() as stack:
            stack.enter_context(patch.object(consumer.legacy, "configure_selection", side_effect=configure))
            final_binding = stack.enter_context(patch.object(consumer.carrier, "validate_binding", return_value=origin))
            stack.enter_context(patch.object(consumer, "recheck_declaration"))
            initial_join = stack.enter_context(patch.object(consumer, "_recheck_initial_declaration",
                side_effect=ValueError("private declaration content") if fail_initial_declaration else None))
            stack.enter_context(patch.object(consumer.binding, "config", return_value={"binding": {
                "path": str(binding_path), "sha256": binding_pin}}))
            stack.enter_context(patch.object(consumer.binding, "bind", return_value=bound))
            source_read = stack.enter_context(patch.object(consumer.binding, "load_verified_source",
                side_effect=ValueError("private source content") if fail_initial_source else None,
                return_value=(report, files, baseline)))
            stack.enter_context(patch.object(consumer.carrier, "extract", side_effect=extract))
            stack.enter_context(patch.object(consumer.carrier, "revalidate_extraction", side_effect=revalidate))
            stack.enter_context(patch.object(consumer.sdk, "validate_export", side_effect=validate_export))
            stack.enter_context(patch.object(consumer.legacy, "read_hub", side_effect=[{"BUILD.bazel": b"old\n"}, {"BUILD.bazel": b"new\n"}]))
            stack.enter_context(patch.object(consumer.binding, "verify_hub_delta", return_value=True))
            stack.enter_context(patch.object(consumer.legacy, "execute_query", side_effect=run_query))
            stack.enter_context(patch.object(consumer.query_tools, "verify_repository", side_effect=tools))
            hold = stack.enter_context(patch.object(consumer.legacy, "hold_root", wraps=consumer.legacy.hold_root))
            recheck = stack.enter_context(patch.object(consumer.legacy, "recheck_root", wraps=consumer.legacy.recheck_root))
            stack.enter_context(patch.object(consumer, "write_receipt", side_effect=write_ready))
            with consumer.proof_scope(601.0):
                result = consumer.produce(self.selected, "5" * 64, packed, (), {}, self.declared_proofs(), work, output, 601.0, context)
            self.assertEqual([call.args[0] for call in hold.call_args_list], [retained, controls])
            self.assertEqual([call.args[0] for call in recheck.call_args_list], [retained, controls, retained, controls])
            self.assertEqual(source_read.call_args_list, [unittest.mock.call(self.original)] * 2)
            self.assertEqual(final_binding.call_args_list, [unittest.mock.call(packed, "4" * 64, 601.0)])
            initial_join.assert_called_once()
            self.assertEqual(initial_join.call_args.args[0], {})
            self.assertEqual(initial_join.call_args.args[1]["report"], self.program)
            self.assertEqual(initial_join.call_args.args[2:], (packed, "4" * 64, origin, 601.0))
        self.assertLess(events.index("bound"), events.index("sdk"))
        self.assertGreater(events.index("fresh", events.index("query-tools")), events.index("query-tools"))
        self.assertTrue(all(result[name] is False for name in consumer.FALSE_FLAGS))
        self.assertEqual(result["kind"], consumer.OUTPUT_KIND)
        self.assertEqual(os.stat(output).st_mode & 0o777, 0o700)
        self.assertEqual(os.stat(output / "metadata-receipt.json").st_mode & 0o777, 0o444)
        self.assertEqual(json.loads((output / "metadata-receipt.json").read_bytes()), result)
        return result

    def test_actual_output_workspace_and_root_holds_preserve_v2_scope(self):
        self.run_bounded_consumer()

    def test_initial_callback_diagnostics_have_bounded_static_order_and_no_content(self):
        output = io.StringIO()
        with redirect_stderr(output):
            self.run_bounded_consumer()
        lines = output.getvalue().splitlines()
        phases = ("start", "declaration-ready", "aliases-ready", "source-ready", "output-ready")
        self.assertEqual(len(lines), len(phases))
        for line, phase in zip(lines, phases):
            self.assertRegex(line, "^sdk-carrier-initial-callback: " + phase + r" elapsed_ns=[0-9]+$")
        self.assertNotIn(str(self.root), output.getvalue())
        self.assertNotIn("private", output.getvalue())

    def assert_initial_callback_refusal(self, option, phases):
        output = io.StringIO()
        with redirect_stderr(output), self.assertRaises(ValueError):
            self.run_bounded_consumer(**{option: True})
        lines = output.getvalue().splitlines()
        self.assertEqual(len(lines), len(phases))
        for line, phase in zip(lines, phases):
            self.assertRegex(line, "^sdk-carrier-initial-callback: " + phase + r" elapsed_ns=[0-9]+$")
        self.assertNotIn(str(self.root), output.getvalue())
        self.assertNotIn("private", output.getvalue())
        self.assertFalse((self.root / "result").exists())
        self.assertFalse((self.root / "work").exists())
        self.assertIsNone(consumer._SCOPE.get())

    def test_initial_callback_declaration_failure_preserves_refusal_and_no_output(self):
        self.assert_initial_callback_refusal("fail_initial_declaration", ("start", "refused"))

    def test_initial_callback_source_failure_preserves_refusal_and_no_output(self):
        self.assert_initial_callback_refusal("fail_initial_source", ("start", "declaration-ready", "aliases-ready", "refused"))

    def test_authenticated_initial_origin_context_refuses_before_dependent_output(self):
        with self.assertRaises(ValueError):
            self.run_bounded_consumer(bad_initial_context=True)
        self.assertFalse((self.root / "result").exists())
        self.assertFalse((self.root / "work").exists())
        self.assertIsNone(consumer._SCOPE.get())

    def test_query_workspace_mutation_refuses_before_metadata_receipt(self):
        with self.assertRaises(ValueError):
            self.run_bounded_consumer(mutate_workspace=True)
        self.assertFalse((self.root / "result/metadata-receipt.json").exists())
        self.assertIsNone(consumer._SCOPE.get())

    def test_query_binding_mutation_refuses_actual_retained_readback_before_metadata_receipt(self):
        with self.assertRaises(ValueError):
            self.run_bounded_consumer(mutate_binding=True)
        self.assertFalse((self.root / "result/metadata-receipt.json").exists())
        self.assertIsNone(consumer._SCOPE.get())

    def test_late_final_extracted_custody_failure_refuses_before_metadata_receipt(self):
        with self.assertRaises(ValueError):
            self.run_bounded_consumer(fail_final_custody=True)
        self.assertFalse((self.root / "result/metadata-receipt.json").exists())
        self.assertIsNone(consumer._SCOPE.get())

    def test_ready_publication_workspace_mutation_has_no_accepted_return(self):
        with self.assertRaises(ValueError):
            self.run_bounded_consumer(mutate_ready_workspace=True)
        # Failed outer execution must never qualify retained partial diagnostics.
        self.assertTrue((self.root / "result/metadata-receipt.json").exists())
        self.assertIsNone(consumer._SCOPE.get())

    def test_ready_publication_fresh_custody_loss_has_no_accepted_return(self):
        with self.assertRaises(ValueError):
            self.run_bounded_consumer(fail_ready_custody=True)
        self.assertTrue((self.root / "result/metadata-receipt.json").exists())
        self.assertIsNone(consumer._SCOPE.get())

    def test_ready_publication_proof_alias_mutation_has_no_accepted_return(self):
        with self.assertRaises(ValueError):
            self.run_bounded_consumer(mutate_ready_proof=True)
        self.assertTrue((self.root / "result/metadata-receipt.json").exists())
        self.assertIsNone(consumer._SCOPE.get())

    def run_publication_main(self, *, changed_selection=False, failed_publication=False,
            expired_readback=False):
        """Actual main/scope/encoding; only the expensive producer is a fixture.

        This models publication admission, never genuine SDK/source qualification.
        The fixture writes a real receipt before returning or refusing, allowing
        a retained partial output to be distinguished from an admitted marker.
        """
        runfiles = self.root / "marker-runfiles"
        output = self.root / "marker-output"
        temporary = self.root / "marker-tmp"
        for path in (runfiles, output, temporary):
            path.mkdir()
        (runfiles / "_repo_mapping").write_bytes(b"_main,fixture,fixture\n")
        raw = self.encoded_selection()
        result = {"kind": consumer.OUTPUT_KIND, "model_only": True}
        published = output / "native-sdk-carrier-metadata" / "metadata-receipt.json"
        events = []

        def declaration(name, maximum):
            self.assertEqual((name, maximum), (consumer.CONFIG, 16384))
            events.append("selection")
            if changed_selection and events.count("selection") == 2:
                return raw + b"changed"
            return raw

        def publication(*args):
            self.assertEqual(args[-2], 601.0)
            self.assertEqual(consumer._SCOPE.get(), 601.0)
            events.append("publication")
            published.parent.mkdir()
            published.write_bytes(consumer.source.encoded(result))
            if failed_publication:
                raise ValueError("model: final publication custody refused")
            return result

        actual_tick = consumer.tick

        def final_tick(deadline):
            if expired_readback and events.count("selection") == 2:
                raise ValueError("model: original cutoff expired after readback")
            actual_tick(deadline)

        class Captured(io.StringIO):
            def write(stream, value):
                if value.startswith("omux-native-carrier-metadata-output-sha256="):
                    self.assertIsNone(consumer._SCOPE.get())
                    self.assertEqual(events, ["selection", "publication", "selection"])
                return super().write(value)

        stream = Captured()
        saved = (consumer.source.DEADLINE, consumer.legacy.DEADLINE,
            consumer.legacy.INPUT_CONTROL, consumer.legacy.BINDING_SHA,
            consumer.legacy.QUERY_REPOSITORY)
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {"TEST_SRCDIR": str(runfiles),
                "TEST_UNDECLARED_OUTPUTS_DIR": str(output), "TEST_TMPDIR": str(temporary),
                "TEST_TIMEOUT": "1200"}))
            stack.enter_context(patch.object(consumer.sys, "argv", ["metadata-model"]))
            stack.enter_context(patch.object(consumer.os, "umask", return_value=0o077))
            stack.enter_context(patch.object(consumer, "envelope", return_value=(10**9, 1201 * 10**9, {})))
            stack.enter_context(patch.object(consumer.legacy, "configure_selection"))
            stack.enter_context(patch.object(consumer.binding.ninth.parent, "declared", side_effect=declaration))
            stack.enter_context(patch.object(consumer.legacy, "declared_query_tools", return_value=True))
            stack.enter_context(patch.object(consumer, "declared_carrier", return_value=(self.root, (), {})))
            stack.enter_context(patch.object(consumer, "declared_proofs", return_value=object()))
            stack.enter_context(patch.object(consumer, "produce", side_effect=publication))
            stack.enter_context(patch.object(consumer, "tick", side_effect=final_tick))
            stack.enter_context(redirect_stdout(stream))
            try:
                consumer.main()
            except ValueError:
                if not (changed_selection or failed_publication or expired_readback):
                    raise
            else:
                self.assertFalse(changed_selection or failed_publication or expired_readback)
        self.assertIsNone(consumer._SCOPE.get())
        self.assertEqual(saved, (consumer.source.DEADLINE, consumer.legacy.DEADLINE,
            consumer.legacy.INPUT_CONTROL, consumer.legacy.BINDING_SHA,
            consumer.legacy.QUERY_REPOSITORY))
        self.assertTrue(published.is_file())
        return stream.getvalue(), published.read_bytes()

    def test_actual_main_marker_binds_receipt_after_final_readback_and_scope_restore(self):
        text, raw = self.run_publication_main()
        markers = [line for line in text.splitlines()
            if line.startswith("omux-native-carrier-metadata-output-sha256=")]
        self.assertEqual(markers, ["omux-native-carrier-metadata-output-sha256=" + consumer.source.sha(raw)])

    def test_partial_publication_refusal_has_no_output_marker(self):
        text, _ = self.run_publication_main(failed_publication=True)
        self.assertNotIn("omux-native-carrier-metadata-output-sha256=", text)

    def test_changed_selector_after_publication_has_no_output_marker(self):
        text, _ = self.run_publication_main(changed_selection=True)
        self.assertNotIn("omux-native-carrier-metadata-output-sha256=", text)

    def test_original_cutoff_after_publication_has_no_output_marker(self):
        text, _ = self.run_publication_main(expired_readback=True)
        self.assertNotIn("omux-native-carrier-metadata-output-sha256=", text)


if __name__ == "__main__":
    unittest.main()
