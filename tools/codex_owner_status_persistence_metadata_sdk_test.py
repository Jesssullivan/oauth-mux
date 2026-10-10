"""Bounded metadata/SDK source models; no actual artifact or native tools read."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import codex_live_source as source
import codex_protocol_history_metadata as metadata
import codex_owner_status_persistence_metadata_producer as producer
import codex_owner_status_persistence_sdk_export as selected
import codex_retained_sdk_export as sdk


class PersistenceMetadataSdkTests(unittest.TestCase):
    def test_real_metadata_and_sdk_copy_replaces_only_hub_with_fresh_source_graph(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            material = root / "retained"
            (material / "repositories" / metadata.HUB).mkdir(parents=True)
            spoke = material / "repositories/spoke"
            spoke.mkdir()
            (spoke / "public-file").write_bytes(b"unchanged spoke\n")
            (spoke / "public-file").chmod(0o444)
            row = {field: [] for field in metadata.LISTS}
            row.update({field: {} for field in metadata.PLATFORMS | metadata.MAPS})
            row["deps"] = [metadata.ROLLOUT, metadata.HISTORY]
            row["aliases"] = {metadata.ROLLOUT: "codex_rollout", metadata.HISTORY: "codex_history"}
            data = {metadata.PACKAGE: row}
            old = {"BUILD.bazel": b"# bounded hub\n", "defs.bzl": b"# unchanged\n",
                "data.bzl": ("DEP_DATA = " + repr(data) + "\n").encode()}
            fresh = copy.deepcopy(data)
            fresh[metadata.PACKAGE]["deps"].remove(metadata.ROLLOUT)
            del fresh[metadata.PACKAGE]["aliases"][metadata.ROLLOUT]
            generated = {**old, "data.bzl": ("DEP_DATA = " + repr(fresh) + "\n").encode()}
            for name, value in old.items():
                path = material / "repositories" / metadata.HUB / name
                path.write_bytes(value)
                path.chmod(0o444)
            registry = material / "registry-cache"
            registry.mkdir()
            (registry / "public").write_bytes(b"registry\n")
            (registry / "public").chmod(0o444)
            for directory, _, _ in os.walk(material, topdown=False):
                Path(directory).chmod(0o555)
            budget = sdk.Budget(sdk.time.time() + 60)
            repositories = []
            for name in (metadata.HUB, "spoke"):
                rows = sdk.inventory(material / "repositories" / name, budget, sealed=True)
                repositories.append({"canonical_name": name, "files": rows,
                    "inventory_sha256": sdk.digest(sdk.canonical(rows)), "absent_links": []})
            retained = {"repositories": repositories, "modules": {}, "registry_metadata": {"isolated": True},
                "nix_store_roots": [sdk.JDK], "nix_inventory": []}
            material.chmod(0o700)
            (material / "receipt.json").write_bytes(source.encoded(retained))
            (material / "receipt.json").chmod(0o444)
            material.chmod(0o555)
            files = {"MODULE.bazel.lock": ("100644", b"isolated-lock\n"), "native.rs": ("100644", b"native\n")}
            graph = {name: {"sha256": source.sha(value)} for name, (_, value) in files.items()}
            report = {"inventory_sha256": "isolated-inventory", "graph_files": graph}
            document = {"kind": producer.KIND, "source_root": str(root), "source_receipt_sha256": "isolated-source",
                "source_inventory_sha256": report["inventory_sha256"], "binding_receipt_sha256": producer.BINDING_SHA,
                "export_root": str(material), "export_receipt_sha256": source.sha(source.encoded(retained))}
            exported = {"repositories": {name: str(material / "repositories" / name) for name in (metadata.HUB, "spoke")},
                "registry_cache": str(registry), "inventory_sha256": "isolated-retained"}
            def query(plan, output):
                hub = root / "work/output-base/external" / metadata.HUB
                hub.mkdir(parents=True)
                for name, value in generated.items():
                    (hub / name).write_bytes(value)
                    (hub / name).chmod(0o444)
                return 0
            real_inventory = sdk.inventory
            def inventory(path, *args, **kwargs):
                return [] if Path(path) == Path(sdk.JDK) else real_inventory(path, *args, **kwargs)
            previous = os.umask(0o077)
            try:
                with patch.multiple(producer, EXPORT_ROOT=material, EXPORT_SHA=document["export_receipt_sha256"], INPUT_CONTROL=root / "isolated-binding"), patch.object(producer, "selected_document", return_value=document), patch.object(producer, "load_candidate", return_value=(report, files, {"baseline_graph_files": {}})), patch.object(sdk, "validate_export", return_value=exported), patch.object(producer, "execute_query", side_effect=query), patch.object(sdk, "inventory", side_effect=inventory), patch.object(sdk, "registry_metadata", return_value=retained["registry_metadata"]), patch.object(producer.binding, "INVENTORY_SHA", report["inventory_sha256"]):
                    deadline = producer.time.monotonic() + 60
                    producer.produce(document, producer.BINDING_SHA, root / "work", root / "metadata", 60, absolute_deadline=deadline)
                    result = selected.export(document, root / "metadata", root / "sdk", deadline)
                    drift = root / "metadata/hub/defs.bzl"
                    drift.chmod(0o600)
                    drift.write_bytes(b"unqualified generated wrapper\n")
                    drift.chmod(0o444)
                    with self.assertRaises(ValueError):
                        selected.export(document, root / "metadata", root / "refused-sdk", deadline)
                    self.assertFalse((root / "refused-sdk/receipt.json").exists())
                self.assertEqual(result["kind"], selected.KIND)
                self.assertEqual((root / "sdk/repositories/spoke/public-file").read_bytes(), b"unchanged spoke\n")
                self.assertEqual((root / "sdk/repositories" / metadata.HUB / "data.bzl").read_bytes(), generated["data.bzl"])
                self.assertEqual((material / "repositories" / metadata.HUB / "data.bzl").read_bytes(), old["data.bzl"])
                self.assertEqual(result["graph_files"], graph)
                self.assertIs(result["sdk_export_qualified"], True)
                for field in ("schema_producer_qualified", "native_compile_passed", "native_support", "provider_evaluation", "live_handoff_proven"):
                    self.assertIs(result[field], False)
            finally:
                os.umask(previous)
                source.DEADLINE = None
                producer.DEADLINE = None
                for directory, _, _ in os.walk(root):
                    Path(directory).chmod(0o700)

    def test_selected_document_is_closed_actual_n3_n4_and_not_fourth(self):
        document = producer.selected_document()
        self.assertEqual(producer.validate_document(document), document)
        for field, value in (("kind", "omux-protocol-history-metadata-input-v1"),
            ("source_root", "/different"), ("source_receipt_sha256", "0" * 64),
            ("source_inventory_sha256", "0" * 64), ("binding_receipt_sha256", "0" * 64),
            ("export_root", "/different"), ("export_receipt_sha256", "0" * 64), ("extra", True)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                producer.validate_document({**document, field: value})

    def test_n4_pin_and_exact_reconstructed_binding_refuse_rehashed_claims(self):
        document = {"kind": "isolated-source-only", "native_support": False}
        raw = source.encoded(document)
        with patch.multiple(producer, BINDING_SHA=source.sha(raw), BINDING_BYTES=len(raw)), patch.object(producer.binding, "bind", return_value=document):
            self.assertEqual(producer.parse_selection(raw, source.sha(raw)), producer.selected_document())
            for changed, digest in ((raw + b"\n", source.sha(raw)), (raw, "0" * 64)):
                with self.assertRaises(ValueError):
                    producer.parse_selection(changed, digest)
            changed = source.encoded({**document, "native_support": True})
            with patch.multiple(producer, BINDING_SHA=source.sha(changed), BINDING_BYTES=len(changed)), self.assertRaises(ValueError):
                producer.parse_selection(changed, source.sha(changed))

    def test_candidate_reads_sealed_n4_and_actual_reconstruction_then_rechecks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "receipt-root"
            root.mkdir()
            path = root / "binding.json"
            bound = {"isolated": "exact"}
            raw = source.encoded(bound)
            path.write_bytes(raw)
            path.chmod(0o555)
            root.chmod(0o555)
            report, files, parent = {"inventory_sha256": "isolated"}, {"native.rs": ("100644", b"native\n")}, {"baseline_graph_files": {}}
            try:
                with patch.multiple(producer, INPUT_CONTROL=path, BINDING_SHA=source.sha(raw), BINDING_BYTES=len(raw)), patch.object(producer.binding, "bind", return_value=bound), patch.object(producer.binding, "load_verified_source", return_value=(report, files)) as loaded, patch.object(producer.history, "load_parent", return_value=({}, parent)):
                    self.assertEqual(producer.load_candidate(producer.selected_document()), (report, files, parent))
                    loaded.assert_called_once_with()
                    path.chmod(0o444)
                    with self.assertRaises(ValueError):
                        producer.load_candidate(producer.selected_document())
            finally:
                root.chmod(0o700)

    def test_fixed_offline_query_omits_only_hub_and_retains_locked_tool_plan(self):
        names = (metadata.HUB, "rules_rs+", "rules_rs++crate+crates__fixture-1")
        repositories = {name: str(producer.EXPORT_ROOT / "repositories" / name) for name in names}
        plan = producer.query_plan(Path("/owned-work"), Path("/owned-source"),
            {"repositories": repositories, "registry_cache": str(producer.EXPORT_ROOT / "registry-cache")})
        self.assertEqual([row for row in plan["argv"] if row.startswith("--override_repository=")],
            ["--override_repository=" + name + "=" + repositories[name] for name in sorted(names) if name != metadata.HUB])
        for flag in ("--lockfile_mode=error", "--repository_disable_download", "--repo_contents_cache=", "--repo_env=CARGO_NET_OFFLINE=true"):
            self.assertEqual(plan["argv"].count(flag), 1)
        self.assertEqual(plan["argv"][-2:], ["--output=build", "@crates//:all"])
        self.assertEqual(plan["argv"][0], producer.BAZEL)
        self.assertEqual(plan["environment"]["PATH"], producer.LOCKED_PATH)
        self.assertFalse(any(row.startswith("--override_module=") for row in plan["argv"]))

    def test_sealed_real_copy_rechecks_every_file_and_refuses_changed_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            origin = root / "origin"
            origin.mkdir()
            (origin / "file").write_bytes(b"bounded material\n")
            (origin / "file").chmod(0o444)
            origin.chmod(0o555)
            budget = sdk.Budget(sdk.time.time() + 60)
            expected = sdk.inventory(origin, budget, sealed=True)
            budget.authorize_export_passes()
            try:
                selected.copy_tree(origin, root / "copy", expected, budget)
                self.assertEqual((root / "copy/file").read_bytes(), b"bounded material\n")
                changed = copy.deepcopy(expected)
                changed[0]["sha256"] = "0" * 64
                with self.assertRaises(ValueError):
                    selected.copy_tree(origin, root / "refused", changed, budget)
            finally:
                for directory, _, _ in os.walk(root):
                    Path(directory).chmod(0o700)

    def test_deadline_never_extended_and_unconfigured_query_repo_refuses_main(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            env = {"TEST_TIMEOUT": "900", "TEST_TMPDIR": str(root), "TEST_UNDECLARED_OUTPUTS_DIR": str(root)}
            document = producer.selected_document()
            repository = root / "declared-query-tools"
            def declare():
                producer.QUERY_REPOSITORY = repository
                return document, producer.BINDING_SHA
            with patch.dict(os.environ, env), patch.object(selected.os, "umask"), patch.object(producer, "declared_selection", side_effect=declare), patch.object(selected.time, "monotonic", return_value=100.0), patch.object(producer, "produce") as generated, patch.object(selected, "export") as exported, patch.object(producer.query_tools, "verify_repository", return_value={"inputs_rechecked": True}) as verified:
                selected.main()
                self.assertEqual(generated.call_args.kwargs["absolute_deadline"], 940.0)
                self.assertEqual(exported.call_args.args[-1], 940.0)
                verified.assert_called_once_with(repository, 940.0)
            with patch.dict(os.environ, env), patch.object(selected.os, "umask"), patch.object(producer, "declared_selection", return_value=(document, producer.BINDING_SHA)), patch.object(producer, "produce") as generated, patch.object(selected, "export") as exported, self.assertRaises(ValueError):
                selected.main()
            generated.assert_not_called()
            exported.assert_not_called()
            with patch.object(producer, "hold_root") as held:
                for deadline in (producer.time.monotonic() - 1, producer.time.monotonic() + 841, True):
                    with self.assertRaises(ValueError):
                        selected.export(document, root / "metadata", root / "sdk", deadline)
                held.assert_not_called()


if __name__ == "__main__":
    unittest.main()
