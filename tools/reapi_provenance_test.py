"""Adversarial graph/receipt tests; no network, providers or ambient tools."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import reapi_provenance as provenance

TOOL_ROOT = "/nix/store/" + "1" * 32 + "-declared-tool"
CLOSURE = "9" * 32 + "-omux-bazel-closure"
MANIFEST = {"system": "aarch64-darwin", "apple": {"sdk_version": "14.4"}}
TOOL_PATH = "external/+omux_nix_repository+omux_nix/closure/" + TOOL_ROOT.split("/")[-1] + "/bin/tool"


def fixture(tool_path=TOOL_PATH):
    graph = {"targets": [], "actions": [], "artifacts": [], "pathFragments": [], "depSetOfFiles": [{"id": 1, "directArtifactIds": [1]}]}
    fragments = {}

    def artifact(path):
        parent = 0
        for label in path.split("/"):
            key = parent, label
            if key not in fragments:
                identifier = len(fragments) + 1
                fragments[key] = identifier
                graph["pathFragments"].append({"id": identifier, "label": label, "parentId": parent})
            parent = fragments[key]
        identifier = len(graph["artifacts"]) + 1
        graph["artifacts"].append({"id": identifier, "pathFragmentId": parent})
        return identifier

    artifact(tool_path)
    receipts = []
    for index, (label, mnemonic) in enumerate(sorted(provenance.REQUIRED_TARGETS), 1):
        output = "bazel-out/darwin/bin/output" + str(index)
        graph["targets"].append({"id": index, "label": label})
        arguments = [TOOL_ROOT + "/bin/tool", "--output", output]
        graph["actions"].append({"targetId": index, "mnemonic": mnemonic, "arguments": arguments, "environmentVariables": [{"key": "PATH", "value": ""}], "inputDepSetIds": [1], "outputIds": [artifact(output)], "executionPlatform": "@@+omux_nix_repository+omux_nix//:execution_platform"})
        receipts.append({"targetLabel": label, "mnemonic": mnemonic, "commandArgs": arguments, "environmentVariables": [{"name": "PATH", "value": ""}], "listedOutputs": [output], "platform": {"properties": [{"name": "nix_closure", "value": CLOSURE}]}, "inputs": [{"path": tool_path, "digest": {"hash": "b" * 64, "sizeBytes": "1", "hashFunctionName": "SHA-256"}}], "status": "", "exitCode": 0, "remotable": True, "cacheHit": False, "runner": "remote", "digest": {"hash": "a" * 64, "sizeBytes": "123", "hashFunctionName": "SHA-256"}, "actualOutputs": [{"path": output, "digest": {"hash": hashlib.sha256(b"artifact").hexdigest(), "sizeBytes": "8", "hashFunctionName": "SHA-256"}}]})
    archive_index = next(index for index, record in enumerate(receipts) if record["targetLabel"] == "//clients/macos:archive")
    graph["depSetOfFiles"].append({"id": 2, "transitiveDepSetIds": [1], "directArtifactIds": [action["outputIds"][0] for index, action in enumerate(graph["actions"]) if index != archive_index]})
    graph["actions"][archive_index]["inputDepSetIds"] = [2]
    receipts[archive_index]["inputs"].extend(copy.deepcopy(record["actualOutputs"][0]) for index, record in enumerate(receipts) if index != archive_index)
    return graph, receipts


class ProvenanceTest(unittest.TestCase):
    def setUp(self):
        self.graph, self.receipts = fixture()

    def plan(self, graph=None):
        return provenance.action_plan(graph if graph is not None else self.graph, MANIFEST, TOOL_ROOT + "\n")[0]

    def reject_graph(self, transform):
        graph = copy.deepcopy(self.graph)
        transform(graph)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            self.plan(graph)

    def reject_receipt(self, transform):
        records = copy.deepcopy(self.receipts)
        transform(records)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            provenance.reconcile(self.plan(), records, CLOSURE)

    def test_complete_graph_and_fresh_remote_receipts(self):
        plan, summary = provenance.action_plan(self.graph, MANIFEST, TOOL_ROOT + "\n")
        metadata, outputs = provenance.reconcile(plan, self.receipts, CLOSURE, fresh=True)
        self.assertEqual(summary["spawn_actions"], 5)
        self.assertFalse(summary["analysis_routing_verified"])
        self.assertFalse(summary["repository_bootstrap_verified"])
        self.assertFalse(summary["receipt_platform_properties_match"])
        self.assertFalse(summary["worker_routing_verified"])
        self.assertEqual(metadata["remote_executions"], 5)
        self.assertEqual(metadata["remote_cache_hits"], 0)
        self.assertTrue(metadata["receipt_platform_properties_match"])
        self.assertFalse(metadata["worker_routing_verified"])
        self.assertNotIn("receipt_routing_verified", metadata)
        self.assertTrue(metadata["fresh_execution_verified"])
        self.assertEqual(len(outputs), 5)

    def test_remote_cache_acceptance_distinct_from_fresh_execution(self):
        self.receipts[0].update(cacheHit=True, runner="remote cache hit")
        metadata, _ = provenance.reconcile(self.plan(), self.receipts, CLOSURE)
        self.assertEqual(metadata["remote_executions"], 4)
        self.assertEqual(metadata["remote_cache_hits"], 1)
        self.assertFalse(metadata["fresh_execution_verified"])
        with self.assertRaises(ValueError):
            provenance.reconcile(self.plan(), self.receipts, CLOSURE, fresh=True)

    def test_aquery_empty_scalar_default_matches_explicit_receipt_value(self):
        self.graph["actions"][0]["environmentVariables"][0].pop("value")
        provenance.reconcile(self.plan(), self.receipts, CLOSURE, fresh=True)
        self.reject_receipt(lambda records: records[0]["environmentVariables"][0].pop("value"))

    def test_disk_cache_local_fallback_and_inconsistent_runner_rejected(self):
        for cache, runner in [(True, "disk cache hit"), (False, "linux-sandbox"), (True, "remote"), (False, "remote cache hit"), (False, "worker")]:
            with self.subTest(cache=cache, runner=runner):
                self.reject_receipt(lambda records: records[0].update(cacheHit=cache, runner=runner))

    def test_missing_duplicate_and_unmatched_receipts_rejected(self):
        self.reject_receipt(lambda records: records.pop())
        self.reject_receipt(lambda records: records.append(copy.deepcopy(records[0])))
        self.reject_receipt(lambda records: records[0].update(targetLabel="//private:unmatched"))
        self.reject_receipt(lambda records: records[0]["commandArgs"].append("changed"))
        self.reject_receipt(lambda records: records[0]["environmentVariables"].append({"name": "PATH", "value": "changed"}))
        self.reject_receipt(lambda records: records[0].update(environmentVariables=[{"name": "PATH", "value": "changed"}]))
        self.reject_receipt(lambda records: records[0].update(listedOutputs=["different-output"]))

    def test_failed_incomplete_or_malformed_status_rejected(self):
        for field, value in [("status", "SUCCESS"), ("status", "TIMEOUT"), ("exitCode", 1), ("exitCode", False), ("remotable", False), ("cacheHit", 0)]:
            with self.subTest(field=field, value=value):
                self.reject_receipt(lambda records: records[0].update({field: value}))
        for field in ("status", "exitCode", "cacheHit", "remotable", "digest"):
            self.reject_receipt(lambda records: records[0].pop(field))

    def test_exact_receipt_routing_and_no_duplicate_properties(self):
        self.reject_receipt(lambda records: records[0]["platform"]["properties"][0].update(value="wrong-closure"))
        self.reject_receipt(lambda records: records[0].update(platform={}))
        self.reject_receipt(lambda records: records[0]["platform"]["properties"].append({"name": "nix_closure", "value": CLOSURE}))

    def test_external_tool_actions_cannot_disappear_or_execute_locally(self):
        external = copy.deepcopy(self.graph["actions"][0])
        external["targetId"] = 6
        external["outputIds"] = [len(self.graph["artifacts"]) + 1]
        external["arguments"][-1] = "external-tool-output"
        self.graph["pathFragments"].append({"id": len(self.graph["pathFragments"]) + 1, "label": "external-tool-output"})
        self.graph["artifacts"].append({"id": external["outputIds"][0], "pathFragmentId": self.graph["pathFragments"][-1]["id"]})
        self.graph["targets"].append({"id": 6, "label": "@@translate-c+//:tool"})
        self.graph["actions"].append(external)
        self.graph["depSetOfFiles"][1]["directArtifactIds"].append(external["outputIds"][0])
        record = copy.deepcopy(self.receipts[0])
        record["targetLabel"] = "@@translate-c+//:tool"
        record["commandArgs"][-1] = "external-tool-output"
        record["listedOutputs"] = ["external-tool-output"]
        record["actualOutputs"][0]["path"] = "external-tool-output"
        self.receipts.append(record)
        next(item for item in self.receipts if item["targetLabel"] == "//clients/macos:archive")["inputs"].append(copy.deepcopy(record["actualOutputs"][0]))
        plan, summary = provenance.action_plan(self.graph, MANIFEST, TOOL_ROOT + "\n")
        self.assertEqual(summary["external_tool_actions"], 1)
        provenance.reconcile(plan, self.receipts, CLOSURE)
        self.reject_receipt(lambda records: records[-1].update(runner="linux-sandbox"))
        self.reject_receipt(lambda records: records.pop())

    def test_non_spawn_actions_are_counted_and_missing_spawn_args_fail(self):
        self.graph["actions"].append({"mnemonic": "FileWrite"})
        _, summary = provenance.action_plan(self.graph, MANIFEST, TOOL_ROOT + "\n")
        self.assertEqual(summary["non_spawn_actions"], 0)
        self.assertEqual(summary["unrequested_registered_actions"], 1)
        self.reject_graph(lambda graph: graph["actions"][0].pop("arguments"))
        self.reject_graph(lambda graph: graph["actions"][0].update(arguments=[]))

    def test_unrequested_auxiliary_spawns_and_output_conflicts_are_outside_scope(self):
        auxiliary = copy.deepcopy(self.graph["actions"][0])
        auxiliary["targetId"] = 6
        output_id = len(self.graph["artifacts"]) + 1
        fragment_id = len(self.graph["pathFragments"]) + 1
        self.graph["pathFragments"].append({"id": fragment_id, "label": "unused-output"})
        self.graph["artifacts"].append({"id": output_id, "pathFragmentId": fragment_id})
        auxiliary["outputIds"] = [output_id]
        auxiliary["arguments"] = ["/usr/bin/unrequested-tool"]
        self.graph["targets"].append({"id": 6, "label": "//:unrequested_docs"})
        self.graph["actions"].extend([auxiliary, copy.deepcopy(auxiliary)])
        plan, summary = provenance.action_plan(self.graph, MANIFEST, TOOL_ROOT + "\n")
        self.assertEqual(summary["registered_actions"], 7)
        self.assertEqual(summary["reachable_actions"], 5)
        self.assertEqual(summary["unrequested_registered_actions"], 2)
        self.assertEqual(summary["scope"], "archive_artifact_producer_dependencies")
        provenance.reconcile(plan, self.receipts, CLOSURE)
        self.graph["depSetOfFiles"][1]["directArtifactIds"].append(output_id)
        with self.assertRaises(ValueError):
            self.plan()

    def test_reachable_output_conflict_and_archive_root_ambiguity_rejected(self):
        conflicting = copy.deepcopy(self.graph["actions"][0])
        conflicting["arguments"].append("different-command")
        self.reject_graph(lambda graph: graph["actions"].append(conflicting))
        archive = next(action for action in self.graph["actions"] if self.graph["targets"][action["targetId"] - 1]["label"] == "//clients/macos:archive")
        ambiguous = copy.deepcopy(archive)
        ambiguous["arguments"].append("different-command")
        self.reject_graph(lambda graph: graph["actions"].append(ambiguous))

    def test_identical_action_registrations_collapse_without_duplicate_receipts(self):
        self.graph["actions"].extend(copy.deepcopy(self.graph["actions"]))
        plan, summary = provenance.action_plan(self.graph, MANIFEST, TOOL_ROOT + "\n")
        self.assertEqual(summary["registered_actions"], 10)
        self.assertEqual(summary["reachable_actions"], 5)
        self.assertEqual(summary["reachable_registered_actions"], 10)
        self.assertEqual(summary["duplicate_registered_actions"], 5)
        self.assertEqual(summary["unrequested_registered_actions"], 0)
        provenance.reconcile(plan, self.receipts, CLOSURE)

    def test_platform_complete_archive_and_declared_absolute_tools(self):
        self.reject_graph(lambda graph: graph["actions"][0].update(executionPlatform="@@evil_omux_nix//:execution_platform/extra"))
        self.reject_graph(lambda graph: graph["actions"].pop())
        self.reject_graph(lambda graph: graph["actions"][0]["arguments"].append("/nix/store/" + "2" * 32 + "-undeclared/bin/tool"))
        self.reject_graph(lambda graph: graph["actions"][0]["environmentVariables"].append({"key": "SDKROOT", "value": "/nix/store/" + "2" * 32 + "-undeclared/sdk"}))
        self.reject_graph(lambda graph: graph["actions"][0]["arguments"].__setitem__(0, "/usr/bin/tool"))
        self.reject_graph(lambda graph: graph["actions"][0]["arguments"].__setitem__(0, "undeclared-tool"))
        self.reject_graph(lambda graph: graph["actions"][0]["environmentVariables"][0].update(value="/usr/bin:/bin"))
        self.reject_graph(lambda graph: graph["actions"][0]["arguments"].__setitem__(0, TOOL_ROOT + "/../../bin/sh"))
        self.reject_graph(lambda graph: graph["actions"][0]["arguments"].__setitem__(0, TOOL_ROOT + "/bin/undeclared"))
        self.reject_graph(lambda graph: graph["actions"][0].update(executionPlatform="@@evil_omux_nix//:execution_platform"))

    def test_manifest_bound_package_aliases_require_declared_files_and_digests(self):
        alias = "external/+omux_nix_repository+omux_nix/packages/declared/out/bin/tool"
        graph, receipts = fixture(alias)
        manifest = dict(MANIFEST, packages={"declared": {"out": TOOL_ROOT}})
        plan, _ = provenance.action_plan(graph, manifest, TOOL_ROOT + "\n")
        provenance.reconcile(plan, receipts, CLOSURE, fresh=True)
        for mutation in [lambda records: records[0]["inputs"].clear(), lambda records: records[0]["inputs"][0].pop("digest"), lambda records: records[0]["inputs"][0].update(path=TOOL_PATH)]:
            changed = copy.deepcopy(receipts)
            mutation(changed)
            with self.assertRaises(ValueError):
                provenance.reconcile(plan, changed, CLOSURE)
        with self.assertRaises(ValueError):
            provenance.action_plan(graph, MANIFEST, TOOL_ROOT + "\n")
        foreign = "/nix/store/" + "2" * 32 + "-foreign"
        with self.assertRaises(ValueError):
            provenance.action_plan(graph, dict(MANIFEST, packages={"declared": {"out": foreign}}), TOOL_ROOT + "\n")
        with self.assertRaises(ValueError):
            provenance.action_plan(graph, dict(MANIFEST, packages={"declared": {"out": foreign}}), TOOL_ROOT + "\n" + foreign + "\n")

    def test_authorized_root_does_not_authorize_undeclared_file_or_directory(self):
        self.reject_graph(lambda graph: graph["actions"][0]["arguments"].append(TOOL_ROOT + "/undeclared/file"))
        self.reject_graph(lambda graph: graph["actions"][0]["environmentVariables"].append({"key": "SDKROOT", "value": TOOL_ROOT + "/undeclared"}))
        self.graph["actions"][0]["arguments"].append(TOOL_ROOT + "/bin")
        self.plan()

    def test_output_receipts_belong_to_the_matching_action(self):
        self.reject_receipt(lambda records: records[0]["actualOutputs"].append(copy.deepcopy(records[1]["actualOutputs"][0])))
        self.reject_receipt(lambda records: records[0]["actualOutputs"].append(copy.deepcopy(records[0]["actualOutputs"][0])))
        self.reject_graph(lambda graph: graph["actions"][1].update(outputIds=graph["actions"][0]["outputIds"]))
        self.reject_receipt(lambda records: records[0].update(actualOutputs=[]))
        self.reject_receipt(lambda records: records[0]["actualOutputs"][0].pop("digest"))

    def test_complete_regular_input_identity_and_content_metadata(self):
        self.reject_receipt(lambda records: records[0]["inputs"].append(copy.deepcopy(records[0]["inputs"][0])))
        self.reject_receipt(lambda records: records[0]["inputs"].append({"path": "src/foreign.zig", "digest": copy.deepcopy(records[0]["inputs"][0]["digest"])}))
        self.reject_receipt(lambda records: records[0]["inputs"][0].pop("digest"))
        self.reject_receipt(lambda records: records[0]["inputs"][0].update(symlinkTargetPath="unattested"))
        source_fragment = len(self.graph["pathFragments"]) + 1
        source_artifact = len(self.graph["artifacts"]) + 1
        self.graph["pathFragments"].append({"id": source_fragment, "label": "declared-source.zig"})
        self.graph["artifacts"].append({"id": source_artifact, "pathFragmentId": source_fragment})
        self.graph["depSetOfFiles"][0]["directArtifactIds"].append(source_artifact)
        # Matching the executable and one store root does not account for source.
        self.reject_receipt(lambda records: None)
        for record in self.receipts:
            record["inputs"].append({"path": "declared-source.zig", "digest": copy.deepcopy(record["inputs"][0]["digest"])})
        provenance.reconcile(self.plan(), self.receipts, CLOSURE)

    def test_tree_inputs_allow_only_owned_descendants(self):
        fragment = len(self.graph["pathFragments"]) + 1
        artifact = len(self.graph["artifacts"]) + 1
        self.graph["pathFragments"].append({"id": fragment, "label": "declared-tree"})
        self.graph["artifacts"].append({"id": artifact, "pathFragmentId": fragment, "isTreeArtifact": True})
        self.graph["depSetOfFiles"][0]["directArtifactIds"].append(artifact)
        for record in self.receipts:
            record["inputs"].append({"path": "declared-tree/child.zig", "digest": copy.deepcopy(record["inputs"][0]["digest"])})
        provenance.reconcile(self.plan(), self.receipts, CLOSURE)
        self.reject_receipt(lambda records: records[0]["inputs"][-1].update(path="declared-tree-prefix/foreign.zig"))
        self.reject_receipt(lambda records: records[0]["inputs"][-1].update(path="declared-tree/../foreign.zig"))

    def test_unresolved_symlink_inputs_require_analyzed_immutable_target(self):
        fragment = len(self.graph["pathFragments"]) + 1
        artifact = len(self.graph["artifacts"]) + 1
        self.graph["pathFragments"].append({"id": fragment, "label": "declared-symlink"})
        self.graph["artifacts"].append({"id": artifact, "pathFragmentId": fragment})
        self.graph["depSetOfFiles"][0]["directArtifactIds"].append(artifact)
        self.graph["actions"].append({"mnemonic": "UnresolvedSymlink", "outputIds": [artifact], "unresolvedSymlinkTarget": TOOL_ROOT + "/bin/tool"})
        for record in self.receipts:
            record["inputs"].append({"path": "declared-symlink", "symlinkTargetPath": TOOL_ROOT + "/bin/tool"})
        provenance.reconcile(self.plan(), self.receipts, CLOSURE)
        self.reject_receipt(lambda records: records[0]["inputs"][-1].update(symlinkTargetPath="/etc/host"))
        self.reject_graph(lambda graph: graph["actions"][-1].update(unresolvedSymlinkTarget="/etc/host"))

    def test_only_declared_tree_outputs_allow_child_receipts(self):
        first = self.graph["actions"][0]["outputIds"][0]
        self.graph["artifacts"][first - 1]["isTreeArtifact"] = True
        base = self.receipts[0]["listedOutputs"][0]
        self.receipts[0]["actualOutputs"][0]["path"] = base + "/child"
        archive = next(item for item in self.receipts if item["targetLabel"] == "//clients/macos:archive")
        archive["inputs"] = [copy.deepcopy(self.receipts[0]["actualOutputs"][0]) if item["path"] == base else item for item in archive["inputs"]]
        metadata, _ = provenance.reconcile(self.plan(), self.receipts, CLOSURE)
        self.assertFalse(metadata["tree_output_materialization_verified"])
        self.reject_receipt(lambda records: records[0]["actualOutputs"][0].update(path=base + "-prefix/child"))

    def test_virtual_parameter_inputs_are_explicitly_accounted_for(self):
        self.graph["actions"][0]["paramFiles"] = [{"execPath": "declared.params", "arguments": ["--synthetic"]}]
        self.reject_receipt(lambda records: None)
        self.receipts[0]["inputs"].append({"path": "declared.params", "digest": copy.deepcopy(self.receipts[0]["inputs"][0]["digest"])})
        provenance.reconcile(self.plan(), self.receipts, CLOSURE)

    def test_generated_tree_input_enumeration_matches_producer_receipt(self):
        producer_artifact = self.graph["actions"][0]["outputIds"][0]
        self.graph["artifacts"][producer_artifact - 1]["isTreeArtifact"] = True
        base = self.receipts[0]["listedOutputs"][0]
        self.receipts[0]["actualOutputs"][0]["path"] = base + "/child"
        self.graph["depSetOfFiles"].append({"id": 3, "directArtifactIds": [producer_artifact], "transitiveDepSetIds": [1]})
        self.graph["actions"][1]["inputDepSetIds"] = [3]
        self.reject_receipt(lambda records: None)
        self.receipts[1]["inputs"].append(copy.deepcopy(self.receipts[0]["actualOutputs"][0]))
        archive = next(item for item in self.receipts if item["targetLabel"] == "//clients/macos:archive")
        archive["inputs"] = [copy.deepcopy(self.receipts[0]["actualOutputs"][0]) if item["path"] == base else item for item in archive["inputs"]]
        provenance.reconcile(self.plan(), self.receipts, CLOSURE)
        self.reject_receipt(lambda records: records[1]["inputs"][-1].update(path=base + "/different-child"))
        self.reject_receipt(lambda records: records[1]["inputs"][-1]["digest"].update(hash="f" * 64))

    def test_coordinator_tools_rejected_in_analysis_and_receipts(self):
        self.reject_graph(lambda graph: next(item for item in graph["pathFragments"] if item["label"] == "+omux_nix_repository+omux_nix").update(label="omux_host+"))
        self.reject_receipt(lambda records: records[0]["inputs"].append({"path": "external/omux_host+/packages/python/bin/python"}))
        self.reject_receipt(lambda records: records[0].update(inputs=[]))

    def test_duplicate_ids_cycles_missing_refs_and_traversal_rejected(self):
        self.reject_graph(lambda graph: graph["targets"].append(copy.deepcopy(graph["targets"][0])))
        self.reject_graph(lambda graph: graph["pathFragments"][0].update(parentId=graph["pathFragments"][0]["id"]))
        self.reject_graph(lambda graph: graph["depSetOfFiles"][0].update(transitiveDepSetIds=[1]))
        self.reject_graph(lambda graph: graph["actions"][0].update(inputDepSetIds=[999]))
        self.reject_graph(lambda graph: graph["pathFragments"][0].update(label=".."))
        self.reject_graph(lambda graph: graph["pathFragments"][0].update(label="external/other"))

    def test_manifest_system_sdk_and_duplicate_store_roots_rejected(self):
        for manifest in [{"system": "x86_64-linux", "apple": {"sdk_version": "14.4"}}, {"system": "aarch64-darwin", "apple": {"sdk_version": "15"}}, {"system": "aarch64-darwin", "apple": None}]:
            with self.assertRaises(ValueError):
                provenance.action_plan(self.graph, manifest, TOOL_ROOT + "\n")
        for roots in ["", TOOL_ROOT + "\n" + TOOL_ROOT, "not-a-store-path", TOOL_ROOT + "/bin"]:
            with self.assertRaises(ValueError):
                provenance.action_plan(self.graph, MANIFEST, roots)

    def test_digest_algorithm_hash_and_size_are_fail_closed(self):
        for field, value in [("hashFunctionName", "MD5"), ("hash", "z" * 64), ("sizeBytes", "-1"), ("sizeBytes", True), ("sizeBytes", 2**63)]:
            self.reject_receipt(lambda records: records[0]["digest"].update({field: value}))

    def test_concatenated_pretty_json_not_array_and_duplicate_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private.json"
            path.write_text("\n".join(json.dumps(record, indent=2) for record in self.receipts))
            self.assertEqual(provenance.load_receipts(path), self.receipts)
            for payload in [json.dumps(self.receipts), '{"status":"", "status":"private"}', '{"x":NaN}', '{"x":1} trailing', '{"x":']:
                path.write_text(payload)
                with self.assertRaises(ValueError):
                    provenance.load_receipts(path)

    def test_total_bytes_receipt_count_and_graph_depth_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private.json"
            path.write_text("123456789")
            with patch.object(provenance, "LIMIT", 8), self.assertRaises(ValueError):
                provenance.read(path)
            path.write_text("{}{}")
            with patch.object(provenance, "MAX_ACTIONS", 1), self.assertRaises(ValueError):
                provenance.load_receipts(path)
        with patch.object(provenance, "MAX_DEPTH", 1), self.assertRaises(ValueError):
            self.plan()

    def test_artifact_hash_bytes_bind_receipt_without_install_claim(self):
        plan = self.plan()
        _, outputs = provenance.reconcile(plan, self.receipts, CLOSURE, fresh=True)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact"
            path.write_bytes(b"artifact")
            summary = provenance.artifact_summary(path, self.receipts[0]["listedOutputs"][0], plan, outputs)
            self.assertEqual(summary["artifact_bytes"], 8)
            self.assertTrue(summary["artifact_verified"])
            path.write_bytes(b"different")
            with self.assertRaises(ValueError):
                provenance.artifact_summary(path, self.receipts[0]["listedOutputs"][0], plan, outputs)
            with self.assertRaises(ValueError):
                provenance.artifact_summary(path, "undeclared", plan, outputs)

    def test_cli_prints_only_metadata_and_keeps_installed_proof_false(self):
        # Deliberately bogus values verify that summaries cannot leak inputs.
        self.graph["actions"][0]["arguments"].append("private@example.invalid?credential=PRIVATE-SENTINEL")
        self.receipts[0]["commandArgs"].append("private@example.invalid?credential=PRIVATE-SENTINEL")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "graph").write_text(json.dumps(self.graph))
            (root / "manifest").write_text(json.dumps(MANIFEST))
            (root / "roots").write_text(TOOL_ROOT + "\n")
            (root / "receipts").write_text("".join(json.dumps(record) for record in self.receipts))
            arguments = ["provenance", "--target-root", "//clients/macos:archive", "--aquery", str(root / "graph"), "--manifest", str(root / "manifest"), "--store-paths", str(root / "roots"), "--closure", CLOSURE, "--execution-log", str(root / "receipts"), "--fresh"]
            output = io.StringIO()
            with patch("sys.argv", arguments), patch("sys.stdout", output):
                provenance.main()
            value = json.loads(output.getvalue())
            self.assertEqual(value["phase"], "execution_reconciled")
            self.assertFalse(value["installed_proof"])
            self.assertTrue(value["receipt_platform_properties_match"])
            self.assertFalse(value["worker_routing_verified"])
            for forbidden in ["PRIVATE-SENTINEL", "private@example", "commandArgs", "environmentVariables", "//clients", str(root), TOOL_ROOT]:
                self.assertNotIn(forbidden, output.getvalue())

    def test_cli_internal_failures_never_emit_exception_text_or_paths(self):
        for error in [FileNotFoundError("PRIVATE-SENTINEL/path?credential=private"), KeyError("PRIVATE-SENTINEL"), TypeError("PRIVATE-SENTINEL")]:
            with self.subTest(error=type(error).__name__), patch.object(provenance, "main", side_effect=error):
                with self.assertRaises(SystemExit) as rejected:
                    provenance.run_cli()
                message = str(rejected.exception)
                self.assertRegex(message, r"^Darwin provenance reconciliation rejected \((?:io|schema-key|schema-type); source line [0-9]+\)$")
                for forbidden in ["PRIVATE-SENTINEL", "credential", "path", "Traceback", "environment", "command"]:
                    self.assertNotIn(forbidden, message)


if __name__ == "__main__":
    unittest.main()
