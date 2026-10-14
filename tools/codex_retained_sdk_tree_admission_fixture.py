"""Model-only declared public files; never genuine execution qualification.

Consumes the existing real tiny carrier/extraction fixture. Namespace and
original SOURCE selection are explicit synthetic seams; proof readers,
policy grammar, XML, aliases, hashes, full carrier/tree scans and opaque owner
factories remain the production functions. No owner or finished flag is forged.
This file is declared only by model targets, never materializer/SOURCE DATA.
"""
from contextlib import contextmanager, ExitStack
import copy
import hashlib
import os
from pathlib import Path
import re
import shutil
import time
from unittest.mock import patch

import codex_native_sdk_carrier as core
import codex_native_carrier_metadata as metadata
import codex_native_file_writer_model_source as family
import codex_original_sdk_inputs as original
import codex_retained_sdk_tree_inputs as admission
import guard_native_acquisition_inputs_reserved as seal_guard
import guard_native_sdk_tree_reserved as tree_guard

UUID_SEAL = "11111111-1111-1111-1111-111111111111"
UUID_TREE = "22222222-2222-2222-2222-222222222222"
UUID_SOURCE = "33333333-3333-3333-3333-333333333333"
PRODUCTION_EPOCH = "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/" + UUID_TREE


def _write(path, raw, mode=0o444):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(raw)
    path.chmod(mode)
    return {"path": str(path), "sha256": core.sha(raw), "bytes": len(raw)}


def _alias(path, target):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.symlink_to(target)


def _resident():
    # Pure guard schema stimulus, not a sampled kernel admission/cgroup claim.
    return {"scope": "sampled-fixed-default-cgroup-kernel-reservation-v1",
        "kernel_bounds": {"memory.max": "1048576", "memory.swap.max": "0",
            "pids.max": "1", "cpu.max": "1000 100000"}, "observations": 1,
        "initial_direct_processes_retained": True, "initial_direct_process_count": 1,
        "outer_pid_namespace_matched": True, "hierarchical_caps": True,
        "descendant_process_inventory": False, "installation_qualified": False,
        "health_observed": False, "custody_observed": False,
        "resident_signalled": False, "whole_host_reservation": False}


def _outer(epoch, target, profile, entry, until, output_base, graph, commit):
    return {"id": epoch.name, "unit": "omux-execution-" + epoch.name + ".service",
        "manager": "system", "profile": profile, "exit": 0, "workload_exit": 0,
        "controller_failure": None, "descendants_empty": True,
        "cleanup": {"state": "empty", "ownership": "verified", "readback_attempts": 2},
        "source_dirty": "false", "source_commit": commit, "graph_sha256": graph,
        "verb": "test", "targets": [target], "epoch_start_ns": entry,
        "output_base": str(output_base),
        "observed_properties": {"RuntimeMaxUSec": "19min 30s", "MemoryMax": "4026531840",
            "MemorySwapMax": "0", "TasksMax": "480", "PrivateNetwork": "yes",
            "KillMode": "control-group", "SendSIGKILL": "yes", "OOMPolicy": "kill",
            "RemainAfterExit": "yes", "CPUQuotaPerSecUSec": "1.9s"}}


def _evidence(epoch, target, entry, log):
    files, paths = [], {}
    for source, raw in (("test.log", log), ("test.xml",
            b'<testsuites><testsuite tests="1" failures="0" errors="0" skipped="0"/></testsuites>')):
        filename = hashlib.sha256((target + "\0k8-fastbuild\0" + source).encode()).hexdigest() + ".evidence"
        pin = _write(epoch / "test-evidence" / filename, raw, 0o600)
        paths["test_log" if source == "test.log" else "test_xml"] = pin
        files.append({"source": source, "state": "copied", "file": filename,
            "sha256": pin["sha256"], "bytes": pin["bytes"]})
    files += [{"source": "test.outputs_manifest/MANIFEST", "state": "missing", "bytes": 0},
        {"source": "test.outputs_manifest/ANNOTATIONS", "state": "missing", "bytes": 0}]
    value = {"schema": 1, "bazel_exit": 0, "epoch_start_ns": entry, "targets": [target],
        "results": [{"target": target, "configuration": "k8-fastbuild", "state": "observed", "files": files}]}
    pin = _write(epoch / "test-evidence.json", core.encoded(value), 0o600)
    paths["test_evidence"] = pin
    return paths, {"state": "preserved", "sha256": pin["sha256"]}


class DeclaredTreeFixture:
    """Actual synthetic files and scoped lexical/ancestry seams; no capability."""
    def __init__(self, tiny):
        self.tiny = tiny
        self.root = Path(tiny.root) / "declared-tree-admission-model"
        self.runfiles = self.root / "runfiles"
        self.external = self.root / "external"
        self.seal_epoch = self.root / UUID_SEAL
        self.tree_epoch = self.root / UUID_TREE
        self.source_epoch = self.root / UUID_SOURCE
        self.entry = time.monotonic_ns()
        self.until = self.entry + 1200 * 10**9
        self.commit, self.graph = "a" * 40, "b" * 64
        self.context = {"MODE": admission.PROFILE, "ENTRY_NS": str(self.entry),
            "DEADLINE_NS": str(self.until), "EPOCH": str(self.tree_epoch),
            "SOURCE_COMMIT": self.commit, "GRAPH_SHA256": self.graph, "BOOT_ID": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}
        self.domain_raw = core.encoded({"schema_version": 1, "kind": "omux-sdk-tree-current-clock-domain-v1",
            "clock": "linux-CLOCK_MONOTONIC", "boot_id": self.context["BOOT_ID"]})
        self.source_context = {**{key: value for key, value in self.context.items() if key != "BOOT_ID"}, "MODE": original.MODE, "EPOCH": str(self.source_epoch)}
        self.rows = [["_main", metadata.REPOSITORY, metadata.REPOSITORY],
            ["_main", metadata.PROOF_REPOSITORY, metadata.PROOF_REPOSITORY],
            ["_main", admission.PROOF_REPOSITORY, admission.PROOF_REPOSITORY]]
        self.stack = ExitStack()

    def __enter__(self):
        try:
            self.root.mkdir(mode=0o700)
            self.runfiles.mkdir(mode=0o700)
            self.external.mkdir(mode=0o700)
            for path in (self.seal_epoch, self.tree_epoch, self.source_epoch): path.mkdir(mode=0o700)
            real_creator, real_source = admission._context, original.validate_context
            def creator_namespace(value):
                real_creator({**value, "EPOCH": PRODUCTION_EPOCH})
                if value["EPOCH"] != str(self.tree_epoch): raise ValueError("synthetic creator namespace mismatch")
                return int(value["ENTRY_NS"]), int(value["DEADLINE_NS"])
            def source_namespace(value):
                real_source({**value, "EPOCH": PRODUCTION_EPOCH})
                if value["EPOCH"] != str(self.source_epoch): raise ValueError("synthetic SOURCE namespace mismatch")
                return dict(value)
            self.stack.enter_context(patch.object(admission, "_context", side_effect=creator_namespace))
            self.stack.enter_context(patch.object(original, "validate_context", side_effect=source_namespace))
            self.stack.enter_context(patch.object(metadata.protocol, "PRODUCER_SCOPE",
                re.compile(re.escape(str(self.seal_epoch / "receipt.json")) + r"\Z")))
            # Original SOURCE/build ancestry is explicitly outside this tiny model.
            self.original_selection = {"kind": "synthetic-original-source-selection", "source_receipt_sha256": "1" * 64}
            self.stack.enter_context(patch.object(metadata.binding, "selected_document",
                side_effect=lambda *unused: copy.deepcopy(self.original_selection)))
            self.stack.enter_context(patch.object(metadata.legacy, "configure_selection", return_value=None))
            self.stack.enter_context(patch.object(metadata.legacy, "EXPORT_SHA", self.tiny.origin_pin))
            self.stack.enter_context(patch.object(original, "ORIGIN_PIN", self.tiny.origin_pin))
            self.stack.enter_context(patch.object(original, "ORIGIN", self.tiny.model.origin))
            self.stack.enter_context(patch.object(metadata.binding.ninth.parent, "ROOT", self.runfiles / "_main"))
            self.env = {"OMUX_NATIVE_SDK_TREE_" + key: value for key, value in self.context.items()}
            self.env["OMUX_NATIVE_SDK_TREE_CURRENT_BOOT_ID"] = self.context["BOOT_ID"]
            self.env.update({"RUNFILES_DIR": str(self.runfiles), "TEST_SRCDIR": str(self.runfiles)})
            self.stack.enter_context(patch.dict(os.environ, self.env))
            self._original_roles()
            # These bytes belong to the explicitly synthetic SOURCE-ancestry
            # seam, not a genuine selected original SOURCE or SDK capability.
            self.ancestry_paths = [self.runfiles / "_main" / metadata.binding.CONFIG,
                self.runfiles / "_main" / metadata.binding.N9_WITNESS]
            for path in self.ancestry_paths:
                _write(path, core.encoded({"kind": "synthetic-source-ancestry-control",
                    "role": path.name, "source_qualified": False}))
            self.stack.enter_context(patch.object(metadata.binding, "N9_WITNESS_SHA",
                core.sha(self.ancestry_paths[1].read_bytes())))
            self._descriptor()
            self.mapping_path = self.runfiles / "_repo_mapping"
            _write(self.mapping_path, ("\n".join(",".join(row) for row in self.rows) + "\n").encode())
            return self
        except BaseException:
            self.stack.close()
            raise

    def _original_roles(self):
        report_path = self.seal_epoch / "output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools"
        report_path /= "codex_native_sdk_carrier_seal_producer/test.outputs/sdk-private/native-sdk-carrier-producer.json"
        self.carrier_root = report_path.parent / "sdk-carrier"
        shutil.copytree(self.tiny.carrier_root, self.carrier_root, symlinks=True)
        files = [{"name": name, "sha256": core.sha((self.carrier_root / name).read_bytes()),
            "size": (self.carrier_root / name).stat().st_size} for name in core.FILES]
        program = {"kind": metadata.PRODUCER_KIND, "producer": metadata.SEAL_TARGET,
            "carrier_receipt_sha256": self.tiny.carrier_pin, "origin_receipt_sha256": self.tiny.origin_pin,
            "producer_context": {"mode": metadata.SEAL_PROFILE, "epoch": str(self.seal_epoch),
                "source_commit": self.commit, "graph_sha256": self.graph,
                "entry_monotonic_ns": self.entry, "deadline_monotonic_ns": self.until,
                "work_cutoff_monotonic_ns": self.entry + 1170 * 10**9},
            "files": files, "all_four_leaves_rechecked": True, "sdk_execution_qualified": False,
            "metadata_qualified": False, "compiler_qualified": False, "runtime_qualified": False}
        paths, evidence = _evidence(self.seal_epoch, metadata.SEAL_TARGET, self.entry, core.encoded(program) + b"\n")
        paths["program_report"] = _write(report_path, core.encoded(program), 0o555)
        outer = _outer(self.seal_epoch, metadata.SEAL_TARGET, metadata.SEAL_PROFILE,
            self.entry, self.until, self.seal_epoch / "output-base", self.graph, self.commit)
        outer.update(test_evidence=evidence, cache_reuse_requested=False, cache_policy=None, cache_key=None,
            native_acquisition_inputs_reservation=seal_guard.projection(
                metadata.SEAL_PROFILE, self.entry, self.until, True, _resident()))
        paths["outer_receipt"] = _write(self.seal_epoch / "receipt.json", core.encoded(outer), 0o600)
        selected = {"original_selection": self.original_selection,
            "carrier": {"receipt_sha256": self.tiny.carrier_pin},
            "qualification": {"producer": {"receipt": paths["outer_receipt"]["path"],
                "sha256": paths["outer_receipt"]["sha256"], "source_commit": self.commit, "graph_sha256": self.graph},
                "report": {"path": str(report_path), "sha256": paths["program_report"]["sha256"]}}}
        self.original_paths = paths
        self.original_config_path = self.runfiles / "_main" / metadata.CONFIG
        _write(self.original_config_path, core.encoded({"schema_version": 2, "kind": metadata.KIND,
            "status": "selected-qualified-carrier-for-metadata", "selection": selected}), 0o644)
        physical = self.external / metadata.REPOSITORY
        declaration = {"carrier_root": str(self.carrier_root),
            "digests": {row["name"]: row["sha256"] for row in files}}
        self.original_declaration_path = physical / "selection.json"
        _write(self.original_declaration_path, core.encoded(declaration))
        _alias(self.runfiles / metadata.REPOSITORY / "selection.json", physical / "selection.json")
        for name in core.FILES: _alias(self.runfiles / metadata.REPOSITORY / "carrier" / name, self.carrier_root / name)
        proof_root = self.external / metadata.PROOF_REPOSITORY
        proof_map = {"kind": metadata.PROOF_KIND, "proofs": {role: {
            "path": paths[role]["path"], "sha256": paths[role]["sha256"], "alias": alias}
            for role, alias in metadata.PROOF_ALIASES.items()}}
        self.original_proof_map = proof_root / "proof-inputs.json"
        _write(self.original_proof_map, core.encoded(proof_map))
        _alias(self.runfiles / metadata.PROOF_REPOSITORY / "proof-inputs.json", self.original_proof_map)
        for role, alias in metadata.PROOF_ALIASES.items():
            _alias(self.runfiles / metadata.PROOF_REPOSITORY / alias, Path(paths[role]["path"]))

    def _descriptor(self):
        key = core.sha(b"synthetic two-cohort dependency namespace, not a real live lock")
        self.key, self.namespace = key, "cache-v2-sdk-tree-" + key
        self.output_base = self.root / self.namespace / "output-base"
        self.output = self.output_base / "execroot/_main/bazel-out/k8-fastbuild/bin" / tree_guard.LAYOUT
        self.output.mkdir(parents=True, mode=0o700)
        self.context_path = self.output / "creator-context.json"
        _write(self.context_path, core.encoded(self.context) + b"\n")
        self.domain_path = self.output / "current-clock-domain.json"
        _write(self.domain_path, self.domain_raw)
        code, tool = self.root / "public/model_materializer.py", self.root / "public/locked_model_tool"
        _write(code, b"# synthetic public code input\n")
        _write(tool, b"synthetic locked tool closure input\n", 0o555)
        proofs = [{"logical_path": "proof/" + role, "execution_path": row["path"]}
            for role, row in sorted(self.original_paths.items())]
        proofs += [{"logical_path": "proof/config", "execution_path": str(self.original_config_path)},
            {"logical_path": "proof/mapping", "execution_path": str(self.original_proof_map)},
            {"logical_path": "proof/carrier-selection", "execution_path": str(self.original_declaration_path)}]
        proofs += [{"logical_path": "_main/" + name, "execution_path": str(path)}
            for name, path in zip((metadata.binding.CONFIG, metadata.binding.N9_WITNESS), self.ancestry_paths)]
        for path, target in (("code/model_materializer.py", code), ("tools/locked_model_tool", tool)):
            _alias(self.runfiles / path, target)
        for row in proofs:
            alias, physical = self.runfiles / row["logical_path"], Path(row["execution_path"])
            if alias != physical: _alias(alias, physical)
        self.descriptor = {"schema_version": 1, "kind": "omux-retained-public-sdk-tree-declared-action-inputs-v1",
            "code": [{"logical_path": "code/model_materializer.py", "execution_path": str(code)}],
            "tools": [{"logical_path": "tools/locked_model_tool", "execution_path": str(tool)}],
            "proofs": proofs, "carrier": [{"name": name, "logical_path": metadata.REPOSITORY + "/carrier/" + name,
                "execution_path": str(self.carrier_root / name)} for name in core.FILES]}
        self.descriptor_path = self.output / "declared-inputs.json"
        _write(self.descriptor_path, core.encoded(self.descriptor))
        self.qualifier_output = self.root / "qualifier-output"
        self.qualifier_output.mkdir(mode=0o700)
        self.declare_artifact()

    def materialize_args(self):
        from types import SimpleNamespace
        return SimpleNamespace(tree_output=str(self.output / "tree"), inventory_output=str(self.output / "inventory.json"),
            receipt_output=str(self.output / "receipt.json"), recipe_output=str(self.output / "recipe.json"),
            creator_context=str(self.context_path), input_descriptor=str(self.descriptor_path), clock_domain=str(self.domain_path))

    def qualifier_args(self):
        from types import SimpleNamespace
        return SimpleNamespace(data=str(self.runfiles / admission.DATA),
            input_descriptor=str(self.runfiles / admission.BASE / "declared-inputs.json"),
            clock_domain=str(self.runfiles / admission.BASE / "current-clock-domain.json"))

    def declare_artifact(self):
        layout = {"kind": "omux-retained-public-sdk-tree-declared-data-v1", "recipe": admission.BASE + "/recipe.json",
            "creator_context": admission.BASE + "/creator-context.json", "artifact": {"root": admission.BASE + "/tree",
                "receipt": admission.BASE + "/receipt.json", "inventory": admission.BASE + "/inventory.json"}}
        _write(self.runfiles / admission.DATA, core.encoded(layout))
        for name in ("creator-context.json", "inventory.json", "receipt.json", "recipe.json", "tree", "declared-inputs.json", "current-clock-domain.json"):
            _alias(self.runfiles / admission.BASE / name, self.output / name)

    def publish_tree(self):
        """Model-only immutable epoch copies and synthetic 0/0 collector shape.

        Call after the real tiny materializer/qualifier returned. These files
        exercise provenance joins; they never select a real SDK/execute policy.
        """
        names = ("creator-context.json", "inventory.json", "receipt.json", "recipe.json")
        copies, ledger = {}, []
        for name in names:
            pin = _write(self.tree_epoch / "sdk-tree-created" / name, (self.output / name).read_bytes())
            copies[name] = pin
            ledger.append({"name": name, **pin})
        program = core.decode((self.output / "receipt.json").read_bytes())
        materialization = {key: program["materialization"][key] for key in ("recipe_sha256", "action_inputs_sha256")}
        origin = {"schema_version": 1, "kind": "omux-retained-sdk-tree-artifact-origin-v1", "family": tree_guard.FAMILY,
            "checkout": str(self.root), "namespace": self.namespace, "key": self.key, "output_base": str(self.output_base),
            "creator_run_id": self.tree_epoch.name, "creator_source_commit": self.commit, "creator_graph_sha256": self.graph,
            "creator_context": self.context, "materialization": materialization,
            "artifact_layout": tree_guard.LAYOUT, "created_metadata": ledger,
            "sdk_execution_qualified": False, "source_qualified": False, "runtime_qualified": False}
        paths, evidence = _evidence(self.tree_epoch, admission.TARGET, self.entry,
            b"retained-sdk-tree: receipt-sha256=" + copies["receipt.json"]["sha256"].encode() + b"\n")
        outer = _outer(self.tree_epoch, admission.TARGET, admission.PROFILE, self.entry, self.until,
            self.output_base, self.graph, self.commit)
        outer.update(test_evidence=evidence, cache_key=self.key, cache_policy=2, cache_reuse_requested=True,
            native_sdk_tree_reservation=tree_guard.projection(admission.PROFILE, self.entry, self.until, True, _resident()),
            native_sdk_tree_terminal_publication=tree_guard.publication_record(self.entry, self.until),
            native_sdk_tree_artifact_origin=origin,
            native_sdk_tree_dependency_lease={"kind": "omux-retained-sdk-tree-dependency-lease-v1",
                "family": tree_guard.FAMILY, "key": self.key, "namespace": self.namespace, "checkout": str(self.root),
                "output_base": str(self.output_base), "run_id": self.tree_epoch.name, "profile": admission.PROFILE,
                "source_commit": self.commit, "graph_sha256": self.graph,
                "entry_monotonic_ns": self.entry, "deadline_monotonic_ns": self.until,
                "sdk_execution_qualified": False, "source_qualified": False, "runtime_qualified": False})
        paths["outer_receipt"] = _write(self.tree_epoch / "receipt.json", core.encoded(outer), 0o600)
        confirmation_raw = core.encoded(tree_guard.qualification_record(outer,
            paths["outer_receipt"]["sha256"], paths["outer_receipt"]["bytes"], time.monotonic_ns(),
            core.identity(os.stat(paths["outer_receipt"]["path"], follow_symlinks=False))))
        paths["qualification_confirmation"] = _write(self.tree_epoch / "sdk-tree-qualified.json", confirmation_raw)
        for role, name in (("program_receipt", "receipt.json"), ("selected_inventory", "inventory.json"),
                ("selected_recipe", "recipe.json"), ("selected_creator_context", "creator-context.json")):
            paths[role] = copies[name]
        selector = {"schema_version": 1, "kind": admission.SELECTION_KIND,
            "status": "SELECTED-SUCCESSFUL-CREATOR-CONTENT-ONLY", "selection": {
                "creator_context": self.context, "producer": {"receipt": paths["outer_receipt"]["path"],
                    "sha256": paths["outer_receipt"]["sha256"], "source_commit": self.commit, "graph_sha256": self.graph},
                "receipt": copies["receipt.json"], "inventory": copies["inventory.json"], "materialization": materialization,
                "confirmation": paths["qualification_confirmation"]}}
        _write(self.runfiles / admission.CONFIG, core.encoded(selector), 0o644)
        repository = self.external / admission.PROOF_REPOSITORY
        mapping = {"kind": admission.PROOF_KIND, "proofs": {role: {**paths[role], "alias": alias}
            for role, alias in admission.ALIASES.items()}}
        _write(repository / "sdk-tree-proof-inputs.json", core.encoded(mapping))
        _alias(self.runfiles / admission.PROOF_REPOSITORY / "sdk-tree-proof-inputs.json", repository / "sdk-tree-proof-inputs.json")
        for role, alias in admission.ALIASES.items():
            _alias(self.runfiles / admission.PROOF_REPOSITORY / alias, Path(paths[role]["path"]))
        self.tree_paths, self.selector = paths, selector

    def refresh_confirmation(self):
        """Coherently rebuild synthetic confirmation after a model-only mutation.

        No parent observer/execution/selector authority is established by this
        helper. Actual held receipt bytes/current witness feed the pure schema.
        """
        outer_path = self.tree_epoch / "receipt.json"
        raw = outer_path.read_bytes()
        outer = core.decode(raw)
        doc = tree_guard.qualification_record(outer, core.sha(raw), len(raw), time.monotonic_ns(),
            core.identity(os.stat(outer_path, follow_symlinks=False)))
        path = self.tree_epoch / "sdk-tree-qualified.json"
        path.chmod(0o600)
        selected = _write(path, core.encoded(doc))
        selector_path = self.runfiles / admission.CONFIG
        selector = core.decode(selector_path.read_bytes())
        selector["selection"]["confirmation"] = selected
        selector_path.chmod(0o600)
        _write(selector_path, core.encoded(selector), 0o644)
        mapping_path = self.external / admission.PROOF_REPOSITORY / "sdk-tree-proof-inputs.json"
        mapping = core.decode(mapping_path.read_bytes())
        mapping["proofs"]["qualification_confirmation"] = {**selected, "alias": admission.ALIASES["qualification_confirmation"]}
        mapping_path.chmod(0o600)
        _write(mapping_path, core.encoded(mapping))
        self.tree_paths["qualification_confirmation"] = selected

    @contextmanager
    def retained_source(self):
        cutoff = (self.entry + 600 * 10**9) / 10**9
        env = {"OMUX_NATIVE_FILE_WRITER_MODELS_" + key: value for key, value in self.source_context.items()}
        with patch.dict(os.environ, env), patch.object(family.source, "DEADLINE", cutoff), family.HeldControls() as held:
            held.add(self.mapping_path, maximum=1024 * 1024)
            yield held

    def __exit__(self, kind, error, trace):
        return self.stack.__exit__(kind, error, trace)
