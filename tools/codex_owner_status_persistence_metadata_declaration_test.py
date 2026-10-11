"""Bounded structural/publication models, not genuine SDK authentication.

The rule model executes the declared rule's Python-compatible function bodies
with finite repository API doubles. It is not a real Bazel invalidation proof.
"""
import argparse
import ast
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace
import unittest
from unittest import mock
import sys
import tempfile

import codex_owner_status_persistence_metadata_declaration as helper

RULE_PATH = None


def regular(path, value=b"selected"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    return {"path": path.name, "kind": "file", "size": len(value),
        "sha256": helper.sha(value), "mode": 292}


def fixture(root):
    source, export, jdk = root/"source-role", root/"sdk-role", root/"jdk-role"
    control = root/"control.json"
    source.joinpath("source/sub").mkdir(parents=True)
    a, z = source/"source/a", source/"source/z"
    a.write_bytes(b"a")
    z.write_bytes(b"z")
    (source/"source/sub/link").symlink_to("../a")
    source_doc = {"kind": "omux-owner-status-persistence-source-v1",
        "status": "verified-owner-status-persistence-source-pending-sdk-and-schema",
        "inventory_sha256": "1"*64, "sdk_metadata_qualified": False,
        "native_compile_passed": False, "provider_evaluation": False,
        "source_inventory": {"z": {"mode": "100755", "sha256": helper.sha(b"z")},
            "sub/link": {"mode": "120000", "sha256": helper.sha(b"../a")},
            "a": {"mode": "100644", "sha256": helper.sha(b"a")}}}
    (source/"source-receipt.json").write_bytes(helper.encode(source_doc))
    rs = export/"repositories/rules_rs++crate+crates"
    cross = export/"repositories/cross"
    rs.mkdir(parents=True)
    cross.mkdir(parents=True)
    rrow = regular(rs/"own")
    crow = regular(cross/"data")
    (rs/"cross-link").symlink_to("../cross/data")
    (rs/"missing-link").symlink_to("../cross/missing")
    jdk.mkdir()
    jrow = regular(jdk/"jfile")
    (jdk/"internal").symlink_to("jfile")
    # Deliberately not an authorized symbolic target or watched input.
    outside = root/"outside"
    outside.mkdir()
    regular(outside/"unselected")
    (jdk/"external").symlink_to(str(outside))
    graphs = {"z.graph": {"sha256": helper.sha(b"zgraph")},
              "a.graph": {"sha256": helper.sha(b"agraph")}}
    regular(export/"graph/z.graph", b"zgraph")
    regular(export/"graph/a.graph", b"agraph")
    registry = []
    for value in (b"registry-z", b"registry-a"):
        sha = helper.sha(value)
        path = "content_addressable/sha256/" + sha + "/file"
        regular(export/"registry-cache"/path, value)
        registry.append({"path": path, "size": len(value), "sha256": sha})
    exported = {"schema": "omux-retained-native-sdk-export-v1", "qualification_only": False,
        "nix_store_roots": [str(jdk)], "repositories": [
            {"canonical_name": "rules_rs++crate+crates", "files": [rrow,
                {"path": "cross-link", "kind": "symlink", "target": "../cross/data"},
                {"path": "missing-link", "kind": "symlink", "target": "../cross/missing"}],
                "absent_links": [{"origin": "rules_rs++crate+crates/missing-link", "target": "cross/missing"}]},
            {"canonical_name": "cross", "files": [crow]}],
        "nix_inventory": [jrow, {"path": "internal", "kind": "symlink", "target": "jfile"},
            {"path": "external", "kind": "symlink", "target": str(outside)}],
        "graph_files": graphs, "registry_metadata": {"files": registry}}
    (export/"receipt.json").write_bytes(helper.encode(exported))
    binding = {"kind": "omux-owner-status-persistence-metadata-binding-v1",
        "source_reconstructed_and_fully_read": True, "metadata_input": {
            "kind": "omux-owner-status-persistence-metadata-input-v1", "source_root": str(source),
            "source_receipt_sha256": "2"*64, "source_inventory_sha256": "1"*64}}
    raw = helper.encode(binding)
    control.write_bytes(raw)
    roles = helper.RolePolicy(str(control), str(source), str(export), str(jdk),
        "3"*64, "2"*64, "1"*64, len(raw), 3)
    # Independently spell out the original ordered mapping: JDK absolute keys
    # precede relative repository keys; graph/registry preserve metadata order.
    inputs = [str(control), str(source/"source-receipt.json"), str(a), str(z),
        str(export/"receipt.json"), str(jdk/"jfile"), str(cross/"data"), str(rs/"own"),
        str(export/"graph/z.graph"), str(export/"graph/a.graph")] + [
            str(export/"registry-cache"/row["path"]) for row in registry]
    watches = [str(source/"source/sub/link"), str(rs/"cross-link")] + inputs
    return roles, inputs, watches


class Model(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.roles, self.inputs, self.watches = fixture(self.root)
        self.output = self.root/"repository"
        self.output.mkdir(mode=0o700)

    def tearDown(self):
        self.temp.cleanup()

    def prepare(self):
        return helper.prepare(str(self.output), self.roles)

    def materialize(self, report, **kwargs):
        return helper.materialize(str(self.output), report["plan_sha256"], self.roles, **kwargs)

    def no_publication(self):
        for name in ("BUILD.bazel", "input-files", "metadata-input.json", "metadata-input.sha256", helper.STAGE):
            self.assertFalse((self.output/name).exists(), name)

    def test_exact_entire_mapping_watch_order_and_publication(self):
        report = self.prepare()
        self.assertEqual(report["regularInputs"], self.inputs)
        self.assertEqual(report["watchInputs"], self.watches)
        self.no_publication()
        transitions = []
        result = self.materialize(report, event=lambda stage: transitions.append(
            (stage, (self.output/"BUILD.bazel").exists())))
        self.assertEqual(transitions, [("before-alias-publication", False),
            ("metadata-published", False), ("before-ready", False), ("ready-published", True)])
        self.assertEqual(result["input_count"], len(self.inputs))
        for index, source in enumerate(self.inputs):
            self.assertEqual(os.readlink(self.output/"input-files"/str(index)), source)
        self.assertEqual(len(list((self.output/"input-files").iterdir())), len(self.inputs))
        self.assertEqual((self.output/"metadata-input.json").read_bytes(), Path(self.roles.control).read_bytes())
        self.assertEqual((self.output/"metadata-input.sha256").read_bytes(), b"3"*64 + b"\n")
        labels = ["input-files/" + str(i) for i in range(len(self.inputs))] + [
            "metadata-input.json", "metadata-input.sha256"]
        expected = ('package(default_visibility = ["//visibility:public"])\n' +
            "exports_files(" + json.dumps(labels) + ")\n" +
            'filegroup(name = "inputs", srcs = ' + json.dumps(labels) + ")\n").encode()
        self.assertEqual((self.output/"BUILD.bazel").read_bytes(), expected)

    def test_external_jdk_symbolic_targets_not_read_or_watched(self):
        original = helper.Physical.directory
        forbidden = str(self.root/"outside")
        def directory(physical, path):
            self.assertFalse(path == forbidden or path.startswith(forbidden + "/"))
            return original(physical, path)
        with mock.patch.object(helper.Physical, "directory", directory):
            report = self.prepare()
            self.materialize(report)
        self.assertNotIn(str(Path(self.roles.jdk)/"external"), report["watchInputs"])
        self.assertNotIn(str(Path(self.roles.jdk)/"internal"), report["watchInputs"])

    def test_absent_target_created_between_phases_refused(self):
        report = self.prepare()
        missing = Path(self.roles.export)/"repositories/cross/missing"
        self.assertNotIn(str(missing), report["watchInputs"])
        missing.write_bytes(b"new")
        with self.assertRaises(ValueError):
            self.materialize(report)
        self.no_publication()

    def test_missing_link_removed_between_phases_refused(self):
        report = self.prepare()
        (Path(self.roles.export)/"repositories/rules_rs++crate+crates/missing-link").unlink()
        with self.assertRaises(ValueError):
            self.materialize(report)
        self.no_publication()

    def test_same_bytes_selected_ancestor_replacement_refused(self):
        report = self.prepare()
        selected = Path(self.roles.source)
        selected.rename(self.root/"old-source")
        shutil.copytree(self.root/"old-source", selected, symlinks=True)
        with self.assertRaisesRegex(ValueError, "original-plan-and-witnesses"):
            self.materialize(report)
        self.no_publication()

    def test_same_terminal_link_retarget_refused(self):
        report = self.prepare()
        selected = Path(self.roles.export)/"repositories/rules_rs++crate+crates/cross-link"
        selected.unlink()
        selected.symlink_to("../cross/./data")
        with self.assertRaisesRegex(ValueError, "symbolic-target-text"):
            self.materialize(report)
        self.no_publication()

    def test_cross_root_file_change_and_source_link_escape_refused(self):
        report = self.prepare()
        (Path(self.roles.export)/"repositories/cross/data").write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "original-plan-and-witnesses"):
            self.materialize(report)
        self.no_publication()
        source_link = Path(self.roles.source)/"source/sub/link"
        source_link.unlink()
        source_link.symlink_to(str(Path(self.roles.export)/"repositories/cross/data"))
        with helper.Physical() as physical, self.assertRaisesRegex(ValueError, "physical-link-root"):
            helper.declaration(physical, self.roles)

    def test_regular_leaf_link_or_fifo_and_directory_ancestor_link_refused(self):
        selected = Path(self.roles.source)/"source/a"
        selected.unlink()
        selected.symlink_to("z")
        with self.assertRaises(ValueError):
            self.prepare()
        selected.unlink()
        os.mkfifo(selected)
        with self.assertRaises(ValueError):
            self.prepare()
        selected.unlink()
        selected.write_bytes(b"a")
        sub = Path(self.roles.source)/"source/sub"
        sub.rename(sub.with_name("old-sub"))
        sub.symlink_to("old-sub", target_is_directory=True)
        with self.assertRaises(ValueError):
            self.prepare()

    def test_plan_digest_and_reordered_or_elided_mapping_refused(self):
        report = self.prepare()
        for mutation in (lambda plan: plan["regularInputs"].reverse(),
                         lambda plan: plan["regularInputs"].pop(),
                         lambda plan: plan["watchInputs"].pop()):
            original = (self.output/helper.PLAN).read_bytes()
            plan = json.loads(original)
            mutation(plan)
            changed = helper.encode(plan)
            (self.output/helper.PLAN).write_bytes(changed)
            with self.assertRaisesRegex(ValueError, "plan-byte-binding"):
                self.materialize(report)
            with self.assertRaisesRegex(ValueError, "original-plan-and-witnesses"):
                helper.materialize(str(self.output), helper.sha(changed), self.roles)
            self.no_publication()
            (self.output/helper.PLAN).write_bytes(original)

    def test_each_publication_failure_rolls_back_owned_outputs(self):
        report = self.prepare()
        for selected in ("before-alias-publication", "metadata-published", "before-ready", "ready-published"):
            with self.subTest(selected=selected):
                def event(stage):
                    if stage == selected:
                        raise RuntimeError("original-stage-error")
                with self.assertRaisesRegex(RuntimeError, "original-stage-error"):
                    self.materialize(report, event=event)
                self.no_publication()

    def test_emit_failure_rolls_back_ready_marker(self):
        report = self.prepare()
        def emit(_):
            raise BrokenPipeError("report-rejected")
        with self.assertRaisesRegex(BrokenPipeError, "report-rejected"):
            self.materialize(report, emit=emit)
        self.no_publication()

    def test_exclusive_publication_preserves_foreign_ready_file(self):
        report = self.prepare()
        def event(stage):
            if stage == "before-ready":
                (self.output/"BUILD.bazel").write_bytes(b"foreign-ready")
        with self.assertRaises(FileExistsError):
            self.materialize(report, event=event)
        self.assertEqual((self.output/"BUILD.bazel").read_bytes(), b"foreign-ready")
        self.assertFalse((self.output/"input-files").exists())
        self.assertFalse((self.output/"metadata-input.json").exists())
        self.assertFalse((self.output/helper.STAGE).exists())

    def test_exclusive_alias_publication_preserves_foreign_directory(self):
        report = self.prepare()
        def event(stage):
            if stage == "before-alias-publication":
                (self.output/"input-files").mkdir()
                (self.output/"input-files/foreign").write_bytes(b"foreign")
        with self.assertRaises(FileExistsError):
            self.materialize(report, event=event)
        self.assertEqual((self.output/"input-files/foreign").read_bytes(), b"foreign")
        self.assertFalse((self.output/"BUILD.bazel").exists())
        self.assertFalse((self.output/helper.STAGE).exists())

    def test_success_cleanup_failure_still_removes_owned_readiness(self):
        report = self.prepare()
        def event(stage):
            if stage == "ready-published":
                (self.output/helper.STAGE).rename(self.output/"owned-stage-moved")
                (self.output/helper.STAGE).mkdir()
                (self.output/helper.STAGE/"foreign").write_bytes(b"foreign")
        with self.assertRaisesRegex(ValueError, "owned-cleanup-refused"):
            self.materialize(report, event=event)
        self.assertEqual((self.output/helper.STAGE/"foreign").read_bytes(), b"foreign")
        self.assertFalse((self.output/"BUILD.bazel").exists())
        self.assertFalse((self.output/"input-files").exists())

    def test_foreign_substitution_refuses_cleanup_preserves_primary(self):
        report = self.prepare()
        def event(stage):
            if stage == "metadata-published":
                target = self.output/"metadata-input.json"
                target.rename(self.output/"owned-metadata-moved")
                target.write_bytes(b"foreign")
                raise RuntimeError("original-error")
        with self.assertRaisesRegex(RuntimeError, "original-error") as caught:
            self.materialize(report, event=event)
        self.assertEqual((self.output/"metadata-input.json").read_bytes(), b"foreign")
        self.assertTrue(any("cleanup refused" in note for note in caught.exception.__notes__))
        self.assertFalse((self.output/"BUILD.bazel").exists())
        self.assertFalse((self.output/"input-files").exists())

    def test_late_source_mutation_rolls_back_readiness(self):
        report = self.prepare()
        def event(stage):
            if stage == "ready-published":
                (Path(self.roles.source)/"source/a").write_bytes(b"later-change")
        with self.assertRaisesRegex(ValueError, "changed-input-witness"):
            self.materialize(report, event=event)
        self.no_publication()

    def test_late_metadata_in_place_mutation_refuses_acceptance(self):
        report = self.prepare()
        def event(stage):
            if stage == "ready-published":
                (self.output/"metadata-input.json").write_bytes(b"changed-in-place")
        with self.assertRaisesRegex(ValueError, "output-byte-readback"):
            self.materialize(report, event=event)
        self.no_publication()

    def test_published_alias_parent_replacement_refused_at_both_seams(self):
        parent = self.output
        for selected in ("metadata-published", "ready-published"):
            with self.subTest(selected=selected):
                self.output = parent/selected
                self.output.mkdir()
                report = self.prepare()
                emitted = []
                def event(stage):
                    if stage == selected:
                        (self.output/"input-files").rename(self.output/"owned-aliases-moved")
                        (self.output/"input-files").mkdir()
                        (self.output/"input-files/foreign").write_bytes(b"foreign-directory")
                with self.assertRaisesRegex(ValueError, "published-alias-parent") as caught:
                    self.materialize(report, event=event, emit=emitted.append)
                self.assertEqual(emitted, [])
                self.assertEqual((self.output/"input-files/foreign").read_bytes(), b"foreign-directory")
                self.assertEqual(os.readlink(self.output/"owned-aliases-moved/0"), self.inputs[0])
                self.assertTrue(any("cleanup refused" in note for note in caught.exception.__notes__))
                for name in ("BUILD.bazel", "metadata-input.json", "metadata-input.sha256", helper.STAGE):
                    self.assertFalse((self.output/name).exists(), name)
                self.assertEqual((Path(self.roles.source)/"source/a").read_bytes(), b"a")

    def test_ready_alias_leaf_substitution_and_extra_leaf_refused(self):
        parent = self.output
        for change, predicate in (("substitute", "published-alias-recheck"),
                                  ("extra", "published-alias-count")):
            with self.subTest(change=change):
                self.output = parent/change
                self.output.mkdir()
                report = self.prepare()
                emitted = []
                foreign_target = str(Path(self.roles.source)/"source/z")
                def event(stage):
                    if stage == "ready-published":
                        if change == "substitute":
                            (self.output/"input-files/0").rename(self.output/"owned-alias-moved")
                            (self.output/"input-files/0").symlink_to(foreign_target)
                        else:
                            (self.output/"input-files/foreign").symlink_to(foreign_target)
                with self.assertRaisesRegex(ValueError, predicate) as caught:
                    self.materialize(report, event=event, emit=emitted.append)
                self.assertEqual(emitted, [])
                foreign = "0" if change == "substitute" else "foreign"
                self.assertEqual(os.readlink(self.output/"input-files"/foreign), foreign_target)
                if change == "substitute":
                    self.assertEqual(os.readlink(self.output/"owned-alias-moved"), self.inputs[0])
                self.assertTrue(any("cleanup refused" in note for note in caught.exception.__notes__))
                for name in ("BUILD.bazel", "metadata-input.json", "metadata-input.sha256", helper.STAGE):
                    self.assertFalse((self.output/name).exists(), name)
                self.assertEqual((Path(self.roles.source)/"source/a").read_bytes(), b"a")

    def test_production_cli_has_no_alternate_selector(self):
        with mock.patch.object(sys, "argv", ["helper", "--phase", "plan", "--directory", str(self.output),
                                            "--source", self.roles.source]), self.assertRaises(SystemExit) as caught:
            helper.main()
        self.assertEqual(caught.exception.code, 2)
        self.assertFalse((self.output/helper.PLAN).exists())


class RuleModel(unittest.TestCase):
    @staticmethod
    def namespace():
        raw = RULE_PATH.read_text()
        tree = ast.parse(raw)
        class Translate(ast.NodeTransformer):
            def visit_Call(self, node):
                node = self.generic_visit(node)
                if isinstance(node.func, ast.Attribute) and node.func.attr == "elems":
                    return ast.copy_location(ast.Call(func=ast.Name(id="list", ctx=ast.Load()),
                        args=[node.func.value], keywords=[]), node)
                return node
        tree = ast.fix_missing_locations(Translate().visit(tree))
        kinds = {str: "string", dict: "dict", list: "list", bool: "bool", int: "int"}
        namespace = {"type": lambda value: kinds.get(type(value)), "repr": json.dumps,
            "json": SimpleNamespace(decode=json.loads), "Label": lambda value: value,
            "attr": SimpleNamespace(string=lambda **_: None, label=lambda **_: None),
            "repository_rule": lambda **_: None,
            "fail": lambda category: (_ for _ in ()).throw(ValueError(category))}
        exec(compile(tree, str(RULE_PATH), "exec"), namespace)
        return namespace

    def test_fixed_source_roles_match_command_authority(self):
        namespace = self.namespace()
        for key, value in {"_CONTROL": helper.CONTROL, "_CONTROL_SHA": helper.CONTROL_SHA,
            "_SOURCE": helper.SOURCE, "_EXPORT": helper.EXPORT, "_JDK": helper.JDK}.items():
            self.assertEqual(namespace[key], value)
        self.assertEqual(helper.RolePolicy(), helper.RolePolicy(
            helper.CONTROL, helper.SOURCE, helper.EXPORT, helper.JDK,
            helper.CONTROL_SHA, helper.SOURCE_SHA, helper.INVENTORY_SHA, 2896, 8549))

    def test_actual_rule_preserves_watches_and_phase_order_without_leaf_rpcs(self):
        namespace = self.namespace()
        control = " "*2896
        inputs = [helper.CONTROL, helper.SOURCE + "/source-receipt.json", helper.SOURCE + "/source/a",
                  helper.EXPORT + "/receipt.json", helper.JDK + "/lib/regular"]
        watches = [helper.SOURCE + "/source/link", helper.EXPORT + "/repositories/r/link"] + inputs
        plan = {"kind": helper.KIND, "plan_sha256": "a"*64, "selection_sha256": helper.CONTROL_SHA,
            "regularInputs": inputs, "watchInputs": watches, "control_raw": control}
        made = {"materialized": True, "input_count": len(inputs), "selection_sha256": helper.CONTROL_SHA,
            "plan_sha256": "a"*64, "build_sha256": "b"*64}
        events, recorded = [], []
        bootstrap = "/nix/store/" + "a"*32 + "-bootstrap"
        python = "/nix/store/" + "b"*32 + "-python"
        native = "/nix/store/" + "c"*32 + "-native.json"
        paths = "/nix/store/" + "d"*32 + "-closure-info/store-paths"
        class FakePath:
            def __init__(self, value):
                self.value = str(value)
            def __str__(self):
                return self.value
            @property
            def realpath(self):
                if self.value == bootstrap + "/native.json":
                    return native
                if self.value == bootstrap + "/store-paths":
                    return paths
                if self.value in inputs or self.value in watches:
                    raise AssertionError("per-leaf physical RPC")
                return self.value
            @property
            def exists(self):
                if self.value in inputs or self.value in watches:
                    raise AssertionError("per-leaf exists RPC")
                return True
            @property
            def is_dir(self):
                return False
        class Context:
            attr = SimpleNamespace(selection=helper.CONTROL, sha256=helper.CONTROL_SHA,
                bootstrap_closure=bootstrap, _declaration_helper="declared-helper.py")
            os = SimpleNamespace(name="linux", arch="x86_64", environ={})
            def path(self, value):
                return FakePath(value)
            def watch(self, path):
                recorded.append(str(path))
                events.append("watch")
            def file(self, name, raw, executable=False):
                self.assert_file = (name, raw, executable)
            def read(self, path, watch="no"):
                value = str(path)
                if value == native:
                    return json.dumps({"system": "x86_64-linux", "packages": {"python": {"out": python}}})
                if value == paths:
                    return python + "\n"
                if value == "declared-helper.py":
                    return "declared helper bytes"
                if value == "metadata-input.json":
                    return control
                if value == "metadata-input.sha256":
                    return helper.CONTROL_SHA + "\n"
                if value == "BUILD.bazel":
                    return helper.build_bytes(len(inputs)).decode()
                raise AssertionError(value)
            def execute(self, command, timeout):
                if command[:3] != [python + "/bin/python3", "-I", "-S"] or timeout != 600:
                    raise AssertionError("declared isolated interpreter/call bound")
                if command[command.index("--phase") + 1] == "plan":
                    events.append("plan")
                    return SimpleNamespace(return_code=0, stdout=json.dumps(plan))
                self.assert_watches = list(recorded)
                events.append("materialize")
                return SimpleNamespace(return_code=0, stdout=json.dumps(made))
        context = Context()
        namespace["_implementation"](context)
        self.assertEqual(recorded[-len(watches):], watches)
        self.assertEqual(context.assert_watches[-len(watches):], watches)
        self.assertEqual(events[events.index("plan") + 1:], ["watch"]*len(watches) + ["materialize"])
        self.assertEqual(context.assert_file, (".metadata-declaration.py", "declared helper bytes", False))
        # The real source has no tree-watch or source-symlink API operation.
        calls = [node.func.attr for node in ast.walk(ast.parse(RULE_PATH.read_text()))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)]
        self.assertNotIn("watch_tree", calls)
        self.assertNotIn("symlink", calls)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--rule", required=True)
    options, remaining = parser.parse_known_args()
    RULE_PATH = Path(options.rule)
    unittest.main(argv=[sys.argv[0]] + remaining)
