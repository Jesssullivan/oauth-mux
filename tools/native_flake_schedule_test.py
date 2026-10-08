"""Actual FD/NAR/copy/schedule joins; only external Nix child work is injected."""
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import native_flake_schedule as schedule
import native_flake_sources_test as source_models
import nix_private_store_qualification_test as runtime_models
import nar_descriptor as nar
import nix_private_store_seed as seed

DRV = "/nix/store/"+"d"*32+"-omux-bazel-closure.drv"
CHILD = "/nix/store/"+"e"*32+"-dependency.drv"
OUT = "/nix/store/"+"f"*32+"-omux-bazel-closure"
DEPENDENCY = "/nix/store/"+"b"*32+"-dependency"
SCRIPT = "/nix/store/"+"c"*32+"-builder.sh"


def encoded(value):
    return seed.encoded(value)


def row(name, out, *, children=None, srcs=None):
    return {"version": 4, "name": name, "outputs": {"out": {"path": out.rsplit("/",1)[1]}},
        "inputs": {"srcs": [path.rsplit("/",1)[1] for path in srcs or []],
            "drvs": {path.rsplit("/",1)[1]: {"outputs": ["out"], "dynamicOutputs": {}}
                for path in children or []}},
        "system": "x86_64-linux", "builder": "builtin:synthetic-model", "args": [],
        "env": {"out": out}}


class Fixture:
    def __init__(self, directory):
        self.root = Path(directory)
        (self.root/"runtime").mkdir()
        self.runtime = runtime_models.Fixture(self.root/"runtime")
        source_model = source_models.NativeFlakeSourcesTest()
        self.lock, self.bundle, self.data, _ = source_model.fixture()
        self.descriptors = encoded(self.bundle)
        self.labels = self.root/"labels"
        self.labels.mkdir()
        source_model.materialize(self.labels, self.data)
        self.descriptor_path = self.labels/"source-descriptors.json"
        self.descriptor_path.write_bytes(self.descriptors)
        self.project = {name: b"public-fixed-input" for name in schedule.PROJECT_FILES}
        self.project["flake.lock"] = self.lock
        self.imports = {}
        self.calls = []
        self.extra = {}
        self.raw_graph = encoded({"version": 4, "derivations": {
            DRV.rsplit("/",1)[1]: row("omux-bazel-closure", OUT, children=[CHILD], srcs=[SCRIPT]),
            CHILD.rsplit("/",1)[1]: row("dependency", DEPENDENCY)}})

    def registration(self, private):
        text = runtime_models.dump_db_wire(self.runtime.value).decode("ascii")
        for logical, refs in sorted(self.extra.items()):
            physical = private/"nix/store"/logical.rsplit("/",1)[1]
            descriptor = schedule.proof.describe_root(logical, physical)
            hashed = nar.hash_descriptor(descriptor,
                opener=lambda _, relative: nar.open_regular(str(physical), relative))
            text += "\n".join([logical, hashed["narHash"][7:], str(hashed["narSize"]), "",
                              str(len(refs)), *refs])+"\n"
        return text.encode()

    def runner(self, command, environment, root, deadline, *, tool_fd, input_file=None, output_limit=None, diagnostics=None):
        self.calls.append((command, deadline, output_limit))
        assert os.fstat(tool_fd).st_mode & 0o100
        assert environment["NIX_REMOTE"] == "" and environment["PATH"] == ""
        private = Path(command[command.index("--store")+1].removeprefix("local?root="))
        if command[-1] == "--load-db":
            assert input_file.read() == self.runtime.value["registration"].encode()
            return b""
        if command[-1] == "--dump-db":
            return self.registration(private)
        if "--add-fixed" in command:
            physical = Path(command[-1])
            role = physical.parent.name
            logical = "/nix/store/"+str(len(self.imports)+1)*32+"-source"
            destination = private/"nix/store"/logical.rsplit("/",1)[1]
            descriptor = nar.describe(physical)
            schedule.copy_tree(descriptor, destination,
                lambda _, relative: nar.open_regular(str(physical), relative), deadline)
            self.imports[role] = logical
            self.extra[logical] = []
            return (logical+"\n").encode()
        if "eval" in command:
            for logical in (DRV, CHILD, SCRIPT):
                physical = private/"nix/store"/logical.rsplit("/",1)[1]
                physical.write_bytes(b"public-generated-"+logical.rsplit("/",1)[1].encode())
                os.chmod(physical,0o444)
            self.extra.update({DRV: [CHILD,SCRIPT], CHILD: [], SCRIPT: []})
            raw = encoded({"drvPath": DRV, "outPath": OUT, "system": "x86_64-linux",
                           "sourcePaths": self.imports})
            if diagnostics is not None:
                diagnostics.update({"child_exit": 0, "stdout_bytes": len(raw), "stderr_bytes": 0,
                    "stderr_sha256": seed.sha(b""), "streams_complete": True,
                    "transport_reason": "child-zero", "stderr_reason": "unclassified",
                    "stderr_classification_truncated": False})
            return raw
        if "derivation" in command:
            assert "--recursive" in command
            return self.raw_graph
        raise AssertionError("unexpected operation")

    def operate(self, runner=None, deadline=None, entry=None):
        def describe(logical, physical=None):
            actual = self.runtime.physical[logical] if physical is None else physical
            value = nar.describe(actual)
            value["root"] = logical
            return value
        with patch.object(schedule.proof, "source_opener", return_value=self.runtime.opener), \
             patch.object(schedule.proof, "describe_root", side_effect=describe):
            return schedule.operate(self.runtime.value, encoded(self.runtime.value), self.descriptors,
                self.descriptor_path, self.project, "{ projectSource, nixpkgsSource, utilsSource, systemsSource }: {}",
                self.root, float(time.monotonic()+60) if deadline is None else deadline,
                runner=self.runner if runner is None else runner, entry=entry)


class ScheduleModels(unittest.TestCase):

    def test_failed_target_json_is_separate_from_actual_zero_child(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            def runner(*args, **kwargs):
                raw = model.runner(*args, **kwargs)
                if "eval" in args[0]:
                    kwargs["diagnostics"]["stdout_bytes"] = len(b"not JSON")
                    return b"not JSON"
                return raw
            with self.assertRaises(ValueError):
                model.operate(runner)
            self.assertEqual(schedule.PHASE, "target-document")
            self.assertEqual(schedule.DIAGNOSTICS["child_exit"], 0)
            self.assertEqual(schedule.DIAGNOSTICS["transport_reason"], "child-zero")
            self.assertEqual(list(model.root.glob("nix-private-build-*")), [])

    def test_imported_role_join_is_separate_from_valid_target_document(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            def runner(*args, **kwargs):
                raw = model.runner(*args, **kwargs)
                if "eval" in args[0]:
                    value = json.loads(raw)
                    value["sourcePaths"]["systems"] = SCRIPT
                    raw = encoded(value)
                    if kwargs.get("diagnostics") is not None:
                        kwargs["diagnostics"]["stdout_bytes"] = len(raw)
                    return raw
                return raw
            with self.assertRaises(ValueError):
                model.operate(runner)
            self.assertEqual(schedule.PHASE, "imported-source-join")
            self.assertEqual(schedule.DIAGNOSTICS["child_exit"], 0)
            self.assertEqual(list(model.root.glob("nix-private-build-*")), [])

    def test_fixed_elapsed_witness_uses_entry_without_changing_original_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            entry = float(time.monotonic()-1)
            deadline = float(time.monotonic()+60)
            model.operate(deadline=deadline, entry=entry)
            self.assertEqual({call[1] for call in model.calls}, {deadline})
            report = schedule.diagnostic_summary()
            phases = {row["phase"] for row in report["phase_elapsed"]}
            self.assertTrue({"source-verify", "source-copy", "source-store-import",
                             "current-flake-evaluation", "target-document", "imported-source-join"} <= phases)
            ticks = [row["elapsed_ms"] for row in report["phase_elapsed"]]
            self.assertEqual(ticks, sorted(ticks))
            self.assertGreaterEqual(ticks[0], 1000)
            self.assertTrue(all(type(tick) is int and 0 <= tick <= schedule.MAX_WITNESS_MS for tick in ticks))
            self.assertNotIn(str(model.root), json.dumps(report))

    def test_disposable_source_copy_rehashes_without_per_file_fsync(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "original"
            original.mkdir()
            (original / "payload").write_bytes(b"declared-copy-bytes\n")
            descriptor = nar.describe(original)
            with patch.object(schedule.os, "fsync", side_effect=AssertionError("disposable copy fsync")):
                result = schedule.copy_tree(descriptor, Path(directory) / "copied",
                    nar.open_regular, float(time.monotonic() + 10), durable=False)
            self.assertEqual(result, nar.hash_descriptor(descriptor))
            self.assertEqual((Path(directory) / "copied/payload").read_bytes(), b"declared-copy-bytes\n")

    def test_published_generated_copy_retains_payload_and_receipt_fsync(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "original"
            original.write_bytes(b"generated")
            descriptor = nar.describe(original)
            proof = nar.hash_descriptor(descriptor)
            output = Path(directory) / "output"
            output.mkdir()
            item = {"descriptor": descriptor, "artifact_root": "generated/00000000", **proof}
            with patch.object(schedule.os, "fsync", wraps=schedule.os.fsync) as sync:
                schedule.persist({"generated": {str(original): item}},
                    {("generated/00000000", ""): b"generated"}, output,
                    float(time.monotonic() + 10))
            self.assertEqual(sync.call_count, 2)
            self.assertEqual((output / "generated/00000000").read_bytes(), b"generated")
            self.assertTrue((output / "native-flake-obligations.json").is_file())

    def test_disposable_source_copy_flush_failure_propagates(self):
        class FlushFailure:
            def __init__(self, stream):
                self.stream = stream
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.stream.close()
            def write(self, data):
                return self.stream.write(data)
            def flush(self):
                raise OSError("modeled public flush failure")
            def fileno(self):
                return self.stream.fileno()
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "original"
            original.write_bytes(b"copy")
            descriptor = nar.describe(original)
            fdopen = schedule.os.fdopen
            with patch.object(schedule.os, "fdopen", side_effect=lambda *args: FlushFailure(fdopen(*args))), self.assertRaises(OSError):
                schedule.copy_tree(descriptor, Path(directory) / "copied",
                    lambda *_: io.BytesIO(b"copy"), float(time.monotonic() + 10),
                    durable=False)

    def test_actual_copy_import_graph_generated_nars_and_cleanup_preserve_scope(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            result, payloads = model.operate()
            self.assertTrue(result["source_rechecked"])
            self.assertTrue(result["runtime_seed_rechecked"])
            self.assertTrue(result["private_root_removed"])
            self.assertFalse(result["realized"])
            self.assertFalse(result["complete_build_seed_verified"])
            self.assertFalse(result["scheduler_pruned_plan"])
            self.assertEqual(set(result["derivations"]), {DRV, CHILD})
            self.assertIn(DRV, result["generated"])
            self.assertEqual(list(model.root.glob("nix-private-build-*")), [])
            self.assertTrue(all(call[1] == model.calls[0][1] for call in model.calls))
            self.assertEqual(sum("--add-fixed" in call[0] for call in model.calls),4)
            self.assertFalse(any("build" in call[0] for call in model.calls))
            output = model.root/"output"
            output.mkdir()
            schedule.persist(result,payloads,output,float(time.monotonic()+60))
            retained = json.loads((output/"native-flake-obligations.json").read_bytes())
            self.assertEqual(retained,result)
            for logical in (DRV,CHILD,SCRIPT):
                item = retained["generated"][logical]
                path = output/item["artifact_root"]
                hashed = nar.hash_descriptor(nar.describe(path))
                self.assertEqual(hashed["narHash"],item["narHash"])


    def test_both_actual_dump_joins_use_the_pinned_barehex_adapter(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            adapter = schedule.proof.readback_records
            with patch.object(schedule.proof, "readback_records", wraps=adapter) as parsed:
                result, _ = model.operate()
            self.assertEqual(parsed.call_count, 2)
            for call in parsed.call_args_list:
                wire = call.args[0].decode("ascii").splitlines()
                self.assertEqual(len(wire[1]), 64)
                self.assertNotIn("sha256:", wire[1])
            self.assertTrue(result["runtime_seed_rechecked"])
            self.assertTrue(result["private_root_removed"])
            self.assertFalse(result["complete_build_seed_verified"])

    def test_wrong_wire_at_each_dump_stops_and_removes_only_owned_root(self):
        for refused_dump in (1, 2):
            with self.subTest(dump=refused_dump), tempfile.TemporaryDirectory() as directory:
                model = Fixture(directory)
                seen = 0
                def runner(*args, **kwargs):
                    nonlocal seen
                    raw = model.runner(*args, **kwargs)
                    if args[0][-1] == "--dump-db":
                        seen += 1
                        if seen == refused_dump:
                            return raw.replace(b"\n", b"\nsha256:", 1)
                    return raw
                with self.assertRaises(ValueError):
                    model.operate(runner)
                self.assertEqual(seen, refused_dump)
                self.assertEqual(list(model.root.glob("nix-private-build-*")), [])
                self.assertEqual(any("eval" in call[0] for call in model.calls), refused_dump == 2)

    def test_old_json_or_bool_version_rejected(self):
        for value in ({"inputDrvs": {}, "inputSrcs":[]}, {"version": True,"derivations": {}}):
            with self.assertRaises(ValueError):
                schedule.derivations(encoded(value),{"drvPath":DRV,"outPath":OUT})

    def test_incomplete_extra_or_output_substituted_recursive_graph_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Fixture(directory).raw_graph
            for kind in ("missing","extra","output","edge-output"):
                graph = json.loads(original)
                if kind == "missing":
                    graph["derivations"].pop(CHILD.rsplit("/",1)[1])
                elif kind == "extra":
                    graph["derivations"]["a"*32+"-unused.drv"] = row("unused",DEPENDENCY)
                elif kind == "output":
                    graph["derivations"][DRV.rsplit("/",1)[1]]["env"]["out"] = DEPENDENCY
                else:
                    graph["derivations"][DRV.rsplit("/",1)[1]]["inputs"]["drvs"][CHILD.rsplit("/",1)[1]]["outputs"] = ["wrong"]
                with self.assertRaises(ValueError):
                    schedule.derivations(encoded(graph),{"drvPath":DRV,"outPath":OUT})

    def test_dynamic_or_impure_obligations_not_silently_dropped(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Fixture(directory).raw_graph
            for kind in ("dynamic","impure"):
                graph = json.loads(original)
                row_value = graph["derivations"][DRV.rsplit("/",1)[1]]
                if kind == "dynamic":
                    row_value["inputs"]["drvs"][CHILD.rsplit("/",1)[1]]["dynamicOutputs"] = {"out":{}}
                else:
                    row_value["outputs"]["out"] = {"method":"nar","hashAlgo":"sha256","impure":True}
                with self.assertRaises(ValueError):
                    schedule.derivations(encoded(graph),{"drvPath":DRV,"outPath":OUT})

    def test_failed_evaluation_preserves_phase_and_removes_only_owned_root(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            def runner(*args,**kwargs):
                if "eval" in args[0]:
                    raise ValueError("modeled evaluator failure")
                return model.runner(*args,**kwargs)
            with self.assertRaises(ValueError):
                model.operate(runner)
            self.assertEqual(schedule.PHASE,"current-flake-evaluation")
            self.assertEqual(list(model.root.glob("nix-private-build-*")),[])

    def test_imported_role_substitution_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            def runner(*args,**kwargs):
                raw = model.runner(*args,**kwargs)
                if "eval" in args[0]:
                    value = json.loads(raw)
                    value["sourcePaths"]["systems"] = SCRIPT
                    raw = encoded(value)
                    if kwargs.get("diagnostics") is not None:
                        kwargs["diagnostics"]["stdout_bytes"] = len(raw)
                    return raw
                return raw
            with self.assertRaises(ValueError):
                model.operate(runner)

    def test_changed_declared_source_before_child_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            (model.labels/"regular/00000000").write_bytes(b"BAD")
            with patch.object(schedule.proof,"OwnedRoot",side_effect=AssertionError("root created")), self.assertRaises(ValueError):
                model.operate()
            self.assertEqual(model.calls,[])

    def test_non_declared_source_alias_is_not_followed(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            alias = model.labels/"regular/00000000"
            alias.unlink()
            alias.symlink_to("/unselected/private-input")
            with self.assertRaises(ValueError):
                model.operate()
            self.assertEqual(model.calls,[])

    def test_original_deadline_before_owned_root(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            with self.assertRaises(ValueError), patch.object(schedule.proof,"OwnedRoot",side_effect=AssertionError("created")):
                model.operate(deadline=float(time.monotonic()-1))

    def test_fixed_query_argv_no_realization_or_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            private = Path(directory)
            tools={"nix":runtime_models.NIX+"/bin/nix"}
            for command in (schedule.plan(tools,private,"fixed"),
                            schedule.plan(tools,private,"fixed",DRV)):
                self.assertIn("--offline",command)
                self.assertIn("--eval-store",command)
                self.assertEqual(command[command.index("--eval-store")+1],command[command.index("--store")+1])
                self.assertNotIn("build",command)
                self.assertNotIn("--impure",command)
                self.assertEqual(command[command.index("builders")+1],"")
                self.assertEqual(command[command.index("substituters")+1],"")
            paths = {role:Path("/nix/store/"+"a"*32+"-"+role) for role in ("project",*schedule.sources.ROLES)}
            expression = schedule.expression("fixed",paths,{role:"b"*64 for role in paths})
            self.assertEqual(expression.count("sha256 ="),4)
            self.assertEqual(expression.count("builtins.path"),4)

    def test_source_changed_during_evaluation_refused_after_actual_child(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            def runner(*args, **kwargs):
                raw = model.runner(*args, **kwargs)
                if "derivation" in args[0]:
                    (model.labels/"regular/00000000").write_bytes(b"changed-public-source")
                return raw
            with self.assertRaises(ValueError):
                model.operate(runner)
            self.assertTrue(any("derivation" in call[0] for call in model.calls))
            self.assertEqual(list(model.root.glob("nix-private-build-*")), [])

    def test_copied_runtime_changed_by_child_refuses_after_actual_evaluation(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            def runner(*args, **kwargs):
                raw = model.runner(*args, **kwargs)
                if "derivation" in args[0]:
                    private = Path(args[0][args[0].index("--store")+1].removeprefix("local?root="))
                    leaf = private/"nix/store"/runtime_models.LIB.rsplit("/", 1)[1]/"lib/libc.so"
                    original = leaf.read_bytes()
                    os.chmod(leaf, 0o600)
                    leaf.write_bytes(bytes([original[0]^1])+original[1:])
                    os.chmod(leaf, 0o555)
                return raw
            with self.assertRaises(ValueError):
                model.operate(runner)
            self.assertTrue(any("derivation" in call[0] for call in model.calls))
            self.assertEqual(list(model.root.glob("nix-private-build-*")), [])

    def test_generated_payload_substitution_fails_real_nar_readback(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            result, payloads = model.operate()
            item = result["generated"][DRV]
            key = (item["artifact_root"], "")
            payloads[key] = bytes([payloads[key][0] ^ 1]) + payloads[key][1:]
            output = model.root/"output"
            output.mkdir()
            with self.assertRaises(ValueError):
                schedule.persist(result, payloads, output, float(time.monotonic()+60))
            self.assertFalse((output/"native-flake-obligations.json").exists())

    def test_realized_target_in_registration_is_not_an_obligations_only_result(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Fixture(directory)
            def runner(*args, **kwargs):
                raw = model.runner(*args, **kwargs)
                if "eval" in args[0]:
                    private = Path(args[0][args[0].index("--store")+1].removeprefix("local?root="))
                    (private/"nix/store"/OUT.rsplit("/", 1)[1]).write_bytes(b"unexpected-built-output")
                    model.extra[OUT] = []
                return raw
            with self.assertRaises(ValueError):
                model.operate(runner)
            self.assertEqual(list(model.root.glob("nix-private-build-*")), [])

    def test_oversized_generated_payload_refuses_before_payload_open(self):
        # External NAR qualification is injected here to isolate the payload IO bound.
        with tempfile.TemporaryDirectory() as directory:
            digest = "a"*64
            descriptor = {"root": DRV, "nodes": [{"path": "", "type": "regular",
                "size": schedule.MAX_ARTIFACT_BYTES+1, "executable": False}]}
            records = {DRV: {"record": [DRV, "sha256:"+digest, "1", ""], "references": []}}
            with patch.object(schedule.proof, "describe_root", return_value=descriptor), \
                 patch.object(schedule.nar, "hash_descriptor", return_value={"narHash": "sha256:"+digest, "narSize": 1}), \
                 patch.object(schedule.nar, "open_regular") as opener:
                with self.assertRaises(ValueError):
                    schedule.generated_objects(Path(directory), records, [],
                        {"sourcePaths": {}, "outPath": OUT}, {DRV: {"inputSrcs": []}},
                        float(time.monotonic()+10))
            opener.assert_not_called()

    def test_persist_expiry_does_not_create_new_clock(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                schedule.persist({"generated":{}},{},directory,float(time.monotonic()-1))
            self.assertEqual(list(Path(directory).iterdir()),[])

    def test_transport_output_limit_is_literal_bounded_before_spawn(self):
        with patch.object(schedule.proof.subprocess,"Popen") as spawn:
            for limit in (True,0,32*1024**2+1):
                with self.assertRaises(ValueError):
                    schedule.proof.run(["fixed"],{},Path("/"),float(time.monotonic()+10),
                                       tool_fd=777,output_limit=limit)
        spawn.assert_not_called()


if __name__ == "__main__":
    unittest.main()
