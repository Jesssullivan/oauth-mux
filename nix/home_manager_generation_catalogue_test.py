"""Finite graph/filesystem models. No Nix child or installed HM is impersonated."""
import copy
from contextlib import contextmanager
import hashlib
import json
import os
import stat
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from unittest.mock import Mock

import home_manager_generation_catalogue as model


class GenerationCatalogueTests(unittest.TestCase):
    def setUp(self):
        self.proposal = "/nix/store/" + "a" * 32 + "-hm-generation.drv"
        self.dependency = "/nix/store/" + "b" * 32 + "-builder.drv"
        self.source = "/nix/store/" + "c" * 32 + "-builder-script"
        self.output = "/nix/store/" + "d" * 32 + "-builder"
        self.result = "/nix/store/" + "f" * 32 + "-hm-generation"
        self.records = {path: {"references": []} for path in (self.proposal, self.dependency, self.source)}
        def row(name, result, builder, srcs, drvs):
            return {"name": name, "version": 4, "system": "x86_64-linux", "builder": builder,
                "args": ["-e", self.source], "env": {"out": result},
                "outputs": {"out": {"path": result.rsplit("/", 1)[1]}},
                "inputs": {"srcs": [item.rsplit("/", 1)[1] for item in srcs],
                    "drvs": {path.rsplit("/", 1)[1]: {"outputs": names, "dynamicOutputs": {}} for path, names in drvs.items()}}}
        self.value = {"version": 4, "derivations": {
            self.proposal.rsplit("/", 1)[1]: row("hm-generation", self.result, self.output + "/bin/bash",
                [self.source], {self.dependency: ["out"]}),
            self.dependency.rsplit("/", 1)[1]: row("builder", self.output, self.source + "/build",
                [self.source], {})}}

    def read(self, value=None, bindings=None):
        return model.graph(model.seed.encoded(self.value if value is None else value), self.proposal,
            self.records, {} if bindings is None else bindings)

    def test_selected_output_missing_from_drv_references_is_an_unqualified_acquisition_root(self):
        result = self.read()
        self.assertEqual(result["missingDeclaredRoots"], [self.output])
        self.assertIn(self.output, result["requiredRoots"])
        self.assertNotIn(self.result, result["requiredRoots"])
        self.assertEqual(result["outputPath"], self.result)
        self.assertFalse(result["builderClosureQualified"])
        self.assertFalse(result["generationRealized"])

    def test_even_present_output_names_do_not_promote_full_builder_content(self):
        self.records[self.output] = {"references": []}
        result = self.read()
        self.assertEqual(result["missingDeclaredRoots"], [])
        self.assertFalse(result["builderClosureQualified"])

    def test_forged_proposal_or_source_and_missing_dependency_refuse(self):
        for fault in ("proposal", "source", "dependency"):
            with self.subTest(fault=fault):
                value = copy.deepcopy(self.value)
                if fault == "proposal": del self.records[self.proposal]
                elif fault == "source": value["derivations"][self.proposal.rsplit("/", 1)[1]]["inputs"]["srcs"] = ["g"*32+"-foreign"]
                else: del value["derivations"][self.dependency.rsplit("/", 1)[1]]
                try:
                    with self.assertRaises((ValueError, KeyError)): self.read(value)
                finally: self.records[self.proposal] = {"references": []}

    def test_dynamic_deferred_impure_or_wrong_version_refuse(self):
        for fault in ("dynamic", "deferred", "impure", "version", "platform"):
            with self.subTest(fault=fault):
                value = copy.deepcopy(self.value)
                row = value["derivations"][self.proposal.rsplit("/", 1)[1]]
                if fault == "dynamic": row["inputs"]["drvs"][self.dependency.rsplit("/", 1)[1]]["dynamicOutputs"] = {"out": {}}
                elif fault == "deferred": row["outputs"]["out"] = {}
                elif fault == "impure": row["outputs"]["out"] = {"impure": True, "method": "nar", "hashAlgo": "sha256"}
                elif fault == "platform": row["system"] = "aarch64-darwin"
                else: value["version"] = True
                with self.assertRaises((ValueError, KeyError)): self.read(value)

    def test_output_name_membership_and_builder_input_membership_refuse(self):
        for fault in ("output", "builder"):
            value = copy.deepcopy(self.value)
            row = value["derivations"][self.proposal.rsplit("/", 1)[1]]
            if fault == "output": row["inputs"]["drvs"][self.dependency.rsplit("/", 1)[1]]["outputs"] = ["missing"]
            else: row["builder"] = "/nix/store/" + "g"*32 + "-ambient/bin/bash"
            with self.assertRaises((ValueError, KeyError)): self.read(value)

    def test_fixed_output_requires_actual_isolated_binding_and_explicit_env_join(self):
        row = self.value["derivations"][self.dependency.rsplit("/", 1)[1]]
        row["outputs"]["out"] = {"method": "nar", "hash": "sha256-" + "A"*43 + "="}
        with self.assertRaises(ValueError): self.read()
        result = self.read(bindings={(self.dependency, "out"): self.output})
        self.assertEqual(result["requiredOutputEdges"][0]["path"], self.output)
        with self.assertRaises(ValueError): self.read(bindings={(self.dependency, "out"): self.result})

    def test_unknown_extra_drv_duplicate_key_and_oversize_refuse(self):
        value = copy.deepcopy(self.value)
        value["derivations"]["g"*32+"-unselected.drv"] = copy.deepcopy(value["derivations"][self.dependency.rsplit("/", 1)[1]])
        self.records["/nix/store/"+"g"*32+"-unselected.drv"] = {"references": []}
        with self.assertRaises(ValueError): self.read(value)
        with self.assertRaises(ValueError): model.graph(b'{"version":4,"version":4,"derivations":{}}', self.proposal, self.records, {})
        with self.assertRaises(ValueError): model.graph(b" "*(model.MAX_GRAPH_BYTES+1), self.proposal, self.records, {})

    def test_expression_has_private_fixed_hash_modules_and_no_impure_fetch_or_activation(self):
        value = {"roles": {"nixpkgs": self.source, "home-manager": self.output, "artifact": self.result},
            "artifact": {"channel": "development", "narHash": "sha256-"+"A"*43+"=", "sourceRevision": "1"*40},
            "pair": {name: {"narHash": "sha256-"+"A"*43+"="} for name in ("home-manager", "nixpkgs")}}
        rendered = model.expression(value, Path("/public/private/modules"), "sha256-"+"A"*43+"=", Path("/public/private/store"))
        self.assertIn("builtins.path", rendered)
        self.assertEqual(rendered.count("builtins.path"), 4)
        self.assertNotIn("builtins.storePath", rendered)
        self.assertIn("sha256 =", rendered)
        self.assertNotIn("getFlake", rendered)
        self.assertNotIn("--impure", rendered)
        self.assertNotIn("activate", rendered)
        self.assertIn('\\${', model.literal("public ${expression}"))

    def test_module_writer_partial_writes_and_failure_retire_actual_fd_once(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR")) as temporary:
            root = Path(temporary); (root/"private-store").mkdir(mode=0o700)
            class Owned:
                path = root
                def recheck(self):
                    model.require(root.lstat().st_uid == os.getuid() and root.lstat().st_mode & 0o777 == 0o700)
            modules = {name: b"public fixture bytes" for name in (*model.inputs.MODULES, model.MODULE)}
            opened, closed = [], []
            actual_open, actual_close, actual_write = os.open, os.close, os.write
            writes = []
            def capture(*args, **kwargs):
                fd = actual_open(*args, **kwargs); opened.append(fd); return fd
            def close(fd): closed.append(fd); return actual_close(fd)
            def write(fd, raw):
                writes.append(fd)
                if len(writes) <= 2: return actual_write(fd, raw[:3])
                raise OSError("public synthetic writer refusal")
            with patch.object(model.os, "open", capture), patch.object(model.os, "close", close), patch.object(model.os, "write", write):
                with self.assertRaises(OSError): model.Generation(modules)({}, Owned(), root/"private-store", None,
                    float(time.monotonic()+120), None)
            self.assertEqual(sorted(opened), sorted(closed))
            self.assertEqual(len(writes), 3)
            for fd in opened:
                with self.assertRaises(OSError): os.fstat(fd)

    def test_deadline_expires_during_real_module_write_and_drains_fd(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR")) as temporary:
            root = Path(temporary)
            class Owned:
                path = root
                def recheck(self):
                    model.require(root.lstat().st_uid == os.getuid() and root.lstat().st_mode & 0o777 == 0o700)
            modules = {name: b"public" for name in (*model.inputs.MODULES, model.MODULE)}
            opened = []
            actual_open, actual_dup, actual_write = os.open, os.dup, os.write
            deadline = float(time.monotonic()+120)
            def capture(*args, **kwargs):
                fd = actual_open(*args, **kwargs); opened.append(fd); return fd
            def duplicate(fd):
                result = actual_dup(fd); opened.append(result); return result
            with patch.object(model.private.time, "monotonic", return_value=deadline-1) as clock:
                def write(fd, raw):
                    result = actual_write(fd, raw); clock.return_value = deadline+1; return result
                with patch.object(model.os, "open", capture), patch.object(model.os, "dup", duplicate), \
                        patch.object(model.os, "write", write):
                    with self.assertRaises(ValueError): model.Generation(modules)({}, Owned(), root, None, deadline, None)
            self.assertEqual(len(opened), 4)
            for fd in opened:
                with self.assertRaises(OSError): os.fstat(fd)

    def test_real_callback_fresh_origin_and_historical_input_split_refuse_unrelated_graph(self):
        dump = "".join("\n".join([path, "0"*64, "1", "", "0"]) + "\n"
            for path in sorted(self.records)).encode("ascii")
        for wrong in (False, True, "mutation", "historical"):
            with self.subTest(wrong=wrong), tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR")) as temporary:
                root = Path(temporary); store = root/"private-store"; store.mkdir(mode=0o700)
                tool_file = root/"public-tool"; tool_file.write_bytes(b"public synthetic executable"); tool_file.chmod(0o555)
                modules = {name: b"public synthetic Nix model" for name in (*model.inputs.MODULES, model.MODULE)}
                class Owned:
                    path = root
                    def recheck(self):
                        self_info = root.lstat()
                        model.require(self_info.st_uid == os.getuid() and self_info.st_mode & 0o777 == 0o700)
                class Declared:
                    @contextmanager
                    def open(self, unused_root, unused_member):
                        with model.inputs.regular(tool_file, float(time.monotonic()+120)) as stream: yield stream
                    def check(self): pass
                value = {"roots": sorted(self.records), "roles": {"nix": self.output+"/bin/nix", "nix_store": self.output+"/bin/nix-store",
                    "derivation": self.dependency if wrong == "historical" else self.proposal,
                    "home-manager": self.source, "nixpkgs": self.source, "artifact": self.result},
                    "artifact": {"narHash": "sha256-"+"A"*43+"=", "sourceRevision": "1"*40,
                        "manifestSha256": "2"*64, "channel": "development"},
                    "pair": {name: {"narHash": "sha256-"+"A"*43+"="} for name in ("home-manager", "nixpkgs")}}
                commands = []
                def runner(argv, env, cwd, deadline, *, tool_fd, **kwargs):
                    self.assertEqual(os.fstat(tool_fd).st_ino, tool_file.stat().st_ino)
                    self.assertEqual(cwd, root); self.assertIn("local?root="+str(store), argv)
                    if "--dump-db" not in argv: self.assertIn("--offline", argv)
                    self.assertNotIn("--impure", argv)
                    self.assertEqual(env["PATH"], ""); commands.append(argv)
                    if "eval" in argv:
                        return model.seed.encoded({"drvPath": self.dependency if wrong is True else self.proposal,
                            "outputPath": self.result, "channel": "development", "identity": "ai.xoxd.omux.dev",
                            "scope": "isolated-home-manager-generation-derivation-only"})
                    if "--dump-db" in argv: return dump
                    self.assertIn("derivation", argv); self.assertIn("--recursive", argv)
                    if wrong == "mutation":
                        leaf = root/"generation-modules"/model.MODULE
                        leaf.chmod(0o600); leaf.write_bytes(b"changed public module"); leaf.chmod(0o444)
                    return model.seed.encoded(self.value)
                generation = model.Generation(modules)
                failure = None
                try:
                    with patch.object(model.seed, "resolve_member", side_effect=lambda unused, tool: tool), \
                            patch.object(model.inputs, "shape", return_value=self.records), \
                            patch.object(model, "generated_inputs", return_value=({}, {})):
                        if wrong is True or wrong == "mutation":
                            with self.assertRaises(ValueError): generation(value, Owned(), store, Declared(),
                                float(time.monotonic()+120), runner)
                            self.assertEqual(len(commands), 3 if wrong is True else 4)
                        else:
                            result = generation(value, Owned(), store, Declared(), float(time.monotonic()+120), runner)
                            self.assertEqual(len(commands), 4)
                            self.assertEqual(result["missingDeclaredRoots"], [self.output])
                            self.assertEqual(result["proposedDerivation"], self.proposal)
                            self.assertIs(result["historicalInputDerivationAuthority"], False)
                            self.assertFalse(result["activated"])
                            self.assertFalse(result["generationRealized"])
                            for name, raw in modules.items(): self.assertEqual((root/"generation-modules"/name).read_bytes(), raw)
                except BaseException as error:
                    failure = error
                    raise
                finally:
                    cleanup = None
                    try: generation.close(float(time.monotonic()+120),
                        check=failure is None and (wrong is False or wrong == "historical"))
                    except BaseException as error: cleanup = error
                    try: (root/"generation-modules").chmod(0o700)
                    except BaseException as error:
                        if cleanup is None: cleanup = error
                    if cleanup is not None:
                        if failure is not None: raise failure from cleanup
                        raise cleanup

    def test_actual_main_cold_selector_refuses_before_platform_provenance_or_registration(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR")) as temporary:
            root = Path(temporary)
            files = {}
            for name in ("selection", "layout", "locked-seed", "artifact-selection", "pair-selection"):
                path = root/name; path.write_bytes(b"{}\n"); files[name] = str(path)
            (root/"selection").write_bytes(model.seed.encoded({"schemaVersion": 1,
                "kind": "omux-linux-hm-realization-input-selection-v1", "selection": None}))
            entry = time.monotonic_ns()
            argv = ["generation"]
            for name, path in files.items(): argv += ["--"+name, path]
            argv += ["--module", model.MODULE+"=/public/unavailable"]
            with patch.object(model.sys, "argv", argv), patch.dict(os.environ, {
                    "OMUX_HM_ROOT_ENTRY_NS": str(entry), "OMUX_HM_ROOT_DEADLINE_NS": str(entry+1200*10**9),
                    "OMUX_HM_RESERVED_PROFILE": model.PROFILE}), \
                    patch.object(model.private, "platform") as platform, patch.object(model, "provenance") as authority, \
                    patch.object(model.inputs, "qualify") as registration:
                with self.assertRaises(ValueError): model.main()
                platform.assert_not_called(); authority.assert_not_called(); registration.assert_not_called()

    def test_generated_public_drv_bytes_survive_owned_root_removal_in_request(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR")) as temporary:
            root = Path(temporary); directory = root/"nix/store"; directory.mkdir(parents=True, mode=0o700)
            drv = directory/self.proposal.rsplit("/", 1)[1]
            raw = b'Derive([],[],[],"x86_64-linux","/nix/store/public-builder",[],[])'
            drv.write_bytes(raw); drv.chmod(0o444)
            description = model.inputs.nar.describe(drv); description["root"] = self.proposal
            deadline = float(time.monotonic()+120)
            proof = model.inputs.nar.hash_descriptor(description,
                opener=lambda unused, unused2: model.inputs.regular(drv, deadline), deadline=deadline)
            record = [self.proposal, proof["narHash"], str(proof["narSize"]), "", "0"]
            actual = {self.proposal: {"record": record, "references": []}}
            value = {"roles": {name: self.source for name in ("home-manager", "nixpkgs", "artifact")}, "artifact": {"narHash": "sha256-"+"A"*43+"="},
                "descriptors": {self.source: {"nodes": []}}}
            with patch.object(model.inputs, "shape", return_value={}):
                retained, facts = model.generated_inputs(value, root, actual, deadline)
            drv.unlink()
            member = retained[self.proposal]["content"]["files"][""]
            self.assertEqual(model.base64.b64decode(member["base64"], validate=True), raw)
            self.assertEqual(member["sha256"], hashlib.sha256(raw).hexdigest())
            self.assertEqual(retained[self.proposal]["record"], record)
            self.assertEqual(set(facts), {str(drv)})

    def test_existing_selected_drv_is_still_retained_when_actual_generation_reuses_it(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR")) as temporary:
            root = Path(temporary); directory = root/"nix/store"; directory.mkdir(parents=True, mode=0o700)
            drv = directory/self.proposal.rsplit("/", 1)[1]; raw = b"public selected drv bytes"
            drv.write_bytes(raw); drv.chmod(0o444)
            description = model.inputs.nar.describe(drv); description["root"] = self.proposal
            deadline = float(time.monotonic()+120)
            proof = model.inputs.nar.hash_descriptor(description,
                opener=lambda unused, unused2: model.inputs.regular(drv, deadline), deadline=deadline)
            row = {"record": [self.proposal, proof["narHash"], str(proof["narSize"]), "", "0"], "references": []}
            records = {self.proposal: row}
            value = {"roles": {name: self.source for name in ("home-manager", "nixpkgs", "artifact")},
                "descriptors": {self.source: {"nodes": []}}}
            with patch.object(model.inputs, "shape", return_value=records):
                retained, unused = model.generated_inputs(value, root, records, deadline, required_metadata=(self.proposal,))
            self.assertEqual(model.base64.b64decode(retained[self.proposal]["content"]["files"][""]["base64"]), raw)

    def test_generated_metadata_suffix_nar_registration_and_writable_leaf_refuse(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR")) as temporary:
            root = Path(temporary); directory = root/"nix/store"; directory.mkdir(parents=True, mode=0o700)
            drv = directory/self.proposal.rsplit("/", 1)[1]; drv.write_bytes(b"public drv"); drv.chmod(0o444)
            description = model.inputs.nar.describe(drv); description["root"] = self.proposal
            deadline = float(time.monotonic()+120)
            proof = model.inputs.nar.hash_descriptor(description,
                opener=lambda unused, unused2: model.inputs.regular(drv, deadline), deadline=deadline)
            record = [self.proposal, proof["narHash"], str(proof["narSize"]), "", "0"]
            value = {"roles": {name: self.source for name in ("home-manager", "nixpkgs", "artifact")}, "artifact": {"narHash": "sha256-"+"A"*43+"="},
                "descriptors": {self.source: {"nodes": []}}}
            for fault in ("hash", "size", "mode", "scratch"):
                with self.subTest(fault=fault):
                    row = list(record)
                    if fault == "hash": row[1] = "sha256:"+"0"*64
                    elif fault == "size": row[2] = str(int(row[2])+1)
                    elif fault == "mode": drv.chmod(0o600)
                    else:
                        drv.chmod(0o600); drv.write_bytes(str(root.parent).encode()); drv.chmod(0o444)
                    try:
                        with patch.object(model.inputs, "shape", return_value={}):
                            with self.assertRaises(ValueError): model.generated_inputs(value, root,
                                {self.proposal: {"record": row, "references": []}}, deadline)
                    finally:
                        drv.chmod(0o600); drv.write_bytes(b"public drv"); drv.chmod(0o444)

    def test_actual_dump_parser_duplicate_truncated_and_unknown_reference_refuse(self):
        row = [self.proposal, "0"*64, "1", "", "0"]
        raw = ("\n".join(row)+"\n").encode()
        self.assertEqual(set(model.registration(raw)), {self.proposal})
        for bad in (raw+raw, b"/nix/store/truncated\n", ("\n".join(row[:-1]+["1",self.output])+"\n").encode()):
            with self.assertRaises(ValueError): model.registration(bad)

    def test_actual_final_writer_close_changed_bytes_or_same_byte_replacement_refuses_before_child(self):
        for fault in ("bytes", "replacement"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR")) as temporary:
                root = Path(temporary)
                class Owned:
                    path = root
                    def recheck(self):
                        model.require(root.lstat().st_uid == os.getuid() and root.lstat().st_mode & 0o777 == 0o700)
                modules = {name: b"public original module" for name in (*model.inputs.MODULES, model.MODULE)}
                generation = model.Generation(modules)
                opened, closed, fired = [], [], []
                actual_open, actual_dup, actual_close = os.open, os.dup, os.close
                def capture(*args, **kwargs):
                    fd = actual_open(*args, **kwargs); opened.append(fd); return fd
                def duplicate(fd):
                    result = actual_dup(fd); opened.append(result); return result
                def close(fd):
                    info = os.fstat(fd)
                    target = root/"generation-modules"/model.MODULE
                    match = stat.S_ISREG(info.st_mode) and target.exists() and info.st_ino == target.stat().st_ino
                    actual_close(fd); closed.append(fd)
                    if match and not fired:
                        fired.append(True)
                        directory = target.parent; directory.chmod(0o700)
                        try:
                            if fault == "replacement":
                                displaced = directory/(model.MODULE+".displaced")
                                target.rename(displaced)
                                self.assertEqual(displaced.stat().st_ino, info.st_ino)
                                self.assertEqual(displaced.stat().st_nlink, 1)
                                target.write_bytes(modules[model.MODULE])
                                self.assertNotEqual(target.stat().st_ino, info.st_ino)
                            else:
                                target.chmod(0o600); target.write_bytes(b"public changed module")
                            target.chmod(0o444)
                        finally: directory.chmod(0o555)
                runner = Mock(side_effect=AssertionError("evaluator must not start"))
                with patch.object(model.os, "open", capture), patch.object(model.os, "dup", duplicate), \
                        patch.object(model.os, "close", close):
                    with self.assertRaises(ValueError): generation({}, Owned(), root, None,
                        float(time.monotonic()+120), runner)
                self.assertEqual(fired, [True]); runner.assert_not_called()
                self.assertEqual(len(opened), 11)
                self.assertEqual(sorted(opened), sorted(closed))
                for fd in opened:
                    with self.assertRaises(OSError): os.fstat(fd)
                (root/"generation-modules").chmod(0o700)

    def test_original_writer_close_failure_attempts_all_duplicates_once_and_keeps_first_cause(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR")) as temporary:
            root = Path(temporary)
            class Owned:
                path = root
                def recheck(self): pass
            modules = {name: b"public original module" for name in (*model.inputs.MODULES, model.MODULE)}
            opened, closed, fired = [], [], []
            actual_open, actual_dup, actual_close = os.open, os.dup, os.close
            primary = OSError("public original writer close fault")
            def capture(*args, **kwargs):
                fd = actual_open(*args, **kwargs); opened.append(fd); return fd
            def duplicate(fd):
                result = actual_dup(fd); opened.append(result); return result
            def close(fd):
                info = os.fstat(fd); actual_close(fd); closed.append(fd)
                if stat.S_ISREG(info.st_mode) and not fired:
                    fired.append(True); raise primary
            runner = Mock(side_effect=AssertionError("evaluator must not start"))
            with patch.object(model.os, "open", capture), patch.object(model.os, "dup", duplicate), \
                    patch.object(model.os, "close", close):
                with self.assertRaises(OSError) as error: model.Generation(modules)({}, Owned(), root, None,
                    float(time.monotonic()+120), runner)
            self.assertIs(error.exception, primary); runner.assert_not_called()
            self.assertEqual(len(opened), 11); self.assertEqual(sorted(opened), sorted(closed))
            for fd in opened:
                with self.assertRaises(OSError): os.fstat(fd)
            (root/"generation-modules").chmod(0o700)

    def test_original_duplicate_and_root_remain_held_through_admission_and_final_close_fault_refuses(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR")) as temporary:
            root = Path(temporary)
            class Owned:
                path = root
                def recheck(self): pass
            modules = {name: b"public original module" for name in (*model.inputs.MODULES, model.MODULE)}
            owner = model.module_owner.Modules(Owned(), modules)
            deadline = float(time.monotonic()+120)
            failure = None
            try:
                owner.create(deadline); owner.admit(deadline)
                held = [slot.fd for slot in owner.readers.values()] + [owner.root.fd]
                self.assertEqual(len(held), 6)
                for name, slot in owner.readers.items():
                    self.assertIsNone(owner.writers[name].fd)
                    self.assertEqual(model.inputs.facts(os.fstat(slot.fd)), slot.witness)
                    self.assertEqual(slot.witness, model.inputs.facts((owner.path/name).lstat()))
                actual_close = os.close; fired = []
                def close(fd):
                    actual_close(fd)
                    if fd == held[-1] and not fired:
                        fired.append(True); owner.path.chmod(0o700)
                        target = owner.path/model.MODULE; target.chmod(0o600); target.write_bytes(b"late changed body"); target.chmod(0o444)
                        owner.path.chmod(0o555)
                with patch.object(model.os, "close", close):
                    with self.assertRaises(ValueError): owner.close(deadline)
                self.assertEqual(fired, [True])
                for fd in held:
                    with self.assertRaises(OSError): os.fstat(fd)
            except BaseException as error:
                failure = error
                raise
            finally:
                cleanup = None
                try: owner.close(deadline, check=False)
                except BaseException as error: cleanup = error
                try: owner.path.chmod(0o700)
                except BaseException as error:
                    if cleanup is None: cleanup = error
                if cleanup is not None:
                    if failure is not None: raise failure from cleanup
                    raise cleanup


if __name__ == "__main__":
    unittest.main()
