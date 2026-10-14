"""Real public filesystem/registration models; no Nix child or HM activation."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest.mock import patch

import home_manager_realization_inputs as model


class ClosureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR"))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.base = self.root / "declared"; self.base.mkdir(mode=0o700)
        self.deadline = float(time.monotonic() + 120)
        self.names = {name: "/nix/store/" + character*32 + "-" + suffix for name, character, suffix in (
            ("home-manager", "a", "hm-source"), ("nixpkgs", "b", "nixpkgs-source"),
            ("artifact", "c", "omux-artifact"), ("derivation", "d", "generation.drv"),
            ("bash", "e", "bash"), ("nix", "f", "nix"), ("builder", "g", "builder-input"))}
        physical = {}; descriptions = {}; registration = []; pins = {}
        artifact_rows = []
        manifest = {"schemaVersion": 1, "target": "x86_64-linux", "distribution": "portable-linux",
            "product": {"status": "experimental"}, "channel": "development",
            "provenance": {"sourceRevision": "1"*40, "sourceDirty": False}, "artifacts": artifact_rows}
        for index, (name, logical) in enumerate(self.names.items()):
            actual = self.root / ("physical-" + str(index)); physical[logical] = str(actual)
            if name == "derivation": actual.write_bytes(b'Derive([],[],[],"x86_64-linux","/fixture",[],[])'); actual.chmod(0o444)
            else:
                actual.mkdir(mode=0o700)
                if name in ("bash", "nix"):
                    (actual/"bin").mkdir(mode=0o700)
                    for tool in (["bash"] if name == "bash" else ["nix", "nix-store"]):
                        (actual/"bin"/tool).write_bytes(b"public synthetic executable"); (actual/"bin"/tool).chmod(0o555)
                    (actual/"bin").chmod(0o555)
                elif name == "artifact":
                    (actual/"bin").mkdir(mode=0o700)
                    for tool in ("omux", "omuxd", "omux-native-host", "omux-control"):
                        raw = ("public fixture " + tool).encode(); (actual/"bin"/tool).write_bytes(raw); (actual/"bin"/tool).chmod(0o555)
                        artifact_rows.append({"path": "bin/"+tool, "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(), "mode": "0755"})
                    (actual/"release-manifest.json").write_bytes(model.seed.encoded(manifest)); (actual/"release-manifest.json").chmod(0o444)
                    (actual/"bin").chmod(0o555)
                else:
                    (actual/"public").write_bytes(b"public synthetic root"); (actual/"public").chmod(0o444)
                    (actual/"inert").symlink_to("/unqualified/nonexistent/public-link")
                actual.chmod(0o555)
            description = model.nar.describe(actual); description["root"] = logical; descriptions[logical] = description
            proof = model.nar.hash_descriptor(description,
                opener=lambda unused, relative, actual=actual: model.nar.open_regular(str(actual), relative), deadline=self.deadline)
            pins[name] = "sha256-" + base64.b64encode(bytes.fromhex(proof["narHash"][7:])).decode()
            references = [self.names["builder"]] if name == "derivation" else []
            registration.append((logical, [logical, proof["narHash"], str(proof["narSize"]), "", str(len(references))] + references))
        files = []
        for logical in sorted(descriptions):
            for node in descriptions[logical]["nodes"]:
                if node["type"] == "regular":
                    files.append({"root": logical, "path": node["path"], "alias": "members/"+str(len(files)),
                        "source": physical[logical] + ("/"+node["path"] if node["path"] else "")})
        (self.base/"members").mkdir(mode=0o700)
        for row in files: (self.base/row["alias"]).symlink_to(row["source"])
        roles = {name: self.names[name] for name in ("home-manager", "nixpkgs", "artifact", "derivation")}
        roles.update(bash=self.names["bash"]+"/bin/bash", nix=self.names["nix"]+"/bin/nix", nix_store=self.names["nix"]+"/bin/nix-store")
        self.value = {"schemaVersion": 1, "kind": model.KIND, "system": "x86_64-linux",
            "sourceCommit": "1"*40, "sourceGraphSha256": "2"*64,
            "moduleSha256": {name: "3"*64 for name in model.MODULES}, "roles": roles,
            "roots": sorted(descriptions), "registration": "".join("\n".join(row)+"\n" for unused,row in sorted(registration)),
            "descriptors": descriptions, "files": files, "physicalRoots": physical,
            "pair": {name: {"revision": "4"*40, "narHash": pins[name]} for name in ("home-manager", "nixpkgs")},
            "artifact": {"narHash": pins["artifact"], "manifestSha256": hashlib.sha256(model.seed.encoded(manifest)).hexdigest(),
                "sourceRevision": "1"*40, "channel": "development"}}
        # Only pinned pair constants are substituted for tiny inert NAR fixtures;
        # no original source/provenance/activation success is impersonated.
        self.addCleanup(patch.stopall)
        patch.object(model, "PINS", {name: ("4"*40, pins[name]) for name in ("home-manager", "nixpkgs")}).start()

    def test_complete_closure_includes_derivation_builder_not_only_tools_and_verifies_real_nars(self):
        inputs = model.Inputs(self.value, self.base, self.deadline)
        records, size = model.verify(self.value, inputs.open, self.deadline)
        model.artifact_bytes(self.value, inputs.open, self.deadline); inputs.check()
        self.assertEqual(set(records), set(self.names.values()))
        self.assertGreater(size, 0)
        self.assertIn(self.names["builder"], records[self.names["derivation"]]["references"])
        self.assertEqual(len(inputs.observed), len(self.value["files"]))

    def test_missing_extra_reference_and_non_derivation_roles_refuse(self):
        for mutate in ("missing", "extra", "role", "mode"):
            with self.subTest(mutate=mutate):
                value = copy.deepcopy(self.value)
                if mutate == "missing": value["roots"].remove(self.names["builder"])
                elif mutate == "extra": value["roots"].append("/nix/store/"+"h"*32+"-foreign")
                elif mutate == "role": value["roles"]["derivation"] = self.names["bash"]
                else: value["system"] = "aarch64-darwin"
                with self.assertRaises((ValueError, KeyError)): model.shape(value)

    def test_full_nar_actual_mutation_and_wrong_public_manifest_sha_refuse(self):
        source = Path(self.value["physicalRoots"][self.names["builder"]])/"public"
        source.chmod(0o600); source.write_bytes(b"changed actual content"); source.chmod(0o444)
        with self.assertRaises(ValueError): model.verify(self.value, model.Inputs(self.value,self.base,self.deadline).open,self.deadline)
        value = copy.deepcopy(self.value); value["artifact"]["manifestSha256"] = "0"*64
        with self.assertRaises(ValueError): model.artifact_bytes(value, model.Inputs(value,self.base,self.deadline).open,self.deadline)

    def test_alias_substitution_same_bytes_and_same_byte_inode_replacement_refuse_current_observation(self):
        inputs = model.Inputs(self.value,self.base,self.deadline); model.verify(self.value,inputs.open,self.deadline)
        row = self.value["files"][0]; alias=self.base/row["alias"]; physical=Path(row["source"])
        duplicate=self.root/"foreign-copy"; duplicate.write_bytes(physical.read_bytes()); duplicate.chmod(0o444)
        alias.unlink(); alias.symlink_to(duplicate)
        with self.assertRaises(ValueError): inputs.check()
        alias.unlink(); alias.symlink_to(physical)
        with self.assertRaises(ValueError): inputs.check() # Original alias inode changed.

    def test_read_fd_fstat_failure_closes_actual_acquired_descriptor_once(self):
        row=self.value["files"][0]
        actual_open=os.open; actual_fstat=os.fstat; actual_close=os.close
        for secondary in (False,True):
            with self.subTest(secondary=secondary):
                inputs=model.Inputs(self.value,self.base,self.deadline)
                acquired=[];closed=[];active={};leaf=[None]
                first=MemoryError("public initial regular fstat fault")
                cleanup=OSError("public secondary close fault")
                def opening(path,flags,*args,**kwargs):
                    fd=actual_open(path,flags,*args,**kwargs)
                    try:
                        ordinal=len(acquired);acquired.append(fd);active[fd]=ordinal
                        if not flags & os.O_DIRECTORY:leaf[0]=fd
                    except BaseException:
                        actual_close(fd)
                        raise
                    return fd
                def failing(fd):
                    if fd==leaf[0]:raise first
                    return actual_fstat(fd)
                def closing(fd):
                    actual_close(fd)
                    closed.append(active.pop(fd))
                    if secondary and fd==leaf[0]:raise cleanup
                with patch.object(model.os,"open",side_effect=opening), \
                        patch.object(model.os,"fstat",side_effect=failing), \
                        patch.object(model.os,"close",side_effect=closing):
                    with self.assertRaises(MemoryError) as failure:
                        with inputs.open(row["root"],row["path"]):pass
                self.assertIs(failure.exception,first)
                self.assertIsNotNone(leaf[0])
                self.assertEqual(sorted(closed),list(range(len(acquired))))
                self.assertEqual(active,{})
                for fd in set(acquired):
                    with self.assertRaises(OSError):actual_fstat(fd)

    def test_copied_complete_tree_inert_links_and_late_namespace_or_mode_changes_refuse(self):
        inputs=model.Inputs(self.value,self.base,self.deadline); target=self.root/"private-copy"; target.mkdir(mode=0o700)
        directory=model.copy(self.value,target,inputs.open,self.deadline)
        model.verify_copy(self.value,directory,self.deadline)
        fixture=directory/self.names["builder"].rsplit("/",1)[1]
        self.assertEqual(os.readlink(fixture/"inert"),"/unqualified/nonexistent/public-link")
        fixture.chmod(0o700); (fixture/"extra").write_bytes(b"extra"); (fixture/"extra").chmod(0o444); fixture.chmod(0o555)
        with self.assertRaises(ValueError): model.verify_copy(self.value,directory,self.deadline)

    def test_exact_registration_readback_and_partial_wrong_hash_or_reference_refuse(self):
        records=model.shape(self.value)
        raw=self.value["registration"].replace("sha256:","").encode("ascii")
        actual=model.private.readback_records(raw,self.value["roots"])
        model.private.compare_readback(records,actual)
        for mutate in ("hash","refs","partial"):
            with self.subTest(mutate=mutate):
                wrong=copy.deepcopy(actual)
                if mutate=="hash": wrong[self.names["bash"]]["record"][1]="sha256:"+"0"*64
                elif mutate=="refs": wrong[self.names["derivation"]]["references"]=[]
                else: del wrong[self.names["builder"]]
                with self.assertRaises(ValueError): model.private.compare_readback(records,wrong)

    def test_registration_only_full_flow_records_no_realization_or_activation_and_disposes_private_root(self):
        calls=[]
        def runner(command,environment,cwd,deadline,**kwargs):
            calls.append((command,environment,cwd,kwargs))
            self.assertTrue(command[1:3]==["--store","local?root="+str(cwd/"private-store")])
            self.assertIn("tool_fd",kwargs); self.assertTrue(stat.S_ISREG(os.fstat(kwargs["tool_fd"]).st_mode))
            self.assertNotIn("build",command); self.assertNotIn("eval",command)
            self.assertEqual(environment["NIX_REMOTE"],"")
            if command[-1]=="--load-db": return b""
            return self.value["registration"].replace("sha256:","").encode("ascii")
        result,inputs=model.qualify(self.value,self.base,self.root,self.deadline,runner=runner)
        self.assertEqual([row[0][-1] for row in calls],["--load-db","--dump-db"])
        self.assertTrue(result["privateRootRemoved"]); self.assertFalse(calls[0][2].exists())
        for flag in ("homeManagerDerivationQualified","generationRealized","activated","updated","removed","serviceReady","browserInstalled"):
            self.assertIs(result[flag],False)
        inputs.check()

    def test_registration_child_refusal_preserves_primary_and_private_root_cleanup(self):
        calls=[]; first=ValueError("public registration failure")
        def runner(command,environment,cwd,deadline,**kwargs): calls.append(cwd); raise first
        with self.assertRaises(ValueError) as refused: model.qualify(self.value,self.base,self.root,self.deadline,runner=runner)
        self.assertIs(refused.exception,first); self.assertEqual(len(calls),1); self.assertFalse(calls[0].exists())

    def test_original_expiry_refuses_before_regular_bytes(self):
        inputs=model.Inputs(self.value,self.base,float(time.monotonic()-1)); row=self.value["files"][0]
        with patch.object(model,"regular",wraps=model.regular) as opening:
            with self.assertRaises(ValueError):
                with inputs.open(row["root"],row["path"]): pass
            self.assertEqual(opening.call_count,0)

    def test_copied_same_byte_leaf_replacement_and_permission_drift_refuse_original_copy_witness(self):
        inputs=model.Inputs(self.value,self.base,self.deadline); target=self.root/"private-witness"; target.mkdir(mode=0o700)
        directory=model.copy(self.value,target,inputs.open,self.deadline)
        expected=model.copy_facts(self.value,directory,self.deadline)
        destination=directory/self.names["builder"].rsplit("/",1)[1]
        leaf=destination/"public"; destination.chmod(0o700); leaf.rename(destination/"old-public")
        leaf.write_bytes((destination/"old-public").read_bytes()); leaf.chmod(0o444)
        (destination/"old-public").unlink(); destination.chmod(0o555)
        with self.assertRaises(ValueError):model.verify_copy(self.value,directory,self.deadline,expected)
        destination.chmod(0o700)
        with self.assertRaises(ValueError):model.copy_facts(self.value,directory,self.deadline)

    def test_actual_partial_copy_write_failure_closes_writer_and_keeps_first_error(self):
        inputs=model.Inputs(self.value,self.base,self.deadline); target=self.root/"copy-fault"; target.mkdir(mode=0o700)
        actual_open=os.open; actual_close=os.close; acquired=[]; closed=[]; first=OSError("public write fault")
        def opening(path,flags,*args,**kwargs):
            fd=actual_open(path,flags,*args,**kwargs)
            if flags & os.O_WRONLY:acquired.append(fd)
            return fd
        def close(fd):
            if fd in acquired:closed.append(fd)
            return actual_close(fd)
        with patch.object(model.os,"open",side_effect=opening),patch.object(model.os,"write",side_effect=first),patch.object(model.os,"close",side_effect=close):
            with self.assertRaises(OSError) as failure:model.copy(self.value,target,inputs.open,self.deadline)
        self.assertIs(failure.exception,first);self.assertEqual(closed,acquired)
        for fd in acquired:
            with self.assertRaises(OSError):os.fstat(fd)

    def test_selected_locked_pair_hash_cannot_be_replaced_by_self_reported_all_tools(self):
        value=copy.deepcopy(self.value);value["pair"]["home-manager"]["narHash"]="sha256-"+base64.b64encode(b"\0"*32).decode()
        with self.assertRaises(ValueError):model.shape(value)
        value=copy.deepcopy(self.value);value["roles"]["derivation"]=value["roles"]["nix"].rsplit("/bin/",1)[0]
        with self.assertRaises(ValueError):model.shape(value)

    def test_locked_bootstrap_tools_records_and_canonical_runtime_locations_are_independent(self):
        value=copy.deepcopy(self.value)
        roots=sorted([self.names["bash"],self.names["nix"]])
        records=model.shape(value)
        locked={"schemaVersion":1,"kind":model.seed.KIND,"system":"x86_64-linux",
            "tools":{name:value["roles"][name] for name in ("bash","nix","nix_store")},
            "roots":roots,"registration":"".join("\n".join(records[root]["record"])+"\n" for root in roots),
            "descriptors":{root:value["descriptors"][root] for root in roots},"files":[],
            "regular_bytes":0,"metadata_sha256":{name:"0"*64 for name in ("native","paths","registration")}}
        for root in roots:
            value["physicalRoots"][root]=root
            for node in locked["descriptors"][root]["nodes"]:
                if node["type"]=="regular":
                    source=root+("/"+node["path"] if node["path"] else "")
                    locked["files"].append({"source":source,"alias":"private-store-inputs/"+str(len(locked["files"]))})
                    locked["regular_bytes"]+=node["size"]
        for row in value["files"]:
            row["source"]=value["physicalRoots"][row["root"]]+("/"+row["path"] if row["path"] else "")
        self.assertEqual(model.locked_tools(value,locked),model.seed.sha(model.seed.encoded(locked)))
        wrong=copy.deepcopy(value);wrong["physicalRoots"][roots[0]]=self.value["physicalRoots"][roots[0]]
        for row in wrong["files"]:
            row["source"]=wrong["physicalRoots"][row["root"]]+("/"+row["path"] if row["path"] else "")
        with self.assertRaises(ValueError):model.locked_tools(wrong,locked)
        wrong=copy.deepcopy(locked);wrong["registration"]=wrong["registration"].replace(records[roots[0]]["record"][1],"sha256:"+"0"*64)
        with self.assertRaises(ValueError):model.locked_tools(value,wrong)

    def test_declared_control_alias_reads_original_physical_body_and_refuses_read_boundary_drift(self):
        physical=self.root/"public-control.json";physical.write_bytes(b'{"public":true}\n');physical.chmod(0o444)
        alias=self.base/"control.json";alias.symlink_to(physical)
        captured=model.control_capture(alias)
        self.assertEqual(model.control_read(alias,65536,captured,self.deadline),physical.read_bytes())
        replacement=self.root/"same-control.json";replacement.write_bytes(physical.read_bytes());replacement.chmod(0o444)
        alias.unlink();alias.symlink_to(replacement)
        with self.assertRaises(ValueError):model.control_read(alias,65536,captured,self.deadline)
        alias.unlink();alias.symlink_to(physical)
        captured=model.control_capture(alias)
        actual_read=os.read;changed=[False]
        def reading(fd,bound):
            raw=actual_read(fd,bound)
            if not changed[0]:
                changed[0]=True
                physical.chmod(0o600);physical.write_bytes(b'{"public":false}\n');physical.chmod(0o444)
            return raw
        with patch.object(model.os,"read",side_effect=reading):
            with self.assertRaises(ValueError):model.control_read(alias,65536,captured,self.deadline)
        self.assertTrue(changed[0])
        with self.assertRaises(ValueError):model.control_check(alias,captured)

    def test_tracked_input_provenance_differs_from_current_consumer_without_cycle_or_env_rebase(self):
        layout=self.root/"historical-layout.json";wire=model.seed.encoded(self.value)
        layout.write_bytes(wire);layout.chmod(0o444)
        selector=self.root/"selection.json"
        selection={"schemaVersion":1,"kind":"omux-linux-hm-realization-input-selection-v1",
            "selection":{"path":str(layout),"sha256":model.seed.sha(wire),"bytes":len(wire)}}
        selector.write_bytes(model.seed.encoded(selection));selector.chmod(0o444)
        alias=self.base/"layout.json";alias.symlink_to(layout)
        captured=model.control_capture(alias)
        self.assertEqual(model.seed.sha(model.control_read(alias,model.seed.MAX_METADATA,captured,self.deadline)),
            selection["selection"]["sha256"])
        environment={"OMUX_HM_REALIZATION_SOURCE_COMMIT":"4"*40,
            "OMUX_HM_REALIZATION_GRAPH_SHA256":"5"*64}
        current=model.consumer_context(environment)
        self.assertNotEqual(current["sourceCommit"],self.value["sourceCommit"])
        self.assertNotEqual(current["sourceGraphSha256"],self.value["sourceGraphSha256"])
        self.assertEqual(model.consumer_context(environment,current),current)
        for key in environment:
            wrong={**environment,key:("6"*40 if key.endswith("COMMIT") else "7"*64)}
            with self.assertRaises(ValueError):model.consumer_context(wrong,current)
        wrong=copy.deepcopy(self.value);wrong["sourceCommit"]="9"*40
        wrong["artifact"]["sourceRevision"]="9"*40
        with self.assertRaises(ValueError):
            model.artifact_bytes(wrong,model.Inputs(wrong,self.base,self.deadline).open,self.deadline)
        missing={**environment};del missing["OMUX_HM_REALIZATION_SOURCE_COMMIT"]
        with self.assertRaises(ValueError):model.consumer_context(missing)

    def test_actual_short_progress_raw_controls_and_manifest_suffix_bound_and_early_eof_are_complete(self):
        physical=self.root/"bounded-control.json";payload=b'{"public":true}\n'
        physical.write_bytes(payload);physical.chmod(0o444)
        alias=self.base/"bounded-control.json";alias.symlink_to(physical)
        captured=model.control_capture(alias);actual_read=os.read;calls=[]
        def short(fd,bound):
            calls.append(bound)
            return actual_read(fd,min(bound,3))
        with patch.object(model.os,"read",side_effect=short):
            self.assertEqual(model.control_read(alias,65536,captured,self.deadline),payload)
            model.artifact_bytes(self.value,model.Inputs(self.value,self.base,self.deadline).open,self.deadline)
        self.assertGreater(len(calls),3)
        self.assertTrue(all(0<bound<=65536 for bound in calls))
        with patch.object(model.os,"read",return_value=b""):
            with self.assertRaises(ValueError):model.control_read(alias,65536,captured,self.deadline)
        with self.assertRaises(ValueError):model.control_read(alias,len(payload)-1,captured,self.deadline)
        physical.chmod(0o600);physical.write_bytes(payload+b'OTHER');physical.chmod(0o444)
        captured=model.control_capture(alias)
        with patch.object(model.os,"read",side_effect=short):
            raw=model.control_read(alias,65536,captured,self.deadline)
            self.assertEqual(raw,payload+b'OTHER')
            with self.assertRaises(ValueError):model.json.loads(raw,object_pairs_hook=model.seed.unique)
        manifest_root=self.value["roles"]["artifact"]
        manifest=Path(self.value["physicalRoots"][manifest_root])/"release-manifest.json"
        original=manifest.read_bytes();manifest.chmod(0o600);manifest.write_bytes(original+b'OTHER');manifest.chmod(0o444)
        value=copy.deepcopy(self.value)
        next(node for node in value["descriptors"][manifest_root]["nodes"] if node["path"]=="release-manifest.json")["size"]=len(original)+5
        with patch.object(model.os,"read",side_effect=short):
            with self.assertRaises(ValueError):model.artifact_bytes(value,model.Inputs(value,self.base,self.deadline).open,self.deadline)
        manifest.chmod(0o600);manifest.write_bytes(b'x'*65537);manifest.chmod(0o444)
        next(node for node in value["descriptors"][manifest_root]["nodes"] if node["path"]=="release-manifest.json")["size"]=65537
        with patch.object(model.os,"read",side_effect=short):
            with self.assertRaises(ValueError):model.artifact_bytes(value,model.Inputs(value,self.base,self.deadline).open,self.deadline)
        with self.assertRaises(ValueError):model.raw_metadata(physical,65536,self.deadline,proc_status=True)


if __name__ == "__main__": unittest.main()
