"""Actual FD and closed receipt predicates; no synthetic build/SDK qualification."""
from contextlib import ExitStack
import copy
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import codex_native_owned_history_cli as cli
import owned_history_runtime as proof
import owned_history_native_tui_runtime as reader
import guard_native_owned_history_cli_reserved as guard


class CustodyModels(unittest.TestCase):
    def owner(self):
        return proof.Held(time.monotonic()+60,time.monotonic_ns()+60*10**9)

    def fixture(self,root,name="member",raw=b"actual-owned-public-bytes",mode=0o444):
        path = root/name
        path.write_bytes(raw); path.chmod(mode)
        return path

    def test_actual_full_read_hash_and_same_byte_inode_replacement_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); path = self.fixture(root)
            with self.owner() as owner:
                self.assertEqual(owner.add(path,128,expected=proof.sha(path.read_bytes()),size=path.stat().st_size),path.read_bytes())
                fd = owner.files[path]["fd"]
                replacement = self.fixture(root,"replacement")
                os.replace(replacement,path)
                with self.assertRaises(ValueError): owner.full()
            with self.assertRaises(OSError): os.fstat(fd)

    def test_actual_late_inplace_mutation_refuses_after_other_reads(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve(); first=self.fixture(root); last=self.fixture(root,"last",b"last")
            with self.owner() as owner:
                owner.add(first,128); owner.add(last,128)
                first.chmod(0o600); first.write_bytes(b"x"*first.stat().st_size); first.chmod(0o444)
                with self.assertRaises(ValueError): owner.fence()

    def test_actual_alias_retarget_same_bytes_refuses_original_named_link(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve(); physical=root/"physical"; physical.mkdir()
            first=self.fixture(physical); second=self.fixture(physical,"second")
            aliases=root/"aliases"; aliases.mkdir(); alias=aliases/"selected"; alias.symlink_to(first)
            with self.owner() as owner:
                owner.add(alias,128); alias.unlink(); alias.symlink_to(second)
                with self.assertRaises(ValueError): owner.raw(alias)

    def test_actual_parent_replacement_refuses_original_ancestry(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve(); parent=root/"parent"; parent.mkdir(); path=self.fixture(parent)
            with self.owner() as owner:
                owner.add(path,128); parent.rename(root/"original"); parent.mkdir(); self.fixture(parent)
                with self.assertRaises(ValueError): owner.fence()

    def test_actual_zero_length_stream_and_partial_pread_keep_eof_and_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve(); path=self.fixture(root,raw=b"abcdef"); empty=self.fixture(root,"empty",b"")
            real=os.pread
            with self.owner() as owner:
                with patch.object(proof.os,"pread",side_effect=lambda fd,n,offset:real(fd,min(n,2),offset)):
                    self.assertEqual(owner.add(path,128),b"abcdef")
                self.assertEqual(owner.add(empty,128),b"")
                owner.full()

    def test_eof_growth_after_exact_initial_size_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve(); path=self.fixture(root)
            with self.owner() as owner:
                owner.add(path,128)
                real=os.pread
                def read(fd,n,offset):
                    if n==1 and offset==owner.files[path]["size"]: return b"foreign"
                    return real(fd,n,offset)
                with patch.object(proof.os,"pread",side_effect=read):
                    with self.assertRaises(ValueError): owner.raw(path)

    def test_slot_registration_before_or_after_insertion_acquires_no_fd(self):
        class Fail(list):
            def __init__(self,after): super().__init__(); self.after=after
            def append(self,value):
                if self.after: super().append(value)
                raise MemoryError("model-only")
        for after in (False,True):
            with self.subTest(after=after):
                owner=self.owner(); owner.slots=Fail(after)
                with patch.object(proof.os,"open") as opened:
                    with self.assertRaises(MemoryError): owner.open("/",os.O_RDONLY|os.O_DIRECTORY)
                opened.assert_not_called(); owner.close()

    def test_actual_close_error_drains_once_and_preserves_body_first_cause(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve(); first=self.fixture(root); second=self.fixture(root,"second")
            owner=self.owner()
            try:
                owner.add(first,128); owner.add(second,128)
                fds=[slot.fd for slot in owner.slots if slot.fd is not None]; closed=[]; real=os.close
                original=ValueError("body"); cleanup=[]
                def close(fd):
                    closed.append(fd); real(fd)
                    if len(closed)==1:
                        cleanup.append(OSError("model-only-after-real-close")); raise cleanup[0]
                with patch.object(proof.os,"close",side_effect=close):
                    with self.assertRaises(ValueError) as observed:
                        with owner: raise original
                self.assertIs(observed.exception,original); self.assertEqual(set(closed),set(fds)); self.assertEqual(len(closed),len(fds))
                self.assertIs(observed.exception.__cause__,cleanup[0])
                for fd in fds:
                    with self.assertRaises(OSError): os.fstat(fd)
            finally: owner.close()

    def test_actual_final_close_error_is_fatal_on_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve(); owner=self.owner()
            try:
                owner.add(self.fixture(root),128)
                real=os.close; calls=[]
                def close(fd):
                    calls.append(fd); real(fd)
                    if len(calls)==1: raise OSError("model-only")
                with patch.object(proof.os,"close",side_effect=close):
                    with self.assertRaises(OSError): owner.__exit__(None,None,None)
                self.assertTrue(owner.closed)
            finally: owner.close()

    def test_original_cutoff_refuses_without_rebasing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve(); owner=self.owner(); path=self.fixture(root)
            try:
                owner.add(path,128); cutoff=owner.deadline
                with patch.object(proof.time,"monotonic",return_value=cutoff):
                    with self.assertRaises(ValueError): owner.full()
                self.assertEqual(owner.deadline,cutoff)
            finally: owner.close()

    def test_foreign_uid_writable_mode_hash_and_byte_bounds_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve(); path=self.fixture(root)
            for kwargs in ({"maximum":1},{"maximum":128,"expected":"1"*64,"size":path.stat().st_size},
                           {"maximum":128,"owner":os.getuid()+1}):
                with self.owner() as owner:
                    with self.assertRaises(ValueError): owner.add(path,**kwargs)
            path.chmod(0o644)
            with self.owner() as owner:
                with self.assertRaises(ValueError): owner.add(path,128)


class PublicationModels(unittest.TestCase):
    owner=CustodyModels.owner
    fixture=CustodyModels.fixture
    # No fake package/model success: these seams call the actual filesystem
    # publication and terminal owners with bounded diagnostic bytes only.
    def test_prepared_transform_sibling_keeps_original_compiler_parent(self):
        with tempfile.TemporaryDirectory() as temporary:
            work=Path(temporary).resolve()/"work"; cli.prepare_work(work)
            binary=self.fixture(work,"binary"); private=work/"package-transform"
            with self.owner() as owner:
                owner.add(binary,128); anchor=owner.parents[work][1]
                copied=self.fixture(private,"codex"); copied.unlink()
                owner.full(); self.assertEqual(owner.parents[work][1],anchor)
                self.assertTrue(private.is_dir())

    def test_publication_joins_creators_and_refuses_close_mutation_or_replacement(self):
        for fault in (None,"bytes","replacement"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary).resolve(); output=root/cli.OUTPUT; output.mkdir(mode=0o700)
                bodies={name:b"public-"+name.encode() for name in reader.OUTPUT_NAMES}
                bodies["cli-stdout.log"]=b""; bodies["cli-stderr.log"]=b""
                owner=self.owner(); real_open=os.open; real_close=os.close; acquired=[]; mutation=[]
                def opened(*args,**kwargs):
                    fd=real_open(*args,**kwargs); acquired.append(fd); return fd
                def closed(fd):
                    target=output/"runtime-receipt.json"
                    chosen=target.exists() and os.fstat(fd).st_ino==target.stat().st_ino
                    real_close(fd)
                    if fault is not None and chosen and not mutation:
                        mutation.append(fault)
                        if fault=="bytes":
                            target.chmod(0o600); target.write_bytes(b"x"*len(bodies[target.name])); target.chmod(0o444)
                        else:
                            output.chmod(0o700); replacement=self.fixture(output,"replacement",bodies[target.name])
                            os.replace(replacement,target); output.chmod(0o555)
                try:
                    with patch.object(proof.os,"open",side_effect=opened), patch.object(proof.os,"close",side_effect=closed):
                        if fault is None:
                            cli.publish_owned(owner,output,bodies); owner.full(); owner.close(); owner.named_fence()
                        else:
                            with self.assertRaises(ValueError):
                                with owner: cli.publish_owned(owner,output,bodies)
                    self.assertEqual(mutation,[] if fault is None else [fault])
                    self.assertTrue(owner.closed); self.assertEqual(output.stat().st_mode&0o777,0o555)
                    if fault=="replacement": self.assertEqual((output/"runtime-receipt.json").read_bytes(),bodies["runtime-receipt.json"])
                    for fd in acquired:
                        with self.assertRaises(OSError): os.fstat(fd)
                finally:
                    owner.close(); output.chmod(0o700)

    def test_prepared_output_directory_cannot_be_replaced_before_publication(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve(); output=root/cli.OUTPUT; output.mkdir(mode=0o700)
            owner=self.owner(); slot=proof.Slot()
            try:
                slot.fd=os.open(output,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
                anchor=proof.identity(os.fstat(slot.fd))
                output.rename(root/"original-output"); output.mkdir(mode=0o700)
                with self.assertRaises(ValueError): cli.publish_owned(owner,output,{name:b"public" for name in reader.OUTPUT_NAMES},prepared=(slot.fd,anchor))
                self.assertEqual(list(output.iterdir()),[])
                self.assertEqual(proof.identity(os.fstat(slot.fd)),proof.identity((root/"original-output").stat()))
            finally: slot.close(); owner.close()

    def test_final_control_close_mutation_refuses_previously_closed_reader_inputs(self):
        for role in ("package","installed"):
            for fault in ("bytes","replacement"):
                with self.subTest(role=role,fault=fault), tempfile.TemporaryDirectory() as temporary:
                    root=Path(temporary).resolve()
                    for name in ("package","installed","controls"): (root/name).mkdir()
                    package=self.fixture(root/"package"); installed=self.fixture(root/"installed")
                    control_file=self.fixture(root/"controls")
                    package_owner,installed_owner,control=self.owner(),self.owner(),self.owner()
                    actual=object.__new__(reader.Reader)
                    actual.owner,actual.installed,actual.retired_installed=package_owner,installed_owner,None
                    actual.closed=False
                    try:
                        package_owner.add(package,128); installed_owner.add(installed,128); control.add(control_file,128)
                        fds=[slot.fd for owner in (package_owner,installed_owner,control) for slot in owner.slots]
                        trigger=control.files[control_file]["fd"]; target=package if role=="package" else installed
                        original=target.stat().st_ino; mutation=[]; real=os.close
                        def close(fd):
                            real(fd)
                            if fd==trigger:
                                mutation.append(fd)
                                if fault=="bytes":
                                    target.chmod(0o600); target.write_bytes(b"x"*target.stat().st_size); target.chmod(0o444)
                                else: os.replace(self.fixture(target.parent,"replacement"),target)
                        actual.close()
                        with patch.object(proof.os,"close",side_effect=close): control.close()
                        with self.assertRaises(ValueError): actual.terminal()
                        self.assertEqual(mutation,[trigger]); self.assertTrue(actual.closed)
                        if fault=="replacement": self.assertNotEqual(target.stat().st_ino,original)
                        for fd in fds:
                            with self.assertRaises(OSError): os.fstat(fd)
                    finally:
                        actual.close(); control.close()

    def test_post_close_terminal_clock_never_rebases_original_cutoff(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve(); owner=self.owner()
            try:
                owner.add(self.fixture(root),128); deadline=owner.deadline; until=owner.until_ns
                fds=[slot.fd for slot in owner.slots]; owner.close(); owner.named_fence()
                with patch.object(proof.time,"monotonic",return_value=deadline):
                    with self.assertRaises(ValueError): owner.named_fence()
                with patch.object(proof.time,"monotonic_ns",return_value=until):
                    with self.assertRaises(ValueError): owner.named_fence()
                self.assertEqual((owner.deadline,owner.until_ns),(deadline,until))
                for fd in fds:
                    with self.assertRaises(OSError): os.fstat(fd)
            finally: owner.close()

    def test_publication_slot_failure_before_after_append_drains_actual_open_fds(self):
        class Fail(list):
            def __init__(self,after,at): super().__init__(); self.after,self.at,self.calls=after,at,0
            def append(self,value):
                self.calls+=1
                if self.calls!=self.at: return super().append(value)
                if self.after: super().append(value)
                raise MemoryError("model-slot")
        real_held=proof.Held
        for after in (False,True):
            for at in (1,3):
                with self.subTest(after=after,at=at), tempfile.TemporaryDirectory() as temporary:
                    root=Path(temporary).resolve(); output=root/cli.OUTPUT; output.mkdir(mode=0o700)
                    owner=self.owner(); acquired=[]; real=os.open
                    class Creator(real_held):
                        def __init__(self,*args): super().__init__(*args); self.slots=Fail(after,at)
                    def opened(*args,**kwargs):
                        fd=real(*args,**kwargs); acquired.append(fd); return fd
                    try:
                        with patch.object(proof,"Held",Creator),patch.object(proof.os,"open",side_effect=opened):
                            with self.assertRaises(MemoryError): cli.publish_owned(owner,output,{name:b"public" for name in reader.OUTPUT_NAMES})
                        self.assertEqual(len(acquired),at-1)
                        for fd in acquired:
                            with self.assertRaises(OSError): os.fstat(fd)
                    finally: owner.close(); output.chmod(0o700)

    def test_runtime_manifest_capture_precedes_actual_parse_and_replacement_refuses(self):
        for fault in (None,"before","after"):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary).resolve(); a=proof.encoded({"schema_version":1,"runfiles":["_main/public-a"]})
                b=proof.encoded({"schema_version":1,"runfiles":["_main/public-b"]})
                manifest=self.fixture(root,"runtime.json",a); original=manifest.stat().st_ino; seen=[]
                real=cli.runtime.read_json
                with self.owner() as owner:
                    def parse(path):
                        self.assertIn(manifest,owner.files); self.assertEqual(owner.raw(manifest),a); seen.append(True)
                        if fault=="before": os.replace(self.fixture(root,"replacement",b),manifest)
                        value=real(path)
                        if fault=="after": os.replace(self.fixture(root,"replacement",b),manifest)
                        return value
                    with patch.object(cli.runtime,"read_json",side_effect=parse):
                        if fault is None:
                            selected,raw=cli.held_runtime_inputs(owner,manifest,root)
                            self.assertEqual((selected,raw),([root/"_main/public-a"],a))
                        else:
                            with self.assertRaises(ValueError): cli.held_runtime_inputs(owner,manifest,root)
                    self.assertEqual(seen,[True])
                    if fault is not None: self.assertNotEqual(manifest.stat().st_ino,original)


class AdmissionModels(unittest.TestCase):
    def test_exact_cli_cohort_only_no_bare_extra_mixed_build_or_old_profile(self):
        self.assertEqual(guard.selected(guard.PROFILE,guard.ARGUMENTS),{"PrivateNetwork":"yes"})
        for vector in (["test",guard.ARGUMENTS[-1]],guard.ARGUMENTS+["//:docs_check"],
                       list(reversed(guard.ARGUMENTS)),["build",*guard.ARGUMENTS[1:]]):
            with self.assertRaises(ValueError): guard.selected(guard.PROFILE,vector)
        with self.assertRaises(ValueError): guard.selected("native-siwc-catalog-models-reserved",guard.ARGUMENTS)

    def test_non_owner_refuses_before_sdk_source_query_or_scratch_io(self):
        with tempfile.TemporaryDirectory() as temporary:
            work=Path(temporary)/"new"
            report={"kind":cli.models.history.KIND,"patch_sha256":["1"*64]*12+[proof.HISTORY_PATCH],
                    "native_owned_history_controls_sha256":proof.HISTORY_CONTROL}
            with patch.object(cli.family.query_tools,"verify_repository") as query:
                with self.assertRaises(ValueError): cli.build_plan(object(),object(),report,work,time.monotonic()+60)
            query.assert_not_called(); self.assertFalse(work.exists())

    def test_cold_old_generic_and_redirected_runtime_selection_refuse(self):
        cold=proof.encoded({"schema_version":1,"kind":proof.SELECTION_KIND,"status":"PENDING-GENUINE-CLI-PACKAGE","package":None})
        with self.assertRaises(ValueError): reader.selected(cold)
        with self.assertRaises(ValueError): reader.selected(proof.encoded({"schema_version":1,"kind":"omux-direct-native-tui-package-pin-v1"}))

    def test_exact_declaration_control_644_reaches_real_cold_refusal_and_closes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve(); control=root/"runtime-selection.json"
            raw=proof.encoded({"schema_version":1,"kind":proof.SELECTION_KIND,"status":"PENDING-GENUINE-CLI-PACKAGE","package":None})
            control.write_bytes(raw); control.chmod(0o644)
            seen=[]; fds=[]; actual_selected=reader.selected; actual_open=os.open
            def selected(value): seen.append(value); return actual_selected(value)
            def opened(*args,**kwargs):
                fd=actual_open(*args,**kwargs); fds.append(fd); return fd
            with patch.object(reader,"selected",side_effect=selected),patch.object(proof.os,"open",side_effect=opened):
                with self.assertRaises(ValueError): reader.Reader(control,proof.sha(raw),root/"input-aliases.json",time.monotonic()+60,time.monotonic_ns()+60*10**9)
            self.assertEqual(seen,[raw]); self.assertTrue(fds)
            for fd in fds:
                with self.assertRaises(OSError): os.fstat(fd)

    def test_xml_failure_error_skipped_and_outer_counter_refuse(self):
        reader.xml_success(b'<testsuites tests="1" failures="0" errors="0"><testsuite tests="1" failures="0" errors="0"><testcase/></testsuite></testsuites>')
        for raw in (b'<testsuites failures="1"><testsuite/></testsuites>',b'<testsuite><testcase><failure/></testcase></testsuite>',
                    b'<testsuite skipped="1"/>',b'<testsuite><error/></testsuite>'):
            with self.assertRaises(ValueError): reader.xml_success(raw)

    def test_exact_declared_expected_controls_join_all60_without_filter(self):
        root=Path(__file__).parent.parent/"integrations/codex-upstream"
        raws={name:(root/name).read_bytes() for name in proof.CONTROL_PINS}
        expected=proof.required_tests(raws)
        self.assertEqual(tuple(map(len,expected.values())),(50,4,6,0))
        changed=dict(raws); name=next(iter(changed)); changed[name]+=b" "
        with self.assertRaises(ValueError): proof.required_tests(changed)

    def test_package_parser_refuses_old_family_without_loading_elf(self):
        value={"kind":"native-owner-runtime-proof-candidate"}
        with self.assertRaises(ValueError): proof.verify_package(b"old",proof.encoded(value),expected_tests={},portable=None,runtime=None)

    def test_package_context_must_match_independent_outer_all_six_roles(self):
        entry=1000; until=entry+1200*10**9; outer_path=Path("/public-model-epoch/receipt.json")
        outer={"source_commit":"1"*40,"graph_sha256":"2"*64,"native_owned_history_cli_reservation":{
            "original_entry_monotonic_ns":entry,"original_deadline_monotonic_ns":until}}
        context={"mode":guard.INPUT_MODE,"epoch":str(outer_path.parent),"source_commit":outer["source_commit"],
            "graph_sha256":outer["graph_sha256"],"entry_monotonic_ns":entry,"deadline_monotonic_ns":until}
        sdk={"consumer_context":{"MODE":guard.INPUT_MODE,"EPOCH":str(outer_path.parent),
            "SOURCE_COMMIT":outer["source_commit"],"GRAPH_SHA256":outer["graph_sha256"],
            "ENTRY_NS":str(entry),"DEADLINE_NS":str(until)}}
        receipt={"sdk":copy.deepcopy(sdk),"models":{"producer_context":context,
            "original_entry_monotonic_ns":entry,"original_outer_deadline_monotonic_ns":until,
            "original_proof_deadline_monotonic_ns":entry+600*10**9,"transported_sdk":copy.deepcopy(sdk)}}
        # Only this pure join is exercised; this is not guardian/package authority.
        reader.package_context(receipt,outer,outer_path)
        for section,keys in (("producer_context",context),("consumer_context",sdk["consumer_context"])):
            for key in keys:
                with self.subTest(section=section,key=key):
                    changed=copy.deepcopy(receipt)
                    if section=="producer_context": target=changed["models"][section]
                    else:
                        target=changed["sdk"][section]
                        changed["models"]["transported_sdk"]=changed["sdk"]
                    target[key]=(target[key]+1) if type(target[key]) is int else target[key]+"-different"
                    with self.assertRaises(ValueError): reader.package_context(changed,outer,outer_path)
        for key in ("original_entry_monotonic_ns","original_outer_deadline_monotonic_ns","original_proof_deadline_monotonic_ns"):
            changed=copy.deepcopy(receipt); changed["models"][key]+=1
            with self.assertRaises(ValueError): reader.package_context(changed,outer,outer_path)

    def test_guardian_actual_schema_caps_and_owned_pre_post_cleanup_are_required(self):
        run=Path("/public-model-epoch"); unit="omux-execution-"+run.name+".service"
        group="/system.slice/"+unit
        identity=(unit,"1"*32,"42")
        terminal={"Id":unit,"InvocationID":identity[1],"ExecMainPID":"42","MainPID":"0","LoadState":"loaded",
            "ActiveState":"active","SubState":"exited","RemainAfterExit":"yes","ExecMainCode":"1","ExecMainStatus":"0","Result":"success"}
        pre=guard.kernel.pre_stop_projection(terminal,identity)
        terminal.update(ActiveState="inactive",SubState="dead")
        post=guard.kernel.post_stop_projection(terminal,identity); post["original_cgroup_state"]="absent"
        resident={"scope":"sampled-fixed-default-cgroup-kernel-reservation-v1","observations":2,
            "kernel_bounds":{"memory.max":"268435456","memory.swap.max":"0","pids.max":"32","cpu.max":"10000 100000"},
            "initial_direct_process_count":1,"initial_direct_processes_retained":True,"outer_pid_namespace_matched":True,
            "hierarchical_caps":True,"descendant_process_inventory":False,"installation_qualified":False,"health_observed":False,
            "custody_observed":False,"resident_signalled":False,"whole_host_reservation":False}
        outer={"id":run.name,"artifact_epoch":run.name,"unit":unit,"output_base":str(run/"output-base"),
            "original_cgroup_identity":{"device":1,"inode":2},"native_owned_history_cli_reservation":{"resident":resident},
            "observed_properties":guard.properties({"MemorySwapMax":"0","PrivateNetwork":"yes","KillMode":"control-group",
                "SendSIGKILL":"yes","OOMPolicy":"kill","MainPID":"42","ControlGroup":group}),
            "startup_history":[{"ActiveState":"active","SubState":"running","MainPID":"42","ExecMainPID":"42","ControlGroup":group}],
            "cleanup":{"state":"empty","stop":"succeeded","ownership":"verified","readback_attempts":2,"pre_stop":pre,"post_stop":post}}
        # Real guard diagnostic producers, pure metadata predicate; no receipt
        # owner/real guardian success is manufactured by this synthetic vector.
        reader.guardian_state(outer,run/"receipt.json")
        changes=[("unit", "foreign"),("output_base","/foreign"),("artifact_epoch","foreign")]
        changes += [("observed_properties."+key,"unbounded") for key in ("MemoryMax","MemorySwapMax","TasksMax",
            "CPUQuotaPerSecUSec","PrivateNetwork","KillMode","SendSIGKILL","OOMPolicy","RemainAfterExit","MainPID","ControlGroup")]
        changes += [("cleanup.stop","not-requested"),("cleanup.readback_attempts",1),
            ("cleanup.pre_stop.Id_matches",False),("cleanup.pre_stop.ExecMainStatus",1),
            ("cleanup.post_stop.original_cgroup_state","populated"),("cleanup.post_stop.predicate","manager-query-refused"),
            ("cleanup.post_stop.InvocationID_matches",False)]
        for path,value in changes:
            with self.subTest(path=path):
                changed=copy.deepcopy(outer); parent=changed; fields=path.split(".")
                for name in fields[:-1]: parent=parent[name]
                parent[fields[-1]]=value
                with self.assertRaises(ValueError): reader.guardian_state(changed,run/"receipt.json")

    def test_declaration_contains_cold_null_exact_typed_cohort_and_source_data(self):
        root=Path(__file__).parent
        bzl=(root/"codex_owned_history_cli_targets.bzl").read_text()
        self.assertIn('"codex_native_owned_history_cli_producer"',bzl)
        self.assertIn('"codex_native_owned_history_cli_test"',bzl)
        self.assertIn('"//delivery:owned_history_runtime.py"',bzl)
        self.assertIn('"//delivery:owned_history_native_tui_runtime.py"',bzl)
        self.assertIn('"@omux_nix//:tool_wrappers/strip"',bzl)
        selection=proof.decode((root.parent/"integrations/codex-upstream/native-owned-history/runtime-selection.json").read_bytes())
        self.assertIsNone(selection["package"]); self.assertEqual(selection["kind"],proof.SELECTION_KIND)

    def test_copied_evidence_names_bind_exact_target_configuration_and_role(self):
        import guard_test_evidence as collector
        configuration="k8-fastbuild"; rows=[]; total=0
        for target in reader.TARGETS:
            entries=[]
            for name in collector.FILES:
                if name in ("test.log","test.xml"):
                    body=b"public-diagnostic"
                    entries.append({"source":name,"state":"copied","file":proof.sha((target+"\0"+configuration+"\0"+name).encode())+".evidence",
                        "sha256":proof.sha(body),"bytes":len(body)}); total+=len(body)
                else: entries.append({"source":name,"state":"missing","bytes":0})
            rows.append({"target":target,"configuration":configuration,"state":"observed","files":entries})
        index={"schema":1,"bazel_exit":0,"epoch_start_ns":123,"targets":reader.TARGETS,"bytes":total,"copied_files":4,
            "results":rows,"acceptance":"evidence copies preserve invocation status; no inferred PASS"}
        outer={"epoch_start_ns":123}; root=Path("/public-model-epoch/output-base/execroot/_main/bazel-out")/configuration/"testlogs/tools/producer/test.outputs"/cli.OUTPUT
        self.assertEqual([(target,name) for target,name,_ in reader.collector_roles(index,outer,root)],
            [(target,name) for target in reader.TARGETS for name in ("test.log","test.xml")])
        for fault in ("filename","configuration","target","role","state","sum","count"):
            with self.subTest(fault=fault):
                changed=copy.deepcopy(index); result=changed["results"][0]; row=result["files"][0]
                if fault=="filename": row["file"]="1"*64+".evidence"
                elif fault=="configuration": result["configuration"]="other-fastbuild"
                elif fault=="target": result["target"]=reader.TARGETS[1]
                elif fault=="role": row["source"]="test.xml"
                elif fault=="state": row["state"]="missing"
                elif fault=="sum": changed["bytes"]+=1
                else: changed["copied_files"]+=1
                with self.assertRaises(ValueError): reader.collector_roles(changed,outer,root)
        for state in ("copy-refused","changed-during-copy","over-budget"):
            with self.subTest(optional_state=state):
                changed=copy.deepcopy(index); changed["results"][0]["files"][2]["state"]=state
                with self.assertRaises(ValueError): reader.collector_roles(changed,outer,root)


if __name__=="__main__": unittest.main()
