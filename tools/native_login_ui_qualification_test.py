"""Provider-free preparation models. No SSH/Nix/GUI/provider process is invoked."""
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import struct
import sys
import tempfile
import time
import types
import unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch

import native_login_ui_qualification as local
import native_login_ui_prepare_remote as remote
import yoga_portal_worker as worker


class Preparation(unittest.TestCase):
    def test_actual_declared_bootstrap_stays_inside_both_existing_bounds(self):
        code = local.bootstrap(Path(worker.__file__).read_text(),Path(remote.__file__).read_text(),
            local.elf_parser_source(Path(self.parser_source).read_bytes()))
        self.assertLessEqual(len(code.encode()),96*1024)
        self.assertLessEqual(len(local.carrier.remote_command('/usr/bin/python3',code).encode()),120*1024)
        with self.assertRaisesRegex(worker.Refusal,'declared_bootstrap_source_bound') as refused:
            local.bootstrap('x'*(96*1024),'','')
        self.assertEqual(local.refusal_record(refused.exception)['category'],'bootstrap_bound')

    def test_closed_remote_refusal_roundtrip_discards_private_error_and_unknown_fields(self):
        config = {'expected_os':{},'rows':[],'control_sha256':'0'*64,'control_bytes':8,
            'task_id':'11111111-1111-4111-8111-111111111111','deadline_seconds':60}
        with patch.object(remote.resource,'setrlimit'),patch.object(remote.signal,'alarm'),\
            patch.object(remote.os,'environ',{}),\
            patch.object(remote,'seat',side_effect=FileNotFoundError('PRIVATE_MODEL_CANARY')):
            with self.assertRaises(FileNotFoundError) as refused:
                remote.prepare(worker,config)
        observed = remote.refusal_record(refused.exception)
        self.assertEqual(observed['phase'],'seat')
        self.assertEqual(observed['category'],'missing_input')
        local.set_phase('remote_result')
        record = local.refusal_record(local.RemoteRefusal(observed))
        self.assertEqual(record['remote_phase'],'seat')
        self.assertEqual(record['remote_category'],'missing_input')
        self.assertNotIn('PRIVATE_MODEL_CANARY',json.dumps(record))
        for forged in ({**observed,'private':'PRIVATE_MODEL_CANARY'},
                {**observed,'phase':'PRIVATE_MODEL_CANARY'},{**observed,'category':'PRIVATE_MODEL_CANARY'}):
            with self.assertRaisesRegex(worker.Refusal,'remote_refusal_frame_invalid'):
                local.RemoteRefusal(forged)
        failure = local.delivery.GateError('PRIVATE_MODEL_CANARY',hints={
            'stderrFlags':{'ssh_auth_rejected':True,'private':'PRIVATE_MODEL_CANARY'}})
        self.assertEqual(local.refusal_record(failure)['category'],'ssh_authentication')
        self.assertNotIn('PRIVATE_MODEL_CANARY',json.dumps(local.refusal_record(failure)))
        failure = local.delivery.GateError('PRIVATE_MODEL_CANARY',hints={
            'osBootstrapFailure':{'step':'nix-custody','category':'missing-input'}})
        record = local.refusal_record(failure)
        self.assertEqual(record['os_bootstrap_phase'],'nix-custody')
        self.assertEqual(record['os_bootstrap_category'],'missing-input')
        failure.hints['osBootstrapFailure']['step'] = 'PRIVATE_MODEL_CANARY'
        record = local.refusal_record(failure)
        self.assertNotIn('os_bootstrap_phase',record)
        self.assertNotIn('PRIVATE_MODEL_CANARY',json.dumps(record))

    def test_actual_main_marks_control_input_refusal_before_any_ssh_boundary(self):
        raw = b'{}'
        config = {'schema_version':1,'scope':'omux-native-login-ui-prepare-v1',
            'os_qualification_sha256':hashlib.sha256(raw).hexdigest(),'control_sha256':'0'*64,
            'known_hosts_path':'selected','ssh_auth_socket':None,'output_parent':local.OUTPUT,'deadline_seconds':60}
        arguments = ['model']
        for name in ('control','inventory','source-receipt','known-hosts','worker','remote-worker','elf-parser'):
            arguments.extend(('--'+name,'selected'))
        environment = {'OMUX_NATIVE_LOGIN_UI_PREPARE_INPUT_MANIFEST':local.INPUT,
            'OMUX_NATIVE_LOGIN_UI_ORIGINAL_DEADLINE_NS':str(time.monotonic_ns()+300*10**9)}
        with patch.object(sys,'argv',arguments),patch.object(local.os,'environ',environment),\
            patch.object(local,'namespace',side_effect=[(41,()),(42,())]),\
            patch.object(local,'private_metadata',side_effect=[local.canonical(config),raw]),\
            patch.object(local.settings,'qualification',return_value={}),\
            patch.object(local.delivery,'read_public',side_effect=PermissionError('PRIVATE_MODEL_CANARY')),\
            patch.object(local.delivery,'Backend') as backend,patch.object(local,'remote_prepare') as prepare,\
            patch.object(local.subprocess,'Popen') as spawn,patch.object(local.os,'close') as close:
            with self.assertRaises(PermissionError) as refused:
                local.main()
        record = local.refusal_record(refused.exception)
        self.assertEqual(record['phase'],'control_input')
        self.assertEqual(record['category'],'access_refused')
        self.assertNotIn('PRIVATE_MODEL_CANARY',json.dumps(record))
        backend.assert_not_called()
        prepare.assert_not_called()
        spawn.assert_not_called()
        self.assertEqual([call.args[0] for call in close.call_args_list],[42,41])

    def test_wrong_actual_registry_refuses_before_any_physical_hash(self):
        rows = local.subset(Path(self.inventory).read_bytes())
        wrong = {row["path"]:{"narSize":row["narSize"],"narHash":row["narHash"],"references":row["references"]} for row in rows}
        wrong[rows[0]["path"]]["narSize"] = True
        for actual in ({},wrong):
            with patch.object(Path,"resolve",autospec=True,side_effect=lambda path,*a,**kw:path),\
                patch.object(remote.os,"open",return_value=42),patch.object(remote.os,"close"),\
                patch.object(remote.os,"fstat",return_value=SimpleNamespace(st_uid=0,st_mode=stat.S_IFDIR|0o555,
                    st_dev=1,st_ino=2,st_mtime_ns=3,st_ctime_ns=4)),\
                patch.object(remote,"nix_operation",return_value=json.dumps(actual).encode()) as call:
                with self.assertRaisesRegex(ValueError,"destination_registration_"):
                    remote.verify_rows(worker,3,rows,time.monotonic()+1)
            self.assertEqual(call.call_count,1)
            self.assertEqual(call.call_args.args[2][:6],["path-info","--store","daemon","--offline","--json",rows[0]["path"]])

    def test_exact_existing_inventory_projects_reference_closed_181(self):
        data = Path(self.inventory).read_bytes()
        rows = local.subset(data)
        names = {row["path"] for row in rows}
        self.assertEqual(len(rows),181)
        self.assertEqual(sum(row["narSize"] for row in rows),869166464)
        self.assertTrue(local.ROOTS <= names)
        self.assertTrue(all(set(row["references"]) <= names for row in rows))
        with self.assertRaisesRegex(worker.Refusal,"fixed_inventory_required"):
            local.subset(data+b" ")

    def test_generated_os_identity_reads_actual_bytes_despite_size_zero(self):
        generated = b"SYNTHETIC-BOOT-IDENTITY\n"
        with patch.object(remote.os,"open",return_value=77),patch.object(remote.os,"close") as release,\
            patch.object(remote.os,"fstat",return_value=SimpleNamespace(st_mode=stat.S_IFREG|0o444,st_size=0)),\
            patch.object(remote.os,"read",side_effect=[generated,b""]):
            self.assertEqual(remote.os_identity_digest("/proc/sys/kernel/random/boot_id"),hashlib.sha256(generated).hexdigest())
        release.assert_called_once_with(77)

    def stage_model(self,wrong=False):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)/".local/state"
            state.mkdir(parents=True,mode=0o700)
            data = b"\x7fELFsynthetic-nonexecuted-comparison-bytes"
            pieces = [data[:1],data[1:3],data[3:]]
            config = {"task_id":"11111111-1111-4111-8111-111111111111","control_bytes":len(data),
                "control_sha256":"0"*64 if wrong else hashlib.sha256(data).hexdigest()}
            import pwd
            with patch.object(pwd,"getpwuid",return_value=SimpleNamespace(pw_dir=folder)),\
                patch.object(remote.select,"select",return_value=([0],[],[])),\
                patch.object(remote.os,"read",side_effect=pieces),patch.object(worker,"read_line",return_value=None):
                if wrong:
                    with self.assertRaisesRegex(ValueError,"control_digest_mismatch"):
                        remote.stage(worker,config,time.monotonic()+1)
                    self.assertEqual(list((state/"omux-native-login-ui").iterdir()),[])
                else:
                    path,identity = remote.stage(worker,config,time.monotonic()+1)
                    self.assertEqual(Path(path).read_bytes(),data)
                    info = os.stat(path,follow_symlinks=False)
                    self.assertEqual(stat.S_IMODE(info.st_mode),0o500)
                    self.assertEqual(stat.S_IMODE(Path(path).parent.stat().st_mode),0o700)
                    self.assertEqual((info.st_dev,info.st_ino),identity)

    def test_stage_accepts_segmented_elf_prefix_and_creates_only_new_public_file(self):
        self.stage_model()

    def test_stage_digest_failure_removes_only_new_task(self):
        self.stage_model(wrong=True)

    def test_nix_constructor_failure_reaps_only_still_owned_child(self):
        process = Mock(pid=4321)
        process.stdout = Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("owned-model",5),0]
        with patch.object(remote.subprocess,"Popen",return_value=process),\
            patch.object(remote.os,"pidfd_open",side_effect=OSError("synthetic")),\
            patch.object(remote.os.path,"lexists",return_value=False):
            with self.assertRaises(OSError):
                remote.nix_operation(worker,3,["hash","path"],time.monotonic()+1,128)
        self.assertEqual([call.args[0] for call in process.send_signal.call_args_list],[signal.SIGTERM,signal.SIGKILL])
        process.stdout.close.assert_called_once()

    def test_receipt_publish_is_exclusive_and_existing_output_remains(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = os.open(folder,os.O_RDONLY|os.O_DIRECTORY)
            try:
                local.publish(directory,{"closure.json":b'{"synthetic":true}',"seat.json":b'{}',"ui-qualification.json":b'{}'})
                for path in Path(folder).iterdir():
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode),0o600)
                before = {path.name:path.read_bytes() for path in Path(folder).iterdir()}
                with self.assertRaisesRegex(worker.Refusal,"new_empty_output_required"):
                    local.publish(directory,{"closure.json":b'{}'})
                self.assertEqual({path.name:path.read_bytes() for path in Path(folder).iterdir()},before)
            finally:
                os.close(directory)


def elf_model(needed=(),interpreter=None,rpath=(),path_tag=29,padding=b""):
    strings,references = bytearray(b"\0"),[]
    for tag,value in [(1,name) for name in needed]+([(path_tag,":".join(rpath))] if rpath else []):
        references.append((tag,len(strings)))
        strings.extend(value.encode()+b"\0")
    strings.extend(padding)
    count = 2+(interpreter is not None)
    dyn = 64+56*count
    size = 16*(len(references)+3)
    off = dyn+size
    interp = b"" if interpreter is None else interpreter.encode()+b"\0"
    ioff,base = off+len(strings),0x400000
    length = ioff+len(interp)
    header = b"\x7fELF\x02\x01\x01"+bytes(9)+struct.pack("<HHIQQQIHHHHHH",3,62,1,0,64,0,0,64,56,count,0,0,0)
    heads = struct.pack("<IIQQQQQQ",1,5,0,base,base,length,length,4096)
    heads += struct.pack("<IIQQQQQQ",2,4,dyn,base+dyn,0,size,size,8)
    if interpreter is not None:
        heads += struct.pack("<IIQQQQQQ",3,4,ioff,base+ioff,0,len(interp),len(interp),1)
    return header+heads+b"".join(struct.pack("<qQ",tag,value) for tag,value in
        references+[(5,base+off),(10,len(strings)),(0,0)])+strings+interp


class ElfClosureModels(unittest.TestCase):
    def test_actual_declared_control_closed_graph_before_any_ui_execution(self):
        rows = local.subset(Path(Preparation.inventory).read_bytes())
        roots = []
        graph = control = None
        until = time.monotonic()+120
        try:
            # This selected artifact and all181 source inputs are target data.
            selected = Path(Preparation.control).resolve(strict=True)
            source = os.open(selected,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK)
            try:
                before = os.fstat(source)
                self.assertTrue(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 128*1024*1024)
                payload = bytearray()
                while len(payload) < before.st_size:
                    self.assertLess(time.monotonic(),until)
                    piece = os.read(source,min(65536,before.st_size-len(payload)))
                    self.assertTrue(piece)
                    payload.extend(piece)
                self.assertEqual(remote.ElfClosure.witness(before),remote.ElfClosure.witness(os.fstat(source)))
            finally:
                os.close(source)
            for row in rows:
                self.assertLess(time.monotonic(),until)
                path = row["path"]
                self.assertEqual(str(Path(path).resolve(strict=True)),path)
                fd = os.open(path,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
                info = os.fstat(fd)
                roots.append((path,fd,(info.st_dev,info.st_ino,info.st_uid,info.st_mode,info.st_mtime_ns,info.st_ctime_ns)))
                self.assertEqual(info.st_uid,0)
                self.assertFalse(info.st_mode & 0o222)
            with tempfile.TemporaryDirectory(prefix="omux-public-elf-model-") as directory:
                path = str(Path(directory)/"control")
                control = os.open(path,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
                try:
                    offset = 0
                    while offset < len(payload):
                        self.assertLess(time.monotonic(),until)
                        count = os.write(control,payload[offset:offset+65536])
                        self.assertGreater(count,0)
                        offset += count
                    os.fchmod(control,0o500)
                    os.fsync(control)
                    graph = remote.ElfClosure(worker,control,path,rows,remote.PLUGIN,until,roots)
                    graph.check()
                    self.assertGreater(len(graph.files),1)
                finally:
                    if graph is not None:
                        graph.close()
                        graph = None
                    os.close(control)
                    control = None
        finally:
            if graph is not None:
                graph.close()
            if control is not None:
                os.close(control)
            for _,fd,_ in roots:
                os.close(fd)

    def test_declared_elf_parser_accepts_real_multiplied_constants_and_refuses_other_ast(self):
        data = Path(Preparation.parser_source).read_bytes()
        source = local.elf_parser_source(data)
        module = types.ModuleType("actual_declared_parser_constant_model")
        exec(compile(source,"<declared-parser-model>","exec"),module.__dict__)
        self.assertEqual(module._MAX_FILE,128*1024*1024)
        self.assertEqual(module._MAX_BACKEND_FILE,512*1024*1024)
        marker = b"_MAX_FILE = 128 * 1024 * 1024"
        self.assertEqual(data.count(marker),1)
        for expression in (b"int('128')",b"2 ** 27",b"True",b"1024 * 1024 * 1024",b"128 * 1024"):
            with self.subTest(expression=expression),self.assertRaisesRegex(ValueError,"declared_elf_constant_"):
                local.elf_parser_source(data.replace(marker,b"_MAX_FILE = "+expression))

    def graph(self,*,control_rpath=None,transitive_needed=("libc.so.6",),ambiguous=False,
            child_rpath=True,path_tag=29,child_empty_tag=None,direct_libc=False,child_driver=False,
            child_search=None,forbidden_probe_prefix=None):
        rows = local.subset(Path(Preparation.inventory).read_bytes())
        roots = {row["path"] for row in rows}
        qt = "/nix/store/1q8sx67miwfn3ws5k7mkmkcjbym4akkp-qtbase-6.11.0/lib"
        glibc = "/nix/store/fjkx1l5cnskzrqacf08z7i8z17256w0j-glibc-2.42-61/lib"
        loader = glibc+"/ld-linux-x86-64.so.2"
        control = "/model/private/control"
        child_paths = child_search if child_search is not None else (
            ("/run/opengl-driver/lib",glibc) if child_driver else
            (((glibc,) if child_rpath else ()) if child_empty_tag is None else ("",)))
        files = {control:elf_model(("libQt6Core.so.6","libc.so.6") if direct_libc else ("libQt6Core.so.6",),loader,
                (qt,glibc) if control_rpath is None else control_rpath,path_tag),
            loader:elf_model(),glibc+"/libc.so.6":elf_model(("ld-linux-x86-64.so.2",),rpath=(glibc,)),
            qt+"/libQt6Core.so.6":elf_model(transitive_needed,
                rpath=child_paths,
                path_tag=29 if child_empty_tag is None else child_empty_tag),
            remote.PLUGIN:elf_model(("libQt6Core.so.6",),rpath=(qt,))}
        if ambiguous:
            files[glibc+"/libQt6Core.so.6"] = elf_model()
        directories = roots|{qt,glibc}
        descriptors = {path:2000+index for index,path in enumerate(files)}
        records = {descriptor:(path,payload) for path,payload in files.items()
            for descriptor in [descriptors[path]]}
        records[1999] = control,files[control]
        rootfds = {4000+index:path for index,path in enumerate(sorted(roots))}
        def information(path):
            directory = path in directories
            return SimpleNamespace(st_dev=1,st_ino=hash(path),st_uid=0 if path != control else 1000,
                st_mode=(stat.S_IFDIR|0o555) if directory else stat.S_IFREG|(0o500 if path == control else 0o444),
                st_size=4096 if directory else len(files[path]),st_mtime_ns=1,st_ctime_ns=1)
        def held(fd):
            return information(rootfds[fd] if fd in rootfds else records[fd][0])
        pins = [(path,fd,(info.st_dev,info.st_ino,info.st_uid,info.st_mode,info.st_mtime_ns,info.st_ctime_ns))
            for fd,path in rootfds.items() for info in [information(path)]]
        def no_foreign_probe(path):
            if forbidden_probe_prefix is not None:
                self.assertFalse(str(path).startswith(forbidden_probe_prefix))
        def canonical_path(path,*args,**kwargs):
            no_foreign_probe(path)
            return path
        def exists(path):
            no_foreign_probe(path)
            return str(path) in files or str(path) in directories
        with patch.object(Path,"resolve",autospec=True,side_effect=canonical_path),\
            patch.object(remote.os,"dup",return_value=1999),\
            patch.object(remote.os,"open",side_effect=lambda path,*a,**kw:descriptors[str(path)]),\
            patch.object(remote.os,"fstat",side_effect=held),\
            patch.object(remote.os,"stat",side_effect=lambda path,*a,**kw:information(str(path))),\
            patch.object(remote.os,"pread",side_effect=lambda fd,size,offset:records[fd][1][offset:offset+size]),\
            patch.object(remote.os.path,"lexists",side_effect=exists),\
            patch.object(remote.os,"close") as close:
            graph = remote.ElfClosure(worker,descriptors[control],control,rows,remote.PLUGIN,time.monotonic()+5,pins)
            graph.check()
            self.assertIn(loader,graph.files)
            self.assertIn(qt+"/libQt6Core.so.6",graph.files)
            graph.close()
            self.assertEqual(set(call.args[0] for call in close.call_args_list),
                {1999,descriptors[loader],descriptors[glibc+"/libc.so.6"],
                 descriptors[qt+"/libQt6Core.so.6"],descriptors[remote.PLUGIN]})

    def test_actual_pure_parser_and_closed_transitive_graph_hold_and_release_files(self):
        self.graph()

    def test_ambient_or_bazel_relative_control_search_refuses(self):
        qt = "/nix/store/1q8sx67miwfn3ws5k7mkmkcjbym4akkp-qtbase-6.11.0/lib"
        for paths in (("/usr/lib",),("$ORIGIN/../../_solib_k8",),("",""),("",qt),(qt,""),(qt,"",qt)):
            with self.subTest(paths=paths),self.assertRaisesRegex(ValueError,"dialog_elf_"):
                self.graph(control_rpath=paths)

    def test_transitive_foreign_or_unresolved_needed_refuses(self):
        for needed in (("/usr/lib/outside.so",),("missing-model.so.1",)):
            with self.subTest(needed=needed),self.assertRaisesRegex(ValueError,"dialog_elf_"):
                self.graph(transitive_needed=needed)

    def test_first_lookup_target_is_adopted_in_declared_order(self):
        self.graph(ambiguous=True)
        inspector = object.__new__(remote.ElfClosure)
        inspector.until = time.monotonic()+5
        inspector.files = {}
        for directories in (("/first","/second"),("/second","/first")):
            inspector.names = {}
            with self.subTest(directories=directories),\
                patch.object(remote.os.path,"lexists",return_value=True) as exists,\
                patch.object(inspector,"directory",side_effect=lambda value,*args:value),\
                patch.object(inspector,"member",side_effect=lambda value:value) as member:
                selected = inspector.resolve("model.so.1",tuple((value,"",False) for value in directories),"control")
                self.assertEqual(selected,directories[0]+"/model.so.1")
                exists.assert_called_once_with(selected)
                member.assert_called_once_with(selected)

    def test_runpath_is_not_inherited_but_rpath_is(self):
        self.graph(child_rpath=False,path_tag=15)
        with self.assertRaisesRegex(ValueError,"dialog_elf_needed_unresolved"):
            self.graph(child_rpath=False,path_tag=29)

    def test_whole_empty_search_tag_ignores_nul_terminated_padding(self):
        inspector = object.__new__(remote.ElfClosure)
        for tag in (15,29):
            with self.subTest(tag=tag):
                metadata = inspector.metadata(elf_model(rpath=("",),path_tag=tag,padding=b"XXXXXXXX"))
                self.assertEqual(metadata["rpath"],[])
                self.assertEqual(metadata["runpath"],tag == 29)
                self.graph(control_rpath=("",),path_tag=tag)

    def test_whole_empty_runpath_still_blocks_ancestor_rpath(self):
        self.graph(path_tag=15,child_empty_tag=15)
        with self.assertRaisesRegex(ValueError,"dialog_elf_needed_unresolved"):
            self.graph(path_tag=15,child_empty_tag=29)

    def test_direct_sibling_is_held_before_first_child_needs_it(self):
        self.graph(child_rpath=False,path_tag=29,direct_libc=True)

    def test_driver_search_is_denied_if_a_new_lookup_reaches_it(self):
        self.graph(child_driver=True,direct_libc=True)
        with self.assertRaisesRegex(ValueError,"dialog_elf_nonclosure_search"):
            self.graph(child_driver=True)
        with self.assertRaisesRegex(ValueError,"dialog_elf_nonclosure_search"):
            self.graph(control_rpath=("/run/opengl-driver/lib",))

    def test_unused_foreign_dso_search_is_not_probed_and_consulted_prefix_refuses(self):
        glibc = "/nix/store/fjkx1l5cnskzrqacf08z7i8z17256w0j-glibc-2.42-61/lib"
        denied = ("/nix/store/00000000000000000000000000000000-unqualified-model/lib",
            "/usr/lib","/run/opengl-driver/lib","${ORIGIN}/unqualified-model")
        for prefix in denied:
            with self.subTest(prefix=prefix):
                self.graph(child_search=(prefix,glibc),direct_libc=True,forbidden_probe_prefix=prefix)
                with self.assertRaisesRegex(ValueError,"dialog_elf_nonclosure_search.*parent=libQt6Core.so.6"):
                    self.graph(child_search=(prefix,glibc),forbidden_probe_prefix=prefix)
                with self.assertRaisesRegex(ValueError,"dialog_elf_nonclosure_search"):
                    self.graph(control_rpath=(prefix,),forbidden_probe_prefix=prefix)

    def test_loaded_name_reuses_held_file_before_any_new_search(self):
        inspector = object.__new__(remote.ElfClosure)
        inspector.until = time.monotonic()+5
        inspector.names = {"model.so.1":"/model/held/model.so.1"}
        inspector.files = {"/model/held/model.so.1":True}
        with patch.object(remote.os.path,"lexists") as exists,patch.object(inspector,"member") as member:
            self.assertEqual(inspector.resolve("model.so.1",("/model/later",),"control"),
                "/model/held/model.so.1")
            exists.assert_not_called()
            member.assert_not_called()
            inspector.files = {}
            with self.assertRaisesRegex(ValueError,"dialog_elf_loaded_name_without_hold"):
                inspector.resolve("model.so.1",("/model/later",),"control")


if __name__ == "__main__":
    Preparation.inventory = sys.argv.pop(1)
    Preparation.parser_source = sys.argv.pop(1)
    module = types.ModuleType("declared_pure_elf_parser_model")
    exec(compile(local.elf_parser_source(Path(Preparation.parser_source).read_bytes()),"<declared-elf-model>","exec"),module.__dict__)
    remote.elf = module
    Preparation.control = sys.argv.pop(1)
    unittest.main()
