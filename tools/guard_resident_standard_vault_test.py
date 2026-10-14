"""Provider-free models for versioned local standard-service metadata."""
import copy
import contextlib
import json
import tempfile
import time
import os
from pathlib import Path
import unittest
from unittest.mock import call, patch
import guard_resident_vault_profile as vault

def observed():
    base={"uid":os.getuid(),"pid":101,"start_ticks":7}
    return {"schema":"omux-existing-vault-metadata-v2","broker":dict(base),
        "manager":dict(base,pid=102,owner=":1.2"),"secret_service":dict(base,pid=103,owner=":1.3"),
        "provider":"standard-secret-service","default_collection":"/org/freedesktop/secrets/collection/selected",
        "default_exists":True,"locked":True,"items_read":False,"secrets_read":False,"provider_invocation":False}
def selected(unlock=False):
    return {"schema_version":2,"purpose":"unlock-standard-vault" if unlock else "observe-standard-vault",
        "permissions":{"metadata":True,"unlock":unlock},"mapping":None,"expected":observed() if unlock else None}
def legacy():
    value=observed();value["schema"]="omux-existing-vault-metadata-v1"
    del value["default_collection"];value["default_is_login"]=True;value["provider"]="gnome-keyring-48.0"
    for name in ("broker","manager","secret_service"):
        value[name]["exe"]=vault.GNOME_EXE if name=="secret_service" else "/usr/bin/synthetic-platform"
    return value

class StandardVaultModels(unittest.TestCase):
    def test_standard_roles_need_owned_stable_pid_not_a_readable_exe(self):
        with patch.object(vault.resident,"start_ticks",return_value=7) as ticks, \
                patch.object(vault.os,"readlink",side_effect=PermissionError("protected")) as readlink:
            self.assertEqual(vault.standard_process(101),{"uid":os.getuid(),"pid":101,"start_ticks":7})
            self.assertEqual(ticks.call_args_list,[call(101),call(101)])
            readlink.assert_not_called()
        with patch.object(vault.resident,"start_ticks",return_value=7), \
                patch.object(vault.os,"readlink",side_effect=PermissionError("protected")):
            with self.assertRaises(PermissionError):vault.process(101)
        for ticks in ((7,8),(0,0)):
            with patch.object(vault.resident,"start_ticks",side_effect=ticks):
                with self.assertRaises(ValueError):vault.standard_process(101)
        with patch.object(vault.resident,"start_ticks",side_effect=ValueError("foreign owner")):
            with self.assertRaises(ValueError):vault.standard_process(101)

    def test_v2_shape_is_exact_and_legacy_exe_evidence_remains_mandatory(self):
        self.assertEqual(vault.standard_observation(observed()),observed())
        self.assertEqual(vault.validate_observation(legacy()),legacy())
        with self.assertRaises(ValueError):vault.validate_observation(observed())
        with self.assertRaises(ValueError):vault.standard_observation(legacy())
        for name in ("broker","manager","secret_service"):
            value=observed();value[name]["exe"]="/usr/bin/ignored"
            with self.assertRaises(ValueError):vault.standard_observation(value)
            value=legacy();del value[name]["exe"]
            with self.assertRaises(ValueError):vault.validate_observation(value)
            for key,replacement in (("uid",os.getuid()+1),("pid",1),("start_ticks",0),("pid",True)):
                value=observed();value[name][key]=replacement
                with self.assertRaises(ValueError):vault.standard_observation(value)
        for owner in ("org.freedesktop.secrets",":1/2","",None):
            value=observed();value["secret_service"]["owner"]=owner
            with self.assertRaises(ValueError):vault.standard_observation(value)

    def test_standard_unlock_requires_existing_locked_collection_with_no_factor_mapping(self):
        self.assertEqual(vault.schema(selected()),selected())
        self.assertEqual(vault.schema(selected(True)),selected(True))
        for mutate in ("mapping","old-snapshot","old-version","permission","missing","unlocked"):
            value=selected(True)
            if mutate=="mapping":value["mapping"]={"role":"become/password"}
            elif mutate=="old-snapshot":value["expected"]=legacy()
            elif mutate=="old-version":value["schema_version"]=1
            elif mutate=="permission":value["permissions"]["unlock"]=False
            elif mutate=="missing":
                value["expected"]["default_collection"]="/";value["expected"]["default_exists"]=False
                value["expected"]["locked"]=None
            else:value["expected"]["locked"]=False
            with self.subTest(mutation=mutate),self.assertRaises(ValueError):vault.schema(value)
        for path in ("", "/double//slash", "/trailing/", "/../selected", "/has space"):
            value=observed();value["default_collection"]=path
            with self.assertRaises(ValueError):vault.standard_observation(value)
        value=observed();value.update(secret_service=None,provider="absent",default_collection=None,
            default_exists=None,locked=None)
        self.assertEqual(vault.standard_observation(value),value)
        with self.assertRaises(ValueError):vault.standard_unlockable(value)

    def test_expected_snapshot_rechecks_all_actual_role_pids_without_fallback(self):
        value=observed()
        with patch.object(vault,"standard_process",side_effect=lambda pid:
                {key:item for key,item in next(row for row in
                    (value["broker"],value["manager"],value["secret_service"]) if row["pid"]==pid).items()
                    if key!="owner"}) as process,patch.object(vault,"process") as legacy_process:
            vault.expected_processes(value)
            self.assertEqual(process.call_args_list,[call(101),call(102),call(103)])
            legacy_process.assert_not_called()
        changed={key:item for key,item in value["broker"].items() if key!="owner"};changed["start_ticks"]+=1
        with patch.object(vault,"standard_process",return_value=changed):
            with self.assertRaises(ValueError):vault.expected_processes(value)
        value=legacy()
        with patch.object(vault,"process",side_effect=PermissionError("protected")), \
                patch.object(vault,"standard_process") as standard_process:
            with self.assertRaises(PermissionError):vault.expected_processes(value)
            standard_process.assert_not_called()

    def test_only_four_exact_vault_run_labels_share_unchanged_offline_bounds(self):
        for label in vault.LABELS:
            self.assertEqual(vault.finite(["run",label],"system","input.json",False),
                {"PrivateNetwork":"yes","ProtectSystem":"strict","PrivateTmp":"yes"})
        for arguments in (["run",vault.STANDARD_LABEL,"--standard-service-metadata"],
                ["run","//delivery:arbitrary"],["test",vault.STANDARD_UNLOCK_LABEL]):
            with self.assertRaises(ValueError):vault.finite(arguments,"system","input.json",False)
        for manager,reuse in (("user",False),("system",True)):
            with self.assertRaises(ValueError):vault.finite(["run",vault.STANDARD_LABEL],manager,"input.json",reuse)
        self.assertEqual((vault.PROOF_MEMORY,vault.PROOF_TASKS,vault.PROOF_CPU_PERCENT),(4026531840,480,190))

    def test_standard_namespace_binding_has_only_bus_and_no_control_or_factor(self):
        admission=vault.Admission.__new__(vault.Admission)
        admission.root=Path("/owned/input");admission.sources={admission.root/"bus":Path("/run/user/1000/bus")}
        self.assertEqual(admission.bindings(),["/owned/input:/omux-resident-inputs",
            "/run/user/1000/bus:/omux-resident-inputs/bus:norbind"])


class AdmissionOwnershipModels(unittest.TestCase):
    @contextlib.contextmanager
    def namespace(self):
        # Only ancestors/runtime and bus peer are fixture-adapted. Constructor
        # input, mountpoint, all FD opens/fstats/unlinks/closes are real.
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/"input";root.mkdir(mode=0o700)
            runtime=Path(temporary)/"runtime";runtime.mkdir(mode=0o700)
            manifest=root/"input.json"
            manifest.write_text(json.dumps(selected()),encoding="ascii");manifest.chmod(0o600)
            opened=[]
            roles={}
            actual_open=os.open
            actual_fstat=os.fstat
            runtime_name=Path("/run/user")/str(os.getuid())
            def open_directory(path,private=False):
                target=runtime if Path(path)==runtime_name else Path(path)
                return actual_open(target,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            actual_hold=vault.Admission._hold_fd
            def hold(instance,opener,*arguments,**options):
                # Observe the returned actual ownership operation, without
                # mirroring it or treating transient ancestry reads as held.
                fd=actual_hold(instance,opener,*arguments,**options)
                opened.append(fd)
                path=arguments[0]
                roles[fd]=("runtime" if Path(path)==runtime_name else "directory") if opener is vault.resident.open_directory else (
                    "file" if str(path)=="input.json" else "placeholder")
                return fd
            with patch.object(vault.resident,"open_directory",side_effect=open_directory), \
                    patch.object(vault.Admission,"_hold_fd",hold), \
                    patch.object(vault,"socket_witness",return_value=((1,2,3,4,5),101,7)):
                yield root,manifest,opened,roles,actual_fstat

    def assert_drained(self,instance,opened,actual_fstat):
        self.assertEqual(instance.held,[])
        self.assertEqual(instance.created,[])
        for descriptor in opened:
            with self.assertRaises(OSError):actual_fstat(descriptor)

    def test_actual_constructor_preregistration_append_allocation_interrupt_failures_open_no_untracked_fd(self):
        sites=[("held",index) for index in range(1,5)]+[("parents",1),("created",1)]
        for field,index in sites:
            for after in (False,True):
                for error_type in (MemoryError,KeyboardInterrupt):
                    with self.subTest(field=field,index=index,after=after,error=error_type),self.namespace() as (root,manifest,opened,_,actual_fstat):
                        primary=error_type("private allocation seam")
                        reached=[]
                        class Slots(list):
                            def append(self,value):
                                reached.append(None)
                                if len(reached)==index and not after:raise primary
                                super().append(value)
                                if len(reached)==index and after:raise primary
                        class Failing(vault.Admission):
                            def __setattr__(self,name,value):
                                if name==field:value=Slots(value)
                                object.__setattr__(self,name,value)
                        instance=Failing.__new__(Failing)
                        with self.assertRaises(error_type) as refused:
                            instance.__init__(manifest,root,time.monotonic_ns()+120*10**9,label=vault.STANDARD_LABEL)
                        self.assertIs(refused.exception,primary)
                        self.assertEqual(len(reached),index)
                        if field=="held":self.assertEqual(len(opened),index-1)
                        elif field=="parents":self.assertEqual(len(opened),3)
                        else:self.assertEqual(len(opened),3)
                        self.assert_drained(instance,opened,actual_fstat)
                        self.assertEqual(list(root.iterdir()),[manifest])

    def test_actual_constructor_returned_fd_field_transfer_refusal_is_owned_before_assignment(self):
        for field in ("directory","file","facts"):
            for after in (False,True):
                for error_type in (MemoryError,KeyboardInterrupt):
                    with self.subTest(field=field,after=after,error=error_type),self.namespace() as (root,manifest,opened,_,actual_fstat):
                        primary=error_type("private field transfer")
                        class Failing(vault.Admission):
                            def __setattr__(self,name,value):
                                if name==field and not after:raise primary
                                object.__setattr__(self,name,value)
                                if name==field and after:raise primary
                        instance=Failing.__new__(Failing)
                        with self.assertRaises(error_type) as refused:
                            instance.__init__(manifest,root,time.monotonic_ns()+120*10**9,label=vault.STANDARD_LABEL)
                        self.assertIs(refused.exception,primary)
                        self.assertEqual(len(opened),{"directory":1,"file":2,"facts":4}[field])
                        self.assert_drained(instance,opened,actual_fstat)
                        self.assertEqual(list(root.iterdir()),[manifest])

    def test_actual_input_runtime_placeholder_fstat_and_fchmod_failures_drain_original_fds(self):
        for role,occurrence in (("file",1),("runtime",1),("placeholder",1),("placeholder",2),("chmod",1)):
            with self.subTest(role=role,occurrence=occurrence),self.namespace() as (root,manifest,opened,roles,actual_fstat):
                primary=MemoryError("private metadata record")
                reached=[]
                def fstat(descriptor):
                    if roles.get(descriptor)==role:
                        reached.append(descriptor)
                        if len(reached)==occurrence:raise primary
                    return actual_fstat(descriptor)
                actual_chmod=os.fchmod
                def chmod(descriptor,mode):
                    reached.append(descriptor)
                    actual_chmod(descriptor,mode)
                    raise primary
                instance=vault.Admission.__new__(vault.Admission)
                with patch.object(vault.os,"fstat",side_effect=fstat), \
                        patch.object(vault.os,"fchmod",side_effect=chmod if role=="chmod" else actual_chmod):
                    with self.assertRaises(MemoryError) as refused:
                        instance.__init__(manifest,root,time.monotonic_ns()+120*10**9,label=vault.STANDARD_LABEL)
                self.assertIs(refused.exception,primary)
                self.assertEqual(len(reached),occurrence)
                self.assert_drained(instance,opened,actual_fstat)
                if role=="placeholder" and occurrence==1:
                    # No first fstat creator witness: refuse/close, without
                    # guessing that a basename is ours or claiming cleanup.
                    self.assertTrue((root/"bus").is_file())
                else:self.assertEqual(list(root.iterdir()),[manifest])

    def test_actual_close_first_middle_unlink_faults_attempt_all_once_and_preserve_foreign(self):
        for seam in ("first-close","middle-close","unlink","foreign"):
            with self.subTest(seam=seam),self.namespace() as (root,manifest,opened,_,actual_fstat):
                instance=vault.Admission(manifest,root,time.monotonic_ns()+120*10**9,label=vault.STANDARD_LABEL)
                self.assertEqual(len(opened),4)
                self.assertEqual(instance.facts["purpose"],"observe-standard-vault")
                self.assertFalse(instance.facts["factor_contents_read_by_guard"])
                actual_close=os.close
                actual_unlink=Path.unlink
                primary=OSError("private close/remove fault")
                attempts=[]
                if seam=="foreign":
                    (root/"bus").rename(root/"original-bus")
                    (root/"bus").write_bytes(b"public foreign");(root/"bus").chmod(0o600)
                def close(descriptor):
                    attempts.append(descriptor)
                    actual_close(descriptor)
                    if seam=="first-close" and len(attempts)==1:raise primary
                    if seam=="middle-close" and len(attempts)==2:raise primary
                def unlink(path,*arguments,**options):
                    if seam=="unlink" and path==root/"bus":raise primary
                    return actual_unlink(path,*arguments,**options)
                with patch.object(vault.os,"close",side_effect=close),patch.object(Path,"unlink",unlink):
                    if seam=="foreign":instance.close()
                    else:
                        with self.assertRaises(OSError) as refused:instance.close()
                        self.assertIs(refused.exception,primary)
                    self.assertEqual(attempts,list(reversed(opened)))
                    instance.close()
                    self.assertEqual(attempts,list(reversed(opened)))
                self.assert_drained(instance,opened,actual_fstat)
                if seam=="foreign":self.assertEqual((root/"bus").read_bytes(),b"public foreign")
                elif seam=="unlink":self.assertTrue((root/"bus").is_file())
                else:self.assertEqual(list(root.iterdir()),[manifest])

    def test_actual_constructor_primary_bus_refusal_survives_cleanup_fault_and_all_fds_drain(self):
        with self.namespace() as (root,manifest,opened,_,actual_fstat):
            primary=KeyboardInterrupt("private bus refusal")
            secondary=OSError("private close refusal")
            reached=[]
            actual_close=os.close
            def close(descriptor):
                reached.append(descriptor)
                actual_close(descriptor)
                raise secondary
            instance=vault.Admission.__new__(vault.Admission)
            with patch.object(vault,"socket_witness",side_effect=primary), \
                    patch.object(vault.os,"close",side_effect=close):
                with self.assertRaises(KeyboardInterrupt) as refused:
                    instance.__init__(manifest,root,time.monotonic_ns()+120*10**9,label=vault.STANDARD_LABEL)
            self.assertIs(refused.exception,primary)
            self.assertEqual(len(opened),3)
            self.assertEqual(reached,list(reversed(opened)))
            self.assert_drained(instance,opened,actual_fstat)
            self.assertEqual(list(root.iterdir()),[manifest])


    def test_shared_nofollow_opener_old_parent_close_fault_drains_acquired_child_without_retry(self):
        for old_index in (0,1):
            for child_close_fault in (False,True):
                with self.subTest(old_index=old_index,child_close_fault=child_close_fault),tempfile.TemporaryDirectory() as temporary:
                    base=Path(temporary);(base/"parent").mkdir(mode=0o700);(base/"parent/child").mkdir(mode=0o700)
                    actual_open=os.open
                    actual_close=os.close
                    actual_fstat=os.fstat
                    opened=[]
                    attempts=[]
                    primary=OSError("private old-parent close")
                    def opening(path,flags,*arguments,**options):
                        descriptor=actual_open(base if path=="/" else path,flags,*arguments,**options)
                        opened.append(descriptor)
                        return descriptor
                    def closing(descriptor):
                        attempts.append(descriptor)
                        actual_close(descriptor)
                        if descriptor==opened[old_index]:raise primary
                        if child_close_fault and descriptor==opened[-1]:raise MemoryError("private child close")
                    with patch.object(vault.resident.os,"open",side_effect=opening), \
                            patch.object(vault.resident.os,"close",side_effect=closing):
                        with self.assertRaises(OSError) as refused:
                            vault.resident.open_directory(Path("/parent/child"),private=True)
                    self.assertIs(refused.exception,primary)
                    self.assertEqual(len(opened),old_index+2)
                    self.assertEqual(attempts,opened)
                    for descriptor in opened:
                        with self.assertRaises(OSError):actual_fstat(descriptor)

    def test_shared_nofollow_opener_fstat_mode_symlink_refusals_and_successful_integer_abi(self):
        for seam in ("fstat","mode","symlink","success"):
            with self.subTest(seam=seam),tempfile.TemporaryDirectory() as temporary:
                base=Path(temporary);(base/"parent").mkdir(mode=0o700);(base/"parent/child").mkdir(mode=0o700)
                if seam=="mode":(base/"parent/child").chmod(0o777)
                if seam=="symlink":
                    (base/"parent/child").rename(base/"target")
                    (base/"parent/child").symlink_to(base/"target",target_is_directory=True)
                actual_open=os.open
                actual_close=os.close
                actual_fstat=os.fstat
                opened=[]
                attempts=[]
                reached=[]
                primary=KeyboardInterrupt("private child metadata")
                def opening(path,flags,*arguments,**options):
                    descriptor=actual_open(base if path=="/" else path,flags,*arguments,**options)
                    opened.append(descriptor)
                    return descriptor
                def closing(descriptor):
                    attempts.append(descriptor);actual_close(descriptor)
                def fstat(descriptor):
                    reached.append(descriptor)
                    if seam=="fstat":raise primary
                    return actual_fstat(descriptor)
                with patch.object(vault.resident.os,"open",side_effect=opening), \
                        patch.object(vault.resident.os,"close",side_effect=closing), \
                        patch.object(vault.resident.os,"fstat",side_effect=fstat):
                    if seam=="success":
                        descriptor=vault.resident.open_directory(Path("/parent/child"),private=True)
                        self.assertIs(type(descriptor),int)
                        self.assertEqual(descriptor,opened[-1])
                        self.assertEqual(actual_fstat(descriptor).st_ino,(base/"parent/child").stat().st_ino)
                        self.assertEqual(attempts,opened[:-1])
                        os.close(descriptor)
                    else:
                        with self.assertRaises((OSError,ValueError,KeyboardInterrupt)) as refused:
                            vault.resident.open_directory(Path("/parent/child"),private=True)
                        if seam=="fstat":self.assertIs(refused.exception,primary)
                    self.assertEqual(attempts,opened)
                    for descriptor in opened:
                        with self.assertRaises(OSError):actual_fstat(descriptor)
                if seam=="fstat":self.assertTrue(reached)

if __name__=="__main__":
    unittest.main()
