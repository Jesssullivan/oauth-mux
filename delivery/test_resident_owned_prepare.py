"""Provider-free declared prepare models; synthetic archive/manager, real installer IO."""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import unittest
import uuid
from unittest import mock
import resident_owned_prepare as carrier
import guard_resident_owned_prepare as prepare
import guard_resident_enrollment_profile as guard
import guard_resident_owned_update as owned
import guard_resident_setup_dispatch as dispatch
import install
import pack
from test_delivery import DeliveryFixture

def fixture_directory(path,private=False):
    """Only this synthetic walker exempts the canonical root-owned sticky /tmp."""
    path=guard.canonical(str(path))
    descriptor=os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    current=Path("/")
    try:
        for part in path.parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=descriptor)
            os.close(descriptor)
            descriptor=child
            current/=part
            info=os.fstat(descriptor)
            sticky_tmp=current == Path("/tmp").resolve() and info.st_uid == 0 and info.st_mode&stat.S_ISVTX
            guard.require(info.st_uid in (0,os.getuid()) and (not info.st_mode&0o022 or sticky_tmp))
        if private:
            info=os.fstat(descriptor)
            guard.require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise

class PrepareModels(unittest.TestCase):
    # Reuse the real synthetic archive factory without inheriting unrelated suites.
    setUp=DeliveryFixture.setUp
    write=DeliveryFixture.write
    portable_bundle=DeliveryFixture.portable_bundle

    def fixture(self,*,retained=False):
        self.systemd.write_bytes(b"[Service]\nExecStart=@EXEC@\nUMask=0077\n[Install]\nWantedBy=default.target\n")
        payload=self.portable_bundle("release")
        manifest,files=pack.verify_bundle(payload)
        home=self.root/("home-"+uuid.uuid4().hex)
        paths=guard.fixed_paths(home)
        for key in ("prefix","records","runtime_state"):
            paths[key].mkdir(mode=0o700,parents=True)
        config=home/".config/systemd/user"
        (config/"default.target.wants").mkdir(mode=0o700,parents=True)
        (paths["runtime_state"]/"daemon.lock").write_bytes(b"")
        (paths["runtime_state"]/"daemon.lock").chmod(0o600)
        if retained:
            (paths["runtime_state"]/"metadata.sqlite").write_bytes(b"synthetic encrypted-state sentinel")
            (paths["runtime_state"]/"metadata.sqlite").chmod(0o600)
        epoch=str(uuid.uuid4())
        qpath=home/".local/state/omux-execution-20261005"/epoch/"receipt.json"
        qpath.parent.mkdir(mode=0o700,parents=True)
        archive=qpath.parent/"output-base"/owned.ARCHIVE_RELATIVE
        archive.parent.mkdir(mode=0o700,parents=True)
        archive.write_bytes(payload)
        qvalue={"id":epoch,"artifact_epoch":epoch,"profile":"standard","verb":"build",
            "targets":["//delivery:default_instance_archive"],"exit":0,"workload_exit":0,
            "descendants_empty":True,"cleanup":{"state":"empty"},"controller_failure":None,
            "source_dirty":"false","source_commit":"a"*40,"graph_sha256":"b"*64,
            "cache_reuse_requested":False,"cache_policy":None,"cache_key":None,
            "output_base":str(qpath.parent/"output-base")}
        qraw=pack.json_bytes(qvalue)
        qpath.write_bytes(qraw)
        selection={"archive_path":str(archive),"archive_sha256":pack.digest(payload),"archive_bytes":len(payload),
            "manifest_sha256":pack.digest(files["release-manifest.json"]),
            "qualification":{"path":str(qpath),"sha256":pack.digest(qraw),"bytes":len(qraw),
                "source_commit":"a"*40,"graph_sha256":"b"*64}}
        value={"schema_version":1,"ownership":"omux-installation","action":"prepare-owned","instance":"default",
            **{key:str(path) for key,path in paths.items()},"native_context":None,
            "permissions":{"connect_source":False,"activate_service":False,"restart_daemon":False},
            "service_preparation":{"daemon_reload":True,"enable_for_login":True,"start_now":False},
            "install_archive":selection}
        return home,value,payload

    def absent(self,limits=""):
        return {"LoadState":"not-found","ActiveState":"inactive","SubState":"dead","MainPID":"0",
            "FragmentPath":"","ControlGroup":"","MemoryMax":limits,"MemorySwapMax":limits,
            "TasksMax":limits,"CPUQuotaPerSecUSec":limits}

    def test_schema_exact_label_source_flags_hm_context_and_effect_authority(self):
        home,value,_=self.fixture()
        self.assertIs(prepare.schema(value,home),value)
        self.assertIs(guard.manifest_schema(value,home),value)
        self.assertIs(dispatch.carrier(["run",prepare.LABEL]),guard)
        self.assertEqual(guard.finite(["run",prepare.LABEL],"system",Path("/closed/input.json"),False)["PrivateNetwork"],"yes")
        guard.carrier_purpose(prepare.LABEL,"prepare-owned",False)
        for label in (guard.LABEL,guard.LIFECYCLE_LABEL,guard.EXISTING_ENROLLMENT_LABEL):
            with self.assertRaises(ValueError): guard.carrier_purpose(label,"prepare-owned",False)
        for key,changed in (("ownership","home-manager"),("native_context",{}),("instance","dev"),("action","install-and-enroll")):
            bad=copy.deepcopy(value);bad[key]=changed
            with self.assertRaises(ValueError): prepare.schema(bad,home)
        for group in ("permissions","service_preparation"):
            for key in value[group]:
                bad=copy.deepcopy(value);bad[group][key]=not value[group][key]
                with self.assertRaises(ValueError): prepare.schema(bad,home)
                bad[group][key]=int(value[group][key])
                with self.assertRaises(ValueError): prepare.schema(bad,home)
        for arguments,manager,reuse in ((["run","//delivery:install"],"system",False),
            (["run",prepare.LABEL,"--start"],"system",False),(["run",prepare.LABEL],"user",False),
            (["run",prepare.LABEL],"system",True)):
            with self.assertRaises(ValueError): guard.finite(arguments,manager,Path("/closed/input.json"),reuse)

    def test_missing_unit_defaults_are_not_effective_resident_caps(self):
        for limits in ("","infinity","18446744073709551615"):
            self.assertTrue(prepare.absent_service(self.absent(limits)))
        for key,item in (("LoadState","loaded"),("MainPID","1"),("ActiveState","active"),
            ("FragmentPath","/foreign/unit"),("ControlGroup","/populated")):
            value=self.absent();value[key]=item
            with self.assertRaises(ValueError): prepare.absent_service(value)

    def manager(self,home,value,*,bad_caps=False):
        calls=[]
        loaded=False
        def bounded(command,environment,**options):
            nonlocal loaded
            self.assertEqual(environment,{"HOME":str(home),"DBUS_SESSION_BUS_ADDRESS":"unix:path=/omux-resident-inputs/bus"})
            self.assertEqual(command[:3],["/declared/systemctl","--user","--quiet"])
            self.assertEqual(options["timeout"],15)
            calls.append(command[3:])
            verb=command[3]
            if verb == "show":
                if not loaded: values=self.absent("infinity")
                else:
                    exe=str(Path(value["prefix"])/"bin/omuxd")
                    values={"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","MainPID":"0",
                        "FragmentPath":str(home/".config/systemd/user/ai.xoxd.omux.service"),"ControlGroup":"",
                        "UnitFileState":"enabled","Slice":"app.slice","ExecStart":"{ path="+exe+" ; argv[]="+exe+" --state-dir "+value["runtime_state"]+" ; ignore_errors=no ; pid=0 ; status=0/0 }",
                        "DropInPaths":"","NeedDaemonReload":"no","MemoryMax":"268435456","MemorySwapMax":"0",
                        "TasksMax":"33" if bad_caps else "32","CPUQuotaPerSecUSec":"100ms"}
                return ("\n".join(key+"="+item for key,item in sorted(values.items()))+"\n").encode()
            if verb == "enable":
                self.assertEqual(command[4:],[value["service_path"]])
                for parent in (home/".config/systemd/user",home/".config/systemd/user/default.target.wants"):
                    (parent/"ai.xoxd.omux.service").symlink_to(value["service_path"])
                return b""
            if verb == "daemon-reload":
                self.assertEqual(command[4:],[])
                loaded=True
                return b""
            raise AssertionError("no start/restart/stop/unlock/source or installed executable")
        return bounded,calls

    def test_real_archive_installer_registration_and_independent_postcleanup_transition(self):
        home,value,_=self.fixture(retained=True)
        deadline=time.monotonic_ns()+120*10**9
        with mock.patch.object(guard,"open_directory",side_effect=fixture_directory), \
                mock.patch.object(owned,"inactive_cgroup",return_value={"unit_cgroup_absent":True}):
            observer=prepare.InstallationPrepare(value,home,deadline)
            try:
                bounded,calls=self.manager(home,value)
                result=carrier.execute_prepare(Path("/declared/systemctl"),value,
                    {"HOME":str(home),"DBUS_SESSION_BUS_ADDRESS":"unix:path=/omux-resident-inputs/bus"},
                    bounded,lambda timeout=20:timeout,deadline)
                self.assertTrue(result["service_enabled_for_login"])
                self.assertFalse(result["service_started"])
                self.assertEqual([row[0] for row in calls if row[0] != "show"],["enable","daemon-reload"])
                # Producer did not claim the independent guardian transition.
                self.assertFalse(observer.finished)
                observer.installed()
                self.assertTrue(observer.finished)
                self.assertFalse(install._record(Path(value["prefix"]),Path(value["records"]))["serviceActivated"])
                self.assertEqual((Path(value["runtime_state"])/"metadata.sqlite").read_bytes(),
                    b"synthetic encrypted-state sentinel")
                observer.recheck()
                (Path(value["prefix"])/"bin/omux").write_bytes(b"mutated installed bytes")
                with self.assertRaises(ValueError): observer.recheck()
            finally: observer.close()

    def test_foreign_alias_or_nonempty_destination_refuses_before_mutation(self):
        with mock.patch.object(guard,"open_directory",side_effect=fixture_directory):
            for role in ("alias","prefix","records"):
                home,value,_=self.fixture()
                target=(home/".config/systemd/user/ai.xoxd.omux.service" if role == "alias"
                    else Path(value[role])/"foreign")
                target.write_bytes(b"foreign")
                with mock.patch.object(install,"_write",side_effect=AssertionError("no installation writes")):
                    with self.assertRaises(ValueError): prepare.InstallationPrepare(value,home,time.monotonic_ns()+30*10**9)

    def test_mutated_build_and_archive_pins_refuse(self):
        with mock.patch.object(guard,"open_directory",side_effect=fixture_directory):
            for role in ("qualification","archive"):
                home,value,_=self.fixture()
                path=Path(value["install_archive"]["qualification"]["path"] if role == "qualification"
                    else value["install_archive"]["archive_path"])
                path.write_bytes(path.read_bytes()+b"changed")
                with self.assertRaises(ValueError): prepare.InstallationPrepare(value,home,time.monotonic_ns()+30*10**9)

    def test_prepare_lock_contention_is_nonblocking_and_no_payload_is_written(self):
        home,value,payload=self.fixture()
        records=Path(value["records"])
        fd=os.open(records/"install.lock",os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:
            fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            with mock.patch.object(install,"_write",side_effect=AssertionError("no write after contention")):
                with self.assertRaises(BlockingIOError):
                    install.prepare_bundle(payload,Path(value["prefix"]),records,Path(value["service_path"]),
                        Path(value["runtime_state"]),mock.Mock(),mock.Mock(),deadline_ns=time.monotonic_ns()+30*10**9)
            self.assertFalse((Path(value["prefix"])/"bin").exists())
        finally: os.close(fd)

    def test_callback_failure_rolls_back_new_payload_record_and_never_registers(self):
        home,value,payload=self.fixture()
        before,after=mock.Mock(),mock.Mock(side_effect=ValueError("postwrite predicate"))
        with self.assertRaises(ValueError):
            install.prepare_bundle(payload,Path(value["prefix"]),Path(value["records"]),Path(value["service_path"]),
                Path(value["runtime_state"]),before,after,deadline_ns=time.monotonic_ns()+30*10**9)
        before.assert_called_once_with()
        after.assert_called_once()
        self.assertFalse((Path(value["records"])/"install.json").exists())
        self.assertFalse(Path(value["service_path"]).exists())
        self.assertFalse((Path(value["prefix"])/"bin/omuxd").exists())
        self.assertFalse((home/".config/systemd/user/ai.xoxd.omux.service").exists())

    def test_original_deadline_failure_before_and_during_write_is_not_renewed(self):
        home,value,payload=self.fixture()
        args=(payload,Path(value["prefix"]),Path(value["records"]),Path(value["service_path"]),Path(value["runtime_state"]))
        with self.assertRaises(ValueError): install.prepare_bundle(*args,mock.Mock(),mock.Mock(),deadline_ns=time.monotonic_ns()-1)
        before=mock.Mock()
        now=[1]
        writes=[]
        actual_write=install._write
        def write_then_expire(path,raw,mode):
            actual_write(path,raw,mode)
            writes.append(path)
            now[0]=100
        with mock.patch.object(install.time,"monotonic_ns",side_effect=lambda:now[0]), \
                mock.patch.object(install,"_write",side_effect=write_then_expire):
            with self.assertRaises(ValueError): install.prepare_bundle(*args,before,mock.Mock(),deadline_ns=50)
        before.assert_called_once_with()
        self.assertEqual(len(writes),1)
        self.assertFalse(writes[0].exists())
        self.assertFalse((Path(value["records"])/"install.json").exists())

    def test_registration_bad_caps_retains_explicit_partial_install_no_start(self):
        home,value,_=self.fixture()
        with mock.patch.object(guard,"open_directory",side_effect=fixture_directory), \
                mock.patch.object(owned,"inactive_cgroup",return_value={"unit_cgroup_absent":True}):
            bounded,calls=self.manager(home,value,bad_caps=True)
            with self.assertRaises(ValueError): carrier.execute_prepare(Path("/declared/systemctl"),value,
                {"HOME":str(home),"DBUS_SESSION_BUS_ADDRESS":"unix:path=/omux-resident-inputs/bus"},
                bounded,lambda timeout=20:timeout,time.monotonic_ns()+120*10**9)
            self.assertIsNotNone(install._record(Path(value["prefix"]),Path(value["records"])))
            self.assertEqual([row[0] for row in calls if row[0] != "show"],["enable","daemon-reload"])

    def test_postcleanup_transition_requires_exact_success_and_same_original_deadline(self):
        admission=guard.Admission.__new__(guard.Admission)
        admission.installation_prepare=mock.Mock()
        admission.installation_prepare.files=[]
        admission.original_deadline_ns=time.monotonic_ns()+120*10**9
        admission.deadline_ns=admission.original_deadline_ns-30*10**9
        for status,cleaned in ((False,True),(0,False),(1,True)):
            with self.assertRaises(ValueError): admission.complete_owned_prepare(status,cleaned)
        admission.installation_prepare.installed.assert_not_called()
        admission.complete_owned_prepare(0,True)
        self.assertEqual(admission.deadline_ns,admission.original_deadline_ns)
        self.assertEqual(admission.installation_prepare.deadline,admission.original_deadline_ns)
        admission.installation_prepare.installed.assert_called_once_with()

    def test_retargeted_owned_alias_after_registration_refuses(self):
        home,value,payload=self.fixture()
        with mock.patch.object(guard,"open_directory",side_effect=fixture_directory):
            witness=prepare.InstallationPrepare(value,home,time.monotonic_ns()+60*10**9)
            try:
                install.prepare_bundle(payload,Path(value["prefix"]),Path(value["records"]),Path(value["service_path"]),
                    Path(value["runtime_state"]),witness.before_write,witness.written,deadline_ns=witness.deadline)
                aliases=[home/".config/systemd/user/ai.xoxd.omux.service",
                    home/".config/systemd/user/default.target.wants/ai.xoxd.omux.service"]
                for alias in aliases: alias.symlink_to(value["service_path"])
                witness.installed()
                aliases[0].unlink()
                aliases[0].symlink_to(value["service_path"])
                with self.assertRaises(ValueError): witness.recheck()
            finally: witness.close()

    def test_existing_owned_record_cannot_be_adopted_by_first_prepare(self):
        home,value,payload=self.fixture()
        install.install_bundle(payload,Path(value["prefix"]),Path(value["records"]),Path(value["service_path"]),
            daemon_state_dir=Path(value["runtime_state"]))
        before=mock.Mock()
        with mock.patch.object(install,"_write",side_effect=AssertionError("no replacement")):
            with self.assertRaises(ValueError):
                install.prepare_bundle(payload,Path(value["prefix"]),Path(value["records"]),Path(value["service_path"]),
                    Path(value["runtime_state"]),before,mock.Mock(),deadline_ns=time.monotonic_ns()+30*10**9)
        before.assert_not_called()

    def test_prepare_early_constructor_cleanup_detaches_all_owned_resources_on_fault(self):
        admission=guard.Admission.__new__(guard.Admission)
        admission.preparing_label=True
        admission.installation_prepare=mock.Mock(close=mock.Mock(side_effect=OSError("close")))
        admission.owned_start=None
        admission.created_sockets=[]
        admission.created_control=None
        admission.created_manager=False
        admission.held=[10,11]
        with mock.patch.object(guard.os,"close") as close:
            with self.assertRaises(OSError): admission.close()
            self.assertEqual(close.call_args_list,[mock.call(11),mock.call(10)])
        self.assertEqual(admission.held,[])
        self.assertIsNone(admission.installation_prepare)


    def test_prepare_close_failure_still_releases_runtime_files_and_parent_fds(self):
        witness=prepare.InstallationPrepare.__new__(prepare.InstallationPrepare)
        witness.software=mock.Mock(close=mock.Mock(side_effect=OSError("close")))
        witness.runtime=mock.Mock()
        public=mock.Mock()
        witness.files=[public]
        witness.parents=[(Path("/synthetic"),11,())]
        runtime=witness.runtime
        with mock.patch.object(prepare.os,"close") as close:
            with self.assertRaises(OSError): witness.close()
            runtime.close.assert_called_once_with()
            public.close.assert_called_once_with()
            close.assert_called_once_with(11)

if __name__ == "__main__":
    unittest.main()
