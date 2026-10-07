"""Offline owned-update authority, runtime fencing and installation transition models."""
import copy
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
import stat
import time
import unittest
from unittest import mock
import guard_resident_owned_update as update
import guard_resident_enrollment_profile as resident

HOME = Path("/home/jess")
EPOCH = "11111111-1111-4111-8111-111111111111"
ROOT = HOME/".local/state/omux-execution-20261005"/EPOCH
def selection():
    return {"previous_archive_sha256":"a"*64,"previous_archive_bytes":1,"previous_manifest_sha256":"b"*64,
        "previous_archive_path":str(ROOT/"output-base/execroot/_main/bazel-out/k8-fastbuild/bin/delivery/default_instance_archive.tar.gz"),
        "archive_sha256":"c"*64,"archive_bytes":1,"manifest_sha256":"d"*64,
        "archive_path":str(ROOT/"output-base/execroot/_main/bazel-out/k8-fastbuild/bin/delivery/default_instance_archive.tar.gz"),
        "qualification":{"path":str(ROOT/"receipt.json"),"sha256":"e"*64,"bytes":1,
            "source_commit":"f"*40,"graph_sha256":"0"*64}}
def manifest():
    return {"schema_version":1,"ownership":"omux-installation","action":"update-existing","instance":"default",
        **{key:str(path) for key,path in resident.fixed_paths(HOME).items()},
        "native_context":None,"permissions":{"connect_source":False,"activate_service":False,"restart_daemon":False},
        "update":selection()}
def idle(selected):
    exe = str(Path(selected["prefix"])/"bin/omuxd")
    state = selected["runtime_state"]
    return {"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","MainPID":"0","ControlGroup":"",
        "FragmentPath":selected["service_path"],"UnitFileState":"enabled","Slice":"app.slice","DropInPaths":"","NeedDaemonReload":"no",
        "ExecStart":"{ path="+exe+" ; argv[]="+exe+" --state-dir "+state+" ; ignore_errors=no ; pid=0 ; status=0/0 }",
        "MemoryMax":"268435456","MemorySwapMax":"0","TasksMax":"32","CPUQuotaPerSecUSec":"100ms"}

def fixture_directory(path,private=False):
    """Test-only nofollow walk; exempt only actual root-owned sticky /tmp."""
    path = resident.canonical(str(path))
    descriptor = os.open("/",os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    current = Path("/")
    try:
        for part in path.parts[1:]:
            child = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            current /= part
            info = os.fstat(descriptor)
            sticky_tmp = current == Path("/tmp") and info.st_uid == 0 and info.st_mode&stat.S_ISVTX
            resident.require(info.st_uid in (0,os.getuid()) and (not info.st_mode&0o022 or sticky_tmp))
        if private:
            info = os.fstat(descriptor)
            resident.require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise

class UpdateModels(unittest.TestCase):
    def start_manifest(self):
        value = manifest()
        value["action"] = "start-existing"
        value["permissions"]["activate_service"] = True
        update_value = value.pop("update")
        value["start"] = {key:update_value[key] for key in
            ("archive_path","archive_sha256","archive_bytes","manifest_sha256","qualification")}
        return value

    def test_first_start_is_owned_context_free_and_refuses_source_factor_or_restart(self):
        value = self.start_manifest()
        self.assertEqual(resident.manifest_schema(value,HOME),value)
        changes = (("ownership","home-manager"),("native_context",{"codex_home":"/private/native"}),
            ("factor","/private/factor"))
        for key,field in changes:
            bad = copy.deepcopy(value)
            bad[key] = field
            with self.assertRaises(ValueError):
                resident.manifest_schema(bad,HOME)
        for key,field in (("connect_source",True),("restart_daemon",True),("activate_service",False)):
            bad = copy.deepcopy(value)
            bad["permissions"][key] = field
            with self.assertRaises(ValueError):
                resident.manifest_schema(bad,HOME)

    def test_first_start_active_properties_refuse_wrong_unit_or_limits(self):
        selected = self.start_manifest()
        values = idle(selected)
        uid = os.getuid()
        values.update(ActiveState="active",SubState="running",MainPID="10",
            ControlGroup="/user.slice/user-"+str(uid)+".slice/user@"+str(uid)+".service/app.slice/ai.xoxd.omux.service")
        with mock.patch.object(resident,"resolve_owned_unit_fragment",return_value=Path(selected["service_path"])):
            self.assertEqual(update.active_start_properties(values,selected)[0],10)
        for key,value in (("MemoryMax","268435457"),("ControlGroup","/foreign"),("ExecStart","foreign"),
            ("UnitFileState","disabled"),("SubState","auto-restart"),("MainPID","0")):
            bad = dict(values)
            bad[key] = value
            with self.assertRaises(ValueError):
                update.active_start_properties(bad,selected)

    def test_first_start_stale_qualification_refuses_before_archive_or_state_io(self):
        selected=self.start_manifest()
        receipt=self.actual_test_receipt()
        receipt.update(id=EPOCH,artifact_epoch=EPOCH,verb="build",targets=["//delivery:default_instance_archive"])
        # Deliberately stale source; the public receipt hash itself still matches.
        raw=json.dumps(receipt).encode()
        q=selected["start"]["qualification"]
        q.update(sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw))
        public=mock.Mock(raw=raw)
        with mock.patch.object(update,"PublicFile",return_value=public) as files, \
                mock.patch.object(update.os,"open",side_effect=AssertionError("no private or archive IO")):
            with self.assertRaises(ValueError):
                update.OwnedFirstStart(selected,HOME,time.monotonic_ns()+30*10**9)
        files.assert_called_once_with(q["path"],mock.ANY,8*1024*1024)
        public.close.assert_called_once_with()

    def test_first_start_control_peer_requires_private_socket_and_same_process(self):
        peer=((1,2,stat.S_IFSOCK|0o600,os.getuid(),os.getgid()),10,20)
        with mock.patch.object(resident,"start_ticks",return_value=20):
            update.start_control_peer(peer,10)
            for bad in (((1,2,stat.S_IFSOCK|0o666,os.getuid(),os.getgid()),10,20),
                    (peer[0],11,20),(peer[0],10,21)):
                with self.assertRaises(ValueError):
                    update.start_control_peer(bad,10)

    def test_locked_control_plane_truth_never_claims_usable_custody(self):
        value = {"protocol_version":1,"status":"vault_locked","custody_available":False,"metadata_loaded":False,
            "provider_access":False,"live_handoff_proven":False,"recovery_action":"unlock_platform_vault_then_restart_daemon"}
        self.assertEqual(update.start_health(value),{"control_plane_ready":True,"custody_available":False,"vault_locked":True})
        for key in ("custody_available","metadata_loaded","provider_access","live_handoff_proven"):
            bad = dict(value)
            bad[key] = True
            with self.assertRaises(ValueError):
                update.start_health(bad)
        with self.assertRaises(ValueError):
            update.start_health({"protocol_version":1,"status":"repair_required","custody_available":False,"live_handoff_proven":False})

    def test_first_start_recheck_refuses_actual_modified_owned_unit(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root=Path(temporary)
            root.chmod(0o700)
            home=root/"home"
            selected={"ownership":"omux-installation",**{key:str(path) for key,path in resident.fixed_paths(home).items()}}
            records=Path(selected["records"])
            unit=Path(selected["service_path"])
            records.mkdir(mode=0o700,parents=True)
            unit.parent.mkdir(mode=0o700,parents=True)
            unit.write_bytes(b"public owned unit")
            unit.chmod(0o600)
            record={"schemaVersion":1,"prefix":selected["prefix"],"product":{},"userService":str(unit),
                "serviceActivated":False,"artifact":{"archiveSha256":"a"*64},
                "files":[{"path":str(unit),"sha256":hashlib.sha256(unit.read_bytes()).hexdigest(),"mode":0o600}]}
            (records/"install.json").write_text(json.dumps(record))
            (records/"install.json").chmod(0o600)
            state=Path(selected["runtime_state"])
            state.mkdir(mode=0o700)
            (state/"daemon.lock").write_bytes(b"")
            (state/"daemon.lock").chmod(0o600)
            witness=update.OwnedFirstStart.__new__(update.OwnedFirstStart)
            witness.deadline=time.monotonic_ns()+30*10**9
            witness.files=[]
            witness.unit=resident.OwnedUnitCustody(selected)
            witness.state=state
            witness.directory=fixture_directory(state,private=True)
            witness.root_identity=resident.stable(os.fstat(witness.directory))
            witness.lock=os.open(state/"daemon.lock",os.O_PATH|os.O_NOFOLLOW)
            witness.lock_identity=resident.file_identity(os.fstat(witness.lock))
            try:
                witness.pristine()
                unit.write_bytes(b"modified owned unit")
                with self.assertRaises(ValueError):
                    witness.recheck()
            finally:
                witness.close()

    def test_retained_zero_lock_metadata_does_not_hold_exclusion_or_read_private_bytes(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            state = Path(temporary)
            state.chmod(0o700)
            (state/"daemon.lock").write_bytes(b"")
            (state/"daemon.lock").chmod(0o600)
            witness = update.OwnedFirstStart.__new__(update.OwnedFirstStart)
            witness.deadline=time.monotonic_ns()+30*10**9
            witness.files=[]
            witness.unit=mock.Mock()
            witness.state=state
            witness.directory=fixture_directory(state,private=True)
            witness.root_identity=resident.stable(os.fstat(witness.directory))
            witness.lock=os.open(state/"daemon.lock",os.O_PATH|os.O_NOFOLLOW)
            witness.lock_identity=resident.file_identity(os.fstat(witness.lock))
            try:
                with mock.patch.object(update.os,"read",side_effect=AssertionError("no private bytes")), \
                        mock.patch.object(update.os,"pread",side_effect=AssertionError("no private bytes")):
                    witness.pristine()
                other=os.open(state/"daemon.lock",os.O_RDWR|os.O_NOFOLLOW)
                try:
                    fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:
                    os.close(other)
                for name in ("state.sqlite","factor"):
                    (state/name).write_bytes(b"synthetic private bytes")
                    (state/name).chmod(0o600)
                    with self.assertRaises(ValueError):
                        witness.pristine()
                    (state/name).unlink()
                normal=("state.sqlite","state.sqlite.authority","state.sqlite.authority.lock")
                for name in normal:
                    (state/name).write_bytes(b"synthetic initialized custody")
                    (state/name).chmod(0o600)
                witness.recheck()
                with self.assertRaises(ValueError):
                    witness.pristine()
                for name in normal:
                    (state/name).unlink()
                (state/"daemon.lock").unlink()
                (state/"daemon.lock").write_bytes(b"")
                (state/"daemon.lock").chmod(0o600)
                with self.assertRaises(ValueError):
                    witness.recheck()
            finally:
                witness.close()
    def setUp(self):
        patcher = mock.patch.object(resident,"open_directory",side_effect=fixture_directory)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_update_is_owned_context_free_and_cannot_activate_or_connect(self):
        selected = manifest()
        self.assertEqual(resident.manifest_schema(selected,HOME),selected)
        for field in ("connect_source","activate_service","restart_daemon"):
            changed = copy.deepcopy(selected)
            changed["permissions"][field] = True
            with self.subTest(field=field),self.assertRaises(ValueError):
                resident.manifest_schema(changed,HOME)
        for key,value in (("ownership","home-manager"),("native_context",{"codex_home":"/home/jess/.codex"})):
            changed = copy.deepcopy(selected)
            changed[key] = value
            with self.assertRaises(ValueError):
                resident.manifest_schema(changed,HOME)
        changed = copy.deepcopy(selected)
        changed["action"] = "activate-existing-and-enroll"
        with self.assertRaises(ValueError):
            resident.manifest_schema(changed,HOME)

    def actual_test_receipt(self):
        # Exact public producer projection from f6410a6f; TEST is deliberately not a BUILD proof.
        return {
            "id": "f6410a6f-da21-40b7-bfc6-1b785494d745",
            "artifact_epoch": "f6410a6f-da21-40b7-bfc6-1b785494d745",
            "profile": "standard",
            "verb": "test",
            "targets": [
                "//:engine_test",
                "//:docs_check",
                "//tools:runtime_source_receipt",
                "//tools:execution_guard_test",
                "//tools:guard_dependency_profile_test",
                "//tools:guard_codex_live_profile_test",
                "//tools:guard_codex_fresh_live_profile_test",
                "//tools:guard_codex_login_profile_test",
                "//tools:guard_native_login_ui_profile_test",
                "//tools:guard_resident_enrollment_profile_test",
                "//delivery:resident_enrollment_contract_test"
            ],
            "source_dirty": "false",
            "source_commit": "77686afbb4135042b0d89343269cf66e3065f723",
            "graph_sha256": "58b05968c40297da5a868590788099807dc1d344288513c185b8eba65e51c6f9",
            "output_base": "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/cache-v2-e445854abf597c0a8db904e3ad38a5dd26ba36aff33272028835b6d3998cbf41/output-base",
            "cache_reuse_requested": True,
            "cache_policy": 2,
            "cache_key": "e445854abf597c0a8db904e3ad38a5dd26ba36aff33272028835b6d3998cbf41",
            "exit": 0,
            "workload_exit": 0,
            "descendants_empty": True,
            "cleanup": {
                "ownership": "unproved",
                "readback_attempts": 0,
                "state": "empty",
                "stop": "not-requested"
            },
            "controller_failure": None
        }

    def test_actual_i2_successful_build_receipt_is_accepted_without_rewriting_producer_fields(self):
        # Closed public projection of actual fb5f3568 BUILD receipt, SHA8585c7de3c189349918a933f5e936001e03581e527b1e3afb9064ad90e3d445a.
        # Paths here are public software outputs; no account/runtime/vault/profile selectors are copied.
        receipt = {
            "id": "fb5f3568-f7b2-4bfc-9118-b1846975074d",
            "artifact_epoch": "fb5f3568-f7b2-4bfc-9118-b1846975074d",
            "profile": "standard",
            "verb": "build",
            "targets": [
                "//delivery:default_instance_archive"
            ],
            "source_dirty": "false",
            "source_commit": "77686afbb4135042b0d89343269cf66e3065f723",
            "graph_sha256": "58b05968c40297da5a868590788099807dc1d344288513c185b8eba65e51c6f9",
            "output_base": "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/cache-v2-e445854abf597c0a8db904e3ad38a5dd26ba36aff33272028835b6d3998cbf41/output-base",
            "cache_reuse_requested": True,
            "cache_policy": 2,
            "cache_key": "e445854abf597c0a8db904e3ad38a5dd26ba36aff33272028835b6d3998cbf41",
            "exit": 0,
            "workload_exit": 0,
            "descendants_empty": True,
            "cleanup": {
                "state": "empty"
            },
            "controller_failure": None
        }
        qualification = self.qualification_for(receipt)
        qualification.update(sha256="8585c7de3c189349918a933f5e936001e03581e527b1e3afb9064ad90e3d445a",bytes=16710)
        actual_output = update.qualification_output(receipt,qualification)
        self.assertEqual(actual_output,Path(receipt["output_base"]))
        selected = selection()
        selected.update(archive_path=str(actual_output/update.ARCHIVE_RELATIVE),
            archive_sha256="929af8d4839bde414e139cede0bcb46c5bcdfee283ceddfeee46766f0872dfa0",
            archive_bytes=59609684,qualification=qualification)
        self.assertEqual(update.pins(selected,HOME),selected)

    def qualification_for(self,receipt):
        return {"path":"/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/"+receipt["id"]+"/receipt.json",
            "sha256":"a"*64,"bytes":1,"source_commit":receipt["source_commit"],"graph_sha256":receipt["graph_sha256"]}

    def test_producer_cached_and_uncached_shapes_and_explicit_clean_string(self):
        actual_test = self.actual_test_receipt()
        qualification = self.qualification_for(actual_test)
        with self.assertRaises(ValueError):
            update.qualification_output(actual_test,qualification)
        # Synthetic successful BUILD using the observed canonical producer cache/source fields.
        build = copy.deepcopy(actual_test)
        build.update(verb="build",targets=["//delivery:default_instance_archive"])
        self.assertEqual(update.qualification_output(build,qualification),Path(build["output_base"]))
        selected = selection()
        selected.update(archive_path=str(Path(build["output_base"])/update.ARCHIVE_RELATIVE),
            qualification=qualification)
        update.pins(selected,HOME)
        uncached = copy.deepcopy(build)
        uncached.update(cache_reuse_requested=False,cache_policy=None,cache_key=None,
            output_base=str(Path(qualification["path"]).parent/"output-base"))
        self.assertEqual(update.qualification_output(uncached,qualification),Path(uncached["output_base"]))
        for dirty in (False,True,None,0,1,"true","False","FALSE"," false ",""):
            changed = copy.deepcopy(build)
            changed["source_dirty"] = dirty
            with self.subTest(dirty=dirty),self.assertRaises(ValueError):
                update.qualification_output(changed,qualification)

    def test_producer_epoch_cache_key_pointer_and_workload_qualification_are_exact(self):
        build = self.actual_test_receipt()
        build.update(verb="build",targets=["//delivery:default_instance_archive"])
        qualification = self.qualification_for(build)
        cases = (("id",EPOCH),("artifact_epoch",EPOCH),("cache_reuse_requested",1),("cache_policy",2.0),
            ("cache_policy",True),("cache_key","../foreign"),("cache_key","b"*64),
            ("output_base",str(Path(qualification["path"]).parent/"output-base")),
            ("verb","test"),("profile","resident-enrollment"),("targets",["//delivery:resident_codex_enrollment"]),
            ("exit",125),("workload_exit",1),("descendants_empty",False),("source_commit","0"*40),
            ("graph_sha256","0"*64),("controller_failure",{}))
        for key,value in cases:
            changed = copy.deepcopy(build)
            changed[key] = value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                update.qualification_output(changed,qualification)
        uncached = copy.deepcopy(build)
        uncached.update(cache_reuse_requested=False,cache_policy=None,cache_key=None,
            output_base=str(Path(qualification["path"]).parent/"output-base"))
        for key,value in (("cache_policy",2),("cache_key","b"*64),("cache_reuse_requested",0)):
            changed = copy.deepcopy(uncached)
            changed[key] = value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                update.qualification_output(changed,qualification)

    def test_public_selection_refuses_credential_selectors_before_any_io(self):
        update.pins(selection(),HOME)
        cases = []
        for key in ("archive_path","previous_archive_path"):
            changed = selection()
            changed[key] = "/home/jess/.codex/auth.json"
            cases.append(changed)
        changed = selection()
        changed["qualification"]["path"] = "/home/jess/.codex/auth.json"
        cases.append(changed)
        changed = selection()
        changed["archive_bytes"] = True
        cases.append(changed)
        changed = selection()
        changed["archive_sha256"] = changed["previous_archive_sha256"]
        cases.append(changed)
        for changed in cases:
            with mock.patch.object(update.os,"open",side_effect=AssertionError("pre-IO refusal required")):
                with self.assertRaises((ValueError,KeyError)):
                    update.pins(changed,HOME)

    def test_effective_inactive_unit_requires_exact_exec_state_caps_and_no_dropins(self):
        selected = manifest()
        values = idle(selected)
        with mock.patch.object(resident,"resolve_owned_unit_fragment",return_value=Path(selected["service_path"])):
            self.assertEqual(update.inactive_installation(values,selected),Path(selected["service_path"]))
        changes = (("ActiveState","active"),("SubState","running"),("MainPID","11"),
            ("ControlGroup","/foreign"),("Slice","foreign.slice"),("DropInPaths","/foreign.conf"),("NeedDaemonReload","yes"),
            ("MemoryMax","268435457"),("TasksMax","33"),("CPUQuotaPerSecUSec","100001us"),
            ("ExecStart",values["ExecStart"].replace(selected["runtime_state"],"/another/state")),
            ("ExecStart",values["ExecStart"].replace("--state-dir","--force --state-dir")))
        for key,value in changes:
            changed = dict(values)
            changed[key] = value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                update.inactive_installation(changed,selected)

    def test_inactive_cgroup_checks_actual_descendant_population_without_signals(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            (root/"cgroup.procs").write_text("")
            (root/"cgroup.events").write_text("populated 0\nfrozen 0\n")
            original_path = update.Path
            def path(value):
                return root if str(value) == "/sys/fs/cgroup/user.slice" else original_path(value)
            # Exact derived cgroup is redirected to a synthetic filesystem fixture.
            expected = root/("user-"+str(os.getuid())+".slice")/("user@"+str(os.getuid())+".service")/"app.slice/ai.xoxd.omux.service"
            expected.mkdir(parents=True)
            for name in ("cgroup.procs","cgroup.events"):
                (expected/name).write_bytes((root/name).read_bytes())
            with mock.patch.object(update,"Path",side_effect=path):
                self.assertEqual(update.inactive_cgroup(time.monotonic_ns()+30*10**9),{"unit_cgroup_empty":True})
                (expected/"cgroup.events").write_text("populated 1\nfrozen 0\n")
                with self.assertRaises(ValueError):
                    update.inactive_cgroup(time.monotonic_ns()+30*10**9)
                (expected/"cgroup.events").write_text("populated 0\nfrozen 0\n")
                (expected/"cgroup.procs").write_text("123\n")
                with self.assertRaises(ValueError):
                    update.inactive_cgroup(time.monotonic_ns()+30*10**9)

    def runtime(self,root):
        root.chmod(0o700)
        state = root/"state"
        state.mkdir(mode=0o700)
        for name,data in (("daemon.lock",b""),("metadata.sqlite",b"synthetic encrypted state")):
            (state/name).write_bytes(data)
            (state/name).chmod(0o600)
        return state

    def test_existing_zero_lock_is_held_and_private_bytes_never_read(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            state = self.runtime(Path(temporary))
            with mock.patch.object(update.os,"read",side_effect=AssertionError("no private reads")), \
                    mock.patch.object(update.os,"pread",side_effect=AssertionError("no private reads")):
                fence = update.RuntimeFence(state,time.monotonic_ns()+30*10**9)
                fence.recheck()
            other = os.open(state/"daemon.lock",os.O_RDWR|os.O_NOFOLLOW)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
                fence.close()
                fcntl.flock(other,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:
                os.close(other)
            self.assertTrue((state/"daemon.lock").exists())
            self.assertEqual((state/"metadata.sqlite").read_bytes(),b"synthetic encrypted state")

    def test_runtime_named_held_mutation_and_same_content_replacement_refuse(self):
        for replacement in (False,True):
            with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
                state = self.runtime(Path(temporary))
                fence = update.RuntimeFence(state,time.monotonic_ns()+30*10**9)
                try:
                    target = state/"metadata.sqlite"
                    if replacement:
                        target.unlink()
                    target.write_bytes(b"synthetic encrypted state")
                    target.chmod(0o600)
                    with self.assertRaises(ValueError):
                        fence.recheck()
                finally:
                    fence.close()

    def test_runtime_symlink_and_missing_lock_refuse_without_creating_or_deleting(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            state = self.runtime(Path(temporary))
            (state/"daemon.lock").unlink()
            with self.assertRaises(FileNotFoundError):
                update.RuntimeFence(state,time.monotonic_ns()+30*10**9)
            self.assertFalse((state/"daemon.lock").exists())
            (state/"daemon.lock").write_bytes(b"")
            (state/"daemon.lock").chmod(0o600)
            (state/"link").symlink_to(state/"metadata.sqlite")
            with self.assertRaises(ValueError):
                update.RuntimeFence(state,time.monotonic_ns()+30*10**9)
            self.assertTrue((state/"link").is_symlink())

    def test_guard_transition_requires_success_and_empty_owned_cleanup(self):
        admission = resident.Admission.__new__(resident.Admission)
        admission.installation_update = mock.Mock()
        admission.recheck = mock.Mock(return_value={})
        for status,cleaned in ((1,True),(0,False),(True,True),(0,1)):
            with self.subTest(status=status,cleaned=cleaned),self.assertRaises(ValueError):
                admission.complete_owned_update(status,cleaned)
        admission.installation_update.completed.assert_not_called()
        admission.recheck.assert_not_called()
        admission.complete_owned_update(0,True)
        admission.installation_update.completed.assert_called_once_with()
        admission.recheck.assert_called_once_with()

    def test_runtime_is_readonly_and_only_installation_placement_is_writable(self):
        admission = resident.Admission.__new__(resident.Admission)
        admission.selected = manifest()
        admission.product_directories = [(Path(admission.selected[name]),None,None)
            for name in ("prefix","records","runtime_state")]
        admission.installation_update = mock.Mock()
        actual = admission.writable_binding().split()
        self.assertEqual(set(actual),{admission.selected[name]+":"+admission.selected[name] for name in ("prefix","records")})
        self.assertNotIn(admission.selected["runtime_state"]+":"+admission.selected["runtime_state"],actual)

if __name__ == "__main__":
    unittest.main()
