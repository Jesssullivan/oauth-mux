"""Provider-free resident admission and complementary reservation predicates."""
import copy
import errno
import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import guard_resident_enrollment_profile as resident
from execution_guard import resident_enrollment_command

HOME = Path("/home/jess")
def manifest():
    return {"schema_version":1,"ownership":"omux-installation","action":"install-and-enroll",
        "instance":"default",**{k:str(v) for k,v in resident.fixed_paths(HOME).items()},
        "native_context":{"application":"codex","provenance":"authorized-working-native-context",
            "codex_home":"/home/jess/.codex"},"permissions":{"connect_source":True,
            "activate_service":True,"restart_daemon":True}}

def limits():
    return ({"MemoryMax":"268435456","MemorySwapMax":"0","TasksMax":"32","CPUQuotaPerSecUSec":"100ms"},
        {"memory.max":"268435456","memory.swap.max":"0","pids.max":"32","cpu.max":"10000 100000"})

def systemctl_bind_readback(configured):
    """Pinned systemctl v260.1: nonrecursive has no suffix, recursive has rbind."""
    return " ".join(value.removesuffix(":norbind") if value.endswith(":norbind")
        else value if value.endswith(":rbind") else value+":rbind" for value in configured)

class ResidentModels(unittest.TestCase):
    def test_actual_socket_refusal_identifies_fixed_peer_role_preserves_order_and_early_cleanup(self):
        # Every directory/socket is synthetic and private. Route only the fixed
        # host peer selectors to these owned fixtures; never contact a host bus.
        for failed_role in ("bus","manager"):
            with self.subTest(role=failed_role),tempfile.TemporaryDirectory() as temporary:
                fixture=Path(temporary)
                namespace=fixture/"inputs"
                runtime=fixture/"runtime"
                namespace.mkdir(mode=0o700)
                runtime.mkdir(mode=0o700)
                (runtime/"systemd").mkdir(mode=0o700)
                (namespace/"input.json").write_bytes(b"{}")
                (namespace/"input.json").chmod(0o600)
                actual_runtime=Path("/run/user")/str(os.getuid())
                peer_paths={actual_runtime/"bus":runtime/"bus",
                    actual_runtime/"systemd/private":runtime/"systemd/private"}
                directory_paths={actual_runtime:runtime,actual_runtime/"systemd":runtime/"systemd"}
                allowed={namespace,namespace/"systemd",runtime,runtime/"systemd"}
                opened=[]
                contacted=[]
                original_witness=resident.socket_witness
                def fixture_directory(path,private=False):
                    selected=directory_paths.get(Path(path),Path(path))
                    self.assertIn(selected,allowed)
                    descriptor=os.open(selected,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
                    opened.append(descriptor)
                    info=os.fstat(descriptor)
                    self.assertEqual(info.st_uid,os.getuid())
                    self.assertEqual(stat.S_IMODE(info.st_mode),0o700)
                    return descriptor
                def fixture_peer(path):
                    self.assertIn(path,peer_paths)
                    contacted.append(path)
                    return original_witness(peer_paths[path])
                with resident.socket.socket(resident.socket.AF_UNIX,resident.socket.SOCK_STREAM) as bus, \
                        resident.socket.socket(resident.socket.AF_UNIX,resident.socket.SOCK_STREAM) as manager:
                    bus.bind(str(runtime/"bus"))
                    manager.bind(str(runtime/"systemd/private"))
                    (runtime/"bus").chmod(0o600)
                    (runtime/"systemd/private").chmod(0o600)
                    if failed_role != "bus":
                        bus.listen(2)
                    if failed_role != "manager":
                        manager.listen(2)
                    instance=resident.Admission.__new__(resident.Admission)
                    with patch.object(resident,"open_directory",side_effect=fixture_directory), \
                            patch.object(resident,"socket_witness",side_effect=fixture_peer):
                        with self.assertRaises(OSError) as caught:
                            instance.__init__(namespace/"input.json",HOME,10**18)
                        phase="session-bus-peer" if failed_role == "bus" else "session-manager-peer"
                        self.assertEqual(resident.diagnostic_projection(caught.exception),
                            {"phase":phase,"errno":"ECONNREFUSED"})
                        expected=[actual_runtime/"bus"]+([actual_runtime/"systemd/private"] if failed_role == "manager" else [])
                        self.assertEqual(contacted,expected)
                        self.assertEqual(list(namespace.iterdir()),[namespace/"input.json"])
                        self.assertEqual(instance.held,[])
                        self.assertEqual(instance.created_sockets,[])
                        for descriptor in opened:
                            with self.assertRaises(OSError) as closed:
                                os.fstat(descriptor)
                            self.assertEqual(closed.exception.errno,errno.EBADF)
                        self.assertTrue(stat.S_ISSOCK((runtime/"bus").stat(follow_symlinks=False).st_mode))
                        self.assertTrue(stat.S_ISSOCK((runtime/"systemd/private").stat(follow_symlinks=False).st_mode))
                        # Recheck uses the same helper and real refused socket;
                        # its existing outer decorator retains the refined tag.
                        failed_path=expected[-1]
                        recheck=resident.diagnostic_method(lambda self:self.session_peer_witness(failed_path,recheck=True))
                        with self.assertRaises(OSError) as caught_again:
                            recheck(instance)
                        self.assertEqual(resident.diagnostic_projection(caught_again.exception),
                            {"phase":phase+"-recheck","errno":"ECONNREFUSED"})

    def test_diagnostics_are_closed_and_never_render_underlying_messages_paths_or_errno_values(self):
        from execution_guard import rejection_diagnostic
        class Sensitive(OSError):
            def __str__(self):
                raise AssertionError("private exception rendering forbidden")
        class Failure:
            diagnostic_phase = "retained-lock"
            @resident.diagnostic_method
            def fail(self):
                raise Sensitive(errno.EACCES,"private credential text","/private/factor-or-source")
        with self.assertRaises(OSError) as caught:
            Failure().fail()
        self.assertEqual(resident.diagnostic_projection(caught.exception),{"phase":"retained-lock","errno":"EACCES"})
        self.assertEqual(rejection_diagnostic(caught.exception,"operatorinputs"),
            "execution containment rejected; stage=operatorinputs; exception=OSError; resident_phase=retained-lock; resident_errno=EACCES")
        self.assertEqual(resident.rejection(caught.exception),"resident-enrollment-admission-refused;phase=retained-lock;errno=EACCES")
        self.assertIsNone(resident.diagnostic_projection(Sensitive(errno.EACCES,"private")))
        arbitrary = resident.ResidentAdmissionOSError("private/path/value",123456789)
        self.assertEqual(resident.diagnostic_projection(arbitrary),{"phase":"unknown","errno":"other"})
        self.assertEqual(resident.diagnostic_projection(resident.ResidentAdmissionValueError("manifest-schema")),
            {"phase":"manifest-schema","errno":"none"})

    def test_actual_admission_namespace_open_failure_retains_errno_category_and_cleanup(self):
        with patch.object(resident,"open_directory",side_effect=OSError(errno.EACCES,"private","/private/input")), \
                patch.object(resident.Admission,"close") as cleanup:
            with self.assertRaises(OSError) as caught:
                resident.Admission("/private/input/input.json",HOME,10**18)
            cleanup.assert_called_once_with()
        self.assertEqual(resident.diagnostic_projection(caught.exception),{"phase":"namespace-directory","errno":"EACCES"})

    def test_actual_service_query_failure_is_closed_and_never_admits(self):
        admission = resident.Admission.__new__(resident.Admission)
        admission.deadline_ns = 30000000001
        admission.selected = {"action":"start-existing","ownership":"omux-installation"}
        with patch.object(resident.time,"monotonic_ns",return_value=1), \
                patch.object(resident.subprocess,"run",side_effect=OSError(errno.ENOTSOCK,"private transport")):
            with self.assertRaises(OSError) as caught:
                admission.service_observation("/declared/systemctl",starting=True)
        self.assertEqual(resident.diagnostic_projection(caught.exception),{"phase":"manager-query","errno":"ENOTSOCK"})

    def test_first_start_qualification_open_failure_is_preserved_through_outer_admission_tag(self):
        import guard_resident_owned_update as owned
        selected={"start":{}}
        selection={"qualification":{"path":"/public/receipt.json"}}
        with patch.object(owned,"start_pins",return_value=selection), \
                patch.object(owned,"PublicFile",side_effect=OSError(errno.ENOENT,"private input")):
            with self.assertRaises(OSError) as caught:
                owned.OwnedFirstStart(selected,HOME,10**18)
        self.assertEqual(resident.diagnostic_projection(caught.exception),{"phase":"qualification-open","errno":"ENOENT"})
        class Outer:
            diagnostic_phase="owned-first-start"
            @resident.diagnostic_method
            def fail(self):
                raise caught.exception
        with self.assertRaises(OSError) as nested:
            Outer().fail()
        self.assertIs(nested.exception,caught.exception)

    def test_inactive_cgroup_open_failure_is_not_reclassified_as_absent_or_admitted(self):
        import guard_resident_owned_update as owned
        from unittest.mock import Mock
        admission = resident.Admission.__new__(resident.Admission)
        admission.deadline_ns=30000000001
        admission.selected={"action":"start-existing","ownership":"omux-installation"}
        admission.owned_start=Mock()
        values={name:"" for name in owned.IDLE_PROPERTIES}
        values.update(LoadState="loaded",ActiveState="inactive",SubState="dead",MainPID="0")
        response=SimpleNamespace(returncode=0,stderr=b"",stdout="\n".join(key+"="+value for key,value in values.items()).encode())
        with patch.object(resident.time,"monotonic_ns",return_value=1), \
                patch.object(resident.subprocess,"run",return_value=response), \
                patch.object(owned,"inactive_installation",return_value=None), \
                patch.object(owned,"inactive_cgroup",side_effect=OSError(errno.EACCES,"private cgroup")):
            with self.assertRaises(OSError) as caught:
                admission.service_observation("/declared/systemctl",starting=True)
        self.assertEqual(resident.diagnostic_projection(caught.exception),{"phase":"inactive-cgroup","errno":"EACCES"})

    def test_fixed_sum_and_valid_bounds(self):
        self.assertEqual(resident.PROOF_MEMORY+resident.RESIDENT_MEMORY,4294967296)
        self.assertEqual(resident.PROOF_TASKS+resident.RESIDENT_TASKS,512)
        self.assertEqual(resident.PROOF_CPU_PERCENT+resident.RESIDENT_CPU_PERCENT,200)
        self.assertTrue(resident.check_resident_bounds(*limits()))
        p,c = limits()
        p.update(MemoryMax="134217728",TasksMax="16",CPUQuotaPerSecUSec="50ms")
        c.update({"memory.max":"134217728","pids.max":"16","cpu.max":"5000 100000"})
        self.assertTrue(resident.check_resident_bounds(p,c))

    def test_unlimited_mismatched_expanded_resident_limits_refuse(self):
        for key,value in (("MemoryMax","max"),("MemoryMax","268435457"),("MemorySwapMax","1"),
                ("TasksMax","33"),("CPUQuotaPerSecUSec","101ms")):
            p,c = limits()
            p[key] = value
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                resident.check_resident_bounds(p,c)
        for key,value in (("cpu.max","max 100000"),("cpu.max","10001 100000"),
                ("pids.max","max"),("memory.max","268435455")):
            p,c = limits()
            c[key] = value
            with self.subTest(key=key),self.assertRaises(ValueError):
                resident.check_resident_bounds(p,c)

    def test_exact_action_and_unrelated_or_delegated_work_refuse(self):
        resident.finite(["run",resident.LABEL],"system","/private/input.json",False)
        for args,manager,reuse,other in ((["run","//:other"],"system",False,()),
                (["test",resident.LABEL],"system",False,()),
                (["run",resident.LABEL,"//:other"],"system",False,()),
                (["run",resident.LABEL],"user",False,()),
                (["run",resident.LABEL],"system",True,()),
                (["run",resident.LABEL],"system",False,("foreign",))):
            with self.assertRaises(ValueError):
                resident.finite(args,manager,"/private/input.json",reuse,other)

    def test_manifest_cannot_authorize_arbitrary_host_writes(self):
        resident.manifest_schema(manifest(),HOME)
        for key in ("prefix","records","runtime_state","service_path"):
            value = manifest()
            value[key] = "/home/jess/other-user-work"
            with self.subTest(key=key),self.assertRaises(ValueError):
                resident.manifest_schema(value,HOME)
        value = manifest()
        value["native_context"]["codex_home"] = value["runtime_state"]
        with self.assertRaises(ValueError):
            resident.manifest_schema(value,HOME)

    def test_home_manager_cannot_install_activate_or_select_mutable_package(self):
        for prefix,action,activate in (("/home/jess/mutable","enroll-existing",False),
                ("/nix/store/"+"a"*32+"-omux","install-and-enroll",False),
                ("/nix/store/"+"a"*32+"-omux","enroll-existing",True)):
            value = manifest()
            value.update(ownership="home-manager",prefix=prefix,action=action,
                service_path=str(HOME/".config/systemd/user/ai.xoxd.omux.service"))
            value["permissions"]["activate_service"] = activate
            with self.assertRaises(ValueError):
                resident.manifest_schema(value,HOME)

    def test_private_schema_duplicate_and_secret_field_refuse(self):
        with self.assertRaises(ValueError):
            json.loads('{"action":"one","action":"two"}',object_pairs_hook=resident.unique)
        value = manifest()
        value["native_context"]["access_token"] = "unneeded"
        with self.assertRaises(ValueError):
            resident.manifest_schema(value,HOME)

    def test_private_projection_and_failure_never_stringify_inputs(self):
        actual = {"BindReadOnlyPaths":"/private/account/input.json:/omux-resident-inputs",
            "BindPaths":"/private/owned/state:/private/owned/state"}
        redacted = resident.projection(actual)
        self.assertNotIn("/private/",str(redacted))
        self.assertIn("/private/",actual["BindPaths"])
        class Sensitive(ValueError):
            def __str__(self):
                raise AssertionError("exception text must remain private")
        self.assertEqual(resident.rejection(Sensitive()),"resident-enrollment-admission-refused")

    def test_exact_namespace_binds_deny_extra_duplicates_writable_injection(self):
        admission = resident.Admission.__new__(resident.Admission)
        admission.root = Path("/private/input")
        admission.selected = manifest()
        admission.sources = {admission.root/"bus":Path("/run/user/1000/bus"),
            admission.root/"systemd/private":Path("/run/user/1000/systemd/private")}
        admission.product_directories = [(Path("/private/product"),None,None)]
        run = Path("/private/run")
        actual = {"BindReadOnlyPaths":systemctl_bind_readback(admission.bindings()),
            "BindPaths":systemctl_bind_readback(admission.writable_binding().split()+[str(run)+":"+str(run)])}
        admission.verify_bindings(actual,run)
        self.assertIn("/run/user/1000/bus:/omux-resident-inputs/bus",actual["BindReadOnlyPaths"].split())
        self.assertIn("/run/user/1000/systemd/private:/omux-resident-inputs/systemd/private",actual["BindReadOnlyPaths"].split())
        self.assertNotIn(":norbind",actual["BindReadOnlyPaths"])
        self.assertEqual(sum(value.endswith(":norbind") for value in admission.bindings()),2)
        for role in ("BindReadOnlyPaths","BindPaths"):
            for token in actual[role].split():
                replacement = token.removesuffix(":rbind") if token.endswith(":rbind") else token+":rbind"
                bad = {**actual,role:" ".join(replacement if value == token else value for value in actual[role].split())}
                with self.subTest(role=role,token=token),self.assertRaises(ValueError):
                    admission.verify_bindings(bad,run)
        for role in ("BindReadOnlyPaths","BindPaths"):
            bad = dict(actual)
            bad[role] += " /foreign:/foreign:rbind"
            with self.assertRaises(ValueError):
                admission.verify_bindings(bad,run)
        bad = dict(actual)
        bad["BindReadOnlyPaths"] += " "+actual["BindReadOnlyPaths"].split()[0]
        with self.assertRaises(ValueError):
            admission.verify_bindings(bad,run)

    def test_declared_run_builds_offline_and_carries_only_fixed_private_environment(self):
        admission = SimpleNamespace(manifest="/private/input.json",environment=lambda:{
            resident.VARIABLE:resident.DESTINATION+"/input.json",
            resident.DEADLINE_VARIABLE:"123",
            "DBUS_SESSION_BUS_ADDRESS":"unix:path="+resident.DESTINATION+"/bus",
            "XDG_RUNTIME_DIR":resident.DESTINATION})
        command = resident_enrollment_command("/store/bazel",Path("/private/run"),["run",resident.LABEL],admission)
        self.assertIn("run",command)
        self.assertIn("--jobs=2",command)
        self.assertIn("--sandbox_default_allow_network=false",command)
        self.assertIn("--spawn_strategy=linux-sandbox",command)
        self.assertIn("--run_env="+resident.VARIABLE+"="+resident.DESTINATION+"/input.json",command)
        self.assertNotIn("/private/input.json",str(command))


    def test_resident_repository_inputs_accept_only_exact_complete_public_pair(self):
        self.assertEqual(resident.repository_inputs(None,None),[])
        expected = [str(resident.REPOSITORY_CACHE)+":"+str(resident.REPOSITORY_CACHE)]
        self.assertEqual(resident.repository_inputs(resident.REPOSITORY_CACHE,resident.NIXPKGS_SOURCE),expected)
        for cache,source in ((resident.REPOSITORY_CACHE,None),(None,resident.NIXPKGS_SOURCE),
                (Path("/foreign/cache"),resident.NIXPKGS_SOURCE),
                (resident.REPOSITORY_CACHE,Path("/nix/store/"+"a"*32+"-source")),
                (str(resident.REPOSITORY_CACHE),resident.NIXPKGS_SOURCE)):
            with self.subTest(cache=cache,source=source),self.assertRaises(ValueError):
                resident.repository_inputs(cache,source)

    def test_resident_commands_use_exact_repository_inputs_with_fresh_output_and_offline_limits(self):
        import guard_resident_vault_profile as vault
        admission = SimpleNamespace(manifest="/private/input.json",environment=lambda:{resident.DEADLINE_VARIABLE:"123"})
        for label in (resident.LABEL,vault.LABEL,vault.UNLOCK_LABEL):
            command = resident_enrollment_command("/store/bazel",Path("/private/run"),["run",label],admission,
                repository_cache=resident.REPOSITORY_CACHE,nixpkgs_source=resident.NIXPKGS_SOURCE)
            for flag in ("--repository_cache="+str(resident.REPOSITORY_CACHE),
                    "--repo_env=OMUX_NIXPKGS_EVALUATION_SOURCE="+str(resident.NIXPKGS_SOURCE),
                    "--repository_disable_download","--repo_contents_cache=","--output_base=/private/run/output-base",
                    "--jobs=2","--host_jvm_args=-Xmx1536m","--host_jvm_args=-XX:ActiveProcessorCount=2",
                    "--remote_executor=","--remote_cache=","--disk_cache=","--lockfile_mode=error",
                    "--sandbox_default_allow_network=false","--spawn_strategy=linux-sandbox"):
                with self.subTest(label=label,flag=flag):
                    self.assertIn(flag,command)
                    self.assertEqual(command.count(flag),1)
            self.assertEqual(command[-1],label)
            self.assertNotIn("cache-v2-",str(command))
        with self.assertRaises(ValueError):
            resident_enrollment_command("/store/bazel",Path("/private/run"),["run","//:other"],admission,
                repository_cache=resident.REPOSITORY_CACHE,nixpkgs_source=resident.NIXPKGS_SOURCE)

    def test_repository_directory_bind_is_readonly_exact_recursive_for_both_resident_admissions(self):
        import guard_resident_vault_profile as vault
        for admission_class in (resident.Admission,vault.Admission):
            admission = admission_class.__new__(admission_class)
            admission.root = Path("/private/input")
            admission.sources = {}
            admission.selected = manifest()
            admission.product_directories = []
            admission.offline_repository_bindings = resident.repository_inputs(resident.REPOSITORY_CACHE,resident.NIXPKGS_SOURCE)
            run = Path("/private/run")
            actual = {"BindReadOnlyPaths":systemctl_bind_readback(admission.bindings()),
                "BindPaths":str(run)+":"+str(run)+":rbind"}
            admission.verify_bindings(actual,run)
            cache = str(resident.REPOSITORY_CACHE)+":"+str(resident.REPOSITORY_CACHE)
            self.assertIn(cache+":rbind",actual["BindReadOnlyPaths"].split())
            for changed in (cache,cache+":norbind","/foreign:/foreign:rbind"):
                bad = {**actual,"BindReadOnlyPaths":actual["BindReadOnlyPaths"].replace(cache+":rbind",changed)}
                with self.subTest(admission_class=admission_class,changed=changed),self.assertRaises(ValueError):
                    admission.verify_bindings(bad,run)
            for role in ("BindReadOnlyPaths","BindPaths"):
                bad = dict(actual)
                bad[role] += " "+cache+":rbind"
                with self.subTest(admission_class=admission_class,role=role),self.assertRaises(ValueError):
                    admission.verify_bindings(bad,run)

    def test_service_probe_accepts_existing_owned_metadata_and_refuses_foreign_owner(self):
        env = {"DBUS_SESSION_BUS_ADDRESS":"unix:path="+resident.DESTINATION+"/bus"}
        value = {"schema_version":1,"broker":{"pid":2,"uid":os.getuid()},
            "manager":{"owner":":1.2","pid":3,"uid":os.getuid()},
            "secret_service":{"owner":":1.3","pid":4,"uid":os.getuid()}}
        def answer():
            return SimpleNamespace(returncode=0,stderr=b"",stdout=json.dumps(value).encode())
        with patch.object(resident.time,"monotonic_ns",return_value=1), \
                patch.object(resident,"start_ticks",return_value=100), \
                patch.object(resident.subprocess,"run",side_effect=lambda *a,**k:answer()) as invoke:
            observed = resident.observe_existing_session_services(env,10000000001,Path("/declared/probe"))
            self.assertEqual(observed["manager"]["start_ticks"],100)
            self.assertEqual(invoke.call_args.args[0],["/declared/probe"])
            self.assertEqual(invoke.call_args.kwargs["env"][resident.DEADLINE_VARIABLE],"10000000001")
            self.assertNotIn(resident.DEADLINE_VARIABLE,env)
            value["secret_service"]["uid"] = os.getuid()+1
            with self.assertRaises(ValueError):
                resident.observe_existing_session_services(env,10000000001,Path("/declared/probe"))
        with self.assertRaises(ValueError):
            resident.observe_existing_session_services({"DBUS_SESSION_BUS_ADDRESS":"unix:path=/foreign"},10000000001,"probe")

class ResidentControlTransportModels(unittest.TestCase):
    def test_state_hash_selects_same_daemon_and_client_runtime_child(self):
        state = "/home/owned/.local/state/omux"
        expected = "omux-" + hashlib.sha256(state.encode()).hexdigest()[:32]
        self.assertEqual(resident.runtime_child(state), expected)
        self.assertEqual(resident.runtime_binding(state, 1000),
                         "/run/user/1000/" + expected + ":/omux-resident-inputs/" + expected)
        self.assertNotEqual(resident.runtime_child(state), resident.runtime_child(state + "-dev"))
        for bad in ("relative", "/state//omux", "/state/../omux", "/state/omux/"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                resident.runtime_child(bad)

    def test_control_placeholder_cleanup_retains_real_runtime_and_replacements(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root/"actual-runtime"
            source.mkdir(mode=0o700)
            placeholder = root/"namespace-child"
            placeholder.mkdir(mode=0o700)
            admission = resident.Admission.__new__(resident.Admission)
            admission.held = []
            admission.created_sockets = []
            admission.created_manager = False
            admission.created_control = (placeholder,resident.stable(placeholder.stat(follow_symlinks=False)))
            admission.close()
            self.assertTrue(source.is_dir())
            self.assertFalse(placeholder.exists())
            placeholder.mkdir(mode=0o700)
            admission.created_control = (placeholder,resident.stable(placeholder.stat(follow_symlinks=False)))
            placeholder.rename(root/"original-placeholder")
            placeholder.mkdir(mode=0o700)
            admission.close()
            self.assertTrue(placeholder.is_dir())
            self.assertTrue(source.is_dir())

class ResidentLeafMountModels(unittest.TestCase):
    def test_empty_regular_mountpoint_is_held_private_and_exclusive(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)/"bus"
            placeholder = resident.regular_mountpoint(path)
            try:
                witness = resident.regular_mountpoint_witness(path,placeholder.fileno())
                info = os.fstat(placeholder.fileno())
                self.assertTrue(stat.S_ISREG(info.st_mode))
                self.assertEqual(stat.S_IMODE(info.st_mode),0o600)
                self.assertEqual(info.st_size,0)
                self.assertEqual(info.st_nlink,1)
                self.assertEqual(witness,resident.stable(info))
                with self.assertRaises(FileExistsError):
                    resident.regular_mountpoint(path)
            finally:
                placeholder.close()

    def test_regular_mountpoint_rejects_replacement_symlink_hardlink_data_and_socket(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for change in ("replacement","symlink","hardlink","data","socket"):
                path = root/change
                placeholder = resident.regular_mountpoint(path)
                try:
                    if change == "replacement":
                        path.rename(root/"original")
                        path.touch(mode=0o600)
                    elif change == "symlink":
                        path.rename(root/"symlink-original")
                        path.symlink_to(root/"symlink-original")
                    elif change == "hardlink":
                        os.link(path,root/"link")
                    elif change == "data":
                        path.write_bytes(b"unexpected metadata")
                    else:
                        path.unlink()
                        fake = resident.socket.socket(resident.socket.AF_UNIX,resident.socket.SOCK_STREAM)
                        try:
                            fake.bind(str(path))
                        finally:
                            fake.close()
                    with self.subTest(change=change),self.assertRaises(ValueError):
                        resident.regular_mountpoint_witness(path,placeholder.fileno())
                finally:
                    placeholder.close()

    def test_socket_leaf_configuration_and_pinned_readback_have_distinct_exact_modes(self):
        leaf = "/run/user/1000/bus:/omux-resident-inputs/bus"
        root = "/private/input:/omux-resident-inputs"
        self.assertEqual(resident.normalize_binds(root+" "+leaf+":norbind",[leaf]),[root,leaf])
        self.assertEqual(resident.normalize_binds(root+":rbind "+leaf+":norbind",[leaf]),[root,leaf])
        self.assertEqual(resident.normalize_binds(root+":rbind "+leaf,[leaf],readback=True),[root,leaf])
        for readback,actual in ((False,leaf),(False,leaf+":rbind"),(False,root+":norbind"),
                (True,leaf+":rbind"),(True,leaf+":norbind"),(True,root),(True,root+":norbind"),
                (True,leaf+":unknown"),(True,leaf+":norbind:rbind")):
            with self.subTest(readback=readback,actual=actual),self.assertRaises(ValueError):
                resident.normalize_binds(actual,[leaf],readback=readback)

    def test_leaf_cleanup_closes_only_owned_mountpoint_and_retains_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root/"bus"
            placeholder = resident.regular_mountpoint(path)
            witness = resident.regular_mountpoint_witness(path,placeholder.fileno())
            admission = resident.Admission.__new__(resident.Admission)
            admission.held = []
            admission.created_manager = False
            admission.created_sockets = [(placeholder,path,witness)]
            path.rename(root/"held-original")
            path.touch(mode=0o600)
            admission.close()
            self.assertTrue(placeholder.closed)
            self.assertTrue(path.exists())
            self.assertTrue((root/"held-original").exists())

class MissingUnitModels(unittest.TestCase):
    def admission(self,action="install-and-enroll",ownership="omux-installation"):
        admission = resident.Admission.__new__(resident.Admission)
        admission.deadline_ns = 30000000001
        admission.selected = {"action":action,"ownership":ownership}
        return admission

    def result(self,code=4,**changes):
        values = {"LoadState":"not-found","ActiveState":"inactive","SubState":"dead","MainPID":"0",
            "FragmentPath":"","ControlGroup":"","MemoryMax":"infinity","MemorySwapMax":"infinity",
            "TasksMax":"infinity","CPUQuotaPerSecUSec":"infinity"}
        values.update(changes)
        return SimpleNamespace(returncode=code,stderr=b"",
            stdout="".join(k+"="+v+"\n" for k,v in values.items()).encode("ascii"))

    def test_new_owned_absent_unit_accepts_success_or_not_found_status(self):
        for code in (0,4):
            with self.subTest(code=code),patch.object(resident.time,"monotonic_ns",return_value=1), \
                    patch.object(resident.subprocess,"run",return_value=self.result(code)) as invoke:
                self.assertEqual(self.admission().service_observation("/declared/systemctl",starting=True),
                    {"active":False,"new_owned_service_admitted":True})
                self.assertEqual(invoke.call_args.args[0][-1],"ai.xoxd.omux.service")
                self.assertLessEqual(invoke.call_args.kwargs["timeout"],15)

    def test_not_found_status_cannot_admit_existing_foreign_or_other_error(self):
        cases = ((self.admission(),False,4),
            (self.admission("enroll-existing"),True,4),
            (self.admission(ownership="home-manager"),True,4),
            (self.admission(),True,1),(self.admission(),True,5))
        for admission,starting,code in cases:
            with self.subTest(starting=starting,code=code), \
                    patch.object(resident.time,"monotonic_ns",return_value=1), \
                    patch.object(resident.subprocess,"run",return_value=self.result(code)):
                with self.assertRaises(ValueError):
                    admission.service_observation("/declared/systemctl",starting=starting)

    def test_absent_unit_requires_zero_pid_empty_authority_and_dead_inactive_state(self):
        for key,value in (("LoadState","loaded"),("ActiveState","active"),("SubState","running"),
                ("MainPID","2"),("MainPID",""),("MainPID","00"),("FragmentPath","/foreign/unit"),
                ("ControlGroup","/foreign/cgroup")):
            for code in (0,4):
                with self.subTest(key=key,code=code), \
                        patch.object(resident.time,"monotonic_ns",return_value=1), \
                        patch.object(resident.subprocess,"run",return_value=self.result(code,**{key:value})):
                    with self.assertRaises(ValueError):
                        self.admission().service_observation("/declared/systemctl",starting=True)

    def test_absent_reply_rejects_duplicate_missing_malformed_or_stderr_properties(self):
        result = self.result()
        replies = (result.stdout+b"MainPID=0\n",result.stdout.replace(b"MainPID=0\n",b""),
            result.stdout+b"malformed\n")
        for stdout in replies:
            with patch.object(resident.time,"monotonic_ns",return_value=1), \
                    patch.object(resident.subprocess,"run",return_value=SimpleNamespace(
                        returncode=4,stderr=b"",stdout=stdout)):
                with self.assertRaises(ValueError):
                    self.admission().service_observation("/declared/systemctl",starting=True)
        with patch.object(resident.time,"monotonic_ns",return_value=1), \
                patch.object(resident.subprocess,"run",return_value=SimpleNamespace(
                    returncode=4,stderr=b"generic diagnostic",stdout=result.stdout)):
            with self.assertRaises(ValueError):
                self.admission().service_observation("/declared/systemctl",starting=True)

class PlatformActivationModels(unittest.TestCase):
    def observed(self,secret=True):
        def row(pid,owner=None):
            return {"pid":pid,"uid":os.getuid(),"start_ticks":100,**({"owner":owner} if owner else {})}
        return {"schema_version":1,"broker":row(2),"manager":row(3,":1.2"),
            "secret_service":row(4,":1.3") if secret else None}

    def test_absence_to_owned_allowed_only_explicit_new_first_install(self):
        before,after = self.observed(False),self.observed(True)
        self.assertTrue(resident.same_session_transport(before,after))
        with self.assertRaises(ValueError):
            resident.freeze_session_owners(before,after)
        self.assertEqual(resident.freeze_session_owners(before,after,allow_platform_activation=True),after)
        self.assertEqual(resident.freeze_session_owners(after,copy.deepcopy(after)),after)

    def test_foreign_lost_changed_owner_or_transport_never_freezes(self):
        before = self.observed(True)
        changed = self.observed(True)
        changed["secret_service"]["owner"] = ":1.4"
        missing = self.observed(False)
        foreign = self.observed(True)
        foreign["secret_service"]["uid"] += 1
        transport = self.observed(True)
        transport["manager"]["start_ticks"] += 1
        for after in (changed,missing,foreign,transport):
            with self.subTest(after=after),self.assertRaises(ValueError):
                resident.freeze_session_owners(before,after,allow_platform_activation=True)
        with self.assertRaises(ValueError):
            resident.freeze_session_owners(self.observed(False),missing,allow_platform_activation=True)

    def test_probe_optional_absence_is_closed_boolean_option_and_default_is_strict(self):
        value = {"schema_version":1,"broker":{"pid":2,"uid":os.getuid()},
            "manager":{"owner":":1.2","pid":3,"uid":os.getuid()},"secret_service":None}
        env = {"DBUS_SESSION_BUS_ADDRESS":"unix:path="+resident.DESTINATION+"/bus"}
        result = SimpleNamespace(returncode=0,stderr=b"",stdout=json.dumps(value).encode())
        with patch.object(resident.time,"monotonic_ns",return_value=1), \
                patch.object(resident,"start_ticks",return_value=100), \
                patch.object(resident.subprocess,"run",return_value=result) as invoke:
            with self.assertRaises(ValueError):
                resident.observe_existing_session_services(env,10000000001,"probe")
            after = resident.observe_existing_session_services(env,10000000001,"probe",
                allow_missing_secret_service=True)
            self.assertIsNone(after["secret_service"])
            self.assertEqual(invoke.call_args.args[0],["probe","--allow-missing-secret-service-before-first-start"])
            self.assertEqual(invoke.call_args.kwargs["env"][resident.DEADLINE_VARIABLE],"10000000001")
            with self.assertRaises(ValueError):
                resident.observe_existing_session_services(env,10000000001,"probe",allow_missing_secret_service=1)

    def test_optional_phase_never_tolerates_missing_broker_or_manager(self):
        env = {"DBUS_SESSION_BUS_ADDRESS":"unix:path="+resident.DESTINATION+"/bus"}
        for name in ("broker","manager"):
            value = {"schema_version":1,"broker":{"pid":2,"uid":os.getuid()},
                "manager":{"owner":":1.2","pid":3,"uid":os.getuid()},"secret_service":None}
            value[name] = None
            result = SimpleNamespace(returncode=0,stderr=b"",stdout=json.dumps(value).encode())
            with patch.object(resident.time,"monotonic_ns",return_value=1), \
                    patch.object(resident,"start_ticks",return_value=100), \
                    patch.object(resident.subprocess,"run",return_value=result):
                with self.assertRaises(ValueError):
                    resident.observe_existing_session_services(env,10000000001,"probe",allow_missing_secret_service=True)



class OwnedRecoveryModels(unittest.TestCase):
    def prepare(self,home):
        selected = manifest()
        selected.update(action="activate-existing-and-enroll",
            **{key:str(value) for key,value in resident.fixed_paths(home).items()})
        selected["native_context"]["codex_home"] = str(home/".codex")
        unit = Path(selected["service_path"])
        records = Path(selected["records"])
        unit.parent.mkdir(parents=True,mode=0o700)
        records.mkdir(parents=True,mode=0o700)
        raw = b"[Service]\nExecStart=/public/declared/omuxd\nMemoryMax=268435456\n"
        unit.write_bytes(raw)
        unit.chmod(0o600)
        record = {"schemaVersion":1,"prefix":selected["prefix"],"product":"omux",
            "userService":str(unit),"serviceActivated":False,"artifact":{"archiveSha256":"a"*64},
            "files":[{"path":str(unit),"mode":0o600,"sha256":hashlib.sha256(raw).hexdigest()}]}
        record_path = records/"install.json"
        record_path.write_text(json.dumps(record))
        record_path.chmod(0o600)
        alias = home/".config/systemd/user"/unit.name
        alias.parent.mkdir(parents=True,mode=0o700)
        alias.symlink_to(unit)
        state = Path(selected["runtime_state"])
        state.mkdir(mode=0o700)
        control = home/"control-placeholder"
        control.mkdir(mode=0o700)
        return selected,unit,alias,record_path,state,control

    def test_closed_recovery_action_permissions_and_home_manager_refusal(self):
        value = manifest()
        value["action"] = "activate-existing-and-enroll"
        resident.manifest_schema(value,HOME)
        value["permissions"]["activate_service"] = False
        with self.assertRaises(ValueError):
            resident.manifest_schema(value,HOME)
        value["permissions"]["activate_service"] = True
        value.update(ownership="home-manager",prefix="/nix/store/"+"a"*32+"-omux",
            service_path=str(HOME/".config/systemd/user/ai.xoxd.omux.service"))
        with self.assertRaises(ValueError):
            resident.manifest_schema(value,HOME)

    def test_exact_owned_alias_and_recorded_unit_digest_are_held(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            selected,unit,alias,record_path,_,_ = self.prepare(Path(temporary))
            custody = resident.OwnedUnitCustody(selected)
            try:
                self.assertEqual(custody.verify_fragment(unit),unit)
                self.assertEqual(custody.verify_fragment(alias),unit)
                custody.recheck()
                unit.write_bytes(b"modified owned unit")
                with self.assertRaises(ValueError):
                    custody.recheck()
            finally:
                custody.close()

    def test_alias_foreign_relative_hardlink_and_changed_parent_are_refused(self):
        for change in ("foreign","relative","regular","hardlink","parent"):
            with self.subTest(change=change),tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
                selected,unit,alias,_,_,_ = self.prepare(Path(temporary))
                if change == "parent":
                    alias.parent.chmod(0o777)
                else:
                    alias.unlink()
                    if change == "foreign":
                        alias.symlink_to(unit.parent/"foreign.service")
                    elif change == "relative":
                        alias.symlink_to(os.path.relpath(unit,alias.parent))
                    elif change == "regular":
                        alias.write_text("foreign unit")
                    else:
                        os.link(unit,alias)
                with self.assertRaises(ValueError):
                    resident.resolve_owned_unit_fragment(alias,unit)

    def test_record_digest_symlink_replacement_and_unmanaged_rows_refused(self):
        for change in ("digest","record-symlink","record-replace","unit-hardlink","extra-native-path","alias-replace"):
            with self.subTest(change=change),tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
                selected,unit,alias,record_path,_,_ = self.prepare(Path(temporary))
                if change in ("digest","extra-native-path"):
                    record = json.loads(record_path.read_text())
                    if change == "digest":
                        record["files"][0]["sha256"] = "b"*64
                    else:
                        record["files"].append({"path":str(Path(temporary)/".codex/auth.json"),
                            "mode":0o600,"sha256":"c"*64})
                    record_path.write_text(json.dumps(record))
                    with self.assertRaises(ValueError):
                        resident.OwnedUnitCustody(selected)
                elif change == "record-symlink":
                    original = record_path.with_name("original.json")
                    record_path.rename(original)
                    record_path.symlink_to(original)
                    with self.assertRaises((ValueError,OSError)):
                        resident.OwnedUnitCustody(selected)
                elif change == "unit-hardlink":
                    os.link(unit,unit.with_name("second-unit"))
                    with self.assertRaises(ValueError):
                        resident.OwnedUnitCustody(selected)
                elif change == "alias-replace":
                    custody = resident.OwnedUnitCustody(selected)
                    try:
                        custody.verify_fragment(alias)
                        alias.rename(alias.with_name("old-alias"))
                        alias.symlink_to(unit)
                        with self.assertRaises(ValueError):
                            custody.recheck()
                    finally:
                        custody.close()
                else:
                    custody = resident.OwnedUnitCustody(selected)
                    try:
                        record_path.rename(record_path.with_name("old-record"))
                        record_path.write_bytes(b"{}")
                        record_path.chmod(0o600)
                        with self.assertRaises(ValueError):
                            custody.recheck()
                    finally:
                        custody.close()

    def test_starting_recovery_qualifies_actual_loaded_inactive_metadata_and_empty_state(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            selected,unit,alias,_,state,control = self.prepare(Path(temporary))
            admission = resident.Admission.__new__(resident.Admission)
            admission.selected = selected
            admission.deadline_ns = 30000000001
            admission.owned_unit = resident.OwnedUnitCustody(selected)
            admission.recovery_empty = [resident.open_directory(state,True),resident.open_directory(control,True)]
            values = {"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","MainPID":"0",
                "FragmentPath":str(alias),"ControlGroup":"","MemoryMax":"268435456",
                "MemorySwapMax":"0","TasksMax":"32","CPUQuotaPerSecUSec":"100ms","UnitFileState":"enabled"}
            def result(properties,code=0):
                return SimpleNamespace(returncode=code,stderr=b"",
                    stdout="".join(k+"="+v+"\n" for k,v in properties.items()).encode("ascii"))
            try:
                with patch.object(resident.time,"monotonic_ns",return_value=1), \
                        patch.object(resident.subprocess,"run",return_value=result(values)):
                    self.assertEqual(admission.service_observation("/declared/systemctl",starting=True),
                        {"active":False,"owned_partial_install_admitted":True,"bounded":True})
                for key,value in (("LoadState","not-found"),("ActiveState","active"),("SubState","running"),
                        ("MainPID","2"),("MainPID","00"),("ControlGroup","/foreign"),("UnitFileState","disabled"),("UnitFileState","static"),
                        ("MemoryMax","268435457"),("MemoryMax","268435455"),("MemorySwapMax","1"),
                        ("TasksMax","33"),("CPUQuotaPerSecUSec","101ms"),("FragmentPath",str(unit.parent/"foreign.service"))):
                    changed = dict(values)
                    changed[key] = value
                    with self.subTest(key=key),patch.object(resident.time,"monotonic_ns",return_value=1), \
                            patch.object(resident.subprocess,"run",return_value=result(changed)):
                        with self.assertRaises(ValueError):
                            admission.service_observation("/declared/systemctl",starting=True)
                with patch.object(resident.time,"monotonic_ns",return_value=1), \
                        patch.object(resident.subprocess,"run",return_value=result(values,4)):
                    with self.assertRaises(ValueError):
                        admission.service_observation("/declared/systemctl",starting=True)
                (state/"state.db").write_bytes(b"existing encrypted database metadata")
                with patch.object(resident.time,"monotonic_ns",return_value=1), \
                        patch.object(resident.subprocess,"run",return_value=result(values)):
                    with self.assertRaises(ValueError):
                        admission.service_observation("/declared/systemctl",starting=True)
            finally:
                for descriptor in admission.recovery_empty:
                    os.close(descriptor)
                admission.owned_unit.close()

class InactiveObservationModels(unittest.TestCase):
    def selected(self):
        value=manifest()
        value.update(action="observe-inactive",native_context=None,
            permissions={"connect_source":False,"activate_service":False,"restart_daemon":False},
            start={"archive_path":"/synthetic/public/archive"})
        return value

    def test_exact_existing_lifecycle_only_no_caller_authority_or_enrollment(self):
        import guard_resident_owned_update as owned
        selected=self.selected()
        with patch.object(owned,"start_pins",return_value=selected["start"]):
            self.assertIs(resident.manifest_schema(selected,HOME),selected)
            resident.carrier_purpose(resident.LIFECYCLE_LABEL,"observe-inactive")
            for label in (resident.LABEL,resident.EXISTING_ENROLLMENT_LABEL,"//delivery:arbitrary"):
                with self.assertRaises(ValueError):
                    resident.carrier_purpose(label,"observe-inactive")
            for key in selected["permissions"]:
                changed=copy.deepcopy(selected)
                changed["permissions"][key]=True
                with self.assertRaises(ValueError):
                    resident.manifest_schema(changed,HOME)
            changed=copy.deepcopy(selected)
            changed["native_context"]=manifest()["native_context"]
            with self.assertRaises(ValueError):
                resident.manifest_schema(changed,HOME)

    def test_normal_encrypted_state_is_metadata_only_unlocked_and_replacement_refuses(self):
        import guard_resident_owned_update as owned
        from unittest.mock import Mock
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            state=Path(temporary)
            state.chmod(0o700)
            for name,raw in (("daemon.lock",b""),("state.sqlite",b"synthetic opaque ciphertext"),
                             ("state.sqlite.authority",b"synthetic opaque authority")):
                (state/name).write_bytes(raw)
                (state/name).chmod(0o600)
            selected={**self.selected(),"runtime_state":str(state)}
            software=Mock(files=[])
            actual_open=os.open
            def metadata_only(path,flags,*args,**kwargs):
                if str(path) in ("daemon.lock","state.sqlite","state.sqlite.authority"):
                    self.assertTrue(flags & os.O_PATH)
                return actual_open(path,flags,*args,**kwargs)
            with patch.object(owned,"QualifiedExistingEnrollment",return_value=software), \
                    patch.object(owned.os,"open",side_effect=metadata_only), \
                    patch.object(owned.fcntl,"flock",side_effect=AssertionError("no lock acquisition")):
                witness=owned.OwnedInactiveObservation(selected,HOME,time.monotonic_ns()+60*10**9)
                try:
                    witness.recheck()
                    original=state/"state.sqlite"
                    original.rename(state/"retired")
                    original.write_bytes(b"synthetic opaque ciphertext")
                    original.chmod(0o600)
                    with self.assertRaises(ValueError):
                        witness.recheck()
                finally:
                    witness.close()
                software.close.assert_called_once_with()

    def test_inactive_guard_actual_properties_local_environment_and_original_work_deadline(self):
        import guard_resident_owned_update as owned
        from unittest.mock import Mock
        admission=resident.Admission.__new__(resident.Admission)
        admission.selected=self.selected()
        admission.deadline_ns=40*10**9
        admission.owned_start=Mock()
        admission.control_source=Path("/synthetic/control")
        admission.recheck=Mock(return_value={})
        executable=str(Path(admission.selected["prefix"])/"bin/omuxd")
        values={"LoadState":"loaded","ActiveState":"inactive","SubState":"dead","MainPID":"0",
            "FragmentPath":admission.selected["service_path"],"ControlGroup":"","UnitFileState":"enabled",
            "Slice":"app.slice","ExecStart":"{ path="+executable+" ; argv[]="+executable+" --state-dir "+
                admission.selected["runtime_state"]+" ; ignore_errors=no ; pid=0 ; status=0/0 }",
            "DropInPaths":"","NeedDaemonReload":"no","MemoryMax":"268435456","MemorySwapMax":"0",
            "TasksMax":"32","CPUQuotaPerSecUSec":"100ms"}
        def response(changed):
            return SimpleNamespace(returncode=0,stderr=b"",
                stdout="".join(k+"="+v+"\n" for k,v in changed.items()).encode())
        with patch.object(resident.time,"monotonic_ns",return_value=30*10**9), \
                patch.object(resident.subprocess,"run",return_value=response(values)) as query, \
                patch.object(resident,"resolve_owned_unit_fragment",return_value=Path(values["FragmentPath"])), \
                patch.object(owned,"inactive_cgroup",return_value={"unit_cgroup_empty":True}) as population, \
                patch.object(resident.os,"listdir",return_value=[]):
            result=admission.service_observation("/declared/systemctl",starting=True)
            self.assertTrue(result["main_pid_zero"] and result["unit_cgroup_empty"])
            self.assertFalse(result["active"] or result["service_mutation_requested"] or result["custody_verified"])
            self.assertEqual(query.call_args.kwargs["timeout"],10)
            self.assertEqual(set(query.call_args.kwargs["env"]),
                {"HOME","LC_ALL","XDG_RUNTIME_DIR","DBUS_SESSION_BUS_ADDRESS"})
            population.assert_called_once_with(admission.deadline_ns)
            admission.recheck.assert_called_once_with()
            for key,value in (("ActiveState","active"),("MainPID","2"),("ControlGroup","/foreign"),
                              ("TasksMax","33"),("CPUQuotaPerSecUSec","101ms")):
                with self.subTest(key=key),patch.object(resident.subprocess,"run",
                        return_value=response({**values,key:value})),self.assertRaises(ValueError):
                    admission.service_observation("/declared/systemctl")
        with patch.object(resident.time,"monotonic_ns",return_value=admission.deadline_ns), \
                patch.object(resident.subprocess,"run") as query,self.assertRaises(ValueError):
            admission.service_observation("/declared/systemctl")
        query.assert_not_called()

    def test_inactive_witness_close_failure_still_releases_software_and_namespace(self):
        import guard_resident_owned_update as owned
        from unittest.mock import Mock
        witness=owned.OwnedInactiveObservation.__new__(owned.OwnedInactiveObservation)
        runtime,software=Mock(),Mock()
        runtime.close.side_effect=OSError("synthetic close fault")
        witness.runtime,witness.software=runtime,software
        with self.assertRaises(OSError):
            witness.close()
        software.close.assert_called_once_with()
        self.assertIsNone(witness.runtime)
        self.assertIsNone(witness.software)
        admission=resident.Admission.__new__(resident.Admission)
        admission.selected=self.selected()
        admission.owned_start=Mock()
        admission.owned_start.close.side_effect=OSError("synthetic witness close fault")
        descriptor=os.open("/dev/null",os.O_RDONLY|os.O_CLOEXEC)
        admission.held=[descriptor]
        with self.assertRaises(OSError):
            admission.close()
        with self.assertRaises(OSError):
            os.fstat(descriptor)
        self.assertEqual(admission.held,[])

    def test_initial_peer_calls_cannot_spend_the_original_cleanup_reserve(self):
        admission=resident.Admission.__new__(resident.Admission)
        admission.root=Path("/synthetic/inputs")
        bus=Path("/synthetic/bus")
        admission.sources={admission.root/"systemd/private":Path("/synthetic/manager"),
                           admission.root/"bus":bus}
        admission.original_deadline_ns=40*10**9
        admission.deadline_ns=40*10**9
        with patch.object(resident.time,"monotonic_ns",return_value=9*10**9), \
                patch.object(resident,"socket_witness") as peer,self.assertRaises(ValueError):
            admission.session_peer_witness(bus)
        peer.assert_not_called()
        with patch.object(resident.time,"monotonic_ns",return_value=7*10**9), \
                patch.object(resident,"socket_witness",return_value="synthetic peer") as peer:
            self.assertEqual(admission.session_peer_witness(bus),"synthetic peer")
        peer.assert_called_once_with(bus)

    def test_post_cleanup_proof_requires_zero_cleaned_exact_epoch_and_graph(self):
        import guard_resident_setup_dispatch as dispatch
        from unittest.mock import Mock
        value=dispatch.Admission.__new__(dispatch.Admission)
        value.run=Path("/synthetic/epoch")
        value.systemctl=Path("/declared/systemctl")
        value.inner=Mock(installation_update=None,selected=self.selected())
        value.inner.service_observation.return_value={"active":False,"main_pid_zero":True,
            "unit_cgroup_empty":True,"service_mutation_requested":False}
        for status,cleaned,epoch,graph in ((1,True,"epoch","a"*64),(False,True,"epoch","a"*64),
                (0,False,"epoch","a"*64),(0,True,"other","a"*64),(0,True,"epoch","x"*64)):
            with self.subTest(status=status,cleaned=cleaned,epoch=epoch),self.assertRaises(ValueError):
                value.completed(status,cleaned,epoch,None,graph)
        value.inner.service_observation.assert_not_called()
        result=value.completed(0,True,"epoch",None,"a"*64)
        self.assertTrue(result["verified_after_cleanup"])
        self.assertEqual(result["source_graph_sha256"],"a"*64)
        self.assertEqual(result["action_epoch"],"epoch")

if __name__ == "__main__":
    unittest.main()
