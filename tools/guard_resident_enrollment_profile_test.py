"""Provider-free resident admission and complementary reservation predicates."""
import copy
import json
import os
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

class ResidentModels(unittest.TestCase):
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
        admission.sources = {admission.root/"bus":Path("/run/user/1000/bus"),
            admission.root/"systemd/private":Path("/run/user/1000/systemd/private")}
        admission.product_directories = [(Path("/private/product"),None,None)]
        run = Path("/private/run")
        actual = {"BindReadOnlyPaths":" ".join(v+":rbind" for v in admission.bindings()),
            "BindPaths":admission.writable_binding()+" "+str(run)+":"+str(run)}
        admission.verify_bindings(actual,run)
        for role in ("BindReadOnlyPaths","BindPaths"):
            bad = dict(actual)
            bad[role] += " /foreign:/foreign"
            with self.assertRaises(ValueError):
                admission.verify_bindings(bad,run)
        bad = dict(actual)
        bad["BindReadOnlyPaths"] += " "+admission.bindings()[0]
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


if __name__ == "__main__":
    unittest.main()
