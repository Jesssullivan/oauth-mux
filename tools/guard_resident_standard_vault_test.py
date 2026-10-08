"""Provider-free models for versioned local standard-service metadata."""
import copy
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

if __name__=="__main__":
    unittest.main()
