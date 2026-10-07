"""Provider-free models exercise actual pre-IO gates and the compiled control frame."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).parent.parent/"tools"))
import guard_resident_vault_profile as vault
import resident_vault as action
CLIENT=None
def observed():
    common={"uid":os.getuid(),"pid":101,"start_ticks":7,"exe":"/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-bus/bin/dbus-broker"}
    return {"schema":"omux-existing-vault-metadata-v1","broker":dict(common),
        "manager":dict(common,pid=102,owner=":1.2",exe="/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-manager/bin/systemd"),
        "secret_service":dict(common,pid=103,owner=":1.3",exe=vault.GNOME_EXE),
        "provider":"gnome-keyring-48.0","default_exists":True,"default_is_login":True,"locked":True,
        "items_read":False,"secrets_read":False,"provider_invocation":False}
def selected():
    return {"schema_version":1,"purpose":"unlock-existing-login-vault",
        "permissions":{"metadata":True,"unlock":True},
        "mapping":{"role":"become/password","purpose":"gnome-login-keyring-unlock","encoding":"exact-bytes","user_confirmed":True},
        "expected":observed()}
class VaultModels(unittest.TestCase):
    def test_original_deadline_keeps_cleanup_reserve(self):
        now=10**12
        with patch.object(action.time,"monotonic_ns",return_value=now):
            self.assertEqual(action.deadline({vault.DEADLINE_VARIABLE:str(now+120*10**9)}),now+90*10**9)
            for remaining in (0,30*10**9,1201*10**9):
                with self.assertRaises(ValueError):
                    action.deadline({vault.DEADLINE_VARIABLE:str(now+remaining)})
    def test_named_directory_recheck_reopens_canonical_ancestors(self):
        witness=(1,2,0o40700,os.getuid(),os.getgid())
        with patch.object(vault.resident,"open_directory",return_value=17) as opening, \
                patch.object(vault.os,"fstat",return_value=object()), \
                patch.object(vault.resident,"stable",return_value=witness), \
                patch.object(vault.os,"close") as closing:
            vault.named_directory(Path("/run/user")/str(os.getuid()),witness)
            opening.assert_called_once_with(Path("/run/user")/str(os.getuid()),private=False)
            closing.assert_called_once_with(17)
        with patch.object(vault.resident,"open_directory",side_effect=OSError("nofollow")):
            with self.assertRaises(OSError):vault.named_directory(Path("/run/user")/str(os.getuid()),witness)
    def test_one_owned_exact_sops_generation_projection_only(self):
        uid=os.getuid()
        valid="/run/user/"+str(uid)+"/secrets.d/4920"
        self.assertEqual(vault.generation_target(valid,uid),Path(valid))
        for target in ("/tmp/factor","/run/user/"+str(uid+1)+"/secrets.d/4920",
                valid+"/become/password",valid+"/../4921",valid.replace("/4920","/04920"),
                valid.replace("/4920","/current"),valid+":suffix"):
            with self.assertRaises(ValueError):vault.generation_target(target,uid)
    def test_metadata_requires_no_private_parameters(self):
        value={"schema_version":1,"purpose":"observe-default-vault","permissions":{"metadata":True,"unlock":False},
            "mapping":None,"expected":None}
        self.assertEqual(vault.schema(value),value)
        for key in ("mapping","expected"):
            changed=copy.deepcopy(value);changed[key]=selected()[key]
            with self.assertRaises(ValueError):vault.schema(changed)
    def test_unmapped_or_unconfirmed_factor_is_refused(self):
        for mutation in (None,{},dict(selected()["mapping"],user_confirmed=False),
                dict(selected()["mapping"],user_confirmed=1),
                dict(selected()["mapping"],role="../password"),
                dict(selected()["mapping"],purpose="sudo"),
                dict(selected()["mapping"],encoding="strip-newline")):
            value=selected();value["mapping"]=mutation
            with self.assertRaises(ValueError):vault.schema(value)
    def test_unknown_owner_provider_alias_or_lock_is_refused_before_factor_io(self):
        changes=(("provider","unqualified-existing-provider"),("default_exists",False),
            ("default_is_login",False),("locked",False),("locked",None))
        for key,value in changes:
            before=observed();before[key]=value
            with patch.object(action.os,"open") as opening,patch.object(action.socket,"socket") as connecting:
                with self.assertRaises(ValueError):action.unlock(before,selected(),"/declared/client",10**18)
                opening.assert_not_called();connecting.assert_not_called()
    def test_changed_expected_snapshot_is_refused_before_factor_io(self):
        before=observed();before["secret_service"]["start_ticks"]+=1
        with patch.object(action.os,"open") as opening,patch.object(action.socket,"socket") as connecting:
            with self.assertRaises(ValueError):action.unlock(before,selected(),"/declared/client",10**18)
            opening.assert_not_called();connecting.assert_not_called()
    def test_success_requires_same_owner_alias_and_unlocked(self):
        before=observed();after=copy.deepcopy(before);after["locked"]=False
        self.assertTrue(vault.compare_after(before,after))
        for name in ("broker","manager","secret_service"):
            changed=copy.deepcopy(after);changed[name]["start_ticks"]+=1
            with self.assertRaises(ValueError):vault.compare_after(before,changed)
        for key,value in (("locked",True),("default_is_login",False),("default_exists",False)):
            changed=copy.deepcopy(after);changed[key]=value
            with self.assertRaises(ValueError):vault.compare_after(before,changed)
    def test_undeclared_labels_flags_and_cross_profile_inputs_are_refused(self):
        for arguments,manager,reuse,unrelated in (
            (["run",vault.LABEL,"--secret=forbidden"],"system",False,()),
            (["run","//delivery:resident_codex_enrollment"],"system",False,()),
            (["run",vault.LABEL],"user",False,()),
            (["run",vault.LABEL],"system",True,()),
            (["run",vault.LABEL],"system",False,("unrelated",))):
            with self.assertRaises(ValueError):vault.finite(arguments,manager,"input.json",reuse,unrelated)
        self.assertEqual(vault.finite(["run",vault.LABEL],"system","input.json",False)["PrivateNetwork"],"yes")
    def test_observation_closed_shape_rejects_labels_and_secret_fields(self):
        for key in ("items","Label","token","email","factor"):
            value=observed();value[key]="forbidden"
            with self.assertRaises(ValueError):vault.validate_observation(value)
    def test_compiled_client_exact_unlock_frame_bounds_and_zeroization(self):
        self.assertIsNotNone(CLIENT)
        answer=subprocess.run([CLIENT,"--model"],env={},stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,timeout=5,check=False)
        self.assertEqual((answer.returncode,answer.stdout,answer.stderr),(0,b"",b""))
    def test_compiled_client_refuses_absent_mapping_before_stdin_or_socket(self):
        answer=subprocess.run([CLIENT,"--existing-unlock-stdin"],env={},stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,check=False)
        self.assertEqual((answer.returncode,answer.stdout,answer.stderr),(125,b"",b""))
if __name__=="__main__":
    if len(sys.argv)>1:
        CLIENT=sys.argv.pop(1)
    unittest.main()
