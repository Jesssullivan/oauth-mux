"""Provider-free regressions for the factor-free OS-mediated setup action."""
import contextlib
import copy
import io
import json
import os
from types import SimpleNamespace
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest.mock import patch
import resident_standard_vault as action
vault=action.vault
CLIENT=None
def observed():
    row={"uid":os.getuid(),"pid":101,"start_ticks":7}
    return {"schema":"omux-existing-vault-metadata-v2","broker":dict(row),
        "manager":dict(row,pid=102,owner=":1.2"),"secret_service":dict(row,pid=103,owner=":1.3"),
        "provider":"standard-secret-service","default_collection":"/org/freedesktop/secrets/collection/existing",
        "default_exists":True,"locked":True,"items_read":False,"secrets_read":False,"provider_invocation":False}
def selected():
    return {"schema_version":2,"purpose":"unlock-standard-vault","permissions":{"metadata":True,"unlock":True},
        "mapping":None,"expected":observed()}
def result(status):
    return SimpleNamespace(returncode=0 if status=="unlocked-for-client" else 125,
        stdout=json.dumps({"schema":"omux-standard-vault-unlock-result-v1","status":status}).encode())
class StandardVaultModels(unittest.TestCase):
    def test_compiled_prompt_binds_completion_and_refuses_signal_flood_or_late_success(self):
        answer=subprocess.run([CLIENT,"--standard-model"],env={},stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,check=False)
        self.assertEqual((answer.returncode,answer.stdout,answer.stderr),(0,b"",b""))
    def test_compiled_standard_mode_refuses_missing_witness_before_bus_or_stdin(self):
        answer=subprocess.run([CLIENT,"--standard-secret-service-unlock"],env={},
            input=b"unused-private-input",stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5,check=False)
        self.assertEqual((answer.returncode,answer.stderr),(125,b""))
        self.assertEqual(json.loads(answer.stdout),
            {"schema":"omux-standard-vault-unlock-result-v1","status":"arguments"})
    def test_compiled_metadata_pipe_rejects_empty_oversized_nul_or_trailing_data_before_bus(self):
        arguments=[CLIENT,"--standard-secret-service-unlock","101","7",":1.2","102","7",":1.3","103","7"]
        for body in (b"",b"/",b"/collection/existing\n",b"/collection/existing\0",b"x"*4096):
            environment={"DBUS_SESSION_BUS_ADDRESS":"unix:path="+action.resident.DESTINATION+"/bus",
                vault.DEADLINE_VARIABLE:str(time.monotonic_ns()+2*10**9)}
            answer=subprocess.run(arguments,env=environment,input=body,stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,timeout=5,check=False)
            self.assertEqual((answer.returncode,answer.stderr),(125,b""))
            self.assertEqual(json.loads(answer.stdout),
                {"schema":"omux-standard-vault-unlock-result-v1","status":"collection-input-refused"})
    def test_explicit_standard_observer_never_uses_legacy_executable_predicate(self):
        value=observed()
        with patch.object(action,"budget",return_value=1), \
                patch.object(action.subprocess,"run",return_value=SimpleNamespace(returncode=0,
                    stdout=json.dumps(value).encode())) as running, \
                patch.object(vault,"expected_processes") as processes, \
                patch.object(vault,"process",side_effect=AssertionError("legacy exe inspection")):
            self.assertEqual(action.observe("/declared/observer",10**18),value)
        self.assertEqual(running.call_args.args[0],["/declared/observer","--standard-service-metadata"])
        self.assertEqual(running.call_args.kwargs["stdin"],subprocess.DEVNULL)
        processes.assert_called_once_with(value)
    def test_changed_expected_collection_or_owner_prevents_unlock_dispatch(self):
        for role,key,new in ((None,"default_collection","/collection/other"),("secret_service","owner",":1.4"),
                ("broker","start_ticks",8)):
            before=observed()
            if role is None:before[key]=new
            else:before[role][key]=new
            with patch.object(action.subprocess,"run") as running:
                with self.assertRaises(ValueError):action.unlock(before,selected(),"/declared/client",10**18)
                running.assert_not_called()
    def test_unlock_dispatch_has_only_public_witnesses_no_factor_or_proprietary_channel(self):
        before=observed()
        with patch.object(vault,"expected_processes") as processes,patch.object(action,"budget",return_value=120), \
                patch.object(action.subprocess,"run",return_value=result("unlocked-for-client")) as running, \
                patch.object(action.common.os,"open",side_effect=AssertionError("factor IO")), \
                patch.object(action.common.socket,"socket",side_effect=AssertionError("private control IO")):
            self.assertEqual(action.unlock(before,selected(),"/declared/client",10**18),"unlocked-for-client")
        args=running.call_args.args[0]
        self.assertEqual(args,["/declared/client","--standard-secret-service-unlock","101","7",":1.2","102","7",
            ":1.3","103","7"])
        self.assertNotIn("stdin",running.call_args.kwargs)
        self.assertEqual(running.call_args.kwargs["input"],before["default_collection"].encode("ascii"))
        self.assertNotIn(before["default_collection"],args)
        self.assertNotIn("pass_fds",running.call_args.kwargs)
        self.assertEqual(running.call_args.kwargs["timeout"],120)
        self.assertEqual(set(running.call_args.kwargs["env"]),{"DBUS_SESSION_BUS_ADDRESS",vault.DEADLINE_VARIABLE,"LC_ALL"})
        self.assertEqual(processes.call_count,2)
    def test_cancellation_unavailable_prompt_and_deadlines_remain_closed_refusals(self):
        for status in ("cancelled","prompt-unavailable","prompt-timeout","deadline"):
            with self.subTest(status=status),patch.object(vault,"expected_processes"), \
                    patch.object(action,"budget",return_value=120), \
                    patch.object(action.subprocess,"run",return_value=result(status)):
                with self.assertRaises(action.StandardRefusal) as failure:
                    action.unlock(observed(),selected(),"/declared/client",10**18)
                self.assertEqual(action.refusal_projection(failure.exception)["predicate"],status)
        with patch.object(vault,"expected_processes"),patch.object(action,"budget",return_value=120), \
                patch.object(action.subprocess,"run",side_effect=subprocess.TimeoutExpired("not-published",120)):
            with self.assertRaises(action.StandardRefusal) as failure:
                action.unlock(observed(),selected(),"/declared/client",10**18)
            self.assertEqual(failure.exception.status,"deadline")
    def test_foreign_child_text_unknown_status_duplicate_keys_or_exit_mismatch_are_redacted(self):
        answers=(SimpleNamespace(returncode=125,stdout=b"/private/account/data"),
            SimpleNamespace(returncode=125,stdout=b'{"schema":"omux-standard-vault-unlock-result-v1","status":"cancelled:/private"}'),
            SimpleNamespace(returncode=125,stdout=b'{"schema":"omux-standard-vault-unlock-result-v1","status":"cancelled","status":"deadline"}'),
            SimpleNamespace(returncode=125,stdout=result("unlocked-for-client").stdout),
            SimpleNamespace(returncode=0,stdout=result("cancelled").stdout))
        for answer in answers:
            with self.assertRaises(action.StandardRefusal) as failure:action.client_status(answer)
            self.assertEqual(failure.exception.status,"client-exit")
    def test_after_observation_owner_alias_and_existence_changes_refuse(self):
        for role,key,new in (("secret_service","owner",":1.4"),("manager","start_ticks",8),
                ("broker","pid",104),(None,"default_collection","/collection/other"),
                (None,"default_exists",False),(None,"locked",None)):
            after=observed()
            if role is None:after[key]=new
            else:after[role][key]=new
            with self.assertRaises(ValueError):action.compare_after(observed(),after)
    def test_connection_scoped_success_retains_independent_locked_state_without_custody_claim(self):
        for locked in (False,True):
            after=observed();after["locked"]=locked
            with patch.object(action,"deadline",return_value=10**18), \
                    patch.object(action,"private_manifest",return_value=selected()), \
                    patch.object(action,"observe",side_effect=[observed(),after]), \
                    patch.object(action,"unlock",return_value="unlocked-for-client"), \
                    patch.object(action,"retain") as retain,contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(action.main(["unlock","/declared/observer","/declared/client"]),0)
            output=retain.call_args.args[0]
            self.assertIs(output["observation"]["locked"],locked)
            self.assertEqual(output["unlock_effect_scope"],"helper-connection-verified/resident-readiness-unproved")
            self.assertIs(output["resident_key_readiness_proven"],False)
            self.assertIs(output["resident_custody_proven"],False)
            self.assertIs(output["omux_wrapping_key_regeneration"],False)
    def test_metadata_action_cannot_dispatch_unlock_and_v1_selector_is_rejected(self):
        meta={"schema_version":2,"purpose":"observe-standard-vault","permissions":{"metadata":True,"unlock":False},
            "mapping":None,"expected":None}
        with patch.object(action,"deadline",return_value=10**18),patch.object(action,"private_manifest",return_value=meta), \
                patch.object(action,"observe",side_effect=[observed(),observed()]), \
                patch.object(action,"unlock") as unlock,patch.object(action,"retain"),contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(action.main(["observe","/declared/observer","/declared/client"]),0)
            unlock.assert_not_called()
        bad=copy.deepcopy(selected());bad["schema_version"]=1
        with patch.object(action,"deadline",return_value=10**18),patch.object(action,"private_manifest",return_value=bad), \
                patch.object(action,"observe") as observe:
            with self.assertRaises(ValueError):action.main(["unlock","/declared/observer","/declared/client"])
            observe.assert_not_called()
    def test_no_os_error_message_or_secret_exception_is_published(self):
        class Sensitive(OSError):
            def __str__(self):raise AssertionError("must not stringify private errors")
        self.assertEqual(action.refusal_projection(Sensitive())["predicate"],"carrier-gate")
if __name__=="__main__":
    CLIENT=sys.argv.pop(1)
    unittest.main()
