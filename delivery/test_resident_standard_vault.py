"""Provider-free regressions for the factor-free OS-mediated setup action."""
import contextlib
import copy
import io
import json
import os
from types import SimpleNamespace
from pathlib import Path
import subprocess
import stat
import sys
import time
import tempfile
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
                patch.object(action,"unlock") as unlock,patch.object(action,"retain"), \
                patch.object(vault.MetadataOutput,"consume",return_value=None),contextlib.redirect_stdout(io.StringIO()):
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

    def metadata_output(self):
        return {"schema":"omux-resident-standard-vault-action-v1","purpose":"observe-standard-vault",
            "observation":observed(),"unlock_dispatched":False,"client_status":"not-dispatched",
            "unlock_effect_scope":"not-dispatched","unchanged_service_owner":True,"unchanged_default_collection":True,
            "factor_material_access":False,"provider_invocation":False,"omux_datastore_access":False,
            "omux_wrapping_key_regeneration":False,"resident_key_readiness_proven":False,
            "resident_custody_proven":False,"normal_os_unlock_passed":False,"native_support":False}

    @contextlib.contextmanager
    def held_output(self, seconds=120):
        # Only the nofollow ancestor opener is adapted to Bazel's shared
        # TEST_TMPDIR ancestry. All run/file FDs, identities and operations are real.
        with tempfile.TemporaryDirectory() as temporary:
            run=Path(temporary)/"yoga-proof"/"11111111-2222-3333-4444-555555555555"
            run.parent.mkdir(mode=0o700);run.mkdir(mode=0o700)
            until=time.monotonic_ns()+int(seconds*10**9)
            def opened(path,private=False):
                return os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            original=os.open(run,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            with patch.object(vault.resident,"open_directory",side_effect=opened):
                owner=vault.MetadataOutput(run,until,descriptor=original)
                os.close(original)
                try:
                    owner.bind("a"*40,"b"*64,"c"*64,"d"*64)
                    environment={**owner.environment(),"OMUX_EXECUTION_GUARD":str(run),
                        vault.DEADLINE_VARIABLE:str(until)}
                    yield owner,environment,run
                finally:owner.close()

    def test_real_owned_yoga_root_publication_uses_guardian_fd_tuple_and_exact_frame(self):
        with self.held_output() as (guardian,environment,run):
            worker=vault.MetadataOutput.consume(environment)
            try:action.common.retain(self.metadata_output(),worker)
            finally:worker.close()
            guardian.check()
            output=run/"resident-vault-metadata.json"
            self.assertEqual(json.loads(output.read_bytes()),self.metadata_output())
            self.assertEqual(output.stat().st_mode & 0o777,0o600)
            self.assertLessEqual(output.stat().st_size,vault.OUTPUT_LIMIT)
            with self.assertRaises(FileExistsError):
                worker=vault.MetadataOutput.consume(environment)
                try:worker.publish(self.metadata_output())
                finally:worker.close()
            self.assertEqual(json.loads(output.read_bytes()),self.metadata_output())

    def test_real_held_directory_replacement_refuses_before_output_and_preserves_foreign(self):
        with self.held_output() as (_,environment,run):
            worker=vault.MetadataOutput.consume(environment)
            try:
                displaced=run.with_name("displaced")
                run.rename(displaced);run.mkdir(mode=0o700)
                (run/"foreign").write_bytes(b"public foreign")
                with self.assertRaises(ValueError):worker.publish(self.metadata_output())
                self.assertFalse((displaced/"resident-vault-metadata.json").exists())
                self.assertEqual((run/"foreign").read_bytes(),b"public foreign")
            finally:worker.close()

    def test_real_output_escape_uuid_uid_and_fixed_operation_context_are_refused(self):
        with self.held_output() as (_,environment,run):
            original=vault.output_unwire(environment[vault.OUTPUT_VARIABLE])
            alternate=run.parent/"66666666-7777-8888-9999-aaaaaaaaaaaa"
            alternate.mkdir(mode=0o700)
            for key,value in (("run",str(alternate)),("epoch",alternate.name),("profile","standard"),
                    ("manager","user"),("target",vault.STANDARD_UNLOCK_LABEL),
                    ("purpose","unlock-standard-vault"),("source_graph_sha256","bad")):
                changed=dict(original);changed[key]=value
                selected=dict(environment);selected[vault.OUTPUT_VARIABLE]=vault.output_wire(changed)
                selected[vault.OUTPUT_SHA_VARIABLE]=vault.hashlib.sha256(selected[vault.OUTPUT_VARIABLE].encode("ascii")).hexdigest()
                if key=="run":selected["OMUX_EXECUTION_GUARD"]=str(alternate)
                with self.subTest(key=key),self.assertRaises(ValueError):
                    vault.MetadataOutput.consume(selected)
            with patch.object(vault.os,"getuid",return_value=os.getuid()+1),self.assertRaises(ValueError):
                vault.MetadataOutput.consume(environment)
            self.assertEqual(list(alternate.iterdir()),[])
            self.assertFalse((run/"resident-vault-metadata.json").exists())

    def test_actual_expired_clock_and_oversized_authority_refuse_without_output(self):
        with self.held_output() as (_,environment,run):
            changed=vault.output_unwire(environment[vault.OUTPUT_VARIABLE])
            changed["deadline_ns"]=time.monotonic_ns()-1
            bad=dict(environment);bad[vault.OUTPUT_VARIABLE]=vault.output_wire(changed)
            bad[vault.DEADLINE_VARIABLE]=str(changed["deadline_ns"])
            bad[vault.OUTPUT_SHA_VARIABLE]=vault.hashlib.sha256(bad[vault.OUTPUT_VARIABLE].encode("ascii")).hexdigest()
            with self.assertRaises(ValueError):vault.MetadataOutput.consume(bad)
            bad=dict(environment);bad[vault.OUTPUT_VARIABLE]="x"*4097
            with self.assertRaises(ValueError):vault.MetadataOutput.consume(bad)
            bad[vault.OUTPUT_VARIABLE]="x"*5463
            with self.assertRaises(ValueError):vault.MetadataOutput.consume(bad)
            self.assertFalse((run/"resident-vault-metadata.json").exists())

    def test_actual_post_write_directory_swap_rolls_back_held_output_without_touching_foreign(self):
        with self.held_output() as (_,environment,run):
            worker=vault.MetadataOutput.consume(environment)
            fsync=os.fsync
            swapped=False
            def swapping(descriptor):
                nonlocal swapped
                fsync(descriptor)
                if not swapped:
                    swapped=True
                    run.rename(run.with_name("original"));run.mkdir(mode=0o700)
                    (run/"foreign").write_bytes(b"public foreign")
            try:
                with patch.object(vault.os,"fsync",side_effect=swapping),self.assertRaises(ValueError):
                    worker.publish(self.metadata_output())
                self.assertFalse((run.with_name("original")/"resident-vault-metadata.json").exists())
                self.assertEqual((run/"foreign").read_bytes(),b"public foreign")
            finally:worker.close()

    def test_actual_clock_expiry_after_file_fsync_refuses_and_removes_own_partial(self):
        with self.held_output(seconds=31) as (_,environment,run):
            worker=vault.MetadataOutput.consume(environment)
            fsync=os.fsync
            reached=[]
            def late(descriptor):
                reached.append(descriptor)
                fsync(descriptor)
                time.sleep(1.1)
            try:
                with patch.object(vault.os,"fsync",side_effect=late),self.assertRaises(ValueError):
                    worker.publish(self.metadata_output())
                self.assertTrue(reached)
                self.assertFalse((run/"resident-vault-metadata.json").exists())
            finally:worker.close()

    def test_real_symlink_substitution_and_output_extension_are_refused(self):
        with self.held_output() as (_,environment,run):
            target=run.with_name("target");target.mkdir(mode=0o700)
            worker=vault.MetadataOutput.consume(environment)
            try:
                extension=self.metadata_output();extension["undeclared"]="x"*20000
                with self.assertRaises(ValueError):worker.publish(extension)
                self.assertFalse((run/"resident-vault-metadata.json").exists())
                run.rename(run.with_name("old"));run.symlink_to(target,target_is_directory=True)
                with self.assertRaises(OSError):worker.publish(self.metadata_output())
                self.assertEqual(list(target.iterdir()),[])
            finally:worker.close()


    def test_actual_guardian_original_fd_cannot_adopt_a_different_named_run(self):
        with self.held_output() as (guardian,_,run):
            other=run.parent/"66666666-7777-8888-9999-aaaaaaaaaaaa"
            other.mkdir(mode=0o700)
            with self.assertRaises(ValueError):
                vault.MetadataOutput(other,guardian.deadline_ns,descriptor=guardian.fd)
            guardian.check()
            self.assertEqual(list(other.iterdir()),[])

    def test_actual_first_output_close_failure_removes_owned_file_and_never_retries_fd(self):
        with self.held_output() as (_,environment,run):
            worker=vault.MetadataOutput.consume(environment)
            real_close=os.close
            attempts=[]
            def closing(descriptor):
                regular=stat.S_ISREG(os.fstat(descriptor).st_mode)
                real_close(descriptor)
                if regular:
                    attempts.append(descriptor)
                    raise OSError("private fault")
            try:
                with patch.object(vault.os,"close",side_effect=closing),self.assertRaises(OSError):
                    worker.publish(self.metadata_output())
                # The real regular output FD was closed before its error:
                # retry could close a reused number and is forbidden.
                self.assertEqual(len(attempts),1)
                self.assertFalse((run/"resident-vault-metadata.json").exists())
            finally:worker.close()


    def test_actual_final_readback_byte_mode_and_link_drift_refuse_and_preserve_foreign(self):
        for mutation in ("bytes","mode","link"):
            with self.subTest(mutation=mutation),self.held_output() as (_,environment,run):
                worker=vault.MetadataOutput.consume(environment)
                fsync=os.fsync
                def changed(descriptor):
                    fsync(descriptor)
                    if stat.S_ISREG(os.fstat(descriptor).st_mode):
                        if mutation=="bytes":os.pwrite(descriptor,b"x",0)
                        elif mutation=="mode":os.fchmod(descriptor,0o644)
                        else:os.link(run/"resident-vault-metadata.json",run/"foreign-link")
                try:
                    with patch.object(vault.os,"fsync",side_effect=changed),self.assertRaises(ValueError):
                        worker.publish(self.metadata_output())
                    self.assertFalse((run/"resident-vault-metadata.json").exists())
                    if mutation=="link":self.assertTrue((run/"foreign-link").is_file())
                finally:worker.close()


    def test_minted_exact_source_and_closure_context_cannot_be_changed_after_guard_export(self):
        with self.held_output() as (_,environment,run):
            for field in ("source_commit","source_graph_sha256","closure_sha256","bootstrap_sha256"):
                changed=vault.output_unwire(environment[vault.OUTPUT_VARIABLE])
                changed[field]="e"*len(changed[field])
                bad=dict(environment);bad[vault.OUTPUT_VARIABLE]=vault.output_wire(changed)
                with self.subTest(field=field),self.assertRaises(ValueError):
                    vault.MetadataOutput.consume(bad)
            self.assertFalse((run/"resident-vault-metadata.json").exists())


    def test_actual_last_directory_fsync_mutation_replacement_unlink_and_error_refuse(self):
        for mutation in ("bytes","mode","link","replace","unlink","fault"):
            with self.subTest(mutation=mutation),self.held_output() as (_,environment,run):
                worker=vault.MetadataOutput.consume(environment)
                real_fsync=os.fsync
                reached=[]
                def last(descriptor):
                    real_fsync(descriptor)
                    if stat.S_ISDIR(os.fstat(descriptor).st_mode):
                        reached.append(descriptor)
                        output=run/"resident-vault-metadata.json"
                        if mutation=="bytes":
                            with output.open("r+b") as stream:stream.write(b"x")
                        elif mutation=="mode":output.chmod(0o644)
                        elif mutation=="link":os.link(output,run/"foreign-link")
                        elif mutation=="replace":
                            output.rename(run/"original-leaf")
                            output.write_bytes((run/"original-leaf").read_bytes());output.chmod(0o600)
                        elif mutation=="unlink":output.unlink()
                        else:raise OSError("private last fsync")
                try:
                    with patch.object(vault.os,"fsync",side_effect=last),self.assertRaises((OSError,ValueError)):
                        worker.publish(self.metadata_output())
                    self.assertEqual(len(reached),1)
                    if mutation=="replace":
                        self.assertEqual(json.loads((run/"resident-vault-metadata.json").read_bytes()),self.metadata_output())
                    else:self.assertFalse((run/"resident-vault-metadata.json").exists())
                finally:worker.close()

    def test_actual_writer_close_same_byte_replacement_refuses_without_fd_retry(self):
        with self.held_output() as (_,environment,run):
            worker=vault.MetadataOutput.consume(environment)
            original_close=os.close
            reached=[]
            def swapped(descriptor):
                regular=stat.S_ISREG(os.fstat(descriptor).st_mode)
                original_close(descriptor)
                if regular:
                    reached.append(descriptor)
                    output=run/"resident-vault-metadata.json"
                    output.rename(run/"original-leaf")
                    output.write_bytes((run/"original-leaf").read_bytes());output.chmod(0o600)
            try:
                with patch.object(vault.os,"close",side_effect=swapped),self.assertRaises(ValueError):
                    worker.publish(self.metadata_output())
                self.assertEqual(len(reached),1)
                self.assertEqual(json.loads((run/"resident-vault-metadata.json").read_bytes()),self.metadata_output())
            finally:worker.close()

    def test_parent_ack_binds_worker_creator_not_a_later_same_byte_output_inode(self):
        with self.held_output() as (guardian,environment,run):
            worker=vault.MetadataOutput.consume(environment)
            try:
                worker.publish(self.metadata_output())
                terminal=worker.terminal_frame()
            finally:worker.close()
            receiver=vault.MetadataTerminalReceiver(environment)
            try:
                receiver.feed(vault.TERMINAL_PREFIX+vault.output_wire(terminal).encode("ascii")+b"\n")
                receiver.finish(0)
            finally:receiver.close()
            guardian.pin_ack()
            original=run/"resident-vault-metadata.json"
            original.rename(run/"old-leaf")
            original.write_bytes((run/"old-leaf").read_bytes());original.chmod(0o600)
            with self.assertRaises(ValueError):guardian.verify_output()
            # Explicitly dispose the failed held parent proof; foreign new inode
            # remains, and the original creator FD is still single-owner.
            guardian.failed=True
            self.assertEqual(json.loads(original.read_bytes()),self.metadata_output())

    def test_receiver_unique_complete_closed_original_context_and_exit_cutoff(self):
        scenarios=("partial","duplicate","malformed","oversized","wrong-epoch","wrong-context",
            "wrong-leaf","nonzero","late")
        for scenario in scenarios:
            with self.subTest(scenario=scenario),self.held_output() as (_,environment,run):
                worker=vault.MetadataOutput.consume(environment)
                try:worker.publish(self.metadata_output());terminal=worker.terminal_frame()
                finally:worker.close()
                receiver=vault.MetadataTerminalReceiver(environment)
                frame=vault.TERMINAL_PREFIX+vault.output_wire(terminal).encode("ascii")+b"\n"
                try:
                    with self.assertRaises((ValueError,OSError)):
                        if scenario=="partial":receiver.feed(frame[:-1])
                        elif scenario=="duplicate":receiver.feed(frame+frame)
                        elif scenario=="malformed":receiver.feed(vault.TERMINAL_PREFIX+b"not-json\n")
                        elif scenario=="oversized":receiver.feed(vault.TERMINAL_PREFIX+b"x"*8192+b"\n")
                        elif scenario in ("wrong-epoch","wrong-context","wrong-leaf"):
                            changed=dict(terminal)
                            if scenario=="wrong-epoch":changed["epoch"]="66666666-7777-8888-9999-aaaaaaaaaaaa"
                            elif scenario=="wrong-context":changed["context_sha256"]="e"*64
                            else:changed["leaf"]=list(terminal["leaf"]);changed["leaf"][1]+=1
                            receiver.feed(vault.TERMINAL_PREFIX+vault.output_wire(changed).encode("ascii")+b"\n")
                        else:receiver.feed(frame)
                        if scenario=="late":
                            with patch.object(vault.time,"monotonic_ns",return_value=receiver.owner.deadline_ns-30*10**9):
                                receiver.finish(0)
                        else:receiver.finish(1 if scenario=="nonzero" else 0)
                    self.assertFalse((run/vault.ACK_NAME).exists())
                finally:receiver.close()

    def test_actual_main_late_owner_close_summary_write_and_flush_never_accept_terminal(self):
        for seam in ("close","write","flush","terminal-write","terminal-flush"):
            with self.subTest(seam=seam),self.held_output(seconds=31) as (_,environment,run):
                owned=vault.MetadataOutput.consume(environment)
                reached=[]
                class LateStdout(io.StringIO):
                    def write(self,value):
                        selected=seam=="write" or (seam=="terminal-write" and value.startswith(vault.TERMINAL_PREFIX.decode("ascii")))
                        if selected and not reached:
                            reached.append(seam);time.sleep(1.1)
                        return super().write(value)
                    def flush(self):
                        selected=seam=="flush" or (seam=="terminal-flush" and vault.TERMINAL_PREFIX.decode("ascii") in self.getvalue())
                        if selected and not reached:
                            reached.append(seam);time.sleep(1.1)
                        return super().flush()
                stdout=LateStdout()
                actual_close=owned.close
                def late_close():
                    actual_close()
                    if seam=="close":reached.append(seam);time.sleep(1.1)
                meta={"schema_version":2,"purpose":"observe-standard-vault",
                    "permissions":{"metadata":True,"unlock":False},"mapping":None,"expected":None}
                with patch.dict(action.os.environ,environment,clear=True), \
                        patch.object(action,"private_manifest",return_value=meta), \
                        patch.object(action,"observe",side_effect=[observed(),observed()]), \
                        patch.object(vault.MetadataOutput,"consume",return_value=owned), \
                        patch.object(owned,"close",side_effect=late_close),contextlib.redirect_stdout(stdout):
                    with self.assertRaises(ValueError):
                        action.main(["observe","/declared/observer","/declared/client"])
                self.assertEqual(reached,[seam])
                if seam in ("close","write","flush"):
                    self.assertNotIn(vault.TERMINAL_PREFIX.decode("ascii"),stdout.getvalue())
                else:
                    # A failed writer can have already flushed a provisional
                    # frame; the actual receiver still refuses expired/nonzero
                    # source completion and never creates an accepted ACK.
                    self.assertIn(vault.TERMINAL_PREFIX.decode("ascii"),stdout.getvalue())
                    with self.assertRaises(ValueError):vault.MetadataTerminalReceiver(environment)
                    self.assertFalse((run/vault.ACK_NAME).exists())
                self.assertFalse((run/"resident-vault-metadata.json").exists())


    def test_receiver_actual_fd_transfer_and_parser_allocation_interrupt_failures_keep_first_cause(self):
        cases=[(field,moment,error_type,False) for field in ("pending","skip","terminal","owner")
            for moment in ("before","after") for error_type in (MemoryError,KeyboardInterrupt)]
        cases.append(("owner","after",MemoryError,True))
        for field,moment,error_type,close_fault in cases:
            with self.subTest(field=field,moment=moment,error=error_type,close_fault=close_fault),self.held_output() as (guardian,environment,_):
                primary=error_type("private constructor fault")
                acquired=[]
                attempts=[]
                actual_consume=vault.MetadataOutput.consume
                actual_close=os.close
                def consume(selected):
                    owned=actual_consume(selected)
                    acquired.append((owned,owned.fd))
                    return owned
                class SetupFault(vault.MetadataTerminalReceiver):
                    def __setattr__(self,name,value):
                        selected=name==field and (name!="owner" or value is not None)
                        if selected and moment=="before":raise primary
                        object.__setattr__(self,name,value)
                        if selected and moment=="after":raise primary
                def close(descriptor):
                    selected=bool(acquired) and descriptor==acquired[0][1]
                    actual_close(descriptor)
                    if selected:
                        attempts.append(descriptor)
                        if close_fault:raise OSError("private secondary close fault")
                try:
                    with patch.object(vault.MetadataOutput,"consume",side_effect=consume), \
                            patch.object(vault.os,"close",side_effect=close):
                        with self.assertRaises(error_type) as refused:SetupFault(environment)
                    self.assertIs(refused.exception,primary)
                    if field=="owner":
                        self.assertEqual(len(acquired),1)
                        self.assertEqual(attempts,[acquired[0][1]])
                        self.assertIsNone(acquired[0][0].fd)
                        with self.assertRaises(OSError):os.fstat(acquired[0][1])
                    else:
                        self.assertEqual(acquired,[])
                        self.assertEqual(attempts,[])
                    guardian.check()
                finally:
                    # A failing regression still disposes its explicitly
                    # captured real owner; detached descriptors are not retried.
                    for owned,_ in acquired:
                        if owned.fd is not None:owned.close()

    def test_actual_last_root_read_ack_mutation_replacement_unlink_refuses_both_leaf_proof(self):
        for mutation in ("bytes","mode","link","replace","unlink"):
            with self.subTest(mutation=mutation),self.held_output() as (guardian,environment,run):
                producer=vault.MetadataOutput.consume(environment)
                try:producer.publish(self.metadata_output());terminal=producer.terminal_frame()
                finally:producer.close()
                receiver=vault.MetadataTerminalReceiver(environment)
                try:
                    receiver.feed(vault.TERMINAL_PREFIX+vault.output_wire(terminal).encode("ascii")+b"\n")
                    receiver.finish(0)
                finally:receiver.close()
                guardian.pin_ack()
                actual_named=vault.named_directory
                reached=[]
                def last(path,witness,private=False):
                    actual_named(path,witness,private=private)
                    reached.append(path)
                    if len(reached)==2:
                        ack=run/vault.ACK_NAME
                        if mutation=="bytes":
                            with ack.open("r+b") as stream:stream.write(b"x")
                        elif mutation=="mode":ack.chmod(0o644)
                        elif mutation=="link":os.link(ack,run/"foreign-ack-link")
                        elif mutation=="replace":
                            ack.rename(run/"original-ack")
                            ack.write_bytes((run/"original-ack").read_bytes());ack.chmod(0o600)
                        else:ack.unlink()
                try:
                    with patch.object(vault,"named_directory",side_effect=last),self.assertRaises((OSError,ValueError)):
                        guardian.verify_output()
                    self.assertEqual(reached,[run,run])
                    # Original metadata is unchanged; this is the ACK-only
                    # final root-I/O counterexample, not an output refusal.
                    self.assertEqual(json.loads((run/"resident-vault-metadata.json").read_bytes()),self.metadata_output())
                    if mutation=="replace":
                        self.assertEqual((run/vault.ACK_NAME).read_bytes(),(run/"original-ack").read_bytes())
                    if mutation=="link":self.assertTrue((run/"foreign-ack-link").is_file())
                finally:guardian.failed=True

    def test_actual_last_root_close_crosses_original_work_cutoff_after_both_files(self):
        with self.held_output(seconds=34) as (guardian,environment,run):
            producer=vault.MetadataOutput.consume(environment)
            try:producer.publish(self.metadata_output());terminal=producer.terminal_frame()
            finally:producer.close()
            receiver=vault.MetadataTerminalReceiver(environment)
            try:
                receiver.feed(vault.TERMINAL_PREFIX+vault.output_wire(terminal).encode("ascii")+b"\n")
                receiver.finish(0)
            finally:receiver.close()
            guardian.pin_ack()
            actual_named=vault.named_directory
            reached=[]
            def late(path,witness,private=False):
                actual_named(path,witness,private=private)
                reached.append(path)
                if len(reached)==2:
                    remaining=(guardian.deadline_ns-30*10**9-time.monotonic_ns())/10**9
                    self.assertGreater(remaining,0)
                    time.sleep(remaining+0.05)
            try:
                with patch.object(vault,"named_directory",side_effect=late),self.assertRaises(ValueError):
                    guardian.verify_output(30*10**9)
                self.assertEqual(reached,[run,run])
                self.assertGreaterEqual(time.monotonic_ns(),guardian.deadline_ns-30*10**9)
                self.assertEqual(json.loads((run/"resident-vault-metadata.json").read_bytes()),self.metadata_output())
                self.assertTrue((run/vault.ACK_NAME).is_file())
            finally:guardian.failed=True


    def test_actual_final_ack_body_read_metadata_drift_refuses_and_drains_both_original_fds(self):
        for mutation in ("bytes","mode","link","replace","unlink"):
            with self.subTest(mutation=mutation),self.held_output() as (guardian,environment,run):
                producer=vault.MetadataOutput.consume(environment)
                try:producer.publish(self.metadata_output());terminal=producer.terminal_frame()
                finally:producer.close()
                receiver=vault.MetadataTerminalReceiver(environment)
                try:
                    receiver.feed(vault.TERMINAL_PREFIX+vault.output_wire(terminal).encode("ascii")+b"\n")
                    receiver.finish(0)
                finally:receiver.close()
                guardian.pin_ack()
                original_ack=guardian.ack_snapshot[1]
                actual_read=os.pread
                reached=[]
                def last(descriptor,size,offset):
                    raw=actual_read(descriptor,size,offset)
                    if descriptor==guardian.ack_fd:
                        reached.append(descriptor)
                        if len(reached)==2:
                            output=run/"resident-vault-metadata.json"
                            if mutation=="bytes":
                                with output.open("r+b") as stream:stream.write(b"x")
                            elif mutation=="mode":output.chmod(0o644)
                            elif mutation=="link":os.link(output,run/"foreign-output-link")
                            elif mutation=="replace":
                                output.rename(run/"original-output")
                                output.write_bytes((run/"original-output").read_bytes());output.chmod(0o600)
                            else:output.unlink()
                    return raw
                try:
                    with patch.object(vault.os,"pread",side_effect=last),self.assertRaises((OSError,ValueError)):
                        guardian.verify_output()
                    self.assertEqual(reached,[guardian.ack_fd,guardian.ack_fd])
                    self.assertEqual((run/vault.ACK_NAME).read_bytes(),original_ack)
                    if mutation=="replace":
                        self.assertEqual((run/"resident-vault-metadata.json").read_bytes(),(run/"original-output").read_bytes())
                    if mutation=="link":self.assertTrue((run/"foreign-output-link").is_file())
                finally:
                    guardian.failed=True
                    held=(guardian.output_fd,guardian.ack_fd,guardian.fd)
                    guardian.close()
                    self.assertIsNone(guardian.output_fd)
                    self.assertIsNone(guardian.ack_fd)
                    self.assertIsNone(guardian.fd)
                    for descriptor in held:
                        with self.assertRaises(OSError):os.fstat(descriptor)

if __name__=="__main__":
    CLIENT=sys.argv.pop(1)
    unittest.main()
