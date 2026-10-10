"""Owned component fixtures, imported by the existing reserved model cohort."""
import os
import hashlib
import io
from pathlib import Path
import select
import signal
import tempfile
import time
import unittest
from unittest.mock import patch
import codex_native_acquisition_process as process
import codex_native_acquisition_runtime_qualification as runtime

class ProcessTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.deadline=time.monotonic()+10
    def registered(self):
        image=os.open('/proc/self/exe',os.O_RDONLY|os.O_CLOEXEC)
        loader=os.open('/dev/null',os.O_RDONLY|os.O_CLOEXEC)
        result=process.RegisteredImage(image,process.identity(image),loader,process.identity(loader),{},
            self.deadline,lambda:None)
        self.addCleanup(result.close);return result
    def context(self):
        keys=('HOME','XDG_RUNTIME_DIR','XDG_CACHE_HOME','XDG_CONFIG_HOME','XDG_STATE_HOME')
        result={}
        for index,key in enumerate(keys):
            p=self.root/str(index);p.mkdir(mode=0o700);result[key]=str(p)
        return result
    def test_unset_registration_does_not_select_or_launch(self):
        with patch.object(process,'register',side_effect=AssertionError('no selected inputs')):
            with self.assertRaises(ValueError):runtime.registration()
    def test_registered_image_repeats_retained_authority_and_original_deadline(self):
        image=self.registered();calls=[];image.revalidate=lambda:calls.append(1)
        image.check();self.assertEqual(calls,[1])
        with patch.object(process.compilation,'tick',side_effect=ValueError('expired')):
            with self.assertRaises(ValueError):image.check()
        self.assertEqual(calls,[1])
    def test_direct_child_real_fork_waits_once_preserves_nonzero(self):
        image=self.registered();child=process.OwnedChild(image);self.addCleanup(child.close)
        # Real fork/pidfd/GO/wait ownership, with the exec seam returning exit7.
        # This is an ownership fixture and never claims a native candidate run.
        with patch.object(os,'execve',side_effect=lambda *args:os._exit(7)):
            child.launch(('codex','app-server'),self.root/'private')
        self.assertTrue(select.select([child.pidfd],[],[],2)[0])
        self.assertEqual(child.reap(),7);self.assertEqual(child.reap(),7)
        child.close();self.assertIsNone(child.pidfd)
    def test_live_owned_child_cleanup_signals_original_pidfd(self):
        image=self.registered();child=process.OwnedChild(image);self.addCleanup(child.close)
        def wait(*args):
            while True:signal.pause()
        with patch.object(os,'execve',side_effect=wait):
            child.launch(('codex','app-server'),self.root/'private')
        child.close();self.assertTrue(child.reaped)
        self.assertEqual(child.status,-signal.SIGKILL);child.close()
    def test_unreviewed_argv_and_inherited_environment_refuse_before_fork(self):
        child=process.OwnedChild(self.registered())
        with patch.object(os,'fork',side_effect=AssertionError('no fork')):
            with self.assertRaises(ValueError):child.launch(('codex','resume','arbitrary'),self.root/'private')
            with self.assertRaises(ValueError):child.launch(('codex','app-server'),self.root)
    def test_pre_go_failure_closes_pipe_and_reaps_exact_unlaunched_child(self):
        child=process.OwnedChild(self.registered());self.addCleanup(child.close)
        with patch.object(os,'pidfd_open',side_effect=OSError('pidfd unavailable')):
            with self.assertRaises(OSError):child.launch(('codex','app-server'),self.root/'private')
        self.assertTrue(child.reaped);self.assertEqual(child.status,125)
    def test_child_fence_rejects_process_start_drift_before_native_peer(self):
        child=process.OwnedChild(self.registered());child.pid=123;child.pidfd=99;child.start=5
        class Peer:
            def fence_child(self,fd):raise AssertionError('no native peer after drift')
        with patch.object(process.select,'select',return_value=([],[],[])),\
             patch.object(process,'process_start',return_value=6):
            with self.assertRaises(ValueError):child.fence(Peer())
    def test_nar_hash_encoding_and_wrong_closure_refuse(self):
        self.assertEqual(process.nar_hex('sha256:'+'0'*51+'1'),'01'+'00'*31)
        with self.assertRaises(ValueError):process.nar_hex('sha256:'+'z'*52)
        with patch.object(process,'descriptor',side_effect=AssertionError('no unselected store read')):
            with self.assertRaises(ValueError):process.verify_closure({'schema_version':1},'/nix/store/x/ld',self.deadline)
    def test_actual_canonical_nar_fixture_requires_exact_full_bytes(self):
        root='/nix/store/'+'0'*32+'-fixture';loader=root+'/ld';raw=b'fixture-loader'
        descriptor={'schemaVersion':1,'root':root,'nodes':[{'path':'','type':'directory'},
            {'path':'ld','type':'regular','size':len(raw),'executable':True}]}
        actual_hash=process.nar.hash_descriptor
        def hash_bytes(desc,deadline):
            return actual_hash(desc,opener=lambda root,path:io.BytesIO(raw),deadline=deadline)
        value=hash_bytes(descriptor,self.deadline)
        proof={'schema_version':1,'status':'registered-linux-nix-runtime-closure-proof-candidate',
            'native_support':False,'loader_lookup_qualified':False,'target':'x86_64-linux',
            'original_interpreter':loader,'roots':[{'path':root}],
            'registration_rows':[{'path':root,'narHash':value['narHash'],
                'narSize':value['narSize'],'references':[]}],
            'files':[{'path':loader,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}],
            'aliases':[]}
        with patch.object(process,'descriptor',return_value=(descriptor,[])),\
             patch.object(process.nar,'hash_descriptor',side_effect=hash_bytes),\
             patch.object(process.compilation,'read_bytes',return_value=raw):
            selected,_=process.verify_closure(proof,loader,self.deadline)
            self.assertEqual(selected['path'],loader)
            proof['registration_rows'][0]['narHash']='sha256:'+'f'*64
            with self.assertRaises(ValueError):process.verify_closure(proof,loader,self.deadline)
    def test_closure_missing_reference_refuses_before_nar_read(self):
        root='/nix/store/'+'0'*32+'-fixture'
        proof={'schema_version':1,'status':'registered-linux-nix-runtime-closure-proof-candidate',
            'native_support':False,'loader_lookup_qualified':False,'target':'x86_64-linux',
            'original_interpreter':root+'/ld','roots':[{'path':root}],
            'registration_rows':[{'path':root,'narHash':'sha256:'+'0'*64,'narSize':1,
                'references':[root+'-missing']}]}
        with patch.object(process,'descriptor',side_effect=AssertionError('no incomplete closure read')):
            with self.assertRaises(ValueError):process.verify_closure(proof,root+'/ld',self.deadline)
    def test_owned_acquisition_brackets_authenticated_fd_parser(self):
        calls=[]
        class Registered:deadline=self.deadline
        class Child:
            registered=Registered()
            def fence(self,peer):calls.append('fence')
        with patch.object(runtime,'receive_authenticated_acquisition',side_effect=lambda *args:calls.append('fd') or {'ok':1}):
            self.assertEqual(runtime.receive_owned_acquisition(Child(),object(),object(),{},b'k',b'p',self.deadline),{'ok':1})
        self.assertEqual(calls,['fence','fd','fence'])
    def fake_admitted(self):
        child=process.OwnedChild(self.registered())
        child.pid=123;child.pidfd=os.open('/dev/null',os.O_RDONLY|os.O_CLOEXEC)
        child.go_attempted=True;child.go_released=True
        # This fixture replaces only kernel operations; it never claims pidfd
        # qualification. Real fork/pidfd models above cover the normal helper.
        def release():
            if child.pidfd is not None:os.close(child.pidfd);child.pidfd=None
        self.addCleanup(release);return child
    def test_cleanup_timeout_retains_original_fd_then_retries_same_cutoff(self):
        child=self.fake_admitted();original=child.pidfd;cutoffs=[]
        def timeout(*args):
            cutoffs.append(args[3]);return ([],[],[])
        with patch.object(process.select,'select',side_effect=timeout),\
             patch.object(process.time,'monotonic',return_value=self.deadline+1),\
             patch.object(process.signal,'pidfd_send_signal') as send:
            with self.assertRaises(ValueError):child.close()
            send.assert_called_once_with(original,signal.SIGKILL,None,0)
        self.assertEqual(child.pidfd,original);self.assertFalse(child.reaped)
        self.assertIsNotNone(child.cleanup_failure)
        self.assertEqual(child.registered.deadline,self.deadline)
        self.assertEqual(cutoffs,[0,0])
        with patch.object(process.select,'select',return_value=([original],[],[])),\
             patch.object(process.time,'monotonic',return_value=self.deadline+1),\
             patch.object(os,'waitpid',return_value=(123,7<<8)) as wait,\
             patch.object(process.signal,'pidfd_send_signal') as send:
            child.close();child.close();send.assert_not_called();wait.assert_called_once_with(123,os.WNOHANG)
        self.assertTrue(child.reaped);self.assertEqual(child.status,7)
        self.assertIsNone(child.pidfd);self.assertIsNone(child.cleanup_failure)
    def test_cleanup_interruption_retains_custody_and_no_numeric_pid_signal(self):
        child=self.fake_admitted();original=child.pidfd
        with patch.object(process.select,'select',side_effect=InterruptedError('fixture')),\
             patch.object(os,'kill',side_effect=AssertionError('no numeric PID signal')):
            with self.assertRaises(InterruptedError):child.close()
        self.assertEqual(child.pidfd,original)
        with patch.object(process.select,'select',return_value=([original],[],[])),\
             patch.object(os,'waitpid',return_value=(123,0)):
            child.close()
        self.assertTrue(child.reaped);self.assertIsNone(child.pidfd)
    def test_admitted_missing_pidfd_cannot_enter_pre_go_cleanup(self):
        child=self.fake_admitted();os.close(child.pidfd);child.pidfd=None
        with patch.object(os,'waitpid',side_effect=AssertionError('no pre-GO wait fallback')):
            with self.assertRaises(ValueError):child.close()
    def test_launch_preserves_primary_when_owned_cleanup_also_fails(self):
        image=self.registered();child=process.OwnedChild(image)
        primary=ValueError('primary-launch-fixture');cleanup=InterruptedError('cleanup-fixture')
        image.check=lambda:None
        fd=os.open('/dev/null',os.O_RDONLY|os.O_CLOEXEC)
        self.addCleanup(os.close,fd)
        with patch.object(os,'fork',return_value=123),\
             patch.object(os,'pidfd_open',return_value=fd),\
             patch.object(process,'process_start',return_value=1),\
             patch.object(image,'check',side_effect=[None,primary]),\
             patch.object(child,'close',side_effect=cleanup):
            with self.assertRaises(ValueError) as caught:
                child.launch(('codex','app-server'),self.root/'private')
        self.assertIs(caught.exception,primary);self.assertIs(child.cleanup_failure,cleanup)
        self.assertIn('native-runtime-owned-child-cleanup-incomplete',primary.__notes__)
        self.assertFalse(child.go_attempted);self.assertEqual(child.pidfd,fd)

if __name__=='__main__':unittest.main()
