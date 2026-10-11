"""Direct ordinary reader/refusal models; no successful native authority tuple."""
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import time
import unittest
from unittest.mock import Mock,patch
sys.path.insert(0,str(Path(__file__).parent.parent/'tools'))
import direct_native_tui_runtime as direct
import test_installed_direct_native_tui as entry
import test_installed_native_tui as tui

class DirectOrdinaryContract(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.deadline=time.monotonic()+10.0

    def test_pending_configuration_refuses_before_package_or_process_io(self):
        pin=self.root/'pin.json';raw=b'{"kind":"unconfigured-direct-native-tui"}\n';pin.write_bytes(raw)
        with patch.object(direct.material,'producer_success',side_effect=AssertionError('no package IO')) as producer, \
                patch.object(tui.subprocess,'Popen',side_effect=AssertionError('no child IO')) as child:
            with self.assertRaises(ValueError):direct.DirectReader(pin,hashlib.sha256(raw).hexdigest(),self.deadline)
        producer.assert_not_called();child.assert_not_called()

    def test_versioned_pin_rejects_duplicates_mismatched_digest_and_legacy_kind(self):
        for raw in (b'{"kind":"x","kind":"y"}', b'{"kind":"omux-fresh-native-runtime-v1"}',
                    b'{"schema_version":true,"kind":"omux-direct-native-tui-package-pin-v1","package":{}}'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):direct.selected_pin(raw,hashlib.sha256(raw).hexdigest())
        with self.assertRaises(ValueError):direct.selected_pin(b'{}','0'*64)

    def test_original_guardian_clock_rejects_reset_wrong_mode_and_expiry(self):
        values={'OMUX_NATIVE_ORDINARY_MODE':direct.PROFILE,'OMUX_NATIVE_ORDINARY_ENTRY_NS':str(100*10**9),
                'OMUX_NATIVE_ORDINARY_DEADLINE_NS':str(1300*10**9)}
        self.assertEqual(direct.original_deadlines(values,clock_ns=lambda:200*10**9),(1270.0,1300.0))
        for altered in ({**values,'OMUX_NATIVE_ORDINARY_MODE':'native-acquisition-runtime-qualification-reserved'},
                        {**values,'OMUX_NATIVE_ORDINARY_ENTRY_NS':'0100'},
                        {**values,'OMUX_NATIVE_ORDINARY_DEADLINE_NS':str(1400*10**9)}):
            with self.assertRaises(ValueError):direct.original_deadlines(altered,clock_ns=lambda:200*10**9)
        with self.assertRaises(ValueError):direct.original_deadlines(values,clock_ns=lambda:1270*10**9)

    def test_no_original_clock_precedes_pin_or_native_fixture(self):
        with patch.object(sys,'argv',['fixture','--direct-pin=/not-read','--direct-pin-sha-file=/not-read']), \
                patch.dict(os.environ,{},clear=True),patch.object(Path,'resolve',side_effect=lambda p,**kw:p), \
                patch.object(direct.retained,'public_runtime_file',side_effect=AssertionError('no pin IO')) as read, \
                patch.object(tui,'main',side_effect=AssertionError('no fixture')) as fixture:
            with self.assertRaises(ValueError):entry.main()
        read.assert_not_called();fixture.assert_not_called()

    def test_actual_private_environment_retains_only_declared_runfiles_and_original_clock(self):
        runfiles=self.root/'runfiles';runfiles.mkdir()
        (runfiles/'_repo_mapping').write_text('_,declared,canonical\n')
        private=self.root/'private';private.mkdir(mode=0o700)
        clock={'OMUX_NATIVE_ORDINARY_MODE':direct.PROFILE,'OMUX_NATIVE_ORDINARY_ENTRY_NS':'100',
               'OMUX_NATIVE_ORDINARY_DEADLINE_NS':'200'}
        transported=entry.declared_child_environment({**clock,'RUNFILES_DIR':str(runfiles),
            'HOME':'/not-forwarded','TOKEN':'not-forwarded','LD_PRELOAD':'not-forwarded'})
        actual=tui.private_child_environment(private,transported)
        self.assertEqual(actual['TEST_SRCDIR'],str(runfiles.resolve()))
        self.assertEqual((Path(actual['TEST_SRCDIR'])/'_repo_mapping').read_text(),'_,declared,canonical\n')
        self.assertEqual(actual['HOME'],str(private));self.assertEqual(actual['PATH'],'/nonexistent')
        self.assertNotIn('TOKEN',actual);self.assertNotIn('LD_PRELOAD',actual)
        for name,value in clock.items():self.assertEqual(actual[name],value)
        other=self.root/'other';other.mkdir()
        for invalid in ({**clock}, {**clock,'TEST_SRCDIR':'relative'},
                {**clock,'TEST_SRCDIR':str(runfiles),'RUNFILES_DIR':str(other)}):
            with self.assertRaises(ValueError):entry.declared_child_environment(invalid)
        (runfiles/'_repo_mapping').unlink()
        with self.assertRaises(ValueError):entry.declared_child_environment({**clock,'TEST_SRCDIR':str(runfiles)})

    def test_genuine_guardian_refusal_precedes_archive_and_source_admission(self):
        reader=object.__new__(direct.DirectReader);reader.pin=self.root/'pin';reader.sha='a'*64
        reader.deadline=self.deadline;reader.package={'root':'fixture-only-no-authority','producer':{}}
        with patch.object(direct.retained,'public_runtime_file',return_value=b'fixture-only'), \
                patch.object(direct,'selected_pin',return_value=reader.package), \
                patch.object(direct.material,'producer_success',side_effect=ValueError('genuine refusal')) as producer, \
                patch.object(direct.deployment,'bounded_read',side_effect=AssertionError('no archive IO')) as read, \
                patch.object(direct.fresh,'verify_runtime_files',side_effect=AssertionError('no native verifier')) as verifier:
            with self.assertRaises(ValueError):reader.load()
        producer.assert_called_once_with(reader.package,direct.deployment.TARGET,'fresh-native-runtime',self.deadline)
        read.assert_not_called();verifier.assert_not_called()

    def test_real_kernel_primary_refuses_compiler_or_loader_substitute_and_closes_fds(self):
        backend=self.root/'not-current-main';raw=b'fixture only not an executable authority';backend.write_bytes(raw);backend.chmod(0o755)
        real_close=os.close;closed=[]
        def close(fd):closed.append(fd);real_close(fd)
        with patch.object(direct.os,'close',side_effect=close):
            with self.assertRaises(ValueError):direct.mapped_primary(os.getpid(),backend,
                {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'mode':0o755},{'files':[]},self.deadline)
        self.assertEqual(len(closed),3);self.assertEqual(len(set(closed)),3)

    def test_cold_resume_store_and_accepted_prefix_invariants_remain_exact(self):
        before=(('row',),(1,2),b'digest',b'accepted original\n')
        for changed in ((("row",),(1,3),b'digest',b'accepted original\ncheckpoint\n'),
                        (("row",),(1,2),b'digest',b'rewritten\ncheckpoint\n')):
            with patch.object(tui.native_resumed_checkpoint,'validate_paginated_checkpoint') as checkpoint:
                with self.assertRaises(ValueError):tui.resumed_history(before,changed,'thread')
            checkpoint.assert_not_called()

    def test_direct_reader_cannot_enter_live_provider_fixture(self):
        reader=Mock()
        with patch.dict(os.environ,{'OMUX_ISOLATED_VAULT_PROOF':'private-bus-private-xdg'}):
            with self.assertRaises(ValueError):tui.inside(*([self.root/'not-read']*5),live=Mock(),runtime_reader=reader)
        reader.assert_not_called()

    def test_expired_original_deadline_still_reaps_actual_owned_private_leader(self):
        import subprocess
        child=subprocess.Popen([sys.executable,'-I','-B','-c','import time;time.sleep(30)'],
            start_new_session=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        with self.assertRaises(ValueError):tui.support.bounded_private_session(child,
            absolute_deadline=time.monotonic()-1.0)
        self.assertIsNotNone(child.returncode)
        self.assertTrue(child.stdout.closed and child.stderr.closed)

    def test_guardian_log_cannot_bind_extra_duplicate_or_changed_output_inventory(self):
        document={'schema_version':1,'kind':'omux-native-acquisition-package-output-v1',
            'purpose':'evaluation-only','acquisitionContract':'unsupported',
            'files':{name:{'sha256':'a'*64,'bytes':1} for name in direct.deployment.OUTPUTS}}
        raw=json.dumps(document).encode();marker=b'omux-native-package-output-sha256='+hashlib.sha256(raw).hexdigest().encode()
        for log in (marker+b'\n'+marker+b'\n',b'prefix '+marker+b'\n',
                    b'omux-native-package-output-sha256='+b'0'*64+b'\n'):
            with self.assertRaises(ValueError):direct.deployment.closed_inventory(raw,log)
        document['files']['extra']={'sha256':'a'*64,'bytes':1}
        raw=json.dumps(document).encode();marker=b'omux-native-package-output-sha256='+hashlib.sha256(raw).hexdigest().encode()+b'\n'
        with self.assertRaises(ValueError):direct.deployment.closed_inventory(raw,marker)

    def test_real_installed_closure_rejects_changed_library_ca_mode_and_foreign_file(self):
        prefix=self.root/'candidate';prefix.mkdir(mode=0o700)
        manifest={'files':{}}
        for name,raw in (('bin/codex',b'fixture launcher'),('lib/codex/libexec/codex.bin',b'fixture backend'),
                         ('lib/codex/lib/ld-linux-x86-64.so.2',b'fixture interpreter'),
                         ('lib/codex/share/ca-bundle.crt',b'fixture CA')):
            path=prefix/name;path.parent.mkdir(mode=0o700,parents=True,exist_ok=True);path.write_bytes(raw)
            mode=0o644 if name.endswith('.crt') else 0o755;path.chmod(mode)
            manifest['files'][name]={'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'mode':mode}
        for folder,_,_ in os.walk(prefix):Path(folder).chmod(0o700)
        direct.verify_installed_files(prefix,manifest,self.deadline)
        ca=prefix/'lib/codex/share/ca-bundle.crt';original=ca.read_bytes();ca.write_bytes(b'replaced CA')
        with self.assertRaises(ValueError):direct.verify_installed_files(prefix,manifest,self.deadline)
        ca.write_bytes(original);ca.chmod(0o600)
        with self.assertRaises(ValueError):direct.verify_installed_files(prefix,manifest,self.deadline)
        ca.chmod(0o644);foreign=prefix/'bin/foreign';foreign.write_bytes(b'fixture only')
        with self.assertRaises(ValueError):direct.verify_installed_files(prefix,manifest,self.deadline)
        foreign.unlink();loader=prefix/'lib/codex/lib/ld-linux-x86-64.so.2';loader.unlink();loader.symlink_to(ca)
        with self.assertRaises(ValueError):direct.verify_installed_files(prefix,manifest,self.deadline)

if __name__=='__main__':unittest.main()
