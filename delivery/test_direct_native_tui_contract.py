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

class CarrierOrdinaryContract(unittest.TestCase):
    def setUp(self):
        import carrier_direct_native_tui_runtime as carrier_direct
        self.carrier=carrier_direct
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.until_ns=time.monotonic_ns()+10*10**9;self.deadline=self.until_ns/10**9
        self.aliases=self.root/'aliases';self.aliases.mkdir(mode=0o700)
        self.source=self.root/'physical';self.source.mkdir(mode=0o700)

    def held_fixture(self,*,mode=0o444,generated=False):
        path=self.source/'receipt.json';raw=b'fixture-only compact receipt'
        path.write_bytes(raw);path.chmod(mode)
        (self.aliases/'receipt').symlink_to(path)
        owner=self.carrier.HeldInputs(self.aliases,self.deadline,self.until_ns)
        self.addCleanup(owner.close)
        owner.add('receipt',path,1024,hashlib.sha256(raw).hexdigest(),len(raw),generated_control=generated)
        return owner,path,raw

    def test_actual_held_compact_read_rechecks_names_aliases_bytes_and_fd_custody(self):
        owner,path,raw=self.held_fixture()
        self.assertEqual(owner.read(path,hashlib.sha256(raw).hexdigest(),self.deadline),raw)
        owner.recheck()
        fd=owner.files[path]['fd'];owner.close()
        with self.assertRaises(OSError):os.fstat(fd)
        with self.assertRaises(ValueError):owner.raw(path)

    def test_compact_same_byte_replacement_content_and_alias_mutation_refuse(self):
        for change in ('replacement','content','alias'):
            with self.subTest(change=change):
                local=self.root/change;local.mkdir(mode=0o700)
                path=local/'receipt';raw=b'original selected bytes';path.write_bytes(raw);path.chmod(0o444)
                alias=self.aliases/change;alias.symlink_to(path)
                with self.carrier.HeldInputs(self.aliases,self.deadline,self.until_ns) as owner:
                    owner.add(change,path,1024,hashlib.sha256(raw).hexdigest(),len(raw))
                    if change=='replacement':
                        replacement=local/'replacement';replacement.write_bytes(raw);replacement.chmod(0o444)
                        replacement.replace(path)
                    elif change=='content':path.chmod(0o600);path.write_bytes(b'changed selected bytes');path.chmod(0o444)
                    else:alias.unlink();alias.symlink_to(local/'absent')
                    with self.assertRaises((ValueError,FileNotFoundError)):owner.recheck()

    def test_compact_parent_replacement_and_undeclared_read_refuse(self):
        owner,path,raw=self.held_fixture()
        with self.assertRaises(ValueError):owner.read(self.root/'undeclared','a'*64,self.deadline)
        moved=self.root/'moved';self.source.rename(moved);self.source.mkdir(mode=0o700)
        (self.source/path.name).write_bytes(raw);(self.source/path.name).chmod(0o444)
        with self.assertRaises(ValueError):owner.recheck()

    def test_generated_control_mode_is_explicit_and_original_ns_expiry_refuses(self):
        path=self.source/'control';raw=b'fixture control';path.write_bytes(raw);path.chmod(0o644)
        (self.aliases/'control').symlink_to(path)
        with self.carrier.HeldInputs(self.aliases,self.deadline,self.until_ns) as owner:
            with self.assertRaises(ValueError):owner.add('control',path,1024)
        with self.carrier.HeldInputs(self.aliases,self.deadline,self.until_ns) as owner:
            owner.add('control',path,1024,hashlib.sha256(raw).hexdigest(),len(raw),generated_control=True)
            with patch.object(self.carrier.time,'monotonic_ns',return_value=self.until_ns):
                with self.assertRaises(ValueError):owner.recheck()

    def test_carrier_genuine_guardian_refusal_precedes_archive_or_full_sdk_replay(self):
        reader=object.__new__(self.carrier.CarrierDirectReader)
        reader.pin=self.root/'pin';reader.sha='a'*64;reader.deadline=self.deadline
        reader.package={'root':'fixture-only','producer':{}};reader.owner=Mock()
        reader.owner.raw.return_value=b'fixture-only'
        with patch.object(direct,'selected_pin',return_value=reader.package), \
                patch.object(direct.material,'producer_success',side_effect=ValueError('genuine proof refuses')) as proof, \
                patch.object(direct.material,'validate_chain',side_effect=AssertionError('no SDK replay')) as chain, \
                patch.object(direct.fresh,'verify_runtime_files',side_effect=AssertionError('no archive admission')) as archive:
            with self.assertRaises(ValueError):reader.load()
        proof.assert_called_once_with(reader.package,self.carrier.TARGET,'fresh-native-runtime',
            self.deadline,declared=reader.owner)
        chain.assert_not_called();archive.assert_not_called()

    def test_actual_entry_carrier_branch_spans_fixture_and_closes_on_refusal(self):
        pin=self.root/'pin';pin.write_bytes(b'fixture-only')
        control=self.root/'control';control.write_text('a'*64+'\n')
        until=self.until_ns+30*10**9;entry_ns=until-1200*10**9
        env={'OMUX_NATIVE_ORDINARY_MODE':direct.PROFILE,
            'OMUX_NATIVE_ORDINARY_ENTRY_NS':str(entry_ns),'OMUX_NATIVE_ORDINARY_DEADLINE_NS':str(until)}
        reader=Mock()
        def fixture(**kwargs):
            self.assertIs(kwargs['runtime_reader'],reader)
            self.assertEqual(kwargs['entrypoint_args'][-1],'--carrier-v2')
            self.assertEqual(sys.argv[1:],['fixture-positional'])
            reader.close.assert_not_called()
            raise ValueError('fixture refusal')
        with patch.object(sys,'argv',['fixture','--direct-pin='+str(pin),
                '--direct-pin-sha-file='+str(control),'--carrier-v2','fixture-positional']), \
                patch.dict(os.environ,env,clear=True), \
                patch.object(self.carrier,'CarrierDirectReader',return_value=reader) as constructor, \
                patch.object(entry,'declared_child_environment',return_value={}), \
                patch.object(tui,'main',side_effect=fixture):
            with self.assertRaises(ValueError):entry.main()
        constructor.assert_called_once_with(pin,'a'*64,self.deadline,entry_ns=entry_ns,original_deadline_ns=until)
        reader.close.assert_called_once_with()

    def test_carrier_mode_requires_existing_original_clock_before_any_native_io(self):
        with patch.object(sys,'argv',['fixture','--direct-pin=/not-read',
                '--direct-pin-sha-file=/not-read','--carrier-v2']),patch.dict(os.environ,{},clear=True), \
                patch.object(direct.retained,'public_runtime_file',side_effect=AssertionError('no pin IO')) as read:
            with self.assertRaises(ValueError):entry.main()
        read.assert_not_called()

    def test_actual_success_waits_for_real_final_held_leaf_join_and_owned_close(self):
        for mutation in ('content','replacement'):
            with self.subTest(mutation=mutation):
                local=self.root/mutation;local.mkdir(mode=0o700)
                path=local/'selected';raw=b'original compact bytes';path.write_bytes(raw);path.chmod(0o444)
                alias=self.aliases/mutation;alias.symlink_to(path)
                owner=self.carrier.HeldInputs(self.aliases,self.deadline,self.until_ns)
                owner.add(mutation,path,1024,hashlib.sha256(raw).hexdigest(),len(raw))
                fd=owner.files[path]['fd']
                reader=object.__new__(self.carrier.CarrierDirectReader);reader.owner=owner
                # Only genuine guardian/archive/NAR construction is a seam;
                # actual finish, captured FDs/bytes/names and cleanup are real.
                reader.load=owner.recheck
                pin=self.root/'pin';pin.write_bytes(b'fixture-only')
                control=self.root/'control';control.write_text('a'*64+'\n')
                until=self.until_ns+30*10**9;entry_ns=until-1200*10**9
                env={'OMUX_NATIVE_ORDINARY_MODE':direct.PROFILE,
                    'OMUX_NATIVE_ORDINARY_ENTRY_NS':str(entry_ns),'OMUX_NATIVE_ORDINARY_DEADLINE_NS':str(until)}
                def fixture(**kwargs):
                    if mutation=='content':path.chmod(0o600);path.write_bytes(b'changed compact bytes');path.chmod(0o444)
                    else:
                        replacement=local/'replacement';replacement.write_bytes(raw);replacement.chmod(0o444)
                        replacement.replace(path)
                    return 0
                with patch.object(sys,'argv',['fixture','--direct-pin='+str(pin),
                        '--direct-pin-sha-file='+str(control),'--carrier-v2']), \
                        patch.dict(os.environ,env,clear=True), \
                        patch.object(self.carrier,'CarrierDirectReader',return_value=reader), \
                        patch.object(entry,'declared_child_environment',return_value={}), \
                        patch.object(tui,'main',side_effect=fixture):
                    with self.assertRaises(ValueError):entry.main()
                self.assertTrue(owner.closed)
                with self.assertRaises(OSError):os.fstat(fd)

    def test_runtime_inventory_witness_survives_later_compact_readback(self):
        reader=object.__new__(self.carrier.CarrierDirectReader);reader.deadline=self.deadline;reader.owner=Mock()
        path=self.source/'library';path.write_bytes(b'fixture library')
        info=path.lstat();witness=(info.st_dev,info.st_ino,info.st_mode,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
        desc={'schemaVersion':1,'root':'fixture-only-no-NAR-authority','nodes':[]}
        with patch.object(direct.process,'descriptor',return_value=(desc,[])):
            reader.final_closure([(desc,[(path,witness)])])
            replacement=self.source/'new';replacement.write_bytes(path.read_bytes());replacement.replace(path)
            with self.assertRaises(ValueError):reader.final_closure([(desc,[(path,witness)])])

    def test_actual_declared_target_excludes_sdk_data_and_retains_original_clock(self):
        import ast
        build=ast.parse((Path(__file__).parent/'BUILD.bazel').read_text())
        calls={node.value.keywords[0].value.value:node.value for node in build.body
            if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call)
            and isinstance(node.value.func,ast.Name) and node.value.func.id=='python_test'
            and node.value.keywords and node.value.keywords[0].arg=='name'}
        new={kw.arg:kw.value for kw in calls['installed_carrier_native_tui_test'].keywords}
        old={kw.arg:kw.value for kw in calls['installed_direct_native_tui_test'].keywords}
        data=ast.literal_eval(new['data']);args=ast.literal_eval(new['args'])
        self.assertNotIn('//tools:codex_direct_native_tui_support_data',data)
        self.assertFalse(any('sdk_carrier_acquired' in label or 'sdk_carrier_inputs' in label for label in data))
        self.assertEqual(new['srcs'].id,'_CARRIER_DIRECT_ORDINARY_TUI_SOURCES')
        self.assertIn('--carrier-v2',args);self.assertNotIn('--carrier-v2',ast.literal_eval(old['args']))
        self.assertEqual(ast.literal_eval(new['env_inherit']),['OMUX_NATIVE_ORDINARY_MODE',
            'OMUX_NATIVE_ORDINARY_ENTRY_NS','OMUX_NATIVE_ORDINARY_DEADLINE_NS'])
        self.assertIn('//tools:codex_direct_native_tui_support_data',ast.literal_eval(old['data']))
        for name in ('direct_native_tui_contract_test','carrier_direct_native_tui_contract_test'):
            model={kw.arg:kw.value for kw in calls[name].keywords}
            self.assertIn('//tools:direct_native_tui_inputs.bzl',ast.literal_eval(model['data']))

    def test_runtime_alias_mutated_during_last_inventory_pass_is_refused(self):
        reader=object.__new__(self.carrier.CarrierDirectReader);reader.owner=Mock();reader.deadline=self.deadline
        alias=self.aliases/'runtime-library';physical=self.source/'library';physical.write_bytes(b'fixture library')
        alias.symlink_to(physical)
        reader.closure_parents={};reader.closure_witnesses={alias:reader.path_witness(alias)}
        desc={'schemaVersion':1,'root':'fixture-only-NAR-seam','nodes':[]}
        def last_inventory(*args):
            alias.unlink();alias.symlink_to(physical)
            return desc,[]
        with patch.object(direct.process,'descriptor',side_effect=last_inventory):
            reader.final_closure([(desc,[])])
        with self.assertRaises(ValueError):reader.closure_alias_fence()

    def test_final_runtime_alias_fence_refuses_late_same_target_replacement(self):
        reader=object.__new__(self.carrier.CarrierDirectReader);reader.owner=Mock()
        alias=self.aliases/'runtime-library';physical=self.source/'library';physical.write_bytes(b'fixture library')
        alias.symlink_to(physical)
        reader.closure_parents={};reader.closure_witnesses={alias:reader.path_witness(alias)}
        reader.closure_alias_fence()
        alias.unlink();alias.symlink_to(physical)
        with self.assertRaises(ValueError):reader.closure_alias_fence()

    def test_carrier_closure_requires_exact_declared_root_aliases(self):
        reader=object.__new__(self.carrier.CarrierDirectReader);reader.pin=self.aliases/'input-pin.json';reader.owner=Mock()
        root='/nix/store/'+'0'*32+'-fixture-only'
        reader.owner.raw.return_value=b'{}'
        with self.assertRaises(ValueError):reader.closure_aliases({'registration_rows':[{'path':root}]})
        with self.assertRaises(ValueError):reader.closure_aliases({'registration_rows':[{'path':'/not/nix'}]})

class RuntimeDeclarationModels(unittest.TestCase):
    def setUp(self):
        import direct_native_runtime_closure_inputs as scanner
        self.scanner=scanner;self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.tree=self.root/'immutable-fixture';self.tree.mkdir(mode=0o700)
        until=time.monotonic_ns()+40*10**9;self.clock=scanner.Clock(until-1200*10**9,until)

    def scan_fixture(self):
        # Only Nix-root/UID0 ancestor admission is a seam. Streaming dirents,
        # nofollow stat/open/link reads, bounds and physical joins are actual IO.
        import re
        anchor=self.scanner.Anchor
        def fixture_anchor(path,clock,**kwargs):return anchor(path,clock,immutable=False)
        with patch.object(self.scanner,'OWNER',os.getuid()), \
                patch.object(self.scanner,'STORE',re.compile(re.escape(str(self.tree)))), \
                patch.object(self.scanner,'Anchor',side_effect=fixture_anchor):
            return self.scanner.scan([str(self.tree)],self.clock)

    def test_real_streaming_inventory_never_reads_symbolic_external_target(self):
        file=self.tree/'library';file.write_bytes(b'fixture library');file.chmod(0o444)
        outside=self.root/'outside';outside.write_bytes(b'not declared authority');outside.chmod(0o600)
        (self.tree/'inert-link').symlink_to(outside)
        self.tree.chmod(0o555)
        actual_open=os.open
        with patch.object(self.scanner.os,'open',wraps=actual_open) as opened:
            result=self.scan_fixture()
        self.assertEqual(result['members'],[{'alias':'runtime-closure/root-0/library','path':str(file)}])
        self.assertFalse(any(str(call.args[0])==str(outside) for call in opened.call_args_list))
        self.assertEqual(result['original_entry_monotonic_ns'],self.clock.entry)
        self.assertEqual(result['original_deadline_monotonic_ns'],self.clock.until)

    def test_global_node_limit_refuses_stream_before_sort_or_later_stat(self):
        for name in ('a','b','c'):
            file=self.tree/name;file.write_bytes(b'fixture');file.chmod(0o444)
        self.tree.chmod(0o555);actual_stat=os.stat
        with patch.object(self.scanner,'MAX_NODES',2), \
                patch.object(self.scanner.os,'stat',wraps=actual_stat) as inspected, \
                patch.object(self.scanner,'sorted',create=True,side_effect=AssertionError('must reject before sorting')):
            with self.assertRaises(ValueError):self.scan_fixture()
        leaf_stats=[call.args[0] for call in inspected.call_args_list if call.args and call.args[0] in ('a','b','c')]
        self.assertEqual(len(leaf_stats),2) # initial before/after for only first streamed entry

    def test_byte_and_metadata_bounds_refuse_before_retaining_inventory(self):
        file=self.tree/'library';file.write_bytes(b'four');file.chmod(0o444);self.tree.chmod(0o555)
        for constant,value in (('MAX_BYTES',3),('MAX_DOCUMENT',1)):
            with self.subTest(bound=constant),patch.object(self.scanner,constant,value):
                with self.assertRaises(ValueError):self.scan_fixture()

    def test_special_and_writable_nodes_refuse_without_external_reads(self):
        file=self.tree/'writable';file.write_bytes(b'fixture');file.chmod(0o600)
        with self.assertRaises(ValueError):self.scan_fixture()
        file.unlink();os.mkfifo(self.tree/'fifo',mode=0o444)
        with self.assertRaises(ValueError):self.scan_fixture()

    def test_every_regular_and_symbolic_node_joins_actual_depth128_boundary(self):
        for kind in ('regular','symlink'):
            for depth in (128,129):
                with self.subTest(kind=kind,depth=depth):
                    self.tree=self.root/(kind+str(depth));self.tree.mkdir(mode=0o700)
                    parent=self.tree;directories=[parent]
                    for _ in range(depth-1):
                        parent=parent/'d';parent.mkdir(mode=0o700);directories.append(parent)
                    leaf=parent/'leaf'
                    if kind=='regular':leaf.write_bytes(b'fixture');leaf.chmod(0o444)
                    else:leaf.symlink_to('/not-followed-external-target')
                    for directory in reversed(directories):directory.chmod(0o555)
                    if depth==128:
                        result=self.scan_fixture()
                        self.assertEqual(len(result['members']),1 if kind=='regular' else 0)
                    else:
                        with self.assertRaises(ValueError):self.scan_fixture()

    def test_streamed_directory_depth_refuses_before_stat_and_retention_sort(self):
        import builtins
        parent=self.tree;directories=[parent]
        for name in ('a','b','blocked'):
            parent=parent/name;parent.mkdir(mode=0o700);directories.append(parent)
        for directory in reversed(directories):directory.chmod(0o555)
        actual_stat=os.stat
        with patch.object(self.scanner,'MAX_DEPTH',2), \
                patch.object(self.scanner.os,'stat',wraps=actual_stat) as inspected, \
                patch.object(self.scanner,'sorted',create=True,wraps=builtins.sorted) as ordered:
            with self.assertRaises(ValueError):self.scan_fixture()
        self.assertFalse(any(call.args and call.args[0]=='blocked' for call in inspected.call_args_list))
        self.assertFalse(any(any(row[0]=='blocked' for row in call.args[0])
            for call in ordered.call_args_list))

    def test_actual_parent_name_swap_and_expiry_refuse_and_close(self):
        with self.scanner.Anchor(self.tree,self.clock) as held:
            fd=held.fd;old=self.root/'old';self.tree.rename(old);self.tree.mkdir(mode=0o700)
            with self.assertRaises(ValueError):held.check()
        with self.assertRaises(OSError):os.fstat(fd)
        with patch.object(self.scanner.time,'monotonic_ns',return_value=self.clock.work):
            with self.assertRaises(ValueError):self.clock.tick()

    def test_actual_rule_declares_scanner_tool_and_original_repository_clock(self):
        import ast
        source=(Path(__file__).parent.parent/'tools/direct_native_tui_inputs.bzl').read_text()
        tree=ast.parse(source)
        rule=next(node.value for node in tree.body if isinstance(node,ast.Assign)
            and any(isinstance(target,ast.Name) and target.id=='ordinary_direct_native_inputs' for target in node.targets))
        keywords={kw.arg:kw.value for kw in rule.keywords}
        self.assertEqual(keywords['environ'].id,'_ENV')
        self.assertTrue(ast.literal_eval(keywords['local']))
        attrs=keywords['attrs'];labels={key.value:value for key,value in zip(attrs.keys,attrs.values)}
        self.assertEqual(labels['_scanner'].keywords[0].value.args[0].value,
            '//tools:direct_native_runtime_closure_inputs.py')
        self.assertEqual(labels['_python'].keywords[0].value.args[0].value,
            '@omux_nix//:tool_wrappers/python')
        self.assertNotIn('.readdir(',source);self.assertNotIn('.watch_tree(',source)
        executes=[node for node in ast.walk(tree) if isinstance(node,ast.Call)
            and isinstance(node.func,ast.Attribute) and node.func.attr=='execute']
        self.assertEqual(len(executes),1)
        self.assertEqual({kw.arg:kw.value for kw in executes[0].keywords}['environment'].id,'environment')

    def publication_functions(self):
        # Executes only the exact four Python-compatible declaration functions
        # inside the Bazel model. No repository fetch, SDK or native authority.
        import ast
        from types import SimpleNamespace
        path=Path(__file__).parent.parent/'tools/direct_native_tui_inputs.bzl'
        tree=ast.parse(path.read_text())
        names={'_path','_store_root','_runtime_mapping','_publish_runtime'}
        module=ast.Module(body=[node for node in tree.body
            if isinstance(node,ast.FunctionDef) and node.name in names],type_ignores=[])
        def kind(value):
            return {str:'string',dict:'dict',list:'list',int:'int',bool:'bool'}.get(type(value),'unknown')
        def refusal(reason):raise ValueError(reason)
        environment={'json':SimpleNamespace(decode=json.loads),'type':kind,'fail':refusal}
        exec(compile(ast.fix_missing_locations(module),str(path),'exec'),environment)
        return environment

    def captured_document(self):
        root='/nix/store/'+'0'*32+'-fixture'
        return {'schema_version':1,'kind':'omux-direct-carrier-runtime-closure-inputs-v1',
            'roots':[root],'members':[{'alias':'runtime-closure/root-0/library','path':root+'/library'}],
            'original_entry_monotonic_ns':self.clock.entry,'original_deadline_monotonic_ns':self.clock.until}

    def test_actual_captured_publication_ignores_same_size_replaced_disk_map(self):
        from types import SimpleNamespace
        functions=self.publication_functions();document=self.captured_document()
        raw=json.dumps(document,sort_keys=True,separators=(',',':'))+'\n'
        replaced=raw.replace('library','foreign');self.assertEqual(len(raw),len(replaced))
        output=self.root/'runtime-closure-inputs.json';output.write_text(replaced)
        def publish(name,value,**kwargs):
            self.assertEqual(name,output.name);self.assertEqual(kwargs,{'executable':False})
            (self.root/name).write_text(value)
        ctx=SimpleNamespace(file=Mock(side_effect=publish),path=lambda value:value,symlink=Mock(),
            read=Mock(side_effect=AssertionError('no independent map reread')))
        aliases=functions['_publish_runtime'](ctx,raw,self.clock.entry,self.clock.until)
        self.assertEqual(output.read_text(),raw);self.assertNotEqual(output.read_text(),replaced)
        self.assertEqual(aliases,['runtime-closure/root-0/library'])
        ctx.read.assert_not_called();ctx.symlink.assert_called_once_with(document['roots'][0],'runtime-closure/root-0')

    def test_captured_map_role_depth_context_refusals_precede_publication(self):
        from types import SimpleNamespace
        functions=self.publication_functions();base=self.captured_document()
        mutations=[]
        for change in ('context','root','traversal','duplicate','depth','extra'):
            document=json.loads(json.dumps(base))
            if change=='context':document['original_entry_monotonic_ns']+=1
            elif change=='root':document['roots']=['/not/nix/store']
            elif change=='traversal':document['members'][0]['path']=base['roots'][0]+'/../library'
            elif change=='duplicate':document['members'].append(dict(document['members'][0]))
            elif change=='depth':
                relative='/'.join(['d']*128+['leaf'])
                document['members'][0]={'alias':'runtime-closure/root-0/'+relative,'path':base['roots'][0]+'/'+relative}
            else:document['members'][0]['extra']='refused'
            mutations.append((change,document))
        for change,document in mutations:
            with self.subTest(change=change):
                ctx=SimpleNamespace(file=Mock(),path=Mock(),symlink=Mock())
                with self.assertRaises(ValueError):functions['_publish_runtime'](ctx,json.dumps(document),self.clock.entry,self.clock.until)
                ctx.file.assert_not_called();ctx.path.assert_not_called();ctx.symlink.assert_not_called()

    def test_actual_scanner_main_emits_only_captured_bounded_map(self):
        import io
        import re
        from types import SimpleNamespace
        leaf=self.tree/'library';leaf.write_bytes(b'fixture');leaf.chmod(0o444);self.tree.chmod(0o555)
        registration=self.root/'registration-receipt.json'
        registration.write_text(json.dumps({'registration_rows':[{'path':str(self.tree),'narSize':64}]}))
        registration.chmod(0o444);capture=io.BytesIO();anchor=self.scanner.Anchor
        def fixture_anchor(path,clock,**kwargs):return anchor(path,clock,immutable=False)
        env={'OMUX_NATIVE_ORDINARY_MODE':self.scanner.MODE,'OMUX_NATIVE_ORDINARY_ENTRY_NS':str(self.clock.entry),
             'OMUX_NATIVE_ORDINARY_DEADLINE_NS':str(self.clock.until)}
        with patch.object(self.scanner,'OWNER',os.getuid()), \
                patch.object(self.scanner,'STORE',re.compile(re.escape(str(self.tree)))), \
                patch.object(self.scanner,'PUBLIC',re.compile(re.escape(str(registration)))), \
                patch.object(self.scanner,'Anchor',side_effect=fixture_anchor), \
                patch.dict(os.environ,env,clear=True), \
                patch.object(sys,'argv',['scanner','--registration',str(registration)]), \
                patch.object(sys,'stdout',SimpleNamespace(buffer=capture)):
            self.scanner.main()
        raw=capture.getvalue();self.assertLessEqual(len(raw),self.scanner.MAX_DOCUMENT)
        document=json.loads(raw);self.assertEqual(document['roots'],[str(self.tree)])
        self.assertEqual(document['members'],[{'alias':'runtime-closure/root-0/library','path':str(leaf)}])
        self.assertEqual(document['original_entry_monotonic_ns'],self.clock.entry)
        self.assertEqual(document['original_deadline_monotonic_ns'],self.clock.until)
        self.assertNotIn('sha256',document) # no detached digest or helper-output reread

    def test_original_repository_clock_has_no_absent_or_renewed_fallback(self):
        values={'OMUX_NATIVE_ORDINARY_MODE':self.scanner.MODE,
            'OMUX_NATIVE_ORDINARY_ENTRY_NS':str(self.clock.entry),
            'OMUX_NATIVE_ORDINARY_DEADLINE_NS':str(self.clock.until)}
        self.assertEqual(self.scanner.envelope(values).work,self.clock.work)
        for changed in ({}, {**values,'OMUX_NATIVE_ORDINARY_MODE':'other'},
                {**values,'OMUX_NATIVE_ORDINARY_DEADLINE_NS':str(self.clock.until+1)}):
            with self.assertRaises(ValueError):self.scanner.envelope(changed)

if __name__=='__main__':unittest.main()
