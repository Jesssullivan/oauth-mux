"""Actual new cohort/envelope/refusal wiring; no SDK or native qualification."""
from pathlib import Path
import hashlib
import json
import os
import stat
import tempfile
import uuid
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import execution_guard as guard
import guard_native_seed_plan_reserved as kernel
import guard_native_siwc_catalog_content_source_reserved as model
import guard_native_file_writer_models_reserved as old
import guard_native_siwc_catalog_source_reserved as historical
import guard_native_siwc_content_delivery as delivery


class CatalogContentReservationTests(unittest.TestCase):
    def args(self):
        return SimpleNamespace(profile=model.PROFILE, manager='system', reuse_owned_cache=False,
            source_commit='a'*40, source_dirty='false', repository_cache=None, nixpkgs_source=None)

    def test_only_exact_catalog_content_cohort_not_old_source_login19_or_native_children(self):
        self.assertTrue(model.request(self.args(), model.ARGUMENTS))
        for arguments in (old.ARGUMENTS, historical.ARGUMENTS, model.ARGUMENTS[:-1], list(reversed(model.ARGUMENTS)),
                model.ARGUMENTS + ['//:docs_check'], ['test','//codex-rs/core:core-unit-tests']):
            with self.assertRaises(ValueError): model.request(self.args(), arguments)
        with self.assertRaises(ValueError): old.selected(old.PROFILE, model.ARGUMENTS)
        self.assertNotIn(model.PROFILE, old.PROFILES)
        self.assertNotIn(model.PROFILE, historical.PROFILES)
        with self.assertRaises(ValueError): historical.selected(historical.PROFILE, model.ARGUMENTS)
        self.assertEqual(old.ARGUMENTS, ['test','//tools:codex_native_file_writer_model_source_test',
            '//tools:codex_native_file_writer_models_producer'])

    def test_original_actual_graph_clock_forwarded_to_repo_and_test_without_new_budget(self):
        entry, deadline = 100*10**9, 1300*10**9
        run = Path('/home/jess/.local/state/omux-execution-20261005/12345678-1234-1234-1234-123456789abc')
        with patch.object(kernel.time, 'monotonic_ns', return_value=200*10**9):
            command = model.command(guard.bazel_command, 'bazel', run, model.ARGUMENTS,
                model.PROFILE, entry, deadline, graph_sha256='b'*64, source_commit='a'*40, source_dirty='false')
            self.assertEqual(model.runtime_seconds(entry, deadline), 840)
        values = {model.MODE:model.INPUT_MODE, model.ENTRY:str(entry), model.DEADLINE:str(deadline),
            model.EPOCH:str(run), model.SOURCE:'a'*40, model.GRAPH:'b'*64}
        for key, value in values.items():
            for kind in ('repo_env','test_env'):
                self.assertEqual([v for v in command if v.startswith('--'+kind+'='+key+'=')], ['--'+kind+'='+key+'='+value])
        self.assertIn('--test_timeout=840', command)
        self.assertIn('--repository_disable_download', command)
        self.assertEqual(command[-2:], model.ARGUMENTS[1:])
        self.assertNotEqual(model.INPUT_MODE, model.PROFILE)
        self.assertEqual(model.INPUT_MODE, old.PROFILE)
        self.assertEqual(model.MEMORY, old.MEMORY); self.assertEqual(model.TASKS, old.TASKS)
        self.assertEqual(model.CPU, old.CPU)

    def test_expired_dirty_cache_reuse_and_foreign_epoch_refuse_before_builder(self):
        for name, value in (('source_dirty','true'),('reuse_owned_cache','true'),('manager','user')):
            args = self.args(); setattr(args,name,value)
            with self.assertRaises(ValueError): model.request(args,model.ARGUMENTS)
        builder = Mock()
        with patch.object(kernel.time,'monotonic_ns',return_value=1300*10**9):
            with self.assertRaises(ValueError): model.command(builder,'bazel',Path('/foreign/epoch'),model.ARGUMENTS,
                model.PROFILE,100*10**9,1300*10**9,graph_sha256='b'*64,source_commit='a'*40,source_dirty='false')
        builder.assert_not_called()
        with patch.object(kernel.time,'monotonic_ns',return_value=200*10**9):
            with self.assertRaises(ValueError): model.command(builder,'bazel',Path('/foreign/epoch'),model.ARGUMENTS,
                model.PROFILE,100*10**9,1300*10**9,graph_sha256='b'*64,source_commit='a'*40,source_dirty='false')
        builder.assert_not_called()

    def test_coordinator_dispatch_rejects_wrong_vector_before_tool_reads_and_claims_stay_false(self):
        with patch.object(guard,'immutable',side_effect=AssertionError('tool read')) as tool:
            with self.assertRaises(ValueError): guard.main(['--profile',model.PROFILE,'--manager','system',
                '--source-commit','a'*40,'--source-dirty','false','--',*old.ARGUMENTS])
        tool.assert_not_called()
        report = model.projection(100*10**9,1300*10**9,None,None)
        self.assertEqual(report['scope'],'fixed-native-siwc-catalog-content-source-reserved-v1')
        self.assertFalse(report['native20_qualified_by_admission'])
        self.assertTrue(all(value is False for name,value in report.items() if name.endswith('_qualified')))



class ContentDependencyAndDeliveryTests(unittest.TestCase):
    """Real small-FS owner/receipt faults; no SDK or SOURCE acceptance mirrors."""
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.parent=Path(self.temp.name).resolve()
        self.state=self.parent/'state'; self.state.mkdir(mode=0o700)
        self.checkout=self.parent/'checkout'; self.checkout.mkdir(mode=0o700)
        self.entry,self.until=1000*10**9,2200*10**9
        self.clock=1200*10**9
        self.key='a'*64
        self.current=model.time.monotonic_ns
        self.addCleanup(patch.stopall)
        patch.object(model.time,'monotonic_ns',side_effect=lambda:self.clock).start()
        patch.object(kernel.resident,'PUBLIC_ROOTS',(self.state,)).start()
        # Same explicit seam as guard_cache small-FS models: production still
        # validates every actual system ancestor; the Bazel temp ancestor is not
        # asserted as operator state authority by this fixture.
        patch.object(model.cache,'trusted_directory',side_effect=lambda path:
            os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)).start()
        self.run=self.state/str(uuid.uuid4()); self.run.mkdir(mode=0o700)
        self.lease=None

    def tearDown(self):
        if self.lease is not None: self.lease.close()

    def acquire(self,run=None):
        lease=model.ContentDependencyLease(self.state,self.key,(run or self.run).name,
            checkout=self.checkout,source_commit='b'*40,graph_sha256='c'*64,
            entry=self.entry,deadline=self.until)
        lease.__enter__(); self.lease=lease; return lease

    def receipt(self,failed=True):
        result={'id':self.run.name,'profile':model.PROFILE,'source_commit':'b'*40,'graph_sha256':'c'*64,
            'cache_key':self.key,'cache_policy':2,'cache_reuse_requested':True,
            'exit':125 if failed else 0,'workload_exit':3 if failed else 0,'descendants_empty':True,
            'cleanup':{'state':'empty','ownership':'verified','readback_attempts':2},
            'test_evidence':{'state':'preserved'},'source_phase_receipt':None,
            'native_siwc_content_delivery':None,'native_siwc_content_publication':None}
        if not failed:
            result.update(source_phase_receipt={'sha256':'d'*64},native_siwc_content_publication={'kind':'transport'},
                native_siwc_content_delivery={'exit':0})
        result['native_siwc_content_dependency_disposition']=self.lease.disposition(result)
        raw=delivery.encoded(result); path=self.run/'receipt.json'; path.write_bytes(raw); path.chmod(0o600)
        return result,hashlib.sha256(raw).hexdigest()

    def test_cold_failed_source_only_reuses_dependencies_not_source_or_delivery(self):
        lease=self.acquire(); lease.prepare_capture()
        self.clock=self.entry+650*10**9  # SOURCE600 expired; dependency work1170 remains.
        receipt,pin=self.receipt(); lease.complete(True,pin)
        facts=lease.facts(); self.assertEqual(facts['run_id'],self.run.name)
        marker=model.cache.read_marker(lease.directory)
        self.assertTrue(marker['clean']); self.assertEqual(marker['cleanup_receipt_sha256'],pin)
        self.assertFalse(receipt['native_siwc_content_dependency_disposition']['source_qualified_by_disposition'])
        self.assertIsNone(receipt['native_siwc_content_publication'])
        lease.close(); self.lease=None
        later=self.state/str(uuid.uuid4()); later.mkdir(mode=0o700)
        self.clock=self.entry+100*10**9
        second=self.acquire(later)
        self.assertEqual(second.output_base,Path(facts['output_base']))
        self.assertEqual(model.cache.read_marker(second.directory)['last_run'],later.name)
        self.assertFalse(model.cache.read_marker(second.directory)['clean'])
        self.assertFalse((later/'source-phase-receipt.json').exists())
        self.assertFalse((later/'native-content-delivery-request.json').exists())

    def test_failed_source_never_creates_success_checkpoint_or_delivery_request(self):
        lease=self.acquire(); lease.prepare_capture()
        source={'exit':3,'workload_exit':3,'targets':model.ARGUMENTS[1:],'profile':model.PROFILE}
        with self.assertRaises(ValueError): delivery.source_checkpoint(self.run,lease,source,self.entry,self.until)
        self.assertFalse((self.run/'source-phase-receipt.json').exists())
        self.assertFalse((self.run/'native-content-delivery-request.json').exists())

    def test_unknown_cleanup_cannot_mark_dependency_state_clean(self):
        lease=self.acquire(); lease.prepare_capture(); result,pin=self.receipt()
        result['cleanup']['ownership']='unproved'
        raw=delivery.encoded(result); (self.run/'receipt.json').write_bytes(raw)
        with self.assertRaises(ValueError): lease.complete(True,hashlib.sha256(raw).hexdigest())
        self.assertFalse(model.cache.read_marker(lease.directory)['clean'])

    def test_wrong_failure_receipt_digest_context_or_fake_product_fields_refuse(self):
        lease=self.acquire(); lease.prepare_capture(); result,pin=self.receipt()
        with self.assertRaises(ValueError): lease.complete(True,'0'*64)
        for key,value in (('graph_sha256','f'*64),('native_siwc_content_publication',{'kind':'forged'}),
                ('source_phase_receipt',{'sha256':'d'*64})):
            changed=dict(result); changed[key]=value
            raw=delivery.encoded(changed); (self.run/'receipt.json').write_bytes(raw)
            with self.assertRaises(ValueError): lease.complete(True,hashlib.sha256(raw).hexdigest())
            self.assertFalse(model.cache.read_marker(lease.directory)['clean'])

    def test_dirty_cache_and_stale_source_test_outputs_do_not_bootstrap(self):
        lease=self.acquire()
        stale=lease.output_base/'stale-source'; stale.write_bytes(b'unqualified')
        lease.close(); self.lease=None
        later=self.state/str(uuid.uuid4()); later.mkdir(mode=0o700)
        with self.assertRaises(ValueError): self.acquire(later)
        self.assertEqual(stale.read_bytes(),b'unqualified')
        self.assertFalse((later/'source-phase-receipt.json').exists())

    def test_marker_replacement_during_marker_io_refuses_final_joint_fence(self):
        lease=self.acquire(); original=model.cache.read_marker
        def read(directory):
            value=original(directory)
            path=self.state/lease.name/'owner.json'
            raw=path.read_bytes(); path.unlink(); path.write_bytes(raw); path.chmod(0o600)
            return value
        with patch.object(model.cache,'read_marker',side_effect=read):
            with self.assertRaises(ValueError): lease.fence()

    def test_named_cache_root_checkout_and_lock_substitution_refuse(self):
        for change in ('checkout','lock','base'):
            with self.subTest(change=change):
                lease=self.acquire()
                if change=='checkout':
                    self.checkout.rename(self.parent/'aside'); self.checkout.mkdir(mode=0o700)
                elif change=='lock':
                    path=self.state/lease.name/'cache.lock'; path.unlink(); path.touch(mode=0o600)
                else:
                    lease.output_base.rename(lease.output_base.parent/'aside'); lease.output_base.mkdir(mode=0o700)
                with self.assertRaises(ValueError): lease.fence()
                lease.close(); self.lease=None
                # A separate fresh cache namespace prevents a refusal being
                # accidentally erased or promoted by the next subcase.
                self.key=hashlib.sha256((self.key+change).encode()).hexdigest()
                if change=='checkout':
                    self.checkout.rmdir(); (self.parent/'aside').rename(self.checkout)

    def test_all_detached_descriptors_attempted_after_interrupting_close(self):
        lease=self.acquire()
        expected=[lease.marker_fd,lease.base_fd,lease.checkout_fd,lease.state_fd,lease.lock,lease.directory]
        real=os.close; observed=[]
        def close(fd):
            observed.append(fd); real(fd)
            if fd==expected[0]: raise KeyboardInterrupt('synthetic-close-interruption')
        with patch.object(model.os,'close',side_effect=close):
            with self.assertRaises(KeyboardInterrupt): lease.close()
        self.assertEqual(observed,expected)
        self.assertFalse(lease.active)
        self.assertTrue(all(getattr(lease,key) is None for key in ('marker_fd','base_fd','checkout_fd','state_fd','lock','directory')))
        with self.assertRaises(ValueError): lease.facts()

    def test_capture_expiry_and_source_command_cannot_extend_source600(self):
        lease=self.acquire()
        self.clock=self.entry+600*10**9
        with self.assertRaises(ValueError): lease.fence()
        lease.prepare_capture()  # delivery/dependency custody only.
        with patch.object(Path,'cwd',return_value=self.checkout):
            with self.assertRaises(ValueError): model.command(guard.bazel_command,'bazel',self.run,model.ARGUMENTS,
                model.PROFILE,self.entry,self.until,graph_sha256='c'*64,source_commit='b'*40,source_dirty='false',dependency_lease=lease)
        self.clock=self.until-30*10**9
        with self.assertRaises(ValueError): lease.fence()
        with self.assertRaises(ValueError): model.delivery_seconds(self.entry,self.until)

    def test_cache_source_argv_retains_all_fresh_values_and_disallows_raw_override(self):
        lease=self.acquire()
        with patch.object(Path,'cwd',return_value=self.checkout):
            command=model.command(guard.bazel_command,'bazel',self.run,model.ARGUMENTS,model.PROFILE,
                self.entry,self.until,graph_sha256='c'*64,source_commit='b'*40,source_dirty='false',dependency_lease=lease)
            with self.assertRaises(ValueError): model.command(guard.bazel_command,'bazel',self.run,model.ARGUMENTS,
                model.PROFILE,self.entry,self.until,graph_sha256='c'*64,source_commit='b'*40,source_dirty='false',
                dependency_lease=lease,output_base=self.parent/'foreign')
        self.assertIn('--output_base='+str(lease.output_base),command)
        for key,value in {model.MODE:model.INPUT_MODE,model.ENTRY:str(self.entry),model.DEADLINE:str(self.until),
                model.EPOCH:str(self.run),model.SOURCE:'b'*40,model.GRAPH:'c'*64}.items():
            for kind in ('repo_env','test_env'):
                self.assertEqual(command.count('--'+kind+'='+key+'='+value),1)
        self.assertIn('--nocache_test_results',command)
        self.assertIn('--remote_executor=',command)

    def test_stable_key_excludes_epoch_but_partitions_checkout_and_immutable_tools(self):
        profile={'content_dependency_scope':model.DEPENDENCY_SCOPE,'targets':model.ARGUMENTS}
        inputs={'python':'/nix/store/aaaa-python'}
        first=model.cache.stable_fingerprint(self.checkout,inputs,os.getuid(),os.getgid(),'system',profile)
        second=model.cache.stable_fingerprint(self.checkout,dict(inputs),os.getuid(),os.getgid(),'system',dict(profile))
        self.assertEqual(first,second)
        other=self.parent/'other'; other.mkdir(mode=0o700)
        self.assertNotEqual(first,model.cache.stable_fingerprint(other,inputs,os.getuid(),os.getgid(),'system',profile))
        self.assertNotEqual(first,model.cache.stable_fingerprint(self.checkout,{'python':'/nix/store/bbbb-python'},
            os.getuid(),os.getgid(),'system',profile))

    def test_delivery_timeout_captured_once_and_fresh_unit_not_source_unit(self):
        sample=self.until-30*10**9-50*10**9
        self.clock=sample
        seconds=model.delivery_seconds(self.entry,self.until,sample_ns=sample)
        self.assertEqual(seconds,50)
        self.clock+=2*10**9
        command,values=model.delivery_command(guard.bazel_command,'bazel',self.run,self.entry,self.until,'d'*64,
            source_commit='b'*40,graph_sha256='c'*64,seconds=seconds,sample_ns=sample)
        self.assertIn('--test_timeout=50',command)
        self.assertIn('--output_base='+str(self.run/'delivery-output-base'),command)
        self.assertIn('--output_user_root='+str(self.run/'delivery-user-root'),command)
        self.assertEqual(values[model.EPOCH],str(self.run))
        self.assertEqual(values[model.ENTRY],str(self.entry))
        identifier,unit=model.delivery_identity(self.run)
        self.assertNotEqual(identifier,self.run.name)
        self.assertEqual(identifier,str(uuid.uuid5(uuid.UUID(self.run.name),'omux-native-siwc-content-delivery-v1')))
        self.assertNotEqual(unit,'omux-execution-'+self.run.name+'.service')
        with self.assertRaises(ValueError): model.delivery_command(guard.bazel_command,'bazel',self.run,self.entry,self.until,'d'*64,
            source_commit='b'*40,graph_sha256='c'*64,seconds=51,sample_ns=sample)

    def test_actual_metadata_read_detects_named_replacement_and_original_cutoff(self):
        path=self.run/'metadata.json'; path.write_bytes(b'{"kind":"test"}'); path.chmod(0o600)
        real=os.read; changed=False
        def read(fd,count):
            nonlocal changed
            block=real(fd,count)
            if block and not changed:
                changed=True; path.unlink(); path.write_bytes(b'{"kind":"test"}'); path.chmod(0o600)
            return block
        with patch.object(delivery.os,'read',side_effect=read):
            with self.assertRaises(ValueError): delivery.read_metadata(path,entry=self.entry,until=self.until)
        self.clock=self.until-30*10**9
        with self.assertRaises(ValueError): delivery.read_metadata(path,entry=self.entry,until=self.until)

    def test_actual_metadata_writer_flush_and_close_expiry_never_report_success(self):
        real=os.fsync
        def expire(fd):
            real(fd); self.clock=self.until-30*10**9
        with patch.object(delivery.os,'fsync',side_effect=expire):
            with self.assertRaises(ValueError): delivery.write_metadata(self.run,'late.json',{'kind':'test'},0o400,self.entry,self.until)
        self.assertTrue((self.run/'late.json').exists())  # refused bytes are not erased or promoted.


    def source_phase(self):
        manifest={'results':[{'target':target,'configuration':'k8-fastbuild','state':'observed',
            'files':[{'source':name,'state':'copied'} for name in ('test.log','test.xml')]}
            for target in model.ARGUMENTS[1:]]}
        raw=delivery.encoded(manifest); (self.run/'test-evidence.json').write_bytes(raw)
        (self.run/'test-evidence.json').chmod(0o600)
        return {'id':self.run.name,'profile':model.PROFILE,'targets':model.ARGUMENTS[1:],
            'exit':0,'workload_exit':0,'source_commit':'b'*40,'graph_sha256':'c'*64,
            'epoch_start_ns':1,'command':['fixed-source-argv'],'limits':{},'worker':{},
            'descendants_empty':True,'cleanup':{'state':'empty','stop':'succeeded','ownership':'verified',
                'readback_attempts':2,'pre_stop':{},'post_stop':{}},
            'test_evidence':{'state':'preserved','sha256':hashlib.sha256(raw).hexdigest()},
            'native_siwc_catalog_content_source_reservation':{'verified_after_cleanup':True}}

    def dispatch_boundary(self,source,*,fault):
        # Manager/kernel seams are explicit synthetic fixtures. The actual
        # execute_delivery code, real lease, request, checkpoint and filesystem
        # run normally. These tests never assert live process ownership or SDK.
        lease=self.lease; _,unit=model.delivery_identity(self.run); trace=[]; actual={}
        class Pin:
            def __init__(self,path): self.path=path; trace.append('pin-open')
            def observe(self): return 'empty'
            def close(self): trace.append('pin-close')
        class Worker:
            def __init__(self,profile,entry,until,pin,value,pid,ticks):
                self.invocation='d'*32; self.bounds={'memory.max':str(model.MEMORY),'memory.swap.max':'0',
                    'pids.max':str(model.TASKS),'cpu.max':'190000 100000','memory.oom.group':'1'}
                trace.append(('worker',profile,entry,until,pid,ticks))
            def authorize_cleanup(self,value): trace.append('authorize')
            def close(self): trace.append('worker-close')
        def call(parts,**kwargs):
            trace.append((kwargs['operation'],list(parts)))
            if kwargs['operation']=='launch':
                for part in parts:
                    if part.startswith('--property='):
                        key,value=part[len('--property='):].split('=',1); actual[key]=value
                actual.update(Id='foreign.service' if fault=='startup' else unit,ActiveState='active',
                    ControlGroup='/synthetic/'+unit,MainPID='123',ExecMainPID='123',InvocationID='d'*32,
                    Environment='TOOL=/nix/store/aaaa-tool')
            return dict(actual)
        api=SimpleNamespace(__file__=guard.__file__,PROPERTIES=guard.PROPERTIES,DELEGATION_ENV=guard.DELEGATION_ENV,
            CLEANUP_SECONDS=guard.CLEANUP_SECONDS,CONTROLLER_TIMEOUT=guard.CONTROLLER_TIMEOUT,
            bazel_command=guard.bazel_command,system_masks=guard.system_masks,properties=lambda value:value,
            await_startup=lambda read:(read(),[]),CgroupPin=Pin,process_start_ticks=lambda pid:'100',
            verify=lambda value,path,manager,isolation,profile,runtime_seconds: trace.append(('runtime',runtime_seconds)),
            unit_epoch_identity=lambda *args,**kwargs: trace.append(('identity',kwargs['unit'])),
            system_identity=lambda *args:None,check_free_space=lambda path:None,
            capture_cleanup_pin=lambda *args,**kwargs:None,authorize_cleanup=lambda *args,**kwargs:None)
        def monitor(*args):
            trace.append('monitor')
            if fault=='monitor': raise ValueError('synthetic-monitor-refusal')
            return 0
        summary={'state':'unproved' if fault in ('startup','cleanup') else 'empty',
            'ownership':'unproved' if fault=='startup' else 'verified','readback_attempts':2,'stop':'succeeded',
            'pre_stop':{},'post_stop':{}}
        def cleanup(**kwargs): trace.append('cleanup'); return dict(summary)
        real_read=Path.read_text
        with (patch.object(model,'WorkloadWitness',Worker),patch.object(model,'monitor',side_effect=monitor),
                patch.object(model,'cleanup_retained',side_effect=cleanup),patch.object(Path,'read_text',
                new=lambda path,*args,**kwargs:'0::/synthetic-supervisor' if path==Path('/proc/self/cgroup')
                    else real_read(path,*args,**kwargs))):
            with self.assertRaises(delivery.DeliveryRefused) as refusal:
                delivery.execute_delivery(api,call=call,run=self.run,lease=lease,source=source,
                    resident=SimpleNamespace(observe=lambda **kwargs:trace.append('resident')),
                    entry=self.entry,until=self.until,bazel='bazel',python='/nix/store/aaaa-python',
                    runner='/nix/store/aaaa-systemd-run',control='/nix/store/aaaa-systemctl',
                    environment={'TOOL':'/nix/store/aaaa-tool'},isolation={},repository_cache=None,nixpkgs_source=None)
        return refusal.exception,trace

    def test_actual_delivery_startup_refusal_preserves_association_and_not_source_empty(self):
        lease=self.acquire(); lease.prepare_capture()
        refusal,trace=self.dispatch_boundary(self.source_phase(),fault='startup')
        value=refusal.observation
        self.assertTrue(value['started']); self.assertEqual(value['phase'],'startup')
        self.assertEqual(value['unit'],model.delivery_identity(self.run)[1])
        self.assertFalse(delivery.aggregate_empty(True,value))
        self.assertEqual(value['cleanup']['state'],'unproved')
        self.assertEqual(value['exit'],125)
        self.assertNotIn('monitor',trace)
        self.assertFalse(model.cache.read_marker(lease.directory)['clean'])
        self.assertEqual(json.loads((self.run/'source-phase-receipt.json').read_bytes())['exit'],0)
        self.assertFalse((self.run/'native-content-retained/publication-receipt.json').exists())

    def test_actual_monitor_refusal_attempts_cleanup_and_closes_before_refused_return(self):
        lease=self.acquire(); lease.prepare_capture()
        refusal,trace=self.dispatch_boundary(self.source_phase(),fault='monitor')
        value=refusal.observation
        self.assertEqual(value['phase'],'monitor'); self.assertEqual(value['exit'],125)
        self.assertEqual(value['worker']['unit'],value['unit'])
        self.assertIn('cleanup',trace)
        self.assertLess(trace.index('cleanup'),trace.index('worker-close'))
        self.assertLess(trace.index('worker-close'),trace.index('pin-close'))
        self.assertTrue(delivery.aggregate_empty(True,value))  # independently verified delivery empty, never success.
        self.assertFalse(delivery.aggregate_empty(False,value))
        self.assertEqual(value['test_evidence']['state'],'not-preserved')
        self.assertFalse(model.cache.read_marker(lease.directory)['clean'])

    def test_actual_cleanup_refusal_cannot_inherit_source_empty_or_clean_cache(self):
        lease=self.acquire(); lease.prepare_capture()
        refusal,trace=self.dispatch_boundary(self.source_phase(),fault='cleanup')
        value=refusal.observation
        self.assertEqual(value['workload_exit'],0)
        self.assertFalse(delivery.aggregate_empty(True,value))
        self.assertEqual(value['exit'],125)
        self.assertIn('worker-close',trace); self.assertIn('pin-close',trace)
        self.assertFalse(model.cache.read_marker(lease.directory)['clean'])

    def test_source_unproved_empty_blocks_actual_second_dispatch_before_handoff(self):
        lease=self.acquire(); lease.prepare_capture(); source=self.source_phase()
        source['cleanup']['ownership']='unproved'
        call=Mock()
        with self.assertRaises(ValueError):
            delivery.execute_delivery(SimpleNamespace(),call=call,run=self.run,lease=lease,source=source,
                resident=SimpleNamespace(),entry=self.entry,until=self.until,bazel='bazel',python='python',runner='run',
                control='ctl',environment={},isolation={},repository_cache=None,nixpkgs_source=None)
        call.assert_not_called()
        self.assertFalse((self.run/'native-content-delivery-request.json').exists())


    def actual_resident_observations(self):
        path=self.parent/'resident-fixture'; path.mkdir(mode=0o700)
        rows={'memory.max':str(kernel.resident.RESIDENT_MEMORY),'memory.swap.max':'0',
            'pids.max':str(kernel.resident.RESIDENT_TASKS),'cpu.max':'10000 100000',
            'cgroup.procs':str(os.getpid()),'cgroup.events':'populated 1','pids.current':'1'}
        for name,value in rows.items(): (path/name).write_text(value)
        directory=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        pidfd=os.pidfd_open(os.getpid(),0)
        self.addCleanup(os.close,pidfd); self.addCleanup(os.close,directory)
        owner=kernel.Witness.__new__(kernel.Witness)
        owner.entry,owner.deadline=self.entry,self.until
        owner.directory=directory; owner.chain=[(path,directory,kernel.resident.stable(os.fstat(directory)))]
        owner.identity=owner.chain[0][2]; owner.bounds=None; owner.samples=0
        owner.processes=[(os.getpid(),pidfd,kernel.process(os.getpid()))]
        first=owner.observe(); second=owner.observe()
        return owner,path,first,second

    def test_real_resident_observe_advances_counts_without_equal_projection_fabrication(self):
        owner,path,first,second=self.actual_resident_observations()
        self.assertEqual((first['observations'],second['observations']),(1,2))
        model.resident_continuity(first,second)
        initial=model.projection(self.entry,self.until,True,first)
        final=model.projection(self.entry,self.until,True,second)
        self.assertNotEqual(initial,final)
        self.assertEqual(initial['resident']['observations'],1)
        self.assertEqual(final['resident']['observations'],2)

    def test_real_resident_changed_bounds_or_retained_process_predicate_refuses(self):
        owner,path,first,second=self.actual_resident_observations()
        (path/'cpu.max').write_text('20000 100000')
        with self.assertRaises(ValueError): owner.observe()
        changed=dict(second); changed['initial_direct_processes_retained']=False
        with self.assertRaises(ValueError): model.resident_continuity(first,changed)
        changed=dict(second); changed['observations']=0
        with self.assertRaises(ValueError): model.resident_continuity(first,changed)


    def test_actual_three_metadata_bodies_preserve_first_io_error_after_cutoff(self):
        container=self.run/'native-content-retained'; container.mkdir(mode=0o700)
        publication=container/'publication-receipt.json'; publication.write_bytes(b'{}'); publication.chmod(0o444)
        container.chmod(0o555)
        self.addCleanup(container.chmod,0o700)
        path=self.run/'body-error.json'; path.write_bytes(b'{}'); path.chmod(0o600)
        real_open,real_close=os.open,os.close
        for kind in ('read','write','publication'):
            with self.subTest(kind=kind):
                self.clock=self.entry+100*10**9
                opened=[]; closed=[]; primary=OSError(5,'synthetic-metadata-body-io')
                def open_fd(*args,**kwargs):
                    fd=real_open(*args,**kwargs); opened.append(fd); return fd
                def close_fd(fd): closed.append(fd); return real_close(fd)
                def fail(*args,**kwargs):
                    self.clock=self.until-30*10**9; raise primary
                with (patch.object(delivery.os,'open',side_effect=open_fd),
                        patch.object(delivery.os,'close',side_effect=close_fd),
                        patch.object(delivery.os,'write' if kind=='write' else 'read',side_effect=fail)):
                    with self.assertRaises(OSError) as refused:
                        if kind=='read': delivery.read_metadata(path,entry=self.entry,until=self.until)
                        elif kind=='write': delivery.write_metadata(self.run,'writer-body-error.json',
                            {'kind':'test'},0o400,self.entry,self.until)
                        else: delivery.publication_descriptor(self.run,None,{},self.entry,self.until)
                self.assertIs(refused.exception,primary)
                self.assertEqual(closed,list(reversed(opened)))
                self.assertEqual(len(opened),3 if kind=='publication' else 2)

    def test_actual_body_plus_close_failure_and_expiry_keeps_body_with_secondary_cause(self):
        path=self.run/'body-and-close.json'; path.write_bytes(b'{}'); path.chmod(0o600)
        primary=OSError(5,'synthetic-body-failure'); secondary=OSError(28,'synthetic-close-failure')
        real_open,real_close=os.open,os.close; opened=[]; closed=[]
        def open_fd(*args,**kwargs):
            fd=real_open(*args,**kwargs); opened.append(fd); return fd
        def fail_read(*args,**kwargs): raise primary
        def close_fd(fd):
            closed.append(fd); real_close(fd)
            self.clock=self.until-30*10**9
            if len(closed)==1: raise secondary
        with (patch.object(delivery.os,'open',side_effect=open_fd),
                patch.object(delivery.os,'read',side_effect=fail_read),
                patch.object(delivery.os,'close',side_effect=close_fd)):
            with self.assertRaises(OSError) as refused:
                delivery.read_metadata(path,entry=self.entry,until=self.until)
        self.assertIs(refused.exception,primary)
        self.assertIs(refused.exception.__cause__,secondary)
        self.assertEqual(closed,list(reversed(opened)))
        self.assertEqual(len(opened),2)

    def test_actual_successful_metadata_body_still_refuses_post_close_expiry(self):
        path=self.run/'successful-body-late-close.json'; path.write_bytes(b'{"kind":"test"}'); path.chmod(0o600)
        real_open,real_close=os.open,os.close; opened=[]; closed=[]
        def open_fd(*args,**kwargs):
            fd=real_open(*args,**kwargs); opened.append(fd); return fd
        def close_fd(fd):
            closed.append(fd); real_close(fd); self.clock=self.until-30*10**9
        with (patch.object(delivery.os,'open',side_effect=open_fd),
                patch.object(delivery.os,'close',side_effect=close_fd)):
            with self.assertRaises(ValueError): delivery.read_metadata(path,entry=self.entry,until=self.until)
        self.assertEqual(closed,list(reversed(opened)))
        self.assertEqual(len(opened),2)


    def test_actual_receipt_run_rename_during_read_or_close_refuses_detached_role(self):
        real_read,real_close=os.read,os.close
        for phase in ('read','close'):
            with self.subTest(phase=phase):
                self.key=hashlib.sha256((self.key+phase).encode()).hexdigest()
                self.run=self.state/str(uuid.uuid4()); self.run.mkdir(mode=0o700)
                lease=self.acquire(); lease.prepare_capture(); result,pin=self.receipt()
                aside=self.state/(self.run.name+'-aside'); changed=False
                def replace():
                    nonlocal changed
                    if not changed:
                        changed=True; self.run.rename(aside); self.run.mkdir(mode=0o700)
                        (self.run/'receipt.json').write_bytes((aside/'receipt.json').read_bytes())
                        (self.run/'receipt.json').chmod(0o600)
                def read(fd,count):
                    block=real_read(fd,count)
                    if phase=='read' and block: replace()
                    return block
                def close(fd):
                    real_close(fd)
                    if phase=='close': replace()
                with patch.object(model.os,'read',side_effect=read),patch.object(model.os,'close',side_effect=close):
                    with self.assertRaises(ValueError): lease._receipt(self.run.name,pin)
                self.assertEqual((aside/'receipt.json').read_bytes(),(self.run/'receipt.json').read_bytes())
                self.assertFalse(model.cache.read_marker(lease.directory)['clean'])
                lease.close(); self.lease=None

    def test_actual_metadata_parent_replacement_during_read_or_close_refuses(self):
        real_read,real_close=os.read,os.close
        for phase in ('read','close'):
            with self.subTest(phase=phase):
                parent=self.run/phase; parent.mkdir(mode=0o700)
                path=parent/'metadata.json'; path.write_bytes(b'{"kind":"test"}'); path.chmod(0o600)
                aside=self.run/(phase+'-aside'); changed=False
                def replace():
                    nonlocal changed
                    if not changed:
                        changed=True; parent.rename(aside); parent.mkdir(mode=0o700)
                        path.write_bytes(b'{"kind":"test"}'); path.chmod(0o600)
                def read(fd,count):
                    block=real_read(fd,count)
                    if phase=='read' and block: replace()
                    return block
                def close(fd):
                    real_close(fd)
                    if phase=='close': replace()
                with patch.object(delivery.os,'read',side_effect=read),patch.object(delivery.os,'close',side_effect=close):
                    with self.assertRaises(ValueError): delivery.read_metadata(path,entry=self.entry,until=self.until)
                self.assertEqual((aside/'metadata.json').read_bytes(),path.read_bytes())


    def test_actual_metadata_enrollment_failure_before_or_after_insert_closes_every_open_once(self):
        container=self.run/'native-content-retained'; container.mkdir(mode=0o700)
        publication=container/'publication-receipt.json'; publication.write_bytes(b'{}'); publication.chmod(0o444)
        container.chmod(0o555); self.addCleanup(container.chmod,0o700)
        path=self.run/'registration-read.json'; path.write_bytes(b'{}'); path.chmod(0o600)
        real_open,real_close=os.open,os.close; base_owners=delivery.Owned
        for kind,slots in (('read',2),('write',2),('publication',3)):
            for slot in range(1,slots+1):
                for inserted in (False,True):
                    with self.subTest(kind=kind,slot=slot,inserted=inserted):
                        primary=MemoryError('synthetic-registration-failure')
                        opened=[]; closed=[]; registries=[]
                        class FaultOwners(base_owners):
                            def __init__(self): super().__init__(); self.calls=0; registries.append(self)
                            def append(self,fd):
                                self.calls+=1
                                if self.calls==slot:
                                    if inserted: super().append(fd)
                                    raise primary
                                super().append(fd)
                        def open_fd(*args,**kwargs):
                            fd=real_open(*args,**kwargs); opened.append(fd); return fd
                        def close_fd(fd): closed.append(fd); return real_close(fd)
                        with (patch.object(delivery,'Owned',FaultOwners),
                                patch.object(delivery.os,'open',side_effect=open_fd),
                                patch.object(delivery.os,'close',side_effect=close_fd)):
                            with self.assertRaises(MemoryError) as refused:
                                if kind=='read': delivery.read_metadata(path,entry=self.entry,until=self.until)
                                elif kind=='write': delivery.write_metadata(self.run,
                                    'registration-write-'+str(slot)+'-'+str(inserted)+'.json',
                                    {'kind':'test'},0o400,self.entry,self.until)
                                else: delivery.publication_descriptor(self.run,None,{},self.entry,self.until)
                        self.assertIs(refused.exception,primary)
                        self.assertEqual(len(opened),slot)
                        self.assertEqual(closed,list(reversed(opened)))
                        self.assertEqual(len(closed),len(set(closed)))
                        self.assertTrue(all(not owner for owner in registries))

    def test_uninserted_close_error_preserves_allocation_primary_and_drains_prior_owners(self):
        path=self.run/'registration-close-error.json'; path.write_bytes(b'{}'); path.chmod(0o600)
        primary=MemoryError('synthetic-uninserted-registration')
        secondary=OSError(5,'synthetic-uninserted-close')
        real_open,real_close=os.open,os.close; opened=[]; closed=[]; registries=[]
        base_owners=delivery.Owned
        class FaultOwners(base_owners):
            def __init__(self): super().__init__(); self.calls=0; registries.append(self)
            def append(self,fd):
                self.calls+=1
                if self.calls==2: raise primary
                super().append(fd)
        def open_fd(*args,**kwargs):
            fd=real_open(*args,**kwargs); opened.append(fd); return fd
        def close_fd(fd):
            closed.append(fd); real_close(fd)
            if len(closed)==1: raise secondary
        with (patch.object(delivery,'Owned',FaultOwners),
                patch.object(delivery.os,'open',side_effect=open_fd),
                patch.object(delivery.os,'close',side_effect=close_fd)):
            with self.assertRaises(MemoryError) as refused:
                delivery.read_metadata(path,entry=self.entry,until=self.until)
        self.assertIs(refused.exception,primary)
        self.assertIs(refused.exception.__cause__,secondary)
        self.assertEqual(closed,list(reversed(opened)))
        self.assertEqual(len(closed),2)
        self.assertTrue(all(not owner for owner in registries))


if __name__ == '__main__': unittest.main()
