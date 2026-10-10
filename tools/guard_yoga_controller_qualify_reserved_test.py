"""Reserved prerequisite and distinct unchanged standard receipt authority."""
from pathlib import Path
from contextlib import contextmanager
import hashlib
import os
import tempfile
import copy
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import execution_guard as guard
import guard_yoga_controller_qualify_reserved as route
import yoga_delivery_settings as readonly

class PrerequisiteModels(unittest.TestCase):
    def args(self):
        return SimpleNamespace(profile=route.PROFILE,manager='system',source_commit='a'*40,
            source_dirty='false',state_dir=route.STATE,coordination_dir=route.COORDINATION)

    def test_exact_role_state_lock_and_clean_source(self):
        self.assertTrue(route.request(self.args(),route.ARGUMENTS))
        for vector in (['run','//tools:yoga_controller_verify'],['run','//tools:yoga_sealed_transfer_stage'],
            ['test','//tools:yoga_controller_qualify'],route.ARGUMENTS+['--','other']):
            with self.assertRaises(ValueError):route.selected(route.PROFILE,vector)
        for key,value in (('manager','user'),('state_dir',Path('/srv/other')),('state_dir',None),
            ('coordination_dir',Path('/srv/other')),('source_dirty','true'),('source_commit','unknown'),
            ('yoga_delivery_epoch','a'),('reuse_owned_cache',True)):
            args=self.args();setattr(args,key,value)
            with self.assertRaises(ValueError):route.request(args,route.ARGUMENTS)

    def test_real_state_preparation_reuses_only_fixed_delivery_coordination(self):
        with patch.object(guard,'private'),patch.object(guard,'check_free_space'):
            self.assertEqual(guard.prepare_state(route.STATE,route.STATE_PROFILE,route.COORDINATION,
                arguments=route.ARGUMENTS),route.COORDINATION)
            with self.assertRaises(ValueError):
                guard.prepare_state(route.STATE,'standard',route.COORDINATION,arguments=route.ARGUMENTS)

    def receipt(self):
        epoch='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';lock={'fixture':True}
        resident={'scope':'sampled-fixed-default-cgroup-kernel-reservation-v1','observations':2,
            'initial_direct_processes_retained':True,'outer_pid_namespace_matched':True,
            'hierarchical_caps':True,'resident_signalled':False,
            'kernel_bounds':{'memory.max':'268435456','memory.swap.max':'0','pids.max':'32','cpu.max':'10000 100000'}}
        count=sum(required for _,required in route.http_inputs.DECLARED)
        inputs={'scope':'fixed-yoga-controller-locked-http-snapshot-v1',
            'module_sha256':route.http_inputs.MODULE_SHA256,'lock_sha256':route.http_inputs.LOCK_SHA256,
            'declared_inputs':len(route.http_inputs.DECLARED),'copied_files':count,'copied_bytes':count,
            'missing_optional_inputs':len(route.http_inputs.DECLARED)-count,'snapshot_sha256':'e'*64,
            'verified_after_cleanup':True,'custody_released':True,'downloads_allowed':False,
            'complete_dependency_closure_proved':False}
        receipt={'id':epoch,'artifact_epoch':epoch,'source_commit':'a'*40,'source_dirty':'false',
            'exit':0,'workload_exit':0,'descendants_empty':True,'controller_failure':None,'rejection':None,
            'cleanup':{'state':'empty','ownership':'verified','readback_attempts':2},'verb':'run',
            'targets':['//tools:yoga_controller_qualify'],'profile':route.PROFILE,'manager':'system',
            'coordination_directory':str(route.COORDINATION),'coordination_lock':str(route.COORDINATION/'execution.lock'),
            'graph_sha256':'b'*64,'limits':route.properties(guard.PROPERTIES),
            'closure_manifest_sha256':readonly.NATIVE,'bootstrap_manifest_sha256':readonly.executable.BOOTSTRAP_SHA,
            'yoga_controller_http_inputs':inputs,
            'reserved_failure':None,'yoga_controller_qualify_reservation':route.projection(1,1+1200*10**9,True,resident),
            'yoga_delivery':{'source_verified_after_cleanup':True,'controller_tools':readonly.TOOLS,'mode':'qualify',
                'coordination_lock_witness':lock,'remote_owned_containment_verified':False,'copy_performed':False,
                'remote_cleanup':'unknown','qualification':{'path':'qualification.json','sha256':'c'*64}}}
        return receipt,epoch,lock

    def test_real_prior_outer_cleanup_graph_caps_and_resident_predicates(self):
        receipt,epoch,lock=self.receipt()
        self.assertEqual(route.prior_receipt(receipt,epoch,'b'*64,guard.PROPERTIES,lock,source_commit='a'*40),'c'*64)
        for mutation in (lambda r:r.update(exit=125),lambda r:r.update(workload_exit=3),
            lambda r:r.update(graph_sha256='d'*64),lambda r:r.update(source_commit='d'*40),
            lambda r:r.update(limits=guard.PROPERTIES),
            lambda r:r['cleanup'].update(readback_attempts=1),lambda r:r.update(source_dirty='true'),
            lambda r:r['yoga_controller_qualify_reservation'].update(verified_after_cleanup=False),
            lambda r:r['yoga_controller_qualify_reservation']['resident'].update(resident_signalled=True),
            lambda r:r['yoga_controller_qualify_reservation']['resident']['kernel_bounds'].update(**{'pids.max':'64'}),
            lambda r:r['yoga_delivery'].update(coordination_lock_witness={'other':True}),
            lambda r:r['yoga_controller_http_inputs'].update(verified_after_cleanup=False),
            lambda r:r['yoga_controller_http_inputs'].update(custody_released=False),
            lambda r:r['yoga_controller_http_inputs'].update(downloads_allowed=True),
            lambda r:r['yoga_controller_http_inputs'].update(module_sha256='0'*64),
            lambda r:r['yoga_controller_http_inputs'].update(snapshot_sha256='unknown'),
            lambda r:r['yoga_controller_http_inputs'].update(copied_files=True)):
            bad=copy.deepcopy(receipt);mutation(bad)
            with self.assertRaises(ValueError):route.prior_receipt(bad,epoch,'b'*64,guard.PROPERTIES,lock,source_commit='a'*40)

    def test_standard_receipt_policy_is_distinct_and_unchanged(self):
        receipt,epoch,lock=self.receipt()
        historical=dict(receipt,profile=readonly.profile.PROFILE,limits=guard.PROPERTIES)
        self.assertEqual(readonly.prior_receipt(historical,epoch,'b'*64,guard.PROPERTIES,lock),'c'*64)
        with self.assertRaises(ValueError):route.prior_receipt(historical,epoch,'b'*64,guard.PROPERTIES,lock,source_commit='a'*40)
        with self.assertRaises(ValueError):readonly.prior_receipt(receipt,epoch,'b'*64,guard.PROPERTIES,lock)

    def test_constructor_offline_flags_and_original_deadline(self):
        entry=time.monotonic_ns();deadline=entry+1200*10**9
        with patch.object(guard,'yoga_delivery_command',return_value=(['bazel','run',route.ARGUMENTS[1]],{})) as constructor:
            result=route.command(None,'bazel',Path('/fixed/run'),route.ARGUMENTS,route.PROFILE,entry,deadline,
                source_commit='a'*40,source_dirty='false',repository_cache=None,nixpkgs_source=None)
        self.assertEqual(result,['bazel','run','--repository_disable_download','--repo_contents_cache=',
            '--repository_cache=/fixed/run/yoga-controller-http-inputs',route.ARGUMENTS[1]])
        self.assertEqual(constructor.call_args.args[3],deadline)
        with self.assertRaises(ValueError):guard.bazel_command('/fixed/bazel',Path('/fixed/run'),route.ARGUMENTS)

    def test_exact_runtime_and_non_delivery_projection(self):
        route.verify_runtime('10s',10)
        for value in ('9s','11s','infinity'):
            with self.assertRaises(ValueError):route.verify_runtime(value,10)
        value=route.projection(1,1+1200*10**9,False,{'observations':1})
        self.assertFalse(value['verified_after_cleanup'])
        for key in ('copy_performed','installation_qualified','seat_qualified','toolbar_consent_proved','credential_acquisition'):
            self.assertIs(value[key],False)

    def test_real_shared_deadline_and_complete_qualified_delivery_interfaces(self):
        self.assertIs(route.CLEANUP_RESERVE_NS,readonly.CLEANUP_RESERVE_NS)
        self.assertEqual(route.CLEANUP_RESERVE_NS,15*10**9)
        for name in ('finite','tools','budget','lock_witness','finish'):
            self.assertIs(getattr(route,name),getattr(readonly,name))
        for name in ('MEMORY','TASKS','CPU','Witness','WorkloadWitness','monitor',
                'cleanup_retained','release_worker','properties','remaining'):
            self.assertIs(getattr(route,name),getattr(route.kernel,name))
        entry,deadline=100*10**9,1300*10**9
        # This is the actual shared calculation called by guard main. It has no
        # clock read or validation of its own; the existing admission owns those.
        with patch.object(guard.time,'monotonic',side_effect=AssertionError('clock-reset')):
            self.assertEqual(guard.delivery_monitor_deadline(deadline,route),1285)
            self.assertEqual(guard.delivery_monitor_deadline(deadline,readonly),1285)
        with patch.object(route.kernel.time,'monotonic_ns',return_value=entry):
            self.assertEqual(route.kernel.envelope(entry,deadline),1270*10**9)
            self.assertEqual(route.runtime_seconds(deadline),1170)
            self.assertEqual(route.remaining(entry,deadline),1170)
            self.assertEqual(route.budget(deadline,30*10**9),1170)
        with patch.object(route.kernel.time,'monotonic_ns',return_value=1270*10**9):
            with self.assertRaises(ValueError):route.runtime_seconds(deadline)
            with self.assertRaises(ValueError):route.remaining(entry,deadline)
            self.assertEqual(route.remaining(entry,deadline,cleanup=True),30)
        with patch.object(route.kernel.time,'monotonic_ns',return_value=deadline):
            with self.assertRaises(ValueError):route.remaining(entry,deadline,cleanup=True)
            with self.assertRaises(ValueError):route.budget(deadline)
        # Retain the existing kernel's exact integer/original-envelope predicates.
        for changed_entry,changed_deadline in ((True,deadline),(entry,True),(entry,deadline+1),(0,1200*10**9)):
            with self.assertRaises(ValueError):route.kernel.envelope(changed_entry,changed_deadline)

    def test_real_qualification_constructor_and_readonly_dispatch_without_launch(self):
        entry,deadline=100*10**9,1300*10**9
        with patch.object(route.kernel.time,'monotonic_ns',return_value=entry), \
                patch.object(guard,'controller_run',side_effect=AssertionError('controller-launch')):
            route.finite(route.ARGUMENTS,'system',None,())
            route.tools(dict(readonly.TOOLS),readonly.NATIVE,readonly.executable.BOOTSTRAP_SHA)
            command=route.command(None,'/fixed/bazel',Path('/fixed/run'),route.ARGUMENTS,route.PROFILE,
                entry,deadline,source_commit='a'*40,source_dirty='false')
            self.assertEqual(command[command.index('run')+1:command.index('run')+3],
                ['--repository_disable_download','--repo_contents_cache='])
            self.assertEqual(command[-1],route.ARGUMENTS[1])
            self.assertEqual(command.count('--repository_cache=/fixed/run/yoga-controller-http-inputs'),1)
            self.assertIn('--run_env=OMUX_YOGA_DELIVERY_DEADLINE_NS='+str(deadline),command)
            self.assertIn('--run_env=OMUX_YOGA_DELIVERY_MODE=qualify',command)
            self.assertIn('--run_env=OMUX_YOGA_DELIVERY_AUTHORITY_SHA256=',command)
            self.assertIn('--repo_env=OMUX_YOGA_DELIVERY_QUALIFICATION=',command)
            self.assertIn('--output_base=/fixed/run/output-base',command)
            for value in ('--remote_executor=','--remote_cache=','--lockfile_mode=error'):
                self.assertIn(value,command)
            with self.assertRaises(ValueError):route.finite(route.ARGUMENTS,'system','a'*36,())
            with self.assertRaises(ValueError):route.tools(dict(readonly.TOOLS,bazel='/other'),
                readonly.NATIVE,readonly.executable.BOOTSTRAP_SHA)
            unproved=route.finish(Path('/unused'),route.ARGUMENTS,125,True,True,deadline,{'fixture':True})
            self.assertEqual(unproved['mode'],'qualify')
            self.assertIsNone(unproved['qualification'])
            self.assertIs(unproved['copy_performed'],False)

    def test_actual_guard_qualification_caps_and_exact_runtime_readback(self):
        import tempfile
        import guard_resident_observation as resident
        caps=route.properties(guard.PROPERTIES)
        caps.update(MemoryMax=str(route.MEMORY),TasksMax=str(route.TASKS),
            CPUQuotaPerSecUSec=str(route.CPU*10000)+'us')
        self.assertEqual(route.MEMORY+resident.RESIDENT_MEMORY,4*1024**3)
        self.assertEqual(route.TASKS+resident.RESIDENT_TASKS,512)
        self.assertEqual(route.CPU+resident.RESIDENT_CPU_PERCENT,200)
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for name,value in guard.CGROUP.items():
                (root/name).write_text({'memory.max':str(route.MEMORY),'pids.max':str(route.TASKS)}.get(name,value))
            (root/'cpu.max').write_text(str(route.CPU*1000)+' 100000')
            actual={**caps,**route.selected(route.PROFILE,route.ARGUMENTS),**guard.SANDBOX,
                'PrivateNetwork':'no','RuntimeMaxUSec':'17s',
                'TemporaryFileSystem':guard.system_masks(profile='standard'),
                'UnsetEnvironment':' '.join(guard.DELEGATION_ENV)}
            isolation={**guard.SANDBOX,**route.selected(route.PROFILE,route.ARGUMENTS)}
            guard.verify(actual,root,'system',isolation,route.PROFILE,runtime_seconds=17)
            for key,value in (('MemoryMax','4294967296'),('TasksMax','512'),('CPUQuotaPerSecUSec','2s'),
                    ('RuntimeMaxUSec','16s'),('RuntimeMaxUSec','18s'),('RuntimeMaxUSec','infinity'),
                    ('PrivateNetwork','yes')):
                with self.subTest(property=key,value=value),self.assertRaises(ValueError):
                    guard.verify({**actual,key:value},root,'system',isolation,route.PROFILE,runtime_seconds=17)

    @contextmanager
    def http_fixture(self):
        http=route.http_inputs
        entry,deadline=100*10**9,1300*10**9
        with tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR']) as temporary:
            root=Path(temporary)
            source=root/'source';source.mkdir(mode=0o700)
            module,lock=b'locked-module',b'locked-module-lock'
            (source/'MODULE.bazel').write_bytes(module);(source/'MODULE.bazel.lock').write_bytes(lock)
            cache=root/'cache';payloads=cache/'content_addressable'/'sha256';payloads.mkdir(parents=True)
            rows=[]
            for payload,required,present in ((b'registry',True,True),(b'archive',False,True),(b'absent',False,False)):
                sha=hashlib.sha256(payload).hexdigest();rows.append((sha,required))
                if present:
                    parent=payloads/sha;parent.mkdir();(parent/'file').write_bytes(payload)
            run=root/'epoch';run.mkdir(mode=0o700)
            with patch.object(http,'SOURCE_ROOT',source),patch.object(http,'CACHE',cache), \
                    patch.object(http,'MODULE_SHA256',hashlib.sha256(module).hexdigest()), \
                    patch.object(http,'LOCK_SHA256',hashlib.sha256(lock).hexdigest()), \
                    patch.object(http,'DECLARED',tuple(rows)), \
                    patch.object(http,'CANONICAL_IDS',((rows[1][0],'https://fixture.example/first https://fixture.example/second'),)), \
                    patch.object(http.kernel.time,'monotonic_ns',return_value=entry):
                yield http,root,run,source,payloads,rows,entry,deadline

    def test_http_snapshot_copies_only_pinned_bytes_and_actual_derived_command(self):
        with self.http_fixture() as (http,root,run,source,payloads,rows,entry,deadline):
            unrelated=payloads/('f'*64);unrelated.mkdir();(unrelated/'file').write_bytes(b'undeclared')
            snapshot=http.Snapshot(run,entry,deadline)
            try:
                self.assertEqual(snapshot.facts()['copied_files'],2)
                self.assertEqual(snapshot.facts()['missing_optional_inputs'],1)
                self.assertFalse(snapshot.facts()['complete_dependency_closure_proved'])
                for sha,_,descriptor,before in snapshot.rows:
                    self.assertEqual(http.digest_file(descriptor,snapshot.budget,http.MAX_FILE)[0],sha)
                    self.assertEqual(before[2]&0o777,0o444)
                command=route.command(None,'/fixed/bazel',run,route.ARGUMENTS,route.PROFILE,entry,deadline,
                    source_commit='a'*40,source_dirty='false')
                self.assertEqual(command.count('--repository_cache='+str(snapshot.path)),1)
                self.assertIn('--repository_disable_download',command)
                self.assertIn('--repo_contents_cache=',command)
                self.assertNotIn(str(http.CACHE),command)
                snapshot.verify_binding({'BindReadOnlyPaths':snapshot.binding(),'BindPaths':''})
                for bad in ({'BindReadOnlyPaths':str(http.CACHE),'BindPaths':''},
                    {'BindReadOnlyPaths':snapshot.binding(),'BindPaths':'/other'},
                    {'BindReadOnlyPaths':snapshot.binding()+' /other','BindPaths':''}):
                    with self.assertRaises(ValueError):snapshot.verify_binding(bad)
                with self.assertRaises(ValueError):route.command(None,'/fixed/bazel',run,route.ARGUMENTS,
                    route.PROFILE,entry,deadline,repository_cache=http.CACHE)
                snapshot.recheck(content=True,cleanup=True)
                self.assertTrue(snapshot.facts()['verified_after_cleanup'])
                self.assertFalse(snapshot.facts()['downloads_allowed'])
            finally:snapshot.close()
            self.assertTrue(snapshot.facts()['custody_released'])

    def test_http_snapshot_missing_mismatched_linked_or_rebound_source_refuses(self):
        import os
        for mutation in ('required-missing','changed-payload','symlink-payload','hardlink-payload','source-lock'):
            with self.subTest(mutation=mutation),self.http_fixture() as fixture:
                http,root,run,source,payloads,rows,entry,deadline=fixture
                target=payloads/rows[0][0]/'file'
                if mutation=='required-missing':
                    target.unlink();target.parent.rmdir()
                elif mutation=='changed-payload':target.write_bytes(b'changed')
                elif mutation=='symlink-payload':
                    target.unlink();target.symlink_to(source/'MODULE.bazel')
                elif mutation=='hardlink-payload':os.link(target,root/'extra-link')
                else:(source/'MODULE.bazel.lock').write_bytes(b'other-lock')
                with self.assertRaises((ValueError,OSError)):http.Snapshot(run,entry,deadline)

    def test_http_snapshot_rechecks_actual_namespace_without_trusting_mode_only(self):
        for mutation in ('byte-change','extra-member','rebound-directory'):
            with self.subTest(mutation=mutation),self.http_fixture() as fixture:
                http,root,run,source,payloads,rows,entry,deadline=fixture
                snapshot=http.Snapshot(run,entry,deadline)
                try:
                    hashes=snapshot.path/'content_addressable'/'sha256';target=hashes/rows[0][0]/'file'
                    if mutation=='byte-change':
                        target.chmod(0o644);target.write_bytes(b'changed');target.chmod(0o444)
                    elif mutation=='extra-member':
                        hashes.chmod(0o755);(hashes/'undeclared').write_bytes(b'x');hashes.chmod(0o555)
                    else:
                        hashes.chmod(0o755)
                        parent=target.parent;parent.rename(hashes/'retained-old')
                        parent.mkdir(mode=0o755);(parent/'file').write_bytes(b'registry')
                        (parent/'file').chmod(0o444);parent.chmod(0o555);hashes.chmod(0o555)
                    with self.assertRaises(ValueError):snapshot.recheck(content=True)
                finally:snapshot.close()

    def test_http_snapshot_preserves_original_work_and_cleanup_deadlines(self):
        with self.http_fixture() as (http,root,run,source,payloads,rows,entry,deadline):
            snapshot=http.Snapshot(run,entry,deadline)
            try:
                with patch.object(http.kernel.time,'monotonic_ns',return_value=deadline-30*10**9):
                    with self.assertRaises(ValueError):snapshot.recheck()
                    snapshot.recheck(content=True,cleanup=True)
                with patch.object(http.kernel.time,'monotonic_ns',return_value=deadline):
                    with self.assertRaises(ValueError):snapshot.recheck(content=True,cleanup=True)
            finally:snapshot.close()

    def test_real_canonical_id_marker_binds_exact_url_order_and_pinned_payload(self):
        with self.http_fixture() as (http,root,run,source,payloads,rows,entry,deadline):
            sha=rows[0][0]
            first='https://fixture.example/first https://fixture.example/second'
            second='https://fixture.example/second https://fixture.example/first'
            source_marker=payloads/sha/http.canonical_marker(first)
            self.assertFalse(source_marker.exists())  # Legacy CAS file alone is not a canonical-ID hit.
            snapshots=[]
            try:
                for index,canonical in enumerate((first,second)):
                    epoch=root/('canonical-epoch-'+str(index));epoch.mkdir(mode=0o700)
                    with patch.object(http,'CANONICAL_IDS',((sha,canonical),)):
                        snapshot=http.Snapshot(epoch,entry,deadline);snapshots.append(snapshot)
                    marker=snapshot.path/'content_addressable'/'sha256'/sha/http.canonical_marker(canonical)
                    self.assertTrue(marker.is_file());self.assertEqual(marker.read_bytes(),b'')
                    self.assertEqual(marker.stat().st_mode&0o777,0o444)
                    self.assertEqual(marker.stat().st_nlink,1)
                    expected='id-'+hashlib.sha256(canonical.encode('utf-8')).hexdigest()
                    self.assertEqual(marker.name,expected)
                    self.assertFalse(marker.with_name(http.canonical_marker(second if index==0 else first)).exists())
                    snapshot.recheck(content=True,cleanup=True)
                    self.assertEqual(http.digest_file(snapshot.rows[0][2],snapshot.budget,http.MAX_FILE)[0],sha)
                self.assertNotEqual(snapshots[0].facts()['snapshot_sha256'],snapshots[1].facts()['snapshot_sha256'])
                self.assertEqual(snapshots[0].facts()['copied_bytes'],snapshots[1].facts()['copied_bytes'])
                self.assertFalse(snapshots[0].facts()['complete_dependency_closure_proved'])
            finally:
                for snapshot in snapshots:snapshot.close()
            self.assertTrue(all(snapshot.facts()['custody_released'] for snapshot in snapshots))

    def test_real_canonical_id_marker_custody_refuses_missing_extra_or_changed_leaves(self):
        for mutation in ('missing','extra','nonempty','symlink','hardlink','rebound'):
            with self.subTest(mutation=mutation),self.http_fixture() as fixture:
                http,root,run,source,payloads,rows,entry,deadline=fixture
                snapshot=http.Snapshot(run,entry,deadline)
                try:
                    sha,_,name,_,_=snapshot.marker_rows[0]
                    parent=snapshot.path/'content_addressable'/'sha256'/sha
                    target=parent/name;parent.chmod(0o755)
                    if mutation=='missing':target.unlink()
                    elif mutation=='extra':target.with_name('id-'+'0'*64).write_bytes(b'')
                    elif mutation=='nonempty':
                        target.chmod(0o644);target.write_bytes(b'x');target.chmod(0o444)
                    elif mutation=='symlink':
                        target.unlink();target.symlink_to(parent/'file')
                    elif mutation=='hardlink':os.link(target,root/'extra-marker-link')
                    else:
                        target.rename(root/'retained-marker');target.write_bytes(b'');target.chmod(0o444)
                    parent.chmod(0o555)
                    with self.assertRaises((ValueError,OSError)):snapshot.recheck(content=True,cleanup=True)
                finally:snapshot.close()

if __name__=='__main__':unittest.main()
