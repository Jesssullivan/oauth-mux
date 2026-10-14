"""Actual parent lease FD/name/cohort boundaries; no SDK producer qualification."""
import copy
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import uuid
import guard_native_sdk_tree_reserved as tree


class LeaseBoundaries(unittest.TestCase):
    @contextmanager
    def fixture(self,profile=tree.PRODUCER):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as temporary:
            state=Path(temporary).resolve();state.chmod(0o700)
            checkout=state/'checkout';checkout.mkdir(mode=0o700)
            # Only the test's exact private temporary root is admitted. All
            # subsequent cache/lock/marker/base/receipt FD operations are real.
            def trusted(path):
                self.assertEqual(Path(path),state)
                return os.open(state,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            entry=time.monotonic_ns();until=entry+1200*10**9
            with patch.object(tree.kernel.resident,'PUBLIC_ROOTS',(state,)), \
                    patch.object(tree.cache,'trusted_directory',trusted):
                lease=tree.SDKTreeDependencyLease(state,'3'*64,str(uuid.uuid4()),
                    checkout=checkout,source_commit='4'*40,graph_sha256='5'*64,
                    entry=entry,deadline=until,profile=profile)
                try: yield state,checkout,lease
                finally: lease.close()

    def test_actual_boot_role_is_bounded_stable_and_drains_before_return(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as temporary:
            path=Path(temporary)/'boot-id';path.write_bytes(b'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa\n');path.chmod(0o444)
            entry=time.monotonic_ns();deadline=entry+1200*10**9
            real_open,real_close=os.open,os.close;opened=[];closed=[]
            def acquire(*args,**kwargs):
                fd=real_open(*args,**kwargs);opened.append(fd);return fd
            def retire(fd):closed.append(fd);real_close(fd)
            with patch.object(tree,'BOOT_ID_PATH',path), patch.object(tree.os,'open',acquire), patch.object(tree.os,'close',retire):
                self.assertEqual(tree.current_boot_id(entry,deadline),'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa')
            self.assertEqual(len(closed),len(set(closed)))
            self.assertEqual(set(opened),set(closed))
            for fd in opened:
                with self.assertRaises(OSError):os.fstat(fd)
            path.chmod(0o600);path.write_bytes(b'not-a-clock-domain\n');path.chmod(0o444)
            with patch.object(tree,'BOOT_ID_PATH',path):
                with self.assertRaises(ValueError):tree.current_boot_id(entry,deadline)
            with patch.object(tree,'BOOT_ID_PATH',path), patch.object(tree.time,'monotonic_ns',return_value=deadline-30*10**9):
                with self.assertRaises(ValueError):tree.current_boot_id(entry,deadline)

    def test_actual_command_declares_current_boot_only_for_both_closed_cohorts(self):
        import guard_resident_enrollment_profile as enrollment
        for profile in tree.PROFILES:
            with self.subTest(profile=profile), self.fixture(profile) as (state,checkout,lease):
                lease.__enter__()
                run=state/lease.run_id
                def builder(bazel,run,arguments,**kwargs):
                    return [str(bazel),'--disk_cache=','--remote_cache=','--remote_executor=',*arguments]
                # Namespace/configuration seams only; actual lease/fence and
                # kernel boot capture remain real, and no action executes.
                with patch.object(tree.Path,'cwd',return_value=checkout), \
                        patch.object(enrollment,'repository_inputs',return_value=None):
                    result=tree.command(builder,'declared-bazel',run,tree.COHORTS[profile],profile,
                        lease.entry,lease.deadline,graph_sha256=lease.graph_sha256,dependency_lease=lease,
                        source_commit=lease.source_commit,source_dirty='false',output_base=None,
                        repository_cache='declared-model',nixpkgs_source='declared-model')
                current='OMUX_NATIVE_SDK_TREE_CURRENT_BOOT_ID='+lease.boot_id
                self.assertIn('--action_env='+current,result)
                self.assertIn('--test_env='+current,result)
                if profile == tree.PRODUCER:
                    self.assertIn('--action_env=OMUX_NATIVE_SDK_TREE_BOOT_ID='+lease.boot_id,result)
                else:
                    self.assertFalse(any('OMUX_NATIVE_FILE_WRITER_MODELS_BOOT_ID=' in value for value in result))
                self.assertEqual([value for value in result if value.startswith('--action_env=OMUX_NATIVE_SDK_TREE_CURRENT_BOOT_ID=')],
                    ['--action_env='+current])

    def failed_receipt(self,state,lease):
        run=state/lease.run_id;run.mkdir(mode=0o700)
        (run/'test-evidence').mkdir(mode=0o700)
        index={'schema':1,'bazel_exit':3,'epoch_start_ns':1,'targets':tree.COHORTS[lease.profile][1:],
            'bytes':0,'copied_files':0,'results':[{'target':target,'state':'missing-test-directory','files':[]}
                for target in tree.COHORTS[lease.profile][1:]],
            'acceptance':'evidence copies preserve invocation status; no inferred PASS'}
        index_raw=(json.dumps(index,sort_keys=True)+'\n').encode()
        index_path=run/'test-evidence.json';index_path.write_bytes(index_raw);index_path.chmod(0o600)
        resident={'scope':'sampled-fixed-default-cgroup-kernel-reservation-v1',
            'kernel_bounds':{'memory.max':str(tree.kernel.resident.RESIDENT_MEMORY),'memory.swap.max':'0',
                'pids.max':str(tree.kernel.resident.RESIDENT_TASKS),'cpu.max':'10000 100000'},
            'observations':2,'initial_direct_process_count':1,'initial_direct_processes_retained':True,
            'outer_pid_namespace_matched':True,'hierarchical_caps':True,'descendant_process_inventory':False,
            'installation_qualified':False,'health_observed':False,'custody_observed':False,'resident_signalled':False,
            'whole_host_reservation':False}
        row={'id':lease.run_id,'verb':'test','profile':lease.profile,
            'unit':'omux-execution-'+lease.run_id+'.service','manager':'system','epoch_start_ns':1,
            'targets':tree.COHORTS[lease.profile][1:],'cache_key':lease.key,'cache_policy':2,
            'cache_reuse_requested':True,'output_base':str(lease.output_base),
            'source_dirty':'false','source_commit':lease.source_commit,'graph_sha256':lease.graph_sha256,
            'descendants_empty':True,'controller_failure':None,'exit':125,'workload_exit':3,
            'cleanup':{'ownership':'verified','state':'empty','readback_attempts':2},
            'test_evidence':{'state':'preserved','manifest':'test-evidence.json','sha256':hashlib.sha256(index_raw).hexdigest(),
                'bytes':0,'files':0},'native_sdk_tree_dependency_lease':lease.facts(),
            'observed_properties':{'MemoryMax':str(tree.MEMORY),'MemorySwapMax':'0','TasksMax':str(tree.TASKS),
                'PrivateNetwork':'yes','KillMode':'control-group','SendSIGKILL':'yes','OOMPolicy':'kill','RemainAfterExit':'yes',
                'CPUQuotaPerSecUSec':'1.9s','RuntimeMaxUSec':'19min30s' if lease.profile == tree.PRODUCER else '14min'},
            'native_sdk_tree_artifact_origin':None}
        row['native_sdk_tree_terminal_publication']=tree.publication_record(lease.entry,lease.deadline)
        name='native_sdk_tree_reservation' if lease.profile == tree.PRODUCER else 'native_sdk_tree_source_reservation'
        row[name]=tree.projection(lease.profile,lease.entry,lease.deadline,True,resident)
        row['native_sdk_tree_dependency_disposition']=lease.disposition(row)
        raw=(json.dumps(row,sort_keys=True)+'\n').encode()
        path=run/'receipt.json';path.write_bytes(raw);path.chmod(0o600)
        self.confirmation_fixture(row,path,raw)
        return row,path,hashlib.sha256(raw).hexdigest()

    def confirmation_fixture(self,row,path,raw):
        # Synthetic historical marker only for model setup; genuine finalizer
        # tests remove both fixtures and run actual publication/qualification.
        record=tree.qualification_record(row,hashlib.sha256(raw).hexdigest(),len(raw),
            time.monotonic_ns(),list(tree.old._witness(os.stat(path,follow_symlinks=False))))
        target=path.parent/'sdk-tree-qualified.json'
        target.write_text(json.dumps(record,sort_keys=True)+'\n');target.chmod(0o600)

    def remove_canonical_fixture(self,path):
        path.unlink();(path.parent/'sdk-tree-qualified.json').unlink()

    def test_real_lock_is_exclusive_and_clones_are_not_owners(self):
        with self.fixture() as (state,checkout,lease):
            lease.__enter__();lease.fence()
            second=tree.SDKTreeDependencyLease(state,lease.key,str(uuid.uuid4()),
                checkout=checkout,source_commit='4'*40,graph_sha256='5'*64,
                entry=lease.entry,deadline=lease.deadline,profile=tree.SOURCE_PROFILE)
            try:
                with self.assertRaises(BlockingIOError):second.__enter__()
            finally:second.close()
            with self.assertRaises(ValueError):copy.copy(lease)
            with self.assertRaises(ValueError):copy.deepcopy(lease)

    def test_real_same_named_marker_replacement_cannot_replace_held_owner(self):
        with self.fixture() as (state,checkout,lease):
            lease.__enter__();marker=state/lease.name/'owner.json'
            old=marker.read_bytes();marker.rename(marker.with_name('retired-marker.json'))
            marker.write_bytes(old);marker.chmod(0o600)
            with self.assertRaises(ValueError):lease.fence()

    def test_real_output_base_replacement_cannot_replace_held_root(self):
        with self.fixture() as (state,checkout,lease):
            lease.__enter__();lease.output_base.rename(lease.output_base.with_name('retired-base'))
            lease.output_base.mkdir(mode=0o700)
            with self.assertRaises(ValueError):lease.fence()

    def test_cancelled_epoch_stays_dirty_and_never_implies_cleanup(self):
        with self.fixture() as (state,checkout,lease):
            lease.__enter__();lease.close()
            second=tree.SDKTreeDependencyLease(state,lease.key,str(uuid.uuid4()),
                checkout=checkout,source_commit='4'*40,graph_sha256='5'*64,
                entry=lease.entry,deadline=lease.deadline,profile=tree.SOURCE_PROFILE)
            try:
                with self.assertRaises(ValueError):second.__enter__()
            finally:second.close()

    def test_failed_sdk_can_retain_only_data_after_exact_owned_cleanup(self):
        with self.fixture() as (state,checkout,lease):
            lease.__enter__();lease.prepare_capture()
            row,path,digest=self.failed_receipt(state,lease)
            self.assertEqual(row['native_sdk_tree_dependency_disposition']['state'],
                'dependency-only-after-owned-failure')
            self.assertIs(row['native_sdk_tree_dependency_disposition']['sdk_execution_qualified'],False)
            lease.complete(True,digest);lease.close()
            second=tree.SDKTreeDependencyLease(state,lease.key,str(uuid.uuid4()),
                checkout=checkout,source_commit='6'*40,graph_sha256='7'*64,
                entry=lease.entry,deadline=lease.deadline,profile=tree.SOURCE_PROFILE)
            try:
                second.__enter__();second.fence()
                self.assertIs(second.facts()['sdk_execution_qualified'],False)
            finally:second.close()

    def test_foreign_cohort_and_modified_receipt_fail_before_reuse(self):
        for mutation in ('profile','bytes','cleanup','positive_origin','projection','index','caps'):
            with self.fixture() as (state,checkout,lease):
                lease.__enter__();lease.prepare_capture()
                row,path,digest=self.failed_receipt(state,lease)
                if mutation == 'profile':row['profile']='native-siwc-catalog-content-source-reserved'
                if mutation == 'cleanup':row['cleanup']['readback_attempts']=1
                if mutation == 'positive_origin':row['native_sdk_tree_artifact_origin']={'ready':True}
                if mutation == 'projection':row['native_sdk_tree_reservation']['work_cutoff_monotonic_ns']+=1
                if mutation == 'index':
                    index=state/lease.run_id/'test-evidence.json';index.write_bytes(index.read_bytes()+b' ')
                if mutation == 'caps':row['observed_properties']['TasksMax']='481'
                raw=(json.dumps(row,sort_keys=True)+'\n').encode();path.write_bytes(raw)
                if mutation == 'bytes':path.write_bytes(raw+b' ')
                changed=hashlib.sha256(raw).hexdigest()
                with self.assertRaises(ValueError):lease.complete(True,digest if mutation == 'bytes' else changed)

    def test_cross_checkout_prior_receipt_fails_closed(self):
        with self.fixture() as (state,checkout,lease):
            lease.__enter__();lease.prepare_capture();row,path,digest=self.failed_receipt(state,lease)
            lease.complete(True,digest);lease.close()
            other=state/'other-checkout';other.mkdir(mode=0o700)
            second=tree.SDKTreeDependencyLease(state,lease.key,str(uuid.uuid4()),checkout=other,
                source_commit='4'*40,graph_sha256='5'*64,entry=lease.entry,deadline=lease.deadline,
                profile=tree.SOURCE_PROFILE)
            try:
                with self.assertRaises(ValueError):second.__enter__()
            finally:second.close()

    def test_successful_source_cohort_reuses_namespace_without_sdk_origin(self):
        with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
            lease.__enter__();lease.prepare_capture();row,path,digest=self.failed_receipt(state,lease)
            row['exit']=row['workload_exit']=0
            results=[];used=0
            for target in row['targets']:
                members=[]
                for source,raw in [('test.log',b'model-only source cohort\n'),
                        ('test.xml',b'<testsuite tests="1" failures="0" errors="0"/>')]:
                    name=hashlib.sha256((target+'\0k8-fastbuild\0'+source).encode()).hexdigest()+'.evidence'
                    copied=path.parent/'test-evidence'/name;copied.write_bytes(raw);copied.chmod(0o600)
                    members.append({'source':source,'state':'copied','bytes':len(raw),
                        'sha256':hashlib.sha256(raw).hexdigest(),'file':name});used+=len(raw)
                members += [{'source':name,'state':'missing','bytes':0} for name in
                    ('test.outputs_manifest/MANIFEST','test.outputs_manifest/ANNOTATIONS')]
                results.append({'target':target,'configuration':'k8-fastbuild','state':'observed','files':members})
            index={'schema':1,'bazel_exit':0,'epoch_start_ns':1,'targets':row['targets'],'bytes':used,
                'copied_files':4,'results':results,'acceptance':'evidence copies preserve invocation status; no inferred PASS'}
            raw=(json.dumps(index,sort_keys=True)+'\n').encode();(path.parent/'test-evidence.json').write_bytes(raw)
            row['test_evidence'].update(sha256=hashlib.sha256(raw).hexdigest(),bytes=used,files=4)
            row['native_sdk_tree_dependency_disposition']=lease.disposition(row)
            raw=(json.dumps(row,sort_keys=True)+'\n').encode();path.write_bytes(raw)
            self.confirmation_fixture(row,path,raw)
            lease.complete(True,hashlib.sha256(raw).hexdigest());lease.close()
            second=tree.SDKTreeDependencyLease(state,lease.key,str(uuid.uuid4()),checkout=checkout,
                source_commit='6'*40,graph_sha256='7'*64,entry=lease.entry,deadline=lease.deadline,profile=tree.PRODUCER)
            try:
                second.__enter__();second.fence()
                self.assertIs(second.facts()['sdk_execution_qualified'],False)
            finally:second.close()

    def test_modified_prior_index_refuses_before_next_namespace_admission(self):
        with self.fixture() as (state,checkout,lease):
            lease.__enter__();lease.prepare_capture();row,path,digest=self.failed_receipt(state,lease)
            lease.complete(True,digest);lease.close()
            index=path.parent/'test-evidence.json';index.write_bytes(index.read_bytes()+b' ')
            second=tree.SDKTreeDependencyLease(state,lease.key,str(uuid.uuid4()),checkout=checkout,
                source_commit='6'*40,graph_sha256='7'*64,entry=lease.entry,deadline=lease.deadline,profile=tree.SOURCE_PROFILE)
            try:
                with self.assertRaises(ValueError):second.__enter__()
            finally:second.close()

    def test_source_clock_remains_original600_and_producer_original1170(self):
        for profile,cutoff in ((tree.SOURCE_PROFILE,600),(tree.PRODUCER,1170)):
            with self.fixture(profile) as (state,checkout,lease):
                lease.__enter__()
                with patch.object(tree.time,'monotonic_ns',return_value=lease.entry+cutoff*10**9):
                    with self.assertRaises(ValueError):lease.fence()
                facts=tree.projection(profile,lease.entry,lease.deadline,None,{})
                self.assertEqual(facts['work_cutoff_monotonic_ns'],lease.entry+cutoff*10**9)
                self.assertIs(facts['sdk_execution_qualified'],False)

    def metadata_fixture(self,state,lease):
        # Tiny public metadata only. This deliberately creates no SDK tree,
        # producer success, source qualification or production selector.
        root=lease.output_base/'execroot/_main/bazel-out/k8-fastbuild/bin'/tree.LAYOUT
        root.mkdir(parents=True)
        epoch=state/lease.run_id;epoch.mkdir(mode=0o700)
        context={'MODE':tree.PRODUCER,'ENTRY_NS':str(lease.entry),'DEADLINE_NS':str(lease.deadline),
            'EPOCH':str(epoch),'SOURCE_COMMIT':lease.source_commit,'GRAPH_SHA256':lease.graph_sha256,'BOOT_ID':lease.boot_id}
        encode=lambda doc:(json.dumps(doc,sort_keys=True)+'\n').encode()
        recipe=encode({'kind':'test-only-public-metadata-copy-fixture'})
        nars={'sdk':{'test-only':'sdk-commitment'},'jdk':{'test-only':'jdk-commitment'}}
        inventory=encode({'nars':nars})
        material={'recipe_sha256':hashlib.sha256(recipe).hexdigest(),'action_inputs_sha256':'8'*64,
            'inventory_sha256':hashlib.sha256(inventory).hexdigest(),'sdk_nar':nars['sdk'],'jdk_nar':nars['jdk']}
        report=encode({'kind':'omux-retained-public-sdk-tree-producer-v1','producer':tree.TARGET,
            'tree_root':'tree','inventory':{'sha256':hashlib.sha256(inventory).hexdigest(),'bytes':len(inventory)},
            'materialization':material})
        docs={'creator-context.json':encode(context),'inventory.json':inventory,
            'receipt.json':report,'recipe.json':recipe}
        for name,raw in docs.items():
            path=root/name;path.write_bytes(raw);path.chmod(0o444)
        return root,epoch,docs

    def test_real_metadata_copy_is_exclusive_complete_and_not_sdk_authority(self):
        with self.fixture() as (state,checkout,lease):
            lease.__enter__();root,epoch,docs=self.metadata_fixture(state,lease)
            lease.prepare_capture()
            origin=tree.capture_creator_metadata(lease,epoch)
            self.assertEqual([row['name'] for row in origin['created_metadata']],sorted(docs))
            self.assertEqual(set(origin['materialization']),{'recipe_sha256','action_inputs_sha256'})
            for name,raw in docs.items():
                output=epoch/'sdk-tree-created'/name
                self.assertEqual(output.read_bytes(),raw)
                self.assertEqual(output.stat().st_mode & 0o777,0o444)
            self.assertIs(origin['sdk_execution_qualified'],False)
            self.assertIs(origin['source_qualified'],False)
            with self.assertRaises(FileExistsError):tree.capture_creator_metadata(lease,epoch)

    def test_metadata_context_mismatch_refuses_before_publishing_copy(self):
        with self.fixture() as (state,checkout,lease):
            lease.__enter__();root,epoch,docs=self.metadata_fixture(state,lease)
            path=root/'creator-context.json';path.chmod(0o600)
            context=json.loads(docs['creator-context.json']);context['SOURCE_COMMIT']='9'*40
            path.write_text(json.dumps(context));path.chmod(0o444)
            lease.prepare_capture()
            with self.assertRaises(ValueError):tree.capture_creator_metadata(lease,epoch)
            self.assertFalse((epoch/'sdk-tree-created').exists())

    def test_metadata_materialization_output_mismatch_cannot_publish_origin(self):
        with self.fixture() as (state,checkout,lease):
            lease.__enter__();root,epoch,docs=self.metadata_fixture(state,lease)
            path=root/'receipt.json';path.chmod(0o600)
            report=json.loads(docs['receipt.json']);report['materialization']['sdk_nar']={'wrong':'commitment'}
            path.write_text(json.dumps(report));path.chmod(0o444)
            lease.prepare_capture()
            with self.assertRaises(ValueError):tree.capture_creator_metadata(lease,epoch)
            self.assertFalse((epoch/'sdk-tree-created').exists())

    def successful_source_candidate(self,state,lease,xml=b'<testsuite tests="1" failures="0" errors="0"/>'):
        # Actual parent FD/index/XML grammar, model-only SOURCE cohort stimulus.
        row,path,digest=self.failed_receipt(state,lease);row['exit']=row['workload_exit']=0
        results=[];used=0;xml_paths=[]
        for target in row['targets']:
            members=[]
            for source,raw in [('test.log',b'model-only parent finalization\n'),('test.xml',xml)]:
                name=hashlib.sha256((target+'\0k8-fastbuild\0'+source).encode()).hexdigest()+'.evidence'
                copied=path.parent/'test-evidence'/name;copied.write_bytes(raw);copied.chmod(0o600)
                if source == 'test.xml':xml_paths.append(copied)
                members.append({'source':source,'state':'copied','bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),'file':name})
                used+=len(raw)
            members += [{'source':name,'state':'missing','bytes':0} for name in
                ('test.outputs_manifest/MANIFEST','test.outputs_manifest/ANNOTATIONS')]
            results.append({'target':target,'configuration':'k8-fastbuild','state':'observed','files':members})
        index={'schema':1,'bazel_exit':0,'epoch_start_ns':1,'targets':row['targets'],'bytes':used,'copied_files':4,
            'results':results,'acceptance':'evidence copies preserve invocation status; no inferred PASS'}
        raw=(json.dumps(index,sort_keys=True)+'\n').encode();(path.parent/'test-evidence.json').write_bytes(raw)
        row['test_evidence'].update(sha256=hashlib.sha256(raw).hexdigest(),bytes=used,files=4)
        row['native_sdk_tree_dependency_disposition']=lease.disposition(row)
        raw=(json.dumps(row,sort_keys=True)+'\n').encode();path.write_bytes(raw)
        self.confirmation_fixture(row,path,raw)
        return row,path,hashlib.sha256(raw).hexdigest(),xml_paths

    def assert_refused_terminal(self,path):
        row=json.loads(path.read_bytes())
        self.assertEqual(row['exit'],125)
        self.assertIsNone(row['native_sdk_tree_artifact_origin'])
        self.assertNotIn('native_sdk_tree_dependency_disposition',row)
        self.assertEqual(row['native_sdk_tree_terminal_publication']['state'],'refused-before-commit')
        return row

    def test_actual_finalizer_completion_refusal_never_publishes_success(self):
        with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
            lease.__enter__();lease.prepare_capture();row,path,digest,xml=self.successful_source_candidate(state,lease)
            self.remove_canonical_fixture(path);failure=ValueError('model-completion-refusal')
            with patch.object(tree.cache,'graph_digest',return_value=('a'*64,[])), \
                    patch.object(lease,'complete',side_effect=failure):
                with self.assertRaises(ValueError) as found:tree.publish_terminal(lease,path.parent,row,('a'*64,[]))
            self.assertIs(found.exception,failure);self.assert_refused_terminal(path)
            directory=os.open(state/lease.name,os.O_RDONLY|os.O_DIRECTORY)
            try:self.assertFalse(tree.cache.read_marker(directory)['clean'])
            finally:os.close(directory)
            self.assertIsNone(lease.lock);self.assertIsNone(lease.base_fd)

    def test_actual_finalizer_missing_disposition_refuses_and_attempts_all_input_drains(self):
        with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
            lease.__enter__();lease.prepare_capture();row,path,digest,xml=self.successful_source_candidate(state,lease)
            self.remove_canonical_fixture(path);row.pop('native_sdk_tree_dependency_disposition');called=[]
            primary_cleanup=OSError('model-first-input-close');secondary_cleanup=OSError('model-second-input-close')
            def first():called.append('first');raise primary_cleanup
            def second():called.append('second');raise secondary_cleanup
            with patch.object(tree.cache,'graph_digest',return_value=('a'*64,[])):
                with self.assertRaises(ValueError) as found:
                    tree.publish_terminal(lease,path.parent,row,('a'*64,[]),close_inputs=(first,second))
            self.assertEqual(called,['first','second']);self.assertIs(found.exception.__cause__,primary_cleanup)
            self.assert_refused_terminal(path);self.assertIsNone(lease.lock)

    def test_actual_finalizer_input_drain_failure_prevents_commit_without_numeric_retry(self):
        with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
            lease.__enter__();lease.prepare_capture();row,path,digest,xml=self.successful_source_candidate(state,lease)
            self.remove_canonical_fixture(path);owned=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY);calls=[]
            primary=OSError('model-input-close-after-effect')
            def first():calls.append('first');os.close(owned);raise primary
            def second():calls.append('second')
            with patch.object(tree.cache,'graph_digest',return_value=('a'*64,[])):
                with self.assertRaises(OSError) as found:
                    tree.publish_terminal(lease,path.parent,row,('a'*64,[]),close_inputs=(first,second))
            self.assertIs(found.exception,primary);self.assertEqual(calls,['first','second'])
            self.assert_refused_terminal(path)
            with self.assertRaises(OSError):os.fstat(owned)
            directory=os.open(state/lease.name,os.O_RDONLY|os.O_DIRECTORY)
            try:prepared=tree.cache.read_marker(directory)
            finally:os.close(directory)
            self.assertTrue(prepared['clean'])
            self.assertNotEqual(prepared['cleanup_receipt_sha256'],hashlib.sha256(path.read_bytes()).hexdigest())
            second=tree.SDKTreeDependencyLease(state,lease.key,str(uuid.uuid4()),checkout=checkout,
                source_commit='6'*40,graph_sha256='7'*64,entry=lease.entry,deadline=lease.deadline,profile=tree.PRODUCER)
            try:
                with patch.object(second,'_receipt',wraps=second._receipt) as admission:
                    with self.assertRaises(ValueError):second.__enter__()
                self.assertTrue(admission.called);self.assertIsNone(second.lock)
            finally:second.close()

    def test_actual_unselectable_candidate_fsync_failure_never_leaves_success(self):
        with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
            lease.__enter__();lease.prepare_capture();row,path,digest,xml=self.successful_source_candidate(state,lease)
            self.remove_canonical_fixture(path);actual=os.fsync;failed=[];primary=OSError('model-candidate-fsync')
            def fsync(fd):
                if not failed:failed.append(fd);raise primary
                return actual(fd)
            with patch.object(tree.cache,'graph_digest',return_value=('a'*64,[])),patch.object(tree.os,'fsync',side_effect=fsync):
                with self.assertRaises(OSError) as found:tree.publish_terminal(lease,path.parent,row,('a'*64,[]))
            self.assertIs(found.exception,primary);self.assertFalse(path.exists())
            self.assertFalse((path.parent/'sdk-tree-qualified.json').exists())
            self.assertEqual(lease.terminal_stage,'not-attempted');self.assertIsNone(lease.lock)

    def test_precommit_epoch_substitution_never_writes_refusal_into_replacement(self):
        with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
            lease.__enter__();lease.prepare_capture();row,path,digest,xml=self.successful_source_candidate(state,lease)
            self.remove_canonical_fixture(path);retired=path.parent.with_name(path.parent.name+'-retired');changed=[]
            def graph(root):
                if not changed:path.parent.rename(retired);path.parent.mkdir(mode=0o700);changed.append(True)
                return ('b'*64,[])
            with patch.object(tree.cache,'graph_digest',side_effect=graph):
                with self.assertRaises(ValueError):tree.publish_terminal(lease,path.parent,row,('a'*64,[]))
            self.assertEqual(changed,[True]);self.assertEqual(list(path.parent.iterdir()),[])
            self.assertFalse((retired/'receipt.json').exists())
            for name in ('marker_fd','base_fd','checkout_fd','state_fd','lock','directory'):self.assertIsNone(getattr(lease,name))

    def test_publication_fence_rejoins_checkout_and_base_after_marker_io(self):
        for name in ('checkout','output-base'):
            with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
                lease.__enter__();lease.prepare_capture();read=tree.cache.read_marker;changed=[]
                def read_then_replace(directory):
                    row=read(directory)
                    if lease.publication_ready and not changed:
                        root=checkout if name == 'checkout' else lease.output_base
                        root.rename(root.with_name(root.name+'-retired'))
                        root.mkdir(mode=0o700);changed.append(name)
                    return row
                with patch.object(tree.cache,'read_marker',side_effect=read_then_replace):
                    with self.assertRaises(ValueError):lease.prepare_publication()
                self.assertEqual(changed,[name]);self.assertIsNotNone(lease.lock)

    def test_hostile_primary_cause_cannot_skip_remaining_actual_owned_closes(self):
        class Hostile(OSError):
            def __getattribute__(self,name):
                if name == '__cause__':raise RuntimeError('hostile-cause-get')
                return super().__getattribute__(name)
            def __setattr__(self,name,value):
                if name == '__cause__':raise RuntimeError('hostile-cause-set')
                return super().__setattr__(name,value)
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as temporary:
            owned=[os.open(temporary,os.O_RDONLY|os.O_DIRECTORY) for _ in range(3)]
            primary=Hostile('model-primary');cleanup=OSError('model-cleanup-after-effect');calls=[]
            def first():calls.append(0);os.close(owned[0]);raise cleanup
            def second():calls.append(1);os.close(owned[1])
            def third():calls.append(2);os.close(owned[2])
            result=tree._drain_operations((first,second,third),primary)
            self.assertIs(result,primary);self.assertEqual(calls,[0,1,2])
            self.assertIs(BaseException.__cause__.__get__(primary),cleanup)
            for fd in owned:
                with self.assertRaises(OSError):os.fstat(fd)

    def test_actual_finalizer_changed_evidence_refuses_and_closes_all_owners(self):
        with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
            lease.__enter__();lease.prepare_capture();row,path,digest,xml=self.successful_source_candidate(state,lease)
            self.remove_canonical_fixture(path);actual=lease.complete
            def changed(*args):
                index=path.parent/'test-evidence.json';index.write_bytes(index.read_bytes()+b' ')
                return actual(*args)
            with patch.object(tree.cache,'graph_digest',return_value=('a'*64,[])),patch.object(lease,'complete',side_effect=changed):
                with self.assertRaises(ValueError):tree.publish_terminal(lease,path.parent,row,('a'*64,[]))
            self.assert_refused_terminal(path)
            for name in ('marker_fd','base_fd','checkout_fd','state_fd','lock','directory'):self.assertIsNone(getattr(lease,name))

    def test_actual_finalizer_late_graph_change_is_a_refusal_not_skipped_completion(self):
        for readings in ([('a'*64,[]),('b'*64,[])],[('a'*64,[]),('a'*64,[]),('b'*64,[])]):
            with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
                lease.__enter__();lease.prepare_capture();row,path,digest,xml=self.successful_source_candidate(state,lease)
                self.remove_canonical_fixture(path)
                with patch.object(tree.cache,'graph_digest',side_effect=readings):
                    with self.assertRaises(ValueError):tree.publish_terminal(lease,path.parent,row,('a'*64,[]))
                self.assert_refused_terminal(path)

    def test_actual_qualification_close_error_cannot_publish_success_or_retry_fd(self):
        with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
            lease.__enter__();lease.prepare_capture();row,path,digest,xml=self.successful_source_candidate(state,lease)
            self.remove_canonical_fixture(path);target=lease.base_fd;actual_close=os.close;calls=[];failure=OSError('model-close-after-effect')
            def close(fd):
                actual_close(fd)
                if fd == target and not calls:calls.append(fd);raise failure
            with patch.object(tree.cache,'graph_digest',return_value=('a'*64,[])),patch.object(tree.os,'close',side_effect=close):
                with self.assertRaises(OSError) as found:tree.publish_terminal(lease,path.parent,row,('a'*64,[]))
            self.assertIs(found.exception,failure);self.assertEqual(calls,[target]);self.assert_refused_terminal(path)

    def test_successful_input_close_crossing_original_cutoff_refuses_before_commit(self):
        with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
            lease.__enter__();lease.prepare_capture();row,path,digest,xml=self.successful_source_candidate(state,lease)
            self.remove_canonical_fixture(path);actual_close=os.close;target=lease.checkout_fd;clock=time.monotonic_ns;expired=[False]
            def close(fd):
                actual_close(fd)
                if fd == target:expired[0]=True
            with patch.object(tree.cache,'graph_digest',return_value=('a'*64,[])), \
                    patch.object(tree.os,'close',side_effect=close),patch.object(tree.time,'monotonic_ns',
                        side_effect=lambda:lease.deadline-30*10**9 if expired[0] else clock()):
                with self.assertRaises(ValueError):tree.publish_terminal(lease,path.parent,row,('a'*64,[]))
            self.assert_refused_terminal(path)

    def test_canonical_commit_keeps_actual_exclusive_writer_until_rename(self):
        with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
            lease.__enter__();lease.prepare_capture();row,path,digest,xml=self.successful_source_candidate(state,lease)
            self.remove_canonical_fixture(path);rename=os.rename;commits=[]
            def publish(source,target,*args,**kwargs):
                if Path(source).name == 'receipt.pending.json':
                    self.assertTrue(lease.publication_ready);self.assertIsNone(lease.base_fd);os.fstat(lease.lock)
                    second=tree.SDKTreeDependencyLease(state,lease.key,str(uuid.uuid4()),checkout=checkout,
                        source_commit='6'*40,graph_sha256='7'*64,entry=lease.entry,deadline=lease.deadline,profile=tree.PRODUCER)
                    try:
                        with self.assertRaises(BlockingIOError):second.__enter__()
                    finally:second.close()
                    commits.append(True)
                return rename(source,target,*args,**kwargs)
            with patch.object(tree.cache,'graph_digest',return_value=('a'*64,[])),patch.object(tree.os,'rename',side_effect=publish):
                self.assertEqual(tree.publish_terminal(lease,path.parent,row,('a'*64,[])),0)
            self.assertEqual(commits,[True]);self.assertEqual(json.loads(path.read_bytes())['exit'],0)
            self.assertEqual(lease.terminal_stage,'qualified');self.assertIsNone(lease.lock)

    def test_postcommit_writer_close_error_is_not_a_rewritten_or_acknowledged_success(self):
        with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
            lease.__enter__();lease.prepare_capture();row,path,digest,xml=self.successful_source_candidate(state,lease)
            self.remove_canonical_fixture(path);target=lease.state_fd;close=os.close;raised=[]
            def fail(fd):
                close(fd)
                if fd == target and not raised:raised.append(fd);raise OSError('model-writer-release-after-effect')
            with patch.object(tree.cache,'graph_digest',return_value=('a'*64,[])),patch.object(tree.os,'close',side_effect=fail):
                with self.assertRaises(tree.TerminalPostCommitError) as found:tree.publish_terminal(lease,path.parent,row,('a'*64,[]))
            self.assertEqual(found.exception.state,'committed-writer-release-failed')
            self.assertEqual(json.loads(path.read_bytes())['exit'],0)
            self.assertEqual(lease.terminal_stage,'qualified');self.assertEqual(raised,[target])

    def test_completed_rename_exception_is_commit_unknown_without_false_rollback(self):
        with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
            lease.__enter__();lease.prepare_capture();row,path,digest,xml=self.successful_source_candidate(state,lease)
            self.remove_canonical_fixture(path);rename=os.rename
            def uncertain(source,target,*args,**kwargs):
                result=rename(source,target,*args,**kwargs)
                if Path(source).name == 'receipt.pending.json':raise OSError('model-rename-after-effect')
                return result
            with patch.object(tree.cache,'graph_digest',return_value=('a'*64,[])),patch.object(tree.os,'rename',side_effect=uncertain):
                with self.assertRaises(tree.TerminalPostCommitError) as found:tree.publish_terminal(lease,path.parent,row,('a'*64,[]))
            self.assertEqual(found.exception.state,'commit-unknown');self.assertEqual(json.loads(path.read_bytes())['exit'],0)
            self.assertEqual(lease.terminal_stage,'commit-unknown');self.assertIsNone(lease.lock)
            self.assertFalse((path.parent/'sdk-tree-qualified.json').exists())

    def test_late_actual_canonical_rename_never_emits_qualification_confirmation(self):
        with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
            lease.__enter__();lease.prepare_capture();row,path,digest,xml=self.successful_source_candidate(state,lease)
            self.remove_canonical_fixture(path);rename=os.rename;clock=time.monotonic_ns;late=[False]
            def delayed(source,target,*args,**kwargs):
                result=rename(source,target,*args,**kwargs)
                if source == 'receipt.pending.json':late[0]=True
                return result
            with patch.object(tree.cache,'graph_digest',return_value=('a'*64,[])),patch.object(tree.os,'rename',side_effect=delayed), \
                    patch.object(tree.time,'monotonic_ns',side_effect=lambda:lease.deadline-30*10**9 if late[0] else clock()):
                with self.assertRaises(tree.TerminalPostCommitError) as found:tree.publish_terminal(lease,path.parent,row,('a'*64,[]))
            self.assertEqual(found.exception.state,'committed-unqualified')
            self.assertEqual(json.loads(path.read_bytes())['exit'],0)
            self.assertFalse((path.parent/'sdk-tree-qualified.json').exists())
            second=tree.SDKTreeDependencyLease(state,lease.key,str(uuid.uuid4()),checkout=checkout,
                source_commit='6'*40,graph_sha256='7'*64,entry=lease.entry,deadline=lease.deadline,profile=tree.PRODUCER)
            try:
                with patch.object(second,'_confirmation',wraps=second._confirmation) as confirmation:
                    with self.assertRaises(FileNotFoundError):second.__enter__()
                self.assertTrue(confirmation.called);self.assertIsNone(second.lock)
            finally:second.close()

    def test_postcanonical_graph_fault_keeps_provenance_inadmissible(self):
        with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
            lease.__enter__();lease.prepare_capture();row,path,digest,xml=self.successful_source_candidate(state,lease)
            self.remove_canonical_fixture(path)
            with patch.object(tree.cache,'graph_digest',side_effect=[('a'*64,[])]*3+[('b'*64,[])]):
                with self.assertRaises(tree.TerminalPostCommitError) as found:tree.publish_terminal(lease,path.parent,row,('a'*64,[]))
            self.assertEqual(found.exception.state,'committed-unqualified')
            self.assertEqual(json.loads(path.read_bytes())['exit'],0)
            self.assertFalse((path.parent/'sdk-tree-qualified.json').exists())

    def test_final_graph_io_ctime_only_canonical_mutation_cannot_mint_confirmation(self):
        with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
            lease.__enter__();lease.prepare_capture();row,path,digest,xml=self.successful_source_candidate(state,lease)
            self.remove_canonical_fixture(path);calls=[];changed=[]
            def graph(root):
                calls.append(root)
                if len(calls) == 4:
                    before=tree.old._witness(os.stat(path,follow_symlinks=False))
                    path.chmod(0o400);path.chmod(0o600)
                    after=tree.old._witness(os.stat(path,follow_symlinks=False))
                    self.assertEqual(before[:8],after[:8]);self.assertNotEqual(before[8],after[8]);changed.append(True)
                return ('a'*64,[])
            with patch.object(tree.cache,'graph_digest',side_effect=graph):
                with self.assertRaises(tree.TerminalPostCommitError) as found:tree.publish_terminal(lease,path.parent,row,('a'*64,[]))
            self.assertEqual(changed,[True]);self.assertEqual(found.exception.state,'committed-unqualified')
            self.assertFalse((path.parent/'sdk-tree-qualified.json').exists())

    def test_epoch_writer_fd_confines_rename_when_named_epoch_is_replaced(self):
        with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
            lease.__enter__();lease.prepare_capture();row,path,digest,xml=self.successful_source_candidate(state,lease)
            self.remove_canonical_fixture(path);rename=os.rename;retired=path.parent.with_name(path.parent.name+'-retired')
            def replace(source,target,*args,**kwargs):
                if source == 'receipt.pending.json':
                    rename(path.parent,retired);path.parent.mkdir(mode=0o700)
                    self.assertEqual(kwargs['src_dir_fd'],kwargs['dst_dir_fd'])
                return rename(source,target,*args,**kwargs)
            with patch.object(tree.cache,'graph_digest',return_value=('a'*64,[])),patch.object(tree.os,'rename',side_effect=replace):
                with self.assertRaises(tree.TerminalPostCommitError) as found:tree.publish_terminal(lease,path.parent,row,('a'*64,[]))
            self.assertEqual(found.exception.state,'committed-unqualified')
            self.assertFalse(path.exists());self.assertTrue((retired/'receipt.json').exists())
            self.assertFalse((path.parent/'sdk-tree-qualified.json').exists())
            self.assertFalse((retired/'sdk-tree-qualified.json').exists())

    def test_confirmation_delivery_failure_does_not_upgrade_canonical_provenance(self):
        with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
            lease.__enter__();lease.prepare_capture();row,path,digest,xml=self.successful_source_candidate(state,lease)
            self.remove_canonical_fixture(path);rename=os.rename;fsync=os.fsync;canonical=[False];failed=[]
            def published(source,target,*args,**kwargs):
                result=rename(source,target,*args,**kwargs)
                if source == 'receipt.pending.json':canonical[0]=True
                return result
            def fail(fd):
                if canonical[0] and not failed:failed.append(fd);raise OSError('model-confirmation-fsync')
                return fsync(fd)
            with patch.object(tree.cache,'graph_digest',return_value=('a'*64,[])),patch.object(tree.os,'rename',side_effect=published), \
                    patch.object(tree.os,'fsync',side_effect=fail):
                with self.assertRaises(tree.TerminalPostCommitError) as found:tree.publish_terminal(lease,path.parent,row,('a'*64,[]))
            self.assertEqual(found.exception.state,'committed-unqualified')
            self.assertEqual(json.loads(path.read_bytes())['exit'],0)
            self.assertFalse((path.parent/'sdk-tree-qualified.json').exists())

    def test_missing_late_and_foreign_confirmation_refuse_actual_prior_lease(self):
        for mutation in ('missing','late','foreign','false','receipt'):
            with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
                lease.__enter__();lease.prepare_capture();row,path,digest,xml=self.successful_source_candidate(state,lease)
                self.remove_canonical_fixture(path)
                with patch.object(tree.cache,'graph_digest',return_value=('a'*64,[])):
                    self.assertEqual(tree.publish_terminal(lease,path.parent,row,('a'*64,[])),0)
                confirm=path.parent/'sdk-tree-qualified.json'
                if mutation == 'missing':confirm.unlink()
                else:
                    record=json.loads(confirm.read_bytes())
                    if mutation == 'late':record['observed_qualified_monotonic_ns']=lease.deadline-30*10**9
                    if mutation == 'foreign':record['epoch']=str(state/str(uuid.uuid4()))
                    if mutation == 'false':record['qualification']['qualification_input_closes_verified']=False
                    if mutation == 'receipt':record['receipt']['sha256']='9'*64
                    confirm.write_text(json.dumps(record,sort_keys=True)+'\n')
                second=tree.SDKTreeDependencyLease(state,lease.key,str(uuid.uuid4()),checkout=checkout,
                    source_commit='6'*40,graph_sha256='7'*64,entry=lease.entry,deadline=lease.deadline,profile=tree.PRODUCER)
                try:
                    with patch.object(second,'_confirmation',wraps=second._confirmation) as confirmation:
                        with self.assertRaises((OSError,ValueError)):second.__enter__()
                    self.assertTrue(confirmation.called);self.assertIsNone(second.lock)
                finally:second.close()

    def test_actual_parent_xml_refusal_is_typed_not_an_earlier_pin_mismatch(self):
        for xml in (b'<testsuite',b'<?xml version="1.0" encoding="no-such-codec"?><testsuite tests="1"/>'):
            with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
                lease.__enter__();lease.prepare_capture();row,path,digest,xmls=self.successful_source_candidate(state,lease,xml)
                with patch.object(tree,'_xml_success',wraps=tree._xml_success) as parser:
                    with self.assertRaises(ValueError) as found:lease.complete(True,digest)
                self.assertTrue(parser.called);self.assertIsNone(found.exception.__cause__)
                lease.close();self.assertIsNone(lease.lock);self.assertIsNone(lease.base_fd)

    def test_actual_prior_receipt_xml_refusal_is_typed_and_drains_opened_owner(self):
        with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
            lease.__enter__();lease.prepare_capture()
            row,path,digest,xmls=self.successful_source_candidate(state,lease,b'<testsuite')
            # Deliberately inconsistent prior marker is negative model data,
            # never actual producer qualification or a populated selector.
            tree.cache.write_marker(lease.directory,{'schema':2,'key':lease.key,'clean':True,
                'last_run':lease.run_id,'cleanup_receipt_sha256':digest})
            lease.close()
            second=tree.SDKTreeDependencyLease(state,lease.key,str(uuid.uuid4()),checkout=checkout,
                source_commit='6'*40,graph_sha256='7'*64,entry=lease.entry,deadline=lease.deadline,profile=tree.PRODUCER)
            try:
                with patch.object(tree,'_xml_success',wraps=tree._xml_success) as parser:
                    with self.assertRaises(ValueError) as found:second.__enter__()
                self.assertTrue(parser.called);self.assertIsNone(found.exception.__cause__)
                self.assertIsNone(second.lock);self.assertIsNone(second.directory)
            finally:second.close()

    def test_actual_reopened_evidence_named_refusal_keeps_primary_on_close_failure(self):
        with self.fixture(tree.SOURCE_PROFILE) as (state,checkout,lease):
            lease.__enter__();lease.prepare_capture();row,path,digest,xml=self.successful_source_candidate(state,lease)
            opened=[];target=[None];open_actual=os.open;stat_actual=os.stat;close_actual=os.close
            primary=ValueError('model-reopened-named-join');cleanup=OSError('model-close-after-effect');closed=[]
            def open_directory(name,flags,*args,**kwargs):
                fd=open_actual(name,flags,*args,**kwargs)
                if name == 'test-evidence' and flags & os.O_DIRECTORY:
                    opened.append(fd)
                    if len(opened) == 2:target[0]=fd
                return fd
            def named(name,*args,**kwargs):
                if target[0] is not None and kwargs.get('dir_fd') == target[0] and str(name).endswith('.evidence'):
                    raise primary
                return stat_actual(name,*args,**kwargs)
            def close(fd):
                close_actual(fd)
                if fd == target[0] and not closed:closed.append(fd);raise cleanup
            with patch.object(tree.os,'open',side_effect=open_directory),patch.object(tree.os,'stat',side_effect=named), \
                    patch.object(tree.os,'close',side_effect=close):
                with self.assertRaises(ValueError) as found:lease.complete(True,digest)
            self.assertIs(found.exception,primary);self.assertIs(found.exception.__cause__,cleanup)
            self.assertEqual(closed,[target[0]])
            with self.assertRaises(OSError):os.fstat(target[0])


if __name__ == '__main__':unittest.main()
