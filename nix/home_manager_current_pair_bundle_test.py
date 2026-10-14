"""Real tiny source/NAR/custody fixtures; no Nix or artifact execution."""
import copy
from contextlib import contextmanager
import io
import json
import os
from pathlib import Path
import shutil
import stat
import time
import unittest
from unittest.mock import patch
import home_manager_bundle as old
import home_manager_bundle_test as fixtures
import home_manager_current_artifact_test as authority_fixtures
import home_manager_current_pair_bundle as pair

class PairTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.BundleTests('runTest');self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        f=self.fixture
        # Deliberately no artifact root/receipt: no legacy metadata path is usable.
        for directory,_,_ in __import__('os').walk(f.retained/'artifact'):
            Path(directory).chmod(0o700)
        shutil.rmtree(f.retained/'artifact');(f.retained/'artifact-receipt.json').unlink()
        f.write(f.layout,old.encoded({'schemaVersion':1,'kind':'omux-current-home-manager-pair-layout-v1',
            'pairReceipt':'pair/receipt.json','pairInventory':'pair/inventory.json',
            'pairReceiptSha256':old.PAIR_SHA,'sourceWrapper':old.SOURCE_WRAPPER}))
        f.retained_representation()
        entry=time.monotonic_ns()
        self.binding={'schemaVersion':1,'kind':'omux-current-home-manager-pair-action-v1',
            'sourceRevision':'a'*40,'sourceDirty':False,'graphSha256':'b'*64,
            'originalEntryMonotonicNs':entry,'originalDeadlineMonotonicNs':entry+1200000000000}

    def produce(self):
        f=self.fixture
        return pair.reconstruct(f.layout,f.lock_path,f.outputs,self.binding,deadline=time.monotonic()+180,leaf_model=True)

    def test_real_pair_without_artifact_publishes_final_flags_and_retains_inputs(self):
        f=self.fixture;source=f.retained/'pair/home-manager/default.nix'
        before=(old.acquired.snapshot(source.stat()),source.read_bytes())
        with patch.object(old,'artifact_metadata',side_effect=AssertionError('legacy artifact consulted')), \
                patch.object(old.artifact,'development_manifest',side_effect=AssertionError('legacy manifest consulted')):
            result=self.produce()
        raw=(f.outputs/'receipt.json').read_bytes();receipt=pair.validate_compact(raw,result['receiptSha256'])
        self.assertEqual(receipt['binding'],self.binding)
        self.assertTrue(receipt['privateTreesRemoved']);self.assertTrue(receipt['reconstructedCanonicalNarVerified'])
        self.assertFalse(receipt['retainedPhysicalNarVerified']);self.assertFalse(receipt['currentArtifactQualified'])
        self.assertEqual(before,(old.acquired.snapshot(source.stat()),source.read_bytes()))
        self.assertEqual(sorted(p.name for p in f.outputs.iterdir()),['bundle','receipt.json'])
        self.assertEqual(pair.sha((f.outputs/'bundle').read_bytes()),receipt['bundleSha256'])

    def test_real_new_frame_materializes_and_nar_verifies_only_two_sources(self):
        f=self.fixture;result=self.produce();raw=(f.outputs/'receipt.json').read_bytes()
        receipt=pair.validate_compact(raw,result['receiptSha256']);work=time.monotonic()+120
        raw_pair=(f.retained/'pair/receipt.json').read_bytes();inventory=(f.retained/'pair/inventory.json').read_bytes()
        _,descriptors=old.pair_metadata(f.lock,raw_pair,inventory)
        with old.private_tree(f.scratch,work+60,admission_deadline=work) as worker:
            pair.materialize_pair(io.BytesIO((f.outputs/'bundle').read_bytes()),lambda:None,worker,f.lock,receipt,work)
            pair.canonical_pair(worker,f.lock,raw_pair,inventory,descriptors,work)
            self.assertEqual(sorted(p.name for p in worker.path.iterdir()),['home','pair'])
        self.assertEqual(list(f.scratch.iterdir()),[])

    def test_original_expired_clock_refuses_before_declared_input_io(self):
        self.binding['originalEntryMonotonicNs']=1;self.binding['originalDeadlineMonotonicNs']=1200000000001
        with patch.object(old,'RepresentationInputs') as reader,self.assertRaises(ValueError):self.produce()
        reader.assert_not_called()

    def test_transport_mode_refusal_preserves_outputs_empty(self):
        (self.fixture.retained/'pair/home-manager/default.nix').chmod(0o444)
        with self.assertRaises(ValueError):self.produce()
        self.assertEqual(list(self.fixture.outputs.iterdir()),[])

    def test_late_declared_byte_corruption_rolls_back_publication(self):
        original=pair.write_frame
        def corrupt(*args,**kwargs):
            result=original(*args,**kwargs)
            path=self.fixture.retained/'pair/home-manager/default.nix';data=path.read_bytes()
            path.chmod(0o600);path.write_bytes(b'X'+data[1:]);path.chmod(0o555)
            return result
        with patch.object(pair,'write_frame',side_effect=corrupt),self.assertRaises(ValueError):self.produce()
        self.assertEqual(list(self.fixture.outputs.iterdir()),[])

    def test_cleanup_refusal_withholds_both_final_files(self):
        original=old.private_tree
        @contextmanager
        def refused(*args,**kwargs):
            with original(*args,**kwargs) as worker:yield worker
            raise ValueError('modeled-cleanup-refusal')
        with patch.object(old,'private_tree',refused),self.assertRaises(ValueError):self.produce()
        self.assertEqual(list(self.fixture.outputs.iterdir()),[])

    def test_cross_family_magic_refused_in_both_real_materializers(self):
        work=time.monotonic()+120
        # Supply a complete magic-width read for either family. The shorter
        # old magic alone would test truncation before the pair magic check.
        header_bytes=max(len(old.MAGIC),len(pair.MAGIC))
        old_header=old.MAGIC.ljust(header_bytes,b'\x00')
        pair_header=pair.MAGIC.ljust(header_bytes,b'\x00')
        with old.private_tree(self.fixture.scratch,work+60,admission_deadline=work) as worker:
            with self.assertRaisesRegex(ValueError,'bundle-magic'):
                pair.materialize_pair(io.BytesIO(old_header),lambda:None,worker,self.fixture.lock,{},work)
            with self.assertRaisesRegex(ValueError,'bundle-magic'):
                old.materialize(io.BytesIO(pair_header),lambda:None,worker,self.fixture.lock,{},work)

    def test_receipt_wrong_family_and_optimistic_flags_refused(self):
        result=self.produce();raw=(self.fixture.outputs/'receipt.json').read_bytes();receipt=json.loads(raw)
        for field,value in [('kind','omux-home-manager-bundle-v1'),('currentArtifactQualified',True),
                            ('privateTreesRemoved',False),('retainedPhysicalNarVerified',True)]:
            with self.subTest(field=field):
                modified={**receipt,field:value};data=old.encoded(modified)
                with self.assertRaises(ValueError):pair.validate_compact(data,pair.sha(data))

    def test_pending_selection_before_selected_authority_io(self):
        with patch.object(pair,'selected_inputs') as reader,self.assertRaises(ValueError):
            pair.selected_document(old.encoded({'schemaVersion':1,'kind':pair.SELECT,'selection':None}))
        reader.assert_not_called()

    def test_action_mode_and_original_clock_require_exact_family(self):
        env={'OMUX_CURRENT_HM_MODE':pair.current.admission.PAIR,'OMUX_CURRENT_HM_ENTRY_NS':str(self.binding['originalEntryMonotonicNs']),
             'OMUX_CURRENT_HM_DEADLINE_NS':str(self.binding['originalDeadlineMonotonicNs']),
             'OMUX_CURRENT_HM_SOURCE_COMMIT':'a'*40,'OMUX_CURRENT_HM_SOURCE_DIRTY':'false','OMUX_CURRENT_HM_GRAPH_SHA256':'b'*64}
        binding,end=pair.original_binding(env);self.assertEqual(binding,self.binding)
        self.assertLessEqual(end,pair.current.kernel.envelope(binding['originalEntryMonotonicNs'],binding['originalDeadlineMonotonicNs'])/1e9)
        for key,value in [('OMUX_CURRENT_HM_MODE',pair.current.admission.PROFILE),('OMUX_CURRENT_HM_SOURCE_DIRTY','unknown'),
                          ('OMUX_CURRENT_HM_DEADLINE_NS',str(self.binding['originalDeadlineMonotonicNs']+1))]:
            with self.subTest(key=key),self.assertRaises(ValueError):pair.original_binding({**env,key:value})

    def test_actual_selected_producer_clock_source_terminal_xml_and_marker_joins(self):
        result=self.produce();receipt=json.loads((self.fixture.outputs/'receipt.json').read_bytes())
        epoch='00000000-0000-0000-0000-000000000001';parent=pair.current.PUBLIC[0]+'/'+epoch
        fixture=authority_fixtures.CurrentAuthorityTest('runTest');outer=fixture.outer()
        outer['profile']=pair.current.admission.PAIR
        outer['current_home_manager_artifact_reservation']=pair.current.admission.projection(pair.current.admission.PAIR,
            self.binding['originalEntryMonotonicNs'],self.binding['originalDeadlineMonotonicNs'],True,
            outer['current_home_manager_artifact_reservation']['resident'])
        marker={'scope':pair.KIND,'bundleSha256':result['bundleSha256'],'receiptSha256':result['receiptSha256'],
            'pairReceiptSha256':receipt['pairReceiptSha256'],'bindingSha256':receipt['bindingSha256'],'activationQualified':False}
        log=old.encoded(marker);xml=b'<testsuite tests="1" failures="0" errors="0" skipped="0"><testcase name="producer"/></testsuite>'
        contents={};members=[]
        for name,data in [('test.log',log),('test.xml',xml)]:
            digest=pair.sha(data);leaf=digest+'.evidence';contents[parent+'/test-evidence/'+leaf]=data
            members.append({'source':name,'state':'copied','file':leaf,'sha256':digest,'bytes':len(data)})
        evidence={'schema':1,'bazel_exit':0,'epoch_start_ns':123,'targets':[pair.TARGET],
                  'results':[{'target':pair.TARGET,'state':'observed','files':members}]}
        data=old.encoded(evidence);contents[parent+'/test-evidence.json']=data
        outer.update({'id':epoch,'unit':'omux-execution-'+epoch+'.service','manager':'system','exit':0,'workload_exit':0,
            'controller_failure':None,'descendants_empty':True,'cleanup':{'state':'empty','ownership':'verified','readback_attempts':2},
            'source_commit':'a'*40,'source_dirty':'false','graph_sha256':'b'*64,'verb':'test','targets':[pair.TARGET],
            'test_evidence':{'state':'preserved','sha256':pair.sha(data)},'epoch_start_ns':123,'output_base':parent+'/output-base'})
        def run(row,compact=receipt,duplicate=False):
            raw=old.encoded(row);contents[parent+'/receipt.json']=raw
            selection={'root':parent+'/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/home_manager_current_pair_reconstruction_producer/test.outputs',
                'bundleSha256':result['bundleSha256'],'receiptSha256':result['receiptSha256'],
                'producer':{'receipt':parent+'/receipt.json','sha256':pair.sha(raw),'source_commit':'a'*40,
                            'source_dirty':'false','graph_sha256':'b'*64}}
            def read(path,maximum,deadline,expected=None,**kwargs):
                data=contents[str(path)];self.assertLessEqual(len(data),maximum)
                if expected is not None: self.assertEqual(pair.sha(data),expected)
                return data,('fixture',pair.sha(data))
            with patch.object(pair.current,'read',side_effect=read):
                return pair.producer_authority(selection,compact,time.monotonic()+30)
        self.assertEqual(len(run(outer)),4)
        for field,value in [('exit',125),('targets',['//tools:home_manager_retained_reconstruction_producer']),
                            ('graph_sha256','0'*64),('source_dirty','true'),('descendants_empty',False)]:
            row=copy.deepcopy(outer);row[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):run(row)
        altered=copy.deepcopy(receipt);altered['binding']['originalEntryMonotonicNs']+=1
        with self.assertRaises(ValueError):run(outer,altered)
        bad=copy.deepcopy(outer);bad['cleanup']['ownership']='unproved'
        with self.assertRaises(ValueError):run(bad)
        # A successful wrapper with a duplicated marker remains inadmissible.
        data=log+b'\n'+log+b'\n';digest=pair.sha(data);contents[parent+'/test-evidence/'+digest+'.evidence']=data
        changed=copy.deepcopy(evidence);row=next(r for r in changed['results'][0]['files'] if r['source']=='test.log')
        row.update(file=digest+'.evidence',sha256=digest,bytes=len(data))
        raw=old.encoded(changed);contents[parent+'/test-evidence.json']=raw
        duplicated=copy.deepcopy(outer);duplicated['test_evidence']['sha256']=pair.sha(raw)
        with self.assertRaisesRegex(ValueError,'marker'):run(duplicated)

    def packed_fixture(self, *, mutate_outer=None, log_suffix=b'', corrupt_pack=False,
                       transport='physical-forest-v1'):
        f=self.fixture;root=f.base/'packed';root.mkdir(mode=0o700)
        raw_pair=(f.retained/'pair/receipt.json').read_bytes()
        inventory=(f.retained/'pair/inventory.json').read_bytes()
        for name in old.acquired.NAMES:
            shutil.copytree(f.fixture.roots[name],root/name,symlinks=True)
        with pair.acquisition.HeldDirectory(root) as held:
            meta=pair.source_pack.write(held.fd,raw_pair,inventory,time.monotonic()+120,
                anchor=held.check,charge=lambda info:self.assertLessEqual(info.st_size,pair.source_pack.MAX_BYTES),
                transport=transport)
        # The bootstrap fixture has no source leaves after packing. Canonical
        # proof must therefore come from actual decoded regular bytes.
        for name in old.acquired.NAMES:
            for directory,_,_ in os.walk(root/name):Path(directory).chmod(0o700)
            shutil.rmtree(root/name)
        if corrupt_pack:
            path=root/'source.pack';data=path.read_bytes()
            f.write(path,data[:-1]+bytes([data[-1]^1]));meta['packSha256']=pair.sha(path.read_bytes())
        metadata=pair.source_pack.encoded(meta);f.write(root/'source-pack.json',metadata)
        epoch='00000000-0000-0000-0000-000000000010';parent=pair.source_pack.STATE+'/'+epoch
        marker={'scope':'finite-paired-source-acquisition','receiptSha256':old.PAIR_SHA,
            'evaluationExecuted':False,'activation':'unproved','packedSourceSha256':meta['packSha256'],
            'packedSourceMetadataSha256':pair.sha(metadata)}
        if transport == 'packed-only-v2':marker['transport']=transport
        log=old.encoded(marker)+log_suffix
        xml=b'<testsuite tests="1" failures="0" errors="0" skipped="0"><testcase name="source-pack"/></testsuite>'
        authority=root/'authority';authority.mkdir(mode=0o700);members=[]
        for name,data in [('test.log',log),('test.xml',xml)]:
            digest=pair.sha(data);leaf=digest+'.evidence';f.write(authority/leaf,data)
            members.append({'source':name,'state':'copied','file':leaf,'sha256':digest,'bytes':len(data)})
        evidence=old.encoded({'schema':1,'bazel_exit':0,'epoch_start_ns':123,'targets':[pair.source_pack.TARGET],
            'results':[{'target':pair.source_pack.TARGET,'state':'observed','files':members}]})
        f.write(authority/'test-evidence.json',evidence)
        caps={'MemoryMax':'4294967296','MemorySwapMax':'0','TasksMax':'512','CPUQuotaPerSecUSec':'2s',
            'RuntimeMaxUSec':'20min','KillMode':'control-group','SendSIGKILL':'yes','TimeoutStopUSec':'10s','OOMPolicy':'kill'}
        outer={'id':epoch,'unit':'omux-execution-'+epoch+'.service','manager':'system','profile':'dependency-prefetch',
            'exit':0,'workload_exit':0,'controller_failure':None,'descendants_empty':True,
            'cleanup':{'state':'empty','ownership':'verified','readback_attempts':2},
            'source_commit':'c'*40,'source_dirty':'false','graph_sha256':'d'*64,'verb':'test',
            'targets':[pair.source_pack.TARGET],'test_evidence':{'state':'preserved','sha256':pair.sha(evidence)},
            'output_base':parent+'/output-base','epoch_start_ns':123,'cache_reuse_requested':False,
            'cache_policy':None,'cache_key':None,'coordination_directory':'/home/jess/.local/state/omux-execution-20261005',
            'coordination_lock':'/home/jess/.local/state/omux-execution-20261005/execution.lock','limits':caps,
            'observed_properties':{**caps,'PrivateNetwork':'no','PrivateUsers':'no','NoNewPrivileges':'yes',
                'ProtectControlGroups':'yes','RestrictSUIDSGID':'yes','User':str(os.getuid()),'Group':str(os.getgid())}}
        if mutate_outer is not None:mutate_outer(outer)
        raw=old.encoded(outer);f.write(authority/'receipt.json',raw)
        selection={'schemaVersion':1,'kind':pair.source_pack.SELECT,'selection':{
            'root':parent+'/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/home_manager_acquisition_producer/test.outputs/home-manager-pair',
            'packSha256':meta['packSha256'],'packBytes':meta['packBytes'],'metadataSha256':pair.sha(metadata),
            'producer':{'receipt':parent+'/receipt.json','sha256':pair.sha(raw),'source_commit':'c'*40,
                'source_dirty':'false','graph_sha256':'d'*64}}}
        if transport == 'packed-only-v2':
            selection.update(schemaVersion=2,kind=pair.source_pack.SELECT_V2)
            selection['selection']['transport']=transport
        layout=root/'layout.json';f.write(layout,old.encoded({'schemaVersion':1,
            'kind':'omux-current-home-manager-packed-layout-v1','sourceSelection':selection}))
        return root,layout,selection,meta

    def packed_produce(self,layout):
        f=self.fixture
        return pair.reconstruct(layout,f.lock_path,f.outputs,self.binding,deadline=time.monotonic()+180)

    def test_v2_real_reconstruction_retains_two_canonical_proofs_and_private_cleanup(self):
        root,layout,selection,meta=self.packed_fixture(transport='packed-only-v2')
        calls=[];actual=pair.canonical_pair
        def checking(*args,**kwargs):
            value=actual(*args,**kwargs);calls.append(value);return value
        with patch.object(pair,'canonical_pair',side_effect=checking):result=self.packed_produce(layout)
        self.assertEqual(len(calls),2)
        self.assertEqual(calls[0],calls[1])
        self.assertEqual(result['sourceTransport']['producerReceiptSha256'],selection['selection']['producer']['sha256'])
        self.assertEqual(result['sourceTransport']['packSha256'],meta['packSha256'])
        self.assertFalse(result['retainedPhysicalNarVerified']);self.assertFalse(result['activationQualified'])
        self.assertEqual(sorted(x.name for x in self.fixture.outputs.iterdir()),['bundle','receipt.json'])
        pair.validate_compact((self.fixture.outputs/'receipt.json').read_bytes(),result['receiptSha256'])
        self.assertFalse(any((root/name).exists() for name in old.acquired.NAMES))
        self.assertFalse(any(p.name.startswith('omux-hm') for p in self.fixture.outputs.iterdir()))

    def test_v2_selection_cannot_adopt_v1_metadata_or_reach_producer_authority(self):
        root,layout,selection,meta=self.packed_fixture()
        selection.update(schemaVersion=2,kind=pair.source_pack.SELECT_V2)
        selection['selection']['transport']='packed-only-v2'
        self.fixture.write(layout,old.encoded({'schemaVersion':1,
            'kind':'omux-current-home-manager-packed-layout-v1','sourceSelection':selection}))
        with patch.object(pair.PackedSources,'authenticate') as authenticate, \
                self.assertRaisesRegex(ValueError,'current-pair-source-pack-transport'):
            self.packed_produce(layout)
        authenticate.assert_not_called()
        self.assertEqual(list(self.fixture.outputs.iterdir()),[])

    def test_v2_truncated_pack_refuses_without_publishing_bundle(self):
        root,layout,selection,meta=self.packed_fixture(transport='packed-only-v2')
        path=root/'source.pack';self.fixture.write(path,path.read_bytes()[:-1])
        with self.assertRaises(ValueError):self.packed_produce(layout)
        self.assertEqual(list(self.fixture.outputs.iterdir()),[])

    def test_real_packed_only_input_runs_decoder_full_nar_before_after_and_private_cleanup(self):
        root,layout,selection,meta=self.packed_fixture();calls=[];actual=pair.canonical_pair
        def checking(*args,**kwargs):
            value=actual(*args,**kwargs);calls.append(value);return value
        with patch.object(pair,'canonical_pair',side_effect=checking):result=self.packed_produce(layout)
        self.assertEqual(len(calls),2);self.assertEqual(calls[0],calls[1])
        self.assertEqual(result['sourceTransport']['producerReceiptSha256'],selection['selection']['producer']['sha256'])
        self.assertEqual(result['sourceTransport']['packSha256'],meta['packSha256'])
        self.assertFalse(result['retainedPhysicalNarVerified']);self.assertFalse(result['activationQualified'])
        self.assertEqual(sorted(x.name for x in self.fixture.outputs.iterdir()),['bundle','receipt.json'])
        pair.validate_compact((self.fixture.outputs/'receipt.json').read_bytes(),result['receiptSha256'])
        self.assertFalse(any(x.name.startswith('omux-hm') for x in self.fixture.outputs.iterdir()))
        self.assertFalse((root/'home-manager').exists());self.assertFalse((root/'nixpkgs').exists())

    def test_pack_and_all_authority_fds_stay_held_and_late_equal_size_bytes_refuse(self):
        root,layout,selection,_=self.packed_fixture();inputs=old.Inputs(root,time.monotonic()+120)
        with self.assertRaises(ValueError),pair.PackedSources(inputs,old.encoded(selection),time.monotonic()+120) as packed:
            self.assertEqual(len(packed.held),6)
            for row in packed.held.values():self.assertFalse(row[0].closed)
            path=root/'source.pack';data=path.read_bytes();path.chmod(0o600)
            path.write_bytes(data[:-1]+bytes([data[-1]^1]));path.chmod(0o444)
            packed.recheck()
        for row in packed.held.values():self.assertTrue(row[0].closed)

    def test_packed_pending_and_production_leaf_layout_refuse_before_lock_io(self):
        f=self.fixture;root=f.base/'pending-pack';root.mkdir()
        layout=root/'layout.json';f.write(layout,old.encoded({'schemaVersion':1,
            'kind':'omux-current-home-manager-packed-layout-v1','sourceSelection':{
                'schemaVersion':1,'kind':pair.source_pack.SELECT,'selection':None}}))
        for candidate in (layout,f.layout):
            with self.subTest(candidate=candidate.name),patch.object(pair.evaluator,'read_declared') as read, self.assertRaises(ValueError):
                self.packed_produce(candidate)
            read.assert_not_called()
        self.assertEqual(list(f.outputs.iterdir()),[])

    def test_upstream_failed_dirty_wrong_profile_cleanup_and_caps_refuse_before_worker(self):
        changes=[lambda v:v.update(exit=125),lambda v:v.update(source_dirty='true'),
            lambda v:v.update(profile=pair.current.admission.PAIR),
            lambda v:v['cleanup'].update(ownership='unproved'),
            lambda v:v['observed_properties'].update(TasksMax='513'),
            lambda v:v.update(cache_reuse_requested=True)]
        for change in changes:
            root,layout,_,_=self.packed_fixture(mutate_outer=change)
            with patch.object(old,'private_tree') as worker,self.assertRaises(ValueError):self.packed_produce(layout)
            worker.assert_not_called();self.assertEqual(list(self.fixture.outputs.iterdir()),[])
            for directory,_,_ in os.walk(root):Path(directory).chmod(0o700)
            shutil.rmtree(root)

    def test_late_held_pack_rebinding_rolls_back_final_bundle_and_owned_worker(self):
        root,layout,_,_=self.packed_fixture();actual=pair.write_frame
        def rebinding(*args,**kwargs):
            result=actual(*args,**kwargs);path=root/'source.pack';path.rename(root/'retired.pack')
            self.fixture.write(path,(root/'retired.pack').read_bytes());return result
        with patch.object(pair,'write_frame',side_effect=rebinding),self.assertRaises(ValueError):self.packed_produce(layout)
        self.assertEqual(list(self.fixture.outputs.iterdir()),[])

    def test_buffered_canonical_and_retained_source_rebinding_refuses_and_closes_owner(self):
        for retained in (False,True):
            with self.subTest(retained=retained):
                root=self.fixture.base/('stream-retained' if retained else 'stream-canonical')
                source=root/'pair/home-manager/default.nix';source.parent.mkdir(parents=True)
                self.fixture.write(source,b'x'*65536)
                if retained:source.chmod(0o555)
                inputs=(old.RepresentationInputs(root,time.monotonic()+120,'layout.json') if retained
                    else old.Inputs(root,time.monotonic()+120))
                descriptors={name:{'nodes':[]} for name in pair.acquired.NAMES}
                descriptors['home-manager']['nodes']=[{'type':'regular','path':'default.nix','size':65536}]
                actual=inputs.open;held=[]
                @contextmanager
                def tracking(*args,**kwargs):
                    with actual(*args,**kwargs) as (reader,info,check):
                        # Canonical Reader is the real fdopen object; retained
                        # Reader wraps it, so retain the actual yielded check.
                        held.append(check)
                        yield reader,info,check
                stream=pair.PairStream(inputs,(),descriptors)
                self.addCleanup(stream.close)
                with patch.object(inputs,'open',side_effect=tracking):
                    self.assertEqual(stream.read(len(pair.MAGIC)+1),pair.MAGIC+b'x')
                    self.assertEqual(len(stream.pending),65535)
                    self.assertIs(stream.active_check,held[0])
                    source.rename(source.with_name('retired.nix'))
                    self.fixture.write(source,b'x'*65536)
                    if retained:source.chmod(0o555)
                    with self.assertRaisesRegex(ValueError,'bundle-input-changed'):stream.read(1)
                self.assertTrue(stream.closed);self.assertEqual(stream.pending,b'')
                self.assertIsNone(stream.active_check)
                if retained:self.assertIsNone(inputs.active_check)

    def test_buffered_canonical_close_releases_real_fd_and_refuses_reuse(self):
        root=self.fixture.base/'stream-close';source=root/'pair/home-manager/default.nix'
        source.parent.mkdir(parents=True);self.fixture.write(source,b'x'*65536)
        inputs=old.Inputs(root,time.monotonic()+120)
        descriptors={name:{'nodes':[]} for name in pair.acquired.NAMES}
        descriptors['home-manager']['nodes']=[{'type':'regular','path':'default.nix','size':65536}]
        actual=inputs.open;held=[]
        @contextmanager
        def tracking(*args,**kwargs):
            with actual(*args,**kwargs) as row:
                held.append(row[0].fileno());yield row
        stream=pair.PairStream(inputs,(),descriptors);self.addCleanup(stream.close)
        with patch.object(inputs,'open',side_effect=tracking):
            self.assertEqual(stream.read(len(pair.MAGIC)+1),pair.MAGIC+b'x')
            self.assertEqual(len(stream.pending),65535);os.fstat(held[0])
            stream.close()
        self.assertIsNone(stream.active_check);self.assertEqual(stream.pending,b'')
        with self.assertRaises(OSError):os.fstat(held[0])
        with self.assertRaisesRegex(ValueError,'current-pair-stream-closed'):stream.read(1)
        with self.assertRaisesRegex(ValueError,'current-pair-stream-closed'):stream.check()
        stream.close()

    def test_buffered_canonical_expiry_inside_real_held_check_refuses_and_closes(self):
        root=self.fixture.base/'stream-expiry';source=root/'pair/home-manager/default.nix'
        source.parent.mkdir(parents=True);self.fixture.write(source,b'x'*65536)
        clock=[time.monotonic()];deadline=clock[0]+120
        inputs=old.Inputs(root,deadline)
        descriptors={name:{'nodes':[]} for name in pair.acquired.NAMES}
        descriptors['home-manager']['nodes']=[{'type':'regular','path':'default.nix','size':65536}]
        actual=inputs.open;held=[];armed=[False]
        @contextmanager
        def tracking(*args,**kwargs):
            with actual(*args,**kwargs) as (reader,info,check):
                held.append(reader.fileno())
                def checked_then_expired():
                    check()  # Actual named/FD/full-stat/parent/original-clock check.
                    if armed[0]:clock[0]=deadline+1
                yield reader,info,checked_then_expired
        stream=pair.PairStream(inputs,(),descriptors);self.addCleanup(stream.close)
        with patch.object(inputs,'open',side_effect=tracking),patch.object(old.time,'monotonic',side_effect=lambda:clock[0]):
            self.assertEqual(stream.read(len(pair.MAGIC)+1),pair.MAGIC+b'x')
            self.assertEqual(len(stream.pending),65535);os.fstat(held[0])
            armed[0]=True
            with self.assertRaisesRegex(ValueError,'acquired-verification-deadline'):stream.read(1)
        self.assertEqual(clock[0],deadline+1)
        self.assertTrue(stream.closed);self.assertIsNone(stream.active_check)
        self.assertEqual(stream.pending,b'')
        with self.assertRaises(OSError):os.fstat(held[0])

    def test_correct_digest_corrupt_packed_payload_still_requires_actual_canonical_nar(self):
        # All actual transport/producer predicate functions run. This modeled
        # producer's honestly rehashed corrupt payload still fails original NAR.
        root,layout,_,_=self.packed_fixture(corrupt_pack=True)
        with self.assertRaisesRegex(ValueError,'(nar|hash|binding)'):self.packed_produce(layout)
        self.assertEqual(list(self.fixture.outputs.iterdir()),[])

if __name__=='__main__':unittest.main()
