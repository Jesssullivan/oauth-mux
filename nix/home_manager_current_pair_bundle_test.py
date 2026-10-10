"""Real tiny source/NAR/custody fixtures; no Nix or artifact execution."""
import copy
from contextlib import contextmanager
import io
import json
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
        return pair.reconstruct(f.layout,f.lock_path,f.outputs,self.binding,deadline=time.monotonic()+180)

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

if __name__=='__main__':unittest.main()
