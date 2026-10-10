import copy
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import home_manager_current_artifact as current
import home_manager_current_evaluation as main

class CurrentAuthorityTest(unittest.TestCase):
    def receipt(self, dirty=False):
        value={key:False for key in ('shipped','activationQualified','browserQualified','custodyQualified','continuityQualified','liveQualified')}
        value.update({'schemaVersion':1,'kind':'omux-current-home-manager-artifact-v1','sourceRevision':'a'*40,
            'sourceDirty':dirty,'graphSha256':'b'*64,'originalEntryMonotonicNs':1,'originalDeadlineMonotonicNs':1200000000001,
            'archiveSha256':'c'*64,'archiveBytes':1,'manifestSha256':'d'*64,'narHash':'sha256-'+'A'*43+'=',
            'narSize':1,'system':'x86_64-linux','channel':'development','nativeBins':current.artifact.NATIVE_BINS,
            'extensionSha256':'e'*64,'extensionBytes':1,'extensionMetadataSha256':'f'*64,
            'sourceQualification':'original-coordinator-source-and-declared-current-graph'})
        return value

    def outer(self):
        resident={'scope':'sampled-fixed-default-cgroup-kernel-reservation-v1','kernel_bounds':{'memory.max':'268435456',
            'memory.swap.max':'0','pids.max':'32','cpu.max':'10000 100000'},'observations':2,
            'initial_direct_process_count':1}
        resident.update({key:True for key in ('initial_direct_processes_retained','outer_pid_namespace_matched','hierarchical_caps')})
        resident.update({key:False for key in ('descendant_process_inventory','installation_qualified','health_observed',
            'custody_observed','resident_signalled','whole_host_reservation')})
        return {'current_home_manager_artifact_reservation':current.admission.projection(current.admission.PROFILE,
            1,1200000000001,True,resident),'profile':current.admission.PROFILE,'cache_reuse_requested':False,
            'cache_policy':None,'cache_key':None,'observed_properties':{'MemoryMax':'4026531840','MemorySwapMax':'0',
            'TasksMax':'480','PrivateNetwork':'yes','KillMode':'control-group','SendSIGKILL':'yes','OOMPolicy':'kill',
            'RemainAfterExit':'yes','CPUQuotaPerSecUSec':'1.9s','RuntimeMaxUSec':'19min 30s'}}

    def test_current_clean_and_dirty_and_legacy_separation(self):
        for dirty in (False,True):
            value=self.receipt(dirty); raw=current.artifact.encoded(value)
            self.assertEqual(current.validate_receipt(raw,current.sha(raw)),value)
            with self.assertRaises(ValueError): current.artifact.validate_receipt(raw,current.sha(raw))
        value=self.receipt(); value['kind']='omux-home-manager-development-artifact'
        raw=current.artifact.encoded(value)
        with self.assertRaises(ValueError): current.validate_receipt(raw,current.sha(raw))

    def test_schema_digest_and_false_claim_refusals(self):
        for key,value in (('sourceDirty','false'),('activationQualified',True),('sourceQualification','caller-declared-dirty-development'),
                          ('originalDeadlineMonotonicNs',1300000000001),('extra','field')):
            row=self.receipt(); row[key]=value; raw=current.artifact.encoded(row)
            with self.assertRaises(ValueError): current.validate_receipt(raw,current.sha(raw))
        raw=current.artifact.encoded(self.receipt())
        with self.assertRaises(ValueError): current.validate_receipt(raw,'0'*64)

    def test_exact_original_producer_policy_and_caps(self):
        self.assertIsInstance(current.policy(self.outer()),dict)
        for mutation in ('profile','cache','swap','tasks','cpu','runtime','resident','claimed-custody'):
            outer=self.outer()
            if mutation=='profile': outer['profile']='standard'
            elif mutation=='cache': outer['cache_reuse_requested']=True
            elif mutation=='swap': outer['observed_properties']['MemorySwapMax']='1'
            elif mutation=='tasks': outer['observed_properties']['TasksMax']='512'
            elif mutation=='cpu': outer['observed_properties']['CPUQuotaPerSecUSec']='2s'
            elif mutation=='runtime': outer['observed_properties']['RuntimeMaxUSec']='20min 1s'
            elif mutation=='resident': outer['current_home_manager_artifact_reservation']['resident']['kernel_bounds']['pids.max']='33'
            else: outer['current_home_manager_artifact_reservation']['resident']['custody_observed']=True
            with self.assertRaises(ValueError): current.policy(outer)

    def test_actual_xml_cases_require_real_success_no_skips(self):
        current.successful_xml(b'<testsuite tests="1" failures="0" errors="0" skipped="0"><testcase name="producer"/></testsuite>')
        for raw in (b'<testsuite tests="0"/>',b'<testsuite tests="1" skipped="1"/>',b'<testsuite tests="1" errors="1"/>'):
            with self.assertRaises(ValueError): current.successful_xml(raw)

    def test_pending_selector_before_material_or_nix_access(self):
        from types import SimpleNamespace
        raw=b'{"schemaVersion":1,"kind":"omux-current-home-manager-selection-v1","selection":null}'
        with patch.object(main,'original_clock',return_value=(1,1200000000001)), \
             patch.object(main.bundle.evaluator,'read_declared',return_value=(raw,('declared',))), \
             patch.object(main.current,'verify_selected',side_effect=AssertionError('material IO')), \
             patch.object(main.bundle,'evaluate_bundle',side_effect=AssertionError('evaluator IO')):
            with self.assertRaisesRegex(ValueError,'pending'): main.evaluate(SimpleNamespace(selection='declared'),{})

    def test_physical_owner_mode_and_leaf_alias_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'receipt'; path.write_bytes(b'bound'); path.chmod(0o444)
            self.assertEqual(current.read(path,10,time.monotonic()+30,current.sha(b'bound'))[0],b'bound')
            path.chmod(0o666)
            with self.assertRaises(ValueError): current.read(path,10,time.monotonic()+30,readonly=False)
            path.chmod(0o444)
            alias=Path(directory)/'alias'; alias.symlink_to(path.name)
            with self.assertRaises(OSError): current.read(alias,10,time.monotonic()+30)

    def test_real_inventory_and_late_byte_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); file=root/'leaf'; file.write_bytes(b'original'); file.chmod(0o444)
            files,nodes,facts,nar,size=current.artifact.tree_bytes(root,time.monotonic()+30)
            self.assertEqual(files,{'leaf':b'original'})
            receipt={'narHash':nar,'narSize':size}
            inventory={'schemaVersion':1,'nodes':nodes}
            current.inventory_binding(inventory,nodes,nar,size,receipt)
            changed=copy.deepcopy(inventory)
            next(row for row in changed['nodes'] if row['type']=='regular')['sha256']='0'*64
            with self.assertRaises(ValueError): current.inventory_binding(changed,nodes,nar,size,receipt)
            with self.assertRaises(ValueError): current.inventory_binding(inventory,nodes,nar,size+1,receipt)
            file.chmod(0o600); file.write_bytes(b'corrupted'); file.chmod(0o444)
            after=current.artifact.tree_bytes(root,time.monotonic()+30)
            self.assertNotEqual(after[2],facts); self.assertNotEqual(after[3],nar)
            with self.assertRaises(ValueError): current.inventory_binding(inventory,after[1],after[3],after[4],receipt)

    def test_selection_schema_refuses_foreign_original_receipt(self):
        epoch='00000000-0000-0000-0000-000000000001'
        producer={'receipt':current.PUBLIC[0]+'/'+epoch+'/receipt.json','sha256':'a'*64,
            'source_commit':'b'*40,'source_dirty':'false','graph_sha256':'c'*64}
        row={'root':current.PUBLIC[0]+'/'+epoch+'/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/delivery/current_home_manager_artifact/test.outputs/current-home-manager',
            'receiptSha256':'d'*64,'inventorySha256':'e'*64,'producer':producer}
        value={'schemaVersion':1,'kind':'omux-current-home-manager-selection-v1','selection':row}
        self.assertEqual(current.selected_document(current.artifact.encoded(value)),row)
        producer['receipt']='/tmp/'+epoch+'/receipt.json'
        with self.assertRaises(ValueError): current.selected_document(current.artifact.encoded(value))

    def test_actual_producer_reader_source_epoch_terminal_and_log_joins(self):
        epoch='00000000-0000-0000-0000-000000000001'
        parent=current.PUBLIC[0]+'/'+epoch
        receipt=self.receipt()
        log=current.artifact.encoded({'scope':receipt['kind'],'manifestSha256':receipt['manifestSha256'],
            'narHash':receipt['narHash'],'shipped':False})+b'\n'
        xml=b'<testsuite tests="1" failures="0" errors="0" skipped="0"><testcase name="producer"/></testsuite>'
        members=[];contents={}
        for name,raw in (('test.log',log),('test.xml',xml)):
            digest=current.sha(raw); file=digest+'.evidence'
            members.append({'source':name,'state':'copied','file':file,'sha256':digest,'bytes':len(raw)})
            contents[parent+'/test-evidence/'+file]=raw
        evidence={'schema':1,'bazel_exit':0,'epoch_start_ns':123,'targets':[current.TARGET],
            'results':[{'target':current.TARGET,'state':'observed','files':members}]}
        raw_evidence=current.artifact.encoded(evidence); contents[parent+'/test-evidence.json']=raw_evidence
        outer=self.outer(); outer.update({'id':epoch,'unit':'omux-execution-'+epoch+'.service','manager':'system',
            'exit':0,'workload_exit':0,'controller_failure':None,'descendants_empty':True,
            'cleanup':{'state':'empty','ownership':'verified','readback_attempts':2},'source_commit':'a'*40,
            'source_dirty':'false','graph_sha256':'b'*64,'verb':'test','targets':[current.TARGET],
            'test_evidence':{'state':'preserved','sha256':current.sha(raw_evidence)},'epoch_start_ns':123,
            'output_base':parent+'/output-base'})
        def run(row):
            raw=current.artifact.encoded(row); contents[parent+'/receipt.json']=raw
            selection={'root':parent+'/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/delivery/current_home_manager_artifact/test.outputs/current-home-manager',
                'producer':{'receipt':parent+'/receipt.json','sha256':current.sha(raw),'source_commit':'a'*40,
                    'source_dirty':'false','graph_sha256':'b'*64}}
            def read(path,maximum,deadline,expected=None,**kwargs):
                data=contents[str(path)]; self.assertLessEqual(len(data),maximum)
                if expected is not None: self.assertEqual(current.sha(data),expected)
                return data,('fixture',len(data))
            with patch.object(current,'read',side_effect=read):
                return current.producer_authority(selection,receipt,time.monotonic()+30)
        self.assertEqual(len(run(outer)),4)
        for key,value in (('exit',125),('workload_exit',3),('targets',['//delivery:development_home_manager_archive_verify']),
                          ('graph_sha256','0'*64),('source_dirty','true'),('descendants_empty',False)):
            row=copy.deepcopy(outer);row[key]=value
            with self.assertRaises(ValueError): run(row)
        row=copy.deepcopy(outer);row['cleanup']['ownership']='unproved'
        with self.assertRaises(ValueError): run(row)

if __name__=='__main__': unittest.main()
