"""Modern evaluation role boundaries; never synthetic actual lineage proof."""
import time
import hashlib
import json
import re
from contextlib import contextmanager
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import codex_native_acquisition_material as material

class MaterialTests(unittest.TestCase):
    def test_real_ledger_relative_snapshot_joins_absolute_retained_role(self):
        import codex_native_acquisition_compilation as compiler
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); deadline=float(time.monotonic()+20)
            document={'material':{'fixture':'not-an-actual-qualified-source'},
                'controller_inventory_sha256':'a'*64}
            carrier={'native_dispatch_ledger':{'aggregate_maximum':8,'dispatched':8,
                'current_dispatch':8,'remaining':0}}
            raw=compiler.encoded(carrier);pin=hashlib.sha256(raw).hexdigest()
            relative=compiler.GOAL_SNAPSHOT_PREFIX+pin+'.json'
            physical=root/relative;physical.parent.mkdir(parents=True)
            physical.write_bytes(raw);physical.chmod(0o444)
            snapshot={'path':relative,'sha256':pin,'bytes':len(raw)}
            wrapper={'schema_version':1,'kind':'omux-native-acquisition-root-dispatch-ledger-v1',
                'actor':'Root','phase':'after-pre-action-advancement','aggregate':8,'dispatched':8,
                'remaining':0,'material_sha256':hashlib.sha256(compiler.encoded(document['material'])).hexdigest(),
                'controller_inventory_sha256':'a'*64,
                'compiler_controller':{'source_commit':'f'*40,'graph_sha256':'e'*64},
                'goal_snapshot':snapshot}
            encoded=compiler.encoded(wrapper);ledger=root/'ledger.json'
            ledger.write_bytes(encoded);ledger.chmod(0o444)
            document['ledger']={'path':str(ledger),'sha256':hashlib.sha256(encoded).hexdigest()}
            with mock.patch.object(compiler,'PUBLIC_ROOT',root):
                verified=compiler.ledger(document,deadline)
                retained={'path':material.selected_role_path('compiler_ledger_snapshot',verified['goal_snapshot']),
                    'sha256':pin,'bytes':len(raw)}
                material._member(retained)
                self.assertEqual(retained['path'],str(physical))
                with self.assertRaises(ValueError):
                    material._member({**retained,'path':relative})
                for wrong in ('../private.json',str(physical),compiler.GOAL_SNAPSHOT_PREFIX+'b'*64+'.json'):
                    with self.assertRaises(ValueError):
                        material.selected_role_path('compiler_ledger_snapshot',{**snapshot,'path':wrong})

    def test_legacy_and_summary_documents_fail_before_reads(self):
        with mock.patch.object(material,'validate_selection') as validate:
            for value in ({'schema_version':1,'kind':'legacy','files':{}},
                    {'material_family':'native-acquisition-evaluation-v1','compiler_qualified':True},
                    {'schema_version':1,'kind':material.PACKAGE_KIND,'purpose':'deployment'}):
                with self.assertRaises(ValueError):material.validate_paths(value)
            validate.assert_not_called()

    def test_member_contract_refuses_bool_bytes_escape_and_unpinned_data(self):
        good={'path':'/fixture/receipt.json','sha256':'a'*64,'bytes':1}
        material._member(good)
        for row in ({**good,'bytes':True},{**good,'path':'/fixture/../outside'},
                    {**good,'sha256':'unconfigured'},{**good,'bytes':0},
                    {**good,'role':'compiler'}):
            with self.assertRaises(ValueError):material._member(row)

    def test_original_deadline_mandatory_not_a_reset(self):
        for deadline in (None,time.monotonic()+60,int(time.monotonic()+60)):
            if type(deadline) is float:
                material.tick(deadline)
            else:
                with self.assertRaises(ValueError):material.tick(deadline)
        with self.assertRaises(ValueError):material.tick(float(time.monotonic()-1))

class ProducerSuccessTests(unittest.TestCase):
    @contextmanager
    def fixture(self):
        """Real reader/hash/XML/policy; only the disposable producer scope differs."""
        import codex_protocol_history_native as protocol
        import guard_resident_native_source_acquisition_source_reserved as admission
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            epoch=root/'11111111-1111-1111-1111-111111111111'
            epoch.mkdir(mode=0o700)
            evidence_directory=epoch/'test-evidence';evidence_directory.mkdir(mode=0o700)
            resident={'scope':'sampled-fixed-default-cgroup-kernel-reservation-v1',
                'kernel_bounds':{'memory.max':'268435456','memory.swap.max':'0',
                    'pids.max':'32','cpu.max':'10000 100000'},'observations':1,
                'initial_direct_processes_retained':True,'initial_direct_process_count':1,
                'outer_pid_namespace_matched':True,'hierarchical_caps':True,
                **{name:False for name in ('descendant_process_inventory','installation_qualified',
                    'health_observed','custody_observed','resident_signalled','whole_host_reservation')}}
            targets=admission.ARGUMENTS[1:]
            manifest={'schema':1,'bazel_exit':0,'epoch_start_ns':1,'targets':targets,'results':[]}
            for index,target in enumerate(targets):
                files=[]
                for name,raw in [('test.log',('public fixture '+str(index)+'\n').encode()),
                        ('test.xml',('<testsuite tests="1" failures="0" errors="0" skipped="0" '
                            'name="fixture'+str(index)+'"><testcase name="fixture"/></testsuite>').encode())]:
                    pin=hashlib.sha256(raw).hexdigest();leaf=pin+'.evidence'
                    (evidence_directory/leaf).write_bytes(raw)
                    (evidence_directory/leaf).chmod(0o444)
                    files.append({'source':name,'file':leaf,'sha256':pin,'bytes':len(raw),'state':'copied'})
                manifest['results'].append({'target':target,'state':'observed','files':files})
            receipt={'id':epoch.name,'unit':'omux-execution-'+epoch.name+'.service',
                'profile':admission.PROFILE,'manager':'system','exit':0,'workload_exit':0,
                'controller_failure':None,'descendants_empty':True,'cleanup':{'state':'empty'},
                'source_dirty':'false','source_commit':'a'*40,'graph_sha256':'b'*64,
                'verb':'test','targets':targets,'epoch_start_ns':1,
                'cache_reuse_requested':False,'cache_policy':None,'cache_key':None,
                'output_base':str(epoch/'output-base'),
                'test_evidence':{'state':'preserved','sha256':None},
                'observed_properties':{'MemoryMax':'4026531840','MemorySwapMax':'0','TasksMax':'480',
                    'PrivateNetwork':'yes','KillMode':'control-group','SendSIGKILL':'yes',
                    'OOMPolicy':'kill','RemainAfterExit':'yes','CPUQuotaPerSecUSec':'1.900000s',
                    'RuntimeMaxUSec':'19min 29s'},
                'resident_native_source_acquisition_source_reservation':admission.projection(
                    1,1+1200*10**9,True,resident)}
            selected={'root':receipt['output_base']+'/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/'
                'codex_native_source_acquisition_source_producer/test.outputs/native-source-acquisition-source',
                'producer':{'receipt':str(epoch/'receipt.json'),'sha256':None,
                    'source_commit':receipt['source_commit'],'graph_sha256':receipt['graph_sha256']}}
            def reseal():
                for name,value in [('test-evidence.json',manifest),('receipt.json',receipt)]:
                    if name=='receipt.json':
                        receipt['test_evidence']['sha256']=hashlib.sha256((epoch/'test-evidence.json').read_bytes()).hexdigest()
                    file=epoch/name
                    if file.exists():file.chmod(0o600)
                    file.write_bytes((json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode())
                    file.chmod(0o444)
                selected['producer']['sha256']=hashlib.sha256((epoch/'receipt.json').read_bytes()).hexdigest()
            reseal()
            # Production pin grammar is unchanged. This test seam names only
            # its own disposable epoch; metadata readers and predicates are real.
            scope=re.compile(re.escape(str(root))+r'/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}/receipt\.json\Z')
            with mock.patch.object(protocol,'PRODUCER_SCOPE',scope):
                yield selected,receipt,manifest,evidence_directory,reseal,protocol

    def invoke(self,selected):
        return material.producer_success(selected,material.SOURCE_TARGET,
            'native-source-acquisition-source',float(time.monotonic()+20))

    def test_actual_producer_success_reads_all_real_cohort_metadata_bytes_and_xml(self):
        with self.fixture() as (selected,receipt,manifest,directory,reseal,protocol):
            with mock.patch.object(protocol,'hash_regular',wraps=protocol.hash_regular) as hashed:
                self.assertEqual(self.invoke(selected),receipt)
            self.assertEqual(hashed.call_count,6)
            self.assertEqual({call.args[1] for call in hashed.call_args_list},
                {entry['file'] for row in manifest['results'] for entry in row['files']})

    def test_invalid_output_namespace_refuses_before_evidence_reads(self):
        for namespace in ('bad/extra','k8 fastbuild',''):
            with self.subTest(namespace=namespace),self.fixture() as (selected,receipt,manifest,directory,reseal,protocol):
                selected['root']=selected['root'].replace('k8-fastbuild',namespace)
                with mock.patch.object(protocol,'read_json',wraps=protocol.read_json) as read, self.assertRaises(ValueError):
                    self.invoke(selected)
                self.assertEqual(read.call_count,1)

    def test_rehashed_invalid_evidence_names_refuse_before_open(self):
        for name in ('g'*64+'.evidence','a'*64+'.evidence/extra','../'+('a'*64)+'.evidence'):
            with self.subTest(name=name),self.fixture() as (selected,receipt,manifest,directory,reseal,protocol):
                manifest['results'][0]['files'][0]['file']=name;reseal()
                with mock.patch.object(protocol,'hash_regular',wraps=protocol.hash_regular) as hashed, self.assertRaises(ValueError):
                    self.invoke(selected)
                hashed.assert_not_called()

    def test_rehashed_guardian_policy_or_success_drift_refuses_before_evidence(self):
        for changed in ('cleanup','caps','reservation','source','targets'):
            with self.subTest(changed=changed),self.fixture() as (selected,receipt,manifest,directory,reseal,protocol):
                if changed=='cleanup':receipt['cleanup']['state']='unknown'
                elif changed=='caps':receipt['observed_properties']['MemorySwapMax']='1'
                elif changed=='reservation':receipt['resident_native_source_acquisition_source_reservation']['native_image_qualified']=True
                elif changed=='source':receipt['source_commit']='c'*40
                else:receipt['targets']=[material.SOURCE_TARGET]
                reseal()
                with mock.patch.object(protocol,'read_json',wraps=protocol.read_json) as read, self.assertRaises(ValueError):
                    self.invoke(selected)
                self.assertEqual(read.call_count,1)

    def test_actual_evidence_hash_size_and_xml_refuse_rehashed_manifest_drift(self):
        for changed in ('hash','size','xml'):
            with self.subTest(changed=changed),self.fixture() as (selected,receipt,manifest,directory,reseal,protocol):
                row=manifest['results'][0]['files'][1]
                if changed=='hash':row['sha256']='f'*64
                elif changed=='size':row['bytes']+=1
                else:
                    file=directory/row['file'];file.chmod(0o600)
                    raw=b'<testsuite tests="1" failures="1" errors="0" skipped="0"/>'
                    file.write_bytes(raw);file.chmod(0o444)
                    row.update(sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw))
                reseal()
                with self.assertRaises(ValueError):self.invoke(selected)


if __name__=='__main__':unittest.main()
