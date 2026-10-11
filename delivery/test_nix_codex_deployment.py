import hashlib
import copy
import json
import os
import unittest
import tempfile
import time
from pathlib import Path
from unittest.mock import patch
import nix_codex_deployment as deployment

class DeploymentInventoryTests(unittest.TestCase):
    def test_real_bounded_metadata_reader_refuses_size_expiry_and_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'metadata'
            path.write_bytes(b'actual synthetic metadata')
            self.assertEqual(deployment.bounded_read(path,64,time.monotonic()+30),b'actual synthetic metadata')
            with self.assertRaises(ValueError):deployment.bounded_read(path,1,time.monotonic()+30)
            with self.assertRaises(ValueError):deployment.bounded_read(path,64,time.monotonic()-1)
            alias=Path(directory)/'alias'
            alias.symlink_to(path)
            with self.assertRaises(ValueError):deployment.bounded_read(alias,64,time.monotonic()+30)
    def fixture(self):
        value={'schema_version':1,'kind':'omux-native-acquisition-package-output-v1',
            'purpose':'evaluation-only','acquisitionContract':'unsupported',
            'files':{name:{'sha256':'a'*64,'bytes':1} for name in deployment.OUTPUTS}}
        raw=deployment.encoded(value)
        marker=b'omux-native-package-output-sha256='+hashlib.sha256(raw).hexdigest().encode()+b'\n'
        return value,raw,marker
    def test_exact_guardian_log_binding_accepts_only_one_closed_inventory_marker(self):
        value,raw,marker=self.fixture()
        self.assertEqual(deployment.closed_inventory(raw,b'ordinary test output\n'+marker),value)
        for log in (b'',marker+marker,b'prefix '+marker,marker+b'omux-native-package-output-sha256=invalid\n',marker.upper()):
            with self.assertRaises(ValueError):deployment.closed_inventory(raw,log)
    def test_inventory_rejects_role_escape_extra_missing_length_and_duplicate_json(self):
        value,raw,marker=self.fixture()
        changes=[]
        for field in ('../runtime-manifest.json','extra.json'):
            changed={**value,'files':{**value['files'],field:{'sha256':'a'*64,'bytes':1}}}
            changes.append(deployment.encoded(changed))
        changed={**value,'files':{name:row for name,row in value['files'].items() if name!=deployment.OUTPUTS[0]}}
        changes.append(deployment.encoded(changed))
        value['files'][deployment.OUTPUTS[0]]['bytes']=True
        changes.append(deployment.encoded(value))
        changes.append(b'{"schema_version":1,"schema_version":1}')
        for body in changes:
            exact=b'omux-native-package-output-sha256='+hashlib.sha256(body).hexdigest().encode()+b'\n'
            with self.assertRaises(ValueError):deployment.closed_inventory(body,exact)

class CarrierRetentionTests(unittest.TestCase):
    def fixture(self, directory):
        """Trusted genuine PACKAGE boundary; retention itself uses actual files."""
        root = Path(directory)/'package'; root.mkdir(mode=0o700)
        evidence = Path(directory)/'epoch'; evidence.mkdir(mode=0o700)
        (evidence/'test-evidence').mkdir(mode=0o700)
        def write(path, value):
            raw = deployment.encoded(value) if isinstance(value,dict) else value
            path.write_bytes(raw); path.chmod(0o444)
            return {'path':str(path),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)}
        row = write(root/'compact.json',b'public compact fixture')
        def group(count=2):
            return {'outer':dict(row),'evidence':dict(row),
                'members':{format(n,'064x')+'.evidence':dict(row) for n in range(count)}}
        carrier = {'manifest_sha256':'1'*64,'manifest_bytes':7,
            'origin':{'receipt_sha256':'2'*64,'receipt_bytes':8},'payload_sha256':'3'*64,'payload_bytes':9000000000}
        carrier_row = write(root/'carrier-receipt.json',carrier)
        transport = [{'name':'manifest.json','sha256':'1'*64,'bytes':7},
            {'name':'origin-receipt.json','sha256':'2'*64,'bytes':8},
            {'name':'payload.bin','sha256':'3'*64,'bytes':9000000000},
            {'name':'receipt.json','sha256':carrier_row['sha256'],'bytes':carrier_row['bytes']}]
        core = {'schema_version':2,'kind':'omux-native-carrier-sdk-authority-core-v2',
            'source':{},'original_selection':{},'carrier_files':transport,'seal':{},'metadata':{},
            'hub_inventory_sha256':'4'*64,'graph_inventory_sha256':'5'*64}
        core_row = write(root/'authority.json',core)
        selection = {'schema_version':2,'kind':deployment.CARRIER_PACKAGE,'purpose':'evaluation-only',
            'material':{},'compilation':{},'files':{role:dict(row) for role in
                ('source','sdk','sdk_metadata','plan','query','compiler_selection','compiler_ledger',
                 'compiler_ledger_snapshot','compiler','compiler_outer','codex','config_schema')},
            'protocol_schema_files':{'stable/a.json':dict(row),'experimental/a.json':dict(row)},
            'native_acquisition_artifact_files':{str(n)+'/test.log':dict(row) for n in range(6)},
            'authority_receipts':{name:group(6 if name == 'source' else 2) for name in ('source','sdk','plan','query','compiler')},
            'carrier_materials':{'schema_version':2,'kind':'omux-native-carrier-retained-authority-v2',
                'authority_sha256':core_row['sha256'],'carrier_files':transport,
                'projection':{'receipt_sha256':row['sha256'],'inventory_sha256':core_row['sha256'],
                    'hub_inventory_sha256':'4'*64,'graph_inventory_sha256':'5'*64},
                'receipts':{'authority_document':core_row,'carrier_receipt':carrier_row,
                    'seal_program':dict(row),'metadata_program':dict(row)},
                'authorities':{'seal':group(),'metadata':group()}}}
        selection_row = write(root/'package-selection.json',selection)
        report = {'kind':'omux-native-source-acquisition-fresh-native-package-v1',
            'chain':{'material_family':'native-carrier-acquisition-evaluation-v2'},
            'native_support':False,'provider_evaluation':False,'selection_sha256':selection_row['sha256'],
            'producer_target':deployment.CARRIER_TARGET}
        output_rows = {name:write(root/name,report if name in ('runtime-manifest.json','runtime-receipt.json') else b'fixture output')
            for name in deployment.OUTPUTS if name != 'package-selection.json'}
        output_rows['package-selection.json'] = selection_row
        inventory = {'files':{name:{key:value for key,value in pin.items() if key != 'path'} for name,pin in output_rows.items()}}
        inventory_raw = deployment.encoded(inventory); write(root/'package-outputs.json',inventory_raw)
        outer_row = write(evidence/'receipt.json',b'trusted genuine outer fixture')
        index_row = write(evidence/'test-evidence.json',b'authenticated evidence fixture')
        members = []
        for source, name in (('test.log','a'*64+'.evidence'),('test.xml','b'*64+'.evidence')):
            pin = write(evidence/'test-evidence'/name,source.encode())
            members.append({'source':source,'state':'copied','file':name,'sha256':pin['sha256'],'bytes':pin['bytes']})
        members += [{'source':'test.outputs_manifest/MANIFEST','state':'copied','file':'c'*64+'.evidence','sha256':'d'*64,'bytes':12},
            {'source':'test.outputs_manifest/ANNOTATIONS','state':'missing','bytes':0}]
        selected = {'root':str(root),'producer':{'receipt':outer_row['path'],'sha256':outer_row['sha256']}}
        receipt = {'test_evidence':{'sha256':index_row['sha256']}}
        return selection,root,inventory,inventory_raw,selected,receipt,Path(index_row['path']).read_bytes(),members

    def test_actual_retention_keeps_raw_core_compact_proofs_and_never_reads_transport(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory); destination = Path(directory)/'retained'
            declaration = deployment.stage_carrier(*args,destination,time.monotonic()+30)
            compact = declaration['modern_materials']['carrier_materials']
            self.assertEqual(set(compact),{'receipts','authorities'})
            original = args[0]['carrier_materials']['receipts']['authority_document']
            self.assertEqual((destination/compact['receipts']['authority_document']['path']).read_bytes(),Path(original['path']).read_bytes())
            self.assertFalse(any(p.name in ('payload.bin','manifest.json','origin-receipt.json') for p in destination.rglob('*')))
            self.assertEqual(len(compact['authorities']['seal']['members']),2)
            self.assertEqual(deployment.closed_json((destination/'share/omux/native/codex/deployment.json').read_bytes()),declaration)

    def test_preflight_refuses_count_bytes_and_declaration_before_any_output(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory)
            for constant,value in (('MAX_RETAINED_ROWS',1),('MAX_RETAINED_BYTES',1),('MAX_DECLARATION',1)):
                destination = Path(directory)/constant
                with patch.object(deployment,constant,value),self.assertRaises(ValueError):
                    deployment.stage_carrier(*args,destination,time.monotonic()+30)
                self.assertFalse(destination.exists())

    def test_actual_raw_drift_tuple_mixing_family_and_deadline_refuse(self):
        for fault in ('core','tuple','family','deadline','symlink'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as directory:
                args = list(self.fixture(directory)); selection,root = args[:2]
                deadline = time.monotonic()+30
                if fault == 'core':
                    path = root/'authority.json'; path.chmod(0o600); path.write_bytes(b'changed'); path.chmod(0o444)
                if fault == 'tuple':selection['carrier_materials']['carrier_files'][0]['sha256'] = 'f'*64
                if fault == 'family':
                    path = root/'runtime-manifest.json'; value = deployment.closed_json(path.read_bytes())
                    value['chain']['material_family'] = 'native-acquisition-evaluation-v1'
                    path.chmod(0o600); path.write_bytes(deployment.encoded(value)); path.chmod(0o444)
                    args[2]['files']['runtime-manifest.json'] = {'sha256':hashlib.sha256(path.read_bytes()).hexdigest(),'bytes':path.stat().st_size}
                if fault == 'deadline':deadline = time.monotonic()-1
                if fault == 'symlink':
                    path = root/'authority.json'; moved = root/'moved.json'; path.rename(moved); path.symlink_to(moved)
                with self.assertRaises(ValueError):deployment.stage_carrier(*args,Path(directory)/'retained',deadline)

    def test_required_copied_log_xml_identity_names_are_independent_from_content_sha(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory); members = args[-1]; outer = args[4]['producer']['receipt']
            selected = deployment.carrier_evidence_members(members,outer)
            self.assertEqual(selected['a'*64+'.evidence']['sha256'],hashlib.sha256(b'test.log').hexdigest())
            for fault in ('missing','duplicate','samefile','foreign'):
                changed = copy.deepcopy(members)
                if fault == 'missing':changed[1] = {'source':'test.xml','state':'missing','bytes':0}
                if fault == 'duplicate':changed[1] = dict(changed[0])
                if fault == 'samefile':changed[1]['file'] = changed[0]['file']
                if fault == 'foreign':changed[2]['source'] = 'arbitrary'
                with self.subTest(fault=fault),self.assertRaises(ValueError):deployment.carrier_evidence_members(changed,outer)

    def test_post_publication_original_and_retained_mutation_refuse_acceptance(self):
        for fault in ('original','retained'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as directory:
                args = self.fixture(directory); destination = Path(directory)/'retained'
                reader = deployment.bounded_read; mutated = []
                def read(path, maximum, deadline):
                    raw = reader(path,maximum,deadline)
                    if Path(path).name == 'deployment.json' and not mutated:
                        row = args[0]['carrier_materials']['receipts']['authority_document']
                        target = Path(row['path']) if fault == 'original' else destination/('inputs/'+row['sha256'])
                        target.chmod(0o600); target.write_bytes(b'late mutation'); target.chmod(0o444)
                        mutated.append(True)
                    return raw
                with patch.object(deployment,'bounded_read',side_effect=read),self.assertRaises(ValueError):
                    deployment.stage_carrier(*args,destination,time.monotonic()+30)
                self.assertEqual(mutated,[True])

    def test_original_deadline_expiring_after_last_final_authentication_refuses_return(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory); destination = Path(directory)/'retained'
            deadline = time.monotonic()+30; clock = [deadline-1]
            state = {'rows':0,'remaining':None,'expired':False}
            plan = deployment.carrier_retention_plan; reader = deployment.bounded_read
            def planned(*values):
                result = plan(*values); state['rows'] = len(result[2]); return result
            def read(path,maximum,until):
                raw = reader(path,maximum,until)
                if Path(path).name == 'deployment.json':state['remaining'] = 2*state['rows']
                elif state['remaining'] is not None:
                    state['remaining'] -= 1
                    if state['remaining'] == 0:
                        # Last original reader succeeded; its SHA/equality still
                        # happens before the production terminal admission tick.
                        clock[0] = deadline; state['expired'] = True
                return raw
            with patch.object(deployment,'carrier_retention_plan',side_effect=planned),\
                    patch.object(deployment,'bounded_read',side_effect=read),\
                    patch.object(deployment.time,'monotonic',side_effect=lambda:clock[0]),self.assertRaises(ValueError):
                deployment.stage_carrier(*args,destination,deadline)
            self.assertTrue(state['expired'])
            self.assertEqual(state['remaining'],0)
            self.assertTrue((destination/'share/omux/native/codex/deployment.json').is_file())

    def test_candidate_namespace_chooses_one_exact_producer_verifier_without_fallback(self):
        suffix = '/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/'
        root = '/home/jess/.local/state/omux-execution-20261005/model'+suffix
        self.assertEqual(deployment.package_producer_target(root+'codex_native_carrier_runtime_package/test.outputs/fresh-native-runtime'),deployment.CARRIER_TARGET)
        self.assertEqual(deployment.package_producer_target(root+'codex_native_acquisition_runtime_package/test.outputs/fresh-native-runtime'),deployment.TARGET)
        # Added components do not select the new verifier. Genuine namespace
        # validation remains producer_success's obligation for either candidate.
        self.assertEqual(deployment.package_producer_target(root+'codex_native_carrier_runtime_package/test.outputs/fresh-native-runtime/extra'),deployment.TARGET)

if __name__=='__main__':unittest.main()
