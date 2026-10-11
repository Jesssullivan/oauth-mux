"""Actual sealed-file admission fixtures; models never mutate a Root ledger."""
import copy
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import sys
import codex_native_acquisition_compilation as compilation

class CompilationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name); self.deadline=time.monotonic()+20.0
        self.outer_calls=[]
        def outer(selection,target,output_name,deadline):
            self.outer_calls.append((selection,target,output_name,deadline))
            compilation.tick(deadline)
            if selection['producer']!={'fixture':'actual-outer-policy-double'}:
                raise ValueError('outer-policy-refused')
            return {'exit':0,'source_commit':'f'*40,'graph_sha256':'e'*64}
        self.outer=outer
        self.addCleanup(patch.stopall)
        patch.dict(sys.modules,{'codex_native_acquisition_material':SimpleNamespace(producer_success=outer)}).start()
        patch.object(compilation,'controller_inputs',return_value='a'*64).start()
        patch.object(compilation,'PUBLIC_ROOT',self.root).start()
        self.material={'source_inventory_sha256':'1'*64,'sdk_inventory_sha256':'2'*64,
            'mapping_sha256':'3'*64,'patch_sha256':[str(index)*64 for index in range(1,10)]}
        self.document={'material':{'actual_selection':'fixture-only',
            'controller_source_commit':'f'*40,'controller_graph_sha256':'e'*64},
            'controller_inventory_sha256':'a'*64}
        self.carrier={'other_public_carrier_fields':{'retained':True},'native_dispatch_ledger':{
            'aggregate_maximum':8,'dispatched':8,'current_dispatch':8,'remaining':0}}
        raw=compilation.encoded(self.carrier);pin=hashlib.sha256(raw).hexdigest()
        relative=compilation.GOAL_SNAPSHOT_PREFIX+pin+'.json'
        self.snapshot_path=self.root/relative;self.snapshot_path.parent.mkdir(parents=True)
        self.snapshot_path.write_bytes(raw);self.snapshot_path.chmod(0o444)
        ledger={'schema_version':1,'kind':'omux-native-acquisition-root-dispatch-ledger-v1',
            'actor':'Root','phase':'after-pre-action-advancement','aggregate':8,'dispatched':8,
            'remaining':0,'material_sha256':hashlib.sha256(compilation.encoded(self.document['material'])).hexdigest(),
            'controller_inventory_sha256':'a'*64,
            'compiler_controller':{'source_commit':'f'*40,'graph_sha256':'e'*64},
            'goal_snapshot':{'path':relative,'sha256':pin,'bytes':len(raw)}}
        self.document['ledger']=self.seal('ledger',ledger)
        for role in ('plan','query'):
            self.document[role]=self.seal(role,{'schema_version':1,
                'kind':'omux-native-acquisition-'+role+'-qualification-v1','material':self.material,
                'controller_inventory_sha256':'a'*64,'caps':compilation.CAPS,
                'verb':'test','targets':list(compilation.TARGETS),'qualified':True,
                'exit':0,'closure_rechecked':True})
            self.document[role]['producer']={'fixture':'actual-outer-policy-double'}

    def seal(self,name,value):
        path=self.root/name; raw=compilation.encoded(value)
        if path.exists():path.chmod(0o600)
        path.write_bytes(raw); path.chmod(0o444)
        return {'path':str(path),'sha256':hashlib.sha256(raw).hexdigest()}

    def verifier(self,value,deadline):
        self.assertEqual(value,self.document['material']); compilation.tick(deadline)
        return copy.deepcopy(self.material)

    def test_real_sealed_prerequisites_and_ledger_unchanged(self):
        row=self.document['ledger']; before=Path(row['path']).read_bytes()
        actual,_=compilation.prerequisites(self.document,self.deadline,self.verifier)
        self.assertEqual(actual,self.material)
        self.assertEqual(Path(row['path']).read_bytes(),before)
        self.assertEqual([row[1] for row in self.outer_calls],
            ['//tools:codex_native_acquisition_plan_producer','//tools:codex_native_acquisition_query_producer'])

    def test_original_deadline_expired_before_material(self):
        with self.assertRaises(ValueError):
            compilation.prerequisites(self.document,time.monotonic()-1.0,
                lambda *args:self.fail('expired admission reached material'))

    def test_ledger_wrong_remaining_boolean_and_actor_refused(self):
        original=compilation.read_json(**{'path':self.document['ledger']['path'],
            'pin':self.document['ledger']['sha256'],'deadline':self.deadline})
        for changes in ({'remaining':1},{'dispatched':True},{'actor':'model'},
                        {'phase':'before-pre-action-advancement'},{'aggregate':7}):
            self.document['ledger']=self.seal('ledger',{**original,**changes})
            with self.assertRaises(ValueError):compilation.ledger(self.document,self.deadline)

    def test_source_sdk_and_ninth_patch_identity_refused(self):
        for field in ('source_inventory_sha256','sdk_inventory_sha256','mapping_sha256'):
            wrong={**self.material,field:'b'*64}
            with self.assertRaises(ValueError):
                compilation.prerequisites(self.document,self.deadline,lambda *_:wrong)
        wrong={**self.material,'patch_sha256':self.material['patch_sha256'][:-1]}
        with self.assertRaises(ValueError):
            compilation.prerequisites(self.document,self.deadline,lambda *_:wrong)

    def test_actual_plan_query_corruption_and_unqualified_refused(self):
        for role in ('plan','query'):
            original=compilation.read_json(self.document[role]['path'],
                self.document[role]['sha256'],self.deadline)
            self.document[role]=self.seal(role,{**original,'qualified':False})
            self.document[role]['producer']={'fixture':'actual-outer-policy-double'}
            with self.assertRaises(ValueError):
                compilation.prerequisites(self.document,self.deadline,self.verifier)
            self.document[role]=self.seal(role,original)
            self.document[role]['producer']={'fixture':'actual-outer-policy-double'}
            path=Path(self.document[role]['path']);path.chmod(0o600);path.write_bytes(b'corrupted');path.chmod(0o444)
            with self.assertRaises(ValueError):
                compilation.prerequisites(self.document,self.deadline,self.verifier)
            self.document[role]=self.seal(role,original)
            self.document[role]['producer']={'fixture':'actual-outer-policy-double'}

    def test_independent_outer_failure_precedes_claim_receipt(self):
        self.document['query']['producer']={'fixture':'wrong-independent-epoch'}
        with self.assertRaises(ValueError):
            compilation.prerequisites(self.document,self.deadline,self.verifier)
        self.assertEqual(self.outer_calls[-1][1],'//tools:codex_native_acquisition_query_producer')

    def test_actual_unit_test_targets_selected(self):
        self.assertEqual(compilation.TARGETS[:3],('//codex-rs/core:core-unit-tests',
            '//codex-rs/config:config-unit-tests','//codex-rs/login:login-unit-tests'))

    def test_real_query_closure_digest_drift_refused(self):
        with patch.object(compilation,'controller_inputs',side_effect=['a'*64,'b'*64]):
            with self.assertRaises(ValueError):
                compilation.prerequisites(self.document,self.deadline,self.verifier)

    def test_actual_cross_key_ledger_seven_and_current_seven_refused(self):
        wrapper=compilation.read_json(self.document['ledger']['path'],self.document['ledger']['sha256'],self.deadline)
        for changes in ({'dispatched':7,'current_dispatch':7,'remaining':1},
                        {'current_dispatch':7},{'aggregate_maximum':9},{'remaining':False}):
            full=copy.deepcopy(self.carrier);full['native_dispatch_ledger'].update(changes)
            raw=compilation.encoded(full);pin=hashlib.sha256(raw).hexdigest()
            relative=compilation.GOAL_SNAPSHOT_PREFIX+pin+'.json';path=self.root/relative
            path.write_bytes(raw);path.chmod(0o444)
            self.document['ledger']=self.seal('ledger',{**wrapper,
                'goal_snapshot':{'path':relative,'sha256':pin,'bytes':len(raw)}})
            with self.assertRaises(ValueError):compilation.ledger(self.document,self.deadline)

    def test_raw_full_root_snapshot_byte_corruption_and_namespace_refused(self):
        wrapper=compilation.read_json(self.document['ledger']['path'],self.document['ledger']['sha256'],self.deadline)
        bad={**wrapper['goal_snapshot'],'path':'../private.json'}
        self.document['ledger']=self.seal('ledger',{**wrapper,'goal_snapshot':bad})
        with self.assertRaises(ValueError):compilation.ledger(self.document,self.deadline)
        self.document['ledger']=self.seal('ledger',wrapper)
        self.snapshot_path.chmod(0o600);self.snapshot_path.write_bytes(b'corrupt');self.snapshot_path.chmod(0o444)
        with self.assertRaises(ValueError):compilation.ledger(self.document,self.deadline)

    def test_actual_compiler_root_actor_is_independent_and_wrong_actor_refused(self):
        wrapper=compilation.read_json(self.document['ledger']['path'],self.document['ledger']['sha256'],self.deadline)
        self.document['ledger']=self.seal('ledger',{**wrapper,
            'compiler_controller':{'source_commit':'c'*40,'graph_sha256':'d'*64}})
        self.assertNotEqual(compilation.ledger(self.document,self.deadline)['compiler_controller']['source_commit'],
            self.document['material']['controller_source_commit'])
        with self.assertRaises(ValueError):
            compilation.readback(self.document,{'path':str(self.root/'receipt.json'),
                'sha256':'b'*64,'producer':{'fixture':'actual-outer-policy-double'}},self.deadline)

    def test_late_ledger_corruption_after_material_refused(self):
        def corrupt(value,deadline):
            row=self.document['ledger'];path=Path(row['path']);path.chmod(0o600)
            path.write_bytes(b'late-corruption');path.chmod(0o444)
            return self.material
        with self.assertRaises(ValueError):
            compilation.prerequisites(self.document,self.deadline,corrupt)

    def test_real_artifact_schema_xml_and_symlink_refusal(self):
        row=self.seal('schema',{'definitions':{'OmuxBrokerContextMode':{'enum':['full_native','text_transcript_v1']},
            'OmuxBrokerConfig':{'properties':{'context_mode':{'default':'full_native'}}}}})
        raw=Path(row['path']).read_bytes(); artifact={**row,'bytes':len(raw),'role':'config-schema'}
        self.assertEqual(compilation.artifact(artifact,self.deadline),artifact)
        link=self.root/'link';link.symlink_to(row['path'])
        with self.assertRaises(OSError):compilation.artifact({**artifact,'path':str(link)},self.deadline)
        xml=b'<testsuite tests="1" failures="1" errors="0" skipped="0"/>'
        path=self.root/'xml';path.write_bytes(xml);path.chmod(0o444)
        with self.assertRaises(ValueError):compilation.artifact({'path':str(path),
            'sha256':hashlib.sha256(xml).hexdigest(),'bytes':len(xml),'role':'test-xml'},self.deadline)

    def test_exact_owned_command_follows_real_prerequisites(self):
        with patch.object(compilation,'qualify_material',side_effect=self.verifier), \
             patch.object(compilation,'fixed_plan',return_value={'argv':['/locked/bazel','test',*compilation.TARGETS]}) as builder:
            plan=compilation.command(self.document,self.root/'work',self.deadline)
            self.assertEqual(plan['argv'][-6:],list(compilation.TARGETS))
            self.assertEqual(builder.call_args.args,(self.document['material'],self.root/'work',self.deadline))

    def test_full_actual_artifact_tree_and_extra_empty_directory_refused(self):
        import codex_native_profile as native
        root=self.root/'artifacts';root.mkdir();rows=[]
        def retain(name,raw,role):
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(raw);path.chmod(0o444)
            row={'path':str(path),'sha256':hashlib.sha256(raw).hexdigest(),
                'bytes':len(raw),'role':role};rows.append(row)
            compilation.artifact(row,self.deadline)
        elf=bytearray(64);elf[:6]=b'\x7fELF\x02\x01';elf[18:20]=b'\x3e\x00'
        retain('native-cli',bytes(elf),'native-cli')
        retain('schema/config.json',compilation.encoded({'definitions':{
            'OmuxBrokerContextMode':{'enum':['full_native','text_transcript_v1']},
            'OmuxBrokerConfig':{'properties':{'context_mode':{'default':'full_native'}}}}}), 'config-schema')
        for mode in ('stable','experimental'):
            retain('schema/'+mode+'/nested/actual.json',b'{}\n',mode+'-schema')
        for target in compilation.TARGETS[:3]:
            name=target.split(':')[1];gates=native.QUALIFICATION_GATES[target]
            log=('\n'.join('test '+gate+' ... ok' for gate in gates)+
                '\ntest result: ok. '+str(len(gates))+' passed; 0 failed; 0 ignored;\n').encode()
            retain('tests/'+name+'/test.log',log,'test-log')
            retain('tests/'+name+'/test.xml',b'<testsuite tests="1" failures="0" errors="0" skipped="0"/>','test-xml')
        compilation.artifact_closure(root,rows,self.deadline)
        (root/'schema/stable/extra-empty').mkdir()
        with self.assertRaises(ValueError):compilation.artifact_closure(root,rows,self.deadline)

    def test_real_cli_elf_and_late_corruption_refused(self):
        row=self.seal('fake-cli',{'pretend':'native'})
        artifact={**row,'bytes':Path(row['path']).stat().st_size,'role':'native-cli'}
        with self.assertRaises(ValueError):compilation.artifact(artifact,self.deadline)
        path=Path(row['path']);path.chmod(0o600);path.write_bytes(b'late');path.chmod(0o444)
        with self.assertRaises(ValueError):compilation.read_bytes(path,row['sha256'],self.deadline)

if __name__=='__main__':unittest.main()
