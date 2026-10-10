"""Declared package models use real completed journals/artifacts; native work is synthetic.

Only external source/SDK qualification and temporary producer path scopes are
stubbed in joined-chain models. No process, vault, provider or compiler runs.
"""
import copy
from contextlib import contextmanager
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import codex_protocol_history_package_consumer as subject
import codex_protocol_history_completed_inputs_test as fixtures
import codex_protocol_history_source as history


def pin(path):
    raw=Path(path).read_bytes()
    return {'path':str(path),'sha256':subject.fresh.digest(raw),'bytes':len(raw)}


def no_mode(value):
    return {key:item for key,item in value.items() if key!='mode'}


@contextmanager
def joined(root):
    model=fixtures.CompletedFixture(root,with_cli=True)
    source_report={'inventory_sha256':model.document['source']['inventory_sha256']}
    export_report={'inventory_sha256':model.document['sdk']['inventory_sha256']}
    for role,leaf,report in (('source','source-receipt.json',source_report),('sdk','receipt.json',export_report)):
        directory=Path(model.document[role]['root']);directory.chmod(0o700)
        path=directory/leaf;path.write_bytes(fixtures.encoded(report));path.chmod(0o444)
        directory.chmod(0o555)
        model.document[role]['receipt_sha256']=pin(path)['sha256']
    original=root/'protocol-history-native-selection.json'
    original.chmod(0o600);original.write_bytes(fixtures.old_models.source.encoded(model.document));original.chmod(0o400)
    with model as active,patch.object(subject.fresh,'STATE',root),\
            patch.object(subject.fresh,'DEADLINE',time.monotonic()+120),\
            patch.object(subject,'_producer_path'),\
            patch.object(subject,'source_sdk',return_value=(source_report,export_report,active.qualified[1])):
        files={'source':pin(Path(active.document['source']['root'])/'source-receipt.json'),
            'export':pin(Path(active.document['sdk']['root'])/'receipt.json'),
            'protocol_run':pin(root/active.receipts[1]['id']/'receipt.json'),
            'schema_run':pin(root/active.receipts[2]['id']/'receipt.json'),
            'compile':pin(root/active.cli_receipt['id']/'receipt.json'),
            'qualification_run':pin(root/active.cli_receipt['id']/'receipt.json'),
            'protocol_artifacts':pin(root/active.receipts[1]['id']/subject.protocol.ARTIFACTS),
            'schema_artifacts':pin(root/active.receipts[2]['id']/subject.protocol.ARTIFACTS),
            'cli_artifacts':pin(root/active.cli_receipt['id']/subject.cli.ARTIFACTS)}
        new=active.cli_envelope['artifacts'];schema=active.envelopes[2]['artifacts']
        files.update(codex={key:new['cli'][key] for key in ('path','sha256','bytes')},
            qualification=no_mode(new['qualification']['group']),
            qualification_xml=no_mode(new['qualification']['xml']),config_schema=no_mode(schema['config_schema']))
        extras={}
        for artifacts in (active.envelopes[1]['artifacts'],new['qualification']):
            for value in (artifacts['manifest'],*artifacts['logs'].values()):extras[value['path']]=value
        document={'kind':subject.KIND,'source_root':active.document['source']['root'],
            'export_root':active.document['sdk']['root'],'patch_sha256':history.PARENT_PATCHES+[history.PATCH_SHA],
            'files':files,'protocol_schema_roots':schema['protocol_schema_roots'],
            'protocol_schema_files':{mode+'/json/'+rest:no_mode(value)
                for name,value in schema['protocol_schema_files'].items()
                for mode,rest in [name.split('/',1)]},
            'native_cli_selection':active.selection,'protocol_history_artifact_files':extras}
        yield active,document


def load(document):
    return subject.load_inputs(document,lambda role,value,maximum:
        subject.fresh.read_selected(Path(value['path']),value,maximum))


class ProtocolHistoryPackageModels(unittest.TestCase):
    def test_actual_three_successful_runs_and_declared_seven_logs_join(self):
        with tempfile.TemporaryDirectory() as temporary,joined(Path(temporary)) as (model,document):
            values,schemas,extra=load(document)
            chain=subject.validate_chain(document,values,schemas,extra)
            self.assertEqual(len(values),13);self.assertEqual(len(extra),7)
            self.assertEqual(chain['compile_invocation_id'],model.cli_receipt['id'])
            self.assertNotEqual(chain['compile_invocation_id'],chain['schema_invocation_id'])
            self.assertEqual(chain['patch_sha256'],history.PARENT_PATCHES+[history.PATCH_SHA])
            self.assertEqual(chain['compile_evidence_kind'],'protocol-history-explicit-cli-and-fourteen')
            self.assertEqual(len(chain['qualified_tests']),3)

    def test_failed_or_boolean_cli_receipt_refuses_before_executable_and_schema_reads(self):
        for failure in (False,124,125):
            with self.subTest(exit=failure),tempfile.TemporaryDirectory() as temporary,\
                    joined(Path(temporary)) as (model,document):
                changed=copy.deepcopy(model.cli_receipt);changed['exit']=failure
                path=Path(document['files']['compile']['path']);path.chmod(0o600)
                path.write_bytes(fixtures.encoded(changed));path.chmod(0o600)
                document['files']['compile']=document['files']['qualification_run']=pin(path)
                roles=[]
                def read(role,value,maximum):
                    roles.append(role)
                    return subject.fresh.read_selected(Path(value['path']),value,maximum)
                with self.assertRaises(ValueError):subject.load_inputs(document,read)
                self.assertNotIn('codex',roles);self.assertNotIn('config_schema',roles)

    def test_same_path_output_replacement_is_not_adopted(self):
        with tempfile.TemporaryDirectory() as temporary,joined(Path(temporary)) as (model,document):
            output=Path(model.cli_receipt['output_base'])
            output.rename(output.parent/'old-output');output.mkdir(mode=0o700)
            with patch.object(subject.cli,'collect_artifacts') as output_reader,self.assertRaises(ValueError):
                load(document)
            output_reader.assert_not_called()

    def test_pending_cli_journal_is_not_success(self):
        with tempfile.TemporaryDirectory() as temporary,joined(Path(temporary)) as (model,document):
            path=Path(model.cli_receipt['output_base']).parent/subject.cli.JOURNAL
            value=json.loads(path.read_bytes());value['status']='pending'
            path.chmod(0o600);path.write_bytes(fixtures.encoded(value));path.chmod(0o600)
            with self.assertRaises(ValueError):load(document)

    def test_controller_graph_substitution_cannot_be_hidden_by_outer_pin(self):
        with tempfile.TemporaryDirectory() as temporary,joined(Path(temporary)) as (model,document):
            value=copy.deepcopy(model.cli_receipt);value['graph_sha256']='0'*64
            path=Path(document['files']['compile']['path']);path.write_bytes(fixtures.encoded(value))
            document['files']['compile']=document['files']['qualification_run']=pin(path)
            with self.assertRaises(ValueError):load(document)

    def test_changed_actual_named_log_and_complete_schema_membership_are_required(self):
        for change in ('log','extra_schema'):
            with self.subTest(change=change),tempfile.TemporaryDirectory() as temporary,\
                    joined(Path(temporary)) as (model,document):
                if change=='log':
                    path=Path(next(iter(model.cli_envelope['artifacts']['qualification']['logs'].values()))['path'])
                    path.write_bytes(path.read_bytes()+b'test unrelated_case ... ok\n')
                else:
                    path=Path(document['protocol_schema_roots']['stable'])/'Undeclared.json'
                    path.write_bytes(b'{}\n');path.chmod(0o444)
                with self.assertRaises(ValueError):load(document)

    def test_missing_or_reassigned_declared_evidence_alias_refuses(self):
        with tempfile.TemporaryDirectory() as temporary,joined(Path(temporary)) as (model,document):
            with self.assertRaises(ValueError):
                subject.load_inputs(document,lambda role,value,maximum:
                    subject.fresh.read_selected(Path(value['path']),value,maximum),
                    lambda role,value:Path(value['path']).parent/'different.evidence')
            del document['protocol_history_artifact_files'][next(iter(document['protocol_history_artifact_files']))]
            with self.assertRaises(ValueError):load(document)

    def test_schema_and_cli_paths_cannot_be_swapped_into_closed_failed_cache_namespace(self):
        with tempfile.TemporaryDirectory() as temporary,joined(Path(temporary)) as (_,document):
            for role in ('codex','config_schema'):
                wrong=copy.deepcopy(document)
                path=wrong['files'][role]['path']
                wrong['files'][role]['path']=path.replace('protocol-history-cli-','cache-v2-').replace(
                    'protocol-history-checks-','cache-v2-')
                with self.subTest(role=role),self.assertRaises(ValueError):subject.validate_paths(wrong)

    def test_real_producer_namespace_and_partial_role_schema_refuse_before_io(self):
        for role in ('source','export'):
            with self.subTest(role=role),self.assertRaises(ValueError):
                subject._producer_path(role,'/private/receipt.json')
        with tempfile.TemporaryDirectory() as temporary,joined(Path(temporary)) as (_,document):
            del document['files']['protocol_run']
            with patch.object(subject.fresh,'read_selected') as reader,self.assertRaises(ValueError):
                subject.load_inputs(document,reader)
            reader.assert_not_called()

    def test_old_source_kind_extra_claim_and_wrong_fourth_patch_are_refused(self):
        # Header failures precede full inventory IO. Actual factory/SDK models
        # independently qualify genuine transformed and selected-export bytes.
        report={key:None for key in subject.SOURCE_FIELDS}
        report.update(schema_version=1,kind=history.KIND,status='verified-protocol-history-source-pending-sdk-metadata',
            commit=subject.fresh.COMMIT,parent_source_root=str(history.PARENT),
            parent_source_receipt_sha256=history.PARENT_RECEIPT_SHA,
            parent_source_inventory_sha256=history.PARENT_INVENTORY_SHA,
            patch_sha256=history.PARENT_PATCHES+[history.PATCH_SHA],
            sdk_metadata_qualified=False,native_support=False,native_compile_passed=False,provider_evaluation=False)
        document={'kind':subject.KIND,'patch_sha256':report['patch_sha256']}
        for change in ('kind','extra','patch','claim'):
            value=copy.deepcopy(report)
            if change=='kind':value['kind']='omux-native-source-v1'
            elif change=='extra':value['future_support']=True
            elif change=='patch':value['patch_sha256'][-1]='0'*64
            else:value['native_support']=True
            with self.subTest(change=change),self.assertRaises(ValueError):
                subject.source_sdk(document,{'source':fixtures.encoded(value),'export':b'{}'})


if __name__=='__main__':
    unittest.main()
