"""Actual consumer/producer composition over owned model bytes; no native IO."""
import copy
from contextlib import contextmanager
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import codex_native_staged_compilation_test as producer_models
import codex_native_staged_compilation as staged
import codex_staged_native_package_consumer as consumer
import codex_fresh_native_runtime as fresh


def file_pin(path):
    raw = path.read_bytes()
    return {'path':str(path),'sha256':fresh.digest(raw),'bytes':len(raw)}


class StagedConsumerModels(unittest.TestCase):
    @contextmanager
    def chain(self):
        fixture = producer_models.StagedAdmissionModels(methodName='runTest')
        with fixture.fixture(),patch.object(fresh,'STATE',fixture.state):
            source_raw = fresh.encoded(fixture.source_meta)
            export_raw = fresh.encoded(fixture.export_meta)
            inputs = dict(staged.INPUTS,source_receipt_sha256=fresh.digest(source_raw),
                export_receipt_sha256=fresh.digest(export_raw))
            with patch.object(staged,'INPUTS',inputs):
                receipts,values,files,artifacts = {},{}, {},[]
                for number,role in enumerate(consumer.RUNS,1):
                    admission = fixture.admit(number)
                    try:
                        receipt = fixture.complete(admission)
                        receipts[role] = receipt
                        path = admission.run/'receipt.json'
                        files[role] = file_pin(path)
                        values[role] = path.read_bytes()
                        envelope = admission.run/staged.ARTIFACTS
                        envelope_role = consumer.ARTIFACTS[number-1]
                        files[envelope_role] = file_pin(envelope)
                        values[envelope_role] = envelope.read_bytes()
                        artifacts.append(json.loads(values[envelope_role])['artifacts'])
                    finally:
                        admission.close()
                files['source'] = {'path':inputs['source_root']+'/source-receipt.json',
                    'sha256':fresh.digest(source_raw),'bytes':len(source_raw)}
                files['export'] = {'path':inputs['export_root']+'/receipt.json',
                    'sha256':fresh.digest(export_raw),'bytes':len(export_raw)}
                values.update(source=source_raw,export=export_raw)
                qualified,schema = artifacts[2],artifacts[3]
                for role,pin in (('qualification',qualified['qualification']['group']),
                        ('qualification_xml',qualified['qualification']['xml']),
                        ('config_schema',schema['config_schema'])):
                    files[role] = consumer.without_mode(pin)
                    values[role] = Path(pin['path']).read_bytes()
                files['codex'] = {key:qualified['cli'][key] for key in ('path','sha256','bytes')}
                values['codex'] = Path(files['codex']['path']).read_bytes()
                extra = {pin['path']:pin for pin in (
                    *artifacts[0]['libraries'].values(),qualified['qualification']['manifest'],
                    *qualified['qualification']['logs'].values())}
                protocol = {mode+'/json/'+rest:consumer.without_mode(pin)
                    for name,pin in schema['protocol_schema_files'].items()
                    for mode,rest in [name.split('/',1)]}
                selection = {'kind':consumer.KIND,'files':files,
                    'source_root':inputs['source_root'],'export_root':inputs['export_root'],
                    'patch_sha256':inputs['patch_sha256'],
                    'staged_artifact_files':extra,'protocol_schema_files':protocol,
                    'protocol_schema_roots':schema['protocol_schema_roots']}
                def read(role,pin,maximum):
                    if role in values:
                        return values[role]
                    return fresh.read_selected(Path(pin['path']),pin,maximum)
                yield fixture,selection,values,receipts,artifacts,read

    def test_actual_four_stage_chain_rehashes_three_libraries_all14_logs_and_complete_schemas(self):
        with self.chain() as (_,selection,values,receipts,_,read):
            loaded,protocol,extra = consumer.load_inputs(selection,read)
            result = consumer.validate_artifacts(selection,loaded,protocol,extra,receipts)
            self.assertEqual(result['library_invocation_id'],receipts['library_run']['id'])
            self.assertNotEqual(receipts['compile']['id'],receipts['qualification_run']['id'])
            self.assertEqual(set(result['stages']),set(consumer.RUNS))
            self.assertEqual(len(result['staged_artifact_files']),7)
            fresh.validate_protocol_inventory(selection)

    def test_missing_A_and_reusing_C_as_B_refuse_before_any_actual_output_read(self):
        with self.chain() as (_,selection,values,_,_,read):
            missing = copy.deepcopy(selection)
            del missing['files']['library_run']
            with patch.object(staged,'artifact_file') as output:
                with self.assertRaises(ValueError):consumer.load_inputs(missing,read)
                output.assert_not_called()
            mixed = copy.deepcopy(selection)
            mixed['files']['compile'] = mixed['files']['qualification_run']
            changed = dict(values,compile=values['qualification_run'])
            with patch.object(staged,'artifact_file') as output:
                with self.assertRaises(ValueError):
                    consumer.load_inputs(mixed,lambda role,pin,maximum:changed[role])
                output.assert_not_called()

    def test_positive_pins_do_not_allow_mutated_custody_graph_clock_cleanup_or_history(self):
        with self.chain() as (_,selection,values,_,_,_):
            mutations = (
                lambda row:row['native_staged_compilation']['custody']['output_base'].update(inode=999999),
                lambda row:row['native_staged_compilation']['custody']['root'].update(device=True),
                lambda row:row.update(graph_sha256='0'*64),
                lambda row:row['native_sdk'].update(original_deadline_monotonic_ns=1),
                lambda row:row.update(descendants_empty=False),
                lambda row:row.update(native_fresh_completion={'kind':'old-9/10'}),
                lambda row:row['native_staged_compilation'].update(stage_history=[]),
                lambda row:row['native_sdk']['plan']['argv'].append('--jobs=2'),
            )
            for mutate in mutations:
                selected = copy.deepcopy(selection)
                changed = dict(values)
                row = fresh.parse(changed['compile'])
                mutate(row)
                changed['compile'] = fresh.encoded(row)
                selected['files']['compile'].update(sha256=fresh.digest(changed['compile']),
                    bytes=len(changed['compile']))
                with self.subTest(mutate=mutate),patch.object(staged,'artifact_file') as output:
                    with self.assertRaises(ValueError):
                        consumer.load_inputs(selected,lambda role,pin,maximum:changed[role])
                    output.assert_not_called()

    def test_same_path_replaced_output_directory_cannot_inherit_A_identity(self):
        with self.chain() as (_,selection,values,receipts,_,read):
            path = Path(receipts['library_run']['native_staged_compilation']['output_base'])
            saved = path.with_name('saved-output')
            path.rename(saved)
            path.mkdir(mode=0o700)
            try:
                with patch.object(staged,'artifact_file') as output:
                    with self.assertRaises(ValueError):consumer.load_inputs(selection,read)
                    output.assert_not_called()
            finally:
                path.rmdir()
                saved.rename(path)

    def test_same_inode_fixed_chain_content_change_refuses_before_artifact_reads(self):
        with self.chain() as (_,selection,_,_,_,read):
            raw = staged.CHAIN.read_bytes()
            changed = fresh.parse(raw)
            changed['selector_sha256'] = '0'*64
            staged.CHAIN.chmod(0o600)
            staged.CHAIN.write_bytes(staged.canonical(changed)+b'\n')
            staged.CHAIN.chmod(0o400)
            try:
                with patch.object(staged,'artifact_file') as output:
                    with self.assertRaises(ValueError):consumer.load_inputs(selection,read)
                    output.assert_not_called()
            finally:
                staged.CHAIN.chmod(0o600);staged.CHAIN.write_bytes(raw);staged.CHAIN.chmod(0o400)

    def test_changed_A_library_C_log_and_foreign_D_json_refuse_actual_bytes(self):
        with self.chain() as (_,selection,_,_,artifacts,read):
            paths = (Path(next(iter(artifacts[0]['libraries'].values()))['path']),
                Path(next(iter(artifacts[2]['qualification']['logs'].values()))['path']))
            for path in paths:
                raw,mode = path.read_bytes(),path.stat().st_mode & 0o777
                path.chmod(0o600)
                path.write_bytes(raw+b'foreign replacement\n')
                path.chmod(mode)
                try:
                    with self.subTest(path=path),self.assertRaises(ValueError):
                        consumer.load_inputs(selection,read)
                finally:
                    path.chmod(0o600);path.write_bytes(raw);path.chmod(mode)
            foreign = Path(selection['protocol_schema_roots']['stable'])/'foreign.json'
            foreign.write_bytes(b'{}');foreign.chmod(0o444)
            try:
                with self.assertRaises(ValueError):fresh.validate_protocol_inventory(selection)
            finally:
                foreign.unlink()

    def test_old_completion_dispatch_remains_separate_and_staged_kind_never_accepts_old_roles(self):
        ordinary = {'kind':fresh.SELECTION_KIND,'files':{name:{} for name in fresh.ROLES}}
        self.assertEqual(fresh.package_roles(ordinary),fresh.ROLES)
        with patch.object(fresh,'validate_fresh_completion_receipts',return_value='old reader') as old:
            self.assertEqual(fresh.validate_action_receipts(ordinary,
                {'qualification_run':fresh.encoded({'native_fresh_completion':{'kind':'old'}})}, {},{}),'old reader')
            old.assert_called_once()
        with self.assertRaises(ValueError):consumer.validate_paths(dict(ordinary,kind=consumer.KIND))
        with self.assertRaises(ValueError):fresh.package_roles(dict(ordinary,kind='unknown'))

    def test_staged_package_producer_cannot_omit_reader_code_from_qualified_graph(self):
        graph = ['tools/codex_fresh_native_runtime.py','tools/codex_staged_native_package_consumer.py',
            'tools/codex_native_staged_compilation.py']
        consumer.validate_producer_graph(graph)
        for missing in graph:
            with self.subTest(missing=missing),self.assertRaises(ValueError):
                consumer.validate_producer_graph([path for path in graph if path != missing])
        with self.assertRaises(ValueError):consumer.validate_producer_graph(graph+[graph[0]])

    def test_schema_depth_and_link_refuse_before_foreign_json_byte_reads(self):
        with self.chain() as (_,selection,_,_,_,read):
            root = Path(selection['protocol_schema_roots']['stable'])
            deep = root
            for number in range(17):
                deep = deep/('d'+str(number))
                deep.mkdir(mode=0o700)
            reads = []
            def observed(role,pin,maximum):
                reads.append(role)
                return read(role,pin,maximum)
            try:
                with self.assertRaises(ValueError):consumer.load_inputs(selection,observed)
                self.assertFalse(any(role.startswith('protocol/') for role in reads))
            finally:
                while deep != root:
                    parent = deep.parent;deep.rmdir();deep = parent
            linked = root/'linked.json'
            linked.symlink_to(root/'ClientRequest.json')
            try:
                with self.assertRaises(ValueError):consumer.load_inputs(selection,observed)
            finally:
                linked.unlink()


if __name__ == '__main__':
    unittest.main()
