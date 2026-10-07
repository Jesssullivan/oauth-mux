"""Finite public path, full JSON inventory and ELF-edge models; no tools invoked."""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import codex_fresh_native_runtime as fresh


def elf(needed=(), interpreter=None, rpath=()):
    strings, references = bytearray(b'\0'), []
    for tag, value in [(1,n) for n in needed] + ([(29,':'.join(rpath))] if rpath else []):
        references.append((tag,len(strings)))
        strings.extend(value.encode()+b'\0')
    count = 2+(interpreter is not None)
    dyn = 64+56*count
    size = 16*(len(references)+3)
    off = dyn+size
    interp = b'' if interpreter is None else interpreter.encode()+b'\0'
    ioff, base = off+len(strings), 0x400000
    length = ioff+len(interp)
    header = b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',3,62,1,0,64,0,0,64,56,count,0,0,0)
    heads = struct.pack('<IIQQQQQQ',1,5,0,base,base,length,length,4096)
    heads += struct.pack('<IIQQQQQQ',2,4,dyn,base+dyn,0,size,size,8)
    if interpreter is not None:
        heads += struct.pack('<IIQQQQQQ',3,4,ioff,base+ioff,0,len(interp),len(interp),1)
    return header+heads+b''.join(struct.pack('<qQ',t,v) for t,v in references+[(5,base+off),(10,len(strings)),(0,0)])+strings+interp


class FreshRuntimeModels(unittest.TestCase):
    def bundle(self, outside=False):
        r = fresh.runtime
        loader = r.PREFIX+'lib/ld-linux-x86-64.so.2'
        libc = r.PREFIX+'lib/libc.so.6'
        backend = elf(('outside.so' if outside else 'libc.so.6',),
            fresh.portable._BACKEND_INTERPRETER,('$ORIGIN/../lib',))
        files = {r.BACKEND:backend,loader:elf(),libc:elf(),
            r.CA:b'-----BEGIN CERTIFICATE-----\ncHVibGlj\n-----END CERTIFICATE-----\n',
            'bin/codex':r.codex_launcher('ld-linux-x86-64.so.2')}
        inventory = {n:{'sha256':fresh.digest(v),'bytes':len(v),'mode':0o644 if n==r.CA else 0o755} for n,v in files.items()}
        manifest = {'kind':fresh.KIND,'status':fresh.STATUS,'native_support':False,'provider_evaluation':False,
            'experimental_text_policy_compiled':True,'chain':{'fixture':'ELF-model-only'},
            'executable':{'packaged_sha256':fresh.digest(backend),'packaged_bytes':len(backend)},
            'selection_sha256':'a'*64,'producer_source_sha256':'b'*64,
            'producer_target':'//tools:codex_fresh_native_runtime_package','files':inventory,
            'runtime':{'dependencies':sorted((loader,libc)),'loader':loader,'caBundle':r.CA,
                'backendInterpreter':fresh.portable._BACKEND_INTERPRETER}}
        payload = r.archive_bytes(files,manifest)
        receipt = {k:manifest[k] for k in ('kind','status','native_support','provider_evaluation',
            'experimental_text_policy_compiled','chain','executable','selection_sha256',
            'producer_source_sha256','producer_target')}
        receipt.update(archive_bytes=len(payload),archive_sha256=fresh.digest(payload),
            manifest_sha256=fresh.digest(fresh.encoded(manifest)),
            runtime_inventory={n:{'sha256':row['sha256'],'bytes':row['bytes'],
                'mode':0o444 if n==r.CA else 0o555} for n,row in inventory.items()})
        return payload,receipt,files

    def test_archive_accepts_closed_fixture_and_refuses_outside_elf_or_inventory(self):
        payload,receipt,files = self.bundle()
        self.assertEqual(fresh.verify_runtime_files(payload,receipt)[1],files)
        for field,value in (('archive_sha256','0'*64),('native_support',True),
                ('experimental_text_policy_compiled',False),('kind','retained009')):
            with self.assertRaises(ValueError):
                fresh.verify_runtime_files(payload,{**receipt,field:value})
        changed = copy.deepcopy(receipt)
        changed['runtime_inventory'][fresh.runtime.BACKEND]['mode'] = 0o755
        with self.assertRaises(ValueError):
            fresh.verify_runtime_files(payload,changed)
        payload,receipt,_ = self.bundle(outside=True)
        with self.assertRaises(ValueError):
            fresh.verify_runtime_files(payload,receipt)

    def test_complete_generated_json_inventory_refuses_extra_missing_and_links(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(fresh,'STATE',Path(temporary)):
            roots, files = {}, {}
            prefix = Path(temporary)/('cache-v2-'+'a'*64)/'output-base/execroot/_main/bazel-out/k8-opt/bin/bazel/schema'
            for mode in ('stable','experimental'):
                root = prefix/('public-schema-bundle.'+mode)/'json'
                root.mkdir(parents=True)
                (root/'ClientRequest.json').write_bytes(b'{}')
                (root/'ClientRequest.json').chmod(0o400)
                roots[mode] = str(root)
                files[mode+'/json/ClientRequest.json'] = {}
            selected = {'protocol_schema_roots':roots,'protocol_schema_files':files}
            for folder,_,_ in os.walk(temporary):
                Path(folder).chmod(0o700)
            fresh.validate_protocol_inventory(selected)
            root = Path(roots['stable'])
            (root/'extra.json').write_bytes(b'{}')
            (root/'extra.json').chmod(0o400)
            with self.assertRaises(ValueError):
                fresh.validate_protocol_inventory(selected)
            (root/'extra.json').unlink()
            (root/'ClientRequest.json').unlink()
            with self.assertRaises(ValueError):
                fresh.validate_protocol_inventory(selected)
            (root/'ClientRequest.json').symlink_to(Path(roots['experimental'])/'ClientRequest.json')
            with self.assertRaises(ValueError):
                fresh.validate_protocol_inventory(selected)

    def test_export_producer_binding_and_empty_epoch(self):
        home = '/home/jess/.local/state/omux-execution-20261005'
        fast = '/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005'
        epoch = '5c6a5577-0000-4000-8000-000000000000'
        direct = fast+'/'+epoch+'/sdk-private/sdk-export/receipt.json'
        historical = home+'/'+epoch+'/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_retained_sdk_export_producer/test.outputs/sdk-private/sdk-export/receipt.json'
        with patch.object(fresh,'canonical_path',side_effect=Path):
            for path,producer in ((direct,'//tools:codex_retained_sdk_export_run'),
                    (historical,'//tools:codex_retained_sdk_export_producer')):
                selected = {'files':{'export':{'path':path}}}
                fresh.validate_export_producer(selected,{'producer':producer})
                for wrong in (None,'//tools:codex_retained_sdk_export_run' if 'producer' in producer else '//tools:codex_retained_sdk_export_producer','//tools:other'):
                    with self.subTest(path=path,wrong=wrong), self.assertRaises(ValueError):
                        fresh.validate_export_producer(selected,{'producer':wrong})
            for role,path in (('export',fast),('export',home),('source',fast),
                    ('source',direct),('export',home+'/'+epoch+'/sdk-private/sdk-export/receipt.json')):
                with self.subTest(role=role,path=path), self.assertRaises(ValueError):
                    fresh.validate_public_receipt_path(role,path)

    def test_foreign_role_paths_are_refused_before_any_file_read(self):
        selection = {'kind':fresh.SELECTION_KIND,
            'files':{role:{'path':'/private/credentials.json'} for role in fresh.ROLES},
            'protocol_schema_files':{}}
        with self.assertRaises(ValueError):
            fresh.validate_selection_paths(selection)

    def test_exact_source_cache_and_public_export_namespaces(self):
        home = '/home/jess/.local/state/omux-execution-20261005/'
        fast = '/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/'
        epoch = '5c6a5577-0000-4000-8000-000000000000'
        cache = 'cache-v2-'+'a'*64
        prefix = '/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/'
        source_tail = prefix+'codex_live_source_producer/test.outputs/codex-live-source/source-receipt.json'
        export_tail = prefix+'codex_retained_sdk_export_producer/test.outputs/sdk-private/sdk-export/receipt.json'
        run_tail = '/sdk-private/sdk-export/receipt.json'
        accepted = (('source',home+epoch+source_tail,'//tools:codex_live_source_producer'),
                    ('source',home+cache+source_tail,'//tools:codex_live_source_producer'),
                    ('export',home+epoch+export_tail,'//tools:codex_retained_sdk_export_producer'),
                    ('export',fast+epoch+export_tail,'//tools:codex_retained_sdk_export_producer'),
                    ('export',fast+epoch+run_tail,'//tools:codex_retained_sdk_export_run'))
        refused = [('source',fast+epoch+source_tail),('source',fast+cache+source_tail),
                   ('source',home+epoch+export_tail),('source',home+epoch+run_tail),
                   ('export',home+epoch+run_tail),('export',home+cache+export_tail),
                   ('export',fast+cache+export_tail),('export',fast+cache+run_tail),
                   ('export',fast+epoch+source_tail),('export',fast+epoch+'/extra'+run_tail),
                   ('source',home+epoch+'/extra'+source_tail),('source','/foreign/'+epoch+source_tail)]
        for bad in ('short',epoch.upper(),epoch+'0','cache-v2-'+'a'*63,'cache-v2-'+'g'*64,'cache-'+'a'*64):
            refused.extend((('source',home+bad+source_tail),('export',fast+bad+run_tail)))
        with patch.object(fresh,'canonical_path',side_effect=Path):
            for role,path,producer in accepted:
                with self.subTest(role=role,path=path):
                    self.assertEqual(fresh.validate_public_receipt_path(role,path),producer)
                    for changed in (path+'/extra',path.replace('receipt.json','receipt.json.bak')):
                        with self.assertRaises(ValueError): fresh.validate_public_receipt_path(role,changed)
            for role,path in refused:
                with self.subTest(role=role,path=path),self.assertRaises(ValueError):
                    fresh.validate_public_receipt_path(role,path)



class CombinedActionChainModels(unittest.TestCase):
    def fresh_fixture(self):
        from codex_native_fresh_completion import consumed_dispatches
        from codex_native_profile import core_codegen_policy
        import codex_native_profile as native
        selection,values,source,exported = self.fixture()
        key = '9'*64
        base = fresh.STATE/('cache-v2-'+key)/'output-base'
        history = consumed_dispatches()
        exported['mapping_sha256'] = '8'*64
        for role,attempt in (('qualification_run',9),('schema_run',10)):
            value = fresh.parse(values[role])
            candidate = {'kind':'omux-native-fresh-core-completion-v1','key':key,'provenance_sha256':key,
                'workspace':str(base.parent/'native-input/source'),'output_base':str(base),
                'global_attempt':attempt,'max_global_attempts':10,'verified_before_launch':True,
                'source_commit':'7'*40,'selector_sha256':'6'*64,
                'verified_after_cleanup':True,'core_codegen':core_codegen_policy(),
                'previous_dispatches':copy.deepcopy(history)}
            if attempt == 10:
                prior = fresh.parse(values['qualification_run'])
                candidate['previous_dispatches'].append({'id':prior['id'],
                    'sha256':selection['files']['qualification_run']['sha256'],'cache_key':key,'attempt':9})
            value.update(native_candidate_cache=None,native_fresh_completion=candidate,
                test_evidence={'state':'preserved' if attempt == 9 else 'not-applicable'},
                manager='system',source_dirty='false',source_commit='7'*40,output_base=str(base),
                unit='omux-execution-'+value['id']+'.service')
            value['native_sdk'].update(aggregate_seconds=3600,original_entry_monotonic_ns=100*10**9,
                original_deadline_monotonic_ns=3700*10**9)
            value['native_sdk']['plan'].update(candidate_output_base=str(base),core_codegen=core_codegen_policy())
            value['native_sdk']['plan'].update(cwd=candidate['workspace'],mapping_sha256=exported['mapping_sha256'],
                environment={'USE_BAZEL_VERSION':native.BAZEL_VERSION},
                argv=[fresh.BAZEL,*native.core_codegen_arguments(),'--lockfile_mode=error',
                    '--repository_disable_download','--sandbox_default_allow_network=false','--jobs=1',
                    '--host_jvm_args=-Xmx768m','--repo_contents_cache=','--disk_cache=',
                    '--remote_executor=','--remote_cache=','--local_test_jobs=1'])
            raw = fresh.encoded(value)
            values[role] = raw
            selection['files'][role].update(sha256=fresh.digest(raw),bytes=len(raw))
            if attempt == 9:
                selection['files']['compile'] = dict(selection['files'][role])
                values['compile'] = raw
        return selection,values,source,exported

    def test_dedicated_fresh_completion_joins_real_nine_and_ten(self):
        selection,values,source,exported = self.fresh_fixture()
        receipts,key,combined = fresh.validate_action_receipts(selection,values,source,exported)
        self.assertTrue(combined)
        self.assertIsNone(receipts['compile']['native_candidate_cache'])
        self.assertEqual(receipts['compile'],receipts['qualification_run'])
        self.assertEqual(receipts['schema_run']['native_fresh_completion']['global_attempt'],10)

    def test_fresh_completion_refuses_false_null_oom_history_policy_or_namespace(self):
        mutations = (
            ('qualification_run',lambda r:r.update(manager='user')),
            ('qualification_run',lambda r:r.update(source_dirty='true')),
            ('schema_run',lambda r:r.update(source_commit='0'*40)),
            ('schema_run',lambda r:r['native_fresh_completion'].update(selector_sha256='0'*64)),
            ('qualification_run',lambda r:r.update(unit='other.service')),
            ('qualification_run',lambda r:r.update(output_base='/old/output-base')),
            ('qualification_run',lambda r:r['native_sdk'].update(original_entry_monotonic_ns=True)),
            ('schema_run',lambda r:r['native_sdk'].update(original_deadline_monotonic_ns=True)),
            ('qualification_run',lambda r:r['native_sdk']['plan']['argv'].remove('--disk_cache=')),
            ('qualification_run',lambda r:r.update(exit=False)),
            ('qualification_run',lambda r:r.update(workload_exit=None)),
            ('qualification_run',lambda r:r.update(exit=137,workload_exit=137)),
            ('qualification_run',lambda r:r.update(native_candidate_cache={'key':'9'*64})),
            ('qualification_run',lambda r:r['native_fresh_completion'].update(verified_before_launch=None)),
            ('schema_run',lambda r:r['native_fresh_completion'].update(verified_after_cleanup=False)),
            ('schema_run',lambda r:r['native_fresh_completion'].update(global_attempt=11)),
            ('qualification_run',lambda r:r['native_fresh_completion']['previous_dispatches'].pop()),
            ('schema_run',lambda r:r['native_fresh_completion']['previous_dispatches'][-1].update(sha256='0'*64)),
            ('qualification_run',lambda r:r['native_fresh_completion'].update(workspace='/old/source')),
            ('qualification_run',lambda r:r['native_sdk']['plan']['core_codegen']['policy']['options'].append('-Clto=fat')),
            ('schema_run',lambda r:r['native_sdk'].update(original_deadline_monotonic_ns=7300*10**9)),
            ('schema_run',lambda r:r.update(test_evidence={'state':'preserved'})),
            ('qualification_run',lambda r:r.update(test_evidence={'state':'not-applicable'})),
            ('schema_run',lambda r:r.update(test_evidence={'state':'preservation-incomplete'})))
        for role,mutate in mutations:
            selection,values,source,exported = self.fresh_fixture()
            self.change(selection,values,role,mutate)
            with self.subTest(role=role),self.assertRaises(ValueError):
                fresh.validate_action_receipts(selection,values,source,exported)

    def fixture(self, combined=True, phase2=False):
        origin=fresh.PHASE2_PRIOR_TRANSITION['from_provenance_sha256'] if phase2 else 'a'*64
        provenance='b'*64 if combined else origin; graph='c'*64
        first_attempt=6 if phase2 else 5
        base=fresh.STATE/('cache-v2-'+origin)/'output-base'
        source={'inventory_sha256':'1'*64}; exported={'inventory_sha256':'2'*64}
        files={'source':{'sha256':'3'*64},'export':{'sha256':'4'*64}}
        transition={'schema_version':1,'amendment_sha256':'d'*64,
            'prior_epoch':'12345678-1234-4234-8234-123456789aaa','prior_cleanup_receipt_sha256':'e'*64,
            'from_controller_graph_sha256':'f'*64,'to_controller_graph_sha256':graph,
            'from_provenance_sha256':origin,'to_provenance_sha256':provenance,
            'from_attempt':4,'first_attempt':5,'aggregate_before':6,'aggregate_max':8}
        if phase2:
            transition.update(schema_version=2,prior_epoch=fresh.PHASE2_FAILED_EPOCH,
                prior_cleanup_receipt_sha256=fresh.PHASE2_FAILED_RECEIPT,
                from_controller_graph_sha256=fresh.PHASE2_PRIOR_TRANSITION['to_controller_graph_sha256'],
                from_provenance_sha256=fresh.PHASE2_PRIOR_TRANSITION['to_provenance_sha256'],
                from_attempt=5,first_attempt=6,aggregate_before=7,aggregate_max=9)
        specs=(('qualification_run',fresh.COMBINED_MODE,(*tuple(fresh.QUALIFICATION_GATES),fresh.CLI),first_attempt),
            ('schema_run','schema',('//bazel/schema:native-config-schema','//bazel/schema:public-schema-bundle'),first_attempt+1)) if combined else (
            ('compile','cli-opt',(fresh.CLI,),1),
            ('qualification_run','qualification',tuple(fresh.QUALIFICATION_GATES),2),
            ('schema_run','schema',('//bazel/schema:native-config-schema','//bazel/schema:public-schema-bundle'),3))
        previous=[{'id':'87654321-1234-4234-8234-%012d'%n,
            'sha256':hashlib.sha256(('prior%d'%n).encode()).hexdigest(),
            'cache_key':origin,'attempt':min(n,4)} for n in range(1,7)]
        if phase2:
            previous.append({'id':fresh.PHASE2_FAILED_EPOCH,'sha256':fresh.PHASE2_FAILED_RECEIPT,
                'cache_key':origin,'attempt':5})
        values={}
        for role,mode,targets,attempt in specs:
            epoch='12345678-1234-4234-8234-%012d'%attempt
            candidate={'key':origin,'provenance_sha256':provenance,'workspace':str(base.parent/'native-input/source'),
                'output_base':str(base),'max_attempts':7 if phase2 else 6,'attempt':attempt}
            if combined:
                history=list(previous)
                if role=='schema_run':
                    prior=fresh.parse(values['qualification_run'])
                    history.append({'id':prior['id'],'sha256':files['qualification_run']['sha256'],
                        'cache_key':origin,'attempt':first_attempt})
                candidate.update(origin_provenance_sha256=origin,
                    transition_history=([copy.deepcopy(fresh.PHASE2_PRIOR_TRANSITION)] if phase2 else [])+[transition],
                    aggregate_attempt=attempt+2,aggregate_max_attempts=9 if phase2 else 8,
                    transition_verified_after_cleanup=True,aggregate_previous_dispatches=history)
            if phase2:
                candidate['phase2_verified_before_launch']=True
            receipt={'id':epoch,'profile':'codex-native','exit':0,'workload_exit':0,
                'descendants_empty':True,'controller_failure':None,'graph_sha256':graph,
                'targets':list(targets),'native_candidate_cache':candidate,
                'native_sdk':{'mode':mode,'source_and_export_verified_after_cleanup':True,
                    'source_receipt_sha256':files['source']['sha256'],'export_receipt_sha256':files['export']['sha256'],
                    'plan':{'candidate_output_base':str(base),'source_inventory_sha256':source['inventory_sha256'],
                        'export_inventory_sha256':exported['inventory_sha256'],'argv':[fresh.BAZEL]}}}
            if phase2:
                receipt['native_sdk'].update(aggregate_seconds=3600,
                    original_entry_monotonic_ns=100*10**9,
                    original_deadline_monotonic_ns=3700*10**9)
            raw=fresh.encoded(receipt); values[role]=raw
            files[role]={'path':str(fresh.STATE/epoch/'receipt.json'),'sha256':fresh.digest(raw),'bytes':len(raw)}
        if combined:
            files['compile']=dict(files['qualification_run']); values['compile']=values['qualification_run']
        return {'files':files},values,source,exported

    def change(self, selection, values, role, mutate):
        receipt=fresh.parse(values[role]); mutate(receipt); values[role]=fresh.encoded(receipt)
        if role=='qualification_run' and selection['files']['compile']==selection['files'][role]:
            values['compile']=values[role]

    def test_two_actual_combined_and_schema_receipts_and_old_three_actions_both_join(self):
        for combined in (True,False):
            selection,values,source,exported=self.fixture(combined)
            receipts,cache,observed=fresh.validate_action_receipts(selection,values,source,exported)
            self.assertEqual(observed,combined)
            self.assertEqual(len({row['id'] for row in receipts.values()}),2 if combined else 3)
            self.assertEqual(receipts['compile']['native_sdk']['mode'],fresh.COMBINED_MODE if combined else 'cli-opt')

    def test_failed_role_wrong_targets_cleanup_graph_key_counter_or_fake_cli_opt_refuses(self):
        mutations=(
            ('schema_run',lambda r:r.update(exit=1)),
            ('schema_run',lambda r:r.update(descendants_empty=False)),
            ('qualification_run',lambda r:r['native_sdk'].update(mode='cli-opt')),
            ('qualification_run',lambda r:r.update(targets=list(fresh.QUALIFICATION_GATES))),
            ('schema_run',lambda r:r.update(graph_sha256='9'*64)),
            ('schema_run',lambda r:r['native_candidate_cache'].update(provenance_sha256='9'*64)),
            ('schema_run',lambda r:r['native_candidate_cache'].update(aggregate_attempt=7)),
            ('qualification_run',lambda r:r['native_candidate_cache'].update(transition_history=[])),
            ('qualification_run',lambda r:r['native_candidate_cache'].update(attempt=6)),
            ('schema_run',lambda r:r['native_candidate_cache'].update(attempt=5)),
            ('schema_run',lambda r:r['native_candidate_cache'].update(transition_verified_after_cleanup=False)),
            ('qualification_run',lambda r:r['native_candidate_cache'].pop('transition_verified_after_cleanup')),
            ('schema_run',lambda r:r['native_candidate_cache'].update(aggregate_max_attempts=9)),
            ('schema_run',lambda r:r['native_candidate_cache'].update(aggregate_previous_dispatches=[])),
            ('schema_run',lambda r:r['native_sdk'].update(source_and_export_verified_after_cleanup=False)))
        for role,mutate in mutations:
            selection,values,source,exported=self.fixture()
            self.change(selection,values,role,mutate)
            with self.subTest(role=role,mutate=mutate),self.assertRaises(ValueError):
                fresh.validate_action_receipts(selection,values,source,exported)


    def test_phase2_retry_and_independent_schema_preserve_actual_failed_fifth_dispatch(self):
        selection,values,source,exported=self.fixture(phase2=True)
        receipts,cache,combined=fresh.validate_action_receipts(selection,values,source,exported)
        self.assertTrue(combined)
        qualification=receipts['qualification_run']['native_candidate_cache']
        schema=receipts['schema_run']['native_candidate_cache']
        self.assertEqual((qualification['attempt'],schema['attempt']),(6,7))
        self.assertEqual((qualification['aggregate_attempt'],schema['aggregate_attempt']),(8,9))
        self.assertEqual(qualification['transition_history'][0],fresh.PHASE2_PRIOR_TRANSITION)
        self.assertEqual(qualification['aggregate_previous_dispatches'][-1]['sha256'],fresh.PHASE2_FAILED_RECEIPT)

    def test_phase2_cannot_relabel_timeout_skip_history_reset_budget_or_broaden_limits(self):
        mutations=(
            ('qualification_run',lambda r:r.update(exit=125,workload_exit=124)),
            ('qualification_run',lambda r:r['native_candidate_cache'].update(attempt=5)),
            ('schema_run',lambda r:r['native_candidate_cache'].update(attempt=6)),
            ('schema_run',lambda r:r['native_candidate_cache'].update(max_attempts=8)),
            ('schema_run',lambda r:r['native_candidate_cache'].update(aggregate_max_attempts=10)),
            ('qualification_run',lambda r:r['native_candidate_cache']['transition_history'][0].update(amendment_sha256='9'*64)),
            ('qualification_run',lambda r:r['native_candidate_cache']['transition_history'][0].update(schema_version=True)),
            ('qualification_run',lambda r:r['native_candidate_cache']['transition_history'][1].update(prior_cleanup_receipt_sha256='9'*64)),
            ('qualification_run',lambda r:r['native_candidate_cache']['aggregate_previous_dispatches'].pop()),
            ('qualification_run',lambda r:r['native_candidate_cache']['aggregate_previous_dispatches'][-1].update(sha256='9'*64)),
            ('schema_run',lambda r:r['native_sdk'].update(aggregate_seconds=1200)),
            ('schema_run',lambda r:r['native_sdk'].update(original_deadline_monotonic_ns=3701*10**9)),
            ('schema_run',lambda r:r['native_sdk'].pop('original_entry_monotonic_ns')),
            ('schema_run',lambda r:r['native_candidate_cache'].update(transition_verified_after_cleanup=False)),
            ('qualification_run',lambda r:r['native_candidate_cache'].update(phase2_verified_before_launch=False)),
            ('schema_run',lambda r:r['native_candidate_cache'].pop('phase2_verified_before_launch')))
        for role,mutate in mutations:
            selection,values,source,exported=self.fixture(phase2=True)
            self.change(selection,values,role,mutate)
            with self.subTest(role=role,mutate=mutate),self.assertRaises(ValueError):
                fresh.validate_action_receipts(selection,values,source,exported)

    def test_combined_cli_actual_bytes_and_context_must_match_same_guarded_receipt(self):
        selection,values,source,exported=self.fixture()
        receipt=fresh.parse(values['qualification_run'])
        raw=b'\x7fELFactual-model'; values['codex']=raw
        path=Path(receipt['native_candidate_cache']['output_base'])/'execroot/_main/bazel-out/k8-opt/bin/codex-rs/cli/codex'
        pin={'path':str(path),'sha256':fresh.digest(raw),'bytes':len(raw)}; selection['files']['codex']=pin
        context={'invocation_id':receipt['id'],'output_base':receipt['native_candidate_cache']['output_base'],
            'source_receipt_sha256':selection['files']['source']['sha256'],
            'export_receipt_sha256':selection['files']['export']['sha256'],
            'source_inventory_sha256':source['inventory_sha256'],'export_inventory_sha256':exported['inventory_sha256'],
            'candidate_cache_key':receipt['native_candidate_cache']['key'],
            'candidate_provenance_sha256':receipt['native_candidate_cache']['provenance_sha256'],
            'controller_graph_sha256':receipt['graph_sha256'],'bazel':fresh.BAZEL,
            'workload_exit':0,'descendants_empty':True,'source_and_export_verified_after_cleanup':True}
        group={'cli_context':context,'cli_artifact':{'kind':'actual-explicit-cli-target-v1',
            'target':fresh.CLI,'configuration':'k8-opt',**pin}}
        fresh.validate_combined_cli(group,selection,values,receipt,source,exported)
        for field in ('invocation_id','candidate_provenance_sha256','controller_graph_sha256','bazel'):
            changed=copy.deepcopy(group); changed['cli_context'][field]='foreign'
            with self.subTest(field=field),self.assertRaises(ValueError):
                fresh.validate_combined_cli(changed,selection,values,receipt,source,exported)
        for field,value in (('target','//foreign:cli'),('sha256','9'*64),('configuration','wrong-opt'),('bytes',len(raw)+1)):
            changed=copy.deepcopy(group); changed['cli_artifact'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                fresh.validate_combined_cli(changed,selection,values,receipt,source,exported)
        values['codex']=raw+b'changed'
        with self.assertRaises(ValueError):
            fresh.validate_combined_cli(group,selection,values,receipt,source,exported)

if __name__ == '__main__':
    unittest.main()
