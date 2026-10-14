"""Actual exact-context ten-file transform; no SDK/compiler/history qualification."""
import copy
from pathlib import Path
import time
import unittest
from unittest.mock import patch
import codex_native_owned_history_source as history
import codex_native_siwc_catalog_source_test as catalog_fixture


class HistorySourceTests(unittest.TestCase):
    def setUp(self):
        self.deadline = history.source.DEADLINE
        history.source.DEADLINE = time.monotonic()+120
        self.control = history.controls()[1]; self.raw = history.model_patch(self.control)
        root = Path(__file__).parent.parent
        self.before = {name:('100644',(root/history.BASE/'preimages'/name).read_bytes()) for name in history.PATHS}
        self.before.update({name:('100644',(root/history.catalog.previous.BASE/physical).read_bytes())
            for name,physical in catalog_fixture.GRAPH.items()})
        self.before['unrelated'] = ('100644',b'public unrelated preserved fixture\n')
    def tearDown(self): history.source.DEADLINE = self.deadline

    def transformed(self): return history.transform(self.before,self.raw,self.control)

    def report(self):
        record = history.content.intake_record()
        parent = {'kind':record['input_kind'],'status':'verified-tenth-file-writer-source-uncompiled','inventory_sha256':record['input_inventory_sha256'],
            'tracked_files':record['input_members'],'source_bytes':record['input_source_bytes'],
            'patch_sha256':record['historical_patch_sha256'],
            'patches':[{'patch_sha256':pin,'paths':[]} for pin in record['historical_patch_sha256']],
            'graph_files':{},**{name:False for name in history.tenth.FLAGS}}
        return history.make_report(parent,self.transformed(),history.catalog.previous.controls()[1],
            history.catalog.previous.configuration()[1])

    def test_actual_ten_file_patch_preserves_inventory_and_full_native_graph(self):
        result = self.transformed()
        self.assertEqual(set(result),set(self.before))
        self.assertEqual({name for name in result if result[name] != self.before[name]},history.PATHS)
        for name in history.PATHS:
            self.assertEqual(history.source.sha(result[name][1]),self.control['delta']['paths'][name]['after']['sha256'])
        for name in set(catalog_fixture.GRAPH)|{'unrelated'}: self.assertEqual(result[name],self.before[name])

    def test_every_actual_preimage_and_logical_mode_is_required(self):
        for name in history.PATHS:
            for wrong in (('100644',self.before[name][1]+b'context-drift'),('100755',self.before[name][1])):
                with self.assertRaises(ValueError): history.transform({**self.before,name:wrong},self.raw,self.control)
        absent = dict(self.before); absent.pop(next(iter(history.PATHS)))
        with self.assertRaises(ValueError): history.transform(absent,self.raw,self.control)

    def test_rehashed_patch_duplicate_unknown_path_and_changed_context_still_refuse(self):
        changed = self.raw.replace(b'+++ b/codex-rs/core/src/codex_thread.rs',b'+++ b/codex-rs/core/src/unqualified.rs',1)
        for raw in (self.raw+self.raw,changed,self.raw+b'unknown trailer\n'):
            control = copy.deepcopy(self.control)
            control['delta']['patch'].update(sha256=history.source.sha(raw),bytes=len(raw))
            with self.assertRaises(ValueError): history.transform(self.before,raw,control)

    def test_final_byte_mode_member_and_graph_changes_refuse(self):
        good = self.transformed()
        variants = [{**good,'extra':('100644',b'extra')},{**good,'unrelated':('100644',b'changed')}]
        variants += [{**good,name:('100644',b'changed')} for name in history.PATHS|set(catalog_fixture.GRAPH)]
        variants += [{**good,name:('100755',good[name][1])} for name in history.PATHS]
        for wrong in variants:
            with self.assertRaises(ValueError): history.validate_transition(self.before,wrong,self.control)

    def test_real_report_has_thirteen_ordered_deltas_and_no_runtime_promotion(self):
        report = self.report();history.validate_report_method(report)
        self.assertEqual(report['kind'],history.KIND);self.assertEqual(report['status'],history.STATUS)
        self.assertEqual(report['native_catalog_controls_sha256'],history.catalog.CONTROL_SHA)
        self.assertEqual(len(report['patch_sha256']),13);self.assertEqual(report['patch_sha256'][-1],history.PATCH_SHA)
        self.assertTrue(all(report[key] is False for key in history.previous.FALSE_FLAGS))
        self.assertEqual(report['native_test_contract']['new_methods'],20)
        self.assertEqual(report['native_owned_history_test_contract']['new_normal_methods'],25)
        self.assertEqual(len(report['native_v4_test_contract']['expected']),15)

    def test_report_old_kind_wrong_ledger_control_and_actual_afterimage_refuse(self):
        good = self.report()
        variants = [{**good,'kind':history.content.KIND},{**good,'native_controls_sha256':'a'*64},
            {**good,'patch_sha256':good['patch_sha256'][:-1]},
            {**good,'historical_ancestor_reexecution':True},{**good,'native_runtime_qualified':True}]
        changed=copy.deepcopy(good);changed['source_inventory'][next(iter(history.PATHS))]['sha256']='a'*64;variants.append(changed)
        changed=copy.deepcopy(good);changed['patch_sha256'][0]='a'*64;variants.append(changed)
        for wrong in variants:
            with self.assertRaises(ValueError): history.validate_report_method(wrong)

    def test_closed_recipe_default_and_explicit_transform_do_not_create_readiness(self):
        raw=history.previous.declared(history.COMPOSITION,16384)
        actual=history.recipe(raw)
        self.assertIn(actual,('catalog-twelve-v1','owned-history-thirteen-v3'))
        with patch.object(history.content,'main') as old,patch.object(history,'main') as new:
            history.content.selected_main()
            if actual == 'catalog-twelve-v1':
                old.assert_called_once_with();new.assert_not_called()
            else:
                new.assert_called_once_with();old.assert_not_called()
        # Historical default is explicit fixture data, never an assumption
        # about the separately adopted current production source recipe.
        default=b'{\n  "kind": "omux-native-source-composition-v1",\n  "recipe": "catalog-twelve-v1",\n  "schema_version": 1\n}\n'
        self.assertEqual(history.recipe(default),'catalog-twelve-v1')
        with patch.object(history.previous,'declared',return_value=default), \
                patch.object(history.content,'main') as old,patch.object(history,'main') as new:
            history.content.selected_main();old.assert_called_once_with();new.assert_not_called()
        with patch.object(history.previous,'declared',return_value=b'{"schema_version":1,"kind":"omux-native-source-composition-v1","recipe":"owned-history-thirteen-v3"}'), \
                patch.object(history,'main') as run,patch.object(history.content,'main') as old:
            history.content.selected_main();run.assert_called_once_with();old.assert_not_called()
        for raw in (b'{"schema_version":1,"kind":"omux-native-source-composition-v1","recipe":"ready"}',
                b'{"schema_version":true,"kind":"omux-native-source-composition-v1","recipe":"catalog-twelve-v1"}',
                b'{"schema_version":1,"kind":"omux-native-source-composition-v1","recipe":"catalog-twelve-v1","ready":true}'):
            with self.assertRaises(ValueError):history.recipe(raw)

    def test_actual_hooks_keep_intake_sdk_regeneration_and_original_nested_admission(self):
        token=object()
        with patch.object(history.previous,'main') as run:
            history.main(_admitted=token)
        fields=run.call_args.kwargs
        self.assertIs(fields['_admitted'],token);self.assertIs(fields['_producer'],history.produce)
        self.assertIs(fields['_input_factory'],history.content.intake.Inputs)
        self.assertIs(fields['_sdk_factory'],history.content.transported.open_sdk)
        self.assertIs(fields['_retainer'],history.retain_selected_controls)
        with patch.object(history.previous,'produce') as run:history.produce('actual-owned-args')
        fields=run.call_args.kwargs
        self.assertIs(fields['_transform'],history.compose);self.assertIs(fields['_report'],history.make_report)
        self.assertIs(fields['_source_intake'],history.content.intake.source_intake)
        self.assertIs(fields['_regenerator'],history.content.transported.regenerate)
        self.assertIs(fields['_sdk_record'],history.content.transported.record)

    def test_retainer_pins_all_new_artifacts_before_long_work(self):
        seen=[]
        class Owner:
            def add(self,path,digest=None,maximum=None):
                seen.append((path,digest,maximum));return path.read_bytes()
        with patch.object(history.content,'retain_controls',return_value=('original','controls')):
            self.assertEqual(history.retain_controls(Owner()),('original','controls'))
        self.assertEqual({path.name for path,digest,maximum in seen},{'native-source-controls.json',
            'native-owned-history-v3.patch','native-delta-manifest.json','expected-tests.json','source-composition.json'})
        self.assertEqual(seen[0][1],history.CONTROL_SHA)



    def test_actual_declared_retained_rule_rejects_mixed_old_new_schema(self):
        # Executes the actual _retained repository declaration body. Physical
        # existence is an explicit path-shape seam; no byte/custody proof here.
        import json
        text=(Path(__file__).parent/'codex_native_siwc_catalog_model_inputs.bzl').read_text()
        body=text[text.index('def _retained('):text.index('def _implementation(')]
        run='/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/01234567-0123-0123-0123-0123456789ab'
        class StarlarkString(str):
            # This local seam preserves Starlark string operations used by the
            # literal declaration body; it makes no filesystem/custody claim.
            def elems(self):return tuple(self)
            def replace(self,old,new,count=-1):
                return StarlarkString(super().replace(old,new,count))
        def starlark_value(value):
            if isinstance(value,str):return StarlarkString(value)
            if type(value) is dict:return {key:starlark_value(item) for key,item in value.items()}
            if type(value) is list:return [starlark_value(item) for item in value]
            return value
        def starlark_type(value):
            if isinstance(value,str):return 'string'
            return {dict:'dict',list:'list',int:'int',bool:'bool',type(None):'NoneType'}[type(value)]
        self.assertEqual(StarlarkString('ab-cd').replace('-','').elems(),('a','b','c','d'))
        decoded=starlark_value(json.loads('{"source_commit":"'+'a'*40+'","rows":["x"],"n":1,"flag":true}'))
        self.assertEqual(decoded['source_commit'].elems(),tuple('a'*40))
        self.assertEqual(decoded['rows'][0].elems(),('x',))
        self.assertEqual([starlark_type(decoded[key]) for key in ('source_commit','rows','n','flag')],
            ['string','list','int','bool'])
        class Physical:
            def __init__(self,path):self.path=path
            def __str__(self):return self.path
            @property
            def dirname(self):return Physical(self.path.rsplit('/',1)[0])
            @property
            def basename(self):return StarlarkString(self.path.rsplit('/',1)[-1])
            @property
            def realpath(self):return self
            exists=True;is_dir=False
        def need(value):
            if not value:raise ValueError('fixture declaration refusal')
        sha=lambda value:isinstance(value,str) and len(value)==64 and all(c in '0123456789abcdef' for c in value)
        space={'type':starlark_type,'_need':need,'_sha':sha,'_physical':lambda ctx,path,directory=False:Physical(path),
            '_name':lambda name:need(not name.startswith('/') and '..' not in name.split('/')),
            'json':type('Codec',(),{'decode':staticmethod(lambda raw:starlark_value(json.loads(raw))),'encode':staticmethod(json.dumps)})}
        exec(compile(body,'<actual-retained-declaration-body>','exec'),space)
        inventory={'public/'+str(i):{'mode':'100644','sha256':'a'*64} for i in range(8557)}
        report={'kind':history.KIND,'status':history.STATUS,'source_inventory':inventory,
            'inventory_sha256':'b'*64,'native_controls_sha256':history.CONTROL_SHA,
            'native_owned_history_controls_sha256':history.CONTROL_SHA,
            'native_owned_history_manifest_sha256':history.MANIFEST_SHA,
            'patch_sha256':['a'*64]*12+[history.PATCH_SHA],
            'generated_hub':{name:{'sha256':'c'*64,'bytes':1} for name in ('BUILD.bazel','defs.bzl','data.bzl')}}
        targets=['//tools:codex_native_siwc_catalog_content_source_test','//tools:codex_native_siwc_catalog_content_source_producer']
        root=run+'/native-content-retained/native-siwc-catalog-content-source'
        phase={'kind':'omux-native-siwc-content-source-phase-v1','id':run.rsplit('/',1)[1],
            'targets':targets,'exit':0,'workload_exit':0}
        publication={'kind':'omux-native-siwc-content-retained-publication-v1',
            'source_phase_receipt_sha256':'d'*64,'publication':{'root':root},'original_action_sdk_custody_inherited':False}
        raw_phase=json.dumps(phase);raw_publication=json.dumps(publication)
        selected={'root':root,'receipt_bytes':len(json.dumps(report)),'receipt_sha256':'e'*64,'inventory_sha256':'b'*64,
            'producer':{'receipt':run+'/receipt.json','sha256':'f'*64,'source_commit':'a'*40,'graph_sha256':'1'*64},
            'source_phase_receipt':{'sha256':'d'*64,'bytes':len(raw_phase)},
            'transport_receipt':{'sha256':'2'*64,'bytes':len(raw_publication)}}
        outer={'id':phase['id'],'profile':'native-siwc-catalog-content-source-reserved','targets':targets,
            'exit':0,'workload_exit':0,'source_commit':'a'*40,'graph_sha256':'1'*64,
            'source_phase_receipt':{'path':'source-phase-receipt.json',**selected['source_phase_receipt']},
            'native_siwc_content_publication':{'root':root,'transport_receipt':{'path':run+'/native-content-retained/publication-receipt.json',**selected['transport_receipt']},
                'source_phase_receipt_sha256':'d'*64,'original_action_sdk_custody_inherited':False},
            'native_siwc_content_delivery':{'started':True,'phase':'complete','exit':0,'workload_exit':0,
                'cleanup':{'state':'empty','ownership':'verified','readback_attempts':2}}}
        results=[]
        for target in targets:
            results.append({'target':target,'state':'observed','files':[{'source':kind,'state':'copied','file':pin*64+'.evidence','sha256':pin*64}
                for kind,pin in (('test.log','3' if target==targets[0] else '5'),('test.xml','4' if target==targets[0] else '6'))]})
        documents={run+'/receipt.json':json.dumps(outer),run+'/source-phase-receipt.json':raw_phase,
            run+'/native-content-retained/publication-receipt.json':raw_publication,
            run+'/test-evidence.json':json.dumps({'targets':targets,'results':results})}
        class Context:
            def __init__(self,report):
                self.docs=dict(documents);self.docs[root+'/source-receipt.json']=json.dumps(report);self.outputs={};self.aliases=[]
            def read(self,path):return self.docs[str(path)]
            def path(self,path):return Physical(path)
            def watch(self,path):pass
            def symlink(self,path,alias):self.aliases.append((str(path),alias))
            def file(self,name,raw,executable=False):self.outputs[name]=raw
        config={'schema_version':1,'kind':'omux-native-siwc-catalog-owned-history-retained-selection-v3',
            'status':'qualified-retained-catalog-owned-history-source-hub-uncompiled',
            'catalog_controls_sha256':history.CONTROL_SHA,'source':selected}
        config=starlark_value(config)
        context=Context(report);space['_retained'](context,config)
        declaration=json.loads(context.outputs['source-inputs.json'])
        self.assertEqual(declaration['kind'],'omux-native-siwc-catalog-owned-history-retained-input-v3')
        self.assertEqual(len(declaration['inputs']),8569)
        self.assertEqual(len(context.aliases),8569)
        for wrong in ({**config,'status':'qualified-retained-catalog-content-source-hub-uncompiled'},
                {**config,'catalog_controls_sha256':history.catalog.CONTROL_SHA}):
            with self.assertRaises(ValueError):space['_retained'](Context(report),wrong)
        for key,value in (('kind',history.content.KIND),('patch_sha256',['a'*64]*12),
                ('native_owned_history_controls_sha256','a'*64),('native_owned_history_manifest_sha256','a'*64)):
            wrong={**report,key:value};changed=copy.deepcopy(config);changed['source']['receipt_bytes']=len(json.dumps(wrong))
            with self.assertRaises(ValueError):space['_retained'](Context(wrong),changed)



    def test_selected_producer_cannot_use_default_recipe_or_uncaptured_change(self):
        # Literal historical default bytes remain an explicit negative input.
        # Reading the current production file here would stop exercising this
        # refusal after root intentionally selects the thirteen-delta recipe.
        default=b'{\n  "kind": "omux-native-source-composition-v1",\n  "recipe": "catalog-twelve-v1",\n  "schema_version": 1\n}\n'
        class Owner:
            def add(self,path,digest=None,maximum=None):return default
        # No SOURCE IO or qualification is performed by this actual control
        # retainer model. The production owner supplies all held/name fences.
        with patch.object(history,'retain_controls',return_value=('old','controls')):
            with self.assertRaises(ValueError):history.retain_selected_controls(Owner())
        selected=b'{"schema_version":1,"kind":"omux-native-source-composition-v1","recipe":"owned-history-thirteen-v3"}'
        with patch.object(history,'retain_controls',return_value=('old','controls')):
            owner=type('Selected',(),{'add':lambda self,*args,**kwargs:selected})()
            self.assertEqual(history.retain_selected_controls(owner),('old','controls'))


if __name__ == '__main__':unittest.main()
