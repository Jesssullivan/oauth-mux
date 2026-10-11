"""Actual rule decisions; translation is model-only, real BUILD loads Starlark."""
import copy
import ast
import json
from pathlib import Path
from types import SimpleNamespace
import unittest


def model():
    raw = Path(__file__).with_name('codex_native_carrier_material_inputs.bzl').read_text()
    kinds = {str:'string',int:'int',bool:'bool',dict:'dict',list:'list'}
    def fail(message): raise ValueError(message)
    namespace = {'type':lambda value:kinds.get(type(value),type(value).__name__),'fail':fail,
        'attr':SimpleNamespace(label=lambda **kw:kw,string=lambda **kw:kw),
        'repository_rule':lambda **kw:kw,'json':SimpleNamespace(decode=json.loads,encode=json.dumps)}
    exec(compile(raw.replace('.elems()',''),'<actual carrier material declaration>','exec'),namespace)
    return namespace


class PathModel:
    def __init__(self,value,context):
        self.raw = value; self.exists = value not in context.missing
        self.is_dir = False; self.realpath = context.redirects.get(value,value)
    def __str__(self): return self.raw


class Context:
    def __init__(self,model,stage='metadata'):
        self.attr = SimpleNamespace(selection='/tracked/carrier.json',stage=stage)
        self.missing = set(); self.redirects = {}; self.files = {}; self.events = []; self.outputs = {}; self.aliases = []
        self.metadata = self.program(model,'metadata','1')
        self.metadata['report'] = {'kind':'omux-native-sdk-carrier-metadata-v2',
            'generated_hub':[{'path':name,'sha256':'a'*64} for name in ('BUILD.bazel','defs.bzl','data.bzl')]}
        self.files[self.metadata['selected']['program']['path']] = json.dumps(self.metadata['report'])
        self.metadata['selected']['program']['bytes'] = len(self.files[self.metadata['selected']['program']['path']])
        root = self.metadata['selected']['program']['path'].removesuffix('/metadata-receipt.json')
        for row in self.metadata['report']['generated_hub']: self.files[root+'/hub/source/'+row['path']] = 'hub model'
        self.sdk = self.program(model,'sdk','2')
        sdk_root = self.sdk['selected']['program']['path'].removesuffix('/sdk-receipt.json')
        self.sdk_report = {'kind':'omux-native-carrier-sdk-projection-v2','authority_sha256':'b'*64,
            'hub_files':{'BUILD.bazel':{'mode':'100644','bytes':3,'sha256':'c'*64}},
            'graph_files':{'MODULE.bazel':{'mode':'100644','bytes':3,'sha256':'d'*64}}}
        self.files[self.sdk['selected']['program']['path']] = json.dumps(self.sdk_report)
        self.sdk['selected']['program']['bytes'] = len(self.files[self.sdk['selected']['program']['path']])
        self.files[sdk_root+'/authority.json'] = json.dumps({'kind':'omux-native-carrier-sdk-authority-core-v2'})
        self.selector = {'schema_version':2,'kind':'omux-native-carrier-material-config-v2',
            'status':'actual-qualified-carrier-route-selected','metadata':self.metadata['selected'],'compile':None,
            'selection':None if stage == 'metadata' else {'schema_version':2,'kind':'omux-native-carrier-native-selection-v2',
                'sdk':{'root':sdk_root,'receipt_sha256':self.sdk['selected']['program']['sha256'],
                    'inventory_sha256':'b'*64,'producer':self.sdk['selected']['producer']}}}
    def program(self,model,role,digit):
        epoch = '/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/' + digit*8+'-'+digit*4+'-'+digit*4+'-'+digit*4+'-'+digit*12
        suffix = {'metadata':'native-sdk-carrier-metadata/metadata-receipt.json',
            'sdk':'native-carrier-sdk-export/sdk-receipt.json','plan':'native-acquisition-plan/receipt.json',
            'query':'native-acquisition-query/receipt.json','compiler':'native-acquisition-compilation/receipt.json'}[role]
        report = epoch+'/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/'+model['_TARGETS'][role].split(':')[1]+'/test.outputs/'+suffix
        selected = {'producer':{'receipt':epoch+'/receipt.json','sha256':'e'*64,'source_commit':'f'*40,'graph_sha256':'a'*64},
            'program':{'path':report,'sha256':'b'*64,'bytes':1}}
        outer = {'profile':model['_PROFILES'][role],'targets':[model['_TARGETS'][role]],'verb':'test',
            'exit':0,'workload_exit':0,'source_dirty':'false','controller_failure':None,'descendants_empty':True,
            'cleanup':{'state':'empty'},'source_commit':'f'*40,'graph_sha256':'a'*64,'output_base':epoch+'/output-base',
            'epoch_start_ns':123,'test_evidence':{'state':'preserved','sha256':'c'*64}}
        evidence = {'schema':1,'bazel_exit':0,'targets':outer['targets'],'epoch_start_ns':123,
            'results':[{'target':model['_TARGETS'][role],'state':'observed','files':[
                {'source':leaf,'state':'copied','sha256':d*64,'file':d*64+'.evidence','bytes':100}
                for leaf,d in [('test.log','3'),('test.xml','4')]]}]}
        self.files[epoch+'/receipt.json'] = json.dumps(outer)
        self.files[epoch+'/test-evidence.json'] = json.dumps(evidence)
        return {'selected':selected,'outer':outer,'evidence':evidence}
    def path(self,value): return PathModel(str(value),self)
    def watch(self,path): self.events.append(('watch',str(path)))
    def watch_tree(self,path): raise AssertionError('no mutable host SDK traversal')
    def read(self,path,**kwargs):
        value = str(path); self.events.append(('read',value))
        return json.dumps(self.selector) if value == self.attr.selection else self.files[value]
    def symlink(self,path,alias): self.aliases.append((str(path),alias))
    def file(self,name,raw,**kwargs): self.outputs[name] = raw


class DeclarationModels(unittest.TestCase):
    def setUp(self): self.rule = model()
    def run_rule(self,ctx): self.rule['_implementation'](ctx)
    def compiler_context(self,*,result=False):
        ctx=Context(self.rule,'material')
        selector_path='/model/compiler-selection.json'
        ledger_path='/model/compiler-ledger.json'
        snapshot={'path':'docs/agent-notes/2026-10-10-native-acquisition-input-lift.UNAPPLIED/ledger-snapshots/'+'a'*64+'.json',
            'sha256':'a'*64,'bytes':123}
        ctx.files[ledger_path]=json.dumps({'kind':'omux-native-acquisition-root-dispatch-ledger-v1',
            'actor':'Root','aggregate':8,'dispatched':8,'remaining':0,'goal_snapshot':snapshot})
        document={'schema_version':1,'kind':'omux-native-acquisition-compilation-v1-selection',
            'material':ctx.selector['selection'],'ledger':{'path':ledger_path,'sha256':'b'*64},
            'controller_inventory_sha256':'c'*64}
        for role,digit in [('plan','5'),('query','6')]:
            program=ctx.program(self.rule,role,digit)
            row=program['selected'];raw=json.dumps({'model_only':True})
            ctx.files[row['program']['path']]=raw
            document[role]={'path':row['program']['path'],'sha256':row['program']['sha256'],'producer':row['producer']}
        selected_raw=json.dumps(document);ctx.files[selector_path]=selected_raw
        ctx.selector['compile']={'selection':{'path':selector_path,'sha256':'d'*64,'bytes':len(selected_raw)},'result':None}
        if result:
            program=ctx.program(self.rule,'compiler','7');row=program['selected']
            root=row['program']['path'].removesuffix('/receipt.json')+'/artifacts/'
            artifacts=[{'path':root+'native-cli','sha256':'e'*64,'bytes':100,'role':'native-cli'}]
            artifacts += [{'path':root+'tests/t'+str(index)+'.log','sha256':'f'*64,'bytes':12,'role':'test-log'} for index in range(6)]
            report_raw=json.dumps({'kind':'omux-native-acquisition-compilation-v1','artifacts':artifacts})
            ctx.files[row['program']['path']]=report_raw
            ctx.selector['compile']['result']={**row['program'],'bytes':len(report_raw),'producer':row['producer']}
        return ctx

    def test_compiler_stage_declares_ledger_snapshot_and_genuine_plan_query_proofs(self):
        ctx=self.compiler_context();self.run_rule(ctx)
        files=json.loads(ctx.outputs['inputs.json'])['files']
        self.assertIn('compiler/selection.json',files)
        self.assertIn('compiler/goal-snapshot.json',files)
        for role in ('plan','query'):
            self.assertEqual(len([key for key in files if key.startswith(role+'/')]),5)
        self.assertFalse(any('registry-cache' in row['path'] for row in files.values()))

    def test_compiler_result_artifact_roles_and_boundaries_are_declared(self):
        ctx=self.compiler_context(result=True);self.run_rule(ctx)
        files=json.loads(ctx.outputs['inputs.json'])['files']
        self.assertIn('compiler/artifacts/native-cli',files)
        row=ctx.selector['compile']['result'];report=json.loads(ctx.files[row['path']])
        report['artifacts'][0]['path']='/unselected/native-cli'
        ctx.files[row['path']]=json.dumps(report);row['bytes']=len(ctx.files[row['path']])
        with self.assertRaises(ValueError):self.run_rule(ctx)

    def test_compiler_selector_material_or_ledger_spend_substitution_refuses(self):
        for defect in ('material','ledger'):
            ctx=self.compiler_context()
            if defect=='material':
                path=ctx.selector['compile']['selection']['path'];document=json.loads(ctx.files[path])
                document['material']={'kind':'wrong'};ctx.files[path]=json.dumps(document)
                ctx.selector['compile']['selection']['bytes']=len(ctx.files[path])
            else:
                document=json.loads(ctx.files['/model/compiler-ledger.json']);document['remaining']=1
                ctx.files['/model/compiler-ledger.json']=json.dumps(document)
            with self.assertRaises(ValueError):self.run_rule(ctx)
    def test_metadata_stage_declares_actual_five_proofs_and_hub_only(self):
        ctx = Context(self.rule); self.run_rule(ctx)
        document = json.loads(ctx.outputs['inputs.json'])
        self.assertEqual(document['stage'],'metadata')
        self.assertEqual(set(document['files']),{'metadata/'+leaf for leaf in ('outer-receipt.json','test-evidence.json',
            'test-log.evidence','test-xml.evidence','program-report.json')} | {'metadata/hub/'+name for name in ('BUILD.bazel','defs.bzl','data.bzl')})
        self.assertFalse(any('sdk-export/' in path or 'registry-cache' in path for path,_ in ctx.aliases))
        self.assertNotIn('selected-material.json',ctx.outputs)
    def test_material_stage_retains_sdk_projection_and_all_proofs(self):
        ctx = Context(self.rule,'material'); self.run_rule(ctx)
        document = json.loads(ctx.outputs['inputs.json'])
        self.assertIn('sdk/authority.json',document['files'])
        self.assertIn('sdk/hub/BUILD.bazel',document['files'])
        self.assertIn('sdk/graph/MODULE.bazel',document['files'])
        self.assertEqual(json.loads(ctx.outputs['selected-material.json']),ctx.selector['selection'])
        self.assertEqual({row['alias'] for row in document['files'].values()},{alias for _,alias in ctx.aliases})
    def test_cold_or_wrong_profile_failed_outer_refuses(self):
        for defect in ('cold','profile','failed'):
            ctx = Context(self.rule)
            if defect == 'cold': ctx.selector['metadata'] = None
            else:
                outer = copy.deepcopy(ctx.metadata['outer']); outer['profile' if defect == 'profile' else 'exit'] = 'standard' if defect == 'profile' else 1
                ctx.files[ctx.metadata['selected']['producer']['receipt']] = json.dumps(outer)
            with self.assertRaises(ValueError): self.run_rule(ctx)
            self.assertNotIn('BUILD.bazel',ctx.outputs)
    def test_wrong_program_namespace_missing_and_redirected_leaf_refuse(self):
        for defect in ('namespace','missing','redirect'):
            ctx = Context(self.rule); path = ctx.metadata['selected']['program']['path']
            if defect == 'namespace': ctx.metadata['selected']['program']['path'] = '/other/program.json'
            elif defect == 'missing': ctx.missing.add(path)
            else: ctx.redirects[path] = '/other/program.json'
            with self.assertRaises(ValueError): self.run_rule(ctx)
            self.assertNotIn('BUILD.bazel',ctx.outputs)
    def test_duplicate_hub_name_traversal_and_uncopied_evidence_refuse(self):
        for defect in ('duplicate','traversal','evidence'):
            ctx = Context(self.rule)
            if defect == 'evidence':
                evidence = copy.deepcopy(ctx.metadata['evidence']); evidence['results'][0]['files'][0]['state'] = 'missing'
                epoch = ctx.metadata['selected']['producer']['receipt'].removesuffix('/receipt.json')
                ctx.files[epoch+'/test-evidence.json'] = json.dumps(evidence)
            else:
                report = copy.deepcopy(ctx.metadata['report'])
                if defect == 'duplicate': report['generated_hub'].append(report['generated_hub'][0])
                else: report['generated_hub'][0]['path'] = '../escape'
                raw = json.dumps(report); ctx.files[ctx.metadata['selected']['program']['path']] = raw
                ctx.metadata['selected']['program']['bytes'] = len(raw)
            with self.assertRaises(ValueError): self.run_rule(ctx)
            self.assertNotIn('BUILD.bazel',ctx.outputs)

    def test_source_only_actual_rule_decisions_preserve_legacy_default(self):
        raw = Path(__file__).with_name('codex_native_acquisition_inputs.bzl').read_text()
        syntax = ast.parse(raw)
        implementation = next(node for node in syntax.body if isinstance(node,ast.FunctionDef) and node.name == '_implementation')
        branches = [node for node in implementation.body if isinstance(node,ast.If)
            and any(isinstance(call,ast.Call) and isinstance(call.func,ast.Name)
                and call.func.id in ('_declare_sdk','_declare_compiler') for call in ast.walk(node))]
        self.assertEqual(len(branches),2)
        decisions = ast.Module(body=branches,type_ignores=[])
        for source_only,expected in ((True,[]),(False,['sdk','compile'])):
            events = []
            context = SimpleNamespace(attr=SimpleNamespace(source_only=source_only))
            namespace = {'ctx':context,'value':{'sdk':{'model':'sdk'},'compile':{'model':'compile'}},'names':[],
                '_declare_sdk':lambda *args:events.append('sdk'),
                '_declare_compiler':lambda *args:events.append('compile')}
            exec(compile(ast.fix_missing_locations(decisions),'<actual source-only rule branches>','exec'),namespace)
            self.assertEqual(events,expected)
        declaration = next(node for node in syntax.body if isinstance(node,ast.Assign)
            and any(isinstance(target,ast.Name) and target.id == 'codex_native_acquisition_inputs' for target in node.targets))
        attributes = next(keyword.value for keyword in declaration.value.keywords if keyword.arg == 'attrs')
        source_attr = next(value for key,value in zip(attributes.keys,attributes.values) if key.value == 'source_only')
        self.assertIs(next(keyword.value.value for keyword in source_attr.keywords if keyword.arg == 'default'),False)
        # The source-only branch changes only SDK/compiler declaration. SOURCE
        # inventory still binds all8552 members before those two branches.
        self.assertIn('len(files) == 8552',raw)
        self.assertTrue(any(isinstance(node,ast.For) and isinstance(node.target,ast.Tuple)
            and [item.id for item in node.target.elts] == ['name','pin'] for node in ast.walk(implementation)))

    def test_actual_collector_four_rows_keep_only_required_log_and_xml_authority(self):
        ctx = Context(self.rule)
        index = copy.deepcopy(ctx.metadata['evidence'])
        index['results'][0]['files'] += [
            {'source':'test.outputs_manifest/MANIFEST','state':'copied','file':'a'*64+'.evidence','sha256':'b'*64,'bytes':324},
            {'source':'test.outputs_manifest/ANNOTATIONS','state':'missing','bytes':0}]
        # Collector filenames identify target/config/source; content pins are
        # independent. Neither diagnostics nor matching-name guesses are proof.
        index['results'][0]['files'][0]['file'] = 'c'*64+'.evidence'
        index['results'][0]['files'][1]['file'] = 'd'*64+'.evidence'
        epoch = ctx.metadata['selected']['producer']['receipt'].removesuffix('/receipt.json')
        ctx.files[epoch+'/test-evidence.json'] = json.dumps(index)
        self.run_rule(ctx)
        document = json.loads(ctx.outputs['inputs.json'])
        self.assertEqual(document['files']['metadata/test-log.evidence']['path'],epoch+'/test-evidence/'+'c'*64+'.evidence')
        self.assertEqual(document['files']['metadata/test-log.evidence']['sha256'],'3'*64)
        self.assertNotIn('metadata/MANIFEST',document['files'])
        index['results'][0]['files'][1]['state'] = 'missing'
        ctx.files[epoch+'/test-evidence.json'] = json.dumps(index)
        with self.assertRaises(ValueError): self.run_rule(ctx)


if __name__ == '__main__': unittest.main()
