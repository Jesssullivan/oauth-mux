"""Actual typed tree-owner/proof/FD/callback models; no compiled/source readiness."""
from contextlib import ExitStack
import copy
import json
import os
from pathlib import Path
import re
import tempfile
import time
import unittest
from unittest.mock import Mock,patch
import codex_native_siwc_catalog_tree_model_inputs as tree
import codex_native_siwc_catalog_models as model
from codex_retained_sdk_tree_fixture import TinyCarrier
from codex_retained_sdk_tree_admission_fixture import DeclaredTreeFixture,_resident,_outer
import codex_native_retained_sdk_tree_producer as producer


class TreeModelInputsTests(unittest.TestCase):
    def setUp(self):
        self.deadline=tree.source.DEADLINE
        tree.source.DEADLINE=time.monotonic()+120
    def tearDown(self):tree.source.DEADLINE=self.deadline

    def selected(self,base):
        run=base/'01234567-0123-0123-0123-0123456789ab'
        root=base/('cache-v2-sdk-tree-'+'d'*64)/'output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_native_siwc_catalog_tree_source_producer/test.outputs'/tree.LEAF
        row={'root':str(root),'receipt_sha256':'a'*64,'receipt_bytes':1,'inventory_sha256':'b'*64,
            'producer':{'receipt':str(run/'receipt.json'),'sha256':'c'*64,'source_commit':'a'*40,'graph_sha256':'b'*64},
            'source_terminal_confirmation':{'sha256':'e'*64,'bytes':1}}
        return {'schema_version':1,'kind':tree.SELECTION_KIND,'status':tree.SELECTED_STATUS,
            'catalog_controls_sha256':tree.history.CONTROL_SHA,'source':row}

    def test_closed_direct_tree_selector_never_aliases_old_content_or_cold(self):
        base=Path('/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005')
        good=self.selected(base);self.assertEqual(model.selection(json.dumps(good).encode()),good)
        for wrong in ({**good,'kind':model.delivery.HISTORY_SELECTION_KIND},
                {**good,'status':model.delivery.HISTORY_STATUS},{**good,'source':None},
                {**good,'catalog_controls_sha256':model.catalog.CONTROL_SHA},{**good,'ready':True}):
            with self.assertRaises(ValueError):model.selection(json.dumps(wrong).encode())
        for fault in ('leaf','cache','confirmation'):
            changed=copy.deepcopy(good)
            if fault=='leaf':changed['source']['root']=changed['source']['root'].replace(tree.LEAF,'native-siwc-catalog-content-source')
            if fault=='cache':changed['source']['root']=changed['source']['root'].replace('cache-v2-sdk-tree-','cache-v2-')
            if fault=='confirmation':changed['source'].pop('source_terminal_confirmation')
            with self.assertRaises(ValueError):model.selection(json.dumps(changed).encode())

    def test_new_route_requires_actual_tree_type_before_any_source_or_scratch_effect(self):
        report={'kind':tree.history.KIND,'patch_sha256':['a'*64]*13,
            'transported_sdk':{'kind':tree.reader.KIND},**{name:False for name in model.catalog.previous.FALSE_FLAGS}}
        for sdk in (Mock(),object.__new__(model.content_catalog.transported.HeldTransportedSDK)):
            with tempfile.TemporaryDirectory() as temporary,patch.object(model.native,'command_from_verified_inputs') as command:
                published=Mock(active=True);work=Path(temporary)/'work'
                with self.assertRaises(ValueError):model.native_plan(published,sdk,report,work,time.monotonic()+300)
                self.assertFalse(work.exists());published.full.assert_not_called();command.assert_not_called()

    def test_real_admitted_tree_owner_proves_mapping_and_refuses_changed_record(self):
        with TinyCarrier() as tiny,DeclaredTreeFixture(tiny) as fixture:
            producer.materialize(fixture.materialize_args());tiny.normalize(fixture.output/'tree');fixture.publish_tree()
            with fixture.retained_source() as held:
                with tree.reader.open_declared(fixture.runfiles,fixture.rows,fixture.entry,fixture.until,
                        fixture.source_context,held) as current:
                    report={'kind':tree.history.KIND,'tracked_files':8557,
                        'source_inventory':{'public/'+str(i):{'mode':'100644','sha256':'a'*64} for i in range(8557)},
                        'producer_context':{'mode':fixture.source_context['MODE'],
                        'entry_monotonic_ns':fixture.entry,'deadline_monotonic_ns':fixture.until,
                        'epoch':str(fixture.source_epoch),'source_commit':fixture.commit,'graph_sha256':fixture.graph},
                        'transported_sdk':current.record()}
                    report['inventory_sha256']=tree.source.sha(tree.source.canonical(report['source_inventory']))
                    # Native delta checks are separately exact-file models. This
                    # semantic seam admits no fake SDK owner or finished flag.
                    with patch.object(tree.history,'validate_report_method'):
                        self.assertEqual(tree.admit_sdk(current,report),current.sdk_root)
                        raw=tiny.model.original
                        self.assertEqual(current.read_regular('sdk','receipt.json',tree.reader.core.MAX_METADATA),raw)
                        wrong=copy.deepcopy(report);wrong['transported_sdk']['inventory_sha256']='a'*64
                        with self.assertRaises(ValueError):tree.admit_sdk(current,wrong)
                        current.finish();current.fence()

    def test_actual_tree_owner_cannot_be_accepted_after_finish_close_or_wrong_context(self):
        with TinyCarrier() as tiny,DeclaredTreeFixture(tiny) as fixture:
            producer.materialize(fixture.materialize_args());tiny.normalize(fixture.output/'tree');fixture.publish_tree()
            with fixture.retained_source() as held:
                with tree.reader.open_declared(fixture.runfiles,fixture.rows,fixture.entry,fixture.until,
                    fixture.source_context,held) as current:
                    report={'tracked_files':8557,
                        'source_inventory':{'public/'+str(i):{'mode':'100644','sha256':'a'*64} for i in range(8557)},
                        'producer_context':{'mode':fixture.source_context['MODE'],'entry_monotonic_ns':fixture.entry,
                        'deadline_monotonic_ns':fixture.until,'epoch':str(fixture.source_epoch),
                        'source_commit':fixture.commit,'graph_sha256':fixture.graph},'transported_sdk':current.record()}
                    report['inventory_sha256']=tree.source.sha(tree.source.canonical(report['source_inventory']))
                    with patch.object(tree.history,'validate_report_method'):
                        wrong=copy.deepcopy(report);wrong['transported_sdk']['consumer_context']['SOURCE_COMMIT']='c'*40
                        with self.assertRaises(ValueError):tree.admit_sdk(current,wrong)
                    current.finish()
                with self.assertRaises(ValueError):tree.admit_sdk(current,report)

    def test_complete_sixty_name_contract_preserves_old_thirty_five_and_refuses_missing_new(self):
        old=model.expected_tests();current=model.history_expected_tests()
        self.assertEqual(tuple(map(len,current.values())),(50,4,6,0))
        self.assertEqual(len({name for names in current.values() for name in names}),60)
        for target,names in current.items():
            self.assertEqual(names[:len(old[target])],old[target])
            raw=('running '+str(len(names))+' tests\n'+''.join('test '+name+' ... ok\n' for name in names)+
                'test result: ok. '+str(len(names))+' passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n').encode()
            self.assertEqual(model.accept_log(raw,names)['required_passed'],list(names))
            if len(names)>len(old[target]):
                missing=raw.replace(('test '+names[-1]+' ... ok\n').encode(),b'')
                with self.assertRaises(ValueError):model.accept_log(missing,names)

    def proof_fixture(self,base,mutation=None,optional=None):
        scoped=patch.object(tree.family.protocol,'PRODUCER_SCOPE',re.compile(re.escape(str(base))+r'/[0-9a-f-]{36}/receipt.json'))
        scoped.start();self.addCleanup(scoped.stop)
        value=self.selected(base);row=value['source'];run=Path(row['producer']['receipt']).parent;run.mkdir()
        root=Path(row['root']);root.mkdir(parents=True)
        entry=time.monotonic_ns();until=entry+1200*10**9;key='d'*64
        output=base/('cache-v2-sdk-tree-'+key)/'output-base'
        context={'mode':tree.guard.old.INPUT_MODE,'entry_monotonic_ns':entry,'deadline_monotonic_ns':until,
            'epoch':str(run),'source_commit':'a'*40,'graph_sha256':'b'*64}
        report={'producer_context':context,'inventory_sha256':row['inventory_sha256']}
        raw=tree.source.encoded(report);(root/'source-receipt.json').write_bytes(raw);(root/'source-receipt.json').chmod(0o444)
        row.update(receipt_sha256=tree.source.sha(raw),receipt_bytes=len(raw))
        outer=_outer(run,tree.TARGETS[1],tree.PROFILE,entry,until,output,'b'*64,'a'*40)
        outer['targets']=list(tree.TARGETS);outer['observed_properties']['RuntimeMaxUSec']='14min'
        outer['cache_reuse_requested']=True;outer['cache_policy']=2;outer['cache_key']=key
        outer['cleanup']={'state':'empty','stop':'succeeded','ownership':'verified','readback_attempts':2,
            'pre_stop':{'schema_version':1,'scope':'reserved-owned-pre-stop-diagnostic-v1','LoadState':'loaded',
                'ActiveState':'active','SubState':'exited','MainPID':'zero','RemainAfterExit':'yes','Id_matches':True,
                'InvocationID_matches':True,'ExecMainPID_matches':True,'ExecMainCode':'1','ExecMainStatus':0,
                'Result':'success','terminal_class':'unqualified'},
            'post_stop':{'schema_version':1,'scope':'reserved-owned-post-stop-diagnostic-v1','LoadState':'not-found',
                'ActiveState':'inactive','SubState':'dead','MainPID':'zero','Id_matches':True,
                'InvocationID_matches':False,'ExecMainPID_matches':False,'original_cgroup_state':'absent','predicate':'manager-predicate-passed'}}
        outer['native_sdk_tree_dependency_lease']={'kind':'omux-retained-sdk-tree-dependency-lease-v1','family':tree.guard.FAMILY,
            'key':key,'namespace':'cache-v2-sdk-tree-'+key,'output_base':str(output),'run_id':run.name,
            'checkout':str(base/'checkout'),'profile':tree.PROFILE,'source_commit':'a'*40,'graph_sha256':'b'*64,
            'entry_monotonic_ns':entry,'deadline_monotonic_ns':until,
            'sdk_execution_qualified':False,'source_qualified':False,'runtime_qualified':False}
        outer['native_sdk_tree_source_reservation']=tree.guard.projection(tree.PROFILE,entry,until,True,_resident())
        outer['native_sdk_tree_terminal_publication']=tree.guard.publication_record(entry,until)
        outer['native_sdk_tree_artifact_origin']=None
        outer['native_sdk_tree_dependency_disposition']={'kind':'omux-retained-sdk-tree-dependency-disposition-v1',
            'family':tree.guard.FAMILY,'state':'dependency-data-after-success','checkout':str(base/'checkout'),
            'key':key,'namespace':'cache-v2-sdk-tree-'+key,'sdk_execution_qualified':False,'source_qualified':False,'runtime_qualified':False}
        env={'MODE':context['mode'],'ENTRY_NS':str(entry),'DEADLINE_NS':str(until),'EPOCH':str(run),
            'SOURCE_COMMIT':'a'*40,'GRAPH_SHA256':'b'*64}
        outer['command']=['/nix/store/public-fixture/bin/bazel','--output_base='+str(output),
            'test','--remote_executor=','--remote_cache=','--repository_disable_download','--repo_contents_cache=',
            '--nocache_test_results','--test_timeout=840']+[
                '--'+kind+'=OMUX_NATIVE_FILE_WRITER_MODELS_'+name+'='+part for kind in ('repo_env','test_env') for name,part in env.items()]+list(tree.TARGETS)
        evidence={'schema':1,'bazel_exit':0,'epoch_start_ns':entry,'targets':list(tree.TARGETS),'results':[],'bytes':0,'copied_files':0}
        paths=[root/'source-receipt.json',run/'receipt.json',run/'sdk-tree-qualified.json',run/'test-evidence.json']
        for index,target in enumerate(tree.TARGETS):
            files=[]
            for role,body in (('test.log',b'public successful test'),('test.xml',b'<testsuite tests="1" failures="0" errors="0" skipped="0"/>')):
                name=tree.source.sha((target+role).encode())+'.evidence';path=run/'test-evidence'/name
                path.parent.mkdir(exist_ok=True);path.write_bytes(body);path.chmod(0o600);paths.append(path)
                evidence['bytes']+=len(body);evidence['copied_files']+=1
                files.append({'source':role,'state':'copied','bytes':len(body),'sha256':tree.source.sha(body),'file':name})
            for role in ('test.outputs_manifest/MANIFEST','test.outputs_manifest/ANNOTATIONS'):
                if optional == 'empty':
                    body=b'';name=tree.source.sha((target+role).encode())+'.evidence';path=run/'test-evidence'/name
                    path.write_bytes(body);path.chmod(0o600);paths.append(path);evidence['copied_files']+=1
                    files.append({'source':role,'state':'copied','bytes':0,'sha256':tree.source.sha(body),'file':name})
                else:files.append({'source':role,'state':'stale' if optional == 'stale' else 'missing','bytes':0})
            evidence['results'].append({'target':target,'configuration':'k8-fastbuild','state':'observed','files':files})
        raw=tree.source.encoded(evidence);(run/'test-evidence.json').write_bytes(raw);(run/'test-evidence.json').chmod(0o600)
        outer['test_evidence']={'state':'preserved','manifest':'test-evidence.json','sha256':tree.source.sha(raw),'bytes':evidence['bytes'],'files':evidence['copied_files']}
        if mutation:mutation(outer)
        raw=tree.source.encoded(outer);(run/'receipt.json').write_bytes(raw);(run/'receipt.json').chmod(0o600)
        row['producer']['sha256']=tree.source.sha(raw)
        witness=list(tree.guard.old._witness((run/'receipt.json').stat()))
        # Constructor validates all terminal predicates for normal fixtures.
        # Refusal fixtures mutate only after a valid confirmation was produced.
        confirmed=tree.guard.qualification_record(outer,row['producer']['sha256'],len(raw),entry+10,witness)
        raw=tree.source.encoded(confirmed);(run/'sdk-tree-qualified.json').write_bytes(raw);(run/'sdk-tree-qualified.json').chmod(0o600)
        row['source_terminal_confirmation']={'sha256':tree.source.sha(raw),'bytes':len(raw)}
        repository=base/'external/fixture_repo';repository.mkdir(parents=True);(repository/'input').mkdir()
        document={'kind':tree.INPUT_KIND,'selection':row,'inputs':[]}
        for index,path in enumerate(paths):
            alias='input/'+str(index);(repository/alias).symlink_to(path)
            document['inputs'].append({'path':str(path),'alias':alias})
        (repository/'source-inputs.json').write_bytes(tree.source.encoded(document));(repository/'source-inputs.json').chmod(0o644)
        runfiles=base/'runfiles';runfiles.mkdir();(runfiles/'fixture_repo').symlink_to(repository)
        return row,runfiles,[['_main',tree.REPOSITORY,'fixture_repo']],run,outer

    def test_actual_private_source_terminal_roles_and_late_samebyte_confirmation_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary);row,runfiles,rows,run,outer=self.proof_fixture(base)
            # The schema proof uses real pinned files/aliases/held full-nine;
            # native8557 delta equivalence is a separate model/source gate.
            with patch.object(tree,'validate_report_method'),tree.Inputs(runfiles,rows) as inputs:
                actual,required=tree.guardian(row,inputs)
                self.assertEqual(actual,outer);self.assertEqual(set(inputs.rows),required)
                self.assertEqual(len(required),8)
                original=run/'sdk-tree-qualified.json';replacement=run/'replacement'
                replacement.write_bytes(original.read_bytes());replacement.chmod(0o600);replacement.replace(original)
                with self.assertRaises(ValueError):tree.guardian(row,inputs)

    def test_failure_or_dependency_only_terminal_fact_cannot_admit_source(self):
        for fault in ('failed','cleanup','dependency','wronglease','command'):
            with tempfile.TemporaryDirectory() as temporary:
                base=Path(temporary);row,runfiles,rows,run,outer=self.proof_fixture(base)
                if fault=='failed':outer['exit']=outer['workload_exit']=125
                if fault=='cleanup':outer['cleanup']['ownership']='unproved'
                if fault=='dependency':outer['native_sdk_tree_dependency_disposition']['state']='dependency-only-after-owned-failure'
                if fault=='wronglease':outer['native_sdk_tree_dependency_lease']['output_base']=str(base/'arbitrary')
                if fault=='command':outer['command'].insert(2,'--cache_test_results')
                raw=tree.source.encoded(outer);(run/'receipt.json').write_bytes(raw)
                row['producer']['sha256']=tree.source.sha(raw)
                document=runfiles/'fixture_repo/source-inputs.json';data=json.loads(document.read_bytes());data['selection']=row
                document.write_bytes(tree.source.encoded(data))
                with patch.object(tree,'validate_report_method'),tree.Inputs(runfiles,rows) as inputs:
                    with self.assertRaises(ValueError):tree.guardian(row,inputs)

    def test_role_only_owner600_not_arbitrary_source_or_foreign_kind(self):
        for fault in ('source-mode','proof-mode','kind'):
            with tempfile.TemporaryDirectory() as temporary:
                base=Path(temporary);row,runfiles,rows,run,outer=self.proof_fixture(base)
                if fault=='source-mode':(Path(row['root'])/'source-receipt.json').chmod(0o600)
                if fault=='proof-mode':(run/'sdk-tree-qualified.json').chmod(0o644)
                if fault=='kind':
                    p=runfiles/'fixture_repo/source-inputs.json';data=json.loads(p.read_bytes());data['kind']=model.delivery.INPUT_KIND;p.write_bytes(tree.source.encoded(data))
                with patch.object(tree,'validate_report_method'):
                    with self.assertRaises(ValueError):
                        with tree.Inputs(runfiles,rows) as inputs:tree.guardian(row,inputs)

    def test_private_after_models_prepare_partial_acquisition_closes_once(self):
        class Owner(model.AfterModelsOwner):
            def __init__(self,path):self.path=path;self.fd=None;self.closed=0
            def prepare(self,*clock):
                self.fd=os.open(self.path,os.O_RDONLY|os.O_CLOEXEC);raise ValueError('public prepare refusal')
            def close(self):
                self.closed+=1;fd,self.fd=self.fd,None
                if fd is not None:os.close(fd)
        with tempfile.TemporaryDirectory() as temporary:
            leaf=Path(temporary)/'public';leaf.write_bytes(b'public')
            owner=Owner(leaf);extra=model.ExtraOwners()
            with patch.object(model.family,'reuse_admission',return_value=(1,2,3)),patch.object(model.family,'producer_context',return_value={}):
                with self.assertRaises(ValueError):
                    with extra:extra.register_after_models(owner,1,2,3)
            self.assertEqual(owner.closed,1);self.assertIsNone(owner.fd);self.assertIsNone(extra.after_models)
            extra.close();self.assertEqual(owner.closed,1)

    def test_after_models_body_error_stays_primary_and_all_cleanup_is_attempted(self):
        primary=ValueError('public body identity');calls=[]
        class Owner(model.AfterModelsOwner):
            def close(self):calls.append('image-close');raise OSError('public close refusal')
        extra=model.ExtraOwners();extra.after_models=Owner()
        extra.streams=Mock();extra.streams.close.side_effect=lambda:calls.append('streams-close')
        extra.evidence=Mock();extra.evidence.close.side_effect=lambda:calls.append('evidence-close')
        extra.stack=Mock();extra.stack.close.side_effect=lambda:calls.append('inputs-close')
        try:
            with extra:raise primary
        except ValueError as caught:self.assertIs(caught,primary)
        else:self.fail('original body error suppressed')
        self.assertEqual(calls,['streams-close','evidence-close','inputs-close','image-close'])
        self.assertIsNone(extra.after_models)

    def test_private_image_short_is_last_and_no_image_callback_on_model_refusal(self):
        calls=[];extra=model.ExtraOwners();extra.source_family=tree
        extra.captured=Mock();extra.captured.check.side_effect=lambda:calls.append('source')
        extra.inputs=Mock();extra.inputs.check.side_effect=lambda:calls.append('input')
        extra.evidence=Mock();extra.evidence.fence.side_effect=lambda:calls.append('evidence')
        class Owner(model.AfterModelsOwner):
            def short(self):calls.append('image')
            def __call__(self,*args):calls.append('image-work')
            def close(self):pass
        extra.after_models=Owner();extra.short();self.assertEqual(calls,['source','input','evidence','image'])
        # With no after-owner, this remains a no-op and cannot imply image proof.
        extra.after_models=None;extra.after_actual_models(*([None]*9))
        self.assertNotIn('image-work',calls)

    def test_tree_route_declares_complete_data_and_old_selector_stays_null(self):
        root=Path(__file__).parent
        macro=(root/'codex_native_siwc_catalog_models_targets.bzl').read_text()
        for item in ('codex_native_siwc_catalog_tree_model_inputs.py','codex_retained_sdk_tree_reader.py',
                '@omux_retained_public_sdk_tree_proof_inputs//:inputs','//tools:codex_native_retained_sdk_tree_materialized'):
            self.assertIn(item,macro)
        cold=model.family.decode(model.family.declared(model.SELECTION,16384))
        self.assertIsNone(cold['source'])
        with self.assertRaises(ValueError):model.selection(tree.source.encoded(cold))



    def test_real_tree_owner_late_samebyte_sdk_member_replacement_refuses(self):
        with TinyCarrier() as tiny,DeclaredTreeFixture(tiny) as fixture:
            producer.materialize(fixture.materialize_args());tiny.normalize(fixture.output/'tree');fixture.publish_tree()
            with fixture.retained_source() as held:
                current=tree.reader.open_declared(fixture.runfiles,fixture.rows,fixture.entry,fixture.until,
                    fixture.source_context,held);current.__enter__()
                try:
                    leaf=current.sdk_root/'receipt.json';parent=leaf.parent;parent.chmod(0o700)
                    replacement=parent/'public-replacement';replacement.write_bytes(leaf.read_bytes());replacement.chmod(0o555)
                    saved=fixture.root/'original-receipt';leaf.rename(saved);replacement.rename(leaf);parent.chmod(0o555)
                    self.assertNotEqual(saved.stat().st_ino,leaf.stat().st_ino)
                    with self.assertRaises(ValueError):current.fence()
                finally:current.close()

    def test_private_after_actual_models_checks_source_then_invokes_owner_once(self):
        phases=[]
        class Owner(model.AfterModelsOwner):
            def __call__(self,*args):phases.append('image-work');self.args=args
            def short(self):phases.append('image-short')
            def close(self):phases.append('image-close')
        owner=Owner();extra=model.ExtraOwners();extra.source_family=tree;extra.after_models=owner
        current=object.__new__(tree.reader.HeldRetainedSdkTree)
        inputs=Mock();inputs.check_all.side_effect=lambda:phases.append('input')
        retained=Mock();retained.full.side_effect=lambda:phases.append('retained-full');retained.fence.side_effect=lambda:phases.append('retained-short')
        published=Mock();published.fence.side_effect=lambda:phases.append('source');published.terminal.side_effect=lambda:phases.append('source-terminal')
        current.fence=lambda:phases.append('sdk')
        extra.full=lambda:phases.append('extra-full');extra.short=lambda:owner.short()
        report={'producer_context':{'public':'context-fixture'}};pin={'public':'actualmodelpin-fixture'}
        cutoff=tree.source.DEADLINE
        with patch.object(model.family,'producer_context',return_value=report['producer_context']), \
                patch.object(tree,'admit_sdk',side_effect=lambda *args:phases.append('typed-sdk')), \
                patch.object(model.family.query,'DEADLINE',cutoff):
            extra.after_actual_models(published,current,report,retained,inputs,1,2,cutoff,pin)
        self.assertEqual(phases.count('image-work'),1)
        self.assertLess(phases.index('source-terminal'),phases.index('image-work'))
        self.assertGreater(phases.index('image-short'),phases.index('image-work'))
        self.assertIs(owner.args[0],extra);self.assertIs(owner.args[-1],pin)
        # This seam doesn't pretend object.__new__ provided actual SDK proof;
        # real sealed tree-owner admission is covered by the preceding methods.
        extra.after_models=None



    def test_actual_tree_repository_body_declares_every_source_hub_and_terminal_role(self):
        rule=(Path(__file__).parent/'codex_native_siwc_catalog_model_inputs.bzl').read_text()
        body=rule[rule.index('def _tree('):rule.index('def _implementation(')]
        class Literal(str):
            def elems(self):return self
            def __getitem__(self,key):
                value=super().__getitem__(key)
                return Literal(value) if type(value) is str else value
        sliced=Literal('prefix/k8-fastbuild/suffix')[len('prefix/'):-len('/suffix')]
        self.assertIs(type(sliced),Literal);self.assertEqual(sliced,'k8-fastbuild')
        self.assertEqual(list(sliced.elems()),list('k8-fastbuild'))
        def wrap(value):
            if type(value) is str:return Literal(value)
            if type(value) is dict:return {key:wrap(item) for key,item in value.items()}
            if type(value) is list:return [wrap(item) for item in value]
            return value
        kinds={dict:'dict',list:'list',int:'int',bool:'bool',str:'string',Literal:'string'}
        def type_name(value):return kinds.get(type(value),'unsupported')
        def need(value):
            if not value:raise ValueError('public declaration refusal')
        class Physical:
            def __init__(self,path):self.path=str(path)
            def __str__(self):return self.path
            @property
            def dirname(self):return Physical(self.path.rsplit('/',1)[0])
            @property
            def basename(self):return self.path.rsplit('/',1)[-1]
            @property
            def realpath(self):return self
            exists=True;is_dir=False
        codec=type('Codec',(),{'decode':staticmethod(lambda raw:wrap(json.loads(raw))),'encode':staticmethod(json.dumps)})
        namespace={'type':type_name,'json':codec,'_need':need,
            '_physical':lambda ctx,path,directory=False:Physical(path),
            '_sha':lambda value:isinstance(value,str) and re.fullmatch(r'[0-9a-f]{64}',value) is not None,
            '_name':lambda value:need(not value.startswith('/') and '..' not in value.split('/'))}
        exec(compile(body,'<actual-tree-declaration-body>','exec'),namespace)
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary);row,runfiles,rows,run,outer=self.proof_fixture(base)
            inventory={'public/'+str(i):{'mode':'100644','sha256':'a'*64} for i in range(8557)}
            report={'kind':tree.history.KIND,'status':tree.history.STATUS,'native_controls_sha256':tree.history.CONTROL_SHA,
                'source_inventory':inventory,'inventory_sha256':row['inventory_sha256'],
                'patch_sha256':['a'*64]*12+[tree.history.PATCH_SHA],'transported_sdk':{'kind':tree.reader.KIND},
                'generated_hub':{name:{'sha256':'b'*64,'bytes':1} for name in ('BUILD.bazel','defs.bzl','data.bzl')}}
            documents={str(run/'receipt.json'):json.dumps(outer),
                str(run/'sdk-tree-qualified.json'):(run/'sdk-tree-qualified.json').read_text(),
                str(run/'test-evidence.json'):(run/'test-evidence.json').read_text(),
                row['root']+'/source-receipt.json':json.dumps(report)}
            # Exact confirmation raw extent includes real outer encoded extent;
            # this declaration model doesn't authenticate its raw SHA. Action
            # guardian above does that independently with actual owned files.
            documents[str(run/'receipt.json')]=(run/'receipt.json').read_text()
            row['receipt_bytes']=len(documents[row['root']+'/source-receipt.json'])
            class Context:
                def __init__(self):self.outputs={};self.aliases=[]
                def path(self,path):return Physical(path)
                def read(self,path):return documents[str(path)]
                def watch(self,path):pass
                def symlink(self,path,alias):self.aliases.append((str(path),alias))
                def file(self,name,raw,executable=False):self.outputs[name]=raw
            value={'schema_version':1,'kind':tree.SELECTION_KIND,'status':tree.SELECTED_STATUS,
                'catalog_controls_sha256':tree.history.CONTROL_SHA,'source':row}
            ctx=Context();namespace['_tree'](ctx,wrap(value))
            mapped=json.loads(ctx.outputs['source-inputs.json'])
            self.assertEqual(mapped['kind'],tree.INPUT_KIND)
            self.assertEqual(len(mapped['inputs']),8557+8+3)
            paths={item['path'] for item in mapped['inputs']}
            self.assertIn(str(run/'sdk-tree-qualified.json'),paths)
            self.assertTrue(all(row['root']+'/source/'+name in paths for name in inventory))
            original_evidence=json.loads(documents[str(run/'test-evidence.json')])
            for optional in ('stale','empty'):
                evidence=copy.deepcopy(original_evidence);optional_paths=[]
                for result in evidence['results']:
                    for member in result['files'][2:]:
                        if optional == 'stale':member['state']='stale'
                        else:
                            name=tree.source.sha((result['target']+member['source']).encode())+'.evidence'
                            member.update(state='copied',file=name,sha256=tree.source.sha(b''))
                            optional_paths.append(str(run/'test-evidence'/name))
                documents[str(run/'test-evidence.json')]=json.dumps(evidence)
                accepted=Context();namespace['_tree'](accepted,wrap(value))
                selected_paths={item['path'] for item in json.loads(accepted.outputs['source-inputs.json'])['inputs']}
                self.assertEqual(len(selected_paths),len(paths)+len(optional_paths))
                self.assertTrue(all(path in selected_paths for path in optional_paths))
            bad=copy.deepcopy(original_evidence);bad['results'][0]['files'][2]['state']='copy-refused'
            documents[str(run/'test-evidence.json')]=json.dumps(bad)
            with self.assertRaises(ValueError):namespace['_tree'](Context(),wrap(value))
            documents[str(run/'test-evidence.json')]=json.dumps(original_evidence)
            for key,changed in (('kind',tree.history.content.KIND),('patch_sha256',['a'*64]*12),
                    ('transported_sdk',{'kind':model.content_catalog.transported.KIND})):
                wrong={**report,key:changed};documents[row['root']+'/source-receipt.json']=json.dumps(wrong)
                failed=copy.deepcopy(value);failed['source']['receipt_bytes']=len(json.dumps(wrong))
                with self.assertRaises(ValueError):namespace['_tree'](Context(),wrap(failed))


    def test_actual_optional_stale_and_copied_empty_roles_match_collector_grammar(self):
        for optional in ('stale','empty'):
            with tempfile.TemporaryDirectory() as temporary:
                base=Path(temporary);row,runfiles,rows,run,outer=self.proof_fixture(base,optional=optional)
                with patch.object(tree,'validate_report_method'),tree.Inputs(runfiles,rows) as inputs:
                    actual,required=tree.guardian(row,inputs)
                    self.assertEqual(actual,outer);self.assertEqual(set(inputs.rows),required)
                    self.assertEqual(len(required),12 if optional == 'empty' else 8)
                    empty=[path for path,value in inputs.held.items() if value[2][6] == 0]
                    self.assertEqual(len(empty),4 if optional == 'empty' else 0)
                    if empty:
                        path=Path(empty[0]);replacement=path.parent/'replacement'
                        replacement.write_bytes(b'');replacement.chmod(0o600);replacement.replace(path)
                        with self.assertRaises(ValueError):inputs.check_all()

    def test_samebyte_outer_replaced_before_first_read_fails_creator_witness_join(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary);row,runfiles,rows,run,outer=self.proof_fixture(base)
            path=run/'receipt.json';before=tree.family.tenth.witness(path.stat());raw=path.read_bytes()
            replacement=run/'replacement';replacement.write_bytes(raw);replacement.chmod(0o600);replacement.replace(path)
            self.assertEqual(tree.source.sha(path.read_bytes()),row['producer']['sha256'])
            self.assertNotEqual(tree.family.tenth.witness(path.stat()),before)
            with patch.object(tree,'validate_report_method'),tree.Inputs(runfiles,rows) as inputs:
                with self.assertRaises(ValueError):tree.guardian(row,inputs)
                self.assertEqual(inputs.held[str(path)][2],tree.family.tenth.witness(path.stat()))

    def test_empty_role_cannot_authorize_core_metadata_log_or_arbitrary_alias(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary);row,runfiles,rows,run,outer=self.proof_fixture(base,optional='empty')
            with patch.object(tree,'validate_report_method'),tree.Inputs(runfiles,rows) as inputs:
                tree.guardian(row,inputs)
                evidence=json.loads((run/'test-evidence.json').read_bytes())
                member=evidence['results'][0]['files'][2]
                path=run/'test-evidence'/member['file']
                for changed in ({**member,'source':'test.log'},{**member,'state':'copy-refused'},
                        {**member,'sha256':'a'*64},{**member,'bytes':1}):
                    with self.assertRaises(ValueError):inputs.read_empty_optional(path,changed,tree.source.DEADLINE)
                with self.assertRaises(ValueError):inputs.read_empty_optional(run/'receipt.json',member,tree.source.DEADLINE)
                # No optional read is active: default capture still refuses an
                # empty copied leaf; it cannot acquire zero-byte authority.
                with self.assertRaises(ValueError):inputs._capture(path,64*1024*1024)


if __name__ == '__main__':unittest.main()
