"""Typed historical facts and actual held role/alias IO; no SOURCE/native proof."""
import copy
import json
import os
from pathlib import Path
import re
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch
import codex_native_siwc_catalog_models as model
import codex_native_siwc_content_delivery_inputs as delivery

source, family = delivery.source, delivery.family


def encoded(value):
    return (json.dumps(value,sort_keys=True,separators=(',',':'))+'\n').encode()


class RetainedDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.before = source.DEADLINE
        source.DEADLINE = time.monotonic()+120
    def tearDown(self): source.DEADLINE = self.before

    def fixture(self, base, *, phase_mode=0o600, mutation=None):
        # Only producer scope is narrowed to this actual private fixture root.
        # All schema, worker/cleanup, raw pins, roles, declarations, aliases and
        # held/named full-nine IO remain production predicates. Tiny receipt is
        # not a complete SOURCE; this exercises only proof admission.
        identifier = '01234567-0123-0123-0123-0123456789ab'
        run = base/identifier; run.mkdir()
        retained = run/'native-content-retained'; retained.mkdir()
        root = retained/delivery.LEAF; root.mkdir()
        report_path = root/'source-receipt.json'; report_raw=b'public receipt-only fixture\n'
        report_path.write_bytes(report_raw); report_path.chmod(0o444)
        entry = 1000000000; until=entry+1200*10**9
        context = {'MODE':delivery.guard.INPUT_MODE,'ENTRY_NS':str(entry),'DEADLINE_NS':str(until),
            'EPOCH':str(run),'SOURCE_COMMIT':'a'*40,'GRAPH_SHA256':'b'*64}
        bounds = {'memory.max':str(delivery.guard.MEMORY),'memory.swap.max':'0',
            'pids.max':str(delivery.guard.TASKS),'cpu.max':'190000 100000','memory.oom.group':'1'}
        def worker(identity):
            return {'unit':'omux-execution-'+identity+'.service','invocation':'c'*32,'pid':123,
                'start_ticks':'12345','cgroup':'/sys/fs/cgroup/system.slice/omux-execution-'+identity+'.service',
                'kernel_bounds':bounds.copy()}
        def cleanup():
            return {'state':'empty','stop':'succeeded','ownership':'verified','readback_attempts':2,
                'pre_stop':{'schema_version':1,'scope':'reserved-owned-pre-stop-diagnostic-v1',
                    'LoadState':'loaded','ActiveState':'active','SubState':'exited','MainPID':'zero','RemainAfterExit':'yes',
                    'Id_matches':True,'InvocationID_matches':True,'ExecMainPID_matches':True,
                    'ExecMainCode':'1','ExecMainStatus':0,'Result':'success','terminal_class':'unqualified'},
                'post_stop':{'schema_version':1,'scope':'reserved-owned-post-stop-diagnostic-v1',
                    'Id_matches':True,'InvocationID_matches':True,'ExecMainPID_matches':True,
                    'MainPID':'zero','ActiveState':'inactive','SubState':'dead','LoadState':'loaded',
                    'original_cgroup_state':'absent','predicate':'manager-predicate-passed'}}
        resident={'scope':'sampled-fixed-default-cgroup-kernel-reservation-v1',
            'kernel_bounds':{'memory.max':str(delivery.guard.kernel.resident.RESIDENT_MEMORY),
            'memory.swap.max':'0','pids.max':str(delivery.guard.kernel.resident.RESIDENT_TASKS),
            'cpu.max':'10000 100000'},'observations':3,'initial_direct_processes_retained':True,
            'initial_direct_process_count':1,'outer_pid_namespace_matched':True,'hierarchical_caps':True,
            'descendant_process_inventory':False,'installation_qualified':False,'health_observed':False,
            'custody_observed':False,'resident_signalled':False,'whole_host_reservation':False}
        evidence_dir=run/'test-evidence'; evidence_dir.mkdir()
        evidence={'schema':1,'bazel_exit':0,'epoch_start_ns':1,'targets':delivery.guard.ARGUMENTS[1:],'results':[]}
        for index,target in enumerate(evidence['targets']):
            files=[]
            for extension in ('log','xml'):
                body=(b'public fixture successful model log\n' if extension=='log' else
                    b'<testsuite tests="1" failures="0" errors="0"><testcase name="public"/></testsuite>')
                # Filename identity intentionally differs from raw content SHA.
                name=source.sha((target+extension).encode())+'.evidence'
                path=evidence_dir/name;path.write_bytes(body);path.chmod(0o600)
                files.append({'source':'test.'+extension,'state':'copied','file':name,'sha256':source.sha(body),'bytes':len(body)})
            evidence['results'].append({'target':target,'state':'observed','configuration':'k8-fastbuild','files':files})
        evidence_raw=encoded(evidence);(run/'test-evidence.json').write_bytes(evidence_raw);(run/'test-evidence.json').chmod(0o600)
        evidence_ref={'state':'preserved','manifest':'test-evidence.json','sha256':source.sha(evidence_raw),
            'bytes':sum(row['bytes'] for result in evidence['results'] for row in result['files']),'files':4}
        lease={'kind':'omux-native-siwc-content-dependency-lease-v1','key':'d'*64,'namespace':'cache-v2-'+'d'*64,
            'output_base':str(base/('cache-v2-'+'d'*64)/'output-base'),'run_id':identifier,'checkout':str(base/'checkout'),
            'source_commit':context['SOURCE_COMMIT'],'graph_sha256':context['GRAPH_SHA256'],
            'entry_monotonic_ns':entry,'deadline_monotonic_ns':until}
        def command(targets, **extra):
            args=['/nix/store/public-bazel-fixture/bin/bazel','--remote_executor=','--remote_cache=',
                'test','--nocache_test_results','--repository_disable_download','--repo_contents_cache=']
            args += ['--test_env=OMUX_NATIVE_FILE_WRITER_MODELS_'+key+'='+value for key,value in context.items()]
            if targets==delivery.guard.ARGUMENTS[1:]:
                args += ['--repo_env=OMUX_NATIVE_FILE_WRITER_MODELS_'+key+'='+value for key,value in context.items()]
            args += [prefix+value for prefix,value in extra.items()]
            return args+targets
        phase={'schema_version':1,'kind':delivery.PHASE_KIND,'id':identifier,'profile':delivery.guard.PROFILE,
            'targets':delivery.guard.ARGUMENTS[1:],'source_commit':context['SOURCE_COMMIT'],'graph_sha256':context['GRAPH_SHA256'],
            'context':context,'clocks':{'source_until_ns':entry+600*10**9,'work_until_ns':until-30*10**9,'outer_until_ns':until},
            'exit':0,'workload_exit':0,'epoch_start_ns':1,'output_base':lease['output_base'],
            'cache_reuse_requested':True,'cache_policy':2,'cache_key':lease['key'],'dependency_lease':lease,
            'command':command(delivery.guard.ARGUMENTS[1:],**{'--test_timeout=':'840'}),'limits':{'public':'bounded kernel facts separately checked'},
            'worker':worker(identifier),'cleanup':cleanup(),'descendants_empty':True,'test_evidence':evidence_ref,
            'native_siwc_catalog_content_source_reservation':delivery.guard.projection(entry,until,True,resident)}
        phase_raw=encoded(phase);phase_pin={'sha256':source.sha(phase_raw),'bytes':len(phase_raw)}
        (run/'source-phase-receipt.json').write_bytes(phase_raw);(run/'source-phase-receipt.json').chmod(phase_mode)
        publication={'schema_version':1,'kind':delivery.PUBLICATION_KIND,'scope':'operational-fresh-source-hub-delivery-only',
            'context':context,'clocks':phase['clocks'],'dependency_lease':lease,
            'source_phase_receipt_sha256':phase_pin['sha256'],'test_evidence_sha256':evidence_ref['sha256'],
            'original_action':{'root':str(Path(lease['output_base'])/'execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_native_siwc_catalog_content_source_producer/test.outputs'/delivery.LEAF),
                'source_receipt_sha256':source.sha(report_raw),'source_receipt_bytes':len(report_raw),'inventory_sha256':'e'*64},
            'publication':{'root':str(root),'members':{'source/public-'+str(i):{} for i in range(8559)},
                'source_bytes':8557,'fresh_witnesses_sha256':'f'*64},**{flag:False for flag in delivery.FLAGS}}
        publication_raw=encoded(publication);publication_pin={'sha256':source.sha(publication_raw),'bytes':len(publication_raw)}
        (retained/'publication-receipt.json').write_bytes(publication_raw);(retained/'publication-receipt.json').chmod(0o444)
        request={'schema_version':1,'kind':'omux-native-siwc-content-delivery-request-v1','context':context,
            'clocks':phase['clocks'],'dependency_lease':lease,'source_phase_receipt_sha256':phase_pin['sha256'],
            'test_evidence_sha256':evidence_ref['sha256'],'configuration':'k8-fastbuild'}
        identity=str(uuid.uuid5(uuid.UUID(identifier),'omux-native-siwc-content-delivery-v1'))
        delivered={'unit':'omux-execution-'+identity+'.service','started':True,'phase':'complete',
            'worker':worker(identity),'cleanup':cleanup(),
            'test_evidence':{'state':'preserved','manifest':'delivery-evidence/test-evidence.json','sha256':'9'*64,'bytes':12,'files':2},
            'exit':0,'workload_exit':0,'effective_timeout_seconds':840,'timeout_sample_monotonic_ns':entry,
            'command':command([delivery.DELIVERY_TARGET],**{'--output_base=':str(run/'delivery-output-base'),
                '--output_user_root=':str(run/'delivery-user-root'),'--test_timeout=':'840',
                '--test_env=OMUX_NATIVE_SIWC_CONTENT_DELIVERY_REQUEST=':str(run/'native-content-delivery-request.json'),
                '--test_env=OMUX_NATIVE_SIWC_CONTENT_DELIVERY_REQUEST_SHA256=':source.sha(encoded(request))})}
        descriptor={'kind':delivery.PUBLICATION_KIND,'root':str(root),
            'transport_receipt':{'path':str(retained/'publication-receipt.json'),**publication_pin},
            'source_receipt':{'sha256':source.sha(report_raw),'bytes':len(report_raw),'inventory_sha256':'e'*64},
            'context':context,'source_phase_receipt_sha256':phase_pin['sha256'],
            'test_evidence_sha256':evidence_ref['sha256'],'original_action_sdk_custody_inherited':False}
        outer={**{key:phase[key] for key in ('id','profile','targets','source_commit','graph_sha256','exit','workload_exit',
            'epoch_start_ns','output_base','cache_reuse_requested','cache_policy','cache_key','command','limits','cleanup',
            'test_evidence','descendants_empty','native_siwc_catalog_content_source_reservation')},
            'controller_failure':None,'source_dirty':'false','verb':'test','manager':'system',
            'unit':phase['worker']['unit'],'observed_properties':{'MainPID':str(phase['worker']['pid']),
                'ControlGroup':phase['worker']['cgroup'][len('/sys/fs/cgroup'):],'RuntimeMaxUSec':'14min',
                'ActiveState':'active','Result':'success'},
            'startup_history':[{'ActiveState':'active','SubState':'running','Result':'success','Job':'0',
                'MainPID':str(phase['worker']['pid']),'ExecMainPID':str(phase['worker']['pid']),
                'ControlGroup':phase['worker']['cgroup'][len('/sys/fs/cgroup'):]}],
            'original_cgroup_identity':{'device':1,'inode':2},
            'source_phase_receipt':{'path':'source-phase-receipt.json',**phase_pin},
            'native_siwc_content_publication':descriptor,'native_siwc_content_delivery':delivered,
            'native_siwc_content_dependency_disposition':{'kind':'omux-native-siwc-content-dependency-disposition-v1',
                'state':'dependencies-after-owned-source-and-delivery-success','checkout':lease['checkout'],'key':lease['key'],
                'source_qualified_by_disposition':False,'delivery_qualified_by_disposition':False,'native_runtime_qualified':False}}
        outer=copy.deepcopy(outer)
        if mutation is not None:mutation(outer)
        outer_raw=encoded(outer);(run/'receipt.json').write_bytes(outer_raw);(run/'receipt.json').chmod(0o600)
        selected={'root':str(root),'receipt_sha256':source.sha(report_raw),'receipt_bytes':len(report_raw),'inventory_sha256':'e'*64,
            'producer':{'receipt':str(run/'receipt.json'),'sha256':source.sha(outer_raw),'source_commit':'a'*40,'graph_sha256':'b'*64},
            'source_phase_receipt':phase_pin,'transport_receipt':publication_pin}
        paths=[root/'source-receipt.json',run/'receipt.json',run/'test-evidence.json',run/'source-phase-receipt.json',retained/'publication-receipt.json']
        paths += [evidence_dir/member['file'] for result in evidence['results'] for member in result['files']]
        repository=base/'external'/'fixture_repo';repository.mkdir(parents=True)
        alias_dir=repository/'input';alias_dir.mkdir()
        document={'kind':delivery.INPUT_KIND,'selection':selected,'inputs':[]}
        for index,path in enumerate(paths):
            alias='input/'+str(index);(repository/alias).symlink_to(path)
            document['inputs'].append({'path':str(path),'alias':alias})
        (repository/'source-inputs.json').write_bytes(encoded(document));(repository/'source-inputs.json').chmod(0o644)
        runfiles=base/'runfiles';runfiles.mkdir();(runfiles/'fixture_repo').symlink_to(repository)
        return selected,runfiles,[['_main',delivery.REPOSITORY,'fixture_repo']],run,outer

    def scope(self, base):
        return patch.object(family.protocol,'PRODUCER_SCOPE',re.compile(re.escape(str(base))+r'/[0-9a-f-]{36}/receipt.json'))

    def test_new_closed_selector_cannot_be_presented_as_old_family_or_arbitrary_root(self):
        producer={'receipt':'/home/jess/.local/state/omux-execution-20261005/01234567-0123-0123-0123-0123456789ab/receipt.json',
            'sha256':'a'*64,'source_commit':'b'*40,'graph_sha256':'c'*64}
        row={'root':str(Path(producer['receipt']).parent/'native-content-retained'/delivery.LEAF),
            'receipt_sha256':'d'*64,'receipt_bytes':1,'inventory_sha256':'e'*64,'producer':producer,
            'transport_receipt':{'sha256':'f'*64,'bytes':1},'source_phase_receipt':{'sha256':'0'*64,'bytes':1}}
        value={'schema_version':1,'kind':delivery.SELECTION_KIND,'status':delivery.STATUS,
            'catalog_controls_sha256':model.catalog.CONTROL_SHA,'source':row}
        self.assertEqual(model.selection(encoded(value)),value)
        changes=[{**value,'kind':'omux-native-siwc-catalog-model-selection-v1'},
            {**value,'status':'qualified-catalog-content-source-hub-uncompiled'},{**value,'source':None},
            {**value,'source':{**row,'root':str(Path(producer['receipt']).parent/'output-base/replayed')}},
            {**value,'source':{k:v for k,v in row.items() if k!='transport_receipt'}}]
        for wrong in changes:
            with self.assertRaises(ValueError):model.selection(encoded(wrong))

    def test_actual_declared_proof_admission_joins_private_roles_and_no_original_cache_reads(self):
        for mode in (0o400,0o600):
            with tempfile.TemporaryDirectory() as temporary:
                base=Path(temporary);row,runfiles,rows,run,outer=self.fixture(base,phase_mode=mode)
                self.assertFalse(Path(outer['output_base']).exists())
                before=set(os.listdir('/proc/self/fd'))
                with self.scope(base),delivery.RetainedInputs(runfiles,rows) as inputs:
                    accepted,required=delivery.guardian(row,inputs)
                    self.assertEqual(accepted,outer);self.assertEqual(set(inputs.rows),required)
                    self.assertEqual(len(required),9)
                    self.assertNotIn(str(Path(outer['output_base'])),inputs.held)
                    delivery.guardian(row,inputs)
                self.assertEqual(set(os.listdir('/proc/self/fd')),before)

    def test_delivery_failed_missing_cleanup_unknown_worker_or_dependency_only_cannot_admit(self):
        def removed(value):value.pop('native_siwc_content_delivery')
        changes=[removed,lambda v:v['native_siwc_content_delivery'].update(exit=125),
            lambda v:v['native_siwc_content_delivery'].update(started=False),
            lambda v:v['native_siwc_content_delivery'].update(phase='cleanup'),
            lambda v:v['native_siwc_content_delivery']['cleanup'].update(ownership='unproved'),
            lambda v:v['native_siwc_content_delivery']['cleanup'].update(readback_attempts=1),
            lambda v:v['native_siwc_content_delivery']['worker'].update(invocation='unknown'),
            lambda v:v['native_siwc_content_dependency_disposition'].update(state='dependency-only-after-owned-source-failure'),
            lambda v:v.update(exit=3,workload_exit=3)]
        for changed in changes:
            with tempfile.TemporaryDirectory() as temporary:
                base=Path(temporary);row,runfiles,rows,run,unused=self.fixture(base,mutation=changed)
                before=set(os.listdir('/proc/self/fd'))
                with self.scope(base),delivery.RetainedInputs(runfiles,rows) as inputs:
                    with self.assertRaises((ValueError,KeyError)):delivery.guardian(row,inputs)
                self.assertEqual(set(os.listdir('/proc/self/fd')),before)

    def test_final_source_unit_startup_process_and_action_runtime_cannot_contradict_checkpoint(self):
        changes=[lambda v:v.pop('unit'),lambda v:v.pop('observed_properties'),
            lambda v:v['observed_properties'].pop('MainPID'),
            lambda v:v['observed_properties'].pop('ControlGroup'),
            lambda v:v.pop('startup_history'),
            lambda v:v['startup_history'][-1].update(MainPID='124'),
            lambda v:v['startup_history'][-1].update(ExecMainPID='124'),
            lambda v:v['startup_history'][-1].update(ControlGroup='/system.slice/other.service'),
            lambda v:v['original_cgroup_identity'].update(inode=None),
            lambda v:v.update(unit='omux-execution-'+str(uuid.uuid4())+'.service'),
            lambda v:v['observed_properties'].update(MainPID='124'),
            lambda v:v['observed_properties'].update(ControlGroup='/system.slice/other.service'),
            lambda v:v['observed_properties'].update(RuntimeMaxUSec='15min'),
            lambda v:v['observed_properties'].pop('RuntimeMaxUSec')]
        for changed in changes:
            with tempfile.TemporaryDirectory() as temporary:
                base=Path(temporary);row,runfiles,rows,run,unused=self.fixture(base,mutation=changed)
                with self.scope(base),delivery.RetainedInputs(runfiles,rows) as inputs:
                    with self.assertRaises((ValueError,KeyError)):delivery.guardian(row,inputs)
        # SOURCE timeout validation directly exercises the production command
        # predicate with its original authenticated context and complete argv.
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary);row,runfiles,rows,run,outer=self.fixture(base)
            phase=family.decode((run/'source-phase-receipt.json').read_bytes())
            delivery._command(phase['command'],phase['context'])
            for raw in ('0','841','0840','1200','bad'):
                changed=[part if not part.startswith('--test_timeout=') else '--test_timeout='+raw
                    for part in phase['command']]
                with self.assertRaises(ValueError):delivery._command(changed,phase['context'])
            with self.assertRaises(ValueError):
                delivery._command([part for part in phase['command'] if not part.startswith('--test_timeout=')],phase['context'])
            with self.assertRaises(ValueError):
                delivery._command(phase['command'][:-2]+['--test_timeout=840']+phase['command'][-2:],phase['context'])
            with self.assertRaises(ValueError):
                delivery._command(phase['command'][:-2]+['--test_timeout','1200']+phase['command'][-2:],phase['context'])

    def test_final_resident_sample_can_advance_without_renewing_source_clock_or_bounds(self):
        key='native_siwc_catalog_content_source_reservation'
        cases=[('increased',lambda v:v[key]['resident'].update(observations=4),True),
            ('regressed',lambda v:v[key]['resident'].update(observations=2),False),
            ('overflow',lambda v:v[key]['resident'].update(observations=65536),False),
            ('bounds',lambda v:v[key]['resident']['kernel_bounds'].update(**{'pids.max':'31'}),False),
            ('process',lambda v:v[key]['resident'].update(initial_direct_process_count=2),False),
            ('namespace',lambda v:v[key]['resident'].update(outer_pid_namespace_matched=False),False),
            ('clock',lambda v:v[key].update(original_entry_monotonic_ns=2),False)]
        for name,changed,accepted in cases:
            with tempfile.TemporaryDirectory() as temporary:
                base=Path(temporary);row,runfiles,rows,run,unused=self.fixture(base,mutation=changed)
                with self.scope(base),delivery.RetainedInputs(runfiles,rows) as inputs:
                    if accepted:
                        outer,unused=delivery.guardian(row,inputs)
                        self.assertEqual(outer[key]['resident']['observations'],4)
                        self.assertEqual(inputs.publication['clocks']['source_until_ns'],601*10**9)
                    else:
                        with self.assertRaises(ValueError):delivery.guardian(row,inputs)

    def test_original_deadline_timeout_request_pin_and_local_cache_flags_are_exact(self):
        changes=[lambda v:v['native_siwc_content_delivery'].update(effective_timeout_seconds=841),
            lambda v:v['native_siwc_content_delivery'].update(timeout_sample_monotonic_ns=1201*10**9),
            lambda v:v['native_siwc_content_delivery']['command'].insert(-1,'--remote_cache=https://untrusted.invalid'),
            lambda v:v['native_siwc_content_delivery']['command'].insert(-1,'--cache_test_results=yes'),
            lambda v:v['native_siwc_content_delivery']['command'].__setitem__(slice(-1,-1),['--test_timeout','1200']),
            lambda v:v['native_siwc_content_delivery']['command'].__setitem__(-2,'--test_env=OMUX_NATIVE_SIWC_CONTENT_DELIVERY_REQUEST_SHA256='+'0'*64),
            lambda v:v.update(cache_policy=None,cache_reuse_requested=False)]
        for changed in changes:
            with tempfile.TemporaryDirectory() as temporary:
                base=Path(temporary);row,runfiles,rows,run,unused=self.fixture(base,mutation=changed)
                with self.scope(base),delivery.RetainedInputs(runfiles,rows) as inputs:
                    with self.assertRaises(ValueError):delivery.guardian(row,inputs)
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary);row,runfiles,rows,run,unused=self.fixture(base)
            with self.scope(base),delivery.RetainedInputs(runfiles,rows) as inputs:
                source.DEADLINE=time.monotonic()-1
                with self.assertRaises(ValueError):delivery.guardian(row,inputs)

    def test_wrong_role_writable_private_mode_and_missing_declared_member_refuse(self):
        for fault in ('source0400','phase0644','publication0600','omitted'):
            with tempfile.TemporaryDirectory() as temporary:
                base=Path(temporary);row,runfiles,rows,run,unused=self.fixture(base)
                if fault=='source0400':Path(row['root'],'source-receipt.json').chmod(0o400)
                elif fault=='phase0644':(run/'source-phase-receipt.json').chmod(0o644)
                elif fault=='publication0600':(run/'native-content-retained/publication-receipt.json').chmod(0o600)
                else:
                    doc_path=base/'external/fixture_repo/source-inputs.json';doc=family.decode(doc_path.read_bytes())
                    doc['inputs'].pop();doc_path.write_bytes(encoded(doc))
                    (base/'external/fixture_repo/input/8').unlink()
                with self.scope(base),delivery.RetainedInputs(runfiles,rows) as inputs:
                    with self.assertRaises((ValueError,KeyError)):
                        delivery.guardian(row,inputs)
                        inputs.read(Path(row['root'])/'source-receipt.json',row['receipt_sha256'],source.DEADLINE)

    def test_late_same_byte_phase_replacement_and_alias_replacement_refuse_and_drain(self):
        for fault in ('phase','alias'):
            with tempfile.TemporaryDirectory() as temporary:
                base=Path(temporary);row,runfiles,rows,run,unused=self.fixture(base)
                before=set(os.listdir('/proc/self/fd'))
                with self.scope(base),delivery.RetainedInputs(runfiles,rows) as inputs:
                    delivery.guardian(row,inputs)
                    if fault=='phase':
                        path=run/'source-phase-receipt.json';raw=path.read_bytes();path.unlink();path.write_bytes(raw);path.chmod(0o600)
                    else:
                        alias=inputs.rows[str(run/'source-phase-receipt.json')];literal=os.readlink(alias);alias.unlink();alias.symlink_to(literal)
                    with self.assertRaises(ValueError):delivery.guardian(row,inputs)
                self.assertEqual(set(os.listdir('/proc/self/fd')),before)

    def test_authenticated_transport_flags_never_inherit_previous_action_sdk_or_runtime_authority(self):
        for flag in delivery.FLAGS:
            with tempfile.TemporaryDirectory() as temporary:
                base=Path(temporary);row,runfiles,rows,run,outer=self.fixture(base)
                path=run/'native-content-retained/publication-receipt.json'
                value=family.decode(path.read_bytes());value[flag]=True
                raw=encoded(value);path.chmod(0o644);path.write_bytes(raw);path.chmod(0o444)
                row['transport_receipt']={'sha256':source.sha(raw),'bytes':len(raw)}
                outer['native_siwc_content_publication']['transport_receipt']={'path':str(path),**row['transport_receipt']}
                outer_raw=encoded(outer);(run/'receipt.json').write_bytes(outer_raw)
                row['producer']['sha256']=source.sha(outer_raw)
                document_path=base/'external/fixture_repo/source-inputs.json'
                document=family.decode(document_path.read_bytes());document['selection']=row;document_path.write_bytes(encoded(document))
                with self.scope(base),delivery.RetainedInputs(runfiles,rows) as inputs:
                    with self.assertRaises(ValueError):delivery.guardian(row,inputs)

    def test_new_capture_callback_failure_before_or_after_enrollment_acquires_no_unowned_fd(self):
        for selected in (1,2):
            for appended in (False,True):
                with tempfile.TemporaryDirectory() as temporary:
                    base=Path(temporary);row,runfiles,rows,run,unused=self.fixture(base)
                    original=family.ExitStack.callback;owners=[];failed=[]
                    def callback(stack,method,*args,**kwargs):
                        owner=getattr(method,'__self__',None)
                        if isinstance(owner,delivery._OwnedFD):
                            owners.append(owner)
                            self.assertIsNone(owner.fd)
                            if len(owners)==selected:
                                failed.append(owner)
                                if appended:original(stack,method,*args,**kwargs)
                                raise MemoryError('public registration fixture')
                        return original(stack,method,*args,**kwargs)
                    before=set(os.listdir('/proc/self/fd'))
                    with patch.object(family.ExitStack,'callback',new=callback):
                        with self.assertRaises(MemoryError):delivery.RetainedInputs(runfiles,rows)
                    self.assertEqual(len(failed),1);self.assertTrue(all(owner.fd is None for owner in owners))
                    self.assertEqual(set(os.listdir('/proc/self/fd')),before)

    def test_interpreted_option_families_refuse_bare_overrides_and_boolean_aliases_in_both_phases(self):
        # The actual production command predicate receives otherwise-valid
        # SOURCE and delivery argv/context; this is not a Bazel parse claim.
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary);row,runfiles,rows,run,outer=self.fixture(base)
            phase=family.decode((run/'source-phase-receipt.json').read_bytes())
            context=phase['context']
            assignments=[('remote_cache','https://untrusted.invalid'),
                ('remote_executor','https://untrusted.invalid'),('repo_contents_cache','/public/other'),
                ('test_timeout','1200'),('output_base','/public/other'),('output_user_root','/public/other'),
                ('test_env','OMUX_NATIVE_FILE_WRITER_MODELS_ENTRY_NS=2'),
                ('repo_env','OMUX_NATIVE_FILE_WRITER_MODELS_ENTRY_NS=2'),
                ('test_env','OMUX_NATIVE_SIWC_CONTENT_DELIVERY_REQUEST_SHA256='+'0'*64)]
            faults=[['--'+name,value] for name,value in assignments]
            faults += [['--'+name+':'+value] for name,value in assignments]
            faults += [['--nocache_test_results=false'],['--nocache_test_results=true'],
                ['--cache_test_results=yes'],['--nocache_test_results'],
                ['--repository_disable_download=false'],['--repository_disable_download=true'],
                ['--norepository_disable_download'],['--repository_disable_download'],
                ['--repo_contents_cache=/public/other'],['--test_filter','public'],
                ['--test_filter=public'],['--test_arg','public'],['--test_arg=public']]
            for is_delivery in (False,True):
                argv=outer['native_siwc_content_delivery']['command'] if is_delivery else phase['command']
                target_count=1 if is_delivery else 2
                kwargs={}
                if is_delivery:
                    prefix='--test_env=OMUX_NATIVE_SIWC_CONTENT_DELIVERY_REQUEST_SHA256='
                    pin=[part[len(prefix):] for part in argv if part.startswith(prefix)]
                    self.assertEqual(len(pin),1)
                    kwargs={'delivery':True,'timeout':outer['native_siwc_content_delivery']['effective_timeout_seconds'],
                        'request_pin':pin[0]}
                delivery._command(argv,context,**kwargs)
                # Legitimate other canonical options and unrelated env keys
                # remain accepted; this is not an arbitrary Bazel whitelist.
                extra=['--jobs=1','--test_output=errors','--compilation_mode=opt',
                    '--test_env=PUBLIC_FIXTURE=ok','--repo_env=PUBLIC_FIXTURE=ok']
                delivery._command(argv[:-target_count]+extra+argv[-target_count:],context,**kwargs)
                for added in faults:
                    changed=argv[:-target_count]+added+argv[-target_count:]
                    with self.assertRaises(ValueError):delivery._command(changed,context,**kwargs)
                protected = ['OMUX_NATIVE_FILE_WRITER_MODELS_'+name for name in context]
                requests = ['OMUX_NATIVE_SIWC_CONTENT_DELIVERY_REQUEST',
                    'OMUX_NATIVE_SIWC_CONTENT_DELIVERY_REQUEST_SHA256']
                for kind in ('test_env','repo_env'):
                    for key in protected+requests:
                        for entry in (key,key+'=wrong'):
                            changed=argv[:-target_count]+['--'+kind+'='+entry]+argv[-target_count:]
                            with self.assertRaises(ValueError):delivery._command(changed,context,**kwargs)
                # Unrelated inherited names remain legal; protected optional
                # delivery repo context may be present only explicitly correct.
                extra=['--test_env=PUBLIC_INHERITED_FIXTURE','--repo_env=PUBLIC_INHERITED_FIXTURE']
                if is_delivery:
                    extra += ['--repo_env=OMUX_NATIVE_FILE_WRITER_MODELS_'+key+'='+value
                        for key,value in context.items()]
                delivery._command(argv[:-target_count]+extra+argv[-target_count:],context,**kwargs)


    def test_constructor_metadata_failure_closes_every_real_enrolled_descriptor(self):
        with tempfile.TemporaryDirectory() as temporary:
            base=Path(temporary);row,runfiles,rows,run,unused=self.fixture(base)
            original=os.fstat; failed=[]
            def fstat(fd):
                value=original(fd)
                if delivery.stat.S_ISREG(value.st_mode) and not failed:
                    failed.append(fd);raise OSError('public constructor metadata fault')
                return value
            before=set(os.listdir('/proc/self/fd'))
            with patch.object(delivery.os,'fstat',side_effect=fstat):
                with self.assertRaises(OSError):delivery.RetainedInputs(runfiles,rows)
            self.assertEqual(len(failed),1)
            with self.assertRaises(OSError):original(failed[0])
            self.assertEqual(set(os.listdir('/proc/self/fd')),before)

    def test_complete_logical_members_require_literal_links_exact_hub_and_false_sdk_custody(self):
        context={'MODE':delivery.guard.INPUT_MODE,'EPOCH':'/public/01234567-0123-0123-0123-0123456789ab',
            'SOURCE_COMMIT':'a'*40,'GRAPH_SHA256':'b'*64,'ENTRY_NS':'1','DEADLINE_NS':str(1+1200*10**9)}
        files={'public/'+str(i):('100644',b'public\n') for i in range(8556)}
        files['public/link']=('120000',b'0')
        hub={'BUILD.bazel':b'public hub\n'};raw=b'public receipt\n'
        report={'source_bytes':sum(len(body) for mode,body in files.values()),'inventory_sha256':'c'*64,
            'producer_context':{'mode':context['MODE'],'epoch':context['EPOCH'],'source_commit':context['SOURCE_COMMIT'],
                'graph_sha256':context['GRAPH_SHA256'],'entry_monotonic_ns':1,'deadline_monotonic_ns':1+1200*10**9}}
        members={**{'source/'+name:{'mode':mode,'sha256':source.sha(body),'bytes':len(body),
            'physical_mode':0o777 if mode=='120000' else 0o555,**({'literal':body.decode()} if mode=='120000' else {})}
            for name,(mode,body) in files.items()},'hub/source/BUILD.bazel':{'mode':'100644','sha256':source.sha(hub['BUILD.bazel']),
                'bytes':len(hub['BUILD.bazel']),'physical_mode':0o555},
            'source-receipt.json':{'mode':'100644','sha256':source.sha(raw),'bytes':len(raw),'physical_mode':0o444}}
        publication={'context':context,'original_action':{'source_receipt_sha256':source.sha(raw),'source_receipt_bytes':len(raw),
            'inventory_sha256':'c'*64},'publication':{'members':members,'source_bytes':report['source_bytes']}}
        delivery.validate_members(publication,report,files,hub,raw)
        for fault in ('link','mode','omitted','hub'):
            changed=copy.deepcopy(publication)
            if fault=='link':changed['publication']['members']['source/public/link']['literal']='outside'
            elif fault=='mode':changed['publication']['members']['source/public/0']['physical_mode']=0o444
            elif fault=='omitted':changed['publication']['members'].pop('source/public/1')
            else:changed['publication']['members']['hub/source/BUILD.bazel']['sha256']='d'*64
            with self.assertRaises(ValueError):delivery.validate_members(changed,report,files,hub,raw)

    def test_declared_new_family_adds_only_two_proof_leaves_and_keeps_old_complete_graph(self):
        root=Path(__file__).parent
        rule=(root/'codex_native_siwc_catalog_model_inputs.bzl').read_text()
        macro=(root/'codex_native_siwc_catalog_models_targets.bzl').read_text()
        self.assertIn('len(paths) == 8566 + len(hub)',rule)
        self.assertIn('len(paths) == 8564 + len(hub)',rule)
        self.assertIn('source-phase-receipt.json',rule);self.assertIn('publication-receipt.json',rule)
        self.assertIn('PENDING-GENUINE-SOURCE-QUALIFICATION',rule)
        self.assertIn('codex_native_siwc_content_delivery_inputs.py',macro)
        self.assertIn('@omux_native_siwc_catalog_model_inputs//:inputs',macro)
        self.assertIn('catalog_content_source_data()',macro)
        self.assertNotIn('native_siwc_content_publication.py',macro)



    def test_history_role_type_rejects_unreviewed_subclass_before_any_io(self):
        class Foreign(delivery.HistoryRetainedInputs):pass
        with patch.object(family.Inputs,'__init__') as base:
            with self.assertRaises(ValueError):Foreign(Path('/unqualified'),[])
            base.assert_not_called()
            owner=delivery.HistoryRetainedInputs(Path('/unqualified'),[])
            self.assertIs(type(owner),delivery.HistoryRetainedInputs)
            self.assertEqual(base.call_args.kwargs['_kind'],delivery.HISTORY_INPUT_KIND)
            self.assertEqual(base.call_args.kwargs['_repository'],delivery.REPOSITORY)
            owner=delivery.RetainedInputs(Path('/unqualified'),[])
            self.assertEqual(base.call_args.kwargs['_kind'],delivery.INPUT_KIND)

    def test_new_history_selector_has_no_source_ready_or_old_family_alias(self):
        run=Path('/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/01234567-0123-0123-0123-0123456789ab')
        row={'root':str(run/'native-content-retained'/delivery.LEAF),'receipt_sha256':'a'*64,
            'receipt_bytes':1,'inventory_sha256':'b'*64,'producer':{'receipt':str(run/'receipt.json'),
                'sha256':'c'*64,'source_commit':'d'*40,'graph_sha256':'e'*64},
            'transport_receipt':{'sha256':'f'*64,'bytes':1},'source_phase_receipt':{'sha256':'1'*64,'bytes':1}}
        value={'schema_version':1,'kind':delivery.HISTORY_SELECTION_KIND,'status':delivery.HISTORY_STATUS,
            'catalog_controls_sha256':delivery.HISTORY_CONTROL_SHA,'source':row}
        self.assertEqual(delivery.history_selection(value),value)
        for wrong in ({**value,'kind':delivery.SELECTION_KIND},{**value,'status':delivery.STATUS},
                {**value,'catalog_controls_sha256':model.catalog.CONTROL_SHA},{**value,'source':None},
                {**value,'ready':True}):
            with self.assertRaises(ValueError):delivery.history_selection(wrong)
        changed=copy.deepcopy(value);changed['source']['root']=str(run/'output-base'/delivery.LEAF)
        with self.assertRaises(ValueError):delivery.history_selection(changed)



    def test_new_kind_actual_private_proofs_remain_pinned_and_late_replacement_refuses(self):
        for mode in (0o400,0o600):
            with tempfile.TemporaryDirectory() as temporary:
                base=Path(temporary);row,runfiles,rows,run,outer=self.fixture(base,phase_mode=mode)
                declaration=runfiles/'fixture_repo/source-inputs.json'
                document=json.loads(declaration.read_bytes());document['kind']=delivery.HISTORY_INPUT_KIND
                declaration.write_bytes(encoded(document))
                before=set(os.listdir('/proc/self/fd'))
                with self.scope(base),delivery.HistoryRetainedInputs(runfiles,rows) as inputs:
                    accepted,required=delivery.guardian(row,inputs)
                    self.assertEqual(accepted,outer);self.assertEqual(set(inputs.rows),required)
                    self.assertFalse(Path(outer['output_base']).exists())
                    actual=run/'source-phase-receipt.json'
                    replacement=run/'phase-replacement';replacement.write_bytes(actual.read_bytes());replacement.chmod(mode)
                    replacement.replace(actual)
                    with self.assertRaises(ValueError):delivery.guardian(row,inputs)
                self.assertEqual(set(os.listdir('/proc/self/fd')),before)


if __name__=='__main__':unittest.main()
