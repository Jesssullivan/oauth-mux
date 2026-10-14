"""Closed route boundaries with real clocks/FDs and explicit proof seams."""
from contextlib import contextmanager,redirect_stdout
import ast
import copy
import io
import os
from pathlib import Path
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import codex_native_carrier_material as material
import codex_native_carrier_material_test as fixtures
import codex_native_carrier_preflight as entrypoint
import codex_native_acquisition_compilation as compilation


class DownstreamModels(unittest.TestCase):
    setUp = fixtures.CarrierMaterialModels.setUp
    tearDown = fixtures.CarrierMaterialModels.tearDown

    def test_actual_declared_package_branch_and_model_data_separation(self):
        build=ast.parse(Path(__file__).with_name('BUILD.bazel').read_text())
        declarations={}
        for node in build.body:
            if isinstance(node,ast.Expr) and isinstance(node.value,ast.Call):
                call=node.value
                if isinstance(call.func,ast.Name) and call.func.id=='python_test':
                    keywords={row.arg:row.value for row in call.keywords}
                    if isinstance(keywords.get('name'),ast.Constant):
                        declarations[keywords['name'].value]=keywords
        target=declarations['codex_native_carrier_runtime_package']
        args=target['args'];self.assertIsInstance(args,ast.List)
        literal=[row.value for row in args.elts if isinstance(row,ast.Constant)]
        self.assertEqual(literal[0],'--carrier-v2')
        self.assertIn('$(location @omux_native_acquisition_package_data//:input-aliases.json)',literal)
        self.assertEqual(ast.literal_eval(target['env_inherit']),[
            'OMUX_NATIVE_PACKAGE_MODE','OMUX_NATIVE_PACKAGE_ENTRY_NS','OMUX_NATIVE_PACKAGE_DEADLINE_NS'])
        self.assertEqual(target['srcs'].id,'_NATIVE_CARRIER_PACKAGE_SOURCES')
        self.assertIsInstance(target['data'],ast.Call)
        model=declarations['codex_native_carrier_downstream_test']
        self.assertEqual(ast.literal_eval(model['data']),['BUILD.bazel'])
        self.assertEqual(ast.literal_eval(model['tags']),['manual','no-remote','no-cache'])
        route=next(node.value for node in build.body if isinstance(node,ast.Assign)
            and any(isinstance(name,ast.Name) and name.id=='_NATIVE_CARRIER_DOWNSTREAM_DATA' for name in node.targets))
        self.assertIsInstance(route,ast.BinOp)
        self.assertEqual(ast.literal_eval(route.right),[
            '@omux_native_carrier_source_inputs//:inputs',
            '@omux_native_carrier_material_inputs//:inputs',
            '//integrations/codex-upstream:native-carrier-material-inputs.json'])
        self.assertIsInstance(route.left,ast.ListComp)
        self.assertEqual(route.left.generators[0].iter.id,'_NATIVE_CARRIER_METADATA_DATA')
        self.assertEqual(route.left.generators[0].ifs[0].comparators[0].value,
            '@omux_native_acquisition_metadata_inputs//:inputs')

    def selected(self):
        return {'schema_version':2,'kind':material.KIND,'source':self.source,
            'sdk':{'root':'/model/sdk-projection','receipt_sha256':'a'*64,
                'inventory_sha256':'b'*64,'producer':self.actor},
            'controller_source_commit':self.actor['source_commit'],
            'controller_graph_sha256':self.actor['graph_sha256']}

    def test_owned_compiler_writer_and_executable_custody(self):
        with compilation.carrier_outputs(self.deadline) as output:
            output.start(self.root/'compiler');output.mkdir('work')
            output.write('artifacts/native-cli',b'ELF model',executable=True)
            output.write('artifacts/schema/config.json',b'{}')
            self.assertEqual(output.read('artifacts/native-cli',material.source.sha(b'ELF model'),32),b'ELF model')
            self.assertEqual((output.output.path/'artifacts/native-cli').stat().st_mode&0o777,0o555)
            self.assertIsNone(output.selected_name('/unrelated/native-cli'))
            output.write('receipt.json',b'{}');output.finish()
            self.assertEqual(output.read('artifacts/schema/config.json',material.source.sha(b'{}'),32),b'{}')
        self.assertIsNone(compilation._CARRIER_OUTPUT.get())

    def test_owned_compiler_same_byte_nested_replacement_refuses(self):
        with self.assertRaises(ValueError):
            with compilation.carrier_outputs(self.deadline) as output:
                output.start(self.root/'compiler-replaced');output.mkdir('work')
                output.write('artifacts/schema/config.json',b'{}');output.finish()
                self.assertEqual(output.read('artifacts/schema/config.json',material.source.sha(b'{}'),32),b'{}')
                leaf=output.output.path/'artifacts/schema/config.json'
                leaf.parent.chmod(0o700);leaf.rename(leaf.with_name('old.json'))
                leaf.write_bytes(b'{}');leaf.chmod(0o444);leaf.parent.chmod(0o555)
                output.read('artifacts/schema/config.json',material.source.sha(b'{}'),32)
        self.assertIsNone(compilation._CARRIER_OUTPUT.get())

    def test_actual_compiler_receipt_is_read_back_and_held(self):
        document={'material':self.selected(),'ledger':{'sha256':'a'*64},'controller_inventory_sha256':'b'*64}
        import codex_native_acquisition_metadata as producer
        with compilation.carrier_outputs(self.deadline) as output, \
                patch.object(material,'current',return_value=SimpleNamespace(deadline=self.deadline)), \
                patch.object(compilation,'prerequisites',return_value=(document['material'],{})), \
                patch.object(compilation,'fixed_plan',return_value={}), \
                patch.object(compilation,'run_once'), \
                patch.object(compilation,'retain_artifacts',return_value=[]), \
                patch.object(compilation,'artifact_closure'), \
                patch.object(producer.query_tools,'verify_repository',return_value={
                    'status':'declared-fixed-query-tools-byte-qualified','inputs_rechecked':True}), \
                patch.object(producer,'DEADLINE',producer.DEADLINE), \
                patch.object(producer.source,'DEADLINE',producer.source.DEADLINE):
            # Child compilation/guardian are explicit seams; publication uses
            # the actual producer, exclusive writer, bytes and retained FDs.
            report=compilation.produce(document,self.root/'actual-compiler',self.deadline)
            raw=compilation.encoded(report)
            self.assertIn('receipt.json',output.output.root.projection_leaves)
            self.assertEqual(output.read('receipt.json',material.source.sha(raw),len(raw)),raw)

    def test_unread_owned_receipt_late_replacement_refuses(self):
        with self.assertRaises(ValueError):
            with compilation.carrier_outputs(self.deadline) as output:
                output.start(self.root/'unread-compiler')
                output.write('receipt.json',b'{}');output.finish()
                self.assertIn('receipt.json',output.output.root.projection_leaves)
                root=output.output.path;root.chmod(0o700)
                leaf=root/'receipt.json';leaf.rename(root/'old-receipt.json')
                leaf.write_bytes(b'{}');leaf.chmod(0o444);root.chmod(0o555)
        self.assertIsNone(compilation._CARRIER_OUTPUT.get())

    def test_declared_reader_joins_original_work_clock_and_rejects_renewed_clock(self):
        leaf=self.root/'declared.json';leaf.write_bytes(b'{}');leaf.chmod(0o444)
        entry=time.monotonic_ns()
        with material.query_tools.consumer_phase(entry,entry+1200*10**9) as phase:
            reader=material.DeclaredInputs.__new__(material.DeclaredInputs)
            reader.clock=material.carrier.Clock(phase.query_deadline)
            reader.by_path={str(leaf):{'sha256':material.source.sha(b'{}'),'bytes':2}}
            reader.recheck=lambda:None # Explicit generated mapping seam.
            with material.DeclaredRoot(self.root,reader.clock) as held:
                reader.parents={self.root:held}
                self.assertEqual(reader.read(leaf,material.source.sha(b'{}'),phase.work_deadline),b'{}')
                self.assertEqual(reader.read(leaf,material.source.sha(b'{}'),phase.query_deadline),b'{}')
                with self.assertRaises(ValueError):
                    reader.read(leaf,material.source.sha(b'{}'),float(phase.work_deadline+1))

    def package_adapter(self,*,changed_compile=False):
        document=self.selected()
        selected={'path':'/model/compiler-selection.json','sha256':'c'*64}
        result={'path':'/model/compiler-result.json','sha256':'d'*64,'producer':self.actor}
        package={'kind':material.PACKAGE_KIND,'material':document,
            'compilation':{'selection':selected,'result':result}}
        configured={'compile':{'selection':{**selected,'bytes':12},'result':{**result,'bytes':13}}}
        if changed_compile:configured['compile']['selection']['sha256']='e'*64
        events=[];entry=time.monotonic_ns()
        @contextmanager
        def scope(value,deadline,temporary,runfiles):
            self.assertEqual(value,document)
            self.assertEqual(deadline,float((entry+1170*10**9)/10**9))
            events.append('enter');yield SimpleNamespace(deadline=float((entry+600*10**9)/10**9));events.append('close')
        with patch.object(material,'session_scope',side_effect=scope), \
                patch.object(material,'validate_package_paths',side_effect=lambda value:events.append('validate')), \
                patch.object(material,'config',return_value=(configured,'f'*64)):
            with material.session_scope_for_package(package,float((entry+1170*10**9)/10**9),
                    self.root/'scope',self.root,entry_ns=entry,original_deadline_ns=entry+1200*10**9) as session:
                self.assertEqual(session.deadline,float((entry+600*10**9)/10**9));events.append('body')
                with self.assertRaises(ValueError):
                    with material.query_tools.consumer_phase(entry,entry+1200*10**9):pass
        return events

    def test_package_adapter_one_original_phase_and_close(self):
        self.assertEqual(self.package_adapter(),['enter','validate','body','close'])

    def test_package_adapter_compiler_selector_substitution_refuses_before_body(self):
        with self.assertRaises(ValueError):self.package_adapter(changed_compile=True)

    def test_actual_session_scope_rereads_both_selectors_after_long_close(self):
        from contextlib import ExitStack
        for changed in (None,'material','metadata'):
            with self.subTest(changed=changed):
                runfiles=self.root/('scope-'+str(changed));runfiles.mkdir()
                (runfiles/'_repo_mapping').write_text('root,selected,selected\n')
                files={material.CONFIG:runfiles/'material.json',material.metadata.CONFIG:runfiles/'metadata.json'}
                for leaf in files.values():leaf.write_bytes(b'original')
                document=self.selected();events=[]
                configured={'selection':document,'metadata':{'model_only':True}}
                session=SimpleNamespace(core={'metadata':configured['metadata']})
                @contextmanager
                def installed(value):
                    self.assertIs(value,session);events.append('enter');yield value;events.append('close')
                    if changed is not None:files[material.CONFIG if changed=='material' else material.metadata.CONFIG].write_bytes(b'changed')
                @contextmanager
                def proof(deadline):
                    self.assertEqual(deadline,self.deadline);yield
                def declared(name,maximum):
                    raw=files[name].read_bytes();self.assertLessEqual(len(raw),maximum);return raw
                with ExitStack() as stack:
                    # SOURCE/guardian/construction are explicit seams; the
                    # actual scope ordering and exact final raw read are tested.
                    stack.enter_context(patch.object(material,'validate_selection'))
                    stack.enter_context(patch.object(material,'config',return_value=(configured,'a'*64)))
                    stack.enter_context(patch.object(material.binding.ninth.parent,'declared',side_effect=declared))
                    stack.enter_context(patch.object(material.metadata,'selection',return_value={}))
                    stack.enter_context(patch.object(material.metadata,'declared_carrier',return_value=(None,None,None)))
                    stack.enter_context(patch.object(material.metadata,'declared_proofs',return_value={}))
                    stack.enter_context(patch.object(material,'DeclaredInputs'))
                    stack.enter_context(patch.object(material,'Session',return_value=session))
                    stack.enter_context(patch.object(material,'installed_session',side_effect=installed))
                    stack.enter_context(patch.object(material.metadata,'proof_scope',side_effect=proof))
                    stack.enter_context(patch.object(material.query_tools,'verification_deadline',return_value=self.deadline))
                    def run():
                        with material.session_scope(document,self.deadline,self.root/'temporary',runfiles):events.append('body')
                    if changed is None:run()
                    else:
                        with self.assertRaises(ValueError):run()
                self.assertEqual(events,['enter','body','close'])

    def run_dispatch(self,*,close_refuses=False,selector_changed=False,
            late_selector=None,late_receipt=None,final_encoding_expiry=False,
            final_publisher_mutation=None,final_integer_expiry=False,final_hash_expiry=False):
        from contextlib import ExitStack
        mode='compilation' if late_receipt is not None or final_publisher_mutation is not None else 'plan'
        document=self.selected();configured={'selection':document,'compile':None}
        if mode=='compilation':configured['compile']={'selection':{'path':'/model/compiler.json','sha256':'c'*64},'result':None}
        runfiles=self.root/'dispatch-runfiles';runfiles.mkdir()
        outputs=self.root/'dispatch-outputs';outputs.mkdir()
        temporary=self.root/'dispatch-tmp';temporary.mkdir()
        entry=time.monotonic_ns();events=[];calls=[0];report={'model_only':True};publication_fds=[]
        env={'OMUX_NATIVE_CARRIER_MODE':entrypoint.PROFILES[mode],
            'OMUX_NATIVE_CARRIER_ENTRY_NS':str(entry),'OMUX_NATIVE_CARRIER_DEADLINE_NS':str(entry+1200*10**9),
            'OMUX_NATIVE_CARRIER_EPOCH':str(Path(self.actor['receipt']).parent),
            'OMUX_NATIVE_CARRIER_SOURCE_COMMIT':self.actor['source_commit'],
            'OMUX_NATIVE_CARRIER_GRAPH_SHA256':self.actor['graph_sha256'],
            'TEST_SRCDIR':str(runfiles),'TEST_UNDECLARED_OUTPUTS_DIR':str(outputs),
            'TEST_TMPDIR':str(temporary),'TEST_TIMEOUT':'1200'}
        @contextmanager
        def scope(selected,deadline,work,files):
            self.assertEqual(selected,document)
            session=SimpleNamespace(deadline=float((entry+600*10**9)/10**9))
            events.append('enter');yield session;events.append('close')
            if late_receipt is not None:
                output=compilation._CARRIER_OUTPUT.get();root=output.output.path;leaf=root/'receipt.json'
                root.chmod(0o700)
                if late_receipt=='replacement':
                    leaf.rename(root/'old-receipt.json');leaf.write_bytes(material.source.encoded(report))
                else:
                    leaf.chmod(0o600);leaf.write_bytes(b'{"changed":true}\n')
                leaf.chmod(0o444);root.chmod(0o555)
            if close_refuses:raise ValueError('model: final custody changed')
        def produce(*args):
            self.assertEqual(args[0:2],('plan',document));events.append('produce');return report
        def config():
            calls[0]+=1
            if final_publisher_mutation is not None and final_publisher_mutation[0]=='material' and calls[0]==3:
                mutate_publication()
            changed=(selector_changed and calls[0]>1) or (late_selector=='material' and 'close' in events)
            return configured,('b'*64 if changed else 'a'*64)
        def selected_metadata(*args):
            self.assertEqual(args,(material.metadata.CONFIG,16384))
            if final_publisher_mutation is not None and final_publisher_mutation[0]=='metadata' and 'close' in events:
                mutate_publication()
            return b'changed' if late_selector=='metadata' and 'close' in events else b'original'
        def compile_produce(candidate,path,deadline):
            self.assertEqual(candidate['material'],document);events.append('produce')
            output=compilation._CARRIER_OUTPUT.get();output.start(path)
            # Intentionally leave this leaf unread to exercise finish's full
            # writer set, then mutate it during the actual dispatch close.
            output.write('receipt.json',material.source.encoded(report));output.finish()
            publication_fds.extend(fd for _,fd,_ in output.output.root.chain)
            for parent,leaf,_ in output.output.root.projection_leaves.values():
                publication_fds.extend((parent,leaf))
            return report
        original_encoded=material.source.encoded;original_sha=material.source.sha;original_tick=material.tick;encoded_expired=[False]
        original_ns=time.monotonic_ns;integer_expired=[False];mutations=[]
        def mutate_publication():
            output=compilation._CARRIER_OUTPUT.get()
            self.assertIsNotNone(output)
            self.assertTrue(output.output.root.chain)
            root=output.output.path;leaf=root/'receipt.json';root.chmod(0o700)
            if final_publisher_mutation[1]=='replacement':
                leaf.rename(root/'displaced-receipt.json')
                leaf.write_bytes(original_encoded(report))
            else:
                leaf.chmod(0o600);leaf.write_bytes(b'{"changed":true}\n')
            leaf.chmod(0o444);root.chmod(0o555);mutations.append(True)
        def encode(value):
            raw=original_encoded(value)
            if final_encoding_expiry:encoded_expired[0]=True
            if 'close' in events:
                if final_integer_expiry:integer_expired[0]=True
                if final_publisher_mutation is not None and final_publisher_mutation[0]=='encoding':
                    mutate_publication()
            return raw
        def now_ns():return entry+600*10**9 if integer_expired[0] else original_ns()
        def hash_output(raw):
            pin=original_sha(raw)
            if 'close' in events:
                if final_hash_expiry:encoded_expired[0]=True
                if final_publisher_mutation is not None and final_publisher_mutation[0]=='digest':
                    mutate_publication()
            return pin
        def tick(deadline):
            if encoded_expired[0]:raise ValueError('model: original cutoff expired during encoding')
            original_tick(deadline)
        stream=io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ,env))
            stack.enter_context(patch.object(entrypoint.sys,'argv',['route-model']))
            stack.enter_context(patch.object(material,'config',side_effect=config))
            stack.enter_context(patch.object(material.binding.ninth.parent,'declared',side_effect=selected_metadata))
            stack.enter_context(patch.object(material,'session_scope',side_effect=scope))
            stack.enter_context(patch.object(entrypoint.preflight,'produce',side_effect=produce))
            stack.enter_context(patch.object(compilation,'selected_document',return_value={'material':document}))
            stack.enter_context(patch.object(compilation,'produce',side_effect=compile_produce))
            stack.enter_context(patch.object(material.source,'encoded',side_effect=encode))
            stack.enter_context(patch.object(material.source,'sha',side_effect=hash_output))
            stack.enter_context(patch.object(compilation,'encoded',side_effect=encode))
            stack.enter_context(patch.object(material,'tick',side_effect=tick))
            stack.enter_context(patch.object(entrypoint.time,'monotonic_ns',side_effect=now_ns))
            stack.enter_context(redirect_stdout(stream))
            if close_refuses or selector_changed or late_selector is not None or late_receipt is not None or final_encoding_expiry\
                    or final_publisher_mutation is not None or final_integer_expiry or final_hash_expiry:
                with self.assertRaises(ValueError):entrypoint.main(mode)
            else:entrypoint.main(mode)
        if final_publisher_mutation is not None:self.assertEqual(mutations,[True])
        self.assertIsNone(compilation._CARRIER_OUTPUT.get())
        for fd in publication_fds:
            with self.assertRaises(OSError):os.fstat(fd)
        return stream.getvalue(),events,report

    def test_actual_dispatch_marker_follows_successful_session_close(self):
        output,events,report=self.run_dispatch()
        self.assertEqual(events,['enter','produce','close'])
        self.assertEqual(output.splitlines(),['omux-native-carrier-plan-output-sha256='+material.source.sha(material.source.encoded(report))])

    def test_actual_dispatch_final_custody_or_selector_refusal_has_no_marker(self):
        output,_,_=self.run_dispatch(close_refuses=True)
        self.assertNotIn('output-sha256=',output)
        # Each fixture dispatch has a fresh declared output namespace.
        self.tearDown();self.setUp()
        output,_,_=self.run_dispatch(selector_changed=True)
        self.assertNotIn('output-sha256=',output)

    def test_actual_dispatch_postclose_selector_mutations_have_no_marker(self):
        for selector in ('material','metadata'):
            with self.subTest(selector=selector):
                output,events,_=self.run_dispatch(late_selector=selector)
                self.assertEqual(events,['enter','produce','close'])
                self.assertNotIn('output-sha256=',output)
            self.tearDown();self.setUp()

    def test_actual_compiler_dispatch_late_receipt_mutations_have_no_marker(self):
        for mutation in ('replacement','content'):
            with self.subTest(mutation=mutation):
                output,events,_=self.run_dispatch(late_receipt=mutation)
                self.assertEqual(events,['enter','produce','close'])
                self.assertNotIn('output-sha256=',output)
            self.tearDown();self.setUp()

    def test_actual_dispatch_original_cutoff_after_encoding_has_no_marker(self):
        output,events,_=self.run_dispatch(final_encoding_expiry=True)
        self.assertEqual(events,['enter','produce','close'])
        self.assertNotIn('output-sha256=',output)

    def test_actual_dispatch_publication_mutation_during_final_selectors_or_encoding_refuses(self):
        for point in ('material','metadata','encoding','digest'):
            for mutation in ('replacement','content'):
                with self.subTest(point=point,mutation=mutation):
                    output,events,_=self.run_dispatch(final_publisher_mutation=(point,mutation))
                    self.assertEqual(events,['enter','produce','close'])
                    self.assertNotIn('output-sha256=',output)
                self.tearDown();self.setUp()

    def test_actual_dispatch_exact_integer_cutoff_after_publisher_close_has_no_marker(self):
        output,events,_=self.run_dispatch(final_integer_expiry=True)
        self.assertEqual(events,['enter','produce','close'])
        self.assertNotIn('output-sha256=',output)

    def test_actual_dispatch_cutoff_during_output_digest_has_no_marker(self):
        output,events,_=self.run_dispatch(final_hash_expiry=True)
        self.assertEqual(events,['enter','produce','close'])
        self.assertNotIn('output-sha256=',output)

    def retained_selectors(self,retained,root):
        # Admission/SDK construction are explicit seams. The actual Session
        # handoff, immutable phase, alias/parent/leaf FDs and bytes are real.
        for name in (material.CONFIG,material.metadata.CONFIG):
            leaf=root/name;leaf.parent.mkdir(parents=True,exist_ok=True)
            leaf.write_bytes(b'original');leaf.chmod(0o644)
        entry=time.monotonic_ns()-500*10**9
        with material.query_tools.consumer_phase(entry,entry+1200*10**9) as phase:
            from contextlib import ExitStack
            session=material.Session.__new__(material.Session)
            session.closed=False;session.stack=ExitStack();session.deadline=phase.query_deadline
            session.selector_bytes=(b'original',b'original')
            token=material._SCOPE.set(session)
            try:
                selectors=retained.enter_context(session.retain_selectors())
                session.close()
                with self.assertRaises(ValueError):session.retain_selectors()
            finally:material._SCOPE.reset(token)
        self.assertIsNone(material.query_tools._CONSUMER_PHASE.get())
        return selectors

    def test_selector_fd_handoff_survives_session_close_and_cleans_up(self):
        from contextlib import ExitStack
        with patch.object(material.binding.ninth.parent,'ROOT',self.root),ExitStack() as retained:
            selectors=self.retained_selectors(retained,self.root)
            fds=[row[3] for row in selectors.rows]
            selectors.check()
            with patch.object(material.carrier.time,'monotonic_ns',return_value=selectors.clock.until_ns):
                with self.assertRaises(ValueError):selectors.check()
            retained.close()
            with self.assertRaises(ValueError):selectors.check()
        for fd in fds:
            with self.assertRaises(OSError):os.fstat(fd)

    def test_retained_selectors_postclose_content_replacement_and_alias_refuse(self):
        from contextlib import ExitStack
        for mutation in ('content','same-byte-replacement','alias'):
            with self.subTest(mutation=mutation):
                root=self.root/mutation;root.mkdir()
                with patch.object(material.binding.ninth.parent,'ROOT',root),ExitStack() as retained:
                    selectors=self.retained_selectors(retained,root)
                    fds=[row[3] for row in selectors.rows]
                    leaf=root/material.metadata.CONFIG
                    if mutation=='content':leaf.write_bytes(b'changed')
                    else:
                        leaf.rename(leaf.with_name('original.json'))
                        if mutation=='same-byte-replacement':leaf.write_bytes(b'original');leaf.chmod(0o644)
                        else:leaf.symlink_to('original.json')
                    with self.assertRaises(ValueError):selectors.check()
                for fd in fds:
                    with self.assertRaises(OSError):os.fstat(fd)


if __name__=='__main__':unittest.main()
