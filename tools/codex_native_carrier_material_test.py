"""Closed v2 authority, real projection IO and original-clock lifecycle models.

Fixtures prove their stated predicates, never genuine carrier/SDK execution.
"""
import copy
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import codex_native_sdk_carrier as carrier
import codex_native_carrier_material as material
import codex_native_carrier_sdk_export as export
import codex_retained_sdk_export as sdk
import codex_native_sdk_carrier_test as carrier_fixtures


class CarrierMaterialModels(unittest.TestCase):
    def tiny_fresh(self):
        """Real tiny origin→carrier→fresh content/NAR proof, fixture JDK only."""
        from contextlib import ExitStack
        fixture = carrier_fixtures.CarrierModels()
        fixture.setUp();stack = ExitStack();stack.callback(fixture.tearDown)
        try:
            root,origin,pin = fixture.seal()
            extracted = fixture.root/'fresh'
            receipt = carrier.extract(root,pin,extracted,fixture.deadline)
            clock = carrier.Clock(fixture.deadline)
            packed = stack.enter_context(carrier.Root(root,clock))
            fresh = {role:stack.enter_context(carrier.Root(extracted/role,clock)) for role in ('sdk','jdk')}
            custody = material.FreshCustody(packed,origin,receipt,fresh,clock)
            stack.callback(custody.close)
            self.assertEqual(carrier.revalidate_extraction(root,pin,extracted,fixture.deadline),receipt)
            return stack,fixture,extracted,custody
        except BaseException:stack.close();raise

    def test_real_fresh_witness_fence_rejects_same_byte_replacement_after_source_io(self):
        stack,fixture,extracted,custody = self.tiny_fresh()
        with stack:
            custody.check()
            leaf = extracted/'sdk/graph/MODULE.bazel';raw = leaf.read_bytes()
            # Explicit final SOURCE-I/O mutation seam, after real full proof.
            leaf.parent.chmod(0o700);leaf.rename(fixture.root/'old-MODULE.bazel')
            leaf.write_bytes(raw);leaf.chmod(0o400);leaf.parent.chmod(0o555)
            with self.assertRaises(ValueError):custody.check()

    def test_real_fresh_witness_fence_rejects_added_namespace_and_link_retarget(self):
        stack,fixture,extracted,custody = self.tiny_fresh()
        with stack:
            root = extracted/'jdk';root.chmod(0o700)
            (root/'unselected').write_bytes(b'extra');(root/'unselected').chmod(0o444);root.chmod(0o555)
            with self.assertRaises(ValueError):custody.check()
        stack,fixture,extracted,custody = self.tiny_fresh()
        with stack:
            root = extracted/'jdk';root.chmod(0o700)
            (root/'inert').unlink();(root/'inert').symlink_to('/unselected/external')
            root.chmod(0o555)
            with self.assertRaises(ValueError):custody.check()

    def test_real_fresh_witness_fence_holds_extraction_receipt_identity(self):
        stack,fixture,extracted,custody = self.tiny_fresh()
        with stack:
            leaf = extracted/'extraction-receipt.json';raw = leaf.read_bytes()
            extracted.chmod(0o700);leaf.rename(extracted/'old-receipt.json')
            leaf.write_bytes(raw);leaf.chmod(0o444);extracted.chmod(0o555)
            with self.assertRaises(ValueError):custody.check()

    def test_session_final_fence_refuses_fresh_mutation_during_postscan_source_sweep(self):
        from contextlib import ExitStack
        stack,fixture,extracted,custody = self.tiny_fresh()
        with stack:
            session = material.Session.__new__(material.Session)
            session.closed = False;session.deadline = fixture.deadline;session.stack = ExitStack()
            session.carrier_root = custody.output.path.parent/'carrier'
            session.pin = custody.receipt['carrier_receipt_sha256'];session.extracted = extracted
            session.extraction = custody.receipt;session.extraction_pin = carrier.sha(custody.receipt_raw)
            session.fresh_custody = custody;session.fresh = custody.roots
            held = SimpleNamespace(check=lambda:None)
            session.root = session.carrier_hold = session.temporary_hold = held
            session.inputs = SimpleNamespace(recheck=lambda:None)
            events = [];session.recheck = lambda:events.append('initial-full-proof')
            session.source_proof = SimpleNamespace(finish=lambda:events.append('source-finish'))
            def mutate_source_sweep():
                events.append('postscan-source')
                leaf = extracted/'sdk/graph/MODULE.bazel';raw = leaf.read_bytes()
                leaf.parent.chmod(0o700);leaf.rename(fixture.root/'prior-MODULE.bazel')
                leaf.write_bytes(raw);leaf.chmod(0o400);leaf.parent.chmod(0o555)
            session.recheck_sources = mutate_source_sweep
            actual = carrier.revalidate_extraction
            def scan(*args,**kwargs):
                events.append('final-fullscan');return actual(*args,**kwargs)
            with patch.object(carrier,'revalidate_extraction',side_effect=scan):
                with self.assertRaises(ValueError):
                    with material.installed_session(session):pass
            self.assertTrue(session.closed);self.assertIsNone(material._SCOPE.get())
            self.assertEqual(events,['initial-full-proof','source-finish','final-fullscan','postscan-source'])

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.deadline = float(time.monotonic()+120)
        self.actor = {'receipt':'/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/12345678-1234-1234-1234-123456789abc/receipt.json',
            'sha256':'1'*64,'source_commit':'2'*40,'graph_sha256':'3'*64}
        self.source = {'root':'/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/12345678-1234-1234-1234-123456789abc/output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_native_source_acquisition_source_producer/test.outputs/native-source-acquisition-source',
            'receipt_sha256':'4'*64,'inventory_sha256':'5'*64,'producer':self.actor}
        self.original = {'kind':'omux-native-source-acquisition-metadata-input-v1',
            'source_root':self.source['root'],'source_receipt_sha256':'4'*64,'source_inventory_sha256':'5'*64,
            'export_root':'/selected-model-only-origin','export_receipt_sha256':'6'*64,'binding_receipt_sha256':'7'*64}
        self.patches = [patch.object(material.binding,'selected_document',return_value=self.original),
            patch.object(material.binding,'config',return_value={'source':self.source})]
        for item in self.patches: item.start()
        self.program = {'producer':self.actor,'program':{'path':'/selected-model/report.json','sha256':'8'*64,'bytes':123}}
        self.hub = {'BUILD.bazel':b'build model','defs.bzl':b'defs model','data.bzl':b'data model','empty':b''}
        self.graph = {name:('model graph ' + name).encode() for name in sdk.GRAPH}
        self.hub_rows = export.mapped_members(self.hub)
        self.graph_rows = export.mapped_members(self.graph)
        self.core = {'schema_version':2,'kind':material.CORE_KIND,'source':self.source,
            'original_selection':self.original,'carrier_files':[{'name':name,'sha256':'9'*64,'bytes':10} for name in carrier.FILES],
            'seal':self.program,'metadata':self.program,'hub_inventory_sha256':carrier.sha(carrier.encoded(self.hub_rows)),
            'graph_inventory_sha256':carrier.sha(carrier.encoded(self.graph_rows))}
        self.raw = carrier.encoded(self.core)
        pin = carrier.sha(self.raw)
        self.report = {**self.core,'kind':material.SDK_KIND,'status':'verified-carrier-sdk-projection-with-fresh-custody',
            'authority_sha256':pin,'inventory_sha256':pin,'hub_files':self.hub_rows,'graph_files':self.graph_rows,
            'mapping_sha256':self.graph_rows['MODULE.bazel.lock']['sha256'],'patch_sha256':['a'*64]*9,
            'sdk_export_qualified':True,'source_and_carrier_rechecked':True,
            **{name:False for name in material.FALSE_FLAGS}}

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        # Only synthetic owned fixture objects are made removable.
        for path in self.root.rglob('*'):
            if not path.is_symlink(): path.chmod(0o700 if path.is_dir() else 0o600)
        self.temporary.cleanup()

    def test_non_circular_raw_core_and_projection_maps(self):
        self.assertEqual(material.report_shape(self.report,self.raw),self.core)
        self.assertNotIn('receipt_sha256',self.core)
        self.assertEqual(self.report['inventory_sha256'],carrier.sha(self.raw))
        self.assertEqual(self.hub_rows['empty']['bytes'],0)

    def test_false_claims_extra_fields_and_core_substitution_refuse(self):
        for key in material.FALSE_FLAGS:
            with self.subTest(key=key):
                report = copy.deepcopy(self.report); report[key] = True
                with self.assertRaises(ValueError): material.report_shape(report,self.raw)
        report = copy.deepcopy(self.report); report['extra'] = False
        with self.assertRaises(ValueError): material.report_shape(report,self.raw)
        mutated = copy.deepcopy(self.core); mutated['source']['inventory_sha256'] = 'b'*64
        with self.assertRaises(ValueError): material.report_shape(self.report,carrier.encoded(mutated))

    def test_tuple_order_duplicate_row_and_boolean_size_refuse(self):
        for change in ('order','duplicate','boolean'):
            with self.subTest(change=change):
                rows = copy.deepcopy(self.core['carrier_files'])
                if change == 'order': rows.reverse()
                elif change == 'duplicate': rows[1]['name'] = rows[0]['name']
                else: rows[0]['bytes'] = True
                with self.assertRaises(ValueError): material.file_tuple(rows)

    def test_map_parent_symlink_modes_and_digest_mutation_refuse(self):
        for rows in ({'../escape':self.hub_rows['BUILD.bazel']}, {'ok':{'sha256':'a'*64,'bytes':0,'mode':100644}}):
            with self.assertRaises(ValueError): material.member_map(rows)
        changed = copy.deepcopy(self.report); changed['hub_files']['BUILD.bazel']['sha256'] = 'b'*64
        with self.assertRaises(ValueError): material.report_shape(changed,self.raw)

    def test_real_projection_fd_writes_modes_and_exact_namespace(self):
        output = carrier.Output(self.root/'projection',carrier.Clock(self.deadline))
        try:
            export.write_members(output,'hub',self.hub,self.hub_rows)
            export.write_members(output,'graph',self.graph,self.graph_rows)
            output.file('authority.json',self.raw); output.file('sdk-receipt.json',carrier.encoded(self.report)); output.finish()
            self.assertEqual(material.projection_read(output.root,self.report,output.clock),{'hub':self.hub,'graph':self.graph})
            self.assertEqual((output.path/'hub/empty').stat().st_mode & 0o777,0o444)
            output.path.chmod(0o700); (output.path/'unexpected').write_bytes(b'unselected'); output.path.chmod(0o555)
            with self.assertRaises(ValueError): material.projection_read(output.root,self.report,output.clock)
        finally: output.close()

    def retained_projection_fixture(self,name,*,normalized=False):
        """Real compact writer, then optional fixture-only Bazel0555 retention."""
        modes = {name:'100644' for name in self.hub}
        modes['defs.bzl'] = '100755'
        hub_rows = export.mapped_members(self.hub,modes)
        core = copy.deepcopy(self.core)
        core['hub_inventory_sha256'] = carrier.sha(carrier.encoded(hub_rows))
        raw = carrier.encoded(core);pin = carrier.sha(raw)
        report = {**copy.deepcopy(self.report),**core,'kind':material.SDK_KIND,
            'authority_sha256':pin,'inventory_sha256':pin,'hub_files':hub_rows}
        self.assertEqual(material.report_shape(report,raw),core)
        output = material.ProjectionOutput(self.root/name,carrier.Clock(self.deadline))
        try:
            export.write_members(output,'hub',self.hub,hub_rows)
            export.write_members(output,'graph',self.graph,self.graph_rows)
            output.file('authority.json',raw);output.file('sdk-receipt.json',carrier.encoded(report));output.finish()
            self.assertTrue(output.root.owned)
            self.assertEqual(material.projection_read(output.root,report,output.clock),{'hub':self.hub,'graph':self.graph})
            self.assertEqual((output.path/'hub/empty').stat().st_mode & 0o777,0o444)
            self.assertEqual((output.path/'hub/defs.bzl').stat().st_mode & 0o777,0o555)
        finally:output.close()
        if normalized:
            # Only closed synthetic owned bytes are normalized, never live/original artifacts.
            for leaf in output.path.rglob('*'):
                if leaf.is_file():leaf.chmod(0o555)
        return output.path,report,raw

    def test_retained_projection_public_read_preserves_selected_bytes_and_logical_modes(self):
        for normalized in (False,True):
            with self.subTest(normalized=normalized):
                path,report,raw = self.retained_projection_fixture('retained-' + str(normalized),normalized=normalized)
                clock = carrier.Clock(self.deadline)
                with material.ProjectionRoot(path,clock) as root:
                    self.assertFalse(root.owned)
                    authority = carrier.read(root,'authority.json',material.MAX_DOCUMENT,report['authority_sha256'])
                    receipt = carrier.read(root,'sdk-receipt.json',material.MAX_DOCUMENT,carrier.sha(carrier.encoded(report)))
                    self.assertEqual(authority,raw)
                    self.assertEqual(material.report_shape(json.loads(receipt),authority),json.loads(raw))
                    self.assertEqual(material.projection_read(root,report,clock),{'hub':self.hub,'graph':self.graph})
                    self.assertEqual(report['hub_files']['empty']['mode'],'100644')
                    self.assertEqual(report['hub_files']['empty']['bytes'],0)
                    self.assertEqual(report['hub_files']['defs.bzl']['mode'],'100755')
                    root.check()
                self.assertEqual((path/'authority.json').stat().st_mode & 0o777,0o555 if normalized else 0o444)

    def test_fresh_owned_projection_nonexecutables_remain_exact444(self):
        for index,name in enumerate(('authority.json','sdk-receipt.json','hub/empty','graph/MODULE.bazel')):
            with self.subTest(name=name):
                # The original owned Output also reaches the exact fresh mode predicate,
                # without ProjectionOutput's additional created-leaf witness refusal.
                output = carrier.Output(self.root/('fresh-mode-' + str(index)),carrier.Clock(self.deadline))
                try:
                    export.write_members(output,'hub',self.hub,self.hub_rows)
                    export.write_members(output,'graph',self.graph,self.graph_rows)
                    output.file('authority.json',self.raw);output.file('sdk-receipt.json',carrier.encoded(self.report));output.finish()
                    self.assertTrue(output.root.owned)
                    (output.path/name).chmod(0o555)
                    with self.assertRaises(ValueError):material.projection_read(output.root,self.report,output.clock)
                finally:output.close()

    def test_retained_projection_writable_modes_and_executable_downgrade_refuse(self):
        for name in ('authority.json','sdk-receipt.json','hub/empty','graph/MODULE.bazel'):
            for mode in (0o600,0o644,0o666,0o755):
                with self.subTest(name=name,mode=mode):
                    path,report,_ = self.retained_projection_fixture('bad-mode-' + name.replace('/','-') + '-' + str(mode),normalized=True)
                    (path/name).chmod(mode);clock = carrier.Clock(self.deadline)
                    with material.ProjectionRoot(path,clock) as root:
                        with self.assertRaises(ValueError):material.projection_read(root,report,clock)
        path,report,_ = self.retained_projection_fixture('bad-executable',normalized=True)
        (path/'hub/defs.bzl').chmod(0o444);clock = carrier.Clock(self.deadline)
        with material.ProjectionRoot(path,clock) as root:
            with self.assertRaises(ValueError):material.projection_read(root,report,clock)

    def test_retained_projection_selected_hash_namespace_and_symlink_refuse(self):
        path,report,_ = self.retained_projection_fixture('bad-auth',normalized=True)
        clock = carrier.Clock(self.deadline)
        with material.ProjectionRoot(path,clock) as root:
            with self.assertRaises(ValueError):carrier.read(root,'authority.json',material.MAX_DOCUMENT,'b'*64)
        changed = copy.deepcopy(report);changed['hub_files']['empty']['mode'] = '100755'
        with self.assertRaises(ValueError):material.report_shape(changed,(path/'authority.json').read_bytes())
        for action in ('extra','symlink','bytes'):
            with self.subTest(action=action):
                path,report,_ = self.retained_projection_fixture('bad-selected-' + action,normalized=True)
                if action == 'extra':
                    path.chmod(0o700);(path/'unselected').write_bytes(b'extra');(path/'unselected').chmod(0o555);path.chmod(0o555)
                elif action == 'symlink':
                    parent = path/'hub';parent.chmod(0o700);(parent/'empty').unlink()
                    (parent/'empty').symlink_to(path/'authority.json');parent.chmod(0o555)
                else:
                    leaf = path/'graph/MODULE.bazel';leaf.chmod(0o600);leaf.write_bytes(b'changed');leaf.chmod(0o555)
                clock = carrier.Clock(self.deadline)
                with material.ProjectionRoot(path,clock) as root:
                    with self.assertRaises((ValueError,OSError)):material.projection_read(root,report,clock)

    def test_retained_projection_allowed_mode_and_same_byte_identity_races_refuse(self):
        for action in ('mode','replace','bytes'):
            with self.subTest(action=action):
                path,report,_ = self.retained_projection_fixture('retained-race-' + action,normalized=True)
                clock = carrier.Clock(self.deadline)
                with material.ProjectionRoot(path,clock) as root:
                    self.assertEqual(material.projection_read(root,report,clock),{'hub':self.hub,'graph':self.graph})
                    leaf = path/'hub/empty'
                    if action == 'mode':leaf.chmod(0o444)
                    elif action == 'replace':
                        leaf.parent.chmod(0o700);leaf.rename(self.root/'old-empty')
                        leaf.write_bytes(b'');leaf.chmod(0o555);leaf.parent.chmod(0o555)
                    else:leaf.chmod(0o600);leaf.write_bytes(b'changed');leaf.chmod(0o555)
                    with self.assertRaises(ValueError):root.check()
                    with self.assertRaises(ValueError):material.projection_read(root,report,clock)

    def test_retained_projection_original_clock_is_not_renewed(self):
        path,report,_ = self.retained_projection_fixture('expired-projection',normalized=True)
        with self.assertRaises(ValueError):material.ProjectionRoot(path,carrier.Clock(float(time.monotonic()-1)))
        clock = carrier.Clock(self.deadline)
        with material.ProjectionRoot(path,clock) as root:
            material.projection_read(root,report,clock)
            with patch.object(carrier.time,'monotonic',return_value=self.deadline+1):
                with self.assertRaises(ValueError):material.projection_read(root,report,clock)
                with self.assertRaises(ValueError):root.check()
            self.assertEqual(clock.deadline,self.deadline)

    def test_projection_named_parent_replacement_refuses_before_write(self):
        output = carrier.Output(self.root/'projection',carrier.Clock(self.deadline))
        try:
            output.mkdir('hub'); (output.path/'hub').rename(output.path/'held-hub')
            (output.path/'hub').symlink_to(self.root,target_is_directory=True)
            with self.assertRaises(ValueError): export.write_members(output,'hub/nested',{'file':b'bytes'},export.mapped_members({'file':b'bytes'}))
            self.assertFalse((self.root/'nested').exists())
        finally: output.close()

    def test_projection_output_joins_created_identity_under_bazel_mode755_parent(self):
        parent = self.root/'bazel-outputs'; parent.mkdir(mode=0o755)
        output = material.ProjectionOutput(parent/'projection',carrier.Clock(self.deadline))
        try:
            held = carrier.identity(os.fstat(output.root.fd),True)
            self.assertEqual(held,carrier.identity(os.stat(output.path,follow_symlinks=False),True))
            output.file('owned.json',b'owned projection')
            output.finish()
            self.assertEqual((output.path/'owned.json').stat().st_mode & 0o777,0o444)
            output.path.rename(parent/'held-output')
            output.path.mkdir(mode=0o700)
            with self.assertRaises(ValueError): output.root.check()
            self.assertFalse((output.path/'owned.json').exists())
        finally: output.close()

    def test_unique_output_hash_marker_missing_duplicate_and_mismatch_refuse(self):
        prefix = 'omux-native-carrier-sdk-output-sha256='
        line = (prefix + 'a'*64).encode()
        material.output_marker(b'other output\n' + line + b'\n',prefix,'a'*64)
        for raw in (b'other output\n',line+b'\n'+line+b'\n',(prefix+'b'*64).encode()):
            with self.assertRaises(ValueError): material.output_marker(raw,prefix,'a'*64)

    def test_cold_config_never_mints_selected_authority(self):
        value = {'schema_version':2,'kind':material.CONFIG_KIND,'status':'awaiting-qualified-carrier-route',
            'metadata':None,'selection':None,'compile':None}
        self.assertEqual(material.config(carrier.encoded(value))[0],value)
        value['selection'] = self.report
        with self.assertRaises(ValueError): material.config(carrier.encoded(value))

    def test_original_integer_envelope_no_late_renewal(self):
        entry = time.monotonic_ns()
        env = {'OMUX_NATIVE_CARRIER_MODE':export.PROFILE,'OMUX_NATIVE_CARRIER_ENTRY_NS':str(entry),
            'OMUX_NATIVE_CARRIER_DEADLINE_NS':str(entry+1200*10**9),
            'OMUX_NATIVE_CARRIER_EPOCH':str(Path(self.actor['receipt']).parent),
            'OMUX_NATIVE_CARRIER_SOURCE_COMMIT':self.actor['source_commit'],
            'OMUX_NATIVE_CARRIER_GRAPH_SHA256':self.actor['graph_sha256']}
        got_entry,got_until,cutoff = export.envelope(env)
        self.assertEqual((got_entry,got_until),(entry,entry+1200*10**9))
        self.assertEqual(cutoff,float((entry+600*10**9)/10**9))
        with patch.object(export.time,'monotonic_ns',return_value=entry+601*10**9):
            with self.assertRaises(ValueError): export.envelope(env)
        env['OMUX_NATIVE_CARRIER_DEADLINE_NS'] = str(entry+1201*10**9)
        with self.assertRaises(ValueError): export.envelope(env)

    def test_expired_context_and_missing_session_refuse(self):
        with self.assertRaises(ValueError): material.tick(float(time.monotonic()-1))
        with self.assertRaises(ValueError): material.current({},self.deadline)

    def test_real_declared_alias_read_duplicate_control_and_alias_replacement(self):
        external = self.root/'external'/material.METADATA_REPOSITORY; external.mkdir(parents=True,mode=0o700)
        origin = self.root/'evidence'; origin.mkdir(mode=0o700)
        leaf = origin/'program.json'; raw = b'{"model":"declared"}'; leaf.write_bytes(raw); leaf.chmod(0o444)
        runfiles = self.root/'runfiles'; repository = runfiles/material.METADATA_REPOSITORY
        (repository/'inputs/metadata').mkdir(parents=True,mode=0o700)
        row = {'path':str(leaf),'sha256':carrier.sha(raw),'bytes':len(raw),'alias':'inputs/metadata/program-report.json'}
        mapping = carrier.encoded({'kind':material.DECLARED_KIND,'stage':'metadata','files':{'metadata/program-report.json':row}})
        (external/'inputs.json').write_bytes(mapping); (external/'inputs.json').chmod(0o444)
        (repository/'inputs.json').symlink_to(external/'inputs.json')
        alias = repository/row['alias']; alias.symlink_to(leaf)
        with material.DeclaredInputs(runfiles,[['_main',material.METADATA_REPOSITORY,material.METADATA_REPOSITORY]],self.deadline,stage='metadata') as declared:
            self.assertEqual(declared.role('metadata/program-report.json'),raw)
            alias.unlink(); other = origin/'other.json'; other.write_bytes(raw); other.chmod(0o444); alias.symlink_to(other)
            with self.assertRaises(ValueError): declared.role('metadata/program-report.json')
        (external/'inputs.json').chmod(0o600); (external/'inputs.json').write_bytes(b'{"kind":"a","kind":"b"}')
        with self.assertRaises(ValueError):
            material.DeclaredInputs(runfiles,[['_main',material.METADATA_REPOSITORY,material.METADATA_REPOSITORY]],self.deadline,stage='metadata')

    def test_actual_declared_material_bytes_bind_separate_selector_pin_and_recheck(self):
        external = self.root/'external'/material.REPOSITORY; external.mkdir(parents=True,mode=0o755)
        leaf = self.root/'sdk-model.json'; raw = carrier.encoded(self.report)
        leaf.write_bytes(raw); leaf.chmod(0o444)
        runfiles = self.root/'material-runfiles'; repository = runfiles/material.REPOSITORY
        (repository/'inputs/sdk').mkdir(parents=True,mode=0o700)
        row = {'path':str(leaf),'sha256':carrier.sha(raw),'bytes':len(raw),'alias':'inputs/sdk/program-report.json'}
        mapping = carrier.encoded({'kind':material.DECLARED_KIND,'stage':'material','files':{'sdk/program-report.json':row}})
        document = {'schema_version':2,'kind':material.KIND,'source':self.source,
            'sdk':{'root':str(self.root),'receipt_sha256':carrier.sha(raw),
                'inventory_sha256':carrier.sha(self.raw),'producer':self.actor},
            'controller_source_commit':self.actor['source_commit'],'controller_graph_sha256':self.actor['graph_sha256']}
        selected_raw = carrier.encoded(document)
        for name,value in (('inputs.json',mapping),('selected-material.json',selected_raw)):
            (external/name).write_bytes(value); (external/name).chmod(0o444)
            (repository/name).symlink_to(external/name)
        (repository/row['alias']).symlink_to(leaf)
        with material.DeclaredInputs(runfiles,[['_main',material.REPOSITORY,material.REPOSITORY]],self.deadline,stage='material') as declared:
            self.assertEqual(declared.selection,document)
            self.assertEqual(declared.selection_raw,selected_raw)
            self.assertNotEqual(carrier.sha(declared.selection_raw),self.report['authority_sha256'])
            self.assertEqual(declared.role('sdk/program-report.json'),raw)
            (external/'selected-material.json').chmod(0o600)
            (external/'selected-material.json').write_bytes(selected_raw+b' ')
            with self.assertRaises(ValueError): declared.recheck()

    def test_writer_identity_rejects_same_byte_nested_replacement_before_first_read(self):
        output = material.ProjectionOutput(self.root/'writer-projection',carrier.Clock(self.deadline))
        try:
            export.write_members(output,'hub',self.hub,self.hub_rows)
            export.write_members(output,'graph',self.graph,self.graph_rows)
            output.file('authority.json',self.raw)
            leaf = output.path/'hub/BUILD.bazel'; raw = leaf.read_bytes()
            leaf.parent.chmod(0o700); leaf.rename(leaf.with_name('old-BUILD.bazel'))
            leaf.write_bytes(raw); leaf.chmod(0o444); leaf.parent.chmod(0o555)
            with self.assertRaises(ValueError): output.root.open('hub/BUILD.bazel')
        finally: output.close()

    def test_held_nested_projection_leaf_replacement_refuses_even_with_identical_bytes(self):
        output = material.ProjectionOutput(self.root/'held-projection',carrier.Clock(self.deadline))
        try:
            export.write_members(output,'hub',self.hub,self.hub_rows)
            export.write_members(output,'graph',self.graph,self.graph_rows)
            output.file('authority.json',self.raw); output.file('sdk-receipt.json',carrier.encoded(self.report)); output.finish()
            self.assertEqual(material.projection_read(output.root,self.report,output.clock),{'hub':self.hub,'graph':self.graph})
            leaf = output.path/'hub/data.bzl'; raw = leaf.read_bytes()
            leaf.parent.chmod(0o700); leaf.rename(leaf.with_name('old-data.bzl'))
            leaf.write_bytes(raw); leaf.chmod(0o444); leaf.parent.chmod(0o555)
            with self.assertRaises(ValueError): output.root.check()
        finally: output.close()

    def test_declared_route_xml_rejects_outer_failure_error_skip_and_negative_counts(self):
        child = '<testsuite tests="1" failures="0" errors="0" skipped="0"/>'
        self.assertTrue(material.legacy.declared_xml_success(('<testsuites>'+child+'</testsuites>').encode()))
        self.assertTrue(material.legacy.declared_xml_success(child.encode()))
        for counter in ('failures','errors','skipped'):
            with self.subTest(counter=counter),self.assertRaises(ValueError):
                material.legacy.declared_xml_success(('<testsuites '+counter+'="1">'+child+'</testsuites>').encode())
        for count in ('0','-1','not-a-count'):
            with self.subTest(count=count),self.assertRaises(ValueError):
                material.legacy.declared_xml_success(('<testsuites tests="'+count+'">'+child+'</testsuites>').encode())

    def test_final_source_fence_refuses_mutation_during_long_carrier_pass(self):
        session = material.Session.__new__(material.Session)
        session.closed = False; session.deadline = self.deadline; session.caller_deadline = self.deadline; session.clock = carrier.Clock(self.deadline)
        session.authenticated = {}; session.authenticate = lambda:{}
        session.core = {'original_selection':self.original}
        session.source_report = {}; session.parent = {'baseline_graph_files':{}}; session.exported = {}
        session.projected = {}; session.report = {}; session.origin = {}; session.extraction = {}
        session.carrier_root = self.root; session.pin = 'a'*64; session.extracted = self.root/'extracted'; session.extraction_pin = 'b'*64
        mutated = [False]; events = []
        def source_fence():
            events.append('source-fence')
            if mutated[0]: raise ValueError('model: SOURCE changed during final carrier phase')
        held = SimpleNamespace(recheck=source_fence)
        session.source_proof = SimpleNamespace(snapshots=[(name,held) for name in ('third','fifth','sixth','seventh','ninth')],
            join_n5=lambda unused:None,join_n9=lambda unused:None)
        root = SimpleNamespace(check=lambda:None)
        session.root = session.carrier_hold = session.temporary_hold = root
        session.inputs = SimpleNamespace(recheck=lambda:None); session.fresh = {'sdk':root,'jdk':root}
        def carrier_pass(*args,**kwargs):
            events.append('carrier-pass'); mutated[0] = True; return {}
        with patch.object(material.query_tools,'verify_repository',return_value={'status':'declared-fixed-query-tools-byte-qualified','inputs_rechecked':True}), \
                patch.object(material.binding,'load_verified_source',return_value=({},)), \
                patch.object(material.sdk,'validate_export',return_value={}), \
                patch.object(material,'projection_read',return_value={}), \
                patch.object(material.carrier,'validate_binding',return_value={}), \
                patch.object(material.carrier,'revalidate_extraction',side_effect=carrier_pass):
            with self.assertRaises(ValueError): session.recheck()
        self.assertEqual(events[-2:],['carrier-pass','source-fence'])



    def test_session_exit_fresh_readback_follows_source_finish_and_restores_context_on_refusal(self):
        from contextlib import ExitStack
        session = material.Session.__new__(material.Session)
        session.closed = False; session.deadline = self.deadline; session.stack = ExitStack()
        session.carrier_root = self.root; session.pin = 'a'*64
        session.extracted = self.root/'extracted'; session.extraction_pin = 'b'*64; session.extraction = {}
        events = []
        session.recheck = lambda:events.append('initial-fence')
        session.source_proof = SimpleNamespace(finish=lambda:events.append('source-finish'))
        session.stack.callback(lambda:events.append('closed'))
        def final_fresh(*args,**kwargs):
            self.assertEqual(events,['initial-fence','source-finish'])
            raise ValueError('model: fresh custody lost during final source sweep')
        with patch.object(material.carrier,'revalidate_extraction',side_effect=final_fresh):
            with self.assertRaises(ValueError):
                with material.installed_session(session):
                    self.assertIs(material._SCOPE.get(),session)
        self.assertTrue(session.closed)
        self.assertIsNone(material._SCOPE.get())
        self.assertEqual(events,['initial-fence','source-finish','closed'])

    def run_sdk_main_boundary(self,*,changed_selector=False):
        from contextlib import ExitStack,redirect_stdout
        import io
        runfiles = self.root/'main-runfiles'; runfiles.mkdir()
        (runfiles/'_repo_mapping').write_bytes(b'_main,fixture,fixture\n')
        output = self.root/'main-output'; output.mkdir()
        temporary = self.root/'main-tmp'; temporary.mkdir()
        selected = {'original_selection':self.original,'carrier':{'receipt_sha256':'a'*64},
            'qualification':{'producer':self.actor,'report':{'path':'/model/seal-program.json','sha256':'b'*64}}}
        selector = carrier.encoded({'schema_version':2,'kind':material.metadata.KIND,
            'status':'selected-qualified-carrier-for-metadata','selection':selected})
        reads = []; published = output/export.OUTPUT/'sdk-receipt.json'
        result = {'kind':material.SDK_KIND,'model_only':True}
        def declared(name,maximum):
            self.assertEqual((name,maximum),(material.metadata.CONFIG,16384))
            reads.append(name)
            return selector+b'changed' if changed_selector and len(reads)==2 else selector
        def produce(*args):
            self.assertEqual(material.metadata._SCOPE.get(),args[-1])
            published.parent.mkdir(); published.write_bytes(carrier.encoded(result))
            return result
        class Inputs:
            def __enter__(unused): return unused
            def __exit__(unused,*args): return None
        entry = time.monotonic_ns()
        env = {'OMUX_NATIVE_CARRIER_MODE':export.PROFILE,'OMUX_NATIVE_CARRIER_ENTRY_NS':str(entry),
            'OMUX_NATIVE_CARRIER_DEADLINE_NS':str(entry+1200*10**9),
            'OMUX_NATIVE_CARRIER_EPOCH':str(Path(self.actor['receipt']).parent),
            'OMUX_NATIVE_CARRIER_SOURCE_COMMIT':self.actor['source_commit'],
            'OMUX_NATIVE_CARRIER_GRAPH_SHA256':self.actor['graph_sha256'],
            'TEST_SRCDIR':str(runfiles),'TEST_UNDECLARED_OUTPUTS_DIR':str(output),
            'TEST_TMPDIR':str(temporary),'TEST_TIMEOUT':'1200'}
        stream = io.StringIO()
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ,env))
            stack.enter_context(patch.object(export.sys,'argv',['sdk-model']))
            stack.enter_context(patch.object(export.os,'umask',return_value=0o077))
            stack.enter_context(patch.object(material.metadata.legacy,'configure_selection'))
            stack.enter_context(patch.object(material.binding.ninth.parent,'declared',side_effect=declared))
            stack.enter_context(patch.object(material,'config',return_value=({'metadata':self.program},'c'*64)))
            stack.enter_context(patch.object(material.metadata.legacy,'declared_query_tools',return_value=True))
            stack.enter_context(patch.object(export.query_tools,'verify_repository',
                return_value={'status':'declared-fixed-query-tools-byte-qualified','inputs_rechecked':True}))
            stack.enter_context(patch.object(material.metadata,'declared_carrier',return_value=(self.root,(),{})))
            stack.enter_context(patch.object(material.metadata,'declared_proofs',return_value=object()))
            stack.enter_context(patch.object(material,'DeclaredInputs',return_value=Inputs()))
            stack.enter_context(patch.object(export,'produce',side_effect=produce))
            stack.enter_context(redirect_stdout(stream))
            if changed_selector:
                with self.assertRaises(ValueError): export.main()
            else: export.main()
        self.assertIsNone(material.metadata._SCOPE.get())
        self.assertEqual(len(reads),2)
        self.assertTrue(published.is_file())
        return stream.getvalue(),published.read_bytes()

    def test_sdk_actual_main_marker_binds_publication_and_two_selector_reads(self):
        output,raw = self.run_sdk_main_boundary()
        self.assertEqual(output.splitlines(),['omux-native-carrier-sdk-output-sha256='+carrier.sha(raw)])

    def test_sdk_selector_changed_after_publication_has_no_success_marker(self):
        output,_ = self.run_sdk_main_boundary(changed_selector=True)
        self.assertNotIn('omux-native-carrier-sdk-output-sha256=',output)

if __name__ == '__main__': unittest.main()
