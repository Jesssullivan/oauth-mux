"""Real tiny complete carrier/extraction/NAR tests; no native execution proof."""
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import time
import threading
import unittest
from unittest.mock import patch

import codex_transported_sdk_inputs as transported
import codex_native_sdk_carrier_test as fixture_module

core, family = transported.core, transported.family


class TransportedSDKTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixture_module.CarrierModels()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.origin_patch = patch.object(transported.original,'ORIGIN',self.fixture.origin)
        self.pin_patch = patch.object(transported.original,'ORIGIN_PIN',self.fixture.pin)
        self.origin_patch.start(); self.pin_patch.start()
        self.addCleanup(self.origin_patch.stop); self.addCleanup(self.pin_patch.stop)
        self.carrier, self.report, self.pin = self.fixture.seal()
        self.entry = time.monotonic_ns(); self.until = self.entry+1200*10**9
        self.cutoff = (self.entry+600*10**9)/10**9
        self.context = {'MODE':transported.original.MODE,'ENTRY_NS':str(self.entry),'DEADLINE_NS':str(self.until),
            'EPOCH':self.fixture.context['epoch'],'SOURCE_COMMIT':'1'*40,'GRAPH_SHA256':'2'*64}
        self.alias_dir = self.fixture.root/'aliases';self.alias_dir.mkdir(mode=0o700)
        for name in core.FILES: (self.alias_dir/name).symlink_to(self.carrier/name)
        self.selection = {'carrier_root':str(self.carrier),'digests':{
            name:core.sha((self.carrier/name).read_bytes()) for name in core.FILES}}
        self.fixture.write(self.alias_dir/'selection.json',core.encoded(self.selection),0o444)
        self.alias_dir.chmod(0o555)
        self.aliases = tuple((self.alias_dir/name,self.carrier/name) for name in core.FILES)+(
            (self.alias_dir/'selection.json',self.alias_dir/'selection.json'),)
        self.declaration = {'selection':self.selection,'selection_path':str(self.alias_dir/'selection.json'),
            'selection_sha256':core.sha(core.encoded(self.selection))}
        self.temporary = self.fixture.root/'work';self.temporary.mkdir(mode=0o700)
        self.environment = {'OMUX_NATIVE_FILE_WRITER_MODELS_'+key:value for key,value in self.context.items()}
        self.environment['TEST_TMPDIR'] = str(self.temporary)

    @contextmanager
    def owner(self):
        old = family.source.DEADLINE
        family.source.DEADLINE = self.cutoff
        try:
            with patch.dict(os.environ,self.environment,clear=True), family.HeldControls() as retained:
                for alias,physical in self.aliases: retained.add_alias(alias,physical)
                session = transported.HeldTransportedSDK(self.carrier,self.pin,self.entry,self.until,self.context,
                    self.temporary/'siwc-transported-sdk',self.aliases,self.declaration,retained)
                self.last_session = session
                with session: yield session
        finally: family.source.DEADLINE = old

    def test_complete_transport_rebases_every_mapping_without_reading_original_hosts(self):
        original_init = core.Root.__init__
        def no_origin(owner,path,*args,**kwargs):
            self.assertNotIn(Path(path),(self.fixture.origin,Path(core.sdk.JDK)))
            return original_init(owner,path,*args,**kwargs)
        with patch.object(core.Root,'__init__',no_origin), self.owner() as session:
            self.assertEqual(session.read_regular('sdk','repositories/public+/tool',4096),b'tool model\x00bytes')
            mapping = session.mapping(); original = core.decode(session.original_mapping)
            self.assertEqual(set(mapping['repositories']),set(original['repositories']))
            self.assertTrue(all(path == str(session.sdk_root/'repositories'/name)
                for name,path in mapping['repositories'].items()))
            self.assertEqual(mapping['registry_cache'],str(session.sdk_root/'registry-cache'))
            self.assertEqual(mapping['graph_files'],original['graph_files'])
            for module,value in mapping['module_overrides'].items():
                self.assertIn(value,mapping['repositories'].values())
            record = session.record()
            self.assertFalse(record['original_inodes_reused']);self.assertFalse(record['ambient_original_roots_read'])
            self.assertTrue(record['downstream_requires_fresh_extraction'])
            self.assertEqual(record['physical_paths_scope'],'current-held-action-only')
            self.assertFalse(record['portable_execution_qualified'])
            self.assertEqual(session.until_ns,self.entry+600*10**9)
            session.finish()
        self.assertFalse(session.active)
        with self.assertRaises(ValueError): session.mapping()

    def test_transport_corrupt_payload_refuses_before_content_owner_is_ready(self):
        path = self.carrier/'payload.bin';path.chmod(0o600)
        raw = path.read_bytes();path.write_bytes(bytes([raw[0]^1])+raw[1:]);path.chmod(0o444)
        with self.assertRaises(ValueError):
            with self.owner(): self.fail('corrupt packed payload admitted')

    def test_unlisted_regular_and_reentry_refuse_without_renewing_clock(self):
        with self.owner() as session:
            cutoff = session.until_ns
            with self.assertRaises(ValueError): session.read_regular('sdk','undeclared',4096)
            with self.assertRaises(ValueError): session.__enter__()
            self.assertEqual(session.until_ns,cutoff)
            session.finish()

    def test_same_target_declared_alias_replacement_is_refused_by_actual_held_owner(self):
        with self.assertRaises(ValueError):
            with self.owner() as session:
                alias,physical = self.aliases[0]
                self.alias_dir.chmod(0o700);alias.unlink();alias.symlink_to(physical);self.alias_dir.chmod(0o555)
                session.fence()
        self.assertFalse(session.active)
        self.assertEqual(session.transport._held,())

    def test_fresh_member_same_bytes_new_inode_and_receipt_in_place_drift_refuse(self):
        # Separate owned temporary sessions preserve both fresh regular and
        # extraction-receipt negative paths; neither changes original witnesses.
        with self.assertRaises(ValueError):
            with self.owner() as session:
                path = session.sdk_root/'repositories/public+/tool'
                raw = path.read_bytes();path.parent.chmod(0o700);path.unlink()
                self.fixture.write(path,raw,0o555);path.parent.chmod(0o555)
                session.fence()
        self.assertFalse(session.finished)
        # A distinct fresh action scratch is necessary after failed extraction;
        # never reopen a prior result or reset that session's cutoff.
        self.temporary = self.fixture.root/'next-work';self.temporary.mkdir(mode=0o700)
        self.environment['TEST_TMPDIR'] = str(self.temporary)
        with self.assertRaises(ValueError):
            with self.owner() as session:
                path = session.extracted/'extraction-receipt.json'
                raw = path.read_bytes();path.chmod(0o600);path.write_bytes(raw);path.chmod(0o444)
                session.fence()
        self.assertFalse(session.finished)

    def test_last_fresh_proof_detects_mutation_during_complete_carrier_final(self):
        with self.assertRaises(ValueError):
            with self.owner() as session:
                complete = session.transport.full_final
                fired = []
                def late():
                    complete()
                    path = session.sdk_root/'repositories/public+/tool'
                    path.chmod(0o600);path.write_bytes(b'changed full transport model');path.chmod(0o555)
                    fired.append(True)
                with patch.object(session.transport,'full_final',side_effect=late): session.finish()
        self.assertEqual(fired,[True]);self.assertFalse(session.finished);self.assertFalse(session.active)
        self.assertEqual(session.transport._held,())

    def test_current_context_and_original_integer_expiry_refuse_without_final_credit(self):
        with self.assertRaises(ValueError):
            with self.owner() as session:
                with patch.dict(os.environ,{'OMUX_NATIVE_FILE_WRITER_MODELS_GRAPH_SHA256':'f'*64}): session.check()
        self.temporary = self.fixture.root/'expired-work';self.temporary.mkdir(mode=0o700)
        self.environment['TEST_TMPDIR'] = str(self.temporary)
        with self.assertRaises(ValueError):
            with self.owner() as session:
                cutoff = session.until_ns
                with patch.object(core.time,'monotonic_ns',return_value=cutoff): session.fence()
        self.assertEqual(session.until_ns,self.entry+600*10**9)
        self.assertFalse(session.finished);self.assertFalse(session.active)

    def test_last_normal_exit_namespace_drift_of_receipt_or_output_roots_refuses(self):
        for fault in ('receipt-samebytes','output-extra','scratch-extra'):
            with self.subTest(fault=fault):
                self.temporary = self.fixture.root/('late-exit-'+fault)
                self.temporary.mkdir(mode=0o700)
                self.environment['TEST_TMPDIR'] = str(self.temporary)
                fired = []
                with self.assertRaises(ValueError):
                    with self.owner() as session:
                        session.finish()
                        namespace = core._fresh_namespace
                        def late(*args,**kwargs):
                            value = namespace(*args,**kwargs)
                            if not fired:
                                if fault == 'receipt-samebytes':
                                    path = session.extracted/'extraction-receipt.json'
                                    raw = path.read_bytes();path.chmod(0o600);path.write_bytes(raw);path.chmod(0o444)
                                elif fault == 'output-extra':
                                    session.extracted.chmod(0o700)
                                    self.fixture.write(session.extracted/'unexpected',b'public late exit fixture')
                                    session.extracted.chmod(0o555)
                                else:
                                    self.fixture.write(session.temporary/'unexpected',b'public late exit fixture')
                                fired.append(True)
                            return value
                        # Keep this seam alive while the actual owner context
                        # exits normally, after finish's full byte/NAR proofs.
                        seam = patch.object(core,'_fresh_namespace',side_effect=late)
                        seam.start()
                        self.addCleanup(seam.stop)
                seam.stop()
                self.assertEqual(fired,[True])
                self.assertFalse(session.active)
                self.assertEqual(session.transport._held,())
                self.assertEqual(session.output.chain,[])
                self.assertEqual(session.scratch.chain,[])

    def test_action_scratch_omits_only_worker_fsync_and_default_extract_keeps_it(self):
        fsync = os.fsync
        worker_sync = []
        def durable(fd):
            if threading.current_thread().name.startswith('sdk-copy-'):
                worker_sync.append(core.identity(os.fstat(fd)))
            return fsync(fd)
        held = core.HeldCarrier(self.carrier,self.pin,self.cutoff)
        held._clock.until_ns = held._until_ns = self.entry+600*10**9
        with patch.object(core.os,'fsync',side_effect=durable),held:
            permanent = self.fixture.root/'default-extraction'
            receipt = core.extract(self.carrier,self.pin,permanent,self.cutoff,_held_carrier=held)
            unused_report,unused_proof,rows,unused_files = held._binding()
            self.assertEqual(len(worker_sync),sum(row['kind']=='file' for row in rows.values()))
            self.assertEqual(receipt['kind'],core.EXTRACTED)
            self.assertNotIn('durability_scope',receipt)
            held.full_final()
            self.assertEqual(core.revalidate_extraction(self.carrier,self.pin,permanent,self.cutoff,
                pinned_extraction_receipt_sha256=core.sha(core.encoded(receipt)),_held_carrier=held),receipt)
        def scratch(fd):
            if threading.current_thread().name.startswith('sdk-copy-'):
                self.fail('ephemeral scratch issued per-file power-loss sync')
            return fsync(fd)
        with patch.object(core.os,'fsync',side_effect=scratch),self.owner() as session:
            receipt = core.decode(session.extraction)
            self.assertEqual(receipt['kind'],core.SCRATCH_EXTRACTED)
            self.assertEqual(receipt['consumer_context'],self.context)
            self.assertFalse(receipt['crash_durable_delivery'])
            self.assertFalse(receipt['downstream_custody_authority'])
            self.assertEqual(session.read_regular('sdk','repositories/public+/tool',4096),b'tool model\x00bytes')
            # Old permanent receipt/schema consumers cannot admit this new role.
            with self.assertRaises(ValueError):
                core.revalidate_extraction(self.carrier,self.pin,session.extracted,self.cutoff,
                    pinned_extraction_receipt_sha256=session.extraction_pin,_held_carrier=session.transport)
            session.finish()

    def test_action_scratch_wrong_path_or_captured_context_refuses_before_creation(self):
        held = core.HeldCarrier(self.carrier,self.pin,self.cutoff)
        held._clock.until_ns = held._until_ns = self.entry+600*10**9
        with patch.dict(os.environ,self.environment,clear=True),held:
            good = self.temporary/'siwc-transported-sdk'/'extracted'
            wrong = self.temporary/'arbitrary-output'
            for path,context in ((wrong,self.context),(good,{**self.context,'GRAPH_SHA256':'f'*64})):
                with self.assertRaises(ValueError):
                    core.extract_action_scratch(self.carrier,self.pin,path,self.cutoff,
                        _held_carrier=held,consumer_context=context)
                self.assertFalse(path.exists())
            self.assertIsNone(held._extracted)
            held.report();held.full_final()

    def test_action_scratch_write_and_digest_faults_keep_full_refusal_and_owner_cleanup(self):
        for fault in ('digest','write'):
            with self.subTest(fault=fault):
                self.temporary = self.fixture.root/('fault-work-'+fault);self.temporary.mkdir(mode=0o700)
                self.environment['TEST_TMPDIR'] = str(self.temporary)
                actual = core._copy_regular_job
                fired = []
                def refuse(state,parent,leaf,witness,payload,entry):
                    fired.append(True)
                    if fault == 'write': raise OSError('public scratch IO fixture')
                    changed = dict(entry);changed['sha256']='f'*64
                    return actual(state,parent,leaf,witness,payload,changed)
                with patch.object(core,'_copy_regular_job',side_effect=refuse):
                    with self.assertRaises((ValueError,OSError)):
                        with self.owner(): self.fail('invalid scratch copy admitted')
                self.assertTrue(fired)
                session = self.last_session
                self.assertFalse(session.active);self.assertFalse(session.finished)
                self.assertIsNone(session.transport._extracted)
                self.assertEqual(session.transport._held,())
                self.assertEqual(session.scratch.chain,[])
                self.assertFalse((session.extracted/'extraction-receipt.json').exists())

    def test_action_scratch_copy_integer_expiry_keeps_original_cutoff_and_joins_workers(self):
        fired = threading.Event()
        actual_sync = core._ActionScratchCopyState.sync
        actual_ns = core.time.monotonic_ns
        def sync(state,fd):
            actual_sync(state,fd);fired.set()
        def expired(): return self.entry+600*10**9 if fired.is_set() else actual_ns()
        with patch.object(core._ActionScratchCopyState,'sync',side_effect=sync,autospec=True), \
                patch.object(core.time,'monotonic_ns',side_effect=expired):
            with self.assertRaises(ValueError):
                with self.owner(): self.fail('original expired copy admitted')
        self.assertTrue(fired.is_set())
        session = self.last_session
        self.assertEqual(session.until_ns,self.entry+600*10**9)
        self.assertFalse(session.active);self.assertFalse(session.finished)
        self.assertIsNone(session.transport._extracted);self.assertEqual(session.transport._held,())
        self.assertFalse(any(thread.name in ('sdk-copy-0','sdk-copy-1') for thread in threading.enumerate()))

    def test_missing_final_or_foreign_declaration_and_alias_roles_refuse(self):
        with self.assertRaises(ValueError):
            with self.owner() as session: self.assertFalse(session.finished)
        old = family.source.DEADLINE;family.source.DEADLINE = self.cutoff
        try:
            with patch.dict(os.environ,self.environment,clear=True),family.HeldControls() as retained:
                for alias,physical in self.aliases:retained.add_alias(alias,physical)
                for fault in ('pin','aliases'):
                    declaration = copy.deepcopy(self.declaration);aliases = self.aliases
                    if fault == 'pin':declaration['selection']['digests']['receipt.json']='a'*64
                    else:aliases = aliases[1:]+aliases[:1]
                    with self.assertRaises(ValueError):
                        transported.HeldTransportedSDK(self.carrier,self.pin,self.entry,self.until,self.context,
                            self.temporary/'never-created',aliases,declaration,retained)
        finally:family.source.DEADLINE = old



    @contextmanager
    def budget_owner(self):
        import codex_native_siwc_source as controller
        real_alias = family.HeldControls.add_alias
        def add(owner, alias, physical):
            result = real_alias(owner, alias, physical)
            if not hasattr(owner, '_source_phase_observer'):
                observer = controller._SourcePhaseObserver(self.entry, self.until, self.cutoff)
                observer.bind(owner)
                # Explicit controller-stage seam: separate actual-main fixture
                # covers these placements. All real transported IO follows.
                for stage in observer.stages[:5]: observer.emit(stage)
            return result
        with patch.object(family.HeldControls, 'add_alias', add):
            with self.owner() as session: yield session

    def test_budget_complete_real_transport_ten_scalar_records_and_all_full_proofs(self):
        import io
        import codex_native_siwc_source as controller
        sink = io.StringIO()
        with patch.object(controller.sys, 'stderr', sink), self.budget_owner() as session:
            self.assertEqual(session.mapping()['graph_files'], core.decode(session.original_mapping)['graph_files'])
            self.assertEqual(session.alias_owner._source_phase_observer.count, 10)
            self.assertEqual(session.until_ns, self.entry+600*10**9)
            session.finish()
        lines = [line for line in sink.getvalue().splitlines() if line.startswith('native-source-budget:')]
        self.assertEqual(len(lines), 10)
        for stage, line in zip(controller._SourcePhaseObserver.stages, lines):
            self.assertRegex(line, '^native-source-budget: phase='+stage+r' elapsed_ns=[0-9]+ remaining_ns=[0-9]+$')
            self.assertLessEqual(len(line.encode()), 160)
        self.assertFalse(session.active); self.assertEqual(session.transport._held, ())
        self.assertEqual(session.until_ns, self.entry+600*10**9)

    def test_budget_real_transport_each_io_refusal_boundary_drains_held_resources(self):
        import io
        import codex_native_siwc_source as controller
        for stage in controller._SourcePhaseObserver.stages[5:]:
            with self.subTest(stage=stage):
                self.temporary = self.fixture.root/('budget-'+stage); self.temporary.mkdir(mode=0o700)
                self.environment['TEST_TMPDIR'] = str(self.temporary)
                first = OSError('synthetic sensitive write body'); owned = []
                class Refusing(io.StringIO):
                    def write(inner, text):
                        if 'native-source-budget: phase='+stage+' ' in text:
                            current = self.last_session
                            if hasattr(current, 'scratch'):
                                owned.extend(fd for _, fd, _ in current.scratch.chain)
                            if hasattr(current, 'transport'):
                                owned.extend(fd for _, fd, _ in current.transport._held)
                                owned.extend(fd for _, fd, _ in current.transport._root.chain)
                            raise first
                        return super().write(text)
                with patch.object(controller.sys, 'stderr', Refusing()):
                    with self.assertRaises(OSError) as failure:
                        with self.budget_owner(): self.fail('diagnostic refusal admitted')
                self.assertIs(failure.exception, first); self.assertFalse(self.last_session.active)
                if hasattr(self.last_session, 'transport'): self.assertEqual(self.last_session.transport._held, ())
                self.assertEqual(self.last_session.clock.until_ns, self.entry+600*10**9)
                self.fixture.assert_descriptors_closed(owned)

    def test_budget_body_first_cause_survives_actual_held_owner_close_error(self):
        import io
        import codex_native_siwc_source as controller
        first, cleanup = MemoryError('synthetic private proof body'), OSError('synthetic close refusal')
        real_close = os.close; armed, owned, attempted = [False], [], []
        def refused(owner):
            owned.extend(fd for _, fd, _ in owner._held)
            owned.extend(fd for _, fd, _ in owner._root.chain)
            armed[0] = True
            raise first
        def close(fd):
            real_close(fd)
            if armed[0] and fd in owned:
                attempted.append(fd)
                if len(attempted) == 1: raise cleanup
        with patch.object(controller.sys, 'stderr', io.StringIO()), \
                patch.object(core.HeldCarrier, '_binding', refused), patch.object(core.os, 'close', close):
            with self.assertRaises(MemoryError) as failure:
                with self.budget_owner(): self.fail('initial proof refusal admitted')
        self.assertIs(failure.exception, first); self.assertIs(failure.exception.__cause__, cleanup)
        self.assertEqual(set(attempted), set(owned)); self.assertEqual(len(attempted), len(owned))
        self.fixture.assert_descriptors_closed(owned)
        self.assertFalse(self.last_session.active); self.assertEqual(self.last_session.transport._held, ())

    def test_budget_successful_flush_expiry_cannot_dispatch_extraction_or_renew_clock(self):
        import io
        import codex_native_siwc_source as controller
        real_ns, real_float = time.monotonic_ns, time.monotonic
        late, pending = [False], [False]
        class Late(io.StringIO):
            def write(inner, text):
                if 'native-source-budget: phase=extraction-dispatch ' in text: pending[0] = True
                return super().write(text)
            def flush(inner):
                if pending[0]: late[0] = True
        def ns(): return self.entry+600*10**9 if late[0] else real_ns()
        def seconds(): return self.cutoff if late[0] else real_float()
        with patch.object(controller.sys, 'stderr', Late()), patch.object(core.time, 'monotonic_ns', ns), \
                patch.object(core.time, 'monotonic', seconds), patch.object(core, 'extract_action_scratch') as extraction:
            with self.assertRaises(ValueError):
                with self.budget_owner(): self.fail('late diagnostic admitted extraction')
        extraction.assert_not_called(); self.assertTrue(late[0])
        self.assertEqual(self.last_session.clock.deadline, self.cutoff)
        self.assertEqual(self.last_session.clock.until_ns, self.entry+600*10**9)
        self.assertFalse(self.last_session.active); self.assertEqual(self.last_session.transport._held, ())

    def test_budget_observer_order_cap_redaction_foreign_owner_fail_before_output(self):
        import io
        import codex_native_siwc_source as controller
        old = family.source.DEADLINE; family.source.DEADLINE = self.cutoff
        try:
            sink = io.StringIO()
            with patch.object(controller.sys, 'stderr', sink):
                observer = controller._SourcePhaseObserver(self.entry, self.until, self.cutoff)
                for stage in ('secret/path-or-token', 'controls-complete', None):
                    with self.assertRaises(ValueError): observer.emit(stage)
                self.assertEqual(sink.getvalue(), '')
                for stage in observer.stages: observer.emit(stage)
                before = sink.getvalue()
                with self.assertRaises(ValueError): observer.emit('controller-entry')
                self.assertEqual(sink.getvalue(), before); self.assertEqual(observer.count, 10)
                with family.HeldControls() as owner:
                    actual = controller._SourcePhaseObserver(self.entry, self.until, self.cutoff)
                    actual.bind(owner)
                    with self.assertRaises(ValueError): actual.bind(owner)
            with patch.object(controller.sys, 'stderr', sink), self.owner() as session:
                session.alias_owner._source_phase_observer = object()
                with self.assertRaises(ValueError): session._budget_phase('transported-entry')
                del session.alias_owner._source_phase_observer
                session.finish()
        finally: family.source.DEADLINE = old


if __name__ == '__main__':unittest.main()
