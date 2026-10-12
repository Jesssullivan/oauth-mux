"""Real tiny complete carrier/extraction/NAR tests; no native execution proof."""
from contextlib import contextmanager
import copy
import json
import os
from pathlib import Path
import time
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


if __name__ == '__main__':unittest.main()
