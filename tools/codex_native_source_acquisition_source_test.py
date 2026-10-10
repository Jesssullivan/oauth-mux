"""Real strict nine-stage transform and sealed parent fixtures; no native IO."""
import copy
from contextlib import contextmanager
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import codex_native_source_acquisition_source as successor
import codex_native_source_context_refresh_source_test as refresh_models

source = successor.source

class AcquisitionSourceModels(refresh_models.RefreshSourceTests):
    def acquisition_fixture(self):
        files, report, refresh = self.fixture()
        root = successor.parent.ROOT / 'integrations/codex-upstream/acquisition-preimages'
        for name in successor.PREIMAGES:
            if name not in successor.parent.PREIMAGES:
                files[name] = ('100644', (root / name).read_bytes())
        inventory = successor.parent.seventh.status.inventory(files)
        report.update(source_inventory=inventory, inventory_sha256=source.sha(source.canonical(inventory)),
            tracked_files=len(files), source_bytes=sum(len(raw) for _, raw in files.values()),
            graph_files={name: {'sha256': source.sha(files[name][1])} for name in successor.parent.seventh.history.GRAPH})
        return files, report, refresh, successor.read_patch()

    def binding_value(self, root, config):
        def identity(path, regular=False):
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try: return successor.binding.identity(fd, regular)
            finally: os.close(fd)
        return {'root_identity': identity(root), 'source_root_identity': identity(root / 'source'),
            'receipt_identity': identity(root / 'source-receipt.json', True)}

    def test_ninth_exact_real_patch_and_all_inventory_retained(self):
        files, report, refresh, raw = self.acquisition_fixture()
        eighth = successor.parent.transform(files, refresh)
        result = successor.transform(eighth, raw)
        self.assertEqual(set(result), set(files) | {successor.NEW})
        self.assertEqual(len(result), len(files)+1)
        for name, pin in successor.AFTERIMAGES.items(): self.assertEqual(source.sha(result[name][1]), pin)
        for name in set(eighth)-set(successor.PREIMAGES): self.assertEqual(result[name], eighth[name])
        receipt = successor.expected_receipt(successor.parent.expected_receipt(report, eighth,
            self.config(Path('/synthetic'), files, report)), result, self.config(Path('/synthetic'), files, report))
        self.assertEqual(len(receipt['patch_sha256']),9)
        self.assertEqual(receipt['graph_files']['codex-rs/Cargo.lock']['sha256'],successor.AFTERIMAGES['codex-rs/Cargo.lock'])
        self.assertTrue(all(receipt[name] is False for name in successor.FLAGS))

    def test_ninth_wrong_parent_newfile_mode_and_unrelated_graph_refuse(self):
        files, _, refresh, raw = self.acquisition_fixture(); before=successor.parent.transform(files,refresh)
        for bad in ({**before,successor.NEW:('100644',b'existing')},
                {**before,'codex-rs/Cargo.lock':('100644',b'wrong parent')},
                {**before,'codex-rs/app-server/Cargo.toml':('100755',before['codex-rs/app-server/Cargo.toml'][1])}):
            with self.assertRaises(ValueError): successor.transform(bad,raw)
        after=successor.transform(before,raw)
        for bad in ({**after,'unrelated':('100644',b'extra')},
                {**after,successor.parent.seventh.history.GRAPH[0]:('100644',b'drift')},
                {**after,successor.NEW:('100755',after[successor.NEW][1])}):
            with self.assertRaises(ValueError): successor.validate_transition(before,bad)

    def test_ninth_rehashed_duplicate_hunk_position_context_and_afterimage_refuse(self):
        files, _, refresh, raw=self.acquisition_fixture();before=successor.parent.transform(files,refresh)
        first=raw.index(b'diff --git ',1);start=raw.index(b'@@ -');end=raw.index(b'\n',start)
        variants=(raw+raw[:first],raw[:start]+raw[start:end].replace(b'+',b'+999',1)+raw[end:],
            raw.replace(b' "futures",',b' "foreign-context",',1),raw.replace(b'new file mode 100644',b'new file mode 100755',1))
        for changed in variants:
            self.assertNotEqual(raw,changed)
            with patch.multiple(successor,PATCH_SHA=source.sha(changed),PATCH_BYTES=len(changed)),self.assertRaises(ValueError):
                successor.transform(before,changed)
        with patch.object(successor,'AFTERIMAGES',{**successor.AFTERIMAGES,successor.NEW:'0'*64}),self.assertRaises(ValueError):
            successor.transform(before,raw)

    def test_actual_binding_schema_does_not_invent_foreign_parent(self):
        config,value=successor.binding.load()
        self.assertEqual(config['source_members'],8551);self.assertEqual(config['source_bytes'],84683541)
        self.assertEqual(config['receipt_sha256'],'fbe2e3d1cdb7c4d601b45144182fdb1cdb6858d8565032ba4f060dcf253bf4ed')
        with patch.object(successor.parent,'load_input',return_value={**config,'root':'/synthetic-foreign'}),self.assertRaises(ValueError):
            successor.binding.load()
        self.assertTrue(value['all_future_qualification_false'])

    def test_real_sealed_n5_fixture_produce_ninth_without_eighth_output(self):
        files,report,_,_=self.acquisition_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            try:
                origin=root/'seventh';self.sealed_parent(origin,files,report)
                config=self.config(origin,files,report);value=self.binding_value(origin,config)
                with patch.object(successor.parent,'reconstruct_seventh',return_value=(report,files)), \
                        patch.object(successor.binding,'load',return_value=(config,value)):
                    receipt=successor.produce(root/'ninth',60)
                    with patch.object(source,'DEADLINE',successor.time.monotonic()+60):
                        verified,inventory=successor.verify_output(root/'ninth',source.sha(source.encoded(receipt)),receipt['inventory_sha256'])
                        self.assertEqual(verified,receipt)
                        self.assertEqual(len(inventory),len(files)+1)
                        for pin in ('0'*64, 'private-bait'):
                            with self.assertRaises(ValueError):successor.verify_output(root/'ninth',pin,receipt['inventory_sha256'])
                self.assertEqual(len(receipt['patch_sha256']),9)
                source.verify_written(root/'ninth/source',successor.transform(successor.parent.transform(files,successor.parent.read_patch()),successor.read_patch()))
                self.assertEqual((root/'ninth/source-receipt.json').read_bytes(),source.encoded(receipt))
                self.assertFalse((root/'eighth').exists())
                self.assertTrue(all(receipt[name] is False for name in successor.FLAGS))
            finally:self.cleanup(root)
        self.assertIsNone(source.DEADLINE)

    def test_real_binding_named_replacement_and_receipt_corruption_refuse(self):
        files,report,_,_=self.acquisition_fixture()
        for fault in ('root','receipt','mode'):
            with tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)
                try:
                    origin=root/'seventh';self.sealed_parent(origin,files,report)
                    config=self.config(origin,files,report);value=self.binding_value(origin,config)
                    with self.assertRaises((ValueError,OSError)), successor.binding.hold(config,value) as witness:
                        if fault=='root':
                            origin.rename(root/'old');origin.mkdir();origin.chmod(0o555)
                        elif fault=='receipt':
                            target=origin/'source-receipt.json';target.chmod(0o600);target.write_bytes(b'corrupt');target.chmod(0o555)
                        else:(origin/'source').chmod(0o700)
                        with self.assertRaises((ValueError,OSError)):witness()
                        # Context-manager's terminal fence must also refuse.
                finally:self.cleanup(root)

    def test_ninth_late_parent_patch_input_or_output_corruption_has_no_receipt(self):
        files,report,_,raw=self.acquisition_fixture()
        for fault in ('parent','patch','binding','output'):
            with tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)
                try:
                    origin=root/'seventh';self.sealed_parent(origin,files,report)
                    config=self.config(origin,files,report);value=self.binding_value(origin,config)
                    read=successor.read_patch;verify=source.verify_written;calls=[]
                    def checked(path,expected):
                        verify(path,expected);calls.append(path)
                        if path==root/'ninth/source' and len(calls)==2:
                            if fault=='parent':
                                victim=origin/'source/codex-rs/fixture-executable';victim.chmod(0o600);victim.write_bytes(b'drift');victim.chmod(0o555)
                            if fault=='output':
                                victim=root/'ninth/source'/successor.NEW;victim.chmod(0o600);victim.write_bytes(b'drift');victim.chmod(0o555)
                    bindings=[(config,value),(config,{**value,'root_identity':{}})] if fault=='binding' else [(config,value)]*2
                    patches=[raw,raw+b'corrupt'] if fault=='patch' else [raw]*2
                    with patch.object(successor.parent,'reconstruct_seventh',return_value=(report,files)), \
                            patch.object(successor.binding,'load',side_effect=bindings), \
                            patch.object(successor,'read_patch',side_effect=patches),patch.object(source,'verify_written',side_effect=checked),self.assertRaises(ValueError):
                        successor.produce(root/'ninth',60)
                    self.assertFalse((root/'ninth/source-receipt.json').exists())
                finally:self.cleanup(root)
        self.assertIsNone(source.DEADLINE)

    def test_terminal_binding_fence_leaves_partial_output_unqualified(self):
        files,report,_,_=self.acquisition_fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            try:
                origin=root/'seventh';self.sealed_parent(origin,files,report)
                config=self.config(origin,files,report);value=self.binding_value(origin,config)
                held=successor.binding.hold
                @contextmanager
                def late(config,value):
                    with held(config,value) as witness:yield witness
                    raise ValueError('terminal synthetic binding drift')
                with patch.object(successor.parent,'reconstruct_seventh',return_value=(report,files)), \
                        patch.object(successor.binding,'load',return_value=(config,value)), \
                        patch.object(successor.binding,'hold',side_effect=late),self.assertRaises(ValueError):
                    successor.produce(root/'ninth',60)
                self.assertEqual((root/'ninth').stat().st_mode & 0o777,0o700)
                with patch.object(source,'DEADLINE',successor.time.monotonic()+60), \
                        patch.object(successor.binding,'load',return_value=(config,value)),self.assertRaises(ValueError):
                    successor.verify_output(root/'ninth','0'*64,'0'*64)
            finally:self.cleanup(root)

if __name__=='__main__':unittest.main()
