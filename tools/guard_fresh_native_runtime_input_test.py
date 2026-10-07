"""Declared Bazel refusal model for nested selector pre-read admission."""
import unittest
from pathlib import Path
from unittest.mock import patch
import guard_fresh_native_runtime_input as guard


class AdmissionModel(unittest.TestCase):
    def test_foreign_nested_role_refused_before_open(self):
        calls = []
        selected = {'kind':guard.KIND,'package_selection':{'path':'/public/package.json'},
            'package_run':{},'producer_graph_sha256':'0'*64,'producer_source_sha256':'0'*64,
            'archive':{},'manifest':{},'receipt':{},'bundle_directory':'/public/leaf'}
        package = {'files':{'source':{'path':'/home/jess/.config/foreign-credential'}}}
        def read(path, pin, maximum):
            calls.append(str(path))
            return b'outer' if len(calls) == 1 else b'package'
        def parse(raw):
            return selected if raw == b'outer' else package
        def reject(value):
            self.assertEqual(value, package)
            raise ValueError('foreign public namespace')
        with patch.object(guard.fresh,'read_selected',side_effect=read), \
                patch.object(guard.fresh,'parse',side_effect=parse), \
                patch.object(guard.fresh,'canonical_path',side_effect=Path), \
                patch.object(guard,'operator_path',side_effect=lambda value,filename:Path(value)), \
                patch.object(guard,'validate_outer'), \
                patch.object(guard.fresh,'validate_selection_paths',side_effect=reject):
            with self.assertRaises(ValueError):
                guard.Admission(Path('/public/selector.json'),'0'*64,1,10**18)
        self.assertEqual(calls,['/public/selector.json','/public/package.json'])

    def test_poisoned_outer_pin_denied_before_artifact_read(self):
        epoch = 'a75d77f9-8a8c-453c-ab14-467d1d70e0e5'
        parent = str(guard.HOME_COORD/epoch/'output-base')+guard.PACKAGE_SUFFIX
        def pin(path):
            return {'path':path,'sha256':'0'*64,'bytes':1}
        selected = {'kind':guard.KIND,
            'package_selection':pin(str(guard.HOME_COORD/'package-selection.json')),
            'package_run':pin(str(guard.HOME_COORD/epoch/'receipt.json')),
            'producer_graph_sha256':'0'*64,'producer_source_sha256':'0'*64,
            'archive':pin(parent+'/fresh-native-runtime.tar.gz'),
            'manifest':pin(parent+'/runtime-manifest.json'),
            'receipt':pin(parent+'/runtime-receipt.json'),'bundle_directory':parent+'/'+'0'*64}
        for role in ('package_selection','package_run','archive','manifest','receipt'):
            poisoned = dict(selected)
            poisoned[role] = pin('/home/jess/.config/foreign-credential')
            with self.subTest(role=role), \
                    patch.object(guard.fresh,'canonical_path',side_effect=Path), \
                    patch.object(guard.fresh,'read_selected',return_value=b'outer') as reader, \
                    patch.object(guard.fresh,'parse',return_value=poisoned):
                with self.assertRaises(ValueError):
                    guard.Admission(guard.HOME_COORD/'fresh-runtime-selection.json','0'*64,1,10**18)
                self.assertEqual(reader.call_count,1)


if __name__ == '__main__':
    unittest.main()
