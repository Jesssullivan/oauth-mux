"""Fixed source support and namespace models, no imports of provider runtimes."""
from pathlib import Path
from types import SimpleNamespace
import unittest
import yoga_installed_controller_support as support


class Models(unittest.TestCase):
    def value(self):
        return {'root': str(support.DELIVERY), 'files': {
            'codex_device_acquisition_component.py': {'sha256': 'a' * 64, 'bytes': 1}}}

    def test_only_one_fixed_successor_role(self):
        value = self.value(); self.assertIs(support.support(value), value)
        for changed in ({'root': '/private/foreign', 'files': value['files']},
                        {'root': value['root'], 'files': {}},
                        {'root': value['root'], 'files': {**value['files'], 'foreign.py': {'sha256': 'a' * 64, 'bytes': 1}}}):
            with self.assertRaises(ValueError): support.support(changed)

    def test_controller_and_source_root_must_join(self):
        support.controller({'root': str(support.TOOLS)}, support.ROOT)
        for value, root in (({'root': '/private/foreign'}, support.ROOT),
                            ({'root': str(support.TOOLS)}, '/private/foreign')):
            with self.assertRaises(ValueError): support.controller(value, root)

    def test_physical_controller_root_and_foreign_checkout_bindings(self):
        actual = Path(support.__file__).resolve().parent.parent
        package = {'root': str(actual / 'tools')}
        support.controller(package, actual)
        data = self.value()
        support.support(data)
        self.assertEqual(data['root'], str(actual / 'delivery'))
        component = actual / 'delivery/codex_device_acquisition_component.py'
        self.assertEqual(support.declared(str(component), lambda _: self.fail('not an alias')),
                         (component, component))
        foreign = (actual.parent / (actual.name + '-foreign'),
                   Path('/srv/fast-local/jess/git/oauth-mux-protocol-sdk-20261008'))
        for root in foreign:
            if root == actual: continue
            with self.subTest(root=root):
                with self.assertRaises(ValueError): support.controller(package, root)
                with self.assertRaises(ValueError): support.controller({'root': str(root/'tools')}, actual)
                with self.assertRaises(ValueError): support.support({**data, 'root': str(root/'delivery')})
                with self.assertRaises(ValueError): support.declared(str(root/'delivery'/component.name), lambda _: None)

    def test_canonical_data_role_only(self):
        actual = support.DELIVERY / 'codex_device_acquisition_component.py'
        self.assertEqual(support.declared(str(actual), lambda _: self.fail('output role')), (actual, actual))
        with self.assertRaises(ValueError): support.declared('/private/foreign.py', lambda _: None)
        alias = '/model/epoch/output-base/action.sh.runfiles/_main/delivery/codex_device_acquisition_component.py'
        calls = []
        self.assertEqual(support.declared(alias, calls.append), (Path(alias), actual))
        self.assertEqual(calls, [Path(alias)])

    def test_record_hash_must_be_a_whole_inventory_member(self):
        value = {'codex_device_acquisition_component.py': 'a' * 64}
        support.record_shape(value, {'delivery/codex_device_acquisition_component.py': {'sha256': 'a' * 64}})
        for inventory in ({}, {'delivery/codex_device_acquisition_component.py': {'sha256': 'b' * 64}}):
            with self.assertRaises(ValueError): support.record_shape(value, inventory)

    def test_loaded_support_cannot_escape_sealed_delivery(self):
        root = Path('/model/sealed'); hashes = {'codex_device_acquisition_component.py': 'a' * 64}
        support.loaded_modules(root, hashes, [SimpleNamespace(__file__=str(root/'delivery/codex_device_acquisition_component.py'))])
        with self.assertRaises(ValueError):
            support.loaded_modules(root, hashes, [SimpleNamespace(__file__='/private/codex_device_acquisition_component.py')])

    def test_support_insertion_reindexes_actual_alias_order(self):
        mapping = {'+repo/a': '/nix/store/selected/a', '_main/delivery/z.py': '/old/z.py',
                   '_main/tools/a.py': '/old/a.py',
                   '_main/delivery/codex_device_acquisition_component.py': str(support.DELIVERY/'codex_device_acquisition_component.py')}
        extra = {'_main/delivery/codex_device_acquisition_component.py': 'delivery/codex_device_acquisition_component.py'}
        copied, store = support.reindex(mapping, {'f000001': 'delivery/z.py', 'f000002': 'tools/a.py'},
            {'f000000': '/nix/store/selected/a'}, extra, 123, lambda until: self.assertEqual(until, 123))
        self.assertEqual(copied, {'f000001': 'delivery/codex_device_acquisition_component.py',
                                 'f000002': 'delivery/z.py', 'f000003': 'tools/a.py'})
        self.assertEqual(store, {'f000000': '/nix/store/selected/a'})
        for changed in ({}, {'f000001': '/nix/store/foreign/a'}):
            with self.assertRaises(ValueError):
                support.reindex(mapping, {'f000001': 'delivery/z.py', 'f000002': 'tools/a.py'},
                                changed, extra, 123, lambda _: None)


if __name__ == '__main__': unittest.main()
