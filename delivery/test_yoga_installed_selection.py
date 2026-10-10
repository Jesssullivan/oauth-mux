"""Synthetic metadata/custody models only; no c106 or host execution proof."""
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

import yoga_installed_selection as assembly
import yoga_installed_workspace as workspace


class SelectionTests(unittest.TestCase):
    def test_real_execroot_inventory_route_old_fence_and_exact_leaf_success(self):
        for name, repository in assembly.INVENTORY_REPOS.items():
            for runner in ('linux-sandbox', 'processwrapper-sandbox'):
                with self.subTest(name=name, runner=runner), tempfile.TemporaryDirectory() as temporary:
                    root, base, parent, alias, canonical, expected = self.hop_fixture(temporary, runner)
                    if name != 'browserInventory':
                        expected = base / 'external' / repository / 'inventory.json'
                        expected.parent.mkdir(parents=True, mode=0o755)
                        expected.write_bytes(b'{"public":true}\n'); expected.chmod(0o644)
                        canonical = canonical.parent.parent / repository / 'inventory.json'
                        canonical.parent.mkdir(parents=True, mode=0o755); canonical.symlink_to(expected)
                        alias = alias.parent.parent / repository / 'inventory.json'
                    repository_alias = base / 'execroot/_main/external' / repository
                    repository_alias.parent.mkdir(parents=True, mode=0o755)
                    repository_alias.symlink_to(expected.parent, target_is_directory=True)
                    execroot_inventory = repository_alias / 'inventory.json'
                    # Reproduce a real sandbox input file pointing directly at
                    # its artifact's execroot leaf, rather than a runfiles tree.
                    sandbox_runfiles = alias.parent.parent
                    sandbox_runfiles.unlink(); sandbox_runfiles.mkdir(mode=0o755)
                    alias.parent.mkdir(mode=0o755); alias.symlink_to(execroot_inventory)
                    with patch.object(workspace, '_ASSEMBLY_COORDS', (root,)), \
                            patch.object(workspace.payload, 'parent', side_effect=parent):
                        context = workspace.AssemblyContext(base, time.monotonic() + 30)
                        try:
                            previous = (alias, canonical, expected)
                            diagnostic = assembly._AssemblyDiagnostic()
                            diagnostic.alias(runner)
                            with patch.object(workspace.os, 'lstat', wraps=os.lstat) as inspected, self.assertRaises(ValueError):
                                workspace.safe_resolve(alias, frozenset(), declared_paths=previous,
                                    _trace=diagnostic.resolver)
                            witness = json.loads(diagnostic.refusal())
                            self.assertEqual(witness['operation'], 'namespace-fence')
                            self.assertEqual(witness['declaredNamespace'], {'aliasLayout': runner,
                                'candidateClass': 'outside', 'linkForm': 'absolute', 'symbolicHops': 1})
                            self.assertFalse(any(Path(call.args[0]) == repository_alias for call in inspected.call_args_list))
                            paths = assembly.declared_alias_paths(alias, expected, repository + '/inventory.json',
                                selected_base=base, _assembly_context=context)
                            self.assertEqual(paths, (alias, canonical, execroot_inventory, expected))
                            self.assertEqual(assembly.declared_inventory(alias, name, selected_base=base,
                                _assembly_context=context), expected)
                            # Publication rechecks retain this exact tuple.
                            self.assertEqual(workspace.safe_resolve(alias, frozenset(), declared_paths=paths), expected)
                        finally: context.close()

    def test_execroot_inventory_route_keeps_direct_canonical_and_controller_limits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base, parent, alias, canonical, expected = self.hop_fixture(temporary)
            role = assembly.INVENTORY_REPOS['browserInventory'] + '/inventory.json'
            with patch.object(workspace, '_ASSEMBLY_COORDS', (root,)), \
                    patch.object(workspace.payload, 'parent', side_effect=parent):
                context = workspace.AssemblyContext(base, time.monotonic() + 30)
                try:
                    execroot_inventory = base / 'execroot/_main/external' / role
                    self.assertEqual(assembly.declared_alias_paths(expected, expected, role,
                        selected_base=base, _assembly_context=context), (expected, expected))
                    self.assertEqual(assembly.declared_alias_paths(canonical, expected, role,
                        selected_base=base, _assembly_context=context), (canonical, execroot_inventory, expected))
                    with patch.object(workspace.os, 'lstat') as inspected, self.assertRaises(ValueError):
                        assembly.declared_inventory(execroot_inventory, 'browserInventory',
                            selected_base=base, _assembly_context=context)
                    inspected.assert_not_called()
                    controller_alias = canonical.parent.parent / '_main/tools/source.py'
                    destination = assembly.CONTROLLER / 'source.py'
                    self.assertEqual(assembly.declared_alias_paths(controller_alias, destination,
                        '_main/tools/source.py', selected_base=base, _assembly_context=context),
                        (controller_alias, destination))
                finally: context.close()

    def test_execroot_inventory_route_rejects_foreign_epoch_root_role_and_private_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base, parent, alias, canonical, expected = self.hop_fixture(temporary)
            repository = assembly.INVENTORY_REPOS['browserInventory']
            execroot_inventory = base / 'execroot/_main/external' / repository / 'inventory.json'
            sandbox_runfiles = alias.parent.parent
            sandbox_runfiles.unlink(); sandbox_runfiles.mkdir(mode=0o755)
            alias.parent.mkdir(mode=0o755)
            other_epoch = root / 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
            other_root = root.parent / 'other-root'
            other_repo = base / 'execroot/_main/external/+undeclared-repository'
            wrong_known_repo = base / 'execroot/_main/external' / assembly.INVENTORY_REPOS['controllerInventory']
            invalid = ((other_epoch / 'output-base/execroot/_main/external' / repository / 'inventory.json', other_epoch),
                (other_root / base.parent.name / 'output-base/execroot/_main/external' / repository / 'inventory.json', other_root),
                (execroot_inventory.with_name('unowned.json'), execroot_inventory.with_name('unowned.json')),
                (other_repo / 'inventory.json', other_repo), (wrong_known_repo / 'inventory.json', wrong_known_repo),
                (Path('/home/private/inventory-canary'), Path('/home/private')))
            with patch.object(workspace, '_ASSEMBLY_COORDS', (root,)), \
                    patch.object(workspace.payload, 'parent', side_effect=parent):
                context = workspace.AssemblyContext(base, time.monotonic() + 30)
                try:
                    for target, forbidden in invalid:
                        if alias.is_symlink(): alias.unlink()
                        alias.symlink_to(target)
                        diagnostic = assembly._AssemblyDiagnostic()
                        with patch.object(workspace.os, 'lstat', wraps=os.lstat) as inspected, self.assertRaises(ValueError):
                            assembly.declared_inventory(alias, 'browserInventory', selected_base=base,
                                _assembly_context=context, _diagnostic=diagnostic)
                        self.assertEqual(diagnostic.operation, 'namespace-fence')
                        self.assertFalse(any(Path(call.args[0]) == forbidden or Path(call.args[0]).is_relative_to(forbidden)
                            for call in inspected.call_args_list))
                        self.assertNotIn(str(target), diagnostic.refusal().decode())
                finally: context.close()

    def test_changed_execroot_repository_alias_refuses_before_foreign_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base, parent, alias, canonical, expected = self.hop_fixture(temporary)
            repository = assembly.INVENTORY_REPOS['browserInventory']
            repository_alias = base / 'execroot/_main/external' / repository
            repository_alias.parent.mkdir(parents=True, mode=0o755)
            repository_alias.symlink_to(expected.parent, target_is_directory=True)
            canonical.unlink(); canonical.symlink_to(repository_alias / 'inventory.json')
            with patch.object(workspace, '_ASSEMBLY_COORDS', (root,)), \
                    patch.object(workspace.payload, 'parent', side_effect=parent):
                context = workspace.AssemblyContext(base, time.monotonic() + 30)
                try:
                    self.assertEqual(assembly.declared_inventory(alias, 'browserInventory',
                        selected_base=base, _assembly_context=context), expected)
                    other_epoch = root / 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
                    for target, forbidden in ((base / 'external/+undeclared-repository', base / 'external/+undeclared-repository'),
                            (other_epoch / 'output-base/external' / repository, other_epoch),
                            (Path('/home/private/metadata-canary'), Path('/home/private'))):
                        repository_alias.unlink(); repository_alias.symlink_to(target, target_is_directory=True)
                        with patch.object(workspace.os, 'lstat', wraps=os.lstat) as inspected, self.assertRaises(ValueError):
                            assembly.declared_inventory(alias, 'browserInventory', selected_base=base,
                                _assembly_context=context)
                        self.assertFalse(any(Path(call.args[0]) == forbidden or Path(call.args[0]).is_relative_to(forbidden)
                            for call in inspected.call_args_list))
                finally: context.close()

    def test_context_precheck_and_postcheck_are_distinct_from_resolver(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base, parent, alias, canonical, expected = self.hop_fixture(temporary)
            with patch.object(workspace, '_ASSEMBLY_COORDS', (root,)), \
                    patch.object(workspace.payload, 'parent', side_effect=parent):
                context = workspace.AssemblyContext(base, time.monotonic() + 30)
                try:
                    diagnostic = assembly._AssemblyDiagnostic()
                    with patch.object(context, 'recheck', side_effect=ValueError('private-canary')), \
                            patch.object(workspace, 'safe_resolve') as resolver, self.assertRaises(ValueError):
                        assembly.declared_inventory(alias, 'browserInventory', selected_base=base,
                            _assembly_context=context, _diagnostic=diagnostic)
                    resolver.assert_not_called()
                    before = json.loads(diagnostic.refusal())
                    self.assertEqual(before['phase'], 'browser-inventory-alias-context-precheck')
                    self.assertEqual(before['operation'], 'stage')
                    self.assertEqual(before['declaredNamespace']['candidateClass'], 'unobserved')
                    self.assertEqual(before['declaredNamespace']['aliasLayout'], 'processwrapper-sandbox')
                    diagnostic = assembly._AssemblyDiagnostic()
                    with patch.object(context, 'recheck', side_effect=[None, ValueError('private-canary')]), \
                            self.assertRaises(ValueError):
                        assembly.declared_inventory(alias, 'browserInventory', selected_base=base,
                            _assembly_context=context, _diagnostic=diagnostic)
                    after = json.loads(diagnostic.refusal())
                    self.assertEqual(after['phase'], 'browser-inventory-alias-context-postcheck')
                    self.assertEqual(after['operation'], 'stage')
                    self.assertEqual(after['declaredNamespace']['candidateClass'], 'declared-leaf')
                    self.assertNotIn('canary', diagnostic.refusal().decode())
                finally: context.close()

    def test_resolver_fence_witness_does_not_read_or_disclose_private_hop(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base, parent, alias, canonical, expected = self.hop_fixture(temporary)
            canonical.unlink(); canonical.symlink_to('/home/private/secret-canary')
            with patch.object(workspace, '_ASSEMBLY_COORDS', (root,)), \
                    patch.object(workspace.payload, 'parent', side_effect=parent):
                context = workspace.AssemblyContext(base, time.monotonic() + 30)
                diagnostic = assembly._AssemblyDiagnostic()
                try:
                    with patch.object(workspace.os, 'lstat', wraps=os.lstat) as inspected, self.assertRaises(ValueError):
                        assembly.declared_inventory(alias, 'browserInventory', selected_base=base,
                            _assembly_context=context, _diagnostic=diagnostic)
                    value = json.loads(diagnostic.refusal())
                    self.assertEqual(value['phase'], 'browser-inventory-alias-resolution')
                    self.assertEqual(value['operation'], 'namespace-fence')
                    self.assertEqual(value['declaredNamespace'], {'aliasLayout': 'processwrapper-sandbox',
                        'candidateClass': 'outside', 'linkForm': 'absolute', 'symbolicHops': 2})
                    self.assertFalse(any(str(call.args[0]).startswith('/home/private') for call in inspected.call_args_list))
                    self.assertNotIn('secret-canary', diagnostic.refusal().decode())
                    self.assertNotIn(str(base), diagnostic.refusal().decode())
                finally: context.close()

    def test_relative_parent_hops_preserve_resolution_and_refuse_undeclared_detour(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base, parent, alias, canonical, expected = self.hop_fixture(temporary)
            relative = os.path.relpath(expected, canonical.parent)
            canonical.unlink(); canonical.symlink_to(relative)
            paths = (alias, canonical, expected)
            diagnostic = assembly._AssemblyDiagnostic()
            with patch.object(workspace.os, 'lstat', wraps=os.lstat) as plain_inspected:
                plain = workspace.safe_resolve(alias, frozenset(), declared_paths=paths)
            plain_calls = plain_inspected.call_args_list
            with patch.object(workspace.os, 'lstat', wraps=os.lstat) as inspected:
                traced = workspace.safe_resolve(alias, frozenset(), declared_paths=paths, _trace=diagnostic.resolver)
            self.assertEqual(plain, expected); self.assertEqual(traced, plain)
            self.assertEqual(inspected.call_args_list, plain_calls)
            self.assertEqual(diagnostic.namespace['linkForm'], 'relative-parent')
            self.assertEqual(diagnostic.namespace['symbolicHops'], 2)
            self.assertEqual(diagnostic.operation, 'final-namespace-fence')
            self.assertEqual(diagnostic.namespace['candidateClass'], 'declared-leaf')
            canonical.unlink(); canonical.symlink_to('undeclared-canary/../' + relative)
            diagnostic = assembly._AssemblyDiagnostic()
            with patch.object(workspace.os, 'lstat', wraps=os.lstat) as inspected, self.assertRaises(ValueError):
                workspace.safe_resolve(alias, frozenset(), declared_paths=paths, _trace=diagnostic.resolver)
            self.assertEqual(diagnostic.operation, 'namespace-fence')
            self.assertEqual(diagnostic.namespace['candidateClass'], 'outside')
            self.assertFalse(any('undeclared-canary' in str(call.args[0]) for call in inspected.call_args_list))
            self.assertNotIn('undeclared-canary', diagnostic.refusal().decode())

    def test_lstat_error_operation_is_redacted_and_adds_no_probe(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base, parent, alias, canonical, expected = self.hop_fixture(temporary)
            diagnostic = assembly._AssemblyDiagnostic()
            original_lstat = os.lstat
            def inspect_once(path):
                if Path(path) == canonical: raise PermissionError('private-canary')
                return original_lstat(path)
            with patch.object(workspace.os, 'lstat', side_effect=inspect_once) as inspected, self.assertRaises(PermissionError):
                workspace.safe_resolve(canonical, frozenset(), declared_paths=(canonical, expected), _trace=diagnostic.resolver)
            self.assertEqual(diagnostic.operation, 'lstat')
            self.assertEqual(diagnostic.namespace['candidateClass'], 'declared-leaf')
            self.assertEqual(sum(Path(call.args[0]) == canonical for call in inspected.call_args_list), 1)
            self.assertNotIn('canary', diagnostic.refusal().decode())

    def test_resolution_witness_categories_and_hops_are_closed(self):
        diagnostic = assembly._AssemblyDiagnostic()
        for operation, category, form, hops in (('/private', 'outside', 'absolute', 1),
                ('lstat', '/private', 'absolute', 1), ('lstat', 'outside', '/private', 1),
                ('lstat', 'outside', 'absolute', True), ('lstat', 'outside', 'absolute', 66)):
            with self.assertRaises(ValueError): diagnostic.resolver(operation, category, form, hops)
            self.assertEqual(diagnostic.operation, 'stage')
        with self.assertRaises(ValueError): diagnostic.alias('/private')
        value = json.loads(diagnostic.refusal())
        self.assertEqual(value['diagnosticMeaning'], 'last-entered-operation')
        self.assertEqual(value['declaredNamespace']['aliasLayout'], 'unobserved')
        self.assertFalse(value['executionAuthority']); self.assertFalse(value['toolbarConsentProved'])

    def hop_fixture(self, temporary, runner='processwrapper-sandbox', identifier='7'):
        root, base, parent = self.context_fixture(temporary)
        repository = assembly.INVENTORY_REPOS['browserInventory']
        expected = base / 'external' / repository / 'inventory.json'
        expected.parent.mkdir(parents=True, mode=0o755)
        expected.write_bytes(b'{"public":true}\n'); expected.chmod(0o644)
        relative = Path('execroot/_main/bazel-out/k8-fastbuild/bin/delivery/yoga_installed_selection.sh.runfiles')
        canonical = base / relative / repository / 'inventory.json'
        canonical.parent.mkdir(parents=True, mode=0o755)
        canonical.symlink_to(expected)
        sandbox_tree = base / 'sandbox' / runner / identifier / relative
        sandbox_tree.parent.mkdir(parents=True, mode=0o755)
        sandbox_tree.symlink_to(base / relative, target_is_directory=True)
        alias = sandbox_tree / repository / 'inventory.json'
        return root, base, parent, alias, canonical, expected

    def test_actual_sandbox_to_canonical_leaf_old_refusal_and_corrected_success(self):
        for runner, identifier in (('linux-sandbox', '0'), ('processwrapper-sandbox', '17')):
            with self.subTest(runner=runner), tempfile.TemporaryDirectory() as temporary:
                root, base, parent, alias, canonical, expected = self.hop_fixture(temporary, runner, identifier)
                with patch.object(workspace, '_ASSEMBLY_COORDS', (root,)), \
                        patch.object(workspace.payload, 'parent', side_effect=parent):
                    context = workspace.AssemblyContext(base, time.monotonic() + 30)
                    try:
                        # The existing shared resolver remains strict: the
                        # undeclared intermediate canonical tree still refuses.
                        with self.assertRaises(ValueError):
                            workspace.safe_resolve(alias, frozenset(), declared_paths=(alias, expected))
                        self.assertEqual(assembly.declared_alias_paths(alias, expected,
                            assembly.INVENTORY_REPOS['browserInventory'] + '/inventory.json',
                            selected_base=base, _assembly_context=context), (alias, canonical,
                                base / 'execroot/_main/external' / assembly.INVENTORY_REPOS['browserInventory'] / 'inventory.json', expected))
                        self.assertEqual(assembly.declared_inventory(alias, 'browserInventory',
                            selected_base=base, _assembly_context=context), expected)
                        # The exact tuple must survive publication-time rechecks.
                        paths = assembly.declared_alias_paths(alias, expected,
                            assembly.INVENTORY_REPOS['browserInventory'] + '/inventory.json',
                            selected_base=base, _assembly_context=context)
                        self.assertEqual(workspace.safe_resolve(alias, frozenset(), declared_paths=paths), expected)
                    finally: context.close()

    def test_sandbox_alternative_requires_live_exact_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base, parent, alias, canonical, expected = self.hop_fixture(temporary)
            with patch.object(workspace, '_ASSEMBLY_COORDS', (root,)), \
                    patch.object(workspace.payload, 'parent', side_effect=parent):
                with patch.object(workspace.os, 'lstat') as inspected, self.assertRaises(ValueError):
                    assembly.declared_inventory(alias, 'browserInventory', selected_base=base)
                inspected.assert_not_called()
                context = workspace.AssemblyContext(base, time.monotonic() + 30)
                context.close()
                with patch.object(workspace.os, 'lstat') as inspected, self.assertRaises(ValueError):
                    assembly.declared_inventory(alias, 'browserInventory', selected_base=base, _assembly_context=context)
                inspected.assert_not_called()

    def test_foreign_root_epoch_target_and_sandbox_shapes_refuse_before_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base, parent, alias, canonical, expected = self.hop_fixture(temporary)
            role = assembly.INVENTORY_REPOS['browserInventory'] + '/inventory.json'
            suffix = 'execroot/_main/bazel-out/k8-fastbuild/bin/delivery/yoga_installed_selection.sh.runfiles/' + role
            invalid = [Path('/home/private') / suffix,
                root.parent / 'other-root' / base.parent.name / 'output-base' / suffix,
                root / 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' / 'output-base' / suffix,
                base / suffix.replace('yoga_installed_selection.sh.runfiles', 'other.sh.runfiles'),
                base / ('sandbox/foreign-sandbox/7/' + suffix),
                base / ('sandbox/linux-sandbox/01/' + suffix),
                base / ('sandbox/linux-sandbox/1234567890/' + suffix),
                base / ('sandbox/linux-sandbox/7/sandbox/processwrapper-sandbox/8/' + suffix)]
            with patch.object(workspace, '_ASSEMBLY_COORDS', (root,)), \
                    patch.object(workspace.payload, 'parent', side_effect=parent):
                context = workspace.AssemblyContext(base, time.monotonic() + 30)
                try:
                    for selected in invalid:
                        with self.subTest(alias=selected), patch.object(workspace.os, 'lstat') as inspected, \
                                patch.object(context, 'recheck') as checked, self.assertRaises(ValueError):
                            assembly.declared_inventory(selected, 'browserInventory', selected_base=base,
                                _assembly_context=context)
                        inspected.assert_not_called(); checked.assert_not_called()
                finally: context.close()

    def test_private_and_undeclared_hops_refuse_before_outside_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base, parent, alias, canonical, expected = self.hop_fixture(temporary)
            with patch.object(workspace, '_ASSEMBLY_COORDS', (root,)), \
                    patch.object(workspace.payload, 'parent', side_effect=parent):
                context = workspace.AssemblyContext(base, time.monotonic() + 30)
                try:
                    for outside in (Path('/home/private/inventory.json'), base / 'undeclared-hop/inventory.json'):
                        canonical.unlink(); canonical.symlink_to(outside)
                        diagnostic = assembly._AssemblyDiagnostic()
                        with patch.object(workspace.os, 'lstat', wraps=os.lstat) as inspected, self.assertRaises(ValueError):
                            assembly.declared_inventory(alias, 'browserInventory', selected_base=base,
                                _assembly_context=context, _diagnostic=diagnostic)
                        self.assertEqual(diagnostic.phase, 'browser-inventory-alias-resolution')
                        self.assertFalse(any(Path(call.args[0]) == outside or Path(call.args[0]).is_relative_to(outside.parent)
                            for call in inspected.call_args_list))
                        self.assertNotIn(str(outside), diagnostic.refusal().decode())
                finally: context.close()

    def test_exact_final_endpoint_stays_required_after_resolution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base, parent, alias, canonical, expected = self.hop_fixture(temporary)
            diagnostic = assembly._AssemblyDiagnostic()
            with patch.object(workspace, '_ASSEMBLY_COORDS', (root,)), \
                    patch.object(workspace.payload, 'parent', side_effect=parent):
                context = workspace.AssemblyContext(base, time.monotonic() + 30)
                try:
                    with patch.object(workspace, 'safe_resolve', return_value=expected.with_name('other.json')), \
                            self.assertRaises(ValueError):
                        assembly.declared_inventory(alias, 'browserInventory', selected_base=base,
                            _assembly_context=context, _diagnostic=diagnostic)
                    self.assertEqual(diagnostic.phase, 'browser-inventory-alias-endpoint')
                finally: context.close()

    def test_controller_and_eager_support_keep_only_their_exact_canonical_leaf(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base, parent, alias, canonical, expected = self.hop_fixture(temporary)
            runfiles = canonical.parent.parent
            sandbox_runfiles = alias.parent.parent
            tools = root / 'public-tools'; delivery = root / 'public-delivery'
            tools.mkdir(mode=0o700); delivery.mkdir(mode=0o700)
            source = tools / 'source.py'; source.write_bytes(b'# public fixture\n')
            support_file = delivery / 'codex_device_acquisition_component.py'; support_file.write_bytes(b'# public fixture\n')
            with patch.object(workspace, '_ASSEMBLY_COORDS', (root,)), \
                    patch.object(workspace.payload, 'parent', side_effect=parent), \
                    patch.object(assembly, 'CONTROLLER', tools), patch.object(assembly.support, 'DELIVERY', delivery):
                context = workspace.AssemblyContext(base, time.monotonic() + 30)
                try:
                    for role, destination in (('_main/tools/source.py', source),
                            ('_main/delivery/codex_device_acquisition_component.py', support_file)):
                        direct = runfiles / role; direct.parent.mkdir(parents=True, mode=0o755)
                        direct.symlink_to(destination)
                        selected = sandbox_runfiles / role
                        paths = assembly.declared_alias_paths(selected, destination, role,
                            selected_base=base, _assembly_context=context)
                        self.assertEqual(paths, (selected, direct, destination))
                        self.assertEqual(workspace.safe_resolve(selected, frozenset(), declared_paths=paths), destination)
                    self.assertEqual(assembly.declared_controller(sandbox_runfiles / '_main/tools/source.py',
                        'source.py', selected_base=base, _assembly_context=context), source)
                finally: context.close()

    def test_bound_output_base_supports_only_two_existing_roots_and_fresh_uuid(self):
        epoch = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        for root in workspace._ASSEMBLY_COORDS:
            base = root / epoch / 'output-base'
            self.assertEqual(workspace.assembly_base(base), base)
            for suffix in ('execroot/_main/test.runfiles/_main/tools/source.py',
                    'sandbox/processwrapper-sandbox/7/execroot/_main/bazel-out/k8-fastbuild/testlogs/delivery/yoga_installed_selection/test.outputs'):
                path = base / suffix
                self.assertEqual(workspace.assembly_base(path, child=True), base)
                self.assertEqual(assembly.output_base(path, selected_base=base), base)

    def test_arbitrary_nearby_private_and_cache_roots_refuse_before_metadata(self):
        epoch = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        invalid = [Path('/home/private') / epoch / 'output-base']
        for root in workspace._ASSEMBLY_COORDS:
            invalid += [Path(str(root) + '-other') / epoch / 'output-base',
                root / ('cache-v2-' + 'a' * 64) / 'output-base',
                root / 'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA' / 'output-base',
                root / epoch / 'output-base' / 'foreign']
        for path in invalid:
            with self.subTest(path=path), patch.object(workspace.os, 'open') as opened, \
                    patch.object(workspace.os, 'lstat') as inspected, self.assertRaises(ValueError):
                workspace.AssemblyContext(path, time.monotonic() + 30)
            opened.assert_not_called(); inspected.assert_not_called()

    def test_cross_epoch_and_cross_root_aliases_refuse_before_resolution(self):
        selected = workspace._ASSEMBLY_COORDS[0] / 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' / 'output-base'
        foreign = [workspace._ASSEMBLY_COORDS[1] / selected.parent.name / 'output-base',
            workspace._ASSEMBLY_COORDS[0] / 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' / 'output-base']
        suffix = 'execroot/_main/test.runfiles/'
        for base in foreign:
            with patch.object(workspace, 'safe_resolve') as resolved:
                with self.assertRaises(ValueError):
                    assembly.declared_inventory(base / suffix / assembly.INVENTORY_REPOS['browserInventory'] / 'inventory.json',
                        'browserInventory', selected_base=selected)
                with self.assertRaises(ValueError):
                    assembly.declared_controller(base / suffix / '_main/tools/source.py', 'source.py', selected_base=selected)
                with self.assertRaises(ValueError):
                    assembly.support.declared(base / suffix / '_main/delivery/codex_device_acquisition_component.py',
                        lambda path: assembly.output_base(path, selected_base=selected))
                with self.assertRaises(ValueError):
                    assembly.output_parent(base / 'execroot/_main/bazel-out/k8-fastbuild/testlogs/delivery/yoga_installed_selection/test.outputs',
                        selected_base=selected)
                resolved.assert_not_called()

    def test_home_inventory_without_held_context_retains_historical_refusal(self):
        base = workspace._ASSEMBLY_COORDS[1] / 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' / 'output-base'
        path = base / 'external' / assembly.INVENTORY_REPOS['browserInventory'] / 'inventory.json'
        with patch.object(workspace.os, 'open') as opened, self.assertRaises(ValueError):
            workspace.PhysicalCapture(path, workspace.INVENTORY_SHA['browserInventory'], 1024,
                time.monotonic() + 30, declared_inventory='browserInventory')
        opened.assert_not_called()

    def context_fixture(self, temporary):
        root = Path(temporary) / 'execution-root'; root.mkdir(mode=0o700)
        epoch = root / 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'; epoch.mkdir(mode=0o700)
        base = epoch / 'output-base'; base.mkdir(mode=0o755)
        def parent(path):
            # Fixture-only sticky /tmp allowance; production uses the actual
            # strict no-follow walker through every ancestor.
            directory = Path(path).parent
            self.assertTrue(directory == root or directory.is_relative_to(root))
            return os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        return root, base, parent

    def test_actual_context_holds_owner_private_modes_and_directory_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base, parent = self.context_fixture(temporary)
            with patch.object(workspace, '_ASSEMBLY_COORDS', (root,)), \
                    patch.object(workspace.payload, 'parent', side_effect=parent):
                context = workspace.AssemblyContext(base, time.monotonic() + 30)
                try:
                    context.recheck()
                    root.chmod(0o755)
                    with self.assertRaises(ValueError): context.recheck()
                    root.chmod(0o700)
                    base.rename(base.with_name('held-original'))
                    base.mkdir(mode=0o755)
                    with self.assertRaises(ValueError): context.recheck()
                finally: context.close()

    def test_actual_context_refuses_foreign_owner_and_unprivate_epoch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base, parent = self.context_fixture(temporary)
            uid = os.getuid()
            with patch.object(workspace, '_ASSEMBLY_COORDS', (root,)), \
                    patch.object(workspace.payload, 'parent', side_effect=parent):
                with patch.object(workspace.os, 'getuid', return_value=uid + 1), self.assertRaises(ValueError):
                    workspace.AssemblyContext(base, time.monotonic() + 30)
                base.parent.chmod(0o755)
                with self.assertRaises(ValueError): workspace.AssemblyContext(base, time.monotonic() + 30)

    def test_bound_capture_rejects_other_epoch_before_open(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base, parent = self.context_fixture(temporary)
            with patch.object(workspace, '_ASSEMBLY_COORDS', (root,)), \
                    patch.object(workspace.payload, 'parent', side_effect=parent):
                context = workspace.AssemblyContext(base, time.monotonic() + 30)
                try:
                    other = root / 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' / 'output-base'
                    path = other / 'external' / assembly.INVENTORY_REPOS['browserInventory'] / 'inventory.json'
                    with patch.object(workspace.os, 'open') as opened, self.assertRaises(ValueError):
                        workspace.PhysicalCapture(path, workspace.INVENTORY_SHA['browserInventory'], 1024,
                            time.monotonic() + 30, declared_inventory='browserInventory', _assembly_context=context)
                    opened.assert_not_called()
                finally: context.close()

    def test_bound_capture_reads_actual_pinned_file_and_rechecks_changed_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, base, parent = self.context_fixture(temporary)
            directory = base / 'external' / assembly.INVENTORY_REPOS['browserInventory']
            directory.mkdir(parents=True, mode=0o700)
            path = directory / 'inventory.json'; content = b'{"public":true}\n'
            path.write_bytes(content); path.chmod(0o600)
            digest = hashlib.sha256(content).hexdigest()
            with patch.object(workspace, '_ASSEMBLY_COORDS', (root,)), \
                    patch.object(workspace.payload, 'parent', side_effect=parent), \
                    patch.dict(workspace.INVENTORY_SHA, {'browserInventory': digest}):
                context = workspace.AssemblyContext(base, time.monotonic() + 30)
                try:
                    held = workspace.PhysicalCapture(path, digest, 1024, time.monotonic() + 30,
                        declared_inventory='browserInventory', _assembly_context=context)
                    try:
                        self.assertEqual(held.bytes(1024), content)
                        path.write_bytes(b'{"changed":true}\n')
                        with self.assertRaises(ValueError): held.check()
                    finally: held.close()
                finally: context.close()

    def test_refusal_phase_is_closed_and_has_no_execution_authority(self):
        diagnostic = assembly._AssemblyDiagnostic()
        for phase in assembly._PHASES:
            diagnostic.enter(phase)
            self.assertEqual(json.loads(diagnostic.refusal()), {'schemaVersion': 1,
                'scope': 'yoga-installed-selection-refusal-v1', 'phase': phase,
                'operation': 'stage', 'diagnosticMeaning': 'last-entered-operation',
                'declaredNamespace': {'aliasLayout': 'unobserved', 'candidateClass': 'unobserved',
                    'linkForm': 'unobserved', 'symbolicHops': 0},
                'executionAuthority': False, 'toolbarConsentProved': False,
                'browserInvoked': False, 'providerInvoked': False})
        diagnostic.enter('request')
        for invalid in ('/home/private/input', 'exception-canary', None, [], {}):
            with self.assertRaises(ValueError): diagnostic.enter(invalid)
            self.assertEqual(diagnostic.phase, 'request')

    def test_main_refusal_reports_phase_without_exception_or_input_text(self):
        def refuse(*args, **kwargs):
            kwargs['_diagnostic'].enter('controller-package')
            raise ValueError('exception-canary /home/private/input')
        argv = ['selector', '--browser-inventory', '/private/browser-canary',
            '--controller-inventory', '/private/controller-canary', '--controller-file',
            '/private/source-canary', '--controller-support-file', '/private/support-canary']
        stderr = io.StringIO()
        with patch.object(assembly.sys, 'argv', argv), \
                patch.dict(os.environ, {'OMUX_INSTALLED_SELECTION_DEADLINE_NS': '999999999999999',
                    'TEST_UNDECLARED_OUTPUTS_DIR': '/private/output-canary'}), \
                patch.object(assembly, 'assemble', side_effect=refuse) as selected, \
                redirect_stderr(stderr), self.assertRaises(SystemExit) as refused:
            assembly.main()
        self.assertEqual(refused.exception.code, 125)
        selected.assert_called_once()
        lines = stderr.getvalue().splitlines()
        self.assertEqual(lines[0], 'installed-toolbar-selection-assembly-refused')
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[1])['phase'], 'controller-package')
        self.assertNotIn('canary', stderr.getvalue())
        self.assertNotIn('/private/', stderr.getvalue())
        self.assertNotIn('/home/', stderr.getvalue())

    def test_bad_deadline_refusal_stays_before_assembly(self):
        argv = ['selector', '--browser-inventory', 'browser', '--controller-inventory',
            'controller', '--controller-file', 'source', '--controller-support-file', 'support']
        stderr = io.StringIO()
        with patch.object(assembly.sys, 'argv', argv), \
                patch.dict(os.environ, {'OMUX_INSTALLED_SELECTION_DEADLINE_NS': 'invalid'}), \
                patch.object(assembly, 'assemble') as selected, redirect_stderr(stderr), \
                self.assertRaises(SystemExit) as refused:
            assembly.main()
        self.assertEqual(refused.exception.code, 125)
        selected.assert_not_called()
        self.assertEqual(json.loads(stderr.getvalue().splitlines()[1])['phase'], 'request')

    def test_declared_inventory_only_uses_exact_public_repository_file(self):
        base = assembly.COORD / ('a' * 8 + '-aaaa-aaaa-aaaa-' + 'a' * 12) / 'output-base'
        for name, repository in assembly.INVENTORY_REPOS.items():
            alias = base / 'execroot/_main/test.runfiles' / repository / 'inventory.json'
            expected = base / 'external' / repository / 'inventory.json'
            with patch.object(workspace, 'safe_resolve', return_value=expected) as resolve:
                self.assertEqual(assembly.declared_inventory(alias, name), expected)
                resolve.assert_called_once_with(str(alias), frozenset(), declared_paths=(alias, expected))
            with patch.object(workspace, 'safe_resolve') as resolve, self.assertRaises(ValueError):
                assembly.declared_inventory('/home/private/inventory.json', name)
            resolve.assert_not_called()
            with patch.object(workspace, 'safe_resolve', return_value=Path('/home/private/file')):
                with self.assertRaises(ValueError): assembly.declared_inventory(alias, name)

    def test_measurement_reuses_actual_held_reader_and_none_stays_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); path = root / 'source.py'
            path.write_bytes(b'public source\n'); path.chmod(0o600)
            # Fixture exemption only: allow the test's canonical sticky /tmp
            # ancestor, while production keeps its full strict nofollow walk.
            def parent(selected):
                self.assertEqual(Path(selected).parent, root)
                return os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            until = time.monotonic() + 30
            with patch.object(workspace.payload, 'parent', side_effect=parent):
                with self.assertRaises(ValueError):
                    workspace.PhysicalCapture(path, None, 1024, until, controller_root=root)
                held = workspace.PhysicalCapture.measure(path, 1024, until, controller_root=root)
                try:
                    self.assertEqual(held.sha, hashlib.sha256(b'public source\n').hexdigest())
                    self.assertEqual(held.bytes(1024), b'public source\n')
                    path.write_bytes(b'changed public source\n')
                    with self.assertRaises(ValueError): held.check()
                finally: held.close()

    def test_declared_inventory_bad_pin_or_path_refuses_before_open(self):
        path = assembly.COORD / ('a' * 8 + '-aaaa-aaaa-aaaa-' + 'a' * 12) / 'output-base/external' / assembly.INVENTORY_REPOS['browserInventory'] / 'inventory.json'
        for selected, digest in ((path, '0' * 64), (Path('/home/private/inventory.json'), workspace.INVENTORY_SHA['browserInventory'])):
            with patch.object(workspace.os, 'open') as opened, self.assertRaises(ValueError):
                workspace.PhysicalCapture(selected, digest, 1024, time.monotonic() + 30, declared_inventory='browserInventory')
            opened.assert_not_called()

    def test_fixed_input_inventory_is_exact_and_artifact_pins_remain_independent(self):
        self.assertEqual(set(assembly.INPUT_KEYS), workspace.payload.INPUTS)
        self.assertEqual(set(assembly.INPUT_SHA), workspace.payload.INPUTS)
        for name, (digest, _) in workspace.ARTIFACTS.items(): self.assertEqual(assembly.INPUT_SHA[name], digest)
        self.assertEqual(assembly.INPUT_SHA['observer'], workspace.ORIGIN_SOURCE_SHA['delivery/yoga_toolbar_observer.mjs'])

    def test_publish_actual_three_files_and_no_adoption_or_extra_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            coord = Path(temporary)
            output = coord / ('a' * 8 + '-aaaa-aaaa-aaaa-' + 'a' * 12) / 'output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/delivery/yoga_installed_selection/test.outputs'
            output.mkdir(parents=True, mode=0o700)
            files = {'selection.json': b'{"synthetic":true}\n', 'browser-inventory.json': b'{"public":1}\n',
                     'controller-inventory.json': b'{"public":2}\n'}
            def parent(selected):
                self.assertEqual(Path(selected).parent, output)
                return os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            with patch.object(assembly, 'COORD', coord), patch.object(workspace.payload, 'parent', side_effect=parent):
                root = assembly.publish(output, files, time.monotonic() + 30)
                self.assertEqual(set(os.listdir(root)), set(files))
                for name, content in files.items():
                    self.assertEqual((root / name).read_bytes(), content)
                    self.assertEqual((root / name).stat().st_mode & 0o777, 0o600)
                with self.assertRaises(FileExistsError): assembly.publish(output, files, time.monotonic() + 30)
                with self.assertRaises(ValueError): assembly.publish(output, dict(files, foreign=b'public'), time.monotonic() + 30)

    def test_historical_bootstrap_substitution_cannot_be_blessed_by_measured_map(self):
        for key, expected in assembly.BOOTSTRAP_SHA.items():
            physical = Path(assembly.BOOTSTRAP_PATH[key])
            assembly.historical_pin(key, physical, expected)
            # A rewritten fileSha256 agreeing with substituted public bytes
            # still cannot change the independent historical executable pin.
            changed = hashlib.sha256(b'self-consistent substituted bootstrap').hexdigest()
            rewritten = {key: changed}
            with self.subTest(key=key), self.assertRaises(ValueError):
                assembly.historical_pin(key, physical, rewritten[key])
            with self.assertRaises(ValueError):
                assembly.historical_pin(key, physical.parent / 'foreign', expected)

    def test_full_output_namespace_accepts_real_execroot_shapes_and_refuses_before_open(self):
        base = assembly.COORD / ('a' * 8 + '-aaaa-aaaa-aaaa-' + 'a' * 12) / 'output-base'
        suffix = 'execroot/_main/bazel-out/k8-fastbuild/testlogs/delivery/yoga_installed_selection/test.outputs'
        for prefix in ('', 'sandbox/linux-sandbox/0/', 'sandbox/linux-sandbox/17/', 'sandbox/processwrapper-sandbox/7/'):
            selected = base / (prefix + suffix)
            self.assertEqual(assembly.output_parent(selected), selected)
        for suffix in ('foreign/delivery/yoga_installed_selection/test.outputs',
                       'execroot/_main/bazel-out/k8-fastbuild/bin/delivery/yoga_installed_selection/test.outputs',
                       'sandbox/linux-sandbox/01/execroot/_main/bazel-out/k8-fastbuild/testlogs/delivery/yoga_installed_selection/test.outputs',
                       'execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/yoga_installed_selection/test.outputs'):
            with patch.object(workspace.payload, 'parent') as opened, self.assertRaises(ValueError):
                assembly.publish(base / suffix, {'selection.json': b'1', 'browser-inventory.json': b'2',
                                                 'controller-inventory.json': b'3'}, time.monotonic() + 30)
            opened.assert_not_called()

    def test_publication_refuses_canonical_parent_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            coord = Path(temporary)
            output = coord / ('a' * 8 + '-aaaa-aaaa-aaaa-' + 'a' * 12) / 'output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/delivery/yoga_installed_selection/test.outputs'
            output.mkdir(parents=True, mode=0o700)
            files = {'selection.json': b'1', 'browser-inventory.json': b'2', 'controller-inventory.json': b'3'}
            def parent(selected):
                self.assertEqual(Path(selected).parent, output)
                return os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            original = workspace.verify_output
            def replace_parent(*args):
                original(*args)
                output.rename(output.with_name('held-original'))
                output.mkdir(mode=0o700)
            with patch.object(assembly, 'COORD', coord), patch.object(workspace.payload, 'parent', side_effect=parent), \
                    patch.object(workspace, 'verify_output', side_effect=replace_parent):
                with self.assertRaises(ValueError):
                    assembly.publish(output, files, time.monotonic() + 30)
            self.assertEqual(list(output.iterdir()), [])
            self.assertEqual(set(os.listdir(output.with_name('held-original') / 'installed-toolbar-selection')), set(files))

    def test_shared_resolver_refuses_private_extra_hop_before_metadata(self):
        alias = str(assembly.COORD / ('a' * 8 + '-aaaa-aaaa-aaaa-' + 'a' * 12) / 'output-base/external/public/inventory.json')
        with patch.object(workspace.os, 'lstat') as observed, self.assertRaises(ValueError):
            workspace.safe_resolve('/home/private/file', frozenset(), declared_paths=(Path(alias),))
        observed.assert_not_called()


if __name__ == '__main__': unittest.main()
