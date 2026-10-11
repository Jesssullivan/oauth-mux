"""Actual macro/import closure models; no selected inputs or project imports.

Evaluate declaration functions with finite depset/target collectors. Walk
declared Python syntax without importing or running those modules. These
models prove syntactic graph non-regression, including explicitly classified
existing deferred imports; they do not prove function-call reachability,
configured-node counts or producer performance.
"""
import ast
import copy
import os
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest


class DeclaredSet:
    def __init__(self, values):
        self.values = list(dict.fromkeys(values))

    def to_list(self):
        return self.values[:]


# Existing unresolved imports are bound to exact module/function sites. They
# belong to coordinator request/command/cleanup, installation witness validation
# or registration collection. No unknown module or newly moved eager import is
# accepted by this classification.
DEFERRED_IMPORTS = {
    ('guard_native_seed_plan_reserved', 'request', 'guard_resident_enrollment_profile'),
    ('guard_native_seed_plan_reserved', 'command', 'guard_resident_enrollment_profile'),
    ('guard_native_seed_plan_reserved', 'cleanup_retained', 'execution_guard'),
    ('codex_query_registration', 'collect', 'cached_nix_inventory'),
    ('guard_query_registration_reserved', 'request', 'guard_resident_enrollment_profile'),
    ('guard_query_registration_reserved', 'command', 'guard_resident_enrollment_profile'),
    ('guard_resident_native_source_acquisition_source_reserved', 'request', 'guard_resident_enrollment_profile'),
    ('guard_resident_native_source_acquisition_source_reserved', 'command', 'guard_resident_enrollment_profile'),
    ('guard_native_acquisition_inputs_reserved', 'request', 'guard_resident_enrollment_profile'),
    ('guard_native_acquisition_inputs_reserved', 'command', 'guard_resident_enrollment_profile'),
    ('guard_native_acquisition_inputs_reserved', 'command', 'execution_guard'),
    ('guard_resident_owner_status_persistence_source_reserved', 'request', 'guard_resident_enrollment_profile'),
    ('guard_resident_owner_status_persistence_source_reserved', 'command', 'guard_resident_enrollment_profile'),
    ('guard_native_metadata_sdk_reserved', 'request', 'guard_resident_enrollment_profile'),
    ('guard_native_metadata_sdk_reserved', 'command', 'guard_resident_enrollment_profile'),
    ('guard_resident_observation', 'InstallationWitness.__init__', 'pack'),
}


class ImportSites(ast.NodeVisitor):
    def __init__(self):
        self.scope = []
        self.sites = []

    def definition(self, node):
        self.scope.append(node.name)
        self.generic_visit(node)
        self.scope.pop()

    visit_FunctionDef = definition
    visit_AsyncFunctionDef = definition
    visit_ClassDef = definition

    def visit_Import(self, node):
        self.sites += [('.'.join(self.scope), alias.name.split('.')[0], 0)
            for alias in node.names]

    def visit_ImportFrom(self, node):
        self.sites.append(('.'.join(self.scope), (node.module or '').split('.')[0], node.level))


def functions(path, names, environment):
    definitions = [node for node in ast.parse(path.read_text()).body
        if isinstance(node, ast.FunctionDef) and node.name in names]
    if {node.name for node in definitions} != set(names):
        raise AssertionError('missing actual declaration function')
    module = ast.Module(body=definitions, type_ignores=[])
    exec(compile(ast.fix_missing_locations(module), str(path), 'exec'), environment)
    return environment


class SourceClosure(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(os.environ['TEST_SRCDIR']) / '_main'
        tools = cls.root / 'tools'
        build = ast.parse((tools / 'BUILD.bazel').read_text())
        assignments = {node.targets[0].id: node.value for node in build.body
            if isinstance(node, ast.Assign) and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)}

        def value(node):
            if isinstance(node, ast.Constant):
                return node.value
            if isinstance(node, (ast.List, ast.Tuple)):
                return [value(item) for item in node.elts]
            if isinstance(node, ast.Name):
                return value(assignments[node.id])
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                return value(node.left) + value(node.right)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'depset':
                return DeclaredSet(value(node.args[0]))
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == 'to_list':
                return value(node.func.value).to_list()
            raise AssertionError('unreviewed declaration expression: ' + ast.dump(node))

        calls = [node.value for node in build.body if isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name)
            and node.value.func.id == 'native_acquisition_input_targets']
        if len(calls) != 1:
            raise AssertionError('expected the actual single native target declaration')
        cls.arguments = {kw.arg: value(kw.value) for kw in calls[0].keywords}
        cls.targets = {}

        def collect(**kwargs):
            if kwargs['name'] in cls.targets:
                raise AssertionError('duplicate target')
            cls.targets[kwargs['name']] = kwargs

        cls.environment = functions(tools / 'codex_native_acquisition_targets.bzl',
            ('native_acquisition_source_closure', 'native_acquisition_sources_for',
                'native_acquisition_input_targets'),
            {'depset': DeclaredSet, 'python_test': collect})
        cls.environment['native_acquisition_input_targets'](**cls.arguments)
        cls.shared = cls.environment['native_acquisition_source_closure'](
            cls.arguments['source_sources'], cls.arguments['sdk_sources'])
        cls.portable = staticmethod(functions(tools / 'rules.bzl', ('_portable_python_sources',),
            {'native': SimpleNamespace(package_name=lambda: 'tools')})['_portable_python_sources'])

    def source_graph(self, selected, overrides=None, *, entrypoint='codex_native_acquisition_metadata'):
        modules = {}
        for label in selected:
            path = self.root / (label[2:].replace(':', '/') if label.startswith('//') else 'tools/' + label)
            if path.suffix == '.py':
                self.assertNotIn(path.stem, modules, 'ambiguous declared Python module')
                modules[path.stem] = path
        remaining = [entrypoint]
        visited = set()
        edges, unresolved = set(), set()
        while remaining:
            name = remaining.pop()
            if name in visited:
                continue
            visited.add(name)
            syntax = (overrides or {}).get(name)
            if syntax is None:
                syntax = ast.parse(modules[name].read_text())
            imports = ImportSites()
            imports.visit(syntax)
            for scope, imported_name, level in imports.sites:
                self.assertEqual(level, 0, 'relative import needs explicit review')
                edge = (name, scope, imported_name)
                edges.add(edge)
                if imported_name in modules:
                    remaining.append(imported_name)
                elif imported_name not in sys.stdlib_module_names:
                    unresolved.add(edge)
                self.assertNotEqual(imported_name, 'importlib', 'dynamic loader needs review')
            self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == '__import__' for node in ast.walk(syntax)), 'dynamic import needs review')
        return visited, edges, unresolved

    def classified_graph(self, selected, overrides=None, *, entrypoint='codex_native_acquisition_metadata'):
        graph = self.source_graph(selected, overrides, entrypoint=entrypoint)
        self.assertEqual(graph[2], DEFERRED_IMPORTS,
            'new/removed/moved unresolved import requires independent source review')
        self.assertTrue(all(scope for _, scope, _ in graph[2]),
            'all eager imports must be declared or standard library')
        return graph

    def test_metadata_syntactic_import_graph_and_deferred_gaps_unchanged(self):
        baseline = self.classified_graph(self.shared)
        filtered = self.classified_graph(self.targets['codex_native_acquisition_metadata_producer']['srcs'])
        self.assertEqual(filtered, baseline)
        visited = filtered[0]
        for name in ('codex_native_acquisition_binding', 'codex_protocol_history_native',
                'native_flake_sources', 'nix_private_store_qualification'):
            self.assertIn(name, visited)
        self.assertNotIn('portable', visited)
        self.assertNotIn('codex_native_acquisition_bridge_material', visited)

    def test_sdk_syntactic_import_graph_from_actual_main_unchanged(self):
        target = self.targets['codex_native_acquisition_sdk_export_producer']
        entrypoint = Path(target['main']).stem
        self.assertEqual(entrypoint, 'codex_native_acquisition_sdk_export')
        baseline = self.classified_graph(self.shared, entrypoint=entrypoint)
        filtered = self.classified_graph(target['srcs'], entrypoint=entrypoint)
        self.assertEqual(filtered, baseline)
        for name in (entrypoint, 'codex_native_acquisition_metadata',
                'codex_native_acquisition_binding', 'codex_retained_sdk_export',
                'codex_protocol_history_query_tools', 'native_flake_sources',
                'nix_private_store_qualification'):
            self.assertIn(name, filtered[0])
        self.assertNotIn('portable', filtered[0])
        self.assertNotIn('codex_native_acquisition_bridge_material', filtered[0])

    def test_unclassified_or_eager_project_import_refused(self):
        original = ast.parse((self.root / 'tools/guard_native_seed_plan_reserved.py').read_text())
        eager = copy.deepcopy(original)
        eager.body.append(ast.Import(names=[ast.alias(name='guard_resident_enrollment_profile')]))
        changed = copy.deepcopy(original)
        request = next(node for node in changed.body
            if isinstance(node, ast.FunctionDef) and node.name == 'request')
        request.body.append(ast.Import(names=[ast.alias(name='unreviewed_project_dependency')]))
        for name in ('codex_native_acquisition_metadata_producer',
                'codex_native_acquisition_sdk_export_producer'):
            target = self.targets[name]
            for syntax in (eager, changed):
                with self.subTest(target=name, imports=ast.dump(syntax)[-120:]), self.assertRaises(AssertionError):
                    self.classified_graph(target['srcs'], {'guard_native_seed_plan_reserved': syntax},
                        entrypoint=Path(target['main']).stem)

    def test_metadata_only_loses_unused_launcher_branch(self):
        target = self.targets['codex_native_acquisition_metadata_producer']
        self.assertEqual(set(self.shared) - set(target['srcs']),
            {'//delivery:portable.py', 'codex_native_acquisition_bridge_material.py'})
        self.assertEqual(set(target['srcs']) - set(self.shared), set())
        self.assertNotIn('//delivery:portable_launcher_template', self.portable(dict(target))['srcs'])

    def test_sdk_only_loses_unused_launcher_branch_and_preserves_data(self):
        target = self.targets['codex_native_acquisition_sdk_export_producer']
        self.assertEqual(set(self.shared) - set(target['srcs']),
            {'//delivery:portable.py', 'codex_native_acquisition_bridge_material.py'})
        self.assertEqual(set(target['srcs']) - set(self.shared), set())
        self.assertNotIn('//delivery:portable_launcher_template', self.portable(dict(target))['srcs'])
        self.assertEqual(target['data'], self.targets['codex_native_acquisition_metadata_producer']['data'])
        self.assertTrue(set(self.arguments['parent_data'] + self.arguments['sdk_data']) <= set(target['data']))

    def test_other_pipeline_targets_retain_portable_and_shared_sources(self):
        for name, target in self.targets.items():
            if name in ('codex_native_acquisition_metadata_producer',
                    'codex_native_acquisition_sdk_export_producer', 'guard_native_acquisition_inputs_reserved_test'):
                continue
            with self.subTest(target=name):
                self.assertTrue(set(self.shared) <= set(target['srcs']))
                self.assertIn('//delivery:portable_launcher_template', self.portable(dict(target))['srcs'])
        runtime = self.targets['codex_native_acquisition_runtime_qualification_producer']
        self.assertIn('//:native_peer_runtime_bridge.so', runtime['data'])
        self.assertIn('//integrations/codex-upstream:native_acquisition_runtime_configuration', runtime['data'])

    def test_metadata_data_preserves_full_ancestry_sdk_and_selectors(self):
        target = self.targets['codex_native_acquisition_metadata_producer']
        self.assertEqual(target['data'], self.targets['codex_native_acquisition_sdk_export_producer']['data'])
        self.assertTrue(set(self.arguments['parent_data'] + self.arguments['sdk_data']) <= set(target['data']))
        for label in ('@omux_native_acquisition_metadata_inputs//:inputs',
                '@omux_owner_status_persistence_metadata_inputs//:inputs',
                '@omux_protocol_history_query_tools//:inputs',
                '@omux_codex_owner_status_persistence_binding_inputs//:inputs',
                '@omux_codex_native_source_context_refresh_inputs//:inputs',
                '//integrations/codex-upstream:native_acquisition_input_configuration',
                '//integrations/codex-upstream:native_acquisition_n9_binding'):
            self.assertIn(label, target['data'])


if __name__ == '__main__':
    unittest.main()
