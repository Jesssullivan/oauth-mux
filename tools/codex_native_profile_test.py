import hashlib
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import codex_native_candidate_cache as candidate_cache
import codex_native_profile as native
import codex_retained_sdk_export as sdk_export
from codex_retained_sdk_export import SCHEMA, canonical, digest, inventory, Budget, validate_export

class SourceMutationTests(unittest.TestCase):
    def test_locked_dispatcher_selection_overrides_ambient_without_source_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'sealed-source'
            source.mkdir(mode=0o700)
            version = source / '.bazelversion'
            version.write_bytes(b'9.0.0\n')
            version.chmod(0o444)
            run = root / 'run'
            run.mkdir(mode=0o700)
            args = SimpleNamespace(native_source_root=root/'input',
                native_export_root=root/'export', native_deadline=None,
                native_mode='analysis')
            retained = {'inventory_sha256':'1'*64}
            exported = {'registry_cache':str(args.native_export_root/'registry-cache'),
                'inventory_sha256':'2'*64,'mapping_sha256':'3'*64,
                'repositories':{},'module_overrides':{}}
            candidate = SimpleNamespace(source=source, root=root/'candidate',
                lease=SimpleNamespace(output_base=root/'output-base'))
            with patch.object(native, 'verify_inputs', return_value=(retained,exported)), \
                    patch.dict(os.environ, {'USE_BAZEL_VERSION':'9.0.0','BAZEL_REAL':'/foreign/bazel'}):
                plan = native.command(args,run,'/nix/store/locked-tool/bin',
                    '/nix/store/i27rhb3nr65rkrwz36bchkwmav6ggsmn-bash-5.3p9/bin/bash',candidate)
            self.assertEqual(plan['environment']['USE_BAZEL_VERSION'],'9.0.1')
            self.assertNotIn('BAZEL_REAL',plan['environment'])
            self.assertEqual(plan['argv'][0],native.BAZEL)
            self.assertIn('--repository_disable_download',plan['argv'])
            self.assertIn('--sandbox_default_allow_network=false',plan['argv'])
            self.assertEqual(version.read_bytes(),b'9.0.0\n')
            self.assertEqual(version.stat().st_mode & 0o777,0o444)

    def test_dispatcher_selection_is_explicit_candidate_provenance(self):
        self._check_dispatcher_selection_provenance()

    def test_registry_modules_preserve_identity_while_repo_bytes_remain_sealed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            run = root/'run'
            run.mkdir(mode=0o700)
            source = root/'sealed-source'
            source.mkdir(mode=0o700)
            selected_bytes = {'MODULE.bazel':b'bazel_dep(name="rules_rs",version="0.0.96")\n',
                'MODULE.bazel.lock':b'{"lockFileVersion":26,"moduleExtensions":{}}\n'}
            for name,value in selected_bytes.items():
                (source/name).write_bytes(value)
                (source/name).chmod(0o444)
            args = SimpleNamespace(native_source_root=root/'input',
                native_export_root=root/'export',native_deadline=None,native_mode='analysis')
            repos = {name:str(args.native_export_root/'repositories'/name) for name in
                ('aspect_tools_telemetry+','rules_rs+')}
            exported = {'registry_cache':str(args.native_export_root/'registry-cache'),
                'inventory_sha256':'2'*64,'mapping_sha256':'3'*64,'repositories':repos,
                'module_overrides':{'aspect_tools_telemetry':repos['aspect_tools_telemetry+'],
                    'rules_rs':repos['rules_rs+']}}
            candidate = SimpleNamespace(source=source,root=root/'candidate',
                lease=SimpleNamespace(output_base=root/'output-base'))
            with patch.object(native,'verify_inputs',return_value=({'inventory_sha256':'1'*64},exported)):
                plan = native.command(args,run,'/nix/store/locked-tool/bin',
                    '/nix/store/i27rhb3nr65rkrwz36bchkwmav6ggsmn-bash-5.3p9/bin/bash',candidate)
            self.assertEqual([arg for arg in plan['argv'] if arg.startswith('--override_repository=')],
                ['--override_repository='+name+'='+repos[name] for name in sorted(repos)])
            self.assertFalse(any(arg.startswith('--override_module=') for arg in plan['argv']))
            self.assertIn('--lockfile_mode=error',plan['argv'])
            self.assertIn('--repository_cache='+exported['registry_cache'],plan['argv'])
            self.assertIn('--repository_disable_download',plan['argv'])
            self.assertIn('--sandbox_default_allow_network=false',plan['argv'])
            self.assertIn('--repo_contents_cache=',plan['argv'])
            self.assertEqual(plan['mapping_sha256'],exported['mapping_sha256'])
            for name,value in selected_bytes.items():
                self.assertEqual((source/name).read_bytes(),value)
                self.assertEqual((source/name).stat().st_mode & 0o777,0o444)

    def _check_dispatcher_selection_provenance(self):
        args = SimpleNamespace(state_dir=candidate_cache.native.STATE,native_cache_attempt=1,
            native_source_root=Path('/public/source'),native_source_sha256='1'*64,
            native_patch_sha256=['2'*64,'3'*64,'4'*64],native_export_root=Path('/public/export'),
            native_export_sha256='5'*64)
        source = {'inventory_sha256':'6'*64,'graph_files':{}}
        export = {'inventory_sha256':'7'*64,'mapping_sha256':'8'*64}
        with patch.object(native,'verify_inputs',return_value=(source,export)):
            selected = candidate_cache.bindings(args,{'bazel':native.BAZEL},
                ('9'*64,[]),'/nix/store/locked-tool/bin','system')
            with patch.object(native,'BAZEL_VERSION','9.0.0'):
                changed = candidate_cache.bindings(args,{'bazel':native.BAZEL},
                    ('9'*64,[]),'/nix/store/locked-tool/bin','system')
        self.assertEqual(selected['bazel_dispatcher_environment'],{'USE_BAZEL_VERSION':'9.0.1'})
        self.assertEqual(selected['module_resolution_policy'],native.MODULE_RESOLUTION_POLICY)
        self.assertNotEqual(hashlib.sha256(candidate_cache.canonical(selected)).hexdigest(),
            hashlib.sha256(candidate_cache.canonical(changed)).hexdigest())

    def test_grouped_exact_gates_reject_equal_count_substitution_and_zero(self):
        for target, names in native.QUALIFICATION_GATES.items():
            def log(selected):
                return ('\n'.join('test ' + name + ' ... ok' for name in selected)
                    + '\ntest result: ok. %d passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n'
                    % len(selected)).encode()
            self.assertEqual(native.qualification_log(log(names), target), sorted(names))
            for bad in ((), names[:-1], (*names[:-1], 'unrelated::test'),
                        (*names, names[0])):
                with self.assertRaises(ValueError):
                    native.qualification_log(log(bad), target)
            with self.assertRaises(ValueError):
                native.qualification_log(log(names).replace(b' ... ok', b' ... ignored', 1), target)
    def test_zero_matching_tests_never_passes_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            run = Path(temp)
            (run / 'test-evidence').mkdir()
            target = run / 'test-evidence/log.evidence'
            for count in (0, 1, 8):
                value = ('test result: ok. %d passed; 0 failed; 0 ignored;\n' % count).encode()
                target.write_bytes(value)
                target.chmod(0o600)
                manifest = {'results': [{'files': [{'source': 'test.log', 'state': 'copied',
                    'file': 'log.evidence', 'sha256': hashlib.sha256(value).hexdigest()}]}]}
                if count < 8:
                    with self.assertRaises(ValueError):
                        native.meaningful_tests(run, manifest, 'core-text')
                else:
                    native.meaningful_tests(run, manifest, 'core-text')

    def test_full_byte_inventory_detects_changed_source(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / 'source'
            source.mkdir()
            rows = {}
            for name in native.GRAPH:
                target = source / name
                target.parent.mkdir(parents=True, exist_ok=True)
                value = (name + '\n').encode()
                target.write_bytes(value)
                target.chmod(0o555)
                rows[name] = {'mode': '100644', 'sha256': hashlib.sha256(value).hexdigest()}
            for folder, _, _ in os.walk(source, topdown=False):
                Path(folder).chmod(0o555)
            pins = ['1' * 64, '2' * 64, '3' * 64]
            receipt = {'schema_version': 1, 'status': 'verified-fresh-native-candidate',
                'commit': native.COMMIT, 'baseline_receipt_sha256': native.BASE_RECEIPT_SHA,
                'baseline_inventory_sha256': native.BASE_INVENTORY, 'patch_sha256': pins,
                'native_support': False, 'native_compile_passed': False, 'provider_evaluation': False,
                'source_inventory': rows, 'inventory_sha256': hashlib.sha256(json.dumps(rows, sort_keys=True).encode()).hexdigest(),
                'source_bytes': sum(len((n + '\n').encode()) for n in rows), 'tracked_files': len(rows),
                'graph_files': {n: {'sha256': r['sha256']} for n, r in rows.items()},
                'baseline_graph_files': {n: {'sha256': r['sha256']} for n, r in rows.items()}}
            raw = json.dumps(receipt).encode()
            (root / 'source-receipt.json').write_bytes(raw)
            pin = hashlib.sha256(raw).hexdigest()
            native.validate_source(root, pin, pins)
            target = source / native.GRAPH[0]
            target.chmod(0o755)
            target.write_bytes(b'changed\n')
            target.chmod(0o555)
            with self.assertRaises(ValueError):
                native.validate_source(root, pin, pins)
            for folder, _, _ in os.walk(source):
                Path(folder).chmod(0o755)

    def test_export_payload_mutation_rejected_without_ready_mock(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / 'repositories' / 'fixture'
            repo.mkdir(parents=True)
            item = repo / 'BUILD.bazel'
            item.write_bytes(b'exports_files([])\n')
            item.chmod(0o444)
            repo.chmod(0o555)
            rows = inventory(repo, Budget(time.time() + 60), sealed=True)
            record = {'canonical_name': 'fixture', 'files': rows,
                'inventory_sha256': digest(canonical(rows))}
            graph = root / 'graph'
            graph.mkdir()
            metadata_raw = canonical({'mirrors': []})
            metadata_sha = digest(metadata_raw)
            lock_raw = canonical({'registryFileHashes': {'https://bcr.bazel.build/bazel_registry.json': metadata_sha}})
            (graph / 'MODULE.bazel.lock').write_bytes(lock_raw)
            graph_files = {'MODULE.bazel.lock': {'sha256': digest(lock_raw)}}
            registry_cache = root / 'registry-cache'
            payload = registry_cache / 'content_addressable/sha256' / metadata_sha / 'file'
            payload.parent.mkdir(parents=True)
            payload.write_bytes(metadata_raw)
            payload.chmod(0o444)
            for folder, _, _ in os.walk(registry_cache, topdown=False):
                Path(folder).chmod(0o555)
            registry_metadata = sdk_export.registry_metadata(graph / 'MODULE.bazel.lock',
                digest(lock_raw), registry_cache, Budget(time.time() + 60), sealed=True)
            nix_fixture = root / 'nix-fixture'
            nix_fixture.mkdir()
            (nix_fixture / 'tool').write_bytes(b'fixture tool\n')
            (nix_fixture / 'tool').chmod(0o444)
            nix_fixture.chmod(0o555)
            receipt = {'schema': SCHEMA, 'baseline_inventory_sha256': native.BASE_INVENTORY,
                'graph_files': graph_files, 'qualification_only': False, 'repositories': [record],
                'modules': {},
                'inventory_sha256': digest(canonical([record])), 'mapping_sha256': digest(lock_raw),
                'registry_metadata': registry_metadata,
                'nix_store_roots': [str(nix_fixture)],
                'nix_inventory': inventory(nix_fixture, Budget(time.time() + 60), sealed=True)}
            raw = canonical(receipt)
            (root / 'receipt.json').write_bytes(raw)
            pin = digest(raw)
            # Only the fixed store location is substituted; every fixture byte
            # still goes through the real nofollow inventory validator.
            with patch.object(sdk_export, 'JDK', str(nix_fixture)):
                validate_export(root, pin, native.BASE_INVENTORY, graph_files)
                item.chmod(0o644)
                item.write_bytes(b'changed\n')
                item.chmod(0o444)
                with self.assertRaises(ValueError):
                    validate_export(root, pin, native.BASE_INVENTORY, graph_files)
                item.chmod(0o644)
                item.write_bytes(b'exports_files([])\n')
                item.chmod(0o444)
                (graph / 'MODULE.bazel.lock').write_bytes(b'{"changed": true}\n')
                with self.assertRaises(ValueError):
                    validate_export(root, pin, native.BASE_INVENTORY, graph_files)
            repo.chmod(0o755)
            nix_fixture.chmod(0o755)
            for folder, _, _ in os.walk(registry_cache):
                Path(folder).chmod(0o755)


class CombinedQualificationTests(unittest.TestCase):
    def context(self, root):
        return {'invocation_id':'12345678-1234-4234-8234-123456789abc',
            'output_base':str(root/('cache-v2-'+'a'*64)/'output-base'),
            'source_receipt_sha256':'1'*64, 'export_receipt_sha256':'2'*64,
            'source_inventory_sha256':'3'*64, 'export_inventory_sha256':'4'*64,
            'candidate_cache_key':'a'*64, 'candidate_provenance_sha256':'b'*64,
            'controller_graph_sha256':'c'*64, 'bazel':native.BAZEL,
            'workload_exit':0, 'descendants_empty':True,
            'source_and_export_verified_after_cleanup':True}

    def fixture(self, root, context):
        run=root/context['invocation_id']; (run/'test-evidence').mkdir(parents=True,mode=0o700)
        rows=[]
        for index,(target,names) in enumerate(native.QUALIFICATION_GATES.items()):
            value=('\n'.join('test '+name+' ... ok' for name in names)
                +'\ntest result: ok. %d passed; 0 failed; 0 ignored;\n'%len(names)).encode()
            path=run/'test-evidence'/('log%d'%index); path.write_bytes(value); path.chmod(0o600)
            rows.append({'target':target,'files':[{'source':'test.log','state':'copied',
                'file':path.name,'sha256':hashlib.sha256(value).hexdigest()}]})
        rows.append({'target':native.CLI,'state':'missing-test-directory','files':[]})
        return run,{'targets':list(native.MODES[native.COMBINED_MODE][1]),'results':rows}

    def cli(self, context, configuration='k8-opt'):
        path=Path(context['output_base'])/'execroot/_main/bazel-out'/configuration/'bin/codex-rs/cli/codex'
        path.parent.mkdir(parents=True,mode=0o700,exist_ok=True)
        path.write_bytes(b'\x7fELFmodel-actual-file'); path.chmod(0o500)
        return path

    def test_explicit_combined_command_preserves_four_targets_14_names_and_old_modes(self):
        self.assertEqual(native.MODES[native.COMBINED_MODE],('test',(native.CORE,native.CONFIG,native.LOGIN,native.CLI),None))
        self.assertEqual(native.MODES['qualification'],('test',(native.CORE,native.CONFIG,native.LOGIN),None))
        self.assertEqual(native.MODES['cli-opt'],('build',(native.CLI,),None))
        self.assertEqual(native.MODES['schema'][1],('//bazel/schema:native-config-schema','//bazel/schema:public-schema-bundle'))
        self.assertEqual(sum(map(len,native.QUALIFICATION_GATES.values())),14)
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); run=root/'run'; run.mkdir(mode=0o700); source=root/'source'; source.mkdir(mode=0o700)
            args=SimpleNamespace(native_source_root=root/'input',native_export_root=root/'export',
                native_deadline=None,native_mode=native.COMBINED_MODE)
            exported={'registry_cache':str(args.native_export_root/'registry-cache'),
                'inventory_sha256':'2'*64,'mapping_sha256':'3'*64,'repositories':{},'module_overrides':{}}
            candidate=SimpleNamespace(source=source,root=root/'candidate',lease=SimpleNamespace(output_base=root/'output-base'))
            with patch.object(native,'verify_inputs',return_value=({'inventory_sha256':'1'*64},exported)):
                plan=native.command(args,run,'/nix/store/locked-tool/bin',
                    '/nix/store/i27rhb3nr65rkrwz36bchkwmav6ggsmn-bash-5.3p9/bin/bash',candidate)
            self.assertEqual(plan['argv'][-4:],list(native.MODES[native.COMBINED_MODE][1]))
            for name in (name for names in native.QUALIFICATION_GATES.values() for name in names):
                self.assertEqual(plan['argv'].count('--test_arg='+name),1)

    def test_actual_cli_hash_and_exact_three_test_logs_are_joined(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(native,'STATE',Path(temp)):
            root=Path(temp); context=self.context(root); path=self.cli(context); run,manifest=self.fixture(root,context)
            result=native.meaningful_tests(run,manifest,native.COMBINED_MODE,context)
            self.assertEqual(result['passed'],14)
            self.assertEqual(result['cli_artifact']['path'],str(path))
            self.assertEqual(result['cli_artifact']['sha256'],hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(result['cli_context'],context)
            self.assertNotIn(native.CLI,result['targets'])
            self.assertTrue((run/'native-qualification.xml').is_file())

    def test_failed_cleanup_wrong_tool_missing_duplicate_symlink_or_nonelf_cli_refuses(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(native,'STATE',Path(temp)):
            root=Path(temp); context=self.context(root); path=self.cli(context)
            for key,value in (('workload_exit',1),('descendants_empty',False),
                    ('source_and_export_verified_after_cleanup',False),('bazel','/foreign/bazel'),
                    ('output_base','/foreign/output-base')):
                with self.subTest(key=key),self.assertRaises(ValueError): native.combined_cli_artifact({**context,key:value})
            path.unlink()
            with self.assertRaises(ValueError): native.combined_cli_artifact(context)
            path=self.cli(context); path.chmod(0o700); path.write_bytes(b'not-an-elf')
            with self.assertRaises(ValueError): native.combined_cli_artifact(context)
            path.write_bytes(b'\x7fELFfixture'); path.chmod(0o500); other=self.cli(context,'other-opt')
            with self.assertRaises(ValueError): native.combined_cli_artifact(context)
            other.unlink(); path.unlink(); path.symlink_to(other)
            with self.assertRaises(ValueError): native.combined_cli_artifact(context)

    def test_extra_test_row_or_missing_explicit_cli_request_refuses(self):
        with tempfile.TemporaryDirectory() as temp,patch.object(native,'STATE',Path(temp)):
            root=Path(temp); context=self.context(root); self.cli(context); run,manifest=self.fixture(root,context)
            manifest['results'].append({'target':'//foreign:test','files':[]})
            with self.assertRaises(ValueError): native.meaningful_tests(run,manifest,native.COMBINED_MODE,context)
            manifest['results'].pop(); manifest['targets'].remove(native.CLI)
            with self.assertRaises(ValueError): native.meaningful_tests(run,manifest,native.COMBINED_MODE,context)

class RegistryMetadataAdmissionTests(unittest.TestCase):
    def test_actual_registry_bytes_missing_extra_and_outside_urls(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            metadata_raw = canonical({'mirrors': []})
            metadata_sha = digest(metadata_raw)
            url = 'https://bcr.bazel.build/bazel_registry.json'
            lock = root / 'MODULE.bazel.lock'
            lock_raw = canonical({'registryFileHashes': {url: metadata_sha}})
            lock.write_bytes(lock_raw)
            cache = root / 'registry-cache'
            sha_root = cache / 'content_addressable/sha256'
            payload = sha_root / metadata_sha / 'file'
            payload.parent.mkdir(parents=True)
            payload.write_bytes(metadata_raw)
            payload.chmod(0o444)
            for folder, _, _ in os.walk(cache, topdown=False):
                Path(folder).chmod(0o555)
            def verify():
                return sdk_export.registry_metadata(lock, digest(lock_raw), cache,
                    Budget(time.time() + 60), sealed=True)
            verified = verify()
            self.assertEqual(verified['files'][0]['sha256'], metadata_sha)
            payload.chmod(0o644)
            payload.write_bytes(b'{"changed":true}')
            payload.chmod(0o444)
            with self.assertRaises(ValueError):
                verify()
            payload.chmod(0o644)
            payload.write_bytes(metadata_raw)
            payload.chmod(0o444)
            payload.parent.chmod(0o755)
            payload.unlink()
            with self.assertRaises((ValueError, FileNotFoundError)):
                verify()
            payload.write_bytes(metadata_raw)
            payload.chmod(0o444)
            payload.parent.chmod(0o555)
            sha_root.chmod(0o755)
            extra = sha_root / ('4' * 64)
            extra.mkdir()
            (extra / 'file').write_bytes(b'opaque unselected bytes')
            (extra / 'file').chmod(0o444)
            extra.chmod(0o555)
            sha_root.chmod(0o555)
            with self.assertRaises(ValueError):
                verify()
            sha_root.chmod(0o755)
            extra.chmod(0o755)
            (extra / 'file').unlink()
            extra.rmdir()
            sha_root.chmod(0o555)
            lock_raw = canonical({'registryFileHashes': {'https://outside.invalid/modules/x/1.0/MODULE.bazel': metadata_sha}})
            lock.write_bytes(lock_raw)
            with self.assertRaises(ValueError):
                verify()
            for folder, _, _ in os.walk(cache):
                Path(folder).chmod(0o755)


class NativeCompletionBudgetModels(unittest.TestCase):
    def request(self, phase2=True):
        return SimpleNamespace(profile='codex-native', manager='system',
            native_owned_candidate_cache=True, native_mode=native.COMBINED_MODE,
            native_cache_attempt=6, native_cache_phase2=Path('/public/phase2.json') if phase2 else None,
            native_cache_phase2_sha256='a'*64 if phase2 else None,
            native_cache_transition=None, native_cache_transition_sha256=None,
            native_aggregate_seconds=3600 if phase2 else 1200)

    def test_verified_retry_keeps_setup_time_and_cleanup_inside_original_budget(self):
        entry=100 * 10**9
        for phase2, expected in ((False, 180), (True, 2580)):
            args=self.request(phase2)
            candidate=SimpleNamespace(phase2_verified_before_launch=True)
            args.native_deadline=native.completion_deadline(args,entry,candidate)
            # Nine hundred seconds of admission is already consumed.
            with patch.object(native.time,'monotonic',return_value=1000):
                self.assertEqual(native.runtime(args),expected)
        with patch.object(native.time,'monotonic',return_value=3581):
            with self.assertRaises(ValueError):
                native.runtime(args)

    def test_unverified_foreign_or_unselected_request_cannot_extend_deadline(self):
        mutations=(('profile','standard'),('manager','user'),
            ('native_owned_candidate_cache',False),('native_mode','qualification'),
            ('native_cache_attempt',5),('native_cache_phase2_sha256',None),
            ('native_cache_transition',Path('/public/phase1.json')),
            ('native_aggregate_seconds',7200))
        for field,value in mutations:
            args=self.request(); setattr(args,field,value)
            with self.subTest(field=field),self.assertRaises(ValueError):
                native.completion_deadline(args,100 * 10**9,
                    SimpleNamespace(phase2_verified_before_launch=True))
        for verified in (None,False):
            with self.assertRaises(ValueError):
                native.completion_deadline(self.request(),100 * 10**9,
                    SimpleNamespace(phase2_verified_before_launch=verified))
        args=self.request(False); args.native_aggregate_seconds=3600
        with self.assertRaises(ValueError):
            native.completion_deadline(args,100 * 10**9,
                SimpleNamespace(phase2_verified_before_launch=True))

if __name__ == '__main__':
    unittest.main()
