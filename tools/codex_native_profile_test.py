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

if __name__ == '__main__':
    unittest.main()
