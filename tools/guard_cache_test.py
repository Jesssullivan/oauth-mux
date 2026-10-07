"""Pure cache-fence fixtures, executed only by a declared Bazel test."""
import os
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import uuid
from guard_cache import CacheLease, fingerprint, stable_fingerprint, graph_digest, trusted_directory


class CacheTest(unittest.TestCase):
    def test_v2_stable_key_partitions_containment_and_tools_not_source_graph(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs = {'bazel': '/nix/store/example/bin/bazel', 'java': '/nix/store/jdk'}
            profile = {'memory': 4294967296, 'test_strategy': 'processwrapper-sandbox', 'batch': True}
            first = stable_fingerprint(directory, inputs, 1000, 1000, 'user', profile)
            (Path(directory) / 'BUILD.bazel').write_text('graph changed')
            self.assertEqual(first, stable_fingerprint(directory, inputs, 1000, 1000, 'user', profile))
            self.assertNotEqual(first, stable_fingerprint(directory, inputs, 1000, 1000, 'system', profile))
            self.assertNotEqual(first, stable_fingerprint(directory, inputs, 1001, 1000, 'user', profile))
            self.assertNotEqual(first, stable_fingerprint(directory, inputs, 1000, 1000, 'user', {**profile, 'memory': 1}))
            self.assertNotEqual(first, stable_fingerprint(directory, {**inputs, 'java': '/nix/store/other'}, 1000, 1000, 'user', profile))

    def test_v2_never_adopts_legacy_cache_namespace(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch('guard_cache.trusted_directory', side_effect=lambda path:
                       os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)):
                with CacheLease(directory, 'a' * 64, str(uuid.uuid4())):
                    pass  # Dirty legacy key must not block or be adopted by v2.
                with CacheLease(directory, 'a' * 64, str(uuid.uuid4()), policy_version=2) as lease:
                    self.assertEqual(lease.output_base.parent.name, 'cache-v2-' + 'a' * 64)
                self.assertTrue((Path(directory) / ('cache-' + 'a' * 64) / 'owner.json').exists())

    def test_graph_key_tracks_rules_without_application_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'BUILD.bazel').write_text('graph-one')
            (root / 'runtime.zig').write_text('application-one')
            (root / 'tools').mkdir()
            (root / 'tools' / 'repository.py').write_text('repository-rule-one')
            first, selected = graph_digest(root)
            self.assertEqual(selected, ['BUILD.bazel', 'tools/repository.py'])
            (root / 'runtime.zig').write_text('application-two')
            self.assertEqual(first, graph_digest(root)[0])
            (root / 'tools' / 'repository.py').write_text('repository-rule-two')
            self.assertNotEqual(first, graph_digest(root)[0])

    def test_key_binds_graph_and_tool_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            inputs = {'bazel': '/nix/store/example/bin/bazel', 'java': '/nix/store/jdk'}
            first = fingerprint(directory, 'a' * 64, inputs)
            self.assertNotEqual(first, fingerprint(directory, 'b' * 64, inputs))
            self.assertNotEqual(first, fingerprint(directory, 'a' * 64, {**inputs, 'java': '/nix/store/other'}))

    def test_reuse_only_after_bound_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            os.chmod(directory, 0o700)
            # Isolate marker/lease tests from Bazel's potentially world-writable
            # TEST_TMPDIR ancestors. Production never uses this replacement.
            with patch('guard_cache.trusted_directory', side_effect=lambda path:
                       os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)):
                first_id = str(uuid.uuid4())
                run = Path(directory) / first_id
                run.mkdir(mode=0o700)
                content = json.dumps({'id': first_id, 'descendants_empty': True}).encode()
                (run / 'receipt.json').write_bytes(content)
                digest = hashlib.sha256(content).hexdigest()
                with CacheLease(directory, 'a' * 64, first_id) as first:
                    path = first.output_base
                    with self.assertRaises(BlockingIOError):
                        with CacheLease(directory, 'a' * 64, str(uuid.uuid4())):
                            pass
                    with self.assertRaises(ValueError):
                        first.complete(False, 'b' * 64)
                    first.complete(True, digest)
                with CacheLease(directory, 'a' * 64, str(uuid.uuid4())) as second:
                    self.assertEqual(path, second.output_base)
                    # Deliberately leave dirty, simulating failed cleanup/crash.
                with self.assertRaises(ValueError):
                    with CacheLease(directory, 'a' * 64, str(uuid.uuid4())):
                        pass

    def test_relative_state_refused(self):
        with self.assertRaises(ValueError):
            trusted_directory(Path('relative'))

    def test_graph_directory_symlink_refused(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as external:
            root = Path(directory)
            (root / 'BUILD.bazel').write_text('graph')
            (root / 'external-graph').symlink_to(external, target_is_directory=True)
            with self.assertRaises(ValueError):
                graph_digest(root)

    def test_only_root_direnv_operator_state_is_excluded(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as external:
            root = Path(directory)
            (root / 'BUILD.bazel').write_text('graph')
            before = graph_digest(root)
            operator = root / '.direnv'
            operator.mkdir()
            (operator / 'flake-profile').symlink_to(external, target_is_directory=True)
            (operator / 'BUILD.bazel').write_text('operator state is not graph input')
            self.assertEqual(before, graph_digest(root))
            package = root / 'package'
            package.mkdir()
            (package / '.direnv').symlink_to(external, target_is_directory=True)
            with self.assertRaises(ValueError):
                graph_digest(root)


if __name__ == '__main__':
    unittest.main()
