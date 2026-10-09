"""Provider-free installed-workspace models; intended Bazel-only execution."""
import copy
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest.mock import patch

import yoga_installed_workspace as installed


class InstalledWorkspaceTests(unittest.TestCase):
    def projection(self):
        # Actual closed public projection of BUILD464e, not a qualifying fake RUN.
        return {'id': installed.BUILD_ID, 'artifact_epoch': installed.BUILD_ID,
            'source_commit': installed.SOURCE_COMMIT, 'source_dirty': 'false',
            'graph_sha256': installed.SOURCE_GRAPH, 'profile': 'standard', 'verb': 'build',
            'targets': [installed.LABEL], 'exit': 0, 'workload_exit': 0, 'descendants_empty': True,
            'controller_failure': None, 'output_base': installed.OUTPUT_BASE,
            'cache_reuse_requested': True, 'cache_policy': 2,
            'cache_key': '39f2eb3574f1f88de5326867c7d8ef4bc518faba8cb6b2048f84613edac8947d',
            'cleanup': {'ownership': 'unproved', 'readback_attempts': 0, 'state': 'empty', 'stop': 'not-requested'}}

    def test_actual_build_projection_keeps_unstamped_artifact_truth_separate(self):
        result = installed.origin(self.projection())
        self.assertEqual(result['source_dirty'], 'false')
        self.assertEqual(result['cleanup']['ownership'], 'unproved')
        self.assertNotIn('embeddedArtifactProvenance', result)

    def test_test_dirty_wrong_types_and_pointer_substitution_refuse(self):
        for key, value in [('verb', 'test'), ('source_dirty', False), ('source_dirty', 'true'),
                ('exit', False), ('cache_policy', True), ('descendants_empty', 1),
                ('output_base', installed.OUTPUT_BASE + '-other'), ('source_commit', 'f' * 40),
                ('targets', [installed.LABEL, '//:foreign'])]:
            picked = self.projection(); picked[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                installed.origin(picked)

    def lines(self):
        return ''.join('_main/' + name + ' ' + installed.SOURCE_ROOT + '/' + name + '\n'
                       for name in sorted(installed.ORIGIN_FILES))

    def test_runfiles_required_sources_duplicate_and_unjustified_escape_marker(self):
        value = installed.manifest(self.lines().encode())
        self.assertEqual(len(value), len(installed.ORIGIN_FILES))
        for content in [self.lines() + self.lines().splitlines()[0] + '\n',
                        ' ' + self.lines(), self.lines().split('\n', 1)[1],
                        self.lines() + '../outside /srv/public\n']:
            with self.assertRaises(ValueError):
                installed.manifest(content.encode())

    def test_actual_pinned_hrtf_and_alsa_record_shapes_decode_without_omission(self):
        # Public selected manifest lines5903/13698; pure parser data only.
        prefix = '+cached_site_repository+omux_cached_site/closure/'
        cases = (
            '2ahpi3w4gh6l039bs3ai7isv7ga4n0y6-openal-soft-1.24.3/share/openal/hrtf/Default HRTF.mhr',
            '3innqpmxwvmr2vc8h51g47aqdl6zj2b4-alsa-lib-1.2.15.3/share/alsa/ucm2/NXP/iMX8/Librem_5/Librem 5.conf',
        )
        extra = ''
        expected = installed.manifest(self.lines().encode())
        for suffix in cases:
            key = prefix + suffix
            target = installed.OUTPUT_BASE + '/external/' + key
            extra += ' ' + key.replace(' ', '\\s') + ' ' + target + '\n'
            expected[key] = target
        self.assertEqual(installed.manifest((self.lines() + extra).encode()), expected)
        self.assertEqual(len(expected), len(installed.ORIGIN_FILES) + 2)
        with self.assertRaises(ValueError):
            installed.manifest((self.lines() + extra + extra.splitlines()[0] + '\n').encode())

    def test_manifest_escape_grammar_and_decoded_unsafe_paths_refuse(self):
        bad = (
            ' +repo/file\\q /srv/public/file',
            ' +repo/file\\ /srv/public/file',
            ' +repo/file\\bname /srv/public/file',
            ' +repo/file\\nname /srv/public/file',
            ' /absolute\\skey /srv/public/file',
            ' +repo/../unsafe\\skey /srv/public/file',
            ' +repo/file\\sname /srv/public/file\\nname',
            ' +repo/file\\sname /srv/public/file\\bname',
            ' +repo/file\\sname /srv/public/file\\sname',
            ' +repo/file\\sname relative/file',
            '  +repo/file\\sname /srv/public/file',
        )
        for record in bad:
            with self.subTest(record=record), self.assertRaises(ValueError):
                installed.manifest((self.lines() + record + '\n').encode())
        # Decoding is not custody: a syntactically valid personal selector is
        # still refused by the existing namespace fence before metadata reads.
        value = installed.manifest((self.lines() + ' +repo/file\\sname /home/private/file name\n').encode())
        with patch.object(installed.os, 'lstat') as observed, self.assertRaises(ValueError):
            installed.safe_resolve(value['+repo/file name'], frozenset())
        observed.assert_not_called()

    def test_original_repo_mapping_and_launcher_are_omitted_only_by_exact_key(self):
        content = self.lines() + '_repo_mapping ' + installed.OUTPUT_BASE + '/execroot/_main/bazel-out/k8-fastbuild/bin/delivery/yoga_toolbar_consent_proof.sh.repo_mapping\n'
        content += '_main/delivery/yoga_toolbar_consent_proof.sh ' + installed.OUTPUT_BASE + '/execroot/_main/bazel-out/k8-fastbuild/bin/delivery/yoga_toolbar_consent_proof.sh\n'
        self.assertEqual(installed.manifest(content.encode()), installed.manifest(self.lines().encode()))
        with self.assertRaises(ValueError):
            installed.manifest(content.replace('.sh.repo_mapping', '.foreign').encode())

    def test_foreign_private_path_is_refused_before_any_metadata_consult(self):
        with patch.object(installed.os, 'lstat') as observed, self.assertRaises(ValueError):
            installed.safe_resolve('/home/private/auth.json', frozenset())
        observed.assert_not_called()

    def test_capture_personal_and_runtime_metadata_refuses_before_open(self):
        for path in ('/home/private/selection.json', '/run/user/1000/input.json',
                     '/srv/other/selection.json'):
            with self.subTest(path=path), patch.object(installed.payload, 'parent') as parent, \
                 patch.object(installed.os, 'open') as opened, self.assertRaises(ValueError):
                installed.PhysicalCapture(path, 'a' * 64, 64, time.monotonic() + 10)
            parent.assert_not_called(); opened.assert_not_called()
        self.assertEqual(installed.public_capture_path(installed.BUILD_RECEIPT),
                         Path(installed.BUILD_RECEIPT))

    def test_symlink_hop_cannot_consult_foreign_runtime(self):
        base = '/nix/store/' + 'a' * 32 + '-selected'
        directory = type('Info', (), {'st_mode': stat.S_IFDIR | 0o555})()
        link = type('Info', (), {'st_mode': stat.S_IFLNK | 0o777})()
        def observed(path):
            self.assertFalse(str(path).startswith('/run/'))
            return link if str(path) == base + '/alias' else directory
        with patch.object(installed.os, 'lstat', side_effect=observed), \
             patch.object(installed.os, 'readlink', return_value='/run/user/1000/private'), \
             self.assertRaises(ValueError):
            installed.safe_resolve(base + '/alias', frozenset({base}))

    def test_fixed_rule_deduplicates_alias_assets_and_preserves_actual_arguments(self):
        mapping = {'_main/delivery/a': '/srv/a', '_main/delivery/b': '/srv/a'}
        files = installed.build_files(mapping, {'f000000': 'data/a', 'f000001': 'data/a'}, {})
        module, build = files['MODULE.bazel'].decode(), files['delivery/BUILD.bazel'].decode()
        self.assertNotIn('bazel_dep(', module)
        self.assertEqual(build.count("'//:data/a'"), 1)
        self.assertIn(repr(installed.LAUNCH_ARGS), build)
        self.assertNotIn('rules_zig', build)
        self.assertIn('int(index)', installed.RULE)
        self.assertNotIn('ctx.execute', installed.REPOSITORY)

    def test_subpackage_sources_have_declared_package_labels(self):
        mapping = {'_main/delivery/reader.py': '/srv/public-reader'}
        files = installed.build_files(mapping, {'f000000': 'delivery/reader.py'}, {})
        self.assertNotIn('delivery/reader.py', files['BUILD.bazel'].decode())
        self.assertIn("'//delivery:reader.py'", files['delivery/BUILD.bazel'].decode())
        self.assertIn("exports_files(['reader.py'])", files['delivery/BUILD.bazel'].decode())

    def test_physical_capture_does_not_re_resolve_a_replaced_authorized_alias(self):
        # The authorized path is opened no-follow; alias rechecks are separate.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); public = root / 'public'
            public.symlink_to('/unselected/private')
            parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with patch.object(installed.payload, 'parent', side_effect=lambda _: os.dup(parent)), \
                     patch.object(Path, 'resolve', side_effect=AssertionError('no unrestricted alias resolution')), \
                     self.assertRaises(OSError):
                    installed.PhysicalCapture(installed.SOURCE_ROOT + '/delivery/public',
                                              'a' * 64, 64, time.monotonic() + 10)
            finally:
                os.close(parent)

    def test_real_output_readback_refuses_extra_content_modes_and_symlinks(self):
        # Only output descriptors are modeled here; no production ancestor exemption.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); path = root / 'public.txt'
            path.write_bytes(b'selected'); path.chmod(0o444)
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                expected = {'public.txt': b'selected'}
                installed.verify_output(fd, expected, {}, time.monotonic() + 10)
                path.chmod(0o644)
                with self.assertRaises(ValueError):
                    installed.verify_output(fd, expected, {}, time.monotonic() + 10)
                path.chmod(0o444)
                (root / 'extra').write_bytes(b'unselected')
                with self.assertRaises(ValueError):
                    installed.verify_output(fd, expected, {}, time.monotonic() + 10)
                (root / 'extra').unlink(); path.unlink(); path.symlink_to('/does-not-exist')
                with self.assertRaises(ValueError):
                    installed.verify_output(fd, expected, {}, time.monotonic() + 10)
            finally:
                os.close(fd)


    def test_reserved_third_launcher_is_declared_without_rewriting_origin_target(self):
        mapping={'_main/tools/yoga_reserved_session_qualification.py':'/srv/root/tools/yoga_reserved_session_qualification.py'}
        copied={'f000000':'tools/yoga_reserved_session_qualification.py'}
        original=installed.build_files(mapping,copied,{})
        reserved=installed.build_files(mapping,copied,{},reserved=True)
        self.assertNotIn(b'yoga_reserved_session_qualification.sh',original['BUILD.bazel'])
        self.assertIn(b'yoga_reserved_session_qualification.sh',reserved['BUILD.bazel'])
        self.assertIn(b'name = \'yoga_reserved_session_qualification\'',reserved['tools/BUILD.bazel'])
        self.assertEqual(reserved['delivery/BUILD.bazel'],original['delivery/BUILD.bazel'])
        self.assertEqual(installed.SOURCE_COMMIT,'c106a52523d2161063a6a58d6d29a8f86039f827')

if __name__ == '__main__':
    unittest.main()
