"""Closed new cohorts; admission never certifies SDK/60models/image/ordinary."""
from pathlib import Path
from types import SimpleNamespace
import time
import unittest
from unittest.mock import Mock,patch
import guard_native_owned_history_reserved as guard
import guard_native_siwc_catalog_models_reserved as old


class OwnedHistoryReservationTests(unittest.TestCase):
    def test_exact_model_pair_only_no_oldprofile_extra_or_bare_admission(self):
        self.assertEqual(guard.selected(guard.PROFILE,guard.ARGUMENTS),{'PrivateNetwork':'yes'})
        for profile,args in ((old.PROFILE,guard.ARGUMENTS),(guard.PROFILE,guard.ARGUMENTS[:-1]),
                (guard.PROFILE,guard.ARGUMENTS+['//:docs_check']),
                (guard.PROFILE,['test',guard.ARGUMENTS[2],guard.ARGUMENTS[1]])):
            with self.assertRaises(ValueError):guard.selected(profile,args)
        self.assertEqual(old.selected(old.PROFILE,old.ARGUMENTS),{'PrivateNetwork':'yes'})

    def test_fixed_command_keeps_original_context_six_repo_and_six_test_fields(self):
        entry=time.monotonic_ns();until=entry+1200*10**9
        run=Path('/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/01234567-0123-0123-0123-0123456789ab')
        builder=Mock(return_value=['/nix/store/public-bazel/bin/bazel','test',*guard.ARGUMENTS[1:]])
        with patch('guard_resident_enrollment_profile.repository_inputs'),patch.object(guard,'runtime_seconds',return_value=840):
            command=guard.command(builder,'/nix/store/public-bazel/bin/bazel',run,guard.ARGUMENTS,guard.PROFILE,entry,until,
                graph_sha256='b'*64,source_commit='a'*40,source_dirty='false',repository_cache=Path('/public/cache'),nixpkgs_source=Path('/nix/store/public-source'))
        self.assertEqual(command[-2:],guard.ARGUMENTS[1:]);self.assertIn('--test_timeout=840',command)
        for kind in ('repo_env','test_env'):
            values=[row for row in command if row.startswith('--'+kind+'=OMUX_NATIVE_FILE_WRITER_MODELS_')]
            self.assertEqual(len(values),6)
            self.assertIn('--'+kind+'='+guard.MODE+'='+guard.INPUT_MODE,values)
            self.assertIn('--'+kind+'='+guard.ENTRY+'='+str(entry),values)
            self.assertIn('--'+kind+'='+guard.DEADLINE+'='+str(until),values)
        with patch('guard_resident_enrollment_profile.repository_inputs'),self.assertRaises(ValueError):guard.command(builder,'/nix/store/public-bazel/bin/bazel',run,guard.ARGUMENTS,guard.PROFILE,entry,until,
            graph_sha256='b'*64,source_commit='a'*40,source_dirty='false',output_base=Path('/arbitrary'))

    def test_projection_and_runtime_cannot_promote_or_extend_original_proof(self):
        entry=time.monotonic_ns();until=entry+1200*10**9
        value=guard.projection(entry,until,True,{'public':'schema-only fixture'})
        self.assertEqual(value['scope'],'fixed-native-retained-sdk-tree-models-reserved-v1')
        self.assertEqual(value['action_cap_seconds'],840)
        self.assertTrue(all(value[name] is False for name in ('sdk_qualified','compiler_qualified','native_image_qualified',
            'native60_qualified_by_admission','ordinary_launch_qualified','continuity_qualified','live_qualified')))
        with patch.object(guard,'remaining',return_value=17):self.assertEqual(guard.runtime_seconds(entry,until),17)
        with patch.object(guard,'remaining',return_value=1100):self.assertEqual(guard.runtime_seconds(entry,until),840)
        with self.assertRaises(ValueError):guard.projection(entry,until+1,True,{})

    def test_bounded_owned_worker_monitor_requires_actual_typed_witness(self):
        with self.assertRaises(ValueError):guard.monitor(guard.PROFILE,Mock(),Mock(),time.monotonic()+1,lambda:None)
        with self.assertRaises(ValueError):guard.release_worker(Mock())
        self.assertTrue(guard.release_worker(None))


    def boot_command(self,module,capture):
        entry=time.monotonic_ns();until=entry+1200*10**9
        run=Path('/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/01234567-0123-0123-0123-0123456789ab')
        builder=Mock(return_value=['/nix/store/public-bazel/bin/bazel','test',*module.ARGUMENTS[1:]])
        with patch('guard_resident_enrollment_profile.repository_inputs'),patch.object(module,'runtime_seconds',return_value=840),capture:
            result=module.command(builder,'/nix/store/public-bazel/bin/bazel',run,module.ARGUMENTS,module.PROFILE,entry,until,
                graph_sha256='b'*64,source_commit='a'*40,source_dirty='false',repository_cache=Path('/public/cache'),nixpkgs_source=Path('/nix/store/public-source'))
        return result,entry,until,builder

    def test_current_boot_capture_is_source600_and_keeps_source_six_context(self):
        boot='aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
        capture=patch.object(guard.sdk_tree,'current_boot_id',return_value=boot)
        result,entry,until,builder=self.boot_command(guard,capture)
        for kind in ('action_env','test_env'):
            self.assertEqual([part for part in result if part.startswith('--'+kind+'=OMUX_NATIVE_SDK_TREE_CURRENT_BOOT_ID=')],
                ['--'+kind+'=OMUX_NATIVE_SDK_TREE_CURRENT_BOOT_ID='+boot])
        for kind in ('repo_env','test_env'):
            self.assertEqual(len([part for part in result if part.startswith('--'+kind+'=OMUX_NATIVE_FILE_WRITER_MODELS_')]),6)
        self.assertFalse(any('OMUX_NATIVE_FILE_WRITER_MODELS_BOOT_ID=' in part or 'OMUX_NATIVE_SDK_TREE_BOOT_ID=' in part for part in result))
        builder.assert_called_once()
        self.assertEqual(guard.sdk_tree.PROFILES,(guard.sdk_tree.PRODUCER,guard.sdk_tree.SOURCE_PROFILE))

    def test_model_and_cli_use_same_actual_capture_contract_but_distinct_admission(self):
        import guard_native_owned_history_cli_reserved as cli
        for module in (guard,cli):
            actual=module.sdk_tree.current_boot_id
            calls=[]
            def capture(entry,until,profile):
                calls.append((entry,until,profile));return 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
            result,entry,until,builder=self.boot_command(module,patch.object(module.sdk_tree,'current_boot_id',side_effect=capture))
            self.assertEqual(calls,[(entry,until,module.sdk_tree.SOURCE_PROFILE)])
            self.assertEqual(result[-2:],module.ARGUMENTS[1:]);self.assertIn('--test_timeout=840',result)
            with self.assertRaises(ValueError):module.selected(cli.PROFILE if module is guard else guard.PROFILE,module.ARGUMENTS)
            self.assertIs(module.sdk_tree.current_boot_id,actual)

    def test_real_capture_original_source_cutoff_refuses_before_builder_or_kernel_open(self):
        entry=time.monotonic_ns();until=entry+1200*10**9
        run=Path('/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/01234567-0123-0123-0123-0123456789ab')
        builder=Mock(return_value=['/nix/store/public-bazel/bin/bazel','test',*guard.ARGUMENTS[1:]])
        with patch('guard_resident_enrollment_profile.repository_inputs'),patch.object(guard,'runtime_seconds',return_value=840),                patch.object(guard.sdk_tree.time,'monotonic_ns',return_value=entry+600*10**9),patch.object(guard.sdk_tree.os,'open') as opened:
            with self.assertRaises(ValueError):guard.command(builder,'/nix/store/public-bazel/bin/bazel',run,guard.ARGUMENTS,guard.PROFILE,entry,until,
                graph_sha256='b'*64,source_commit='a'*40,source_dirty='false',repository_cache=Path('/public/cache'),nixpkgs_source=Path('/nix/store/public-source'))
            opened.assert_not_called();builder.assert_not_called()

    def test_capture_refusal_cannot_invoke_builder_or_fabricate_boot_action_input(self):
        entry=time.monotonic_ns();until=entry+1200*10**9
        run=Path('/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/01234567-0123-0123-0123-0123456789ab')
        builder=Mock(return_value=['/nix/store/public-bazel/bin/bazel','test',*guard.ARGUMENTS[1:]])
        primary=ValueError('public role refusal')
        with patch('guard_resident_enrollment_profile.repository_inputs'),patch.object(guard,'runtime_seconds',return_value=840),                patch.object(guard.sdk_tree,'current_boot_id',side_effect=primary):
            with self.assertRaises(ValueError) as caught:guard.command(builder,'/nix/store/public-bazel/bin/bazel',run,guard.ARGUMENTS,guard.PROFILE,entry,until,
                graph_sha256='b'*64,source_commit='a'*40,source_dirty='false',repository_cache=Path('/public/cache'),nixpkgs_source=Path('/nix/store/public-source'))
            self.assertIs(caught.exception,primary);builder.assert_not_called()


if __name__=='__main__':unittest.main()
