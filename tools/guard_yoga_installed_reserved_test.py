"""Fixed-vector and shared-kernel models; no normal resident or browser IO."""
import argparse
from pathlib import Path
import unittest
from unittest.mock import patch
import guard_native_seed_plan_reserved as kernel
import guard_yoga_installed_reserved as yoga
import guard_yoga_installed_producer as producer
import guard_resident_observation as resident


class Models(unittest.TestCase):
    def request(self, profile):
        return argparse.Namespace(profile=profile, manager='system', reuse_owned_cache=False,
            source_commit='a' * 40, source_dirty='false', repository_cache=None,
            nixpkgs_source=None, yoga_installed_producer_selection_sha256=(
                'b' * 64 if profile == yoga.WORKSPACE_PROFILE else None))

    def test_exact_vectors_and_early_foreign_configuration_refusal(self):
        for profile in yoga.PROFILES:
            args = self.request(profile)
            self.assertTrue(yoga.request(args, yoga.VECTORS[profile]))
            for changed in ([], yoga.VECTORS[profile] + ['--test_arg=foreign'],
                            ['run', '//delivery:resident_owned_lifecycle']):
                with patch.object(yoga, 'Witness', side_effect=AssertionError('resident read')) as witness:
                    with self.assertRaises(ValueError): yoga.request(args, changed)
                    witness.assert_not_called()
            for name, value in (('manager', 'user'), ('reuse_owned_cache', True),
                ('source_dirty', 'true'), ('resident_vault_manifest', '/private/foreign'),
                ('yoga_qualification', '/private/foreign'), ('native_mode', 'compile')):
                bad = argparse.Namespace(**vars(args)); setattr(bad, name, value)
                with self.assertRaises(ValueError): yoga.request(bad, yoga.VECTORS[profile])

    def test_digest_is_only_workspace_authority(self):
        for profile in (yoga.SELECTION_PROFILE, yoga.MODEL_PROFILE):
            args = self.request(profile); args.yoga_installed_producer_selection_sha256 = 'b' * 64
            with self.assertRaises(ValueError): yoga.request(args, yoga.VECTORS[profile])
        for digest in (None, 'b' * 63, True, '/private/foreign'):
            args = self.request(yoga.WORKSPACE_PROFILE); args.yoga_installed_producer_selection_sha256 = digest
            with self.assertRaises(ValueError): yoga.request(args, yoga.VECTORS[args.profile])

    def test_exact_kernel_identity_caps_and_original_clock(self):
        for name in ('Witness', 'WorkloadWitness', 'monitor', 'cleanup_retained', 'release_worker',
                     'properties', 'remaining'):
            self.assertIs(getattr(yoga, name), getattr(kernel, name))
        self.assertEqual(yoga.MEMORY + resident.RESIDENT_MEMORY, 4 * 1024 ** 3)
        self.assertEqual(yoga.TASKS + resident.RESIDENT_TASKS, 512)
        self.assertEqual(yoga.CPU + resident.RESIDENT_CPU_PERCENT, 200)
        with patch.object(kernel.time, 'monotonic_ns', return_value=1271 * 10 ** 9):
            with self.assertRaises(ValueError): yoga.remaining(100 * 10 ** 9, 1300 * 10 ** 9)
            self.assertEqual(yoga.remaining(100 * 10 ** 9, 1300 * 10 ** 9, cleanup=True), 29)

    def test_selection_fixed_environment_and_models_do_not_share_it(self):
        def builder(bazel, run, arguments, **options):
            self.assertEqual(options['profile'], 'standard')
            return [bazel, *arguments]
        deadline = 1300 * 10 ** 9
        with patch.object(kernel.time, 'monotonic_ns', return_value=200 * 10 ** 9):
            result = yoga.command(builder, 'bazel', Path('/model/epoch'), yoga.VECTORS[yoga.SELECTION_PROFILE],
                                  yoga.SELECTION_PROFILE, 100 * 10 ** 9, deadline)
            self.assertEqual(result[-1], yoga.SELECTION_LABEL)
            self.assertIn('--test_env=OMUX_INSTALLED_SELECTION_DEADLINE_NS=' + str(deadline), result)
            self.assertIn('--repository_disable_download', result)
            self.assertIn('--repo_contents_cache=', result)
            result = yoga.command(builder, 'bazel', Path('/model/epoch'), yoga.MODEL_ARGUMENTS,
                                  yoga.MODEL_PROFILE, 100 * 10 ** 9, deadline)
            self.assertFalse(any(value.startswith('--test_env=') for value in result))

    def test_workspace_uses_actual_producer_command_and_v2_only(self):
        held = producer.Admission.__new__(producer.Admission); held.selection_schema = 2
        def builder(bazel, run, arguments, **options): return [bazel, *arguments]
        argv = ['--selection', str(producer.SELECTION), '--selection-sha256', 'b' * 64,
                '--output', str(producer.OUTPUT), '--deadline-monotonic-ns', str(1300 * 10 ** 9)]
        with patch.object(kernel.time, 'monotonic_ns', return_value=200 * 10 ** 9), \
             patch.object(producer.Admission, 'recheck'), patch.object(producer.Admission, 'argv', return_value=argv):
            result = yoga.command(builder, 'bazel', Path('/model/epoch'), yoga.VECTORS[yoga.WORKSPACE_PROFILE],
                                  yoga.WORKSPACE_PROFILE, 100 * 10 ** 9, 1300 * 10 ** 9, admission=held)
            self.assertEqual(result[1], 'run')
            self.assertEqual(result[result.index('--') + 1:], argv)
            self.assertEqual(result[result.index('--') - 1], yoga.WORKSPACE_LABEL)
            held.selection_schema = 1
            with self.assertRaises(ValueError):
                yoga.command(builder, 'bazel', Path('/model/epoch'), yoga.VECTORS[yoga.WORKSPACE_PROFILE],
                             yoga.WORKSPACE_PROFILE, 100 * 10 ** 9, 1300 * 10 ** 9, admission=held)

    def test_projection_never_promotes_product_gates(self):
        for profile in yoga.PROFILES:
            value = yoga.projection(profile, 100 * 10 ** 9, 1300 * 10 ** 9, True, {'sampled': True})
            for name in ('browser_invoked', 'provider_invoked', 'normal_vault_observed',
                'destination_installation_qualified', 'seat_qualified', 'toolbar_consent_proved',
                'native_runtime_qualified', 'continuity_qualified'):
                self.assertIs(value[name], False)


if __name__ == '__main__': unittest.main()
