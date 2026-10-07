"""Pure profile/coordination predicates; no downloads or system commands."""
from pathlib import Path
import unittest
from guard_dependency_profile import (BUNDLE_FETCH_LABEL, FETCH_LABEL, HOME_MANAGER_FETCH_LABEL,
    GIT_FETCH_LABEL, COORDINATION_DIRECTORY, HOME_MANAGER_STATE, HOME_GIT_STATE, HOME_HTTP_STATE,
    selected_profile, validate_coordination)


class DependencyProfileTest(unittest.TestCase):
    def test_http_home_state_requires_sole_bundle_producer_and_existing_controller_lock(self):
        arguments = ['test', BUNDLE_FETCH_LABEL]
        self.assertEqual(selected_profile('dependency-prefetch', arguments), {'PrivateNetwork': 'no'})
        self.assertEqual(validate_coordination('dependency-prefetch', COORDINATION_DIRECTORY,
            HOME_HTTP_STATE, arguments=arguments), COORDINATION_DIRECTORY)
        for selected in (None, HOME_HTTP_STATE, HOME_GIT_STATE, Path('/home/jess/.local/state/other-lock')):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                validate_coordination('dependency-prefetch', selected, HOME_HTTP_STATE, arguments=arguments)

    def test_http_home_state_refuses_other_profiles_producers_and_extended_context(self):
        for profile in ('standard', 'installed-browser', 'codex-sdk', 'yoga-toolbar'):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                validate_coordination(profile, COORDINATION_DIRECTORY, HOME_HTTP_STATE,
                    arguments=['test', BUNDLE_FETCH_LABEL])
        for arguments in (None, [], ['test', FETCH_LABEL], ['test', HOME_MANAGER_FETCH_LABEL],
                          ['test', GIT_FETCH_LABEL], ['test', '//tools:codex_dependency_bundle_plan'],
                          ['test', '//tools:codex_dependency_bundle_producer_extra'], ['test', '//...'],
                          ['build', BUNDLE_FETCH_LABEL], ['run', BUNDLE_FETCH_LABEL],
                          ['test', BUNDLE_FETCH_LABEL, BUNDLE_FETCH_LABEL],
                          ['test', BUNDLE_FETCH_LABEL, GIT_FETCH_LABEL],
                          ['test', BUNDLE_FETCH_LABEL, '--test_arg=--shard-index=0']):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                validate_coordination('dependency-prefetch', COORDINATION_DIRECTORY,
                    HOME_HTTP_STATE, arguments=arguments)
        for options in ({'site_inputs': True}, {'pack_input': True}, {'recovery_input': True}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                selected_profile('dependency-prefetch', ['test', BUNDLE_FETCH_LABEL], **options)
        for state in (HOME_HTTP_STATE / 'child', HOME_HTTP_STATE.parent / 'omux-codex-http-prefetch-20261005',
                      Path('/home/jess/.local/state/../state/omux-codex-http-prefetch-20261006')):
            with self.subTest(state=state), self.assertRaises(ValueError):
                validate_coordination('dependency-prefetch', COORDINATION_DIRECTORY, state,
                    arguments=['test', BUNDLE_FETCH_LABEL])

    def test_http_home_route_preserves_fast_and_distinct_hm_and_git_routes(self):
        fast = Path('/srv/fast-local/jess/state/codex/omux-dependency-prefetch-20261005')
        for label in (FETCH_LABEL, BUNDLE_FETCH_LABEL, HOME_MANAGER_FETCH_LABEL):
            with self.subTest(label=label):
                self.assertEqual(validate_coordination('dependency-prefetch', COORDINATION_DIRECTORY,
                    fast, arguments=['test', label]), COORDINATION_DIRECTORY)
        for state, label in ((HOME_MANAGER_STATE, HOME_MANAGER_FETCH_LABEL), (HOME_GIT_STATE, GIT_FETCH_LABEL)):
            self.assertEqual(validate_coordination('dependency-prefetch', COORDINATION_DIRECTORY,
                state, arguments=['test', label]), COORDINATION_DIRECTORY)
            with self.assertRaises(ValueError):
                validate_coordination('dependency-prefetch', COORDINATION_DIRECTORY,
                    state, arguments=['test', BUNDLE_FETCH_LABEL])

    def test_first_git_home_state_requires_exact_producer_and_existing_controller_lock(self):
        arguments = ['test', GIT_FETCH_LABEL]
        self.assertEqual(selected_profile('dependency-prefetch', arguments), {'PrivateNetwork': 'no'})
        self.assertEqual(validate_coordination('dependency-prefetch', COORDINATION_DIRECTORY,
            HOME_GIT_STATE, arguments=arguments), COORDINATION_DIRECTORY)
        for selected in (None, HOME_GIT_STATE, HOME_MANAGER_STATE, Path('/home/jess/.local/state/other-lock')):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                validate_coordination('dependency-prefetch', selected, HOME_GIT_STATE, arguments=arguments)
        for profile in ('standard', 'installed-browser', 'codex-sdk', 'yoga-toolbar'):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                validate_coordination(profile, COORDINATION_DIRECTORY, HOME_GIT_STATE, arguments=arguments)

    def test_first_git_home_state_rejects_wrong_missing_and_extended_context(self):
        for arguments in (None, [], ['test', FETCH_LABEL], ['test', BUNDLE_FETCH_LABEL],
                          ['test', HOME_MANAGER_FETCH_LABEL], ['test', '//tools:codex_git_input_producer'],
                          ['test', '//tools:codex_git_input_producer_1'], ['test', '//...'],
                          ['build', GIT_FETCH_LABEL], ['run', GIT_FETCH_LABEL],
                          ['test', GIT_FETCH_LABEL, GIT_FETCH_LABEL],
                          ['test', GIT_FETCH_LABEL, HOME_MANAGER_FETCH_LABEL],
                          ['test', GIT_FETCH_LABEL, '--test_arg=--requirement-index=1']):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                validate_coordination('dependency-prefetch', COORDINATION_DIRECTORY,
                    HOME_GIT_STATE, arguments=arguments)
        arguments = ['test', GIT_FETCH_LABEL]
        for state in (HOME_GIT_STATE.parent / 'omux-codex-git-prefetch-20261005',
                      HOME_GIT_STATE / 'child', HOME_MANAGER_STATE, COORDINATION_DIRECTORY,
                      Path('/srv/fast-local/jess/state/codex/omux-dependency-prefetch-20261005'),
                      Path('/home/jess/.local/state/../state/omux-codex-git-prefetch-20261006')):
            with self.subTest(state=state), self.assertRaises(ValueError):
                validate_coordination('dependency-prefetch', COORDINATION_DIRECTORY, state,
                    arguments=arguments)

    def test_git_home_admission_preserves_existing_fast_and_home_manager_lanes(self):
        fast = Path('/srv/fast-local/jess/state/codex/omux-dependency-prefetch-20261005')
        for label in (FETCH_LABEL, BUNDLE_FETCH_LABEL, HOME_MANAGER_FETCH_LABEL):
            with self.subTest(label=label):
                self.assertEqual(validate_coordination('dependency-prefetch', COORDINATION_DIRECTORY,
                    fast, arguments=['test', label]), COORDINATION_DIRECTORY)
        self.assertEqual(validate_coordination('dependency-prefetch', COORDINATION_DIRECTORY,
            HOME_MANAGER_STATE, arguments=['test', HOME_MANAGER_FETCH_LABEL]), COORDINATION_DIRECTORY)

    def test_home_manager_home_state_requires_exact_network_producer_and_existing_lock(self):
        arguments = ['test', HOME_MANAGER_FETCH_LABEL]
        self.assertEqual(selected_profile('dependency-prefetch', arguments), {'PrivateNetwork': 'no'})
        self.assertEqual(validate_coordination('dependency-prefetch', COORDINATION_DIRECTORY,
            HOME_MANAGER_STATE, arguments=arguments), COORDINATION_DIRECTORY)
        self.assertEqual(selected_profile('standard', arguments), {'PrivateNetwork': 'yes'})
        for profile in ('standard', 'installed-browser', 'codex-sdk', 'yoga-toolbar'):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                validate_coordination(profile, COORDINATION_DIRECTORY, HOME_MANAGER_STATE, arguments=arguments)
        for selected in (None, HOME_MANAGER_STATE, Path('/home/jess/.local/state/other-lock')):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                validate_coordination('dependency-prefetch', selected, HOME_MANAGER_STATE, arguments=arguments)

    def test_home_manager_home_state_rejects_missing_other_and_extended_label_context(self):
        for arguments in (None, [], ['test', FETCH_LABEL], ['test', BUNDLE_FETCH_LABEL],
                          ['test', '//tools:codex_git_input_producer'], ['test', '//...'],
                          ['build', HOME_MANAGER_FETCH_LABEL], ['run', HOME_MANAGER_FETCH_LABEL],
                          ['test', HOME_MANAGER_FETCH_LABEL, HOME_MANAGER_FETCH_LABEL],
                          ['test', HOME_MANAGER_FETCH_LABEL, FETCH_LABEL],
                          ['test', HOME_MANAGER_FETCH_LABEL, '--test_arg=--source-root=/other']):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                validate_coordination('dependency-prefetch', COORDINATION_DIRECTORY,
                    HOME_MANAGER_STATE, arguments=arguments)
        arguments = ['test', HOME_MANAGER_FETCH_LABEL]
        for root in (HOME_MANAGER_STATE.parent / 'omux-home-manager-prefetch-20261005',
                     HOME_MANAGER_STATE / 'child', COORDINATION_DIRECTORY,
                     Path('/home/jess/.local/state/../state/omux-home-manager-prefetch-20261006')):
            with self.subTest(root=root), self.assertRaises(ValueError):
                validate_coordination('dependency-prefetch', COORDINATION_DIRECTORY, root, arguments=arguments)
        with self.assertRaises(ValueError):
            selected_profile('dependency-prefetch', ['test', '//tools:codex_git_input_producer'])

    def test_yoga_requires_one_local_run_without_other_inputs(self):
        selected = ['run', '//delivery:yoga_toolbar_consent_proof']
        self.assertEqual(selected_profile('yoga-toolbar', selected), {'PrivateNetwork': 'yes'})
        for arguments in (['test', selected[1]], selected + ['//:other'], selected + ['--', '--inside'],
                          ['run', '//delivery:yoga_toolbar_attest'], ['run', '//...']):
            with self.assertRaises(ValueError):
                selected_profile('yoga-toolbar', arguments)
        for options in ({'site_inputs': True}, {'pack_input': True}, {'recovery_input': True}):
            with self.assertRaises(ValueError):
                selected_profile('yoga-toolbar', selected, **options)
        root = Path('/srv/omux-yoga-state')
        self.assertEqual(validate_coordination('yoga-toolbar', None, root), root)
        for selected, root in ((None, Path('/home/user/state')),
                               (Path('/srv/other-lock'), Path('/srv/state'))):
            with self.assertRaises(ValueError):
                validate_coordination('yoga-toolbar', selected, root)

    def test_sdk_requires_one_fixed_lane_and_shared_fast_coordination(self):
        from unittest.mock import patch
        import sys
        from types import SimpleNamespace
        fake = SimpleNamespace(LANES={'core': ('//codex-rs/core:core-unit-tests', 'fixed')})
        with patch.dict(sys.modules, codex_sdk_profile=fake):
            self.assertEqual(selected_profile('codex-sdk', ['test', '//codex-rs/core:core-unit-tests']), {'PrivateNetwork': 'yes'})
            for labels in (['test', '//...'], ['build', '//codex-rs/core:core-unit-tests'],
                           ['test', BUNDLE_FETCH_LABEL], ['test', HOME_MANAGER_FETCH_LABEL]):
                with self.assertRaises(ValueError):
                    selected_profile('codex-sdk', labels)
            with self.assertRaises(ValueError):
                selected_profile('codex-sdk', ['test', '//codex-rs/core:core-unit-tests'], site_inputs=True)
        fast = Path('/srv/fast-local/jess/state/codex/sdk-fast')
        self.assertEqual(validate_coordination('codex-sdk', COORDINATION_DIRECTORY, fast), COORDINATION_DIRECTORY)
        with self.assertRaises(ValueError):
            validate_coordination('codex-sdk', None, fast)

    def test_fresh_inputs_require_pair_and_finite_producer(self):
        from guard_dependency_profile import selected_fresh_inputs, PRISTINE_DIRECTORY, DELTA_DIRECTORY, FRESH_LABEL
        self.assertEqual(selected_fresh_inputs('standard', ['test', '//:other'], None, None, None), {})
        for profile, labels, pristine, delta in (
                ('standard', ['test', FRESH_LABEL], PRISTINE_DIRECTORY, None),
                ('standard', ['test', '//:other'], PRISTINE_DIRECTORY, DELTA_DIRECTORY),
                ('standard', ['test', FRESH_LABEL, '//...'], PRISTINE_DIRECTORY, DELTA_DIRECTORY),
                ('installed-browser', ['test', FRESH_LABEL], PRISTINE_DIRECTORY, DELTA_DIRECTORY)):
            with self.assertRaises(ValueError):
                selected_fresh_inputs(profile, labels, pristine, delta, None)

    def test_recovery_input_is_standard_only(self):
        self.assertEqual(selected_profile('standard', ['test', '//:producer'], recovery_input=True),
                         {'PrivateNetwork': 'yes'})
        for profile in ('dependency-prefetch', 'installed-browser'):
            with self.assertRaises(ValueError):
                selected_profile(profile, ['test', '//:producer'], recovery_input=True)

    def test_installed_browser_allows_site_inputs_but_requires_exact_label_and_no_pack(self):
        label = ['test', '//delivery:installed_chromium_test']
        self.assertEqual(selected_profile('installed-browser', label, site_inputs=True), {'PrivateNetwork': 'yes'})
        for args, pack in ((label, True), (['build', label[1]], False), (label + ['//:other'], False)):
            with self.assertRaises(ValueError):
                selected_profile('installed-browser', args, pack_input=pack)

    def test_network_permission_requires_one_exact_declared_producer(self):
        self.assertEqual(selected_profile('standard', ['test', '//:any']), {'PrivateNetwork': 'yes'})
        for label in (FETCH_LABEL, BUNDLE_FETCH_LABEL, HOME_MANAGER_FETCH_LABEL, GIT_FETCH_LABEL):
            with self.subTest(label=label):
                self.assertEqual(selected_profile('dependency-prefetch', ['test', label]), {'PrivateNetwork': 'no'})
                self.assertEqual(selected_profile('standard', ['test', label]), {'PrivateNetwork': 'yes'})
                for arguments in (['build', label], ['run', label], ['test', label, '//:extra'],
                                  ['test', label, label], ['test', label, '--test_arg=--shard-size=64'],
                                  ['test', '--test_arg=--shard-index=1', label],
                                  ['test', label, '--test_arg=--source-root=/unreviewed'],
                                  ['test', label, '--test_arg=--nix=/unreviewed/nix'],
                                  ['test', label, '--state-dir=/home/jess/other'],
                                  ['test', label, '--remote_executor=arbitrary']):
                    with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                        selected_profile('dependency-prefetch', arguments)
                for kwargs in ({'site_inputs': True}, {'pack_input': True}, {'recovery_input': True}):
                    with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                        selected_profile('dependency-prefetch', ['test', label], **kwargs)

    def test_network_permission_rejects_mixed_and_undeclared_lanes(self):
        for arguments in ([], ['test'], ['test', '//...'],
                          ['test', '//tools:codex_dependency_bundle_plan'],
                          ['test', FETCH_LABEL, BUNDLE_FETCH_LABEL],
                          ['test', BUNDLE_FETCH_LABEL, FETCH_LABEL],
                          ['test', '//codex-rs/core:core-unit-tests'],
                          ['test', '//tools:codex_dependency_bundle_producer_extra']):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                selected_profile('dependency-prefetch', arguments)
        labels = (FETCH_LABEL, BUNDLE_FETCH_LABEL, HOME_MANAGER_FETCH_LABEL, GIT_FETCH_LABEL)
        for first in labels:
            for second in labels:
                with self.subTest(first=first, second=second), self.assertRaises(ValueError):
                    selected_profile('dependency-prefetch', ['test', first, second])

    def test_home_manager_acquisition_does_not_admit_related_workloads(self):
        for label in ('//tools:home_manager_acquisition_test', '//tools:home_manager_source_probe',
                      '//tools:home_manager_qualified_evaluation',
                      '//tools:home_manager_acquisition_producer_extra'):
            with self.subTest(label=label), self.assertRaises(ValueError):
                selected_profile('dependency-prefetch', ['test', label])
        fixed_fast = Path('/srv/fast-local/jess/state/codex/omux-dependency-prefetch-20261005')
        self.assertEqual(validate_coordination('dependency-prefetch', COORDINATION_DIRECTORY, fixed_fast),
                         COORDINATION_DIRECTORY)
        for coordination, state in ((fixed_fast, fixed_fast), (None, fixed_fast),
                                    (COORDINATION_DIRECTORY, Path('/home/jess/.local/state/other'))):
            with self.subTest(coordination=coordination, state=state), self.assertRaises(ValueError):
                validate_coordination('dependency-prefetch', coordination, state)

    def test_dependency_lane_shares_the_existing_controller_lock(self):
        fast = Path('/srv/fast-local/jess/state/codex/omux-dependency-prefetch')
        self.assertEqual(validate_coordination('dependency-prefetch', COORDINATION_DIRECTORY, fast), COORDINATION_DIRECTORY)
        for selected, state in ((None, fast), (fast, fast), (COORDINATION_DIRECTORY, COORDINATION_DIRECTORY),
                                (COORDINATION_DIRECTORY, Path('/home/jess/other'))):
            with self.assertRaises(ValueError):
                validate_coordination('dependency-prefetch', selected, state)
        self.assertEqual(validate_coordination('standard', None, Path('/private/state')), Path('/private/state'))
        self.assertEqual(validate_coordination('standard', COORDINATION_DIRECTORY, fast),
                         COORDINATION_DIRECTORY)
        with self.assertRaises(ValueError):
            validate_coordination('standard', Path('/other/lock'), Path('/private/state'))
        with self.assertRaises(ValueError):
            validate_coordination('standard', COORDINATION_DIRECTORY, Path('/home/jess/other'))
        with self.assertRaises(ValueError):
            validate_coordination('dependency-prefetch', COORDINATION_DIRECTORY,
                                  Path('/srv/fast-local/jess/state/../elsewhere'))


if __name__ == '__main__':
    unittest.main()
