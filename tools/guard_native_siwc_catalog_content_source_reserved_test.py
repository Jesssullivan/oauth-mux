"""Actual new cohort/envelope/refusal wiring; no SDK or native qualification."""
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import execution_guard as guard
import guard_native_seed_plan_reserved as kernel
import guard_native_siwc_catalog_content_source_reserved as model
import guard_native_file_writer_models_reserved as old
import guard_native_siwc_catalog_source_reserved as historical


class CatalogContentReservationTests(unittest.TestCase):
    def args(self):
        return SimpleNamespace(profile=model.PROFILE, manager='system', reuse_owned_cache=False,
            source_commit='a'*40, source_dirty='false', repository_cache=None, nixpkgs_source=None)

    def test_only_exact_catalog_content_cohort_not_old_source_login19_or_native_children(self):
        self.assertTrue(model.request(self.args(), model.ARGUMENTS))
        for arguments in (old.ARGUMENTS, historical.ARGUMENTS, model.ARGUMENTS[:-1], list(reversed(model.ARGUMENTS)),
                model.ARGUMENTS + ['//:docs_check'], ['test','//codex-rs/core:core-unit-tests']):
            with self.assertRaises(ValueError): model.request(self.args(), arguments)
        with self.assertRaises(ValueError): old.selected(old.PROFILE, model.ARGUMENTS)
        self.assertNotIn(model.PROFILE, old.PROFILES)
        self.assertNotIn(model.PROFILE, historical.PROFILES)
        with self.assertRaises(ValueError): historical.selected(historical.PROFILE, model.ARGUMENTS)
        self.assertEqual(old.ARGUMENTS, ['test','//tools:codex_native_file_writer_model_source_test',
            '//tools:codex_native_file_writer_models_producer'])

    def test_original_actual_graph_clock_forwarded_to_repo_and_test_without_new_budget(self):
        entry, deadline = 100*10**9, 1300*10**9
        run = Path('/home/jess/.local/state/omux-execution-20261005/12345678-1234-1234-1234-123456789abc')
        with patch.object(kernel.time, 'monotonic_ns', return_value=200*10**9):
            command = model.command(guard.bazel_command, 'bazel', run, model.ARGUMENTS,
                model.PROFILE, entry, deadline, graph_sha256='b'*64, source_commit='a'*40, source_dirty='false')
            self.assertEqual(model.runtime_seconds(entry, deadline), 840)
        values = {model.MODE:model.INPUT_MODE, model.ENTRY:str(entry), model.DEADLINE:str(deadline),
            model.EPOCH:str(run), model.SOURCE:'a'*40, model.GRAPH:'b'*64}
        for key, value in values.items():
            for kind in ('repo_env','test_env'):
                self.assertEqual([v for v in command if v.startswith('--'+kind+'='+key+'=')], ['--'+kind+'='+key+'='+value])
        self.assertIn('--test_timeout=840', command)
        self.assertIn('--repository_disable_download', command)
        self.assertEqual(command[-2:], model.ARGUMENTS[1:])
        self.assertNotEqual(model.INPUT_MODE, model.PROFILE)
        self.assertEqual(model.INPUT_MODE, old.PROFILE)
        self.assertEqual(model.MEMORY, old.MEMORY); self.assertEqual(model.TASKS, old.TASKS)
        self.assertEqual(model.CPU, old.CPU)

    def test_expired_dirty_cache_reuse_and_foreign_epoch_refuse_before_builder(self):
        for name, value in (('source_dirty','true'),('reuse_owned_cache',True),('manager','user')):
            args = self.args(); setattr(args,name,value)
            with self.assertRaises(ValueError): model.request(args,model.ARGUMENTS)
        builder = Mock()
        with patch.object(kernel.time,'monotonic_ns',return_value=1300*10**9):
            with self.assertRaises(ValueError): model.command(builder,'bazel',Path('/foreign/epoch'),model.ARGUMENTS,
                model.PROFILE,100*10**9,1300*10**9,graph_sha256='b'*64,source_commit='a'*40,source_dirty='false')
        builder.assert_not_called()
        with patch.object(kernel.time,'monotonic_ns',return_value=200*10**9):
            with self.assertRaises(ValueError): model.command(builder,'bazel',Path('/foreign/epoch'),model.ARGUMENTS,
                model.PROFILE,100*10**9,1300*10**9,graph_sha256='b'*64,source_commit='a'*40,source_dirty='false')
        builder.assert_not_called()

    def test_coordinator_dispatch_rejects_wrong_vector_before_tool_reads_and_claims_stay_false(self):
        with patch.object(guard,'immutable',side_effect=AssertionError('tool read')) as tool:
            with self.assertRaises(ValueError): guard.main(['--profile',model.PROFILE,'--manager','system',
                '--source-commit','a'*40,'--source-dirty','false','--',*old.ARGUMENTS])
        tool.assert_not_called()
        report = model.projection(100*10**9,1300*10**9,None,None)
        self.assertEqual(report['scope'],'fixed-native-siwc-catalog-content-source-reserved-v1')
        self.assertFalse(report['native20_qualified_by_admission'])
        self.assertTrue(all(value is False for name,value in report.items() if name.endswith('_qualified')))


if __name__ == '__main__': unittest.main()
