"""Finite ninth plan/query boundaries; fixtures confer no actual proof."""
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock
import codex_native_acquisition_preflight as preflight

class PreflightTests(unittest.TestCase):
    def test_absent_sdk_refuses_before_any_material_read(self):
        with mock.patch.object(preflight.binding,'config',return_value={'sdk':None}), \
                mock.patch.object(preflight.material,'validate_selection') as validate:
            with self.assertRaises(ValueError):preflight.selected_material()
            validate.assert_not_called()

    def test_query_uses_only_actual_ninth_sdk_and_cold_fixed_targets(self):
        document={'source':{'root':'/fixture/ninth'},'sdk':{'root':'/fixture/sdk'}}
        hub=preflight.metadata.metadata.HUB
        exported={'registry_cache':'/fixture/sdk/registry-cache',
            'repositories':{hub:'/fixture/sdk/repositories/'+hub,'tool':'/fixture/sdk/repositories/tool'}}
        with mock.patch.object(preflight.material,'validate_selection',return_value=document):
            plan=preflight.query_plan(Path('/fixture/work'),document,exported)
            self.assertEqual(plan['cwd'],'/fixture/ninth/source')
            self.assertIn('--remote_executor=',plan['argv'])
            self.assertIn('--remote_cache=',plan['argv'])
            self.assertIn('--repository_disable_download',plan['argv'])
            self.assertEqual(plan['argv'][-1],'set('+' '.join(preflight.compilation.TARGETS)+')')
            self.assertEqual(plan['argv'].count('query'),1)
            for replacement in ('/fixture/legacy/repositories/tool','/fixture/sdk/repositories/other'):
                wrong={**exported,'repositories':{**exported['repositories'],'tool':replacement}}
                with self.assertRaises(ValueError):preflight.query_plan(Path('/fixture/work'),document,wrong)

    def test_expired_original_deadline_and_wrong_mode_read_nothing(self):
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(preflight.metadata,'configure_selection') as configure, \
                mock.patch.object(preflight.material,'qualify_selection') as qualify:
            root=Path(tmp)
            for mode,deadline in (('query',float(time.monotonic()-1)),('build',float(time.monotonic()+60))):
                with self.assertRaises(ValueError):
                    preflight.produce(mode,{},root/'work',root/'output',deadline,root/'repository')
            configure.assert_not_called();qualify.assert_not_called()
            self.assertFalse((root/'work').exists());self.assertFalse((root/'output').exists())

if __name__=='__main__':unittest.main()
