"""Modern evaluation role boundaries; never synthetic actual lineage proof."""
import time
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import codex_native_acquisition_material as material

class MaterialTests(unittest.TestCase):
    def test_real_ledger_relative_snapshot_joins_absolute_retained_role(self):
        import codex_native_acquisition_compilation as compiler
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); deadline=float(time.monotonic()+20)
            document={'material':{'fixture':'not-an-actual-qualified-source'},
                'controller_inventory_sha256':'a'*64}
            carrier={'native_dispatch_ledger':{'aggregate_maximum':8,'dispatched':8,
                'current_dispatch':8,'remaining':0}}
            raw=compiler.encoded(carrier);pin=hashlib.sha256(raw).hexdigest()
            relative=compiler.GOAL_SNAPSHOT_PREFIX+pin+'.json'
            physical=root/relative;physical.parent.mkdir(parents=True)
            physical.write_bytes(raw);physical.chmod(0o444)
            snapshot={'path':relative,'sha256':pin,'bytes':len(raw)}
            wrapper={'schema_version':1,'kind':'omux-native-acquisition-root-dispatch-ledger-v1',
                'actor':'Root','phase':'after-pre-action-advancement','aggregate':8,'dispatched':8,
                'remaining':0,'material_sha256':hashlib.sha256(compiler.encoded(document['material'])).hexdigest(),
                'controller_inventory_sha256':'a'*64,
                'compiler_controller':{'source_commit':'f'*40,'graph_sha256':'e'*64},
                'goal_snapshot':snapshot}
            encoded=compiler.encoded(wrapper);ledger=root/'ledger.json'
            ledger.write_bytes(encoded);ledger.chmod(0o444)
            document['ledger']={'path':str(ledger),'sha256':hashlib.sha256(encoded).hexdigest()}
            with mock.patch.object(compiler,'PUBLIC_ROOT',root):
                verified=compiler.ledger(document,deadline)
                retained={'path':material.selected_role_path('compiler_ledger_snapshot',verified['goal_snapshot']),
                    'sha256':pin,'bytes':len(raw)}
                material._member(retained)
                self.assertEqual(retained['path'],str(physical))
                with self.assertRaises(ValueError):
                    material._member({**retained,'path':relative})
                for wrong in ('../private.json',str(physical),compiler.GOAL_SNAPSHOT_PREFIX+'b'*64+'.json'):
                    with self.assertRaises(ValueError):
                        material.selected_role_path('compiler_ledger_snapshot',{**snapshot,'path':wrong})

    def test_legacy_and_summary_documents_fail_before_reads(self):
        with mock.patch.object(material,'validate_selection') as validate:
            for value in ({'schema_version':1,'kind':'legacy','files':{}},
                    {'material_family':'native-acquisition-evaluation-v1','compiler_qualified':True},
                    {'schema_version':1,'kind':material.PACKAGE_KIND,'purpose':'deployment'}):
                with self.assertRaises(ValueError):material.validate_paths(value)
            validate.assert_not_called()

    def test_member_contract_refuses_bool_bytes_escape_and_unpinned_data(self):
        good={'path':'/fixture/receipt.json','sha256':'a'*64,'bytes':1}
        material._member(good)
        for row in ({**good,'bytes':True},{**good,'path':'/fixture/../outside'},
                    {**good,'sha256':'unconfigured'},{**good,'bytes':0},
                    {**good,'role':'compiler'}):
            with self.assertRaises(ValueError):material._member(row)

    def test_original_deadline_mandatory_not_a_reset(self):
        for deadline in (None,time.monotonic()+60,int(time.monotonic()+60)):
            if type(deadline) is float:
                material.tick(deadline)
            else:
                with self.assertRaises(ValueError):material.tick(deadline)
        with self.assertRaises(ValueError):material.tick(float(time.monotonic()-1))

if __name__=='__main__':unittest.main()
