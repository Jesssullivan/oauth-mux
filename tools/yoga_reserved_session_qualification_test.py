"""Reserved held qualification models; synthetic metadata never supplies a seat."""
import copy
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
import yoga_reserved_session_qualification as reserved_qualification
import yoga_session_qualification as qualification
import guard_yoga_toolbar_reserved as reserved
import guard_yoga_installed_workspace as installed
from yoga_session_qualification_test import QualificationTests


class ReservedQualificationModels(unittest.TestCase):
    def fixture(self):
        fixture=QualificationTests('runTest');fixture.setUp()
        fixture.selection.update(scope=reserved.SELECTION_SCOPE,
            originalEntryMonotonicNs=fixture.deadline-1200*10**9,
            installedWorkspace={'path':fixture.source+'/installed-workspace.json','sha256':'4'*64})
        held=Mock()
        return fixture,held

    def test_reserved_producer_preserves_selected_pair_and_no_execution_claim(self):
        fixture,held=self.fixture()
        with patch.object(qualification,'produce',reserved_qualification.produce), \
             patch.object(installed,'Capture',return_value=held),patch.object(reserved,'capture') as custody:
            result,call,checks=fixture.produce()
        receipt=qualification.guard.decode(call.args[1])
        self.assertEqual(receipt['scope'],reserved.QUALIFICATION_SCOPE)
        self.assertEqual(receipt[reserved.CLOCK],fixture.selection[reserved.CLOCK])
        self.assertEqual(receipt['deadlineMonotonicNs'],fixture.deadline)
        self.assertEqual(receipt['installedWorkspace'],fixture.selection['installedWorkspace'])
        self.assertEqual(result[reserved.CLOCK],receipt[reserved.CLOCK])
        self.assertFalse(result['executionAuthority']);self.assertFalse(result['toolbarConsentProved'])
        custody.assert_called_once();held.close.assert_called_once();fixture.pin.close.assert_called_once()

    def test_clock_change_during_publication_refuses_and_closes_custody(self):
        fixture,held=self.fixture()
        def publication(path,payload,deadline,verify):
            verify()
            fixture.selection[reserved.CLOCK]+=10**9
            verify()
            raise AssertionError('changed clock was accepted')
        with patch.object(qualification,'produce',reserved_qualification.produce), \
             patch.object(installed,'Capture',return_value=held),patch.object(reserved,'capture'), \
             self.assertRaises(ValueError):
            fixture.produce(publication=publication)
        held.close.assert_called_once();fixture.pin.close.assert_called_once()

    def test_old_scope_and_missing_pair_refuse_before_live_identity(self):
        fixture,held=self.fixture()
        valid=copy.deepcopy(fixture.selection)
        for change in ({'scope':qualification.INSTALLED_SCOPE},{reserved.CLOCK:True},
                       {reserved.CLOCK:fixture.selection[reserved.CLOCK]+10**9}):
            fixture.selection={**valid,**change}
            with patch.object(qualification.os,'getuid',return_value=fixture.uid), \
                 patch.object(qualification.pwd,'getpwuid',return_value=SimpleNamespace(pw_dir='/home/operator')), \
                 patch.object(qualification,'read_selection',return_value=fixture.selection), \
                 patch.object(qualification,'identity_capture',side_effect=AssertionError('identity read')) as identity, \
                 patch.object(installed,'Capture',side_effect=AssertionError('inventory read')) as inventory, \
                 self.assertRaises(ValueError):
                reserved_qualification.produce(fixture.path,'1'*64,fixture.output,fixture.deadline)
            identity.assert_not_called();inventory.assert_not_called()
        with self.assertRaises(ValueError):
            qualification.validate_selection(valid,fixture.deadline,fixture.uid,Path('/home/operator'))


if __name__=='__main__':unittest.main()
