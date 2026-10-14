"""Synthetic bounded policy models; no seat, browser, operator or provider proof."""
import argparse
import copy
from pathlib import Path
import unittest
from unittest.mock import patch
import guard_native_seed_plan_reserved as kernel
import guard_yoga_toolbar_reserved as reserved


class ReservedToolbarModels(unittest.TestCase):
    def request(self):
        return argparse.Namespace(profile=reserved.PROFILE, manager='system', reuse_owned_cache=False,
            yoga_qualification=Path('/srv/model/qualification.json'), yoga_qualification_sha256='a'*64,
            yoga_deadline_monotonic_ns=1300*10**9)

    def test_exact_request_rejects_foreign_inputs_before_admission(self):
        args = self.request()
        with patch.object(reserved, 'preallocate', side_effect=AssertionError('local read')) as held:
            self.assertTrue(reserved.request(args, ['run', reserved.LABEL]))
            for edit in ({'manager':'user'}, {'reuse_owned_cache':True},
                {'source_commit':'a'*40}, {'source_dirty':'false'}, {'repository_cache':Path('/private/cache')},
                {'resident_vault_manifest':Path('/private/vault')}, {'yoga_qualification_sha256':'a'*63}):
                changed=argparse.Namespace(**{**vars(args), **edit})
                with self.assertRaises(ValueError): reserved.request(changed, ['run', reserved.LABEL])
            for vector in (['test', reserved.LABEL], ['run', reserved.LABEL, '--inside'], ['run','//:foreign']):
                with self.assertRaises(ValueError): reserved.request(args,vector)
            held.assert_not_called()

    def test_original_pair_is_held_not_reset_by_later_entry(self):
        value={reserved.CLOCK:100*10**9,'deadlineMonotonicNs':1300*10**9}
        with patch.object(kernel.time,'monotonic_ns',return_value=200*10**9):
            self.assertEqual(reserved.clock(value), (100*10**9,1300*10**9))
            self.assertEqual(reserved.runtime(*reserved.clock(value)),1070)
            for changed in ({reserved.CLOCK:200*10**9}, {'deadlineMonotonicNs':1400*10**9},
                {reserved.CLOCK:True}, {'deadlineMonotonicNs':True}):
                with self.assertRaises(ValueError): reserved.clock({**value, **changed})
            with self.assertRaises(ValueError): reserved.clock(value,1400*10**9)
        with patch.object(kernel.time,'monotonic_ns',return_value=1271*10**9):
            with self.assertRaises(ValueError): reserved.clock(value)
            self.assertEqual(reserved.clock(value,cleanup=True),(100*10**9,1300*10**9))

    def test_models_are_separate_exact_vector_without_live_inputs(self):
        args=argparse.Namespace(profile=reserved.MODEL_PROFILE,manager='system',reuse_owned_cache=False,
            source_commit='a'*40,source_dirty='false',repository_cache=None,nixpkgs_source=None)
        self.assertEqual(len(reserved.MODEL_ARGUMENTS),13)
        self.assertTrue(reserved.request(args,reserved.MODEL_ARGUMENTS))
        for value in (['test','//:docs_check'],reserved.MODEL_ARGUMENTS+['--untrusted'],['run',reserved.LABEL]):
            with self.assertRaises(ValueError):reserved.request(args,value)
        args.yoga_qualification=Path('/private/foreign')
        with self.assertRaises(ValueError):reserved.request(args,reserved.MODEL_ARGUMENTS)
        def builder(bazel,run,arguments,**options):
            self.assertEqual(options['profile'],'standard')
            return [bazel,*arguments]
        with patch.object(kernel.time,'monotonic_ns',return_value=200*10**9):
            result=reserved.command(builder,'bazel',Path('/srv/model'),reserved.MODEL_ARGUMENTS,
                reserved.MODEL_PROFILE,100*10**9,1300*10**9)
            self.assertIn('--repository_disable_download',result)
            with self.assertRaises(ValueError):reserved.command(builder,'bazel',Path('/srv/model'),
                ['run',reserved.LABEL],reserved.PROFILE,100*10**9,1300*10**9)
        projection=reserved.model_projection(100*10**9,1300*10**9,True,{})
        self.assertFalse(projection['browserInvoked']);self.assertFalse(projection['toolbarConsentProved'])

    def test_common_kernel_identity_and_caps(self):
        for name in ('Witness','WorkloadWitness','remaining','properties','monitor','cleanup_retained','release_worker'):
            self.assertIs(getattr(reserved,name),getattr(kernel,name))
        valid={'memory.max':str(reserved.MEMORY),'memory.swap.max':'0','pids.max':'480',
               'memory.oom.group':'1','cpu.max':'190000 100000'}
        reserved.verify_cgroup(valid)
        for name,value in [('memory.max',str(4*1024**3)),('pids.max','512'),('cpu.max','200000 100000'),
                           ('memory.swap.max','1'),('memory.oom.group','0')]:
            with self.assertRaises(ValueError): reserved.verify_cgroup({**valid,name:value})

    def test_fixed_plan_and_runtime_refuse_cap_clock_or_duration_changes(self):
        policy=reserved.policy(100*10**9,1300*10**9,1070)
        plan={'scope':reserved.PLAN_SCOPE,'deadlineNs':1300*10**9,'reservation':policy}
        with patch.object(kernel.time,'monotonic_ns',return_value=200*10**9):
            self.assertIs(reserved.plan(plan),policy)
            for name,value in [('memoryBytes',4*1024**3),('tasks',512),('cpuPercent',200),
                               ('runtimeSeconds',1200),(reserved.CLOCK,200*10**9)]:
                bad=copy.deepcopy(plan);bad['reservation'][name]=value
                with self.assertRaises(ValueError): reserved.plan(bad)
        for value in ('17min 50s','1070s','1070000ms','1070000000us'):
            reserved.verify_runtime(value,1070)
        for value in ('infinity','1200s','1069s','1070s junk','1070','-1070s'):
            with self.assertRaises(ValueError): reserved.verify_runtime(value,1070)

    def test_local_scopes_require_recorded_pair_and_preserve_old_validators(self):
        import yoga_session_qualification as qualification
        import guard_yoga_profile as guard
        value={key:None for key in qualification.INSTALLED_FIELDS}
        value.update(scope=reserved.SELECTION_SCOPE,originalEntryMonotonicNs=100*10**9,
                     deadlineMonotonicNs=1300*10**9)
        with patch.object(kernel.time,'monotonic_ns',return_value=200*10**9), \
             patch.object(qualification,'validate_selection',return_value=True) as old:
            self.assertIs(reserved.selection(value,1300*10**9,1000,Path('/home/model')),value)
            validated=old.call_args.args[0]
            self.assertEqual(validated['scope'],qualification.INSTALLED_SCOPE)
            self.assertNotIn(reserved.CLOCK,validated)
            self.assertEqual(value['scope'],reserved.SELECTION_SCOPE)
            for change in ({'scope':qualification.INSTALLED_SCOPE},{reserved.CLOCK:200*10**9},{'foreign':True}):
                with self.assertRaises(ValueError): reserved.selection({**value,**change},1300*10**9,1000,Path('/home/model'))
        receipt={key:None for key in guard.INSTALLED_FIELDS}
        receipt.update(scope=reserved.QUALIFICATION_SCOPE,originalEntryMonotonicNs=100*10**9,
                       deadlineMonotonicNs=1300*10**9)
        with patch.object(kernel.time,'monotonic_ns',return_value=200*10**9),patch.object(guard,'schema') as old:
            self.assertIs(reserved.schema(receipt,1300*10**9,'/srv/model',{},'a'*64,1000),receipt)
            self.assertEqual(old.call_args.args[0]['scope'],guard.INSTALLED_SCOPE)
            self.assertNotIn(reserved.CLOCK,old.call_args.args[0])

    def test_every_final_join_must_pass_before_reserved_consent_projection(self):
        yoga={'executionPassed':True,'toolbarConsentProved':True,'machineObservationsJoined':True,
              'humanGestureProvenance':'operator-attested'}
        for name in yoga:
            changed=dict(yoga);changed[name]=False
            self.assertFalse(reserved.projection(100*10**9,1300*10**9,True,{},changed,0)['toolbarConsentProved'])
        for verified,exit in ((False,0),(True,125),(False,125)):
            self.assertFalse(reserved.projection(100*10**9,1300*10**9,verified,{},yoga,exit)['toolbarConsentProved'])
        value=reserved.projection(100*10**9,1300*10**9,True,{},yoga,0)
        self.assertTrue(value['toolbarConsentProved'])
        for name in ('providerAuthorityProved','normalVaultCustodyProved','nativeContinuityProved'):
            self.assertFalse(value[name])

    def test_late_original_deadline_refusal_clears_every_receipt_consent_flag(self):
        yoga={'executionPassed':True,'toolbarConsentProved':True,'machineObservationsJoined':True,
              'humanGestureProvenance':'operator-attested'}
        for now,verified,expected in ((1299*10**9,True,0),(1300*10**9,True,125),(1299*10**9,False,125)):
            receipt={'profile':reserved.PROFILE,'exit':0,
                     'yoga':{'toolbarConsentProved':True,'summary':dict(yoga)}}
            with patch.object(kernel.time,'monotonic_ns',return_value=now):
                self.assertIs(reserved.finalize(receipt,100*10**9,1300*10**9,verified,{}),receipt)
            self.assertEqual(receipt['exit'],expected)
            for proof in (receipt['yoga']['toolbarConsentProved'],receipt['yoga']['summary']['toolbarConsentProved'],
                          receipt['yoga_toolbar_reservation']['toolbarConsentProved']):
                self.assertIs(proof,expected==0)


if __name__=='__main__':unittest.main()
