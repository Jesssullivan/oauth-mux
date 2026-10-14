"""Exact new TEST adapter gates; no project process, service or network IO."""
from pathlib import Path
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import guard_yoga_sealed_transfer_models_reserved as model

class AdmissionModels(unittest.TestCase):
    def args(self):
        return SimpleNamespace(profile=model.PROFILE,manager='system',source_commit='a'*40,
            source_dirty='false',repository_cache=None,nixpkgs_source=None)

    def test_exact_test_vector_and_order_only(self):
        self.assertEqual(model.selected(model.PROFILE,list(model.MODELS)),{'PrivateNetwork':'yes'})
        for vector in (['run',model.MODELS[1]],model.MODELS[:-1],model.MODELS+['//...'],
            [model.MODELS[0],*reversed(model.MODELS[1:])]):
            with self.assertRaises(ValueError): model.selected(model.PROFILE,vector)

    def test_closed_manager_source_and_unrelated_arguments(self):
        with patch('guard_resident_enrollment_profile.repository_inputs') as repository:
            self.assertTrue(model.request(self.args(),model.MODELS)); repository.assert_called_once_with(None,None)
        for key,value in (('manager','user'),('source_dirty','true'),('source_commit','unknown'),
            ('yoga_qualification','private'),('reuse_owned_cache',True)):
            args=self.args(); setattr(args,key,value)
            with self.assertRaises(ValueError): model.request(args,model.MODELS)

    def test_command_retains_fixed_vector_and_offline_options(self):
        entry=time.monotonic_ns(); deadline=entry+1200*10**9
        observed=[]
        def builder(bazel,root,arguments,**kwargs):
            observed.append((bazel,root,arguments,kwargs)); return [bazel,'test',*arguments[1:]]
        with patch('guard_resident_enrollment_profile.repository_inputs'):
            result=model.command(builder,'/fixed/bazel',Path('/fixed/run'),model.MODELS,model.PROFILE,entry,deadline)
        self.assertEqual(result,['/fixed/bazel','test','--repository_disable_download','--repo_contents_cache=',*model.MODELS[1:]])
        self.assertEqual(observed[0][3],{'profile':'standard'})

    def test_runtime_requires_actual_exact_value(self):
        model.verify_runtime('10s',10)
        for actual in ('9s','11s','infinity'):
            with self.assertRaises(ValueError): model.verify_runtime(actual,10)

    def test_model_projection_never_claims_transfer_or_human_proof(self):
        value=model.projection(1,1+1200*10**9,True,{'samples':1})
        for name in ('provider_invoked','browser_invoked','ssh_invoked','workspace_transferred',
            'destination_registration_qualified','seat_qualified','toolbar_consent_proved'):
            self.assertIs(value[name],False)
        self.assertTrue(value['verified_after_cleanup'])

if __name__=='__main__': unittest.main()
