import unittest
from unittest.mock import patch
import guard_current_home_manager_artifact_reserved as guard

class AdmissionTest(unittest.TestCase):
    def test_exact_vectors_and_cross_family_refusal(self):
        for profile,vector in guard.VECTORS.items():
            self.assertEqual(guard.selected(profile,vector),{'PrivateNetwork':'yes'})
            for bad in (vector[:-1],vector+['//:omux'],['run']+vector[1:],list(reversed(vector))):
                with self.assertRaises(ValueError): guard.selected(profile,bad)
        with self.assertRaises(ValueError): guard.selected('standard',guard.VECTORS[guard.PROFILE])

    def test_original_clock_transport_and_offline(self):
        for profile in (guard.PROFILE,guard.EVALUATE):
            def builder(*args,**kwargs): return ['bazel']+guard.VECTORS[profile]
            with patch.object(guard,'remaining'), patch('guard_resident_enrollment_profile.repository_inputs'), \
                    patch('execution_guard.graph_digest',return_value=('b'*64,None)):
                command=guard.command(builder,'bazel','run',guard.VECTORS[profile],profile,
                    1,1200000000001,source_commit='a'*40,source_dirty='false')
            self.assertIn('--test_env=OMUX_CURRENT_HM_MODE='+profile,command)
            self.assertIn('--test_env=OMUX_CURRENT_HM_ENTRY_NS=1',command)
            self.assertIn('--test_env=OMUX_CURRENT_HM_DEADLINE_NS=1200000000001',command)
            self.assertIn('--repository_disable_download',command)
            self.assertIn('--repo_contents_cache=',command)
            self.assertIn(guard.VECTORS[profile][1],command)

    def test_projections_never_promote_artifact_or_activation(self):
        value=guard.projection(guard.PROFILE,1,1200000000001,True,{'active':True})
        for key in ('shipped','artifact_qualified','activation_qualified','browser_qualified',
                    'custody_qualified','health_qualified','continuity_qualified','live_qualified'):
            self.assertIs(value[key],False)

if __name__=='__main__': unittest.main()
