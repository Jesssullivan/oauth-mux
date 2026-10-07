import unittest
from unittest.mock import patch
import guard_yoga_delivery_profile as profile

class ProfileTests(unittest.TestCase):
    def test_fixed_state_and_existing_home_coordinator(self):
        args = ['run','//tools:yoga_controller_qualify']
        self.assertEqual(profile.coordination(profile.COORDINATION,profile.STATE,args),profile.COORDINATION)
        for coordination,state in ((profile.STATE,profile.STATE),(profile.COORDINATION,profile.COORDINATION)):
            with self.assertRaises(ValueError): profile.coordination(coordination,state,args)

    def test_provider_free_fixed_labels_and_no_flags(self):
        for label in profile.MODES:
            self.assertEqual(profile.selected(['run',label]),{'PrivateNetwork':'no'})
        for args in (['test','//tools:yoga_controller_qualify'],['run','//tools:yoga_controller_copy'],
                     ['run','//tools:yoga_controller_qualify','--','--seconds','1200']):
            with self.assertRaises(ValueError): profile.selected(args)
        with self.assertRaises(ValueError): profile.selected(['run','//tools:yoga_controller_qualify'],site=True)

    def test_deadline_origin_and_prior_digest_rules(self):
        with patch('time.monotonic_ns',return_value=100*10**9):
            result = profile.envelope(1200*10**9,['run','//tools:yoga_controller_qualify'])
            self.assertEqual(result['OMUX_YOGA_DELIVERY_DEADLINE_NS'],str(1200*10**9))
            self.assertNotIn('OMUX_YOGA_DELIVERY_AUTHORITY_SHA256',result)
            with self.assertRaises(ValueError): profile.envelope(1301*10**9,['run','//tools:yoga_controller_qualify'])
            with self.assertRaises(ValueError): profile.envelope(130*10**9,['run','//tools:yoga_controller_qualify'])
            with self.assertRaises(ValueError): profile.envelope(1200*10**9,['run','//tools:yoga_controller_qualify'],'a'*64)
            with self.assertRaises(ValueError): profile.envelope(1200*10**9,['run','//tools:yoga_controller_inspect'])
            result = profile.envelope(1200*10**9,['run','//tools:yoga_controller_verify'],'a'*64)
            self.assertEqual(result['OMUX_YOGA_DELIVERY_AUTHORITY_SHA256'],'a'*64)
            self.assertIn('--run_env=OMUX_YOGA_DELIVERY_DEADLINE_NS='+str(1200*10**9),profile.run_options(result))

if __name__ == '__main__': unittest.main()
