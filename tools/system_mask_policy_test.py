"""Pure diagnostic policy predicates; no mounts, managers or workload execution."""
import unittest
from system_mask_policy import OPTIONS, paths, setting, verify_effective


class MaskTest(unittest.TestCase):
    def test_site_masks_require_bluetooth_and_separate_file_mask(self):
        # /etc/environment is a regular file and is checked by the controller's
        # InaccessiblePaths readback, not an invalid tmpfs directory mount.
        value = setting('/home/fixture', profile='site')
        self.assertIn('/etc/bluetooth:' + OPTIONS, value)
        self.assertNotIn('/etc/environment:', value)
        verify_effective(value, '/home/fixture', profile='site')
        with self.assertRaises(ValueError):
            verify_effective(setting('/home/fixture'), '/home/fixture', profile='site')

    def test_browser_profile_requires_its_fixed_extra_mask(self):
        value = setting('/home/fixture', profile='installed-browser')
        self.assertIn('/etc/bluetooth:' + OPTIONS, value)
        verify_effective(value, '/home/fixture', profile='installed-browser')
        with self.assertRaises(ValueError):
            verify_effective(setting('/home/fixture'), '/home/fixture', profile='installed-browser')
        with self.assertRaises(ValueError):
            verify_effective(value, '/home/fixture')
        with self.assertRaises(ValueError):
            setting('/home/fixture', profile='arbitrary')

    def test_exact_masked_coverage(self):
        self.assertEqual(paths('/home/fixture'), ('/run', '/nix/var/nix/daemon-socket',
                         '/home/fixture/.config/sops-nix/secrets/become'))
        verify_effective(setting('/home/fixture'), '/home/fixture')
        verify_effective(setting('/home/fixture').replace('mode=000', 'mode=0').replace('size=1M', 'size=1048576'), '/home/fixture')

    def test_mutable_unbounded_and_incomplete_masks_refused(self):
        original = setting('/home/fixture')
        bad = ('', original.replace('ro,', 'rw,'), original.replace('mode=000', 'mode=700'),
               original.replace('size=1M', 'size=4G'), original + ' /other:' + OPTIONS,
               original + ' /run:' + OPTIONS, ' '.join(original.split()[:-1]),
               original.replace('ro,mode', 'ro,nosuid,mode'),
               original.replace('size=1M', 'size=1M,size=1M'))
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    verify_effective(value, '/home/fixture')

    def test_relative_and_ambiguous_home_refused(self):
        for home in ('relative', '/home/../other', '/home/name with space'):
            with self.assertRaises(ValueError):
                paths(home)


if __name__ == '__main__':
    unittest.main()
