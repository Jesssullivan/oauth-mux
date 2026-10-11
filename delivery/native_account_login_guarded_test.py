"""A UI descriptor is selected after launch; never assume inherited FD 3."""
import os
import unittest
import native_account_login as core

class InProcessDescriptorTests(unittest.TestCase):
    def test_dynamic_pipe_is_the_pipe_passed_to_the_helper(self):
        held = []
        ui = None
        try:
            # Occupy lower slots so an inherited fd=3 assumption is observably wrong.
            held.extend(os.open("/dev/null",os.O_RDONLY) for _ in range(6))
            reader,writer = os.pipe2(os.O_CLOEXEC|os.O_NONBLOCK)
            held.extend((reader,writer))
            self.assertGreater(writer,3)
            ui = core.private_ui(writer)
            self.assertNotEqual(ui,writer)
            self.assertEqual((os.fstat(ui).st_dev,os.fstat(ui).st_ino),
                             (os.fstat(writer).st_dev,os.fstat(writer).st_ino))
            os.write(ui,b"nonsecret-offline-fixture\n")
            self.assertEqual(os.read(reader,128),b"nonsecret-offline-fixture\n")
        finally:
            if ui is not None:
                os.close(ui)
            for fd in reversed(held):
                os.close(fd)

if __name__ == "__main__":
    unittest.main()
