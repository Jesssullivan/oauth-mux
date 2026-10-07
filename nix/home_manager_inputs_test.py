import copy
import unittest
from home_manager_inputs import PINS, paired_sources


class PairedInputsTests(unittest.TestCase):
    def setUp(self):
        self.lock = {"root": "root", "nodes": {"root": {"inputs": {"home-manager": "hm", "nixpkgs": "np"}}}}
        self.inputs = {}
        for name, node in (("home-manager", "hm"), ("nixpkgs", "np")):
            revision, nar_hash = PINS[name]
            self.lock["nodes"][node] = {"locked": {"rev": revision, "narHash": nar_hash}}
            self.inputs[name] = {"schemaVersion": 1, "revision": revision, "narHash": nar_hash,
                                 "source": "/nix/store/" + "a" * 32 + "-" + node}
        self.lock["nodes"]["hm"]["inputs"] = {"nixpkgs": ["nixpkgs"]}

    def test_bindings_are_not_nar_proof(self):
        self.assertTrue(all(x["verification"] == "pending-byte-hash" for x in paired_sources(self.lock, self.inputs).values()))

    def test_wrong_revision_and_path_refused(self):
        for name in PINS:
            for key, value in (("revision", "b" * 40), ("source", "/tmp/source")):
                inputs = copy.deepcopy(self.inputs)
                inputs[name][key] = value
                with self.assertRaises(ValueError):
                    paired_sources(self.lock, inputs)

    def test_different_follow_refused(self):
        self.lock["nodes"]["hm"]["inputs"]["nixpkgs"] = ["other"]
        with self.assertRaises(ValueError):
            paired_sources(self.lock, self.inputs)


if __name__ == "__main__":
    unittest.main()
