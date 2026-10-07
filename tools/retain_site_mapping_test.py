import json
import unittest
from unittest.mock import patch
import retain_site_mapping as proof


class RetentionTest(unittest.TestCase):
    def fixture(self):
        result = {"passed": True, "sourceContentRehashed": True, "selectedOutputsMatched": True,
                  "provenance": proof.PROVENANCE, "realized": False, "browserExecuted": False,
                  "nixpkgsSourceNarHash": "sha256-bxrdOn8SCOv8tN4JbTF/TXq7kjo9ag4M+C8yzzIRYbE=",
                  "nixpkgsRevision": "1c3fe55ad329cbcb28471bb30f05c9827f724c76"}
        content = json.dumps(result).encode() + b"\n"
        log = content + b" " * (1073 - len(content))
        sha = proof.digest(log)
        manifest = json.dumps({"bazel_exit": 0, "results": [{"target": proof.TARGET,
            "state": "observed", "files": [{"source": "test.log", "state": "copied",
                "file": proof.FILE, "bytes": 1073, "sha256": sha}]}]}).encode()
        receipt = {"id": proof.EPOCH, "exit": 0, "workload_exit": 0, "descendants_empty": True,
                   "test_evidence": {"state": "preserved", "manifest": "test-evidence.json",
                                     "sha256": proof.digest(manifest)}}
        return receipt, manifest, log

    def test_exact_success_and_refusal(self):
        receipt, manifest, log = self.fixture()
        with patch.object(proof, "MANIFEST_SHA", proof.digest(manifest)), patch.object(proof, "LOG_SHA", proof.digest(log)):
            proof.validate(receipt, manifest, log)
            for key, value in (("id", "another-epoch"), ("exit", 125), ("descendants_empty", False)):
                altered = dict(receipt, **{key: value})
                with self.assertRaises(ValueError):
                    proof.validate(altered, manifest, log)
            with self.assertRaises(ValueError):
                proof.validate(receipt, manifest, log[:-1] + b"x")
            with self.assertRaises(ValueError):
                proof.validate(receipt, manifest + b" ", log)


if __name__ == "__main__":
    unittest.main()
