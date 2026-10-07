"""Synthetic update predicates only; no deployment or daemon interaction."""
import copy
import unittest

from update_plan import check_readback, plan_update


class UpdatePlanTests(unittest.TestCase):
    def setUp(self):
        self.current = {"schemaVersion": 1, "owner": "home-manager", "payload_verified": True,
                        "artifact": {"channel": "development", "target": "x86_64-linux", "manifestSha256": "a" * 64}}
        self.target = copy.deepcopy(self.current)
        self.target["artifact"].update(manifestSha256="b" * 64, compatibility={
            "schema_version": 1, "storage_read": [3], "storage_write": 3,
            "snapshot_read": [2], "snapshot_write": 2, "protocol_read": [2], "custody_formats": [1],
            "preserves_features": ["tombstones-v1", "credential-generations-v1", "replay-authority-v1"]})
        self.runtime = {"schema_version": 1, "authenticated": True, "custody_available": True,
                        "channel": "development", "instance": "dev", "artifact_digest": "a" * 64,
                        "protocol_version": 2, "storage_schema": 3, "snapshot_schema": 2, "custody_format": 1,
                        "revision": 7, "checkpoint_sequence": 9, "preservation_commitment": "c" * 64,
                        "active_work": 0, "required_features": ["tombstones-v1", "credential-generations-v1", "replay-authority-v1"],
                        "update_fence": {"id": "d" * 64, "expires_at": 120, "quiescent": True, "revision": 7}}

    def plan(self):
        return plan_update(self.current, self.target, self.runtime, 100)

    def test_compatible_proposal_never_authorizes_activation(self):
        self.assertEqual(self.plan()["decision"], "proposal")
        self.assertFalse(self.plan()["activation_authorized"])

    def test_missing_real_readback_or_fence_refuses(self):
        self.runtime["authenticated"] = False
        self.assertEqual(self.plan()["reason"], "runtime_readback_unavailable")
        self.runtime["authenticated"] = True
        del self.runtime["update_fence"]
        self.assertEqual(self.plan()["reason"], "update_fence_unavailable")

    def test_same_schema_without_preservation_capabilities_refuses(self):
        self.target["artifact"]["compatibility"]["preserves_features"] = ["tombstones-v1"]
        self.assertEqual(self.plan()["reason"], "preservation_capability_missing")

    def test_downgrade_checks_current_schema_and_never_restores_state(self):
        self.target["artifact"]["compatibility"]["storage_read"] = [2]
        self.assertEqual(self.plan()["reason"], "schema_incompatible")
        self.target["artifact"]["compatibility"]["storage_read"] = [3]
        self.target["artifact"]["compatibility"]["storage_write"] = 4
        self.assertEqual(self.plan()["reason"], "schema_incompatible")

    def test_context_changes_and_unknown_compatibility_refuse(self):
        self.target["artifact"]["channel"] = "release"
        self.assertEqual(self.plan()["reason"], "artifact_context_mismatch")
        self.target["artifact"]["channel"] = "development"
        del self.target["artifact"]["compatibility"]
        self.assertEqual(self.plan()["reason"], "compatibility_unknown")

    def test_expired_unbounded_or_busy_fence_refuses(self):
        for expiry in (100, 131):
            self.runtime["update_fence"]["expires_at"] = expiry
            self.assertEqual(self.plan()["reason"], "update_fence_expired_or_unbounded")
        self.runtime["update_fence"]["expires_at"] = 120
        self.runtime["active_work"] = 1
        self.assertEqual(self.plan()["reason"], "custody_not_quiescent")

    def test_post_readback_rejects_authority_restore_or_changed_commitment(self):
        proposal = self.plan()
        after = copy.deepcopy(self.runtime)
        after["artifact_digest"] = "b" * 64
        self.assertEqual(check_readback(proposal, after, 101)["decision"], "readback_predicates_passed")
        for field, value in (("checkpoint_sequence", 8), ("revision", 6), ("preservation_commitment", "e" * 64)):
            altered = dict(after, **{field: value})
            self.assertEqual(check_readback(proposal, altered, 101)["reason"], "custody_preservation_failed")
        self.assertEqual(check_readback(proposal, after, 120)["reason"], "update_fence_expired_or_unbounded")


if __name__ == "__main__":
    unittest.main()
