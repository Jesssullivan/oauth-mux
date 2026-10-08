"""Provider-free selected resident metadata/refusal models."""
import copy
import time
import unittest
from unittest import mock

import resident_codex_live_composition as resident


def domain():
    now = int(time.time())
    handles = [{"account_handle": account * 64, "source_handle": source * 64,
                "grant_handle": grant * 64, "grant_generation": 7}
               for account, source, grant in (("a", "c", "e"), ("b", "d", "f"))]
    snapshot = {"protocol_version": 2, "custody_available": True, "captured_at": now,
                "revision": 17, "accounts": [], "sources": [], "grants": [],
                "leases": [], "bindings": []}
    for row in handles:
        snapshot["accounts"].append({"id": row["account_handle"],
            "identity": {"provider": "codex", "verified": True}, "lifecycle": "active",
            "source_ids": [row["source_handle"]]})
        snapshot["sources"].append({"id": row["source_handle"], "provider": "codex",
            "kind": "native_store", "status": "connected", "authorized_at": now - 1,
            "authorized_until": now + 900})
        snapshot["grants"].append({"id": row["grant_handle"],
            "account_id": row["account_handle"], "source_id": row["source_handle"],
            "generation": 7, "credential_kind": "oauth_access", "ownership": "external",
            "status": "ready", "audience": "https://chatgpt.com",
            "purposes": ["request", "account_read"], "provider_expires_at": now + 900,
            "custody_expires_at": now + 900})
    return snapshot, handles


class ResidentSelectedDomainTest(unittest.TestCase):
    def test_preserves_unrelated_provider_records_without_global_two_account_requirement(self):
        snapshot, handles = domain()
        snapshot["accounts"].append({"id": "1" * 64,
            "identity": {"provider": "github"}, "lifecycle": "active", "source_ids": []})
        before = copy.deepcopy(snapshot)
        self.assertIs(snapshot, resident.selected_domain(snapshot, handles))
        self.assertEqual(snapshot, before)

    def test_ready_account_labels_cannot_replace_exact_source_grant_join(self):
        changes = (
            lambda snapshot: snapshot["grants"][0].update(source_id="0" * 64),
            lambda snapshot: snapshot["grants"][0].update(generation=8),
            lambda snapshot: snapshot["grants"][0].update(generation=True),
            lambda snapshot: snapshot["grants"][0].update(ownership="omux"),
            lambda snapshot: snapshot["grants"][0].update(custody_expires_at=None),
            lambda snapshot: snapshot["grants"][0].pop("custody_expires_at"),
            lambda snapshot: snapshot["grants"][0].update(custody_expires_at=True),
            lambda snapshot: snapshot["grants"][0].update(custody_expires_at=0),
            lambda snapshot: snapshot["sources"][0].update(authorized_until=0),
            lambda snapshot: snapshot["accounts"][0].update(identity={"provider": "github"}),
            lambda snapshot: snapshot["accounts"][0].update(identity={"provider": "codex", "verified": False}),
            lambda snapshot: snapshot["accounts"][0].update(identity={"provider": "codex"}),
            lambda snapshot: snapshot["accounts"][0].update(identity={"provider": "codex", "verified": 1}),
        )
        for change in changes:
            snapshot, handles = domain()
            change(snapshot)
            with self.subTest(change=change), self.assertRaises(Exception):
                resident.selected_domain(snapshot, handles)

    def test_other_active_codex_and_ambiguous_grants_refuse_without_mutating_policy(self):
        for more in ("account", "grant"):
            snapshot, handles = domain()
            if more == "account":
                snapshot["accounts"].append({"id": "1" * 64, "lifecycle": "active",
                    "identity": {"provider": "codex"}, "source_ids": []})
            else:
                alternate = copy.deepcopy(snapshot["grants"][0])
                alternate["id"] = "1" * 64
                snapshot["grants"].append(alternate)
            before = copy.deepcopy(snapshot)
            with self.subTest(more=more), self.assertRaises(Exception):
                resident.selected_domain(snapshot, handles)
            self.assertEqual(snapshot, before)

    def test_only_acknowledged_selected_drain_disposition_is_allowed(self):
        snapshot, handles = domain()
        snapshot["accounts"][0]["lifecycle"] = "draining"
        with self.assertRaises(Exception):
            resident.selected_domain(snapshot, handles)
        resident.selected_domain(snapshot, handles, handles[0]["account_handle"])
        with self.assertRaises(Exception):
            resident.selected_domain(snapshot, handles, handles[1]["account_handle"])

    def test_exact_native_generation_and_owner_are_required(self):
        actual = {"owner_id": [7] * 32, "adapter_epoch": 2, "endpoint_generation": 3,
                  "thread_instance_generation": 4, "attachment_generation": 5}
        expected = {**{key: str(value) for key, value in actual.items() if key != "owner_id"},
                    "owner_id": bytes([7] * 32).hex()}
        self.assertTrue(resident.same_reference(actual, expected))
        for field in actual:
            changed = copy.deepcopy(actual)
            changed[field] = [8] * 32 if field == "owner_id" else actual[field] + 1
            with self.subTest(field=field):
                self.assertFalse(resident.same_reference(changed, expected))

    def test_duplicate_account_or_source_is_not_independent_account_authority(self):
        _, handles = domain()
        for field in ("account_handle", "source_handle", "grant_handle"):
            changed = copy.deepcopy(handles)
            changed[1][field] = changed[0][field]
            with self.subTest(field=field), self.assertRaises(Exception):
                resident.selected_handles(changed)

    def test_drain_authority_for_a_never_issues_mutation_for_b(self):
        _, handles = domain()
        scenario = resident.ResidentScenario("public-test-model", handles, "/public-pin",
            allow_account_wide_drain=True, drain_account_handle=handles[0]["account_handle"])
        calls = []
        def cli(method, params=None):
            calls.append((method, params))
            raise AssertionError("unauthorized account reached control transport")
        with self.assertRaises(Exception):
            scenario.mutate(cli, "account.drain", {"account_id": handles[1]["account_handle"]})
        self.assertEqual(calls, [])

    def drain_fixture(self, *, failure=None, foreign=None, first_account=None):
        snapshot, handles = domain()
        scenario = resident.ResidentScenario("public-test-model", handles, "/public-pin",
            allow_account_wide_drain=True, drain_account_handle=handles[0]["account_handle"])
        scenario.thread = "10000000-0000-4000-8000-000000000001"
        scenario.native_ref = {"owner_id": "07" * 32, "adapter_epoch": "2",
            "endpoint_generation": "3", "thread_instance_generation": "4", "attachment_generation": "5"}
        binding = {"application": "codex", "session_id": scenario.thread,
            "native_ref": {**scenario.native_ref, "owner_id": [7] * 32},
            "account_id": handles[0]["account_handle"], "grant_id": handles[0]["grant_handle"],
            "grant_generation": 7, "route_generation": 9}
        snapshot["bindings"] = [binding]
        if foreign == "lease":
            snapshot["leases"] = [{"account_id": handles[1]["account_handle"]}]
        elif foreign == "binding":
            snapshot["bindings"].append({**binding, "session_id": "another-native-session"})
        audit = {"schema_version": 1, "thread_id": scenario.thread, "native_ref": scenario.native_ref,
            "pending_requests": False, "pending_outcomes": False,
            "binding": {"account_handle": handles[0]["account_handle"], "route_generation": 9},
            "records": [{"alternate": None, "first": {"issued_sequence": 1, "state": "completed",
                "account_handle": first_account or handles[0]["account_handle"],
                "accepted_report": {"event": "accepted"}, "terminal_report": {"event": "completed"}}}]}
        calls = []
        def control(method, params=None):
            calls.append((method, copy.deepcopy(params)))
            if method == "state.snapshot":
                return copy.deepcopy(snapshot)
            if method == "integrations.nativeRequestAudit":
                return copy.deepcopy(audit)
            if method == "system.health":
                return {"custody_available": True,
                    "request_authority": {"remaining": 1, "snapshot_bytes_remaining": 32768},
                    "mutation_authority": {"guaranteed_admissions_remaining": 1}}
            self.assertEqual(method, "account.drain")
            if failure:
                raise ValueError(failure)
            snapshot["accounts"][0]["lifecycle"] = "draining"
            snapshot["revision"] += 1
            return {"updated": True}
        return scenario, control, calls, handles

    def test_actual_selected_drain_uses_original_revision_and_one_operation(self):
        scenario, control, calls, handles = self.drain_fixture()
        result = scenario.mutate(control, "account.drain", {"account_id": handles[0]["account_handle"]})
        self.assertEqual(result, {"updated": True})
        mutations = [params for method, params in calls if method == "account.drain"]
        self.assertEqual(len(mutations), 1)
        self.assertEqual(mutations[0]["account_id"], handles[0]["account_handle"])
        self.assertEqual(mutations[0]["expected_revision"], 17)
        self.assertRegex(mutations[0]["operation_id"], r"^[0-9a-f]{64}$")
        self.assertEqual(scenario.drained, handles[0]["account_handle"])
        with self.assertRaises(ValueError):
            scenario.mutate(control, "account.drain", {"account_id": handles[0]["account_handle"]})
        self.assertEqual(len([method for method, _ in calls if method == "account.drain"]), 1)

    def test_lost_ack_or_stale_revision_never_retry_or_restore(self):
        for failure in ("ambiguous acknowledgement", "stale revision"):
            with self.subTest(failure=failure):
                scenario, control, calls, handles = self.drain_fixture(failure=failure)
                with self.assertRaises(ValueError):
                    scenario.mutate(control, "account.drain", {"account_id": handles[0]["account_handle"]})
                self.assertIsNone(scenario.drained)
                self.assertEqual([method for method, _ in calls if method.startswith("account.")],
                                 ["account.drain"])

    def test_foreign_held_work_and_wrong_first_account_refuse_before_mutation(self):
        for foreign in ("lease", "binding", "wrong_first"):
            with self.subTest(foreign=foreign):
                scenario, control, calls, handles = self.drain_fixture(
                    foreign=foreign, first_account="b" * 64 if foreign == "wrong_first" else None)
                with self.assertRaises(ValueError):
                    scenario.mutate(control, "account.drain", {"account_id": handles[0]["account_handle"]})
                self.assertFalse(any(method.startswith("account.") for method, _ in calls))

    def test_current_binding_grant_generation_is_required_without_historical_claim(self):
        scenario, control, calls, handles = self.drain_fixture()
        def changed(method, params=None):
            result = control(method, params)
            if method == "state.snapshot":
                result["bindings"][0]["grant_generation"] = 8
            return result
        with self.assertRaises(ValueError):
            scenario.audit(changed, scenario.thread, scenario.native_ref)
        self.assertEqual(scenario.route_observations, {})

    def test_actual_binding_and_audit_authority_reject_bool_as_generation_one(self):
        for field in ("grant", "binding_route", "audit_route", "issued_sequence"):
            with self.subTest(field=field):
                scenario, control, calls, handles = self.drain_fixture()
                scenario.selected[0]["grant_generation"] = 1
                def changed(method, params=None):
                    value = control(method, params)
                    if method == "state.snapshot":
                        value["grants"][0]["generation"] = 1
                        value["bindings"][0]["grant_generation"] = True if field == "grant" else 1
                        value["bindings"][0]["route_generation"] = True if field == "binding_route" else 1
                    elif method == "integrations.nativeRequestAudit":
                        value["binding"]["route_generation"] = True if field == "audit_route" else 1
                        value["records"][0]["first"]["issued_sequence"] = True if field == "issued_sequence" else 1
                    return value
                with self.assertRaises(ValueError):
                    scenario.audit(changed, scenario.thread, scenario.native_ref)
                self.assertEqual(scenario.route_observations, {})


if __name__ == "__main__":
    unittest.main()
