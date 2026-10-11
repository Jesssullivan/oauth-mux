"""Selected resident proof composition; no installation or service lifecycle.

Used only by a separately admitted resident RUN after real profile/peer/runtime
qualification. This module has no executable entry point, credential reader,
adapter channel or source enrollment path.
"""
from __future__ import annotations
import copy
import os
import re
import time

import test_installed_codex_live_continuity as live

HANDLE = re.compile(r"[0-9a-f]{64}\Z")
SCOPE = "resident_operator_drain_same_process_completed_turn_substitution"


def require(value):
    live.require(value, "resident completed-turn qualification refused")


def selected_handles(value):
    require(isinstance(value, list) and len(value) == 2)
    selected = copy.deepcopy(value)
    fields = {"account_handle", "source_handle", "grant_handle", "grant_generation"}
    for row in selected:
        require(isinstance(row, dict) and set(row) == fields)
        require(all(isinstance(row[key], str) and HANDLE.fullmatch(row[key])
                    for key in fields - {"grant_generation"}))
        require(type(row["grant_generation"]) is int
                and 0 < row["grant_generation"] < 2**64)
    for key in fields - {"grant_generation"}:
        require(len({row[key] for row in selected}) == 2)
    return selected


def exact_row(rows, key, value):
    require(isinstance(rows, list))
    matches = [row for row in rows if isinstance(row, dict) and row.get(key) == value]
    require(len(matches) == 1)
    return matches[0]


def not_expired(value, now):
    return value is None or (type(value) is int and value > now)


def selected_domain(snapshot, selected, drained=None):
    """Qualify metadata from the actual control response, without rewriting it."""
    require(isinstance(snapshot, dict) and snapshot.get("protocol_version") == 2
            and snapshot.get("custody_available") is True)
    now = snapshot.get("captured_at")
    require(type(snapshot.get("revision")) is int and 0 <= snapshot["revision"] < 2**64)
    require(type(now) is int and 0 <= now <= int(time.time()) + 5)
    require(int(time.time()) - now <= 10)
    allowed = {row["account_handle"] for row in selected}
    require(drained is None or drained in allowed)
    for row in selected:
        account = exact_row(snapshot["accounts"], "id", row["account_handle"])
        source = exact_row(snapshot["sources"], "id", row["source_handle"])
        grant = exact_row(snapshot["grants"], "id", row["grant_handle"])
        require(account.get("identity", {}).get("provider") == "codex"
                and account.get("identity", {}).get("verified") is True
                and account.get("lifecycle") ==
                    ("draining" if row["account_handle"] == drained else "active")
                and row["source_handle"] in account.get("source_ids", []))
        require(source.get("provider") == "codex" and source.get("kind") == "native_store"
                and source.get("status") == "connected"
                and type(source.get("authorized_at")) is int
                and 0 <= source["authorized_at"] <= now
                and not_expired(source.get("authorized_until"), now))
        require(grant.get("account_id") == row["account_handle"]
                and grant.get("source_id") == row["source_handle"]
                and type(grant.get("generation")) is int
                and grant.get("generation") == row["grant_generation"]
                and grant.get("credential_kind") == "oauth_access"
                and grant.get("ownership") == "external" and grant.get("status") == "ready"
                and grant.get("audience") == "https://chatgpt.com"
                and "request" in grant.get("purposes", [])
                and not_expired(grant.get("provider_expires_at"), now)
                and type(grant.get("custody_expires_at")) is int
                and grant["custody_expires_at"] > now)
        # Current native acquire does not accept a per-binding account/grant
        # allowlist. Refuse an ambiguous usable grant, without changing policy.
        usable = [item for item in snapshot["grants"]
                  if item.get("account_id") == row["account_handle"]
                  and item.get("status") == "ready" and "request" in item.get("purposes", [])
                  and item.get("audience") == "https://chatgpt.com"
                  and not_expired(item.get("provider_expires_at"), now)
                  and not_expired(item.get("custody_expires_at"), now)]
        require(len(usable) == 1 and usable[0]["id"] == row["grant_handle"])
    # Unrelated provider accounts are retained. Other active Codex accounts
    # would make this narrow selected-two-account proof nondeterministic.
    active_codex = {row["id"] for row in snapshot["accounts"]
                    if row.get("identity", {}).get("provider") == "codex"
                    and row.get("lifecycle") == "active"}
    require(active_codex == allowed - ({drained} if drained else set()))
    return snapshot


def same_reference(actual, expected):
    if not isinstance(actual, dict) or not isinstance(expected, dict):
        return False
    if set(actual) != set(expected):
        return False
    try:
        owner = live.support.fixed_bytes(actual["owner_id"], 32).hex()
        return owner == expected["owner_id"] and all(
            str(actual[key]) == expected[key] for key in expected if key != "owner_id")
    except (ValueError, TypeError, KeyError):
        return False


class ResidentScenario(live.LiveScenario):
    """Keep the native acceptance algorithm; replace only isolated enrollment.

    The controller pins/rechecks real daemon/socket/install identity separately.
    This class cannot issue an installation, attach, source mutation or adapter
    request. Explicit account-wide drain authorization retains its disposition.
    """

    def __init__(self, model, handles, runtime_pin, *, allow_account_wide_drain,
                 drain_account_handle):
        require(allow_account_wide_drain is True)
        super().__init__({"model": model}, "fresh", runtime_pin)
        self.selected = selected_handles(handles)
        self.accounts = [row["account_handle"] for row in self.selected]
        require(drain_account_handle == self.accounts[0])
        self.drain_account_handle = drain_account_handle
        self.sources = [row["source_handle"] for row in self.selected]
        self.drained = None
        self.native_ref = None
        self.thread = None
        self.route_observations = {}

    def configure(self, config):
        # The actual reversible integration producer owns config setup.
        raise ValueError("resident proof cannot rewrite native configuration")

    def enroll(self, cli):
        raise ValueError("resident proof cannot enroll account sources")

    def check_domain(self, snapshot):
        return selected_domain(snapshot, self.selected, self.drained)

    def audit(self, cli, thread, native_ref):
        snapshot = self.check_domain(cli("state.snapshot"))
        audit = super().audit(cli, thread, native_ref)
        for row in audit["records"]:
            sequence = row["first"]["issued_sequence"]
            require(type(sequence) is int and 0 < sequence < 2**64)
        if audit["records"]:
            ordered = sorted(audit["records"], key=lambda row: row["first"]["issued_sequence"])
            require(ordered[0]["first"]["account_handle"] == self.drain_account_handle)
        if audit.get("binding") is not None:
            route = audit["binding"]["route_generation"]
            require(type(route) is int and 0 < route < 2**64)
            bindings = [row for row in snapshot["bindings"]
                        if row.get("application") == "codex"
                        and row.get("session_id") == thread
                        and same_reference(row.get("native_ref"), native_ref)]
            require(len(bindings) == 1)
            binding = bindings[0]
            selected = exact_row(self.selected, "account_handle", binding["account_id"])
            require(binding["grant_id"] == selected["grant_handle"]
                    and type(binding["grant_generation"]) is int
                    and 0 < binding["grant_generation"] < 2**64
                    and binding["grant_generation"] == selected["grant_generation"]
                    and type(binding["route_generation"]) is int
                    and 0 < binding["route_generation"] < 2**64
                    and binding["account_id"] == audit["binding"]["account_handle"]
                    and binding["route_generation"] == audit["binding"]["route_generation"])
            # Private current-route cross-check, not historical lease authority.
            if not audit["pending_requests"] and not audit["pending_outcomes"]:
                self.route_observations[binding["account_id"]] = copy.deepcopy(binding)
                require(len(self.route_observations) <= 2)
        return audit

    def mutate(self, cli, method, params):
        require(method == "account.drain" and set(params) == {"account_id"}
                and params["account_id"] == self.drain_account_handle and self.drained is None
                and self.native_ref is not None and self.thread is not None)
        snapshot = self.check_domain(cli("state.snapshot"))
        account = params["account_id"]
        audit = self.audit(cli, self.thread, self.native_ref)
        require(len(audit["records"]) == 1 and not audit["pending_requests"]
                and not audit["pending_outcomes"] and audit["binding"] is not None
                and audit["binding"]["account_handle"] == account)
        first = audit["records"][0]
        require(first["alternate"] is None and first["first"]["state"] == "completed"
                and first["first"]["account_handle"] == account
                and first["first"]["accepted_report"] is not None
                and first["first"]["terminal_report"] is not None)
        require(snapshot["leases"] == [])
        require(not any(not (row.get("application") == "codex"
                                 and row.get("session_id") == self.thread
                                 and same_reference(row.get("native_ref"), self.native_ref))
                        for row in snapshot["bindings"]))
        health = cli("system.health")
        require(health["custody_available"] is True
                and health["request_authority"]["remaining"] >= 1
                and health["request_authority"]["snapshot_bytes_remaining"] >= 32768
                and health["mutation_authority"]["guaranteed_admissions_remaining"] >= 1)
        operation = os.urandom(32).hex()
        # One acknowledged mutation. A lost/ambiguous reply aborts this proof;
        # never issue a new operation ID or silently restore account lifecycle.
        result = cli(method, {**params, "operation_id": operation,
                              "expected_revision": snapshot["revision"]})
        require(result.get("updated") is True)
        self.drained = account
        self.check_domain(cli("state.snapshot"))
        return result

    def prove_attached(self, cli, recheck_resident, home, thread, terminal,
                       endpoint, observed, baseline, candidate, receipt):
        """Composition only; guarded caller owns real observations and native UI.

        recheck_resident must throw on actual peer/pidfs/service/install drift;
        no boolean assertion from a manifest can satisfy that observer.
        The caller writes a distinct closed resident receipt only after its
        final native cleanup and service observation. This returns raw private
        proof data in memory and never publishes a receipt itself.
        """
        self.native_ref, self.thread = observed["nativeRef"], thread
        require(self.native_ref is not None)
        reads = {"system.health", "state.snapshot", "integrations.nativeRequestAudit"}
        def control(method, params=None):
            require(method in reads or method == "account.drain")
            recheck_resident()
            result = cli(method, params or {})
            recheck_resident()
            return result
        health = control("system.health")
        require(health["protocol_version"] == 2 and health["custody_available"] is True
                and health["request_authority"]["remaining"] >= 2
                and health["request_authority"]["snapshot_bytes_remaining"] >= 65536
                and health["mutation_authority"]["guaranteed_admissions_remaining"] >= 1)
        self.check_domain(control("state.snapshot"))
        result, completed = super().prove_same_process(control, home, thread, terminal, endpoint,
                                          observed, baseline, candidate, receipt)
        self.check_domain(control("state.snapshot"))
        recheck_resident()
        require(self.drained is not None and set(self.route_observations) == set(self.accounts))
        # Do not emit the superclass isolated receipt as a resident success.
        return {"native_result": result, "completed_history": completed,
                "resident_scope": SCOPE, "account_drain_disposition": "retained",
                "private_current_route_cross_checks": copy.deepcopy(list(self.route_observations.values()))}
