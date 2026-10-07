"""Adversarial, isolated cross-file documentation contract fixtures."""

import json
import os
from pathlib import Path
import tempfile
import unittest

import docs_check


class DocumentationContractTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR"))
        self.addCleanup(self.scratch.cleanup)
        self.root = Path(self.scratch.name)
        self.manifest = {
            "schema_version": 1,
            "architecture": "docs/current.md",
            "current": ["docs/current.md", "docs/adr.md"],
            "historical_inventory": "docs/history/inventory.md",
            "historical_extra": [],
            "historical_prefixes": ["docs/history/"],
            "acceptance_families": [{"path": "docs/current.md", "pattern": "SC-[0-9]+", "ids": ["SC-01", "SC-02"]}],
            "decisions": [{"path": "docs/adr.md", "id": "ADR-001"}],
            "milestone_ledger": ".goal/checkpoints.json",
        }
        self.body = "# Current\n\n| SC-01 | First |\n| SC-02 | Second |\n\nSee ADR-001 and [receipt](receipt.json).\n"
        self.write("docs/current.md", self.body)
        self.write("docs/adr.md", "# ADR-001 — Native direction\n")
        self.write("docs/receipt.json", "{}")
        self.write("docs/history/inventory.md", "| `docs/history/old.md` | Retained |\n")
        self.write("docs/history/old.md", "[obsolete](missing.md)\n```sh\njust historical\n```\n")
        self.ledger = {
            "schema_version": 1,
            "authority": "docs/current.md",
            "automatic_dispatch": False,
            "independent_active_goals": False,
            "timezone": "America/New_York",
            "start": "2026-10-03T03:41:49Z",
            "milestones": [
                {"id": "h3", "due": "2026-10-03T06:41:49Z", "status": "planned", "evidence": []},
                {"id": "h5", "due": "2026-10-03T08:41:49Z", "status": "planned", "depends_on": ["h3"], "evidence": []},
                {"id": "h10", "due": "2026-10-03T13:41:49Z", "status": "planned", "depends_on": ["h3", "h5"], "evidence": []},
                {"id": "weekend", "due": "2026-10-05T03:59:00Z", "status": "planned", "depends_on": ["h10"], "evidence": []},
            ],
        }
        self.save_ledger()

    def write(self, path, body):
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(body)

    def save_ledger(self):
        self.write(self.manifest["milestone_ledger"], json.dumps(self.ledger))

    def reject_graph(self, message):
        with self.assertRaisesRegex(docs_check.ContractError, message):
            docs_check.check_graph(self.root, self.manifest)

    def reject_acceptance(self, message):
        with self.assertRaisesRegex(docs_check.ContractError, message):
            docs_check.check_acceptance(self.root, self.manifest)

    def reject_ledger(self, message):
        self.save_ledger()
        with self.assertRaisesRegex(docs_check.ContractError, message):
            docs_check.check_milestones(self.root, self.manifest)

    def test_valid_graph_including_historical_exceptions(self):
        self.assertEqual(docs_check.check_graph(self.root, self.manifest), (2, 1, 1))
        self.assertEqual(docs_check.check_acceptance(self.root, self.manifest), 3)
        self.assertEqual(docs_check.check_milestones(self.root, self.manifest), 4)

    def test_deleted_acceptance_and_references_still_rejected(self):
        self.write("docs/current.md", self.body.replace("| SC-02 | Second |\n", ""))
        self.reject_acceptance("stable acceptance inventory changed")

    def test_renumbered_acceptance_and_references_still_rejected(self):
        self.write("docs/current.md", (self.body + "See SC-02.\n").replace("SC-02", "SC-03"))
        self.reject_acceptance("stable acceptance inventory changed")

    def test_unknown_adr_reference(self):
        self.write("docs/current.md", self.body + "See ADR-999.\n")
        self.reject_acceptance("undeclared acceptance ADR-999")

    def test_renumbered_adr_title(self):
        self.write("docs/adr.md", "# ADR-002 — Renumbered\n")
        self.reject_acceptance("stable ADR identifier changed")

    def test_current_historical_overlap(self):
        self.manifest["historical_extra"] = ["docs/current.md"]
        self.reject_graph("historical/current overlap")

    def test_unclassified_document(self):
        self.write("docs/new.md", "Unclassified direction")
        self.reject_graph("unclassified document")

    def test_broken_crossfile_link(self):
        (self.root / "docs/receipt.json").unlink()
        self.reject_graph("missing link target docs/receipt.json")

    def test_retired_document_returned(self):
        self.write("docs/history/inventory.md", "| `docs/retired.md` | Deleted |\n")
        self.write("docs/retired.md", "Returned obsolete direction")
        self.reject_graph("retired document returned")

    def test_retired_commands_with_fences_and_prefixes(self):
        cases = [
            ("", "zig build"),
            ("console", "$ just check"),
            ("sh", "env MODE=fixture zig build"),
            ("bash", "sudo zig build"),
            ("shell", "nix develop --command zig build"),
            ("text", "nix develop --command env MODE=fixture ./scripts/check.sh"),
            ("sh", "sh -c 'just check'"),
        ]
        for fence, command in cases:
            with self.subTest(fence=fence, command=command):
                self.write("docs/current.md", self.body + f"```{fence}\n{command}\n```\n")
                self.reject_graph("retired executable example")

    def test_legitimate_nix_bazel_commands_allowed(self):
        self.write("docs/current.md", self.body + "```sh\nnix develop --command bazelisk test //:docs_check\nnix develop --command bazelisk build //...\n```\n")
        docs_check.check_graph(self.root, self.manifest)

    def test_false_pass_without_evidence(self):
        self.ledger["milestones"][0]["status"] = "passed"
        self.reject_ledger("completion without evidence")

    def test_nonexistent_evidence(self):
        self.ledger["milestones"][0].update(status="passed", evidence=[{"kind": "document", "path": "docs/missing.md"}])
        self.reject_ledger("nonexistent/nonportable evidence")

    def test_fabricated_unstructured_evidence(self):
        self.ledger["milestones"][0].update(status="passed", evidence=["trust me"])
        self.reject_ledger("unstructured evidence")

    def test_fabricated_local_check_missing_invocation(self):
        self.ledger["milestones"][0].update(status="passed", evidence=[{"kind": "local_check", "path": "docs/current.md", "command": "nix develop --command bazelisk test //...", "result": "passed"}])
        self.reject_ledger("missing invocation ID")

    def test_non_bazel_or_failed_local_receipt(self):
        for command, result in [("zig build", "passed"), ("nix develop --command bazelisk test //...", "failed")]:
            with self.subTest(command=command, result=result):
                self.ledger["milestones"][0].update(status="passed", evidence=[{"kind": "local_check", "path": "docs/current.md", "invocation_id": "12345678-1234-1234-1234-123456789abc", "command": command, "result": result}])
                self.reject_ledger("undeclared/unpassed local check")

    def test_removed_required_dependency(self):
        self.ledger["milestones"][1].pop("depends_on")
        self.reject_ledger("required dependency changed")

    def test_valid_uuid_without_recorded_invocation_is_rejected(self):
        self.ledger["milestones"][0].update(status="passed", evidence=[{
            "kind": "local_check", "path": "docs/current.md",
            "invocation_id": "12345678-1234-1234-1234-123456789abc",
            "command": "nix develop --command bazelisk test //...", "result": "passed",
        }])
        self.reject_ledger("invocation absent from referenced receipt")

    def test_recorded_local_check_is_accepted(self):
        invocation = "12345678-1234-1234-1234-123456789abc"
        self.write("docs/check-receipt.md", "Recorded invocation " + invocation)
        self.ledger["milestones"][0].update(status="passed", evidence=[{
            "kind": "local_check", "path": "docs/check-receipt.md",
            "invocation_id": invocation,
            "command": "nix develop --command bazelisk test //...", "result": "passed",
        }])
        self.save_ledger()
        self.assertEqual(docs_check.check_milestones(self.root, self.manifest), 4)

    def test_recorded_clean_environment_local_check_is_accepted(self):
        invocation = "12345678-1234-1234-1234-123456789abc"
        self.write("docs/check-receipt.md", "Recorded invocation " + invocation)
        self.ledger["milestones"][0].update(status="passed", evidence=[{
            "kind": "local_check", "path": "docs/check-receipt.md",
            "invocation_id": invocation,
            "command": "nix develop --ignore-environment --keep HOME --command bazelisk --nosystem_rc --nohome_rc test //...",
            "result": "passed",
        }])
        self.save_ledger()
        self.assertEqual(docs_check.check_milestones(self.root, self.manifest), 4)

    def test_clean_environment_receipt_does_not_allow_arbitrary_nix_flags(self):
        for options in ("--ignore-environment --keep API_TOKEN", "--ignore-environment --keep HOME --keep API_TOKEN"):
            with self.subTest(options=options):
                self.ledger["milestones"][0].update(status="passed", evidence=[{
                    "kind": "local_check", "path": "docs/current.md",
                    "invocation_id": "12345678-1234-1234-1234-123456789abc",
                    "command": "nix develop " + options + " --command bazelisk test //...",
                    "result": "passed",
                }])
                self.reject_ledger("undeclared/unpassed local check")

    def test_wrong_hour_deadline(self):
        self.ledger["milestones"][1]["due"] = "2026-10-03T09:41:49Z"
        self.reject_ledger("incorrect deadline h5")

    def test_invalid_status(self):
        self.ledger["milestones"][0]["status"] = "done"
        self.reject_ledger("invalid status h3")

    def test_pass_with_unmet_predecessor(self):
        self.ledger["milestones"][1].update(status="passed", evidence=[{"kind": "document", "path": "docs/current.md"}])
        self.reject_ledger("unmet dependency")

    def test_valid_structured_pass(self):
        self.ledger["milestones"][0].update(status="passed", evidence=[{"kind": "document", "path": "docs/current.md"}])
        self.save_ledger()
        self.assertEqual(docs_check.check_milestones(self.root, self.manifest), 4)

    def sprint_fixture(self):
        self.manifest["sprint_ledgers"] = [".goal/sprint.json"]
        return {
            "schema_version": 1, "kind": "implementation_sprint_checkpoint",
            "authority": "docs/current.md", "start": "2026-10-03T10:07:56Z",
            "due": "2026-10-03T15:07:56Z", "duration_hours": 5,
            "status": "in_progress", "automatic_dispatch": False,
            "independent_active_goals": False,
            "claim": "experimental_unshipped_live_continuity_unavailable",
            "acceptance": [{"id": "safety", "issues": ["TIN-5337"], "status": "in_progress"}],
        }

    def test_sprint_checkpoint_does_not_reuse_ratification_pass(self):
        sprint = self.sprint_fixture()
        self.write(".goal/sprint.json", json.dumps(sprint))
        self.assertEqual(docs_check.check_sprints(self.root, self.manifest), 1)
        sprint["status"] = "passed"
        self.write(".goal/sprint.json", json.dumps(sprint))
        with self.assertRaisesRegex(docs_check.ContractError, "incomplete acceptance"):
            docs_check.check_sprints(self.root, self.manifest)

    def test_sprint_deadline_and_dispatch_cannot_change_silently(self):
        for key, value, message in (("due", "2026-10-03T14:07:56Z", "incorrect sprint deadline"),
                                    ("automatic_dispatch", True, "invents dispatch"),
                                    ("claim", "live_supported", "promotes support")):
            with self.subTest(key=key):
                sprint = self.sprint_fixture()
                sprint[key] = value
                self.write(".goal/sprint.json", json.dumps(sprint))
                with self.assertRaisesRegex(docs_check.ContractError, message):
                    docs_check.check_sprints(self.root, self.manifest)

    def test_sprint_blocker_requires_action_and_pass_requires_receipt(self):
        sprint = self.sprint_fixture()
        for status, message in (("blocked", "lacks next action"), ("passed", "completion without evidence")):
            with self.subTest(status=status):
                sprint["acceptance"][0].update(status=status, evidence=[])
                self.write(".goal/sprint.json", json.dumps(sprint))
                with self.assertRaisesRegex(docs_check.ContractError, message):
                    docs_check.check_sprints(self.root, self.manifest)

    def test_sprint_acceptance_ids_are_unique(self):
        sprint = self.sprint_fixture()
        sprint["acceptance"] *= 2
        self.write(".goal/sprint.json", json.dumps(sprint))
        with self.assertRaisesRegex(docs_check.ContractError, "duplicate/missing sprint acceptance"):
            docs_check.check_sprints(self.root, self.manifest)


if __name__ == "__main__":
    unittest.main()
