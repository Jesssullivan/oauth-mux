"""Pure proof-join tests; no candidate executable, host config or store access."""
import copy
import base64
import json
import stat
import unittest
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

import browser_runtime_authority as authority


class AuthorityTests(unittest.TestCase):
    def setUp(self):
        self.root = "/nix/store/" + "0" * 32 + "-chromium-147.0.7727.116"
        self.systemd_roots = sorted("/nix/store/" + alias.split("/")[1] for alias in authority.SYSTEMD_ALIASES)
        self.inventory = {"schemaVersion": 1, "system": "x86_64-linux", "mode": "local-sqlite-readonly-snapshot",
                          "contentRehashed": False, "realized": False, "published": False,
                          "roots": [self.root], "packages": {name: {"out": self.root} for name in
                              ("node", "python", "pnpm", "bash", "coreutils", "chromium")},
                          "paths": [{"path": self.root, "narSize": 42, "references": [authority.BLUEZ_ROOT] + self.systemd_roots},
                                    {"path": authority.BLUEZ_ROOT, "narSize": 1, "references": []}]
                                    + [{"path": root, "narSize": 1, "references": []} for root in self.systemd_roots]}
        self.inventory_bytes = authority.canonical(self.inventory)
        # Synthetic inventory only: keep real production input pins intact.
        self.inventory_pin = patch.object(authority, "INVENTORY_SHA256", authority.digest(self.inventory_bytes))
        self.inventory_pin.start()
        self.addCleanup(self.inventory_pin.stop)
        self.mapping = {"schemaVersion": 1, "passed": True, "mode": "shared-selection-offline-evaluation",
                        "provenance": {"rootsSha256": authority.ROOTS_SHA256, "lockSha256": authority.LOCK_SHA256,
                                       "selectionSha256": authority.SELECTION_SHA256, "flakeSha256": authority.FLAKE_SHA256},
                        "sourceInputSha256": "1" * 64, "nixpkgsRevision": authority.REVISION,
                        "nixpkgsSourceNarHash": authority.SOURCE_NAR_HASH,
                        "sourceContentRehashed": True, "selectedOutputsMatched": True,
                        "evaluationStore": "private-local-temporary", "evaluationStoreByteLimit": 1024**3,
                        "wholeFlakeEvaluated": False, "realized": False, "browserExecuted": False}
        self.nar = {"schemaVersion": 1, "passed": True, "inventorySha256": authority.INVENTORY_SHA256,
                    "descriptorSha256": "2" * 64, "verifiedPaths": 4, "verifiedRegularInputs": 1,
                    "verifiedNarBytes": 45, "contentRehashed": True, "linkTargetsFollowed": False,
                    "executionAuthority": False, "flakeMappingVerified": False, "realized": False}
        self.exclusions = authority.canonical({"schemaVersion": 1, "policy": authority.EXCLUSION_POLICY,
            "executionAuthority": False, "exclusions": [
                {"alias": "closure/" + authority.BLUEZ_ROOT.split("/")[-1] + "/etc/bluetooth/" + name + ".conf",
                 "policy": authority.EXCLUSION_POLICY, "reason": "inert host configuration link; excluded from execution inputs",
                 "target_class": "host-configuration", "target_followed": False}
                for name in ("input", "main", "network")]
                + [{"alias": alias, "reason": "operator runtime environment configuration; not an action input"}
                   for alias in sorted(authority.SYSTEMD_ALIASES)]})

    def joined(self, mapping=None, nar=None):
        mapping_content = b"bounded Bazel banner\n" + authority.canonical(mapping or self.mapping) + b"\n"
        nar_content = authority.canonical(nar or self.nar)
        exclusions = self.exclusions
        return authority.join(self.inventory_bytes, mapping_content, nar_content, exclusions,
                              authority.digest(mapping_content), authority.digest(nar_content), authority.digest(exclusions))

    def test_two_prior_receipts_join_without_broadening_scope(self):
        value = authority.validate_authority(authority.canonical(self.joined()))
        self.assertEqual(value["storePaths"], sorted([self.root, authority.BLUEZ_ROOT] + self.systemd_roots))
        self.assertEqual(value["requiredUnavailablePaths"], ["/etc/bluetooth", "/etc/environment"])
        self.assertIs(value["providerAccess"], False)
        self.assertIs(value["productionExport"], False)
        self.assertIs(value["manualPopupConsentProven"], False)
        self.assertNotIn("bounded Bazel banner", json.dumps(value))

    def test_failed_or_unrelated_receipts_never_join(self):
        for field, incorrect in (("passed", False), ("contentRehashed", False),
                                 ("verifiedNarBytes", 41), ("inventorySha256", "3" * 64),
                                 ("linkTargetsFollowed", True), ("executionAuthority", True)):
            altered = dict(self.nar, **{field: incorrect})
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.joined(nar=altered)
        for field, incorrect in (("passed", False), ("selectedOutputsMatched", False),
                                 ("browserExecuted", True), ("nixpkgsRevision", "0" * 40)):
            altered = dict(self.mapping, **{field: incorrect})
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.joined(mapping=altered)

    def test_previous_flake_mapping_remains_historical(self):
        altered = copy.deepcopy(self.mapping)
        altered["provenance"]["flakeSha256"] = "237d394ea17115bb418e078596f7700d614fb4634f377f121a775eaaf5ae7be9"
        with self.assertRaises(ValueError):
            self.joined(mapping=altered)

    def test_tampered_join_payload_or_removed_mask_is_rejected(self):
        original = self.joined()
        for change in (lambda value: value.update(providerAccess=True),
                       lambda value: value.update(requiredUnavailablePaths=[]),
                       lambda value: value["proofs"]["nar"]["receipt"].update(verifiedPaths=3),
                       lambda value: value.update(storePaths=[self.root, "/nix/store/" + "4" * 32 + "-undeclared"]),
                       lambda value: value["proofs"].pop("mapping")):
            value = copy.deepcopy(original)
            change(value)
            with self.assertRaises(ValueError):
                authority.validate_authority(authority.canonical(value))

    def test_sha_mismatch_and_multiple_receipt_lines_are_refused(self):
        content = authority.canonical(self.mapping)
        with self.assertRaises(ValueError):
            authority.join(self.inventory_bytes, content, authority.canonical(self.nar), self.exclusions,
                           "f" * 64, authority.digest(authority.canonical(self.nar)), authority.digest(self.exclusions))
        with self.assertRaises(ValueError):
            authority.receipt_from_input(content + b"\n" + content + b"\n")
        with self.assertRaises(ValueError):
            authority.parse(b'{"passed":true,"passed":false}')

    def test_generic_alias_exemptions_are_refused(self):
        for alias in ("closure/" + "0" * 32 + "-bluez-5.85/etc/bluetooth/main.conf",
                      "closure/" + "0" * 32 + "-bluez-5.86/etc/bluetooth/secret.conf",
                      "closure/" + "0" * 32 + "-bluez-5.86/etc/other.conf"):
            entries = json.loads(self.exclusions)["exclusions"]
            entries[0]["alias"] = alias
            with self.subTest(alias=alias), self.assertRaises(ValueError):
                authority.validate_exclusions(entries, [self.root, authority.BLUEZ_ROOT] + self.systemd_roots)

    def test_systemd_allowlist_never_admits_other_roots_or_link_metadata(self):
        paths = [self.root, authority.BLUEZ_ROOT] + self.systemd_roots
        for mutate in (lambda item: item.update(alias=item["alias"].replace("260.1", "260.2")),
                       lambda item: item.update(target_followed=False),
                       lambda item: item.update(reason="arbitrary runtime exemption")):
            entries = json.loads(self.exclusions)["exclusions"]
            mutate(entries[3])
            with self.assertRaises(ValueError):
                authority.validate_exclusions(entries, paths)

    def test_declared_exclusions_cli_retains_byte_digest_and_exact_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = {"inventory": self.inventory_bytes, "mapping": authority.canonical(self.mapping),
                     "nar": authority.canonical(self.nar), "exclusions": self.exclusions}
            for name, content in files.items():
                (root / name).write_bytes(content)
            arguments = ["producer"]
            for name in files:
                arguments += ["--" + name, str(root / name)]
            arguments += ["--mapping-sha256", authority.digest(files["mapping"]),
                          "--nar-sha256", authority.digest(files["nar"]), "--declared-exclusions",
                          "--out", str(root / "authority")]
            with patch("sys.argv", arguments):
                authority.main()
            value = authority.validate_authority((root / "authority").read_bytes())
            self.assertEqual(value["exclusionsInputSha256"], authority.digest(self.exclusions))
            altered = json.loads(self.exclusions)
            altered["exclusions"][0]["target_followed"] = True
            (root / "exclusions").write_bytes(authority.canonical(altered))
            (root / "authority").unlink()
            with patch("sys.argv", arguments), self.assertRaises(ValueError):
                authority.main()
            self.assertFalse((root / "authority").exists())
            with patch("sys.argv", arguments + ["--exclusions-sha256", "0" * 64]), self.assertRaises(SystemExit):
                authority.main()


class RuntimeRootTests(unittest.TestCase):
    # Independent known NAR vector from the pinned qualified inventory. Tests
    # mock metadata only; no actual store object is read, changed or executed.
    ROOT = "/nix/store/0xw7b9d5gdp28dzn0hdgcimd8g4kswc2-chromium-147.0.7727.116-sandbox"
    TARGET = "/nix/store/ia19lrfqmyf36wqisjlynpm48i0mbvzf-chromium-unwrapped-147.0.7727.116-sandbox"
    HASH = "7cde83be192ae8d7082bac38a2c2e5c9b1d2adaf652436ccb4bd8d0768de2c0f"

    def setUp(self):
        self.paths = [self.ROOT, self.TARGET]
        self.rows = {
            self.ROOT: {"path": self.ROOT, "references": [self.TARGET], "narSize": 200,
                        "narHash": "sha256:" + self.HASH},
            self.TARGET: {"path": self.TARGET, "references": [], "narSize": 1,
                          "narHash": "sha256:" + "b" * 64},
        }
        self.modes = {self.ROOT: stat.S_IFLNK | 0o777, self.TARGET: stat.S_IFDIR | 0o555}
        self.lstat = Mock(side_effect=lambda path: SimpleNamespace(st_mode=self.modes[path]))
        self.readlink = Mock(return_value=self.TARGET)

    def validate(self):
        return authority.validate_runtime_roots(self.paths, self.rows, lstat=self.lstat, readlink=self.readlink)

    def refused(self, reason):
        with self.assertRaises(authority.RuntimeRootError) as failure:
            self.validate()
        self.assertEqual(failure.exception.reason, reason)
        self.assertEqual(failure.exception.args, (reason,))
        self.assertEqual(str(failure.exception), reason)

    def test_valid_registered_directory_and_regular_roots_need_no_link_reads(self):
        self.modes[self.ROOT] = stat.S_IFREG | 0o444
        self.validate()
        self.readlink.assert_not_called()
        self.assertEqual(self.lstat.call_args_list, [call(self.ROOT), call(self.TARGET)])

    def test_exact_qualified_link_nar_admits_direct_directory_or_regular_target(self):
        for target_mode in (stat.S_IFDIR | 0o555, stat.S_IFREG | 0o444):
            with self.subTest(kind=stat.S_IFMT(target_mode)):
                self.modes[self.TARGET] = target_mode
                self.validate()
        self.assertEqual(self.readlink.call_args_list, [call(self.ROOT), call(self.ROOT)])

    def test_equivalent_sri_nar_hash_is_accepted(self):
        self.rows[self.ROOT]["narHash"] = "sha256-" + base64.b64encode(bytes.fromhex(self.HASH)).decode("ascii")
        self.validate()

    def test_wrong_nar_hash_or_size_refuses_before_target_metadata(self):
        for field, wrong in (("narHash", "sha256:" + "0" * 64), ("narSize", 201), ("narSize", True)):
            with self.subTest(field=field):
                original = self.rows[self.ROOT][field]
                self.rows[self.ROOT][field] = wrong
                self.lstat.reset_mock()
                self.refused("runtime_closure_alias_nar_mismatch")
                self.assertEqual(self.lstat.call_args_list, [call(self.ROOT)])
                self.rows[self.ROOT][field] = original

    def test_registered_but_undeclared_link_target_is_refused(self):
        self.rows[self.ROOT]["references"] = []
        self.refused("runtime_closure_alias_unqualified")
        self.assertEqual(self.lstat.call_args_list, [call(self.ROOT)])

    def test_nonregistered_relative_parent_and_host_targets_are_refused_without_following(self):
        for target in ("/nix/store/" + "0" * 32 + "-unregistered", self.TARGET.lstrip("/"),
                       "../" + self.TARGET.lstrip("/"), "/etc/environment", "/etc/bluetooth/main.conf",
                       "/run/wrappers/bin/chromium", "/" + "x" * 256):
            with self.subTest(kind="nonqualified-target"):
                self.readlink.return_value = target
                self.lstat.reset_mock()
                self.refused("runtime_closure_alias_unqualified")
                self.assertEqual(self.lstat.call_args_list, [call(self.ROOT)])

    def test_another_declared_registered_target_still_requires_exact_nar_link_text(self):
        other = "/nix/store/" + "0" * 32 + "-another-target"
        self.paths.append(other)
        self.rows[other] = {"path": other, "references": [], "narHash": "sha256:" + "c" * 64, "narSize": 1}
        self.rows[self.ROOT]["references"].append(other)
        self.readlink.return_value = other
        self.refused("runtime_closure_alias_nar_mismatch")
        self.assertEqual(self.lstat.call_args_list, [call(self.ROOT)])

    def test_link_chain_and_special_target_are_refused_at_one_hop(self):
        for target_kind in (stat.S_IFLNK, stat.S_IFIFO, stat.S_IFSOCK):
            with self.subTest(kind=target_kind):
                self.modes[self.TARGET] = target_kind | 0o600
                self.readlink.reset_mock()
                self.refused("runtime_closure_alias_target_invalid")
                self.readlink.assert_called_once_with(self.ROOT)

    def test_special_source_root_is_refused(self):
        self.modes[self.ROOT] = stat.S_IFIFO | 0o600
        self.refused("runtime_closure_special")
        self.readlink.assert_not_called()

    def test_missing_or_unreadable_metadata_has_only_finite_diagnostics(self):
        for problem, reason in ((FileNotFoundError("raw-fixture-path"), "runtime_closure_missing"),
                                (PermissionError("raw-fixture-error"), "runtime_closure_unreadable")):
            with self.subTest(reason=reason):
                self.lstat.side_effect = problem
                self.refused(reason)
                self.readlink.assert_not_called()

    def test_link_read_failure_has_only_finite_diagnostics(self):
        self.readlink.side_effect = PermissionError("raw-fixture-link-error")
        self.refused("runtime_closure_unreadable")

    def test_incomplete_duplicate_or_noncanonical_inventory_selection_is_refused_before_io(self):
        for paths, rows in (([], {}), ([self.ROOT, self.ROOT], self.rows),
                            (self.paths, {self.ROOT: self.rows[self.ROOT]}),
                            (["/etc/environment"], {"/etc/environment": {"path": "/etc/environment", "references": []}})):
            with self.subTest(kind="selection-shape"), self.assertRaises(authority.RuntimeRootError) as failure:
                authority.validate_runtime_roots(paths, rows, lstat=self.lstat, readlink=self.readlink)
            self.assertEqual(failure.exception.reason, "runtime_closure_unavailable")
        self.lstat.assert_not_called()
        self.readlink.assert_not_called()


if __name__ == "__main__":
    unittest.main()
