"""Contract test for the v0.2 package-lane consumer projection.

Scope (TIN-2799 / TIN-2050): every packaged release asset in
`release-manifest.json` must declare a well-formed, internally consistent
`declared_v0_2_members` projection *before* any packaging script is wired to
consume it. This test does not build, package, or install anything; it only
proves the data every future consumer (release-local.sh, the Homebrew
formula, dist/install.sh, nfpm configs) will read is shaped the way
`docs/v02-package-lane-migration-plan.md` assumes.

It is intentionally independent of `scripts/release-manifest-current.sh`
(a bash/jq helper) so a schema regression is caught in a fast, dependency-free
lane.
"""

from __future__ import annotations

import json
import pathlib
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "release-manifest.json"

# Kinds that ship an actual executable pair and therefore must declare a
# non-empty v0.2 member projection. Non-executable assets (the installer
# script itself, checksums, the manifest, the formula file) legitimately
# declare an empty projection.
EXECUTABLE_ASSET_KINDS = {"archive", "deb", "rpm"}


def load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text())


class ReleaseManifestV02ConsumerSchemaTest(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = load_manifest()

    def _compatibility_links(self) -> list[dict]:
        return self.manifest["product"]["compatibility_links"]

    def test_compatibility_links_declare_primary_and_target(self) -> None:
        links = self._compatibility_links()
        self.assertTrue(links, "product.compatibility_links must be non-empty")
        primary = self.manifest["product"]["primary_executable"]
        for link in links:
            self.assertEqual(
                link["target"],
                primary,
                f"compatibility link {link['name']!r} must target the "
                f"declared primary executable {primary!r}",
            )
            self.assertEqual(
                link["materialization"],
                "same_bytes",
                f"compatibility link {link['name']!r} must be same_bytes, "
                "not an independently rebuilt copy",
            )

    def test_every_executable_asset_declares_v02_members(self) -> None:
        primary = self.manifest["product"]["primary_executable"]
        compat_names = {link["name"] for link in self._compatibility_links()}
        for asset in self.manifest["release_assets"]:
            if asset["kind"] not in EXECUTABLE_ASSET_KINDS:
                continue
            with self.subTest(asset=asset["id"]):
                declared = asset["declared_v0_2_members"]
                self.assertTrue(
                    declared,
                    f"{asset['id']} is a {asset['kind']} asset and must "
                    "declare a non-empty declared_v0_2_members projection",
                )
                # Windows targets use the .exe-suffixed names; every other
                # target uses the bare primary/compat names.
                is_windows = asset["target_id"] is not None and "windows" in asset["target_id"]
                suffix = ".exe" if is_windows else ""
                expected_primary_name = f"{primary}{suffix}"
                expected_names = {f"{name}{suffix}" for name in compat_names}
                expected_names.add(expected_primary_name)

                # deb/rpm members are absolute install paths; archives are
                # bare filenames. Normalize both to a bare basename set.
                declared_basenames = {member.rsplit("/", 1)[-1] for member in declared}

                self.assertIn(
                    expected_primary_name,
                    declared_basenames,
                    f"{asset['id']} must declare the primary executable "
                    f"{expected_primary_name!r}",
                )
                self.assertTrue(
                    expected_names & declared_basenames >= {expected_primary_name},
                    f"{asset['id']} declared_v0_2_members {declared!r} does "
                    f"not include the expected primary/compat pair "
                    f"{expected_names!r}",
                )
                for name in declared_basenames:
                    self.assertIn(
                        name,
                        expected_names,
                        f"{asset['id']} declares unexpected v0.2 member "
                        f"{name!r} not derived from primary_executable or "
                        "a declared compatibility_link",
                    )

    def test_declared_v02_members_never_widen_beyond_primary_and_compat_pair(self) -> None:
        # v0.2 intentionally narrows default archive/package membership to
        # just the primary executable and its compatibility link — the
        # bundled `codex` shim that v0.1.15 ships by default is dropped from
        # the v0.2 projection (it becomes an explicit opt-in lane per
        # docs/release-install-lanes.md's Codex Shim Contract). This test
        # locks in that narrowing as intentional: it fails if a future
        # edit adds a third member to any declared_v0_2_members list without
        # a corresponding update here, so the widening is reviewed rather
        # than silent.
        primary = self.manifest["product"]["primary_executable"]
        compat_names = {link["name"] for link in self._compatibility_links()}
        for asset in self.manifest["release_assets"]:
            if asset["kind"] not in EXECUTABLE_ASSET_KINDS:
                continue
            with self.subTest(asset=asset["id"]):
                declared = asset["declared_v0_2_members"]
                if not declared:
                    continue
                self.assertEqual(
                    len(declared),
                    2,
                    f"{asset['id']} declared_v0_2_members {declared!r} has "
                    "an unexpected member count; v0.2 default packaging is "
                    "exactly [primary, compatibility-link] with no bundled "
                    "codex shim",
                )
                declared_basenames = {member.rsplit("/", 1)[-1] for member in declared}
                for name in declared_basenames:
                    stem = name[: -len(".exe")] if name.endswith(".exe") else name
                    self.assertIn(
                        stem,
                        compat_names | {primary},
                        f"{asset['id']} declares {name!r}, which is neither "
                        f"the primary executable {primary!r} nor a declared "
                        "compatibility link",
                    )


if __name__ == "__main__":
    unittest.main()
