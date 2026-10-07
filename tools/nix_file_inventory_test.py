from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nix_file_inventory import SITE_BLUEZ_ROOT, SITE_INERT_POLICY, inert_site_alias, inventory, declared_resolve


class InventoryTest(unittest.TestCase):
    def test_site_bluez_policy_requires_exact_root_path_and_literal(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = SITE_BLUEZ_ROOT / 'etc/bluetooth'
            for name in ('input.conf', 'main.conf', 'network.conf'):
                alias = Path(directory) / name
                alias.symlink_to('/etc/bluetooth/' + name)
                self.assertTrue(inert_site_alias(alias, parent, {SITE_BLUEZ_ROOT}, SITE_INERT_POLICY))
                self.assertFalse(inert_site_alias(alias, parent, {SITE_BLUEZ_ROOT}, None))
                self.assertFalse(inert_site_alias(alias, parent, set(), SITE_INERT_POLICY))
                self.assertFalse(inert_site_alias(alias, parent / 'other', {SITE_BLUEZ_ROOT}, SITE_INERT_POLICY))
                changed = Path('/nix/store/' + 'a' * 32 + '-bluez-5.86')
                self.assertFalse(inert_site_alias(alias, changed / 'etc/bluetooth', {changed}, SITE_INERT_POLICY))
                alias.unlink()
                alias.symlink_to('/etc/bluetooth/other.conf')
                self.assertFalse(inert_site_alias(alias, parent, {SITE_BLUEZ_ROOT}, SITE_INERT_POLICY))
            alias = Path(directory) / 'other.conf'
            alias.symlink_to('/etc/bluetooth/other.conf')
            self.assertFalse(inert_site_alias(alias, parent, {SITE_BLUEZ_ROOT}, SITE_INERT_POLICY))

    def test_outside_alias_reports_public_source_without_reading_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / ('a' * 32 + '-public-package')
            source.mkdir()
            outside = root / 'operator-private-target'
            (source / 'unsafe-alias').symlink_to(outside)
            repository = root / 'repository'
            (repository / 'closure').mkdir(parents=True)
            (repository / 'closure' / source.name).symlink_to(source)
            original = Path.is_symlink
            def guarded(item):
                if item == outside:
                    self.fail('unsafe target metadata was consulted')
                return original(item)
            with patch.object(Path, 'is_symlink', guarded), self.assertRaises(ValueError) as caught:
                inventory(repository, ['closure'], [source])
            message = str(caught.exception)
            self.assertIn('public_source_alias=closure/' + source.name + '/unsafe-alias', message)
            self.assertIn('target_class=outside-declared-closure', message)
            self.assertNotIn('operator-private-target', message)

    def test_directory_aliases_preserved_ancestor_cycles_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            library = root / "closure" / "sdk" / "Versions" / "A"
            library.mkdir(parents=True)
            (library / "api.h").write_text("public header")
            (library.parent / "Current").symlink_to("A", target_is_directory=True)
            (library / "cycle").symlink_to("../..", target_is_directory=True)
            (library / "dangling").symlink_to("missing")
            (library / "self").symlink_to("self")
            self.assertEqual(inventory(root, ["closure"]), ["closure/sdk/Versions/A/api.h", "closure/sdk/Versions/Current/api.h"])

    def test_unrepresentable_labels_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "packages").mkdir()
            for name in ["okay.h", "colon:name", "back\\slash", "new\nline"]:
                (root / "packages" / name).write_text("public")
            self.assertEqual(inventory(root, ["packages"]), ["packages/okay.h"])

    def test_rejects_symlinks_outside_declared_closure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "immutable"
            allowed.mkdir()
            (allowed / "api.h").write_text("public")
            outside = root / "outside"
            outside.write_text("undeclared")
            (allowed / "escape").symlink_to(outside)
            (root / "closure").symlink_to(allowed, target_is_directory=True)
            with self.assertRaises(ValueError):
                inventory(root, ["closure"], [allowed])

    def test_rejects_external_alias_reentry_for_files_and_directories(self):
        for directory_alias in [False, True]:
            with self.subTest(directory_alias=directory_alias), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                allowed = root / "immutable"
                allowed.mkdir()
                (allowed / "api.h").write_text("public")
                external = root / "operator-alias"
                external.symlink_to(allowed if directory_alias else allowed / "api.h", target_is_directory=directory_alias)
                (allowed / "escape").symlink_to(external, target_is_directory=directory_alias)
                repository = root / "repository"
                repository.mkdir()
                (repository / "closure").symlink_to(allowed, target_is_directory=True)
                with self.assertRaises(ValueError):
                    inventory(repository, ["closure"], [allowed])

    def test_preserves_declared_inter_store_alias_chain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "immutable-one", root / "immutable-two"
            first.mkdir()
            second.mkdir()
            (second / "api.h").write_text("public")
            (first / "api.h").symlink_to(second / "api.h")
            repository = root / "repository"
            repository.mkdir()
            (repository / "closure").symlink_to(first, target_is_directory=True)
            self.assertEqual(inventory(repository, ["closure"], [first, second]), ["closure/api.h"])

    def test_parent_components_follow_resolved_directory_alias_semantics(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = root / "immutable-one", root / "immutable-two"
            first.mkdir()
            (second / "subdirectory").mkdir(parents=True)
            (first / "directory-alias").symlink_to(second / "subdirectory", target_is_directory=True)
            (first / "api.h").symlink_to(str(first / "directory-alias") + "/../unique.h")
            (second / "unique.h").write_text("public")
            self.assertEqual(declared_resolve(first / "api.h", root / "repository", {first, second}), second / "unique.h")

    def test_rejects_plain_undeclared_directory_reentry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed, undeclared = root / "immutable", root / "undeclared-directory"
            allowed.mkdir()
            undeclared.mkdir()
            (allowed / "api.h").write_text("public")
            (allowed / "escape").symlink_to(str(allowed) + "/../undeclared-directory/../immutable/api.h")
            repository = root / "repository"
            repository.mkdir()
            (repository / "closure").symlink_to(allowed, target_is_directory=True)
            with self.assertRaises(ValueError):
                inventory(repository, ["closure"], [allowed])

    def test_physical_directory_cache_preserves_alias_hop_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed = root / "immutable"
            allowed.mkdir()
            (allowed / "physical").mkdir()
            for index in range(65):
                (allowed / ("alias" + str(index))).symlink_to("alias" + str(index + 1) if index < 64 else "physical", target_is_directory=True)
            cache = {allowed: allowed, allowed / "physical": allowed / "physical"}
            with self.assertRaises(RuntimeError):
                declared_resolve(allowed / "alias0", root / "repository", {allowed}, directory_cache=cache)
            self.assertEqual(declared_resolve(allowed / "alias1", root / "repository", {allowed}, directory_cache=cache), allowed / "physical")

    def test_validated_parent_cache_skips_metadata_and_retains_hop_cost(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allowed, repository = root / "immutable", root / "repository"
            allowed.mkdir()
            (allowed / "api.h").write_text("public")
            (allowed / "alias.h").symlink_to("api.h")
            logical = repository / "closure" / "store"
            observed = []
            original = Path.is_symlink
            def tracked(path):
                observed.append(path)
                return original(path)
            with patch.object(Path, "is_symlink", tracked):
                self.assertEqual(declared_resolve(logical / "api.h", repository, {allowed}, parent_cache={logical: (allowed, 2)}), allowed / "api.h")
            self.assertEqual(observed, [allowed / "api.h"])
            with self.assertRaises(RuntimeError):
                declared_resolve(logical / "alias.h", repository, {allowed}, parent_cache={logical: (allowed, 64)})

    def test_only_exact_systemd_operator_alias_is_recorded_and_omitted(self):
        for package, basename, target, accepted in [
            ("systemd-minimal-260.1", "99-environment.conf", "../../../../../etc/environment", True),
            ("systemd-260.1", "99-environment.conf", "../../../../../etc/environment", True),
            ("other-systemd-260.1", "99-environment.conf", "../../../../../etc/environment", False),
            ("systemd-260.2", "99-environment.conf", "../../../../../etc/environment", False),
            ("systemd-minimal-260.2", "99-environment.conf", "../../../../../etc/environment", False),
            ("systemd-minimal-260.1", "98-environment.conf", "../../../../../etc/environment", False),
            ("systemd-minimal-260.1", "99-environment.conf", "../../../../../etc/other", False),
        ]:
            with self.subTest(package=package, basename=basename, target=target), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / ("a" * 32 + "-" + package)
                parent = source / "lib" / "environment.d"
                parent.mkdir(parents=True)
                (parent / basename).symlink_to(target)
                (root / "closure").symlink_to(source, target_is_directory=True)
                exclusions = []
                if accepted:
                    self.assertEqual(inventory(root, ["closure"], [source], exclusions), [])
                    self.assertEqual(len(exclusions), 1)
                    self.assertIn("operator runtime", exclusions[0]["reason"])
                else:
                    with self.assertRaises(ValueError):
                        inventory(root, ["closure"], [source], exclusions)


if __name__ == "__main__":
    unittest.main()
