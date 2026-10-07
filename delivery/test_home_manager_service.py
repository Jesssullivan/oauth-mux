"""Synthetic definition fixtures; no filesystem ownership or fleet activation."""
import copy
import hashlib
import unittest
from home_manager_service import verify_definition


class DefinitionTests(unittest.TestCase):
    def setUp(self):
        self.name = "ai.xoxd.omux.dev.service"
        self.source = "/nix/store/" + "a" * 32 + "-unit/" + self.name
        self.body = b"[Service]\nUMask=0077\n"
        self.record = {"schemaVersion": 1, "owner": "home-manager", "channel": "development",
                       "instance": "dev", "artifactManifestSha256": "b" * 64,
                       "scope": "definition-only-not-activation",
                       "unit": {"name": self.name, "mode": 420, "sourcePath": self.source,
                                "installedPath": "/home/model/.config/systemd/user/" + self.name,
                                "sha256": hashlib.sha256(self.body).hexdigest()},
                       "login": {"sourcePath": self.source, "installedPath":
                                 "/home/model/.config/systemd/user/default.target.wants/" + self.name}}

    def check(self, record=None, **changes):
        args = dict(channel="development", manifest_sha256="b" * 64,
                    config_home="/home/model/.config", unit_bytes=self.body,
                    unit_link=self.source, login_link="../" + self.name)
        args.update(changes)
        return verify_definition(self.record if record is None else record, **args)

    def test_definition_never_claims_activation(self):
        self.assertEqual(self.check(), {"definition": "modeled-compatible", "activation": "unknown"})

    def test_bytes_and_independent_bindings(self):
        for change in ({"unit_bytes": self.body + b"#changed"}, {"channel": "release"},
                       {"manifest_sha256": "c" * 64}, {"config_home": "/home/other/.config"},
                       {"unit_bytes": b"x" * 65537}):
            self.assertEqual(self.check(**change)["definition"], "unknown")

    def test_intermediate_or_escaping_links_refused(self):
        for link in ("../../" + self.name, "/nix/store/" + "a" * 32 + "-home-manager-files/unit"):
            self.assertEqual(self.check(unit_link=link)["definition"], "unknown")
            self.assertEqual(self.check(login_link=link)["definition"], "unknown")

    def test_scope_and_instance_required(self):
        for key, value in (("scope", "activated"), ("instance", "default"), ("owner", "portable")):
            record = copy.deepcopy(self.record)
            record[key] = value
            self.assertEqual(self.check(record)["definition"], "unknown")


if __name__ == "__main__":
    unittest.main()
