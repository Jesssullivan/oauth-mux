import base64
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from channel import archive, extension_id
import native_host_setup as setup


class ChannelTest(unittest.TestCase):
    def test_reproducible_distinct_channels(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps({"name": "Omux", "version": "0.2.0"}))
            identities = []
            for index, channel in enumerate(("release", "development")):
                key = root / "public.key"
                key.write_text(base64.b64encode(bytes([index + 1]) * 64).decode())
                identities.append(extension_id(key.read_text()))
                outputs = [root / f"{channel}{n}.zip" for n in range(2)]
                for output in outputs:
                    archive(manifest, [], key, channel, output)
                self.assertEqual(outputs[0].read_bytes(), outputs[1].read_bytes())
                with zipfile.ZipFile(outputs[0]) as package:
                    config = package.read("shared/channel.mjs").decode()
                    self.assertIn('"ai.xoxd.omux.dev"' if index else '"ai.xoxd.omux"', config)
            self.assertNotEqual(*identities)

    def test_invalid_public_identity(self):
        for key in ("not-base64", "YQ=="):
            with self.assertRaises(ValueError):
                extension_id(key)

    def test_firefox_channels_join_exact_registration_without_chromium_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = {"name": "Omux", "version": "0.2.0",
                      "permissions": ["nativeMessaging", "storage", "activeTab"],
                      "optional_permissions": ["cookies"],
                      "optional_host_permissions": ["https://github.com/*"],
                      "browser_specific_settings": {"gecko": {
                          "id": "browser-sources@omux.xoxd.ai", "strict_min_version": "128.0"}}}
            manifest = root / "manifest.json"
            manifest.write_text(json.dumps(source))
            for channel, instance in (("release", "default"), ("development", "dev")):
                with self.subTest(channel=channel):
                    outputs = [root / f"{channel}{index}.xpi" for index in range(2)]
                    for output in outputs:
                        archive(manifest, [], None, channel, output, browser="firefox")
                    self.assertEqual(outputs[0].read_bytes(), outputs[1].read_bytes())
                    with zipfile.ZipFile(outputs[0]) as package:
                        actual = json.loads(package.read("manifest.json"))
                        identity = actual["browser_specific_settings"]["gecko"]["id"]
                        registration = setup.manifest("firefox", identity, "/nix/store/fixture/bin/omux-native-host", channel)
                        self.assertEqual(registration["allowed_extensions"], [identity])
                        self.assertEqual(identity, setup.CHANNEL_FIREFOX_IDS[channel])
                        self.assertEqual(package.read("shared/channel.mjs").decode(),
                                         f'export const CHANNEL = "{channel}";\n'
                                         f'export const INSTANCE = "{instance}";\n'
                                         f'export const NATIVE_HOST = "{registration["name"]}";\n')
                        self.assertNotIn("key", actual)
                        for field in ("permissions", "optional_permissions", "optional_host_permissions"):
                            self.assertEqual(actual[field], source[field])
                        other = "release" if channel == "development" else "development"
                        with self.assertRaises(setup.SetupError):
                            setup.manifest("firefox", identity, "/nix/store/fixture/bin/omux-native-host", other)
            self.assertEqual(json.loads(manifest.read_text()), source)

    def test_firefox_archive_rejects_identity_drift_and_chromium_key(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "manifest.json"
            source = {"name": "Omux", "browser_specific_settings": {"gecko": {
                "id": "browser-sources-dev@omux.xoxd.ai"}}}
            manifest.write_text(json.dumps(source))
            with self.assertRaisesRegex(ValueError, "exact release identity"):
                archive(manifest, [], None, "development", root / "drift.xpi", browser="firefox")
            source["browser_specific_settings"]["gecko"]["id"] = "browser-sources@omux.xoxd.ai"
            manifest.write_text(json.dumps(source))
            with self.assertRaisesRegex(ValueError, "Chromium identity key"):
                archive(manifest, [], root / "unused.key", "development", root / "key.xpi", browser="firefox")
            source["key"] = "unused"
            manifest.write_text(json.dumps(source))
            with self.assertRaisesRegex(ValueError, "Chromium identity key"):
                archive(manifest, [], None, "development", root / "embedded-key.xpi", browser="firefox")


if __name__ == "__main__":
    unittest.main()
