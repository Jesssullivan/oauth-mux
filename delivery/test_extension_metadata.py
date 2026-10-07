import base64
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from extension_metadata import metadata


class MetadataTest(unittest.TestCase):
    def test_archive_facts_and_channel_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "development.zip"
            with zipfile.ZipFile(path, "w") as package:
                package.writestr("manifest.json", json.dumps({
                    "key": base64.b64encode(b"public test fixture" * 4).decode(), "version": "0.2.0"}))
                package.writestr("shared/channel.mjs", 'export const CHANNEL = "development";\n'
                                 'export const INSTANCE = "dev";\n'
                                 'export const NATIVE_HOST = "ai.xoxd.omux.dev";\n')
            result = metadata(path, "development", "a" * 40, True)
            self.assertEqual(result["artifact"]["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(result["source"], {"commit": "a" * 40, "dirty": True})
            self.assertEqual(result["signing"]["status"], "unsigned")
            self.assertEqual(result["capability_limits"]["native_continuity"], "unproved")
            with self.assertRaises(ValueError):
                metadata(path, "release", "a" * 40, False)
            with self.assertRaises(ValueError):
                metadata(path, "development", "unknown", False)


if __name__ == "__main__":
    unittest.main()
