import base64
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from channel import archive, extension_id


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


if __name__ == "__main__":
    unittest.main()
