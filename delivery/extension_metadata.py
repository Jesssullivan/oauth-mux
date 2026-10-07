"""Derive unsigned archive facts; publication and native proofs stay explicit."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import zipfile

CHANNELS = {"release": ("default", "ai.xoxd.omux"),
            "development": ("dev", "ai.xoxd.omux.dev")}


def metadata(archive, channel, source_commit, source_dirty):
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", source_commit):
        raise ValueError("source commit must be an explicit full digest")
    instance, host = CHANNELS[channel]
    path = Path(archive)
    with zipfile.ZipFile(path) as package:
        manifest = json.loads(package.read("manifest.json"))
        key = base64.b64decode(manifest["key"], validate=True)
        config = package.read("shared/channel.mjs").decode()
        expected = (f'export const CHANNEL = {json.dumps(channel)};\n'
                    f'export const INSTANCE = {json.dumps(instance)};\n'
                    f'export const NATIVE_HOST = {json.dumps(host)};\n')
        if config != expected or len(key) < 32:
            raise ValueError("archive channel or identity does not match")
    identity = "".join(chr(ord("a") + int(c, 16))
                       for c in hashlib.sha256(key).hexdigest()[:32])
    content = path.read_bytes()
    return {"schema_version": 1, "channel": channel, "instance": instance,
            "source": {"commit": source_commit, "dirty": source_dirty},
            "artifact": {"filename": path.name, "sha256": hashlib.sha256(content).hexdigest(),
                         "bytes": len(content), "format": "zip"},
            "extension": {"id": identity, "version": manifest["version"], "browser": "chromium"},
            "native_host": host, "protocol_version": 1,
            "capability_limits": {"max_message_bytes": 262144, "max_secret_bytes": 8192,
                                  "max_capsule_bytes": 131072,
                                  "provider_acquisition": "experimental", "native_continuity": "unproved"},
            "signing": {"status": "unsigned", "store_publication": "unpublished"}}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True)
    parser.add_argument("--channel", choices=CHANNELS, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-dirty", choices=("true", "false"), required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    result = metadata(args.archive, args.channel, args.source_commit, args.source_dirty == "true")
    Path(args.out).write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")


if __name__ == "__main__":
    main()
