"""Deterministic unsigned channel archives with exact browser identities."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import zipfile

CHANNELS = {"release": ("default", "ai.xoxd.omux"),
            "development": ("dev", "ai.xoxd.omux.dev")}
FIREFOX_IDS = {"release": "browser-sources@omux.xoxd.ai",
               "development": "browser-sources-dev@omux.xoxd.ai"}


def extension_id(key):
    raw = base64.b64decode(key, validate=True)
    if len(raw) < 32:
        raise ValueError("public identity key is too short")
    return "".join(chr(ord("a") + int(c, 16))
                   for c in hashlib.sha256(raw).hexdigest()[:32])


def archive(manifest_path, sources, key_path, channel, output, browser="chromium"):
    instance, host = CHANNELS[channel]
    manifest = json.loads(Path(manifest_path).read_text())
    if browser == "chromium":
        if key_path is None:
            raise ValueError("Chromium channel archive requires a public identity key")
        key = Path(key_path).read_text().strip()
        extension_id(key)
        manifest["key"] = key
    elif browser == "firefox":
        if key_path is not None or "key" in manifest:
            raise ValueError("Firefox channel archive cannot use a Chromium identity key")
        gecko = manifest["browser_specific_settings"]["gecko"]
        if gecko["id"] != FIREFOX_IDS["release"]:
            raise ValueError("Firefox source manifest must declare the exact release identity")
        gecko["id"] = FIREFOX_IDS[channel]
    else:
        raise ValueError("unsupported archive browser")
    if channel == "development":
        manifest["name"] += " (development)"
    entries = {"manifest.json": (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()}
    for source in sources:
        path = Path(source)
        name = "shared/" + path.name
        if name in entries:
            raise ValueError("duplicate archive source")
        entries[name] = path.read_bytes()
    entries["shared/channel.mjs"] = (
        f'export const CHANNEL = {json.dumps(channel)};\n'
        f'export const INSTANCE = {json.dumps(instance)};\n'
        f'export const NATIVE_HOST = {json.dumps(host)};\n').encode()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as target:
        for name, content in sorted(entries.items()):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            target.writestr(info, content)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--source", action="append", default=[])
    parser.add_argument("--public-key")
    parser.add_argument("--browser", choices=("chromium", "firefox"), default="chromium")
    parser.add_argument("--channel", choices=CHANNELS, required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    archive(args.manifest, args.source, args.public_key, args.channel, args.out, args.browser)


if __name__ == "__main__":
    main()
