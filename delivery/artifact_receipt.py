"""Finite declared artifact facts; no execution, publication or native proof."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import zipfile
import zlib

from extension_metadata import CHANNELS
import pack

ARCHIVE_LIMIT = 128 * 1024 * 1024
METADATA_LIMIT = 16 * 1024
TOTAL_LIMIT = 5 * ARCHIVE_LIMIT + METADATA_LIMIT
ZIP_MEMBERS = 256


def digest(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON field")
            result[key] = value
        return result
    def invalid_constant(_):
        raise ValueError("nonfinite JSON number")
    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid_constant)


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_input(value, limit, *, bundle=False):
    # Resolve only the explicitly declared file, never enumerate a directory.
    logical = Path(value)
    real = logical.resolve(strict=True)
    descriptor = os.open(real, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError("input must be a bounded regular file")
        if bundle:
            # Reuse the existing reader on an already verified stable regular
            # descriptor. Its own 256-MiB cap also bounds a racing growth;
            # accepted inputs must satisfy our tighter 128-MiB cap below.
            data = pack.read_bundle(Path("/dev/fd") / str(descriptor))
        else:
            with os.fdopen(os.dup(descriptor), "rb") as stream:
                data = stream.read(limit + 1)
        after = os.fstat(descriptor)
        if (len(data) > limit or len(data) != before.st_size
                or identity(before) != identity(after)
                or identity(logical.stat()) != identity(after)):
            raise ValueError("input exceeded its bound or changed while reading")
        return data, identity(after)
    finally:
        os.close(descriptor)


def bundle_facts(data):
    manifest, files = pack.verify_bundle(data)
    # Reject duplicate/nonfinite manifest JSON independently of the existing
    # verifier, and retain only the verifier's public artifact/provenance facts.
    if strict_json(files["release-manifest.json"]) != manifest:
        raise ValueError("manifest interpretation mismatch")
    provenance = manifest["provenance"]
    exact_fields(provenance, ("sourceRevision", "sourceDirty"))
    revision = provenance["sourceRevision"]
    if revision is not None and not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision):
        raise ValueError("bundle source revision is not an exact object ID")
    for entry in manifest["artifacts"]:
        exact_fields(entry, ("path", "sha256", "size", "mode"))
        if (not re.fullmatch(r"[A-Za-z0-9._/+\-]+", entry["path"])
                or type(entry["size"]) is not int):
            raise ValueError("artifact entry outside public facts policy")
    return {"archive_sha256": digest(data), "archive_bytes": len(data),
            "manifest_sha256": digest(files["release-manifest.json"]),
            "channel": manifest.get("channel"), "target": manifest["target"],
            "distribution": manifest["distribution"], "provenance": manifest["provenance"],
            "artifacts": sorted(manifest["artifacts"], key=lambda entry: entry["path"])}


def extension_facts(data):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if not entries or len(entries) > ZIP_MEMBERS:
            raise ValueError("extension member count exceeded")
        names, total = set(), 0
        for entry in entries:
            name = entry.filename.rstrip("/") if entry.is_dir() else entry.filename
            path = PurePosixPath(name)
            if (not name or path.is_absolute() or str(path) != name
                    or any(part in ("", ".", "..") for part in name.split("/"))
                    or "\\" in name or any(ord(character) < 32 for character in name)
                    or entry.filename in names or entry.flag_bits & 1
                    or stat.S_ISLNK(entry.external_attr >> 16)):
                raise ValueError("unsafe or duplicate extension member")
            names.add(entry.filename)
            total += entry.file_size
            if entry.file_size < 0 or total > ARCHIVE_LIMIT:
                raise ValueError("extension expanded byte limit exceeded")
        if (archive.getinfo("manifest.json").file_size > 64 * 1024
                or archive.getinfo("shared/channel.mjs").file_size > 4096):
            raise ValueError("extension public metadata exceeds bound")
        manifest_data = archive.read("manifest.json")
        channel_data = archive.read("shared/channel.mjs")
    manifest = strict_json(manifest_data)
    if (not isinstance(manifest, dict) or type(manifest.get("version")) is not str
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,63}", manifest["version"])
            or type(manifest.get("key")) is not str or len(manifest["key"]) > 8192):
        raise ValueError("invalid extension identity or version")
    key = base64.b64decode(manifest["key"], validate=True)
    if not 32 <= len(key) <= 4096:
        raise ValueError("extension public key exceeds identity bounds")
    channel = None
    for candidate, (instance, host) in CHANNELS.items():
        expected = (f'export const CHANNEL = {json.dumps(candidate)};\n'
                    f'export const INSTANCE = {json.dumps(instance)};\n'
                    f'export const NATIVE_HOST = {json.dumps(host)};\n').encode()
        if channel_data == expected:
            channel = candidate
            break
    if channel is None:
        raise ValueError("extension channel does not match exact public configuration")
    extension_id = "".join(chr(ord("a") + int(value, 16)) for value in digest(key)[:32])
    instance, host = CHANNELS[channel]
    return {"archive_sha256": digest(data), "archive_bytes": len(data),
            "manifest_sha256": digest(manifest_data), "channel_mjs_sha256": digest(channel_data),
            "channel_mjs": channel_data.decode("ascii"), "channel": channel,
            "instance": instance, "native_host": host, "extension_id": extension_id,
            "version": manifest["version"], "signing": "unsigned", "publication": "unpublished"}


def exact_fields(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ValueError("unexpected metadata fields")


def metadata_facts(data, extensions):
    value = strict_json(data)
    exact_fields(value, ("schema_version", "channel", "instance", "source", "artifact",
                         "extension", "native_host", "protocol_version", "capability_limits", "signing"))
    channel = value["channel"]
    if type(channel) is not str or channel not in CHANNELS:
        raise ValueError("unsupported metadata channel")
    instance, host = CHANNELS[channel]
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1
            or type(value["protocol_version"]) is not int or value["protocol_version"] != 1
            or value["instance"] != instance or value["native_host"] != host):
        raise ValueError("metadata channel, instance or protocol mismatch")
    exact_fields(value["source"], ("commit", "dirty"))
    if (type(value["source"]["commit"]) is not str
            or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", value["source"]["commit"])
            or type(value["source"]["dirty"]) is not bool):
        raise ValueError("invalid metadata source provenance")
    exact_fields(value["artifact"], ("filename", "sha256", "bytes", "format"))
    artifact = value["artifact"]
    if (type(artifact["filename"]) is not str
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.zip", artifact["filename"])
            or type(artifact["sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", artifact["sha256"])
            or type(artifact["bytes"]) is not int or not 0 < artifact["bytes"] <= ARCHIVE_LIMIT
            or artifact["format"] != "zip"):
        raise ValueError("invalid metadata artifact")
    exact_fields(value["extension"], ("id", "version", "browser"))
    extension = value["extension"]
    if (type(extension["id"]) is not str or not re.fullmatch(r"[a-p]{32}", extension["id"])
            or type(extension["version"]) is not str
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,63}", extension["version"])
            or extension["browser"] != "chromium"):
        raise ValueError("invalid metadata extension")
    exact_fields(value["signing"], ("status", "store_publication"))
    if value["signing"] != {"status": "unsigned", "store_publication": "unpublished"}:
        raise ValueError("metadata asserts unsupported publication")
    expected_limits = {"max_message_bytes": 262144, "max_secret_bytes": 8192,
                       "max_capsule_bytes": 131072, "provider_acquisition": "experimental",
                       "native_continuity": "unproved"}
    exact_fields(value["capability_limits"], expected_limits)
    if (value["capability_limits"] != expected_limits
            or any(type(value["capability_limits"][key]) is not int
                   for key in ("max_message_bytes", "max_secret_bytes", "max_capsule_bytes"))):
        raise ValueError("metadata capability limits mismatch")
    matches = [item for item in extensions if item["archive_sha256"] == artifact["sha256"]]
    if len(matches) != 1:
        raise ValueError("metadata must match exactly one declared extension")
    observed = matches[0]
    if (artifact["bytes"] != observed["archive_bytes"] or channel != observed["channel"]
            or extension["id"] != observed["extension_id"] or extension["version"] != observed["version"]
            or artifact["filename"] != observed["filename"]):
        raise ValueError("metadata disagrees with declared extension")
    return {"raw_sha256": digest(data), "raw_bytes": len(data), "value": value,
            "source_provenance_verified": False}


def collect(bundles=(), extensions=(), metadata=()):
    if (len(bundles) > 3 or len(extensions) > 2 or len(metadata) > 1
            or not (bundles or extensions) or (metadata and not extensions)):
        raise ValueError("declared input count outside policy")
    receipt = {"schema": "omux.artifact-receipt.v1", "claim": "source_artifact_facts_only",
               "authentication_performed": False, "application_execution_performed": False,
               "native_support_proved": False, "compiled_source_binding_proved": False,
               "payload_output": False, "bundles": [], "extensions": [], "metadata": None}
    seen, captured, total = set(), [], 0
    for kind, paths in (("bundles", bundles), ("extensions", extensions), ("metadata", metadata)):
        for value in paths:
            limit = METADATA_LIMIT if kind == "metadata" else ARCHIVE_LIMIT
            data, observed = read_input(value, limit, bundle=kind == "bundles")
            if observed[:2] in seen:
                raise ValueError("duplicate declared artifact")
            seen.add(observed[:2])
            captured.append((Path(value), observed))
            total += len(data)
            if total > TOTAL_LIMIT:
                raise ValueError("aggregate input byte limit exceeded")
            if kind == "bundles":
                facts = bundle_facts(data)
            elif kind == "extensions":
                facts = extension_facts(data)
            else:
                receipt["metadata"] = metadata_facts(data, receipt["extensions"])
                continue
            name = Path(value).name
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,159}", name):
                raise ValueError("artifact filename outside public policy")
            facts["filename"] = name
            receipt[kind].append(facts)
    for path, observed in captured:
        if identity(path.stat()) != observed:
            raise ValueError("declared artifact changed before receipt publication")
    for kind in ("bundles", "extensions"):
        receipt[kind].sort(key=lambda item: (item["filename"], item["archive_sha256"]))
    receipt["total_input_bytes"] = total
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", action="append", default=[])
    parser.add_argument("--extension", action="append", default=[])
    parser.add_argument("--metadata", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        receipt = collect(args.bundle, args.extension, args.metadata)
        output = Path(os.environ["TEST_UNDECLARED_OUTPUTS_DIR"])
        if not output.is_dir() or output.is_symlink():
            raise ValueError("test output root must be a directory")
        destination = output / "artifact-receipt"
        destination.mkdir(mode=0o700, exist_ok=False)
        with (destination / "receipt.json").open("xb") as stream:
            stream.write((json.dumps(receipt, sort_keys=True, indent=2, allow_nan=False) + "\n").encode())
    except (OSError, ValueError, KeyError, TypeError, AttributeError, zipfile.BadZipFile,
            EOFError, tarfile.TarError, zlib.error, NotImplementedError, RuntimeError):
        print("artifact receipt failed; no artifact claim issued", file=sys.stderr)
        return 1
    print("artifact receipt: source_artifact_facts_only; no authentication; no payload output")
    return 0


if __name__ == "__main__":
    sys.exit(main())
