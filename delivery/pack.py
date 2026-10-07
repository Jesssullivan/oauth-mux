"""Deterministic experimental distributions with verified, bounded archive IO.

Invoked exclusively by a declared Bazel action or `bazel run //delivery:bundle`.
Portable Linux archives contain their declared loader, library and trust
closures. No successor archive inherits historical live integration claims.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import tarfile
from pathlib import Path, PurePosixPath

MAX_BYTES = 256 * 1024 * 1024
MAX_FILES = 256
SUPPORTED_TARGETS = {"x86_64-linux", "aarch64-linux", "x86_64-macos", "aarch64-macos"}
BINARIES = ("omux", "omuxd", "oauth-mux", "omux-native-host", "git-credential-omux")
REQUIRED_FILES = {
    *("bin/" + name for name in BINARIES), "share/omux/reference.json",
    "share/omux/services/omux.service.in", "share/omux/services/dev.xoxd.omux.plist.in",
    "release-manifest.json", "SHA256SUMS",
}


def digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def read_bundle(path: Path) -> bytes:
    if not path.is_file() or path.stat().st_size > MAX_BYTES:
        raise ValueError("bundle input must be a bounded regular file")
    with path.open("rb") as reader:
        payload = reader.read(MAX_BYTES + 1)
    if len(payload) > MAX_BYTES:
        raise ValueError("bundle input exceeds bounded size")
    return payload


def read_witness(path: Path) -> dict:
    if not path.is_file() or path.stat().st_size > 16 * 1024:
        raise ValueError("native resolution witness must be a bounded regular file")
    with path.open("rb") as reader:
        payload = reader.read(16 * 1024 + 1)
    if len(payload) > 16 * 1024:
        raise ValueError("native resolution witness exceeds its size bound")
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError("native resolution witness must be an object")
    return value


def checked_name(name: str) -> str:
    path = PurePosixPath(name)
    if not name or path.is_absolute() or str(path) != name or any(part in {"", ".", ".."} for part in name.split("/")):
        raise ValueError("unsafe archive member")
    return name


def archive_mode(name: str, runtime: dict | None = None) -> int:
    executable = name.startswith("bin/") or name in {
        "lib/omux/libexec/omux.bin", "lib/omux/libexec/omuxd.bin", "lib/omux/qt/libexec/omux-control.bin",
    } or (runtime is not None and name in {runtime["loader"], runtime.get("qt", {}).get("loader")})
    return 0o755 if executable else 0o644


def make_bundle(binary: Path, daemon: Path, reference: Path, systemd_template: Path,
                launchd_template: Path, target: str, source_revision: str | None = None,
                source_dirty: bool = True, epoch: int = 0,
                runtime_files: list[Path] | None = None, patchelf: Path | None = None,
                ca_bundle: Path | None = None, control: Path | None = None,
                qt_plugins: list[Path] | None = None, resolution_witness: dict | None = None,
                qt_runtime_files: list[Path] | None = None, channel: str | None = None) -> bytes:
    if channel is not None and channel not in {"development", "release"}:
        raise ValueError("unsupported artifact channel")
    if channel is not None and runtime_files is None:
        raise ValueError("known-channel packaging requires declared portable instance-bound launchers")
    if target not in SUPPORTED_TARGETS or not 0 <= epoch <= 0xFFFFFFFF:
        raise ValueError("unsupported target or epoch")
    inputs = [binary, daemon, reference, systemd_template, launchd_template]
    if control is not None:
        inputs.append(control)
    for path in inputs:
        if not path.is_file() or path.is_symlink() or path.stat().st_size > MAX_BYTES:
            raise ValueError("bundle inputs must be regular files")
    cli_copies = 1 if runtime_files is not None else len(BINARIES) - 1
    projected = binary.stat().st_size * cli_copies + sum(path.stat().st_size for path in inputs[1:])
    if projected > MAX_BYTES:
        raise ValueError("archive inputs exceed bounded payload size")
    public_reference = json.loads(reference.read_bytes())
    if public_reference.get("schemaVersion") != 1:
        raise ValueError("unsupported reference schema")
    product = public_reference["product"]
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+-]{0,63}", product["version"]):
        raise ValueError("invalid product version")
    if product["status"] != "experimental":
        raise ValueError("development bundler cannot publish stable claims")
    if source_revision is not None:
        if not re.fullmatch(r"[0-9a-f]{40,64}", source_revision):
            raise ValueError("source revision must be a full commit digest")
        public_reference["provenance"] = {"sourceRevision": source_revision, "sourceDirty": source_dirty}
    elif not source_dirty:
        raise ValueError("a clean bundle requires an explicit source revision")
    cli = binary.read_bytes()
    files = {
        "bin/omux": cli,
        "bin/omuxd": daemon.read_bytes(),
        "bin/oauth-mux": cli,
        "bin/omux-native-host": cli,
        "bin/git-credential-omux": cli,
        "share/omux/reference.json": json_bytes(public_reference),
        "share/omux/services/omux.service.in": systemd_template.read_bytes(),
        "share/omux/services/dev.xoxd.omux.plist.in": launchd_template.read_bytes(),
    }
    runtime = None
    distribution = "development-nix-closure-required"
    if runtime_files is not None or patchelf is not None or control is not None or qt_plugins is not None or qt_runtime_files is not None:
        if runtime_files is None or patchelf is None or ca_bundle is None or not target.endswith("-linux"):
            raise ValueError("portable Linux assembly requires declared runtime files, trust bundle and patchelf")
        from portable import assemble_linux
        runtime_payload, runtime = assemble_linux(binary, daemon, runtime_files, patchelf, target, ca_bundle,
                                                  control=control, qt_plugins=qt_plugins,
                                                  resolution_witness=resolution_witness, qt_runtime_files=qt_runtime_files,
                                                  channel=channel)
        files.update(runtime_payload)
        distribution = "portable-linux"
    manifest = {
        "schemaVersion": 1,
        "product": product,
        "target": target,
        "distribution": distribution,
        "provenance": public_reference["provenance"],
        "artifacts": [{"path": name, "sha256": digest(data), "size": len(data),
                       "mode": f"{archive_mode(name, runtime):04o}"}
                      for name, data in sorted(files.items())],
    }
    if runtime is not None:
        manifest["runtime"] = runtime
    if channel is not None:
        manifest["channel"] = channel
    files["release-manifest.json"] = json_bytes(manifest)
    files["SHA256SUMS"] = "".join(f"{digest(data)}  {name}\n" for name, data in sorted(files.items())).encode()
    if sum(map(len, files.values())) > MAX_BYTES:
        raise ValueError("archive exceeds bounded payload size")
    result = io.BytesIO()
    with gzip.GzipFile(fileobj=result, mode="wb", filename="", mtime=epoch, compresslevel=9) as gz:
        with tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, data in sorted(files.items()):
                entry = tarfile.TarInfo(name)
                entry.size, entry.mtime = len(data), epoch
                entry.mode = archive_mode(name, runtime)
                entry.uid = entry.gid = 0
                entry.uname = entry.gname = ""
                archive.addfile(entry, io.BytesIO(data))
    return result.getvalue()


def archive_contents(payload):
    """Bounded public archive extraction, without executing or importing its loader."""
    if len(payload) > MAX_BYTES:
        raise ValueError("archive exceeds bounded compressed size")
    files: dict[str, bytes] = {}
    modes: dict[str, int] = {}
    total = 0
    # Bound decompression before tarfile parses any PAX/GNU metadata. Member
    # accounting alone cannot bound an extended header processed internally.
    maximum_tar = MAX_BYTES + MAX_FILES * 1024 + 16 * 1024
    with gzip.GzipFile(fileobj=io.BytesIO(payload), mode="rb") as compressed:
        decompressed = compressed.read(maximum_tar + 1)
    if len(decompressed) > maximum_tar:
        raise ValueError("archive exceeds bounded decompressed size")
    with tarfile.open(fileobj=io.BytesIO(decompressed), mode="r:") as archive:
        for member in archive:
            name = checked_name(member.name)
            if not member.isfile() or name in files or len(files) >= MAX_FILES:
                raise ValueError("archive contains duplicate or non-file members")
            total += member.size
            if member.size < 0 or total > MAX_BYTES or member.mode not in {0o644, 0o755}:
                raise ValueError("invalid archive size or permissions")
            reader = archive.extractfile(member)
            if reader is None:
                raise ValueError("missing archive payload")
            files[name] = reader.read(member.size + 1)
            if len(files[name]) != member.size:
                raise ValueError("truncated archive payload")
            modes[name] = member.mode
    return files, modes


def verify_bundle(payload: bytes, require_publishable: bool = False) -> tuple[dict, dict[str, bytes]]:
    files, modes = archive_contents(payload)
    if not REQUIRED_FILES.issubset(files):
        raise ValueError("archive members do not match development distribution")
    manifest = json.loads(files["release-manifest.json"])
    if manifest.get("schemaVersion") != 1 or manifest.get("target") not in SUPPORTED_TARGETS:
        raise ValueError("unsupported manifest")
    if "channel" in manifest and manifest["channel"] not in {"development", "release"}:
        raise ValueError("unsupported artifact channel")
    distribution = manifest.get("distribution")
    if distribution not in {"development-nix-closure-required", "portable-linux"} or manifest["product"].get("status") != "experimental":
        raise ValueError("archive misrepresents distribution support")
    if distribution == "development-nix-closure-required" and set(files) != REQUIRED_FILES:
        raise ValueError("unexpected development archive files")
    if distribution == "development-nix-closure-required" and "runtime" in manifest:
        raise ValueError("development archive cannot assert a portable runtime")
    if distribution == "development-nix-closure-required" and "channel" in manifest:
        raise ValueError("known-channel packaging requires declared portable instance-bound launchers")
    if distribution == "portable-linux":
        from portable import verify_linux
        verify_linux(files, manifest)
    expected = set(files) - {"release-manifest.json", "SHA256SUMS"}
    artifacts = manifest.get("artifacts", [])
    if len(artifacts) != len(expected) or {item["path"] for item in artifacts} != expected:
        raise ValueError("manifest does not account for every artifact")
    for item in artifacts:
        data = files[item["path"]]
        if (digest(data) != item["sha256"] or len(data) != item["size"] or modes[item["path"]] != int(item["mode"], 8)
                or modes[item["path"]] != archive_mode(item["path"], manifest.get("runtime"))):
            raise ValueError("artifact digest, size or mode mismatch")
    expected_sums = "".join(f"{digest(data)}  {name}\n" for name, data in sorted(files.items()) if name != "SHA256SUMS").encode()
    if files["SHA256SUMS"] != expected_sums or any(files["bin/omux"] != files["bin/" + name] for name in BINARIES if name != "omuxd"):
        raise ValueError("checksum list or compatibility executable mismatch")
    reference = json.loads(files["share/omux/reference.json"])
    if reference.get("schemaVersion") != 1 or reference.get("product") != manifest["product"] or reference.get("provenance") != manifest["provenance"]:
        raise ValueError("source-reference provenance mismatch")
    provenance = manifest["provenance"]
    if (not isinstance(provenance, dict) or not isinstance(provenance.get("sourceDirty"), bool)
            or (provenance.get("sourceRevision") is not None
                and (not isinstance(provenance["sourceRevision"], str)
                     or not re.fullmatch(r"[0-9a-f]{40,64}", provenance["sourceRevision"])))):
        raise ValueError("invalid source provenance")
    if require_publishable and (provenance.get("sourceDirty") is not False or not re.fullmatch(r"[0-9a-f]{40,64}", provenance.get("sourceRevision", ""))):
        raise ValueError("publication requires clean full-commit provenance")
    return manifest, files


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--require-publishable", action="store_true")
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--daemon", type=Path)
    parser.add_argument("--reference", type=Path)
    parser.add_argument("--systemd-template", type=Path)
    parser.add_argument("--launchd-template", type=Path)
    parser.add_argument("--target", choices=sorted(SUPPORTED_TARGETS))
    parser.add_argument("--channel", choices=["development", "release"])
    parser.add_argument("--source-revision")
    parser.add_argument("--source-dirty", choices=["true", "false"], default="true")
    parser.add_argument("--epoch", type=int, default=0)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--runtime-file", type=Path, action="append")
    parser.add_argument("--patchelf", type=Path)
    parser.add_argument("--ca-bundle", type=Path)
    parser.add_argument("--control", type=Path)
    parser.add_argument("--qt-plugin", type=Path, action="append")
    parser.add_argument("--qt-runtime-file", type=Path, action="append")
    parser.add_argument("--resolution-witness", type=Path)
    args = parser.parse_args()
    if args.verify:
        payload = read_bundle(args.verify)
        manifest, _ = verify_bundle(payload, args.require_publishable)
    else:
        if not all([args.binary, args.daemon, args.reference, args.systemd_template, args.launchd_template, args.target, args.output]):
            parser.error("bundling requires all declared inputs, target and output")
        # Bazel exposes declared inputs through sandbox/runfile symlinks.
        payload = make_bundle(args.binary.resolve(strict=True), args.daemon.resolve(strict=True), args.reference.resolve(strict=True),
                              args.systemd_template.resolve(strict=True), args.launchd_template.resolve(strict=True),
                              args.target, args.source_revision, args.source_dirty == "true", args.epoch,
                              runtime_files=args.runtime_file,
                              patchelf=args.patchelf.resolve(strict=True) if args.patchelf is not None else None,
                              ca_bundle=args.ca_bundle.resolve(strict=True) if args.ca_bundle is not None else None,
                              control=args.control.resolve(strict=True) if args.control is not None else None,
                              qt_plugins=args.qt_plugin,
                              qt_runtime_files=args.qt_runtime_file,
                              resolution_witness=read_witness(args.resolution_witness) if args.resolution_witness is not None else None,
                              channel=args.channel)
        manifest, _ = verify_bundle(payload, args.require_publishable)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(payload)
    print(json.dumps({"product": manifest["product"], "target": manifest["target"],
                      "distribution": manifest["distribution"], "provenance": manifest["provenance"],
                      "archiveSha256": digest(payload), "archiveBytes": len(payload),
                      "artifactCount": len(manifest["artifacts"])}))


if __name__ == "__main__":
    main()
