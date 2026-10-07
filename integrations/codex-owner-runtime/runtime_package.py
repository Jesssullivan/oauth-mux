"""R-HOOK-CONVERGENCE-20261004/R-N13: separate declared SDK runtime proof input.

The operator import preserves the produced ELF and its source artifact. Only a
private copy is stripped and relocated using the explicitly declared tools.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "codex-upstream"))
sys.path.insert(0, str(ROOT.parent / "delivery"))
from patch_io import HASH, digest, verify_artifact
from restore_source import COMMIT, private_root, safe_name, write_receipt
import portable

MAX_ORIGINAL_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
MAX_BACKEND_BYTES = 512 * 1024 * 1024
MAX_RUNTIME_BYTES = 512 * 1024 * 1024
MAX_DECLARED_RUNTIME_BYTES = 256 * 1024 * 1024
MAX_METADATA_BYTES = 16 * 1024 * 1024
MAX_FILES = 4096
PREFIX = "lib/codex/"
BACKEND = PREFIX + "libexec/codex.bin"
CA = PREFIX + "share/ca-bundle.crt"
MANIFEST = "runtime-manifest.json"
STATUS = "native-owner-runtime-proof-candidate"
RULING = "R-HOOK-CONVERGENCE-20261004"
PRODUCER_CONFIGURATIONS = ("owner-linux-fastbuild", "owner-linux-opt")
PHASES = ("copy", "strip", "read-stripped", "loader", "relocate", "assemble",
          "original-verify", "archive-build", "archive-verify", "write")


def phase_marker(phase):
    """R-N13: fixed source-owned diagnostic only; no external error content."""
    if phase not in PHASES:
        raise ValueError("unknown runtime import phase")
    print("Runtime import phase: " + phase, file=sys.stderr, flush=True)


def stripped_size_marker(size):
    """Report only the private copy's bounded numeric length before ELF read."""
    if type(size) is not int or not 0 <= size <= MAX_ORIGINAL_BYTES:
        raise ValueError("private stripped copy size exceeds import bound")
    print("Runtime import stripped bytes: " + str(size), file=sys.stderr, flush=True)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate runtime metadata key")
        result[key] = value
    return result


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def read_json(path):
    with path.open("rb") as stream:
        value = stream.read(16 * 1024 * 1024 + 1)
    if len(value) > 16 * 1024 * 1024:
        raise ValueError("runtime metadata exceeds bound")
    return json.loads(value, object_pairs_hook=unique_object)


def hash_uuid(value):
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("invalid producer invocation UUID")
    return value


def read_runtime_inputs(path, runfiles_root):
    """Resolve only finite canonical keys supplied by the declared filegroup."""
    value = read_json(path)
    if (not isinstance(value, dict) or type(value.get("schema_version")) is not int or
            value.get("schema_version") != 1 or set(value) != {"schema_version", "runfiles"}):
        raise ValueError("runtime response-file schema differs")
    keys = value["runfiles"]
    if not isinstance(keys, list) or not 0 < len(keys) <= MAX_FILES:
        raise ValueError("runtime response-file selection exceeds bound")
    selected, seen = [], set()
    for key in keys:
        if (not isinstance(key, str) or not key or key.startswith("/") or
                str(PurePosixPath(key)) != key or any(part in (".", "..", "") for part in key.split("/")) or
                "\\" in key or any(ord(char) < 32 or ord(char) == 127 for char in key) or key in seen or
                len(key) > 4096 or len(key.split("/")) < 2):
            raise ValueError("runtime response-file key is foreign or duplicated")
        seen.add(key)
        selected.append(runfiles_root / key)
    if keys != sorted(keys):
        raise ValueError("runtime response-file selection is not canonical")
    return selected


def stream_original(source, destination=None):
    """No-follow bounded stream; source bytes are never modified."""
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    checksum, count = hashlib.sha256(), 0
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or
                before.st_mode & 0o022 or not 0 < before.st_size <= MAX_ORIGINAL_BYTES):
            raise ValueError("produced executable custody or bound differs")
        while True:
            value = stream.read(1024 * 1024)
            if not value:
                break
            count += len(value)
            if count > MAX_ORIGINAL_BYTES:
                raise ValueError("produced executable exceeds stream bound")
            checksum.update(value)
            if destination is not None:
                destination.write(value)
        after = os.fstat(stream.fileno())
        if (count != before.st_size or
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError("produced executable changed during import")
    return {"sha256": checksum.hexdigest(), "bytes": count}


def candidate_inputs(artifact, source_receipt, producer_receipt):
    manifest = read_json(artifact / "manifest.json")
    validation = read_json(artifact / "validation.json")
    if (manifest.get("native_support") is not False or manifest.get("upstream_commit") != COMMIT or
            manifest.get("status") != "upstream-patch-candidate" or
            manifest.get("upstream_repository") != "https://github.com/openai/codex" or
            validation.get("native_support") is not False or validation.get("upstream_commit") != COMMIT):
        raise ValueError("candidate source or support boundary differs")
    verify_artifact(artifact, manifest)
    for field in ("patch_sha256", "base_sha256", "binary_overlay_sha256"):
        if validation["artifact"][field] != manifest[field]:
            raise ValueError("candidate validation describes another artifact")
    if validation["artifact"]["reviewed_changed_files"] != len(manifest["files"]):
        raise ValueError("candidate changed-file count differs")
    source = read_json(source_receipt)
    producer = read_json(producer_receipt)
    verification = validation["checks"]["complete_final_source_verification"]
    compilation = validation["checks"]["final_source_eight_production_labels"]
    inventory = source["files"]
    if (not isinstance(inventory, dict) or not 0 < len(inventory) <= 50000 or
            type(source.get("tracked_files")) is not int or source["tracked_files"] != len(inventory)):
        raise ValueError("source receipt inventory differs")
    for name, record in inventory.items():
        safe_name(name)
        if record.get("mode") not in ("100644", "100755", "120000") or not HASH.fullmatch(record.get("sha256", "")):
            raise ValueError("source receipt file custody differs")
    inventory_hash = digest(json.dumps(inventory, sort_keys=True).encode())
    if (source.get("phase") != "verify-prepared" or source.get("commit") != COMMIT or
            source.get("patch_sha256") != manifest["patch_sha256"] or
            source.get("complete_inventory_sha256") != inventory_hash or
            verification.get("status") != "passed" or verification.get("complete_inventory_sha256") != inventory_hash or
            verification.get("tracked_files") != source["tracked_files"] or
            compilation.get("status") != "passed" or
            producer.get("target") != "//codex-rs/cli:codex" or
            producer.get("configuration") not in PRODUCER_CONFIGURATIONS or
            source.get("bazel_configuration") != producer.get("configuration")):
        raise ValueError("source or executable producer scope differs")
    expected = {
        "upstream_commit": COMMIT,
        "patch_sha256": manifest["patch_sha256"], "base_sha256": manifest["base_sha256"],
        "binary_overlay_sha256": manifest["binary_overlay_sha256"],
        "validation_sha256": digest((artifact / "validation.json").read_bytes()),
        "complete_source_inventory_sha256": inventory_hash,
        "compile_invocation_id": hash_uuid(compilation["invocation_id"]),
        "source_verification_invocation_id": hash_uuid(verification["invocation_id"]),
    }
    if any(producer.get(key) != value for key, value in expected.items()):
        raise ValueError("producer receipt does not bind current candidate source")
    # Preserve the immutable artifact's historical receipt IDs, while binding
    # this import to root's fresh selected-CLI build and complete-source readback.
    expected["current_compile_invocation_id"] = hash_uuid(producer["current_compile_invocation_id"])
    expected["current_configuration"] = producer["configuration"]
    expected["current_source_verification_invocation_id"] = hash_uuid(producer["current_source_verification_invocation_id"])
    expected["current_source_receipt_sha256"] = digest(source_receipt.read_bytes())
    if producer.get("current_source_receipt_sha256") != expected["current_source_receipt_sha256"]:
        raise ValueError("producer does not bind current complete-source receipt")
    if (not isinstance(producer.get("original_sha256"), str) or not HASH.fullmatch(producer["original_sha256"]) or
            type(producer.get("original_bytes")) is not int or not 0 < producer["original_bytes"] <= MAX_ORIGINAL_BYTES):
        raise ValueError("producer receipt executable identity differs")
    return expected, producer


def run_tool(command, tool_path=""):
    try:
        subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       check=True, timeout=180, env={"LC_ALL": "C", "PATH": tool_path})
    except (OSError, subprocess.SubprocessError) as error:
        raise ValueError("declared runtime transformation failed") from error


def select_loader(metadata, runtime_files):
    interpreter = metadata["interpreter"]
    standard = "/lib64/ld-linux-x86-64.so.2"
    choices = [path for path in runtime_files if path.name == "ld-linux-x86-64.so.2"]
    if not choices:
        raise ValueError("declared runtime loader is missing")
    first = portable._read(choices[0])
    if any(portable._read(path) != first for path in choices[1:]):
        raise ValueError("declared runtime loader is ambiguous")
    loader = choices[0]
    if portable.elf_metadata(first)["machine"] != 62:
        raise ValueError("declared loader machine differs")
    if interpreter != standard:
        if not isinstance(interpreter, str) or not interpreter.startswith("/"):
            raise ValueError("produced executable has no qualified loader")
        # Resolve only the aliases of the explicitly supplied declared inputs.
        # The original interpreter path itself is never opened or searched.
        aliases = set()
        for choice in choices:
            current, seen = choice.absolute(), set()
            for _ in range(64):
                aliases.add(str(current))
                current = current.parent.resolve(strict=True) / current.name
                aliases.add(str(current))
                if not current.is_symlink():
                    break
                if current in seen:
                    raise ValueError("declared loader aliases cycle")
                seen.add(current)
                target = current.readlink()
                current = target if target.is_absolute() else current.parent / target
            else:
                raise ValueError("declared loader aliases exceed bound")
        if interpreter not in aliases:
            raise ValueError("produced executable has a foreign loader")
    return loader, {"original_interpreter": interpreter, "declared_loader_sha256": digest(first),
                    "declared_loader_bytes": len(first)}


def codex_launcher(loader):
    name = portable._basename(loader)
    return ("#!/bin/sh\nset -eu\nunset LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH\n"
            "launch_dir=${0%/*}\nif [ \"$launch_dir\" = \"$0\" ]; then launch_dir=.; fi\n"
            "pkg_root=$(CDPATH= cd -P \"$launch_dir/..\" && pwd -P) || exit 1\n"
            "runtime=$pkg_root/lib/codex\n"
            "SSL_CERT_FILE=\"$runtime/share/ca-bundle.crt\"\nexport SSL_CERT_FILE\n"
            f'exec "$runtime/lib/{name}" --inhibit-cache --library-path "$runtime/lib" '
            '--argv0 "$0" "$runtime/libexec/codex.bin" "$@"\n').encode("ascii")


def assemble_runtime(stripped, runtime_files, patchelf, ca_bundle):
    # Existing strict resolver is intentionally unchanged. Its two backend
    # slots receive the same SDK copy, then only one SDK backend is published.
    files, witness = portable.assemble_linux(stripped, stripped, runtime_files, patchelf,
                                            "x86_64-linux", ca_bundle, backend_max_bytes=MAX_BACKEND_BYTES)
    selected = {}
    for name, value in files.items():
        if name.startswith("lib/omux/lib/") or name == "lib/omux/share/ca-bundle.crt":
            selected[PREFIX + name.removeprefix("lib/omux/")] = value
    selected[BACKEND] = files["lib/omux/libexec/omux.bin"]
    loader = PREFIX + witness["loader"].removeprefix("lib/omux/")
    selected["bin/codex"] = codex_launcher(Path(loader).name)
    runtime = {"loader": loader, "dependencies": sorted(PREFIX + name.removeprefix("lib/omux/")
               for name in witness["dependencies"]), "backendInterpreter": witness["backendInterpreter"],
               "caBundle": CA, "backend_max_bytes": MAX_BACKEND_BYTES}
    return selected, runtime


def archive_bytes(files, manifest):
    metadata = json_bytes(manifest)
    if (len(files) + 1 > MAX_FILES or sum(map(len, files.values())) > MAX_RUNTIME_BYTES or
            len(metadata) > MAX_METADATA_BYTES):
        raise ValueError("runtime archive inputs exceed finite payload bound")
    values = {**files, MANIFEST: metadata}
    raw = io.BytesIO()
    with gzip.GzipFile(fileobj=raw, filename="", mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name, value in sorted(values.items()):
                entry = tarfile.TarInfo(name)
                entry.size = len(value)
                entry.mode = 0o644 if name in (MANIFEST, CA) else 0o755
                entry.mtime = 0
                archive.addfile(entry, io.BytesIO(value))
    if len(raw.getvalue()) > MAX_ARCHIVE_BYTES:
        raise ValueError("runtime archive exceeds transfer bound")
    return raw.getvalue()


def verify_runtime_files(payload, receipt):
    """Consumer check: exact receipt, archive members and every packaged ELF edge."""
    if len(payload) > MAX_ARCHIVE_BYTES or digest(payload) != receipt.get("archive_sha256") or len(payload) != receipt.get("archive_bytes"):
        raise ValueError("runtime archive differs from external receipt")
    files, modes = {}, {}
    with gzip.GzipFile(fileobj=io.BytesIO(payload)) as stream:
        raw = stream.read(MAX_RUNTIME_BYTES + MAX_METADATA_BYTES + 1)
    if len(raw) > MAX_RUNTIME_BYTES + MAX_METADATA_BYTES:
        raise ValueError("runtime archive raw bytes exceed bound")
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive:
            name = member.name
            member_bound = MAX_BACKEND_BYTES if name == BACKEND else MAX_METADATA_BYTES if name == MANIFEST else portable._MAX_FILE
            if (not member.isfile() or name in files or len(files) >= MAX_FILES or
                    not name or str(PurePosixPath(name)) != name or name.startswith("/") or
                    any(part in (".", "..") for part in name.split("/")) or
                    any(char in name for char in "\\\0\r\n\t") or
                    not 0 <= member.size <= member_bound or member.mode not in (0o644, 0o755)):
                raise ValueError("runtime archive has a foreign or unsafe member")
            value = archive.extractfile(member).read(member_bound + 1)
            if len(value) != member.size:
                raise ValueError("runtime archive member is truncated")
            files[name], modes[name] = value, member.mode
    if sum(len(value) for name, value in files.items() if name != MANIFEST) > MAX_RUNTIME_BYTES:
        raise ValueError("runtime archive payload bytes exceed aggregate bound")
    if MANIFEST not in files or digest(files[MANIFEST]) != receipt.get("manifest_sha256") or modes[MANIFEST] != 0o644:
        raise ValueError("runtime manifest differs from external receipt")
    manifest = json.loads(files[MANIFEST], object_pairs_hook=unique_object)
    if (manifest.get("schema_version") != 1 or manifest.get("status") != STATUS or
            manifest.get("native_support") is not False or manifest.get("target") != "x86_64-linux" or
            receipt.get("native_support") is not False or receipt.get("status") != STATUS or
            receipt.get("candidate") != manifest.get("candidate") or receipt.get("executable") != manifest.get("executable")):
        raise ValueError("runtime proof identity or scope differs")
    candidate = manifest["candidate"]
    if (candidate.get("upstream_commit") != COMMIT or
            candidate.get("current_configuration") not in PRODUCER_CONFIGURATIONS):
        raise ValueError("runtime upstream pin differs")
    for field in ("patch_sha256", "base_sha256", "binary_overlay_sha256", "validation_sha256", "complete_source_inventory_sha256", "current_source_receipt_sha256"):
        if not isinstance(candidate.get(field), str) or not HASH.fullmatch(candidate[field]):
            raise ValueError("runtime candidate digest differs")
    for field in ("compile_invocation_id", "source_verification_invocation_id", "current_compile_invocation_id", "current_source_verification_invocation_id"):
        hash_uuid(candidate[field])
    executable = manifest["executable"]
    if type(executable.get("backend_max_bytes")) is not int or executable["backend_max_bytes"] != MAX_BACKEND_BYTES:
        raise ValueError("runtime executable role bound differs")
    for phase, bound in (("original", MAX_ORIGINAL_BYTES), ("stripped", MAX_BACKEND_BYTES), ("packaged", MAX_BACKEND_BYTES)):
        if (not isinstance(executable.get(phase + "_sha256"), str) or not HASH.fullmatch(executable[phase + "_sha256"]) or
                type(executable.get(phase + "_bytes")) is not int or not 0 < executable[phase + "_bytes"] <= bound):
            raise ValueError("runtime executable digest or bound differs")
    if set(files) != set(manifest["files"]) | {MANIFEST}:
        raise ValueError("runtime archive membership differs")
    for name, record in manifest["files"].items():
        if record != {"sha256": digest(files[name]), "bytes": len(files[name]), "mode": modes[name]}:
            raise ValueError("runtime member bytes or mode differ")
    runtime = manifest["runtime"]
    if type(runtime.get("backend_max_bytes")) is not int or runtime["backend_max_bytes"] != MAX_BACKEND_BYTES:
        raise ValueError("runtime backend role bound differs")
    dependencies = runtime["dependencies"]
    if (not isinstance(dependencies, list) or not dependencies or dependencies != sorted(set(dependencies)) or
            runtime["loader"] not in dependencies or runtime.get("caBundle") != CA or
            runtime.get("backendInterpreter") != portable._BACKEND_INTERPRETER or
            set(files) != {MANIFEST, "bin/codex", BACKEND, CA, *dependencies}):
        raise ValueError("runtime closure inventory differs")
    for name in dependencies:
        if name != PREFIX + "lib/" + portable._basename(name):
            raise ValueError("runtime dependency leaves private library directory")
    names = {Path(name).name for name in dependencies}
    for name in [BACKEND, *dependencies]:
        metadata = portable.elf_metadata(files[name], max_bytes=MAX_BACKEND_BYTES if name == BACKEND else portable._MAX_FILE)
        if metadata["machine"] != 62 or any("/" in value or value not in names for value in metadata["needed"]):
            raise ValueError("runtime ELF dependency leaves closed graph")
        if name == BACKEND:
            if metadata["interpreter"] != portable._BACKEND_INTERPRETER or metadata["rpath"] != ["$ORIGIN/../lib"]:
                raise ValueError("runtime backend lookup differs")
        elif (metadata["interpreter"] not in (None, portable._BACKEND_INTERPRETER) or
              any(value != "$ORIGIN" for value in metadata["rpath"])):
            raise ValueError("runtime library lookup leaves closed graph")
    if files["bin/codex"] != codex_launcher(Path(runtime["loader"]).name):
        raise ValueError("runtime launcher differs")
    portable._verify_ca_bundle(files[CA])
    executable = manifest["executable"]
    if executable["packaged_sha256"] != digest(files[BACKEND]) or executable["packaged_bytes"] != len(files[BACKEND]):
        raise ValueError("runtime packaged executable identity differs")
    return manifest, files


def read_runtime_bundle(archive_path, receipt_path):
    with Path(archive_path).open("rb") as stream:
        payload = stream.read(MAX_ARCHIVE_BYTES + 1)
    return verify_runtime_files(payload, read_json(Path(receipt_path)))


def build_package(source, artifact, source_receipt, producer_receipt, output, strip, patchelf, runtime_files, ca_bundle, tool_path,
                  runtime_input_manifest_sha256=None):
    candidate, producer = candidate_inputs(artifact, source_receipt, producer_receipt)
    if not runtime_files or len(runtime_files) > MAX_FILES or len(set(runtime_files)) != len(runtime_files):
        raise ValueError("declared runtime files absent or duplicated")
    if not re.fullmatch(r"/nix/store/[a-z0-9]{32}-[A-Za-z0-9+._-]+/bin", tool_path):
        raise ValueError("declared tool search path differs")
    runtime_inventory, declared_bytes = [], 0
    for path in runtime_files:
        value = portable._read(path)
        declared_bytes += len(value)
        if declared_bytes > MAX_DECLARED_RUNTIME_BYTES:
            raise ValueError("declared runtime input bytes exceed bound")
        runtime_inventory.append({"basename": path.name, "declared_source": str(path.resolve(strict=True)),
                                  "sha256": digest(value), "bytes": len(value)})
    if source.resolve() != source or any(output.resolve().is_relative_to(path.resolve()) for path in (source.parent, artifact)):
        raise ValueError("runtime output overlaps produced source or artifact")
    private_root(output, create=True)
    write_receipt(output, "runtime-import-intent.json", {"ruling_id": "R-N13", "additional_ruling_id": RULING,
        "candidate": candidate, "original_sha256": producer["original_sha256"], "original_bytes": producer["original_bytes"]})
    with tempfile.TemporaryDirectory(dir=output, prefix=".runtime-copy-") as temporary:
        copied = Path(temporary) / "codex.bin"
        phase_marker("copy")
        with copied.open("xb") as destination:
            original = stream_original(source, destination)
            destination.flush()
            os.fsync(destination.fileno())
        copied.chmod(0o755)
        if original != {"sha256": producer["original_sha256"], "bytes": producer["original_bytes"]}:
            raise ValueError("produced executable differs from exact receipt")
        phase_marker("strip")
        run_tool([str(strip), "--strip-all", str(copied)], tool_path)
        phase_marker("read-stripped")
        stripped_size_marker(copied.stat().st_size)
        stripped = portable._read(copied, max_bytes=MAX_BACKEND_BYTES)
        stripped_metadata = portable.elf_metadata(stripped, max_bytes=MAX_BACKEND_BYTES)
        phase_marker("loader")
        loader, loader_witness = select_loader(stripped_metadata, runtime_files)
        phase_marker("relocate")
        run_tool([str(patchelf), "--set-interpreter", str(loader), str(copied)], tool_path)
        phase_marker("assemble")
        files, runtime = assemble_runtime(copied, runtime_files, patchelf, ca_bundle)
    # A second bounded stream proves the original output remains byte-identical.
    phase_marker("original-verify")
    if stream_original(source) != original:
        raise ValueError("produced original changed during runtime packaging")
    if len(files) > MAX_FILES or sum(map(len, files.values())) > MAX_RUNTIME_BYTES:
        raise ValueError("runtime payload exceeds bound")
    executable = {"backend_max_bytes": MAX_BACKEND_BYTES,
        "original_sha256": original["sha256"], "original_bytes": original["bytes"],
        "stripped_sha256": digest(stripped), "stripped_bytes": len(stripped),
        "packaged_sha256": digest(files[BACKEND]), "packaged_bytes": len(files[BACKEND])}
    manifest = {"schema_version": 1, "status": STATUS, "native_support": False, "target": "x86_64-linux",
        "candidate": candidate, "executable": executable, "runtime": runtime, "loader_relocation": loader_witness,
        "files": {name: {"sha256": digest(value), "bytes": len(value), "mode": 0o644 if name == CA else 0o755}
                  for name, value in sorted(files.items())},
        "runtime_input_inventory": runtime_inventory,
        "transformations": {"strip_option": "--strip-all", "strip_tool_sha256": digest(strip.resolve().read_bytes()),
            "tool_search_path": tool_path,
            "patchelf_tool_sha256": digest(patchelf.resolve().read_bytes()),
            "producer_receipt_sha256": digest(producer_receipt.read_bytes()),
            "source_receipt_sha256": digest(source_receipt.read_bytes())}}
    if runtime_input_manifest_sha256 is not None:
        if not HASH.fullmatch(runtime_input_manifest_sha256):
            raise ValueError("runtime input response-file digest differs")
        manifest["transformations"]["runtime_input_manifest_sha256"] = runtime_input_manifest_sha256
    phase_marker("archive-build")
    payload = archive_bytes(files, manifest)
    receipt = {"schema_version": 1, "ruling_id": "R-N13", "additional_ruling_id": RULING,
        "status": STATUS, "native_support": False, "candidate": candidate, "executable": executable,
        "archive_sha256": digest(payload), "archive_bytes": len(payload), "manifest_sha256": digest(json_bytes(manifest)),
        "scope": "Declared transformed runtime proof input; no SDK execution, installation or continuity proof."}
    phase_marker("archive-verify")
    verify_runtime_files(payload, receipt)
    phase_marker("write")
    for name, value in (("codex-owner-runtime.tar.gz", payload), ("runtime-manifest.json", json_bytes(manifest))):
        descriptor = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    write_receipt(output, "runtime-receipt.json", receipt)
    return receipt


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for name in ("source-binary", "artifact-dir", "source-receipt", "producer-receipt", "output-directory", "strip", "patchelf", "ca-bundle"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--runtime-files-manifest", type=Path, required=True,
                        help="Declared finite JSON file with canonical runfiles keys")
    parser.add_argument("--tool-path", required=True)
    args = parser.parse_args()
    # Fixed Bazel data/tool arguments may not be shadowed by appended operator
    # arguments. The target supplies each of these exactly once.
    for name in ("artifact-dir", "strip", "patchelf", "ca-bundle", "runtime-files-manifest", "tool-path"):
        if sum(argument.split("=", 1)[0] == "--" + name for argument in sys.argv[1:]) != 1:
            parser.error("declared runtime input option duplicated or absent")
    artifact = args.artifact_dir.parent if args.artifact_dir.is_file() else args.artifact_dir
    try:
        # __file__ is deliberately the declared main's runfiles path; resolving
        # its symlink would instead point at an ambient workspace source tree.
        runtime_files = read_runtime_inputs(args.runtime_files_manifest, ROOT.parent.parent)
        receipt = build_package(args.source_binary, artifact, args.source_receipt, args.producer_receipt,
            args.output_directory, args.strip, args.patchelf, runtime_files, args.ca_bundle, args.tool_path,
            runtime_input_manifest_sha256=digest(args.runtime_files_manifest.read_bytes()))
    except (ValueError, OSError, KeyError, TypeError, tarfile.TarError):
        print("Runtime import refused: declared input custody, bounds or closure failed.", file=sys.stderr)
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
