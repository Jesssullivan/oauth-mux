"""Current declared Omux artifact; no activation, registration or browser effects."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time

# Logical declared runfiles only; never resolve to an ambient checkout.
sys.path.insert(0, str(Path(__file__).absolute().parent.parent / "nix"))
import home_manager_artifact as export
import pack
import dev_stage

MODE = "current-home-manager-artifact-reserved"
ENV = "OMUX_CURRENT_HM_"


PHASES = ('entry','provenance','component-aliases','extension-metadata','extension-bytes',
    'extension-validation','portable-pack','archive-validation','component-binding',
    'metadata-recheck','publication-parent','archive-create','archive-write','archive-readback',
    'envelope-create','artifact-copy','artifact-seal','artifact-nar','receipt-metadata',
    'envelope-seal','publication-recheck','resource-close')
PREDICATES = {
    'current-artifact-provenance-refused':'provenance',
    'current-artifact-original-clock-refused':'original-clock',
    'current-extension-metadata-changed':'extension-metadata-drift',
    'current-artifact-components':'component-binding',
    'current-archive-short-write':'archive-short-write',
    'current-archive-write-replaced':'archive-write-identity',
    'current-artifact-copy-byte-binding':'copied-artifact-bytes',
    'current-artifact-publication-changed':'published-artifact-drift',
    'archive inputs exceed bounded payload size':'pack-input-size',
    'archive exceeds bounded payload size':'pack-payload-size',
    'unsupported reference schema':'reference-schema',
    'development bundler cannot publish stable claims':'reference-status',
    'invalid native Qt resolution witness':'qt-witness-schema',
    'invalid canonical library variant custody':'qt-witness-variants',
    'Qt resolution witness does not bind its packaged control':'qt-control-binding',
    'acquired-tree-node-writable':'sealed-tree-mode',
}


def phase(progress, value):
    if value not in PHASES:
        raise ValueError('current-artifact-diagnostic-phase-refused')
    if progress is not None:
        progress['phase'] = value


def diagnostic(error, progress):
    value = progress.get('phase','entry')
    value = value if value in PHASES else 'entry'
    category = next((name for cls,name in ((dev_stage.StageError,'extension'),(OSError,'os'),
        (KeyError,'key'),(TypeError,'type'),(ValueError,'value')) if isinstance(error,cls)), 'unclassified')
    predicate = PREDICATES.get(error.args[0], 'unclassified') if (type(error) is ValueError
        and len(error.args)==1 and type(error.args[0]) is str) else 'unclassified'
    return {'scope':'current-home-manager-artifact-refusal-v1','phase':value,'category':category,
            'predicate':predicate,'shipped':False,'artifactQualified':False,
            'activationQualified':False,'browserQualified':False,'custodyQualified':False,
            'continuityQualified':False,'liveQualified':False}


def provenance(environment, now_ns=None):
    value = {name: environment.get(ENV + name) for name in
             ("MODE", "SOURCE_COMMIT", "SOURCE_DIRTY", "GRAPH_SHA256", "ENTRY_NS", "DEADLINE_NS")}
    if (value["MODE"] != MODE or not re.fullmatch(r"[0-9a-f]{40}", value["SOURCE_COMMIT"] or "")
            or value["SOURCE_DIRTY"] not in ("true", "false")
            or not re.fullmatch(r"[0-9a-f]{64}", value["GRAPH_SHA256"] or "")
            or not all(re.fullmatch(r"[1-9][0-9]{0,19}", value[key] or "")
                       for key in ("ENTRY_NS", "DEADLINE_NS"))):
        raise ValueError("current-artifact-provenance-refused")
    entry, deadline = int(value["ENTRY_NS"]), int(value["DEADLINE_NS"])
    now = time.monotonic_ns() if now_ns is None else now_ns
    if deadline - entry != 1200_000_000_000 or not entry <= now < deadline - 30_000_000_000:
        raise ValueError("current-artifact-original-clock-refused")
    return {"sourceRevision": value["SOURCE_COMMIT"], "sourceDirty": value["SOURCE_DIRTY"] == "true",
            "graphSha256": value["GRAPH_SHA256"], "originalEntryMonotonicNs": entry,
            "originalDeadlineMonotonicNs": deadline}, (deadline - 30_000_000_000) / 1e9


def recheck_metadata(path, expected):
    export.require(pack.read_bundle(path) == expected, "current-extension-metadata-changed")
    return expected


def component_paths(args):
    # Strict scalar pack inputs need physical files. Runtime/plugin vectors are
    # declared aliases: portable validates their bounded chains and SONAME roles.
    # Resolving the vectors here erases that existing declared input authority.
    for name,value in vars(args).items():
        if isinstance(value,Path):
            setattr(args,name,value.resolve(strict=True))
    return args


def produce(args, environment, progress=None):
    phase(progress, "provenance")
    evidence, until = provenance(environment)
    export.acquired.check_deadline(until)
    # Paths are fixed declared target arguments. Canonicalize their Bazel runfile
    # aliases once; this route has no caller-selected component path or fallback.
    phase(progress, "component-aliases")
    component_paths(args)
    phase(progress, "extension-metadata")
    metadata_raw = pack.read_bundle(args.metadata)
    metadata = json.loads(metadata_raw)
    phase(progress, "extension-bytes")
    extension = pack.read_bundle(args.extension)
    # Existing exact development extension schema/id/member proof, before publication.
    import tempfile
    phase(progress, "extension-validation")
    with tempfile.TemporaryDirectory(prefix="omux-current-extension-", dir=environment["TEST_TMPDIR"]) as temp:
        dev_stage.unpack(extension, Path(temp), metadata)
    export.acquired.check_deadline(until)
    phase(progress, "portable-pack")
    payload = pack.make_bundle(args.core, args.daemon, args.reference, args.systemd_template,
        args.launchd_template, "x86_64-linux", source_revision=evidence["sourceRevision"],
        source_dirty=evidence["sourceDirty"], runtime_files=args.runtime_file, patchelf=args.patchelf,
        ca_bundle=args.ca_bundle, control=args.control, qt_plugins=args.qt_plugin,
        resolution_witness=pack.read_witness(args.resolution_witness),
        qt_runtime_files=args.qt_runtime_file, channel="development", action_deadline=until)
    phase(progress, "archive-validation")
    manifest, files = pack.verify_bundle(payload)
    phase(progress, "component-binding")
    export.require(manifest["provenance"] == {key: evidence[key] for key in ("sourceRevision", "sourceDirty")}
                   and all(name in files for name in export.NATIVE_BINS), "current-artifact-components")
    # Fresh exclusive envelope; no installer or service operation is called.
    export.acquired.check_deadline(until)
    phase(progress, "metadata-recheck")
    recheck_metadata(args.metadata, metadata_raw)
    return publish(payload, files, manifest, extension, metadata_raw, evidence,
                   Path(environment["TEST_UNDECLARED_OUTPUTS_DIR"]), until, progress=progress)


def publish(payload, files, manifest, extension, metadata_raw, evidence, output, until, *, progress=None):
    phase(progress, "publication-parent")
    with export.HeldDirectory(output) as initial_parent:
        initial_parent.check()
        archive_path = output / "current-home-manager.tar.gz"
        export.acquired.check_deadline(until)
        phase(progress, "archive-create")
        fd = os.open(archive_path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=initial_parent.fd)
        try:
            phase(progress, "archive-write")
            view = memoryview(payload)
            offset = 0
            while offset < len(view):
                initial_parent.check()
                export.acquired.check_deadline(until)
                count = os.write(fd, view[offset:offset + 65536])
                export.require(count > 0, "current-archive-short-write")
                offset += count
            os.fsync(fd)
            export.acquired.check_deadline(until)
            export.require(export.snapshot(os.fstat(fd)) == export.snapshot(os.stat(
                archive_path.name, dir_fd=initial_parent.fd, follow_symlinks=False)),
                "current-archive-write-replaced")
        finally:
            os.close(fd)
        initial_parent.check()
        export.acquired.check_deadline(until)
        phase(progress, "archive-readback")
        archive = export.Archive(archive_path, pack.digest(payload), until)
        try:
            with export.HeldDirectory(output) as parent:
                tree = export.ExportTree(parent, archive, until)
                try:
                    phase(progress, "envelope-create")
                    tree.directory("current-home-manager")
                    tree.directory("current-home-manager/artifact")
                    phase(progress, "artifact-copy")
                    for name, raw in sorted(files.items()):
                        tree.write("current-home-manager/artifact/" + name, raw,
                                   executable=bool(pack.archive_mode(name, manifest.get("runtime")) & 0o111))
                    phase(progress, "artifact-seal")
                    tree.seal("current-home-manager/artifact")
                    root = output / "current-home-manager/artifact"
                    phase(progress, "artifact-nar")
                    actual, nodes, facts, nar_hash, nar_size = export.tree_bytes(root, until)
                    export.require(actual == files, "current-artifact-copy-byte-binding")
                    phase(progress, "receipt-metadata")
                    receipt = {"schemaVersion": 1, "kind": "omux-current-home-manager-artifact-v1",
                        **evidence, "archiveSha256": pack.digest(payload), "archiveBytes": len(payload),
                        "manifestSha256": pack.digest(files["release-manifest.json"]),
                        "narHash": nar_hash, "narSize": nar_size, "system": "x86_64-linux",
                        "channel": "development", "nativeBins": export.NATIVE_BINS,
                        "extensionSha256": pack.digest(extension), "extensionBytes": len(extension),
                        "extensionMetadataSha256": pack.digest(metadata_raw),
                        "sourceQualification": "original-coordinator-source-and-declared-current-graph",
                        "shipped": False, "activationQualified": False, "browserQualified": False,
                        "custodyQualified": False, "continuityQualified": False, "liveQualified": False}
                    tree.write("current-home-manager/extension.zip", extension)
                    tree.write("current-home-manager/extension-metadata.json", metadata_raw)
                    tree.write("current-home-manager/inventory.json", export.encoded({"schemaVersion": 1, "nodes": nodes}))
                    tree.write("current-home-manager/receipt.json", export.encoded(receipt))
                    phase(progress, "envelope-seal")
                    tree.seal("current-home-manager")
                    phase(progress, "publication-recheck")
                    tree.check()
                    export.require(export.tree_bytes(root, until)[2] == facts, "current-artifact-publication-changed")
                    initial_parent.check()
                    phase(progress, "resource-close")
                    return receipt
                finally:
                    tree.close()
        finally:
            archive.close()


def main():
    parser = argparse.ArgumentParser()
    for name in ("core", "daemon", "control", "reference", "systemd-template", "launchd-template",
                 "extension", "metadata", "resolution-witness", "patchelf", "ca-bundle"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("runtime-file", "qt-runtime-file", "qt-plugin"):
        parser.add_argument("--" + name, type=Path, action="append", required=True)
    args = parser.parse_args()
    progress = {}
    try:
        receipt = produce(args, os.environ, progress)
        print(json.dumps({"scope": receipt["kind"], "manifestSha256": receipt["manifestSha256"],
                          "narHash": receipt["narHash"], "shipped": False}, sort_keys=True))
        return 0
    except (ValueError, OSError, KeyError, TypeError, dev_stage.StageError) as error:
        print(json.dumps(diagnostic(error, progress), sort_keys=True))
        print("current-home-manager-artifact-refused", file=sys.stderr)
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
