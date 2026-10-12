"""Reseal a declared final signed app without signing or mutating that input."""
import argparse
from pathlib import Path
import time

from bundle import module


def main():
    parser = argparse.ArgumentParser()
    for name in ("app", "output", "receipt", "source-revision", "source-dirty", "channel", "version",
                 "operator-receipt", "operator-receipt-sha256", "artifact-module", "macho-module"):
        parser.add_argument("--" + name, required=True)
    args = parser.parse_args()
    artifact = module("darwin_artifact", args.artifact_module)
    artifact.require(args.source_dirty in ("true", "false"), "dirty selector")
    # The caller supplies a separately pinned metadata-only operator receipt.
    # Descriptor custody and closed receipt fields are verified before copying.
    signed = artifact.read_selected(args.operator_receipt, artifact.MAX_METADATA,
                                    time.monotonic() + artifact.MAX_SECONDS)
    artifact.require(artifact.digest(args.operator_receipt_sha256) and
                     artifact.sha(signed) == args.operator_receipt_sha256,
                     "declared operator receipt binding")
    result = artifact.seal(args.app, args.output, args.source_revision, args.source_dirty == "true", args.channel,
                           args.version, artifact.load_macho(args.macho_module), signed)
    Path(args.receipt).write_bytes(artifact.encoded(result))


if __name__ == "__main__":
    main()
