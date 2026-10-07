"""Review or apply the pinned native hook to an explicit upstream checkout."""

import argparse
import json
from pathlib import Path

from patch_io import combine_changes, verify_artifact, verify_inputs


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--write", action="store_true", help="Apply after all source hashes pass")
    args = parser.parse_args()
    artifact = args.artifact_dir.parent if args.artifact_dir.is_file() else args.artifact_dir
    manifest = json.loads((artifact / "manifest.json").read_text())
    _, patch, overlay = verify_artifact(artifact, manifest)
    original = verify_inputs(args.checkout.resolve(), manifest)
    changed = combine_changes(patch, overlay, original, manifest)
    if args.write:
        for name, value in changed.items():
            path = args.checkout / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(value)
    print(f"{'Applied' if args.write else 'Checked'} native hook for {manifest['upstream_commit']}; upstream compile/live proof remains required.")


if __name__ == "__main__":
    main()
