"""Verify dedicated proof workspace metadata without reading operator data."""
import argparse
import os
from pathlib import Path
import stat


def safe_directory(path, uid, private=False):
    metadata = os.lstat(path)
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in {0, uid} or metadata.st_mode & 0o022:
        raise ValueError("unsafe proof directory metadata")
    if private and (metadata.st_uid != uid or stat.S_IMODE(metadata.st_mode) != 0o700):
        raise ValueError("proof directory must already be private and owned")


def validate_ancestry(path, uid, anchor=Path("/")):
    if (not path.is_absolute() or ".." in path.parts or any(value in str(path) for value in ["\n", "\r", "\x00"])
            or not (path == anchor or anchor in path.parents)):
        raise ValueError("proof directory must have safe absolute ancestry")
    for component in reversed([path, *path.parents]):
        if component == anchor or anchor in component.parents:
            safe_directory(component, uid)


def validate_workspace(workspace, base, home, uid, platform):
    if not home.is_absolute() or ".." in home.parts:
        raise ValueError("HOME authority must be absolute")
    validate_ancestry(home, uid)
    if os.lstat(home).st_uid != uid:
        raise ValueError("HOME authority must be owned")
    if base.name != ("OmuxProof" if platform == "Darwin" else "omux-proof"):
        raise ValueError("unrecognized proof base")
    if platform == "Darwin" and base != home / "Library" / "Application Support" / "OmuxProof":
        raise ValueError("Darwin proof base must use its fixed user state path")
    if workspace.parent != base or not workspace.name.startswith(".run-") or len(workspace.name) > 64:
        raise ValueError("workspace must be a dedicated proof child")
    validate_ancestry(workspace, uid)
    safe_directory(base, uid, private=True)
    safe_directory(workspace, uid, private=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--platform", choices=["Linux", "Darwin"], required=True)
    args = parser.parse_args()
    try:
        validate_workspace(args.workspace, args.base, Path(os.environ["HOME"]), os.getuid(), args.platform)
    except (OSError, ValueError):
        parser.exit(3, "proof workspace custody rejected\n")
