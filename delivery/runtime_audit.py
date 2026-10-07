"""Observe pinned native Qt loader resolution without provider or vault access.

This bounded startup witness does not establish interactive platform support.
Invoke only through the declared Bazel runtime_audit target.
"""
from __future__ import annotations

import hashlib
import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path

from portable import elf_metadata


def digest(path: Path) -> str:
    if not path.is_file() or path.stat().st_size > 128 * 1024 * 1024:
        raise ValueError("audit input is not a bounded regular file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("control", type=Path)
    parser.add_argument("plugin", type=Path)
    parser.add_argument("--variant", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    control = args.control.resolve(strict=True)
    plugin = args.plugin.resolve(strict=True)
    if plugin.name != "libqoffscreen.so" or plugin.parent.name != "platforms":
        raise ValueError("audit requires the declared Qt offscreen platform plugin")
    with tempfile.TemporaryDirectory(dir=str(Path("/tmp").resolve())) as temporary:
        root = Path(temporary)
        # A short private namespace leaves space for Omux's hashed socket child.
        desktop = root / "r"
        environment = {"PATH": "/nonexistent", "LANG": "C"}
        for name, child in (("XDG_RUNTIME_DIR", "r"), ("XDG_STATE_HOME", "s"), ("XDG_CONFIG_HOME", "c"),
                            ("XDG_DATA_HOME", "d"), ("XDG_CACHE_HOME", "k")):
            directory = root / child
            directory.mkdir(mode=0o700)
            environment[name] = str(directory)
        # Offline startup never connects. Supply its private fixture endpoint
        # explicitly: namespace UID remapping can make host /tmp ancestry
        # appear foreign, and default runtime custody is a separate test gate.
        completed = subprocess.run([str(control), "--self-check", "--socket", str(desktop / "control.sock")], stdin=subprocess.DEVNULL,
                                   capture_output=True, timeout=10, check=False, env=environment | {
                                       "QT_QPA_PLATFORM": "offscreen", "XDG_RUNTIME_DIR": str(desktop),
                                       "QT_PLUGIN_PATH": str(plugin.parent.parent),
                                       "QT_QPA_PLATFORM_PLUGIN_PATH": str(plugin.parent),
                                       "LD_DEBUG": "libs",
                                   })
    if completed.returncode != 0 or completed.stdout.strip() != b"OMUX_CONTROL_SELF_CHECK_OK":
        classifications = ("Unsafe absolute Omux path", "Omux directory unavailable or unsafe",
                           "Omux directory must be private to the current user", "Omux socket path is too long",
                           "Omux directory unavailable", "Unsafe Omux directory owner",
                           "Unsafe Omux directory permissions")
        reason = next((value for value in classifications if value.encode() in completed.stderr), "unclassified")
        raise ValueError(f"native Qt startup did not produce the bounded success marker (exit={completed.returncode}, reason={reason})")
    # Never publish full loader diagnostics: only public pinned library inputs.
    names = sorted(set(re.findall(rb"calling init: (/nix/store/[^\s]+/libsystemd\.so\.[^\s]+)", completed.stderr)))
    libraries = []
    for raw in names:
        path = Path(raw.decode("ascii")).resolve(strict=True)
        if not str(path).startswith("/nix/store/"):
            raise ValueError("native resolution escaped declared Nix inputs")
        variants = sorted({digest(candidate) for candidate in args.variant})
        canonical = digest(path)
        if args.variant and canonical not in variants:
            raise ValueError("native loaded library is outside declared candidate custody")
        libraries.append({"soname": "libsystemd.so.0", "sha256": canonical,
                          "variants": variants or [canonical]})
    if len(libraries) != 1:
        raise ValueError("native Qt startup did not expose exactly one systemd resolution witness")
    result = json.dumps({
        "schemaVersion": 1, "scope": "native-qt-offscreen-startup-only",
        "target": {62: "x86_64-linux", 183: "aarch64-linux"}[elf_metadata(control.read_bytes())["machine"]],
        "controlSha256": digest(control), "libraries": libraries,
    }, sort_keys=True, indent=2) + "\n"
    if args.output is None:
        print(result, end="")
    else:
        args.output.write_text(result)


if __name__ == "__main__":
    main()
