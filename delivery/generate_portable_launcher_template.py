"""Generate the trusted Linux launcher template from a declared Bazel ELF.

This module deliberately does not import portable: portable imports its generated
output. The archive's own hashes never establish trust in a launcher template.
Run this generator only as its declared Bazel action using the locked toolchain.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import struct

ABI = 1
_MACHINES = {"x86_64-linux": 62, "aarch64-linux": 183}
_MAX_FILE = 32 * 1024 * 1024
_MAX_HEADERS = 4096
_MAX_SECTIONS = 8192
_MAGIC = b"OMUXLNXLAUNCHv1\0"


def _range(payload: bytes, offset: int, size: int) -> None:
    if offset < 0 or size < 0 or offset > len(payload) or size > len(payload) - offset:
        raise ValueError("launcher ELF range is outside the bounded file")


def validate_template(payload: bytes, target: str) -> None:
    """Accept only a bounded, non-PIE static ELF64 Linux executable.

    PT_DYNAMIC and SHT_DYNAMIC are refused wholesale: there can be no dynamic
    dependency, interpreter, RPATH or RUNPATH hidden in an uninspected table.
    Section headers are optional, but every supplied table and file-backed
    section is bounded. Only the exact native target selected by Bazel is trusted.
    """
    if target not in _MACHINES:
        raise ValueError("unsupported launcher target")
    if not 64 <= len(payload) <= _MAX_FILE or payload[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("launcher is not bounded ELF64 little-endian version 1")
    if payload[7] not in (0, 3) or payload[8] != 0 or any(payload[9:16]):
        raise ValueError("unsupported launcher ELF ABI")
    header = struct.unpack_from("<HHIQQQIHHHHHH", payload, 16)
    kind, machine, version, entry, phoff, shoff, flags, ehsize, phsize, phnum, shsize, shnum, shstr = header
    if kind != 2 or machine != _MACHINES[target] or version != 1 or ehsize != 64 or flags != 0:
        raise ValueError("launcher requires the exact target's static ET_EXEC")
    if not 0 < phnum <= _MAX_HEADERS or phsize != 56 or phoff < 64:
        raise ValueError("invalid launcher program-header table")
    _range(payload, phoff, phsize * phnum)
    loads = []
    executable_entry = False
    stack_headers = 0
    for index in range(phnum):
        ptype, pflags, offset, vaddr, _, filesz, memsz, align = struct.unpack_from(
            "<IIQQQQQQ", payload, phoff + index * phsize)
        _range(payload, offset, filesz)
        if ptype in (2, 3):
            raise ValueError("launcher must have no PT_DYNAMIC or PT_INTERP")
        if ptype == 1:
            if filesz > memsz or vaddr + memsz > 1 << 64 or pflags & ~7:
                raise ValueError("invalid launcher load segment")
            if align not in (0, 1) and (align & (align - 1) or offset % align != vaddr % align):
                raise ValueError("invalid launcher load alignment")
            if pflags & 1 and pflags & 2:
                raise ValueError("launcher has a writable executable segment")
            if pflags & 1 and vaddr <= entry < vaddr + filesz:
                executable_entry = True
            loads.append((vaddr, vaddr + memsz))
        elif ptype == 0x6474E551:
            stack_headers += 1
            if pflags & 1 or memsz != 0:
                raise ValueError("launcher requires a nonexecutable zero-size GNU_STACK")
    if stack_headers != 1:
        raise ValueError("launcher requires exactly one zero-size GNU_STACK")
    if not executable_entry or not loads:
        raise ValueError("launcher entry is not in a file-backed executable load")
    loads.sort()
    if any(left[1] > right[0] for left, right in zip(loads, loads[1:])):
        raise ValueError("launcher load segments overlap")
    if shoff == 0:
        if shnum != 0 or shstr != 0 or shsize not in (0, 64):
            raise ValueError("invalid absent launcher section table")
    else:
        if shoff < 64 or shsize != 64 or not 0 < shnum <= _MAX_SECTIONS or shstr >= shnum:
            raise ValueError("invalid launcher section table")
        _range(payload, shoff, shnum * shsize)
        for index in range(shnum):
            _, stype, _, _, offset, size, link, _, alignment, _ = struct.unpack_from(
                "<IIQQQQIIQQ", payload, shoff + index * shsize)
            if stype == 6:
                raise ValueError("launcher must have no dynamic section")
            if stype not in (0, 8):
                _range(payload, offset, size)
            if alignment not in (0, 1) and alignment & (alignment - 1):
                raise ValueError("invalid launcher section alignment")
            if link >= shnum:
                raise ValueError("launcher section link is outside its table")
    if len(payload) >= 256 and payload[-256:-240] == _MAGIC:
        raise ValueError("compiled template already contains a launcher record")


def render_template(payload: bytes, target: str) -> str:
    validate_template(payload, target)
    chunks = [repr(payload[index:index + 64]) for index in range(0, len(payload), 64)]
    return (
        "# Generated by the declared Bazel Linux launcher template action.\n"
        "# Trusted build input; never regenerate from archive-supplied bytes.\n"
        f"ABI = {ABI}\nTARGET = {target!r}\n"
        "TEMPLATE = (\n" + "".join(f"    {chunk}\n" for chunk in chunks) + ")\n"
        f"SHA256 = {hashlib.sha256(payload).hexdigest()!r}\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--launcher", type=Path, required=True)
    parser.add_argument("--target", choices=tuple(_MACHINES), required=True)
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args()
    with options.launcher.open("rb") as source:
        payload = source.read(_MAX_FILE + 1)
    try:
        rendered = render_template(payload, options.target)
    except ValueError as error:
        # Parser diagnostics describe structure only, never input bytes.
        parser.error(str(error))
    options.output.write_text(rendered, encoding="ascii")


if __name__ == "__main__":
    main()
