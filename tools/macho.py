"""Strict Mach-O metadata inspection for the macOS bundle action.

This module reads bytes only: it neither executes a binary nor asks the host
loader to inspect it. Layouts and command constants follow Apple's
EXTERNAL_HEADERS/mach-o/{loader,fat}.h. It supports the two macOS 64-bit
architectures shipped by Omux, including universal containers in either byte
order. Signature metadata describes a bounded blob, not signature validity.
"""

from dataclasses import dataclass
import struct

__all__ = ("MachOSlice", "parse_macho")


@dataclass(frozen=True, slots=True)
class MachOSlice:
    architecture: str
    filetype: int
    dependencies: tuple[str, ...]
    rpaths: tuple[str, ...]
    install_id: str | None
    minimum_os: tuple[int, int, int] | None
    code_signature: tuple[int, int] | None


_THIN_MAGIC = {b"\xcf\xfa\xed\xfe": "<", b"\xfe\xed\xfa\xcf": ">"}
_THIN_32_MAGIC = {b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce"}
_FAT_MAGIC = {
    b"\xca\xfe\xba\xbe": (">", False),
    b"\xbe\xba\xfe\xca": ("<", False),
    b"\xca\xfe\xba\xbf": (">", True),
    b"\xbf\xba\xfe\xca": ("<", True),
}
_ARCHITECTURES = {0x01000007: "x86_64", 0x0100000C: "arm64"}
_DYLIB_LOAD_COMMANDS = {0xC, 0x80000018, 0x8000001F, 0x80000023, 0x20}
_LC_ID_DYLIB = 0xD
_LC_RPATH = 0x8000001C
_LC_CODE_SIGNATURE = 0x1D
_LC_VERSION_MIN_MACOSX = 0x24
_LC_BUILD_VERSION = 0x32


def _check_range(offset: int, size: int, limit: int, description: str) -> None:
    # Subtraction keeps this check safe if ported to a fixed-width language.
    if offset < 0 or size < 0 or offset > limit or size > limit - offset:
        raise ValueError(description + " is out of bounds")


def _unpack(data: memoryview, endian: str, fmt: str, offset: int, description: str):
    _check_range(offset, struct.calcsize(endian + fmt), len(data), description)
    return struct.unpack_from(endian + fmt, data, offset)


def _command_string(command: memoryview, endian: str, minimum: int) -> str:
    if len(command) < minimum:
        raise ValueError("truncated path load command")
    (offset,) = _unpack(command, endian, "I", 8, "path offset")
    if offset < minimum or offset >= len(command):
        raise ValueError("invalid load-command string offset")
    value = bytes(command[offset:])
    terminator = value.find(b"\0")
    if terminator < 0:
        raise ValueError("unterminated load-command string")
    if terminator == 0:
        raise ValueError("empty load-command path")
    # Apple's loader.h requires zero load-command padding. Its
    # install_name_tool zeroes replacement commands before writing shorter
    # names, so this also accepts its normal relocation output.
    # https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h
    if any(value[terminator + 1 :]):
        raise ValueError("nonzero load-command string padding")
    try:
        return value[:terminator].decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("load-command path is not UTF-8") from None


def _version(value: int) -> tuple[int, int, int]:
    return (value >> 16, (value >> 8) & 0xFF, value & 0xFF)


def _minimum_os(
    previous: tuple[int, int, int] | None, value: int
) -> tuple[int, int, int]:
    version = _version(value)
    if previous is not None and previous != version:
        raise ValueError("conflicting macOS minimum versions")
    return version


def _parse_thin(data: memoryview, expected_cpu: tuple[int, int] | None) -> MachOSlice:
    magic = bytes(data[:4])
    if magic in _THIN_32_MAGIC:
        raise ValueError("32-bit Mach-O slices are unsupported")
    endian = _THIN_MAGIC.get(magic)
    if endian is None:
        raise ValueError("slice is not a 64-bit Mach-O file")
    header = _unpack(data, endian, "8I", 0, "Mach-O header")
    _, cpu, subtype, filetype, ncommands, commands_size, _, reserved = header
    architecture = _ARCHITECTURES.get(cpu)
    if architecture is None:
        raise ValueError("unsupported Mach-O CPU type")
    if expected_cpu is not None and expected_cpu != (cpu, subtype):
        raise ValueError("universal CPU metadata differs from slice header")
    if reserved != 0:
        raise ValueError("nonzero reserved Mach-O header field")
    _check_range(32, commands_size, len(data), "Mach-O load-command region")
    if commands_size % 8 or ncommands > commands_size // 8:
        raise ValueError("invalid Mach-O load-command count or alignment")

    dependencies: list[str] = []
    rpaths: list[str] = []
    install_id = None
    minimum_os = None
    code_signature = None
    cursor = 32
    commands_end = cursor + commands_size
    for _ in range(ncommands):
        if commands_end - cursor < 8:
            raise ValueError("truncated load-command header")
        cmd, cmdsize = _unpack(data, endian, "2I", cursor, "load-command header")
        if cmdsize < 8 or cmdsize % 8:
            raise ValueError("invalid load-command size or alignment")
        _check_range(cursor, cmdsize, commands_end, "Mach-O load command")
        command = data[cursor : cursor + cmdsize]
        if cmd in _DYLIB_LOAD_COMMANDS or cmd == _LC_ID_DYLIB:
            path = _command_string(command, endian, 24)
            if cmd == _LC_ID_DYLIB:
                if install_id is not None:
                    raise ValueError("duplicate dylib install-ID command")
                install_id = path
            else:
                dependencies.append(path)
        elif cmd == _LC_RPATH:
            rpaths.append(_command_string(command, endian, 12))
        elif cmd == _LC_VERSION_MIN_MACOSX:
            if cmdsize != 16:
                raise ValueError("invalid macOS minimum-version command size")
            version, _ = _unpack(command, endian, "2I", 8, "minimum-version fields")
            minimum_os = _minimum_os(minimum_os, version)
        elif cmd == _LC_BUILD_VERSION:
            if cmdsize < 24:
                raise ValueError("truncated build-version command")
            platform, version, _, ntools = _unpack(
                command, endian, "4I", 8, "build-version fields"
            )
            if cmdsize != 24 + ntools * 8:
                raise ValueError("invalid build-version tool-table size")
            if platform != 1:
                raise ValueError("build-version platform is not macOS")
            minimum_os = _minimum_os(minimum_os, version)
        elif cmd == _LC_CODE_SIGNATURE:
            if cmdsize != 16:
                raise ValueError("invalid code-signature command size")
            if code_signature is not None:
                raise ValueError("duplicate code-signature command")
            offset, size = _unpack(command, endian, "2I", 8, "code-signature fields")
            _check_range(offset, size, len(data), "code-signature blob")
            if size == 0 or offset < commands_end:
                raise ValueError("empty or overlapping code-signature blob")
            code_signature = (offset, size)
        cursor += cmdsize
    if cursor != commands_end:
        raise ValueError("load commands do not fill their declared region")
    return MachOSlice(
        architecture=architecture,
        filetype=filetype,
        dependencies=tuple(dependencies),
        rpaths=tuple(rpaths),
        install_id=install_id,
        minimum_os=minimum_os,
        code_signature=code_signature,
    )


def parse_macho(data: bytes) -> tuple[MachOSlice, ...]:
    """Inspect supported thin or universal Mach-O bytes.

    Slices retain their universal-table order. All offsets are validated before
    reading; code-signature offsets in the result are relative to their slice.
    Invalid input raises ValueError with a static diagnostic that does not echo
    binary data, embedded paths, or host details.
    """
    if not isinstance(data, bytes):
        raise ValueError("Mach-O input must be bytes")
    if len(data) < 4:
        raise ValueError("truncated Mach-O magic")
    view = memoryview(data)
    magic = data[:4]
    container = _FAT_MAGIC.get(magic)
    if container is None:
        return (_parse_thin(view, None),)

    endian, fat64 = container
    (count,) = _unpack(view, endian, "I", 4, "universal header")
    entry_size = 32 if fat64 else 20
    table_size = count * entry_size
    _check_range(8, table_size, len(view), "universal slice table")
    if count == 0:
        raise ValueError("universal file has no slices")
    table_end = 8 + table_size
    entries = []
    seen_cpus = set()
    for index in range(count):
        cursor = 8 + index * entry_size
        if fat64:
            cpu, subtype, offset, size, alignment, reserved = _unpack(
                view, endian, "IIQQII", cursor, "universal slice entry"
            )
            if reserved != 0:
                raise ValueError("nonzero reserved universal slice field")
        else:
            cpu, subtype, offset, size, alignment = _unpack(
                view, endian, "5I", cursor, "universal slice entry"
            )
        if cpu not in _ARCHITECTURES:
            raise ValueError("unsupported universal CPU type")
        if cpu in seen_cpus:
            raise ValueError("duplicate universal architecture")
        seen_cpus.add(cpu)
        if alignment > (63 if fat64 else 31) or offset % (1 << alignment):
            raise ValueError("invalid universal slice alignment")
        _check_range(offset, size, len(view), "universal slice")
        if offset < table_end or size == 0:
            raise ValueError("empty universal slice or overlap with its table")
        entries.append((offset, size, cpu, subtype))

    previous_end = table_end
    for offset, size, _, _ in sorted(entries):
        if offset < previous_end:
            raise ValueError("overlapping universal slices")
        previous_end = offset + size
    return tuple(
        _parse_thin(view[offset : offset + size], (cpu, subtype))
        for offset, size, cpu, subtype in entries
    )
