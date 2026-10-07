"""Mach-O metadata and rejection tests using synthetic, non-secret bytes."""

import struct
import unittest

from macho import MachOSlice, parse_macho


ARM64 = 0x0100000C
X86_64 = 0x01000007
LC_LOAD_DYLIB = 0xC
LC_ID_DYLIB = 0xD
LC_LOAD_WEAK_DYLIB = 0x80000018
LC_REEXPORT_DYLIB = 0x8000001F
LC_LAZY_LOAD_DYLIB = 0x20
LC_LOAD_UPWARD_DYLIB = 0x80000023
LC_RPATH = 0x8000001C
LC_VERSION_MIN_MACOSX = 0x24
LC_BUILD_VERSION = 0x32
LC_CODE_SIGNATURE = 0x1D


def padded(value, alignment=8):
    return value + b"\0" * (-len(value) % alignment)


def dylib(name, command=LC_LOAD_DYLIB, endian="<", name_offset=24):
    value = name.encode("utf-8") if isinstance(name, str) else name
    suffix = padded(value + b"\0")
    return struct.pack(endian + "6I", command, 24 + len(suffix), name_offset, 0, 0, 0) + suffix


def rpath(name, endian="<", name_offset=12):
    value = name.encode("utf-8") if isinstance(name, str) else name
    size = (12 + len(value) + 1 + 7) & ~7
    return struct.pack(endian + "3I", LC_RPATH, size, name_offset) + value + b"\0" * (size - 12 - len(value))


def packed_version(major, minor=0, patch=0):
    return (major << 16) | (minor << 8) | patch


def min_version(version=(13, 0, 0), endian="<"):
    return struct.pack(endian + "4I", LC_VERSION_MIN_MACOSX, 16, packed_version(*version), packed_version(14, 4))


def build_version(version=(13, 0, 0), endian="<", platform=1, tools=()):
    header = struct.pack(endian + "6I", LC_BUILD_VERSION, 24 + 8 * len(tools), platform, packed_version(*version), packed_version(14, 4), len(tools))
    return header + b"".join(struct.pack(endian + "2I", *tool) for tool in tools)


def signature(offset, size, endian="<"):
    return struct.pack(endian + "4I", LC_CODE_SIGNATURE, 16, offset, size)


def thin(commands=(), endian="<", cpu=ARM64, subtype=None, filetype=2, payload=b"", ncmds=None, sizeofcmds=None):
    subtype = (3 if cpu == X86_64 else 0) if subtype is None else subtype
    body = b"".join(commands)
    header = struct.pack(endian + "8I", 0xFEEDFACF, cpu, subtype, filetype, len(commands) if ncmds is None else ncmds, len(body) if sizeofcmds is None else sizeofcmds, 0, 0)
    return header + body + payload


def fat(slices, endian=">", wide=False, entries=None):
    """A bounded table followed by slices; alignment exponent zero is valid."""
    width = 32 if wide else 20
    next_offset = 8 + width * len(slices)
    rows = []
    payload = b""
    for index, item in enumerate(slices):
        data, cpu, subtype = item
        row = (cpu, subtype, next_offset, len(data), 0)
        if entries and index in entries:
            row = entries[index]
        rows.append(struct.pack(endian + ("IIQQII" if wide else "5I"), *row, 0) if wide else struct.pack(endian + "5I", *row))
        payload += data
        next_offset += len(data)
    return struct.pack(endian + "2I", 0xCAFEBABF if wide else 0xCAFEBABE, len(slices)) + b"".join(rows) + payload


class MachOTest(unittest.TestCase):
    def rejected(self, data):
        with self.assertRaises(ValueError):
            parse_macho(data)

    def test_minimal_thin_has_no_inferred_metadata(self):
        result = parse_macho(thin())
        self.assertIsInstance(result, tuple)
        self.assertEqual(len(result), 1)
        item = result[0]
        self.assertIsInstance(item, MachOSlice)
        self.assertEqual(item.architecture, "arm64")
        self.assertEqual(item.filetype, 2)
        self.assertEqual(item.dependencies, ())
        self.assertEqual(item.rpaths, ())
        self.assertIsNone(item.install_id)
        self.assertIsNone(item.minimum_os)
        self.assertIsNone(item.code_signature)

    def test_thin_endian_and_supported_architectures(self):
        for endian in ("<", ">"):
            for cpu, architecture in ((ARM64, "arm64"), (X86_64, "x86_64")):
                with self.subTest(endian=endian, architecture=architecture):
                    result = parse_macho(thin([min_version((13, 2, 1), endian)], endian, cpu))[0]
                    self.assertEqual(result.architecture, architecture)
                    self.assertEqual(result.minimum_os, (13, 2, 1))

    def test_every_supported_dependency_command_is_reported(self):
        commands = (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_REEXPORT_DYLIB, LC_LOAD_UPWARD_DYLIB, LC_LAZY_LOAD_DYLIB)
        names = tuple("@rpath/library_%s.dylib" % index for index in range(len(commands)))
        result = parse_macho(thin([dylib(name, command) for command, name in zip(commands, names)]))[0]
        self.assertEqual(result.dependencies, names)

    def test_install_id_is_separate_from_dependencies(self):
        result = parse_macho(thin([dylib("@rpath/owned.dylib", LC_ID_DYLIB), dylib("/usr/lib/libSystem.B.dylib")], filetype=6))[0]
        self.assertEqual(result.install_id, "@rpath/owned.dylib")
        self.assertEqual(result.dependencies, ("/usr/lib/libSystem.B.dylib",))
        self.assertEqual(result.filetype, 6)

    def test_rpaths_preserve_order_and_utf8(self):
        paths = ("@executable_path/../Frameworks", "@loader_path/../Libraries", "/synthetic/é")
        result = parse_macho(thin([rpath(path) for path in paths]))[0]
        self.assertEqual(result.rpaths, paths)

    def test_big_endian_path_and_signature_command_fields(self):
        commands = [dylib("@rpath/owned.dylib", LC_ID_DYLIB, ">"), dylib("/usr/lib/libSystem.B.dylib", endian=">"), rpath("@loader_path", ">")]
        offset = 32 + sum(len(command) for command in commands) + 16
        result = parse_macho(thin(commands + [signature(offset, 4, ">")], endian=">", payload=b"sign"))[0]
        self.assertEqual(result.install_id, "@rpath/owned.dylib")
        self.assertEqual(result.dependencies, ("/usr/lib/libSystem.B.dylib",))
        self.assertEqual(result.rpaths, ("@loader_path",))
        self.assertEqual(result.code_signature, (offset, 4))

    def test_build_version_with_tool_entries(self):
        result = parse_macho(thin([build_version((14, 4, 2), tools=((1, packed_version(16)), (3, packed_version(15))))]))[0]
        self.assertEqual(result.minimum_os, (14, 4, 2))

    def test_matching_minimum_version_commands_are_accepted(self):
        result = parse_macho(thin([min_version((13, 1, 2)), build_version((13, 1, 2))]))[0]
        self.assertEqual(result.minimum_os, (13, 1, 2))

    def test_conflicting_minimum_versions_are_rejected(self):
        self.rejected(thin([min_version((13, 0, 0)), build_version((14, 0, 0))]))

    def test_fat32_and_fat64_endian_variants(self):
        arm = thin([dylib("/usr/lib/libSystem.B.dylib")])
        intel = thin([rpath("@loader_path", endian=">")], endian=">", cpu=X86_64)
        for endian in ("<", ">"):
            for wide in (False, True):
                with self.subTest(endian=endian, wide=wide):
                    result = parse_macho(fat([(arm, ARM64, 0), (intel, X86_64, 3)], endian, wide))
                    self.assertEqual(tuple(item.architecture for item in result), ("arm64", "x86_64"))
                    self.assertEqual(result[0].dependencies, ("/usr/lib/libSystem.B.dylib",))
                    self.assertEqual(result[1].rpaths, ("@loader_path",))

    def test_code_signature_offsets_are_slice_relative(self):
        signed = thin([signature(48, 4)], payload=b"sign")
        result = parse_macho(fat([(signed, ARM64, 0)]))[0]
        self.assertEqual(result.code_signature, (48, 4))

    def test_signature_exactly_at_end_is_accepted(self):
        result = parse_macho(thin([signature(48, 4)], payload=b"sign"))[0]
        self.assertEqual(result.code_signature, (48, 4))

    def test_unknown_load_command_can_be_skipped_with_valid_bounds(self):
        command = struct.pack("<4I", 0x7654, 16, 0, 0)
        result = parse_macho(thin([command, dylib("@rpath/known.dylib")]))[0]
        self.assertEqual(result.dependencies, ("@rpath/known.dylib",))

    def test_unknown_magic_and_short_headers_are_rejected(self):
        for data in (b"", b"MZ" + b"\0" * 62, b"\xcf\xfa\xed", thin()[:31], b"\xca\xfe\xba\xbe\0\0\0"):
            with self.subTest(length=len(data)):
                self.rejected(data)

    def test_actual_32_bit_slice_is_rejected(self):
        for endian in ("<", ">"):
            self.rejected(struct.pack(endian + "7I", 0xFEEDFACE, 7, 3, 2, 0, 0, 0))

    def test_unsupported_cpu_is_rejected(self):
        self.rejected(thin(cpu=0x01000012))

    def test_load_command_minimum_and_alignment_are_checked(self):
        for size in (0, 4, 9, 12):
            with self.subTest(size=size):
                command = struct.pack("<2I", 0x7654, size) + b"\0" * max(size - 8, 0)
                self.rejected(thin([command]))

    def test_command_cannot_extend_outside_declared_command_region(self):
        command = struct.pack("<2I", 0x7654, 16)
        self.rejected(thin([command], payload=b"\0" * 8))

    def test_load_command_count_must_consume_exact_region(self):
        command = struct.pack("<2I", 0x7654, 8)
        self.rejected(thin([command], ncmds=0))
        self.rejected(thin([command], ncmds=2))
        self.rejected(thin([command], sizeofcmds=16, payload=b"\0" * 8))

    def test_command_region_must_fit_slice(self):
        self.rejected(thin(sizeofcmds=8))

    def test_dylib_command_header_must_be_complete(self):
        self.rejected(thin([struct.pack("<2I", LC_LOAD_DYLIB, 8)]))

    def test_dylib_string_offset_cannot_enter_header_or_leave_command(self):
        for offset in (0, 8, 23, 32, 0xFFFFFFFF):
            with self.subTest(offset=offset):
                self.rejected(thin([dylib("a", name_offset=offset)]))

    def test_rpath_string_offset_cannot_enter_header_or_leave_command(self):
        for offset in (0, 8, 11, 16, 0xFFFFFFFF):
            with self.subTest(offset=offset):
                self.rejected(thin([rpath("a", name_offset=offset)]))

    def test_unterminated_strings_do_not_use_following_command_bytes(self):
        bad_dylib = struct.pack("<6I", LC_LOAD_DYLIB, 32, 24, 0, 0, 0) + b"abcdefgh"
        bad_rpath = struct.pack("<3I", LC_RPATH, 16, 12) + b"abcd"
        for command in (bad_dylib, bad_rpath):
            self.rejected(thin([command, struct.pack("<2I", 0x7654, 8)]))

    def test_invalid_utf8_dependency_and_rpath_are_rejected(self):
        self.rejected(thin([dylib(b"\xff")]))
        self.rejected(thin([rpath(b"\xff")]))

    def test_empty_and_nonzero_padded_paths_are_rejected(self):
        for command in (dylib(""), rpath(""), dylib("a")[:-1] + b"x", rpath("a")[:-1] + b"x"):
            self.rejected(thin([command]))

    def test_duplicate_install_ids_are_rejected_even_if_equal(self):
        self.rejected(thin([dylib("@rpath/id", LC_ID_DYLIB), dylib("@rpath/id", LC_ID_DYLIB)]))

    def test_duplicate_signature_commands_are_rejected(self):
        self.rejected(thin([signature(64, 4), signature(64, 4)], payload=b"sign"))

    def test_signature_data_must_fit_same_slice(self):
        for offset, size in ((48, 5), (49, 4), (0xFFFFFFFF, 4), (48, 0xFFFFFFFF)):
            with self.subTest(offset=offset, size=size):
                self.rejected(thin([signature(offset, size)], payload=b"sign"))

    def test_signature_cannot_be_empty_or_overlap_headers_and_commands(self):
        for offset, size in ((48, 0), (0, 4), (31, 4), (32, 4), (47, 4)):
            with self.subTest(offset=offset, size=size):
                self.rejected(thin([signature(offset, size)], payload=b"sign"))

    def test_signature_cannot_spill_into_next_fat_slice(self):
        first = thin([signature(48, 8)], payload=b"sign")
        self.rejected(fat([(first, ARM64, 0), (thin(cpu=X86_64), X86_64, 3)]))

    def test_version_command_headers_are_checked(self):
        self.rejected(thin([struct.pack("<2I", LC_VERSION_MIN_MACOSX, 8)]))
        self.rejected(thin([struct.pack("<2I", LC_BUILD_VERSION, 8)]))

    def test_build_version_tool_count_must_fit_command(self):
        command = struct.pack("<6I", LC_BUILD_VERSION, 24, 1, packed_version(13), packed_version(14), 1)
        self.rejected(thin([command]))

    def test_build_version_must_name_macos_platform(self):
        self.rejected(thin([build_version(platform=2)]))

    def test_nonzero_reserved_thin_field_is_rejected(self):
        data = thin()
        self.rejected(data[:28] + struct.pack("<I", 1))

    def test_nonzero_reserved_fat64_field_is_rejected(self):
        data = fat([(thin(), ARM64, 0)], wide=True)
        self.rejected(data[:36] + struct.pack(">I", 1) + data[40:])

    def test_input_requires_immutable_bytes(self):
        self.rejected(bytearray(thin()))
        self.rejected(memoryview(thin()))

    def test_empty_fat_and_truncated_fat_table_are_rejected(self):
        self.rejected(struct.pack(">2I", 0xCAFEBABE, 0))
        self.rejected(struct.pack(">2I", 0xCAFEBABE, 1))
        self.rejected(struct.pack(">2I", 0xCAFEBABF, 1) + b"\0" * 31)

    def test_fat_slice_cpu_and_subtype_must_match_table(self):
        arm = thin()
        self.rejected(fat([(arm, X86_64, 3)]))
        self.rejected(fat([(arm, ARM64, 1)]))

    def test_duplicate_fat_architectures_are_rejected(self):
        self.rejected(fat([(thin(), ARM64, 0), (thin(), ARM64, 0)]))

    def test_fat_slice_cannot_overlap_table(self):
        self.rejected(fat([(thin(), ARM64, 0)], entries={0: (ARM64, 0, 8, 32, 0)}))

    def test_fat_slices_cannot_overlap_each_other(self):
        self.rejected(fat([(thin(), ARM64, 0), (thin(cpu=X86_64), X86_64, 3)], entries={1: (X86_64, 3, 48, 32, 0)}))

    def test_fat_slice_ranges_must_fit_input(self):
        for offset, size in ((29, 32), (28, 33), (0xFFFFFFFF, 32), (28, 0xFFFFFFFF), (28, 0)):
            with self.subTest(offset=offset, size=size):
                self.rejected(fat([(thin(), ARM64, 0)], entries={0: (ARM64, 0, offset, size, 0)}))

    def test_fat64_large_offsets_and_sizes_cannot_wrap_bounds(self):
        self.rejected(fat([(thin(), ARM64, 0)], wide=True, entries={0: (ARM64, 0, 0xFFFFFFFFFFFFFFFF, 32, 0)}))
        self.rejected(fat([(thin(), ARM64, 0)], wide=True, entries={0: (ARM64, 0, 40, 0xFFFFFFFFFFFFFFFF, 0)}))

    def test_fat_slice_alignment_is_enforced_when_declared(self):
        self.rejected(fat([(thin(), ARM64, 0)], entries={0: (ARM64, 0, 28, 32, 3)}))

    def test_fat_alignment_exponents_have_format_bounds(self):
        self.rejected(fat([(thin(), ARM64, 0)], entries={0: (ARM64, 0, 28, 32, 32)}))
        self.rejected(fat([(thin(), ARM64, 0)], wide=True, entries={0: (ARM64, 0, 40, 32, 64)}))
        self.rejected(fat([(thin(), ARM64, 0)], wide=True, entries={0: (ARM64, 0, 0xFFFFFFFFFFFFFFFF, 32, 0xFFFFFFFF)}))


if __name__ == "__main__":
    unittest.main()
