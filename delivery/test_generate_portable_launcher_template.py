"""Bounded static-template validation models; execution only through Bazel."""
from __future__ import annotations

import hashlib
import struct
import unittest

import generate_portable_launcher_template as generator


def static_elf(machine: int = 62, *, program_type: int = 1, flags: int = 5,
               section_type: int | None = None, stack_count: int = 1,
               stack_flags: int = 6, stack_memsz: int = 0) -> bytes:
    count = 1 + stack_count
    body_offset = 64 + 56 * count
    section_offset = body_offset + 1 if section_type is not None else 0
    size = body_offset + 1 + (64 if section_type is not None else 0)
    base = 0x400000
    ident = b"\x7fELF\x02\x01\x01" + bytes(9)
    header = ident + struct.pack("<HHIQQQIHHHHHH", 2, machine, 1, base + body_offset,
                                64, section_offset, 0, 64, 56, count,
                                64 if section_type is not None else 0,
                                1 if section_type is not None else 0, 0)
    program = struct.pack("<IIQQQQQQ", program_type, flags, 0, base, base, size, size, 4096)
    section = (struct.pack("<IIQQQQIIQQ", 0, section_type, 0, 0, body_offset, 1, 0, 0, 1, 0)
               if section_type is not None else b"")
    stack = struct.pack("<IIQQQQQQ", 0x6474E551, stack_flags, 0, 0, 0, 0, stack_memsz, 0)
    return header + program + stack * stack_count + b"\0" + section


class StaticTemplateGeneratorTest(unittest.TestCase):
    def test_both_declared_targets_render_exact_bytes_and_recomputed_digest(self) -> None:
        for target, machine in (("x86_64-linux", 62), ("aarch64-linux", 183)):
            payload = static_elf(machine)
            generator.validate_template(payload, target)
            namespace = {}
            exec(generator.render_template(payload, target), namespace)
            self.assertEqual(namespace["ABI"], 1)
            self.assertEqual(namespace["TARGET"], target)
            self.assertEqual(namespace["TEMPLATE"], payload)
            self.assertEqual(namespace["SHA256"], hashlib.sha256(payload).hexdigest())
            with self.assertRaises(ValueError):
                generator.validate_template(payload, "aarch64-linux" if machine == 62 else "x86_64-linux")
        with self.assertRaises(ValueError):
            generator.validate_template(static_elf(), "x86_64-macos")

    def test_dynamic_program_headers_sections_and_writable_executable_mapping_refuse(self) -> None:
        for payload in (static_elf(program_type=2), static_elf(program_type=3),
                        static_elf(flags=7), static_elf(flags=4), static_elf(section_type=6)):
            with self.subTest(size=len(payload)), self.assertRaises(ValueError):
                generator.validate_template(payload, "x86_64-linux")

    def test_exact_single_zero_stack_header_preserves_inherited_limit_contract(self) -> None:
        generator.validate_template(static_elf(), "x86_64-linux")
        for payload in (static_elf(stack_count=0), static_elf(stack_count=2),
                        static_elf(stack_flags=7), static_elf(stack_memsz=4096)):
            with self.subTest(size=len(payload)), self.assertRaises(ValueError):
                generator.validate_template(payload, "x86_64-linux")

    def test_truncation_malformed_tables_and_entry_outside_file_backed_mapping_refuse(self) -> None:
        valid = static_elf()
        cases = [b"", b"text", valid[:63], valid[:100], valid[:-1]]
        for offset, fmt, value in ((4, "<B", 1), (5, "<B", 2), (7, "<B", 255),
                                   (16, "<H", 3), (18, "<H", 40), (20, "<I", 2),
                                   (24, "<Q", 0), (32, "<Q", 1 << 63),
                                   (54, "<H", 55), (56, "<H", 65535),
                                   (64 + 32, "<Q", 999999), (64 + 48, "<Q", 3)):
            payload = bytearray(valid)
            struct.pack_into(fmt, payload, offset, value)
            cases.append(bytes(payload))
        for payload in cases:
            with self.subTest(size=len(payload)), self.assertRaises(ValueError):
                generator.validate_template(payload, "x86_64-linux")

    def test_section_bounds_links_and_preexisting_record_refuse(self) -> None:
        valid = static_elf(section_type=1)
        generator.validate_template(valid, "x86_64-linux")
        shoff = struct.unpack_from("<Q", valid, 40)[0]
        for offset, fmt, value in ((40, "<Q", 1 << 63), (58, "<H", 63), (60, "<H", 65535),
                                   (shoff + 24, "<Q", 999999), (shoff + 40, "<I", 1),
                                   (shoff + 48, "<Q", 3)):
            payload = bytearray(valid)
            struct.pack_into(fmt, payload, offset, value)
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                generator.validate_template(payload, "x86_64-linux")
        footer = b"OMUXLNXLAUNCHv1\0" + bytes(240)
        with self.assertRaisesRegex(ValueError, "already contains"):
            generator.validate_template(static_elf() + footer, "x86_64-linux")


if __name__ == "__main__":
    unittest.main()
