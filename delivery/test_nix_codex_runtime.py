"""Source models for direct-main boundaries; never a live native claim."""
import struct
import hashlib
import os
import tempfile
import time
import unittest
from pathlib import Path
import nix_codex_runtime as nix


def elf(interpreter):
    value = interpreter.encode('ascii')+b'\0'
    data = bytearray(120+len(value))
    data[:16] = b'\x7fELF\x02\x01\x01'+b'\0'*9
    struct.pack_into('<HHIQQQIHHHHHH',data,16,3,62,1,0,64,0,0,64,56,1,0,0,0)
    struct.pack_into('<IIQQQQQQ',data,64,3,0,120,120,0,len(value),len(value),1)
    data[120:] = value
    return bytes(data)

class DirectMainBoundaryTests(unittest.TestCase):
    def test_dynamic_segment_must_match_unique_load_virtual_mapping(self):
        value = bytearray(192)
        value[:16] = b'\x7fELF\x02\x01\x01'+b'\0'*9
        struct.pack_into('<HHIQQQIHHHHHH',value,16,3,62,1,0,64,0,0,64,56,2,0,0,0)
        struct.pack_into('<IIQQQQQQ',value,64,1,4,0,0x1000,0,192,192,1)
        struct.pack_into('<IIQQQQQQ',value,120,2,4,176,0x10b0,0,16,16,8)
        self.assertIsNone(nix.elf_info(bytes(value))['soname'])
        struct.pack_into('<Q',value,120+16,0x10b1)
        with self.assertRaises(ValueError):
            nix.elf_info(bytes(value))
    def test_original_package_deadline_never_resets_at_consumer_entry(self):
        entry = 100*10**9
        environment = {'OMUX_NATIVE_PACKAGE_MODE':'native-acquisition-package-reserved',
            'OMUX_NATIVE_PACKAGE_ENTRY_NS':str(entry),
            'OMUX_NATIVE_PACKAGE_DEADLINE_NS':str(entry+1200*10**9)}
        self.assertEqual(nix.original_package_deadline(environment,clock_ns=lambda:entry+600*10**9),1270)
        with self.assertRaises(ValueError):
            nix.original_package_deadline(environment,clock_ns=lambda:entry+1170*10**9)
        environment['OMUX_NATIVE_PACKAGE_ENTRY_NS']='0100000000000'
        with self.assertRaises(ValueError):
            nix.original_package_deadline(environment,clock_ns=lambda:entry)
        with self.assertRaises(ValueError):
            nix.original_package_deadline({},clock_ns=lambda:entry)
    def test_actual_output_inventory_binds_five_sealed_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            for name in nix.PACKAGE_OUTPUT_NAMES:
                path = Path(directory)/name
                path.write_bytes(name.encode())
                path.chmod(0o444)
            value = nix.package_output_inventory(directory,time.monotonic()+30)
            self.assertEqual(set(value['files']),set(nix.PACKAGE_OUTPUT_NAMES))
            for name,row in value['files'].items():
                self.assertEqual(row,{'sha256':hashlib.sha256(name.encode()).hexdigest(),'bytes':len(name)})
            self.assertEqual(value['acquisitionContract'],'unsupported')
            path = Path(directory)/nix.PACKAGE_OUTPUT_NAMES[0]
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                nix.package_output_inventory(directory,time.monotonic()+30)

    def test_output_inventory_refuses_symlink_missing_and_expired_original_clock(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                nix.package_output_inventory(directory,time.monotonic()+30)
            for name in nix.PACKAGE_OUTPUT_NAMES:
                path = Path(directory)/name
                path.write_bytes(b'x')
                path.chmod(0o444)
            with self.assertRaises(ValueError):
                nix.package_output_inventory(directory,time.monotonic()-1)
            path = Path(directory)/nix.PACKAGE_OUTPUT_NAMES[0]
            path.unlink()
            path.symlink_to(nix.PACKAGE_OUTPUT_NAMES[1])
            with self.assertRaises(ValueError):
                nix.package_output_inventory(directory,time.monotonic()+30)
    def test_launcher_executes_backend_and_clears_injected_loader_environment(self):
        value = nix.launcher()
        self.assertTrue(value.endswith(b'exec "$runtime/libexec/codex.bin" "$@"\n'))
        self.assertIn(b'unset LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH\n',value)
        self.assertNotIn(b'--library-path',value)
        self.assertNotIn(b'--argv0',value)
        self.assertNotIn(b'exec "$runtime/lib/',value)

    def test_original_interpreter_parser_preserves_exact_bytes(self):
        path = '/nix/store/'+('a'*32)+'-glibc/lib/ld-linux-x86-64.so.2'
        value = elf(path)
        self.assertEqual(nix.elf_info(value)['interpreter'],path)
        self.assertEqual(value,elf(path))

    def test_standard_host_interpreter_refuses_before_declared_file_or_query_io(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError,'namespace'):
                nix.assemble(elf('/lib64/ld-linux-x86-64.so.2'),[Path(directory)/'absent'],
                             Path(directory)/'ca',time.monotonic()+1)

    def test_expired_original_deadline_refuses_before_elf_or_files(self):
        with self.assertRaisesRegex(ValueError,'deadline'):
            nix.assemble(b'invalid',[],Path('/unselected'),time.monotonic()-1)

    def test_declared_nix_namespace_rejects_path_escape_and_non_nix_hash(self):
        for path in ('/tmp/a','/nix/store/'+('e'*32)+'-glibc/lib/x',
                     '/nix/store/'+('a'*32)+'-glibc/../x'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                nix.root_of(path)

if __name__ == '__main__':
    unittest.main()
