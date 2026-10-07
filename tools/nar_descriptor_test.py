import io
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from nar_descriptor import describe, hash_descriptor, open_regular, serialize, validate_descriptor


def token(value):
    value = value.encode() if isinstance(value, str) else value
    return struct.pack('<Q', len(value)) + value + b'\0' * (-len(value) % 8)


class DescriptorTest(unittest.TestCase):
    def test_fifo_open_is_nonblocking_and_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / 'fifo'
            os.mkfifo(fifo)
            original = os.open
            def guarded(path, flags, *args, **kwargs):
                if path == 'fifo':
                    self.assertTrue(flags & os.O_NONBLOCK)
                return original(path, flags, *args, **kwargs)
            with patch('nar_descriptor.os.open', guarded), self.assertRaises(ValueError):
                open_regular(str(fifo), '')

    def test_regular_canonical_width_padding_and_executable(self):
        value = {'schemaVersion': 1, 'root': '/unused', 'nodes': [{'path': '', 'type': 'regular', 'size': 3, 'executable': True}]}
        output = bytearray()
        serialize(value, output.extend, opener=lambda *_: io.BytesIO(b'abc'))
        expected = b''.join(token(item) for item in ['nix-archive-1', '(', 'type', 'regular', 'executable', '', 'contents', b'abc', ')'])
        self.assertEqual(bytes(output), expected)

    def test_external_directory_link_is_inert(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / 'public'
            root.mkdir()
            outside = Path(directory) / 'private'
            (root / 'inert').symlink_to(outside, target_is_directory=True)
            original = os.scandir
            def guard(path):
                if Path(path) == outside:
                    self.fail('external link target followed')
                return original(path)
            with patch('nar_descriptor.os.scandir', guard):
                value = describe(root)
                result = hash_descriptor(value, opener=lambda *_: self.fail('link bytes opened'))
            self.assertFalse(result['linkTargetsFollowed'])
            self.assertFalse(result['executionAuthority'])

    def test_duplicate_traversal_special_and_link_parent_refused(self):
        for nodes in [
            [{'path': '', 'type': 'directory'}, {'path': '', 'type': 'directory'}],
            [{'path': '../escape', 'type': 'directory'}],
            [{'path': '', 'type': 'fifo'}],
            [{'path': '', 'type': 'symlink', 'target': '/external'}, {'path': 'child', 'type': 'directory'}],
        ]:
            with self.assertRaises(ValueError):
                validate_descriptor({'schemaVersion': 1, 'root': '/unused', 'nodes': nodes})

    def test_sort_order_and_content_corruption(self):
        value = {'schemaVersion': 1, 'root': '/unused', 'nodes': [{'path': '', 'type': 'directory'}, {'path': 'z', 'type': 'regular', 'size': 1, 'executable': False}, {'path': 'a', 'type': 'symlink', 'target': '/external'}]}
        output = bytearray()
        serialize(value, output.extend, opener=lambda *_: io.BytesIO(b'x'))
        self.assertLess(output.index(token('a')), output.index(token('z')))
        with self.assertRaises(ValueError):
            hash_descriptor(value, opener=lambda *_: io.BytesIO(b''))


if __name__ == '__main__':
    unittest.main()
