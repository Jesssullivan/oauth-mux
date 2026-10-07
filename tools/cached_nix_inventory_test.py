from pathlib import Path
import sqlite3
import tempfile
import unittest

from cached_nix_inventory import persist_inventory, roots_from_input, snapshot_inventory


class InventoryTest(unittest.TestCase):
    def test_output_is_private_exclusive_and_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = {'roots': [], 'paths': [], 'contentRehashed': False}
            result = persist_inventory(inventory, directory)
            target = Path(directory) / 'inventory.json'
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(result['bytes'], len(target.read_bytes()))
            self.assertFalse(result['contentRehashed'])
            with self.assertRaises(FileExistsError):
                persist_inventory(inventory, directory)

    def test_exact_recursive_snapshot_and_no_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / 'db.sqlite'
            first = '/nix/store/' + 'a' * 32 + '-node'
            second = '/nix/store/' + 'b' * 32 + '-lib'
            db = sqlite3.connect(database)
            db.executescript('CREATE TABLE ValidPaths(id INTEGER PRIMARY KEY, path TEXT, hash TEXT, narSize INTEGER); CREATE TABLE Refs(referrer INTEGER, reference INTEGER);')
            db.executemany('INSERT INTO ValidPaths VALUES (?, ?, ?, ?)', [(1, first, 'sha256:' + 'c' * 64, 100), (2, second, 'sha256:' + 'd' * 64, 20)])
            db.execute('INSERT INTO Refs VALUES (1, 2)')
            db.commit()
            db.close()
            before = database.read_bytes()
            rows = snapshot_inventory(database, [first], exists=lambda _: True)
            self.assertEqual(rows[0]['references'], [second])
            self.assertEqual(len(rows), 2)
            self.assertEqual(before, database.read_bytes())
            with self.assertRaises(ValueError):
                snapshot_inventory(database, [first], exists=lambda value: value != second)

    def test_rejects_arbitrary_root(self):
        packages = {name: {'out': '/tmp/forbidden'} for name in ('node', 'python', 'pnpm', 'bash', 'coreutils', 'chromium')}
        with self.assertRaises(ValueError):
            roots_from_input({'schemaVersion': 1, 'system': 'x86_64-linux', 'packages': packages, 'helperTools': ['/tmp/forbidden']})

    def test_missing_database_is_not_created(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / 'absent.sqlite'
            with self.assertRaises(sqlite3.Error):
                snapshot_inventory(database, [])
            self.assertFalse(database.exists())


if __name__ == '__main__':
    unittest.main()
