"""Exact actual N5 source witness, never credential or installed-image authority."""
from contextlib import contextmanager
import json
import os
import stat
import codex_native_source_context_refresh_source as parent

source = parent.source
BINDING = 'integrations/codex-upstream/native-source-acquisition-n5-binding.json'
BINDING_SHA = '9a56fa9a9d1b815a60ac28a6e5da96cd7b91fe4fccd17add98d18f6f701aeaff'

def identity(fd, regular=False):
    value = os.fstat(fd)
    source.require(value.st_uid == os.getuid() and stat.S_IMODE(value.st_mode) == 0o555
        and (stat.S_ISREG(value.st_mode) and value.st_nlink == 1 if regular else stat.S_ISDIR(value.st_mode)))
    result = {'device': value.st_dev, 'inode': value.st_ino, 'uid': value.st_uid, 'mode': stat.S_IMODE(value.st_mode)}
    if regular: result['nlink'] = value.st_nlink
    return result

def load():
    raw = parent.declared(BINDING, 8192)
    source.require(source.sha(raw) == BINDING_SHA)
    value = json.loads(raw, object_pairs_hook=source.unique)
    config = parent.load_input()
    source.require(config == {'schema_version': 1, 'status': 'actual-seventh-source-pinned',
        'root': value['root'], 'receipt_sha256': value['receipt_sha256'], 'receipt_bytes': value['receipt_bytes'],
        'inventory_sha256': value['inventory_sha256'], 'source_members': value['tracked_files'], 'source_bytes': value['source_bytes']}
        and value['tracked_files'] == 8551 and value['source_bytes'] == 84683541
        and value['kind'] == parent.seventh.KIND and value['status'] == 'verified-seventh-native-context-source-uncompiled'
        and value['all_future_qualification_false'] is True)
    return config, value

@contextmanager
def hold(config, value):
    root = source.directory(parent.Path(config['root']))
    tree = receipt = None
    try:
        tree = source.directory(parent.Path(config['root']) / 'source')
        receipt = os.open('source-receipt.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
        def recheck():
            source.tick()
            for fd, key, path in ((root, 'root_identity', parent.Path(config['root'])),
                    (tree, 'source_root_identity', parent.Path(config['root']) / 'source')):
                source.require(identity(fd) == value[key])
                named = source.directory(path)
                try: source.require(identity(named) == value[key])
                finally: os.close(named)
            source.require(identity(receipt, True) == value['receipt_identity'])
            named = os.open('source-receipt.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=root)
            try: source.require(identity(named, True) == value['receipt_identity'])
            finally: os.close(named)
            raw, mode = source.read(root, 'source-receipt.json', source.MAX_METADATA)
            source.require(mode == 0o555 and len(raw) == config['receipt_bytes'] and source.sha(raw) == config['receipt_sha256'])
        recheck()
        yield recheck
        recheck()
    finally:
        for fd in (receipt, tree, root):
            if fd is not None: os.close(fd)
