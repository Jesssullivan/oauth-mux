import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import codex_retained_sdk_export as sdk

class PrivateImportTests(unittest.TestCase):
    def test_readlink_access_time_change_preserves_public_link_identity(self):
        from types import SimpleNamespace
        link = self.root/'public-link'; os.symlink('missing-public-target',link)
        before = os.stat(link,follow_symlinks=False)
        values = {key:getattr(before,key) for key in sdk.LINK_IDENTITY_FIELDS}
        values['st_atime_ns'] = before.st_atime_ns+1000000000
        parent = sdk.open_dir(self.root)
        try:
            with patch.object(sdk.os,'stat',return_value=SimpleNamespace(**values)):
                self.assertEqual(sdk.stable_link_target(parent,'public-link',before),'missing-public-target')
            for key in sdk.LINK_IDENTITY_FIELDS:
                changed = dict(values); changed[key] += 1
                with self.subTest(key=key), patch.object(sdk.os,'stat',return_value=SimpleNamespace(**changed)):
                    with self.assertRaisesRegex(ValueError,'link mutated'):
                        sdk.stable_link_target(parent,'public-link',before)
            with patch.object(sdk.os,'readlink',side_effect=['first-public-target','changed-public-target']):
                with self.assertRaisesRegex(ValueError,'target mutated'):
                    sdk.stable_link_target(parent,'public-link',before)
        finally:
            os.close(parent)
        self.assertEqual(os.readlink(link),'missing-public-target')

    def test_export_pass_counts_accumulate_without_resetting_shared_bytes(self):
        budget = self.budget(); budget.files = 3; budget.check(7)
        budget.authorize_export_passes(); budget.export_pass('copy'); budget.files += 4
        budget.export_pass('sealed_readback'); budget.files += 5
        budget.export_pass('copy'); budget.files += 2
        self.assertEqual(budget.entry_counts(),{'qualification':3,'copy':6,'sealed_readback':5})
        self.assertEqual(budget.bytes,7)
        with self.assertRaises(ValueError): budget.export_pass('fourth')
        with self.assertRaises(ValueError): budget.authorize_export_passes()
    def test_export_pass_entry_and_shared_byte_bounds_still_refuse(self):
        budget = self.budget(); budget.authorize_export_passes(); budget.export_pass('copy')
        budget.files = sdk.MAX_FILES+1
        with self.assertRaisesRegex(ValueError,'entry bound'): budget.entry_counts()
        budget = self.budget(); budget.authorize_export_passes(); budget.export_pass('copy')
        budget.bytes = sdk.MAX_BYTES; budget.export_pass('sealed_readback')
        with self.assertRaisesRegex(ValueError,'byte bound'): budget.check(1)

    def test_public_missing_links_preserve_raw_bytes_and_record_absence(self):
        rows = [{'path':'first','kind':'symlink','target':'second'},
                {'path':'second','kind':'symlink','target':'tools/downloader.cfg'}]
        repos = [{'canonical_name':'tar.bzl+','source_root':str(self.root),
                  'files':rows,'inventory_sha256':sdk.digest(sdk.canonical(rows))}]
        sdk.relocate_links(repos,[],self.budget())
        expected = [{'origin':'tar.bzl+/first','target':'tar.bzl+/tools/downloader.cfg'},
                    {'origin':'tar.bzl+/second','target':'tar.bzl+/tools/downloader.cfg'}]
        self.assertEqual(repos[0]['absent_links'],expected)
        self.assertEqual(repos[0]['source_files'],rows)
        self.assertEqual(sdk.public_link_absences(repos,self.budget()),expected)
        repos[0]['files'].append({'path':'tools/downloader.cfg','kind':'file','sha256':'0'*64,'size':0,'mode':0o444})
        self.assertEqual(sdk.public_link_absences(repos,self.budget()),[])
    def test_missing_link_escape_cycle_and_depth_still_refuse(self):
        for rows in ([{'path':'x','kind':'symlink','target':'../../outside'}],
                     [{'path':'x','kind':'symlink','target':'x'}],
                     [{'path':str(i),'kind':'symlink','target':str(i+1)} for i in range(65)]):
            with self.subTest(rows=rows):
                with self.assertRaises(ValueError):
                    sdk.public_link_absences([{'canonical_name':'fixture','files':rows}],self.budget())
    def test_missing_link_unselected_absolute_target_refuses(self):
        with self.assertRaises(ValueError):
            sdk.public_link_absences([{'canonical_name':'fixture','files':[{'path':'x','kind':'symlink','target':'/unselected/public'}]}],self.budget())

    def jdk_fixture(self):
        root = self.boundary/'jdk-fixture'
        root.mkdir()
        names = ('lib','lib/openjdk','lib/openjdk/bin','lib/openjdk/include','nix-support','share')
        for name in names: (root/name).mkdir(parents=True,exist_ok=True)
        payload = root/'lib/openjdk/bin/java'
        payload.write_bytes(b'public immutable JDK fixture bytes\n'); os.chmod(payload,0o444)
        os.symlink('lib/openjdk/bin',root/'bin')
        os.symlink('lib/openjdk/include',root/'include')
        for name in reversed(names): os.chmod(root/name,0o555)
        os.chmod(root,0o555)
        return root,sdk.inventory(root,self.budget(),sealed=True)
    def test_fixed_jdk_aliases_and_directories_preserve_pointer_semantics(self):
        root,rows = self.jdk_fixture()
        with patch.object(sdk,'JDK',str(root)), patch.object(sdk,'NIX_OWNER_UID',os.getuid()):
            for alias in ('bin','include','lib','nix-support','share'):
                sdk.check_jdk_directory(alias,rows,self.budget())
        self.assertEqual(os.readlink(root/'bin'),'lib/openjdk/bin')
        self.assertEqual(os.readlink(root/'include'),'lib/openjdk/include')
        self.assertEqual((root/'lib/openjdk/bin/java').read_bytes(),b'public immutable JDK fixture bytes\n')
    def test_jdk_alias_escape_and_cycle_refuse_without_following(self):
        for target in ('../outside','bin'):
            with self.subTest(target=target):
                root,rows = self.jdk_fixture()
                os.chmod(root,0o700); (root/'bin').unlink(); os.symlink(target,root/'bin'); os.chmod(root,0o555)
                rows = sdk.inventory(root,self.budget(),sealed=True)
                with patch.object(sdk,'JDK',str(root)), patch.object(sdk,'NIX_OWNER_UID',os.getuid()):
                    with self.assertRaisesRegex(ValueError,'independent inventory'):
                        sdk.check_jdk_directory('bin',rows,self.budget())
                for path,dirs,files in os.walk(root): os.chmod(path,0o700)
                import shutil
                shutil.rmtree(root)
    def test_jdk_target_component_symlink_refuses(self):
        root,rows = self.jdk_fixture()
        target = root/'lib/openjdk/bin'
        os.chmod(target,0o700); (target/'java').unlink()
        os.chmod(target.parent,0o700); target.rmdir(); os.symlink('../include',target); os.chmod(target.parent,0o555)
        rows = sdk.inventory(root,self.budget(),sealed=True)
        with patch.object(sdk,'JDK',str(root)), patch.object(sdk,'NIX_OWNER_UID',os.getuid()):
            with self.assertRaisesRegex(ValueError,'component missing'):
                sdk.check_jdk_directory('bin',rows,self.budget())
    def test_jdk_mutable_target_and_foreign_owner_refuse(self):
        root,rows = self.jdk_fixture()
        with patch.object(sdk,'JDK',str(root)), patch.object(sdk,'NIX_OWNER_UID',os.getuid()+1):
            with self.assertRaisesRegex(ValueError,'mutable immutable-JDK'):
                sdk.check_jdk_directory('bin',rows,self.budget())
        os.chmod(root/'lib/openjdk/bin',0o775)
        with patch.object(sdk,'JDK',str(root)), patch.object(sdk,'NIX_OWNER_UID',os.getuid()):
            with self.assertRaisesRegex(ValueError,'mutable immutable-JDK'):
                sdk.check_jdk_directory('bin',rows,self.budget())
    def test_jdk_alias_mutation_during_resolution_refuses(self):
        root,rows = self.jdk_fixture(); original = os.readlink
        def changing(name,*args,**kwargs):
            result = original(name,*args,**kwargs)
            if name=='bin':
                os.chmod(root,0o700); (root/'bin').unlink(); os.symlink('lib/openjdk/include',root/'bin'); os.chmod(root,0o555)
            return result
        with patch.object(sdk,'JDK',str(root)), patch.object(sdk,'NIX_OWNER_UID',os.getuid()), patch.object(sdk.os,'readlink',side_effect=changing):
            with self.assertRaisesRegex(ValueError,'changed'):
                sdk.check_jdk_directory('bin',rows,self.budget())
    def test_unselected_jdk_alias_and_duplicate_inventory_refuse(self):
        root,rows = self.jdk_fixture()
        with patch.object(sdk,'JDK',str(root)), patch.object(sdk,'NIX_OWNER_UID',os.getuid()):
            with self.assertRaisesRegex(ValueError,'unselected'):
                sdk.check_jdk_directory('tools',rows,self.budget())
            with self.assertRaisesRegex(ValueError,'duplicate'):
                sdk.check_jdk_directory('bin',rows+[rows[0]],self.budget())

    def test_selected_public_server_directory_copy_retains_actual_bytes(self):
        source = self.root/'server'
        source.mkdir()
        data = b'public source server implementation\n'
        source.joinpath('implementation.txt').write_bytes(data)
        destination = self.boundary/'repositories'/'fixture_public'
        destination.mkdir(parents=True)
        rows = sdk.inventory(self.root,self.budget(),output=destination)
        for row in rows:
            if row['kind']=='directory': os.chmod(destination/row['path'],0o555)
        os.chmod(destination,0o555)
        self.assertEqual((destination/'server'/'implementation.txt').read_bytes(),data)
        self.assertIn({'path':'server','kind':'directory','mode':0o555},rows)
        self.assertEqual(rows,sdk.inventory(destination,self.budget(),sealed=True))
    def test_unselected_server_directory_and_selected_server_file_refuse(self):
        outside = self.boundary/'outside'; outside.mkdir(); (outside/'server').mkdir()
        with self.assertRaisesRegex(ValueError,'server must be'): sdk.inventory(outside,self.budget())
        (self.root/'server').write_bytes(b'public')
        with self.assertRaisesRegex(ValueError,'server must be'): sdk.inventory(self.root,self.budget())
    def test_selected_server_symlink_refuses(self):
        target = self.root/'ordinary'; target.mkdir()
        os.symlink('ordinary',self.root/'server')
        with self.assertRaisesRegex(ValueError,'server must be'): sdk.inventory(self.root,self.budget())
    def test_forbidden_metadata_is_classified_without_omission(self):
        for name in ('.git','action_cache','command.log'):
            with self.subTest(name=name):
                path = self.root/name; path.write_bytes(b'public fixture')
                with self.assertRaisesRegex(ValueError,'forbidden basename'):
                    sdk.inventory(self.root,self.budget())
                path.unlink()
    def test_noncanonical_entry_is_classified(self):
        self.root.joinpath('public\nname').write_bytes(b'public')
        with self.assertRaisesRegex(ValueError,'noncanonical basename'):
            sdk.inventory(self.root,self.budget())
    def test_existing_aggregate_entry_bound_still_refuses(self):
        self.file()
        budget = self.budget(); budget.files = sdk.MAX_FILES
        with self.assertRaisesRegex(ValueError,'entry bound max=500000'):
            sdk.inventory(self.root,budget)
        self.assertEqual(budget.files,sdk.MAX_FILES+1)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.boundary = Path(self.temporary.name)
        os.chmod(self.boundary,0o700)
        self.cache = self.boundary/'cache'
        self.root = self.cache/('a'*64)/'00000000-0000-4000-8000-000000000001'
        self.root.mkdir(parents=True)
        self.patches = [patch.object(sdk,'CACHE',self.cache),patch.object(sdk,'CACHE_PRIVATE_PARENT',self.boundary)]
        for item in self.patches:
            item.start()
    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        # Test copied outputs are readonly; remove them only inside this fixture.
        for path,dirs,files in os.walk(self.boundary):
            os.chmod(path,0o700)
            for name in files:
                if not Path(path,name).is_symlink():
                    os.chmod(Path(path,name),0o600)
        self.temporary.cleanup()
    def budget(self):
        return sdk.Budget(time.time()+30)
    def file(self,mode=0o664):
        path = self.root/'public-input.txt'
        path.write_bytes(b'public SDK input\n')
        os.chmod(path,mode)
        return path
    def test_private_grouped_public_copy_has_real_bytes_and_sealed_modes(self):
        data = b'public SDK input\n'
        self.file(0o664)
        script = self.root/'script.sh'
        script.write_bytes(b'#!/bin/sh\nexit 0\n')
        os.chmod(script,0o775)
        destination = self.boundary/'copied'
        destination.mkdir()
        rows = sdk.inventory(self.root,self.budget(),output=destination)
        self.assertEqual(destination.joinpath('public-input.txt').read_bytes(),data)
        pins = {row['path']:row for row in rows}
        self.assertEqual(pins['public-input.txt']['sha256'],hashlib.sha256(data).hexdigest())
        self.assertEqual(os.stat(destination/'public-input.txt').st_mode & 0o777,0o444)
        self.assertEqual(os.stat(destination/'script.sh').st_mode & 0o777,0o555)
    def test_actual_grouped_directory_is_bounded_by_private_ancestry(self):
        child = self.root/'dir'
        child.mkdir(); os.chmod(child,0o775)
        child.joinpath('x').write_bytes(b'public')
        self.assertIn('dir/x',{r['path'] for r in sdk.inventory(self.root,self.budget())})
    def test_nonprivate_exact_boundary_refuses(self):
        self.file(); os.chmod(self.boundary,0o755)
        with self.assertRaisesRegex(ValueError,'boundary'):
            sdk.inventory(self.root,self.budget())
    def test_world_writable_regular_refuses(self):
        self.file(0o777)
        with self.assertRaises(ValueError): sdk.inventory(self.root,self.budget())
    def test_grouped_hardlinked_regular_refuses(self):
        path = self.file(); os.link(path,self.root/'alias')
        with self.assertRaises(ValueError): sdk.inventory(self.root,self.budget())
    def test_world_writable_directory_refuses(self):
        child = self.root/'dir'; child.mkdir(); os.chmod(child,0o777)
        with self.assertRaises(ValueError): sdk.inventory(self.root,self.budget())
    def test_unselected_grouped_regular_refuses(self):
        outside = self.boundary/'outside'; outside.mkdir()
        target = outside/'x'; target.write_bytes(b'public'); os.chmod(target,0o664)
        with self.assertRaises(ValueError): sdk.inventory(outside,self.budget())
    def test_nix_namespace_cannot_receive_normalization_lease(self):
        nix = Path('/nix/store/'+('a'*32)+'-public-sdk')
        self.assertIsNone(sdk.public_import(nix,False))
        with self.assertRaisesRegex(ValueError,'outside exact selected'):
            sdk.PrivatePublicImport(nix)
    def test_boundary_change_during_file_read_refuses(self):
        self.file(); original = os.read
        def changing(fd,count):
            result = original(fd,count)
            if result: os.chmod(self.boundary,0o755)
            return result
        with patch.object(sdk.os,'read',side_effect=changing):
            with self.assertRaisesRegex(ValueError,'ancestry changed'): sdk.inventory(self.root,self.budget())
    def test_generic_and_sealed_readers_still_refuse_grouped_mode(self):
        self.file()
        with self.assertRaises(ValueError): sdk.inventory(self.root,self.budget(),sealed=True)
        fd = sdk.open_dir(self.root)
        try:
            with self.assertRaises(ValueError): sdk.read_file(fd,'public-input.txt',self.budget())
        finally: os.close(fd)
    def test_changed_held_boundary_refuses(self):
        self.file(); lease = sdk.PrivatePublicImport(self.root)
        try:
            os.chmod(self.boundary,0o755)
            with self.assertRaisesRegex(ValueError,'ancestry changed'): lease.recheck()
        finally: lease.close()
    def test_symlinked_ancestor_refuses(self):
        self.file(); alias = self.boundary/'alias'; os.symlink(self.cache,alias)
        with patch.object(sdk,'CACHE',alias):
            with self.assertRaises(OSError): sdk.PrivatePublicImport(alias/('a'*64)/self.root.name)

if __name__ == '__main__': unittest.main()
