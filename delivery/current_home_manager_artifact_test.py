import unittest
from unittest.mock import patch
import current_home_manager_artifact as artifact

class CurrentArtifactTest(unittest.TestCase):
    def environment(self):
        return {artifact.ENV + key: value for key,value in {'MODE':artifact.MODE,
            'SOURCE_COMMIT':'a'*40,'SOURCE_DIRTY':'false','GRAPH_SHA256':'b'*64,
            'ENTRY_NS':'1000000000','DEADLINE_NS':'1201000000000'}.items()}

    def test_original_clean_and_dirty_are_truthful(self):
        env = self.environment()
        value,until = artifact.provenance(env, 1000000000)
        self.assertIs(value['sourceDirty'],False)
        self.assertEqual(until,1171)
        env[artifact.ENV+'SOURCE_DIRTY']='true'
        self.assertIs(artifact.provenance(env,1000000000)[0]['sourceDirty'],True)

    def test_expiry_and_clock_reset_refuse(self):
        for now in (999999999,1171000000000):
            with self.assertRaises(ValueError): artifact.provenance(self.environment(),now)
        env=self.environment(); env[artifact.ENV+'DEADLINE_NS']='1202000000000'
        with self.assertRaises(ValueError): artifact.provenance(env,1000000000)

    def test_missing_or_fabricated_provenance_refuses_before_component_io(self):
        for key in ('MODE','SOURCE_COMMIT','SOURCE_DIRTY','GRAPH_SHA256','ENTRY_NS','DEADLINE_NS'):
            env=self.environment(); env[artifact.ENV+key]='invalid'
            with patch.object(artifact.pack,'read_bundle',side_effect=AssertionError('unexpected read')):
                with self.assertRaises(ValueError): artifact.produce(None,env)

    def test_existing_export_directory_custody_checks_remain_real(self):
        import tempfile
        import os
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'owned'; root.mkdir(mode=0o700)
            with artifact.export.HeldDirectory(root) as held:
                held.check()
                root.rename(root.with_name('old')); root.mkdir(mode=0o700)
                with self.assertRaises(ValueError): held.check()

    def test_patchelf_keeps_local_bound_intersected_with_original_cutoff(self):
        import portable
        from pathlib import Path
        metadata={'needed': [], 'interpreter': None}
        with patch.object(portable.time,'monotonic',return_value=100), patch.object(portable.subprocess,'run') as run:
            portable._patch(Path('file'),metadata,Path('patchelf'),False,action_deadline=105)
            self.assertEqual(run.call_args.kwargs['timeout'],5)
            portable._patch(Path('file'),metadata,Path('patchelf'),False)
            self.assertEqual(run.call_args.kwargs['timeout'],60)
            run.reset_mock()
            with self.assertRaises(ValueError):
                portable._patch(Path('file'),metadata,Path('patchelf'),False,action_deadline=100)
            run.assert_not_called()

    def publisher_fixture(self, root):
        import time
        evidence={'sourceRevision':'a'*40,'sourceDirty':False,'graphSha256':'b'*64,
                  'originalEntryMonotonicNs':1,'originalDeadlineMonotonicNs':1200000000001}
        files={'bin/omux':b'cli','release-manifest.json':b'{}'}
        return artifact.publish(b'bounded-archive-fixture',files,{},b'extension',b'metadata',
                                evidence,root,time.monotonic()+60)

    def test_real_owned_publication_and_existing_output_refusal(self):
        import tempfile
        import json
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            receipt=self.publisher_fixture(root)
            self.assertEqual((root/'current-home-manager/artifact/bin/omux').read_bytes(),b'cli')
            self.assertEqual((root/'current-home-manager/extension-metadata.json').read_bytes(),b'metadata')
            self.assertEqual(json.loads((root/'current-home-manager/receipt.json').read_bytes()),receipt)
            self.assertIs(receipt['sourceDirty'],False)
            with self.assertRaises(FileExistsError): self.publisher_fixture(root)

    def test_output_parent_swap_refuses_before_new_envelope(self):
        import tempfile
        from pathlib import Path
        real=artifact.export.Archive
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)/'out'; root.mkdir(mode=0o700)
            def swap(*args,**kwargs):
                archive=real(*args,**kwargs)
                root.rename(root.with_name('old')); root.mkdir(mode=0o700)
                return archive
            with patch.object(artifact.export,'Archive',side_effect=swap):
                with self.assertRaises(ValueError): self.publisher_fixture(root)
            self.assertEqual(list(root.iterdir()),[])

    def test_validated_metadata_drift_refuses_real_readback(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'metadata'; path.write_bytes(b'original')
            self.assertEqual(artifact.recheck_metadata(path,b'original'),b'original')
            path.write_bytes(b'changed')
            with self.assertRaises(ValueError): artifact.recheck_metadata(path,b'original')

if __name__=='__main__': unittest.main()
