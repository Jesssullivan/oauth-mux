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

    def test_closed_diagnostic_predicates_redact_arbitrary_error_data(self):
        import json
        marker='/private/secret-input-example'
        for error in (ValueError(marker),OSError(marker),KeyError(marker),TypeError(marker),artifact.dev_stage.StageError(marker)):
            value=artifact.diagnostic(error,{'phase':'portable-pack'})
            self.assertEqual(value['phase'],'portable-pack')
            self.assertEqual(value['predicate'],'unclassified')
            self.assertNotIn(marker,json.dumps(value))
            self.assertTrue(all(value[key] is False for key in ('shipped','artifactQualified','activationQualified',
                'browserQualified','custodyQualified','continuityQualified','liveQualified')))
        self.assertEqual(artifact.diagnostic(ValueError('archive inputs exceed bounded payload size'),{})['predicate'],'pack-input-size')
        self.assertEqual(artifact.diagnostic(ValueError('unknown'),{'phase':marker})['phase'],'entry')
        with self.assertRaises(ValueError): artifact.phase({},marker)

    def test_real_provenance_refusal_records_phase_before_component_read(self):
        progress={};environment=self.environment();environment[artifact.ENV+'MODE']='wrong'
        with patch.object(artifact.pack,'read_bundle',side_effect=AssertionError('unexpected IO')):
            with self.assertRaises(ValueError) as error: artifact.produce(None,environment,progress)
        self.assertEqual(artifact.diagnostic(error.exception,progress)['phase'],'provenance')
        self.assertEqual(artifact.diagnostic(error.exception,progress)['predicate'],'provenance')

    def test_main_retains_generic_refusal_with_closed_diagnostic(self):
        import contextlib
        import io
        import json
        def fail(args,environment,progress):
            artifact.phase(progress,'archive-validation')
            raise ValueError('/private/secret-input-example')
        output,error=io.StringIO(),io.StringIO()
        with patch('argparse.ArgumentParser.parse_args',return_value=object()),patch.object(artifact,'produce',side_effect=fail), \
                contextlib.redirect_stdout(output),contextlib.redirect_stderr(error):
            self.assertEqual(artifact.main(),125)
        value=json.loads(output.getvalue())
        self.assertEqual(value['phase'],'archive-validation')
        self.assertEqual(value['predicate'],'unclassified')
        self.assertEqual(error.getvalue(),'current-home-manager-artifact-refused\n')
        self.assertNotIn('secret-input-example',output.getvalue()+error.getvalue())

    def test_declared_soname_alias_survives_real_portable_closure_selection(self):
        import argparse
        import portable
        import test_portable as fixtures
        case=fixtures.AssemblyTest()
        case.setUp()
        try:
            physical=case.sqlite.with_name('libsqlite3.so.0.1')
            case.sqlite.rename(physical)
            case.sqlite.symlink_to(physical.name)
            args=argparse.Namespace(core=case.cli,runtime_file=case.runtime,qt_runtime_file=[],qt_plugin=[])
            old=[path.resolve(strict=True) for path in case.runtime]
            with patch.object(portable,'_patch',side_effect=case.patch_fixture):
                with self.assertRaisesRegex(ValueError,'declared runtime closure is missing libsqlite3.so.0'):
                    portable.assemble_linux(case.cli,case.daemon,old,case.patchelf,'x86_64-linux',case.ca_bundle)
                artifact.component_paths(args)
                files,metadata=portable.assemble_linux(args.core,case.daemon,args.runtime_file,
                    case.patchelf,'x86_64-linux',case.ca_bundle)
            self.assertIs(args.runtime_file,case.runtime)
            self.assertEqual(args.runtime_file[-1].name,'libsqlite3.so.0')
            self.assertIn('lib/omux/lib/libsqlite3.so.0',files)
            portable.verify_linux_runtime(files,{'target':'x86_64-linux','runtime':metadata})
        finally:
            case.doCleanups()

if __name__=='__main__': unittest.main()
