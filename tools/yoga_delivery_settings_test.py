import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import yoga_delivery_settings as settings

class SettingsTests(unittest.TestCase):
    epoch = '12345678-1234-4123-8123-123456789012'
    deadline = 1200 * 10**9
    lock = {'lock':'fixture'}
    def qualification(self):
        return {'schemaVersion':1,'scope':'yoga-authenticated-OS-executable-qualification-v1',
            'bootstrapManifestSha256':settings.executable.BOOTSTRAP_SHA,'inventorySha256':settings.INVENTORY,
            'sourceReceiptSha256':settings.SOURCE_RECEIPT,'sshPath':settings.executable.SSH,'sshSha256':'a'*64,
            'remote':dict(schemaVersion=1,hostAlias='yoga',system='x86_64-linux',bootstrapTrust=settings.executable.TRUST,
                machineIdSha256='a'*64,bootIdSha256='b'*64,uid=1000,labSourceRevision='f'*40,
                labGenerationMarkerSha256='a'*64,labDeploymentIdSha256='b'*64,
                homeManagerGeneration='/nix/store/'+'c'*32+'-home-manager-generation',
                remoteNixPath='/nix/store/'+'d'*32+'-nix/bin/nix',remoteNixSha256='e'*64,remoteNixBytes=42)}

    def receipt(self, qualification_sha256):
        return dict(id=self.epoch,artifact_epoch=self.epoch,exit=0,workload_exit=0,descendants_empty=True,
            controller_failure=None,rejection=None,cleanup={'state':'empty'},verb='run',
            targets=['//tools:yoga_controller_qualify'],profile=settings.profile.PROFILE,manager='system',
            coordination_directory=str(settings.profile.COORDINATION),
            coordination_lock=str(settings.profile.COORDINATION/'execution.lock'),graph_sha256='f'*64,
            limits={'fixed':'fixture'},closure_manifest_sha256=settings.NATIVE,
            bootstrap_manifest_sha256=settings.executable.BOOTSTRAP_SHA,
            yoga_delivery=dict(source_verified_after_cleanup=True,controller_tools=settings.TOOLS,mode='qualify',
                coordination_lock_witness=self.lock,
                remote_owned_containment_verified=False,copy_performed=False,remote_cleanup='unknown',
                qualification={'path':'qualification.json','sha256':qualification_sha256}))

    def result(self):
        return dict(schemaVersion=1,scope='yoga-controller-destination-readonly-v1',mode='qualify',passed=True,
            inventorySha256=settings.INVENTORY,sourceReceiptSha256=settings.SOURCE_RECEIPT,copyPerformed=False,
            remoteCleanup='unknown',remoteOwnedContainmentVerified=False,destinationRegistrationVerified=False,
            destinationContentRehashed=False,offlineGraphVerified=False,wrapperExecutionAuthority=False,
            qualification=self.qualification(), sshHostKeyAuthority={
                'scope':'existing-neo-yoga-ed25519-host-pin-2026-10-04',
                'sha256':'e2931feebc4e623a9e0946dab4989729c48793ca90f60ed7922df026c26b77d8',
                'byteCount':97})

    def fixture_open(self,path,*unused):
        descriptor = os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        settings.DIRECTORY_PINS[descriptor] = ([descriptor],[settings.directory_identity(os.fstat(descriptor))],[])
        return descriptor

    def write(self,path,data):
        path.write_bytes(data); path.chmod(0o600)

    def test_raw_d631_closure_pin_is_distinct_from_canonical_inventory_manifest(self):
        # Exact public d631 receipt and controller-evidence.json independently
        # record this raw digest for 12way/native.json -> s3iz...-native.json.
        raw = '7f19ccff61a0d5981641a73ab65067eac6de77e13e146b4be06ac6b36652bd41'
        canonical_input = 'b24fb333d7cd58e57790cf02c69cf9a0c1eba3afc7359ab18318973d8b77d2c0'
        settings.tools(dict(settings.TOOLS), raw, settings.executable.BOOTSTRAP_SHA)
        for wrong in (canonical_input, '0' * 64):
            with self.assertRaisesRegex(ValueError, 'unchanged-d631-controller-tools'):
                settings.tools(dict(settings.TOOLS), wrong, settings.executable.BOOTSTRAP_SHA)
        changed = dict(settings.TOOLS, closure='/nix/store/' + 'a' * 32 + '-omux-bazel-closure')
        with self.assertRaisesRegex(ValueError, 'unchanged-d631-controller-tools'):
            settings.tools(changed, raw, settings.executable.BOOTSTRAP_SHA)
        receipt = self.receipt('a' * 64)
        receipt['closure_manifest_sha256'] = canonical_input
        with self.assertRaisesRegex(ValueError, 'successful-same-graph-qualify-guard-epoch'):
            settings.prior_receipt(receipt, self.epoch, 'f' * 64, {'fixed': 'fixture'}, self.lock)

    def test_finite_scope_refuses_authority_for_qualify_and_unrelated_routes(self):
        settings.finite(['run','//tools:yoga_controller_qualify'],'system',None,[])
        for args,manager,epoch,other in ((['run','//tools:yoga_controller_qualify'],'system',self.epoch,[]),
                (['run','//tools:yoga_controller_inspect'],'system',None,[]),
                (['run','//tools:yoga_controller_verify'],'user',self.epoch,[]),
                (['run','//tools:yoga_controller_verify'],'system',self.epoch,['provider-config'])):
            with self.assertRaises(ValueError): settings.finite(args,manager,epoch,other)

    def test_original_deadline_and_residual_runtime_do_not_restart(self):
        with patch.object(settings.time,'monotonic_ns',return_value=100*10**9):
            self.assertEqual(settings.runtime_seconds(self.deadline),1085)
        with patch.object(settings.time,'monotonic_ns',return_value=self.deadline):
            with self.assertRaises(ValueError): settings.runtime_seconds(self.deadline)
        self.assertEqual(settings.effective_runtime('18min 5s',1085),1085*10**6)
        for value in ('20min','infinity','1086s','-1s','0s','20garbage'):
            with self.assertRaises(ValueError): settings.effective_runtime(value,1085)

    def test_terminal_epoch_chain_refuses_graph_result_cleanup_label_and_pin_drift(self):
        original = self.receipt('a'*64)
        self.assertEqual(settings.prior_receipt(original,self.epoch,'f'*64,{'fixed':'fixture'},self.lock),'a'*64)
        for key,value in (('exit',True),('workload_exit',1),('descendants_empty',False),('graph_sha256','a'*64),
                          ('targets',['//tools:yoga_controller_inspect']),('bootstrap_manifest_sha256','0'*64)):
            changed = copy.deepcopy(original); changed[key] = value
            with self.assertRaises(ValueError): settings.prior_receipt(changed,self.epoch,'f'*64,{'fixed':'fixture'},self.lock)
        changed = copy.deepcopy(original); changed['yoga_delivery']['source_verified_after_cleanup'] = False
        with self.assertRaises(ValueError): settings.prior_receipt(changed,self.epoch,'f'*64,{'fixed':'fixture'},self.lock)
        changed = copy.deepcopy(original); changed['cleanup'] = []
        with self.assertRaises(ValueError): settings.prior_receipt(changed,self.epoch,'f'*64,{'fixed':'fixture'},self.lock)
        for key in ('controller_failure','rejection'):
            changed = copy.deepcopy(original); del changed[key]
            with self.assertRaises(ValueError): settings.prior_receipt(changed,self.epoch,'f'*64,{'fixed':'fixture'},self.lock)

    def test_qualification_extraction_requires_exact_existing_host_pin_observation(self):
        result = self.result()
        with patch.object(settings.time, 'monotonic_ns', return_value=0):
            for wrong in (None, {}, dict(result['sshHostKeyAuthority'], sha256='0' * 64),
                          dict(result['sshHostKeyAuthority'], byteCount=97.0),
                          dict(result['sshHostKeyAuthority'], extra=True)):
                result['sshHostKeyAuthority'] = wrong
                with self.assertRaisesRegex(ValueError, 'exact-existing-ssh-host-pin'):
                    settings.extract(settings.canonical(result), self.deadline)

    def test_guard_extracts_one_canonical_result_and_refuses_duplicate_or_failed_result(self):
        result = self.result()
        with patch.object(settings.time,'monotonic_ns',return_value=0):
            data = settings.canonical(result)
            self.assertEqual(settings.extract(b'INFO: fake declared Bazel output\n'+data+b'\n',self.deadline),
                             settings.canonical(result['qualification']))
            for log in (data+b'\n'+data+b'\n',b'INFO: no proof\n'):
                with self.assertRaises(ValueError): settings.extract(log,self.deadline)
            result['passed'] = False
            with self.assertRaises(ValueError): settings.extract(settings.canonical(result),self.deadline)

    def test_closed_file_chain_rechecks_bytes_and_custody_before_launch(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary); run = state/self.epoch; run.mkdir(mode=0o700)
            content = settings.canonical(self.qualification())
            receipt = self.receipt(hashlib.sha256(content).hexdigest())
            self.write(run/'receipt.json',settings.canonical(receipt)); self.write(run/'qualification.json',content)
            with patch.object(settings.profile,'STATE',state), \
                    patch.object(settings,'trusted_directory',side_effect=self.fixture_open), \
                    patch.object(settings.time,'monotonic_ns',return_value=0):
                prior = settings.select_prior(self.epoch,'f'*64,{'fixed':'fixture'},self.deadline,self.lock)
                settings.recheck(prior,'f'*64,{'fixed':'fixture'},self.deadline,self.lock)
                self.assertIn('receipt_identity',prior); self.assertIn('qualification_identity',prior)
                changed = dict(receipt,source_dirty='true')
                self.write(run/'receipt.json',settings.canonical(changed))
                with self.assertRaisesRegex(ValueError,'changed-before-launch'):
                    settings.recheck(prior,'f'*64,{'fixed':'fixture'},self.deadline,self.lock)
                (run/'qualification.json').chmod(0o644)
                with self.assertRaisesRegex(ValueError,'custody'):
                    settings.select_prior(self.epoch,'f'*64,{'fixed':'fixture'},self.deadline,self.lock)

    def test_symlink_and_hardlink_prior_extractions_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary); self.write(directory/'source',b'{}')
            descriptor = self.fixture_open(directory)
            try:
                (directory/'qualification.json').symlink_to('source')
                with patch.object(settings.time,'monotonic_ns',return_value=0),self.assertRaises(OSError):
                    settings.read_owned(descriptor,'qualification.json',16384,self.deadline)
                (directory/'qualification.json').unlink(); os.link(directory/'source',directory/'qualification.json')
                with patch.object(settings.time,'monotonic_ns',return_value=0),self.assertRaisesRegex(ValueError,'custody'):
                    settings.read_owned(descriptor,'qualification.json',16384,self.deadline)
            finally: settings.close_directory(descriptor)

    def test_publication_is_exclusive_and_only_follows_verified_terminal_result(self):
        args = ['run','//tools:yoga_controller_qualify']
        with patch.object(settings,'trusted_directory') as opened,patch.object(settings.time,'monotonic_ns',return_value=0):
            record = settings.finish(Path('/unused'),args,0,False,True,self.deadline,self.lock)
            self.assertIsNone(record['qualification']); opened.assert_not_called()
        with tempfile.TemporaryDirectory() as temporary:
            run = Path(temporary); self.write(run/'workload.log',settings.canonical(self.result())+b'\n')
            with patch.object(settings,'trusted_directory',side_effect=self.fixture_open), \
                    patch.object(settings.time,'monotonic_ns',return_value=0):
                record = settings.finish(run,args,0,True,True,self.deadline,self.lock)
                self.assertEqual(record['qualification']['sha256'],hashlib.sha256((run/'qualification.json').read_bytes()).hexdigest())
                self.assertEqual((run/'qualification.json').stat().st_mode & 0o777,0o600)
                with self.assertRaises(FileExistsError): settings.publish(run,b'new',self.deadline)

    def test_ancestor_open_failure_attempts_every_release_and_preserves_primary(self):
        good = SimpleNamespace(st_dev=1,st_ino=2,st_uid=os.getuid(),st_mode=stat.S_IFDIR|0o700)
        calls = []
        def close(descriptor):
            calls.append(descriptor)
            if descriptor == 12: raise OSError('close')
        with patch.object(settings.time,'monotonic_ns',return_value=0), \
                patch.object(settings.os,'open',side_effect=[11,12,13]), \
                patch.object(settings.os,'fstat',side_effect=[good,good,ValueError('primary-custody')]), \
                patch.object(settings.os,'close',side_effect=close):
            with self.assertRaisesRegex(ValueError,'primary-custody') as captured:
                settings.trusted_directory('/first/second',self.deadline)
        self.assertEqual(calls,[13,12,11])
        self.assertIn('qualification-custody-release-incomplete',captured.exception.__notes__)

    def test_prior_lock_replacement_does_not_inherit_qualification(self):
        receipt = self.receipt('a'*64)
        with self.assertRaisesRegex(ValueError,'extraction-required'):
            settings.prior_receipt(receipt,self.epoch,'f'*64,{'fixed':'fixture'},{'replacement':'lock'})

    def test_actual_named_home_lock_replacement_is_refused_while_original_fd_remains_held(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            held = os.open(directory/'execution.lock',os.O_RDWR|os.O_CREAT|os.O_EXCL,0o600)
            try:
                with patch.object(settings.profile,'COORDINATION',directory), \
                        patch.object(settings,'trusted_directory',side_effect=self.fixture_open), \
                        patch.object(settings.time,'monotonic_ns',return_value=0):
                    original = settings.lock_witness(held,self.deadline)
                    (directory/'execution.lock').rename(directory/'held-lock')
                    self.write(directory/'execution.lock',b'replacement')
                    with self.assertRaisesRegex(ValueError,'lock-custody-changed'):
                        settings.lock_witness(held,self.deadline)
                    self.assertEqual(os.fstat(held).st_ino,original['inode'])
            finally: os.close(held)

if __name__ == '__main__': unittest.main()
