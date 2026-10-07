"""Distribution and ownership tests; execute with Bazel //delivery:delivery_test."""
from __future__ import annotations

import gzip
import io
import json
import os
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import install
import pack
import portable
from test_portable import AssemblyTest, elf


class DeliveryFixture(unittest.TestCase):
    def setUp(self) -> None:
        # Bazel's TEST_TMPDIR can descend through host-owned cache directories
        # that correctly fail installation custody checks in a root sandbox.
        # Use a canonical sticky system temp root with our own private child.
        self.directory = tempfile.TemporaryDirectory(dir=str(Path("/tmp").resolve()))
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        self.binary = self.write("cli", b"synthetic cli executable\n")
        self.daemon = self.write("daemon", b"synthetic daemon executable\n")
        self.reference = self.write("reference.json", pack.json_bytes({
            "schemaVersion": 1,
            "product": {"name": "Omux", "version": "0.2.0-dev", "status": "experimental"},
            "provenance": {"sourceRevision": None, "sourceDirty": True},
        }))
        self.systemd = self.write("omux.service.in", b"[Service]\nExecStart=@EXEC@\n")
        self.launchd = self.write("dev.xoxd.omux.plist.in", b"<plist><string>@EXEC@</string></plist>\n")

    def write(self, name: str, data: bytes) -> Path:
        path = self.inputs / name
        path.write_bytes(data)
        return path

    def bundle(self, **kwargs: object) -> bytes:
        return pack.make_bundle(self.binary, self.daemon, self.reference, self.systemd,
                                self.launchd, target="x86_64-linux", **kwargs)

    def portable_bundle(self, channel: str, **kwargs: object) -> bytes:
        """Real archive assembly/verification with bounded synthetic ELF inputs.

        Only the external patcher is replaced by the existing ELF fixture rewrite;
        channel-bound launchers, manifest accounting and installer checks are real.
        """
        loader = self.write("ld-linux-x86-64.so.2", elf())
        libc = self.write("libc.so.6", elf(interpreter=str(loader)))
        cli = self.write("portable-cli", elf(("libc.so.6",), interpreter=str(loader)))
        daemon = self.write("portable-daemon", elf(("libc.so.6",), interpreter=str(loader)))
        patcher = self.write("fixture-patchelf", b"declared synthetic patcher")
        ca_bundle = self.write("fixture-ca.crt", b"-----BEGIN CERTIFICATE-----\ncHVibGlj\n-----END CERTIFICATE-----\n")
        with mock.patch.object(portable, "_patch", side_effect=AssemblyTest.patch_fixture):
            return pack.make_bundle(cli, daemon, self.reference, self.systemd, self.launchd,
                                    target="x86_64-linux", channel=channel,
                                    runtime_files=[loader, libc], patchelf=patcher, ca_bundle=ca_bundle,
                                    **kwargs)

    def rewrite_archive(self, payload: bytes, changes: dict[str, bytes] | None = None,
                        extra: list[tuple[tarfile.TarInfo, bytes | None]] | None = None,
                        omit: set[str] | None = None) -> bytes:
        """Preserve archive metadata while constructing hostile transport inputs."""
        result = io.BytesIO()
        with gzip.GzipFile(fileobj=result, mode="wb", filename="", mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as output:
                with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as original:
                    for member in original:
                        if member.name in (omit or set()):
                            continue
                        data = (changes or {}).get(member.name)
                        if data is None:
                            reader = original.extractfile(member)
                            self.assertIsNotNone(reader)
                            data = reader.read()
                        member.size = len(data)
                        output.addfile(member, io.BytesIO(data))
                for member, data in extra or []:
                    if data is not None:
                        member.size = len(data)
                    output.addfile(member, None if data is None else io.BytesIO(data))
        return result.getvalue()


class BundleTest(DeliveryFixture):
    def test_channel_is_explicit_and_does_not_follow_product_status(self) -> None:
        legacy, _ = pack.verify_bundle(self.bundle())
        self.assertNotIn("channel", legacy)
        for channel in ("development", "release"):
            declared, _ = pack.verify_bundle(self.portable_bundle(channel))
            self.assertEqual(declared["channel"], channel)
            self.assertEqual(declared["product"]["status"], "experimental")
            with self.assertRaisesRegex(ValueError, "portable"):
                self.bundle(channel=channel)
        for channel in ("dev", "default", "stable", ""):
            with self.subTest(channel=channel), self.assertRaisesRegex(ValueError, "channel"):
                self.bundle(channel=channel)
        payload = self.portable_bundle("development")
        manifest, _ = pack.verify_bundle(payload)
        manifest["channel"] = "dev"
        # Channel validation precedes integrity accounting and cannot be bypassed
        # by a consumer trusting a manifest declaration without its vocabulary.
        with self.assertRaisesRegex(ValueError, "artifact channel"):
            pack.verify_bundle(self.rewrite_archive(payload, {"release-manifest.json": pack.json_bytes(manifest)}))

    def test_bundle_is_reproducible_despite_input_metadata(self) -> None:
        first = self.bundle(epoch=1234)
        for path in self.inputs.iterdir():
            path.chmod(0o600)
            os.utime(path, (999999, 999999))
        second = self.bundle(epoch=1234)
        self.assertEqual(first, second)
        manifest, files = pack.verify_bundle(first)
        self.assertEqual(manifest["target"], "x86_64-linux")
        self.assertEqual(manifest["distribution"], "development-nix-closure-required")
        self.assertEqual(set(files), pack.REQUIRED_FILES)
        for name in pack.BINARIES:
            self.assertEqual(files["bin/" + name], files["bin/omuxd" if name == "omuxd" else "bin/omux"])
        with tarfile.open(fileobj=io.BytesIO(first), mode="r:gz") as archive:
            self.assertEqual(archive.getnames(), sorted(files))
            for member in archive:
                self.assertEqual((member.uid, member.gid, member.uname, member.gname), (0, 0, "", ""))
                self.assertEqual(member.mtime, 1234)
                self.assertEqual(member.mode, 0o755 if member.name.startswith("bin/") else 0o644)

    def test_clean_full_commit_provenance_is_required_for_publication(self) -> None:
        with self.assertRaises(ValueError):
            pack.verify_bundle(self.bundle(), require_publishable=True)
        revision = "a" * 40
        manifest, files = pack.verify_bundle(self.bundle(source_revision=revision, source_dirty=False),
                                           require_publishable=True)
        self.assertEqual(manifest["provenance"], {"sourceRevision": revision, "sourceDirty": False})
        self.assertEqual(json.loads(files["share/omux/reference.json"])["provenance"],
                         manifest["provenance"])
        with self.assertRaises(ValueError):
            self.bundle(source_dirty=False)
        with self.assertRaises(ValueError):
            self.bundle(source_revision="short-revision", source_dirty=False)

    def test_explicit_dirty_development_provenance_preserves_historical_default(self) -> None:
        reference_before = self.reference.read_bytes()
        historical = self.portable_bundle("development")
        historical_manifest, _ = pack.verify_bundle(historical)
        self.assertEqual(historical_manifest["provenance"], {"sourceRevision": None, "sourceDirty": True})

        revision = "f5f83c1ad99c2920de6759791b327a99a02a2ec5"
        declared = self.portable_bundle("development", source_revision=revision, source_dirty=True)
        manifest, files = pack.verify_bundle(declared)
        self.assertEqual(manifest["channel"], "development")
        self.assertEqual(manifest["product"]["status"], "experimental")
        self.assertEqual(manifest["provenance"], {"sourceRevision": revision, "sourceDirty": True})
        self.assertEqual(json.loads(files["share/omux/reference.json"])["provenance"], manifest["provenance"])
        self.assertNotEqual(declared, historical)
        self.assertEqual(self.reference.read_bytes(), reference_before)
        # Recording the new archive does not mutate or reinterpret default
        # producer bytes, and its explicit revision does not make it publishable.
        self.assertEqual(self.portable_bundle("development"), historical)
        with self.assertRaisesRegex(ValueError, "publication requires clean"):
            pack.verify_bundle(declared, require_publishable=True)

    def test_declared_development_revision_rejects_malformed_inputs(self) -> None:
        for revision in ("short-revision", "A" * 40, "g" * 40, "a" * 65):
            with self.subTest(revision=revision), self.assertRaisesRegex(ValueError, "full commit digest"):
                self.portable_bundle("development", source_revision=revision, source_dirty=True)

    def test_checksum_payload_and_manifest_tampering_are_rejected(self) -> None:
        payload = self.bundle()
        for path in ("bin/omux", "bin/omuxd", "SHA256SUMS", "share/omux/reference.json"):
            with self.subTest(path=path), self.assertRaises((ValueError, json.JSONDecodeError)):
                pack.verify_bundle(self.rewrite_archive(payload, {path: b"altered artifact\n"}))
        manifest, _ = pack.verify_bundle(payload)
        manifest["artifacts"][0]["sha256"] = "0" * 64
        with self.assertRaises(ValueError):
            pack.verify_bundle(self.rewrite_archive(payload, {"release-manifest.json": pack.json_bytes(manifest)}))

    def test_missing_and_duplicate_members_are_rejected(self) -> None:
        payload = self.bundle()
        with self.assertRaises(ValueError):
            pack.verify_bundle(self.rewrite_archive(payload, omit={"bin/omuxd"}))
        duplicate = tarfile.TarInfo("bin/omux")
        duplicate.mode = 0o755
        with self.assertRaises(ValueError):
            pack.verify_bundle(self.rewrite_archive(payload, extra=[(duplicate, b"duplicate")]))

    def test_unsafe_paths_and_link_members_are_rejected(self) -> None:
        payload = self.bundle()
        for path in ("../escape", "/absolute", "bin/../../escape", "bin/./omux", "bin//omux"):
            member = tarfile.TarInfo(path)
            member.mode = 0o644
            with self.subTest(path=path), self.assertRaises(ValueError):
                pack.verify_bundle(self.rewrite_archive(payload, extra=[(member, b"untrusted")]))
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE, tarfile.FIFOTYPE):
            member = tarfile.TarInfo("untrusted-member")
            member.mode = 0o644
            member.type = kind
            member.linkname = "../escape"
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                pack.verify_bundle(self.rewrite_archive(payload, extra=[(member, None)]))

    def test_bounds_and_source_validation(self) -> None:
        for target in ("x86_64-windows", "arbitrary"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                pack.make_bundle(self.binary, self.daemon, self.reference, self.systemd,
                                 self.launchd, target=target)
        with self.assertRaises(ValueError):
            self.bundle(epoch=-1)
        with self.assertRaises(ValueError):
            self.bundle(epoch=2**32)
        link = self.inputs / "linked-cli"
        link.symlink_to(self.binary)
        with self.assertRaises(ValueError):
            pack.make_bundle(link, self.daemon, self.reference, self.systemd,
                             self.launchd, target="x86_64-linux")
        reference = json.loads(self.reference.read_bytes())
        reference["product"]["status"] = "stable"
        self.reference.write_bytes(pack.json_bytes(reference))
        with self.assertRaises(ValueError):
            self.bundle()

    def test_compressed_extended_metadata_is_bounded_before_tar_parsing(self) -> None:
        overhead = pack.MAX_FILES * 1024 + 16 * 1024
        compressed = gzip.compress(b"x" * (overhead + 1025), mtime=0)
        with mock.patch.object(pack, "MAX_BYTES", 1024), mock.patch.object(pack.tarfile, "open") as parser:
            with self.assertRaisesRegex(ValueError, "decompressed"):
                pack.verify_bundle(compressed)
            parser.assert_not_called()

    def test_bundle_file_read_rejects_oversized_and_nonregular_inputs(self) -> None:
        archive = self.root / "distribution.tar.gz"
        archive.write_bytes(b"x" * 1025)
        with mock.patch.object(pack, "MAX_BYTES", 1024):
            with self.assertRaisesRegex(ValueError, "bounded"):
                pack.read_bundle(archive)
            with self.assertRaisesRegex(ValueError, "regular"):
                pack.read_bundle(self.inputs)
            archive.write_bytes(b"bounded input")
            self.assertEqual(pack.read_bundle(archive), b"bounded input")


class InstallationTest(DeliveryFixture):
    def test_owned_linux_service_binds_persistent_daemon_state_without_activation(self) -> None:
        service = self.service.with_name("ai.xoxd.omux.dev.service")
        persistent = self.root / 'runtime state with % and $ and "quotes"'
        receipt = install.install_bundle(self.portable_bundle("development"), self.prefix, self.state,
                                         service, daemon_state_dir=persistent)
        self.assertFalse(receipt["serviceActivated"])
        self.assertIn('--state-dir "' + str(persistent).replace("%", "%%").replace("$", "$$").replace('"', '\\"') + '"',
                      service.read_text())
        self.assertFalse(persistent.exists())
        for bound in ("MemoryMax=268435456\n", "MemorySwapMax=0\n", "TasksMax=32\n", "CPUQuota=10%\n"):
            self.assertIn(bound, service.read_text())
        runtime = "/run/user/" + str(os.getuid())
        self.assertIn('Environment="DBUS_SESSION_BUS_ADDRESS=unix:path=' + runtime + '/bus"\n', service.read_text())
        self.assertIn('Environment="XDG_RUNTIME_DIR=' + runtime + '"\n', service.read_text())
        self.assertEqual(next(entry for entry in receipt["files"] if entry["path"] == str(service))["mode"], 0o600)

    def test_daemon_state_binding_requires_an_owned_linux_service(self) -> None:
        persistent = self.root / "runtime-state"
        with self.assertRaisesRegex(ValueError, "requires a Linux owned service"):
            install.install_bundle(self.portable_bundle("development"), self.prefix, self.state,
                                   daemon_state_dir=persistent)
        self.assertFalse(self.prefix.exists())

    def test_receipt_binds_archive_provenance_without_claiming_activation(self) -> None:
        payload = self.portable_bundle("development", source_revision="a" * 40, source_dirty=False)
        manifest, files = pack.verify_bundle(payload)
        self.service = self.service.with_name("ai.xoxd.omux.dev.service")
        receipt = self.install(payload)
        self.assertEqual(receipt["schemaVersion"], 1)
        self.assertEqual(receipt["artifact"], {
            "channel": "development", "target": manifest["target"],
            "distribution": manifest["distribution"], "provenance": manifest["provenance"],
            "archiveSha256": pack.digest(payload), "manifestSha256": pack.digest(files["release-manifest.json"]),
        })
        self.assertFalse(receipt["serviceActivated"])
        service = self.service.read_text()
        for key, value in {"OMUX_INSTALL_PREFIX": self.prefix,
                           "OMUX_INSTALL_RECORD": self.state / install.RECORD,
                           "OMUX_INSTALL_SERVICE_PATH": self.service}.items():
            self.assertIn(f'Environment="{key}={value}"', service)
        self.assertNotIn("CODEX_HOME", service)
        self.assertNotIn("CLAUDE_CONFIG_DIR", service)
        self.assertIn('Environment="OMUX_INSTANCE=dev"', service)

    def test_declared_channels_cannot_install_into_another_instance_unit(self) -> None:
        for channel, instance, unit in (("development", "dev", "ai.xoxd.omux.dev.service"),
                                        ("release", "default", "ai.xoxd.omux.service")):
            with self.subTest(channel=channel):
                prefix = self.root / channel / "prefix"
                state = self.root / channel / "receipts"
                service = self.root / channel / unit
                with self.assertRaisesRegex(ValueError, "service identity"):
                    install.install_bundle(self.portable_bundle(channel), prefix, state,
                                           service.with_name("omux.service"))
                self.assertFalse(prefix.exists())
                receipt = install.install_bundle(self.portable_bundle(channel), prefix, state, service)
                self.assertEqual(receipt["artifact"]["channel"], channel)
                self.assertIn(f'Environment="OMUX_INSTANCE={instance}"', service.read_text())

    def test_legacy_channel_remains_unknown_and_old_receipt_still_removable(self) -> None:
        receipt = self.install()
        self.assertEqual(receipt["artifact"]["channel"], "unknown")
        self.assertNotIn("OMUX_INSTANCE", self.service.read_text())
        del receipt["artifact"]
        (self.state / install.RECORD).write_bytes(pack.json_bytes(receipt))
        self.assertNotIn("artifact", install._record(self.prefix, self.state))
        install.uninstall(self.prefix, self.state)
        self.assertFalse((self.prefix / "bin/omuxd").exists())

    def setUp(self) -> None:
        super().setUp()
        self.prefix = self.root / "prefix"
        self.state = self.root / "state"
        self.service = self.root / "user-services" / "omux.service"

    def installed_paths(self) -> set[Path]:
        return {self.prefix / "bin" / name for name in pack.BINARIES} | {self.service}

    def install(self, payload: bytes | None = None) -> dict:
        return install.install_bundle(payload or self.bundle(), self.prefix, self.state, self.service)

    def add_obsolete_owned_runtime(self) -> Path:
        """Represent a previous bundle's declared, now-obsolete runtime file."""
        path = self.prefix / "lib/omux/lib/liblegacy.so.1"
        path.parent.mkdir(parents=True)
        data = b"synthetic obsolete runtime payload\n"
        path.write_bytes(data)
        path.chmod(0o644)
        record_path = self.state / install.RECORD
        record = json.loads(record_path.read_bytes())
        record["files"].append({"path": str(path), "sha256": pack.digest(data), "mode": 0o644})
        record_path.write_bytes(pack.json_bytes(record))
        return path

    def qt_distribution(self) -> tuple[dict, dict[str, bytes]]:
        """Declared installer inputs; separate suites verify actual ELF archives."""
        manifest, files = pack.verify_bundle(self.bundle())
        additions = {
            "bin/omux-control": b"synthetic control launcher\n",
            "lib/omux/qt/libexec/omux-control.bin": b"synthetic control executable\n",
            "lib/omux/qt/libexec/qt.conf": b"[Paths]\nPlugins=../plugins\n",
            "lib/omux/qt/lib/ld-test.so.1": b"synthetic Qt loader\n",
            "lib/omux/qt/lib/libqt-test.so.1": b"synthetic Qt library\n",
            "lib/omux/qt/plugins/platforms/libqxcb.so": b"synthetic xcb plugin\n",
            "lib/omux/qt/plugins/platforms/libqminimal.so": b"synthetic minimal plugin\n",
        }
        files.update(additions)
        manifest["distribution"] = "portable-linux"
        for name, data in additions.items():
            mode = "0755" if name in {"bin/omux-control", "lib/omux/qt/libexec/omux-control.bin", "lib/omux/qt/lib/ld-test.so.1"} else "0644"
            manifest["artifacts"].append({"path": name, "sha256": pack.digest(data), "size": len(data), "mode": mode})
        return manifest, files

    def install_qt(self) -> tuple[dict, dict[str, bytes]]:
        manifest, files = self.qt_distribution()
        # This seam isolates ownership behavior from portable assembly. It is
        # never used to claim ELF validity or distributable-runtime support.
        with mock.patch.object(install, "verify_bundle", return_value=(manifest, files)):
            record = self.install(b"synthetic verified ownership inputs")
        return record, files

    def test_install_and_uninstall_preserve_runtime_and_native_files(self) -> None:
        self.state.mkdir(mode=0o700)
        runtime = self.state / "accounts.sqlite"
        runtime.write_bytes(b"synthetic persistent account metadata")
        self.service.parent.mkdir()
        unowned = self.service.parent / "unrelated.service"
        unowned.write_bytes(b"unowned native service")
        record = self.install()
        self.assertFalse(record["serviceActivated"])
        self.assertEqual({Path(item["path"]) for item in record["files"]}, self.installed_paths())
        self.assertEqual((self.prefix / "bin/omux").read_bytes(), self.binary.read_bytes())
        self.assertIn(str(self.prefix / "bin/omuxd"), self.service.read_text())
        self.assertNotIn("@EXEC@", self.service.read_text())
        self.assertEqual((self.state / install.RECORD).stat().st_mode & 0o777, 0o600)
        for path in self.installed_paths():
            self.assertEqual(path.stat().st_mode & 0o777, 0o600 if path == self.service else 0o755)
        result = install.uninstall(self.prefix, self.state)
        self.assertEqual(set(result["removed"]), {str(path) for path in self.installed_paths()})
        self.assertEqual(result["preserved"], [])
        self.assertFalse((self.state / install.RECORD).exists())
        self.assertEqual(runtime.read_bytes(), b"synthetic persistent account metadata")
        self.assertEqual(unowned.read_bytes(), b"unowned native service")
        self.assertTrue(self.state.is_dir())
        self.assertTrue(self.prefix.is_dir())
        self.assertEqual(install.uninstall(self.prefix, self.state), {"removed": [], "preserved": []})

    def test_modified_native_file_is_retained_with_ownership_record(self) -> None:
        self.install()
        edited = b"user edited service configuration\n"
        self.service.write_bytes(edited)
        result = install.uninstall(self.prefix, self.state)
        self.assertEqual(result["preserved"], [str(self.service)])
        self.assertEqual(set(result["removed"]), {str(path) for path in self.installed_paths() - {self.service}})
        self.assertEqual(self.service.read_bytes(), edited)
        record = json.loads((self.state / install.RECORD).read_bytes())
        self.assertEqual([item["path"] for item in record["files"]], [str(self.service)])
        self.assertEqual(install.uninstall(self.prefix, self.state)["preserved"], [str(self.service)])

    def test_unowned_conflict_is_rejected_before_any_installation_write(self) -> None:
        collision = self.prefix / "bin/omuxd"
        collision.parent.mkdir(parents=True)
        collision.write_bytes(b"another application's executable\n")
        with self.assertRaisesRegex(ValueError, "unowned"):
            self.install()
        self.assertEqual(collision.read_bytes(), b"another application's executable\n")
        for name in pack.BINARIES:
            if name != "omuxd":
                self.assertFalse((self.prefix / "bin" / name).exists())
        self.assertFalse(self.service.exists())
        self.assertFalse((self.state / install.RECORD).exists())

    def test_modified_owned_file_blocks_upgrade_before_partial_write(self) -> None:
        self.install()
        before = {path: path.read_bytes() for path in self.installed_paths()}
        self.service.write_bytes(b"user modification\n")
        self.binary.write_bytes(b"upgraded executable\n")
        with self.assertRaisesRegex(ValueError, "modified"):
            self.install()
        for path in self.installed_paths() - {self.service}:
            self.assertEqual(path.read_bytes(), before[path])
        self.assertEqual(self.service.read_bytes(), b"user modification\n")

    def test_symlink_targets_and_directory_ancestry_are_rejected(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        self.prefix.symlink_to(outside, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            self.install()
        self.assertEqual(list(outside.iterdir()), [])
        self.prefix.unlink()
        (self.prefix / "bin").mkdir(parents=True)
        target = outside / "unowned"
        target.write_bytes(b"preserve symlink target")
        (self.prefix / "bin/omux").symlink_to(target)
        with self.assertRaisesRegex(ValueError, "unowned"):
            self.install()
        self.assertEqual(target.read_bytes(), b"preserve symlink target")
        self.assertFalse((self.prefix / "bin/omuxd").exists())

    def test_uninstall_preserves_replaced_symlink(self) -> None:
        self.install()
        path = self.prefix / "bin/omux"
        path.unlink()
        outside = self.root / "replacement"
        outside.write_bytes(b"user-owned replacement")
        path.symlink_to(outside)
        result = install.uninstall(self.prefix, self.state)
        self.assertEqual(result["preserved"], [str(path)])
        self.assertTrue(path.is_symlink())
        self.assertEqual(outside.read_bytes(), b"user-owned replacement")

    def test_failed_ownership_commit_rolls_back_upgrade(self) -> None:
        self.install()
        obsolete = self.add_obsolete_owned_runtime()
        original_files = {path: path.read_bytes() for path in self.installed_paths() | {obsolete}}
        original_record = (self.state / install.RECORD).read_bytes()
        self.binary.write_bytes(b"replacement cli\n")
        original_write = install._write

        def fail_record(path: Path, data: bytes, mode: int) -> None:
            if path == self.state / install.RECORD:
                raise OSError("simulated ownership commit failure")
            original_write(path, data, mode)

        with mock.patch.object(install, "_write", side_effect=fail_record):
            with self.assertRaisesRegex(OSError, "simulated"):
                self.install()
        self.assertEqual((self.state / install.RECORD).read_bytes(), original_record)
        for path, data in original_files.items():
            self.assertEqual(path.read_bytes(), data)
        self.assertEqual(obsolete.stat().st_mode & 0o777, 0o644)

    def test_upgrade_removes_unchanged_obsolete_owned_runtime(self) -> None:
        self.install()
        obsolete = self.add_obsolete_owned_runtime()
        self.binary.write_bytes(b"upgraded cli executable\n")
        record = self.install()
        self.assertFalse(obsolete.exists())
        self.assertNotIn(str(obsolete), {entry["path"] for entry in record["files"]})
        self.assertEqual((self.prefix / "bin/omux").read_bytes(), self.binary.read_bytes())
        self.assertEqual(json.loads((self.state / install.RECORD).read_bytes()), record)

    def test_modified_obsolete_runtime_blocks_upgrade_without_mutation(self) -> None:
        self.install()
        obsolete = self.add_obsolete_owned_runtime()
        obsolete.write_bytes(b"user modified obsolete runtime\n")
        original_files = {path: path.read_bytes() for path in self.installed_paths() | {obsolete}}
        original_record = (self.state / install.RECORD).read_bytes()
        self.binary.write_bytes(b"upgraded cli executable\n")
        with self.assertRaisesRegex(ValueError, "modified owned"):
            self.install()
        self.assertEqual((self.state / install.RECORD).read_bytes(), original_record)
        for path, data in original_files.items():
            self.assertEqual(path.read_bytes(), data)

    def test_bad_bundle_and_wrong_platform_do_not_create_install_state(self) -> None:
        with self.assertRaises((ValueError, tarfile.TarError, OSError, EOFError)):
            self.install(b"invalid compressed bundle")
        self.assertFalse(self.state.exists())
        with self.assertRaisesRegex(ValueError, "platform"):
            install.install_bundle(self.bundle(), self.prefix, self.state, self.service, platform="macos")
        self.assertFalse(self.state.exists())

    def test_service_payload_and_control_collisions_fail_before_custody_creation(self) -> None:
        collisions = [self.prefix / "bin" / name for name in pack.BINARIES]
        collisions.extend([
            self.state / install.RECORD, self.state / "install.lock",
            self.prefix / ".omux-install.lock", self.prefix / "bin",
            self.prefix, self.state, self.root,
        ])
        for service in collisions:
            with self.subTest(service=service):
                with self.assertRaisesRegex(ValueError, "collide"):
                    install.install_bundle(self.bundle(), self.prefix, self.state, service)
                self.assertFalse(self.prefix.exists())
                self.assertFalse(self.state.exists())
                self.assertEqual(set(self.root.iterdir()), {self.inputs})

    def test_service_runtime_collisions_fail_before_custody_creation(self) -> None:
        manifest, files = self.qt_distribution()
        collisions = [self.prefix / name for name in files if name.startswith("lib/omux/")]
        collisions.extend([self.prefix / "bin/omux-control", self.prefix / "lib/omux/qt"])
        for service in collisions:
            with self.subTest(service=service):
                with mock.patch.object(install, "verify_bundle", return_value=(manifest, files)):
                    with self.assertRaisesRegex(ValueError, "collide"):
                        install.install_bundle(b"synthetic verified ownership inputs", self.prefix, self.state, service)
                self.assertFalse(self.prefix.exists())
                self.assertFalse(self.state.exists())

    def test_collision_refusal_preserves_existing_owned_installation(self) -> None:
        self.install()
        originals = {path: path.read_bytes() for path in self.installed_paths()}
        originals.update({path: path.read_bytes() for path in (
            self.state / install.RECORD, self.state / "install.lock", self.prefix / ".omux-install.lock",
        )})
        self.binary.write_bytes(b"upgraded executable\n")
        for service in (self.prefix / "bin/omux", self.state / install.RECORD,
                        self.state / "install.lock", self.prefix / ".omux-install.lock"):
            with self.subTest(service=service):
                with self.assertRaisesRegex(ValueError, "collide"):
                    install.install_bundle(self.bundle(), self.prefix, self.state, service)
                for path, data in originals.items():
                    self.assertEqual(path.read_bytes(), data)

    def test_service_path_escaping_and_explicit_no_service_install(self) -> None:
        self.prefix = self.root / "prefix with % and $ specifiers"
        self.install()
        text = self.service.read_text()
        self.assertIn('ExecStart="', text)
        self.assertIn("%%", text)
        self.assertIn("$$", text)
        install.uninstall(self.prefix, self.state)
        record = install.install_bundle(self.bundle(), self.prefix, self.state)
        self.assertIsNone(record["userService"])
        self.assertFalse(record["serviceActivated"])
        self.assertEqual(len(record["files"]), len(pack.BINARIES))

    def test_unsafe_record_permissions_and_service_move_are_rejected(self) -> None:
        self.install()
        with self.assertRaisesRegex(ValueError, "placement"):
            install.install_bundle(self.bundle(), self.prefix, self.state, self.root / "other.service")
        (self.state / install.RECORD).chmod(0o644)
        with self.assertRaisesRegex(ValueError, "private"):
            install.uninstall(self.prefix, self.state)
        self.assertTrue(all(path.exists() for path in self.installed_paths()))

    def test_nonprivate_or_symlink_state_directory_is_rejected(self) -> None:
        self.state.mkdir(mode=0o755)
        with self.assertRaisesRegex(ValueError, "private"):
            self.install()
        self.assertFalse(self.prefix.exists())
        self.state.rmdir()
        outside = self.root / "outside-state"
        outside.mkdir(mode=0o700)
        self.state.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "directory"):
            self.install()
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse(self.prefix.exists())

    def test_another_state_root_cannot_adopt_an_owned_prefix(self) -> None:
        self.install()
        before = {path: path.read_bytes() for path in self.installed_paths()}
        original_record = (self.state / install.RECORD).read_bytes()
        other_state = self.root / "another-state"
        self.binary.write_bytes(b"competing replacement cli\n")
        with self.assertRaisesRegex(ValueError, "unowned"):
            install.install_bundle(self.bundle(), self.prefix, other_state, self.service)
        self.assertFalse((other_state / install.RECORD).exists())
        self.assertEqual((self.state / install.RECORD).read_bytes(), original_record)
        for path, data in before.items():
            self.assertEqual(path.read_bytes(), data)

    def test_optional_qt_control_and_configuration_are_owned_and_removed(self) -> None:
        record, files = self.install_qt()
        additions = {
            "bin/omux-control", "lib/omux/qt/libexec/omux-control.bin", "lib/omux/qt/libexec/qt.conf",
            "lib/omux/qt/lib/ld-test.so.1", "lib/omux/qt/lib/libqt-test.so.1",
            "lib/omux/qt/plugins/platforms/libqxcb.so", "lib/omux/qt/plugins/platforms/libqminimal.so",
        }
        expected = self.installed_paths() | {self.prefix / name for name in additions}
        self.assertEqual({Path(entry["path"]) for entry in record["files"]}, expected)
        for name in additions:
            path = self.prefix / name
            self.assertEqual(path.read_bytes(), files[name])
            executable = name in {"bin/omux-control", "lib/omux/qt/libexec/omux-control.bin", "lib/omux/qt/lib/ld-test.so.1"}
            self.assertEqual(path.stat().st_mode & 0o777, 0o755 if executable else 0o644)
        result = install.uninstall(self.prefix, self.state)
        self.assertEqual(set(result["removed"]), {str(path) for path in expected})
        self.assertEqual(result["preserved"], [])
        self.assertFalse(any(path.exists() for path in expected))

    def test_uninstall_preserves_modified_qt_plugin_and_unknown_files(self) -> None:
        self.install_qt()
        modified = self.prefix / "lib/omux/qt/plugins/platforms/libqxcb.so"
        modified.write_bytes(b"user modified Qt plugin\n")
        unknown = {
            self.prefix / "lib/omux/qt/plugins/platforms/libqcustom.so": b"unowned plugin\n",
            self.prefix / "lib/omux/qt/preferences.json": b"unowned settings\n",
        }
        for path, data in unknown.items():
            path.write_bytes(data)
        result = install.uninstall(self.prefix, self.state)
        self.assertEqual(result["preserved"], [str(modified)])
        self.assertEqual(modified.read_bytes(), b"user modified Qt plugin\n")
        for path, data in unknown.items():
            self.assertEqual(path.read_bytes(), data)
        retained = json.loads((self.state / install.RECORD).read_bytes())
        self.assertEqual([entry["path"] for entry in retained["files"]], [str(modified)])
        self.assertFalse((self.prefix / "bin/omux-control").exists())
        self.assertFalse((self.prefix / "lib/omux/qt/libexec/qt.conf").exists())

    def test_ownership_record_rejects_paths_outside_qt_platform_namespace(self) -> None:
        record, _ = self.install_qt()
        record_path = self.state / install.RECORD
        originals = {Path(entry["path"]): Path(entry["path"]).read_bytes() for entry in record["files"]}
        relatives = (
            "lib/omux/qt/plugins/platforms/../../preferences.json",
            "lib/omux/qt/plugins/imageformats/libqgif.so",
            "lib/omux/qt/plugins/platforms/nested/libqbad.so",
            "lib/omux/qt/plugins/platforms/libqbad.dylib",
            "lib/omux/libexec/other.bin",
        )
        for relative in relatives:
            with self.subTest(relative=relative):
                path = self.prefix / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                data = b"synthetic forbidden ownership payload\n"
                path.write_bytes(data)
                tampered = json.loads(pack.json_bytes(record))
                tampered["files"].append({"path": str(path), "sha256": pack.digest(data), "mode": 0o644})
                encoded = pack.json_bytes(tampered)
                record_path.write_bytes(encoded)
                with self.assertRaisesRegex(ValueError, "unmanaged"):
                    install.uninstall(self.prefix, self.state)
                self.assertEqual(record_path.read_bytes(), encoded)
                self.assertEqual(path.read_bytes(), data)
                for owned, original in originals.items():
                    self.assertEqual(owned.read_bytes(), original)
        record_path.write_bytes(pack.json_bytes(record))


if __name__ == "__main__":
    unittest.main()
