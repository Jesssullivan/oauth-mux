"""Provider-free carrier models. All SSH/GIO/native process launches are mocked."""
import contextlib
import ctypes as C
import fcntl
import io
import json
import os
from pathlib import Path
import signal
import socket
import stat
import subprocess
import threading
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import yoga_portal_carrier as carrier
import yoga_portal_worker as worker
import ssh_policy

URI = b"https://auth.openai.com/codex/device"
FRAME = json.dumps({"verification_url":URI.decode(),"user_code":"MODEL-NOT-A-SECRET"},
    sort_keys=True,separators=(",",":")).encode()


class Models(unittest.TestCase):
    def test_standalone_dialog_runtime_seals_public_fonts_and_removes_only_owned_empty_home(self):
        with tempfile.TemporaryDirectory() as directory:
            config = {"dialog_path":directory+"/control","uid":os.getuid(),"wayland_socket":"wayland-model",
                "qt_platform_plugin":"/declared/plugins/platforms/libqwayland.so"}
            runtime = worker.DialogRuntime(config)
            home = Path(runtime.environment["HOME"])
            self.assertEqual(stat.S_IMODE(home.stat().st_mode),0o700)
            self.assertEqual(runtime.environment["LD_LIBRARY_PATH"],":".join(worker.DIALOG_LIBRARY_DIRECTORIES))
            payload = os.pread(runtime.fonts,4096,0)
            self.assertIn(worker.FONT_DIRECTORY.encode(),payload)
            self.assertNotIn(b"include",payload)
            self.assertNotIn(b"cachedir",payload)
            self.assertEqual(runtime.environment["FONTCONFIG_FILE"],"/proc/self/fd/"+str(runtime.fonts))
            with self.assertRaises(OSError):
                os.pwrite(runtime.fonts,b"changed",0)
            self.assertTrue(fcntl.fcntl(runtime.fonts,fcntl.F_GET_SEALS)&fcntl.F_SEAL_WRITE)
            runtime.close()
            self.assertFalse(home.exists())
            self.assertEqual(list(Path(directory).iterdir()),[])

    def test_standalone_runtime_mkdir_collision_never_removes_existing_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            name = "home-00000000-0000-0000-0000-000000000000"
            existing = Path(directory)/name
            existing.mkdir(mode=0o700)
            with patch.object(worker.uuid,"uuid4",return_value="00000000-0000-0000-0000-000000000000"):
                with self.assertRaises(FileExistsError):
                    worker.DialogRuntime({"dialog_path":directory+"/control"})
            self.assertTrue(existing.is_dir())

    def test_standalone_runtime_refuses_nonempty_home_without_deleting_child(self):
        with tempfile.TemporaryDirectory() as directory:
            config = {"dialog_path":directory+"/control","uid":os.getuid(),"wayland_socket":"wayland-model",
                "qt_platform_plugin":"/declared/plugins/platforms/libqwayland.so"}
            runtime = worker.DialogRuntime(config)
            home = Path(runtime.environment["HOME"])
            (home/"unexpected-public-model").write_bytes(b"model")
            with self.assertRaisesRegex(worker.Refusal,"dialog_runtime_not_empty"):
                runtime.close()
            self.assertEqual((home/"unexpected-public-model").read_bytes(),b"model")

    def test_operator_cancel_refuses_delivery_and_is_never_success(self):
        process = Mock(returncode=1)
        process.stdin,process.stdout = io.BytesIO(),io.BytesIO()
        process.poll.return_value = 1
        dialog = worker.Dialog.__new__(worker.Dialog)
        dialog.process,dialog.pidfd,dialog.until = process,None,time.monotonic()+1
        with self.assertRaisesRegex(worker.Refusal,"dialog_closed"):
            dialog.present(FRAME)
        self.assertEqual(process.stdin.getvalue(),b"")
        with self.assertRaisesRegex(worker.Refusal,"dialog_cancelled"):
            dialog.close(success=True)
        process.send_signal.assert_not_called()
        self.assertTrue(process.stdin.closed and process.stdout.closed)

    def test_dialog_pidfd_failure_escalates_only_still_owned_child(self):
        process = Mock(pid=4321,returncode=0)
        process.stdin,process.stdout = io.BytesIO(),io.BytesIO()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("owned-model",5),subprocess.TimeoutExpired("owned-model",5),0]
        selected = {"uid":1000,"wayland_socket":"/run/user/1000/wayland-0",
            "qt_platform_plugin":"/declared/plugins/platforms/libqwayland-egl.so"}
        with patch.object(worker,"DialogRuntime",return_value=Mock(fonts=101,environment={})),\
            patch.object(worker.subprocess,"Popen",return_value=process),\
            patch.object(worker.os,"pidfd_open",side_effect=OSError("synthetic")):
            with self.assertRaises(OSError):
                worker.Dialog(3,selected,time.monotonic()+1)
        self.assertEqual([call.args[0] for call in process.send_signal.call_args_list],[signal.SIGTERM,signal.SIGKILL])
        self.assertEqual(process.wait.call_count,3)
        self.assertTrue(process.stdin.closed and process.stdout.closed)

    def test_dialog_held_executable_and_public_flag_only_no_payload(self):
        process = Mock(pid=4321,returncode=0)
        process.stdin = io.BytesIO()
        process.stdout = Mock(wraps=io.BytesIO())
        process.stdout.fileno.return_value = 42
        selected = {"uid":1000,"wayland_socket":"/run/user/1000/wayland-0",
            "qt_platform_plugin":"/declared/plugins/platforms/libqwayland-egl.so"}
        with patch.object(worker,"DialogRuntime",return_value=Mock(fonts=101,environment={"QT_QPA_PLATFORM":"wayland"})),\
            patch.object(worker.subprocess,"Popen",return_value=process) as launch,\
            patch.object(worker.os,"pidfd_open",return_value=99),patch.object(worker.os,"close"),\
            patch.object(worker,"read_line",return_value=b"OMUX_NATIVE_DEVICE_DIALOG_READY"):
            dialog = worker.Dialog(7,selected,time.monotonic()+1)
            arguments = launch.call_args.args[0]
            environment = launch.call_args.kwargs["env"]
            self.assertEqual(arguments,["/proc/self/fd/7","--native-device-login-stdin"])
            self.assertEqual(launch.call_args.kwargs["pass_fds"],(7,101))
            self.assertEqual(environment["QT_QPA_PLATFORM"],"wayland")
            self.assertNotIn("DBUS_SESSION_BUS_ADDRESS",environment)
            self.assertFalse(any("MODEL-NOT-A-SECRET" in str(value) for value in environment.values()))
            dialog.close(success=True)
    def public_policy_model(self,text):
        original = Path.read_text
        def read(path,*args,**kwargs):
            if str(path) == "/etc/ssh/ssh_config":
                return text
            return original(path,*args,**kwargs)
        stack = contextlib.ExitStack()
        stack.enter_context(patch.object(Path,"is_symlink",return_value=False))
        stack.enter_context(patch.object(Path,"resolve",autospec=True,side_effect=lambda path,*a,**kw:path))
        stack.enter_context(patch.object(Path,"stat",return_value=SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o644,st_size=len(text))))
        stack.enter_context(patch.object(Path,"read_text",autospec=True,side_effect=read))
        stack.enter_context(patch.object(Path,"home",return_value=Path("/authorized/model-home")))
        return stack

    def test_public_only_policy_never_includes_ambient_user_config(self):
        with self.public_policy_model("Ciphers aes256-gcm@openssh.com\n"):
            with ssh_policy.operator_config(include_user=False) as options:
                self.assertEqual(options[0],"-F")
                text = Path(options[1]).read_text()
                self.assertNotIn("model-home",text)
                self.assertIn("Include",text)

    def test_public_only_policy_rejects_unrelated_forwarding(self):
        for directive in ("LocalForward","RemoteForward","DynamicForward"):
            with self.public_policy_model(directive+" 1455 elsewhere:1455\n"):
                with self.assertRaisesRegex(ValueError,"unrelated forwarding"):
                    with ssh_policy.operator_config(include_user=False):
                        pass

    def test_device_arguments_clear_all_forwarding_without_uri_or_code(self):
        args = carrier.ssh_arguments({"ssh_path":"/declared/ssh"},["-F","/public/config"],[],"public-worker")
        forwards = [args[index+1] for index,value in enumerate(args[:-1]) if value == "-R"]
        self.assertEqual(forwards,[])
        for option in ("-oClearAllForwardings=yes","-oControlMaster=no","-oControlPath=none",
            "-oForwardAgent=no","-oProxyCommand=none","-oProxyJump=none","-oStrictHostKeyChecking=yes"):
            self.assertIn(option,args)
        self.assertEqual(args[-2:], ["yoga","public-worker"])
        self.assertFalse(any(URI.decode() in arg for arg in args))
        self.assertFalse(any("MODEL-NOT-A-SECRET" in arg for arg in args))

    def test_remote_exec_has_public_code_only_and_clears_loader_inputs(self):
        command = carrier.remote_command("/nix/store/declared/bin/python3","print('metadata')")
        self.assertIn("unset LD_PRELOAD LD_LIBRARY_PATH",command)
        self.assertIn(" -I -S -c ",command)
        self.assertNotIn(URI.decode(),command)

    def test_device_frame_is_canonical_exact_fields_and_duplicate_free(self):
        self.assertEqual(worker.device_frame(FRAME)["user_code"],"MODEL-NOT-A-SECRET")
        for wrong in (b'{}',FRAME+b' ',FRAME.replace(b'MODEL-NOT-A-SECRET',b'bad\\ncode'),
            b'{"user_code":"one","user_code":"two","verification_url":"https://auth.openai.com/codex/device"}'):
            with self.assertRaises(worker.Refusal):
                worker.device_frame(wrong)

    def test_missing_qualified_ui_closure_refuses_metadata_admission(self):
        selected = {"python_path":"/nix/store/"+"0"*32+"-model/bin/python3",
            "gio_path":"/nix/store/"+"0"*32+"-model/lib/libgio-2.0.so.0",
            "python_sha256":"a"*64,"gio_sha256":"b"*64,"machine_id_sha256":"c"*64,
            "boot_id_sha256":"d"*64,"uid":1000,"wayland_socket":"/run/user/1000/wayland-0",
            "wayland_device":1,"wayland_inode":2,"closure_qualified":True,"seat_qualified":True,
            "dialog_path":"/authorized/owned/dialog","dialog_sha256":"e"*64,
            "qt_platform_plugin":"/nix/store/"+"0"*32+"-model/plugins/platforms/libqwayland-egl.so",
            "qt_platform_plugin_sha256":"f"*64,"deadline_seconds":1}
        selected["closure_qualified"] = False
        with patch.object(worker.os,"getuid",return_value=1000):
            with self.assertRaisesRegex(worker.Refusal,"independent_qualification_required"):
                worker.selection(selected)

    def test_uri_scope_rejects_browser_login_and_other_provider(self):
        self.assertEqual(worker.uri_bytes(URI),URI)
        for wrong in (URI.replace(b"auth.openai.com",b"example.invalid"),
            b"https://auth.openai.com/oauth/authorize",URI+b"\n",URI+b"#private"):
            with self.assertRaises(worker.Refusal):
                worker.uri_bytes(wrong)

    def test_cancelled_private_read_never_consumes_a_frame(self):
        reader, writer = os.pipe()
        stop = threading.Event()
        stop.set()
        try:
            os.write(writer,b"still-private\n")
            with self.assertRaisesRegex(worker.Refusal,"private_channel_stopped"):
                worker.read_line(reader,time.monotonic()+1,stop=stop)
            self.assertEqual(os.read(reader,14),b"still-private\n")
        finally:
            os.close(reader)
            os.close(writer)

    def test_real_gio_stream_peer_is_checked_and_owned_fd_retained(self):
        first, second = socket.socketpair()
        portal = worker.Portal.__new__(worker.Portal)
        portal.connection, portal.error = 101,C.c_void_p()
        portal.gio = Mock()
        portal.gio.g_dbus_connection_get_stream.return_value = 202
        portal.gio.g_socket_connection_get_socket.return_value = 303
        portal.gio.g_socket_get_fd.return_value = first.fileno()
        try:
            portal.check_stream_peer(os.getuid())
            portal.gio.g_dbus_connection_get_stream.assert_called_with(101)
            portal.gio.g_socket_connection_get_socket.assert_called_with(202)
            portal.gio.g_socket_get_fd.assert_called_with(303)
            with self.assertRaisesRegex(worker.Refusal,"desktop_bus_peer_mismatch"):
                portal.check_stream_peer(os.getuid()+1)
            # Peer validation duplicates the actual transport; it leaves GIO's fd owned.
            first.sendall(b"x")
            self.assertEqual(second.recv(1),b"x")
        finally:
            first.close()
            second.close()

    def test_portal_receives_uri_as_memory_argument_without_stdout(self):
        portal = worker.Portal.__new__(worker.Portal)
        portal.gio = Mock()
        portal.gio.g_variant_type_new.return_value = 404
        portal.gio.g_variant_new_array.return_value = 505
        portal.gio.g_variant_new.return_value = 606
        portal.owner,portal.pid,portal.start_ticks = b":1.75",os.getpid(),777
        portal.pid_start = lambda:777
        portal.bus_uint = lambda method: os.getuid() if method == b"GetConnectionUnixUser" else os.getpid()
        portal.call = Mock(return_value=b"/org/freedesktop/portal/desktop/request/1_75/model")
        stdout,stderr = io.StringIO(),io.StringIO()
        with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
            portal.open_uri(URI)
        variant_call = portal.gio.g_variant_new.call_args.args
        self.assertEqual(variant_call[0],b"(ss@a{sv})")
        self.assertEqual(variant_call[2].value,URI)
        portal_call = portal.call.call_args.args
        self.assertEqual(portal_call[0],b":1.75")
        self.assertEqual(portal_call[3],b"OpenURI")
        self.assertEqual(stdout.getvalue()+stderr.getvalue(),"")

    def test_portal_openuri_schema_is_checked_before_private_delivery(self):
        interface = (b'<node><interface name="org.freedesktop.portal.OpenURI"><method name="OpenURI">'
            b'<arg type="s" direction="in"/><arg type="s" direction="in"/>'
            b'<arg type="a{sv}" direction="in"/><arg type="o" direction="out"/>'
            b'</method></interface></node>')
        worker.portal_interface(interface)
        for wrong in (interface.replace(b'OpenURI',b'Unexpected'),interface.replace(b'a{sv}',b'v'),
            b'<!ENTITY private "never-expand">'+interface):
            with self.assertRaisesRegex(worker.Refusal,"portal_interface_unavailable"):
                worker.portal_interface(wrong)

    def test_portal_owner_drift_refuses_before_private_variant(self):
        portal = worker.Portal.__new__(worker.Portal)
        portal.gio = Mock()
        portal.owner,portal.pid,portal.start_ticks = b":1.75",os.getpid(),777
        portal.pid_start = lambda:778
        with self.assertRaisesRegex(worker.Refusal,"portal_owner_changed"):
            portal.open_uri(URI)
        portal.gio.g_variant_new.assert_not_called()

    def test_relay_sends_device_frame_only_to_private_ssh_stdin(self):
        with patch.object(carrier,"ui_selection",side_effect=lambda value:value):
            owned = carrier.YogaPortalCarrier({},time.monotonic()+2,"/declared/worker")
        owned.reader,writer = os.pipe()
        ssh_read,ssh_write = os.pipe()
        owned.process = Mock()
        owned.process.stdin = os.fdopen(ssh_write,"wb",buffering=0)
        owned.hosts = Mock()
        owned.remote_result = Mock(return_value={"scope":"omux-yoga-portal-requested-v1","uri_requested":True})
        owned.process.poll.return_value = None
        owned.stopping.wait = Mock(return_value=True)
        stdout,stderr = io.StringIO(),io.StringIO()
        try:
            os.write(writer,FRAME+b"\n")
            with contextlib.redirect_stdout(stdout),contextlib.redirect_stderr(stderr):
                owned.relay()
            self.assertTrue(owned.requested.is_set())
            self.assertIsNone(owned.failure)
            self.assertEqual(os.read(ssh_read,len(FRAME)+1),FRAME+b"\n")
            self.assertEqual(stdout.getvalue()+stderr.getvalue(),"")
        finally:
            owned.process.stdin.close()
            os.close(ssh_read)
            os.close(owned.reader)
            os.close(writer)

    def test_owned_ssh_pidfd_failure_escalates_and_reaps_without_foreign_signal(self):
        ui = {"ssh_path":"/declared/ssh","ssh_sha256":"a"*64,"known_hosts_path":"/declared/host-pin",
            "remote":{"python_path":"/declared/python"},"ssh_auth_socket":None}
        process = Mock(pid=4321,returncode=0)
        process.stdin,process.stdout = io.BytesIO(),io.BytesIO()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("own-model",5),subprocess.TimeoutExpired("own-model",5),0]
        host = Mock()
        policy = Mock()
        policy.__enter__ = Mock(return_value=[])
        policy.__exit__ = Mock(return_value=False)
        with patch.object(carrier,"ui_selection",side_effect=lambda value:value),\
            patch.object(carrier,"qualified_join"),patch.object(carrier.qualification,"executable_hash"),\
            patch.object(carrier,"KnownHostAuthority",return_value=host),\
            patch.object(carrier,"operator_config",return_value=policy),\
            patch.object(Path,"read_bytes",return_value=b"pass"),\
            patch.object(carrier,"ssh_arguments",return_value=["/declared/ssh"]),\
            patch.object(carrier.subprocess,"Popen",return_value=process),\
            patch.object(carrier.os,"pidfd_open",side_effect=OSError("synthetic")),\
            patch.dict(os.environ,{},clear=True),contextlib.redirect_stdout(io.StringIO()):
            owned = carrier.YogaPortalCarrier(ui,time.monotonic()+2,"/declared/worker")
            with self.assertRaises(OSError):
                owned.open()
        self.assertEqual([call.args[0] for call in process.send_signal.call_args_list],[signal.SIGTERM,signal.SIGKILL])
        self.assertEqual(process.wait.call_count,3)
        self.assertTrue(process.stdin.closed and process.stdout.closed)
        host.close.assert_called_once()
        policy.__exit__.assert_called_once()

    def test_stuck_relay_retains_fds_for_outer_owned_guard_cleanup(self):
        with patch.object(carrier,"ui_selection",side_effect=lambda value:value):
            owned = carrier.YogaPortalCarrier({},time.monotonic()+2,"/declared/worker")
        owned.thread = Mock()
        owned.thread.is_alive.return_value = True
        owned.reader,owned.writer = os.pipe()
        owned.process = Mock()
        try:
            with self.assertRaisesRegex(worker.Refusal,"private_ui_thread_cleanup_incomplete"):
                owned.close()
            os.fstat(owned.reader)
            os.fstat(owned.writer)
            owned.process.stdin.close.assert_not_called()
            owned.process.send_signal.assert_not_called()
        finally:
            os.close(owned.reader)
            os.close(owned.writer)


    def test_actual_dialog_close_faults_cannot_skip_reap_or_runtime_release(self):
        dialog = worker.Dialog.__new__(worker.Dialog)
        dialog.process = Mock()
        dialog.process.poll.return_value = None
        dialog.process.stdin.close.side_effect = OSError(5,"synthetic-close")
        dialog.process.stdout.close.side_effect = OSError(5,"synthetic-close")
        dialog.process.wait.side_effect = [subprocess.TimeoutExpired("model",5),
            subprocess.TimeoutExpired("model",5),0]
        process = dialog.process
        dialog.pidfd = 19
        dialog.runtime = Mock()
        dialog.runtime.close.side_effect = OSError(5,"synthetic-close")
        runtime = dialog.runtime
        with patch.object(worker.signal,"pidfd_send_signal") as signals,patch.object(worker.os,"close") as close:
            with self.assertRaisesRegex(worker.Refusal,"^owned_dialog_cleanup_incomplete$"):
                dialog.close(success=True)
        self.assertEqual([call.args[1] for call in signals.call_args_list],[signal.SIGTERM,signal.SIGKILL])
        self.assertEqual(process.wait.call_count,3)
        process.stdout.close.assert_called_once()
        runtime.close.assert_called_once()
        close.assert_called_once_with(19)
        self.assertIsNone(dialog.process)
        self.assertIsNone(dialog.pidfd)
        self.assertIsNone(dialog.runtime)

    def test_actual_dialog_runtime_releases_all_fds_on_first_close_fault(self):
        with tempfile.TemporaryDirectory() as directory:
            config = {"dialog_path":directory+"/control","uid":os.getuid(),"wayland_socket":"wayland-model",
                "qt_platform_plugin":"/declared/plugins/platforms/libqwayland.so"}
            runtime = worker.DialogRuntime(config)
            held = [runtime.fonts,runtime.home,runtime.parent]
            close = os.close
            seen = []
            def failing_close(fd):
                seen.append(fd)
                close(fd)
                if fd == held[0]:
                    raise OSError(5,"synthetic-close")
            with patch.object(worker.os,"close",side_effect=failing_close):
                with self.assertRaisesRegex(worker.Refusal,"^dialog_runtime_cleanup_incomplete$"):
                    runtime.close()
            self.assertEqual(seen,held)
            self.assertEqual((runtime.fonts,runtime.home,runtime.parent),(None,None,None))
            self.assertEqual(list(Path(directory).iterdir()),[])

    def test_actual_carrier_close_retains_failure_and_releases_later_resources(self):
        with patch.object(carrier,"ui_selection",side_effect=lambda value:value):
            owned = carrier.YogaPortalCarrier({},time.monotonic()+5,"/declared/worker")
        owned.process = Mock()
        owned.process.poll.return_value = None
        owned.process.stdin.close.side_effect = OSError(5,"synthetic-close")
        owned.process.stdout.close.side_effect = OSError(5,"synthetic-close")
        owned.process.wait.side_effect = [subprocess.TimeoutExpired("model",5),
            subprocess.TimeoutExpired("model",5),0]
        owned.reader,owned.writer,owned.pidfd = 11,12,13
        owned.hosts,owned.policy = Mock(),Mock()
        hosts,policy = owned.hosts,owned.policy
        hosts.close.side_effect = OSError(5,"synthetic-close")
        def close_fd(fd):
            if fd in (12,11):
                raise OSError(5,"synthetic-close")
        with patch.object(carrier.os,"close",side_effect=close_fd) as close,\
            patch.object(carrier.signal,"pidfd_send_signal") as signals,patch.object(carrier,"qualified_join"):
            with self.assertRaisesRegex(worker.Refusal,"^owned_ssh_cleanup_incomplete$"):
                owned.close(success=True)
        self.assertEqual([call.args[1] for call in signals.call_args_list],[signal.SIGTERM,signal.SIGKILL])
        self.assertEqual(owned.process.wait.call_count,3)
        self.assertEqual([call.args[0] for call in close.call_args_list],[12,11,13])
        owned.process.stdout.close.assert_called_once()
        hosts.close.assert_called_once()
        policy.__exit__.assert_called_once()
        self.assertEqual((owned.writer,owned.reader,owned.pidfd,owned.hosts,owned.policy),(None,None,None,None,None))


if __name__ == "__main__":
    unittest.main()
