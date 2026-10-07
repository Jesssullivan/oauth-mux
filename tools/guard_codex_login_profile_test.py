"""Offline admission and private transport regressions; no provider/native run."""
import json
import os
import socket
import stat
import tempfile
from pathlib import Path
import sys
import time
import unittest
from unittest import mock
import guard_codex_login_profile as login
import guard_codex_live_profile as live
import guard_dependency_profile as dependency
import execution_guard as guard

def selection():
    return {"retained009_bundle":True, "schema_version":1, "authorize_provider_login":True, "native_device_contract_qualified":True,
        "native_sha256":login.BACKEND_SHA, "source_receipt_sha256":"b"*64,
        "state_parent":"/private/operator/profiles", "deadline_seconds":900,
        "ui":{"host_alias":"yoga", "ssh_path":login.SSH, "ssh_sha256":"c"*64,
            "known_hosts_path":login.KNOWN_HOSTS, "qualification_path":"/private/operator/qualification.json",
            "qualification_sha256":"d"*64, "ssh_auth_socket":None,
            "remote":{"python_path":"/nix/store/"+"a"*32+"-python/bin/python3",
                "python_sha256":"e"*64, "gio_path":"/nix/store/"+"b"*32+"-glib/lib/libgio-2.0.so.0",
                "gio_sha256":"f"*64, "uid":1000, "machine_id_sha256":"1"*64,
                "boot_id_sha256":"2"*64, "wayland_socket":"/run/user/1000/wayland-0",
                "wayland_device":1, "wayland_inode":2, "closure_qualified":True, "seat_qualified":True,
                "dialog_path":"/private/qualified/control", "dialog_sha256":"3"*64,
                "qt_platform_plugin":"/nix/store/"+"c"*32+"-qtwayland/lib/qt-6/plugins/platforms/libqwayland-generic.so",
                "qt_platform_plugin_sha256":"4"*64}}}

def systemctl_bind_readback(configured):
    """Pinned systemctl v260.1: nonrecursive has no suffix, recursive has rbind."""
    return " ".join(value.removesuffix(":norbind") if value.endswith(":norbind")
        else value if value.endswith(":rbind") else value+":rbind" for value in configured)

class LoginProfileTests(unittest.TestCase):
    def test_one_exact_run_separate_from_live_and_standard(self):
        self.assertEqual(dependency.selected_profile("codex-login",["run",login.LABEL]),{"PrivateNetwork":"no"})
        for arguments in (["test",login.LABEL],["run","//delivery:native_account_login_test"],
                ["run",login.LABEL,"//tools:execution_guard_test"],["run",login.LABEL,"--"],
                ["run","//..."],["run","//delivery:yoga_toolbar_consent_proof"]):
            with self.subTest(arguments=arguments),self.assertRaises(ValueError):
                dependency.selected_profile("codex-login",arguments)
        with self.assertRaises(ValueError):
            live.selected(["run",login.LABEL])
        with self.assertRaises(ValueError):
            guard.bazel_command("/nix/store/bazel",Path("/private/run"),["run",login.LABEL])

    def test_finite_inputs_are_exclusive_and_require_independent_pins(self):
        base = (["run",login.LABEL],"system",Path("/private/input.json"),Path("/private/"+"a"*64),False)
        pins = ("a"*64,"b"*64,"d"*64)
        login.finite(*base,pins=pins)
        for manager,reuse,unrelated,selected_pins in (
                ("user",False,(),pins),("system",True,(),pins),
                ("system",False,(Path("/private/runtime009"),),pins),
                ("system",False,(),()),("system",False,(),("a"*64,"b"*64,"x"*64))):
            with self.subTest(manager=manager,reuse=reuse,unrelated=unrelated),self.assertRaises(ValueError):
                login.finite(base[0],manager,base[2],base[3],reuse,unrelated,pins=selected_pins)

    def test_manifest_has_no_inherited_fd_or_uri_field(self):
        value = selection()
        self.assertEqual(login.schema(json.dumps(value)),value)
        for field in ("private_ui_fd","url","token","auth_json"):
            selected = dict(value)
            selected[field] = "private-value"
            with self.subTest(field=field),self.assertRaises(ValueError):
                login.schema(json.dumps(selected))
        for field,bad in (("retained009_bundle",False),("schema_version",True),("deadline_seconds",True),
                ("deadline_seconds",0),("deadline_seconds",901),("authorize_provider_login",False),
                ("native_device_contract_qualified",False),("native_sha256","not-a-digest")):
            selected = dict(value)
            selected[field] = bad
            with self.subTest(field=field,bad=bad),self.assertRaises(ValueError):
                login.schema(json.dumps(selected))
        with self.assertRaises(ValueError):
            login.schema('{"schema_version":1,"schema_version":1}')

    def test_remote_qualification_is_typed_and_fixed(self):
        for name,bad in (("closure_qualified",False),("seat_qualified",False),("uid",True),
                ("wayland_socket","/run/user/2000/wayland-0"),("python_path","/usr/bin/python3"),
                ("dialog_path","/private/../control"),("qt_platform_plugin","/private/plugin.so")):
            value = selection()
            value["ui"]["remote"][name] = bad
            with self.subTest(name=name),self.assertRaises(ValueError):
                login.schema(json.dumps(value))
        for name,bad in (("ssh_path","/usr/bin/ssh"),("known_hosts_path","/private/other"),
                ("qualification_path","/private/file:ambiguous"),("ssh_auth_socket","/private/agent\n")):
            value = selection()
            value["ui"][name] = bad
            with self.subTest(name=name),self.assertRaises(ValueError):
                login.schema(json.dumps(value))

    def test_failed_readback_projection_never_mutates_private_data(self):
        actual = {"BindReadOnlyPaths":"/private/operator/profile:/omux-native-login/input.json",
                  "BindPaths":"/private/account/source:/bad", "MemoryMax":"wrong"}
        projected = login.projection(actual)
        self.assertNotIn("/private",json.dumps(projected))
        self.assertIn("/private/operator/profile",actual["BindReadOnlyPaths"])
        for outcome in (False,True):
            self.assertNotIn("/private",json.dumps(login.projection(actual,verified=outcome)))
        admission = object.__new__(login.Admission)
        admission.manifest = Path("/private/input.json")
        admission.namespace = Path("/private")
        admission.directory = Path("/private/native")
        admission.qualification = Path("/private/ui.json")
        admission.agent_path = None
        with self.assertRaises(ValueError):
            admission.verify_bindings(actual)
        self.assertNotIn("/private",json.dumps(projected))

    def test_closed_oserror_rejection_never_renders_selector(self):
        class PrivateFailure(OSError):
            def __str__(self):
                raise AssertionError("private path must never render")
        self.assertEqual(login.rejection(PrivateFailure(13,"denied","/private/account/auth.json")),
                         "codex-login-admission-refused")

    def test_command_has_fixed_manifest_original_deadline_and_limits(self):
        admitted = mock.Mock(directory=Path("/private/"+"a"*64),deadline=1234567890123,namespace_fd=999)
        admitted_namespace = mock.Mock(st_dev=17, st_ino=23)
        with mock.patch.object(guard.os,"fstat",return_value=admitted_namespace):
            command = guard.codex_login_command("/nix/store/bazel",Path("/private/run"),
                                              ["run",login.LABEL],admitted)
        for flag in ("--batch","--jobs=2","--host_jvm_args=-Xmx1536m",
                "--spawn_strategy=linux-sandbox","--sandbox_default_allow_network=false",
                "--remote_cache=","--remote_executor=",
                "--run_env="+login.VARIABLE+"="+login.DESTINATION,
                "--run_env=OMUX_NATIVE_LOGIN_NAMESPACE_ID=17:23",
                "--run_env=OMUX_NATIVE_LOGIN_ORIGINAL_DEADLINE_NS=1234567890123"):
            self.assertIn(flag,command)
        self.assertEqual(command[-1],login.LABEL)
        self.assertEqual(command.count("run"),1)
        self.assertNotIn("--repo_env="+login.DIRECTORY_VARIABLE+"=",command)
        self.assertNotIn("private_ui_fd"," ".join(command))
        self.assertNotIn("auth.json"," ".join(command))

    def test_bind_order_can_normalize_but_duplicates_or_mutability_refuse(self):
        admission = object.__new__(login.Admission)
        admission.manifest = Path("/private/input.json")
        admission.namespace = Path("/private")
        admission.directory = Path("/private/native")
        admission.qualification = Path("/private/ui.json")
        admission.agent_path = None
        actual = {"BindReadOnlyPaths":systemctl_bind_readback(reversed(admission.bindings())),"BindPaths":""}
        admission.verify_bindings(actual)
        actual["BindReadOnlyPaths"] = " ".join(value + ":rbind" for value in admission.bindings())
        admission.verify_bindings(actual)
        actual["BindReadOnlyPaths"] = " ".join(value + ":rw" for value in admission.bindings())
        with self.assertRaises(ValueError):
            admission.verify_bindings(actual)
        actual["BindReadOnlyPaths"] = systemctl_bind_readback(admission.bindings())
        actual["BindReadOnlyPaths"] += " " + actual["BindReadOnlyPaths"].split()[0]
        with self.assertRaises(ValueError):
            admission.verify_bindings(actual)
        actual["BindReadOnlyPaths"] = " ".join(admission.bindings())
        actual["BindPaths"] = "/private/native:/private/native:rbind"
        with self.assertRaises(ValueError):
            admission.verify_bindings(actual)

    def test_root_created_public_namespace_is_refused(self):
        import stat
        for mode,uid in ((0o755,os.getuid()),(0o700,os.getuid()+1),(0o777,os.getuid())):
            info = mock.Mock(st_mode=stat.S_IFDIR|mode, st_uid=uid)
            with self.subTest(mode=mode,uid=uid),self.assertRaises(ValueError):
                login.namespace_custody(info)
        login.namespace_custody(mock.Mock(st_mode=stat.S_IFDIR|0o700,st_uid=os.getuid()))

    def test_exact_namespace_membership_and_no_follow_socket_mountpoint(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            (parent/"input.json").write_bytes(b"{}")
            (parent/"ui-qualification.json").write_bytes(b"{}")
            fd = os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                login.namespace_membership(fd)
                with self.assertRaises(ValueError):
                    login.namespace_membership(fd,agent=True)
                (parent/"extra").write_bytes(b"not-an-authorized-input")
                with self.assertRaises(ValueError):
                    login.namespace_membership(fd)
                (parent/"extra").unlink()
                (parent/"socket-link").symlink_to("input.json")
                with self.assertRaises(ValueError):
                    login.namespace_membership(fd)
            finally:
                os.close(fd)

    def test_actual_agent_source_refuses_links_and_unowned_or_public_sockets(self):
        import socket
        import stat
        import tempfile
        for mode,uid,nlink in ((0o644,os.getuid(),1),(0o600,os.getuid()+1,1),(0o600,os.getuid(),2)):
            with self.subTest(mode=mode,uid=uid),self.assertRaises(ValueError):
                login.placeholder_custody(mock.Mock(st_mode=stat.S_IFSOCK|mode,st_uid=uid,st_nlink=nlink))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            channel = socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)
            try:
                channel.bind(str(path/"ssh-agent.sock"))
                (path/"ssh-agent.sock").chmod(0o600)
                held = os.open(path/"ssh-agent.sock",os.O_PATH|os.O_NOFOLLOW)
                try:
                    login.placeholder_custody(os.fstat(held))
                finally:
                    os.close(held)
                (path/"linked.sock").symlink_to("ssh-agent.sock")
                held = os.open(path/"linked.sock",os.O_PATH|os.O_NOFOLLOW)
                try:
                    with self.assertRaises(ValueError):
                        login.placeholder_custody(os.fstat(held))
                finally:
                    os.close(held)
            finally:
                channel.close()

    def test_agent_destination_regular_and_source_socket_have_separate_custody(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root/"ssh-agent.sock"
            path.touch(mode=0o600)
            login.agent_mountpoint_custody(path.stat(follow_symlinks=False))
            with self.assertRaises(ValueError):
                login.placeholder_custody(path.stat(follow_symlinks=False))
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as channel:
                actual = root/"actual-agent"
                channel.bind(str(actual))
                actual.chmod(0o600)
                login.placeholder_custody(actual.stat(follow_symlinks=False))
                with self.assertRaises(ValueError):
                    login.agent_mountpoint_custody(actual.stat(follow_symlinks=False))
            for change in ("data","mode","hardlink"):
                path.write_bytes(b"")
                path.chmod(0o600)
                if change == "data":
                    path.write_bytes(b"unexpected metadata")
                elif change == "mode":
                    path.chmod(0o700)
                else:
                    os.link(path,root/"second-link")
                with self.subTest(change=change),self.assertRaises(ValueError):
                    login.agent_mountpoint_custody(path.stat(follow_symlinks=False))
            for uid in (os.getuid()+1,):
                with self.assertRaises(ValueError):
                    login.agent_mountpoint_custody(mock.Mock(st_mode=stat.S_IFREG|0o600,
                        st_uid=uid,st_nlink=1,st_size=0))

    def test_agent_regular_mountpoint_rechecks_held_named_identity_and_refuses_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root/"ssh-agent.sock"
            path.touch(mode=0o600)
            parent = os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            held = os.open(path,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC)
            try:
                self.assertEqual(login.agent_mountpoint_identity(parent,held),live.identity(os.fstat(held)))
                path.rename(root/"original")
                path.touch(mode=0o600)
                with self.assertRaises(ValueError):
                    login.agent_mountpoint_identity(parent,held)
                path.unlink()
                path.symlink_to(root/"original")
                with self.assertRaises(ValueError):
                    login.agent_mountpoint_identity(parent,held)
            finally:
                os.close(held)
                os.close(parent)

    def test_selected_agent_leaf_requires_norbind_without_widening_native_directory_mounts(self):
        admitted = object.__new__(login.Admission)
        admitted.namespace,admitted.directory = Path("/private/input"),Path("/private/native")
        admitted.agent_path = "/private/authorized-agent"
        leaf = admitted.agent_path+":"+login.AGENT_DESTINATION
        actual = {"BindReadOnlyPaths":systemctl_bind_readback(admitted.bindings()),"BindPaths":""}
        admitted.verify_bindings(actual)
        self.assertIn(leaf,actual["BindReadOnlyPaths"].split())
        self.assertIn(leaf+":norbind",admitted.bindings())
        for token in actual["BindReadOnlyPaths"].split():
            if token.endswith(":rbind"):
                changed = {**actual,"BindReadOnlyPaths":actual["BindReadOnlyPaths"].replace(token,token.removesuffix(":rbind"))}
                with self.subTest(token=token),self.assertRaises(ValueError):
                    admitted.verify_bindings(changed)
        directory_binds = " ".join(v+":rbind" for v in admitted.bindings() if not v.endswith(":norbind"))
        for selector in (leaf+":norbind",leaf+":rbind",leaf+":rw",leaf+":unknown"):
            with self.subTest(selector=selector),self.assertRaises(ValueError):
                admitted.verify_bindings({**actual,"BindReadOnlyPaths":directory_binds+" "+selector})
        for field,extra in (("BindReadOnlyPaths"," "+leaf),
                ("BindReadOnlyPaths"," /private/other:/extra:rbind"),("BindPaths","/private/native:/private/native:rbind")):
            with self.subTest(field=field),self.assertRaises(ValueError):
                admitted.verify_bindings({**actual,field:actual[field]+extra})

    def test_configuration_and_pinned_systemctl_readback_keep_native_agent_modes_distinct(self):
        leaf = "/private/agent:"+login.AGENT_DESTINATION
        root = "/private/input:/omux-native-login"
        self.assertEqual(login.normalized_bindings(root+" "+leaf+":norbind",[leaf]),{root,leaf})
        self.assertEqual(login.normalized_bindings(root+":rbind "+leaf,[leaf],readback=True),{root,leaf})
        for readback,value in ((False,leaf),(False,leaf+":rbind"),(False,root+":norbind"),
                (True,leaf+":rbind"),(True,leaf+":norbind"),(True,root),(True,root+":norbind")):
            with self.subTest(readback=readback,value=value),self.assertRaises(ValueError):
                login.normalized_bindings(value,[leaf],readback=readback)

    def test_original_deadline_is_not_reset(self):
        admission = object.__new__(login.Admission)
        admission.deadline = 1200*10**9
        with mock.patch.object(login.time,"monotonic_ns",return_value=1100*10**9):
            self.assertEqual(admission.runtime_seconds(),70)
        with mock.patch.object(login.time,"monotonic_ns",return_value=1200*10**9):
            with self.assertRaises(ValueError):
                admission.runtime_seconds()


    def test_retained_device_receipt_requires_all_ten_files_and_actual_branch(self):
        response_properties = {name:{"type":"string"} for name in ("type","loginId","verificationUrl","userCode")}
        response_properties["type"]["enum"] = ["chatgptDeviceCode"]
        receipt = {"schema_version":1,"kind":"omux-retained-device-api-qualification-v1",
            "status":"provider-free-device-api-qualified","archive_sha256":login.ARCHIVE_SHA,
            "manifest_sha256":login.MANIFEST_SHA,"backend_sha256":login.BACKEND_SHA,
            "backend_bytes":318579008,"loader_sha256":login.RUNTIME_FILES["lib/codex/lib/ld-linux-x86-64.so.2"][0],
            "runtime_inventory":{name:{"sha256":pin,"bytes":size,"mode":mode}
                for name,(pin,size,mode) in login.RUNTIME_FILES.items()},
            "native_support":False,"text_continuity":False,"provider_evaluation":False,
            "device_api":{"method":"account/login/start","provider_invocation":False,
                "request":{"type":"object","properties":{"type":{"type":"string","enum":["chatgptDeviceCode"]}},
                    "required":["type"]},
                "response":{"type":"object","properties":response_properties,
                    "required":list(response_properties)}}}
        login.device_qualification(receipt)
        import copy
        for changed in ("inventory","backend","live","bool_schema","browser"):
            value = copy.deepcopy(receipt)
            if changed == "inventory":
                value["runtime_inventory"].pop("lib/codex/share/ca-bundle.crt")
            elif changed == "backend":
                value["backend_sha256"] = "f"*64
            elif changed == "live":
                value["provider_evaluation"] = True
            elif changed == "bool_schema":
                value["schema_version"] = True
            else:
                value["device_api"]["response"]["properties"]["type"]["enum"] = ["chatgpt"]
            with self.subTest(changed=changed),self.assertRaises(ValueError):
                login.device_qualification(value)

    def test_runtime_namespace_refuses_extra_symlink_and_parent_escape(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/"lib").mkdir()
            (root/"lib"/"payload").write_bytes(b"public model")
            (root/"lib").chmod(0o555)
            fd = os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                login.runtime_membership(fd,{"lib"})
                held = login.open_runtime(fd,"lib",directory=True)
                try:
                    login.runtime_membership(held,{"payload"})
                finally:
                    os.close(held)
                for path in ("../payload","/absolute","lib//payload","lib/./payload"):
                    with self.subTest(path=path),self.assertRaises(ValueError):
                        login.open_runtime(fd,path)
                (root/"link").symlink_to("lib")
                with self.assertRaises(OSError):
                    login.open_runtime(fd,"link/payload")
                with self.assertRaises(ValueError):
                    login.runtime_membership(fd,{"lib"})
                (root/"lib").chmod(0o755)
                with self.assertRaises(ValueError):
                    login.open_runtime(fd,"lib",directory=True)
            finally:
                os.close(fd)
                (root/"lib").chmod(0o700)

if __name__ == "__main__":
    unittest.main()
