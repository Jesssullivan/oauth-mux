"""Offline exact provider-free UI route/input/output regressions."""
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest import mock
import execution_guard as guard
import guard_dependency_profile as dependency
import guard_native_login_ui_profile as ui
import guard_codex_login_profile as login

def plan():
    return {"schema_version":1,"scope":"omux-native-login-ui-prepare-v1",
        "os_qualification_sha256":"a"*64,"control_sha256":"b"*64,
        "known_hosts_path":login.KNOWN_HOSTS,"ssh_auth_socket":None,
        "output_parent":ui.OUTPUT_DESTINATION,"deadline_seconds":900}

class PrepareModels(unittest.TestCase):
    def test_exact_provider_free_route_does_not_inherit_login_admission(self):
        self.assertEqual(dependency.selected_profile("native-login-ui",["run",ui.LABEL]),{"PrivateNetwork":"no"})
        for args in (["test",ui.LABEL],["run",login.LABEL],["run",ui.LABEL,"--"],["run","//..."]):
            with self.subTest(args=args),self.assertRaises(ValueError):
                ui.selected(args)
        with self.assertRaises(ValueError):
            login.selected(["run",ui.LABEL])
        with self.assertRaises(ValueError):
            guard.bazel_command("/nix/store/bazel",Path("/private/run"),["run",ui.LABEL])

    def test_private_schema_never_accepts_qualification_flags_provider_fields_or_output_selector(self):
        self.assertEqual(ui.schema(json.dumps(plan())),plan())
        for field,value in (("schema_version",True),("deadline_seconds",True),("deadline_seconds",901),
                ("scope","login"),("output_parent","/private/other"),("control_sha256","bad"),
                ("known_hosts_path","/private/other")):
            changed = {**plan(),field:value}
            with self.subTest(field=field),self.assertRaises(ValueError):
                ui.schema(json.dumps(changed))
        for field in ("closure_qualified","seat_qualified","user_code","token","source_path"):
            with self.subTest(field=field),self.assertRaises(ValueError):
                ui.schema(json.dumps({**plan(),field:True}))
        with self.assertRaises(ValueError):
            ui.schema('{"schema_version":1,"schema_version":1}')

    def test_finite_inputs_independent_pins_system_manager_and_exclusive_scope(self):
        args = (["run",ui.LABEL],"system",Path("/private/prepare/input.json"),Path("/private/new-output"),False,("a"*64,"b"*64,"c"*64))
        ui.finite(*args)
        for index,value in ((1,"user"),(2,None),(3,None),(4,True),(5,())):
            changed = list(args)
            changed[index] = value
            with self.subTest(index=index),self.assertRaises(ValueError):
                ui.finite(*changed)
        with self.assertRaises(ValueError):
            ui.finite(*args,unrelated=(Path("/private/native"),))

    def test_one_exact_writable_output_and_immutable_input_binds(self):
        admitted = object.__new__(ui.Admission)
        admitted.namespace = Path("/private/prepare")
        admitted.output = Path("/private/output")
        admitted.agent_path = None
        actual = {"BindReadOnlyPaths":" ".join(admitted.bindings()),
            "BindPaths":admitted.writable_binding()}
        admitted.verify_bindings(actual)
        admitted.verify_bindings({key:value+":rbind" for key,value in actual.items()})
        for key,value in (("BindPaths",""),("BindPaths",actual["BindPaths"]+" /private/extra:/extra"),
                ("BindReadOnlyPaths",actual["BindReadOnlyPaths"]+":rw"),
                ("BindReadOnlyPaths",actual["BindReadOnlyPaths"]+" "+actual["BindReadOnlyPaths"])):
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                admitted.verify_bindings({**actual,key:value})

    def test_failure_projection_copies_private_bind_data_and_never_renders_error(self):
        actual = {"BindReadOnlyPaths":"/private/input:/fixed","BindPaths":"/private/output:/fixed"}
        projected = ui.projection(actual)
        self.assertNotIn("/private",json.dumps(projected))
        self.assertIn("/private",actual["BindPaths"])
        class PrivateError(OSError):
            def __str__(self):
                raise AssertionError("private selector rendered")
        self.assertEqual(ui.rejection(PrivateError(13,"private","/private/input")),"native-ui-prepare-refused")

    def test_real_owned_output_starts_empty_and_refuses_symlink_extra_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fd = os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            try:
                login.namespace_custody(os.fstat(fd))
                ui.members(fd,set())
                (root/"extra").write_bytes(b"public model")
                with self.assertRaises(ValueError):
                    ui.members(fd,set())
                (root/"extra").unlink()
                (root/"closure.json").symlink_to("outside")
                with self.assertRaises(ValueError):
                    ui.members(fd,ui.RECEIPTS)
                with self.assertRaises((ValueError,OSError)):
                    import guard_codex_live_profile as private
                    os.open("closure.json",os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
            finally:
                os.close(fd)

    def test_command_preserves_original_deadline_limits_and_namespace_authorities(self):
        admitted = mock.Mock(deadline=1234567890000,namespace_fd=21,output_fd=22)
        with mock.patch.object(guard.os,"fstat",side_effect=lambda fd:mock.Mock(st_dev=17,st_ino=fd)):
            command = guard.native_login_ui_command("/nix/store/bazel",Path("/private/run"),["run",ui.LABEL],admitted)
        for flag in ("--batch","--jobs=2","--host_jvm_args=-Xmx1536m","--spawn_strategy=linux-sandbox",
                "--sandbox_default_allow_network=false","--remote_cache=","--remote_executor=",
                "--run_env="+ui.VARIABLE+"="+ui.DESTINATION,
                "--run_env=OMUX_NATIVE_LOGIN_UI_NAMESPACE_ID=17:21",
                "--run_env=OMUX_NATIVE_LOGIN_UI_OUTPUT_ID=17:22",
                "--run_env=OMUX_NATIVE_LOGIN_UI_ORIGINAL_DEADLINE_NS=1234567890000"):
            self.assertIn(flag,command)
        self.assertEqual(command[-1],ui.LABEL)
        self.assertEqual(command.count("run"),1)
        self.assertNotIn("ssh-agent.sock"," ".join(command))

    def test_original_deadline_keeps_thirty_second_cleanup_reserve(self):
        admitted = object.__new__(ui.Admission)
        admitted.deadline = 1200*10**9
        with mock.patch.object(ui.time,"monotonic_ns",return_value=1100*10**9):
            self.assertEqual(admitted.runtime_seconds(),70)
        with mock.patch.object(ui.time,"monotonic_ns",return_value=1170*10**9):
            with self.assertRaises(ValueError):
                admitted.runtime_seconds()


    def test_measured_closure_and_seat_refuse_empty_flags_mismatched_remote_and_missing_eof(self):
        import copy
        names = sorted(ui.UI_ROOTS)+["/nix/store/"+("0"*29)+str(index).zfill(3)+"-model" for index in range(177)]
        rows = [{"path":path,"narHash":"sha256:"+"a"*64,"narSize":1,"references":[]} for path in names]
        rows[0]["narSize"] = 869166464-180
        remote = {name:"public-model" for name in login.REMOTE_FIELDS}
        remote.update(uid=1000,dialog_sha256="b"*64)
        closure = {"schema_version":1,"scope":"omux-native-login-ui-closure-v1","rows":rows,
            "verified_paths":181,"verified_nar_bytes":869166464,"destination_registration_verified":True,
            "destination_content_rehashed":True,"store_import_performed":False,"dialog_sha256":"b"*64,
            "source_inventory_sha256":ui.INVENTORY_SHA,"os_qualification_sha256":"a"*64}
        seat = {**remote,"schema_version":1,"scope":"omux-native-login-ui-seat-v1",
            "wayland_peer_pid":2001,"wayland_peer_uid":1000,"wayland_peer_start_ticks":5,
            "portal_owner_pid":2002,"portal_owner_start_ticks":6,"actual_dialog_ready":True,
            "actual_dialog_eof_clean_exit":True,"provider_request_performed":False,"portal_openuri_performed":False}
        rows_sha256 = hashlib.sha256(ui.canonical_rows(rows)).hexdigest()
        ui.measured_receipts(closure,seat,remote,"a"*64,"b"*64,rows_sha256)
        for change in ("empty_closure","empty_seat","missing_path","rehashed_false","import","source_pin","code",
                "missing_eof","peer_uid","remote_mismatch","portal_open","changed_row_same_count_and_total"):
            c,s = copy.deepcopy(closure),copy.deepcopy(seat)
            if change == "changed_row_same_count_and_total":
                c["rows"][0]["narHash"] = "sha256:"+"c"*64
            elif change == "empty_closure":
                c = {}
            elif change == "empty_seat":
                s = {}
            elif change == "missing_path":
                c["rows"].pop()
            elif change == "rehashed_false":
                c["destination_content_rehashed"] = False
            elif change == "import":
                c["store_import_performed"] = True
            elif change == "source_pin":
                c["source_inventory_sha256"] = "0"*64
            elif change == "code":
                s["user_code"] = "MODEL"
            elif change == "missing_eof":
                s["actual_dialog_eof_clean_exit"] = False
            elif change == "peer_uid":
                s["wayland_peer_uid"] = 1001
            elif change == "remote_mismatch":
                s["python_sha256"] = "different-public-pin"
            else:
                s["portal_openuri_performed"] = True
            with self.subTest(change=change),self.assertRaises(ValueError):
                ui.measured_receipts(c,s,remote,"a"*64,"b"*64,rows_sha256)


    def test_authoritative_inventory_projection_is_derived_from_independently_pinned_bytes(self):
        selected = sorted(ui.UI_ROOTS)+["/nix/store/"+("0"*29)+str(index).zfill(3)+"-selected-model" for index in range(177)]
        unused = ["/nix/store/"+("1"*29)+str(index).zfill(3)+"-unused-model" for index in range(291)]
        rows = [{"path":name,"narHash":"sha256:"+"a"*64,"narSize":1,"references":[]} for name in selected+unused]
        rows[0]["narSize"] = 869166464-180
        rows[0]["references"] = selected[4:]
        raw = json.dumps({"schemaVersion":1,"roots":sorted(ui.UI_ROOTS),"paths":rows}).encode()
        pin = hashlib.sha256(raw).hexdigest()
        projected = ui.selected_inventory_rows(raw,pin)
        self.assertEqual([row["path"] for row in projected],sorted(selected))
        self.assertEqual(sum(row["narSize"] for row in projected),869166464)
        changed = raw.replace(("sha256:"+"a"*64).encode(),("sha256:"+"b"*64).encode(),1)
        with self.assertRaises(ValueError):
            ui.selected_inventory_rows(changed,pin)
        with self.assertRaises(ValueError):
            ui.selected_inventory_rows(raw)

if __name__ == "__main__":
    unittest.main()
