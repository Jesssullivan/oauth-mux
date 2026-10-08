"""Contained native OAuth setup with an in-process private desktop URI carrier."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import stat
import sys
import time
import pwd
import native_login_enrollment_selector as enrollment_selector
import native_account_login as core

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", required=True)
    parser.add_argument("--source-receipt", required=True)
    parser.add_argument("--portal-worker", required=True)
    parser.add_argument("--loader", required=True)
    parser.add_argument("--ca-bundle", required=True)
    args = parser.parse_args()
    # The argument is a declared logical RUNFILES path. Do not resolve the
    # symlinked main/worker and accidentally import undeclared source modules.
    sys.path.insert(0, str(Path(args.portal_worker).parent))
    import guard_codex_login_profile as profile
    import guard_codex_live_profile as inputs
    from yoga_portal_carrier import YogaPortalCarrier
    core.require(os.environ.get(profile.VARIABLE) == profile.DESTINATION,
                 "contained_manifest_selector_required")
    deadline = os.environ.get("OMUX_NATIVE_LOGIN_ORIGINAL_DEADLINE_NS", "")
    core.require(deadline.isascii() and deadline.isdecimal() and len(deadline) <= 20,
                 "original_deadline_required")
    until = (int(deadline) - 30 * 10**9) / 10**9
    core.require(0 < until - time.monotonic() <= 1200, "original_deadline_expired")
    with ExitStack() as custody:
        namespace = os.open("/omux-native-login", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        custody.callback(os.close, namespace)
        namespace_info = os.fstat(namespace)
        profile.namespace_custody(namespace_info)
        namespace_identity = inputs.identity(namespace_info)
        core.require(profile.namespace_id(namespace_info) == os.environ.get("OMUX_NATIVE_LOGIN_NAMESPACE_ID"),
                     "held_namespace_authority_required")
        fd = inputs.open_private(Path(profile.DESTINATION), 65536, read=True)
        custody.callback(os.close, fd)
        before = inputs.identity(os.fstat(fd))
        raw = os.pread(fd, 65537, 0)
        core.require(len(raw) == before[5] and inputs.identity(os.fstat(fd)) == before,
                     "manifest_changed")
        config = profile.schema(raw)
        core.require(config["schema_version"] == 2, "enrollment_selector_required")
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        enrollment_selector.validate_template(config["enrollment"],home)
        profile.namespace_membership(namespace, config["ui"]["ssh_auth_socket"] is not None)
        until = min(until, time.monotonic() + config["deadline_seconds"])
        native_fd = core.hold_input(args.codex, config["native_sha256"], 600*1024*1024, True)
        custody.callback(os.close, native_fd)
        receipt_fd = core.hold_input(args.source_receipt, config["source_receipt_sha256"], 16*1024*1024)
        custody.callback(os.close, receipt_fd)
        qualified = json.loads(os.pread(receipt_fd,16*1024*1024+1,0),object_pairs_hook=core.unique_object)
        profile.device_qualification(qualified)
        native_directory = Path(args.codex).resolve(strict=True).parent
        loader_path = Path(args.loader).resolve(strict=True)
        ca_path = Path(args.ca_bundle).resolve(strict=True)
        core.require(loader_path == native_directory / "runtime/lib/codex/lib/ld-linux-x86-64.so.2"
            and ca_path == native_directory / "runtime/lib/codex/share/ca-bundle.crt",
            "declared_runtime_layout_required")
        loader_pin,loader_bytes,_ = profile.RUNTIME_FILES["lib/codex/lib/ld-linux-x86-64.so.2"]
        loader_fd = core.hold_input(str(loader_path),loader_pin,loader_bytes)
        custody.callback(os.close,loader_fd)
        ca_pin,ca_bytes,_ = profile.RUNTIME_FILES["lib/codex/share/ca-bundle.crt"]
        ca_fd = core.hold_input(str(ca_path),ca_pin,ca_bytes)
        custody.callback(os.close,ca_fd)
        executable_identities = [(held,inputs.identity(os.fstat(held)))
            for held in (native_fd,loader_fd,ca_fd,receipt_fd)]
        ui_selection = dict(config["ui"])
        ui_selection["qualification_path"] = profile.QUALIFICATION_DESTINATION
        carrier = YogaPortalCarrier(ui_selection, until, args.portal_worker)
        custody.callback(carrier.close)
        # Qualified private dialog/portal readiness precedes native device login.
        # This descriptor did not exist during Bazel's launcher.
        ui = core.private_ui(carrier.open())
        custody.callback(os.close, ui)
        handle, root, root_fd = core.profile(config["state_parent"])
        custody.callback(os.close, root_fd)
        print(json.dumps({"scope":"omux-native-login-started-v1", "profile_handle":handle,
            "identity_verified":False, "native_support":False}, sort_keys=True), flush=True)
        environment = {"LANG":"C.UTF-8", "LC_ALL":"C.UTF-8", "PATH":"/nonexistent",
                       "CODEX_HOME":str(root), "HOME":str(root), "RUST_LOG":"off",
                       "SSL_CERT_FILE":str(ca_path), "CURL_CA_BUNDLE":str(ca_path)}
        for name in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME", "XDG_RUNTIME_DIR"):
            child = name.lower()
            os.mkdir(child, 0o700, dir_fd=root_fd)
            environment[name] = str(root / child)
        core.require(time.monotonic() < until, "original_deadline_expired")
        core.require(carrier.failure is None and carrier.process is not None
                     and carrier.process.poll() is None, "private_ui_transport_unavailable")
        core.require(all(inputs.identity(os.fstat(held)) == identity
            for held,identity in executable_identities), "declared_runtime_changed")
        native = core.Native(native_fd, environment, root, loader_fd=loader_fd,
                             library_path=str(loader_path.parent))
        custody.callback(native.close)
        core.device_login(native, ui, until, healthy=lambda:
            carrier.failure is None and carrier.process is not None and carrier.process.poll() is None)
        auth = os.stat("auth.json", dir_fd=root_fd, follow_symlinks=False)
        core.require(stat.S_ISREG(auth.st_mode) and auth.st_uid == os.getuid()
                     and stat.S_IMODE(auth.st_mode) == 0o600 and auth.st_nlink == 1,
                     "native_auth_custody")
        native.close()
        # The accepted UI reply may trail the native completion notification.
        while not carrier.requested.is_set() and carrier.failure is None and time.monotonic() < until:
            carrier.requested.wait(min(.2, max(0, until-time.monotonic())))
        carrier.close(success=True)
        core.require(inputs.identity(os.fstat(namespace)) == namespace_identity
            and inputs.identity(os.stat("/omux-native-login", follow_symlinks=False)) == namespace_identity,
                     "private_namespace_changed")
        profile.namespace_membership(namespace, config["ui"]["ssh_auth_socket"] is not None)
        core.require(inputs.identity(os.fstat(fd)) == before
            and inputs.identity(os.stat(profile.DESTINATION, follow_symlinks=False)) == before
            and os.pread(fd, 65537, 0) == raw, "manifest_changed")
        enrollment_selector.publish(config["enrollment"],root,root_fd,home,
            min(int(deadline)-30*10**9,int(until*10**9)))
        print(json.dumps({"scope":"omux-native-login-v1", "profile_handle":handle,
            "native_login_completed":True, "enrollment_selector_ready":True,
            "resident_enrollment_completed":False, "identity_verified":False,
            "renewal_owner":"native", "native_support":False}, sort_keys=True), flush=True)
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except (Exception, KeyboardInterrupt):
        # No exception string, native protocol frame, URL or private path.
        print('{"scope":"omux-native-login-refused-v1","reason":"contained_setup_action_failed"}',
              file=sys.stderr)
        sys.exit(125)
