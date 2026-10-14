"""Device-only Yoga UI: private code frame, one owned dialog, existing portal.

No callback forwarding, auth files, browser automation or private frame output.
The controller joins the exact new dialog to the qualified locked UI closure.
"""
import ctypes as C
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import select
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import urllib.parse
import uuid
import xml.etree.ElementTree as ET

MAX_LINE = 16384
SHA = re.compile(r"[0-9a-f]{64}")
STORE = re.compile(r"/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[A-Za-z0-9+._?=-]+/[A-Za-z0-9+._?=@/-]+")


class Refusal(ValueError):
    pass


def require(value, reason):
    if not value:
        raise Refusal(reason)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "configuration_invalid")
        result[key] = value
    return result


def read_line(fd, until, maximum=MAX_LINE, allow_eof=False, stop=None):
    """One byte at a time prevents consuming the following private frame."""
    data = bytearray()
    while time.monotonic() < until:
        require(stop is None or not stop.is_set(), "private_channel_stopped")
        ready, _, _ = select.select([fd], [], [], min(.2, max(0, until-time.monotonic())))
        if not ready:
            continue
        piece = os.read(fd, 1)
        if not piece:
            require(allow_eof and not data, "private_channel_closed")
            return None
        if piece == b"\n":
            return bytes(data)
        data.extend(piece)
        require(len(data) <= maximum, "private_frame_bound")
    raise Refusal("worker_deadline")


def selection(value):
    fields = {"python_path", "python_sha256", "gio_path", "gio_sha256", "uid",
        "machine_id_sha256", "boot_id_sha256", "wayland_socket", "wayland_device",
        "wayland_inode", "closure_qualified", "seat_qualified", "dialog_path", "dialog_sha256",
        "qt_platform_plugin", "qt_platform_plugin_sha256", "deadline_seconds"}
    require(type(value) is dict and set(value) == fields, "configuration_invalid")
    require(value["closure_qualified"] is True and value["seat_qualified"] is True, "independent_qualification_required")
    for name in ("python_sha256", "gio_sha256", "machine_id_sha256", "boot_id_sha256", "dialog_sha256", "qt_platform_plugin_sha256"):
        require(type(value[name]) is str and SHA.fullmatch(value[name]), "input_pin_invalid")
    for name in ("python_path", "gio_path", "qt_platform_plugin"):
        require(type(value[name]) is str and STORE.fullmatch(value[name]) and ".." not in Path(value[name]).parts
                and str(Path(value[name])) == value[name], "input_selector_invalid")
    require(type(value["dialog_path"]) is str and value["dialog_path"].startswith("/")
        and ".." not in Path(value["dialog_path"]).parts and str(Path(value["dialog_path"])) == value["dialog_path"], "dialog_selector_invalid")
    require(type(value["uid"]) is int and value["uid"] == os.getuid() and value["uid"] > 0, "seat_identity_changed")
    require(type(value["deadline_seconds"]) is int and 1 <= value["deadline_seconds"] <= 900, "worker_deadline")
    require(type(value["wayland_socket"]) is str and re.fullmatch(r"/run/user/"+str(value["uid"])+r"/wayland-[0-9]{1,3}", value["wayland_socket"]), "seat_selector_invalid")
    for name in ("wayland_device", "wayland_inode"):
        require(type(value[name]) is int and value[name] > 0, "seat_selector_invalid")
    return value


def held_immutable(path, expected, maximum):
    """Hold exact canonical root-owned Nix input; closure qualification is prior."""
    require(str(Path(path).resolve(strict=True)) == path, "input_selector_not_canonical")
    parents = [os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)]
    fd = None
    try:
        walked = Path("/")
        for part in Path(path).parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parents[-1])
            parents.append(child)
            walked /= part
            info = os.fstat(child)
            sticky_store = walked == Path("/nix/store") and stat.S_IMODE(info.st_mode) == 0o1775
            require(info.st_uid == 0 and (not info.st_mode & 0o022 or sticky_store), "immutable_ancestor_custody")
            if walked.is_relative_to("/nix/store") and walked != Path("/nix/store"):
                require(not info.st_mode & 0o222, "immutable_ancestor_custody")
        fd = os.open(Path(path).name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parents[-1])
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == 0 and not before.st_mode & 0o222
            and 0 < before.st_size <= maximum, "immutable_input_custody")
        count, digest = 0, hashlib.sha256()
        while count < before.st_size:
            part = os.pread(fd, min(65536, before.st_size-count), count)
            require(bool(part), "immutable_input_changed")
            count += len(part)
            digest.update(part)
        witness = lambda s: (s.st_dev,s.st_ino,s.st_uid,s.st_mode,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        require(digest.hexdigest() == expected and witness(before) == witness(os.fstat(fd))
            == witness(os.stat(Path(path).name, dir_fd=parents[-1], follow_symlinks=False)), "immutable_input_pin_differs")
        result, fd = fd, None
        return result
    finally:
        if fd is not None:
            os.close(fd)
        for parent in reversed(parents):
            os.close(parent)


def check_host_and_seat(value):
    for path, key in (("/etc/machine-id", "machine_id_sha256"),
        ("/proc/sys/kernel/random/boot_id", "boot_id_sha256")):
        with open(path, "rb") as source:
            data = source.read(4097)
        require(0 < len(data) <= 4096 and hashlib.sha256(data).hexdigest() == value[key], "host_identity_changed")
    info = os.stat(value["wayland_socket"], follow_symlinks=False)
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == value["uid"]
        and (info.st_dev, info.st_ino) == (value["wayland_device"], value["wayland_inode"]), "seat_identity_changed")
    parent = os.stat("/run/user/"+str(value["uid"]), follow_symlinks=False)
    require(stat.S_ISDIR(parent.st_mode) and parent.st_uid == value["uid"]
        and stat.S_IMODE(parent.st_mode) == 0o700, "seat_identity_changed")


def uri_bytes(value):
    require(value == b"https://auth.openai.com/codex/device", "native_uri_invalid")
    return value


def device_frame(data):
    require(type(data) is bytes and 0 < len(data) <= 4096, "device_frame_invalid")
    try:
        value = json.loads(data,object_pairs_hook=unique)
        require(type(value) is dict and set(value) == {"verification_url","user_code"}, "device_frame_invalid")
        uri_bytes(value["verification_url"].encode("ascii"))
        code = value["user_code"]
        require(type(code) is str and 1 <= len(code) <= 128 and all(0x21 <= ord(c) < 0x7f for c in code), "device_frame_invalid")
        require(json.dumps(value,sort_keys=True,separators=(",",":")).encode("ascii") == data, "device_frame_invalid")
    except (ValueError,TypeError,KeyError,UnicodeError):
        raise Refusal("device_frame_invalid") from None
    return value


def portal_interface(data):
    require(type(data) is bytes and 0 < len(data) <= 65536 and b"<!ENTITY" not in data, "portal_interface_unavailable")
    try:
        node = ET.fromstring(data)
    except ET.ParseError:
        raise Refusal("portal_interface_unavailable") from None
    interfaces = [item for item in node.findall("interface") if item.get("name") == "org.freedesktop.portal.OpenURI"]
    require(len(interfaces) == 1,"portal_interface_unavailable")
    methods = [item for item in interfaces[0].findall("method") if item.get("name") == "OpenURI"]
    require(len(methods) == 1 and [(item.get("direction","in"),item.get("type")) for item in methods[0].findall("arg")]
        == [("in","s"),("in","s"),("in","a{sv}"),("out","o")],"portal_interface_unavailable")


class Portal:
    def __init__(self, library, uid):
        self.gio = C.CDLL("/proc/self/fd/"+str(library))
        self.connection = None
        self.error = C.c_void_p()
        functions = {
            "g_dbus_connection_new_for_address_sync": (C.c_void_p,[C.c_char_p,C.c_int,C.c_void_p,C.c_void_p,C.POINTER(C.c_void_p)]),
            "g_dbus_connection_get_stream": (C.c_void_p,[C.c_void_p]),
            "g_socket_connection_get_socket": (C.c_void_p,[C.c_void_p]), "g_socket_get_fd": (C.c_int,[C.c_void_p]),
            "g_dbus_connection_call_sync": (C.c_void_p,[C.c_void_p,C.c_char_p,C.c_char_p,C.c_char_p,C.c_char_p,C.c_void_p,C.c_void_p,C.c_int,C.c_int,C.c_void_p,C.POINTER(C.c_void_p)]),
            "g_variant_type_new": (C.c_void_p,[C.c_char_p]), "g_variant_type_free": (None,[C.c_void_p]),
            "g_variant_new": (C.c_void_p,[C.c_char_p]),
            "g_variant_new_array": (C.c_void_p,[C.c_void_p,C.POINTER(C.c_void_p),C.c_size_t]),
            "g_variant_get_child_value": (C.c_void_p,[C.c_void_p,C.c_size_t]),
            "g_variant_get_size": (C.c_size_t,[C.c_void_p]),
            "g_variant_get_string": (C.c_char_p,[C.c_void_p,C.POINTER(C.c_size_t)]),
            "g_variant_get_uint32": (C.c_uint32,[C.c_void_p]), "g_variant_unref": (None,[C.c_void_p]),
            "g_error_free": (None,[C.c_void_p]), "g_object_unref": (None,[C.c_void_p]),
            "g_dbus_connection_close_sync": (C.c_int,[C.c_void_p,C.c_void_p,C.POINTER(C.c_void_p)])}
        for name, (restype,args) in functions.items():
            function = getattr(self.gio,name)
            function.restype, function.argtypes = restype,args
        address = ("unix:path=/run/user/"+str(uid)+"/bus").encode()
        endpoint = "/run/user/"+str(uid)+"/bus"
        info = os.stat(endpoint, follow_symlinks=False)
        require(stat.S_ISSOCK(info.st_mode) and info.st_uid == uid, "desktop_bus_custody")
        self.connection = self.gio.g_dbus_connection_new_for_address_sync(address,9,None,None,C.byref(self.error))
        self.check(self.connection, "desktop_bus_unavailable")
        try:
            self.check_stream_peer(uid)
            self.owner = self.call(b"org.freedesktop.DBus",b"/org/freedesktop/DBus",b"org.freedesktop.DBus",
                b"GetNameOwner",self.gio.g_variant_new(b"(s)",C.c_char_p(b"org.freedesktop.portal.Desktop")),b"(s)","string")
            require(type(self.owner) is bytes and re.fullmatch(rb":[0-9]+\.[0-9]+",self.owner), "portal_owner_invalid")
            owner_uid = self.bus_uint(b"GetConnectionUnixUser")
            require(owner_uid == uid, "portal_owner_mismatch")
            self.pid = self.bus_uint(b"GetConnectionUnixProcessID")
            require(self.pid > 0 and os.stat("/proc/"+str(self.pid)).st_uid == uid, "portal_owner_mismatch")
            self.start_ticks = self.pid_start()
            interface = self.call(self.owner,b"/org/freedesktop/portal/desktop",b"org.freedesktop.DBus.Introspectable",
                b"Introspect",None,b"(s)","string")
            portal_interface(interface)
        except BaseException:
            self.close()
            raise

    def check_stream_peer(self, uid):
        stream = self.gio.g_dbus_connection_get_stream(self.connection)
        self.check(stream,"desktop_bus_stream_unavailable")
        connected = self.gio.g_socket_connection_get_socket(stream)
        self.check(connected,"desktop_bus_stream_unavailable")
        descriptor = self.gio.g_socket_get_fd(connected)
        require(descriptor >= 0,"desktop_bus_stream_unavailable")
        with socket.socket(fileno=os.dup(descriptor)) as channel:
            require(channel.family == socket.AF_UNIX,"desktop_bus_peer_mismatch")
            _, peer_uid, _ = struct.unpack("3i",channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            require(peer_uid == uid,"desktop_bus_peer_mismatch")

    def check(self, value, reason):
        if not value:
            if self.error.value:
                self.gio.g_error_free(self.error)
                self.error = C.c_void_p()
            raise Refusal(reason)

    def call(self, destination,path,interface,method,parameters,reply_type,kind):
        selected = self.gio.g_variant_type_new(reply_type)
        result = None
        child = None
        try:
            result = self.gio.g_dbus_connection_call_sync(self.connection,destination,path,interface,method,
                parameters,selected,1,5000,None,C.byref(self.error))
            self.check(result,"portal_call_refused")
            require(self.gio.g_variant_get_size(result) <= 65536,"portal_reply_bound")
            child = self.gio.g_variant_get_child_value(result,0)
            self.check(child,"portal_reply_invalid")
            return (self.gio.g_variant_get_string(child,None) if kind == "string"
                else int(self.gio.g_variant_get_uint32(child)))
        finally:
            if child:
                self.gio.g_variant_unref(child)
            if result:
                self.gio.g_variant_unref(result)
            self.gio.g_variant_type_free(selected)

    def bus_uint(self, method):
        return self.call(b"org.freedesktop.DBus",b"/org/freedesktop/DBus",b"org.freedesktop.DBus",method,
            self.gio.g_variant_new(b"(s)",C.c_char_p(self.owner)),b"(u)","uint")

    def pid_start(self):
        with open("/proc/"+str(self.pid)+"/stat","r",encoding="ascii") as source:
            data = source.read(8193)
        require(len(data) <= 8192 and ")" in data, "portal_owner_invalid")
        fields = data[data.rfind(")")+2:].split()
        require(len(fields) >= 20 and fields[19].isdigit(), "portal_owner_invalid")
        return int(fields[19])

    def open_uri(self, private_uri):
        uri = uri_bytes(private_uri)
        require(self.pid_start() == self.start_ticks and self.bus_uint(b"GetConnectionUnixUser") == os.getuid()
            and self.bus_uint(b"GetConnectionUnixProcessID") == self.pid, "portal_owner_changed")
        entry = self.gio.g_variant_type_new(b"{sv}")
        try:
            options = self.gio.g_variant_new_array(entry,None,0)
        finally:
            self.gio.g_variant_type_free(entry)
        parameters = self.gio.g_variant_new(b"(ss@a{sv})",C.c_char_p(b""),C.c_char_p(uri),C.c_void_p(options))
        request = self.call(self.owner,b"/org/freedesktop/portal/desktop",b"org.freedesktop.portal.OpenURI",
            b"OpenURI",parameters,b"(o)","string")
        require(type(request) is bytes and request.startswith(b"/org/freedesktop/portal/desktop/request/"), "portal_reply_invalid")
        # Request acceptance is metadata, not proof of browser opening or consent.

    def close(self):
        if self.connection:
            connection, self.connection = self.connection, None
            try:
                self.gio.g_dbus_connection_close_sync(connection,None,C.byref(self.error))
                if self.error.value:
                    self.gio.g_error_free(self.error)
                    self.error = C.c_void_p()
            finally:
                self.gio.g_object_unref(connection)


def held_dialog(path,expected):
    require(str(Path(path).resolve(strict=True)) == path,"dialog_selector_not_canonical")
    fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
            and stat.S_IMODE(before.st_mode) == 0o500 and before.st_nlink == 1
            and 0 < before.st_size <= 128*1024*1024,"dialog_custody_invalid")
        digest,count = hashlib.sha256(),0
        while count < before.st_size:
            data = os.pread(fd,min(65536,before.st_size-count),count)
            require(bool(data),"dialog_changed")
            digest.update(data)
            count += len(data)
        witness = lambda s: (s.st_dev,s.st_ino,s.st_uid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
        require(digest.hexdigest() == expected and witness(before) == witness(os.fstat(fd))
            == witness(os.stat(path,follow_symlinks=False)),"dialog_pin_differs")
        result,fd = fd,None
        return result
    finally:
        if fd is not None:
            os.close(fd)


QT_LIBRARY_DIRECTORY = "/nix/store/1q8sx67miwfn3ws5k7mkmkcjbym4akkp-qtbase-6.11.0/lib"
DIALOG_LIBRARY_DIRECTORIES = (QT_LIBRARY_DIRECTORY,
    "/nix/store/fdqacryg2w9kiwb94c9rzfsyff4im8xj-libglvnd-1.7.0/lib",
    "/nix/store/n1ykqk7ibmp4h5r4x5fng4cn9wjlgj9y-libxext-1.3.7/lib")
FONT_DIRECTORY = "/nix/store/0wcl9csd4li3na9z59j7g1igf2c1iz33-dejavu-fonts-minimal-2.37/share/fonts/truetype"


class DialogRuntime:
    """Fresh empty HOME plus sealed public-only font selection, never user config."""
    def __init__(self,config):
        self.parent = self.home = self.fonts = None
        self.name = self.identity = None
        parent = Path(config["dialog_path"]).parent
        require(parent.is_absolute() and parent.resolve(strict=True) == parent,"dialog_runtime_selector")
        try:
            self.parent = os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            info = os.fstat(self.parent)
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,"dialog_runtime_custody")
            name = "home-"+str(uuid.uuid4())
            os.mkdir(name,0o700,dir_fd=self.parent)
            self.name = name
            info = os.stat(name,dir_fd=self.parent,follow_symlinks=False)
            self.identity = info.st_dev,info.st_ino
            self.home = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.parent)
            info = os.fstat(self.home)
            require((info.st_dev,info.st_ino) == self.identity,"dialog_runtime_changed")
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,"dialog_runtime_custody")
            self.fonts = os.memfd_create("omux-public-font-selection",os.MFD_CLOEXEC|os.MFD_ALLOW_SEALING)
            payload = ('<?xml version="1.0"?><fontconfig><dir>'+FONT_DIRECTORY+'</dir></fontconfig>').encode("ascii")
            require(os.write(self.fonts,payload) == len(payload),"dialog_font_selection_refused")
            fcntl.fcntl(self.fonts,fcntl.F_ADD_SEALS,fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL)
            self.environment = {"LANG":"C","LC_ALL":"C","PATH":"",
                "HOME":str(parent/self.name),"XDG_CONFIG_HOME":str(parent/self.name/"config"),
                "XDG_DATA_HOME":str(parent/self.name/"data"),"XDG_STATE_HOME":str(parent/self.name/"state"),
                "XDG_CACHE_HOME":str(parent/self.name/"cache"),"XDG_CONFIG_DIRS":"/.omux-native-login-unavailable",
                "XDG_DATA_DIRS":"/.omux-native-login-unavailable","FONTCONFIG_FILE":"/proc/self/fd/"+str(self.fonts),
                "FONTCONFIG_PATH":"/.omux-native-login-unavailable","LD_LIBRARY_PATH":":".join(DIALOG_LIBRARY_DIRECTORIES),
                "XDG_RUNTIME_DIR":"/run/user/"+str(config["uid"]),"WAYLAND_DISPLAY":config["wayland_socket"],
                "QT_QPA_PLATFORM":"wayland","QT_STYLE_OVERRIDE":"Fusion","QT_QPA_PLATFORMTHEME":"",
                "QT_PLUGIN_PATH":str(Path(config["qt_platform_plugin"]).parent.parent),
                "QT_QPA_PLATFORM_PLUGIN_PATH":str(Path(config["qt_platform_plugin"]).parent),
                "QT_LOGGING_RULES":"*.debug=false;*.info=false;*.warning=false;*.critical=false"}
        except BaseException:
            self.close()
            raise

    def close(self):
        failure = None
        try:
            if self.name is not None:
                current = os.stat(self.name,dir_fd=self.parent,follow_symlinks=False)
                require(self.identity is not None and (current.st_dev,current.st_ino) == self.identity
                    and current.st_uid == os.getuid() and stat.S_IMODE(current.st_mode) == 0o700,"dialog_runtime_changed")
                if self.home is not None:
                    held = os.fstat(self.home)
                    require((held.st_dev,held.st_ino) == self.identity,"dialog_runtime_changed")
                try:
                    os.rmdir(self.name,dir_fd=self.parent)
                except OSError:
                    raise Refusal("dialog_runtime_not_empty") from None
        except BaseException as error:
            failure = error
        for name in ("fonts","home","parent"):
            fd = getattr(self,name)
            setattr(self,name,None)
            if fd is not None:
                try:
                    os.close(fd)
                except BaseException as error:
                    failure = failure or error
        self.name = None
        if isinstance(failure,Refusal):
            raise failure from None
        require(failure is None,"dialog_runtime_cleanup_incomplete")


class Dialog:
    def __init__(self,executable,config,until):
        self.process = self.pidfd = None
        self.runtime = None
        self.until = until
        require(hasattr(os,"pidfd_open") and hasattr(signal,"pidfd_send_signal"),"dialog_pidfd_required")
        # This constructor precedes Portal/GIO initialization: fork happens
        # before GIO can create threads. Parent death closes only our dialog.
        libc = C.CDLL(None)
        libc.prctl.argtypes = [C.c_int,C.c_ulong,C.c_ulong,C.c_ulong,C.c_ulong]
        libc.prctl.restype = C.c_int
        owner = os.getpid()
        def owned_child():
            if libc.prctl(1,signal.SIGTERM,0,0,0) != 0 or os.getppid() != owner:
                os._exit(1)
        try:
            self.runtime = DialogRuntime(config)
            self.process = subprocess.Popen(["/proc/self/fd/"+str(executable),"--native-device-login-stdin"],
                executable="/proc/self/fd/"+str(executable),pass_fds=(executable,self.runtime.fonts),
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
                env=self.runtime.environment,umask=0o077,preexec_fn=owned_child)
            self.pidfd = os.pidfd_open(self.process.pid)
            require(read_line(self.process.stdout.fileno(),min(until,time.monotonic()+30),128)
                == b"OMUX_NATIVE_DEVICE_DIALOG_READY","dialog_not_ready")
        except BaseException:
            self.close()
            raise

    def is_set(self):
        return self.process.poll() is not None

    def present(self,frame):
        require(not self.is_set(),"dialog_closed")
        fd = self.process.stdin.fileno()
        os.set_blocking(fd,False)
        offset = 0
        until = min(self.until,time.monotonic()+30)
        while offset < len(frame)+1 and time.monotonic() < until:
            require(not self.is_set(),"dialog_closed")
            _,ready,_ = select.select([],[fd],[],min(.2,max(0,until-time.monotonic())))
            if ready:
                try:
                    count = os.write(fd,(frame+b"\n")[offset:])
                except BlockingIOError:
                    continue
                require(count > 0,"dialog_channel_closed")
                offset += count
        require(offset == len(frame)+1,"dialog_channel_deadline")
        require(read_line(self.process.stdout.fileno(),until,128)
            == b"OMUX_NATIVE_DEVICE_DIALOG_DISPLAYED","dialog_not_displayed")

    def close(self,success=False):
        process,self.process = self.process,None
        failure = None
        reaped = process is None
        if process is not None:
            try:
                if process.stdin is not None:
                    process.stdin.close()
            except BrokenPipeError:
                pass
            except BaseException as error:
                failure = error
            try:
                process.wait(timeout=5)
                reaped = True
            except subprocess.TimeoutExpired:
                pass
            except BaseException as error:
                failure = failure or error
            if not reaped:
                for sig in (signal.SIGTERM,signal.SIGKILL):
                    try:
                        if self.pidfd is not None:
                            signal.pidfd_send_signal(self.pidfd,sig)
                        elif process.poll() is None:
                            process.send_signal(sig)
                    except ProcessLookupError:
                        pass
                    except BaseException as error:
                        failure = failure or error
                    try:
                        process.wait(timeout=5)
                        reaped = True
                        break
                    except subprocess.TimeoutExpired:
                        pass
                    except BaseException as error:
                        failure = failure or error
            try:
                process.stdout.close()
            except BaseException as error:
                failure = failure or error
        pidfd,self.pidfd = self.pidfd,None
        if pidfd is not None:
            try:
                os.close(pidfd)
            except BaseException as error:
                failure = failure or error
        runtime,self.runtime = getattr(self,"runtime",None),None
        if runtime is not None:
            try:
                runtime.close()
            except BaseException as error:
                failure = failure or error
        require(reaped and failure is None,"owned_dialog_cleanup_incomplete")
        if success and process is not None:
            require(process.returncode == 0,"dialog_cancelled")

def main():
    config = selection(json.loads(read_line(0,time.monotonic()+30),object_pairs_hook=unique))
    os.environ.clear()
    os.environ.update({"LANG":"C","LC_ALL":"C","PATH":"","GIO_USE_VFS":"local",
        "GIO_MODULE_DIR":"/.omux-native-login-unavailable","GIO_EXTRA_MODULES":""})
    signal.alarm(config["deadline_seconds"]+15)
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
    until = time.monotonic()+config["deadline_seconds"]
    python = gio = executable = plugin = None
    portal = dialog = None
    try:
        require(str(Path("/proc/self/exe").resolve(strict=True)) == config["python_path"], "interpreter_pin_differs")
        python = held_immutable(config["python_path"],config["python_sha256"],128*1024*1024)
        gio = held_immutable(config["gio_path"],config["gio_sha256"],128*1024*1024)
        plugin = held_immutable(config["qt_platform_plugin"],config["qt_platform_plugin_sha256"],128*1024*1024)
        executable = held_dialog(config["dialog_path"],config["dialog_sha256"])
        check_host_and_seat(config)
        dialog = Dialog(executable,config,until)
        portal = Portal(gio,config["uid"])
        print(json.dumps({"scope":"omux-yoga-portal-ready-v1","uid":config["uid"],
            "portal_owner_pid":portal.pid,"portal_owner_start_ticks":portal.start_ticks,
            "owned_dialog_pid":dialog.process.pid,"dialog_available":True,"portal_available":True},sort_keys=True),flush=True)
        frame = read_line(0,until,4096,allow_eof=True,stop=dialog)
        if frame is None:
            # Provider-free transport readiness/EOF exercise: no OpenURI call.
            dialog.close(success=True)
            return 0
        prompt = device_frame(frame)
        check_host_and_seat(config)
        dialog.present(frame)
        frame = None
        portal.open_uri(prompt["verification_url"].encode("ascii"))
        prompt = None
        print('{"scope":"omux-yoga-portal-requested-v1","uri_requested":true}',flush=True)
        require(read_line(0,until,16,allow_eof=True,stop=dialog) is None,"unexpected_private_frame")
        dialog.close(success=True)
        return 0
    finally:
        failure = None
        for release in ([dialog.close] if dialog is not None else []) + (
                [portal.close] if portal is not None else []) + [
                lambda fd=fd: os.close(fd) for fd in (executable,plugin,gio,python) if fd is not None]:
            try:
                release()
            except BaseException as error:
                failure = failure or error
        require(failure is None,"owned_portal_cleanup_incomplete")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        # Native GError strings, source selectors and URI bytes stay private.
        print('{"scope":"omux-yoga-portal-refused-v1","reason":"portal_transport_refused"}',file=sys.stderr)
        sys.exit(1)
