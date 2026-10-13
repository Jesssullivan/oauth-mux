"""Typed existing-vault namespace; original enrollment admission remains separate."""
import hashlib
import base64
import json
import os
from pathlib import Path
import pwd
import re
import stat
import socket
import struct
import time
import guard_resident_enrollment_profile as resident

LABEL = "//delivery:resident_vault_metadata"
UNLOCK_LABEL = "//delivery:resident_vault_unlock"
STANDARD_LABEL = "//delivery:resident_standard_vault_metadata"
STANDARD_UNLOCK_LABEL = "//delivery:resident_standard_vault_unlock"
LABELS = (LABEL,UNLOCK_LABEL,STANDARD_LABEL,STANDARD_UNLOCK_LABEL)
DESTINATION = resident.DESTINATION
VARIABLE = "OMUX_RESIDENT_VAULT_MANIFEST"
DEADLINE_VARIABLE = resident.DEADLINE_VARIABLE
PROOF_MEMORY,PROOF_TASKS,PROOF_CPU_PERCENT = resident.PROOF_MEMORY,resident.PROOF_TASKS,resident.PROOF_CPU_PERCENT
GNOME_EXE = "/nix/store/x1199bxd4ia75dd1nmh0xnnpfzxz1785-gnome-keyring-48.0/bin/.gnome-keyring-daemon-wrapped"
def require(value):
    if not value:
        raise ValueError("resident-vault-admission-refused")
def finite(arguments,manager,manifest,reuse,unrelated=()):
    require(arguments in tuple(["run",label] for label in LABELS) and manager=="system"
        and manifest is not None and not reuse and not any(unrelated))
    return {"PrivateNetwork":"yes","ProtectSystem":"strict","PrivateTmp":"yes"}
def rejection(error):
    return "resident-vault-admission-refused"
def projection(actual,verified=False):
    result=dict(actual)
    result["BindReadOnlyPaths"]="verified-vault-metadata-inputs" if verified else "vault-inputs-redacted"
    result["BindPaths"]="verified-owned-proof-output" if verified else "vault-output-redacted"
    return result
def identity(info):
    return tuple(getattr(info,key) for key in ("st_dev","st_ino","st_uid","st_gid","st_mode","st_nlink","st_size","st_mtime_ns","st_ctime_ns"))
def process(pid):
    ticks=resident.start_ticks(pid)
    exe=os.readlink("/proc/"+str(pid)+"/exe")
    require(re.fullmatch(r"/(?:nix/store|usr|run/wrappers/bin)/[A-Za-z0-9/+._-]{1,4000}",exe))
    require(resident.start_ticks(pid)==ticks)
    return {"uid":os.getuid(),"pid":pid,"start_ticks":ticks,"exe":exe}
def standard_process(pid):
    # Fixed v2 consumers use the authenticated local peer/service role.
    ticks=resident.start_ticks(pid)
    require(type(ticks) is int and ticks>0 and resident.start_ticks(pid)==ticks)
    return {"uid":os.getuid(),"pid":pid,"start_ticks":ticks}
def standard_observation(value):
    require(type(value) is dict and set(value)=={"schema","broker","manager","secret_service","provider",
        "default_collection","default_exists","locked","items_read","secrets_read","provider_invocation"}
        and value["schema"]=="omux-existing-vault-metadata-v2"
        and all(value[key] is False for key in ("items_read","secrets_read","provider_invocation")))
    for name in ("broker","manager","secret_service"):
        row=value[name]
        if row is None:
            require(name=="secret_service" and value["provider"]=="absent")
            continue
        require(type(row) is dict and set(row)==({"uid","pid","start_ticks"} if name=="broker"
            else {"uid","pid","start_ticks","owner"}))
        require(type(row["uid"]) is int and row["uid"]==os.getuid()
            and type(row["pid"]) is int and row["pid"]>1
            and type(row["start_ticks"]) is int and row["start_ticks"]>0)
        if name!="broker":
            require(type(row["owner"]) is str and re.fullmatch(r":[0-9]+[.][0-9]+",row["owner"]))
    require(value["provider"] in ("absent","standard-secret-service")
        and (value["provider"]=="absent")==(value["secret_service"] is None))
    if value["provider"]=="standard-secret-service":
        path=value["default_collection"]
        require(type(path) is str and len(path)<=4095
            and re.fullmatch(r"/(?:[A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)*)?",path))
        require(type(value["default_exists"]) is bool and value["default_exists"]==(path!="/")
            and (type(value["locked"]) is bool if value["default_exists"] else value["locked"] is None))
    else:
        require(value["default_collection"] is value["default_exists"] is value["locked"] is None)
    return value
def standard_unlockable(value):
    standard_observation(value)
    require(value["provider"]=="standard-secret-service" and value["default_exists"] is True
        and value["locked"] is True)
def standard_schema(value):
    require(type(value) is dict and set(value)=={"schema_version","purpose","permissions","mapping","expected"}
        and type(value["schema_version"]) is int and value["schema_version"]==2
        and value["purpose"] in ("observe-standard-vault","unlock-standard-vault"))
    permissions=value["permissions"]
    require(type(permissions) is dict and set(permissions)=={"metadata","unlock"}
        and permissions["metadata"] is True and type(permissions["unlock"]) is bool and value["mapping"] is None)
    if value["purpose"]=="observe-standard-vault":
        require(permissions["unlock"] is False and value["expected"] is None)
    else:
        require(permissions["unlock"] is True)
        standard_unlockable(value["expected"])
    return value
def expected_processes(expected):
    standard=expected["schema"]=="omux-existing-vault-metadata-v2"
    if standard:standard_observation(expected)
    else:validate_observation(expected)
    for name in ("broker","manager","secret_service"):
        row=expected[name]
        if row is not None:
            actual=standard_process(row["pid"]) if standard else process(row["pid"])
            require(actual=={key:item for key,item in row.items() if key!="owner"})
def validate_observation(value):
    require(type(value) is dict and set(value)=={"schema","broker","manager","secret_service","provider",
        "default_exists","default_is_login","locked","items_read","secrets_read","provider_invocation"}
        and value["schema"]=="omux-existing-vault-metadata-v1"
        and all(value[key] is False for key in ("items_read","secrets_read","provider_invocation")))
    for name in ("broker","manager","secret_service"):
        row=value[name]
        if row is None:
            require(name=="secret_service" and value["provider"]=="absent")
            continue
        require(type(row) is dict and set(row)==({"uid","pid","start_ticks","exe"} if name=="broker"
            else {"uid","pid","start_ticks","exe","owner"}))
        require(type(row["uid"]) is int and row["uid"]==os.getuid()
            and type(row["pid"]) is int and row["pid"]>1
            and type(row["start_ticks"]) is int and row["start_ticks"]>0
            and type(row["exe"]) is str and re.fullmatch(r"/(?:nix/store|usr|run/wrappers/bin)/[A-Za-z0-9/+._-]{1,4000}",row["exe"]))
        if name!="broker":
            require(type(row["owner"]) is str and re.fullmatch(r":[0-9]+[.][0-9]+",row["owner"]))
    require(value["provider"] in ("absent","gnome-keyring-48.0","unqualified-existing-provider")
        and (value["provider"]=="absent")== (value["secret_service"] is None))
    if value["provider"]=="gnome-keyring-48.0":
        require(value["secret_service"] is not None and value["secret_service"]["exe"]==GNOME_EXE
            and type(value["default_exists"]) is bool and type(value["default_is_login"]) is bool
            and (type(value["locked"]) is bool if value["default_exists"] else value["locked"] is None)
            and (not value["default_is_login"] or value["default_exists"]))
    else:
        require(value["default_exists"] is value["default_is_login"] is value["locked"] is None)
        require(value["provider"]=="absent" or value["secret_service"] is not None)
    return value
def unlockable(value):
    validate_observation(value)
    require(value["provider"]=="gnome-keyring-48.0" and value["default_exists"] is True
        and value["default_is_login"] is True and value["locked"] is True)
def schema(value):
    if type(value) is dict and value.get("schema_version")==2:
        return standard_schema(value)
    require(type(value) is dict and set(value)=={"schema_version","purpose","permissions","mapping","expected"}
        and type(value["schema_version"]) is int and value["schema_version"]==1
        and value["purpose"] in ("observe-default-vault","unlock-existing-login-vault"))
    permissions=value["permissions"]
    require(type(permissions) is dict and set(permissions)=={"metadata","unlock"}
        and permissions["metadata"] is True and type(permissions["unlock"]) is bool)
    if value["purpose"]=="observe-default-vault":
        require(permissions["unlock"] is False and value["mapping"] is None and value["expected"] is None)
    else:
        require(permissions["unlock"] is True)
        mapping=value["mapping"]
        require(type(mapping) is dict and set(mapping)=={"role","purpose","encoding","user_confirmed"}
            and mapping["user_confirmed"] is True
            and mapping=={"role":"become/password","purpose":"gnome-login-keyring-unlock",
                "encoding":"exact-bytes","user_confirmed":True})
        unlockable(value["expected"])
    return value
def compare_after(before,after):
    validate_observation(before);validate_observation(after)
    require(all(before[key]==after[key] for key in ("broker","manager","secret_service","provider","default_exists","default_is_login"))
        and after["locked"] is False)
    return True
def named_directory(path,witness,private=False):
    # Reopen every named canonical ancestor with O_NOFOLLOW, then compare held identity.
    descriptor=resident.open_directory(path,private=private)
    try:
        require(resident.stable(os.fstat(descriptor))==witness)
    finally:
        os.close(descriptor)
def socket_witness(path,deadline_ns):
    now=time.monotonic_ns();require(now<deadline_ns)
    before=path.stat(follow_symlinks=False)
    require(stat.S_ISSOCK(before.st_mode) and before.st_uid==os.getuid())
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as peer:
        peer.settimeout(min(2,(deadline_ns-now)/10**9))
        peer.connect(str(path))
        pid,uid,gid=struct.unpack("3i",peer.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        require(uid==os.getuid() and pid>1)
        witness=(resident.stable(before),pid,resident.start_ticks(pid))
    require(time.monotonic_ns()<deadline_ns
        and resident.stable(before)==resident.stable(path.stat(follow_symlinks=False)))
    return witness
def generation_target(value,uid):
    require(type(value) is str and re.fullmatch(r"/run/user/"+str(uid)+r"/secrets[.]d/[1-9][0-9]{0,18}",value))
    return resident.canonical(value)

# Only the standard metadata operation receives this guardian-origin output
# capability. It is not a request selector or authority for unlock/enrollment.
OUTPUT_VARIABLE = "OMUX_RESIDENT_METADATA_OUTPUT"
OUTPUT_SHA_VARIABLE = "OMUX_RESIDENT_METADATA_OUTPUT_SHA256"
OUTPUT_LIMIT = 16384
TERMINAL_PREFIX = b"OMUX_STANDARD_VAULT_METADATA_TERMINAL "
ACK_NAME = "resident-vault-publication.json"
OUTPUT_FIELDS = frozenset(("schema", "run", "epoch", "identity", "deadline_ns",
    "profile", "manager", "target", "purpose", "source_commit", "source_graph_sha256",
    "closure_sha256", "bootstrap_sha256"))


def output_wire(value):
    raw=json.dumps(value,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")
    require(0<len(raw)<=4096)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

def output_unwire(value):
    require(type(value) is str and re.fullmatch(r"[A-Za-z0-9_-]{1,5462}",value))
    raw=base64.b64decode(value+"="*(-len(value)%4),altchars=b"-_",validate=True)
    require(0<len(raw)<=4096 and base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")==value)
    return json.loads(raw,object_pairs_hook=resident.unique)

class MetadataOutput:
    def __init__(self, run, deadline_ns, descriptor=None):
        self.fd = None
        self.context = None
        self.output_fd = None
        self.ack_fd = None
        self.output_snapshot = None
        self.ack_snapshot = None
        self.created = None
        self.created_ack = None
        self.failed = False
        self.run = resident.canonical(str(run))
        require(re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", self.run.name))
        self.deadline_ns = deadline_ns
        try:
            self.fd = os.dup(descriptor) if descriptor is not None else resident.open_directory(self.run, private=True)
            info = os.fstat(self.fd)
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
                and stat.S_IMODE(info.st_mode) == 0o700)
            self.witness = resident.stable(info)
            self.check()
        except BaseException:
            try:
                self.close()
            except BaseException:
                pass  # Detached once; preserve the original admission failure.
            raise

    def check(self, reserve_ns=0):
        require(type(self.deadline_ns) is int
            and 0 < self.deadline_ns - time.monotonic_ns() - reserve_ns <= 1200 * 10**9
            and self.fd is not None and resident.stable(os.fstat(self.fd)) == self.witness)
        named_directory(self.run, self.witness, private=True)

    def bind(self, source_commit, graph_sha256, closure_sha256, bootstrap_sha256):
        require(self.context is None and type(source_commit) is str
            and re.fullmatch(r"[0-9a-f]{40}", source_commit))
        for digest in (graph_sha256, closure_sha256, bootstrap_sha256):
            require(type(digest) is str and re.fullmatch(r"[0-9a-f]{64}", digest))
        self.check()
        self.context = {"schema": "omux-standard-vault-metadata-output-v1",
            "run": str(self.run), "epoch": self.run.name, "identity": list(self.witness),
            "deadline_ns": self.deadline_ns, "profile": "resident-enrollment",
            "manager": "system", "target": STANDARD_LABEL, "purpose": "observe-standard-vault",
            "source_commit": source_commit, "source_graph_sha256": graph_sha256,
            "closure_sha256": closure_sha256, "bootstrap_sha256": bootstrap_sha256}

    def environment(self):
        self.check()
        require(self.context is not None)
        raw = output_wire(self.context)
        return {OUTPUT_VARIABLE: raw, OUTPUT_SHA_VARIABLE: hashlib.sha256(raw.encode("ascii")).hexdigest()}

    @classmethod
    def consume(cls, environment):
        raw = environment.get(OUTPUT_VARIABLE, "")
        require(type(raw) is str and 0 < len(raw.encode("ascii")) <= 5462
            and hashlib.sha256(raw.encode("ascii")).hexdigest() == environment.get(OUTPUT_SHA_VARIABLE))
        value = output_unwire(raw)
        require(type(value) is dict and set(value) == OUTPUT_FIELDS
            and value["schema"] == "omux-standard-vault-metadata-output-v1"
            and value["profile"] == "resident-enrollment" and value["manager"] == "system"
            and value["target"] == STANDARD_LABEL and value["purpose"] == "observe-standard-vault"
            and value["run"] == environment.get("OMUX_EXECUTION_GUARD")
            and str(value["deadline_ns"]) == environment.get(DEADLINE_VARIABLE)
            and type(value["identity"]) is list and len(value["identity"]) == 5
            and all(type(part) is int for part in value["identity"]))
        owner = cls(value["run"], value["deadline_ns"])
        try:
            require(owner.run.name == value["epoch"] and list(owner.witness) == value["identity"])
            owner.bind(value["source_commit"], value["source_graph_sha256"],
                value["closure_sha256"], value["bootstrap_sha256"])
            require(owner.context == value)
            owner.check(30 * 10**9)
            return owner
        except BaseException:
            try:
                owner.close()
            except BaseException:
                pass  # Preserve failed admission, never retry an owned FD.
            raise

    @staticmethod
    def metadata_bytes(value):
        require(type(value) is dict and set(value) == {
            "schema", "purpose", "observation", "unlock_dispatched", "client_status",
            "unlock_effect_scope", "unchanged_service_owner", "unchanged_default_collection",
            "factor_material_access", "provider_invocation", "omux_datastore_access",
            "omux_wrapping_key_regeneration", "resident_key_readiness_proven",
            "resident_custody_proven", "normal_os_unlock_passed", "native_support"}
            and value["client_status"] == "not-dispatched" and value["unlock_effect_scope"] == "not-dispatched"
            and value["unchanged_service_owner"] is True and value["unchanged_default_collection"] is True
            and value.get("schema") == "omux-resident-standard-vault-action-v1"
            and value.get("purpose") == "observe-standard-vault"
            and all(value.get(name) is False for name in ("unlock_dispatched",
                "factor_material_access", "provider_invocation", "omux_datastore_access",
                "omux_wrapping_key_regeneration", "resident_key_readiness_proven",
                "resident_custody_proven", "normal_os_unlock_passed", "native_support")))
        standard_observation(value["observation"])
        raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
        require(0 < len(raw) <= OUTPUT_LIMIT)
        return raw

    def publish(self, value):
        require(self.context is not None)
        raw=self.metadata_bytes(value)
        self.check(30 * 10**9)
        descriptor = None
        created = None
        try:
            descriptor = os.open("resident-vault-metadata.json",
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.fd)
            created = os.fstat(descriptor)
            self.created=(created.st_dev,created.st_ino)
            require(stat.S_ISREG(created.st_mode) and created.st_uid == os.getuid()
                and created.st_nlink == 1 and stat.S_IMODE(created.st_mode) == 0o600)
            offset = 0
            while offset < len(raw):
                self.check(30 * 10**9)
                written = os.write(descriptor, raw[offset:])
                require(written > 0)
                offset += written
            os.fsync(descriptor)
            authenticated = os.fstat(descriptor)
            require(resident.stable(authenticated) == resident.stable(created)
                and authenticated.st_nlink == 1 and authenticated.st_size == len(raw))
            require(os.pread(descriptor, OUTPUT_LIMIT + 1, 0) == raw)
            final = os.fstat(descriptor)
            require(identity(final) == identity(authenticated) ==
                identity(os.stat("resident-vault-metadata.json", dir_fd=self.fd, follow_symlinks=False)))
            self.check(30 * 10**9)
            # Original writer survives the last directory publication I/O.
            os.fsync(self.fd)
            require(identity(os.fstat(descriptor))==identity(authenticated)
                and os.pread(descriptor,OUTPUT_LIMIT+1,0)==raw)
            self.check(30*10**9)
            require(identity(os.fstat(descriptor))==identity(authenticated)==
                identity(os.stat("resident-vault-metadata.json",dir_fd=self.fd,follow_symlinks=False)))
            self.output_snapshot=(identity(authenticated),raw)
            closing,descriptor=descriptor,None
            os.close(closing)
            self.pin_output(self.terminal_frame())
            self.verify_output(30*10**9)
        except BaseException:
            self.failed=True
            try:
                if created is not None:
                    named = os.stat("resident-vault-metadata.json", dir_fd=self.fd, follow_symlinks=False)
                    if (named.st_dev, named.st_ino) == (created.st_dev, created.st_ino):
                        os.unlink("resident-vault-metadata.json", dir_fd=self.fd)
            except BaseException:
                pass  # Preserve the original failure; no cleanup success is claimed.
            finally:
                if descriptor is not None:
                    closing, descriptor = descriptor, None
                    try:
                        os.close(closing)
                    except BaseException:
                        pass  # Detached once; never retry an ambiguously closed FD.
            raise


    def terminal_frame(self):
        require(self.output_snapshot is not None and self.context is not None)
        return {"schema":"omux-standard-vault-metadata-terminal-v1","epoch":self.run.name,
            "context_sha256":hashlib.sha256(output_wire(self.context).encode("ascii")).hexdigest(),
            "leaf":list(self.output_snapshot[0]),
            "bytes_sha256":hashlib.sha256(self.output_snapshot[1]).hexdigest()}

    def validate_terminal(self,value):
        require(type(value) is dict and set(value)==
            {"schema","epoch","context_sha256","leaf","bytes_sha256"}
            and value["schema"]=="omux-standard-vault-metadata-terminal-v1"
            and value["epoch"]==self.run.name
            and value["context_sha256"]==self.environment()[OUTPUT_SHA_VARIABLE]
            and type(value["leaf"]) is list and len(value["leaf"])==9
            and all(type(part) is int for part in value["leaf"])
            and type(value["bytes_sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}",value["bytes_sha256"]))

    def pin_output(self,terminal,reserve_ns=30*10**9):
        self.validate_terminal(terminal)
        require(self.output_fd is None)
        self.check(reserve_ns)
        self.output_fd=os.open("resident-vault-metadata.json",
            os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.fd)
        before=os.fstat(self.output_fd)
        require(identity(before)==tuple(terminal["leaf"]) and stat.S_ISREG(before.st_mode)
            and before.st_uid==os.getuid() and stat.S_IMODE(before.st_mode)==0o600
            and before.st_nlink==1 and 0<before.st_size<=OUTPUT_LIMIT)
        raw=os.pread(self.output_fd,OUTPUT_LIMIT+1,0)
        require(len(raw)==before.st_size and hashlib.sha256(raw).hexdigest()==terminal["bytes_sha256"]
            and self.metadata_bytes(json.loads(raw,object_pairs_hook=resident.unique))==raw)
        self.output_snapshot=(identity(before),raw)
        self.created=(before.st_dev,before.st_ino)
        self.verify_output(reserve_ns)

    def verify_output(self,reserve_ns=0):
        require(self.output_fd is not None and self.output_snapshot is not None)
        witness,raw=self.output_snapshot
        self.check(reserve_ns)
        require(identity(os.fstat(self.output_fd))==witness and os.pread(self.output_fd,OUTPUT_LIMIT+1,0)==raw
            and identity(os.fstat(self.output_fd))==witness==
                identity(os.stat("resident-vault-metadata.json",dir_fd=self.fd,follow_symlinks=False)))
        if self.ack_fd is not None:
            expected,encoded=self.ack_snapshot
            require(identity(os.fstat(self.ack_fd))==expected and os.pread(self.ack_fd,5463,0)==encoded
                and identity(os.fstat(self.ack_fd))==expected==
                    identity(os.stat(ACK_NAME,dir_fd=self.fd,follow_symlinks=False)))
        self.check(reserve_ns)
        # Rejoin both original leaves after the LAST root ancestry I/O.
        require(identity(os.fstat(self.output_fd))==witness and os.pread(self.output_fd,OUTPUT_LIMIT+1,0)==raw
            and identity(os.fstat(self.output_fd))==witness==
                identity(os.stat("resident-vault-metadata.json",dir_fd=self.fd,follow_symlinks=False)))
        if self.ack_fd is not None:
            require(identity(os.fstat(self.ack_fd))==expected and os.pread(self.ack_fd,5463,0)==encoded
                and identity(os.fstat(self.ack_fd))==expected==
                    identity(os.stat(ACK_NAME,dir_fd=self.fd,follow_symlinks=False)))
        # Final physical-only fence follows ALL body reads, including ACK.
        require(identity(os.fstat(self.output_fd))==witness==
            identity(os.stat("resident-vault-metadata.json",dir_fd=self.fd,follow_symlinks=False)))
        if self.ack_fd is not None:
            require(identity(os.fstat(self.ack_fd))==expected==
                identity(os.stat(ACK_NAME,dir_fd=self.fd,follow_symlinks=False)))
        # No further named-root I/O follows this original-cutoff sample.
        require(0<self.deadline_ns-time.monotonic_ns()-reserve_ns<=1200*10**9)

    def verify_closed(self):
        require(self.fd is None and self.output_fd is None and self.output_snapshot is not None)
        verifier=MetadataOutput(self.run,self.deadline_ns)
        try:
            require(verifier.witness==self.witness)
            verifier.bind(self.context["source_commit"],self.context["source_graph_sha256"],
                self.context["closure_sha256"],self.context["bootstrap_sha256"])
            verifier.pin_output(self.terminal_frame())
            verifier.verify_output(30*10**9)
        except BaseException:
            verifier.failed=True
            try:verifier.close()
            except BaseException:pass  # Keep the first leaf/cutoff refusal.
            raise
        else:verifier.close()
        require(time.monotonic_ns()<self.deadline_ns-30*10**9)

    def retain_ack(self,terminal):
        self.validate_terminal(terminal)
        self.verify_output(30*10**9)
        raw=(output_wire(terminal)+"\n").encode("ascii")
        require(len(raw)<=5462)
        descriptor=None
        created=None
        try:
            descriptor=os.open(ACK_NAME,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=self.fd)
            created=os.fstat(descriptor)
            self.created_ack=(created.st_dev,created.st_ino)
            require(stat.S_ISREG(created.st_mode) and created.st_uid==os.getuid()
                and stat.S_IMODE(created.st_mode)==0o600 and created.st_nlink==1)
            offset=0
            while offset<len(raw):
                self.check(30*10**9)
                written=os.write(descriptor,raw[offset:]);require(written>0);offset+=written
            os.fsync(descriptor)
            expected=identity(os.fstat(descriptor))
            require(resident.stable(os.fstat(descriptor))==resident.stable(created)
                and os.fstat(descriptor).st_nlink==1 and os.fstat(descriptor).st_size==len(raw))
            os.fsync(self.fd)
            require(identity(os.fstat(descriptor))==expected and os.pread(descriptor,5463,0)==raw
                and identity(os.fstat(descriptor))==expected==
                    identity(os.stat(ACK_NAME,dir_fd=self.fd,follow_symlinks=False)))
            self.verify_output(30*10**9)
            closing,descriptor=descriptor,None;os.close(closing)
            self.check(30*10**9)
            require(identity(os.stat(ACK_NAME,dir_fd=self.fd,follow_symlinks=False))==expected)
            self.ack_fd=os.open(ACK_NAME,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.fd)
            self.ack_snapshot=(expected,raw)
            self.verify_output(30*10**9)
        except BaseException:
            self.abort()
            raise
        finally:
            if descriptor is not None:
                closing,descriptor=descriptor,None
                try:os.close(closing)
                except BaseException:
                    if not self.failed:
                        self.abort()
                        raise

    def pin_ack(self):
        require(self.ack_fd is None and self.output_fd is None)
        self.check()
        self.ack_fd=os.open(ACK_NAME,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.fd)
        before=os.fstat(self.ack_fd)
        require(stat.S_ISREG(before.st_mode) and before.st_uid==os.getuid()
            and stat.S_IMODE(before.st_mode)==0o600 and before.st_nlink==1 and 0<before.st_size<=5462)
        raw=os.pread(self.ack_fd,5463,0)
        require(len(raw)==before.st_size and raw.endswith(b"\n"))
        terminal=output_unwire(raw[:-1].decode("ascii"))
        require((output_wire(terminal)+"\n").encode("ascii")==raw)
        self.ack_snapshot=(identity(before),raw)
        self.pin_output(terminal,reserve_ns=0)
        self.verify_output()

    def abort(self):
        # Cleanup reduces authority and may use the existing reserve; never
        # adopt a replacement root or unlink another creator's inode.
        self.failed=True
        if self.created is None and self.created_ack is None:return
        owned=None
        try:
            owned=resident.open_directory(self.run,private=True)
            require(resident.stable(os.fstat(owned))==self.witness)
            for name,created in (("resident-vault-metadata.json",self.created),(ACK_NAME,self.created_ack)):
                if created is not None:
                    try:
                        named=os.stat(name,dir_fd=owned,follow_symlinks=False)
                        if (named.st_dev,named.st_ino)==created:os.unlink(name,dir_fd=owned)
                    except FileNotFoundError:pass
        except BaseException:pass  # No cleanup success claim; preserve first refusal.
        finally:
            if owned is not None:
                closing,owned=owned,None
                try:os.close(closing)
                except BaseException:pass

    def close(self):
        failure=None
        for field in ("ack_fd","output_fd"):
            closing=getattr(self,field,None);setattr(self,field,None)
            if closing is not None:
                try:os.close(closing)
                except BaseException as error:
                    if failure is None:failure=error
        if self.fd is not None and self.output_snapshot is not None and not self.failed:
            try:
                self.check()
                require(identity(os.stat("resident-vault-metadata.json",dir_fd=self.fd,follow_symlinks=False))
                    ==self.output_snapshot[0])
                if self.ack_snapshot is not None:
                    require(identity(os.stat(ACK_NAME,dir_fd=self.fd,follow_symlinks=False))==self.ack_snapshot[0])
            except BaseException as error:
                if failure is None:failure=error
        closing,self.fd=self.fd,None
        if closing is not None:
            try:os.close(closing)
            except BaseException as error:
                if failure is None:failure=error
        if failure is not None:
            self.abort()
            raise failure

class MetadataTerminalReceiver:
    """Only the guardian's exact metadata worker consumes this private pipe."""
    def __init__(self,environment):
        # Create every parser/owner slot before acquiring an integer-owned FD.
        self.owner=None
        self.pending=b""
        self.skip=False
        self.terminal=None
        owner=None
        try:
            owner=MetadataOutput.consume(environment)
            self.owner=owner
        except BaseException:
            # A failed transfer (even after assignment) retains its local owner.
            if owner is not None:
                try:owner.close()
                except BaseException:pass  # Detached once; keep the first cause.
            raise

    def feed(self,data):
        require(type(data) is bytes and len(data)<=65536)
        self.owner.check(30*10**9)
        segments=data.split(b"\n")
        for index,part in enumerate(segments):
            complete=index<len(segments)-1
            if not self.skip:
                self.pending+=part
                if self.pending.startswith(TERMINAL_PREFIX):
                    require(len(self.pending)<=8192)
                elif not TERMINAL_PREFIX.startswith(self.pending):
                    self.skip=True;self.pending=b""
                if complete and not self.skip and self.pending:
                    require(self.pending.startswith(TERMINAL_PREFIX) and self.terminal is None)
                    value=output_unwire(self.pending[len(TERMINAL_PREFIX):].decode("ascii"))
                    self.owner.validate_terminal(value)
                    self.terminal=value
            if complete:self.pending=b"";self.skip=False

    def finish(self,status):
        require(type(status) is int and status==0 and self.terminal is not None
            and (self.skip or not self.pending))
        self.owner.check(30*10**9)
        self.owner.pin_output(self.terminal)
        self.owner.retain_ack(self.terminal)
        self.owner.verify_output(30*10**9)

    def close(self):
        closing,self.owner=self.owner,None
        if closing is not None:
            try:
                closing.close()
                require(time.monotonic_ns()<closing.deadline_ns-30*10**9)
            except BaseException:
                closing.abort()
                raise

class Admission:
    def __init__(self,manifest,home,deadline_ns,label=None):
        self.deadline_ns=deadline_ns;self.held=[];self.created=[];self.parents=[];self.links=[];self.leaf=None
        self.manifest=resident.canonical(str(manifest));self.root=self.manifest.parent
        require(self.manifest.name=="input.json")
        try:
            self.directory=resident.open_directory(self.root,private=True);self.held.append(self.directory)
            require(os.listdir(self.directory)==["input.json"])
            self.file=os.open("input.json",os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=self.directory)
            self.held.append(self.file);info=os.fstat(self.file)
            require(stat.S_ISREG(info.st_mode) and info.st_uid==os.getuid()
                and stat.S_IMODE(info.st_mode) in (0o400,0o600) and info.st_nlink==1 and 0<info.st_size<=16384)
            self.file_identity=identity(info);self.raw=os.pread(self.file,16385,0)
            require(len(self.raw)==info.st_size)
            self.selected=schema(json.loads(self.raw,object_pairs_hook=resident.unique))
            require(label==({"observe-default-vault":LABEL,"unlock-existing-login-vault":UNLOCK_LABEL,
                "observe-standard-vault":STANDARD_LABEL,"unlock-standard-vault":STANDARD_UNLOCK_LABEL}[self.selected["purpose"]]))
            self.root_identity=resident.stable(os.fstat(self.directory))
            runtime=Path("/run/user")/str(os.getuid())
            runtime_fd=resident.open_directory(runtime,private=True);self.held.append(runtime_fd)
            self.parents.append((runtime,runtime_fd,resident.stable(os.fstat(runtime_fd))))
            self.sources={self.root/"bus":runtime/"bus"}
            self.socket_identities={runtime/"bus":socket_witness(runtime/"bus",self.deadline_ns)}
            if self.selected["purpose"]=="unlock-standard-vault":
                expected=self.selected["expected"];bus=self.socket_identities[runtime/"bus"]
                require(bus[1]==expected["broker"]["pid"] and bus[2]==expected["broker"]["start_ticks"])
                expected_processes(expected)
            if self.selected["purpose"]=="unlock-existing-login-vault":
                expected=self.selected["expected"]
                bus=self.socket_identities[runtime/"bus"]
                require(bus[1]==expected["broker"]["pid"] and bus[2]==expected["broker"]["start_ticks"])
                for name in ("broker","manager","secret_service"):
                    require(process(expected[name]["pid"])=={key:value for key,value in expected[name].items() if key!="owner"})
                control=runtime/"keyring"/"control"
                keyring=resident.open_directory(control.parent,private=True);self.held.append(keyring)
                self.parents.append((control.parent,keyring,resident.stable(os.fstat(keyring))))
                witness=socket_witness(control,self.deadline_ns)
                require(witness[1]==expected["secret_service"]["pid"] and witness[2]==expected["secret_service"]["start_ticks"])
                self.sources[self.root/"control"]=control;self.socket_identities[control]=witness
                # Mapping and independently selected public provider witness have passed.
                # Hold only metadata here. The declared carrier preflights current alias/Locked before content IO.
                sops_parent=Path(home)/".config/sops-nix"
                sops_fd=resident.open_directory(sops_parent);self.held.append(sops_fd)
                self.parents.append((sops_parent,sops_fd,resident.stable(os.fstat(sops_fd))))
                projected=os.stat("secrets",dir_fd=sops_fd,follow_symlinks=False)
                require(projected.st_uid==os.getuid())
                if stat.S_ISLNK(projected.st_mode):
                    require(projected.st_nlink==1)
                    target=os.readlink("secrets",dir_fd=sops_fd)
                    secret_root=generation_target(target,os.getuid())
                    self.links.append((sops_fd,identity(projected),target))
                else:
                    require(stat.S_ISDIR(projected.st_mode) and not projected.st_mode&0o022)
                    secret_root=sops_parent/"secrets"
                # One owned generation projection. The held0700 runtime ancestor
                # protects the physical generation from other users.
                for parent in (secret_root.parent,secret_root,secret_root/"become"):
                    parent_fd=resident.open_directory(parent);self.held.append(parent_fd)
                    require(os.fstat(parent_fd).st_uid==os.getuid())
                    self.parents.append((parent,parent_fd,resident.stable(os.fstat(parent_fd))))
                leaf=secret_root/"become/password";self.factor_path=leaf
                factor_parent=parent_fd
                self.leaf=os.open(leaf.name,os.O_PATH|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=factor_parent)
                self.held.append(self.leaf);factor=os.fstat(self.leaf)
                require(stat.S_ISREG(factor.st_mode) and factor.st_uid==os.getuid()
                    and stat.S_IMODE(factor.st_mode) in (0o400,0o600) and factor.st_nlink==1 and 1<=factor.st_size<=4096)
                self.factor_identity=identity(factor)
                self.sources[self.root/"factor"]=Path("/proc")/str(os.getpid())/"fd"/str(self.leaf)
            for path in self.sources:
                placeholder=resident.regular_mountpoint(path)
                self.created.append((placeholder,path,resident.stable(os.fstat(placeholder.fileno()))))
            self.facts=self.recheck()
        except BaseException:
            self.close();raise
    def recheck(self):
        require(time.monotonic_ns()<self.deadline_ns and resident.stable(os.fstat(self.directory))==self.root_identity
            ==resident.stable(self.root.stat(follow_symlinks=False)))
        named_directory(self.root,self.root_identity,private=True)
        require(set(os.listdir(self.directory))=={"input.json"}|{path.name for path in self.sources})
        require(identity(os.fstat(self.file))==self.file_identity==identity(os.stat("input.json",dir_fd=self.directory,follow_symlinks=False))
            and os.pread(self.file,16385,0)==self.raw)
        for path,fd,witness in self.parents:
            require(resident.stable(os.fstat(fd))==witness)
            named_directory(path,witness)
        for parent,witness,target in self.links:
            require(identity(os.stat("secrets",dir_fd=parent,follow_symlinks=False))==witness
                and os.readlink("secrets",dir_fd=parent)==target)
        for path,witness in self.socket_identities.items():
            require(socket_witness(path,self.deadline_ns)==witness)
        for placeholder,path,witness in self.created:
            require(resident.regular_mountpoint_witness(path,placeholder.fileno())==witness)
        if self.selected["purpose"]=="unlock-standard-vault":
            expected_processes(self.selected["expected"])
        if self.leaf is not None:
            require(identity(os.fstat(self.leaf))==self.factor_identity==identity(self.factor_path.stat(follow_symlinks=False)))
            for name in ("broker","manager","secret_service"):
                row=self.selected["expected"][name]
                require(process(row["pid"])=={key:value for key,value in row.items() if key!="owner"})
        return {"scope":"existing-vault-metadata-or-authorized-unlock","purpose":self.selected["purpose"],
            "factor_contents_read_by_guard":False,"provider_invocation":False,
            "workload_memory":PROOF_MEMORY,"workload_tasks":PROOF_TASKS,
            "workload_cpu_percent":PROOF_CPU_PERCENT,"resident_reservation_qualified":False}
    def bindings(self):
        return list(getattr(self,"offline_repository_bindings",()))+[str(self.root)+":"+DESTINATION]+[str(source)+":"+DESTINATION+"/"+target.name+":norbind"
            for target,source in self.sources.items()]
    def writable_binding(self):
        return ""
    def verify_bindings(self,actual,run=None):
        leaves=[str(source)+":"+DESTINATION+"/"+target.name for target,source in self.sources.items()]
        expected_ro=resident.normalize_binds(" ".join(self.bindings()),leaves)
        expected_rw=[] if run is None else [str(run)+":"+str(run)]
        ro=resident.normalize_binds(actual.get("BindReadOnlyPaths",""),leaves,readback=True)
        rw=resident.normalize_binds(actual.get("BindPaths",""),readback=True)
        require(len(ro)==len(expected_ro) and set(ro)==set(expected_ro) and len(rw)==len(expected_rw) and set(rw)==set(expected_rw))
    def service_observation(self,systemctl,starting=False):
        return {"service_action":False,"datastore_read":False,"wrapping_key_replacement":False,"purpose":self.selected["purpose"]}
    def environment(self):
        info=os.fstat(self.directory)
        return {VARIABLE:DESTINATION+"/input.json",DEADLINE_VARIABLE:str(self.deadline_ns),
            "OMUX_RESIDENT_NAMESPACE_ID":str(info.st_dev)+":"+str(info.st_ino),
            "DBUS_SESSION_BUS_ADDRESS":"unix:path="+DESTINATION+"/bus","XDG_RUNTIME_DIR":DESTINATION,
            **getattr(self, "metadata_output_environment", {})}
    def runtime_seconds(self):
        remaining=(self.deadline_ns-time.monotonic_ns())//10**9-30
        require(0<remaining<=1200);return int(remaining)
    def close(self):
        for placeholder,path,witness in reversed(self.created):
            placeholder.close()
            if path.exists() and resident.stable(path.stat(follow_symlinks=False))==witness: path.unlink()
        self.created=[]
        for fd in reversed(self.held):os.close(fd)
        self.held=[]
