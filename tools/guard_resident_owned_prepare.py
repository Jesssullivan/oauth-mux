"""Exact first owned preparation; no account/custody or daemon execution."""
import hashlib
import json
import os
from pathlib import Path
import stat
import guard_resident_enrollment_profile as resident
import guard_resident_owned_update as owned
from guard_resident_owned_update import install, pack

LABEL = "//delivery:resident_owned_prepare"
ACTION = "prepare-owned"

def schema(value,home):
    resident.require(type(value) is dict and set(value) == {
        "schema_version","ownership","action","instance","prefix","records","runtime_state",
        "service_path","native_context","permissions","install_archive","service_preparation"}
        and type(value["schema_version"]) is int and value["schema_version"] == 1
        and value["ownership"] == "omux-installation" and value["action"] == ACTION
        and value["instance"] == "default" and value["native_context"] is None)
    for key,path in resident.fixed_paths(home).items():
        resident.require(resident.canonical(value[key]) == path)
    permissions=value["permissions"]
    resident.require(type(permissions) is dict and set(permissions) == {
        "connect_source","activate_service","restart_daemon"}
        and all(type(item) is bool and item is False for item in permissions.values()))
    preparation=value["service_preparation"]
    resident.require(type(preparation) is dict and set(preparation) == {
        "daemon_reload","enable_for_login","start_now"}
        and all(type(item) is bool for item in preparation.values())
        and preparation == {"daemon_reload":True,"enable_for_login":True,"start_now":False})
    owned.start_pins(value["install_archive"],home)
    return value

def absent_service(values):
    resident.require(type(values) is dict and set(values) == {
        "LoadState","ActiveState","SubState","MainPID","FragmentPath","ControlGroup",
        "MemoryMax","MemorySwapMax","TasksMax","CPUQuotaPerSecUSec"}
        and values["LoadState"] == "not-found" and values["ActiveState"] == "inactive"
        and values["SubState"] == "dead" and values["MainPID"] == "0"
        and values["FragmentPath"] == "" and values["ControlGroup"] == ""
        and all(type(item) is str for item in values.values()))
    return True

class InstallationPrepare:
    """Public archive and installation transition; runtime metadata never content."""
    def __init__(self,selected,home,deadline,*,acquire_runtime_lock=True):
        self.selected,self.home,self.deadline = schema(selected,home),Path(home),deadline
        self.files,self.parents,self.aliases,self.software = [],[],[],None
        self.runtime=None
        self.finished=False
        try:
            self.selection=selected["install_archive"]
            q=self.selection["qualification"]
            qualification=owned.PublicFile(q["path"],deadline,8*1024*1024)
            self.files.append(qualification)
            resident.require(len(qualification.raw) == q["bytes"]
                and hashlib.sha256(qualification.raw).hexdigest() == q["sha256"])
            receipt=json.loads(qualification.raw,object_pairs_hook=resident.unique)
            output=owned.qualification_output(receipt,q)
            resident.require(Path(self.selection["archive_path"]) == output/owned.ARCHIVE_RELATIVE)
            archive=owned.PublicFile(self.selection["archive_path"],deadline,pack.MAX_BYTES)
            self.files.append(archive)
            resident.require(len(archive.raw) == self.selection["archive_bytes"]
                and hashlib.sha256(archive.raw).hexdigest() == self.selection["archive_sha256"])
            files,_=pack.archive_contents(archive.raw)
            resident.require(hashlib.sha256(files["release-manifest.json"]).hexdigest() == self.selection["manifest_sha256"])
            manifest=json.loads(files["release-manifest.json"],object_pairs_hook=resident.unique)
            resident.require(manifest["channel"] == "release" and manifest["distribution"] == "portable-linux"
                and manifest["target"] == "x86_64-linux"
                and manifest["provenance"] == {"sourceRevision":None,"sourceDirty":True})
            self.product=manifest["product"]
            self.artifact={"channel":manifest["channel"],"target":manifest["target"],
                "distribution":manifest["distribution"],"provenance":manifest["provenance"],
                "archiveSha256":self.selection["archive_sha256"],"manifestSha256":self.selection["manifest_sha256"]}
            self.plan=install.installation_plan(manifest,files,Path(selected["prefix"]),Path(selected["records"]),
                Path(selected["service_path"]),"linux",daemon_state_dir=Path(selected["runtime_state"]))
            self.expected={str(path):{"sha256":hashlib.sha256(raw).hexdigest(),"mode":mode}
                for path,raw,mode in self.plan}
            resident.require(len(self.expected) == len(self.plan))
            self.runtime=owned.RuntimeFence(selected["runtime_state"],deadline,acquire_lock=acquire_runtime_lock)
            for key in ("prefix","records"):
                path=Path(selected[key])
                fd=resident.open_directory(path,private=True)
                self.parents.append((path,fd,resident.stable(os.fstat(fd))))
                resident.require(not os.listdir(fd))
            unit=Path(selected["service_path"])
            config=self.home/".config/systemd/user"
            for parent in (config,config/"default.target.wants"):
                fd=resident.open_directory(parent)
                self.parents.append((parent,fd,resident.stable(os.fstat(fd))))
                resident.require(os.fstat(fd).st_uid == os.getuid())
                # Other units are metadata only; unchanged and never opened as content.
                before=self.directory_entries(fd)
                resident.require(unit.name not in before)
                self.aliases.append((parent/unit.name,fd,before,None))
            self.recheck()
        except BaseException:
            self.close()
            raise

    def directory_entries(self,fd):
        names=os.listdir(fd)
        resident.require(len(names) <= 4096)
        result={}
        for name in names:
            owned.tick(self.deadline)
            info=os.stat(name,dir_fd=fd,follow_symlinks=False)
            # Directory metadata naturally changes when our exact child link is
            # installed. Type/owner/mode/inode stay fixed; selected parent names
            # and the exact unit leaves are independently fenced below.
            result[name]=resident.stable(info) if stat.S_ISDIR(info.st_mode) else resident.file_identity(info)
        return result

    def parent_recheck(self):
        for path,fd,witness in self.parents:
            current=resident.open_directory(path)
            try:
                resident.require(resident.stable(os.fstat(current)) == witness
                    == resident.stable(os.fstat(fd)))
            finally:
                os.close(current)

    def alias_recheck(self,installed=False):
        for path,fd,before,witness in self.aliases:
            current=self.directory_entries(fd)
            others={name:value for name,value in current.items() if name != path.name}
            resident.require(others == before)
            if installed:
                resident.require(path.name in current)
                info=os.stat(path.name,dir_fd=fd,follow_symlinks=False)
                resident.require(stat.S_ISLNK(info.st_mode) and info.st_uid == os.getuid()
                    and info.st_nlink == 1 and os.readlink(path.name,dir_fd=fd) == self.selected["service_path"]
                    and (witness is None or current[path.name] == witness))
            else:
                resident.require(path.name not in current)

    def empty_destinations(self,locks=False):
        for key,allowed in (("prefix",{".omux-install.lock"}),("records",{"install.lock"})):
            path=Path(self.selected[key])
            fd=next(fd for name,fd,_ in self.parents if name == path)
            resident.require(set(os.listdir(fd)) == (allowed if locks else set()))
            for name in os.listdir(fd):
                info=os.stat(name,dir_fd=fd,follow_symlinks=False)
                resident.require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1 and info.st_size == 0)

    def before_write(self):
        owned.tick(self.deadline)
        self.parent_recheck()
        self.alias_recheck()
        self.runtime.recheck()
        self.empty_destinations(locks=True)

    def inventory_recheck(self):
        prefix=Path(self.selected["prefix"])
        paths={Path(path) for path in self.expected} | {prefix/".omux-install.lock"}
        directories={prefix}
        for path in paths:
            directories.update(parent for parent in path.parents if parent == prefix or prefix in parent.parents)
        seen=set()
        def walk(path,depth=0):
            owned.tick(self.deadline)
            resident.require(depth <= 16)
            fd=resident.open_directory(path)
            try:
                for name in os.listdir(fd):
                    child=path/name
                    info=os.stat(name,dir_fd=fd,follow_symlinks=False)
                    resident.require(info.st_uid == os.getuid())
                    if stat.S_ISDIR(info.st_mode):
                        resident.require(child in directories and not info.st_mode&0o022)
                        walk(child,depth+1)
                    else:
                        resident.require(child in paths and stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
                        if child == prefix/".omux-install.lock":
                            resident.require(stat.S_IMODE(info.st_mode) == 0o600 and info.st_size == 0)
                        seen.add(child)
            finally:
                os.close(fd)
        walk(prefix)
        resident.require(seen == paths)
        record_parent=Path(self.selected["records"])
        fd=next(fd for name,fd,_ in self.parents if name == record_parent)
        resident.require(set(os.listdir(fd)) == {"install.lock",install.RECORD})
        for name in ("install.lock",):
            info=os.stat(name,dir_fd=fd,follow_symlinks=False)
            resident.require(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
                and info.st_uid == os.getuid() and info.st_nlink == 1 and info.st_size == 0)

    def written(self,result):
        """Inside installer rollback scope, before any enable/reload operation."""
        owned.tick(self.deadline)
        self.parent_recheck()
        self.runtime.recheck()
        self.alias_recheck()
        self.inventory_recheck()
        unit=None
        files=[]
        try:
            unit=resident.OwnedUnitCustody(self.selected)
            record=json.loads(unit.files[0][4],object_pairs_hook=resident.unique)
            resident.require(type(result) is dict and record == result and record["serviceActivated"] is False
                and record["product"] == self.product and record["artifact"] == self.artifact
                and len(record["files"]) == len(self.expected)
                and {row["path"]:{"sha256":row["sha256"],"mode":row["mode"]}
                    for row in record["files"]} == self.expected)
            for row in record["files"]:
                public=owned.PublicFile(row["path"],self.deadline,128*1024*1024,owned=True)
                files.append(public)
                resident.require(stat.S_IMODE(os.fstat(public.fd).st_mode) == row["mode"]
                    and hashlib.sha256(public.raw).hexdigest() == row["sha256"])
            self.runtime.recheck()
        finally:
            failure=None
            for held in ([unit] if unit is not None else [])+list(reversed(files)):
                try: held.close()
                except BaseException as error:
                    if failure is None: failure=error
            if failure is not None: raise failure

    def installed(self):
        resident.require(not self.finished and self.software is None)
        self.parent_recheck()
        self.runtime.recheck()
        for public in self.files:
            public.recheck()
        self.alias_recheck(installed=True)
        self.inventory_recheck()
        software=owned.QualifiedExistingEnrollment({**self.selected,
            "existing_archive":self.selection},self.home,self.deadline)
        try:
            record=json.loads(software.unit.files[0][4],object_pairs_hook=resident.unique)
            resident.require(record["serviceActivated"] is False
                and len(record["files"]) == len(self.expected)
                and {row["path"]:{"sha256":row["sha256"],"mode":row["mode"]}
                    for row in record["files"]} == self.expected)
        except BaseException:
            software.close()
            raise
        self.software=software
        self.aliases=[(path,fd,before,resident.file_identity(os.stat(path.name,dir_fd=fd,follow_symlinks=False)))
            for path,fd,before,_ in self.aliases]
        self.finished=True
        self.recheck()
        return self.projection()

    def projection(self):
        return {"installation_prepared":True,"service_enabled_for_login":True,
            "future_login_activation_possible":True,"service_active":False,"service_started":False,
            "source_connected":False,"provider_request_performed":False,"vault_material_read":False,
            "custody_verified":False,"runtime_metadata_preserved":True,
            "archive_sha256":self.selection["archive_sha256"]}

    def recheck(self):
        owned.tick(self.deadline)
        self.parent_recheck()
        self.runtime.recheck()
        self.alias_recheck(installed=self.finished)
        for public in self.files:
            public.recheck()
        if self.finished:
            self.software.recheck()
            self.inventory_recheck()
        else:
            self.empty_destinations()

    def close(self):
        held=[self.software,self.runtime]+list(reversed(self.files))
        self.software=self.runtime=None
        self.files=[]
        parents,self.parents=self.parents,[]
        failure=None
        for value in held:
            if value is not None:
                try:
                    value.close()
                except BaseException as error:
                    if failure is None: failure=error
        for _,fd,_ in reversed(parents):
            try:
                os.close(fd)
            except BaseException as error:
                if failure is None: failure=error
        if failure is not None: raise failure
