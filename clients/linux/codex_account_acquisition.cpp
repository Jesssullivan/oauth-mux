#include "codex_account_acquisition.h"
#include "device_code_dialog.h"
#include <QApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QDialogButtonBox>
#include <QDir>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QProcessEnvironment>
#include <QThread>
#include <QMap>
#include <QUuid>
#include <QVBoxLayout>
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <pwd.h>
#include <stdexcept>
#include <sys/file.h>
#include <dirent.h>
#include <limits>
#include <map>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace {
void require(bool value) { if (!value) throw std::runtime_error("acquisition_invalid"); }
bool hex(const QString &value, int length) {
    if (value.size() != length) return false;
    for (auto c : value) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}
bool handle(const QString &value) { return hex(value,64); }
bool uuid(const QJsonValue &v) {
    return v.isString() && !QUuid(v.toString()).isNull() && QUuid(v.toString()).toString(QUuid::WithoutBraces)==v.toString();
}
bool uniqueJsonKeys(const QByteArray &raw);
bool integer(const QJsonValue &v, qint64 *out) {
    if (!v.isDouble()) return false;
    const auto n = v.toInteger(std::numeric_limits<qint64>::min());
    if (n == std::numeric_limits<qint64>::min() || v.toDouble() != double(n)) return false;
    *out = n; return true;
}
bool future(const QJsonValue &v, qint64 now, bool nullable) {
    qint64 n; return (nullable && v.isNull()) || (integer(v, &n) && n > now);
}
bool keys(const QJsonObject &v, QStringList expected) {
    auto actual = v.keys(); std::sort(expected.begin(), expected.end()); return actual == expected;
}
struct FD {
    int value = -1;
    FD() = default;
    explicit FD(int n) : value(n) {}
    ~FD() { if (value >= 0) ::close(value); }
    FD(const FD &) = delete;
    FD &operator=(const FD &) = delete;
    FD(FD &&v) noexcept : value(v.value) { v.value = -1; }
    FD &operator=(FD &&v) noexcept {
        if (value >= 0) ::close(value); value = v.value; v.value = -1; return *this;
    }
};
bool same(const struct stat &a, const struct stat &b) {
    return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_uid == b.st_uid
        && a.st_mode == b.st_mode && a.st_nlink == b.st_nlink && a.st_size == b.st_size
        && a.st_mtim.tv_sec == b.st_mtim.tv_sec && a.st_mtim.tv_nsec == b.st_mtim.tv_nsec
        && a.st_ctim.tv_sec == b.st_ctim.tv_sec && a.st_ctim.tv_nsec == b.st_ctim.tv_nsec;
}
struct stat metadata(int fd) { struct stat v{}; require(::fstat(fd,&v) == 0); return v; }
QByteArray absolute(const QString &path) {
    const auto p = path.toUtf8();
    require(p.size() > 1 && p[0] == '/' && !p.endsWith('/') && !p.contains('\0')
        && QDir::cleanPath(path) == path);
    for (const auto &part : p.mid(1).split('/')) require(!part.isEmpty() && part != "." && part != "..");
    return p;
}
FD directory(const QString &path, bool privateFinal = true) {
    const auto p = absolute(path);
    FD held(::open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)); require(held.value >= 0);
    for (const auto &part : p.mid(1).split('/')) {
        const auto parent = metadata(held.value);
        require(S_ISDIR(parent.st_mode) && (parent.st_uid == 0 || parent.st_uid == ::getuid())
            && (!(parent.st_mode & 0022) || (parent.st_uid == 0 && (parent.st_mode & S_ISVTX))));
        held = FD(::openat(held.value,part.constData(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
        require(held.value >= 0);
    }
    const auto m = metadata(held.value);
    require(S_ISDIR(m.st_mode) && m.st_uid == ::getuid()
        && (privateFinal ? (m.st_mode & 0777) == 0700 : !(m.st_mode & 0022)));
    return held;
}
void recheckDirectory(const QString &path, int fd, bool privateFinal = true) {
    auto current = directory(path,privateFinal); require(same(metadata(current.value),metadata(fd)));
}
QString homeRoot(const char *xdg, const QString &fallback) {
    const auto value = qgetenv(xdg);
    if (!value.isEmpty()) { const auto path = QString::fromUtf8(value); absolute(path); return path; }
    const auto *user = ::getpwuid(::getuid()); require(user && user->pw_dir);
    const auto home = QString::fromLocal8Bit(user->pw_dir); absolute(home); return home + fallback;
}
FD ensure(const QString &path) {
    const auto p = absolute(path);
    FD held(::open("/",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)); require(held.value >= 0);
    for (const auto &part : p.mid(1).split('/')) {
        const auto parent = metadata(held.value);
        require((parent.st_uid == 0 || parent.st_uid == ::getuid())
            && (!(parent.st_mode & 0022) || (parent.st_uid == 0 && (parent.st_mode & S_ISVTX))));
        if (::mkdirat(held.value,part.constData(),0700) < 0) require(errno == EEXIST);
        held = FD(::openat(held.value,part.constData(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
        require(held.value >= 0);
    }
    const auto m = metadata(held.value); require(m.st_uid == ::getuid() && (m.st_mode & 0777) == 0700);
    return held;
}
QByteArray read(int fd, qint64 maximum) {
    const auto before = metadata(fd);
    require(S_ISREG(before.st_mode) && before.st_nlink == 1 && before.st_uid == ::getuid()
        && !(before.st_mode & 0022) && before.st_size > 0 && before.st_size <= maximum);
    QByteArray result; result.reserve(qsizetype(before.st_size));
    char bytes[65536]; qint64 offset = 0;
    while (offset < before.st_size) {
        const auto count = ::pread(fd,bytes,size_t(std::min(qint64(sizeof(bytes)),before.st_size-offset)),offset);
        require(count > 0); result.append(bytes,count); offset += count;
    }
    require(same(before,metadata(fd))); return result;
}
QJsonObject json(const QByteArray &raw, bool canonical = true) {
    require(raw.endsWith('\n'));
    const auto body = raw.first(raw.size()-1);
    QJsonParseError error; auto doc = QJsonDocument::fromJson(body,&error);
    require(error.error == QJsonParseError::NoError && doc.isObject() && uniqueJsonKeys(body)
        && (!canonical || doc.toJson(QJsonDocument::Compact) == body));
    return doc.object();
}
void entries(int fd, QSet<QString> expected) {
    FD copy(::openat(fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)); require(copy.value>=0);
    DIR *d=::fdopendir(copy.value); require(d); copy.value=-1;
    try {
        int count=0; QSet<QString> actual; errno=0;
        while (auto *entry=::readdir(d)) {
            const QString name=QString::fromUtf8(entry->d_name);
            if (name=="." || name=="..") continue;
            require(++count<=expected.size()); actual.insert(name); errno=0;
        }
        require(errno==0 && actual==expected);
    } catch (...) { ::closedir(d); throw; }
    require(::closedir(d)==0);
}
QString digest(const QByteArray &v) { return QString::fromLatin1(QCryptographicHash::hash(v,QCryptographicHash::Sha256).toHex()); }
int signalOwn(int fd, int signal) {
    return int(::syscall(SYS_pidfd_send_signal,fd,signal,nullptr,0));
}
} // namespace

// Component reader is the only native executable selection boundary.
namespace {
bool uniqueJsonKeys(const QByteArray &raw) {
    qsizetype at = 0; int depth = 0;
    const auto white = [&] { while (at < raw.size() && (raw[at]==' ' || raw[at]=='\n' || raw[at]=='\r' || raw[at]=='\t')) ++at; };
    std::function<bool()> value;
    const auto string = [&](QString *decoded) {
        if (at >= raw.size() || raw[at] != '"') return false;
        const auto start = at++;
        bool escaped = false;
        while (at < raw.size()) {
            const char c = raw[at++];
            if (!escaped && c == '"') {
                if (decoded) {
                    QJsonParseError error;
                    auto d = QJsonDocument::fromJson("["+raw.mid(start,at-start)+"]",&error);
                    if (error.error != QJsonParseError::NoError || !d.isArray()) return false;
                    *decoded = d.array().first().toString();
                }
                return true;
            }
            if (!escaped && c == '\\') escaped = true; else escaped = false;
        }
        return false;
    };
    value = [&] {
        white(); if (at >= raw.size() || ++depth > 32) return false;
        bool result = true;
        if (raw[at]=='{') {
            ++at; white(); QSet<QString> names;
            if (at < raw.size() && raw[at]=='}') ++at;
            else while (true) {
                QString key;
                if (!string(&key) || names.contains(key)) { result=false; break; }
                names.insert(key); white();
                if (at>=raw.size() || raw[at++]!=':' || !value()) { result=false; break; }
                white(); if (at>=raw.size()) { result=false; break; }
                if (raw[at]=='}') { ++at; break; }
                if (raw[at++]!=',') { result=false; break; } white();
            }
        } else if (raw[at]=='[') {
            ++at; white();
            if (at<raw.size() && raw[at]==']') ++at;
            else while (true) {
                if (!value()) { result=false; break; } white();
                if (at>=raw.size()) { result=false; break; }
                if (raw[at]==']') { ++at; break; }
                if (raw[at++]!=',') { result=false; break; }
            }
        } else if (raw[at]=='"') result=string(nullptr);
        else {
            const auto start=at;
            while (at<raw.size() && raw[at]!=',' && raw[at]!='}' && raw[at]!=']'
                && raw[at]!=' ' && raw[at]!='\n' && raw[at]!='\r' && raw[at]!='\t') ++at;
            result=at>start;
        }
        --depth; return result;
    };
    if (!value()) return false; white(); return at==raw.size();
}
struct Pin { QString sha; qint64 bytes; int mode; };
#ifdef OMUX_ACQUISITION_MODELS
// Provider-free reader models substitute only immutable public bytes/lengths.
// The fixed path/mode/API/receipt predicates stay unchanged; no child is launched.
const QByteArray modelRuntimeBytes("synthetic-nonexecutable-component\n");
const QString backendPin = digest(modelRuntimeBytes);
const qint64 backendBytes = modelRuntimeBytes.size();
#else
const QString backendPin = "0b82d7f1535ab98ca2854dad0ac908912c9df56f29bb70c664e18e9956dc4a3f";
const qint64 backendBytes = 318579008;
#endif
const QMap<QString,Pin> runtimePolicy = [] {
    QMap<QString,Pin> rows{
    {"bin/codex",{"4ba3c25cd8821ffc6fac24445750460126c0a0130281dd40fc783ff6c622a4f3",421,0555}},
    {"lib/codex/lib/ld-linux-x86-64.so.2",{"1640ec4d1cfcc3c19430b368cbbb057c5652eac340ecba12cf9dfbe2c3769d07",263056,0555}},
    {"lib/codex/lib/libc.so.6",{"b4ae5be136ce59078de8e83112c2d36e1c7b86894f37dfe7d387b2827eb1120c",2472888,0555}},
    {"lib/codex/lib/libdl.so.2",{"cb6e1b1b5762b30f608096da734d74c1366ecbe1ed830b6a3389a87dc9d35093",17400,0555}},
    {"lib/codex/lib/libm.so.6",{"b0cd1f6a166e255d28375d7dcd91636971a1fa79d33fc67e88e4b7957961bb51",1127520,0555}},
    {"lib/codex/lib/libpthread.so.0",{"bc2abac356f226c4ef4bed4e5b92e25821482a91a0554056cb0e05d1ae3261b0",21656,0555}},
    {"lib/codex/lib/librt.so.1",{"bba80a7e69ba2d2afb60dd38ce251babad50bc2ae048fa8e6d4638df3f857671",17568,0555}},
    {"lib/codex/lib/libutil.so.1",{"1e10f2f88caf7a5f15543a267c2577f8813325231c2b6a1178d32cfbc7ce1e7c",17472,0555}},
    {"lib/codex/libexec/codex.bin",{backendPin,backendBytes,0555}},
    {"lib/codex/share/ca-bundle.crt",{"10608e4255ef550895125880d93c736051e54a7b5dfc746d1ec5bdb81816926f",521594,0444}}
    };
#ifdef OMUX_ACQUISITION_MODELS
    for (auto it=rows.begin();it!=rows.end();++it) { it->sha=digest(modelRuntimeBytes); it->bytes=modelRuntimeBytes.size(); }
#endif
    return rows;
}();
QJsonObject policyJson() {
    QJsonObject result;
    for (auto it=runtimePolicy.begin();it!=runtimePolicy.end();++it)
        result.insert(it.key(),QJsonObject{{"sha256",it->sha},{"bytes",it->bytes},{"mode",it->mode}});
    return result;
}
bool falseValue(const QJsonObject &v,const char *key) { return v.value(key).isBool() && !v.value(key).toBool(); }
bool exactInteger(const QJsonValue &v,qint64 n) { qint64 actual; return integer(v,&actual) && actual==n; }
void deviceReport(const QJsonObject &v) {
    require(exactInteger(v.value("schema_version"),1)
        && v.value("kind")=="omux-retained-device-api-qualification-v1"
        && v.value("status")=="provider-free-device-api-qualified"
        && v.value("archive_sha256")=="0094334d7fd27b81f613ebe734305412bd13f95f1f3396ba2f0396168e5223ad"
        && exactInteger(v.value("archive_bytes"),119923125)
        && v.value("manifest_sha256")=="5626b375f0f3c1818340345c952394ef44b59acbc177ab83f7b910c6fb105678"
        && v.value("source_receipt_sha256")=="e3c6d45bc93119ddf1da8bee6e02de3c7c3a3bbe52bb6d2664eb4b7b3d7b5273"
        && v.value("producer_receipt_sha256")=="545727183aa4e361eb1967fa3599dd30e5fd38a78f68dad9fec74793f8f713ee"
        && v.value("backend_sha256")==backendPin && exactInteger(v.value("backend_bytes"),backendBytes)
        && v.value("loader_sha256")==runtimePolicy.value("lib/codex/lib/ld-linux-x86-64.so.2").sha
        && v.value("version")=="codex 0.0.0" && v.value("runtime_inventory").toObject()==policyJson()
        && v.value("runtime_inventory_sha256")==digest(QJsonDocument(policyJson()).toJson(QJsonDocument::Compact)+'\n')
        && falseValue(v,"native_support") && falseValue(v,"text_continuity") && falseValue(v,"provider_evaluation"));
    const auto api=v.value("device_api").toObject(), request=api.value("request").toObject(), response=api.value("response").toObject();
    require(keys(api,{"method","request","response","provider_invocation"}) && api.value("method")=="account/login/start"
        && falseValue(api,"provider_invocation") && request.value("type")=="object" && response.value("type")=="object");
    const auto props=request.value("properties").toObject(), responseProps=response.value("properties").toObject();
    require(keys(props,{"type"}) && props.value("type").toObject().value("enum").toArray()==QJsonArray{"chatgptDeviceCode"}
        && request.value("required").toArray()==QJsonArray{"type"} && keys(responseProps,{"type","loginId","verificationUrl","userCode"})
        && responseProps.value("type").toObject().value("enum").toArray()==QJsonArray{"chatgptDeviceCode"});
    QSet<QString> required;
    for (const auto &name:response.value("required").toArray()) { require(name.isString()); required.insert(name.toString()); }
    require(required==QSet<QString>{"type","loginId","verificationUrl","userCode"} && response.value("required").toArray().size()==4);
    for (const auto &name:responseProps.keys()) require(responseProps.value(name).toObject().value("type")=="string");
}
} // namespace

class CodexAcquisitionRuntime {
public:
    FD root, recordRoot, leaf, lock, backend, loader, libraries, ca, profile, enrollment, sourceParent, intent, active;
    struct stat intentIdentity{}, activeIdentity{};
    QString dataHome,stateHome,parentPath,recordPath,leafPath,profilePath,sourceParentPath,componentSha,error;
    std::atomic_bool cancelled{false};
    QElapsedTimer clock;
    std::map<QString,FD> files;
    QMap<QString,struct stat> identities, directoryIdentities;
    struct stat rootIdentity{},recordIdentity{},leafIdentity{},lockIdentity{};
    void tick() { require(!cancelled.load() && clock.isValid() && clock.elapsed()<120000); }
    FD member(const QString &relative, bool dir=false) {
        require(!relative.startsWith('/') && !relative.contains('\0'));
        FD held(::dup(leaf.value)); require(held.value>=0);
        const auto parts=relative.toUtf8().split('/');
        for (qsizetype n=0;n<parts.size();++n) {
            require(!parts[n].isEmpty() && parts[n]!="." && parts[n]!="..");
            const auto parent=metadata(held.value);
            require(S_ISDIR(parent.st_mode) && parent.st_uid==::getuid() && (parent.st_mode&0777)==0555);
            held=FD(::openat(held.value,parts[n].constData(),O_RDONLY|O_NOFOLLOW|O_CLOEXEC
                | (n+1<parts.size() || dir ? O_DIRECTORY : O_NONBLOCK)));
            require(held.value>=0);
        }
        return held;
    }
    void fileHash(int fd, const Pin &pin) {
        tick(); const auto before=metadata(fd);
        require(S_ISREG(before.st_mode) && before.st_uid==::getuid() && before.st_nlink==1
            && (before.st_mode&0777)==pin.mode && before.st_size==pin.bytes);
        QCryptographicHash hasher(QCryptographicHash::Sha256);
        char block[1024*1024]; qint64 offset=0;
        while (offset<before.st_size) {
            tick(); const auto count=::pread(fd,block,size_t(std::min(qint64(sizeof(block)),before.st_size-offset)),offset);
            require(count>0); hasher.addData(QByteArrayView(block,count)); offset+=count;
        }
        require(same(before,metadata(fd)) && QString::fromLatin1(hasher.result().toHex())==pin.sha);
    }
    static Pin pin(const QJsonValue &v) {
        require(v.isObject()); const auto row=v.toObject(); qint64 bytes,mode;
        require(keys(row,{"sha256","bytes","mode"}) && handle(row.value("sha256").toString())
            && integer(row.value("bytes"),&bytes) && bytes>0 && bytes<=512*1024*1024
            && integer(row.value("mode"),&mode) && (mode==0444 || mode==0555));
        return {row.value("sha256").toString(),bytes,int(mode)};
    }
    void inventory(int fd,const QString &relative,const QMap<QString,Pin> &expected,int &count) {
        tick(); const auto m=metadata(fd);
        require(S_ISDIR(m.st_mode) && m.st_uid==::getuid() && (m.st_mode&0777)==0555);
        directoryIdentities.insert(relative,m);
        FD duplicate(::openat(fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)); require(duplicate.value>=0);
        DIR *entries=::fdopendir(duplicate.value); require(entries); duplicate.value=-1;
        try {
            errno=0;
            while (auto *entry=::readdir(entries)) {
                const QByteArray name(entry->d_name); if (name=="." || name=="..") continue;
                require(++count<=40);
                const auto path=relative.isEmpty()?QString::fromUtf8(name):relative+"/"+QString::fromUtf8(name);
                struct stat observed{}; require(::fstatat(fd,name.constData(),&observed,AT_SYMLINK_NOFOLLOW)==0);
                if (S_ISDIR(observed.st_mode)) {
                    bool needed=false; for (const auto &key:expected.keys()) if (key.startsWith(path+"/")) needed=true;
                    require(needed); FD child(::openat(fd,name.constData(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
                    require(child.value>=0); inventory(child.value,path,expected,count);
                } else require(S_ISREG(observed.st_mode) && expected.contains(path));
                errno=0;
            }
            require(errno==0);
        } catch (...) { ::closedir(entries); throw; }
        require(::closedir(entries)==0);
    }
    void prepare() {
        clock.start();
        try {
            dataHome=homeRoot("XDG_DATA_HOME","/.local/share"); stateHome=homeRoot("XDG_STATE_HOME","/.local/state");
            parentPath=dataHome+"/omux-acquisition/codex"; recordPath=stateHome+"/omux-acquisition/codex";
            const auto selectedPath=parentPath+"/current.json";
            // ENOENT is reported before opening any native input.
            if (!QFileInfo::exists(selectedPath)) { error="Account sign-in component is not installed. Connect an existing source, or install the separately qualified acquisition component."; return; }
            root=directory(parentPath); recordRoot=directory(recordPath);
            rootIdentity=metadata(root.value); recordIdentity=metadata(recordRoot.value);
            entries(root.value,{".lock","current.json",backendPin}); entries(recordRoot.value,{"install.json","producer.json"});
            lock=FD(::openat(root.value,".lock",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
            require(lock.value>=0); lockIdentity=metadata(lock.value);
            require(S_ISREG(lockIdentity.st_mode) && lockIdentity.st_uid==::getuid()
                && lockIdentity.st_nlink==1 && (lockIdentity.st_mode&0777)==0600
                && ::flock(lock.value,LOCK_SH|LOCK_NB)==0);
            FD selected(::openat(root.value,"current.json",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
            FD record(::openat(recordRoot.value,"install.json",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
            require(selected.value>=0 && record.value>=0 && (metadata(selected.value).st_mode&0777)==0600
                && (metadata(record.value).st_mode&0777)==0600);
            const auto selectedRaw=read(selected.value,65536), recordRaw=read(record.value,65536);
            const auto selection=json(selectedRaw), installation=json(recordRaw);
            require(keys(selection,{"schema_version","scope","component_sha256","backend_sha256"})
                && exactInteger(selection.value("schema_version"),1)
                && selection.value("scope")=="omux-codex-device-acquisition-selection-v1"
                && selection.value("backend_sha256")==backendPin && handle(selection.value("component_sha256").toString()));
            leafPath=parentPath+"/"+backendPin; leaf=directory(leafPath,false); leafIdentity=metadata(leaf.value);
            require((leafIdentity.st_mode&0777)==0555);
            auto descriptor=member("component.json"); require((metadata(descriptor.value).st_mode&0777)==0444);
            const auto descriptorRaw=read(descriptor.value,65536); const auto d=json(descriptorRaw);
            componentSha=digest(descriptorRaw);
            require(digest(descriptorRaw)==selection.value("component_sha256")
                && keys(d,{"schema_version","scope","purpose","system","backend_sha256","files","qualification",
                    "version","renewal_owner","native_support","text_continuity","provider_evaluation"})
                && exactInteger(d.value("schema_version"),1) && d.value("scope")=="omux-codex-device-acquisition-component-v1"
                && d.value("purpose")=="device-account-acquisition" && d.value("system")=="x86_64-linux"
                && d.value("backend_sha256")==backendPin && d.value("version")=="codex 0.0.0"
                && d.value("renewal_owner")=="native" && falseValue(d,"native_support") && falseValue(d,"text_continuity")
                && falseValue(d,"provider_evaluation") && d.value("files").isObject());
            QMap<QString,Pin> expected;
            expected.insert("codex",{backendPin,backendBytes,0555});
            for (auto it=runtimePolicy.begin();it!=runtimePolicy.end();++it) expected.insert("runtime/"+it.key(),it.value());
            const auto rows=d.value("files").toObject();
            require(rows.size()==13 && rows.contains("native-source-receipt.json") && rows.contains("qualification.json"));
            for (auto it=rows.begin();it!=rows.end();++it) {
                const auto actual=pin(it.value());
                if (expected.contains(it.key())) {
                    const auto p=expected.value(it.key()); require(p.sha==actual.sha && p.bytes==actual.bytes && p.mode==actual.mode);
                } else {
                    require((it.key()=="native-source-receipt.json" || it.key()=="qualification.json") && actual.mode==0444
                        && actual.bytes<=1024*1024); expected.insert(it.key(),actual);
                }
            }
            require(expected.size()==13);
            expected.insert("component.json",{digest(descriptorRaw),descriptorRaw.size(),0444});
            auto recordFiles=rows;
            recordFiles.insert("component.json",QJsonObject{{"sha256",digest(descriptorRaw)},{"bytes",descriptorRaw.size()},{"mode",0444}});
            require(keys(installation,{"schema_version","scope","component_sha256","backend_sha256","data_home","state_home",
                "qualification_sha256","device_receipt_sha256","descriptor_bytes","files","producer"})
                && exactInteger(installation.value("schema_version"),1)
                && installation.value("scope")=="omux-codex-device-acquisition-install-v1"
                && installation.value("component_sha256")==selection.value("component_sha256")
                && installation.value("backend_sha256")==backendPin && installation.value("data_home")==dataHome
                && installation.value("state_home")==stateHome && exactInteger(installation.value("descriptor_bytes"),descriptorRaw.size())
                && installation.value("files").toObject()==recordFiles
                && installation.value("qualification_sha256")==expected.value("qualification.json").sha
                && installation.value("device_receipt_sha256")==expected.value("native-source-receipt.json").sha);
            int count=0; inventory(leaf.value,"",expected,count);
            for (auto it=expected.begin();it!=expected.end();++it) {
                auto fd=member(it.key()); fileHash(fd.value,it.value()); identities.insert(it.key(),metadata(fd.value));
                files.emplace(it.key(),std::move(fd));
            }
            const auto innerRaw=read(files.at("native-source-receipt.json").value,1024*1024);
            const auto outerRaw=read(files.at("qualification.json").value,1024*1024);
            const auto inner=json(innerRaw), outer=json(outerRaw,false), q=d.value("qualification").toObject();
            require(keys(q,{"inner","outer"}) && keys(q.value("inner").toObject(),{"sha256","bytes"})
                && keys(q.value("outer").toObject(),{"sha256","bytes","id","source_commit","graph_sha256"}));
            const auto iq=q.value("inner").toObject(), oq=q.value("outer").toObject();
            require(iq.value("sha256")==digest(innerRaw) && exactInteger(iq.value("bytes"),innerRaw.size())
                && oq.value("sha256")==digest(outerRaw) && exactInteger(oq.value("bytes"),outerRaw.size())
                && oq.value("id")==outer.value("id") && oq.value("source_commit")==outer.value("source_commit")
                && oq.value("graph_sha256")==outer.value("graph_sha256") && handle(oq.value("graph_sha256").toString())
                && outer.value("artifact_epoch")==outer.value("id") && uuid(outer.value("id"))
                && hex(outer.value("source_commit").toString(),40) && outer.value("source_dirty")=="false"
                && outer.value("profile")=="standard" && outer.value("manager")=="system" && outer.value("verb")=="test"
                && outer.value("targets").toArray()==QJsonArray{"//tools:codex_retained_device_api_qualification"}
                && exactInteger(outer.value("exit"),0) && exactInteger(outer.value("workload_exit"),0)
                && outer.value("controller_failure").isNull() && outer.value("descendants_empty").isBool()
                && outer.value("descendants_empty").toBool() && outer.value("cleanup").toObject().value("state")=="empty"
                && outer.value("test_evidence").toObject().value("state")=="preserved"
                && outer.value("codex_owner_runtime_input").toObject().value("verified_after_cleanup").isBool()
                && outer.value("codex_owner_runtime_input").toObject().value("verified_after_cleanup").toBool());
            const auto producer=installation.value("producer").toObject();
            require(keys(producer,{"sha256","bytes","id","source_commit","graph_sha256"}));
            FD producerFD(::openat(recordRoot.value,"producer.json",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
            require(producerFD.value>=0 && (metadata(producerFD.value).st_mode&0777)==0600);
            const auto producerRaw=read(producerFD.value,1024*1024); const auto p=json(producerRaw,false);
            require(producer.value("sha256")==digest(producerRaw) && exactInteger(producer.value("bytes"),producerRaw.size())
                && producer.value("id")==p.value("id") && uuid(p.value("id")) && p.value("id")==p.value("artifact_epoch")
                && hex(p.value("source_commit").toString(),40)
                && producer.value("source_commit")==p.value("source_commit")
                && producer.value("graph_sha256")==p.value("graph_sha256") && handle(producer.value("graph_sha256").toString())
                && p.value("source_dirty")=="false" && p.value("profile")=="codex-device-component" && p.value("manager")=="system" && p.value("verb")=="test"
                && p.value("targets").toArray()==QJsonArray{"//delivery:codex_device_acquisition_component"}
                && exactInteger(p.value("exit"),0) && exactInteger(p.value("workload_exit"),0)
                && p.value("controller_failure").isNull() && p.value("descendants_empty").isBool()
                && p.value("descendants_empty").toBool() && p.value("cleanup").toObject().value("state")=="empty"
                && p.value("test_evidence").toObject().value("state")=="preserved");
            const auto component=p.value("codex_device_component").toObject(),
                input=component.value("input").toObject(), output=component.value("output").toObject();
            qint64 originalEntry, originalDeadline;
            require(keys(component,{"input","output","verified_after_cleanup","original_entry_monotonic_ns","original_deadline_monotonic_ns"})
                && integer(component.value("original_entry_monotonic_ns"),&originalEntry) && originalEntry>0
                && integer(component.value("original_deadline_monotonic_ns"),&originalDeadline) && originalDeadline>originalEntry
                && originalDeadline-originalEntry==1200LL*1000000000LL
                && component.value("verified_after_cleanup").isBool() && component.value("verified_after_cleanup").toBool()
                && keys(input,{"scope","action","manifest_sha256","provider_request_performed","native_execution_performed",
                    "resident_effects_authorized","continuity_qualified","credential_contents_read"})
                && falseValue(input,"provider_request_performed") && falseValue(input,"native_execution_performed")
                && falseValue(input,"resident_effects_authorized") && falseValue(input,"continuity_qualified")
                && falseValue(input,"credential_contents_read")
                && input.value("scope")=="provider-free-codex-device-component" && input.value("action")=="produce"
                && handle(input.value("manifest_sha256").toString())
                && keys(output,{"action_epoch","controller_graph_sha256","manifest_sha256","action",
                    "provider_request_performed","resident_enrollment_completed","continuity_qualified"})
                && output.value("action")=="produce" && output.value("action_epoch")==p.value("id")
                && output.value("controller_graph_sha256")==p.value("graph_sha256")
                && output.value("manifest_sha256")==input.value("manifest_sha256")
                && falseValue(output,"provider_request_performed") && falseValue(output,"resident_enrollment_completed")
                && falseValue(output,"continuity_qualified"));
            identities.insert("@producer",metadata(producerFD.value)); files.emplace("@producer",std::move(producerFD));
            deviceReport(inner);
            identities.insert("@selection",metadata(selected.value)); files.emplace("@selection",std::move(selected));
            identities.insert("@record",metadata(record.value)); files.emplace("@record",std::move(record));
            backend=FD(::dup(files.at("codex").value));
            loader=FD(::dup(files.at("runtime/lib/codex/lib/ld-linux-x86-64.so.2").value));
            ca=FD(::dup(files.at("runtime/lib/codex/share/ca-bundle.crt").value));
            libraries=member("runtime/lib/codex/lib",true);
            require(backend.value>=0 && loader.value>=0 && ca.value>=0);
            recheck();
        } catch (...) {
            error=cancelled.load()?"Sign-in preparation cancelled.":"Account sign-in component is invalid or lacks its independent device API qualification. No provider sign-in was started.";
        }
    }
    void recheck() {
        require(!cancelled.load());
        recheckDirectory(parentPath,root.value); recheckDirectory(recordPath,recordRoot.value);
        entries(root.value,{".lock","current.json",backendPin}); entries(recordRoot.value,{"install.json","producer.json"});
        require(same(rootIdentity,metadata(root.value)) && same(recordIdentity,metadata(recordRoot.value)));
        recheckDirectory(leafPath,leaf.value,false); require(same(leafIdentity,metadata(leaf.value)));
        for (auto it=directoryIdentities.begin();it!=directoryIdentities.end();++it) {
            FD dir=it.key().isEmpty()?FD(::dup(leaf.value)):member(it.key(),true);
            require(dir.value>=0 && same(it.value(),metadata(dir.value)));
        }
        FD current(::openat(root.value,".lock",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
        require(current.value>=0 && same(metadata(current.value),lockIdentity) && same(metadata(lock.value),lockIdentity));
        for (const auto &[name,fd]:files) {
            FD named;
            if (name=="@selection") named=FD(::openat(root.value,"current.json",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
            else if (name=="@producer") named=FD(::openat(recordRoot.value,"producer.json",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
            else if (name=="@record") named=FD(::openat(recordRoot.value,"install.json",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
            else named=member(name);
            require(named.value>=0 && same(metadata(named.value),identities.value(name))
                && same(metadata(fd.value),identities.value(name)));
        }
    }
};


bool CodexAccountAcquisition::parseNativeFrame(const QByteArray &raw,QJsonObject *out) {
    if (!out || raw.isEmpty() || raw.size()>65536 || !uniqueJsonKeys(raw)) return false;
    QJsonParseError error; const auto doc=QJsonDocument::fromJson(raw,&error);
    if (error.error!=QJsonParseError::NoError || !doc.isObject()) return false;
    *out=doc.object(); return true;
}
bool CodexAccountAcquisition::usableEnrollment(const QJsonObject &s, const QString &source,
                                               const QString &job, qint64 generation, qint64 now) {
    if (now < 0 || !handle(source) || !s.value("custody_available").isBool()
        || !s.value("custody_available").toBool() || !s.value("sources").isArray()
        || !s.value("accounts").isArray() || !s.value("grants").isArray() || !s.value("jobs").isArray()) return false;
    QJsonObject origin, account, grant, operation;
    int origins = 0, accounts = 0, grants = 0, jobs = 0;
    for (const auto &v : s.value("sources").toArray()) {
        if (!v.isObject()) return false;
        if (v.toObject().value("id").toString() == source) { origin = v.toObject(); ++origins; }
    }
    qint64 authorized;
    if (origins != 1 || !keys(origin,{"id","provider","label","kind","status","authorized_at","authorized_until"})
        || !origin.value("label").isString() || origin.value("provider") != "codex" || origin.value("kind") != "native_store"
        || (origin.value("status") != "connected" && origin.value("status") != "detached")
        || !integer(origin.value("authorized_at"),&authorized) || authorized > now
        || !future(origin.value("authorized_until"),now,true)) return false;
    for (const auto &v : s.value("accounts").toArray()) {
        if (!v.isObject()) return false;
        const auto a = v.toObject();
        if (a.value("source_ids").toArray().contains(source)) { account = a; ++accounts; }
    }
    const auto identity = account.value("identity").toObject();
    if (accounts != 1 || !handle(account.value("id").toString()) || account.value("lifecycle") != "active"
        || !keys(identity,{"provider","verified"}) || identity.value("provider") != "codex"
        || !identity.value("verified").isBool() || !identity.value("verified").toBool()) return false;
    for (const auto &v : s.value("grants").toArray()) {
        if (!v.isObject()) return false;
        if (v.toObject().value("source_id").toString() == source) { grant = v.toObject(); ++grants; }
    }
    qint64 grantGeneration;
    if (grants != 1 || !handle(grant.value("id").toString())
        || grant.value("account_id") != account.value("id") || grant.value("credential_kind") != "oauth_access"
        || grant.value("ownership") != "external" || grant.value("status") != "ready"
        || grant.value("audience") != "https://chatgpt.com" || !grant.value("purposes").toArray().contains("request")
        || !future(grant.value("provider_expires_at"),now,true) || !future(grant.value("custody_expires_at"),now,false)
        || !integer(grant.value("generation"),&grantGeneration) || grantGeneration <= 0) return false;
    for (const auto &v : s.value("jobs").toArray()) {
        if (!v.isObject()) return false;
        if (v.toObject().value("id").toString() == job) { operation = v.toObject(); ++jobs; }
    }
    qint64 current;
    return !job.isEmpty() && generation > 0 && jobs == 1 && operation.value("kind") == "enrollment"
        && operation.value("status") == "completed" && integer(operation.value("operation_generation"),&current)
        && current == generation;
}

CodexAccountAcquisition::CodexAccountAcquisition(OmuxClient &client, QWidget *parent)
    : QObject(parent), client_(client), parent_(parent) {
    deadline_.setInterval(100);
    QObject::connect(&deadline_,&QTimer::timeout,this,[this] {
        if (!within() || ((phase_ == Phase::Initialize || phase_ == Phase::StartLogin) && !within(30000))) {
            if (native_.state() != QProcess::NotRunning) { completed_ = false; stopNative(false); }
            else finish("Sign-in expired. The private native profile is retained; no enrollment success is claimed.");
        }
    });
    escalation_.setSingleShot(true);
    QObject::connect(&escalation_,&QTimer::timeout,this,[this] {
        if (native_.state() == QProcess::NotRunning) return;
        if (++stopStep_ == 1) {
            if (pidfd_ < 0 || signalOwn(pidfd_,SIGKILL) != 0) cleanupFailed_ = true;
            escalation_.start(5000);
        } else cleanupFailed_ = true;
        // QProcess completion must reap the child before component/profile custody
        // is released. A still-live child is never reported as successful.
        status("Stopping the owned sign-in process; its outcome remains unproved.");
    });
    pollTimer_.setInterval(500);
    QObject::connect(&pollTimer_,&QTimer::timeout,this,[this] { poll(); });
    QObject::connect(&native_,&QProcess::started,this,[this] {
        pidfd_ = int(::syscall(SYS_pidfd_open,native_.processId(),0));
        if (pidfd_ < 0) { native_.kill(); cleanupFailed_ = true; stopNative(false); return; }
        if (phase_==Phase::Stopping || !within() || !custodyAvailable_) {
            completed_=false; phase_=Phase::Stopping;
            if (signalOwn(pidfd_,SIGTERM)!=0) cleanupFailed_=true;
            escalation_.start(5000); return;
        }
        phase_ = Phase::Initialize;
        send({{"id",1},{"method","initialize"},{"params",QJsonObject{
            {"clientInfo",QJsonObject{{"name","omux-account-acquisition"},{"title",QJsonValue()},{"version","1"}}},
            {"capabilities",QJsonObject{{"experimentalApi",false},{"requestAttestation",false}}}}}});
    });
    QObject::connect(&native_,&QProcess::readyReadStandardOutput,this,[this] { receive(); });
    // Native diagnostics may contain provider data. Discard rather than project.
    QObject::connect(&native_,&QProcess::readyReadStandardError,this,[this] {
        auto bytes = native_.readAllStandardError(); bytes.fill('\0');
    });
    QObject::connect(&native_,qOverload<int,QProcess::ExitStatus>(&QProcess::finished),this,
        [this](int code,QProcess::ExitStatus result) { nativeStopped(code,result); });
    QObject::connect(&native_,&QProcess::errorOccurred,this,[this](QProcess::ProcessError error) {
        if (error == QProcess::FailedToStart) finish("The qualified acquisition component could not start. No account was enrolled.");
    });
}
CodexAccountAcquisition::~CodexAccountAcquisition() {
    QObject::disconnect(&native_,nullptr,this,nullptr);
    deadline_.stop(); escalation_.stop(); pollTimer_.stop(); clearPrompt();
    native_.closeWriteChannel();
    if (native_.state() != QProcess::NotRunning) {
        if (pidfd_ >= 0) signalOwn(pidfd_,SIGTERM); else native_.terminate();
        if (!native_.waitForFinished(5000)) {
            if (pidfd_ >= 0) signalOwn(pidfd_,SIGKILL); else native_.kill();
            native_.waitForFinished(5000);
        }
    }
    if (pidfd_ >= 0) ::close(pidfd_);
    buffer_.fill('\0'); loginID_.fill(QChar('\0'));
}
bool CodexAccountAcquisition::within(qint64 ms) const { return elapsed_.isValid() && elapsed_.elapsed() < ms; }
void CodexAccountAcquisition::status(const QString &value) { if (onStatus) onStatus(value); }
void CodexAccountAcquisition::start(bool custodyAvailable) {
    if (busy()) return;
    if (QGuiApplication::platformName() != "wayland") {
        status("Account sign-in needs the normal local Wayland desktop. No provider sign-in was started."); return;
    }
    if (!client_.ready() || client_.hasUncertainOperations() || !custodyAvailable) {
        status("Restore the daemon's credential custody before signing in. No provider sign-in was started."); return;
    }
    custodyAvailable_ = custodyAvailable;
    phase_ = Phase::Preparing; elapsed_.start(); deadline_.start();
    completed_ = cleanupFailed_ = pollPending_ = recovering_ = false; received_ = messages_ = stopStep_ = 0; buffer_.clear();
    loginID_.clear(); sourceID_.clear(); jobID_.clear(); jobGeneration_ = 0;
    if (onChanged) onChanged();
    status("Verifying the separate account-acquisition component…");
    // Hashing the retained executable does not block the Sources tab.
    auto runtime = std::make_shared<CodexAcquisitionRuntime>();
    runtime_ = runtime;
    try {
        runtime->sourceParentPath=homeRoot("XDG_STATE_HOME","/.local/state")+"/omux-native-sources/codex";
        runtime->sourceParent=ensure(runtime->sourceParentPath);
        // Recovering an already admitted operation requires no installed native
        // component, no credential reads and no provider acquisition.
        if (recoverIntent()) return;
    } catch (...) { finish("The retained enrollment intent has invalid custody. No effect was dispatched."); return; }
    if (!client_.supportsEnrollmentGeneration()) {
        finish("This daemon lacks generation-bound account enrollment. Upgrade the Omux daemon before starting a new sign-in."); return;
    }
    auto *worker = QThread::create([runtime] { runtime->prepare(); });
    QObject::connect(worker,&QThread::finished,this,[this,runtime] {
        if (phase_ != Phase::Preparing || runtime_ != runtime) return;
        if (!runtime->error.isEmpty()) { finish(runtime->error); return; }
        if (!within() || !custodyAvailable_ || !client_.ready() || !client_.supportsEnrollmentGeneration() || client_.hasUncertainOperations()) {
            finish("Credential custody or control readiness changed. No provider sign-in was started."); return;
        }
        try { launch(); } catch (...) { finish("The private sign-in context could not be established. No account was enrolled."); }
    });
    QObject::connect(worker,&QThread::finished,worker,&QObject::deleteLater);
    worker->start();
}
void CodexAccountAcquisition::launch() {
    require(runtime_ && within());
    const auto parentPath = homeRoot("XDG_STATE_HOME","/.local/state") + "/omux-native-sources/codex";
    auto parent = ensure(parentPath);
    runtime_->sourceParentPath=parentPath; runtime_->sourceParent=FD(::dup(parent.value));
    if (recoverIntent()) return;
    const auto name = "native-login-" + QUuid::createUuid().toString(QUuid::WithoutBraces).remove('-').toLower();
    require(::mkdirat(parent.value,name.toUtf8().constData(),0700) == 0);
    profile_ = parentPath + "/" + name;
    runtime_->profile = directory(profile_);
    runtime_->profilePath = profile_;
    recheckDirectory(parentPath,parent.value);
    QProcessEnvironment env;
    env.insert("LANG","C.UTF-8"); env.insert("LC_ALL","C.UTF-8"); env.insert("PATH","/nonexistent");
    env.insert("HOME",profile_); env.insert("CODEX_HOME",profile_); env.insert("RUST_LOG","off");
    for (const auto *key : {"XDG_CONFIG_HOME","XDG_DATA_HOME","XDG_CACHE_HOME","XDG_STATE_HOME","XDG_RUNTIME_DIR"}) {
        const auto child = QByteArray(key).toLower();
        require(::mkdirat(runtime_->profile.value,child.constData(),0700) == 0);
        env.insert(key,profile_+"/"+QString::fromLatin1(child));
    }
    env.insert("SSL_CERT_FILE",QString("/proc/self/fd/%1").arg(runtime_->ca.value));
    env.insert("CURL_CA_BUNDLE",env.value("SSL_CERT_FILE"));
    require(::fsync(runtime_->profile.value)==0 && ::fsync(parent.value)==0);
    runtime_->recheck();
    native_.setProcessEnvironment(env); native_.setWorkingDirectory(profile_);
    native_.setStandardErrorFile(QProcess::nullDevice());
    const int loader = runtime_->loader.value, backend = runtime_->backend.value,
        library = runtime_->libraries.value, ca = runtime_->ca.value;
    native_.setProgram(QString("/proc/self/fd/%1").arg(loader));
    native_.setArguments({"--inhibit-cache","--library-path",QString("/proc/self/fd/%1").arg(library),
        "--argv0","codex",QString("/proc/self/fd/%1").arg(backend),"-c","cli_auth_credentials_store=\"file\"",
        "app-server","--listen","stdio://","--strict-config"});
    const auto originalParent=::getpid();
    native_.setChildProcessModifier([loader,backend,library,ca,originalParent] {
        ::umask(0077);
        struct rlimit core{0,0}; if (::setrlimit(RLIMIT_CORE,&core) != 0) _exit(126);
        if (::prctl(PR_SET_PDEATHSIG,SIGKILL) != 0 || ::getppid() != originalParent) _exit(126);
        for (int fd : {loader,backend,library,ca}) {
            const int flags = ::fcntl(fd,F_GETFD);
            if (flags < 0 || ::fcntl(fd,F_SETFD,flags & ~FD_CLOEXEC) < 0) _exit(126);
        }
    });
    native_.start();
}
void CodexAccountAcquisition::send(const QJsonObject &v) {
    if (!within() || native_.state() != QProcess::Running) { stopNative(false); return; }
    auto bytes = QJsonDocument(v).toJson(QJsonDocument::Compact)+'\n';
    if (native_.write(bytes) != bytes.size()) stopNative(false);
    bytes.fill('\0');
}
void CodexAccountAcquisition::receive() {
    auto bytes = native_.readAllStandardOutput();
    received_ += bytes.size();
    if (received_ > 1024*1024 || buffer_.size()+bytes.size() > 65536) { bytes.fill('\0'); stopNative(false); return; }
    buffer_ += bytes; bytes.fill('\0');
    while (buffer_.contains('\n')) {
        auto row = buffer_.first(buffer_.indexOf('\n')); buffer_.remove(0,row.size()+1);
        QJsonObject value;
        // Accept native field ordering, but refuse duplicate decoded keys.
        if (++messages_ > 256 || !parseNativeFrame(row,&value)) { row.fill('\0'); stopNative(false); return; }
        row.fill('\0'); frame(value);
        if (phase_ == Phase::Stopping) { buffer_.fill('\0'); buffer_.clear(); return; }
    }
}
void CodexAccountAcquisition::frame(const QJsonObject &v) {
    if (!within() || !custodyAvailable_) { stopNative(false); return; }
    if ((phase_ == Phase::Initialize || phase_ == Phase::StartLogin) && !v.contains("id")) return;
    if (phase_ == Phase::Initialize) {
        if (v.value("id") != 1 || !v.value("result").isObject() || v.contains("error")) { stopNative(false); return; }
        send({{"method","initialized"},{"params",QJsonObject()}});
        phase_ = Phase::StartLogin;
        send({{"id",2},{"method","account/login/start"},{"params",QJsonObject{{"type","chatgptDeviceCode"}}}});
    } else if (phase_ == Phase::StartLogin) {
        const auto r = v.value("result").toObject();
        NativeDevicePrompt prompt;
        const auto raw = QJsonDocument(QJsonObject{{"verification_url",r.value("verificationUrl")},
            {"user_code",r.value("userCode")}}).toJson(QJsonDocument::Compact);
        if (v.value("id") != 2 || v.contains("error") || r.value("type") != "chatgptDeviceCode"
            || !r.value("loginId").isString() || r.value("loginId").toString().isEmpty()
            || r.value("loginId").toString().size() > 256 || !parseNativeDevicePrompt(raw,&prompt)) { stopNative(false); return; }
        loginID_ = r.value("loginId").toString();
        prompt_ = new QDialog(parent_); prompt_->setWindowTitle("Sign in to a Codex account");
        auto *layout = new QVBoxLayout(prompt_);
        auto *instructions = new QLabel("Open the address in your browser and enter this one-time code. Choose the account you want to connect. Never share the code.",prompt_);
        instructions->setWordWrap(true); instructions->setTextFormat(Qt::PlainText); layout->addWidget(instructions);
        for (const auto &text : {prompt.verificationUrl,prompt.userCode}) {
            auto *label = new QLabel(text,prompt_); label->setTextFormat(Qt::PlainText);
            label->setTextInteractionFlags(Qt::NoTextInteraction); layout->addWidget(label);
        }
        auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel,prompt_); layout->addWidget(buttons);
        QObject::connect(buttons,&QDialogButtonBox::rejected,this,[this] { cancel(); });
        QObject::connect(prompt_,&QDialog::rejected,this,[this] { cancel(); });
        prompt.userCode.fill(QChar('\0')); phase_ = Phase::Consent;
        prompt_->show(); prompt_->raise(); prompt_->activateWindow();
        QTimer::singleShot(0,this,[this] { if (phase_==Phase::Consent && (!prompt_ || !prompt_->isVisible())) stopNative(false); });
        status("Waiting for your device consent. Identity and enrollment are not yet verified.");
    } else if (phase_ == Phase::Consent) {
        if (v.contains("id")) { stopNative(false); return; }
        if (v.value("method") == "account/login/completed") {
            const auto p = v.value("params").toObject();
            if (p.value("loginId") != loginID_ || !p.value("success").isBool() || !p.value("success").toBool()) {
                stopNative(false); return;
            }
            stopNative(true);
        }
    }
}
void CodexAccountAcquisition::clearPrompt() {
    if (!prompt_) return;
    for (auto *label : prompt_->findChildren<QLabel *>()) label->clear();
    QObject::disconnect(prompt_,nullptr,this,nullptr); prompt_->hide(); prompt_->deleteLater(); prompt_ = nullptr;
    loginID_.fill(QChar('\0')); loginID_.clear(); buffer_.fill('\0'); buffer_.clear();
}
void CodexAccountAcquisition::stopNative(bool success) {
    if (phase_ == Phase::Stopping) return;
    completed_ = success; phase_ = Phase::Stopping; clearPrompt(); native_.closeWriteChannel();
    if (native_.state() == QProcess::NotRunning) { nativeStopped(-1,QProcess::CrashExit); return; }
    // EOF permits an orderly app-server exit. Cancellation terminates only our
    // held child; a successful login still needs actual clean exit and readback.
    if (!success && pidfd_ >= 0 && signalOwn(pidfd_,SIGTERM) != 0) cleanupFailed_ = true;
    escalation_.start(5000);
}
void CodexAccountAcquisition::nativeStopped(int code,QProcess::ExitStatus result) {
    escalation_.stop();
    if (pidfd_ >= 0) { if (::close(pidfd_) != 0) cleanupFailed_ = true; pidfd_ = -1; }
    clearPrompt();
    if (!completed_ || cleanupFailed_ || code != 0 || result != QProcess::NormalExit || !within()
        || !custodyAvailable_ || !client_.ready() || client_.hasUncertainOperations()) {
        finish("Sign-in did not establish an enrolled account. The owned profile is retained; no request was replayed."); return;
    }
    try {
        runtime_->recheck(); recheckDirectory(profile_,runtime_->profile.value);
        FD auth(::openat(runtime_->profile.value,"auth.json",O_PATH|O_NOFOLLOW|O_CLOEXEC));
        require(auth.value >= 0); const auto m = metadata(auth.value);
        require(S_ISREG(m.st_mode) && m.st_uid == ::getuid() && m.st_nlink == 1
            && ((m.st_mode & 0777) == 0600 || (m.st_mode & 0777) == 0400) && m.st_size > 0 && m.st_size <= 128*1024);
    } catch (...) { finish("The native sign-in output failed private custody verification. No enrollment was requested."); return; }
    connectSource();
}
void CodexAccountAcquisition::checkpoint(const QString &phase) {
    require(runtime_ && within());
    recheckDirectory(runtime_->sourceParentPath,runtime_->sourceParent.value);
    if (runtime_->active.value>=0) {
        FD active(::openat(runtime_->sourceParent.value,"active.json",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
        require(active.value>=0 && same(metadata(active.value),runtime_->activeIdentity)
            && same(metadata(runtime_->active.value),runtime_->activeIdentity));
    } else {
        struct stat absent{};
        require(::fstatat(runtime_->sourceParent.value,"active.json",&absent,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT);
    }
    recheckDirectory(profile_,runtime_->profile.value);
    if (runtime_->enrollment.value < 0) {
        require(::mkdirat(runtime_->profile.value,"enrollment-inputs",0700)==0);
        runtime_->enrollment=FD(::openat(runtime_->profile.value,"enrollment-inputs",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC));
        require(runtime_->enrollment.value>=0);
    }
    recheckDirectory(profile_+"/enrollment-inputs",runtime_->enrollment.value);
    const QJsonObject record{{"schema_version",1},{"scope","omux-codex-local-enrollment-intent-v1"},
        {"component_sha256",runtime_->componentSha},{"codex_home",profile_},{"renewal_owner","native"},{"endpoint",client_.socketPath()},
        {"connect_operation_id",connectID_},{"enrollment_operation_id",enrollmentID_},{"phase",phase},
        {"source_id",sourceID_.isEmpty()?QJsonValue():QJsonValue(sourceID_)},
        {"job_id",jobID_.isEmpty()?QJsonValue():QJsonValue(jobID_)},
        {"job_generation",jobGeneration_>0?QJsonValue(jobGeneration_):QJsonValue()},
        {"connect_params",QJsonObject{{"kind","native_store"},{"provider","codex"},{"label","Codex account"},
            {"source_path",profile_+"/auth.json"},{"operation_id",connectID_},{"expected_revision",connectRevision_}}},
        {"enrollment_params",QJsonObject{{"source_id",sourceID_.isEmpty()?QJsonValue():QJsonValue(sourceID_)},
            {"include_operation_generation",true},{"operation_id",enrollmentID_},
            {"expected_revision",enrollmentRevision_>=0?QJsonValue(enrollmentRevision_):QJsonValue()}}}};
    if (runtime_->intent.value>=0) {
        entries(runtime_->enrollment.value,{"input.json"});
        FD named(::openat(runtime_->enrollment.value,"input.json",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
        require(named.value>=0 && same(metadata(named.value),runtime_->intentIdentity)
            && same(metadata(runtime_->intent.value),runtime_->intentIdentity));
    } else {
        entries(runtime_->enrollment.value,{});
        struct stat absent{}; require(::fstatat(runtime_->enrollment.value,"input.json",&absent,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT);
    }
    const auto raw=QJsonDocument(record).toJson(QJsonDocument::Compact)+'\n';
    FD fd(::openat(runtime_->enrollment.value,".input.pending",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));
    require(fd.value>=0);
    qsizetype offset=0;
    while (offset<raw.size()) {
        require(within()); auto n=::write(fd.value,raw.constData()+offset,size_t(raw.size()-offset)); require(n>0); offset+=n;
    }
    require(::fsync(fd.value)==0);
    recheckDirectory(profile_,runtime_->profile.value);
    recheckDirectory(profile_+"/enrollment-inputs",runtime_->enrollment.value);
    require(::renameat(runtime_->enrollment.value,".input.pending",runtime_->enrollment.value,"input.json")==0
        && ::fsync(runtime_->enrollment.value)==0 && ::fsync(runtime_->profile.value)==0);
    runtime_->intent=FD(::openat(runtime_->enrollment.value,"input.json",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
    require(runtime_->intent.value>=0); runtime_->intentIdentity=metadata(runtime_->intent.value);
    entries(runtime_->enrollment.value,{"input.json"});
    if (runtime_->active.value<0) {
        recheckDirectory(runtime_->sourceParentPath,runtime_->sourceParent.value);
        FD active(::openat(runtime_->sourceParent.value,"active.json",O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600));
        require(active.value>=0);
        const auto pointer=QJsonDocument(QJsonObject{{"schema_version",1},{"scope","omux-codex-active-acquisition-v1"},
            {"profile_handle",QFileInfo(profile_).fileName().mid(13)}}).toJson(QJsonDocument::Compact)+'\n';
        require(::write(active.value,pointer.constData(),size_t(pointer.size()))==pointer.size()
            && ::fsync(active.value)==0 && ::fsync(runtime_->sourceParent.value)==0);
        runtime_->active=FD(::openat(runtime_->sourceParent.value,"active.json",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
        require(runtime_->active.value>=0); runtime_->activeIdentity=metadata(runtime_->active.value);
    }
    recheckDirectory(runtime_->sourceParentPath,runtime_->sourceParent.value);
    recheckDirectory(profile_,runtime_->profile.value);
    recheckDirectory(profile_+"/enrollment-inputs",runtime_->enrollment.value);
    FD active(::openat(runtime_->sourceParent.value,"active.json",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
    require(active.value>=0 && same(metadata(active.value),runtime_->activeIdentity)
        && same(metadata(runtime_->active.value),runtime_->activeIdentity) && within());
}
bool CodexAccountAcquisition::recoverIntent() {
    struct stat exists{};
    if (::fstatat(runtime_->sourceParent.value,"active.json",&exists,AT_SYMLINK_NOFOLLOW)<0) {
        require(errno==ENOENT); return false;
    }
    runtime_->active=FD(::openat(runtime_->sourceParent.value,"active.json",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
    require(runtime_->active.value>=0 && (metadata(runtime_->active.value).st_mode&0777)==0600);
    const auto pointer=json(read(runtime_->active.value,4096));
    const auto opaque=pointer.value("profile_handle").toString();
    require(keys(pointer,{"schema_version","scope","profile_handle"}) && exactInteger(pointer.value("schema_version"),1)
        && pointer.value("scope")=="omux-codex-active-acquisition-v1" && opaque.size()==32);
    for (auto ch:opaque) require((ch>='0' && ch<='9') || (ch>='a' && ch<='f'));
    profile_=runtime_->sourceParentPath+"/native-login-"+opaque;
    runtime_->profile=directory(profile_); runtime_->profilePath=profile_;
    runtime_->enrollment=directory(profile_+"/enrollment-inputs");
    entries(runtime_->enrollment.value,{"input.json"});
    runtime_->intent=FD(::openat(runtime_->enrollment.value,"input.json",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
    require(runtime_->intent.value>=0 && (metadata(runtime_->intent.value).st_mode&0777)==0600);
    const auto r=json(read(runtime_->intent.value,16384));
    require(keys(r,{"schema_version","scope","component_sha256","codex_home","renewal_owner","connect_operation_id",
        "enrollment_operation_id","phase","source_id","job_id","job_generation","connect_params","enrollment_params","endpoint"})
        && exactInteger(r.value("schema_version"),1) && r.value("scope")=="omux-codex-local-enrollment-intent-v1"
        && handle(r.value("component_sha256").toString()) && r.value("codex_home")==profile_
        && r.value("endpoint")==client_.socketPath()
        && r.value("renewal_owner")=="native" && handle(r.value("connect_operation_id").toString())
        && handle(r.value("enrollment_operation_id").toString())
        && r.value("connect_operation_id")!=r.value("enrollment_operation_id"));
    runtime_->componentSha=r.value("component_sha256").toString();
    connectID_=r.value("connect_operation_id").toString(); enrollmentID_=r.value("enrollment_operation_id").toString();
    sourceID_=r.value("source_id").toString(); jobID_=r.value("job_id").toString();
    const auto cp=r.value("connect_params").toObject(), ep=r.value("enrollment_params").toObject();
    require(keys(cp,{"kind","provider","label","source_path","operation_id","expected_revision"})
        && cp.value("kind")=="native_store" && cp.value("provider")=="codex" && cp.value("label")=="Codex account"
        && cp.value("source_path")==profile_+"/auth.json" && cp.value("operation_id")==connectID_
        && integer(cp.value("expected_revision"),&connectRevision_) && connectRevision_>=0
        && keys(ep,{"source_id","include_operation_generation","operation_id","expected_revision"})
        && ep.value("source_id")==r.value("source_id") && ep.value("include_operation_generation").isBool()
        && ep.value("include_operation_generation").toBool() && ep.value("operation_id")==enrollmentID_);
    const auto phase=r.value("phase").toString();
    require(phase=="source-connect-pending" || phase=="enrollment-pending" || phase=="identity-verification-admitted" || phase=="identity-ready");
    recovering_=true;
    runtime_->activeIdentity=metadata(runtime_->active.value); runtime_->intentIdentity=metadata(runtime_->intent.value);
    recheckDirectory(runtime_->sourceParentPath,runtime_->sourceParent.value);
    recheckDirectory(profile_,runtime_->profile.value); recheckDirectory(profile_+"/enrollment-inputs",runtime_->enrollment.value);
    if (phase=="source-connect-pending") {
        require(r.value("source_id").isNull() && r.value("job_id").isNull() && r.value("job_generation").isNull()
            && ep.value("expected_revision").isNull());
        phase_=Phase::Connecting; client_.recoverMutation(connectID_);
    } else {
        require(handle(sourceID_) && integer(ep.value("expected_revision"),&enrollmentRevision_) && enrollmentRevision_>=0);
        if (phase=="enrollment-pending") {
            require(r.value("job_id").isNull() && r.value("job_generation").isNull());
            phase_=Phase::Enrolling; client_.recoverMutation(enrollmentID_);
        } else {
            require(jobID_=="reconcile-"+sourceID_ && integer(r.value("job_generation"),&jobGeneration_) && jobGeneration_>0);
            phase_=Phase::Verifying; enrollmentStart_=elapsed_.elapsed(); pollTimer_.start(); poll();
        }
    }
    status("Recovering the retained enrollment intent using metadata only. No sign-in or mutation is replayed.");
    return true;
}
void CodexAccountAcquisition::clearIntent() {
    if (!runtime_ || runtime_->active.value<0) return;
    recheckDirectory(runtime_->sourceParentPath,runtime_->sourceParent.value);
    FD named(::openat(runtime_->sourceParent.value,"active.json",O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK));
    require(named.value>=0 && same(metadata(named.value),runtime_->activeIdentity)
        && same(metadata(runtime_->active.value),runtime_->activeIdentity));
    require(::unlinkat(runtime_->sourceParent.value,"active.json",0)==0 && ::fsync(runtime_->sourceParent.value)==0);
    runtime_->active=FD();
}
void CodexAccountAcquisition::connectSource() {
    // A second fresh account must not inherit the first enrollment's captured
    // revision in its pre-dispatch journal.
    connectRevision_=enrollmentRevision_=-1;
    phase_ = Phase::Connecting;
    const auto id=[] { return (QUuid::createUuid().toString(QUuid::WithoutBraces)
        + QUuid::createUuid().toString(QUuid::WithoutBraces)).remove('-').toLower(); };
    connectID_=id(); enrollmentID_=id();
    client_.request("state.snapshot",{},[this](const QJsonObject &s,const QString &error) {
        if (phase_!=Phase::Connecting) return;
        if (!error.isEmpty() || !s.value("custody_available").isBool() || !s.value("custody_available").toBool()
            || !integer(s.value("revision"),&connectRevision_) || connectRevision_<0 || !within()) {
            finish("Daemon readiness changed. No source mutation was sent."); return;
        }
        try { checkpoint("source-connect-pending"); }
        catch (...) { finish("The private enrollment intent could not be committed. No daemon mutation was sent."); return; }
        status("Native sign-in completed. Requesting source authorization; provider identity is still unverified.");
        client_.request("source.connect",{{"kind","native_store"},{"provider","codex"},{"label","Codex account"},
            {"source_path",profile_+"/auth.json"},{"operation_id",connectID_},{"expected_revision",connectRevision_}},
            [this](const QJsonObject &r,const QString &error) { connectedSource(r,error); });
    });
}
void CodexAccountAcquisition::connectedSource(const QJsonObject &r,const QString &error) {
    if (phase_ != Phase::Connecting) return;
    if (!error.isEmpty()) {
        if (client_.hasUncertainOperations()) { status(client_.uncertaintyMessage()); return; }
        finish("Source authorization failed. The private native profile is retained; no mutation was replayed."); return;
    }
    if (!handle(r.value("source_id").toString()) || r.value("status") != "authorized"
        || r.value("identity_admission") != "verification_required") {
        finish("Source authorization returned an unsupported result. The private intent is retained; no mutation was replayed."); return;
    }
    sourceID_ = r.value("source_id").toString();
    if (recovering_) {
        // A metadata replay does not renew a lost workflow's authorization to
        // perform its next external effect. The ordinary Sources-tab Enroll
        // control is a separate explicit intent for this recovered source.
        if (onSourceConnected) onSourceConnected(sourceID_);
        finish("The original source connection was recovered. Select Enroll from source to authorize identity verification; no workflow effect was replayed.",false);
        return;
    }
    if (!custodyAvailable_ || !within() || !client_.ready() || !client_.supportsEnrollmentGeneration() || client_.hasUncertainOperations()) {
        finish("The source was connected, but enrollment needs restored custody and a ready daemon."); return;
    }
    client_.request("state.snapshot",{},[this](const QJsonObject &s,const QString &error) {
        if (phase_!=Phase::Connecting) return;
        if (!error.isEmpty() || !s.value("custody_available").isBool() || !s.value("custody_available").toBool()
            || !integer(s.value("revision"),&enrollmentRevision_) || enrollmentRevision_<0 || !within()) {
            finish("The source was connected. Readiness changed before enrollment; its intent is retained."); return;
        }
        try { checkpoint("enrollment-pending"); }
        catch (...) { finish("The source was connected. Enrollment intent persistence failed; no enrollment was sent."); return; }
        phase_ = Phase::Enrolling;
        client_.request("enrollment.start",{{"source_id",sourceID_},{"include_operation_generation",true},
            {"operation_id",enrollmentID_},{"expected_revision",enrollmentRevision_}},
            [this](const QJsonObject &r,const QString &error) { admittedEnrollment(r,error); });
    });
}
void CodexAccountAcquisition::admittedEnrollment(const QJsonObject &r,const QString &error) {
    if (phase_ != Phase::Enrolling) return;
    if (!error.isEmpty() && client_.hasUncertainOperations()) { status(client_.uncertaintyMessage()); return; }
    qint64 generation, admitted;
    if (!error.isEmpty() || !keys(r,{"operation_id","status","operation_generation","admitted_revision"})
        || !integer(r.value("admitted_revision"),&admitted) || admitted<enrollmentRevision_
        || r.value("status") != "verifying_identity"
        || r.value("operation_id") != "reconcile-"+sourceID_
        || !integer(r.value("operation_generation"),&generation) || generation <= 0) {
        finish("The source remains connected. Enrollment was not proven; resolve its action before requesting another intent."); return;
    }
    jobID_ = r.value("operation_id").toString(); jobGeneration_ = generation;
    try { checkpoint("identity-verification-admitted"); }
    catch (...) { finish("Enrollment was admitted, but its local journal readback failed. Inspect the daemon's action; no success is claimed."); return; }
    enrollmentStart_ = elapsed_.elapsed(); phase_ = Phase::Verifying; pollTimer_.start(); poll();
}
bool CodexAccountAcquisition::operationEvent(const QJsonObject &e) {
    if (!busy() || e.value("operation_kind")!="mutation") return false;
    const auto expected=phase_==Phase::Connecting?connectID_:phase_==Phase::Enrolling?enrollmentID_:QString();
    if (expected.isEmpty() || e.value("operation_id")!=expected) return false;
    if (e.value("operation_status")=="completed" && e.value("operation_result").isObject()) {
        if (phase_==Phase::Connecting) connectedSource(e.value("operation_result").toObject(),{});
        else admittedEnrollment(e.value("operation_result").toObject(),{});
    } else if (e.value("operation_status")=="not_found")
        finish("No committed operation was found. The private intent is retained; the original request was not replayed.");
    return true;
}
void CodexAccountAcquisition::poll() {
    if (phase_ != Phase::Verifying || pollPending_) return;
    if (!within() || elapsed_.elapsed()-enrollmentStart_ >= 120000 || !custodyAvailable_
        || !client_.ready() || client_.hasUncertainOperations()) {
        finish("The source is retained. Enrollment readiness is unproved; inspect its action before repeating an intent."); return;
    }
    pollPending_=true;
    client_.request("state.snapshot",{},[this](const QJsonObject &s,const QString &error) {
        pollPending_=false;
        if (phase_ != Phase::Verifying || !error.isEmpty()) return;
        observe(s);
    });
}
void CodexAccountAcquisition::observe(const QJsonObject &s) {
    custodyAvailable_ = s.value("custody_available").isBool() && s.value("custody_available").toBool();
    if (!busy()) return;
    if (!custodyAvailable_) {
        if (native_.state() != QProcess::NotRunning) stopNative(false);
        else finish("Credential custody became unavailable. The source is retained; enrollment readiness is unproved.");
        return;
    }
    if (phase_ != Phase::Verifying) return;
    for (const auto &v : s.value("jobs").toArray()) {
        const auto j = v.toObject(); qint64 generation;
        if (j.value("id") == jobID_ && (!integer(j.value("operation_generation"),&generation)
            || generation != jobGeneration_ || j.value("status") == "failed")) {
            finish("Identity verification failed or was superseded. The source is retained; no usable grant is claimed."); return;
        }
    }
    if (usableEnrollment(s,sourceID_,jobID_,jobGeneration_,QDateTime::currentSecsSinceEpoch()))
        try { checkpoint("identity-ready");
            finish("Account identity verified and usable request authority retained. Renewal remains owned by the native source; continuity is a separate capability.",false);
        } catch (...) { finish("The daemon reports usable authority, but local completion persistence failed. No completed onboarding claim is recorded."); }
}
void CodexAccountAcquisition::cancel() {
    if (!busy()) return;
    if (phase_ == Phase::Preparing) { if (runtime_) runtime_->cancelled.store(true); finish("Sign-in cancelled before provider acquisition."); }
    else if (native_.state() != QProcess::NotRunning) stopNative(false);
    else finish("Sign-in observation cancelled. Any admitted daemon action and source remain owned by the daemon; no mutation was replayed.");
}
void CodexAccountAcquisition::finish(const QString &message,bool retainIntent) {
    deadline_.stop(); pollTimer_.stop(); escalation_.stop(); clearPrompt();
    // Held component lock cannot be released while our native process is live.
    if (native_.state() != QProcess::NotRunning) { status("Owned sign-in cleanup is unresolved."); return; }
    if (!retainIntent) {
        try { clearIntent(); }
        catch (...) { status("Local completion custody failed. The retained intent must be reconciled."); phase_=Phase::Idle; runtime_.reset(); if (onChanged) onChanged(); return; }
    }
    phase_ = Phase::Idle; runtime_.reset(); status(message); if (onChanged) onChanged();
}

#ifdef OMUX_ACQUISITION_MODELS
#include "codex_account_acquisition_test.h"
#endif
