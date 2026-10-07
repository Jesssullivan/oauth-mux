#include "runtime_paths.h"

#include <QCryptographicHash>
#include <QDir>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace {
[[noreturn]] void fail(const char *classification) {
    throw std::runtime_error(classification);
}

void absolute(const QByteArray &path) {
    if (path.size() < 2 || path.front() != '/' || path.back() == '/' || path.contains('\0'))
        fail("Unsafe absolute Omux path");
    const auto components = path.mid(1).split('/');
    for (const auto &component : components)
        if (component.isEmpty() || component == "." || component == "..")
            fail("Unsafe absolute Omux path");
}

class Descriptor {
public:
    explicit Descriptor(int value) : value_(value) {}
    ~Descriptor() { if (value_ >= 0) ::close(value_); }
    Descriptor(const Descriptor &) = delete;
    Descriptor &operator=(const Descriptor &) = delete;
    int get() const { return value_; }
    int release() { const int value = value_; value_ = -1; return value; }
    void reset(int value) { if (value_ >= 0) ::close(value_); value_ = value; }
private:
    int value_;
};

int openPrivateDirectory(const QByteArray &path) {
    absolute(path);
    Descriptor directory(::open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (directory.get() < 0) fail("Omux directory unavailable");
    for (const auto &component : path.mid(1).split('/')) {
        struct stat metadata {};
        if (::fstat(directory.get(), &metadata) != 0) fail("Omux directory metadata unavailable");
        if (!S_ISDIR(metadata.st_mode) || (metadata.st_uid != ::getuid() && metadata.st_uid != 0))
            fail("Unsafe Omux directory owner");
        if ((metadata.st_mode & 0022) && !(metadata.st_uid == 0 && (metadata.st_mode & S_ISVTX)))
            fail("Unsafe Omux directory permissions");
        const int next = ::openat(directory.get(), component.constData(),
                                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0) fail("Omux directory unavailable or unsafe");
        directory.reset(next);
    }
    struct stat metadata {};
    if (::fstat(directory.get(), &metadata) != 0) fail("Omux directory metadata unavailable");
    if (!S_ISDIR(metadata.st_mode) || metadata.st_uid != ::getuid() || (metadata.st_mode & 0777) != 0700)
        fail("Omux directory must be private to the current user");
    return directory.release();
}

void privateDirectory(const QByteArray &path) {
    Descriptor directory(openPrivateDirectory(path));
}
}

#ifdef OMUX_RUNTIME_PATHS_TEST
#include <QCoreApplication>
#include <QTemporaryDir>
#include <functional>

namespace {
bool rejected(const std::function<void()> &operation) {
    try { operation(); } catch (const std::runtime_error &) { return true; }
    return false;
}
}

int main(int argc, char **argv) {
    QCoreApplication application(argc, argv);
    // A short disposable root keeps the hashed runtime child inside AF_UNIX's
    // native bound. This fixture never opens user state or user sockets.
    QTemporaryDir root("/tmp/omux-qt-path-XXXXXX");
    if (!root.isValid() || ::chmod(root.path().toUtf8().constData(), 0700) != 0) return 1;
    const QString firstState = root.path() + "/first";
    const QString secondState = root.path() + "/second";
    const QString first = OmuxRuntimePaths::controlSocketForState(firstState, root.path());
    const QString second = OmuxRuntimePaths::controlSocketForState(secondState, root.path());
    if (first == second || first != OmuxRuntimePaths::controlSocketForState(firstState, root.path())) return 2;
    if (OmuxRuntimePaths::controlSocketForState(firstState, std::nullopt) != firstState + "/run/control.sock") return 3;
    if (!rejected([&] { OmuxRuntimePaths::controlSocketForState(firstState, QString()); }) ||
        !rejected([&] { OmuxRuntimePaths::controlSocketForState(firstState, QString("relative")); }) ||
        !rejected([&] { OmuxRuntimePaths::controlSocketForState(firstState, root.path() + "/missing"); })) return 4;
    const auto alias = (root.path() + "/alias").toUtf8();
    if (::symlink(".", alias.constData()) != 0 ||
        !rejected([&] { OmuxRuntimePaths::controlSocketForState(firstState, QString::fromUtf8(alias)); })) return 5;
    if (::chmod(root.path().toUtf8().constData(), 0755) != 0 ||
        !rejected([&] { OmuxRuntimePaths::controlSocketForState(firstState, root.path()); })) return 6;
    if (::chmod(root.path().toUtf8().constData(), 0700) != 0) return 7;
    const QString parent = root.path() + "/private";
    if (!QDir().mkdir(parent) || ::chmod(parent.toUtf8().constData(), 0700) != 0) return 8;
    OmuxRuntimePaths::validateSocketPath(parent + "/control.sock");
    const auto socketPath = (parent + "/control.sock").toUtf8();
    {
        Descriptor regular(::open(socketPath.constData(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
        if (regular.get() < 0 || !rejected([&] { OmuxRuntimePaths::validateSocketPath(QString::fromUtf8(socketPath)); })) return 14;
    }
    if (::unlink(socketPath.constData()) != 0 || ::symlink("missing.sock", socketPath.constData()) != 0 ||
        !rejected([&] { OmuxRuntimePaths::validateSocketPath(QString::fromUtf8(socketPath)); }) ||
        ::unlink(socketPath.constData()) != 0) return 15;
    Descriptor socket(::socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
    sockaddr_un address {};
    address.sun_family = AF_UNIX;
    std::memcpy(address.sun_path, socketPath.constData(), static_cast<size_t>(socketPath.size() + 1));
    if (socket.get() < 0 || ::bind(socket.get(), reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0 ||
        ::chmod(socketPath.constData(), 0600) != 0) return 16;
    OmuxRuntimePaths::validateSocketPath(QString::fromUtf8(socketPath));
    if (::chmod(socketPath.constData(), 0666) != 0 ||
        !rejected([&] { OmuxRuntimePaths::validateSocketPath(QString::fromUtf8(socketPath)); }) ||
        ::unlink(socketPath.constData()) != 0) return 17;
    if (::chmod(parent.toUtf8().constData(), 0755) != 0 ||
        !rejected([&] { OmuxRuntimePaths::validateSocketPath(parent + "/control.sock"); })) return 9;
    if (!rejected([&] { OmuxRuntimePaths::controlSocketForState("/" + QString(107, 'a'), std::nullopt); })) return 10;
    qunsetenv("OMUX_SOCKET");
    qunsetenv("OMUX_INSTANCE");
    qputenv("HOME", root.path().toUtf8());
    qunsetenv("XDG_STATE_HOME");
    qputenv("XDG_RUNTIME_DIR", root.path().toUtf8());
    const QString expected = OmuxRuntimePaths::controlSocketForState(root.path() + "/.local/state/omux", root.path());
    if (OmuxRuntimePaths::defaultControlSocket() != expected) return 11;
    qputenv("OMUX_INSTANCE", "dev");
    if (OmuxRuntimePaths::defaultControlSocket() != OmuxRuntimePaths::controlSocketForState(root.path() + "/.local/state/omux-dev", root.path())
        || OmuxRuntimePaths::defaultControlSocket() == expected) return 18;
    qputenv("OMUX_INSTANCE", "release");
    if (!rejected([] { OmuxRuntimePaths::defaultControlSocket(); })) return 19;
    qunsetenv("OMUX_INSTANCE");
    qputenv("XDG_RUNTIME_DIR", "");
    if (!rejected([] { OmuxRuntimePaths::defaultControlSocket(); })) return 12;
    qunsetenv("XDG_RUNTIME_DIR");
    if (OmuxRuntimePaths::defaultControlSocket() != root.path() + "/.local/state/omux/run/control.sock") return 13;
    return 0;
}
#endif

namespace OmuxRuntimePaths {
void validateSocketPath(const QString &path) {
    const QByteArray bytes = path.toUtf8();
    absolute(bytes);
    if (bytes.size() >= static_cast<qsizetype>(sizeof(sockaddr_un::sun_path)))
        fail("Omux socket path too long");
    // Existing private parent custody is checked without opening the socket;
    // peer-user validation remains mandatory after connection.
    const auto separator = bytes.lastIndexOf('/');
    Descriptor directory(openPrivateDirectory(bytes.left(separator)));
    struct stat metadata {};
    const auto name = bytes.mid(separator + 1);
    if (::fstatat(directory.get(), name.constData(), &metadata, AT_SYMLINK_NOFOLLOW) != 0) {
        if (errno == ENOENT) return;
        fail("Omux socket metadata unavailable");
    }
    if (!S_ISSOCK(metadata.st_mode) || metadata.st_uid != ::getuid() || (metadata.st_mode & 0777) != 0600)
        fail("Omux socket must be private to the current user");
}

QString controlSocketForState(const QString &state, const std::optional<QString> &runtime) {
    const auto stateBytes = state.toUtf8();
    absolute(stateBytes);
    QString run = state + "/run";
    if (runtime) {
        privateDirectory(runtime->toUtf8());
        const auto digest = QCryptographicHash::hash(stateBytes, QCryptographicHash::Sha256).left(16).toHex();
        run = *runtime + "/omux-" + QString::fromLatin1(digest);
    }
    const QString socket = run + "/control.sock";
    if (socket.toUtf8().size() >= static_cast<qsizetype>(sizeof(sockaddr_un::sun_path)))
        fail("Omux socket path too long");
    return socket;
}

QString defaultControlSocket() {
    const auto instance = qEnvironmentVariable("OMUX_INSTANCE", "default");
    if (instance != "default" && instance != "dev") fail("Unknown Omux instance");
    if (qEnvironmentVariableIsSet("OMUX_SOCKET")) {
        const auto selected = qEnvironmentVariable("OMUX_SOCKET");
        validateSocketPath(selected);
        return selected;
    }
    // Match defaultState: HOME remains required even with XDG_STATE_HOME.
    const auto home = qEnvironmentVariable("HOME");
    absolute(home.toUtf8());
    const auto stateBase = qEnvironmentVariableIsSet("XDG_STATE_HOME")
        ? qEnvironmentVariable("XDG_STATE_HOME") : home + "/.local/state";
    absolute(stateBase.toUtf8());
    return controlSocketForState(stateBase + (instance == "dev" ? "/omux-dev" : "/omux"), qEnvironmentVariableIsSet("XDG_RUNTIME_DIR")
        ? std::optional<QString>(qEnvironmentVariable("XDG_RUNTIME_DIR")) : std::nullopt);
}
}
