#include "siwc_browser.h"
#include <QApplication>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QMap>
#include <QSet>
#include <QSocketNotifier>
#include <QTimer>
#include <QUrlQuery>
#include <QDesktopServices>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

namespace {
bool token(const QString &value, int length, bool hex = false) {
    if (value.size() != length) return false;
    for (const auto c : value) {
        if (hex ? !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
                : !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_')) return false;
    }
    return !hex || value != QString(length, '0');
}
}

bool validateSiwcAuthorization(const QString &profile, const QString &value, QUrl *out) {
    if (profile != "openai_siwc_responses_v1" || value.size() > 8192
        || !value.startsWith("https://auth.openai.com/api/accounts/authorize?")) return false;
    for (const auto c : value) if (c.unicode() < 0x21 || c.unicode() >= 0x7f) return false;
    const QUrl url = QUrl::fromEncoded(value.toLatin1(), QUrl::StrictMode);
    if (!url.isValid() || url.scheme() != "https" || url.host() != "auth.openai.com" || url.port() != -1
        || !url.userInfo().isEmpty() || url.hasFragment() || url.path() != "/api/accounts/authorize") return false;
    const auto items = QUrlQuery(url).queryItems(QUrl::FullyDecoded);
    const QSet<QString> allowed {"client_id", "agent_name_hint", "ext_agent_host_id", "response_type", "redirect_uri", "scope",
        "state", "nonce", "code_challenge_method", "code_challenge", "resource"};
    if (items.size() != allowed.size()) return false;
    QMap<QString, QString> fields;
    for (const auto &item : items) {
        if (!allowed.contains(item.first) || fields.contains(item.first)) return false;
        fields.insert(item.first, item.second);
    }
    if (fields.value("client_id") != "dynamic_agent_client" || fields.value("agent_name_hint") != "omux"
        || fields.value("response_type") != "code" || fields.value("code_challenge_method") != "S256"
        || fields.value("scope") != "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"
        || fields.value("resource") != "https://api.openai.com/v1" || !token(fields.value("ext_agent_host_id"), 64, true)
        || !token(fields.value("state"), 43) || !token(fields.value("nonce"), 43) || !token(fields.value("code_challenge"), 43)) return false;
    const auto redirectText = fields.value("redirect_uri");
    const auto redirect = QUrl::fromEncoded(redirectText.toLatin1(), QUrl::StrictMode);
    if (!redirect.isValid() || redirect.scheme() != "http" || redirect.host() != "127.0.0.1" || redirect.port() <= 0
        || redirect.port() > 65535 || !redirect.userInfo().isEmpty() || redirect.hasQuery() || redirect.hasFragment()
        || redirect.path() != "/auth/callback"
        || redirectText != "http://127.0.0.1:" + QString::number(redirect.port()) + "/auth/callback") return false;
    if (out) *out = url;
    return true;
}

bool openSiwcAuthorization(const QString &profile, const QString &value) {
    QUrl url;
    if (!validateSiwcAuthorization(profile, value, &url)) return false;
    // The one-use URL contains private state/nonce. It belongs only to the
    // approved desktop handler, never a control diagnostic or core dump.
    struct rlimit core {0, 0};
    if (::setrlimit(RLIMIT_CORE, &core) != 0) return false;
    const int savedOut = ::fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3), savedError = ::fcntl(STDERR_FILENO, F_DUPFD_CLOEXEC, 3);
    const int silent = ::open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (savedOut < 0 || savedError < 0 || silent < 0) {
        if (savedOut >= 0) ::close(savedOut);
        if (savedError >= 0) ::close(savedError);
        if (silent >= 0) ::close(silent);
        return false;
    }
    const bool muted = ::dup2(silent, STDOUT_FILENO) >= 0 && ::dup2(silent, STDERR_FILENO) >= 0;
    const bool opened = muted && QDesktopServices::openUrl(url);
    const bool restoredOut = ::dup2(savedOut, STDOUT_FILENO) >= 0;
    const bool restoredError = ::dup2(savedError, STDERR_FILENO) >= 0;
    ::close(savedOut); ::close(savedError); ::close(silent);
    url.clear();
    return opened && restoredOut && restoredError;
}

int runSiwcBrowserPipe(QApplication &app) {
    struct stat input {};
    if (::fstat(STDIN_FILENO, &input) != 0 || input.st_uid != ::getuid()
        || (!S_ISFIFO(input.st_mode) && !S_ISSOCK(input.st_mode))) return 1;
    const int original = ::fcntl(STDIN_FILENO, F_GETFL);
    if (original < 0 || ::fcntl(STDIN_FILENO, F_SETFL, original | O_NONBLOCK) != 0) return 1;
    QByteArray frame;
    int result = 1;
    bool finished = false;
    QSocketNotifier notifier(STDIN_FILENO, QSocketNotifier::Read);
    const auto finish = [&](int code) {
        if (finished) return;
        finished = true;
        notifier.setEnabled(false);
        frame.fill('\0'); frame.clear(); result = code; app.exit(code);
    };
    QObject::connect(&notifier, &QSocketNotifier::activated, &app, [&] {
        char buffer[1024];
        while (true) {
            const auto count = ::read(STDIN_FILENO, buffer, sizeof(buffer));
            if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            if (count <= 0 || frame.size() + count > 8192) { finish(1); return; }
            frame.append(buffer, qsizetype(count));
            std::memset(buffer, 0, sizeof(buffer));
            const auto end = frame.indexOf('\n');
            if (end < 0) continue;
            if (end + 1 != frame.size()) { finish(1); return; }
            QJsonParseError error;
            auto document = QJsonDocument::fromJson(frame.first(end), &error);
            const auto data = document.object();
            if (error.error != QJsonParseError::NoError || !document.isObject() || document.toJson(QJsonDocument::Compact) != frame.first(end) || data.size() != 2
                || !data.value("profile").isString() || !data.value("authorization_url").isString()) { finish(1); return; }
            const bool opened = openSiwcAuthorization(data.value("profile").toString(), data.value("authorization_url").toString());
            document = {}; finish(opened ? 0 : 1); return;
        }
    });
    QTimer::singleShot(15000, &app, [&] { finish(1); });
    app.exec();
    ::fcntl(STDIN_FILENO, F_SETFL, original);
    return result;
}
