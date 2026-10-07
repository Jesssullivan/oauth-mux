#include "tray.h"
#include <QApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QJsonDocument>
#include <QLocalServer>
#include <QPushButton>
#include <QTemporaryDir>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <cstdio>
#include <memory>

namespace {
bool until(const std::function<bool()> &done) {
    QElapsedTimer elapsed;
    elapsed.start();
    while (!done() && elapsed.elapsed() < 3000)
        QApplication::processEvents(QEventLoop::AllEvents, 10);
    return done();
}
QJsonObject report(bool duplicate) {
    QJsonArray findings;
    for (const auto *phase : {"artifact", "service", "vault", "source", "identity", "grant", "native"})
        findings.append(QJsonObject{{"phase", duplicate ? "artifact" : phase},
            {"reason", QString(phase) == "native" ? "unknown" : "ready"},
            {"action", QString(phase) == "native" ? "inspect_capability" : "none"}});
    return {{"schema_version", 1}, {"ready", false}, {"findings", findings}, {"seamless_handoff_proven", false}};
}
}

int main(int argc, char **argv) {
    // The declared offscreen plugin is a Bazel input. Qt's compiled Nix
    // defaults need not be visible inside the local test sandbox.
    std::setvbuf(stderr, nullptr, _IONBF, 0);
    qInstallMessageHandler([](QtMsgType, const QMessageLogContext &, const QString &message) {
        std::fprintf(stderr, "setup_ui_test Qt: %s\n", message.toUtf8().constData());
    });
    if (argc != 3) {
        std::fprintf(stderr, "setup_ui_test requires declared offscreen plugin and font configuration inputs\n");
        return 7;
    }
    const QFileInfo plugin(QString::fromLocal8Bit(argv[1]));
    if (!plugin.exists() || plugin.fileName() != "libqoffscreen.so") {
        std::fprintf(stderr, "setup_ui_test declared offscreen plugin unavailable\n");
        return 8;
    }
    const auto platforms = plugin.absolutePath();
    const auto plugins = QDir(platforms).absoluteFilePath("..");
    qputenv("QT_PLUGIN_PATH", plugins.toUtf8());
    qputenv("QT_QPA_PLATFORM_PLUGIN_PATH", platforms.toUtf8());
    qputenv("QT_QPA_PLATFORM", "offscreen");
    const QFileInfo fontConfig(QString::fromLocal8Bit(argv[2]));
    if (!fontConfig.isFile()) {
        std::fprintf(stderr, "setup_ui_test declared font configuration unavailable\n");
        return 9;
    }
    QTemporaryDir desktop("/tmp/omux-setup-desktop-XXXXXX");
    if (!desktop.isValid()) return 10;
    qputenv("FONTCONFIG_FILE", fontConfig.absoluteFilePath().toUtf8());
    qputenv("FONTCONFIG_PATH", fontConfig.absolutePath().toUtf8());
    qputenv("XDG_CACHE_HOME", desktop.path().toUtf8());
    qputenv("XDG_CONFIG_HOME", desktop.path().toUtf8());
    qputenv("XDG_DATA_HOME", desktop.path().toUtf8());
    qputenv("XDG_RUNTIME_DIR", desktop.path().toUtf8());
    qputenv("QT_QPA_FONTDIR", desktop.path().toUtf8());
    std::fprintf(stderr, "setup_ui_test: constructing Qt offscreen application\n");
    QApplication app(argc, argv);
    QCoreApplication::setLibraryPaths({plugins});
    QTemporaryDir directory("/tmp/omux-setup-ui-XXXXXX");
    QLocalServer server;
    server.setSocketOptions(QLocalServer::UserAccessOption);
    const auto socketPath = directory.path() + "/control.sock";
    if (!server.listen(socketPath) || !QFile::setPermissions(socketPath, QFile::ReadOwner | QFile::WriteOwner)) {
        std::fprintf(stderr, "setup_ui_test: private fixture listener unavailable\n");
        return 1;
    }
    bool duplicate = false;
    bool decline = false;
    int mutations = 0;
    QObject::connect(&server, &QLocalServer::newConnection, &server, [&] {
        auto *socket = server.nextPendingConnection();
        socket->setParent(&server);
        auto buffer = std::make_shared<QByteArray>();
        QObject::connect(socket, &QLocalSocket::readyRead, socket, [&, socket, buffer] {
            *buffer += socket->readAll();
            while (buffer->contains('\n')) {
                const auto end = buffer->indexOf('\n');
                const auto request = QJsonDocument::fromJson(buffer->left(end)).object();
                buffer->remove(0, end + 1);
                const auto method = request.value("method").toString();
                if (method == "setup.readiness" && decline) {
                    socket->write(QJsonDocument(QJsonObject{{"jsonrpc", "2.0"}, {"id", request.value("id")},
                        {"error", QJsonObject{{"code", -32000}, {"message", "CustodyLocked"}}}}).toJson(QJsonDocument::Compact) + '\n');
                    continue;
                }
                QJsonObject result;
                if (method == "system.handshake") result = {{"protocol_version", 2}};
                else if (method == "state.snapshot") result = {{"revision", 1}, {"custody_available", true}};
                else if (method == "setup.readiness") result = report(duplicate);
                else if (method == "integrations.status") result = {{"integrations", QJsonArray{}}};
                else ++mutations;
                socket->write(QJsonDocument(QJsonObject{{"jsonrpc", "2.0"}, {"id", request.value("id")},
                    {"result", result}}).toJson(QJsonDocument::Compact) + '\n');
            }
        });
    });
    {
        // Offline construction avoids invoking any host service manager.
        OmuxTray window(socketPath, false, true);
        std::fprintf(stderr, "setup_ui_test: controls constructed\n");
        window.show();
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Reconnect") button->click();
        auto *table = window.findChild<QTableWidget *>("setupReadiness");
        auto *notice = window.findChild<QLabel *>("setupNotice");
        if (!table || !notice || !until([&] { return table->rowCount() == 7; })) return 2;
        if (table->item(6, 1)->text() != "unknown" || !notice->text().contains("Home Manager")) return 3;
        duplicate = true;
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Check setup") button->click();
        if (!until([&] { return notice->text().contains("unsupported readiness"); }) || table->rowCount() != 0) return 4;
        decline = true;
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Check setup") button->click();
        if (!until([&] { return notice->text().contains("CustodyLocked"); })) return 6;
        window.close();
    }
    // UI close/destruction sends no shutdown, mutation, or removal request.
    QApplication::processEvents();
    return server.isListening() && mutations == 0 ? 0 : 5;
}
