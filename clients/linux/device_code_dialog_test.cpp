#include "device_code_dialog.h"
#include <QApplication>
#include <QDialog>
#include <QDir>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QTemporaryDir>
#include <QTimer>
#include <cstdio>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    const QFileInfo plugin(QString::fromLocal8Bit(argv[1]));
    const QFileInfo fonts(QString::fromLocal8Bit(argv[2]));
    if (!plugin.isFile() || plugin.fileName() != "libqoffscreen.so" || !fonts.isFile()) return 2;
    qputenv("QT_PLUGIN_PATH", QDir(plugin.absolutePath()).absoluteFilePath("..").toUtf8());
    qputenv("QT_QPA_PLATFORM_PLUGIN_PATH", plugin.absolutePath().toUtf8());
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QTemporaryDir desktop;
    if (!desktop.isValid()) return 2;
    qputenv("FONTCONFIG_FILE", fonts.absoluteFilePath().toUtf8());
    qputenv("FONTCONFIG_PATH", fonts.absolutePath().toUtf8());
    for (const auto *name : {"XDG_CONFIG_HOME","XDG_DATA_HOME","XDG_CACHE_HOME","XDG_RUNTIME_DIR","QT_QPA_FONTDIR"})
        qputenv(name, desktop.path().toUtf8());
    QApplication app(argc, argv);
    QCoreApplication::setLibraryPaths({QDir(plugin.absolutePath()).absoluteFilePath("..")});
    const auto frame = QJsonDocument(QJsonObject{{"verification_url","https://auth.openai.com/codex/device"},
        {"user_code","MODEL-NOT-A-SECRET"}}).toJson(QJsonDocument::Compact);
    NativeDevicePrompt prompt;
    if (!parseNativeDevicePrompt(frame, &prompt)) return 3;
    for (const auto &bad : {QByteArray("{}"), QByteArray("{\"user_code\":\"a\",\"user_code\":\"b\",\"verification_url\":\"https://auth.openai.com/codex/device\"}"),
        QByteArray("{\"user_code\":\"<not-rich-text>\",\"verification_url\":\"https://elsewhere.invalid/device\"}"),QByteArray(4097,'x')})
        if (parseNativeDevicePrompt(bad, &prompt)) return 4;
    int pipe[2];
    if (::pipe(pipe) != 0) return 5;
    const auto original = ::dup(STDIN_FILENO);
    if (original < 0 || ::dup2(pipe[0],STDIN_FILENO) < 0) return 5;
    ::close(pipe[0]);
    bool privateDisplay = false;
    QTimer::singleShot(20, &app, [&] {
        const auto message = frame + '\n';
        if (::write(pipe[1],message.constData(),message.size()) != message.size()) app.exit(1);
    });
    QTimer::singleShot(100, &app, [&] {
        for (auto *window : QApplication::topLevelWidgets()) {
            if (auto *label = window->findChild<QLabel *>("nativeDeviceCode"))
                privateDisplay = window->isVisible() && label->text() == "MODEL-NOT-A-SECRET"
                    && label->textFormat() == Qt::PlainText && label->textInteractionFlags() == Qt::NoTextInteraction;
        }
        ::close(pipe[1]);
    });
    QTimer::singleShot(2000, &app, [&] { app.exit(1); });
    const auto result = runNativeDeviceDialog(app, true);
    ::dup2(original,STDIN_FILENO);
    ::close(original);
    if (result != 0 || !privateDisplay) return 6;
    int cancelPipe[2];
    if (::pipe(cancelPipe) != 0) return 7;
    const auto cancelOriginal = ::dup(STDIN_FILENO);
    if (cancelOriginal < 0 || ::dup2(cancelPipe[0],STDIN_FILENO) < 0) return 7;
    ::close(cancelPipe[0]);
    bool cancelledAndCleared = false;
    QTimer::singleShot(20, &app, [&] {
        const auto message = frame + '\n';
        if (::write(cancelPipe[1],message.constData(),message.size()) != message.size()) app.exit(1);
    });
    QTimer::singleShot(100, &app, [&] {
        for (auto *window : QApplication::topLevelWidgets()) {
            if (auto *dialog = qobject_cast<QDialog *>(window)) {
                auto *label = dialog->findChild<QLabel *>("nativeDeviceCode");
                if (label && label->text() == "MODEL-NOT-A-SECRET" && dialog->isVisible()) {
                    dialog->reject();
                    cancelledAndCleared = label->text().isEmpty() && !dialog->isVisible();
                }
            }
        }
    });
    const auto cancelResult = runNativeDeviceDialog(app, true);
    ::close(cancelPipe[1]);
    ::dup2(cancelOriginal,STDIN_FILENO);
    ::close(cancelOriginal);
    if (cancelResult != 1 || !cancelledAndCleared) return 8;
    std::puts("OMUX_NATIVE_DEVICE_DIALOG_MODEL_OK");
    return 0;
}
