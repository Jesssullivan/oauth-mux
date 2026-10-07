#include "tray.h"
#include "device_code_dialog.h"
#include <QApplication>
#include <QCommandLineParser>
#include <QFileInfo>
#include <QTimer>
#include <QMessageBox>
#include <exception>
#include <cstdio>
#include <cstring>
#include <utility>
#include <sys/resource.h>

int main(int argc, char **argv) {
    const bool deviceDialog = argc == 2 && std::strcmp(argv[1], "--native-device-login-stdin") == 0;
    if (deviceDialog) {
        struct rlimit limit{0, 0};
        if (::setrlimit(RLIMIT_CORE, &limit) != 0) return 1;
    }
    bool selfCheck = false;
    for (int index = 1; index < argc; ++index)
        if (std::strcmp(argv[index], "--self-check") == 0 || std::strcmp(argv[index], "--smoke") == 0)
            selfCheck = true;
    if (selfCheck && qEnvironmentVariableIsEmpty("QT_QPA_PLATFORM")) qputenv("QT_QPA_PLATFORM", "offscreen");
    // Font/XKB files are host desktop resources, never compiler/tool inputs.
    for (const auto &[variable, path] : {
            std::pair{"FONTCONFIG_FILE", "/etc/fonts/fonts.conf"},
            std::pair{"FONTCONFIG_PATH", "/etc/fonts"},
            std::pair{"QT_QPA_FONTDIR", "/usr/share/fonts"},
            std::pair{"XKB_CONFIG_ROOT", "/usr/share/X11/xkb"}})
        if (qEnvironmentVariableIsEmpty(variable) && QFileInfo::exists(QString::fromUtf8(path)))
            qputenv(variable, QByteArray(path));
    QApplication app(argc, argv);
    // A packaged loader may own /proc/self/exe. Explicit packaged plugin paths
    // must replace Qt's compiled Nix defaults rather than append to them.
    if (!qEnvironmentVariableIsEmpty("QT_PLUGIN_PATH"))
        QCoreApplication::setLibraryPaths(qEnvironmentVariable("QT_PLUGIN_PATH").split(':', Qt::SkipEmptyParts));
    app.setApplicationName("Omux");
    app.setOrganizationName("xoxd.ai");
    QCommandLineParser parser;
    parser.setApplicationDescription("Account and route controls for the Omux user service");
    parser.addHelpOption();
    parser.addOption({"native-device-login-stdin", "Show a one-time native sign-in code from a private pipe."});
    parser.addOption({"socket", "Connect to this private Omux control socket.", "path"});
    parser.addOption({{"self-check", "smoke"}, "Construct the real controls offline, process an event cycle, and exit."});
    parser.process(app);
    if (parser.isSet("native-device-login-stdin"))
        return deviceDialog ? runNativeDeviceDialog(app) : 1;
    try {
        OmuxTray window(parser.isSet("socket") ? parser.value("socket") : OmuxClient::defaultSocketPath(), !selfCheck, parser.isSet("socket"));
        window.show();
        if (selfCheck) {
            QTimer::singleShot(1000, &app, [&app] { app.exit(1); });
            QTimer::singleShot(20, &app, [&app, &window] {
                if (!window.isVisible()) { app.exit(1); return; }
                std::puts("OMUX_CONTROL_SELF_CHECK_OK");
                std::fflush(stdout);
                app.exit(0);
            });
        }
        return app.exec();
    } catch (const std::exception &error) {
        const auto message = QString::fromUtf8(error.what());
        std::fprintf(stderr, "Omux control unavailable: %s\n", error.what());
        if (!selfCheck) QMessageBox::critical(nullptr, "Omux control unavailable", message);
        return 1;
    }
}
