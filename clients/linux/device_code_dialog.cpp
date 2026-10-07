#include "device_code_dialog.h"
#include <QApplication>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFont>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QLabel>
#include <QSocketNotifier>
#include <QTimer>
#include <QVBoxLayout>
#include <cerrno>
#include <cstdio>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

bool parseNativeDevicePrompt(const QByteArray &frame, NativeDevicePrompt *result) {
    if (!result || frame.isEmpty() || frame.size() > 4096) return false;
    QJsonParseError error;
    const auto document = QJsonDocument::fromJson(frame, &error);
    if (error.error != QJsonParseError::NoError || !document.isObject()) return false;
    // The producer emits canonical sorted compact JSON. Equality also rejects
    // duplicate keys rather than accepting QJsonObject's last-value behavior.
    if (document.toJson(QJsonDocument::Compact) != frame) return false;
    const auto value = document.object();
    if (value.size() != 2 || !value.contains("verification_url") || !value.contains("user_code")
        || !value.value("verification_url").isString() || !value.value("user_code").isString()) return false;
    const auto url = value.value("verification_url").toString();
    const auto code = value.value("user_code").toString();
    if (url != QStringLiteral("https://auth.openai.com/codex/device") || code.isEmpty() || code.size() > 128) return false;
    for (const auto character : code)
        if (character.unicode() < 0x21 || character.unicode() >= 0x7f) return false;
    *result = {url, code};
    return true;
}

int runNativeDeviceDialog(QApplication &app, bool offlineTest) {
    struct stat input{};
    if (::fstat(STDIN_FILENO, &input) != 0 || input.st_uid != ::getuid()
        || (!S_ISFIFO(input.st_mode) && !S_ISSOCK(input.st_mode))) return 1;
    if (!offlineTest && QGuiApplication::platformName() != QStringLiteral("wayland")) return 1;
    const auto flags = ::fcntl(STDIN_FILENO, F_GETFL);
    if (flags < 0 || ::fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK) != 0) return 1;
    QDialog dialog;
    dialog.setWindowTitle(QStringLiteral("Sign in to a second Codex account"));
    dialog.setMinimumWidth(440);
    auto *layout = new QVBoxLayout(&dialog);
    auto *instruction = new QLabel(QStringLiteral("Waiting for your one-time sign-in code."), &dialog);
    instruction->setWordWrap(true);
    instruction->setTextFormat(Qt::PlainText);
    auto *url = new QLabel(&dialog);
    url->setTextFormat(Qt::PlainText);
    url->setTextInteractionFlags(Qt::NoTextInteraction);
    auto *code = new QLabel(&dialog);
    code->setObjectName(QStringLiteral("nativeDeviceCode"));
    code->setTextFormat(Qt::PlainText);
    code->setTextInteractionFlags(Qt::NoTextInteraction);
    QFont font = code->font();
    font.setPointSize(22);
    font.setBold(true);
    code->setFont(font);
    auto *warning = new QLabel(QStringLiteral("Continue only if you started this sign-in in Omux. Choose the other account in your browser. Never share this code."), &dialog);
    warning->setWordWrap(true);
    warning->setTextFormat(Qt::PlainText);
    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, &dialog);
    for (auto *label : {instruction, url, code, warning}) layout->addWidget(label);
    layout->addWidget(buttons);
    QByteArray buffer;
    bool displayed = false;
    bool finished = false;
    int outcome = 1;
    QSocketNotifier notifier(STDIN_FILENO, QSocketNotifier::Read, &dialog);
    const auto clear = [&] {
        code->clear();
        url->clear();
        buffer.fill('\0');
        buffer.clear();
    };
    const auto finish = [&](int value) {
        if (finished) return;
        finished = true;
        notifier.setEnabled(false);
        outcome = value;
        clear();
        dialog.hide();
        app.exit(value);
    };
    QObject::connect(buttons, &QDialogButtonBox::rejected, &dialog, [&] { finish(1); });
    QObject::connect(&dialog, &QDialog::rejected, &dialog, [&] { finish(1); });
    QObject::connect(&notifier, &QSocketNotifier::activated, &dialog, [&] {
        char bytes[1024];
        while (true) {
            const auto count = ::read(STDIN_FILENO, bytes, sizeof(bytes));
            if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            if (count < 0) { finish(1); return; }
            if (count == 0) { finish(0); return; }
            if (displayed || buffer.size() + count > 4097) { finish(1); return; }
            buffer.append(bytes, static_cast<qsizetype>(count));
            const auto end = buffer.indexOf('\n');
            if (end < 0) continue;
            if (end + 1 != buffer.size()) { finish(1); return; }
            NativeDevicePrompt prompt;
            if (!parseNativeDevicePrompt(buffer.first(end), &prompt)) { finish(1); return; }
            instruction->setText(QStringLiteral("Sign in in your browser, then enter this one-time code while this sign-in window is open."));
            url->setText(prompt.verificationUrl);
            code->setText(prompt.userCode);
            prompt.userCode.fill(QChar('\0'));
            prompt.verificationUrl.clear();
            buffer.fill('\0');
            buffer.clear();
            displayed = true;
            dialog.raise();
            dialog.activateWindow();
            std::puts("OMUX_NATIVE_DEVICE_DIALOG_DISPLAYED");
            std::fflush(stdout);
        }
    });
    QTimer::singleShot(90000, &dialog, [&] { if (!displayed) finish(1); });
    QTimer::singleShot(900000, &dialog, [&] { finish(1); });
    dialog.show();
    QTimer::singleShot(0, &dialog, [&] {
        if (!dialog.isVisible()) { finish(1); return; }
        std::puts("OMUX_NATIVE_DEVICE_DIALOG_READY");
        std::fflush(stdout);
    });
    app.exec();
    notifier.setEnabled(false);
    clear();
    ::fcntl(STDIN_FILENO, F_SETFL, flags);
    return outcome;
}
