#pragma once
#include <QByteArray>
#include <QString>
class QApplication;

struct NativeDevicePrompt {
    QString verificationUrl;
    QString userCode;
};

bool parseNativeDevicePrompt(const QByteArray &frame, NativeDevicePrompt *result);
int runNativeDeviceDialog(QApplication &app, bool offlineTest = false);
