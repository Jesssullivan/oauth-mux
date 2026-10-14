#pragma once
#include <QString>
#include <QUrl>

class QApplication;
// Closed dispatch policy for the daemon's documented OSS enrollment profile.
// Validation/launch never confers identity, grants or native application support.
bool validateSiwcAuthorization(const QString &profile, const QString &value, QUrl *url = nullptr);
bool openSiwcAuthorization(const QString &profile, const QString &value);
int runSiwcBrowserPipe(QApplication &app);
