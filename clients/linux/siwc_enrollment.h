#pragma once
#include "omux_client.h"
#include <QDialog>
#include <QElapsedTimer>
#include <QJsonObject>
#include <QPointer>
#include <QTimer>
#include <functional>

class QLabel;
class QPushButton;
class QSpinBox;
class QCheckBox;
class QComboBox;

// Thin consent and observation only. The daemon owns registration, callback,
// provider verification, encrypted paired commit and renewal.
class SiwcEnrollment final : public QObject {
public:
    using Browser = std::function<bool(const QString &, const QString &)>;
    explicit SiwcEnrollment(OmuxClient &, QWidget *, Browser = {});
    void open();
    void connectionChanged(bool);
    void observe(const QJsonObject &);
    bool operationEvent(const QJsonObject &);
    std::function<void()> onCommitted;
    static bool descriptorValid(const QJsonObject &);
    static bool statusValid(const QJsonObject &, const QString &);
private:
    void descriptor();
    void pending();
    void prepare();
    void admitted(const QJsonObject &, bool recovered);
    void authorize();
    void status();
    void withdraw();
    void withdrawn(const QJsonObject &);
    void showStatus(const QJsonObject &);
    void message(const QString &);
    void controls();
    void failed(const QString &);
    OmuxClient &client_;
    QWidget *parent_;
    Browser browser_;
    QPointer<QDialog> panel_;
    QPointer<QLabel> notice_;
    QPointer<QPushButton> start_, browserButton_, cancel_, check_;
    QPointer<QSpinBox> seconds_;
    QPointer<QCheckBox> consent_;
    QPointer<QComboBox> recover_;
    QTimer poll_;
    QElapsedTimer elapsed_;
    QJsonObject descriptor_, latest_;
    QString transaction_, source_, operation_, withdrawalOperation_, withdrawalTransaction_, withdrawalSource_;
    qint64 flowSeconds_ = 0, prepareSeconds_ = 0;
    quint64 generation_ = 0, selection_ = 0, prepareSelection_ = 0;
    bool preparePending_ = false, authorizePending_ = false, statusPending_ = false, withdrawPending_ = false;
    bool authorizationAttempted_ = false, connected_ = false, terminal_ = false;
    bool descriptorPending_ = false;
};
