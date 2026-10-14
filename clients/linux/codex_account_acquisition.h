#pragma once
#include "omux_client.h"
#include <QDialog>
#include <QElapsedTimer>
#include <QJsonObject>
#include <QProcess>
#include <QTimer>
#include <functional>
#include <memory>

class CodexAcquisitionRuntime;
// This operation owns only one fresh native source. It never launches a user's
// ordinary application, adopts renewal ownership, or invokes an evaluation guard.
class CodexAccountAcquisition final : public QObject {
public:
    explicit CodexAccountAcquisition(OmuxClient &client, QWidget *parent);
    ~CodexAccountAcquisition() override;
    bool busy() const { return phase_ != Phase::Idle; }
    void start(bool custodyAvailable);
    void cancel();
    void observe(const QJsonObject &snapshot);
    bool operationEvent(const QJsonObject &event);
    std::function<void(const QString &)> onStatus;
    std::function<void()> onChanged;
    std::function<void(const QString &)> onSourceConnected;
    static bool parseNativeFrame(const QByteArray &, QJsonObject *);
    static bool usableEnrollment(const QJsonObject &, const QString &, const QString &,
                                 qint64 generation, qint64 now);
private:
    enum class Phase { Idle, Preparing, Initialize, StartLogin, Consent, Stopping, Connecting, Enrolling, Verifying };
    void launch();
    void receive();
    void frame(const QJsonObject &);
    void send(const QJsonObject &);
    void stopNative(bool completed);
    void nativeStopped(int exitCode, QProcess::ExitStatus);
    void connectSource();
    void connectedSource(const QJsonObject &, const QString &);
    void admittedEnrollment(const QJsonObject &, const QString &);
    void checkpoint(const QString &phase);
    bool recoverIntent();
    void clearIntent();
    void poll();
    void finish(const QString &, bool retainIntent = true);
    void status(const QString &);
    bool within(qint64 milliseconds = 900000) const;
    void clearPrompt();
    OmuxClient &client_;
    QWidget *parent_;
    // QProcess must be destroyed/reaped before this held component lease.
    std::shared_ptr<CodexAcquisitionRuntime> runtime_;
    QProcess native_;
    QTimer deadline_, escalation_, pollTimer_;
    QElapsedTimer elapsed_;
    Phase phase_ = Phase::Idle;
    QString profile_, loginID_, sourceID_, jobID_, connectID_, enrollmentID_;
    qint64 jobGeneration_ = 0, enrollmentStart_ = 0, connectRevision_ = -1, enrollmentRevision_ = -1;
    QByteArray buffer_;
    qsizetype received_ = 0;
    int messages_ = 0, pidfd_ = -1;
    bool completed_ = false, custodyAvailable_ = false, cleanupFailed_ = false, pollPending_ = false, recovering_ = false;
    int stopStep_ = 0;
    friend struct CodexAcquisitionModels;
    QDialog *prompt_ = nullptr;
};
