#pragma once

#include <QHash>
#include <QElapsedTimer>
#include <QJsonObject>
#include <QLocalSocket>
#include <QObject>
#include <QSet>
#include <QTimer>
#include <functional>

// A control client never asks for or receives credential material. Mutations are
// sent once: a disconnected transport leaves their result unknown until the next
// snapshot rather than replaying an operation that may already have committed.
class OmuxClient final : public QObject {
public:
    using Reply = std::function<void(const QJsonObject &, const QString &)>;
    explicit OmuxClient(QString socketPath, QObject *parent = nullptr);
    ~OmuxClient() override;
    void connectToDaemon();
    void request(const QString &method, QJsonObject params, Reply reply);
    bool ready() const { return ready_; }
    bool hasUncertainOperations() const { return !uncertain_.isEmpty(); }
    QString uncertaintyMessage() const;
    const QString &socketPath() const { return socketPath_; }
    std::function<void(bool, const QString &)> onConnection;
    std::function<void(const QJsonObject &)> onEvent;
    static QString defaultSocketPath();

private:
    struct Pending { Reply reply; qint64 deadline; QString operationID; bool mutation; };
    QHash<QString, QString> uncertain_;
    QSet<QString> reconciling_;
    QSet<QString> verifications_;
    QSet<QString> stoppedVerifications_;
    qint64 nextVerificationQuery_ = 0;
    qint64 revision_ = 0;
    void reconcileOperations();
    void readFrames();
    void disconnectWithReason(const QString &reason);
    void send(const QString &method, const QJsonObject &params, Reply reply);
    void publishConnection(bool connected, const QString &message);
    bool verifyPeer() const;
    QString socketPath_;
    QLocalSocket socket_;
    QTimer reconnect_;
    QTimer deadlines_;
    QElapsedTimer clock_;
    QByteArray buffer_;
    QHash<qint64, Pending> pending_;
    qint64 nextID_ = 1;
    qint64 connectDeadline_ = 0;
    bool ready_ = false;
    bool connecting_ = false;
    static constexpr qsizetype maximumFrame = 1024 * 1024;
};
