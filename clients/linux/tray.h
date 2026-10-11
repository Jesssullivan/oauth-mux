#pragma once

#include "omux_client.h"
#include "codex_account_acquisition.h"
#include <QDialog>
#include <QJsonArray>
#include <QLabel>
#include <QSystemTrayIcon>
#include <QTableWidget>
#include <QTimer>

class QPushButton;

class OmuxTray final : public QDialog {
public:
    explicit OmuxTray(QString socketPath, bool startConnections = true, bool explicitSocket = false);
private:
    void refresh();
    void refreshReadiness();
    void applySnapshot(const QJsonObject &snapshot);
    void action(const QString &method, QJsonObject params);
    void connectSource();
    void enroll();
    void accountAction(const QString &method);
    void sourceAction(const QString &method);
    QJsonObject selectedSource() const;
    QString sourceReconcileIssue(bool forEnrollment = false) const;
    void updateMutationControls();
    void integrationAction(const QString &method);
    void discoverNative();
    void nativeAction(const QString &method);
    void serviceAction(const QString &action);
    QString selectedID(QTableWidget *table) const;
    QTableWidget *makeTable(const QStringList &columns);
    void fillTable(QTableWidget *table, const QJsonArray &array,
                   const QStringList &fields);
    void closeEvent(QCloseEvent *event) override;
    OmuxClient client_;
    std::unique_ptr<CodexAccountAcquisition> acquisition_;
    QPushButton *sourceSignIn_;
    QSystemTrayIcon tray_;
    QLabel *connection_;
    QLabel *message_;
    QLabel *policy_;
    QLabel *service_;
    QTableWidget *readiness_;
    QLabel *setupNotice_;
    QPushButton *setupVerify_;
    QTableWidget *accounts_;
    QTableWidget *sources_;
    QLabel *sourceNotice_;
    QLabel *sourceAcquisitionNotice_;
    QPushButton *sourceEnroll_;
    QPushButton *sourceReconcile_;
    QPushButton *sourceDisconnect_;
    QTableWidget *grants_;
    QTableWidget *capacity_;
    QTableWidget *bindings_;
    QTableWidget *leases_;
    QTableWidget *operations_;
    QTableWidget *integrations_;
    QTableWidget *nativeThreads_;
    QTimer refreshTimer_;
    bool refreshing_ = false;
    bool explicitSocket_ = false;
    bool connected_ = false;
    bool custodyAvailable_ = false;
    qint64 revision_ = -1;
    QJsonObject snapshot_;
    QHash<QString, QString> integrationPaths_;
    QHash<QString, QString> accountLabels_;
    QString nativeSocket_;
    QString acquisitionSourceSelection_;
    QList<QWidget *> mutationControls_;
};
