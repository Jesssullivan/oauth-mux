#include "siwc_enrollment.h"
#include "siwc_browser.h"
#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QDir>
#include <QElapsedTimer>
#include <QEvent>
#include <QFileInfo>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QLocalServer>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QTemporaryDir>
#include <QTimer>
#include <memory>
#include <sys/resource.h>

namespace {
bool until(const std::function<bool()> &predicate) {
    QElapsedTimer timer; timer.start();
    while (timer.elapsed() < 5000) { QApplication::processEvents(); if (predicate()) return true; }
    return false;
}
QJsonObject descriptor() {
    return {{"schema_version", 1}, {"profile", "openai_siwc_responses_v1"}, {"purpose", "fresh_openai_siwc_oauth_enrollment"},
        {"provider", "openai_siwc"}, {"issuer", "https://auth.openai.com"}, {"audience", "https://api.openai.com/v1"},
        {"enrollment_io_policy", "documented_oss_dynamic_registration_v1"}, {"experimental", true}, {"implemented", true}, {"custody_available", true},
        {"provider_proof", false}, {"native_support_proven", false}, {"live_handoff_proven", false},
        {"methods", QJsonObject{{"prepare", "oauth.enrollment.prepare.siwc.v1"}, {"authorization", "oauth.enrollment.authorization.v1"},
            {"status", "oauth.enrollment.status.v1"}, {"pending", "oauth.enrollment.pending.v1"}, {"withdraw", "oauth.enrollment.withdraw.v1"}}},
        {"authorization_policy", QJsonObject{{"scheme", "https"}, {"host", "auth.openai.com"}, {"path", "/api/accounts/authorize"},
            {"initial_client_id", "dynamic_agent_client"}, {"agent_name_hint", "omux"}, {"redirect_scheme", "http"}, {"redirect_host", "127.0.0.1"},
            {"redirect_path", "/auth/callback"}, {"redirect_port", "held_nonzero_loopback"}, {"resource", "https://api.openai.com/v1"},
            {"scopes", "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"}, {"pkce", "S256"}}},
        {"flow", QJsonObject{{"minimum_seconds", 1}, {"maximum_seconds", 3600}, {"minted_once", true}, {"wall_and_awake", true},
            {"rpc_deadline_separate", true}, {"exchange_max_seconds", 120}, {"authorization_deliveries", 1}, {"reconnect_renews", false}}}};
}
QString authorization() {
    return "https://auth.openai.com/api/accounts/authorize?client_id=dynamic_agent_client&agent_name_hint=omux&ext_agent_host_id="
        + QString(64, '1') + "&response_type=code&redirect_uri=http%3A%2F%2F127.0.0.1%3A12345%2Fauth%2Fcallback"
        + "&scope=openid%20profile%20email%20offline_access%20resource.invoke%20chatgpt.tokens.use.direct&state=" + QString(43, 'A')
        + "&nonce=" + QString(43, 'B') + "&code_challenge_method=S256&code_challenge=" + QString(43, 'C') + "&resource=https%3A%2F%2Fapi.openai.com%2Fv1";
}
}
int main(int argc, char **argv) {
    if (argc != 3 || !QFileInfo::exists(argv[1]) || !QFileInfo::exists(argv[2])) return 1;
    qputenv("QT_QPA_PLATFORM", "offscreen"); qputenv("FONTCONFIG_FILE", QFileInfo(argv[2]).absoluteFilePath().toUtf8());
    QDir plugins = QFileInfo(argv[1]).dir(); if (!plugins.cdUp()) return 2;
    qputenv("QT_PLUGIN_PATH", plugins.absolutePath().toUtf8());
    QApplication app(argc, argv); QCoreApplication::setLibraryPaths({plugins.absolutePath()});
    if (!validateSiwcAuthorization("openai_siwc_responses_v1", authorization())) return 3;
    for (const auto invalid : {authorization() + "&state=duplicate", QString(authorization()).replace("auth.openai.com", "invalid.example"),
            QString(authorization()).replace("127.0.0.1", "localhost"), QString(authorization()).replace("dynamic_agent_client", "unsupported-client"),
            QString(authorization()).replace("S256", "plain"), authorization() + "#fragment"})
        if (validateSiwcAuthorization("openai_siwc_responses_v1", invalid)) return 4;
    QTemporaryDir temporary; if (!temporary.isValid()) return 5;
    const auto socketPath = temporary.path() + "/control";
    QLocalServer server;
    server.setSocketOptions(QLocalServer::UserAccessOption);
    if (!server.listen(socketPath)) return 6;
    if (!QFile::setPermissions(socketPath, QFile::ReadOwner | QFile::WriteOwner)) return 48;
    QJsonValue capability = true;
    QString transaction(64, '2'), source(64, '3'); const QString account(64, '4');
    qint64 revision = 9007199254740993LL, seconds = 600;
    int prepares = 0, authorizations = 0, statuses = 0, withdrawals = 0, browserLaunches = 0, commits = 0;
    bool wireValid = true, ready = false, custody = true, heldAuthorization = false;
    QString state = "pending", phase = "prepared";
    QLocalSocket *held = nullptr; QByteArray heldReply;
    QJsonArray pendingRows;
    bool holdStatus = false, holdWithdrawal = false, holdOperation = false, holdPrepare = false;
    QLocalSocket *oldStatusSocket = nullptr, *oldWithdrawalSocket = nullptr, *oldOperationSocket = nullptr, *oldPrepareSocket = nullptr;
    QByteArray oldStatusReply, oldWithdrawalReply, oldOperationReply, oldPrepareReply;
    QJsonObject operationResult;
    QString oldWithdrawalOperation;
    int operationReads = 0;
    bool coreCustody = true;
    QObject::connect(&server, &QLocalServer::newConnection, &app, [&] {
        while (server.hasPendingConnections()) {
            auto *socket = server.nextPendingConnection(); auto buffer = std::make_shared<QByteArray>();
            QObject::connect(socket, &QLocalSocket::readyRead, &app, [&, socket, buffer] {
                buffer->append(socket->readAll());
                while (true) {
                    const auto end = buffer->indexOf('\n'); if (end < 0) return;
                    const auto raw = buffer->first(end); const auto call = QJsonDocument::fromJson(raw).object(); buffer->remove(0, end + 1);
                    const auto method = call.value("method").toString(); const auto params = call.value("params").toObject();
                    QJsonObject result;
                    if (method == "system.handshake") result = {{"protocol_version", 2}, {"capabilities", QJsonObject{{"owned_siwc_enrollment_v1", capability}}}};
                    else if (method == "state.snapshot") result = {{"revision", revision}, {"custody_available", custody}};
                    else if (method == "oauth.enrollment.descriptor.v1") { result = descriptor(); result.insert("custody_available", custody); }
                    else if (method == "oauth.enrollment.pending.v1") result = {{"schema_version", 1}, {"custody_available", custody}, {"status", custody ? "current" : "unknown"},
                        {"pending", custody ? QJsonValue(pendingRows) : QJsonValue(QJsonValue::Null)}};
                    else if (method == "oauth.enrollment.prepare.siwc.v1") {
                        ++prepares; oldWithdrawalOperation = params.value("operation_id").toString(); seconds = params.value("consent_seconds").toInteger();
                        wireValid = wireValid && params.size() == 5 && params.value("provider") == "openai_siwc"
                            && params.value("purpose") == "fresh_openai_siwc_oauth_enrollment" && params.value("operation_id").toString().size() == 64
                            && params.value("expected_revision").toInteger() == revision
                            && raw.contains(QByteArray("\"expected_revision\":") + QByteArray::number(revision)) && seconds >= 1 && seconds <= 3600;
                        result = {{"transaction_id", transaction}, {"source_id", source}, {"admitted_revision", ++revision}, {"flow_expires_at", QDateTime::currentSecsSinceEpoch() + seconds},
                            {"flow_seconds", seconds}, {"phase", "prepared"}, {"consent_recorded", true}, {"registration", "enrollment_policy"},
                            {"blocked_reason", QJsonValue(QJsonValue::Null)}, {"authorization_available", true}, {"provider_request_initiated", false}, {"grant_activated", false}};
                        operationResult = result;
                    } else if (method == "oauth.enrollment.status.v1") {
                        ++statuses;
                        wireValid = wireValid && params.size() == 2 && params.value("transaction_id") == transaction
                            && params.value("purpose") == "fresh_openai_siwc_oauth_enrollment" && !params.contains("consent_seconds") && !params.contains("operation_id");
                        if (!custody) result = {{"schema_version", 1}, {"transaction_id", transaction}, {"status", "unknown"}, {"phase", QJsonValue(QJsonValue::Null)},
                            {"custody_available", false}, {"paired_committed", QJsonValue(QJsonValue::Null)}, {"grant_ready", QJsonValue(QJsonValue::Null)}, {"reason", "custody_unavailable"}};
                        else {
                            result = {{"schema_version", 1}, {"transaction_id", transaction}, {"revision", revision}, {"status", state}, {"phase", phase},
                                {"custody_available", true}, {"paired_committed", state == "paired" || state == "retired"}, {"grant_ready", state == "paired" && ready},
                                {"consent_status", state == "cancelled" ? "withdrawn" : "recorded"}, {"source_id", source}, {"account_id", state == "paired" || state == "retired" ? QJsonValue(account) : QJsonValue(QJsonValue::Null)}};
                            if (state != "paired" && state != "retired") { result.insert("flow_expires_at", QDateTime::currentSecsSinceEpoch() + seconds); result.insert("flow_seconds", seconds); result.insert("flow_expired", state == "expired"); }
                            else result.insert("retirement_reason", state == "retired" ? "source_disconnected" : "none");
                        }
                    } else if (method == "oauth.enrollment.authorization.v1") {
                        ++authorizations;
                        struct rlimit core {};
                        coreCustody = coreCustody && ::getrlimit(RLIMIT_CORE, &core) == 0 && core.rlim_cur == 0 && core.rlim_max == 0;
                        wireValid = wireValid && params.size() == 3 && params.value("purpose") == "fresh_openai_siwc_oauth_enrollment"
                            && params.value("transaction_id") == transaction && params.value("expected_revision").toInteger() == revision && !params.contains("operation_id");
                        result = {{"authorization_url", authorization()}, {"provider_request_initiated", false}, {"grant_activated", false}};
                    } else if (method == "oauth.enrollment.withdraw.v1") {
                        ++withdrawals; oldWithdrawalOperation = params.value("operation_id").toString();
                        wireValid = wireValid && params.size() == 4 && params.value("transaction_id") == transaction && params.value("expected_revision").toInteger() == revision
                            && params.value("purpose") == "fresh_openai_siwc_oauth_enrollment" && params.value("operation_id").toString().size() == 64;
                        result = {{"consent_withdrawn", true}, {"issued_work_may_have_occurred", true}, {"upstream_revoked", false}};
                        operationResult = result;
                    } else if (method == "operation.status") {
                        ++operationReads;
                        wireValid = wireValid && params.size() == 1 && params.value("operation_id") == oldWithdrawalOperation;
                        result = {{"operation_id", oldWithdrawalOperation}, {"status", "completed"},
                            {"result", operationResult}};
                    } else { wireValid = false; result = {}; }
                    auto reply = QJsonDocument(QJsonObject{{"jsonrpc", "2.0"}, {"id", call.value("id")}, {"result", result}}).toJson(QJsonDocument::Compact) + '\n';
                    if (method == "oauth.enrollment.authorization.v1" && heldAuthorization) { held = socket; heldReply = reply; continue; }
                    if (method == "oauth.enrollment.prepare.siwc.v1" && holdPrepare) { oldPrepareSocket = socket; oldPrepareReply = reply; continue; }
                    if (method == "oauth.enrollment.status.v1" && holdStatus) { oldStatusSocket = socket; oldStatusReply = reply; continue; }
                    if (method == "oauth.enrollment.withdraw.v1" && holdWithdrawal) { oldWithdrawalSocket = socket; oldWithdrawalReply = reply; continue; }
                    if (method == "operation.status" && holdOperation) { oldOperationSocket = socket; oldOperationReply = reply; continue; }
                    socket->write(reply); socket->flush();
                }
            });
        }
    });
    for (const auto value : {QJsonValue(false), QJsonValue(QString("true"))}) {
        capability = value; QWidget parent; OmuxClient client(socketPath); SiwcEnrollment enrollment(client, &parent);
        client.connectToDaemon(); if (!until([&] { return client.ready(); })) return 7;
        enrollment.open(); auto *panel = parent.findChild<QDialog *>("siwcEnrollment");
        auto *notice = panel->findChild<QLabel *>("siwcStatus");
        if (!notice->text().contains("has not negotiated") || prepares != 0 || authorizations != 0) return 8;
    }
    capability = true;
    QWidget parent; OmuxClient client(socketPath);
    SiwcEnrollment enrollment(client, &parent, [&](const QString &profile, const QString &url) {
        ++browserLaunches; return validateSiwcAuthorization(profile, url);
    });
    enrollment.onCommitted = [&] { ++commits; };
    client.onConnection = [&](bool connected, const QString &) { enrollment.connectionChanged(connected); };
    client.connectToDaemon(); if (!until([&] { return client.ready(); })) return 9;
    bool snapshot = false; client.request("state.snapshot", {}, [&](const QJsonObject &, const QString &) { snapshot = true; }); if (!until([&] { return snapshot; })) return 10;
    enrollment.open(); auto *panel = parent.findChild<QDialog *>("siwcEnrollment");
    auto *notice = panel->findChild<QLabel *>("siwcStatus"); auto *consent = panel->findChild<QCheckBox *>("siwcConsent");
    auto *start = panel->findChild<QPushButton *>("siwcStart"); auto *check = panel->findChild<QPushButton *>("siwcCheck");
    auto *cancel = panel->findChild<QPushButton *>("siwcCancel");
    if (!until([&] { return notice->text().contains("Confirm finite consent"); }) || start->isEnabled()) return 11;
    consent->setChecked(true); start->click();
    if (!until([&] { return browserLaunches == 1 && notice->text().contains("Enrollment pending"); }) || prepares != 1 || authorizations != 1 || commits != 0) return 12;
    for (const auto *label : panel->findChildren<QLabel *>()) if (label->text().contains("authorize?") || label->text().contains("code_challenge")) return 13;
    // Automatic completion uses actual status reads, not account counts or a
    // second consent/authorization delivery. Paired-but-unusable is distinct.
    state = "paired"; phase = "active"; ready = false;
    if (!until([&] { return notice->text().contains("current request grant is unavailable"); }) || commits != 1 || prepares != 1 || authorizations != 1) return 14;
    ready = true; check->click(); if (!until([&] { return notice->text().contains("Request authority is retained"); })) return 15;
    custody = false; check->click(); if (!until([&] { return notice->text().contains("normal OS Secret Service"); }) || cancel->isEnabled()) return 16;
    custody = true; enrollment.observe({{"custody_available", true}}); if (!until([&] { return cancel->isEnabled(); })) return 17;
    // Independent typed reply variants exercise actual rendering and clear
    // prior readiness. They are projection samples, not actor transition proof.
    for (const auto &sample : {qMakePair(QString("expired"), QString("prepared")), qMakePair(QString("quarantined"), QString("quarantined")),
            qMakePair(QString("unknown"), QString("completion_unknown")), qMakePair(QString("cancelled"), QString("retired")), qMakePair(QString("retired"), QString("retired"))}) {
        state = sample.first; phase = sample.second; check->click();
        const auto expected = state == "expired" ? "original enrollment expired" : state == "cancelled" ? "Enrollment is cancelled"
            : state == "retired" ? "Retirement alone does not establish consent withdrawal" : "Unknown or quarantined";
        if (!until([&] { return notice->text().contains(expected); }) || notice->text().contains("Request authority is retained") || prepares != 1 || authorizations != 1) return 22;
    }
    QTimer::singleShot(0, &app, [&] { for (auto *widget : QApplication::topLevelWidgets()) if (auto *box = qobject_cast<QMessageBox *>(widget)) box->done(QMessageBox::Yes); });
    cancel->click(); if (!until([&] { return withdrawals == 1 && notice->text().contains("paired grants for it were retired"); }) || consent->isChecked() || start->isEnabled()) return 18;
    // Explicit cancellation also fences an already-issued held URL response.
    state = "pending"; phase = "prepared"; heldAuthorization = true;
    consent->setChecked(true); start->click(); if (!until([&] { return held != nullptr; })) return 19;
    QTimer::singleShot(0, &app, [&] { for (auto *widget : QApplication::topLevelWidgets()) if (auto *box = qobject_cast<QMessageBox *>(widget)) box->done(QMessageBox::Yes); });
    cancel->click(); if (!until([&] { return withdrawals == 2 && notice->text().contains("paired grants for it were retired"); })) return 23;
    held->write(heldReply); held->flush();
    snapshot = false; client.request("state.snapshot", {}, [&](const QJsonObject &, const QString &) { snapshot = true; });
    if (!until([&] { return snapshot; }) || browserLaunches != 1 || authorizations != 2 || prepares != 2) return 24;
    // Closing the panel preserves daemon flow ownership but stops UI delivery.
    held = nullptr; consent->setChecked(true); start->click(); if (!until([&] { return held != nullptr; })) return 25;
    panel->close(); held->write(heldReply); held->flush();
    snapshot = false; client.request("state.snapshot", {}, [&](const QJsonObject &, const QString &) { snapshot = true; });
    if (!until([&] { return snapshot; }) || browserLaunches != 1 || authorizations != 3 || prepares != 3) return 20;
    if (!wireValid || statuses < 5 || withdrawals != 2 || !coreCustody) return 21;
    // Recover an actual undelivered daemon owner in a fresh thin manager. No
    // prepare, consent renewal or URL retry occurs while switching selections.
    heldAuthorization = false; state = "pending"; phase = "prepared"; ready = false;
    const auto pendingRow = [&](const QString &id, const QString &sourceID, bool delivered) {
        return QJsonObject{{"transaction_id", id}, {"source_id", sourceID}, {"phase", "prepared"},
            {"flow_expires_at", QDateTime::currentSecsSinceEpoch() + 600}, {"authorization_delivered", delivered}};
    };
    const QString first(64, '5'), firstSource(64, '6'), second(64, '7'), secondSource(64, '8');
    transaction = first; source = firstSource;
    pendingRows = {pendingRow(first, firstSource, false), pendingRow(second, secondSource, true)};
    QWidget recoveredParent; OmuxClient recoveredClient(socketPath);
    SiwcEnrollment recovered(recoveredClient, &recoveredParent, [&](const QString &profile, const QString &url) {
        ++browserLaunches; return validateSiwcAuthorization(profile, url);
    });
    recoveredClient.onEvent = [&](const QJsonObject &event) { recovered.operationEvent(event); };
    recoveredClient.connectToDaemon(); if (!until([&] { return recoveredClient.ready(); })) return 26;
    snapshot = false; recoveredClient.request("state.snapshot", {}, [&](const QJsonObject &, const QString &) { snapshot = true; });
    if (!until([&] { return snapshot; })) return 27;
    recovered.open(); auto *recoveredPanel = recoveredParent.findChild<QDialog *>("siwcEnrollment");
    auto *selection = recoveredPanel->findChild<QComboBox *>("siwcPending");
    auto *recoveredNotice = recoveredPanel->findChild<QLabel *>("siwcStatus");
    auto *recoveredCheck = recoveredPanel->findChild<QPushButton *>("siwcCheck");
    auto *recoveredConsent = recoveredPanel->findChild<QCheckBox *>("siwcConsent");
    auto *recoveredOpen = recoveredPanel->findChild<QPushButton *>("siwcOpenBrowser");
    if (!until([&] { return selection->count() == 3; })) return 28;
    selection->setCurrentIndex(1); selection->activated(1);
    if (!until([&] { return recoveredNotice->text().contains("Transaction " + first); })) return 29;
    recoveredConsent->setChecked(true); recoveredOpen->click();
    if (!until([&] { return browserLaunches == 2 && recoveredNotice->text().contains("Enrollment pending"); })
        || authorizations != 4 || prepares != 3 || !coreCustody) return 30;
    // A held old status callback may neither hold the new request gate nor
    // replace the newer owner's display when it eventually arrives.
    holdStatus = true; recoveredCheck->click(); if (!until([&] { return oldStatusSocket != nullptr; })) return 31;
    holdStatus = false; transaction = second; source = secondSource;
    selection->setCurrentIndex(2); selection->activated(2);
    if (!until([&] { return recoveredCheck->isEnabled() && recoveredNotice->text().contains("Transaction " + second); })) return 32;
    oldStatusSocket->write(oldStatusReply); oldStatusSocket->flush();
    snapshot = false; recoveredClient.request("state.snapshot", {}, [&](const QJsonObject &, const QString &) { snapshot = true; });
    if (!until([&] { return snapshot; }) || !recoveredNotice->text().contains("Transaction " + second)
        || authorizations != 4 || prepares != 3) return 33;
    // A source-specific withdrawal remains bound to the original handle even
    // if its operation.status ACK is read after closure and selecting another.
    holdWithdrawal = holdOperation = true;
    QTimer::singleShot(0, &app, [&] { for (auto *widget : QApplication::topLevelWidgets()) if (auto *box = qobject_cast<QMessageBox *>(widget)) box->done(QMessageBox::Yes); });
    recoveredPanel->findChild<QPushButton *>("siwcCancel")->click();
    if (!until([&] { return oldWithdrawalSocket != nullptr; })) return 34;
    recoveredPanel->close();
    if (!until([&] { return oldOperationSocket != nullptr; })) return 35;
    QApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    recovered.open(); recoveredPanel = recoveredParent.findChild<QDialog *>("siwcEnrollment");
    selection = recoveredPanel->findChild<QComboBox *>("siwcPending"); recoveredNotice = recoveredPanel->findChild<QLabel *>("siwcStatus");
    if (!until([&] { return selection->count() == 3; })) return 36;
    transaction = first; source = firstSource; selection->setCurrentIndex(1); selection->activated(1);
    if (!until([&] { return recoveredNotice->text().contains("Transaction " + first); })) return 37;
    holdOperation = holdWithdrawal = false;
    oldOperationSocket->write(oldOperationReply); oldOperationSocket->flush();
    oldWithdrawalSocket->write(oldWithdrawalReply); oldWithdrawalSocket->flush();
    snapshot = false; recoveredClient.request("state.snapshot", {}, [&](const QJsonObject &, const QString &) { snapshot = true; });
    if (!until([&] { return snapshot && !recoveredClient.hasUncertainOperations(); })
        || !recoveredNotice->text().contains("Transaction " + first) || recoveredNotice->text().contains("consent was withdrawn")
        || withdrawals != 3 || prepares != 3 || authorizations != 4 || operationReads != 1) return 38;
    recoveredPanel->close(); QApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    // Original prepare completion is also selection-bound. Recovered operation
    // ACK may expose its original public owner, but cannot choose it for a user
    // who has explicitly selected another pending owner in the meantime.
    transaction = QString(64, '9'); source = QString(64, 'a');
    pendingRows = {pendingRow(first, firstSource, true)};
    holdPrepare = holdOperation = true; oldOperationSocket = nullptr;
    QWidget preparingParent; OmuxClient preparingClient(socketPath);
    SiwcEnrollment preparing(preparingClient, &preparingParent, [&](const QString &, const QString &) { ++browserLaunches; return true; });
    preparingClient.onEvent = [&](const QJsonObject &event) { preparing.operationEvent(event); };
    preparingClient.connectToDaemon(); if (!until([&] { return preparingClient.ready(); })) return 40;
    snapshot = false; preparingClient.request("state.snapshot", {}, [&](const QJsonObject &, const QString &) { snapshot = true; });
    if (!until([&] { return snapshot; })) return 41;
    preparing.open(); auto *preparingPanel = preparingParent.findChild<QDialog *>("siwcEnrollment");
    if (!until([&] { return preparingPanel->findChild<QLabel *>("siwcStatus")->text().contains("Confirm finite consent"); })) return 42;
    preparingPanel->findChild<QCheckBox *>("siwcConsent")->setChecked(true);
    preparingPanel->findChild<QPushButton *>("siwcStart")->click();
    if (!until([&] { return oldPrepareSocket != nullptr; })) return 43;
    preparingPanel->close(); if (!until([&] { return oldOperationSocket != nullptr; })) return 44;
    QApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
    preparing.open(); preparingPanel = preparingParent.findChild<QDialog *>("siwcEnrollment");
    selection = preparingPanel->findChild<QComboBox *>("siwcPending");
    auto *preparingNotice = preparingPanel->findChild<QLabel *>("siwcStatus");
    if (!until([&] { return selection->count() == 2; })) return 45;
    transaction = first; source = firstSource; selection->setCurrentIndex(1); selection->activated(1);
    if (!until([&] { return preparingNotice->text().contains("Transaction " + first); })) return 46;
    holdPrepare = holdOperation = false;
    oldOperationSocket->write(oldOperationReply); oldOperationSocket->flush();
    oldPrepareSocket->write(oldPrepareReply); oldPrepareSocket->flush();
    snapshot = false; preparingClient.request("state.snapshot", {}, [&](const QJsonObject &, const QString &) { snapshot = true; });
    if (!until([&] { return snapshot && !preparingClient.hasUncertainOperations(); })
        || !preparingNotice->text().contains("Transaction " + first) || browserLaunches != 2
        || authorizations != 4 || prepares != 4 || withdrawals != 3 || operationReads != 2) return 47;
    return wireValid && coreCustody ? 0 : 39;
}
