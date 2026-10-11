#include "tray.h"
#include <QAbstractItemModel>
#include <QApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QJsonDocument>
#include <QLocalServer>
#include <QPushButton>
#include <QSet>
#include <QTemporaryDir>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QDateTime>
#include <cstdio>
#include <memory>

namespace {
bool until(const std::function<bool()> &done) {
    QElapsedTimer elapsed;
    elapsed.start();
    while (!done() && elapsed.elapsed() < 3000)
        QApplication::processEvents(QEventLoop::AllEvents, 10);
    return done();
}
QJsonObject report(bool duplicate) {
    QJsonArray findings;
    for (const auto *phase : {"artifact", "service", "vault", "source", "identity", "grant", "native"})
        findings.append(QJsonObject{{"phase", duplicate ? "artifact" : phase},
            {"reason", QString(phase) == "native" ? "missing" : "ready"},
            {"action", QString(phase) == "native" ? "install_native_adapter" : "none"}});
    return {{"schema_version", 1}, {"ready", false}, {"findings", findings}, {"seamless_handoff_proven", false}};
}
QJsonObject capacitySnapshot(bool custodyReady) {
    const auto now = QDateTime::currentSecsSinceEpoch();
    const QJsonObject resource {{"kind", "api-calls"}, {"target", "core"}, {"unit", "calls"}, {"scope", "github:rest:core"}};
    const QJsonObject total {{"provider", "github"}, {"resource", resource}, {"remaining", 42},
        {"window_start", now - 3600}, {"window_end", now + 3600}, {"complete", true},
        {"buckets", 1}, {"unknown_buckets", 0}};
    auto partial = total;
    partial.insert("complete", false);
    partial.insert("buckets", 0);
    partial.insert("unknown_buckets", 1);
    partial.insert("remaining", 0);
    const QJsonObject sample {{"account_id", "retained-fixture"}, {"resource", resource}, {"remaining", 42},
        {"status", "ready"}, {"observed_at", now - 10}, {"expires_at", now + 3600},
        {"window_start", now - 3600}, {"window_end", now + 3600}};
    auto unavailable = sample;
    unavailable.insert("status", "unavailable");
    unavailable.insert("remaining", 0);
    auto unknown = sample;
    unknown.insert("status", "unknown");
    auto expired = sample;
    expired.insert("expires_at", now - 1);
    auto ended = sample;
    ended.insert("window_end", now - 1);
    auto futureObservation = sample;
    futureObservation.insert("observed_at", now + 1800);
    auto futureWindow = sample;
    futureWindow.insert("window_start", now + 3600);
    futureWindow.insert("window_end", now + 7200);
    return {{"revision", 1}, {"custody_available", custodyReady}, {"captured_at", now},
        {"accounts", QJsonArray{QJsonObject{{"id", "retained-fixture"}, {"label", "Retained fixture"},
            {"identity", QJsonObject{{"provider", "github"}}}, {"account_type", "future_plan"}, {"lifecycle", "paused"}}}},
        {"capacity", QJsonArray{total, partial}},
        {"observations", QJsonArray{sample, unavailable, unknown, expired, ended, futureObservation, futureWindow}}};
}
QJsonObject drilldownSnapshot(bool custodyReady, int mode) {
    const auto now = QDateTime::currentSecsSinceEpoch();
    const QJsonObject resource {{"kind", "api-calls"}, {"target", "core"}, {"unit", "calls"}, {"scope", "github:rest:core"}};
    auto bytes = resource;
    bytes.insert("unit", "bytes");
    bytes.insert("scope", "github:rest:bytes");
    const QJsonObject total {{"provider", "github"}, {"issuer", "synthetic-issuer-group"}, {"resource", resource},
        {"remaining", 17}, {"limit", 100}, {"window_start", now - 3600}, {"window_end", now + 3600},
        {"complete", true}, {"buckets", 1}, {"unknown_buckets", 0}};
    auto partial = total;
    partial.insert("resource", bytes);
    partial.insert("remaining", 0);
    partial.insert("complete", false);
    partial.insert("buckets", 0);
    partial.insert("unknown_buckets", 1);
    const QJsonObject observation {{"account_id", "detail-account-a"}, {"resource", resource},
        {"bucket_id", "synthetic-shared-bucket"}, {"remaining", 17}, {"limit", 100},
        {"window_start", now - 3600}, {"window_end", now + 3600}, {"observed_at", now - 10},
        {"expires_at", now + 3600}, {"status", "ready"}, {"provenance", "fixture"}};
    auto shared = observation;
    shared.insert("account_id", "detail-account-b");
    auto unknown = observation;
    unknown.insert("resource", bytes);
    unknown.insert("bucket_id", "synthetic-other-bucket");
    unknown.insert("status", "unknown");
    unknown.insert("remaining", 999);
    unknown.insert("window_start", now - 1800);
    unknown.insert("window_end", now + 1800);
    const QJsonObject account {{"id", "detail-account-a"}, {"label", "Descriptive fixture label"},
        {"identity", QJsonObject{{"provider", "github"}, {"verified", false}}},
        {"account_type", "fixture-type"}, {"lifecycle", "paused"},
        {"source_ids", QJsonArray{"detail-source-connected", "detail-source-detached"}}};
    auto otherAccount = account;
    otherAccount.insert("id", "detail-account-b");
    otherAccount.insert("identity", QJsonObject{{"provider", "github"}, {"verified", true}});
    otherAccount.insert("lifecycle", "active");
    const QJsonObject source {{"id", "detail-source-connected"}, {"provider", "github"}, {"label", "Source fixture"},
        {"kind", "explicit"}, {"status", "connected"}, {"authorized_at", now - 100}, {"authorized_until", now + 1000}};
    auto detached = source;
    detached.insert("id", "detail-source-detached");
    detached.insert("status", "detached");
    const QJsonObject grant {{"id", "detail-grant-ready"}, {"account_id", "detail-account-a"},
        {"source_id", "detail-source-detached"}, {"status", "ready"}, {"credential_kind", "oauth_access"},
        {"ownership", "adopted"}, {"purposes", QJsonArray{"request"}}, {"audience", "https://github.com"},
        {"scopes", QJsonArray{"fixture-scope"}}, {"generation", 4},
        {"provider_expires_at", now + 3600}, {"custody_expires_at", QJsonValue(QJsonValue::Null)}};
    auto invalid = grant;
    invalid.insert("id", "detail-grant-invalid");
    invalid.insert("source_id", "detail-source-connected");
    invalid.insert("status", "invalid");
    invalid.insert("credential_kind", "oauth_refresh");
    invalid.insert("ownership", "external");
    invalid.insert("purposes", QJsonArray{"renewal"});
    auto otherGrant = grant;
    otherGrant.insert("id", "detail-grant-other");
    otherGrant.insert("account_id", "detail-account-b");
    const QJsonObject binding {{"id", "detail-route-a"}, {"application", "git"}, {"session_id", "synthetic-session"},
        {"native_ref", QJsonValue(QJsonValue::Null)}, {"account_id", "detail-account-a"},
        {"grant_id", "detail-grant-ready"}, {"grant_generation", 3}, {"route_generation", 2}, {"in_flight", 1}};
    auto otherBinding = binding;
    otherBinding.insert("id", "detail-route-b");
    otherBinding.insert("account_id", "detail-account-b");
    otherBinding.insert("grant_id", "detail-grant-other");
    otherBinding.insert("grant_generation", 4);
    const QJsonObject lease {{"id", "detail-lease-a"}, {"binding_id", "detail-route-a"},
        {"account_id", "detail-account-a"}, {"grant_id", "detail-grant-ready"}, {"grant_generation", 3},
        {"route_generation", 2}, {"purpose", "request"}, {"audience", "https://github.com"},
        {"scopes", QJsonArray{"fixture-scope"}}, {"started_at", now - 100}, {"expires_at", now + 1000}};
    auto otherLease = lease;
    otherLease.insert("id", "detail-lease-other");
    otherLease.insert("binding_id", "detail-route-b");
    otherLease.insert("account_id", "detail-account-b");
    otherLease.insert("grant_id", "detail-grant-other");
    otherLease.insert("grant_generation", 4);
    QJsonObject snapshot {{"revision", 2}, {"custody_available", custodyReady}, {"captured_at", now},
        {"accounts", QJsonArray{account, otherAccount}}, {"sources", QJsonArray{source, detached}},
        {"grants", QJsonArray{grant, invalid, otherGrant}}, {"bindings", QJsonArray{binding, otherBinding}},
        {"leases", QJsonArray{lease, otherLease}}, {"capacity", QJsonArray{total, partial}},
        {"observations", QJsonArray{observation, shared, unknown}}};
    if (mode == 1) {
        auto missing = account;
        missing.insert("identity", QJsonObject{{"provider", "github"}});
        missing.remove("source_ids");
        snapshot.insert("accounts", QJsonArray{missing});
        snapshot.remove("grants");
        snapshot.remove("sources");
    } else if (mode == 2) snapshot.insert("grants", QJsonArray{});
    return snapshot;
}
}

int main(int argc, char **argv) {
    // The declared offscreen plugin is a Bazel input. Qt's compiled Nix
    // defaults need not be visible inside the local test sandbox.
    std::setvbuf(stderr, nullptr, _IONBF, 0);
    qInstallMessageHandler([](QtMsgType, const QMessageLogContext &, const QString &message) {
        std::fprintf(stderr, "setup_ui_test Qt: %s\n", message.toUtf8().constData());
    });
    if (argc != 3) {
        std::fprintf(stderr, "setup_ui_test requires declared offscreen plugin and font configuration inputs\n");
        return 7;
    }
    const QFileInfo plugin(QString::fromLocal8Bit(argv[1]));
    if (!plugin.exists() || plugin.fileName() != "libqoffscreen.so") {
        std::fprintf(stderr, "setup_ui_test declared offscreen plugin unavailable\n");
        return 8;
    }
    const auto platforms = plugin.absolutePath();
    const auto plugins = QDir(platforms).absoluteFilePath("..");
    qputenv("QT_PLUGIN_PATH", plugins.toUtf8());
    qputenv("QT_QPA_PLATFORM_PLUGIN_PATH", platforms.toUtf8());
    qputenv("QT_QPA_PLATFORM", "offscreen");
    const QFileInfo fontConfig(QString::fromLocal8Bit(argv[2]));
    if (!fontConfig.isFile()) {
        std::fprintf(stderr, "setup_ui_test declared font configuration unavailable\n");
        return 9;
    }
    QTemporaryDir desktop("/tmp/omux-setup-desktop-XXXXXX");
    if (!desktop.isValid()) return 10;
    qputenv("FONTCONFIG_FILE", fontConfig.absoluteFilePath().toUtf8());
    qputenv("FONTCONFIG_PATH", fontConfig.absolutePath().toUtf8());
    qputenv("XDG_CACHE_HOME", desktop.path().toUtf8());
    qputenv("XDG_CONFIG_HOME", desktop.path().toUtf8());
    qputenv("XDG_DATA_HOME", desktop.path().toUtf8());
    qputenv("XDG_RUNTIME_DIR", desktop.path().toUtf8());
    qputenv("QT_QPA_FONTDIR", desktop.path().toUtf8());
    std::fprintf(stderr, "setup_ui_test: constructing Qt offscreen application\n");
    QApplication app(argc, argv);
    QCoreApplication::setLibraryPaths({plugins});
    QTemporaryDir directory("/tmp/omux-setup-ui-XXXXXX");
    QLocalServer server;
    server.setSocketOptions(QLocalServer::UserAccessOption);
    const auto socketPath = directory.path() + "/control.sock";
    if (!server.listen(socketPath) || !QFile::setPermissions(socketPath, QFile::ReadOwner | QFile::WriteOwner)) {
        std::fprintf(stderr, "setup_ui_test: private fixture listener unavailable\n");
        return 1;
    }
    bool duplicate = false;
    bool contradictoryReady = false;
    bool decline = false;
    bool snapshotDecline = false;
    QString snapshotRefusal = "SnapshotTooLarge";
    bool holdNextReadiness = false;
    QLocalSocket *heldReadinessSocket = nullptr;
    QByteArray heldReadinessReply;
    bool omitCapture = false;
    bool integrationDecline = false;
    bool omitRuntime = false;
    bool detailsFixture = false;
    int detailsMode = 0;
    bool uncertainRecovery = false;
    bool originalOutcomeCompleted = false;
    QString originalOperation;
    int originalMutationRequests = 0;
    int originalOutcomeQueries = 0;
    bool originalWireValid = true;
    bool pendingRemovalFixture = false;
    QString removalReason = "NativeRequestsPending";
    int removalRequests = 0;
    QSet<QString> removalOperations;
    bool removalWireValid = true;
    QJsonObject runtimeSelection {{"qualification", "measured_installed_bytes_only"},
        {"native_support", false}, {"state", "unselected"}, {"reason", QJsonValue(QJsonValue::Null)}};
    int connections = 0;
    int mutations = 0;
    int reopenRequests = 0;
    int readinessRequests = 0;
    bool strictReopen = true;
    bool custodyReady = true;
    QString reopenResultMode = "ready";
    QJsonValue reopenCapability(QJsonValue::Undefined); // Absent capability is the installed-old-service case.
    QObject::connect(&server, &QLocalServer::newConnection, &server, [&] {
        ++connections;
        auto *socket = server.nextPendingConnection();
        socket->setParent(&server);
        auto buffer = std::make_shared<QByteArray>();
        QObject::connect(socket, &QLocalSocket::readyRead, socket, [&, socket, buffer] {
            *buffer += socket->readAll();
            while (buffer->contains('\n')) {
                const auto end = buffer->indexOf('\n');
                const auto request = QJsonDocument::fromJson(buffer->left(end)).object();
                buffer->remove(0, end + 1);
                const auto method = request.value("method").toString();
                if (uncertainRecovery && method == "policy.set") {
                    ++originalMutationRequests;
                    const auto params = request.value("params").toObject();
                    originalOperation = params.value("operation_id").toString();
                    originalWireValid = originalWireValid && !originalOperation.isEmpty()
                        && params.value("expected_revision").toInteger(-1) == 1;
                    custodyReady = false;
                    snapshotDecline = true;
                    snapshotRefusal = "CustodyLocked";
                    socket->write(QJsonDocument(QJsonObject{{"jsonrpc", "2.0"}, {"id", request.value("id")},
                        {"error", QJsonObject{{"code", -32000}, {"message", "CustodyLocked"}}}}).toJson(QJsonDocument::Compact) + '\n');
                    continue;
                }
                if (uncertainRecovery && method == "operation.status" && !custodyReady) {
                    ++originalOutcomeQueries;
                    originalWireValid = originalWireValid
                        && request.value("params").toObject().value("operation_id").toString() == originalOperation;
                    socket->write(QJsonDocument(QJsonObject{{"jsonrpc", "2.0"}, {"id", request.value("id")},
                        {"error", QJsonObject{{"code", -32000}, {"message", "CustodyLocked"}}}}).toJson(QJsonDocument::Compact) + '\n');
                    continue;
                }
                if (method == "setup.readiness" && decline) {
                    socket->write(QJsonDocument(QJsonObject{{"jsonrpc", "2.0"}, {"id", request.value("id")},
                        {"error", QJsonObject{{"code", -32000}, {"message", "CustodyLocked"}}}}).toJson(QJsonDocument::Compact) + '\n');
                    continue;
                }
                if ((method == "state.snapshot" && snapshotDecline)
                    || (method == "integrations.status" && integrationDecline)) {
                    socket->write(QJsonDocument(QJsonObject{{"jsonrpc", "2.0"}, {"id", request.value("id")},
                        {"error", QJsonObject{{"code", -32000}, {"message", snapshotRefusal}}}}).toJson(QJsonDocument::Compact) + '\n');
                    continue;
                }
                QJsonObject result;
                if (method == "system.handshake") {
                    result = {{"protocol_version", 2}};
                    if (!reopenCapability.isUndefined())
                        result.insert("capabilities", QJsonObject{{"custody_reopen", reopenCapability}});
                }
                else if (method == "state.snapshot") {
                    result = detailsFixture ? drilldownSnapshot(custodyReady, detailsMode) : capacitySnapshot(custodyReady);
                    if (omitCapture) result.remove("captured_at");
                }
                else if (method == "setup.readiness") {
                    ++readinessRequests;
                    result = report(duplicate);
                    if (contradictoryReady) result.insert("ready", true);
                    if (!custodyReady && !duplicate) {
                        auto findings = result.value("findings").toArray();
                        // Match engine.setupSnapshot: retained Locked custody
                        // is stale, not a fresh OS-vault observation.
                        findings[2] = QJsonObject{{"phase", "vault"}, {"reason", "observation_stale"},
                            {"action", "refresh_observation"}};
                        result.insert("findings", findings);
                    }
                }
                else if (method == "custody.reopen") {
                    ++reopenRequests;
                    strictReopen = strictReopen && request.value("params").isObject()
                        && request.value("params").toObject().isEmpty()
                        && reopenCapability.isBool() && reopenCapability.toBool();
                    if (reopenResultMode == "locked-refusal" || reopenResultMode == "missing-key-refusal") {
                        socket->write(QJsonDocument(QJsonObject{{"jsonrpc", "2.0"}, {"id", request.value("id")},
                            {"error", QJsonObject{{"code", -32000},
                                {"message", reopenResultMode == "locked-refusal" ? "Locked" : "Missing"}}}}).toJson(QJsonDocument::Compact) + '\n');
                        continue;
                    }
                    custodyReady = reopenResultMode == "ready" || reopenResultMode == "ready-idempotent";
                    if (uncertainRecovery && custodyReady) snapshotDecline = false;
                    result = {{"reopened", true}, {"custody_available", true}, {"metadata_loaded", true}, {"account_count", 0},
                        {"provider_request_initiated", false}, {"live_handoff_proven", false}};
                    if (reopenResultMode == "missing-loaded") result.remove("metadata_loaded");
                    else if (reopenResultMode == "ready-idempotent") result.insert("reopened", false);
                    else if (reopenResultMode == "false-loaded") result.insert("metadata_loaded", false);
                    else if (reopenResultMode == "false-custody") result.insert("custody_available", false);
                    else if (reopenResultMode == "string-custody") result.insert("custody_available", "true");
                    else if (reopenResultMode == "null-count") result.insert("account_count", QJsonValue());
                    else if (reopenResultMode == "negative-count") result.insert("account_count", -1);
                    else if (reopenResultMode == "fraction-count") result.insert("account_count", 0.5);
                    else if (reopenResultMode == "string-reopened") result.insert("reopened", "true");
                    else if (reopenResultMode == "provider-access") result.insert("provider_request_initiated", true);
                    else if (reopenResultMode == "handoff-claim") result.insert("live_handoff_proven", true);
                    else if (reopenResultMode == "extra-field") result.insert("extra", true);
                }
                else if (method == "integrations.status") {
                    result = {{"adapters", QJsonArray{}}, {"installed", QJsonArray{}}};
                    if (pendingRemovalFixture) {
                        result.insert("adapters", QJsonArray{QJsonObject{{"id", "codex"}, {"capabilities", QJsonArray{}}}});
                        result.insert("installed", QJsonArray{QString("codex")});
                    }
                    if (!omitRuntime) result.insert("runtime_selection", runtimeSelection);
                }
                else if (uncertainRecovery && method == "operation.status") {
                    ++originalOutcomeQueries;
                    originalWireValid = originalWireValid
                        && request.value("params").toObject().value("operation_id").toString() == originalOperation;
                    result = {{"operation_id", originalOperation},
                        {"status", originalOutcomeCompleted ? "completed" : "started"}, {"result", QJsonObject{}}};
                }
                else if (pendingRemovalFixture && method == "integrations.remove") {
                    ++removalRequests;
                    const auto params = request.value("params").toObject();
                    const auto operation = params.value("operation_id").toString();
                    removalWireValid = removalWireValid && params.value("adapter").toString() == "codex"
                        && operation.size() == 64 && !removalOperations.contains(operation)
                        && params.value("expected_revision").toInteger(-1) == 1;
                    removalOperations.insert(operation);
                    // Exact status-less Engine.completeNativeRemovalPending shape.
                    result = {{"removed", false}, {"adapter", "codex"}, {"installed", true},
                        {"pending_safe_detach", true}, {"reason", removalReason}};
                }
                else ++mutations;
                if (method == "setup.readiness" && holdNextReadiness) {
                    holdNextReadiness = false;
                    heldReadinessSocket = socket;
                    heldReadinessReply = QJsonDocument(QJsonObject{{"jsonrpc", "2.0"}, {"id", request.value("id")},
                        {"result", result}}).toJson(QJsonDocument::Compact) + '\n';
                    continue;
                }
                socket->write(QJsonDocument(QJsonObject{{"jsonrpc", "2.0"}, {"id", request.value("id")},
                    {"result", result}}).toJson(QJsonDocument::Compact) + '\n');
            }
        });
    });
    {
        // Offline construction avoids invoking any host service manager.
        OmuxTray window(socketPath, false, true);
        std::fprintf(stderr, "setup_ui_test: controls constructed\n");
        window.show();
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Reconnect") button->click();
        auto *table = window.findChild<QTableWidget *>("setupReadiness");
        auto *notice = window.findChild<QLabel *>("setupNotice");
        if (!table || !notice || !until([&] { return table->rowCount() == 7; })) return 2;
        if (table->item(6, 1)->text() != "missing" || !notice->text().contains("Home Manager")) return 3;
        // The real socket→applySnapshot path displays observations retained for
        // a paused account without presenting its total as request eligibility.
        auto *capacity = window.findChild<QTableWidget *>("capacityObservations");
        if (!capacity || !until([&] { return capacity->rowCount() == 9; })) return 31;
        if (capacity->item(0, 0)->text() != "github (retained observation total)"
            || capacity->item(0, 3)->text() != "42" || capacity->item(0, 4)->text() != "calls"
            || capacity->item(0, 2)->text() != "github:rest:core"
            || capacity->item(0, 5)->text() == "Unknown"
            || capacity->item(0, 6)->text() != "Complete at snapshot"
            || capacity->item(0, 7)->text() != "—"
            || capacity->item(1, 3)->text() != "Unknown"
            || !capacity->item(1, 6)->text().startsWith("Partial at snapshot:")) return 32;
        if (capacity->item(2, 6)->text() != "Current" || capacity->item(2, 7)->text() != "ready"
            || capacity->item(3, 3)->text() != "0" || capacity->item(3, 6)->text() != "Current"
            || capacity->item(3, 7)->text() != "unavailable") return 33;
        for (int row : {4, 7, 8})
            if (capacity->item(row, 3)->text() != "Unknown" || capacity->item(row, 6)->text() != "Unknown") return 34;
        for (int row : {5, 6})
            if (capacity->item(row, 3)->text() != "42" || capacity->item(row, 6)->text() != "Stale") return 35;
        auto *snapshotNotice = window.findChild<QLabel *>("snapshotNotice");
        auto *runtimeNotice = window.findChild<QLabel *>("runtimeSelection");
        if (!snapshotNotice || !runtimeNotice || !until([&] {
                return runtimeNotice->text().contains("Runtime selection: unselected");
            }) || !snapshotNotice->text().contains("revision 1")
            || snapshotNotice->text().contains("Unavailable")) return 38;
        const auto lastSnapshot = snapshotNotice->text();
        // Hold a real readiness reply across the later snapshot failure. It
        // must not repopulate rows after that failure invalidates the query.
        holdNextReadiness = true;
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Check setup") button->click();
        if (!until([&] { return heldReadinessSocket != nullptr; })) return 51;
        const int beforeSnapshotFailureConnections = connections;
        const int beforeSnapshotFailureReadiness = readinessRequests;
        snapshotDecline = true;
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Refresh") button->click();
        if (!until([&] { return snapshotNotice->text().contains("Snapshot refresh failed"); })
            || !snapshotNotice->text().contains(lastSnapshot) || table->rowCount() != 0
            || capacity->rowCount() != 9 || capacity->item(0, 3)->text() != "42"
            || connections != beforeSnapshotFailureConnections
            || readinessRequests != beforeSnapshotFailureReadiness) return 39;
        for (int row = 0; row < capacity->rowCount(); ++row)
            if (capacity->item(row, 6)->text() != "Stale: snapshot refresh failed") return 40;
        bool staleReadinessReappeared = false;
        const auto staleRows = QObject::connect(table->model(), &QAbstractItemModel::rowsInserted,
            &window, [&] { staleReadinessReappeared = true; });
        heldReadinessSocket->write(heldReadinessReply);
        heldReadinessSocket->flush();
        snapshotRefusal = "SnapshotCardinalityExceeded";
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Refresh") button->click();
        // The second reply is a socket-order fence after the held readiness
        // reply, rather than a sleep that assumes the callback was processed.
        if (!until([&] { return snapshotNotice->text().contains(snapshotRefusal); })
            || staleReadinessReappeared || table->rowCount() != 0) return 52;
        QObject::disconnect(staleRows);
        snapshotRefusal = "SnapshotTooLarge";
        snapshotDecline = false;
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Refresh") button->click();
        if (!until([&] {
                return table->rowCount() == 7 && capacity->item(2, 6)->text() == "Current";
            }) || snapshotNotice->text().contains("refresh failed")) return 41;
        // Missing capture metadata stays unknown; the UI must not invent a
        // capture timestamp from its own wall clock when a reply omits it.
        omitCapture = true;
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Refresh") button->click();
        if (!until([&] { return snapshotNotice->text().contains("captured Unavailable"); })) return 42;
        omitCapture = false;
        // Use the daemon's exact existing status contract through the actual
        // socket→applySnapshot→integrations.status projection, never a mock UI.
        for (const auto *state : {"refused", "pending", "committed_historical_facts", "unselected"}) {
            runtimeSelection.insert("state", state);
            runtimeSelection.insert("reason", QString(state) == "refused"
                ? QJsonValue("NativeCustodyPending") : QJsonValue(QJsonValue::Null));
            for (auto *button : window.findChildren<QPushButton *>())
                if (button->text() == "Refresh") button->click();
            if (!until([&] { return runtimeNotice->text().contains(QString("Runtime selection: ") + state); })
                || !runtimeNotice->text().contains("measured installed bytes only")
                || !runtimeNotice->text().contains("support remains unproved")) return 43;
            if (QString(state) == "refused" && !runtimeNotice->text().contains("NativeCustodyPending")) return 44;
        }
        runtimeSelection.insert("native_support", true);
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Refresh") button->click();
        if (!until([&] { return runtimeNotice->text().contains("report is unsupported"); })) return 45;
        runtimeSelection.insert("native_support", false);
        omitRuntime = true;
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Refresh") button->click();
        if (!until([&] { return runtimeNotice->text().contains("unavailable in this service"); })) return 46;
        omitRuntime = false;
        integrationDecline = true;
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Refresh") button->click();
        if (!until([&] { return runtimeNotice->text().contains("Integration status refresh failed"); })
            || !runtimeNotice->text().contains("Runtime selection is unverified")
            || !runtimeNotice->text().contains("SnapshotTooLarge")) return 47;
        integrationDecline = false;
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Refresh") button->click();
        if (!until([&] { return runtimeNotice->text().contains("Runtime selection: unselected"); })) return 48;
        decline = true;
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Check setup") button->click();
        if (!until([&] { return notice->text().contains("Shared setup readiness unavailable"); })
            || table->rowCount() != 0) return 49;
        decline = false;
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Check setup") button->click();
        if (!until([&] { return table->rowCount() == 7; })) return 50;
        // Ordinary connection/readiness must not trigger an automatic reopen.
        if (reopenRequests != 0) return 11;
        // A top-level success cannot override the actual missing native row.
        contradictoryReady = true;
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Check setup") button->click();
        if (!until([&] { return notice->text().contains("unsupported readiness"); })
            || table->rowCount() != 0 || mutations != 0 || reopenRequests != 0) return 29;
        contradictoryReady = false;
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Check setup") button->click();
        if (!until([&] { return table->rowCount() == 7; })
            || notice->text().contains("Setup requirements are ready")) return 30;
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Resume after vault unlock") button->click();
        if (!until([&] { return notice->text().contains("requires an update"); })
            || reopenRequests != 0) return 12;
        duplicate = true;
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Check setup") button->click();
        if (!until([&] { return notice->text().contains("unsupported readiness"); }) || table->rowCount() != 0) return 4;
        decline = true;
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Check setup") button->click();
        if (!until([&] { return notice->text().contains("CustodyLocked"); })) return 6;
        window.close();
    }
    duplicate = false;
    decline = false;
    // Fresh private mock connections exercise false/non-boolean advertisements
    // and the supported explicit action. Every other effect-bearing RPC fails
    // the final mutation check; no normal daemon or vault is used.
    for (const auto capability : {QJsonValue(false), QJsonValue(QString("true")), QJsonValue(true)}) {
        reopenCapability = capability;
        custodyReady = false;
        OmuxTray window(socketPath, false, true);
        window.show();
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Reconnect") button->click();
        auto *table = window.findChild<QTableWidget *>("setupReadiness");
        auto *notice = window.findChild<QLabel *>("setupNotice");
        if (!table || !notice || !until([&] {
                return table->rowCount() == 7 && table->item(2, 1)->text() == "observation_stale";
            }) || reopenRequests != 0) return 13;
        auto *capacity = window.findChild<QTableWidget *>("capacityObservations");
        if (!capacity || !until([&] { return capacity->rowCount() == 9; })) return 36;
        for (int row = 0; row < capacity->rowCount(); ++row)
            if (capacity->item(row, 6)->text() != "Stale: service or custody unavailable") return 37;
        const int beforeReadiness = readinessRequests;
        const int beforeConnections = connections;
        bool clicked = false;
        for (auto *button : window.findChildren<QPushButton *>()) {
            if (button->text() == "Resume after vault unlock") {
                button->click();
                clicked = true;
            }
        }
        if (!clicked) return 14;
        if (!capability.isBool() || !capability.toBool()) {
            if (!until([&] { return notice->text().contains("requires an update"); })
                || reopenRequests != 0) return 15;
        } else {
            if (!until([&] { return reopenRequests == 1 && readinessRequests > beforeReadiness
                    && table->rowCount() == 7 && table->item(2, 1)->text() == "ready"; })
                || !strictReopen || mutations != 0 || connections != beforeConnections) return 16;
        }
        window.close();
    }
    int expectedReopenRequests = 1;
    // Actual private Qt request/reply handling must preserve a Locked refusal
    // and reject unsupported success shapes without claiming ready or retrying.
    for (const auto *mode : {"locked-refusal", "missing-key-refusal", "missing-loaded", "false-loaded", "false-custody",
            "string-custody", "null-count", "negative-count", "fraction-count", "string-reopened",
            "provider-access", "handoff-claim", "extra-field"}) {
        reopenResultMode = mode;
        reopenCapability = true;
        custodyReady = false;
        OmuxTray window(socketPath, false, true);
        window.show();
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Reconnect") button->click();
        auto *table = window.findChild<QTableWidget *>("setupReadiness");
        auto *notice = window.findChild<QLabel *>("setupNotice");
        if (!table || !notice || !until([&] {
                return table->rowCount() == 7 && table->item(2, 1)->text() == "observation_stale";
            }) || reopenRequests != expectedReopenRequests) return 17;
        const int beforeReadiness = readinessRequests;
        const int beforeConnections = connections;
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Resume after vault unlock") button->click();
        ++expectedReopenRequests;
        const bool refused = reopenResultMode == "locked-refusal";
        const bool missing = reopenResultMode == "missing-key-refusal";
        if (!until([&] {
                return reopenRequests == expectedReopenRequests
                    && notice->text().contains(refused ? "normal OS Secret Service vault"
                        : missing ? "vault key is missing or invalid" : "unverified custody result");
            }) || !notice->text().contains("preserved") || !notice->text().contains("unavailable")
            || notice->text().contains("Custody is ready") || custodyReady || !strictReopen
            || mutations != 0 || connections != beforeConnections
            || readinessRequests != beforeReadiness || table->item(2, 1)->text() != "observation_stale") return 18;
        if (refused && !notice->text().contains("does not establish the current OS vault lock state")) return 19;
        if (missing && (!notice->text().contains("original key")
                || notice->text().contains("unlock it through your desktop"))) return 24;
        auto *signIn = window.findChild<QPushButton *>("codexAccountSignIn");
        if (!signIn || signIn->isEnabled()) return 21;
        // A later event turn must not erase refusal guidance or replay reopening.
        QApplication::processEvents();
        if (reopenRequests != expectedReopenRequests || readinessRequests != beforeReadiness) return 20;
        const auto retainedFeedback = notice->property("custodyFeedback").toString();
        if (retainedFeedback.isEmpty()) return 25;
        // Exercise the same real snapshot/readiness path as the periodic refresh.
        // It must not erase the retained refusal or reopen automatically.
        for (auto *button : window.findChildren<QPushButton *>())
            if (button->text() == "Refresh") button->click();
        if (!until([&] {
                return readinessRequests > beforeReadiness && notice->text().contains(retainedFeedback);
            }) || reopenRequests != expectedReopenRequests || signIn->isEnabled()) return 26;
        if (refused || missing) {
            // Failed and unsupported readiness replies cannot erase the earlier
            // custody refusal. Each path uses actual private Qt RPC handling.
            decline = true;
            for (auto *button : window.findChildren<QPushButton *>())
                if (button->text() == "Check setup") button->click();
            if (!until([&] {
                    return notice->text().contains("Shared setup readiness unavailable")
                        && notice->text().contains(retainedFeedback);
                }) || reopenRequests != expectedReopenRequests || signIn->isEnabled()) return 27;
            decline = false;
            duplicate = true;
            for (auto *button : window.findChildren<QPushButton *>())
                if (button->text() == "Check setup") button->click();
            if (!until([&] {
                    return notice->text().contains("unsupported readiness report")
                        && notice->text().contains(retainedFeedback) && table->rowCount() == 0;
                }) || reopenRequests != expectedReopenRequests || signIn->isEnabled()) return 28;
            duplicate = false;
            for (auto *button : window.findChildren<QPushButton *>())
                if (button->text() == "Refresh") button->click();
            if (!until([&] {
                    return table->rowCount() == 7 && table->item(2, 1)->text() == "observation_stale"
                        && notice->text().contains(retainedFeedback);
                }) || reopenRequests != expectedReopenRequests || signIn->isEnabled()) return 29;
        }
        if (QString(mode) == "extra-field") {
            // Recovery uses this same failed UI/peer. The daemon can already be
            // ready, so reopened:false with genuine loaded custody is valid.
            reopenResultMode = "ready-idempotent";
            const int beforeRecoveryReadiness = readinessRequests;
            for (auto *button : window.findChildren<QPushButton *>())
                if (button->text() == "Resume after vault unlock") button->click();
            ++expectedReopenRequests;
            if (!until([&] {
                    return reopenRequests == expectedReopenRequests && readinessRequests > beforeRecoveryReadiness
                        && table->rowCount() == 7 && table->item(2, 1)->text() == "ready";
                }) || !strictReopen || mutations != 0 || connections != beforeConnections
                    || !notice->property("custodyFeedback").toString().isEmpty()) return 23;
        }
        window.close();
    }
    // A locked actor cannot answer the original account operation outcome.
    // Explicit custody recovery must remain accessible without replaying that
    // operation or allowing other account mutations before it is reconciled.
    uncertainRecovery = true;
    custodyReady = true;
    reopenCapability = true;
    reopenResultMode = "locked-refusal";
    {
        OmuxTray window(socketPath, false, true);
        window.show();
        QPushButton *pausePreparation = nullptr;
        QPushButton *resumeCustody = nullptr;
        QPushButton *refresh = nullptr;
        for (auto *button : window.findChildren<QPushButton *>()) {
            if (button->text() == "Pause preparation") pausePreparation = button;
            if (button->text() == "Resume after vault unlock") resumeCustody = button;
            if (button->text() == "Refresh") refresh = button;
            if (button->text() == "Reconnect") button->click();
        }
        const auto hasText = [&](const QString &needle) {
            for (auto *label : window.findChildren<QLabel *>())
                if (label->text().contains(needle)) return true;
            return false;
        };
        if (!pausePreparation || !resumeCustody || !refresh
            || !until([&] { return pausePreparation->isEnabled(); })) return 53;
        auto *snapshotNotice = window.findChild<QLabel *>("snapshotNotice");
        auto *readiness = window.findChild<QTableWidget *>("setupReadiness");
        if (!snapshotNotice || !readiness) return 63;
        const int recoveryConnections = connections;
        pausePreparation->click();
        if (!until([&] { return originalOutcomeQueries > 0 && !pausePreparation->isEnabled(); })
            || originalMutationRequests != 1 || !originalWireValid || !hasText(originalOperation)) return 54;
        refresh->click();
        if (!until([&] { return hasText("Snapshot refresh failed (CustodyLocked)"); })) return 55;
        resumeCustody->click();
        ++expectedReopenRequests;
        if (!until([&] { return hasText("Custody could not be reopened"); })
            || reopenRequests != expectedReopenRequests || pausePreparation->isEnabled()
            || originalMutationRequests != 1 || !hasText(originalOperation)) return 56;
        reopenResultMode = "ready";
        const int queriesBeforeReopen = originalOutcomeQueries;
        resumeCustody->click();
        ++expectedReopenRequests;
        if (!until([&] {
                return originalOutcomeQueries > queriesBeforeReopen
                    && snapshotNotice->text().startsWith("Last daemon snapshot:")
                    && readiness->rowCount() == 7 && readiness->item(2, 1)->text() == "ready";
            }) || reopenRequests != expectedReopenRequests || pausePreparation->isEnabled()
            || originalMutationRequests != 1 || !hasText(originalOperation)
            || connections != recoveryConnections || !strictReopen || !originalWireValid) return 57;
        // Even restored custody does not resolve a started original operation.
        pausePreparation->click();
        QApplication::processEvents();
        if (originalMutationRequests != 1) return 58;
        originalOutcomeCompleted = true;
        refresh->click();
        if (!until([&] { return pausePreparation->isEnabled(); })
            || originalMutationRequests != 1 || !originalWireValid || reopenRequests != expectedReopenRequests) return 59;
        // Read a retained installed catalog, then request removal once for each
        // actual pending-safe-detach reason. Neither result means removed.
        pendingRemovalFixture = true;
        QTableWidget *catalog = nullptr;
        for (auto *candidate : window.findChildren<QTableWidget *>())
            if (candidate->columnCount() == 5 && candidate->horizontalHeaderItem(1)->text() == "Installed") catalog = candidate;
        refresh->click();
        if (!catalog || !until([&] { return catalog->rowCount() == 1; })) return 60;
        catalog->selectRow(0);
        for (const auto *reason : {"NativeRequestsPending", "NativeCustodyPending"}) {
            removalReason = reason;
            for (auto *button : window.findChildren<QPushButton *>())
                if (button->text() == "Remove integration") button->click();
            if (!until([&] { return hasText("Reason: " + removalReason); })
                || !hasText("Integration remains installed; removal is pending safe detachment")
                || hasText("Action accepted; account state will refresh.") || !removalWireValid) return 61;
        }
        if (!until([&] { return catalog->rowCount() == 1 && catalog->item(0, 1)->text() == "Yes"; })
            || removalRequests != 2 || removalOperations.size() != 2 || originalMutationRequests != 1
            || reopenRequests != expectedReopenRequests || connections != recoveryConnections) return 62;
        window.close();
    }
    // Actual socket→applySnapshot→selected-row details: metadata joins never
    // infer usable authority from a ready grant or add shared observations.
    uncertainRecovery = false;
    pendingRemovalFixture = false;
    snapshotDecline = false;
    custodyReady = true;
    detailsFixture = true;
    {
        OmuxTray window(socketPath, false, true);
        window.show();
        auto *accounts = window.findChild<QTableWidget *>("accounts");
        auto *routes = window.findChild<QTableWidget *>("activeRoutes");
        auto *capacity = window.findChild<QTableWidget *>("capacityObservations");
        auto *refresh = [&]() -> QPushButton * {
            for (auto *button : window.findChildren<QPushButton *>()) if (button->text() == "Refresh") return button;
            return nullptr;
        }();
        for (auto *button : window.findChildren<QPushButton *>()) if (button->text() == "Reconnect") button->click();
        if (!accounts || !routes || !capacity || !refresh || !until([&] {
                return accounts->rowCount() == 2 && routes->rowCount() == 2 && capacity->rowCount() == 5;
            })) return 64;
        const auto inspect = [&](QTableWidget *view, int row, const char *buttonName, const char *dialogName) {
            view->selectRow(row);
            auto *button = window.findChild<QPushButton *>(buttonName);
            if (button) button->click();
            return window.findChild<QDialog *>(dialogName);
        };
        const auto fact = [](QDialog *dialog, const QString &name) {
            auto *view = dialog ? dialog->findChild<QTableWidget *>("detailFacts") : nullptr;
            if (view) for (int row = 0; row < view->rowCount(); ++row)
                if (view->item(row, 0)->text() == name) return view->item(row, 1)->text();
            return QString();
        };
        const auto hasText = [](QDialog *dialog, const QString &value) {
            if (dialog) for (const auto *label : dialog->findChildren<QLabel *>()) if (label->text().contains(value)) return true;
            return false;
        };
        auto *account = inspect(accounts, 0, "accountDetails", "accountDrilldown");
        auto *sources = account ? account->findChild<QTableWidget *>("detailSources") : nullptr;
        auto *grants = account ? account->findChild<QTableWidget *>("detailGrants") : nullptr;
        auto *observations = account ? account->findChild<QTableWidget *>("detailObservations") : nullptr;
        auto *accountRoutes = account ? account->findChild<QTableWidget *>("detailRoutes") : nullptr;
        if (!account || !sources || !grants || !observations || !accountRoutes
            || fact(account, "Identity verified") != "No" || fact(account, "Lifecycle") != "paused"
            || !fact(account, "Usable request grant").startsWith("Unknown:")
            || !fact(account, "Actual renewal writer").startsWith("Unknown:")
            || sources->rowCount() != 2 || sources->item(1, 3)->text() != "detached"
            || grants->rowCount() != 2 || grants->item(0, 2)->text() != "ready"
            || grants->item(0, 4)->text() != "adopted" || grants->item(1, 2)->text() != "invalid"
            || observations->rowCount() != 2 || observations->item(0, 3)->text() != "synthetic-shared-bucket"
            || observations->item(1, 4)->text() != "Unknown" || accountRoutes->rowCount() != 1) return 65;
        delete account;
        auto *route = inspect(routes, 0, "routeDetails", "routeDrilldown");
        auto *leases = route ? route->findChild<QTableWidget *>("detailLeases") : nullptr;
        grants = route ? route->findChild<QTableWidget *>("detailGrants") : nullptr;
        if (!route || !leases || !grants || fact(route, "Grant generation") != "3"
            || !fact(route, "Live application / usable authority").startsWith("Unknown:")
            || grants->rowCount() != 1 || grants->item(0, 1)->text() != "detail-account-a"
            || grants->item(0, 9)->text() != "4" || leases->rowCount() != 1
            || leases->item(0, 1)->text() != "detail-account-a" || leases->item(0, 3)->text() != "3"
            || leases->item(0, 4)->text() != "2") return 66;
        delete route;
        auto *resource = inspect(capacity, 0, "resourceDetails", "resourceDrilldown");
        if (!resource || fact(resource, "Remaining observation") != "17" || fact(resource, "Counted buckets") != "1"
            || fact(resource, "Issuer group") != "synthetic-issuer-group"
            || !fact(resource, "Observation membership").startsWith("Unavailable:")
            || !fact(resource, "Row kind").contains("not request eligibility")) return 67;
        delete resource;
        resource = inspect(capacity, 4, "resourceDetails", "resourceDrilldown");
        if (!resource || fact(resource, "Unit") != "bytes" || fact(resource, "Scope") != "github:rest:bytes"
            || fact(resource, "Remaining observation") != "Unknown" || fact(resource, "Provenance") != "fixture"
            || fact(resource, "Observation status") != "unknown") return 68;
        delete resource;
        // A failed refresh keeps retained rows inspectable without current counts
        // or fresh account observations; recover through a later real reply.
        snapshotDecline = true;
        refresh->click();
        auto *snapshotNotice = window.findChild<QLabel *>("snapshotNotice");
        if (!until([&] { return snapshotNotice->text().startsWith("Snapshot refresh failed"); })) return 69;
        account = inspect(accounts, 0, "accountDetails", "accountDrilldown");
        observations = account ? account->findChild<QTableWidget *>("detailObservations") : nullptr;
        if (!account || !observations || !hasText(account, "current account and related-record counts are Unknown")
            || !observations->item(0, 6)->text().startsWith("Stale:")) return 70;
        delete account;
        snapshotDecline = false;
        custodyReady = false;
        refresh->click();
        const auto connection = [&]() -> QLabel * {
            for (auto *label : window.findChildren<QLabel *>()) if (label->text() == "Connected; credential custody unavailable") return label;
            return nullptr;
        };
        if (!until([&] { return connection() != nullptr && snapshotNotice->text().startsWith("Last daemon snapshot:"); })) return 71;
        account = inspect(accounts, 0, "accountDetails", "accountDrilldown");
        if (!account || !hasText(account, "current account and related-record counts are Unknown")) return 72;
        delete account;
        custodyReady = true;
        detailsMode = 1;
        refresh->click();
        if (!until([&] { return accounts->rowCount() == 1; })) return 73;
        account = inspect(accounts, 0, "accountDetails", "accountDrilldown");
        if (!account || fact(account, "Identity verified") != "Unknown"
            || !hasText(account, "Grant metadata; ownership is not a verified renewal writer (current count Unknown)")) return 74;
        delete account;
        detailsMode = 2;
        refresh->click();
        if (!until([&] { return accounts->rowCount() == 2; })) return 75;
        account = inspect(accounts, 0, "accountDetails", "accountDrilldown");
        if (!account || !hasText(account, "Grant metadata; ownership is not a verified renewal writer (0 retained rows)")) return 76;
        delete account;
        window.close();
    }
    // UI close/destruction sends no unexpected shutdown, mutation, or removal request.
    QApplication::processEvents();
    return server.isListening() && mutations == 0 && reopenRequests == expectedReopenRequests && strictReopen
        && originalMutationRequests == 1 && originalWireValid && removalRequests == 2 && removalWireValid ? 0 : 5;
}
