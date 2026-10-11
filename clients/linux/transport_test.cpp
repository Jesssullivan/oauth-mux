#include "omux_client.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QEventLoop>
#include <QFile>
#include <QJsonDocument>
#include <QJsonArray>
#include <QLocalServer>
#include <QTemporaryDir>
#include <cstdio>
#include <cstdlib>
#include <utility>

namespace {
bool waitUntil(const std::function<bool()> &predicate, int timeout = 2000) {
    if (predicate()) return true;
    QEventLoop loop;
    QTimer tick;
    tick.setInterval(5);
    QTimer timeoutTimer;
    timeoutTimer.setSingleShot(true);
    QObject::connect(&tick, &QTimer::timeout, &loop, [&] { if (predicate()) loop.quit(); });
    QObject::connect(&timeoutTimer, &QTimer::timeout, &loop, &QEventLoop::quit);
    tick.start(); timeoutTimer.start(timeout); loop.exec();
    return predicate();
}

class Fixture {
public:
    QTemporaryDir directory;
    QLocalServer server;
    std::function<void(QLocalSocket *, const QJsonObject &)> receive;
    int connections = 0;
    Fixture() {
        QObject::connect(&server, &QLocalServer::newConnection, &server, [this] {
            while (server.hasPendingConnections()) {
                ++connections;
                auto *socket = server.nextPendingConnection();
                socket->setParent(&server);
                auto *buffer = new QByteArray;
                QObject::connect(socket, &QObject::destroyed, [buffer] { delete buffer; });
                QObject::connect(socket, &QLocalSocket::readyRead, socket, [this, socket, buffer] {
                    *buffer += socket->readAll();
                    while (buffer->contains('\n')) {
                        const auto end = buffer->indexOf('\n');
                        const auto frame = buffer->left(end);
                        buffer->remove(0, end + 1);
                        if (receive) receive(socket, QJsonDocument::fromJson(frame).object());
                    }
                });
            }
        });
        server.setSocketOptions(QLocalServer::UserAccessOption);
        if (!server.listen(path())) std::abort();
        if (!QFile::setPermissions(path(), QFile::ReadOwner | QFile::WriteOwner)) std::abort();
    }
    QString path() const { return directory.path() + "/control.sock"; }
    static void reply(QLocalSocket *socket, const QJsonObject &request, QJsonObject result) {
        socket->write(QJsonDocument(QJsonObject{{"jsonrpc", "2.0"}, {"id", request.value("id")},
            {"result", result}}).toJson(QJsonDocument::Compact) + '\n');
    }
    static void decline(QLocalSocket *socket, const QJsonObject &request, const QString &reason) {
        socket->write(QJsonDocument(QJsonObject{{"jsonrpc", "2.0"}, {"id", request.value("id")},
            {"error", QJsonObject{{"code", -32000}, {"message", reason}}}}).toJson(QJsonDocument::Compact) + '\n');
    }
};

bool versionNegotiation() {
    Fixture fixture;
    bool sawHandshake = false;
    bool completed = false;
    bool passed = false;
    fixture.receive = [&](QLocalSocket *socket, const QJsonObject &request) {
        if (request.value("method").toString() == "system.handshake") {
            sawHandshake = request.value("params").toObject().value("protocol_version").toInt() == 2;
            Fixture::reply(socket, request, {{"protocol_version", 2}});
        } else {
            Fixture::reply(socket, request, {{"revision", 7}, {"accounts", QJsonArray{}}});
        }
    };
    OmuxClient client(fixture.path());
    client.onConnection = [&](bool ready, const QString &) {
        if (ready) client.request("state.snapshot", {}, [&](const QJsonObject &result, const QString &error) {
            passed = sawHandshake && error.isEmpty() && result.value("revision").toInt() == 7;
            completed = true;
        });
    };
    client.connectToDaemon();
    return waitUntil([&] { return completed; }) && passed;
}

bool incompatibleVersion() {
    Fixture fixture;
    bool rejected = false;
    fixture.receive = [](QLocalSocket *socket, const QJsonObject &request) {
        Fixture::reply(socket, request, {{"protocol_version", 99}});
    };
    OmuxClient client(fixture.path());
    client.onConnection = [&](bool ready, const QString &message) {
        rejected = !ready && message.contains("unsupported control protocol");
    };
    client.connectToDaemon();
    return waitUntil([&] { return rejected; }) && !client.ready();
}

bool malformedAndOversizedFrames() {
    for (const bool oversized : {false, true}) {
        Fixture fixture;
        bool failed = false;
        fixture.receive = [&](QLocalSocket *socket, const QJsonObject &) {
            socket->write(oversized ? QByteArray(1024 * 1024 + 1, 'x') : QByteArray("invalid\n"));
        };
        OmuxClient client(fixture.path());
        client.onConnection = [&](bool ready, const QString &message) {
            if (!ready && (message.contains("invalid") || message.contains("limit"))) failed = true;
        };
        client.connectToDaemon();
        if (!waitUntil([&] { return failed; }) || client.ready()) return false;
    }
    return true;
}

bool noMutationReplay() {
    Fixture fixture;
    bool outcomeUnknown = false;
    bool mutationSent = false;
    int mutations = 0;
    QString operationID;
    bool reconciled = false;
    fixture.receive = [&](QLocalSocket *socket, const QJsonObject &request) {
        if (request.value("method").toString() == "system.handshake") {
            Fixture::reply(socket, request, {{"protocol_version", 2}});
        } else if (request.value("method").toString() == "operation.status") {
            reconciled = request.value("params").toObject().value("operation_id").toString() == operationID;
            Fixture::reply(socket, request, {{"status", "completed"}, {"operation_id", operationID}, {"result", QJsonObject{{"accepted", true}}}});
        } else {
            const auto params = request.value("params").toObject();
            operationID = params.value("operation_id").toString();
            if (operationID.isEmpty() || !params.contains("expected_revision")) return;
            ++mutations;
            socket->disconnectFromServer(); // Could have committed before the transport vanished.
        }
    };
    OmuxClient client(fixture.path());
    client.onConnection = [&](bool ready, const QString &) {
        if (ready && !mutationSent) {
            mutationSent = true;
            client.request("account.pause", {{"account_id", "opaque-account"}},
                [&](const QJsonObject &, const QString &error) { outcomeUnknown = error.contains("unknown"); });
        }
    };
    client.connectToDaemon();
    if (!waitUntil([&] { return outcomeUnknown; })) return false;
    // Verify reconnection without replaying the committed-or-unknown mutation.
    return waitUntil([&] { return fixture.connections >= 2 && client.ready() && reconciled; }, 6500) && mutations == 1;
}

enum class DeclineOutcome { indeterminate, started, completed, absent, queryFailure, malformedCompleted };

bool declaredFailureReconciliation(DeclineOutcome outcome) {
    Fixture fixture;
    OmuxClient client(fixture.path());
    QString originalID;
    bool originalError = false;
    bool reentrantBlocked = false;
    bool invalidIDRefused = false;
    bool recovered = false;
    bool nextActionCompleted = false;
    bool wireValid = true;
    int mutations = 0;
    int queries = 0;
    int finishedQueries = 0;
    const bool terminal = outcome == DeclineOutcome::completed || outcome == DeclineOutcome::absent;
    fixture.receive = [&](QLocalSocket *socket, const QJsonObject &request) {
        const auto method = request.value("method").toString();
        const auto params = request.value("params").toObject();
        if (method == "system.handshake") {
            Fixture::reply(socket, request, {{"protocol_version", 2}});
        } else if (method == "state.snapshot") {
            Fixture::reply(socket, request, {{"revision", 7}});
        } else if (method == "operation.status") {
            ++queries;
            wireValid = wireValid && params.value("operation_id").toString() == originalID;
            if (outcome == DeclineOutcome::absent || outcome == DeclineOutcome::queryFailure) {
                Fixture::decline(socket, request, outcome == DeclineOutcome::absent ? "UnknownOperation" : "CustodyUnavailable");
            } else {
                const auto status = outcome == DeclineOutcome::indeterminate ? "indeterminate"
                    : outcome == DeclineOutcome::started ? "started" : "completed";
                QJsonObject result {{"operation_id", originalID}, {"status", status}};
                if (outcome == DeclineOutcome::completed) result.insert("result", QJsonObject{{"accepted", true}});
                Fixture::reply(socket, request, result);
            }
            // Ordered notification proves the preceding status response was decoded.
            socket->write(QJsonDocument(QJsonObject{{"jsonrpc", "2.0"}, {"method", "events.changed"},
                {"params", QJsonObject{{"reconciliation_probe", queries}}}}).toJson(QJsonDocument::Compact) + '\n');
        } else {
            ++mutations;
            if (mutations == 1) {
                originalID = params.value("operation_id").toString();
                wireValid = wireValid && !originalID.isEmpty() && params.value("expected_revision").toInteger() == 7;
                Fixture::decline(socket, request, outcome == DeclineOutcome::absent ? "StaleRevision" : "NativeTimeout");
            } else {
                wireValid = wireValid && params.value("operation_id").toString() != originalID;
                Fixture::reply(socket, request, {{"accepted", true}, {"revision", 8}});
            }
        }
    };
    client.onEvent = [&](const QJsonObject &event) {
        if (event.contains("reconciliation_probe")) {
            finishedQueries = event.value("reconciliation_probe").toInt();
            return;
        }
        recovered = event.value("operation_id").toString() == originalID
            && event.value("operation_error").toString() == (outcome == DeclineOutcome::absent ? "StaleRevision" : "NativeTimeout");
    };
    client.onConnection = [&](bool ready, const QString &) {
        if (!ready) return;
        client.request("state.snapshot", {}, [&](const QJsonObject &, const QString &error) {
            if (!error.isEmpty()) { wireValid = false; return; }
            client.request("integrations.install", {{"adapter", "codex"}, {"operation_id", "unsafe/id"}},
                [&](const QJsonObject &, const QString &reason) { invalidIDRefused = reason == "Invalid operation identifier."; });
            client.request("integrations.install", {{"adapter", "codex"}}, [&](const QJsonObject &, const QString &reason) {
                originalError = reason == (outcome == DeclineOutcome::absent ? "StaleRevision" : "NativeTimeout");
                // The hold must precede the original callback, including reentrant clicks.
                client.request("account.pause", {{"account_id", "opaque-account"}}, [&](const QJsonObject &, const QString &blocked) {
                    reentrantBlocked = blocked.contains("unknown outcome");
                });
            });
        });
    };
    client.connectToDaemon();
    if (!waitUntil([&] { return invalidIDRefused && originalError && reentrantBlocked && finishedQueries == 1; })) return false;
    if (terminal && !waitUntil([&] { return recovered; })) return false;
    bool secondBlocked = false;
    client.request("account.resume", {{"account_id", "opaque-account"}}, [&](const QJsonObject &, const QString &error) {
        nextActionCompleted = error.isEmpty();
        secondBlocked = error.contains("unknown outcome");
    });
    if (terminal) return waitUntil([&] { return nextActionCompleted; }) && wireValid && mutations == 2 && queries == 1;
    // Metadata reads remain usable and query the original identity again; no mutation is replayed.
    client.request("state.snapshot", {}, [](const QJsonObject &, const QString &) {});
    return waitUntil([&] { return finishedQueries == 2; }) && secondBlocked && !recovered && wireValid && mutations == 1;
}
bool identifiedSetupVerification(bool indeterminate = false, bool recover = false, bool timedOut = false, const QString &vaultReason = {}) {
    Fixture fixture;
    OmuxClient client(fixture.path());
    int passive = 0, checks = 0, statusQueries = 0;
    bool complete = false, duplicateBlocked = false, wireValid = true;
    const QString operation = "setup-verification-owned";
    fixture.receive = [&](QLocalSocket *socket, const QJsonObject &request) {
        const auto method = request.value("method").toString();
        const auto params = request.value("params").toObject();
        if (method == "system.handshake") Fixture::reply(socket, request, {{"protocol_version", 2}});
        else if (method == "setup.refresh" && params.isEmpty()) {
            ++passive;
            Fixture::reply(socket, request, {{"status", "installation_selection_required"}});
        } else if (method == "setup.refresh") {
            ++checks;
            wireValid = wireValid && params.size() == 2 && params.value("operation_id").toString() == operation
                && params.value("expected_revision").isDouble();
            Fixture::reply(socket, request, {{"schema_version", 1}, {"operation_id", operation}, {"generation", 1}, {"status", "pending"}});
        } else if (method == "operation.status") {
            ++statusQueries;
            wireValid = wireValid && params.value("operation_id").toString() == operation;
            if (indeterminate && (!recover || statusQueries == 1)) Fixture::reply(socket, request, {{"operation_id", operation}, {"status", "indeterminate"}, {"result", QJsonValue()}});
            else if (recover && statusQueries == 2) Fixture::decline(socket, request, "UnknownOperation");
            else if (statusQueries == 1) Fixture::reply(socket, request, {{"operation_id", operation}, {"status", "started"}, {"result", QJsonValue()}});
            else {
                QJsonArray phases;
                for (int index = 0; index < 7; ++index) phases.append(QJsonObject{{"outcome", "unknown"}, {"reason", "observation_unknown"}});
                if (!vaultReason.isEmpty()) phases[2] = QJsonObject{{"outcome", "action_required"}, {"reason", vaultReason}};
                if (recover && statusQueries == 3) phases = QJsonArray{QJsonValue(), QJsonValue(), QJsonValue(), QJsonValue(), QJsonValue(), QJsonValue(), QJsonValue()};
                if (recover && statusQueries == 4) phases[0] = QJsonObject{{"reason", "missing"}, {"outcome", "verified_ready"}};
                QJsonObject terminal {
                    {"schema_version", 1}, {"operation_id", operation}, {"generation", 1}, {"observed_at", 1},
                    {"outcome", "verification_completed"}, {"refusal", QJsonValue()}, {"phases", phases},
                    {"elapsed_ns", 1}, {"timing_scope", "admission_to_terminal_before_commit_process_local"}};
                if (recover && statusQueries == 5) terminal["generation"] = 1.5;
                if (recover && statusQueries == 6) terminal["refusal"] = "busy";
                if (timedOut) {
                    terminal["outcome"] = "safe_refusal";
                    terminal["refusal"] = "collection_timed_out";
                    terminal["elapsed_ns"] = QJsonValue();
                    // A timeout cannot establish measured completion or any
                    // verified phase. Each malformed reply must keep its fence.
                    if (statusQueries == 2) terminal["elapsed_ns"] = 1;
                    if (statusQueries == 4) {
                        terminal["schema_version"] = 2;
                        terminal["elapsed_ns"] = 1;
                    }
                    if (statusQueries == 3) {
                        phases[0] = QJsonObject{{"reason", "ready"}, {"outcome", "verified_ready"}};
                        terminal["phases"] = phases;
                    }
                }
                Fixture::reply(socket, request, {{"operation_id", operation}, {"status", "completed"}, {"result", terminal}});
            }
            if ((recover && statusQueries < 7) || (timedOut && statusQueries < 4)) QTimer::singleShot(20, &client, [&] {
                wireValid = wireValid && client.hasUncertainOperations();
                client.request("state.snapshot", {}, [](const QJsonObject &, const QString &) {});
            });
        } else if (method == "state.snapshot") Fixture::reply(socket, request, {{"revision", 0}});
        else wireValid = false;
    };
    client.onEvent = [&](const QJsonObject &event) {
        complete = event.value("operation_kind").toString() == "setup_verification"
            && event.value("operation_status").toString() == (indeterminate && !recover ? "indeterminate" : "completed");
        if (!vaultReason.isEmpty() && complete) {
            const auto phase = event.value("operation_result").toObject().value("phases").toArray()[2].toObject();
            wireValid = wireValid && phase.value("reason").toString() == vaultReason
                && phase.value("outcome").toString() == "action_required";
        }
        if (timedOut && complete) {
            const auto terminal = event.value("operation_result").toObject();
            wireValid = wireValid && terminal.value("outcome").toString() == "safe_refusal"
                && terminal.value("refusal").toString() == "collection_timed_out"
                && terminal.value("schema_version").toInt() == 2
                && terminal.value("elapsed_ns").toInteger(-1) == 1 && terminal.value("phases").toArray().size() == 7;
            for (const auto &phase : terminal.value("phases").toArray()) {
                wireValid = wireValid && phase.toObject().value("outcome").toString() == "unknown"
                    && phase.toObject().value("reason").toString() == "observation_unknown";
            }
        }
    };
    client.onConnection = [&](bool ready, const QString &) {
        if (!ready) return;
        client.request("setup.refresh", {}, [&](const QJsonObject &, const QString &error) {
            if (!error.isEmpty()) { wireValid = false; return; }
            client.request("setup.refresh", {{"operation_id", operation}}, [&](const QJsonObject &, const QString &error) {
                wireValid = wireValid && error.isEmpty();
                client.request("setup.refresh", {{"operation_id", "duplicate-intent"}}, [&](const QJsonObject &, const QString &held) {
                    duplicateBlocked = !held.isEmpty();
                });
            });
        });
    };
    client.connectToDaemon();
    return waitUntil([&] { return complete; }, 3500) && wireValid && duplicateBlocked
        && passive == 1 && checks == 1 && statusQueries >= (timedOut ? 4 : recover ? 7 : indeterminate ? 1 : 2)
        && client.hasUncertainOperations() == (indeterminate && !recover);
}
} // namespace

int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    const std::pair<const char *, std::function<bool()>> tests[] {
        {"versioned same-user socket", versionNegotiation},
        {"identified setup polls one operation without repeating verification", [] { return identifiedSetupVerification(); }},
        {"setup key restoration reason retains authentic terminal classification", [] { return identifiedSetupVerification(false, false, false, "vault_key_unavailable"); }},
        {"setup access denial reason retains authentic terminal classification", [] { return identifiedSetupVerification(false, false, false, "vault_access_denied"); }},
        {"setup unavailable reason retains authentic terminal classification", [] { return identifiedSetupVerification(false, false, false, "vault_unavailable"); }},
        {"setup timeout rejects invented readiness and timing before accepting safe refusal", [] { return identifiedSetupVerification(false, false, true); }},
        {"indeterminate setup keeps the operation fence", [] { return identifiedSetupVerification(true); }},
        {"indeterminate setup survives missing and malformed status before validated completion", [] { return identifiedSetupVerification(true, true); }},
        {"reject incompatible version", incompatibleVersion},
        {"bounded valid frames", malformedAndOversizedFrames},
        {"reconnect without mutation replay", noMutationReplay},
        {"declared external failure retains indeterminate identity", [] { return declaredFailureReconciliation(DeclineOutcome::indeterminate); }},
        {"started mutation remains held", [] { return declaredFailureReconciliation(DeclineOutcome::started); }},
        {"completed mutation recovers without replay", [] { return declaredFailureReconciliation(DeclineOutcome::completed); }},
        {"authoritative absence releases safe preflight refusal", [] { return declaredFailureReconciliation(DeclineOutcome::absent); }},
        {"failed outcome query retains mutation identity", [] { return declaredFailureReconciliation(DeclineOutcome::queryFailure); }},
        {"malformed completed outcome stays held", [] { return declaredFailureReconciliation(DeclineOutcome::malformedCompleted); }},
    };
    for (const auto &[name, test] : tests) {
        if (!test()) { std::fprintf(stderr, "FAIL: %s\n", name); return 1; }
        std::fprintf(stdout, "PASS: %s\n", name);
        std::fflush(stdout);
    }
    return 0;
}
