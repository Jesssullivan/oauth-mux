#include "omux_client.h"
#include "runtime_paths.h"

#include <QDir>
#include <QUuid>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonParseError>
#include <QStandardPaths>
#include <sys/socket.h>
#include <utility>
#include <cmath>
#include <unistd.h>

namespace {
bool mutationMethod(const QString &method, const QJsonObject &params = {}) {
    if (method == "setup.refresh") return params.contains("operation_id") || params.contains("expected_revision");
    static const QStringList names {"source.connect", "source.reconcile", "source.disconnect", "account.pause", "account.resume", "account.drain", "account.forget", "enrollment.start", "repair.start", "operation.cancel", "integrations.install", "integrations.remove", "integrations.attach", "integrations.detach", "policy.set"};
    return names.contains(method);
}
bool validOperationID(const QString &id) {
    if (id.isEmpty() || id.size() > 64) return false;
    for (const auto character : id) {
        const auto byte = character.unicode();
        if (!((byte >= 'a' && byte <= 'z') || (byte >= 'A' && byte <= 'Z') ||
              (byte >= '0' && byte <= '9') || byte == '-' || byte == '_')) return false;
    }
    return true;
}
bool verificationTerminal(const QJsonObject &result, const QString &operation) {
    const QStringList fields {"schema_version", "operation_id", "generation", "observed_at", "outcome", "refusal", "phases", "elapsed_ns", "timing_scope"};
    if (result.size() != fields.size()) return false;
    for (const auto &field : fields) if (!result.contains(field)) return false;
    // Qt preserves JSON integers within qint64. Values outside that exact
    // representation remain fenced rather than accepting rounded authority.
    const auto nonnegativeInteger = [](const QJsonValue &value) {
        return value.isDouble() && std::isfinite(value.toDouble())
            && std::floor(value.toDouble()) == value.toDouble() && value.toInteger(-1) >= 0;
    };
    const auto outcome = result.value("outcome").toString();
    const auto version = result.value("schema_version").toInteger(-1);
    if (!nonnegativeInteger(result.value("schema_version")) || (version != 1 && version != 2)
        || result.value("operation_id").toString() != operation
        || !nonnegativeInteger(result.value("generation")) || !nonnegativeInteger(result.value("observed_at"))
        || result.value("timing_scope").toString() != "admission_to_terminal_before_commit_process_local"
        || (!result.value("elapsed_ns").isNull() && !nonnegativeInteger(result.value("elapsed_ns")))
        || !result.value("phases").isArray() || result.value("phases").toArray().size() != 7) return false;
    const bool completed = outcome == "verification_completed";
    const bool refusal = outcome == "safe_refusal";
    if ((!completed && !refusal) || (completed && (!result.value("refusal").isNull() || result.value("generation").toInteger() == 0))
        || (refusal && (!QStringList{"busy", "installation_selection_required", "collection_timed_out"}.contains(result.value("refusal").toString())
            || (version == 1 && !result.value("elapsed_ns").isNull())))) return false;
    const QStringList unknown {"observation_unknown", "observation_stale", "evidence_unobserved", "synthetic_only", "native_evidence_missing", "channel_unknown"};
    const QStringList action {"channel_mismatch", "missing", "pending", "incompatible", "vault_locked", "vault_key_lost", "vault_key_unavailable", "vault_access_denied", "vault_unavailable", "authority_expired", "browser_required", "native_unsupported"};
    for (const auto &value : result.value("phases").toArray()) {
        if (!value.isObject()) return false;
        const auto phase = value.toObject();
        if (phase.size() != 2 || !phase.value("reason").isString() || !phase.value("outcome").isString()) return false;
        const auto reason = phase.value("reason").toString();
        const auto classified = reason == "ready" ? QString("verified_ready")
            : unknown.contains(reason) ? QString("unknown") : action.contains(reason) ? QString("action_required") : QString();
        if (classified.isEmpty() || phase.value("outcome").toString() != classified
            || (refusal && (reason != "observation_unknown" || classified != "unknown"))) return false;
    }
    return true;
}
}

QString OmuxClient::defaultSocketPath() {
    return OmuxRuntimePaths::defaultControlSocket();
}

OmuxClient::OmuxClient(QString socketPath, QObject *parent)
    : QObject(parent), socketPath_(std::move(socketPath)) {
    socket_.setReadBufferSize(maximumFrame + 1);
    clock_.start();
    reconnect_.setSingleShot(true);
    reconnect_.setInterval(5000);
    connect(&reconnect_, &QTimer::timeout, this, [this] { connectToDaemon(); });
    connect(&socket_, &QLocalSocket::connected, this, [this] {
        connecting_ = false;
        if (!verifyPeer()) {
            disconnectWithReason("The local service belongs to another user; connection refused.");
            return;
        }
        send("system.handshake", {{"protocol_version", 2}, {"client", "omux-linux"}},
            [this](const QJsonObject &result, const QString &error) {
                if (!error.isEmpty() || result.value("protocol_version").toInt() != 2) {
                    disconnectWithReason("The service uses an unsupported control protocol.");
                    return;
                }
                enrollmentGeneration_ = result.value("capabilities").toObject().value("enrollment_generation_reply").isBool()
                    && result.value("capabilities").toObject().value("enrollment_generation_reply").toBool();
                custodyReopen_ = result.value("capabilities").toObject().value("custody_reopen").isBool()
                    && result.value("capabilities").toObject().value("custody_reopen").toBool();
                ready_ = true;
                publishConnection(true, "Connected");
                reconcileOperations();
            });
    });
    connect(&socket_, &QLocalSocket::readyRead, this, [this] { readFrames(); });
    connect(&socket_, &QLocalSocket::disconnected, this, [this] {
        disconnectWithReason("Service disconnected. Reconnecting…");
    });
    connect(&socket_, &QLocalSocket::errorOccurred, this,
        [this](QLocalSocket::LocalSocketError) {
            disconnectWithReason("Service unavailable. Start the Omux user service or reconnect.");
        });
    deadlines_.setInterval(250);
    connect(&deadlines_, &QTimer::timeout, this, [this] {
        const qint64 now = clock_.elapsed();
        if (ready_ && verifications_.size() > stoppedVerifications_.size() && now >= nextVerificationQuery_) {
            nextVerificationQuery_ = now + 1000;
            reconcileOperations();
        }
        if (connecting_ && now >= connectDeadline_) {
            disconnectWithReason("Connection timed out. Reconnecting…");
            return;
        }
        const auto ids = pending_.keys();
        for (const qint64 id : ids) {
            if (!pending_.contains(id)) continue;
            if (pending_.value(id).deadline > now) continue;
            auto entry = pending_.take(id);
            if (entry.mutation) uncertain_.insert(entry.operationID, "Service request timed out.");
            auto reply = std::move(entry.reply);
            reply({}, "Service request timed out; query operation status before repeating an action.");
            if (entry.mutation && ready_) reconcileOperations();
        }
    });
    deadlines_.start();
}

OmuxClient::~OmuxClient() {
    // Member QObjects die before QObject's base destructor disconnects this
    // receiver. In particular, QLocalSocket can emit disconnected while closing;
    // that callback must not touch an already-destroyed pending map or timer.
    QObject::disconnect(&socket_, nullptr, this, nullptr);
    QObject::disconnect(&reconnect_, nullptr, this, nullptr);
    QObject::disconnect(&deadlines_, nullptr, this, nullptr);
    reconnect_.stop();
    deadlines_.stop();
    socket_.abort();
    pending_.clear();
}

bool OmuxClient::verifyPeer() const {
#ifdef Q_OS_LINUX
    struct ucred peer {};
    socklen_t size = sizeof(peer);
    return getsockopt(static_cast<int>(socket_.socketDescriptor()), SOL_SOCKET,
                      SO_PEERCRED, &peer, &size) == 0
        && size == sizeof(peer) && peer.uid == geteuid();
#else
    uid_t uid; gid_t gid;
    return getpeereid(static_cast<int>(socket_.socketDescriptor()), &uid, &gid) == 0
        && uid == geteuid();
#endif
}

void OmuxClient::publishConnection(bool connected, const QString &message) {
    if (onConnection) onConnection(connected, message);
}

void OmuxClient::connectToDaemon() {
    if (ready_ || connecting_) return;
    reconnect_.stop();
    connecting_ = true;
    connectDeadline_ = clock_.elapsed() + 3000;
    publishConnection(false, "Connecting…");
    try { OmuxRuntimePaths::validateSocketPath(socketPath_); }
    catch (const std::exception &error) { disconnectWithReason(QString::fromUtf8(error.what())); return; }
    socket_.connectToServer(socketPath_);
}

void OmuxClient::disconnectWithReason(const QString &reason) {
    ready_ = false;
    custodyReopen_ = false;
    enrollmentGeneration_ = false;
    connecting_ = false;
    buffer_.clear();
    // Clear before abort: Qt can deliver disconnected synchronously.
    const auto pending = std::exchange(pending_, {});
    if (socket_.state() != QLocalSocket::UnconnectedState) socket_.abort();
    for (const Pending &entry : pending) {
        if (entry.mutation) uncertain_.insert(entry.operationID, "Connection lost; the action outcome may be unknown.");
        entry.reply({}, "Connection lost; the action outcome may be unknown. Query operation status before repeating it.");
    }
    publishConnection(false, reason);
    if (!reconnect_.isActive()) reconnect_.start();
}

void OmuxClient::request(const QString &method, QJsonObject params, Reply reply) {
    if (!ready_) { reply({}, "Omux is disconnected."); return; }
    if (mutationMethod(method, params)) {
        if (!uncertain_.isEmpty()) { reply({}, uncertaintyMessage()); return; }
        if (!params.contains("operation_id")) params.insert("operation_id", QUuid::createUuid().toString(QUuid::WithoutBraces));
        if (!validOperationID(params.value("operation_id").toString())) { reply({}, "Invalid operation identifier."); return; }
        if (!params.contains("expected_revision")) params.insert("expected_revision", revision_);
    }
    if (method == "setup.refresh" && mutationMethod(method, params)) {
        const auto operation = params.value("operation_id").toString();
        verifications_.insert(operation);
        uncertain_.insert(operation, "Local setup verification is pending. Its completion does not establish installation or handoff success.");
    }
    send(method, params, std::move(reply));
    if (method == "state.snapshot" && !uncertain_.isEmpty()) reconcileOperations();
}

void OmuxClient::recoverMutation(const QString &operationID) {
    if (operationID.size()!=64) return;
    for (const auto c:operationID)
        if (!((c>='0' && c<='9') || (c>='a' && c<='f'))) return;
    uncertain_.insert(operationID,"A retained enrollment intent needs its original operation outcome.");
    if (ready_) reconcileOperations();
}

QString OmuxClient::uncertaintyMessage() const {
    if (uncertain_.isEmpty()) return {};
    const auto held = uncertain_.constBegin();
    return held.value() + "\nA previous action has an unknown outcome and may have partially taken effect. Reconcile operation "
        + held.key() + " before requesting another mutation.";
}

void OmuxClient::send(const QString &method, const QJsonObject &params, Reply reply) {
    const qint64 id = nextID_++;
    const QJsonObject envelope {{"jsonrpc", "2.0"}, {"id", id},
                               {"method", method}, {"params", params}};
    const QByteArray frame = QJsonDocument(envelope).toJson(QJsonDocument::Compact) + '\n';
    if (frame.size() > maximumFrame) { reply({}, "Request is too large."); return; }
    const bool nativeOperation = method.startsWith("integrations.") && method != "integrations.status";
    pending_.insert(id, {std::move(reply), clock_.elapsed() + (nativeOperation ? 20000 : 10000), params.value("operation_id").toString(), mutationMethod(method, params)});
    if (socket_.write(frame) != frame.size())
        disconnectWithReason("Could not send the service request.");
}

void OmuxClient::readFrames() {
    buffer_ += socket_.readAll();
    while (true) {
        const qsizetype newline = buffer_.indexOf('\n');
        if (newline < 0) {
            if (buffer_.size() > maximumFrame)
                disconnectWithReason("Service response exceeds the control protocol limit.");
            return;
        }
        if (newline > maximumFrame) {
            disconnectWithReason("Service response exceeds the control protocol limit.");
            return;
        }
        const QByteArray frame = buffer_.left(newline);
        buffer_.remove(0, newline + 1);
        QJsonParseError parseError;
        const auto document = QJsonDocument::fromJson(frame, &parseError);
        if (parseError.error != QJsonParseError::NoError || !document.isObject()) {
            disconnectWithReason("Service returned an invalid control response."); return;
        }
        const QJsonObject envelope = document.object();
        if (envelope.value("jsonrpc").toString() != "2.0") {
            disconnectWithReason("Service returned an invalid control envelope."); return;
        }
        if (!envelope.contains("id")) {
            if (envelope.value("method").toString() == "events.changed" && onEvent)
                onEvent(envelope.value("params").toObject());
            continue;
        }
        const qint64 id = envelope.value("id").toInteger(-1);
        if (!pending_.contains(id)) continue; // A late timeout reply cannot resurrect a request.
        auto entry = pending_.take(id);
        auto reply = std::move(entry.reply);
        if (envelope.contains("error")) {
            const auto error = envelope.value("error").toObject();
            const auto reason = error.value("message").toString("The service declined the action.");
            if (entry.mutation) uncertain_.insert(entry.operationID, reason);
            reply({}, reason);
            if (entry.mutation && ready_) reconcileOperations();
        } else if (envelope.value("result").isObject()) {
            const auto result = envelope.value("result").toObject();
            if (result.contains("revision")) revision_ = result.value("revision").toInteger();
            if (verifications_.contains(entry.operationID) && verificationTerminal(result, entry.operationID)) {
                verifications_.remove(entry.operationID);
                stoppedVerifications_.remove(entry.operationID);
                uncertain_.remove(entry.operationID);
            }
            reply(result, {});
        } else {
            if (entry.mutation) uncertain_.insert(entry.operationID, "Service returned an invalid result.");
            reply({}, "Service returned an invalid result.");
            if (entry.mutation && ready_) reconcileOperations();
        }
    }
}

void OmuxClient::reconcileOperations() {
    const auto ids = uncertain_.keys();
    for (const auto &operationID : ids) {
        if (reconciling_.contains(operationID)) continue;
        reconciling_.insert(operationID);
        send("operation.status", {{"operation_id", operationID}}, [this, operationID](const QJsonObject &result, const QString &error) {
            reconciling_.remove(operationID);
            const auto status = result.value("status").toString();
            const bool verification = verifications_.contains(operationID);
            if (verification && error.isEmpty() && status == "indeterminate" && result.value("operation_id").toString() == operationID) {
                stoppedVerifications_.insert(operationID);
                uncertain_[operationID] = "Setup verification outcome is indeterminate. Preserve this operation identity; do not submit another verification.";
                if (onEvent) onEvent({{"operation_id", operationID}, {"operation_status", "indeterminate"}, {"operation_kind", "setup_verification"}});
            }
            if ((error.isEmpty() && status == "completed" && result.value("operation_id").toString() == operationID && result.value("result").isObject()
                && (!verification || verificationTerminal(result.value("result").toObject(), operationID))) || (error == "UnknownOperation" && !verification)) {
                verifications_.remove(operationID);
                stoppedVerifications_.remove(operationID);
                const auto originalError = uncertain_.take(operationID);
                if (onEvent) onEvent({{"operation_id", operationID}, {"operation_status", error.isEmpty() ? status : "not_found"}, {"operation_kind", verification ? "setup_verification" : "mutation"}, {"operation_error", originalError}, {"operation_result", result.value("result")}});
            }
        });
    }
}
