#include "siwc_enrollment.h"
#include "siwc_browser.h"
#include <QCheckBox>
#include <QComboBox>
#include <QDateTime>
#include <QDialogButtonBox>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QJsonArray>
#include <QMessageBox>
#include <QPushButton>
#include <QSpinBox>
#include <QSet>
#include <QUuid>
#include <QVariant>
#include <QVBoxLayout>
#include <utility>
#include <sys/resource.h>

namespace {
const QString purpose = "fresh_openai_siwc_oauth_enrollment";
bool handle(const QJsonValue &v) {
    if (!v.isString() || v.toString().size() != 64 || v.toString() == QString(64, '0')) return false;
    for (const auto c : v.toString()) if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}
bool integer(const QJsonValue &v, qint64 minimum = 0) {
    return v.isDouble() && v.toInteger(-1) >= minimum && v.toDouble() == double(v.toInteger(-1));
}
bool falseFlag(const QJsonObject &v, const char *key) { return v.value(key).isBool() && !v.value(key).toBool(); }
QString operationID() {
    return QUuid::createUuid().toString(QUuid::WithoutBraces).remove('-') + QUuid::createUuid().toString(QUuid::WithoutBraces).remove('-');
}
}

bool SiwcEnrollment::descriptorValid(const QJsonObject &d) {
    const QJsonObject methods {{"prepare", "oauth.enrollment.prepare.siwc.v1"}, {"authorization", "oauth.enrollment.authorization.v1"},
        {"status", "oauth.enrollment.status.v1"}, {"pending", "oauth.enrollment.pending.v1"}, {"withdraw", "oauth.enrollment.withdraw.v1"}};
    const QJsonObject policy {{"scheme", "https"}, {"host", "auth.openai.com"}, {"path", "/api/accounts/authorize"},
        {"initial_client_id", "dynamic_agent_client"}, {"agent_name_hint", "omux"}, {"redirect_scheme", "http"},
        {"redirect_host", "127.0.0.1"}, {"redirect_path", "/auth/callback"}, {"redirect_port", "held_nonzero_loopback"},
        {"resource", "https://api.openai.com/v1"}, {"scopes", "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct"}, {"pkce", "S256"}};
    const auto flow = d.value("flow").toObject();
    return d.value("schema_version") == 1 && d.value("profile") == "openai_siwc_responses_v1"
        && d.value("purpose") == purpose && d.value("provider") == "openai_siwc"
        && d.value("issuer") == "https://auth.openai.com" && d.value("audience") == "https://api.openai.com/v1"
        && d.value("enrollment_io_policy") == "documented_oss_dynamic_registration_v1"
        && d.value("experimental") == true && d.value("implemented").isBool() && d.value("custody_available").isBool()
        && falseFlag(d, "provider_proof") && falseFlag(d, "native_support_proven") && falseFlag(d, "live_handoff_proven")
        && d.value("methods").toObject() == methods && d.value("authorization_policy").toObject() == policy
        && flow.value("minimum_seconds") == 1 && flow.value("maximum_seconds") == 3600
        && flow.value("minted_once") == true && flow.value("wall_and_awake") == true && flow.value("rpc_deadline_separate") == true
        && flow.value("authorization_deliveries") == 1 && flow.value("reconnect_renews") == false;
}

bool SiwcEnrollment::statusValid(const QJsonObject &s, const QString &id) {
    const auto state = s.value("status").toString();
    if (s.value("schema_version") != 1 || s.value("transaction_id") != id || !handle(s.value("transaction_id"))
        || !s.value("custody_available").isBool()
        || !QStringList{"pending", "expired", "cancelled", "unknown", "quarantined", "paired", "retired", "not_retained"}.contains(state)) return false;
    if (!s.value("custody_available").toBool()) return state == "unknown" && s.value("phase").isNull()
        && s.value("paired_committed").isNull() && s.value("grant_ready").isNull() && s.value("reason") == "custody_unavailable";
    if (!integer(s.value("revision"))) return false;
    if (state == "not_retained") return s.value("phase").isNull() && s.value("paired_committed").isNull() && s.value("grant_ready").isNull();
    if (!QStringList{"prepared", "callback_consumed", "exchange_issued", "verifying", "active", "completion_unknown", "quarantined", "retired"}.contains(s.value("phase").toString())
        || !s.value("paired_committed").isBool() || !s.value("grant_ready").isBool() || !handle(s.value("source_id"))
        || !QStringList{"recorded", "withdrawn"}.contains(s.value("consent_status").toString())) return false;
    if (s.value("paired_committed").toBool()) return (state == "paired" || state == "retired") && handle(s.value("account_id"))
        && QStringList{"none", "withdrawn", "source_disconnected", "forgotten"}.contains(s.value("retirement_reason").toString())
        && (state == "paired" ? s.value("phase") == "active" && s.value("consent_status") == "recorded"
            : s.value("phase") == "retired" && !s.value("grant_ready").toBool());
    return !s.value("grant_ready").toBool() && s.value("account_id").isNull() && integer(s.value("flow_expires_at"), 1)
        && integer(s.value("flow_seconds"), 1) && s.value("flow_seconds").toInteger() <= 3600 && s.value("flow_expired").isBool()
        && state != "paired" && (state != "pending" || (!s.value("flow_expired").toBool() && s.value("consent_status") == "recorded"));
}

SiwcEnrollment::SiwcEnrollment(OmuxClient &client, QWidget *parent, Browser browser)
    : QObject(parent), client_(client), parent_(parent), browser_(browser ? std::move(browser) : openSiwcAuthorization) {
    poll_.setInterval(2000);
    connect(&poll_, &QTimer::timeout, this, [this] {
        if (!panel_ || terminal_ || !elapsed_.isValid() || elapsed_.elapsed() >= flowSeconds_ * 1000) {
            poll_.stop();
            if (panel_ && !terminal_) message("Status observation stopped at the original finite bound. Current authority is Unknown; Check status reads the daemon outcome without renewing consent.");
            return;
        }
        if (connected_) status();
    });
}

void SiwcEnrollment::open() {
    if (panel_) { panel_->show(); panel_->raise(); panel_->activateWindow(); return; }
    panel_ = new QDialog(parent_);
    panel_->setAttribute(Qt::WA_DeleteOnClose);
    panel_->setObjectName("siwcEnrollment"); panel_->setWindowTitle("Add an account — daemon-owned sign-in"); panel_->resize(660, 430);
    auto *layout = new QVBoxLayout(panel_);
    auto *intro = new QLabel("Sign in with ChatGPT connects a separate Omux API Responses source. Omux owns the callback, verified paired grant and renewal. Your browser handles authentication. This does not authenticate native Codex, alter native history or prove application continuity.");
    intro->setTextFormat(Qt::PlainText); intro->setWordWrap(true); layout->addWidget(intro);
    notice_ = new QLabel("Reading the daemon's experimental enrollment descriptor…");
    notice_->setObjectName("siwcStatus"); notice_->setTextFormat(Qt::PlainText); notice_->setWordWrap(true); layout->addWidget(notice_);
    auto *form = new QFormLayout;
    seconds_ = new QSpinBox; seconds_->setObjectName("siwcConsentSeconds"); seconds_->setRange(1, 3600); seconds_->setValue(600);
    form->addRow("Maximum sign-in time (seconds)", seconds_);
    recover_ = new QComboBox; recover_->setObjectName("siwcPending"); recover_->addItem("New sign-in"); form->addRow("Existing pending enrollment", recover_); layout->addLayout(form);
    consent_ = new QCheckBox("I authorize this finite daemon-owned sign-in and its resulting paired API source.");
    consent_->setObjectName("siwcConsent"); layout->addWidget(consent_);
    auto *buttons = new QHBoxLayout;
    start_ = new QPushButton("Sign in in browser"); start_->setObjectName("siwcStart");
    browserButton_ = new QPushButton("Open existing consented sign-in"); browserButton_->setObjectName("siwcOpenBrowser");
    check_ = new QPushButton("Check status"); check_->setObjectName("siwcCheck");
    cancel_ = new QPushButton("Cancel / remove this source…"); cancel_->setObjectName("siwcCancel");
    for (auto *b : {start_.data(), browserButton_.data(), check_.data(), cancel_.data()}) buttons->addWidget(b);
    layout->addLayout(buttons);
    auto *close = new QDialogButtonBox(QDialogButtonBox::Close); layout->addWidget(close);
    connect(close, &QDialogButtonBox::rejected, panel_, &QDialog::close);
    connect(panel_, &QDialog::finished, this, [this] {
        poll_.stop(); ++generation_;
        if (preparePending_ && !operation_.isEmpty()) client_.recoverMutation(operation_);
        if (withdrawPending_ && !withdrawalOperation_.isEmpty()) client_.recoverMutation(withdrawalOperation_);
        preparePending_ = authorizePending_ = statusPending_ = withdrawPending_ = descriptorPending_ = false;
        if (terminal_ && latest_.value("status") == "paired") {
            // Closing completed onboarding releases only this UI selection.
            // A later Add account intent leaves the committed source intact.
            transaction_.clear(); source_.clear(); operation_.clear(); latest_ = {};
            terminal_ = false; authorizationAttempted_ = false;
        }
    });
    connect(consent_, &QCheckBox::toggled, panel_, [this] { controls(); });
    connect(start_, &QPushButton::clicked, panel_, [this] { prepare(); });
    connect(browserButton_, &QPushButton::clicked, panel_, [this] { authorize(); });
    connect(check_, &QPushButton::clicked, panel_, [this] { status(); });
    connect(cancel_, &QPushButton::clicked, panel_, [this] { withdraw(); });
    connect(recover_, &QComboBox::activated, panel_, [this] {
        const auto selected = recover_->currentData().value<QJsonObject>();
        if (selected.isEmpty()) { if (!transaction_.isEmpty()) return; message("New finite sign-in needs explicit consent."); controls(); return; }
        ++generation_; statusPending_ = descriptorPending_ = false; ++selection_; transaction_ = selected.value("transaction_id").toString(); source_ = selected.value("source_id").toString();
        authorizationAttempted_ = selected.value("authorization_delivered").toBool(true); terminal_ = false;
        flowSeconds_ = qBound<qint64>(qint64{1}, selected.value("flow_expires_at").toInteger() - QDateTime::currentSecsSinceEpoch(), qint64{3600});
        elapsed_.start(); latest_ = {}; consent_->setChecked(false); poll_.start(); status(); descriptor(); controls();
    });
    connected_ = client_.ready();
    controls(); panel_->show(); descriptor();
    if (!transaction_.isEmpty()) {
        if (!terminal_ && elapsed_.isValid() && elapsed_.elapsed() < flowSeconds_ * 1000) poll_.start();
        status();
    }
}

void SiwcEnrollment::message(const QString &text) { if (notice_) notice_->setText(text); }
void SiwcEnrollment::failed(const QString &error) {
    const bool custody = QStringList{"Locked", "VaultLocked", "CustodyLocked", "WrappingKeyUnavailable"}.contains(error);
    if (custody && descriptorValid(descriptor_)) descriptor_.insert("custody_available", false);
    if (consent_) consent_->setChecked(false);
    message(custody ? "Credential custody is unavailable. Restore access to the normal OS Secret Service vault; unlock it through your desktop if requested by the OS. Then use Setup → Resume after vault unlock and retry this original status/action. Existing encrypted data remains preserved; no new key or plaintext fallback is created. The required authentication factor is determined by the OS."
        : "Enrollment outcome is Unknown or refused. " + (client_.hasUncertainOperations() ? client_.uncertaintyMessage() : "No action or authorization delivery is repeated automatically. Check status or cancel before a fresh explicit sign-in."));
    controls();
}
void SiwcEnrollment::controls() {
    if (!panel_) return;
    const bool available = connected_ && client_.supportsSiwcEnrollment() && descriptorValid(descriptor_) && descriptor_.value("implemented").toBool()
        && descriptor_.value("custody_available").toBool() && !client_.hasUncertainOperations();
    start_->setEnabled(available && transaction_.isEmpty() && consent_->isChecked() && !preparePending_);
    browserButton_->setEnabled(available && !transaction_.isEmpty() && !authorizationAttempted_ && !authorizePending_ && !terminal_ && consent_->isChecked());
    check_->setEnabled(connected_ && !transaction_.isEmpty() && !statusPending_);
    cancel_->setEnabled(available && !transaction_.isEmpty() && !withdrawPending_);
    recover_->setEnabled(!preparePending_ && !authorizePending_ && !withdrawPending_);
    seconds_->setEnabled(transaction_.isEmpty() && !preparePending_);
}
void SiwcEnrollment::connectionChanged(bool connected) {
    connected_ = connected;
    if (!connected) { latest_ = {}; message("Disconnected; current enrollment and grant readiness are Unknown. Original consent is not renewed, and one-use authorization is not repeated."); }
    else if (panel_) descriptor();
    controls();
}
void SiwcEnrollment::observe(const QJsonObject &snapshot) {
    if (panel_ && !descriptorPending_ && descriptorValid(descriptor_) && snapshot.value("custody_available").isBool()
        && descriptor_.value("custody_available") != snapshot.value("custody_available")) descriptor();
}
void SiwcEnrollment::descriptor() {
    if (!panel_ || !client_.ready()) { failed("Disconnected"); return; }
    if (!client_.supportsSiwcEnrollment()) { descriptor_ = {}; message("This service has not negotiated daemon-owned SIWC enrollment. Update the managed package/service; experimental external-source imports are separate."); controls(); return; }
    if (descriptorPending_) return;
    descriptorPending_ = true;
    const auto generation = generation_;
    client_.request("oauth.enrollment.descriptor.v1", {}, [self = QPointer<SiwcEnrollment>(this), generation](const QJsonObject &d, const QString &error) {
        if (!self || !self->panel_ || generation != self->generation_) return;
        self->descriptorPending_ = false;
        self->descriptor_ = {};
        if (!error.isEmpty() || !descriptorValid(d)) { self->failed(error); return; }
        self->descriptor_ = d; self->controls();
        if (!d.value("implemented").toBool()) self->message("This service does not implement the negotiated enrollment profile. No browser sign-in or provider request is available.");
        else if (!d.value("custody_available").toBool()) self->failed("WrappingKeyUnavailable");
        else if (self->transaction_.isEmpty()) self->message("Experimental daemon-owned Sign in with ChatGPT is implemented. Provider qualification and native application support remain unproved. Confirm finite consent to open your normal browser.");
        self->pending();
    });
}
void SiwcEnrollment::pending() {
    const auto generation = generation_;
    client_.request("oauth.enrollment.pending.v1", {}, [self = QPointer<SiwcEnrollment>(this), generation](const QJsonObject &s, const QString &error) {
        if (!self || !self->panel_ || generation != self->generation_) return;
        if (!error.isEmpty() || s.value("schema_version") != 1 || !s.value("custody_available").isBool()) {
            self->recover_->clear(); self->recover_->addItem("Unknown: pending enrollment list unavailable"); return;
        }
        if (!s.value("custody_available").toBool()) {
            self->recover_->clear(); self->recover_->addItem("Unknown: custody unavailable"); return;
        }
        if (!s.value("pending").isArray() || s.value("pending").toArray().size() > 16) {
            self->recover_->clear(); self->recover_->addItem("Unknown: unsupported pending enrollment list"); return;
        }
        QSet<QString> ids;
        for (const auto &v : s.value("pending").toArray()) {
            const auto row = v.toObject(); const auto id = row.value("transaction_id").toString();
            if (!handle(row.value("transaction_id")) || ids.contains(id) || !handle(row.value("source_id")) || !integer(row.value("flow_expires_at"), 1)
                || !row.value("authorization_delivered").isBool()
                || !QStringList{"prepared", "callback_consumed", "exchange_issued", "verifying"}.contains(row.value("phase").toString())) {
                self->recover_->clear(); self->recover_->addItem("Unknown: unsupported pending enrollment list"); return;
            }
            ids.insert(id);
        }
        self->recover_->clear(); self->recover_->addItem("New sign-in");
        for (const auto &v : s.value("pending").toArray()) {
            const auto row = v.toObject();
            if (!handle(row.value("transaction_id")) || !handle(row.value("source_id")) || !integer(row.value("flow_expires_at"), 1)
                || !row.value("authorization_delivered").isBool()) continue;
            self->recover_->addItem("Pending source " + row.value("source_id").toString(), QVariant::fromValue(row));
        }
    });
}
void SiwcEnrollment::prepare() {
    if (!start_ || !start_->isEnabled()) return;
    struct rlimit core {0, 0};
    if (::setrlimit(RLIMIT_CORE, &core) != 0) { failed("CoreCustodyUnavailable"); return; }
    ++selection_; prepareSelection_ = selection_;
    operation_ = operationID(); preparePending_ = true; flowSeconds_ = seconds_->value(); elapsed_.start();
    prepareSeconds_ = flowSeconds_;
    terminal_ = false; authorizationAttempted_ = false; latest_ = {};
    message("Recording your original finite consent. No account or grant has been admitted."); controls();
    const auto generation = generation_;
    client_.request(descriptor_.value("methods").toObject().value("prepare").toString(),
        {{"provider", descriptor_.value("provider")}, {"purpose", descriptor_.value("purpose")}, {"consent_seconds", flowSeconds_}, {"operation_id", operation_}},
        [self = QPointer<SiwcEnrollment>(this), generation](const QJsonObject &r, const QString &error) {
        if (!self || generation != self->generation_) return;
        self->preparePending_ = false;
        if (!error.isEmpty()) { self->failed(error); return; }
        self->admitted(r, false);
    });
}
void SiwcEnrollment::admitted(const QJsonObject &r, bool recovered) {
    if (!handle(r.value("transaction_id")) || !handle(r.value("source_id")) || !integer(r.value("admitted_revision"))
        || !integer(r.value("flow_expires_at"), 1) || r.value("flow_seconds").toInteger() != flowSeconds_
        || r.value("phase") != "prepared" || r.value("consent_recorded") != true || r.value("registration") != "enrollment_policy"
        || r.value("authorization_available") != true || !r.value("blocked_reason").isNull()
        || !falseFlag(r, "provider_request_initiated") || !falseFlag(r, "grant_activated")) { failed("InvalidEnrollmentReply"); return; }
    transaction_ = r.value("transaction_id").toString(); source_ = r.value("source_id").toString(); latest_ = {};
    poll_.start(); controls();
    if (recovered || !panel_) { message("Original consent recovered; no browser effect was repeated. Check status, or explicitly open its undelivered sign-in within the original bound."); return; }
    authorize();
}
bool SiwcEnrollment::operationEvent(const QJsonObject &event) {
    if (!withdrawalOperation_.isEmpty() && event.value("operation_id") == withdrawalOperation_ && event.value("operation_kind") == "mutation") {
        if (event.value("operation_status") == "completed" && event.value("operation_result").isObject()) withdrawn(event.value("operation_result").toObject());
        else if (event.value("operation_status") == "not_found") {
            const bool selected = transaction_ == withdrawalTransaction_ && source_ == withdrawalSource_;
            withdrawPending_ = false; withdrawalOperation_.clear(); withdrawalTransaction_.clear(); withdrawalSource_.clear();
            if (selected) failed("UnknownOperation"); else controls();
        }
        return true;
    }
    if (operation_.isEmpty() || event.value("operation_id") != operation_ || event.value("operation_kind") != "mutation") return false;
    if (event.value("operation_status") == "completed" && event.value("operation_result").isObject()) {
        preparePending_ = false;
        if (prepareSelection_ == selection_) {
            flowSeconds_ = prepareSeconds_; admitted(event.value("operation_result").toObject(), true);
        } else if (panel_) pending(); // Original completion cannot replace a selected owner.
        operation_.clear();
    } else if (event.value("operation_status") == "not_found") {
        preparePending_ = false;
        if (prepareSelection_ == selection_) failed("UnknownOperation"); else controls();
    }
    return true;
}
void SiwcEnrollment::authorize() {
    if (!panel_ || authorizationAttempted_ || authorizePending_ || terminal_ || transaction_.isEmpty() || !consent_->isChecked()) return;
    // Recovered consent can deliver a private URL in a fresh ordinary process.
    // Establish custody before any authorization request, not after receipt.
    struct rlimit core {0, 0};
    if (::setrlimit(RLIMIT_CORE, &core) != 0) { failed("CoreCustodyUnavailable"); return; }
    authorizePending_ = true; controls();
    const auto generation = generation_;
    client_.request("oauth.enrollment.status.v1", {{"purpose", purpose}, {"transaction_id", transaction_}},
        [self = QPointer<SiwcEnrollment>(this), generation](const QJsonObject &s, const QString &error) {
        if (!self || !self->panel_ || generation != self->generation_) return;
        if (!error.isEmpty() || !statusValid(s, self->transaction_) || s.value("status") != "pending" || s.value("phase") != "prepared") {
            self->authorizePending_ = false; self->failed(error); return;
        }
        self->authorizationAttempted_ = true;
        self->client_.request("oauth.enrollment.authorization.v1", {{"purpose", purpose}, {"transaction_id", self->transaction_}, {"expected_revision", s.value("revision")}},
            [self, generation](const QJsonObject &r, const QString &error) {
            if (!self || !self->panel_ || generation != self->generation_) return;
            self->authorizePending_ = false;
            if (!error.isEmpty() || r.size() != 3 || !r.value("authorization_url").isString()
                || !falseFlag(r, "provider_request_initiated") || !falseFlag(r, "grant_activated")) { self->failed(error); return; }
            auto url = r.value("authorization_url").toString();
            const bool safe = validateSiwcAuthorization(self->descriptor_.value("profile").toString(), url);
            const bool opened = safe && self->browser_(self->descriptor_.value("profile").toString(), url);
            url.fill(QChar('\0')); url.clear();
            self->message(opened ? "Browser sign-in opened. Enrollment is pending; no account or paired grant is counted until the daemon verifies and commits it. This panel checks redacted status within the original finite consent."
                : "Browser delivery is refused or unavailable. The one-use authorization is not repeated. Cancel this enrollment before a new explicit sign-in; the original flow remains daemon-owned.");
            self->controls(); self->status();
        });
    });
}
void SiwcEnrollment::status() {
    if (!panel_ || transaction_.isEmpty() || !connected_ || !client_.supportsSiwcEnrollment() || statusPending_) return;
    statusPending_ = true; controls(); const auto generation = generation_;
    client_.request("oauth.enrollment.status.v1", {{"purpose", purpose}, {"transaction_id", transaction_}},
        [self = QPointer<SiwcEnrollment>(this), generation](const QJsonObject &s, const QString &error) {
        if (!self || !self->panel_ || generation != self->generation_) return;
        self->statusPending_ = false;
        if (!error.isEmpty() || !statusValid(s, self->transaction_)) { self->latest_ = {}; self->failed(error); return; }
        self->showStatus(s); self->controls();
    });
}
void SiwcEnrollment::showStatus(const QJsonObject &s) {
    latest_ = s; const auto state = s.value("status").toString();
    if (!s.value("custody_available").toBool()) { failed("WrappingKeyUnavailable"); return; }
    if (handle(s.value("source_id"))) source_ = s.value("source_id").toString();
    terminal_ = state != "pending"; if (terminal_) poll_.stop();
    QString text = "Transaction " + transaction_ + " · source " + source_ + "\n";
    if (state == "paired" && s.value("paired_committed") == true) {
        text += "Opaque verified account: " + s.value("account_id").toString() + "\n";
        text += s.value("grant_ready") == true ? "Verified account and paired API grant are committed. Request authority is retained for the advertised API profile; quota, entitlement and provider acceptance remain separate."
            : "Verified paired enrollment is committed; the current request grant is unavailable. Inspect account/source readiness before use.";
        if (onCommitted) onCommitted();
    } else if (state == "pending") text += "Enrollment pending (" + s.value("phase").toString() + "); no paired grant committed. Original consent expires "
        + QDateTime::fromSecsSinceEpoch(s.value("flow_expires_at").toInteger()).toString(Qt::ISODate) + ".";
    else if (state == "expired") text += "The original enrollment expired. No paired grant was committed; cancel/clean up before a fresh explicit sign-in.";
    else if (state == "cancelled") text += "Enrollment is cancelled. Provider revocation and removal of native application history are not claimed.";
    else if (state == "retired") text += "Source enrollment is retired. Retirement alone does not establish consent withdrawal. Recorded consent: "
        + s.value("consent_status").toString() + "; retirement reason: " + s.value("retirement_reason").toString()
        + ". Provider revocation and removal of native application history are not claimed.";
    else text += "Enrollment/grant outcome is Unknown or quarantined. No usable grant is claimed; inspect this original transaction before a fresh intent.";
    text += "\nNative application support, live process attachment and seamless handoff remain unproved."; message(text);
}
void SiwcEnrollment::withdraw() {
    if (!cancel_ || !cancel_->isEnabled()) return;
    if (QMessageBox::question(panel_, "Cancel or remove this source?", "End this enrollment's consent and remove this source's retained paired grants. Other sources and native history remain separate. This does not revoke access at the provider.") != QMessageBox::Yes) return;
    // The explicit cancellation intent stops UI delivery immediately. Even an
    // already-issued authorization reply may not open after this boundary.
    ++generation_; poll_.stop(); authorizePending_ = statusPending_ = descriptorPending_ = false;
    withdrawPending_ = true; withdrawalOperation_ = operationID();
    withdrawalTransaction_ = transaction_; withdrawalSource_ = source_; consent_->setChecked(false);
    controls(); const auto generation = generation_;
    client_.request("oauth.enrollment.withdraw.v1", {{"purpose", purpose}, {"transaction_id", transaction_}, {"operation_id", withdrawalOperation_}},
        [self = QPointer<SiwcEnrollment>(this), generation](const QJsonObject &r, const QString &error) {
        if (!self || !self->panel_ || generation != self->generation_) return;
        if (!error.isEmpty()) { self->withdrawPending_ = false; self->failed(error); return; }
        self->withdrawn(r);
    });
}
void SiwcEnrollment::withdrawn(const QJsonObject &r) {
    withdrawPending_ = false;
    if (r.size() != 3 || r.value("consent_withdrawn") != true || !r.value("issued_work_may_have_occurred").isBool()
        || !falseFlag(r, "upstream_revoked")) { failed("InvalidWithdrawalReply"); return; }
    const bool selected = transaction_ == withdrawalTransaction_ && source_ == withdrawalSource_;
    withdrawalOperation_.clear(); withdrawalTransaction_.clear(); withdrawalSource_.clear();
    if (!selected) {
        // This ACK belongs only to the original source. A later UI selection is
        // neither retired nor relabelled by another owner's completion.
        if (onCommitted) onCommitted();
        if (panel_) pending();
        controls(); return;
    }
    poll_.stop(); terminal_ = true; transaction_.clear(); source_.clear(); latest_ = {}; operation_.clear();
    authorizationAttempted_ = false; if (consent_) consent_->setChecked(false);
    message("This source's consent was withdrawn; any locally retained paired grants for it were retired. Already issued work may have occurred; provider revocation is not claimed. A fresh sign-in needs new explicit finite consent.");
    controls(); if (onCommitted) onCommitted(); if (panel_) pending();
}
