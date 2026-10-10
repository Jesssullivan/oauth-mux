#include "tray.h"

#include <QApplication>
#include <QCloseEvent>
#include <QComboBox>
#include <QDesktopServices>
#include <QDialogButtonBox>
#include <QDir>
#include <QDateTime>
#include <QFormLayout>
#include <QFileInfo>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QInputDialog>
#include <QItemSelectionModel>
#include <QJsonDocument>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>
#include <QProcess>
#include <QProcessEnvironment>
#include <QSet>
#include <QStyle>
#include <QTabWidget>
#include <QUrl>
#include <QUuid>
#include <QVariant>
#include <QVBoxLayout>
#include <cmath>

namespace {
bool reopenedCustody(const QJsonObject &result) {
    const QStringList fields {"reopened", "custody_available", "metadata_loaded", "account_count",
        "provider_request_initiated", "live_handoff_proven"};
    if (result.size() != fields.size()) return false;
    for (const auto &field : fields) if (!result.contains(field)) return false;
    const auto count = result.value("account_count");
    return result.value("reopened").isBool()
        && result.value("custody_available").isBool() && result.value("custody_available").toBool()
        && result.value("metadata_loaded").isBool() && result.value("metadata_loaded").toBool()
        && count.isDouble() && std::isfinite(count.toDouble())
        && std::floor(count.toDouble()) == count.toDouble() && count.toInteger(-1) >= 0
        && result.value("provider_request_initiated").isBool() && !result.value("provider_request_initiated").toBool()
        && result.value("live_handoff_proven").isBool() && !result.value("live_handoff_proven").toBool();
}

QString text(const QJsonObject &object, const QString &field) {
    QJsonValue value = object;
    for (const auto &part : field.split('.')) value = value.toObject().value(part);
    if (value.isString()) {
        if (field == "label" && value.toString().isEmpty()) return object.value("id").toString("Unnamed");
        if (field == "resource.target" && value.toString().isEmpty()) return object.value("resource").toObject().value("kind").toString("Unknown");
        if (field == "resource.unit" && value.toString() == "custom") return object.value("resource").toObject().value("unit_name").toString("Unknown custom unit");
        return value.toString();
    }
    if (value.isDouble()) return field.endsWith("_at")
        ? QDateTime::fromSecsSinceEpoch(value.toInteger()).toString(Qt::ISODate)
        : QString::number(value.toDouble(), 'g', 12);
    if (value.isBool()) return value.toBool() ? "Yes" : "No";
    if (value.isArray()) {
        QStringList elements;
        for (const auto &element : value.toArray()) if (element.isString()) elements.append(element.toString());
        return elements.isEmpty() ? "Unknown" : elements.join(", ");
    }
    return "Unknown";
}

QJsonArray capacityRows(const QJsonArray &records, bool connected) {
    QJsonArray result;
    const qint64 now = QDateTime::currentSecsSinceEpoch();
    for (const auto &value : records) {
        auto record = value.toObject();
        if (!record.contains("window")) {
            const auto start = record.value("window_start");
            const auto end = record.value("window_end");
            record.insert("window", start.isDouble() && end.isDouble()
                ? QDateTime::fromSecsSinceEpoch(start.toInteger()).toString(Qt::ISODate)
                    + " — " + QDateTime::fromSecsSinceEpoch(end.toInteger()).toString(Qt::ISODate)
                : "Unknown");
        }
        if (!connected) record.insert("freshness", "Stale: service or custody unavailable");
        else if (!record.contains("freshness") && record.value("complete").isBool()) {
            const bool complete = record.value("complete").toBool();
            record.insert("freshness", complete ? "Current"
                : QString("Partial: %1 unknown or stale buckets").arg(record.value("unknown_buckets").toInteger()));
            if (!complete && record.value("buckets").toInteger() == 0)
                record.insert("remaining", QJsonValue());
        } else if (!record.contains("freshness")) {
            const auto expiry = record.value("expires_at");
            const auto status = record.value("status").toString();
            record.insert("freshness", !expiry.isDouble() || status == "unknown"
                ? "Unknown" : expiry.toInteger() <= now ? "Stale" : "Current");
        }
        if (record.value("freshness").toString() == "Unknown" || record.value("status").toString() == "unknown")
            record.insert("remaining", QJsonValue());
        result.append(record);
    }
    return result;
}

QJsonArray capacityDisplayRows(const QJsonObject &snapshot) {
    QJsonArray rows;
    for (const auto &value : snapshot.value("capacity").toArray()) {
        auto row = value.toObject();
        row.insert("provider", row.value("provider").toString() + " (compatible total)");
        rows.append(row);
    }
    for (const auto &value : snapshot.value("observations").toArray()) {
        auto row = value.toObject();
        const auto accountID = row.value("account_id").toString();
        QString account = accountID;
        for (const auto &candidate : snapshot.value("accounts").toArray()) {
            const auto record = candidate.toObject();
            if (record.value("id").toString() == accountID) {
                account = text(record, "label") + " (" + record.value("identity").toObject().value("provider").toString() + ")";
                break;
            }
        }
        row.insert("provider", account + " (observation)");
        rows.append(row);
    }
    return rows;
}

bool nativeHex(const QJsonValue &value) {
    if (!value.isString() || value.toString().size() != 64) return false;
    for (const auto character : value.toString())
        if (!(character >= QChar('0') && character <= QChar('9'))
            && !(character >= QChar('a') && character <= QChar('f'))) return false;
    return value.toString() != QString(64, '0');
}

bool nativeGeneration(const QJsonValue &value) {
    if (!value.isString()) return false;
    const auto decimal = value.toString();
    if (decimal.isEmpty() || decimal.size() > 20 || decimal.front() == QChar('0')) return false;
    for (const auto character : decimal)
        if (character < QChar('0') || character > QChar('9')) return false;
    bool valid = false;
    const auto generation = decimal.toULongLong(&valid);
    return valid && generation != 0;
}

bool nativeReference(const QJsonValue &value, const QJsonObject &row) {
    if (!value.isObject()) return false;
    const auto reference = value.toObject();
    if (reference.value("owner_id") != row.value("owner_id")) return false;
    for (const auto *field : {"adapter_epoch", "endpoint_generation", "thread_instance_generation", "attachment_generation"})
        if (!nativeGeneration(reference.value(field))) return false;
    return reference.value("endpoint_generation") == row.value("endpoint_generation")
        && reference.value("thread_instance_generation") == row.value("thread_instance_generation")
        && reference.value("attachment_generation") == row.value("attachment_generation");
}

QString integrationPath(const QString &adapter) {
    if (adapter == "git") return qEnvironmentVariable("GIT_CONFIG_GLOBAL", QDir::homePath() + "/.gitconfig");
    if (adapter == "codex") return qEnvironmentVariable("CODEX_HOME", QDir::homePath() + "/.codex") + "/config.toml";
    if (adapter == "claude") return qEnvironmentVariable("CLAUDE_CONFIG_DIR", QDir::homePath() + "/.claude") + "/settings.json";
    return {};
}

QJsonArray integrationRows(const QJsonObject &result) {
    if (result.value("integrations").isArray()) return result.value("integrations").toArray();
    QJsonArray rows;
    const auto installed = result.value("installed").toArray();
    for (const auto &value : result.value("adapters").toArray()) {
        auto adapter = value.toObject();
        const auto id = adapter.value("id").toString();
        adapter.insert("adapter", id);
        adapter.insert("installed", installed.contains(QJsonValue(id)));
        QStringList capabilities, limitations;
        for (const auto &capability : adapter.value("capabilities").toArray()) {
            const auto item = capability.toObject();
            capabilities.append(item.value("name").toString() + " (" + item.value("proof").toString() + ")");
            limitations.append(item.value("name").toString() + ": " + item.value("limitation").toString());
        }
        adapter.insert("capability", capabilities.join("; "));
        adapter.insert("limitation", limitations.join('\n'));
        rows.append(adapter);
    }
    return rows;
}

QPushButton *button(QHBoxLayout *layout, const QString &label, QObject *owner,
                    std::function<void()> callback) {
    auto *result = new QPushButton(label);
    layout->addWidget(result);
    QObject::connect(result, &QPushButton::clicked, owner, std::move(callback));
    return result;
}

QWidget *page(QTableWidget *table, QHBoxLayout **actions) {
    auto *result = new QWidget;
    auto *layout = new QVBoxLayout(result);
    layout->addWidget(table);
    *actions = new QHBoxLayout;
    layout->addLayout(*actions);
    return result;
}
} // namespace

OmuxTray::OmuxTray(QString socketPath, bool startConnections, bool explicitSocket)
    : client_(std::move(socketPath), this), tray_(this), explicitSocket_(explicitSocket) {
    setWindowTitle("Omux account and route controls");
    const auto instance = qEnvironmentVariable("OMUX_INSTANCE", "default");
    setWindowTitle("Omux — " + instance + " account and route controls");
    resize(980, 540);
    auto *layout = new QVBoxLayout(this);
    auto *top = new QHBoxLayout;
    connection_ = new QLabel("Connecting…");
    connection_->setWordWrap(true);
    top->addWidget(connection_, 1);
    button(top, "Reconnect", this, [this] { client_.connectToDaemon(); refresh(); });
    button(top, "Refresh", this, [this] { refresh(); });
    layout->addLayout(top);
    message_ = new QLabel;
    message_->setWordWrap(true);
    message_->setTextFormat(Qt::PlainText);
    layout->addWidget(message_);
    policy_ = new QLabel("Routes stay with a compatible account; alternatives are kept ready.");
    policy_->setWordWrap(true);
    layout->addWidget(policy_);

    auto *tabs = new QTabWidget;
    layout->addWidget(tabs);
    QHBoxLayout *actions;
    const auto mutationButton = [this](QHBoxLayout *target, const QString &title,
                                      std::function<void()> callback) {
        auto *control = button(target, title, this, std::move(callback));
        control->setEnabled(false);
        mutationControls_.append(control);
        return control;
    };
    readiness_ = makeTable({"Requirement", "State", "Next action"});
    readiness_->setObjectName("setupReadiness");
    auto *setupPage = page(readiness_, &actions);
    setupNotice_ = new QLabel("Readiness has not been queried. Installation, service activation, custody, source connection, verified identity, usable authority and native capability are separate requirements.");
    setupNotice_->setObjectName("setupNotice");
    setupNotice_->setWordWrap(true);
    setupNotice_->setTextFormat(Qt::PlainText);
    static_cast<QVBoxLayout *>(setupPage->layout())->insertWidget(0, setupNotice_);
    button(actions, "Check setup", this, [this] { refreshReadiness(); });
    button(actions, "Resume after vault unlock", this, [this] {
        if (!client_.ready()) { setupNotice_->setText("Connect to the service first."); return; }
        if (!client_.supportsCustodyReopen()) { setupNotice_->setText("This installed service requires an update before it can resume custody without restarting."); return; }
        if (client_.hasUncertainOperations()) { setupNotice_->setText(client_.uncertaintyMessage()); return; }
        client_.request("custody.reopen", {}, [this](const QJsonObject &result, const QString &error) {
            if (!error.isEmpty()) {
                custodyAvailable_ = false;
                updateMutationControls();
                if (error == "Locked" || error == "VaultLocked" || error == "CustodyLocked")
                    setupNotice_->setText("Custody could not be reopened. Check the normal OS Secret Service vault and unlock it through your desktop if needed, then choose Resume after vault unlock. Existing encrypted account data remains preserved; enrollment is still unavailable. This refusal does not establish the current OS vault lock state.");
                else if (error == "Missing" || error == "InvalidKey")
                    setupNotice_->setText("The existing vault key is missing or invalid. Existing encrypted account data remains preserved; enrollment is unavailable. Repair access to the original key before resuming custody. A replacement key cannot open these accounts.");
                else
                    setupNotice_->setText("Custody could not be verified. Existing encrypted account data remains preserved; enrollment is unavailable. Restore access to the normal platform vault or service, then explicitly resume custody. The current OS vault lock state is unverified.");
                setupNotice_->setProperty("custodyFeedback", setupNotice_->text());
                return;
            }
            if (!reopenedCustody(result)) {
                custodyAvailable_ = false;
                updateMutationControls();
                setupNotice_->setText("The service returned an unverified custody result. Account enrollment remains unavailable until compatible custody and loaded-metadata evidence is available. Existing encrypted account data remains preserved.");
                setupNotice_->setProperty("custodyFeedback", setupNotice_->text());
                return;
            }
            setupNotice_->setProperty("custodyFeedback", QVariant());
            setupNotice_->setText("Custody is ready. Source connection, verified identity and usable authority are separate enrollment steps.");
            refresh();
            refreshReadiness();
        });
    });
    setupVerify_ = button(actions, "Verify setup", this, [this] {
        if (!client_.ready() || client_.hasUncertainOperations()) return;
        client_.request("setup.refresh", {{"operation_id", QUuid::createUuid().toString(QUuid::WithoutBraces)}},
            [this](const QJsonObject &result, const QString &error) {
                setupNotice_->setText(!error.isEmpty() ? (client_.hasUncertainOperations() ? client_.uncertaintyMessage() : error)
                    : client_.hasUncertainOperations()
                        ? "Local verification is pending or unresolved. Its operation identity is retained and queried without repeating the check. Readiness outcomes remain independent."
                        : result.value("outcome").toString() == "safe_refusal"
                            ? "Local verification was safely refused: " + result.value("refusal").toString() + ". Inspect readiness for the next action."
                        : "Local verification reached a terminal outcome. Inspect readiness; this does not prove installation, enrollment or handoff success.");
                updateMutationControls();
                refreshReadiness();
            });
        updateMutationControls();
    });
    setupVerify_->setEnabled(false);
    actions->addStretch();
    tabs->addTab(setupPage, "Setup");
    accounts_ = makeTable({"Account", "Provider", "Type", "Lifecycle", "ID"});
    tabs->addTab(page(accounts_, &actions), "Accounts");
    mutationButton(actions, "Repair", [this] { accountAction("repair.start"); });
    mutationButton(actions, "Pause", [this] { accountAction("account.pause"); });
    mutationButton(actions, "Resume", [this] { accountAction("account.resume"); });
    mutationButton(actions, "Drain", [this] { accountAction("account.drain"); });
    mutationButton(actions, "Forget…", [this] { accountAction("account.forget"); });
    actions->addStretch();

    sources_ = makeTable({"Source", "Provider", "Kind", "State", "ID"});
    auto *sourcePage = page(sources_, &actions);
    sourceNotice_ = new QLabel("Connect an existing source, or sign in to a new Codex account using the separately qualified acquisition component.");
    sourceNotice_->setWordWrap(true);
    static_cast<QVBoxLayout *>(sourcePage->layout())->insertWidget(1, sourceNotice_);
    sourceAcquisitionNotice_ = new QLabel("New-account sign-in needs a separately qualified acquisition component and available OS credential custody.");
    sourceAcquisitionNotice_->setObjectName("codexAccountAcquisitionStatus");
    sourceAcquisitionNotice_->setWordWrap(true);
    sourceAcquisitionNotice_->setTextFormat(Qt::PlainText);
    static_cast<QVBoxLayout *>(sourcePage->layout())->insertWidget(2,sourceAcquisitionNotice_);
    tabs->addTab(sourcePage, "Sources");
    mutationButton(actions, "Connect source…", [this] { connectSource(); });
    sourceSignIn_ = mutationButton(actions, "Sign in to a Codex account…", [this] {
        acquisition_->start(custodyAvailable_);
    });
    sourceSignIn_->setObjectName("codexAccountSignIn");
    button(actions, "Cancel sign-in observation", this, [this] { acquisition_->cancel(); })->setObjectName("codexAccountCancel");
    sourceEnroll_ = mutationButton(actions, "Enroll from source", [this] { enroll(); });
    sourceReconcile_ = mutationButton(actions, "Reconcile", [this] { sourceAction("source.reconcile"); });
    sourceDisconnect_ = mutationButton(actions, "Disconnect", [this] { sourceAction("source.disconnect"); });
    connect(sources_, &QTableWidget::itemSelectionChanged, this, [this] { updateMutationControls(); });
    actions->addStretch();

    grants_ = makeTable({"Account", "Credential type", "Renewal owner", "Purposes", "Audience", "Provider validity", "Custody validity", "Generation"});
    tabs->addTab(page(grants_, &actions), "Grants");
    actions->addWidget(new QLabel("Authorization metadata only. Provider validity and custody authorization are independent."));

    capacity_ = makeTable({"Provider", "Resource", "Scope", "Remaining", "Unit", "Window", "Freshness"});
    tabs->addTab(page(capacity_, &actions), "Capacity");
    auto *capacityNote = new QLabel("Per-account observations remain separate from compatible totals. Percentages and provider decisions are not additive quotas; unknown or stale values stay explicit.");
    capacityNote->setWordWrap(true);
    actions->addWidget(capacityNote);

    bindings_ = makeTable({"Application", "Session", "Account", "In flight", "ID"});
    tabs->addTab(page(bindings_, &actions), "Active routes");
    actions->addWidget(new QLabel("Native application history stays with the application."));

    leases_ = makeTable({"Route", "Account", "Purpose", "Started", "Expires", "Generation"});
    tabs->addTab(page(leases_, &actions), "Leases");
    actions->addWidget(new QLabel("Leases authorize bounded use; they do not extend provider credentials."));

    operations_ = makeTable({"Action", "Status", "Account", "ID"});
    tabs->addTab(page(operations_, &actions), "Actions");
    mutationButton(actions, "Cancel action", [this] {
        const QString id = selectedID(operations_);
        if (!id.isEmpty()) action("operation.cancel", {{"target_operation_id", id}});
    });
    actions->addStretch();

    integrations_ = makeTable({"Application", "Installed", "Capability", "Version", "ID"});
    auto *integrationPage = page(integrations_, &actions);
    nativeThreads_ = makeTable({"Native thread", "Process", "Version", "Hook compatibility"});
    static_cast<QVBoxLayout *>(integrationPage->layout())->insertWidget(1, nativeThreads_);
    tabs->addTab(integrationPage, "Integrations");
    button(actions, "Discover Codex", this, [this] { discoverNative(); });
    mutationButton(actions, "Attach selected thread", [this] { nativeAction("integrations.attach"); })->setObjectName("nativeAttach");
    mutationButton(actions, "Detach selected thread", [this] { nativeAction("integrations.detach"); })->setObjectName("nativeDetach");
    connect(nativeThreads_->selectionModel(), &QItemSelectionModel::selectionChanged, this,
        [this] { updateMutationControls(); });
    mutationButton(actions, "Install integration…", [this] { integrationAction("integrations.install"); });
    mutationButton(actions, "Remove integration", [this] { integrationAction("integrations.remove"); });
    actions->addStretch();

    auto *servicePage = new QWidget;
    auto *serviceLayout = new QVBoxLayout(servicePage);
    service_ = new QLabel("The user service runs independently of these controls.");
    service_->setWordWrap(true);
    service_->setTextFormat(Qt::PlainText);
    serviceLayout->addWidget(service_);
    auto *serviceButtons = new QHBoxLayout;
    button(serviceButtons, "Start service", this, [this] { serviceAction("start"); });
    button(serviceButtons, "Login setup guidance", this, [this] {
        service_->setText("Managed needs change: set programs.omux.enable in Home Manager and activate the reviewed generation. Omux controls do not overwrite managed service definitions or browser registrations.");
    });
    serviceButtons->addStretch();
    serviceLayout->addLayout(serviceButtons);
    auto *serviceNote = new QLabel("Home Manager owns packages, login activation and browser host registration. Start uses the already installed unit. Quitting controls leaves the daemon running. Removal and source disconnect are separate operations.");
    serviceNote->setWordWrap(true);
    serviceLayout->addWidget(serviceNote);
    serviceLayout->addStretch();
    tabs->addTab(servicePage, "Service");

    auto *policyActions = new QHBoxLayout;
    mutationButton(policyActions, "Keep alternatives ready", [this] {
        action("policy.set", {{"sticky_routes", true}, {"warm_alternatives", true}});
    });
    mutationButton(policyActions, "Pause preparation", [this] {
        action("policy.set", {{"sticky_routes", true}, {"warm_alternatives", false}});
    });
    policyActions->addStretch();
    layout->addLayout(policyActions);

    const bool trayAvailable = QSystemTrayIcon::isSystemTrayAvailable();
    QApplication::setQuitOnLastWindowClosed(!trayAvailable);
    if (trayAvailable) {
        tray_.setIcon(style()->standardIcon(QStyle::SP_DriveNetIcon));
        tray_.setToolTip("Omux: connecting");
        auto *menu = new QMenu(this);
        menu->addAction("Accounts and routes…", this, [this] { show(); raise(); activateWindow(); });
        menu->addAction("Refresh", this, [this] { refresh(); });
        menu->addSeparator();
        menu->addAction("Quit controls", qApp, &QApplication::quit);
        tray_.setContextMenu(menu);
        connect(&tray_, &QSystemTrayIcon::activated, this,
            [this](QSystemTrayIcon::ActivationReason reason) {
                if (reason == QSystemTrayIcon::Trigger || reason == QSystemTrayIcon::DoubleClick) {
                    show(); raise(); activateWindow();
                }
            });
        tray_.show();
    }
    client_.onConnection = [this](bool connected, const QString &message) {
        const bool changed = connected_ != connected;
        connected_ = connected;
        connection_->setText(message);
        tray_.setToolTip(connected ? "Omux: connected" : "Omux: service unavailable");
        if (!connected) {
            setupVerify_->setEnabled(false);
            setupNotice_->setText("Service unavailable. Displayed readiness may be stale; connection failure does not establish whether packages or browser registration are installed.");
            custodyAvailable_ = false;
            for (auto *control : mutationControls_) control->setEnabled(false);
            message_->setText((client_.hasUncertainOperations() ? client_.uncertaintyMessage() + "\n" : QString())
                + "Displayed account data may be stale until the service reconnects.");
            fillTable(capacity_, capacityRows(capacityDisplayRows(snapshot_), false),
                {"provider", "resource.target", "resource.scope", "remaining", "resource.unit", "window", "freshness"});
            if (changed && tray_.isVisible())
                tray_.showMessage("Omux service unavailable", "Accounts and routes will refresh after reconnection.");
        } else {
            refresh();
        }
    };
    acquisition_ = std::make_unique<CodexAccountAcquisition>(client_,this);
    acquisition_->onStatus = [this](const QString &message) { sourceAcquisitionNotice_->setText(message); };
    acquisition_->onChanged = [this] { updateMutationControls(); refresh(); };
    acquisition_->onSourceConnected = [this](const QString &id) { acquisitionSourceSelection_=id; };
    client_.onEvent = [this](const QJsonObject &event) {
        if (acquisition_->operationEvent(event)) { updateMutationControls(); refresh(); return; }
        const auto status = event.value("operation_status").toString();
        if (event.value("operation_kind").toString() == "setup_verification") {
            const auto terminal = event.value("operation_result").toObject();
            message_->setText(status == "indeterminate"
                ? "Setup verification outcome is indeterminate. Retain its operation identity; another check is disabled."
                : terminal.value("outcome").toString() == "safe_refusal"
                    ? "Local setup verification was safely refused: " + terminal.value("refusal").toString() + ". Inspect readiness for the next action."
                : "Local setup verification completed. Inspect seven readiness outcomes; completion does not prove installation, enrollment or seamless handoff.");
            updateMutationControls();
            refresh();
            return;
        }
        if (status == "completed" || status == "not_found") {
            message_->setText(event.value("operation_error").toString() + "\n" +
                (status == "completed" ? "The previous action outcome was recovered; account state will refresh."
                                       : "No committed operation was found; another action may be requested."));
        }
        refresh();
    };
    refreshTimer_.setInterval(3000);
    connect(&refreshTimer_, &QTimer::timeout, this, [this] { refresh(); });
    if (startConnections) {
        refreshTimer_.start();
        client_.connectToDaemon();
        serviceAction("show");
    } else {
        connection_->setText("Offline client self-check");
    }
}

QTableWidget *OmuxTray::makeTable(const QStringList &columns) {
    auto *table = new QTableWidget(0, columns.size());
    table->setHorizontalHeaderLabels(columns);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->verticalHeader()->hide();
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    table->horizontalHeader()->setStretchLastSection(true);
    return table;
}

QString OmuxTray::selectedID(QTableWidget *table) const {
    const auto selection = table->selectionModel()->selectedRows();
    if (selection.isEmpty()) return {};
    const auto *item = table->item(selection.first().row(), 0);
    return item ? item->data(Qt::UserRole).toString() : QString();
}

void OmuxTray::fillTable(QTableWidget *table, const QJsonArray &array,
                        const QStringList &fields) {
    const QString previous = selectedID(table);
    // A removed source must not silently select the next row at its old index.
    if (table == sources_) table->clearSelection();
    table->setRowCount(array.size());
    for (qsizetype row = 0; row < array.size(); ++row) {
        const auto object = array[row].toObject();
        for (qsizetype column = 0; column < fields.size(); ++column) {
            const QString value = text(object, fields[column]);
            auto *item = new QTableWidgetItem(fields[column] == "account_id"
                ? accountLabels_.value(value, value) : value);
            if (fields[column] == "capability") item->setToolTip(object.value("limitation").toString());
            if (column == 0) {
                item->setData(Qt::UserRole, object.value("id").toString());
                if (table == nativeThreads_) item->setData(Qt::UserRole + 1, QVariant::fromValue(object));
            }
            table->setItem(row, column, item);
        }
        if (!previous.isEmpty() && object.value("id").toString() == previous)
            table->selectRow(row);
    }
}

void OmuxTray::refresh() {
    if (!client_.ready() || refreshing_) return;
    refreshing_ = true;
    client_.request("state.snapshot", {}, [this](const QJsonObject &result, const QString &error) {
        refreshing_ = false;
        if (!error.isEmpty()) { message_->setText((client_.hasUncertainOperations() ? client_.uncertaintyMessage() + "\n" : QString()) + error); return; }
        applySnapshot(result);
        refreshReadiness();
    });
}

void OmuxTray::refreshReadiness() {
    if (!client_.ready()) {
        setupNotice_->setText("Connect to the selected daemon to query readiness. Home Manager owns installation; these controls never rewrite managed files.");
        return;
    }
    client_.request("setup.readiness", {}, [this](const QJsonObject &result, const QString &error) {
        const auto custodyFeedback = setupNotice_->property("custodyFeedback").toString();
        if (!error.isEmpty()) {
            setupNotice_->setText("Shared setup readiness unavailable. No installation or continuity claim can be inferred from this connection. " + error);
            if (!custodyFeedback.isEmpty()) setupNotice_->setText(setupNotice_->text() + "\n" + custodyFeedback);
            return;
        }
        QJsonArray rows;
        QSet<QString> seen;
        bool valid = true;
        bool allReady = true;
        const QHash<QString, QString> phases {{"artifact", "Installed artifacts"}, {"service", "Service activation"},
            {"vault", "Credential custody"}, {"source", "Source connection"}, {"identity", "Verified identity"},
            {"grant", "Usable authority"}, {"native", "Native application capability"}};
        for (const auto &value : result.value("findings").toArray()) {
            const auto finding = value.toObject();
            const auto phase = finding.value("phase").toString();
            if (!phases.contains(phase) || seen.contains(phase)
                || !finding.value("reason").isString() || finding.value("reason").toString().isEmpty()
                || !finding.value("action").isString() || finding.value("action").toString().isEmpty()) valid = false;
            seen.insert(phase);
            allReady = allReady && finding.value("reason").toString() == "ready";
            rows.append(QJsonObject{{"requirement", phases.value(phase, phase)},
                {"state", finding.value("reason")}, {"next_action", finding.value("action")}});
        }
        fillTable(readiness_, rows, {"requirement", "state", "next_action"});
        if (!valid || result.value("schema_version").toInt() != 1 || rows.size() != 7
            || !result.value("ready").isBool() || result.value("ready").toBool() != allReady
            || !result.value("seamless_handoff_proven").isBool()
            || result.value("seamless_handoff_proven").toBool(true)) {
            setupNotice_->setText("The daemon returned an unsupported readiness report. Requirements remain unknown until a compatible report is available.");
            if (!custodyFeedback.isEmpty()) setupNotice_->setText(setupNotice_->text() + "\n" + custodyFeedback);
            readiness_->setRowCount(0);
            return;
        }
        if (!custodyFeedback.isEmpty()) {
            setupNotice_->setText(custodyFeedback);
            return;
        }
        setupNotice_->setText(result.value("ready").toBool(false)
            ? "Setup requirements are ready. Seamless handoff remains a separate version-bound proof. Home Manager owns installation changes."
            : "Setup needs attention. Follow each reported action; Home Manager owns packages, service definitions and browser registration. These controls do not overwrite managed files.");
    });
}

void OmuxTray::applySnapshot(const QJsonObject &snapshot) {
    snapshot_ = snapshot;
    custodyAvailable_ = snapshot.value("custody_available").toBool(false)
        && setupNotice_->property("custodyFeedback").toString().isEmpty();
    acquisition_->observe(snapshot);
    updateMutationControls();
    connection_->setText(custodyAvailable_ ? "Connected" : "Connected; credential custody unavailable");
    accountLabels_.clear();
    for (const auto &value : snapshot.value("accounts").toArray()) {
        const auto record = value.toObject();
        const auto provider = record.value("identity").toObject().value("provider").toString();
        accountLabels_.insert(record.value("id").toString(), text(record, "label")
            + (provider.isEmpty() ? QString() : " (" + provider + ")"));
    }
    const qint64 revision = snapshot.value("revision").toInteger();
    if (revision_ >= 0 && revision != revision_ && !client_.hasUncertainOperations()) message_->clear();
    revision_ = revision;
    if (!custodyAvailable_)
        message_->setText("Credential custody is unavailable. Account data may be stale; account and routing changes are disabled until custody is restored.");
    else if (message_->text().startsWith("Credential custody is unavailable.")
             || message_->text().startsWith("Displayed account data may be stale"))
        message_->clear();
    if (client_.hasUncertainOperations()) message_->setText(client_.uncertaintyMessage()
        + (custodyAvailable_ ? QString() : "\nCredential custody is unavailable; the action outcome cannot be resolved."));
    fillTable(accounts_, snapshot.value("accounts").toArray(), {"label", "identity.provider", "account_type", "lifecycle", "id"});
    fillTable(sources_, snapshot.value("sources").toArray(), {"label", "provider", "kind", "status", "id"});
    if (!acquisitionSourceSelection_.isEmpty()) {
        for (int row=0;row<sources_->rowCount();++row)
            if (sources_->item(row,4) && sources_->item(row,4)->text()==acquisitionSourceSelection_) {
                sources_->selectRow(row); acquisitionSourceSelection_.clear(); break;
            }
    }
    updateMutationControls();
    fillTable(grants_, snapshot.value("grants").toArray(), {"account_id", "credential_kind", "ownership", "purposes", "audience", "provider_expires_at", "custody_expires_at", "generation"});
    fillTable(capacity_, capacityRows(capacityDisplayRows(snapshot), connected_ && custodyAvailable_),
              {"provider", "resource.target", "resource.scope", "remaining", "resource.unit", "window", "freshness"});
    fillTable(bindings_, snapshot.value("bindings").toArray(), {"application", "session_id", "account_id", "in_flight", "id"});
    fillTable(leases_, snapshot.value("leases").toArray(), {"binding_id", "account_id", "purpose", "started_at", "expires_at", "route_generation"});
    fillTable(operations_, snapshot.value("jobs").toArray(), {"kind", "status", "account_id", "id"});
    const auto policy = snapshot.value("policy").toObject();
    policy_->setText(policy.value("warm_alternatives").toBool(true)
        ? "All compatible accounts are eligible. Routes stay sticky; alternatives are kept ready."
        : "All compatible accounts are eligible. Routes stay sticky; alternative preparation is paused.");
    client_.request("integrations.status", {}, [this](const QJsonObject &result, const QString &error) {
        if (error.isEmpty()) {
            integrationPaths_.clear();
            const auto integrations = integrationRows(result);
            for (const auto &value : integrations) {
                const auto record = value.toObject();
                integrationPaths_.insert(record.value("adapter").toString(), record.value("config_path").toString());
            }
            fillTable(integrations_, integrations,
                      {"adapter", "installed", "capability", "version", "id"});
        } else {
            message_->setText((client_.hasUncertainOperations() ? client_.uncertaintyMessage() + "\n" : QString())
                + "Integration status is unavailable. Displayed capabilities may be stale.");
        }
    });
}

void OmuxTray::action(const QString &method, QJsonObject params) {
    if (!connected_ || !custodyAvailable_) {
        message_->setText(!connected_ ? "The service is disconnected. Reconnect before requesting an action."
            : "Credential custody is unavailable. Restore custody before changing accounts or routes.");
        return;
    }
    message_->setText("Requesting action…");
    if (method == "integrations.attach" || method == "integrations.detach"
        || (method == "integrations.remove" && params.value("adapter").toString("codex") == "codex")) {
        params.insert("operation_id", (QUuid::createUuid().toString(QUuid::WithoutBraces)
            + QUuid::createUuid().toString(QUuid::WithoutBraces)).remove('-').toLower());
    }
    client_.request(method, std::move(params), [this](const QJsonObject &result, const QString &error) {
        if (!error.isEmpty()) {
            message_->setText(client_.hasUncertainOperations() ? client_.uncertaintyMessage() : error);
            updateMutationControls();
            return;
        }
        const QString status = result.value("status").toString();
        message_->setText(result.value("message").toString(
            status == "verifying_identity" ? "Source verification is pending. Inspect Actions for its outcome."
            : status == "removal_pending" || status == "pending_removal" ? "Removal is pending while accepted work drains. Native application history remains in place; refresh status before repeating removal."
            : status == "reconciled" ? "Source reconciliation completed. Account state will refresh."
            : "Action accepted; account state will refresh."));
        // Only a provider HTTPS enrollment link may leave the local control plane.
        const QUrl url(result.value("authorization_url").toString());
        if (url.isValid() && url.scheme() == "https" && !url.host().isEmpty())
            QDesktopServices::openUrl(url);
        refresh();
    });
}

void OmuxTray::accountAction(const QString &method) {
    const QString id = selectedID(accounts_);
    if (id.isEmpty()) { message_->setText("Select an account first."); return; }
    if (method == "account.forget" && QMessageBox::question(this, "Forget account?",
        "Remove retained grants and account history? Automatic discovery will not enroll this account again.") != QMessageBox::Yes)
        return;
    action(method, {{"account_id", id}});
}

void OmuxTray::sourceAction(const QString &method) {
    const QString id = selectedSource().value("id").toString();
    if (id.isEmpty()) { message_->setText("Select a source first."); return; }
    if (method == "source.reconcile" && !sourceReconcileIssue().isEmpty()) {
        message_->setText(sourceReconcileIssue()); return;
    }
    if (method == "source.disconnect" && QMessageBox::question(this, "Disconnect selected source context?",
        "End acquisition authorization for this selected source context and remove secrets retained through it? Independently authorized grants and native application history keep their own lifecycle. Pending work must drain before removal completes.") != QMessageBox::Yes) return;
    action(method, {{"source_id", id}});
}

QJsonObject OmuxTray::selectedSource() const {
    const QString id = selectedID(sources_);
    if (!id.isEmpty()) for (const auto &value : snapshot_.value("sources").toArray()) {
        const auto row = value.toObject();
        if (row.value("id").toString() == id) return row;
    }
    return {};
}

QString OmuxTray::sourceReconcileIssue(bool forEnrollment) const {
    const auto source = selectedSource();
    if (source.isEmpty()) return "Select a source. Enrollment requires a connected source; Reconcile can recheck a detached source.";
    const auto status = source.value("status").toString();
    if (status == "disconnected") return "This source is disconnected. Its acquisition authorization has ended.";
    if (status != "connected" && status != "detached") return "This source's state is unavailable. Refresh before requesting reconciliation.";
    if (forEnrollment && status != "connected") return "Enrollment requires a connected source. Reconcile can recheck this detached source's authorized file.";
    const auto kind = source.value("kind").toString();
    if (kind != "native_store" && kind != "explicit") return "Browser and OAuth source acquisition are unavailable. This source cannot enroll accounts here.";
    const auto provider = source.value("provider").toString();
    if (provider != "codex" && provider != "github") return "This source's provider requires an acquisition adapter before accounts can be enrolled.";
    return {};
}

void OmuxTray::updateMutationControls() {
    setupVerify_->setEnabled(connected_ && !client_.hasUncertainOperations());
    const bool allowed = connected_ && custodyAvailable_ && !client_.hasUncertainOperations() && (!acquisition_ || !acquisition_->busy());
    if (auto *cancel = findChild<QPushButton *>("codexAccountCancel")) cancel->setEnabled(acquisition_ && acquisition_->busy());
    for (auto *control : mutationControls_) control->setEnabled(allowed);
    const auto selected = nativeThreads_->selectionModel()->selectedRows();
    const auto *nativeItem = selected.isEmpty() ? nullptr : nativeThreads_->item(selected.first().row(), 0);
    const auto native = nativeItem ? nativeItem->data(Qt::UserRole + 1).value<QJsonObject>() : QJsonObject();
    const bool compatible = native.value("support").toString() == "compatible_hook";
    if (auto *attach = findChild<QPushButton *>("nativeAttach")) attach->setEnabled(allowed && compatible);
    if (auto *detach = findChild<QPushButton *>("nativeDetach"))
        detach->setEnabled(allowed && compatible && nativeReference(native.value("native_ref"), native));
    const QString issue = sourceReconcileIssue();
    sourceEnroll_->setEnabled(allowed && sourceReconcileIssue(true).isEmpty());
    sourceReconcile_->setEnabled(allowed && issue.isEmpty());
    const auto source = selectedSource();
    sourceDisconnect_->setEnabled(allowed && !source.isEmpty() && source.value("status").toString() != "disconnected");
    sourceNotice_->setText(!issue.isEmpty() ? issue
        : source.value("status").toString() == "detached"
            ? "This source is detached. Reconcile rechecks its authorized file and may reconnect it when available. Enrollment requires a connected source. The daemon validates acquisition authorization."
            : "Enroll from source requests identity verification for " + source.value("provider").toString()
                + " using this connected source. Sign in creates a separate private Codex context without asking for profile paths. The daemon independently verifies identity and grant authority.");
}

void OmuxTray::connectSource() {
    QDialog dialog(this);
    dialog.setWindowTitle("Connect an account source");
    auto *form = new QFormLayout(&dialog);
    QComboBox kind; kind.addItem("Native application store", "native_store");
    QComboBox provider; provider.addItems({"codex", "github"});
    QLineEdit label;
    QLineEdit sourcePath;
    sourcePath.setPlaceholderText("Absolute file path; Codex may use its native default");
    form->addRow("Source type", &kind); form->addRow("Provider", &provider);
    form->addRow("Name", &label);
    form->addRow("Native source file", &sourcePath);
    auto *notice = new QLabel("Connect authorizes an existing native source; it does not sign in or verify an account. Browser and OAuth source acquisition are unavailable. Account enrollment requires source reconciliation and identity verification.");
    notice->setWordWrap(true); form->addRow(notice);
    auto *pathNotice = new QLabel("GitHub requires an explicit source file. Leaving the Codex path blank authorizes the daemon's native Codex source. The controls do not read or search source files.");
    pathNotice->setWordWrap(true); form->addRow(pathNotice);
    QDialogButtonBox buttons(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    form->addRow(&buttons);
    const auto updateConnect = [&] {
        const QString path = sourcePath.text().trimmed();
        bool pathValid = path.isEmpty() ? provider.currentText() == "codex"
            : path.startsWith('/') && path.size() > 1 && !path.contains(QChar('\0'));
        if (!path.isEmpty()) for (const auto &part : path.mid(1).split('/'))
            if (part.isEmpty() || part == "." || part == "..") pathValid = false;
        buttons.button(QDialogButtonBox::Ok)->setEnabled(pathValid && connected_ && custodyAvailable_
            && !client_.hasUncertainOperations());
    };
    connect(&provider, &QComboBox::currentTextChanged, &dialog, updateConnect);
    connect(&sourcePath, &QLineEdit::textChanged, &dialog, updateConnect);
    updateConnect();
    connect(&buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(&buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    if (dialog.exec() == QDialog::Accepted) {
        const QString name = label.text().trimmed().isEmpty()
            ? provider.currentText() + " " + kind.currentData().toString() : label.text().trimmed();
        QJsonObject params {{"kind", kind.currentData().toString()},
                            {"provider", provider.currentText()}, {"label", name}};
        const QString path = sourcePath.text().trimmed();
        if (!path.isEmpty()) params.insert("source_path", path);
        action("source.connect", params);
    }
}

void OmuxTray::enroll() {
    const QString issue = sourceReconcileIssue(true);
    if (!issue.isEmpty()) { message_->setText(issue); return; }
    const auto source = selectedSource();
    action("enrollment.start", {{"source_id", source.value("id").toString()},
                                {"provider", source.value("provider").toString()}});
}

void OmuxTray::integrationAction(const QString &method) {
    QString adapter;
    if (method == "integrations.remove") {
        const auto selected = integrations_->selectionModel()->selectedRows();
        if (selected.isEmpty()) { message_->setText("Select an integration first."); return; }
        adapter = integrations_->item(selected.first().row(), 0)->text();
    } else {
        bool accepted;
        adapter = QInputDialog::getItem(this, "Install native integration", "Application",
                                       {"codex", "claude", "git"}, 0, false, &accepted);
        if (!accepted) return;
    }
    QString path = integrationPaths_.value(adapter);
    if (path.isEmpty()) path = integrationPath(adapter);
    if (method == "integrations.install") {
        bool accepted;
        path = QInputDialog::getText(this, "Native integration configuration",
            "Configuration file", QLineEdit::Normal, path, &accepted);
        if (!accepted) return;
    }
    action(method, {{"adapter", adapter}, {"config_path", path}});
}

void OmuxTray::discoverNative() {
    nativeSocket_.clear();
    nativeThreads_->clearSelection();
    fillTable(nativeThreads_, {}, {"thread_id", "owner_id", "version", "support"});
    client_.request("integrations.discover", {{"adapter", "codex"}},
        [this](const QJsonObject &result, const QString &error) {
            if (!error.isEmpty()) { message_->setText("Native discovery failed: " + error); return; }
            QJsonArray threads;
            QSet<QString> identities;
            const auto invalid = [this] { message_->setText("Native discovery returned invalid owner metadata. Discover again before acting."); };
            if (!result.value("owners").isArray() || result.value("owners").toArray().size() > 256) { invalid(); return; }
            for (const auto &value : result.value("owners").toArray()) {
                const auto owner = value.toObject();
                const auto endpoint = owner.value("owner_endpoint").toString();
                if (!nativeHex(owner.value("owner_id")) || !nativeHex(owner.value("process_nonce"))
                    || !nativeGeneration(owner.value("endpoint_generation")) || !endpoint.startsWith('/')
                    || endpoint.toUtf8().size() > 107 || endpoint.contains(QChar(0))
                    || !owner.value("native_version").isString() || owner.value("native_version").toString().isEmpty()
                    || owner.value("native_version").toString().toUtf8().size() > 256 || !owner.value("support").isString()
                    || !owner.value("threads").isArray()) { invalid(); return; }
                for (const auto &descriptor : owner.value("threads").toArray()) {
                    const auto thread = descriptor.toObject();
                    const auto threadID = thread.value("thread_id").toString();
                    bool validThread = !threadID.isEmpty() && threadID.toUtf8().size() <= 256;
                    for (const auto character : threadID) if (character.unicode() < 32) validThread = false;
                    if (!validThread
                        || !nativeGeneration(thread.value("thread_instance_generation"))
                        || !nativeGeneration(thread.value("attachment_generation")) || threads.size() >= 1024) { invalid(); return; }
                    auto row = thread;
                    for (const auto *field : {"owner_id", "process_nonce", "endpoint_generation", "owner_endpoint"})
                        row.insert(field, owner.value(field));
                    row.insert("version", owner.value("native_version"));
                    row.insert("support", owner.value("support"));
                    const auto key = QString::fromUtf8(QJsonDocument(QJsonArray{row.value("owner_id"), row.value("process_nonce"),
                        row.value("endpoint_generation"), row.value("thread_instance_generation"), row.value("attachment_generation"),
                        threadID}).toJson(QJsonDocument::Compact));
                    if (identities.contains(key)) { invalid(); return; }
                    identities.insert(key);
                    row.insert("id", key);
                    if (!thread.value("native_ref").isNull() && !thread.value("native_ref").isUndefined()
                        && !nativeReference(thread.value("native_ref"), row)) { invalid(); return; }
                    threads.append(row);
                }
            }
            fillTable(nativeThreads_, threads, {"thread_id", "owner_id", "version", "support"});
            updateMutationControls();
            message_->setText("Hook compatibility is experimental; live continuity remains unproved. Processes: "
                + QString::number(result.value("owners").toArray().size()) + ". Loaded threads: " + QString::number(threads.size()) + ".");
        });
}

void OmuxTray::nativeAction(const QString &method) {
    const auto selected = nativeThreads_->selectionModel()->selectedRows();
    if (selected.isEmpty()) {
        message_->setText("Discover native threads and select one first."); return;
    }
    const auto *item = nativeThreads_->item(selected.first().row(), 0);
    if (!item) { message_->setText("Discover native threads and select one first."); return; }
    const auto row = item->data(Qt::UserRole + 1).value<QJsonObject>();
    if (row.value("support").toString() != "compatible_hook") {
        message_->setText("This native application has no compatible account-broker hook."); return;
    }
    QJsonObject params{{"adapter", "codex"}, {"thread_id", row.value("thread_id")}};
    for (const auto *field : {"owner_endpoint", "owner_id", "process_nonce", "endpoint_generation", "thread_instance_generation"})
        params.insert(field, row.value(field));
    if (method == "integrations.detach") {
        if (!nativeReference(row.value("native_ref"), row)) {
            message_->setText("This thread has no verified committed attachment to detach. Discover again after attachment."); return;
        }
        params.insert("native_ref", row.value("native_ref"));
    }
    action(method, params);
}

void OmuxTray::closeEvent(QCloseEvent *event) {
    if (tray_.isVisible()) { hide(); event->ignore(); }
    else event->accept();
    // Closing controls never sends a shutdown request to the daemon.
}

void OmuxTray::serviceAction(const QString &actionName) {
    // systemd is a host platform service boundary, like SMAppService on macOS.
    // Never search PATH or execute an arbitrary user-provided service manager.
    const QString program = "/usr/bin/systemctl";
    if (!QFileInfo::exists(program)) {
        service_->setText("The host systemd user service manager is unavailable. The Omux daemon can still run independently of these controls.");
        return;
    }
    QStringList arguments {"--user"};
    if (actionName == "show") arguments << "show" << "--property=ActiveState" << "--value";
    else if (actionName == "start") arguments << "start";
    else return;
    const auto instance = qEnvironmentVariable("OMUX_INSTANCE", "default");
    if (instance != "default" && instance != "dev") {
        service_->setText("Unknown instance: service control is unavailable. Select a declared Omux instance.");
        return;
    }
    // Custom sockets may identify another daemon. Never start a guessed unit.
    if (actionName == "start" && (explicitSocket_ || qEnvironmentVariableIsSet("OMUX_SOCKET"))) {
        service_->setText("An explicit socket is selected. Start its declared service through the owning deployment configuration.");
        return;
    }
    arguments << (instance == "dev" ? "ai.xoxd.omux.dev.service" : "ai.xoxd.omux.service");
    auto *process = new QProcess(this);
    auto environment = QProcessEnvironment::systemEnvironment();
    // A portable Qt launcher supplies its own libraries. Host systemctl must
    // resolve the host's ABI and service libraries, independent of that bundle.
    for (const auto *name : {"LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT", "LD_DEBUG", "LD_DEBUG_OUTPUT",
                             "QT_PLUGIN_PATH", "QT_QPA_PLATFORM_PLUGIN_PATH", "QT_QPA_PLATFORM", "QML2_IMPORT_PATH"})
        environment.remove(QString::fromUtf8(name));
    process->setProcessEnvironment(environment);
    auto *deadline = new QTimer(process);
    deadline->setSingleShot(true);
    deadline->setInterval(10000);
    connect(deadline, &QTimer::timeout, process, [process] { process->kill(); });
    connect(process, qOverload<int, QProcess::ExitStatus>(&QProcess::finished), this,
        [this, process, deadline, actionName](int code, QProcess::ExitStatus status) {
            deadline->stop();
            if (code != 0 || status != QProcess::NormalExit) {
                service_->setText("The user service could not be queried or updated. Verify that the packaged user unit is installed and the user service manager is available.");
            } else if (actionName == "show") {
                const QString state = QString::fromUtf8(process->readAllStandardOutput()).trimmed();
                service_->setText("User service: " + (state.isEmpty() ? QString("Unknown") : state));
            } else {
                service_->setText("User service updated.");
                client_.connectToDaemon();
                refresh();
            }
            process->deleteLater();
        });
    connect(process, &QProcess::errorOccurred, this, [this, process](QProcess::ProcessError error) {
        if (error == QProcess::FailedToStart) {
            service_->setText("The host user service manager could not be started.");
            process->deleteLater();
        }
    });
    deadline->start();
    process->start(program, arguments);
}
