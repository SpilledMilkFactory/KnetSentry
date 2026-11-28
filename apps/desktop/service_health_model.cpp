// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "service_health_model.hpp"

#include <QFile>
#include <QRandomGenerator>
#include <QStringList>
#include <unistd.h>

namespace knetsentry::desktop {
namespace {
QString decimal(std::uint64_t value) {
    return QString::number(static_cast<qulonglong>(value));
}
QString measurement(const std::optional<std::uint64_t>& value, const QString& unit) {
    return value ? QObject::tr("%1 %2").arg(decimal(*value), unit) : QObject::tr("Unavailable");
}
} // namespace

ServiceHealthModel::ServiceHealthModel(const QString& directory, QObject* parent)
    : QObject(parent), directory_(QFile::encodeName(directory)) {
    refresh_timer_.setInterval(30000);
    refresh_timer_.setTimerType(Qt::PreciseTimer);
    exchange_timer_.setInterval(25);
    exchange_timer_.setTimerType(Qt::PreciseTimer);
    connect(&refresh_timer_, &QTimer::timeout, this, &ServiceHealthModel::refresh);
    connect(&exchange_timer_, &QTimer::timeout, this, &ServiceHealthModel::advance);
}

void ServiceHealthModel::setDirectory(const QString& directory) {
    refresh_timer_.stop();
    exchange_timer_.stop();
    client_.cancel();
    agent_client_.cancel();
    directory_ = QFile::encodeName(directory);
    Q_EMIT changed();
}

service::HealthQueryState ServiceHealthModel::queryState() const noexcept {
    return client_.state();
}

void ServiceHealthModel::start() {
    if (directory_.isEmpty() || ::geteuid() == 0 || refresh_timer_.isActive()) { return; }
    refresh();
    refresh_timer_.start();
}

void ServiceHealthModel::refresh() {
    if (directory_.isEmpty() || ::geteuid() == 0 || exchange_timer_.isActive()) { return; }
    agent_client_.cancel();
    const auto id = QByteArray::number(QRandomGenerator::system()->generate64(), 16).rightJustified(16, '0');
    client_.begin(std::string_view(directory_.constData(), static_cast<std::size_t>(directory_.size())),
                  std::string_view(id.constData(), static_cast<std::size_t>(id.size())));
    if (client_.state() == service::HealthQueryState::Pending) { exchange_timer_.start(); }
    Q_EMIT changed();
}

void ServiceHealthModel::advance() {
    if (client_.state() == service::HealthQueryState::Pending) {
        client_.advance();
        if (client_.state() == service::HealthQueryState::Pending) { return; }
        if (available()) {
            const auto id = QByteArray::number(QRandomGenerator::system()->generate64(), 16).rightJustified(16, '0');
            agent_client_.begin_agents(std::string_view(directory_.constData(), static_cast<std::size_t>(directory_.size())),
                std::string_view(id.constData(), static_cast<std::size_t>(id.size())));
        }
        if (agent_client_.state() != service::HealthQueryState::Pending) { exchange_timer_.stop(); }
        Q_EMIT changed();
        return;
    }
    agent_client_.advance();
    if (agent_client_.state() != service::HealthQueryState::Pending) {
        exchange_timer_.stop();
        Q_EMIT changed();
    }
}

bool ServiceHealthModel::available() const noexcept {
    return client_.state() == service::HealthQueryState::Available && client_.snapshot().has_value();
}
QString ServiceHealthModel::status() const {
    if (directory_.isEmpty()) { return tr("Not connected — no IPC directory configured"); }
    if (::geteuid() == 0) { return tr("Unavailable — root desktop IPC is disabled"); }
    switch (client_.state()) {
    case service::HealthQueryState::Idle: return tr("Waiting for service health");
    case service::HealthQueryState::Pending: return tr("Checking management daemon…");
    case service::HealthQueryState::Available: return tr("Running — verified health snapshot");
    case service::HealthQueryState::Unavailable: return tr("Disconnected or unavailable");
    case service::HealthQueryState::Invalid: return tr("Unavailable — invalid or incomplete response");
    }
    return tr("Unavailable");
}
QString ServiceHealthModel::components() const {
    if (!available()) { return tr("Daemon component information unavailable."); }
    const auto& snapshot = *client_.snapshot();
    return tr("Configuration: %1\nLocal IPC: ready\nSecurity monitoring: unavailable")
        .arg(snapshot.explicit_config ? tr("Validated file") : tr("Safe defaults"));
}
QString ServiceHealthModel::resources() const {
    if (!available()) { return tr("Uptime, CPU time and memory unavailable."); }
    const auto& snapshot = *client_.snapshot();
    return tr("Uptime: %1 ms\nCumulative CPU time: %2\nPeak resident memory: %3")
        .arg(decimal(snapshot.uptime_ms), measurement(snapshot.usage.cpu_ms, tr("ms")),
             measurement(snapshot.usage.peak_rss_kib, tr("KiB")));
}
QString ServiceHealthModel::errors() const {
    if (!available()) { return tr("Operational error counters unavailable."); }
    const auto& snapshot = *client_.snapshot();
    return tr("Rejected requests: %1\nTransport errors: %2\nSampling errors: %3")
        .arg(decimal(snapshot.rejected), decimal(snapshot.transport_errors), decimal(snapshot.sampling_errors));
}
// The KSIPC/1 HEALTH contract belongs to the lifecycle-only manager. It
// reports configuration validation and IPC readiness, not a policy inventory.
// Never infer approvals from local interfaces, a healthy daemon, or counters.
QString ServiceHealthModel::scopeState() const {
    if (!available()) { return tr("Unavailable — no current verified daemon health"); }
    return tr("Lifecycle only — network authorization not activated.\n"
              "Configuration: %1. Policy revision and firewall state are not reported.")
        .arg(client_.snapshot()->explicit_config ? tr("Validated v1 file") : tr("Safe defaults"));
}
QString ServiceHealthModel::scopeNetworks() const {
    return available()
        ? tr("No operational approvals loaded by the lifecycle-only manager. No network inventory is published.")
        : tr("Unavailable — approved network inventory not reported.");
}
QString ServiceHealthModel::scopeInterfaces() const {
    return available()
        ? tr("No operational interface bindings loaded. Local adapters are not automatically approved.")
        : tr("Unavailable — approved interface inventory not reported.");
}
QString ServiceHealthModel::scopeDenials() const {
    if (!available()) {
        return tr("Network connection denials: unavailable (not collected).\n"
                  "Local IPC rejected requests: unavailable.");
    }
    return tr("Network connection denials: unavailable (not collected).\n"
              "Local IPC rejected requests: %1 (not network denials or incidents).")
        .arg(decimal(client_.snapshot()->rejected));
}
QString ServiceHealthModel::agentRegistryStatus() const {
    if (!available()) { return tr("Unavailable — no current verified daemon health"); }
    if (agent_client_.state() == service::HealthQueryState::Pending) { return tr("Checking enrollment registry…"); }
    if (!agent_client_.roster() || agent_client_.roster()->status != enrollment::Status::Ok) {
        return tr("Unavailable — no readable manager-selected enrollment registry");
    }
    return tr("Verified registry snapshot — %1 endpoint identities (not live sessions)")
        .arg(decimal(agent_client_.roster()->size));
}
QString ServiceHealthModel::dashboardRegistry() const {
    if (!available() || !agent_client_.roster() || agent_client_.roster()->status != enrollment::Status::Ok) {
        return tr("Unavailable — no current verified registry snapshot. Monitored assets unavailable.");
    }
    const auto& roster = *agent_client_.roster();
    std::size_t approved{};
    for (std::size_t i = 0; i < roster.size; ++i) {
        if (roster.entries.at(i).approved) { ++approved; }
    }
    return tr("%1 approved, %2 revoked registry identities (not live sessions).\n"
              "Monitored assets unavailable.")
        .arg(decimal(approved), decimal(roster.size - approved));
}
namespace {
QString roster_text(const service::HealthClient& client, bool approved) {
    if (!client.roster() || client.roster()->status != enrollment::Status::Ok) {
        return QObject::tr("Unavailable — no current registry snapshot.");
    }
    QStringList rows;
    for (std::size_t i = 0; i < client.roster()->size; ++i) {
        const auto& entry = client.roster()->entries.at(i);
        if (entry.approved != approved) { continue; }
        const auto id = QByteArray(reinterpret_cast<const char*>(entry.id.data()),
            static_cast<qsizetype>(entry.id.size())).toHex();
        rows.append(QString::fromLatin1(id.constData(), id.size()));
    }
    return rows.isEmpty() ? QObject::tr("None in the verified registry snapshot.") : rows.join(QLatin1Char('\n'));
}
} // namespace
QString ServiceHealthModel::approvedAgents() const { return roster_text(agent_client_, true); }
QString ServiceHealthModel::revokedAgents() const { return roster_text(agent_client_, false); }
bool ServiceHealthModel::attachTelemetry(int fd) {
    if (::geteuid() == 0) { return false; }
    if (!telemetry_reader_.attach(fd)) { Q_EMIT telemetryChanged(); return false; }
    telemetry_timer_.setInterval(250);
    connect(&telemetry_timer_, &QTimer::timeout, this, [this] {
        if (telemetry_reader_.poll()) { Q_EMIT telemetryChanged(); }
        if (telemetry_reader_.link() == agent::StatusLink::Disconnected ||
            telemetry_reader_.link() == agent::StatusLink::Invalid) { telemetry_timer_.stop(); }
    });
    telemetry_timer_.start();
    Q_EMIT telemetryChanged();
    return true;
}
QString ServiceHealthModel::telemetryStatus() const {
    switch (telemetry_reader_.link()) {
    case agent::StatusLink::Unconfigured: return tr("Unavailable — no local status stream selected");
    case agent::StatusLink::Waiting: return tr("Waiting for local agent report");
    case agent::StatusLink::Current: return tr("Current local report — launcher-provided, not remotely authenticated");
    case agent::StatusLink::Stale: return tr("Unavailable — local report expired");
    case agent::StatusLink::Disconnected: return tr("Unavailable — local status stream disconnected");
    case agent::StatusLink::Invalid: return tr("Unavailable — invalid local status stream");
    }
    return tr("Unavailable");
}
QString ServiceHealthModel::telemetryCollector() const {
    const auto& sample = telemetry_reader_.current();
    if (!sample) { return tr("Unavailable"); }
    if (sample->mode == "none") { return tr("None — lifecycle only"); }
    if (sample->mode == "journal") { return tr("Journal metadata"); }
    if (sample->mode == "authentication") { return tr("Authentication and SSH"); }
    if (sample->mode == "audit") { return tr("Linux Audit (journal)"); }
    if (sample->mode == "fim") { return tr("File integrity (content and metadata)"); }
    if (sample->mode == "fim-metadata") { return tr("File integrity (metadata only)"); }
    return tr("Unavailable");
}
QString ServiceHealthModel::telemetryHealth() const {
    const auto& sample = telemetry_reader_.current();
    if (!sample) { return tr("Unavailable"); }
    if (sample->health == "idle") { return tr("No active collector"); }
    if (sample->health == "active") { return tr("Local collection polling — coverage unknown"); }
    if (sample->health == "paused") { return tr("Paused — offline buffer full"); }
    if (sample->health == "blocked") { return tr("Blocked — source failure; coverage unknown"); }
    if (sample->health == "source-failed") { return tr("Source failed — coverage unknown"); }
    if (sample->health == "failed") { return tr("Failed — coverage unknown"); }
    return tr("Unavailable");
}
QString ServiceHealthModel::telemetryRate() const {
    const auto& sample = telemetry_reader_.current();
    if (!sample || sample->interval_ms == 0) { return tr("Unavailable"); }
    const double rate = static_cast<double>(sample->observations) * 1000.0 / static_cast<double>(sample->interval_ms);
    return tr("%1 observations/s (%2 in %3 ms)")
        .arg(QString::number(rate, 'f', 2), decimal(sample->observations), decimal(sample->interval_ms));
}
QString ServiceHealthModel::telemetryQueue() const {
    const auto& sample = telemetry_reader_.current();
    if (!sample || !sample->queued || sample->health == "failed") { return tr("Unavailable"); }
    return tr("%1 / 128 locally queued records — delivery unavailable").arg(decimal(*sample->queued));
}
QString ServiceHealthModel::telemetryFailure() const {
    const auto& sample = telemetry_reader_.current();
    if (sample && (sample->health == "blocked" || sample->health == "source-failed")) {
        return tr("Reported source failure — details not collected");
    }
    if (sample && sample->health == "failed") {
        return tr("Reported collection failure — source observation or protected state; details not collected");
    }
    if (!sample && telemetry_reader_.last_failure()) { return tr("Last report indicated failure — not current"); }
    if (sample && sample->health == "active") { return tr("No failure in current report — not a historical error counter"); }
    return tr("Unavailable");
}
} // namespace knetsentry::desktop
