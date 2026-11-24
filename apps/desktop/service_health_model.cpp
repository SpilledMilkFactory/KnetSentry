// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "service_health_model.hpp"

#include <QFile>
#include <QRandomGenerator>
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
    const auto id = QByteArray::number(QRandomGenerator::system()->generate64(), 16).rightJustified(16, '0');
    client_.begin(std::string_view(directory_.constData(), static_cast<std::size_t>(directory_.size())),
                  std::string_view(id.constData(), static_cast<std::size_t>(id.size())));
    if (client_.state() == service::HealthQueryState::Pending) { exchange_timer_.start(); }
    Q_EMIT changed();
}

void ServiceHealthModel::advance() {
    client_.advance();
    if (client_.state() != service::HealthQueryState::Pending) {
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
} // namespace knetsentry::desktop
