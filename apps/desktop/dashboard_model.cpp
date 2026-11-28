// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "dashboard_model.hpp"
#include <knetsentry/service/dashboard_summary.hpp>
#include <QRandomGenerator>
#include <unistd.h>

namespace knetsentry::desktop {
namespace {
QString decimal(std::uint64_t value) { return QString::number(static_cast<qulonglong>(value)); }
QByteArray requestId() { return QByteArray::number(QRandomGenerator::system()->generate64(), 16).rightJustified(16, '0'); }
std::string_view view(const QByteArray& value) {
    return {value.constData(), static_cast<std::size_t>(value.size())};
}
} // namespace
DashboardModel::DashboardModel(const QString& directory, QObject* parent)
    : QObject(parent), directory_(directory.toUtf8()) {
    exchange_.setInterval(25);
    expiry_.setSingleShot(true);
    expiry_.setTimerType(Qt::PreciseTimer);
    expiry_.setInterval(30000);
    connect(&exchange_, &QTimer::timeout, this, &DashboardModel::advance);
    connect(&expiry_, &QTimer::timeout, this, &DashboardModel::clear);
    reset();
}
bool DashboardModel::configured() const noexcept { return !directory_.isEmpty() && ::geteuid() != 0; }
void DashboardModel::reset() {
    exchange_.stop(); expiry_.stop(); client_.cancel(); event_session_.clear(); reading_alerts_ = false;
    events_ = alerts_ = detections_ = configured() ? tr("Unavailable — no current stored snapshot. Refresh to request one.") :
        tr("Unavailable — explicit non-root manager IPC selection required.");
}
void DashboardModel::clear() { reset(); Q_EMIT changed(); }
void DashboardModel::refresh() {
    if (busy() || !configured()) { return; }
    reset();
    events_ = alerts_ = detections_ = tr("Requesting approved stored summaries…");
    service::EventQuery query;
    query.descending = true;
    const auto id = requestId();
    client_.begin_events(view(directory_), view(id), query);
    expiry_.start();
    exchange_.start();
    Q_EMIT changed();
}
void DashboardModel::beginAlerts() {
    client_.cancel();
    reading_alerts_ = true;
    const auto id = requestId();
    // Default operation is List. Do not propagate writable flags or expose actions.
    client_.begin_alerts(view(directory_), view(id), service::AlertQuery{});
}
void DashboardModel::advance() {
    client_.advance();
    if (client_.state() == service::HealthQueryState::Pending) { return; }
    if (!reading_alerts_) {
        events_ = tr("Unavailable — stored event query denied, invalid or inaccessible.");
        if (client_.state() == service::HealthQueryState::Available && client_.events()) {
            const auto& result = *client_.events();
            if (const auto summary = service::summarize_events(result)) {
                event_session_ = result.session;
                events_ = tr("%1 stored events on page; %2 failure outcomes. %3")
                    .arg(decimal(summary->count), decimal(summary->failures), result.page.more ? tr("More records exist.") : tr("End of returned scope."));
                if (summary->count != 0) {
                    events_ += tr("\nMaximum receiver time on page (Unix ms): %1").arg(decimal(summary->newest_receiver_ms));
                }
            }
        }
        beginAlerts();
        Q_EMIT changed();
        return;
    }
    alerts_ = detections_ = tr("Unavailable — stored alert query denied, invalid or inaccessible.");
    if (client_.state() == service::HealthQueryState::Available && client_.alerts()) {
        const auto& result = *client_.alerts();
        if (const auto summary = service::summarize_alerts(result)) {
            if (!event_session_.empty() && event_session_ != result.session) {
                events_ = alerts_ = detections_ = tr("Unavailable — manager instance changed during refresh.");
            } else {
                const auto scope = result.more ? tr("More records exist.") : tr("End of returned development scope.");
                alerts_ = tr("%1 active stored alerts on page (%2 open, %3 acknowledged); %4 resolved.\n%5 high/critical active. %6")
                    .arg(decimal(summary->open + summary->acknowledged), decimal(summary->open), decimal(summary->acknowledged),
                         decimal(summary->resolved), decimal(summary->high_active), scope);
                detections_ = tr("%1 distinct rule identifiers in %2 stored alerts on page. %3\nLive rule execution unavailable.")
                    .arg(decimal(summary->distinct_rules), decimal(summary->count), scope);
            }
        }
    }
    client_.cancel(); event_session_.clear(); exchange_.stop();
    Q_EMIT changed();
}
} // namespace knetsentry::desktop
