// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "timeline_model.hpp"
#include <QRandomGenerator>
#include <unistd.h>

namespace knetsentry::desktop {
namespace {
QString number(std::uint64_t n) { return QString::number(static_cast<qulonglong>(n)); }
QByteArray requestId() { return QByteArray::number(QRandomGenerator::system()->generate64(), 16).rightJustified(16, '0'); }
std::string_view view(const QByteArray& value) { return {value.constData(), static_cast<std::size_t>(value.size())}; }
QString outcome(std::uint64_t value) {
    return value == 2 ? QStringLiteral("Failure") : value == 1 ? QStringLiteral("Success") : QStringLiteral("Unknown");
}
} // namespace
TimelineModel::TimelineModel(const QString& directory, QObject* parent) : QObject(parent), directory_(directory.toUtf8()) {
    exchange_.setInterval(25);
    expiry_.setSingleShot(true); expiry_.setTimerType(Qt::PreciseTimer); expiry_.setInterval(30000);
    connect(&exchange_, &QTimer::timeout, this, &TimelineModel::advance);
    connect(&expiry_, &QTimer::timeout, this, &TimelineModel::clear);
    reset();
}
bool TimelineModel::configured() const noexcept { return !directory_.isEmpty() && ::geteuid() != 0; }
void TimelineModel::reset() {
    exchange_.stop(); expiry_.stop(); client_.cancel();
    events_ = {}; alerts_ = {}; rows_.clear(); related_rows_.clear();
    entries_.clear(); related_.clear(); evidence_.clear(); detail_.clear(); evidence_detail_.clear(); selected_ = -1;
    phase_ = Phase::Events;
    status_ = configured() ? tr("Unavailable — refresh to request stored timeline pages.") : tr("Unavailable — explicit non-root manager IPC selection required.");
}
void TimelineModel::clear() { reset(); Q_EMIT changed(); }
void TimelineModel::fail() { reset(); status_ = tr("Unavailable — denied, invalid, stale or inaccessible timeline response."); Q_EMIT changed(); }
void TimelineModel::refresh() {
    if (!configured() || busy()) { return; }
    reset(); status_ = tr("Requesting approved stored timeline pages…");
    service::EventQuery query; query.descending = true;
    const auto id = requestId(); client_.begin_events(view(directory_), view(id), query);
    expiry_.start(); exchange_.start(); Q_EMIT changed();
}
void TimelineModel::requestAlert(const service::AlertQuery& query) {
    client_.cancel(); const auto id = requestId();
    client_.begin_alerts(view(directory_), view(id), query); exchange_.start(); Q_EMIT changed();
}
void TimelineModel::advance() {
    client_.advance();
    if (client_.state() == service::HealthQueryState::Pending) { return; }
    if (client_.state() != service::HealthQueryState::Available) { fail(); return; }
    if (phase_ == Phase::Events) {
        if (!client_.events() || !service::summarize_events(*client_.events())) { fail(); return; }
        events_ = *client_.events(); phase_ = Phase::Alerts; requestAlert({}); return;
    }
    if (!client_.alerts() || client_.alerts()->result != "OK" || client_.alerts()->session != events_.session) { fail(); return; }
    if (phase_ == Phase::Evidence) {
        const auto& result = *client_.alerts();
        evidence_detail_ = tr("Verified evidence #%1 at request time\nSource time (Unix ms): %2\nReceiver time (Unix ms): %3\nOutcome: %4\nIntegrity origin: %5")
            .arg(number(result.evidence), number(result.source_time), number(result.receiver_time), outcome(result.outcome),
                 result.origin == 1 ? tr("Admission") : tr("Legacy baseline"));
    } else {
        alerts_ = *client_.alerts();
        const auto timeline = service::investigation_timeline(events_, alerts_);
        if (!timeline) { fail(); return; }
        rows_ = *timeline;
        for (const auto& row : rows_) {
            if (row.alert()) {
                const auto& a = alerts_.rows.at(row.index);
                entries_.append(tr("%1 | Alert %2/%3 | %4 (creation)").arg(number(row.time), number(row.generation), number(row.id), QString::fromStdString(a.source)));
            } else {
                const auto& e = events_.page.events.at(row.index);
                entries_.append(tr("%1 | Event #%2 | %3 (receipt)").arg(number(row.time), number(row.id), QString::fromStdString(e.source_unit)));
            }
        }
        status_ = tr("%1 records on returned pages. Events: %2; alerts: %3. Not a complete timeline.")
            .arg(entries_.size()).arg(events_.page.more ? tr("more records") : tr("end of scope"), alerts_.more ? tr("more records") : tr("end of scope"));
    }
    client_.cancel(); exchange_.stop(); Q_EMIT changed();
}
void TimelineModel::select(int row) {
    if (busy() || row < 0 || static_cast<std::size_t>(row) >= rows_.size()) { return; }
    selected_ = row; related_rows_.clear(); related_.clear(); evidence_.clear(); evidence_detail_.clear();
    const auto& selected = rows_.at(static_cast<std::size_t>(row));
    if (selected.alert()) {
        const auto& a = alerts_.rows.at(selected.index);
        detail_ = tr("Alert %1/%2\nRule: %3\nSource unit: %4\nCreated (Unix ms): %5\nUpdated (Unix ms): %6\nRevision: %7\nSeverity code: %8 (0 unspecified, 1 informational, 2 low, 3 medium, 4 high, 5 critical)\nLifecycle code: %9 (0 open, 1 acknowledged, 2 resolved)\nAsset identity unavailable.")
            .arg(number(a.generation), number(a.trigger), QString::fromStdString(a.rule), QString::fromStdString(a.source), number(a.created), number(a.updated), number(a.revision), number(a.severity), number(a.status));
        for (const auto id : a.evidence) { evidence_.append(number(id)); }
    } else {
        const auto& e = events_.page.events.at(selected.index);
        detail_ = tr("Event #%1\nSource unit: %2\nSource time (Unix ms): %3\nReceiver time (Unix ms): %4\nOutcome: %5\nAsset identity unavailable.")
            .arg(number(e.id), QString::fromStdString(e.source_unit), number(e.time_ms), number(e.received_ms), outcome(static_cast<std::uint64_t>(e.status_id)));
    }
    for (std::size_t i = 0; i < rows_.size(); ++i) {
        const auto& candidate = rows_.at(i);
        if (candidate.alert() == selected.alert()) { continue; }
        const auto& event = events_.page.events.at(selected.alert() ? candidate.index : selected.index);
        const auto& alert = alerts_.rows.at(selected.alert() ? selected.index : candidate.index);
        if (service::timeline_link(event, alert)) { related_rows_.push_back(static_cast<int>(i)); related_.append(entries_.at(static_cast<qsizetype>(i))); }
    }
    Q_EMIT changed();
}
void TimelineModel::follow(int row) {
    if (busy() || row < 0 || static_cast<std::size_t>(row) >= related_rows_.size()) { return; }
    select(related_rows_.at(static_cast<std::size_t>(row)));
}
void TimelineModel::verifyEvidence(int row) {
    if (busy() || selected_ < 0 || row < 0 || static_cast<std::size_t>(selected_) >= rows_.size()) { return; }
    const auto& selected = rows_.at(static_cast<std::size_t>(selected_));
    if (!selected.alert()) { return; }
    const auto& a = alerts_.rows.at(selected.index);
    if (static_cast<std::size_t>(row) >= a.evidence.size()) { return; }
    service::AlertQuery query; query.operation = service::AlertQuery::Operation::Evidence;
    query.session = alerts_.session; query.generation = a.generation; query.trigger = a.trigger;
    query.revision = a.revision; query.evidence = a.evidence.at(static_cast<std::size_t>(row));
    phase_ = Phase::Evidence; evidence_detail_.clear(); requestAlert(query);
}
} // namespace knetsentry::desktop
