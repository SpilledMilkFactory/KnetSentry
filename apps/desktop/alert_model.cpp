// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "alert_model.hpp"
#include <QRandomGenerator>
#include <QVariant>
namespace knetsentry::desktop {
namespace {
QString decimal(std::uint64_t n) { return QString::number(static_cast<qulonglong>(n)); }
QString severity(std::uint64_t n) {
    switch (n) {
    case 1: return QStringLiteral("Informational"); case 2: return QStringLiteral("Low");
    case 3: return QStringLiteral("Medium"); case 4: return QStringLiteral("High");
    case 5: return QStringLiteral("Critical"); default: return QStringLiteral("Unspecified");
    }
}
QString lifecycle(std::uint64_t n) {
    switch (n) { case 0: return QStringLiteral("Open"); case 1: return QStringLiteral("Acknowledged");
    case 2: return QStringLiteral("Resolved"); default: return QStringLiteral("Unknown"); }
}
QString coverage(std::uint64_t n) {
    switch (n) { case 1: return QStringLiteral("Partial"); case 2: return QStringLiteral("Source observed"); default: return QStringLiteral("Unknown"); }
}
} // namespace
AlertModel::AlertModel(const QString& directory, QObject* parent) : QAbstractListModel(parent), directory_(directory.toUtf8()) {
    exchange_.setInterval(20); expiry_.setSingleShot(true); expiry_.setInterval(30000);
    connect(&exchange_, &QTimer::timeout, this, &AlertModel::advance);
    connect(&expiry_, &QTimer::timeout, this, &AlertModel::clear); clear();
}
int AlertModel::rowCount(const QModelIndex& parent) const { return parent.isValid() ? 0 : static_cast<int>(rows_.size()); }
QHash<int,QByteArray> AlertModel::roleNames() const { return {{AlertLabel,"alertLabel"}}; }
QVariant AlertModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.model() != this || index.column() != 0 || index.row() < 0 || index.row() >= rowCount() || (role != AlertLabel && role != Qt::DisplayRole)) { return {}; }
    const auto& r = rows_[static_cast<std::size_t>(index.row())];
    return QStringLiteral("%1/%2 · %3 · %4 · %5").arg(decimal(r.generation),decimal(r.trigger),severity(r.severity),lifecycle(r.status),QString::fromStdString(r.source));
}
void AlertModel::discard() {
    exchange_.stop(); expiry_.stop(); client_.cancel(); beginResetModel(); rows_.clear(); endResetModel();
    selection_ = -1; detail_.clear(); evidence_.clear(); evidence_detail_.clear(); busy_ = more_ = writable_ = false;
}
void AlertModel::clear() {
    const bool uncertain = busy_ && request_.operation == service::AlertQuery::Operation::Acknowledge;
    discard(); query_ = {}; request_ = {};
    status_ = uncertain ? QStringLiteral("Acknowledgement outcome unknown. Refresh before retrying.") :
        directory_.isEmpty() ? QStringLiteral("Unavailable — explicit alert-enabled manager required.") : QStringLiteral("No current alert snapshot. Select Refresh."); Q_EMIT changed();
}
void AlertModel::search(int filter) {
    if (busy_) { return; }
    discard(); query_ = {};
    if (filter < -1 || filter > 5) {
        status_ = tr("Invalid alert severity filter."); Q_EMIT changed(); return;
    }
    query_.severity = filter; request(query_);
}
void AlertModel::next() {
    if (busy_ || !more_ || rows_.empty()) { return; }
    query_.offset += static_cast<std::uint64_t>(rows_.size()); discard(); request(query_);
}
void AlertModel::request(const service::AlertQuery& q) {
    request_ = q;
    const auto id = QString::number(QRandomGenerator::system()->generate64(),16).rightJustified(16,QLatin1Char('0')).toLatin1();
    client_.begin_alerts(std::string_view(directory_.constData(),static_cast<std::size_t>(directory_.size())),std::string_view(id.constData(),static_cast<std::size_t>(id.size())),request_);
    busy_ = client_.state() == service::HealthQueryState::Pending;
    status_ = busy_ ? QStringLiteral("Requesting approved alert state…") : QStringLiteral("Alert request unavailable. Refresh required.");
    if (busy_) { exchange_.start(); } else { discard(); }
    Q_EMIT changed();
}
void AlertModel::advance() {
    client_.advance(); if (client_.state() == service::HealthQueryState::Pending) { return; }
    exchange_.stop(); busy_ = false;
    const auto result = client_.alerts(); client_.cancel();
    if (!result || result->result != "OK") {
        const bool ack = request_.operation == service::AlertQuery::Operation::Acknowledge;
        discard(); status_ = ack ? QStringLiteral("Acknowledgement not confirmed. Refresh before retrying.") : QStringLiteral("Alert or linked evidence unavailable, denied or stale. Refresh required.");
    } else if (request_.operation == service::AlertQuery::Operation::Acknowledge) {
        discard(); status_ = QStringLiteral("Acknowledgement committed. Refresh to view current lifecycle state.");
    } else if (request_.operation == service::AlertQuery::Operation::Evidence) {
        evidence_detail_ = QStringLiteral("Verified stored evidence #%1\nSource time (Unix ms): %2\nReceiver time (Unix ms): %3\nOutcome: %4\nIntegrity origin: %5")
            .arg(decimal(result->evidence),decimal(result->source_time),decimal(result->receiver_time),result->outcome == 2 ? QStringLiteral("Failure") : result->outcome == 1 ? QStringLiteral("Success") : QStringLiteral("Unknown"),result->origin == 1 ? QStringLiteral("Admission") : QStringLiteral("Legacy baseline"));
        status_ = QStringLiteral("Linked evidence verified at request time — not live monitoring.");
    } else {
        query_.session = result->session; beginResetModel(); rows_ = result->rows; endResetModel(); more_ = result->more; writable_ = result->writable;
        status_ = rows_.empty() ? QStringLiteral("No matching stored alerts in this scope.") : QStringLiteral("%1 stored alerts on this page — not live monitoring. %2")
            .arg(rowCount()).arg(more_ ? tr("More matching records available.") : tr("End of matching results."));
        expiry_.start();
    }
    Q_EMIT changed();
}
void AlertModel::select(int row) {
    if (busy_) { return; }
    selection_ = -1; detail_.clear(); evidence_.clear(); evidence_detail_.clear();
    if (row >= 0 && row < rowCount()) {
        selection_ = row; const auto& r = rows_[static_cast<std::size_t>(row)];
        detail_ = QStringLiteral("Alert %1/%2\nRule: %3\nSource: %4\nSeverity: %5\nStatus: %6\nRevision: %7\nCreated (Unix ms): %8\nUpdated (Unix ms): %9\nCoverage: %10")
            .arg(decimal(r.generation),decimal(r.trigger),QString::fromStdString(r.rule),QString::fromStdString(r.source),severity(r.severity),lifecycle(r.status),decimal(r.revision),decimal(r.created),decimal(r.updated),coverage(r.coverage));
        for (const auto id : r.evidence) { evidence_.append(decimal(id)); }
    }
    Q_EMIT changed();
}
bool AlertModel::canAcknowledge() const noexcept {
    return !busy_ && writable_ && selection_ >= 0 && selection_ < rowCount() && rows_[static_cast<std::size_t>(selection_)].status == 0;
}
service::AlertQuery AlertModel::selectedQuery(service::AlertQuery::Operation operation) const {
    service::AlertQuery q; q.operation = operation; q.session = query_.session;
    const auto& r = rows_[static_cast<std::size_t>(selection_)]; q.generation = r.generation; q.trigger = r.trigger; q.revision = r.revision; return q;
}
void AlertModel::acknowledge() { if (canAcknowledge()) { request(selectedQuery(service::AlertQuery::Operation::Acknowledge)); } }
void AlertModel::inspectEvidence(int index) {
    if (busy_ || selection_ < 0 || selection_ >= rowCount() || index < 0 || index >= evidence_.size()) { return; }
    auto q = selectedQuery(service::AlertQuery::Operation::Evidence); q.evidence = rows_[static_cast<std::size_t>(selection_)].evidence[static_cast<std::size_t>(index)];
    evidence_detail_.clear(); request(q);
}
} // namespace knetsentry::desktop
