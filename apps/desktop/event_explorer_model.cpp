// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "event_explorer_model.hpp"
#include <QRandomGenerator>
#include <QVariant>

namespace knetsentry::desktop {
namespace {
QString outcome_name(agent::OcsfStatus status) {
    switch (status) {
    case agent::OcsfStatus::Success: return QStringLiteral("Success");
    case agent::OcsfStatus::Failure: return QStringLiteral("Failure");
    case agent::OcsfStatus::Unknown: return QStringLiteral("Unknown");
    }
    return QStringLiteral("Unknown");
}
QString mapping_name(agent::MappingResult mapping) {
    switch (mapping) {
    case agent::MappingResult::Classified: return QStringLiteral("Classified");
    case agent::MappingResult::MetadataOnly: return QStringLiteral("Metadata only");
    case agent::MappingResult::AuditTypeUnmapped: return QStringLiteral("Audit type unmapped");
    case agent::MappingResult::Redacted: return QStringLiteral("Redacted");
    case agent::MappingResult::Unclassified: return QStringLiteral("Unclassified");
    }
    return QStringLiteral("Unknown");
}
QString mode_name(agent::JournalMode mode) {
    switch (mode) {
    case agent::JournalMode::Metadata: return QStringLiteral("Journal metadata");
    case agent::JournalMode::Authentication: return QStringLiteral("Authentication");
    case agent::JournalMode::Audit: return QStringLiteral("Audit");
    case agent::JournalMode::Unsupported: return QStringLiteral("Unsupported");
    }
    return QStringLiteral("Unknown");
}
QString activity_name(agent::OcsfActivity activity) {
    switch (activity) {
    case agent::OcsfActivity::Unknown: return QStringLiteral("Unknown");
    case agent::OcsfActivity::Logon: return QStringLiteral("Logon");
    case agent::OcsfActivity::Logoff: return QStringLiteral("Logoff");
    }
    return QStringLiteral("Unknown");
}
QString decimal(std::uint64_t n) { return QString::number(static_cast<qulonglong>(n)); }
} // namespace
EventExplorerModel::EventExplorerModel(const QString& directory, QObject* parent)
    : QAbstractListModel(parent), directory_(directory.toUtf8()) {
    exchange_.setInterval(20);
    expiry_.setSingleShot(true);
    expiry_.setInterval(30000);
    connect(&exchange_, &QTimer::timeout, this, &EventExplorerModel::advance);
    connect(&expiry_, &QTimer::timeout, this, &EventExplorerModel::clear);
    clear();
}
int EventExplorerModel::rowCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : static_cast<int>(rows_.size());
}
QVariant EventExplorerModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.model() != this || index.column() != 0 || index.row() < 0 ||
        index.row() >= rowCount() || (role != EventLabel && role != Qt::DisplayRole)) { return {}; }
    const auto& e = rows_[static_cast<std::size_t>(index.row())];
    return QStringLiteral("#%1 · %2 · %3").arg(decimal(e.id), QString::fromStdString(e.source_unit), outcome_name(e.status_id));
}
QHash<int, QByteArray> EventExplorerModel::roleNames() const { return {{EventLabel, "eventLabel"}}; }
void EventExplorerModel::discard() {
    exchange_.stop(); expiry_.stop(); client_.cancel();
    beginResetModel(); rows_.clear(); endResetModel();
    busy_ = false; more_ = false; detail_.clear();
}
void EventExplorerModel::clear() {
    discard(); query_ = {};
    status_ = directory_.isEmpty() ? QStringLiteral("Unavailable — start with an explicit event-enabled manager IPC directory.") :
        QStringLiteral("No current search. Select filters and Search.");
    Q_EMIT changed();
}
void EventExplorerModel::search(const QString& source, int mode, int outcome, bool descending) {
    discard(); query_ = {};
    // Reject before converting potentially oversized QML input.
    if (source.size() > 128) { status_ = QStringLiteral("Invalid source filter."); Q_EMIT changed(); return; }
    query_.source = source.toUtf8().toStdString(); query_.mode = mode; query_.outcome = outcome; query_.descending = descending;
    if (!service::valid_event_query(query_)) { status_ = QStringLiteral("Invalid search filters."); Q_EMIT changed(); return; }
    request();
}
void EventExplorerModel::next() {
    if (busy_ || !more_ || rows_.empty()) { return; }
    query_.after = rows_.back().id;
    request();
}
void EventExplorerModel::request() {
    discard();
    const auto id = QString::number(QRandomGenerator::system()->generate64(), 16).rightJustified(16, QLatin1Char('0')).toLatin1();
    client_.begin_events(std::string_view(directory_.constData(), static_cast<std::size_t>(directory_.size())),
        std::string_view(id.constData(), static_cast<std::size_t>(id.size())), query_);
    busy_ = client_.state() == service::HealthQueryState::Pending;
    status_ = busy_ ? QStringLiteral("Searching approved storage…") : QStringLiteral("Event query unavailable or rejected.");
    if (busy_) { exchange_.start(); }
    Q_EMIT changed();
}
void EventExplorerModel::advance() {
    client_.advance();
    if (client_.state() == service::HealthQueryState::Pending) { return; }
    exchange_.stop(); busy_ = false;
    const auto& result = client_.events();
    if (client_.state() != service::HealthQueryState::Available || !result) {
        status_ = QStringLiteral("Event query unavailable or rejected. Search again.");
    } else if (result->page.status == storage::StoreStatus::Ok) {
        query_.session = result->session; query_.revision = result->page.revision;
        beginResetModel(); rows_ = result->page.events; endResetModel();
        more_ = result->page.more;
        status_ = rows_.empty() ? QStringLiteral("No matching stored events in this snapshot.") :
            QStringLiteral("%1 matching records on this page — stored snapshot, not live monitoring.").arg(rowCount());
        expiry_.start();
    } else if (result->page.status == storage::StoreStatus::IntegrityFailure) {
        status_ = QStringLiteral("Evidence integrity verification failed. No records displayed.");
    } else if (result->page.status == storage::StoreStatus::Stale) {
        status_ = QStringLiteral("Storage snapshot changed. Start a new search.");
    } else { status_ = QStringLiteral("Approved event storage unavailable."); }
    client_.cancel();
    Q_EMIT changed();
}
void EventExplorerModel::select(int row) {
    detail_.clear();
    if (row >= 0 && row < rowCount()) {
        const auto& e = rows_[static_cast<std::size_t>(row)];
        detail_ = QStringLiteral("Event ID: %1\nSource: %2\nCollector: %3\nSource time (Unix ms): %4\nReceiver time (Unix ms): %5\nOCSF class: %6\nActivity: %7\nOutcome: %8\nMapping: %9\nSeverity: Unknown (mapping revision 1)")
            .arg(decimal(e.id), QString::fromStdString(e.source_unit), mode_name(e.source_mode),
                 decimal(e.time_ms), decimal(e.received_ms), decimal(static_cast<std::uint64_t>(e.class_uid)),
                 activity_name(e.activity_id), outcome_name(e.status_id), mapping_name(e.mapping));
    }
    Q_EMIT changed();
}
} // namespace knetsentry::desktop
