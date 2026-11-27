// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/storage/event_store.hpp>
#include <algorithm>
#include <limits>
#include <stdexcept>
#include <type_traits>
#include <utility>

namespace knetsentry::storage {
namespace {
constexpr auto max_id = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
constexpr auto max_received_ms = max_id;
bool valid_received(std::uint64_t ms) noexcept { return ms != 0 && ms <= max_received_ms; }
bool valid_severity(agent::OcsfSeverity severity) noexcept {
    using S = agent::OcsfSeverity;
    switch (severity) {
    case S::Unknown: case S::Informational: case S::Low: case S::Medium:
    case S::High: case S::Critical: case S::Fatal: case S::Other: return true;
    }
    return false;
}
agent::OcsfCategory category_of(const agent::NormalizedEvent& event) noexcept {
    return event.class_uid == agent::OcsfClass::Authentication
        ? agent::OcsfCategory::IdentityAndAccessManagement : agent::OcsfCategory::Unknown;
}
} // namespace
bool valid_search_query(const SearchQuery& q) noexcept {
    using C = agent::OcsfClass;
    using S = agent::OcsfStatus;
    using J = agent::JournalMode;
    using A = agent::OcsfActivity;
    using M = agent::MappingResult;
    using G = agent::OcsfCategory;
    return q.limit > 0 && q.limit <= EventStore::max_page && q.from_ms <= q.through_ms &&
        (q.binding.empty() || agent::valid_delivery_binding(q.binding)) &&
        (q.source_unit.empty() || q.source_unit == "audit" || agent::valid_journal_unit(q.source_unit)) &&
        (!q.source_mode || *q.source_mode == J::Metadata || *q.source_mode == J::Authentication || *q.source_mode == J::Audit) &&
        (!q.category || *q.category == G::Unknown || *q.category == G::IdentityAndAccessManagement) &&
        (!q.severity || valid_severity(*q.severity)) &&
        (!q.activity || *q.activity == A::Unknown || *q.activity == A::Logon || *q.activity == A::Logoff) &&
        (!q.mapping || *q.mapping == M::Classified || *q.mapping == M::MetadataOnly ||
            *q.mapping == M::AuditTypeUnmapped || *q.mapping == M::Redacted || *q.mapping == M::Unclassified) &&
        (!q.class_uid || *q.class_uid == C::Base || *q.class_uid == C::Authentication) &&
        (!q.status_id || *q.status_id == S::Unknown || *q.status_id == S::Success || *q.status_id == S::Failure) &&
        (q.after == 0 || q.revision.has_value());
}
bool matches_search_query(const SearchQuery& q, const RawEvidence& raw, const agent::NormalizedEvent& event) noexcept {
    return raw.id > q.after && event.time_ms >= q.from_ms && event.time_ms <= q.through_ms &&
        (q.binding.empty() || q.binding == raw.binding) &&
        (q.source_unit.empty() || q.source_unit == raw.unit) &&
        (!q.source_mode || *q.source_mode == raw.mode) &&
        (!q.category || *q.category == category_of(event)) &&
        (!q.severity || *q.severity == event.severity_id) &&
        (!q.activity || *q.activity == event.activity_id) &&
        (!q.mapping || *q.mapping == event.mapping) &&
        (!q.class_uid || *q.class_uid == event.class_uid) &&
        (!q.status_id || *q.status_id == event.status_id);
}
EventSummary summarize_event(const RawEvidence& raw, const agent::NormalizedEvent& event) {
    return {raw.id, event.time_ms, raw.received_ms, event.class_uid, event.activity_id, event.status_id,
        event.mapping, category_of(event), event.severity_id, raw.mode, raw.unit};
}
bool valid_storage_policy(const StoragePolicy& p) noexcept {
    return p.record_limit > 0 && p.record_limit <= StoragePolicy::record_ceiling &&
        p.wire_byte_limit > 0 && p.wire_byte_limit <= StoragePolicy::wire_ceiling &&
        p.database_page_limit >= 16 && p.database_page_limit <= StoragePolicy::page_ceiling &&
        p.warning_percent > 0 && p.warning_percent <= 100 &&
        p.retention_ms <= max_received_ms && p.cleanup_batch > 0 && p.cleanup_batch <= EventStore::max_page;
}
bool quota_warning(std::size_t used, std::size_t limit, std::size_t percent) noexcept {
    // All callers use validated bounded policy values; avoid multiplication overflow even for arbitrary arguments.
    if (limit == 0 || percent == 0 || percent > 100) { return false; }
    const auto threshold = (limit / 100) * percent + ((limit % 100) * percent + 99) / 100;
    return used >= threshold;
}
EventStore::EventStore(StoragePolicy policy) : policy_(policy) {
    if (!valid_storage_policy(policy)) { throw std::invalid_argument("invalid storage policy"); }
}
RetentionPreview EventStore::preview_cleanup(std::uint64_t now_ms) const {
    if (!valid_received(now_ms) || policy().retention_ms == 0) { return {}; }
    const auto before = now_ms > policy().retention_ms ? now_ms - policy().retention_ms : 1U;
    return preview_retention(before, policy().cleanup_batch);
}
RetentionResult EventStore::apply_cleanup(std::uint64_t now_ms, const RetentionPlan& plan) {
    if (plan.ids.size() > max_page) { return {}; }
    const auto expected = preview_cleanup(now_ms);
    if (expected.status != StoreStatus::Ok || !expected.plan) { return {expected.status, 0}; }
    const auto& current = *expected.plan;
    if (plan.revision != current.revision) { return {StoreStatus::Stale, 0}; }
    if (plan.before_received_ms != current.before_received_ms || plan.limit != current.limit || plan.ids != current.ids) { return {}; }
    return apply_retention(plan); // Revalidates within the mutation transaction.
}
ReadResult<StorageUsage> MemoryEventStore::usage() const {
    StorageUsage result;
    result.records = entries_.size();
    for (const auto& entry : entries_) {
        result.wire_bytes += entry.raw.canonical_row.size();
        if (entry.raw.held) { ++result.held; }
        if (!entry.normalized) { ++result.pending; }
    }
    result.record_warning = quota_warning(result.records, policy().record_limit, policy().warning_percent);
    result.wire_warning = quota_warning(result.wire_bytes, policy().wire_byte_limit, policy().warning_percent);
    return {StoreStatus::Ok, result};
}
AppendResult MemoryEventStore::append(const RawInput& input) {
    if (!valid_received(input.received_ms) || !agent::valid_delivery_binding(input.binding)) { return {}; }
    auto parsed = agent::parse_delivery_row(input.canonical_row, input.unit, input.mode);
    if (!parsed) { return {}; }
    // The endpoint part of the configured binding and native cursor form the
    // existing receipt identity. A changed binding/profile cannot overwrite it.
    const auto existing = std::ranges::find_if(entries_, [&](const auto& entry) {
        return std::string_view(entry.raw.binding).substr(0, 32) == input.binding.substr(0, 32) &&
            entry.cursor == parsed->cursor;
    });
    if (existing != entries_.end()) {
        const auto& raw = existing->raw;
        if (raw.binding == input.binding && raw.unit == input.unit && raw.mode == input.mode && raw.canonical_row == input.canonical_row) {
            return {StoreStatus::ExactRetry, raw.id, Durability::Volatile};
        }
        return {StoreStatus::Conflict, 0, Durability::None};
    }
    const auto used = usage().value->wire_bytes;
    if (entries_.size() >= policy().record_limit || used >= policy().wire_byte_limit ||
        input.canonical_row.size() > policy().wire_byte_limit - used) { return {StoreStatus::Capacity, 0, Durability::None}; }
    if (next_id_ == max_id || revision_ == max_id) { return {StoreStatus::Exhausted, 0, Durability::None}; }
    RawEvidence raw{next_id_, std::string(input.binding), std::string(input.unit), std::string(input.canonical_row),
        input.mode, input.received_ms, false};
    static_assert(std::is_nothrow_move_constructible_v<Entry>);
    entries_.push_back({std::move(raw), std::move(parsed->cursor), std::nullopt});
    ++revision_;
    return {StoreStatus::Ok, next_id_++, Durability::Volatile};
}
IndexResult MemoryEventStore::index(EventId id) {
    auto entry = std::ranges::find_if(entries_, [id](const auto& e) { return e.raw.id == id; });
    if (entry == entries_.end()) { return {StoreStatus::NotFound, Durability::None}; }
    if (entry->normalized) { return {StoreStatus::ExactRetry, Durability::Volatile}; }
    if (revision_ == max_id) { return {StoreStatus::Exhausted, Durability::None}; }
    const auto& raw = entry->raw;
    auto event = agent::normalize_event(raw.canonical_row, raw.binding, raw.unit, raw.mode);
    if (!event) { return {}; }
    static_assert(std::is_nothrow_move_assignable_v<std::optional<agent::NormalizedEvent>>);
    entry->normalized = std::move(event);
    ++revision_;
    return {StoreStatus::Ok, Durability::Volatile};
}
ReadResult<RawEvidence> MemoryEventStore::raw(EventId id) const {
    const auto entry = std::ranges::find_if(entries_, [id](const auto& e) { return e.raw.id == id; });
    if (entry == entries_.end()) { return {}; }
    return {StoreStatus::Ok, entry->raw};
}
ReadResult<agent::NormalizedEvent> MemoryEventStore::normalized(EventId id) const {
    const auto entry = std::ranges::find_if(entries_, [id](const auto& e) { return e.raw.id == id; });
    if (entry == entries_.end()) { return {}; }
    if (!entry->normalized) { return {StoreStatus::IndexPending, std::nullopt}; }
    return {StoreStatus::Ok, entry->normalized};
}
SearchPage MemoryEventStore::search(const SearchQuery& query) const {
    SearchPage page;
    if (!valid_search_query(query)) { return page; }
    page.revision = revision_;
    if (query.revision && *query.revision != revision_) { page.status = StoreStatus::Stale; return page; }
    page.status = StoreStatus::Ok;
    for (const auto& entry : entries_) {
        if (!entry.normalized || entry.raw.id <= query.after) { continue; }
        const auto& event = *entry.normalized;
        if (!matches_search_query(query, entry.raw, event)) { continue; }
        if (page.events.size() == query.limit) { page.more = true; break; }
        page.events.push_back(summarize_event(entry.raw, event));
    }
    return page;
}
PendingPage MemoryEventStore::pending(EventId after, std::optional<std::uint64_t> revision, std::size_t limit) const {
    PendingPage page;
    if (limit == 0 || limit > max_page || (after != 0 && !revision)) { return page; }
    page.revision = revision_;
    if (revision && *revision != revision_) { page.status = StoreStatus::Stale; return page; }
    page.status = StoreStatus::Ok;
    for (const auto& entry : entries_) {
        if (entry.normalized || entry.raw.id <= after) { continue; }
        if (page.ids.size() == limit) { page.more = true; break; }
        page.ids.push_back(entry.raw.id);
    }
    return page;
}
StoreStatus MemoryEventStore::set_hold(EventId id, bool held) {
    auto entry = std::ranges::find_if(entries_, [id](const auto& e) { return e.raw.id == id; });
    if (entry == entries_.end()) { return StoreStatus::NotFound; }
    if (entry->raw.held == held) { return StoreStatus::ExactRetry; }
    if (revision_ == max_id) { return StoreStatus::Exhausted; }
    entry->raw.held = held;
    ++revision_;
    return StoreStatus::Ok;
}
RetentionPreview MemoryEventStore::preview_retention(std::uint64_t before_received_ms, std::size_t limit) const {
    if (!valid_received(before_received_ms) || limit == 0 || limit > max_page) { return {}; }
    RetentionPlan plan{revision_, before_received_ms, limit, {}};
    for (const auto& entry : entries_) {
        // Never delete raw evidence awaiting indexing, or explicitly held evidence.
        if (entry.normalized && !entry.raw.held && entry.raw.received_ms < before_received_ms) {
            plan.ids.push_back(entry.raw.id);
            if (plan.ids.size() == limit) { break; }
        }
    }
    return {StoreStatus::Ok, std::move(plan)};
}
RetentionResult MemoryEventStore::apply_retention(const RetentionPlan& plan) {
    if (plan.ids.size() > max_page) { return {}; }
    if (plan.revision != revision_) { return {StoreStatus::Stale, 0}; }
    const auto expected = preview_retention(plan.before_received_ms, plan.limit);
    if (expected.status != StoreStatus::Ok || !expected.plan || expected.plan->ids != plan.ids) { return {}; }
    if (plan.ids.empty()) { return {StoreStatus::Ok, 0}; }
    if (revision_ == max_id) { return {StoreStatus::Exhausted, 0}; }
    static_assert(std::is_nothrow_move_assignable_v<Entry>);
    const auto removed = std::erase_if(entries_, [&](const auto& entry) {
        return std::ranges::find(plan.ids, entry.raw.id) != plan.ids.end();
    });
    ++revision_;
    return {StoreStatus::Ok, removed};
}
} // namespace knetsentry::storage
