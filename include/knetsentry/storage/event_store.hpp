// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <knetsentry/agent/normalization.hpp>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace knetsentry::storage {
using EventId = std::uint64_t;
enum class Durability { None, Volatile, Durable };
enum class StoreStatus {
    Ok, ExactRetry, Invalid, Conflict, Capacity, NotFound, IndexPending, Stale, Exhausted,
    Unavailable, IoError, IntegrityFailure
};
struct RawInput {
    std::string_view binding, unit, canonical_row;
    agent::JournalMode mode{agent::JournalMode::Metadata};
    std::uint64_t received_ms{}; // Trusted receiver clock, not source time.
};
enum class IntegrityOrigin { LegacyBaseline, Admission };
struct EvidenceIntegrity {
    // SHA-256, encoding revision 1; lowercase hexadecimal.
    std::string sha256;
    IntegrityOrigin origin{IntegrityOrigin::LegacyBaseline};
};
struct RawEvidence {
    EventId id{};
    std::string binding, unit, canonical_row;
    agent::JournalMode mode{agent::JournalMode::Metadata};
    std::uint64_t received_ms{};
    bool held{};
    std::optional<EvidenceIntegrity> integrity{}; // Absent in volatile reference store.
};
struct AppendResult {
    StoreStatus status{StoreStatus::Invalid};
    EventId id{};
    Durability durability{Durability::None};
};
struct IndexResult {
    StoreStatus status{StoreStatus::Invalid};
    Durability durability{Durability::None};
};
template<class T> struct ReadResult {
    StoreStatus status{StoreStatus::NotFound};
    std::optional<T> value;
};
struct EventSummary {
    EventId id{};
    std::uint64_t time_ms{}, received_ms{};
    agent::OcsfClass class_uid{agent::OcsfClass::Base};
    agent::OcsfActivity activity_id{agent::OcsfActivity::Unknown};
    agent::OcsfStatus status_id{agent::OcsfStatus::Unknown};
    agent::MappingResult mapping{agent::MappingResult::MetadataOnly};
    agent::OcsfCategory category{agent::OcsfCategory::Unknown};
    agent::OcsfSeverity severity{agent::OcsfSeverity::Unknown};
    agent::JournalMode source_mode{agent::JournalMode::Metadata};
    std::string source_unit;
};
struct SearchQuery {
    std::optional<agent::OcsfClass> class_uid;
    std::optional<agent::OcsfStatus> status_id;
    std::string_view binding; // Empty means all sources visible to this trusted caller.
    std::uint64_t from_ms{}, through_ms{std::numeric_limits<std::uint64_t>::max()}; // Inclusive source time.
    EventId after{};
    std::optional<std::uint64_t> revision;
    std::size_t limit{32};
    // All supplied filters are conjunctive; source_unit is exact, not a pattern.
    std::string_view source_unit;
    std::optional<agent::JournalMode> source_mode;
    std::optional<agent::OcsfCategory> category;
    std::optional<agent::OcsfSeverity> severity;
    std::optional<agent::OcsfActivity> activity;
    std::optional<agent::MappingResult> mapping;
};
// Shared query contract for both backends; not an authorization boundary.
[[nodiscard]] bool valid_search_query(const SearchQuery& query) noexcept;
[[nodiscard]] bool matches_search_query(const SearchQuery& query, const RawEvidence& raw,
    const agent::NormalizedEvent& event) noexcept;
[[nodiscard]] EventSummary summarize_event(const RawEvidence& raw, const agent::NormalizedEvent& event);
struct SearchPage {
    StoreStatus status{StoreStatus::Invalid};
    std::uint64_t revision{};
    std::vector<EventSummary> events;
    bool more{};
};
struct PendingPage {
    StoreStatus status{StoreStatus::Invalid};
    std::uint64_t revision{};
    std::vector<EventId> ids;
    bool more{};
};
struct RetentionPlan {
    std::uint64_t revision{}, before_received_ms{};
    std::size_t limit{};
    std::vector<EventId> ids;
};
struct RetentionPreview {
    StoreStatus status{StoreStatus::Invalid};
    std::optional<RetentionPlan> plan;
};
struct RetentionResult {
    StoreStatus status{StoreStatus::Invalid};
    std::size_t removed{};
};
// Immutable caller-supplied development policy. Zero age disables policy cleanup.
struct StoragePolicy {
    static constexpr std::size_t record_ceiling = 128;
    static constexpr std::size_t wire_ceiling = record_ceiling * 2048;
    static constexpr std::size_t page_ceiling = 2048;
    static constexpr std::size_t page_bytes = 4096;
    std::size_t record_limit{record_ceiling};
    std::size_t wire_byte_limit{wire_ceiling};
    std::size_t database_page_limit{page_ceiling};
    std::size_t warning_percent{80};
    std::uint64_t retention_ms{};
    std::size_t cleanup_batch{32};
};
struct DiskUsage {
    std::size_t allocated_pages{}, reusable_pages{};
    bool warning{};
};
struct StorageUsage {
    std::size_t records{}, wire_bytes{}, held{}, pending{};
    bool record_warning{}, wire_warning{};
    std::optional<DiskUsage> disk; // Absent for volatile storage.
};
[[nodiscard]] bool valid_storage_policy(const StoragePolicy& policy) noexcept;
[[nodiscard]] bool quota_warning(std::size_t used, std::size_t limit, std::size_t percent) noexcept;
// Single serialized trusted service owner. Authorization, clock acquisition and
// durable ACK adaptation belong to the caller. IDs/revisions are backend-scoped;
// never reuse a cursor or retention plan with another backend instance.
// Allocation errors may propagate; no unbounded input or implicit deletion.
class EventStore {
public:
    static constexpr std::size_t max_page = 32;
    virtual ~EventStore() = default;
    [[nodiscard]] const StoragePolicy& policy() const noexcept { return policy_; }
    [[nodiscard]] virtual ReadResult<StorageUsage> usage() const = 0;
    // Both calls require the same trusted clock snapshot. No implicit deletion.
    [[nodiscard]] RetentionPreview preview_cleanup(std::uint64_t now_ms) const;
    [[nodiscard]] RetentionResult apply_cleanup(std::uint64_t now_ms, const RetentionPlan& plan);
    [[nodiscard]] virtual Durability durability() const noexcept = 0;
    [[nodiscard]] virtual AppendResult append(const RawInput& input) = 0;
    [[nodiscard]] virtual IndexResult index(EventId id) = 0;
    [[nodiscard]] virtual ReadResult<RawEvidence> raw(EventId id) const = 0;
    [[nodiscard]] virtual ReadResult<agent::NormalizedEvent> normalized(EventId id) const = 0;
    [[nodiscard]] virtual SearchPage search(const SearchQuery& query) const = 0;
    [[nodiscard]] virtual PendingPage pending(EventId after, std::optional<std::uint64_t> revision,
        std::size_t limit) const = 0;
    [[nodiscard]] virtual StoreStatus set_hold(EventId id, bool held) = 0;
    [[nodiscard]] virtual RetentionPreview preview_retention(std::uint64_t before_received_ms,
        std::size_t limit) const = 0;
    [[nodiscard]] virtual RetentionResult apply_retention(const RetentionPlan& plan) = 0;
protected:
    explicit EventStore(StoragePolicy policy);
private:
    const StoragePolicy policy_;
};
// Reference backend only: never a durable ReceiptSink, no disk or network IO.
class MemoryEventStore final : public EventStore {
public:
    static constexpr std::size_t max_records = StoragePolicy::record_ceiling;
    explicit MemoryEventStore(StoragePolicy policy = {}) : EventStore(policy) {}
    MemoryEventStore(const MemoryEventStore&) = delete;
    MemoryEventStore& operator=(const MemoryEventStore&) = delete;
    [[nodiscard]] Durability durability() const noexcept override { return Durability::Volatile; }
    [[nodiscard]] ReadResult<StorageUsage> usage() const override;
    [[nodiscard]] AppendResult append(const RawInput& input) override;
    [[nodiscard]] IndexResult index(EventId id) override;
    [[nodiscard]] ReadResult<RawEvidence> raw(EventId id) const override;
    [[nodiscard]] ReadResult<agent::NormalizedEvent> normalized(EventId id) const override;
    [[nodiscard]] SearchPage search(const SearchQuery& query) const override;
    [[nodiscard]] PendingPage pending(EventId after, std::optional<std::uint64_t> revision,
        std::size_t limit) const override;
    [[nodiscard]] StoreStatus set_hold(EventId id, bool held) override;
    [[nodiscard]] RetentionPreview preview_retention(std::uint64_t before_received_ms,
        std::size_t limit) const override;
    [[nodiscard]] RetentionResult apply_retention(const RetentionPlan& plan) override;
private:
    struct Entry {
        RawEvidence raw;
        std::string cursor;
        std::optional<agent::NormalizedEvent> normalized;
    };
    std::vector<Entry> entries_;
    EventId next_id_{1};
    std::uint64_t revision_{1};
};
} // namespace knetsentry::storage
