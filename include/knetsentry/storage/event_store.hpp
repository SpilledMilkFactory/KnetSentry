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
};
struct SearchQuery {
    std::optional<agent::OcsfClass> class_uid;
    std::optional<agent::OcsfStatus> status_id;
    std::string_view binding; // Empty means all sources visible to this trusted caller.
    std::uint64_t from_ms{}, through_ms{std::numeric_limits<std::uint64_t>::max()}; // Inclusive source time.
    EventId after{};
    std::optional<std::uint64_t> revision;
    std::size_t limit{32};
};
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
// Single serialized trusted service owner. Authorization, clock acquisition and
// durable ACK adaptation belong to the caller. IDs/revisions are backend-scoped;
// never reuse a cursor or retention plan with another backend instance.
// Allocation errors may propagate; no unbounded input or implicit deletion.
class EventStore {
public:
    static constexpr std::size_t max_page = 32;
    virtual ~EventStore() = default;
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
};
// Reference backend only: never a durable ReceiptSink, no disk or network IO.
class MemoryEventStore final : public EventStore {
public:
    static constexpr std::size_t max_records = 128;
    MemoryEventStore() = default;
    MemoryEventStore(const MemoryEventStore&) = delete;
    MemoryEventStore& operator=(const MemoryEventStore&) = delete;
    [[nodiscard]] Durability durability() const noexcept override { return Durability::Volatile; }
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
