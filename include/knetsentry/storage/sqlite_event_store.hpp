// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <knetsentry/storage/event_store.hpp>
#include <memory>

namespace knetsentry::storage {
// Development backend for minimized KSTD evidence and indexes. The caller must
// supply a dedicated, trusted, private local directory; not a production raw-volume
// selector or ReceiptSink. Serialized owner only. Opening failures throw a
// generic runtime_error; operation failures return typed storage outcomes.
enum class LegacyIntegrityPolicy { Reject, EstablishBaseline };
class SqliteEventStore final : public EventStore {
public:
    explicit SqliteEventStore(const std::string& directory,
        LegacyIntegrityPolicy legacy = LegacyIntegrityPolicy::Reject);
    ~SqliteEventStore() override;
    SqliteEventStore(const SqliteEventStore&) = delete;
    SqliteEventStore& operator=(const SqliteEventStore&) = delete;
    static constexpr std::size_t max_records = 128;
    [[nodiscard]] Durability durability() const noexcept override { return Durability::Durable; }
    [[nodiscard]] AppendResult append(const RawInput& input) override;
    [[nodiscard]] IndexResult index(EventId id) override;
    [[nodiscard]] ReadResult<RawEvidence> raw(EventId id) const override;
    [[nodiscard]] ReadResult<agent::NormalizedEvent> normalized(EventId id) const override;
    [[nodiscard]] SearchPage search(const SearchQuery& query) const override;
    [[nodiscard]] PendingPage pending(EventId after, std::optional<std::uint64_t> revision, std::size_t limit) const override;
    [[nodiscard]] StoreStatus set_hold(EventId id, bool held) override;
    [[nodiscard]] RetentionPreview preview_retention(std::uint64_t before_received_ms, std::size_t limit) const override;
    [[nodiscard]] RetentionResult apply_retention(const RetentionPlan& plan) override;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace knetsentry::storage
