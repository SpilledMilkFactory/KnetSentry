// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <knetsentry/storage/event_store.hpp>
#include <array>
#include <memory>

namespace knetsentry::storage {
// Explicit approval snapshot supplied by a trusted service owner, not an
// authorization token. Mount identifiers are boot/namespace scoped.
struct LocationApproval {
    std::string path, boot_id;
    std::uint64_t mount_id{}, device{}, inode{}, filesystem_type{};
    std::array<int, 2> filesystem_id{};
    bool development_overlay{};
    bool operator==(const LocationApproval&) const = default;
};
[[nodiscard]] LocationApproval inspect_storage_location(const std::string& path,
    bool development_overlay = false);
struct SplitStorageConfig {
    LocationApproval raw, index;
    StoragePolicy policy{};
    std::uint64_t reserve_bytes{1024 * 1024};
};
enum class SplitOpenMode { CreateNew, Existing };
// Bounded independent raw segment and SQLite projection foundation. No implicit
// migration, deletion, operational receipt adapter or desktop access.
class SplitEventStore final {
public:
    explicit SplitEventStore(const SplitStorageConfig& config, SplitOpenMode mode);
    ~SplitEventStore();
    SplitEventStore(const SplitEventStore&) = delete;
    SplitEventStore& operator=(const SplitEventStore&) = delete;
    [[nodiscard]] AppendResult append(const RawInput& input);
    [[nodiscard]] IndexResult index(EventId id);
    [[nodiscard]] ReadResult<RawEvidence> raw(EventId id) const;
    [[nodiscard]] SearchPage search(const SearchQuery& query) const;
    [[nodiscard]] PendingPage pending(EventId after, std::optional<std::uint64_t> revision,
        std::size_t limit) const;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace knetsentry::storage
