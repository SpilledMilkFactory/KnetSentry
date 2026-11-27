// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include "knetsentry/agent/lifecycle.hpp"
#include "knetsentry/agent/authentication.hpp"
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace knetsentry::agent {
enum class JournalMode { Metadata = 0, Authentication = 1, Audit = 2, Unsupported = 3 };
// Decode an untrusted numeric mode before it enters a typed interface.
[[nodiscard]] constexpr JournalMode decode_journal_mode(std::int64_t value) noexcept {
    switch (value) {
    case 0: return JournalMode::Metadata;
    case 1: return JournalMode::Authentication;
    case 2: return JournalMode::Audit;
    default: return JournalMode::Unsupported;
    }
}
struct JournalRecord {
    std::string cursor, unit, machine, boot;
    std::uint64_t realtime_usec{}, monotonic_usec{};
    AuthEvent auth{AuthEvent::None};
    std::uint64_t audit_type{}, audit_id{};
};
enum class JournalResult { Record, End, Error };
class JournalSource {
public:
    virtual ~JournalSource() = default;
    virtual bool open(std::string_view unit) = 0;
    // Position strictly after an exact checkpoint, or at the beginning for empty.
    virtual bool resume(std::string_view cursor) = 0;
    virtual JournalResult next(JournalRecord& record) = 0;
    virtual void close() noexcept = 0;
};
// An empty directory argument uses the local journal. Nonempty is for isolated tests only.
std::unique_ptr<JournalSource> make_journal_source(std::string directory = {}, JournalMode mode = JournalMode::Metadata, bool redact_auth = false);
// Audit uses the fixed source marker "audit", not a service unit.
[[nodiscard]] bool parse_audit_number(std::string_view value, std::uint64_t& output) noexcept;
[[nodiscard]] bool valid_journal_unit(std::string_view unit) noexcept;
[[nodiscard]] bool valid_journal_directory(std::string_view path) noexcept;
[[nodiscard]] bool valid_delivery_binding(std::string_view binding) noexcept;
class DeliverySender;
// Canonical wire row validation shared by the local spool and receiver.
[[nodiscard]] std::optional<JournalRecord> parse_delivery_row(std::string_view row, std::string_view unit, JournalMode mode);
[[nodiscard]] bool valid_delivery_row(std::string_view row, std::string_view unit, JournalMode mode);
class JournalCollector final : public Collector {
public:
    static constexpr std::size_t max_records = 128;
    static constexpr std::size_t batch_size = 16;
    JournalCollector(JournalSource& source, std::string unit, std::string directory,
                     JournalMode mode = JournalMode::Metadata, std::string binding = {},
                     std::string privacy_fingerprint = {}, bool redact_auth = false);
    ~JournalCollector() override { stop(); }
    JournalCollector(const JournalCollector&) = delete;
    JournalCollector& operator=(const JournalCollector&) = delete;
    bool start() noexcept override;
    void stop() noexcept override;
    // False stops collection: no automatic reset, fallback, or skipping.
    // Buffered source failures leave already committed records deliverable.
    [[nodiscard]] bool pump() noexcept;
    [[nodiscard]] std::size_t count() const noexcept { return count_; }
    [[nodiscard]] bool backpressured() const noexcept { return !binding_.empty() && count_ >= max_records; }
    [[nodiscard]] bool collection_blocked() const noexcept { return collection_blocked_; }
    [[nodiscard]] bool source_failed() const noexcept { return source_failed_; }
    [[nodiscard]] const char* error() const noexcept { return error_; }
private:
    friend class DeliverySender;
    [[nodiscard]] std::string_view front() const noexcept;
    bool acknowledge(std::string_view expected) noexcept;
    bool replace_state(std::string_view next);
    bool fail(const char* reason) noexcept;
    bool block_source(const char* reason) noexcept;
    bool load();
    bool commit(const JournalRecord& record);
    JournalSource& source_;
    JournalMode mode_;
    const char* state_name_;
    const char* pending_name_;
    std::string unit_, directory_, state_, cursor_, binding_;
    std::string header_, privacy_fingerprint_;
    bool redact_auth_{};
    std::vector<std::string> queued_;
    int fd_{-1};
    std::size_t count_{};
    std::vector<std::string> seen_;
    bool running_{};
    bool collection_blocked_{};
    bool source_failed_{};
    bool sending_{};
    bool started_{};
    const char* error_{"not started"};
};
} // namespace knetsentry::agent
