// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include "knetsentry/agent/lifecycle.hpp"
#include "knetsentry/agent/authentication.hpp"
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace knetsentry::agent {
enum class JournalMode { Metadata, Authentication, Audit };
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
std::unique_ptr<JournalSource> make_journal_source(std::string directory = {}, JournalMode mode = JournalMode::Metadata);
// Audit uses the fixed source marker "audit", not a service unit.
[[nodiscard]] bool parse_audit_number(std::string_view value, std::uint64_t& output) noexcept;
[[nodiscard]] bool valid_journal_unit(std::string_view unit) noexcept;
[[nodiscard]] bool valid_journal_directory(std::string_view path) noexcept;
class JournalCollector final : public Collector {
public:
    static constexpr std::size_t max_records = 128;
    static constexpr std::size_t batch_size = 16;
    JournalCollector(JournalSource& source, std::string unit, std::string directory,
                     JournalMode mode = JournalMode::Metadata);
    ~JournalCollector() override { stop(); }
    JournalCollector(const JournalCollector&) = delete;
    JournalCollector& operator=(const JournalCollector&) = delete;
    bool start() noexcept override;
    void stop() noexcept override;
    // False is terminal: no automatic reset, fallback, or skipping.
    [[nodiscard]] bool pump() noexcept;
    [[nodiscard]] std::size_t count() const noexcept { return count_; }
    [[nodiscard]] const char* error() const noexcept { return error_; }
private:
    bool fail(const char* reason) noexcept;
    bool load();
    bool commit(const JournalRecord& record);
    JournalSource& source_;
    JournalMode mode_;
    const char* state_name_;
    const char* pending_name_;
    std::string unit_, directory_, state_, cursor_;
    int fd_{-1};
    std::size_t count_{};
    std::vector<std::string> seen_;
    bool running_{};
    bool started_{};
    const char* error_{"not started"};
};
} // namespace knetsentry::agent
