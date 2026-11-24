// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once

#include "knetsentry/service/lifecycle.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace knetsentry::service {

inline constexpr std::size_t max_health_response_size = 256;

enum class HealthError : unsigned char { Rejected, Transport, Sampling };

struct ResourceUsage {
    std::optional<std::uint64_t> cpu_ms;
    std::optional<std::uint64_t> peak_rss_kib;
};

struct HealthSnapshot {
    State state;
    std::uint64_t uptime_ms;
    ResourceUsage usage;
    bool explicit_config;
    std::uint64_t rejected;
    std::uint64_t transport_errors;
    std::uint64_t sampling_errors;
};

// Single-thread-owned, constant-space process health; never stores peer data.
class HealthTracker final {
public:
    explicit HealthTracker(bool explicit_config) noexcept;
    void record(HealthError error) noexcept;
    [[nodiscard]] HealthSnapshot sample(State state) noexcept;

private:
    std::chrono::steady_clock::time_point started_;
    bool explicit_config_;
    std::uint64_t rejected_{};
    std::uint64_t transport_errors_{};
    std::uint64_t sampling_errors_{};
};

// Strict fixed-field encoding. Returns zero for invalid input or insufficient
// capacity; callers must never send a partial result. IPC is ready only while
// serving a running manager. No caller-provided text except a validated ID.
[[nodiscard]] std::size_t encode_health(const HealthSnapshot& snapshot,
    std::string_view request_id, std::span<char> output) noexcept;

// Checked arithmetic also used for deterministic boundary tests.
[[nodiscard]] std::optional<std::uint64_t> cpu_time_ms(
    std::int64_t user_sec, std::int64_t user_usec,
    std::int64_t system_sec, std::int64_t system_usec) noexcept;
void saturating_increment(std::uint64_t& value) noexcept;

} // namespace knetsentry::service
