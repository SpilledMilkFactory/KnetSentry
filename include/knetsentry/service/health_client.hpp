// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once

#include "knetsentry/service/health.hpp"

#include <array>
#include <chrono>
#include <optional>
#include <string_view>

namespace knetsentry::service {

// Client-side validation of the untrusted KSIPC/1 health payload.
[[nodiscard]] std::optional<HealthSnapshot> decode_health(
    std::string_view payload, std::string_view request_id) noexcept;

enum class HealthQueryState { Idle, Pending, Available, Unavailable, Invalid };

// One nonblocking Unix-domain exchange. No worker threads, network sockets,
// daemon discovery or administrative operations. Call advance from an event loop.
class HealthClient final {
public:
    HealthClient() = default;
    ~HealthClient() noexcept;
    HealthClient(const HealthClient&) = delete;
    HealthClient& operator=(const HealthClient&) = delete;
    void begin(std::string_view directory, std::string_view request_id) noexcept;
    void advance() noexcept;
    void cancel() noexcept;
    [[nodiscard]] HealthQueryState state() const noexcept { return state_; }
    [[nodiscard]] const std::optional<HealthSnapshot>& snapshot() const noexcept { return snapshot_; }
private:
    void finish(HealthQueryState state) noexcept;
    [[nodiscard]] bool verify_peer() const noexcept;
    enum class Phase { Connect, Send, Receive };
    int fd_{-1};
    Phase phase_{Phase::Connect};
    HealthQueryState state_{HealthQueryState::Idle};
    std::chrono::steady_clock::time_point deadline_{};
    std::array<char, 16> request_id_{};
    std::array<char, 64> request_{};
    std::size_t request_size_{0};
    std::size_t sent_{0};
    // One extra byte detects oversized/trailing data without allocating.
    std::array<char, max_health_response_size + 5> response_{};
    std::size_t received_{0};
    std::optional<HealthSnapshot> snapshot_{};
};

} // namespace knetsentry::service
