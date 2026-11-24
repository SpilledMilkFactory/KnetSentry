// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/service/health.hpp"

#include <array>
#include <limits>
#include <string_view>

int main() {
    using namespace knetsentry::service;
    constexpr auto max = std::numeric_limits<std::uint64_t>::max();
    constexpr auto signed_max = std::numeric_limits<std::int64_t>::max();
    if (cpu_time_ms(1, 999999, 2, 999999) != 4999U ||
        cpu_time_ms(0, 500, 0, 500) != 1U || cpu_time_ms(0, 0, 0, 0) != 0U ||
        cpu_time_ms(-1, 0, 0, 0) || cpu_time_ms(0, -1, 0, 0) ||
        cpu_time_ms(0, 1000000, 0, 0) || cpu_time_ms(0, 0, 0, 1000000) ||
        cpu_time_ms(signed_max, 0, signed_max, 0)) { return 1; }
    auto count = max - 1;
    saturating_increment(count);
    saturating_increment(count);
    if (count != max) { return 2; }

    constexpr std::string_view id = "0123456789abcdef";
    std::array<char, max_health_response_size> buffer{};
    HealthSnapshot snapshot{State::Running, max, {max, max}, true, max, max, max};
    const auto length = encode_health(snapshot, id, buffer);
    if (length == 0 || length > buffer.size() ||
        std::string_view(buffer.data(), length) !=
        "KSIPC/1 OK 0123456789abcdef HEALTH RUNNING 18446744073709551615 "
        "18446744073709551615 18446744073709551615 CONFIG_VALIDATED IPC_READY "
        "MONITORING_UNAVAILABLE 18446744073709551615 18446744073709551615 "
        "18446744073709551615\n") { return 3; }
    if (encode_health(snapshot, id, std::span<char>(buffer).first(length - 1)) != 0 ||
        encode_health(snapshot, id, {}) != 0 ||
        encode_health(snapshot, "0123456789abcdeG", buffer) != 0) { return 4; }
    snapshot.state = State::Failed;
    if (encode_health(snapshot, id, buffer) != 0) { return 5; }
    snapshot = {State::Running, 0, {}, false, 1, 2, 3};
    const auto unavailable = encode_health(snapshot, id, buffer);
    if (std::string_view(buffer.data(), unavailable) !=
        "KSIPC/1 OK 0123456789abcdef HEALTH RUNNING 0 NA NA CONFIG_DEFAULT "
        "IPC_READY MONITORING_UNAVAILABLE 1 2 3\n") { return 6; }

    HealthTracker tracker(false);
    tracker.record(HealthError::Rejected);
    tracker.record(HealthError::Transport);
    tracker.record(HealthError::Transport);
    tracker.record(HealthError::Sampling);
    const auto first = tracker.sample(State::Running);
    const auto second = tracker.sample(State::Running);
    if (first.state != State::Running || first.explicit_config || first.rejected != 1 ||
        first.transport_errors != 2 || first.sampling_errors != 1 ||
        !first.usage.cpu_ms || !first.usage.peak_rss_kib || *first.usage.peak_rss_kib == 0 ||
        !second.usage.cpu_ms || !second.usage.peak_rss_kib ||
        second.uptime_ms < first.uptime_ms || *second.usage.cpu_ms < *first.usage.cpu_ms ||
        *second.usage.peak_rss_kib < *first.usage.peak_rss_kib ||
        second.sampling_errors != 1) { return 7; }
    return 0;
}
