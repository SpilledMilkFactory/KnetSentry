// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/service/health.hpp"

#include <algorithm>
#include <charconv>
#include <limits>
#include <sys/resource.h>

namespace knetsentry::service {
namespace {
constexpr auto maximum = std::numeric_limits<std::uint64_t>::max();

class Encoder final {
public:
    explicit Encoder(std::span<char> output) noexcept : output_(output) {}
    bool text(std::string_view value) noexcept {
        if (value.size() > output_.size() - used_) { return false; }
        std::ranges::copy(value, output_.subspan(used_).begin());
        used_ += value.size();
        return true;
    }
    bool number(std::optional<std::uint64_t> value) noexcept {
        if (!value) { return text("NA"); }
        char digits[20]{};
        const auto result = std::to_chars(digits, digits + sizeof(digits), *value);
        return result.ec == std::errc{} &&
            text(std::string_view(digits, static_cast<std::size_t>(result.ptr - digits)));
    }
    [[nodiscard]] std::size_t size() const noexcept { return used_; }
private:
    std::span<char> output_;
    std::size_t used_{};
};
} // namespace

void saturating_increment(std::uint64_t& value) noexcept {
    if (value < maximum) { ++value; }
}

std::optional<std::uint64_t> cpu_time_ms(std::int64_t user_sec, std::int64_t user_usec,
    std::int64_t system_sec, std::int64_t system_usec) noexcept {
    if (user_sec < 0 || system_sec < 0 || user_usec < 0 || user_usec >= 1000000 ||
        system_usec < 0 || system_usec >= 1000000) { return std::nullopt; }
    const auto user = static_cast<std::uint64_t>(user_sec);
    const auto system = static_cast<std::uint64_t>(system_sec);
    const auto fraction = static_cast<std::uint64_t>((user_usec + system_usec) / 1000);
    if (user > maximum - system) { return std::nullopt; }
    const auto seconds = user + system;
    if (seconds > (maximum - fraction) / 1000U) { return std::nullopt; }
    return seconds * 1000U + fraction;
}

HealthTracker::HealthTracker(bool explicit_config) noexcept
    : started_(std::chrono::steady_clock::now()), explicit_config_(explicit_config) {}

void HealthTracker::record(HealthError error) noexcept {
    switch (error) {
    case HealthError::Rejected: saturating_increment(rejected_); break;
    case HealthError::Transport: saturating_increment(transport_errors_); break;
    case HealthError::Sampling: saturating_increment(sampling_errors_); break;
    }
}

HealthSnapshot HealthTracker::sample(State state) noexcept {
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started_).count();
    ResourceUsage usage{};
    struct rusage stats{};
    if (::getrusage(RUSAGE_SELF, &stats) == 0) {
        usage.cpu_ms = cpu_time_ms(stats.ru_utime.tv_sec, stats.ru_utime.tv_usec,
                                  stats.ru_stime.tv_sec, stats.ru_stime.tv_usec);
        if (stats.ru_maxrss > 0) {
            usage.peak_rss_kib = static_cast<std::uint64_t>(stats.ru_maxrss);
        }
    }
    if (!usage.cpu_ms || !usage.peak_rss_kib) { record(HealthError::Sampling); }
    return {state, elapsed < 0 ? 0U : static_cast<std::uint64_t>(elapsed), usage,
            explicit_config_, rejected_, transport_errors_, sampling_errors_};
}

std::size_t encode_health(const HealthSnapshot& snapshot, std::string_view request_id,
    std::span<char> output) noexcept {
    if (snapshot.state != State::Running || request_id.size() != 16 ||
        !std::ranges::all_of(request_id, [](char c) {
            return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        })) { return 0; }
    Encoder encoder(output.first(std::min(output.size(), max_health_response_size)));
    if (!(encoder.text("KSIPC/1 OK ") && encoder.text(request_id) &&
        encoder.text(" HEALTH RUNNING ") && encoder.number(snapshot.uptime_ms) &&
        encoder.text(" ") && encoder.number(snapshot.usage.cpu_ms) &&
        encoder.text(" ") && encoder.number(snapshot.usage.peak_rss_kib) &&
        encoder.text(snapshot.explicit_config ? " CONFIG_VALIDATED" : " CONFIG_DEFAULT") &&
        encoder.text(" IPC_READY MONITORING_UNAVAILABLE ") && encoder.number(snapshot.rejected) &&
        encoder.text(" ") && encoder.number(snapshot.transport_errors) &&
        encoder.text(" ") && encoder.number(snapshot.sampling_errors) && encoder.text("\n"))) {
        return 0;
    }
    return encoder.size();
}
} // namespace knetsentry::service
