// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <knetsentry/core/enrollment.hpp>
#include <optional>
#include <span>
#include <string_view>

namespace knetsentry::service {
inline constexpr std::size_t max_roster_response_size = 4608;
// UNAVAILABLE is a valid response, distinct from an empty approved registry.
[[nodiscard]] std::size_t encode_roster(const enrollment::Roster& roster,
    std::string_view request_id, std::span<char> output) noexcept;
[[nodiscard]] std::optional<enrollment::Roster> decode_roster(
    std::string_view payload, std::string_view request_id) noexcept;
} // namespace knetsentry::service
