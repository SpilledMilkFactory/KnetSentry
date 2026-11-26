// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <string>
#include <string_view>
#include <vector>

namespace knetsentry::agent {
struct PrivacyDecision {
    std::string fingerprint;
    bool redact_auth{};
    bool redact_slot{};
    bool redact_content{};
};
// A startup snapshot of explicit operator policy, not enrollment or OS authority.
// Reject unknown, duplicate, incompatible and denied selections before collection.
[[nodiscard]] bool authorize_privacy(std::string_view policy, std::string_view collector,
    std::string_view unit, const std::vector<std::string>& paths, bool buffered, PrivacyDecision& decision);
} // namespace knetsentry::agent
