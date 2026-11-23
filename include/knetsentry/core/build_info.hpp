// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once

#include <string_view>

namespace knetsentry::core {

// Static, non-sensitive build identity. No network, filesystem, or GUI access.
[[nodiscard]] std::string_view product_name() noexcept;
[[nodiscard]] std::string_view project_version() noexcept;
[[nodiscard]] std::string_view implementation_state() noexcept;

} // namespace knetsentry::core
