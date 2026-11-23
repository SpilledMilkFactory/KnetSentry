// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/core/build_info.hpp"

namespace knetsentry::core {

std::string_view product_name() noexcept { return "KnetSentry"; }

std::string_view project_version() noexcept {
    return KNETSENTRY_PROJECT_VERSION;
}

std::string_view implementation_state() noexcept {
    return "M1.1 build foundation (no operational SIEM)";
}

} // namespace knetsentry::core
