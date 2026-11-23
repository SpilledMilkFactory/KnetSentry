// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/core/build_info.hpp"

#include <iostream>
#include <string_view>

int main() {
    using namespace std::literals;
    if (knetsentry::core::product_name() != "KnetSentry"sv ||
        knetsentry::core::project_version().empty() ||
        knetsentry::core::implementation_state().find("M1.1") == std::string_view::npos) {
        std::cerr << "KnetSentry build contract failed\n";
        return 1;
    }
    return 0;
}
