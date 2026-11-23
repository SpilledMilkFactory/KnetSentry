# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: BSD-2-Clause

# The QML/Kirigami application shell and resource registration are M1.3.
# This bootstrap currently validates Qt integration in a headless-safe process.
add_executable(knetsentry main.cpp)
target_compile_features(knetsentry PRIVATE cxx_std_23)
knetsentry_apply_project_options(knetsentry)
target_link_libraries(knetsentry PRIVATE KnetSentry::Core Qt6::Core)
