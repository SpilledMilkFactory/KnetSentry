# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: BSD-2-Clause

find_package(Threads REQUIRED)
add_executable(knetsentryd main.cpp)
target_link_libraries(knetsentryd PRIVATE
    KnetSentry::Core KnetSentry::Service Threads::Threads)
knetsentry_apply_project_options(knetsentryd)
