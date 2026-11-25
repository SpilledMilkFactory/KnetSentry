# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: BSD-2-Clause
add_library(knetsentry_agent_lifecycle STATIC lifecycle.cpp)
add_library(KnetSentry::AgentLifecycle ALIAS knetsentry_agent_lifecycle)
target_include_directories(knetsentry_agent_lifecycle PUBLIC "${PROJECT_SOURCE_DIR}/include")
knetsentry_apply_project_options(knetsentry_agent_lifecycle)

# M5.2: distro-provided shared systemd library; no downloaded or bundled dependencies.
find_package(PkgConfig REQUIRED)
pkg_check_modules(SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
add_library(knetsentry_agent_journal STATIC journal.cpp systemd_journal.cpp)
add_library(KnetSentry::AgentJournal ALIAS knetsentry_agent_journal)
target_link_libraries(knetsentry_agent_journal PUBLIC KnetSentry::AgentLifecycle PRIVATE PkgConfig::SYSTEMD)
knetsentry_apply_project_options(knetsentry_agent_journal)
