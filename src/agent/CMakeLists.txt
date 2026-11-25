# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: BSD-2-Clause
add_library(knetsentry_agent_lifecycle STATIC lifecycle.cpp)
add_library(KnetSentry::AgentLifecycle ALIAS knetsentry_agent_lifecycle)
target_include_directories(knetsentry_agent_lifecycle PUBLIC "${PROJECT_SOURCE_DIR}/include")
knetsentry_apply_project_options(knetsentry_agent_lifecycle)
