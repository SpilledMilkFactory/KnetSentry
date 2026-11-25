# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: BSD-2-Clause
add_executable(knetsentry-agent agent_main.cpp)
target_link_libraries(knetsentry-agent PRIVATE KnetSentry::AgentLifecycle KnetSentry::AgentJournal)
knetsentry_apply_project_options(knetsentry-agent)
