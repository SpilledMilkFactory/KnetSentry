# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: BSD-2-Clause
find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto)
add_executable(knetsentry-agent agent_main.cpp privacy.cpp)
target_link_libraries(knetsentry-agent PRIVATE KnetSentry::AgentLifecycle KnetSentry::AgentJournal KnetSentry::AgentFIM OpenSSL::Crypto)
knetsentry_apply_project_options(knetsentry-agent)
