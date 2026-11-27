# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: BSD-2-Clause

add_library(knetsentry_service STATIC lifecycle.cpp configuration.cpp local_ipc.cpp health.cpp audit.cpp health_client.cpp agent_roster.cpp event_query.cpp alert_query.cpp)
add_library(KnetSentry::Service ALIAS knetsentry_service)
target_include_directories(knetsentry_service PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_compile_features(knetsentry_service PUBLIC cxx_std_23)
target_link_libraries(knetsentry_service PRIVATE KnetSentry::Registry KnetSentry::EventStorage KnetSentry::Detection)
knetsentry_apply_project_options(knetsentry_service)
