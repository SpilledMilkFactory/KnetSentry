# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: BSD-2-Clause

add_library(knetsentry_core STATIC build_info.cpp diagnostics.cpp)
add_library(KnetSentry::Core ALIAS knetsentry_core)

target_compile_features(knetsentry_core PUBLIC cxx_std_23)
knetsentry_apply_project_options(knetsentry_core)
target_include_directories(knetsentry_core
    PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_compile_definitions(knetsentry_core
    PRIVATE KNETSENTRY_PROJECT_VERSION="${PROJECT_VERSION}")
set_target_properties(knetsentry_core PROPERTIES
    POSITION_INDEPENDENT_CODE ON)
