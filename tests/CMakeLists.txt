# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: BSD-2-Clause

add_executable(knetsentry_core_smoke core_smoke.cpp)
target_link_libraries(knetsentry_core_smoke PRIVATE KnetSentry::Core)

add_test(NAME knetsentry_core_build_identity
    COMMAND knetsentry_core_smoke)
set_tests_properties(knetsentry_core_build_identity PROPERTIES LABELS "unit;smoke")

if(KNETSENTRY_BUILD_DESKTOP)
    add_test(NAME knetsentry_desktop_version
        COMMAND $<TARGET_FILE:knetsentry> --version)
    set_tests_properties(knetsentry_desktop_version PROPERTIES LABELS "smoke;desktop")
endif()
