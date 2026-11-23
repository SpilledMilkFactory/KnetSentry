# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: BSD-2-Clause

add_executable(knetsentry_core_smoke core_smoke.cpp)
target_link_libraries(knetsentry_core_smoke PRIVATE KnetSentry::Core)
knetsentry_apply_project_options(knetsentry_core_smoke)

add_test(NAME knetsentry_core_build_identity
    COMMAND knetsentry_core_smoke)
set_tests_properties(knetsentry_core_build_identity PROPERTIES LABELS "unit;smoke")

if(KNETSENTRY_BUILD_DESKTOP)
    add_test(NAME knetsentry_desktop_version
        COMMAND $<TARGET_FILE:knetsentry> --version)
    set_tests_properties(knetsentry_desktop_version PROPERTIES LABELS "smoke;desktop")
endif()

# M1.2 actual build evidence: assert active compiler flags and (on Linux)
# release ELF properties, not only that options appear in CMake source.
find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(NAME knetsentry_build_hardening
    COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/scripts/verify_m12_hardening.py"
            --build-dir "${PROJECT_BINARY_DIR}")
set_tests_properties(knetsentry_build_hardening PROPERTIES LABELS "security;build")
