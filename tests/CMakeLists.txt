# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: BSD-2-Clause

find_package(Python3 REQUIRED COMPONENTS Interpreter)
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

    # A real import/instantiation test, independent of a physical display.
    # Missing Kirigami/QML runtime modules MUST fail rather than be skipped.
    add_test(NAME knetsentry_kirigami_qml_startup
        COMMAND $<TARGET_FILE:knetsentry> --self-test-qml)
    set_tests_properties(knetsentry_kirigami_qml_startup PROPERTIES
        LABELS "smoke;desktop;qml"
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen;QT_QUICK_BACKEND=software;QT_QUICK_CONTROLS_STYLE=Basic"
        TIMEOUT 30)
    # M1.4: visit all seven pages through the actual QML router, reject an
    # invalid destination, and ensure top-level switches do not grow the stack.
    add_test(NAME knetsentry_primary_navigation
        COMMAND $<TARGET_FILE:knetsentry> --self-test-navigation)
    set_tests_properties(knetsentry_primary_navigation PROPERTIES
        LABELS "desktop;qml;navigation;regression"
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen;QT_QUICK_BACKEND=software;QT_QUICK_CONTROLS_STYLE=Basic"
        TIMEOUT 30)
    # Verify real QML replacement no longer emits the Kirigami PageRow
    # "created graphical object was not placed" warning. This separate
    # process is only run in non-instrumented configurations: sanitized QML
    # startup/navigation are already covered by the two scoped LSan tests.
    if(NOT KNETSENTRY_ENABLE_SANITIZERS)
        add_test(NAME knetsentry_navigation_qml_diagnostics
            COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/scripts/check_m14_runtime_diagnostics.py"
                --build-dir "${PROJECT_BINARY_DIR}")
        set_tests_properties(knetsentry_navigation_qml_diagnostics PROPERTIES
            LABELS "desktop;qml;navigation;regression"
            TIMEOUT 50)
    endif()
    # M1.5 visual integration executes the real Kirigami/QML module. Keep
    # this separate from LSan-scoped QML tests until its external leak budget
    # is independently qualified; the existing sanitized navigation test
    # still exercises every themed page and its lifetime.
    if(NOT KNETSENTRY_ENABLE_SANITIZERS)
        add_test(NAME knetsentry_visual_system
            COMMAND $<TARGET_FILE:knetsentry> --self-test-visual)
        set_tests_properties(knetsentry_visual_system PROPERTIES
            LABELS "desktop;qml;visual;regression"
            ENVIRONMENT "QT_QPA_PLATFORM=offscreen;QT_QUICK_BACKEND=software;QT_QUICK_CONTROLS_STYLE=Basic"
            TIMEOUT 30)
    endif()
    # The two observed third-party leak stacks are not KnetSentry leaks.
    # Scope LSan suppressions to this specific full-QML smoke test only;
    # keep detect_leaks=1 for the entire sanitizer preset. The negative
    # control below proves first-party leaks remain detectable.
    if(KNETSENTRY_ENABLE_SANITIZERS)
        set_property(TEST knetsentry_kirigami_qml_startup APPEND PROPERTY ENVIRONMENT
            "LSAN_OPTIONS=suppressions=${PROJECT_SOURCE_DIR}/tests/sanitizers/lsan_qml_third_party.supp:print_suppressions=1")
        set_property(TEST knetsentry_primary_navigation APPEND PROPERTY ENVIRONMENT
            "LSAN_OPTIONS=suppressions=${PROJECT_SOURCE_DIR}/tests/sanitizers/lsan_qml_third_party.supp:print_suppressions=1")
    endif()
endif()

# M1.2 actual build evidence: assert active compiler flags and (on Linux)
# release ELF properties, not only that options appear in CMake source.
add_test(NAME knetsentry_build_hardening
    COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/scripts/verify_m12_hardening.py"
            --build-dir "${PROJECT_BINARY_DIR}")
set_tests_properties(knetsentry_build_hardening PROPERTIES LABELS "security;build")

# Deliberately leak in a separate *test-only* process and require LSan to
# reject it, even with the same scoped QML third-party suppressions present.
# The fixture is never built into the GUI or manager, and only exists in
# instrumented configurations. The Python wrapper turns expected failure
# into a passing negative-control CTest without masking unexpected failures.
if(KNETSENTRY_ENABLE_SANITIZERS)
    add_executable(knetsentry_lsan_probe sanitizers/lsan_probe.cpp)
    knetsentry_apply_project_options(knetsentry_lsan_probe)
    add_test(NAME knetsentry_lsan_negative_control
        COMMAND "${Python3_EXECUTABLE}"
            "${PROJECT_SOURCE_DIR}/scripts/verify_m13_lsan.py"
            --probe "$<TARGET_FILE:knetsentry_lsan_probe>")
    set_tests_properties(knetsentry_lsan_negative_control PROPERTIES
        LABELS "security;sanitizer;regression"
        ENVIRONMENT "LSAN_OPTIONS=suppressions=${PROJECT_SOURCE_DIR}/tests/sanitizers/lsan_qml_third_party.supp:print_suppressions=1"
        TIMEOUT 30)
endif()
