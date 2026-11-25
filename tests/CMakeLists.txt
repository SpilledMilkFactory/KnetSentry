# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: BSD-2-Clause

find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_executable(knetsentry_core_smoke core_smoke.cpp)
target_link_libraries(knetsentry_core_smoke PRIVATE KnetSentry::Core)
knetsentry_apply_project_options(knetsentry_core_smoke)

add_test(NAME knetsentry_core_build_identity
    COMMAND knetsentry_core_smoke)
set_tests_properties(knetsentry_core_build_identity PROPERTIES LABELS "unit;smoke")

# M1.6: Qt-independent structured diagnostics, bounded JSONL formatting,
# redaction, sink failure and concurrent sequence verification. The Python
# wrapper must parse actual compiled output; zero emitted records is failure.
find_package(Threads REQUIRED)
add_executable(knetsentry_diagnostics_probe diagnostics_smoke.cpp)
target_link_libraries(knetsentry_diagnostics_probe PRIVATE
    KnetSentry::Core Threads::Threads)
knetsentry_apply_project_options(knetsentry_diagnostics_probe)
add_test(NAME knetsentry_structured_diagnostics
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/scripts/verify_m16_diagnostics.py"
        --probe "$<TARGET_FILE:knetsentry_diagnostics_probe>")
set_tests_properties(knetsentry_structured_diagnostics PROPERTIES
    LABELS "security;unit;privacy;regression" TIMEOUT 30)

# M1.7: validate actual configured test inventory; never allow zero-test PASS
# or a core-only CTest run to qualify the Qt desktop.
add_test(NAME knetsentry_configuration_contract
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/scripts/verify_m17_suites.py"
        --build-dir "${PROJECT_BINARY_DIR}")
set_tests_properties(knetsentry_configuration_contract PROPERTIES
    LABELS "configuration;security;regression" TIMEOUT 30)

# M1.7 independent first-party unit boundary and privacy regression.
add_executable(knetsentry_core_contract_m17 core_contract_m17.cpp)
target_link_libraries(knetsentry_core_contract_m17 PRIVATE KnetSentry::Core)
knetsentry_apply_project_options(knetsentry_core_contract_m17)
add_test(NAME knetsentry_core_boundary_contract
    COMMAND $<TARGET_FILE:knetsentry_core_contract_m17>)
set_tests_properties(knetsentry_core_boundary_contract PROPERTIES
    LABELS "unit;security;privacy;regression" TIMEOUT 30)

# M3.1: pure network-scope preflight, no live IP communication.
add_executable(knetsentry_network_scope_test network_scope_m31.cpp)
target_link_libraries(knetsentry_network_scope_test PRIVATE KnetSentry::Core)
knetsentry_apply_project_options(knetsentry_network_scope_test)
add_test(NAME knetsentry_network_scope_policy
    COMMAND $<TARGET_FILE:knetsentry_network_scope_test>)
set_tests_properties(knetsentry_network_scope_policy PROPERTIES
    LABELS "unit;security;network;regression" TIMEOUT 15)

# M3.2: dual-stack prefix validation on the same policy boundary.
add_executable(knetsentry_network_prefix_test network_scope_m32.cpp)
target_link_libraries(knetsentry_network_prefix_test PRIVATE KnetSentry::Core)
knetsentry_apply_project_options(knetsentry_network_prefix_test)
add_test(NAME knetsentry_network_prefix_validation
    COMMAND $<TARGET_FILE:knetsentry_network_prefix_test>)
set_tests_properties(knetsentry_network_prefix_validation PROPERTIES
    LABELS "unit;security;network;regression" TIMEOUT 15)

# M3.3: read-only Linux topology, strict fixtures and actual kernel replies.
add_executable(knetsentry_network_topology_test network_topology_m33.cpp)
target_include_directories(knetsentry_network_topology_test PRIVATE "${PROJECT_SOURCE_DIR}/src/core")
target_link_libraries(knetsentry_network_topology_test PRIVATE KnetSentry::Core Threads::Threads)
knetsentry_apply_project_options(knetsentry_network_topology_test)
add_test(NAME knetsentry_network_topology_awareness
    COMMAND $<TARGET_FILE:knetsentry_network_topology_test>)
set_tests_properties(knetsentry_network_topology_awareness PROPERTIES
    LABELS "unit;security;network;regression" TIMEOUT 15)

# M3.4: fail-closed activation and topology-aware preflight lifecycle.
add_executable(knetsentry_network_authorization_test network_authorization_m34.cpp)
target_link_libraries(knetsentry_network_authorization_test PRIVATE KnetSentry::Core)
knetsentry_apply_project_options(knetsentry_network_authorization_test)
add_test(NAME knetsentry_network_fail_closed_authorization
    COMMAND $<TARGET_FILE:knetsentry_network_authorization_test>)
set_tests_properties(knetsentry_network_fail_closed_authorization PROPERTIES
    LABELS "unit;security;network;regression" TIMEOUT 15)

# M3.5: unprivileged rule-generation and strict applied-policy fixtures.
add_test(NAME knetsentry_firewall_profile_contract
    COMMAND "${Python3_EXECUTABLE}" -B
        "${PROJECT_SOURCE_DIR}/scripts/verify_m35_firewall.py")
set_tests_properties(knetsentry_firewall_profile_contract PROPERTIES
    LABELS "unit;security;network;regression" TIMEOUT 15)

# M3.6: mandatory offline policy fixture; privileged live fixture is explicit.
add_executable(knetsentry_network_isolation_test network_isolation_m36.cpp)
target_include_directories(knetsentry_network_isolation_test PRIVATE "${PROJECT_SOURCE_DIR}/src/core")
target_link_libraries(knetsentry_network_isolation_test PRIVATE KnetSentry::Core Threads::Threads)
knetsentry_apply_project_options(knetsentry_network_isolation_test)
add_test(NAME knetsentry_network_isolation_fixture
    COMMAND $<TARGET_FILE:knetsentry_network_isolation_test>)
set_tests_properties(knetsentry_network_isolation_fixture PROPERTIES
    LABELS "unit;security;network;regression" TIMEOUT 15)

# M3.7: offline adversarial policy matrix using the existing fixture binary.
add_test(NAME knetsentry_network_adversarial_boundary
    COMMAND $<TARGET_FILE:knetsentry_network_isolation_test> --adversarial)
set_tests_properties(knetsentry_network_adversarial_boundary PROPERTIES
    LABELS "unit;security;network;regression" TIMEOUT 15)

# M2.1 management process: test explicit state transitions and real POSIX
# shutdown from a separate process, including both supported stop signals.
add_executable(knetsentry_service_lifecycle_test service_lifecycle_m21.cpp)
target_link_libraries(knetsentry_service_lifecycle_test PRIVATE KnetSentry::Service)
knetsentry_apply_project_options(knetsentry_service_lifecycle_test)
add_test(NAME knetsentry_manager_state_contract
    COMMAND $<TARGET_FILE:knetsentry_service_lifecycle_test>)
set_tests_properties(knetsentry_manager_state_contract PROPERTIES
    LABELS "unit;security;service;regression" TIMEOUT 15)

add_test(NAME knetsentry_manager_signal_lifecycle
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/scripts/check_m21_manager_runtime.py"
        --binary "$<TARGET_FILE:knetsentryd>")
set_tests_properties(knetsentry_manager_signal_lifecycle PROPERTIES
    LABELS "integration;security;service;regression" TIMEOUT 45)

# M2.2 strict versioned manager config: compiled schema tests and real process
# rejection of missing, unsafe, future-version and forbidden settings.
add_executable(knetsentry_service_configuration_test service_configuration_m22.cpp)
target_link_libraries(knetsentry_service_configuration_test PRIVATE KnetSentry::Service)
knetsentry_apply_project_options(knetsentry_service_configuration_test)
add_test(NAME knetsentry_manager_configuration_contract
    COMMAND $<TARGET_FILE:knetsentry_service_configuration_test>)
set_tests_properties(knetsentry_manager_configuration_contract PROPERTIES
    LABELS "unit;security;service;configuration;regression" TIMEOUT 20)

add_test(NAME knetsentry_manager_configuration_runtime
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/scripts/check_m22_config_runtime.py"
        --binary "$<TARGET_FILE:knetsentryd>")
set_tests_properties(knetsentry_manager_configuration_runtime PROPERTIES
    LABELS "integration;security;service;configuration;regression" TIMEOUT 50)

# M2.3 I-01/TB-05: kernel peer credentials, deny-by-default role mapping,
# versioned framed protocol and real hostile AF_UNIX clients.
add_executable(knetsentry_service_ipc_test service_ipc_m23.cpp)
target_link_libraries(knetsentry_service_ipc_test PRIVATE KnetSentry::Service)
knetsentry_apply_project_options(knetsentry_service_ipc_test)
add_test(NAME knetsentry_local_ipc_authorization_contract
    COMMAND $<TARGET_FILE:knetsentry_service_ipc_test>)
set_tests_properties(knetsentry_local_ipc_authorization_contract PROPERTIES
    LABELS "unit;security;ipc;service;regression" TIMEOUT 20)

add_test(NAME knetsentry_local_ipc_runtime
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/scripts/check_m23_ipc_runtime.py"
        --binary "$<TARGET_FILE:knetsentryd>")
set_tests_properties(knetsentry_local_ipc_runtime PROPERTIES
    LABELS "integration;security;ipc;service;regression" TIMEOUT 60)

# M2.4: bounded health encoding, measured resources and authorized live IPC.
add_executable(knetsentry_service_health_test service_health_m24.cpp)
target_link_libraries(knetsentry_service_health_test PRIVATE KnetSentry::Service)
knetsentry_apply_project_options(knetsentry_service_health_test)
add_test(NAME knetsentry_service_health_contract
    COMMAND $<TARGET_FILE:knetsentry_service_health_test>)
set_tests_properties(knetsentry_service_health_contract PROPERTIES
    LABELS "unit;security;service;regression" TIMEOUT 20)
add_test(NAME knetsentry_service_health_runtime
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/scripts/check_m24_health_runtime.py"
        --binary "$<TARGET_FILE:knetsentryd>")
set_tests_properties(knetsentry_service_health_runtime PROPERTIES
    LABELS "integration;security;ipc;service;regression" TIMEOUT 60)

# M2.5: protected bounded audit sink and live fail-closed integration.
add_executable(knetsentry_service_audit_test service_audit_m25.cpp)
target_link_libraries(knetsentry_service_audit_test PRIVATE KnetSentry::Service)
knetsentry_apply_project_options(knetsentry_service_audit_test)
add_test(NAME knetsentry_service_audit_contract
    COMMAND $<TARGET_FILE:knetsentry_service_audit_test>)
set_tests_properties(knetsentry_service_audit_contract PROPERTIES
    LABELS "unit;security;privacy;service;regression" TIMEOUT 60)
add_test(NAME knetsentry_service_audit_runtime
    COMMAND "${Python3_EXECUTABLE}"
        "${PROJECT_SOURCE_DIR}/scripts/check_m25_audit_runtime.py"
        --binary $<TARGET_FILE:knetsentryd>)
set_tests_properties(knetsentry_service_audit_runtime PROPERTIES
    LABELS "integration;security;privacy;ipc;service;regression" TIMEOUT 60)

# M2.6: native client remains independently testable without Qt.
add_executable(knetsentry_health_client_test service_health_client_m26.cpp)
target_link_libraries(knetsentry_health_client_test PRIVATE KnetSentry::Service)
knetsentry_apply_project_options(knetsentry_health_client_test)
add_test(NAME knetsentry_health_client_contract COMMAND $<TARGET_FILE:knetsentry_health_client_test>)
set_tests_properties(knetsentry_health_client_contract PROPERTIES
    LABELS "unit;security;ipc;regression" TIMEOUT 15)
add_test(NAME knetsentry_health_client_runtime
    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/check_m26_health_client.py"
        --probe $<TARGET_FILE:knetsentry_health_client_test> --manager $<TARGET_FILE:knetsentryd>)
set_tests_properties(knetsentry_health_client_runtime PROPERTIES
    LABELS "integration;security;ipc;regression" TIMEOUT 40)

# M2.7: portable policy regression; actual systemd sandbox requires a booted host.
add_test(NAME knetsentry_systemd_policy_contract
    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/verify_m27_systemd.py")
set_tests_properties(knetsentry_systemd_policy_contract PROPERTIES
    LABELS "security;service;configuration;regression" TIMEOUT 15)

# M2.8: real foreground process transitions and authenticated IPC recovery.
add_test(NAME knetsentry_service_lifecycle_ipc_integration
    COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/check_m28_lifecycle_ipc.py"
        --manager $<TARGET_FILE:knetsentryd> --probe $<TARGET_FILE:knetsentry_health_client_test>)
set_tests_properties(knetsentry_service_lifecycle_ipc_integration PROPERTIES
    LABELS "integration;security;ipc;service;privacy;regression" TIMEOUT 90)

if(KNETSENTRY_BUILD_DESKTOP)
    # Qt Test is required for full desktop test qualification, not silently
    # skipped if unavailable. The core-only preset remains Qt-independent.
    find_package(Qt6 REQUIRED COMPONENTS Test)

    add_executable(knetsentry_qt_health_test qt/service_health_qtest.cpp
        ../apps/desktop/service_health_model.cpp ../apps/desktop/service_health_model.hpp)
    set_target_properties(knetsentry_qt_health_test PROPERTIES AUTOMOC ON)
    target_include_directories(knetsentry_qt_health_test PRIVATE "${PROJECT_SOURCE_DIR}/apps/desktop")
    target_link_libraries(knetsentry_qt_health_test PRIVATE KnetSentry::Service Qt6::Core Qt6::Qml Qt6::Test)
    knetsentry_apply_project_options(knetsentry_qt_health_test)
    add_test(NAME knetsentry_qt_health_model COMMAND $<TARGET_FILE:knetsentry_qt_health_test>)
    set_tests_properties(knetsentry_qt_health_model PROPERTIES
        LABELS "qt;model;security;regression" TIMEOUT 15)
    add_executable(knetsentry_qt_daemon_control_test qt/daemon_control_qtest.cpp
        ../apps/desktop/daemon_control.cpp ../apps/desktop/daemon_control.hpp
        ../apps/desktop/service_health_model.cpp ../apps/desktop/service_health_model.hpp)
    set_target_properties(knetsentry_qt_daemon_control_test PROPERTIES AUTOMOC ON)
    target_include_directories(knetsentry_qt_daemon_control_test PRIVATE "${PROJECT_SOURCE_DIR}/apps/desktop")
    target_compile_definitions(knetsentry_qt_daemon_control_test PRIVATE
        KNETSENTRY_MANAGER_EXECUTABLE="$<TARGET_FILE:knetsentryd>")
    target_link_libraries(knetsentry_qt_daemon_control_test PRIVATE KnetSentry::Service Qt6::Core Qt6::Qml Qt6::Test)
    knetsentry_apply_project_options(knetsentry_qt_daemon_control_test)
    add_dependencies(knetsentry_qt_daemon_control_test knetsentryd)
    add_test(NAME knetsentry_qt_daemon_control COMMAND $<TARGET_FILE:knetsentry_qt_daemon_control_test>)
    set_tests_properties(knetsentry_qt_daemon_control PROPERTIES
        LABELS "qt;model;security;integration;regression" TIMEOUT 35)
    if(NOT KNETSENTRY_ENABLE_SANITIZERS)
        add_test(NAME knetsentry_gui_daemon_toolbar
            COMMAND $<TARGET_FILE:knetsentry> --self-test-daemon-controls)
        set_tests_properties(knetsentry_gui_daemon_toolbar PROPERTIES
            ENVIRONMENT "QT_QPA_PLATFORM=offscreen;QT_QUICK_BACKEND=software;QT_QUICK_CONTROLS_STYLE=Basic"
            LABELS "qt;desktop;qml;integration;security;regression" TIMEOUT 30)
    endif()

    # No new QML leak suppression: the model is always instrumented, and the
    # existing sanitized QML startup/navigation tests instantiate its bindings.
    if(NOT KNETSENTRY_ENABLE_SANITIZERS)
        add_test(NAME knetsentry_gui_health_runtime
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/scripts/check_m26_gui_runtime.py"
                --desktop $<TARGET_FILE:knetsentry> --manager $<TARGET_FILE:knetsentryd>)
        set_tests_properties(knetsentry_gui_health_runtime PROPERTIES
            LABELS "qt;desktop;qml;integration;ipc;regression" TIMEOUT 45)
    endif()

    add_executable(knetsentry_qt_model_test qt/section_catalog_qtest.cpp)
    set_target_properties(knetsentry_qt_model_test PROPERTIES AUTOMOC ON)
    target_include_directories(knetsentry_qt_model_test PRIVATE
        "${PROJECT_SOURCE_DIR}/apps/desktop")
    target_link_libraries(knetsentry_qt_model_test PRIVATE
        knetsentry_section_catalog Qt6::Core Qt6::Test)
    knetsentry_apply_project_options(knetsentry_qt_model_test)
    add_test(NAME knetsentry_qt_model_contract
        COMMAND $<TARGET_FILE:knetsentry_qt_model_test>)
    set_tests_properties(knetsentry_qt_model_contract PROPERTIES
        LABELS "qt;model;unit;regression;security" TIMEOUT 30)

    # QProcess-based Qt Test: verify the real GUI binary's headless CLI and
    # offscreen Kirigami initialization without any mocked application state.
    # Keep the extra QML-launching process out of sanitizer configs until its
    # third-party LSan behavior is separately qualified; the existing two
    # approved QML tests continue running with leak detection enabled.
    if(NOT KNETSENTRY_ENABLE_SANITIZERS)
        add_executable(knetsentry_qt_application_test qt/application_qtest.cpp)
        set_target_properties(knetsentry_qt_application_test PROPERTIES AUTOMOC ON)
        target_compile_definitions(knetsentry_qt_application_test PRIVATE
            KNETSENTRY_DESKTOP_EXECUTABLE="$<TARGET_FILE:knetsentry>")
        target_link_libraries(knetsentry_qt_application_test PRIVATE
            Qt6::Core Qt6::Test)
        knetsentry_apply_project_options(knetsentry_qt_application_test)
        add_dependencies(knetsentry_qt_application_test knetsentry)
        add_test(NAME knetsentry_qt_application_lifecycle
            COMMAND $<TARGET_FILE:knetsentry_qt_application_test>)
        set_tests_properties(knetsentry_qt_application_lifecycle PROPERTIES
            LABELS "qt;desktop;qml;regression" TIMEOUT 80)
    endif()
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
    # M1.6: prove the real Qt application publishes the expected fixed-code
    # GUI lifecycle diagnostic records. The sanitizer QML startup test already
    # covers this path; do not introduce another unqualified LSan exception.
    if(NOT KNETSENTRY_ENABLE_SANITIZERS)
        add_test(NAME knetsentry_desktop_diagnostic_lifecycle
            COMMAND "${Python3_EXECUTABLE}"
                "${PROJECT_SOURCE_DIR}/scripts/verify_m16_diagnostics.py"
                --desktop-binary "$<TARGET_FILE:knetsentry>")
        set_tests_properties(knetsentry_desktop_diagnostic_lifecycle PROPERTIES
            LABELS "desktop;qml;privacy;security;regression" TIMEOUT 40)
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

# M4.1: bounded agent wire codec and connection-local ordering (offline only).
add_executable(knetsentry_agent_protocol_test agent_protocol_m41.cpp)
target_link_libraries(knetsentry_agent_protocol_test PRIVATE KnetSentry::Core)
knetsentry_apply_project_options(knetsentry_agent_protocol_test)
add_test(NAME knetsentry_agent_protocol_contract
    COMMAND $<TARGET_FILE:knetsentry_agent_protocol_test>)
set_tests_properties(knetsentry_agent_protocol_contract PROPERTIES
    LABELS "unit;security;regression" TIMEOUT 15)

# M4.2: ephemeral key-storage and explicit certificate trust regressions.
add_executable(knetsentry_identity_test identity_m42.cpp)
target_link_libraries(knetsentry_identity_test PRIVATE KnetSentry::Identity)
knetsentry_apply_project_options(knetsentry_identity_test)
add_test(NAME knetsentry_identity_contract COMMAND $<TARGET_FILE:knetsentry_identity_test>)
set_tests_properties(knetsentry_identity_contract PROPERTIES LABELS "unit;security;regression;privacy" TIMEOUT 20)

# M4.3: real encrypted mutual TLS through bounded, in-memory wire endpoints.
add_executable(knetsentry_tls_test tls_m43.cpp)
target_link_libraries(knetsentry_tls_test PRIVATE KnetSentry::Tls KnetSentry::Core)
knetsentry_apply_project_options(knetsentry_tls_test)
add_test(NAME knetsentry_tls_contract COMMAND $<TARGET_FILE:knetsentry_tls_test>)
set_tests_properties(knetsentry_tls_contract PROPERTIES LABELS "integration;security;regression;privacy" TIMEOUT 30)
