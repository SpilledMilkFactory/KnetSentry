# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: BSD-2-Clause

add_library(knetsentry_core STATIC build_info.cpp diagnostics.cpp network_scope.cpp linux_topology.cpp network_authorization.cpp agent_protocol.cpp)
add_library(KnetSentry::Core ALIAS knetsentry_core)

target_compile_features(knetsentry_core PUBLIC cxx_std_23)
knetsentry_apply_project_options(knetsentry_core)
target_include_directories(knetsentry_core
    PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_compile_definitions(knetsentry_core
    PRIVATE KNETSENTRY_PROJECT_VERSION="${PROJECT_VERSION}")
set_target_properties(knetsentry_core PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

# M4.2: separate identity library; no operational manager/desktop linkage yet.
set(OPENSSL_USE_STATIC_LIBS FALSE)
find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto SSL)
if(DEFINED OpenSSL_VERSION)
    set(_ks_openssl_version "${OpenSSL_VERSION}")
else()
    set(_ks_openssl_version "${OPENSSL_VERSION}")
endif()
if(_ks_openssl_version VERSION_LESS 3.5 OR NOT _ks_openssl_version VERSION_LESS 3.6 OR
   NOT OPENSSL_CRYPTO_LIBRARY MATCHES "\\.so(\\.|$)" OR
   NOT OPENSSL_SSL_LIBRARY MATCHES "\\.so(\\.|$)")
    message(FATAL_ERROR "M4.3 requires system shared OpenSSL 3.5.x libcrypto and libssl")
endif()
add_library(knetsentry_identity STATIC identity.cpp)
add_library(KnetSentry::Identity ALIAS knetsentry_identity)
target_compile_features(knetsentry_identity PUBLIC cxx_std_23)
target_include_directories(knetsentry_identity PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(knetsentry_identity PUBLIC OpenSSL::Crypto)
knetsentry_apply_project_options(knetsentry_identity)

# M4.3: isolated TLS state machine; no production socket or service linkage.
add_library(knetsentry_tls STATIC tls_transport.cpp)
add_library(KnetSentry::Tls ALIAS knetsentry_tls)
target_compile_features(knetsentry_tls PUBLIC cxx_std_23)
target_include_directories(knetsentry_tls PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(knetsentry_tls PUBLIC KnetSentry::Identity OpenSSL::SSL)
knetsentry_apply_project_options(knetsentry_tls)

# M4.4: offline administrative registry and TLS-backed admission boundary.
add_library(knetsentry_enrollment STATIC enrollment.cpp)
add_library(KnetSentry::Enrollment ALIAS knetsentry_enrollment)
target_compile_features(knetsentry_enrollment PUBLIC cxx_std_23)
target_include_directories(knetsentry_enrollment PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(knetsentry_enrollment PUBLIC KnetSentry::Tls)
knetsentry_apply_project_options(knetsentry_enrollment)

add_executable(knetsentry-enrollment enrollment_admin.cpp)
target_link_libraries(knetsentry-enrollment PRIVATE KnetSentry::Enrollment)
knetsentry_apply_project_options(knetsentry-enrollment)
