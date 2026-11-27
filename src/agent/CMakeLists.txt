# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: BSD-2-Clause
add_library(knetsentry_agent_lifecycle STATIC lifecycle.cpp)
add_library(KnetSentry::AgentLifecycle ALIAS knetsentry_agent_lifecycle)
target_include_directories(knetsentry_agent_lifecycle PUBLIC "${PROJECT_SOURCE_DIR}/include")
knetsentry_apply_project_options(knetsentry_agent_lifecycle)

# M5.2: distro-provided shared systemd library; no downloaded or bundled dependencies.
find_package(PkgConfig REQUIRED)
pkg_check_modules(SYSTEMD REQUIRED IMPORTED_TARGET libsystemd)
add_library(knetsentry_agent_journal STATIC journal.cpp systemd_journal.cpp authentication.cpp)
add_library(KnetSentry::AgentJournal ALIAS knetsentry_agent_journal)
target_link_libraries(knetsentry_agent_journal PUBLIC KnetSentry::AgentLifecycle PRIVATE PkgConfig::SYSTEMD)
knetsentry_apply_project_options(knetsentry_agent_journal)

# M5.5: offline delivery contract, no operational socket adapter.
add_library(knetsentry_agent_delivery STATIC delivery.cpp receipt.cpp ingestion.cpp normalization.cpp)
add_library(KnetSentry::AgentDelivery ALIAS knetsentry_agent_delivery)
target_link_libraries(knetsentry_agent_delivery PUBLIC KnetSentry::AgentJournal KnetSentry::Enrollment)
knetsentry_apply_project_options(knetsentry_agent_delivery)

# M5.6: explicitly approved files, no network or persistent file contents.
find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto)
add_library(knetsentry_agent_fim STATIC fim.cpp)
add_library(KnetSentry::AgentFIM ALIAS knetsentry_agent_fim)
target_link_libraries(knetsentry_agent_fim PUBLIC KnetSentry::AgentLifecycle PRIVATE OpenSSL::Crypto)
knetsentry_apply_project_options(knetsentry_agent_fim)

# M6.3: database-independent storage contract and volatile reference backend.
add_library(knetsentry_event_storage STATIC event_store.cpp)
add_library(KnetSentry::EventStorage ALIAS knetsentry_event_storage)
target_link_libraries(knetsentry_event_storage PUBLIC KnetSentry::AgentDelivery)
knetsentry_apply_project_options(knetsentry_event_storage)

# M6.4: distro SQLite, no download, amalgamation or extension loading.
find_package(SQLite3 3.37 REQUIRED)
add_library(knetsentry_sqlite_storage STATIC sqlite_event_store.cpp)
add_library(KnetSentry::SqliteStorage ALIAS knetsentry_sqlite_storage)
target_link_libraries(knetsentry_sqlite_storage PUBLIC KnetSentry::EventStorage PRIVATE SQLite::SQLite3 OpenSSL::Crypto)
knetsentry_apply_project_options(knetsentry_sqlite_storage)

# M6.10: independently approved raw segments and bounded SQLite projection.
add_library(knetsentry_split_storage STATIC split_event_store.cpp)
add_library(KnetSentry::SplitStorage ALIAS knetsentry_split_storage)
target_link_libraries(knetsentry_split_storage PUBLIC KnetSentry::EventStorage PRIVATE SQLite::SQLite3 OpenSSL::Crypto)
knetsentry_apply_project_options(knetsentry_split_storage)
