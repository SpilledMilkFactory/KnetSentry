# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: BSD-2-Clause

# M1.3: real Qt Quick/Kirigami application. Security services remain outside QML.
# M1.7: first-party read-only Qt item-model foundation, independently Qt Test-able.
add_library(knetsentry_section_catalog STATIC
    section_catalog_model.cpp section_catalog_model.hpp)
set_target_properties(knetsentry_section_catalog PROPERTIES AUTOMOC ON)
target_link_libraries(knetsentry_section_catalog PUBLIC Qt6::Core)
knetsentry_apply_project_options(knetsentry_section_catalog)

add_executable(knetsentry main.cpp)
target_compile_features(knetsentry PRIVATE cxx_std_23)
target_include_directories(knetsentry PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
knetsentry_apply_project_options(knetsentry)
target_link_libraries(knetsentry PRIVATE
    KnetSentry::Core KnetSentry::Service knetsentry_section_catalog Qt6::Core Qt6::Gui Qt6::Qml Qt6::Quick Qt6::QuickControls2)

# Qt 6-managed QML module and embedded resources; no loose QML directory
# searched at runtime and no handwritten resource path assumptions.
qt_add_qml_module(knetsentry
    URI io.github.spilledmilkfactory.KnetSentry
    VERSION 1.0
    SOURCES dashboard_model.cpp dashboard_model.hpp alert_model.cpp alert_model.hpp event_explorer_model.cpp event_explorer_model.hpp service_health_model.cpp service_health_model.hpp daemon_control.cpp daemon_control.hpp
    QML_FILES Main.qml SectionPage.qml DesignTokens.qml StatusBadge.qml SeverityBadge.qml SurfaceCard.qml SnapshotBars.qml
    RESOURCES icons/menu.svg icons/play.svg icons/stop.svg
)

# Qt 6.10's generated QML cache registry can trigger GCC 15's
# -Wnull-dereference diagnostic while inlining QHash internals. Preserve
# -Werror for *all* first-party C++ and other generated sources: downgrade
# only this Qt-generated translation unit's specific diagnostic to a warning.
# Keep QML ahead-of-time compilation enabled and remove this exception once
# the distribution's Qt/GCC combination no longer needs it.
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    set(_knetsentry_qmlcache_loader
        "${CMAKE_CURRENT_BINARY_DIR}/.rcc/qmlcache/knetsentry_qmlcache_loader.cpp")
    set_source_files_properties("${_knetsentry_qmlcache_loader}"
        PROPERTIES COMPILE_OPTIONS "-Wno-error=null-dereference")
endif()
