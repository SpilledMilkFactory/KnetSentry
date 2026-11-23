# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: BSD-2-Clause

# M1.3: real Qt Quick/Kirigami application. Security services remain outside QML.
add_executable(knetsentry main.cpp)
target_compile_features(knetsentry PRIVATE cxx_std_23)
knetsentry_apply_project_options(knetsentry)
target_link_libraries(knetsentry PRIVATE
    KnetSentry::Core Qt6::Core Qt6::Gui Qt6::Qml Qt6::Quick Qt6::QuickControls2)

# Qt 6-managed QML module and embedded resources; no loose QML directory
# searched at runtime and no handwritten resource path assumptions.
qt_add_qml_module(knetsentry
    URI io.github.spilledmilkfactory.KnetSentry
    VERSION 1.0
    QML_FILES Main.qml SectionPage.qml
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
