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
    QML_FILES Main.qml
)
