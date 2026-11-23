# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: BSD-2-Clause

cmake_minimum_required(VERSION 3.25)

project(KnetSentry VERSION 0.0.0 LANGUAGES CXX)

# M1.1 is a build foundation, NOT an implemented SIEM or Kirigami window.
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(KNETSENTRY_BUILD_DESKTOP "Build the Qt/Kirigami desktop bootstrap" ON)

include(CTest)

# The core never depends on Qt, KDE, a GUI session, or privileged networking.
add_subdirectory(src/core)

# Default configuration checks real, system-installed Qt/KDE packages; it
# never downloads dependencies or silently falls back to a fake GUI.
if(KNETSENTRY_BUILD_DESKTOP)
    find_package(ECM 6.0.0 REQUIRED NO_MODULE)
    list(PREPEND CMAKE_MODULE_PATH ${ECM_MODULE_PATH})
    include(ECMFindQmlModule)
    find_package(Qt6 REQUIRED NO_MODULE COMPONENTS Core Gui Qml Quick QuickControls2)
    find_package(KF6 REQUIRED COMPONENTS Kirigami)
    ecm_find_qmlmodule(org.kde.kirigami REQUIRED)
    add_subdirectory(apps/desktop)
endif()

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
