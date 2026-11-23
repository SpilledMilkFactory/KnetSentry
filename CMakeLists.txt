# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: BSD-2-Clause

cmake_minimum_required(VERSION 3.25)

project(KnetSentry VERSION 0.0.0 LANGUAGES CXX)

# M1.3 adds the desktop QML shell; SIEM services remain unimplemented.
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(KNETSENTRY_BUILD_DESKTOP "Build the Qt/Kirigami desktop application" ON)

include(CTest)

# M1.2: enable checks only for our own targets; never change third-party
# Qt/KDE compilation flags or instrument their installed binaries.
include(cmake/KnetSentryBuildOptions.cmake)

# The core never depends on Qt, KDE, a GUI session, or privileged networking.
add_subdirectory(src/core)

# Default configuration checks real, system-installed Qt/KDE packages; it
# never downloads dependencies or silently falls back to a fake GUI.
if(KNETSENTRY_BUILD_DESKTOP)
    find_package(ECM 6.0.0 REQUIRED NO_MODULE)
    list(PREPEND CMAKE_MODULE_PATH ${ECM_MODULE_PATH})
    find_package(Qt6 REQUIRED NO_MODULE COMPONENTS Core Gui Qml Quick QuickControls2)

    # The Clazy compiler wrapper uses Clang rather than the system GCC.
    # Ubuntu's Kirigami CMake package requires compiler-compatible OpenMP;
    # GCC's libgomp does not automatically satisfy Clang's libomp discovery.
    # Diagnose this before FindKF6 presents the misleading "Kirigami missing" error.
    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" AND
       CMAKE_CXX_COMPILER MATCHES "(^|/)clazy(-[0-9]+)?$")
        find_package(OpenMP QUIET COMPONENTS CXX)
        if(NOT OpenMP_CXX_FOUND)
            string(REGEX MATCH "^[0-9]+" _knetsentry_clang_major
                "${CMAKE_CXX_COMPILER_VERSION}")
            message(FATAL_ERROR
                "Clazy uses Clang ${CMAKE_CXX_COMPILER_VERSION}, but that toolchain "
                "cannot find OpenMP. This prevents Ubuntu's installed Kirigami "
                "package from being resolved; Kirigami itself is not necessarily "
                "missing. On Ubuntu 26.04 install the matching LLVM OpenMP "
                "development runtime (for Clang ${_knetsentry_clang_major}: "
                "sudo apt install libomp-${_knetsentry_clang_major}-dev), "
                "then reconfigure with cmake --preset linux-clazy --fresh. "
                "Do not override or disable Kirigami dependency validation.")
        endif()
    endif()

    find_package(KF6 REQUIRED COMPONENTS Kirigami)
    # ECM's legacy qmlplugindump path can report false negatives for modern
    # Qt 6 Kirigami modules. A mandatory runtime CTest below loads a real
    # Kirigami.ApplicationWindow instead of trusting metadata-only discovery.
    qt_standard_project_setup(REQUIRES 6.5)
    add_subdirectory(apps/desktop)
endif()

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
