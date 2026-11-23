# SPDX-FileCopyrightText: 2026 Chris Sutton
# SPDX-License-Identifier: BSD-2-Clause
include_guard(GLOBAL)

# Project-owned code only. We do not impose these options on installed Qt/KDE.
option(KNETSENTRY_WARNINGS_AS_ERRORS "Treat project-owned C++ warnings as errors" ON)
option(KNETSENTRY_ENABLE_RELEASE_HARDENING "Harden KnetSentry release targets" ON)
option(KNETSENTRY_ENABLE_SANITIZERS "Instrument KnetSentry-owned C++ with ASan+UBSan" OFF)
option(KNETSENTRY_ENABLE_CLANG_TIDY "Run clang-tidy on KnetSentry-owned C++" OFF)

if(KNETSENTRY_ENABLE_SANITIZERS AND CMAKE_BUILD_TYPE STREQUAL "Release")
    message(FATAL_ERROR "Sanitizers require a non-Release build (use linux-sanitize)")
endif()
if(KNETSENTRY_ENABLE_SANITIZERS AND NOT CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang)$")
    message(FATAL_ERROR "ASan/UBSan configuration requires supported GCC or Clang")
endif()

add_library(knetsentry_project_warnings INTERFACE)
add_library(knetsentry_project_hardening INTERFACE)
add_library(knetsentry_project_sanitizers INTERFACE)

if(CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang)$")
    target_compile_options(knetsentry_project_warnings INTERFACE
        -Wall -Wextra -Wpedantic -Wshadow -Wformat=2
        -Wconversion -Wsign-conversion -Wnull-dereference)
    if(KNETSENTRY_WARNINGS_AS_ERRORS)
        target_compile_options(knetsentry_project_warnings INTERFACE -Werror)
    endif()
elseif(KNETSENTRY_WARNINGS_AS_ERRORS)
    message(FATAL_ERROR "Warnings-as-errors not qualified on compiler ${CMAKE_CXX_COMPILER_ID}")
endif()

# Enforce the requested hardening options on supported GNU/Linux toolchains.
# Positive flag probes do not replace M15 ELF/content inspection.
if(KNETSENTRY_ENABLE_RELEASE_HARDENING AND CMAKE_SYSTEM_NAME STREQUAL "Linux")
    if(NOT CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang)$")
        message(FATAL_ERROR "Linux hardening not qualified for ${CMAKE_CXX_COMPILER_ID}")
    endif()
    include(CheckCXXCompilerFlag)
    include(CheckLinkerFlag)
    include(CheckPIESupported)
    check_cxx_compiler_flag("-fstack-protector-strong" KNETSENTRY_HAVE_STACK_PROTECTOR)
    check_cxx_compiler_flag("-D_FORTIFY_SOURCE=3" KNETSENTRY_HAVE_FORTIFY_3)
    check_linker_flag(CXX "LINKER:-z,relro" KNETSENTRY_HAVE_RELRO)
    check_linker_flag(CXX "LINKER:-z,now" KNETSENTRY_HAVE_NOW)
    check_pie_supported(LANGUAGES CXX)
    foreach(required IN ITEMS
            KNETSENTRY_HAVE_STACK_PROTECTOR KNETSENTRY_HAVE_FORTIFY_3
            KNETSENTRY_HAVE_RELRO KNETSENTRY_HAVE_NOW CMAKE_CXX_LINK_PIE_SUPPORTED)
        if(NOT ${required})
            message(FATAL_ERROR "Required release-hardening capability unavailable: ${required}")
        endif()
    endforeach()
    target_compile_options(knetsentry_project_hardening INTERFACE
        "$<$<CONFIG:Release>:-fstack-protector-strong>")
    target_compile_definitions(knetsentry_project_hardening INTERFACE
        "$<$<CONFIG:Release>:_FORTIFY_SOURCE=3>")
    target_link_options(knetsentry_project_hardening INTERFACE
        "$<$<CONFIG:Release>:LINKER:-z,relro>"
        "$<$<CONFIG:Release>:LINKER:-z,now>")
elseif(NOT KNETSENTRY_ENABLE_RELEASE_HARDENING)
    message(WARNING "Release hardening disabled: this build is NOT release-qualified")
endif()

if(KNETSENTRY_ENABLE_SANITIZERS)
    target_compile_options(knetsentry_project_sanitizers INTERFACE
        -fsanitize=address,undefined -fno-omit-frame-pointer
        -fno-optimize-sibling-calls -g)
    target_link_options(knetsentry_project_sanitizers INTERFACE
        -fsanitize=address,undefined)
endif()

if(KNETSENTRY_ENABLE_CLANG_TIDY)
    find_program(KNETSENTRY_CLANG_TIDY_EXECUTABLE
        NAMES clang-tidy clang-tidy-21 clang-tidy-20 clang-tidy-19
              clang-tidy-18 clang-tidy-17)
    if(NOT KNETSENTRY_CLANG_TIDY_EXECUTABLE)
        message(FATAL_ERROR "clang-tidy requested but unavailable: install clang-tidy or disable analysis")
    endif()
endif()

# Call explicitly for every first-party target (including newly added ones).
function(knetsentry_apply_project_options target)
    if(NOT TARGET "${target}")
        message(FATAL_ERROR "Project options requested for nonexistent target ${target}")
    endif()
    target_link_libraries("${target}" PRIVATE
        knetsentry_project_warnings
        knetsentry_project_hardening
        knetsentry_project_sanitizers)
    set_target_properties("${target}" PROPERTIES POSITION_INDEPENDENT_CODE ON)
    if(KNETSENTRY_ENABLE_CLANG_TIDY)
        set_property(TARGET "${target}" PROPERTY CXX_CLANG_TIDY
            "${KNETSENTRY_CLANG_TIDY_EXECUTABLE}")
    endif()
endfunction()
