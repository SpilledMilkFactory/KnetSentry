// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace knetsentry::service {

// Schema v1 describes lifecycle-only operation. Future capabilities require
// an explicit schema revision, threat review and new authorization tests.
enum class ConfigurationMode : std::uint8_t { LifecycleOnly };
struct ManagerConfiguration final {
    std::uint32_t schema_version{1};
    ConfigurationMode mode{ConfigurationMode::LifecycleOnly};
    bool monitoring_enabled{false};
    bool network_listeners_enabled{false};
    bool packet_capture_enabled{false};
    bool public_intelligence_enabled{false};
    bool privileged_actions_enabled{false};
};

enum class ConfigurationError : std::uint8_t {
    None, Empty, TooLarge, Syntax, MissingField, DuplicateField, UnknownField,
    UnsupportedVersion, UnsafeSetting, UnsafePath, UnsafeFile, ReadFailure
};

struct ConfigurationResult final {
    ManagerConfiguration value{};
    ConfigurationError error{ConfigurationError::None};
    [[nodiscard]] bool ok() const noexcept { return error == ConfigurationError::None; }
};

// Bounded strict ASCII key/value syntax; all seven keys required exactly once.
// No interpolation, includes, secrets, expressions, or ignored unknown keys.
[[nodiscard]] ConfigurationResult parse_configuration(std::string_view text) noexcept;

// POSIX, owner-only regular files. Never opens a symlink final component,
// FIFO, device, directory, or arbitrary URL; rejects unsafe permissions.
// Must receive an absolute path. Returns only a fixed error enum, never
// reflects untrusted bytes or file paths into diagnostics.
[[nodiscard]] ConfigurationResult load_configuration(std::string_view path) noexcept;

} // namespace knetsentry::service
