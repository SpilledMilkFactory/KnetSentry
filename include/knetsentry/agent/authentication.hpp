// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <string_view>

namespace knetsentry::agent {
// Source-reported observations, not verified authentication decisions.
enum class AuthEvent { None, Unclassified, SshAccepted, SshFailed, SshInvalidUser,
                       SessionOpened, SessionClosed, LoginFailed, AuthenticationFailed,
                       LoginSessionCreated, LoginSessionRemoved };
[[nodiscard]] bool valid_auth_unit(std::string_view unit) noexcept;
[[nodiscard]] AuthEvent classify_auth(std::string_view unit, std::string_view message) noexcept;
[[nodiscard]] std::string_view auth_event_name(AuthEvent event) noexcept;
[[nodiscard]] AuthEvent parse_auth_event(std::string_view name) noexcept;
[[nodiscard]] bool valid_auth_event(std::string_view unit, AuthEvent event) noexcept;
} // namespace knetsentry::agent
