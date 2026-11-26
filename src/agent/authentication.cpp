// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/agent/authentication.hpp"
#include <algorithm>
#include <array>
#include <arpa/inet.h>
#include <charconv>
#include <utility>

namespace knetsentry::agent {
namespace {
constexpr std::array names{
    std::pair{AuthEvent::Redacted, std::string_view("redacted")},
    std::pair{AuthEvent::Unclassified, std::string_view("unclassified")},
    std::pair{AuthEvent::SshAccepted, std::string_view("ssh-accepted")},
    std::pair{AuthEvent::SshFailed, std::string_view("ssh-failed")},
    std::pair{AuthEvent::SshInvalidUser, std::string_view("ssh-invalid-user")},
    std::pair{AuthEvent::SessionOpened, std::string_view("session-opened")},
    std::pair{AuthEvent::SessionClosed, std::string_view("session-closed")},
    std::pair{AuthEvent::LoginFailed, std::string_view("login-failed")},
    std::pair{AuthEvent::AuthenticationFailed, std::string_view("authentication-failed")},
    std::pair{AuthEvent::LoginSessionCreated, std::string_view("login-session-created")},
    std::pair{AuthEvent::LoginSessionRemoved, std::string_view("login-session-removed")}};
bool instance(std::string_view unit, std::string_view prefix) noexcept {
    return unit.starts_with(prefix) && unit.ends_with(".service") && unit.size() > prefix.size() + 8;
}
bool ssh(std::string_view unit) noexcept {
    return unit == "ssh.service" || unit == "sshd.service" || instance(unit, "ssh@") || instance(unit, "sshd@");
}
bool login(std::string_view unit) noexcept {
    return unit == "login.service" || instance(unit, "getty@") || instance(unit, "serial-getty@");
}
std::string_view take(std::string_view& text) noexcept {
    const auto end = text.find(' ');
    const auto value = text.substr(0, end);
    text.remove_prefix(end == text.npos ? text.size() : end + 1);
    return value;
}
bool consume(std::string_view& text, std::string_view prefix) noexcept {
    if (!text.starts_with(prefix)) { return false; }
    text.remove_prefix(prefix.size());
    return true;
}
bool token(std::string_view value) noexcept {
    return !value.empty() && value.size() <= 128 && std::ranges::all_of(value, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.' || c == '@' || c == '$';
    });
}
bool endpoint(std::string_view& text) noexcept {
    const auto address = take(text);
    if (address.empty() || address.size() >= INET6_ADDRSTRLEN) { return false; }
    std::array<char, INET6_ADDRSTRLEN> buffer{};
    std::ranges::copy(address, buffer.begin());
    in6_addr ip6{};
    in_addr ip4{};
    if (::inet_pton(AF_INET, buffer.data(), &ip4) != 1 && ::inet_pton(AF_INET6, buffer.data(), &ip6) != 1) { return false; }
    if (!consume(text, "port ")) { return false; }
    const auto port = take(text);
    unsigned int number{};
    if (port.empty()) { return false; }
    const auto parsed = std::from_chars(port.data(), port.data() + port.size(), number);
    return parsed.ec == std::errc{} && parsed.ptr == port.data() + port.size() && number > 0 && number <= 65535;
}
AuthEvent ssh_event(std::string_view text) noexcept {
    if (consume(text, "Invalid user ")) {
        return token(take(text)) && consume(text, "from ") && endpoint(text) && (text.empty() || text == "[preauth]")
            ? AuthEvent::SshInvalidUser : AuthEvent::Unclassified;
    }
    const bool accepted = consume(text, "Accepted ");
    if (!accepted && !consume(text, "Failed ")) { return AuthEvent::Unclassified; }
    const auto method = take(text);
    if (method != "password" && method != "publickey" && method != "keyboard-interactive/pam" &&
        method != "keyboard-interactive" && method != "none" && method != "hostbased") { return AuthEvent::Unclassified; }
    if (!consume(text, "for ")) { return AuthEvent::Unclassified; }
    if (consume(text, "invalid user ") && accepted) { return AuthEvent::Unclassified; }
    if (!token(take(text)) || !consume(text, "from ") || !endpoint(text)) { return AuthEvent::Unclassified; }
    // OpenSSH may append a key type/fingerprint; never retain it.
    if (text != "ssh2" && !text.starts_with("ssh2: ")) { return AuthEvent::Unclassified; }
    return accepted ? AuthEvent::SshAccepted : AuthEvent::SshFailed;
}
bool pam_user(std::string_view user) noexcept {
    const auto suffix = user.find("(uid=");
    if (suffix == user.npos) { return token(user); }
    if (!token(user.substr(0, suffix)) || !user.ends_with(')')) { return false; }
    const auto uid = user.substr(suffix + 5, user.size() - suffix - 6);
    return !uid.empty() && std::ranges::all_of(uid, [](char c) { return c >= '0' && c <= '9'; });
}
AuthEvent pam(std::string_view text, bool is_ssh) noexcept {
    if (!consume(text, "pam_unix(") || !consume(text, is_ssh ? "sshd:" : "login:")) { return AuthEvent::Unclassified; }
    if (consume(text, "session): session opened for user ")) {
        return pam_user(take(text)) ? AuthEvent::SessionOpened : AuthEvent::Unclassified;
    }
    if (consume(text, "session): session closed for user ")) {
        return pam_user(take(text)) ? AuthEvent::SessionClosed : AuthEvent::Unclassified;
    }
    if (text == "auth): authentication failure" || text.starts_with("auth): authentication failure; ")) {
        return AuthEvent::AuthenticationFailed;
    }
    return AuthEvent::Unclassified;
}
} // namespace
bool valid_auth_unit(std::string_view unit) noexcept {
    return unit.size() <= 128 && std::ranges::all_of(unit, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == '@';
    }) && (ssh(unit) || login(unit) || unit == "systemd-logind.service");
}
std::string_view auth_event_name(AuthEvent event) noexcept {
    for (const auto& entry : names) { if (entry.first == event) { return entry.second; } }
    return {};
}
AuthEvent parse_auth_event(std::string_view name) noexcept {
    for (const auto& entry : names) { if (entry.second == name) { return entry.first; } }
    return AuthEvent::None;
}
bool valid_auth_event(std::string_view unit, AuthEvent event) noexcept {
    if (!valid_auth_unit(unit)) { return false; }
    if (event == AuthEvent::Unclassified || event == AuthEvent::Redacted) { return true; }
    if (ssh(unit)) {
        return event == AuthEvent::SshAccepted || event == AuthEvent::SshFailed || event == AuthEvent::SshInvalidUser ||
            event == AuthEvent::SessionOpened || event == AuthEvent::SessionClosed || event == AuthEvent::AuthenticationFailed;
    }
    if (login(unit)) { return event == AuthEvent::SessionOpened || event == AuthEvent::SessionClosed ||
        event == AuthEvent::LoginFailed || event == AuthEvent::AuthenticationFailed; }
    return event == AuthEvent::LoginSessionCreated || event == AuthEvent::LoginSessionRemoved;
}
AuthEvent classify_auth(std::string_view unit, std::string_view message) noexcept {
    if (!valid_auth_unit(unit) || message.empty() || message.size() > 1024 ||
        !std::ranges::all_of(message, [](char c) { return c >= ' ' && c <= '~'; })) { return AuthEvent::Unclassified; }
    if (ssh(unit)) {
        return message.starts_with("pam_unix(") ? pam(message, true) : ssh_event(message);
    }
    if (login(unit)) {
        if (message.starts_with("FAILED LOGIN (")) {
            auto rest = message.substr(14);
            const auto end = rest.find(") on '");
            if (end != rest.npos && end > 0 && std::ranges::all_of(rest.substr(0, end),
                    [](char c) { return c >= '0' && c <= '9'; }) && rest.find("' FOR '", end + 6) != rest.npos) {
                return AuthEvent::LoginFailed;
            }
        }
        return pam(message, false);
    }
    if (consume(message, "New session ")) {
        return token(take(message)) && consume(message, "of user ") && message.ends_with('.') &&
            token(message.substr(0, message.size() - 1)) ? AuthEvent::LoginSessionCreated : AuthEvent::Unclassified;
    }
    if (consume(message, "Removed session ") && message.ends_with('.') &&
        token(message.substr(0, message.size() - 1))) { return AuthEvent::LoginSessionRemoved; }
    return AuthEvent::Unclassified;
}
} // namespace knetsentry::agent
