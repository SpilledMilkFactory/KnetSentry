// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/service/configuration.hpp"

#include <array>
#include <iostream>
#include <string>
#include <string_view>

using knetsentry::service::ConfigurationError;
using knetsentry::service::parse_configuration;

namespace {
constexpr std::string_view valid =
    "schema_version = 1\n"
    "mode = lifecycle_only\n"
    "monitoring_enabled = false\n"
    "network_listeners_enabled = false\n"
    "packet_capture_enabled = false\n"
    "public_intelligence_enabled = false\n"
    "privileged_actions_enabled = false\n";

[[nodiscard]] bool expect(std::string_view input, ConfigurationError expected,
                          std::string_view name) {
    const auto result = parse_configuration(input);
    if (result.error != expected) {
        std::cerr << "Unexpected config test outcome: " << name << '\n';
        return false;
    }
    if (result.ok() && (result.value.schema_version != 1 ||
        result.value.monitoring_enabled || result.value.network_listeners_enabled ||
        result.value.packet_capture_enabled || result.value.public_intelligence_enabled ||
        result.value.privileged_actions_enabled)) {
        std::cerr << "Unexpectedly enabled a security capability: " << name << '\n';
        return false;
    }
    return true;
}

[[nodiscard]] std::string replace(std::string_view old_text, std::string_view new_text) {
    std::string result(valid);
    const auto position = result.find(old_text);
    if (position != std::string::npos) { result.replace(position, old_text.size(), new_text); }
    return result;
}
} // namespace

int main() {
    bool ok = true;
    auto check = [&ok](std::string_view text, ConfigurationError error,
                       std::string_view name) {
        if (!expect(text, error, name)) { ok = false; }
    };
    check(valid, ConfigurationError::None, "valid strict v1");
    check(std::string("# comment\n\n") + std::string(valid),
          ConfigurationError::None, "comments and blanks");
    check({}, ConfigurationError::Empty, "empty");
    check("# only a comment\n", ConfigurationError::MissingField, "missing all keys");
    check(replace("schema_version = 1", "schema_version = 2"),
          ConfigurationError::UnsupportedVersion, "future schema");
    check(replace("schema_version = 1", "schema_version = -1"),
          ConfigurationError::UnsupportedVersion, "negative version");
    check(replace("schema_version = 1", "schema_version = 01"),
          ConfigurationError::UnsupportedVersion, "noncanonical version");
    check(replace("mode = lifecycle_only", "mode = active"),
          ConfigurationError::UnsafeSetting, "unsupported mode");
    check(replace("packet_capture_enabled = false", "packet_capture_enabled = true"),
          ConfigurationError::UnsafeSetting, "capture cannot be enabled");
    check(replace("monitoring_enabled = false", "monitoring_enabled = true"),
          ConfigurationError::UnsafeSetting, "monitoring cannot be enabled");
    check(replace("network_listeners_enabled = false", "network_listeners_enabled = true"),
          ConfigurationError::UnsafeSetting, "listener cannot be enabled");
    check(replace("public_intelligence_enabled = false", "public_intelligence_enabled = true"),
          ConfigurationError::UnsafeSetting, "egress cannot be enabled");
    check(replace("privileged_actions_enabled = false", "privileged_actions_enabled = true"),
          ConfigurationError::UnsafeSetting, "privileges cannot be enabled");
    check(replace("monitoring_enabled = false", "monitoring_enabled = FALSE"),
          ConfigurationError::UnsafeSetting, "case change rejected");
    check(replace("mode = lifecycle_only", ""),
          ConfigurationError::MissingField, "missing mode");
    check(std::string(valid) + "mode = lifecycle_only\n",
          ConfigurationError::DuplicateField, "duplicate field");
    check(std::string(valid) + "secret = value\n",
          ConfigurationError::UnknownField, "unknown field");
    check(replace("mode = lifecycle_only", "mode == lifecycle_only"),
          ConfigurationError::Syntax, "two separators");
    check(std::string(valid).append(1, '\0'), ConfigurationError::Syntax, "nul byte");
    check(std::string(valid) + "\r", ConfigurationError::Syntax, "cr byte");
    check(std::string(valid) + "\t", ConfigurationError::Syntax, "tab byte");
    check(std::string(valid) + "\xFF", ConfigurationError::Syntax, "non ascii");
    check(std::string(4097, 'a'), ConfigurationError::TooLarge, "bounded document");
    check(std::string(33, '\n') + std::string(valid),
          ConfigurationError::TooLarge, "bounded line count");
    // No 'contains' semantics: wrong key spelling is a hard failure.
    check(replace("packet_capture_enabled", "packet-capture-enabled"),
          ConfigurationError::UnknownField, "unknown key alias");
    return ok ? 0 : 1;
}
