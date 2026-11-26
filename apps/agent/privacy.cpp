// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/agent/privacy.hpp"
#include "knetsentry/agent/fim.hpp"
#include "knetsentry/agent/journal.hpp"
#include <algorithm>
#include <array>
#include <openssl/evp.h>
#include <set>

namespace knetsentry::agent {
namespace {
bool below(std::string_view path, std::string_view prefix) {
    return path == prefix || (path.starts_with(prefix) && path.size() > prefix.size() && path[prefix.size()] == '/');
}
}
bool authorize_privacy(std::string_view policy, std::string_view collector,
    std::string_view unit, const std::vector<std::string>& paths, bool buffered, PrivacyDecision& decision) {
    decision = {};
    if (policy.size() > 24576 || !policy.starts_with("v1;") || policy.ends_with(';')) { return false; }
    const auto original = policy;
    policy.remove_prefix(3);
    std::set<std::string_view> units, denied_units, files, denied_files, permits, redactions;
    std::string_view selected;
    std::size_t count{};
    while (!policy.empty()) {
        if (++count > 48) { return false; }
        const auto end = policy.find(';');
        const auto token = policy.substr(0, end);
        const auto eq = token.find('=');
        if (eq == token.npos || eq == 0 || eq + 1 == token.size()) { return false; }
        const auto key = token.substr(0, eq), value = token.substr(eq + 1);
        if (key == "collector") {
            if (!selected.empty()) { return false; }
            selected = value;
        } else if (key == "allow-unit" || key == "deny-unit") {
            if (!valid_journal_unit(value) || !(key == "allow-unit" ? units : denied_units).insert(value).second) { return false; }
        } else if (key == "allow-path" || key == "deny-path") {
            if (!valid_fim_path(value) || !(key == "allow-path" ? files : denied_files).insert(value).second) { return false; }
        } else if (key == "permit") {
            if ((value != "journal-identifiers" && value != "auth-message" && value != "audit-identifiers" &&
                 value != "file-content" && value != "buffering") || !permits.insert(value).second) { return false; }
        } else if (key == "redact") {
            if ((value != "auth-category" && value != "fim-slot" && value != "fim-content") || !redactions.insert(value).second) { return false; }
        } else { return false; }
        if (end == policy.npos) { break; }
        policy.remove_prefix(end + 1);
    }
    if (selected != collector || (collector != "journal" && collector != "authentication" && collector != "audit" && collector != "fim")) { return false; }
    const bool fim = collector == "fim", auth = collector == "authentication", audit = collector == "audit";
    const bool redact_auth = redactions.contains("auth-category"), redact_slot = redactions.contains("fim-slot"),
        redact_content = redactions.contains("fim-content");
    if ((!auth && redact_auth) || (!fim && (redact_slot || redact_content)) ||
        permits.contains("file-content") != (fim && !redact_content) || permits.contains("journal-identifiers") == fim ||
        permits.contains("audit-identifiers") != audit || permits.contains("auth-message") != (auth && !redact_auth) ||
        permits.contains("buffering") != buffered) { return false; }
    if (fim) {
        if (!units.empty() || !denied_units.empty() || paths.empty() || paths.size() > max_fim_paths || files.size() > max_fim_paths || buffered) { return false; }
        for (const auto& path : paths) {
            if (!files.contains(path) || std::ranges::any_of(denied_files, [&](auto prefix) { return below(path, prefix); })) { return false; }
        }
    } else {
        if (!files.empty() || !denied_files.empty() || !paths.empty()) { return false; }
        if (audit) { if (!units.empty() || !denied_units.empty() || unit != "audit") { return false; } }
        else if (!units.contains(unit) || denied_units.contains(unit) ||
                 (auth && !std::ranges::all_of(units, valid_auth_unit))) { return false; }
    }
    std::array<unsigned char, 32> digest{};
    unsigned int size{};
    if (EVP_Digest(original.data(), original.size(), digest.data(), &size, EVP_sha256(), nullptr) != 1 || size != digest.size()) { return false; }
    constexpr std::string_view hex = "0123456789abcdef";
    for (const auto byte : digest) { decision.fingerprint += hex[byte >> 4]; decision.fingerprint += hex[byte & 15]; }
    decision.redact_auth = redact_auth;
    decision.redact_slot = redact_slot;
    decision.redact_content = redact_content;
    return true;
}
} // namespace knetsentry::agent
