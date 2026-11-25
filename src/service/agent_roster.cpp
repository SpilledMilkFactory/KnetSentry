// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/service/agent_roster.hpp>
#include <algorithm>

namespace knetsentry::service {
namespace {
constexpr std::string_view prefix = "KSIPC/1 OK ";
constexpr std::string_view ready = " AGENTS READY\n";
constexpr std::string_view unavailable = " AGENTS UNAVAILABLE\n";
constexpr std::string_view hex = "0123456789abcdef";
bool valid_id(std::string_view id) noexcept {
    return id.size() == 16 && std::ranges::all_of(id, [](char c) { return hex.find(c) != std::string_view::npos; });
}
bool nonzero(const enrollment::EndpointId& id) noexcept {
    return std::ranges::any_of(id, [](unsigned char b) { return b != 0; });
}
} // namespace
std::size_t encode_roster(const enrollment::Roster& roster, std::string_view request_id,
    std::span<char> output) noexcept {
    if (!valid_id(request_id) || roster.size > enrollment::max_endpoints) { return 0; }
    const bool available = roster.status == enrollment::Status::Ok;
    const auto suffix = available ? ready : unavailable;
    const auto count = prefix.size() + request_id.size() + suffix.size() + (available ? roster.size * 35U : 0U);
    if (count > output.size() || count > max_roster_response_size) { return 0; }
    auto cursor = output.begin();
    for (auto text : {prefix, request_id, suffix}) { cursor = std::ranges::copy(text, cursor).out; }
    if (available) {
        for (std::size_t i = 0; i < roster.size; ++i) {
            const auto& row = roster.entries.at(i);
            if (!nonzero(row.id)) { return 0; }
            for (std::size_t j = 0; j < i; ++j) {
                if (roster.entries.at(j).id == row.id) { return 0; }
            }
            *cursor++ = row.approved ? 'A' : 'R';
            *cursor++ = ' ';
            for (auto byte : row.id) { *cursor++ = hex.at(byte >> 4U); *cursor++ = hex.at(byte & 15U); }
            *cursor++ = '\n';
        }
    }
    return count;
}
std::optional<enrollment::Roster> decode_roster(std::string_view payload, std::string_view request_id) noexcept {
    if (!valid_id(request_id) || payload.size() > max_roster_response_size || !payload.starts_with(prefix)) {
        return std::nullopt;
    }
    payload.remove_prefix(prefix.size());
    if (!payload.starts_with(request_id)) { return std::nullopt; }
    payload.remove_prefix(request_id.size());
    if (payload == unavailable) { return enrollment::Roster{}; }
    if (!payload.starts_with(ready)) { return std::nullopt; }
    payload.remove_prefix(ready.size());
    if (payload.size() % 35U != 0 || payload.size() / 35U > enrollment::max_endpoints) { return std::nullopt; }
    enrollment::Roster result{};
    result.status = enrollment::Status::Ok;
    while (!payload.empty()) {
        const auto row = payload.substr(0, 35);
        if ((row[0] != 'A' && row[0] != 'R') || row[1] != ' ' || row[34] != '\n') { return std::nullopt; }
        enrollment::RosterEntry entry{};
        entry.approved = row[0] == 'A';
        for (std::size_t i = 0; i < entry.id.size(); ++i) {
            const auto hi = hex.find(row[2 + 2 * i]);
            const auto lo = hex.find(row[3 + 2 * i]);
            if (hi == std::string_view::npos || lo == std::string_view::npos) { return std::nullopt; }
            entry.id.at(i) = static_cast<unsigned char>(hi * 16U + lo);
        }
        if (!nonzero(entry.id)) { return std::nullopt; }
        for (std::size_t i = 0; i < result.size; ++i) {
            if (result.entries.at(i).id == entry.id) { return std::nullopt; }
        }
        result.entries.at(result.size++) = entry;
        payload.remove_prefix(35);
    }
    return result;
}
} // namespace knetsentry::service
