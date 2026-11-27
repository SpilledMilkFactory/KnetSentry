// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/service/event_query.hpp>
#include <algorithm>
#include <knetsentry/agent/authentication.hpp>
#include <array>
#include <charconv>
#include <limits>
#include <utility>

namespace knetsentry::service {
namespace {
using storage::StoreStatus;
constexpr auto ceiling = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
bool hex(std::string_view s, std::size_t n) {
    return s.size() == n && std::ranges::all_of(s, [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}
bool number(std::string_view s, std::uint64_t& n) {
    if (s.empty() || s.size() > 19 || (s.size() > 1 && s.front() == '0')) { return false; }
    const auto result = std::from_chars(s.data(), s.data() + s.size(), n);
    return result.ec == std::errc{} && result.ptr == s.data() + s.size() && n <= ceiling;
}
template<std::size_t N> bool fields(std::string_view line, std::array<std::string_view, N>& out) {
    for (std::size_t i = 0; i < N; ++i) {
        const auto end = line.find(' ');
        if ((i + 1 == N) != (end == line.npos)) { return false; }
        out[i] = line.substr(0, end);
        if (out[i].empty()) { return false; }
        if (end != line.npos) { line.remove_prefix(end + 1); }
    }
    return true;
}
bool selection(std::string_view s, int& n) {
    if (s == "-") { n = -1; return true; }
    if (s.size() != 1 || s.front() < '0' || s.front() > '2') { return false; }
    n = s.front() - '0'; return true;
}
std::string choice(int n) { return n == -1 ? "-" : std::to_string(n); }
std::optional<agent::OcsfStatus> outcome(int n) {
    switch (n) {
    case 0: return agent::OcsfStatus::Unknown;
    case 1: return agent::OcsfStatus::Success;
    case 2: return agent::OcsfStatus::Failure;
    default: return std::nullopt;
    }
}
std::string code(StoreStatus status) {
    if (status == StoreStatus::Ok) { return "OK"; }
    if (status == StoreStatus::Stale) { return "STALE"; }
    if (status == StoreStatus::IntegrityFailure) { return "INTEGRITY"; }
    return "UNAVAILABLE";
}
std::optional<StoreStatus> parse_code(std::string_view s) {
    if (s == "OK") { return StoreStatus::Ok; }
    if (s == "STALE") { return StoreStatus::Stale; }
    if (s == "INTEGRITY") { return StoreStatus::IntegrityFailure; }
    if (s == "UNAVAILABLE") { return StoreStatus::Unavailable; }
    return std::nullopt;
}
std::optional<agent::MappingResult> mapping(std::uint64_t n) {
    switch (n) {
    case 0: return agent::MappingResult::Classified;
    case 1: return agent::MappingResult::MetadataOnly;
    case 2: return agent::MappingResult::AuditTypeUnmapped;
    case 3: return agent::MappingResult::Redacted;
    case 4: return agent::MappingResult::Unclassified;
    default: return std::nullopt;
    }
}
std::optional<agent::OcsfActivity> activity(std::uint64_t n) {
    switch (n) {
    case 0: return agent::OcsfActivity::Unknown;
    case 1: return agent::OcsfActivity::Logon;
    case 2: return agent::OcsfActivity::Logoff;
    default: return std::nullopt;
    }
}
} // namespace
bool valid_event_query(const EventQuery& q) noexcept {
    return (q.source.empty() || q.source == "audit" || agent::valid_journal_unit(q.source)) &&
        q.mode >= -1 && q.mode <= 2 && q.outcome >= -1 && q.outcome <= 2 && q.after <= ceiling && q.revision <= ceiling &&
        ((q.after == 0 && q.revision == 0 && q.session.empty()) ||
         (q.after > 0 && q.revision > 0 && hex(q.session, 32)));
}
std::string encode_event_request(const EventQuery& q, std::string_view id) {
    if (!valid_event_query(q) || !hex(id, 16)) { return {}; }
    return "KSIPC/1 EVENTS " + std::string(id) + " " + (q.descending ? "D" : "A") + " " +
        choice(q.mode) + " " + choice(q.outcome) + " " + (q.source.empty() ? "-" : q.source) + " " +
        std::to_string(q.after) + " " + std::to_string(q.revision) + " " + (q.session.empty() ? "-" : q.session) + "\n";
}
std::optional<EventQuery> decode_event_request(std::string_view payload, std::string_view id) {
    if (!hex(id, 16) || payload.empty() || payload.size() > max_event_request || !payload.ends_with('\n')) { return {}; }
    payload.remove_suffix(1);
    std::array<std::string_view, 10> f{}; EventQuery q;
    if (!fields(payload, f) || f[0] != "KSIPC/1" || f[1] != "EVENTS" || f[2] != id ||
        (f[3] != "A" && f[3] != "D") || !selection(f[4], q.mode) || !selection(f[5], q.outcome) ||
        !number(f[7], q.after) || !number(f[8], q.revision)) { return {}; }
    q.descending = f[3] == "D";
    if (f[6] != "-") { q.source = f[6]; }
    if (f[9] != "-") { q.session = f[9]; }
    if (!valid_event_query(q)) { return {}; }
    return q;
}
std::string query_events(const storage::EventStore* store, std::string_view session, const EventQuery& q, std::string_view id) {
    if (!valid_event_query(q) || !hex(id, 16) || !hex(session, 32)) { return {}; }
    storage::SearchPage page;
    if (!store) { page.status = StoreStatus::Unavailable; }
    else if (!q.session.empty() && q.session != session) { page.status = StoreStatus::Stale; }
    else {
        storage::SearchQuery query;
        query.source_unit = q.source; query.descending = q.descending; query.after = q.after; query.limit = event_page_size;
        if (q.revision) { query.revision = q.revision; }
        if (q.mode >= 0) { query.source_mode = agent::decode_journal_mode(q.mode); }
        query.status_id = outcome(q.outcome);
        page = store->search(query);
    }
    const bool ok = page.status == StoreStatus::Ok;
    if (page.events.size() > event_page_size) { return {}; }
    std::string result = "KSIPC/1 EVENTS " + std::string(id) + " " + code(page.status) + " " + std::string(session) + " " +
        std::to_string(ok ? page.revision : 0) + " " + (ok && page.more ? "1" : "0") + "\n";
    if (ok) {
        for (const auto& e : page.events) {
            result += std::to_string(e.id) + " " + std::to_string(e.time_ms) + " " + std::to_string(e.received_ms) + " " +
                std::to_string(static_cast<std::uint64_t>(e.class_uid)) + " " + std::to_string(static_cast<std::uint64_t>(e.activity_id)) + " " +
                std::to_string(static_cast<std::uint64_t>(e.status_id)) + " " + std::to_string(static_cast<std::uint64_t>(e.mapping)) + " " +
                std::to_string(static_cast<std::uint64_t>(e.source_mode)) + " " + e.source_unit + "\n";
        }
    }
    return result.size() <= max_event_response ? result : std::string{};
}
std::optional<EventPage> decode_event_page(std::string_view payload, std::string_view id, const EventQuery& q) {
    if (!valid_event_query(q) || !hex(id, 16) || payload.empty() || payload.size() > max_event_response || !payload.ends_with('\n')) { return {}; }
    const auto end = payload.find('\n'); std::array<std::string_view, 7> h{}; EventPage result;
    if (!fields(payload.substr(0, end), h) || h[0] != "KSIPC/1" || h[1] != "EVENTS" || h[2] != id ||
        !hex(h[4], 32) || !number(h[5], result.page.revision) || (h[6] != "0" && h[6] != "1")) { return {}; }
    const auto status = parse_code(h[3]); if (!status) { return {}; }
    result.page.status = *status; result.session = h[4]; result.page.more = h[6] == "1";
    payload.remove_prefix(end + 1);
    if (*status != StoreStatus::Ok) {
        if (!payload.empty() || result.page.revision != 0 || result.page.more) { return {}; }
        return result;
    }
    if (result.page.revision == 0 || (q.revision && (q.revision != result.page.revision || q.session != result.session))) { return {}; }
    auto previous = q.after;
    while (!payload.empty()) {
        const auto newline = payload.find('\n'); std::array<std::string_view, 9> f{}; std::array<std::uint64_t, 8> n{};
        if (result.page.events.size() == event_page_size || newline == payload.npos || !fields(payload.substr(0, newline), f)) { return {}; }
        for (std::size_t i = 0; i < n.size(); ++i) { if (!number(f[i], n[i])) { return {}; } }
        const auto m = mapping(n[6]); const auto a = activity(n[4]);
        if (n[0] == 0 || (previous && (q.descending ? n[0] >= previous : n[0] <= previous)) || n[2] == 0 ||
            (n[3] != 0 && n[3] != 3002) || !a || n[5] > 2 || !m || n[7] > 2 ||
            (n[7] == 2 ? f[8] != "audit" : !agent::valid_journal_unit(f[8])) ||
            (!q.source.empty() && q.source != f[8]) || (q.mode >= 0 && static_cast<std::uint64_t>(q.mode) != n[7]) ||
            (q.outcome >= 0 && static_cast<std::uint64_t>(q.outcome) != n[5])) { return {}; }
        if ((n[7] == 0 && *m != agent::MappingResult::MetadataOnly) ||
            (n[7] == 2 && *m != agent::MappingResult::AuditTypeUnmapped) ||
            (n[7] == 1 && (!agent::valid_auth_unit(f[8]) || *m == agent::MappingResult::MetadataOnly || *m == agent::MappingResult::AuditTypeUnmapped))) { return {}; }
        if ((n[3] == 3002) != (*m == agent::MappingResult::Classified) ||
            (n[3] == 0 && (n[4] != 0 || n[5] != 0))) { return {}; }
        storage::EventSummary e;
        e.id = n[0]; e.time_ms = n[1]; e.received_ms = n[2];
        e.class_uid = n[3] == 0 ? agent::OcsfClass::Base : agent::OcsfClass::Authentication;
        e.category = n[3] == 0 ? agent::OcsfCategory::Unknown : agent::OcsfCategory::IdentityAndAccessManagement;
        e.activity_id = *a; e.status_id = *outcome(static_cast<int>(n[5])); e.mapping = *m;
        e.source_mode = agent::decode_journal_mode(static_cast<std::int64_t>(n[7])); e.source_unit = f[8];
        result.page.events.push_back(std::move(e)); previous = n[0]; payload.remove_prefix(newline + 1);
    }
    if (result.page.more && result.page.events.size() != event_page_size) { return {}; }
    return result;
}
} // namespace knetsentry::service
