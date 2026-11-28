// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <knetsentry/service/alert_query.hpp>
#include <knetsentry/service/event_query.hpp>
#include <algorithm>
#include <array>

namespace knetsentry::service {
// Page-local projections only. Never infer coverage or a global total.
struct DashboardEvents {
    std::size_t count{}, failures{};
    std::uint64_t newest_receiver_ms{};
    // Unknown, success, failure. Receiver-age bins oldest to newest.
    std::array<std::size_t, 3> outcomes{};
    std::array<std::array<std::size_t, 4>, 3> activity{};
};
struct DashboardAlerts {
    std::size_t count{}, open{}, acknowledged{}, resolved{}, distinct_rules{}, high_active{};
    std::array<std::size_t, 6> severities{}, active_severities{};
};
[[nodiscard]] inline std::optional<DashboardEvents> summarize_events(const EventPage& input) noexcept {
    const auto& page = input.page;
    if (page.status != storage::StoreStatus::Ok || page.events.size() > event_page_size ||
        (page.more && page.events.size() != event_page_size)) { return {}; }
    DashboardEvents out;
    out.count = page.events.size();
    for (const auto& row : page.events) {
        out.newest_receiver_ms = std::max(out.newest_receiver_ms, row.received_ms);
    }
    for (const auto& row : page.events) {
        std::size_t outcome{};
        switch (row.status_id) {
        case agent::OcsfStatus::Unknown: outcome = 0; break;
        case agent::OcsfStatus::Success: outcome = 1; break;
        case agent::OcsfStatus::Failure: outcome = 2; ++out.failures; break;
        default: return {};
        }
        const auto age = out.newest_receiver_ms - row.received_ms;
        const auto bin = static_cast<std::size_t>(3 - std::min<std::uint64_t>(age / 1000, 3));
        ++out.outcomes.at(outcome);
        ++out.activity.at(outcome).at(bin);
    }
    return out;
}
[[nodiscard]] inline std::optional<DashboardAlerts> summarize_alerts(const AlertPage& page) noexcept {
    if (page.result != "OK" || page.rows.size() > alert_page_size ||
        (page.more && page.rows.size() != alert_page_size)) { return {}; }
    DashboardAlerts out;
    std::array<std::string_view, alert_page_size> rules{};
    out.count = page.rows.size();
    for (const auto& row : page.rows) {
        if (row.status > 2 || row.severity > 5 || row.rule.empty()) { return {}; }
        const auto severity = static_cast<std::size_t>(row.severity);
        ++out.severities.at(severity);
        if (row.status != 2) { ++out.active_severities.at(severity); }
        if (row.status == 0) { ++out.open; }
        if (row.status == 1) { ++out.acknowledged; }
        if (row.status == 2) { ++out.resolved; }
        if (row.status != 2 && row.severity >= 4) { ++out.high_active; }
        const std::string_view rule = row.rule;
        const auto end = rules.begin() + static_cast<std::ptrdiff_t>(out.distinct_rules);
        if (std::find(rules.begin(), end, rule) == end) { rules.at(out.distinct_rules++) = rule; }
    }
    return out;
}
} // namespace knetsentry::service
