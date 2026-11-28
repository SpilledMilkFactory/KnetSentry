// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <knetsentry/service/dashboard_summary.hpp>
#include <tuple>
#include <functional>

namespace knetsentry::service {
// An index into the validated pages, not a new identity or correlation result.
struct TimelineEntry {
    std::uint64_t time{}, generation{}, id{}; // generation zero denotes event
    std::size_t index{};
    [[nodiscard]] bool alert() const noexcept { return generation != 0; }
};
[[nodiscard]] inline std::optional<std::vector<TimelineEntry>> investigation_timeline(
    const EventPage& events, const AlertPage& alerts) {
    if (events.session.empty() || events.session != alerts.session ||
        !summarize_events(events) || !summarize_alerts(alerts)) { return {}; }
    std::vector<TimelineEntry> rows;
    rows.reserve(event_page_size + alert_page_size);
    for (std::size_t i = 0; i < events.page.events.size(); ++i) {
        const auto& e = events.page.events[i];
        if (!e.id || !e.received_ms || e.source_unit.empty()) { return {}; }
        rows.push_back({e.received_ms, 0, e.id, i});
    }
    for (std::size_t i = 0; i < alerts.rows.size(); ++i) {
        const auto& a = alerts.rows[i];
        if (!a.generation || !a.trigger || !a.revision || !a.created || a.updated < a.created ||
            a.source.empty() || a.evidence.empty() || a.evidence.size() > 16 ||
            a.evidence.front() == 0 || a.evidence.back() != a.trigger ||
            std::adjacent_find(a.evidence.begin(), a.evidence.end(), std::greater_equal<>{}) != a.evidence.end()) { return {}; }
        rows.push_back({a.created, a.generation, a.trigger, i});
    }
    for (std::size_t i = 0; i < rows.size(); ++i) {
        for (std::size_t j = 0; j < i; ++j) {
            if (rows[i].generation == rows[j].generation && rows[i].id == rows[j].id) { return {}; }
        }
    }
    std::sort(rows.begin(), rows.end(), [](const auto& a, const auto& b) {
        return std::tie(a.time, a.generation, a.id) < std::tie(b.time, b.generation, b.id);
    });
    return rows;
}
// Same returned store ID AND source unit; never infer a relationship from time or unit alone.
[[nodiscard]] inline bool timeline_link(const storage::EventSummary& event, const AlertRow& alert) {
    return event.source_mode == agent::JournalMode::Authentication && event.source_unit == alert.source &&
        std::find(alert.evidence.begin(), alert.evidence.end(), event.id) != alert.evidence.end();
}
} // namespace knetsentry::service
