// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/service/dashboard_summary.hpp>
#include <iostream>
#include <limits>
#include <stdexcept>
namespace {
using namespace knetsentry::service;
void require(bool ok, const char* message) { if (!ok) { throw std::runtime_error(message); } }
void verify() {
    EventPage events;
    require(!summarize_events(events), "unavailable is not zero");
    events.page.status = knetsentry::storage::StoreStatus::Ok;
    const auto emptyEvents = summarize_events(events);
    require(emptyEvents && emptyEvents->count == 0, "verified empty page");
    events.page.more = true;
    require(!summarize_events(events), "short truncated page");
    events.page.events.resize(event_page_size);
    events.page.events.front().status_id = knetsentry::agent::OcsfStatus::Failure;
    events.page.events.front().received_ms = 100;
    events.page.events.back().received_ms = 9;
    const auto e = summarize_events(events);
    require(e && e->count == 8 && e->failures == 1 && e->newest_receiver_ms == 100, "page-local counts and receiver maximum");
    require(e->outcomes == std::array<std::size_t, 3>{7, 0, 1}, "outcome histogram");
    require(e->activity.at(0) == std::array<std::size_t, 4>{0, 0, 0, 7} &&
        e->activity.at(2) == std::array<std::size_t, 4>{0, 0, 0, 1}, "receiver bins");
    // Deliberately not in timestamp order. Check exact bin edges and full-width arithmetic.
    const auto maximum = std::numeric_limits<std::uint64_t>::max();
    const std::array<std::uint64_t, 8> ages{1000, 0, 3000, 999, 2000, 2999, 1999, maximum};
    for (std::size_t i = 0; i < ages.size(); ++i) {
        auto& row = events.page.events.at(i);
        row.received_ms = maximum - ages.at(i);
        row.status_id = knetsentry::agent::OcsfStatus::Success;
    }
    events.page.events.at(2).status_id = knetsentry::agent::OcsfStatus::Failure;
    const auto edges = summarize_events(events);
    require(edges && edges->newest_receiver_ms == maximum &&
        edges->outcomes == std::array<std::size_t, 3>{0, 7, 1} &&
        edges->activity.at(1) == std::array<std::size_t, 4>{1, 2, 2, 2} &&
        edges->activity.at(2) == std::array<std::size_t, 4>{1, 0, 0, 0}, "receiver age boundaries and extreme timestamps");
    require(emptyEvents->outcomes == std::array<std::size_t, 3>{} &&
        emptyEvents->activity.at(0) == std::array<std::size_t, 4>{}, "verified empty histogram");
    events.page.events.emplace_back();
    require(!summarize_events(events), "oversized events");
    events.page.events.clear();
    events.page.status = knetsentry::storage::StoreStatus::IntegrityFailure;
    require(!summarize_events(events), "integrity failure");
    AlertPage alerts;
    require(!summarize_alerts(alerts), "unavailable alerts");
    alerts.result = "OK";
    const auto emptyAlerts = summarize_alerts(alerts);
    require(emptyAlerts && emptyAlerts->count == 0, "verified empty alerts");
    alerts.rows.resize(alert_page_size);
    alerts.more = true;
    for (auto& row : alerts.rows) { row.rule = "fixture-rule"; row.severity = 4; }
    alerts.rows.at(1).status = 1;
    alerts.rows.at(2).status = 2;
    alerts.rows.at(2).rule = "other-fixture-rule";
    const auto a = summarize_alerts(alerts);
    require(a && a->count == 8 && a->open == 6 && a->acknowledged == 1 && a->resolved == 1 &&
        a->distinct_rules == 2 && a->high_active == 7, "bounded lifecycle and distinct-rule counts");
    require(a->severities == std::array<std::size_t, 6>{0, 0, 0, 0, 8, 0} &&
        a->active_severities == std::array<std::size_t, 6>{0, 0, 0, 0, 7, 0}, "active severity distribution");
    for (std::size_t i = 0; i < alerts.rows.size(); ++i) { alerts.rows.at(i).severity = i % 6; }
    const auto mixed = summarize_alerts(alerts);
    require(mixed && mixed->severities == std::array<std::size_t, 6>{2, 2, 1, 1, 1, 1} &&
        mixed->active_severities == std::array<std::size_t, 6>{2, 2, 0, 1, 1, 1}, "all severity values and resolved exclusion");
    require(emptyAlerts->severities == std::array<std::size_t, 6>{}, "verified empty distribution");
    alerts.rows.front().status = 3;
    require(!summarize_alerts(alerts), "unknown lifecycle");
    alerts.rows.front().status = 0;
    alerts.rows.front().severity = 6;
    require(!summarize_alerts(alerts), "unknown severity");
    alerts.rows.front().severity = 4;
    alerts.rows.front().rule.clear();
    require(!summarize_alerts(alerts), "missing rule");
    alerts.rows.front().rule = "fixture-rule";
    alerts.rows.emplace_back();
    require(!summarize_alerts(alerts), "oversized alerts");
    alerts.rows.clear();
    require(!summarize_alerts(alerts), "short truncated alerts");
    alerts.more = false;
    alerts.result = "DENIED";
    require(!summarize_alerts(alerts), "denied is not zero");
}
} // namespace
int main() try {
    verify();
    std::cout << "M8.1 bounded stored page summaries and unavailable/empty distinction: PASS\n";
    std::cout << "M8.2 outcome histogram, receiver bins and severity distributions: PASS\n";
    return 0;
} catch (const std::exception& e) {
    std::cerr << "M8.1 dashboard summary failure: " << e.what() << '\n';
    return 1;
}
