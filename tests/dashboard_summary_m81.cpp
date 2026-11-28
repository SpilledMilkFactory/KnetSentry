// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/service/dashboard_summary.hpp>
#include <iostream>
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
    return 0;
} catch (const std::exception& e) {
    std::cerr << "M8.1 dashboard summary failure: " << e.what() << '\n';
    return 1;
}
