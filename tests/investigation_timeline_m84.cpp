// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/service/investigation_timeline.hpp>
#include <iostream>
#include <stdexcept>

namespace {
using namespace knetsentry::service;
void require(bool value, const char* message) { if (!value) { throw std::runtime_error(message); } }
void verify() {
    EventPage events; events.session = "same"; events.page.status = knetsentry::storage::StoreStatus::Ok;
    AlertPage alerts; alerts.session = events.session; alerts.result = "OK";
    const auto empty = investigation_timeline(events, alerts);
    require(empty && empty->empty(), "available empty");
    knetsentry::storage::EventSummary e; e.id = 9; e.received_ms = 30; e.time_ms = 1; e.source_unit = "ssh.service"; e.source_mode = knetsentry::agent::JournalMode::Authentication;
    events.page.events.push_back(e); e.id = 8; e.received_ms = 20; e.time_ms = 100; events.page.events.push_back(e);
    AlertRow a; a.generation = 1; a.trigger = 9; a.revision = 1; a.created = 20; a.updated = 30; a.rule = "rule";
    a.source = "ssh.service"; a.evidence = {1, 9}; alerts.rows.push_back(a);
    const auto rows = investigation_timeline(events, alerts);
    require(rows && rows->size() == 3 && rows->at(0).id == 8 && !rows->at(0).alert() && rows->at(1).alert() && rows->at(2).id == 9, "receipt/creation and deterministic tie order");
    require(timeline_link(events.page.events.at(0), a) && !timeline_link(events.page.events.at(1), a), "explicit ID only");
    auto incompatible = events.page.events.at(0); incompatible.source_mode = knetsentry::agent::JournalMode::Metadata;
    require(!timeline_link(incompatible, a), "collector conflict");
    a.source = "other.service"; require(!timeline_link(events.page.events.at(0), a), "source conflict");
    alerts.session = "other"; require(!investigation_timeline(events, alerts), "instance mismatch"); alerts.session = events.session;
    alerts.result = "DENIED"; require(!investigation_timeline(events, alerts), "denied"); alerts.result = "OK";
    events.page.events.push_back(e); require(!investigation_timeline(events, alerts), "duplicate ID"); events.page.events.pop_back();
    alerts.rows.front().evidence = {9, 9}; require(!investigation_timeline(events, alerts), "duplicate evidence"); alerts.rows.front().evidence = {1, 9};
    alerts.more = true; require(!investigation_timeline(events, alerts), "inconsistent page"); alerts.more = false;
    events.page.events.front().received_ms = UINT64_MAX;
    const auto extreme = investigation_timeline(events, alerts);
    require(extreme && extreme->back().time == UINT64_MAX, "full width time");
    events.page.events.resize(9); require(!investigation_timeline(events, alerts), "oversized event page");
}
} // namespace
int main() {
    try { verify(); std::cout << "M8.4 chronology, explicit links and refusal: PASS\n"; return 0; }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
