// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <knetsentry/detection/alerts.hpp>
#include <optional>
namespace knetsentry::service {
inline constexpr std::size_t alert_page_size = 8, max_alert_response = 4096;
struct AlertQuery {
    enum class Operation { List, Acknowledge, Evidence };
    Operation operation{Operation::List};
    int severity{-1};
    std::uint64_t offset{}, generation{}, trigger{}, revision{}, evidence{};
    std::string session;
};
struct AlertRow {
    std::uint64_t generation{}, trigger{}, revision{}, severity{}, status{}, created{}, updated{}, coverage{};
    std::string rule, source;
    std::vector<std::uint64_t> evidence;
};
struct AlertPage {
    std::string session, result;
    bool more{}, writable{};
    std::vector<AlertRow> rows;
    std::uint64_t evidence{}, source_time{}, receiver_time{}, outcome{}, origin{};
};
// Explicit development profile: exact SSH failure rule, not arbitrary production policy loading.
[[nodiscard]] std::optional<detection::SchedulePolicy> alert_profile(std::string_view scope);
[[nodiscard]] std::optional<detection::SchedulePolicy> load_alert_profile(std::string_view directory);
[[nodiscard]] std::string encode_alert_request(const AlertQuery& q, std::string_view id);
[[nodiscard]] std::optional<AlertQuery> decode_alert_request(std::string_view payload, std::string_view id);
[[nodiscard]] std::optional<AlertPage> decode_alert_page(std::string_view payload, std::string_view id, const AlertQuery& q);
[[nodiscard]] std::string query_alerts(const detection::SchedulePolicy& policy, std::string_view directory,
    const storage::EventStore& store, std::string_view session, const AlertQuery& q, std::string_view id,
    bool writable, std::string_view actor, std::uint64_t now);
} // namespace knetsentry::service
