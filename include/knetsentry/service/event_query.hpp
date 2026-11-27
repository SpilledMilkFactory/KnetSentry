// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <knetsentry/storage/event_store.hpp>
#include <optional>
#include <string>
#include <string_view>

namespace knetsentry::service {
inline constexpr std::size_t event_page_size = 8;
inline constexpr std::size_t max_event_request = 256;
inline constexpr std::size_t max_event_response = 4096;
struct EventQuery {
    std::string source;
    int mode{-1}, outcome{-1}; // -1 = any; supported wire values 0..2.
    bool descending{};
    std::uint64_t after{}, revision{};
    std::string session; // manager instance; empty only on initial request.
};
struct EventPage {
    storage::SearchPage page;
    std::string session;
};
[[nodiscard]] bool valid_event_query(const EventQuery& q) noexcept;
[[nodiscard]] std::string encode_event_request(const EventQuery& q, std::string_view id);
[[nodiscard]] std::optional<EventQuery> decode_event_request(std::string_view payload, std::string_view id);
[[nodiscard]] std::string query_events(const storage::EventStore* store, std::string_view session,
    const EventQuery& q, std::string_view id);
[[nodiscard]] std::optional<EventPage> decode_event_page(std::string_view payload, std::string_view id,
    const EventQuery& q);
} // namespace knetsentry::service
