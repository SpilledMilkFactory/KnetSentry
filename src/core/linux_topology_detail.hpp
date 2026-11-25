// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace knetsentry::core::topology_detail {
using Bytes = std::span<const std::byte>;
enum class Inspection : std::uint8_t { Unavailable, Rejected, Accepted };
struct Address final {
    std::array<std::byte, 16> bytes{};
    int family{};
    std::size_t size{};
};
[[nodiscard]] bool parse_address(std::string_view text, Address& address) noexcept;
// Message payloads, excluding the netlink header. Strict single path profile.
[[nodiscard]] bool direct_route(Bytes payload, const Address& destination,
    std::uint32_t index, bool fib_match) noexcept;
[[nodiscard]] bool approved_link(Bytes payload, std::uint32_t index,
    std::string_view name) noexcept;
// Optional bounded reply-shape diagnostics for synthetic live tests only.
// No addresses, attribute payloads or interface names are retained.
struct RouteAttributeShape final { unsigned type{}; std::size_t size{}; };
struct RouteReplyShape final {
    bool received{};
    bool attributes_valid{};
    bool zero_source{};
    unsigned family{}, source_bits{}, destination_bits{}, table{}, type{}, scope{}, flags{};
    std::array<RouteAttributeShape, 32> attributes{};
    std::size_t count{};
};
// Read-only kernel exchanges; kept internal rather than returning reusable evidence.
[[nodiscard]] Inspection query_route(const Address& destination, std::uint32_t index,
    std::uint16_t port, bool fib_match, RouteReplyShape* shape = nullptr) noexcept;
[[nodiscard]] Inspection query_link(std::uint32_t index, std::string_view name) noexcept;
[[nodiscard]] bool watcher_quiet(int descriptor) noexcept;
} // namespace knetsentry::core::topology_detail
