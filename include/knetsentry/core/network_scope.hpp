// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace knetsentry::core {

// Pure preflight decision, not a socket or authenticated session.
enum class NetworkComponent : std::uint8_t { Unknown, Agent, Manager, Collector, Intelligence, Ai, Desktop };
enum class NetworkPurpose : std::uint8_t { Unknown, AgentTransport, PassiveObservation, ActiveDiscovery, IntelligenceSync, Administration };
enum class NetworkProtocol : std::uint8_t { Unknown, Tcp, Udp };
enum class RouteKind : std::uint8_t { Unknown, OnLinkUnicast, Routed, DefaultGateway, Overlay, Unavailable };
enum class ScopeDecision : std::uint8_t {
    DeniedPolicy, DeniedPurpose, DeniedEndpoint, DeniedRoute, DeniedApproval,
    CandidateInScope
};

struct EndpointApproval final {
    std::string_view agent;
    std::string_view manager;
    std::string_view destination;
    std::uint32_t interface_index{};
    std::uint16_t port{};
};

// Schema 2 only: canonical numeric CIDR network, never a proposed endpoint.
struct PrefixApproval final {
    std::string_view agent;
    std::string_view manager;
    std::string_view network;
    std::uint32_t interface_index{};
    std::uint16_t port{};
};

// Trusted topology adapter input, never telemetry or remote fields.
// This pure policy does not acquire live evidence. See LinuxTopology for
// the separate kernel-facing preflight adapter.
struct RouteEvidence final {
    RouteKind kind{RouteKind::Unknown};
    std::string_view destination;
    std::uint32_t interface_index{};
    std::uint64_t policy_generation{};
};

struct NetworkProposal final {
    NetworkComponent component{NetworkComponent::Unknown};
    NetworkPurpose purpose{NetworkPurpose::Unknown};
    NetworkProtocol protocol{NetworkProtocol::Unknown};
    EndpointApproval endpoint{};
    RouteEvidence route{};
};

class NetworkScopePolicy final {
public:
    static constexpr std::size_t max_approvals = 64;
    static constexpr std::size_t max_identity_length = 64;
    NetworkScopePolicy() = default;

    // Trusted administrator-approved input only. Invalid or duplicate rules
    // invalidate the entire snapshot; no partial allowlist is published.
    [[nodiscard]] static NetworkScopePolicy compile(
        std::uint32_t schema, std::uint64_t generation,
        std::span<const EndpointApproval> approvals) noexcept;
    // Schema 2 explicitly enables prefix approvals. The combined limit is
    // max_approvals; overlapping rules for the same identity/interface/port
    // are rejected, including exact entries covered by a prefix.
    [[nodiscard]] static NetworkScopePolicy compile(
        std::uint32_t schema, std::uint64_t generation,
        std::span<const EndpointApproval> approvals,
        std::span<const PrefixApproval> prefixes) noexcept;
    [[nodiscard]] bool valid() const noexcept { return valid_; }
    [[nodiscard]] std::uint64_t generation() const noexcept { return generation_; }
    [[nodiscard]] ScopeDecision evaluate(const NetworkProposal& proposal) const noexcept;

private:
    struct Address final {
        std::array<std::uint8_t, 16> bytes{};
        std::uint8_t family{};
        bool operator==(const Address&) const = default;
    };
    struct Rule final {
        std::array<char, max_identity_length> agent{};
        std::array<char, max_identity_length> manager{};
        Address destination{};
        std::uint32_t interface_index{};
        std::uint16_t port{};
        std::uint8_t prefix_length{};
        bool operator==(const Rule&) const = default;
    };
    [[nodiscard]] static bool parse_address(std::string_view text, Address& result) noexcept;
    [[nodiscard]] static bool parse_endpoint(const EndpointApproval& input, Rule& result) noexcept;
    [[nodiscard]] static bool parse_prefix(const PrefixApproval& input, Rule& result) noexcept;
    [[nodiscard]] static bool same_binding(const Rule& first, const Rule& second) noexcept;
    [[nodiscard]] static bool contains(const Address& network, std::uint8_t length,
                                       const Address& address) noexcept;
    [[nodiscard]] static bool matches(const Rule& rule, const Rule& candidate) noexcept;
    [[nodiscard]] bool append(const Rule& rule) noexcept;
    std::array<Rule, max_approvals> rules_{};
    std::size_t count_{};
    std::uint64_t generation_{};
    bool valid_{};
};

} // namespace knetsentry::core
