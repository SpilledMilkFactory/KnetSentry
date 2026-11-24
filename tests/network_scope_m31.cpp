// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/core/network_scope.hpp"

#include <array>
#include <bit>
#include <iostream>
#include <string>

using namespace knetsentry::core;
namespace {
using Decision = ScopeDecision;
int failures = 0;
void check(bool passed, std::string_view label) {
    if (!passed) {
        std::cerr << "M3.1 failed: " << label << '\n';
        ++failures;
    }
}
NetworkProposal propose(const EndpointApproval& endpoint) {
    return {NetworkComponent::Agent, NetworkPurpose::AgentTransport, NetworkProtocol::Tcp,
            endpoint, {RouteKind::OnLinkUnicast, endpoint.destination, endpoint.interface_index, 7}};
}
} // namespace

int main() {
    const EndpointApproval ipv4{"agent-A", "manager-A", "192.0.2.10", 3, 7443};
    const EndpointApproval ipv6{"agent-A", "manager-A", "2001:db8::10", 3, 7443};
    const EndpointApproval link{"agent-A", "manager-A", "fe80::10", 4, 7443};
    const EndpointApproval private_ip{"agent-A", "manager-A", "192.168.1.10", 3, 7443};
    const EndpointApproval ula{"agent-A", "manager-A", "fd00::10", 3, 7443};
    const std::array approvals{ipv4, ipv6, link, private_ip, ula};
    const auto policy = NetworkScopePolicy::compile(1, 7, approvals);
    check(policy.valid(), "valid snapshot");
    for (const auto& endpoint : approvals) {
        check(policy.evaluate(propose(endpoint)) == Decision::CandidateInScope, "exact approved endpoint");
    }
    auto proposal = propose(ipv6);
    proposal.endpoint.destination = "2001:0DB8:0000:0000:0000:0000:0000:0010";
    check(policy.evaluate(proposal) == Decision::CandidateInScope, "normalized IPv6");
    check(NetworkScopePolicy{}.evaluate(proposal) == Decision::DeniedPolicy, "default denied");
    const auto empty = NetworkScopePolicy::compile(1, 7, {});
    check(empty.valid() && empty.evaluate(proposal) == Decision::DeniedApproval, "empty denied");
    check(!NetworkScopePolicy::compile(2, 7, approvals).valid(), "schema rejected");
    check(!NetworkScopePolicy::compile(1, 0, approvals).valid(), "zero generation rejected");
    const std::array duplicates{ipv6, proposal.endpoint};
    check(!NetworkScopePolicy::compile(1, 7, duplicates).valid(), "normalized duplicate rejected");
    std::array<EndpointApproval, NetworkScopePolicy::max_approvals + 1> oversized{};
    check(!NetworkScopePolicy::compile(1, 7, oversized).valid(), "approval count bounded");
    proposal = propose(ipv4);
    for (const auto component : {NetworkComponent::Unknown, NetworkComponent::Manager,
             NetworkComponent::Collector, NetworkComponent::Intelligence, NetworkComponent::Ai,
             NetworkComponent::Desktop, std::bit_cast<NetworkComponent>(std::uint8_t{255})}) {
        proposal.component = component;
        check(policy.evaluate(proposal) == Decision::DeniedPurpose, "component denied");
    }
    proposal = propose(ipv4);
    for (const auto purpose : {NetworkPurpose::Unknown, NetworkPurpose::PassiveObservation,
             NetworkPurpose::ActiveDiscovery, NetworkPurpose::IntelligenceSync, NetworkPurpose::Administration,
             std::bit_cast<NetworkPurpose>(std::uint8_t{255})}) {
        proposal.purpose = purpose;
        check(policy.evaluate(proposal) == Decision::DeniedPurpose, "purpose denied");
    }
    proposal = propose(ipv4);
    for (const auto protocol : {NetworkProtocol::Unknown, NetworkProtocol::Udp,
             std::bit_cast<NetworkProtocol>(std::uint8_t{255})}) {
        proposal.protocol = protocol;
        check(policy.evaluate(proposal) == Decision::DeniedPurpose, "protocol denied");
    }
    for (const auto route : {RouteKind::Unknown, RouteKind::Routed, RouteKind::DefaultGateway,
             RouteKind::Overlay, RouteKind::Unavailable, std::bit_cast<RouteKind>(std::uint8_t{255})}) {
        proposal = propose(ipv4);
        proposal.route.kind = route;
        check(policy.evaluate(proposal) == Decision::DeniedRoute, "route denied");
    }
    proposal = propose(ipv4);
    proposal.route.policy_generation = 6;
    check(policy.evaluate(proposal) == Decision::DeniedRoute, "stale generation denied");
    proposal = propose(ipv4);
    proposal.route.interface_index = 8;
    check(policy.evaluate(proposal) == Decision::DeniedRoute, "route interface mismatch");
    proposal = propose(ipv4);
    proposal.route.destination = "192.0.2.11";
    check(policy.evaluate(proposal) == Decision::DeniedRoute, "route destination mismatch");
    for (const auto address : {"192.168.1.11", "198.51.100.10", "fd00::11", "2001:db8::11"}) {
        auto endpoint = ipv4;
        endpoint.destination = address;
        check(policy.evaluate(propose(endpoint)) == Decision::DeniedApproval, "unapproved numeric endpoint");
    }
    for (const std::string_view address : {"", "localhost", "192.0.2.010", "0xc000020a", "3221225994",
             "192.0.2.10/32", "192.0.2.10:7443", "[2001:db8::10]", "fe80::10%4", " 192.0.2.10",
             "0.0.0.0", "127.0.0.1", "224.0.0.1", "255.255.255.255", "::", "::1", "ff02::1",
             "::ffff:192.0.2.10", "::192.0.2.10", "64:ff9b::c000:20a", "2002:c000:20a::1", "2001:0::1"}) {
        auto endpoint = ipv4;
        endpoint.destination = address;
        check(policy.evaluate(propose(endpoint)) == Decision::DeniedEndpoint, "unsafe literal denied");
        const std::array invalid{ipv4, endpoint};
        const auto rejected = NetworkScopePolicy::compile(1, 7, invalid);
        check(!rejected.valid() && rejected.evaluate(propose(ipv4)) == Decision::DeniedPolicy,
              "invalid snapshot cannot retain partial approval");
    }
    auto endpoint = ipv4;
    endpoint.destination = std::string_view{"192.0.2.10\0junk", sizeof("192.0.2.10\0junk") - 1};
    check(policy.evaluate(propose(endpoint)) == Decision::DeniedEndpoint, "embedded NUL denied");
    endpoint = link;
    endpoint.interface_index = 5;
    check(policy.evaluate(propose(endpoint)) == Decision::DeniedApproval, "link-local interface binding");
    endpoint = ipv4;
    endpoint.agent = "agent-B";
    check(policy.evaluate(propose(endpoint)) == Decision::DeniedApproval, "agent mismatch");
    endpoint = ipv4;
    endpoint.manager = "manager-B";
    check(policy.evaluate(propose(endpoint)) == Decision::DeniedApproval, "manager mismatch");
    endpoint = ipv4;
    endpoint.port = 443;
    check(policy.evaluate(propose(endpoint)) == Decision::DeniedApproval, "port mismatch");
    endpoint.port = 0;
    check(policy.evaluate(propose(endpoint)) == Decision::DeniedEndpoint, "zero port");
    endpoint = ipv4;
    endpoint.interface_index = 0;
    check(policy.evaluate(propose(endpoint)) == Decision::DeniedEndpoint, "zero interface");
    endpoint = ipv4;
    endpoint.agent = "agent\nA";
    check(policy.evaluate(propose(endpoint)) == Decision::DeniedEndpoint, "invalid identity");
    const std::string too_long(65, 'a');
    endpoint.agent = too_long;
    check(policy.evaluate(propose(endpoint)) == Decision::DeniedEndpoint, "identity length bounded");
    std::string mutable_identity = "agent-A";
    endpoint = ipv4;
    endpoint.agent = mutable_identity;
    const std::array owned{endpoint};
    const auto copied = NetworkScopePolicy::compile(1, 7, owned);
    mutable_identity[0] = 'X';
    check(copied.evaluate(propose(ipv4)) == Decision::CandidateInScope, "snapshot owns approval values");
    std::array<EndpointApproval, NetworkScopePolicy::max_approvals> maximum{};
    for (std::size_t index = 0; index < maximum.size(); ++index) {
        maximum[index] = ipv4;
        maximum[index].port = static_cast<std::uint16_t>(index + 1);
    }
    const auto full = NetworkScopePolicy::compile(1, 7, maximum);
    check(full.valid() && full.evaluate(propose(maximum.back())) == Decision::CandidateInScope,
          "maximum approved rule count and last entry");
    const auto newer = NetworkScopePolicy::compile(1, 8, approvals);
    proposal = propose(ipv4);
    check(newer.evaluate(proposal) == Decision::DeniedRoute, "new snapshot rejects old evidence");
    proposal.route.policy_generation = 8;
    check(newer.evaluate(proposal) == Decision::CandidateInScope, "new generation matches");
    if (failures != 0) {
        return 1;
    }
    std::cout << "M3.1 exact endpoint policy, purpose separation, route binding and fail-closed fixtures: PASS\n";
    return 0;
}
