// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/core/network_authorization.hpp"
#include "linux_topology_detail.hpp"

#include <array>
#include <chrono>
#include <iostream>
#include <net/if.h>
#include <string_view>
#include <thread>

namespace {
using namespace knetsentry::core;
namespace detail = knetsentry::core::topology_detail;
constexpr std::uint16_t port = 37443;
constexpr std::uint64_t generation = 36;
int failures = 0;
void check(bool ok, std::string_view label) {
    if (!ok) { std::cerr << "M3.6 FAIL: " << label << '\n'; ++failures; }
}
void check_route(const detail::Address& address, std::uint32_t index, bool fib_match,
                 std::string_view literal) {
    detail::RouteReplyShape shape{};
    const auto result = detail::query_route(address, index, port, fib_match, &shape);
    if (result != detail::Inspection::Accepted) {
        std::cerr << "M3.6 route diagnostic: endpoint=" << literal
                  << " lookup=" << (fib_match ? "FIB" : "effective")
                  << " inspection=" << (result == detail::Inspection::Rejected ? "rejected" : "unavailable")
                  << " reply=" << shape.received << " attributes_valid=" << shape.attributes_valid
                  << " family=" << shape.family << " src_bits=" << shape.source_bits
                  << " dst_bits=" << shape.destination_bits << " table=" << shape.table
                  << " type=" << shape.type << " scope=" << shape.scope << " flags=" << shape.flags
                  << " zero_source=" << shape.zero_source << " attributes(type:length)=";
        for (std::size_t i = 0; i < shape.count; ++i) {
            std::cerr << ' ' << shape.attributes[i].type << ':' << shape.attributes[i].size;
        }
        std::cerr << '\n';
    } else {
        std::cout << "M3.6 route PASS: endpoint=" << literal
                  << " lookup=" << (fib_match ? "FIB" : "effective")
                  << " src_bits=" << shape.source_bits << " zero_source=" << shape.zero_source << '\n';
    }
    check(result == detail::Inspection::Accepted, fib_match ? "actual FIB route" : "actual effective route");
}
void exercise(std::uint32_t index, bool live) {
    const std::array approvals{EndpointApproval{"agent", "manager", "192.0.2.2", index, port},
        EndpointApproval{"agent", "manager", "2001:db8:36::2", index, port}};
    const std::array bindings{InterfaceBinding{index, "ks36a"}};
    const auto policy = NetworkScopePolicy::compile(1, generation, approvals);
    check(policy.valid(), "fixture policy");
    for (const auto& approved : approvals) {
        NetworkProposal proposal{NetworkComponent::Agent, NetworkPurpose::AgentTransport,
            NetworkProtocol::Tcp, approved, {RouteKind::OnLinkUnicast, approved.destination, index, generation}};
        check(policy.evaluate(proposal) == ScopeDecision::CandidateInScope, "synthetic approved candidate");
        auto denied = proposal;
        denied.endpoint.destination = approved.destination == "192.0.2.2" ? "192.0.2.3" : "2001:db8:36::3";
        denied.route.destination = denied.endpoint.destination;
        check(policy.evaluate(denied) == ScopeDecision::DeniedApproval, "reachable but unapproved address");
        denied = proposal;
        denied.endpoint.port = port + 1;
        check(policy.evaluate(denied) == ScopeDecision::DeniedApproval, "unapproved port");
        denied = proposal;
        denied.endpoint.manager = "other";
        check(policy.evaluate(denied) == ScopeDecision::DeniedApproval, "unapproved identity");
        denied = proposal;
        denied.endpoint.interface_index = index + 1;
        denied.route.interface_index = index + 1;
        check(policy.evaluate(denied) == ScopeDecision::DeniedApproval, "unapproved interface");
        denied = proposal;
        denied.protocol = NetworkProtocol::Udp;
        check(policy.evaluate(denied) == ScopeDecision::DeniedPurpose, "unapproved protocol");
        denied = proposal;
        denied.route.policy_generation = generation - 1;
        check(policy.evaluate(denied) == ScopeDecision::DeniedRoute, "stale route evidence");
        if (live) {
            detail::Address address{};
            check(detail::parse_address(approved.destination, address), "fixture address");
            check_route(address, index, false, approved.destination);
            check_route(address, index, true, approved.destination);
            detail::Address outside{};
            check(detail::parse_address(approved.destination == "192.0.2.2" ? "198.51.100.2" :
                  "2001:db8:37::2", outside), "out-of-segment fixture address");
            check(detail::query_route(outside, index, port, false) != detail::Inspection::Accepted,
                  "no approved route outside the isolated segment");
            check(detail::query_link(index, "ks36a") == detail::Inspection::Rejected,
                  "production virtual attachment denied");
            NetworkAuthorization gate;
            check(gate.activate(ConfigurationEvidence::Validated, 1, generation, approvals, {}, bindings) ==
                  AuthorizationState::Ready, "activation");
            auto unapproved = proposal;
            unapproved.endpoint.port = port + 1;
            const auto ordinary = gate.evaluate(unapproved, generation);
            check(ordinary.state == AuthorizationState::Ready && !ordinary.candidate_in_scope(),
                  "ordinary denial does not withdraw authority");
            const auto result = gate.evaluate(proposal, generation);
            check(!result.candidate_in_scope() && result.state == AuthorizationState::RouteUnverified,
                  "production authority withdrawn despite reachable virtual peer");
            check(gate.activate(ConfigurationEvidence::Validated, 1, generation, approvals, {}, bindings) ==
                  AuthorizationState::StaleGeneration, "stale reactivation denied");
        }
    }
}
void adversarial() {
    constexpr std::array v4{PrefixApproval{"agent", "manager", "192.0.2.0/24", 7, port}};
    constexpr std::array v6{PrefixApproval{"agent", "manager", "2001:db8:36::/64", 7, port}};
    const auto only4 = NetworkScopePolicy::compile(2, generation, {}, v4);
    const auto only6 = NetworkScopePolicy::compile(2, generation, {}, v6);
    check(only4.valid() && only6.valid(), "M3.7 independent prefix policies");
    const auto proposal = [](std::string_view address) {
        return NetworkProposal{NetworkComponent::Agent, NetworkPurpose::AgentTransport,
            NetworkProtocol::Tcp, {"agent", "manager", address, 7, port},
            {RouteKind::OnLinkUnicast, address, 7, generation}};
    };
    using Decision = ScopeDecision;
    const auto expect = [&](const NetworkScopePolicy& policy, const NetworkProposal& input,
                            Decision expected, std::string_view label) {
        check(policy.evaluate(input) == expected, label);
    };
    expect(only4, proposal("192.0.2.2"), Decision::CandidateInScope, "M3.7 IPv4 control");
    expect(only6, proposal("2001:db8:36::2"), Decision::CandidateInScope, "M3.7 IPv6 control");
    expect(only4, proposal("2001:db8:36::2"), Decision::DeniedApproval, "M3.7 no implicit IPv6");
    expect(only6, proposal("192.0.2.2"), Decision::DeniedApproval, "M3.7 no implicit IPv4");
    expect(only4, proposal("203.0.113.2"), Decision::DeniedApproval, "M3.7 distinct network denied");
    expect(only6, proposal("2001:db8:38::2"), Decision::DeniedApproval, "M3.7 outside IPv6 prefix");
    for (const auto address : {"::ffff:c000:202", "::ffff:192.0.2.2", "64:ff9b::c000:202",
             "2002:c000:202::1", "2001::1", "ff02::1", "fe80::2%7", "::", "::1"}) {
        expect(only4, proposal(address), Decision::DeniedEndpoint, "M3.7 ambiguous IPv6 denied");
        expect(only6, proposal(address), Decision::DeniedEndpoint, "M3.7 ambiguous IPv6 denied");
    }
    for (const auto& policy : {&only4, &only6}) {
        const auto base = proposal(policy == &only4 ? "192.0.2.2" : "2001:db8:36::2");
        auto altered = base;
        altered.protocol = NetworkProtocol::Udp;
        expect(*policy, altered, Decision::DeniedPurpose, "M3.7 protocol substitution");
        altered = base;
        altered.purpose = NetworkPurpose::IntelligenceSync;
        expect(*policy, altered, Decision::DeniedPurpose, "M3.7 purpose substitution");
        altered = base;
        altered.component = NetworkComponent::Collector;
        expect(*policy, altered, Decision::DeniedPurpose, "M3.7 component substitution");
        altered = base;
        altered.endpoint.agent = "different";
        expect(*policy, altered, Decision::DeniedApproval, "M3.7 agent substitution");
        altered = base;
        altered.endpoint.manager = "different";
        expect(*policy, altered, Decision::DeniedApproval, "M3.7 manager substitution");
        altered = base;
        altered.endpoint.port = port + 1;
        expect(*policy, altered, Decision::DeniedApproval, "M3.7 port substitution");
        altered = base;
        altered.endpoint.interface_index = 8;
        altered.route.interface_index = 8;
        expect(*policy, altered, Decision::DeniedApproval, "M3.7 interface substitution");
        altered = base;
        altered.route.destination = policy == &only4 ? "192.0.2.3" : "2001:db8:36::3";
        expect(*policy, altered, Decision::DeniedRoute, "M3.7 wrong route destination");
        altered = base;
        altered.route.interface_index = 8;
        expect(*policy, altered, Decision::DeniedRoute, "M3.7 wrong route interface");
        for (const auto revision : {generation - 1, generation + 1, std::uint64_t{0}}) {
            altered = base;
            altered.route.policy_generation = revision;
            expect(*policy, altered, Decision::DeniedRoute, "M3.7 wrong route revision");
        }
        for (const auto kind : {RouteKind::Unknown, RouteKind::Routed, RouteKind::DefaultGateway,
                 RouteKind::Overlay, RouteKind::Unavailable}) {
            altered = base;
            altered.route.kind = kind;
            expect(*policy, altered, Decision::DeniedRoute, "M3.7 unsupported route kind");
        }
    }
}
int watch(bool restoration) {
    const auto index = if_nametoindex("ks36a");
    if (index == 0) { return 1; }
    const std::array approvals{EndpointApproval{"agent", "manager", "192.0.2.2", index, port}};
    const std::array bindings{InterfaceBinding{index, "ks36a"}};
    NetworkAuthorization gate;
    if (gate.activate(ConfigurationEvidence::Validated, 1, generation, approvals, {}, bindings) !=
        AuthorizationState::Ready) { return 1; }
    std::cout << "READY" << std::endl;
    if (std::cin.get() != '\n') { return 1; }
    for (int attempt = 0; attempt < 100; ++attempt) {
        if (gate.check_changes() == AuthorizationState::TopologyInvalidated) {
            const NetworkProposal proposal{NetworkComponent::Agent, NetworkPurpose::AgentTransport,
                NetworkProtocol::Tcp, approvals.front(), {RouteKind::OnLinkUnicast, "192.0.2.2", index, generation}};
            const auto denied = gate.evaluate(proposal, generation);
            if (denied.candidate_in_scope() || denied.state != AuthorizationState::TopologyInvalidated) {
                return 1;
            }
            if (restoration) {
                std::cout << "INVALIDATED" << std::endl;
                if (std::cin.get() != '\n' || gate.check_changes() != AuthorizationState::TopologyInvalidated ||
                    gate.evaluate(proposal, generation).candidate_in_scope()) { return 1; }
            }
            return gate.activate(ConfigurationEvidence::Validated, 1, generation, approvals, {}, bindings) ==
                    AuthorizationState::StaleGeneration ? 0 : 1;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    return 1;
}
} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view{argv[1]} == "--watch") { return watch(false); }
    if (argc == 2 && std::string_view{argv[1]} == "--watch-restoration") { return watch(true); }
    if (argc == 2 && std::string_view{argv[1]} == "--adversarial") {
        adversarial();
        if (failures == 0) { std::cout << "M3.7 adversarial policy matrix: PASS\n"; }
        return failures == 0 ? 0 : 1;
    }
    if (argc == 2 && (std::string_view{argv[1]} == "--route-denied-v4" ||
                      std::string_view{argv[1]} == "--route-denied-v6")) {
        const auto index = if_nametoindex("ks36a");
        detail::Address address{};
        const auto literal = std::string_view{argv[1]} == "--route-denied-v4"
            ? "192.0.2.2" : "2001:db8:36::2";
        if (index == 0 || !detail::parse_address(literal, address)) { return 1; }
        return detail::query_route(address, index, port, false) != detail::Inspection::Accepted &&
            detail::query_route(address, index, port, true) != detail::Inspection::Accepted ? 0 : 1;
    }
    if (argc == 1) {
        exercise(7, false);
        if (failures == 0) { std::cout << "M3.6 synthetic policy fixture: PASS\n"; }
    } else if (argc == 2 && std::string_view{argv[1]} == "--live") {
        const auto index = if_nametoindex("ks36a");
        if (index == 0) { return 1; }
        exercise(index, true);
        if (failures == 0) { std::cout << "M3.6 live route and production virtual attachment denial: PASS\n"; }
    } else { return 1; }
    return failures == 0 ? 0 : 1;
}
