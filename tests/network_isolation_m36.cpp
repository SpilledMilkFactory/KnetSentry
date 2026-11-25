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
            check(detail::query_route(address, index, port, false) == detail::Inspection::Accepted,
                  "actual effective route");
            check(detail::query_route(address, index, port, true) == detail::Inspection::Accepted,
                  "actual FIB route");
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
int watch() {
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
            return !denied.candidate_in_scope() && denied.state == AuthorizationState::TopologyInvalidated &&
                gate.activate(ConfigurationEvidence::Validated, 1, generation, approvals, {}, bindings) ==
                    AuthorizationState::StaleGeneration ? 0 : 1;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    return 1;
}
} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view{argv[1]} == "--watch") { return watch(); }
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
