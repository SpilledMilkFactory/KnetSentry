// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/core/network_authorization.hpp"

#include <array>
#include <bit>
#include <iostream>
#include <limits>
#include <string>
#include <sys/resource.h>
#include <type_traits>

namespace {
using namespace knetsentry::core;
using State = AuthorizationState;
using Config = ConfigurationEvidence;
constexpr EndpointApproval endpoint{"agent", "manager", "192.0.2.10", 1, 7443};
constexpr std::array approvals{endpoint};
constexpr std::array bindings{InterfaceBinding{1, "lo"}};
constexpr NetworkProposal proposal{NetworkComponent::Agent, NetworkPurpose::AgentTransport,
    NetworkProtocol::Tcp, endpoint, {RouteKind::OnLinkUnicast, endpoint.destination, 1, 1}};
int failures{};
void check(bool condition, std::string_view label) {
    if (!condition) { std::cerr << "M3.4 FAIL: " << label << '\n'; ++failures; }
}
State activate(NetworkAuthorization& gate, std::uint64_t generation,
    Config config = Config::Validated) {
    return gate.activate(config, 1, generation, approvals, {}, bindings);
}
void denied(NetworkAuthorization& gate, std::uint64_t generation, State expected) {
    const auto result = gate.evaluate(proposal, generation);
    check(result.state == expected && !result.candidate_in_scope() &&
        result.decision != ScopeDecision::CandidateInScope, "closed state cannot return candidate");
}
void lifecycle_tests() {
    NetworkAuthorization gate;
    denied(gate, 0, State::Unconfigured);
    check(activate(gate, 0) == State::StaleGeneration, "zero revision");
    check(activate(gate, 1, Config::Unavailable) == State::ConfigurationUnavailable,
        "missing configuration");
    denied(gate, 1, State::ConfigurationUnavailable);
    check(activate(gate, 1) == State::StaleGeneration, "failed revision consumed");
    check(activate(gate, 2, Config::Invalid) == State::InvalidConfiguration, "invalid configuration");
    check(activate(gate, 3, std::bit_cast<Config>(std::uint8_t{255})) == State::InvalidConfiguration,
        "unknown configuration classification");
    check(gate.activate(Config::Validated, 99, 4, approvals, {}, bindings) == State::InvalidPolicy,
        "unknown policy schema");
    check(gate.activate(Config::Validated, 1, 5, {}, {}, {}) == State::EmptyPolicy, "empty policy");
    check(activate(gate, 6) == State::Ready, "new valid revision establishes observation");
    const auto stale = gate.evaluate(proposal, 5);
    check(stale.state == State::Ready && stale.decision == ScopeDecision::DeniedPolicy &&
        !stale.candidate_in_scope(), "stale request cannot authorize or withdraw active revision");
    check(activate(gate, 6) == State::StaleGeneration, "same revision cannot rearm");
    denied(gate, 6, State::StaleGeneration);
    check(activate(gate, 7) == State::Ready, "explicit newer revision");
    check(activate(gate, 4) == State::StaleGeneration && gate.high_water_generation() == 7,
        "rollback closes without lowering high water");
    check(activate(gate, 8) == State::Ready, "recover from rollback with newer revision");
    check(activate(gate, 9, Config::Unavailable) == State::ConfigurationUnavailable,
        "unavailable replacement withdraws active policy");
    denied(gate, 8, State::ConfigurationUnavailable);
    check(activate(gate, 10) == State::Ready, "new revision after configuration loss");
    gate.disable();
    denied(gate, 10, State::Disabled);
    check(activate(gate, 10) == State::StaleGeneration, "disable cannot reset generation");
    check(activate(gate, std::numeric_limits<std::uint64_t>::max()) == State::Ready,
        "maximum revision accepted once");
    gate.disable();
    check(activate(gate, 1) == State::StaleGeneration &&
        gate.high_water_generation() == std::numeric_limits<std::uint64_t>::max(), "no wraparound");
}
void binding_tests() {
    NetworkAuthorization gate;
    std::uint64_t generation{};
    const auto reject = [&](std::span<const InterfaceBinding> input) {
        check(gate.activate(Config::Validated, 1, ++generation, approvals, {}, input) ==
            State::InvalidBindings, "invalid interface binding rejected");
        denied(gate, generation, State::InvalidBindings);
    };
    reject({});
    for (const auto name : {std::string_view{}, std::string_view{"."}, std::string_view{".."},
            std::string_view{"bad name"}, std::string_view{"eth0:1"}, std::string_view{"0123456789abcdef"},
            std::string_view{"lo\0hidden", 9}}) {
        const std::array invalid{InterfaceBinding{1, name}};
        reject(invalid);
    }
    reject(std::array{InterfaceBinding{0, "lo"}});
    reject(std::array{InterfaceBinding{2, "eth0"}});
    reject(std::array{InterfaceBinding{1, "lo"}, InterfaceBinding{1, "other"}});
    reject(std::array{InterfaceBinding{1, "lo"}, InterfaceBinding{2, "eth0"}});
    constexpr std::array mixed{endpoint, EndpointApproval{"agent", "manager", "192.0.2.11", 2, 7443}};
    check(gate.activate(Config::Validated, 1, ++generation, mixed, {}, bindings) == State::InvalidBindings,
        "partial coverage rejected");
    constexpr std::array aliases{InterfaceBinding{1, "lo"}, InterfaceBinding{2, "lo"}};
    check(gate.activate(Config::Validated, 1, ++generation, mixed, {}, aliases) == State::InvalidBindings,
        "duplicate name rejected");
    constexpr std::array prefixes{PrefixApproval{"agent", "manager", "2001:db8::/64", 2, 7443}};
    check(gate.activate(Config::Validated, 1, ++generation, approvals, prefixes, bindings) == State::InvalidPolicy,
        "schema 1 cannot accept prefixes");
    check(gate.activate(Config::Validated, 2, ++generation, approvals, prefixes, bindings) == State::InvalidBindings,
        "prefix interfaces also require coverage");
    constexpr std::array dual{InterfaceBinding{1, "lo"}, InterfaceBinding{2, "eth0"}};
    check(gate.activate(Config::Validated, 2, ++generation, approvals, prefixes, dual) == State::Ready,
        "dual stack fully bound revision");
    constexpr std::array invalid_rule{EndpointApproval{"agent", "manager", "bad", 1, 7443}};
    check(gate.activate(Config::Validated, 1, ++generation, invalid_rule, {}, bindings) == State::InvalidPolicy,
        "invalid replacement closes valid snapshot");
    denied(gate, generation - 1, State::InvalidPolicy);
}
void evaluation_tests() {
    NetworkAuthorization gate;
    // A real loopback attachment is unsupported, even with a synthetically
    // approved documentation address and fabricated positive route evidence.
    check(activate(gate, 1) == State::Ready, "initial observer available");
    auto request = proposal;
    request.purpose = NetworkPurpose::IntelligenceSync;
    check(gate.evaluate(request, 1).decision == ScopeDecision::DeniedPurpose, "purpose denial");
    request = proposal;
    request.endpoint.destination = "192.0.2.11";
    check(gate.evaluate(request, 1).decision == ScopeDecision::DeniedApproval, "scope denial");
    request.endpoint.destination = "bad";
    check(gate.evaluate(request, 1).decision == ScopeDecision::DeniedEndpoint, "endpoint denial");
    request = proposal;
    request.endpoint.interface_index = 2;
    check(gate.evaluate(request, 1).decision == ScopeDecision::DeniedApproval, "unbound interface denial");
    check(gate.check_changes() == State::Ready, "ordinary denials do not withdraw policy");
    const auto result = gate.evaluate(proposal, 1);
    check(result.state == State::RouteUnverified && result.decision == ScopeDecision::DeniedRoute &&
        !result.candidate_in_scope(), "real unsupported attachment latches route uncertainty");
    denied(gate, 1, State::RouteUnverified);
    check(activate(gate, 1) == State::StaleGeneration, "route failure cannot rearm old policy");
    // Owned binding: caller mutating storage after activation cannot change it.
    std::string mutable_name{"lo"};
    const std::array mutable_binding{InterfaceBinding{1, mutable_name}};
    check(gate.activate(Config::Validated, 1, 2, approvals, {}, mutable_binding) == State::Ready,
        "owned binding activation");
    mutable_name[0] = '\0';
    check(gate.evaluate(proposal, 2).state == State::RouteUnverified, "owned binding remains fail closed");
}
void unavailable_topology_test() {
    // Temporarily prevent new descriptors in this test process only. Existing
    // descriptors stay valid. Restore before asserting or running other tests.
    struct rlimit original{};
    if (getrlimit(RLIMIT_NOFILE, &original) != 0) {
        check(false, "read descriptor limit"); return;
    }
    auto restricted = original;
    restricted.rlim_cur = 0;
    if (setrlimit(RLIMIT_NOFILE, &restricted) != 0) {
        check(false, "set test descriptor limit"); return;
    }
    NetworkAuthorization gate;
    const auto result = activate(gate, 1);
    if (setrlimit(RLIMIT_NOFILE, &original) != 0) {
        check(false, "restore descriptor limit"); return;
    }
    check(result == State::TopologyUnavailable, "unavailable kernel observation closes");
    denied(gate, 1, State::TopologyUnavailable);
    check(activate(gate, 1) == State::StaleGeneration, "restored descriptors do not rearm old revision");
    check(activate(gate, 2) == State::Ready, "new revision after observation recovery");
}
} // namespace

int main() {
    static_assert(!std::is_copy_constructible_v<NetworkAuthorization>);
    static_assert(!std::is_move_constructible_v<NetworkAuthorization>);
    check(!AuthorizationResult{}.candidate_in_scope(), "default result denies");
    check(!AuthorizationResult{State::Ready, ScopeDecision::CandidateInScope, 0}.candidate_in_scope(),
        "zero revision cannot be a candidate");
    for (unsigned state = 0; state <= 255; ++state) {
        for (unsigned decision = 0; decision <= 255; ++decision) {
            const auto typed_state = static_cast<State>(state);
            const auto typed_decision = static_cast<ScopeDecision>(decision);
            check(AuthorizationResult{typed_state, typed_decision, 1}.candidate_in_scope() ==
                (typed_state == State::Ready && typed_decision == ScopeDecision::CandidateInScope),
                "only exact ready candidate classification is positive");
        }
    }
    lifecycle_tests();
    binding_tests();
    evaluation_tests();
    unavailable_topology_test();
    if (failures != 0) { return 1; }
    std::cout << "M3.4 fail-closed configuration, generation, binding and topology regression: PASS\n";
    return 0;
}
