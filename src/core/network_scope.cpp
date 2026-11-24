// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/core/network_scope.hpp"

#include <algorithm>
#include <arpa/inet.h>

namespace knetsentry::core {
namespace {

bool valid_identity(std::string_view text) noexcept {
    return !text.empty() && text.size() <= NetworkScopePolicy::max_identity_length &&
        std::all_of(text.begin(), text.end(), [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
        });
}

} // namespace

bool NetworkScopePolicy::parse_address(std::string_view text, Address& result) noexcept {
    // Numeric literals only. Reject embedded NUL before passing to C API.
    // Interface scope is a separate numeric field.
    if (text.empty() || text.size() >= INET6_ADDRSTRLEN ||
        text.find('\0') != std::string_view::npos) {
        return false;
    }
    std::array<char, INET6_ADDRSTRLEN> input{};
    std::copy(text.begin(), text.end(), input.begin());
    Address parsed{};
    if (inet_pton(AF_INET, input.data(), parsed.bytes.data()) == 1) {
        const auto first = parsed.bytes[0];
        if (first == 0 || first == 127 || first >= 224) {
            return false;
        }
        parsed.family = 4;
    } else if (inet_pton(AF_INET6, input.data(), parsed.bytes.data()) == 1) {
        const auto first = parsed.bytes[0];
        const auto second = parsed.bytes[1];
        const bool global = (first & 0xe0U) == 0x20U;
        const bool unique_local = (first & 0xfeU) == 0xfcU;
        const bool link_local = first == 0xfeU && (second & 0xc0U) == 0x80U;
        const bool transition = (first == 0x20U && second == 0x02U) ||
            (first == 0x20U && second == 0x01U && parsed.bytes[2] == 0 && parsed.bytes[3] == 0);
        // Deny mapped/compatible IPv4, unspecified, loopback, multicast,
        // NAT64 well-known prefix, and known transition ranges in this profile.
        if (!(global || unique_local || link_local) || transition) {
            return false;
        }
        parsed.family = 6;
    } else {
        return false;
    }
    result = parsed;
    return true;
}

bool NetworkScopePolicy::parse_endpoint(const EndpointApproval& input, Rule& result) noexcept {
    if (!valid_identity(input.agent) || !valid_identity(input.manager) ||
        input.interface_index == 0 || input.port == 0) {
        return false;
    }
    Rule rule{};
    if (!parse_address(input.destination, rule.destination)) {
        return false;
    }
    std::copy(input.agent.begin(), input.agent.end(), rule.agent.begin());
    std::copy(input.manager.begin(), input.manager.end(), rule.manager.begin());
    rule.interface_index = input.interface_index;
    rule.port = input.port;
    result = rule;
    return true;
}

NetworkScopePolicy NetworkScopePolicy::compile(
    std::uint32_t schema, std::uint64_t generation,
    std::span<const EndpointApproval> approvals) noexcept {
    NetworkScopePolicy policy;
    if (schema != 1 || generation == 0 || approvals.size() > max_approvals) {
        return policy;
    }
    for (const auto& approval : approvals) {
        Rule rule{};
        if (!parse_endpoint(approval, rule)) {
            return {};
        }
        for (std::size_t index = 0; index < policy.count_; ++index) {
            if (policy.rules_[index] == rule) {
                return {};
            }
        }
        policy.rules_[policy.count_] = rule;
        ++policy.count_;
    }
    policy.generation_ = generation;
    policy.valid_ = true;
    return policy;
}

ScopeDecision NetworkScopePolicy::evaluate(const NetworkProposal& proposal) const noexcept {
    if (!valid_) {
        return ScopeDecision::DeniedPolicy;
    }
    if (proposal.component != NetworkComponent::Agent ||
        proposal.purpose != NetworkPurpose::AgentTransport ||
        proposal.protocol != NetworkProtocol::Tcp) {
        return ScopeDecision::DeniedPurpose;
    }
    Rule candidate{};
    if (!parse_endpoint(proposal.endpoint, candidate)) {
        return ScopeDecision::DeniedEndpoint;
    }
    Address routed{};
    if (proposal.route.kind != RouteKind::OnLinkUnicast ||
        proposal.route.policy_generation != generation_ ||
        proposal.route.interface_index != candidate.interface_index ||
        !parse_address(proposal.route.destination, routed) || routed != candidate.destination) {
        return ScopeDecision::DeniedRoute;
    }
    for (std::size_t index = 0; index < count_; ++index) {
        if (rules_[index] == candidate) {
            return ScopeDecision::CandidateInScope;
        }
    }
    return ScopeDecision::DeniedApproval;
}

} // namespace knetsentry::core
