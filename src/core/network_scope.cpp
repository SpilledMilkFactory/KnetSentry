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
    } else if (text.find('.') == std::string_view::npos &&
               inet_pton(AF_INET6, input.data(), parsed.bytes.data()) == 1) {
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
    rule.prefix_length = rule.destination.family == 4 ? 32 : 128;
    result = rule;
    return true;
}

bool NetworkScopePolicy::contains(const Address& network, std::uint8_t length,
                                  const Address& address) noexcept {
    if (network.family != address.family) {
        return false;
    }
    const std::size_t whole = length / 8U;
    const unsigned remainder = length % 8U;
    for (std::size_t index = 0; index < whole; ++index) {
        if (network.bytes[index] != address.bytes[index]) {
            return false;
        }
    }
    if (remainder == 0) {
        return true;
    }
    const unsigned mask = 0xffU << (8U - remainder);
    return (network.bytes[whole] & mask) == (address.bytes[whole] & mask);
}

bool NetworkScopePolicy::parse_prefix(const PrefixApproval& input, Rule& result) noexcept {
    // Bounded, canonical decimal CIDR length. No whitespace, signs, zones,
    // leading zeros, implicit host-bit masking or wildcard /0 approvals.
    if (input.network.size() > INET6_ADDRSTRLEN + 3U) {
        return false;
    }
    const auto slash = input.network.find('/');
    if (slash == std::string_view::npos) {
        return false;
    }
    const auto suffix = input.network.substr(slash + 1);
    if (suffix.empty() || suffix.size() > 3 || suffix.front() == '0') {
        return false;
    }
    unsigned length = 0;
    for (const char digit : suffix) {
        if (digit < '0' || digit > '9') {
            return false;
        }
        length = length * 10U + static_cast<unsigned>(digit - '0');
    }
    Rule rule{};
    if (!parse_endpoint({input.agent, input.manager, input.network.substr(0, slash),
                         input.interface_index, input.port}, rule) || length > rule.prefix_length) {
        return false;
    }
    const unsigned width = rule.prefix_length;
    for (unsigned bit = length; bit < width; ++bit) {
        if ((rule.destination.bytes[bit / 8U] & (0x80U >> (bit % 8U))) != 0) {
            return false;
        }
    }
    // Every address in an approval must belong to a supported address class.
    // IPv4: reject a range crossing the excluded 127/8 or high 224/3 space.
    // The parser has already excluded a base in 0/8, 127/8 or >=224.
    const auto& bytes = rule.destination.bytes;
    if (rule.destination.family == 4) {
        const unsigned high_first = static_cast<unsigned>(bytes[0]) |
            (length < 8 ? (0xffU >> length) : 0U);
        if (high_first >= 224U || (bytes[0] < 127U && high_first >= 127U)) {
            return false;
        }
    } else {
        const unsigned minimum = (bytes[0] & 0xe0U) == 0x20U ? 3U :
            ((bytes[0] & 0xfeU) == 0xfcU ? 7U : 10U);
        if (length < minimum) {
            return false;
        }
        // Reject prefixes containing known transition blocks, even when
        // their base address itself is ordinary global unicast-format.
        Address six_to_four{};
        six_to_four.family = 6;
        six_to_four.bytes[0] = 0x20;
        six_to_four.bytes[1] = 0x02;
        Address teredo{};
        teredo.family = 6;
        teredo.bytes[0] = 0x20;
        teredo.bytes[1] = 0x01;
        const auto bits = static_cast<std::uint8_t>(length);
        if (contains(rule.destination, std::min(bits, std::uint8_t{16}), six_to_four) ||
            contains(rule.destination, std::min(bits, std::uint8_t{32}), teredo)) {
            return false;
        }
    }
    rule.prefix_length = static_cast<std::uint8_t>(length);
    result = rule;
    return true;
}

bool NetworkScopePolicy::same_binding(const Rule& first, const Rule& second) noexcept {
    return first.agent == second.agent && first.manager == second.manager &&
        first.interface_index == second.interface_index && first.port == second.port;
}

bool NetworkScopePolicy::matches(const Rule& rule, const Rule& candidate) noexcept {
    if (!same_binding(rule, candidate) ||
        !contains(rule.destination, rule.prefix_length, candidate.destination)) {
        return false;
    }
    // For IPv4 prefix approvals, conservatively exclude the approval's
    // all-zero/all-one host part except /31 (point-to-point) and /32.
    // Actual subnet broadcast/address validity still requires live topology.
    if (rule.destination.family == 4 && rule.prefix_length < 31) {
        bool all_zero = true;
        bool all_one = true;
        for (unsigned bit = rule.prefix_length; bit < 32U; ++bit) {
            const bool set = (candidate.destination.bytes[bit / 8U] &
                              (0x80U >> (bit % 8U))) != 0;
            all_zero = all_zero && !set;
            all_one = all_one && set;
        }
        if (all_zero || all_one) {
            return false;
        }
    }
    return true;
}

bool NetworkScopePolicy::append(const Rule& rule) noexcept {
    if (count_ >= max_approvals) {
        return false;
    }
    for (std::size_t index = 0; index < count_; ++index) {
        const auto& prior = rules_[index];
        if (same_binding(prior, rule) &&
            contains(prior.destination, std::min(prior.prefix_length, rule.prefix_length),
                     rule.destination)) {
            return false;
        }
    }
    rules_[count_] = rule;
    ++count_;
    return true;
}

NetworkScopePolicy NetworkScopePolicy::compile(
    std::uint32_t schema, std::uint64_t generation,
    std::span<const EndpointApproval> approvals) noexcept {
    if (schema != 1) {
        return {};
    }
    return compile(2, generation, approvals, {});
}

NetworkScopePolicy NetworkScopePolicy::compile(
    std::uint32_t schema, std::uint64_t generation,
    std::span<const EndpointApproval> approvals,
    std::span<const PrefixApproval> prefixes) noexcept {
    NetworkScopePolicy policy;
    if (schema != 2 || generation == 0 || approvals.size() > max_approvals ||
        prefixes.size() > max_approvals - approvals.size()) {
        return policy;
    }
    for (const auto& approval : approvals) {
        Rule rule{};
        if (!parse_endpoint(approval, rule) || !policy.append(rule)) {
            return {};
        }
    }
    for (const auto& prefix : prefixes) {
        Rule rule{};
        if (!parse_prefix(prefix, rule) || !policy.append(rule)) {
            return {};
        }
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
        if (matches(rules_[index], candidate)) {
            return ScopeDecision::CandidateInScope;
        }
    }
    return ScopeDecision::DeniedApproval;
}

} // namespace knetsentry::core
