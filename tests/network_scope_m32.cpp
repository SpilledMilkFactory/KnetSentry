// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/core/network_scope.hpp"

#include <arpa/inet.h>
#include <array>
#include <iostream>
#include <string>

using namespace knetsentry::core;
namespace {
using Decision = ScopeDecision;
int failures = 0;
void check(bool passed, std::string_view label) {
    if (!passed) {
        std::cerr << "M3.2 failed: " << label << '\n';
        ++failures;
    }
}
constexpr PrefixApproval v4{"agent-A", "manager-A", "192.0.2.0/24", 3, 7443};
constexpr PrefixApproval v6{"agent-A", "manager-A", "2001:db8:abcd:1200::/57", 3, 7443};
constexpr PrefixApproval link{"agent-A", "manager-A", "fe80::/64", 4, 7443};
constexpr EndpointApproval exact{"agent-A", "manager-A", "198.51.100.10", 3, 7443};
NetworkProposal propose(std::string_view address, std::uint32_t iface = 3) {
    return {NetworkComponent::Agent, NetworkPurpose::AgentTransport, NetworkProtocol::Tcp,
            {"agent-A", "manager-A", address, iface, 7443},
            {RouteKind::OnLinkUnicast, address, iface, 7}};
}
NetworkScopePolicy single(std::string_view network) {
    auto prefix = v4;
    prefix.network = network;
    const std::array rules{prefix};
    return NetworkScopePolicy::compile(2, 7, {}, rules);
}
std::string literal(const std::array<std::uint8_t, 16>& bytes, int family) {
    std::array<char, INET6_ADDRSTRLEN> buffer{};
    if (inet_ntop(family, bytes.data(), buffer.data(), buffer.size()) == nullptr) {
        check(false, "numeric fixture formatting");
        return {};
    }
    return buffer.data();
}
void bit_sweep(int family, unsigned width, unsigned minimum,
               const std::array<std::uint8_t, 16>& base) {
    // For each tested length, flip each possible bit independently. This
    // includes non-byte-aligned boundaries and the last bit of each family.
    for (unsigned length = minimum; length <= width; ++length) {
        const auto network = literal(base, family) + '/' + std::to_string(length);
        const auto policy = single(network);
        check(policy.valid(), "canonical prefix at every tested length");
        for (unsigned bit = 0; bit < width; ++bit) {
            auto bytes = base;
            bytes[bit / 8U] ^= static_cast<std::uint8_t>(0x80U >> (bit % 8U));
            const auto address = literal(bytes, family);
            const bool inside = bit >= length;
            // A /30 single host bit is neither network nor broadcast. For
            // /31 both endpoints are eligible. All other flipped host bits
            // also leave at least one zero and one one in the host part.
            check((policy.evaluate(propose(address)) == Decision::CandidateInScope) == inside,
                  "individual bit boundary");
        }
    }
}
} // namespace

int main() {
    const std::array prefixes{v4, v6, link};
    const std::array endpoints{exact};
    const auto policy = NetworkScopePolicy::compile(2, 7, endpoints, prefixes);
    check(policy.valid(), "mixed exact/prefix schema 2");
    check(!NetworkScopePolicy::compile(1, 7, endpoints, prefixes).valid(), "no implicit schema upgrade");
    check(!NetworkScopePolicy::compile(3, 7, endpoints, prefixes).valid(), "unknown schema");
    check(!NetworkScopePolicy::compile(2, 0, endpoints, prefixes).valid(), "zero generation");
    check(NetworkScopePolicy::compile(2, 7, {}, {}).valid(), "empty schema 2");
    check(NetworkScopePolicy::compile(2, 7, {}, {}).evaluate(propose("192.0.2.1")) ==
          Decision::DeniedApproval, "empty schema 2 denies");
    for (const auto address : {"192.0.2.1", "192.0.2.254", "198.51.100.10",
             "2001:db8:abcd:1200::", "2001:0DB8:ABCD:127F:ffff:ffff:ffff:ffff"}) {
        check(policy.evaluate(propose(address)) == Decision::CandidateInScope, "approved boundary");
    }
    for (const auto address : {"192.0.1.255", "192.0.3.1", "192.0.2.0", "192.0.2.255",
             "198.51.100.11", "2001:db8:abcd:1280::", "2001:db8:abcd:11ff::", "fd00::1"}) {
        check(policy.evaluate(propose(address)) == Decision::DeniedApproval, "out-of-scope boundary");
    }
    check(policy.evaluate(propose("fe80::abcd", 4)) == Decision::CandidateInScope, "link-local approved");
    check(policy.evaluate(propose("fe80::abcd", 3)) == Decision::DeniedApproval, "link-local wrong interface");
    check(policy.evaluate(propose("192.0.2.10", 4)) == Decision::DeniedApproval, "IPv4 wrong interface");
    auto candidate = propose("192.0.2.10");
    candidate.endpoint.agent = "agent-B";
    check(policy.evaluate(candidate) == Decision::DeniedApproval, "agent binding");
    candidate = propose("192.0.2.10");
    candidate.endpoint.manager = "manager-B";
    check(policy.evaluate(candidate) == Decision::DeniedApproval, "manager binding");
    candidate = propose("192.0.2.10");
    candidate.endpoint.port = 443;
    check(policy.evaluate(candidate) == Decision::DeniedApproval, "port binding");
    candidate = propose("192.0.2.10");
    candidate.route.destination = "192.0.2.11";
    check(policy.evaluate(candidate) == Decision::DeniedRoute, "same prefix is not same route destination");
    candidate.route.destination = "2001:db8:abcd:1200::1";
    check(policy.evaluate(candidate) == Decision::DeniedRoute, "route family mismatch");
    candidate = propose("192.0.2.10");
    candidate.route.interface_index = 4;
    check(policy.evaluate(candidate) == Decision::DeniedRoute, "route interface mismatch");
    candidate = propose("192.0.2.10");
    candidate.route.policy_generation = 6;
    check(policy.evaluate(candidate) == Decision::DeniedRoute, "stale generation");
    candidate = propose("192.0.2.10");
    candidate.route.kind = RouteKind::DefaultGateway;
    check(policy.evaluate(candidate) == Decision::DeniedRoute, "default route denied");
    candidate = propose("192.0.2.10");
    candidate.purpose = NetworkPurpose::ActiveDiscovery;
    check(policy.evaluate(candidate) == Decision::DeniedPurpose, "prefix not discovery permission");
    candidate.purpose = NetworkPurpose::IntelligenceSync;
    check(policy.evaluate(candidate) == Decision::DeniedPurpose, "prefix not intelligence permission");
    candidate = propose("192.0.2.10");
    candidate.protocol = NetworkProtocol::Udp;
    check(policy.evaluate(candidate) == Decision::DeniedPurpose, "prefix not UDP permission");
    for (const auto address : {"192.0.2.0/24", "::ffff:192.0.2.10", "2001:db8::192.0.2.10",
             "fe80::abcd%4", "192.0.2.010", "192.0.2.10 ", "ff02::1", "::1", "127.0.0.1"}) {
        check(policy.evaluate(propose(address)) == Decision::DeniedEndpoint, "ambiguous endpoint denied");
    }
    for (const std::string_view invalid : {"", "192.0.2.0", "192.0.2.0/", "192.0.2.0/0",
             "192.0.2.0/024", "192.0.2.0/+24", "192.0.2.0/-1", "192.0.2.0/33", "192.0.2.0/9999",
             "192.0.2.0/24/1", "192.0.2.0/24 ", "192.0.2.0/255.255.255.0", "192.0.2.1/24",
             "0.0.0.0/0", "64.0.0.0/2", "192.0.0.0/2", "127.0.0.0/8", "224.0.0.0/4",
             "2001:db8::1/64", "2001:db8::/129", "::/0", "::ffff:192.0.2.0/120",
             "fe80::%4/64", "fe80::/9", "fc00::/6", "2000::/3", "2000::/14",
             "2001::/32", "2002::/16", "ff00::/8", "64:ff9b::/96", "2001:db8::192.0.2.0/120"}) {
        auto bad = v4;
        bad.network = invalid;
        const std::array rules{v4, bad};
        const auto rejected = NetworkScopePolicy::compile(2, 7, endpoints, rules);
        check(!rejected.valid() && rejected.evaluate(propose(exact.destination)) == Decision::DeniedPolicy,
              "invalid prefix rejects entire mixed snapshot");
    }
    check(!single(std::string_view{"192.0.2.0/24\0junk", sizeof("192.0.2.0/24\0junk") - 1}).valid(),
          "embedded NUL suffix");
    check(!single(std::string_view{"192.0.2.0\0/24", sizeof("192.0.2.0\0/24") - 1}).valid(),
          "embedded NUL address");
    auto duplicate = v6;
    duplicate.network = "2001:0DB8:ABCD:1200:0:0:0:0/57";
    const std::array duplicates{v6, duplicate};
    check(!NetworkScopePolicy::compile(2, 7, {}, duplicates).valid(), "normalized prefix duplicate");
    auto nested = v4;
    nested.network = "192.0.2.128/25";
    const std::array overlap{v4, nested};
    const std::array reversed{nested, v4};
    check(!NetworkScopePolicy::compile(2, 7, {}, overlap).valid() &&
          !NetworkScopePolicy::compile(2, 7, {}, reversed).valid(), "overlap rejected in either order");
    auto covered = exact;
    covered.destination = "192.0.2.255";
    const std::array covered_exact{covered};
    const std::array v4_only{v4};
    check(!NetworkScopePolicy::compile(2, 7, covered_exact, v4_only).valid(), "exact overlap cannot bypass edge rule");
    nested.interface_index = 4;
    const std::array independent{v4, nested};
    check(NetworkScopePolicy::compile(2, 7, {}, independent).valid(), "separate interface binding");
    auto invalid_binding = v4;
    invalid_binding.interface_index = 0;
    check(!NetworkScopePolicy::compile(2, 7, {}, std::array{invalid_binding}).valid(), "zero interface");
    invalid_binding = v4;
    invalid_binding.port = 0;
    check(!NetworkScopePolicy::compile(2, 7, {}, std::array{invalid_binding}).valid(), "zero port");
    invalid_binding = v4;
    invalid_binding.agent = "bad agent";
    check(!NetworkScopePolicy::compile(2, 7, {}, std::array{invalid_binding}).valid(), "invalid identity");
    std::string mutable_prefix = "192.0.2.0/24";
    auto owned = v4;
    owned.network = mutable_prefix;
    const auto copied = NetworkScopePolicy::compile(2, 7, {}, std::array{owned});
    mutable_prefix[0] = '9';
    check(copied.evaluate(propose("192.0.2.1")) == Decision::CandidateInScope, "owned prefix data");
    std::array<PrefixApproval, NetworkScopePolicy::max_approvals> maximum{};
    for (std::size_t i = 0; i < maximum.size(); ++i) {
        maximum[i] = v4;
        maximum[i].port = static_cast<std::uint16_t>(i + 1);
    }
    check(NetworkScopePolicy::compile(2, 7, {}, maximum).valid(), "full prefix capacity");
    check(!NetworkScopePolicy::compile(2, 7, endpoints, maximum).valid(), "combined capacity exceeded");
    const auto edge31 = single("192.0.2.0/31");
    check(edge31.evaluate(propose("192.0.2.0")) == Decision::CandidateInScope &&
          edge31.evaluate(propose("192.0.2.1")) == Decision::CandidateInScope, "IPv4 /31 edges");
    check(single("192.0.2.0/32").evaluate(propose("192.0.2.0")) == Decision::CandidateInScope, "IPv4 /32");
    check(single("fd00::/127").evaluate(propose("fd00::1")) == Decision::CandidateInScope, "IPv6 /127");
    check(single("fd00::/128").evaluate(propose("fd00::")) == Decision::CandidateInScope, "IPv6 /128");
    check(single("fd00::/128").evaluate(propose("fd00::1")) == Decision::DeniedApproval, "IPv6 /128 outside");
    bit_sweep(AF_INET, 32, 8, {10});
    bit_sweep(AF_INET6, 128, 8, {0xfd});
    if (failures != 0) {
        return 1;
    }
    std::cout << "M3.2 IPv4/IPv6 canonical prefixes, bit boundaries, interface constraints and fail-closed fixtures: PASS\n";
    return 0;
}
