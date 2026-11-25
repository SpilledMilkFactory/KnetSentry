// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/core/linux_topology.hpp"
#include "knetsentry/core/network_authorization.hpp"
#include "linux_topology_detail.hpp"

#include <arpa/inet.h>
#include <array>
#include <chrono>
#include <charconv>
#include <cstring>
#include <iostream>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>
#include <string_view>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace knetsentry::core;
namespace detail = knetsentry::core::topology_detail;
namespace {
using Buffer = std::vector<std::byte>;
int failures = 0;
void check(bool result, std::string_view label) {
    if (!result) {
        std::cerr << "M3.3 failed: " << label << '\n';
        ++failures;
    }
}

template <typename T>
Buffer body(const T& value) {
    const auto bytes = std::as_bytes(std::span{&value, 1});
    return {bytes.begin(), bytes.end()};
}
void attr(Buffer& buffer, std::uint16_t type, detail::Bytes value) {
    const auto length = sizeof(rtattr) + value.size();
    const rtattr header{static_cast<unsigned short>(length), type};
    const auto bytes = body(header);
    buffer.insert(buffer.end(), bytes.begin(), bytes.end());
    buffer.insert(buffer.end(), value.begin(), value.end());
    buffer.resize(buffer.size() + ((4U - length % 4U) % 4U));
}
template <typename T>
void attr_value(Buffer& buffer, std::uint16_t type, const T& value) {
    attr(buffer, type, std::as_bytes(std::span{&value, 1}));
}
detail::Address address(std::string_view literal) {
    detail::Address value{};
    check(detail::parse_address(literal, value), "fixture address");
    return value;
}
Buffer route_fixture(const detail::Address& base, unsigned length, std::uint32_t index = 3,
                     unsigned char type = RTN_UNICAST, unsigned char table = RT_TABLE_MAIN) {
    rtmsg header{};
    header.rtm_family = static_cast<unsigned char>(base.family);
    header.rtm_dst_len = static_cast<unsigned char>(length);
    header.rtm_type = type;
    header.rtm_table = table;
    header.rtm_scope = base.family == AF_INET ? RT_SCOPE_LINK : RT_SCOPE_UNIVERSE;
    auto buffer = body(header);
    attr(buffer, RTA_DST, detail::Bytes{base.bytes}.first(base.size));
    attr_value(buffer, RTA_OIF, index);
    attr_value(buffer, RTA_TABLE, static_cast<std::uint32_t>(table));
    return buffer;
}
Buffer link_fixture(unsigned flags = IFF_UP | IFF_RUNNING | IFF_LOWER_UP,
                    unsigned short kind = ARPHRD_ETHER) {
    ifinfomsg header{};
    header.ifi_index = 3;
    header.ifi_type = kind;
    header.ifi_flags = flags;
    auto buffer = body(header);
    constexpr std::array name{'e', 't', 'h', '0', '\0'};
    attr(buffer, IFLA_IFNAME, std::as_bytes(std::span{name}));
    return buffer;
}
void route_tests() {
    const auto target = address("192.0.2.10");
    const auto base = address("192.0.2.0");
    const auto host = route_fixture(target, 32);
    const auto prefix = route_fixture(base, 24);
    check(detail::direct_route(host, target, 3, false), "effective IPv4 host route");
    check(detail::direct_route(prefix, target, 3, true), "matched IPv4 prefix");
    check(!detail::direct_route(prefix, target, 3, false), "effective route must be exact");
    check(!detail::direct_route(prefix, target, 4, true), "wrong OIF");
    check(!detail::direct_route(prefix, address("192.0.3.10"), 3, true), "wrong prefix");
    check(!detail::direct_route(prefix, base, 3, true), "network edge");
    check(!detail::direct_route(prefix, address("192.0.2.255"), 3, true), "broadcast edge");
    check(!detail::direct_route(route_fixture(address("0.0.0.0"), 0), target, 3, true), "direct default route");
    check(!detail::direct_route(route_fixture(target, 24), target, 3, true), "noncanonical FIB prefix");
    for (const auto kind : {RTN_LOCAL, RTN_BROADCAST, RTN_BLACKHOLE, RTN_UNREACHABLE, RTN_THROW}) {
        check(!detail::direct_route(route_fixture(target, 32, 3, static_cast<unsigned char>(kind)),
                                   target, 3, false), "unsupported route type");
    }
    check(!detail::direct_route(route_fixture(target, 32, 3, RTN_UNICAST, 100), target, 3, false),
          "non-main routing table");
    for (const auto attribute : {RTA_GATEWAY, RTA_VIA, RTA_MULTIPATH, RTA_NH_ID, RTA_ENCAP,
                                 RTA_NEWDST, RTA_SRC, RTA_OIF, RTA_DST, RTA_TABLE}) {
        auto invalid = host;
        attr_value(invalid, static_cast<std::uint16_t>(attribute), std::uint32_t{3});
        check(!detail::direct_route(invalid, target, 3, false), "unsupported or duplicate route attribute");
    }
    auto unknown = host;
    attr_value(unknown, 999, std::uint32_t{3});
    check(!detail::direct_route(unknown, target, 3, false), "unknown route attribute");
    auto truncated = host;
    truncated.pop_back();
    check(!detail::direct_route(truncated, target, 3, false), "truncated route attribute");
    auto malformed = host;
    const rtattr invalid_length{0, RTA_DST};
    std::memcpy(malformed.data() + sizeof(rtmsg), &invalid_length, sizeof(invalid_length));
    check(!detail::direct_route(malformed, target, 3, false), "zero route attribute length");
    const auto v6 = address("2001:db8:abcd:127f::1");
    const auto v6prefix = route_fixture(address("2001:db8:abcd:1200::"), 57);
    check(detail::direct_route(route_fixture(v6, 128), v6, 3, false), "effective IPv6 route");
    check(detail::direct_route(v6prefix, v6, 3, true), "non-byte IPv6 prefix");
    check(!detail::direct_route(v6prefix, address("2001:db8:abcd:1280::1"), 3, true), "IPv6 prefix boundary");
    check(!detail::direct_route(v6prefix, target, 3, true), "family mismatch");
    // Kernels with CONFIG_IPV6_SUBTREES report an unspecified source echo
    // for effective IPv6 lookups. Reproduce both supported reply shapes.
    const auto zero = address("::");
    const auto with_source = [&](Buffer buffer, unsigned char bits, const detail::Address& source,
                                 std::uint16_t type = RTA_SRC) {
        rtmsg header{};
        std::memcpy(&header, buffer.data(), sizeof(header));
        header.rtm_src_len = bits;
        std::memcpy(buffer.data(), &header, sizeof(header));
        attr(buffer, type, detail::Bytes{source.bytes}.first(source.size));
        return buffer;
    };
    const auto v6host = route_fixture(v6, 128);
    const auto echo = with_source(v6host, 128, zero);
    check(detail::direct_route(echo, v6, 3, false), "IPv6 unspecified effective source echo");
    check(!detail::direct_route(echo, v6, 3, true), "source echo forbidden in FIB lookup");
    check(!detail::direct_route(with_source(v6prefix, 128, zero), v6, 3, true), "source-specific FIB prefix");
    check(!detail::direct_route(with_source(v6host, 128, v6), v6, 3, false), "nonzero effective source");
    check(!detail::direct_route(with_source(v6host, 0, zero), v6, 3, false), "source echo missing length");
    check(!detail::direct_route(with_source(v6host, 64, zero), v6, 3, false), "source echo partial length");
    check(!detail::direct_route(with_source(v6host, 128, address("0.0.0.0")), v6, 3, false), "short source echo");
    check(!detail::direct_route(with_source(echo, 128, zero), v6, 3, false), "duplicate source echo");
    check(!detail::direct_route(with_source(v6host, 128, zero,
        static_cast<std::uint16_t>(RTA_SRC | NLA_F_NESTED)), v6, 3, false), "flagged source echo");
    check(!detail::direct_route(with_source(host, 32, address("0.0.0.0")), target, 3, false), "IPv4 source echo");
    auto missing_source = v6host;
    rtmsg header{};
    std::memcpy(&header, missing_source.data(), sizeof(header));
    header.rtm_src_len = 128;
    std::memcpy(missing_source.data(), &header, sizeof(header));
    check(!detail::direct_route(missing_source, v6, 3, false), "source length without echo");
    auto echo_gateway = echo;
    attr(echo_gateway, RTA_GATEWAY, detail::Bytes{v6.bytes});
    check(!detail::direct_route(echo_gateway, v6, 3, false), "echo cannot rescue gateway");
    check(!detail::direct_route(echo, v6, 4, false), "echo cannot rescue wrong output interface");
    if (failures == 0) { std::cout << "M3.3 IPv6 effective source-echo compatibility fixtures: PASS\n"; }
    check(detail::direct_route(route_fixture(address("fe80::"), 64), address("fe80::10"), 3, true),
          "link-local route fixture");
    check(!detail::direct_route(route_fixture(address("::"), 0), v6, 3, true), "IPv6 default route");
}
void link_tests() {
    const auto good = link_fixture();
    check(detail::approved_link(good, 3, "eth0"), "approved active interface");
    check(!detail::approved_link(good, 4, "eth0"), "index mismatch");
    check(!detail::approved_link(good, 3, "eth1"), "name mismatch");
    check(!detail::approved_link(link_fixture(IFF_UP), 3, "eth0"), "carrier unavailable");
    check(!detail::approved_link(link_fixture(IFF_UP | IFF_RUNNING | IFF_LOWER_UP | IFF_LOOPBACK), 3, "eth0"),
          "loopback flags");
    check(!detail::approved_link(link_fixture(IFF_UP | IFF_RUNNING | IFF_LOWER_UP, ARPHRD_NONE), 3, "eth0"),
          "unsupported hardware type");
    for (const auto attribute : {IFLA_LINKINFO, IFLA_LINK, IFLA_MASTER, IFLA_LINK_NETNSID}) {
        auto invalid = good;
        attr_value(invalid, static_cast<std::uint16_t>(attribute), std::uint32_t{1});
        check(!detail::approved_link(invalid, 3, "eth0"), "stacked or virtual attachment");
    }
    auto flagged = good;
    attr_value(flagged, static_cast<std::uint16_t>(IFLA_LINKINFO | NLA_F_NESTED), std::uint32_t{1});
    check(!detail::approved_link(flagged, 3, "eth0"), "flagged virtual link attribute");
    auto invalid = good;
    invalid.pop_back();
    check(!detail::approved_link(invalid, 3, "eth0"), "truncated link attribute");
}
void notification_tests() {
    std::array<int, 2> fds{};
    if (pipe(fds.data()) != 0) {
        check(false, "notification fixture pipe");
        return;
    }
    check(detail::watcher_quiet(fds[0]), "empty notification source");
    constexpr char event = 'x';
    check(write(fds[1], &event, 1) == 1, "notification fixture event");
    check(!detail::watcher_quiet(fds[0]), "pending change invalidates");
    close(fds[1]);
    check(!detail::watcher_quiet(fds[0]), "notification loss invalidates");
    close(fds[0]);
    check(!detail::watcher_quiet(-1), "unavailable notification source");
}
void kernel_tests() {
    // Linux loopback index 1 is not an eligible attachment. These exchanges
    // verify actual kernel reply correlation without emitting IP traffic or
    // recording any real host addresses, interfaces or routes.
    check(detail::query_link(1, "lo") == detail::Inspection::Rejected, "live loopback link response");
    check(detail::query_route(address("127.0.0.1"), 1, 7443, false) == detail::Inspection::Rejected,
          "live local route response");
    check(detail::query_route(address("127.0.0.1"), 1, 7443, true) == detail::Inspection::Rejected,
          "live FIB response");
    LinuxTopology monitor;
    check(monitor.check_changes() == TopologyState::Current, "live notification subscription");
    constexpr EndpointApproval approval{"agent", "manager", "192.0.2.10", 1, 7443};
    const auto policy = NetworkScopePolicy::compile(1, 7, std::span{&approval, 1});
    NetworkProposal proposal{NetworkComponent::Agent, NetworkPurpose::AgentTransport,
        NetworkProtocol::Tcp, approval, {RouteKind::OnLinkUnicast, approval.destination, 1, 7}};
    check(policy.evaluate(proposal) == ScopeDecision::CandidateInScope, "synthetic baseline preflight");
    check(monitor.evaluate(policy, proposal, "lo").decision == ScopeDecision::DeniedRoute,
          "forged route cannot bypass actual attachment inspection");
    const auto revised = NetworkScopePolicy::compile(1, 8, std::span{&approval, 1});
    check(monitor.evaluate(revised, proposal, "lo").state == TopologyState::Invalidated,
          "policy revision invalidates observation epoch");
    check(monitor.check_changes() == TopologyState::Invalidated, "invalidation is sticky");
    check(monitor.evaluate(policy, proposal, "lo").decision == ScopeDecision::DeniedRoute,
          "old policy cannot rearm invalidated monitor");
}
int watch() {
    LinuxTopology monitor;
    if (monitor.check_changes() != TopologyState::Current) { return 1; }
    NetworkAuthorization gate;
    constexpr std::array approvals{EndpointApproval{"agent", "manager", "192.0.2.10", 1, 7443}};
    constexpr std::array bindings{InterfaceBinding{1, "lo"}};
    if (gate.activate(ConfigurationEvidence::Validated, 1, 1, approvals, {}, bindings) !=
        AuthorizationState::Ready) { return 1; }
    std::cout << "READY" << std::endl;
    if (std::cin.get() != '\n') { return 1; }
    for (int attempt = 0; attempt < 100; ++attempt) {
        const auto topology = monitor.check_changes();
        const auto authorization = gate.check_changes();
        if (topology == TopologyState::Invalidated && authorization == AuthorizationState::TopologyInvalidated) {
            const NetworkProposal proposal{NetworkComponent::Agent, NetworkPurpose::AgentTransport,
                NetworkProtocol::Tcp, approvals.front(), {RouteKind::OnLinkUnicast, "192.0.2.10", 1, 1}};
            const auto denied = gate.evaluate(proposal, 1);
            return monitor.check_changes() == TopologyState::Invalidated &&
                denied.state == AuthorizationState::TopologyInvalidated && !denied.candidate_in_scope() &&
                gate.activate(ConfigurationEvidence::Validated, 1, 1, approvals, {}, bindings) ==
                    AuthorizationState::StaleGeneration ? 0 : 1;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    return 1;
}
} // namespace

int main(int argc, char** argv) {
    if (argc == 2 && std::string_view{argv[1]} == "--watch") { return watch(); }
    if (argc == 3 && std::string_view{argv[1]} == "--namespace-routes") {
        // The optional isolated namespace has a veth pair. Actual direct
        // routes may pass the route parser but the attachment gate denies it.
        const std::string_view index_text{argv[2]};
        std::uint32_t index{};
        const auto result = std::from_chars(index_text.data(), index_text.data() + index_text.size(), index);
        if (result.ec != std::errc{} || result.ptr != index_text.data() + index_text.size() || index == 0) {
            return 1;
        }
        for (const auto literal : {"192.0.2.10", "2001:db8:3::10"}) {
            const auto target = address(literal);
            check(detail::query_route(target, index, 7443, false) == detail::Inspection::Accepted,
                  "isolated effective route");
            check(detail::query_route(target, index, 7443, true) == detail::Inspection::Accepted,
                  "isolated FIB route");
        }
        for (const auto literal : {"203.0.113.10", "2001:db8:4::10"}) {
            const auto target = address(literal);
            check(detail::query_route(target, index, 7443, true) == detail::Inspection::Rejected,
                  "isolated default route denial");
        }
        check(detail::query_link(index, "ks33a") == detail::Inspection::Rejected,
              "isolated direct route does not override virtual link denial");
        if (failures != 0) { return 1; }
        std::cout << "M3.3 isolated IPv4/IPv6 kernel direct route inspection: PASS\n";
        return 0;
    }
    if (argc != 1) { return 1; }
    route_tests();
    link_tests();
    notification_tests();
    kernel_tests();
    if (failures != 0) { return 1; }
    std::cout << "M3.3 route and link fixtures, kernel replies and invalidation: PASS\n";
    return 0;
}
