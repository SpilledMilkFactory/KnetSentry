// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/core/linux_topology.hpp"
#include "linux_topology_detail.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

namespace knetsentry::core {
namespace {
using topology_detail::Address;
using topology_detail::Bytes;
using topology_detail::Inspection;

template <typename T>
bool read_value(Bytes bytes, T& value) noexcept {
    if (bytes.size() != sizeof(T)) {
        return false;
    }
    std::memcpy(&value, bytes.data(), sizeof(T));
    return true;
}

template <typename T, typename Visitor>
bool attributes(Bytes payload, T& header, Visitor visit) noexcept {
    if (payload.size() < sizeof(T)) {
        return false;
    }
    std::memcpy(&header, payload.data(), sizeof(T));
    payload = payload.subspan(sizeof(T));
    while (!payload.empty()) {
        rtattr attr{};
        if (payload.size() < sizeof(attr)) {
            return false;
        }
        std::memcpy(&attr, payload.data(), sizeof(attr));
        const std::size_t length = attr.rta_len;
        const std::size_t aligned = (length + 3U) & ~std::size_t{3};
        if (length < sizeof(attr) || aligned > payload.size() ||
            !visit(attr.rta_type, payload.subspan(sizeof(attr), length - sizeof(attr)))) {
            return false;
        }
        payload = payload.subspan(aligned);
    }
    return true;
}

bool valid_shape(const Address& address) noexcept {
    return (address.family == AF_INET && address.size == 4) ||
        (address.family == AF_INET6 && address.size == 16);
}

bool prefix_matches(Bytes prefix, const Address& address, unsigned bits) noexcept {
    if (!valid_shape(address) || prefix.size() != address.size || bits == 0 || bits > address.size * 8U) {
        return false;
    }
    for (unsigned bit = 0; bit < bits; ++bit) {
        const auto mask = std::byte{static_cast<unsigned char>(0x80U >> (bit % 8U))};
        if ((prefix[bit / 8U] & mask) != (address.bytes[bit / 8U] & mask)) {
            return false;
        }
    }
    // A FIB prefix must be canonical.
    for (auto bit = bits; bit < address.size * 8U; ++bit) {
        const auto mask = std::byte{static_cast<unsigned char>(0x80U >> (bit % 8U))};
        if ((prefix[bit / 8U] & mask) != std::byte{}) {
            return false;
        }
    }
    return true;
}

class Descriptor final {
public:
    explicit Descriptor(int fd) noexcept : fd_{fd} {}
    ~Descriptor() { if (fd_ >= 0) { close(fd_); } }
    Descriptor(const Descriptor&) = delete;
    Descriptor& operator=(const Descriptor&) = delete;
    [[nodiscard]] int get() const noexcept { return fd_; }
private:
    int fd_;
};

int open_netlink() noexcept {
    const int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
    if (fd < 0) {
        return -1;
    }
    sockaddr_nl local{};
    local.nl_family = AF_NETLINK;
    if (bind(fd, reinterpret_cast<const sockaddr*>(&local), sizeof(local)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

// One bounded kernel request, one strictly correlated reply. Unsupported,
// truncated, multi-part, error or unexpected responses never yield evidence.
class Query final {
public:
    template <typename T>
    Query(std::uint16_t type, const T& body) noexcept {
        nlmsghdr header{};
        header.nlmsg_len = static_cast<std::uint32_t>(sizeof(header) + sizeof(body));
        header.nlmsg_type = type;
        header.nlmsg_flags = NLM_F_REQUEST;
        header.nlmsg_seq = 1;
        used_ = header.nlmsg_len;
        std::memcpy(data_.data(), &header, sizeof(header));
        std::memcpy(data_.data() + sizeof(header), &body, sizeof(body));
    }
    bool append(std::uint16_t type, Bytes value) noexcept {
        const auto length = sizeof(rtattr) + value.size();
        const auto aligned = (length + 3U) & ~std::size_t{3};
        if (aligned > data_.size() - used_) {
            return false;
        }
        const rtattr attr{static_cast<unsigned short>(length), type};
        std::memcpy(data_.data() + used_, &attr, sizeof(attr));
        std::memcpy(data_.data() + used_ + sizeof(attr), value.data(), value.size());
        used_ += aligned;
        const auto size = static_cast<std::uint32_t>(used_);
        std::memcpy(data_.data(), &size, sizeof(size));
        return true;
    }
    template <typename T>
    bool append_value(std::uint16_t type, const T& value) noexcept {
        return append(type, std::as_bytes(std::span{&value, 1}));
    }
    template <typename Visitor>
    Inspection exchange(std::uint16_t expected_type, Visitor visit) const noexcept {
        const Descriptor fd{open_netlink()};
        if (fd.get() < 0) {
            return Inspection::Unavailable;
        }
        sockaddr_nl kernel{};
        kernel.nl_family = AF_NETLINK;
        const auto sent = sendto(fd.get(), data_.data(), used_, MSG_DONTWAIT,
            reinterpret_cast<const sockaddr*>(&kernel), sizeof(kernel));
        if (sent < 0 || static_cast<std::size_t>(sent) != used_) {
            return Inspection::Unavailable;
        }
        pollfd ready{fd.get(), POLLIN, 0};
        if (poll(&ready, 1, 250) != 1 || ready.revents != POLLIN) {
            return Inspection::Unavailable;
        }
        std::array<std::byte, 8192> response{};
        sockaddr_nl sender{};
        iovec buffer{response.data(), response.size()};
        msghdr message{};
        message.msg_name = &sender;
        message.msg_namelen = sizeof(sender);
        message.msg_iov = &buffer;
        message.msg_iovlen = 1;
        const auto received = recvmsg(fd.get(), &message, MSG_DONTWAIT);
        if (received < static_cast<ssize_t>(sizeof(nlmsghdr)) ||
            (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 ||
            message.msg_namelen != sizeof(sender) || sender.nl_family != AF_NETLINK ||
            sender.nl_pid != 0 || sender.nl_groups != 0) {
            return Inspection::Unavailable;
        }
        nlmsghdr header{};
        std::memcpy(&header, response.data(), sizeof(header));
        if (header.nlmsg_len != static_cast<std::size_t>(received) ||
            header.nlmsg_len > response.size() || header.nlmsg_type != expected_type ||
            header.nlmsg_seq != 1 || (header.nlmsg_flags & (NLM_F_MULTI | NLM_F_DUMP_INTR)) != 0) {
            return Inspection::Unavailable;
        }
        return visit(Bytes{response}.subspan(sizeof(header), header.nlmsg_len - sizeof(header)))
            ? Inspection::Accepted : Inspection::Rejected;
    }
private:
    std::array<std::byte, 128> data_{};
    std::size_t used_{};
};

} // namespace

namespace topology_detail {
Inspection query_route(const Address& destination, std::uint32_t index,
                 std::uint16_t port, bool fib_match) noexcept {
    if (!valid_shape(destination) || index == 0 || port == 0) {
        return Inspection::Unavailable;
    }
    rtmsg route{};
    route.rtm_family = static_cast<unsigned char>(destination.family);
    route.rtm_dst_len = static_cast<unsigned char>(destination.size * 8U);
    route.rtm_flags = fib_match ? RTM_F_FIB_MATCH : 0;
    Query query{RTM_GETROUTE, route};
    const std::uint8_t protocol = IPPROTO_TCP;
    const std::uint16_t network_port = htons(port);
    if (!query.append(RTA_DST, Bytes{destination.bytes}.first(destination.size)) ||
        !query.append_value(RTA_IP_PROTO, protocol) || !query.append_value(RTA_DPORT, network_port)) {
        return Inspection::Unavailable;
    }
    // IPv6 link-local lookup needs its explicit zone. Do not force OIF for
    // other addresses: inspect the actual selected path instead.
    const bool link_local = destination.family == AF_INET6 &&
        destination.bytes[0] == std::byte{0xfe} &&
        (destination.bytes[1] & std::byte{0xc0}) == std::byte{0x80};
    if (link_local && !query.append_value(RTA_OIF, index)) {
        return Inspection::Unavailable;
    }
    return query.exchange(RTM_NEWROUTE, [&](Bytes payload) {
        return topology_detail::direct_route(payload, destination, index, fib_match);
    });
}

Inspection query_link(std::uint32_t index, std::string_view name) noexcept {
    if (index == 0 || index > 0x7fffffffU) {
        return Inspection::Unavailable;
    }
    ifinfomsg link{};
    link.ifi_family = AF_UNSPEC;
    link.ifi_index = static_cast<int>(index);
    const Query query{RTM_GETLINK, link};
    return query.exchange(RTM_NEWLINK, [&](Bytes payload) {
        return topology_detail::approved_link(payload, index, name);
    });
}
bool parse_address(std::string_view text, Address& address) noexcept {
    if (text.empty() || text.size() >= INET6_ADDRSTRLEN || text.find('\0') != text.npos) {
        return false;
    }
    std::array<char, INET6_ADDRSTRLEN> input{};
    std::copy(text.begin(), text.end(), input.begin());
    Address candidate{};
    if (inet_pton(AF_INET, input.data(), candidate.bytes.data()) == 1) {
        candidate.family = AF_INET;
        candidate.size = 4;
    } else if (text.find('.') == text.npos &&
               inet_pton(AF_INET6, input.data(), candidate.bytes.data()) == 1) {
        candidate.family = AF_INET6;
        candidate.size = 16;
    } else {
        return false;
    }
    address = candidate;
    return true;
}

bool direct_route(Bytes payload, const Address& destination, std::uint32_t index,
                  bool fib_match) noexcept {
    if (!valid_shape(destination)) { return false; }
    rtmsg route{};
    std::uint32_t table{};
    std::uint32_t output{};
    bool have_table = false;
    bool have_output = false;
    bool have_destination = false;
    Bytes prefix;
    const bool parsed = attributes(payload, route, [&](unsigned type, Bytes value) {
        switch (type) {
        case RTA_DST:
            if (have_destination) { return false; }
            have_destination = true;
            prefix = value;
            return true;
        case RTA_OIF:
            if (have_output) { return false; }
            have_output = read_value(value, output);
            return have_output;
        case RTA_TABLE:
            if (have_table) { return false; }
            have_table = read_value(value, table);
            return have_table;
        // Known metadata that cannot widen the selected output path.
        case RTA_PREFSRC: return value.size() == destination.size;
        case RTA_PRIORITY: case RTA_UID:
            return value.size() == sizeof(std::uint32_t);
        case RTA_MARK: {
            std::uint32_t mark{};
            return read_value(value, mark) && mark == 0;
        }
        case RTA_CACHEINFO: return value.size() == sizeof(rta_cacheinfo);
        case RTA_METRICS: return true; // transport metrics, not path selection
        case RTA_PREF: return value.size() == 1;
        // Gateways, multipath, nexthop objects, encapsulation, source routes,
        // and all unknown routing attributes are outside the initial profile.
        default: return false;
        }
    });
    const unsigned bits = route.rtm_dst_len;
    if (!parsed || route.rtm_family != destination.family || route.rtm_type != RTN_UNICAST ||
        route.rtm_src_len != 0 || route.rtm_tos != 0 || !have_output || output != index ||
        index == 0 || !have_destination ||
        (have_table ? table : route.rtm_table) != RT_TABLE_MAIN ||
        (have_table && route.rtm_table != RT_TABLE_UNSPEC && route.rtm_table != table) ||
        (route.rtm_flags & ~static_cast<unsigned>(RTM_F_CLONED)) != 0 ||
        (route.rtm_scope != RT_SCOPE_LINK && route.rtm_scope != RT_SCOPE_UNIVERSE) ||
        (fib_match && destination.family == AF_INET && route.rtm_scope != RT_SCOPE_LINK) ||
        (!fib_match && bits != destination.size * 8U) ||
        !prefix_matches(prefix, destination, bits)) {
        return false;
    }
    // A default route with no gateway still cannot qualify. FIB_MATCH is
    // required in addition to the effective host lookup to expose its prefix.
    if (fib_match && destination.family == AF_INET && bits <= 30U) {
        bool all_zero = true;
        bool all_one = true;
        for (auto bit = bits; bit < 32U; ++bit) {
            const auto mask = std::byte{static_cast<unsigned char>(0x80U >> (bit % 8U))};
            const bool set = (destination.bytes[bit / 8U] & mask) != std::byte{};
            all_zero = all_zero && !set;
            all_one = all_one && set;
        }
        if (all_zero || all_one) { return false; }
    }
    return true;
}

bool approved_link(Bytes payload, std::uint32_t index, std::string_view name) noexcept {
    if (name.empty() || name.size() >= IFNAMSIZ || name.find('\0') != name.npos) {
        return false;
    }
    ifinfomsg link{};
    bool have_name = false;
    const bool parsed = attributes(payload, link, [&](unsigned raw_type, Bytes value) {
        // Attribute flags must not conceal a known disallowed link kind.
        const unsigned type = raw_type & static_cast<unsigned>(NLA_TYPE_MASK);
        if (type == IFLA_IFNAME) {
            if (raw_type != type || have_name || value.size() != name.size() + 1 || value.back() != std::byte{} ||
                std::memcmp(value.data(), name.data(), name.size()) != 0) {
                return false;
            }
            have_name = true;
        }
        // Conservative initial Ethernet-like profile. No known virtual kind,
        // subordinate/stacked interface, master, or cross-namespace link.
        return type != IFLA_LINKINFO && type != IFLA_MASTER && type != IFLA_LINK &&
            type != IFLA_LINK_NETNSID && type != IFLA_NET_NS_PID && type != IFLA_NET_NS_FD;
    });
    constexpr unsigned required = IFF_UP | IFF_RUNNING | IFF_LOWER_UP;
    constexpr unsigned forbidden = IFF_LOOPBACK | IFF_POINTOPOINT | IFF_DORMANT;
    return parsed && have_name && link.ifi_index > 0 &&
        static_cast<std::uint32_t>(link.ifi_index) == index && link.ifi_type == ARPHRD_ETHER &&
        (link.ifi_flags & required) == required && (link.ifi_flags & forbidden) == 0;
}
bool watcher_quiet(int descriptor) noexcept {
    if (descriptor < 0) { return false; }
    pollfd pending{descriptor, POLLIN, 0};
    return poll(&pending, 1, 0) == 0;
}
} // namespace topology_detail

LinuxTopology::LinuxTopology() noexcept {
    owner_tid_ = gettid();
    namespace_fd_ = open("/proc/thread-self/ns/net", O_RDONLY | O_CLOEXEC);
    if (namespace_fd_ < 0) { return; }
    watcher_ = open_netlink();
    if (watcher_ < 0) { return; }
    constexpr std::array groups{RTNLGRP_LINK, RTNLGRP_IPV4_IFADDR, RTNLGRP_IPV6_IFADDR,
        RTNLGRP_IPV4_ROUTE, RTNLGRP_IPV6_ROUTE, RTNLGRP_IPV4_RULE, RTNLGRP_IPV6_RULE,
        RTNLGRP_NEXTHOP, RTNLGRP_IPV4_NETCONF, RTNLGRP_IPV6_NETCONF, RTNLGRP_IPV6_IFINFO};
    for (const int group : groups) {
        if (setsockopt(watcher_, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &group, sizeof(group)) != 0) {
            return;
        }
    }
    state_ = TopologyState::Current;
}

LinuxTopology::~LinuxTopology() {
    if (watcher_ >= 0) { close(watcher_); }
    if (namespace_fd_ >= 0) { close(namespace_fd_); }
}

TopologyState LinuxTopology::check_changes() noexcept {
    if (state_ != TopologyState::Current) { return state_; }
    struct stat original{};
    struct stat current{};
    if (gettid() != owner_tid_ || fstat(namespace_fd_, &original) != 0 ||
        stat("/proc/thread-self/ns/net", &current) != 0 || original.st_dev != current.st_dev ||
        original.st_ino != current.st_ino || !topology_detail::watcher_quiet(watcher_)) {
        // Any queued message, overrun, error, interrupted poll or namespace
        // change requires revalidation. Do not drain/rearm stale authority.
        state_ = TopologyState::Invalidated;
    }
    return state_;
}

TopologyResult LinuxTopology::evaluate(const NetworkScopePolicy& policy,
    const NetworkProposal& proposal, std::string_view expected_interface) noexcept {
    const auto initial = check_changes();
    if (initial != TopologyState::Current) { return {initial, ScopeDecision::DeniedRoute}; }
    if (generation_ != 0 && generation_ != policy.generation()) {
        state_ = TopologyState::Invalidated;
        return {state_, ScopeDecision::DeniedRoute};
    }
    if (policy.valid()) { generation_ = policy.generation(); }
    auto candidate = proposal;
    // Pre-filter only: never publish this result without live checks below.
    // Ignore caller-provided route data, including its generation.
    candidate.route = {RouteKind::OnLinkUnicast, proposal.endpoint.destination,
                       proposal.endpoint.interface_index, policy.generation()};
    const auto preflight = policy.evaluate(candidate);
    if (preflight != ScopeDecision::CandidateInScope) { return {initial, preflight}; }
    Address destination{};
    const auto index = proposal.endpoint.interface_index;
    const bool verified = topology_detail::parse_address(proposal.endpoint.destination, destination) &&
        topology_detail::query_link(index, expected_interface) == Inspection::Accepted &&
        topology_detail::query_route(destination, index, proposal.endpoint.port, false) == Inspection::Accepted &&
        topology_detail::query_route(destination, index, proposal.endpoint.port, true) == Inspection::Accepted;
    const auto final_state = check_changes();
    return {final_state, verified && final_state == TopologyState::Current
        ? policy.evaluate(candidate) : ScopeDecision::DeniedRoute};
}
} // namespace knetsentry::core
