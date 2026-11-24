// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once

#include "knetsentry/core/network_scope.hpp"

#include <cstdint>
#include <string_view>

namespace knetsentry::core {

// Single-thread-owned, namespace-bound observation epoch. Invalidation is
// sticky: a new epoch requires external administrative binding revalidation.
enum class TopologyState : std::uint8_t { Unavailable, Current, Invalidated };
struct TopologyResult final {
    TopologyState state{TopologyState::Unavailable};
    ScopeDecision decision{ScopeDecision::DeniedRoute};
};

class LinuxTopology final {
public:
    LinuxTopology() noexcept;
    ~LinuxTopology();
    LinuxTopology(const LinuxTopology&) = delete;
    LinuxTopology& operator=(const LinuxTopology&) = delete;
    LinuxTopology(LinuxTopology&&) = delete;
    LinuxTopology& operator=(LinuxTopology&&) = delete;

    // Nonblocking. Any subscribed notification, loss, namespace or owner
    // change invalidates the epoch. No automatic rearm or cached permission.
    [[nodiscard]] TopologyState check_changes() noexcept;

    // Ignore proposal.route completely; only locally acquired evidence is
    // supplied to the pure policy. Expected interface name is trusted admin
    // input, not inferred from the route. No IP socket is opened.
    [[nodiscard]] TopologyResult evaluate(const NetworkScopePolicy& policy,
        const NetworkProposal& proposal, std::string_view expected_interface) noexcept;

private:
    int watcher_{-1};
    int namespace_fd_{-1};
    int owner_tid_{};
    std::uint64_t generation_{};
    TopologyState state_{TopologyState::Unavailable};
};

} // namespace knetsentry::core
