// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once

#include "knetsentry/core/linux_topology.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

namespace knetsentry::core {

// Trusted administrative configuration status, not an IPC or telemetry field.
enum class ConfigurationEvidence : std::uint8_t { Unavailable, Invalid, Validated };
enum class AuthorizationState : std::uint8_t {
    Unconfigured, Disabled, ConfigurationUnavailable, InvalidConfiguration,
    StaleGeneration, InvalidPolicy, EmptyPolicy, InvalidBindings,
    TopologyUnavailable, TopologyInvalidated, RouteUnverified, Ready
};
struct InterfaceBinding final {
    std::uint32_t index{};
    std::string_view name;
};
struct AuthorizationResult final {
    AuthorizationState state{AuthorizationState::Unconfigured};
    ScopeDecision decision{ScopeDecision::DeniedPolicy};
    std::uint64_t generation{};
    [[nodiscard]] bool candidate_in_scope() const noexcept {
        return state == AuthorizationState::Ready && generation != 0 &&
            decision == ScopeDecision::CandidateInScope;
    }
};

// Owner-thread-only, in-memory preflight authority for the initial agent
// transport profile. No transport permit, socket, or persistent config store.
// Every activation attempt first discards the old snapshot and topology epoch.
class NetworkAuthorization final {
public:
    NetworkAuthorization() = default;
    NetworkAuthorization(const NetworkAuthorization&) = delete;
    NetworkAuthorization& operator=(const NetworkAuthorization&) = delete;
    NetworkAuthorization(NetworkAuthorization&&) = delete;
    NetworkAuthorization& operator=(NetworkAuthorization&&) = delete;

    // Only a trusted local administrator/configuration publisher may call
    // activate. A fresh nonzero revision is consumed even on rejection.
    // Bindings must cover exactly the interfaces referenced by the approvals.
    [[nodiscard]] AuthorizationState activate(ConfigurationEvidence configuration,
        std::uint32_t schema, std::uint64_t generation,
        std::span<const EndpointApproval> exact,
        std::span<const PrefixApproval> prefixes,
        std::span<const InterfaceBinding> bindings) noexcept;
    // Explicit loss/withdrawal of configuration closes without resetting the
    // high-water mark. Recovery always requires a new administrative revision.
    void disable() noexcept;
    [[nodiscard]] AuthorizationState check_changes() noexcept;
    [[nodiscard]] AuthorizationResult evaluate(const NetworkProposal& proposal,
        std::uint64_t expected_generation) noexcept;
    [[nodiscard]] std::uint64_t high_water_generation() const noexcept { return high_water_; }

private:
    // Linux IFNAMSIZ is 16 including the terminator. Use bounded owned values.
    static constexpr std::size_t name_capacity = 16;
    struct Binding final {
        std::uint32_t index{};
        std::array<char, name_capacity> name{};
    };
    [[nodiscard]] AuthorizationState close(AuthorizationState reason) noexcept;
    [[nodiscard]] bool load_bindings(std::span<const EndpointApproval> exact,
        std::span<const PrefixApproval> prefixes,
        std::span<const InterfaceBinding> bindings) noexcept;
    [[nodiscard]] std::string_view interface_name(std::uint32_t index) const noexcept;
    NetworkScopePolicy policy_{};
    std::array<Binding, NetworkScopePolicy::max_approvals> bindings_{};
    std::size_t binding_count_{};
    std::optional<LinuxTopology> topology_;
    std::uint64_t high_water_{};
    AuthorizationState state_{AuthorizationState::Unconfigured};
};

} // namespace knetsentry::core
