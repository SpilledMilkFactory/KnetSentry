// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/core/network_authorization.hpp"

#include <algorithm>
#include <net/if.h>

namespace knetsentry::core {
namespace {
// Narrow initial administrative profile. Reject ambiguous names, whitespace,
// embedded NUL, and names that cannot fit the kernel interface-name field.
bool valid_name(std::string_view name) noexcept {
    return !name.empty() && name.size() < IFNAMSIZ && name != "." && name != ".." &&
        std::ranges::all_of(name, [](char ch) {
            return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                (ch >= '0' && ch <= '9') || ch == '_' || ch == '-' || ch == '.';
        });
}
} // namespace

AuthorizationState NetworkAuthorization::close(AuthorizationState reason) noexcept {
    topology_.reset();
    policy_ = NetworkScopePolicy{};
    bindings_ = {};
    binding_count_ = 0;
    state_ = reason;
    return state_;
}

void NetworkAuthorization::disable() noexcept {
    static_cast<void>(close(AuthorizationState::Disabled));
}

std::string_view NetworkAuthorization::interface_name(std::uint32_t index) const noexcept {
    for (std::size_t pos = 0; pos < binding_count_; ++pos) {
        if (bindings_[pos].index == index) { return bindings_[pos].name.data(); }
    }
    return {};
}

bool NetworkAuthorization::load_bindings(std::span<const EndpointApproval> exact,
    std::span<const PrefixApproval> prefixes,
    std::span<const InterfaceBinding> bindings) noexcept {
    static_assert(name_capacity == IFNAMSIZ);
    if (bindings.empty() || bindings.size() > bindings_.size()) { return false; }
    for (const auto& binding : bindings) {
        if (binding.index == 0 || !valid_name(binding.name) ||
            !interface_name(binding.index).empty()) { return false; }
        for (std::size_t pos = 0; pos < binding_count_; ++pos) {
            if (binding.name == bindings_[pos].name.data()) { return false; }
        }
        const auto uses_index = [&binding](const auto& approval) {
            return approval.interface_index == binding.index;
        };
        if (!std::ranges::any_of(exact, uses_index) &&
            !std::ranges::any_of(prefixes, uses_index)) { return false; }
        auto& owned = bindings_[binding_count_++];
        owned.index = binding.index;
        std::ranges::copy(binding.name, owned.name.begin());
    }
    const auto covered = [this](const auto& approval) {
        return !interface_name(approval.interface_index).empty();
    };
    return std::ranges::all_of(exact, covered) && std::ranges::all_of(prefixes, covered);
}

AuthorizationState NetworkAuthorization::activate(ConfigurationEvidence configuration,
    std::uint32_t schema, std::uint64_t generation,
    std::span<const EndpointApproval> exact,
    std::span<const PrefixApproval> prefixes,
    std::span<const InterfaceBinding> bindings) noexcept {
    // Withdraw before checking anything. Invalid updates cannot retain the
    // previous authority, even if the revision itself was malformed or stale.
    static_cast<void>(close(AuthorizationState::Unconfigured));
    if (generation == 0 || generation <= high_water_) {
        return close(AuthorizationState::StaleGeneration);
    }
    high_water_ = generation;
    if (configuration == ConfigurationEvidence::Unavailable) {
        return close(AuthorizationState::ConfigurationUnavailable);
    }
    if (configuration != ConfigurationEvidence::Validated) {
        return close(AuthorizationState::InvalidConfiguration);
    }
    policy_ = schema == 1 && prefixes.empty()
        ? NetworkScopePolicy::compile(schema, generation, exact)
        : NetworkScopePolicy::compile(schema, generation, exact, prefixes);
    if (!policy_.valid()) { return close(AuthorizationState::InvalidPolicy); }
    if (exact.empty() && prefixes.empty()) { return close(AuthorizationState::EmptyPolicy); }
    if (!load_bindings(exact, prefixes, bindings)) {
        return close(AuthorizationState::InvalidBindings);
    }
    topology_.emplace();
    state_ = AuthorizationState::Ready;
    return check_changes();
}

AuthorizationState NetworkAuthorization::check_changes() noexcept {
    if (state_ != AuthorizationState::Ready) { return state_; }
    if (!topology_.has_value()) { return close(AuthorizationState::TopologyUnavailable); }
    switch (topology_->check_changes()) {
    case TopologyState::Current: return state_;
    case TopologyState::Invalidated: return close(AuthorizationState::TopologyInvalidated);
    case TopologyState::Unavailable: return close(AuthorizationState::TopologyUnavailable);
    }
    return close(AuthorizationState::TopologyUnavailable);
}

AuthorizationResult NetworkAuthorization::evaluate(const NetworkProposal& proposal,
    std::uint64_t expected_generation) noexcept {
    if (check_changes() != AuthorizationState::Ready || expected_generation != high_water_) {
        return {state_, ScopeDecision::DeniedPolicy, high_water_};
    }
    const auto name = interface_name(proposal.endpoint.interface_index);
    if (name.empty()) { return {state_, ScopeDecision::DeniedApproval, high_water_}; }
    // Never take the interface name or route evidence from the proposal.
    const auto result = topology_->evaluate(policy_, proposal, name);
    if (result.state != TopologyState::Current) {
        const auto reason = result.state == TopologyState::Invalidated
            ? AuthorizationState::TopologyInvalidated : AuthorizationState::TopologyUnavailable;
        return {close(reason), ScopeDecision::DeniedRoute, high_water_};
    }
    switch (result.decision) {
    case ScopeDecision::CandidateInScope:
    case ScopeDecision::DeniedPurpose:
    case ScopeDecision::DeniedEndpoint:
    case ScopeDecision::DeniedApproval:
        return {state_, result.decision, high_water_};
    case ScopeDecision::DeniedRoute:
        return {close(AuthorizationState::RouteUnverified), result.decision, high_water_};
    case ScopeDecision::DeniedPolicy:
        break;
    }
    return {close(AuthorizationState::InvalidPolicy), ScopeDecision::DeniedPolicy, high_water_};
}

} // namespace knetsentry::core
