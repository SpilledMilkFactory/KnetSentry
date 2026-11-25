// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once

#include <knetsentry/core/tls_transport.hpp>
#include <array>
#include <optional>

namespace knetsentry::enrollment {
using EndpointId = std::array<unsigned char, 16>;
inline constexpr std::size_t max_endpoints = 128;
enum class Status { Ok, InvalidInput, UnsafeStorage, Unavailable, Busy,
    Corrupt, Conflict, Full, Unknown, NotAuthenticated, IdentityMismatch, Io, Revoked };
struct Lookup { Status status{Status::Unavailable}; std::optional<identity::Fingerprint> pin{}; };

// Authority is the explicitly trusted, euid-owned private directory descriptor.
// Never expose initialize/approve to peer requests. No implicit initialization.
[[nodiscard]] Status initialize(int directory) noexcept;
[[nodiscard]] Status approve(int directory, const EndpointId& id,
    const identity::Fingerprint& pin) noexcept;
// Explicit compare-and-replace; retired keys and revoked IDs cannot be reused.
[[nodiscard]] Status rotate(int directory, const EndpointId& id,
    const identity::Fingerprint& expected, const identity::Fingerprint& replacement) noexcept;
[[nodiscard]] Status revoke(int directory, const EndpointId& id,
    const identity::Fingerprint& expected) noexcept;
[[nodiscard]] Lookup lookup(int directory, const EndpointId& id) noexcept;
// Only a currently Trusted manager-side TLS session can supply agent proof.
// This is enrollment admission, not network or monitoring authorization.
[[nodiscard]] Status authorize(int directory, const EndpointId& id,
    const tls::Session& session) noexcept;
// Operational consumers must revalidate before each application operation.
// Any denial makes the supplied session terminal; no cached grant is returned.
[[nodiscard]] Status revalidate(int directory, const EndpointId& id,
    tls::Session& session) noexcept;
} // namespace knetsentry::enrollment
