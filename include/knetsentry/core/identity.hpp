// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once

#include <array>
#include <cstddef>
#include <memory>
#include <optional>
#include <span>
#include <openssl/types.h>

namespace knetsentry::identity {

enum class Role { Agent, Manager };
enum class Error { None, InvalidInput, UnsafeStorage, Io, AlreadyExists, Crypto, CertificateRejected };
inline constexpr std::size_t max_key_bytes = 1024;
inline constexpr std::size_t max_certificate_bytes = 8192;
using Fingerprint = std::array<unsigned char, 32>;
struct KeyDeleter { void operator()(EVP_PKEY* key) const noexcept; };
using Key = std::unique_ptr<EVP_PKEY, KeyDeleter>;
struct KeyResult {
    Error error{Error::Crypto};
    Key key{};
};

// A trusted caller opens and retains a private directory descriptor. No path
// supplied by a peer is ever used. The directory must be euid-owned, mode 0700.
[[nodiscard]] KeyResult create_key(int directory, Role role) noexcept;
[[nodiscard]] KeyResult load_key(int directory, Role role) noexcept;
[[nodiscard]] std::optional<Fingerprint> fingerprint(EVP_PKEY* key) noexcept;

// Explicit trusted root, expected role and independently approved key pin.
// This is offline certificate validation, NOT enrollment or proof of possession.
[[nodiscard]] Error validate_certificate(std::span<const unsigned char> leaf_der,
    std::span<const unsigned char> root_der, Role role,
    const Fingerprint& expected) noexcept;

} // namespace knetsentry::identity
