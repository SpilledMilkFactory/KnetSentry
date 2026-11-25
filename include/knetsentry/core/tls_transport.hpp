// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once

#include <knetsentry/core/identity.hpp>
#include <memory>
#include <span>

namespace knetsentry::tls {

inline constexpr std::size_t max_plaintext = 4096;
inline constexpr std::size_t max_ciphertext_chunk = 16384;
inline constexpr std::size_t wire_buffer_bytes = 65536;
inline constexpr std::size_t max_handshake_input = 262144;

enum class State { Handshake, Trusted, Closing, Closed, Failed };
enum class Status { Ok, WouldBlock, NotReady, InvalidInput, Closed, Failed };
struct Result { Status status; std::size_t bytes{}; };

// Local credentials and peer pin must come from trusted callers, never from
// peer-provided enrollment data. No sockets or network authorization here.
struct Credentials {
    identity::Role role;
    EVP_PKEY* key;
    std::span<const unsigned char> certificate;
    std::span<const unsigned char> root;
    identity::Fingerprint peer_pin;
};

// Single-threaded, single-use TLS state machine. Caller owns network policy,
// ciphertext delivery, scheduling, connection lifetime and KSAP framing.
class Session final {
public:
    [[nodiscard]] static std::unique_ptr<Session> create(const Credentials& credentials) noexcept;
    ~Session();
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;
    // Observing state also checks deadlines and current certificate validity.
    [[nodiscard]] State state() const noexcept;
    // Verified peer pin only for a currently trusted manager-side session.
    [[nodiscard]] std::optional<identity::Fingerprint> authenticated_agent() const noexcept;
    // Trusted caller supplies the CURRENT approved peer pin; no pin means
    // revoked/unavailable. A mismatch or invalid session is terminal.
    [[nodiscard]] Status revalidate_peer(std::optional<identity::Fingerprint> approved) noexcept;
    [[nodiscard]] Status handshake() noexcept;
    [[nodiscard]] Result ingest(std::span<const unsigned char> ciphertext) noexcept;
    [[nodiscard]] Result drain(std::span<unsigned char> ciphertext) noexcept;
    // On WouldBlock retry write with identical bytes until it completes.
    [[nodiscard]] Result write(std::span<const unsigned char> plaintext) noexcept;
    [[nodiscard]] Result read(std::span<unsigned char, max_plaintext> plaintext) noexcept;
    [[nodiscard]] Status shutdown() noexcept;
    // Call on transport loss/timeout; never treat an abrupt EOF as clean close.
    void abort() noexcept;
private:
    struct Impl;
    explicit Session(std::unique_ptr<Impl> impl) noexcept;
    std::unique_ptr<Impl> impl_;
};

} // namespace knetsentry::tls
