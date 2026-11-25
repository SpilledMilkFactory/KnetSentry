// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once

#include <knetsentry/core/agent_protocol.hpp>
#include <knetsentry/core/enrollment.hpp>

namespace knetsentry::agent_health {
using Millis = std::uint64_t;
inline constexpr Millis heartbeat_interval = 30000;
inline constexpr Millis missing_after = 90000;
inline constexpr Millis attempt_timeout = 10000;
inline constexpr Millis initial_retry = 1000;
inline constexpr Millis maximum_retry = 60000;

enum class Health { Missing, Awaiting, Healthy, Degraded, Untrusted, ProtocolError };
struct Counters { std::uint64_t uptime_ms{}, dropped_records{}; };
struct Snapshot { Health health{Health::Missing}; std::optional<Counters> counters{}; };

// One instance per explicitly configured endpoint. Single-threaded. The
// constructor duplicates the trusted registry directory. All times are trusted
// local monotonic milliseconds. Owns one established manager-side TLS session.
class Tracker final {
public:
    Tracker(int directory, const enrollment::EndpointId& id) noexcept;
    ~Tracker();
    Tracker(const Tracker&) = delete;
    Tracker& operator=(const Tracker&) = delete;
    [[nodiscard]] bool attach(std::unique_ptr<tls::Session> session, Millis now) noexcept;
    [[nodiscard]] tls::Result ingest(std::span<const unsigned char> bytes, Millis now) noexcept;
    [[nodiscard]] tls::Result drain(std::span<unsigned char> bytes, Millis now) noexcept;
    // At most one bounded TLS read per call; call periodically even when idle.
    [[nodiscard]] Snapshot poll(Millis now) noexcept;
    void disconnected() noexcept;
private:
    [[nodiscard]] bool check(Millis now) noexcept;
    void invalidate(Health reason) noexcept;
    [[nodiscard]] bool consume(std::span<const unsigned char> bytes, Millis now) noexcept;
    int directory_;
    enrollment::EndpointId id_;
    std::unique_ptr<tls::Session> session_;
    std::optional<core::agent_protocol::SessionValidator> validator_;
    std::array<std::byte, core::agent_protocol::max_frame_size> frame_{};
    std::size_t used_{};
    std::size_t wanted_{core::agent_protocol::header_size};
    Millis last_clock_{}, last_report_{};
    Snapshot snapshot_{};
};

// One reporter per established agent-side session. Borrowed session must
// outlive reporter. Caller drives ciphertext and supplies current manager pin.
// WouldBlock retains the exact pending frame; counters advance only on write.
class Reporter final {
public:
    explicit Reporter(tls::Session& session) noexcept : session_(session) {}
    Reporter(const Reporter&) = delete;
    Reporter& operator=(const Reporter&) = delete;
    [[nodiscard]] tls::Status send(std::optional<identity::Fingerprint> manager_pin,
        Millis now, Counters counters) noexcept;
private:
    tls::Session& session_;
    core::agent_protocol::Encoded pending_{};
    Counters pending_counters_{}, last_counters_{};
    std::uint64_t sequence_{1};
    Millis last_clock_{}, last_report_{};
};

// Scheduling gate only, never network authority. One outstanding attempt.
// Caller must cancel timed-out attempts and enforce
// current network authorization before every actual connection operation.
class Reconnect final {
public:
    enum class Phase { Waiting, Connecting, Online, Blocked };
    Reconnect() = default;
    Reconnect(const Reconnect&) = delete;
    Reconnect& operator=(const Reconnect&) = delete;
    [[nodiscard]] std::optional<std::uint64_t> begin(Millis now) noexcept;
    [[nodiscard]] bool connected(Millis now, std::uint64_t attempt) noexcept;
    void lost(Millis now, std::uint64_t attempt) noexcept;
    [[nodiscard]] Phase phase(Millis now) noexcept;
private:
    [[nodiscard]] bool advance(Millis now) noexcept;
    void retry(Millis now) noexcept;
    Phase phase_{Phase::Waiting};
    Millis last_clock_{}, since_{}, wait_{}, next_delay_{initial_retry};
    std::uint64_t attempt_{};
};
} // namespace knetsentry::agent_health
