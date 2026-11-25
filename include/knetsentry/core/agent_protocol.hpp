// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace knetsentry::core::agent_protocol {

inline constexpr std::size_t header_size = 20;
inline constexpr std::size_t heartbeat_body_size = 16;
inline constexpr std::size_t max_frame_size = header_size + heartbeat_body_size;
inline constexpr std::uint8_t major_version = 1;
inline constexpr std::uint8_t minor_version = 0;

enum class Kind : std::uint8_t { Hello = 1, Heartbeat = 2 };
enum class Error : std::uint8_t {
    None, Truncated, Oversize, BadMagic, UnsupportedVersion, UnsupportedKind,
    ReservedFlags, InvalidLength, InvalidSequence, InvalidPayload,
    UnexpectedMessage, CounterRegression, SessionClosed
};

// All values are untrusted reported data, not authenticated identities or evidence.
struct Message final {
    Kind kind{};
    std::uint64_t sequence{};
    std::uint64_t uptime_ms{};
    std::uint64_t dropped_records{};
    bool operator==(const Message&) const = default;
};
struct HeaderResult final {
    Error error{Error::Truncated};
    std::size_t frame_size{};
};
struct Encoded final {
    Error error{Error::InvalidPayload};
    std::array<std::byte, max_frame_size> bytes{};
    std::size_t size{};
};
struct Decoded final {
    Error error{Error::Truncated};
    Message message{};
};

// Inspect exactly a fixed header before reading a body. No allocation or I/O.
[[nodiscard]] HeaderResult inspect_header(std::span<const std::byte> header) noexcept;
// Encode only canonical, supported messages. Failed results have size zero.
[[nodiscard]] Encoded encode(const Message& message) noexcept;
// Decode exactly one frame. Trailing bytes are not silently consumed.
[[nodiscard]] Decoded decode(std::span<const std::byte> frame) noexcept;

// One instance per future authenticated, authorized transport connection.
// This is syntax/order checking only, never a permission or replay defense
// across connections. Any violation permanently closes this validator.
class SessionValidator final {
public:
    SessionValidator() = default;
    SessionValidator(const SessionValidator&) = delete;
    SessionValidator& operator=(const SessionValidator&) = delete;
    SessionValidator(SessionValidator&&) = delete;
    SessionValidator& operator=(SessionValidator&&) = delete;
    [[nodiscard]] Decoded accept(std::span<const std::byte> frame) noexcept;
    [[nodiscard]] bool closed() const noexcept { return closed_; }
    void close() noexcept { closed_ = true; }
private:
    std::uint64_t last_sequence_{};
    std::uint64_t uptime_ms_{};
    std::uint64_t dropped_records_{};
    bool closed_{};
};

} // namespace knetsentry::core::agent_protocol
