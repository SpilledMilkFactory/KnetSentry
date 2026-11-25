// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/core/agent_protocol.hpp"

#include <algorithm>
#include <limits>

namespace knetsentry::core::agent_protocol {
namespace {
constexpr std::array magic{std::byte{0x4b}, std::byte{0x53}, std::byte{0x41}, std::byte{0x50}};

// Explicit network byte order; never serialize a native struct or enum layout.
std::uint64_t read_be(std::span<const std::byte> bytes) noexcept {
    std::uint64_t result{};
    for (const auto byte : bytes) {
        result = (result << 8U) | std::to_integer<std::uint64_t>(byte);
    }
    return result;
}
void write_be(std::span<std::byte> bytes, std::uint64_t value) noexcept {
    for (auto it = bytes.rbegin(); it != bytes.rend(); ++it) {
        *it = static_cast<std::byte>(value & 0xffU);
        value >>= 8U;
    }
}
} // namespace

HeaderResult inspect_header(std::span<const std::byte> header) noexcept {
    if (header.size() < header_size) { return {Error::Truncated, 0}; }
    if (header.size() != header_size) { return {Error::InvalidLength, 0}; }
    if (!std::equal(magic.begin(), magic.end(), header.begin())) { return {Error::BadMagic, 0}; }
    if (header[4] != std::byte{major_version} || header[5] != std::byte{minor_version}) {
        return {Error::UnsupportedVersion, 0};
    }
    if (header[7] != std::byte{}) { return {Error::ReservedFlags, 0}; }
    const auto length = read_be(header.subspan(8, 4));
    if (length > heartbeat_body_size) { return {Error::Oversize, 0}; }
    const auto kind = std::to_integer<std::uint8_t>(header[6]);
    if (kind != static_cast<std::uint8_t>(Kind::Hello) &&
        kind != static_cast<std::uint8_t>(Kind::Heartbeat)) {
        return {Error::UnsupportedKind, 0};
    }
    const auto expected = kind == static_cast<std::uint8_t>(Kind::Hello) ? 0U : heartbeat_body_size;
    if (length != expected) { return {Error::InvalidLength, 0}; }
    if (read_be(header.subspan(12, 8)) == 0) { return {Error::InvalidSequence, 0}; }
    return {Error::None, header_size + expected};
}

Encoded encode(const Message& message) noexcept {
    Encoded result{};
    if (message.kind != Kind::Hello && message.kind != Kind::Heartbeat) {
        result.error = Error::UnsupportedKind;
        return result;
    }
    if (message.sequence == 0) { result.error = Error::InvalidSequence; return result; }
    if (message.kind == Kind::Hello && (message.uptime_ms != 0 || message.dropped_records != 0)) {
        return result;
    }
    const auto length = message.kind == Kind::Hello ? 0U : heartbeat_body_size;
    auto bytes = std::span{result.bytes};
    std::copy(magic.begin(), magic.end(), bytes.begin());
    bytes[4] = std::byte{major_version};
    bytes[5] = std::byte{minor_version};
    bytes[6] = static_cast<std::byte>(message.kind);
    write_be(bytes.subspan(8, 4), length);
    write_be(bytes.subspan(12, 8), message.sequence);
    if (message.kind == Kind::Heartbeat) {
        write_be(bytes.subspan(header_size, 8), message.uptime_ms);
        write_be(bytes.subspan(header_size + 8, 8), message.dropped_records);
    }
    result.error = Error::None;
    result.size = header_size + length;
    return result;
}

Decoded decode(std::span<const std::byte> frame) noexcept {
    if (frame.size() > max_frame_size) { return {Error::Oversize, {}}; }
    if (frame.size() < header_size) { return {Error::Truncated, {}}; }
    const auto header = inspect_header(frame.first(header_size));
    if (header.error != Error::None) { return {header.error, {}}; }
    if (frame.size() < header.frame_size) { return {Error::Truncated, {}}; }
    if (frame.size() != header.frame_size) { return {Error::InvalidLength, {}}; }
    Message message{static_cast<Kind>(std::to_integer<std::uint8_t>(frame[6])),
                    read_be(frame.subspan(12, 8)), 0, 0};
    if (message.kind == Kind::Heartbeat) {
        message.uptime_ms = read_be(frame.subspan(header_size, 8));
        message.dropped_records = read_be(frame.subspan(header_size + 8, 8));
    }
    return {Error::None, message};
}

Decoded SessionValidator::accept(std::span<const std::byte> frame) noexcept {
    if (closed_) { return {Error::SessionClosed, {}}; }
    const auto reject = [this](Error error) noexcept -> Decoded {
        close();
        return {error, {}};
    };
    const auto decoded = decode(frame);
    if (decoded.error != Error::None) { return reject(decoded.error); }
    const auto& message = decoded.message;
    if (last_sequence_ == std::numeric_limits<std::uint64_t>::max() ||
        message.sequence != last_sequence_ + 1U) {
        return reject(Error::InvalidSequence);
    }
    if (message.kind != (last_sequence_ == 0 ? Kind::Hello : Kind::Heartbeat)) {
        return reject(Error::UnexpectedMessage);
    }
    if (message.uptime_ms < uptime_ms_ || message.dropped_records < dropped_records_) {
        return reject(Error::CounterRegression);
    }
    last_sequence_ = message.sequence;
    uptime_ms_ = message.uptime_ms;
    dropped_records_ = message.dropped_records;
    if (last_sequence_ == std::numeric_limits<std::uint64_t>::max()) { close(); }
    return decoded;
}

} // namespace knetsentry::core::agent_protocol
