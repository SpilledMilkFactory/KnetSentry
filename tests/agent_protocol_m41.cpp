// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/core/agent_protocol.hpp"

#include <algorithm>
#include <array>
#include <iostream>
#include <limits>
#include <string_view>

namespace {
using namespace knetsentry::core::agent_protocol;
int failures{};
void check(bool condition, std::string_view label) {
    if (!condition) { std::cerr << "M4.1 FAIL: " << label << '\n'; ++failures; }
}
std::span<const std::byte> wire(const Encoded& encoded) {
    return std::span{encoded.bytes}.first(encoded.size);
}
Decoded accept(SessionValidator& session, const Message& message) {
    const auto encoded = encode(message);
    check(encoded.error == Error::None, "session fixture encoded");
    return session.accept(wire(encoded));
}
void expect_error(std::span<const std::byte> frame, Error expected) {
    const auto result = decode(frame);
    check(result.error == expected && result.message == Message{}, "exact rejection and cleared output");
}
void sequence_failure(const Message& next, Error expected) {
    SessionValidator session;
    check(accept(session, {Kind::Hello, 1}).error == Error::None, "hello first");
    check(accept(session, {Kind::Heartbeat, 2, 100, 3}).error == Error::None, "heartbeat first");
    check(accept(session, next).error == expected && session.closed(), "sticky sequence/payload denial");
    check(accept(session, {Kind::Heartbeat, 3, 101, 4}).error == Error::SessionClosed,
          "no resynchronization after rejection");
}
} // namespace

int main() {
    using namespace knetsentry::core::agent_protocol;
    constexpr std::array<unsigned char, 20> hello_golden{
        0x4b, 0x53, 0x41, 0x50, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    constexpr std::array<unsigned char, 36> heartbeat_golden{
        0x4b, 0x53, 0x41, 0x50, 1, 0, 2, 0, 0, 0, 0, 16, 0, 0, 0, 0, 0, 0, 0, 2,
        1, 2, 3, 4, 5, 6, 7, 8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8};
    const Message hello{Kind::Hello, 1};
    const Message heartbeat{Kind::Heartbeat, 2, 0x0102030405060708ULL, 0xf1f2f3f4f5f6f7f8ULL};
    const auto h = encode(hello);
    const auto b = encode(heartbeat);
    const auto golden_matches = [](const auto& golden, const Encoded& encoded) {
        return encoded.error == Error::None && encoded.size == golden.size() &&
            std::equal(golden.begin(), golden.end(), encoded.bytes.begin(),
                       [](auto left, std::byte right) { return std::byte{left} == right; });
    };
    check(golden_matches(hello_golden, h), "hello golden bytes");
    check(golden_matches(heartbeat_golden, b), "heartbeat golden bytes");
    std::array<std::byte, heartbeat_golden.size()> independent{};
    std::transform(heartbeat_golden.begin(), heartbeat_golden.end(), independent.begin(),
                   [](auto value) { return std::byte{value}; });
    const auto decoded = decode(independent);
    check(decoded.error == Error::None && decoded.message == heartbeat, "independent golden decode");
    check(decode(wire(h)).message == hello, "hello round trip");
    check(inspect_header(wire(h)).frame_size == header_size, "hello header bound");
    check(inspect_header(wire(b).first(header_size)).frame_size == max_frame_size, "heartbeat header bound");
    for (std::size_t size = 0; size < b.size; ++size) {
        expect_error(wire(b).first(size), Error::Truncated);
    }
    for (std::size_t size = 0; size < header_size; ++size) {
        const auto result = inspect_header(wire(h).first(size));
        check(result.error == Error::Truncated && result.frame_size == 0, "partial header denied");
    }
    check(inspect_header(wire(b)).error == Error::InvalidLength, "header requires exact size");
    expect_error(std::span{h.bytes}.first(header_size + 1), Error::InvalidLength);
    std::array<std::byte, max_frame_size + 1> extra{};
    std::copy(b.bytes.begin(), b.bytes.end(), extra.begin());
    expect_error(extra, Error::Oversize);
    const auto mutate = [&](std::size_t offset, std::byte value, Error error) {
        auto changed = b.bytes;
        changed[offset] = value;
        const auto result = inspect_header(std::span{changed}.first(header_size));
        check(result.error == error && result.frame_size == 0, "header rejection before body");
        expect_error(changed, error);
    };
    for (std::size_t offset = 0; offset < 4; ++offset) { mutate(offset, std::byte{}, Error::BadMagic); }
    for (unsigned value = 0; value < 256; ++value) {
        const auto byte = static_cast<std::byte>(value);
        if (value != 1) { mutate(4, byte, Error::UnsupportedVersion); }
        if (value != 0) {
            mutate(5, byte, Error::UnsupportedVersion);
            mutate(7, byte, Error::ReservedFlags);
        }
        if (value != 1 && value != 2) { mutate(6, byte, Error::UnsupportedKind); }
        if (value < 16) { mutate(11, byte, Error::InvalidLength); }
        if (value > 16) { mutate(11, byte, Error::Oversize); }
    }
    for (std::size_t offset = 8; offset < 11; ++offset) { mutate(offset, std::byte{0xff}, Error::Oversize); }
    mutate(19, std::byte{}, Error::InvalidSequence);
    mutate(6, std::byte{1}, Error::InvalidLength);
    for (const auto message : {Message{Kind::Hello, 0}, Message{Kind::Hello, 1, 1, 0},
                               Message{Kind::Hello, 1, 0, 1}, Message{static_cast<Kind>(255), 1}}) {
        const auto result = encode(message);
        check(result.error != Error::None && result.size == 0 &&
              std::all_of(result.bytes.begin(), result.bytes.end(), [](auto v) { return v == std::byte{}; }),
              "invalid encoder input leaves no bytes");
    }
    const auto max = std::numeric_limits<std::uint64_t>::max();
    const Message limit{Kind::Heartbeat, max, max, max};
    const auto limit_encoded = encode(limit);
    check(decode(wire(limit_encoded)).message == limit, "uint64 maximum round trip");
    SessionValidator good;
    check(accept(good, hello).error == Error::None, "valid hello");
    check(accept(good, {Kind::Heartbeat, 2, 0, 0}).error == Error::None, "zero counters");
    check(accept(good, {Kind::Heartbeat, 3, max, max}).error == Error::None, "maximum counters");
    check(accept(good, {Kind::Heartbeat, 4, max, max}).error == Error::None, "unchanged counters");
    good.close();
    check(accept(good, {Kind::Heartbeat, 5, max, max}).error == Error::SessionClosed, "explicit closure");
    sequence_failure({Kind::Heartbeat, 2, 100, 3}, Error::InvalidSequence);
    sequence_failure({Kind::Heartbeat, 1, 100, 3}, Error::InvalidSequence);
    sequence_failure({Kind::Heartbeat, 4, 100, 3}, Error::InvalidSequence);
    sequence_failure({Kind::Heartbeat, max, 100, 3}, Error::InvalidSequence);
    sequence_failure({Kind::Hello, 3}, Error::UnexpectedMessage);
    sequence_failure({Kind::Heartbeat, 3, 99, 3}, Error::CounterRegression);
    sequence_failure({Kind::Heartbeat, 3, 100, 2}, Error::CounterRegression);
    SessionValidator no_hello;
    check(accept(no_hello, {Kind::Heartbeat, 1}).error == Error::UnexpectedMessage && no_hello.closed(),
          "heartbeat cannot start session");
    SessionValidator wrong_start;
    check(accept(wrong_start, {Kind::Hello, 2}).error == Error::InvalidSequence && wrong_start.closed(),
          "sequence must start at one");
    SessionValidator malformed;
    check(malformed.accept(wire(h).first(1)).error == Error::Truncated && malformed.closed(),
          "incomplete frame closes validator");
    check(malformed.accept(wire(h)).error == Error::SessionClosed, "malformed cannot recover");
    SessionValidator fresh;
    check(accept(fresh, hello).error == Error::None, "fresh connection has independent ordering only");
    if (failures != 0) { return 1; }
    std::cout << "M4.1 agent protocol golden wire, bounded framing and session rejection: PASS\n";
    return 0;
}
