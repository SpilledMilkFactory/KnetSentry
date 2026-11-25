// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/service/health_client.hpp"
#include "knetsentry/service/local_ipc.hpp"

#include <array>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

using namespace knetsentry::service;
namespace enrollment = knetsentry::enrollment;

int main(int argc, char** argv) {
    constexpr std::string_view id = "0123456789abcdef";
    if (argc == 2) {
        HealthClient client;
        client.begin_agents(argv[1], id);
        while (client.state() == HealthQueryState::Pending) {
            client.advance();
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        if (!client.roster()) {
            std::cout << (client.state() == HealthQueryState::Invalid ? "invalid" : "unavailable") << '\n';
            return client.snapshot() ? 1 : 0;
        }
        std::array<char, max_roster_response_size> bytes{};
        const auto size = encode_roster(*client.roster(), id, bytes);
        if (size == 0 || client.snapshot()) { return 1; }
        std::cout.write(bytes.data(), static_cast<std::streamsize>(size));
        client.cancel();
        return client.roster() ? 1 : 0;
    }
    if (argc != 1) { return 1; }
    if (!authorize_local_peer(1000, 1000, 1000, 1000, IpcAction::Agents) ||
        authorize_local_peer(1001, 1000, 1000, 1000, IpcAction::Agents) ||
        authorize_local_peer(1000, 1001, 1000, 1000, IpcAction::Agents) ||
        authorize_local_peer(1000, 1000, 1000, 1000, IpcAction::Administrative)) { return 1; }
    enrollment::Roster roster{};
    roster.status = enrollment::Status::Ok;
    roster.size = enrollment::max_endpoints;
    for (std::size_t i = 0; i < roster.size; ++i) {
        roster.entries.at(i).id.front() = static_cast<unsigned char>(i + 1U);
        roster.entries.at(i).approved = i % 2 == 0;
    }
    std::array<char, max_roster_response_size> bytes{};
    const auto size = encode_roster(roster, id, bytes);
    if (size == 0 || size > bytes.size()) { return 1; }
    const std::string wire(bytes.data(), size);
    const auto decoded = decode_roster(wire, id);
    if (!decoded || decoded->status != enrollment::Status::Ok || decoded->size != roster.size) { return 1; }
    for (std::size_t i = 0; i < roster.size; ++i) {
        if (decoded->entries.at(i).id != roster.entries.at(i).id ||
            decoded->entries.at(i).approved != roster.entries.at(i).approved) { return 1; }
    }
    const std::string start = "KSIPC/1 OK 0123456789abcdef AGENTS READY\n";
    const std::string row = "A 01010101010101010101010101010101\n";
    const auto empty = decode_roster(start, id);
    const auto unavailable = decode_roster("KSIPC/1 OK 0123456789abcdef AGENTS UNAVAILABLE\n", id);
    if (!empty || empty->status != enrollment::Status::Ok || empty->size != 0 ||
        !unavailable || unavailable->status == enrollment::Status::Ok || unavailable->size != 0) { return 1; }
    for (const auto& invalid : {start + row + row, start + "A 00000000000000000000000000000000\n",
        start + "X 01010101010101010101010101010101\n", start + "A 0101010101010101010101010101010F\n",
        start + row + "x", wire + row, wire.substr(0, wire.size() - 1),
        std::string("KSIPC/1 OK 0123456789abcdef AGENTS UNAVAILABLE\n") + row}) {
        if (decode_roster(invalid, id)) { return 1; }
    }
    if (decode_roster(wire, "fedcba9876543210") ||
        encode_roster(roster, id, std::span<char>(bytes).first(1)) != 0) { return 1; }
    roster.entries.at(1).id = roster.entries.front().id;
    if (encode_roster(roster, id, bytes) != 0) { return 1; }
    std::cout << "M4.7 bounded roster codec, unique identities and read-only authorization: PASS\n";
    return 0;
}
