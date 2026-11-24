// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/service/health_client.hpp"

#include <chrono>
#include <iostream>
#include <limits>
#include <string>
#include <thread>

using namespace knetsentry::service;

int main(int argc, char* argv[]) {
    constexpr std::string_view id = "0123456789abcdef";
    if (argc == 2) {
        HealthClient client;
        client.begin(argv[1], id);
        while (client.state() == HealthQueryState::Pending) {
            client.advance();
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        if (client.state() == HealthQueryState::Available && client.snapshot()) {
            const auto& value = *client.snapshot();
            std::cout << "available " << value.uptime_ms << ' ' << value.explicit_config << '\n';
        } else {
            if (client.snapshot()) { return 1; }
            std::cout << (client.state() == HealthQueryState::Invalid ? "invalid" : "unavailable") << '\n';
        }
        return 0;
    }
    if (argc != 1) { return 1; }
    const std::string valid = "KSIPC/1 OK 0123456789abcdef HEALTH RUNNING 42 0 123 CONFIG_DEFAULT IPC_READY MONITORING_UNAVAILABLE 1 2 3\n";
    const auto snapshot = decode_health(valid, id);
    if (!snapshot || snapshot->uptime_ms != 42 || snapshot->usage.cpu_ms != 0 ||
        snapshot->usage.peak_rss_kib != 123 || snapshot->explicit_config ||
        snapshot->rejected != 1 || snapshot->transport_errors != 2 || snapshot->sampling_errors != 3) { return 1; }
    auto changed = [&](std::string_view from, std::string_view to) {
        auto text = valid;
        text.replace(text.find(from), from.size(), to);
        return text;
    };
    const auto unavailable = decode_health(changed("0 123", "NA NA"), id);
    if (!unavailable || unavailable->usage.cpu_ms || unavailable->usage.peak_rss_kib) { return 1; }
    const auto maximum = decode_health(changed("42", "18446744073709551615"), id);
    if (!maximum || maximum->uptime_ms != std::numeric_limits<std::uint64_t>::max()) { return 1; }
    for (const auto& bad : {changed("42", "18446744073709551616"), changed("42", "-1"),
        changed("42", "+1"), changed("42", "042"), changed("42", "NA"),
        changed("42", "4\t2"), changed("42", " 42"), changed(" 123 ", " 0 "),
        changed("RUNNING", "STOPPED"), changed("MONITORING_UNAVAILABLE", "MONITORING_READY"),
        changed("CONFIG_DEFAULT", "CONFIG_UNKNOWN"), changed("IPC_READY", "IPC_UNKNOWN"),
        changed("KSIPC/1", "KSIPC/2"), changed("HEALTH", "STATUS"), valid + "x", valid + "\n",
        valid.substr(0, valid.size() - 1), std::string(257, 'x')}) {
        if (decode_health(bad, id)) { std::cerr << "Invalid health accepted\n"; return 1; }
    }
    if (decode_health(valid, "fedcba9876543210") || decode_health(valid, "invalid")) { return 1; }
    HealthClient client;
    client.begin("relative", id);
    if (client.state() != HealthQueryState::Unavailable || client.snapshot()) { return 1; }
    client.cancel();
    if (client.state() != HealthQueryState::Idle) { return 1; }
    std::cout << "M2.6 client parser contract: PASS\n";
    return 0;
}
