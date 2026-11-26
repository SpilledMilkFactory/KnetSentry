// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/agent/telemetry_status.hpp"
#include <iostream>
#include <string>
#include <thread>

namespace {
using namespace knetsentry::agent;
constexpr auto valid = "KSSTAT1\tjournal\tactive\t100\t2\t1000\t12";
bool send(int fd, std::string_view bytes) {
    return ::write(fd, bytes.data(), bytes.size()) == static_cast<ssize_t>(bytes.size());
}
bool contract() {
    const auto parsed = parse_status(valid);
    if (!parsed || parsed->mode != "journal" || parsed->observations != 2 || parsed->queued != 12) { return false; }
    for (const std::string_view bad : {
        "KSSTAT2\tjournal\tactive\t100\t2\t1000\t12", "KSSTAT1\tsecret\tactive\t100\t2\t1000\t12",
        "KSSTAT1\tjournal\tactive\t100\t17\t1000\t12", "KSSTAT1\tjournal\tactive\t100\t2\t0\t12",
        "KSSTAT1\tjournal\tpaused\t100\t0\t0\t127", "KSSTAT1\tjournal\tblocked\t100\t0\t0\t-",
        "KSSTAT1\tfim\tactive\t100\t0\t0\t1", "KSSTAT1\tjournal\tactive\t100\t0\t60001\t0",
        "KSSTAT1\tjournal\tactive\t0100\t0\t0\t-", "KSSTAT1\tjournal\tactive\t100\t0\t0\t129", "KSSTAT1\tjournal\tactive\t100\t0\t0\t128",
        "KSSTAT1\tjournal\tsource-failed\t100\t0\t0\t12",
        "KSSTAT1\tjournal\tactive\t18446744073709551616\t0\t0\t-", "KSSTAT1\tnone\tactive\t100\t0\t0\t-",
        "KSSTAT1\tjournal\tactive\t100\t0\t0\t-\tprivate", "KSSTAT1\tjournal\tfailed\t100\t0\t1000\t-"}) {
        if (parse_status(bad)) { return false; }
    }
    for (const std::string_view good : {"KSSTAT1\tnone\tidle\t100\t0\t0\t-",
        "KSSTAT1\tauthentication\tpaused\t100\t0\t0\t128", "KSSTAT1\taudit\tblocked\t100\t0\t0\t4",
        "KSSTAT1\tfim-metadata\tactive\t100\t8\t1000\t-", "KSSTAT1\tfim\tfailed\t100\t0\t0\t-",
        "KSSTAT1\tjournal\tsource-failed\t100\t0\t0\t-"}) {
        if (!parse_status(good)) { return false; }
    }
    return true;
}
bool stream_contract() {
    std::array<int, 2> fds{};
    if (::pipe2(fds.data(), O_CLOEXEC) != 0) { return false; }
    StatusReader reader;
    if (!reader.attach(fds[0])) { return false; }
    ::close(fds[0]);
    const auto line = std::string("KSSTAT1\tfim\tactive\t") + std::to_string(status_now()) + "\t1\t1000\t-\n";
    if (!send(fds[1], std::string_view(line).substr(0, 8)) || reader.poll() || reader.current() ||
        !send(fds[1], std::string_view(line).substr(8)) || !reader.poll() || !reader.current() ||
        reader.current()->observations != 1) { return false; }
    // A replay invalidates the stream rather than preserving a misleading sample.
    if (!send(fds[1], line) || !reader.poll() || reader.current() || reader.link() != StatusLink::Invalid) { return false; }
    ::close(fds[1]);
    if (::pipe2(fds.data(), O_CLOEXEC) != 0) { return false; }
    StatusReader second;
    if (!second.attach(fds[0])) { return false; }
    ::close(fds[0]);
    StatusWriter writer;
    if (!writer.attach(fds[1])) { return false; }
    writer.publish("audit", "blocked", 0, 3);
    if (!second.poll() || !second.current() || !second.last_failure()) { return false; }
    std::this_thread::sleep_for(std::chrono::milliseconds(status_fresh_ms + 20));
    if (!second.poll() || second.current() || second.link() != StatusLink::Stale) { return false; }
    writer.publish("audit", "active", 2, 5);
    if (!second.poll() || !second.current() || second.current()->observations != 2 || second.last_failure()) { return false; }
    return true;
}
bool disconnect_contract() {
    std::array<int, 2> fds{};
    if (::pipe2(fds.data(), O_CLOEXEC) != 0) { return false; }
    StatusReader reader;
    if (!reader.attach(fds[0])) { return false; }
    ::close(fds[0]);
    const auto line = std::string("KSSTAT1\tfim\tfailed\t") + std::to_string(status_now()) + "\t0\t0\t-\n";
    if (!send(fds[1], line) || !reader.poll() || !reader.current()) { return false; }
    ::close(fds[1]);
    if (!reader.poll() || reader.current() || reader.link() != StatusLink::Disconnected || !reader.last_failure()) { return false; }
    if (::pipe2(fds.data(), O_CLOEXEC) != 0) { return false; }
    StatusReader oversized;
    if (!oversized.attach(fds[0])) { return false; }
    ::close(fds[0]);
    if (!send(fds[1], std::string(status_max_line + 1, 'x')) || !oversized.poll() || oversized.current() ||
        oversized.link() != StatusLink::Invalid) { return false; }
    ::close(fds[1]);
    return true;
}
bool pressure_contract() {
    std::array<int, 2> fds{};
    if (::pipe2(fds.data(), O_CLOEXEC) != 0) { return false; }
    StatusWriter writer;
    if (!writer.attach(fds[1]) || !status_pipe(fds[0], O_RDONLY)) { return false; }
    std::array<char, 4096> bytes{};
    while (::write(fds[1], bytes.data(), bytes.size()) > 0) {}
    if (errno != EAGAIN) { return false; }
    // Saturated observer must not block the producer (CTest also bounds runtime).
    writer.publish("none", "idle");
    while (::read(fds[0], bytes.data(), bytes.size()) > 0) {}
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
    writer.publish("none", "idle");
    const auto n = ::read(fds[0], bytes.data(), bytes.size());
    if (n <= 1 || bytes.at(static_cast<std::size_t>(n) - 1) != '\n') { return false; }
    const auto sample = parse_status(std::string_view(bytes.data(), static_cast<std::size_t>(n) - 1));
    ::close(fds[0]);
    return sample && sample->mode == "none" && sample->health == "idle";
}
} // namespace
int main() {
    if (!contract() || !stream_contract() || !disconnect_contract() || !pressure_contract()) {
        std::cerr << "M5.9 status stream contract: FAIL\n";
        return 1;
    }
    std::cout << "M5.9 bounded status parsing, partial reads, replay rejection, expiry, recovery, disconnect and pipe pressure: PASS\n";
    return 0;
}
