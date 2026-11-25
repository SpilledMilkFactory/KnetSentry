// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/agent/lifecycle.hpp"
#include <array>
#include <iostream>

namespace {
using namespace knetsentry::agent;
struct Trace { std::array<int, 16> events{}; std::size_t size{}; };
class Module final : public Collector {
public:
    Module(Trace& trace, int id, bool success = true) : trace_(trace), id_(id), success_(success) {}
    bool start() noexcept override { trace_.events.at(trace_.size++) = id_; return success_; }
    void stop() noexcept override { trace_.events.at(trace_.size++) = -id_; }
private:
    Trace& trace_;
    int id_;
    bool success_;
};
}
int main() {
    using namespace knetsentry::agent;
    const std::array<std::string_view, 4> good{"--schema-version", "1", "--collectors", "none"};
    auto bad = good;
    bad[3] = "all";
    if (!valid_configuration(good) || valid_configuration(bad) || valid_configuration({})) { return 1; }
    Trace trace;
    Module first(trace, 1), second(trace, 2), failing(trace, 3, false);
    const std::array<Collector*, 2> modules{&first, &second};
    {
        Lifecycle lifecycle;
        if (!lifecycle.start(modules) || lifecycle.state() != State::Running || lifecycle.start(modules)) { return 2; }
    }
    if (trace.size != 4 || trace.events[0] != 1 || trace.events[1] != 2 ||
        trace.events[2] != -2 || trace.events[3] != -1) { return 3; }
    trace = {};
    const std::array<Collector*, 3> failure{&first, &failing, &second};
    Lifecycle lifecycle;
    if (lifecycle.start(failure) || lifecycle.state() != State::Failed || lifecycle.start(modules)) { return 4; }
    lifecycle.stop();
    if (trace.size != 4 || trace.events[0] != 1 || trace.events[1] != 3 ||
        trace.events[2] != -3 || trace.events[3] != -1) { return 5; }
    trace = {};
    const std::array<Collector*, 2> duplicate{&first, &first}, null_module{&first, nullptr};
    const std::array<Collector*, Lifecycle::max_collectors + 1> oversized{};
    for (const auto invalid : {std::span<Collector* const>(duplicate),
                              std::span<Collector* const>(null_module),
                              std::span<Collector* const>(oversized)}) {
        Lifecycle rejected;
        if (rejected.start(invalid) || rejected.state() != State::Failed || trace.size != 0) { return 6; }
    }
    Lifecycle empty;
    if (!empty.start({})) { return 7; }
    empty.stop();
    empty.stop();
    if (empty.state() != State::Stopped || empty.start({})) { return 8; }
    std::cout << "M5.1 collector lifecycle, rollback, bounded registration and configuration: PASS\n";
}
