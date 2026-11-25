// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/agent/lifecycle.hpp"

namespace knetsentry::agent {
bool valid_configuration(std::span<const std::string_view> args) noexcept {
    return args.size() == 4 && args[0] == "--schema-version" && args[1] == "1" &&
        args[2] == "--collectors" && args[3] == "none";
}
bool Lifecycle::start(std::span<Collector* const> modules) noexcept {
    if (state_ != State::Idle) { return false; }
    if (modules.size() > max_collectors) { state_ = State::Failed; return false; }
    for (std::size_t i = 0; i < modules.size(); ++i) {
        if (modules[i] == nullptr) { state_ = State::Failed; return false; }
        for (std::size_t j = 0; j < i; ++j) {
            if (modules[i] == modules[j]) { state_ = State::Failed; return false; }
        }
    }
    for (auto* module : modules) {
        active_[count_++] = module;
        if (!module->start()) {
            unwind();
            state_ = State::Failed;
            return false;
        }
    }
    state_ = State::Running;
    return true;
}
void Lifecycle::unwind() noexcept {
    while (count_ != 0) {
        auto* module = active_[--count_];
        active_[count_] = nullptr;
        module->stop();
    }
}
void Lifecycle::stop() noexcept {
    if (state_ == State::Running || state_ == State::Idle) {
        unwind();
        state_ = State::Stopped;
    }
}
} // namespace knetsentry::agent
