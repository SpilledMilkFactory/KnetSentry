// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/service/lifecycle.hpp"

namespace knetsentry::service {

bool Lifecycle::begin_start() noexcept {
    if (state_ != State::Created) return false;
    state_ = State::Starting;
    return true;
}

bool Lifecycle::mark_ready() noexcept {
    if (state_ != State::Starting) return false;
    state_ = State::Running;
    return true;
}

bool Lifecycle::request_stop() noexcept {
    // An early operator stop is valid while startup is still in progress.
    if (state_ != State::Starting && state_ != State::Running) return false;
    state_ = State::Stopping;
    return true;
}

bool Lifecycle::complete_stop() noexcept {
    if (state_ != State::Stopping) return false;
    state_ = State::Stopped;
    return true;
}

bool Lifecycle::mark_failed() noexcept {
    if (state_ == State::Stopped || state_ == State::Failed) return false;
    state_ = State::Failed;
    return true;
}

} // namespace knetsentry::service
