// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once

#include <cstdint>

namespace knetsentry::service {

// Single-thread-owned manager lifecycle. All changes are explicit; this is
// not a concurrent scheduler or a privileged service controller.
enum class State : std::uint8_t {
    Created, Starting, Running, Stopping, Stopped, Failed
};

class Lifecycle final {
public:
    [[nodiscard]] State state() const noexcept { return state_; }
    [[nodiscard]] bool begin_start() noexcept;
    [[nodiscard]] bool mark_ready() noexcept;
    [[nodiscard]] bool request_stop() noexcept;
    [[nodiscard]] bool complete_stop() noexcept;
    [[nodiscard]] bool mark_failed() noexcept;

private:
    State state_{State::Created};
};

} // namespace knetsentry::service
