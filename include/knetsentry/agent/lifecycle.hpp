// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <array>
#include <cstddef>
#include <span>
#include <string_view>

namespace knetsentry::agent {
[[nodiscard]] bool valid_configuration(std::span<const std::string_view> args) noexcept;
// Trusted static modules only; stop must be safe after partial startup.
class Collector {
public:
    virtual ~Collector() = default;
    [[nodiscard]] virtual bool start() noexcept = 0;
    virtual void stop() noexcept = 0;
};
enum class State { Idle, Running, Stopped, Failed };
class Lifecycle final {
public:
    static constexpr std::size_t max_collectors = 8;
    Lifecycle() = default;
    ~Lifecycle() { stop(); }
    Lifecycle(const Lifecycle&) = delete;
    Lifecycle& operator=(const Lifecycle&) = delete;
    // Borrowed modules must outlive this lifecycle. No restart after termination.
    [[nodiscard]] bool start(std::span<Collector* const> modules) noexcept;
    void stop() noexcept;
    [[nodiscard]] State state() const noexcept { return state_; }
private:
    void unwind() noexcept;
    std::array<Collector*, max_collectors> active_{};
    std::size_t count_{};
    State state_{State::Idle};
};
} // namespace knetsentry::agent
