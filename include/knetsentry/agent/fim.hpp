// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include "knetsentry/agent/lifecycle.hpp"
#include <memory>
#include <string>
#include <vector>

namespace knetsentry::agent {
inline constexpr std::size_t max_fim_paths = 8;
inline constexpr std::size_t max_fim_bytes = 1024 * 1024;
[[nodiscard]] bool valid_fim_path(std::string_view path) noexcept;
enum class IntegrityChange { None, Created, Deleted, Replaced, Content, Metadata };
[[nodiscard]] std::string_view change_name(IntegrityChange change) noexcept;
class IntegrityCollector final : public Collector {
public:
    explicit IntegrityCollector(std::vector<std::string> paths);
    ~IntegrityCollector() override;
    IntegrityCollector(const IntegrityCollector&) = delete;
    IntegrityCollector& operator=(const IntegrityCollector&) = delete;
    [[nodiscard]] bool start() noexcept override;
    void stop() noexcept override;
    // Fixed slot indices, never paths, contents, or fingerprints.
    [[nodiscard]] bool pump(std::array<IntegrityChange, max_fim_paths>& changes) noexcept;
private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
} // namespace knetsentry::agent
