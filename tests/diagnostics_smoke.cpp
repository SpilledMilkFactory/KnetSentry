// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/core/diagnostics.hpp"

#include <array>
#include <cstdint>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

int main() {
    using namespace knetsentry::core;
    std::ostringstream capture;
    DiagnosticLogger logger(capture);
    std::string sensitive(8192, 'S');
    sensitive += "\npassword=TOPSECRET_42\r\nAuthorization: Bearer SECRET_M16_TOKEN"
                 "\"},{\"unsafe\":true";
    // An extremely long, injection-shaped secret is represented ONLY by a
    // constant marker; the logger must not scan or print any of its bytes.
    if (!logger.write({DiagnosticLevel::Warning, DiagnosticComponent::Verification,
                       DiagnosticEvent::VerificationRejected, DiagnosticOutcome::Rejected,
                       0U, SensitiveContext{sensitive}})) {
        return 1;
    }
    if (!logger.write({DiagnosticLevel::Info, DiagnosticComponent::Core,
                       DiagnosticEvent::SelfTest, DiagnosticOutcome::Success,
                       std::numeric_limits<std::uint64_t>::max(), std::nullopt})) {
        return 2;
    }
    if (!logger.write({DiagnosticLevel::Debug, DiagnosticComponent::Desktop,
                       DiagnosticEvent::GuiStarting, DiagnosticOutcome::Started})) {
        return 3;
    }
    constexpr int threads = 4;
    constexpr int records_per_thread = 32;
    std::array<std::thread, threads> workers;
    std::array<bool, threads> completed{};
    for (int worker = 0; worker < threads; ++worker) {
        workers[static_cast<std::size_t>(worker)] = std::thread([&logger, &completed, worker]() {
            bool ok = true;
            for (int i = 0; i < records_per_thread; ++i) {
                ok = logger.write({DiagnosticLevel::Info, DiagnosticComponent::Verification,
                                   DiagnosticEvent::SelfTest, DiagnosticOutcome::Success,
                                   static_cast<std::uint64_t>(i)}) && ok;
            }
            completed[static_cast<std::size_t>(worker)] = ok;
        });
    }
    for (auto& thread : workers) {
        thread.join();
    }
    for (const bool ok : completed) {
        if (!ok) { return 4; }
    }
    // Failed sinks must be observable without logging untrusted exception text.
    std::ostringstream broken;
    broken.setstate(std::ios::badbit);
    DiagnosticLogger broken_logger(broken);
    if (broken_logger.write({})) { return 5; }
    // An invalid enum cannot become a misleading diagnostic record.
    if (logger.write({DiagnosticLevel::Info, DiagnosticComponent::Core,
                      static_cast<DiagnosticEvent>(255), DiagnosticOutcome::Rejected})) {
        return 8;
    }
    // No sensitive source bytes may be forwarded to stdout as part of the
    // test protocol (the verifier checks JSON and known secret sentinels).
    const std::string result = capture.str();
    if (result.find("TOPSECRET_42") != std::string::npos ||
        result.find("SECRET_M16_TOKEN") != std::string::npos ||
        result.find("Authorization") != std::string::npos ||
        result.find("[REDACTED]") == std::string::npos) {
        return 6;
    }
    std::cout << result;
    return std::cout.good() ? 0 : 7;
}
