// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/core/build_info.hpp"
#include "knetsentry/core/diagnostics.hpp"

#include <cstdint>
#include <iostream>
#include <limits>
#include <sstream>
#include <string>

int main() {
    using namespace knetsentry::core;
    // This is a true executable unit test: checks remain active in Release
    // (no assert(), which disappears under NDEBUG).
    if (product_name() != "KnetSentry" || project_version().empty()) {
        std::cerr << "Invalid core identity\n";
        return 1;
    }
    std::ostringstream first;
    DiagnosticLogger logger(first);
    const std::string secret = "NOT_FOR_PUBLIC_OUTPUT_M17\nAuthorization: bearer token";
    if (!logger.write({DiagnosticLevel::Warning, DiagnosticComponent::Verification,
                       DiagnosticEvent::VerificationRejected, DiagnosticOutcome::Rejected,
                       std::numeric_limits<std::uint64_t>::max(), SensitiveContext{secret}}) ||
        !logger.write({DiagnosticLevel::Info, DiagnosticComponent::Core,
                       DiagnosticEvent::SelfTest, DiagnosticOutcome::Success})) {
        std::cerr << "Valid core diagnostic record rejected\n";
        return 1;
    }
    const std::string serialized = first.str();
    if (serialized.find(secret) != std::string::npos ||
        serialized.find("NOT_FOR_PUBLIC_OUTPUT_M17") != std::string::npos ||
        serialized.find("[REDACTED]") == std::string::npos ||
        serialized.find("18446744073709551615") == std::string::npos ||
        serialized.find("\"sequence\":1") == std::string::npos ||
        serialized.find("\"sequence\":2") == std::string::npos) {
        std::cerr << "Private metadata, unsigned boundary, or ordering contract failed\n";
        return 1;
    }
    std::ostringstream second;
    DiagnosticLogger another(second);
    if (!another.write({DiagnosticLevel::Info, DiagnosticComponent::Core,
                        DiagnosticEvent::SelfTest, DiagnosticOutcome::Success}) ||
        second.str().find("\"sequence\":1") == std::string::npos) {
        std::cerr << "Independent logger sequence contract failed\n";
        return 1;
    }
    if (logger.write({DiagnosticLevel::Info, DiagnosticComponent::Core,
                      static_cast<DiagnosticEvent>(255), DiagnosticOutcome::Rejected})) {
        std::cerr << "Unapproved enum value accepted\n";
        return 1;
    }
    if (first.str() != serialized) {
        std::cerr << "Invalid event altered approved record output\n";
        return 1;
    }
    return 0;
}
