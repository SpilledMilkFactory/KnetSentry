// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <knetsentry/agent/journal.hpp>
#include <optional>

namespace knetsentry::agent {
// Internal OCSF-aligned subset, not a complete OCSF serialization contract.
enum class OcsfClass : std::uint32_t { Base = 0, Authentication = 3002 };
enum class OcsfActivity : std::uint32_t { Unknown = 0, Logon = 1, Logoff = 2 };
enum class OcsfStatus : std::uint32_t { Unknown = 0, Success = 1, Failure = 2 };
enum class OcsfSeverity : std::uint32_t { Unknown = 0 };
enum class MappingResult { Classified, MetadataOnly, AuditTypeUnmapped, Redacted, Unclassified };
struct NormalizedEvent {
    static constexpr std::string_view schema_version = "1.4.0";
    static constexpr std::uint32_t mapping_revision = 1;
    OcsfClass class_uid{OcsfClass::Base};
    OcsfActivity activity_id{OcsfActivity::Unknown};
    OcsfStatus status_id{OcsfStatus::Unknown};
    OcsfSeverity severity_id{OcsfSeverity::Unknown};
    MappingResult mapping{MappingResult::MetadataOnly};
    std::uint64_t time_ms{}; // Source journal realtime, not manager arrival time.
    JournalMode source_mode{JournalMode::Metadata};
    // Trusted configuration, not source-reported machine identity or a credential.
    std::string destination_binding;
    JournalRecord source;
    std::string canonical_row; // Exact minimized original, not a raw journal message.
    [[nodiscard]] std::uint32_t category_uid() const noexcept {
        return class_uid == OcsfClass::Authentication ? 3U : 0U;
    }
    [[nodiscard]] std::uint32_t type_uid() const noexcept {
        return static_cast<std::uint32_t>(class_uid) * 100U + static_cast<std::uint32_t>(activity_id);
    }
};
// Pure mapping. The caller must establish authorization/identity and choose the
// binding and exact source independently of the row. No authentication here.
// Invalid input returns nullopt; allocation failure propagates to the caller.
[[nodiscard]] std::optional<NormalizedEvent> normalize_event(std::string_view canonical_row,
    std::string_view configured_binding, std::string_view unit, JournalMode mode);
} // namespace knetsentry::agent
