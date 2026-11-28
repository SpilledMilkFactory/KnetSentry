// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <knetsentry/detection/scheduler.hpp>

namespace knetsentry::detection {
enum class AlertStatus { Open, Acknowledged, Resolved };
enum class AlertResult { Ok, ExactRetry, Invalid, Unverified, Unavailable, Capacity, Conflict, NotFound };
enum class AlertAction { Acknowledge, Resolve, AddNote };
struct AlertNote {
    std::uint64_t time_ms{};
    std::string analyst, text;
};
struct AlertEvidence {
    storage::EventId id{};
    std::uint64_t received_ms{}, source_ms{};
    std::string sha256;
    storage::IntegrityOrigin integrity_origin{storage::IntegrityOrigin::LegacyBaseline};
    bool operator==(const AlertEvidence&) const = default;
};
struct AlertRecord {
    std::uint64_t generation{}, revision{1}, created_ms{}, updated_ms{}, acknowledged_ms{}, resolved_ms{};
    std::uint64_t snapshot_revision{};
    Coverage coverage{Coverage::Unknown};
    AlertStatus status{AlertStatus::Open};
    std::string acknowledged_by, resolved_by;
    std::vector<AlertEvidence> evidence;
    std::vector<AlertNote> notes;
};
struct AlertSnapshot {
    AlertResult result{AlertResult::Invalid};
    std::string schedule_identity, store_identity, binding, source, rule_id;
    std::uint32_t rule_version{};
    RuleSeverity severity{RuleSeverity::Unspecified};
    std::vector<AlertRecord> alerts;
};
// Caller authenticates and authorizes the analyst, approves separate directories and
// serializes scheduler, alert and event-store operations. Tokens are not credentials.
// This is a private single-scope offline ledger, not a service or authorization boundary.
inline constexpr std::size_t max_alerts = 128, max_alert_notes = 8, max_alert_note_bytes = 256;
[[nodiscard]] bool initialize_alerts(const SchedulePolicy& policy, std::string_view directory, bool authorized);
[[nodiscard]] AlertSnapshot read_alerts(const SchedulePolicy& policy, std::string_view directory, bool authorized, bool recover_pending = true);
// Read committed scheduler batch directly, not a caller-fabricated report. No ACK is performed.
// After Ok/ExactRetry the caller may acknowledge precisely the returned input generation.
[[nodiscard]] AlertResult consume_alerts(const SchedulePolicy& policy, std::string_view directory,
    std::string_view schedule_directory, const storage::EventStore& store, std::uint64_t generation,
    std::uint64_t now_ms, bool authorized, EvidenceTrust trust);
// Stable ID = (schedule identity, generation, evidence.back().id). Optimistic revision required.
[[nodiscard]] AlertResult update_alert(const SchedulePolicy& policy, std::string_view directory,
    std::uint64_t generation, storage::EventId trigger, std::uint64_t expected_revision,
    AlertAction action, std::string_view analyst, std::string_view note, std::uint64_t now_ms, bool authorized);
} // namespace knetsentry::detection
