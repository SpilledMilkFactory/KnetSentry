// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/agent/normalization.hpp>
#include <utility>

namespace knetsentry::agent {
std::optional<NormalizedEvent> normalize_event(std::string_view canonical_row,
    std::string_view configured_binding, std::string_view unit, JournalMode mode) {
    if (!valid_delivery_binding(configured_binding)) { return std::nullopt; }
    auto record = parse_delivery_row(canonical_row, unit, mode);
    if (!record) { return std::nullopt; }
    NormalizedEvent event;
    event.time_ms = record->realtime_usec / 1000U;
    event.source_mode = mode;
    event.destination_binding = configured_binding;
    event.canonical_row = canonical_row;
    event.source = std::move(*record);
    if (mode == JournalMode::Metadata) { return event; }
    if (mode == JournalMode::Audit) {
        event.mapping = MappingResult::AuditTypeUnmapped;
        return event;
    }
    switch (event.source.auth) {
    case AuthEvent::Redacted:
        event.mapping = MappingResult::Redacted;
        return event;
    case AuthEvent::Unclassified:
        event.mapping = MappingResult::Unclassified;
        return event;
    case AuthEvent::None:
        return std::nullopt; // Not a valid authentication row.
    case AuthEvent::SshAccepted:
        event.activity_id = OcsfActivity::Logon;
        event.status_id = OcsfStatus::Success;
        break;
    case AuthEvent::SshFailed:
    case AuthEvent::LoginFailed:
        event.activity_id = OcsfActivity::Logon;
        event.status_id = OcsfStatus::Failure;
        break;
    case AuthEvent::AuthenticationFailed:
        event.status_id = OcsfStatus::Failure;
        break;
    case AuthEvent::SshInvalidUser:
        // A preauthentication observation does not establish a completed attempt.
        break;
    case AuthEvent::SessionOpened:
    case AuthEvent::LoginSessionCreated:
        event.activity_id = OcsfActivity::Logon;
        break;
    case AuthEvent::SessionClosed:
    case AuthEvent::LoginSessionRemoved:
        event.activity_id = OcsfActivity::Logoff;
        break;
    }
    event.class_uid = OcsfClass::Authentication;
    event.mapping = MappingResult::Classified;
    return event;
}
} // namespace knetsentry::agent
