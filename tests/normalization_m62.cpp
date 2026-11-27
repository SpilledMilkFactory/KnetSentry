// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/agent/normalization.hpp>
#include <array>
#include <iostream>
#include <stdexcept>

namespace {
using namespace knetsentry::agent;
void require(bool condition, const char* message) {
    if (!condition) { throw std::runtime_error(message); }
}
std::string row(std::string_view unit, std::string_view suffix = {}, std::string_view realtime = "1795000000123456") {
    return "cursor-1\t" + std::string(realtime) + "\t42\t" + std::string(32, 'c') + '\t' +
        std::string(32, 'd') + '\t' + std::string(unit) + std::string(suffix) + '\n';
}
void verify() {
    const std::string binding = std::string(32, 'a') + std::string(64, 'b');
    require(NormalizedEvent::schema_version == "1.4.0" && NormalizedEvent::mapping_revision == 1, "schema pin");
    struct Case {
        std::string_view unit, suffix;
        JournalMode mode;
        OcsfClass cls;
        OcsfActivity activity;
        OcsfStatus status;
        MappingResult mapping;
        AuthEvent auth;
    };
    using J = JournalMode; using C = OcsfClass; using A = OcsfActivity;
    using S = OcsfStatus; using M = MappingResult; using E = AuthEvent;
    constexpr std::array cases{
        Case{"fixture.service", "", J::Metadata, C::Base, A::Unknown, S::Unknown, M::MetadataOnly, E::None},
        Case{"audit", "\t1100\t9", J::Audit, C::Base, A::Unknown, S::Unknown, M::AuditTypeUnmapped, E::None},
        Case{"ssh.service", "\tssh-accepted", J::Authentication, C::Authentication, A::Logon, S::Success, M::Classified, E::SshAccepted},
        Case{"sshd.service", "\tssh-failed", J::Authentication, C::Authentication, A::Logon, S::Failure, M::Classified, E::SshFailed},
        Case{"ssh@fixture.service", "\tssh-invalid-user", J::Authentication, C::Authentication, A::Unknown, S::Unknown, M::Classified, E::SshInvalidUser},
        Case{"ssh.service", "\tsession-opened", J::Authentication, C::Authentication, A::Logon, S::Unknown, M::Classified, E::SessionOpened},
        Case{"login.service", "\tsession-closed", J::Authentication, C::Authentication, A::Logoff, S::Unknown, M::Classified, E::SessionClosed},
        Case{"getty@tty1.service", "\tlogin-failed", J::Authentication, C::Authentication, A::Logon, S::Failure, M::Classified, E::LoginFailed},
        Case{"login.service", "\tauthentication-failed", J::Authentication, C::Authentication, A::Unknown, S::Failure, M::Classified, E::AuthenticationFailed},
        Case{"systemd-logind.service", "\tlogin-session-created", J::Authentication, C::Authentication, A::Logon, S::Unknown, M::Classified, E::LoginSessionCreated},
        Case{"systemd-logind.service", "\tlogin-session-removed", J::Authentication, C::Authentication, A::Logoff, S::Unknown, M::Classified, E::LoginSessionRemoved},
        Case{"ssh.service", "\tredacted", J::Authentication, C::Base, A::Unknown, S::Unknown, M::Redacted, E::Redacted},
        Case{"ssh.service", "\tunclassified", J::Authentication, C::Base, A::Unknown, S::Unknown, M::Unclassified, E::Unclassified}};
    for (const auto& c : cases) {
        const auto original = row(c.unit, c.suffix);
        auto input = original;
        const auto event = normalize_event(input, binding, c.unit, c.mode);
        require(event.has_value(), "valid profile rejected");
        input.clear(); // Result owns its evidence rather than borrowing caller buffers.
        require(event->class_uid == c.cls && event->activity_id == c.activity && event->status_id == c.status &&
            event->mapping == c.mapping && event->severity_id == OcsfSeverity::Unknown, "classification mapping");
        require(event->category_uid() == (c.cls == C::Authentication ? 3U : 0U) &&
            event->type_uid() == (c.cls == C::Authentication ? 300200U : 0U) + static_cast<std::uint32_t>(c.activity), "OCSF identifiers");
        require(event->canonical_row == original && event->destination_binding == binding && event->source_mode == c.mode &&
            event->source.unit == c.unit && event->source.cursor == "cursor-1" && event->source.machine == std::string(32, 'c') &&
            event->source.boot == std::string(32, 'd') && event->source.auth == c.auth, "original provenance");
        require(event->source.realtime_usec == 1795000000123456ULL && event->source.monotonic_usec == 42 &&
            event->time_ms == 1795000000123ULL, "timestamp units or precision");
        require(event->source.audit_type == (c.mode == J::Audit ? 1100U : 0U) &&
            event->source.audit_id == (c.mode == J::Audit ? 9U : 0U), "audit provenance");
    }
    const auto base = row("fixture.service");
    const auto valid = [&](std::string_view wire) { return normalize_event(wire, binding, "fixture.service", J::Metadata); };
    require(!valid("") && !valid(std::string(2049, 'x')) && !valid(base.substr(0, base.size() - 1)) &&
        !valid(base + base) && !valid(row("other.service")) && !valid(row("fixture.service", "\tredacted")), "invalid row bounds");
    for (const auto stamp : {"0", "01", "-1", "+1", "1x", "36028797018963968", "18446744073709551616"}) {
        require(!valid(row("fixture.service", "", stamp)), "malformed timestamp accepted");
    }
    const auto tiny = valid(row("fixture.service", "", "1"));
    const auto large = valid(row("fixture.service", "", "36028797018963967"));
    require(tiny && tiny->time_ms == 0 && tiny->source.realtime_usec == 1 && large &&
        large->time_ms == 36028797018963ULL, "timestamp boundaries");
    auto invalid = base; invalid[0] = '\x01'; require(!valid(invalid), "control character accepted");
    invalid = base; invalid[0] = '\0'; require(!valid(invalid), "NUL accepted");
    invalid = base; invalid.replace(invalid.find(std::string(32, 'c')), 32, std::string(32, '0'));
    require(!valid(invalid), "zero machine ID accepted");
    require(decode_journal_mode(-1) == J::Unsupported && decode_journal_mode(0) == J::Metadata &&
        decode_journal_mode(1) == J::Authentication && decode_journal_mode(2) == J::Audit &&
        decode_journal_mode(99) == J::Unsupported, "numeric mode decoding");
    require(!normalize_event(base, "invalid", "fixture.service", J::Metadata) &&
        !normalize_event(base, std::string(96, '0'), "fixture.service", J::Metadata) &&
        !normalize_event(base, binding, "fixture.service", decode_journal_mode(99)), "invalid configuration accepted");
    require(!normalize_event(row("ssh.service", "\tlogin-failed"), binding, "ssh.service", J::Authentication) &&
        !normalize_event(row("ssh.service", "\tunknown"), binding, "ssh.service", J::Authentication) &&
        !normalize_event(row("audit", "\t0999\t9"), binding, "audit", J::Audit) &&
        !normalize_event(row("audit", "\t1100\t0"), binding, "audit", J::Audit), "invalid native category accepted");
    std::cout << "M6.2 pinned OCSF mapping, original provenance, redaction, timestamps and invalid rejection: PASS\n";
}
} // namespace
int main() {
    try { verify(); return 0; }
    catch (const std::exception& e) { std::cerr << "M6.2: " << e.what() << '\n'; return 1; }
}
