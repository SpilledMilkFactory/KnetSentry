// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/detection/authentication_patterns.hpp>
#include <iostream>
#include <stdexcept>

namespace {
using namespace knetsentry::detection;
using namespace knetsentry::storage;
using knetsentry::agent::JournalMode;
using P = AuthenticationPattern;
void require(bool condition, const char* message) {
    if (!condition) { throw std::runtime_error(message); }
}
std::string binding(char marker = 'a') { return std::string(32, marker) + std::string(64, 'b'); }
EventId append(MemoryEventStore& store, unsigned n, std::uint64_t offset, std::string_view category = "ssh-failed",
    char endpoint = 'a', std::string_view unit = "ssh.service", bool index = true) {
    const auto row = "cursor" + std::to_string(n) + "\t1795000000123456\t42\t" + std::string(32, 'c') + '\t' +
        std::string(32, 'd') + '\t' + std::string(unit) + '\t' + std::string(category) + '\n';
    const auto admission = store.append({binding(endpoint), unit, row, JournalMode::Authentication, 1795000000000ULL + offset});
    require(admission.status == StoreStatus::Ok, "fixture admission");
    if (index) { require(store.index(admission.id).status == StoreStatus::Ok, "fixture indexing"); }
    return admission.id;
}
AuthenticationReport scan(const MemoryEventStore& store, AuthenticationPolicy policy = {3, 100},
    char endpoint = 'a', std::string_view unit = "ssh.service") {
    return detect_authentication(store, binding(endpoint), unit, EvidenceTrust::VerifiedStored, Coverage::Partial, policy);
}
void positive() {
    MemoryEventStore store;
    const auto first = append(store, 1, 0);
    const auto second = append(store, 2, 50);
    const auto third = append(store, 3, 100);
    const auto success = append(store, 4, 101, "ssh-accepted");
    const auto anomaly = append(store, 5, 102, "authentication-failed");
    const auto before = store.search({});
    const auto narrow = scan(store);
    require(narrow.status == PatternStatus::Evaluated && narrow.observed == 5 && narrow.indeterminate == 1 && narrow.findings.size() == 2, "inclusive threshold and expired sequence");
    const auto wide = scan(store, {3, 101});
    require(wide.status == PatternStatus::Evaluated && wide.policy.threshold == 3 && wide.policy.window_ms == 101 && wide.findings.size() == 3, "wide sequence count");
    const auto& repeated = wide.findings[0];
    const auto& sequence = wide.findings[1];
    const auto& unusual = wide.findings[2];
    const std::vector<EventId> expected_failures{first, second, third};
    const std::vector<EventId> expected_sequence{first, second, third, success};
    require(repeated.pattern == P::RepeatedFailures && repeated.evidence_ids == expected_failures && repeated.severity == RuleSeverity::Medium && repeated.version == 1, "repeat evidence");
    require(sequence.pattern == P::SuccessAfterFailures && sequence.evidence_ids == expected_sequence && sequence.severity == RuleSeverity::High && sequence.coverage == Coverage::Partial, "sequence evidence");
    require(unusual.pattern == P::UnspecifiedActivityFailure && unusual.evidence_ids.size() == 1 && unusual.evidence_ids.front() == anomaly, "anomaly evidence");
    require(scan(store, {3, 101}) == wide, "non-deterministic scan");
    const auto after = store.search({});
    require(before.revision == after.revision && before.events.size() == after.events.size(), "store changed");
}
void negative() {
    MemoryEventStore store;
    append(store, 1, 0);
    append(store, 2, 1, "ssh-failed", 'e');
    append(store, 3, 2, "ssh-failed", 'a', "sshd.service");
    append(store, 4, 3, "ssh-accepted");
    append(store, 5, 4);
    append(store, 6, 105);
    append(store, 7, 106, "ssh-invalid-user");
    append(store, 8, 107);
    append(store, 9, 108, "redacted");
    append(store, 10, 109);
    append(store, 11, 110, "ssh-accepted");
    const auto report = scan(store);
    require(report.status == PatternStatus::Evaluated && report.observed == 9 && report.indeterminate == 2 && report.findings.size() == 1 &&
        report.findings.front().pattern == P::InvalidUserObservation && report.findings.front().evidence_ids.size() == 1 &&
        report.findings.front().evidence_ids.front() == 7, "scope, expiry or unknown barrier");
    require(scan(store, {3, 100}, 'e').observed == 1 && scan(store, {3, 100}, 'a', "sshd.service").observed == 1, "scope leakage");
    require(detect_authentication(store, "", "ssh.service", EvidenceTrust::VerifiedStored, Coverage::Partial).status == PatternStatus::Invalid, "empty binding");
    require(detect_authentication(store, binding(), "ssh*.service", EvidenceTrust::VerifiedStored, Coverage::Partial).status == PatternStatus::Invalid, "wildcard");
    require(detect_authentication(store, binding(), "ssh.service", EvidenceTrust::Unverified, Coverage::Partial).status == PatternStatus::Unverified, "unverified scan");
    require(scan(store, {1, 100}).status == PatternStatus::Invalid && scan(store, {17, 100}).status == PatternStatus::Invalid && scan(store, {3, 0}).status == PatternStatus::Invalid, "policy bounds");
    append(store, 12, 111, "ssh-failed", 'e', "ssh.service", false);
    const auto pending = scan(store);
    require(pending.status == PatternStatus::Unavailable && pending.findings.empty() && pending.observed == 0, "pending index returned partial report");
    MemoryEventStore clock;
    append(clock, 1, 10);
    append(clock, 2, 9);
    require(scan(clock).status == PatternStatus::Invalid, "receiver clock regression");
    MemoryEventStore tie;
    append(tie, 1, 0);
    append(tie, 2, 0);
    append(tie, 3, 0);
    append(tie, 4, 0, "ssh-accepted");
    const auto tied = scan(tie);
    require(tied.findings.size() == 1 && tied.findings.front().pattern == P::RepeatedFailures, "ambiguous success ordering");
    MemoryEventStore empty;
    require(scan(empty).status == PatternStatus::Evaluated && scan(empty).observed == 0, "empty scope");
    append(empty, 1, 1, "login-session-created", 'a', "systemd-logind.service");
    const auto unsupported = scan(empty, {3, 100}, 'a', "systemd-logind.service");
    require(unsupported.status == PatternStatus::Evaluated && unsupported.indeterminate == 1 && unsupported.findings.empty(), "unsupported source semantics");
}
void capacity() {
    MemoryEventStore store;
    for (unsigned i = 1; i <= 128; ++i) { append(store, i, i); }
    const auto result = scan(store, {16, 600000});
    require(result.status == PatternStatus::Evaluated && result.observed == 128 && result.findings.size() == 1, "bounded pages or repeated emission");
    require(result.findings.front().evidence_ids.size() == 16, "bounded evidence list");
    MemoryEventStore crossing;
    for (unsigned i = 1; i <= 30; ++i) { append(crossing, i, i, "ssh-accepted"); }
    append(crossing, 31, 31);
    append(crossing, 32, 32);
    append(crossing, 33, 33);
    append(crossing, 34, 34, "ssh-accepted");
    const auto paged = scan(crossing);
    require(paged.findings.size() == 2 && paged.observed == 34 && paged.findings[1].evidence_ids.back() == 34, "cross-page sequence");
}
} // namespace
int main() {
    try { positive(); negative(); capacity(); }
    catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
    std::cout << "M7.3 scoped authentication patterns, evidence links and deterministic receiver windows: PASS\n";
    std::cout << "M7.3 negative fixtures, pending refusal, clock regression and bounded pagination: PASS\n";
    return 0;
}
