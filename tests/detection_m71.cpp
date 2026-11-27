// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/detection/engine.hpp>
#include <algorithm>
#include <array>
#include <iostream>
#include <stdexcept>

namespace {
using namespace knetsentry::detection;
using namespace knetsentry::agent;
using namespace knetsentry::storage;
using A = OcsfActivity;
using S = OcsfStatus;
void require(bool condition, const char* message) {
    if (!condition) { throw std::runtime_error(message); }
}
EventSummary fixture(MemoryEventStore& store, std::string_view cursor, std::string_view unit,
    std::string_view suffix, JournalMode mode = JournalMode::Authentication) {
    const auto binding = std::string(32, 'a') + std::string(64, 'b');
    const auto row = std::string(cursor) + "\t1795000000123456\t42\t" + std::string(32, 'c') + '\t' +
        std::string(32, 'd') + '\t' + std::string(unit) + std::string(suffix) + '\n';
    const auto admission = store.append({binding, unit, row, mode, 1795000000999ULL});
    require(admission.status == StoreStatus::Ok, "fixture admission");
    require(store.index(admission.id).status == StoreStatus::Ok, "fixture indexing");
    SearchQuery q;
    q.source_unit = unit;
    q.descending = true;
    q.limit = 1;
    const auto page = store.search(q);
    require(page.status == StoreStatus::Ok && page.events.size() == 1 && page.events.front().id == admission.id, "fixture search");
    return page.events.front();
}
void verify() {
    MemoryEventStore store;
    const auto failed = fixture(store, "one", "ssh.service", "\tssh-failed");
    const auto accepted = fixture(store, "two", "sshd.service", "\tssh-accepted");
    const auto session = fixture(store, "three", "ssh.service", "\tsession-opened");
    const auto preauth = fixture(store, "four", "ssh.service", "\tssh-invalid-user");
    const auto redacted = fixture(store, "five", "ssh.service", "\tredacted");
    const auto unclassified = fixture(store, "six", "ssh.service", "\tunclassified");
    const auto metadata = fixture(store, "seven", "fixture.service", "", JournalMode::Metadata);
    const auto audit = fixture(store, "eight", "audit", "\t1100\t9", JournalMode::Audit);
    const auto generic = fixture(store, "nine", "login.service", "\tauthentication-failed");
    const auto closed = fixture(store, "ten", "systemd-logind.service", "\tlogin-session-removed");
    const auto other_failed = fixture(store, "eleven", "sshd.service", "\tssh-failed");
    const auto before = store.search({});
    require(before.status == StoreStatus::Ok, "initial snapshot");
    std::array rules{Rule{"z-failure", 3, std::nullopt, S::Failure, ""},
        Rule{"a-ssh-failure", 1, A::Logon, S::Failure, "ssh.service"},
        Rule{"b-success", 2, A::Logon, S::Success, ""},
        Rule{"c-logoff", 1, A::Logoff, std::nullopt, ""}};
    const auto engine = Engine::create(rules);
    require(engine.has_value(), "rule activation");
    std::ranges::reverse(rules);
    const auto reversed = Engine::create(rules);
    require(reversed.has_value(), "reversed activation");
    rules.front().id = "changed";
    const auto evaluate = [&](const EventSummary& event) { return engine->evaluate(event, EvidenceTrust::VerifiedStored, Coverage::Partial); };
    const auto result = evaluate(failed);
    require(result.status == EvaluationStatus::Evaluated && result.coverage == Coverage::Partial && result.evaluated == 4 && result.indeterminate == 0 &&
        result.findings == std::vector<Finding>{{"a-ssh-failure", 1, failed.id, Coverage::Partial}, {"z-failure", 3, failed.id, Coverage::Partial}}, "failure findings");
    require(result == reversed->evaluate(failed, EvidenceTrust::VerifiedStored, Coverage::Partial), "input order affected findings");
    for (int i = 0; i < 1000; ++i) { require(evaluate(failed) == result, "repeat mismatch"); }
    require(evaluate(other_failed).findings == std::vector<Finding>{{"z-failure", 3, other_failed.id, Coverage::Partial}}, "exact source isolation");
    require(evaluate(accepted).findings == std::vector<Finding>{{"b-success", 2, accepted.id, Coverage::Partial}}, "success match");
    require(evaluate(session).findings.empty() && evaluate(session).indeterminate == 3 && evaluate(session).evaluated == 1, "unknown outcome");
    require(evaluate(preauth).findings.empty() && evaluate(preauth).indeterminate == 4, "unknown activity and outcome");
    require(evaluate(generic).findings == std::vector<Finding>{{"z-failure", 3, generic.id, Coverage::Partial}} && evaluate(generic).indeterminate == 1, "partial known evidence");
    require(evaluate(closed).findings == std::vector<Finding>{{"c-logoff", 1, closed.id, Coverage::Partial}}, "logoff match");
    for (const auto& event : {redacted, unclassified, metadata, audit}) {
        const auto r = evaluate(event);
        require(r.status == EvaluationStatus::Unsupported && r.findings.empty() && r.evaluated == 0 && r.indeterminate == 0, "unsupported evidence");
    }
    require(engine->evaluate(failed, EvidenceTrust::Unverified, Coverage::Unknown).status == EvaluationStatus::Unverified, "unverified evidence");
    const auto unknown = engine->evaluate(failed, EvidenceTrust::VerifiedStored, Coverage::Unknown);
    require(!unknown.findings.empty() && unknown.findings.front().coverage == Coverage::Unknown, "coverage upgraded");
    auto invalid = failed; invalid.id = 0; require(evaluate(invalid).status == EvaluationStatus::Invalid, "zero id");
    invalid = failed; invalid.received_ms = 0; require(evaluate(invalid).status == EvaluationStatus::Invalid, "zero receipt time");
    invalid = failed; invalid.time_ms = 36028797018964ULL; require(evaluate(invalid).status == EvaluationStatus::Invalid, "time bound");
    invalid = failed; invalid.time_ms = 0; require(evaluate(invalid).status == EvaluationStatus::Evaluated, "submillisecond time");
    invalid = failed; invalid.source_unit = "systemd-logind.service"; require(evaluate(invalid).status == EvaluationStatus::Invalid, "impossible source mapping");
    invalid = failed; invalid.activity_id = A::Logoff; require(evaluate(invalid).status == EvaluationStatus::Invalid, "impossible outcome");
    invalid = failed; invalid.severity = OcsfSeverity::High; require(evaluate(invalid).status == EvaluationStatus::Invalid, "invented severity");
    invalid = failed; invalid.source_unit = std::string(129, 'x'); require(evaluate(invalid).status == EvaluationStatus::Invalid, "source bound");
    invalid = failed; invalid.mapping = MappingResult::Redacted; require(evaluate(invalid).status == EvaluationStatus::Invalid, "contradictory redaction");
    require(evaluate(failed) == result, "invalid input poisoned engine");
    std::cout << "M7.1 normalized storage, deterministic findings, unknown/redacted evidence and trust: PASS\n";
    const auto rejects = [](const Rule& rule) { return !Engine::create(std::span(&rule, 1)); };
    require(rejects({"bad*", 1, A::Logon, S::Failure, ""}) && rejects({"", 1, A::Logon, S::Failure, ""}) &&
        rejects({std::string(65, 'x'), 1, A::Logon, S::Failure, ""}) && rejects({"bad", 0, A::Logon, S::Failure, ""}) &&
        rejects({"bad", 1, std::nullopt, std::nullopt, ""}) && rejects({"bad", 1, A::Unknown, S::Failure, ""}) &&
        rejects({"bad", 1, A::Logon, S::Unknown, ""}) && rejects({"bad", 1, A::Logon, S::Failure, "ssh@*.service"}), "invalid rule accepted");
    const std::array duplicates{Rule{"same", 1, A::Logon, S::Failure, ""}, Rule{"same", 2, A::Logon, S::Success, ""}};
    require(!Engine::create(duplicates), "duplicate id accepted");
    const Rule only_failure{"failure-only", 1, A::Logon, S::Failure, ""};
    const auto narrow = Engine::create(std::span(&only_failure, 1));
    require(narrow.has_value(), "narrow policy");
    const auto no_match = narrow->evaluate(accepted, EvidenceTrust::VerifiedStored, Coverage::SourceObserved);
    require(no_match.status == EvaluationStatus::Evaluated && no_match.coverage == Coverage::SourceObserved &&
        no_match.evaluated == 1 && no_match.indeterminate == 0 && no_match.findings.empty(), "definite nonmatch");
    const auto empty = Engine::create({});
    require(empty && empty->evaluate(failed, EvidenceTrust::VerifiedStored, Coverage::Unknown).status == EvaluationStatus::NoRules, "empty policy");
    std::vector<Rule> maximum;
    for (std::size_t i = 0; i < Engine::max_rules; ++i) { maximum.push_back({"rule-" + std::to_string(i), 1, A::Logon, S::Failure, ""}); }
    const auto bounded = Engine::create(maximum);
    require(bounded && bounded->evaluate(failed, EvidenceTrust::VerifiedStored, Coverage::Unknown).findings.size() == Engine::max_rules, "maximum findings");
    maximum.push_back({"overflow", 1, A::Logon, S::Failure, ""});
    require(!Engine::create(maximum), "rule capacity");
    const auto after = store.search({});
    require(after.status == StoreStatus::Ok && after.revision == before.revision && after.events.size() == 11, "engine modified storage");
    std::cout << "M7.1 bounded rule activation, duplicate IDs, maximum fanout and immutable evidence: PASS\n";
}
} // namespace
int main() {
    try { verify(); return 0; }
    catch (const std::exception& e) { std::cerr << "M7.1: " << e.what() << '\n'; return 1; }
}
