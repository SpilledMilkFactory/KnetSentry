// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/detection/scheduler.hpp>
#include <knetsentry/agent/journal.hpp>
#include "private_state.hpp"
#include <algorithm>
#include <array>
#include <charconv>
#include <limits>
#include <openssl/evp.h>
#include <stdexcept>
#include <sys/file.h>
#include <utility>

namespace knetsentry::detection {
namespace {
using namespace agent::private_state;
using storage::StoreStatus;
constexpr auto ceiling = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
constexpr auto capacity = storage::StoragePolicy::record_ceiling;
constexpr const char* state_name = "schedule-m75.v1";
constexpr const char* pending_name = "schedule-m75.pending";
struct Observation { storage::EventId id; std::uint64_t time; };
struct State {
    std::uint64_t cursor{}, received{}, emitted{}, tick{};
    std::vector<Observation> context;
    ScheduleReport report;
};
bool valid_coverage(Coverage value) {
    return value == Coverage::Unknown || value == Coverage::Partial || value == Coverage::SourceObserved;
}
std::optional<Coverage> decode_coverage(std::uint64_t value) {
    switch (value) {
    case 0: return Coverage::Unknown;
    case 1: return Coverage::Partial;
    case 2: return Coverage::SourceObserved;
    default: return std::nullopt;
    }
}
ScheduleReport refused(ScheduleStatus status) {
    ScheduleReport result;
    result.status = status;
    return result;
}
bool valid_policy(const SchedulePolicy& p) {
    return p.store_identity.size() == 64 && p.store_identity.find_first_not_of('0') != std::string::npos &&
        std::ranges::all_of(p.store_identity, [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }) &&
        agent::valid_delivery_binding(p.binding) && agent::valid_auth_unit(p.rule.predicate.source_unit) &&
        p.interval_ms > 0 && p.interval_ms <= SchedulePolicy::max_period_ms &&
        p.window_ms > 0 && p.window_ms <= SchedulePolicy::max_period_ms &&
        p.suppression_ms <= SchedulePolicy::max_period_ms && p.threshold > 0 && p.threshold <= SchedulePolicy::max_context &&
        ValidatedRuleSet::compile(std::span(&p.rule, 1)).rules.has_value();
}
std::string digest(std::string_view data) {
    std::array<unsigned char, 32> bytes{};
    unsigned int size{};
    if (EVP_Digest(data.data(), data.size(), bytes.data(), &size, EVP_sha256(), nullptr) != 1 || size != bytes.size()) {
        throw std::runtime_error("schedule digest unavailable");
    }
    constexpr std::string_view hex = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (const auto byte : bytes) { result += hex[byte >> 4U]; result += hex[byte & 15U]; }
    return result;
}
std::string identity(const SchedulePolicy& p) {
    const auto& r = p.rule;
    // Validated ASCII metadata cannot contain tabs or newlines. Bind semantics, not merely rule ID.
    return digest("KnetSentry:schedule:policy:v1\t" + p.store_identity + '\t' + p.binding + '\t' + r.predicate.id + '\t' +
        std::to_string(r.predicate.version) + '\t' + std::to_string(r.schema_version) + '\t' + r.ocsf_version + '\t' +
        std::to_string(r.mapping_revision) + '\t' + r.predicate.source_unit + '\t' +
        (r.predicate.activity ? std::to_string(static_cast<std::uint32_t>(*r.predicate.activity)) : "-") + '\t' +
        (r.predicate.outcome ? std::to_string(static_cast<std::uint32_t>(*r.predicate.outcome)) : "-") + '\t' +
        std::to_string(static_cast<std::uint32_t>(r.severity)) + '\t' + r.title + '\t' + r.description + '\t' +
        std::to_string(p.interval_ms) + '\t' + std::to_string(p.window_ms) + '\t' + std::to_string(p.suppression_ms) + '\t' +
        std::to_string(p.threshold) + '\n');
}
std::string header(const SchedulePolicy& p) { return "KNETSENTRY-SCHEDULE-V1\t" + identity(p) + '\n'; }
void identify(const SchedulePolicy& p, ScheduleReport& report) {
    report.rule_id = p.rule.predicate.id;
    report.rule_version = p.rule.predicate.version;
    report.severity = p.rule.severity;
    report.schedule_identity = identity(p);
}
void put(std::string& out, std::uint64_t n) { out += std::to_string(n) + '\n'; }
std::string encode(const SchedulePolicy& policy, const State& state) {
    auto out = header(policy);
    const auto& report = state.report;
    for (const auto n : {state.cursor, state.received, state.emitted, state.tick, report.generation, report.revision,
        static_cast<std::uint64_t>(report.coverage), static_cast<std::uint64_t>(report.observed),
        static_cast<std::uint64_t>(report.expired), static_cast<std::uint64_t>(report.suppressed),
        static_cast<std::uint64_t>(state.context.size())}) { put(out, n); }
    for (const auto& observation : state.context) { put(out, observation.id); put(out, observation.time); }
    put(out, report.findings.size());
    for (const auto& finding : report.findings) {
        put(out, finding.received_ms);
        put(out, finding.evidence_ids.size());
        for (const auto id : finding.evidence_ids) { put(out, id); }
    }
    out += digest(out) + '\n';
    return out;
}
bool take(std::string_view& input, std::uint64_t& n) {
    const auto end = input.find('\n');
    if (end == input.npos || end == 0 || end > 19) { return false; }
    const auto field = input.substr(0, end);
    const auto parsed = std::from_chars(field.data(), field.data() + field.size(), n);
    if (parsed.ec != std::errc{} || parsed.ptr != field.data() + field.size() || n > ceiling) { return false; }
    input.remove_prefix(end + 1);
    return true;
}
bool decode(const SchedulePolicy& p, std::string_view input, State& s) {
    const auto original = input;
    const auto prefix = header(p);
    if (!input.starts_with(prefix) || input.size() < prefix.size() + 65 || !input.ends_with('\n') ||
        digest(input.substr(0, input.size() - 65)) != input.substr(input.size() - 65, 64)) { return false; }
    input.remove_suffix(65);
    input.remove_prefix(prefix.size());
    auto& r = s.report;
    std::uint64_t coverage{}, observed{}, expired{}, suppressed{}, count{};
    if (!take(input, s.cursor) || !take(input, s.received) || !take(input, s.emitted) || !take(input, s.tick) ||
        !take(input, r.generation) || !take(input, r.revision) || !take(input, coverage) || !take(input, observed) ||
        !take(input, expired) || !take(input, suppressed) || !take(input, count) || count > p.threshold ||
        observed > capacity || expired > observed || suppressed > observed - expired ||
        s.emitted > s.received || s.received > s.tick || (s.cursor == 0) != (s.received == 0)) { return false; }
    const auto decoded = decode_coverage(coverage);
    if (!decoded) { return false; }
    r.coverage = *decoded;
    r.observed = static_cast<std::size_t>(observed);
    r.expired = static_cast<std::size_t>(expired);
    r.suppressed = static_cast<std::size_t>(suppressed);
    std::uint64_t previous_id{}, previous_time{};
    for (std::uint64_t i = 0; i < count; ++i) {
        Observation item{};
        if (!take(input, item.id) || !take(input, item.time) || item.id <= previous_id || item.id > s.cursor ||
            item.time == 0 || item.time < previous_time || item.time > s.received || s.tick - item.time > p.window_ms) { return false; }
        s.context.push_back(item);
        previous_id = item.id; previous_time = item.time;
    }
    if (!take(input, count) || count > observed - expired - suppressed) { return false; }
    previous_id = 0; previous_time = 0;
    for (std::uint64_t i = 0; i < count; ++i) {
        ScheduledFinding finding;
        std::uint64_t size{};
        if (!take(input, finding.received_ms) || finding.received_ms == 0 || finding.received_ms < previous_time ||
            finding.received_ms > s.emitted || !take(input, size) || size != p.threshold) { return false; }
        std::uint64_t prior{};
        for (std::uint64_t j = 0; j < size; ++j) {
            std::uint64_t id{};
            if (!take(input, id) || id <= prior || id > s.cursor) { return false; }
            finding.evidence_ids.push_back(id); prior = id;
        }
        if (prior <= previous_id) { return false; }
        previous_id = prior; previous_time = finding.received_ms;
        r.findings.push_back(std::move(finding));
    }
    if (!r.findings.empty() && previous_time != s.emitted) { return false; }
    if (r.generation == 0) {
        const State initial;
        return original == encode(p, initial);
    }
    return s.tick != 0 && r.revision != 0 && input.empty() && encode(p, s) == original;
}
int locked_directory(std::string_view path) {
    if (::geteuid() == 0 || !agent::valid_journal_directory(path)) { return -1; }
    File dir(open_directory(path));
    if (dir.fd < 0 || !directory_private(dir.fd) || ::flock(dir.fd, LOCK_EX | LOCK_NB) != 0) { return -1; }
    return std::exchange(dir.fd, -1);
}
bool absent(int fd, const char* name) {
    struct stat st{};
    return ::fstatat(fd, name, &st, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
}
bool load(int fd, const SchedulePolicy& policy, State& state) {
    File file(::openat(fd, state_name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (file.fd < 0 || !regular_private(file.fd)) { return false; }
    std::string data;
    std::array<char, 4096> bytes{};
    for (;;) {
        const auto n = ::read(file.fd, bytes.data(), bytes.size());
        if (n < 0 && errno == EINTR) { continue; }
        if (n < 0) { return false; }
        if (n == 0) { break; }
        const auto size = static_cast<std::size_t>(n);
        if (size > max_state - data.size()) { return false; }
        data.append(bytes.data(), size);
    }
    if (!decode(policy, data, state)) { return false; }
    // Only a verified committed state can authorize removal of an abandoned temporary file.
    File pending(::openat(fd, pending_name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (pending.fd >= 0) {
        if (!regular_private(pending.fd) || ::unlinkat(fd, pending_name, 0) != 0) { return false; }
    } else if (errno != ENOENT) { return false; }
    return ::fsync(fd) == 0;
}
bool commit(int fd, const SchedulePolicy& p, const State& state) {
    const auto data = encode(p, state);
    if (!directory_private(fd) || data.size() > max_state) { return false; }
    File pending(::openat(fd, pending_name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
    return pending.fd >= 0 && regular_private(pending.fd) && write_all(pending.fd, data) && ::fsync(pending.fd) == 0 &&
        ::renameat(fd, pending_name, fd, state_name) == 0 && ::fsync(fd) == 0;
}
bool observe(const SchedulePolicy& p, const Engine& engine, const storage::EventSummary& event,
    std::uint64_t now, Coverage coverage, State& s) {
    if (event.id <= s.cursor || event.source_unit != p.rule.predicate.source_unit ||
        event.source_mode != agent::JournalMode::Authentication || event.audit_type != 0 ||
        event.received_ms < s.received || event.received_ms > now) { return false; }
    const auto evaluated = engine.evaluate(event, EvidenceTrust::VerifiedStored, coverage);
    if (evaluated.status != EvaluationStatus::Evaluated && evaluated.status != EvaluationStatus::Unsupported) { return false; }
    s.cursor = event.id; s.received = event.received_ms;
    ++s.report.observed;
    if (now - event.received_ms > p.window_ms) { ++s.report.expired; return true; }
    std::erase_if(s.context, [&](const Observation& item) { return event.received_ms - item.time > p.window_ms; });
    if (evaluated.findings.empty()) { return true; }
    if (s.context.size() == p.threshold) { s.context.erase(s.context.begin()); }
    s.context.push_back({event.id, event.received_ms});
    if (s.context.size() != p.threshold) { return true; }
    if (s.emitted != 0 && event.received_ms - s.emitted < p.suppression_ms) { ++s.report.suppressed; return true; }
    ScheduledFinding finding;
    finding.received_ms = event.received_ms;
    for (const auto& item : s.context) { finding.evidence_ids.push_back(item.id); }
    s.report.findings.push_back(std::move(finding));
    s.emitted = event.received_ms;
    return true;
}
bool scan(const SchedulePolicy& p, const storage::EventStore& store, const Engine& engine,
    std::uint64_t now, Coverage coverage, State& s) {
    storage::SearchQuery query;
    query.binding = p.binding;
    query.source_unit = p.rule.predicate.source_unit;
    query.source_mode = agent::JournalMode::Authentication;
    // Revisit the bounded retained snapshot to prove that carried correlation
    // context still exists. Never silently correlate deleted evidence.
    const auto prior_context = s.context;
    const auto checkpoint = s.cursor;
    std::size_t context_seen{};
    std::uint64_t previous_time{};
    query.limit = storage::EventStore::max_page;
    constexpr auto pages = capacity / storage::EventStore::max_page;
    for (std::size_t i = 0; i < pages; ++i) {
        const auto page = store.search(query);
        if (page.status != StoreStatus::Ok || page.revision == 0 || page.revision > ceiling || page.revision < s.report.revision ||
            (query.revision && page.revision != *query.revision) || page.events.size() > query.limit ||
            (page.more && page.events.empty())) { return false; }
        query.revision = page.revision;
        s.report.revision = page.revision;
        for (const auto& event : page.events) {
            if (event.id <= query.after || event.source_unit != p.rule.predicate.source_unit ||
                event.source_mode != agent::JournalMode::Authentication || event.audit_type != 0 ||
                event.received_ms < previous_time || event.received_ms > now) { return false; }
            if (event.id <= checkpoint) {
                const auto evaluated = engine.evaluate(event, EvidenceTrust::VerifiedStored, coverage);
                if (evaluated.status != EvaluationStatus::Evaluated && evaluated.status != EvaluationStatus::Unsupported) { return false; }
                const auto carried = std::ranges::find(prior_context, event.id, &Observation::id);
                if (carried != prior_context.end()) {
                    if (carried->time != event.received_ms || evaluated.findings.empty()) { return false; }
                    ++context_seen;
                }
            } else {
                if (context_seen != prior_context.size() || !observe(p, engine, event, now, coverage, s)) { return false; }
            }
            previous_time = event.received_ms;
            query.after = event.id;
        }
        if (!page.more) {
            const auto pending = store.pending(0, query.revision, 1);
            return context_seen == prior_context.size() && pending.status == StoreStatus::Ok &&
                pending.revision == page.revision && !pending.more && pending.ids.empty();
        }
    }
    return false;
}
} // namespace
bool initialize_schedule(const SchedulePolicy& policy, std::string_view directory) {
    if (!valid_policy(policy)) { return false; }
    File dir(locked_directory(directory));
    return dir.fd >= 0 && absent(dir.fd, state_name) && absent(dir.fd, pending_name) && commit(dir.fd, policy, State{});
}
ScheduleReport run_schedule(const SchedulePolicy& policy, std::string_view directory,
    const storage::EventStore& store, std::uint64_t now_ms, bool enabled, EvidenceTrust trust, Coverage coverage) {
    if (!valid_policy(policy) || now_ms == 0 || now_ms > ceiling || !valid_coverage(coverage) ||
        (trust != EvidenceTrust::Unverified && trust != EvidenceTrust::VerifiedStored)) { return {}; }
    if (trust != EvidenceTrust::VerifiedStored) { return refused(ScheduleStatus::Unverified); }
    if (!enabled) { return refused(ScheduleStatus::Disabled); }
    File dir(locked_directory(directory));
    State state;
    if (dir.fd < 0 || !load(dir.fd, policy, state)) { return refused(ScheduleStatus::Unavailable); }
    if (now_ms < state.tick) { return refused(ScheduleStatus::Invalid); }
    if (!state.report.findings.empty()) {
        state.report.status = ScheduleStatus::Replay;
        identify(policy, state.report);
        return state.report;
    }
    if (state.tick != 0 && now_ms - state.tick < policy.interval_ms) { return refused(ScheduleStatus::NotDue); }
    if (state.report.generation == ceiling) { return refused(ScheduleStatus::Unavailable); }
    const auto compiled = ValidatedRuleSet::compile(std::span(&policy.rule, 1));
    if (!compiled.rules) { return {}; }
    state.report.observed = 0; state.report.expired = 0; state.report.suppressed = 0;
    std::erase_if(state.context, [&](const Observation& item) { return now_ms - item.time > policy.window_ms; });
    state.report.coverage = state.context.empty() ? coverage : std::min(state.report.coverage, coverage);
    if (!scan(policy, store, compiled.rules->engine(), now_ms, coverage, state)) { return refused(ScheduleStatus::Unavailable); }
    state.tick = now_ms;
    ++state.report.generation;
    if (!commit(dir.fd, policy, state)) { return refused(ScheduleStatus::Unavailable); }
    state.report.status = ScheduleStatus::Evaluated;
    identify(policy, state.report);
    return state.report;
}
std::optional<std::string> schedule_policy_identity(const SchedulePolicy& policy) {
    if (!valid_policy(policy)) { return std::nullopt; }
    return identity(policy);
}
ScheduleReport pending_schedule(const SchedulePolicy& policy, std::string_view directory, EvidenceTrust trust) {
    if (!valid_policy(policy)) { return {}; }
    if (trust != EvidenceTrust::VerifiedStored) { return refused(ScheduleStatus::Unverified); }
    File dir(locked_directory(directory));
    State state;
    if (dir.fd < 0 || !load(dir.fd, policy, state)) { return refused(ScheduleStatus::Unavailable); }
    if (state.report.findings.empty()) { return refused(ScheduleStatus::NotDue); }
    state.report.status = ScheduleStatus::Replay;
    identify(policy, state.report);
    return state.report;
}
bool acknowledge_schedule(const SchedulePolicy& policy, std::string_view directory, std::uint64_t generation) {
    if (!valid_policy(policy) || generation == 0) { return false; }
    File dir(locked_directory(directory));
    State state;
    if (dir.fd < 0 || !load(dir.fd, policy, state) || state.report.generation != generation || state.report.findings.empty()) { return false; }
    state.report.findings.clear();
    return commit(dir.fd, policy, state);
}
} // namespace knetsentry::detection
