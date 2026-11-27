// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/detection/alerts.hpp>
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
constexpr const char* name = "alerts-m76.v1";
constexpr const char* pending = "alerts-m76.pending";
bool hex(std::string_view s) {
    return s.size() == 64 && std::ranges::all_of(s, [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}
bool printable(std::string_view s, std::size_t limit) {
    return !s.empty() && s.size() <= limit && std::ranges::all_of(s, [](char c) { return c >= ' ' && c <= '~'; });
}
bool actor(std::string_view s) {
    return printable(s, 64) && std::ranges::all_of(s, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
    });
}
std::string digest(std::string_view s) {
    std::array<unsigned char, 32> bytes{}; unsigned int size{};
    if (EVP_Digest(s.data(), s.size(), bytes.data(), &size, EVP_sha256(), nullptr) != 1 || size != bytes.size()) {
        throw std::runtime_error("alert digest unavailable");
    }
    constexpr std::string_view alphabet = "0123456789abcdef";
    std::string out;
    for (auto b : bytes) { out += alphabet[b >> 4U]; out += alphabet[b & 15U]; }
    return out;
}
void put(std::string& out, std::uint64_t n) { out += std::to_string(n) + '\n'; }
void line(std::string& out, std::string_view s) { out += s; out += '\n'; }
bool take_line(std::string_view& in, std::string& s, std::size_t max) {
    const auto end = in.find('\n');
    if (end == in.npos || end > max) { return false; }
    s = in.substr(0, end); in.remove_prefix(end + 1); return true;
}
bool take(std::string_view& in, std::uint64_t& n) {
    std::string field;
    if (!take_line(in, field, 19) || field.empty()) { return false; }
    const auto parsed = std::from_chars(field.data(), field.data() + field.size(), n);
    return parsed.ec == std::errc{} && parsed.ptr == field.data() + field.size() && n <= ceiling;
}
std::string ledger_scope(const SchedulePolicy& p, std::string_view identity) {
    return std::string(identity) + '\t' + p.store_identity + '\t' + p.binding + '\t' + p.rule.predicate.source_unit + '\t' +
        p.rule.predicate.id + '\t' + std::to_string(p.rule.predicate.version) + '\t' +
        std::to_string(static_cast<std::uint32_t>(p.rule.severity));
}
using Records = std::vector<AlertRecord>;
std::string encode(std::string_view identity, const Records& records) {
    std::string out = "KNETSENTRY-ALERTS-V1\t" + std::string(identity) + '\n';
    put(out, records.size());
    for (const auto& a : records) {
        for (const auto n : {a.generation, a.revision, a.created_ms, a.updated_ms, a.acknowledged_ms, a.resolved_ms,
            a.snapshot_revision, static_cast<std::uint64_t>(a.coverage), static_cast<std::uint64_t>(a.status)}) { put(out, n); }
        line(out, a.acknowledged_by); line(out, a.resolved_by);
        put(out, a.evidence.size());
        for (const auto& e : a.evidence) { put(out, e.id); put(out, e.received_ms); put(out, e.source_ms); line(out, e.sha256); put(out, static_cast<std::uint64_t>(e.integrity_origin)); }
        put(out, a.notes.size());
        for (const auto& note : a.notes) { put(out, note.time_ms); line(out, note.analyst); line(out, note.text); }
    }
    out += digest(out) + '\n'; return out;
}
bool decode(const SchedulePolicy& policy, std::string_view identity, std::string_view in, Records& records) {
    const auto original = in;
    const auto prefix = "KNETSENTRY-ALERTS-V1\t" + std::string(identity) + '\n';
    if (!in.starts_with(prefix) || in.size() < prefix.size() + 65 || !in.ends_with('\n') ||
        digest(in.substr(0, in.size() - 65)) != in.substr(in.size() - 65, 64)) { return false; }
    in.remove_suffix(65); in.remove_prefix(prefix.size());
    std::uint64_t count{};
    if (!take(in, count) || count > max_alerts) { return false; }
    std::uint64_t prior_generation{}, prior_trigger{}, prior_created{};
    for (std::uint64_t i = 0; i < count; ++i) {
        AlertRecord a; std::uint64_t coverage{}, status{}, size{};
        if (!take(in, a.generation) || !take(in, a.revision) || !take(in, a.created_ms) || !take(in, a.updated_ms) ||
            !take(in, a.acknowledged_ms) || !take(in, a.resolved_ms) || !take(in, a.snapshot_revision) ||
            !take(in, coverage) || !take(in, status) || coverage > 2 || status > 2 || a.generation == 0 ||
            a.generation < prior_generation || a.created_ms == 0 || a.created_ms < prior_created || a.updated_ms < a.created_ms ||
            a.snapshot_revision == 0 || !take_line(in, a.acknowledged_by, 64) || !take_line(in, a.resolved_by, 64) ||
            !take(in, size) || size == 0 || size != policy.threshold) { return false; }
        a.coverage = coverage == 0 ? Coverage::Unknown : coverage == 1 ? Coverage::Partial : Coverage::SourceObserved;
        a.status = status == 0 ? AlertStatus::Open : status == 1 ? AlertStatus::Acknowledged : AlertStatus::Resolved;
        if ((status == 0 && (a.acknowledged_ms != 0 || !a.acknowledged_by.empty())) ||
            (status > 0 && (!actor(a.acknowledged_by) || a.acknowledged_ms < a.created_ms || a.acknowledged_ms > a.updated_ms)) ||
            (status < 2 && (a.resolved_ms != 0 || !a.resolved_by.empty())) ||
            (status == 2 && (!actor(a.resolved_by) || a.resolved_ms < a.acknowledged_ms || a.resolved_ms > a.updated_ms))) { return false; }
        std::uint64_t prior_id{}, prior_time{};
        for (std::uint64_t j = 0; j < size; ++j) {
            AlertEvidence e; std::uint64_t origin{};
            if (!take(in, e.id) || e.id <= prior_id || !take(in, e.received_ms) || e.received_ms == 0 ||
                e.received_ms < prior_time || e.received_ms > a.created_ms || !take(in, e.source_ms) || !take_line(in, e.sha256, 64) || !hex(e.sha256) ||
                !take(in, origin) || origin > 1) { return false; }
            e.integrity_origin = origin == 0 ? storage::IntegrityOrigin::LegacyBaseline : storage::IntegrityOrigin::Admission;
            prior_id = e.id; prior_time = e.received_ms; a.evidence.push_back(std::move(e));
        }
        if (a.evidence.back().received_ms - a.evidence.front().received_ms > policy.window_ms ||
            (!records.empty() && a.generation == prior_generation &&
                (a.created_ms != records.back().created_ms || a.snapshot_revision != records.back().snapshot_revision ||
                    a.coverage != records.back().coverage)) ||
            prior_id <= prior_trigger || !take(in, size) || size > max_alert_notes || a.revision != 1 + status + size) { return false; }
        prior_time = a.created_ms;
        for (std::uint64_t j = 0; j < size; ++j) {
            AlertNote note;
            if (!take(in, note.time_ms) || note.time_ms < prior_time || note.time_ms > a.updated_ms ||
                !take_line(in, note.analyst, 64) || !actor(note.analyst) || !take_line(in, note.text, max_alert_note_bytes) ||
                !printable(note.text, max_alert_note_bytes)) { return false; }
            prior_time = note.time_ms; a.notes.push_back(std::move(note));
        }
        if (a.updated_ms != std::max({a.created_ms, a.acknowledged_ms, a.resolved_ms, prior_time})) { return false; }
        prior_generation = a.generation; prior_trigger = prior_id; prior_created = a.created_ms;
        records.push_back(std::move(a));
    }
    return in.empty() && encode(identity, records) == original;
}
int locked(std::string_view path) {
    if (::geteuid() == 0 || !agent::valid_journal_directory(path)) { return -1; }
    File dir(open_directory(path));
    if (dir.fd < 0 || !directory_private(dir.fd) || ::flock(dir.fd, LOCK_EX | LOCK_NB) != 0) { return -1; }
    return std::exchange(dir.fd, -1);
}
bool absent(int fd, const char* filename) {
    struct stat st{}; return ::fstatat(fd, filename, &st, AT_SYMLINK_NOFOLLOW) != 0 && errno == ENOENT;
}
bool load(int fd, const SchedulePolicy& policy, std::string_view identity, Records& records) {
    File file(::openat(fd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (file.fd < 0 || !regular_private(file.fd)) { return false; }
    std::array<char, 4096> bytes{}; std::string data;
    for (;;) {
        const auto n = ::read(file.fd, bytes.data(), bytes.size());
        if (n < 0 && errno == EINTR) { continue; }
        if (n < 0) { return false; }
        if (n == 0) { break; }
        const auto size = static_cast<std::size_t>(n);
        if (size > max_state - data.size()) { return false; }
        data.append(bytes.data(), size);
    }
    if (!decode(policy, identity, data, records)) { return false; }
    File temp(::openat(fd, pending, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (temp.fd >= 0) {
        if (!regular_private(temp.fd) || ::unlinkat(fd, pending, 0) != 0) { return false; }
    } else if (errno != ENOENT) { return false; }
    return ::fsync(fd) == 0;
}
AlertResult commit(int fd, std::string_view identity, const Records& records) {
    const auto data = encode(identity, records);
    if (data.size() > max_state) { return AlertResult::Capacity; }
    if (!directory_private(fd)) { return AlertResult::Unavailable; }
    File temp(::openat(fd, pending, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
    if (temp.fd < 0 || !regular_private(temp.fd) || !write_all(temp.fd, data) || ::fsync(temp.fd) != 0 ||
        ::renameat(fd, pending, fd, name) != 0 || ::fsync(fd) != 0) { return AlertResult::Unavailable; }
    return AlertResult::Ok;
}
bool build_alert(const SchedulePolicy& p, const ScheduleReport& report, const ScheduledFinding& finding,
    const storage::EventStore& store, const Engine& engine, std::uint64_t now, AlertRecord& a) {
    if (finding.evidence_ids.size() != p.threshold || finding.received_ms > now) { return false; }
    a.generation = report.generation; a.snapshot_revision = report.revision; a.coverage = report.coverage;
    a.created_ms = now; a.updated_ms = now;
    std::uint64_t previous_id{}, previous_time{};
    for (const auto id : finding.evidence_ids) {
        const auto raw = store.raw(id);
        const auto normalized = store.normalized(id);
        if (raw.status != StoreStatus::Ok || !raw.value || normalized.status != StoreStatus::Ok || !normalized.value) { return false; }
        const auto& r = *raw.value;
        if (id <= previous_id || r.id != id || r.binding != p.binding || r.unit != p.rule.predicate.source_unit ||
            r.mode != agent::JournalMode::Authentication || !r.integrity || !hex(r.integrity->sha256) ||
            r.received_ms == 0 || r.received_ms < previous_time || r.received_ms > finding.received_ms ||
            finding.received_ms - r.received_ms > p.window_ms) { return false; }
        const auto evaluated = engine.evaluate(storage::summarize_event(r, *normalized.value), EvidenceTrust::VerifiedStored, report.coverage);
        if (evaluated.status != EvaluationStatus::Evaluated || evaluated.findings.size() != 1) { return false; }
        if (normalized.value->time_ms > ceiling || (r.integrity->origin != storage::IntegrityOrigin::LegacyBaseline &&
            r.integrity->origin != storage::IntegrityOrigin::Admission)) { return false; }
        a.evidence.push_back({id, r.received_ms, normalized.value->time_ms, r.integrity->sha256, r.integrity->origin});
        previous_id = id; previous_time = r.received_ms;
    }
    return previous_time == finding.received_ms;
}
} // namespace
bool initialize_alerts(const SchedulePolicy& p, std::string_view directory, bool authorized) {
    if (!authorized) { return false; }
    const auto identity = schedule_policy_identity(p);
    if (!identity) { return false; }
    File dir(locked(directory));
    return dir.fd >= 0 && absent(dir.fd, name) && absent(dir.fd, pending) && commit(dir.fd, ledger_scope(p, *identity), {}) == AlertResult::Ok;
}
AlertSnapshot read_alerts(const SchedulePolicy& p, std::string_view directory, bool authorized) {
    AlertSnapshot out;
    if (!authorized) { out.result = AlertResult::Unverified; return out; }
    const auto identity = schedule_policy_identity(p);
    if (!identity) { return out; }
    File dir(locked(directory)); Records records;
    if (dir.fd < 0 || !load(dir.fd, p, ledger_scope(p, *identity), records)) { out.result = AlertResult::Unavailable; return out; }
    out.result = AlertResult::Ok; out.schedule_identity = *identity; out.store_identity = p.store_identity;
    out.binding = p.binding; out.source = p.rule.predicate.source_unit; out.rule_id = p.rule.predicate.id;
    out.rule_version = p.rule.predicate.version; out.severity = p.rule.severity; out.alerts = std::move(records);
    return out;
}
AlertResult consume_alerts(const SchedulePolicy& p, std::string_view directory, std::string_view schedule_directory,
    const storage::EventStore& store, std::uint64_t generation, std::uint64_t now, bool authorized, EvidenceTrust trust) {
    if (!authorized || trust != EvidenceTrust::VerifiedStored) { return AlertResult::Unverified; }
    const auto identity = schedule_policy_identity(p);
    if (!identity || generation == 0 || now == 0 || now > ceiling || directory == schedule_directory ||
        store.durability() != storage::Durability::Durable) { return AlertResult::Invalid; }
    File dir(locked(directory)); Records records;
    if (dir.fd < 0 || !load(dir.fd, p, ledger_scope(p, *identity), records)) { return AlertResult::Unavailable; }
    const auto report = pending_schedule(p, schedule_directory, trust);
    if (report.status != ScheduleStatus::Replay) { return AlertResult::Unavailable; }
    if (report.generation != generation || report.schedule_identity != *identity) { return AlertResult::Conflict; }
    const auto compiled = ValidatedRuleSet::compile(std::span(&p.rule, 1));
    if (!compiled.rules) { return AlertResult::Invalid; }
    const auto pending_index = store.pending(0, std::nullopt, 1);
    if (pending_index.status != StoreStatus::Ok || pending_index.more || !pending_index.ids.empty() || pending_index.revision < report.revision) { return AlertResult::Unavailable; }
    const bool retry = !records.empty() && records.back().generation == generation;
    if (!records.empty() && (generation < records.back().generation || now < records.back().created_ms)) { return AlertResult::Conflict; }
    if (!retry && report.findings.size() > max_alerts - records.size()) { return AlertResult::Capacity; }
    std::size_t seen{};
    for (const auto& finding : report.findings) {
        AlertRecord a;
        if (!build_alert(p, report, finding, store, compiled.rules->engine(), now, a)) { return AlertResult::Unavailable; }
        if (retry) {
            const auto it = std::ranges::find_if(records, [&](const AlertRecord& old) {
                return old.generation == generation && old.evidence.back().id == a.evidence.back().id;
            });
            if (it == records.end() || it->evidence != a.evidence || it->coverage != a.coverage ||
                it->snapshot_revision != a.snapshot_revision) { return AlertResult::Conflict; }
            ++seen;
        } else {
            if (!records.empty() && a.evidence.back().id <= records.back().evidence.back().id) { return AlertResult::Conflict; }
            records.push_back(std::move(a));
        }
    }
    const auto after = store.pending(0, pending_index.revision, 1);
    if (after.status != StoreStatus::Ok || after.revision != pending_index.revision || after.more || !after.ids.empty()) { return AlertResult::Unavailable; }
    if (retry) {
        const auto count = std::ranges::count_if(records, [&](const AlertRecord& a) { return a.generation == generation; });
        return seen == static_cast<std::size_t>(count) ? AlertResult::ExactRetry : AlertResult::Conflict;
    }
    return commit(dir.fd, ledger_scope(p, *identity), records);
}
AlertResult update_alert(const SchedulePolicy& p, std::string_view directory, std::uint64_t generation,
    storage::EventId trigger, std::uint64_t expected_revision, AlertAction action, std::string_view analyst,
    std::string_view note, std::uint64_t now, bool authorized) {
    if (!authorized) { return AlertResult::Unverified; }
    const auto identity = schedule_policy_identity(p);
    if (!identity || generation == 0 || trigger == 0 || expected_revision == 0 || now == 0 || now > ceiling || !actor(analyst) ||
        (action == AlertAction::AddNote ? !printable(note, max_alert_note_bytes) : !note.empty())) { return AlertResult::Invalid; }
    File dir(locked(directory)); Records records;
    if (dir.fd < 0 || !load(dir.fd, p, ledger_scope(p, *identity), records)) { return AlertResult::Unavailable; }
    const auto it = std::ranges::find_if(records, [&](const AlertRecord& a) { return a.generation == generation && a.evidence.back().id == trigger; });
    if (it == records.end()) { return AlertResult::NotFound; }
    auto& a = *it;
    if (a.revision != expected_revision || now < a.updated_ms) { return AlertResult::Conflict; }
    switch (action) {
    case AlertAction::Acknowledge:
        if (a.status != AlertStatus::Open) { return AlertResult::Conflict; }
        a.status = AlertStatus::Acknowledged; a.acknowledged_ms = now; a.acknowledged_by = analyst; break;
    case AlertAction::Resolve:
        if (a.status != AlertStatus::Acknowledged) { return AlertResult::Conflict; }
        a.status = AlertStatus::Resolved; a.resolved_ms = now; a.resolved_by = analyst; break;
    case AlertAction::AddNote:
        if (a.notes.size() >= max_alert_notes) { return AlertResult::Capacity; }
        a.notes.push_back({now, std::string(analyst), std::string(note)}); break;
    default: return AlertResult::Invalid;
    }
    ++a.revision; a.updated_ms = now;
    return commit(dir.fd, ledger_scope(p, *identity), records);
}
} // namespace knetsentry::detection
