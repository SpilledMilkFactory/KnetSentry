// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/service/alert_query.hpp>
#include <algorithm>
#include <charconv>
#include <limits>
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <knetsentry/agent/journal.hpp>
namespace knetsentry::service {
namespace {
using namespace detection;
constexpr auto ceiling = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
bool hex(std::string_view s, std::size_t n) {
    return s.size() == n && std::ranges::all_of(s, [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}
bool number(std::string_view s, std::uint64_t& n) {
    if (s.empty() || s.size() > 19 || (s.size() > 1 && s.front() == '0')) { return false; }
    const auto r = std::from_chars(s.data(), s.data() + s.size(), n);
    return r.ec == std::errc{} && r.ptr == s.data() + s.size() && n <= ceiling;
}
bool token(std::string_view s) {
    return !s.empty() && s.size() <= 128 && std::ranges::all_of(s, [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_';
    });
}
std::vector<std::string_view> split(std::string_view s) {
    std::vector<std::string_view> out;
    while (!s.empty()) {
        const auto pos = s.find(' '); out.push_back(s.substr(0, pos));
        if (pos == s.npos) { break; }
        s.remove_prefix(pos + 1);
        if (s.empty()) { out.emplace_back(); }
    }
    return out;
}
std::string_view take_line(std::string_view& s) {
    const auto end = s.find('\n');
    if (end == s.npos) { s = {}; return {}; }
    const auto line = s.substr(0, end); s.remove_prefix(end + 1); return line;
}
std::string n(std::uint64_t v) { return std::to_string(v); }
bool valid(const AlertQuery& q) {
    if (q.severity < -1 || q.severity > 5 || q.offset > max_alerts || q.generation > ceiling || q.trigger > ceiling || q.revision > ceiling || q.evidence > ceiling) { return false; }
    switch (q.operation) {
    case AlertQuery::Operation::List: return q.generation == 0 && q.trigger == 0 && q.revision == 0 && q.evidence == 0 && ((q.offset == 0 && q.session.empty()) || (q.offset > 0 && hex(q.session,32)));
    case AlertQuery::Operation::Acknowledge: return q.severity == -1 && q.offset == 0 && q.generation && q.trigger && q.revision && q.evidence == 0 && hex(q.session,32);
    case AlertQuery::Operation::Evidence: return q.severity == -1 && q.offset == 0 && q.generation && q.trigger && q.revision && q.evidence && hex(q.session,32);
    }
    return false;
}
} // namespace
std::optional<detection::SchedulePolicy> alert_profile(std::string_view scope) {
    if (scope.size() != 161 || scope[64] != ':' || !hex(scope.substr(0,64),64) || !hex(scope.substr(65),96)) { return {}; }
    SchedulePolicy p; p.store_identity = scope.substr(0,64); p.binding = scope.substr(65);
    p.threshold = 2; p.interval_ms = 1; p.suppression_ms = 0;
    p.rule.schema_version = ValidatedRuleSet::schema_version;
    p.rule.ocsf_version = agent::NormalizedEvent::schema_version; p.rule.mapping_revision = agent::NormalizedEvent::mapping_revision;
    p.rule.predicate = {"ssh-failure", 1, agent::OcsfActivity::Logon, agent::OcsfStatus::Failure, "ssh.service"};
    p.rule.title = "Authentication failures"; p.rule.description = "Two scoped SSH failures.";
    p.rule.severity = RuleSeverity::Medium; p.rule.source_mode = agent::JournalMode::Authentication;
    if (!schedule_policy_identity(p)) { return {}; }
    return p;
}
std::optional<detection::SchedulePolicy> load_alert_profile(std::string_view directory) {
    if (::geteuid() == 0 || !agent::valid_journal_directory(directory)) { return {}; }
    struct Descriptor final {
        int fd;
        explicit Descriptor(int value) : fd(value) {}
        ~Descriptor() { if (fd >= 0) { ::close(fd); } }
        Descriptor(const Descriptor&) = delete; Descriptor& operator=(const Descriptor&) = delete;
    } dir(::open("/",O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (dir.fd < 0) { return {}; }
    directory.remove_prefix(1);
    while (!directory.empty()) {
        const auto slash = directory.find('/'); const std::string component(directory.substr(0,slash));
        const auto next = ::openat(dir.fd,component.c_str(),O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next < 0) { return {}; }
        ::close(dir.fd); dir.fd = next;
        if (slash == directory.npos) { break; }
        directory.remove_prefix(slash+1);
    }
    struct stat info{};
    if (::fstat(dir.fd,&info) != 0 || info.st_uid != ::geteuid() || (info.st_mode & 07777U) != 0700U) { return {}; }
    Descriptor file(::openat(dir.fd,"alert-scope-m77.v1",O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (file.fd < 0 || ::fstat(file.fd,&info) != 0 || !S_ISREG(info.st_mode) || info.st_uid != ::geteuid() || info.st_nlink != 1 || (info.st_mode & 07777U) != 0600U || info.st_size != 162) { return {}; }
    std::array<char,163> buffer{}; std::size_t size{};
    while (size < buffer.size()) {
        const auto got = ::read(file.fd,buffer.data()+size,buffer.size()-size);
        if (got < 0 && errno == EINTR) { continue; }
        if (got < 0) { return {}; }
        if (got == 0) { break; }
        size += static_cast<std::size_t>(got);
    }
    if (size != 162 || buffer[161] != '\n') { return {}; }
    return alert_profile(std::string_view(buffer.data(),161));
}
std::string encode_alert_request(const AlertQuery& q, std::string_view id) {
    if (!valid(q) || !hex(id,16)) { return {}; }
    const auto op = q.operation == AlertQuery::Operation::List ? "L" : q.operation == AlertQuery::Operation::Acknowledge ? "A" : "E";
    return "KSIPC/1 ALERTS " + std::string(id) + " " + op + " " + std::to_string(q.severity + 1) + " " + n(q.offset) + " " + n(q.generation) + " " + n(q.trigger) + " " + n(q.revision) + " " + n(q.evidence) + " " + (q.session.empty() ? "-" : q.session) + "\n";
}
std::optional<AlertQuery> decode_alert_request(std::string_view payload, std::string_view id) {
    if (payload.size() > 256 || !payload.ends_with('\n')) { return {}; }
    payload.remove_suffix(1); const auto f = split(payload); AlertQuery q; std::uint64_t sev{};
    if (f.size() != 11 || f[0] != "KSIPC/1" || f[1] != "ALERTS" || f[2] != id || !number(f[4],sev) || sev > 6 ||
        !number(f[5],q.offset) || !number(f[6],q.generation) || !number(f[7],q.trigger) || !number(f[8],q.revision) || !number(f[9],q.evidence)) { return {}; }
    if (f[3] == "L") { q.operation = AlertQuery::Operation::List; }
    else if (f[3] == "A") { q.operation = AlertQuery::Operation::Acknowledge; }
    else if (f[3] == "E") { q.operation = AlertQuery::Operation::Evidence; } else { return {}; }
    q.severity = static_cast<int>(sev) - 1; if (f[10] != "-") { q.session = f[10]; }
    if (encode_alert_request(q,id) != std::string(payload) + '\n') { return {}; }
    return q;
}
std::string query_alerts(const SchedulePolicy& policy, std::string_view directory, const storage::EventStore& store,
    std::string_view session, const AlertQuery& q, std::string_view id, bool writable, std::string_view actor, std::uint64_t now) {
    if (!valid(q) || !hex(id,16) || !hex(session,32)) { return {}; }
    const auto header = [&](std::string_view result, bool more = false) {
        return "KSIPC/1 ALERTS " + std::string(id) + " " + std::string(result) + " " + std::string(session) + " " + (more ? "1" : "0") + " " + (writable ? "1" : "0") + "\n";
    };
    if (!q.session.empty() && q.session != session) { return header("STALE"); }
    const auto snapshot = read_alerts(policy,directory,true,false);
    if (snapshot.result != AlertResult::Ok || store.durability() != storage::Durability::Durable) { return header("UNAVAILABLE"); }
    if (q.operation == AlertQuery::Operation::List) {
        std::string rows; std::uint64_t matched{}; std::size_t count{}; bool more{};
        for (const auto& a : snapshot.alerts) {
            if (q.severity >= 0 && static_cast<int>(snapshot.severity) != q.severity) { continue; }
            if (matched++ < q.offset) { continue; }
            if (count == alert_page_size) { more = true; break; }
            ++count;
            rows += n(a.generation) + " " + n(a.evidence.back().id) + " " + n(a.revision) + " " + n(static_cast<std::uint64_t>(snapshot.severity)) + " " + n(static_cast<std::uint64_t>(a.status)) + " " + n(a.created_ms) + " " + n(a.updated_ms) + " " + n(static_cast<std::uint64_t>(a.coverage)) + " " + snapshot.rule_id + " " + snapshot.source;
            for (const auto& e : a.evidence) { rows += " " + n(e.id); } rows += '\n';
        }
        auto out = header("OK",more) + rows; return out.size() <= max_alert_response ? out : header("UNAVAILABLE");
    }
    const auto it = std::ranges::find_if(snapshot.alerts,[&](const auto& a) { return a.generation == q.generation && a.evidence.back().id == q.trigger; });
    if (it == snapshot.alerts.end() || it->revision != q.revision) { return header("STALE"); }
    if (q.operation == AlertQuery::Operation::Acknowledge) {
        if (!writable) { return header("DENIED"); }
        const auto result = update_alert(policy,directory,q.generation,q.trigger,q.revision,AlertAction::Acknowledge,actor,"",now,true);
        return header(result == AlertResult::Ok ? "OK" : result == AlertResult::Conflict ? "STALE" : "UNAVAILABLE");
    }
    const auto e = std::ranges::find_if(it->evidence,[&](const auto& item) { return item.id == q.evidence; });
    if (e == it->evidence.end()) { return header("DENIED"); }
    const auto raw = store.raw(e->id); const auto normalized = store.normalized(e->id);
    if (raw.status != storage::StoreStatus::Ok || normalized.status != storage::StoreStatus::Ok || !raw.value || !normalized.value || !raw.value->integrity ||
        raw.value->id != e->id || raw.value->binding != snapshot.binding || raw.value->unit != snapshot.source || raw.value->mode != agent::JournalMode::Authentication || raw.value->received_ms != e->received_ms || normalized.value->time_ms != e->source_ms ||
        raw.value->integrity->sha256 != e->sha256 || raw.value->integrity->origin != e->integrity_origin) { return header("UNAVAILABLE"); }
    const auto summary = storage::summarize_event(*raw.value,*normalized.value);
    return header("OK") + n(e->id) + " " + n(e->source_ms) + " " + n(e->received_ms) + " " + n(static_cast<std::uint64_t>(summary.status_id)) + " " + n(static_cast<std::uint64_t>(e->integrity_origin)) + "\n";
}
std::optional<AlertPage> decode_alert_page(std::string_view payload, std::string_view id, const AlertQuery& q) {
    if (!valid(q) || !hex(id,16) || payload.size() > max_alert_response || !payload.ends_with('\n')) { return {}; }
    const auto h = split(take_line(payload)); AlertPage page;
    if (h.size() != 7 || h[0] != "KSIPC/1" || h[1] != "ALERTS" || h[2] != id || !hex(h[4],32) || (h[5] != "0" && h[5] != "1") || (h[6] != "0" && h[6] != "1")) { return {}; }
    page.result = h[3]; page.session = h[4]; page.more = h[5] == "1"; page.writable = h[6] == "1";
    if (page.result != "OK") {
        if ((page.result != "STALE" && page.result != "DENIED" && page.result != "UNAVAILABLE") || page.more || !payload.empty()) { return {}; }
        return page;
    }
    if (!q.session.empty() && q.session != page.session) { return {}; }
    if (q.operation == AlertQuery::Operation::Acknowledge) { return payload.empty() && !page.more && page.writable ? std::optional<AlertPage>{page} : std::nullopt; }
    if (q.operation == AlertQuery::Operation::Evidence) {
        const auto f = split(take_line(payload));
        if (page.more || !payload.empty() || f.size() != 5 || !number(f[0],page.evidence) || page.evidence != q.evidence || !number(f[1],page.source_time) || !number(f[2],page.receiver_time) || !page.receiver_time || !number(f[3],page.outcome) || page.outcome > 2 || !number(f[4],page.origin) || page.origin > 1) { return {}; }
        return page;
    }
    while (!payload.empty()) {
        const auto f = split(take_line(payload)); AlertRow r;
        if (page.rows.size() == alert_page_size || f.size() < 11 || f.size() > 26 || !number(f[0],r.generation) || !r.generation || !number(f[1],r.trigger) || !r.trigger || !number(f[2],r.revision) || !r.revision || !number(f[3],r.severity) || r.severity > 5 || (q.severity >= 0 && r.severity != static_cast<std::uint64_t>(q.severity)) || !number(f[4],r.status) || r.status > 2 || !number(f[5],r.created) || !r.created || !number(f[6],r.updated) || r.updated < r.created || !number(f[7],r.coverage) || r.coverage > 2 || !token(f[8]) || !token(f[9])) { return {}; }
        r.rule = f[8]; r.source = f[9];
        for (std::size_t i=10;i<f.size();++i) { std::uint64_t value{}; if (!number(f[i],value) || !value || (!r.evidence.empty() && value <= r.evidence.back())) { return {}; } r.evidence.push_back(value); }
        if (r.evidence.back() != r.trigger || (!page.rows.empty() && (r.generation < page.rows.back().generation || (r.generation == page.rows.back().generation && r.trigger <= page.rows.back().trigger)))) { return {}; }
        page.rows.push_back(std::move(r));
    }
    if (page.more && (page.rows.size() != alert_page_size || q.offset + alert_page_size >= max_alerts)) { return {}; }
    return page;
}
} // namespace knetsentry::service
