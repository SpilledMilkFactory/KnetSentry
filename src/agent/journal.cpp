// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/agent/journal.hpp"
#include "private_state.hpp"
#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstdio>
#include <fcntl.h>
#include <linux/magic.h>
#include <sys/vfs.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>

namespace knetsentry::agent {
namespace {
constexpr std::size_t max_cursor = 1024;
using namespace private_state;
bool cursor_valid(std::string_view value) {
    return !value.empty() && value.size() <= max_cursor &&
        std::ranges::all_of(value, [](char c) { return c >= '!' && c <= '~'; });
}
bool id_valid(std::string_view value) {
    return value.size() == 32 && std::ranges::all_of(value, [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    }) && value != "00000000000000000000000000000000";
}
bool number(std::string_view value, std::uint64_t& out) {
    const auto result = std::from_chars(value.data(), value.data() + value.size(), out);
    return result.ec == std::errc{} && result.ptr == value.data() + value.size();
}
bool record_valid(const JournalRecord& r, std::string_view unit, JournalMode mode) {
    const bool event_valid = mode == JournalMode::Authentication ? valid_auth_event(unit, r.auth) : r.auth == AuthEvent::None;
    const bool audit_valid = mode == JournalMode::Audit ? (unit == "audit" && r.audit_type >= 1000 && r.audit_type <= 65535 && r.audit_id != 0) :
        (r.audit_type == 0 && r.audit_id == 0);
    return event_valid && audit_valid && r.unit == unit && cursor_valid(r.cursor) && id_valid(r.machine) &&
        id_valid(r.boot) && r.realtime_usec != 0 &&
        r.realtime_usec < (std::uint64_t{1} << 55) && r.monotonic_usec < (std::uint64_t{1} << 55);
}
std::string row(const JournalRecord& r) {
    return r.cursor + '\t' + std::to_string(r.realtime_usec) + '\t' +
        std::to_string(r.monotonic_usec) + '\t' + r.machine + '\t' + r.boot + '\t' + r.unit +
        (r.auth == AuthEvent::None ? std::string{} : '\t' + std::string(auth_event_name(r.auth))) +
        (r.audit_type == 0 ? std::string{} : '\t' + std::to_string(r.audit_type) + '\t' + std::to_string(r.audit_id)) + '\n';
}
bool parse_row(std::string_view line, JournalRecord& r, JournalMode mode) {
    if (mode == JournalMode::Audit) {
        const auto id_tab = line.rfind('\t');
        if (id_tab == line.npos || !parse_audit_number(line.substr(id_tab + 1), r.audit_id)) { return false; }
        line = line.substr(0, id_tab);
        const auto type_tab = line.rfind('\t');
        if (type_tab == line.npos || !parse_audit_number(line.substr(type_tab + 1), r.audit_type)) { return false; }
        line = line.substr(0, type_tab);
    }
    if (mode == JournalMode::Authentication) {
        const auto tab = line.rfind('\t');
        if (tab == line.npos) { return false; }
        r.auth = parse_auth_event(line.substr(tab + 1));
        if (r.auth == AuthEvent::None) { return false; }
        line = line.substr(0, tab);
    }
    std::array<std::string_view, 6> fields{};
    for (std::size_t i = 0; i < fields.size() - 1; ++i) {
        const auto tab = line.find('\t');
        if (tab == line.npos) { return false; }
        fields[i] = line.substr(0, tab);
        line.remove_prefix(tab + 1);
    }
    fields.back() = line;
    r.cursor = fields[0]; r.machine = fields[3]; r.boot = fields[4]; r.unit = fields[5];
    return number(fields[1], r.realtime_usec) && number(fields[2], r.monotonic_usec);
}
} // namespace
bool valid_delivery_binding(std::string_view binding) noexcept {
    return binding.size() == 96 && std::ranges::all_of(binding, [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    }) && binding.substr(0, 32) != "00000000000000000000000000000000" &&
        binding.substr(32) != "0000000000000000000000000000000000000000000000000000000000000000";
}
bool valid_delivery_row(std::string_view wire, std::string_view unit, JournalMode mode) {
    if ((mode != JournalMode::Metadata && mode != JournalMode::Authentication && mode != JournalMode::Audit) ||
        (mode == JournalMode::Audit ? unit != "audit" : !valid_journal_unit(unit)) ||
        (mode == JournalMode::Authentication && !valid_auth_unit(unit)) ||
        wire.empty() || wire.size() > 2048 || !wire.ends_with('\n')) { return false; }
    JournalRecord record;
    return parse_row(wire.substr(0, wire.size() - 1), record, mode) &&
        record_valid(record, unit, mode) && row(record) == wire;
}
bool parse_audit_number(std::string_view value, std::uint64_t& output) noexcept {
    if (value.empty() || value.size() > 20 || (value.size() > 1 && value.front() == '0') ||
        !std::ranges::all_of(value, [](char c) { return c >= '0' && c <= '9'; })) { return false; }
    return number(value, output);
}
bool valid_journal_unit(std::string_view unit) noexcept {
    return unit.size() > 8 && unit.size() <= 128 && unit.ends_with(".service") &&
        std::ranges::all_of(unit, [](char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == '@';
        });
}
bool valid_journal_directory(std::string_view path) noexcept {
    if (path.size() < 2 || path.size() > 4095 || path.front() != '/' || path.back() == '/') { return false; }
    path.remove_prefix(1);
    while (!path.empty()) {
        const auto slash = path.find('/');
        const auto part = path.substr(0, slash);
        if (part.empty() || part == "." || part == ".." ||
            !std::ranges::all_of(part, [](char c) { return c >= ' ' && c <= '~'; })) { return false; }
        if (slash == path.npos) { return true; }
        path.remove_prefix(slash + 1);
    }
    return false;
}
JournalCollector::JournalCollector(JournalSource& source, std::string unit, std::string directory, JournalMode mode, std::string binding, std::string privacy_fingerprint, bool redact_auth)
    : source_(source), mode_(mode),
      state_name_(mode == JournalMode::Audit ? "audit-m54.v1" :
                  mode == JournalMode::Authentication ? "auth-m53.v1" : "journal-m52.v1"),
      pending_name_(mode == JournalMode::Audit ? "audit-m54.pending" :
                    mode == JournalMode::Authentication ? "auth-m53.pending" : "journal-m52.pending"), unit_(std::move(unit)), directory_(std::move(directory)), binding_(std::move(binding)),
      privacy_fingerprint_(std::move(privacy_fingerprint)), redact_auth_(redact_auth) {
    if (!binding_.empty()) {
        state_name_ = "telemetry-m55.v1";
        pending_name_ = "telemetry-m55.pending";
    }
}
bool JournalCollector::fail(const char* reason) noexcept {
    error_ = reason;
    stop();
    return false;
}
bool JournalCollector::block_source(const char* reason) noexcept {
    if (binding_.empty()) { return fail(reason); }
    // Source visibility may disappear while disconnected. Do not make already
    // committed evidence inaccessible; no collection resumes without restart.
    error_ = reason;
    collection_blocked_ = true;
    source_.close();
    return false;
}
void JournalCollector::stop() noexcept {
    running_ = false;
    source_.close();
    if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
}
bool JournalCollector::load() {
    state_ = std::string(mode_ == JournalMode::Audit ? "KNETSENTRY-AUDIT-V1\t" :
                         mode_ == JournalMode::Authentication ? "KNETSENTRY-AUTH-V1\t" : "KNETSENTRY-JOURNAL-V1\t") + unit_ + '\n';
    if (!binding_.empty()) {
        state_ = "KNETSENTRY-OUTBOX-V1\t" + binding_ + '\t' + state_;
    }
    if (!privacy_fingerprint_.empty()) { state_ = "KNETSENTRY-PRIVACY-V1\t" + privacy_fingerprint_ + '\n' + state_; }
    header_ = state_;
    if (!binding_.empty()) { state_ += '\n'; }
    File file(::openat(fd_, state_name_, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
    if (file.fd < 0) { return errno == ENOENT; }
    if (!regular_private(file.fd)) { return false; }
    state_.clear();
    std::array<char, 4096> buffer{};
    for (;;) {
        const auto n = ::read(file.fd, buffer.data(), buffer.size());
        if (n < 0 && errno == EINTR) { continue; }
        if (n < 0) { return false; }
        if (n == 0) { break; }
        state_.append(buffer.data(), static_cast<std::size_t>(n));
        if (state_.size() > max_state) { return false; }
    }
    if (!state_.starts_with(header_)) { return false; }
    std::string_view rest(state_);
    rest.remove_prefix(header_.size());
    if (!binding_.empty()) {
        const auto end = rest.find('\n');
        if (end == rest.npos) { return false; }
        cursor_ = rest.substr(0, end);
        if (!cursor_.empty() && !cursor_valid(cursor_)) { return false; }
        rest.remove_prefix(end + 1);
    }
    while (!rest.empty()) {
        const auto end = rest.find('\n');
        if (end == rest.npos || ++count_ > max_records) { return false; }
        JournalRecord record;
        if (!parse_row(rest.substr(0, end), record, mode_) || !record_valid(record, unit_, mode_) ||
            (mode_ == JournalMode::Authentication && (record.auth == AuthEvent::Redacted) != redact_auth_) ||
            std::ranges::find(seen_, record.cursor) != seen_.end()) { return false; }
        if (binding_.empty()) { cursor_ = record.cursor; }
        else {
            if (row(record) != rest.substr(0, end + 1)) { return false; }
            queued_.emplace_back(rest.substr(0, end + 1));
        }
        seen_.push_back(record.cursor);
        rest.remove_prefix(end + 1);
    }
    return binding_.empty() || queued_.empty() || seen_.back() == cursor_;
}
bool JournalCollector::start() noexcept {
    if ((!privacy_fingerprint_.empty() && (privacy_fingerprint_.size() != 64 ||
        !std::ranges::all_of(privacy_fingerprint_, [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); }))) ||
        (redact_auth_ && (mode_ != JournalMode::Authentication || privacy_fingerprint_.empty())) ||
        (!binding_.empty() && !valid_delivery_binding(binding_)) ||
        (mode_ != JournalMode::Metadata && mode_ != JournalMode::Authentication && mode_ != JournalMode::Audit) ||
        started_ || (mode_ == JournalMode::Audit ? unit_ != "audit" : !valid_journal_unit(unit_)) || !valid_journal_directory(directory_) ||
        (mode_ == JournalMode::Authentication && !valid_auth_unit(unit_))) { return false; }
    started_ = true;
    try {
        fd_ = open_directory(directory_);
        if (fd_ < 0 || !directory_private(fd_) || ::flock(fd_, LOCK_EX | LOCK_NB) != 0) {
            return fail("unsafe or busy state directory");
        }
        if (!load()) { return fail("invalid or inaccessible state"); }
        // A crash before rename leaves only an uncommitted temporary file. Never
        // unlink an unverified object, and never use pending contents as a cursor.
        File pending(::openat(fd_, pending_name_, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
        if (pending.fd >= 0) {
            if (!regular_private(pending.fd) || ::unlinkat(fd_, pending_name_, 0) != 0 ||
                ::fsync(fd_) != 0) { return fail("unsafe pending state"); }
        } else if (errno != ENOENT) { return fail("unsafe pending state"); }
        running_ = true;
        error_ = "none";
        if (!source_.open(unit_)) {
            (void)block_source("journal open failed");
            return running_;
        }
        if (!source_.resume(cursor_)) {
            (void)block_source("journal checkpoint unavailable");
            return running_;
        }
        return true;
    } catch (...) { return fail("journal startup failed"); }
}
bool JournalCollector::replace_state(std::string_view next) {
    if (!directory_private(fd_)) { return false; }
    if (next.size() > max_state) { return false; }
    File pending(::openat(fd_, pending_name_, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
    if (pending.fd < 0 || !regular_private(pending.fd) || !write_all(pending.fd, next) ||
        ::fsync(pending.fd) != 0 || ::renameat(fd_, pending_name_, fd_, state_name_) != 0 ||
        ::fsync(fd_) != 0) { return false; }
    state_ = next;
    return true;
}
bool JournalCollector::commit(const JournalRecord& record) {
    auto encoded = row(record);
    auto next = state_ + encoded;
    if (!binding_.empty()) {
        next = header_ + record.cursor + '\n';
        for (const auto& item : queued_) { next += item; }
        next += encoded;
    }
    if (!replace_state(next)) { return false; }
    if (!binding_.empty()) { queued_.push_back(std::move(encoded)); }
    cursor_ = record.cursor;
    seen_.push_back(cursor_);
    ++count_;
    return true;
}
std::string_view JournalCollector::front() const noexcept {
    if (!running_ || binding_.empty() || queued_.empty()) { return {}; }
    return queued_.front();
}
bool JournalCollector::acknowledge(std::string_view expected) noexcept {
    try {
        if (expected.empty() || front() != expected) { return false; }
        auto next = header_ + cursor_ + '\n';
        for (std::size_t i = 1; i < queued_.size(); ++i) { next += queued_[i]; }
        if (!replace_state(next)) { return fail("telemetry acknowledgment commit failed"); }
        queued_.erase(queued_.begin());
        seen_.erase(seen_.begin());
        --count_;
        return true;
    } catch (...) { return fail("telemetry acknowledgment failed"); }
}
bool JournalCollector::pump() noexcept {
    if (!running_ || collection_blocked_) { return false; }
    try {
        if (!directory_private(fd_)) { return fail("unsafe state directory"); }
        if (backpressured()) { return true; }
        if (!source_.resume(cursor_)) { return block_source("journal checkpoint unavailable"); }
        for (std::size_t i = 0; i < batch_size; ++i) {
            // Backpressure: do not consume a source record without queue capacity.
            if (!binding_.empty() && count_ >= max_records) { return true; }
            JournalRecord record;
            const auto result = source_.next(record);
            if (result == JournalResult::End) { return true; }
            if (result != JournalResult::Record || !record_valid(record, unit_, mode_) ||
            (mode_ == JournalMode::Authentication && (record.auth == AuthEvent::Redacted) != redact_auth_) ||
                (record.cursor == cursor_ || std::ranges::find(seen_, record.cursor) != seen_.end())) { return block_source("invalid journal record"); }
            if (count_ >= max_records) { return fail("journal state capacity reached"); }
            if (!commit(record)) { return fail("journal state commit failed"); }
        }
        return true;
    } catch (...) { return fail("journal collection failed"); }
}
} // namespace knetsentry::agent
