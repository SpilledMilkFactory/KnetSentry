// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/agent/delivery.hpp>
#include "private_state.hpp"
#include <algorithm>
#include <array>
#include <cstdio>
#include <sys/file.h>
#include <utility>

namespace knetsentry::agent {
namespace {
using namespace private_state;
constexpr const char* inbox_name = "telemetry-inbox-m55.v1";
constexpr const char* pending_name = "telemetry-inbox-m55.pending";
std::string_view cursor(std::string_view row) noexcept { return row.substr(0, row.find('\t')); }
} // namespace
ReceiptInbox::ReceiptInbox(enrollment::EndpointId endpoint, identity::Fingerprint manager,
    JournalMode mode, std::string unit, std::string directory)
    : endpoint_(endpoint), mode_(mode), unit_(std::move(unit)), directory_(std::move(directory)),
      binding_(delivery_binding(endpoint, manager)) {}
ReceiptInbox::~ReceiptInbox() { if (fd_ >= 0) { ::close(fd_); } }
bool ReceiptInbox::fail() noexcept {
    ready_ = false;
    if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
    return false;
}
bool ReceiptInbox::load() {
    state_ = header_;
    File file(::openat(fd_, inbox_name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
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
    while (!rest.empty()) {
        const auto end = rest.find('\n');
        if (end == rest.npos || rows_.size() >= JournalCollector::max_records) { return false; }
        const auto entry = rest.substr(0, end + 1);
        if (!valid_delivery_row(entry, unit_, mode_) || std::ranges::any_of(rows_, [&](const auto& previous) {
            return cursor(previous) == cursor(entry);
        })) { return false; }
        rows_.emplace_back(entry);
        rest.remove_prefix(end + 1);
    }
    return true;
}
bool ReceiptInbox::start() noexcept {
    if (started_) { return false; }
    started_ = true;
    try {
        if (!valid_delivery_binding(binding_) || !valid_journal_directory(directory_) ||
            (mode_ != JournalMode::Metadata && mode_ != JournalMode::Authentication && mode_ != JournalMode::Audit) ||
            (mode_ == JournalMode::Audit ? unit_ != "audit" : !valid_journal_unit(unit_)) ||
            (mode_ == JournalMode::Authentication && !valid_auth_unit(unit_))) { return false; }
        const char* mode = mode_ == JournalMode::Audit ? "audit" : mode_ == JournalMode::Authentication ? "auth" : "metadata";
        header_ = "KNETSENTRY-INBOX-V1\t" + binding_ + '\t' + mode + '\t' + unit_ + '\n';
        fd_ = open_directory(directory_);
        if (fd_ < 0 || !directory_private(fd_) || ::flock(fd_, LOCK_EX | LOCK_NB) != 0 || !load()) { return fail(); }
        File pending(::openat(fd_, pending_name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK));
        if (pending.fd >= 0) {
            if (!regular_private(pending.fd) || ::unlinkat(fd_, pending_name, 0) != 0 || ::fsync(fd_) != 0) { return fail(); }
        } else if (errno != ENOENT) { return fail(); }
        ready_ = true;
        return true;
    } catch (...) { return fail(); }
}
bool ReceiptInbox::commit(const enrollment::EndpointId& endpoint, std::string_view binding, std::string_view canonical_row) noexcept {
    if (!ready_ || endpoint != endpoint_ || binding != binding_) { return false; }
    try {
        if (!directory_private(fd_)) { return fail(); }
        if (!valid_delivery_row(canonical_row, unit_, mode_)) { return false; }
        const auto existing = std::ranges::find_if(rows_, [&](const auto& previous) {
            return cursor(previous) == cursor(canonical_row);
        });
        // Exact retries can be acknowledged even at capacity. Conflicting
        // payloads for an already accepted cursor never replace evidence.
        if (existing != rows_.end()) { return *existing == canonical_row; }
        if (rows_.size() >= JournalCollector::max_records || canonical_row.size() > max_state - state_.size()) { return false; }
        auto next = state_;
        next += canonical_row;
        File pending(::openat(fd_, pending_name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
        if (pending.fd < 0 || !regular_private(pending.fd) || !write_all(pending.fd, next) ||
            ::fsync(pending.fd) != 0 || ::renameat(fd_, pending_name, fd_, inbox_name) != 0 || ::fsync(fd_) != 0) { return fail(); }
        state_ = std::move(next);
        rows_.emplace_back(canonical_row);
        return true;
    } catch (...) { return fail(); }
}
} // namespace knetsentry::agent
