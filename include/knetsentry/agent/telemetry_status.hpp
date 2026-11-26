// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once

#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <fcntl.h>
#include <initializer_list>
#include <optional>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

namespace knetsentry::agent {
// Explicit launcher-provided, single-writer local pipe. No endpoint identity,
// raw observations, filesystem locations, policy strings or credentials.
inline constexpr std::uint64_t status_fresh_ms = 5000;
inline constexpr std::size_t status_max_line = 160;
static_assert(status_max_line < 512); // POSIX minimum atomic pipe-write size.
struct TelemetryStatus {
    std::string_view mode, health;
    std::uint64_t stamp{}, observations{}, interval_ms{};
    std::optional<std::uint64_t> queued;
};
inline std::uint64_t status_now() noexcept {
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}
inline bool status_number(std::string_view field, std::uint64_t& value) noexcept {
    if (field.empty() || (field.size() > 1 && field.front() == '0')) { return false; }
    const auto result = std::from_chars(field.data(), field.data() + field.size(), value);
    return result.ec == std::errc{} && result.ptr == field.data() + field.size();
}
inline std::optional<TelemetryStatus> parse_status(std::string_view line) noexcept {
    if (line.size() > status_max_line) { return std::nullopt; }
    std::array<std::string_view, 7> fields{};
    for (std::size_t i = 0; i < fields.size(); ++i) {
        const auto split = line.find('\t');
        if ((i == fields.size() - 1) != (split == std::string_view::npos)) { return std::nullopt; }
        fields[i] = line.substr(0, split);
        if (split != std::string_view::npos) { line.remove_prefix(split + 1); }
    }
    if (fields[0] != "KSSTAT1") { return std::nullopt; }
    TelemetryStatus out{};
    // Assign static strings, never retain views into caller-controlled buffers.
    for (const std::string_view mode : {"none", "journal", "authentication", "audit", "fim", "fim-metadata"}) {
        if (fields[1] == mode) { out.mode = mode; }
    }
    for (const std::string_view health : {"idle", "active", "paused", "blocked", "source-failed", "failed"}) {
        if (fields[2] == health) { out.health = health; }
    }
    if (out.mode.empty() || out.health.empty() || !status_number(fields[3], out.stamp) || out.stamp == 0 ||
        !status_number(fields[4], out.observations) || !status_number(fields[5], out.interval_ms)) { return std::nullopt; }
    if (fields[6] != "-") {
        std::uint64_t queue{};
        if (!status_number(fields[6], queue) || queue > 128) { return std::nullopt; }
        out.queued = queue;
    }
    const bool fim = out.mode == "fim" || out.mode == "fim-metadata";
    if ((out.mode == "none") != (out.health == "idle") ||
        ((fim || out.mode == "none") && out.queued) ||
        (out.health == "paused" && (!out.queued || *out.queued != 128)) ||
        (out.health == "blocked" && !out.queued) ||
        ((out.health == "failed" || out.health == "source-failed") && out.queued) ||
        (out.health == "active" && out.queued && *out.queued == 128) ||
        (out.interval_ms != 0 && (out.health != "active" || out.interval_ms > 60000)) ||
        (out.interval_ms == 0 && out.observations != 0) || out.observations > (fim ? 8U : 16U)) {
        return std::nullopt;
    }
    return out;
}
inline bool status_pipe(int fd, int direction) noexcept {
    struct stat info{};
    const int flags = ::fcntl(fd, F_GETFL);
    return flags >= 0 && (flags & O_ACCMODE) == direction && ::fstat(fd, &info) == 0 &&
        S_ISFIFO(info.st_mode) && ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}
class StatusWriter {
public:
    StatusWriter() = default;
    StatusWriter(const StatusWriter&) = delete;
    StatusWriter& operator=(const StatusWriter&) = delete;
    ~StatusWriter() { if (fd_ >= 0) { ::close(fd_); } }
    bool attach(int fd) noexcept {
        if (fd_ >= 0 || !status_pipe(fd, O_WRONLY)) { return false; }
        sigset_t signal{};
        if (::sigemptyset(&signal) != 0 || ::sigaddset(&signal, SIGPIPE) != 0 ||
            ::sigprocmask(SIG_BLOCK, &signal, nullptr) != 0 || ::fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) { return false; }
        fd_ = fd;
        return true;
    }
    void publish(const char* mode, const char* health, std::uint64_t observations = 0,
                 int queued = -1) noexcept {
        if (fd_ < 0) { return; }
        const auto now = status_now();
        const auto interval = previous_ != 0 && now > previous_ && now - previous_ <= 60000 &&
            std::string_view(health) == "active" ? now - previous_ : 0;
        if (now <= previous_) { return; }
        previous_ = now;
        if (interval == 0) { observations = 0; }
        std::array<char, 24> queue{};
        if (queued >= 0) { std::snprintf(queue.data(), queue.size(), "%d", queued); }
        else { queue[0] = '-'; }
        std::array<char, status_max_line> bytes{};
        const int n = std::snprintf(bytes.data(), bytes.size(), "KSSTAT1\t%s\t%s\t%llu\t%llu\t%llu\t%s\n",
            mode, health, static_cast<unsigned long long>(now), static_cast<unsigned long long>(observations),
            static_cast<unsigned long long>(interval), queue.data());
        if (n <= 0 || static_cast<std::size_t>(n) >= bytes.size()) { return; }
        const auto result = ::write(fd_, bytes.data(), static_cast<std::size_t>(n));
        // One bounded atomic pipe write. Never delay collection for observers.
        if (result != n && !(result < 0 && (errno == EAGAIN || errno == EINTR))) {
            ::close(fd_);
            fd_ = -1;
        }
    }
private:
    int fd_{-1};
    std::uint64_t previous_{};
};

enum class StatusLink { Unconfigured, Waiting, Current, Stale, Disconnected, Invalid };
class StatusReader {
public:
    StatusReader() = default;
    StatusReader(const StatusReader&) = delete;
    StatusReader& operator=(const StatusReader&) = delete;
    ~StatusReader() { if (fd_ >= 0) { ::close(fd_); } }
    bool attach(int fd) noexcept {
        if (link_ != StatusLink::Unconfigured) { return false; }
        fd_ = ::fcntl(fd, F_DUPFD_CLOEXEC, 4);
        if (fd_ < 0 || !status_pipe(fd_, O_RDONLY)) { end(StatusLink::Invalid); return false; }
        link_ = StatusLink::Waiting;
        last_ = 0;
        opened_ = status_now();
        return true;
    }
    [[nodiscard]] StatusLink link() const noexcept { return link_; }
    [[nodiscard]] const std::optional<TelemetryStatus>& current() const noexcept { return current_; }
    [[nodiscard]] bool last_failure() const noexcept { return last_failure_; }
    bool poll() noexcept {
        if (fd_ < 0) { return false; }
        bool changed = false;
        const auto now = status_now();
        if ((link_ == StatusLink::Current || link_ == StatusLink::Waiting) &&
            now - (last_ == 0 ? opened_ : last_) > status_fresh_ms) {
            current_.reset(); link_ = StatusLink::Stale; changed = true;
        }
        std::array<char, 4096> bytes{};
        const auto count = ::read(fd_, bytes.data(), bytes.size());
        if (count == 0) { end(used_ == 0 ? StatusLink::Disconnected : StatusLink::Invalid); return true; }
        if (count < 0) {
            if (errno == EAGAIN || errno == EINTR) { return changed; }
            end(StatusLink::Invalid); return true;
        }
        for (std::size_t i = 0; i < static_cast<std::size_t>(count); ++i) {
            if (bytes[i] != '\n') {
                if (used_ == line_.size()) { end(StatusLink::Invalid); return true; }
                line_[used_++] = bytes[i];
                continue;
            }
            const auto parsed = parse_status(std::string_view(line_.data(), used_));
            used_ = 0;
            const auto received = status_now();
            if (!parsed || parsed->stamp <= last_ || parsed->stamp > received ||
                (!mode_.empty() && parsed->mode != mode_)) {
                end(StatusLink::Invalid); return true;
            }
            mode_ = parsed->mode;
            last_ = parsed->stamp;
            if (received - last_ > status_fresh_ms) { continue; }
            current_ = parsed;
            last_failure_ = parsed->health == "failed" || parsed->health == "source-failed" || parsed->health == "blocked";
            link_ = StatusLink::Current;
            changed = true;
        }
        return changed;
    }
private:
    void end(StatusLink link) noexcept {
        if (fd_ >= 0) { ::close(fd_); fd_ = -1; }
        current_.reset(); link_ = link;
        if (link == StatusLink::Invalid) { last_failure_ = false; }
    }
    int fd_{-1};
    StatusLink link_{StatusLink::Unconfigured};
    std::uint64_t last_{}, opened_{};
    std::string_view mode_;
    bool last_failure_{};
    std::array<char, status_max_line> line_{};
    std::size_t used_{};
    std::optional<TelemetryStatus> current_;
};
} // namespace knetsentry::agent
