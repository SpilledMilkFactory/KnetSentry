// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/service/health_client.hpp"

#include <algorithm>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

namespace knetsentry::service {
namespace {
[[nodiscard]] bool valid_id(std::string_view id) noexcept {
    return id.size() == 16 && std::ranges::all_of(id, [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}
[[nodiscard]] bool number(std::string_view text, std::uint64_t& value) noexcept {
    if (text.empty() || text.size() > 20 || (text.size() > 1 && text.front() == '0') ||
        !std::ranges::all_of(text, [](char c) { return c >= '0' && c <= '9'; })) { return false; }
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    return result.ec == std::errc{} && result.ptr == text.data() + text.size();
}
[[nodiscard]] bool resource(std::string_view text, std::optional<std::uint64_t>& value) noexcept {
    if (text == "NA") { value.reset(); return true; }
    std::uint64_t parsed{};
    if (!number(text, parsed)) { return false; }
    value = parsed;
    return true;
}
[[nodiscard]] std::size_t frame_size(const char* header) noexcept {
    std::size_t size = 0;
    for (std::size_t i = 0; i < 4; ++i) {
        size = (size << 8U) | static_cast<unsigned char>(header[i]);
    }
    return size;
}
} // namespace

std::optional<HealthSnapshot> decode_health(std::string_view payload, std::string_view request_id) noexcept {
    if (!valid_id(request_id) || payload.empty() || payload.size() > max_health_response_size ||
        payload.back() != '\n') { return std::nullopt; }
    payload.remove_suffix(1);
    std::array<std::string_view, 14> fields{};
    for (std::size_t i = 0; i < fields.size(); ++i) {
        const auto end = payload.find(' ');
        if ((i + 1 == fields.size()) != (end == std::string_view::npos)) { return std::nullopt; }
        fields[i] = payload.substr(0, end);
        if (fields[i].empty()) { return std::nullopt; }
        if (end != std::string_view::npos) { payload.remove_prefix(end + 1); }
    }
    if (fields[0] != "KSIPC/1" || fields[1] != "OK" || fields[2] != request_id ||
        fields[3] != "HEALTH" || fields[4] != "RUNNING" ||
        (fields[8] != "CONFIG_DEFAULT" && fields[8] != "CONFIG_VALIDATED") ||
        fields[9] != "IPC_READY" || fields[10] != "MONITORING_UNAVAILABLE") { return std::nullopt; }
    HealthSnapshot result{};
    result.state = State::Running;
    result.explicit_config = fields[8] == "CONFIG_VALIDATED";
    if (!number(fields[5], result.uptime_ms) || !resource(fields[6], result.usage.cpu_ms) ||
        !resource(fields[7], result.usage.peak_rss_kib) ||
        (result.usage.peak_rss_kib && *result.usage.peak_rss_kib == 0) ||
        !number(fields[11], result.rejected) || !number(fields[12], result.transport_errors) ||
        !number(fields[13], result.sampling_errors)) { return std::nullopt; }
    return result;
}

HealthClient::~HealthClient() noexcept { cancel(); }
void HealthClient::finish(HealthQueryState state) noexcept {
    if (fd_ >= 0) { static_cast<void>(::close(fd_)); fd_ = -1; }
    state_ = state;
    if (state != HealthQueryState::Available) { snapshot_.reset(); roster_.reset(); events_.reset(); alerts_.reset(); }
}
void HealthClient::cancel() noexcept {
    finish(HealthQueryState::Idle);
    event_query_ = {}; alert_query_ = {};
    request_.fill(0);
    response_.fill(0);
}

void HealthClient::begin(std::string_view directory, std::string_view request_id) noexcept {
    begin_query(directory, request_id, false);
}
void HealthClient::begin_agents(std::string_view directory, std::string_view request_id) noexcept {
    begin_query(directory, request_id, true);
}
void HealthClient::begin_events(std::string_view directory, std::string_view request_id, const EventQuery& query) noexcept {
    begin_query(directory, request_id, false, &query);
}
void HealthClient::begin_alerts(std::string_view directory, std::string_view request_id, const AlertQuery& query) noexcept {
    begin_query(directory, request_id, false, nullptr, &query);
}
void HealthClient::begin_query(std::string_view directory, std::string_view request_id, bool agents, const EventQuery* query, const AlertQuery* alert) noexcept {
    cancel();
    agents_ = agents;
    event_request_ = query != nullptr; alert_request_ = alert != nullptr;
    state_ = HealthQueryState::Unavailable;
    constexpr std::string_view suffix = "/manager.sock";
    sockaddr_un address{};
    if (!valid_id(request_id) || directory.size() < 2 || directory.front() != '/' ||
        directory.back() == '/' || directory.find('\0') != std::string_view::npos ||
        directory.size() >= sizeof(address.sun_path) - suffix.size()) { return; }
    std::size_t begin = 1;
    while (begin < directory.size()) {
        const auto end = directory.find('/', begin);
        const auto part = directory.substr(begin, end == std::string_view::npos ? end : end - begin);
        if (part.empty() || part == "." || part == "..") { return; }
        if (end == std::string_view::npos) { break; }
        begin = end + 1;
    }
    // The path checks are defense in depth. Peer credentials on the connected
    // descriptor, not the pathname, authorize the initial same-UID/GID peer.
    std::memcpy(address.sun_path, directory.data(), directory.size());
    struct stat info{};
    if (::lstat(address.sun_path, &info) != 0 || !S_ISDIR(info.st_mode) ||
        info.st_uid != ::geteuid() || (info.st_mode & 07777U) != 0700U) { return; }
    std::memcpy(address.sun_path + directory.size(), suffix.data(), suffix.size());
    if (::lstat(address.sun_path, &info) != 0 || !S_ISSOCK(info.st_mode) ||
        info.st_uid != ::geteuid() || (info.st_mode & 07777U) != 0600U) { return; }
    address.sun_family = AF_UNIX;
    fd_ = ::socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd_ < 0) { return; }
    const auto connected = ::connect(fd_, reinterpret_cast<const sockaddr*>(&address), sizeof(address));
    if (connected != 0 && errno != EINPROGRESS) { finish(HealthQueryState::Unavailable); return; }
    std::ranges::copy(request_id, request_id_.begin());
    if (query || alert) {
        try {
            if (query) { event_query_ = *query; }
            if (alert) { alert_query_ = *alert; }
            const auto payload = alert ? encode_alert_request(alert_query_,request_id) : encode_event_request(event_query_,request_id);
            if (payload.empty() || payload.size() > max_event_request) { finish(HealthQueryState::Invalid); return; }
            const auto size = payload.size();
            request_[0] = request_[1] = 0;
            request_[2] = static_cast<char>((size >> 8U) & 255U);
            request_[3] = static_cast<char>(size & 255U);
            std::ranges::copy(payload, request_.begin() + 4);
            request_size_ = size + 4;
        } catch (...) { finish(HealthQueryState::Invalid); return; }
    } else {
        const std::string_view prefix = agents_ ? "KSIPC/1 AGENTS " : "KSIPC/1 HEALTH ";
        const auto size = prefix.size() + 16U + 1U;
        request_[0] = request_[1] = request_[2] = 0;
        request_[3] = static_cast<char>(size);
        std::ranges::copy(prefix, request_.begin() + 4);
        std::ranges::copy(request_id_, request_.begin() + 4 + static_cast<std::ptrdiff_t>(prefix.size()));
        request_[size + 3U] = '\n';
        request_size_ = size + 4U;
    }
    sent_ = received_ = 0;
    phase_ = Phase::Connect;
    state_ = HealthQueryState::Pending;
    deadline_ = std::chrono::steady_clock::now() + std::chrono::seconds(2);
}

bool HealthClient::verify_peer() const noexcept {
    struct ucred peer{};
    socklen_t size = sizeof(peer);
    return ::getsockopt(fd_, SOL_SOCKET, SO_PEERCRED, &peer, &size) == 0 &&
        size == sizeof(peer) && peer.pid > 0 && peer.uid == ::geteuid() && peer.gid == ::getegid();
}

void HealthClient::advance() noexcept {
    if (state_ != HealthQueryState::Pending) { return; }
    if (std::chrono::steady_clock::now() >= deadline_) { finish(HealthQueryState::Unavailable); return; }
    pollfd item{fd_, static_cast<short>(phase_ == Phase::Receive ? POLLIN : POLLOUT), 0};
    const int ready = ::poll(&item, 1, 0);
    if (ready < 0 && errno == EINTR) { return; }
    if (ready < 0 || (item.revents & POLLNVAL) != 0) { finish(HealthQueryState::Unavailable); return; }
    if (ready == 0) { return; }
    if (phase_ == Phase::Connect) {
        int error = 0;
        socklen_t size = sizeof(error);
        if (::getsockopt(fd_, SOL_SOCKET, SO_ERROR, &error, &size) != 0 || error != 0 ||
            !verify_peer()) { finish(HealthQueryState::Unavailable); return; }
        phase_ = Phase::Send;
    }
    if (phase_ == Phase::Send) {
        const auto count = ::send(fd_, request_.data() + sent_, request_size_ - sent_, MSG_NOSIGNAL);
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) { return; }
        if (count <= 0) { finish(HealthQueryState::Unavailable); return; }
        sent_ += static_cast<std::size_t>(count);
        if (sent_ == request_size_) { phase_ = Phase::Receive; }
        return;
    }
    const auto count = ::recv(fd_, response_.data() + received_, response_.size() - received_, 0);
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) { return; }
    if (count < 0) { finish(HealthQueryState::Unavailable); return; }
    received_ += static_cast<std::size_t>(count);
    if (received_ >= 4) {
        const auto size = frame_size(response_.data());
        if (size == 0 || size > (alert_request_ ? max_alert_response : event_request_ ? max_event_response : (agents_ ? max_roster_response_size : max_health_response_size)) || received_ > size + 4) {
            finish(HealthQueryState::Invalid); return;
        }
        if (count == 0 && received_ == size + 4) {
            const std::string_view payload(response_.data() + 4, size);
            const std::string_view id(request_id_.data(), request_id_.size());
            if (alert_request_) {
                try { alerts_ = decode_alert_page(payload,id,alert_query_); }
                catch (...) { finish(HealthQueryState::Invalid); return; }
            } else if (event_request_) {
                try { events_ = decode_event_page(payload, id, event_query_); }
                catch (...) { finish(HealthQueryState::Invalid); return; }
            } else if (agents_) { roster_ = decode_roster(payload, id); }
            else { snapshot_ = decode_health(payload, id); }
            finish((snapshot_ || roster_ || events_ || alerts_) ? HealthQueryState::Available : HealthQueryState::Invalid);
            return;
        }
    }
    if (count == 0) { finish(HealthQueryState::Invalid); }
}
} // namespace knetsentry::service
