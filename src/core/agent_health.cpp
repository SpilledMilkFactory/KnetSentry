// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/core/agent_health.hpp>

#include <algorithm>
#include <fcntl.h>
#include <limits>
#include <unistd.h>

namespace knetsentry::agent_health {
namespace protocol = core::agent_protocol;
Tracker::Tracker(int directory, const enrollment::EndpointId& id) noexcept
    : directory_(fcntl(directory, F_DUPFD_CLOEXEC, 0)), id_(id) {}
Tracker::~Tracker() {
    disconnected();
    if (directory_ >= 0) { (void)close(directory_); }
}
void Tracker::invalidate(Health reason) noexcept {
    if (session_) { session_->abort(); session_.reset(); }
    validator_.reset();
    frame_.fill(std::byte{});
    used_ = 0;
    wanted_ = protocol::header_size;
    snapshot_ = {reason, std::nullopt};
}
void Tracker::disconnected() noexcept { invalidate(Health::Missing); }
bool Tracker::check(Millis now) noexcept {
    if (now < last_clock_) { invalidate(Health::Untrusted); return false; }
    last_clock_ = now;
    if (!session_) { return false; }
    if (enrollment::revalidate(directory_, id_, *session_) != enrollment::Status::Ok) {
        invalidate(Health::Untrusted);
        return false;
    }
    if (now - last_report_ >= missing_after) { disconnected(); return false; }
    return true;
}
bool Tracker::attach(std::unique_ptr<tls::Session> session, Millis now) noexcept {
    if (check(now) || now < last_clock_ || !session) { return false; }
    if (enrollment::revalidate(directory_, id_, *session) != enrollment::Status::Ok) {
        invalidate(Health::Untrusted);
        return false;
    }
    session_ = std::move(session);
    validator_.emplace();
    last_report_ = now;
    snapshot_ = {Health::Awaiting, std::nullopt};
    return true;
}
tls::Result Tracker::ingest(std::span<const unsigned char> bytes, Millis now) noexcept {
    if (!check(now)) { return {tls::Status::Failed}; }
    const auto result = session_->ingest(bytes);
    if (result.status != tls::Status::Ok && result.status != tls::Status::WouldBlock) {
        invalidate(Health::Untrusted);
    }
    return result;
}
tls::Result Tracker::drain(std::span<unsigned char> bytes, Millis now) noexcept {
    if (!check(now)) { return {tls::Status::Failed}; }
    const auto result = session_->drain(bytes);
    if (result.status != tls::Status::Ok && result.status != tls::Status::WouldBlock) {
        invalidate(Health::Untrusted);
    }
    return result;
}
bool Tracker::consume(std::span<const unsigned char> bytes, Millis now) noexcept {
    while (!bytes.empty()) {
        const auto count = std::min(wanted_ - used_, bytes.size());
        const auto part = std::as_bytes(bytes.first(count));
        std::copy(part.begin(), part.end(), std::span(frame_).subspan(used_, count).begin());
        used_ += count;
        bytes = bytes.subspan(count);
        if (used_ != wanted_) { continue; }
        if (wanted_ == protocol::header_size) {
            const auto header = protocol::inspect_header(std::span(frame_).first(used_));
            if (header.error != protocol::Error::None) { return false; }
            wanted_ = header.frame_size;
            if (used_ != wanted_) { continue; }
        }
        const auto decoded = validator_->accept(std::span(frame_).first(used_));
        if (decoded.error != protocol::Error::None || validator_->closed()) { return false; }
        if (decoded.message.kind == protocol::Kind::Heartbeat) {
            const auto drops = decoded.message.dropped_records;
            snapshot_ = {drops == 0 ? Health::Healthy : Health::Degraded,
                Counters{decoded.message.uptime_ms, drops}};
            last_report_ = now;
        }
        used_ = 0;
        wanted_ = protocol::header_size;
    }
    return true;
}
Snapshot Tracker::poll(Millis now) noexcept {
    if (!check(now)) { return snapshot_; }
    std::array<unsigned char, tls::max_plaintext> bytes{};
    const auto result = session_->read(bytes);
    if (result.status == tls::Status::Ok) {
        if (!consume(std::span(bytes).first(result.bytes), now)) { invalidate(Health::ProtocolError); }
    } else if (result.status == tls::Status::Closed) {
        disconnected();
    } else if (result.status != tls::Status::WouldBlock) {
        invalidate(Health::Untrusted);
    }
    if (session_) { (void)check(now); }
    return snapshot_;
}

tls::Status Reporter::send(std::optional<identity::Fingerprint> manager_pin,
    Millis now, Counters counters) noexcept {
    if (now < last_clock_ || sequence_ == std::numeric_limits<std::uint64_t>::max() ||
        session_.authenticated_agent() || session_.revalidate_peer(manager_pin) != tls::Status::Ok) {
        session_.abort();
        return tls::Status::Failed;
    }
    last_clock_ = now;
    if (pending_.size == 0) {
        if (sequence_ > 2 && now - last_report_ < heartbeat_interval) { return tls::Status::NotReady; }
        if (counters.uptime_ms < last_counters_.uptime_ms ||
            counters.dropped_records < last_counters_.dropped_records) {
            session_.abort(); return tls::Status::Failed;
        }
        pending_counters_ = sequence_ == 1 ? Counters{} : counters;
        pending_ = protocol::encode({sequence_ == 1 ? protocol::Kind::Hello : protocol::Kind::Heartbeat,
            sequence_, pending_counters_.uptime_ms, pending_counters_.dropped_records});
        if (pending_.error != protocol::Error::None) { session_.abort(); return tls::Status::Failed; }
    }
    const auto data = std::span(pending_.bytes).first(pending_.size);
    const auto result = session_.write({reinterpret_cast<const unsigned char*>(data.data()), data.size()});
    if (result.status == tls::Status::Ok && result.bytes == pending_.size) {
        last_counters_ = pending_counters_;
        last_report_ = now;
        ++sequence_;
        pending_ = {};
        return tls::Status::Ok;
    }
    if (result.status == tls::Status::WouldBlock) { return result.status; }
    session_.abort();
    return tls::Status::Failed;
}

void Reconnect::retry(Millis now) noexcept {
    phase_ = Phase::Waiting;
    since_ = now;
    wait_ = next_delay_;
    next_delay_ = std::min(next_delay_ * 2, maximum_retry);
}
bool Reconnect::advance(Millis now) noexcept {
    if (phase_ == Phase::Blocked || now < last_clock_) { phase_ = Phase::Blocked; return false; }
    last_clock_ = now;
    if (phase_ == Phase::Connecting && now - since_ >= attempt_timeout) { retry(now); }
    return true;
}
Reconnect::Phase Reconnect::phase(Millis now) noexcept { (void)advance(now); return phase_; }
std::optional<std::uint64_t> Reconnect::begin(Millis now) noexcept {
    if (!advance(now) || phase_ != Phase::Waiting || now - since_ < wait_) { return std::nullopt; }
    if (attempt_ == std::numeric_limits<std::uint64_t>::max()) {
        phase_ = Phase::Blocked; return std::nullopt;
    }
    phase_ = Phase::Connecting;
    since_ = now;
    return ++attempt_;
}
bool Reconnect::connected(Millis now, std::uint64_t attempt) noexcept {
    if (!advance(now) || phase_ != Phase::Connecting || attempt != attempt_) { return false; }
    phase_ = Phase::Online;
    since_ = now;
    return true;
}
void Reconnect::lost(Millis now, std::uint64_t attempt) noexcept {
    if (!advance(now) || attempt != attempt_) { return; }
    if (phase_ == Phase::Online && now - since_ >= missing_after) { next_delay_ = initial_retry; }
    if (phase_ == Phase::Online || phase_ == Phase::Connecting) { retry(now); }
}
} // namespace knetsentry::agent_health
