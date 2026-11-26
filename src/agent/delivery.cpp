// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/agent/delivery.hpp>
#include <algorithm>
#include <fcntl.h>
#include <openssl/evp.h>
#include <unistd.h>
#include <utility>

namespace knetsentry::agent {
namespace {
constexpr std::size_t header_size = 8, max_body = 2144, digest_size = 32;
constexpr std::uint64_t deadline_ms = 5000;
std::string hex(std::span<const unsigned char> bytes) {
    std::string result;
    for (const auto byte : bytes) {
        result += "0123456789abcdef"[byte >> 4];
        result += "0123456789abcdef"[byte & 15];
    }
    return result;
}
std::span<const unsigned char> bytes(std::string_view value) noexcept {
    return {reinterpret_cast<const unsigned char*>(value.data()), value.size()};
}
std::string frame(char kind, std::string_view body) {
    if (body.empty() || body.size() > max_body) { return {}; }
    std::string result{"KSTD\1", 5};
    result += kind;
    result += static_cast<char>(body.size() >> 8);
    result += static_cast<char>(body.size() & 255);
    result += body;
    return result;
}
std::string acknowledgment(std::string_view payload) {
    std::array<unsigned char, digest_size> digest{};
    std::size_t size{};
    if (EVP_Q_digest(nullptr, "SHA256", nullptr, payload.data(), payload.size(), digest.data(), &size) != 1 ||
        size != digest.size()) { return {}; }
    return frame(2, {reinterpret_cast<const char*>(digest.data()), digest.size()});
}
bool time_ok(std::optional<std::uint64_t>& start, std::uint64_t& last, std::uint64_t now) noexcept {
    if (!start) { start = now; }
    if (now < last || now - *start >= deadline_ms) { return false; }
    last = now;
    return true;
}
enum class Read { Pending, Complete, Failed };
Read receive(tls::Session& session, std::array<unsigned char, 4096>& accumulated,
    std::size_t& used, unsigned char kind) noexcept {
    std::array<unsigned char, tls::max_plaintext> input{};
    const auto result = session.read(input);
    if (result.status == tls::Status::WouldBlock) { return Read::Pending; }
    if (result.status != tls::Status::Ok || result.bytes > accumulated.size() - used) { return Read::Failed; }
    std::copy_n(input.begin(), result.bytes, accumulated.data() + used);
    used += result.bytes;
    if (used < header_size) { return Read::Pending; }
    if (std::string_view(reinterpret_cast<const char*>(accumulated.data()), 5) != std::string_view("KSTD\1", 5) ||
        accumulated[5] != kind) { return Read::Failed; }
    const auto length = (static_cast<std::size_t>(accumulated[6]) << 8) | accumulated[7];
    if (length == 0 || length > max_body || (kind == 2 && length != digest_size) ||
        used > header_size + length) { return Read::Failed; }
    return used == header_size + length ? Read::Complete : Read::Pending;
}
DeliveryState fail(tls::Session& session, DeliveryState& state) noexcept {
    session.abort();
    return state = DeliveryState::Failed;
}
} // namespace
std::string delivery_binding(const enrollment::EndpointId& endpoint, const identity::Fingerprint& manager) {
    return hex(endpoint) + hex(manager);
}
DeliverySender::DeliverySender(JournalCollector& queue, tls::Session& session,
    const enrollment::EndpointId& endpoint, const identity::Fingerprint& manager)
    : queue_(queue), session_(session), binding_(delivery_binding(endpoint, manager)) {
    if (!queue_.sending_ && valid_delivery_binding(binding_) && queue_.binding_ == binding_) {
        queue_.sending_ = true;
        owns_slot_ = true;
    }
}
DeliverySender::~DeliverySender() {
    session_.abort();
    if (owns_slot_) { queue_.sending_ = false; }
}
DeliveryState DeliverySender::step(std::optional<identity::Fingerprint> manager, bool authorized,
    std::uint64_t now) noexcept {
    if (state_ != DeliveryState::Pending) { return state_; }
    try {
        if (!owns_slot_ || session_.protocol() != tls::Protocol::Telemetry || !authorized || !manager || queue_.front().empty() || queue_.binding_ != binding_ || queue_.binding_.substr(32) != hex(*manager) ||
            session_.authenticated_agent() || session_.revalidate_peer(manager) != tls::Status::Ok ||
            !time_ok(start_, last_, now)) { return fail(session_, state_); }
        if (frame_.empty()) {
            row_ = queue_.front();
            if (row_.empty()) { return fail(session_, state_); }
            const auto payload = binding_ + row_;
            frame_ = frame(1, payload);
            ack_ = acknowledgment(payload);
            if (frame_.empty() || ack_.empty()) { return fail(session_, state_); }
        }
        if (!sent_) {
            const auto result = session_.write(bytes(frame_));
            if (result.status == tls::Status::WouldBlock) { return state_; }
            if (result.status != tls::Status::Ok || result.bytes != frame_.size()) { return fail(session_, state_); }
            sent_ = true;
            return state_;
        }
        const auto result = receive(session_, received_, used_, 2);
        if (result == Read::Pending) { return state_; }
        if (result != Read::Complete || used_ != ack_.size() ||
            !std::equal(received_.data(), received_.data() + used_, bytes(ack_).begin()) ||
            session_.revalidate_peer(manager) != tls::Status::Ok || !queue_.acknowledge(row_)) {
            return fail(session_, state_);
        }
        session_.abort();
        return state_ = DeliveryState::Complete;
    } catch (...) { return fail(session_, state_); }
}
DeliveryReceiver::DeliveryReceiver(tls::Session& session, int registry, const enrollment::EndpointId& endpoint,
    const identity::Fingerprint& manager, JournalMode mode, std::string unit, ReceiptSink& sink)
    : session_(session), registry_(-1), endpoint_(endpoint), mode_(mode), unit_(std::move(unit)),
      binding_(delivery_binding(endpoint, manager)), sink_(sink) {
    if (registry >= 0) { registry_ = ::fcntl(registry, F_DUPFD_CLOEXEC, 3); }
}
DeliveryReceiver::~DeliveryReceiver() {
    session_.abort();
    if (registry_ >= 0) { ::close(registry_); }
}
DeliveryState DeliveryReceiver::step(bool authorized, std::uint64_t now) noexcept {
    if (state_ != DeliveryState::Pending) { return state_; }
    try {
        if (session_.protocol() != tls::Protocol::Telemetry || !authorized || !valid_delivery_binding(binding_) || !time_ok(start_, last_, now) ||
            enrollment::revalidate(registry_, endpoint_, session_) != enrollment::Status::Ok) {
            return fail(session_, state_);
        }
        if (ack_.empty()) {
            const auto result = receive(session_, received_, used_, 1);
            if (result == Read::Pending) { return state_; }
            if (result != Read::Complete) { return fail(session_, state_); }
            const std::string_view payload(reinterpret_cast<const char*>(received_.data() + header_size), used_ - header_size);
            if (!payload.starts_with(binding_) ||
                !valid_delivery_row(payload.substr(binding_.size()), unit_, mode_)) { return fail(session_, state_); }
            ack_ = acknowledgment(payload);
            if (ack_.empty() || !sink_.commit(endpoint_, binding_, payload.substr(binding_.size())) ||
                enrollment::revalidate(registry_, endpoint_, session_) != enrollment::Status::Ok) {
                return fail(session_, state_);
            }
        }
        const auto result = session_.write(bytes(ack_));
        if (result.status == tls::Status::WouldBlock) { return state_; }
        if (result.status != tls::Status::Ok || result.bytes != ack_.size()) { return fail(session_, state_); }
        // Caller must drain ACK ciphertext before destroying this receiver.
        return state_ = DeliveryState::Complete;
    } catch (...) { return fail(session_, state_); }
}
} // namespace knetsentry::agent
