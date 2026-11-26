// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#pragma once
#include <knetsentry/agent/journal.hpp>
#include <knetsentry/core/enrollment.hpp>
#include <array>
#include <string>

namespace knetsentry::agent {
// Immutable destination binding, stored with the checkpoint. Not a credential.
[[nodiscard]] std::string delivery_binding(const enrollment::EndpointId& endpoint,
    const identity::Fingerprint& manager);

enum class DeliveryState { Pending, Complete, Failed };
// The trusted receiver must commit idempotently by endpoint + native cursor,
// and reject conflicting content. True means durable acceptance (including
// exact duplicates). The callback must be bounded, nonthrowing and nonreentrant.
class ReceiptSink {
public:
    virtual ~ReceiptSink() = default;
    virtual bool commit(const enrollment::EndpointId& endpoint, std::string_view binding, std::string_view canonical_row) noexcept = 0;
};

// Bounded reusable receiver-side storage, one endpoint/source per explicit
// private directory. No operational manager integration or implicit paths.
class ReceiptInbox final : public ReceiptSink {
public:
    ReceiptInbox(enrollment::EndpointId endpoint, identity::Fingerprint manager,
        JournalMode mode, std::string unit, std::string directory);
    ~ReceiptInbox() override;
    ReceiptInbox(const ReceiptInbox&) = delete;
    ReceiptInbox& operator=(const ReceiptInbox&) = delete;
    [[nodiscard]] bool start() noexcept;
    [[nodiscard]] bool commit(const enrollment::EndpointId& endpoint, std::string_view binding, std::string_view canonical_row) noexcept override;
    [[nodiscard]] std::size_t count() const noexcept { return rows_.size(); }
private:
    [[nodiscard]] bool load();
    [[nodiscard]] bool fail() noexcept;
    enrollment::EndpointId endpoint_;
    JournalMode mode_;
    std::string unit_, directory_, binding_, header_, state_;
    std::vector<std::string> rows_;
    int fd_{-1};
    bool started_{}, ready_{};
};

// Exclusive use of a fresh established TLS session, one record per connection.
// The caller drives ciphertext, network authorization, monotonic time and
// reconnect scheduling. No socket or monitoring permission is granted here.
class DeliverySender final {
public:
    DeliverySender(JournalCollector& queue, tls::Session& session,
        const enrollment::EndpointId& endpoint, const identity::Fingerprint& manager);
    ~DeliverySender();
    DeliverySender(const DeliverySender&) = delete;
    DeliverySender& operator=(const DeliverySender&) = delete;
    [[nodiscard]] DeliveryState step(std::optional<identity::Fingerprint> current_manager,
        bool authorized, std::uint64_t now) noexcept;
private:
    JournalCollector& queue_;
    tls::Session& session_;
    std::string binding_, row_, frame_, ack_;
    std::array<unsigned char, 4096> received_{};
    std::size_t used_{};
    std::optional<std::uint64_t> start_;
    std::uint64_t last_{};
    bool sent_{}, owns_slot_{};
    DeliveryState state_{DeliveryState::Pending};
};
class DeliveryReceiver final {
public:
    DeliveryReceiver(tls::Session& session, int registry, const enrollment::EndpointId& endpoint,
        const identity::Fingerprint& manager, JournalMode mode, std::string unit, ReceiptSink& sink);
    ~DeliveryReceiver();
    DeliveryReceiver(const DeliveryReceiver&) = delete;
    DeliveryReceiver& operator=(const DeliveryReceiver&) = delete;
    [[nodiscard]] DeliveryState step(bool authorized, std::uint64_t now) noexcept;
private:
    tls::Session& session_;
    int registry_;
    enrollment::EndpointId endpoint_;
    JournalMode mode_;
    std::string unit_, binding_, ack_;
    ReceiptSink& sink_;
    std::array<unsigned char, 4096> received_{};
    std::size_t used_{};
    std::optional<std::uint64_t> start_;
    std::uint64_t last_{};
    DeliveryState state_{DeliveryState::Pending};
};
} // namespace knetsentry::agent
