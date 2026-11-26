// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/agent/delivery.hpp>
#include <limits>

namespace knetsentry::agent {
IngestionPipeline::IngestionPipeline(enrollment::EndpointId endpoint, identity::Fingerprint manager,
    JournalMode mode, std::string_view unit, ReceiptSink& sink)
    : endpoint_(endpoint), mode_(mode), unit_(unit.size() <= 128 ? unit : std::string_view{}),
      binding_(delivery_binding(endpoint, manager)), sink_(sink) {
    configured_ = valid_delivery_binding(binding_) &&
        ((mode_ == JournalMode::Metadata && valid_journal_unit(unit_)) ||
         (mode_ == JournalMode::Authentication && valid_auth_unit(unit_)) ||
         (mode_ == JournalMode::Audit && unit_ == "audit"));
}
std::uint64_t IngestionPipeline::count(IngestOutcome outcome) const noexcept {
    const auto i = static_cast<std::size_t>(outcome);
    return i < counts_.size() ? counts_[i] : 0;
}
void IngestionPipeline::record(IngestOutcome outcome) noexcept {
    const auto i = static_cast<std::size_t>(outcome);
    if (i < counts_.size() && counts_[i] != std::numeric_limits<std::uint64_t>::max()) { ++counts_[i]; }
}
bool IngestionPipeline::reserve() noexcept {
    if (active_ >= max_inflight) { return false; }
    ++active_;
    return true;
}
void IngestionPipeline::release() noexcept { --active_; }
IngestOutcome IngestionPipeline::process(std::string_view payload) {
    if (!configured_ || payload.size() <= binding_.size() ||
        payload.size() > binding_.size() + max_row || !payload.starts_with(binding_)) {
        return IngestOutcome::Invalid;
    }
    const auto row = payload.substr(binding_.size());
    if (!valid_delivery_row(row, unit_, mode_)) { return IngestOutcome::Invalid; }
    if (!sink_.commit(endpoint_, binding_, row)) { return IngestOutcome::StorageRejected; }
    record(IngestOutcome::Committed);
    return IngestOutcome::Committed;
}
} // namespace knetsentry::agent
