// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/core/enrollment.hpp>

namespace knetsentry::enrollment {
Status authorize(int directory, const EndpointId& id, const tls::Session& session) noexcept {
    const auto proof = session.authenticated_agent();
    if (!proof) { return Status::NotAuthenticated; }
    const auto approved = lookup(directory, id);
    if (approved.status != Status::Ok) { return approved.status; }
    if (!session.authenticated_agent()) { return Status::NotAuthenticated; }
    return approved.pin == proof ? Status::Ok : Status::IdentityMismatch;
}
Status revalidate(int directory, const EndpointId& id, tls::Session& session) noexcept {
    const auto result = authorize(directory, id, session);
    if (result != Status::Ok) { session.abort(); }
    return result;
}
} // namespace knetsentry::enrollment
