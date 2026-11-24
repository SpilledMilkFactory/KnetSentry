// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/service/local_ipc.hpp"

int main() {
    using knetsentry::service::IpcAction;
    using knetsentry::service::authorize_local_peer;
    constexpr uid_t user = 1000;
    constexpr gid_t group = 1000;
    if (!authorize_local_peer(user, group, user, group, IpcAction::Status)) { return 1; }
    if (authorize_local_peer(1001, group, user, group, IpcAction::Status)) { return 2; }
    if (authorize_local_peer(user, 1001, user, group, IpcAction::Status)) { return 3; }
    if (authorize_local_peer(0, 0, user, group, IpcAction::Status)) { return 4; }
    if (authorize_local_peer(user, group, user, group, IpcAction::Administrative)) { return 5; }
    return 0;
}
