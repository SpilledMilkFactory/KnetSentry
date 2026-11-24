// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/service/lifecycle.hpp"

#include <cstdio>

using knetsentry::service::Lifecycle;
using knetsentry::service::State;

namespace {
[[nodiscard]] bool check(bool actual, const char* label) {
    if (!actual) std::fprintf(stderr, "lifecycle assertion failed: %s\n", label);
    return actual;
}
} // namespace

int main() {
    Lifecycle normal;
    if (!check(normal.state() == State::Created, "created") ||
        !check(!normal.mark_ready(), "cannot skip starting") ||
        !check(!normal.request_stop(), "cannot stop created") ||
        !check(!normal.complete_stop(), "cannot complete unstarted") ||
        !check(normal.begin_start(), "begin start") ||
        !check(!normal.begin_start(), "duplicate start") ||
        !check(normal.mark_ready(), "ready") ||
        !check(!normal.mark_ready(), "duplicate ready") ||
        !check(normal.request_stop(), "request stop") ||
        !check(!normal.request_stop(), "duplicate stop request") ||
        !check(!normal.mark_ready(), "no restart while stopping") ||
        !check(normal.complete_stop(), "complete stop") ||
        !check(normal.state() == State::Stopped, "stopped") ||
        !check(!normal.begin_start(), "terminal stopped cannot restart") ||
        !check(!normal.mark_failed(), "terminal stopped cannot fail")) return 1;

    Lifecycle startup_cancel;
    if (!check(startup_cancel.begin_start(), "startup begin") ||
        !check(startup_cancel.request_stop(), "cancel during startup") ||
        !check(startup_cancel.complete_stop(), "startup cancel stopped")) return 1;

    Lifecycle fault;
    if (!check(fault.begin_start(), "fault begin") ||
        !check(fault.mark_failed(), "mark failed") ||
        !check(fault.state() == State::Failed, "failed") ||
        !check(!fault.mark_ready(), "cannot recover implicitly") ||
        !check(!fault.request_stop(), "failed cannot stop") ||
        !check(!fault.mark_failed(), "duplicate failure")) return 1;

    Lifecycle early_failure;
    if (!check(early_failure.mark_failed(), "fail during initialization") ||
        !check(!early_failure.begin_start(), "cannot start after failure")) return 1;
    return 0;
}
