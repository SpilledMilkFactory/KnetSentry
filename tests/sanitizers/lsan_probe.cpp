// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
// Intentionally leaks memory: test fixture, never linked into production.
#include <cstdlib>

#if defined(__GNUC__) || defined(__clang__)
__attribute__((noinline))
#endif
void knetsentry_intentionally_leak_for_lsan_control() {
    auto *allocation = static_cast<volatile unsigned char *>(std::malloc(1337));
    if (allocation == nullptr) {
        std::abort();
    }
    *allocation = 0x5a;
    // The allocation is deliberately not freed, to verify LeakSanitizer
    // still rejects first-party leaks under GUI-only third-party suppressions.
}

int main() {
    knetsentry_intentionally_leak_for_lsan_control();
    return 0;
}
