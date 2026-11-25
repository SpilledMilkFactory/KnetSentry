// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/core/enrollment.hpp>
#include <iostream>
#include <string_view>
#include <fcntl.h>
#include <unistd.h>

namespace {
using namespace knetsentry::enrollment;
int digit(char c) noexcept {
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    return -1;
}
template<typename T> bool decode(std::string_view text, T& output) noexcept {
    if (text.size() != output.size() * 2) { return false; }
    for (std::size_t i = 0; i < output.size(); ++i) {
        const int hi = digit(text.at(2 * i));
        const int lo = digit(text.at(2 * i + 1));
        if (hi < 0 || lo < 0) { return false; }
        output.at(i) = static_cast<unsigned char>(hi * 16 + lo);
    }
    return true;
}
} // namespace
int main(int argc, char** argv) {
    if (argc != 3 && argc != 5) {
        std::cerr << "Usage: knetsentry-enrollment init PRIVATE_DIR | approve PRIVATE_DIR ENDPOINT_ID PIN\n";
        return 2;
    }
    const std::string_view operation(argv[1]);
    EndpointId id{};
    knetsentry::identity::Fingerprint pin{};
    if (!((argc == 3 && operation == "init") || (argc == 5 && operation == "approve" &&
        decode(std::string_view(argv[3]), id) && decode(std::string_view(argv[4]), pin)))) {
        std::cerr << "Enrollment: invalid arguments\n";
        return 2;
    }
    const int dir = open(argv[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) { std::cerr << "Enrollment: private directory unavailable\n"; return 1; }
    const auto status = operation == "init" ? initialize(dir) : approve(dir, id, pin);
    (void)close(dir);
    if (status != Status::Ok) {
        std::cerr << "Enrollment: rejected or uncertain (status " << static_cast<int>(status) << ")\n";
        return 1;
    }
    std::cout << "Enrollment: administrative operation recorded; no network authority granted\n";
    return 0;
}
