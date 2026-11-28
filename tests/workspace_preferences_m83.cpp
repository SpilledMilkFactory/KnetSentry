// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/desktop/workspace_preferences.hpp>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>

namespace {
using namespace knetsentry::desktop;
void require(bool ok, const char* message) { if (!ok) { throw std::runtime_error(message); } }
struct Fixture {
    std::filesystem::path root;
    ~Fixture() { std::error_code error; std::filesystem::remove_all(root, error); }
};
void verify(const std::filesystem::path& root) {
    for (int ratio = 30; ratio <= 70; ratio += 5) {
        for (int sections = 0; sections <= 7; ++sections) {
            const WorkspacePreferences value{ratio, sections};
            const auto bytes = encode_workspace(value);
            require(decode_workspace({bytes.data(), bytes.size()}) == value, "codec round trip");
        }
    }
    for (const auto* bad : {"", "KSW2:50:7\n", "KSW1:29:7\n", "KSW1:31:7\n", "KSW1:50:8\n", "KSW1:50:7\nextra"}) {
        require(!decode_workspace(bad), "invalid codec");
    }
    const auto directory = root / workspace_directory;
    const auto file = directory / workspace_file;
    require(!load_workspace(root.c_str()), "missing default");
    require(save_workspace(root.c_str(), {65, 1}), "first save");
    require(load_workspace(root.c_str()) == WorkspacePreferences{65, 1}, "restart restore");
    require(!save_workspace(root.c_str(), {71, 7}), "invalid save");
    require(save_workspace(root.c_str(), {30, 7}), "atomic replacement");
    require(load_workspace(root.c_str()) == WorkspacePreferences{30, 7}, "replacement restore");
    { std::ofstream output(file, std::ios::trunc); output << "KSW9:30:7\n"; }
    require(!load_workspace(root.c_str()), "unsupported version");
    require(save_workspace(root.c_str(), {}), "repair regular malformed file");
    require(::chmod(file.c_str(), 0644) == 0, "fixture mode");
    require(!load_workspace(root.c_str()) && !save_workspace(root.c_str(), {}), "unsafe mode refused");
    require(::unlink(file.c_str()) == 0, "remove fixture");
    const auto target = root / "sentinel";
    { std::ofstream output(target); output << "untouched"; }
    require(::chmod(target.c_str(), 0600) == 0, "sentinel mode");
    require(::symlink(target.c_str(), file.c_str()) == 0, "fixture symlink");
    require(!load_workspace(root.c_str()) && !save_workspace(root.c_str(), {}), "symlink refused");
    std::string sentinel;
    { std::ifstream input(target); input >> sentinel; }
    require(sentinel == "untouched", "sentinel untouched");
    require(::unlink(file.c_str()) == 0 && ::mkfifo(file.c_str(), 0600) == 0, "fixture FIFO");
    require(!load_workspace(root.c_str()) && !save_workspace(root.c_str(), {}), "FIFO refused");
    require(::unlink(file.c_str()) == 0 && ::link(target.c_str(), file.c_str()) == 0, "fixture hardlink");
    require(!load_workspace(root.c_str()) && !save_workspace(root.c_str(), {}), "hardlink refused");
    require(::unlink(file.c_str()) == 0 && ::chmod(directory.c_str(), 0755) == 0, "fixture directory mode");
    require(!load_workspace(root.c_str()) && !save_workspace(root.c_str(), {}), "unsafe directory refused");
    require(::rmdir(directory.c_str()) == 0 && ::symlink(root.c_str(), directory.c_str()) == 0, "fixture directory link");
    require(!load_workspace(root.c_str()) && !save_workspace(root.c_str(), {}), "directory symlink refused");
}
} // namespace
int main() {
    char name[] = "/var/tmp/ks83-native-XXXXXX";
    if (::mkdtemp(name) == nullptr) { return 1; }
    const Fixture fixture{std::filesystem::path(name)};
    try {
        verify(fixture.root);
        std::cout << "M8.3 workspace schema, atomic replacement and unsafe-path refusal: PASS\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
