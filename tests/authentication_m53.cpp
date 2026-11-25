// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include "knetsentry/agent/journal.hpp"
#include <array>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <sys/stat.h>
#include <utility>
#include <vector>

namespace {
using namespace knetsentry::agent;
namespace fs = std::filesystem;
void require(bool ok, const char* message) { if (!ok) { throw std::runtime_error(message); } }
struct Temp final {
    fs::path path;
    Temp() {
        std::array<char, 24> pattern{"/tmp/ks-auth-XXXXXX"};
        const auto* result = ::mkdtemp(pattern.data());
        require(result != nullptr, "temporary directory failed");
        path = result;
    }
    ~Temp() { std::error_code error; fs::remove_all(path, error); }
};
std::string read(const fs::path& file) {
    std::ifstream in(file);
    require(in.is_open(), "fixture read failed");
    std::string data;
    std::array<char, 4096> buffer{};
    while (in.read(buffer.data(), static_cast<std::streamsize>(buffer.size())) || in.gcount() > 0) {
        data.append(buffer.data(), static_cast<std::size_t>(in.gcount()));
    }
    require(in.eof() && !in.bad(), "fixture read failed");
    return data;
}
void save(const fs::path& file, const std::string& data) {
    std::ofstream out(file); out << data; out.close();
    require(out.good() && ::chmod(file.c_str(), 0600) == 0, "fixture write failed");
}
void parser() {
    using E = AuthEvent;
    struct Case { std::string_view unit, message; E expected; };
    constexpr std::array cases{
        Case{"ssh.service", "Accepted password for private-user from 192.0.2.1 port 12345 ssh2", E::SshAccepted},
        Case{"sshd.service", "Accepted publickey for private-user from 2001:db8::1 port 22 ssh2: ED25519 SHA256:private-key", E::SshAccepted},
        Case{"sshd@instance.service", "Failed password for invalid user nobody from 192.0.2.2 port 2345 ssh2", E::SshFailed},
        Case{"ssh@instance.service", "Failed keyboard-interactive/pam for private-user from ::1 port 22 ssh2", E::SshFailed},
        Case{"ssh.service", "Invalid user private-user from 192.0.2.1 port 22 [preauth]", E::SshInvalidUser},
        Case{"ssh.service", "pam_unix(sshd:session): session opened for user private-user(uid=1000) by (uid=0)", E::SessionOpened},
        Case{"ssh.service", "pam_unix(sshd:session): session closed for user private-user", E::SessionClosed},
        Case{"ssh.service", "pam_unix(sshd:auth): authentication failure; private-canary", E::AuthenticationFailed},
        Case{"getty@tty1.service", "FAILED LOGIN (1) on '/dev/tty1' FOR 'private-user', Authentication failure", E::LoginFailed},
        Case{"login.service", "pam_unix(login:session): session opened for user private-user by LOGIN(uid=0)", E::SessionOpened},
        Case{"serial-getty@ttyS0.service", "pam_unix(login:session): session closed for user private-user", E::SessionClosed},
        Case{"systemd-logind.service", "New session 3 of user private-user.", E::LoginSessionCreated},
        Case{"systemd-logind.service", "Removed session 3.", E::LoginSessionRemoved},
        Case{"other.service", "Accepted password for private-user from 192.0.2.1 port 22 ssh2", E::Unclassified},
        Case{"ssh.service", "Accepted password for invalid user private-user from 192.0.2.1 port 22 ssh2", E::Unclassified},
        Case{"ssh.service", "Accepted password for private-user from invalid port 22 ssh2", E::Unclassified},
        Case{"ssh.service", "Accepted password for private-user from 192.0.2.1 port 65536 ssh2", E::Unclassified},
        Case{"ssh.service", "Accepted password for private-user from 192.0.2.1 port 22", E::Unclassified},
        Case{"ssh.service", "prefix Accepted password for private-user from 192.0.2.1 port 22 ssh2", E::Unclassified},
        Case{"ssh.service", "pam_unix(login:session): session opened for user private-user", E::Unclassified},
        Case{"ssh.service", "Accepted password for private-user from 192.0.2.1 port 22 ssh2\n", E::Unclassified},
        Case{"ssh.service", "", E::Unclassified}};
    for (const auto& test : cases) { require(classify_auth(test.unit, test.message) == test.expected, "classification mismatch"); }
    require(classify_auth("ssh.service", std::string(1025, 'x')) == E::Unclassified &&
            classify_auth("ssh.service", std::string_view("a\0b", 3)) == E::Unclassified &&
            !valid_auth_event("systemd-logind.service", E::SshAccepted) &&
            parse_auth_event("private-canary") == E::None, "malformed or inconsistent classification accepted");
    std::cout << "M5.3 representative SSH, PAM, login and logind source variations and negative inputs: PASS\n";
}
void native(const std::string& directory, std::string_view unit, const std::vector<std::string>& expected) {
    Temp state;
    auto source = make_journal_source(directory, JournalMode::Authentication);
    const auto file = state.path / "auth-m53.v1";
    const std::string header = "KNETSENTRY-AUTH-V1\t" + std::string(unit) + '\n';
    {
        JournalCollector collector(*source, std::string(unit), state.path.string(), JournalMode::Authentication);
        require(collector.start() && collector.pump() && collector.count() == expected.size(), "native auth collection failed");
    }
    const auto complete = read(file);
    require(complete.find("1234567890abcdef1234567890abcdef") != std::string::npos &&
            complete.find("abcdef1234567890abcdef1234567890") != std::string::npos,
            "native auth provenance missing");
    require(complete.starts_with(header) && complete.find("private-") == std::string::npos &&
        complete.find("192.0.2.") == std::string::npos && complete.find("2001:db8") == std::string::npos &&
        complete.find("MESSAGE") == std::string::npos, "native auth privacy failed");
    std::string_view remaining(complete);
    remaining.remove_prefix(header.size());
    for (const auto& name : expected) {
        const auto end = remaining.find('\n');
        require(end != remaining.npos && remaining.substr(0, end).ends_with('\t' + name), "native event classification mismatch");
        remaining.remove_prefix(end + 1);
    }
    require(remaining.empty(), "unexpected native records");
    const auto end = complete.find('\n', header.size());
    require(end != std::string::npos, "no checkpoint");
    save(file, complete.substr(0, end + 1));
    {
        JournalCollector resume(*source, std::string(unit), state.path.string(), JournalMode::Authentication);
        require(resume.start() && resume.pump() && read(file) == complete, "native auth exact resume failed");
        require(resume.pump() && read(file) == complete, "duplicate on repeated poll");
    }
    {
        JournalCollector restart(*source, std::string(unit), state.path.string(), JournalMode::Authentication);
        require(restart.start() && restart.pump() && read(file) == complete, "native auth restart failed");
    }
    Temp empty;
    auto missing = make_journal_source(empty.path.string(), JournalMode::Authentication);
    {
        JournalCollector stale(*missing, std::string(unit), state.path.string(), JournalMode::Authentication);
        require(!stale.start() && read(file) == complete, "stale auth checkpoint reset");
    }
    auto malformed = complete;
    malformed.replace(malformed.rfind('\t') + 1, expected.back().size(), "invalid-classification");
    save(file, malformed);
    {
        JournalCollector bad(*source, std::string(unit), state.path.string(), JournalMode::Authentication);
        require(!bad.start() && read(file) == malformed, "corrupt auth state accepted");
    }
}
} // namespace
int main(int argc, char** argv) {
    ::umask(0077);
    try {
        parser();
        if (argc != 2) { return 2; }
        {
            Temp state;
            auto source = make_journal_source(argv[1]);
            JournalCollector metadata(*source, "ssh.service", state.path.string());
            require(metadata.start() && metadata.pump() && metadata.count() == 6, "metadata mode regression");
            const auto data = read(state.path / "journal-m52.v1");
            require(data.find("ssh-accepted") == std::string::npos && data.find("private-") == std::string::npos &&
                    data.find("unclassified") == std::string::npos && !fs::exists(state.path / "auth-m53.v1"),
                    "metadata mode unexpectedly persisted classification");
        }
        native(argv[1], "ssh.service", {"ssh-accepted", "ssh-failed", "session-opened", "unclassified", "unclassified", "unclassified"});
        native(argv[1], "sshd.service", {"ssh-invalid-user", "session-closed"});
        native(argv[1], "systemd-logind.service", {"login-session-created", "login-session-removed"});
        native(argv[1], "getty@tty1.service", {"login-failed", "authentication-failed"});
        std::cout << "M5.3 populated native auth journal, privacy, cursor recovery and invalid state: PASS\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "M5.3 fixture failure: " << error.what() << '\n'; return 1; }
}
