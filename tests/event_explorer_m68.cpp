// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/service/event_query.hpp>
#include <knetsentry/service/health_client.hpp>
#include <knetsentry/service/local_ipc.hpp>
#include <knetsentry/storage/sqlite_event_store.hpp>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <utility>
#include <unistd.h>
#include <sys/stat.h>

namespace {
using namespace knetsentry::service;
using namespace knetsentry::storage;
using namespace knetsentry::agent;
constexpr std::string_view request_id = "0123456789abcdef";
constexpr std::string_view session = "0123456789abcdef0123456789abcdef";
void require(bool ok, const char* message) { if (!ok) { throw std::runtime_error(message); } }
class Fixture final {
public:
    Fixture() {
        char name[] = "/var/tmp/ks-m68-XXXXXX";
        const auto* path = mkdtemp(name); require(path != nullptr, "fixture directory"); directory = path;
    }
    ~Fixture() { std::error_code error; std::filesystem::remove_all(directory, error); }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;
    std::string directory;
};
void populate(EventStore& store) {
    const std::string binding(96, 'a');
    for (std::uint64_t i = 1; i <= 21; ++i) {
        const bool success = i % 2 == 1;
        const std::string unit = success ? "sshd.service" : "ssh.service";
        const auto wire = "fixture-cursor-" + std::to_string(i) + '\t' + std::to_string(1795000000000000ULL + i * 1000U) + "\t42\t" +
            std::string(32, 'c') + '\t' + std::string(32, 'd') + '\t' + unit + (success ? "\tssh-accepted\n" : "\tssh-failed\n");
        const auto result = store.append({binding, unit, wire, JournalMode::Authentication, 1795000000000ULL + i});
        require(result.status == StoreStatus::Ok && result.id == i, "admission");
        if (i != 21) { require(store.index(i).status == StoreStatus::Ok, "index"); }
    }
}
EventPage fetch(const EventStore& store, const EventQuery& q) {
    const auto request = encode_event_request(q, request_id);
    const auto decoded = decode_event_request(request, request_id);
    require(decoded.has_value(), "request roundtrip");
    const auto response = query_events(&store, session, *decoded, request_id);
    require(response.find("fixture-cursor") == response.npos && response.find(std::string(96, 'a')) == response.npos, "private evidence leaked");
    auto page = decode_event_page(response, request_id, q); require(page.has_value(), "response roundtrip");
    return std::move(*page);
}
void verify(EventStore& store) {
    EventQuery q;
    const auto first = fetch(store, q);
    require(first.page.events.size() == 8 && first.page.events.front().id == 1 && first.page.events.back().id == 8 && first.page.more, "first page");
    q.after = 8; q.revision = first.page.revision; q.session = first.session;
    const auto next = fetch(store, q);
    require(next.page.events.size() == 8 && next.page.events.front().id == 9 && next.page.events.back().id == 16 && next.page.more, "next page");
    q.after = 16; const auto last = fetch(store, q);
    require(last.page.events.size() == 4 && last.page.events.back().id == 20 && !last.page.more, "last page");
    q = {}; q.descending = true; q.source = "ssh.service"; q.mode = 1; q.outcome = 2;
    const auto reverse = fetch(store, q);
    require(reverse.page.events.size() == 8 && reverse.page.events.front().id == 20 && reverse.page.events.back().id == 6 && reverse.page.more, "global descending filter");
    q.after = 6; q.revision = reverse.page.revision; q.session = reverse.session;
    const auto rest = fetch(store, q);
    require(rest.page.events.size() == 2 && rest.page.events.front().id == 4 && rest.page.events.back().id == 2 && !rest.page.more, "descending continuation");
    q.session = std::string(32, 'b'); require(fetch(store, q).page.status == StoreStatus::Stale, "instance mismatch");
    q.session = reverse.session; require(store.index(21).status == StoreStatus::Ok, "mutation");
    require(fetch(store, q).page.status == StoreStatus::Stale, "revision mismatch");
    q = {}; q.mode = 2; const auto empty = fetch(store, q); require(empty.page.status == StoreStatus::Ok && empty.page.events.empty(), "empty filter");
    q.source = "*.service"; require(encode_event_request(q, request_id).empty(), "wildcard");
    require(!decode_event_request("KSIPC/1 EVENTS 0123456789abcdef A - - - 0 0 - extra\n", request_id), "extra field");
    q = {}; const auto good = query_events(&store, session, q, request_id);
    require(!decode_event_page(good + "extra\n", request_id, q), "trailing data");
    require(!decode_event_page(good, "ffffffffffffffff", q), "wrong request id");
    require(!decode_event_page(good.substr(0, good.size() - 1), request_id, q), "truncation");
    auto wrong = good; const auto pos = wrong.find("sshd.service"); require(pos != wrong.npos, "fixture source");
    wrong.replace(pos, 12, "<b>service</b>"); require(!decode_event_page(wrong, request_id, q), "untrusted source text");
    q.outcome = 2; require(!decode_event_page(good, request_id, q), "response filter mismatch");
    require(!authorize_local_peer(1001, 1000, 1000, 1000, IpcAction::Events) &&
        !authorize_local_peer(1000, 1001, 1000, 1000, IpcAction::Events) &&
        authorize_local_peer(1000, 1000, 1000, 1000, IpcAction::Events), "peer authorization");
}
EventPage client_page(std::string_view dir, const EventQuery& q) {
    HealthClient client; client.begin_events(dir, request_id, q);
    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(3);
    while (client.state() == HealthQueryState::Pending && std::chrono::steady_clock::now() < end) {
        client.advance(); std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    require(client.state() == HealthQueryState::Available && client.events().has_value(), "live client");
    return *client.events();
}
void client_check(std::string_view dir) {
    EventQuery q; q.descending = true; q.outcome = 2;
    const auto first = client_page(dir, q);
    require(first.page.status == StoreStatus::Ok && first.page.events.size() == 8 && first.page.events.front().id == 20 && first.page.events.back().id == 6 && first.page.more, "live first");
    q.after = 6; q.revision = first.page.revision; q.session = first.session;
    const auto next = client_page(dir, q);
    require(next.page.status == StoreStatus::Ok && next.page.events.size() == 2 && next.page.events.front().id == 4 && next.page.events.back().id == 2 && !next.page.more, "live next");
    q.session = std::string(32, 'f'); require(client_page(dir, q).page.status == StoreStatus::Stale, "live stale instance");
}
} // namespace
int main(int argc, char** argv) try {
    ::umask(0077);
    if (argc == 3 && std::string_view(argv[1]) == "--seed") {
        // Test-only, never populate an existing database or a nonempty directory.
        require(std::filesystem::is_empty(argv[2]), "fixture requires a new empty private directory");
        SqliteEventStore store(argv[2]); populate(store);
        std::cout << "M6.8 synthetic persistent fixture: PASS\n"; return 0;
    }
    if (argc == 3 && std::string_view(argv[1]) == "--client") { client_check(argv[2]); return 0; }
    require(argc == 1, "arguments");
    MemoryEventStore memory; populate(memory); verify(memory);
    Fixture fixture;
    bool refused = false;
    try { SqliteEventStore missing(fixture.directory, LegacyIntegrityPolicy::Reject, {}, StorageOpenMode::ExistingV4); }
    catch (const std::runtime_error&) { refused = true; }
    require(refused && std::filesystem::is_empty(fixture.directory), "inspection created a database");
    { SqliteEventStore store(fixture.directory); populate(store); }
    { SqliteEventStore store(fixture.directory, LegacyIntegrityPolicy::Reject, {}, StorageOpenMode::ExistingV4); verify(store); }
    std::cout << "M6.8 bounded explorer protocol, global ordering, filter parity and continuation: PASS\n";
    return 0;
} catch (const std::exception& e) { std::cerr << "M6.8 test failure: " << e.what() << '\n'; return 1; }
