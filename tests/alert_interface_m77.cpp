// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/service/alert_query.hpp>
#include <knetsentry/service/health_client.hpp>
#include <knetsentry/storage/sqlite_event_store.hpp>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <thread>
#include <sys/stat.h>
namespace {
using namespace knetsentry::service;
using namespace knetsentry::detection;
using namespace knetsentry::storage;
constexpr std::string_view id = "0123456789abcdef", session = "0123456789abcdef0123456789abcdef";
void require(bool ok,const char* message) { if (!ok) { throw std::runtime_error(message); } }
SchedulePolicy policy() {
    auto p = alert_profile(std::string(64,'e') + ':' + std::string(32,'a') + std::string(64,'b'));
    require(p.has_value(),"profile"); return std::move(*p);
}
void seed(const std::string& db,const std::string& scheduler,const std::string& alerts) {
    const auto p = policy();
    for (const auto* dir : {&db,&scheduler,&alerts}) { require(std::filesystem::is_empty(*dir),"new empty fixture required"); }
    require(db != scheduler && db != alerts && scheduler != alerts,"separate fixtures");
    require(initialize_schedule(p,scheduler) && initialize_alerts(p,alerts,true),"initialize");
    { std::ofstream scope(alerts + "/alert-scope-m77.v1"); scope << p.store_identity << ':' << p.binding << '\n'; scope.close(); require(scope.good(),"scope file"); }
    require(load_alert_profile(alerts).has_value(),"private scope");
    SqliteEventStore store(db);
    for (std::uint64_t i=1;i<=12;++i) {
        const auto row = "fixture-cursor-" + std::to_string(i) + "\t1795000000123456\t42\t" + std::string(32,'c') + '\t' + std::string(32,'d') + "\tssh.service\tssh-failed\n";
        const auto result = store.append({p.binding,"ssh.service",row,knetsentry::agent::JournalMode::Authentication,1000+i});
        require(result.status == StoreStatus::Ok && store.index(result.id).status == StoreStatus::Ok,"admission");
    }
    const auto batch = run_schedule(p,scheduler,store,1012,true,EvidenceTrust::VerifiedStored,Coverage::Partial);
    require(batch.status == ScheduleStatus::Evaluated && batch.findings.size() == 11,"fixture candidates");
    require(consume_alerts(p,alerts,scheduler,store,batch.generation,1013,true,EvidenceTrust::VerifiedStored) == AlertResult::Ok && acknowledge_schedule(p,scheduler,batch.generation),"fixture alerts");
}
class Fixture final {
public:
    Fixture() { char pattern[] = "/var/tmp/ks-m77-XXXXXX"; const auto* p = ::mkdtemp(pattern); require(p != nullptr,"fixture"); path = p; }
    ~Fixture() { std::error_code error; std::filesystem::remove_all(path,error); }
    Fixture(const Fixture&) = delete; Fixture& operator=(const Fixture&) = delete;
    std::string path;
};
void verify() {
    Fixture db, scheduler, alerts; seed(db.path,scheduler.path,alerts.path);
    const auto p = policy(); SqliteEventStore store(db.path,LegacyIntegrityPolicy::Reject,{},StorageOpenMode::ExistingV4);
    const auto scope = alerts.path + "/alert-scope-m77.v1";
    require(::chmod(scope.c_str(),0644) == 0 && !load_alert_profile(alerts.path),"unsafe scope permissions");
    require(::chmod(scope.c_str(),0600) == 0 && load_alert_profile(alerts.path).has_value(),"scope recovery");
    const auto pending = alerts.path + "/alerts-m76.pending";
    { std::ofstream file(pending); file << "abandoned"; }
    require(read_alerts(p,alerts.path,true,false).result == AlertResult::Unavailable && std::filesystem::exists(pending),"inspection must not remove pending state");
    require(read_alerts(p,alerts.path,true).result == AlertResult::Ok && !std::filesystem::exists(pending),"explicit recovery");
    const auto call = [&](const AlertQuery& q,bool writable = true) {
        const auto encoded = encode_alert_request(q,id); require(decode_alert_request(encoded,id).has_value(),"request codec");
        const auto response = query_alerts(p,alerts.path,store,session,q,id,writable,"uid-1000",1014);
        require(response.find("fixture-cursor") == response.npos && response.find(p.binding) == response.npos,"privacy");
        auto page = decode_alert_page(response,id,q); require(page.has_value(),"response codec"); return std::move(*page);
    };
    AlertQuery q; const auto first = call(q); require(first.rows.size() == 8 && first.more && first.rows.front().trigger == 2,"first page");
    q.offset = 8; q.session = session; const auto last = call(q); require(last.rows.size() == 3 && !last.more && last.rows.front().trigger == 10,"second page");
    q = {}; q.severity = 4; require(call(q).rows.empty(),"severity exclusion"); q.severity = 3; require(call(q).rows.size() == 8,"severity inclusion");
    const auto original = store.raw(1); require(original.value.has_value(),"original");
    q = {}; q.operation = AlertQuery::Operation::Evidence; q.session = session; q.generation = 1; q.trigger = 2; q.revision = 1; q.evidence = 1;
    require(call(q).evidence == 1,"exact link"); q.evidence = 3; require(call(q).result == "DENIED","unlinked ID");
    q.operation = AlertQuery::Operation::Acknowledge; q.evidence = 0;
    require(call(q,false).result == "DENIED","read only"); q.session = std::string(32,'f'); require(call(q).result == "STALE","old manager"); q.session = session;
    require(call(q).result == "OK" && call(q).result == "STALE","ack and replay");
    const auto after = store.raw(1); require(after.value && after.value->canonical_row == original.value->canonical_row && after.value->integrity && original.value->integrity && after.value->integrity->sha256 == original.value->integrity->sha256 && after.value->held == original.value->held,"evidence invariance");
    q = {}; const auto refreshed = call(q); require(refreshed.rows.front().status == 1 && refreshed.rows.front().revision == 2,"durable status");
    require(!decode_alert_request(encode_alert_request(q,id)+"x",id),"trailing request");
    const auto response = query_alerts(p,alerts.path,store,session,q,id,true,"uid-1000",1014);
    require(!decode_alert_page(response+"x\n",id,q) && !decode_alert_page(response,"ffffffffffffffff",q),"malformed response");
    const auto plan = store.preview_retention(1015,32); require(plan.plan && store.apply_retention(*plan.plan).status == StoreStatus::Ok,"expire evidence");
    q = {}; q.operation = AlertQuery::Operation::Evidence; q.session = session; q.generation = 1; q.trigger = 2; q.revision = 2; q.evidence = 1;
    require(call(q).result == "UNAVAILABLE","expired evidence");
    std::cout << "M7.7 bounded alert protocol, filtering, acknowledgement, exact evidence and retention refusal: PASS\n";
}
void client(std::string_view directory) {
    HealthClient c; AlertQuery q; c.begin_alerts(directory,id,q);
    const auto end = std::chrono::steady_clock::now()+std::chrono::seconds(3);
    while (c.state() == HealthQueryState::Pending && std::chrono::steady_clock::now() < end) { c.advance(); std::this_thread::sleep_for(std::chrono::milliseconds(5)); }
    require(c.state() == HealthQueryState::Available && c.alerts() && c.alerts()->rows.size() == 8,"native client");
}
} // namespace
int main(int argc,char** argv) try {
    ::umask(0077);
    if (argc == 5 && std::string_view(argv[1]) == "--seed") { seed(argv[2],argv[3],argv[4]); return 0; }
    if (argc == 3 && std::string_view(argv[1]) == "--client") { client(argv[2]); return 0; }
    require(argc == 1,"arguments"); verify(); return 0;
} catch (const std::exception& e) { std::cerr << "M7.7 test failure: " << e.what() << '\n'; return 1; }
