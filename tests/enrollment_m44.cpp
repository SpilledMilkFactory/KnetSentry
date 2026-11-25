// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/core/tls_transport.hpp>
#include <knetsentry/core/enrollment.hpp>
#include <knetsentry/core/agent_health.hpp>
#include <filesystem>
#include <chrono>
#include <thread>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdlib>
#include <algorithm>
#include <array>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace {
using namespace knetsentry::identity;
using namespace knetsentry::tls;
namespace enroll = knetsentry::enrollment;
using E = enroll::Status;
using Cert = std::unique_ptr<X509, decltype(&X509_free)>;
void require(bool ok, std::string_view reason) {
    if (!ok) { throw std::runtime_error(std::string(reason)); }
}
void extension(X509* cert, X509* issuer, int nid, const char* value) {
    X509V3_CTX ctx{};
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
    std::unique_ptr<X509_EXTENSION, decltype(&X509_EXTENSION_free)> ext(
        X509V3_EXT_conf_nid(nullptr, &ctx, nid, value), X509_EXTENSION_free);
    require(ext && X509_add_ext(cert, ext.get(), -1) == 1, "fixture extension");
}
Cert certificate(EVP_PKEY* subject, X509* issuer, EVP_PKEY* signer,
    const char* name, const char* eku, long before = -60, long after = 3600) {
    Cert cert(X509_new(), X509_free);
    require(cert && X509_set_version(cert.get(), 2) == 1, "fixture X509 version");
    require(ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), issuer == nullptr ? 1 : (eku != nullptr && std::string_view(eku) == "serverAuth" ? 3 : 2)) == 1,
        "fixture serial");
    require(X509_gmtime_adj(X509_getm_notBefore(cert.get()), before) != nullptr &&
        X509_gmtime_adj(X509_getm_notAfter(cert.get()), after) != nullptr, "fixture times");
    auto* dn = X509_get_subject_name(cert.get());
    require(X509_NAME_add_entry_by_txt(dn, "CN", MBSTRING_ASC,
        reinterpret_cast<const unsigned char*>(name), -1, -1, 0) == 1, "fixture name");
    require(X509_set_issuer_name(cert.get(), issuer == nullptr ? dn : X509_get_subject_name(issuer)) == 1 &&
        X509_set_pubkey(cert.get(), subject) == 1, "fixture issuer/key");
    extension(cert.get(), issuer == nullptr ? cert.get() : issuer, NID_basic_constraints,
        issuer == nullptr ? "critical,CA:TRUE,pathlen:0" : "critical,CA:FALSE");
    extension(cert.get(), issuer == nullptr ? cert.get() : issuer, NID_key_usage,
        issuer == nullptr ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature");
    extension(cert.get(), issuer == nullptr ? cert.get() : issuer, NID_subject_key_identifier, "hash");
    if (issuer != nullptr) {
        extension(cert.get(), issuer, NID_authority_key_identifier, "keyid:always");
        if (eku != nullptr) { extension(cert.get(), issuer, NID_ext_key_usage, eku); }
    }
    require(X509_sign(cert.get(), signer, nullptr) > 0, "fixture sign");
    return cert;
}
std::vector<unsigned char> der(X509* cert) {
    const int size = i2d_X509(cert, nullptr);
    require(size > 0, "fixture DER length");
    std::vector<unsigned char> bytes(static_cast<std::size_t>(size));
    auto* cursor = bytes.data();
    require(i2d_X509(cert, &cursor) == size, "fixture DER encode");
    return bytes;
}
struct Fixture {
    Key ca{EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519")};
    Key agent{EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519")};
    Key manager{EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519")};
    Key other{EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519")};
    Cert root{nullptr, X509_free};
    Cert client{nullptr, X509_free};
    Cert server{nullptr, X509_free};
    std::vector<unsigned char> anchor, client_der, server_der;
    Fingerprint agent_pin{}, manager_pin{}, other_pin{};
    Fixture() {
        require(ca && agent && manager && other, "fixture keys");
        root = certificate(ca.get(), nullptr, ca.get(), "root", nullptr);
        client = certificate(agent.get(), root.get(), ca.get(), "agent", "clientAuth");
        server = certificate(manager.get(), root.get(), ca.get(), "manager", "serverAuth");
        anchor = der(root.get()); client_der = der(client.get()); server_der = der(server.get());
        agent_pin = fingerprint(agent.get()).value(); manager_pin = fingerprint(manager.get()).value();
        other_pin = fingerprint(other.get()).value();
    }
    Credentials a() const { return {Role::Agent, agent.get(), client_der, anchor, manager_pin}; }
    Credentials m() const { return {Role::Manager, manager.get(), server_der, anchor, agent_pin}; }
};
void pump(Session& from, Session& to, std::size_t chunk = 137) {
    std::array<unsigned char, max_ciphertext_chunk> buffer{};
    for (int i = 0; i < 1024; ++i) {
        auto out = from.drain(std::span(buffer).first(chunk));
        if (out.status != Status::Ok) { return; }
        auto in = to.ingest(std::span(buffer).first(out.bytes));
        require(in.status == Status::Ok && in.bytes == out.bytes, "fixture ciphertext delivery");
    }
    throw std::runtime_error("fixture pump budget");
}
bool connect(Session& a, Session& m) {
    for (int i = 0; i < 100; ++i) {
        (void)a.handshake();
        if (a.state() == State::Failed) { return false; }
        pump(a, m);
        (void)m.handshake();
        if (m.state() == State::Failed) { return false; }
        pump(m, a);
        if (a.state() == State::Trusted && m.state() == State::Trusted) { return true; }
    }
    throw std::runtime_error("fixture handshake budget");
}
struct Store {
    std::array<char, 32> path{'/','t','m','p','/','k','s','-','m','4','4','-','X','X','X','X','X','X','\0'};
    int fd{-1};
    Store() {
        require(mkdtemp(path.data()) != nullptr, "private fixture directory");
        fd = open(path.data(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) { (void)rmdir(path.data()); throw std::runtime_error("fixture directory open"); }
    }
    ~Store() {
        if (fd >= 0) { (void)close(fd); }
        std::error_code error;
        (void)std::filesystem::remove_all(path.data(), error);
    }
    Store(const Store&) = delete;
    Store& operator=(const Store&) = delete;
};
void storage(Fixture& fixture) {
    Store store;
    enroll::EndpointId id{}; id.at(0) = 1;
    auto other = id; other.at(0) = 2;
    require(enroll::lookup(store.fd, id).status == E::Unavailable, "missing registry must deny");
    require(enroll::approve(store.fd, id, fixture.agent_pin) == E::Unavailable, "implicit initialization");
    require(enroll::initialize(AT_FDCWD) == E::UnsafeStorage, "ambient cwd accepted");
    require(enroll::initialize(store.fd) == E::Ok, "initialize");
    require(enroll::initialize(store.fd) == E::Conflict, "reset existing registry");
    // Nonnegative descriptors can still fail the directory reopen (EBADF/ENOTDIR).
    const auto reject_descriptor = [&](int fd) {
        const auto roster = enroll::inspect(fd);
        require(enroll::initialize(fd) == E::UnsafeStorage &&
            enroll::approve(fd, id, fixture.agent_pin) == E::UnsafeStorage &&
            enroll::rotate(fd, id, fixture.agent_pin, fixture.other_pin) == E::UnsafeStorage &&
            enroll::revoke(fd, id, fixture.agent_pin) == E::UnsafeStorage &&
            enroll::lookup(fd, id).status == E::UnsafeStorage &&
            roster.status == E::UnsafeStorage && roster.size == 0,
            "invalid directory descriptor accepted");
    };
    const int file = openat(store.fd, "endpoints.v1", O_RDONLY | O_CLOEXEC);
    require(file >= 0, "non-directory descriptor fixture");
    reject_descriptor(file);
    require(close(file) == 0, "descriptor close");
    reject_descriptor(file);
    reject_descriptor(AT_FDCWD);
    const auto unchanged = enroll::inspect(store.fd);
    require(unchanged.status == E::Ok && unchanged.size == 0, "invalid descriptor changed registry");
    std::cout << "M4.7 registry reopen failure across all operations: PASS\n";
    require(enroll::lookup(store.fd, id).status == E::Unknown, "unknown ID");
    require(enroll::approve(store.fd, {}, fixture.agent_pin) == E::InvalidInput &&
        enroll::approve(store.fd, id, {}) == E::InvalidInput, "zero fields");
    require(enroll::approve(store.fd, id, fixture.agent_pin) == E::Ok, "explicit approval");
    require(enroll::approve(store.fd, id, fixture.other_pin) == E::Conflict &&
        enroll::approve(store.fd, other, fixture.agent_pin) == E::Conflict &&
        enroll::approve(store.fd, id, fixture.agent_pin) == E::Conflict, "duplicate replacement or alias");
    const int reopened = open(store.path.data(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(reopened >= 0, "reopen");
    const auto persisted = enroll::lookup(reopened, id);
    (void)close(reopened);
    require(persisted.status == E::Ok && persisted.pin == fixture.agent_pin, "persistent binding");
    require(flock(store.fd, LOCK_EX | LOCK_NB) == 0, "fixture lock");
    require(enroll::lookup(store.fd, id).status == E::Busy &&
        enroll::approve(store.fd, other, fixture.other_pin) == E::Busy, "concurrent access not denied");
    require(flock(store.fd, LOCK_UN) == 0, "fixture unlock");
    require(fchmod(store.fd, 0755) == 0, "unsafe directory setup");
    require(enroll::lookup(store.fd, id).status == E::UnsafeStorage, "unsafe directory accepted");
    require(fchmod(store.fd, 0700) == 0, "directory restore");
    require(fchmodat(store.fd, "endpoints.v1", 0644, 0) == 0, "unsafe file setup");
    require(enroll::lookup(store.fd, id).status == E::UnsafeStorage, "unsafe file accepted");
    require(fchmodat(store.fd, "endpoints.v1", 0600, 0) == 0, "file restore");
    require(linkat(store.fd, "endpoints.v1", store.fd, "alias", 0) == 0, "hardlink fixture");
    require(enroll::lookup(store.fd, id).status == E::UnsafeStorage, "hardlink accepted");
    require(unlinkat(store.fd, "alias", 0) == 0, "hardlink cleanup");
    require(renameat(store.fd, "endpoints.v1", store.fd, "saved") == 0, "save registry");
    require(symlinkat("saved", store.fd, "endpoints.v1") == 0, "symlink fixture");
    require(enroll::lookup(store.fd, id).status == E::UnsafeStorage, "symlink accepted");
    require(unlinkat(store.fd, "endpoints.v1", 0) == 0, "symlink cleanup");
    require(mkfifoat(store.fd, "endpoints.v1", 0600) == 0, "FIFO fixture");
    require(enroll::lookup(store.fd, id).status == E::UnsafeStorage, "FIFO accepted");
    require(unlinkat(store.fd, "endpoints.v1", 0) == 0 &&
        renameat(store.fd, "saved", store.fd, "endpoints.v1") == 0, "restore registry");
    for (const auto* name : {"endpoints.v1.pending", "endpoints.v1.new"}) {
        require(symlinkat("missing", store.fd, name) == 0, "stale marker fixture");
        require(enroll::lookup(store.fd, id).status == E::Corrupt &&
            enroll::approve(store.fd, other, fixture.other_pin) == E::Corrupt, "uncertain state accepted");
        require(unlinkat(store.fd, name, 0) == 0, "marker cleanup");
    }
    const int damaged = openat(store.fd, "endpoints.v1", O_WRONLY | O_APPEND | O_CLOEXEC);
    require(damaged >= 0, "damage fixture open");
    const auto count = write(damaged, "x", 1);
    (void)close(damaged);
    require(count == 1 && enroll::lookup(store.fd, id).status == E::Corrupt &&
        enroll::approve(store.fd, other, fixture.other_pin) == E::Corrupt, "trailing data accepted");
    std::cout << "M4.4 persistent unique approvals and fail-closed storage: PASS\n";
}
void malformed_registry(Fixture& fixture) {
    Store store;
    enroll::EndpointId id{}; id.at(0) = 1;
    require(enroll::initialize(store.fd) == E::Ok &&
        enroll::approve(store.fd, id, fixture.agent_pin) == E::Ok, "malformed fixture approval");
    const int fd = openat(store.fd, "endpoints.v1", O_RDWR | O_CLOEXEC);
    require(fd >= 0, "malformed fixture open");
    std::array<unsigned char, 48> record{};
    const auto read_count = pread(fd, record.data(), record.size(), 8);
    const auto write_count = pwrite(fd, record.data(), record.size(), 56);
    const bool duplicate_denied = enroll::lookup(store.fd, id).status == E::Corrupt;
    const int truncated = ftruncate(fd, 56);
    const unsigned char version = 2;
    const auto version_count = pwrite(fd, &version, 1, 5);
    const bool version_denied = enroll::lookup(store.fd, id).status == E::Corrupt;
    const int oversized = ftruncate(fd, 6153);
    const bool oversized_denied = enroll::lookup(store.fd, id).status == E::Corrupt;
    (void)close(fd);
    require(read_count == 48 && write_count == 48 && duplicate_denied && truncated == 0 &&
        version_count == 1 && version_denied && oversized == 0 && oversized_denied,
        "malformed registry accepted");
    std::cout << "M4.4 duplicate records, unknown version and oversized registry rejection: PASS\n";
}
void capacity() {
    Store store;
    require(enroll::initialize(store.fd) == E::Ok, "capacity init");
    for (std::size_t i = 1; i <= enroll::max_endpoints; ++i) {
        enroll::EndpointId id{}; id.at(0) = static_cast<unsigned char>(i);
        Fingerprint pin{}; pin.at(0) = static_cast<unsigned char>(i);
        require(enroll::approve(store.fd, id, pin) == E::Ok, "capacity fixture approval");
    }
    enroll::EndpointId extra{}; extra.at(1) = 1;
    Fingerprint pin{}; pin.at(1) = 1;
    require(enroll::approve(store.fd, extra, pin) == E::Full &&
        enroll::lookup(store.fd, extra).status == E::Unknown, "capacity limit");
    enroll::EndpointId first{}; first.at(0) = 1;
    Fingerprint first_pin{}; first_pin.at(0) = 1;
    require(enroll::rotate(store.fd, first, first_pin, pin) == E::Full &&
        enroll::lookup(store.fd, first).pin == first_pin &&
        enroll::revoke(store.fd, first, first_pin) == E::Ok &&
        enroll::lookup(store.fd, first).status == E::Revoked, "full registry must allow revocation");
    std::cout << "M4.4 bounded registry capacity: PASS\n";
}
void admission(Fixture& fixture) {
    Store store;
    enroll::EndpointId id{}; id.at(0) = 1;
    auto other = id; other.at(0) = 2;
    auto unknown = id; unknown.at(0) = 3;
    require(enroll::initialize(store.fd) == E::Ok, "admission init");
    auto a = Session::create(fixture.a()); auto m = Session::create(fixture.m());
    require(a && m, "TLS session creation");
    require(enroll::authorize(store.fd, id, *m) == E::NotAuthenticated, "prehandshake authority");
    require(connect(*a, *m), "TLS handshake");
    require(enroll::authorize(store.fd, id, *m) == E::Unknown, "valid unknown certificate auto-enrolled");
    require(enroll::lookup(store.fd, id).status == E::Unknown, "admission modified registry");
    require(enroll::approve(store.fd, id, fixture.agent_pin) == E::Ok &&
        enroll::approve(store.fd, other, fixture.other_pin) == E::Ok, "admin approval");
    // A fresh session uses only the approved pin from storage.
    auto creds = fixture.m(); const auto approved = enroll::lookup(store.fd, id);
    require(approved.status == E::Ok && approved.pin.has_value(), "approved pin");
    creds.peer_pin = approved.pin.value();
    a = Session::create(fixture.a()); m = Session::create(creds);
    require(a && m && connect(*a, *m), "approved handshake");
    require(enroll::authorize(store.fd, id, *m) == E::Ok, "approved agent denied");
    require(enroll::authorize(store.fd, other, *m) == E::IdentityMismatch &&
        enroll::authorize(store.fd, unknown, *m) == E::Unknown, "endpoint impersonation accepted");
    require(enroll::authorize(store.fd, id, *a) == E::NotAuthenticated, "agent-side session accepted");
    require(fchmod(store.fd, 0755) == 0 && enroll::authorize(store.fd, id, *m) == E::UnsafeStorage &&
        fchmod(store.fd, 0700) == 0, "unavailable registry allowed session");
    m->abort();
    require(enroll::authorize(store.fd, id, *m) == E::NotAuthenticated, "failed session accepted");
    auto rogue_cert = certificate(fixture.other.get(), fixture.root.get(), fixture.ca.get(), "agent", "clientAuth");
    const auto rogue_der = der(rogue_cert.get());
    auto rogue = fixture.a(); rogue.key = fixture.other.get(); rogue.certificate = rogue_der;
    a = Session::create(rogue); m = Session::create(creds);
    require(a && m && !connect(*a, *m), "same-CA different agent impersonated approved endpoint");
    require(enroll::authorize(store.fd, id, *m) == E::NotAuthenticated, "wrong pin session admitted");
    std::cout << "M4.4 real mTLS admission, unknown agent and identity impersonation rejection: PASS\n";
}
void lifecycle(Fixture& fixture) {
    Store store;
    enroll::EndpointId id{}; id.at(0) = 1;
    auto other = id; other.at(0) = 2;
    require(enroll::initialize(store.fd) == E::Ok &&
        enroll::approve(store.fd, id, fixture.agent_pin) == E::Ok, "lifecycle approval");
    auto a = Session::create(fixture.a()); auto m = Session::create(fixture.m());
    require(a && m && connect(*a, *m) && enroll::revalidate(store.fd, id, *m) == E::Ok,
        "initial admission");
    require(enroll::rotate(store.fd, id, fixture.other_pin, fixture.manager_pin) == E::Conflict &&
        enroll::rotate(store.fd, id, fixture.agent_pin, fixture.agent_pin) == E::Conflict &&
        enroll::revoke(store.fd, id, fixture.other_pin) == E::Conflict, "stale administrative operation");
    require(enroll::rotate(store.fd, id, fixture.agent_pin, fixture.other_pin) == E::Ok,
        "new key rotation");
    require(enroll::lookup(store.fd, id).pin == fixture.other_pin &&
        enroll::revalidate(store.fd, id, *m) == E::IdentityMismatch && m->state() == State::Failed,
        "superseded live session retained trust");
    require(enroll::approve(store.fd, other, fixture.agent_pin) == E::Conflict &&
        enroll::rotate(store.fd, id, fixture.other_pin, fixture.agent_pin) == E::Conflict,
        "retired key reused");
    auto renewed = certificate(fixture.other.get(), fixture.root.get(), fixture.ca.get(), "renewed", "clientAuth");
    const auto renewed_der = der(renewed.get());
    auto new_agent = fixture.a(); new_agent.key = fixture.other.get(); new_agent.certificate = renewed_der;
    auto new_manager = fixture.m(); new_manager.peer_pin = fixture.other_pin;
    a = Session::create(fixture.a()); m = Session::create(new_manager);
    require(a && m && !connect(*a, *m), "superseded certificate handshake accepted");
    a = Session::create(new_agent); m = Session::create(new_manager);
    require(a && m && connect(*a, *m) && enroll::revalidate(store.fd, id, *m) == E::Ok,
        "replacement certificate denied");
    require(enroll::revoke(store.fd, id, fixture.other_pin) == E::Ok &&
        enroll::lookup(store.fd, id).status == E::Revoked && !enroll::lookup(store.fd, id).pin &&
        enroll::revalidate(store.fd, id, *m) == E::Revoked && m->state() == State::Failed,
        "revoked session remained authorized");
    const int reopened = open(store.path.data(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(reopened >= 0, "lifecycle reopen");
    const auto persisted = enroll::lookup(reopened, id);
    (void)close(reopened);
    require(persisted.status == E::Revoked &&
        enroll::approve(store.fd, id, fixture.manager_pin) == E::Conflict &&
        enroll::approve(store.fd, other, fixture.other_pin) == E::Conflict &&
        enroll::rotate(store.fd, id, fixture.other_pin, fixture.manager_pin) == E::Revoked,
        "revocation not persistent or reusable");
    // A fresh handshake with stale cached credentials still cannot pass admission.
    a = Session::create(new_agent); m = Session::create(new_manager);
    require(a && m && connect(*a, *m) && enroll::revalidate(store.fd, id, *m) == E::Revoked &&
        m->state() == State::Failed, "revoked key with cached pin admitted");
    const int fd = openat(store.fd, "endpoints.v1", O_RDWR | O_CLOEXEC);
    require(fd >= 0, "lifecycle corruption fixture");
    const unsigned char invalid = 2;
    const auto written = pwrite(fd, &invalid, 1, 56);
    (void)close(fd);
    require(written == 1 && enroll::lookup(store.fd, id).status == E::Corrupt,
        "invalid lifecycle flag accepted");
    std::cout << "M4.5 rotation, permanent revocation, persistent retired keys and live revalidation: PASS\n";
}
void manager_lifecycle(Fixture& fixture) {
    auto a = Session::create(fixture.a()); auto m = Session::create(fixture.m());
    require(a && m && connect(*a, *m) && a->revalidate_peer(fixture.manager_pin) == Status::Ok,
        "initial manager pin");
    require(a->revalidate_peer(fixture.other_pin) == Status::Failed && a->state() == State::Failed,
        "stale manager session after pin replacement");
    const auto replacement = certificate(fixture.other.get(), fixture.root.get(), fixture.ca.get(),
        "replacement manager", "serverAuth");
    const auto replacement_der = der(replacement.get());
    auto agent = fixture.a(); agent.peer_pin = fixture.other_pin;
    auto manager = fixture.m(); manager.key = fixture.other.get(); manager.certificate = replacement_der;
    a = Session::create(agent); m = Session::create(fixture.m());
    require(a && m && !connect(*a, *m), "old manager handshake after pin replacement");
    a = Session::create(agent); m = Session::create(manager);
    require(a && m && connect(*a, *m) && a->revalidate_peer(fixture.other_pin) == Status::Ok &&
        a->revalidate_peer(std::nullopt) == Status::Failed && a->state() == State::Failed,
        "replacement manager or explicit removal of manager trust");
    std::cout << "M4.5 manager pin replacement and explicit trust removal: PASS\n";
}
void expiry(Fixture& fixture) {
    Store store;
    enroll::EndpointId id{}; id.at(0) = 1;
    require(enroll::initialize(store.fd) == E::Ok &&
        enroll::approve(store.fd, id, fixture.agent_pin) == E::Ok, "expiry approval");
    const auto short_cert = certificate(fixture.agent.get(), fixture.root.get(), fixture.ca.get(),
        "short", "clientAuth", -60, 4);
    const auto short_der = der(short_cert.get());
    auto creds = fixture.a(); creds.certificate = short_der;
    auto a = Session::create(creds); auto m = Session::create(fixture.m());
    require(a && m && connect(*a, *m) && enroll::authorize(store.fd, id, *m) == E::Ok,
        "short-lived initial admission");
    const std::array<unsigned char, 1> message{42};
    require(a->write(message).status == Status::Ok, "pre-expiry write");
    pump(*a, *m);
    const auto short_root = certificate(fixture.ca.get(), nullptr, fixture.ca.get(), "root", nullptr, -60, 4);
    const auto root_der = der(short_root.get());
    auto root_a = fixture.a(); root_a.root = root_der;
    auto root_m = fixture.m(); root_m.root = root_der;
    auto ar = Session::create(root_a); auto mr = Session::create(root_m);
    require(ar && mr && connect(*ar, *mr), "short-lived root handshake");
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(8);
    while ((X509_cmp_current_time(X509_get0_notAfter(short_cert.get())) == 1 ||
            X509_cmp_current_time(X509_get0_notAfter(short_root.get())) == 1) &&
        std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    require(X509_cmp_current_time(X509_get0_notAfter(short_cert.get())) == -1, "expiry fixture clock");
    std::array<unsigned char, max_plaintext> received{};
    received.fill(99);
    require(m->read(received).status == Status::Failed && received.front() == 99 &&
        m->state() == State::Failed && !m->authenticated_agent(), "expired peer plaintext exposed");
    require(a->write(message).status == Status::Failed && a->state() == State::Failed &&
        enroll::revalidate(store.fd, id, *m) == E::NotAuthenticated && !Session::create(creds),
        "expired credential retained trust");
    require(ar->state() == State::Failed && mr->state() == State::Failed &&
        !Session::create(root_a), "expired root retained trust");
    const auto future = certificate(fixture.agent.get(), fixture.root.get(), fixture.ca.get(),
        "future", "clientAuth", 60, 3600);
    const auto future_der = der(future.get()); creds.certificate = future_der;
    require(!Session::create(creds), "not-yet-valid credential accepted");
    std::cout << "M4.5 certificate expiration during TLS, buffered plaintext denial and future validity: PASS\n";
}
void heartbeat(Fixture& fixture) {
    namespace health = knetsentry::agent_health;
    namespace wire = knetsentry::core::agent_protocol;
    using H = health::Health;
    Store store;
    enroll::EndpointId id{}; id.at(0) = 1;
    auto unknown = id; unknown.at(0) = 2;
    require(enroll::initialize(store.fd) == E::Ok &&
        enroll::approve(store.fd, id, fixture.agent_pin) == E::Ok, "heartbeat approval");
    health::Tracker tracker(store.fd, id);
    health::Tracker stranger(store.fd, unknown);
    auto a = Session::create(fixture.a()); auto m = Session::create(fixture.m());
    require(a && m && !tracker.attach(std::move(m), 0), "unauthenticated attachment");
    m = Session::create(fixture.m());
    require(m && connect(*a, *m) && !stranger.attach(std::move(m), 0) &&
        stranger.poll(0).health == H::Untrusted, "unenrolled agent accepted");
    auto start = [&](health::Millis now) {
        a = Session::create(fixture.a()); m = Session::create(fixture.m());
        require(a && m && connect(*a, *m) && tracker.attach(std::move(m), now), "heartbeat attach");
        require(tracker.poll(now).health == H::Awaiting && !tracker.poll(now).counters, "initial health");
    };
    auto transfer = [&](health::Millis now) {
        std::array<unsigned char, max_ciphertext_chunk> buffer{};
        for (int i = 0; i < 1024; ++i) {
            const auto out = a->drain(std::span(buffer).first(17));
            if (out.status == Status::WouldBlock) { return; }
            require(out.status == Status::Ok, "heartbeat ciphertext output");
            const auto in = tracker.ingest(std::span(buffer).first(out.bytes), now);
            require(in.status == Status::Ok && in.bytes == out.bytes, "heartbeat ciphertext input");
        }
        throw std::runtime_error("heartbeat transfer budget");
    };
    auto send_raw = [&](std::span<const std::byte> bytes, health::Millis now) {
        const auto sent = a->write({reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()});
        require(sent.status == Status::Ok && sent.bytes == bytes.size(), "fixture write");
        transfer(now);
    };
    start(10);
    {
        health::Reporter reporter(*a);
        require(reporter.send(fixture.manager_pin, 10, {100, 0}) == Status::Ok, "reporter hello");
        transfer(10);
        require(tracker.poll(10).health == H::Awaiting, "hello marked healthy");
        require(reporter.send(fixture.manager_pin, 10, {100, 0}) == Status::Ok, "first report");
        transfer(10);
        auto snap = tracker.poll(10);
        require(snap.health == H::Healthy && snap.counters && snap.counters->uptime_ms == 100 &&
            snap.counters->dropped_records == 0, "healthy report");
        require(reporter.send(fixture.manager_pin, 30009, {200, 1}) == Status::NotReady, "early report");
        require(reporter.send(fixture.manager_pin, 30010, {200, 1}) == Status::Ok, "second report");
        transfer(30010);
        snap = tracker.poll(30010);
        require(snap.health == H::Degraded && snap.counters && snap.counters->dropped_records == 1, "degraded report");
    }
    auto duplicate_a = Session::create(fixture.a()); auto duplicate_m = Session::create(fixture.m());
    require(duplicate_a && duplicate_m && connect(*duplicate_a, *duplicate_m) &&
        !tracker.attach(std::move(duplicate_m), 30011) && tracker.poll(30011).health == H::Degraded,
        "competing connection displaced live health");
    require(tracker.poll(120009).health == H::Degraded && tracker.poll(120010).health == H::Missing &&
        !tracker.poll(120010).counters, "missing deadline or stale metrics");
    std::cout << "M4.6 actual authenticated reporting, cadence, degradation and missing deadline: PASS\n";

    const auto hello = wire::encode({wire::Kind::Hello, 1, 0, 0});
    const auto beat = wire::encode({wire::Kind::Heartbeat, 2, 1, 0});
    start(120011);
    send_raw(std::span(hello.bytes).first(7), 120011);
    require(tracker.poll(120011).health == H::Awaiting, "partial hello");
    std::array<std::byte, wire::header_size + wire::max_frame_size> combined{};
    std::copy_n(hello.bytes.begin() + 7, hello.size - 7, combined.begin());
    std::copy_n(beat.bytes.begin(), beat.size, combined.begin() + static_cast<std::ptrdiff_t>(hello.size - 7));
    send_raw(std::span(combined).first(hello.size - 7 + beat.size), 120012);
    require(tracker.poll(120012).health == H::Healthy, "fragmented/coalesced frames");
    send_raw(std::span(beat.bytes).first(beat.size), 120013);
    require(tracker.poll(120013).health == H::ProtocolError && !tracker.poll(120013).counters,
        "duplicate sequence refreshed health");
    start(120014);
    send_raw(std::span(beat.bytes).first(beat.size), 120014);
    require(tracker.poll(120014).health == H::ProtocolError, "heartbeat without hello");
    start(120015);
    send_raw(std::span(hello.bytes).first(hello.size), 120015);
    require(tracker.poll(120015).health == H::Awaiting, "hello only");
    require(tracker.poll(210015).health == H::Missing, "hello-only missing deadline");
    start(210016);
    auto malformed = hello; malformed.bytes[8] = std::byte{0xff};
    send_raw(std::span(malformed.bytes).first(malformed.size), 210016);
    require(tracker.poll(210016).health == H::ProtocolError, "oversized frame");
    start(210017);
    send_raw(std::span(hello.bytes).first(hello.size), 210017);
    (void)tracker.poll(210017);
    send_raw(std::span(beat.bytes).first(beat.size), 210018);
    require(tracker.poll(210018).health == H::Healthy, "reconnect report");
    const auto regressed = wire::encode({wire::Kind::Heartbeat, 3, 0, 0});
    send_raw(std::span(regressed.bytes).first(regressed.size), 210019);
    require(tracker.poll(210019).health == H::ProtocolError, "counter regression");
    start(210020);
    send_raw(std::span(hello.bytes).first(hello.size), 210020);
    (void)tracker.poll(210020);
    send_raw(std::span(beat.bytes).first(beat.size), 210021);
    require(tracker.poll(210021).health == H::Healthy, "fresh report");
    require(tracker.poll(210020).health == H::Untrusted && !tracker.poll(210021).counters, "clock regression");
    start(210022);
    {
        health::Reporter denied(*a);
        require(denied.send(std::nullopt, 210022, {}) == Status::Failed && a->state() == State::Failed,
            "reporter accepted withdrawn manager approval");
    }
    tracker.disconnected();
    require(tracker.poll(210022).health == H::Missing && !tracker.poll(210022).counters, "transport loss");
    start(210022);
    require(flock(store.fd, LOCK_EX | LOCK_NB) == 0, "registry lock fixture");
    require(tracker.poll(210022).health == H::Untrusted && !tracker.poll(210022).counters, "busy registry accepted");
    require(flock(store.fd, LOCK_UN) == 0, "registry unlock fixture");
    start(210022);
    require(enroll::rotate(store.fd, id, fixture.agent_pin, fixture.other_pin) == E::Ok &&
        tracker.poll(210023).health == H::Untrusted, "idle rotation revalidation");
    a = Session::create(fixture.a()); m = Session::create(fixture.m());
    require(a && m && connect(*a, *m) && !tracker.attach(std::move(m), 210024), "retired key reattached");
    const auto replacement_cert = certificate(fixture.other.get(), fixture.root.get(), fixture.ca.get(),
        "replacement", "clientAuth");
    const auto replacement_der = der(replacement_cert.get());
    auto replacement_a = fixture.a(); replacement_a.key = fixture.other.get(); replacement_a.certificate = replacement_der;
    auto replacement_m = fixture.m(); replacement_m.peer_pin = fixture.other_pin;
    a = Session::create(replacement_a); m = Session::create(replacement_m);
    require(a && m && connect(*a, *m) && tracker.attach(std::move(m), 210025), "replacement attachment");
    send_raw(std::span(hello.bytes).first(hello.size), 210025);
    (void)tracker.poll(210025);
    send_raw(std::span(beat.bytes).first(beat.size), 210026);
    require(tracker.poll(210026).health == H::Healthy, "replacement report");
    const auto queued = wire::encode({wire::Kind::Heartbeat, 3, 2, 0});
    send_raw(std::span(queued.bytes).first(queued.size), 210027);
    require(enroll::revoke(store.fd, id, fixture.other_pin) == E::Ok &&
        tracker.poll(210027).health == H::Untrusted && !tracker.poll(210027).counters,
        "revoked agent updated buffered health");
    std::cout << "M4.6 framing, ordering, timeout, clock and current enrollment rejection: PASS\n";

    health::Reconnect retry;
    using P = health::Reconnect::Phase;
    const auto first = retry.begin(0);
    require(first && !retry.begin(0) && retry.phase(9999) == P::Connecting &&
        retry.phase(10000) == P::Waiting && !retry.connected(10000, *first) && !retry.begin(10999), "attempt timeout");
    const auto second = retry.begin(11000);
    require(second && *second != *first && !retry.connected(11001, *first), "stale attempt completion");
    retry.lost(11001, *first);
    require(retry.phase(11001) == P::Connecting && retry.connected(11001, *second), "stale loss affected current attempt");
    retry.lost(11002, *second);
    require(!retry.begin(13001), "second cooldown");
    health::Millis now = 13002;
    for (const health::Millis delay : {4000U, 8000U, 16000U, 32000U, 60000U, 60000U}) {
        const auto attempt = retry.begin(now);
        require(attempt.has_value(), "retry not due");
        retry.lost(now, *attempt);
        require(!retry.begin(now + delay - 1), "backoff too short");
        now += delay;
    }
    const auto stable = retry.begin(now);
    require(stable && retry.connected(now, *stable), "stable connection");
    now += health::missing_after;
    retry.lost(now, *stable);
    require(!retry.begin(now + 999) && retry.begin(now + 1000).has_value() &&
        retry.phase(now) == P::Blocked && !retry.begin(now + 100000), "stable reset or clock regression");
    std::cout << "M4.6 bounded reconnect, stale attempt rejection and clock regression: PASS\n";
}
} // namespace
int main(int argc, char** argv) {
    try {
        Fixture fixture;
        if (argc == 2 && std::string_view(argv[1]) == "--lifecycle") {
            lifecycle(fixture); manager_lifecycle(fixture); expiry(fixture);
        } else if (argc == 2 && std::string_view(argv[1]) == "--heartbeat") {
            heartbeat(fixture);
        } else if (argc == 1) {
            storage(fixture); malformed_registry(fixture); capacity(); admission(fixture);
        } else { return 2; }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "M4.4 enrollment regression: FAIL: " << error.what() << '\n'; return 1;
    }
}
