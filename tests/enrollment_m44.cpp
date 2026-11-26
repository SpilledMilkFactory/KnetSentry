// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/core/tls_transport.hpp>
#include <knetsentry/agent/delivery.hpp>
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
    Credentials a(Protocol protocol = Protocol::Ksap) const { return {Role::Agent, agent.get(), client_der, anchor, manager_pin, protocol}; }
    Credentials m(Protocol protocol = Protocol::Ksap) const { return {Role::Manager, manager.get(), server_der, anchor, agent_pin, protocol}; }
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
// Exercise the composed trust boundary using real TLS records and disposable PKI.
void authentication_transport(Fixture& fixture) {
    namespace health = knetsentry::agent_health;
    namespace wire = knetsentry::core::agent_protocol;
    using H = health::Health;
    Store store;
    enroll::EndpointId id{}; id.at(0) = 1;
    auto unknown = id; unknown.at(0) = 2;
    require(enroll::initialize(store.fd) == E::Ok &&
        enroll::approve(store.fd, id, fixture.agent_pin) == E::Ok, "M4.8 registry setup");
    health::Tracker tracker(store.fd, id);
    std::unique_ptr<Session> a;
    health::Millis now = 1;
    const auto hello = wire::encode({wire::Kind::Hello, 1, 0, 0});
    const auto beat = wire::encode({wire::Kind::Heartbeat, 2, 100, 0});
    const auto next = wire::encode({wire::Kind::Heartbeat, 3, 200, 0});
    require(hello.error == wire::Error::None && beat.error == wire::Error::None &&
        next.error == wire::Error::None, "M4.8 fixture encoding");
    auto start = [&] {
        tracker.disconnected();
        ++now;
        a = Session::create(fixture.a());
        auto m = Session::create(fixture.m());
        require(a && m && connect(*a, *m) && tracker.attach(std::move(m), now), "M4.8 fresh admission");
        const auto snap = tracker.poll(now);
        require(snap.health == H::Awaiting && !snap.counters, "M4.8 new session inherited counters");
    };
    auto capture = [&](std::span<const std::byte> bytes) {
        const auto sent = a->write({reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()});
        require(sent.status == Status::Ok && sent.bytes == bytes.size(), "M4.8 fixture write");
        std::array<unsigned char, max_ciphertext_chunk> record{};
        const auto out = a->drain(record);
        require(out.status == Status::Ok && out.bytes > bytes.size() && out.bytes <= record.size(), "M4.8 record capture");
        std::array<unsigned char, max_ciphertext_chunk> extra{};
        require(a->drain(extra).status == Status::WouldBlock, "M4.8 unexpected additional record");
        const auto captured = std::span(record).first(out.bytes);
        return std::vector<unsigned char>(captured.begin(), captured.end());
    };
    auto deliver = [&](std::span<const unsigned char> record) {
        const auto in = tracker.ingest(record, now);
        require(in.status == Status::Ok && in.bytes == record.size(), "M4.8 ciphertext delivery");
    };
    auto send = [&](const wire::Encoded& frame) { deliver(capture(std::span(frame.bytes).first(frame.size))); };
    auto healthy = [&] {
        send(hello);
        require(tracker.poll(now).health == H::Awaiting, "M4.8 hello is not health");
        auto record = capture(std::span(beat.bytes).first(beat.size));
        deliver(record);
        const auto snap = tracker.poll(now);
        require(snap.health == H::Healthy && snap.counters && snap.counters->uptime_ms == 100 &&
            snap.counters->dropped_records == 0, "M4.8 positive health control");
        return record;
    };
    auto rejected = [&](H expected) {
        const auto snap = tracker.poll(now);
        require(snap.health == expected && !snap.counters, "M4.8 rejection or stale counters");
        const auto late = capture(std::span(next.bytes).first(next.size));
        const auto in = tracker.ingest(late, now);
        require(in.status == Status::Failed && in.bytes == 0, "M4.8 terminal session accepted late data");
        const auto after = tracker.poll(now);
        require(after.health == expected && !after.counters, "M4.8 late data resurrected health");
    };
    {
        auto agent = Session::create(fixture.a()); auto manager = Session::create(fixture.m());
        health::Tracker denied(store.fd, unknown);
        require(agent && manager && connect(*agent, *manager), "M4.8 unknown identity TLS control");
        require(!denied.attach(std::move(manager), now) && denied.poll(now).health == H::Untrusted &&
            !denied.poll(now).counters && enroll::lookup(store.fd, unknown).status == E::Unknown,
            "M4.8 unknown endpoint admitted or enrolled");
        auto wrong = fixture.m(); wrong.peer_pin = fixture.other_pin;
        agent = Session::create(fixture.a()); manager = Session::create(wrong);
        require(agent && manager && !connect(*agent, *manager) && manager->state() == State::Failed &&
            !manager->authenticated_agent(), "M4.8 incorrect pin accepted");
    }
    std::cout << "M4.8 unauthorized identity and enrollment separation: PASS\n";
    start();
    const auto old = healthy();
    deliver(old);
    rejected(H::Untrusted);
    start();
    (void)healthy();
    deliver(old);
    rejected(H::Untrusted);
    start();
    (void)healthy();
    send(beat);
    rejected(H::ProtocolError);
    start();
    (void)healthy();
    const auto gap = wire::encode({wire::Kind::Heartbeat, 4, 200, 0});
    send(gap);
    rejected(H::ProtocolError);
    std::cout << "M4.8 same-session and cross-session ciphertext replay, duplicate and skipped sequence: PASS\n";
    for (const std::size_t offset : {0U, 4U, 6U, 7U, 8U, 19U}) {
        start();
        (void)healthy();
        auto malformed = next;
        malformed.bytes.at(offset) = offset == 19 ? std::byte{0} : std::byte{0xff};
        send(malformed);
        rejected(H::ProtocolError);
    }
    std::cout << "M4.8 authenticated malformed KSAP corpus and terminal rejection: PASS\n";
    start();
    (void)healthy();
    const auto partial = capture(std::span(next.bytes).first(next.size));
    deliver(std::span(partial).first(partial.size() - 1));
    const auto pending = tracker.poll(now);
    require(pending.health == H::Healthy && pending.counters && pending.counters->uptime_ms == 100,
        "M4.8 incomplete TLS record changed health");
    tracker.disconnected();
    rejected(H::Missing);
    start();
    (void)healthy();
    send(wire::Encoded{wire::Error::None, next.bytes, wire::header_size + 1});
    const auto partial_frame = tracker.poll(now);
    require(partial_frame.health == H::Healthy && partial_frame.counters && partial_frame.counters->uptime_ms == 100,
        "M4.8 incomplete KSAP frame changed health");
    tracker.disconnected();
    rejected(H::Missing);
    start();
    (void)healthy();
    const auto queued = capture(std::span(next.bytes).first(next.size));
    deliver(queued);
    require(enroll::revoke(store.fd, id, fixture.agent_pin) == E::Ok, "M4.8 revoke");
    rejected(H::Untrusted);
    auto m = Session::create(fixture.m()); a = Session::create(fixture.a());
    require(a && m && connect(*a, *m) && !tracker.attach(std::move(m), ++now) &&
        tracker.poll(now).health == H::Untrusted && !tracker.poll(now).counters,
        "M4.8 revoked identity reattached despite valid TLS");
    std::cout << "M4.8 interrupted TLS and KSAP, fresh recovery, buffered revocation and denied reconnect: PASS\n";
    for (const auto& times : {std::array<long, 2>{-3600, -60}, std::array<long, 2>{3600, 7200}}) {
        const auto invalid = certificate(fixture.agent.get(), fixture.root.get(), fixture.ca.get(),
            "invalid time", "clientAuth", times[0], times[1]);
        const auto bytes = der(invalid.get());
        auto creds = fixture.a(); creds.certificate = bytes;
        require(!Session::create(creds), "M4.8 invalid validity interval accepted");
    }
    auto truncated = fixture.client_der; truncated.pop_back();
    auto creds = fixture.a(); creds.certificate = truncated;
    require(!Session::create(creds), "M4.8 truncated DER accepted");
    a = Session::create(fixture.a()); m = Session::create(fixture.m());
    require(a && m && a->handshake() == Status::WouldBlock, "M4.8 interrupted handshake control");
    pump(*a, *m);
    m->abort();
    std::array<unsigned char, max_plaintext> output{}; output.fill(0x55);
    const auto read = m->read(output);
    require(m->state() == State::Failed && !m->authenticated_agent() && m->handshake() == Status::Failed &&
        read.status == Status::Failed && read.bytes == 0 &&
        std::all_of(output.begin(), output.end(), [](unsigned char value) { return value == 0x55; }) &&
        m->write(std::span(output).first(1)).status == Status::Failed &&
        m->ingest(std::span(output).first(1)).status == Status::Failed &&
        m->drain(output).status == Status::Failed, "M4.8 interrupted handshake not terminal");
    std::cout << "M4.8 invalid certificate validity/DER and interrupted handshake: PASS\n";
}
namespace telemetry = knetsentry::agent;
using D = telemetry::DeliveryState;
struct DeliverySource final : telemetry::JournalSource {
    std::size_t position{}, total{129}, reads{};
    bool available{true};
    bool open(std::string_view unit) override { return available && unit == "fixture.service"; }
    bool resume(std::string_view cursor) override {
        if (!available) { return false; }
        if (cursor.empty()) { position = 0; return true; }
        for (std::size_t i = 1; i <= total; ++i) {
            if (cursor == "cursor-" + std::to_string(i)) { position = i; return true; }
        }
        return false;
    }
    telemetry::JournalResult next(telemetry::JournalRecord& record) override {
        ++reads;
        if (position == total) { return telemetry::JournalResult::End; }
        record = {"cursor-" + std::to_string(++position), "fixture.service", std::string(32, 'a'),
            std::string(32, 'b'), 100, 50};
        return telemetry::JournalResult::Record;
    }
    void close() noexcept override {}
};
// Test instrumentation wraps the real bounded durable inbox.
struct DeliverySink final : telemetry::ReceiptSink {
    telemetry::ReceiptInbox& inbox;
    bool reject{};
    std::size_t attempts{};
    explicit DeliverySink(telemetry::ReceiptInbox& value) : inbox(value) {}
    bool commit(const enroll::EndpointId& endpoint, std::string_view binding, std::string_view row) noexcept override {
        ++attempts;
        return !reject && inbox.commit(endpoint, binding, row);
    }
};
void telemetry_delivery(Fixture& f) {
    Store registry, spool, receipts;
    enroll::EndpointId id{}; id[0] = 1;
    require(enroll::initialize(registry.fd) == E::Ok && enroll::approve(registry.fd, id, f.agent_pin) == E::Ok, "delivery registry");
    const auto binding = telemetry::delivery_binding(id, f.manager_pin);
    DeliverySource source;
    auto queue = std::make_unique<telemetry::JournalCollector>(source, "fixture.service", spool.path.data(),
        telemetry::JournalMode::Metadata, binding);
    require(queue->start(), "outbox startup");
    for (int i = 0; i < 8; ++i) { require(queue->pump(), "outbox fill"); }
    require(queue->count() == 128 && source.reads == 128 && queue->pump() && source.reads == 128, "bounded backpressure");
    const auto fresh = [&] {
        auto a = Session::create(f.a(Protocol::Telemetry)); auto m = Session::create(f.m(Protocol::Telemetry));
        require(a && m && connect(*a, *m), "delivery TLS handshake");
        return std::pair(std::move(a), std::move(m));
    };
    // Separate ALPN prevents protocol confusion with the existing health codec.
    {
        auto a = Session::create(f.a(Protocol::Telemetry)); auto m = Session::create(f.m());
        require(a && m && !connect(*a, *m), "cross-protocol ALPN accepted");
    }
    {
        auto a = Session::create(f.a()); auto m = Session::create(f.m());
        require(a && m && connect(*a, *m), "legacy health TLS handshake");
        telemetry::DeliverySender sender(*queue, *a, id, f.manager_pin);
        require(sender.step(f.manager_pin, true, 1) == D::Failed, "delivery over health ALPN");
    }
    {
        auto [a, m] = fresh();
        knetsentry::agent_health::Reporter reporter(*a);
        require(reporter.send(f.manager_pin, 1, {}) == Status::Failed, "health over delivery ALPN");
        knetsentry::agent_health::Tracker tracker(registry.fd, id);
        require(!tracker.attach(std::move(m), 1), "health tracker accepted delivery ALPN");
    }
    // A trusted but incorrect ACK must never dequeue a record.
    {
        auto [a, m] = fresh();
        telemetry::DeliverySender sender(*queue, *a, id, f.manager_pin);
        require(sender.step(f.manager_pin, true, 1) == D::Pending, "send before invalid ACK");
        pump(*a, *m);
        std::array<unsigned char, 40> bad{};
        require(m->write(bad).status == Status::Ok, "write malformed ACK"); pump(*m, *a);
        require(sender.step(f.manager_pin, true, 2) == D::Failed && queue->count() == 128, "invalid ACK dequeued");
    }
    {
        auto [a, m] = fresh();
        telemetry::DeliverySender sender(*queue, *a, id, f.manager_pin);
        require(sender.step(f.manager_pin, false, 1) == D::Failed && queue->count() == 128, "authorization denial");
    }
    auto inbox = std::make_unique<telemetry::ReceiptInbox>(id, f.manager_pin, telemetry::JournalMode::Metadata,
        "fixture.service", receipts.path.data());
    require(inbox->start(), "inbox startup");
    {
        telemetry::ReceiptInbox concurrent(id, f.manager_pin, telemetry::JournalMode::Metadata, "fixture.service", receipts.path.data());
        require(!concurrent.start(), "concurrent inbox writer");
    }
    {
        auto [a, m] = fresh();
        telemetry::DeliverySender sender(*queue, *a, id, f.manager_pin);
        DeliverySink denied(*inbox); denied.reject = true;
        telemetry::IngestionPipeline pipeline(id, f.manager_pin, telemetry::JournalMode::Metadata, "fixture.service", denied);
        telemetry::DeliveryReceiver receiver(*m, registry.fd, pipeline);
        require(sender.step(f.manager_pin, true, 1) == D::Pending, "send before receiver rejection"); pump(*a, *m);
        require(receiver.step(true, 2) == D::Failed && denied.attempts == 1 && inbox->count() == 0 && queue->count() == 128,
            "receiver rejection acknowledged");
        require(!receiver.normalized_event(), "storage rejection exposed normalized evidence");
    }
    {
        auto [a, m] = fresh();
        telemetry::DeliverySender sender(*queue, *a, id, f.manager_pin);
        auto [other_a, other_m] = fresh();
        telemetry::DeliverySender other(*queue, *other_a, id, f.manager_pin);
        require(other.step(f.manager_pin, true, 1) == D::Failed, "concurrent sender accepted");
        require(sender.step(f.manager_pin, true, 1) == D::Pending, "send before wrong digest"); pump(*a, *m);
        std::array<unsigned char, 40> wrong_digest{'K','S','T','D',1,2,0,32};
        require(m->write(wrong_digest).status == Status::Ok, "wrong digest fixture"); pump(*m, *a);
        require(sender.step(f.manager_pin, true, 2) == D::Failed && queue->count() == 128, "wrong digest acknowledged");
    }
    // Exercise the existing bounded monotonic reconnect scheduler, independent
    // of any socket or network authority.
    knetsentry::agent_health::Reconnect reconnect;
    const auto attempt = reconnect.begin(0);
    require(attempt && reconnect.connected(0, *attempt), "initial reconnect attempt");
    reconnect.lost(1, *attempt);
    require(!reconnect.begin(1000), "retry before backoff");
    const auto retry = reconnect.begin(1001);
    require(retry && *retry != *attempt && reconnect.connected(1001, *retry), "bounded fresh reconnect");
    {
        auto [a, m] = fresh();
        telemetry::DeliverySender sender(*queue, *a, id, f.manager_pin);
        DeliverySink sink(*inbox);
        telemetry::IngestionPipeline pipeline(id, f.manager_pin, telemetry::JournalMode::Metadata, "fixture.service", sink);
        telemetry::DeliveryReceiver receiver(*m, registry.fd, pipeline);
        require(sender.step(f.manager_pin, true, 1) == D::Pending, "first send"); pump(*a, *m, 17);
        require(receiver.step(true, 2) == D::Complete && inbox->count() == 1, "durable receipt");
        require(receiver.normalized_event().has_value(), "durable receipt lost normalized result");
        // Lose all ACK ciphertext, then restart the agent and retry.
        require(queue->count() == 128, "dequeued without acknowledgment");
        a->abort();
        require(sender.step(f.manager_pin, true, 3) == D::Failed, "disconnect terminal");
    }
    queue.reset();
    inbox.reset();
    inbox = std::make_unique<telemetry::ReceiptInbox>(id, f.manager_pin, telemetry::JournalMode::Metadata,
        "fixture.service", receipts.path.data());
    require(inbox->start() && inbox->count() == 1, "receiver restart retained receipt");
    {
        telemetry::JournalCollector wrong(source, "fixture.service", spool.path.data(), telemetry::JournalMode::Metadata,
            telemetry::delivery_binding(id, f.other_pin));
        require(!wrong.start(), "destination substitution accepted");
    }
    queue = std::make_unique<telemetry::JournalCollector>(source, "fixture.service", spool.path.data(),
        telemetry::JournalMode::Metadata, binding);
    require(queue->start() && queue->count() == 128, "restart retains unacked queue");
    {
        auto [a, m] = fresh();
        telemetry::DeliverySender sender(*queue, *a, id, f.manager_pin);
        DeliverySink sink(*inbox);
        telemetry::IngestionPipeline pipeline(id, f.manager_pin, telemetry::JournalMode::Metadata, "fixture.service", sink);
        telemetry::DeliveryReceiver receiver(*m, registry.fd, pipeline);
        require(sender.step(f.manager_pin, true, 1) == D::Pending, "retry send"); pump(*a, *m, 17);
        require(receiver.step(true, 2) == D::Complete && inbox->count() == 1 && sink.attempts == 1, "idempotent retry");
        pump(*m, *a, 13);
        require(sender.step(f.manager_pin, true, 3) == D::Complete && queue->count() == 127, "authenticated ACK");
    }
    queue.reset();
    queue = std::make_unique<telemetry::JournalCollector>(source, "fixture.service", spool.path.data(),
        telemetry::JournalMode::Metadata, binding);
    require(queue->start() && queue->count() == 127 && queue->pump() && queue->count() == 128 && source.position == 129,
        "durable ACK and collection checkpoint");
    // Queue must remain deliverable even when its original source disappears.
    queue.reset(); source.available = false;
    queue = std::make_unique<telemetry::JournalCollector>(source, "fixture.service", spool.path.data(), telemetry::JournalMode::Metadata, binding);
    require(queue->start() && queue->collection_blocked() && !queue->pump() && queue->count() == 128, "unavailable source lost queue");
    {
        auto [a, m] = fresh();
        telemetry::DeliverySender sender(*queue, *a, id, f.manager_pin);
        DeliverySink sink(*inbox);
        telemetry::IngestionPipeline pipeline(id, f.manager_pin, telemetry::JournalMode::Metadata, "fixture.service", sink);
        telemetry::DeliveryReceiver receiver(*m, registry.fd, pipeline);
        require(sender.step(f.manager_pin, true, 1) == D::Pending, "blocked source send"); pump(*a, *m);
        require(receiver.step(true, 2) == D::Complete && inbox->count() == 2, "blocked source receipt"); pump(*m, *a);
        require(sender.step(f.manager_pin, true, 3) == D::Complete && queue->count() == 127, "blocked source ACK");
    }
    {
        auto [a, m] = fresh();
        telemetry::DeliverySender sender(*queue, *a, id, f.manager_pin);
        DeliverySink sink(*inbox);
        telemetry::IngestionPipeline pipeline(id, f.manager_pin, telemetry::JournalMode::Metadata, "fixture.service", sink);
        telemetry::DeliveryReceiver receiver(*m, registry.fd, pipeline);
        require(sender.step(f.manager_pin, true, 1) == D::Pending, "send before revoke"); pump(*a, *m);
        require(enroll::revoke(registry.fd, id, f.agent_pin) == E::Ok && receiver.step(true, 2) == D::Failed && sink.attempts == 0,
            "revoked peer reached sink");
        require(sender.step(f.manager_pin, true, 5001) == D::Failed && queue->count() == 127, "timeout dequeued");
    }
    // A separate one-record stream proves that an empty queue still retains
    // the last collected source checkpoint across a restart.
    {
        Store single_spool, single_receipts;
        DeliverySource single; single.total = 1;
        enroll::EndpointId single_id{}; single_id[0] = 3;
        // Use a fresh registry to avoid any attempt to reuse a revoked pin.
        Store single_registry;
        require(enroll::initialize(single_registry.fd) == E::Ok &&
            enroll::approve(single_registry.fd, single_id, f.agent_pin) == E::Ok, "single registry");
        const auto single_binding = telemetry::delivery_binding(single_id, f.manager_pin);
        telemetry::ReceiptInbox single_inbox(single_id, f.manager_pin, telemetry::JournalMode::Metadata, "fixture.service", single_receipts.path.data());
        require(single_inbox.start(), "single inbox");
        {
            telemetry::JournalCollector single_queue(single, "fixture.service", single_spool.path.data(), telemetry::JournalMode::Metadata, single_binding);
            require(single_queue.start() && single_queue.pump() && single_queue.count() == 1, "single queue");
            auto [a, m] = fresh();
            telemetry::DeliverySender sender(single_queue, *a, single_id, f.manager_pin);
            telemetry::IngestionPipeline pipeline(single_id, f.manager_pin, telemetry::JournalMode::Metadata, "fixture.service", single_inbox);
            telemetry::DeliveryReceiver receiver(*m, single_registry.fd, pipeline);
            require(sender.step(f.manager_pin, true, 1) == D::Pending, "single send"); pump(*a, *m);
            require(receiver.step(true, 2) == D::Complete, "single receipt"); pump(*m, *a);
            require(sender.step(f.manager_pin, true, 3) == D::Complete && single_queue.count() == 0, "empty outbox ACK");
        }
        single.total = 2;
        telemetry::JournalCollector single_queue(single, "fixture.service", single_spool.path.data(), telemetry::JournalMode::Metadata, single_binding);
        require(single_queue.start() && single_queue.count() == 0 && single_queue.pump() && single_queue.count() == 1 && single.position == 2,
            "empty outbox lost checkpoint or recollected acknowledged record");
    }
    // M5.8: exercise actual storage rejection on both sides of a TLS receipt.
    {
        Store fault_registry, fault_spool, fault_receipts;
        enroll::EndpointId fault_id{}; fault_id[0] = 4;
        require(enroll::initialize(fault_registry.fd) == E::Ok &&
            enroll::approve(fault_registry.fd, fault_id, f.agent_pin) == E::Ok, "fault registry");
        const auto fault_binding = telemetry::delivery_binding(fault_id, f.manager_pin);
        DeliverySource fault_source; fault_source.total = 1;
        const auto collide = [](int fd, const char* name) {
            const int pending = ::openat(fd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            require(pending >= 0, "pending collision fixture");
            require(::close(pending) == 0, "pending collision close");
        };
        {
            telemetry::JournalCollector q(fault_source, "fixture.service", fault_spool.path.data(), telemetry::JournalMode::Metadata, fault_binding);
            telemetry::ReceiptInbox r(fault_id, f.manager_pin, telemetry::JournalMode::Metadata, "fixture.service", fault_receipts.path.data());
            require(q.start() && q.pump() && q.count() == 1 && r.start(), "fault setup");
            collide(fault_receipts.fd, "telemetry-inbox-m55.pending");
            auto [a, m] = fresh();
            telemetry::DeliverySender sender(q, *a, fault_id, f.manager_pin);
            telemetry::IngestionPipeline pipeline(fault_id, f.manager_pin, telemetry::JournalMode::Metadata, "fixture.service", r);
            telemetry::DeliveryReceiver receiver(*m, fault_registry.fd, pipeline);
            require(sender.step(f.manager_pin, true, 1) == D::Pending, "fault send"); pump(*a, *m);
            require(receiver.step(true, 2) == D::Failed && r.count() == 0, "failed receipt acknowledged");
            require(sender.step(f.manager_pin, true, 5001) == D::Failed && q.count() == 1, "failed receipt removed sender record");
            require(!std::filesystem::exists(std::filesystem::path(fault_receipts.path.data()) / "telemetry-inbox-m55.v1"), "failed receipt persisted");
        }
        {
            telemetry::JournalCollector q(fault_source, "fixture.service", fault_spool.path.data(), telemetry::JournalMode::Metadata, fault_binding);
            telemetry::ReceiptInbox r(fault_id, f.manager_pin, telemetry::JournalMode::Metadata, "fixture.service", fault_receipts.path.data());
            require(q.start() && q.count() == 1 && r.start() && r.count() == 0, "receipt failure restart");
            auto [a, m] = fresh();
            telemetry::DeliverySender sender(q, *a, fault_id, f.manager_pin);
            telemetry::IngestionPipeline pipeline(fault_id, f.manager_pin, telemetry::JournalMode::Metadata, "fixture.service", r);
            telemetry::DeliveryReceiver receiver(*m, fault_registry.fd, pipeline);
            require(sender.step(f.manager_pin, true, 1) == D::Pending, "receipt retry"); pump(*a, *m);
            require(receiver.step(true, 2) == D::Complete && r.count() == 1, "receipt retry commit"); pump(*m, *a);
            collide(fault_spool.fd, "telemetry-m55.pending");
            require(sender.step(f.manager_pin, true, 3) == D::Failed && q.count() == 1, "failed sender ACK commit removed record");
        }
        {
            telemetry::JournalCollector q(fault_source, "fixture.service", fault_spool.path.data(), telemetry::JournalMode::Metadata, fault_binding);
            telemetry::ReceiptInbox r(fault_id, f.manager_pin, telemetry::JournalMode::Metadata, "fixture.service", fault_receipts.path.data());
            require(q.start() && q.count() == 1 && r.start() && r.count() == 1, "ACK failure restart");
            auto [a, m] = fresh();
            telemetry::DeliverySender sender(q, *a, fault_id, f.manager_pin);
            telemetry::IngestionPipeline pipeline(fault_id, f.manager_pin, telemetry::JournalMode::Metadata, "fixture.service", r);
            telemetry::DeliveryReceiver receiver(*m, fault_registry.fd, pipeline);
            require(sender.step(f.manager_pin, true, 1) == D::Pending, "ACK retry send"); pump(*a, *m);
            require(receiver.step(true, 2) == D::Complete && r.count() == 1, "ACK retry duplicated receipt"); pump(*m, *a);
            require(sender.step(f.manager_pin, true, 3) == D::Complete && q.count() == 0, "ACK retry commit");
        }
        telemetry::JournalCollector q(fault_source, "fixture.service", fault_spool.path.data(), telemetry::JournalMode::Metadata, fault_binding);
        require(q.start() && q.count() == 0 && q.pump() && q.count() == 0, "ACK recovery lost checkpoint");
        std::cout << "M5.8 TLS receiver and sender commit failures, durable retry and deduplication: PASS\n";
    }
    // Verify the real inbox's capacity and idempotency with canonical synthetic rows.
    const auto row = [](std::size_t i) {
        return "cursor-" + std::to_string(i) + "\t100\t50\t" + std::string(32, 'a') + '\t' +
            std::string(32, 'b') + "\tfixture.service\n";
    };
    for (std::size_t i = 3; i <= 128; ++i) { require(inbox->commit(id, binding, row(i)), "fill receiver inbox"); }
    require(inbox->count() == 128 && inbox->commit(id, binding, row(1)) && !inbox->commit(id, binding, row(129)), "inbox overload / exact duplicate");
    auto conflict = row(1); conflict.replace(conflict.find("100"), 3, "101");
    require(!inbox->commit(id, binding, conflict), "conflicting receipt replaced");
    auto other_id = id; other_id[0] = 2;
    require(!inbox->commit(other_id, binding, row(1)) &&
        !inbox->commit(id, telemetry::delivery_binding(id, f.other_pin), row(1)), "wrong endpoint or manager binding receipt");
    std::cout << "M5.5 bounded durable queue/inbox, authenticated ACK, lost ACK retry, restart, destination binding, blocked source and revocation: PASS\n";
}
void ingestion_pipeline(Fixture& f) {
    using O = telemetry::IngestOutcome;
    Store registry, receipts;
    enroll::EndpointId id{}; id[0] = 9;
    require(enroll::initialize(registry.fd) == E::Ok && enroll::approve(registry.fd, id, f.agent_pin) == E::Ok, "ingestion registry");
    const auto binding = telemetry::delivery_binding(id, f.manager_pin);
    const auto row = std::string("cursor-1\t100\t50\t") + std::string(32, 'a') + '\t' + std::string(32, 'b') + "\tfixture.service\n";
    telemetry::ReceiptInbox inbox(id, f.manager_pin, telemetry::JournalMode::Metadata, "fixture.service", receipts.path.data());
    require(inbox.start(), "ingestion inbox");
    DeliverySink sink(inbox);
    telemetry::IngestionPipeline pipeline(id, f.manager_pin, telemetry::JournalMode::Metadata, "fixture.service", sink);
    const auto fresh = [&] {
        auto a = Session::create(f.a(Protocol::Telemetry)); auto m = Session::create(f.m(Protocol::Telemetry));
        require(a && m && connect(*a, *m), "ingestion TLS handshake");
        return std::pair(std::move(a), std::move(m));
    };
    const auto send = [&](Session& a, Session& m, std::string_view payload) {
        std::string wire{"KSTD\1\1", 6};
        wire += static_cast<char>(payload.size() >> 8);
        wire += static_cast<char>(payload.size() & 255);
        wire += payload;
        const std::span<const unsigned char> bytes(reinterpret_cast<const unsigned char*>(wire.data()), wire.size());
        require(a.write(bytes).status == Status::Ok, "ingestion fixture write");
        pump(a, m);
    };
    const auto exchange = [&](std::string_view payload, bool authorized, D expected) {
        const auto before = pipeline.active();
        auto [a, m] = fresh();
        telemetry::DeliveryReceiver receiver(*m, registry.fd, pipeline);
        send(*a, *m, payload);
        require(receiver.step(authorized, 1) == expected && pipeline.active() == before, "ingestion disposition/release");
        const auto& normalized = receiver.normalized_event();
        require(normalized.has_value() == (expected == D::Complete), "normalized evidence escaped before acceptance");
        if (normalized) {
            require(normalized->canonical_row == row && normalized->destination_binding == binding &&
                normalized->source.cursor == "cursor-1" && normalized->source.realtime_usec == 100 &&
                normalized->time_ms == 0 && normalized->mapping == telemetry::MappingResult::MetadataOnly,
                "accepted normalization provenance");
        }
        require(receiver.step(authorized, 2) == expected, "terminal step changed disposition");
        if (expected == D::Failed) { require(m->state() == State::Failed, "rejected exchange did not abort TLS"); }
    };
    exchange(binding + row, false, D::Failed);
    exchange(telemetry::delivery_binding(id, f.other_pin) + row, true, D::Failed);
    exchange(binding + "malformed\n", true, D::Failed);
    exchange(binding + std::string(2049, 'x'), true, D::Failed);
    auto wrong_source = row; wrong_source.replace(wrong_source.find("fixture.service"), 15, "other.service");
    exchange(binding + wrong_source, true, D::Failed);
    require(sink.attempts == 0 && inbox.count() == 0 && pipeline.count(O::Unauthorized) == 1 && pipeline.count(O::Invalid) == 4,
        "invalid or unauthorized input reached durable sink");
    {
        using Peers = std::pair<std::unique_ptr<Session>, std::unique_ptr<Session>>;
        std::vector<Peers> sessions;
        std::vector<std::unique_ptr<telemetry::DeliveryReceiver>> receivers;
        for (std::size_t i = 0; i < telemetry::IngestionPipeline::max_inflight; ++i) {
            sessions.push_back(fresh());
            receivers.push_back(std::make_unique<telemetry::DeliveryReceiver>(*sessions.back().second, registry.fd, pipeline));
            require(receivers.back()->step(true, 10) == D::Pending, "reserve ingestion slot");
        }
        require(pipeline.active() == telemetry::IngestionPipeline::max_inflight, "admission capacity");
        auto [a, m] = fresh();
        telemetry::DeliveryReceiver excess(*m, registry.fd, pipeline);
        send(*a, *m, binding + row);
        require(excess.step(true, 11) == D::Failed && pipeline.count(O::Overloaded) == 1 && sink.attempts == 0,
            "overload reached sink");
        require(!excess.normalized_event(), "overload exposed normalized evidence");
        require(receivers.front()->step(true, 5010) == D::Failed && pipeline.count(O::TransportFailed) == 1,
            "timeout failed to release admission");
        exchange(binding + row, true, D::Complete);
        require(pipeline.active() == telemetry::IngestionPipeline::max_inflight - 1, "capacity recovery");
    }
    require(pipeline.active() == 0 && pipeline.count(O::Abandoned) == 3 && inbox.count() == 1, "abandoned admission recovery");
    exchange(binding + row, true, D::Complete);
    auto conflict = row; conflict.replace(conflict.find("100"), 3, "101");
    exchange(binding + conflict, true, D::Failed);
    sink.reject = true;
    exchange(binding + row, true, D::Failed);
    require(inbox.count() == 1 && sink.attempts == 4 && pipeline.count(O::Committed) == 2 &&
        pipeline.count(O::Acknowledged) == 2 && pipeline.count(O::StorageRejected) == 2, "commit/ack accounting");
    {
        auto unapproved = id; unapproved[0] = 8;
        telemetry::IngestionPipeline wrong_identity(unapproved, f.manager_pin, telemetry::JournalMode::Metadata, "fixture.service", sink);
        auto [a, m] = fresh();
        telemetry::DeliveryReceiver receiver(*m, registry.fd, wrong_identity);
        send(*a, *m, telemetry::delivery_binding(unapproved, f.manager_pin) + row);
        require(receiver.step(true, 1) == D::Failed && wrong_identity.count(O::Unauthorized) == 1 && sink.attempts == 4,
            "unenrolled endpoint reached sink");
    }
    // The canonical validator is selected by trusted configuration, never by
    // a payload's claimed source or additional fields.
    for (const auto mode : {telemetry::JournalMode::Authentication, telemetry::JournalMode::Audit}) {
        Store profile_store;
        const std::string unit = mode == telemetry::JournalMode::Audit ? "audit" : "ssh.service";
        const std::string suffix = mode == telemetry::JournalMode::Audit ? "\t1100\t9\n" : "\tredacted\n";
        auto profile_row = row.substr(0, row.find("fixture.service")) + unit + suffix;
        telemetry::ReceiptInbox profile_inbox(id, f.manager_pin, mode, unit, profile_store.path.data());
        require(profile_inbox.start(), "profile inbox");
        telemetry::IngestionPipeline profile(id, f.manager_pin, mode, unit, profile_inbox);
        {
            auto [a, m] = fresh();
            telemetry::DeliveryReceiver receiver(*m, registry.fd, profile);
            send(*a, *m, binding + row);
            require(receiver.step(true, 1) == D::Failed && profile.count(O::Invalid) == 1 && profile_inbox.count() == 0,
                "cross-profile event accepted");
            require(!receiver.normalized_event(), "cross-profile normalized evidence");
        }
        {
            auto [a, m] = fresh();
            telemetry::DeliveryReceiver receiver(*m, registry.fd, profile);
            send(*a, *m, binding + profile_row);
            require(receiver.step(true, 1) == D::Complete && profile.count(O::Committed) == 1 && profile_inbox.count() == 1,
                "valid configured profile rejected");
            const auto& normalized = receiver.normalized_event();
            require(normalized && normalized->canonical_row == profile_row && normalized->source_mode == mode &&
                normalized->mapping == (mode == telemetry::JournalMode::Audit ? telemetry::MappingResult::AuditTypeUnmapped : telemetry::MappingResult::Redacted),
                "profile normalization lost provenance or redaction");
        }
    }
    {
        telemetry::IngestionPipeline invalid(id, f.manager_pin, telemetry::JournalMode::Metadata, "*.service", sink);
        auto [a, m] = fresh();
        telemetry::DeliveryReceiver receiver(*m, registry.fd, invalid);
        send(*a, *m, binding + row);
        require(receiver.step(true, 1) == D::Failed && invalid.active() == 0 && invalid.count(O::Invalid) == 1 && sink.attempts == 4,
            "invalid routing configuration reached sink");
    }
    {
        auto [a, m] = fresh();
        telemetry::DeliveryReceiver receiver(*m, registry.fd, pipeline);
        require(receiver.step(true, 1) == D::Pending, "reserve before revocation");
        require(enroll::revoke(registry.fd, id, f.agent_pin) == E::Ok, "ingestion revocation");
        send(*a, *m, binding + row);
        require(receiver.step(true, 2) == D::Failed && pipeline.active() == 0 && sink.attempts == 4 &&
            pipeline.count(O::Unauthorized) == 2, "revoked admission reached sink");
    }
    std::cout << "M6.1 authenticated ingestion, invalid rejection, bounded admission, timeout/release, durable retry and disposition counters: PASS\n";
}
} // namespace
int main(int argc, char** argv) {
    try {
        Fixture fixture;
        if (argc == 2 && std::string_view(argv[1]) == "--lifecycle") {
            lifecycle(fixture); manager_lifecycle(fixture); expiry(fixture);
        } else if (argc == 2 && std::string_view(argv[1]) == "--heartbeat") {
            heartbeat(fixture);
        } else if (argc == 2 && std::string_view(argv[1]) == "--authentication-transport") {
            authentication_transport(fixture);
        } else if (argc == 2 && std::string_view(argv[1]) == "--ingestion") {
            ingestion_pipeline(fixture);
        } else if (argc == 2 && std::string_view(argv[1]) == "--telemetry-delivery") {
            telemetry_delivery(fixture);
        } else if (argc == 1) {
            storage(fixture); malformed_registry(fixture); capacity(); admission(fixture);
        } else { return 2; }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "M4.4 enrollment regression: FAIL: " << error.what() << '\n'; return 1;
    }
}
