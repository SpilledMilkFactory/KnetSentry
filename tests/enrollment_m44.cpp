// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/core/tls_transport.hpp>
#include <knetsentry/core/enrollment.hpp>
#include <filesystem>
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
} // namespace
int main() {
    try {
        Fixture fixture;
        storage(fixture); malformed_registry(fixture); capacity(); admission(fixture);
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "M4.4 enrollment regression: FAIL: " << error.what() << '\n'; return 1;
    }
}
