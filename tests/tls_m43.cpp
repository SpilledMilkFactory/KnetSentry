// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/core/tls_transport.hpp>
#include <knetsentry/core/agent_protocol.hpp>
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
namespace protocol = knetsentry::core::agent_protocol;
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
void positive(Fixture& fixture) {
    auto a = Session::create(fixture.a()); auto m = Session::create(fixture.m());
    require(a && m, "valid session creation");
    std::array<unsigned char, max_plaintext> output{};
    const std::array<unsigned char, 3> probe{1, 2, 3};
    require(a->write(probe).status == Status::NotReady && m->read(output).status == Status::NotReady,
        "pre-auth plaintext access");
    require(connect(*a, *m), "mutual authentication");
    auto hello = protocol::encode({protocol::Kind::Hello, 1, 0, 0});
    require(hello.error == protocol::Error::None && hello.size > 0, "KSAP hello fixture");
    auto plaintext = std::as_bytes(std::span(hello.bytes).first(hello.size));
    const auto data = std::span(reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size());
    require(a->write(data).bytes == data.size(), "encrypted KSAP send");
    std::array<unsigned char, max_ciphertext_chunk> wire{};
    auto encrypted = a->drain(wire);
    require(encrypted.status == Status::Ok && encrypted.bytes > data.size(), "TLS record overhead");
    const auto record = std::span(wire).first(encrypted.bytes);
    require(std::search(record.begin(), record.end(), data.begin(), data.end()) == record.end(), "clear KSAP on wire");
    // Feed one byte at a time to exercise fragmented record handling.
    for (const auto byte : record) { require(m->ingest(std::span(&byte, 1)).bytes == 1, "fragment"); }
    auto got = m->read(output);
    require(got.status == Status::Ok && got.bytes == data.size() &&
        std::equal(data.begin(), data.end(), output.begin()), "KSAP receive");
    protocol::SessionValidator validator;
    require(validator.accept(std::as_bytes(std::span(output).first(got.bytes))).error == protocol::Error::None,
        "KSAP codec over authenticated transport");
    require(m->write(probe).bytes == probe.size(), "reverse send"); pump(*m, *a);
    require(a->read(output).bytes == probe.size() && std::equal(probe.begin(), probe.end(), output.begin()), "reverse read");
    require(a->read(output).status == Status::WouldBlock, "idle read");
    std::array<unsigned char, max_plaintext + 1> oversized{};
    require(a->write(oversized).status == Status::InvalidInput, "oversized write");
    // Fill the bounded output queue; retry must keep the same plaintext.
    std::array<unsigned char, max_plaintext> block{};
    std::size_t sent = 0;
    for (int i = 0; i < 64; ++i) {
        const auto result = a->write(block);
        if (result.status == Status::WouldBlock) { break; }
        require(result.status == Status::Ok && result.bytes == block.size(), "bounded queue send");
        sent += result.bytes;
    }
    require(sent > 0 && sent < 64 * block.size(), "backpressure did not occur");
    require(a->write(probe).status == Status::InvalidInput, "changed retry accepted");
    // Drain incrementally, avoiding overfilling the receiver's own queue.
    std::size_t received = 0;
    for (int i = 0; i < 128; ++i) {
        const auto part = a->drain(std::span(wire).first(4096));
        if (part.status == Status::Ok) { require(m->ingest(std::span(wire).first(part.bytes)).bytes == part.bytes, "backpressure pump"); }
        const auto r = m->read(output);
        if (r.status == Status::Ok) { received += r.bytes; }
        else { require(r.status == Status::WouldBlock, "backpressure read"); }
        if (part.status == Status::WouldBlock && r.status == Status::WouldBlock) { break; }
    }
    require(a->write(block).bytes == block.size(), "retry failed"); sent += block.size();
    pump(*a, *m);
    for (int i = 0; i < 64 && received < sent; ++i) {
        const auto r = m->read(output); require(r.status == Status::Ok, "remaining data"); received += r.bytes;
    }
    require(received == sent, "retry duplication or data loss");
    require(a->shutdown() == Status::WouldBlock, "initial close"); pump(*a, *m);
    require(m->read(output).status == Status::Closed, "peer close notify");
    require(m->shutdown() == Status::Closed, "peer shutdown"); pump(*m, *a);
    require(a->shutdown() == Status::Closed, "mutual clean shutdown");
    require(a->write(probe).status == Status::NotReady, "closed write");
    std::cout << "M4.3 TLS 1.3 mutual identity, encrypted KSAP, backpressure and close: PASS\n";
}
void negative(Fixture& fixture) {
    auto bad = fixture.a(); bad.key = fixture.other.get();
    require(!Session::create(bad), "mismatched local key");
    bad = fixture.a(); bad.role = Role::Invalid;
    require(!Session::create(bad), "invalid local role");
    bad = fixture.a(); bad.root = {};
    require(!Session::create(bad), "missing local root");
    bad = fixture.a(); bad.peer_pin = fixture.agent_pin;
    require(!Session::create(bad), "same key role reuse");
    for (const bool wrong_agent : {false, true}) {
        auto ac = fixture.a(); auto mc = fixture.m();
        if (wrong_agent) { mc.peer_pin = fixture.other_pin; } else { ac.peer_pin = fixture.other_pin; }
        auto a = Session::create(ac); auto m = Session::create(mc);
        require(a && m && !connect(*a, *m), "wrong peer pin trusted");
        auto& rejected = wrong_agent ? *m : *a;
        std::array<unsigned char, max_plaintext> output{};
        require(rejected.state() == State::Failed && rejected.read(output).status == Status::Failed &&
            rejected.write(std::span(output).first(1)).status == Status::Failed, "failed session reused");
    }
    auto a = Session::create(fixture.a()); auto m = Session::create(fixture.m());
    require(a && m && connect(*a, *m), "tamper fixture connect");
    std::array<unsigned char, max_ciphertext_chunk> wire{};
    std::array<unsigned char, max_plaintext> output{};
    const std::array<unsigned char, 4> secret{4, 3, 2, 1};
    require(a->write(secret).bytes == secret.size(), "tamper fixture write");
    auto out = a->drain(wire);
    require(out.status == Status::Ok && out.bytes > 5 && out.bytes <= wire.size(), "tamper fixture record");
    wire.at(out.bytes - 1) ^= 1U;
    require(m->ingest(std::span(wire).first(out.bytes)).bytes == out.bytes, "tamper fixture feed");
    output.fill(0x55);
    require(m->read(output).status == Status::Failed && std::all_of(output.begin(), output.end(),
        [](unsigned char b) { return b == 0x55; }), "corrupt record disclosed plaintext");
    a->abort(); require(a->state() == State::Failed && a->handshake() == Status::Failed, "abort not terminal");
    auto incomplete = Session::create(fixture.m());
    require(incomplete != nullptr, "bounded input fixture");
    std::array<unsigned char, max_ciphertext_chunk + 1> large{};
    require(incomplete->ingest(large).status == Status::InvalidInput &&
        incomplete->drain(large).status == Status::InvalidInput, "oversized ciphertext input/output");
    auto input = std::span(large).first(max_ciphertext_chunk);
    for (std::size_t i = 0; i < wire_buffer_bytes / max_ciphertext_chunk; ++i) {
        require(incomplete->ingest(input).bytes == input.size(), "bounded input fill");
    }
    require(incomplete->ingest(input).status == Status::WouldBlock, "unbounded input queue");
    require(incomplete->handshake() == Status::Failed, "malformed TLS handshake trusted");
    require(incomplete->drain(wire).status == Status::Failed, "failed queue exposed");
    std::cout << "M4.3 wrong identity, local credential mismatch, corrupt records, bounded input and abort: PASS\n";
}
// An independently configured TLS client exercises server-side rejection even
// when the peer deliberately ignores our local credential construction rules.
void raw_client(Fixture& fixture, X509* cert, EVP_PKEY* key, int version, bool correct_alpn, bool expected, bool offer_alpn = true) {
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
    require(ctx && SSL_CTX_set_min_proto_version(ctx.get(), version) == 1 &&
        SSL_CTX_set_max_proto_version(ctx.get(), version) == 1, "raw TLS profile");
    if (cert != nullptr) {
        require(SSL_CTX_use_certificate(ctx.get(), cert) == 1 && SSL_CTX_use_PrivateKey(ctx.get(), key) == 1, "raw credential");
    }
    constexpr std::array<unsigned char, 9> good{8, 'k', 's', 'a', 'p', '/', '1', '.', '0'};
    constexpr std::array<unsigned char, 4> wrong{3, 'b', 'a', 'd'};
    if (offer_alpn) {
        require(SSL_CTX_set_alpn_protos(ctx.get(), correct_alpn ? good.data() : wrong.data(),
            correct_alpn ? static_cast<unsigned int>(good.size()) : static_cast<unsigned int>(wrong.size())) == 0, "raw ALPN");
    }
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(ctx.get()), SSL_free);
    require(ssl != nullptr, "raw TLS session");
    BIO* inner = nullptr; BIO* outer = nullptr;
    const int paired = BIO_new_bio_pair(&inner, wire_buffer_bytes, &outer, wire_buffer_bytes);
    std::unique_ptr<BIO, decltype(&BIO_free)> i(inner, BIO_free), o(outer, BIO_free);
    require(paired == 1, "raw BIO pair");
    auto* endpoint = i.release(); SSL_set_bio(ssl.get(), endpoint, endpoint); SSL_set_connect_state(ssl.get());
    auto m = Session::create(fixture.m()); require(m != nullptr, "manager fixture");
    std::array<unsigned char, max_ciphertext_chunk> wire{};
    for (int step = 0; step < 100; ++step) {
        (void)SSL_do_handshake(ssl.get());
        const int count = BIO_read(o.get(), wire.data(), static_cast<int>(wire.size()));
        if (count > 0) { require(m->ingest(std::span(wire).first(static_cast<std::size_t>(count))).bytes == static_cast<std::size_t>(count), "raw delivery"); }
        (void)m->handshake();
        if (m->state() == State::Failed || m->state() == State::Trusted) { break; }
        auto out = m->drain(wire);
        if (out.status == Status::Ok) { require(BIO_write(o.get(), wire.data(), static_cast<int>(out.bytes)) == static_cast<int>(out.bytes), "raw reply"); }
    }
    require(m->state() == (expected ? State::Trusted : State::Failed), "raw peer acceptance mismatch");
}
// A genuine TLS server that never asks for a client certificate must not
// establish a mutually authenticated agent session, even with the right pin.
int raw_alpn(SSL*, const unsigned char** out, unsigned char* length,
    const unsigned char* in, unsigned int size, void*) noexcept {
    if (size != 9 || in == nullptr || in[0] != 8) { return SSL_TLSEXT_ERR_ALERT_FATAL; }
    *out = in + 1; *length = 8; return SSL_TLSEXT_ERR_OK;
}
void raw_server(Fixture& fixture, bool request_client) {
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> ctx(SSL_CTX_new(TLS_server_method()), SSL_CTX_free);
    require(ctx && SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) == 1 &&
        SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION) == 1 &&
        SSL_CTX_use_certificate(ctx.get(), fixture.server.get()) == 1 &&
        SSL_CTX_use_PrivateKey(ctx.get(), fixture.manager.get()) == 1, "unilateral server profile");
    SSL_CTX_set_alpn_select_cb(ctx.get(), raw_alpn, nullptr);
    if (request_client) {
        require(X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx.get()), fixture.root.get()) == 1, "raw server trust");
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    }
    std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(ctx.get()), SSL_free);
    require(ssl != nullptr, "unilateral server SSL");
    BIO* inner = nullptr; BIO* outer = nullptr;
    const int paired = BIO_new_bio_pair(&inner, wire_buffer_bytes, &outer, wire_buffer_bytes);
    std::unique_ptr<BIO, decltype(&BIO_free)> i(inner, BIO_free), o(outer, BIO_free);
    require(paired == 1, "unilateral BIO pair");
    auto* endpoint = i.release(); SSL_set_bio(ssl.get(), endpoint, endpoint); SSL_set_accept_state(ssl.get());
    auto a = Session::create(fixture.a()); require(a != nullptr, "agent fixture");
    std::array<unsigned char, max_ciphertext_chunk> wire{};
    for (int step = 0; step < 100; ++step) {
        (void)a->handshake();
        if (a->state() == State::Failed) { break; }
        auto out = a->drain(wire);
        if (out.status == Status::Ok) { require(BIO_write(o.get(), wire.data(), static_cast<int>(out.bytes)) == static_cast<int>(out.bytes), "unilateral request"); }
        (void)SSL_do_handshake(ssl.get());
        if (a->state() == State::Trusted && SSL_is_init_finished(ssl.get()) == 1) { break; }
        const int count = BIO_read(o.get(), wire.data(), static_cast<int>(wire.size()));
        if (count > 0) { require(a->ingest(std::span(wire).first(static_cast<std::size_t>(count))).bytes == static_cast<std::size_t>(count), "unilateral reply"); }
    }
    if (request_client) {
        require(a->state() == State::Trusted && SSL_is_init_finished(ssl.get()) == 1 &&
            SSL_get_verify_result(ssl.get()) == X509_V_OK, "raw mutual server control");
    } else {
        require(a->state() == State::Failed, "server omitted client authentication but agent trusted");
    }
}
void raw_negatives(Fixture& fixture) {
    raw_client(fixture, fixture.client.get(), fixture.agent.get(), TLS1_3_VERSION, true, true);
    raw_client(fixture, nullptr, nullptr, TLS1_3_VERSION, true, false);
    raw_client(fixture, fixture.client.get(), fixture.agent.get(), TLS1_2_VERSION, true, false);
    raw_client(fixture, fixture.client.get(), fixture.agent.get(), TLS1_3_VERSION, false, false);
    raw_client(fixture, fixture.client.get(), fixture.agent.get(), TLS1_3_VERSION, true, false, false);
    auto expired = certificate(fixture.agent.get(), fixture.root.get(), fixture.ca.get(), "expired", "clientAuth", -3600, -60);
    raw_client(fixture, expired.get(), fixture.agent.get(), TLS1_3_VERSION, true, false);
    auto role = certificate(fixture.agent.get(), fixture.root.get(), fixture.ca.get(), "wrong role", "serverAuth");
    raw_client(fixture, role.get(), fixture.agent.get(), TLS1_3_VERSION, true, false);
    auto mixed = certificate(fixture.agent.get(), fixture.root.get(), fixture.ca.get(), "mixed", "clientAuth,serverAuth");
    raw_client(fixture, mixed.get(), fixture.agent.get(), TLS1_3_VERSION, true, false);
    auto rogue = certificate(fixture.other.get(), nullptr, fixture.other.get(), "rogue", nullptr);
    auto rogue_leaf = certificate(fixture.agent.get(), rogue.get(), fixture.other.get(), "agent", "clientAuth");
    raw_client(fixture, rogue_leaf.get(), fixture.agent.get(), TLS1_3_VERSION, true, false);
    std::cout << "M4.3 missing certificate, TLS downgrade, wrong ALPN, expired/role/rogue certificates: PASS\n";
}
} // namespace
int main() {
    try {
        Fixture fixture;
        positive(fixture); negative(fixture); raw_negatives(fixture); raw_server(fixture, true); raw_server(fixture, false);
        std::cout << "M4.3 server omitted client authentication: rejected\n";
        std::cout << "M4.3 headers=" << OPENSSL_VERSION_STR << "; runtime=" << OpenSSL_version(OPENSSL_VERSION) << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "M4.3 TLS regression: FAIL: " << error.what() << '\n'; return 1;
    }
}
