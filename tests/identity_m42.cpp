// SPDX-FileCopyrightText: 2026 Chris Sutton
// SPDX-License-Identifier: MIT
#include <knetsentry/core/identity.hpp>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

namespace {
using namespace knetsentry::identity;
using Cert = std::unique_ptr<X509, decltype(&X509_free)>;
void require(bool ok, std::string_view reason) {
    if (!ok) { throw std::runtime_error(std::string(reason)); }
}
struct Fixture {
    std::filesystem::path path;
    int directory{-1};
    Fixture() {
        std::array<char, 32> pattern{"/tmp/ks-identity-XXXXXX"};
        const char* result = ::mkdtemp(pattern.data());
        require(result != nullptr, "private test directory");
        path = result;
        directory = ::open(result, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        require(directory >= 0, "directory descriptor");
    }
    ~Fixture() {
        if (directory >= 0) { (void)::close(directory); }
        std::error_code error;
        std::filesystem::remove_all(path, error);
    }
};
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
    require(ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), issuer == nullptr ? 1 : 2) == 1,
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
void rejected(const KeyResult& result, std::string_view reason) {
    require(result.error != Error::None && !result.key, reason);
}
void fingerprint_vector() {
    // RFC 8032 test-vector public key; independently calculated SHA-256.
    constexpr Fingerprint raw{
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};
    constexpr Fingerprint expected{
        0x21, 0xfe, 0x31, 0xdf, 0xa1, 0x54, 0xa2, 0x61,
        0x62, 0x6b, 0xf8, 0x54, 0x04, 0x6f, 0xd2, 0x27,
        0x1b, 0x7b, 0xed, 0x4b, 0x6a, 0xbe, 0x45, 0xaa,
        0x58, 0x87, 0x7e, 0xf4, 0x7f, 0x97, 0x21, 0xb9};
    Key key(EVP_PKEY_new_raw_public_key_ex(nullptr, "ED25519", nullptr, raw.data(), raw.size()));
    require(key && fingerprint(key.get()) == expected, "public-key fingerprint golden vector");
}
void storage_negatives(Fixture& fixture) {
    const auto path = fixture.path / "agent.key";
    require(::chmod(path.c_str(), 0644) == 0, "fixture chmod");
    rejected(load_key(fixture.directory, Role::Agent), "world-readable key accepted");
    require(::chmod(path.c_str(), 0600) == 0, "fixture restore mode");
    const auto hard = fixture.path / "hard";
    std::filesystem::create_hard_link(path, hard);
    rejected(load_key(fixture.directory, Role::Agent), "hardlinked key accepted");
    std::filesystem::remove(hard);
    require(::chmod(fixture.path.c_str(), 0755) == 0, "fixture directory chmod");
    rejected(load_key(fixture.directory, Role::Agent), "public directory accepted");
    rejected(create_key(fixture.directory, Role::Agent), "public directory creation accepted");
    require(::chmod(fixture.path.c_str(), 0700) == 0, "fixture directory restore");
    std::filesystem::remove(path);
    std::filesystem::create_symlink("manager.key", path);
    rejected(load_key(fixture.directory, Role::Agent), "symlink accepted");
    rejected(create_key(fixture.directory, Role::Agent), "symlink overwritten");
    std::filesystem::remove(path);
    require(::mkfifo(path.c_str(), 0600) == 0, "fixture FIFO");
    rejected(load_key(fixture.directory, Role::Agent), "FIFO accepted");
    std::filesystem::remove(path);
    std::filesystem::create_directory(path);
    rejected(load_key(fixture.directory, Role::Agent), "directory accepted");
    std::filesystem::remove(path);
    const auto pending = fixture.path / "agent.key.pending";
    std::filesystem::create_symlink("manager.key", pending);
    rejected(create_key(fixture.directory, Role::Agent), "staging symlink accepted");
    require(std::filesystem::is_symlink(pending) && !std::filesystem::exists(path), "staging mutated");
    std::filesystem::remove(pending);
    { std::ofstream output(pending); output << "stale staging"; }
    require(::chmod(pending.c_str(), 0600) == 0, "fixture staging mode");
    rejected(create_key(fixture.directory, Role::Agent), "existing staging file replaced");
    require(std::filesystem::file_size(pending) == 13 && !std::filesystem::exists(path), "staging replaced");
    std::filesystem::remove(pending);
    auto recreated = create_key(fixture.directory, Role::Agent);
    require(recreated.error == Error::None, "fixture recreation");
    { std::ofstream output(path, std::ios::binary | std::ios::app); output.put('x'); }
    rejected(load_key(fixture.directory, Role::Agent), "trailing key bytes accepted");
    std::filesystem::resize_file(path, max_key_bytes + 1);
    rejected(load_key(fixture.directory, Role::Agent), "oversized key accepted");
    std::filesystem::resize_file(path, 0);
    rejected(load_key(fixture.directory, Role::Agent), "empty key accepted");
    { std::ofstream output(path, std::ios::binary); output << "not a key"; }
    rejected(load_key(fixture.directory, Role::Agent), "malformed key accepted");
    Key wrong(EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519"));
    require(wrong && !fingerprint(wrong.get()), "non-Ed25519 fingerprint accepted");
    std::unique_ptr<PKCS8_PRIV_KEY_INFO, decltype(&PKCS8_PRIV_KEY_INFO_free)> wrong_info(
        EVP_PKEY2PKCS8(wrong.get()), PKCS8_PRIV_KEY_INFO_free);
    require(wrong_info != nullptr, "wrong-algorithm fixture");
    std::unique_ptr<BIO, decltype(&BIO_free)> sink(BIO_new_file(path.c_str(), "wb"), BIO_free);
    require(sink && i2d_PKCS8_PRIV_KEY_INFO_bio(sink.get(), wrong_info.get()) == 1, "wrong-algorithm DER fixture");
    sink.reset();
    rejected(load_key(fixture.directory, Role::Agent), "wrong key algorithm accepted");
    rejected(load_key(-1, Role::Agent), "invalid descriptor accepted");
    rejected(create_key(fixture.directory, static_cast<Role>(99)), "invalid role accepted");
}
void certificate_tests(EVP_PKEY* agent, EVP_PKEY* manager, const Fingerprint& agent_pin,
    const Fingerprint& manager_pin) {
    Key ca(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"));
    Key rogue(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"));
    require(ca && rogue, "fixture CA keys");
    auto root = certificate(ca.get(), nullptr, ca.get(), "test root", nullptr);
    auto wrong_root = certificate(rogue.get(), nullptr, rogue.get(), "test root", nullptr);
    auto leaf = certificate(agent, root.get(), ca.get(), "test agent", "clientAuth");
    auto server = certificate(manager, root.get(), ca.get(), "test manager", "serverAuth");
    const auto anchor = der(root.get());
    const auto client = der(leaf.get());
    const auto manager_cert = der(server.get());
    require(validate_certificate(client, anchor, Role::Agent, agent_pin) == Error::None, "agent cert rejected");
    require(validate_certificate(manager_cert, anchor, Role::Manager, manager_pin) == Error::None, "manager cert rejected");
    auto deny = [&](std::span<const unsigned char> bytes, Role role, const Fingerprint& pin, std::string_view why) {
        require(validate_certificate(bytes, anchor, role, pin) != Error::None, why);
    };
    deny(client, Role::Manager, agent_pin, "agent accepted as manager");
    deny(manager_cert, Role::Agent, manager_pin, "manager accepted as agent");
    deny(client, Role::Agent, manager_pin, "wrong identity pin accepted");
    require(validate_certificate(client, der(wrong_root.get()), Role::Agent, agent_pin) != Error::None, "rogue root accepted");
    require(validate_certificate(client, {}, Role::Agent, agent_pin) != Error::None, "missing anchor accepted");
    require(validate_certificate(client, anchor, static_cast<Role>(99), agent_pin) != Error::None, "bad role accepted");
    deny(anchor, Role::Agent, *fingerprint(ca.get()), "CA accepted as leaf");
    auto expired = certificate(agent, root.get(), ca.get(), "expired", "clientAuth", -3600, -60);
    auto future = certificate(agent, root.get(), ca.get(), "future", "clientAuth", 3600, 7200);
    auto missing = certificate(agent, root.get(), ca.get(), "missing", nullptr);
    auto same_key = certificate(ca.get(), root.get(), ca.get(), "same key", "clientAuth");
    deny(der(same_key.get()), Role::Agent, *fingerprint(ca.get()), "CA key accepted as leaf key");
    auto mixed = certificate(agent, root.get(), ca.get(), "mixed", "clientAuth,serverAuth");
    deny(der(expired.get()), Role::Agent, agent_pin, "expired accepted");
    deny(der(future.get()), Role::Agent, agent_pin, "not-yet-valid accepted");
    deny(der(missing.get()), Role::Agent, agent_pin, "missing EKU accepted");
    deny(der(mixed.get()), Role::Agent, agent_pin, "mixed role accepted");
    auto tampered = client;
    tampered.back() ^= 1U;
    deny(tampered, Role::Agent, agent_pin, "bad signature accepted");
    tampered = client;
    tampered.push_back(0);
    deny(tampered, Role::Agent, agent_pin, "trailing cert data accepted");
    for (std::size_t size = 0; size < client.size(); ++size) {
        deny(std::span(client).first(size), Role::Agent, agent_pin, "truncated cert accepted");
    }
    const std::vector<unsigned char> oversized(max_certificate_bytes + 1);
    deny(oversized, Role::Agent, agent_pin, "oversized cert accepted");
}
} // namespace

int main() {
    try {
        require(OPENSSL_version_major() == 3 && OPENSSL_version_minor() == 5, "unexpected runtime OpenSSL series");
        fingerprint_vector();
        Fixture fixture;
        auto agent = create_key(fixture.directory, Role::Agent);
        auto manager = create_key(fixture.directory, Role::Manager);
        require(agent.error == Error::None && agent.key && manager.error == Error::None && manager.key, "create identities");
        const auto agent_pin = fingerprint(agent.key.get());
        const auto manager_pin = fingerprint(manager.key.get());
        require(agent_pin && manager_pin && *agent_pin != *manager_pin, "distinct identities");
        require(!fingerprint(nullptr), "null key fingerprint");
        auto loaded = load_key(fixture.directory, Role::Agent);
        require(loaded.error == Error::None && fingerprint(loaded.key.get()) == agent_pin, "identity reload");
        auto manager_loaded = load_key(fixture.directory, Role::Manager);
        require(manager_loaded.error == Error::None && fingerprint(manager_loaded.key.get()) == manager_pin, "manager reload");
        rejected(create_key(fixture.directory, Role::Agent), "identity overwritten");
        require(fingerprint(load_key(fixture.directory, Role::Agent).key.get()) == agent_pin, "identity changed");
        require(!std::filesystem::exists(fixture.path / "agent.key.pending") &&
            !std::filesystem::exists(fixture.path / "manager.key.pending"), "staging leaked");
        certificate_tests(agent.key.get(), manager.key.get(), *agent_pin, *manager_pin);
        storage_negatives(fixture);
        std::cout << "M4.2 identity storage and explicit certificate trust: PASS; " << "headers=" << OPENSSL_VERSION_STR << "; runtime=" << OpenSSL_version(OPENSSL_VERSION) << '\n';
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "M4.2 identity regression: FAIL: " << error.what() << '\n';
        return 1;
    }
}
